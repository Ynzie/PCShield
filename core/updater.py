"""Updates from the GitHub releases page (Ynzie/PCShield).

Check: asks GitHub's API for the latest published release (drafts and pre-releases are ignored).
Install: downloads PCShield.exe from that release only, checks its SHA-256 against the digest GitHub
publishes for the file, then swaps it in (the running exe is renamed, not overwritten) and restarts.
Nothing is downloaded or installed without the user clicking Update.
"""
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import install
from .util import DATA_DIR, load_settings, log, now_iso, save_setting
from .version import REPO, VERSION

API = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES = f"https://github.com/{REPO}/releases"
ASSET = "PCShield.exe"
MAX_BYTES = 300 * 1024 * 1024
CHECK_EVERY_HOURS = 24
UA = {"User-Agent": f"PCShield/{VERSION} (+https://github.com/{REPO})"}

STATE = {"running": False, "done": 0, "total": 0, "stage": "", "error": "", "finished": False}
_lock = threading.Lock()


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    """GitHub sends the download to its file servers; never follow a redirect off HTTPS."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).scheme != "https":
            raise urllib.error.URLError("refused a non-HTTPS redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_HttpsOnly)


def _get_json(url, timeout=15):
    req = urllib.request.Request(url, headers={**UA, "Accept": "application/vnd.github+json"})
    try:
        with _opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def newer(latest, current=VERSION):
    a, b = install.version_tuple(latest), install.version_tuple(current)
    return bool(a and b and a > b)


def _asset_ok(url):
    """Only this repo's release downloads."""
    u = urllib.parse.urlparse(url or "")
    return u.scheme == "https" and u.hostname == "github.com" and u.path.startswith(f"/{REPO}/releases/download/") \
        and u.path.endswith("/" + ASSET)


def parse_release(data):
    tag = data.get("tag_name") or ""
    asset = next((a for a in data.get("assets") or [] if a.get("name") == ASSET), None)
    digest = (asset or {}).get("digest") or ""
    sha = digest.split(":", 1)[1].lower() if digest.lower().startswith("sha256:") else ""
    return {
        "latest": tag.lstrip("vV") or None,
        "tag": tag,
        "name": data.get("name") or tag,
        "notes": (data.get("body") or "")[:4000],
        "published": data.get("published_at") or "",
        "page": data.get("html_url") or RELEASES,
        "download": (asset or {}).get("browser_download_url") or "",
        "size": int((asset or {}).get("size") or 0),
        "sha256": sha if re.fullmatch(r"[0-9a-f]{64}", sha) else "",
    }


def check(force=False):
    """{'current', 'latest', 'available', ...}. Without force, reuses a result less than a day old."""
    s = load_settings()
    cached = s.get("update_info")
    if not force and cached and s.get("update_checked"):
        try:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(s["update_checked"])
            if age.total_seconds() < CHECK_EVERY_HOURS * 3600:
                return _result(cached, s["update_checked"])
        except ValueError:
            pass
    try:
        code, data = _get_json(API)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"ok": False, "current": VERSION, "message": f"Couldn't reach GitHub ({getattr(e, 'reason', e)})."}
    if code == 404:
        info = {"latest": None, "page": RELEASES, "none": True}
    elif code != 200:
        return {"ok": False, "current": VERSION, "message": f"GitHub answered {code} - try again later."}
    else:
        info = parse_release(data)
    checked = now_iso()
    save_setting("update_info", info)
    save_setting("update_checked", checked)
    return _result(info, checked)


def _result(info, checked):
    avail = bool(info.get("latest")) and newer(info["latest"])
    can = avail and install.frozen() and _asset_ok(info.get("download")) and bool(info.get("sha256"))
    msg = ("No releases published yet." if info.get("none") else
           f"Version {info['latest']} is available." if avail else "You're on the latest version.")
    if avail and not can:
        msg += " Download it from the releases page." if install.frozen() else " (Running from source: git pull to update.)"
    return {"ok": True, "current": VERSION, "checked": checked, "available": avail, "can_install": can,
            "message": msg, **{k: info.get(k) for k in ("latest", "name", "notes", "published", "page", "size")}}


def cached():
    s = load_settings()
    if not s.get("update_info"):
        return {"ok": True, "current": VERSION, "available": False, "checked": None, "auto": auto_enabled()}
    return {**_result(s["update_info"], s.get("update_checked")), "auto": auto_enabled()}


def auto_enabled():
    return load_settings().get("update_auto", True)


def set_auto(on):
    save_setting("update_auto", bool(on))
    return {"ok": True, "auto": bool(on)}


def due():
    s = load_settings()
    if not auto_enabled():
        return False
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(s.get("update_checked") or "")
        return age.total_seconds() >= CHECK_EVERY_HOURS * 3600
    except ValueError:
        return True


# ---------------------------------------------------------------- install
def state():
    with _lock:
        return dict(STATE)


def _set(**kw):
    with _lock:
        STATE.update(kw)


def start_install(on_done=None):
    with _lock:
        if STATE["running"]:
            return {"ok": False, "message": "Already updating."}
        STATE.update(running=True, done=0, total=0, stage="Checking GitHub", error="", finished=False)
    threading.Thread(target=_install, args=(on_done,), daemon=True).start()
    return {"ok": True}


def _download(url, dest, size):
    req = urllib.request.Request(url, headers={**UA, "Accept": "application/octet-stream"})
    h = hashlib.sha256()
    got = 0
    with _opener.open(req, timeout=60) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            got += len(chunk)
            if got > MAX_BYTES or (size and got > size):
                raise ValueError("download is bigger than the release says")
            h.update(chunk)
            f.write(chunk)
            _set(done=got)
    if size and got != size:
        raise ValueError("download was cut short")
    return h.hexdigest()


def _install(on_done):
    tmp = os.path.join(DATA_DIR, "update-PCShield.exe")  # admin-only folder: nothing can swap it after the check
    try:
        if not install.frozen():
            raise RuntimeError("Running from source - use git pull to update.")
        info = check(force=True)
        if not info.get("ok"):
            raise RuntimeError(info.get("message") or "Couldn't check for updates.")
        if not info.get("available"):
            raise RuntimeError("Already up to date.")
        rel = load_settings().get("update_info") or {}
        if not _asset_ok(rel.get("download")):
            raise RuntimeError(f"That release has no {ASSET} - download it from the releases page.")
        if not rel.get("sha256"):
            raise RuntimeError("GitHub didn't list a checksum for the download, so it can't be verified. "
                               "Download it from the releases page instead.")
        _set(stage=f"Downloading {rel['latest']}", total=rel.get("size") or 0)
        got = _download(rel["download"], tmp, rel.get("size") or 0)
        if got != rel["sha256"]:
            raise RuntimeError("The download didn't match GitHub's checksum - not installing it.")
        _set(stage="Installing")
        targets = [sys.executable]
        if os.path.isfile(install.INSTALL_EXE) and not install._same(install.INSTALL_EXE, sys.executable):
            targets.append(install.INSTALL_EXE)
        for t in targets:
            install.replace_file(tmp, t)
        if os.path.isfile(install.INSTALL_EXE):
            save_setting("installed_version", rel["latest"])
        log(f"updated {VERSION} -> {rel['latest']} ({', '.join(targets)})")
        _set(stage=f"Updated to {rel['latest']} - restarting", finished=True)
        if on_done:
            on_done(sys.executable)
    except Exception as e:  # noqa
        log(f"update failed: {e}")
        _set(error=str(e) or e.__class__.__name__, stage="")
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
        _set(running=False)
