"""File shredder: overwrite, rename, truncate, delete. SSD-aware."""
import os
import secrets
import stat
import threading
import time

from .util import ps, ps_json, run, enum_name, MEDIA_TYPES

REPARSE = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT (symlinks, junctions, OneDrive placeholders)

CHUNK = 1024 * 1024
STATE = {"running": False, "done": 0, "total": 0, "current": "", "errors": [], "log": [], "finished": None}
_lock = threading.Lock()

BLOCKED = [os.path.normcase(os.path.expandvars(p)).rstrip("\\") for p in (
    r"%SystemRoot%", r"%ProgramFiles%", r"%ProgramFiles(x86)%", r"%ProgramData%", r"%PUBLIC%",
    r"%USERPROFILE%", r"%USERPROFILE%\Desktop", r"%USERPROFILE%\Documents", r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\Pictures", r"%USERPROFILE%\AppData", r"%USERPROFILE%\Videos", r"%USERPROFILE%\Music",
    r"%USERPROFILE%\OneDrive", r"%OneDrive%") if "%" not in os.path.expandvars(p)]


def _blocked(path):
    p = os.path.normcase(os.path.abspath(path)).rstrip("\\")
    if len(p) <= 3:  # drive root
        return "a whole drive"
    sysroot = os.path.normcase(os.path.expandvars("%SystemRoot%"))
    for b in BLOCKED:
        if p == b:
            return "a system or profile folder"
        if b.startswith(p + "\\"):  # e.g. C:\Users - it contains everyone's profile
            return "a folder that contains system or profile folders"
    for b in (sysroot, os.path.normcase(os.path.expandvars("%ProgramFiles%")),
              os.path.normcase(os.path.expandvars("%ProgramFiles(x86)%"))):
        if p.startswith(b + "\\"):
            return "inside Windows or Program Files"
    return None


_MEDIA = {"at": 0, "map": {}}


def media_map():
    """{'C': 'SSD', 'D': 'HDD', ...} for every lettered partition - one PowerShell call, cached 60 s."""
    if time.time() - _MEDIA["at"] > 60:
        rows = ps_json("$pd=@{}; Get-PhysicalDisk | ForEach-Object { $pd[[string]$_.DeviceId]=[string]$_.MediaType }; "
                       "Get-Partition | Where-Object DriveLetter | ForEach-Object { [pscustomobject]@{ "
                       "L=[string]$_.DriveLetter; M=$pd[[string]$_.DiskNumber] } }")
        _MEDIA["map"] = {str(r.get("L", "")).upper(): enum_name(r.get("M"), MEDIA_TYPES) or "Unknown" for r in rows}
        _MEDIA["at"] = time.time()
    return _MEDIA["map"]


def drive_media(path):
    letter = os.path.splitdrive(os.path.abspath(path))[0].rstrip(":").upper()
    if not (len(letter) == 1 and letter.isalpha()):
        return "Unknown"
    return media_map().get(letter, "Unknown")


def drives():
    """Drives that actually have a disk in them (an empty card reader would pop up 'no disk in drive')."""
    import psutil
    m = media_map()
    out = []
    for p in psutil.disk_partitions(all=False):
        letter = p.device[:1].upper()
        if letter.isalpha() and p.fstype and ("fixed" in p.opts or "removable" in p.opts):  # no fstype = no media
            out.append({"letter": letter, "media": m.get(letter, "Unknown")})
    return out


def _is_link(path):
    """Symlink or junction - never follow these (they can point outside the chosen folder)."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if os.path.islink(path):
        return True
    if not getattr(st, "st_file_attributes", 0) & REPARSE:
        return False
    # junctions, symlinks and app-exec aliases redirect elsewhere; OneDrive/cloud placeholders are the file itself
    return getattr(st, "st_reparse_tag", 0) in (0xA0000003, 0xA000000C, 0x8000001B)


def _walk(top):
    """Like os.walk(topdown=False) but never descends into junctions/symlinks.
    Yields (files, dirs, links) - links are removed as links, their targets are never touched."""
    files, dirs, links = [], [], []
    stack = [top]
    while stack:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            if _is_link(e.path):
                links.append(e.path)
            elif e.is_dir(follow_symlinks=False):
                dirs.append(e.path)
                stack.append(e.path)
            elif e.is_file(follow_symlinks=False):
                files.append(e.path)
    dirs.sort(key=lambda x: x.count(os.sep), reverse=True)  # deepest first
    return files, dirs, links


def inspect(paths):
    out = []
    for p in paths:
        size, count = 0, 0
        if os.path.isdir(p) and not _is_link(p):
            for f in _walk(p)[0]:
                try:
                    size += os.path.getsize(f)
                    count += 1
                except OSError:
                    pass
        elif os.path.isfile(p):
            size, count = os.path.getsize(p), 1
        out.append({"path": p, "is_dir": os.path.isdir(p), "size": size, "files": count,
                    "blocked": _blocked(p), "media": drive_media(p)})
    return out


def _shred_file(path, passes):
    if _is_link(path):  # a link: delete the link itself, never overwrite what it points to
        os.remove(path)
        return
    if os.stat(path).st_nlink > 1:  # hard link: overwriting would destroy the other name's data too
        raise OSError(0, "has other hard links - skipped so the other copy isn't destroyed")
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)  # clears read-only on Windows; keeps it readable elsewhere
    size = os.path.getsize(path)
    with open(path, "r+b", buffering=0) as f:
        for i in range(passes):
            f.seek(0)
            left = size
            while left > 0:
                n = min(CHUNK, left)
                f.write(b"\x00" * n if (passes > 1 and i == passes - 1) else secrets.token_bytes(n))
                left -= n
            os.fsync(f.fileno())
        f.truncate(0)
        os.fsync(f.fileno())
    d = os.path.dirname(path)
    cur = path
    for _ in range(3):
        new = os.path.join(d, secrets.token_hex(8))
        os.replace(cur, new)
        cur = new
    os.remove(cur)


def _worker(paths, passes, trim):
    files, dirs = [], []
    for p in paths:
        if _is_link(p):
            files.append(p)  # removed as a link only
        elif os.path.isdir(p):
            f, d, links = _walk(p)
            files += f + links
            dirs += d + [p]
        elif os.path.isfile(p):
            files.append(p)
    with _lock:
        STATE.update(running=True, done=0, total=len(files), errors=[], log=[], finished=None)
    for fp in files:
        with _lock:
            STATE["current"] = fp
        try:
            _shred_file(fp, passes)
            with _lock:
                STATE["log"].append(fp)
        except OSError as e:
            with _lock:
                STATE["errors"].append(f"{fp}: {e.strerror or e}")
        with _lock:
            STATE["done"] += 1
    for d in dirs:
        try:
            if os.listdir(d):
                continue  # something inside was skipped (in use / hard link) - leave the folder and its name alone
            new = os.path.join(os.path.dirname(d), secrets.token_hex(8))
            os.replace(d, new)
            os.rmdir(new)
        except OSError:
            pass
    if trim:
        letters = {os.path.splitdrive(os.path.abspath(p))[0].rstrip(":") for p in paths}
        for L in letters:
            if L and drive_media(f"{L}:\\").upper() == "SSD":
                with _lock:
                    STATE["current"] = f"Sending TRIM to {L}: so the SSD erases freed blocks"
                ps(f"Optimize-Volume -DriveLetter {L} -ReTrim", timeout=900)
    with _lock:
        STATE.update(running=False, current="", finished=time.strftime("%Y-%m-%d %H:%M"))


def start(paths, passes=1, trim=True):
    if STATE["running"]:
        return {"ok": False, "message": "Shredder is already running."}
    bad = [(p, _blocked(p)) for p in paths if _blocked(p)]
    if bad:
        return {"ok": False, "message": f"Refusing to shred {bad[0][0]} ({bad[0][1]})."}
    threading.Thread(target=_worker, args=(paths, max(1, min(int(passes), 7)), trim), daemon=True).start()
    return {"ok": True}


def state():
    with _lock:
        s = dict(STATE)
        s["log"] = s["log"][-50:]
    return s


WIPE = {"running": False, "drive": None, "started": None, "finished": None}


def wipe_free_space(letter):
    letter = str(letter or "").strip().rstrip(":\\").upper()
    if not (len(letter) == 1 and letter.isalpha()):
        return {"ok": False, "message": "Pick a drive."}
    if WIPE["running"]:
        return {"ok": False, "message": "Already wiping."}

    def w():
        WIPE.update(running=True, drive=letter, started=time.time(), finished=None)
        run(["cipher", f"/w:{letter}:\\"], timeout=24 * 3600)
        WIPE.update(running=False, finished=time.strftime("%Y-%m-%d %H:%M"))
    threading.Thread(target=w, daemon=True).start()
    return {"ok": True}


def wipe_state():
    s = dict(WIPE)
    if s["running"]:
        s["elapsed"] = int(time.time() - s["started"])
    return s
