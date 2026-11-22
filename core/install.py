"""Keeping the admin side of PC Shield out of reach of normal programs.

PC Shield runs as admin. Two things would let any program running as the user borrow that:

1. The no-prompt shortcut, start-with-Windows and scheduled scans are Task Scheduler tasks that run an exe
   with highest privileges. If that exe sits in Downloads, anything can replace it and then start the task
   (no prompt). So the tasks always point at a copy in Program Files, which only admins can change.
2. Reports, settings and VPN configs are acted on with admin rights (uninstall, registry fixes, Defender
   exclusions, the WireGuard service reads the config). They live in ProgramData\\PCShield, locked so
   only admins and SYSTEM can write there.
"""
import hashlib
import os
import secrets
import shutil
import sys
import time

from .util import (DATA_DIR, OLD_DATA_DIR, PROGRAM_FILES, REPORT_DIR, VPN_DIR, load_settings, log, make_dirs,
                   ps, ps_out, ps_quote, run, save_setting)
from .version import VERSION

INSTALL_DIR = os.path.join(PROGRAM_FILES, "PC Shield")
INSTALL_EXE = os.path.join(INSTALL_DIR, "PCShield.exe")
ADMINS, SYSTEM, USERS = "*S-1-5-32-544", "*S-1-5-18", "*S-1-5-32-545"  # SIDs: work on any Windows language

TASKS = ["PC Shield", "PC Shield Launcher", "PC Shield Quick Scan", "PC Shield Deep Scan"]


def frozen():
    return bool(getattr(sys, "frozen", False))


def version_tuple(v):
    """'v1.10.2' -> (1, 10, 2); anything unparsable -> None."""
    parts = str(v or "").strip().lstrip("vV").split("-")[0].split(".")
    try:
        return tuple(int(p) for p in parts) if parts and parts[0] != "" else None
    except ValueError:
        return None


def _same(a, b):
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def replace_file(src, dst):
    """Copy src over dst, even while dst is running (a running exe can be renamed, not overwritten)."""
    new = dst + ".new"
    shutil.copyfile(src, new)
    try:
        os.replace(new, dst)
    except PermissionError:
        os.replace(dst, f"{dst}.{secrets.token_hex(4)}.old")
        os.replace(new, dst)


def cleanup_old_copies():
    for d in {INSTALL_DIR, os.path.dirname(sys.executable)} if frozen() else {INSTALL_DIR}:
        try:
            for n in os.listdir(d):
                if n.lower().startswith("pcshield.exe.") and n.lower().endswith((".old", ".new")):
                    try:
                        os.remove(os.path.join(d, n))
                    except OSError:
                        pass  # still running - next start
        except OSError:
            pass


def task_target(args=""):
    """(exe, args) for an elevated task. Frozen: the protected Program Files copy."""
    if frozen():
        return INSTALL_EXE, args
    script = os.path.abspath(sys.modules["__main__"].__file__)
    pyw = sys.executable.replace("python.exe", "pythonw.exe")
    return pyw, f'"{script}" {args}'.strip()


def ensure_installed():
    """Put (or refresh) this exe at Program Files\\PC Shield\\PCShield.exe before a task points at it."""
    if not frozen() or _same(sys.executable, INSTALL_EXE):
        return INSTALL_EXE
    os.makedirs(INSTALL_DIR, exist_ok=True)
    if not (os.path.isfile(INSTALL_EXE) and os.path.getsize(INSTALL_EXE) == os.path.getsize(sys.executable)
            and _sha256(INSTALL_EXE) == _sha256(sys.executable)):
        replace_file(sys.executable, INSTALL_EXE)
    save_setting("installed_version", VERSION)
    return INSTALL_EXE


def installed_info():
    return {"path": INSTALL_EXE, "installed": os.path.isfile(INSTALL_EXE),
            "running_installed": frozen() and _same(sys.executable, INSTALL_EXE),
            "version": load_settings().get("installed_version")}


def startup_maintenance():
    """At launch: drop leftovers from an update, refresh the protected copy if this exe is newer,
    and move tasks made by older versions (pointing at Downloads) onto the protected copy."""
    cleanup_old_copies()
    if not frozen():
        return
    try:
        if os.path.isfile(INSTALL_EXE) and not _same(sys.executable, INSTALL_EXE):
            have = version_tuple(load_settings().get("installed_version")) or (0,)
            if version_tuple(VERSION) >= have:
                ensure_installed()
        retarget_tasks()
    except Exception as e:  # noqa
        log(f"startup maintenance: {e}")


def retarget_tasks():
    names = ",".join(ps_quote(n) for n in TASKS)
    exe = ps_quote(INSTALL_EXE)
    stale = ps_out(f"foreach ($n in @({names})) {{ $t=Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue; "
                   f"if ($t -and $t.Actions[0].Execute -ne {exe}) {{ $n }} }}")
    if not stale:
        return []
    ensure_installed()
    out = ps_out(f"foreach ($n in @({names})) {{ $t=Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue; "
                 f"if ($t -and $t.Actions[0].Execute -ne {exe}) {{ $t.Actions[0].Execute={exe}; "
                 f"Set-ScheduledTask -InputObject $t | Out-Null; $n }} }}")
    moved = [n for n in out.splitlines() if n.strip()]
    if moved:
        log(f"tasks now run the protected copy: {', '.join(moved)}")
    return moved


# ---------------------------------------------------------------- protected data folder
WRITE_MASK = 0x500D0156  # write/append/delete/change-permissions/take-ownership, incl. generic write/all


def _is_link(path):
    try:
        return bool(os.lstat(path).st_file_attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
    except (OSError, AttributeError):
        return os.path.islink(path)


def acl_locked(path):
    """True when only Administrators/SYSTEM can change the folder (owner too) and nothing is inherited."""
    out = ps_out(
        f"$a=Get-Acl -LiteralPath {ps_quote(path)}; $sid=[Security.Principal.SecurityIdentifier]; "
        f"$o=$a.GetOwner($sid).Value; $ok=($o -in 'S-1-5-32-544','S-1-5-18') -and $a.AreAccessRulesProtected; "
        f"foreach ($r in $a.GetAccessRules($true,$true,$sid)) {{ if ($r.AccessControlType -eq 'Allow' -and "
        f"$r.IdentityReference.Value -notin 'S-1-5-32-544','S-1-5-18' -and ([long]$r.FileSystemRights -band {WRITE_MASK})) "
        f"{{ $ok=$false }} }}; if ($ok) {{ 'locked' }}")
    return out.strip() == "locked"


def _lock(path, users_read=True):
    grants = ["/grant:r", f"{SYSTEM}:(OI)(CI)F", "/grant:r", f"{ADMINS}:(OI)(CI)F"]
    if users_read:
        grants += ["/grant:r", f"{USERS}:(OI)(CI)RX"]
    run(["icacls", path, "/setowner", ADMINS])
    code, out = run(["icacls", path, "/inheritance:r"] + grants)
    return code == 0


def _aside(path):
    new = f"{path}.untrusted-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}"
    os.replace(path, new)  # renames the link itself if it is one
    log(f"{path} wasn't admin-only - moved it to {new}")
    return new


def secure_data_dir():
    """Make ProgramData\\PCShield admin-only. A folder that isn't (made before locking, or planted by
    another program) is moved aside and only its known data files are carried over."""
    if os.name != "nt":
        return True
    leftovers = []
    for _ in range(3):
        if os.path.lexists(DATA_DIR) and (_is_link(DATA_DIR) or not os.path.isdir(DATA_DIR)):
            leftovers.append(_aside(DATA_DIR))
        if os.path.isdir(DATA_DIR) and acl_locked(DATA_DIR):
            break
        if os.path.isdir(DATA_DIR):
            leftovers.append(_aside(DATA_DIR))
        os.makedirs(DATA_DIR)
        _lock(DATA_DIR)
        if os.listdir(DATA_DIR) or not acl_locked(DATA_DIR):
            continue  # something got in before the lock - start over
        break
    else:
        log("couldn't lock the data folder")
        return False
    make_dirs()
    _lock(VPN_DIR, users_read=False)  # private keys: admins/SYSTEM only
    for old in leftovers:
        _carry_over(old)
    return True


def _copy_known(src_root, max_bytes=20_000_000):
    """Copy only plain data files we understand (never links, never anything else)."""
    copied = 0
    for sub, exts in (("", (".json",)), ("reports", (".json",)), ("vpn", (".conf",))):
        d = os.path.join(src_root, sub)
        if not os.path.isdir(d) or _is_link(d):
            continue
        for n in os.listdir(d):
            src = os.path.join(d, n)
            if not n.lower().endswith(exts) or _is_link(src) or not os.path.isfile(src) or os.path.getsize(src) > max_bytes:
                continue
            if sub == "" and n.lower() != "settings.json":
                continue
            dst = os.path.join(DATA_DIR, sub, n)
            if not os.path.exists(dst):
                shutil.copyfile(src, dst)
                copied += 1
    return copied


def _carry_over(old):
    try:
        if not _is_link(old):
            _copy_known(old)
    except OSError as e:
        log(f"carry over from {old}: {e}")
    _remove_tree(old)


def _remove_tree(root):
    """Delete a moved-aside folder unless it holds links (then leave it - never follow them as admin)."""
    if _is_link(root):
        try:
            os.rmdir(root) if os.path.isdir(root) else os.remove(root)  # removes the link, not its target
        except OSError:
            pass
        return
    for d, dirs, files in os.walk(root):
        if any(_is_link(os.path.join(d, n)) for n in dirs + files):
            return
    shutil.rmtree(root, ignore_errors=True)


def migrate_old_data():
    """1.2 kept data in %LOCALAPPDATA%\\PCShield. Copy it in once, then remove the VPN keys and reports
    from the old per-user folder."""
    if load_settings().get("migrated_from_localappdata") or not os.path.isdir(OLD_DATA_DIR) or _is_link(OLD_DATA_DIR):
        return 0
    copied = _copy_known(OLD_DATA_DIR)
    for sub in ("vpn", "reports"):
        d = os.path.join(OLD_DATA_DIR, sub)
        if os.path.isdir(d) and not _is_link(d):
            for n in os.listdir(d):
                p = os.path.join(d, n)
                if not _is_link(p) and os.path.isfile(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
    try:
        os.remove(os.path.join(OLD_DATA_DIR, "settings.json"))
    except OSError:
        pass
    save_setting("migrated_from_localappdata", True)
    log(f"moved {copied} file(s) from {OLD_DATA_DIR}")
    try:
        from . import vpn
        vpn.repoint_services()  # a connected tunnel's service still names the old config path
    except Exception as e:  # noqa
        log(f"repoint VPN services: {e}")
    return copied
