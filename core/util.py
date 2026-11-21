"""Shared helpers: PowerShell calls, registry access, settings storage."""
import json
import os
import subprocess
import sys
import threading
import winreg
from datetime import datetime, timedelta, timezone

CREATE_NO_WINDOW = 0x08000000

DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "PCShield")
REPORT_DIR = os.path.join(DATA_DIR, "reports")
VPN_DIR = os.path.join(DATA_DIR, "vpn")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
for _d in (DATA_DIR, REPORT_DIR, VPN_DIR):
    os.makedirs(_d, exist_ok=True)

LOG_FILE = os.path.join(DATA_DIR, "pcshield.log")
_settings_lock = threading.Lock()
_log_lock = threading.Lock()


def log(msg):
    """Errors go here (the windowed .exe has no console). Send this file when something breaks."""
    try:
        with _log_lock:
            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 1_000_000:
                os.replace(LOG_FILE, LOG_FILE + ".old")
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}\n")
    except OSError:
        pass


# ---------------------------------------------------------------- PowerShell
def ps(command, timeout=600):
    """Run PowerShell. Never raises on a hang/timeout - returns (stdout, stderr, exit code) instead."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
             "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + command],
            capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW,
            encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout} s", 124
    except OSError as e:
        return "", str(e), 127
    return r.stdout or "", r.stderr or "", r.returncode


def ps_out(command, timeout=600):
    return ps(command, timeout)[0].strip()


def ps_json(command, timeout=600):
    out = ps_out(f"$ProgressPreference='SilentlyContinue'; {command} | ConvertTo-Json -Depth 5 -Compress", timeout)
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def run(cmd, timeout=120, shell=False):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=shell,
                           creationflags=CREATE_NO_WINDOW, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return 124, f"Timed out after {timeout} s"
    except OSError as e:
        return 127, str(e)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


MEDIA_TYPES = {"0": "Unspecified", "3": "HDD", "4": "SSD", "5": "SCM"}
HEALTH = {"0": "Healthy", "1": "Warning", "2": "Unhealthy", "5": "Unknown"}
BUS_TYPES = {"1": "SCSI", "3": "ATA", "6": "Fibre Channel", "7": "USB", "8": "RAID", "10": "SAS", "11": "SATA",
             "12": "SD", "13": "MMC", "15": "File Backed Virtual", "16": "Storage Spaces", "17": "NVMe"}


def enum_name(value, table):
    """Get-PhysicalDisk enum -> name, whether PowerShell gave us 'SSD' or 4."""
    s = str(value if value is not None else "").strip()
    return table.get(s, s)


def ps_quote(s):
    return "'" + str(s).replace("'", "''") + "'"


# ---------------------------------------------------------------- registry
HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}


def reg_get(hive, path, name, default=None):
    try:
        with winreg.OpenKey(HIVES[hive], path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default


def reg_set(hive, path, name, value, kind=winreg.REG_DWORD):
    with winreg.CreateKeyEx(HIVES[hive], path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
        winreg.SetValueEx(k, name, 0, kind, value)


def reg_delete(hive, path, name):
    try:
        with winreg.OpenKey(HIVES[hive], path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
            winreg.DeleteValue(k, name)
    except FileNotFoundError:
        pass


def reg_subkeys(hive, path):
    try:
        with winreg.OpenKey(HIVES[hive], path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return [winreg.EnumKey(k, i) for i in range(winreg.QueryInfoKey(k)[0])]
    except OSError:
        return []


def filetime_to_iso(ft):
    if not ft:
        return None
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(ft) / 10)
        return dt.astimezone().isoformat(timespec="seconds")
    except (OverflowError, ValueError):
        return None


# ---------------------------------------------------------------- settings
def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_setting(key, value):
    with _settings_lock:
        s = load_settings()
        s[key] = value
        tmp = SETTINGS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
        os.replace(tmp, SETTINGS_FILE)


def human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def exe_path():
    """Command that relaunches this app (frozen exe or python + script)."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    script = os.path.abspath(sys.modules["__main__"].__file__)
    pyw = sys.executable.replace("python.exe", "pythonw.exe")
    return f'"{pyw}" "{script}"'
