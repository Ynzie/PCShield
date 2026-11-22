"""Stand-ins for Windows-only modules (registry, PowerShell, window APIs) so PC Shield's
Python logic can be tested on any OS. Imported by test_backend.py before the app code."""
import os
import sys
import types

# ---------------------------------------------------------------- fake winreg
winreg = types.ModuleType("winreg")
winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE = "HKCU", "HKLM"
for n, v in dict(KEY_READ=1, KEY_SET_VALUE=2, KEY_WOW64_64KEY=256, KEY_ALL_ACCESS=3,
                 REG_DWORD=4, REG_SZ=1, REG_BINARY=3, REG_QWORD=11, REG_EXPAND_SZ=2).items():
    setattr(winreg, n, v)
REG = {}  # (hive, lowerpath) -> {"name": str, "values": {lowername: (realname, value, type)}}


def _norm(hive, path):
    return (hive, "\\".join(p for p in path.lower().split("\\") if p))


class _Key:
    def __init__(self, hive, path):
        self.hive, self.path = hive, path

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def Close(self):
        pass


def _resolve(key_or_hive, sub):
    if isinstance(key_or_hive, _Key):
        return key_or_hive.hive, (key_or_hive.path + "\\" + sub) if sub else key_or_hive.path
    return key_or_hive, sub


def OpenKey(k, sub, reserved=0, access=1):
    hive, path = _resolve(k, sub)
    if _norm(hive, path) not in REG:
        raise FileNotFoundError(2, "not found", path)
    return _Key(hive, path)


def CreateKeyEx(k, sub, reserved=0, access=2):
    hive, path = _resolve(k, sub)
    parts = [p for p in path.split("\\") if p]
    for i in range(1, len(parts) + 1):
        REG.setdefault(_norm(hive, "\\".join(parts[:i])), {"name": parts[i - 1], "values": {}})
    return _Key(hive, path)


def QueryValueEx(k, name):
    vals = REG[_norm(k.hive, k.path)]["values"]
    if name.lower() not in vals:
        raise FileNotFoundError(2, "no value", name)
    _, v, t = vals[name.lower()]
    return v, t


def SetValueEx(k, name, reserved, typ, value):
    REG[_norm(k.hive, k.path)]["values"][name.lower()] = (name, value, typ)


def DeleteValue(k, name):
    vals = REG[_norm(k.hive, k.path)]["values"]
    if name.lower() not in vals:
        raise FileNotFoundError(2, "no value", name)
    del vals[name.lower()]


def _children(k):
    h, p = _norm(k.hive, k.path)
    depth = len(p.split("\\")) if p else 0
    return sorted(REG[(hh, pp)]["name"] for (hh, pp) in REG
                  if hh == h and pp.startswith(p + "\\") and len(pp.split("\\")) == depth + 1)


def EnumKey(k, i):
    c = _children(k)
    if i >= len(c):
        raise OSError(259, "no more")
    return c[i]


def EnumValue(k, i):
    vals = list(REG[_norm(k.hive, k.path)]["values"].values())
    if i >= len(vals):
        raise OSError(259, "no more")
    return vals[i]


def QueryInfoKey(k):
    return len(_children(k)), len(REG[_norm(k.hive, k.path)]["values"]), 0


for f in (OpenKey, CreateKeyEx, QueryValueEx, SetValueEx, DeleteValue, EnumKey, EnumValue, QueryInfoKey):
    setattr(winreg, f.__name__, f)
sys.modules["winreg"] = winreg


def reg_put(hive, path, name, value, typ=4):
    k = CreateKeyEx(hive, path)
    SetValueEx(k, name, 0, typ, value)


# ---------------------------------------------------------------- environment
import tempfile as _tf
_TMP = _tf.mkdtemp(prefix="pcshield-test-")
os.environ["LOCALAPPDATA"] = os.path.join(_TMP, "localappdata")  # never touch real app data
os.environ.setdefault("SystemRoot", r"C:\Windows")
os.environ.setdefault("USERPROFILE", r"C:\Users\ynzer")
os.environ.setdefault("ProgramFiles", r"C:\Program Files")
os.environ.setdefault("ProgramFiles(x86)", r"C:\Program Files (x86)")
os.environ["ProgramData"] = os.path.join(_TMP, "programdata")  # data folder (util.DATA_DIR) goes here in tests
os.environ.setdefault("PUBLIC", r"C:\Users\Public")
os.environ.setdefault("APPDATA", r"C:\Users\ynzer\AppData\Roaming")
os.environ["TEMP"] = os.path.join(_TMP, "temp")
os.makedirs(os.environ["TEMP"], exist_ok=True)

# ---------------------------------------------------------------- fake PowerShell
PS_RULES = []   # list of (substring, (stdout, stderr, code)) - first match wins
PS_LOG = []


def fake_ps(command, timeout=600):
    PS_LOG.append(command)
    for sub, resp in PS_RULES:
        if sub in command:
            return resp(command) if callable(resp) else resp
    return "", "", 0

import ctypes as _ct
if not hasattr(_ct, "WINFUNCTYPE"):
    _ct.WINFUNCTYPE = _ct.CFUNCTYPE
