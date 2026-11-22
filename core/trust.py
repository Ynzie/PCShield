"""Trusted publishers. Changes that look like tampering (Defender exclusions, IFEO debuggers...) are not
flagged when the program behind them has a valid digital signature from a publisher on this list.
A valid signature can't be faked, so this is safe in a way that matching folder names would not be."""
import os

import psutil

from . import system
from .util import load_settings, save_setting

DEFAULT_TRUSTED = [
    "Microsoft", "Riot Games", "Valve", "Epic Games", "Electronic Arts", "Activision", "Blizzard",
    "Ubisoft", "Rockstar Games", "Take-Two", "BattlEye", "Even Balance", "Kamu", "NVIDIA",
    "Advanced Micro Devices", "Intel", "Discord", "ASUSTeK", "Micro-Star", "GIGA-BYTE", "Corsair",
    "Razer", "Logitech", "NZXT", "Overwolf", "Mojang", "Bungie", "Wargaming", "Respawn", "Valve Corp",
]


def trusted_list():
    s = load_settings()
    return s.get("trusted_publishers", DEFAULT_TRUSTED)


def add(publisher):
    pub = (publisher or "").strip()
    if not pub:
        return {"ok": False, "message": "Enter a publisher name."}
    lst = trusted_list()
    if not any(p.lower() == pub.lower() for p in lst):
        lst = lst + [pub]
        save_setting("trusted_publishers", lst)
    return {"ok": True, "list": lst}


def remove(publisher):
    lst = [p for p in trusted_list() if p.lower() != (publisher or "").lower()]
    save_setting("trusted_publishers", lst)
    return {"ok": True, "list": lst}


def reset():
    save_setting("trusted_publishers", DEFAULT_TRUSTED)
    return {"ok": True, "list": DEFAULT_TRUSTED}


def is_trusted(signer, status):
    if status != "Valid" or not signer:
        return False
    s = signer.strip().lower()
    for p in trusted_list():
        p = p.strip().lower()
        # whole words only: "Intel" must not trust "Intelligent Tools Ltd", nor "Valve" trust "Valveworks"
        if p and s.startswith(p) and (len(s) == len(p) or not s[len(p)].isalnum()):
            return True
    return False


def _files_for(value, kind):
    v = os.path.expandvars(str(value).strip().strip('"'))
    if kind == "Process":
        if os.path.isabs(v) and os.path.isfile(v):
            return [v]
        name = os.path.basename(v).lower()
        if "*" in name or "?" in name:
            return []
        out = []
        for p in psutil.process_iter(["name", "exe"]):
            if (p.info["name"] or "").lower() == name and p.info["exe"]:
                out.append(p.info["exe"])
        return out[:3] or _find_installed_exe(name)
    if os.path.isfile(v):
        return [v]
    if os.path.isdir(v):
        out, seen = [], 0
        for root, _, files in os.walk(v):
            for f in files:
                seen += 1
                if f.lower().endswith((".exe", ".sys")):
                    out.append(os.path.join(root, f))
                if len(out) >= 8 or seen > 3000:
                    return out
        return out
    return []


def _find_installed_exe(name):
    """Bare process name (e.g. 'vgc.exe' when the game isn't running) -> look in installed programs' folders."""
    sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    if os.path.isfile(os.path.join(sysdir, name)):
        return [os.path.join(sysdir, name)]
    for prog in system.installed_programs():
        loc = prog.get("location")
        if not loc or not os.path.isdir(loc):
            continue
        base_depth = loc.rstrip("\\").count("\\")
        for root, dirs, files in os.walk(loc):
            if root.count("\\") - base_depth >= 2:
                dirs[:] = []
            for f in files:
                if f.lower() == name:
                    return [os.path.join(root, f)]
    return []


def identify(value, kind="Path"):
    """Who signed the program(s) behind a path / process / command line.
    Returns (status, signer). 'Valid' + a name only if every checked file is validly signed by the same publisher."""
    files = _files_for(value, kind)
    if not files:
        return "Unknown", ""
    sigs = system.signatures(files)
    vals = [sigs.get(f.lower(), ("?", "")) for f in files]
    if not vals:
        return "Unknown", ""
    if all(v[0] == "Valid" for v in vals):
        # a game folder can hold exes from several trusted vendors (e.g. Riot + Microsoft runtimes)
        if all(is_trusted(v[1], v[0]) for v in vals):
            riot_first = sorted(vals, key=lambda v: v[1].lower().startswith("microsoft"))
            return "Valid", riot_first[0][1]
        untrusted = next(v for v in vals if not is_trusted(v[1], v[0]))
        return "Valid", untrusted[1]
    bad = next((v for v in vals if v[0] != "Valid"), vals[0])
    return bad[0], bad[1]
