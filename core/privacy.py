"""Windows privacy toggles, remote-desktop exposure, webcam/microphone usage."""
import re
import winreg

import psutil

from . import system
from .util import reg_get, reg_set, reg_delete, reg_subkeys, filetime_to_iso

CDM = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
D = winreg.REG_DWORD

# each value: (hive, path, name, allow_value, deny_value)   allow_value None => delete value
TOGGLES = [
    {"id": "adid", "group": "Advertising and tracking", "title": "Block apps from using your advertising ID",
     "desc": "Stops apps building an ad profile from what you do.",
     "values": [("HKCU", r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 1, 0)]},
    {"id": "start", "group": "Advertising and tracking", "title": "Hide suggested apps and promotions in Start",
     "desc": "Removes sponsored apps and 'recommendations' from the Start menu.",
     "values": [("HKCU", CDM, "SystemPaneSuggestionsEnabled", 1, 0), ("HKCU", CDM, "SubscribedContent-338388Enabled", 1, 0),
                ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_IrisRecommendations", 1, 0)]},
    {"id": "lock", "group": "Advertising and tracking", "title": "Hide ads and 'fun facts' on the lock screen",
     "desc": "Stops promotional content on the lock screen.",
     "values": [("HKCU", CDM, "RotatingLockScreenOverlayEnabled", 1, 0), ("HKCU", CDM, "SubscribedContent-338387Enabled", 1, 0)]},
    {"id": "notif", "group": "Advertising and tracking", "title": "Block tips and offers in notifications",
     "desc": "Stops 'get the most out of Windows' nags and offers.",
     "values": [("HKCU", CDM, "SubscribedContent-338389Enabled", 1, 0), ("HKCU", CDM, "SubscribedContent-310093Enabled", 1, 0),
                ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement", "ScoobeSystemSettingEnabled", 1, 0)]},
    {"id": "diag", "group": "Windows privacy", "title": "Limit diagnostic data and tailored experiences",
     "desc": "Sends Microsoft only the required minimum and stops ads/tips based on it.",
     "values": [("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 1, 0),
                ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", None, 1)]},
    {"id": "settings", "group": "Windows privacy", "title": "Hide suggestions in the Settings app",
     "desc": "Hides suggested content in Settings.",
     "values": [("HKCU", CDM, "SubscribedContent-338393Enabled", 1, 0), ("HKCU", CDM, "SubscribedContent-353694Enabled", 1, 0),
                ("HKCU", CDM, "SubscribedContent-353696Enabled", 1, 0)]},
    {"id": "websearch", "group": "Windows privacy", "title": "Keep Start and taskbar search off the web (no Bing)",
     "desc": "Searching for a file won't send what you type to Bing.",
     "values": [("HKCU", r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", None, 1),
                ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 1, 0)]},
    {"id": "activity", "group": "Windows privacy", "title": "Stop Windows keeping your activity history",
     "desc": "Stops Windows recording which apps, files and sites you use.",
     "values": [("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", None, 0),
                ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", None, 0)]},
]


def _allowed(t):
    return not all(reg_get(h, p, n) == deny for h, p, n, _, deny in t["values"])


def get_toggles():
    return [{k: t[k] for k in ("id", "group", "title", "desc")} | {"allowed": _allowed(t),
            "needs_admin": any(v[0] == "HKLM" for v in t["values"])} for t in TOGGLES]


def set_toggle(tid, allow):
    t = next(x for x in TOGGLES if x["id"] == tid)
    for h, p, n, allow_v, deny_v in t["values"]:
        target = allow_v if allow else deny_v
        if target is None:
            reg_delete(h, p, n)
        else:
            reg_set(h, p, n, target, D)
    return {"ok": True, "allowed": _allowed(t)}


def set_all(allow=False):
    errors = []
    for t in TOGGLES:
        try:
            set_toggle(t["id"], allow)
        except PermissionError:
            errors.append(t["title"])
    return {"ok": not errors, "errors": errors}


# ---------------------------------------------------------------- remote access
TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
RA = r"SYSTEM\CurrentControlSet\Control\Remote Assistance"


def remote_access():
    running = {}
    for p in psutil.process_iter(["name"]):
        n = (p.info["name"] or "").lower()
        running.setdefault(n, []).append(p.pid)
    tools = []
    progs = system.installed_programs()
    for key, procs, note in system.REMOTE_TOOLS:
        pat = re.compile(r"\b" + re.escape(key) + r"\b", re.I)  # whole words: 'atera' must not match 'Collateral'
        inst = next((p for p in progs if pat.search(p["name"])), None)
        live = [pn for pn in procs if pn in running]
        if not (inst or live):
            continue
        same = next((t for t in tools if (inst and t["uninstall_id"] == inst["id"]) or (live and set(live) & set(t["processes"]))), None)
        if same:  # e.g. ScreenConnect and ConnectWise are the same program
            continue
        tools.append({"key": key, "name": inst["name"] if inst else key.title(), "installed": bool(inst),
                      "uninstall_id": inst["id"] if inst else None, "running": bool(live),
                      "processes": live, "note": note})
    return {
        "rdp": reg_get("HKLM", TS, "fDenyTSConnections", 1) == 0,
        "assist": reg_get("HKLM", RA, "fAllowToGetHelp", 0) == 1,
        "tools": tools,
    }


def set_windows_remote(which, enabled):
    if which == "rdp":
        reg_set("HKLM", TS, "fDenyTSConnections", 0 if enabled else 1)
    else:
        reg_set("HKLM", RA, "fAllowToGetHelp", 1 if enabled else 0)
    return {"ok": True}


def kill_tool(processes):
    processes = [str(x).lower() for x in (processes or [])]
    n = 0
    for p in psutil.process_iter(["name"]):
        if (p.info["name"] or "").lower() in processes:
            try:
                p.kill()
                n += 1
            except psutil.Error:
                pass
    return {"ok": True, "killed": n}


# ---------------------------------------------------------------- camera / mic
CONSENT = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"


def _pretty(app):
    if "#" in app:
        return app.replace("#", "\\").split("\\")[-1], app.replace("#", "\\")
    return app.split("_")[0].replace("Microsoft.", "").replace(".", " "), app


def device_usage(cap):
    rows = []
    for hive in ("HKCU", "HKLM"):
        base = f"{CONSENT}\\{cap}"
        for sub in reg_subkeys(hive, base):
            paths = [(f"{base}\\{sub}", sub)] if sub != "NonPackaged" else \
                    [(f"{base}\\NonPackaged\\{s}", s) for s in reg_subkeys(hive, f"{base}\\NonPackaged")]
            for path, app in paths:
                start = reg_get(hive, path, "LastUsedTimeStart", 0) or 0
                stop = reg_get(hive, path, "LastUsedTimeStop", 0) or 0
                if not start:
                    continue
                name, full = _pretty(app)
                rows.append({"app": name, "path": full, "last_start": filetime_to_iso(start),
                             "last_stop": filetime_to_iso(stop), "active": stop == 0 or stop < start, "_t": start})
    rows.sort(key=lambda r: r["_t"], reverse=True)
    for r in rows:
        r.pop("_t")
    return {"allowed": reg_get("HKCU", f"{CONSENT}\\{cap}", "Value", "Allow") != "Deny", "apps": rows}


def set_device_access(cap, allow):
    reg_set("HKCU", f"{CONSENT}\\{cap}", "Value", "Allow" if allow else "Deny", winreg.REG_SZ)
    return {"ok": True}
