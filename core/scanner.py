"""
Scanner: Microsoft Defender engine for malware + our own checks for
PUPs (potentially unwanted programs), PUMs (malicious registry/policy
modifications) and suspicious startup items. Reports saved as JSON.
"""
import glob
import json
import os
import re
import shutil
import sys
import threading
import time
import uuid

from . import system, trust
from .util import (REPORT_DIR, DATA_DIR, ps, ps_json, ps_out, ps_quote, reg_get, reg_set, reg_delete,
                   load_settings, save_setting, now_iso, run)

THREAT_STATUS = {0: "Unknown", 1: "Detected", 2: "Cleaned", 3: "Quarantined", 4: "Removed", 5: "Allowed",
                 6: "Blocked", 102: "Quarantine failed", 103: "Remove failed", 104: "Allow failed",
                 105: "Abandoned", 107: "Block failed"}
UNRESOLVED = {1, 5, 102, 103, 105, 107}
SEVERITY = {0: "Unknown", 1: "Low", 2: "Moderate", 4: "High", 5: "Severe"}

POLICIES_SYS = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
POLICIES_EXP = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
DEF_POL = r"SOFTWARE\Policies\Microsoft\Windows Defender"
WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
HOSTS = os.path.expandvars(r"%SystemRoot%\System32\drivers\etc\hosts")
USERINIT = os.path.expandvars(r"%SystemRoot%\system32\userinit.exe")

# (hive, path, value, bad_value or callable, name, fix ('delete'|('set', value)))
PUM_RULES = [
    ("HKCU", POLICIES_SYS, "DisableTaskMgr", 1, "Task Manager disabled by policy", "delete"),
    ("HKLM", POLICIES_SYS.replace("Software", "SOFTWARE", 1), "DisableTaskMgr", 1, "Task Manager disabled by policy", "delete"),
    ("HKCU", POLICIES_SYS, "DisableRegistryTools", 1, "Registry Editor disabled by policy", "delete"),
    ("HKLM", POLICIES_SYS.replace("Software", "SOFTWARE", 1), "DisableRegistryTools", 1, "Registry Editor disabled by policy", "delete"),
    ("HKCU", r"Software\Policies\Microsoft\Windows\System", "DisableCMD", lambda v: v in (1, 2), "Command Prompt disabled by policy", "delete"),
    ("HKCU", POLICIES_EXP, "NoRun", 1, "Run dialog disabled by policy", "delete"),
    ("HKCU", POLICIES_EXP, "NoControlPanel", 1, "Control Panel disabled by policy", "delete"),
    ("HKCU", POLICIES_EXP, "NoFolderOptions", 1, "Folder Options disabled by policy", "delete"),
    ("HKLM", POLICIES_SYS.replace("Software", "SOFTWARE", 1), "EnableLUA", 0, "User Account Control (UAC) turned off", ("set", 1)),
    ("HKLM", POLICIES_SYS.replace("Software", "SOFTWARE", 1), "ConsentPromptBehaviorAdmin", 0, "UAC prompts silently auto-approved", ("set", 5)),
    ("HKLM", DEF_POL, "DisableAntiSpyware", 1, "Microsoft Defender disabled by policy", "delete"),
    ("HKLM", DEF_POL + r"\Real-Time Protection", "DisableRealtimeMonitoring", 1, "Defender real-time protection disabled by policy", "delete"),
    ("HKLM", DEF_POL + r"\Real-Time Protection", "DisableBehaviorMonitoring", 1, "Defender behavior monitoring disabled by policy", "delete"),
    ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore", "DisableSR", 1, "System Restore disabled by policy", "delete"),
    ("HKLM", WINLOGON, "Shell", lambda v: v is not None and v.strip().lower() not in ("explorer.exe", ""), "Windows shell replaced (Winlogon Shell)", ("set", "explorer.exe")),
    ("HKLM", WINLOGON, "Userinit", lambda v: v is not None and v.strip().strip(",").lower() not in (USERINIT.lower(), "userinit.exe"), "Extra program injected into sign-in (Winlogon Userinit)", ("set", USERINIT + ",")),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "AutoConfigURL", lambda v: bool(v), "Web traffic routed through a proxy script", "delete"),
]
WATCHED_EXES = ["taskmgr.exe", "regedit.exe", "msconfig.exe", "cmd.exe", "msmpeng.exe", "mpcmdrun.exe",
                "securityhealthsystray.exe", "explorer.exe", "utilman.exe", "sethc.exe", "osk.exe", "magnify.exe",
                "narrator.exe", "displayswitch.exe", "chrome.exe", "firefox.exe", "msedge.exe", "mbam.exe"]

_state_lock = threading.Lock()
STATE = {"running": False, "stage": "", "progress": 0, "kind": None, "started": None, "report_id": None, "error": None,
         "step": 0, "steps": 0, "target": None, "scanned": 0, "total": 0, "rate": 0, "eta": None, "pct": None,
         "cancel": False, "scanned_all": 0}
QUICK_TYPICAL = 6 * 1024 ** 3  # a quick scan usually reads a few GB; only used for a rough bar


# ---------------------------------------------------------------- live progress
# Defender has no public progress API, so progress = bytes Defender's engine (MsMpEng.exe) has read
# since this step started, compared with the space used on the drive being scanned. It's an estimate:
# Defender skips files it already knows are clean, so it often finishes before 100%.
def _engine():
    import psutil
    for p in psutil.process_iter(["name"]):
        if (p.info["name"] or "").lower() == "msmpeng.exe":
            return p
    return None


def _engine_read(p):
    try:
        return p.io_counters().read_bytes
    except Exception:
        return None


class _Progress(threading.Thread):
    def __init__(self, total):
        super().__init__(daemon=True)
        self.total, self.stop_ev = total, threading.Event()
        self.proc = _engine()
        self.base = _engine_read(self.proc) if self.proc else None

    def run(self):
        samples = []
        while not self.stop_ev.wait(2):
            if self.base is None:
                continue
            cur = _engine_read(self.proc)
            if cur is None:
                continue
            done = max(0, cur - self.base)
            now = time.time()
            samples.append((now, done))
            samples[:] = [x for x in samples if now - x[0] <= 30]   # rate over the last 30 s
            rate = (samples[-1][1] - samples[0][1]) / max(1, samples[-1][0] - samples[0][0]) if len(samples) > 1 else 0
            pct = min(0.99, done / self.total) if self.total else None
            eta = int((self.total - done) / rate) if (self.total and rate > 1e6 and done < self.total) else None
            _set(scanned=done, rate=int(rate), pct=pct, eta=eta, total=self.total)

    def stop(self):
        self.stop_ev.set()
        with _state_lock:
            STATE["scanned_all"] = STATE.get("scanned_all", 0) + (STATE.get("scanned") or 0)


def _fixed_drives():
    import psutil
    out = []
    for p in psutil.disk_partitions(all=False):
        if "fixed" in (p.opts or "") and p.mountpoint:
            try:
                out.append((p.mountpoint, psutil.disk_usage(p.mountpoint).used))
            except OSError:
                pass
    return out


LOCK_FILE = os.path.join(DATA_DIR, "scan.lock")


def other_scan():
    """Info about a scan running in ANOTHER PC Shield process (e.g. a scheduled scan), else None."""
    import psutil
    try:
        with open(LOCK_FILE, encoding="utf-8") as f:
            info = json.load(f)
        pid = int(info.get("pid", 0))
        if pid and pid != os.getpid() and psutil.pid_exists(pid) \
                and abs(psutil.Process(pid).create_time() - float(info.get("ctime", 0))) < 2:
            return info
    except (OSError, ValueError, json.JSONDecodeError, Exception):
        pass
    return None


def _take_lock(kind):
    import psutil
    try:
        with open(LOCK_FILE, "w", encoding="utf-8") as f:
            json.dump({"pid": os.getpid(), "ctime": psutil.Process().create_time(), "kind": kind,
                       "started": time.time()}, f)
    except OSError:
        pass


def _drop_lock():
    try:
        with open(LOCK_FILE, encoding="utf-8") as f:
            if int(json.load(f).get("pid", 0)) != os.getpid():
                return
        os.remove(LOCK_FILE)
    except (OSError, ValueError, json.JSONDecodeError):
        pass


def cancel_scan():
    if not scan_state()["running"]:
        return {"ok": False, "message": "No scan is running."}
    _set(cancel=True, stage="Cancelling...")
    run([_mpcmdrun(), "-Scan", "-Cancel"], timeout=60)
    return {"ok": True}


def _set(**kw):
    with _state_lock:
        STATE.update(kw)


def scan_state():
    with _state_lock:
        s = dict(STATE)
    if s["running"] and s["started"]:
        s["elapsed"] = int(time.time() - s["started"])
    if not s["running"]:
        bg = other_scan()
        if bg:
            s["background"] = {"kind": bg.get("kind"), "elapsed": int(time.time() - float(bg.get("started", time.time())))}
    return s


def ignored():
    return set(load_settings().get("ignored", []))


# ---------------------------------------------------------------- checks
def check_pums():
    found = []
    for hive, path, name, bad, title, fix in PUM_RULES:
        v = reg_get(hive, path, name)
        hit = bad(v) if callable(bad) else (v == bad)
        if hit:
            found.append({"id": f"pum|{hive}\\{path}|{name}", "category": "pum", "name": title,
                          "location": f"{hive}\\{path}\\{name} = {v}", "fix": {"hive": hive, "path": path, "name": name, "action": fix}})
    for exe in WATCHED_EXES:
        dbg = reg_get("HKLM", f"{IFEO}\\{exe}", "Debugger")
        if dbg:
            st, signer = trust.identify(system.exe_from_command(dbg), "Path")
            if trust.is_trusted(signer, st):
                continue  # e.g. Process Explorer / Process Hacker replacing Task Manager, signed by a trusted publisher
            found.append({"id": f"pum|IFEO|{exe}", "category": "pum", "name": f"{exe} hijacked (Image File Execution Options)",
                          "location": f"HKLM\\{IFEO}\\{exe}\\Debugger = {dbg}", "signer": signer, "sig_status": st,
                          "note": f"Points to a program signed by {signer} ({st})." if signer else "Points to an unsigned or missing program.",
                          "fix": {"hive": "HKLM", "path": f"{IFEO}\\{exe}", "name": "Debugger", "action": "delete"}})
    try:
        with open(HOSTS, encoding="utf-8", errors="replace") as f:
            entries = [l.split("#")[0].split() for l in f]
        pairs = [(e[0], h.lower()) for e in entries if len(e) >= 2 for h in e[1:]
                 if h.lower() not in ("localhost", "localhost.localdomain")]
        security = ("defender", "malwarebytes", "windowsupdate", "update.microsoft", "virustotal", "avast.com",
                    "norton.com", "mcafee.com", "kaspersky", "eset.com", "bitdefender", "wdcp.microsoft", "smartscreen")
        major = ("google", "bank", "paypal", "microsoft", "facebook", "amazon", "apple", "chase", "wellsfargo", "usaa")
        loop = ("0.0.0.0", "127.0.0.1", "::1", "::")
        # blocking security sites at all, or redirecting major sites to some other server, is what malware does
        sus = [(ip, host) for ip, host in pairs if any(k in host for k in security)
               or (ip not in loop and any(k in host for k in major))]
        if sus:
            found.append({"id": "pum|hosts", "category": "pum", "name": f"Hosts file redirects {len(sus)} security/major site(s)",
                          "location": ", ".join(f"{h} -> {ip}" for ip, h in sus[:5]), "fix": {"action": "hosts"}})
    except OSError:
        pass
    pref = ps_json("Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension")
    if pref:
        p = pref[0]
        for kind, key in (("Path", "ExclusionPath"), ("Process", "ExclusionProcess"), ("Extension", "ExclusionExtension")):
            vals = p.get(key) or []
            if isinstance(vals, str):
                vals = [vals]
            for ex in vals:
                if not ex or "N/A" in str(ex):
                    continue
                if kind == "Extension":
                    st, signer = "Unknown", ""
                else:
                    st, signer = trust.identify(ex, kind)
                    if trust.is_trusted(signer, st):
                        continue  # e.g. Riot Vanguard / game anti-cheat excluding its own folder
                who = (f"Belongs to {signer} (signature: {st})." if signer
                       else "Couldn't tell which program this belongs to (folder empty, missing, or unsigned).")
                found.append({"id": f"pum|defex|{kind}|{ex}", "category": "pum", "name": f"Defender skips this {kind.lower()}",
                              "location": str(ex), "fix": {"action": "defex", "kind": kind, "value": ex},
                              "signer": signer, "sig_status": st,
                              "note": who + " Malware often adds itself here - remove it unless you or a program you trust added it."})
    return found


def check_pups():
    found = []
    for p in system.installed_programs():
        m = system.match_bloat(p["name"], p["publisher"])
        if m and m["level"] == "pup":
            found.append({"id": f"pup|{p['name']}", "category": "pup", "name": p["name"],
                          "location": f"{m['category']} - {p['publisher']}", "note": m["advice"],
                          "fix": {"action": "uninstall", "kind": "win32", "ident": p["id"]}})
    return found


def check_startup():
    found = []
    for s in system.startup_entries():
        if s.get("suspicious"):
            found.append({"id": f"startup|{s['id']}", "category": "startup", "name": s["name"],
                          "location": s["command"], "note": (s.get("why") or "Suspicious startup item") + ".",
                          "fix": {"action": "disable_startup", "ident": s["id"]}})
    return found


def defender_detections(since_epoch=None):
    cmd = ("$n=@{}; $sev=@{}; Get-MpThreat | ForEach-Object { $n[[string]$_.ThreatID]=$_.ThreatName; $sev[[string]$_.ThreatID]=$_.SeverityID }; "
           "Get-MpThreatDetection | ForEach-Object { [pscustomobject]@{ ThreatID=[string]$_.ThreatID; "
           "Name=$n[[string]$_.ThreatID]; Severity=$sev[[string]$_.ThreatID]; Status=[int]$_.ThreatStatusID; "
           "When=([datetime]$_.InitialDetectionTime).ToUniversalTime().ToString('o'); "
           "Epoch=[int64](([datetime]$_.InitialDetectionTime).ToUniversalTime() - [datetime]'1970-01-01').TotalSeconds; "
           "Files=($_.Resources -join '; ') } }")
    rows = ps_json(cmd)
    rows.sort(key=lambda r: r.get("Epoch") or 0, reverse=True)  # newest first; one entry per threat
    seen = set()
    out = []
    for r in rows:
        if r.get("ThreatID") in seen:
            continue
        seen.add(r.get("ThreatID"))
        status = int(r.get("Status") or 0)
        if since_epoch is not None and (r.get("Epoch") or 0) < since_epoch - 60 and status not in UNRESOLVED:
            continue
        out.append({"id": f"threat|{r.get('ThreatID')}", "category": "threat",
                    "name": r.get("Name") or f"Threat {r.get('ThreatID')}",
                    "location": "; ".join(_clean_resource(x) for x in (r.get("Files") or "").split(";") if x.strip()),
                    "severity": SEVERITY.get(int(r.get("Severity") or 0), "Unknown"),
                    "status_text": THREAT_STATUS.get(status, str(status)),
                    "resolved": status not in UNRESOLVED, "when": r.get("When"),
                    "fix": {"action": "remove_threat", "threat_id": r.get("ThreatID")}})
    return out


# ---------------------------------------------------------------- scan
LEVELS = ("Low", "Moderate", "High", "Severe")


def review_mode():
    """'all' = ask before acting on anything (default), 'severe' = auto-quarantine severe only, 'auto' = Defender decides."""
    return load_settings().get("review_mode", "all")


def _active_hold():
    """A review-mode hold already in place by a live PC Shield process (this one or a scheduled scan)."""
    import psutil
    held = load_settings().get("defender_hold")
    if held and held.get("pid") and psutil.pid_exists(held["pid"]):
        return held
    return None


def _read_actions():
    prev = ps_json("Get-MpPreference | Select-Object " + ", ".join(f"{l}ThreatDefaultAction" for l in LEVELS))
    return prev[0] if prev else {}


def _hold_defender_actions(mode):
    """During our scan, tell Defender to report instead of quarantining, so the user decides.
    Returns the previous settings so they can be put back. Real-time protection is untouched after the scan."""
    if mode == "auto":
        return None
    if _active_hold():
        return None  # someone else is already holding; never read their NoAction as the 'previous' value
    prev = _read_actions()
    hold = [l for l in LEVELS if not (mode == "severe" and l == "Severe")]
    args = " ".join(f"-{l}ThreatDefaultAction NoAction" for l in hold)
    held = {"prev": prev, "hold": hold, "pid": os.getpid()}
    save_setting("defender_hold", held)  # so a crash mid-scan can't leave Defender in report-only mode
    _, err, code = ps(f"Set-MpPreference {args}")
    now = _read_actions()
    applied = code == 0 and all(int(now.get(f"{l}ThreatDefaultAction") or 0) == 9 for l in hold)
    if code == 0 and not applied:
        err = "Tamper Protection kept Defender's automatic actions on."
    return {**held, "ok": applied, "err": err.strip()}


def _restore_defender_actions(held):
    if not held:
        return
    names = {1: "Clean", 2: "Quarantine", 3: "Remove", 6: "Allow", 8: "UserDefined", 9: "NoAction", 10: "Block"}
    for l in held["hold"]:
        v = int(held["prev"].get(f"{l}ThreatDefaultAction") or 0)
        if v in names:
            ps(f"Set-MpPreference -{l}ThreatDefaultAction {names[v]}")
        else:
            ps(f"Remove-MpPreference -{l}ThreatDefaultAction")
    save_setting("defender_hold", None)


def recover_defender_actions():
    """Called at startup: undo a review-mode hold left behind by a crash or reboot mid-scan."""
    held = load_settings().get("defender_hold")
    import psutil
    if held and not (held.get("pid") and psutil.pid_exists(held["pid"])):
        _restore_defender_actions(held)


def _run_scan(kind, path=None):
    start = time.time()
    rid = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    _set(running=True, kind=kind, started=start, stage="Updating threat definitions", progress=5, report_id=None,
         error=None, cancel=False, steps=0, step=0, pct=None, scanned_all=0)
    _take_lock(kind)
    held = None
    try:
        ps("Update-MpSignature -ErrorAction SilentlyContinue", timeout=300)
        held = _hold_defender_actions(review_mode())

        # build the list of Defender steps
        if kind == "custom" and path:
            steps = [(f"Scanning {path}", f"Start-MpScan -ScanType CustomScan -ScanPath {ps_quote(path)}", path, _folder_size(path))]
        elif kind == "deep":
            steps = [("Quick pass: memory, startup and common hiding spots", "Start-MpScan -ScanType QuickScan", "Memory & startup", QUICK_TYPICAL)]
            for mount, used in _fixed_drives():
                steps.append((f"Scanning every file on {mount.rstrip(chr(92))}",
                              f"Start-MpScan -ScanType CustomScan -ScanPath {ps_quote(mount)}", mount.rstrip("\\"), used))
        else:
            steps = [("Quick scan: memory, startup and common malware locations", "Start-MpScan -ScanType QuickScan",
                      "Memory & startup", QUICK_TYPICAL)]
        _set(steps=len(steps), scanned_all=0)
        err, code = "", 0
        try:
            for i, (label, cmd, target, total) in enumerate(steps, 1):
                if scan_state()["cancel"]:
                    break
                _set(stage=label, step=i, target=target, scanned=0, total=total, pct=0, rate=0, eta=None,
                     progress=15 + int(65 * (i - 1) / len(steps)))
                mon = _Progress(total)
                mon.start()
                try:
                    _, e, c = ps(cmd, timeout=12 * 3600)
                finally:
                    mon.stop()
                if c and not scan_state()["cancel"]:
                    err, code = e, c
        finally:
            _restore_defender_actions(held)
        cancelled = scan_state()["cancel"]
        engine_note = err.strip() if code else ""
        if cancelled:
            engine_note = ("Scan was cancelled - results cover only what was checked. " + engine_note).strip()
        if held and not held["ok"]:
            engine_note = ("Couldn't switch Defender to review mode (Tamper Protection or no admin), "
                           "so it may have quarantined threats itself - you can restore them below. " + held["err"]).strip()

        _set(stage="Checking for potentially unwanted programs", progress=80)
        pups = check_pups()
        _set(stage="Checking registry and system settings for tampering", progress=86)
        pums = check_pums()
        _set(stage="Checking startup items", progress=92)
        starts = check_startup()
        _set(stage="Collecting results", progress=97)
        threats = defender_detections(since_epoch=start)

        ign = ignored()
        detections = threats + pups + pums + starts
        for d in detections:
            if d["id"] in ign:
                d["state"] = "ignored"
            elif d["category"] == "threat" and d.get("resolved"):
                d["state"] = "quarantined"
            else:
                d["state"] = "found"

        programs = len(system.installed_programs())
        report = {
            "id": rid, "kind": kind, "path": path, "started": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(start)),
            "finished": now_iso(), "duration": int(time.time() - start),
            "items_checked": programs + len(PUM_RULES) + len(WATCHED_EXES) + len(system.startup_entries(False)),
            "engine": "Microsoft Defender", "engine_note": engine_note, "review_mode": review_mode(),
            "data_scanned": scan_state().get("scanned_all", 0), "cancelled": cancelled,
            "detections": detections,
        }
        report["summary"] = summarize(report)
        save_report(report)
        _set(running=False, stage="Done", progress=100, report_id=rid, cancel=False)
        return report
    except Exception as e:  # noqa
        _set(running=False, stage="Failed", error=str(e))
        raise
    finally:
        _drop_lock()


def _folder_size(path):
    import psutil
    try:
        if len(path.rstrip("\\")) <= 2:  # a whole drive
            return psutil.disk_usage(path).used
    except OSError:
        pass
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def start_scan(kind="quick", path=None):
    if kind not in ("quick", "deep", "custom") or (kind == "custom" and not (path and os.path.exists(path))):
        return {"ok": False, "message": "Pick a folder or drive that exists."}
    with _state_lock:
        if STATE["running"]:
            return {"ok": False, "message": "A scan is already running."}
        if other_scan():
            return {"ok": False, "message": "A scheduled scan is already running in the background - "
                                            "its report will show up under Reports when it finishes."}
        # mark as running right away so the UI never mistakes the previous report for this scan's result
        STATE.update(running=True, started=time.time(), stage="Starting", progress=1, report_id=None,
                     error=None, cancel=False, steps=0, step=0, pct=None)
    threading.Thread(target=lambda: _safe(_run_scan, kind, path), daemon=True).start()
    return {"ok": True}


def _safe(fn, *a):
    try:
        fn(*a)
    except Exception:
        import traceback
        from .util import log
        log(f"scan failed\n{traceback.format_exc()}")


def summarize(report):
    c = {"threat": 0, "pup": 0, "pum": 0, "startup": 0, "ignored": 0, "quarantined": 0, "fixed": 0, "skipped": 0, "open": 0}
    for d in report["detections"]:
        c[d["category"]] += 1
        st = d.get("state")
        if st in ("ignored", "trusted"):
            c["ignored"] += 1
        elif st == "quarantined":
            c["quarantined"] += 1
        elif st in ("fixed", "restored"):
            c["fixed"] += 1
        elif st == "skipped":
            c["skipped"] += 1
        else:
            c["open"] += 1
    return c


# ---------------------------------------------------------------- reports
MAX_REPORTS = 100


def save_report(r):
    with open(os.path.join(REPORT_DIR, r["id"] + ".json"), "w", encoding="utf-8") as f:
        json.dump(r, f, indent=1)
    old = sorted(glob.glob(os.path.join(REPORT_DIR, "*.json")), reverse=True)[MAX_REPORTS:]
    for fp in old:  # report ids start with a timestamp, so name order = age order
        try:
            os.remove(fp)
        except OSError:
            pass


def list_reports():
    out = []
    for fp in sorted(glob.glob(os.path.join(REPORT_DIR, "*.json")), reverse=True):
        try:
            with open(fp, encoding="utf-8") as f:
                r = json.load(f)
            out.append({k: r.get(k) for k in ("id", "kind", "path", "started", "duration", "summary", "items_checked")})
        except (OSError, json.JSONDecodeError):
            continue
    return out


def get_report(rid):
    with open(os.path.join(REPORT_DIR, os.path.basename(rid) + ".json"), encoding="utf-8") as f:
        return json.load(f)


def delete_report(rid):
    try:
        os.remove(os.path.join(REPORT_DIR, os.path.basename(rid) + ".json"))
    except OSError:
        pass
    return {"ok": True}


def last_report():
    reps = list_reports()
    return reps[0] if reps else None


# ---------------------------------------------------------------- actions
# Nothing is ever changed until the user picks an action for a detection:
#   fix         - quarantine threat / uninstall PUP / restore setting / disable startup item
#   skip        - leave it alone this time (shows again next scan)
#   exclude     - always ignore in future scans (threats are also allowed + path-excluded in Defender)
#   restore     - put back something Defender already quarantined
#   unexclude   - stop excluding

def _clean_resource(part):
    """'file:_C:\\x.exe' / 'containerfile:_C:\\a.zip->(Zip)b.exe' / 'process:_pid:4' -> readable path."""
    p = part.strip()
    m = re.match(r"^([A-Za-z]+):_(.*)$", p)
    return m.group(2) if m else p


def _threat_files(det, must_exist=True):
    files = []
    for part in (det.get("location") or "").split(";"):
        p = _clean_resource(part)
        if "->" in p:
            p = p.split("->")[0]
        if len(p) > 2 and p[1] == ":" and (os.path.exists(p) or not must_exist):
            files.append(p)
    return files


def _quarantine_threat(det):
    """Quarantine ONLY this threat: give its ID a Quarantine action, hold every other threat at 'report only',
    and rescan just its files (or memory/startup if it isn't a file)."""
    tid = int(det["fix"]["threat_id"])
    ps(f"Add-MpPreference -ThreatIDDefaultAction_Ids {tid} -ThreatIDDefaultAction_Actions Quarantine")
    files = _threat_files(det)
    held = _hold_defender_actions("all")
    try:
        if files:
            for f in files:
                ps(f"Start-MpScan -ScanType CustomScan -ScanPath {ps_quote(f)}", timeout=1800)
        else:
            ps("Start-MpScan -ScanType QuickScan", timeout=3600)
    finally:
        _restore_defender_actions(held)
    still = [f for f in files if os.path.exists(f)]
    if still:
        return {"ok": False, "message": "Defender couldn't quarantine it yet (it may be in use - restart and run "
                                        "a quick scan): " + ", ".join(still)}
    if not files:
        active = ps_json(f"Get-MpThreat | Where-Object {{ $_.ThreatID -eq {tid} -and $_.IsActive }} | Select-Object ThreatID")
        if active:
            return {"ok": False, "message": "Defender couldn't remove it yet - restart the PC, or run "
                                            "Windows Security > Scan options > Microsoft Defender Offline scan."}
    return {"ok": True, "message": "Quarantined - you can restore it from this report if it was a mistake."}


def _mpcmdrun():
    return ps_out("$p=Get-ChildItem \"$env:ProgramData\\Microsoft\\Windows Defender\\Platform\" -Directory -ErrorAction SilentlyContinue | "
                  "Sort-Object Name -Descending | Select-Object -First 1; if ($p) { Join-Path $p.FullName 'MpCmdRun.exe' } "
                  "else { \"$env:ProgramFiles\\Windows Defender\\MpCmdRun.exe\" }")


def _restore_threat(det):
    tid = det["fix"]["threat_id"]
    ps(f"Add-MpPreference -ThreatIDDefaultAction_Ids {int(tid)} -ThreatIDDefaultAction_Actions Allow")
    code, out = run([_mpcmdrun(), "-Restore", "-Name", det["name"]], timeout=300)
    return {"ok": code == 0, "message": "Restored and allowed." if code == 0 else out.strip()}


def _exclude_threat(det):
    tid = det["fix"]["threat_id"]
    ps(f"Add-MpPreference -ThreatIDDefaultAction_Ids {int(tid)} -ThreatIDDefaultAction_Actions Allow")
    for f in _threat_files(det):
        ps(f"Add-MpPreference -ExclusionPath {ps_quote(f)}")


def _unexclude_threat(det):
    tid = det["fix"]["threat_id"]
    ps(f"Remove-MpPreference -ThreatIDDefaultAction_Ids {int(tid)}")
    for f in _threat_files(det, must_exist=False):
        ps(f"Remove-MpPreference -ExclusionPath {ps_quote(f)}")


def apply_fix(det):
    fix = det.get("fix") or {}
    a = fix.get("action")
    if a == "remove_threat":
        return _quarantine_threat(det)
    if a == "uninstall":
        return system.uninstall(fix["kind"], fix["ident"])
    if a == "disable_startup":
        system.set_startup(fix["ident"], False)
        return {"ok": True, "message": "Startup item disabled."}
    if a == "delete":
        reg_delete(fix["hive"], fix["path"], fix["name"])
        return {"ok": True, "message": "Setting restored."}
    if isinstance(a, (list, tuple)) and a and a[0] == "set":
        import winreg
        kind = winreg.REG_SZ if isinstance(a[1], str) else winreg.REG_DWORD
        reg_set(fix["hive"], fix["path"], fix["name"], a[1], kind)
        return {"ok": True, "message": "Setting restored to the Windows default."}
    if a == "defex":
        _, err, code = ps(f"Remove-MpPreference -Exclusion{fix['kind']} {ps_quote(fix['value'])}")
        return {"ok": code == 0, "message": "Exclusion removed." if code == 0 else err.strip()}
    if a == "hosts":
        backup = HOSTS + ".pcshield.bak"
        shutil.copy2(HOSTS, backup)
        with open(HOSTS, "w", encoding="ascii") as f:
            f.write("# Reset by PC Shield. Previous file saved as hosts.pcshield.bak\n127.0.0.1 localhost\n::1 localhost\n")
        return {"ok": True, "message": "Hosts file reset (backup saved next to it)."}
    return {"ok": False, "message": "Nothing to fix for this item."}


def _exclusions():
    return load_settings().get("exclusions", {})


def _save_exclusions(ex):
    save_setting("exclusions", ex)
    save_setting("ignored", sorted(ex.keys()))


def apply_actions(report_id, actions):
    """actions: [{"id": detection id, "action": fix|skip|exclude|restore|unexclude}]"""
    r = get_report(report_id)
    ex = _exclusions()
    results = []
    for item in actions:
        det = next((d for d in r["detections"] if d["id"] == item["id"]), None)
        if not det:
            continue
        act = item["action"]
        try:
            if act == "skip":
                det["state"] = "skipped"
                res = {"ok": True, "message": "Left alone."}
            elif act == "exclude":
                if det["category"] == "threat":
                    _exclude_threat(det)
                ex[det["id"]] = {"name": det["name"], "category": det["category"], "location": det.get("location", ""),
                                 "added": now_iso(), "fix": det.get("fix")}
                det["state"] = "ignored"
                res = {"ok": True, "message": "Excluded from future scans."}
            elif act == "unexclude":
                if det["category"] == "threat":
                    _unexclude_threat(det)
                ex.pop(det["id"], None)
                det["state"] = "found"
                res = {"ok": True, "message": "No longer excluded."}
            elif act == "trust":
                if not (det.get("signer") and det.get("sig_status") == "Valid"):
                    res = {"ok": False, "message": "Only validly signed items can be trusted by publisher."}
                else:
                    trust.add(det["signer"].split(",")[0].strip())
                    det["state"] = "trusted"
                    res = {"ok": True, "message": f"Trusted {det['signer']} - its changes won't be flagged again."}
            elif act == "restore" and det["category"] == "threat":
                res = _restore_threat(det)
                if res["ok"]:
                    det["state"] = "restored"
            else:
                res = apply_fix(det)
                if res.get("ok"):
                    det["state"] = "quarantined" if det["category"] == "threat" else "fixed"
        except Exception as e:  # noqa
            res = {"ok": False, "message": str(e)}
        results.append({"id": det["id"], "name": det["name"], **res})
    _save_exclusions(ex)
    r["summary"] = summarize(r)
    save_report(r)
    return {"report": r, "results": results}


def list_exclusions():
    return [{"id": k, **{x: v.get(x) for x in ("name", "category", "location", "added")}} for k, v in _exclusions().items()]


def remove_exclusion(det_id):
    ex = _exclusions()
    v = ex.pop(det_id, None)
    if v and v.get("category") == "threat" and v.get("fix"):
        _unexclude_threat({"fix": v["fix"], "location": v.get("location", "")})
    _save_exclusions(ex)
    return {"ok": True}


# ---------------------------------------------------------------- scheduler
TASK_NAMES = {"quick": "PC Shield Quick Scan", "deep": "PC Shield Deep Scan"}


def get_schedules():
    out = {}
    for kind, name in TASK_NAMES.items():
        rows = ps_json(f"$t=Get-ScheduledTask -TaskName {ps_quote(name)} -ErrorAction SilentlyContinue; if ($t) {{ "
                       f"$i=$t | Get-ScheduledTaskInfo; $tr=$t.Triggers[0]; [pscustomobject]@{{ "
                       f"Next= if ($i.NextRunTime) {{ $i.NextRunTime.ToString('yyyy-MM-dd HH:mm') }} else {{ '' }}; "
                       f"Last= if ($i.LastRunTime -and $i.LastRunTime.Year -gt 2000) {{ $i.LastRunTime.ToString('yyyy-MM-dd HH:mm') }} else {{ '' }}; "
                       f"Start=([datetime]$tr.StartBoundary).ToString('HH:mm'); "
                       f"Weekly= [bool]($tr.CimClass.CimClassName -eq 'MSFT_TaskWeeklyTrigger'); "
                       f"Days=[int]$tr.DaysOfWeek; Enabled= $t.State -ne 'Disabled' }} }}")
        out[kind] = rows[0] if rows else None
    return out


DAYS = {"MON": "Monday", "TUE": "Tuesday", "WED": "Wednesday", "THU": "Thursday", "FRI": "Friday",
        "SAT": "Saturday", "SUN": "Sunday"}


def _scan_command(kind):
    if getattr(sys, "frozen", False):
        return sys.executable, f"--scan {kind}"
    script = os.path.abspath(sys.modules["__main__"].__file__)
    return sys.executable.replace("python.exe", "pythonw.exe"), f'"{script}" --scan {kind}'


def set_schedule(kind, enabled, freq="weekly", day="SUN", time_="03:00"):
    if kind not in TASK_NAMES:
        return {"ok": False, "message": "Unknown scan type."}
    name = TASK_NAMES[kind]
    if not enabled:
        ps(f"Unregister-ScheduledTask -TaskName {ps_quote(name)} -Confirm:$false -ErrorAction SilentlyContinue")
        return {"ok": True}
    if not re.fullmatch(r"\d{1,2}:\d{2}", str(time_ or "")):
        return {"ok": False, "message": "Pick a time."}
    day = DAYS.get(str(day).upper(), "Sunday")
    exe, args = _scan_command(kind)
    trig = (f"New-ScheduledTaskTrigger -Daily -At {ps_quote(time_)}" if freq == "daily"
            else f"New-ScheduledTaskTrigger -Weekly -DaysOfWeek {day} -At {ps_quote(time_)}")
    out, err, code = ps(
        f"$u=\"$env:USERDOMAIN\\$env:USERNAME\"; "
        f"$a=New-ScheduledTaskAction -Execute {ps_quote(exe)} -Argument {ps_quote(args)}; $t={trig}; "
        f"$p=New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest; "
        f"$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable "
        f"-ExecutionTimeLimit (New-TimeSpan -Hours 12) -MultipleInstances IgnoreNew; "
        f"Register-ScheduledTask -TaskName {ps_quote(name)} -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null; 'ok'")
    ok = out.strip().endswith("ok")
    return {"ok": ok, "message": "" if ok else (err.strip() or "Couldn't create the scheduled scan.")}


def headless_scan(kind):
    """Scheduled scan (no window). Skips if a scan is already running in the app."""
    if other_scan():
        return
    _run_scan(kind if kind in ("quick", "deep") else "quick")
