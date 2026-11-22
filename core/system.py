"""Installed programs, bloatware rules, startup entries, PC health, processes, Defender status."""
import os
import re
import secrets
import shutil
import subprocess
import time
import winreg

import psutil

from .util import ps, ps_json, ps_out, ps_quote, sys_exe, human, enum_name, MEDIA_TYPES, HEALTH, BUS_TYPES, CREATE_NO_WINDOW

# (match substring, category, level, advice)
#   level "pup"      -> counted as a PUP by the scanner
#   level "optional" -> only shown on the Bloatware tab
BLOAT_RULES = [
    ("mcafee", "Trial antivirus", "pup", "Remove - Defender is free. If uninstall fails use McAfee's MCPR removal tool."),
    ("norton", "Trial antivirus", "pup", "Remove unless you pay for it. Norton Remove & Reinstall tool cleans leftovers."),
    ("totalav", "Junk antivirus", "pup", "Remove."),
    ("segurazo", "Junk antivirus", "pup", "Remove."),
    ("shield antivirus", "Junk antivirus", "pup", "Remove."),
    ("pc matic", "Trial antivirus", "pup", "Remove."),
    ("avast", "Third-party antivirus", "optional", "Remove if you want Defender as your antivirus."),
    ("avg ", "Third-party antivirus", "optional", "Remove if you want Defender as your antivirus."),
    ("webroot", "Third-party antivirus", "optional", "Remove if you want Defender as your antivirus."),
    ("bitdefender", "Third-party antivirus", "optional", "Remove if you want Defender as your antivirus."),
    ("kaspersky", "Third-party antivirus", "optional", "Remove if you want Defender as your antivirus."),
    ("driver booster", "Driver updater", "pup", "Remove - use Windows Update and vendor sites."),
    ("driver easy", "Driver updater", "pup", "Remove."),
    ("driversupport", "Driver updater", "pup", "Remove."),
    ("driver support", "Driver updater", "pup", "Remove."),
    ("advanced systemcare", "Fake optimizer", "pup", "Remove."),
    ("reimage", "Scareware", "pup", "Remove."),
    ("restoro", "Scareware", "pup", "Remove."),
    ("fortect", "Scareware", "pup", "Remove."),
    ("pc accelerate", "Scareware", "pup", "Remove."),
    ("pc app store", "Adware", "pup", "Remove."),
    ("wave browser", "Browser hijacker", "pup", "Remove."),
    ("webcompanion", "Adware", "pup", "Remove."),
    ("onelaunch", "Adware", "pup", "Remove."),
    ("shift browser", "Browser hijacker", "pup", "Remove."),
    ("pdf wizard", "Adware", "pup", "Remove."),
    ("wildtangent", "OEM game trials", "pup", "Remove."),
    ("ccleaner", "Optimizer", "optional", "Not needed on Windows 10/11."),
    ("booking.com", "OEM promo", "optional", "Remove."),
    ("expressvpn", "OEM promo", "optional", "Remove unless used."),
    ("armoury crate", "Vendor RGB suite (heavy)", "optional", "Very heavy. Keep only if needed for RGB/fans - use the Armoury Crate Uninstall Tool."),
    ("msi center", "Vendor suite (heavy)", "optional", "Keep only if used for RGB/fans."),
    ("dragon center", "Vendor suite (outdated)", "optional", "Replaced by MSI Center - usually safe to remove."),
    ("mystic light", "RGB utility", "optional", "Keep only if used."),
    ("rgb fusion", "RGB utility", "optional", "Keep only if used."),
    ("gigabyte control center", "Vendor suite", "optional", "Keep only if used."),
    ("app center", "Vendor suite (Gigabyte, old)", "optional", "Old and heavy - usually safe to remove."),
    ("polychrome", "RGB utility", "optional", "Keep only if used."),
    ("icue", "RGB / peripheral suite", "optional", "Keep if you have Corsair gear."),
    ("nzxt cam", "Monitoring / RGB suite", "optional", "Known CPU hog. Keep only if needed for the cooler/RGB."),
    ("signalrgb", "RGB utility", "optional", "Don't run more than one RGB app."),
    ("openrgb", "RGB utility", "optional", "Don't run more than one RGB app."),
    ("l-connect", "RGB/fan utility", "optional", "Keep only if used for fans."),
    ("razer synapse", "Peripheral suite", "optional", "Keep if you have Razer gear."),
    ("ai suite", "ASUS tuning suite (old)", "optional", "Old, buggy and heavy - usually safe to remove."),
]

APPX_BLOAT = {
    "king.com": "Candy Crush and friends", "candycrush": "Candy Crush", "disney": "Disney promo",
    "spotifyab": "Spotify (Store version)", "bytedance": "TikTok (preinstalled)", "facebook": "Facebook (preinstalled)",
    "instagram": "Instagram (preinstalled)", "amazon.com.amazon": "Amazon promo", "clipchamp": "Clipchamp",
    "microsoft.bingnews": "News", "microsoft.bingweather": "Weather", "microsoft.getstarted": "Tips",
    "microsoft.microsoftsolitairecollection": "Solitaire (ads)", "microsoft.windowsfeedbackhub": "Feedback Hub",
    "microsoft.zunevideo": "Movies & TV", "microsoft.549981c3f5f10": "Cortana", "dolbylaboratories.dolbyaccess": "Dolby Access (Atmos setup app)",
    "mcafee": "McAfee Store app", "norton": "Norton Store app", "linkedin": "LinkedIn (preinstalled)",
}

REMOTE_TOOLS = [
    # (match in program name, process names, note)
    ("teamviewer", ["teamviewer.exe", "teamviewer_service.exe"], "Common remote tool - also used by scammers."),
    ("anydesk", ["anydesk.exe"], "Most common tool in tech-support scams."),
    ("rustdesk", ["rustdesk.exe"], "Open-source remote desktop."),
    ("chrome remote desktop", ["remoting_host.exe"], "Google's remote desktop host."),
    ("screenconnect", ["screenconnect.clientservice.exe", "screenconnect.windowsclient.exe"], "Heavily abused in scams."),
    ("connectwise", ["screenconnect.clientservice.exe"], "Heavily abused in scams."),
    ("logmein", ["logmein.exe", "lmiguardiansvc.exe"], "Remote access."),
    ("splashtop", ["srservice.exe", "srmanager.exe"], "Remote access."),
    ("ultravnc", ["winvnc.exe"], "VNC server."),
    ("tightvnc", ["tvnserver.exe"], "VNC server."),
    ("realvnc", ["vncserver.exe"], "VNC server."),
    ("vnc server", ["vncserver.exe"], "VNC server."),
    ("supremo", ["supremo.exe", "supremoservice.exe"], "Used in scams."),
    ("ammyy", ["aa_v3.exe", "ammyy_admin.exe"], "Frequently abused."),
    ("remote utilities", ["rutserv.exe", "rfusclient.exe"], "Frequently abused as a RAT."),
    ("netsupport", ["client32.exe"], "Frequently abused as a RAT."),
    ("zoho assist", ["zaservice.exe"], "Remote support."),
    ("ninjarmm", ["ninjarmmagent.exe"], "IT management agent."),
    ("atera", ["ateraagent.exe"], "IT management agent."),
    ("action1", ["action1_agent.exe"], "IT management agent."),
    ("parsec", ["parsecd.exe"], "Game streaming / remote desktop."),
    ("dwservice", ["dwagent.exe"], "Remote access."),
    ("meshcentral", ["meshagent.exe"], "Remote access."),
    ("aeroadmin", ["aeroadmin.exe"], "Remote access."),
    ("getscreen", ["getscreen.exe"], "Remote access."),
    ("remotepc", ["remotepcservice.exe"], "Remote access."),
]

UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def _val(key, name, default=""):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return default


def installed_programs():
    seen, progs = set(), []
    for hive, path in UNINSTALL_KEYS:
        try:
            root = winreg.OpenKey(hive, path)
        except OSError:
            continue
        with root:
            for i in range(winreg.QueryInfoKey(root)[0]):
                try:
                    keyname = winreg.EnumKey(root, i)
                    sub = winreg.OpenKey(root, keyname)
                except OSError:
                    continue
                with sub:
                    name = _val(sub, "DisplayName")
                    if not name or _val(sub, "SystemComponent", 0) == 1 or _val(sub, "ParentKeyName"):
                        continue
                    if name.lower() in seen:
                        continue
                    seen.add(name.lower())
                    size = _val(sub, "EstimatedSize", 0)
                    per_user = hive == winreg.HKEY_CURRENT_USER
                    progs.append({
                        # per-user ids are prefixed so a same-named key can't stand in for a machine-wide program
                        "id": ("HKCU\\" + keyname) if per_user else keyname, "per_user": per_user, "name": name, "publisher": _val(sub, "Publisher") or "",
                        "version": str(_val(sub, "DisplayVersion") or ""), "installed": str(_val(sub, "InstallDate") or ""),
                        "size": size * 1024 if isinstance(size, int) else 0,
                        "uninstall": _val(sub, "UninstallString") or "",
                        "location": str(_val(sub, "InstallLocation") or "").strip().strip('"'),
                    })
    progs.sort(key=lambda p: p["name"].lower())
    return progs


def match_bloat(name, publisher=""):
    text = f"{name} {publisher}".lower()
    for key, cat, level, advice in BLOAT_RULES:
        if key in text:
            return {"category": cat, "level": level, "advice": advice}
    return None


def appx_packages():
    return ps_json("Get-AppxPackage | Select-Object Name, PackageFullName")


def bloat_scan(show_all=False):
    rows = []
    for p in installed_programs():
        m = match_bloat(p["name"], p["publisher"])
        if m or show_all:
            rows.append({**p, "kind": "win32", "category": (m or {}).get("category", ""),
                         "level": (m or {}).get("level", ""), "advice": (m or {}).get("advice", ""),
                         "size_h": human(p["size"]) if p["size"] else ""})
    for a in appx_packages():
        n = (a.get("Name") or "").lower()
        for key, label in APPX_BLOAT.items():
            if key in n:
                rows.append({"id": a["PackageFullName"], "name": a["Name"], "publisher": "Microsoft Store",
                             "kind": "appx", "category": "Store app", "level": "optional",
                             "advice": f"{label} - remove if you don't use it", "size_h": ""})
                break
    return rows


def uninstall(kind, ident, wait_minutes=20):
    if kind == "appx":
        out = ps_out(f"try {{ Remove-AppxPackage -Package {ps_quote(ident)} -ErrorAction Stop; 'ok' }} "
                     f"catch {{ 'ERR: ' + $_.Exception.Message }}")
        ok = out.strip().endswith("ok") and "ERR:" not in out
        return {"ok": ok, "message": "Removed." if ok else out.replace("ERR: ", "").strip() or "Couldn't remove it."}
    progs = installed_programs()
    prog = next((p for p in progs if p["id"] == ident), None)
    if prog is None and not str(ident).startswith("HKCU\\"):  # reports saved by 1.2 used bare key names
        prog = next((p for p in progs if p["id"] == "HKCU\\" + str(ident)), None)
    if not prog or not prog["uninstall"]:
        return {"ok": False, "message": "No uninstaller registered for this program."}
    cmd = prog["uninstall"]
    if "msiexec" in cmd.lower():
        cmd = re.sub(r"(?i)/I\s*(\{)", r"/X\1", cmd)  # '/I{GUID}' or '/I {GUID}' opens repair - /X uninstalls
    # wait (up to a limit) so several uninstallers don't run at once - Windows Installer only allows one
    if prog.get("per_user"):
        run_as_user(cmd, wait_minutes)
    else:
        # cmd.exe by full path (shell=True would use %COMSPEC%, which a program could point elsewhere)
        proc = subprocess.Popen(f'"{sys_exe("cmd")}" /d /s /c "{cmd}"', creationflags=CREATE_NO_WINDOW)
        try:
            proc.wait(timeout=wait_minutes * 60)
        except subprocess.TimeoutExpired:
            pass
    still = any(p["id"] == prog["id"] for p in installed_programs())
    return {"ok": True, "removed": not still,
            "message": f"{prog['name']} removed." if not still else
                       f"Opened the uninstaller for {prog['name']} - finish its prompts if it's still open."}


def run_as_user(cmd, wait_minutes=20):
    """Run a per-user program's uninstaller the way Windows does: as the signed-in user, without admin.
    Its uninstall entry is in the user's registry, which any program the user runs can write - running it
    with PC Shield's admin rights would hand that program admin. (It can still ask for admin itself.)"""
    task = ps_quote(f"PC Shield Uninstall {secrets.token_hex(4)}")
    script = (
        "$u=[Security.Principal.WindowsIdentity]::GetCurrent().Name; "
        f"$a=New-ScheduledTaskAction -Execute {ps_quote(sys_exe('cmd'))} -Argument {ps_quote('/d /s /c "' + cmd + '"')}; "
        "$p=New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Limited; "
        "$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2); "
        f"Register-ScheduledTask -TaskName {task} -Action $a -Principal $p -Settings $s -Force | Out-Null; "
        f"Start-ScheduledTask -TaskName {task}; Start-Sleep -Milliseconds 800; $end=(Get-Date).AddMinutes({int(wait_minutes)}); "
        f"while ((Get-ScheduledTask -TaskName {task}).State -in 'Running','Queued' -and (Get-Date) -lt $end) {{ Start-Sleep 1 }}; "
        f"Unregister-ScheduledTask -TaskName {task} -Confirm:$false; 'ok'")
    out, err, _ = ps(script, timeout=int(wait_minutes) * 60 + 120)
    return out.strip().endswith("ok")


# ------------------------------------------------------------------ startup
APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
RUN_SOURCES = [
    ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Run", "Current user"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run", "All users"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Run32", "All users (32-bit)"),
]
HIVE_BY_NAME = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}


def _approved(hive, sub, name):
    try:
        with winreg.OpenKey(hive, f"{APPROVED}\\{sub}") as k:
            data = winreg.QueryValueEx(k, name)[0]
        return not (data and data[0] & 1)
    except OSError:
        return True


def exe_from_command(cmd):
    cmd = os.path.expandvars(str(cmd).strip())
    if cmd.startswith('"'):
        return cmd[1:].split('"', 1)[0]
    low = cmd.lower()
    for ext in (".exe", ".lnk", ".bat", ".cmd", ".vbs", ".ps1", ".js"):
        i = low.find(ext)
        if i != -1:
            return cmd[: i + len(ext)]
    return cmd.split(" ")[0]


LOLBINS = ("rundll32.exe", "regsvr32.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
           "mshta.exe", "cmd.exe", "conhost.exe", "msiexec.exe", "schtasks.exe", "certutil.exe", "bitsadmin.exe")
SUSPICIOUS_ARGS = re.compile(r"(?i)(-e(nc(odedcommand)?)?\s+[a-z0-9+/=]{20,}|-w(indowstyle)?\s+h(idden)?|frombase64string|"
                             r"downloadstring|invoke-expression|\biex\b|https?://|javascript:|vbscript:)")


def resolve_exe(exe):
    """'rundll32.exe' -> C:\\Windows\\System32\\rundll32.exe (bare names used to show as 'Missing')."""
    if not exe or os.path.isabs(exe):
        return exe
    sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    cand = os.path.join(sysdir, exe if exe.lower().endswith(".exe") else exe + ".exe")
    if os.path.isfile(cand):
        return cand
    return shutil.which(exe) or exe


def resolve_lnk(path):
    out = ps_out(f"(New-Object -ComObject WScript.Shell).CreateShortcut({ps_quote(path)}).TargetPath")
    return out or path


def signatures(paths):
    paths = sorted({p for p in paths if p and os.path.isfile(p)})
    if not paths:
        return {}
    arr = ",".join(ps_quote(p) for p in paths)
    rows = ps_json(
        f"@({arr}) | ForEach-Object {{ $s = Get-AuthenticodeSignature -LiteralPath $_; "
        f"[pscustomobject]@{{Path=$_; Status=[string]$s.Status; "
        f"Signer= if ($s.SignerCertificate) {{ $s.SignerCertificate.GetNameInfo('SimpleName',$false) }} else {{ '' }} }} }}")
    return {r["Path"].lower(): (r.get("Status") or "?", r.get("Signer") or "") for r in rows}


SUSPICIOUS_DIRS = ("\\appdata\\local\\temp", "\\appdata\\roaming\\", "\\programdata\\", "\\users\\public\\", "\\windows\\temp")


def startup_entries(check_signatures=True):
    items = []
    for hname, hive, path, sub, label in RUN_SOURCES:
        try:
            k = winreg.OpenKey(hive, path)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(k)[1]):
            name, cmd, _ = winreg.EnumValue(k, i)
            items.append({"id": f"{hname}|{sub}|{name}", "name": name, "command": str(cmd), "scope": label,
                          "enabled": _approved(hive, sub, name)})
    folders = [("HKCU", os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "Current user (folder)"),
               ("HKLM", os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"), "All users (folder)")]
    for hname, folder, label in folders:
        if not os.path.isdir(folder):
            continue
        for f in os.listdir(folder):
            if f.lower() == "desktop.ini":
                continue
            items.append({"id": f"{hname}|StartupFolder|{f}", "name": os.path.splitext(f)[0],
                          "command": os.path.join(folder, f), "scope": label,
                          "enabled": _approved(HIVE_BY_NAME[hname], "StartupFolder", f)})
    for it in items:
        exe = exe_from_command(it["command"])
        if exe.lower().endswith(".lnk"):
            exe = resolve_lnk(exe)
        it["exe"] = resolve_exe(exe)
    if check_signatures:
        sigs = signatures([i["exe"] for i in items])
        for it in items:
            status, signer = sigs.get(it["exe"].lower(), ("Missing" if not os.path.exists(it["exe"]) else "?", ""))
            it["signature"], it["signer"] = status, signer
            low = it["exe"].lower()
            cmdlow = it["command"].lower()
            host = os.path.basename(low) in LOLBINS
            # unsigned program in a user-writable folder, or a Windows script host launching something sketchy
            it["suspicious"] = it["enabled"] and (
                (status != "Valid" and any(d in low for d in SUSPICIOUS_DIRS))
                or (host and (any(d in cmdlow for d in SUSPICIOUS_DIRS) or bool(SUSPICIOUS_ARGS.search(it["command"]))))
            )
            it["why"] = ("Windows script host launching something from a user folder or with hidden/encoded options"
                         if host and it["suspicious"] else
                         f"Unsigned ({status}) and starts from a user-writable folder" if it["suspicious"] else "")
            it["publisher"] = signer
    return items


def set_startup(entry_id, enabled):
    hname, sub, name = entry_id.split("|", 2)
    with winreg.CreateKeyEx(HIVE_BY_NAME[hname], f"{APPROVED}\\{sub}", 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, bytes([2 if enabled else 3]) + bytes(11))
    return {"ok": True}


# ------------------------------------------------------------------ health
def diagnostics():
    info, flags = [], []

    def flag(level, title, text):
        flags.append({"level": level, "title": title, "text": text})

    vm = psutil.virtual_memory()
    info.append(["Memory", f"{human(vm.total)} ({vm.percent:.0f}% in use)"])
    if vm.total < 15 * 1024 ** 3:
        flag("warn", "Under 16 GB of RAM", "Games + Discord + a browser can easily fill this. 16-32 GB is the sweet spot.")
    if vm.percent > 80:
        flag("bad", "Memory nearly full", f"{vm.percent:.0f}% used right now - check the process list below.")

    du = shutil.disk_usage("C:\\")
    free = du.free / du.total * 100
    info.append(["C: drive", f"{human(du.free)} free of {human(du.total)} ({free:.0f}%)"])
    if free < 15:
        flag("bad", "C: drive almost full", "Windows slows down badly under ~15% free space.")

    sysdisk = ps_out("(Get-Partition -DriveLetter C | Get-Disk).Number")
    disks = ps_json("Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, Size, "
                    "@{n='MediaType';e={[string]$_.MediaType}}, @{n='BusType';e={[string]$_.BusType}}, "
                    "@{n='HealthStatus';e={[string]$_.HealthStatus}}")
    for d in disks:
        on_c = str(d.get("DeviceId")) == sysdisk
        media = enum_name(d.get("MediaType"), MEDIA_TYPES)
        bus = enum_name(d.get("BusType"), BUS_TYPES)
        health = enum_name(d.get("HealthStatus"), HEALTH)
        info.append([f"Disk {d.get('DeviceId')}{' (Windows)' if on_c else ''}",
                     f"{d.get('FriendlyName')} - {media}, {bus}, {human(d.get('Size'))}, {health}"])
        if on_c and media.upper() == "HDD":
            flag("bad", "Windows is on a hard drive (HDD)",
                 "The #1 cause of slow boots and slow app launches. Moving Windows to an SSD is the single biggest fix.")
        if health in ("Warning", "Unhealthy"):
            flag("bad", f"Disk health: {health}", f"{d.get('FriendlyName')} may be failing - back up now.")

    up = (time.time() - psutil.boot_time()) / 86400
    info.append(["Uptime", f"{up:.1f} days"])
    if up > 7:
        flag("warn", "No real restart in over a week", "Shut down doesn't fully reset Windows (Fast Startup). Use Restart sometimes.")

    plan = ps_out("powercfg /getactivescheme")
    plan_name = plan.split("(")[-1].rstrip(")") if "(" in plan else plan
    info.append(["Power plan", plan_name])
    if "saver" in plan.lower():
        flag("warn", "Power saver plan", "Switch to Balanced or High performance.")

    info.append(["CPU", ps_out("(Get-CimInstance Win32_Processor).Name")])
    info.append(["GPU", ps_out("(Get-CimInstance Win32_VideoController).Name -join ', '")])
    info.append(["Windows", ps_out("$o=Get-CimInstance Win32_OperatingSystem; $o.Caption + ' (build ' + $o.BuildNumber + ')'")])

    mem = ps_json("Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity, Speed, ConfiguredClockSpeed")
    if mem:
        cur = [m.get("ConfiguredClockSpeed") or 0 for m in mem]
        rated = [m.get("Speed") or 0 for m in mem]
        info.append(["RAM sticks", f"{len(mem)} x {human(mem[0].get('Capacity'))} at {min(cur)} MT/s (rated {max(rated)})"])
        if len(mem) == 1:
            flag("warn", "Single RAM stick", "Single-channel memory roughly halves bandwidth. A matching second stick helps games a lot.")
        if max(rated) and min(cur) and min(cur) < max(rated) * 0.8:
            flag("warn", "RAM below rated speed", "XMP/EXPO is probably off in the BIOS - turning it on is free performance.")

    st = startup_entries(check_signatures=False)
    on = sum(1 for s in st if s["enabled"])
    info.append(["Startup apps", f"{on} enabled of {len(st)}"])
    if on > 10:
        flag("warn", f"{on} apps launch at boot", "Disable the ones you don't need on the Startup tab.")

    tmp, size = os.environ.get("TEMP", ""), 0
    for root, _, files in os.walk(tmp):
        for f in files:
            try:
                size += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    info.append(["Temp files", human(size)])
    if size > 2 * 1024 ** 3:
        flag("warn", "Lots of temp files", "Settings > System > Storage > Temporary files can clear these.")

    return {"info": info, "flags": flags}


def top_processes(n=30):
    procs = list(psutil.process_iter(["pid", "name", "memory_info"]))
    for p in procs:
        try:
            p.cpu_percent(None)
        except psutil.Error:
            pass
    time.sleep(1.5)
    cores = psutil.cpu_count() or 1
    grouped = {}
    for p in procs:
        if p.pid == 0:
            continue
        try:
            cpu = p.cpu_percent(None) / cores
            mem = p.info["memory_info"].rss if p.info["memory_info"] else 0
        except psutil.Error:
            continue
        g = grouped.setdefault(p.info["name"] or "?", [0, 0.0, 0])
        g[0] += 1
        g[1] += cpu
        g[2] += mem
    rows = sorted(grouped.items(), key=lambda kv: kv[1][2], reverse=True)[:n]
    return [{"name": k, "count": v[0], "cpu": round(v[1], 1), "mem": v[2], "mem_h": human(v[2])} for k, v in rows]


# ------------------------------------------------------------------ Defender
def protection_status():
    av = ps_json("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState")
    products = []
    for a in av:
        state = int(a.get("productState") or 0)
        products.append({"name": a.get("displayName"), "active": ((state >> 12) & 0xF) in (1, 3),
                         "defender": "defender" in (a.get("displayName") or "").lower()})
    st = ps_json("Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, "
                 "IsTamperProtected, AntivirusSignatureLastUpdated, AntivirusSignatureVersion, QuickScanAge, FullScanAge")
    s = st[0] if st else {}
    updated = s.get("AntivirusSignatureLastUpdated")
    if isinstance(updated, str) and updated.startswith("/Date("):
        try:
            updated = time.strftime("%Y-%m-%d %H:%M", time.localtime(int(updated[6:19]) / 1000))
        except ValueError:
            pass
    active_threats = ps_json("Get-MpThreat | Where-Object IsActive | Select-Object ThreatName")
    return {
        "products": products,
        "mode": s.get("AMRunningMode"), "realtime": bool(s.get("RealTimeProtectionEnabled")),
        "av_enabled": bool(s.get("AntivirusEnabled")), "tamper": bool(s.get("IsTamperProtected")),
        "defs_updated": updated, "defs_version": s.get("AntivirusSignatureVersion"),
        "active_threats": len(active_threats),
        "others": [p["name"] for p in products if not p["defender"]],
    }
