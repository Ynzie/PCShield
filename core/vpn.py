"""
VPN control. A VPN needs a server, so this drives two free, real options:
  * WireGuard tunnels (e.g. a free Proton VPN WireGuard config) via the official WireGuard app
  * VPN connections already set up in Windows Settings (rasdial)
"""
import json
import os
import re
import shutil
import time
import urllib.request

import psutil

from .util import VPN_DIR, ps_json, run, load_settings, save_setting

WG_EXE_CANDIDATES = [os.path.expandvars(r"%ProgramFiles%\WireGuard\wireguard.exe")]


def wireguard_exe():
    for p in WG_EXE_CANDIDATES:
        if os.path.isfile(p):
            return p
    return shutil.which("wireguard")


def _service_running(name):
    try:
        return psutil.win_service_get(f"WireGuardTunnel${name}").status() == "running"
    except Exception:
        return False


def wg_tunnels():
    out = []
    for f in sorted(os.listdir(VPN_DIR)):
        if f.endswith(".conf"):
            name = f[:-5]
            server, dns = "", ""
            try:
                with open(os.path.join(VPN_DIR, f), encoding="utf-8") as fh:
                    for line in fh:
                        k, _, v = line.partition("=")
                        if k.strip().lower() == "endpoint":
                            server = v.strip()
                        elif k.strip().lower() == "dns":
                            dns = v.strip()
            except OSError:
                pass
            out.append({"type": "wireguard", "name": name, "server": server, "dns": dns,
                        "connected": _service_running(name)})
    return out


def windows_vpns():
    rows = ps_json("@(Get-VpnConnection -ErrorAction SilentlyContinue) + @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) "
                   "| Select-Object Name, ServerAddress, ConnectionStatus")
    return [{"type": "windows", "name": r.get("Name"), "server": r.get("ServerAddress"),
             "connected": str(r.get("ConnectionStatus")) == "Connected"} for r in rows if r.get("Name")]


def status():
    tunnels = wg_tunnels() + windows_vpns()
    names = [t["name"] for t in tunnels]
    default = load_settings().get("vpn_default")
    if default not in names:  # removed / renamed -> fall back to the first one
        default = names[0] if names else None
    return {"wireguard_installed": bool(wireguard_exe()), "tunnels": tunnels, "default": default,
            "connected": next((t["name"] for t in tunnels if t["connected"]), None)}


def import_config(path):
    base = os.path.splitext(os.path.basename(path))[0]
    name = re.sub(r"[^A-Za-z0-9_=+.-]", "-", base)[:32].strip("-") or "tunnel"
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    if "[Interface]" not in text or "[Peer]" not in text:
        return {"ok": False, "message": "That isn't a WireGuard .conf file."}
    dest = os.path.join(VPN_DIR, name + ".conf")
    with open(dest, "w", encoding="utf-8") as f:
        f.write(text)
    run(["icacls", dest, "/inheritance:r", "/grant:r", "SYSTEM:F", "/grant:r", "Administrators:F",
         "/grant:r", f"{os.environ.get('USERNAME', '')}:F"])
    if not load_settings().get("vpn_default"):
        save_setting("vpn_default", name)
    return {"ok": True, "name": name}


def remove_config(name):
    disconnect(name)
    try:
        os.remove(os.path.join(VPN_DIR, name + ".conf"))
    except OSError:
        pass
    if load_settings().get("vpn_default") == name:
        save_setting("vpn_default", None)
    return {"ok": True}


def set_default(name):
    save_setting("vpn_default", name)
    return {"ok": True}


def _find(name):
    return next((t for t in wg_tunnels() + windows_vpns() if t["name"] == name), None)


def connect(name=None):
    st = status()
    name = name or st["default"]
    t = _find(name) if name else None
    if not t:
        return {"ok": False, "message": "No VPN set up yet - import a WireGuard config on the VPN tab."}
    for other in st["tunnels"]:
        if other["connected"] and other["name"] != name:
            disconnect(other["name"])
    if t["type"] == "wireguard":
        exe = wireguard_exe()
        if not exe:
            return {"ok": False, "message": "Install the free WireGuard app first (button on the VPN tab)."}
        code, out = run([exe, "/installtunnelservice", os.path.join(VPN_DIR, name + ".conf")], timeout=60)
        if code == 0:
            for _ in range(20):  # the tunnel service takes a moment to come up
                if _service_running(name):
                    break
                time.sleep(0.5)
            else:
                code, out = 1, "The tunnel didn't start - check the config or try another server."
    else:
        code, out = run(["rasdial", name], timeout=90)
    save_setting("vpn_default", name)
    return {"ok": code == 0, "message": out.strip() or ("Connected." if code == 0 else "Couldn't connect.")}


def disconnect(name=None):
    st = status()
    name = name or st["connected"]
    t = _find(name) if name else None
    if not t:
        return {"ok": True}
    if t["type"] == "wireguard":
        exe = wireguard_exe()
        code, out = run([exe, "/uninstalltunnelservice", name], timeout=60) if exe else (1, "WireGuard not installed")
    else:
        code, out = run(["rasdial", name, "/disconnect"], timeout=60)
    return {"ok": code == 0, "message": out.strip()}


def toggle():
    st = status()
    return disconnect(st["connected"]) if st["connected"] else connect(st["default"])


def public_ip():
    try:
        req = urllib.request.Request("https://ipinfo.io/json", headers={"User-Agent": "PCShield/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            d = json.loads(r.read().decode())
        return {"ip": d.get("ip"), "city": d.get("city"), "region": d.get("region"),
                "country": d.get("country"), "org": d.get("org")}
    except Exception:
        try:
            with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=8) as r:
                return {"ip": json.loads(r.read().decode()).get("ip")}
        except Exception:
            return {"ip": None}
