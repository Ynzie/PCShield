"""
PC Shield - home security + cleanup app.
UI: web/ (HTML/CSS/JS, same look as SKT GOLD) rendered by pywebview (Edge WebView2).
Backend: core/ (Microsoft Defender engine + our own checks).

  python app.py               -> opens the app
  PCShield.exe --scan quick   -> silent scan (used by the Scan Scheduler)
"""
import ctypes
import functools
import os
import sys
import threading
import time
import traceback
import webbrowser

from core import autostart, install, themes, trust, identity, privacy, scanner, shredder, system, updater, vpn
from core.util import ps, load_settings, save_setting, log, LOG_FILE, WINDOWS_DIR
from core.version import VERSION

APP_NAME = "PC Shield"


def open_unelevated(target):
    """Open a link in the user's normal (non-admin) browser. Starting it from this admin process would
    run the browser as admin too; handing it to explorer.exe opens it with the user's own rights."""
    try:
        import subprocess
        subprocess.Popen([os.path.join(WINDOWS_DIR, "explorer.exe"), target])
    except OSError:
        webbrowser.open(target)


def restart_after_update(exe):
    """Start the new version (it waits for this one to close), then quit."""
    import subprocess
    try:
        subprocess.Popen([exe, "--after-update"], creationflags=0x00000008 | 0x00000200, close_fds=True)  # detached
    except OSError as e:
        log(f"restart after update: {e}")
    t = threading.Timer(1.0, TRAY.quit)
    t.daemon = True
    t.start()


def background_update_check():
    """Once a day (if on in Settings): look for a new release and mention it once per version in the tray."""
    try:
        if not updater.due():
            return
        r = updater.check()
        if r.get("available") and load_settings().get("update_notified") != r.get("latest"):
            save_setting("update_notified", r.get("latest"))
            if TRAY.icon:
                TRAY.icon.notify(f"PC Shield {r['latest']} is available. Open Settings to update.", "PC Shield")
    except Exception as e:  # noqa
        log(f"update check: {e}")


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def resource(*parts):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def safe(fn):
    @functools.wraps(fn)
    def wrap(*a, **kw):
        try:
            return fn(*a, **kw)
        except PermissionError:
            log(f"{fn.__name__}: permission denied\n{traceback.format_exc()}")
            return {"error": "Windows blocked that change - run PC Shield as administrator."}
        except Exception as e:  # noqa
            log(f"{fn.__name__} failed\n{traceback.format_exc()}")
            return {"error": str(e) or e.__class__.__name__}
    return wrap


class Api:
    def __init__(self):
        self._window = None

    # ---------------------------------------------------------- updates
    @safe
    def update_status(self):
        return {**updater.cached(), "install": install.installed_info()}

    @safe
    def check_updates(self):
        return {**updater.check(force=True), "auto": updater.auto_enabled(), "install": install.installed_info()}

    @safe
    def set_update_auto(self, on):
        return updater.set_auto(on)

    @safe
    def install_update(self):
        return updater.start_install(on_done=restart_after_update)

    @safe
    def update_state(self):
        return updater.state()

    # ---------------------------------------------------------- general
    @safe
    def info(self):
        return {"admin": is_admin(), "version": VERSION, "log": LOG_FILE}

    @safe
    @safe
    def open_url(self, url):
        url = str(url or "")
        if not url.startswith(("https://", "ms-settings:", "windowsdefender:")) or any(c in url for c in '"\r\n'):
            return {"ok": False, "message": "Blocked an unexpected link."}
        open_unelevated(url)
        return {"ok": True}

    def _dialog(self, kind, multiple=False, types=()):
        import webview
        fd = getattr(webview, "FileDialog", None)
        const = {"open": fd.OPEN if fd else webview.OPEN_DIALOG, "folder": fd.FOLDER if fd else webview.FOLDER_DIALOG}[kind]
        res = self._window.create_file_dialog(const, allow_multiple=multiple, file_types=types)
        return list(res) if res else []

    @safe
    def pick_files(self):
        return self._dialog("open", multiple=True)

    @safe
    def pick_folder(self):
        r = self._dialog("folder")
        return r[0] if r else None

    @safe
    def get_theme(self):
        return {"theme": themes.current(), "themes": themes.THEMES}

    @safe
    def set_theme(self, theme):
        r = themes.set_theme(theme)
        TRAY.set_theme(theme)
        return r

    @safe
    def shortcuts(self):
        return themes.shortcuts()

    @safe
    def create_shortcuts(self):
        return themes.create_shortcuts()

    @safe
    def trusted(self):
        return trust.trusted_list()

    @safe
    def trust_add(self, pub):
        return trust.add(pub)

    @safe
    def trust_remove(self, pub):
        return trust.remove(pub)

    @safe
    def trust_reset(self):
        return trust.reset()

    @safe
    def close_mode(self):
        return {"tray": load_settings().get("close_to_tray", True)}

    @safe
    def set_close_mode(self, tray):
        save_setting("close_to_tray", bool(tray))
        return {"ok": True}

    @safe
    def autostart_status(self):
        return autostart.status()

    @safe
    def set_autostart(self, enabled):
        return autostart.set_enabled(enabled)

    # ---------------------------------------------------------- dashboard
    @safe
    def dashboard(self):
        toggles = privacy.get_toggles()
        diag_flags = load_settings().get("health_flags")
        return {
            "protection": system.protection_status(),
            "last_scan": scanner.last_report(),
            "scan": scanner.scan_state(),
            "vpn": vpn.status(),
            "privacy": {"private": sum(1 for t in toggles if not t["allowed"]), "total": len(toggles)},
            "footprint": identity.last_footprint(),
            "health_flags": diag_flags,
            "admin": is_admin(),
        }

    @safe
    def update_definitions(self):
        out, err, code = ps("Update-MpSignature", timeout=600)
        return {"ok": code == 0, "message": "Definitions updated." if code == 0 else err.strip()}

    # ---------------------------------------------------------- scanner
    @safe
    def start_scan(self, kind="quick", path=None):
        return scanner.start_scan(kind, path)

    @safe
    def scan_state(self):
        return scanner.scan_state()

    @safe
    def cancel_scan(self):
        return scanner.cancel_scan()

    @safe
    def reports(self):
        return scanner.list_reports()

    @safe
    def report(self, rid):
        return scanner.get_report(rid)

    @safe
    def delete_report(self, rid):
        return scanner.delete_report(rid)

    @safe
    def apply_actions(self, rid, actions):
        return scanner.apply_actions(rid, actions)

    @safe
    def exclusions(self):
        return scanner.list_exclusions()

    @safe
    def remove_exclusion(self, det_id):
        return scanner.remove_exclusion(det_id)

    @safe
    def review_mode(self):
        return scanner.review_mode()

    @safe
    def set_review_mode(self, mode):
        save_setting("review_mode", mode if mode in ("all", "severe", "auto") else "all")
        return {"ok": True}

    @safe
    def schedules(self):
        return scanner.get_schedules()

    @safe
    def set_schedule(self, kind, enabled, freq, day, time_):
        return scanner.set_schedule(kind, enabled, freq, day, time_)

    # ---------------------------------------------------------- startup / bloat / health
    @safe
    def startup(self):
        return system.startup_entries()

    @safe
    def set_startup(self, ident, enabled):
        return system.set_startup(ident, enabled)

    @safe
    def bloat(self, show_all=False):
        return system.bloat_scan(show_all)

    @safe
    def uninstall(self, kind, ident):
        return system.uninstall(kind, ident)

    @safe
    def diagnostics(self):
        d = system.diagnostics()
        save_setting("health_flags", len(d["flags"]))
        return d

    @safe
    def processes(self):
        return system.top_processes()

    # ---------------------------------------------------------- privacy
    @safe
    def privacy_toggles(self):
        return privacy.get_toggles()

    @safe
    def set_privacy(self, tid, allow):
        return privacy.set_toggle(tid, allow)

    @safe
    def privacy_all(self, allow=False):
        return privacy.set_all(allow)

    @safe
    def remote_access(self):
        return privacy.remote_access()

    @safe
    def set_windows_remote(self, which, enabled):
        return privacy.set_windows_remote(which, enabled)

    @safe
    def kill_tool(self, processes):
        return privacy.kill_tool(processes)

    @safe
    def device_usage(self, cap):
        return privacy.device_usage(cap)

    @safe
    def set_device_access(self, cap, allow):
        return privacy.set_device_access(cap, allow)

    # ---------------------------------------------------------- identity
    @safe
    def check_email(self, email):
        return identity.check_email(email)

    @safe
    def last_footprint(self):
        return identity.last_footprint()

    @safe
    def check_password(self, pw):
        return identity.check_password(pw)

    # ---------------------------------------------------------- shredder
    @safe
    def shred_inspect(self, paths):
        return shredder.inspect(paths)

    @safe
    def shred_start(self, paths, passes=1, trim=True):
        return shredder.start(paths, passes, trim)

    @safe
    def shred_state(self):
        return shredder.state()

    @safe
    def drives(self):
        return shredder.drives()

    @safe
    def wipe_free(self, letter):
        return shredder.wipe_free_space(letter)

    @safe
    def wipe_state(self):
        return shredder.wipe_state()

    # ---------------------------------------------------------- vpn
    @safe
    def vpn_status(self):
        return vpn.status()

    @safe
    def vpn_toggle(self):
        return vpn.toggle()

    @safe
    def vpn_connect(self, name):
        return vpn.connect(name)

    @safe
    def vpn_disconnect(self, name):
        return vpn.disconnect(name)

    @safe
    def vpn_import(self):
        files = self._dialog("open", types=("WireGuard config (*.conf)",))
        if not files:
            return {"ok": False, "cancelled": True}
        return vpn.import_config(files[0])

    @safe
    def vpn_remove(self, name):
        return vpn.remove_config(name)

    @safe
    def vpn_set_default(self, name):
        return vpn.set_default(name)

    @safe
    def public_ip(self):
        return vpn.public_ip()


_MUTEX = None


class Tray:
    """System-tray icon so closing the window keeps PC Shield running in the background."""

    def __init__(self):
        self.icon = None
        self.window = None
        self.quitting = False
        self.notified = False

    def _image(self, theme):
        from PIL import Image
        return Image.open(resource("web", "icons", f"{theme or 'kara'}.png"))

    def start(self, window):
        self.window = window
        try:
            import pystray
        except ImportError:
            return
        menu = pystray.Menu(
            pystray.MenuItem("Open PC Shield", lambda *_: self.show(), default=True),
            pystray.MenuItem("Quick scan", lambda *_: self.quick_scan()),
            pystray.MenuItem("VPN on/off", lambda *_: threading.Thread(target=self.vpn_toggle, daemon=True).start()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit PC Shield", lambda *_: self.quit()),
        )
        try:
            self.icon = pystray.Icon("PCShield", self._image(themes.current()), "PC Shield", menu)
            threading.Thread(target=self.icon.run, daemon=True).start()
        except Exception:
            self.icon = None  # no tray -> the X button simply quits
            log(f"tray icon failed\n{traceback.format_exc()}")

    def set_theme(self, theme):
        if self.icon:
            try:
                self.icon.icon = self._image(theme)
            except Exception:
                pass

    def vpn_toggle(self):
        r = vpn.toggle()
        st = vpn.status()
        msg = (f"VPN connected ({st['connected']})" if st.get("connected") else "VPN off") if r.get("ok") \
            else (r.get("message") or "VPN couldn't change")
        try:
            self.icon.notify(msg, "PC Shield")
        except Exception:
            pass

    def show(self):
        if not self.window:
            return
        self.window.show()
        hwnd = themes.find_app_window(APP_NAME)
        if hwnd:
            themes.bring_to_front(hwnd)

    def hide(self):
        if not self.window:
            return
        self.window.hide()
        if self.icon and not self.notified and not load_settings().get("tray_tip_shown"):
            self.notified = True
            save_setting("tray_tip_shown", True)
            try:
                self.icon.notify("Still running in the background. Right-click the tray icon to quit.", "PC Shield")
            except Exception:
                pass

    def quick_scan(self):
        scanner.start_scan("quick")
        self.show()

    def quit(self):
        self.quitting = True
        try:
            if self.icon:
                self.icon.stop()
        finally:
            if self.window:
                self.window.destroy()

    def on_closing(self, *_):
        """X button: hide to tray instead of quitting (unless turned off in Settings or tray unavailable).
        Never blocks a Windows shutdown / sign-out."""
        shutting_down = False
        try:
            shutting_down = bool(ctypes.windll.user32.GetSystemMetrics(0x2000))  # SM_SHUTTINGDOWN
        except Exception:
            pass
        if self.quitting or shutting_down or not self.icon or not load_settings().get("close_to_tray", True):
            if self.icon and not self.quitting:
                self.icon.stop()
            return True
        threading.Timer(0.05, self.hide).start()  # hide outside the close event to avoid a UI deadlock
        return False


TRAY = Tray()


def bring_existing_to_front(wait=0):
    """Single instance: if PC Shield is already open, show that window instead of opening a second copy.
    wait: seconds to wait for the other copy to close first (used right after an update)."""
    global _MUTEX
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateMutexW.restype = ctypes.c_void_p
        k32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        end = time.time() + wait
        while True:
            _MUTEX = k32.CreateMutexW(None, False, "Local\\PCShieldApp")
            if ctypes.get_last_error() != 183:  # ERROR_ALREADY_EXISTS
                return False
            if time.time() >= end:
                break
            k32.CloseHandle(_MUTEX)
            time.sleep(0.5)
        hwnd = themes.find_app_window(APP_NAME)
        if hwnd:
            themes.bring_to_front(hwnd)
        return True
    except Exception:
        return False


def relaunch_as_admin():
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    if not getattr(sys, "frozen", False):
        params = f'"{os.path.abspath(sys.argv[0])}" {params}'
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    if rc > 32:
        sys.exit(0)


def prepare_data():
    """Before anything reads reports/settings: make the data folder admin-only, bring over 1.2's data,
    and put Defender back if a scan was interrupted."""
    if is_admin():
        try:
            install.secure_data_dir()  # admin-only data folder (reports/settings/VPN configs we act on)
            install.migrate_old_data()
        except Exception:
            log(f"securing the data folder failed\n{traceback.format_exc()}")
    try:
        scanner.recover_defender_actions()
    except Exception:
        pass


def selftest(out_path):
    """Used by the GitHub build: prove the packaged exe can load everything it needs, then exit."""
    import json
    result = {"version": VERSION, "ok": True, "errors": []}
    for mod in ("webview", "pystray", "pystray._win32", "PIL.Image", "psutil", "clr"):
        try:
            __import__(mod)
        except Exception as e:  # noqa
            result["ok"] = False
            result["errors"].append(f"import {mod}: {e}")
    for rel in (("web", "index.html"), ("web", "app.js"), ("web", "app.css"), ("web", "icons", "kara.png"),
                ("web", "fonts", "inter-latin-400-normal.woff2"), ("web", "fonts", "orbitron-latin-900-normal.woff2"),
                ("icons", "kara.ico")):
        if not os.path.isfile(resource(*rel)):
            result["ok"] = False
            result["errors"].append("missing " + "/".join(rel))
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    sys.exit(0 if result["ok"] else 1)


def main():
    if "--selftest" in sys.argv:
        i = sys.argv.index("--selftest")
        selftest(sys.argv[i + 1] if i + 1 < len(sys.argv) else os.path.join(os.environ.get("TEMP", "."), "pcshield-selftest.json"))
    if "--scan" in sys.argv:
        prepare_data()
        i = sys.argv.index("--scan")
        try:
            scanner.headless_scan(sys.argv[i + 1] if i + 1 < len(sys.argv) else "quick")
        except Exception:  # no window to show it in - log it instead of a crash dialog at 3 am
            log(f"scheduled scan failed\n{traceback.format_exc()}")
        return
    if not is_admin():
        relaunch_as_admin()  # exits if the elevated copy started
    if bring_existing_to_front(wait=20 if "--after-update" in sys.argv else 0):
        return  # already open - just show it (and leave its data alone)
    prepare_data()
    threading.Thread(target=install.startup_maintenance, daemon=True).start()
    import webview
    api = Api()
    background = "--startup" in sys.argv  # started with Windows: live in the tray until opened
    # maximized=True lets pywebview open it maximized; forcing it with ShowWindow here would also
    # pop the window open when it's meant to start hidden in the tray
    win = webview.create_window(APP_NAME, resource("web", "index.html"), js_api=api,
                                width=1400, height=900, min_size=(980, 640), background_color=themes.CAPTION.get(themes.current() or "kara", "#0d0816"),
                                hidden=background, maximized=True)
    api._window = win

    def _on_shown(*_):
        themes.set_window_icon(themes.current() or "kara", APP_NAME)
        themes.style_titlebar(themes.current() or "kara", APP_NAME)  # title bar = header color (seamless)
        if not background:
            hwnd = themes.find_app_window(APP_NAME)
            if hwnd:
                themes.bring_to_front(hwnd)  # launched via Task Scheduler (no-prompt shortcut) -> may not get focus

    win.events.shown += _on_shown
    win.events.closing += TRAY.on_closing
    try:
        def _started():
            TRAY.start(win)
            t = threading.Timer(20, background_update_check)  # after start-up has settled
            t.daemon = True
            t.start()
        webview.start(_started, gui="edgechromium", debug="--debug" in sys.argv)
    except Exception:
        log(f"window failed to start (is the WebView2 runtime installed?)\n{traceback.format_exc()}")
        ctypes.windll.user32.MessageBoxW(None, "PC Shield couldn't open its window.\n\nInstall the Microsoft Edge "
                                         "WebView2 Runtime (free, from microsoft.com) and try again.\n\n"
                                         f"Details were saved to {LOG_FILE}", APP_NAME, 0x10)


if __name__ == "__main__":
    main()
