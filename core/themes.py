"""Themes: saves the choice, swaps the window/taskbar icon, and keeps PC Shield shortcuts on the
Desktop / Start menu pointed at the matching icon. (The .exe file's own icon is baked in at build time.)"""
import ctypes
import os
import shutil
import sys

from .util import DATA_DIR, ps, ps_out, ps_quote, load_settings, save_setting

THEMES = {
    "kara": "Kara - Purple",
    "kaleb": "Kaleb - Red",
    "anthony": "Anthony - Cotton Candy",
    "james": "James - Green",
    "dnarte": "Dnarte - Dark Blue",
}
ICON_DIR = os.path.join(DATA_DIR, "icons")
SHORTCUT = "PC Shield.lnk"


def _resource(*p):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, *p)


def icon_path(theme):
    """Copy of the theme's .ico in LocalAppData (a stable path shortcuts can point at)."""
    os.makedirs(ICON_DIR, exist_ok=True)
    dst = os.path.join(ICON_DIR, f"{theme}.ico")
    src = _resource("icons", f"{theme}.ico")
    if os.path.isfile(src) and (not os.path.isfile(dst) or os.path.getsize(dst) != os.path.getsize(src)):
        shutil.copyfile(src, dst)
    return dst


def current():
    t = load_settings().get("theme")
    return t if t in THEMES else None


def _target():
    if getattr(sys, "frozen", False):
        return sys.executable, ""
    script = os.path.abspath(sys.modules["__main__"].__file__)
    return sys.executable.replace("python.exe", "pythonw.exe"), f'"{script}"'


def _shortcut_paths():
    out = ps_out("[Environment]::GetFolderPath('Desktop'); [Environment]::GetFolderPath('Programs')").splitlines()
    return [os.path.join(p.strip(), SHORTCUT) for p in out if p.strip()]


def shortcuts():
    paths = _shortcut_paths()
    lp = launcher_path()
    exe, _ = _target()
    return {"desktop": os.path.isfile(paths[0]) if paths else False,
            "start": os.path.isfile(paths[1]) if len(paths) > 1 else False,
            "moved": bool(lp) and os.path.normcase(lp) != os.path.normcase(exe)}


LAUNCHER = "PC Shield Launcher"


def register_launcher():
    """On-demand task with highest privileges. Shortcuts run this task, so PC Shield opens
    elevated without a UAC prompt. The task's command is fixed (no arguments can be passed in)."""
    exe, args = _target()
    script = (
        f"$u=\"$env:USERDOMAIN\\$env:USERNAME\"; "
        f"$a=New-ScheduledTaskAction -Execute {ps_quote(exe)}" + (f" -Argument {ps_quote(args)}" if args else "") + "; "
        f"$p=New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest; "
        f"$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
        f"-ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances Parallel -Priority 4; "
        f"Register-ScheduledTask -TaskName {ps_quote(LAUNCHER)} -Action $a -Principal $p -Settings $s -Force | Out-Null; 'ok'"
    )
    out, err, _ = ps(script)
    if not out.strip().endswith("ok"):
        raise RuntimeError(err.strip() or "Couldn't create the no-prompt launcher task.")


def launcher_path():
    return ps_out(f"$t=Get-ScheduledTask -TaskName {ps_quote(LAUNCHER)} -ErrorAction SilentlyContinue; if ($t) {{ $t.Actions[0].Execute }}")


def _write_shortcut(lnk, theme):
    exe, _ = _target()
    run_args = '/run /tn "' + LAUNCHER + '"'
    schtasks = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "schtasks.exe")
    ps(f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut({ps_quote(lnk)}); "
       f"$s.TargetPath={ps_quote(schtasks)}; $s.Arguments={ps_quote(run_args)}; "
       f"$s.WindowStyle=7; $s.WorkingDirectory={ps_quote(os.path.dirname(exe))}; "
       f"$s.IconLocation={ps_quote(icon_path(theme) + ',0')}; $s.Description='PC Shield'; $s.Save()")


def create_shortcuts():
    theme = current() or "kara"
    register_launcher()
    for lnk in _shortcut_paths():
        _write_shortcut(lnk, theme)
    return {"ok": True, **shortcuts()}


WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)


def _user32():
    """user32 with argtypes set, so 64-bit window handles are passed correctly."""
    from ctypes import wintypes as w
    u = ctypes.WinDLL("user32", use_last_error=True)
    u.GetWindowTextW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
    u.GetClassNameW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
    u.ShowWindow.argtypes = [w.HWND, ctypes.c_int]
    u.IsIconic.argtypes = [w.HWND]
    u.SetForegroundWindow.argtypes = [w.HWND]
    u.BringWindowToTop.argtypes = [w.HWND]
    u.GetForegroundWindow.restype = w.HWND
    u.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.c_void_p]
    u.GetWindowThreadProcessId.restype = w.DWORD
    u.AttachThreadInput.argtypes = [w.DWORD, w.DWORD, w.BOOL]
    u.LoadImageW.argtypes = [w.HINSTANCE, w.LPCWSTR, w.UINT, ctypes.c_int, ctypes.c_int, w.UINT]
    u.LoadImageW.restype = w.HANDLE
    u.SendMessageW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
    u.SendMessageW.restype = w.LPARAM
    u.EnumWindows.argtypes = [WNDENUMPROC, w.LPARAM]
    return u


def bring_to_front(hwnd):
    """Show, un-minimize and focus our window. Works even when PC Shield was started by Task Scheduler
    (the no-prompt shortcut), which Windows otherwise doesn't allow to take focus."""
    try:
        u = _user32()
        k = ctypes.WinDLL("kernel32")
        u.ShowWindow(hwnd, 5)  # SW_SHOW (it may be hidden in the tray)
        if u.IsIconic(hwnd):
            u.ShowWindow(hwnd, 9)  # SW_RESTORE - back to how it was (maximized if it was)
        fg = u.GetForegroundWindow()
        fg_thread = u.GetWindowThreadProcessId(fg, None) if fg else 0
        me = k.GetCurrentThreadId()
        attached = bool(fg_thread and fg_thread != me and u.AttachThreadInput(me, fg_thread, True))
        u.BringWindowToTop(hwnd)
        u.SetForegroundWindow(hwnd)
        if attached:
            u.AttachThreadInput(me, fg_thread, False)
    except Exception:
        pass


def find_app_window(title="PC Shield"):
    """Our window: exact title AND a WinForms window class (so an Explorer folder named 'PC Shield' doesn't match)."""
    user32 = _user32()
    found = []

    def cb(hwnd, _):
        buf = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, buf, 256)
        if buf.value == title:
            cls = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls, 256)
            if cls.value.startswith("WindowsForms"):
                found.append(hwnd)
                return False
        return True
    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return found[0] if found else None


def set_window_icon(theme, title="PC Shield"):
    try:
        user32 = _user32()
        hwnd = find_app_window(title)
        if not hwnd:
            return False
        path = icon_path(theme)
        LR_LOADFROMFILE, IMAGE_ICON, WM_SETICON = 0x10, 1, 0x80
        big = user32.LoadImageW(None, path, IMAGE_ICON, 256, 256, LR_LOADFROMFILE)
        small = user32.LoadImageW(None, path, IMAGE_ICON, 32, 32, LR_LOADFROMFILE)
        if big:
            user32.SendMessageW(hwnd, WM_SETICON, 1, big)
        if small:
            user32.SendMessageW(hwnd, WM_SETICON, 0, small)
        return True
    except Exception:
        return False


# Title bar painted in the same solid color as the app's header (web/app.css --caption), so the
# window's top reads as one seamless bar. Windows 11 paints any color; Windows 10 gets a dark bar.
CAPTION = {"kara": "#0d0816", "kaleb": "#120707", "anthony": "#0d0b14", "james": "#06100b", "dnarte": "#070b17"}
CAPTION_TEXT = {"kara": "#9a8fb0", "kaleb": "#a68e8e", "anthony": "#9d95ae", "james": "#8a9b91", "dnarte": "#8c93a8"}


def _colorref(hex_color):
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return r | (g << 8) | (b << 16)  # COLORREF is 0x00BBGGRR


def style_titlebar(theme, title="PC Shield"):
    try:
        from ctypes import wintypes as w
        hwnd = find_app_window(title)
        if not hwnd:
            return False
        dwm = ctypes.WinDLL("dwmapi")
        dwm.DwmSetWindowAttribute.argtypes = [w.HWND, w.DWORD, ctypes.c_void_p, w.DWORD]

        def put(attr, value):
            v = ctypes.c_int(value)
            return dwm.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(v), ctypes.sizeof(v))

        if put(20, 1) != 0:          # DWMWA_USE_IMMERSIVE_DARK_MODE -> light min/max/close glyphs
            put(19, 1)               # same attribute on Windows 10 1809-1909
        put(38, 1)                   # DWMWA_SYSTEMBACKDROP_TYPE = none, so our exact color shows (not Mica)
        cap = _colorref(CAPTION.get(theme, CAPTION["kara"]))
        put(35, cap)                 # DWMWA_CAPTION_COLOR (Windows 11)
        put(36, _colorref(CAPTION_TEXT.get(theme, CAPTION_TEXT["kara"])))  # DWMWA_TEXT_COLOR
        put(34, cap)                 # DWMWA_BORDER_COLOR - no light outline around the window
        # make Windows repaint the frame now (Windows 10 otherwise waits for a focus change)
        u = ctypes.WinDLL("user32")
        u.SetWindowPos.argtypes = [w.HWND, w.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.UINT]
        u.SetWindowPos(hwnd, None, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020)  # NOSIZE|NOMOVE|NOZORDER|NOACTIVATE|FRAMECHANGED
        return True
    except Exception:
        return False


def set_theme(theme):
    if theme not in THEMES:
        return {"ok": False, "message": "Unknown theme"}
    save_setting("theme", theme)
    set_window_icon(theme)
    style_titlebar(theme)
    sc = shortcuts()
    paths = _shortcut_paths()
    for lnk, exists in zip(paths, (sc["desktop"], sc["start"])):
        if exists:
            _write_shortcut(lnk, theme)
    if sc["desktop"] or sc["start"]:
        ps("ie4uinit.exe -show", timeout=30)  # nudge Explorer to refresh shortcut icons
    return {"ok": True, "theme": theme}
