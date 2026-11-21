# PC Shield

Free, Malwarebytes-style security and cleanup app for Windows. It uses **Microsoft Defender** (built into
Windows) as the scanning engine and adds what Defender doesn't show you: unwanted programs, tampered
Windows settings, sketchy startup items, bloatware, privacy switches, breach checks, a file shredder and a
VPN switch. Nothing is ever removed without you choosing it.

Windows 10/11 only. Built for a few friends' PCs - expect rough edges on hardware it hasn't seen.

## Download

Grab `PCShield.exe` from [Releases](../../releases) and put it in a folder it can stay in (shortcuts, startup
and scheduled scans point to where it lives). No install, no Python needed. It asks for admin when it opens.

- Windows SmartScreen may warn because the exe isn't code-signed: **More info → Run anyway**.
- Blank window? Install the free Microsoft Edge **WebView2 Runtime** (already on Windows 11).

## What it does

| Tab | |
|---|---|
| Dashboard | Protection status, last scan, VPN switch, privacy score, breach count, PC health |
| Scanner | Quick / Deep / folder scans with live progress, reports, scheduler, exclusions |
| Startup | Turn boot apps on/off (Task Manager's own switch), signature check, flags hidden PowerShell/rundll32 tricks |
| Bloatware | Trialware, PUPs, heavy vendor RGB suites, Store junk - uninstall what you pick |
| Performance | "Why is it slow?" - HDD system drive, RAM speed/channels, disk space, power plan, live CPU/RAM use |
| Privacy | Windows ad/tracking switches, remote-access exposure (RDP, AnyDesk, ...), webcam & mic usage log |
| Identity | Email breach lookup and password leak check |
| Shredder | Overwrite + delete files for good, TRIM on SSDs, wipe free space |
| VPN | On/off switch for WireGuard tunnels (e.g. a free Proton VPN config) and Windows VPN profiles |
| Settings | Themes, no-prompt shortcut, start with Windows, tray behavior, trusted publishers |

### How scans handle removals
- During a PC Shield scan, Defender is set to *report only* for the threat levels you picked, then put back
  exactly as it was (also on the next launch if the app ever crashes mid-scan).
- Every finding gets a dropdown: **Quarantine / Uninstall / Restore default / Disable** - **Skip this time** -
  **Exclude from future scans** (or **Trust** the publisher). Quarantined items can be restored.
- Changes made by programs with a valid signature from a trusted publisher (Riot, Valve, NVIDIA, ...) aren't flagged.
- If Tamper Protection stops the report-only switch, the report says so and anything Defender quarantined
  can be restored.

### What leaves your PC
- **Breach check:** the email you type goes to [XposedOrNot](https://xposedornot.com) (free breach database).
- **Password check:** only the first 5 characters of the password's SHA-1 hash go to
  [Have I Been Pwned](https://haveibeenpwned.com/Passwords) - never the password.
- **VPN tab:** asks ipinfo.io for your public IP / location.
- Everything else stays local. Nothing is uploaded anywhere else.

## Themes

Kara (purple), Kaleb (red), Anthony (cotton candy), James (green), Dnarte (dark blue). The theme changes the
colors, logo, title bar, taskbar/tray icon and the shortcut icons. The `.exe` file's own icon is set at build
time (`icon.ico` = Kara's; copy another one from `icons\` over it before building).

## Building from source

Needs Python 3.10-3.13 from python.org ("Add python.exe to PATH" ticked).

1. Clone this repo (or download the ZIP).
2. Double-click **build.bat**. It closes a running PC Shield, installs the build tools and writes
   `dist\PCShield.exe`.

Run without building: `py -m pip install pywebview psutil pystray pillow` then `py app.py`
(`py app.py --debug` opens the WebView dev tools).

Every push to `main` builds the exe on GitHub (see the Actions tab → latest run → Artifacts). To publish a
release for friends: `git tag v1.2.0` then `git push --tags` - the exe is attached to the release automatically.

### Tests

```
python tests/test_backend.py                  # backend logic, Windows parts stubbed - runs anywhere
python -m http.server 8765 --directory web    # then, in another terminal:
python tests/test_ui.py                       # clicks through the UI with fake data (needs Playwright)
```

Preview the UI in any browser with fake data: `web/index.html?mock` (through the local server above).

## Files the app writes

`%LOCALAPPDATA%\PCShield\` - `settings.json`, `reports\` (newest 100), `vpn\*.conf`, `icons\`,
`pcshield.log` (errors - attach it to bug reports).

Task Scheduler: "PC Shield" (start with Windows), "PC Shield Launcher" (no-prompt shortcut),
"PC Shield Quick Scan" / "PC Shield Deep Scan" (scheduled scans).

## License

GPL-3.0-or-later - see [LICENSE](LICENSE).
