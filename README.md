# PC Shield

[![Build](https://github.com/Ynzie/PCShield/actions/workflows/build.yml/badge.svg)](https://github.com/Ynzie/PCShield/actions/workflows/build.yml)

Free, Malwarebytes-style security and cleanup app for Windows. It uses **Microsoft Defender** (built into
Windows) as the scanning engine and adds what Defender doesn't show you: unwanted programs, tampered
Windows settings, sketchy startup items, bloatware, privacy switches, breach checks, a file shredder and a
VPN switch. Nothing is ever removed without you choosing it.

Windows 10/11 only. Built for a few friends' PCs - expect rough edges on hardware it hasn't seen.

## Download

Grab `PCShield.exe` from the [latest release](https://github.com/Ynzie/PCShield/releases/latest) and put it in a folder it can stay in (shortcuts, startup
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
| Settings | Themes, updates, no-prompt shortcut, start with Windows, tray behavior, trusted publishers |

### How scans handle removals
- During a PC Shield scan, Defender is set to *report only* for the threat levels you picked, then put back
  exactly as it was (also on the next launch if the app ever crashes mid-scan).
- Every finding gets a dropdown: **Quarantine / Uninstall / Restore default / Disable** - **Skip this time** -
  **Exclude from future scans** (or **Trust** the publisher). Quarantined items can be restored.
- Changes made by programs with a valid signature from a trusted publisher (Riot, Valve, NVIDIA, ...) aren't flagged.
- If Tamper Protection stops the report-only switch, the report says so and anything Defender quarantined
  can be restored.

### Updates
Settings → **Updates** shows your version and checks this repo's latest release (and once a day on its own,
with a tray notice; switch that off there). **Update** downloads `PCShield.exe` from the release, checks it
against the SHA-256 checksum GitHub lists for the file, swaps it in and restarts. Nothing installs without
the click; drafts and pre-releases are ignored.

### What leaves your PC
- **Breach check:** the email you type goes to [XposedOrNot](https://xposedornot.com) (free breach database).
- **Password check:** only the first 5 characters of the password's SHA-1 hash go to
  [Have I Been Pwned](https://haveibeenpwned.com/Passwords) - never the password.
- **VPN tab:** asks ipinfo.io for your public IP / location.
- **Updates:** asks api.github.com for the latest release (and downloads it when you click Update).
- Everything else stays local. Nothing is uploaded anywhere else. Fonts ship inside the app.

### Security notes
PC Shield runs as admin, so it never lets a normal program steer what it does with those rights:
- The no-prompt shortcut, start-with-Windows and scheduled scans run a copy in
  `C:\Program Files\PC Shield\` (only admins can replace it), never the exe in Downloads.
- Reports, settings and VPN configs live in `C:\ProgramData\PCShield\`, which only admins can change
  (VPN keys: admins and SYSTEM only). A copy of that folder made by anything else is set aside, not trusted.
- Windows tools (PowerShell, icacls, cmd...) are started by full path from the real Windows folder, and
  folder locations come from Windows itself, not from environment variables a program could change.
- Programs installed only for your account are uninstalled with your normal rights, like Windows does.
- Links open in your normal browser, not an admin one. Imported WireGuard configs lose any
  Pre/PostUp script lines.

Found a problem? Open an issue.

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
release for friends: tag a version (`git tag v1.3.0` then `git push --tags`, or **Releases → Draft a new
release → new tag** on GitHub) - the exe is attached to the release automatically, and installed copies offer it
under Settings → Updates.

### Tests

```
python tests/test_backend.py                  # backend logic, Windows parts stubbed - runs anywhere
python tests/test_windows.py                  # real-Windows security checks (admin; the GitHub build runs it)
python -m http.server 8765 --directory web    # then, in another terminal:
python tests/test_ui.py                       # clicks through the UI with fake data (needs Playwright)
```

Preview the UI in any browser with fake data: `web/index.html?mock` (through the local server above).

## Files the app writes

`C:\ProgramData\PCShield\` - `settings.json`, `reports\` (newest 100), `vpn\*.conf`, `icons\`,
`pcshield.log` (errors - attach it to bug reports). Version 1.2 used `%LOCALAPPDATA%\PCShield\`; 1.3 moves
that data over on first start.

`C:\Program Files\PC Shield\PCShield.exe` - the protected copy the tasks below run (made when you turn one on).

Task Scheduler: "PC Shield" (start with Windows), "PC Shield Launcher" (no-prompt shortcut),
"PC Shield Quick Scan" / "PC Shield Deep Scan" (scheduled scans).

### Removing PC Shield
Turn off start with Windows and scheduled scans in the app, quit it from the tray, then (admin) run
`schtasks /delete /tn "PC Shield Launcher" /f`, delete the shortcuts, `C:\Program Files\PC Shield\` and
`C:\ProgramData\PCShield\`.

## License

GPL-3.0-or-later - see [LICENSE](LICENSE).
