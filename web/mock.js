/* Preview-only fake backend. Active only when the page is opened with ?mock - never in the real app. */
if (new URLSearchParams(location.search).has('mock')) {
  const Q = new URLSearchParams(location.search);
  const wait = (v, ms = 250) => new Promise(r => setTimeout(() => r(JSON.parse(JSON.stringify(v))), ms));
  const report = {id: 'r1', kind: 'quick', started: '2026-11-18T09:02:57', duration: 218, items_checked: 412, engine: 'Microsoft Defender', engine_note: '',
    detections: [
      {id: 'threat|1', category: 'threat', name: 'Trojan:Win32/Wacatac.B!ml', severity: 'Severe', location: 'C:\\Users\\Kara\\Downloads\\FreeRobux_Installer.exe', state: 'found'},
      {id: 'threat|2', category: 'threat', name: 'PUA:Win32/Presenoker', severity: 'Low', location: 'C:\\Users\\Kara\\AppData\\Local\\Temp\\setup_x.exe', state: 'quarantined'},
      {id: 'pup|McAfee', category: 'pup', name: 'McAfee LiveSafe', location: 'Trial antivirus - McAfee, LLC', note: 'Remove - Defender is free.', state: 'found'},
      {id: 'pup|Wave', category: 'pup', name: 'Wave Browser', location: 'Browser hijacker - Wavesor Software', note: 'Remove.', state: 'found'},
      {id: 'pum|defex', category: 'pum', name: 'Defender skips this path', location: 'C:\\ProgramData\\svchost', note: "Couldn't tell which program this belongs to.", state: 'found'},
      {id: 'pum|defex2', category: 'pum', name: 'Defender skips this path', location: 'D:\\Games\\SomeLauncher', signer: 'Overgrowth Studios LLC', sig_status: 'Valid', note: 'Belongs to Overgrowth Studios LLC (signature: Valid).', state: 'found'},
      {id: 'startup|x', category: 'startup', name: 'Updater', location: 'C:\\Users\\Kara\\AppData\\Roaming\\upd\\upd.exe /silent', note: 'Unsigned and starts from a user-writable folder.', state: 'ignored'},
    ]};
  const sum = r => { const c = {threat:0,pup:0,pum:0,startup:0,ignored:0,quarantined:0,fixed:0,skipped:0,open:0};
    r.detections.forEach(d => { c[d.category]++; if (d.state==='ignored') c.ignored++; else if (d.state==='quarantined') c.quarantined++; else if (d.state==='found') c.open++; else c.fixed++; }); return c; };
  report.summary = sum(report);
  const PRIV = [
      {id: 'adid', group: 'Advertising and tracking', title: 'Block apps from using your advertising ID', desc: 'Stops apps building an ad profile from what you do.', allowed: false},
      {id: 'start', group: 'Advertising and tracking', title: 'Hide suggested apps and promotions in Start', desc: "Removes sponsored apps from Start.", allowed: true},
      {id: 'lock', group: 'Advertising and tracking', title: "Hide ads and 'fun facts' on the lock screen", desc: 'Stops promotional content on the lock screen.', allowed: true},
      {id: 'diag', group: 'Windows privacy', title: 'Limit diagnostic data and tailored experiences', desc: 'Sends Microsoft only the required minimum.', allowed: false},
      {id: 'websearch', group: 'Windows privacy', title: 'Keep Start and taskbar search off the web (no Bing)', desc: "Searching for a file won't send what you type to Bing.", allowed: true}];
  let scanning = false, scanStart = 0;
  window.MOCK = {
    info: () => wait({admin: true}),
    dashboard: () => wait({protection: {products: [{name: 'Windows Defender', active: true}], mode: 'Normal', realtime: true, tamper: true, av_enabled: true,
      defs_updated: '2026-11-18 03:12', defs_version: '1.421.122.0', active_threats: 1, others: []},
      last_scan: report, scan: {running: scanning}, vpn: {tunnels: [{name: 'proton-US-FREE-12', type: 'wireguard'}], connected: null, default: 'proton-US-FREE-12'},
      privacy: {private: 3, total: 8}, footprint: {email: 'kara@example.com', count: 4, checked: '2026-11-17T20:11:00'}, health_flags: 3, admin: true}),
    update_definitions: () => wait({ok: true, message: 'Definitions updated.'}, 900),
    start_scan: () => { scanning = true; scanStart = Date.now(); setTimeout(() => scanning = false, 9000); return wait({ok: true}); },
    scan_state: () => { const el = Math.round((Date.now() - scanStart) / 1000);
      if (!scanning && Q.has('bg')) return wait({running: false, background: {kind: 'deep', elapsed: 754}}, 50);
      return wait({running: scanning, stage: 'Scanning every file on C:', progress: 40, step: 2, steps: 3, target: 'C:', scanned: 1.3e10 + el * 9e7,
        total: 4.1e11, rate: 9.1e7, pct: (1.3e10 + el * 9e7) / 4.1e11, eta: 4350 - el, elapsed: 1830 + el, report_id: 'r1'}, 50); },
    cancel_scan: () => wait({ok: true}),
    reports: () => wait([{...report}, {...report, id: 'r0', kind: 'deep', started: '2026-11-02T09:02:57', duration: 3920, summary: {threat:0,pup:2,pum:0,startup:0,open:0,ignored:0,quarantined:0,fixed:2}}]),
    report: () => wait(report), delete_report: () => wait({ok: true}),
    apply_actions: (id, acts) => { if (Q.has('fail')) return wait({error: 'Simulated failure'}, 300); acts.forEach(a => { const d = report.detections.find(x => x.id === a.id);
      d.state = a.action === 'exclude' ? 'ignored' : a.action === 'skip' ? 'skipped' : a.action === 'restore' ? 'restored' : a.action === 'unexclude' ? 'found' : d.category === 'threat' ? 'quarantined' : 'fixed'; });
      report.summary = sum(report); return wait({report, results: acts.map(a => ({id: a.id, name: a.id, ok: true}))}, 700); },
    exclusions: () => wait([{id: 'startup|x', category: 'startup', name: 'Updater', location: 'C:\\Users\\Kara\\AppData\\Roaming\\upd\\upd.exe', added: '2026-11-10T12:00:00'}]),
    remove_exclusion: () => wait({ok: true}), review_mode: () => wait('all'), set_review_mode: () => wait({ok: true}),
    schedules: () => wait({quick: {Next: '2026-11-19 12:30', Last: '2026-11-18 12:30', Start: '12:30', Weekly: false, Days: 0, Enabled: true}, deep: {Next: '2026-11-21 03:00', Last: '', Start: '03:00', Weekly: true, Days: 64, Enabled: true}}),
    set_schedule: () => wait({ok: true}), pick_folder: () => wait('D:\\Games'), pick_files: () => wait(['C:\\Users\\Kara\\Documents\\taxes-2025.pdf']),
    startup: () => wait([
      {id: 'a', name: 'Discord', publisher: 'Discord Inc.', signer: 'Discord Inc.', signature: 'Valid', scope: 'Current user', command: 'C:\\Users\\Kara\\AppData\\Local\\Discord\\Update.exe --processStart Discord.exe', enabled: true},
      {id: 'b', name: 'ArmouryCrate', signer: 'ASUSTeK COMPUTER INC.', signature: 'Valid', scope: 'All users', command: '"C:\\Program Files\\ASUS\\ArmouryCrate\\ArmouryCrate.exe"', enabled: true},
      {id: 'c', name: 'Steam', signer: 'Valve Corp.', signature: 'Valid', scope: 'Current user', command: '"C:\\Program Files (x86)\\Steam\\steam.exe" -silent', enabled: false},
      {id: 'd', name: 'Updater', signer: '', signature: 'NotSigned', scope: 'Current user', command: 'C:\\Users\\Kara\\AppData\\Roaming\\upd\\upd.exe /silent', enabled: true, suspicious: true, why: 'Unsigned (NotSigned) and starts from a user-writable folder'}]),
    set_startup: () => wait({ok: true}),
    bloat: () => wait([
      {id: '1', kind: 'win32', name: 'McAfee LiveSafe', category: 'Trial antivirus', level: 'pup', advice: 'Remove - Defender is free.', publisher: 'McAfee, LLC', size_h: '412.0 MB'},
      {id: '2', kind: 'win32', name: 'ARMOURY CRATE Service', category: 'Vendor RGB suite (heavy)', level: 'optional', advice: 'Very heavy. Keep only if needed for RGB/fans.', publisher: 'ASUS', size_h: '1.1 GB'},
      {id: '3', kind: 'appx', name: 'king.com.CandyCrushSaga', category: 'Store app', level: 'optional', advice: 'Candy Crush and friends - safe to remove', publisher: 'Microsoft Store', size_h: ''}]),
    uninstall: () => wait({ok: true, removed: true, message: 'Removed.'}, 600),
    diagnostics: () => wait({flags: [{level: 'bad', title: 'Windows is on a hard drive (HDD)', text: 'The #1 cause of slow boots and slow app launches. Moving Windows to an SSD is the single biggest fix.'},
      {level: 'warn', title: 'RAM below rated speed', text: 'XMP/EXPO is probably off in the BIOS - turning it on is free performance.'},
      {level: 'warn', title: '14 apps launch at boot', text: "Disable the ones she doesn't need on the Startup tab."}],
      info: [['Memory', '16.0 GB (71% in use)'], ['C: drive', '88.2 GB free of 931.5 GB (9%)'], ['Disk 0 (Windows)', 'ST1000DM010 - HDD, SATA, 931.5 GB, Healthy'], ['CPU', 'Intel(R) Core(TM) i7-8700K'], ['GPU', 'NVIDIA GeForce RTX 3060'], ['RAM sticks', '2 x 8.0 GB at 2133 MT/s (rated 3200)']]}, 900),
    processes: () => wait([{name: 'chrome.exe', count: 31, cpu: 6.2, mem: 2.9e9, mem_h: '2.7 GB'}, {name: 'ArmouryCrate.exe', count: 4, cpu: 3.1, mem: 6e8, mem_h: '572.2 MB'}, {name: 'Discord.exe', count: 7, cpu: 1.2, mem: 7e8, mem_h: '667.6 MB'}], 1500),
    privacy_toggles: () => wait(PRIV.map(x => ({...x})))||wait([
      {id: 'adid', group: 'Advertising and tracking', title: 'Allow apps to use your advertising ID', desc: 'Turn this off to stop apps building an ad profile from your activity.', allowed: false},
      {id: 'start', group: 'Advertising and tracking', title: 'Allow suggested apps and promotions in Start', desc: 'Turn this off to remove sponsored apps from Start.', allowed: true},
      {id: 'lock', group: 'Advertising and tracking', title: 'Allow fun facts and ads on the lock screen', desc: 'Turn this off to stop promotional content on the lock screen.', allowed: true},
      {id: 'diag', group: 'Windows privacy', title: 'Allow optional diagnostic data and tailored experiences', desc: 'Send Microsoft only the required minimum.', allowed: false},
      {id: 'websearch', group: 'Windows privacy', title: 'Allow Bing web results in Start and taskbar search', desc: "Searching for a file won't send what you type to Bing.", allowed: true}]),
    set_privacy: (id, allow) => { PRIV.find(x => x.id === id).allowed = allow; return wait({ok: true}); }, privacy_all: () => { PRIV.forEach(x => x.allowed = false); return wait({ok: true}); },
    remote_access: () => wait({rdp: false, assist: true, tools: [{key: 'anydesk', name: 'AnyDesk', installed: true, running: true, processes: ['anydesk.exe'], note: 'Most common tool in tech-support scams.'}]}),
    set_windows_remote: () => wait({ok: true}), kill_tool: () => wait({killed: 1}),
    device_usage: cap => wait({allowed: true, apps: cap === 'webcam' ? [{app: 'Discord.exe', path: 'C:\\Users\\Kara\\AppData\\Local\\Discord\\app-1.0.9\\Discord.exe', last_start: '2026-11-17T21:40:00', active: false}, {app: 'WindowsCamera', path: 'Microsoft.WindowsCamera_8wekyb3d8bbwe', last_start: '2026-10-02T10:00:00'}] : [{app: 'Discord.exe', path: 'C:\\...\\Discord.exe', last_start: '2026-11-18T03:40:00', active: true}]}),
    set_device_access: () => wait({ok: true}),
    last_footprint: () => wait(null),
    check_email: e => wait({ok: true, email: e, count: 2, risk_label: 'Medium', exposed_types: ['Email addresses', 'Passwords', 'Usernames', 'IP addresses'],
      breaches: [{name: 'Canva', domain: 'canva.com', date: '2019', records: 137272116, data: 'Email addresses;Names;Passwords;Usernames', password_risk: 'hardtocrack'},
                 {name: 'Wattpad', domain: 'wattpad.com', date: '2020', records: 268765495, data: 'Email addresses;IP addresses;Passwords', password_risk: 'hardtocrack'}]}, 900),
    check_password: () => wait({ok: true, count: 52341}),
    shred_inspect: p => wait(p.map(x => ({path: x, is_dir: false, size: 2.4e6, files: 1, blocked: null, media: 'SSD'}))),
    shred_start: () => wait({ok: true}), shred_state: () => wait({running: false}), drives: () => wait([{letter: 'C', media: 'HDD'}, {letter: 'D', media: 'SSD'}]),
    wipe_free: () => wait({ok: true}), wipe_state: () => wait({running: false}),
    vpn_status: () => wait({wireguard_installed: true, tunnels: [{name: 'proton-US-FREE-12', type: 'wireguard', server: '149.88.20.3:51820', connected: false}], connected: null, default: 'proton-US-FREE-12'}),
    vpn_toggle: () => wait({ok: true}, 800), vpn_connect: () => wait({ok: true}), vpn_disconnect: () => wait({ok: true}),
    vpn_import: () => wait({ok: true, name: 'proton-NL-FREE-4'}), vpn_remove: () => wait({ok: true}), vpn_set_default: () => wait({ok: true}),
    public_ip: () => wait({ip: '73.162.44.18', city: 'San Antonio', region: 'Texas', country: 'US', org: 'AS7922 Comcast'}),
    open_url: () => wait({ok: true}),
    get_theme: () => wait({theme: new URLSearchParams(location.search).get('theme'), themes: {kara: 'Kara - Purple', kaleb: 'Kaleb - Red', anthony: 'Anthony - Cotton Candy', james: 'James - Green', dnarte: 'Dnarte - Dark Blue'}}),
    set_theme: t => { window.__savedTheme = t; return wait({ok: true, theme: t}); }, shortcuts: () => wait({desktop: false, start: false}), create_shortcuts: () => wait({ok: true}),
    trusted: () => wait(['Microsoft','Riot Games','Valve','Epic Games','NVIDIA','Discord']), trust_add: p => wait({ok: true, list: ['Microsoft','Riot Games',p]}), trust_remove: () => wait({ok: true, list: ['Microsoft']}), trust_reset: () => wait({ok: true, list: ['Microsoft','Riot Games']}),
    close_mode: () => wait({tray: true}), set_close_mode: () => wait({ok: true}),
    autostart_status: () => wait({enabled: false}), set_autostart: e => wait({ok: true, enabled: e}),
  };
}
