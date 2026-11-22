/* PC Shield front-end. Talks to Python via window.pywebview.api (or window.MOCK when opened with ?mock). */
'use strict';

// ------------------------------------------------------------------ plumbing
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const backend = () => (window.pywebview && window.pywebview.api && window.pywebview.api.info ? window.pywebview.api : null) || window.MOCK;
const api = new Proxy({}, { get: (_, m) => async (...a) => {
  const b = backend();
  if (!b || !b[m]) { toast(`Backend not ready (${m})`, true); return {error: 'not ready'}; }
  let r;
  try { r = await b[m](...a); }
  catch (e) { r = {error: (e && e.message) || String(e)}; }
  if (r && r.error) toast(r.error, true);
  return r;
}});

function toast(msg, err = false) {
  const t = document.createElement('div');
  t.className = 'toast' + (err ? ' err' : '');
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), err ? 6000 : 3500);
}

function modal(title, html, buttons = [{label: 'OK', cls: 'go', value: true}]) {
  return new Promise(res => {
    $('#modalBox').innerHTML = `<h3>${esc(title)}</h3><div>${html}</div><div class="acts">${
      buttons.map((b, i) => `<button class="btn ${b.cls || ''}" data-i="${i}">${esc(b.label)}</button>`).join('')}</div>`;
    $('#modal').classList.add('show');
    $('#modalBox').querySelectorAll('.acts button').forEach(btn => btn.onclick = () => {
      $('#modal').classList.remove('show');
      res(buttons[+btn.dataset.i].value);
    });
  });
}
const confirmBox = (title, html, yes = 'Continue', cls = 'go') =>
  modal(title, html, [{label: 'Cancel', value: false}, {label: yes, cls, value: true}]);

const fmtDur = s => { s = +s || 0; const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60;
  return h ? `${h}h ${m}m` : m ? `${m}m ${x}s` : `${x}s`; };
const fmtDate = iso => { if (!iso) return '—'; const d = new Date(iso); return isNaN(d) ? esc(iso) : d.toLocaleString([], {dateStyle: 'medium', timeStyle: 'short'}); };
const human = n => { n = +n || 0; for (const u of ['B','KB','MB','GB','TB']) { if (n < 1024) return n.toFixed(1) + ' ' + u; n /= 1024; } return n.toFixed(1) + ' PB'; };
const loading = (msg = 'Loading') => `<div class="loading"><div class="spinner"></div><div>${esc(msg)}…</div></div>`;
const sw = (checked, attrs = '') => `<label class="sw"><input type="checkbox" ${checked ? 'checked' : ''} ${attrs}><i></i></label>`;

const ICON = {
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>',
  alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z"/><path d="M12 8v5M12 16.5v.5"/></svg>',
  power: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2.2" stroke-linecap="round"><path d="M12 3v8"/><path d="M6.3 6.8a8 8 0 1 0 11.4 0"/></svg>',
};

// ------------------------------------------------------------------ app shell
const TABS = [['dash','Dashboard'],['scan','Scanner'],['startup','Startup'],['bloat','Bloatware'],['perf','Performance'],
              ['privacy','Privacy'],['identity','Identity'],['shred','Shredder'],['vpn','VPN'],['settings','⚙ Settings']];
const S = { tab: 'dash', sub: {}, report: null, scanTimer: null, shredQueue: [], lastScanRunning: false };

function renderTabs() {
  $('#tabs').innerHTML = TABS.map(([id, label]) => `<div class="tab ${S.tab === id ? 'on' : ''}" data-t="${id}">${label}</div>`).join('');
  $('#tabs').querySelectorAll('.tab').forEach(t => t.onclick = () => go(t.dataset.t));
}

function go(tab, sub) {
  S.tab = tab;
  if (sub) S.sub[tab] = sub;
  renderTabs();
  const v = VIEWS[tab];
  $('#main').innerHTML = `<div class="view" id="view"></div>`;
  v($('#view'));
}

function subtabs(tab, list, el, onPick) {
  const cur = S.sub[tab] || list[0][0];
  el.innerHTML = list.map(([id, l]) => `<div class="subtab ${cur === id ? 'on' : ''}" data-s="${id}">${l}</div>`).join('');
  el.querySelectorAll('.subtab').forEach(s => s.onclick = () => { S.sub[tab] = s.dataset.s; go(tab); });
  return cur;
}

async function refreshTop() {
  const v = await api.vpn_status();
  const c = $('#topVpn');
  if (v && !v.error) {
    c.className = 'chip ' + (v.connected ? 'on' : '');
    c.innerHTML = `<span class="dot"></span>VPN ${v.connected ? 'ON' : 'OFF'}`;
  }
}

// ------------------------------------------------------------------ background scan polling
async function pollScan() {
  let running = false;
  try {
    const s = await backend().scan_state();
    running = !!(s && s.running);
    $('#topScan').innerHTML = running
      ? `<span class="chip on" style="cursor:pointer" onclick="go('scan','scan')"><span class="spinner"></span>Scanning${s.pct != null && s.steps ? ' ' + Math.round(s.pct * 100) + '%' : ''}${s.steps > 1 ? ' · ' + s.step + '/' + s.steps : ''} · ${fmtDur(s.elapsed)}</span>`
      : s && s.background ? `<span class="chip on" title="A scheduled scan is running in the background"><span class="spinner"></span>Scheduled ${esc(s.background.kind)} scan · ${fmtDur(s.background.elapsed)}</span>` : '';
    if (S.lastScanRunning && !running && s) {
      if (s.report_id) {
        toast('Scan finished - review the results.');
        S.report = s.report_id; S.sub.scan = 'results';
        if (S.tab === 'scan' || S.tab === 'dash') go('scan', 'results');
      } else if (s.error) {
        toast('Scan failed: ' + s.error, true);
        if (S.tab === 'scan') go('scan', 'scan');
      }
    }
    if (running && S.tab === 'scan' && (S.sub.scan || 'scan') === 'scan') updateScanProgress(s);
  } catch (e) { /* keep polling */ }
  S.lastScanRunning = running;
  clearTimeout(S.pollTimer);
  S.pollTimer = setTimeout(pollScan, running ? 1000 : 4000);
}
const kickPoll = () => { clearTimeout(S.pollTimer); S.pollTimer = setTimeout(pollScan, 150); };

// ================================================================== DASHBOARD
async function viewDash(el) {
  el.innerHTML = loading('Checking protection');
  const d = await api.dashboard();
  if (!el.isConnected) return;  // user switched tabs while this was loading
  if (!d || d.error) { el.innerHTML = '<div class="empty">Couldn\'t load status.</div>'; return; }
  const p = d.protection, ls = d.last_scan;
  const issues = [];
  if (!p.realtime) issues.push(['bad', 'Real-time protection is off', p.others.length ? `${esc(p.others.join(', '))} is in control and Defender is passive.` : 'Turn it on in Windows Security.']);
  if (p.active_threats) issues.push(['bad', `${p.active_threats} active threat(s)`, 'Open the latest scan report to choose what to do.']);
  if (ls && ls.summary && ls.summary.open) issues.push(['warn', `${ls.summary.open} item(s) waiting for your decision`, 'From the last scan.']);
  if (!ls) issues.push(['warn', 'No scan yet', 'Run a quick scan to get a baseline.']);
  if (p.others.length) issues.push(['warn', 'Another antivirus is installed', `${esc(p.others.join(', '))}. If it's a trial you don't pay for, remove it and Defender takes over for free.`]);
  const level = issues.some(i => i[0] === 'bad') ? 'bad' : issues.length ? 'warn' : '';
  const title = level === 'bad' ? 'Action needed' : level ? 'Protected - a few things to look at' : "You're protected";

  el.innerHTML = `
  <div class="panel"><div class="hero">
    <div class="ring ${level} ${d.scan.running ? 'scanning' : ''}" style="color:${level === 'bad' ? 'var(--pink)' : level ? 'var(--amber)' : 'var(--green)'}">${level === 'bad' ? ICON.alert : ICON.shield}</div>
    <div style="flex:1">
      <h2>${title}</h2>
      <div class="muted small">Engine: Microsoft Defender · definitions ${esc(p.defs_updated || 'unknown')} ${p.defs_version ? '(' + esc(p.defs_version) + ')' : ''}</div>
      ${issues.map(([lv, t, x]) => `<div class="flag ${lv}"><span class="ic">${lv === 'bad' ? '⛔' : '⚠️'}</span><div><b>${esc(t)}</b><span>${x}</span></div></div>`).join('')}
    </div>
    <div class="btnrow" style="flex-direction:column;align-items:stretch">
      <button class="btn big" id="dQuick" ${d.scan.running ? 'disabled' : ''}>${d.scan.running ? 'Scanning…' : 'Quick scan'}</button>
      <button class="btn" id="dDeep" ${d.scan.running ? 'disabled' : ''}>Deep scan</button>
    </div>
  </div></div>

  <div class="grid g3">
    <div class="panel">
      <div class="lbl">Last scan</div>
      ${ls ? `<div class="muted small">${fmtDate(ls.started)} · ${ls.kind} · ${fmtDur(ls.duration)}</div>
        <div class="stats">
          <div class="stat ${ls.summary.threat ? 'red' : ''}"><b>${ls.summary.threat}</b><span>Threats</span></div>
          <div class="stat ${ls.summary.pup ? 'red' : ''}"><b>${ls.summary.pup}</b><span>PUPs</span></div>
          <div class="stat ${ls.summary.pum ? 'red' : ''}"><b>${ls.summary.pum}</b><span>PUMs</span></div>
        </div><button class="btn sm blue" id="dReport">View report</button>`
      : `<p class="muted">No scans yet.</p>`}
    </div>
    <div class="panel">
      <div class="lbl">Real-time protection</div>
      <div class="kv"><span>Antivirus</span><b class="${p.realtime ? 'good' : 'bad'}">${p.realtime ? 'On' : 'Off'}</b></div>
      <div class="kv"><span>Mode</span><b>${esc(p.mode || '—')}</b></div>
      <div class="kv"><span>Tamper protection</span><b class="${p.tamper ? 'good' : 'warn'}">${p.tamper ? 'On' : 'Off'}</b></div>
      <div class="btnrow" style="margin-top:10px"><button class="btn sm" id="dDefs">Update definitions</button><button class="btn sm" id="dWS">Windows Security</button></div>
    </div>
    <div class="panel">
      <div class="lbl">VPN</div>
      <div style="display:flex;align-items:center;gap:14px">
        ${sw(!!d.vpn.connected, 'id="dVpn"' + (d.vpn.tunnels.length ? '' : ' disabled'))}
        <div><b>${d.vpn.connected ? 'Connected - ' + esc(d.vpn.connected) : 'Disconnected'}</b>
        <div class="muted small" id="dIp">${d.vpn.tunnels.length ? 'Checking IP…' : 'No VPN set up yet'}</div></div>
      </div>
      <div style="margin-top:12px"><a id="dVpnGo">${d.vpn.tunnels.length ? 'Manage VPN' : 'Set up a free VPN'} →</a></div>
    </div>
    <div class="panel">
      <div class="lbl">Privacy</div>
      <div class="stats" style="margin:4px 0"><div class="stat"><b>${d.privacy.private}/${d.privacy.total}</b><span>Protections on</span></div></div>
      <a id="dPriv">Privacy controls →</a>
    </div>
    <div class="panel">
      <div class="lbl">Digital footprint</div>
      ${d.footprint ? `<div class="stats" style="margin:4px 0"><div class="stat ${d.footprint.count ? 'red' : ''}"><b>${d.footprint.count}</b><span>Breaches</span></div></div>
        <div class="muted small">${esc(d.footprint.email)} · ${fmtDate(d.footprint.checked)}</div>` : '<p class="muted">Check if your email shows up in data breaches.</p>'}
      <a id="dId">Identity →</a>
    </div>
    <div class="panel">
      <div class="lbl">PC health</div>
      ${d.health_flags == null ? '<p class="muted">Find out why the PC is slow.</p>' :
        `<div class="stats" style="margin:4px 0"><div class="stat ${d.health_flags ? 'red' : ''}"><b>${d.health_flags}</b><span>Issues found</span></div></div>`}
      <a id="dPerf">Performance →</a>
    </div>
  </div>`;
  $('#dQuick').onclick = () => startScan('quick');
  $('#dDeep').onclick = () => startScan('deep');
  if ($('#dReport')) $('#dReport').onclick = () => { S.report = ls.id; go('scan', 'results'); };
  $('#dDefs').onclick = async e => { e.target.disabled = true; e.target.textContent = 'Updating…'; const r = await api.update_definitions(); if (r.ok) toast(r.message); go('dash'); };
  $('#dWS').onclick = () => api.open_url('windowsdefender:');
  $('#dVpnGo').onclick = () => go('vpn');
  $('#dPriv').onclick = () => go('privacy');
  $('#dId').onclick = () => go('identity');
  $('#dPerf').onclick = () => go('perf');
  const v = $('#dVpn');
  if (v) v.onchange = async () => { v.disabled = true; const r = await api.vpn_toggle(); if (r.ok === false) toast(r.message || 'VPN failed', true); await sleep(1500); refreshTop(); go('dash'); };
  if (d.vpn.tunnels.length) api.public_ip().then(ip => { const e = $('#dIp'); if (el.isConnected && e && ip) e.textContent = ip.ip ? `${ip.ip} · ${[ip.city, ip.country].filter(Boolean).join(', ')}` : 'Offline'; });
}

// ================================================================== SCANNER
async function startScan(kind, path) {
  if (kind === 'deep' && !await confirmBox('Deep scan', '<p>Scans every file on every drive with Defender. Usually 30 minutes to a couple of hours - the PC stays usable but slower.</p>', 'Start deep scan')) return;
  const r = await api.start_scan(kind, path || null);
  if (r && r.ok === false) { toast(r.message, true); return; }
  S.lastScanRunning = true;
  go('scan', 'scan');
  kickPoll();
}

function viewScan(el) {
  el.innerHTML = `<div class="subtabs" id="st"></div><div id="sb"></div>`;
  const cur = subtabs('scan', [['scan','Scan'],['results','Results'],['reports','Reports'],['sched','Scan Scheduler'],['excl','Exclusions']], $('#st'));
  ({scan: scanHome, results: scanResults, reports: scanReports, sched: scanSched, excl: scanExcl})[cur]($('#sb'));
}

async function scanHome(el) {
  el.innerHTML = loading();
  const [st, reps, mode] = await Promise.all([api.scan_state(), api.reports(), api.review_mode()]);
  if (!el.isConnected) return;  // user switched tabs while this was loading
  const ls = reps && reps[0];
  el.innerHTML = `<div class="grid g2">
    <div class="panel" style="text-align:center;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;min-height:380px">
      <div class="ring ${st.running ? 'scanning' : ''}" style="color:var(--green)">${ICON.shield}</div>
      <div id="scanLive" style="width:100%;max-width:420px"></div>
      <div class="btnrow" style="justify-content:center">
        <button class="btn big" id="sQuick">Quick scan</button>
        <button class="btn big" id="sDeep" style="background:var(--gloss),linear-gradient(135deg,var(--deep),rgb(var(--acc-rgb)))">Deep scan</button>
      </div>
      <a id="sCustom">Scan a specific folder or drive…</a>
      <div class="optbar" style="margin:6px 0 0;text-align:left">
        <label>When threats are found</label>
        <select id="sMode">
          <option value="all" ${mode === 'all' ? 'selected' : ''}>Ask me before removing anything</option>
          <option value="severe" ${mode === 'severe' ? 'selected' : ''}>Ask me, but quarantine severe threats right away</option>
          <option value="auto" ${mode === 'auto' ? 'selected' : ''}>Let Defender quarantine automatically</option>
        </select>
      </div>
      <div class="muted small" style="max-width:460px">Quick: memory, startup and the places malware usually hides (~2-10 min). Deep: every file on every drive. Both also check for unwanted programs, tampered Windows settings and suspicious startup items. Nothing is changed until you choose.</div>
    </div>
    <div class="panel">
      <h3>Last scan</h3>
      ${ls ? `<div class="muted small" style="margin-bottom:10px">${fmtDate(ls.started)}</div>
        <div class="kv"><span>Scan type</span><b>${ls.kind === 'deep' ? 'Deep' : ls.kind === 'custom' ? 'Custom' : 'Quick'}</b></div>
        <div class="kv"><span>Scan duration</span><b>${fmtDur(ls.duration)}</b></div>
        <div class="kv"><span>Items checked</span><b>${(ls.items_checked || 0).toLocaleString()}</b></div>
        <div class="sep"></div>
        <div class="kv"><span>Threats detected</span><b class="${ls.summary.threat ? 'bad' : ''}">${ls.summary.threat}</b></div>
        <div class="kv"><span>PUPs detected</span><b class="${ls.summary.pup ? 'bad' : ''}">${ls.summary.pup}</b></div>
        <div class="kv"><span>PUMs detected</span><b class="${ls.summary.pum ? 'bad' : ''}">${ls.summary.pum}</b></div>
        <div class="kv"><span>Suspicious startup items</span><b class="${ls.summary.startup ? 'bad' : ''}">${ls.summary.startup}</b></div>
        <div class="sep"></div>
        <div class="kv"><span>Waiting for your decision</span><b class="${ls.summary.open ? 'warn' : ''}">${ls.summary.open}</b></div>
        <div class="kv"><span>Detections ignored</span><b>${ls.summary.ignored}</b></div>
        <div class="kv"><span>Detections quarantined</span><b>${ls.summary.quarantined}</b></div>
        <div class="kv"><span>Fixed</span><b>${ls.summary.fixed}</b></div>
        <div style="margin-top:16px;text-align:center"><button class="btn blue" id="sView" style="width:100%">View report</button></div>`
      : '<p class="muted">No scans yet. Run a quick scan to get started.</p>'}
    </div></div>`;
  $('#sQuick').onclick = () => startScan('quick');
  $('#sDeep').onclick = () => startScan('deep');
  $('#sCustom').onclick = async () => { const f = await api.pick_folder(); if (f && !f.error) startScan('custom', f); };
  $('#sMode').onchange = async e => {
    if (e.target.value === 'auto') toast('Defender will quarantine on its own - you can still restore items from the report.');
    await api.set_review_mode(e.target.value);
  };
  if ($('#sView')) $('#sView').onclick = () => { S.report = ls.id; go('scan', 'results'); };
  updateScanProgress(st);
}

function updateScanProgress(s) {
  const live = $('#scanLive');
  if (!live) return;
  ['#sQuick', '#sDeep'].forEach(id => { if ($(id)) $(id).disabled = !!s.running; });
  if (!s.running) { live.innerHTML = s.error ? `<div class="bad small">Scan failed: ${esc(s.error)}</div>` : ''; return; }
  const inDefender = s.progress >= 15 && s.progress < 80 && s.steps;
  const pct = s.pct != null ? Math.round(s.pct * 100) : null;
  live.innerHTML = `
    <div style="margin-bottom:6px"><b>${esc(s.stage)}</b></div>
    ${inDefender ? `<div class="muted small" style="margin-bottom:8px">Step ${s.step} of ${s.steps}${s.target ? ' · ' + esc(s.target) : ''}</div>` : ''}
    <div class="prog ${inDefender && pct == null ? 'ind' : ''}"><i style="width:${inDefender ? (pct ?? 40) : s.progress}%"></i></div>
    ${inDefender ? `<div class="small" style="margin-top:8px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap">
        <span>${pct != null ? pct + '% · ' : ''}${human(s.scanned)}${s.total ? ' of ~' + human(s.total) : ''} checked</span>
        <span class="muted">${s.rate ? human(s.rate) + '/s' : 'measuring speed…'}</span>
        <span>${s.eta != null ? '~' + fmtDur(s.eta) + ' left' : ''}</span></div>` : ''}
    <div class="muted small" style="margin-top:8px">Elapsed ${fmtDur(s.elapsed)} · keep using the PC or switch tabs</div>
    <div class="btnrow" style="justify-content:center;margin-top:10px">
      <button class="btn sm" id="sLive">Defender's live view</button>
      <button class="btn sm no" id="sCancel" ${s.cancel ? 'disabled' : ''}>${s.cancel ? 'Cancelling…' : 'Cancel scan'}</button></div>
    <div class="muted small" style="margin-top:6px">Progress is an estimate - Defender skips files it already knows are clean, so it often finishes early.</div>`;
  $('#sLive').onclick = () => api.open_url('windowsdefender://threat/');
  $('#sCancel').onclick = async () => {
    if (!await confirmBox('Cancel scan?', '<p>Stop the scan now? You\'ll still get a report for what was checked so far.</p>', 'Cancel scan', 'no')) return;
    await api.cancel_scan();
  };
}

const CAT = {threat: 'Threat', pup: 'PUP', pum: 'PUM', startup: 'Startup'};
const FIXLABEL = {threat: 'Quarantine', pup: 'Uninstall', pum: 'Restore default', startup: 'Disable at startup'};
const STATE_TAG = {found: ['warn', 'Needs decision'], ignored: ['', 'Excluded'], quarantined: ['good', 'Quarantined'],
                   fixed: ['good', 'Fixed'], skipped: ['', 'Skipped'], restored: ['', 'Restored'], trusted: ['good', 'Trusted']};

function actionOptions(d) {
  const o = [['', '— choose —']];
  if (d.state === 'found' || d.state === 'skipped' || d.state === 'restored') {
    o.push(['fix', FIXLABEL[d.category]], ['skip', 'Skip this time'], ['exclude', 'Exclude from future scans']);
    if (d.signer && d.sig_status === 'Valid') o.push(['trust', `Trust ${d.signer.split(',')[0]} (all its programs)`]);
  } else if (d.state === 'quarantined' && d.category === 'threat') {
    o.push(['restore', 'Restore & allow'], ['restore+exclude', 'Restore & exclude from future scans']);
  } else if (d.state === 'ignored') {
    o.push(['unexclude', 'Stop excluding']);
  }
  return o;
}

async function scanResults(el) {
  if (!S.report) {
    const reps = await api.reports();
    if (!el.isConnected) return;
    if (reps && reps[0]) S.report = reps[0].id;
  }
  if (!S.report) { el.innerHTML = '<div class="panel empty">No scan results yet.</div>'; return; }
  el.innerHTML = loading('Loading report');
  const r = await api.report(S.report);
  if (!el.isConnected) return;  // user switched tabs while this was loading
  if (!r || r.error) { el.innerHTML = '<div class="panel empty">Report not found.</div>'; return; }
  renderReport(el, r);
}

function renderReport(el, r) {
  const s = r.summary, dets = r.detections;
  const order = {threat: 0, pum: 1, pup: 2, startup: 3};
  dets.sort((a, b) => (a.state === 'found' ? 0 : 1) - (b.state === 'found' ? 0 : 1) || order[a.category] - order[b.category]);
  el.innerHTML = `
  <div class="panel tight"><div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap">
    <div style="flex:1;min-width:240px"><h2>${r.kind === 'deep' ? 'Deep' : r.kind === 'custom' ? 'Custom' : 'Quick'} scan · ${fmtDate(r.started)}</h2>
      <div class="muted small">${fmtDur(r.duration)} · ${r.data_scanned ? human(r.data_scanned) + ' scanned · ' : ''}${(r.items_checked || 0).toLocaleString()} items checked · ${esc(r.engine)}${r.path ? ' · ' + esc(r.path) : ''}</div>
      ${r.engine_note ? `<div class="warn small" style="margin-top:6px">${esc(r.engine_note)}</div>` : ''}</div>
    <div class="stats" style="margin:0">
      <div class="stat ${s.threat ? 'red' : ''}"><b>${s.threat}</b><span>Threats</span></div>
      <div class="stat ${s.pup ? 'red' : ''}"><b>${s.pup}</b><span>PUPs</span></div>
      <div class="stat ${s.pum ? 'red' : ''}"><b>${s.pum}</b><span>PUMs</span></div>
      <div class="stat ${s.startup ? 'red' : ''}"><b>${s.startup}</b><span>Startup</span></div>
    </div>
  </div></div>
  ${dets.length ? `
  <div class="optbar">
    <label>Set all waiting items to</label>
    <select id="bulk"><option value="">—</option><option value="fix">Remove / fix</option><option value="skip">Skip this time</option><option value="exclude">Exclude from future scans</option></select>
    <span class="grow"></span>
    <span class="muted small" id="pending">Nothing selected</span>
    <button class="btn go" id="apply" disabled>Apply actions</button>
  </div>
  <table class="sel"><thead><tr><th>Type</th><th>Name</th><th>Location / details</th><th>Status</th><th style="width:240px">Action</th></tr></thead><tbody>
  ${dets.map((d, i) => { const [tc, tl] = STATE_TAG[d.state] || ['', d.state]; return `<tr>
    <td><span class="tag ${d.category}">${CAT[d.category]}</span>${d.severity ? `<div class="small muted" style="margin-top:4px">${esc(d.severity)}</div>` : ''}</td>
    <td><b>${esc(d.name)}</b>${d.note ? `<div class="small muted">${esc(d.note)}</div>` : ''}</td>
    <td><div class="mono" style="max-width:380px">${esc(d.location)}</div></td>
    <td><span class="tag ${tc}">${tl}</span></td>
    <td><select data-i="${i}" class="act" style="width:100%">${actionOptions(d).map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('')}</select></td></tr>`; }).join('')}
  </tbody></table>
  <p class="muted small">Quarantine moves the file into Defender's locked vault - it can be restored later. Uninstall opens the program's own uninstaller. Excluded items are listed under Scanner → Exclusions.</p>`
  : `<div class="panel" style="text-align:center"><div class="ring" style="margin:0 auto 14px;color:var(--green)">${ICON.shield}</div><h2>All clear</h2><p class="muted">Nothing found in this scan.</p></div>`}
  <div class="btnrow"><button class="btn sm" id="toReports">All reports</button><button class="btn sm" id="newScan">New scan</button></div>`;

  const sels = [...el.querySelectorAll('select.act')];
  const upd = () => {
    const n = sels.filter(x => x.value).length;
    $('#pending').textContent = n ? `${n} action(s) ready` : 'Nothing selected';
    $('#apply').disabled = !n;
  };
  sels.forEach(x => x.onchange = upd);
  if ($('#bulk')) $('#bulk').onchange = e => {
    sels.forEach(x => { const d = dets[+x.dataset.i]; if (['found','skipped','restored'].includes(d.state)) x.value = e.target.value; });
    upd();
  };
  if ($('#apply')) $('#apply').onclick = async () => {
    const actions = [];
    sels.forEach(x => { if (!x.value) return; const id = dets[+x.dataset.i].id;
      if (x.value === 'restore+exclude') actions.push({id, action: 'restore'}, {id, action: 'exclude'}); else actions.push({id, action: x.value}); });
    const fixes = sels.filter(x => x.value === 'fix').map(x => dets[+x.dataset.i]);
    if (fixes.length && !await confirmBox('Apply actions', `<p>This will:</p><ul>${fixes.map(d => `<li>${FIXLABEL[d.category]}: <b>${esc(d.name)}</b></li>`).join('')}</ul>`, 'Apply')) return;
    $('#apply').disabled = true; $('#apply').innerHTML = '<span class="spinner"></span> Working';
    $('#pending').textContent = fixes.some(d => d.category === 'threat') ? 'Defender is quarantining - this can take a minute…' : 'Working…';
    const res = await api.apply_actions(r.id, actions);
    if (!el.isConnected) { if (res && res.results) toast(`${res.results.filter(x => x.ok).length} action(s) done`); return; }
    if (!res || res.error || !res.report) { $('#apply').disabled = false; $('#apply').textContent = 'Apply actions'; upd(); return; }
    const bad = res.results.filter(x => !x.ok);
    bad.forEach(b => toast(`${b.name}: ${b.message}`, true));
    toast(`${res.results.length - bad.length} action(s) done`);
    renderReport(el, res.report);
  };
  $('#toReports').onclick = () => go('scan', 'reports');
  $('#newScan').onclick = () => go('scan', 'scan');
}

async function scanReports(el) {
  el.innerHTML = loading();
  const reps = await api.reports();
  if (!el.isConnected) return;  // user switched tabs while this was loading
  if (!reps || !reps.length) { el.innerHTML = '<div class="panel empty">No reports yet.</div>'; return; }
  el.innerHTML = `<table class="sel"><thead><tr><th>Date</th><th>Type</th><th class="r">Duration</th><th class="c">Threats</th><th class="c">PUPs</th><th class="c">PUMs</th><th class="c">Startup</th><th class="c">Waiting</th><th></th></tr></thead><tbody>
  ${reps.map(r => `<tr><td>${fmtDate(r.started)}</td><td>${r.kind === 'deep' ? 'Deep' : r.kind === 'custom' ? 'Custom' : 'Quick'}</td><td class="r">${fmtDur(r.duration)}</td>
    ${['threat','pup','pum','startup'].map(k => `<td class="c ${r.summary[k] ? 'bad' : 'muted'}">${r.summary[k]}</td>`).join('')}
    <td class="c ${r.summary.open ? 'warn' : 'muted'}">${r.summary.open}</td>
    <td class="r"><button class="btn sm blue" data-o="${r.id}">View</button> <button class="btn sm" data-d="${r.id}">Delete</button></td></tr>`).join('')}
  </tbody></table>`;
  el.querySelectorAll('[data-o]').forEach(b => b.onclick = () => { S.report = b.dataset.o; go('scan', 'results'); });
  el.querySelectorAll('[data-d]').forEach(b => b.onclick = async () => { await api.delete_report(b.dataset.d); scanReports(el); });
}

// Task Scheduler DaysOfWeek bitmask -> our day code
const DAY_BITS = {1: 'SUN', 2: 'MON', 4: 'TUE', 8: 'WED', 16: 'THU', 32: 'FRI', 64: 'SAT'};
function savedDay(t, kind) {
  if (t && t.Days) { const bit = Object.keys(DAY_BITS).map(Number).find(b => t.Days & b); if (bit) return DAY_BITS[bit]; }
  return kind === 'deep' ? 'SUN' : 'WED';
}

async function scanSched(el) {
  el.innerHTML = loading();
  const sc = (await api.schedules()) || {};
  if (!el.isConnected) return;  // user switched tabs while this was loading
  const days = [['MON','Monday'],['TUE','Tuesday'],['WED','Wednesday'],['THU','Thursday'],['FRI','Friday'],['SAT','Saturday'],['SUN','Sunday']];
  const card = (kind, title, desc, t) => `<div class="panel">
    <div class="trow" style="border:none;padding-top:0"><div class="tx"><b class="orb" style="font-size:14px">${title}</b><span>${desc}</span></div>${sw(!!t, `id="en_${kind}"`)}</div>
    <div class="optpanel" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <select id="fq_${kind}"><option value="daily" ${t && !t.Weekly ? 'selected' : ''}>Every day</option><option value="weekly" ${!t || t.Weekly ? 'selected' : ''}>Every week</option></select>
      <select id="dy_${kind}">${days.map(([v, l]) => `<option value="${v}" ${v === savedDay(t, kind) ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <input type="time" id="tm_${kind}" value="${t ? t.Start : (kind === 'deep' ? '03:00' : '12:30')}">
      <button class="btn sm go" id="sv_${kind}">Save</button>
    </div>
    <div class="kv"><span>Next run</span><b>${t && t.Next ? esc(t.Next) : '—'}</b></div>
    <div class="kv"><span>Last run</span><b>${t && t.Last ? esc(t.Last) : '—'}</b></div></div>`;
  el.innerHTML = `<div class="grid g2">${card('quick', 'Quick scan', 'Fast check of the usual hiding spots.', sc.quick)}${card('deep', 'Deep scan', 'Every file on every drive - schedule for when the PC is on but idle.', sc.deep)}</div>
  <p class="muted small">Scheduled scans run quietly in the background and save a report here. Results always wait for you - nothing is removed automatically unless you chose that on the Scan tab. If the PC was off or asleep at the scheduled time, the scan runs as soon as it's back on.</p>`;
  for (const kind of ['quick', 'deep']) {
    const save = async () => {
      const on = $(`#en_${kind}`).checked;
      const r = await api.set_schedule(kind, on, $(`#fq_${kind}`).value, $(`#dy_${kind}`).value, $(`#tm_${kind}`).value);
      if (r && r.ok) { toast(on ? 'Schedule saved' : 'Schedule removed'); scanSched(el); } else if (r) toast(r.message || 'Failed', true);
    };
    $(`#sv_${kind}`).onclick = () => { $(`#en_${kind}`).checked = true; save(); };
    $(`#en_${kind}`).onchange = save;
  }
}

async function scanExcl(el) {
  el.innerHTML = loading();
  const ex = await api.exclusions();
  if (!el.isConnected) return;  // user switched tabs while this was loading
  el.innerHTML = `<div class="panel tight"><p class="muted" style="margin:0">Items here are skipped by future scans. Threats you exclude are also allowed in Defender for that file only.</p></div>
  ${ex && ex.length ? `<table class="sel"><thead><tr><th>Type</th><th>Name</th><th>Location</th><th>Added</th><th></th></tr></thead><tbody>
    ${ex.map(x => `<tr><td><span class="tag ${x.category}">${CAT[x.category] || x.category}</span></td><td><b>${esc(x.name)}</b></td><td class="mono">${esc(x.location)}</td><td>${fmtDate(x.added)}</td>
    <td class="r"><button class="btn sm" data-x="${esc(x.id)}">Remove</button></td></tr>`).join('')}</tbody></table>`
  : '<div class="panel empty">No exclusions.</div>'}`;
  el.querySelectorAll('[data-x]').forEach(b => b.onclick = async () => { await api.remove_exclusion(b.dataset.x); toast('Exclusion removed'); scanExcl(el); });
}

// ================================================================== STARTUP
async function viewStartup(el) {
  el.innerHTML = loading('Reading startup items and checking signatures');
  const items = await api.startup();
  if (!el.isConnected) return;  // user switched tabs while this was loading
  if (!Array.isArray(items)) { el.innerHTML = '<div class="panel empty">Couldn\'t read startup items.</div>'; return; }
  const on = items.filter(i => i.enabled).length;
  el.innerHTML = `<div class="optbar"><label>Startup apps</label><span class="muted small">${on} of ${items.length} launch when Windows starts</span>
    <span class="grow"></span><input type="search" id="q" placeholder="Filter…"><button class="btn sm" id="rf">Refresh</button></div>
  <table class="sel"><thead><tr><th class="c" style="width:70px">Enabled</th><th>Name</th><th>Publisher</th><th>Signature</th><th>Scope</th><th>Command</th></tr></thead><tbody id="tb"></tbody></table>
  <p class="muted small">Turning an item off only stops it launching at boot (the same switch Task Manager uses). Nothing is deleted. Items marked <span class="tag bad">Suspicious</span> are unsigned programs starting from a user folder, or Windows script tools (PowerShell, rundll32…) launching something hidden - worth a look. Hover the tag for details.</p>`;
  const draw = () => {
    const q = ($('#q').value || '').toLowerCase();
    $('#tb').innerHTML = items.filter(i => !q || (i.name + i.command + i.signer).toLowerCase().includes(q)).map(i => `<tr>
      <td class="c">${sw(i.enabled, `data-id="${esc(i.id)}"`)}</td>
      <td><b>${esc(i.name)}</b> ${i.suspicious ? `<span class="tag bad" title="${esc(i.why)}">Suspicious</span>` : ''}</td>
      <td>${esc(i.signer || '—')}</td>
      <td><span class="tag ${i.signature === 'Valid' ? 'good' : i.signature === 'Missing' ? '' : 'warn'}">${esc(i.signature)}</span></td>
      <td class="small muted">${esc(i.scope)}</td>
      <td><div class="cmd" title="${esc(i.command)}">${esc(i.command)}</div></td></tr>`).join('') || '<tr><td colspan="6" class="empty">Nothing matches.</td></tr>';
    $('#tb').querySelectorAll('input[data-id]').forEach(c => c.onchange = async () => {
      const r = await api.set_startup(c.dataset.id, c.checked);
      if (r && r.ok) { items.find(i => i.id === c.dataset.id).enabled = c.checked; toast(c.checked ? 'Enabled at startup' : 'Disabled at startup'); }
      else c.checked = !c.checked;
    });
  };
  $('#q').oninput = draw;
  $('#rf').onclick = () => go('startup');
  draw();
}

// ================================================================== BLOATWARE
async function viewBloat(el, showAll = false) {
  el.innerHTML = loading('Scanning installed programs');
  const rows = await api.bloat(showAll);
  if (!el.isConnected) return;  // user switched tabs while this was loading
  if (!rows || rows.error) { el.innerHTML = ''; return; }
  el.innerHTML = `<div class="optbar"><label>Bloatware</label><span class="muted small">${rows.filter(r => r.category).length} flagged</span>
    <span class="grow"></span><label style="display:flex;gap:8px;align-items:center;text-transform:none;letter-spacing:0;font-size:12px">${sw(showAll, 'id="all"')} Show all programs</label>
    <button class="btn go" id="un" disabled>Uninstall selected</button></div>
  <table class="sel"><thead><tr><th class="c" style="width:40px"></th><th>Program</th><th>Type</th><th>Advice</th><th>Publisher</th><th class="r">Size</th></tr></thead><tbody>
  ${rows.map((r, i) => `<tr><td class="c"><input type="checkbox" data-i="${i}"></td><td><b>${esc(r.name)}</b></td>
    <td>${r.category ? `<span class="tag ${r.level === 'pup' ? 'bad' : 'warn'}">${esc(r.category)}</span>` : ''}</td>
    <td class="small">${esc(r.advice)}</td><td class="small muted">${esc(r.publisher)}</td><td class="r small">${esc(r.size_h)}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">Nothing flagged 🎉</td></tr>'}
  </tbody></table>
  <p class="muted small">Pink = junk worth removing. Amber = optional: vendor RGB/fan apps can stay if you use them for lighting or fan curves.</p>`;
  const boxes = [...el.querySelectorAll('input[data-i]')];
  boxes.forEach(b => b.onchange = () => $('#un').disabled = !boxes.some(x => x.checked));
  $('#all').onchange = e => viewBloat(el, e.target.checked);
  $('#un').onclick = async () => {
    const sel = boxes.filter(b => b.checked).map(b => rows[+b.dataset.i]);
    if (!await confirmBox('Uninstall', `<p>Each program's own uninstaller opens one at a time - follow its prompts:</p><ul>${sel.map(s => `<li>${esc(s.name)}</li>`).join('')}</ul>`, 'Uninstall', 'no')) return;
    $('#un').disabled = true; $('#all').disabled = true;
    for (const [n, s] of sel.entries()) {
      if (el.isConnected) $('#un').innerHTML = `<span class="spinner"></span> ${n + 1}/${sel.length}: ${esc(s.name)}`;
      const r = await api.uninstall(s.kind, s.id);
      if (r && !r.error) toast(r.message || 'Done', r.ok === false);
    }
    if (el.isConnected) viewBloat(el, showAll);
  };
}

// ================================================================== PERFORMANCE
async function viewPerf(el) {
  el.innerHTML = `<div class="grid g2"><div class="panel" id="pf">${loading('Checking hardware and settings')}</div><div class="panel" id="pi"></div></div>
  <div class="panel"><div style="display:flex;align-items:center;gap:10px;margin-bottom:10px"><h3 style="margin:0;flex:1">What's using resources</h3><button class="btn sm go" id="ps">Sample now</button></div><div id="pp" class="muted small">Click "Sample now" while the PC feels slow.</div></div>`;
  $('#ps').onclick = async () => {
    $('#pp').innerHTML = loading('Sampling for 2 seconds');
    const rows = await api.processes();
    if (!el.isConnected || !rows || rows.error) return;
    $('#pp').innerHTML = `<table class="sel"><thead><tr><th>Program</th><th class="c">Instances</th><th class="r">CPU %</th><th class="r">Memory</th></tr></thead><tbody>
      ${rows.map(r => `<tr><td>${esc(r.name)}</td><td class="c">${r.count}</td><td class="r ${r.cpu > 15 ? 'bad' : ''}">${r.cpu.toFixed(1)}</td><td class="r ${r.mem > 1.5e9 ? 'bad' : ''}">${esc(r.mem_h)}</td></tr>`).join('')}</tbody></table>`;
  };
  const d = await api.diagnostics();
  if (!el.isConnected || !d || d.error) return;
  $('#pf').innerHTML = `<h3>Why is it slow?</h3>${d.flags.length ? d.flags.map(f => `<div class="flag ${f.level}"><span class="ic">${f.level === 'bad' ? '⛔' : '⚠️'}</span><div><b>${esc(f.title)}</b><span>${esc(f.text)}</span></div></div>`).join('')
    : '<div class="flag good"><span class="ic">✅</span><div><b>No obvious problems</b><span>Hardware and settings look fine.</span></div></div>'}`;
  $('#pi').innerHTML = `<h3>System</h3>${d.info.map(([k, v]) => `<div class="kv"><span>${esc(k)}</span><b style="text-align:right">${esc(v)}</b></div>`).join('')}`;
}

// ================================================================== PRIVACY
function viewPrivacy(el) {
  el.innerHTML = `<div class="subtabs" id="pt"></div><div id="pb"></div>`;
  const cur = subtabs('privacy', [['win','Windows Privacy settings'],['remote','Remote Desktop programs'],['cam','Webcam & mic monitoring']], $('#pt'));
  ({win: privWin, remote: privRemote, cam: privCam})[cur]($('#pb'));
}

async function privWin(el) {
  el.innerHTML = loading();
  const t = await api.privacy_toggles();
  if (!el.isConnected) return;  // user switched tabs while this was loading
  if (!t || t.error) return;
  const groups = [...new Set(t.map(x => x.group))];
  const on = t.filter(x => !x.allowed).length;   // switch ON = protected (the Windows feature is turned off)
  el.innerHTML = `<div class="panel">
    <div class="trow"><div class="tx"><b>Turn on all privacy protections</b><span>${on} of ${t.length} protections on. Turns off every Windows setting here that shows ads, personalizes content or tracks activity.</span></div>
      <button class="btn go" id="dall" ${on === t.length ? 'disabled' : ''}>${on === t.length ? 'All protected ✓' : 'Protect all'}</button></div>
    ${groups.map(g => `<h3 style="margin-top:18px">${esc(g)}</h3>${t.filter(x => x.group === g).map(x => `
      <div class="trow"><div class="tx"><b>${esc(x.title)}</b><span>${esc(x.desc)}</span></div>${sw(!x.allowed, `data-t="${x.id}"`)}</div>`).join('')}`).join('')}
  </div><p class="muted small">Switch on (right) = protected. Some changes (Start menu, search) apply after signing out or restarting Explorer.</p>`;
  el.querySelectorAll('input[data-t]').forEach(c => c.onchange = async () => {
    const r = await api.set_privacy(c.dataset.t, !c.checked);
    if (!r || r.error) { c.checked = !c.checked; return; }
    toast(c.checked ? 'Protected' : 'Protection turned off');
    privWin(el);
  });
  $('#dall').onclick = async () => {
    const r = await api.privacy_all(false);
    if (r && r.ok) toast('All privacy protections turned on');
    else if (r && r.errors && r.errors.length) toast('Needs admin: ' + r.errors.join(', '), true);
    privWin(el);
  };
}

async function privRemote(el) {
  el.innerHTML = loading('Looking for remote access software');
  const r = await api.remote_access();
  if (!el.isConnected) return;  // user switched tabs while this was loading
  if (!r || r.error) return;
  el.innerHTML = `<div class="panel">
    <h3>Windows remote access</h3>
    <div class="trow"><div class="tx"><b>Remote Desktop</b><span>Lets someone sign into this PC over the network. Off unless you use it.</span></div>${sw(r.rdp, 'data-w="rdp"')}</div>
    <div class="trow"><div class="tx"><b>Remote Assistance</b><span>Lets someone view/control the screen through an invitation. Scammers ask for this.</span></div>${sw(r.assist, 'data-w="assist"')}</div>
  </div>
  <div class="panel"><h3>Remote desktop programs</h3>
  ${r.tools.length ? `<table class="sel"><thead><tr><th>Program</th><th>Status</th><th>Note</th><th></th></tr></thead><tbody>
    ${r.tools.map((t, i) => `<tr><td><b>${esc(t.name)}</b></td><td>${t.running ? '<span class="tag bad">Running now</span>' : ''} ${t.installed ? '<span class="tag">Installed</span>' : ''}</td><td class="small muted">${esc(t.note)}</td>
      <td class="r">${t.running ? `<button class="btn sm" data-k="${i}">Close it</button> ` : ''}${t.installed ? `<button class="btn sm no" data-u="${i}">Uninstall</button>` : ''}</td></tr>`).join('')}</tbody></table>
    <p class="muted small">If you didn't install one of these on purpose, uninstall it - anyone with its ID and password can control the PC.</p>`
  : '<div class="flag good"><span class="ic">✅</span><div><b>No remote desktop programs found</b><span>Nothing can take control of this PC remotely.</span></div></div>'}</div>`;
  el.querySelectorAll('input[data-w]').forEach(c => c.onchange = async () => { const x = await api.set_windows_remote(c.dataset.w, c.checked); if (!x || x.error) c.checked = !c.checked; else toast('Saved'); });
  el.querySelectorAll('[data-k]').forEach(b => b.onclick = async () => { const t = r.tools[+b.dataset.k]; const x = await api.kill_tool(t.processes); if (x && !x.error) toast(`Closed ${x.killed} process(es)`); privRemote(el); });
  el.querySelectorAll('[data-u]').forEach(b => b.onclick = async () => { const t = r.tools[+b.dataset.u];
    if (await confirmBox('Uninstall', `<p>Open the uninstaller for <b>${esc(t.name)}</b>?</p>`, 'Uninstall', 'no')) {
      b.disabled = true; b.innerHTML = '<span class="spinner"></span>';
      const x = await api.uninstall('win32', t.uninstall_id); if (x && !x.error) toast(x.message, x.ok === false); privRemote(el); } });
}

async function privCam(el) {
  el.innerHTML = loading();
  const [cam, mic] = await Promise.all([api.device_usage('webcam'), api.device_usage('microphone')]);
  if (!el.isConnected) return;  // user switched tabs while this was loading
  const block = (cap, title, d) => `<div class="panel">
    <div class="trow" style="padding-top:0"><div class="tx"><b class="orb">${title}</b><span>Let apps use the ${cap === 'webcam' ? 'camera' : 'microphone'}</span></div>${sw(d.allowed, `data-c="${cap}"`)}</div>
    ${d.apps.length ? `<table class="sel"><thead><tr><th>App</th><th>Last used</th><th></th></tr></thead><tbody>
      ${d.apps.slice(0, 25).map(a => `<tr><td><b>${esc(a.app)}</b><div class="mono muted">${esc(a.path)}</div></td><td class="small">${fmtDate(a.last_start)}</td>
      <td>${a.active ? '<span class="tag bad">In use now</span>' : ''}</td></tr>`).join('')}</tbody></table>`
    : '<p class="muted">No apps have used it.</p>'}</div>`;
  el.innerHTML = `<div class="grid g2">${block('webcam', 'Webcam', cam)}${block('microphone', 'Microphone', mic)}</div>
  <p class="muted small">Windows logs every app that turns on the camera or mic. Anything unfamiliar - especially something in AppData or Temp - is worth investigating.</p>`;
  el.querySelectorAll('input[data-c]').forEach(c => c.onchange = async () => { const x = await api.set_device_access(c.dataset.c, c.checked); if (!x || x.error) c.checked = !c.checked; else toast(c.checked ? 'Allowed' : 'Blocked for all apps'); });
}

// ================================================================== IDENTITY
async function viewIdentity(el) {
  const last = await api.last_footprint();
  if (!el.isConnected) return;  // user switched tabs while this was loading
  el.innerHTML = `<div class="panel" style="background:linear-gradient(135deg,rgba(var(--acc2-rgb),.18),rgba(var(--acc-rgb),.04));border-color:rgba(var(--acc2-rgb),.4)">
    <h2>Digital Footprint</h2>
    <p class="muted">Has your personal data been exposed online? Scan an email to see which data breaches it appears in. Fast, simple and free. Results are only saved on this PC.</p>
    <div class="btnrow" style="margin-top:12px"><input type="email" id="em" placeholder="Enter email to scan" style="flex:1;max-width:420px;padding:11px 14px" value="${esc(last && last.email || '')}"><button class="btn big" id="go">Free scan</button></div>
    <div class="muted small" style="margin-top:8px">Uses the free XposedOrNot breach database.</div>
  </div>
  <div id="res"></div>
  <div class="panel">
    <h3>Password check</h3>
    <p class="muted small">See if a password has appeared in known leaks. Only the first 5 characters of its SHA-1 hash leave the PC (Have I Been Pwned k-anonymity) - the password itself never does.</p>
    <div class="btnrow"><input type="password" id="pw" placeholder="Password to test" style="flex:1;max-width:420px"><button class="btn go" id="pgo">Check</button></div>
    <div id="pres" style="margin-top:10px"></div>
  </div>`;
  const run = async () => {
    const email = $('#em').value.trim();
    if (!email) return;
    $('#go').disabled = true;
    $('#res').innerHTML = `<div class="panel">${loading('Searching breach records')}</div>`;
    const r = await api.check_email(email);
    if (!el.isConnected) return;
    $('#go').disabled = false;
    if (!r || r.ok === false) { $('#res').innerHTML = `<div class="panel bad">${esc(r && (r.message || r.error))}</div>`; return; }
    $('#res').innerHTML = `<div class="panel">
      <div class="stats"><div class="stat ${r.count ? 'red' : ''}"><b>${r.count}</b><span>Breaches</span></div>
        ${r.risk_label ? `<div class="stat ${r.count ? 'red' : ''}"><b>${esc(r.risk_label)}</b><span>Risk</span></div>` : ''}
        <div class="stat"><b>${r.exposed_types.length}</b><span>Data types exposed</span></div></div>
      ${r.count ? `<div class="flag warn"><span class="ic">🔐</span><div><b>What to do</b><span>Change the password on any account that used the same password as the breached sites, and turn on two-factor login for email first.</span></div></div>
        <div class="chips" style="margin:10px 0">${r.exposed_types.map(t => `<span class="tag ${/password/i.test(t) ? 'bad' : ''}">${esc(t)}</span>`).join('')}</div>
        ${r.breaches.map(b => `<div class="breach">${b.logo ? `<img src="${esc(b.logo)}" onerror="this.remove()">` : ''}<div style="flex:1"><div class="nm">${esc(b.name)} ${b.domain ? `<span class="muted small">${esc(b.domain)}</span>` : ''}</div>
          <div class="meta">${esc(b.date || 'Unknown date')} · ${b.records ? Number(b.records).toLocaleString() + ' accounts' : ''} ${b.password_risk ? '· passwords: ' + esc(b.password_risk) : ''}</div>
          <div class="chips">${(b.data || '').split(';').filter(Boolean).map(t => `<span class="tag">${esc(t)}</span>`).join('')}</div></div></div>`).join('')}`
      : '<div class="flag good"><span class="ic">✅</span><div><b>Good news</b><span>This email wasn\'t found in any known breach.</span></div></div>'}</div>`;
  };
  $('#go').onclick = run;
  $('#em').onkeydown = e => { if (e.key === 'Enter') run(); };
  const prun = async () => {
    const r = await api.check_password($('#pw').value);
    if (!el.isConnected || !r || r.ok === false) return;
    $('#pres').innerHTML = r.count ? `<div class="flag bad"><span class="ic">⛔</span><div><b>Seen ${r.count.toLocaleString()} times in leaks</b><span>Don't use this password anywhere.</span></div></div>`
      : '<div class="flag good"><span class="ic">✅</span><div><b>Not found in known leaks</b><span>Still use a different password for every site.</span></div></div>';
  };
  $('#pgo').onclick = prun;
  $('#pw').onkeydown = e => { if (e.key === 'Enter') prun(); };
}

// ================================================================== SHREDDER
async function viewShred(el) {
  el.innerHTML = `<div class="grid g2">
  <div class="panel">
    <h2>File Shredder</h2>
    <p class="muted small">Permanently deletes files so recovery tools can't bring them back: overwrites the contents, scrambles the name, then deletes. Skips the Recycle Bin.</p>
    <div class="btnrow" style="margin:12px 0"><button class="btn" id="af">Add files</button><button class="btn" id="ad">Add folder</button><button class="btn sm" id="cl">Clear</button></div>
    <div id="q"></div>
    <div class="optbar" style="margin-top:12px"><label>Overwrite passes</label>
      <select id="ps"><option value="1">1 pass (random) - enough for modern drives</option><option value="3">3 passes</option><option value="7">7 passes (slow)</option></select></div>
    <button class="btn big no" id="go" style="width:100%" disabled>Shred permanently</button>
    <div id="prog" style="margin-top:12px"></div>
  </div>
  <div class="panel">
    <h3>SSD vs hard drive</h3>
    <p class="small muted">On a <b>hard drive (HDD)</b> overwriting is reliable. On an <b>SSD</b> the drive moves data around internally, so an overwrite can't be guaranteed to hit the old copy. For SSDs the shredder also sends a TRIM command afterward, which tells the SSD to erase the freed blocks - that's what actually makes deleted SSD data unrecoverable.</p>
    <div class="sep"></div>
    <h3>Wipe free space</h3>
    <p class="small muted">Overwrites the empty space on a drive, destroying traces of files that were deleted normally in the past. Uses Windows' built-in <span class="mono">cipher /w</span>. Takes a long time on big drives. Not useful on SSDs (TRIM already handles it).</p>
    <div class="btnrow"><select id="dv"><option>Loading…</option></select><button class="btn" id="wf">Wipe free space</button></div>
    <div id="wst" class="small" style="margin-top:8px"></div>
  </div></div>`;
  const drawQ = () => {
    const q = S.shredQueue;
    $('#q').innerHTML = q.length ? `<table class="sel"><thead><tr><th>Item</th><th class="r">Size</th><th>Drive</th><th></th></tr></thead><tbody>
      ${q.map((x, i) => `<tr><td><div class="mono">${esc(x.path)}</div>${x.blocked ? `<span class="tag bad">Blocked: ${esc(x.blocked)}</span>` : ''}</td><td class="r small">${human(x.size)}${x.is_dir ? `<div class="muted">${x.files} files</div>` : ''}</td>
      <td><span class="tag">${esc(x.media)}</span></td><td><a data-r="${i}">✕</a></td></tr>`).join('')}</tbody></table>`
      : '<div class="empty" style="border:1px dashed var(--border2);border-radius:16px">No files added</div>';
    $('#q').querySelectorAll('[data-r]').forEach(a => a.onclick = () => { q.splice(+a.dataset.r, 1); drawQ(); });
    $('#go').disabled = !q.length || q.some(x => x.blocked);
  };
  const add = async paths => {
    if (!paths || paths.error || !paths.length) return;
    const info = await api.shred_inspect(paths);
    if (!el.isConnected) return;
    if (info && !info.error) info.forEach(i => { if (!S.shredQueue.some(x => x.path === i.path)) S.shredQueue.push(i); });
    drawQ();
  };
  $('#af').onclick = async () => add(await api.pick_files());
  $('#ad').onclick = async () => { const f = await api.pick_folder(); if (f && !f.error) add([f]); };
  $('#cl').onclick = () => { S.shredQueue = []; drawQ(); };
  $('#go').onclick = async () => {
    const q = S.shredQueue, files = q.reduce((a, x) => a + x.files, 0), size = q.reduce((a, x) => a + x.size, 0);
    if (!await confirmBox('Shred permanently?', `<p><b>${files} file(s), ${human(size)}</b> will be destroyed. <span class="bad">This cannot be undone</span> - not even with recovery software.</p>`, 'Shred', 'no')) return;
    const r = await api.shred_start(q.map(x => x.path), +$('#ps').value, true);
    if (r && r.ok === false) { toast(r.message, true); return; }
    S.shredQueue = []; drawQ(); pollShred();
  };
  const pollShred = async () => {
    const s = await api.shred_state();
    if (!el.isConnected || !s) return;
    $('#prog').innerHTML = s.running
      ? `<div class="prog"><i style="width:${s.total ? Math.round(s.done / s.total * 100) : 5}%"></i></div><div class="small muted" style="margin-top:6px">${s.done}/${s.total} · ${esc(s.current)}</div>`
      : s.finished ? `<div class="flag ${s.errors.length ? 'warn' : 'good'}"><span class="ic">${s.errors.length ? '⚠️' : '✅'}</span><div><b>Shredded ${s.done - s.errors.length} file(s)</b><span>${s.errors.length ? esc(s.errors.slice(0, 5).join(' · ')) : 'Done ' + esc(s.finished)}</span></div></div>` : '';
    if (s.running) setTimeout(pollShred, 700);
  };
  pollShred();
  const drives = await api.drives();
  if (!el.isConnected) return;  // user switched tabs while this was loading
  if (drives && !drives.error) $('#dv').innerHTML = drives.map(d => `<option value="${d.letter}">${d.letter}: (${esc(d.media)})</option>`).join('');
  const pollWipe = async () => {
    const w = await api.wipe_state();
    if (!el.isConnected || !w) return;
    $('#wst').innerHTML = w.running ? `<span class="spinner"></span> Wiping ${w.drive}: · ${fmtDur(w.elapsed)}` : w.finished ? `<span class="good">Finished ${esc(w.finished)}</span>` : '';
    $('#wf').disabled = w.running;
    if (w.running) setTimeout(pollWipe, 2000);
  };
  $('#wf').onclick = async () => {
    const L = $('#dv').value, d = (drives || []).find(x => x.letter === L);
    if (d && d.media === 'SSD' && !await confirmBox('This is an SSD', '<p>Wiping free space on an SSD adds wear without much benefit - TRIM already erases deleted blocks. Do it anyway?</p>', 'Wipe anyway')) return;
    if (!await confirmBox('Wipe free space', `<p>Overwrite all empty space on <b>${L}:</b>? Existing files are not touched. This can take hours.</p>`, 'Start')) return;
    await api.wipe_free(L); pollWipe();
  };
  pollWipe();
  drawQ();
}

// ================================================================== VPN
async function viewVpn(el) {
  el.innerHTML = loading();
  const v = await api.vpn_status();
  if (!el.isConnected) return;  // user switched tabs while this was loading
  if (!v || v.error) return;
  el.innerHTML = `<div class="grid g2">
  <div class="panel" style="text-align:center">
    <div class="power ${v.connected ? 'on' : ''}" id="pw">${ICON.power}</div>
    <h2 style="margin-top:16px" class="${v.connected ? 'good' : ''}">${v.connected ? 'Connected' : 'Not connected'}</h2>
    <div class="muted">${v.connected ? esc(v.connected) : v.tunnels.length ? 'Tap to connect to ' + esc(v.default) : 'Set up a VPN below to use this switch'}</div>
    <div class="sep" style="margin:16px 0"></div>
    <div class="lbl">Your public IP</div><div id="ip" class="orb" style="font-size:18px">…</div><div id="loc" class="muted small"></div>
  </div>
  <div class="panel">
    <h3>Connections</h3>
    ${v.tunnels.length ? `<table class="sel"><thead><tr><th>Name</th><th>Type</th><th>Server</th><th></th></tr></thead><tbody>
      ${v.tunnels.map((t, i) => `<tr><td><b>${esc(t.name)}</b> ${t.name === v.default ? '<span class="tag good">Default</span>' : ''}</td><td class="small">${t.type === 'wireguard' ? 'WireGuard' : 'Windows VPN'}</td><td class="mono">${esc(t.server)}</td>
      <td class="r" style="white-space:nowrap">${t.connected ? `<button class="btn sm" data-dc="${i}">Disconnect</button>` : `<button class="btn sm go" data-c="${i}">Connect</button>`}
      ${t.name !== v.default ? `<button class="btn sm" data-df="${i}">Make default</button>` : ''}
      ${t.type === 'wireguard' ? `<button class="btn sm" data-rm="${i}">Remove</button>` : ''}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No VPN connections yet.</p>'}
    <div class="btnrow" style="margin-top:12px"><button class="btn go" id="imp" ${v.wireguard_installed ? '' : 'disabled'}>Import WireGuard config</button>
      ${v.wireguard_installed ? '' : '<button class="btn blue" id="wg">Install WireGuard (free)</button>'}</div>
  </div></div>
  <div class="panel">
    <h3>Free VPN setup (one time)</h3>
    <p class="muted small">A VPN needs a server on the other end - an app alone can't provide one. Proton VPN's free plan has no data cap, no ads and a no-logs policy, and it gives you a WireGuard config this switch can control.</p>
    <ol class="small" style="line-height:1.9">
      <li>Install the free WireGuard app. ${v.wireguard_installed ? '<span class="good">✓ installed</span>' : '<a id="wg2">Get it</a>'}</li>
      <li>Make a free account at <a id="pv">account.protonvpn.com</a>.</li>
      <li>Go to <b>Downloads → WireGuard configuration</b>, pick Windows and a free server, then <b>Create</b> and <b>Download</b>.</li>
      <li>Click <b>Import WireGuard config</b> above and choose the .conf file. Done - use the switch here, on the Dashboard or in the top bar.</li>
    </ol>
    <p class="muted small">VPNs already set up in Windows Settings → Network → VPN show up here too.</p>
  </div>`;
  api.public_ip().then(ip => { if (el.isConnected && ip) { $('#ip').textContent = ip.ip || 'Offline'; $('#loc').textContent = [ip.city, ip.region, ip.country].filter(Boolean).join(', ') + (ip.org ? ' · ' + ip.org : ''); } });
  const busy = async (p) => { $('#pw').classList.add('busy'); const r = await p; if (r && r.ok === false) toast(r.message || 'VPN error', true); await sleep(1200); refreshTop(); viewVpn(el); };
  $('#pw').onclick = () => v.tunnels.length ? busy(api.vpn_toggle()) : toast('Set up a VPN first (steps below).', true);
  const T = i => v.tunnels[+i].name;
  el.querySelectorAll('[data-c]').forEach(b => b.onclick = () => busy(api.vpn_connect(T(b.dataset.c))));
  el.querySelectorAll('[data-dc]').forEach(b => b.onclick = () => busy(api.vpn_disconnect(T(b.dataset.dc))));
  el.querySelectorAll('[data-df]').forEach(b => b.onclick = async () => { await api.vpn_set_default(T(b.dataset.df)); viewVpn(el); });
  el.querySelectorAll('[data-rm]').forEach(b => b.onclick = async () => { if (await confirmBox('Remove', `<p>Remove <b>${esc(T(b.dataset.rm))}</b>?</p>`, 'Remove', 'no')) { await api.vpn_remove(T(b.dataset.rm)); viewVpn(el); } });
  $('#imp').onclick = async () => { const r = await api.vpn_import(); if (r && r.ok) { toast(`Imported ${r.name}`); viewVpn(el); } else if (r && !r.cancelled && r.message) toast(r.message, true); };
  const wg = () => api.open_url('https://www.wireguard.com/install/');
  if ($('#wg')) $('#wg').onclick = wg; if ($('#wg2')) $('#wg2').onclick = wg;
  $('#pv').onclick = () => api.open_url('https://account.protonvpn.com/');
}

// ------------------------------------------------------------------ themes
const THEME_SWATCH = {
  kara: ['#07040c', 'rgb(153,51,255)', 'rgb(197,128,255)'], kaleb: ['#080303', 'rgb(200,16,46)', 'rgb(255,77,77)'],
  anthony: ['#05050a', 'rgb(255,140,205)', 'rgb(110,195,255)'], james: ['#030705', 'rgb(0,190,110)', 'rgb(0,255,136)'],
  dnarte: ['#030409', 'rgb(30,70,200)', 'rgb(90,150,255)'],
};
function applyTheme(t) {
  document.documentElement.dataset.theme = t || 'kara';
  const f = $('#favicon'); if (f) f.href = `icons/${t || 'kara'}.png`;
  S.theme = t || 'kara';
}
function themeGrid(themes) {
  return `<div class="themes">${Object.entries(themes).map(([id, label]) => { const [n, sub] = label.split(' - ');
    return `<div class="theme ${S.theme === id ? 'on' : ''}" data-th="${id}"><div class="sw3">${THEME_SWATCH[id].map(c => `<i style="background:${c}"></i>`).join('')}</div>
      <img src="icons/${id}.png" style="width:22px;height:22px;float:right;margin-top:-2px"><b>${esc(sub || n)}</b><span>${esc(n)}</span></div>`; }).join('')}</div>`;
}
function wireThemeGrid(root) {
  root.querySelectorAll('[data-th]').forEach(el => el.onclick = async () => {
    applyTheme(el.dataset.th);
    root.querySelectorAll('[data-th]').forEach(x => x.classList.toggle('on', x === el));
    const r = await api.set_theme(el.dataset.th);
    if (r && r.ok) toast('Theme saved');
  });
}

// ------------------------------------------------------------------ settings
async function buildSettings(el) {
  el.innerHTML = loading('Loading settings');
  const [a, th, sc, cm, up] = await Promise.all([api.autostart_status(), api.get_theme(), api.shortcuts(), api.close_mode(), api.update_status()]);
  if (!el.isConnected) return;  // user switched tabs while this was loading
  if (!a || a.error || !th || th.error) { el.innerHTML = '<div class="empty">Couldn\'t load settings.</div>'; return; }
  const added = sc && (sc.desktop || sc.start);
  el.innerHTML = `
    <div class="lbl" style="margin-top:4px">Theme</div>
    ${themeGrid(th.themes)}
    <p class="muted small">Changes the colors, the app logo, the taskbar and tray icon, and the PC Shield shortcuts.</p>
    <div class="sep"></div>
    <div class="trow"><div class="tx"><b>Updates</b><span id="upMsg"></span></div>
      <div class="btnrow" style="margin:0;flex-wrap:nowrap"><button class="btn sm" id="upCheck">Check now</button><button class="btn sm go" id="upGo" style="display:none">Update</button></div></div>
    <div id="upMore"></div>
    <div class="trow"><div class="tx"><b>Check for updates automatically</b>
      <span>Once a day PC Shield asks GitHub for the newest release and tells you in the tray. Nothing installs until you click Update.</span></div>${sw(up && !up.error ? up.auto !== false : true, 'id="upAuto"')}</div>
    <div class="sep"></div>
    <div class="trow"><div class="tx"><b>No-prompt shortcut (Desktop & Start menu)</b>
      <span>${added ? 'Added - opens PC Shield without the admin prompt, icon follows the theme.' : 'Adds a "PC Shield" shortcut that opens without the admin prompt and uses the theme icon.'}</span></div>
      <button class="btn sm" id="setSc">${added ? 'Re-create' : 'Add shortcut'}</button></div>
    ${sc && sc.moved ? `<div class="flag warn"><span class="ic">⚠️</span><div><b>The exe moved</b><span>Click Re-create so the shortcut opens the new location.</span></div></div>` : ''}
    <div class="trow"><div class="tx"><b>Start PC Shield with Windows</b>
      <span>Starts quietly in the system tray 30 seconds after sign-in, so it doesn't slow down boot. No admin prompt.</span></div>${sw(a.enabled, 'id="setAuto"')}</div>
    ${a.moved ? `<div class="flag warn"><span class="ic">⚠️</span><div><b>The exe moved</b><span>Startup still points to ${esc(a.path)}. Turn the switch off and on again to fix it.</span></div></div>` : ''}
    <div class="trow"><div class="tx"><b>Keep running in the tray when I close the window</b>
      <span>The X button hides PC Shield to the system tray (bottom-right, maybe under the ^ arrow). Right-click the tray icon → Quit to fully close it.</span></div>${sw(cm && cm.tray, 'id="setTray"')}</div>
    <div class="sep"></div>
    <div class="trow" style="border:none"><div class="tx"><b>Trusted publishers</b>
      <span>Exclusions and system changes made by programs digitally signed by these companies aren't flagged as PUMs. Signatures can't be faked, so a fake "Riot" folder won't get through.</span></div>
      <button class="btn sm" id="trReset">Reset list</button></div>
    <div class="chips" id="trList" style="margin-bottom:10px"></div>
    <div class="btnrow"><input type="text" id="trNew" placeholder="Add a publisher, e.g. Riot Games" style="flex:1;max-width:340px"><button class="btn sm go" id="trAdd">Add</button></div>
    <div class="sep"></div>
    <p class="muted small">The shortcut, start with Windows and scheduled scans run a protected copy in <b>${esc((up && up.install && up.install.path) || 'Program Files\\PC Shield')}</b> that only admins can change, so you can move or delete the downloaded exe.</p>`;
  wireThemeGrid(el);
  wireUpdates(el, up);
  const drawTrust = list => {
    el.querySelector('#trList').innerHTML = list.map(p => `<span class="tag" style="text-transform:none;letter-spacing:0;font-size:12px;padding:4px 8px">${esc(p)} <a data-tr="${esc(p)}" style="margin-left:4px">✕</a></span>`).join('');
    el.querySelectorAll('[data-tr]').forEach(x => x.onclick = async () => { const r = await api.trust_remove(x.dataset.tr); if (r && r.ok) drawTrust(r.list); });
  };
  api.trusted().then(l => { if (Array.isArray(l)) drawTrust(l); });
  el.querySelector('#trAdd').onclick = async () => { const r = await api.trust_add(el.querySelector('#trNew').value); if (r && r.ok) { el.querySelector('#trNew').value = ''; drawTrust(r.list); toast('Publisher trusted'); } else if (r) toast(r.message, true); };
  el.querySelector('#trReset').onclick = async () => { const r = await api.trust_reset(); if (r && r.ok) drawTrust(r.list); };
  el.querySelector('#setSc').onclick = async e => { e.target.disabled = true; const r = await api.create_shortcuts(); if (r && r.ok) { toast('Shortcut added - it opens without the admin prompt'); e.target.textContent = 'Re-create'; } e.target.disabled = false; };
  el.querySelector('#setTray').onchange = async e => { await api.set_close_mode(e.target.checked); toast(e.target.checked ? 'X will keep it running in the tray' : 'X will quit PC Shield'); };
  el.querySelector('#setAuto').onchange = async e => {
    e.target.disabled = true;
    const r = await api.set_autostart(e.target.checked);
    e.target.disabled = false;
    if (r && r.ok) toast(r.enabled ? 'PC Shield will start with Windows' : 'Removed from startup');
    else { e.target.checked = !e.target.checked; if (r && r.message) toast(r.message, true); }
  };
}

function drawUpdate(el, r) {
  const msg = el.querySelector('#upMsg'), btn = el.querySelector('#upGo'), more = el.querySelector('#upMore');
  if (!msg) return;
  if (!r || r.error) { msg.textContent = (r && r.error) || "Couldn't check for updates."; return; }
  msg.textContent = [`You have version ${r.current || '?'}`, r.checked ? 'checked ' + fmtDate(r.checked) : 'not checked yet', r.message].filter(Boolean).join(' · ');
  btn.style.display = r.available && r.can_install ? '' : 'none';
  btn.textContent = r.available ? `Update to ${r.latest}` : 'Update';
  more.innerHTML = r.available ? `<div class="flag good"><span class="ic">⬆</span><div style="flex:1"><b>${esc(r.name || 'Version ' + r.latest)}${r.size ? ' · ' + human(r.size) : ''}</b>
      ${r.notes ? `<span style="white-space:pre-wrap;display:block;max-height:180px;overflow:auto">${esc(r.notes.replace(/^#+\s*/gm, '').replace(/\*\*/g, '').trim())}</span>` : ''}
      <a id="upPage">See it on GitHub →</a></div></div>` : '';
  const pg = more.querySelector('#upPage'); if (pg) pg.onclick = () => api.open_url(r.page);
  topUpdate(r);
}

function topUpdate(r) {
  const c = $('#topUpdate');
  if (c) { c.style.display = r && r.available ? '' : 'none'; c.textContent = r && r.available ? `⬆ Update ${r.latest}` : ''; }
}

function wireUpdates(el, up) {
  drawUpdate(el, up);
  el.querySelector('#upAuto').onchange = async e => { await api.set_update_auto(e.target.checked); toast(e.target.checked ? 'Will check GitHub once a day' : 'Automatic update checks off'); };
  el.querySelector('#upCheck').onclick = async e => {
    e.target.disabled = true; el.querySelector('#upMsg').textContent = 'Checking GitHub…';
    const r = await api.check_updates();
    e.target.disabled = false;
    if (el.isConnected) drawUpdate(el, r);
    if (r && r.ok === false) toast(r.message, true);
  };
  el.querySelector('#upGo').onclick = async e => {
    if (!await confirmBox('Update PC Shield', '<p>Download the new version from GitHub, check it matches GitHub\'s checksum, install it and restart PC Shield?</p><p class="muted small">Scans in progress will stop.</p>', 'Update')) return;
    e.target.disabled = true; el.querySelector('#upCheck').disabled = true;
    const r = await api.install_update();
    if (!r || r.ok === false || r.error) { toast((r && (r.message || r.error)) || 'Update failed', true); e.target.disabled = false; el.querySelector('#upCheck').disabled = false; return; }
    for (;;) {
      await sleep(500);
      const st = await api.update_state();
      const msg = el.querySelector('#upMsg');
      if (msg && st) msg.textContent = st.stage + (st.total && st.running ? ` · ${Math.round(st.done / st.total * 100)}%` : '');
      if (!st || !st.running) {
        if (st && st.error) { toast(st.error, true); e.target.disabled = false; el.querySelector('#upCheck').disabled = false; }
        else toast('Updated - restarting PC Shield');
        return;
      }
    }
  };
}

function viewSettings(el) {
  el.innerHTML = `<div class="panel"><h2>Settings</h2><div id="setBody"></div></div>`;
  buildSettings($('#setBody'));
}

async function openWelcome() {
  const done = modal('Welcome to PC Shield - pick a theme', '<div id="setBody"></div>', [{label: 'Done', cls: 'go', value: true}]);
  buildSettings($('#setBody'));
  await done;
  api.set_theme(S.theme || 'kara');  // remember the choice (or the default) so this only shows once
}

// ------------------------------------------------------------------ boot
const VIEWS = {dash: viewDash, scan: viewScan, startup: viewStartup, bloat: el => viewBloat(el), perf: viewPerf,
               privacy: viewPrivacy, identity: viewIdentity, shred: viewShred, vpn: viewVpn, settings: viewSettings};

async function boot() {
  const info = await api.info();
  if (info && !info.error) {
    $('#topAdmin').className = 'chip ' + (info.admin ? 'on' : 'off');
    $('#topAdmin').innerHTML = `<span class="dot"></span>${info.admin ? 'Admin' : 'Limited'}`;
    $('#topAdmin').title = info.admin ? 'Running as administrator' : 'Not running as administrator - some fixes will fail';
  }
  $('#topVpn').onclick = async () => { $('#topVpn').innerHTML = '<span class="spinner"></span> VPN'; const r = await api.vpn_toggle(); if (r && r.ok === false) toast(r.message, true); await sleep(1200); refreshTop(); if (['dash','vpn'].includes(S.tab)) go(S.tab); };
  $('#topSettings').onclick = () => go('settings');
  const th = await api.get_theme();
  applyTheme(th && th.theme);
  go('dash');
  refreshTop();
  if (th && !th.error && !th.theme) setTimeout(openWelcome, 400);  // first launch: pick a theme
  pollScan();
  $('#topUpdate').onclick = () => go('settings');
  const upd = () => api.update_status().then(r => { if (r && !r.error) topUpdate(r); });
  upd(); setTimeout(upd, 30000);  // the daily background check runs ~20 s after start
}

let booted = false;
const bootOnce = () => { if (!booted) { booted = true; boot(); } };
if (window.MOCK || (window.pywebview && window.pywebview.api && window.pywebview.api.info)) bootOnce();
else window.addEventListener('pywebviewready', bootOnce);
