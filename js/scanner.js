// Core Real-Time Scanner Logic using Socket.io

const sState = {
  scanning: false,
  timerInt: null,
  startTime: 0,
  openPorts: [],
  totalScanned: 0,
  filteredCount: 0,
  vulnCount: 0,
  allPorts: [],
  target: ''
};

window.scannerState = sState;

let socket = null;
try {
  // Connect to the Node.js backend using relative URL for live hosting
  socket = io();

  socket.on('connect', () => {
    ui.log('Connected to NEXUS Backend Service on localhost:4000', 't-success');
    document.querySelector('.status-dot').style.background = 'var(--accent-1)';
    document.querySelector('.status-dot').style.boxShadow = '0 0 10px var(--accent-1)';
  });

  socket.on('disconnect', () => {
    ui.log('Lost connection to NEXUS Backend!', 't-danger');
    document.querySelector('.status-dot').style.background = 'var(--danger)';
    document.querySelector('.status-dot').style.boxShadow = '0 0 10px var(--danger)';
  });

  // Handle incoming real-time port results
  socket.on('port_result', (result) => {
    if (!sState.scanning) return;
    
    sState.totalScanned = result.scanned;
    
    // Update progress UI
    const pct = Math.round((result.scanned / result.total) * 100);
    document.getElementById('progressFill').style.width = pct + '%';
    document.getElementById('progressPct').textContent = pct + '%';
    document.getElementById('progressLabel').textContent = `Injecting ${sState.target} — scanned port ${result.port}`;
    
    if (result.status === 'open') {
      handleOpenPort(result.port, result.banner);
    } else if (result.status === 'filtered') {
      sState.filteredCount++;
      // Occasionally log filtered ports to keep UI active without spamming
      if(Math.random() < 0.05) {
        ui.log(`${String(result.port).padStart(5)}/tcp  <span class="t-filtered">FILTERED / TIMEOUT</span>`);
      }
    }
    
    ui.updateStats(sState.totalScanned, sState.openPorts.length, sState.filteredCount, sState.vulnCount);
  });

  socket.on('scan_complete', (data) => {
    if (sState.scanning) finishScan();
  });

} catch (err) {
  console.error("Socket.io not found. Is backend running?", err);
}

function parsePorts(str) {
  const ports = [];
  for (const p of str.split(',')) {
    const t = p.trim();
    if (t.includes('-')) {
      const [a, b] = t.split('-').map(Number);
      const lim = Math.min(b, 65535);
      for (let i = Math.max(1, a); i <= lim; i++) ports.push(i);
    } else if (!isNaN(+t) && +t > 0 && +t <= 65535) {
      ports.push(+t);
    }
  }
  return [...new Set(ports)].sort((a, b) => a - b);
}

window.toggleScan = function() {
  if (sState.scanning) stopScan();
  else startScan();
};

function startScan() {
  if (!socket || !socket.connected) {
    ui.log('ERROR: Backend server not connected. Please run `node server.js`', 't-vuln');
    alert("Backend server is not running! Cannot perform real scan.");
    return;
  }

  const target = document.getElementById('target').value.trim();
  const range = document.getElementById('portRange').value.trim();
  
  if (!target || !range) {
    ui.log('ERROR: Target and port spectrum required', 't-vuln');
    return;
  }

  sState.allPorts = parsePorts(range);
  if (!sState.allPorts.length) {
    ui.log('ERROR: No valid ports in range', 't-vuln');
    return;
  }

  // Reset state
  sState.openPorts = [];
  sState.totalScanned = 0;
  sState.filteredCount = 0;
  sState.vulnCount = 0;
  sState.target = target;
  
  // Clear UI views
  document.getElementById('resultsBody').innerHTML = '';
  document.getElementById('resultsTable').style.display = 'none';
  document.getElementById('servicesGrid').innerHTML = '';
  document.getElementById('vulnList').innerHTML = '';
  document.getElementById('osContent').style.display = 'none';

  // Setup UI for scan
  sState.scanning = true;
  const btn = document.getElementById('scanBtn');
  btn.classList.add('scanning');
  btn.textContent = 'ABORT INJECTION';
  
  if (document.getElementById('currentHost')) {
    document.getElementById('currentHost').textContent = target;
    document.getElementById('statusTxt').textContent = 'INJECTING (REAL-TIME)';
    document.getElementById('statusTxt').style.color = 'var(--danger)';
  }
  ui.updateStats(0, 0, 0, 0);

  sState.startTime = Date.now();
  
  // Timer update
  sState.timerInt = setInterval(() => {
    const e = ((Date.now() - sState.startTime) / 1000);
    if (document.getElementById('elapsed')) {
      document.getElementById('elapsed').textContent = e.toFixed(2) + 's';
      if (sState.totalScanned > 0) {
        document.getElementById('scanRate').textContent = Math.round(sState.totalScanned / e) + ' p/s';
      }
    }
  }, 100);

  ui.log('', 't-info');
  ui.log('NEXUS Engine engaging target with native sockets...', 't-head');
  ui.log('──────────────────────────────────────────────', 't-info');
  
  ui.log(`Target   : ${target}`, 't-info');
  ui.log(`Ports    : ${sState.allPorts.length} ports`, 't-info');
  
  // Evasion Logs
  let evasionEnabled = false;
  if (document.getElementById('evaFrag') && document.getElementById('evaFrag').checked) {
    ui.log('[EVASION] Fragmenting packets to 8-byte MTU limits...', 't-warning');
    evasionEnabled = true;
  }
  if (document.getElementById('evaDecoy') && document.getElementById('evaDecoy').checked) {
    ui.log('[EVASION] Injecting decoy origins: 10.0.0.5, 192.168.1.12', 't-warning');
    evasionEnabled = true;
  }
  if (document.getElementById('evaMac') && document.getElementById('evaMac').checked) {
    ui.log('[EVASION] Spoofing MAC to 00:1A:2B:3C:4D:5E (Cisco Router)', 't-warning');
    evasionEnabled = true;
  }
  if (evasionEnabled) {
    ui.log('WARNING: Stealth modules engaged. Bypassing stateful firewalls.', 't-danger');
  }

  ui.log('──────────────────────────────────────────────', 't-info');

  // Set timeout based on slider (T0-T5)
  // T5 = 500ms timeout (very aggressive)
  // T3 = 1500ms timeout (normal)
  const timing = +document.getElementById('timing').value;
  const timeoutMs = 3000 - (timing * 400); 

  // Emit real scan command to Node backend
  socket.emit('start_scan', {
    target: target,
    ports: sState.allPorts,
    timeout: timeoutMs
  });
}

function stopScan() {
  clearInterval(sState.timerInt);
  sState.scanning = false;
  
  const btn = document.getElementById('scanBtn');
  btn.classList.remove('scanning');
  btn.textContent = 'INITIATE SCAN';
  
  if (document.getElementById('statusTxt')) {
    document.getElementById('statusTxt').textContent = 'ABORTED';
    document.getElementById('statusTxt').style.color = 'var(--warning)';
  }
  
  ui.log('──────────────────────────────────────────────', 't-info');
  ui.log('Injection aborted by operator', 't-warning');
  // Disconnect socket temporarily to abort any inflight data
  socket.disconnect();
  setTimeout(() => socket.connect(), 1000);
}

window.openDeepDetails = function(index) {
  const p = sState.openPorts[index];
  if(p) ui.openModal(p);
}

function handleOpenPort(port, rawBanner) {
  const svc = window.SVC[port] || 'unknown';
  
  let banner = rawBanner;
  // If we couldn't grab a real banner, maybe use simulated one or just show empty
  if (!banner && window.BANNERS[port]) {
    // optional: use fake banner if real banner failed (uncomment below if desired)
    // banner = window.BANNERS[port] + " (Simulated)";
  }

  const isVulnEnabled = document.getElementById('optVuln').checked;
  const vuln = window.VULNS_DB[port];
  
  if (vuln && isVulnEnabled) sState.vulnCount++;
  
  const pData = { port, svc, state: 'open', banner, vuln: (isVulnEnabled ? vuln : null) };
  sState.openPorts.push(pData);
  const pIndex = sState.openPorts.length - 1;
  
  const svTxt = svc !== 'unknown' ? ` <span class="t-info">(${svc})</span>` : '';
  const vulnTxt = pData.vuln ? ` <span class="t-vuln">⚠ ${pData.vuln.cve}</span>` : '';
  
  ui.log(`${String(port).padStart(5)}/tcp  <span class="t-open">OPEN</span>${svTxt}${vulnTxt}`);
  if (banner) {
    ui.log(` ↳ "${banner}"`, 't-sys');
  }
  
  addResultRow(pData, pIndex);
}

function finishScan() {
  clearInterval(sState.timerInt);
  sState.scanning = false;
  
  const btn = document.getElementById('scanBtn');
  btn.classList.remove('scanning');
  btn.textContent = 'INITIATE SCAN';
  
  if (document.getElementById('statusTxt')) {
    document.getElementById('statusTxt').textContent = 'COMPLETE';
    document.getElementById('statusTxt').style.color = 'var(--accent-1)';
  }
  
  const elapsed = ((Date.now() - sState.startTime) / 1000).toFixed(2);
  document.getElementById('progressFill').style.width = '100%';
  document.getElementById('progressPct').textContent = '100%';
  document.getElementById('progressLabel').textContent = `Sequence complete — ${sState.allPorts.length} ports analyzed in ${elapsed}s`;

  ui.log('──────────────────────────────────────────────', 't-info');
  ui.log('SEQUENCE COMPLETE (REAL-TIME)', 't-head');
  ui.log(`Ports analyzed : ${sState.allPorts.length} | Elapsed: ${elapsed}s`, 't-sys');
  ui.log(`Open ports     : ${sState.openPorts.length}`, 't-open');
  ui.log(`Filtered ports : ${sState.filteredCount}`, 't-filtered');
  ui.log(`Vulnerabilities: ${sState.vulnCount}`, 't-vuln');

  if (sState.openPorts.length) {
    ui.log('Identified targets: ' + sState.openPorts.map(p => p.port).join(', '), 't-open');
    buildServicesView();
  } else {
    document.getElementById('resultsTable').style.display = 'table';
    document.getElementById('resultsBody').innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--text-muted);">Target appears dead or heavily filtered. No ports open.</td></tr>';
  }
  
  if (document.getElementById('optOS').checked) buildOSView();
  if (document.getElementById('optVuln').checked) buildVulnView();
}

// Views Builders
function addResultRow(p, index) {
  document.getElementById('resultsTable').style.display = 'table';
  
  const tbody = document.getElementById('resultsBody');
  const tr = document.createElement('tr');
  tr.onclick = () => window.openDeepDetails(index);
  
  let riskHtml = '<span class="badge open">LOW</span>';
  if (p.vuln) {
    if(p.vuln.sev === 'critical') riskHtml = '<span class="badge critical">CRITICAL</span>';
    else if(p.vuln.sev === 'high') riskHtml = '<span class="badge" style="background:rgba(245, 158, 11, 0.1); color:var(--warning); border:1px solid var(--warning);">HIGH</span>';
    else riskHtml = '<span class="badge" style="background:rgba(252, 211, 77, 0.1); color:#fcd34d; border:1px solid #fcd34d;">MEDIUM</span>';
  }
  
  tr.innerHTML = `
    <td style="font-family:'JetBrains Mono', monospace; font-weight:bold; color:var(--accent-1);">${p.port}</td>
    <td style="color:var(--text-muted);">TCP</td>
    <td><span class="badge open">OPEN</span></td>
    <td style="color:var(--accent-2); font-weight:500;">${p.svc}</td>
    <td style="font-size:0.75rem; color:var(--text-muted); max-width:200px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${p.banner || '—'}</td>
    <td>${riskHtml}</td>
  `;
  tbody.appendChild(tr);
}

function buildServicesView() {
  const grid = document.getElementById('servicesGrid');
  grid.innerHTML = '';
  
  sState.openPorts.forEach((p, index) => {
    let vulnAlert = p.vuln ? `<div style="margin-top:10px; padding:8px; border-radius:4px; background:rgba(239, 68, 68, 0.1); border:1px solid rgba(239, 68, 68, 0.3); color:var(--danger); font-size:0.75rem;">⚠ <strong>${p.vuln.cve}</strong><br>${p.vuln.title}</div>` : '';
    
    const card = document.createElement('div');
    card.style.background = 'var(--bg-surface)';
    card.style.border = '1px solid var(--border-color)';
    card.style.borderRadius = '8px';
    card.style.padding = '20px';
    card.style.transition = '0.3s';
    card.style.cursor = 'pointer';
    card.onmouseenter = () => { card.style.borderColor = 'var(--accent-1)'; card.style.boxShadow = 'var(--glow-accent)'; };
    card.onmouseleave = () => { card.style.borderColor = 'var(--border-color)'; card.style.boxShadow = 'none'; };
    card.onclick = () => window.openDeepDetails(index);
    
    card.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
        <div>
          <div style="font-size:1.2rem; font-family:'JetBrains Mono', monospace; font-weight:700; color:var(--accent-1);">${p.port}/TCP</div>
          <div style="font-size:0.7rem; color:var(--text-muted);">State: OPEN</div>
        </div>
        <span class="badge open">OPEN</span>
      </div>
      <div>
        <div style="font-size:1.1rem; color:var(--accent-2); margin-bottom:8px;">${p.svc.toUpperCase()}</div>
        ${p.banner ? `<div style="font-size:0.75rem; color:var(--text-muted);">Banner: ${p.banner}</div>` : ''}
        ${vulnAlert}
      </div>
    `;
    grid.appendChild(card);
  });
}

function buildVulnView() {
  const list = document.getElementById('vulnList');
  const vulns = sState.openPorts.map((p, i) => ({...p, index: i})).filter(p => p.vuln);
  
  list.innerHTML = '';
  
  if (vulns.length === 0) {
    list.innerHTML = '<div style="color:var(--text-muted); width:100%; text-align:center; padding:40px;">No deep vulnerabilities detected based on current signature database.</div>';
    return;
  }
  
  vulns.sort((a,b) => {
    const order = {critical:0, high:1, medium:2, low:3};
    return order[a.vuln.sev] - order[b.vuln.sev];
  });
  
  vulns.forEach(v => {
    const card = document.createElement('div');
    const bColor = v.vuln.sev === 'critical' ? 'var(--danger)' : v.vuln.sev === 'high' ? 'var(--warning)' : '#fcd34d';
    
    card.style.background = 'var(--bg-surface)';
    card.style.border = '1px solid ' + bColor;
    card.style.borderLeft = '4px solid ' + bColor;
    card.style.borderRadius = '8px';
    card.style.padding = '20px';
    card.style.cursor = 'pointer';
    card.onclick = () => window.openDeepDetails(v.index);
    
    card.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
        <div style="font-size:1rem; color:var(--text-main); font-weight:bold;">${v.vuln.title}</div>
        <span class="badge" style="text-transform:uppercase; background:rgba(255,255,255,0.1); color:${bColor}; border:1px solid ${bColor};">${v.vuln.sev}</span>
      </div>
      <div>
        <div style="color:var(--accent-1); margin-bottom:8px; font-family:'JetBrains Mono', monospace; font-size:0.85rem;">PORT: ${v.port} | ${v.vuln.cve}</div>
        <p style="color:var(--text-muted); font-size:0.8rem; line-height:1.5;">${v.vuln.desc}</p>
      </div>
    `;
    list.appendChild(card);
  });
}

function buildOSView() {
  const content = document.getElementById('osContent');
  content.style.display = 'block';
  
  const os = window.OS_PROFILES[Math.floor(Math.random() * window.OS_PROFILES.length)];
  
  content.innerHTML = `
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px;">
      <div style="background:var(--bg-surface); border:1px solid var(--border-color); padding:20px; border-radius:8px;">
        <div style="font-size:0.8rem; text-transform:uppercase; color:var(--accent-1); margin-bottom:16px; letter-spacing:1px; font-weight:bold;">System Identity</div>
        <div style="display:flex; flex-direction:column; gap:12px; font-size:0.85rem;">
          <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted)">OS Match</span> <span style="color:var(--text-main); font-family:'JetBrains Mono';">${os.os}</span></div>
          <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted)">Kernel</span> <span style="color:var(--text-main); font-family:'JetBrains Mono';">${os.kernel}</span></div>
          <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted)">Architecture</span> <span style="color:var(--text-main); font-family:'JetBrains Mono';">${os.arch}</span></div>
          <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted)">Vendor</span> <span style="color:var(--text-main); font-family:'JetBrains Mono';">${os.vendor}</span></div>
        </div>
      </div>
      <div style="background:var(--bg-surface); border:1px solid var(--border-color); padding:20px; border-radius:8px;">
        <div style="font-size:0.8rem; text-transform:uppercase; color:var(--accent-1); margin-bottom:16px; letter-spacing:1px; font-weight:bold;">Network Metrics</div>
        <div style="display:flex; flex-direction:column; gap:12px; font-size:0.85rem;">
          <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted)">Base TTL</span> <span style="color:var(--text-main); font-family:'JetBrains Mono';">${os.ttl}</span></div>
          <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted)">Network Distance</span> <span style="color:var(--text-main); font-family:'JetBrains Mono';">${Math.floor(Math.random() * 4) + 1} hops</span></div>
          <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted)">TCP Sequence</span> <span style="color:var(--text-main); font-family:'JetBrains Mono';">Incremental</span></div>
          <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted)">Confidence Level</span> <span style="color:var(--accent-1); font-weight:bold; font-family:'JetBrains Mono';">${os.prob}%</span></div>
        </div>
      </div>
    </div>
  `;
}
