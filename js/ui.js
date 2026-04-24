// UI Interactions and Management

const ui = {
  // Clock
  initClock() {
    setInterval(() => {
      const n = new Date();
      document.getElementById('navTime').textContent = 
        `${String(n.getHours()).padStart(2, '0')}:${String(n.getMinutes()).padStart(2, '0')}:${String(n.getSeconds()).padStart(2, '0')}`;
    }, 1000);
  },

  // Mobile Sidebar Toggle
  toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
  },

  // Tabs
  switchTab(name, btn) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('view-' + name).classList.add('active');
    if (btn) btn.classList.add('active');
  },

  // Modal logic for Deep Details
  openModal(portData) {
    document.getElementById('modalPortTitle').textContent = `PORT ${portData.port} / TCP`;
    document.getElementById('modalSvcName').textContent = portData.svc.toUpperCase();
    document.getElementById('modalBanner').textContent = portData.banner || 'No banner retrieved';
    
    // Risk
    const riskEl = document.getElementById('modalRisk');
    const cveEl = document.getElementById('modalCve');
    if (portData.vuln) {
      riskEl.textContent = portData.vuln.sev.toUpperCase() + ' RISK';
      riskEl.style.color = portData.vuln.sev === 'critical' || portData.vuln.sev === 'high' ? 'var(--danger)' : 'var(--warning)';
      cveEl.textContent = `${portData.vuln.cve} - ${portData.vuln.title}`;
    } else {
      riskEl.textContent = 'LOW RISK';
      riskEl.style.color = 'var(--success)';
      cveEl.textContent = 'No critical vulnerabilities detected in database.';
    }

    // Deep Details
    const deep = window.DEEP_DETAILS ? window.DEEP_DETAILS[portData.port] : null;
    document.getElementById('modalMitre').textContent = deep ? deep.mitre : "T1046: Network Service Discovery\nMitigation: Follow standard vendor hardening guidelines.";
    document.getElementById('modalHexDump').textContent = deep ? deep.hex : "0000   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................";
    
    document.getElementById('portModal').classList.add('active');
  },

  closeModal() {
    document.getElementById('portModal').classList.remove('active');
  },

  // Logging to terminal
  log(msg, cls = 't-info') {
    const term = document.getElementById('terminal');
    const d = document.createElement('div');
    const n = new Date();
    const ts = `${String(n.getHours()).padStart(2, '0')}:${String(n.getMinutes()).padStart(2, '0')}:${String(n.getSeconds()).padStart(2, '0')}`;
    d.innerHTML = `<span class="t-time">[${ts}]</span> ${msg}`;
    if (cls) d.className = cls;
    
    const cursorDiv = term.lastElementChild;
    term.insertBefore(d, cursorDiv);
    term.scrollTop = term.scrollHeight;
  },

  // Stats updates
  updateStats(total, open, filtered, vulns) {
    document.getElementById('sTotal').textContent = total;
    document.getElementById('sOpen').textContent = open;
    document.getElementById('sFiltered').textContent = filtered;
    document.getElementById('sVulns').textContent = vulns;
  },

  // Clear All
  clearAll() {
    if(window.scannerState) {
      window.scannerState.openPorts = [];
      window.scannerState.totalScanned = 0;
      window.scannerState.filteredCount = 0;
      window.scannerState.vulnCount = 0;
    }
    
    const term = document.getElementById('terminal');
    term.innerHTML = '<div class="t-info">Terminal cleared. Sequence ready.</div><div style="margin-top:12px;"><span class="cursor" style="display:inline-block; width:8px; height:16px; background:var(--accent-1); animation:blink 1s step-end infinite;"></span></div>';
    
    document.getElementById('resultsBody').innerHTML = '';
    document.getElementById('resultsTable').style.display = 'none';
    
    document.getElementById('servicesGrid').innerHTML = '';
    document.getElementById('vulnList').innerHTML = '';
    document.getElementById('osContent').innerHTML = '';
    document.getElementById('osContent').style.display = 'none';
    
    document.getElementById('progressFill').style.width = '0%';
    document.getElementById('progressPct').textContent = '0%';
    document.getElementById('progressLabel').textContent = 'READY — Awaiting input vector';
    
    this.updateStats(0,0,0,0);
  }
};

window.toggleTheme = function() {
  const html = document.documentElement;
  if (html.getAttribute('data-theme') === 'dark') {
    html.setAttribute('data-theme', 'light');
  } else {
    html.setAttribute('data-theme', 'dark');
  }
};

window.applyPreset = function(name) {
  const P = {
    web: { r: '80,443,8000,8080,8443', m: 'syn' },
    db: { r: '1433,3306,5432,6379,9200,27017', m: 'tcp' },
    vuln: { r: '21,22,23,445,3389,6379,27017,7001', m: 'aggressive' },
    full: { r: '1-65535', m: 'syn' },
  };
  if(P[name]) {
    document.getElementById('portRange').value = P[name].r;
    document.getElementById('scanMode').value = P[name].m;
    document.getElementById('optVuln').checked = (name === 'vuln' || name === 'aggressive');
  }
};

document.getElementById('timing').addEventListener('input', function() {
  document.getElementById('timingVal').textContent = 'T' + this.value;
});

ui.initClock();
window.ui = ui;
