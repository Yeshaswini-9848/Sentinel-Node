/* ──────────────────────────────────────────────
   SentinelNode — Dashboard Controller (script.js)
   ────────────────────────────────────────────── */

'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
let isMonitoring = false;
let isSimulation = false;
let pollInterval = null;
let seenAlertIds = new Set();
let allAlerts = []; // Global history of alerts for independent views
let prevPacketCount = 0;

// Chart instances
let timelineChart = null;
let protoChart = null;
let severityChart = null;
let analyticsTimelineChart = null;
let analyticsProtoChart = null;
let analyticsSeverityChart = null;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const monitorBtn = document.getElementById('monitorBtn');
const monitorIcon = document.getElementById('monitorIcon');
const monitorLabel = document.getElementById('monitorLabel');
const interfaceInput = document.getElementById('interfaceInput');
const btnLive = document.getElementById('btnLive');
const btnSim = document.getElementById('btnSim');

const systemBanner = document.getElementById('systemBanner');
const bannerIcon = document.getElementById('bannerIcon');
const bannerText = document.getElementById('bannerText');

const modeChip = document.getElementById('modeChip');
const modeChipText = document.getElementById('modeChipText');
const chipDot = modeChip.querySelector('.chip-dot');

const kpiPacketVal = document.getElementById('kpiPacketVal');
const kpiPacketTrend = document.getElementById('kpiPacketTrend');
const kpiCriticalVal = document.getElementById('kpiCriticalVal');
const kpiHighVal = document.getElementById('kpiHighVal');
const kpiMedVal = document.getElementById('kpiMedVal');

const trafficBody = document.getElementById('trafficBody');
const simBadge = document.getElementById('simBadge');
const packetDisplayCount = document.getElementById('packetDisplayCount');

const alertFeed = document.getElementById('alertFeed');
const clearAlertsBtn = document.getElementById('clearAlertsBtn');
const navAlertCount = document.getElementById('navAlertCount');
const lastSync = document.getElementById('lastSync');

// Sidebar View Links
const navDashboard = document.getElementById('nav-dashboard');
const navAlerts = document.getElementById('nav-alerts');
const navAnalytics = document.getElementById('nav-analytics');

// Views
const views = {
    dashboard: document.getElementById('view-dashboard'),
    alerts: document.getElementById('view-alerts'),
    analytics: document.getElementById('view-analytics')
};

// Alert Page Elements
const alertPageCritical = document.getElementById('alertPageCritical');
const alertPageHigh = document.getElementById('alertPageHigh');
const alertPageMedium = document.getElementById('alertPageMedium');
const alertPageLow = document.getElementById('alertPageLow');
const alertPageTotal = document.getElementById('alertPageTotal');
const alertsTableBody = document.getElementById('alertsTableBody');
const clearAlertsPageBtn = document.getElementById('clearAlertsPageBtn');
const filterBtns = document.querySelectorAll('.filter-btn');

// Analytics Page Elements
const analyticsPackets = document.getElementById('analyticsPackets');
const analyticsAlerts = document.getElementById('analyticsAlerts');
const analyticsLastUpdate = document.getElementById('analyticsLastUpdate');
const analyticsMode = document.getElementById('analyticsMode');

// ── Navigation ────────────────────────────────────────────────────────────────
function switchView(viewName) {
    console.log(`[SentinelNode] Switching to view: ${viewName}`);

    // Update menu UI
    const navLinks = [navDashboard, navAlerts, navAnalytics];
    navLinks.forEach(link => {
        if (link) link.classList.remove('active');
    });

    const activeLink = document.getElementById(`nav-${viewName}`);
    if (activeLink) {
        activeLink.classList.add('active');
    }

    // Update Section Visibility
    Object.keys(views).forEach(key => {
        const viewEl = views[key];
        if (viewEl) {
            viewEl.classList.remove('active-view');
            if (key === viewName) {
                viewEl.classList.add('active-view');
            }
        }
    });

    // Scroll to top of main content
    const mainContent = document.querySelector('.main-content');
    if (mainContent) mainContent.scrollTop = 0;
}

if (navDashboard) navDashboard.addEventListener('click', (e) => { e.preventDefault(); switchView('dashboard'); });
if (navAlerts) navAlerts.addEventListener('click', (e) => { e.preventDefault(); switchView('alerts'); });
if (navAnalytics) navAnalytics.addEventListener('click', (e) => { e.preventDefault(); switchView('analytics'); });


// ── Chart.js Defaults ─────────────────────────────────────────────────────────
Chart.defaults.color = '#64748b';
Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
Chart.defaults.font.family = "'Inter', sans-serif";

const CHART_COLORS = {
    TCP: '#60a5fa',
    UDP: '#a78bfa',
    ICMP: '#ffb830',
    HTTP: '#00e5a0',
    HTTPS: '#00c8ff',
    OTHER: '#3d4f6e',
};

function initCharts() {
    const configLine = (ctx) => ({
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Packets/sec', data: [], borderColor: '#00c8ff', backgroundColor: 'rgba(0,200,255,0.06)', borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0 }] },
        options: { animation: false, responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 8, font: { size: 10 } } }, y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { font: { size: 10 } } } } }
    });

    const configDoughnut = () => ({
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 1, borderColor: '#0f1420' }] },
        options: { animation: false, responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 12, font: { size: 11 } } } } }
    });

    const configBar = () => ({
        type: 'bar',
        data: { labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], datasets: [{ data: [0, 0, 0, 0], backgroundColor: ['rgba(255,61,110,0.7)', 'rgba(255,124,56,0.7)', 'rgba(255,184,48,0.7)', 'rgba(110,231,247,0.7)'], borderRadius: 4, borderWidth: 0 }] },
        options: { animation: false, responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false }, ticks: { font: { size: 10 } } }, y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { font: { size: 10 } } } } }
    });

    // Dashboard Charts
    timelineChart = new Chart(document.getElementById('timelineChart').getContext('2d'), configLine());
    protoChart = new Chart(document.getElementById('protoChart').getContext('2d'), configDoughnut());
    severityChart = new Chart(document.getElementById('severityChart').getContext('2d'), configBar());

    // Analytics Charts
    analyticsTimelineChart = new Chart(document.getElementById('analyticsTimelineChart').getContext('2d'), configLine());
    analyticsProtoChart = new Chart(document.getElementById('analyticsProtoChart').getContext('2d'), configDoughnut());
    analyticsSeverityChart = new Chart(document.getElementById('analyticsSeverityChart').getContext('2d'), configBar());
}

// ── Monitor Button ────────────────────────────────────────────────────────────
monitorBtn.addEventListener('click', () => { isMonitoring ? stopMonitoring() : startMonitoring(); });

async function startMonitoring() {
    const networkInterface = interfaceInput.value.trim() || null;
    try {
        const res = await fetch('/api/start_monitoring', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: networkInterface, simulate: isSimulation })
        });
        const data = await res.json();
        if (data.status !== 'success') { alert(data.message); return; }

        isMonitoring = true;
        seenAlertIds.clear();
        allAlerts = [];
        prevPacketCount = 0;

        // Clear UI
        trafficBody.innerHTML = '';
        alertFeed.innerHTML = '';
        alertsTableBody.innerHTML = '';
        navAlertCount.textContent = '0';

        updateUIMonitoring(true, isSimulation);
        pollInterval = setInterval(fetchData, 1000);
    } catch (e) { console.error('[SentinelNode] error:', e); }
}

async function stopMonitoring() {
    try {
        await fetch('/api/stop_monitoring', { method: 'POST' });
        isMonitoring = false;
        clearInterval(pollInterval);
        updateUIMonitoring(false, false);
    } catch (e) { }
}

async function fetchData() {
    try {
        const res = await fetch('/api/traffic_data');
        const data = await res.json();
        if (data.status !== 'success') return;

        updateKPIs(data.stats);
        updateTrafficTable(data.traffic);
        updateAlertFeed(data.traffic);
        updateAlertsPage(data.stats);
        updateAnalyticsPage(data.stats);
        updateCharts(data.stats);
        lastSync.textContent = new Date().toLocaleTimeString();
    } catch (e) { }
}

function updateKPIs(stats) {
    const sevDist = stats.severity_distribution || {};
    kpiPacketVal.textContent = stats.packet_count || 0;
    kpiCriticalVal.textContent = sevDist.CRITICAL || 0;
    kpiHighVal.textContent = sevDist.HIGH || 0;
    kpiMedVal.textContent = (sevDist.MEDIUM || 0) + (sevDist.LOW || 0);

    const delta = (stats.packet_count || 0) - prevPacketCount;
    kpiPacketTrend.textContent = delta > 0 ? `+${delta}/s` : '—';
    prevPacketCount = stats.packet_count || 0;
    navAlertCount.textContent = stats.alerts_total || 0;
}

function updateTrafficTable(traffic) {
    if (!traffic || !traffic.length) return;
    const rows = [...traffic].reverse().slice(0, 20);
    packetDisplayCount.textContent = rows.length;
    trafficBody.innerHTML = rows.map(p => {
        const sev = (p.severity || 'SAFE').toLowerCase();
        return `<tr>
            <td>${p.timestamp || '—'}</td>
            <td>${p.source_ip || '—'}</td>
            <td class="proto-${(p.protocol || '').toLowerCase()}">${(p.protocol || '').toUpperCase()}</td>
            <td>${p.dest_ip || '—'}</td>
            <td>${p.dst_port || '—'}</td>
            <td>${p.length || 0}B</td>
            <td><span class="badge badge-${sev}">${(p.severity || 'SAFE').toUpperCase()}</span></td>
        </tr>`;
    }).join('');
}

function updateAlertFeed(traffic) {
    [...traffic].reverse().forEach(p => {
        (p.alerts || []).forEach(alert => {
            const id = `${p.source_ip}-${alert.message.substring(0, 15)}`;
            if (seenAlertIds.has(id)) return;
            seenAlertIds.add(id);

            const alertObj = { ...alert, ...p, id };
            allAlerts.unshift(alertObj); // In-memory history

            const sev = alert.severity.toLowerCase();
            const el = document.createElement('div');
            el.className = `alert-item alert-${sev}`;
            el.innerHTML = `<span class="alert-sev-label sev-${sev}">${alert.severity}</span>
                <div class="alert-msg">${alert.message}</div>
                <div class="alert-meta">SRC: ${p.source_ip} | ${p.timestamp}</div>`;
            if (alertFeed.querySelector('.empty-state')) alertFeed.innerHTML = '';
            alertFeed.prepend(el);

            // Add to Alerts Table
            appendAlertToTable(alertObj);
        });
    });
}

function appendAlertToTable(alert) {
    if (alertsTableBody.querySelector('.empty-state')) alertsTableBody.innerHTML = '';
    const row = document.createElement('tr');
    row.dataset.sev = alert.severity;
    row.innerHTML = `<td>${alert.timestamp}</td>
        <td><span class="badge badge-${alert.severity.toLowerCase()}">${alert.severity}</span></td>
        <td style="font-family:inherit; color:#e4ecf7">${alert.message}</td>
        <td>${alert.source_ip}</td>
        <td class="proto-${alert.protocol.toLowerCase()}">${alert.protocol}</td>`;
    alertsTableBody.prepend(row);
}

function updateAlertsPage(stats) {
    const d = stats.severity_distribution || {};
    alertPageCritical.textContent = d.CRITICAL || 0;
    alertPageHigh.textContent = d.HIGH || 0;
    alertPageMedium.textContent = d.MEDIUM || 0;
    alertPageLow.textContent = d.LOW || 0;
    alertPageTotal.textContent = stats.alerts_total || 0;
}

function updateAnalyticsPage(stats) {
    analyticsPackets.textContent = stats.packet_count || 0;
    analyticsAlerts.textContent = stats.alerts_total || 0;
    analyticsLastUpdate.textContent = new Date().toLocaleTimeString();
    analyticsMode.textContent = stats.simulation_mode ? 'Simulation' : 'Live Capture';
}

function updateCharts(stats) {
    const list = [
        { c: timelineChart, data: stats.traffic_timeline },
        { c: analyticsTimelineChart, data: stats.traffic_timeline }
    ];
    list.forEach(item => {
        item.c.data.labels = item.data.map(t => t.time);
        item.c.data.datasets[0].data = item.data.map(t => t.count);
        item.c.update('none');
    });

    const protoDist = stats.protocol_distribution || {};
    const labels = Object.keys(protoDist);
    const colors = labels.map(l => CHART_COLORS[l] || CHART_COLORS.OTHER);
    [protoChart, analyticsProtoChart].forEach(c => {
        c.data.labels = labels;
        c.data.datasets[0].data = Object.values(protoDist);
        c.data.datasets[0].backgroundColor = colors;
        c.update('none');
    });

    const d = stats.severity_distribution || {};
    const sevData = [d.CRITICAL || 0, d.HIGH || 0, d.MEDIUM || 0, d.LOW || 0];
    [severityChart, analyticsSeverityChart].forEach(c => {
        c.data.datasets[0].data = sevData;
        c.update('none');
    });
}

function updateUIMonitoring(active, sim) {
    const s = active ? (sim ? 'sim' : 'active') : 'stopped';
    const i = active ? (sim ? '🟡' : '🟢') : '🔴';
    const t = active ? (sim ? 'SYSTEM STATUS: SIMULATION MODE' : 'SYSTEM STATUS: MONITORING ACTIVE') : 'SYSTEM STATUS: IDLE';
    systemBanner.className = `system-banner banner-${s}`;
    bannerIcon.textContent = i; bannerText.textContent = t;
    chipDot.className = `chip-dot ${s}`; modeChipText.textContent = active ? (sim ? 'Simulation' : 'Active') : 'Idle';
    if (active) {
        monitorBtn.classList.add('stop'); monitorIcon.className = 'fas fa-stop'; monitorLabel.textContent = 'Stop Monitoring';
    } else {
        monitorBtn.classList.remove('stop'); monitorIcon.className = 'fas fa-play'; monitorLabel.textContent = 'Start Monitoring';
    }
}

// Sidebar Source Toggles
btnLive.addEventListener('click', () => { isSimulation = false; btnLive.classList.add('active'); btnSim.classList.remove('active'); });
btnSim.addEventListener('click', () => { isSimulation = true; btnSim.classList.add('active'); btnLive.classList.remove('active'); });

// Alert Page Filter Logic
filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        filterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const sev = btn.dataset.sev;
        Array.from(alertsTableBody.children).forEach(row => {
            if (sev === 'ALL' || row.dataset.sev === sev) row.style.display = 'table-row';
            else row.style.display = 'none';
        });
    });
});

clearAlertsBtn.addEventListener('click', () => { alertFeed.innerHTML = ''; });
clearAlertsPageBtn.addEventListener('click', () => { alertsTableBody.innerHTML = ''; allAlerts = []; });

document.addEventListener('DOMContentLoaded', () => { initCharts(); btnSim.click(); switchView('dashboard'); });
