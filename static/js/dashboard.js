// ─── State ────────────────────────────────────────────────────────────────────
const socket = io();
let trafficChart, attackChart, rtTrafficChart, rtAttackChart, csvPieChart;
let trafficData = { labels: [], normal: [], attacks: [] };
let attackCounts = {};
let selectedFile = null;
let alertCount = 0;

const ATTACK_COLORS = {
    'Normal': '#10b981',
    'DDoS_UDP': '#ef4444',
    'DDoS_ICMP': '#f97316',
    'Ransomware': '#dc2626',
    'DDoS_HTTP': '#ef4444',
    'SQL_injection': '#8b5cf6',
    'Uploading': '#f59e0b',
    'DDoS_TCP': '#ef4444',
    'Backdoor': '#b91c1c',
    'Vulnerability_scanner': '#06b6d4',
    'Port_Scanning': '#3b82f6',
    'XSS': '#a78bfa',
    'Password': '#f43f5e',
    'MITM': '#e11d48',
    'Fingerprinting': '#64748b',
};

const RISK_COLORS = { 'High': '#ef4444', 'Medium': '#f59e0b', 'Low': '#10b981' };

// ─── Socket.IO ────────────────────────────────────────────────────────────────
socket.on('connect', () => {
    document.querySelector('.status-dot').classList.add('connected');
    document.getElementById('statusText').textContent = 'Connected';
});

socket.on('disconnect', () => {
    document.querySelector('.status-dot').classList.remove('connected');
    document.querySelector('.status-dot').classList.add('error');
    document.getElementById('statusText').textContent = 'Disconnected';
});

socket.on('packet_update', (data) => {
    updateStats(data);
    addPacketToFeed(data, 'packetFeed');
    addPacketToFeed(data, 'rtPacketFeed');
    updateTrafficChart(data);
    updateAttackChart(data.attack_counts);
    if (data.is_attack) addAlert(data);
});

socket.on('capture_error', (data) => {
    showToast('Capture Error: ' + data.error, 'error');
    // Reset UI buttons
    const rtStartBtn = document.getElementById('rtStartBtn');
    const rtStopBtn = document.getElementById('rtStopBtn');
    const rtStatus = document.getElementById('rtStatus');
    if (rtStartBtn) rtStartBtn.disabled = false;
    if (rtStopBtn) rtStopBtn.disabled = true;
    if (rtStatus) rtStatus.innerHTML = '<span class="dot-idle"></span> Error - Check console';
});

// ─── Tab Switching ────────────────────────────────────────────────────────────
function switchTab(name) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(`tab-${name}`).classList.add('active');
    document.getElementById(`content-${name}`).classList.add('active');
}

// ─── Stats Update ─────────────────────────────────────────────────────────────
function updateStats(data) {
    document.getElementById('totalPackets').textContent = data.total_packets.toLocaleString();
    document.getElementById('attacksDetected').textContent = data.attacks_detected.toLocaleString();
    const normal = data.total_packets - data.attacks_detected;
    document.getElementById('normalTraffic').textContent = normal.toLocaleString();
    document.getElementById('encTime').textContent = `${data.encryption_time_ms} ms`;
    const rate = data.total_packets > 0
        ? ((data.attacks_detected / data.total_packets) * 100).toFixed(1)
        : '0.0';
    document.getElementById('attackRate').textContent = `${rate}%`;
}

// ─── Packet Feed ──────────────────────────────────────────────────────────────
function addPacketToFeed(data, feedId) {
    const feed = document.getElementById(feedId);
    const empty = feed.querySelector('.feed-empty');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = `packet-item ${data.is_attack ? 'attack' : 'normal'}`;

    const riskBadge = data.is_attack
        ? `<span class="badge ${data.risk_level === 'High' ? 'red' : data.risk_level === 'Medium' ? 'orange' : 'yellow'}">${data.risk_level}</span>`
        : '<span class="badge green">Normal</span>';

    item.innerHTML = `
        <span class="packet-time">${data.timestamp}</span>
        <span class="packet-ips">${data.src_ip} → ${data.dst_ip}</span>
        <span class="packet-type">${riskBadge}</span>
        <span class="packet-type"><span class="badge ${data.is_attack ? 'red' : 'green'}">${data.attack_type}</span></span>
        <span class="packet-conf">${data.confidence}%</span>
        <span class="packet-enc"><i class="fas fa-lock"></i> ${data.encryption_time_ms}ms</span>
    `;

    feed.insertBefore(item, feed.firstChild);

    // Keep max 100 items
    while (feed.children.length > 100) {
        feed.removeChild(feed.lastChild);
    }
}

function clearFeed() {
    ['packetFeed', 'rtPacketFeed'].forEach(id => {
        const feed = document.getElementById(id);
        feed.innerHTML = `<div class="feed-empty">
            <i class="fas fa-satellite-dish"></i>
            <p>Feed cleared</p>
        </div>`;
    });
}

// ─── Alerts ───────────────────────────────────────────────────────────────────
function addAlert(data) {
    alertCount++;
    document.getElementById('alertCount').textContent = alertCount;

    const container = document.getElementById('alertsContainer');
    const empty = container.querySelector('.feed-empty');
    if (empty) empty.remove();

    const riskClass = data.risk_level === 'High' ? '' : data.risk_level === 'Medium' ? 'medium' : 'low';
    const icon = data.risk_level === 'High' ? 'fa-skull-crossbones' : 'fa-triangle-exclamation';

    const item = document.createElement('div');
    item.className = `alert-item ${riskClass}`;
    item.innerHTML = `
        <i class="fas ${icon} alert-icon"></i>
        <div class="alert-body">
            <div class="alert-title">${data.attack_type} Detected</div>
            <div class="alert-meta">${data.src_ip} → ${data.dst_ip} · Confidence: ${data.confidence}%${data.is_anomaly ? ' · ⚠ Anomaly' : ''}</div>
        </div>
        <span class="alert-time">${data.timestamp}</span>
    `;
    container.insertBefore(item, container.firstChild);

    while (container.children.length > 50) {
        container.removeChild(container.lastChild);
    }
}

// ─── Charts ───────────────────────────────────────────────────────────────────
function initCharts() {
    Chart.defaults.color = '#8899b4';
    Chart.defaults.borderColor = '#1e2d4d';

    const lineOpts = {
        responsive: true,
        maintainAspectRatio: true,
        animation: { duration: 200 },
        plugins: { legend: { position: 'top', labels: { boxWidth: 12, font: { size: 11 } } } },
        scales: {
            x: { grid: { color: '#1e2d4d' }, ticks: { maxTicksLimit: 10, font: { size: 10 } } },
            y: { grid: { color: '#1e2d4d' }, beginAtZero: true, ticks: { font: { size: 10 } } }
        }
    };

    const lineData = () => ({
        labels: [],
        datasets: [
            { label: 'Normal', data: [], borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.1)', fill: true, tension: 0.4, pointRadius: 2 },
            { label: 'Attacks', data: [], borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', fill: true, tension: 0.4, pointRadius: 2 }
        ]
    });

    trafficChart = new Chart(document.getElementById('trafficChart'), { type: 'line', data: lineData(), options: lineOpts });
    rtTrafficChart = new Chart(document.getElementById('rtTrafficChart'), { type: 'line', data: lineData(), options: lineOpts });

    const pieOpts = {
        responsive: true,
        maintainAspectRatio: true,
        animation: { duration: 300 },
        plugins: {
            legend: { position: 'right', labels: { boxWidth: 10, font: { size: 10 }, padding: 8 } }
        }
    };

    attackChart = new Chart(document.getElementById('attackChart'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
        options: pieOpts
    });

    rtAttackChart = new Chart(document.getElementById('rtAttackChart'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
        options: pieOpts
    });
}

function updateTrafficChart(data) {
    const now = data.timestamp;
    const isAttack = data.is_attack ? 1 : 0;
    const isNormal = data.is_attack ? 0 : 1;

    [trafficChart, rtTrafficChart].forEach(chart => {
        if (chart.data.labels.length === 0 || chart.data.labels[chart.data.labels.length - 1] !== now) {
            chart.data.labels.push(now);
            chart.data.datasets[0].data.push(isNormal);
            chart.data.datasets[1].data.push(isAttack);
        } else {
            const last = chart.data.labels.length - 1;
            chart.data.datasets[0].data[last] += isNormal;
            chart.data.datasets[1].data[last] += isAttack;
        }

        if (chart.data.labels.length > 30) {
            chart.data.labels.shift();
            chart.data.datasets.forEach(d => d.data.shift());
        }
        chart.update('none');
    });
}

function updateAttackChart(counts) {
    const labels = Object.keys(counts).filter(k => counts[k] > 0);
    const data = labels.map(k => counts[k]);
    const colors = labels.map(k => ATTACK_COLORS[k] || '#64748b');

    [attackChart, rtAttackChart].forEach(chart => {
        chart.data.labels = labels;
        chart.data.datasets[0].data = data;
        chart.data.datasets[0].backgroundColor = colors;
        chart.update('none');
    });
}

// ─── Simulation ───────────────────────────────────────────────────────────────
async function startSimulation() {
    const res = await fetch('/api/simulate/start', { method: 'POST' });
    const data = await res.json();
    document.getElementById('simStartBtn').disabled = true;
    document.getElementById('simStopBtn').disabled = false;
    document.getElementById('simStatus').innerHTML = '<span class="dot-running"></span> Running...';
    showToast('Simulation started');
}

async function stopSimulation() {
    const res = await fetch('/api/simulate/stop', { method: 'POST' });
    document.getElementById('simStartBtn').disabled = false;
    document.getElementById('simStopBtn').disabled = true;
    document.getElementById('simStatus').innerHTML = '<span class="dot-idle"></span> Stopped';
    showToast('Simulation stopped');
}

// ─── Real-time Capture ────────────────────────────────────────────────────────
async function startRealtime() {
    const res = await fetch('/api/realtime/start', { method: 'POST' });
    const data = await res.json();
    if (data.error) {
        showToast('Error: ' + data.error, 'error');
        return;
    }
    document.getElementById('rtStartBtn').disabled = true;
    document.getElementById('rtStopBtn').disabled = false;
    document.getElementById('rtStatus').innerHTML = '<span class="dot-running"></span> Capturing...';
    showToast('Real-time capture started');
}

async function stopRealtime() {
    await fetch('/api/realtime/stop', { method: 'POST' });
    document.getElementById('rtStartBtn').disabled = false;
    document.getElementById('rtStopBtn').disabled = true;
    document.getElementById('rtStatus').innerHTML = '<span class="dot-idle"></span> Stopped';
    showToast('Capture stopped');
}

// ─── CSV Prediction ───────────────────────────────────────────────────────────
function handleFileSelect(event) {
    selectedFile = event.target.files[0];
    if (!selectedFile) return;
    document.getElementById('fileName').textContent = selectedFile.name;
    document.getElementById('fileInfo').classList.remove('hidden');
    document.getElementById('predictBtn').disabled = false;
}

function clearFile() {
    selectedFile = null;
    document.getElementById('csvFile').value = '';
    document.getElementById('fileInfo').classList.add('hidden');
    document.getElementById('predictBtn').disabled = true;
}

// Drag and drop
const uploadZone = document.getElementById('uploadZone');
uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('dragover'); });
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
uploadZone.addEventListener('drop', e => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith('.csv')) {
        selectedFile = file;
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileInfo').classList.remove('hidden');
        document.getElementById('predictBtn').disabled = false;
    }
});

async function runCsvPrediction() {
    if (!selectedFile) return;

    const progress = document.getElementById('csvProgress');
    const fill = document.getElementById('progressFill');
    const text = document.getElementById('progressText');
    progress.classList.remove('hidden');
    fill.style.width = '30%';
    text.textContent = 'Uploading and processing...';
    document.getElementById('predictBtn').disabled = true;

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
        fill.style.width = '60%';
        const res = await fetch('/api/predict/csv', { method: 'POST', body: formData });
        fill.style.width = '90%';
        const data = await res.json();

        if (data.error) {
            showToast('Error: ' + data.error, 'error');
            return;
        }

        fill.style.width = '100%';
        text.textContent = `Done! Processed ${data.processed} rows`;

        // Show summary
        showCsvSummary(data);
        showCsvResults(data.results);

        // Update global stats display
        document.getElementById('totalPackets').textContent = data.processed.toLocaleString();
        document.getElementById('attacksDetected').textContent = data.attacks_found.toLocaleString();
        document.getElementById('normalTraffic').textContent = data.normal_found.toLocaleString();
        document.getElementById('encTime').textContent = `${data.avg_encryption_time_ms} ms`;
        const rate = ((data.attacks_found / data.processed) * 100).toFixed(1);
        document.getElementById('attackRate').textContent = `${rate}%`;

        showToast(`Prediction complete: ${data.attacks_found} attacks found in ${data.processed} rows`);

    } catch (err) {
        showToast('Error: ' + err.message, 'error');
    } finally {
        document.getElementById('predictBtn').disabled = false;
        setTimeout(() => progress.classList.add('hidden'), 2000);
    }
}

function showCsvSummary(data) {
    const panel = document.getElementById('csvSummaryPanel');
    panel.style.display = 'block';

    const rate = ((data.attacks_found / data.processed) * 100).toFixed(1);
    document.getElementById('csvSummary').innerHTML = `
        <div class="summary-item">
            <div class="val" style="color:#3b82f6">${data.processed}</div>
            <div class="lbl">Total Rows</div>
        </div>
        <div class="summary-item">
            <div class="val" style="color:#ef4444">${data.attacks_found}</div>
            <div class="lbl">Attacks</div>
        </div>
        <div class="summary-item">
            <div class="val" style="color:#10b981">${data.normal_found}</div>
            <div class="lbl">Normal</div>
        </div>
        <div class="summary-item">
            <div class="val" style="color:#f59e0b">${rate}%</div>
            <div class="lbl">Attack Rate</div>
        </div>
    `;

    // Count attack types
    const counts = {};
    data.results.forEach(r => {
        counts[r.attack_type] = (counts[r.attack_type] || 0) + 1;
    });
    const labels = Object.keys(counts);
    const vals = labels.map(k => counts[k]);
    const colors = labels.map(k => ATTACK_COLORS[k] || '#64748b');

    if (csvPieChart) csvPieChart.destroy();
    csvPieChart = new Chart(document.getElementById('csvPieChart'), {
        type: 'doughnut',
        data: { labels, datasets: [{ data: vals, backgroundColor: colors }] },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'right', labels: { boxWidth: 10, font: { size: 10 } } }
            }
        }
    });
}

function showCsvResults(results) {
    const panel = document.getElementById('csvResultsPanel');
    panel.style.display = 'block';
    document.getElementById('resultCount').textContent = `${results.length} rows`;

    const tbody = document.getElementById('resultsBody');
    tbody.innerHTML = '';

    results.forEach(r => {
        const riskColor = RISK_COLORS[r.risk_level] || '#64748b';
        const tr = document.createElement('tr');
        if (r.is_attack) tr.className = 'attack-row';
        tr.innerHTML = `
            <td style="color:#8899b4">${r.row + 1}</td>
            <td>${r.src_ip}</td>
            <td>${r.dst_ip}</td>
            <td><span class="badge ${r.is_attack ? 'red' : 'green'}">${r.attack_type}</span></td>
            <td>${r.confidence}%</td>
            <td><span style="color:${riskColor};font-weight:600">${r.risk_level}</span></td>
            <td>${r.is_anomaly ? '<span class="badge orange">Yes</span>' : '<span class="badge gray">No</span>'}</td>
            <td style="color:#8b5cf6">${r.encryption_time_ms} ms</td>
        `;
        tbody.appendChild(tr);
    });
}

async function downloadSample() {
    showToast('Generating sample CSV...');
    window.location.href = '/api/generate_sample';
}

// ─── Reset ────────────────────────────────────────────────────────────────────
async function resetStats() {
    await fetch('/api/reset', { method: 'POST' });
    ['totalPackets', 'attacksDetected', 'normalTraffic'].forEach(id => {
        document.getElementById(id).textContent = '0';
    });
    document.getElementById('encTime').textContent = '0 ms';
    document.getElementById('attackRate').textContent = '0%';
    alertCount = 0;
    document.getElementById('alertCount').textContent = '0';
    document.getElementById('alertsContainer').innerHTML = `<div class="feed-empty">
        <i class="fas fa-shield-halved"></i>
        <p>No alerts yet — system is monitoring</p>
    </div>`;
    clearFeed();
    showToast('Statistics reset');
}

// ─── Toast ────────────────────────────────────────────────────────────────────
function showToast(msg, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.style.borderColor = type === 'error' ? '#ef4444' : '#1e2d4d';
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
}

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
});
