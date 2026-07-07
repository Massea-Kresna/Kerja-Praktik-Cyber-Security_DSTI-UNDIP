/**
 * =======================================================================
 * DSTI UNDIP Pentest Dashboard — Frontend App
 * =======================================================================
 * Mengambil data dari API (Supabase DB / fallback JSON) dan merender
 * dashboard interaktif.
 * =======================================================================
 */

const API_BASE = window.location.origin;

// ===================================================================
// State
// ===================================================================
let allDomains = [];
let allVulns = [];
let currentDomainPage = 1;
const DOMAINS_PER_PAGE = 15;
let searchTimeout = null;

// ===================================================================
// Init
// ===================================================================
document.addEventListener('DOMContentLoaded', () => {
    refreshAll();
});

// ===================================================================
// Refresh All Data
// ===================================================================
async function refreshAll() {
    const btn = document.getElementById('refreshBtn');
    btn.classList.add('spinning');

    try {
        await Promise.all([
            checkHealth(),
            loadDashboardStats(),
            loadDomains(),
            loadVulnerabilities(),
            loadScanHistory()
        ]);
    } catch (err) {
        console.error('Error refreshing data:', err);
    } finally {
        btn.classList.remove('spinning');
    }
}

// ===================================================================
// Health Check
// ===================================================================
async function checkHealth() {
    try {
        const resp = await fetch(`${API_BASE}/api/health`);
        const data = await resp.json();

        const badge = document.getElementById('dbStatus');
        const text = document.getElementById('dbStatusText');
        const banner = document.getElementById('notificationBanner');
        const bannerText = document.getElementById('notificationText');

        if (data.database.connected) {
            badge.className = 'status-badge connected';
            text.textContent = 'Database Terhubung';
            banner.classList.add('hidden');
        } else {
            badge.className = 'status-badge disconnected';
            text.textContent = 'Mode Lokal';
            banner.classList.remove('hidden');
            banner.className = 'notification-banner';
            bannerText.textContent = `${data.database.message}. Dashboard menampilkan data dari file JSON lokal.`;
        }
    } catch (err) {
        const badge = document.getElementById('dbStatus');
        const text = document.getElementById('dbStatusText');
        badge.className = 'status-badge disconnected';
        text.textContent = 'Server Error';

        const banner = document.getElementById('notificationBanner');
        const bannerText = document.getElementById('notificationText');
        banner.classList.remove('hidden');
        bannerText.textContent = 'Tidak dapat terhubung ke server API. Pastikan web_app.py sedang berjalan.';
    }
}

// ===================================================================
// Dashboard Stats
// ===================================================================
async function loadDashboardStats() {
    try {
        const resp = await fetch(`${API_BASE}/api/dashboard-stats`);
        const data = await resp.json();

        // Stat cards
        document.getElementById('statDomains').textContent = data.total_domains || 0;
        document.getElementById('statVulns').textContent = data.total_vulnerabilities || 0;
        document.getElementById('statScans').textContent = (data.recent_scans || []).length;
        document.getElementById('statSource').textContent =
            data.source === 'supabase' ? 'Supabase DB' : 'File JSON';

        // Risk distribution bar
        renderRiskBar(data.risk_distribution || {});

        // Recent scans
        renderRecentScans(data.recent_scans || []);
    } catch (err) {
        console.error('Error loading stats:', err);
        document.getElementById('statDomains').textContent = '!';
        document.getElementById('statVulns').textContent = '!';
        document.getElementById('statScans').textContent = '!';
        document.getElementById('statSource').textContent = 'Error';
    }
}

// ===================================================================
// Risk Distribution Bar
// ===================================================================
function renderRiskBar(dist) {
    const bar = document.getElementById('riskBar');
    const legend = document.getElementById('riskLegend');

    const total = (dist.CRITICAL || 0) + (dist.HIGH || 0) + (dist.MEDIUM || 0) + (dist.LOW || 0) + (dist.SAFE || 0);

    if (total === 0) {
        bar.innerHTML = '<div class="risk-bar-segment safe" style="width: 100%"></div>';
        legend.innerHTML = '<span class="risk-legend-item" style="color: var(--text-tertiary);">Belum ada data scan</span>';
        return;
    }

    const segments = [
        { key: 'CRITICAL', cls: 'high', label: 'Critical', value: dist.CRITICAL || 0 },
        { key: 'HIGH', cls: 'high', label: 'High', value: dist.HIGH || 0 },
        { key: 'MEDIUM', cls: 'medium', label: 'Medium', value: dist.MEDIUM || 0 },
        { key: 'LOW', cls: 'low', label: 'Low', value: dist.LOW || 0 },
        { key: 'SAFE', cls: 'safe', label: 'Safe', value: dist.SAFE || 0 }
    ];

    bar.innerHTML = segments
        .filter(s => s.value > 0)
        .map(s => `<div class="risk-bar-segment ${s.cls}" style="width: ${(s.value / total * 100).toFixed(1)}%"></div>`)
        .join('');

    legend.innerHTML = segments
        .map(s => `
            <div class="risk-legend-item">
                <span class="risk-legend-dot ${s.cls}"></span>
                ${s.label}: <span class="risk-legend-value">${s.value}</span>
            </div>
        `).join('');
}

// ===================================================================
// Recent Scans
// ===================================================================
function renderRecentScans(scans) {
    const tbody = document.getElementById('recentScansBody');

    if (!scans || scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state"><p>Belum ada scan</p><span class="hint">Jalankan main.py atau pentest_tools_scheduler.py</span></td></tr>';
        return;
    }

    tbody.innerHTML = scans.map(scan => {
        const domainName = scan.domains?.domain_name || '-';
        const riskLevel = scan.risk_level || 'SAFE';
        const badgeClass = getBadgeClass(riskLevel);
        const scoreClass = getScoreClass(scan.risk_score);
        const date = formatDate(scan.scan_date);

        return `
            <tr class="fade-in">
                <td><a class="domain-link" onclick="openDomainDetail('${domainName}')">${truncate(domainName, 30)}</a></td>
                <td><span class="badge ${badgeClass}">${riskLevel}</span></td>
                <td><span class="score ${scoreClass}">${(scan.risk_score || 0).toFixed(1)}</span></td>
                <td><span class="timestamp">${date}</span></td>
            </tr>
        `;
    }).join('');
}

// ===================================================================
// Domains
// ===================================================================
async function loadDomains(search = '') {
    try {
        let url = `${API_BASE}/api/domains`;
        if (search) url += `?search=${encodeURIComponent(search)}`;

        const resp = await fetch(url);
        const data = await resp.json();
        allDomains = data.data || [];
        currentDomainPage = 1;
        renderDomainTable();
    } catch (err) {
        console.error('Error loading domains:', err);
        document.getElementById('domainTableBody').innerHTML =
            '<tr><td colspan="5" class="empty-state"><p>Gagal memuat data domain</p></td></tr>';
    }
}

function renderDomainTable() {
    const tbody = document.getElementById('domainTableBody');
    const total = allDomains.length;
    const totalPages = Math.ceil(total / DOMAINS_PER_PAGE);
    const start = (currentDomainPage - 1) * DOMAINS_PER_PAGE;
    const end = start + DOMAINS_PER_PAGE;
    const pageData = allDomains.slice(start, end);

    if (total === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><p>Tidak ada domain ditemukan</p></td></tr>';
        document.getElementById('domainPagination').innerHTML = '';
        return;
    }

    tbody.innerHTML = pageData.map((d, i) => {
        const idx = start + i + 1;
        return `
            <tr class="fade-in">
                <td style="color: var(--text-tertiary)">${idx}</td>
                <td><a class="domain-link" onclick="openDomainDetail('${d.domain_name}')">${d.domain_name}</a></td>
                <td><span class="ip-cell">${d.ip_address || '-'}</span></td>
                <td><span class="badge ${d.is_active ? 'badge-safe' : 'badge-medium'}">${d.is_active ? 'Active' : 'Inactive'}</span></td>
                <td>
                    <button class="refresh-btn" style="padding: 4px 10px; font-size: 0.72rem;" onclick="openDomainDetail('${d.domain_name}')">
                        Detail
                    </button>
                </td>
            </tr>
        `;
    }).join('');

    // Pagination
    const pagDiv = document.getElementById('domainPagination');
    if (totalPages <= 1) {
        pagDiv.innerHTML = `<span class="page-info">Menampilkan ${total} domain</span>`;
        return;
    }

    pagDiv.innerHTML = `
        <button onclick="changeDomainPage(${currentDomainPage - 1})" ${currentDomainPage <= 1 ? 'disabled' : ''}>← Prev</button>
        <span class="page-info">Halaman ${currentDomainPage} dari ${totalPages} (${total} domain)</span>
        <button onclick="changeDomainPage(${currentDomainPage + 1})" ${currentDomainPage >= totalPages ? 'disabled' : ''}>Next →</button>
    `;
}

function changeDomainPage(page) {
    const totalPages = Math.ceil(allDomains.length / DOMAINS_PER_PAGE);
    if (page < 1 || page > totalPages) return;
    currentDomainPage = page;
    renderDomainTable();
}

function searchDomains() {
    clearTimeout(searchTimeout);
    const query = document.getElementById('domainSearch').value.trim();
    searchTimeout = setTimeout(() => loadDomains(query), 300);
}

// ===================================================================
// Vulnerabilities
// ===================================================================
async function loadVulnerabilities(severity = '') {
    try {
        let url = `${API_BASE}/api/vulnerabilities?limit=50`;
        if (severity) url += `&severity=${severity}`;

        const resp = await fetch(url);
        const data = await resp.json();
        allVulns = data.data || [];
        renderVulnList();
    } catch (err) {
        console.error('Error loading vulns:', err);
        document.getElementById('vulnList').innerHTML =
            '<div class="empty-state"><p>Gagal memuat kerentanan</p></div>';
    }
}

function renderVulnList() {
    const container = document.getElementById('vulnList');

    if (!allVulns || allVulns.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="icon">✅</div>
                <p>Tidak ada kerentanan ditemukan</p>
                <span class="hint">Jalankan pipeline scan terlebih dahulu</span>
            </div>
        `;
        return;
    }

    container.innerHTML = allVulns.map(v => {
        const severity = v.severity || 'LOW';
        const badgeClass = getBadgeClass(severity);
        const domainName = v.scan_history?.domains?.domain_name || '-';

        return `
            <div class="vuln-item fade-in">
                <div class="vuln-item-header">
                    <span class="badge ${badgeClass}">${severity}</span>
                    <span class="vuln-item-title">${escapeHtml(v.title || 'Untitled')}</span>
                </div>
                <div class="vuln-item-desc">
                    <strong style="color: var(--accent-blue);">${escapeHtml(domainName)}</strong>
                    ${v.check_type ? ` · ${escapeHtml(v.check_type)}` : ''}
                    ${v.description ? `<br>${escapeHtml(v.description)}` : ''}
                </div>
                ${v.recommendation ? `<div class="vuln-item-rec">💡 ${escapeHtml(v.recommendation)}</div>` : ''}
            </div>
        `;
    }).join('');
}

function filterVulns(btn, severity) {
    // Update active tab
    document.querySelectorAll('#vulnFilterTabs .tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    loadVulnerabilities(severity);
}

// ===================================================================
// Scan History
// ===================================================================
async function loadScanHistory() {
    try {
        const resp = await fetch(`${API_BASE}/api/scan-history?limit=20`);
        const data = await resp.json();
        renderScanHistory(data.data || []);
    } catch (err) {
        console.error('Error loading scan history:', err);
        document.getElementById('scanHistoryBody').innerHTML =
            '<tr><td colspan="4" class="empty-state"><p>Gagal memuat histori</p></td></tr>';
    }
}

function renderScanHistory(scans) {
    const tbody = document.getElementById('scanHistoryBody');

    if (!scans || scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state"><p>Belum ada histori scan</p><span class="hint">Jalankan main.py atau scheduler</span></td></tr>';
        return;
    }

    tbody.innerHTML = scans.map(scan => {
        const domainName = scan.domains?.domain_name || '-';
        const riskLevel = scan.risk_level || 'SAFE';
        const badgeClass = getBadgeClass(riskLevel);
        const scoreClass = getScoreClass(scan.risk_score);
        const date = formatDate(scan.scan_date);

        return `
            <tr class="fade-in">
                <td><a class="domain-link" onclick="openDomainDetail('${domainName}')">${truncate(domainName, 28)}</a></td>
                <td><span class="badge ${badgeClass}">${riskLevel}</span></td>
                <td><span class="score ${scoreClass}">${(scan.risk_score || 0).toFixed(1)}</span></td>
                <td><span class="timestamp">${date}</span></td>
            </tr>
        `;
    }).join('');
}

// ===================================================================
// Domain Detail Modal
// ===================================================================
async function openDomainDetail(domainName) {
    const overlay = document.getElementById('modalOverlay');
    const title = document.getElementById('modalTitle');
    const body = document.getElementById('modalBody');

    title.textContent = domainName;
    body.innerHTML = '<div class="empty-state"><p>Memuat detail...</p></div>';
    overlay.classList.add('active');
    document.body.style.overflow = 'hidden';

    try {
        const resp = await fetch(`${API_BASE}/api/domains/${encodeURIComponent(domainName)}/detail`);

        if (!resp.ok) {
            body.innerHTML = `<div class="empty-state"><p>Domain tidak ditemukan (${resp.status})</p></div>`;
            return;
        }

        const data = await resp.json();
        renderDomainModal(data);
    } catch (err) {
        body.innerHTML = `<div class="empty-state"><p>Gagal memuat detail: ${escapeHtml(err.message)}</p></div>`;
    }
}

function renderDomainModal(data) {
    const body = document.getElementById('modalBody');
    const domain = data.domain || {};
    const scans = data.scans || [];
    const latestScan = scans[0] || {};

    const ports = latestScan.open_ports || [];
    const tech = latestScan.technologies || {};
    const vulns = latestScan.vulnerabilities || [];
    const riskLevel = latestScan.risk_level || 'SAFE';
    const riskScore = latestScan.risk_score || 0;

    let html = '';

    // Domain Info
    html += `
        <div class="modal-section">
            <h3 class="modal-section-title">🌐 Informasi Domain</h3>
            <div class="modal-info-grid">
                <div class="modal-info-item">
                    <div class="modal-info-label">Domain</div>
                    <div class="modal-info-value" style="color: var(--accent-cyan);">${escapeHtml(domain.domain_name || '-')}</div>
                </div>
                <div class="modal-info-item">
                    <div class="modal-info-label">IP Address</div>
                    <div class="modal-info-value">${escapeHtml(domain.ip_address || '-')}</div>
                </div>
                <div class="modal-info-item">
                    <div class="modal-info-label">Risk Level</div>
                    <div class="modal-info-value"><span class="badge ${getBadgeClass(riskLevel)}">${riskLevel}</span></div>
                </div>
                <div class="modal-info-item">
                    <div class="modal-info-label">Risk Score</div>
                    <div class="modal-info-value"><span class="score ${getScoreClass(riskScore)}">${riskScore.toFixed(1)}</span> / 10.0</div>
                </div>
            </div>
        </div>
    `;

    // Open Ports
    html += `
        <div class="modal-section">
            <h3 class="modal-section-title">🔌 Port Terbuka (${ports.length})</h3>
            ${ports.length > 0 ? `
                <div class="port-chips">
                    ${ports.map(p => `
                        <div class="port-chip">
                            <span class="port-number">${p.port_number || p.port}</span>
                            <span class="port-service">${escapeHtml(p.service_name || p.service || '')}</span>
                        </div>
                    `).join('')}
                </div>
            ` : '<div style="color: var(--text-tertiary); font-size: 0.85rem;">Tidak ada port terbuka terdeteksi</div>'}
        </div>
    `;

    // Technologies
    const techEntries = Object.entries(tech).filter(([k, v]) => v && v !== 'Unknown' && !Array.isArray(v));
    html += `
        <div class="modal-section">
            <h3 class="modal-section-title">🛠️ Teknologi Terdeteksi</h3>
            ${techEntries.length > 0 ? `
                <div class="modal-info-grid">
                    ${techEntries.map(([key, value]) => `
                        <div class="modal-info-item">
                            <div class="modal-info-label">${formatTechKey(key)}</div>
                            <div class="modal-info-value" style="font-size: 0.85rem;">${escapeHtml(String(value))}</div>
                        </div>
                    `).join('')}
                </div>
            ` : '<div style="color: var(--text-tertiary); font-size: 0.85rem;">Belum ada data teknologi</div>'}
        </div>
    `;

    // Vulnerabilities
    html += `
        <div class="modal-section">
            <h3 class="modal-section-title">⚡ Kerentanan (${vulns.length})</h3>
            ${vulns.length > 0 ? `
                <div class="vuln-list" style="max-height: 300px;">
                    ${vulns.map(v => `
                        <div class="vuln-item">
                            <div class="vuln-item-header">
                                <span class="badge ${getBadgeClass(v.severity)}">${v.severity || 'LOW'}</span>
                                <span class="vuln-item-title">${escapeHtml(v.title || '')}</span>
                            </div>
                            ${v.description ? `<div class="vuln-item-desc">${escapeHtml(v.description)}</div>` : ''}
                            ${v.recommendation ? `<div class="vuln-item-rec">💡 ${escapeHtml(v.recommendation)}</div>` : ''}
                        </div>
                    `).join('')}
                </div>
            ` : '<div style="color: var(--text-tertiary); font-size: 0.85rem;">Tidak ada kerentanan ditemukan ✅</div>'}
        </div>
    `;

    // Scan History
    if (scans.length > 1) {
        html += `
            <div class="modal-section">
                <h3 class="modal-section-title">📋 Histori Scan (${scans.length})</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Tanggal</th>
                                <th>Risk Level</th>
                                <th>Score</th>
                                <th>Ports</th>
                                <th>Vulns</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${scans.map(s => `
                                <tr>
                                    <td><span class="timestamp">${formatDate(s.scan_date)}</span></td>
                                    <td><span class="badge ${getBadgeClass(s.risk_level)}">${s.risk_level || 'SAFE'}</span></td>
                                    <td><span class="score ${getScoreClass(s.risk_score)}">${(s.risk_score || 0).toFixed(1)}</span></td>
                                    <td>${(s.open_ports || []).length}</td>
                                    <td>${(s.vulnerabilities || []).length}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    body.innerHTML = html;
}

function closeModal() {
    document.getElementById('modalOverlay').classList.remove('active');
    document.body.style.overflow = '';
}

function closeModalOutside(event) {
    if (event.target === document.getElementById('modalOverlay')) {
        closeModal();
    }
}

// Keyboard shortcut
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});

// ===================================================================
// Utility Functions
// ===================================================================
function getBadgeClass(level) {
    const map = {
        'CRITICAL': 'badge-critical',
        'HIGH': 'badge-high',
        'MEDIUM': 'badge-medium',
        'LOW': 'badge-low',
        'SAFE': 'badge-safe',
        'INFO': 'badge-info'
    };
    return map[(level || '').toUpperCase()] || 'badge-safe';
}

function getScoreClass(score) {
    if (score >= 8) return 'critical';
    if (score >= 6) return 'high';
    if (score >= 4) return 'medium';
    if (score > 0) return 'low';
    return 'safe';
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    try {
        const d = new Date(dateStr);
        if (isNaN(d.getTime())) return dateStr;
        return d.toLocaleDateString('id-ID', {
            day: '2-digit',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch {
        return dateStr;
    }
}

function truncate(str, maxLen) {
    if (!str) return '-';
    return str.length > maxLen ? str.substring(0, maxLen) + '...' : str;
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatTechKey(key) {
    return key
        .replace(/_/g, ' ')
        .replace(/\b\w/g, c => c.toUpperCase());
}

// ===================================================================
// Auto-refresh every 60 seconds
// ===================================================================
setInterval(() => {
    refreshAll();
}, 60000);
