/**
 * JAGAWEB — Security Dashboard App.js
 */

const API_BASE = window.location.origin;

// State
let allDomains = [];
let allVulns = [];
let currentDomainData = null;

document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupTabs();
    
    const openBtn = document.getElementById('openCreateUserModalBtn');
    if (openBtn) {
        openBtn.addEventListener('click', openCreateUserModal);
    }
    const closeBtn = document.getElementById('closeCreateUserModalBtn');
    if (closeBtn) {
        closeBtn.addEventListener('click', closeCreateUserModal);
    }
    const createForm = document.getElementById('createUserForm');
    if (createForm) {
        createForm.addEventListener('submit', handleCreateUserSubmit);
    }
});

// ==========================================================================
// Navigation & Views
// ==========================================================================
function switchView(viewId) {
    // Hide all views
    document.querySelectorAll('.view-container').forEach(v => {
        v.classList.add('hidden');
        v.classList.remove('active');
        v.style.display = 'none';
    });
    
    // Deactivate nav items
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    
    // Which view to show?
    let targetView = `view-${viewId}`;
    if (!document.getElementById(targetView)) {
        if (viewId === 'dashboard') targetView = 'view-overview';
        else if (viewId === 'overview') targetView = 'view-overview';
        else if (viewId === 'targets' || viewId === 'inventory') targetView = 'view-inventory';
        else if (viewId === 'vulnerabilities') targetView = 'view-vulnerabilities';
        else if (viewId === 'admin') targetView = 'view-admin';
        else targetView = 'view-overview';
    }
    
    // Activate view
    const viewEl = document.getElementById(targetView);
    if (viewEl) {
        viewEl.classList.remove('hidden');
        viewEl.classList.add('active');
        viewEl.style.display = 'block';
    }
    
    // Activate nav dynamically
    document.querySelectorAll('.sidebar-nav .nav-item').forEach(n => {
        if (n.getAttribute('onclick') && n.getAttribute('onclick').includes(`'${viewId}'`)) {
            n.classList.add('active');
        }
    });

    // Load admin data if switching to admin page
    if (viewId === 'admin') {
        loadAdminUsers();
    }
}

// ==========================================================================
// Data Fetching
// ==========================================================================
async function refreshData() {

    try {
        await checkHealth();
        await Promise.all([
            loadOverview(),
            loadVulnerabilities(),
            loadDomains()
        ]);
    } catch (err) {
        console.error('Refresh error:', err);
    }
}

async function checkHealth() {
    try {
        const resp = await fetch(`${API_BASE}/api/health`);
        const data = await resp.json();
        if (!data.database.connected) {
            console.warn('API is in Local Mode');
        }
    } catch (err) {
        console.error('API Error:', err);
    }
}

// ==========================================================================
// Overview (Dashboard Stats & Chart)
// ==========================================================================
let vulnChartInstance = null;
let sevChartInstance = null;

async function loadOverview() {
    try {
        const [statsResp, trendResp, sevTrendResp] = await Promise.all([
            fetch(`${API_BASE}/api/dashboard-stats`),
            fetch(`${API_BASE}/api/trend-stats`),
            fetch(`${API_BASE}/api/severity-trend-stats`)
        ]);
        
        const statsData = await statsResp.json();
        const trendData = await trendResp.json();
        const sevTrendData = await sevTrendResp.json();
        
        // Update summary cards
        document.getElementById('overviewTotalDomains').textContent = statsData.total_domains || 0;
        document.getElementById('overviewTotalVulns').textContent = statsData.total_vulnerabilities || 0;
        
        const vulnCtx = document.getElementById('vulnBarChart').getContext('2d');
        const sevCtx = document.getElementById('sevTrendChart').getContext('2d');
        
        if (vulnChartInstance) vulnChartInstance.destroy();
        if (sevChartInstance) sevChartInstance.destroy();
        
        // --- 1. Domain Vulnerability Trend ---
        const domainColors = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#22c55e', '#8b5cf6', '#ec4899', '#14b8a6'];
        const domainDatasets = (trendData.datasets || []).map((ds, idx) => ({
            label: ds.label,
            data: ds.data,
            borderColor: domainColors[idx % domainColors.length],
            backgroundColor: domainColors[idx % domainColors.length],
            borderWidth: 2,
            tension: 0.3,
            spanGaps: true,
            pointRadius: ds.data.map(v => v > 0 ? 4 : 0),
            pointHoverRadius: 6
        }));
        
        vulnChartInstance = new Chart(vulnCtx, {
            type: 'line',
            data: {
                labels: trendData.labels || [],
                datasets: domainDatasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0 }
                    },
                    x: {
                        ticks: { maxTicksLimit: 12 }
                    }
                },
                plugins: {
                    legend: { display: true, position: 'bottom' },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            label: function(context) {
                                let label = context.dataset.label || '';
                                if (label) label += ' | Vulns: ';
                                if (context.parsed.y !== null) label += context.parsed.y;
                                return label;
                            }
                        }
                    }
                }
            }
        });

        // --- 2. Severity Trend ---
        const sevColors = {
            'Critical': '#ef4444',
            'High': '#f97316',
            'Medium': '#eab308'
        };
        
        const sevDatasets = (sevTrendData.datasets || []).map((ds, idx) => {
            const color = sevColors[ds.label] || '#9ca3af';
            return {
                label: ds.label,
                data: ds.data,
                borderColor: color,
                backgroundColor: color,
                borderWidth: 2,
                tension: 0.3,
                spanGaps: true,
                pointRadius: ds.data.map(v => v > 0 ? 4 : 0),
                pointHoverRadius: 6
            };
        });
        
        sevChartInstance = new Chart(sevCtx, {
            type: 'line',
            data: {
                labels: sevTrendData.labels || [],
                datasets: sevDatasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0 }
                    },
                    x: {
                        ticks: { maxTicksLimit: 12 }
                    }
                },
                plugins: {
                    legend: { display: true, position: 'bottom' },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            label: function(context) {
                                let label = context.dataset.label || '';
                                if (label) label += ': ';
                                if (context.parsed.y !== null) label += context.parsed.y;
                                return label;
                            }
                        }
                    }
                }
            }
        });

    } catch (err) {
        console.error('Error loading overview:', err);
    }
}

// ==========================================================================
// Automated Pentests (Vulnerabilities View)
// ==========================================================================
async function loadVulnerabilities() {
    try {
        const resp = await fetch(`${API_BASE}/api/scan-history?limit=100`);
        const data = await resp.json();
        allVulns = data.data || [];
        renderVulnerabilitiesList();
    } catch (err) {
        console.error('Error loading scans:', err);
    }
}

function renderVulnerabilitiesList() {
    const container = document.getElementById('vulnListContainer');
    if (!allVulns || allVulns.length === 0) {
        container.innerHTML = `<div class="empty-state">No scan history found.</div>`;
        return;
    }
    
    container.innerHTML = allVulns.map((scan, i) => {
        const domainName = scan.domains?.domain_name || 'Unknown Target';
        const riskLevel = scan.risk_level || 'SAFE';
        const sevClass = getSeverityClass(riskLevel);
        const date = formatDate(scan.scan_date);
        const numVulns = scan.vulnerabilities ? scan.vulnerabilities.length : 0;
        
        return `
            <div class="vuln-row" onclick="openScanModalIndex(${i})">
                <div class="vuln-id">SCAN-${String(scan.id || i+1).padStart(4, '0')}</div>
                <div class="vuln-title">Automated Scan on ${escapeHtml(domainName)}</div>
                <div class="vuln-path">${date}</div>
                <div class="vuln-score ${sevClass}">Vulns: ${numVulns}</div>
                <button class="icon-btn vuln-action">⋮</button>
            </div>
        `;
    }).join('');
}

// Function helper untuk membuka modal dari index
function openScanModalIndex(index) {
    const scan = allVulns[index];
    if (scan) {
        openScanModal(scan);
    }
}

// ==========================================================================
// Inventory (Domains)
// ==========================================================================
async function loadDomains() {
    try {
        const resp = await fetch(`${API_BASE}/api/domains`);
        const data = await resp.json();
        allDomains = data.data || [];
        renderInventoryList();
    } catch (err) {
        console.error('Error loading domains:', err);
    }
}

function renderInventoryList() {
    const tbody = document.getElementById('inventoryTableBody');
    if (!allDomains || allDomains.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" class="empty-state">No domains found.</td></tr>`;
        return;
    }
    
    // Filtering logic
    const searchVal = (document.getElementById('domainSearchInput')?.value || '').toLowerCase();
    const filtered = allDomains.filter(d => 
        (d.domain_name || '').toLowerCase().includes(searchVal) ||
        (d.ip_address || '').toLowerCase().includes(searchVal)
    );
    
    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" class="empty-state">No domains match your search.</td></tr>`;
        return;
    }
    
    tbody.innerHTML = filtered.map(d => `
        <tr>
            <td style="font-weight:500; color:var(--primary)">${escapeHtml(d.domain_name)}</td>
            <td style="font-family:var(--font-mono); color:var(--text-secondary)">${escapeHtml(d.ip_address || '-')}</td>
            <td><span class="badge ${d.is_active ? 'badge-safe' : 'badge-medium'}">${d.is_active ? 'ACTIVE' : 'INACTIVE'}</span></td>
        </tr>
    `).join('');
}

document.addEventListener('DOMContentLoaded', () => {
    // Other init code is at the top of app.js. Adding search listener here.
    const searchInput = document.getElementById('domainSearchInput');
    if (searchInput) {
        searchInput.addEventListener('input', renderInventoryList);
    }
});

// Tabs Logic
function setupTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            // Remove active from all tabs
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            // Add active to clicked tab
            e.target.classList.add('active');
            const targetId = e.target.getAttribute('data-target');
            document.getElementById(targetId).classList.add('active');
        });
    });
}

// ==========================================================================
// Threat Modal
// ==========================================================================
function openThreatModal(vuln) {
    document.getElementById('threatModalOverlay').classList.add('active');
    
    document.getElementById('modalTitle').textContent = vuln.title || 'Vulnerability Alert';
    document.getElementById('modalRuleId').textContent = vuln.check_type || 'Unknown Scanner';
    document.getElementById('modalSeverity').textContent = vuln.severity || 'LOW';
    document.getElementById('modalSeverity').className = `meta-value text-${getSeverityClass(vuln.severity)}`;
    
    document.getElementById('modalDesc').textContent = vuln.description || 'No description available.';
    document.getElementById('modalRecommendation').textContent = vuln.recommendation || 'No recommendation provided.';
    
    // Mock data for evidence logs based on vuln
    const now = new Date().toISOString();
    document.getElementById('modalFirstSeen').textContent = formatDate(now);
    document.getElementById('modalLastSeen').textContent = formatDate(now);
    
    document.getElementById('modalLogTime').textContent = formatDate(now);
    document.getElementById('modalLogHost').textContent = currentDomainData?.domain?.domain_name || 'host';
    document.getElementById('modalLogMsg').textContent = `Matched signature: ${vuln.title}`;
}

function closeThreatModal() {
    document.getElementById('threatModalOverlay').classList.remove('active');
}

// ==========================================================================
// Scan Modal
// ==========================================================================
let currentScanVulns = [];
let currentScanVulnsFilter = 'All';

const SEV_ORDER = {
    'CRITICAL': 1,
    'HIGH': 2,
    'MEDIUM': 3,
    'LOW': 4,
    'INFO': 5,
    'SAFE': 6
};

function openScanModal(scan) {
    document.getElementById('scanModalOverlay').classList.add('active');
    
    document.getElementById('scanModalDomain').textContent = scan.domains?.domain_name || '-';
    document.getElementById('scanModalIp').textContent = scan.domains?.ip_address || '-';
    document.getElementById('scanModalDate').textContent = formatDate(scan.scan_date);
    document.getElementById('scanModalRisk').textContent = scan.risk_level || 'SAFE';
    document.getElementById('scanModalRisk').className = `meta-value text-${getSeverityClass(scan.risk_level)}`;
    
    currentScanVulnsFilter = 'All';
    currentScanVulns = (scan.vulnerabilities || []).slice(); // copy
    
    // Default Sort: High to Low severity
    currentScanVulns.sort((a, b) => {
        const orderA = SEV_ORDER[(a.severity || '').toUpperCase()] || 99;
        const orderB = SEV_ORDER[(b.severity || '').toUpperCase()] || 99;
        return orderA - orderB;
    });
    
    renderScanFilters();
    renderScanVulnsTable();
}

function setScanFilter(sev) {
    currentScanVulnsFilter = sev;
    renderScanFilters();
    renderScanVulnsTable();
}

function renderScanFilters() {
    const filtersContainer = document.getElementById('scanModalFilters');
    
    const counts = {
        'All': currentScanVulns.length,
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Info': 0
    };
    
    currentScanVulns.forEach(v => {
        const s = (v.severity || '').toLowerCase();
        if (s === 'critical') counts['Critical']++;
        else if (s === 'high') counts['High']++;
        else if (s === 'medium') counts['Medium']++;
        else if (s === 'low') counts['Low']++;
        else if (s === 'info') counts['Info']++;
    });
    
    const filterOptions = [
        { label: 'All', key: 'All', color: '', initial: '' },
        { label: 'Critical', key: 'Critical', color: 'var(--sev-critical)', initial: 'C' },
        { label: 'High', key: 'High', color: 'var(--sev-high)', initial: 'H' },
        { label: 'Medium', key: 'Medium', color: 'var(--sev-medium)', initial: 'M' },
        { label: 'Low', key: 'Low', color: 'var(--sev-low)', initial: 'L' },
        { label: 'Info', key: 'Info', color: 'var(--sev-info)', initial: 'I' }
    ];
    
    filtersContainer.innerHTML = filterOptions.map(f => {
        const isActive = currentScanVulnsFilter === f.key ? 'active' : '';
        const dot = f.initial ? `<span class="filter-dot" style="background:${f.color}">${f.initial}</span>` : '';
        return `<button class="filter-btn ${isActive}" onclick="setScanFilter('${f.key}')">
                    ${dot} ${f.label} (${counts[f.key]})
                </button>`;
    }).join('');
}

function renderScanVulnsTable() {
    const tbody = document.getElementById('scanModalVulnBody');
    
    let filtered = currentScanVulns;
    if (currentScanVulnsFilter !== 'All') {
        filtered = currentScanVulns.filter(v => (v.severity || '').toLowerCase() === currentScanVulnsFilter.toLowerCase());
    }
    
    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No vulnerabilities found for this filter.</td></tr>`;
        return;
    }
    
    tbody.innerHTML = filtered.map(v => {
        const sevClass = getSeverityClass(v.severity);
        return `
            <tr>
                <td><span class="badge badge-${sevClass}">${v.severity}</span></td>
                <td style="font-weight:500">${escapeHtml(v.title)}</td>
                <td style="font-family:var(--font-mono); font-size:12px;">${escapeHtml(v.check_type || '-')}</td>
                <td><button class="btn btn-outline btn-sm" onclick='openThreatModal(${JSON.stringify(v).replace(/'/g, "&#39;")})'>Inspect</button></td>
            </tr>
        `;
    }).join('');
}

function closeScanModal() {
    document.getElementById('scanModalOverlay').classList.remove('active');
}

// ==========================================================================
// Helpers
// ==========================================================================
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    try {
        const d = new Date(dateStr);
        if (isNaN(d.getTime())) return dateStr;
        return d.toLocaleString('en-GB', {
            month: 'short', day: '2-digit', year: 'numeric',
            hour: '2-digit', minute: '2-digit', hour12: false
        }).replace(',', '') + ' WIB';
    } catch {
        return dateStr;
    }
}

function getSeverityClass(sev) {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL') return 'critical';
    if (s === 'HIGH') return 'high';
    if (s === 'MEDIUM') return 'medium';
    if (s === 'LOW') return 'low';
    if (s === 'INFO') return 'info';
    return 'safe';
}

function getMockCVSS(sev) {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL') return '9.8';
    if (s === 'HIGH') return '7.5';
    if (s === 'MEDIUM') return '5.0';
    if (s === 'LOW') return '2.5';
    return '0.0';
}

// ==========================================================================
// Authentication & Session Management (Admin Restricted Registration)
// ==========================================================================
let wsLive = null;
let currentUser = null;
let allNotifications = JSON.parse(localStorage.getItem('dsti_notifs') || '[]');

async function checkAuth() {
    try {
        const resp = await fetch(`${API_BASE}/api/auth/me`);
        if (resp.status === 200) {
            const user = await resp.json();
            handleSuccessfulLogin(user);
        } else {
            showLoginOverlay();
        }
    } catch (err) {
        console.error("Gagal memeriksa status auth:", err);
        showLoginOverlay();
    }
}

function showLoginOverlay() {
    document.getElementById('authOverlay').classList.remove('hidden');
    document.getElementById('sidebar-user-container').style.display = 'none';
    document.getElementById('nav-admin').style.display = 'none';
    document.getElementById('mainHeader').style.display = 'none';
    document.getElementById('notifWrapper').style.display = 'none';
    
    if (wsLive) {
        wsLive.close();
        wsLive = null;
    }
}

function handleSuccessfulLogin(user) {
    currentUser = user;
    document.getElementById('authOverlay').classList.add('hidden');
    
    // Show Main Header
    document.getElementById('mainHeader').style.display = 'flex';
    
    // Setup Sidebar User Info
    document.getElementById('sidebar-user-container').style.display = 'flex';
    document.getElementById('sidebar-username').textContent = user.username;
    
    const roleEl = document.getElementById('sidebar-user-role');
    if (user.role === 'admin') {
        roleEl.innerHTML = `<span class="badge-admin-role">Admin</span>`;
        document.getElementById('nav-admin').style.display = 'block';
        document.getElementById('notifWrapper').style.display = 'block';
        
        renderNotificationList();
    } else {
        roleEl.innerHTML = `<span class="badge-user-role">User</span>`;
        document.getElementById('nav-admin').style.display = 'none';
        document.getElementById('notifWrapper').style.display = 'none';
        
        // If regular user was on admin tab, redirect to overview
        const activeNav = document.querySelector('.sidebar-nav .nav-item.active');
        if (activeNav && activeNav.getAttribute('onclick').includes('admin')) {
            switchView('overview');
        }
    }
    
    // Hubungkan WebSocket Live Session untuk semua user (baik admin maupun user biasa)
    connectLiveWebSocket(user.session_id);
    
    // Clean inputs
    document.getElementById('authUsername').value = '';
    document.getElementById('authPassword').value = '';
    document.getElementById('authErrorMsg').style.display = 'none';
    
    refreshData();
}

async function handleAuthSubmit(e) {
    e.preventDefault();
    const username = document.getElementById('authUsername').value.trim();
    const password = document.getElementById('authPassword').value;
    const errMsg = document.getElementById('authErrorMsg');
    
    errMsg.style.display = 'none';
    
    try {
        const resp = await fetch(`${API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await resp.json();
        
        if (resp.status === 200) {
            showToast("Selamat Datang", `Berhasil masuk sebagai ${data.username}!`, "🔑");
            handleSuccessfulLogin(data);
        } else {
            errMsg.textContent = data.detail || "Username atau password salah.";
            errMsg.style.display = 'block';
        }
    } catch (err) {
        errMsg.textContent = "Koneksi ke server gagal.";
        errMsg.style.display = 'block';
    }
}

async function handleLogout() {
    try {
        await fetch(`${API_BASE}/api/auth/logout`, { method: 'POST' });
    } catch (err) {
        console.error("Gagal mengirim request logout:", err);
    }
    showToast("Logout", "Anda berhasil keluar.", "👋");
    showLoginOverlay();
}

// Interceptor global untuk response 401
const originalFetch = window.fetch;
window.fetch = async function(...args) {
    const response = await originalFetch(...args);
    if (response.status === 401 && !args[0].includes('/api/auth/me') && !args[0].includes('/api/auth/login')) {
        showLoginOverlay();
        showToast("Sesi Berakhir", "Sesi Anda telah berakhir. Silakan masuk kembali.", "⚠️");
    }
    return response;
};

// ==========================================================================
// Admin Panel: User Creation Modal & CRUD Handlers
// ==========================================================================
function openCreateUserModal() {
    console.log("[Debug] openCreateUserModal called.");
    const overlay = document.getElementById('createUserModalOverlay');
    if (!overlay) {
        console.error("[Debug] Element #createUserModalOverlay not found!");
        return;
    }
    overlay.classList.add('active');
    console.log("[Debug] added 'active' to #createUserModalOverlay. Class list is now:", overlay.className);
    
    const errorMsg = document.getElementById('createUserErrorMsg');
    if (errorMsg) {
        errorMsg.style.display = 'none';
    } else {
        console.warn("[Debug] Element #createUserErrorMsg not found.");
    }
}

function closeCreateUserModal() {
    document.getElementById('createUserModalOverlay').classList.remove('active');
    document.getElementById('createUsername').value = '';
    document.getElementById('createPassword').value = '';
    document.getElementById('createConfirmPassword').value = '';
}

async function handleCreateUserSubmit(e) {
    e.preventDefault();
    const username = document.getElementById('createUsername').value.trim();
    const password = document.getElementById('createPassword').value;
    const confirmPassword = document.getElementById('createConfirmPassword').value;
    const role = "user";
    const errMsg = document.getElementById('createUserErrorMsg');
    
    errMsg.style.display = 'none';
    
    // Validasi kecocokan password
    if (password !== confirmPassword) {
        errMsg.textContent = "Konfirmasi password tidak sesuai!";
        errMsg.style.display = 'block';
        return;
    }
    
    try {
        const resp = await fetch(`${API_BASE}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, role })
        });
        const data = await resp.json();
        
        if (resp.status === 200) {
            showToast("Sukses", `User baru '${username}' berhasil didaftarkan.`, "✨");
            closeCreateUserModal();
            loadAdminUsers(); // Refresh daftar user
        } else {
            errMsg.textContent = data.detail || "Gagal membuat user baru.";
            errMsg.style.display = 'block';
        }
    } catch (err) {
        errMsg.textContent = "Gagal menghubungi server.";
        errMsg.style.display = 'block';
    }
}

// ==========================================================================
// Admin Panel: User Table List & Control Actions
// ==========================================================================
async function loadAdminUsers() {
    const tbody = document.getElementById('userTableBody');
    try {
        const resp = await fetch(`${API_BASE}/api/admin/users`);
        const result = await resp.json();
        
        if (resp.status === 200) {
            renderUserTable(result.data);
        } else {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state text-danger">${result.detail || 'Gagal memuat daftar user.'}</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state text-danger">Gagal menghubungi server.</td></tr>`;
    }
}

function renderUserTable(users) {
    const tbody = document.getElementById('userTableBody');
    if (!users || users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Tidak ada user terdaftar.</td></tr>`;
        return;
    }
    
    tbody.innerHTML = users.map(u => {
        const isSelf = u.username === currentUser.username;
        const roleBadge = u.role === 'admin' 
            ? `<span class="badge-admin-role">Admin</span>` 
            : `<span class="badge-user-role">User</span>`;
            
        const isOnline = u.is_online;
        const statusBadge = isOnline
            ? `<span class="status-indicator status-online">Online</span>`
            : `<span class="status-indicator status-offline">Offline</span>`;
            
        const lastActiveText = u.is_online ? "Baru saja aktif" : formatRelativeTime(u.last_online);
        
        // Logika check timeout
        let isTimedOut = false;
        if (u.timeout_until) {
            const timeoutDate = new Date(u.timeout_until);
            if (timeoutDate > new Date()) {
                isTimedOut = true;
            }
        }
        
        let actionButtons = '';
        if (isSelf) {
            actionButtons = `<span style="color:var(--text-tertiary); font-style:italic;">Akun Anda</span>`;
        } else if (isTimedOut) {
            actionButtons = `
                <span class="text-timeout" style="margin-right: 12px;">Ditangguhkan (Timeout)</span>
                <button class="btn-timeout" style="border-color:#22c55e; color:#22c55e; margin-left:0;" onclick="triggerRemoveTimeout('${u.username}')">Cabut Timeout</button>
                <button class="btn-delete-user" onclick="triggerDeleteUser('${u.username}')">Hapus</button>
            `;
        } else {
            actionButtons = `
                <button class="btn-force-logout" onclick="triggerForceLogout('${u.username}')">Force Logout</button>
                <button class="btn-timeout" onclick="triggerTimeoutUser('${u.username}')">Timeout 2 Jam</button>
                <button class="btn-delete-user" onclick="triggerDeleteUser('${u.username}')">Hapus</button>
            `;
        }
        
        return `
            <tr>
                <td style="font-weight: 600; color: var(--text-primary);">${escapeHtml(u.username)}</td>
                <td>${roleBadge}</td>
                <td>${statusBadge}</td>
                <td>${lastActiveText}</td>
                <td>${actionButtons}</td>
            </tr>
        `;
    }).join('');
}

async function triggerForceLogout(username) {
    if (!confirm(`Apakah Anda yakin ingin melakukan Force Logout pada user '${username}'?`)) return;
    try {
        const resp = await fetch(`${API_BASE}/api/admin/users/${username}/force-logout`, {
            method: 'POST'
        });
        const data = await resp.json();
        if (resp.status === 200) {
            showToast("Force Logout", `User '${username}' telah berhasil dikeluarkan dari sistem.`, "🔴");
            loadAdminUsers();
        } else {
            alert(data.detail || "Gagal melakukan force logout.");
        }
    } catch (err) {
        alert("Gagal menghubungi server.");
    }
}

async function triggerTimeoutUser(username) {
    if (!confirm(`Apakah Anda yakin ingin menangguhkan (timeout) user '${username}' selama 2 jam?`)) return;
    try {
        const resp = await fetch(`${API_BASE}/api/admin/users/${username}/timeout`, {
            method: 'POST'
        });
        const data = await resp.json();
        if (resp.status === 200) {
            showToast("User Ditangguhkan", `User '${username}' ditangguhkan selama 2 jam.`, "⏳");
            loadAdminUsers();
        } else {
            alert(data.detail || "Gagal melakukan penangguhan.");
        }
    } catch (err) {
        alert("Gagal menghubungi server.");
    }
}

async function triggerRemoveTimeout(username) {
    if (!confirm(`Apakah Anda yakin ingin mencabut status penangguhan (timeout) user '${username}'?`)) return;
    try {
        const resp = await fetch(`${API_BASE}/api/admin/users/${username}/remove-timeout`, {
            method: 'POST'
        });
        const data = await resp.json();
        if (resp.status === 200) {
            showToast("Timeout Dicabut", `Penangguhan untuk user '${username}' berhasil dicabut!`, "💚");
            loadAdminUsers();
        } else {
            alert(data.detail || "Gagal mencabut status timeout.");
        }
    } catch (err) {
        alert("Gagal menghubungi server.");
    }
}

async function triggerDeleteUser(username) {
    if (!confirm(`Apakah Anda yakin ingin menghapus user '${username}' secara permanen? Akun ini tidak akan bisa login kembali.`)) return;
    try {
        const resp = await fetch(`${API_BASE}/api/admin/users/${username}`, {
            method: 'DELETE'
        });
        const data = await resp.json();
        if (resp.status === 200) {
            showToast("Hapus User", `User '${username}' berhasil dihapus dari sistem.`, "🗑️");
            loadAdminUsers();
        } else {
            alert(data.detail || "Gagal menghapus user.");
        }
    } catch (err) {
        alert("Gagal menghubungi server.");
    }
}

function formatRelativeTime(dateStr) {
    if (!dateStr) return 'Belum pernah aktif';
    try {
        const d = new Date(dateStr);
        if (isNaN(d.getTime())) return '-';
        const now = new Date();
        const diffMs = now - d;
        const diffMins = Math.floor(diffMs / 60000);
        
        if (diffMins < 1) return 'Baru saja aktif';
        if (diffMins < 60) return `${diffMins} menit yang lalu`;
        
        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours} jam yang lalu`;
        
        return d.toLocaleDateString('id-ID', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
    } catch {
        return '-';
    }
}

// ==========================================================================
// YouTube-Style Notification Dropdown Logic & Rendering
// ==========================================================================
function toggleNotificationDropdown(e) {
    if (e) e.stopPropagation();
    const dropdown = document.getElementById('notificationDropdown');
    const isHidden = dropdown.style.display === 'none';
    
    if (isHidden) {
        dropdown.style.display = 'flex';
        clearBadge();
    } else {
        dropdown.style.display = 'none';
    }
}

document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('notificationDropdown');
    const bellBtn = document.getElementById('notificationBellBtn');
    if (dropdown && dropdown.style.display !== 'none') {
        if (!dropdown.contains(e.target) && !bellBtn.contains(e.target)) {
            dropdown.style.display = 'none';
        }
    }
});

function updateNotificationBadge() {
    const badge = document.getElementById('notificationBadge');
    const unreadCount = allNotifications.filter(n => n.unread).length;
    
    if (unreadCount > 0) {
        badge.textContent = unreadCount;
        badge.style.display = 'flex';
    } else {
        badge.style.display = 'none';
    }
}

function clearBadge() {
    const badge = document.getElementById('notificationBadge');
    badge.style.display = 'none';
}

function markAllNotificationsAsRead(e) {
    if (e) e.stopPropagation();
    allNotifications.forEach(n => n.unread = false);
    localStorage.setItem('dsti_notifs', JSON.stringify(allNotifications));
    renderNotificationList();
    showToast("Notifikasi", "Semua notifikasi ditandai telah dibaca.", "✔️");
}

function deleteNotification(notifId, e) {
    if (e) e.stopPropagation();
    allNotifications = allNotifications.filter(n => n.id !== notifId);
    localStorage.setItem('dsti_notifs', JSON.stringify(allNotifications));
    renderNotificationList();
}

function renderNotificationList() {
    const listContainer = document.getElementById('notificationList');
    if (!listContainer) return;
    
    updateNotificationBadge();
    
    if (allNotifications.length === 0) {
        listContainer.innerHTML = `<div class="notif-empty-state">Tidak ada notifikasi</div>`;
        return;
    }
    
    listContainer.innerHTML = allNotifications.map(n => {
        const initials = (n.username || 'U').substring(0, 2).toUpperCase();
        const roleText = n.role === 'admin' ? 'Admin' : 'User';
        const unreadClass = n.unread ? 'unread' : '';
        const relativeTime = formatRelativeTime(n.timestamp);
        
        return `
            <div class="notif-item ${unreadClass}" onclick="markAsRead('${n.id}')">
                <div class="notif-unread-dot"></div>
                <div class="notif-avatar">${initials}</div>
                <div class="notif-content">
                    <div class="notif-text">👤 <strong>${escapeHtml(n.username)}</strong> (${roleText}) baru saja masuk ke sistem.</div>
                    <div class="notif-time">${relativeTime}</div>
                </div>
                <div class="notif-actions">
                    <button class="notif-action-btn" onclick="deleteNotification('${n.id}', event)" title="Hapus notifikasi">✕</button>
                </div>
            </div>
        `;
    }).join('');
}

function markAsRead(notifId) {
    const notif = allNotifications.find(n => n.id === notifId);
    if (notif && notif.unread) {
        notif.unread = false;
        localStorage.setItem('dsti_notifs', JSON.stringify(allNotifications));
        renderNotificationList();
    }
}

// ==========================================================================
// WebSockets Client
// ==========================================================================
function connectLiveWebSocket(sessionId) {
    if (wsLive) {
        wsLive.close();
    }
    
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProto}//${window.location.host}/ws/live?session_id=${sessionId}`;
    
    wsLive = new WebSocket(wsUrl);
    
    wsLive.onopen = () => {
        console.log("[WebSocket] Terkoneksi ke Live Session.");
    };
    
    wsLive.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            
            if (data.event === 'user_login') {
                // Notifikasi admin tentang user login baru
                if (currentUser && currentUser.role === 'admin') {
                    showToast(
                        "User Login Baru", 
                        `👤 <b>${escapeHtml(data.username)}</b> (${data.role === 'admin' ? 'Admin' : 'User'}) baru saja masuk ke sistem pada pukul ${data.time}.`,
                        "🔔"
                    );
                    
                    const notif = {
                        id: 'notif_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9),
                        username: data.username,
                        role: data.role,
                        time: data.time,
                        timestamp: new Date().toISOString(),
                        unread: true
                    };
                    allNotifications.unshift(notif);
                    localStorage.setItem('dsti_notifs', JSON.stringify(allNotifications));
                    renderNotificationList();
                    
                    const activeNav = document.querySelector('.sidebar-nav .nav-item.active');
                    if (activeNav && activeNav.getAttribute('onclick').includes('admin')) {
                        loadAdminUsers();
                    }
                }
            } else if (data.event === 'force_logout') {
                showToast("Sesi Diakhiri", "Anda telah dipaksa keluar oleh Administrator.", "⚠️");
                setTimeout(() => {
                    handleLogout();
                }, 1000);
            } else if (data.event === 'timeout') {
                showToast("Akun Ditangguhkan", "Akun Anda telah ditangguhkan selama 2 jam oleh Administrator.", "⏳");
                setTimeout(() => {
                    handleLogout();
                }, 1000);
            }
        } catch (e) {
            console.error("Gagal mem-parsing pesan websocket:", e);
        }
    };
    
    wsLive.onclose = (e) => {
        console.log("[WebSocket] Koneksi Live terputus. Kode:", e.code);
        // Lakukan reconnect otomatis jika masih login dan bukan kode tutup normal (4003)
        if (currentUser && e.code !== 4003 && e.code !== 4000) {
            setTimeout(() => {
                if (currentUser) {
                    connectLiveWebSocket(sessionId);
                }
            }, 5000);
        }
    };
}

function showToast(title, message, icon = "ℹ️") {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = 'toast-notification';
    
    toast.innerHTML = `
        <div class="toast-icon">${icon}</div>
        <div class="toast-body">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        </div>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 5000);
}