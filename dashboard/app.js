/**
 * JAGAWEB — Security Dashboard App.js
 */

const API_BASE = window.location.origin;

// State
let allDomains = [];
let allVulns = [];
let currentDomainData = null;

document.addEventListener('DOMContentLoaded', () => {
    refreshData();
    setupTabs();
});

// ==========================================================================
// Navigation & Views
// ==========================================================================
function switchView(viewId) {
    // Hide all views
    document.querySelectorAll('.view-container').forEach(v => v.classList.add('hidden'));
    document.querySelectorAll('.view-container').forEach(v => v.classList.remove('active'));
    
    // Deactivate nav items
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    
    // Which view to show?
    let targetView = `view-${viewId}`;
    if (!document.getElementById(targetView)) {
        // fallback or not implemented
        if (viewId === 'dashboard') targetView = 'view-overview'; // mapped for now
        else if (viewId === 'overview') targetView = 'view-overview';
        else if (viewId === 'targets' || viewId === 'inventory') targetView = 'view-inventory';
        else if (viewId === 'vulnerabilities') targetView = 'view-vulnerabilities';
        else targetView = 'view-overview';
    }
    
    // Activate view
    const viewEl = document.getElementById(targetView);
    if (viewEl) {
        viewEl.classList.remove('hidden');
        viewEl.classList.add('active');
    }
    
    // Activate nav
    const activeNavs = {
        'overview': 0,
        'vulnerabilities': 1,
        'inventory': 2
    };
    const navItems = document.querySelectorAll('.nav-item');
    if (navItems[activeNavs[viewId]]) {
        navItems[activeNavs[viewId]].classList.add('active');
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

async function loadOverview() {
    try {
        const [statsResp, trendResp] = await Promise.all([
            fetch(`${API_BASE}/api/dashboard-stats`),
            fetch(`${API_BASE}/api/trend-stats`)
        ]);
        
        const statsData = await statsResp.json();
        const trendData = await trendResp.json();
        
        // Update summary cards
        document.getElementById('overviewTotalDomains').textContent = statsData.total_domains || 0;
        document.getElementById('overviewTotalVulns').textContent = statsData.total_vulnerabilities || 0;
        
        const ctx = document.getElementById('vulnBarChart').getContext('2d');
        
        if (vulnChartInstance) {
            vulnChartInstance.destroy();
        }
        
        // Chart colors palette for domains
        const colors = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#22c55e', '#8b5cf6', '#ec4899', '#14b8a6'];
        
        const datasets = (trendData.datasets || []).map((ds, idx) => ({
            label: ds.label,
            data: ds.data,
            borderColor: colors[idx % colors.length],
            backgroundColor: colors[idx % colors.length],
            borderWidth: 2,
            tension: 0.3,
            spanGaps: true,
            pointRadius: 4,
            pointHoverRadius: 6
        }));
        
        vulnChartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: trendData.labels || [],
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    },
                    x: {
                        ticks: {
                            maxTicksLimit: 12
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'bottom'
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            label: function(context) {
                                let label = context.dataset.label || '';
                                if (label) {
                                    label += ' | Vulns: ';
                                }
                                if (context.parsed.y !== null) {
                                    label += context.parsed.y;
                                }
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
        return d.toLocaleDateString('en-US', {
            month: 'short', day: '2-digit', year: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
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
