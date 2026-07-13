/**
 * JAGAWEB — Security Dashboard App.js
 */

const API_BASE = window.location.origin;

// State
let allDomains = [];
let filteredDomains = [];
let allVulns = [];
let filteredVulns = null;
let currentDomainData = null;

// Pagination State for Scan History
let vulnCurrentPage = 1;
let vulnRowsPerPage = 15;

// Pagination State for Domains
let domainCurrentPage = 1;
let domainRowsPerPage = 15;

let selectedDomains = new Set(JSON.parse(localStorage.getItem('dsti_saved_targets') || '[]'));

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('domainSearchInput');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            domainCurrentPage = 1;
            renderInventoryList();
        });
    }

    checkAuth();
    setupTabs();
    // -- (Taruh di dalam blok DOMContentLoaded) --
    const saveBtn = document.getElementById('saveTargetsBtn');
    if (saveBtn) {
        saveBtn.addEventListener('click', async () => {
            const domainsToSave = [...selectedDomains];
            if (domainsToSave.length === 0) {
                showToast('Peringatan', 'Pilih minimal satu domain untuk disimpan.', '⚠️');
                return;
            }

            // Simpan di memori browser
            localStorage.setItem('dsti_saved_targets', JSON.stringify(domainsToSave));
            
            // Tembakkan API ke Backend
            try {
                // Diubah ke endpoint /api/schedule-scan dan mengubah key "domains" menjadi "targets"
                const resp = await fetch(`${API_BASE}/api/schedule-scan`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ targets: domainsToSave })
                });

                if (resp.status === 200) {
                    showToast('Tersimpan', `${domainsToSave.length} domain berhasil disimpan untuk scan interval.`, '💾');
                } else {
                    const data = await resp.json();
                    showToast('Gagal Menyimpan', data.detail || 'Terjadi kesalahan di server.', '❌');
                }
            } catch (err) {
                console.error(err);
                showToast('Koneksi Gagal', 'Gagal menghubungi server.', '🔌');
            }
        });
    }

    const runBtn = document.getElementById('runScanBtn');
    if (runBtn) {
        runBtn.addEventListener('click', async () => {
            const domainsToScan = [...selectedDomains];
            if (domainsToScan.length === 0) return;

            showToast('Scan Dimulai', `Memerintahkan backend untuk memulai scan pada ${domainsToScan.length} domain...`, '🚀');
            
            // Kunci tombol agar tidak di-klik dua kali (spam)
            runBtn.disabled = true;
            runBtn.style.opacity = '0.5';
            runBtn.innerHTML = 'Memproses...';

            try {
                // Karena /api/trigger-pentest hanya menerima 1 domain, kita gunakan Promise.all untuk mengirim banyak permintaan sekaligus
                const scanPromises = domainsToScan.map(domain => {
                    return fetch(`${API_BASE}/api/trigger-pentest?domain_name=${encodeURIComponent(domain)}`, {
                        method: 'POST'
                    });
                });

                const responses = await Promise.all(scanPromises);
                
                // Cek apakah ada request yang gagal
                const allSuccess = responses.every(resp => resp.status === 200 || resp.status === 202);

                if (allSuccess) {
                    showToast('Scan Berhasil Diantrekan', 'Proses scan instan sedang berjalan di latar belakang.', '✅');
                } else {
                    showToast('Peringatan', 'Beberapa scan mungkin gagal dijalankan. Cek log server.', '⚠️');
                }
            } catch (err) {
                console.error(err);
                showToast('Koneksi Gagal', 'Server tidak merespons proses scan.', '🔌');
            } finally {
                // Kembalikan status tombol seperti semula
                refreshCheckboxUI();
                runBtn.innerHTML = `
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                    Scan Sekarang
                `;
            }
        });
    }
    
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

    // Bind scan history pagination events
    const vulnRowsSelect = document.getElementById('vulnRowsSelect');
    if (vulnRowsSelect) {
        vulnRowsSelect.addEventListener('change', (e) => {
            vulnRowsPerPage = parseInt(e.target.value);
            vulnCurrentPage = 1;
            renderVulnerabilitiesList();
        });
    }
    const vulnPrevBtn = document.getElementById('vulnPrevPageBtn');
    if (vulnPrevBtn) {
        vulnPrevBtn.addEventListener('click', () => {
            if (vulnCurrentPage > 1) {
                vulnCurrentPage--;
                renderVulnerabilitiesList();
            }
        });
    }
    const vulnNextBtn = document.getElementById('vulnNextPageBtn');
    if (vulnNextBtn) {
        vulnNextBtn.addEventListener('click', () => {
            const totalPages = Math.ceil(filteredVulns.length / vulnRowsPerPage);
            if (vulnCurrentPage < totalPages) {
                vulnCurrentPage++;
                renderVulnerabilitiesList();
            }
        });
    }
    
    // Bind page input jumps
    const vulnPageInput = document.getElementById('vulnPageInput');
    if (vulnPageInput) {
        vulnPageInput.addEventListener('change', (e) => {
            const totalPages = Math.ceil(filteredVulns.length / vulnRowsPerPage) || 1;
            let val = parseInt(e.target.value);
            if (isNaN(val)) val = 1;
            if (val < 1) val = 1;
            if (val > totalPages) val = totalPages;
            
            vulnCurrentPage = val;
            renderVulnerabilitiesList();
        });
        vulnPageInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                vulnPageInput.blur();
            }
        });
    }

    // Bind date filter buttons
    const filterBtn = document.getElementById('vulnFilterBtn');
    if (filterBtn) {
        filterBtn.addEventListener('click', applyVulnFilters);
    }
    const resetFilterBtn = document.getElementById('vulnResetFilterBtn');
    if (resetFilterBtn) {
        resetFilterBtn.addEventListener('click', resetVulnFilters);
    }

    // Bind domain pagination events
    const domainRowsSelect = document.getElementById('domainRowsSelect');
    if (domainRowsSelect) {
        domainRowsSelect.addEventListener('change', (e) => {
            domainRowsPerPage = parseInt(e.target.value);
            domainCurrentPage = 1;
            renderInventoryList();
        });
    }
    const domainPrevBtn = document.getElementById('domainPrevPageBtn');
    if (domainPrevBtn) {
        domainPrevBtn.addEventListener('click', () => {
            if (domainCurrentPage > 1) {
                domainCurrentPage--;
                renderInventoryList();
            }
        });
    }
    const domainNextBtn = document.getElementById('domainNextPageBtn');
    if (domainNextBtn) {
        domainNextBtn.addEventListener('click', () => {
            const totalPages = Math.ceil(filteredDomains.length / domainRowsPerPage);
            if (domainCurrentPage < totalPages) {
                domainCurrentPage++;
                renderInventoryList();
            }
        });
    }
    const domainPageInput = document.getElementById('domainPageInput');
    if (domainPageInput) {
        domainPageInput.addEventListener('change', (e) => {
            const totalPages = Math.ceil(filteredDomains.length / domainRowsPerPage) || 1;
            let val = parseInt(e.target.value);
            if (isNaN(val)) val = 1;
            if (val < 1) val = 1;
            if (val > totalPages) val = totalPages;
            
            domainCurrentPage = val;
            renderInventoryList();
        });
        domainPageInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                domainPageInput.blur();
            }
        });
    }

    // Refresh otomatis setiap 5 detik
    // setInterval(refreshData, 5000);
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
let rawTrendData = null;
let rawSevTrendData = null;

// Consistent color palette: each domain always gets the same color via hash
const PALETTE = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#22c55e', '#8b5cf6', '#ec4899', '#14b8a6', '#06b6d4', '#a855f7', '#f43f5e', '#10b981', '#6366f1', '#d946ef', '#84cc16'];
const domainColorMap = {};

function getDomainColor(domain) {
    if (domainColorMap[domain]) return domainColorMap[domain];
    // Simple hash to pick a consistent color
    let hash = 0;
    for (let i = 0; i < domain.length; i++) hash = domain.charCodeAt(i) + ((hash << 5) - hash);
    const idx = Math.abs(hash) % PALETTE.length;
    // Avoid collision: find next free color
    const usedColors = Object.values(domainColorMap);
    let color = PALETTE[idx];
    if (usedColors.includes(color)) {
        for (const c of PALETTE) {
            if (!usedColors.includes(c)) { color = c; break; }
        }
    }
    domainColorMap[domain] = color;
    return color;
}

function hexToRgb(hex) {
    if (!hex) return null;
    if (hex.startsWith('#')) hex = hex.slice(1);
    if (hex.length === 3) hex = hex.split('').map(c => c + c).join('');
    const bigint = parseInt(hex, 16);
    return { r: (bigint >> 16) & 255, g: (bigint >> 8) & 255, b: bigint & 255 };
}

// --- Multi-Select Dropdown Helpers ---
function toggleDropdown(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.toggle('open');
}

function filterDropdownItems(dropdownId, query) {
    const container = document.getElementById(dropdownId);
    if (!container) return;
    const items = container.querySelectorAll('.multi-select-item');
    const q = query.toLowerCase();
    items.forEach(item => {
        const text = item.textContent.toLowerCase();
        item.style.display = text.includes(q) ? '' : 'none';
    });
}

function updateDropdownLabel(dropdownId, allLabel, items) {
    const container = document.getElementById(dropdownId);
    if (!container) return;
    const label = container.querySelector('.multi-select-label');
    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    const checked = Array.from(checkboxes).filter(cb => cb.checked);

    if (checked.length === 0 || checked.length === checkboxes.length) {
        label.textContent = allLabel;
    } else if (checked.length === 1) {
        label.textContent = checked[0].value;
    } else {
        label.textContent = `${checked.length} dipilih`;
    }
}

// Close dropdown when clicking outside
document.addEventListener('click', function (e) {
    document.querySelectorAll('.multi-select-dropdown.open').forEach(dd => {
        if (!dd.contains(e.target)) {
            dd.classList.remove('open');
        }
    });
});

async function loadOverview() {
    try {
        const [statsResp, trendResp, sevTrendResp] = await Promise.all([
            fetch(`${API_BASE}/api/dashboard-stats`),
            fetch(`${API_BASE}/api/trend-stats`),
            fetch(`${API_BASE}/api/severity-trend-stats`)
        ]);

        const statsData = await statsResp.json();
        rawTrendData = await trendResp.json();
        rawSevTrendData = await sevTrendResp.json();

        // Update summary cards
        document.getElementById('overviewTotalDomains').textContent = statsData.total_domains || 0;
        document.getElementById('overviewTotalVulns').textContent = statsData.total_vulnerabilities || 0;

        // Populate Domain Filter Checkboxes
        const vulnItemsContainer = document.getElementById('vulnTrendItems');
        if (vulnItemsContainer && rawTrendData.datasets) {
            // Save current state
            const currentChecked = Array.from(vulnItemsContainer.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value);
            const hasExisting = vulnItemsContainer.children.length > 0;
            const allChecked = (!hasExisting || currentChecked.includes('All')) ? 'checked' : '';

            vulnItemsContainer.innerHTML = '';

            const allLabel = document.createElement('label');
            allLabel.className = 'multi-select-item';
            allLabel.innerHTML = `<input type="checkbox" value="All" ${allChecked} onchange="onVulnFilterChange(this)"><b>All Domains</b>`;
            vulnItemsContainer.appendChild(allLabel);

            let sortedDomains = rawTrendData.datasets.map(ds => ds.label).sort();
            // Pre-assign colors
            sortedDomains.forEach(d => getDomainColor(d));

            sortedDomains.forEach(domain => {
                const color = getDomainColor(domain);
                const isChecked = (hasExisting && currentChecked.includes(domain)) ? 'checked' : '';
                const label = document.createElement('label');
                label.className = 'multi-select-item';
                label.innerHTML = `<input type="checkbox" value="${domain}" ${isChecked} onchange="onVulnFilterChange(this)"><span class="sev-dot" style="background:${color}"></span>${domain}`;
                vulnItemsContainer.appendChild(label);
            });
            
            if (hasExisting) {
                updateDropdownLabel('vulnTrendDropdown', 'All Domains');
            }
        }

        // Initial Render
        if (window.renderVulnTrendChart) window.renderVulnTrendChart();
        if (window.renderSevTrendChart) window.renderSevTrendChart();

    } catch (err) {
        console.error('Error loading overview:', err);
    }
}

window.onVulnFilterChange = function (clickedCb) {
    const container = document.getElementById('vulnTrendDropdown');
    if (!container) return;
    const checkboxes = Array.from(container.querySelectorAll('input[type="checkbox"]'));
    const allCb = checkboxes.find(cb => cb.value === 'All');
    const specificCbs = checkboxes.filter(cb => cb.value !== 'All');

    if (clickedCb && clickedCb.value === 'All' && clickedCb.checked) {
        specificCbs.forEach(cb => cb.checked = false);
    } else if (clickedCb && clickedCb.value !== 'All' && clickedCb.checked) {
        if (allCb) allCb.checked = false;
    }

    const checkedSpecifics = specificCbs.filter(cb => cb.checked);
    if (checkedSpecifics.length === 0 && (!allCb || !allCb.checked)) {
        if (allCb) allCb.checked = true;
    }

    updateDropdownLabel('vulnTrendDropdown', 'All Domains');
    renderVulnTrendChart();
};

window.onSevFilterChange = function (clickedCb) {
    const container = document.getElementById('sevTrendDropdown');
    if (!container) return;
    const checkboxes = Array.from(container.querySelectorAll('input[type="checkbox"]'));
    const allCb = checkboxes.find(cb => cb.value === 'All');
    const specificCbs = checkboxes.filter(cb => cb.value !== 'All');

    if (clickedCb && clickedCb.value === 'All' && clickedCb.checked) {
        specificCbs.forEach(cb => cb.checked = false);
    } else if (clickedCb && clickedCb.value !== 'All' && clickedCb.checked) {
        if (allCb) allCb.checked = false;
    }

    const checkedSpecifics = specificCbs.filter(cb => cb.checked);
    if (checkedSpecifics.length === 0 && (!allCb || !allCb.checked)) {
        if (allCb) allCb.checked = true;
    }

    updateDropdownLabel('sevTrendDropdown', 'All Severities');
    renderSevTrendChart();
};

window.renderVulnTrendChart = function () {
    if (!rawTrendData) return;

    const vulnCtx = document.getElementById('vulnBarChart').getContext('2d');
    if (vulnChartInstance) vulnChartInstance.destroy();

    // Get selected domains from checkboxes
    const checkboxes = Array.from(document.querySelectorAll('#vulnTrendItems input[type="checkbox"]'));
    const allCb = checkboxes.find(cb => cb.value === 'All');

    let selectedDomains = [];
    let allChecked = false;

    if (allCb && allCb.checked) {
        allChecked = true;
    } else {
        selectedDomains = checkboxes.filter(cb => cb.checked && cb.value !== 'All').map(cb => cb.value);
        if (selectedDomains.length === 0) allChecked = true;
    }

    let allDatasets = [...(rawTrendData.datasets || [])];
    let finalDatasets = [];

    if (!allChecked && selectedDomains.length > 0) {
        finalDatasets = allDatasets.filter(ds => selectedDomains.includes(ds.label));
    } else {
        // All selected: show top 5 + Others
        allDatasets.sort((a, b) => Math.max(...b.data) - Math.max(...a.data));
        const topN = 5;
        finalDatasets = allDatasets.slice(0, topN);
        if (allDatasets.length > topN) {
            let othersData = new Array(allDatasets[0].data.length).fill(0);
            for (let i = topN; i < allDatasets.length; i++) {
                for (let j = 0; j < allDatasets[i].data.length; j++) {
                    othersData[j] += allDatasets[i].data[j];
                }
            }
            finalDatasets.push({ label: 'Others', data: othersData });
        }
    }

    const domainDatasets = finalDatasets.map((ds) => {
        const baseColor = ds.label === 'Others' ? '#6b7280' : getDomainColor(ds.label);
        return {
            label: ds.label,
            data: ds.data,
            borderColor: baseColor,
            backgroundColor: (context) => {
                const chart = context.chart;
                const { ctx, chartArea } = chart;
                if (!chartArea) return baseColor;
                const gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                const rgb = hexToRgb(baseColor);
                if (rgb) {
                    gradient.addColorStop(0, `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.35)`);
                    gradient.addColorStop(1, `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.0)`);
                    return gradient;
                }
                return baseColor;
            },
            borderWidth: ds.label === 'Others' ? 2 : 2.5,
            borderDash: ds.label === 'Others' ? [5, 5] : [],
            tension: 0.4,
            fill: true,
            spanGaps: true,
            pointRadius: 0,
            pointHoverRadius: 6
        };
    });

    vulnChartInstance = new Chart(vulnCtx, {
        type: 'line',
        data: {
            labels: rawTrendData.labels || [],
            datasets: domainDatasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { precision: 0 },
                    grid: { color: '#e5e7eb', borderDash: [5, 5] },
                    border: { display: false }
                },
                x: {
                    ticks: { maxTicksLimit: 12 },
                    grid: { display: false },
                    border: { display: false }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom',
                    onClick: null
                },
                tooltip: {
                    backgroundColor: '#ffffff',
                    titleColor: '#1f2937',
                    bodyColor: '#374151',
                    borderColor: '#e5e7eb',
                    borderWidth: 1,
                    padding: 12,
                    boxPadding: 6,
                    usePointStyle: true,
                    titleFont: { size: 13, weight: '600' },
                    bodyFont: { size: 12 },
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        label: function (context) {
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
};

window.renderSevTrendChart = function() {
    if (!rawSevTrendData) return;
    
    const sevCtx = document.getElementById('sevTrendChart').getContext('2d');
    if (sevChartInstance) sevChartInstance.destroy();
    
    // Get selected severities from checkboxes
    const checkboxes = Array.from(document.querySelectorAll('#sevTrendItems input[type="checkbox"]'));
    const allCb = checkboxes.find(cb => cb.value === 'All');
    
    let selectedSevs = [];
    let allChecked = false;

    if (allCb && allCb.checked) {
        allChecked = true;
    } else {
        selectedSevs = checkboxes.filter(cb => cb.checked && cb.value !== 'All').map(cb => cb.value);
        if (selectedSevs.length === 0) allChecked = true;
    }
    
    // Update label (handled by onSevFilterChange but good to ensure on initial render)
    updateDropdownLabel('sevTrendDropdown', 'All Severities');
    
    const sevColors = {
        'Critical': '#ef4444',
        'High': '#f97316',
        'Medium': '#eab308',
        'Low': '#3b82f6',
        'Info': '#22c55e'
    };
    
    let baseDatasets = rawSevTrendData.datasets || [];
    if (!allChecked && selectedSevs.length > 0) {
        baseDatasets = baseDatasets.filter(ds => selectedSevs.includes(ds.label));
    }
    
    const sevDatasets = baseDatasets.map((ds) => {
        const color = sevColors[ds.label] || '#9ca3af';
        return {
            label: ds.label,
            data: ds.data,
            domains: ds.domains || [],
            borderColor: color,
            backgroundColor: (context) => {
                const chart = context.chart;
                const {ctx, chartArea} = chart;
                if (!chartArea) return color;
                const gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                const rgb = hexToRgb(color);
                if (rgb) {
                    gradient.addColorStop(0, `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.35)`);
                    gradient.addColorStop(1, `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.0)`);
                    return gradient;
                }
                return color;
            },
            borderWidth: 2.5,
            tension: 0.4,
            fill: true,
            spanGaps: true,
            pointRadius: 0,
            pointHoverRadius: 6
        };
    });

    sevChartInstance = new Chart(sevCtx, {
        type: 'line',
        data: {
            labels: rawSevTrendData.labels || [],
            datasets: sevDatasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { precision: 0 },
                    grid: { color: '#e5e7eb', borderDash: [5, 5] },
                    border: { display: false }
                },
                x: {
                    ticks: { maxTicksLimit: 12 },
                    grid: { display: false },
                    border: { display: false }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom',
                    onClick: null
                },
                tooltip: {
                    backgroundColor: '#ffffff',
                    titleColor: '#1f2937',
                    bodyColor: '#374151',
                    borderColor: '#e5e7eb',
                    borderWidth: 1,
                    padding: 12,
                    boxPadding: 6,
                    usePointStyle: true,
                    titleFont: { size: 13, weight: '600' },
                    bodyFont: { size: 12 },
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            let val = context.parsed.y;
                            if (label) label += ': ';
                            label += val;

                            let domainsList = context.dataset.domains ? context.dataset.domains[context.dataIndex] : null;
                            if (val > 0 && domainsList && domainsList.length > 0) {
                                let lines = [label];
                                domainsList.forEach(d => {
                                    lines.push('   • ' + d);
                                });
                                return lines;
                            }
                            return label;
                        }
                    }
                }
            }
        }
    });
};

// ==========================================================================
// Automated Pentests (Vulnerabilities View)
// ==========================================================================
async function loadVulnerabilities() {
    try {
        const resp = await fetch(`${API_BASE}/api/scan-history?limit=1000`);
        const data = await resp.json();
        allVulns = data.data || [];
        applyVulnFilters();
        renderLowerGrid();
    } catch (err) {
        console.error('Error loading scans:', err);
    }
}

function applyVulnFilters() {
    const startInput = document.getElementById('vulnStartDate')?.value;
    const endInput = document.getElementById('vulnEndDate')?.value;
    
    let startDate = null;
    let endDate = null;
    
    if (startInput) {
        startDate = new Date(startInput);
        startDate.setHours(0, 0, 0, 0);
    }
    
    if (endInput) {
        endDate = new Date(endInput);
        endDate.setHours(23, 59, 59, 999);
    }
    
    filteredVulns = allVulns.filter(scan => {
        if (!scan.scan_date) return false;
        const scanDate = new Date(scan.scan_date);
        
        if (startDate && scanDate < startDate) return false;
        if (endDate && scanDate > endDate) return false;
        
        return true;
    });
    
    vulnCurrentPage = 1;
    renderVulnerabilitiesList();
}

function resetVulnFilters() {
    const startInput = document.getElementById('vulnStartDate');
    const endInput = document.getElementById('vulnEndDate');
    if (startInput) startInput.value = '';
    if (endInput) endInput.value = '';
    
    filteredVulns = [...allVulns];
    vulnCurrentPage = 1;
    renderVulnerabilitiesList();
}

function renderVulnerabilitiesList() {
    const container = document.getElementById('vulnListContainer');
    const paginationControls = document.getElementById('vulnPaginationControls');
    
    // Inisialisasi data filter jika baru pertama kali dimuat
    if (!filteredVulns) filteredVulns = [...allVulns];
    
    if (!filteredVulns || filteredVulns.length === 0) {
        container.innerHTML = `<tr><td colspan="5" class="empty-state">No scan history found for the selected filter.</td></tr>`;
        if (paginationControls) paginationControls.style.display = 'none';
        return;
    }
    
    if (paginationControls) paginationControls.style.display = 'flex';
    
    const totalItems = filteredVulns.length;
    const totalPages = Math.ceil(totalItems / vulnRowsPerPage) || 1;
    if (vulnCurrentPage > totalPages) vulnCurrentPage = totalPages;
    if (vulnCurrentPage < 1) vulnCurrentPage = 1;
    
    const startIdx = (vulnCurrentPage - 1) * vulnRowsPerPage;
    const endIdx = Math.min(startIdx + vulnRowsPerPage, totalItems);
    const paginatedVulns = filteredVulns.slice(startIdx, endIdx);
    
    // Perbarui teks informasi halaman
    const totalPagesEl = document.getElementById('vulnTotalPages');
    if (totalPagesEl) totalPagesEl.textContent = totalPages;
    const pageInput = document.getElementById('vulnPageInput');
    if (pageInput) pageInput.value = vulnCurrentPage;
    
container.innerHTML = paginatedVulns.map((scan) => {
        // PENTING: Cari indeks asli dari allVulns agar pop-up detail tidak tertukar saat difilter
        const actualIndex = allVulns.indexOf(scan);
        const domainName = scan.domains?.domain_name || 'Unknown Target';
        const riskLevel = scan.risk_level || 'SAFE';
        const sevClass = getSeverityClass(riskLevel);
        const date = formatDate(scan.scan_date);
        const numVulns = scan.vulnerabilities ? scan.vulnerabilities.length : 0;

        return `
            <tr onclick="openScanModalIndex(${actualIndex})" style="cursor: pointer;">
                <td style="font-family:var(--font-mono); font-weight:500;">SCAN-${String(scan.id || actualIndex + 1).padStart(4, '0')}</td>
                <td><span style="color:var(--primary); font-weight:500;">${escapeHtml(domainName)}</span></td>
                <td style="color:var(--text-secondary);">${date}</td>
                <td><span class="badge badge-${sevClass}">${numVulns} Vulns</span></td>
                <td><button class="icon-btn" onclick="event.stopPropagation(); openScanModalIndex(${actualIndex})" title="View Details">⋮</button></td>
            </tr>
        `;
    }).join('');
    
    // Perbarui status tombol UI Pagination
    if (paginationControls) {
        paginationControls.style.display = 'flex';
        
        const pageInput = document.getElementById('vulnPageInput');
        if (pageInput) {
            pageInput.value = vulnCurrentPage;
        }
        
        const totalPagesSpan = document.getElementById('vulnTotalPages');
        const totalPages = Math.ceil(filteredVulns.length / vulnRowsPerPage) || 1;
        if (totalPagesSpan) {
            totalPagesSpan.textContent = totalPages;
        }
        
        const prevBtn = document.getElementById('vulnPrevPageBtn');
        if (prevBtn) {
            prevBtn.disabled = (vulnCurrentPage === 1);
            prevBtn.style.opacity = (vulnCurrentPage === 1) ? '0.5' : '1';
            prevBtn.style.cursor = (vulnCurrentPage === 1) ? 'not-allowed' : 'pointer';
        }
        
        const nextBtn = document.getElementById('vulnNextPageBtn');
        if (nextBtn) {
            nextBtn.disabled = (vulnCurrentPage === totalPages || totalPages === 0);
            nextBtn.style.opacity = (vulnCurrentPage === totalPages || totalPages === 0) ? '0.5' : '1';
            nextBtn.style.cursor = (vulnCurrentPage === totalPages || totalPages === 0) ? 'not-allowed' : 'pointer';
        }
    }
}

// ==========================================================================
// Render Lower Dashboard Grid (Recent Alerts & Monitored Domains)
// ==========================================================================
function renderLowerGrid() {
    const alertsBody = document.getElementById('recentAlertsBody');
    const domainsList = document.getElementById('monitoredDomainsList');

    if (!allVulns || allVulns.length === 0) {
        if (alertsBody) alertsBody.innerHTML = `<tr><td colspan="4" class="empty-state">No alerts found.</td></tr>`;
        if (domainsList) domainsList.innerHTML = `<li class="domain-item" style="justify-content: center;"><span class="empty-state">No domains monitored.</span></li>`;
        return;
    }

    // 1. Process Recent Critical Alerts
    let allAlerts = [];
    allVulns.forEach(scan => {
        const domainName = scan.domains?.domain_name || 'Unknown Target';
        const scanDate = scan.scan_date;
        if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
            scan.vulnerabilities.forEach(v => {
                const sev = (v.severity || '').toUpperCase();
                if (['CRITICAL', 'HIGH', 'MEDIUM'].includes(sev)) {
                    allAlerts.push({
                        severity: sev,
                        title: v.title || v.check_type || 'Unknown Vulnerability',
                        target: domainName,
                        date: new Date(scanDate).getTime(),
                        rawDate: scanDate
                    });
                }
            });
        }
    });

    const SEV_WEIGHT = { 'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1 };
    allAlerts.sort((a, b) => {
        const wA = SEV_WEIGHT[a.severity] || 0;
        const wB = SEV_WEIGHT[b.severity] || 0;
        if (wA !== wB) return wB - wA;
        return b.date - a.date;
    });

    const uniqueDomainAlerts = [];
    const seenDomains = new Set();
    for (const alert of allAlerts) {
        if (!seenDomains.has(alert.target)) {
            uniqueDomainAlerts.push(alert);
            seenDomains.add(alert.target);
        }
    }

    const topAlerts = uniqueDomainAlerts.slice(0, 5);
    
    if (alertsBody) {
        if (topAlerts.length === 0) {
            alertsBody.innerHTML = `<tr><td colspan="4" class="empty-state">No high/critical alerts.</td></tr>`;
        } else {
            alertsBody.innerHTML = topAlerts.map(alert => {
                const sevClass = getSeverityClass(alert.severity);
                return `
                    <tr>
                        <td><span class="badge badge-${sevClass}">${alert.severity}</span></td>
                        <td class="font-mono" style="font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 150px;" title="${escapeHtml(alert.title)}">${escapeHtml(alert.title)}</td>
                        <td class="font-mono" style="font-size: 12px;">${escapeHtml(alert.target)}</td>
                        <td style="color: var(--color-muted-light); font-size: 12px;">${formatDate(alert.rawDate)}</td>
                    </tr>
                `;
            }).join('');
        }
    }

    // 2. Process Monitored Domains
    const domainMap = {};
    allVulns.forEach(scan => {
        const domainName = scan.domains?.domain_name || 'Unknown Target';
        const riskLevel = (scan.risk_level || 'SAFE').toUpperCase();
        const scanDate = new Date(scan.scan_date).getTime();

        if (!domainMap[domainName] || scanDate > domainMap[domainName].date) {
            domainMap[domainName] = {
                domain: domainName,
                risk: riskLevel,
                date: scanDate,
                ip: scan.domains?.ip_address || '-'
            };
        }
    });

    let uniqueDomains = Object.values(domainMap);
    const DOMAIN_RISK_WEIGHT = { 'CRITICAL': 6, 'HIGH': 5, 'MEDIUM': 4, 'LOW': 3, 'INFO': 2, 'SAFE': 1 };
    
    const riskFilterEl = document.querySelector('input[name="domainRisk"]:checked');
    const selectedRiskFilter = riskFilterEl ? riskFilterEl.value : 'ALL';
    
    if (selectedRiskFilter !== 'ALL') {
        uniqueDomains = uniqueDomains.filter(d => {
            if (selectedRiskFilter === 'AT_RISK') return d.risk === 'CRITICAL' || d.risk === 'HIGH';
            if (selectedRiskFilter === 'REVIEW') return d.risk === 'MEDIUM' || d.risk === 'LOW';
            if (selectedRiskFilter === 'SECURE') return d.risk === 'SAFE' || d.risk === 'INFO';
            return true;
        });
    }

    uniqueDomains.sort((a, b) => {
        const wA = DOMAIN_RISK_WEIGHT[a.risk] || 0;
        const wB = DOMAIN_RISK_WEIGHT[b.risk] || 0;
        if (wA !== wB) return wB - wA;
        return b.date - a.date;
    });

    const topDomains = uniqueDomains.slice(0, 5);

    if (domainsList) {
        if (topDomains.length === 0) {
            domainsList.innerHTML = `<li class="domain-item" style="justify-content: center;"><span class="empty-state">No domains monitored.</span></li>`;
        } else {
            domainsList.innerHTML = topDomains.map(d => {
                let statusLabel = 'SECURE';
                let statusClass = 'secure';
                
                if (d.risk === 'CRITICAL' || d.risk === 'HIGH') {
                    statusLabel = 'AT RISK';
                    statusClass = 'at-risk';
                } else if (d.risk === 'MEDIUM' || d.risk === 'LOW') {
                    statusLabel = 'REVIEW';
                    statusClass = 'review';
                }

                return `
                    <li class="domain-item">
                        <div class="domain-icon"><svg class="icon"><use href="#icon-globe"/></svg></div>
                        <div class="domain-info">
                            <p class="domain-name">${escapeHtml(d.domain)}</p>
                            <p class="domain-desc">${escapeHtml(d.ip)}</p>
                        </div>
                        <div class="domain-status">
                            <span class="status-label ${statusClass}">${statusLabel}</span>
                            <span class="domain-score">Risk: ${d.risk}</span>
                        </div>
                    </li>
                `;
            }).join('');
        }
    }
}

// Function helper untuk membuka modal dari index
function openScanModalIndex(index) {
    const scan = filteredVulns[index];
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
        domainCurrentPage = 1;
        renderInventoryList();
        
        const manageLink = document.getElementById('manageDomainsLink');
        if (manageLink) {
            manageLink.textContent = `Manage All ${allDomains.length} Domains`;
        }
    } catch (err) {
        console.error('Error loading domains:', err);
    }
}

let currentDomainPage = 1;
const DOMAINS_PER_PAGE = 20;

function renderInventoryList() {
    const tbody = document.getElementById('inventoryTableBody');
    const paginationControls = document.getElementById('domainPaginationControls');
    
    // Perbaikan Bug: Render UI Kosong dengan benar jika tidak ada data dari backend
    if (!allDomains || allDomains.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No domains found.</td></tr>`;
        if (paginationControls) paginationControls.style.display = 'none';
        return;
    }

    // Filtering logic
    const searchVal = (document.getElementById('domainSearchInput')?.value || '').toLowerCase();
    filteredDomains = allDomains.filter(d => 
        (d.domain_name || '').toLowerCase().includes(searchVal) ||
        (d.ip_address || '').toLowerCase().includes(searchVal)
    );
    
    if (filteredDomains.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No domains match your search.</td></tr>`;
        if (paginationControls) paginationControls.style.display = 'none';
        return;
    }
    
    if (paginationControls) paginationControls.style.display = 'flex';
    
    const totalItems = filteredDomains.length;
    const totalPages = Math.ceil(totalItems / domainRowsPerPage) || 1;
    if (domainCurrentPage > totalPages) domainCurrentPage = totalPages;
    if (domainCurrentPage < 1) domainCurrentPage = 1;
    
    const startIdx = (domainCurrentPage - 1) * domainRowsPerPage;
    const endIdx = Math.min(startIdx + domainRowsPerPage, totalItems);
    const paginatedDomains = filteredDomains.slice(startIdx, endIdx);
    
    // Cetak Tabel dengan pengecekan state "selectedDomains"
    tbody.innerHTML = paginatedDomains.map(d => {
        // Cek apakah domain ini ada di memori yang tersimpan
        const isChecked = selectedDomains.has(d.domain_name) ? 'checked' : '';
        return `
        <tr>
            <td style="text-align: center;">
                <input type="checkbox" class="domain-checkbox" value="${escapeHtml(d.domain_name)}" ${isChecked} style="cursor: pointer;">
            </td>
            <td style="font-weight:500; color:var(--primary)">
                <a href="http://${escapeHtml(d.domain_name)}" target="_blank" style="text-decoration: none; color: inherit;">${escapeHtml(d.domain_name)}</a>
            </td>
            <td style="font-family:var(--font-mono); color:var(--text-secondary)">${escapeHtml(d.ip_address || '-')}</td>
            <td><span class="badge ${d.is_active ? 'badge-active' : 'badge-inactive'}">${d.is_active ? 'ACTIVE' : 'INACTIVE'}</span></td>
        </tr>
        `;
    }).join('');
    
    if (paginationControls) {
        const pageInput = document.getElementById('domainPageInput');
        if (pageInput) pageInput.value = domainCurrentPage;
        
        const totalPagesSpan = document.getElementById('domainTotalPages');
        if (totalPagesSpan) totalPagesSpan.textContent = totalPages || 1;
        
        const prevBtn = document.getElementById('domainPrevPageBtn');
        if (prevBtn) {
            prevBtn.disabled = (domainCurrentPage === 1);
            prevBtn.style.opacity = (domainCurrentPage === 1) ? '0.5' : '1';
            prevBtn.style.cursor = (domainCurrentPage === 1) ? 'not-allowed' : 'pointer';
        }
        
        const nextBtn = document.getElementById('domainNextPageBtn');
        if (nextBtn) {
            nextBtn.disabled = (domainCurrentPage === totalPages || totalPages === 0);
            nextBtn.style.opacity = (domainCurrentPage === totalPages || totalPages === 0) ? '0.5' : '1';
            nextBtn.style.cursor = (domainCurrentPage === totalPages || totalPages === 0) ? 'not-allowed' : 'pointer';
        }
    }

    if (typeof updateCheckboxLogic === 'function') {
        updateCheckboxLogic();
    }
}

function updateCheckboxLogic() {
    const checkboxes = document.querySelectorAll('.domain-checkbox');
    const selectAll = document.getElementById('selectAllDomains');
    
    // 1. Re-bind listeners ke setiap checkbox baris
    checkboxes.forEach(cb => {
        cb.addEventListener('change', (e) => {
            if (e.target.checked) {
                // Cegah jika sudah 5 domain
                if (selectedDomains.size >= 5) {
                    e.target.checked = false; // Batalkan centangan otomatis
                    showToast('Batas Maksimal', 'Anda hanya dapat memilih maksimal 5 domain sekaligus.', '⚠️');
                    refreshCheckboxUI();
                    return;
                }
                selectedDomains.add(e.target.value);
            } else {
                selectedDomains.delete(e.target.value);
            }
            refreshCheckboxUI();
        });
    });
    
    // 2. Logika Select All yang disesuaikan dengan limit 5
    if (selectAll) {
        selectAll.onclick = (e) => {
            const isChecked = e.target.checked;
            
            if (isChecked) {
                let addedCount = 0;
                checkboxes.forEach(cb => {
                    // Hanya centang jika belum dicentang DAN keranjang belum penuh (limit 5)
                    if (!cb.checked && selectedDomains.size < 5) {
                        cb.checked = true;
                        selectedDomains.add(cb.value);
                        addedCount++;
                    }
                });
                
                // Beri tahu pengguna jika terpotong oleh limit
                if (selectedDomains.size >= 5 && addedCount > 0) {
                    showToast('Batas Tercapai', 'Hanya dipilih sampai batas maksimal 5 domain.', '⚠️');
                }
            } else {
                // Jika Select All dihapus, buang centang dari semua domain di halaman ini
                checkboxes.forEach(cb => {
                    cb.checked = false;
                    selectedDomains.delete(cb.value);
                });
            }
            refreshCheckboxUI();
        };
    }
    
    // Perbarui teks dan tombol UI pertama kali tabel dimuat
    refreshCheckboxUI();
}

function refreshCheckboxUI() {
    const countText = document.getElementById('selectedDomainCount');
    const runBtn = document.getElementById('runScanBtn');
    const checkboxes = document.querySelectorAll('.domain-checkbox');
    const selectAll = document.getElementById('selectAllDomains');
    
    const count = selectedDomains.size;
    
    // Update teks indikator
    if (countText) {
        countText.textContent = `${count} dari maksimal 5 domain dipilih`;
    }
    
    // Update tombol "Scan Sekarang"
    if (runBtn) {
        if (count > 0) {
            runBtn.disabled = false;
            runBtn.style.opacity = '1';
            runBtn.style.cursor = 'pointer';
        } else {
            runBtn.disabled = true;
            runBtn.style.opacity = '0.5';
            runBtn.style.cursor = 'not-allowed';
        }
    }

    // UX Enhancement: Kunci sisa checkbox jika sudah mencapai batas 5
    checkboxes.forEach(cb => {
        if (!cb.checked && count >= 5) {
            cb.disabled = true;
            cb.style.opacity = '0.4';
            cb.style.cursor = 'not-allowed';
        } else {
            cb.disabled = false;
            cb.style.opacity = '1';
            cb.style.cursor = 'pointer';
        }
    });

    // Sesuaikan status visual kotak centang "Select All"
    if (selectAll) {
        const allDisplayedChecked = checkboxes.length > 0 && Array.from(checkboxes).every(cb => cb.checked);
        selectAll.checked = allDisplayedChecked;
        
        // Matikan Select All jika keranjang sudah penuh dari halaman lain
        if (!selectAll.checked && count >= 5) {
            selectAll.disabled = true;
            selectAll.style.opacity = '0.4';
            selectAll.style.cursor = 'not-allowed';
        } else {
            selectAll.disabled = false;
            selectAll.style.opacity = '1';
            selectAll.style.cursor = 'pointer';
        }
    }
}

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

    const domainName = scan.domains?.domain_name || '';
    document.getElementById('scanModalDomain').textContent = domainName || '-';
    document.getElementById('scanModalIp').textContent = scan.domains?.ip_address || '-';
    document.getElementById('scanModalDate').textContent = formatDate(scan.scan_date);
    document.getElementById('scanModalRisk').textContent = scan.risk_level || 'SAFE';
    document.getElementById('scanModalRisk').className = `meta-value text-${getSeverityClass(scan.risk_level)}`;

    const btnDownload = document.getElementById('btnDownloadReport');
    if (btnDownload && domainName) {
        const pdfFileName = 'pentest_tools_' + domainName.replace(/\./g, '_') + '.pdf';
        btnDownload.href = '/dashboard/reports/' + pdfFileName;
        btnDownload.style.display = 'inline-block';
    } else if (btnDownload) {
        btnDownload.style.display = 'none';
    }

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
let autoRefreshInterval = null;
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

    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
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

    // Mulai refresh otomatis 5 detik HANYA setelah sukses login
    if (autoRefreshInterval) clearInterval(autoRefreshInterval);
    autoRefreshInterval = setInterval(refreshData, 5000);
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
    // Notifikasi "Sesi Berakhir" dinonaktifkan sesuai permintaan
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
                // Notifikasi admin tentang user login baru (hanya untuk user lain, bukan diri sendiri)
                if (currentUser && currentUser.role === 'admin' && data.username !== currentUser.username) {
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

function showToast(title, message, icon = "🔔") {
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