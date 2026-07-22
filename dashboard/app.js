const API_BASE = window.location.origin;
// const API_BASE = "http://10.70.128.26:8000";
// const API_BASE = "http://" + window.location.hostname + ":8000";

// State
let allDomains = [];
let filteredDomains = [];
let allVulns = [];
let filteredVulns = null;
let currentDomainData = null;

// Network Scanner Logic
let networkScans = [];
let filteredNetworkScans = [];
let liveWebScans = [];
let liveNetworkScans = [];
let netCurrentPage = 1;
let netRowsPerPage = 15;

// Web Scanner Logic
let webScans = [];
let filteredWebScans = [];
let webCurrentPage = 1;
let webRowsPerPage = 15;

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

    // Pastikan filter tanggal tren di-reset pada saat dimuat (refresh)
    ['vulnTrend', 'sevTrend'].forEach(prefix => {
        const startInput = document.getElementById(`${prefix}StartDate`);
        const endInput = document.getElementById(`${prefix}EndDate`);
        const label = document.getElementById(`${prefix}DateLabel`);
        if (startInput) startInput.value = '';
        if (endInput) endInput.value = '';
        if (label) label.textContent = '24 Jam';
    });

    // Reset semua input dan form di seluruh halaman ke setelan awalnya
    document.querySelectorAll('form').forEach(f => f.reset());
    document.querySelectorAll('input, select, textarea').forEach(el => {
        if (el.type === 'radio' || el.type === 'checkbox') {
            el.checked = el.defaultChecked;
        } else if (el.tagName === 'SELECT') {
            let hasDefault = false;
            for (let i = 0; i < el.options.length; i++) {
                if (el.options[i].defaultSelected) {
                    el.selectedIndex = i;
                    hasDefault = true;
                    break;
                }
            }
            if (!hasDefault && el.options.length > 0) el.selectedIndex = 0;
        } else if (!['button', 'submit', 'hidden'].includes(el.type)) {
            el.value = el.defaultValue || '';
        }
    });

    // Reset khusus untuk daftar email di Report Action
    const emailListWrapper = document.getElementById('emailListWrapper');
    if (emailListWrapper) {
        emailListWrapper.innerHTML = `
            <div class="email-input-row" style="display: flex; gap: 8px;">
                <input type="email" class="auth-input email-recipient-input" placeholder="contoh@undip.ac.id" style="flex: 1; padding: 8px 12px; margin-bottom: 0;" required>
            </div>
        `;
    }

    // -- (Taruh di dalam blok DOMContentLoaded) --
    const saveBtn = document.getElementById('saveTargetsBtn');
    if (saveBtn) {
        saveBtn.addEventListener('click', async () => {
            const domainsToSave = [...selectedDomains];
            const inactiveDomains = allDomains.filter(d => !selectedDomains.has(d.domain_name)).map(d => d.domain_name);

            // Simpan di memori browser
            localStorage.setItem('dsti_saved_targets', JSON.stringify(domainsToSave));

            // Tembakkan API ke Backend
            try {
                const resp = await fetch(`${API_BASE}/api/schedule-scan`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ targets: domainsToSave, inactive_targets: inactiveDomains })
                });

                if (resp.status === 200) {
                    showToast('Tersimpan', `Status berhasil diperbarui (Aktif: ${domainsToSave.length}, Tidak Aktif: ${inactiveDomains.length}).`, '💾');
                    if (typeof loadDomains === 'function') loadDomains(true);
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

    // -- Logika untuk Tombol Network Scan --
    const runNetworkScanBtn = document.getElementById('runNetworkScanBtn');
    if (runNetworkScanBtn) {
        runNetworkScanBtn.addEventListener('click', async () => {
            const domainsToScan = [...selectedDomains];
            if (domainsToScan.length === 0) return;

            showToast('Scan Jaringan', `Memerintahkan API Pentest-Tools untuk melakukan pemindaian jaringan pada ${domainsToScan.length} domain...`, '🔍');

            runNetworkScanBtn.disabled = true;
            runNetworkScanBtn.style.opacity = '0.5';

            try {
                const resp = await fetch(`${API_BASE}/api/network-scan`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ targets: domainsToScan })
                });

                if (resp.status === 200) {
                    showToast('Scan Diterima', 'Proses Network Scan sedang berjalan secara asinkron di server.', '✅');
                } else {
                    const data = await resp.json();
                    showToast('Gagal', data.detail || 'Server menolak permintaan pemindaian jaringan.', '❌');
                }
            } catch (err) {
                showToast('Koneksi Terputus', 'Gagal menghubungi server.', '🔌');
            } finally {
                refreshCheckboxUI(); // Memastikan status tombol diperbarui berdasarkan jumlah centang saat ini
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

    // Bind auto-filter events for Scan History
    const vulnStartDate = document.getElementById('vulnStartDate');
    const vulnEndDate = document.getElementById('vulnEndDate');
    const vulnDomainSearch = document.getElementById('vulnDomainSearch');
    const vulnTypeFilter = document.getElementById('vulnTypeFilter');

    if (vulnStartDate) vulnStartDate.addEventListener('change', () => applyVulnFilters());
    if (vulnEndDate) vulnEndDate.addEventListener('change', () => applyVulnFilters());
    if (vulnTypeFilter) vulnTypeFilter.addEventListener('change', () => applyVulnFilters());
    if (vulnDomainSearch) {
        // Use a small debounce for text input to prevent lag while typing
        let timeout = null;
        vulnDomainSearch.addEventListener('input', () => {
            clearTimeout(timeout);
            timeout = setTimeout(() => applyVulnFilters(), 300);
        });
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

    // Click outside to close modals
    const scanModalOverlay = document.getElementById('scanModalOverlay');
    if (scanModalOverlay) {
        scanModalOverlay.addEventListener('click', (e) => {
            if (e.target === scanModalOverlay) closeScanModal();
        });
    }

    const threatModalOverlay = document.getElementById('threatModalOverlay');
    if (threatModalOverlay) {
        threatModalOverlay.addEventListener('click', (e) => {
            if (e.target === threatModalOverlay) closeThreatModal();
        });
    }

    const createUserModalOverlay = document.getElementById('createUserModalOverlay');
    if (createUserModalOverlay) {
        createUserModalOverlay.addEventListener('click', (e) => {
            if (e.target === createUserModalOverlay) closeCreateUserModal();
        });
    }

    // Vuln Trend Date Range Logic
    const vulnTrendStart = document.getElementById('vulnTrendStartDate');
    const vulnTrendEnd = document.getElementById('vulnTrendEndDate');
    const vulnTrendResetBtn = document.getElementById('vulnTrendResetBtn');

    if (vulnTrendResetBtn) {
        vulnTrendResetBtn.addEventListener('click', async () => {
            if (vulnTrendStart) vulnTrendStart.value = '';
            if (vulnTrendEnd) vulnTrendEnd.value = '';
            const lbl = document.getElementById('vulnTrendDateLabel');
            if (lbl) lbl.textContent = '24 Jam';
            await loadVulnTrendData();
        });
    }

    // Sev Trend Date Range Logic
    const sevTrendStart = document.getElementById('sevTrendStartDate');
    const sevTrendEnd = document.getElementById('sevTrendEndDate');
    const sevTrendResetBtn = document.getElementById('sevTrendResetBtn');

    if (sevTrendResetBtn) {
        sevTrendResetBtn.addEventListener('click', async () => {
            if (sevTrendStart) sevTrendStart.value = '';
            if (sevTrendEnd) sevTrendEnd.value = '';
            const lbl = document.getElementById('sevTrendDateLabel');
            if (lbl) lbl.textContent = '24 Jam';
            await loadSevTrendData();
        });
    }

    // Removed old exportDomainsBtn listener since it's now handled by global exportDomains function.

    const importBtn = document.getElementById('importDomainsBtn');
    const importInput = document.getElementById('importDomainsInput');
    if (importBtn && importInput) {
        importBtn.addEventListener('click', () => {
            importInput.click();
        });

        importInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = async (e) => {
                const content = e.target.result;
                let importedData = [];

                if (file.name.endsWith('.json')) {
                    try {
                        const data = JSON.parse(content);
                        if (Array.isArray(data)) {
                            importedData = data.map(d => {
                                if (typeof d === 'string') return { domain_name: d, ip_address: '' };
                                return { domain_name: d.domain_name, ip_address: d.ip_address || '' };
                            }).filter(d => d.domain_name);
                        }
                    } catch (err) {
                        showToast('Error', 'Format JSON tidak valid', '❌');
                        return;
                    }
                } else {
                    const lines = content.split('\n').map(d => d.trim()).filter(d => d.length > 0);
                    importedData = lines.map(line => {
                        const parts = line.split(',');
                        return {
                            domain_name: parts[0].trim(),
                            ip_address: parts.length > 1 ? parts[1].trim() : ''
                        };
                    }).filter(d => d.domain_name);
                }

                if (importedData.length > 0) {
                    showToast('Info', `Mengimpor ${importedData.length} domain...`, 'ℹ️');
                    let addedCount = 0;
                    for (const item of importedData) {
                        try {
                            const resp = await fetch(`${API_BASE}/api/domains`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(item)
                            });
                            if (resp.ok) addedCount++;
                        } catch (err) {
                            console.error('Error importing', item.domain_name, err);
                        }
                    }

                    showToast('Import Selesai', `Berhasil menambahkan ${addedCount} dari ${importedData.length} domain.`, '✅');
                    loadDomains();
                }

                importInput.value = '';
            };
            reader.readAsText(file);
        });
    }

    // Refresh otomatis setiap 5 detik
    // setInterval(refreshData, 5000);
});

// Navigation & Views
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
        fetchNotifications();
    }

    // Web Scanner & Network Scanner: start/stop polling for active scans
    if (viewId === 'web-scanner' || viewId === 'network-scanner') {
        fetchActiveScans();
        if (!activeScansInterval) {
            activeScansInterval = setInterval(fetchActiveScans, 5000);
        }
    } else {
        if (activeScansInterval) {
            clearInterval(activeScansInterval);
            activeScansInterval = null;
        }
    }
}

// Data Fetching
async function refreshData(preservePage = true) {
    try {
        await checkHealth();
        await Promise.all([
            // Tidak perlu refresh overview terus menerus, karena chart berat
            // loadOverview(),
            loadVulnerabilities(preservePage),
            loadDomains(preservePage)
        ]);

        // Memanggil fungsi render tabel network khusus
        if (typeof processNetworkScans === 'function') processNetworkScans(preservePage);
        if (typeof processWebScans === 'function') processWebScans(preservePage);
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

// Overview (Dashboard Stats & Chart)
let vulnChartInstance = null;
let sevChartInstance = null;
let rawTrendData = null;
let rawSevTrendData = null;

// Consistent color palette: each domain always gets the same color via hash
const PALETTE = ['#ef4444', '#3b82f6', '#eab308', '#22c55e', '#a855f7'];
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

// --- Date Dropdown Helpers ---
async function setQuickDate(chartPrefix, days, dropdownId) {
    const end = new Date();
    const start = new Date();
    start.setDate(end.getDate() - days);

    document.getElementById(`${chartPrefix}StartDate`).value = start.toISOString().split('T')[0];
    document.getElementById(`${chartPrefix}EndDate`).value = end.toISOString().split('T')[0];

    let labelText = `${days} Hari`;
    if (days === 1) labelText = '24 Jam';

    const labelEl = document.getElementById(`${chartPrefix}DateLabel`);
    if (labelEl) labelEl.textContent = labelText;

    const dd = document.getElementById(dropdownId);
    if (dd) dd.classList.remove('open');

    if (chartPrefix === 'vulnTrend') {
        await loadVulnTrendData();
    } else if (chartPrefix === 'sevTrend') {
        await loadSevTrendData();
    }
}

async function applyCustomDate(chartPrefix, dropdownId) {
    const start = document.getElementById(`${chartPrefix}StartDate`).value;
    const end = document.getElementById(`${chartPrefix}EndDate`).value;

    const labelEl = document.getElementById(`${chartPrefix}DateLabel`);
    if (start && end) {
        if (labelEl) {
            const formatDt = (dStr) => {
                const dt = new Date(dStr);
                return dt.toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' });
            };
            labelEl.textContent = `${formatDt(start)} - ${formatDt(end)}`;
        }
    } else {
        if (labelEl) labelEl.textContent = '24 Jam';
    }

    if (chartPrefix === 'vulnTrend') {
        await loadVulnTrendData();
    } else if (chartPrefix === 'sevTrend') {
        await loadSevTrendData();
    }
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

function updateDropdownLabel(dropdownId, allLabel) {
    const container = document.getElementById(dropdownId);
    if (!container) return;
    const label = container.querySelector('.multi-select-label');
    const checkboxes = Array.from(container.querySelectorAll('input[type="checkbox"]'));
    const checked = checkboxes.filter(cb => cb.checked);

    const isAllChecked = checked.length === 1 && checked[0].value === 'All';

    if (checked.length === 0 || checked.length === checkboxes.length || isAllChecked) {
        label.textContent = allLabel;
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
        const statsResp = await fetch(`${API_BASE}/api/dashboard-stats`);
        const statsData = await statsResp.json();

        // Update summary cards
        document.getElementById('overviewTotalDomains').textContent = statsData.total_domains || 0;
        document.getElementById('overviewTotalVulns').textContent = statsData.total_vulnerabilities || 0;

        await Promise.all([
            loadVulnTrendData(),
            loadSevTrendData()
        ]);
    } catch (err) {
        console.error('Error loading overview:', err);
    }
}

async function loadVulnTrendData() {
    try {
        const startDate = document.getElementById('vulnTrendStartDate')?.value || '';
        const endDate = document.getElementById('vulnTrendEndDate')?.value || '';
        const params = new URLSearchParams();
        if (startDate) params.append('start_date', startDate);
        if (endDate) params.append('end_date', endDate);

        const trendResp = await fetch(`${API_BASE}/api/trend-stats?${params.toString()}`);
        rawTrendData = await trendResp.json();

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

            // Clear existing map and pre-assign colors based on vulnerability rank
            Object.keys(domainColorMap).forEach(key => delete domainColorMap[key]);
            const rankedDomains = [...rawTrendData.datasets]
                .sort((a, b) => b.data.reduce((x, y) => x + y, 0) - a.data.reduce((x, y) => x + y, 0))
                .map(ds => ds.label);

            rankedDomains.forEach((d, idx) => {
                domainColorMap[d] = PALETTE[idx % PALETTE.length];
            });

            let sortedDomains = rawTrendData.datasets.map(ds => ds.label).sort();

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
    } catch (err) {
        console.error('Error loading vuln trend data:', err);
    }
}

async function loadSevTrendData() {
    try {
        const startDate = document.getElementById('sevTrendStartDate')?.value || '';
        const endDate = document.getElementById('sevTrendEndDate')?.value || '';
        const params = new URLSearchParams();
        if (startDate) params.append('start_date', startDate);
        if (endDate) params.append('end_date', endDate);

        const sevTrendResp = await fetch(`${API_BASE}/api/severity-trend-stats?${params.toString()}`);
        rawSevTrendData = await sevTrendResp.json();

        if (window.renderSevTrendChart) window.renderSevTrendChart();
    } catch (err) {
        console.error('Error loading sev trend data:', err);
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

    // Remove 0 count trend chart datasets
    allDatasets = allDatasets.filter(ds => Math.max(...ds.data) > 0);

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
            pointRadius: (ctx) => ctx.raw === 0 ? 0 : 4,
            pointHoverRadius: (ctx) => ctx.raw === 0 ? 0 : 6,
            pointBackgroundColor: baseColor
        };
    });

    if (vulnChartInstance) {
        vulnChartInstance.data.labels = rawTrendData.labels || [];
        vulnChartInstance.data.datasets = domainDatasets;
        vulnChartInstance.update('none');
    } else {
        vulnChartInstance = new Chart(vulnCtx, {
            type: 'line',
            data: {
                labels: rawTrendData.labels || [],
                datasets: domainDatasets
            },
            options: {
                interaction: {
                    mode: 'nearest',
                    intersect: true
                },
                onClick: (event, activeElements) => {
                    if (activeElements && activeElements.length > 0) {
                        const index = activeElements[0].index;
                        const datasetIndex = activeElements[0].datasetIndex;
                        const clickedValue = vulnChartInstance.data.datasets[datasetIndex].data[index];

                        if (rawTrendData && rawTrendData.raw_labels) {
                            let activeCount = 0;
                            let lastActiveLabel = null;
                            vulnChartInstance.data.datasets.forEach(ds => {
                                const val = ds.data[index] || 0;
                                if (val === clickedValue && val > 0) {
                                    activeCount++;
                                    lastActiveLabel = ds.label;
                                }
                            });

                            if (activeCount === 1) {
                                jumpToScanDetail(rawTrendData.raw_labels[index], lastActiveLabel);
                            } else if (activeCount > 1) {
                                showChartDetailModal(vulnChartInstance, index, "Vulnerabilities", rawTrendData.raw_labels[index], false, clickedValue);
                            }
                        }
                    }
                },
                responsive: true,
                maintainAspectRatio: false,
                layout: {
                    padding: {
                        top: 15,
                        right: 15
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grace: '5%',
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
                        labels: {
                            usePointStyle: true,
                            pointStyle: 'circle',
                            generateLabels: (chart) => {
                                return chart.data.datasets.map((dataset, i) => ({
                                    text: dataset.label,
                                    fillStyle: dataset.borderColor,
                                    hidden: !chart.isDatasetVisible(i),
                                    strokeStyle: dataset.borderColor,
                                    pointStyle: 'circle',
                                    datasetIndex: i
                                }));
                            }
                        },
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
                        filter: function (tooltipItem) {
                            return tooltipItem.parsed.y > 0;
                        },
                        callbacks: {
                            labelColor: function (context) {
                                return {
                                    borderColor: context.dataset.borderColor,
                                    backgroundColor: context.dataset.borderColor
                                };
                            },
                            label: function (context) {
                                let label = context.dataset.label || '';
                                if (context.parsed.y !== null) {
                                    return `${label} (${context.parsed.y})`;
                                }
                                return label;
                            }
                        }
                    }
                }
            }
        });
    }
};

window.renderSevTrendChart = function () {
    if (!rawSevTrendData) return;

    const sevCtx = document.getElementById('sevTrendChart').getContext('2d');

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
        'Critical': '#8A2E2E',
        'High': '#FF4A4A',
        'Medium': '#FF9F2A',
        'Low': '#4287F5',
        'Info': '#00D182'
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
                const { ctx, chartArea } = chart;
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
            pointRadius: (ctx) => ctx.raw === 0 ? 0 : 4,
            pointHoverRadius: (ctx) => ctx.raw === 0 ? 0 : 6,
            pointBackgroundColor: color,
            pointHoverBackgroundColor: color
        };
    });

    if (sevChartInstance) {
        sevChartInstance.data.labels = rawSevTrendData.labels || [];
        sevChartInstance.data.datasets = sevDatasets;
        sevChartInstance.update('none');
    } else {
        sevChartInstance = new Chart(sevCtx, {
            type: 'line',
            data: {
                labels: rawSevTrendData.labels || [],
                datasets: sevDatasets
            },
            options: {
                interaction: {
                    mode: 'nearest',
                    intersect: true
                },
                onClick: (event, activeElements) => {
                    if (activeElements && activeElements.length > 0) {
                        const index = activeElements[0].index;
                        const datasetIndex = activeElements[0].datasetIndex;
                        const clickedValue = sevChartInstance.data.datasets[datasetIndex].data[index];

                        if (rawSevTrendData && rawSevTrendData.raw_labels) {
                            let itemBreakdown = [];
                            sevChartInstance.data.datasets.forEach(ds => {
                                const val = ds.data[index] || 0;
                                if (val === clickedValue && val > 0) {
                                    if (ds.domains && ds.domains[index] && Object.keys(ds.domains[index]).length > 0) {
                                        const domainsMap = ds.domains[index];
                                        Object.keys(domainsMap).forEach(dName => {
                                            if (domainsMap[dName] > 0) {
                                                itemBreakdown.push({
                                                    severity: ds.label,
                                                    domain: dName,
                                                    count: domainsMap[dName],
                                                    color: ds.borderColor
                                                });
                                            }
                                        });
                                    } else {
                                        itemBreakdown.push({
                                            severity: ds.label,
                                            domain: null,
                                            count: val,
                                            color: ds.borderColor
                                        });
                                    }
                                }
                            });

                            if (itemBreakdown.length === 1) {
                                const item = itemBreakdown[0];
                                if (item.domain) {
                                    jumpToScanDetail(rawSevTrendData.raw_labels[index], item.domain, false);
                                } else {
                                    jumpToScanDetail(rawSevTrendData.raw_labels[index], item.severity, true);
                                }
                            } else if (itemBreakdown.length > 1) {
                                showSeverityDetailModal(itemBreakdown, sevChartInstance.data.labels[index], rawSevTrendData.raw_labels[index]);
                            }
                        }
                    }
                },
                responsive: true,
                maintainAspectRatio: false,
                layout: {
                    padding: {
                        top: 15,
                        right: 15
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grace: '5%',
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
                        labels: {
                            usePointStyle: true,
                            pointStyle: 'circle',
                            generateLabels: (chart) => {
                                return chart.data.datasets.map((dataset, i) => ({
                                    text: dataset.label,
                                    fillStyle: dataset.borderColor,
                                    hidden: !chart.isDatasetVisible(i),
                                    strokeStyle: dataset.borderColor,
                                    pointStyle: 'circle',
                                    datasetIndex: i
                                }));
                            }
                        },
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
                        filter: function (tooltipItem) {
                            return tooltipItem.parsed.y !== 0;
                        },
                        callbacks: {
                            labelColor: function (context) {
                                return {
                                    borderColor: context.dataset.borderColor,
                                    backgroundColor: context.dataset.borderColor
                                };
                            },
                            label: function (context) {
                                let label = context.dataset.label || '';
                                let val = context.parsed.y;
                                if (val !== null) {
                                    label += ` (${val})`;
                                }

                                let domainsObj = context.dataset.domains ? context.dataset.domains[context.dataIndex] : null;
                                if (val > 0 && domainsObj && typeof domainsObj === 'object') {
                                    let lines = [label];
                                    Object.entries(domainsObj).forEach(([d, count]) => {
                                        lines.push(`   • ${d} (${count})`);
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
    }
};

// Automated Pentests (Vulnerabilities View)
let vulnSortCol = 'date';
let vulnSortDesc = true;

function sortVulnHistory(col) {
    if (vulnSortCol === col) {
        vulnSortDesc = !vulnSortDesc;
    } else {
        vulnSortCol = col;
        vulnSortDesc = (col === 'date' || col === 'vulns');
    }
    applyVulnFilters();
}

function updateSortIcons() {
    const headers = document.querySelectorAll('#scanHistoryHeaders .sortable');
    headers.forEach(th => {
        const icon = th.querySelector('.sort-icon');
        if (icon) icon.innerHTML = '';
    });

    const activeMapping = { 'date': 0, 'domain': 1, 'type': 2, 'vulns': 3, 'severity': 4 };
    const activeIndex = activeMapping[vulnSortCol];

    if (activeIndex !== undefined) {
        const activeTh = document.querySelectorAll('#scanHistoryHeaders th')[activeIndex];
        if (activeTh) {
            const icon = activeTh.querySelector('.sort-icon');
            if (icon) icon.innerHTML = vulnSortDesc ? '↓' : '↑';
        }
    }
}

async function loadVulnerabilities(preservePage = false) {
    try {
        const resp = await fetch(`${API_BASE}/api/scan-history?limit=1000`);
        const data = await resp.json();
        allVulns = data.data || [];
        applyVulnFilters(preservePage);
        renderLowerGrid();
    } catch (err) {
        console.error('Error loading scans:', err);
    }
}

function applyVulnFilters(preservePage = false) {
    const startInput = document.getElementById('vulnStartDate')?.value;
    const endInput = document.getElementById('vulnEndDate')?.value;
    // Ambil kata kunci dari input pencarian
    const domainSearchInput = document.getElementById('vulnDomainSearch')?.value.toLowerCase();
    // Ambil nilai filter tipe scan
    const typeFilter = document.getElementById('vulnTypeFilter')?.value;

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

        // Filter berdasarkan tanggal
        if (startDate && scanDate < startDate) return false;
        if (endDate && scanDate > endDate) return false;

        // Filter berdasarkan pencarian nama domain
        if (domainSearchInput) {
            const domainName = (scan.domains?.domain_name || '').toLowerCase();
            if (!domainName.includes(domainSearchInput)) return false;
        }

        // Filter berdasarkan tipe scan
        if (typeFilter && typeFilter !== 'ALL') {
            let scanType = '';
            if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
                scanType = scan.vulnerabilities[0].check_type || '';
            }
            if (scanType.toLowerCase() !== typeFilter.toLowerCase()) return false;
        }

        return true;
    });

    filteredVulns.sort((a, b) => {
        // (Sisa kode sorting di bawahnya biarkan tetap sama persis seperti sebelumnya)
        let valA, valB;
        if (vulnSortCol === 'date') {
            valA = new Date(a.scan_date).getTime() || 0;
            valB = new Date(b.scan_date).getTime() || 0;
        } else if (vulnSortCol === 'domain') {
            valA = (a.domains?.domain_name || '').toLowerCase();
            valB = (b.domains?.domain_name || '').toLowerCase();
        } else if (vulnSortCol === 'type') {
            valA = (a.vulnerabilities && a.vulnerabilities.length > 0 && a.vulnerabilities[0].check_type || '').toLowerCase();
            valB = (b.vulnerabilities && b.vulnerabilities.length > 0 && b.vulnerabilities[0].check_type || '').toLowerCase();
        } else if (vulnSortCol === 'vulns') {
            valA = a.vulnerabilities ? a.vulnerabilities.length : 0;
            valB = b.vulnerabilities ? b.vulnerabilities.length : 0;
        } else if (vulnSortCol === 'severity') {
            const weights = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1, 'SAFE': 0 };
            valA = weights[(a.risk_level || 'SAFE').toUpperCase()] || 0;
            valB = weights[(b.risk_level || 'SAFE').toUpperCase()] || 0;
        }

        if (valA < valB) return vulnSortDesc ? 1 : -1;
        if (valA > valB) return vulnSortDesc ? -1 : 1;
        return 0;
    });

    updateSortIcons();

    if (!preservePage) {
        vulnCurrentPage = 1;
    }
    renderVulnerabilitiesList();
}

function resetVulnFilters() {
    const startInput = document.getElementById('vulnStartDate');
    const endInput = document.getElementById('vulnEndDate');
    const domainSearchInput = document.getElementById('vulnDomainSearch');
    const typeFilter = document.getElementById('vulnTypeFilter');

    if (startInput) startInput.value = '';
    if (endInput) endInput.value = '';
    if (domainSearchInput) domainSearchInput.value = '';
    if (typeFilter) typeFilter.value = 'ALL';

    applyVulnFilters();
}

function renderVulnerabilitiesList() {
    const container = document.getElementById('vulnListContainer');
    const paginationControls = document.getElementById('vulnPaginationControls');

    // Inisialisasi data filter jika baru pertama kali dimuat
    if (!filteredVulns) filteredVulns = [...allVulns];

    if (!filteredVulns || filteredVulns.length === 0) {
        container.innerHTML = `<tr><td colspan="4" class="empty-state">No scan history found for the selected filter.</td></tr>`;
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

        let scanType = "Unknown Scan";
        if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
            scanType = scan.vulnerabilities[0].check_type || "Unknown Scan";
        }

        return `
            <tr onclick="openScanModalIndex(${actualIndex})" style="cursor: pointer;">
                <td style="color:var(--text-secondary); font-weight:500;">${date}</td>
                <td><span style="color:var(--primary); font-weight:500;">${escapeHtml(domainName)}</span></td>
                <td style="color:var(--text-secondary); font-weight:500;">${escapeHtml(scanType)}</td>
                <td style="font-weight:600;">${numVulns} Vulns</td>
                <td><span class="badge badge-${sevClass}">${(scan.risk_level || 'SAFE').toUpperCase()}</span></td>
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

// =========================================================
// LOGIKA NETWORK SCANNER TERBARU
// =========================================================

function processNetworkScans(preservePage = false) {
    networkScans = allVulns.filter(scan => {
        if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
            const scanType = scan.vulnerabilities[0].check_type || "";
            return scanType.toLowerCase().includes("network");
        }
        return false;
    });

    applyNetworkFilters(preservePage);
}

function applyNetworkFilters(preservePage = false) {
    const searchInput = document.getElementById('netSearchInput')?.value.toLowerCase() || '';

    let dbFiltered = networkScans.filter(scan => {
        const domainName = (scan.domains?.domain_name || '').toLowerCase();
        const ip = (scan.domains?.ip_address || '').toLowerCase();
        if (searchInput && !domainName.includes(searchInput) && !ip.includes(searchInput)) return false;
        return true;
    });

    let liveFiltered = liveNetworkScans.filter(scan => {
        const domainName = (scan.domain || '').toLowerCase();
        if (searchInput && !domainName.includes(searchInput)) return false;
        return true;
    });

    filteredNetworkScans = [...liveFiltered, ...dbFiltered];

    if (!preservePage) {
        netCurrentPage = 1;
    }
    renderNetworkScans();
}

function renderNetworkScans() {
    const tbody = document.getElementById('networkScansTableBody');
    const paginationContainer = document.getElementById('networkPaginationControls');
    const thCount = document.getElementById('thNetworkScansCount');

    if (!filteredNetworkScans || filteredNetworkScans.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state" style="padding: 24px; text-align: center;">No network scans found.</td></tr>`;
        if (paginationContainer) paginationContainer.innerHTML = '';
        if (thCount) thCount.textContent = 'SCANS';
        return;
    }

    const totalItems = filteredNetworkScans.length;
    if (thCount) thCount.textContent = `SCANS`;

    const totalPages = Math.ceil(totalItems / netRowsPerPage) || 1;
    if (netCurrentPage > totalPages) netCurrentPage = totalPages;

    const startIdx = (netCurrentPage - 1) * netRowsPerPage;
    const endIdx = Math.min(startIdx + netRowsPerPage, totalItems);
    const paginatedScans = filteredNetworkScans.slice(startIdx, endIdx);

    tbody.innerHTML = paginatedScans.map((scan, mapIndex) => {
        const isLive = scan.live_status !== undefined;

        let domainName = '';
        let targetSubtitle = '';
        let dateStr = '-';
        let statusHtml = '';
        let summaryHtml = '';
        let actionBtn = '';
        let scanIdLabel = '';
        let actualIndex = -1;

        // ID UNIK & CEK MEMORI UNTUK CHECKBOX (Anti-Amnesia)
        const uniqueScanId = isLive ? `live_${scan.scan_id || mapIndex}` : `db_${scan.id}`;
        const isChecked = window.selectedNetworkScans && window.selectedNetworkScans.has(uniqueScanId) ? 'checked' : '';

        if (isLive) {
            domainName = scan.domain || 'Unknown Target';
            targetSubtitle = scan.target || "Scan in progress...";
            scanIdLabel = scan.type || `Pentest Tool ${scan.scan_id}`;
            const progressVal = scan.progress || 0;

            // Konversi Waktu (EEST ke WIB)
            if (scan.start_time) {
                let rawTime = scan.start_time;
                rawTime = rawTime.replace(' ', 'T');
                if (!rawTime.includes('+') && !rawTime.includes('Z')) {
                    rawTime += '+03:00';
                }
                const d = new Date(rawTime);
                if (!isNaN(d.getTime())) {
                    const year = d.getFullYear();
                    const month = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    const time = d.toLocaleString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                    dateStr = `${year}-${month}-${day} ${time}`;
                } else {
                    dateStr = scan.start_time;
                }
            }

            const radius = 14;
            const circumference = 2 * Math.PI * radius;
            const offset = circumference - (progressVal / 100) * circumference;

            statusHtml = `
                <div style="position: relative; width: 36px; height: 36px; display: flex; align-items: center; justify-content: center;">
                    <svg width="36" height="36" style="transform: rotate(-90deg);">
                        <circle cx="18" cy="18" r="14" fill="none" stroke="#e2e8f0" stroke-width="2"></circle>
                        <circle cx="18" cy="18" r="14" fill="none" stroke="#6366f1" stroke-width="2" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" stroke-linecap="round"></circle>
                    </svg>
                    <span style="position: absolute; font-size: 10px; font-weight: 600; color: #334155;">${progressVal}%</span>
                </div>
            `;
            summaryHtml = `<span style="color: #64748b; font-size: 13px;">${scan.live_status || 'running'}...</span>`;

            actionBtn = `<button class="btn btn-outline" onclick="stopActiveScan(${scan.scan_id})" style="border-color: #ef4444; color: #ef4444; background: rgba(239, 68, 68, 0.03);" onmouseover="this.style.background='#ef4444'; this.style.color='#ffffff';" onmouseout="this.style.background='rgba(239, 68, 68, 0.03)'; this.style.color='#ef4444';">Stop Scan</button>`;

            // STRUKTUR HTML LIVE ROW YANG SUDAH DIRAPIKAN
            return `
                <tr style="cursor: default; border-bottom: 1px solid #f1f5f9; background: #fafafa;">
                    <td style="text-align: center; padding: 16px;" onclick="event.stopPropagation();">
                        <input type="checkbox" value="${uniqueScanId}" ${isChecked} onchange="window.toggleNetworkCheckbox(event, this.value)" onclick="event.stopPropagation();" style="width: 16px; height: 16px; accent-color: var(--primary); cursor: pointer;">
                    </td>
                    <td style="padding: 16px; min-width: 140px;">
                        <div style="display:flex; align-items:center; gap:8px; color: #2563eb; font-weight: 500; font-size: 14px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                            ${scanIdLabel}
                        </div>
                    </td>
                    <td style="padding: 16px;">${statusHtml}</td>
                    <td style="padding: 16px;">
                        <div style="font-weight: 500; font-size: 13px; color: #334155; margin-bottom: 4px;">https://${escapeHtml(domainName)}/</div>
                        <div style="font-size: 13px; color: #94a3b8;">${escapeHtml(targetSubtitle)}</div>
                    </td>
                    <td style="padding: 16px; min-width: 120px;">${summaryHtml}</td>
                    <td style="padding: 16px; font-size: 13px; color: #64748b; white-space: nowrap;">${dateStr}</td>
                    <td style="padding: 16px; text-align:center;">${actionBtn}</td>
                </tr>
            `;

        } else {
            actualIndex = allVulns.indexOf(scan);
            domainName = scan.domains?.domain_name || 'Unknown Target';
            targetSubtitle = scan.domains?.ip_address || '-';
            scanIdLabel = 'Network Scanner';

            if (scan.scan_date) {
                const d = new Date(scan.scan_date);
                if (!isNaN(d.getTime())) {
                    dateStr = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${d.toLocaleString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
                }
            }

            statusHtml = `
                <div style="width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; background: #ecfdf5; border-radius: 50%; color: #10b981;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                </div>
            `;

            let crit = 0, high = 0, med = 0, low = 0;
            if (scan.vulnerabilities) {
                scan.vulnerabilities.forEach(v => {
                    const s = (v.severity || '').toUpperCase();
                    if (s === 'CRITICAL') crit++;
                    else if (s === 'HIGH') high++;
                    else if (s === 'MEDIUM') med++;
                    else if (s === 'LOW' || s === 'INFO') low++;
                });
            }
            summaryHtml = `
                <div style="display:flex; gap:6px;">
                    <span style="background:var(--sev-critical); color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:600; min-width:24px; text-align:center; display:inline-block;">${crit}</span>
                    <span style="background:var(--sev-high); color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:600; min-width:24px; text-align:center; display:inline-block;">${high}</span>
                    <span style="background:var(--sev-medium); color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:600; min-width:24px; text-align:center; display:inline-block;">${med}</span>
                    <span style="background:var(--sev-low); color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:600; min-width:24px; text-align:center; display:inline-block;">${low}</span>
                </div>
            `;

            actionBtn = `<button class="btn btn-outline" onclick="openScanModalIndex(${actualIndex}); event.stopPropagation();">View Report</button>`;

            // STRUKTUR HTML DATABASE ROW YANG SUDAH DIRAPIKAN
            return `
                <tr onclick="openScanModalIndex(${actualIndex})" style="cursor: pointer; border-bottom: 1px solid #f1f5f9; transition: background 0.2s;" onmouseover="this.style.background='#f8fafc'" onmouseout="this.style.background='transparent'">
                    <td style="text-align: center; padding: 16px;" onclick="event.stopPropagation();">
                        <input type="checkbox" value="${uniqueScanId}" ${isChecked} onchange="window.toggleNetworkCheckbox(event, this.value)" onclick="event.stopPropagation();" style="width: 16px; height: 16px; accent-color: var(--primary); cursor: pointer;">
                    </td>
                    <td style="padding: 16px; min-width: 140px;">
                        <div style="display:flex; align-items:center; gap:8px; color: #64748b; font-weight: 500; font-size: 14px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                            ${scanIdLabel}
                        </div>
                    </td>
                    <td style="padding: 16px;">${statusHtml}</td>
                    <td style="padding: 16px;">
                        <div style="font-weight: 500; font-size: 13px; color: #334155; margin-bottom: 4px;">https://${escapeHtml(domainName)}/</div>
                        <div style="font-size: 13px; color: #94a3b8;">${escapeHtml(targetSubtitle)}</div>
                    </td>
                    <td style="padding: 16px; min-width: 120px;">${summaryHtml}</td>
                    <td style="padding: 16px; font-size: 13px; color: #64748b; white-space: nowrap;">${dateStr}</td>
                    <td style="padding: 16px; text-align:left;" onclick="event.stopPropagation();">
                        ${actionBtn}
                    </td>
                </tr>
            `;
        }
    }).join('');

    if (paginationContainer) {
        // Berikan padding agar serasi dengan card tabel
        paginationContainer.style.padding = '16px 24px';

        paginationContainer.innerHTML = `
            <div class="pagination-left" style="display: flex; align-items: center;">
                <span style="font-size: 13px; color: #64748b;">Tampilkan per halaman:</span>
                <select onchange="window.changeNetRows(this.value)" style="margin-left: 8px; padding: 6px 12px; border-radius: 6px; border: 1px solid #cbd5e1; font-size: 13px; outline: none; background: white; color: #1e293b; cursor: pointer;">
                    <option value="10" ${netRowsPerPage === 10 ? 'selected' : ''}>10</option>
                    <option value="15" ${netRowsPerPage === 15 ? 'selected' : ''}>15</option>
                    <option value="25" ${netRowsPerPage === 25 ? 'selected' : ''}>25</option>
                    <option value="50" ${netRowsPerPage === 50 ? 'selected' : ''}>50</option>
                </select>
            </div>
            
            <div class="pagination-right" style="display: flex; align-items: center; gap: 12px;">
                <button class="btn btn-outline btn-sm" onclick="window.changeNetPage(${netCurrentPage - 1})" ${netCurrentPage === 1 ? 'disabled' : ''} style="padding: 6px 12px; min-width: auto; cursor: ${netCurrentPage === 1 ? 'not-allowed' : 'pointer'}; opacity: ${netCurrentPage === 1 ? '0.5' : '1'}; border-color: #cbd5e1; color: #475569;">Sebelumnya</button>
                
                <span style="font-size: 13px; font-weight: 500; color: #64748b; display: flex; align-items: center; gap: 4px;">
                    Halaman 
                    <input type="number" min="1" max="${totalPages}" value="${netCurrentPage}" onchange="window.changeNetPage(this.value)" onkeydown="if(event.key==='Enter') { this.blur(); window.changeNetPage(this.value); }" style="width: 45px; text-align: center; padding: 4px 6px; border-radius: 6px; border: 1px solid #cbd5e1; font-size: 13px; outline: none; background: white; color: #1e293b; margin: 0 4px;"> 
                    dari <span style="margin-left: 2px;">${totalPages}</span>
                </span>
                
                <button class="btn btn-outline btn-sm" onclick="window.changeNetPage(${netCurrentPage + 1})" ${netCurrentPage === totalPages ? 'disabled' : ''} style="padding: 6px 12px; min-width: auto; cursor: ${netCurrentPage === totalPages ? 'not-allowed' : 'pointer'}; opacity: ${netCurrentPage === totalPages ? '0.5' : '1'}; border-color: #cbd5e1; color: #475569;">Selanjutnya</button>
            </div>
        `;
    }
    window.syncNetworkSelectAll();
}

// Fungsi untuk mengganti halaman
window.changeNetPage = function (newPage) {
    const parsedPage = parseInt(newPage);
    if (!isNaN(parsedPage) && parsedPage >= 1) {
        netCurrentPage = parsedPage;
        renderNetworkScans();
    }
};

// Fungsi untuk mengubah jumlah baris
window.changeNetRows = function (newRows) {
    netRowsPerPage = parseInt(newRows);
    netCurrentPage = 1; // Kembalikan ke halaman 1 saat jumlah baris diubah
    renderNetworkScans();
};

// =========================================================
// MEMORI KOTAK CENTANG NETWORK SCANS & SELECT ALL
// =========================================================
window.selectedNetworkScans = new Set();

// 1. Fungsi saat klik checkbox satu per satu di baris
window.toggleNetworkCheckbox = function (e, scanId) {
    e.stopPropagation(); // Mencegah bentrok klik
    if (e.target.checked) {
        window.selectedNetworkScans.add(scanId); // Ingat
    } else {
        window.selectedNetworkScans.delete(scanId); // Lupakan
    }
    window.syncNetworkSelectAll(); // Cek apakah butuh centang "Select All"
};

// 2. Fungsi saat klik "Select All" di kepala tabel
window.toggleAllNetworkScans = function (headerCb) {
    // Ambil semua kotak centang yang sedang tampil di layar
    const rowCbs = document.querySelectorAll('#networkScansTableBody input[type="checkbox"]');
    const isChecked = headerCb.checked;

    rowCbs.forEach(cb => {
        cb.checked = isChecked; // Ubah visualnya
        if (isChecked) {
            window.selectedNetworkScans.add(cb.value); // Simpan semua ke memori
        } else {
            window.selectedNetworkScans.delete(cb.value); // Hapus semua dari memori
        }
    });
};

// 3. Fungsi untuk menyinkronkan status visual "Select All"
window.syncNetworkSelectAll = function () {
    const selectAllCb = document.getElementById('selectAllNetworkScans');
    const rowCbs = document.querySelectorAll('#networkScansTableBody input[type="checkbox"]');

    if (selectAllCb && rowCbs.length > 0) {
        // Jika SEMUA baris tercentang, maka Select All otomatis tercentang
        const allChecked = Array.from(rowCbs).every(cb => cb.checked);
        selectAllCb.checked = allChecked;
    } else if (selectAllCb) {
        selectAllCb.checked = false;
    }
};

// Render Lower Dashboard Grid (Recent Alerts & Monitored Domains)
function renderLowerGrid() {
    const alertsBody = document.getElementById('recentAlertsBody');
    const domainsList = document.getElementById('monitoredDomainsList');

    if (!allVulns || allVulns.length === 0) {
        if (alertsBody) alertsBody.innerHTML = `<tr><td colspan="5" class="empty-state">No alerts found.</td></tr>`;
        if (domainsList) domainsList.innerHTML = `<li class="domain-item" style="justify-content: center;"><span class="empty-state">No domains monitored.</span></li>`;
        return;
    }

    // 1. Process Recent Critical Alerts
    let allAlerts = [];
    allVulns.forEach((scan, scanIdx) => {
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
                        rawDate: scanDate,
                        vulnCount: scan.vulnerabilities.length,
                        globalIndex: scanIdx
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
            alertsBody.innerHTML = `<tr><td colspan="5" class="empty-state">No high/critical alerts.</td></tr>`;
        } else {
            alertsBody.innerHTML = topAlerts.map((alert, idx) => {
                const sevClass = getSeverityClass(alert.severity);
                return `
                    <tr onclick="openScanModalByGlobalIndex(${alert.globalIndex})" style="cursor: pointer;">
                        <td style="text-align: center; font-weight: 600;">${idx + 1}</td>
                        <td class="font-mono" style="font-size: 12px;">${escapeHtml(alert.target)}</td>
                        <td style="font-size: 12px; font-weight: 500;">${alert.vulnCount} Vulns</td>
                        <td><span class="badge badge-${sevClass}">${alert.severity}</span></td>
                        <td style="color: var(--color-muted-light); font-size: 12px;">${formatDate(alert.rawDate)}</td>
                    </tr>
                `;
            }).join('');
        }
    }

    const DOMAIN_RISK_WEIGHT = { 'CRITICAL': 6, 'HIGH': 5, 'MEDIUM': 4, 'LOW': 3, 'INFO': 2, 'SAFE': 1 };

    const domainMap = {};
    allVulns.forEach(scan => {
        const domainName = scan.domains?.domain_name || 'Unknown Target';
        const riskLevel = (scan.risk_level || 'SAFE').toUpperCase();
        const scanDate = new Date(scan.scan_date).getTime();

        if (!domainMap[domainName]) {
            domainMap[domainName] = {
                domain: domainName,
                risk: riskLevel,
                date: scanDate,
                ip: scan.domains?.ip_address || '-'
            };
        } else {
            // Gunakan tingkat risiko tertinggi yang pernah terdeteksi
            const currentWeight = DOMAIN_RISK_WEIGHT[domainMap[domainName].risk] || 0;
            const newWeight = DOMAIN_RISK_WEIGHT[riskLevel] || 0;
            if (newWeight > currentWeight) {
                domainMap[domainName].risk = riskLevel;
            }
            // Selalu perbarui tanggal ke scan yang paling baru
            if (scanDate > domainMap[domainName].date) {
                domainMap[domainName].date = scanDate;
                domainMap[domainName].ip = scan.domains?.ip_address || '-';
            }
        }
    });

    let uniqueDomains = Object.values(domainMap);

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
    const scan = allVulns[index];
    if (scan) {
        openScanModal(scan);
    }
}

function openScanModalByGlobalIndex(index) {
    const scan = allVulns[index];
    if (scan) {
        openScanModal(scan);
    }
}

// Inventory (Domains) & CRUD

const domainModalOverlay = document.getElementById('domainModalOverlay');
const domainForm = document.getElementById('domainForm');
const addDomainBtn = document.getElementById('addDomainBtn');
const closeDomainModalBtn = document.getElementById('closeDomainModalBtn');
const domainIdInput = document.getElementById('domainIdInput');
const domainNameInput = document.getElementById('domainNameInput');
const domainIpInput = document.getElementById('domainIpInput');
const domainErrorMsg = document.getElementById('domainErrorMsg');
const domainModalTitle = document.getElementById('domainModalTitle');

if (addDomainBtn) {
    addDomainBtn.addEventListener('click', () => {
        domainIdInput.value = '';
        domainNameInput.value = '';
        domainIpInput.value = '';
        domainErrorMsg.style.display = 'none';
        domainModalTitle.textContent = 'Tambah Domain';
        domainModalOverlay.classList.add('active');
    });
}

if (closeDomainModalBtn) {
    closeDomainModalBtn.addEventListener('click', () => {
        domainModalOverlay.classList.remove('active');
    });
}

function openEditDomainModal(domain) {
    domainIdInput.value = domain.id;
    domainNameInput.value = domain.domain_name;
    domainIpInput.value = domain.ip_address || '';
    domainErrorMsg.style.display = 'none';
    domainModalTitle.textContent = 'Edit Domain';
    domainModalOverlay.classList.add('active');
}

if (domainForm) {
    domainForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = domainIdInput.value;
        const payload = {
            domain_name: domainNameInput.value,
            ip_address: domainIpInput.value
        };

        try {
            const url = id ? `${API_BASE}/api/domains/${id}` : `${API_BASE}/api/domains`;
            const method = id ? 'PUT' : 'POST';
            const resp = await fetch(url, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await resp.json();

            if (resp.ok) {
                showToast('Sukses', data.message || 'Domain berhasil disimpan', '✅');
                domainModalOverlay.classList.remove('active');
                loadDomains();
            } else {
                domainErrorMsg.textContent = data.detail || 'Terjadi kesalahan';
                domainErrorMsg.style.display = 'block';
            }
        } catch (err) {
            domainErrorMsg.textContent = 'Koneksi error';
            domainErrorMsg.style.display = 'block';
        }
    });
}

async function deleteDomain(id) {
    if (!confirm('Yakin ingin menghapus domain ini?')) return;

    try {
        const resp = await fetch(`${API_BASE}/api/domains/${id}`, { method: 'DELETE' });
        const data = await resp.json();
        if (resp.ok) {
            showToast('Sukses', 'Domain berhasil dihapus', '✅');
            loadDomains();
        } else {
            showToast('Error', data.detail || 'Gagal menghapus domain', '❌');
        }
    } catch (err) {
        showToast('Error', 'Koneksi error', '❌');
    }
}

window.exportDomains = function (format) {
    if (!allDomains || allDomains.length === 0) {
        showToast('Info', 'Tidak ada domain untuk diekspor', 'ℹ️');
        return;
    }

    let content = '';
    let mimeType = '';
    let filename = '';

    const exportData = allDomains.map(d => ({
        domain_name: d.domain_name,
        ip_address: d.ip_address || ''
    }));

    content = JSON.stringify(exportData, null, 2);

    if (format === 'txt') {
        mimeType = 'text/plain';
        filename = 'domains_export.txt';
    } else if (format === 'json') {
        mimeType = 'application/json';
        filename = 'domains_export.json';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Sukses', `Berhasil mengekspor domain dalam format .${format.toUpperCase()}`, '✅');
};
async function loadDomains(preservePage = false) {
    try {
        const resp = await fetch(`${API_BASE}/api/domains`);
        const data = await resp.json();
        allDomains = data.data || [];
        if (!preservePage) {
            domainCurrentPage = 1;
        }
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
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No domains found.</td></tr>`;
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
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No domains match your search.</td></tr>`;
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
            <td style="text-align: center;">
                <div style="display: flex; align-items: center; justify-content: center; gap: 12px;">
                    <button class="icon-btn action-edit" onclick='openEditDomainModal(${JSON.stringify(d).replace(/'/g, "&#39;")})' title="Edit">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
                    </button>
                    <button class="icon-btn action-delete" onclick="deleteDomain(${d.id})" title="Hapus">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    </button>
                </div>
            </td>
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

    const runNetworkScanBtn = document.getElementById('runNetworkScanBtn');
    if (runNetworkScanBtn) {
        if (count > 0) {
            runNetworkScanBtn.disabled = false;
            runNetworkScanBtn.style.opacity = '1';
            runNetworkScanBtn.style.cursor = 'pointer';
        } else {
            runNetworkScanBtn.disabled = true;
            runNetworkScanBtn.style.opacity = '0.5';
            runNetworkScanBtn.style.cursor = 'not-allowed';
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

// Threat Modal
function openThreatModal(vuln) {
    document.getElementById('threatModalOverlay').classList.add('active');

    // Mengisi data inti
    document.getElementById('modalTitle').textContent = vuln.title || 'Vulnerability Alert';
    document.getElementById('modalRuleId').textContent = vuln.check_type || 'Unknown Scanner';
    document.getElementById('modalSeverity').textContent = vuln.severity || 'LOW';
    document.getElementById('modalSeverity').className = `meta-value text-${getSeverityClass(vuln.severity)}`;
    document.getElementById('modalDesc').textContent = vuln.description || 'No description available.';
    document.getElementById('modalRecommendation').textContent = vuln.recommendation || 'No recommendation provided.';

    // ==========================================
    // LOGIKA PENGKATEGORIAN OTOMATIS (ULTIMATE VERSION)
    // ==========================================
    const checkType = (vuln.check_type || '').toLowerCase();
    const titleLower = (vuln.title || '').toLowerCase();
    const threatSignature = checkType + " " + titleLower;

    const categoryBadge = document.getElementById('modalThreatCategory');
    if (categoryBadge) {
        let badgeText = 'Anomaly Detection';
        let badgeClass = 'badge badge-medium';

        // 1. CRITICAL EXPLOITS & INJECTIONS (Paling mematikan)
        if (threatSignature.includes('sql') || threatSignature.includes('injection') || threatSignature.includes('xss') || threatSignature.includes('cross-site scripting') || threatSignature.includes('rce') || threatSignature.includes('ssrf') || threatSignature.includes('xxe') || threatSignature.includes('command execution')) {
            badgeText = 'Critical Web Exploit';
            badgeClass = 'badge badge-critical'; // Merah gelap

            // 2. BROKEN ACCESS CONTROL & AUTHENTICATION
        } else if (threatSignature.includes('auth') || threatSignature.includes('credential') || threatSignature.includes('bypass') || threatSignature.includes('brute force') || threatSignature.includes('traversal') || threatSignature.includes('idor') || threatSignature.includes('default password')) {
            badgeText = 'Access Control Flaw';
            badgeClass = 'badge badge-high'; // Merah

            // 3. CROSS-SITE REQUEST FORGERY
        } else if (threatSignature.includes('csrf') || threatSignature.includes('cross-site request forgery')) {
            badgeText = 'CSRF Vulnerability';
            badgeClass = 'badge badge-high';

            // 4. VULNERABLE & OUTDATED COMPONENTS (CVEs)
        } else if (threatSignature.includes('cve-') || threatSignature.includes('outdated') || threatSignature.includes('vulnerabilities found for') || threatSignature.includes('deprecated') || threatSignature.includes('end-of-life') || threatSignature.includes('version')) {
            badgeText = 'Vulnerable Component';
            badgeClass = 'badge badge-high';

            // 5. SSL / TLS / CRYPTOGRAPHY FAILURES
        } else if (threatSignature.includes('ssl') || threatSignature.includes('tls') || threatSignature.includes('certificate') || threatSignature.includes('cipher') || threatSignature.includes('poodle') || threatSignature.includes('heartbleed') || threatSignature.includes('weak encryption')) {
            badgeText = 'Crypto & SSL Flaw';
            badgeClass = 'badge badge-medium'; // Oranye

            // 6. CMS SPECIFIC (WordPress, Joomla, Plugins)
        } else if (threatSignature.includes('wordpress') || threatSignature.includes('joomla') || threatSignature.includes('drupal') || threatSignature.includes('plugin') || threatSignature.includes('theme')) {
            badgeText = 'CMS Vulnerability';
            badgeClass = 'badge badge-medium';

            // 7. COOKIE & SESSION MANAGEMENT
        } else if (threatSignature.includes('cookie') || threatSignature.includes('httponly') || threatSignature.includes('secure flag') || threatSignature.includes('samesite') || threatSignature.includes('session')) {
            badgeText = 'Insecure Session/Cookie';
            badgeClass = 'badge badge-medium';

            // 8. SECURITY MISCONFIGURATION (Headers)
        } else if (threatSignature.includes('header') || threatSignature.includes('hsts') || threatSignature.includes('csp') || threatSignature.includes('clickjacking') || threatSignature.includes('cors') || threatSignature.includes('mime-sniffing')) {
            badgeText = 'Security Header Missing';
            badgeClass = 'badge badge-low'; // Biru muda

            // 9. INFORMATION DISCLOSURE
        } else if (threatSignature.includes('information') || threatSignature.includes('disclosure') || threatSignature.includes('leak') || threatSignature.includes('directory') || threatSignature.includes('error message') || threatSignature.includes('stack trace') || threatSignature.includes('phpinfo')) {
            badgeText = 'Information Disclosure';
            badgeClass = 'badge badge-low';

            // 10. DNS, MAIL, & INFRASTRUCTURE
        } else if (threatSignature.includes('dns') || threatSignature.includes('spf') || threatSignature.includes('dkim') || threatSignature.includes('dmarc') || threatSignature.includes('zone transfer') || threatSignature.includes('smtp') || threatSignature.includes('relay')) {
            badgeText = 'DNS/Mail Misconfig';
            badgeClass = 'badge badge-info'; // Hijau/Biru Info

            // 11. NETWORK VULNERABILITY (Pastikan di bawah, menggunakan \b agar akurat)
        } else if (threatSignature.includes('network ') || /\bport\b/.test(threatSignature) || threatSignature.includes('tcp') || threatSignature.includes('udp') || threatSignature.includes('ftp') || threatSignature.includes('ssh')) {
            badgeText = 'Network Vulnerability';
            badgeClass = 'badge badge-high';

            // 12. DEFAULT FALLBACK
        } else {
            badgeText = 'Web Vulnerability';
            badgeClass = 'badge badge-medium';
        }

        categoryBadge.textContent = badgeText;
        categoryBadge.className = badgeClass;
    }

    // 2. Threat Type (Format snake_case)
    let threatTypeStr = checkType.replace(/\s+/g, '_') || 'unknown_threat';
    const typeBadge = document.getElementById('modalThreatType');
    if (typeBadge) typeBadge.textContent = threatTypeStr;

    // 3. Program Pemindai
    // Kita gunakan regex agar 'network' deteksinya lebih aman
    const programName = (threatSignature.includes('network ') || /\bport\b/.test(threatSignature)) ? 'network-scanner' : 'web-scanner';
    const progBadge = document.getElementById('modalProgramName');
    if (progBadge) progBadge.textContent = programName;

    // Mock data for evidence logs
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

// Scan Modal
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

    let scanType = "Unknown Scan";
    if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
        scanType = scan.vulnerabilities[0].check_type || "Unknown Scan";
    }
    const typeEl = document.getElementById('scanModalType');
    if (typeEl) {
        typeEl.textContent = scanType;
    }

    const btnDownload = document.getElementById('btnDownloadReport');
    if (btnDownload && domainName && currentUser && currentUser.role === 'admin') {
        // Open Generate Report Modal instead of directly downloading
        btnDownload.removeAttribute('href');
        btnDownload.removeAttribute('target');
        btnDownload.onclick = (e) => {
            e.preventDefault();
            openGenerateReportModal(scan.id);
        };
        btnDownload.style.display = 'inline-flex';
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

// Helpers
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

// Authentication & Session Management (Admin Restricted Registration)
let autoRefreshInterval = null;
let wsLive = null;
let currentUser = null;
let allNotifications = [];

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

    // Reset form login & OTP
    document.getElementById('authForm').style.display = 'block';
    document.getElementById('otpForm').style.display = 'none';
    const otpInput = document.getElementById('authOtp');
    if (otpInput) otpInput.value = '';
    const errorMsg = document.getElementById('authErrorMsg');
    if (errorMsg) errorMsg.style.display = 'none';

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

    // Setup Topbar User Profile
    const topbarProfile = document.getElementById('topbar-user-profile');
    if (topbarProfile) {
        if (user.role === 'admin') {
            topbarProfile.textContent = 'Admin DSTI';
        } else {
            topbarProfile.textContent = user.username;
        }
    }
    const roleEl = document.getElementById('sidebar-user-role');
    if (user.role === 'admin') {
        document.getElementById('sidebar-user-role').innerHTML = `<span class="badge-admin-role">Admin</span>`;
        document.getElementById('nav-admin').style.display = 'flex';
        document.getElementById('notifWrapper').style.display = 'block';

        // Tampilkan menu khusus admin
        const navInventory = document.querySelector('[onclick="switchView(\'inventory\')"]');
        const navWebScanner = document.querySelector('[onclick="switchView(\'web-scanner\')"]');
        const navNetworkScanner = document.querySelector('[onclick="switchView(\'network-scanner\')"]');
        if (navInventory) navInventory.style.display = 'flex';
        if (navWebScanner) navWebScanner.style.display = 'flex';
        if (navNetworkScanner) navNetworkScanner.style.display = 'flex';

        fetchNotifications();
    } else {
        roleEl.innerHTML = `<span class="badge-user-role">User</span>`;
        document.getElementById('nav-admin').style.display = 'none';
        document.getElementById('notifWrapper').style.display = 'none';

        // Sembunyikan menu dari user biasa
        const navInventory = document.querySelector('[onclick="switchView(\'inventory\')"]');
        const navWebScanner = document.querySelector('[onclick="switchView(\'web-scanner\')"]');
        const navNetworkScanner = document.querySelector('[onclick="switchView(\'network-scanner\')"]');
        if (navInventory) navInventory.style.display = 'none';
        if (navWebScanner) navWebScanner.style.display = 'none';
        if (navNetworkScanner) navNetworkScanner.style.display = 'none';

        // Jika user berada di halaman terlarang, kembalikan ke overview
        const activeNav = document.querySelector('.sidebar-nav .nav-item.active');
        if (activeNav) {
            const attr = activeNav.getAttribute('onclick') || '';
            if (attr.includes('admin') || attr.includes('inventory') || attr.includes('web-scanner') || attr.includes('network-scanner')) {
                switchView('overview');
            }
        }
    }

    // Hubungkan WebSocket Live Session untuk semua user (baik admin maupun user biasa)
    connectLiveWebSocket(user.session_id);

    // Clean inputs
    document.getElementById('authUsername').value = '';
    document.getElementById('authPassword').value = '';
    document.getElementById('authErrorMsg').style.display = 'none';

    refreshData();
    loadOverview(); // Load the overview/charts at least once on startup

    // Mulai refresh otomatis 5 detik HANYA setelah sukses login
    if (autoRefreshInterval) clearInterval(autoRefreshInterval);
    autoRefreshInterval = setInterval(() => refreshData(true), 5000);
}

async function handleAuthSubmit(e) {
    e.preventDefault();
    const username = document.getElementById('authUsername').value.trim();
    const password = document.getElementById('authPassword').value;
    const rememberMe = document.getElementById('rememberMe').checked; // Ambil nilai checkbox
    const errMsg = document.getElementById('authErrorMsg');
    const submitBtn = document.getElementById('authSubmitBtn');

    // === AMBIL TOKEN RECAPTCHA ===
    const recaptchaToken = grecaptcha.getResponse();

    if (!recaptchaToken) {
        errMsg.innerText = "Harap selesaikan verifikasi reCAPTCHA.";
        errMsg.style.display = 'block';
        return;
    }

    errMsg.style.display = 'none';

    // Kunci tombol saat memproses
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'Memverifikasi...';
    submitBtn.style.opacity = '0.7';
    submitBtn.disabled = true;

    try {
        const resp = await fetch(`${API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: username,
                password: password,
                recaptcha_token: recaptchaToken,
                remember_me: rememberMe // Kirim data remember me ke backend
            })
        });
        const data = await resp.json();

        if (resp.status === 200) {
            if (data.status === "otp_required") {
                // Sembunyikan form login, tampilkan form OTP
                document.getElementById('authForm').style.display = 'none';
                document.getElementById('otpForm').style.display = 'block';
                showToast("Info", data.message, "📧");
            } else {
                handleSuccessfulLogin(data);
            }
        } else {
            errMsg.innerText = data.detail || "Email atau password salah.";
            errMsg.style.display = 'block';
            grecaptcha.reset(); // Reset reCAPTCHA agar bisa dicentang lagi
        }
    } catch (err) {
        errMsg.innerText = "Koneksi ke server gagal atau server error.";
        errMsg.style.display = 'block';
        grecaptcha.reset();
    } finally {
        submitBtn.textContent = 'Login';
        submitBtn.style.opacity = '1';
        submitBtn.disabled = false;
    }
}

// Global state untuk menyimpan username sementara sebelum OTP divalidasi
let pendingUsername = '';
let pendingRememberMe = false;

async function handleOtpSubmit(e) {
    e.preventDefault();
    const otpInput = document.getElementById('authOtp').value.trim();
    const submitBtn = document.getElementById('otpSubmitBtn');
    const errMsg = document.getElementById('authErrorMsg');

    errMsg.style.display = 'none';

    // Username dan rememberMe diambil dari form sebelumnya
    const username = document.getElementById('authUsername').value.trim();
    const rememberMe = document.getElementById('rememberMe').checked;

    submitBtn.textContent = 'Memverifikasi...';
    submitBtn.style.opacity = '0.7';
    submitBtn.disabled = true;

    try {
        const resp = await fetch(`${API_BASE}/api/auth/verify_otp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: username,
                otp: otpInput,
                remember_me: rememberMe
            })
        });
        const data = await resp.json();

        if (resp.status === 200) {
            // Sembunyikan pesan sukses
            showToast("Sukses", "Verifikasi berhasil.", "✅");

            // Lakukan login
            document.getElementById('otpForm').style.display = 'none';
            document.getElementById('authForm').style.display = 'block';

            handleSuccessfulLogin(data);
        } else {
            errMsg.innerText = data.detail || "Kode OTP salah.";
            errMsg.style.display = 'block';
        }
    } catch (err) {
        errMsg.innerText = "Koneksi ke server gagal atau server error.";
        errMsg.style.display = 'block';
    } finally {
        submitBtn.textContent = 'Verifikasi OTP';
        submitBtn.style.opacity = '1';
        submitBtn.disabled = false;
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
let isSessionExpiredToastShown = false;
const originalFetch = window.fetch.bind(window);
window.fetch = async function (...args) {
    // Pastikan kredensial (cookie) selalu dikirim
    if (args.length === 1 && (typeof args[0] === 'string' || args[0] instanceof URL)) {
        args.push({ credentials: 'include' });
    } else if (args.length === 2) {
        if (!args[1]) args[1] = {};
        if (!args[1].credentials) args[1].credentials = 'include';
    }
    const response = await originalFetch(...args);
    if (response.status === 401 && !args[0].includes('/api/auth/me') && !args[0].includes('/api/auth/login')) {
        showLoginOverlay();
        // Notifikasi "Sesi Berakhir" dinonaktifkan sesuai permintaan
    }
    return response;
};

// Admin Panel: User Creation Modal & CRUD Handlers
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
            loadAdminUsers();
            fetchNotifications(); // Refresh daftar user
        } else {
            errMsg.textContent = data.detail || "Gagal membuat user baru.";
            errMsg.style.display = 'block';
        }
    } catch (err) {
        errMsg.textContent = "Gagal menghubungi server.";
        errMsg.style.display = 'block';
    }
}

// Global variables for user management state
let allAdminUsers = [];
let filteredAdminUsers = [];
let userCurrentPage = 1;
let userRowsPerPage = 10;
let currentTimeoutUser = null;

// Admin Panel: User Table List & Control Actions
async function loadAdminUsers() {
    const tbody = document.getElementById('userTableBody');
    try {
        const resp = await fetch(`${API_BASE}/api/admin/users`);
        const result = await resp.json();

        if (resp.status === 200) {
            allAdminUsers = result.data || [];
            applyUserFilters();
        } else {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state text-danger">${result.detail || 'Gagal memuat daftar user.'}</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state text-danger">Gagal menghubungi server.</td></tr>`;
    }
}

window.applyUserFilters = function (preservePage = false) {
    const searchVal = (document.getElementById('userSearchInput')?.value || '').toLowerCase();

    filteredAdminUsers = allAdminUsers.filter(u => {
        if (!searchVal) return true;
        return (u.username && u.username.toLowerCase().includes(searchVal)) ||
            (u.role && u.role.toLowerCase().includes(searchVal));
    });

    // Sort logic: 
    // 1. Role: 'admin' > 'user'
    // 2. Status: online > offline
    // 3. Last Active: recent > older
    // 4. Username: A-Z
    filteredAdminUsers.sort((a, b) => {
        if (a.role === 'admin' && b.role !== 'admin') return -1;
        if (a.role !== 'admin' && b.role === 'admin') return 1;

        const aOnline = a.is_online ? 1 : 0;
        const bOnline = b.is_online ? 1 : 0;
        if (aOnline !== bOnline) return bOnline - aOnline;

        const timeA = new Date(a.last_online || 0).getTime();
        const timeB = new Date(b.last_online || 0).getTime();
        if (timeA !== timeB) return timeB - timeA;

        const nameA = (a.username || '').toLowerCase();
        const nameB = (b.username || '').toLowerCase();
        return nameA.localeCompare(nameB);
    });

    if (!preservePage) {
        userCurrentPage = 1;
    }
    renderUserTable();
};

window.changeUserPage = function (delta) {
    const totalPages = Math.ceil(filteredAdminUsers.length / userRowsPerPage) || 1;
    let newPage = userCurrentPage + delta;
    if (newPage < 1) newPage = 1;
    if (newPage > totalPages) newPage = totalPages;
    if (newPage !== userCurrentPage) {
        userCurrentPage = newPage;
        renderUserTable();
    }
};

window.changeUserRowsPerPage = function () {
    const select = document.getElementById('userRowsSelect');
    if (!select) return;
    userRowsPerPage = parseInt(select.value, 10);
    userCurrentPage = 1;
    renderUserTable();
};

window.jumpUserPage = function () {
    const input = document.getElementById('userPageInput');
    if (!input) return;
    let page = parseInt(input.value, 10);
    const totalPages = Math.ceil(filteredAdminUsers.length / userRowsPerPage) || 1;
    if (isNaN(page) || page < 1) page = 1;
    if (page > totalPages) page = totalPages;
    userCurrentPage = page;
    renderUserTable();
};

function renderUserPagination(totalItems) {
    const container = document.getElementById('userPaginationControls');
    if (!container) return;

    if (totalItems === 0) {
        container.style.display = 'none';
        return;
    }

    container.style.display = 'flex';
    const totalPages = Math.ceil(totalItems / userRowsPerPage) || 1;

    const prevBtn = document.getElementById('userPrevPageBtn');
    const nextBtn = document.getElementById('userNextPageBtn');
    const pageInput = document.getElementById('userPageInput');
    const totalPagesSpan = document.getElementById('userTotalPages');

    if (prevBtn) prevBtn.disabled = (userCurrentPage === 1);
    if (nextBtn) nextBtn.disabled = (userCurrentPage === totalPages);
    if (pageInput) {
        pageInput.value = userCurrentPage;
        pageInput.max = totalPages;
    }
    if (totalPagesSpan) totalPagesSpan.textContent = totalPages;
}

function renderUserTable() {
    const tbody = document.getElementById('userTableBody');
    if (!filteredAdminUsers || filteredAdminUsers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Tidak ada user terdaftar.</td></tr>`;
        renderUserPagination(0);
        return;
    }

    const totalItems = filteredAdminUsers.length;
    const totalPages = Math.ceil(totalItems / userRowsPerPage) || 1;
    if (userCurrentPage > totalPages) userCurrentPage = totalPages;

    const startIdx = (userCurrentPage - 1) * userRowsPerPage;
    const endIdx = Math.min(startIdx + userRowsPerPage, totalItems);
    const paginatedUsers = filteredAdminUsers.slice(startIdx, endIdx);

    tbody.innerHTML = paginatedUsers.map(u => {
        const isSelf = u.username === currentUser.username;
        const roleBadge = u.role === 'admin'
            ? `<span class="badge-admin-role">Admin</span>`
            : `<span class="badge-user-role">User</span>`;

        const isOnline = u.is_online;
        const lastActiveText = u.is_online ? "Baru saja" : formatRelativeTime(u.last_online);

        // Logika check timeout
        let isTimedOut = false;
        let timeoutText = '';
        if (u.timeout_until) {
            const timeoutDate = new Date(u.timeout_until);
            const now = new Date();
            if (timeoutDate > now) {
                isTimedOut = true;
                const diffSecs = Math.floor((timeoutDate - now) / 1000);
                const mins = Math.floor(diffSecs / 60);
                const secs = diffSecs % 60;
                timeoutText = ` (Sisa ${mins}m ${secs}s)`;
            }
        }

        let statusBadge = '';
        if (isOnline) {
            statusBadge = `<span class="status-indicator status-online">Online</span>`;
        } else if (isTimedOut) {
            statusBadge = `<span class="status-indicator status-timeout">Timeout</span>`;
        } else {
            statusBadge = `<span class="status-indicator status-offline">Offline</span>`;
        }

        let actionButtons = '';
        if (isSelf) {
            actionButtons = `<span style="color:var(--text-tertiary); font-style:italic;">Akun Anda</span>`;
        } else if (isTimedOut) {
            actionButtons = `
                <div style="display: flex; flex-direction: column; gap: 4px; justify-content: center;">
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <button class="btn-timeout" style="border-color:#22c55e; color:#22c55e; margin: 0;" onclick="triggerRemoveTimeout('${u.username}')">Cabut Timeout</button>
                        <button class="btn-delete-user" style="margin: 0;" onclick="triggerDeleteUser('${u.username}')">Hapus</button>
                    </div>
                    <span style="font-size: 11px; color: #ef4444; font-weight: 500; margin-left: 2px;">${timeoutText.trim()}</span>
                </div>
            `;
        } else {
            actionButtons = `
                <div style="display: flex; gap: 8px; align-items: center;">
                    <button class="btn-force-logout" style="margin: 0;" onclick="triggerForceLogout('${u.username}')">Force Logout</button>
                    <button class="btn-timeout" style="margin: 0;" onclick="openTimeoutModal('${u.username}')">Timeout</button>
                    <button class="btn-delete-user" style="margin: 0;" onclick="triggerDeleteUser('${u.username}')">Hapus</button>
                </div>
            `;
        }

        return `
            <tr>
                <td style="font-weight:500;">
                    ${escapeHtml(u.username)}
                    ${isSelf ? '<span style="font-size:10px; color:var(--text-tertiary); margin-left:6px;">(You)</span>' : ''}
                </td>
                <td>${roleBadge}</td>
                <td>${statusBadge}</td>
                <td style="font-size:13px; color:var(--text-secondary);">${lastActiveText}</td>
                <td>${actionButtons}</td>
            </tr>
        `;
    }).join('');

    renderUserPagination(totalItems);
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
            fetchNotifications();
        } else {
            alert(data.detail || "Gagal melakukan force logout.");
        }
    } catch (err) {
        alert("Gagal menghubungi server.");
    }
}

window.openTimeoutModal = function (username) {
    currentTimeoutUser = username;
    document.getElementById('timeoutMinutesInput').value = 30; // default 30 menit
    const modal = document.getElementById('timeoutActionModalOverlay');
    if (modal) modal.classList.add('active');
};

window.closeTimeoutModal = function () {
    currentTimeoutUser = null;
    const modal = document.getElementById('timeoutActionModalOverlay');
    if (modal) modal.classList.remove('active');
};

window.submitTimeout = async function () {
    if (!currentTimeoutUser) return;
    const minutesVal = document.getElementById('timeoutMinutesInput').value;
    const minutes = parseInt(minutesVal, 10);

    if (isNaN(minutes) || minutes < 1) {
        alert("Masukkan durasi menit yang valid (minimal 1).");
        return;
    }

    try {
        const resp = await fetch(`${API_BASE}/api/admin/users/${currentTimeoutUser}/timeout`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ minutes: minutes })
        });
        const data = await resp.json();

        if (resp.status === 200) {
            showToast("User Ditangguhkan", `User '${currentTimeoutUser}' ditangguhkan selama ${minutes} menit.`, "⏳");
            loadAdminUsers();
            fetchNotifications();
        } else {
            alert(data.detail || "Gagal melakukan penangguhan.");
        }
    } catch (err) {
        alert("Gagal menghubungi server.");
    }
};

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
            fetchNotifications();
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
            fetchNotifications();
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

        if (diffMins < 1) return 'Baru saja';
        if (diffMins < 60) return `${diffMins} menit yang lalu`;

        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours} jam yang lalu`;

        return d.toLocaleDateString('id-ID', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
    } catch {
        return '-';
    }
}

// YouTube-Style Notification Dropdown Logic & Rendering
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


async function markAllNotificationsAsRead(e) {
    if (e) e.stopPropagation();

    if (allNotifications.length === 0) return;

    if (!confirm("Apakah Anda yakin ingin menghapus semua notifikasi?")) {
        return;
    }

    try {
        const deletedNotifs = JSON.parse(localStorage.getItem('dsti_deleted_notifs_v3') || '[]');
        allNotifications.forEach(n => {
            if (!deletedNotifs.includes(n.id)) deletedNotifs.push(n.id);
        });
        localStorage.setItem('dsti_deleted_notifs_v3', JSON.stringify(deletedNotifs));

        allNotifications = [];
        renderNotificationList();
        showToast("Notifikasi", "Semua notifikasi dibersihkan.", "✔️");
    } catch (e) { }
}

async function deleteNotification(notifId, e) {
    if (e) e.stopPropagation();

    try {
        const deletedNotifs = JSON.parse(localStorage.getItem('dsti_deleted_notifs_v3') || '[]');
        if (!deletedNotifs.includes(notifId)) deletedNotifs.push(notifId);
        localStorage.setItem('dsti_deleted_notifs_v3', JSON.stringify(deletedNotifs));

        allNotifications = allNotifications.filter(n => n.id !== notifId);
        renderNotificationList();
    } catch (err) {
        console.error("Gagal menghapus notifikasi:", err);
    }
}


async function fetchNotifications() {
    try {
        const res = await fetch('/api/notifications');
        const data = await res.json();
        if (data.status === 'success') {
            const allowedTypes = ['success', 'scan_complete', 'scan_finished'];
            const deletedNotifs = JSON.parse(localStorage.getItem('dsti_deleted_notifs_v3') || '[]');
            const readNotifs = JSON.parse(localStorage.getItem('dsti_read_notifs') || '[]');

            allNotifications = data.data
                .filter(n => allowedTypes.includes(n.type) && !deletedNotifs.includes(n.id))
                .map(n => ({
                    id: n.id,
                    title: n.title,
                    message: n.message,
                    type: n.type,
                    timestamp: n.created_at,
                    unread: !n.is_read && !readNotifs.includes(n.id),
                    domain: n.domain,
                    time: n.time || n.created_at
                }));
            renderNotificationList();
        }
    } catch (e) {
        console.error('Gagal fetch notifikasi', e);
    }
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
        const unreadClass = n.unread ? 'unread' : '';
        const relativeTime = formatRelativeTime(n.timestamp);
        let icon = '🔔';
        if (n.type === 'scan_complete' || n.type === 'success') icon = '✅';
        else if (n.type === 'scan_failed') icon = '❌';
        else if (n.type === 'user_login') icon = '👤';
        else if (n.type === 'scan_finished') icon = '🚀';

        let absoluteTime = '';
        if (n.timestamp) {
            const dateObj = new Date(n.timestamp);
            if (!isNaN(dateObj)) {
                const dateOpts = { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' };
                absoluteTime = dateObj.toLocaleString('id-ID', dateOpts);
            }
        }

        return `
            <div class="notif-item ${unreadClass}" onclick="markAsRead('${n.id}')">
                <div class="notif-unread-dot"></div>
                <div class="notif-avatar" style="background: transparent; font-size: 20px;">${icon}</div>
                <div class="notif-content">
                    <div class="notif-text" style="line-height: 1.4;"><strong>${escapeHtml(n.title)}</strong><br>${escapeHtml(n.message)}</div>
                    <div class="notif-time" style="margin-top: 4px;">${relativeTime} ${absoluteTime ? `(${absoluteTime})` : ''}</div>
                </div>
                <div class="notif-actions">
                    <button class="notif-action-btn" onclick="deleteNotification('${n.id}', event)" title="Hapus notifikasi">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="3 6 5 6 21 6"></polyline>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                        </svg>
                    </button>
                </div>
            </div>
        `;
    }).join('');

}

async function markAsRead(notifId) {
    const notif = allNotifications.find(n => n.id === notifId);
    if (!notif) return;

    // Tandai sebagai read, jangan dihapus
    const readNotifs = JSON.parse(localStorage.getItem('dsti_read_notifs') || '[]');
    if (!readNotifs.includes(notifId)) readNotifs.push(notifId);
    localStorage.setItem('dsti_read_notifs', JSON.stringify(readNotifs));

    notif.unread = false;
    renderNotificationList();

    // Tindakan spesifik ketika notifikasi diklik
    if (notif) {
        if (notif.type === 'scan_finished') {
            // Tutup dropdown notifikasi (jika terbuka)
            const dropdown = document.getElementById('notificationDropdown');
            if (dropdown) dropdown.style.display = 'none';

            // Refresh data dari backend agar scan terbaru termuat ke memori (allVulns)
            await loadVulnerabilities(true);

            // Cari dan buka detail
            jumpToScanDetail(notif.time, notif.domain, false);
        } else {
            // Tampilkan info basic saja untuk login user
            showToast("Info Notifikasi", `Terkait user: ${notif.username || '-'}`, "ℹ️");
        }
    }
}

// WebSockets Client
function connectLiveWebSocket(sessionId) {
    if (wsLive) {
        wsLive.close();
    }

    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProto}//${window.location.host}/ws/live?session_id=${sessionId}`;
    // const wsUrl = `ws://10.70.128.26:8000/ws/live?session_id=${sessionId}`;

    wsLive = new WebSocket(wsUrl);

    wsLive.onopen = () => {
        console.log("[WebSocket] Terkoneksi ke Live Session.");
    };

    wsLive.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);


            if (data.event === 'new_notification') {
                if (currentUser && currentUser.role === 'admin') {
                    showToast(
                        data.notification.title,
                        data.notification.message,
                        "🔔"
                    );
                    fetchNotifications();
                }
            } else if (data.event === 'user_login') {
                if (currentUser && currentUser.role === 'admin' && data.username !== currentUser.username) {
                    const activeNav = document.querySelector('.sidebar-nav .nav-item.active');
                    if (activeNav && activeNav.getAttribute('onclick').includes('admin')) {
                        loadAdminUsers();
                        fetchNotifications();
                    }
                }
            } else if (data.event === 'scan_finished') {
                // Refresh data if needed, but new_notification already handles the toast and notification list.
                if (typeof fetchActiveScans === 'function') fetchActiveScans();
                if (typeof refreshData === 'function') refreshData(true);
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

// Generate Report Modal
function openGenerateReportModal(historyId) {
    document.getElementById('reportHistoryId').value = historyId;
    document.getElementById('generateReportModalOverlay').classList.add('active');
}

document.getElementById('closeGenerateReportModalBtn')?.addEventListener('click', () => {
    document.getElementById('generateReportModalOverlay').classList.remove('active');
});

document.getElementById('btnCancelReport')?.addEventListener('click', () => {
    document.getElementById('generateReportModalOverlay').classList.remove('active');
});

let currentReportPayload = null;
let currentReportAction = 'download';

document.getElementById('generateReportForm')?.addEventListener('submit', (e) => {
    e.preventDefault();
    const historyId = document.getElementById('reportHistoryId').value;
    if (!historyId) return;

    const form = e.target;

    currentReportPayload = {
        history_id: parseInt(historyId),
        report_type: form.report_type.value,
        report_format: form.report_format.value,
        group_findings_by: form.group_by.value,
        include_reproduce: form.filter_reproduce.checked,
        include_informational: form.filter_informational.checked,
        include_false_positives: form.filter_false_positives.checked,
        include_ignored: form.filter_ignored.checked,
        include_not_verified: form.filter_not_verified.checked,
        include_accepted: form.filter_accepted.checked,
        include_fixed: form.filter_fixed.checked
    };

    document.getElementById('generateReportModalOverlay').classList.remove('active');

    // Reset state & show report action modal
    setReportAction('download');
    document.getElementById('reportActionModalOverlay').classList.add('active');
});

function setReportAction(action) {
    currentReportAction = action;
    const cardDownload = document.getElementById('cardDownloadOption');
    const cardShare = document.getElementById('cardShareOption');
    const emailContainer = document.getElementById('emailInputsContainer');
    const btnProcess = document.getElementById('btnProcessReportAction');

    if (action === 'download') {
        cardDownload.style.borderColor = 'var(--primary)';
        cardDownload.style.background = '#f8fafc';
        cardDownload.querySelector('svg').style.color = 'var(--primary)';

        cardShare.style.borderColor = 'var(--color-border)';
        cardShare.style.background = '#ffffff';
        cardShare.querySelector('svg').style.color = 'var(--color-muted)';

        emailContainer.style.display = 'none';
        btnProcess.textContent = 'Download';
    } else {
        cardShare.style.borderColor = 'var(--primary)';
        cardShare.style.background = '#f8fafc';
        cardShare.querySelector('svg').style.color = 'var(--primary)';

        cardDownload.style.borderColor = 'var(--color-border)';
        cardDownload.style.background = '#ffffff';
        cardDownload.querySelector('svg').style.color = 'var(--color-muted)';

        emailContainer.style.display = 'block';
        btnProcess.textContent = 'Kirim Email';
    }
}

document.getElementById('cardDownloadOption')?.addEventListener('click', () => setReportAction('download'));
document.getElementById('cardShareOption')?.addEventListener('click', () => setReportAction('share'));

document.getElementById('closeReportActionModalBtn')?.addEventListener('click', () => {
    document.getElementById('reportActionModalOverlay').classList.remove('active');
});

function addEmailInputRow() {
    const wrapper = document.getElementById('emailListWrapper');
    const row = document.createElement('div');
    row.className = 'email-input-row';
    row.style.display = 'flex';
    row.style.gap = '8px';
    row.innerHTML = `
        <input type="email" class="auth-input email-recipient-input" placeholder="contoh@undip.ac.id" style="flex: 1; padding: 8px 12px; margin-bottom: 0;" required>
        <button type="button" class="btn btn-outline" onclick="this.parentElement.remove()" style="padding: 0 12px; border-color: #ef4444; color: #ef4444; height: 38px; display: flex; align-items: center;" title="Hapus">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
        </button>
    `;
    wrapper.appendChild(row);
}

document.getElementById('btnProcessReportAction')?.addEventListener('click', async () => {
    if (!currentReportPayload) return;

    const btnSubmit = document.getElementById('btnProcessReportAction');
    const originalText = btnSubmit.textContent;
    btnSubmit.innerHTML = 'Memproses...</span>';
    btnSubmit.disabled = true;
    btnSubmit.style.opacity = '0.7';

    try {
        if (currentReportAction === 'download') {
            const resp = await fetch(`${API_BASE}/api/reports/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(currentReportPayload)
            });

            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.detail || 'Gagal generate report');
            }

            const blob = await resp.blob();
            document.getElementById('reportActionModalOverlay').classList.remove('active');
            showToast('Success', 'Report successfully downloaded!', '✅');

            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            const formatExt = currentReportPayload.report_format.toLowerCase();
            a.download = `security_report_${currentReportPayload.history_id}.${formatExt}`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

        } else {
            // Share via Email
            const emailInputs = document.querySelectorAll('.email-recipient-input');
            const emails = Array.from(emailInputs).map(inp => inp.value.trim()).filter(v => v);

            if (emails.length === 0) {
                throw new Error("Masukkan setidaknya satu alamat email");
            }

            for (const email of emails) {
                if (!email.includes('@')) throw new Error(`Email tidak valid: ${email}`);
            }

            const sharePayload = { ...currentReportPayload, emails };

            const resp = await fetch(`${API_BASE}/api/reports/share`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(sharePayload)
            });

            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.detail || 'Gagal mengirim email');
            }

            const data = await resp.json();
            document.getElementById('reportActionModalOverlay').classList.remove('active');
            showToast('Success', data.message, '✅');
        }
    } catch (err) {
        console.error(err);
        showToast('Error', err.message, '❌');
    } finally {
        btnSubmit.textContent = originalText;
        btnSubmit.disabled = false;
        btnSubmit.style.opacity = '1';
    }
});

// --- Web Scanner Logic ---
let activeScansInterval = null;

function fetchActiveScans() {
    fetch(`${API_BASE}/api/scans/active`)
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const allLive = data.data || [];

                // Filter cerdas: ID 350 atau 385 adalah Network Scanner. Sisanya lempar ke Web Scanner.
                liveNetworkScans = allLive.filter(s => s.type.includes('350') || s.type.includes('385') || s.type.toLowerCase().includes('network'));
                liveWebScans = allLive.filter(s => !liveNetworkScans.includes(s));

                // Perbarui tabel Web Scans
                if (typeof applyWebFilters === 'function') applyWebFilters(true);

                // Panggil render Network Scans agar memunculkan progress Live
                if (typeof applyNetworkFilters === 'function') applyNetworkFilters(true);

            } else {
                const tbody = document.querySelector('#webScannerTable tbody');
                if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #ef4444;">Error: ${data.detail || 'Failed to fetch active scans.'}</td></tr>`;
            }
        })
        .catch(err => {
            console.error('Error fetching active scans:', err);
        });
}

// =========================================================
// LOGIKA WEB SCANNER TERBARU
// =========================================================

function processWebScans(preservePage = false) {
    webScans = allVulns.filter(scan => {
        if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
            const scanType = scan.vulnerabilities[0].check_type || "";
            return !scanType.toLowerCase().includes("network");
        }
        return false;
    });

    applyWebFilters(preservePage);
}

function applyWebFilters(preservePage = false) {
    const searchInput = document.getElementById('webScannerSearch')?.value.toLowerCase() || '';

    let dbFiltered = webScans.filter(scan => {
        const domainName = (scan.domains?.domain_name || '').toLowerCase();
        const ip = (scan.domains?.ip_address || '').toLowerCase();
        if (searchInput && !domainName.includes(searchInput) && !ip.includes(searchInput)) return false;
        return true;
    });

    let liveFiltered = liveWebScans.filter(scan => {
        const domainName = (scan.domain || '').toLowerCase();
        if (searchInput && !domainName.includes(searchInput)) return false;
        return true;
    });

    filteredWebScans = [...liveFiltered, ...dbFiltered];

    if (!preservePage) {
        webCurrentPage = 1;
    }
    renderWebScannerTable();
}

function renderWebScannerTable() {
    const tbody = document.getElementById('webScannerTableBody');
    const paginationContainer = document.getElementById('webPaginationControls');
    const thCount = document.getElementById('thWebScansCount');

    if (!tbody) return;

    if (!filteredWebScans || filteredWebScans.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state" style="padding: 24px; text-align: center;">No web scans found.</td></tr>`;
        if (paginationContainer) paginationContainer.innerHTML = '';
        if (thCount) thCount.textContent = 'SCANS';
        return;
    }

    const totalItems = filteredWebScans.length;
    if (thCount) thCount.textContent = `SCANS`;

    const totalPages = Math.ceil(totalItems / webRowsPerPage) || 1;
    if (webCurrentPage > totalPages) webCurrentPage = totalPages;

    const startIdx = (webCurrentPage - 1) * webRowsPerPage;
    const endIdx = Math.min(startIdx + webRowsPerPage, totalItems);
    const paginatedScans = filteredWebScans.slice(startIdx, endIdx);

    tbody.innerHTML = paginatedScans.map((scan, mapIndex) => {
        const isLive = scan.live_status !== undefined;

        let domainName = '';
        let targetSubtitle = '';
        let dateStr = '-';
        let statusHtml = '';
        let summaryHtml = '';
        let actionBtn = '';
        let scanIdLabel = '';
        let actualIndex = -1;

        // ID UNIK & CEK MEMORI UNTUK CHECKBOX (Anti-Amnesia)
        const uniqueScanId = isLive ? `live_${scan.scan_id || mapIndex}` : `db_${scan.id}`;
        const isChecked = window.selectedWebScans && window.selectedWebScans.has(uniqueScanId) ? 'checked' : '';

        if (isLive) {
            domainName = scan.domain || 'Unknown Target';
            targetSubtitle = scan.target || "Scan in progress...";
            scanIdLabel = scan.type || `Website Scanner ${scan.scan_id}`;
            const progressVal = scan.progress || 0;

            // Konversi Waktu (EEST ke WIB)
            if (scan.start_time) {
                let rawTime = scan.start_time;
                rawTime = rawTime.replace(' ', 'T');
                if (!rawTime.includes('+') && !rawTime.includes('Z')) {
                    rawTime += '+03:00';
                }
                const d = new Date(rawTime);
                if (!isNaN(d.getTime())) {
                    const year = d.getFullYear();
                    const month = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    const time = d.toLocaleString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                    dateStr = `${year}-${month}-${day} ${time}`;
                } else {
                    dateStr = scan.start_time;
                }
            }

            const radius = 14;
            const circumference = 2 * Math.PI * radius;
            const offset = circumference - (progressVal / 100) * circumference;

            statusHtml = `
                <div style="position: relative; width: 36px; height: 36px; display: flex; align-items: center; justify-content: center;">
                    <svg width="36" height="36" style="transform: rotate(-90deg);">
                        <circle cx="18" cy="18" r="14" fill="none" stroke="#e2e8f0" stroke-width="2"></circle>
                        <circle cx="18" cy="18" r="14" fill="none" stroke="#2563eb" stroke-width="2" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" stroke-linecap="round"></circle>
                    </svg>
                    <span style="position: absolute; font-size: 10px; font-weight: 600; color: #334155;">${progressVal}%</span>
                </div>
            `;
            summaryHtml = `<span style="color: #64748b; font-size: 13px;">${scan.live_status || 'running'}...</span>`;

            actionBtn = `<button class="btn btn-outline" onclick="stopActiveScan(${scan.scan_id})" style="border-color: #ef4444; color: #ef4444; background: rgba(239, 68, 68, 0.03);" onmouseover="this.style.background='#ef4444'; this.style.color='#ffffff';" onmouseout="this.style.background='rgba(239, 68, 68, 0.03)'; this.style.color='#ef4444';">Stop Scan</button>`;

            return `
                <tr style="cursor: default; border-bottom: 1px solid #f1f5f9; background: #fafafa;">
                    <td style="text-align: center; padding: 16px;" onclick="event.stopPropagation();">
                        <input type="checkbox" value="${uniqueScanId}" ${isChecked} onchange="window.toggleWebCheckbox(event, this.value)" onclick="event.stopPropagation();" style="width: 16px; height: 16px; accent-color: var(--primary); cursor: pointer;">
                    </td>
                    <td style="padding: 16px; min-width: 140px;">
                        <div style="display:flex; align-items:center; gap:8px; color: #2563eb; font-weight: 500; font-size: 14px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                            ${scanIdLabel}
                        </div>
                    </td>
                    <td style="padding: 16px;">${statusHtml}</td>
                    <td style="padding: 16px;">
                        <div style="font-weight: 500; font-size: 13px; color: #334155; margin-bottom: 4px;">https://${escapeHtml(domainName)}/</div>
                        <div style="font-size: 13px; color: #94a3b8;">${escapeHtml(targetSubtitle)}</div>
                    </td>
                    <td style="padding: 16px; min-width: 120px;">${summaryHtml}</td>
                    <td style="padding: 16px; font-size: 13px; color: #64748b; white-space: nowrap;">${dateStr}</td>
                    <td style="padding: 16px; text-align:center;">${actionBtn}</td>
                </tr>
            `;

        } else {
            actualIndex = allVulns.indexOf(scan);
            domainName = scan.domains?.domain_name || 'Unknown Target';
            targetSubtitle = scan.domains?.ip_address || '-';
            scanIdLabel = scan.vulnerabilities && scan.vulnerabilities.length > 0 ? scan.vulnerabilities[0].check_type : 'Website Scanner';

            if (scan.scan_date) {
                const d = new Date(scan.scan_date);
                if (!isNaN(d.getTime())) {
                    dateStr = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${d.toLocaleString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
                }
            }

            statusHtml = `
                <div style="width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; background: #ecfdf5; border-radius: 50%; color: #10b981;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                </div>
            `;

            let crit = 0, high = 0, med = 0, low = 0;
            if (scan.vulnerabilities) {
                scan.vulnerabilities.forEach(v => {
                    const s = (v.severity || '').toUpperCase();
                    if (s === 'CRITICAL') crit++;
                    else if (s === 'HIGH') high++;
                    else if (s === 'MEDIUM') med++;
                    else if (s === 'LOW' || s === 'INFO') low++;
                });
            }
            summaryHtml = `
                <div style="display:flex; gap:6px;">
                    <span style="background:var(--sev-critical); color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:600; min-width:24px; text-align:center; display:inline-block;">${crit}</span>
                    <span style="background:var(--sev-high); color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:600; min-width:24px; text-align:center; display:inline-block;">${high}</span>
                    <span style="background:var(--sev-medium); color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:600; min-width:24px; text-align:center; display:inline-block;">${med}</span>
                    <span style="background:var(--sev-low); color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:600; min-width:24px; text-align:center; display:inline-block;">${low}</span>
                </div>
            `;

            actionBtn = `<button class="btn btn-outline" onclick="openScanModalIndex(${actualIndex}); event.stopPropagation();">View Report</button>`;

            return `
                <tr onclick="openScanModalIndex(${actualIndex})" style="cursor: pointer; border-bottom: 1px solid #f1f5f9; transition: background 0.2s;" onmouseover="this.style.background='#f8fafc'" onmouseout="this.style.background='transparent'">
                    <td style="text-align: center; padding: 16px;" onclick="event.stopPropagation();">
                        <input type="checkbox" value="${uniqueScanId}" ${isChecked} onchange="window.toggleWebCheckbox(event, this.value)" onclick="event.stopPropagation();" style="width: 16px; height: 16px; accent-color: var(--primary); cursor: pointer;">
                    </td>
                    <td style="padding: 16px; min-width: 140px;">
                        <div style="display:flex; align-items:center; gap:8px; color: #64748b; font-weight: 500; font-size: 14px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                            ${scanIdLabel}
                        </div>
                    </td>
                    <td style="padding: 16px;">${statusHtml}</td>
                    <td style="padding: 16px;">
                        <div style="font-weight: 500; font-size: 13px; color: #334155; margin-bottom: 4px;">https://${escapeHtml(domainName)}/</div>
                        <div style="font-size: 13px; color: #94a3b8;">${escapeHtml(targetSubtitle)}</div>
                    </td>
                    <td style="padding: 16px; min-width: 120px;">${summaryHtml}</td>
                    <td style="padding: 16px; font-size: 13px; color: #64748b; white-space: nowrap;">${dateStr}</td>
                    <td style="padding: 16px; text-align:left;" onclick="event.stopPropagation();">
                        ${actionBtn}
                    </td>
                </tr>
            `;
        }
    }).join('');

    if (paginationContainer) {
        paginationContainer.style.padding = '16px 24px';

        paginationContainer.innerHTML = `
            <div class="pagination-left" style="display: flex; align-items: center;">
                <span style="font-size: 13px; color: #64748b;">Tampilkan per halaman:</span>
                <select onchange="window.changeWebRows(this.value)" style="margin-left: 8px; padding: 6px 12px; border-radius: 6px; border: 1px solid #cbd5e1; font-size: 13px; outline: none; background: white; color: #1e293b; cursor: pointer;">
                    <option value="10" ${webRowsPerPage === 10 ? 'selected' : ''}>10</option>
                    <option value="15" ${webRowsPerPage === 15 ? 'selected' : ''}>15</option>
                    <option value="25" ${webRowsPerPage === 25 ? 'selected' : ''}>25</option>
                    <option value="50" ${webRowsPerPage === 50 ? 'selected' : ''}>50</option>
                </select>
            </div>
            
            <div class="pagination-right" style="display: flex; align-items: center; gap: 12px;">
                <button class="btn btn-outline btn-sm" onclick="window.changeWebPage(${webCurrentPage - 1})" ${webCurrentPage === 1 ? 'disabled' : ''} style="padding: 6px 12px; min-width: auto; cursor: ${webCurrentPage === 1 ? 'not-allowed' : 'pointer'}; opacity: ${webCurrentPage === 1 ? '0.5' : '1'}; border-color: #cbd5e1; color: #475569;">Sebelumnya</button>
                
                <span style="font-size: 13px; font-weight: 500; color: #64748b; display: flex; align-items: center; gap: 4px;">
                    Halaman 
                    <input type="number" min="1" max="${totalPages}" value="${webCurrentPage}" onchange="window.changeWebPage(this.value)" onkeydown="if(event.key==='Enter') { this.blur(); window.changeWebPage(this.value); }" style="width: 45px; text-align: center; padding: 4px 6px; border-radius: 6px; border: 1px solid #cbd5e1; font-size: 13px; outline: none; background: white; color: #1e293b; margin: 0 4px;"> 
                    dari <span style="margin-left: 2px;">${totalPages}</span>
                </span>
                
                <button class="btn btn-outline btn-sm" onclick="window.changeWebPage(${webCurrentPage + 1})" ${webCurrentPage === totalPages ? 'disabled' : ''} style="padding: 6px 12px; min-width: auto; cursor: ${webCurrentPage === totalPages ? 'not-allowed' : 'pointer'}; opacity: ${webCurrentPage === totalPages ? '0.5' : '1'}; border-color: #cbd5e1; color: #475569;">Selanjutnya</button>
            </div>
        `;
    }
    window.syncWebSelectAll();
}

window.changeWebPage = function (newPage) {
    const parsedPage = parseInt(newPage);
    if (!isNaN(parsedPage) && parsedPage >= 1) {
        webCurrentPage = parsedPage;
        renderWebScannerTable();
    }
};

window.changeWebRows = function (newRows) {
    webRowsPerPage = parseInt(newRows);
    webCurrentPage = 1;
    renderWebScannerTable();
};

window.selectedWebScans = new Set();

window.toggleWebCheckbox = function (e, scanId) {
    e.stopPropagation();
    if (e.target.checked) {
        window.selectedWebScans.add(scanId);
    } else {
        window.selectedWebScans.delete(scanId);
    }
    window.syncWebSelectAll();
};

window.toggleAllWebScans = function (headerCb) {
    const rowCbs = document.querySelectorAll('#webScannerTableBody input[type="checkbox"]');
    const isChecked = headerCb.checked;

    rowCbs.forEach(cb => {
        cb.checked = isChecked;
        if (isChecked) {
            window.selectedWebScans.add(cb.value);
        } else {
            window.selectedWebScans.delete(cb.value);
        }
    });
};

window.syncWebSelectAll = function () {
    const selectAllCb = document.getElementById('selectAllWebScans');
    const rowCbs = document.querySelectorAll('#webScannerTableBody input[type="checkbox"]');

    if (selectAllCb && rowCbs.length > 0) {
        const allChecked = Array.from(rowCbs).every(cb => cb.checked);
        selectAllCb.checked = allChecked;
    } else if (selectAllCb) {
        selectAllCb.checked = false;
    }
};

function stopActiveScan(scanId) {
    if (!confirm('Are you sure you want to stop this scan?')) return;

    fetch(`${API_BASE}/api/scans/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanId })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                showToast('Success', data.message, '✅');
                fetchActiveScans();
            } else {
                showToast('Error', data.detail || data.message, '❌');
            }
        })
        .catch(err => {
            console.error('Error stopping scan:', err);
            showToast('Error', 'An error occurred while stopping the scan.', '❌');
        });
}

// (Web Scanner polling is handled inside switchView directly)

function openWebScanModal() {
    document.getElementById('webScanModalOverlay').classList.add('active');
    const select = document.getElementById('webScanTargetSelect');

    if (!allDomains || allDomains.length === 0) {
        select.innerHTML = '<option value="">No domains available</option>';
        return;
    }

    select.innerHTML = '<option value="">Select a domain</option>' +
        allDomains.filter(d => d.is_active).map(d => `<option value="${d.domain_name}">${d.domain_name}</option>`).join('');

    // Setup scan type radio card interactivity
    const radios = document.querySelectorAll('input[name="webScanType"]');
    radios.forEach(radio => {
        radio.addEventListener('change', function () {
            radios.forEach(r => {
                const card = r.closest('label');
                if (r.checked) {
                    card.style.borderColor = 'var(--color-accent)';
                    card.style.background = 'rgba(0, 88, 189, 0.04)';
                } else {
                    card.style.borderColor = 'var(--color-border)';
                    card.style.background = '#fff';
                }
            });
        });
    });
}

function submitWebScan() {
    const select = document.getElementById('webScanTargetSelect');
    const domain = select.value;

    const scanTypeElement = document.querySelector('input[name="webScanType"]:checked');
    const selectedScanType = scanTypeElement ? scanTypeElement.value : 'deep';

    if (!domain) {
        showToast('Error', 'Please select a domain to scan.', '❌');
        return;
    }

    const btnSubmit = document.getElementById('btnSubmitWebScan');
    btnSubmit.disabled = true;
    btnSubmit.style.opacity = '0.5';
    btnSubmit.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="animation: spin 1s linear infinite;"><circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="8"></circle></svg>
        Launching...
    `;

    fetch(`${API_BASE}/api/web-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets: [domain], scan_type: selectedScanType })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                showToast('Success', data.message, '✅');
                document.getElementById('webScanModalOverlay').classList.remove('active');
                fetchActiveScans();
            } else {
                showToast('Error', data.detail || data.message, '❌');
            }
        })
        .catch(err => {
            console.error('Error starting web scan:', err);
            showToast('Error', 'An error occurred while starting the web scan.', '❌');
        })
        .finally(() => {
            btnSubmit.disabled = false;
            btnSubmit.style.opacity = '1';
            btnSubmit.innerHTML = `
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
            Launch Scan
        `;
        });
}

// Network Scanner

function openNetworkScanModal() {
    document.getElementById('networkScanModalOverlay').classList.add('active');
    const select = document.getElementById('networkScanTargetSelect');

    if (!allDomains || allDomains.length === 0) {
        select.innerHTML = '<option value="">No domains available</option>';
        return;
    }

    select.innerHTML = '<option value="">Select a domain</option>' +
        allDomains.filter(d => d.is_active).map(d => `<option value="${d.domain_name}">${d.domain_name}</option>`).join('');

    // Setup interaktivitas klik pada kotak radio button (Deep vs Light)
    const radios = document.querySelectorAll('input[name="networkScanType"]');
    radios.forEach(radio => {
        radio.addEventListener('change', function () {
            radios.forEach(r => {
                const card = r.closest('label');
                if (r.checked) {
                    card.style.borderColor = 'var(--color-accent)';
                    card.style.background = 'rgba(0, 88, 189, 0.04)';
                } else {
                    card.style.borderColor = 'var(--color-border)';
                    card.style.background = '#fff';
                }
            });
        });
    });
}

function submitNetworkScan() {
    const select = document.getElementById('networkScanTargetSelect');
    const domain = select.value;

    // ✅ TAMBAHKAN KODE INI: Tangkap radio button yang sedang tercentang
    const scanTypeElement = document.querySelector('input[name="networkScanType"]:checked');
    const selectedScanType = scanTypeElement ? scanTypeElement.value : 'deep';

    if (!domain) {
        showToast('Error', 'Please select a target to scan.', '❌');
        return;
    }

    const btnSubmit = document.getElementById('btnSubmitNetworkScan');
    btnSubmit.disabled = true;
    btnSubmit.style.opacity = '0.5';
    btnSubmit.innerHTML = `...`; // (biarkan kode animasi loading tetap sama)

    fetch(`${API_BASE}/api/network-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // ✅ UBAH BODY INI: Sisipkan scan_type agar dikirim ke server
        body: JSON.stringify({
            targets: [domain],
            scan_type: selectedScanType
        })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                showToast('Success', data.message, '✅');
                document.getElementById('networkScanModalOverlay').classList.remove('active');
                refreshData(true); // Segarkan tabel di belakang layar
            } else {
                showToast('Error', data.detail || data.message, '❌');
            }
        })
        .catch(err => {
            console.error('Error starting network scan:', err);
            showToast('Error', 'An error occurred while starting the network scan.', '❌');
        })
        .finally(() => {
            btnSubmit.disabled = false;
            btnSubmit.style.opacity = '1';
            btnSubmit.innerHTML = `
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
            Launch Scan
        `;
        });
}


window.triggerSingleNetworkScan = async function (domainName) {
    showToast('Scan Jaringan', `Memulai network scan untuk ${domainName}...`, '🚀');
    try {
        const resp = await fetch(`${API_BASE}/api/network-scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targets: [domainName] })
        });

        if (resp.status === 200 || resp.status === 201 || resp.status === 202) {
            showToast('Scan Diantrekan', `Scan untuk ${domainName} sedang berjalan di server.`, '✅');
            // Minta tabel diperbarui sesaat lagi
            setTimeout(() => refreshData(true), 2000);
        } else {
            const data = await resp.json();
            showToast('Gagal', data.detail || 'Gagal memulai scan jaringan.', '❌');
        }
    } catch (err) {
        showToast('Error Koneksi', 'Tidak dapat terhubung ke server.', '🔌');
    }
}

function showSeverityDetailModal(items, timeLabel, rawIsoString) {
    document.getElementById('chartDetailTitle').textContent = `Detail Analisis (${timeLabel})`;

    const listContainer = document.getElementById('chartDetailList');
    listContainer.innerHTML = '';

    items.forEach(item => {
        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.justifyContent = 'space-between';
        row.style.alignItems = 'center';
        row.style.padding = '10px 14px';
        row.style.background = '#f8fafc';
        row.style.borderRadius = '6px';
        row.style.border = '1px solid var(--color-border)';
        row.style.cursor = 'pointer';
        row.style.transition = 'background 0.2s, border-color 0.2s';

        row.onmouseover = () => {
            row.style.background = '#f1f5f9';
            row.style.borderColor = '#cbd5e1';
        };
        row.onmouseout = () => {
            row.style.background = '#f8fafc';
            row.style.borderColor = 'var(--color-border)';
        };

        row.onclick = () => {
            closeChartDetailModal();
            closeChartModal();
            if (item.domain) {
                jumpToScanDetail(rawIsoString, item.domain, false);
            } else {
                jumpToScanDetail(rawIsoString, item.severity, true);
            }
        };

        const leftDiv = document.createElement('div');
        leftDiv.style.display = 'flex';
        leftDiv.style.alignItems = 'center';
        leftDiv.style.gap = '8px';

        const dot = document.createElement('div');
        dot.style.width = '10px';
        dot.style.height = '10px';
        dot.style.borderRadius = '50%';
        dot.style.background = item.color || '#333';

        const label = document.createElement('span');
        label.style.fontSize = '14px';
        label.style.color = 'var(--color-ink)';
        label.style.fontWeight = '500';
        label.textContent = item.domain ? `${item.severity} - ${item.domain}` : item.severity;

        leftDiv.appendChild(dot);
        leftDiv.appendChild(label);

        const rightDiv = document.createElement('div');
        rightDiv.style.display = 'flex';
        rightDiv.style.alignItems = 'center';
        rightDiv.style.gap = '12px';

        const valSpan = document.createElement('span');
        valSpan.style.fontSize = '14px';
        valSpan.style.fontWeight = '600';
        valSpan.style.color = 'var(--color-ink)';
        valSpan.textContent = item.count;

        const chevron = document.createElement('span');
        chevron.style.color = 'var(--color-ink-lighter)';
        chevron.style.fontSize = '14px';
        chevron.innerHTML = '›';

        rightDiv.appendChild(valSpan);
        rightDiv.appendChild(chevron);

        row.appendChild(leftDiv);
        row.appendChild(rightDiv);
        listContainer.appendChild(row);
    });

    document.getElementById('chartDetailModalOverlay').classList.add('active');
}

// --- Chart Click Details Modal ---
function showChartDetailModal(chartInstance, index, titleSuffix, rawIsoString, isSeverity = false, targetValue = null) {
    const timeLabel = chartInstance.data.labels[index];
    const datasets = chartInstance.data.datasets;

    document.getElementById('chartDetailTitle').textContent = `Detail Analisis (${timeLabel})`;

    const listContainer = document.getElementById('chartDetailList');
    listContainer.innerHTML = '';

    let total = 0;

    datasets.forEach(ds => {
        const val = ds.data[index] || 0;
        if (val > 0 && (targetValue === null || val === targetValue)) {
            total += val;

            const row = document.createElement('div');
            row.style.display = 'flex';
            row.style.justifyContent = 'space-between';
            row.style.alignItems = 'center';
            row.style.padding = '10px 14px';
            row.style.background = '#f8fafc';
            row.style.borderRadius = '6px';
            row.style.border = '1px solid var(--color-border)';
            row.style.cursor = 'pointer';
            row.style.transition = 'background 0.2s, border-color 0.2s';

            row.onmouseover = () => {
                row.style.background = '#f1f5f9';
                row.style.borderColor = '#cbd5e1';
            };
            row.onmouseout = () => {
                row.style.background = '#f8fafc';
                row.style.borderColor = 'var(--color-border)';
            };

            row.onclick = () => {
                closeChartDetailModal();
                closeChartModal();
                jumpToScanDetail(rawIsoString, ds.label, isSeverity);
            };

            const leftDiv = document.createElement('div');
            leftDiv.style.display = 'flex';
            leftDiv.style.alignItems = 'center';
            leftDiv.style.gap = '8px';

            const dot = document.createElement('div');
            dot.style.width = '10px';
            dot.style.height = '10px';
            dot.style.borderRadius = '50%';
            dot.style.background = ds.borderColor || '#333';

            const label = document.createElement('span');
            label.style.fontSize = '14px';
            label.style.color = 'var(--color-ink)';
            label.style.fontWeight = '500';
            label.textContent = ds.label;

            leftDiv.appendChild(dot);
            leftDiv.appendChild(label);

            const rightDiv = document.createElement('div');
            rightDiv.style.display = 'flex';
            rightDiv.style.alignItems = 'center';
            rightDiv.style.gap = '12px';

            const valSpan = document.createElement('span');
            valSpan.style.fontSize = '14px';
            valSpan.style.fontWeight = '600';
            valSpan.style.color = 'var(--color-ink)';
            valSpan.textContent = val;

            // Add a small chevron to indicate it's clickable
            const chevron = document.createElement('span');
            chevron.style.color = 'var(--color-ink-lighter)';
            chevron.style.fontSize = '14px';
            chevron.innerHTML = '›';

            rightDiv.appendChild(valSpan);
            rightDiv.appendChild(chevron);

            row.appendChild(leftDiv);
            row.appendChild(rightDiv);
            listContainer.appendChild(row);
        }
    });

    if (total === 0) {
        const emptyMsg = document.createElement('div');
        emptyMsg.style.fontSize = '13px';
        emptyMsg.style.color = 'var(--color-ink-soft)';
        emptyMsg.textContent = 'Tidak ada data kerentanan terdeteksi pada waktu ini.';
        listContainer.appendChild(emptyMsg);
    }

    document.getElementById('chartDetailModalOverlay').classList.add('active');
}

window.closeChartDetailModal = function () {
    document.getElementById('chartDetailModalOverlay').classList.remove('active');
};

// --- Chart Click Detail Redirect ---
function jumpToScanDetail(isoDateString, targetName, isSeverity = false) {
    if (!isoDateString || typeof allVulns === 'undefined' || !allVulns) {
        showToast("Info", "Data riwayat scan belum termuat.", "ℹ️");
        return;
    }

    const targetTime = new Date(isoDateString).getTime();

    let closestScan = null;
    let minDiff = Infinity;

    allVulns.forEach(scan => {
        if (!scan.scan_date) return;

        // Pastikan scan sesuai dengan kriteria yang diklik
        if (isSeverity) {
            let hasSeverity = false;
            if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
                hasSeverity = scan.vulnerabilities.some(v => (v.severity || '').toUpperCase() === targetName.toUpperCase());
            }
            if (!hasSeverity) return;
        } else {
            const domain = scan.domains?.domain_name || 'Unknown';
            if (domain !== targetName && targetName !== 'Others' && targetName !== 'Semua Domain') return;
        }

        const scanTime = new Date(scan.scan_date).getTime();
        const diff = Math.abs(scanTime - targetTime);
        if (diff < minDiff) {
            minDiff = diff;
            closestScan = scan;
        }
    });

    if (closestScan) {
        openScanModal(closestScan);
    } else {
        showToast("Info", "Tidak ada detail scan spesifik yang ditemukan untuk titik ini.", "ℹ️");
    }
}

// Global modal background click-to-close
document.addEventListener('click', (e) => {
    if (e.target && e.target.classList && e.target.classList.contains('modal-overlay')) {
        e.target.classList.remove('active');
        // Close enlarged chart if clicked outside
        if (e.target.id === 'chartModalOverlay') {
            closeChartModal();
        }
    }
});

// Chart Enlarge Logic
let enlargedChartInstance = null;

window.openChartModal = function (sourceChartId, title) {
    const overlay = document.getElementById('chartModalOverlay');
    const titleEl = document.getElementById('chartModalTitle');

    if (overlay) overlay.classList.add('active');
    if (titleEl) titleEl.textContent = title || 'Grafik';

    // Hapus instance sebelumnya jika ada
    if (enlargedChartInstance) {
        enlargedChartInstance.destroy();
        enlargedChartInstance = null;
    }

    setTimeout(() => {
        // Render ulang elemen canvas untuk menghindari bug cache dimensi dari browser
        const modalBody = document.querySelector('#chartModalOverlay .modal-body');
        if (modalBody) {
            modalBody.innerHTML = '<canvas id="enlargedChartCanvas"></canvas>';
            const ctx = document.getElementById('enlargedChartCanvas').getContext('2d');

            if (sourceChartId === 'vulnBarChart') {
                renderEnlargedVulnChart(ctx);
            } else if (sourceChartId === 'sevTrendChart') {
                renderEnlargedSevChart(ctx);
            }
        }
    }, 150);
};

window.renderEnlargedVulnChart = function (ctx) {
    if (!rawTrendData) return;

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
    allDatasets = allDatasets.filter(ds => Math.max(...ds.data) > 0);
    let finalDatasets = [];

    if (!allChecked && selectedDomains.length > 0) {
        finalDatasets = allDatasets.filter(ds => selectedDomains.includes(ds.label));
    } else {
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
            pointRadius: (ctx) => ctx.raw === 0 ? 0 : 4,
            pointHoverRadius: (ctx) => ctx.raw === 0 ? 0 : 8,
            pointBackgroundColor: baseColor
        };
    });

    const options = getEnlargedChartOptions(false);
    options.onClick = (event, activeElements) => {
        if (activeElements && activeElements.length > 0) {
            const index = activeElements[0].index;
            const datasetIndex = activeElements[0].datasetIndex;
            const clickedValue = enlargedChartInstance.data.datasets[datasetIndex].data[index];

            if (rawTrendData && rawTrendData.raw_labels) {
                let activeCount = 0;
                let lastActiveLabel = null;
                enlargedChartInstance.data.datasets.forEach(ds => {
                    const val = ds.data[index] || 0;
                    if (val === clickedValue && val > 0) {
                        activeCount++;
                        lastActiveLabel = ds.label;
                    }
                });

                if (activeCount === 1) {
                    closeChartModal();
                    jumpToScanDetail(rawTrendData.raw_labels[index], lastActiveLabel);
                } else if (activeCount > 1) {
                    showChartDetailModal(enlargedChartInstance, index, "Vulnerabilities", rawTrendData.raw_labels[index], false, clickedValue);
                }
            }
        }
    };

    enlargedChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: rawTrendData.labels || [],
            datasets: domainDatasets
        },
        options: options
    });
};

window.renderEnlargedSevChart = function (ctx) {
    if (!rawSevTrendData) return;

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

    const sevColors = {
        'Critical': '#8A2E2E',
        'High': '#FF4A4A',
        'Medium': '#FF9F2A',
        'Low': '#4287F5',
        'Info': '#00D182'
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
                const { ctx, chartArea } = chart;
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
            pointRadius: (ctx) => ctx.raw === 0 ? 0 : 4,
            pointHoverRadius: (ctx) => ctx.raw === 0 ? 0 : 8,
            pointBackgroundColor: color,
            pointHoverBackgroundColor: color
        };
    });

    const options = getEnlargedChartOptions(true);
    options.onClick = (event, activeElements) => {
        if (activeElements && activeElements.length > 0) {
            const index = activeElements[0].index;
            const datasetIndex = activeElements[0].datasetIndex;
            const clickedValue = enlargedChartInstance.data.datasets[datasetIndex].data[index];

            if (rawSevTrendData && rawSevTrendData.raw_labels) {
                let itemBreakdown = [];
                enlargedChartInstance.data.datasets.forEach(ds => {
                    const val = ds.data[index] || 0;
                    if (val === clickedValue && val > 0) {
                        if (ds.domains && ds.domains[index] && Object.keys(ds.domains[index]).length > 0) {
                            const domainsMap = ds.domains[index];
                            Object.keys(domainsMap).forEach(dName => {
                                if (domainsMap[dName] > 0) {
                                    itemBreakdown.push({
                                        severity: ds.label,
                                        domain: dName,
                                        count: domainsMap[dName],
                                        color: ds.borderColor
                                    });
                                }
                            });
                        } else {
                            itemBreakdown.push({
                                severity: ds.label,
                                domain: null,
                                count: val,
                                color: ds.borderColor
                            });
                        }
                    }
                });

                if (itemBreakdown.length === 1) {
                    const item = itemBreakdown[0];
                    closeChartModal();
                    if (item.domain) {
                        jumpToScanDetail(rawSevTrendData.raw_labels[index], item.domain, false);
                    } else {
                        jumpToScanDetail(rawSevTrendData.raw_labels[index], item.severity, true);
                    }
                } else if (itemBreakdown.length > 1) {
                    showSeverityDetailModal(itemBreakdown, enlargedChartInstance.data.labels[index], rawSevTrendData.raw_labels[index]);
                }
            }
        }
    };

    enlargedChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: rawSevTrendData.labels || [],
            datasets: sevDatasets
        },
        options: options
    });
};

function getEnlargedChartOptions(isSeverity) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
            mode: 'nearest',
            intersect: true
        },
        layout: {
            padding: {
                top: 15,
                right: 15
            }
        },
        scales: {
            y: {
                beginAtZero: true,
                grace: '5%',
                ticks: { precision: 0, font: { size: 14 } },
                grid: { color: '#e5e7eb', borderDash: [5, 5] },
                border: { display: false }
            },
            x: {
                ticks: { maxTicksLimit: 12, font: { size: 14 } },
                grid: { display: false },
                border: { display: false }
            }
        },
        plugins: {
            legend: {
                display: true,
                position: 'bottom',
                labels: {
                    usePointStyle: true,
                    pointStyle: 'circle',
                    font: { size: 15, weight: '500' },
                    padding: 20,
                    generateLabels: (chart) => {
                        return chart.data.datasets.map((dataset, i) => ({
                            text: dataset.label,
                            fillStyle: dataset.borderColor,
                            hidden: !chart.isDatasetVisible(i),
                            strokeStyle: dataset.borderColor,
                            pointStyle: 'circle',
                            datasetIndex: i
                        }));
                    }
                }
            },
            tooltip: {
                backgroundColor: '#ffffff',
                titleColor: '#1f2937',
                bodyColor: '#374151',
                borderColor: '#e5e7eb',
                borderWidth: 1,
                padding: 16,
                boxPadding: 8,
                usePointStyle: true,
                titleFont: { size: 15, weight: '600' },
                bodyFont: { size: 14 },
                filter: function (tooltipItem) {
                    return tooltipItem.parsed.y > 0;
                },
                callbacks: {
                    labelColor: function (context) {
                        return {
                            borderColor: context.dataset.borderColor,
                            backgroundColor: context.dataset.borderColor
                        };
                    },
                    label: function (context) {
                        let label = context.dataset.label || '';
                        let val = context.parsed.y;
                        if (val !== null) {
                            label += ` (${val})`;
                        }

                        if (isSeverity) {
                            let domainsObj = context.dataset.domains ? context.dataset.domains[context.dataIndex] : null;
                            if (val > 0 && domainsObj && typeof domainsObj === 'object') {
                                let lines = [label];
                                Object.entries(domainsObj).forEach(([d, count]) => {
                                    lines.push(`   • ${d} (${count})`);
                                });
                                return lines;
                            }
                        }
                        return label;
                    }
                }
            }
        }
    };
}

window.closeChartModal = function () {
    const overlay = document.getElementById('chartModalOverlay');
    if (overlay) overlay.classList.remove('active');
    if (enlargedChartInstance) {
        enlargedChartInstance.destroy();
        enlargedChartInstance = null;
    }
};

window.toggleSidebar = function () {
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
        const isCollapsed = sidebar.classList.toggle('collapsed');
        const tooltip = document.getElementById('sidebarTooltip');
        const arrow = document.getElementById('sidebarToggleArrow');

        if (tooltip && arrow) {
            if (isCollapsed) {
                tooltip.textContent = 'Buka sidebar';
                // Panah ke kanan
                arrow.setAttribute('d', 'M10 16l4-4-4-4');
            } else {
                tooltip.textContent = 'Tutup sidebar';
                // Panah ke kiri
                arrow.setAttribute('d', 'M14 16l-4-4 4-4');
            }
        }

        setTimeout(() => {
            window.dispatchEvent(new Event('resize'));
        }, 300);
    }
};
