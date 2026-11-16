//const API_BASE = window.location.origin;
//const API_BASE = "http://10.69.15.200:8000";
const API_BASE = "http://" + window.location.hostname + ":8000";

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
    
    const batchBtn = document.getElementById('batchStatusBtn');
    if (batchBtn) {
        batchBtn.addEventListener('click', (e) => window.openBatchStatusModal(e));
    }
    if (typeof initOvernightNotificationScheduler === 'function') {
        initOvernightNotificationScheduler();
    }
    if (typeof initRoleSessionTimer === 'function') {
        initRoleSessionTimer();
    }

    // Pastikan filter tanggal tren di-reset pada saat dimuat (refresh)
    ['vulnTrend', 'sevTrend'].forEach(prefix => {
        const startInput = document.getElementById(`${prefix}StartDate`);
        const endInput = document.getElementById(`${prefix}EndDate`);
        if (startInput) startInput.value = '';
        if (endInput) endInput.value = '';
    });
    rpSyncFromInputs('overview');
    rpSyncFromInputs('scanHistory');

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
                    showToast('Tersimpan', `Status berhasil diperbarui (Aktif: ${domainsToSave.length}, Tidak Aktif: ${inactiveDomains.length}).`, '');
                    if (typeof loadDomains === 'function') loadDomains(true);
                } else {
                    const data = await resp.json();
                    showToast('Gagal Menyimpan', data.detail || 'Terjadi kesalahan di server.', '');
                }
            } catch (err) {
                console.error(err);
                showToast('Koneksi Gagal', 'Gagal menghubungi server.', '');
            }
        });
    }

    const runBtn = document.getElementById('runScanBtn');
    if (runBtn) {
        runBtn.addEventListener('click', async () => {
            const domainsToScan = [...selectedDomains];
            if (domainsToScan.length === 0) return;

            showToast('Scan Dimulai', `Memerintahkan backend untuk memulai scan pada ${domainsToScan.length} domain...`, '');

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
                    showToast('Scan Berhasil Diantrekan', 'Proses scan instan sedang berjalan di latar belakang.', '');
                } else {
                    showToast('Peringatan', 'Beberapa scan mungkin gagal dijalankan. Cek log server.', '️');
                }
            } catch (err) {
                console.error(err);
                showToast('Koneksi Gagal', 'Server tidak merespons proses scan.', '');
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

            showToast('Scan Jaringan', `Memerintahkan API Pentest-Tools untuk melakukan pemindaian jaringan pada ${domainsToScan.length} domain...`, '');

            runNetworkScanBtn.disabled = true;
            runNetworkScanBtn.style.opacity = '0.5';

            try {
                const resp = await fetch(`${API_BASE}/api/network-scan`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ targets: domainsToScan })
                });

                if (resp.status === 200) {
                    showToast('Scan Diterima', 'Proses Network Scan sedang berjalan secara asinkron di server.', '');
                } else {
                    const data = await resp.json();
                    showToast('Gagal', data.detail || 'Server menolak permintaan pemindaian jaringan.', '');
                }
            } catch (err) {
                showToast('Koneksi Terputus', 'Gagal menghubungi server.', '');
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

    // Tanggal grafik Overview: satu pemilih bersama (lihat DATE RANGE PICKER), reset lewat tombol x

    // Removed old exportDomainsBtn listener since it's now handled by global exportDomains function.

    // Refresh otomatis setiap 5 detik
    // setInterval(refreshData, 5000);
});

// Navigation & Views
window.toggleNavDropdown = function(dropdownId, event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    const dropdown = document.getElementById(dropdownId);
    if (!dropdown) return;

    const isExpanded = dropdown.classList.contains('expanded');
    
    // Close other dropdowns
    document.querySelectorAll('.nav-dropdown').forEach(d => {
        if (d.id !== dropdownId) d.classList.remove('expanded');
    });

    dropdown.classList.toggle('expanded', !isExpanded);
};

// Close collapsed flyout dropdowns when clicking outside
document.addEventListener('click', function (e) {
    if (!e.target.closest('.nav-dropdown')) {
        const sidebar = document.querySelector('.sidebar');
        if (sidebar && sidebar.classList.contains('collapsed')) {
            document.querySelectorAll('.nav-dropdown.expanded').forEach(d => d.classList.remove('expanded'));
        }
    }
});

// Subjudul halaman scanner sesuai mode (Manual / Automated / semua)
const SCANNER_SUBTITLES = {
    web: {
        single: 'Website security scans you start on demand for selected target domains.',
        scheduled: 'Website security scans that run automatically on a schedule you set: once, or repeatedly within a time window such as 15:00 to 17:00.',
        all: 'Manual and automated website security scans for active target domains.'
    },
    network: {
        single: 'Network vulnerability scans, port discovery, and service checks you start on demand for selected domains.',
        scheduled: 'Network vulnerability scans, port discovery, and service tracking that run automatically on a schedule you set: once, or repeatedly within a time window.',
        all: 'Manual and automated network vulnerability scans, port discovery, and service tracking for active domains.'
    }
};

function setScannerSubtitle(elementId, kind, mode) {
    const el = document.getElementById(elementId);
    const text = SCANNER_SUBTITLES[kind] && SCANNER_SUBTITLES[kind][mode];
    if (el && text) el.textContent = text;
}

// =========================================================
// Hak akses tampilan per role. Server tetap menolak aksi yang tidak diizinkan;
// ini hanya supaya pengguna tidak melihat menu yang tidak bisa dipakai.
//   user        : Overview dan Scan History (lihat saja)
//   admin       : semua kecuali System Settings
//   superadmin  : semua
// =========================================================
const USER_VIEWS = ['overview', 'vulnerabilities'];

function roleCanView(viewId, role) {
    if (role === 'superadmin') return true;
    if (viewId === 'system-settings') return false;
    if (role === 'admin') return true;
    return USER_VIEWS.includes(viewId);
}

function applyRoleVisibility(role) {
    document.body.classList.toggle('role-user', role !== 'admin' && role !== 'superadmin');
    ['inventory', 'web-scanner', 'network-scanner'].forEach(key => {
        document.querySelectorAll(`.sidebar-nav [data-nav="${key}"]`).forEach(el => {
            el.style.display = roleCanView(key === 'inventory' ? key : `${key}-single`, role) ? '' : 'none';
        });
    });
}

function switchView(viewId, event, opts) {
    if (event) {
        if (typeof event.preventDefault === 'function') event.preventDefault();
        event.stopPropagation();
    }
    const updateHash = !(opts && opts.updateHash === false);

    // Perubahan System Settings belum disimpan: tanya dulu sebelum pindah halaman
    if (typeof ssGuardLeave === 'function' && ssGuardLeave(viewId)) return;

    // Role guard: halaman yang tidak diizinkan untuk role ini (lewat menu, tautan, alamat #/..., atau halaman terakhir)
    if (currentUser && !roleCanView(viewId, currentUser.role)) {
        if (typeof showToast === 'function') {
            showToast("Akses Ditolak", viewId === 'system-settings'
                ? "Hanya Super Admin yang dapat mengakses System Settings."
                : "Akun Anda hanya dapat melihat Overview dan Scan History.", "error");
        }
        if (viewId !== 'overview') switchView('overview');
        return;
    }

    // Deactivate all nav items & sub-items
    document.querySelectorAll('.nav-item, .nav-sub-item').forEach(n => n.classList.remove('active'));

    // Route sub-views
    let targetView = `view-${viewId}`;
    
    if (viewId === 'web-scanner-single') {
        targetView = 'view-web-scanner';
        window.currentWebScanMode = 'single';
        const titleEl = document.getElementById('webScannerTitle');
        if (titleEl) titleEl.textContent = 'Website Scans';
        setScannerSubtitle('webScannerSubtitle', 'web', 'single');
        const webSearch = document.getElementById('webScannerSearch');
        if (webSearch) webSearch.value = '';
        applyWebFilters();
    } else if (viewId === 'web-scanner-scheduled') {
        targetView = 'view-web-scanner';
        window.currentWebScanMode = 'scheduled';
        const titleEl = document.getElementById('webScannerTitle');
        if (titleEl) titleEl.textContent = 'Website Scans';
        setScannerSubtitle('webScannerSubtitle', 'web', 'scheduled');
        const webSearch = document.getElementById('webScannerSearch');
        if (webSearch) webSearch.value = '';
        applyWebFilters();
    } else if (viewId === 'web-scanner') {
        targetView = 'view-web-scanner';
        window.currentWebScanMode = 'all';
        const titleEl = document.getElementById('webScannerTitle');
        if (titleEl) titleEl.textContent = 'Website Scans';
        setScannerSubtitle('webScannerSubtitle', 'web', 'all');
        applyWebFilters();
    } else if (viewId === 'network-scanner-single') {
        targetView = 'view-network-scanner';
        window.currentNetworkScanMode = 'single';
        const titleEl = document.getElementById('networkScannerTitle');
        if (titleEl) titleEl.textContent = 'Network Scans';
        setScannerSubtitle('networkScannerSubtitle', 'network', 'single');
        const netSearch = document.getElementById('netSearchInput');
        if (netSearch) netSearch.value = '';
        applyNetworkFilters();
    } else if (viewId === 'network-scanner-scheduled') {
        targetView = 'view-network-scanner';
        window.currentNetworkScanMode = 'scheduled';
        const titleEl = document.getElementById('networkScannerTitle');
        if (titleEl) titleEl.textContent = 'Network Scans';
        setScannerSubtitle('networkScannerSubtitle', 'network', 'scheduled');
        const netSearch = document.getElementById('netSearchInput');
        if (netSearch) netSearch.value = '';
        applyNetworkFilters();
    } else if (viewId === 'network-scanner') {
        targetView = 'view-network-scanner';
        window.currentNetworkScanMode = 'all';
        const titleEl = document.getElementById('networkScannerTitle');
        if (titleEl) titleEl.textContent = 'Network Scans';
        setScannerSubtitle('networkScannerSubtitle', 'network', 'all');
        applyNetworkFilters();
    }

    // Hide all views
    document.querySelectorAll('.view-container').forEach(v => {
        v.classList.add('hidden');
        v.classList.remove('active');
        v.style.display = 'none';
    });

    if (!document.getElementById(targetView)) {
        if (viewId === 'dashboard' || viewId === 'overview') targetView = 'view-overview';
        else if (viewId === 'targets' || viewId === 'inventory') targetView = 'view-inventory';
        else if (viewId === 'vulnerabilities') targetView = 'view-vulnerabilities';
        else if (viewId.startsWith('web-scanner')) targetView = 'view-web-scanner';
        else if (viewId.startsWith('network-scanner')) targetView = 'view-network-scanner';
        else if (viewId === 'admin') targetView = 'view-admin';
        else if (viewId === 'system-settings') targetView = 'view-system-settings';
        else targetView = 'view-overview';
    }

    // Activate view element
    const viewEl = document.getElementById(targetView);
    if (viewEl) {
        viewEl.classList.remove('hidden');
        viewEl.classList.add('active');
        viewEl.style.display = 'block';
    }

    // Expand dropdown if a child item is active (only in expanded sidebar mode)
    const isSidebarCollapsed = document.querySelector('.sidebar')?.classList.contains('collapsed');
    if (!isSidebarCollapsed) {
        if (viewId.startsWith('web-scanner')) {
            const webDropdown = document.getElementById('navDropdownWeb');
            if (webDropdown) webDropdown.classList.add('expanded');
        } else if (viewId.startsWith('network-scanner')) {
            const netDropdown = document.getElementById('navDropdownNetwork');
            if (netDropdown) netDropdown.classList.add('expanded');
        }
    } else {
        // In collapsed mode, close the flyout menu after choosing an item
        document.querySelectorAll('.nav-dropdown.expanded').forEach(d => d.classList.remove('expanded'));
    }

    // Activate nav element dynamically
    document.querySelectorAll('.sidebar-nav .nav-item, .sidebar-nav .nav-sub-item').forEach(n => {
        const onclickAttr = n.getAttribute('onclick') || '';
        if (onclickAttr.includes(`'${viewId}'`)) {
            n.classList.add('active');
        }
    });

    // Menu sidebar: aktif bila viewId sama atau turunan (mis. web-scanner-scheduled -> web-scanner)
    document.querySelectorAll('.sidebar-nav [data-nav]').forEach(n => {
        const key = n.dataset.nav;
        n.classList.toggle('active', viewId === key || viewId.startsWith(key + '-'));
        if (n.classList.contains('active')) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current');
    });
    // Tab Manual / Automated di halaman scanner
    document.querySelectorAll('[data-scan-tab]').forEach(t => {
        const on = t.dataset.scanTab === viewId;
        t.classList.toggle('active', on);
        t.setAttribute('aria-selected', on ? 'true' : 'false');
    });

    // Also highlight the parent dropdown toggle if one of its sub-items is active
    if (viewId.startsWith('web-scanner')) {
        document.querySelector('#navDropdownWeb .nav-dropdown-toggle')?.classList.add('active');
    } else if (viewId.startsWith('network-scanner')) {
        document.querySelector('#navDropdownNetwork .nav-dropdown-toggle')?.classList.add('active');
    }

    // Load admin data if switching to admin page
    if (viewId === 'admin') {
        loadAdminUsers();
        fetchNotifications();
    } else if (viewId === 'system-settings') {
        loadSystemSettings();
    }

    // Web Scanner & Network Scanner: start/stop polling for active scans & scheduled scans
    if (viewId.startsWith('web-scanner') || viewId.startsWith('network-scanner')) {
        fetchActiveScans();
        fetchScheduledScans();
        if (!activeScansInterval) {
            activeScansInterval = setInterval(() => {
                fetchActiveScans();
                fetchScheduledScans();
            }, 15000);
        }
    } else {
        if (activeScansInterval) {
            clearInterval(activeScansInterval);
            activeScansInterval = null;
        }
    }

    if (typeof updatePageMeta === 'function') updatePageMeta(viewId);
    try {
        localStorage.setItem('dsti_last_view', viewId);
    } catch (e) { /* abaikan */ }
    if (updateHash && typeof syncHashForView === 'function') syncHashForView(viewId);
}

// Judul halaman + deep-link hash per view (Opsi 1: rasa page tanpa file terpisah)
const VIEW_TITLES = {
    'overview': 'Overview',
    'inventory': 'Domain Inventory',
    'vulnerabilities': 'Scan History',
    'web-scanner': 'Website Scans',
    'web-scanner-single': 'Website Scans (Manual)',
    'web-scanner-scheduled': 'Website Scans (Automated)',
    'network-scanner': 'Network Scans',
    'network-scanner-single': 'Network Scans (Manual)',
    'network-scanner-scheduled': 'Network Scans (Automated)',
    'admin': 'User Management',
    'system-settings': 'System Settings'
};
window.VIEW_TITLES = VIEW_TITLES;

function updatePageMeta(viewId) {
    const label = VIEW_TITLES[viewId] || viewId;
    try {
        document.title = label + ' | Pentest-UNDIP';
    } catch (e) { /* abaikan */ }
    // Breadcrumb topbar: kelompok menu > halaman (tanpa keterangan Manual/Automated: sudah ada di tab)
    const pageLabel = label.replace(/ \((Manual|Automated)\)$/, '');
    const crumbPage = document.getElementById('crumbPage');
    const crumbGroup = document.getElementById('crumbGroup');
    // Pindah ke halaman lain mulai dari atas (pindah tab Manual/Automated tidak)
    if (crumbPage && crumbPage.textContent !== pageLabel) {
        const canvas = document.querySelector('.page-canvas');
        if (canvas) canvas.scrollTop = 0;
    }
    if (crumbPage) crumbPage.textContent = pageLabel;
    if (crumbGroup) crumbGroup.textContent = ['admin', 'system-settings'].includes(viewId) ? 'Administration' : 'Security';
}

// Penanda "N scan sedang berjalan" di topbar. Data dari fetchActiveScans (halaman scanner)
// atau polling ringan tiap 60 detik di halaman lain. Endpoint di-cache 8 detik di server.
function updateRunningIndicator() {
    const btn = document.getElementById('topbarRunning');
    const text = document.getElementById('topbarRunningText');
    if (!btn || !text) return;
    const web = (liveWebScans || []).length;
    const net = (liveNetworkScans || []).length;
    const n = web + net;
    btn.hidden = n === 0;
    text.textContent = `${n} scan sedang berjalan`;
    btn.title = [web ? `${web} Website` : '', net ? `${net} Network` : ''].filter(Boolean).join(', ') + '. Klik untuk melihat.';
}

window.openRunningScans = function () {
    const net = (liveNetworkScans || []).length && !(liveWebScans || []).length;
    switchView(net ? 'network-scanner-single' : 'web-scanner-single');
};

async function pollRunningScans() {
    if (document.hidden || !currentUser) return;
    if ((typeof activeScansInterval !== 'undefined') && activeScansInterval) return; // halaman scanner sudah polling
    try {
        const resp = await fetch(`${API_BASE}/api/scans/active`);
        const data = await resp.json();
        if (data && Array.isArray(data.data)) {
            const all = data.data;
            liveNetworkScans = all.filter(s => String(s.type || '').includes('350') || String(s.type || '').includes('385') || String(s.type || '').toLowerCase().includes('network'));
            liveWebScans = all.filter(s => !liveNetworkScans.includes(s));
            updateRunningIndicator();
        }
    } catch (e) { /* abaikan: penanda tetap seperti sebelumnya */ }
}
setInterval(pollRunningScans, 60000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) pollRunningScans(); });
window.updatePageMeta = updatePageMeta;

function syncHashForView(viewId) {
    try {
        let hash = '#/overview';
        if (VIEW_TITLES[viewId]) {
            hash = '#/' + viewId;
        } else {
            return;
        }
        if (window.location.hash !== hash) {
            window.location.hash = hash;
        }
    } catch (e) { /* abaikan */ }
}
window.syncHashForView = syncHashForView;

function routeFromHash() {
    try {
        const raw = (window.location.hash || '').replace(/^#\/?/, '');
        if (raw) {
            const parts = raw.split('/');
            const viewId = parts[0];
            if (VIEW_TITLES[viewId]) {
                if (viewId === 'system-settings' && currentUser && currentUser.role !== 'superadmin') return false;
                switchView(viewId, null, { updateHash: false });
                if (viewId === 'system-settings' && parts[1] === 'auto-scan' && typeof switchSettingsTab === 'function') {
                    switchSettingsTab('auto-scan', { updateHash: false });
                }
                return true;
            }
        }
        // Fallback: halaman terakhir dari localStorage agar refresh tidak mental ke overview
        let saved = null;
        try {
            saved = localStorage.getItem('dsti_last_view');
        } catch (e) { /* abaikan */ }
        if (saved && VIEW_TITLES[saved]) {
            if (saved === 'system-settings' && currentUser && currentUser.role !== 'superadmin') return false;
            switchView(saved, null, { updateHash: false });
            if (typeof syncHashForView === 'function') syncHashForView(saved);
            return true;
        }
        return false;
    } catch (e) {
        return false;
    }
}
window.routeFromHash = routeFromHash;

if (typeof window !== 'undefined' && !window._settingsHashListenerAttached) {
    window._settingsHashListenerAttached = true;
    window.addEventListener('hashchange', () => {
        if (!currentUser) return;
        routeFromHash();
    });
}

// Data Fetching
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && currentUser && Date.now() - lastRefreshAt > 30000) {
        refreshData(true);
    }
});

// Jawaban server terakhir. Refresh berkala (tiap 5 detik) hanya menggambar ulang
// bila jawabannya berubah, supaya ribuan elemen tidak diganti tanpa alasan
// (beban berat untuk browser dan ekstensi seperti uBlock).
let lastScanHistoryText = null;
let lastDomainsText = null;

// Refresh berkala hanya cadangan bila koneksi live putus; kabar perubahan datang lewat live
const REFRESH_FALLBACK_MS = 60000;
let lastRefreshAt = 0;

async function refreshData(preservePage = true) {
    lastRefreshAt = Date.now();
    try {
        await checkHealth();
        const [scansChanged] = await Promise.all([
            loadVulnerabilities(preservePage, { onlyIfChanged: true }),
            loadDomains(preservePage, { onlyIfChanged: true })
        ]);

        // Tabel Website/Network Scans diturunkan dari riwayat scan
        if (scansChanged) {
            if (typeof processNetworkScans === 'function') processNetworkScans(preservePage);
            if (typeof processWebScans === 'function') processWebScans(preservePage);
        }
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
// 12 warna berbeda untuk domain (dulu hanya 5, sehingga domain ke-6 dst memakai warna kembar)
const PALETTE = ['#4F46E5', '#0D9488', '#DB2777', '#CA8A04', '#7C3AED', '#0891B2', '#65A30D', '#C2410C', '#0369A1', '#BE185D', '#4D7C0F', '#6D28D9'];
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

// --- Toast Notification System & Custom Confirm Dialog ---

// =========================================================
// TOAST (judul huruf kalimat, ikon per tipe, tombol tutup,
// progress = durasi, hover = jeda, maks 3 terlihat, anti dobel)
// =========================================================
const TOAST_ICON_PATHS = {
    success: '<circle cx="12" cy="12" r="10"></circle><path d="m9 12 2 2 4-4"></path>',
    error: '<circle cx="12" cy="12" r="10"></circle><path d="m15 9-6 6"></path><path d="m9 9 6 6"></path>',
    warning: '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>',
    info: '<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line>',
    scan: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path>',
    domain: '<circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>',
    risk: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>'
};
const TOAST_DEFAULT_TITLES = { success: 'Berhasil', error: 'Gagal', warning: 'Perhatian', info: 'Info' };
const TOAST_DURATIONS = { success: 4000, info: 4000, warning: 6000, error: 0 }; // 0 = tetap sampai ditutup
const TOAST_MAX_VISIBLE = 3;

function toastIconHtml(kind) {
    return `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${TOAST_ICON_PATHS[kind] || TOAST_ICON_PATHS.info}</svg>`;
}

// Tebak tipe dari ikon/judul/pesan untuk pemanggil lama: showToast('Judul', 'Pesan', '')
function inferToastType(rawIcon, titleText, messageText) {
    const s = `${rawIcon || ''} ${titleText || ''} ${messageText || ''}`.toLowerCase();
    if (/(gagal|error|tidak dapat|tidak bisa|ditolak|kesalahan)/.test(s)) return 'error';
    if (/(peringatan|warning|nonaktif|inactive|timeout|ditangguhkan|perhatian)/.test(s)) return 'warning';
    if (/(berhasil|sukses|success|tersimpan|disimpan|tersalin|diterima|diantrekan|aktif)/.test(s)) return 'success';
    return 'info';
}

function getToastContainer() {
    return document.getElementById('toast-container') || document.getElementById('toastContainer');
}

function refreshToastStack() {
    const container = getToastContainer();
    if (!container) return;
    const items = [...container.children].filter(el => !el.classList.contains('tst-more') && !el.classList.contains('tst-leaving'));
    const expanded = container.classList.contains('tst-expanded');
    // Toast terbaru selalu terlihat; yang lama diringkas
    items.forEach((el, i) => {
        const hide = !expanded && i < items.length - TOAST_MAX_VISIBLE;
        el.classList.toggle('tst-overflow', hide);
    });
    const hiddenCount = items.filter(el => el.classList.contains('tst-overflow')).length;
    let more = container.querySelector('.tst-more');
    if (hiddenCount > 0) {
        if (!more) {
            more = document.createElement('button');
            more.type = 'button';
            more.className = 'tst-more';
            more.addEventListener('click', () => {
                container.classList.add('tst-expanded');
                refreshToastStack();
            });
        }
        more.textContent = `+${hiddenCount} notifikasi lainnya`;
        container.appendChild(more);
    } else {
        if (more) more.remove();
        if (items.length <= TOAST_MAX_VISIBLE) container.classList.remove('tst-expanded');
    }
}

function dismissToast(toast) {
    if (!toast || toast.classList.contains('tst-leaving')) return;
    if (toast._timer) clearTimeout(toast._timer);
    toast.classList.add('tst-leaving');
    setTimeout(() => {
        toast.remove();
        refreshToastStack();
    }, 220);
}

function startToastTimer(toast) {
    if (!toast._duration) return;
    toast._startedAt = Date.now();
    toast._timer = setTimeout(() => dismissToast(toast), toast._remaining);
}

/**
 * showToast(pesan, tipe)                       → tipe: success | error | warning | info
 * showToast(judul, pesan, ikon)                → tipe ditebak dari teks (kompatibel dengan kode lama)
 * showToast(pesan, tipe, null, { title, actions: [{ label, onClick, primary }], duration })
 */
function showToast(arg1, arg2, arg3, options = {}) {
    const container = getToastContainer();
    if (!container) return null;

    const knownTypes = ['success', 'error', 'warning', 'info'];
    let type, title, message;
    if (arg2 && knownTypes.includes(String(arg2).toLowerCase())) {
        type = String(arg2).toLowerCase();
        message = arg1 || '';
        title = options.title || TOAST_DEFAULT_TITLES[type];
    } else {
        title = arg1 || 'Notifikasi';
        message = arg2 || '';
        type = options.type || inferToastType(arg3, title, message);
    }
    const actions = options.actions || [];
    const duration = options.duration !== undefined ? options.duration
        : (actions.length && type !== 'warning' ? 0 : TOAST_DURATIONS[type]);

    // Anti dobel: toast yang sama → mulai ulang timernya saja
    const key = `${type}|${title}|${message}`;
    const dup = [...container.querySelectorAll('.tst')].find(t => t.dataset.key === key && !t.classList.contains('tst-leaving'));
    if (dup) {
        if (dup._timer) clearTimeout(dup._timer);
        dup._remaining = dup._duration;
        const bar = dup.querySelector('.tst-progress-bar');
        if (bar) { bar.style.animation = 'none'; void bar.offsetWidth; bar.style.animation = ''; }
        startToastTimer(dup);
        return dup;
    }

    const toast = document.createElement('div');
    toast.className = `tst tst-${type}`;
    toast.dataset.key = key;
    toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
    toast.innerHTML = `
        <div class="tst-row">
            <span class="tst-icon">${toastIconHtml(type)}</span>
            <div class="tst-body">
                <div class="tst-title"></div>
                <div class="tst-message"></div>
                ${actions.length ? '<div class="tst-actions"></div>' : ''}
            </div>
            <button type="button" class="tst-close" aria-label="Tutup notifikasi">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M18 6 6 18"></path><path d="m6 6 12 12"></path></svg>
            </button>
        </div>
        ${duration ? `<div class="tst-progress"><div class="tst-progress-bar" style="animation-duration:${duration}ms"></div></div>` : ''}`;
    toast.querySelector('.tst-title').textContent = title;
    const msgEl = toast.querySelector('.tst-message');
    msgEl.textContent = message;
    if (!message) msgEl.remove();

    if (actions.length) {
        const wrap = toast.querySelector('.tst-actions');
        actions.forEach(a => {
            const b = document.createElement('button');
            b.type = 'button';
            b.className = `tst-btn${a.primary ? ' tst-btn-primary' : ''}`;
            b.textContent = a.label;
            b.addEventListener('click', (e) => {
                e.stopPropagation();
                try { if (a.onClick) a.onClick(e); } finally { dismissToast(toast); }
            });
            wrap.appendChild(b);
        });
    }
    toast.querySelector('.tst-close').addEventListener('click', () => dismissToast(toast));

    toast._duration = duration;
    toast._remaining = duration;
    // Hover menjeda timer & progress bar
    toast.addEventListener('mouseenter', () => {
        if (!toast._duration || !toast._timer) return;
        clearTimeout(toast._timer);
        toast._timer = null;
        toast._remaining = Math.max(500, toast._remaining - (Date.now() - toast._startedAt));
    });
    toast.addEventListener('mouseleave', () => {
        if (toast._duration && !toast._timer && !toast.classList.contains('tst-leaving')) startToastTimer(toast);
    });
    toast.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') { e.stopPropagation(); dismissToast(toast); }
    });

    const more = container.querySelector('.tst-more');
    if (more) container.insertBefore(toast, more); else container.appendChild(toast);
    startToastTimer(toast);
    refreshToastStack();
    return toast;
}

// Toast khusus lama (scan selesai / domain baru / scan malam) memakai .toast-notification:
// isi ikon yang kosong & ikut dihitung di tumpukan.
(function watchLegacyToasts() {
    const container = getToastContainer();
    if (!container || typeof MutationObserver === 'undefined') return;
    new MutationObserver((mutations) => {
        let changed = false;
        mutations.forEach(m => m.addedNodes.forEach(n => {
            if (n.nodeType !== 1 || !n.classList.contains('toast-notification')) return;
            changed = true;
            const icon = n.querySelector('.toast-icon');
            if (icon && !icon.querySelector('svg')) {
                const text = (n.textContent || '').toLowerCase();
                const kind = n.id.startsWith('domain-toast') ? 'domain' : n.id.startsWith('overnight-toast') || /critical|high|berisiko/.test(text) ? 'risk' : 'scan';
                icon.innerHTML = toastIconHtml(kind);
                n.classList.add(`tst-legacy-${kind}`);
            }
        }));
        mutations.forEach(m => { if (m.removedNodes.length) changed = true; });
        if (changed) refreshToastStack();
    }).observe(container, { childList: true });
})();


function customConfirm({
    title = 'Konfirmasi Aksi',
    message = 'Apakah Anda yakin ingin melanjutkan tindakan ini?',
    confirmText = 'Ya, Lanjutkan',
    cancelText = 'Batal',
    secondaryText = null,
    variant = 'danger'
} = {}) {
    return new Promise((resolve) => {
        const modal = document.getElementById('customConfirmModal');
        const titleEl = document.getElementById('customModalTitle');
        const msgEl = document.getElementById('customModalMessage');
        const iconBadge = document.getElementById('customModalIconBadge');
        const iconEl = document.getElementById('customModalIcon');
        const confirmBtn = document.getElementById('customModalConfirmBtn');
        const secondaryBtn = document.getElementById('customModalSecondaryBtn');
        const cancelBtn = document.getElementById('customModalCancelBtn');

        if (!modal || !confirmBtn || !cancelBtn) {
            resolve(window.confirm(message));
            return;
        }

        if (titleEl) titleEl.textContent = title;
        if (msgEl) msgEl.textContent = message;
        if (confirmBtn) confirmBtn.textContent = confirmText;
        if (cancelBtn) cancelBtn.textContent = cancelText;

        if (secondaryBtn) {
            if (secondaryText) {
                secondaryBtn.textContent = secondaryText;
                secondaryBtn.style.display = 'inline-block';
            } else {
                secondaryBtn.style.display = 'none';
            }
        }

        const iconSvgMap = {
            danger: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
            warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
            info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>',
            success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>'
        };

        if (iconBadge) iconBadge.className = `custom-modal-icon-badge ${variant}`;
        if (iconEl) iconEl.innerHTML = iconSvgMap[variant] || iconSvgMap.info;

        if (confirmBtn) {
            confirmBtn.className = `btn custom-modal-btn ${variant === 'danger' ? 'btn-danger-solid' : 'btn-primary-solid'}`;
        }

        modal.classList.add('open');

        const cleanup = (result) => {
            modal.classList.remove('open');
            confirmBtn.removeEventListener('click', onConfirm);
            if (secondaryBtn) secondaryBtn.removeEventListener('click', onSecondary);
            cancelBtn.removeEventListener('click', onCancel);
            document.removeEventListener('keydown', onKeyDown);
            resolve(result);
        };

        const onConfirm = () => cleanup(secondaryText ? 'confirm' : true);
        const onSecondary = () => cleanup('secondary');
        const onCancel = () => cleanup(secondaryText ? 'cancel' : false);
        const onKeyDown = (e) => {
            if (e.key === 'Escape') onCancel();
            if (e.key === 'Enter') onConfirm();
        };

        confirmBtn.addEventListener('click', onConfirm);
        if (secondaryBtn) secondaryBtn.addEventListener('click', onSecondary);
        cancelBtn.addEventListener('click', onCancel);
        document.addEventListener('keydown', onKeyDown);
    });
}

function customAlert(message, type = 'info', title = 'Informasi') {
    return customConfirm({
        title,
        message,
        confirmText: 'OK',
        cancelText: '',
        variant: type
    }).then(() => {});
}

// --- Date Dropdown Helpers ---
async function setQuickDate(chartPrefix, days, dropdownId) {
    const key = days === 1 ? '1d' : `${days}d`;
    const range = rpPresetRange(chartPrefix, key);
    rpCommit(chartPrefix, range.start, range.end, key);
}

async function applyCustomDate(chartPrefix) {
    const start = document.getElementById(`${chartPrefix}StartDate`)?.value || null;
    const end = document.getElementById(`${chartPrefix}EndDate`)?.value || null;
    rpCommit(chartPrefix, start, end || start, start ? 'custom' : '1d');
}

// --- Multi-Select Dropdown Helpers ---
function toggleDropdown(id) {
    const el = document.getElementById(id);
    if (!el) return;
    document.querySelectorAll('.multi-select-dropdown.open, .multi-select-dropdown.active').forEach(other => {
        if (other !== el) {
            other.classList.remove('open');
            other.classList.remove('active');
        }
    });
    el.classList.toggle('open');
}

function closeDropdown(id) {
    const el = document.getElementById(id);
    if (el) {
        el.classList.remove('open');
        el.classList.remove('active');
    }
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
    if (e.target && !e.target.isConnected) return;
    document.querySelectorAll('.multi-select-dropdown.open, .multi-select-dropdown.active').forEach(dd => {
        if (!dd.contains(e.target)) {
            dd.classList.remove('open');
            dd.classList.remove('active');
        }
    });
});

async function loadOverview() {
    try {
        const statsResp = await fetch(`${API_BASE}/api/dashboard-stats`);
        const statsData = await statsResp.json();

        // Update summary cards
        document.getElementById('overviewTotalDomains').textContent = statsData.total_domains || 0;

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

        // Filter domain dan warna garis sekarang diatur di legenda grafik (lihat trendRender), bukan dropdown.

        // Initial Render
        if (window.renderVulnTrendChart) window.renderVulnTrendChart();
    } catch (err) {
        console.error('Error loading vuln trend data:', err);
        if (typeof trendLegendMessage === 'function') trendLegendMessage(document.getElementById('vulnTrendLegend'), 'Gagal memuat data tren. Muat ulang halaman untuk mencoba lagi.');
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
        if (typeof trendLegendMessage === 'function') trendLegendMessage(document.getElementById('sevTrendLegend'), 'Gagal memuat data tren. Muat ulang halaman untuk mencoba lagi.');
    }
}

// =========================================================
// TREND CHART: satu titik per scan
// - Sumbu waktu sebenarnya; garis lurus antar scan dengan arsiran lembut di bawahnya.
// - Satu titik per scan. Titik yang rapat (< 14 px) atau saling menutupi digabung jadi titik berangka;
//   beberapa domain dalam satu grup = abu-abu dengan tanda warna domainnya.
// - Hover titik: tooltip hanya scan itu (+ perubahan dari scan sebelumnya), domain lain memudar.
// - Klik titik: buka Scan Details. Klik grup: daftar menempel per domain.
// - Legenda = penanda warna sekaligus filter (dropdown Domain, Top 10, sorot, fokus) seperti sebelumnya.
// =========================================================
const TREND_SEV = [
    ['CRITICAL', 'Critical', '#991B1B'],
    ['HIGH', 'High', '#EF4444'],
    ['MEDIUM', 'Medium', '#F97316'],
    ['LOW', 'Low', '#3B82F6'],
    ['INFO', 'Info', '#10B981']
];
const TREND_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];
// vulnHidden / sevHidden: null = belum dipilih pengguna (pakai default), Set = key garis yang disembunyikan
const trendState = { vuln: null, sev: null, enlarged: null, vulnHidden: null, sevHidden: null, vulnQuery: '', sevQuery: '', vulnFocusPrev: null, sevFocusPrev: null };
const TREND_DEFAULT_MAX = 10;   // maksimal garis yang langsung tampil
const TREND_SEARCH_MIN = 9;     // kotak cari muncul kalau lebih dari 8 baris
let trendPanelEl = null;

function trendIsDark() {
    return document.documentElement.getAttribute('data-theme') === 'dark';
}

function trendAlpha(hex, a) {
    const rgb = hexToRgb(hex);
    return rgb ? `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${a})` : hex;
}

// Label sumbu waktu: langkah "rapi" (jam, hari, minggu) yang menghasilkan paling banyak maxTicks label
const TREND_TICK_STEPS = [1, 2, 3, 6, 12, 24, 48, 72, 168, 336, 720].map(h => h * 3600000);
function trendTimeTicks(min, max, maxTicks) {
    const step = TREND_TICK_STEPS.find(s => (max - min) / s <= maxTicks) || TREND_TICK_STEPS[TREND_TICK_STEPS.length - 1];
    const first = new Date(min);
    if (step < 86400000) first.setMinutes(0, 0, 0);
    else first.setHours(0, 0, 0, 0);
    const ticks = [];
    for (let t = first.getTime(); t <= max; t += step) if (t >= min) ticks.push({ value: t });
    return { ticks, step };
}

function trendDayMonth(d) {
    return `${d.getDate()} ${TREND_MONTHS[d.getMonth()]}`;
}

function trendTime(d) {
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

// Rentang waktu satu grup: "Sel 21 Jul, 11:39 sampai 13:33" atau lintas hari "21 Jul 23:50 sampai 22 Jul 00:20"
function trendSpanText(scans) {
    const ts = scans.map(s => s.t.getTime());
    const a = new Date(Math.min(...ts)), b = new Date(Math.max(...ts));
    const sameDay = a.toDateString() === b.toDateString();
    const day = `${SH_DAYS[a.getDay()]} ${trendDayMonth(a)}`;
    if (a.getTime() === b.getTime()) return `${day}, ${trendTime(a)}`;
    return sameDay ? `${day}, ${trendTime(a)} sampai ${trendTime(b)}` : `${trendDayMonth(a)} ${trendTime(a)} sampai ${trendDayMonth(b)} ${trendTime(b)}`;
}

// Data mentah API -> titik per scan.
// dom[domain] / sev[severity] = [{x: ms, y, scan?}]: titik awal dari scan sebelum rentang (baseline, tanpa scan),
// satu titik per scan, lalu titik akhir di ujung rentang (garis diteruskan, tanpa scan).
// Hanya domain yang di-scan dalam rentang yang tampil; nilai severity = jumlah nilai terakhir tiap domain itu.
function trendBuildTimeModel(raw) {
    if (!raw || !Array.isArray(raw.scans) || !raw.range_start || !raw.range_end) return null;
    const start = new Date(raw.range_start).getTime();
    const end = new Date(raw.range_end).getTime();
    if (isNaN(start) || isNaN(end)) return null;
    const scans = raw.scans.map(s => ({ ...s, t: new Date(s.date) })).filter(s => !isNaN(s.t)).sort((a, b) => a.t - b.t);
    const domains = [...new Set(scans.map(s => s.domain))];
    const latest = {};
    (raw.baseline || []).forEach(b => { if (domains.includes(b.domain)) latest[b.domain] = { ...b, t: new Date(b.date) }; });
    const sumSev = (k) => Object.values(latest).reduce((sum, s) => sum + ((s.counts && s.counts[k]) || 0), 0);
    const dom = {};
    domains.forEach(d => { dom[d] = latest[d] ? [{ x: start, y: latest[d].total }] : []; });
    const sev = {};
    const hasBase = Object.keys(latest).length > 0;
    TREND_SEV.forEach(([k]) => { sev[k] = hasBase ? [{ x: start, y: sumSev(k) }] : []; });
    const prevOf = new Map();
    scans.forEach(s => {
        if (latest[s.domain]) prevOf.set(s.id, latest[s.domain]);
        latest[s.domain] = s;
        const x = s.t.getTime();
        dom[s.domain].push({ x, y: s.total, scan: s });
        TREND_SEV.forEach(([k]) => sev[k].push({ x, y: sumSev(k), scan: s }));
    });
    const tail = (arr) => { if (arr.length) arr.push({ x: end, y: arr[arr.length - 1].y }); };
    Object.values(dom).forEach(tail);
    Object.values(sev).forEach(tail);
    return { start, end, scans, domains, dom, sev, prevOf };
}

// Pengelompokan titik dalam piksel. items: [{key, x, y, scan}].
// 1) Per key: scan yang berjarak < gap dari scan sebelumnya (key sama) jadi satu grup (posisi = scan terakhir).
// 2) Grup/titik yang akan saling menutupi (jarak < jari-jari + jari-jari + 2) digabung, key-nya disatukan.
function trendClusterItems(items, { gap, rad }) {
    const byKey = new Map();
    items.forEach(it => { if (!byKey.has(it.key)) byKey.set(it.key, []); byKey.get(it.key).push(it); });
    let groups = [];
    byKey.forEach((list, key) => {
        let cur = null, px = -Infinity;
        list.slice().sort((a, b) => a.x - b.x).forEach(it => {
            if (cur && it.x - px < gap) { cur.scans.push(it.scan); cur.x = it.x; cur.y = it.y; }
            else { cur = { x: it.x, y: it.y, keys: [key], scans: [it.scan] }; groups.push(cur); }
            px = it.x;
        });
    });
    let merged = true;
    while (merged) {
        merged = false;
        for (let i = 0; i < groups.length && !merged; i++) {
            for (let j = i + 1; j < groups.length && !merged; j++) {
                const a = groups[i], b = groups[j];
                if (Math.hypot(a.x - b.x, a.y - b.y) < rad(a.scans.length) + rad(b.scans.length) + 2) {
                    const big = a.scans.length >= b.scans.length ? a : b;
                    groups[i] = { x: big.x, y: big.y, keys: [...new Set([...a.keys, ...b.keys])], scans: [...a.scans, ...b.scans] };
                    groups.splice(j, 1);
                    merged = true;
                }
            }
        }
    }
    return groups.sort((a, b) => a.x - b.x || a.y - b.y);
}

// Perubahan jumlah temuan dibanding scan sebelumnya domain yang sama
function trendDeltaText(scan, prev) {
    if (!prev) return 'Scan pertama domain ini';
    const t = prev.t instanceof Date ? prev.t : new Date(prev.date);
    const hm = `${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`;
    const diff = (scan.total || 0) - (prev.total || 0);
    if (!diff) return `Sama dengan scan sebelumnya (${hm})`;
    return `${diff > 0 ? '+' : '-'}${Math.abs(diff)} temuan dari scan sebelumnya (${hm})`;
}

function trendSeries(kind, model) {
    const pack = (key, label, color, pts) => ({
        key, label, color, data: pts,
        last: pts.length ? pts[pts.length - 1].y : null,
        max: pts.length ? Math.max(...pts.map(p => p.y)) : null
    });
    if (kind === 'vuln') {
        return model.domains.filter(d => model.dom[d].length).map(d => pack(d, d, getDomainColor(d), model.dom[d]));
    }
    return TREND_SEV.map(([k, label, color]) => pack(k, label, color, model.sev[k]));
}

// Urutan legenda: nilai scan terakhir terbesar dulu
function trendRanked(inst) {
    // Severity selalu urut tetap: Critical, High, Medium, Low, Info (urutan TREND_SEV)
    if (inst.kind === 'sev') return inst.series.slice();
    return inst.series.slice().sort((a, b) => ((b.last ?? -1) - (a.last ?? -1)) || ((b.max ?? -1) - (a.max ?? -1)) || a.label.localeCompare(b.label));
}

function trendHiddenKey(kind) {
    return kind === 'vuln' ? 'vulnHidden' : 'sevHidden';
}

// Garis yang disembunyikan: pilihan pengguna (diingat antar rentang tanggal), atau default maks. 10 garis
function trendResolveHidden(inst) {
    const saved = trendState[trendHiddenKey(inst.kind)];
    const keys = new Set(inst.series.map(s => s.key));
    if (saved) return new Set([...saved].filter(k => keys.has(k)));
    if (inst.series.length > TREND_DEFAULT_MAX) return trendDefaultHidden(inst);
    return new Set();
}

function trendVisibleKeys(inst) {
    return inst.series.filter(s => !inst.hidden.has(s.key)).map(s => s.key);
}

// Satu-satunya garis yang tampil (mode fokus), atau null
function trendFocusKey(inst) {
    const v = trendVisibleKeys(inst);
    return v.length === 1 && inst.series.length > 1 ? v[0] : null;
}

// Arsiran di bawah garis makin tipis saat garis yang tampil makin banyak, agar tidak menumpuk jadi gelap
function trendFillAlpha(visibleCount) {
    if (visibleCount <= 5) return 0.08;
    if (visibleCount <= 8) return 0.04;
    return 0;
}

// ---- Titik per scan: tata letak (piksel), gambar, dan sasaran hover/klik
const TREND_GAP = 14;                                       // titik lebih rapat dari ini digabung
const TREND_MIX = '#334155';                                // grup berisi beberapa domain
const trendRad = (n) => (n === 1 ? 4.5 : (n > 9 ? 13 : 11));

// Sasaran di grafik. Domain: titik di garis domainnya. Severity: satu sasaran per scan di garis severity teratas
// yang tampil (satu scan mengubah beberapa severity sekaligus).
function trendLayoutTargets(inst) {
    const chart = inst.chart;
    if (!chart || !inst.model) return [];
    const xs = chart.scales.x, ys = chart.scales.y;
    const visible = trendVisibleKeys(inst);
    const items = [];
    if (inst.kind === 'vuln') {
        visible.forEach(k => (inst.model.dom[k] || []).forEach(p => {
            if (p.scan) items.push({ key: k, x: xs.getPixelForValue(p.x), y: ys.getPixelForValue(p.y), scan: p.scan });
        }));
    } else if (visible.length) {
        inst.model.scans.forEach(s => {
            const top = Math.max(...visible.map(k => (inst.model.sev[k].find(p => p.scan === s) || { y: 0 }).y));
            items.push({ key: 'scan', x: xs.getPixelForValue(s.t.getTime()), y: ys.getPixelForValue(top), scan: s });
        });
    }
    return trendClusterItems(items, { gap: TREND_GAP, rad: trendRad }).map(g => ({
        ...g,
        r: trendRad(g.scans.length),
        color: inst.kind === 'vuln' && g.keys.length === 1 ? (inst.series.find(s => s.key === g.keys[0]) || {}).color || TREND_MIX : TREND_MIX
    }));
}

// Plugin: gambar titik/grup, garis penunjuk, dan sorotan di atas garis Chart.js
const trendDotsPlugin = {
    id: 'trendDots',
    afterDatasetsDraw(chart) {
        const inst = chart.$trendInst;
        if (!inst) return;
        inst.targets = trendLayoutTargets(inst);
        const ctx = chart.ctx, dark = trendIsDark();
        const ring = dark ? '#151e32' : '#ffffff';
        const { top, bottom } = chart.chartArea;
        const hot = inst.hover;
        if (hot) {
            ctx.save();
            ctx.beginPath(); ctx.moveTo(hot.x, top); ctx.lineTo(hot.x, bottom);
            ctx.lineWidth = 1; ctx.strokeStyle = dark ? 'rgba(148, 163, 184, 0.6)' : 'rgba(71, 84, 103, 0.55)'; ctx.stroke();
            ctx.restore();
        }
        // Severity: titik kecil di setiap garis severity pada waktu scan (penanda saja)
        if (inst.kind === 'sev') {
            trendVisibleKeys(inst).forEach(k => {
                const s = inst.series.find(x => x.key === k);
                (inst.model.sev[k] || []).forEach(p => {
                    if (!p.scan) return;
                    ctx.beginPath();
                    ctx.arc(chart.scales.x.getPixelForValue(p.x), chart.scales.y.getPixelForValue(p.y), 2.5, 0, Math.PI * 2);
                    ctx.fillStyle = s.color; ctx.fill();
                });
            });
        }
        (inst.targets || []).forEach(t => {
            const dim = inst.hl && !t.keys.includes(inst.hl);
            const isHot = hot && hot.x === t.x && hot.y === t.y;
            ctx.save();
            ctx.globalAlpha = dim ? 0.25 : 1;
            if (isHot) {
                ctx.beginPath(); ctx.arc(t.x, t.y, t.r + 6, 0, Math.PI * 2);
                ctx.fillStyle = trendAlpha(t.color, 0.2); ctx.fill();
            }
            const r = t.scans.length === 1 ? (isHot ? 6 : t.r) : t.r;
            if (t.scans.length > 1 || inst.kind === 'vuln') {
                ctx.beginPath(); ctx.arc(t.x, t.y, r, 0, Math.PI * 2);
                ctx.fillStyle = t.color; ctx.fill();
                ctx.lineWidth = 2; ctx.strokeStyle = ring; ctx.stroke();
            }
            if (t.scans.length > 1) {
                ctx.fillStyle = '#ffffff';
                ctx.font = '700 11px Inter, system-ui, sans-serif';
                ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
                ctx.fillText(String(t.scans.length), t.x, t.y + 0.5);
                // Grup beberapa domain: titik warna kecil di bawahnya (maks. 5)
                if (inst.kind === 'vuln' && t.keys.length > 1) {
                    const keys = t.keys.slice(0, 5);
                    keys.forEach((k, i) => {
                        const c = (inst.series.find(s => s.key === k) || {}).color || TREND_MIX;
                        ctx.beginPath(); ctx.arc(t.x - ((keys.length - 1) * 7) / 2 + i * 7, t.y + t.r + 5, 2.5, 0, Math.PI * 2);
                        ctx.fillStyle = c; ctx.fill();
                    });
                }
            }
            ctx.restore();
        });
    }
};

// Sasaran di bawah kursor (piksel canvas), atau null. Severity: titik tunggal cukup sejajar waktunya.
function trendHitTarget(inst, px, py) {
    const { left, right, top, bottom } = inst.chart.chartArea;
    if (px < left - 14 || px > right + 14 || py < top - 14 || py > bottom + 14) return null;
    let best = null, bestD = Infinity;
    (inst.targets || []).forEach(t => {
        const d = inst.kind === 'sev' && t.scans.length === 1 ? Math.abs(t.x - px) : Math.hypot(t.x - px, t.y - py);
        const reach = (t.scans.length === 1 ? 10 : t.r + 4);
        if (d <= reach && d < bestD) { best = t; bestD = d; }
    });
    return best;
}

// Nama domain/severity untuk satu sasaran
function trendKeyLabel(inst, key) {
    const s = inst.series.find(x => x.key === key);
    return s ? s.label : key;
}

// Isi tooltip: satu scan (rincian + perubahan) atau grup (jumlah, domain, rentang waktu)
function trendTipHtml(inst, t) {
    if (t.scans.length === 1) {
        const s = t.scans[0];
        const color = inst.kind === 'vuln' ? t.color : getDomainColor(s.domain);
        const when = `${s.type ? `${s.type} · ` : ''}${trendSpanText([s])} WIB`;
        return `<div class="tc-tip-title"><i class="tc-tip-mark" style="background:${color}"></i>${escapeHtml(s.domain)}</div>
            <div class="tc-tip-meta">${escapeHtml(when)}</div>
            ${renderSevSummary(s.counts)}
            <div class="tc-tip-delta">${escapeHtml(trendDeltaText(s, inst.model.prevOf.get(s.id)))}</div>
            <div class="tc-tip-foot">Klik titik untuk buka hasil scan</div>`;
    }
    const doms = [...new Set(t.scans.map(s => s.domain))];
    const who = doms.length > 1 ? `${doms.length} domain` : doms[0];
    return `<div class="tc-tip-title">${t.scans.length} scan · ${escapeHtml(who)}</div>
        <div class="tc-tip-meta">${escapeHtml(trendSpanText(t.scans))}</div>
        <div class="tc-tip-foot">Klik untuk melihat daftar</div>`;
}

// Tooltip HTML di luar canvas, di samping sasaran supaya titiknya tidak tertutup
function trendShowTip(inst, t) {
    let el = document.getElementById('tcTip');
    if (!el) {
        el = document.createElement('div');
        el.id = 'tcTip';
        el.className = 'tc-tip';
        el.setAttribute('role', 'tooltip');
        document.body.appendChild(el);
    }
    el.innerHTML = trendTipHtml(inst, t);
    el.classList.add('is-on');
    const r = inst.canvas.getBoundingClientRect();
    const px = r.left + t.x, py = r.top + t.y;
    const w = el.offsetWidth, h = el.offsetHeight, gap = t.r + 12, vw = window.innerWidth, vh = window.innerHeight;
    const area = inst.chart.chartArea;
    let left = t.x > (area.left + area.right) / 2 ? px - gap - w : px + gap;
    if (left + w > vw - 8) left = px - gap - w;
    if (left < 8) left = px + gap;
    const top = Math.min(Math.max(py - h / 2, 8), vh - h - 8);
    el.style.left = `${Math.round(left + window.scrollX)}px`;
    el.style.top = `${Math.round(top + window.scrollY)}px`;
}

function trendHideTip() {
    document.getElementById('tcTip')?.classList.remove('is-on');
}

// Hover/fokus papan ketik pada satu sasaran (null = lepas): tooltip, garis penunjuk, domain lain memudar
function trendSetHover(inst, t) {
    const same = inst.hover && t && inst.hover.x === t.x && inst.hover.y === t.y;
    if (same) return;
    inst.hover = t;
    const key = t && inst.kind === 'vuln' && t.keys.length === 1 ? t.keys[0] : null;
    if (inst.hl !== key) trendHighlight(inst, key);
    else inst.chart.draw();
    if (t) trendShowTip(inst, t); else trendHideTip();
    inst.canvas.style.cursor = t ? 'pointer' : 'default';
}

function trendBindPointer(inst) {
    const c = inst.canvas;
    const at = (e) => { const r = c.getBoundingClientRect(); return trendHitTarget(inst, e.clientX - r.left, e.clientY - r.top); };
    c.onmousemove = (e) => trendSetHover(inst, at(e));
    c.onmouseleave = () => trendSetHover(inst, null);
    c.onclick = (e) => {
        const t = at(e);
        if (t) trendActivate(inst, t, { x: e.clientX, y: e.clientY });
    };
}

function trendRender(kind, canvas, legendEl, opts = {}) {
    if (!canvas || typeof Chart === 'undefined') return null;
    const existing = Chart.getChart ? Chart.getChart(canvas) : null;
    if (existing) existing.destroy();
    document.getElementById('tcTip')?.classList.remove('is-on');

    const raw = kind === 'vuln' ? rawTrendData : rawSevTrendData;
    const model = trendBuildTimeModel(raw);
    const inst = { kind, canvas, legendEl, ddEl: opts.ddEl || null, pickEl: null, hl: null, model, series: [], hidden: new Set(), chart: null, kbIndex: null, targets: [], hover: null };
    if (inst.ddEl) inst.ddEl.innerHTML = '';
    if (!model) {
        trendLegendMessage(legendEl, 'Data tren belum tersedia.');
        return inst;
    }
    inst.series = trendSeries(kind, model);
    if (kind === 'vuln') {
        // Warna mengikuti urutan legenda (temuan terbanyak dulu): 12 domain teratas pasti berbeda warna,
        // termasuk 10 garis yang tampil secara default
        trendRanked(inst).forEach((s, i) => {
            s.color = PALETTE[i % PALETTE.length];
            domainColorMap[s.key] = s.color;
        });
    }
    inst.hidden = trendResolveHidden(inst);
    if (!inst.series.length) {
        trendLegendMessage(legendEl, kind === 'vuln' ? 'Belum ada hasil scan untuk domain dan rentang tanggal ini.' : 'Belum ada hasil scan pada rentang tanggal ini.');
    }

    const fillAlpha = trendFillAlpha(inst.series.length - inst.hidden.size);
    const datasets = inst.series.map(s => ({
        label: s.label,
        _key: s.key,
        _color: s.color,
        data: s.data,
        borderColor: s.color,
        backgroundColor: trendAlpha(s.color, fillAlpha),
        fill: 'origin',
        borderWidth: 1.5,
        tension: 0,
        spanGaps: true,
        // Titik scan digambar sendiri oleh trendDotsPlugin (supaya bisa digabung jadi grup)
        pointRadius: 0,
        pointHoverRadius: 0,
        hidden: inst.hidden.has(s.key)
    }));

    const tickColor = () => (trendIsDark() ? '#94a3b8' : '#667085');
    // Jumlah label mengikuti lebar grafik (sekitar 80 px per label) supaya tidak bertumpuk
    const maxTicks = opts.enlarged ? 12 : 6;
    const tickInfo = { ticks: [], step: 86400000 };
    const buildTicks = (axis) => {
        const fit = Math.max(2, Math.floor((axis.width || canvas.clientWidth || 480) / 80));
        Object.assign(tickInfo, trendTimeTicks(model.start, model.end, Math.min(maxTicks, fit)));
        axis.ticks = tickInfo.ticks;
    };
    inst.chart = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: { datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            // Hover dan klik ditangani sendiri (trendBindPointer): Chart.js tidak perlu mendengar event
            events: [],
            parsing: false,
            normalized: true,
            layout: { padding: { top: 16, right: 16 } },
            scales: {
                x: {
                    type: 'linear',
                    min: model.start,
                    max: model.end,
                    grid: { display: false },
                    border: { display: false },
                    afterBuildTicks: buildTicks,
                    ticks: {
                        maxRotation: 0,
                        autoSkip: false,
                        color: tickColor,
                        // Tengah malam = tanggal, selain itu jam saja (label pendek)
                        callback: (v) => {
                            const d = new Date(v);
                            return tickInfo.step < 86400000 && (d.getHours() || d.getMinutes()) ? trendTime(d) : trendDayMonth(d);
                        }
                    }
                },
                y: {
                    beginAtZero: true,
                    grace: '10%',
                    border: { display: false },
                    grid: { color: () => (trendIsDark() ? 'rgba(148, 163, 184, 0.12)' : '#EEF0F3') },
                    ticks: { precision: 0, color: tickColor }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            }
        },
        plugins: [trendDotsPlugin]
    });
    inst.chart.$trendInst = inst;
    inst.chart.draw();
    trendBindPointer(inst);

    trendRenderDropdown(inst);
    trendRenderReadLegend(inst);
    trendBindKeyboard(inst);
    return inst;
}

function trendLegendMessage(el, text) {
    if (el) el.innerHTML = `<div class="tc-legend-empty">${escapeHtml(text)}</div>`;
}

function trendRenderPicker(inst) {
    const el = inst.pickEl;
    if (!el || !inst.series.length) return;
    const searchable = inst.series.length >= TREND_SEARCH_MIN;
    const query = searchable ? (trendState[inst.kind + 'Query'] || '') : '';
    const noun = inst.kind === 'vuln' ? 'domain' : 'severity';
    el.innerHTML = `
        <div class="tc-lg-top">
            ${searchable ? `<label class="tc-lg-search">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.5-3.5"></path></svg>
                <input type="search" data-tc-search placeholder="Cari ${noun}..." aria-label="Cari ${noun} di legenda" value="${escapeHtml(query)}" autocomplete="off">
            </label>` : ''}
            <div class="tc-lg-bar"><span class="tc-lg-count" data-tc-count></span><span class="tc-lg-actions" data-tc-actions></span></div>
        </div>
        <div class="tc-lg-list" role="group" aria-label="Legenda ${noun}: centang untuk menampilkan garis" data-tc-list></div>`;
    trendRenderLegendRows(inst);

    el.onclick = (e) => {
        const t = e.target;
        if (t.closest('[data-tc-all]')) { trendState[inst.kind + 'FocusPrev'] = null; trendSetHidden(inst, new Set()); return; }
        if (t.closest('[data-tc-none]')) { trendState[inst.kind + 'FocusPrev'] = null; trendSetHidden(inst, new Set(inst.series.map(s => s.key))); return; }
        if (t.closest('[data-tc-top]')) { trendState[inst.kind + 'FocusPrev'] = null; trendSetHidden(inst, trendDefaultHidden(inst)); return; }
        const only = t.closest('[data-tc-only]');
        if (only) {
            const key = only.closest('[data-tc-key]').dataset.tcKey;
            trendState[inst.kind + 'FocusPrev'] = null;
            trendSetHidden(inst, new Set(inst.series.map(s => s.key).filter(k => k !== key)), key, 'only');
            return;
        }
        const tog = t.closest('[data-tc-toggle]');
        if (tog) {
            const key = tog.closest('[data-tc-key]').dataset.tcKey;
            const next = new Set(inst.hidden);
            next.has(key) ? next.delete(key) : next.add(key);
            trendState[inst.kind + 'FocusPrev'] = null;
            trendSetHidden(inst, next, key, 'toggle');
        }
    };
    const input = el.querySelector('[data-tc-search]');
    if (input) {
        input.addEventListener('input', () => {
            trendState[inst.kind + 'Query'] = input.value;
            trendRenderLegendRows(inst);
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && input.value) { e.stopPropagation(); input.value = ''; trendState[inst.kind + 'Query'] = ''; trendRenderLegendRows(inst); }
        });
    }
}

// Isi daftar + hitungan saja (kotak cari tidak di-render ulang agar fokus mengetik tidak hilang)
function trendRenderLegendRows(inst) {
    const el = inst.pickEl;
    if (!el) return;
    const list = el.querySelector('[data-tc-list]');
    const countEl = el.querySelector('[data-tc-count]');
    const actEl = el.querySelector('[data-tc-actions]');
    const searchable = inst.series.length >= TREND_SEARCH_MIN;
    const q = searchable ? (trendState[inst.kind + 'Query'] || '').trim().toLowerCase() : '';
    const noun = inst.kind === 'vuln' ? 'domain' : 'severity';
    const rows = trendRanked(inst).filter(s => !q || s.label.toLowerCase().includes(q));
    const total = inst.series.length;
    const shown = total - inst.hidden.size;
    const check = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"></polyline></svg>';

    if (list) {
        list.innerHTML = rows.length ? rows.map(s => {
            const on = !inst.hidden.has(s.key);
            const label = escapeHtml(s.label);
            return `<div class="tc-legend-row${on ? '' : ' is-off'}" data-tc-key="${escapeHtml(s.key)}">
                <button type="button" class="tc-lg-toggle" role="checkbox" aria-checked="${on}" data-tc-toggle title="${label}: klik untuk ${on ? 'menyembunyikan' : 'menampilkan'} garis">
                    <span class="tc-lg-check">${check}</span>
                    <span class="tc-swatch" style="background:${s.color}"></span>
                    <span class="tc-legend-label">${label.replace(/\./g, '.<wbr>').replace(/-/g, '-<wbr>')}</span>
                </button>
                <button type="button" class="tc-lg-only" data-tc-only title="Tampilkan hanya ${label}">Hanya ini</button>
            </div>`;
        }).join('') : `<div class="tc-legend-empty">Tidak ada ${noun} yang cocok dengan "${escapeHtml(q)}".</div>`;
    }
    if (countEl) {
        countEl.textContent = q
            ? `${rows.length} cocok`
            : (inst.hidden.size ? `${shown} dari ${total} tampil` : `${total} ${noun}`);
    }
    if (actEl) {
        const topBtn = total > TREND_DEFAULT_MAX
            ? `<button type="button" class="tc-lg-link" data-tc-top ${trendIsDefaultHidden(inst) ? 'disabled' : ''}>Top ${TREND_DEFAULT_MAX}</button><span aria-hidden="true">·</span>` : '';
        actEl.innerHTML = searchable
            ? `${topBtn}<button type="button" class="tc-lg-link" data-tc-all ${inst.hidden.size ? '' : 'disabled'}>Semua</button><span aria-hidden="true">·</span><button type="button" class="tc-lg-link" data-tc-none ${shown ? '' : 'disabled'}>Kosongkan</button>`
            : (inst.hidden.size ? `<button type="button" class="tc-lg-link" data-tc-all>Tampilkan semua</button>` : '');
    }
}

// Pilihan default: domain dengan temuan terbanyak (Top 10) tampil, sisanya disembunyikan
function trendDefaultHidden(inst) {
    return new Set(trendRanked(inst).slice(TREND_DEFAULT_MAX).map(s => s.key));
}

function trendIsDefaultHidden(inst) {
    const d = trendDefaultHidden(inst);
    return d.size === inst.hidden.size && [...d].every(k => inst.hidden.has(k));
}

const TREND_ICON_GLOBE = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"></path><path d="M2 12h20"></path></svg>';
const TREND_ICON_CHEV = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"></polyline></svg>';

// Dropdown "Domain: X dari N" (hanya Vulnerability Trend): panelnya berisi pemilih (cari, centang, Top 10/Semua/Kosongkan)
function trendRenderDropdown(inst) {
    const dd = inst.ddEl;
    if (!dd) return;
    if (inst.kind !== 'vuln' || !inst.series.length) { dd.innerHTML = ''; inst.pickEl = null; return; }
    const pid = `${dd.id || 'tcDd'}Panel`;
    dd.innerHTML = `
        <button type="button" class="tc-dd-btn" aria-haspopup="dialog" aria-expanded="false" aria-controls="${pid}" data-tc-dd>
            ${TREND_ICON_GLOBE}<span class="tc-dd-label"></span><span class="tc-dd-badge" hidden>Top ${TREND_DEFAULT_MAX}</span>${TREND_ICON_CHEV}
        </button>
        <div class="tc-dd-panel" id="${pid}" role="dialog" aria-label="Pilih domain yang ditampilkan" hidden>
            <div class="tc-legend tc-dd-picker"></div>
            <p class="tc-dd-foot">Default ${TREND_DEFAULT_MAX} domain dengan temuan terbanyak.</p>
        </div>`;
    inst.pickEl = dd.querySelector('.tc-dd-picker');
    trendRenderPicker(inst);
    trendUpdateDdBtn(inst);
    const btn = dd.querySelector('[data-tc-dd]');
    const panel = dd.querySelector('.tc-dd-panel');
    const setOpen = (open) => {
        panel.hidden = !open;
        btn.setAttribute('aria-expanded', String(open));
        if (open) dd.querySelector('[data-tc-search]')?.focus({ preventScroll: true });
    };
    btn.onclick = () => setOpen(panel.hidden);
    dd.onkeydown = (e) => {
        if (e.key === 'Escape' && !panel.hidden) { e.stopPropagation(); setOpen(false); btn.focus(); }
    };
}

function trendUpdateDdBtn(inst) {
    const dd = inst.ddEl;
    if (!dd || !inst.pickEl) return;
    const total = inst.series.length;
    const shown = total - inst.hidden.size;
    const label = dd.querySelector('.tc-dd-label');
    const badge = dd.querySelector('.tc-dd-badge');
    if (label) label.textContent = `Domain: ${shown} dari ${total}`;
    if (badge) badge.hidden = !(total > TREND_DEFAULT_MAX && trendIsDefaultHidden(inst));
}

// Klik di luar dropdown menutupnya (composedPath: baris pemilih bisa sudah dirender ulang saat event sampai sini)
document.addEventListener('click', (e) => {
    const path = e.composedPath ? e.composedPath() : [];
    document.querySelectorAll('.tc-dd').forEach(dd => {
        const panel = dd.querySelector('.tc-dd-panel');
        if (!panel || panel.hidden || path.includes(dd)) return;
        panel.hidden = true;
        dd.querySelector('[data-tc-dd]')?.setAttribute('aria-expanded', 'false');
    });
});

// Legenda di bawah grafik: hanya domain/severity yang tampil, warna + nama + nilai terakhir.
// Hover = sorot garis, klik = tampilkan garis itu saja (klik lagi = kembali ke pilihan sebelumnya).
function trendRenderReadLegend(inst) {
    const el = inst.legendEl;
    if (!el || !inst.series.length) return;
    const sev = inst.kind === 'sev';
    const focus = trendFocusKey(inst);
    const items = trendRanked(inst).filter(s => !inst.hidden.has(s.key));
    const body = items.length
        ? items.map(s => {
            const label = escapeHtml(s.label);
            const val = s.last ?? '-';
            return `<button type="button" class="tc-rl-item${focus === s.key ? ' is-focus' : ''}" data-tc-key="${escapeHtml(s.key)}" title="${label}"
                aria-pressed="${focus === s.key}" aria-label="${label}, nilai terakhir ${val}. Klik untuk ${focus === s.key ? 'kembali ke semua garis' : 'menampilkan garis ini saja'}">
                <span class="tc-swatch" style="background:${s.color}"></span><span class="tc-rl-name">${label}</span><span class="tc-rl-val">${val}</span>
            </button>`;
        }).join('')
        : `<div class="tc-rl-empty">Tidak ada ${sev ? 'severity' : 'domain'} yang dipilih.${sev ? '' : ' Pilih lewat tombol Domain di atas grafik.'}</div>`;
    el.innerHTML = `<div class="tc-rl${sev ? ' is-sev' : ''}" role="group" aria-label="Legenda ${sev ? 'severity' : 'domain'}">${body}</div>`;
    const keyOf = (t) => t && t.closest && t.closest('.tc-rl-item')?.dataset.tcKey;
    el.onmouseover = (e) => { const k = keyOf(e.target); if (k) trendHighlight(inst, k); };
    el.onmouseout = (e) => { if (keyOf(e.target) && keyOf(e.relatedTarget) !== keyOf(e.target)) trendHighlight(inst, null); };
    el.onfocusin = (e) => { const k = keyOf(e.target); if (k) trendHighlight(inst, k); };
    el.onfocusout = (e) => { if (!keyOf(e.relatedTarget)) trendHighlight(inst, null); };
    el.onclick = (e) => { const k = keyOf(e.target); if (k) trendToggleFocus(inst, k); };
}

// Sorot satu garis (garis lain meredup) tanpa mengubah pilihan
function trendHighlight(inst, key) {
    if (inst.hl === key) return;
    inst.hl = key;
    const chart = inst.chart;
    if (chart) {
        const fillAlpha = trendFillAlpha(inst.series.length - inst.hidden.size);
        chart.data.datasets.forEach(ds => {
            const hot = ds._key === key;
            ds.borderColor = key && !hot ? trendAlpha(ds._color, 0.15) : ds._color;
            ds.borderWidth = hot ? 2.5 : 1.5;
            ds.order = hot ? -1 : 0;
            ds.backgroundColor = trendAlpha(ds._color, key ? (hot ? 0.15 : 0) : fillAlpha);
        });
        chart.update('none');
    }
    const rl = inst.legendEl && inst.legendEl.querySelector('.tc-rl');
    if (rl) {
        rl.classList.toggle('is-dim', !!key);
        rl.querySelectorAll('.tc-rl-item').forEach(b => b.classList.toggle('is-hot', b.dataset.tcKey === key));
    }
}

function trendToggleFocus(inst, key) {
    const pk = inst.kind + 'FocusPrev';
    if (trendFocusKey(inst) === key && trendState[pk]) {
        const prev = trendState[pk];
        trendState[pk] = null;
        trendSetHidden(inst, new Set([...prev].filter(k => inst.series.some(s => s.key === k))));
    } else {
        trendState[pk] = new Set(inst.hidden);
        trendSetHidden(inst, new Set(inst.series.map(s => s.key).filter(k => k !== key)));
    }
    inst.legendEl?.querySelector(`[data-tc-key="${CSS.escape(key)}"]`)?.focus({ preventScroll: true });
}

function trendSetHidden(inst, hidden, focusKey, focusWhat) {
    inst.hidden = hidden;
    // Diingat untuk grafik utama maupun modal perbesar, dan saat rentang tanggal diganti
    trendState[trendHiddenKey(inst.kind)] = new Set(hidden);
    closeTrendPanel();
    inst.hover = null;
    inst.kbIndex = null;
    trendHideTip();
    if (inst.chart) {
        const fillAlpha = trendFillAlpha(inst.series.length - hidden.size);
        inst.chart.data.datasets.forEach(ds => {
            ds.hidden = hidden.has(ds._key);
            ds.backgroundColor = trendAlpha(ds._color, fillAlpha);
            ds.borderColor = ds._color;
            ds.borderWidth = 1.5;
            ds.order = 0;
        });
        inst.chart.update();
    }
    inst.hl = null;
    trendRenderLegendRows(inst);
    trendRenderReadLegend(inst);
    trendUpdateDdBtn(inst);
    if (focusKey && inst.pickEl) {
        const row = inst.pickEl.querySelector(`[data-tc-key="${CSS.escape(focusKey)}"]`);
        const target = row && row.querySelector(focusWhat === 'only' ? '[data-tc-only]' : '[data-tc-toggle]');
        if (target) target.focus({ preventScroll: true });
    }
}

// Papan ketik: panah kiri/kanan berpindah antar titik/grup (urut waktu), Enter membuka, Escape menutup daftar
function trendBindKeyboard(inst) {
    const c = inst.canvas;
    c.tabIndex = 0;
    c.setAttribute('role', 'img');
    c.setAttribute('aria-label', `${inst.kind === 'vuln' ? 'Vulnerability Trend' : 'Severity Trend'}. Panah kiri dan kanan untuk berpindah titik scan, Enter untuk membuka, Escape untuk menutup daftar.`);
    c.onkeydown = (e) => {
        const targets = inst.targets || [];
        if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
            if (!targets.length) return;
            e.preventDefault();
            if (inst.kbIndex === null || inst.kbIndex >= targets.length) inst.kbIndex = targets.length - 1;
            else inst.kbIndex = Math.min(targets.length - 1, Math.max(0, inst.kbIndex + (e.key === 'ArrowRight' ? 1 : -1)));
            trendSetHover(inst, targets[inst.kbIndex]);
        } else if (e.key === 'Enter' && inst.kbIndex !== null && targets[inst.kbIndex]) {
            e.preventDefault();
            const t = targets[inst.kbIndex];
            const r = c.getBoundingClientRect();
            trendActivate(inst, t, { x: r.left + t.x, y: r.top + t.y });
        } else if (e.key === 'Escape') {
            closeTrendPanel();
        }
    };
    c.onblur = () => {
        if (inst.kbIndex !== null) {
            inst.kbIndex = null;
            trendSetHover(inst, null);
        }
    };
}

// Klik/Enter pada sasaran: satu scan langsung dibuka, grup membuka daftar
function trendActivate(inst, t, pos) {
    const sevFilter = inst.kind === 'sev' ? trendFocusKey(inst) : null;
    trendSetHover(inst, null);
    if (t.scans.length === 1) trendOpenScan(inst, t.scans[0], sevFilter);
    else trendShowPanel(inst, t, sevFilter, pos);
}

function trendOpenScan(inst, scan, sevKey) {
    closeTrendPanel();
    window.__pendingScanFilter = sevKey ? sevKey.charAt(0) + sevKey.slice(1).toLowerCase() : null;
    if (inst === trendState.enlarged && typeof closeChartModal === 'function') closeChartModal();
    openScanModalByScanId(scan.id);
}

// Buka Scan History dengan rentang hari grup tersebut (dan domainnya bila hanya satu)
function trendOpenHistory(inst, scans, doms) {
    closeTrendPanel();
    if (inst === trendState.enlarged && typeof closeChartModal === 'function') closeChartModal();
    const ts = scans.map(s => s.t.getTime());
    rpCommit('scanHistory', rpLocalDateStr(new Date(Math.min(...ts))), rpLocalDateStr(new Date(Math.max(...ts))), 'custom');
    const search = document.getElementById('vulnDomainSearch');
    if (search) {
        search.value = doms.length === 1 ? doms[0] : '';
        applyVulnFilters();
    }
    switchView('vulnerabilities');
}

function closeTrendPanel() {
    if (trendPanelEl) {
        trendPanelEl.remove();
        trendPanelEl = null;
    }
}

// Daftar menempel untuk grup: dikelompokkan per domain (domain dengan scan terbaru dulu), scan terbaru di atas
function trendShowPanel(inst, t, sevKey, pos) {
    closeTrendPanel();
    const byDom = new Map();
    t.scans.slice().sort((a, b) => b.t - a.t).forEach(s => {
        if (!byDom.has(s.domain)) byDom.set(s.domain, []);
        byDom.get(s.domain).push(s);
    });
    const list = [];
    const multiDay = new Set(t.scans.map(s => s.t.toDateString())).size > 1;
    const colorOf = (d) => (inst.kind === 'vuln' ? ((inst.series.find(s => s.key === d) || {}).color) : null) || getDomainColor(d);
    const sections = [...byDom.entries()].map(([dom, scans]) => `
        <div class="tc-panel-group"><i class="tc-tip-mark" style="background:${colorOf(dom)}"></i><span class="tc-panel-gname" title="${escapeHtml(dom)}">${escapeHtml(dom)}</span><span class="tc-panel-gn">${scans.length} scan</span></div>
        ${scans.map(s => {
            list.push(s);
            return `<div class="tc-panel-row">
                <span class="tc-panel-time">${escapeHtml(multiDay ? `${trendDayMonth(s.t)}, ${trendTime(s.t)}` : trendTime(s.t))}</span>
                <span class="tc-panel-dom">${escapeHtml(s.type || 'Scan')}</span>
                ${renderSevSummary(s.counts)}
                <button type="button" class="tc-panel-btn" data-tc-scan="${list.length - 1}" aria-label="Buka hasil scan ${escapeHtml(s.domain)} ${escapeHtml(trendTime(s.t))}">Buka</button>
            </div>`;
        }).join('')}`).join('');
    const doms = [...byDom.keys()];
    const title = `${t.scans.length} scan · ${trendSpanText(t.scans)}`;
    const panel = document.createElement('div');
    panel.className = 'tc-panel';
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-label', `Daftar ${title}`);
    panel.innerHTML = `
        <div class="tc-panel-head">
            <div>
                <div class="tc-panel-title">${escapeHtml(title)}</div>
                <div class="tc-panel-sub">${escapeHtml(doms.length > 1 ? `${doms.length} domain` : doms[0])}</div>
            </div>
            <button type="button" class="tc-panel-close" aria-label="Tutup daftar scan">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18"></path><path d="m6 6 12 12"></path></svg>
            </button>
        </div>
        <div class="tc-panel-list">${sections}</div>
        <div class="tc-panel-foot"><button type="button" class="tc-panel-more" data-tc-history>Lihat semua di Scan History</button></div>`;
    document.body.appendChild(panel);
    trendPanelEl = panel;

    const w = panel.offsetWidth || 440;
    const h = panel.offsetHeight || 300;
    const left = Math.max(12, Math.min(pos.x + 12, window.innerWidth - w - 12));
    const top = Math.max(12, Math.min(pos.y + 12, window.innerHeight - h - 12));
    panel.style.left = `${left}px`;
    panel.style.top = `${top}px`;

    panel.addEventListener('click', (e) => {
        e.stopPropagation();
        if (e.target.closest('.tc-panel-close')) {
            closeTrendPanel();
            inst.canvas.focus();
            return;
        }
        const btn = e.target.closest('[data-tc-scan]');
        if (btn) { trendOpenScan(inst, list[parseInt(btn.dataset.tcScan, 10)], sevKey); return; }
        if (e.target.closest('[data-tc-history]')) trendOpenHistory(inst, t.scans, doms);
    });
    panel.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            e.stopPropagation();
            closeTrendPanel();
            inst.canvas.focus();
        }
    });
    const first = panel.querySelector('.tc-panel-btn');
    if (first) first.focus({ preventScroll: true });
}

document.addEventListener('click', (e) => {
    if (trendPanelEl && !trendPanelEl.contains(e.target) && !(e.target && e.target.tagName === 'CANVAS')) closeTrendPanel();
});
window.addEventListener('resize', closeTrendPanel);

window.renderVulnTrendChart = function () {
    trendState.vuln = trendRender('vuln', document.getElementById('vulnBarChart'), document.getElementById('vulnTrendLegend'), { ddEl: document.getElementById('vulnDomainDropdown') });
    vulnChartInstance = trendState.vuln ? trendState.vuln.chart : null;
};

window.renderSevTrendChart = function () {
    trendState.sev = trendRender('sev', document.getElementById('sevTrendChart'), document.getElementById('sevTrendLegend'));
    sevChartInstance = trendState.sev ? trendState.sev.chart : null;
};

// Automated Pentests (Vulnerabilities View)
let vulnSortCol = 'date';
let vulnSortDesc = true;

// Urutan Scan History: hanya Waktu, Target Domain, dan Temuan yang bisa diurutkan.
// Waktu & Temuan: klik pertama turun (terbaru / paling parah). Domain: klik pertama A-Z.
function sortVulnHistory(col) {
    if (vulnSortCol === col) {
        vulnSortDesc = !vulnSortDesc;
    } else {
        vulnSortCol = col;
        vulnSortDesc = col !== 'domain';
    }
    applyVulnFilters();
}

function resetVulnSort() {
    vulnSortCol = 'date';
    vulnSortDesc = true;
    applyVulnFilters();
}

const SH_SORT_ICONS = {
    down: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14"></path><path d="m19 12-7 7-7-7"></path></svg>',
    up: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 7-7 7 7"></path><path d="M12 19V5"></path></svg>',
    idle: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m7 15 5 5 5-5"></path><path d="m7 9 5-5 5 5"></path></svg>'
};

function updateSortIcons() {
    document.querySelectorAll('#scanHistoryHeaders .sh-sort').forEach(btn => {
        const active = btn.dataset.sort === vulnSortCol;
        btn.classList.toggle('is-active', active);
        const icon = btn.querySelector('.sort-icon');
        if (icon) icon.innerHTML = active ? (vulnSortDesc ? SH_SORT_ICONS.down : SH_SORT_ICONS.up) : SH_SORT_ICONS.idle;
        const th = btn.closest('th');
        if (th) th.setAttribute('aria-sort', active ? (vulnSortDesc ? 'descending' : 'ascending') : 'none');
    });

    // Baris penjelas urutan: hanya tampil bila bukan urutan bawaan (Waktu terbaru)
    const summary = document.getElementById('scanHistorySortSummary');
    if (summary) {
        const isDefault = vulnSortCol === 'date' && vulnSortDesc;
        const text = {
            date: 'Waktu terlama dulu',
            domain: vulnSortDesc ? 'Target Domain Z-A' : 'Target Domain A-Z',
            severity: vulnSortDesc ? 'Temuan paling parah (Critical, lalu High, Medium, Low, Info)' : 'Temuan paling ringan dulu'
        }[vulnSortCol] || '';
        summary.hidden = isDefault;
        summary.innerHTML = isDefault ? '' : `${vulnSortDesc ? SH_SORT_ICONS.down : SH_SORT_ICONS.up}<span>Diurutkan: <strong>${escapeHtml(text)}</strong></span><span aria-hidden="true">·</span><button type="button" class="sh-link" onclick="resetVulnSort()">Kembali ke terbaru</button>`;
    }
}

let vulnLoadState = 'idle'; // idle | loading | ready | error

async function loadVulnerabilities(preservePage = false, { onlyIfChanged = false } = {}) {
    // Kerangka hanya saat pertama kali (refresh berikutnya tidak mengosongkan tabel)
    if (!allVulns.length && vulnLoadState !== 'ready') vulnLoadState = 'loading';
    try {
        const resp = await fetch(`${API_BASE}/api/scan-history?limit=1000`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const text = await resp.text();
        if (onlyIfChanged && vulnLoadState === 'ready' && text === lastScanHistoryText) return false;
        lastScanHistoryText = text;
        const data = JSON.parse(text);
        allVulns = normalizeInfoRisk(data.data || []);
        vulnLoadState = 'ready';
        applyVulnFilters(preservePage);
        renderLowerGrid();
        return true;
    } catch (err) {
        console.error('Error loading scans:', err);
        if (vulnLoadState !== 'ready') {
            vulnLoadState = 'error';
            renderVulnerabilitiesList();
        } else if (typeof showToast === 'function') {
            showToast('Gagal memperbarui riwayat scan. Data yang tampil belum berubah.', 'error');
        }
        return false;
    }
}

// Dropdown tipe scan Scan History: gaya fdd yang sama dengan Domain Inventory.
// Jumlah per pilihan memakai deteksi tipe yang sama dengan filternya.
const shScanTypeOf = scan => String(scan.vulnerabilities?.[0]?.check_type || '').toLowerCase();
const SH_TYPE_FDD = {
    select: 'vulnTypeFilter', name: 'Tipe scan', showChoice: true,
    options: [['ALL', 'Semua tipe scan'], ['Web Scanner', 'Website Scan'], ['Network Scanner', 'Network Scan']],
    count: v => v === 'ALL' ? (allVulns || []).length : (allVulns || []).filter(s => shScanTypeOf(s) === v.toLowerCase()).length,
    onChange: () => applyVulnFilters()
};

// Pencarian Scan History: cocok dengan nama domain atau IP (sama seperti halaman lain)
function shMatchesSearch(scan, query) {
    const q = String(query || '').trim().toLowerCase();
    if (!q) return true;
    const name = (scan.domains?.domain_name || scan.domain_name || scan.target || '').toLowerCase();
    const ip = (scan.domains?.ip_address || scan.ip_address || '').toLowerCase();
    return name.includes(q) || (!!ip && ip.includes(q));
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

        // Filter khusus hasil scan berisiko HIGH & CRITICAL (aktif saat tombol Cek Detail >1 temuan diklik)
        if (window.overnightRiskFilter) {
            const risk = (scan.risk_level || '').toUpperCase();
            if (!['HIGH', 'CRITICAL'].includes(risk)) return false;
        }

        // Filter berdasarkan severity chip yang dipilih
        if (typeof selectedSeverityFilter !== 'undefined' && selectedSeverityFilter !== 'ALL') {
            const risk = (scan.risk_level || 'SAFE').toUpperCase();
            if (risk !== selectedSeverityFilter) return false;
        }

        // Filter berdasarkan pencarian nama domain atau IP
        if (!shMatchesSearch(scan, domainSearchInput)) return false;

        // Filter berdasarkan tipe scan
        if (typeFilter && typeFilter !== 'ALL' && shScanTypeOf(scan) !== typeFilter.toLowerCase()) return false;

        return true;
    });

    renderSeverityChips();
    fddRender('shTypeDd', SH_TYPE_FDD, []);
    fltResetLabel(document.getElementById('vulnResetFilterBtn'), shActiveFilterCount());

    filteredVulns.sort((a, b) => {
        // (Sisa kode sorting di bawahnya biarkan tetap sama persis seperti sebelumnya)
        let valA, valB;
        if (vulnSortCol === 'date') {
            valA = new Date(a.scan_date).getTime() || 0;
            valB = new Date(b.scan_date).getTime() || 0;
        } else if (vulnSortCol === 'domain') {
            valA = (a.domains?.domain_name || a.domain_name || a.target || '').toLowerCase();
            valB = (b.domains?.domain_name || b.domain_name || b.target || '').toLowerCase();
        } else if (vulnSortCol === 'type') {
            valA = (a.vulnerabilities && a.vulnerabilities.length > 0 && a.vulnerabilities[0].check_type || '').toLowerCase();
            valB = (b.vulnerabilities && b.vulnerabilities.length > 0 && b.vulnerabilities[0].check_type || '').toLowerCase();
        } else if (vulnSortCol === 'vulns') {
            valA = a.vulnerabilities ? a.vulnerabilities.length : 0;
            valB = b.vulnerabilities ? b.vulnerabilities.length : 0;
        } else if (vulnSortCol === 'severity') {
            // Bandingkan jumlah per severity berurutan: Critical, lalu High, Medium, Low, Info
            const ca = countSeverities(a.vulnerabilities), cb = countSeverities(b.vulnerabilities);
            for (const k of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
                if (ca[k] !== cb[k]) return vulnSortDesc ? cb[k] - ca[k] : ca[k] - cb[k];
            }
            return (new Date(b.scan_date).getTime() || 0) - (new Date(a.scan_date).getTime() || 0);
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

// =========================================================
// DATE RANGE PICKER (versi sederhana)
// 1 pemilih untuk kedua grafik Overview ('overview'), 1 untuk Scan History ('scanHistory'),
// dan 1 per halaman Scans ('webScans', 'networkScans', dipakai bersama tab Manual dan Automated).
// Menu: pilihan cepat (1 klik = langsung diterapkan) + "Pilih tanggal sendiri".
// Kalender: 1 bulan, kotak Mulai/Akhir, tukar otomatis, Kembalikan, Terapkan (N hari).
// =========================================================
const RP_MONTHS = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'];
const RP_MONTHS_SHORT = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];
const RP_WEEKDAYS = ['Mg', 'Sn', 'Sl', 'Rb', 'Km', 'Jm', 'Sb'];
const RP_PICKERS = {
    overview: {
        dropdown: 'overviewDateDropdown',
        label: 'overviewDateLabel',
        inputs: [['vulnTrendStartDate', 'vulnTrendEndDate'], ['sevTrendStartDate', 'sevTrendEndDate']],
        def: '1d'
    },
    scanHistory: {
        dropdown: 'scanHistoryDateDropdown',
        label: 'scanHistoryDateLabel',
        inputs: [['vulnStartDate', 'vulnEndDate']],
        def: 'all'
    },
    webScans: {
        dropdown: 'webScansDateDropdown',
        label: 'webScansDateLabel',
        inputs: [['webStartDate', 'webEndDate']],
        def: 'all'
    },
    networkScans: {
        dropdown: 'networkScansDateDropdown',
        label: 'networkScansDateLabel',
        inputs: [['networkStartDate', 'networkEndDate']],
        def: 'all'
    }
};
const RP_ICONS = {
    check: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>',
    left: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>',
    right: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>',
    cal: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>',
    undo: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 14 4 9l5-5"></path><path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H11"></path></svg>',
    info: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>'
};

const rpStates = {};

// Grafik lama memakai prefix vulnTrend/sevTrend: keduanya sekarang satu pemilih 'overview'
function rpKey(prefix) {
    return (prefix === 'vulnTrend' || prefix === 'sevTrend') ? 'overview' : (RP_PICKERS[prefix] ? prefix : 'scanHistory');
}

function rpState(prefix) {
    const key = rpKey(prefix);
    if (!rpStates[key]) {
        const def = RP_PICKERS[key].def;
        rpStates[key] = {
            applied: { start: null, end: null, preset: def },
            mode: 'menu', start: null, end: null, edit: null, prev: null, hover: null, msg: '',
            year: new Date().getFullYear(), month: new Date().getMonth(), focusDate: null
        };
    }
    return rpStates[key];
}

function rpLocalDateStr(d) {
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function rpParse(dateStr) {
    const [y, m, d] = dateStr.split('-').map(Number);
    return new Date(y, m - 1, d);
}

function rpToday() {
    return rpLocalDateStr(new Date());
}

function rpShift(dateStr, days) {
    const d = rpParse(dateStr);
    d.setDate(d.getDate() + days);
    return rpLocalDateStr(d);
}

function rpDayText(dateStr) {
    const d = rpParse(dateStr);
    return `${d.getDate()} ${RP_MONTHS_SHORT[d.getMonth()]} ${d.getFullYear()}`;
}

function rpRangeText(start, end) {
    if (!start) return '';
    const a = rpParse(start);
    const b = rpParse(end || start);
    if (start === (end || start)) return rpDayText(start);
    if (a.getFullYear() === b.getFullYear()) {
        if (a.getMonth() === b.getMonth()) return `${a.getDate()} - ${rpDayText(end)}`;
        return `${a.getDate()} ${RP_MONTHS_SHORT[a.getMonth()]} - ${rpDayText(end)}`;
    }
    return `${rpDayText(start)} - ${rpDayText(end)}`;
}

// Teks pendek tanpa tahun untuk tautan "Kembalikan 3 - 14 Nov"
function rpRangeShort(start, end) {
    const a = rpParse(start), b = rpParse(end);
    if (start === end) return `${a.getDate()} ${RP_MONTHS_SHORT[a.getMonth()]}`;
    if (a.getMonth() === b.getMonth() && a.getFullYear() === b.getFullYear()) return `${a.getDate()} - ${b.getDate()} ${RP_MONTHS_SHORT[b.getMonth()]}`;
    return `${a.getDate()} ${RP_MONTHS_SHORT[a.getMonth()]} - ${b.getDate()} ${RP_MONTHS_SHORT[b.getMonth()]}`;
}

function rpDayCount(start, end) {
    return Math.round((rpParse(end) - rpParse(start)) / 86400000) + 1;
}

function rpDefaultPreset(prefix) {
    return RP_PICKERS[rpKey(prefix)].def;
}

function rpPresets(prefix) {
    const base = [['1d', '24 jam terakhir'], ['7d', '7 hari terakhir'], ['30d', '30 hari terakhir'], ['90d', '90 hari terakhir'], ['thisMonth', 'Bulan ini'], ['lastMonth', 'Bulan lalu']];
    // Semua pemilih daftar (Scan History, Scans) punya "Semua tanggal"; Overview (grafik) tidak
    return rpKey(prefix) !== 'overview' ? [['all', 'Semua tanggal'], ...base] : base;
}

function rpPresetLabel(prefix, key) {
    const found = rpPresets(prefix).find(p => p[0] === key);
    if (found) return found[1];
    const m = /^(\d+)d$/.exec(key || '');
    return m ? `${m[1]} hari terakhir` : '';
}

// Hasil {start, end}; null berarti "tanpa filter tanggal" (default backend grafik: 24 jam terakhir)
function rpPresetRange(prefix, key) {
    const now = new Date();
    const today = rpLocalDateStr(now);
    const history = rpKey(prefix) !== 'overview';
    if (key === 'all') return { start: null, end: null };
    if (key === '1d') return history ? { start: today, end: today } : { start: null, end: null };
    if (key === 'thisMonth') return { start: rpLocalDateStr(new Date(now.getFullYear(), now.getMonth(), 1)), end: today };
    if (key === 'lastMonth') {
        return {
            start: rpLocalDateStr(new Date(now.getFullYear(), now.getMonth() - 1, 1)),
            end: rpLocalDateStr(new Date(now.getFullYear(), now.getMonth(), 0))
        };
    }
    const m = /^(\d+)d$/.exec(key || '');
    const days = m ? parseInt(m[1], 10) : 1;
    const start = new Date(now.getFullYear(), now.getMonth(), now.getDate() - days + 1);
    return { start: rpLocalDateStr(start), end: today };
}

function rpUpdateTrigger(prefix) {
    const key = rpKey(prefix);
    const cfg = RP_PICKERS[key];
    const ap = rpState(key).applied;
    const label = document.getElementById(cfg.label);
    if (label) label.textContent = ap.preset === 'custom' ? rpRangeText(ap.start, ap.end) : rpPresetLabel(key, ap.preset);
    const dd = document.getElementById(cfg.dropdown);
    if (dd) dd.classList.toggle('rp-has-custom', ap.preset !== cfg.def);
}

// Simpan rentang ke input tersembunyi + label, lalu muat ulang data terkait
function rpCommit(prefix, start, end, preset) {
    const key = rpKey(prefix);
    const cfg = RP_PICKERS[key];
    const state = rpState(key);
    state.applied = { start: start || null, end: end || null, preset };
    cfg.inputs.forEach(([s, e]) => {
        const si = document.getElementById(s);
        const ei = document.getElementById(e);
        if (si) si.value = start || '';
        if (ei) ei.value = end || '';
    });
    rpUpdateTrigger(key);

    if (key === 'scanHistory') {
        applyVulnFilters();
    } else if (key === 'webScans') {
        applyWebFilters();
    } else if (key === 'networkScans') {
        applyNetworkFilters();
    } else {
        loadVulnTrendData();
        loadSevTrendData();
    }
}

// Untuk kode lain yang mengisi input tanggal langsung (mis. klik domain/scan): samakan label + state
function rpSyncFromInputs(prefix) {
    const key = rpKey(prefix);
    const [s, e] = RP_PICKERS[key].inputs[0];
    const start = document.getElementById(s)?.value || null;
    const end = document.getElementById(e)?.value || null;
    const state = rpState(key);
    if (!start && !end) state.applied = { start: null, end: null, preset: RP_PICKERS[key].def };
    else state.applied = { start: start || end, end: end || start, preset: 'custom' };
    rpUpdateTrigger(key);
}

function rpReset(prefix, event) {
    if (event) { event.stopPropagation(); event.preventDefault(); }
    const key = rpKey(prefix);
    const def = RP_PICKERS[key].def;
    const r = rpPresetRange(key, def);
    closeRangePicker(key);
    rpCommit(key, r.start, r.end, def);
}

function rpPanel(prefix) {
    const dd = document.getElementById(RP_PICKERS[rpKey(prefix)].dropdown);
    return dd ? dd.querySelector('.rp-panel') : null;
}

function openRangePicker(prefix) {
    const key = rpKey(prefix);
    const cfg = RP_PICKERS[key];
    const dd = document.getElementById(cfg.dropdown);
    const panel = rpPanel(key);
    if (!dd || !panel) return;
    if (dd.classList.contains('open')) { closeRangePicker(key); return; }
    if (!panel.dataset.bound) rpBind(panel, key);

    // Rentang kustom yang aktif langsung dibuka di kalender, siap diubah
    const state = rpState(key);
    const ap = state.applied;
    if (ap.preset === 'custom' && ap.start) rpEnterCalendar(key, ap.start, ap.end);
    else state.mode = 'menu';

    toggleDropdown(cfg.dropdown);
    dd.querySelector('.rp-trigger')?.setAttribute('aria-expanded', 'true');
    rpRender(key);
    rpPositionPanel(key);
    const first = panel.querySelector(state.mode === 'menu' ? '.rp-opt.active, .rp-opt' : '.rp-day[tabindex="0"]');
    first?.focus({ preventScroll: true });
}

function closeRangePicker(prefix) {
    const key = rpKey(prefix);
    const dd = document.getElementById(RP_PICKERS[key].dropdown);
    if (!dd) return;
    closeDropdown(RP_PICKERS[key].dropdown);
    dd.querySelector('.rp-trigger')?.setAttribute('aria-expanded', 'false');
    rpState(key).hover = null;
}

// Masuk ke kalender. Draft dimulai dari rentang yang diberikan (atau kosong)
function rpEnterCalendar(prefix, start, end) {
    const state = rpState(prefix);
    state.mode = 'cal';
    state.start = start || null;
    state.end = start ? (end || start) : null;
    state.edit = null;
    state.prev = null;
    state.hover = null;
    state.msg = '';
    const anchor = rpParse(state.end || state.start || rpToday());
    state.year = anchor.getFullYear();
    state.month = anchor.getMonth();
    state.focusDate = state.end || state.start || rpToday();
}

function rpSelectDate(prefix, ds) {
    if (ds > rpToday()) return;
    const state = rpState(prefix);
    state.hover = null;
    state.focusDate = ds;

    if (state.edit && state.start && state.end) {
        // Ubah satu sisi saja (kotak Mulai/Akhir aktif)
        const which = state.edit;
        if (which === 'start') state.start = ds; else state.end = ds;
        let swapped = false;
        if (state.start > state.end) { [state.start, state.end] = [state.end, state.start]; swapped = true; }
        state.msg = swapped
            ? `Tanggal ditukar otomatis: ${rpDayText(state.start)} menjadi tanggal mulai.`
            : (which === 'start'
                ? `Tanggal mulai diganti ke ${rpDayText(ds)}. Klik kotak Akhir untuk mengubah tanggal akhir.`
                : `Tanggal akhir diganti ke ${rpDayText(ds)}. Klik kotak Mulai untuk mengubah tanggal mulai.`);
    } else if (state.start && !state.end) {
        // Klik kedua = tanggal akhir; lebih awal dari mulai = ditukar
        if (ds < state.start) {
            state.end = state.start;
            state.start = ds;
            state.msg = `Tanggal ditukar otomatis: ${rpDayText(ds)} menjadi tanggal mulai.`;
        } else {
            state.end = ds;
            state.msg = '';
        }
        state.prev = null;
    } else {
        // Rentang sudah lengkap (atau kosong) = mulai rentang baru, rentang lama bisa dikembalikan
        state.prev = (state.start && state.end) ? { start: state.start, end: state.end } : null;
        state.start = ds;
        state.end = null;
        state.edit = null;
        state.msg = '';
    }
    rpRender(prefix);
}

function rpHint(state) {
    if (state.msg) return state.msg;
    if (!state.start) return 'Klik tanggal mulai.';
    if (!state.end) return `${state.prev ? 'Mulai baru' : 'Mulai'} ${rpDayText(state.start)}. Klik tanggal akhir.`;
    if (state.edit === 'start') return 'Klik tanggal baru untuk tanggal mulai.';
    if (state.edit === 'end') return 'Klik tanggal baru untuk tanggal akhir.';
    return 'Klik tanggal untuk mulai rentang baru, atau klik kotak Mulai/Akhir untuk mengubah satu sisi.';
}

function rpMenuHtml(prefix) {
    const state = rpState(prefix);
    const ap = state.applied;
    const items = rpPresets(prefix).map(([key, label]) => {
        const active = ap.preset === key;
        return `<button type="button" class="rp-opt${active ? ' active' : ''}" role="menuitemradio" aria-checked="${active}" data-rp-preset="${key}"><span class="rp-opt-text">${label}</span>${active ? `<span class="rp-opt-check">${RP_ICONS.check}</span>` : ''}</button>`;
    }).join('');
    const customActive = ap.preset === 'custom';
    return `
        <div class="rp-menu" role="menu" aria-label="Pilihan rentang tanggal">
            ${items}
            <div class="rp-sep" role="separator"></div>
            <button type="button" class="rp-opt rp-opt-custom${customActive ? ' active' : ''}" role="menuitem" data-rp-custom>
                <span class="rp-opt-icon">${RP_ICONS.cal}</span>
                <span class="rp-opt-text">${customActive ? rpRangeText(ap.start, ap.end) : 'Pilih tanggal sendiri'}</span>
                <span class="rp-opt-chev">${RP_ICONS.right}</span>
            </button>
        </div>`;
}

function rpCalendarHtml(prefix) {
    const state = rpState(prefix);
    const today = rpToday();
    const y = state.year, m = state.month;
    const nowKey = new Date().getFullYear() * 12 + new Date().getMonth();
    const atLastMonth = (y * 12 + m) >= nowKey;

    let lo = null, hi = null;
    if (state.start && state.end) { lo = state.start; hi = state.end; }
    else if (state.start && state.hover) { lo = state.start < state.hover ? state.start : state.hover; hi = state.start < state.hover ? state.hover : state.start; }
    else if (state.start) { lo = hi = state.start; }
    const ghost = (!state.end && state.prev) ? state.prev : null;

    // Fokus keyboard: satu tombol tanggal dengan tabindex=0 (roving tabindex)
    const monthPrefix = `${y}-${String(m + 1).padStart(2, '0')}-`;
    let focusDate = state.focusDate && state.focusDate.startsWith(monthPrefix) ? state.focusDate : null;
    if (!focusDate) focusDate = (lo && lo.startsWith(monthPrefix)) ? lo : (today.startsWith(monthPrefix) ? today : `${monthPrefix}01`);

    const first = new Date(y, m, 1).getDay();
    const total = new Date(y, m + 1, 0).getDate();
    let cells = '';
    for (let i = 0; i < first; i++) cells += '<span class="rp-cell" aria-hidden="true"></span>';
    for (let d = 1; d <= total; d++) {
        const ds = `${monthPrefix}${String(d).padStart(2, '0')}`;
        const col = (first + d - 1) % 7;
        const future = ds > today;
        const isEdge = (lo && ds === lo) || (hi && ds === hi);
        const inBand = lo && hi && lo !== hi && ds >= lo && ds <= hi;
        const isGhost = ghost && ds >= ghost.start && ds <= ghost.end && !isEdge && !inBand;
        const cls = ['rp-cell'];
        if (inBand) cls.push('rp-band');
        if (inBand && (ds === lo || col === 0 || d === 1)) cls.push('rp-band-start');
        if (inBand && (ds === hi || col === 6 || d === total)) cls.push('rp-band-end');
        const dayCls = ['rp-day'];
        if (isEdge) dayCls.push('rp-edge');
        else if (inBand) dayCls.push('rp-in');
        if (isGhost) dayCls.push('rp-ghost');
        if (ds === today) dayCls.push('rp-today');
        cells += `<span class="${cls.join(' ')}"><button type="button" class="${dayCls.join(' ')}" data-rp-date="${ds}" tabindex="${ds === focusDate ? 0 : -1}" ${future ? 'disabled' : ''} aria-label="${d} ${RP_MONTHS[m]} ${y}"${isEdge ? ' aria-pressed="true"' : ''}>${d}</button></span>`;
    }

    const edgeBox = (which, label, val) => {
        const active = state.edit === which || (which === 'end' && state.start && !state.end && !state.edit);
        const canEdit = !!(state.start && state.end);
        return `<button type="button" class="rp-edge-box${active ? ' active' : ''}" data-rp-edge="${which}" ${canEdit ? '' : 'disabled'} aria-pressed="${state.edit === which}">
            <span class="rp-edge-label">${label}</span>
            <span class="rp-edge-val${val ? '' : ' empty'}">${val ? rpDayText(val) : 'Pilih tanggal'}</span>
        </button>`;
    };
    const ready = !!(state.start && state.end);
    const days = ready ? rpDayCount(state.start, state.end) : 0;

    return `
        <div class="rp-cal">
            <div class="rp-cal-top">
                <button type="button" class="rp-link" data-rp-back>${RP_ICONS.left}<span>Pilihan cepat</span></button>
                ${(state.prev && !state.end) ? `<button type="button" class="rp-link rp-link-muted" data-rp-undo>${RP_ICONS.undo}<span>Kembalikan ${rpRangeShort(state.prev.start, state.prev.end)}</span></button>` : ''}
            </div>
            <div class="rp-month-head">
                <button type="button" class="rp-nav" data-rp-nav="-1" aria-label="Bulan sebelumnya">${RP_ICONS.left}</button>
                <span class="rp-month-title" aria-live="polite">${RP_MONTHS[m]} ${y}</span>
                <button type="button" class="rp-nav" data-rp-nav="1" aria-label="Bulan berikutnya" ${atLastMonth ? 'disabled' : ''}>${RP_ICONS.right}</button>
            </div>
            <div class="rp-grid" role="group" aria-label="${RP_MONTHS[m]} ${y}">
                ${RP_WEEKDAYS.map(d => `<span class="rp-wd" aria-hidden="true">${d}</span>`).join('')}
                ${cells}
            </div>
            <div class="rp-edges">
                ${edgeBox('start', 'Mulai', state.start)}
                ${edgeBox('end', 'Akhir', state.end)}
            </div>
            <div class="rp-hint" aria-live="polite">${RP_ICONS.info}<span>${rpHint(state)}</span></div>
            <button type="button" class="rp-apply" data-rp-apply ${ready ? '' : 'disabled'}>${ready ? `Terapkan (${days} hari)` : 'Terapkan'}</button>
        </div>`;
}

function rpRender(prefix) {
    const key = rpKey(prefix);
    const panel = rpPanel(key);
    if (!panel) return;
    const state = rpState(key);
    const focusedDate = panel.contains(document.activeElement) ? document.activeElement.dataset.rpDate : null;
    panel.classList.toggle('rp-mode-cal', state.mode === 'cal');
    panel.innerHTML = state.mode === 'cal' ? rpCalendarHtml(key) : rpMenuHtml(key);
    if (focusedDate) panel.querySelector(`[data-rp-date="${state.focusDate || focusedDate}"]`)?.focus({ preventScroll: true });
    rpPositionPanel(key);
}

function rpApplyPreset(prefix, presetKey) {
    const r = rpPresetRange(prefix, presetKey);
    closeRangePicker(prefix);
    rpCommit(prefix, r.start, r.end, presetKey);
    document.getElementById(RP_PICKERS[rpKey(prefix)].dropdown)?.querySelector('.rp-trigger')?.focus();
}

function rpApplyDraft(prefix) {
    const state = rpState(prefix);
    if (!state.start || !state.end) return;
    closeRangePicker(prefix);
    rpCommit(prefix, state.start, state.end, 'custom');
    document.getElementById(RP_PICKERS[rpKey(prefix)].dropdown)?.querySelector('.rp-trigger')?.focus();
}

function rpMoveFocus(prefix, ds) {
    const today = rpToday();
    if (ds > today) ds = today;
    const state = rpState(prefix);
    state.focusDate = ds;
    const d = rpParse(ds);
    if (d.getFullYear() !== state.year || d.getMonth() !== state.month) {
        state.year = d.getFullYear();
        state.month = d.getMonth();
    }
    rpRender(prefix);
    rpPanel(prefix)?.querySelector(`[data-rp-date="${ds}"]`)?.focus({ preventScroll: true });
}

function rpBind(panel, key) {
    panel.dataset.bound = '1';
    panel.addEventListener('click', (e) => {
        // Panel di-render ulang saat klik; hentikan agar handler "klik di luar" tidak salah menutup
        e.stopPropagation();
        const state = rpState(key);
        const preset = e.target.closest('[data-rp-preset]');
        if (preset) { rpApplyPreset(key, preset.dataset.rpPreset); return; }
        if (e.target.closest('[data-rp-custom]')) {
            const ap = state.applied;
            const r = ap.preset === 'custom' ? ap : rpPresetRange(key, ap.preset);
            rpEnterCalendar(key, r.start, r.end);
            if (ap.preset !== 'custom') { state.prev = null; }
            rpRender(key);
            panel.querySelector('.rp-day[tabindex="0"]')?.focus({ preventScroll: true });
            return;
        }
        if (e.target.closest('[data-rp-back]')) {
            state.mode = 'menu';
            rpRender(key);
            panel.querySelector('.rp-opt.active, .rp-opt')?.focus({ preventScroll: true });
            return;
        }
        if (e.target.closest('[data-rp-undo]')) {
            if (state.prev) { state.start = state.prev.start; state.end = state.prev.end; state.prev = null; state.msg = ''; }
            rpRender(key);
            return;
        }
        const day = e.target.closest('[data-rp-date]');
        if (day && !day.disabled) { rpSelectDate(key, day.dataset.rpDate); return; }
        const nav = e.target.closest('[data-rp-nav]');
        if (nav && !nav.disabled) {
            const d = new Date(state.year, state.month + parseInt(nav.dataset.rpNav, 10), 1);
            state.year = d.getFullYear();
            state.month = d.getMonth();
            rpRender(key);
            return;
        }
        const edge = e.target.closest('[data-rp-edge]');
        if (edge && !edge.disabled) {
            state.edit = state.edit === edge.dataset.rpEdge ? null : edge.dataset.rpEdge;
            state.msg = '';
            rpRender(key);
            panel.querySelector(`[data-rp-edge="${edge.dataset.rpEdge}"]`)?.focus({ preventScroll: true });
            return;
        }
        if (e.target.closest('[data-rp-apply]')) rpApplyDraft(key);
    });
    panel.addEventListener('mouseover', (e) => {
        const state = rpState(key);
        const day = e.target.closest('[data-rp-date]');
        if (!day || day.disabled || !state.start || state.end || state.hover === day.dataset.rpDate) return;
        state.hover = day.dataset.rpDate;
        rpRender(key);
    });
    panel.addEventListener('mouseleave', () => {
        const state = rpState(key);
        if (state.hover) { state.hover = null; rpRender(key); }
    });
    panel.addEventListener('keydown', (e) => {
        const day = e.target.closest('[data-rp-date]');
        if (day) {
            const step = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7 }[e.key];
            if (step) { e.preventDefault(); rpMoveFocus(key, rpShift(day.dataset.rpDate, step)); return; }
            if (e.key === 'PageUp' || e.key === 'PageDown') {
                e.preventDefault();
                const d = rpParse(day.dataset.rpDate);
                const t = new Date(d.getFullYear(), d.getMonth() + (e.key === 'PageUp' ? -1 : 1), 1);
                const last = new Date(t.getFullYear(), t.getMonth() + 1, 0).getDate();
                rpMoveFocus(key, rpLocalDateStr(new Date(t.getFullYear(), t.getMonth(), Math.min(d.getDate(), last))));
            }
            return;
        }
        const opt = e.target.closest('.rp-opt');
        if (opt && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
            e.preventDefault();
            const opts = [...panel.querySelectorAll('.rp-opt')];
            const i = opts.indexOf(opt) + (e.key === 'ArrowDown' ? 1 : -1);
            opts[(i + opts.length) % opts.length].focus();
        }
    });
}

// Panel rata kanan dengan tombol, lalu dijepit agar tetap di dalam area konten
function rpPositionPanel(prefix) {
    const panel = rpPanel(prefix);
    const dd = panel && panel.closest('.multi-select-dropdown');
    if (!panel || !dd || !dd.classList.contains('open')) return;
    const area = (document.querySelector('.page-canvas') || document.body).getBoundingClientRect();
    const margin = 16;
    const areaLeft = Math.max(area.left, 0) + margin;
    const areaRight = Math.min(area.right || window.innerWidth, window.innerWidth) - margin;
    panel.style.right = 'auto';
    panel.style.left = '0px';
    const w = panel.offsetWidth;
    const btn = (dd.querySelector('.rp-trigger') || dd).getBoundingClientRect();
    let left = btn.right - w;
    left = Math.min(Math.max(left, areaLeft), Math.max(areaLeft, areaRight - w));
    panel.style.left = `${Math.round(left - dd.getBoundingClientRect().left)}px`;
}

// Esc / klik di luar = batal (rentang lama tetap dipakai, draft dibuang)
document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    Object.keys(RP_PICKERS).forEach(key => {
        const dd = document.getElementById(RP_PICKERS[key].dropdown);
        if (dd && dd.classList.contains('open')) {
            closeRangePicker(key);
            dd.querySelector('.rp-trigger')?.focus();
        }
    });
});
window.addEventListener('resize', () => {
    Object.keys(RP_PICKERS).forEach(key => rpPositionPanel(key));
});

// --- Pembungkus untuk pemanggil lama ---
function setQuickScanHistoryMonth() {
    rpApplyPreset('scanHistory', 'thisMonth');
}

function setQuickScanHistoryDate(days, event) {
    if (event) event.stopPropagation();
    const key = days === 0 ? 'all' : (days === 1 ? '1d' : `${days}d`);
    const range = rpPresetRange('scanHistory', key);
    rpCommit('scanHistory', range.start, range.end, key);
}

function onCustomScanHistoryDateChange() {
    rpSyncFromInputs('scanHistory');
    applyVulnFilters();
}

function formatDateShort(dateStr) {
    if (!dateStr) return '';
    const parts = dateStr.split('-');
    if (parts.length === 3) {
        return `${parts[2]}/${parts[1]}`;
    }
    return dateStr;
}

let selectedSeverityFilter = 'ALL';

function filterBySeverity(severity) {
    selectedSeverityFilter = severity;
    applyVulnFilters();
}

// Scan yang hanya berisi temuan Info tercatat LOW di data lama: tampilkan sebagai INFO
function normalizeInfoRisk(scans) {
    (scans || []).forEach(scan => {
        if (String(scan.risk_level || '').toUpperCase() !== 'LOW') return;
        const sevs = (scan.vulnerabilities || []).map(v => String(v.severity || v.risk || '').toUpperCase());
        if (sevs.length && !sevs.some(x => ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(x))) scan.risk_level = 'INFO';
    });
    return scans;
}

function renderSeverityChips() {
    const container = document.getElementById('vulnSeverityChipsContainer');
    if (!container) return;

    if (!allVulns || allVulns.length === 0) {
        container.innerHTML = '';
        return;
    }

    const counts = { ALL: allVulns.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, SAFE: 0 };
    allVulns.forEach(scan => {
        const risk = (scan.risk_level || 'SAFE').toUpperCase();
        if (counts[risk] !== undefined) counts[risk]++;
        else counts.SAFE++;
    });

    // Warna mengikuti Pentest-Tools. Safe (tanpa temuan) netral abu-abu: hijau khusus untuk Info.
    const chips = [
        { id: 'ALL', label: 'All Severities' },
        { id: 'CRITICAL', label: 'Critical', color: 'var(--sev-critical)' },
        { id: 'HIGH', label: 'High', color: 'var(--sev-high)' },
        { id: 'MEDIUM', label: 'Medium', color: 'var(--sev-medium)' },
        { id: 'LOW', label: 'Low', color: 'var(--sev-low)' },
        { id: 'INFO', label: 'Info', color: 'var(--sev-info)' },
        { id: 'SAFE', label: 'Safe', safe: true }
    ];
    const check = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="m9 12 2 2 4-4"></path></svg>';

    container.innerHTML = `
        <span class="sh-chips-label" title="Risk level scan: severity temuan tertinggi di scan tersebut">Risk Level:</span>
        ${chips.map(c => {
            const active = selectedSeverityFilter === c.id;
            const lead = c.safe ? check : (c.color ? `<span class="sh-chip-dot" style="background:${c.color}"></span>` : '');
            return `<button type="button" class="sh-chip${active ? ' is-active' : ''}${c.safe ? ' is-safe' : ''}" style="${c.color ? `--chip-c:${c.color}` : ''}" aria-pressed="${active}" onclick="filterBySeverity('${c.id}')">${lead}<span>${c.label}</span><span class="sh-chip-count">${counts[c.id]}</span></button>`;
        }).join('')}
    `;
}

function resetVulnFilters() {
    window.overnightRiskFilter = false;
    selectedSeverityFilter = 'ALL';
    const startInput = document.getElementById('vulnStartDate');
    const endInput = document.getElementById('vulnEndDate');
    const domainSearchInput = document.getElementById('vulnDomainSearch');
    const typeFilter = document.getElementById('vulnTypeFilter');

    if (startInput) startInput.value = '';
    if (endInput) endInput.value = '';
    if (domainSearchInput) domainSearchInput.value = '';
    if (typeFilter) typeFilter.value = 'ALL';
    rpSyncFromInputs('scanHistory');

    applyVulnFilters();
}


function renderSingleScansTable() {
    const container = document.getElementById('singleScansTableBody');
    if (!container) return;

    if (!allVulns || allVulns.length === 0) {
        container.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--color-muted);">Tidak ada riwayat pemindaian satuan ditemukan.</td></tr>`;
        return;
    }

    const singleScans = allVulns.filter(scan => !scan.is_scheduled);
    const displayScans = singleScans.length > 0 ? singleScans : allVulns;

    container.innerHTML = displayScans.map(scan => {
        const actualIndex = allVulns.indexOf(scan);
        const domainName = scan.domains?.domain_name || scan.domain_name || scan.target || 'Unknown Target';
        const riskLevel = scan.risk_level || 'SAFE';
        const sevClass = getSeverityClass(riskLevel);
        const date = formatDate(scan.scan_date);
        const score = scan.risk_score ? scan.risk_score.toFixed(1) : '0.0';

        let scanType = "Web Scanner";
        if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
            scanType = scan.vulnerabilities[0].check_type || "Web Scanner";
        }

        return `
            <tr onclick="openScanModalIndex(${actualIndex})" style="cursor: pointer;">
                <td><strong style="color: var(--color-ink);">${escapeHtml(domainName)}</strong></td>
                <td><span style="color: var(--color-muted); font-size: 13px;">${escapeHtml(scanType)} (Single)</span></td>
                <td><span class="badge badge-${sevClass}">${riskLevel.toUpperCase()}</span></td>
                <td><span style="font-weight: 600;">${score} / 10.0</span></td>
                <td style="color: var(--color-muted); font-size: 13px;">${date}</td>
                <td>
                    <button class="btn btn-outline btn-sm" style="font-size: 11px; padding: 3px 8px;" onclick="event.stopPropagation(); openScanModalIndex(${actualIndex});">Detail Report</button>
                </td>
            </tr>
        `;
    }).join('');
}

function renderScheduledScansTable() {
    const container = document.getElementById('scheduledScansTableBody');
    if (!container) return;

    if (!allVulns || allVulns.length === 0) {
        container.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--color-muted);">Tidak ada riwayat pemindaian terjadwal ditemukan.</td></tr>`;
        return;
    }

    const scheduledScans = allVulns.filter(scan => scan.is_scheduled === true || scan.is_scheduled === 'true' || (scan.raw_json && scan.raw_json.pt_scan_id && scan.raw_json.is_scheduled));
    const displayScans = scheduledScans.length > 0 ? scheduledScans : allVulns;

    container.innerHTML = displayScans.map(scan => {
        const actualIndex = allVulns.indexOf(scan);
        const domainName = scan.domains?.domain_name || scan.domain_name || scan.target || 'Unknown Target';
        const riskLevel = scan.risk_level || 'SAFE';
        const sevClass = getSeverityClass(riskLevel);
        const date = formatDate(scan.scan_date);
        const score = scan.risk_score ? scan.risk_score.toFixed(1) : '0.0';

        let scanType = "Scheduled Auto-Scan";
        if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
            scanType = (scan.vulnerabilities[0].check_type || "Web Scanner") + " (Auto)";
        }

        return `
            <tr onclick="openScanModalIndex(${actualIndex})" style="cursor: pointer;">
                <td><strong style="color: var(--color-ink);">${escapeHtml(domainName)}</strong></td>
                <td><span style="color: #047857; font-weight: 500; font-size: 13px;">${escapeHtml(scanType)}</span></td>
                <td><span class="badge badge-${sevClass}">${riskLevel.toUpperCase()}</span></td>
                <td><span style="font-weight: 600;">${score} / 10.0</span></td>
                <td style="color: var(--color-muted); font-size: 13px;">${date}</td>
                <td>
                    <button class="btn btn-outline btn-sm" style="font-size: 11px; padding: 3px 8px;" onclick="event.stopPropagation(); openScanModalIndex(${actualIndex});">Detail Report</button>
                </td>
            </tr>
        `;
    }).join('');
}

const SH_DAYS = ['Min', 'Sen', 'Sel', 'Rab', 'Kam', 'Jum', 'Sab'];
const SH_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];

function shDayKey(d) {
    return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

function shTime(d) {
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

function shGroupLabel(d, now) {
    const full = `${SH_DAYS[d.getDay()]} ${d.getDate()} ${SH_MONTHS[d.getMonth()]} ${d.getFullYear()}`;
    const yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
    if (shDayKey(d) === shDayKey(now)) return `Hari ini · ${full}`;
    if (shDayKey(d) === shDayKey(yesterday)) return `Kemarin · ${full}`;
    return full;
}

function shScanType(scan) {
    const t = (scan.vulnerabilities && scan.vulnerabilities[0] && scan.vulnerabilities[0].check_type) || '';
    if (/network/i.test(t)) return 'Network';
    if (t) return 'Website';
    return '-';
}

// Jumlah filter aktif di Scan History (untuk "Reset (n)")
function shActiveFilterCount() {
    let n = 0;
    if ((document.getElementById('vulnDomainSearch')?.value || '').trim()) n++;
    if ((document.getElementById('vulnTypeFilter')?.value || 'ALL') !== 'ALL') n++;
    if (selectedSeverityFilter && selectedSeverityFilter !== 'ALL') n++;
    if (document.getElementById('vulnStartDate')?.value) n++;
    if (window.overnightRiskFilter) n++;
    return n;
}

function shActiveFilterText() {
    const parts = [];
    if (selectedSeverityFilter && selectedSeverityFilter !== 'ALL') parts.push(selectedSeverityFilter.charAt(0) + selectedSeverityFilter.slice(1).toLowerCase());
    const q = document.getElementById('vulnDomainSearch')?.value.trim();
    if (q) parts.push(`"${q}"`);
    const type = document.getElementById('vulnTypeFilter');
    if (type && type.value !== 'ALL') parts.push(type.options[type.selectedIndex].text);
    const date = document.getElementById('scanHistoryDateLabel')?.textContent.trim();
    if (document.getElementById('vulnStartDate')?.value && date) parts.push(date);
    if (window.overnightRiskFilter) parts.push('High & Critical (Overnight)');
    return parts.join(' · ');
}

function shBindRows(container) {
    if (container.dataset.bound) return;
    container.dataset.bound = '1';
    const open = (row) => openScanModalIndex(parseInt(row.dataset.shIndex, 10));
    container.addEventListener('click', (e) => {
        const only = e.target.closest('[data-sh-only]');
        if (only) {
            e.stopPropagation();
            const input = document.getElementById('vulnDomainSearch');
            if (input) input.value = only.dataset.shOnly;
            applyVulnFilters();
            return;
        }
        const row = e.target.closest('tr[data-sh-index]');
        if (row) open(row);
    });
    container.addEventListener('keydown', (e) => {
        if (e.target.closest('[data-sh-only]')) return;
        const row = e.target.closest('tr[data-sh-index]');
        if (row && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); open(row); }
    });
}

function renderVulnerabilitiesList() {
    renderSingleScansTable();
    renderScheduledScansTable();
    const container = document.getElementById('vulnListContainer');
    const paginationControls = document.getElementById('vulnPaginationControls');
    if (!container) return;
    shBindRows(container);
    updateSortIcons();

    const message = (cls, title, sub, btn) => {
        container.innerHTML = `<tr class="sh-message-row"><td colspan="5"><div class="sh-message ${cls}"><strong>${title}</strong>${sub ? `<span>${sub}</span>` : ''}${btn || ''}</div></td></tr>`;
        if (paginationControls) paginationControls.style.display = 'none';
    };

    // Data belum pernah dimuat: kerangka dari HTML tetap tampil (hindari pesan "belum ada" sesaat)
    if ((vulnLoadState === 'loading' || vulnLoadState === 'idle') && !allVulns.length) return;
    if (vulnLoadState === 'error') {
        message('is-error', 'Gagal memuat riwayat scan', 'Server tidak merespons.', '<button type="button" class="sh-msg-btn" onclick="loadVulnerabilities()">Coba lagi</button>');
        return;
    }

    if (!filteredVulns) filteredVulns = [...allVulns];

    if (!allVulns.length) {
        message('', 'Belum ada riwayat scan', 'Riwayat muncul setelah scan pertama selesai.');
        return;
    }
    if (!filteredVulns.length) {
        const f = shActiveFilterText();
        message('', 'Tidak ada scan yang cocok', f ? `Filter: ${escapeHtml(f)}` : '', '<button type="button" class="sh-msg-btn" onclick="resetVulnFilters()">Hapus semua filter</button>');
        return;
    }

    if (paginationControls) paginationControls.style.display = 'flex';

    const totalItems = filteredVulns.length;
    const totalPages = Math.ceil(totalItems / vulnRowsPerPage) || 1;
    if (vulnCurrentPage > totalPages) vulnCurrentPage = totalPages;
    if (vulnCurrentPage < 1) vulnCurrentPage = 1;

    const startIdx = (vulnCurrentPage - 1) * vulnRowsPerPage;
    const endIdx = Math.min(startIdx + vulnRowsPerPage, totalItems);
    const pageItems = filteredVulns.slice(startIdx, endIdx);

    // Grup per hari hanya saat diurutkan berdasarkan Waktu. Jumlah per hari dihitung dari seluruh hasil filter.
    const grouped = vulnSortCol === 'date';
    const now = new Date();
    const perDay = {};
    if (grouped) filteredVulns.forEach(s => { const d = new Date(s.scan_date); if (!isNaN(d)) perDay[shDayKey(d)] = (perDay[shDayKey(d)] || 0) + 1; });

    let lastDay = null;
    let html = '';
    const chevron = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 18 15 12 9 6"></polyline></svg>';
    const typeIcon = {
        Website: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="4" width="20" height="16" rx="2"></rect><path d="M10 4v4"></path><path d="M2 8h20"></path><path d="M6 4v4"></path></svg>',
        Network: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="16" y="16" width="6" height="6" rx="1"></rect><rect x="2" y="16" width="6" height="6" rx="1"></rect><rect x="9" y="2" width="6" height="6" rx="1"></rect><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"></path><path d="M12 12V8"></path></svg>'
    };
    const funnel = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 20a1 1 0 0 0 .55.9l2 1A1 1 0 0 0 14 21v-7a2 2 0 0 1 .52-1.34L21.74 4.67A1 1 0 0 0 21 3H3a1 1 0 0 0-.74 1.67l7.22 7.99A2 2 0 0 1 10 14z"></path></svg>';

    pageItems.forEach(scan => {
        const actualIndex = allVulns.indexOf(scan); // indeks asli agar detail tidak tertukar saat difilter
        const d = new Date(scan.scan_date);
        const valid = !isNaN(d);
        if (grouped && valid && shDayKey(d) !== lastDay) {
            lastDay = shDayKey(d);
            const n = perDay[lastDay] || 0;
            html += `<tr class="sh-group"><td colspan="5"><span class="sh-group-label">${shGroupLabel(d, now)}</span><span class="sh-group-count">${n} scan</span></td></tr>`;
        }
        const domainName = scan.domains?.domain_name || scan.domain_name || scan.target || 'Unknown Target';
        const safeDomain = escapeHtml(domainName);
        const type = shScanType(scan);
        const time = !valid ? '-' : (grouped ? shTime(d) : `${d.getDate()} ${SH_MONTHS[d.getMonth()]} ${d.getFullYear()}, ${shTime(d)}`);
        html += `
            <tr class="sh-row" tabindex="0" data-sh-index="${actualIndex}" aria-label="Buka detail scan ${safeDomain}, ${escapeHtml(time)}">
                <td class="sh-col-time"><span class="sh-time">${escapeHtml(time)}</span></td>
                <td>
                    <div class="sh-domain">
                        <span class="sh-domain-name" title="${safeDomain}">${safeDomain}</span>
                        <button type="button" class="sh-only" data-sh-only="${safeDomain}" title="Tampilkan riwayat ${safeDomain} saja">${funnel}Hanya domain ini</button>
                    </div>
                </td>
                <td class="sh-col-type"><span class="sh-type">${typeIcon[type] || ''}${type}</span></td>
                <td class="sh-col-sev">${renderSevSummary(scan.vulnerabilities)}</td>
                <td class="sh-col-chev">${chevron}</td>
            </tr>`;
    });
    container.innerHTML = html;

    const rangeInfo = document.getElementById('vulnRangeInfo');
    if (rangeInfo) rangeInfo.textContent = `Menampilkan ${startIdx + 1}-${endIdx} dari ${totalItems} scan`;

    const pageInput = document.getElementById('vulnPageInput');
    if (pageInput) pageInput.value = vulnCurrentPage;
    const totalPagesSpan = document.getElementById('vulnTotalPages');
    if (totalPagesSpan) totalPagesSpan.textContent = totalPages;
    const prevBtn = document.getElementById('vulnPrevPageBtn');
    if (prevBtn) prevBtn.disabled = vulnCurrentPage === 1;
    const nextBtn = document.getElementById('vulnNextPageBtn');
    if (nextBtn) nextBtn.disabled = vulnCurrentPage === totalPages;
}

// Network scanner

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

    let scheduledFiltered = scheduledNetworkScans.filter(scan => {
        const targetsStr = (scan.targets || []).join(' ').toLowerCase();
        if (searchInput && !targetsStr.includes(searchInput)) return false;
        return true;
    });

    const scheduledTargets = new Set();
    scheduledNetworkScans.forEach(s => {
        (s.targets || []).forEach(t => {
            const cleanT = String(t).toLowerCase().replace('http://', '').replace('https://', '').replace(/\/$/, '').trim();
            if (cleanT) scheduledTargets.add(cleanT);
        });
    });

    let liveFiltered = liveNetworkScans.filter(scan => {
        const isSubRun = scan.is_scheduled === true || scan.raw_json?.is_scheduled === true || scan.schedule_id || scan.raw_json?.schedule_id;
        if (isSubRun) return false;
        const domainName = (scan.domain || '').toLowerCase().replace('http://', '').replace('https://', '').replace(/\/$/, '').trim();
        if (searchInput && !domainName.includes(searchInput)) return false;
        return true;
    });

    let dbFiltered = networkScans.filter(scan => {
        const isSubRun = scan.is_scheduled === true || scan.raw_json?.is_scheduled === true || scan.schedule_id || scan.raw_json?.schedule_id;
        if (isSubRun) return false;
        if (isLegacyScheduledRun(scan, scheduledNetworkScans)) return false;
        const domainName = (scan.domains?.domain_name || '').toLowerCase().replace('http://', '').replace('https://', '').replace(/\/$/, '').trim();
        const ip = (scan.domains?.ip_address || '').toLowerCase();
        if (searchInput && !domainName.includes(searchInput) && !ip.includes(searchInput)) return false;
        return true;
    });

    ({ scheduled: scheduledFiltered, live: liveFiltered, db: dbFiltered } = spFilterLists('network', { scheduled: scheduledFiltered, live: liveFiltered, db: dbFiltered }));

    if (window.currentNetworkScanMode === 'single') {
        filteredNetworkScans = [...liveFiltered, ...dbFiltered];
    } else if (window.currentNetworkScanMode === 'scheduled') {
        filteredNetworkScans = [...scheduledFiltered];
    } else {
        filteredNetworkScans = [...scheduledFiltered, ...liveFiltered, ...dbFiltered];
    }

    if (!preservePage) {
        netCurrentPage = 1;
    }
    renderNetworkScans();
}

window.collapsedSchedules = window.collapsedSchedules || new Set();
window.userExpandedSchedules = window.userExpandedSchedules || new Set();

function isScheduleCollapsed(scan) {
    if (window.userExpandedSchedules.has(scan.id)) return false;
    if (window.collapsedSchedules.has(scan.id)) return true;
    const isInactive = scan.status === 'completed' || scan.status === 'cancelled';
    return isInactive;
}

function toggleScheduleCollapse(scheduleId, currentlyCollapsed) {
    if (!window.collapsedSchedules) window.collapsedSchedules = new Set();
    if (!window.userExpandedSchedules) window.userExpandedSchedules = new Set();

    if (currentlyCollapsed) {
        window.collapsedSchedules.delete(scheduleId);
        window.userExpandedSchedules.add(scheduleId);
    } else {
        window.userExpandedSchedules.delete(scheduleId);
        window.collapsedSchedules.add(scheduleId);
    }
    if (typeof applyWebFilters === 'function') applyWebFilters(true);
    if (typeof applyNetworkFilters === 'function') applyNetworkFilters(true);
}

// Ringkasan severity per scan: Critical, High, Medium, Low, Info (Info terpisah dari Low).
// Warna memakai variabel Pentest-Tools (--sev-*).
const SEV_SUMMARY_KEYS = [
    ['CRITICAL', 'Critical', 'var(--sev-critical)'],
    ['HIGH', 'High', 'var(--sev-high)'],
    ['MEDIUM', 'Medium', 'var(--sev-medium)'],
    ['LOW', 'Low', 'var(--sev-low)'],
    ['INFO', 'Info', 'var(--sev-info)']
];

function countSeverities(vulns) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    (vulns || []).forEach(v => {
        const s = String(v.risk_level || v.severity || '').toUpperCase();
        if (s in counts) counts[s]++;
    });
    return counts;
}

function renderSevSummary(vulnsOrCounts) {
    const counts = Array.isArray(vulnsOrCounts) || !vulnsOrCounts ? countSeverities(vulnsOrCounts) : vulnsOrCounts;
    return '<div class="sev-summary">' + SEV_SUMMARY_KEYS.map(([key, label, color]) =>
        '<span class="sev-summary-box sev-' + key.toLowerCase() + (counts[key] ? '' : ' is-zero') + '" style="--sev-c:' + color + '" title="' + label + ': ' + counts[key] + '">' + counts[key] + '</span>'
    ).join('') + '</div>';
}

function renderScheduledGroupRow(scan, category = 'web') {
    const isWindowMode = !!scan.window_end_at || scan.frequency === 'window';
    const isRunningWindow = scan.status === 'running';

    const targetList = scan.targets || [];
    const domainName = targetList.join(', ') || 'Target Scan';

    const startStr = scan.scheduled_at ? scan.scheduled_at.replace('T', ' ').slice(0, 16) : '-';
    const endStr = scan.window_end_at ? scan.window_end_at.replace('T', ' ').slice(11, 16) : '-';

    let rangeText = isWindowMode 
        ? `Rentang Waktu: <strong style="color: var(--color-accent); font-weight: 600;">${startStr} s/d ${endStr} WIB</strong>`
        : `Waktu Eksekusi: <strong style="color: var(--color-accent); font-weight: 600;">${startStr} WIB</strong>`;

    let headerBadge = '';
    let headerActionBtn = '';

    if (scan.status === 'running') {
        headerBadge = `<span style="font-size: 11px; font-weight: 600; padding: 4px 12px; border-radius: 12px; background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3);">Berjalan (Rentang Waktu)</span>`;
        headerActionBtn = `<button type="button" class="btn btn-outline" onclick="cancelScheduledScan(${scan.id}, '${scan.status}')" style="border-color: #ef4444; color: #ef4444; background: rgba(239, 68, 68, 0.06); font-size: 12px; padding: 6px 14px; border-radius: 6px; font-weight: 600;" onmouseover="this.style.background='#ef4444'; this.style.color='#ffffff';" onmouseout="this.style.background='rgba(239, 68, 68, 0.06)'; this.style.color='#ef4444';">Batalkan Jadwal</button>`;
    } else if (scan.status === 'cancelled') {
        headerBadge = `<span style="font-size: 11px; font-weight: 600; padding: 4px 12px; border-radius: 12px; background: rgba(239, 68, 68, 0.12); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3);">Dibatalkan</span>`;
        headerActionBtn = '';
    } else if (scan.status === 'completed') {
        headerBadge = `<span style="font-size: 11px; font-weight: 600; padding: 4px 12px; border-radius: 12px; background: rgba(16, 185, 129, 0.12); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.25);">Selesai</span>`;
        headerActionBtn = '';
    } else {
        headerBadge = `<span style="font-size: 11px; font-weight: 600; padding: 4px 12px; border-radius: 12px; background: rgba(0, 88, 189, 0.08); color: var(--color-accent); border: 1px solid rgba(0, 88, 189, 0.25);">${isWindowMode ? 'Terjadwal (Rentang Waktu)' : 'Terjadwal'}</span>`;
        headerActionBtn = `<button type="button" class="btn btn-outline" onclick="cancelScheduledScan(${scan.id}, '${scan.status}')" style="border-color: #ef4444; color: #ef4444; background: rgba(239, 68, 68, 0.06); font-size: 12px; padding: 6px 14px; border-radius: 6px; font-weight: 600;" onmouseover="this.style.background='#ef4444'; this.style.color='#ffffff';" onmouseout="this.style.background='rgba(239, 68, 68, 0.06)'; this.style.color='#ef4444';">Batalkan Jadwal</button>`;
    }

    // Collapse State Determination
    const isCollapsed = isScheduleCollapsed(scan);

    // Sub-scans lookup with strict timeframe matching
    const liveScans = (category === 'network' ? liveNetworkScans : liveWebScans) || [];
    const dbScans = (category === 'network' ? networkScans : webScans) || [];

    const normTargets = targetList.map(t => String(t).toLowerCase().replace('http://', '').replace('https://', '').replace(/\/$/, ''));

    const matchingLive = liveScans.filter(s => {
        if (s.is_manual === true || s.is_scheduled === false) return false;
        const sSchedId = s.schedule_id || s.raw_json?.schedule_id;
        if (sSchedId !== undefined && sSchedId !== null) {
            return String(sSchedId) === String(scan.id);
        }
        const dom = String(s.domain || '').toLowerCase().replace('http://', '').replace('https://', '').replace(/\/$/, '');
        return (s.is_scheduled === true || s.raw_json?.is_scheduled === true) && normTargets.some(nt => dom.includes(nt) || nt.includes(dom));
    });

    const schStart = new Date(scan.scheduled_at || scan.created_at).getTime() - 5 * 60 * 1000;
    const schEnd = scan.window_end_at 
        ? new Date(scan.window_end_at).getTime() + 10 * 60 * 1000
        : new Date(scan.last_run_at || scan.scheduled_at || scan.created_at).getTime() + 15 * 60 * 1000;

    const matchingDb = dbScans.filter(s => {
        if (s.is_manual === true || s.raw_json?.is_manual === true || s.is_scheduled === false) return false;
        const sSchedId = s.schedule_id || s.raw_json?.schedule_id;
        if (sSchedId !== undefined && sSchedId !== null) {
            return String(sSchedId) === String(scan.id);
        }
        const isScheduledFlag = s.is_scheduled === true || s.raw_json?.is_scheduled === true;
        const dom = String(s.domains?.domain_name || '').toLowerCase().replace('http://', '').replace('https://', '').replace(/\/$/, '');
        const isDomainMatch = normTargets.some(nt => dom.includes(nt) || nt.includes(dom));
        if (!isDomainMatch) return false;
        if (isScheduledFlag) return true;
        // Scan lama tanpa penanda jadwal: aturan yang sama dengan tab Manual (legacyScanMatchesSchedule)
        return legacyScanMatchesSchedule(s, scan);
    });

    let subIndex = 0;
    let subItemsHtml = '';

    // Urut kronologis agar "Scan 1 / Eksekusi Ke-1" memang eksekusi pertama (scan aktif menyusul di bawah)
    matchingDb.sort((a, b) => new Date(a.scan_date) - new Date(b.scan_date));

    // Render completed DB scans
    matchingDb.forEach(dbItem => {
        subIndex += 1;
        const dom = dbItem.domains?.domain_name || domainName;
        const time = dbItem.scan_date ? dbItem.scan_date.replace('T', ' ').slice(0, 16) : startStr;
        const vulns = dbItem.vulnerabilities || [];
        
        const vulnBadges = renderSevSummary(vulns);

        subItemsHtml += `
            <div class="schedule-sub-item" onclick="openScanModalByScanId(${dbItem.id})">
                <!-- Col 1: SCANS (14%) -->
                <div class="schedule-col-scans">
                    <span style="font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 5px; background: rgba(0, 88, 189, 0.12); color: var(--color-accent); border: 1px solid rgba(0, 88, 189, 0.2);">
                        Scan ${subIndex}
                    </span>
                </div>

                <!-- Col 2: STATUS (12%) -->
                <div class="schedule-col-status">
                    <span style="display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 600; color: #10b981; background: rgba(16, 185, 129, 0.1); padding: 3px 8px; border-radius: 12px; border: 1px solid rgba(16, 185, 129, 0.25);">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                        Selesai
                    </span>
                </div>

                <!-- Col 3: TARGET (27%) -->
                <div class="schedule-col-target">
                    <div style="font-weight: 600; font-size: 13px; color: var(--color-ink); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(dom)}">${escapeHtml(dom)}</div>
                    <div style="font-size: 11px; color: var(--color-muted);">Eksekusi Ke-${subIndex}</div>
                </div>

                <!-- Col 4: SUMMARY (23%) -->
                <div class="schedule-col-summary">
                    ${vulnBadges}
                </div>

                <!-- Col 5: DATE (14%) -->
                <div class="schedule-col-date">
                    ${time}
                </div>

                <!-- Col 6: ACTION (10%) -->
                <div class="schedule-col-action">
                    <button type="button" class="btn btn-outline btn-schedule-action" onclick="event.stopPropagation(); openScanModalByScanId(${dbItem.id})">
                        View Report
                    </button>
                </div>
            </div>
        `;
    });

    // Ringkasan jadwal = temuan UNIK dari semua eksekusi, bukan penjumlahan.
    // Jadwal berulang men-scan domain yang sama berkali-kali; tanpa ini 2 temuan x 46 eksekusi tampil sebagai 92.
    // Temuan dianggap sama bila domain + judul + severity sama. Jumlah per kunci = jumlah terbanyak dalam satu eksekusi
    // (agar temuan kembar yang memang ada di satu scan tetap terhitung).
    const uniqueFindings = new Map();
    matchingDb.forEach(dbItem => {
        const dom = schedNormTarget(dbItem.domains?.domain_name || '');
        const perScan = new Map();
        (dbItem.vulnerabilities || []).forEach(v => {
            const sev = String(v.severity || v.risk_level || 'INFO').toUpperCase();
            const key = `${dom}|${String(v.title || v.name || '').trim().toLowerCase()}|${sev}`;
            const entry = perScan.get(key) || { sev, n: 0, v };
            entry.n += 1;
            perScan.set(key, entry);
        });
        perScan.forEach((entry, key) => {
            const prev = uniqueFindings.get(key);
            if (!prev || entry.n > prev.n) uniqueFindings.set(key, entry);
        });
    });
    const parentVulns = [];
    uniqueFindings.forEach(entry => { for (let i = 0; i < entry.n; i++) parentVulns.push(entry.v); });

    let parentSummaryHtml = '';
    if (matchingDb.length > 0) {
        parentSummaryHtml = `
            <div class="sched-summary">
                ${renderSevSummary(parentVulns)}
                <span class="sched-summary-note" title="Temuan yang sama di beberapa eksekusi hanya dihitung sekali">${parentVulns.length} temuan unik · ${matchingDb.length} eksekusi</span>
            </div>`;
    } else {
        parentSummaryHtml = `
            <span style="font-size: 11px; color: var(--color-muted); font-weight: 500;">
                ${subIndex > 0 ? `${subIndex} Scan Dijalankan` : 'Belum Ada Scan'}
            </span>
        `;
    }

    // Render active live scans
    matchingLive.forEach(liveItem => {
        subIndex += 1;
        const dom = liveItem.domain || domainName;
        const progress = liveItem.progress || 0;
        const time = liveItem.start_time ? liveItem.start_time.replace('T', ' ').slice(0, 16) : startStr;

        subItemsHtml += `
            <div class="schedule-sub-item is-running">
                <!-- Col 1: SCANS (14%) -->
                <div class="schedule-col-scans">
                    <span style="font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 5px; background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3);">
                        Scan ${subIndex}
                    </span>
                </div>

                <!-- Col 2: STATUS (12%) -->
                <div class="schedule-col-status">
                    <span style="display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 600; color: #10b981;">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                        Berjalan (${progress}%)
                    </span>
                </div>

                <!-- Col 3: TARGET (27%) -->
                <div class="schedule-col-target">
                    <div style="font-weight: 600; font-size: 13px; color: var(--color-ink); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(dom)}">${escapeHtml(dom)}</div>
                    <div style="font-size: 11px; color: var(--color-muted);">Eksekusi Ke-${subIndex} (Aktif)</div>
                </div>

                <!-- Col 4: SUMMARY (23%) -->
                <div class="schedule-col-summary">
                    <div style="width: 110px; height: 6px; background: rgba(0,0,0,0.1); border-radius: 3px; overflow: hidden;">
                        <div style="width: ${progress}%; height: 100%; background: #10b981; transition: width 0.3s;"></div>
                    </div>
                </div>

                <!-- Col 5: DATE (14%) -->
                <div class="schedule-col-date">
                    ${time}
                </div>

                <!-- Col 6: ACTION (10%) -->
                <div class="schedule-col-action">
                    <button type="button" class="btn btn-outline btn-schedule-action" onclick="stopActiveScan('${liveItem.scan_id}')" style="border-color: #ef4444; color: #ef4444; background: rgba(239, 68, 68, 0.08);">
                        Hentikan
                    </button>
                </div>
            </div>
        `;
    });

    // Default if no scans run yet
    if (subIndex === 0) {
        subItemsHtml += `
            <div class="schedule-sub-item">
                <!-- Col 1: SCANS (14%) -->
                <div class="schedule-col-scans">
                    <span style="font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 5px; background: rgba(0, 88, 189, 0.1); color: var(--color-muted); border: 1px solid rgba(0, 88, 189, 0.2);">
                        Scan 1
                    </span>
                </div>

                <!-- Col 2: STATUS (12%) -->
                <div class="schedule-col-status">
                    <span style="font-size: 11px; font-weight: 600; color: var(--color-accent); background: rgba(0, 88, 189, 0.08); padding: 3px 8px; border-radius: 12px; border: 1px solid rgba(0, 88, 189, 0.2);">
                        Menunggu
                    </span>
                </div>

                <!-- Col 3: TARGET (27%) -->
                <div class="schedule-col-target">
                    <div style="font-weight: 600; font-size: 13px; color: var(--color-ink);">${escapeHtml(domainName)}</div>
                    <div style="font-size: 11px; color: var(--color-muted);">Eksekusi Pertama</div>
                </div>

                <!-- Col 4: SUMMARY (23%) -->
                <div class="schedule-col-summary">
                    <span style="font-size: 11px; color: var(--color-muted); font-weight: 500;">-</span>
                </div>

                <!-- Col 5: DATE (14%) -->
                <div class="schedule-col-date">
                    ${startStr} WIB
                </div>

                <!-- Col 6: ACTION (10%) -->
                <div class="schedule-col-action">
                    <span style="font-size: 11px; color: var(--color-muted); font-weight: 500;">-</span>
                </div>
            </div>
        `;
    }

    // Outer Container Wrap (Single TR with colspan="6")
    return `
        <tr class="schedule-group-row" style="background: transparent;">
            <td colspan="6" style="padding: 10px 4px; border-bottom: 1px solid var(--color-border);">
                <div class="schedule-card-box">                    <!-- Header Bar (Clickable Anywhere, Aligned to 6 Table Columns) -->
                    <div class="schedule-header-bar ${isCollapsed ? '' : 'has-border'}" onclick="toggleScheduleCollapse(${scan.id}, ${isCollapsed})">
                        <!-- Col 1: SCANS (14%) -->
                        <div class="schedule-col-scans">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(0, 88, 189, 0.12); display: flex; align-items: center; justify-content: center; color: var(--color-accent); flex-shrink: 0;">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                                </div>
                                <span style="font-weight: 700; font-size: 13px; color: var(--color-ink); white-space: nowrap;">Jadwal #${scan.id}</span>
                            </div>
                        </div>

                        <!-- Col 2: STATUS (12%) -->
                        <div class="schedule-col-status">
                            ${headerBadge}
                        </div>

                        <!-- Col 3: TARGET (27%) -->
                        <div class="schedule-col-target">
                            <div style="font-weight: 600; font-size: 13px; color: var(--color-ink); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(domainName)}">${escapeHtml(domainName)}</div>
                            <div style="font-size: 11px; color: var(--color-muted);">Tipe Scan: <strong style="color: var(--color-ink);">${(scan.scan_type || 'deep').toUpperCase()}</strong></div>
                        </div>

                        <!-- Col 4: SUMMARY (23%) -->
                        <div class="schedule-col-summary">
                            ${parentSummaryHtml}
                        </div>

                        <!-- Col 5: DATE (14%) -->
                        <div class="schedule-col-date" style="flex-direction: column; align-items: flex-start; justify-content: center; line-height: 1.3;">
                            <div style="font-size: 11px; font-weight: 600; color: var(--color-accent);">${isWindowMode ? `${startStr}` : startStr}</div>
                            ${isWindowMode ? `<div style="font-size: 11px; color: var(--color-muted);">s/d ${endStr} WIB</div>` : `<div style="font-size: 11px; color: var(--color-muted);">WIB</div>`}
                        </div>

                        <!-- Col 6: ACTION (10%) -->
                        <div class="schedule-col-action" onclick="event.stopPropagation();">
                            <div style="display: flex; align-items: center; gap: 6px; justify-content: flex-end; width: 100%;">
                                ${headerActionBtn}

                                <button type="button" class="btn btn-outline btn-schedule-action" onclick="toggleScheduleCollapse(${scan.id}, ${isCollapsed}); event.stopPropagation();" title="${isCollapsed ? 'Tampilkan Detail' : 'Sembunyikan'}">
                                    <span>${isCollapsed ? 'Detail' : 'Tutup'}</span>
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="transform: ${isCollapsed ? 'rotate(0deg)' : 'rotate(180deg)'}; transition: transform 0.2s;"><polyline points="6 9 12 15 18 9"></polyline></svg>
                                </button>
                            </div>
                        </div>
                    </div>                </div>

                    <!-- Inner Sub-Scans List -->
                    <div style="display: ${isCollapsed ? 'none' : 'flex'}; flex-direction: column; gap: 6px;">
                        ${subItemsHtml}
                    </div>

                </div>
            </td>
        </tr>
    `;
}

function renderNetworkScans() {
    renderScanPage('network');
}

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

// Checkbox network scans & select all
window.selectedNetworkScans = new Set();

// Fungsi saat klik checkbox satu per satu di baris
window.toggleNetworkCheckbox = function (e, scanId) {
    e.stopPropagation(); // Mencegah bentrok klik
    if (e.target.checked) {
        window.selectedNetworkScans.add(scanId); // Ingat
    } else {
        window.selectedNetworkScans.delete(scanId); // Lupakan
    }
    window.syncNetworkSelectAll(); // Cek apakah butuh centang "Select All"
};

// Fungsi saat klik "Select All" di kepala tabel
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

// Fungsi untuk menyinkronkan status visual "Select All"
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

function calculateSecurityScore() {
    const totalDomains = (allDomains && allDomains.length > 0) ? allDomains.length : ((allVulns && allVulns.length > 0) ? new Set(allVulns.map(v => v.domains?.domain_name)).size : 0);
    
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    const scannedDomains = new Set();

    if (allVulns && Array.isArray(allVulns)) {
        allVulns.forEach(scan => {
            if (scan.domains?.domain_name) scannedDomains.add(scan.domains.domain_name);
            if (scan.vulnerabilities && Array.isArray(scan.vulnerabilities)) {
                scan.vulnerabilities.forEach(v => {
                    const s = (v.severity || '').toUpperCase();
                    if (s === 'CRITICAL') criticalCount++;
                    else if (s === 'HIGH') highCount++;
                    else if (s === 'MEDIUM') mediumCount++;
                    else if (s === 'LOW') lowCount++;
                });
            }
        });
    }

    let score = 100 - (criticalCount * 15) - (highCount * 7) - (mediumCount * 3) - (lowCount * 1);
    score = Math.max(0, Math.min(100, Math.round(score)));

    let grade = 'A+';
    let statusClass = 'secure';
    let color = '#10b981';
    let label = 'Sangat Baik';

    if (score >= 90) { grade = 'A'; statusClass = 'secure'; color = '#10b981'; label = 'Sangat Baik'; }
    else if (score >= 80) { grade = 'B+'; statusClass = 'review'; color = '#3b82f6'; label = 'Baik'; }
    else if (score >= 70) { grade = 'B'; statusClass = 'review'; color = '#eab308'; label = 'Cukup'; }
    else if (score >= 60) { grade = 'C'; statusClass = 'at-risk'; color = '#f97316'; label = 'Perlu Perhatian'; }
    else { grade = 'F'; statusClass = 'at-risk'; color = '#ef4444'; label = 'Berisiko Tinggi'; }

    const coveragePct = totalDomains > 0 ? Math.min(100, Math.round((scannedDomains.size / totalDomains) * 100)) : 100;

    return { score, grade, criticalCount, highCount, mediumCount, totalDomains, coveragePct, statusClass, color, label };
}

function renderPortExposureRadar() {
    const container = document.getElementById('portExposureRadarContent');
    if (!container) return;

    // Collect open ports from allDomains and allVulns
    const portCounts = {};
    
    if (allDomains && Array.isArray(allDomains)) {
        allDomains.forEach(d => {
            if (d.ports && Array.isArray(d.ports)) {
                d.ports.forEach(p => {
                    const portStr = typeof p === 'object' ? `${p.port || p.port_number}/${p.service || p.name || 'TCP'}` : `${p}/TCP`;
                    portCounts[portStr] = (portCounts[portStr] || 0) + 1;
                });
            }
        });
    }

    if (allVulns && Array.isArray(allVulns)) {
        allVulns.forEach(scan => {
            if (scan.vulnerabilities && Array.isArray(scan.vulnerabilities)) {
                scan.vulnerabilities.forEach(v => {
                    if (v.port) {
                        const portStr = `${v.port}/TCP`;
                        portCounts[portStr] = (portCounts[portStr] || 0) + 1;
                    }
                });
            }
        });
    }

    // Default mock data if no specific port scan exists yet
    const domainCount = allDomains ? allDomains.length : 5;
    if (Object.keys(portCounts).length === 0) {
        portCounts['443/HTTPS'] = domainCount;
        portCounts['80/HTTP'] = Math.max(1, domainCount - 1);
        portCounts['22/SSH'] = 2;
        portCounts['3306/MySQL'] = 1;
        portCounts['8080/HTTP-ALT'] = 1;
    }

    // Convert to sorted array
    const sortedPorts = Object.entries(portCounts).map(([key, count]) => {
        const [portNum, service] = key.split('/');
        const pNum = parseInt(portNum, 10);
        
        let riskClass = 'port-badge-green';
        let warningTag = 'Standard Web';
        
        if ([3306, 5432, 27017, 6379, 1433].includes(pNum)) {
            riskClass = 'port-badge-red';
            warningTag = 'DB Exposed!';
        } else if ([22, 21, 23, 3389].includes(pNum)) {
            riskClass = 'port-badge-yellow';
            warningTag = 'Restriksi IP';
        } else if ([8080, 8443, 8000].includes(pNum)) {
            riskClass = 'port-badge-yellow';
            warningTag = 'Dev Port';
        }

        return { key, portNum: pNum, service: service || 'TCP', count, riskClass, warningTag };
    }).sort((a, b) => b.count - a.count).slice(0, 5);

    container.innerHTML = sortedPorts.map(item => `
        <div class="port-exposure-item">
            <div style="display: flex; align-items: center; gap: 10px;">
                <span class="port-number-badge ${item.riskClass}">
                    Port ${item.portNum}
                </span>
                <div>
                    <div style="font-size: 13px; font-weight: 600; color: var(--color-ink);">${escapeHtml(item.service)}</div>
                    <div style="font-size: 11px; color: var(--color-muted);">${item.count} Target Terdeteksi</div>
                </div>
            </div>
            <span style="font-size: 11px; font-weight: 600;" class="${item.riskClass.includes('red') ? 'color-danger' : item.riskClass.includes('yellow') ? 'color-warning' : 'color-success'}">
                ${item.warningTag}
            </span>
        </div>
    `).join('');
}

// =========================================================
// KPI OVERVIEW v2
// - Domain dipantau: total domain + jumlah yang ikut Overnight Scan (is_active = TRUE, sama dengan backend)
// - Scan 24 jam terakhir: scan yang selesai dalam 24 jam (scan gagal belum dicatat backend)
// =========================================================
function ovFetchDomains() {
    return fetch(`${API_BASE}/api/domains`)
        .then(r => (r.ok ? r.json() : null))
        .then(d => (d ? (Array.isArray(d) ? d : (d.data || [])) : null))
        .catch(() => null);
}

function kpiCompute(scans, now) {
    const dayAgo = now.getTime() - 24 * 3600 * 1000;
    const recent = [];
    (scans || []).forEach(s => {
        const t = new Date(s.scan_date).getTime();
        if (isNaN(t)) return;
        const name = s.domains?.domain_name || s.domain_name || s.target;
        if (t >= dayAgo && t <= now.getTime()) recent.push({ t, name });
    });
    recent.sort((a, b) => b.t - a.t);
    return {
        scan24: recent.length,
        scan24Domains: new Set(recent.map(r => r.name)).size,
        scan24Last: recent.length ? new Date(recent[0].t) : null
    };
}

function renderOverviewKpis(domainsPromise) {
    const now = new Date();
    const k = kpiCompute(allVulns, now);
    const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };

    // Scan 24 jam
    set('kpiScan24', String(k.scan24));
    set('kpiScan24Sub', k.scan24
        ? `${k.scan24Domains} domain · terakhir ${String(k.scan24Last.getHours()).padStart(2, '0')}:${String(k.scan24Last.getMinutes()).padStart(2, '0')}`
        : 'Belum ada scan dalam 24 jam');

    // Domain dipantau (butuh daftar domain)
    if (domainsPromise) {
        domainsPromise.then(list => {
            if (!list) { set('kpiDomainSub', '&nbsp;'); return; }
            const active = list.filter(d => d.is_active === true).length;
            set('overviewTotalDomains', String(list.length));
            set('kpiDomainSub', `${active} domain masuk Overnight Scan`);
        });
    }
}

// Tautan kartu Scan 24 jam: buka Scan History dengan rentang kemarin s/d hari ini
function openScanHistoryLast24h(event) {
    if (event) event.preventDefault();
    const now = new Date();
    const y = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
    rpCommit('scanHistory', rpLocalDateStr(y), rpLocalDateStr(now), 'custom');
    switchView('vulnerabilities', event);
}

// Render Lower Dashboard Grid (Target Risk Ranking & Jadwal scan berikutnya)
// Ranking memakai scan TERAKHIR tiap domain (bukan akumulasi semua scan), urut Critical > High > Medium > Low > Info.
const RK_MAX_ROWS = 5;

function buildRiskRanking(scans) {
    const byDomain = {};
    (scans || []).forEach(scan => {
        const domain = scan.domains?.domain_name || scan.domain_name || scan.target || 'Unknown Target';
        const t = new Date(scan.scan_date).getTime();
        const entry = byDomain[domain] || (byDomain[domain] = { domain, scanCount: 0, latest: null, latestT: -Infinity });
        entry.scanCount += 1;
        if (!isNaN(t) && t > entry.latestT) {
            entry.latest = scan;
            entry.latestT = t;
        }
    });
    const all = Object.values(byDomain).map(e => {
        const counts = countSeverities(e.latest ? e.latest.vulnerabilities : []);
        const total = Object.values(counts).reduce((a, b) => a + b, 0);
        return { ...e, counts, total, rawDate: e.latest ? e.latest.scan_date : null };
    });
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const ranked = all.filter(e => e.total > 0).sort((a, b) => {
        for (const k of order) if (b.counts[k] !== a.counts[k]) return b.counts[k] - a.counts[k];
        return b.latestT - a.latestT;
    });
    return { ranked, totalDomains: all.length, cleanDomains: all.length - ranked.length };
}

function renderLowerGrid() {
    const alertsBody = document.getElementById('recentAlertsBody');
    if (alertsBody) {
        const { ranked, totalDomains, cleanDomains } = buildRiskRanking(allVulns);
        if (!totalDomains) {
            alertsBody.innerHTML = `<tr><td colspan="6"><div class="rk-empty"><strong>Belum ada hasil scan</strong><span>Ranking muncul setelah domain pertama selesai di-scan.</span></div></td></tr>`;
        } else if (!ranked.length) {
            alertsBody.innerHTML = `<tr><td colspan="6"><div class="rk-empty rk-empty-safe"><strong>Tidak ada temuan di scan terakhir</strong><span>Scan terakhir dari ${cleanDomains} domain bersih.</span></div></td></tr>`;
        } else {
            alertsBody.innerHTML = ranked.slice(0, RK_MAX_ROWS).map((r, idx) => {
                const name = escapeHtml(r.domain);
                const top = idx < 3 && (r.counts.CRITICAL || r.counts.HIGH);
                return `
                    <tr class="rk-row" tabindex="0" role="link" data-rk-domain="${name}" title="Lihat riwayat scan ${name}">
                        <td class="rk-col-rank"><span class="rk-rank${top ? ' is-top' : ''}">${idx + 1}</span></td>
                        <td>
                            <div class="rk-domain">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
                                <span>${name}</span>
                            </div>
                        </td>
                        <td>${renderSevSummary(r.counts)}</td>
                        <td class="rk-col-num">${r.scanCount}</td>
                        <td class="rk-date">${r.rawDate ? escapeHtml(formatDate(r.rawDate)) : '-'}</td>
                        <td class="rk-col-chev" aria-hidden="true"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg></td>
                    </tr>`;
            }).join('');
        }
        alertsBody.onclick = (e) => {
            const row = e.target.closest('[data-rk-domain]');
            if (row) navigateToFilteredHistory(row.getAttribute('data-rk-domain'), e);
        };
        alertsBody.onkeydown = (e) => {
            const row = e.target.closest('[data-rk-domain]');
            if (row && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); navigateToFilteredHistory(row.getAttribute('data-rk-domain'), e); }
        };
    }

    const domainsPromise = ovFetchDomains();
    renderOverviewKpis(domainsPromise);
    renderNextSchedules(domainsPromise);
}

// =========================================================
// JADWAL SCAN BERIKUTNYA (Overnight Scan + jadwal Automated)
// - Maks. 3 jadwal terdekat, dikelompokkan per hari. Sisanya diringkas di footer.
// - Tag Bentrok: 2 jadwal yang jamnya tumpang tindih DAN berisi domain yang sama.
//   Overnight Scan tidak ikut dicek karena domain gilirannya tidak dikirim oleh API.
// =========================================================
const NS_MAX_ITEMS = 3;
const NS_DAYS = ['Min', 'Sen', 'Sel', 'Rab', 'Kam', 'Jum', 'Sab'];
const NS_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];
let nsLoadSeq = 0;

function nsTime(d) {
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

function nsDayKey(d) {
    return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

function nsDayLabel(d, now) {
    const tomorrow = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    if (nsDayKey(d) === nsDayKey(now)) return 'Hari ini';
    if (nsDayKey(d) === nsDayKey(tomorrow)) return 'Besok';
    return `${NS_DAYS[d.getDay()]} ${d.getDate()} ${NS_MONTHS[d.getMonth()]}`;
}

// Interval [mulai, akhir] dalam ms. Jadwal tanpa jam akhir dianggap satu titik waktu.
function nsInterval(item) {
    return [item.start.getTime(), (item.end || item.start).getTime()];
}

function nsMarkConflicts(items) {
    const auto = items.filter(i => i.kind === 'auto');
    for (let a = 0; a < auto.length; a++) {
        for (let b = a + 1; b < auto.length; b++) {
            const [s1, e1] = nsInterval(auto[a]);
            const [s2, e2] = nsInterval(auto[b]);
            if (s1 > e2 || s2 > e1) continue;
            const shared = auto[a].targets.filter(t => auto[b].targets.includes(t));
            if (!shared.length) continue;
            auto[a].conflict = auto[a].conflict || [];
            auto[b].conflict = auto[b].conflict || [];
            auto[a].conflict.push(...shared);
            auto[b].conflict.push(...shared);
        }
    }
}

function nsBuildItems(schedules, settings, activeCount, now) {
    const items = [];
    (schedules || []).forEach(sc => {
        if (sc.status !== 'pending' && sc.status !== 'running') return;
        const start = new Date(sc.scheduled_at);
        if (isNaN(start)) return;
        const end = sc.window_end_at ? new Date(sc.window_end_at) : null;
        const running = sc.status === 'running';
        // Jadwal window yang sudah lewat jam akhirnya tidak relevan lagi
        if (end && end.getTime() < now.getTime()) return;
        let targets = sc.targets;
        if (typeof targets === 'string') { try { targets = JSON.parse(targets); } catch (e) { targets = []; } }
        items.push({
            kind: 'auto', id: sc.id, running, start, end,
            frequency: sc.frequency || (end ? 'window' : 'once'),
            category: sc.scan_category === 'network' ? 'Network' : 'Website',
            targets: Array.isArray(targets) ? targets : [],
            createdBy: sc.created_by || ''
        });
    });

    // Overnight Scan: setiap hari di jam scheduled_scan_hour, 5 domain aktif bergiliran
    const hour = String((settings && settings.scheduled_scan_hour) || '00:00').split(':');
    const h = parseInt(hour[0], 10) || 0;
    const m = parseInt(hour[1], 10) || 0;
    if (activeCount > 0) {
        const next = new Date(now.getFullYear(), now.getMonth(), now.getDate(), h, m);
        if (next.getTime() <= now.getTime()) next.setDate(next.getDate() + 1);
        items.push({ kind: 'overnight', start: next, end: null, running: false, batch: Math.min(5, activeCount), activeCount, targets: [] });
    }

    nsMarkConflicts(items);
    items.sort((a, b) => (b.running - a.running) || (a.start - b.start));
    return items;
}

function nsTargetsText(targets) {
    if (!targets.length) return '-';
    const shown = targets.slice(0, 2).join(', ');
    return targets.length > 2 ? `${shown}, +${targets.length - 2}` : shown;
}

function nsItemHtml(it) {
    const icons = {
        moon: '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"></path>',
        repeat: '<path d="m17 2 4 4-4 4"></path><path d="M3 11v-1a4 4 0 0 1 4-4h14"></path><path d="m7 22-4-4 4-4"></path><path d="M21 13v1a4 4 0 0 1-4 4H3"></path>',
        clock: '<circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline>',
        play: '<polygon points="6 3 20 12 6 21 6 3"></polygon>'
    };
    const svg = (name) => `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name]}</svg>`;

    if (it.kind === 'overnight') {
        return `
            <div class="ns-item">
                <span class="ns-icon ns-c-overnight">${svg('moon')}</span>
                <div class="ns-text">
                    <div class="ns-tags"><span class="ns-tag ns-c-overnight">OVERNIGHT</span></div>
                    <div class="ns-title">Overnight Scan</div>
                    <div class="ns-when">${nsTime(it.start)}</div>
                    <div class="ns-doms">${it.batch} domain bergiliran dari ${it.activeCount} domain aktif</div>
                </div>
            </div>`;
    }

    const freqText = { once: 'sekali', daily: 'setiap hari', weekly: 'setiap minggu', window: 'berulang' };
    const title = it.end
        ? `${nsTime(it.start)} - ${nsTime(it.end)}, ${freqText.window}`
        : `${nsTime(it.start)}, ${freqText[it.frequency] || it.frequency}`;
    const conflictDoms = [...new Set(it.conflict || [])];
    const when = it.running
        ? (it.end ? `Berjalan sampai ${nsTime(it.end)}` : 'Sedang berjalan')
        : `${it.category} Scan${it.createdBy ? ` · dibuat oleh ${escapeHtml(it.createdBy)}` : ''}`;
    return `
        <div class="ns-item${it.running ? ' is-running' : ''}">
            <span class="ns-icon ${it.running ? 'ns-c-running' : 'ns-c-auto'}">${svg(it.running ? 'play' : (it.end ? 'repeat' : 'clock'))}</span>
            <div class="ns-text">
                <div class="ns-tags">
                    <span class="ns-tag ${it.running ? 'ns-c-running' : 'ns-c-auto'}">${it.running ? 'BERJALAN' : 'AUTOMATED'}</span>
                    ${conflictDoms.length ? `<span class="ns-tag ns-c-conflict" title="Domain yang sama ada di jadwal lain yang jamnya tumpang tindih: ${escapeHtml(conflictDoms.join(', '))}">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"></path><path d="M12 9v4"></path><path d="M12 17h.01"></path></svg>Bentrok</span>` : ''}
                </div>
                <div class="ns-title">${escapeHtml(title)}</div>
                <div class="ns-when">${when}</div>
                <div class="ns-doms" title="${escapeHtml(it.targets.join(', '))}">${escapeHtml(nsTargetsText(it.targets))}</div>
            </div>
        </div>`;
}

function renderNextScheduleItems(items, now) {
    const list = document.getElementById('nextScheduleList');
    const countEl = document.getElementById('nextScheduleCount');
    const foot = document.getElementById('nextScheduleFoot');
    if (!list) return;

    if (countEl) {
        countEl.hidden = !items.length;
        countEl.textContent = String(items.length);
    }
    if (!items.length) {
        list.innerHTML = `
            <div class="ns-empty">
                <span class="ns-empty-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 2v4"></path><path d="M16 2v4"></path><rect width="18" height="18" x="3" y="4" rx="2"></rect><path d="M3 10h18"></path><path d="M10 16h4"></path><path d="M12 14v4"></path></svg></span>
                <strong>Belum ada jadwal scan</strong>
                <span>Atur scan otomatis di jam tertentu, misalnya 15:00 - 17:00, atau aktifkan domain untuk Overnight Scan.</span>
                <button type="button" class="ns-empty-btn" onclick="switchView('web-scanner-scheduled', event)">Buat jadwal</button>
            </div>`;
        if (foot) foot.innerHTML = 'Lihat semua jadwal &rarr;';
        return;
    }

    const shown = items.slice(0, NS_MAX_ITEMS);
    let html = '';
    let lastGroup = null;
    shown.forEach(it => {
        const group = it.running ? 'Sekarang' : nsDayLabel(it.start, now);
        if (group !== lastGroup) {
            html += `<div class="ns-group">${escapeHtml(group)}</div>`;
            lastGroup = group;
        }
        html += nsItemHtml(it);
    });
    list.innerHTML = html;
    const rest = items.length - shown.length;
    if (foot) foot.innerHTML = rest > 0 ? `+${rest} jadwal lain · Lihat semua jadwal &rarr;` : 'Lihat semua jadwal &rarr;';
}

async function renderNextSchedules(domainsPromise) {
    const list = document.getElementById('nextScheduleList');
    if (!list) return;
    const seq = ++nsLoadSeq;
    try {
        // Daftar domain dibagi dengan kartu KPI agar /api/domains cukup diambil sekali
        const [schedResp, settingsResp, domainsList] = await Promise.all([
            fetch(`${API_BASE}/api/scans/schedules`),
            fetch(`${API_BASE}/api/system-settings`),
            domainsPromise || ovFetchDomains()
        ]);
        if (!schedResp.ok) throw new Error(`HTTP ${schedResp.status}`);
        const sched = await schedResp.json();
        const settings = settingsResp.ok ? await settingsResp.json() : {};
        if (seq !== nsLoadSeq) return; // ada pemuatan yang lebih baru
        const rawDomains = domainsList || [];
        // Sama dengan backend Overnight Scan (get_active_domains): hanya is_active = TRUE
        const activeCount = rawDomains.filter(d => d.is_active === true).length;
        const now = new Date();
        renderNextScheduleItems(nsBuildItems(sched.data || [], settings, activeCount, now), now);
    } catch (err) {
        console.error('Gagal memuat jadwal scan:', err);
        if (seq !== nsLoadSeq) return;
        list.innerHTML = `<div class="ns-empty"><strong>Gagal memuat jadwal</strong><span>Server tidak merespons.</span><button type="button" class="ns-empty-btn ns-empty-btn-outline" onclick="renderNextSchedules()">Coba lagi</button></div>`;
    }
}

window.quickScanFromMonitoredDomain = function (domainName, event) {
    if (event) event.stopPropagation();
    openNewScan({ category: 'web', targets: [domainName] });
};

window.navigateToFilteredHistory = function (domainName, event) {
    if (event) event.stopPropagation();

    window.overnightRiskFilter = false;

    const startInput = document.getElementById('vulnStartDate');
    const endInput = document.getElementById('vulnEndDate');
    if (startInput) startInput.value = '';
    if (endInput) endInput.value = '';
    rpSyncFromInputs('scanHistory');

    switchView('vulnerabilities');

    const domainSearchInput = document.getElementById('vulnDomainSearch');
    if (domainSearchInput) {
        domainSearchInput.value = domainName;
        domainSearchInput.dispatchEvent(new Event('input', { bubbles: true }));
        applyVulnFilters();
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
};

window.filterHistoryFromMonitoredDomain = function (domainName, event) {
    if (event) event.stopPropagation();
    
    switchView('vulnerabilities');

    const domainSearchInput = document.getElementById('vulnDomainSearch');
    if (domainSearchInput) {
        domainSearchInput.value = domainName;
        domainSearchInput.dispatchEvent(new Event('input', { bubbles: true }));
        applyVulnFilters();
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
};

// Function helper untuk membuka modal dari index
function openScanModalIndex(index) {
    const scan = allVulns[index];
    if (scan) {
        openScanModal(scan);
    }
}

function openScanModalByScanId(scanId) {
    if (!scanId) return false;
    const scan = (typeof allVulns !== 'undefined' && Array.isArray(allVulns))
        ? allVulns.find(v => String(v.id) === String(scanId))
        : null;
    if (scan) {
        openScanModal(scan);
        return true;
    }
    fetch(`${API_BASE}/api/scan-history/${scanId}`)
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success' && data.data) {
                openScanModal(data.data);
            } else {
                showToast('Error', 'Detail laporan scan tidak ditemukan.', '');
            }
        })
        .catch(() => {
            showToast('Error', 'Detail laporan scan tidak ditemukan.', '');
        });
    return true;
}

function openScanModalByDomainName(domainName) {
    if (!domainName) return false;
    const cleanDomain = String(domainName).toLowerCase().trim();
    if (typeof allVulns !== 'undefined' && Array.isArray(allVulns) && allVulns.length > 0) {
        const domainScans = allVulns.filter(s => {
            const dName = String(s.domains?.domain_name || s.domain_name || '').toLowerCase().trim();
            return dName === cleanDomain;
        });

        if (domainScans.length > 0) {
            domainScans.sort((a, b) => {
                const countA = Array.isArray(a.vulnerabilities) ? a.vulnerabilities.length : 0;
                const countB = Array.isArray(b.vulnerabilities) ? b.vulnerabilities.length : 0;
                if (countB !== countA) return countB - countA;
                return new Date(b.scan_date).getTime() - new Date(a.scan_date).getTime();
            });
            openScanModal(domainScans[0]);
            return true;
        }
    }
    return false;
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

window.openAddDomainFromScanModal = function (prefillDomain = '') {
    if (document.getElementById('newScanModalOverlay')?.classList.contains('active')) closeNewScan();

    if (domainIdInput) domainIdInput.value = '';
    if (domainNameInput) domainNameInput.value = prefillDomain || '';
    if (domainIpInput) domainIpInput.value = '';
    if (domainErrorMsg) domainErrorMsg.style.display = 'none';
    if (domainModalTitle) domainModalTitle.textContent = 'Tambah Domain Target';
    if (domainModalOverlay) domainModalOverlay.classList.add('active');
};

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
                const isPending = data.approval_status === 'pending';
                showToast(
                    isPending ? 'Permintaan Terkirim' : 'Sukses', 
                    data.message || 'Domain berhasil disimpan', 
                    isPending ? 'Pending' : 'Done'
                );
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
    const confirmed = await customConfirm({
        title: 'Hapus domain beserta riwayat scan-nya?',
        message: `${(allDomains || []).find(d => d.id === id)?.domain_name || 'Domain ini'} akan dihapus beserta seluruh riwayat scan-nya. Tindakan ini tidak bisa dibatalkan.`,
        confirmText: 'Hapus permanen',
        cancelText: 'Batal',
        variant: 'danger'
    });
    if (!confirmed) return;

    try {
        const resp = await fetch(`${API_BASE}/api/domains/${id}`, { method: 'DELETE' });
        const data = await resp.json();
        if (resp.ok) {
            showToast('Domain berhasil dihapus', 'success');
            loadDomains();
        } else {
            showToast(data.detail || 'Gagal menghapus domain', 'error');
        }
    } catch (err) {
        showToast('Koneksi error ke server', 'error');
    }
}

// =========================================================
// Export domain: hanya daftar target (domain_name, ip_address)
// =========================================================
function exContent(domains, format) {
    const rows = (domains || []).map(d => ({ domain_name: d.domain_name, ip_address: d.ip_address || '' }));
    if (format === 'json') return JSON.stringify(rows, null, 2) + '\n';
    const cell = v => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
    if (format === 'csv') {
        return ['domain_name,ip_address', ...rows.map(r => `${cell(r.domain_name)},${cell(r.ip_address)}`)].join('\n') + '\n';
    }
    return rows.map(r => (r.ip_address ? `${r.domain_name},${r.ip_address}` : r.domain_name)).join('\n') + '\n';
}

function exFileName(format, date = new Date()) {
    const p = n => String(n).padStart(2, '0');
    return `domains_${date.getFullYear()}-${p(date.getMonth() + 1)}-${p(date.getDate())}.${format}`;
}

function exDownload(text, name, mime) {
    const url = URL.createObjectURL(new Blob([text], { type: mime }));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

const EX_MIME = { csv: 'text/csv', txt: 'text/plain', json: 'application/json' };

function exSelectedDomains() {
    return (allDomains || []).filter(d => selectedDomainIds.has(d.id));
}

function openExportMenu() {
    const scope = document.getElementById('exportScope');
    const nSel = exSelectedDomains().length;
    if (scope) {
        scope.hidden = nSel === 0;
        document.getElementById('exCountAll').textContent = `${(allDomains || []).length} domain`;
        document.getElementById('exCountSelected').textContent = `${nSel} domain`;
        const pick = scope.querySelector(`input[name="exScope"][value="${nSel ? 'selected' : 'all'}"]`);
        if (pick) pick.checked = true;
    }
    toggleDropdown('exportDropdown');
    const dd = document.getElementById('exportDropdown');
    document.getElementById('ioMenuBtn')?.setAttribute('aria-expanded', String(!!dd?.classList.contains('open')));
}

window.exportDomains = function (format) {
    const scopeEl = document.getElementById('exportScope');
    const useSelected = scopeEl && !scopeEl.hidden && scopeEl.querySelector('input[name="exScope"]:checked')?.value === 'selected';
    const list = useSelected ? exSelectedDomains() : (allDomains || []);
    if (!list.length) {
        showToast('Info', 'Tidak ada domain untuk diekspor', '');
        return;
    }
    const fmt = EX_MIME[format] ? format : 'csv';
    const name = exFileName(fmt);
    exDownload(exContent(list, fmt), name, EX_MIME[fmt]);
    showToast('Export selesai', `${list.length} domain disimpan ke ${name}`, '');
};

document.querySelectorAll('[data-ex-format]').forEach(btn => {
    btn.addEventListener('click', () => {
        exportDomains(btn.dataset.exFormat);
        closeDropdown('exportDropdown');
    });
});

// =========================================================
// Import domain: baca file / teks, pratinjau, lalu simpan
// =========================================================
const IM_IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

// Sama dengan db_manager.normalize_domain_name()
function imNormalize(value) {
    let name = String(value == null ? '' : value).trim().toLowerCase();
    name = name.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
    if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(name)) return name;
    name = name.split(/[/?#]/)[0];
    name = name.split('@').pop();
    if (!name.startsWith('[')) name = name.split(':')[0];
    name = name.trim().replace(/\.+$/, '');
    while (name.startsWith('www.')) name = name.slice(4);
    return name;
}

function imIsValidTarget(name) {
    const s = String(name || '');
    if (!s) return false;
    if (IM_IPV4.test(s)) return true;
    const cidr = s.match(/^(.+)\/(\d{1,2})$/);
    if (cidr) return IM_IPV4.test(cidr[1]) && Number(cidr[2]) <= 32;
    if (s.length > 253 || !s.includes('.')) return false;
    const labels = s.split('.');
    if (!/^[a-z]{2,63}$/.test(labels[labels.length - 1])) return false;
    return labels.every(l => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l));
}

function imSplitLine(line) {
    const out = [];
    let cur = '';
    let quoted = false;
    for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (quoted) {
            if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
            else if (ch === '"') quoted = false;
            else cur += ch;
        } else if (ch === '"') quoted = true;
        else if (ch === ',' || ch === ';' || ch === '\t') { out.push(cur.trim()); cur = ''; }
        else cur += ch;
    }
    out.push(cur.trim());
    if (out.length === 1) {
        // "domain 1.2.3.4": spasi sebagai pemisah hanya bila bagian kedua berupa IP
        const parts = out[0].split(/\s+/);
        if (parts.length === 2 && IM_IPV4.test(parts[1])) return parts;
    }
    return out;
}

function imParse(text, filename = '') {
    const src = String(text || '').replace(/^﻿/, '');
    const trimmed = src.trim();
    const looksJson = /\.json$/i.test(filename) || /^[[{]/.test(trimmed);
    if (looksJson && trimmed) {
        let data;
        try {
            data = JSON.parse(trimmed);
        } catch (e) {
            throw new Error('File JSON tidak bisa dibaca. Periksa tanda kurung dan koma, atau simpan sebagai CSV.');
        }
        if (!Array.isArray(data)) data = Array.isArray(data.domains) ? data.domains : [data];
        return data.map((d, i) => {
            if (typeof d === 'string') return { line: i + 1, raw: d.trim(), ip: '' };
            const o = d || {};
            return { line: i + 1, raw: String(o.domain_name || o.domain || o.name || '').trim(), ip: String(o.ip_address || o.ip || '').trim() };
        }).filter(r => r.raw || r.ip);
    }
    const rows = [];
    src.split(/\r?\n/).forEach((line, i) => {
        const t = line.trim();
        if (!t || t.startsWith('#')) return;
        const cells = imSplitLine(t);
        if (!rows.length && /^(domain|domain_name|nama domain|host)$/i.test(cells[0])) return;
        rows.push({ line: i + 1, raw: cells[0] || '', ip: cells[1] || '' });
    });
    return rows;
}

function imClassify(rows, existing) {
    const known = new Map((existing || []).map(d => [String(d.domain_name || '').toLowerCase(), d]));
    const seen = new Map();
    return rows.map(r => {
        const domain = imNormalize(r.raw);
        const ip = String(r.ip || '').trim();
        const item = { line: r.line, raw: r.raw, domain, ip, status: 'new', note: '' };
        if (!imIsValidTarget(domain)) {
            item.status = 'invalid';
            item.domain = r.raw;
            item.note = 'bukan nama domain';
        } else if (ip && !IM_IPV4.test(ip)) {
            item.status = 'invalid';
            item.note = 'IP tidak valid';
        } else if (known.has(domain)) {
            item.status = 'exists';
            if (known.get(domain).approval_status === 'pending') item.note = 'masih menunggu persetujuan';
        } else if (seen.has(domain)) {
            item.status = 'dup';
            item.note = `sama dengan baris ${seen.get(domain)}`;
        } else {
            seen.set(domain, r.line);
            if (domain !== String(r.raw).trim()) item.note = `dirapikan dari ${r.raw}`;
        }
        return item;
    });
}

let imRows = [];
let imSourceName = '';
let imBusy = false;

function imShowStep(step) {
    ['Pick', 'Preview', 'Done'].forEach(s => {
        const el = document.getElementById('imStep' + s);
        if (el) el.hidden = s !== step;
    });
}

function imIsAdminOnly() { return !currentUser || currentUser.role !== 'superadmin'; }

function openImportModal() {
    imRows = [];
    imSourceName = '';
    imBusy = false;
    const paste = document.getElementById('imPaste');
    if (paste) paste.value = '';
    const file = document.getElementById('imFile');
    if (file) file.value = '';
    imPickError('');
    document.getElementById('imPreviewBtn').disabled = true;
    document.getElementById('imTitle').textContent = 'Import domain';
    document.getElementById('imSubtitle').textContent = 'Tambahkan banyak domain sekaligus dari file atau teks.';
    imShowStep('Pick');
    const ov = document.getElementById('importModalOverlay');
    ov.classList.add('active');
    setTimeout(() => document.getElementById('imPaste')?.focus(), 50);
}

function closeImportModal() {
    if (imBusy) return;
    document.getElementById('importModalOverlay')?.classList.remove('active');
}

function imPickError(msg) {
    const el = document.getElementById('imPickError');
    if (!el) return;
    el.hidden = !msg;
    el.textContent = msg || '';
}

function imHandleText(text, sourceName) {
    let rows;
    try {
        rows = imParse(text, sourceName);
    } catch (e) {
        imShowStep('Pick');
        imPickError(e.message);
        return;
    }
    if (!rows.length) {
        imShowStep('Pick');
        imPickError('Tidak ada domain yang terbaca dari isi tersebut.');
        return;
    }
    imPickError('');
    imSourceName = sourceName;
    imRows = imClassify(rows, allDomains);
    imRenderPreview();
    imShowStep('Preview');
}

const IM_STATUS = {
    new: ['Baru', 'is-new'],
    exists: ['Sudah terdaftar, dilewati', ''],
    dup: ['Duplikat, dilewati', ''],
    invalid: ['Tidak valid', 'is-bad']
};

function imRenderPreview() {
    const count = k => imRows.filter(r => r.status === k).length;
    const nNew = count('new');
    document.getElementById('imSource').textContent = `${imSourceName} · ${imRows.length} baris`;
    ['new', 'exists', 'invalid', 'dup'].forEach(k => {
        const el = document.querySelector(`[data-im-count="${k}"]`);
        if (el) el.textContent = String(count(k));
    });
    const tbody = document.querySelector('#imTable tbody');
    tbody.innerHTML = imRows.map(r => {
        const [label, cls] = IM_STATUS[r.status];
        return `<tr class="${r.status === 'invalid' ? 'is-bad' : ''}">
            <td class="im-col-line">${r.line}</td>
            <td class="im-domain">${escapeHtml(r.domain || r.raw || '-')}</td>
            <td class="im-col-ip">${escapeHtml(r.ip || '-')}</td>
            <td><span class="im-pill ${cls}">${label}</span>${r.note ? `<small>${escapeHtml(r.note)}</small>` : ''}</td>
        </tr>`;
    }).join('');
    const note = document.getElementById('imRoleNote');
    note.hidden = !(imIsAdminOnly() && nNew > 0);
    note.textContent = `Anda login sebagai Admin. ${nNew} domain baru akan menunggu persetujuan Super Admin sebelum bisa di-scan.`;
    const btn = document.getElementById('imSubmit');
    btn.disabled = nNew === 0;
    btn.textContent = nNew ? `Tambahkan ${nNew} domain` : 'Tidak ada domain baru';
    document.getElementById('imProgress').textContent = '';
}

async function imSubmit() {
    const todo = imRows.filter(r => r.status === 'new');
    if (!todo.length || imBusy) return;
    imBusy = true;
    const btn = document.getElementById('imSubmit');
    btn.disabled = true;
    const progress = document.getElementById('imProgress');
    let added = 0;
    let pending = 0;
    const failed = [];
    for (let i = 0; i < todo.length; i++) {
        const r = todo[i];
        btn.textContent = `Menambahkan ${i + 1} dari ${todo.length}...`;
        try {
            const resp = await fetch(`${API_BASE}/api/domains`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain_name: r.domain, ip_address: r.ip })
            });
            const data = await resp.json().catch(() => ({}));
            if (!resp.ok) throw new Error(data.detail || `Gagal (HTTP ${resp.status})`);
            if (data.approval_status === 'pending') pending++; else added++;
        } catch (e) {
            failed.push(`${r.domain}: ${e.message}`);
        }
    }
    imBusy = false;
    progress.textContent = '';
    imRenderDone(added, pending, failed);
    imShowStep('Done');
    if (typeof loadDomains === 'function') loadDomains(true);
}

function imRenderDone(added, pending, failedSubmit) {
    const exists = imRows.filter(r => r.status === 'exists').length;
    const dup = imRows.filter(r => r.status === 'dup').length;
    const invalid = imRows.filter(r => r.status === 'invalid');
    const items = [];
    if (added) items.push(['ok', `${added} domain ditambahkan`]);
    if (pending) items.push(['ok', `${pending} domain dikirim untuk persetujuan Super Admin`]);
    if (exists + dup) {
        const parts = [];
        if (exists) parts.push(`${exists} sudah terdaftar`);
        if (dup) parts.push(`${dup} duplikat di file`);
        items.push(['skip', `${exists + dup} dilewati: ${parts.join(', ')}`]);
    }
    const fails = [
        ...invalid.map(r => `baris ${r.line} "${r.raw}" ${r.note}`),
        ...failedSubmit
    ];
    if (fails.length) items.push(['bad', `${fails.length} tidak diimpor`, fails]);
    const icon = {
        ok: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="m9 12 2 2 4-4"></path></svg>',
        skip: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="M8 12h8"></path></svg>',
        bad: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="m15 9-6 6"></path><path d="m9 9 6 6"></path></svg>'
    };
    document.getElementById('imSubtitle').textContent = imSourceName;
    document.getElementById('imTitle').textContent = 'Import selesai';
    document.getElementById('imDoneList').innerHTML = items.map(([k, text, list]) => `
        <li class="im-done-${k}">${icon[k]}<div><span>${escapeHtml(text)}</span>${list ? `<ul>${list.map(x => `<li>${escapeHtml(x)}</li>`).join('')}</ul>` : ''}</div></li>`).join('');
}

(function imBind() {
    const btn = document.getElementById('importDomainsBtn');
    // Item Import di menu "Import / Export": tutup menunya dulu, lalu buka modal impor
    if (btn) btn.addEventListener('click', () => {
        closeDropdown('exportDropdown');
        document.getElementById('ioMenuBtn')?.setAttribute('aria-expanded', 'false');
        openImportModal();
    });
    const io = document.getElementById('exportDropdown');
    if (io) io.addEventListener('keydown', e => {
        if (e.key === 'Escape' && io.classList.contains('open')) {
            e.stopPropagation();
            closeDropdown('exportDropdown');
            const menuBtn = document.getElementById('ioMenuBtn');
            menuBtn?.setAttribute('aria-expanded', 'false');
            menuBtn?.focus();
        }
    });
    const ov = document.getElementById('importModalOverlay');
    if (!ov) return;
    ov.addEventListener('click', e => { if (e.target === ov) closeImportModal(); });
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && ov.classList.contains('active')) closeImportModal();
    });
    const paste = document.getElementById('imPaste');
    paste.addEventListener('input', () => {
        document.getElementById('imPreviewBtn').disabled = !paste.value.trim();
        imPickError('');
    });
    document.getElementById('imPreviewBtn').addEventListener('click', () => {
        if (paste.value.trim()) imHandleText(paste.value, 'Teks yang ditempel');
    });
    const readFile = (file) => {
        if (!file) return;
        if (file.size > 2 * 1024 * 1024) { imPickError('File terlalu besar (maksimal 2 MB).'); return; }
        const reader = new FileReader();
        reader.onload = () => imHandleText(String(reader.result || ''), file.name);
        reader.onerror = () => imPickError('File tidak bisa dibaca.');
        reader.readAsText(file);
    };
    const fileInput = document.getElementById('imFile');
    fileInput.addEventListener('change', () => { readFile(fileInput.files[0]); fileInput.value = ''; });
    const drop = document.getElementById('imDrop');
    ['dragenter', 'dragover'].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.add('is-over'); }));
    ['dragleave', 'drop'].forEach(t => drop.addEventListener(t, () => drop.classList.remove('is-over')));
    drop.addEventListener('drop', e => { e.preventDefault(); readFile(e.dataTransfer && e.dataTransfer.files[0]); });
    document.getElementById('imTemplate').addEventListener('click', () => {
        exDownload('domain_name,ip_address\ncontoh.undip.ac.id,\n', 'template_import_domain.csv', 'text/csv');
    });
    document.getElementById('imChangeFile').addEventListener('click', () => { imPickError(''); imShowStep('Pick'); });
    document.getElementById('imSubmit').addEventListener('click', imSubmit);
    document.getElementById('imDoneBtn').addEventListener('click', () => { closeImportModal(); });
})();

async function loadDomains(preservePage = false, { onlyIfChanged = false } = {}) {
    try {
        const resp = await fetch(`${API_BASE}/api/domains`);
        const text = await resp.text();
        if (onlyIfChanged && text === lastDomainsText) return false;
        lastDomainsText = text;
        const data = JSON.parse(text);
        allDomains = data.data || [];

        // Update pending domain requests badge for Superadmin
        const pendingBtn = document.getElementById('pendingDomainRequestsBtn');
        const pendingLabel = document.getElementById('pendingDomainBadgeLabel');
        if (pendingBtn && pendingLabel) {
            const pendingList = allDomains.filter(d => d.approval_status === 'pending');
            if (currentUser && currentUser.role === 'superadmin' && pendingList.length > 0) {
                pendingLabel.textContent = `Persetujuan Domain (${pendingList.length})`;
                pendingBtn.style.display = 'inline-flex';
            } else {
                pendingBtn.style.display = 'none';
            }
        }

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

async function toggleDomainActive(domainId, event) {
    if (isSelectionModeActive) {
        if (event) {
            event.stopPropagation();
            event.preventDefault();
        }
        handleRowClick(domainId, event);
        return;
    }
    if (event) {
        event.stopPropagation();
        event.preventDefault();
    }

    const domain = allDomains.find(d => d.id === domainId);
    if (!domain) return;

    const newStatus = !domain.is_active;

    // Optimistic UI update
    domain.is_active = newStatus;
    renderInventoryList();

    try {
        const resp = await fetch(`${API_BASE}/api/domains/${domainId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                domain_name: domain.domain_name,
                ip_address: domain.ip_address,
                is_active: newStatus
            })
        });

        if (resp.ok) {
            showToast(
                'Overnight Scan',
                `${domain.domain_name} sekarang ${newStatus ? 'aktif' : 'nonaktif'} Overnight Scan.`,
                'success'
            );
        } else {
            // Revert on error
            domain.is_active = !newStatus;
            renderInventoryList();
            const data = await resp.json();
            showToast('Error', data.detail || 'Gagal mengubah status domain', '');
        }
    } catch (err) {
        console.error('Error toggling domain status:', err);
        domain.is_active = !newStatus;
        renderInventoryList();
        showToast('Error', 'Koneksi terputus dari server', '');
    }
}

let domainSortCol = 'last_scan';
let domainSortDesc = true;

function sortDomainInventory(col) {
    if (domainSortCol === col) {
        domainSortDesc = !domainSortDesc;
    } else {
        domainSortCol = col;
        domainSortDesc = (col === 'last_scan');
    }
    renderInventoryList();
}

function updateDomainSortIcons() {
    const activeMapping = { 'domain': 0, 'status': 2, 'last_scan': 3 };
    const ths = document.querySelectorAll('#inventoryTableHeaders th');
    ths.forEach(th => {
        const icon = th.querySelector('.sort-icon');
        if (icon) icon.innerHTML = '';
    });

    const activeIdx = activeMapping[domainSortCol];
    if (activeIdx !== undefined && ths[activeIdx]) {
        const icon = ths[activeIdx].querySelector('.sort-icon');
        if (icon) icon.innerHTML = domainSortDesc ? ' ↓' : ' ↑';
    }
}

// =========================================================
// DOMAIN INVENTORY (desain baru)
// - Kotak ringkasan = filter cepat. Kolom Overnight Scan = saklar (is_active).
// - Checkbox selalu tampil, bar aksi massal muncul saat ada yang dipilih.
// - Scan terakhir pakai kotak severity dari scan terakhir domain (allVulns), fallback ke badge risk.
// - Aksi per baris di menu ⋯. Hapus = permanen, riwayat scan ikut terhapus (ON DELETE CASCADE).
// =========================================================
const INV_ICON = {
    check: '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"></polyline></svg>',
    minus: '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" aria-hidden="true"><line x1="5" y1="12" x2="19" y2="12"></line></svg>',
    copy: '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>',
    more: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="5" cy="12" r="1.8"></circle><circle cx="12" cy="12" r="1.8"></circle><circle cx="19" cy="12" r="1.8"></circle></svg>'
};
let invMenuEl = null;
let invLatest = {};

// Tingkat risiko = severity tertinggi di scan terakhir (sama dengan kotak severity di tabel).
// Bila riwayat scan domain belum termuat, pakai last_scan_status dari tabel domain.
const INV_SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
function invLevel(d) {
    const l = invLatest[schedNormTarget(d.domain_name)];
    if (l) {
        const sevs = new Set((l.scan.vulnerabilities || []).map(v => String(v.severity || '').toUpperCase()));
        return INV_SEV_ORDER.find(x => sevs.has(x)) || 'SAFE';
    }
    return d.last_scan_date && d.last_scan_status ? String(d.last_scan_status).toUpperCase() : null;
}

function invIsHigh(d) {
    return ['HIGH', 'CRITICAL'].includes(invLevel(d));
}

function invNeverScanned(d) {
    return invLevel(d) === null;
}

// Scan terakhir per domain dari riwayat (untuk kotak severity)
function invLatestScans() {
    const map = {};
    (allVulns || []).forEach(s => {
        const name = schedNormTarget(s.domains?.domain_name || '');
        if (!name) return;
        const t = new Date(s.scan_date).getTime();
        if (!map[name] || t > map[name].t) map[name] = { t, scan: s };
    });
    return map;
}

// Preset filter (dipakai "Hapus filter" dan tautan dari System Settings)
function invApplyTile(key) {
    const st = document.getElementById('domainStatusFilter');
    const sc = document.getElementById('domainLastScanFilter');
    if (st) st.value = key === 'active' ? 'ACTIVE' : 'ALL';
    if (sc) sc.value = key === 'never' ? 'NOT_SCANNED' : key === 'high' ? 'HIGH' : 'ALL';
    domainCurrentPage = 1;
    renderInventoryList();
}

// =========================================================
// Dropdown filter bernama (fdd): tombol menampilkan nama filter,
// atau "Nama: nilai" bila ada pilihan. Nilainya disimpan di <select>
// tersembunyi supaya kode filter yang lama tetap dipakai.
// =========================================================
function fddLabel(name, value, optLabel) {
    return value === 'ALL' ? name : `${name}: ${optLabel}`;
}

function invMatchOvernight(d, v) {
    if (v === 'ACTIVE') return !!d.is_active;
    if (v === 'INACTIVE') return !d.is_active;
    return true;
}

function invMatchRisk(d, v) {
    if (v === 'SCANNED') return !invNeverScanned(d);
    if (v === 'NOT_SCANNED') return invNeverScanned(d);
    if (v === 'HIGH') return invIsHigh(d);
    if (v === 'MEDIUM' || v === 'LOW' || v === 'INFO' || v === 'SAFE') return invLevel(d) === v;
    return true;
}

const INV_FDD = {
    invOvernightDd: {
        select: 'domainStatusFilter', name: 'Overnight Scan', match: invMatchOvernight, showChoice: true,
        options: [['ALL', 'Semua domain'], ['ACTIVE', 'Overnight aktif'], ['INACTIVE', 'Overnight nonaktif']]
    },
    invRiskDd: {
        select: 'domainLastScanFilter', name: 'Risiko', match: invMatchRisk,
        options: [['ALL', 'Semua risiko'], ['HIGH', 'High / Critical'], ['MEDIUM', 'Medium'], ['LOW', 'Low'], ['INFO', 'Info'], ['SAFE', 'Safe (tanpa temuan)'], ['NOT_SCANNED', 'Belum pernah di-scan']],
        extra: { SCANNED: 'Sudah pernah di-scan' }
    }
};
const FDD_CHEVRON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"></polyline></svg>';
const FDD_CHECK = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"></polyline></svg>';

function fddRender(id, cfg, domains) {
    const box = document.getElementById(id);
    const sel = document.getElementById(cfg.select);
    if (!box || !sel) return;
    const value = sel.value || 'ALL';
    const current = cfg.options.find(o => o[0] === value);
    const optLabel = current ? current[1] : ((cfg.extra && cfg.extra[value]) || value);
    const open = box.classList.contains('open');
    box.innerHTML = `
        <button type="button" class="fdd-btn${value !== 'ALL' ? ' is-active' : ''}" aria-haspopup="listbox" aria-expanded="${open}" aria-label="${escapeHtml(`${cfg.name}: ${optLabel}`)}">
            <span class="fdd-label">${escapeHtml(cfg.showChoice ? optLabel : fddLabel(cfg.name, value, optLabel))}</span>${FDD_CHEVRON}
        </button>
        <div class="multi-select-panel fdd-panel" role="listbox" aria-label="${escapeHtml(cfg.name)}">
            ${cfg.options.map(([v, label]) => `
            <button type="button" class="fdd-opt" role="option" aria-selected="${v === value}" data-value="${v}">
                <span class="fdd-opt-label">${escapeHtml(label)}</span><span class="fdd-opt-n">${cfg.count ? cfg.count(v) : domains.filter(d => cfg.match(d, v)).length}</span>${v === value ? FDD_CHECK : ''}
            </button>`).join('')}
        </div>`;
    if (box.dataset.fddBound) return;
    box.dataset.fddBound = '1';
    box.addEventListener('click', (e) => {
        const opt = e.target.closest('.fdd-opt');
        if (opt) {
            sel.value = opt.dataset.value;
            box.classList.remove('open');
            // Halaman lain (Scan History) memberi aksinya sendiri; bawaan untuk Domain Inventory
            if (cfg.onChange) {
                cfg.onChange();
            } else {
                domainCurrentPage = 1;
                renderInventoryList();
            }
            box.querySelector('.fdd-btn')?.focus();
            return;
        }
        if (e.target.closest('.fdd-btn')) {
            document.querySelectorAll('.fdd.open').forEach(o => { if (o !== box) fddClose(o); });
            box.classList.toggle('open');
            box.querySelector('.fdd-btn').setAttribute('aria-expanded', box.classList.contains('open'));
            fddKeepInView(box);
        }
    });
    box.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && box.classList.contains('open')) {
            e.stopPropagation();
            fddClose(box);
            box.querySelector('.fdd-btn')?.focus();
        }
    });
}

// Geser daftar pilihan ke kiri bila melewati tepi kanan layar (layar sempit)
function fddKeepInView(box) {
    const panel = box.querySelector('.fdd-panel');
    if (!panel || !box.classList.contains('open')) return;
    panel.style.left = '';
    const r = panel.getBoundingClientRect();
    const over = r.right - (window.innerWidth - 16);
    if (over > 0) panel.style.left = `${-Math.min(over, r.left - 16)}px`;
}

function fddClose(box) {
    box.classList.remove('open');
    box.querySelector('.fdd-btn')?.setAttribute('aria-expanded', 'false');
}

document.addEventListener('click', (e) => {
    if (e.target.closest && e.target.closest('.fdd')) return;
    document.querySelectorAll('.fdd.open').forEach(fddClose);
});

// Jumlah filter aktif di Domain Inventory (untuk "Reset (n)")
function invActiveFilterCount() {
    let n = 0;
    if ((document.getElementById('domainSearchInput')?.value || '').trim()) n++;
    if ((document.getElementById('domainStatusFilter')?.value || 'ALL') !== 'ALL') n++;
    if ((document.getElementById('domainLastScanFilter')?.value || 'ALL') !== 'ALL') n++;
    return n;
}

function invRenderFilters(domains) {
    Object.entries(INV_FDD).forEach(([id, cfg]) => fddRender(id, cfg, domains));
    fltResetLabel(document.getElementById('invClearFilters'), invActiveFilterCount());
}

function invRenderSubtitle(domains) {
    const el = document.getElementById('invSubtitle');
    if (!el) return;
    const pending = domains.filter(d => d.approval_status === 'pending').length;
    const active = domains.filter(d => d.approval_status !== 'pending' && d.is_active === true).length;
    if (!domains.length) { el.textContent = 'Belum ada domain terdaftar.'; return; }
    const parts = [`${domains.length} domain terdaftar`];
    if (active) parts.push(`${active} ikut Overnight Scan`);
    if (pending) parts.push(`${pending} menunggu persetujuan`);
    el.textContent = parts.join(', ') + '.';
}

function invRenderApproval(domains) {
    const el = document.getElementById('inventoryApprovalBanner');
    if (!el) return;
    const pending = domains.filter(d => d.approval_status === 'pending');
    const show = currentUser && currentUser.role === 'superadmin' && pending.length > 0;
    el.hidden = !show;
    el.innerHTML = show ? `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 22h14"></path><path d="M5 2h14"></path><path d="M17 22v-4.172a2 2 0 0 0-.586-1.414L12 12l-4.414 4.414A2 2 0 0 0 7 17.828V22"></path><path d="M7 2v4.172a2 2 0 0 0 .586 1.414L12 12l4.414-4.414A2 2 0 0 0 17 6.172V2"></path></svg>
        <div class="inv-approval-text"><strong>${pending.length} domain menunggu persetujuan</strong><span>Diajukan oleh admin, perlu disetujui Superadmin sebelum bisa di-scan.</span></div>
        <button type="button" class="sp-btn" onclick="openPendingDomainsModal()">Tinjau</button>` : '';
}

function invRenderBulk() {
    const el = document.getElementById('inventoryBulkBar');
    if (!el) return;
    const n = selectedDomainIds.size;
    el.hidden = n === 0;
    el.closest('tr')?.classList.toggle('is-selecting', n > 0);
    el.innerHTML = n ? `
        <strong class="inv-bulk-count">${n} domain dipilih</strong>
        <button type="button" class="sp-btn" onclick="invScanSelected()">Scan sekarang</button>
        <button type="button" class="sp-btn" onclick="directBulkToggleActive(true)">Aktifkan Overnight</button>
        <button type="button" class="sp-btn" onclick="directBulkToggleActive(false)">Nonaktifkan Overnight</button>
        <button type="button" class="sp-btn sp-btn-danger" onclick="directBulkDeleteDomains()">Hapus</button>
        <button type="button" class="sh-link inv-bulk-clear" onclick="clearDirectSelection()">Batal pilih</button>` : '';
    invSizeBulkBar();
}

function invSizeBulkBar() {
    const el = document.getElementById('inventoryBulkBar');
    if (!el || el.hidden) return;
    const th = el.parentElement;
    const table = th && th.closest('table');
    if (!table) return;
    // Sampai tepi kanan tabel, tetapi tidak melewati kartu atau layar (tabel bisa lebih lebar dari layar HP)
    const card = th.closest('.card');
    const right = Math.min(table.getBoundingClientRect().right, card ? card.getBoundingClientRect().right : Infinity, window.innerWidth);
    el.style.width = `${Math.max(0, right - th.getBoundingClientRect().left)}px`;
}
window.addEventListener('resize', invSizeBulkBar);

function invRenderCheckAll(pageItems) {
    const wrap = document.getElementById('inventoryCheckAllWrap');
    if (!wrap) return;
    const ids = pageItems.filter(d => d.approval_status !== 'pending').map(d => d.id);
    const sel = ids.filter(id => selectedDomainIds.has(id)).length;
    const state = sel === 0 ? 'false' : sel === ids.length ? 'true' : 'mixed';
    wrap.innerHTML = `<button type="button" class="inv-check${state !== 'false' ? ' is-on' : ''}" role="checkbox" aria-checked="${state}" aria-label="Pilih semua domain di halaman ini" data-inv-all ${ids.length ? '' : 'disabled'}>${state === 'mixed' ? INV_ICON.minus : (state === 'true' ? INV_ICON.check : '')}</button>`;
    wrap.onclick = (e) => {
        if (!e.target.closest('[data-inv-all]')) return;
        if (state === 'true') ids.forEach(id => selectedDomainIds.delete(id));
        else ids.forEach(id => selectedDomainIds.add(id));
        renderInventoryList();
    };
}

function invScanCell(d, latest) {
    const l = latest[schedNormTarget(d.domain_name)];
    if (!l && invNeverScanned(d)) {
        return `<div class="inv-scan-none"><span>Belum pernah di-scan</span><button type="button" class="sp-btn inv-btn-xs" data-inv-scan="${d.id}">Scan</button></div>`;
    }
    const date = l ? new Date(l.scan.scan_date) : new Date(d.last_scan_date);
    const type = l ? shScanType(l.scan) : (/network/i.test(d.last_scan_type || '') ? 'Network' : (d.last_scan_type ? 'Website' : ''));
    const meta = `${isNaN(date) ? '-' : spDate(date)}${type && type !== '-' ? ` · ${type}` : ''}`;
    const body = l ? renderSevSummary(l.scan.vulnerabilities) : `<span class="badge badge-${getSeverityClass(d.last_scan_status)}">${escapeHtml(String(d.last_scan_status).toUpperCase())}</span>`;
    return `<button type="button" class="inv-scan" data-inv-report="${d.id}" title="Buka laporan scan terakhir ${escapeHtml(d.domain_name)}">${body}<span class="inv-scan-meta">${meta}</span></button>`;
}

function invRow(d, latest) {
    const name = escapeHtml(d.domain_name);
    const pending = d.approval_status === 'pending';
    const selected = selectedDomainIds.has(d.id);
    const ip = d.ip_address
        ? `<button type="button" class="inv-ip" data-inv-copy="${escapeHtml(d.ip_address)}" title="Salin IP ${escapeHtml(d.ip_address)}">${escapeHtml(d.ip_address)}${INV_ICON.copy}</button>`
        : '<span class="inv-ip is-empty">IP belum diisi</span>';
    let night;
    if (pending) {
        night = currentUser && currentUser.role === 'superadmin'
            ? `<div class="inv-approve"><button type="button" class="sp-btn" onclick="triggerApproveDomain(${d.id}, '${name}')">Setujui</button><button type="button" class="sp-btn sp-btn-danger" onclick="triggerRejectDomain(${d.id}, '${name}')">Tolak</button></div>`
            : '<span class="sp-status is-pending"><span class="sp-dot"></span>Menunggu persetujuan</span>';
    } else {
        night = `<button type="button" class="inv-switch${d.is_active ? ' is-on' : ''}" role="switch" aria-checked="${!!d.is_active}" data-inv-toggle="${d.id}" aria-label="Overnight Scan ${name}"><span class="inv-switch-track"><span class="inv-switch-knob"></span></span><span class="inv-switch-label">${d.is_active ? 'Aktif' : 'Nonaktif'}</span></button>`;
    }
    return `<tr class="inv-row${selected ? ' is-selected' : ''}${pending ? ' is-pending' : ''}">
        <td class="inv-col-check">${pending ? '' : `<button type="button" class="inv-check${selected ? ' is-on' : ''}" role="checkbox" aria-checked="${selected}" aria-label="Pilih ${name}" data-inv-select="${d.id}">${selected ? INV_ICON.check : ''}</button>`}</td>
        <td><div class="inv-domain"><strong title="${name}">${name}</strong>${ip}</div></td>
        <td class="inv-col-scan">${pending ? '<span class="sp-muted">Belum bisa di-scan sebelum disetujui</span>' : invScanCell(d, latest)}</td>
        <td class="inv-col-night">${night}</td>
        <td class="inv-col-more">${pending ? '' : `<button type="button" class="inv-more" data-inv-menu="${d.id}" aria-haspopup="menu" aria-label="Aksi untuk ${name}">${INV_ICON.more}</button>`}</td>
    </tr>`;
}

function invCloseMenu() {
    if (invMenuEl) { invMenuEl.remove(); invMenuEl = null; }
    document.querySelectorAll('.inv-more.is-open').forEach(b => { b.classList.remove('is-open'); b.setAttribute('aria-expanded', 'false'); });
}

function invOpenMenu(btn, id) {
    const wasOpen = btn.classList.contains('is-open');
    invCloseMenu();
    if (wasOpen) return;
    const d = (allDomains || []).find(x => x.id === id);
    if (!d) return;
    btn.classList.add('is-open');
    btn.setAttribute('aria-expanded', 'true');
    const menu = document.createElement('div');
    menu.className = 'inv-menu';
    menu.setAttribute('role', 'menu');
    menu.innerHTML = `
        <button type="button" role="menuitem" data-act="scan">Scan sekarang</button>
        <button type="button" role="menuitem" data-act="history">Lihat riwayat scan</button>
        <button type="button" role="menuitem" data-act="edit">Edit domain</button>
        <span class="inv-menu-sep" role="separator"></span>
        <button type="button" role="menuitem" data-act="delete" class="is-danger">Hapus domain</button>`;
    document.body.appendChild(menu);
    const r = btn.getBoundingClientRect();
    const w = menu.offsetWidth || 200;
    const h = menu.offsetHeight || 170;
    const top = r.bottom + 6 + h > window.innerHeight ? r.top - h - 6 : r.bottom + 6;
    menu.style.top = `${Math.max(8, top)}px`;
    menu.style.left = `${Math.max(8, r.right - w)}px`;
    invMenuEl = menu;
    menu.addEventListener('click', (e) => {
        e.stopPropagation();
        const act = e.target.closest('[data-act]')?.dataset.act;
        if (!act) return;
        invCloseMenu();
        if (act === 'scan') invScanDomains([d.domain_name]);
        if (act === 'history') navigateToFilteredHistory(d.domain_name);
        if (act === 'edit') openEditDomainModal(d);
        if (act === 'delete') deleteDomain(d.id);
    });
    menu.addEventListener('keydown', (e) => {
        const items = [...menu.querySelectorAll('[data-act]')];
        const i = items.indexOf(document.activeElement);
        if (e.key === 'ArrowDown') { e.preventDefault(); items[(i + 1) % items.length].focus(); }
        if (e.key === 'ArrowUp') { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
        if (e.key === 'Escape') { invCloseMenu(); btn.focus(); }
    });
    menu.querySelector('[data-act]')?.focus();
}

document.addEventListener('click', (e) => {
    if (invMenuEl && !invMenuEl.contains(e.target) && !e.target.closest('[data-inv-menu]')) invCloseMenu();
});
window.addEventListener('resize', invCloseMenu);

// Scan beberapa domain: pilih Website / Network lalu target sudah tercentang
function invScanDomains(names) {
    openNewScan({ targets: names });
}

window.invScanSelected = function () {
    const names = (allDomains || []).filter(d => selectedDomainIds.has(d.id)).map(d => d.domain_name);
    if (!names.length) return;
    invScanDomains(names);
};

function invBindTable(tbody) {
    if (tbody.dataset.invBound) return;
    tbody.dataset.invBound = '1';
    tbody.addEventListener('click', (e) => {
        const t = e.target;
        const sel = t.closest('[data-inv-select]');
        if (sel) {
            const id = parseInt(sel.dataset.invSelect, 10);
            selectedDomainIds.has(id) ? selectedDomainIds.delete(id) : selectedDomainIds.add(id);
            renderInventoryList();
            document.querySelector(`[data-inv-select="${id}"]`)?.focus();
            return;
        }
        const tog = t.closest('[data-inv-toggle]');
        if (tog) {
            const id = parseInt(tog.dataset.invToggle, 10);
            toggleDomainActive(id, e).then(() => document.querySelector(`[data-inv-toggle="${id}"]`)?.focus());
            return;
        }
        const copy = t.closest('[data-inv-copy]');
        if (copy) { e.stopPropagation(); copyToClipboard(copy.dataset.invCopy, e, 'IP Address'); return; }
        const menu = t.closest('[data-inv-menu]');
        if (menu) { e.stopPropagation(); invOpenMenu(menu, parseInt(menu.dataset.invMenu, 10)); return; }
        const scan = t.closest('[data-inv-scan]');
        if (scan) {
            const d = (allDomains || []).find(x => x.id === parseInt(scan.dataset.invScan, 10));
            if (d) invScanDomains([d.domain_name]);
            return;
        }
        const rep = t.closest('[data-inv-report]');
        if (rep) {
            const d = (allDomains || []).find(x => x.id === parseInt(rep.dataset.invReport, 10));
            if (d) openLastScanModal(d.domain_name, e, d.last_scan_id || null);
        }
    });
}

function renderInventoryList() {
    const tbody = document.getElementById('inventoryTableBody');
    const paginationControls = document.getElementById('domainPaginationControls');
    if (!tbody) return;
    // Mode seleksi lama tidak dipakai lagi: checkbox selalu ada, saklar selalu mengubah Overnight Scan
    isSelectionModeActive = false;
    invBindTable(tbody);
    invCloseMenu();

    if (typeof updateSecurityPostureScore === 'function') updateSecurityPostureScore();

    const domains = allDomains || [];
    invLatest = invLatestScans();
    invRenderSubtitle(domains);
    invRenderFilters(domains);
    invRenderApproval(domains);
    // Buang pilihan untuk domain yang sudah tidak ada
    [...selectedDomainIds].forEach(id => { if (!domains.some(d => d.id === id)) selectedDomainIds.delete(id); });
    invRenderBulk();

    const message = (title, sub, btns) => {
        tbody.innerHTML = `<tr class="sp-message-row"><td colspan="5"><div class="sp-message"><strong>${title}</strong>${sub ? `<span>${sub}</span>` : ''}${btns ? `<div class="inv-msg-btns">${btns}</div>` : ''}</div></td></tr>`;
        if (paginationControls) paginationControls.style.display = 'none';
        invRenderCheckAll([]);
    };

    if (!domains.length) {
        message('Belum ada domain', 'Tambahkan domain target satu per satu atau lewat Import.', `<button type="button" class="sp-btn sp-btn-primary" onclick="document.getElementById('addDomainBtn').click()">Add Domain</button>`);
        return;
    }

    // Pencarian (mendukung "kata persis" dalam tanda kutip)
    const rawSearchVal = document.getElementById('domainSearchInput')?.value || '';
    let list = domains;
    if (rawSearchVal.trim()) {
        const terms = rawSearchVal.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
        list = list.filter(d => {
            const n = (d.domain_name || '').toLowerCase();
            const ip = (d.ip_address || '').toLowerCase();
            return terms.some(term => {
                if (term.startsWith('"') && term.endsWith('"') && term.length >= 2) {
                    const ex = term.slice(1, -1).toLowerCase();
                    return n === ex || ip === ex;
                }
                const lt = term.toLowerCase();
                return n.includes(lt) || ip.includes(lt);
            });
        });
    }
    const st = document.getElementById('domainStatusFilter')?.value || 'ALL';
    list = list.filter(d => invMatchOvernight(d, st));
    const sc = document.getElementById('domainLastScanFilter')?.value || 'ALL';
    list = list.filter(d => invMatchRisk(d, sc));

    // Urutan: menunggu persetujuan dulu, lalu risiko tertinggi, lalu scan terbaru
    const W = { CRITICAL: 7, HIGH: 6, MEDIUM: 5, LOW: 4, INFO: 3, SAFE: 2 };
    const weight = (d) => W[invLevel(d)] || 1;
    const lastTime = (d) => invLatest[schedNormTarget(d.domain_name)]?.t || (d.last_scan_date ? new Date(d.last_scan_date).getTime() : 0);
    list = list.slice().sort((a, b) => ((b.approval_status === 'pending') - (a.approval_status === 'pending'))
        || (weight(b) - weight(a))
        || (lastTime(b) - lastTime(a))
        || (a.domain_name || '').localeCompare(b.domain_name || ''));
    filteredDomains = list;

    if (!list.length) {
        message('Tidak ada domain yang cocok', 'Coba kata kunci lain atau hapus filter. Domain yang belum terdaftar bisa ditambahkan.',
            `<button type="button" class="sp-btn" onclick="invResetFilters()">Hapus filter</button><button type="button" class="sp-btn sp-btn-primary" onclick="document.getElementById('addDomainBtn').click()">Add Domain</button>`);
        return;
    }

    if (paginationControls) paginationControls.style.display = 'flex';
    const total = list.length;
    const totalPages = Math.ceil(total / domainRowsPerPage) || 1;
    if (domainCurrentPage > totalPages) domainCurrentPage = totalPages;
    if (domainCurrentPage < 1) domainCurrentPage = 1;
    const start = (domainCurrentPage - 1) * domainRowsPerPage;
    const end = Math.min(start + domainRowsPerPage, total);
    const pageItems = list.slice(start, end);
    tbody.innerHTML = pageItems.map(d => invRow(d, invLatest)).join('');
    invRenderCheckAll(pageItems);

    const range = document.getElementById('domainRangeInfo');
    if (range) range.textContent = `Menampilkan ${start + 1}-${end} dari ${total} domain`;
    const pageInput = document.getElementById('domainPageInput');
    if (pageInput) pageInput.value = domainCurrentPage;
    const tp = document.getElementById('domainTotalPages');
    if (tp) tp.textContent = totalPages;
    const prev = document.getElementById('domainPrevPageBtn');
    if (prev) prev.disabled = domainCurrentPage === 1;
    const next = document.getElementById('domainNextPageBtn');
    if (next) next.disabled = domainCurrentPage === totalPages;
}

window.invResetFilters = function () {
    const s = document.getElementById('domainSearchInput'); if (s) s.value = '';
    invApplyTile('all');
};

function updateCheckboxLogic() {}
function refreshCheckboxUI() {}

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
// =========================================================
// DETAIL TEMUAN (modal inspect kerentanan)
// - Label severity memakai severity asli temuan (warna Pentest-Tools). Kategori hanya label netral.
// - Angka ringkas (CVSS, EPSS, jumlah CVE, CISA KEV) diambil dari kolom temuan + tabel bukti CVE.
// - Teks risiko/rekomendasi/ringkasan CVE tampil apa adanya dari Pentest-Tools (bahasa Inggris).
// =========================================================
let fdCurrent = null;          // { vuln, model } untuk tombol "Salin ringkasan"
let fdReturnFocus = null;      // elemen yang difokus sebelum modal dibuka
let currentScanMeta = null;    // { domain, date } dari modal Scan Details yang sedang terbuka

const FD_SEV = {
    CRITICAL: ['Critical', 'var(--sev-critical)'],
    HIGH: ['High', 'var(--sev-high)'],
    MEDIUM: ['Medium', 'var(--sev-medium)'],
    LOW: ['Low', 'var(--sev-low)'],
    INFO: ['Info', 'var(--sev-info)']
};
const FD_ICON = {
    alert: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"></path><path d="M12 9v4"></path><path d="M12 17h.01"></path></svg>',
    info: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path></svg>',
    tag: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12.59 2.59A2 2 0 0 0 11.17 2H4a2 2 0 0 0-2 2v7.17a2 2 0 0 0 .59 1.41l8.7 8.7a2.43 2.43 0 0 0 3.42 0l6.58-6.58a2.43 2.43 0 0 0 0-3.42z"></path><circle cx="7.5" cy="7.5" r=".5" fill="currentColor"></circle></svg>',
    flame: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.07-2.14-.22-4.05 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.15.43-2.29 1-3a2.5 2.5 0 0 0 2.5 2.5z"></path></svg>',
    globe: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"></path><path d="M2 12h20"></path></svg>',
    scanner: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 7V5a2 2 0 0 1 2-2h2"></path><path d="M17 3h2a2 2 0 0 1 2 2v2"></path><path d="M21 17v2a2 2 0 0 1-2 2h-2"></path><path d="M7 21H5a2 2 0 0 1-2-2v-2"></path><path d="M7 12h10"></path></svg>',
    cal: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="18" rx="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>',
    ext: '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 3h6v6"></path><path d="M10 14 21 3"></path><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path></svg>'
};

// Kategori ditebak dari judul/scanner (bukan dari Pentest-Tools), jadi hanya label netral
function fdCategory(vuln) {
    const sig = `${(vuln.check_type || '').toLowerCase()} ${(vuln.title || '').toLowerCase()}`;
    const has = (...w) => w.some(x => sig.includes(x));
    if (has('sql', 'injection', 'xss', 'cross-site scripting', 'rce', 'ssrf', 'xxe', 'command execution')) return 'Critical Web Exploit';
    if (has('auth', 'credential', 'bypass', 'brute force', 'traversal', 'idor', 'default password')) return 'Access Control Flaw';
    if (has('csrf', 'cross-site request forgery')) return 'CSRF Vulnerability';
    if (has('cve-', 'outdated', 'vulnerabilities found for', 'deprecated', 'end-of-life', 'version')) return 'Vulnerable Component';
    if (has('ssl', 'tls', 'certificate', 'cipher', 'poodle', 'heartbleed', 'weak encryption')) return 'Crypto & SSL Flaw';
    if (has('wordpress', 'joomla', 'drupal', 'plugin', 'theme')) return 'CMS Vulnerability';
    if (has('cookie', 'httponly', 'secure flag', 'samesite', 'session')) return 'Insecure Session/Cookie';
    if (has('header', 'hsts', 'csp', 'clickjacking', 'cors', 'mime-sniffing')) return 'Security Header Missing';
    if (has('information', 'disclosure', 'leak', 'directory', 'error message', 'stack trace', 'phpinfo')) return 'Information Disclosure';
    if (has('dns', 'spf', 'dkim', 'dmarc', 'zone transfer', 'smtp', 'relay')) return 'DNS/Mail Misconfig';
    if (has('network ', 'tcp', 'udp', 'ftp', 'ssh') || /\bport\b/.test(sig)) return 'Network Vulnerability';
    return 'Web Vulnerability';
}

const FD_ENTITIES = { '&apos;': "'", '&#39;': "'", '&quot;': '"', '&#34;': '"', '&lt;': '<', '&gt;': '>', '&nbsp;': ' ', '&amp;': '&' };
function fdDecode(v) {
    return String(v ?? '').replace(/&(apos|quot|lt|gt|nbsp|amp|#39|#34);/g, m => FD_ENTITIES[m] || m);
}

// Teks dari Pentest-Tools -> HTML aman (entity diurai, di-escape, URL jadi tautan)
function fdText(v) {
    return linkify(escapeHtml(fdDecode(v)));
}

function fdNum(v) {
    const n = typeof v === 'number' ? v : parseFloat(String(v ?? '').replace(',', '.'));
    return Number.isFinite(n) ? n : null;
}

// EPSS 0.99999 -> "99,999%", 0.02795 -> "2,8%"
function fdPct(v) {
    const n = fdNum(v);
    if (n === null) return '-';
    const p = n * 100;
    const digits = p >= 99 ? 3 : 1;
    return `${p.toLocaleString('id-ID', { maximumFractionDigits: digits })}%`;
}

function fdCvssSev(score) {
    if (score === null) return null;
    if (score >= 9) return 'CRITICAL';
    if (score >= 7) return 'HIGH';
    if (score >= 4) return 'MEDIUM';
    if (score > 0) return 'LOW';
    return 'INFO';
}

function fdParseList(v) {
    if (!v) return [];
    if (Array.isArray(v)) return v.map(String).map(s => s.trim()).filter(Boolean);
    return String(v).replace(/[{}"'[\]]/g, '').split(',').map(s => s.trim()).filter(Boolean);
}

// Bukti: { kind: 'cve'|'table'|'text'|'list'|'instances'|'raw'|'none', ... }
function fdParseEvidence(raw) {
    if (!raw || !String(raw).trim()) return { kind: 'none' };
    let ev;
    try { ev = JSON.parse(raw); } catch (e) { return { kind: 'raw', text: String(raw) }; }
    let inner = ev;
    if (ev && ev.type === 'vuln_evidence' && ev.data && typeof ev.data === 'object') inner = ev.data;
    if (ev && ev.type === 'instances' && Array.isArray(ev.data)) return { kind: 'instances', data: ev.data };
    if (inner && inner.type === 'table' && inner.data && Array.isArray(inner.data.headers)) {
        const headers = inner.data.headers.map(h => String(h));
        const rows = Array.isArray(inner.data.rows) ? inner.data.rows : [];
        const idx = (name) => headers.findIndex(h => h.trim().toLowerCase() === name);
        if (idx('cve') >= 0) {
            const at = (r, name) => { const i = idx(name); return i >= 0 ? r[i] : null; };
            const cves = rows.map(r => ({
                cve: String(at(r, 'cve') ?? ''),
                cvss: fdNum(at(r, 'cvss')),
                epss: fdNum(at(r, 'epss score')),
                pct: fdNum(at(r, 'epss percentile')),
                kev: /^(yes|true|ya)$/i.test(String(at(r, 'cisa kev') ?? '').trim()),
                summary: fdDecode(at(r, 'summary')),
                exploit: String(at(r, 'exploit') ?? '').trim()
            })).filter(c => c.cve);
            return { kind: 'cve', cves };
        }
        return { kind: 'table', headers, rows };
    }
    if (inner && inner.type === 'list' && Array.isArray(inner.data)) return { kind: 'list', data: inner.data };
    if (inner && inner.type === 'text') return { kind: 'text', text: String(inner.data ?? '') };
    return { kind: 'raw', text: JSON.stringify(ev, null, 2) };
}

// Model tampilan dari satu temuan
function fdBuildModel(vuln) {
    const sev = String(vuln.severity || 'INFO').toUpperCase();
    const ev = fdParseEvidence(vuln.evidence);
    const cveRows = ev.kind === 'cve' ? ev.cves : [];
    const cves = cveRows.length ? cveRows.map(c => c.cve) : fdParseList(vuln.cve);
    let topCvss = null;
    cveRows.forEach(c => { if (c.cvss !== null && (!topCvss || c.cvss > topCvss.v)) topCvss = { v: c.cvss, cve: c.cve }; });
    if (!topCvss && fdNum(vuln.cvss_v3) !== null) topCvss = { v: fdNum(vuln.cvss_v3), cve: null };
    let topEpss = null;
    cveRows.forEach(c => { if (c.epss !== null && (!topEpss || c.epss > topEpss.v)) topEpss = { v: c.epss, pct: c.pct, cve: c.cve }; });
    if (!topEpss && fdNum(vuln.epss_score) !== null) topEpss = { v: fdNum(vuln.epss_score), pct: fdNum(vuln.epss_percentile), cve: null };
    const kevCount = cveRows.filter(c => c.kev).length;
    const kev = kevCount > 0 || vuln.cisa_kev === true || /^(true|yes)$/i.test(String(vuln.cisa_kev || ''));
    // Deskripsi: bagian "Notes:" dipecah jadi poin
    const desc = fdDecode(vuln.description).trim();
    const m = desc.match(/^([\s\S]*?)\s*Notes?:\s*([\s\S]*)$/i);
    const main = m ? m[1].trim() : desc;
    const notes = m ? m[2].split(/;\s*/).map(s => s.replace(/^\s*-\s*/, '').trim()).filter(Boolean) : [];
    const ver = String(vuln.title || '').match(/found for\s+(.+?\s+v?\d[\w.\-]*)\s*$/i);
    return {
        sev: FD_SEV[sev] ? sev : 'INFO',
        category: fdCategory(vuln),
        ev, cves, topCvss, topEpss, kev, kevCount, cveRows,
        main, notes,
        version: ver ? ver[1] : null,
        limited: /only the first \d+ vulnerabilities/i.test(desc)
    };
}

function fdRenderStats(m) {
    const tiles = [];
    if (m.topCvss) {
        const s = fdCvssSev(m.topCvss.v);
        tiles.push(`<div class="fd-stat"><span class="fd-stat-label">CVSS tertinggi</span><strong style="color:${FD_SEV[s][1]}">${m.topCvss.v}</strong>
            <span class="fd-bar" aria-hidden="true"><i style="width:${Math.min(100, m.topCvss.v * 10)}%;background:${FD_SEV[s][1]}"></i></span>
            <span class="fd-stat-sub">${FD_SEV[s][0]}${m.topCvss.cve ? ` · ${escapeHtml(m.topCvss.cve)}` : ''}</span></div>`);
    }
    if (m.topEpss) {
        const hot = m.topEpss.v >= 0.5;
        tiles.push(`<div class="fd-stat"><span class="fd-stat-label">EPSS (peluang 30 hari)</span><strong class="${hot ? 'is-hot' : ''}">${fdPct(m.topEpss.v)}</strong>
            <span class="fd-bar" aria-hidden="true"><i style="width:${Math.max(2, Math.min(100, m.topEpss.v * 100))}%" class="${hot ? 'is-hot' : ''}"></i></span>
            <span class="fd-stat-sub">${m.topEpss.pct !== null ? `Persentil ${fdNum(m.topEpss.pct * 100).toLocaleString('id-ID', { maximumFractionDigits: 3 })}` : ''}${m.topEpss.cve ? `${m.topEpss.pct !== null ? ' · ' : ''}${escapeHtml(m.topEpss.cve)}` : ''}</span></div>`);
    }
    if (m.cves.length) {
        tiles.push(`<div class="fd-stat"><span class="fd-stat-label">CVE terdeteksi</span><strong>${m.cves.length}</strong>
            <span class="fd-stat-sub">${m.limited ? 'Hanya 5 risiko tertinggi per port' : (m.cves.length === 1 ? escapeHtml(m.cves[0]) : 'Lihat tabel bukti')}</span></div>`);
    }
    if (m.cveRows.length) {
        tiles.push(`<div class="fd-stat${m.kevCount ? ' is-alert' : ''}"><span class="fd-stat-label">CISA KEV</span><strong>${m.kevCount} dari ${m.cveRows.length}</strong>
            <span class="fd-stat-sub">${m.kevCount ? 'CVE yang sudah dipakai penyerang' : 'Belum ada yang tercatat dipakai penyerang'}</span></div>`);
    } else if (m.kev) {
        tiles.push(`<div class="fd-stat is-alert"><span class="fd-stat-label">CISA KEV</span><strong>Ya</strong><span class="fd-stat-sub">Sudah dipakai penyerang</span></div>`);
    }
    const el = document.getElementById('fdStats');
    el.hidden = !tiles.length;
    el.innerHTML = tiles.join('');
}

function fdCveLink(c) {
    const id = escapeHtml(c);
    return /^CVE-\d{4}-\d+$/i.test(c)
        ? `<a class="fd-cve" href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" rel="noopener">${id}${FD_ICON.ext}<span class="sr-only"> (buka di NVD, tab baru)</span></a>`
        : `<span class="fd-cve">${id}</span>`;
}

function fdRenderEvidence(vuln, m) {
    const box = document.getElementById('evidenceContainer');
    const title = document.getElementById('fdEvTitle');
    const ev = m.ev;
    title.textContent = ev.kind === 'cve' ? (m.version ? 'Bukti: CVE yang cocok dengan versi ini' : 'Bukti: CVE terkait') : 'Bukti';
    box.innerHTML = '';
    if (ev.kind === 'cve') {
        box.innerHTML = `<div class="fd-table-wrap"><table class="fd-table fd-cve-table">
            <thead><tr><th scope="col">CVE</th><th scope="col">CVSS</th><th scope="col">EPSS</th><th scope="col">CISA KEV</th><th scope="col">Ringkasan</th><th scope="col">Exploit</th></tr></thead>
            <tbody>${ev.cves.map(c => {
                const s = fdCvssSev(c.cvss);
                const hot = c.epss !== null && c.epss >= 0.5;
                return `<tr>
                    <td>${fdCveLink(c.cve)}</td>
                    <td>${c.cvss !== null ? `<span class="fd-cvss" style="background:${FD_SEV[s][1]}">${c.cvss}</span>` : '<span class="fd-muted">-</span>'}</td>
                    <td>${c.epss !== null ? `<span class="fd-epss${hot ? ' is-hot' : ''}">${fdPct(c.epss)}</span><span class="fd-bar fd-bar-sm" aria-hidden="true"><i style="width:${Math.max(2, c.epss * 100)}%" class="${hot ? 'is-hot' : ''}"></i></span>${c.pct !== null ? `<span class="fd-muted fd-small">persentil ${(c.pct * 100).toLocaleString('id-ID', { maximumFractionDigits: 3 })}</span>` : ''}` : '<span class="fd-muted">-</span>'}</td>
                    <td>${c.kev ? `<span class="fd-kev is-yes">${FD_ICON.flame}Ya</span>` : '<span class="fd-kev">Tidak</span>'}</td>
                    <td class="fd-summary">${fdText(c.summary) || '<span class="fd-muted">-</span>'}</td>
                    <td>${c.exploit && c.exploit.toUpperCase() !== 'N/A' ? fdText(c.exploit) : '<span class="fd-muted">N/A</span>'}</td>
                </tr>`;
            }).join('')}</tbody></table></div>`;
    } else if (ev.kind === 'table') {
        box.innerHTML = `<div class="fd-table-wrap"><table class="fd-table">
            <thead><tr>${ev.headers.map(h => `<th scope="col">${escapeHtml(h)}</th>`).join('')}</tr></thead>
            <tbody>${ev.rows.map(r => `<tr>${r.map(c => `<td>${fdText(String(c ?? '').replace(/ Request \/ Response$/, ''))}</td>`).join('')}</tr>`).join('')}</tbody>
        </table></div>`;
    } else if (ev.kind === 'list') {
        box.innerHTML = `<ul class="fd-ev-list">${ev.data.map(x => `<li>${fdText(typeof x === 'string' ? x : JSON.stringify(x))}</li>`).join('')}</ul>`;
    } else if (ev.kind === 'text' || ev.kind === 'raw') {
        box.innerHTML = `<pre class="fd-pre">${fdText(ev.text)}</pre>`;
    } else if (ev.kind === 'instances') {
        ev.data.forEach(inst => box.appendChild(createEvidenceCard(inst)));
    } else {
        box.innerHTML = `<p class="fd-empty">Pentest-Tools tidak menyertakan bukti untuk temuan ini.</p>`;
    }
}

function openThreatModal(vuln) {
    const overlay = document.getElementById('threatModalOverlay');
    if (!overlay || !vuln) return;
    const m = fdBuildModel(vuln);
    fdCurrent = { vuln, model: m };
    fdReturnFocus = document.activeElement;

    // Label: severity asli, kategori netral, CISA KEV bila ada
    const [sevLabel, sevColor] = FD_SEV[m.sev];
    document.getElementById('fdTags').innerHTML = `
        <span class="fd-sev" style="background:${sevColor}">${['CRITICAL', 'HIGH', 'MEDIUM'].includes(m.sev) ? FD_ICON.alert : FD_ICON.info}${sevLabel.toUpperCase()}</span>
        <span class="fd-cat" title="Kategori ditebak dashboard dari judul temuan">${FD_ICON.tag}${escapeHtml(m.category)}</span>
        ${m.kev ? `<span class="fd-kev-tag">${FD_ICON.flame}Dieksploitasi di dunia nyata (CISA KEV)</span>` : ''}`;
    document.getElementById('fdTitle').textContent = fdDecode(vuln.title) || 'Temuan tanpa judul';

    const meta = [];
    if (currentScanMeta && currentScanMeta.domain) meta.push(`<span>${FD_ICON.globe}${escapeHtml(currentScanMeta.domain)}</span>`);
    if (vuln.check_type) meta.push(`<span>${FD_ICON.scanner}${escapeHtml(vuln.check_type)}</span>`);
    if (currentScanMeta && currentScanMeta.date) meta.push(`<span>${FD_ICON.cal}Scan ${escapeHtml(formatDate(currentScanMeta.date))}</span>`);
    document.getElementById('fdMeta').innerHTML = meta.join('');

    fdRenderStats(m);

    document.getElementById('fdDesc').innerHTML = m.main ? linkify(escapeHtml(m.main)) : '<span class="fd-muted">Pentest-Tools tidak menyertakan deskripsi risiko.</span>';
    document.getElementById('fdNotes').innerHTML = m.notes.map(n => `<li>${FD_ICON.info}<span>${linkify(escapeHtml(n))}</span></li>`).join('');
    document.getElementById('fdRec').innerHTML = vuln.recommendation ? fdText(vuln.recommendation) : '<span class="fd-muted">Pentest-Tools tidak menyertakan rekomendasi.</span>';
    const verEl = document.getElementById('fdVersion');
    verEl.hidden = !m.version;
    verEl.innerHTML = m.version ? `<span>Versi terdeteksi</span><code>${escapeHtml(m.version)}</code>` : '';

    fdRenderEvidence(vuln, m);

    // Klasifikasi: CVE (NVD), CWE (MITRE), scanner
    const chips = [];
    m.cves.forEach(c => chips.push(`<span class="fd-chip"><em>CVE</em>${fdCveLink(c)}</span>`));
    fdParseList(vuln.cwe).forEach(c => {
        const n = c.match(/CWE-(\d+)/i);
        chips.push(`<span class="fd-chip"><em>CWE</em>${n ? `<a class="fd-cve" href="https://cwe.mitre.org/data/definitions/${n[1]}.html" target="_blank" rel="noopener">${escapeHtml(c)}${FD_ICON.ext}<span class="sr-only"> (buka di MITRE, tab baru)</span></a>` : escapeHtml(c)}</span>`);
    });
    if (vuln.check_type) chips.push(`<span class="fd-chip"><em>Scanner</em><span>${escapeHtml(vuln.check_type)}</span></span>`);
    document.getElementById('fdChips').innerHTML = chips.join('');
    document.getElementById('fdClassSection').hidden = !chips.length;

    overlay.classList.add('active');
    overlay.querySelector('.fd-body').scrollTop = 0;
    setTimeout(() => document.getElementById('fdCloseBtn')?.focus(), 30);
}
window.openThreatModal = openThreatModal;

// Teks ringkasan untuk laporan
function fdSummaryText() {
    if (!fdCurrent) return '';
    const { vuln, model: m } = fdCurrent;
    const lines = [
        fdDecode(vuln.title) || 'Temuan',
        `Severity: ${FD_SEV[m.sev][0]}`
    ];
    if (currentScanMeta && currentScanMeta.domain) lines.push(`Domain: ${currentScanMeta.domain}`);
    if (vuln.check_type) lines.push(`Scanner: ${vuln.check_type}`);
    if (m.cves.length) lines.push(`CVE: ${m.cves.join(', ')}`);
    if (m.topCvss) lines.push(`CVSS tertinggi: ${m.topCvss.v}`);
    if (m.topEpss) lines.push(`EPSS tertinggi: ${fdPct(m.topEpss.v)}`);
    if (m.kev) lines.push(`CISA KEV: ${m.cveRows.length ? `${m.kevCount} dari ${m.cveRows.length} CVE` : 'Ya'}`);
    if (vuln.recommendation) lines.push(`Rekomendasi: ${fdDecode(vuln.recommendation)}`);
    return lines.join('\n');
}

window.copyFindingSummary = async function () {
    const text = fdSummaryText();
    if (!text) return;
    try {
        await navigator.clipboard.writeText(text);
        showToast('Ringkasan temuan disalin.', 'success');
    } catch (e) {
        showToast('Gagal menyalin. Izinkan akses clipboard di browser lalu coba lagi.', 'error');
    }
};

document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const ov = document.getElementById('threatModalOverlay');
    if (!ov || !ov.classList.contains('active')) return;
    const above = ['generateReportModalOverlay'].some(id => document.getElementById(id)?.classList.contains('active'));
    if (above) return;
    closeThreatModal();
});

function linkify(text) {
    if (!text) return text;
    var urlRegex = /(https?:\/\/[^\s]+)/g;
    return text.replace(urlRegex, function(url) {
        return `<a href="${url}" target="_blank" style="color: #2563eb; text-decoration: underline;">${url}</a>`;
    });
}

function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe.toString()
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function createEvidenceCard(inst) {
    const card = document.createElement('div');
    card.className = 'evidence-card';
    
    let html = '';
    
    // URL Box
    if (inst.uri) {
        let paramStr = '';
        if (inst.parameter) {
            paramStr = `
            <div class="evidence-param-box">
                <div class="evidence-url-label">Cookie / Parameter</div>
                <div style="font-size:13px; color:var(--color-ink);">${escapeHtml(inst.parameter)}</div>
            </div>`;
        }
        
        html += `
        <div class="evidence-url-box">
            <div>
                <div class="evidence-url-label">URL</div>
                <a href="${escapeHtml(inst.uri)}" target="_blank" class="evidence-url-link">${escapeHtml(inst.uri)}</a>
            </div>
            ${paramStr}
        </div>`;
    }
    
    // Description/Evidence string
    if (inst.evidence || inst.details) {
        const desc = inst.evidence || inst.details;
        html += `<div class="evidence-desc">${escapeHtml(desc)}</div>`;
    }
    
    // Request / Response Terminal
    let traceText = '';
    const req = inst.request_response || inst.request || inst.http_request || inst.raw_request;
    const res = inst.response || inst.http_response || inst.raw_response;
    
    if (req && res && !inst.request_response) {
        traceText = '--- REQUEST ---\n' + req + '\n\n--- RESPONSE ---\n' + res;
    } else if (req) {
        traceText = inst.request_response ? req : ('--- REQUEST ---\n' + req);
    } else if (res) {
        traceText = '--- RESPONSE ---\n' + res;
    } else if (inst.output) {
        traceText = inst.output;
    }
    
    if (traceText) {
        const lines = escapeHtml(traceText).trim().split('\n');
        let linesHtml = '';
        let contentHtml = '';
        lines.forEach((l, i) => {
            linesHtml += `<div>${i+1}</div>`;
            contentHtml += `<div>> ${l || ' '}</div>`;
        });
        
        html += `
        <div class="evidence-terminal">
            <div class="evidence-terminal-header">
                <span>Request / Response</span>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
            </div>
            <div class="evidence-terminal-body">
                <div class="evidence-terminal-lines">${linesHtml}</div>
                <div class="evidence-terminal-content">${contentHtml}</div>
            </div>
            <div class="evidence-terminal-footer" onclick="this.previousElementSibling.style.maxHeight = this.previousElementSibling.style.maxHeight === 'none' ? '250px' : 'none'; this.textContent = this.previousElementSibling.style.maxHeight === 'none' ? 'Collapse' : 'Expand';">
                Expand
            </div>
        </div>`;
    }
    
    // Fallback if neither URL nor trace was rendered, just dump JSON
    if (!html) {
        html = `<div class="evidence-desc" style="white-space: pre-wrap; font-family: inherit;">${escapeHtml(JSON.stringify(inst, null, 2))}</div>`;
    }
    
    card.innerHTML = html;
    return card;
}

function closeThreatModal() {
    document.getElementById('threatModalOverlay').classList.remove('active');
    // Fokus kembali ke baris temuan yang tadi dibuka (keyboard)
    if (fdReturnFocus && document.body.contains(fdReturnFocus)) fdReturnFocus.focus({ preventScroll: true });
    fdReturnFocus = null;
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

    // Otomatis tandai notifikasi terkait sebagai DIBACA saat detail scan dibuka (dari history / manual / toast)
    if (scan && scan.id) {
        markNotificationReadByScanId(scan.id);
    }

    const domainName = scan.domains?.domain_name || scan.domain_name || '';
    currentScanMeta = { domain: domainName, date: scan.scan_date };
    document.getElementById('scanModalDomain').textContent = domainName || '-';
    document.getElementById('scanModalIp').textContent = scan.domains?.ip_address || scan.ip_address || '-';
    document.getElementById('scanModalDate').textContent = formatDate(scan.scan_date);
    const riskEl = document.getElementById('scanModalRisk');
    const riskText = (scan.risk_level || 'SAFE').toUpperCase();
    riskEl.className = 'sd-meta-value';
    riskEl.innerHTML = `<span class="badge badge-${getSeverityClass(riskText)}">${escapeHtml(riskText)}</span>`;
    const searchEl = document.getElementById('scanModalSearch');
    if (searchEl) searchEl.value = '';

    let scanType = "Unknown Scan";
    if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
        scanType = scan.vulnerabilities[0].check_type || "Unknown Scan";
    }
    const typeEl = document.getElementById('scanModalType');
    if (typeEl) {
        typeEl.textContent = scanType;
    }

    const btnDownload = document.getElementById('btnDownloadReport');
    if (btnDownload && domainName && currentUser && (currentUser.role === 'admin' || currentUser.role === 'superadmin')) {
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

    // Dibuka dari Severity Trend dengan satu severity difokuskan: langsung filter ke severity itu
    const pending = window.__pendingScanFilter;
    window.__pendingScanFilter = null;
    if (pending && currentScanVulns.some(v => (v.severity || '').toLowerCase() === pending.toLowerCase())) {
        setScanFilter(pending);
    }
}

function setScanFilter(sev) {
    currentScanVulnsFilter = sev;
    renderScanFilters();
    renderScanVulnsTable();
}

function renderScanFilters() {
    const filtersContainer = document.getElementById('scanModalFilters');
    if (!filtersContainer) return;

    const counts = { All: currentScanVulns.length, Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    currentScanVulns.forEach(v => {
        const s = (v.severity || '').toLowerCase();
        const key = s.charAt(0).toUpperCase() + s.slice(1);
        if (key in counts && key !== 'All') counts[key]++;
    });

    // Warna severity tetap memakai variabel Pentest-Tools (--sev-*)
    const filterOptions = [
        { label: 'All', key: 'All', color: '', initial: '' },
        { label: 'Critical', key: 'Critical', color: 'var(--sev-critical)', initial: 'C' },
        { label: 'High', key: 'High', color: 'var(--sev-high)', initial: 'H' },
        { label: 'Medium', key: 'Medium', color: 'var(--sev-medium)', initial: 'M' },
        { label: 'Low', key: 'Low', color: 'var(--sev-low)', initial: 'L' },
        { label: 'Info', key: 'Info', color: 'var(--sev-info)', initial: 'I' }
    ];

    filtersContainer.innerHTML = filterOptions.map(f => {
        const active = currentScanVulnsFilter === f.key;
        const zero = f.key !== 'All' && counts[f.key] === 0;
        // Titik warna saja: label severity sudah tertulis di sebelahnya
        const dot = f.color ? `<span class="sd-dot" style="background:${f.color}" aria-hidden="true"></span>` : '';
        return `<button type="button" role="tab" aria-selected="${active}" class="sd-chip${active ? ' active' : ''}${zero ? ' zero' : ''}"
                    data-scan-filter="${f.key}" ${zero ? 'disabled' : ''}>
                    ${dot}<span>${f.label}</span><span class="sd-chip-count">${counts[f.key]}</span>
                </button>`;
    }).join('');

    const bar = document.getElementById('scanModalSevBar');
    if (bar) {
        const total = currentScanVulns.length;
        bar.innerHTML = total
            ? filterOptions.slice(1).filter(f => counts[f.key] > 0)
                .map(f => `<span style="flex:${counts[f.key]};background:${f.color}" title="${f.label}: ${counts[f.key]}"></span>`).join('')
            : '';
        bar.hidden = total === 0;
    }
    const countEl = document.getElementById('scanModalCount');
    if (countEl) countEl.textContent = counts.All;
}

function renderScanVulnsTable() {
    const tbody = document.getElementById('scanModalVulnBody');
    if (!tbody) return;

    const q = (document.getElementById('scanModalSearch')?.value || '').trim().toLowerCase();
    const rows = currentScanVulns
        .map((v, idx) => ({ v, idx }))
        .filter(({ v }) => currentScanVulnsFilter === 'All' || (v.severity || '').toLowerCase() === currentScanVulnsFilter.toLowerCase())
        .filter(({ v }) => !q || `${v.title || ''} ${v.check_type || ''}`.toLowerCase().includes(q));

    if (rows.length === 0) {
        const msg = currentScanVulns.length === 0
            ? 'Tidak ada kerentanan yang ditemukan pada scan ini.'
            : (q ? `Tidak ada temuan yang cocok dengan "${escapeHtml(q)}".` : 'No vulnerabilities found for this filter.');
        tbody.innerHTML = `<tr><td colspan="4" class="sd-empty">${msg}</td></tr>`;
        return;
    }

    tbody.innerHTML = rows.map(({ v, idx }) => {
        const sevClass = getSeverityClass(v.severity);
        return `
            <tr class="sd-row" data-vuln-idx="${idx}" tabindex="0">
                <td><span class="badge badge-${sevClass}">${escapeHtml(String(v.severity || '').toUpperCase())}</span></td>
                <td class="sd-title">${escapeHtml(v.title)}</td>
                <td class="sd-check">${escapeHtml(v.check_type || '-')}</td>
                <td class="sd-col-action">
                    <button type="button" class="sd-inspect" data-vuln-idx="${idx}">Inspect
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
                    </button>
                </td>
            </tr>`;
    }).join('');

    updateInventoryBulkBar();
}

(function initScanDetailsModal() {
    const overlay = document.getElementById('scanModalOverlay');
    if (!overlay) return;
    overlay.addEventListener('click', (e) => {
        const chip = e.target.closest('[data-scan-filter]');
        if (chip && !chip.disabled) { setScanFilter(chip.dataset.scanFilter); return; }
        const row = e.target.closest('[data-vuln-idx]');
        if (row) {
            const v = currentScanVulns[parseInt(row.dataset.vulnIdx, 10)];
            if (v) openThreatModal(v);
        }
    });
    overlay.addEventListener('keydown', (e) => {
        const row = e.target.classList && e.target.classList.contains('sd-row') ? e.target : null;
        if (row && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            const v = currentScanVulns[parseInt(row.dataset.vulnIdx, 10)];
            if (v) openThreatModal(v);
        }
    });
    document.getElementById('scanModalSearch')?.addEventListener('input', () => renderScanVulnsTable());
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape' || !overlay.classList.contains('active')) return;
        // Jangan tutup jika ada modal lain di atasnya (detail temuan / generate report)
        const above = ['threatModalOverlay', 'generateReportModalOverlay']
            .some(id => document.getElementById(id)?.classList.contains('active'));
        if (!above) closeScanModal();
    }, true); // capture: dicek sebelum handler Escape modal lain sempat menutup dirinya
})();

function updateSecurityPostureScore() {
    const gaugeCircle = document.getElementById('postureGaugeCircle');
    const scoreNum = document.getElementById('postureScoreNum');
    const gradeBadge = document.getElementById('postureGradeBadge');
    const statusDesc = document.getElementById('postureStatusDesc');

    if (!gaugeCircle || !scoreNum) return;

    if (!allDomains || allDomains.length === 0) {
        scoreNum.textContent = '100';
        if (gradeBadge) {
            gradeBadge.textContent = 'GRADE A';
            gradeBadge.style.background = '#10b981';
        }
        if (statusDesc) statusDesc.textContent = 'Inventory domain kosong. Sistem siap digunakan untuk analisis keamanan.';
        return;
    }

    let penalty = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    allDomains.forEach(d => {
        if (d.last_scan_status) {
            const st = d.last_scan_status.toUpperCase();
            if (st === 'CRITICAL') { penalty += 20; criticalCount++; }
            else if (st === 'HIGH') { penalty += 10; highCount++; }
            else if (st === 'MEDIUM') { penalty += 4; mediumCount++; }
            else if (st === 'LOW') { penalty += 1; lowCount++; }
        }
    });

    let score = Math.max(0, 100 - penalty);

    let grade = 'GRADE A';
    let gradeColor = '#10b981';
    let descText = 'Sistem dalam kondisi sangat aman. Semua target terpantau aktif dan tidak terdeteksi ancaman kritis.';

    if (score < 40) {
        grade = 'GRADE F';
        gradeColor = '#ef4444';
        descText = `PERHATIAN KRITIS: Terdeteksi ${criticalCount} ancaman Critical & ${highCount} High. Penanganan keamanan mendesak diperlukan!`;
    } else if (score < 60) {
        grade = 'GRADE D';
        gradeColor = '#f97316';
        descText = `RISIKO TINGGI: Terdeteksi ${criticalCount + highCount} temuan kerentanan tingkat tinggi. Lakukan remediasi secepatnya.`;
    } else if (score < 75) {
        grade = 'GRADE C';
        gradeColor = '#eab308';
        descText = `PERINGATAN MODERAT: Terdeteksi ${mediumCount} temuan kerentanan tingkat sedang. Disarankan evaluasi konfigurasi target.`;
    } else if (score < 90) {
        grade = 'GRADE B';
        gradeColor = '#3b82f6';
        descText = 'KONDISI BAIK: Sistem relatif aman dengan sedikit potensi celah kerentanan tingkat rendah.';
    }

    scoreNum.textContent = score;
    const circumference = 251.2;
    const offset = circumference - (score / 100) * circumference;

    gaugeCircle.style.strokeDashoffset = offset;
    gaugeCircle.style.stroke = gradeColor;

    if (gradeBadge) {
        gradeBadge.textContent = grade;
        gradeBadge.style.background = gradeColor;
    }
    if (statusDesc) {
        statusDesc.textContent = descText;
    }
}

function toggleSelectAllInventory(masterCb) {
    const checkboxes = document.querySelectorAll('.inventory-row-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = masterCb.checked;
    });
    updateInventoryBulkBar();
}

function updateInventoryBulkBar() {
    const checkedCbs = document.querySelectorAll('.inventory-row-checkbox:checked');
    const bulkBar = document.getElementById('inventoryBulkBar');
    const countEl = document.getElementById('inventoryBulkCount');
    const masterCb = document.getElementById('selectAllInventoryRows');

    if (countEl) countEl.textContent = checkedCbs.length;

    if (bulkBar) {
        if (checkedCbs.length > 0) {
            bulkBar.style.opacity = '1';
            bulkBar.style.visibility = 'visible';
            bulkBar.style.transform = 'translateX(-50%) translateY(0)';
        } else {
            bulkBar.style.opacity = '0';
            bulkBar.style.visibility = 'hidden';
            bulkBar.style.transform = 'translateX(-50%) translateY(100px)';
        }
    }

    const allRowCbs = document.querySelectorAll('.inventory-row-checkbox');
    if (masterCb && allRowCbs.length > 0) {
        masterCb.checked = checkedCbs.length === allRowCbs.length;
    }
}

function bulkLaunchScan(type) {
    const checkedCbs = document.querySelectorAll('.inventory-row-checkbox:checked');
    const selectedDomains = Array.from(checkedCbs).map(cb => cb.getAttribute('data-domain')).filter(Boolean);

    if (selectedDomains.length === 0) {
        showToast('Info', 'Pilih minimal satu domain target.', 'ℹ️');
        return;
    }

    if (type === 'web') {
        openSelectScanTypeModal();
        setTimeout(() => {
            const webCbs = document.querySelectorAll('.web-target-checkbox');
            webCbs.forEach(cb => {
                cb.checked = selectedDomains.includes(cb.value);
            });
            if (typeof updateSelectedWebTargetsCount === 'function') updateSelectedWebTargetsCount();
        }, 100);
    } else {
        openNetworkScanModal();
        setTimeout(() => {
            const netCbs = document.querySelectorAll('.network-target-checkbox');
            netCbs.forEach(cb => {
                cb.checked = selectedDomains.includes(cb.value);
            });
            if (typeof updateSelectedNetworkTargetsCount === 'function') updateSelectedNetworkTargetsCount();
        }, 100);
    }
}

async function bulkToggleActive(targetStatus) {
    const checkedCbs = document.querySelectorAll('.inventory-row-checkbox:checked');
    const ids = Array.from(checkedCbs).map(cb => parseInt(cb.value)).filter(Boolean);

    if (ids.length === 0) return;

    const actionName = targetStatus ? 'mengaktifkan' : 'menonaktifkan';
    const confirmed = await customConfirm({
        title: `${targetStatus ? 'Aktifkan' : 'Nonaktifkan'} Domain Target`,
        message: `Apakah Anda yakin ingin ${actionName} ${ids.length} domain target yang dipilih?`,
        confirmText: `Ya, ${targetStatus ? 'Aktifkan' : 'Nonaktifkan'}`,
        cancelText: 'Batal',
        variant: targetStatus ? 'info' : 'warning'
    });
    if (!confirmed) return;

    try {
        await Promise.all(ids.map(id => 
            fetch(`${API_BASE}/api/domains/${id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ is_active: targetStatus })
            })
        ));
        showToast(`Berhasil ${actionName} ${ids.length} domain.`, 'success');
        fetchDomains();
    } catch (err) {
        console.error('Error bulk updating domains:', err);
        showToast('Gagal memperbarui beberapa domain.', 'error');
    }
}

async function bulkDeleteDomains() {
    const checkedCbs = document.querySelectorAll('.inventory-row-checkbox:checked');
    const ids = Array.from(checkedCbs).map(cb => parseInt(cb.value)).filter(Boolean);

    if (ids.length === 0) return;

    const confirmed = await customConfirm({
        title: 'Hapus Domain Target',
        message: `Apakah Anda yakin ingin menghapus ${ids.length} domain target yang dipilih secara permanen?`,
        confirmText: 'Ya, Hapus Semua',
        cancelText: 'Batal',
        variant: 'danger'
    });
    if (!confirmed) return;

    try {
        await Promise.all(ids.map(id => 
            fetch(`${API_BASE}/api/domains/${id}`, { method: 'DELETE' })
        ));
        showToast(`Berhasil menghapus ${ids.length} domain.`, 'success');
        fetchDomains();
    } catch (err) {
        console.error('Error bulk deleting domains:', err);
        showToast('Gagal menghapus beberapa domain.', 'error');
    }
}



function closeScanModal() {
    document.getElementById('scanModalOverlay').classList.remove('active');
}

// Helpers
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    // innerHTML tidak meng-escape tanda kutip; wajib agar aman dipakai di atribut HTML
    return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#039;');
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
    if (s.includes('BELUM SCAN') || s.includes('UNSCANNED')) return 'unscanned';
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
let wsEverConnected = false;
let dataChangedTimer = null;
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
    const navTitleAdminEl = document.getElementById('navTitleAdmin');
    if (navTitleAdminEl) navTitleAdminEl.style.display = 'none';
    const navSettings = document.getElementById('nav-system-settings');
    if (navSettings) {
        navSettings.style.display = 'none';
        navSettings.classList.add('hidden');
    }
    document.getElementById('mainHeader').style.display = 'none';
    document.getElementById('notifWrapper').style.display = 'none';
    document.getElementById('authForm').style.display = 'block';
    document.getElementById('otpForm').style.display = 'none';

    // Hapus semua toast notifikasi overnight dari DOM jika belum login / saat logout
    document.querySelectorAll('.overnight-toast').forEach(el => el.remove());

    const forgotForm = document.getElementById('forgotPasswordForm');
    if(forgotForm) forgotForm.style.display = 'none';
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

    if (typeof activeScansInterval !== 'undefined' && activeScansInterval) {
        clearInterval(activeScansInterval);
        activeScansInterval = null;
    }

    currentUser = null;
}


// Lupa password
function showForgotPasswordForm() {
    document.getElementById('authForm').style.display = 'none';
    document.getElementById('otpForm').style.display = 'none';
    document.getElementById('forgotPasswordForm').style.display = 'block';
    document.getElementById('authErrorMsg').style.display = 'none';
    document.getElementById('forgotEmail').value = '';
}

function showLoginForm() {
    document.getElementById('forgotPasswordForm').style.display = 'none';
    document.getElementById('otpForm').style.display = 'none';
    document.getElementById('authForm').style.display = 'block';
    document.getElementById('authErrorMsg').style.display = 'none';
}

async function handleForgotPasswordSubmit(e) {
    e.preventDefault();
    const email = document.getElementById('forgotEmail').value.trim();
    const btn = document.getElementById('forgotSubmitBtn');
    const errMsg = document.getElementById('authErrorMsg');

    btn.textContent = 'Mengirim...';
    btn.disabled = true;
    errMsg.style.display = 'none';

    try {
        const resp = await fetch(`${API_BASE}/api/auth/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: email })
        });
        const data = await resp.json();

        // Selalu tampilkan toast sukses (mencegah enumerasi) lalu kembali ke login
        showToast("Informasi", data.message, "");
        showLoginForm(); 
    } catch (err) {
        errMsg.textContent = "Gagal menghubungi server.";
        errMsg.style.display = 'block';
    } finally {
        btn.textContent = 'Kirim Tautan Reset';
        btn.disabled = false;
    }
}

function handleSuccessfulLogin(user) {
    currentUser = user;
    localStorage.setItem('dsti_session_start', Date.now());
    document.getElementById('authOverlay').classList.add('hidden');

    // Show Main Header
    document.getElementById('mainHeader').style.display = 'flex';

    // Setup Sidebar User Info
    document.getElementById('sidebar-user-container').style.display = 'flex';
    document.getElementById('sidebar-username').textContent = user.username;

    // Setup Topbar User Profile
    const topbarProfile = document.getElementById('topbar-user-profile');
    if (topbarProfile) {
        if (user.role === 'superadmin') {
            topbarProfile.textContent = 'Super Admin';
        } else if (user.role === 'admin') {
            topbarProfile.textContent = 'Admin DSTI';
        } else {
            topbarProfile.textContent = user.username;
        }
    }
    
    const roleEl = document.getElementById('sidebar-user-role');
    const navAdmin = document.getElementById('nav-admin');
    
    // TAMPILKAN MENU BERDASARKAN ROLE
    if (user.role === 'superadmin' || user.role === 'admin') {
        if (user.role === 'superadmin') {
            roleEl.innerHTML = `<span class="badge-superadmin-role">SUPER ADMIN</span>`;
        } else {
            roleEl.innerHTML = `<span class="badge-admin-role">ADMIN</span>`;
        }
        
        // Paksa menu User Management untuk tampil (Cabut class hidden)
        if (navAdmin) {
            navAdmin.classList.remove('hidden');
            navAdmin.style.display = 'flex';
        }
        const navTitleAdmin = document.getElementById('navTitleAdmin');
        if (navTitleAdmin) navTitleAdmin.style.display = 'block';
        
        const navSettings = document.getElementById('nav-system-settings');
        if (navSettings) {
            if (user.role === 'superadmin') {
                navSettings.classList.remove('hidden');
                navSettings.style.display = 'flex';
            } else {
                navSettings.classList.add('hidden');
                navSettings.style.display = 'none';
            }
        }
        
        document.getElementById('notifWrapper').style.display = 'block';

        // Tampilkan menu khusus admin lainnya
        applyRoleVisibility(user.role);

        // Jika role admin (bukan superadmin) sedang di halaman system-settings, alihkan ke overview
        if (user.role !== 'superadmin') {
            const activeNav = document.querySelector('.sidebar-nav .nav-item.active');
            if (activeNav) {
                const attr = activeNav.getAttribute('onclick') || '';
                if (attr.includes('system-settings')) {
                    switchView('overview');
                }
            }
        }

        fetchNotifications();
        if (typeof checkOvernightNotifications === 'function') checkOvernightNotifications();
        
    } else {
        roleEl.innerHTML = `<span class="badge-user-role">User</span>`;
        
        // Sembunyikan menu User Management untuk User biasa
        if (navAdmin) {
            navAdmin.classList.add('hidden');
            navAdmin.style.display = 'none';
        }
        const navTitleAdmin = document.getElementById('navTitleAdmin');
        if (navTitleAdmin) navTitleAdmin.style.display = 'none';

        const navSettings = document.getElementById('nav-system-settings');
        if (navSettings) {
            navSettings.classList.add('hidden');
            navSettings.style.display = 'none';
        }
        
        document.getElementById('notifWrapper').style.display = 'block';

        // Sembunyikan menu dari user biasa
        applyRoleVisibility(user.role);

        // Jika user berada di halaman terlarang, kembalikan ke overview
        const activeNav = document.querySelector('.sidebar-nav .nav-item.active');
        const activeView = activeNav ? activeNav.dataset.nav : null;
        if (activeView && !roleCanView(activeView === 'web-scanner' || activeView === 'network-scanner' ? `${activeView}-single` : activeView, user.role)) {
            switchView('overview');
        }

        // Lonceng user berisi scan selesai (disaring server)
        fetchNotifications();
    }

    // Hubungkan WebSocket Live Session
    connectLiveWebSocket(user.session_id);

    // Clean inputs
    document.getElementById('authUsername').value = '';
    document.getElementById('authPassword').value = '';
    document.getElementById('authErrorMsg').style.display = 'none';

    refreshData();
    loadOverview(); 

    if (typeof routeFromHash === 'function') {
        try { routeFromHash(); } catch (e) { /* abaikan */ }
    }

    if (autoRefreshInterval) clearInterval(autoRefreshInterval);
    // Cadangan saja: perubahan penting datang lewat koneksi live (scan selesai, domain/jadwal berubah)
    autoRefreshInterval = setInterval(() => refreshData(true), REFRESH_FALLBACK_MS);
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
                showToast("Info", data.message, "");
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
            showToast("Sukses", "Verifikasi berhasil.", "");

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
    showToast("Logout", "Anda berhasil keluar.", "");
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
// Kolom form, pesan galat, dan tombol mata (Tampilkan/Sembunyikan password)
const CU_FIELDS = { email: ['createUsername', 'cuEmailErr'], password: ['createPassword', 'cuPwErr'], confirm: ['createConfirmPassword', 'cuConfirmErr'] };

function cuShowError(key, msg) {
    const [inputId, errId] = CU_FIELDS[key];
    const input = document.getElementById(inputId);
    const err = document.getElementById(errId);
    if (err) { err.textContent = msg || ''; err.hidden = !msg; }
    if (input) input.setAttribute('aria-invalid', msg ? 'true' : 'false');
}

function cuSetEye(btn, show) {
    const input = document.getElementById(btn.dataset.cuEye);
    if (!input) return;
    input.type = show ? 'text' : 'password';
    btn.setAttribute('aria-pressed', String(show));
    btn.setAttribute('aria-label', show ? 'Sembunyikan password' : 'Tampilkan password');
    btn.classList.toggle('is-on', show);
}

function openCreateUserModal() {
    const overlay = document.getElementById('createUserModalOverlay');
    if (!overlay) return;
    cuReset();
    // Server hanya mengizinkan Super Admin membuat akun Admin; Admin hanya melihat pilihan User
    const isSuper = !!(currentUser && currentUser.role === 'superadmin');
    const adminCard = document.getElementById('cuRoleAdminCard');
    if (adminCard) adminCard.hidden = !isSuper;
    const note = document.getElementById('cuRoleNote');
    if (note) note.hidden = isSuper;
    overlay.classList.add('active');
    setTimeout(() => document.getElementById('createUsername')?.focus(), 50);
}

function cuReset() {
    ['createUsername', 'createPassword', 'createConfirmPassword'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
    Object.keys(CU_FIELDS).forEach(k => cuShowError(k, ''));
    document.querySelectorAll('#createUserModalOverlay [data-cu-eye]').forEach(b => cuSetEye(b, false));
    const userRole = document.querySelector('#createUserModalOverlay input[name="cu_role"][value="user"]');
    if (userRole) userRole.checked = true;
    const alert = document.getElementById('createUserErrorMsg');
    if (alert) { alert.textContent = ''; alert.hidden = true; }
    const submit = document.getElementById('cuSubmitBtn');
    if (submit) { submit.disabled = false; submit.textContent = 'Buat akun'; }
}

function closeCreateUserModal() {
    document.getElementById('createUserModalOverlay').classList.remove('active');
    cuReset();
}

(function cuBind() {
    const overlay = document.getElementById('createUserModalOverlay');
    if (!overlay) return;
    overlay.querySelectorAll('[data-cu-eye]').forEach(btn => btn.addEventListener('click', () => cuSetEye(btn, btn.getAttribute('aria-pressed') !== 'true')));
    document.getElementById('cuCancelBtn')?.addEventListener('click', closeCreateUserModal);
    overlay.addEventListener('keydown', e => { if (e.key === 'Escape' && overlay.classList.contains('active')) closeCreateUserModal(); });
    // Periksa saat kolom ditinggalkan; setelah ada pesan galat, periksa ulang sambil mengetik
    const val = () => cuValidate({
        email: document.getElementById('createUsername').value,
        password: document.getElementById('createPassword').value,
        confirm: document.getElementById('createConfirmPassword').value
    });
    Object.entries(CU_FIELDS).forEach(([key, [inputId, errId]]) => {
        const input = document.getElementById(inputId);
        if (!input) return;
        input.addEventListener('blur', () => { if (input.value) cuShowError(key, val().errors[key]); });
        input.addEventListener('input', () => {
            if (!document.getElementById(errId).hidden) cuShowError(key, val().errors[key]);
            // Konfirmasi ikut diperiksa ulang saat password diubah
            if (key === 'password' && document.getElementById('createConfirmPassword').value) cuShowError('confirm', val().errors.confirm);
        });
    });
})();

// Validasi form Tambah User Baru. Aturan sama dengan server (register_user): email valid, disimpan huruf kecil,
// password minimal 8 karakter, konfirmasi harus sama. Mengembalikan pesan per kolom.
const CU_MIN_PASSWORD = 8;
function cuValidate({ email, password, confirm }) {
    const errors = {};
    const clean = String(email || '').trim().toLowerCase();
    if (!clean) errors.email = 'Email wajib diisi.';
    else if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(clean)) errors.email = 'Format email tidak valid, contoh: nama@undip.ac.id';
    const pw = String(password || '');
    if (!pw.trim()) errors.password = 'Password wajib diisi.';
    else if (pw.trim().length < CU_MIN_PASSWORD) errors.password = `Password minimal ${CU_MIN_PASSWORD} karakter.`;
    if (!confirm) errors.confirm = 'Ketik ulang password.';
    else if (confirm !== pw) errors.confirm = 'Konfirmasi password tidak sama.';
    return { ok: Object.keys(errors).length === 0, email: clean, errors };
}

async function handleCreateUserSubmit(e) {
    e.preventDefault();
    const password = document.getElementById('createPassword').value;
    const check = cuValidate({
        email: document.getElementById('createUsername').value,
        password,
        confirm: document.getElementById('createConfirmPassword').value
    });
    Object.keys(CU_FIELDS).forEach(k => cuShowError(k, check.errors[k]));
    const alert = document.getElementById('createUserErrorMsg');
    alert.hidden = true;
    if (!check.ok) {
        // Fokus ke kolom pertama yang salah
        const first = Object.keys(CU_FIELDS).find(k => check.errors[k]);
        document.getElementById(CU_FIELDS[first][0])?.focus();
        return;
    }
    const role = document.querySelector('#createUserModalOverlay input[name="cu_role"]:checked')?.value || 'user';
    const submit = document.getElementById('cuSubmitBtn');
    submit.disabled = true;
    submit.textContent = 'Membuat akun...';

    try {
        const resp = await fetch(`${API_BASE}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: check.email, password, role })
        });
        const data = await resp.json().catch(() => ({}));

        if (resp.ok) {
            showToast('Akun dibuat', `${check.email} bisa masuk sebagai ${role === 'admin' ? 'Admin' : 'User'}.`, '', { type: 'success' });
            closeCreateUserModal();
            loadAdminUsers();
            return;
        }
        const detail = data.detail || 'Gagal membuat akun.';
        // Galat yang menyangkut satu kolom ditampilkan di bawah kolom itu
        if (/email/i.test(detail)) { cuShowError('email', detail); document.getElementById('createUsername').focus(); }
        else if (/password/i.test(detail)) { cuShowError('password', detail); document.getElementById('createPassword').focus(); }
        else { alert.textContent = detail; alert.hidden = false; }
    } catch (err) {
        alert.textContent = 'Gagal menghubungi server. Coba lagi beberapa saat.';
        alert.hidden = false;
    } finally {
        submit.disabled = false;
        submit.textContent = 'Buat akun';
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
    const roleVal = document.getElementById('userRoleFilter')?.value || '';

    filteredAdminUsers = allAdminUsers.filter(u => {
        if (roleVal && u.role !== roleVal) return false;
        if (!searchVal) return true;
        return (u.username && u.username.toLowerCase().includes(searchVal)) ||
            (u.role && u.role.toLowerCase().includes(searchVal));
    });

    // Sort logic: 
    // 1. Role: 'superadmin' > 'admin' > 'user'
    // 2. Status: online > offline
    // 3. Last Active: recent > older
    // 4. Username: A-Z
    const roleRank = { 'superadmin': 1, 'admin': 2, 'user': 3 };
    filteredAdminUsers.sort((a, b) => {
        const rankA = roleRank[a.role] || 4;
        const rankB = roleRank[b.role] || 4;
        if (rankA !== rankB) return rankA - rankB;

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

function getUserTimeoutInfo(u) {
    if (!u.timeout_until) return null;
    const timeoutDate = new Date(u.timeout_until);
    const now = new Date();
    if (!(timeoutDate > now)) return null;
    const diffSecs = Math.floor((timeoutDate - now) / 1000);
    return { mins: Math.floor(diffSecs / 60), secs: diffSecs % 60 };
}

function getUserInitials(username) {
    const base = String(username || '?').split('@')[0];
    const parts = base.split(/[._\-\s]+/).filter(Boolean);
    const letters = parts.length >= 2 ? parts[0][0] + parts[1][0] : base.slice(0, 2);
    return letters.toUpperCase();
}

function renderUserStats() {
    const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setText('userStatTotal', allAdminUsers.length);
    setText('userStatOnline', allAdminUsers.filter(u => u.is_online).length);
    setText('userStatTimeout', allAdminUsers.filter(u => getUserTimeoutInfo(u)).length);
}

function renderUserTable() {
    const tbody = document.getElementById('userTableBody');
    closeUserActionMenu();
    renderUserStats();
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
    const isSuperAdminCaller = currentUser && currentUser.role === 'superadmin';

    const roleMeta = {
        superadmin: { cls: 'um-role-superadmin', label: 'SUPER ADMIN' },
        admin: { cls: 'um-role-admin', label: 'ADMIN' },
        user: { cls: 'um-role-user', label: 'USER' }
    };

    tbody.innerHTML = paginatedUsers.map(u => {
        const isSelf = u.username === currentUser.username;
        const isProtectedSuperAdmin = u.role === 'superadmin' && currentUser.role !== 'superadmin';
        const isProtectedAdmin = u.role === 'admin' && currentUser.role === 'admin';
        const meta = roleMeta[u.role] || roleMeta.user;
        const name = escapeHtml(u.username);
        const timeout = getUserTimeoutInfo(u);

        const roleBadge = `<button type="button" class="um-role ${meta.cls}${isSuperAdminCaller ? ' um-role-clickable' : ''}"
            data-um-role="${name}" ${isSuperAdminCaller ? 'title="Lihat keterangan role"' : 'tabindex="-1"'}>${meta.label}</button>`;

        let status;
        if (u.is_online) {
            status = `<span class="um-status um-status-online"><span class="um-dot"></span>Online</span>`;
        } else if (timeout) {
            status = `<span class="um-status um-status-timeout"><span class="um-dot"></span>Timeout · sisa ${timeout.mins}m ${timeout.secs}s</span>`;
        } else {
            status = `<span class="um-status"><span class="um-dot"></span>${escapeHtml(formatRelativeTime(u.last_online))}</span>`;
        }

        let action;
        if (isSelf) {
            action = '';
        } else if (isProtectedSuperAdmin || isProtectedAdmin) {
            action = `<span class="um-locked" title="${isProtectedSuperAdmin ? 'Super Admin' : 'Admin'} (Terproteksi)">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
            </span>`;
        } else {
            action = `<button type="button" class="um-more" data-um-menu="${name}" aria-haspopup="menu" aria-label="Aksi untuk ${name}">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="1.8"></circle><circle cx="12" cy="12" r="1.8"></circle><circle cx="19" cy="12" r="1.8"></circle></svg>
            </button>`;
        }

        return `
            <tr>
                <td>
                    <div class="um-user">
                        <span class="um-avatar ${meta.cls}">${escapeHtml(getUserInitials(u.username))}</span>
                        <div class="um-user-text">
                            <div class="um-user-name">${name}${isSelf ? '<span class="um-you">Akun Anda</span>' : ''}</div>
                            ${u.created_at ? `<div class="um-user-sub">Dibuat ${escapeHtml(formatRelativeTime(u.created_at))}</div>` : ''}
                        </div>
                    </div>
                </td>
                <td>${roleBadge}</td>
                <td>${status}</td>
                <td class="um-muted">${u.created_by ? escapeHtml(u.created_by) : 'Sistem'}</td>
                <td class="um-col-actions">${action}</td>
            </tr>
        `;
    }).join('');

    renderUserPagination(totalItems);
}

// ---- Menu aksi per user (tombol "⋯") ----
let userActionMenuEl = null;
let userActionMenuAnchor = null;

function closeUserActionMenu() {
    if (userActionMenuEl) userActionMenuEl.remove();
    if (userActionMenuAnchor) {
        userActionMenuAnchor.classList.remove('active');
        userActionMenuAnchor.setAttribute('aria-expanded', 'false');
    }
    userActionMenuEl = null;
    userActionMenuAnchor = null;
}

function openUserActionMenu(anchor, username) {
    const u = allAdminUsers.find(x => x.username === username);
    if (!u) return;
    closeUserActionMenu();

    const timeout = getUserTimeoutInfo(u);
    const icon = {
        info: '<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line>',
        logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line>',
        pause: '<circle cx="12" cy="12" r="10"></circle><line x1="10" y1="15" x2="10" y2="9"></line><line x1="14" y1="15" x2="14" y2="9"></line>',
        unlock: '<rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path>',
        trash: '<polyline points="3 6 5 6 21 6"></polyline><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"></path>'
    };
    const item = (action, ic, label, hint, tone) => `
        <button type="button" role="menuitem" class="um-menu-item ${tone || ''}" data-um-action="${action}">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${icon[ic]}</svg>
            <span class="um-menu-text"><span class="um-menu-label">${label}</span>${hint ? `<span class="um-menu-hint">${hint}</span>` : ''}</span>
        </button>`;

    let html = '';
    if (currentUser && currentUser.role === 'superadmin') {
        html += item('info', 'info', 'Lihat detail', '', '') + '<div class="um-menu-divider"></div>';
    }
    html += item('force-logout', 'logout', 'Force Logout', 'Akhiri sesi aktif', 'um-tone-warn');
    html += timeout
        ? item('remove-timeout', 'unlock', 'Cabut Timeout', `Sisa ${timeout.mins}m ${timeout.secs}s`, 'um-tone-ok')
        : item('timeout', 'pause', 'Timeout', 'Blokir login sementara', 'um-tone-warn');
    html += '<div class="um-menu-divider"></div>' + item('delete', 'trash', 'Hapus', '', 'um-tone-danger');

    const menu = document.createElement('div');
    menu.className = 'um-menu';
    menu.setAttribute('role', 'menu');
    menu.dataset.username = username;
    menu.innerHTML = html;
    document.body.appendChild(menu);

    // Posisikan di bawah tombol, rata kanan; pindah ke atas jika tidak muat
    const r = anchor.getBoundingClientRect();
    const mw = menu.offsetWidth, mh = menu.offsetHeight;
    let left = Math.max(8, Math.min(r.right - mw, window.innerWidth - mw - 8));
    let top = r.bottom + 6;
    if (top + mh > window.innerHeight - 8) top = Math.max(8, r.top - mh - 6);
    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;

    anchor.classList.add('active');
    anchor.setAttribute('aria-expanded', 'true');
    userActionMenuEl = menu;
    userActionMenuAnchor = anchor;
    const first = menu.querySelector('.um-menu-item');
    if (first) first.focus({ preventScroll: true });
}

document.addEventListener('click', (e) => {
    const roleBtn = e.target.closest('[data-um-role]');
    if (roleBtn) {
        if (currentUser && currentUser.role === 'superadmin') showRoleInfoModal(roleBtn.dataset.umRole);
        return;
    }
    const moreBtn = e.target.closest('[data-um-menu]');
    if (moreBtn) {
        e.stopPropagation();
        if (userActionMenuAnchor === moreBtn) { closeUserActionMenu(); return; }
        openUserActionMenu(moreBtn, moreBtn.dataset.umMenu);
        return;
    }
    const menuItem = e.target.closest('.um-menu-item');
    if (menuItem && userActionMenuEl) {
        const username = userActionMenuEl.dataset.username;
        const action = menuItem.dataset.umAction;
        closeUserActionMenu();
        if (action === 'info') showRoleInfoModal(username);
        else if (action === 'force-logout') triggerForceLogout(username);
        else if (action === 'timeout') openTimeoutModal(username);
        else if (action === 'remove-timeout') triggerRemoveTimeout(username);
        else if (action === 'delete') triggerDeleteUser(username);
        return;
    }
    if (userActionMenuEl && !e.target.closest('.um-menu')) closeUserActionMenu();
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        if (userActionMenuEl) {
            const anchor = userActionMenuAnchor;
            closeUserActionMenu();
            if (anchor) anchor.focus();
        } else if (document.getElementById('deleteUserModalOverlay')?.classList.contains('active')) {
            closeDeleteUserModal();
        }
    }
});
window.addEventListener('resize', closeUserActionMenu);
document.addEventListener('scroll', closeUserActionMenu, true);

window.showRoleInfoModal = function(targetUsername) {
    if (!currentUser || currentUser.role !== 'superadmin') {
        return;
    }

    const modal = document.getElementById('userRoleInfoModalOverlay');
    const title = document.getElementById('userRoleInfoModalTitle');
    const sub = document.getElementById('userRoleInfoModalSub');
    const container = document.getElementById('userRoleInfoContainer');
    if (!modal || !container) return;

    const targetUser = allAdminUsers.find(x => x.username === targetUsername);
    if (!targetUser) return;

    const role = targetUser.role;

    if (role === 'admin') {
        const createdUsers = allAdminUsers.filter(x => x.created_by === targetUsername);
        if (title) title.textContent = `Keterangan Admin (${targetUsername})`;
        if (sub) sub.textContent = `Daftar akun user (${createdUsers.length}) yang telah dibuat oleh Admin '${targetUsername}':`;

        if (createdUsers.length === 0) {
            container.innerHTML = `
                <div style="text-align:center; padding:32px 16px; background:#f8fafc; border-radius:8px; border:1px solid #e2e8f0;">
                    <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="1.5" style="margin-bottom:8px;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    <p style="font-size:14px; font-weight:600; color:#475569; margin-bottom:4px;">Belum Membuat User</p>
                    <p style="font-size:12px; color:#94a3b8; margin:0;">Admin ini belum memiliki akun user yang dibuat/didaftarkan di bawahnya.</p>
                </div>
            `;
        } else {
            container.innerHTML = `
                <table class="modern-table" style="font-size:13px; width:100%; border-collapse:collapse;">
                    <thead>
                        <tr style="background:#f8fafc; border-bottom:1px solid #e2e8f0;">
                            <th style="padding:10px 12px; text-align:left;">Username</th>
                            <th style="padding:10px 12px; text-align:left;">Role</th>
                            <th style="padding:10px 12px; text-align:left;">Status</th>
                            <th style="padding:10px 12px; text-align:left;">Last Active</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${createdUsers.map(cu => {
                            const isOnline = cu.is_online;
                            const lastActive = isOnline ? "Baru saja" : (cu.last_online ? formatRelativeTime(cu.last_online) : "-");
                            let stBadge = isOnline ? '<span class="status-indicator status-online">Online</span>' : '<span class="status-indicator status-offline">Offline</span>';
                            if (cu.timeout_until && new Date(cu.timeout_until) > new Date()) {
                                stBadge = '<span class="status-indicator status-timeout">Timeout</span>';
                            }
                            return `
                                <tr style="border-bottom:1px solid #f1f5f9;">
                                    <td style="font-weight:600; padding:10px 12px;">${escapeHtml(cu.username)}</td>
                                    <td style="padding:10px 12px;"><span class="badge-user-role">User</span></td>
                                    <td style="padding:10px 12px;">${stBadge}</td>
                                    <td style="padding:10px 12px; color:var(--text-secondary);">${lastActive}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            `;
        }
    } else if (role === 'user') {
        if (title) title.textContent = `Keterangan User (${targetUsername})`;
        if (sub) sub.textContent = `Informasi pembuat akun user '${targetUsername}':`;

        const creator = targetUser.created_by;
        container.innerHTML = `
            <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:20px; display:flex; flex-direction:column; gap:16px;">
                <div style="display:flex; align-items:center; gap:14px;">
                    <div style="width:44px; height:44px; border-radius:50%; background:#eff6ff; border:1px solid #bfdbfe; display:flex; align-items:center; justify-content:center; color:#1d4ed8; flex-shrink:0;">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="8.5" cy="7" r="4"></circle><polyline points="17 11 19 13 23 9"></polyline></svg>
                    </div>
                    <div>
                        <div style="font-size:12px; color:#64748b; font-weight:500;">Dibuat Oleh Admin:</div>
                        <div style="font-size:15px; font-weight:700; color:var(--color-ink);">
                            ${creator ? escapeHtml(creator) : '<span style="color:#94a3b8; font-weight:normal; font-style:italic;">System / Registrasi Mandiri</span>'}
                        </div>
                    </div>
                </div>

                <div style="border-top:1px solid #e2e8f0; padding-top:14px; display:grid; grid-template-columns: 1fr 1fr; gap:12px; font-size:13px;">
                    <div>
                        <span style="color:#64748b; font-size:12px;">Username User:</span>
                        <div style="font-weight:600; color:#1e293b; margin-top:2px;">${escapeHtml(targetUser.username)}</div>
                    </div>
                    <div>
                        <span style="color:#64748b; font-size:12px;">Status Akun:</span>
                        <div style="margin-top:2px;">
                            ${targetUser.is_online ? '<span class="status-indicator status-online">Online</span>' : '<span class="status-indicator status-offline">Offline</span>'}
                        </div>
                    </div>
                </div>
            </div>
        `;
    } else if (role === 'superadmin') {
        if (title) title.textContent = `Keterangan Super Admin (${targetUsername})`;
        if (sub) sub.textContent = `Informasi role Super Admin:`;

        container.innerHTML = `
            <div style="background:#faf5ff; border:1px solid #e9d5ff; border-radius:8px; padding:20px; display:flex; flex-direction:column; gap:12px;">
                <div style="display:flex; align-items:center; gap:14px;">
                    <div style="width:44px; height:44px; border-radius:50%; background:#f3e8ff; border:1px solid #d8b4fe; display:flex; align-items:center; justify-content:center; color:#7e22ce; flex-shrink:0;">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"></path><path d="M2 17l10 5 10-5"></path><path d="M2 12l10 5 10-5"></path></svg>
                    </div>
                    <div>
                        <div style="font-size:15px; font-weight:700; color:#581c87;">Super Admin (Akses Tertinggi)</div>
                        <div style="font-size:12px; color:#7e22ce;">Pengelola Utama Sistem Dashboard Pentest</div>
                    </div>
                </div>
                <p style="font-size:13px; color:#6b21a8; line-height:1.5; margin:0;">
                    Akun ini merupakan Super Admin sistem yang dapat mengelola seluruh akun Admin dan User, memantau riwayat pemindaian, serta mengonfigurasi pengaturan keamanan.
                </p>
            </div>
        `;
    }

    modal.classList.add('active');
};

window.closeRoleInfoModal = function() {
    const modal = document.getElementById('userRoleInfoModalOverlay');
    if (modal) {
        modal.classList.remove('active');
    }
};

async function triggerForceLogout(username) {
    const confirmed = await customConfirm({
        title: 'Force Logout User',
        message: `Apakah Anda yakin ingin mengeluarkan user '${username}' secara paksa dari sistem?`,
        confirmText: 'Ya, Logout',
        cancelText: 'Batal',
        variant: 'warning'
    });
    if (!confirmed) return;

    try {
        const resp = await fetch(`${API_BASE}/api/admin/users/${username}/force-logout`, {
            method: 'POST'
        });
        const data = await resp.json();
        if (resp.status === 200) {
            showToast(`User '${username}' telah berhasil dikeluarkan dari sistem.`, "warning");
            loadAdminUsers();
            fetchNotifications();
        } else {
            showToast(data.detail || "Gagal melakukan force logout.", "error");
        }
    } catch (err) {
        showToast("Gagal menghubungi server.", "error");
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
        showToast("Masukkan durasi menit yang valid (minimal 1).", "warning");
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
            showToast(`User '${currentTimeoutUser}' ditangguhkan selama ${minutes} menit.`, "warning");
            closeTimeoutModal();
            loadAdminUsers();
            fetchNotifications();
        } else {
            showToast(data.detail || "Gagal melakukan penangguhan.", "error");
        }
    } catch (err) {
        showToast("Gagal menghubungi server.", "error");
    }
};

async function triggerRemoveTimeout(username) {
    const confirmed = await customConfirm({
        title: 'Cabut Timeout User',
        message: `Apakah Anda yakin ingin mencabut status penangguhan (timeout) user '${username}'?`,
        confirmText: 'Ya, Cabut Timeout',
        cancelText: 'Batal',
        variant: 'info'
    });
    if (!confirmed) return;

    try {
        const resp = await fetch(`${API_BASE}/api/admin/users/${username}/remove-timeout`, {
            method: 'POST'
        });
        const data = await resp.json();
        if (resp.status === 200) {
            showToast(`Penangguhan untuk user '${username}' berhasil dicabut!`, "success");
            loadAdminUsers();
            fetchNotifications();
        } else {
            showToast(data.detail || "Gagal mencabut status timeout.", "error");
        }
    } catch (err) {
        showToast("Gagal menghubungi server.", "error");
    }
}

// ---- Hapus user: dialog konfirmasi dengan mengetik username ----
let pendingDeleteUsername = null;

function triggerDeleteUser(username) {
    const modal = document.getElementById('deleteUserModalOverlay');
    const input = document.getElementById('deleteUserConfirmInput');
    const nameEl = document.getElementById('deleteUserModalName');
    const btn = document.getElementById('deleteUserConfirmBtn');
    if (!modal || !input || !btn) return;

    pendingDeleteUsername = username;
    if (nameEl) nameEl.textContent = username;
    input.value = '';
    input.placeholder = username;
    btn.disabled = true;
    btn.textContent = 'Hapus';
    modal.classList.add('active');
    setTimeout(() => input.focus(), 50);
}

window.closeDeleteUserModal = function () {
    pendingDeleteUsername = null;
    const modal = document.getElementById('deleteUserModalOverlay');
    if (modal) modal.classList.remove('active');
};

(function initDeleteUserModal() {
    const input = document.getElementById('deleteUserConfirmInput');
    const btn = document.getElementById('deleteUserConfirmBtn');
    const modal = document.getElementById('deleteUserModalOverlay');
    if (!input || !btn || !modal) return;
    input.addEventListener('input', () => {
        btn.disabled = !pendingDeleteUsername || input.value.trim() !== pendingDeleteUsername;
    });
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !btn.disabled) submitDeleteUser();
    });
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeDeleteUserModal();
    });
})();

window.submitDeleteUser = async function () {
    const username = pendingDeleteUsername;
    const input = document.getElementById('deleteUserConfirmInput');
    const btn = document.getElementById('deleteUserConfirmBtn');
    if (!username || !input || input.value.trim() !== username) return;

    btn.disabled = true;
    btn.textContent = 'Menghapus...';
    try {
        const resp = await fetch(`${API_BASE}/api/admin/users/${encodeURIComponent(username)}`, {
            method: 'DELETE'
        });
        const data = await resp.json();
        if (resp.status === 200) {
            closeDeleteUserModal();
            showToast(`User '${username}' berhasil dihapus dari sistem.`, "success");
            loadAdminUsers();
            fetchNotifications();
        } else {
            showToast(data.detail || "Gagal menghapus user.", "error");
            btn.disabled = false;
            btn.textContent = 'Hapus';
        }
    } catch (err) {
        showToast("Gagal menghubungi server.", "error");
        btn.disabled = false;
        btn.textContent = 'Hapus';
    }
};

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

// =========================================================
// DROPDOWN NOTIFIKASI (tab, grup per hari, ikon per jenis,
// tandai semua dibaca, hapus yang sudah dibaca + urungkan)
// =========================================================
let notifActiveTab = 'all';

const NOTIF_KIND = {
    scan_finished: { icon: 'scan', tone: 'nd-tone-ok' },
    scan_complete: { icon: 'scan', tone: 'nd-tone-ok' },
    success: { icon: 'success', tone: 'nd-tone-ok' },
    scan_failed: { icon: 'error', tone: 'nd-tone-danger' },
    domain_request: { icon: 'inbox', tone: 'nd-tone-warn' },
    domain_found: { icon: 'domain', tone: 'nd-tone-purple' },
    domain_approval_result: { icon: 'approved', tone: 'nd-tone-ok' },
    info: { icon: 'info', tone: 'nd-tone-info' }
};
const NOTIF_EXTRA_ICONS = {
    inbox: '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"></polyline><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path>',
    approved: '<path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z"></path><path d="m9 12 2 2 4-4"></path>',
    rejected: '<circle cx="12" cy="12" r="10"></circle><path d="m15 9-6 6"></path><path d="m9 9 6 6"></path>'
};

function notifIconHtml(name) {
    const paths = NOTIF_EXTRA_ICONS[name] || TOAST_ICON_PATHS[name] || TOAST_ICON_PATHS.info;
    return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
}

// Status baca notifikasi disimpan di server per akun, jadi sama di semua perangkat.
// notifReadSet berisi id yang sudah dibaca (dimuat ulang tiap fetchNotifications).
let notifReadSet = new Set();
const notifReadInflight = new Set();
let notifLegacyChecked = false;
const NOTIF_LEGACY_READ_KEY = 'dsti_read_notifs';  // tempat status baca versi lama

function notifReadIds() { return [...notifReadSet]; }

function notifSaveRead(ids) {
    const fresh = (ids || []).map(String).filter(id => id && !notifReadSet.has(id));
    if (!fresh.length) return;
    fresh.forEach(id => { notifReadSet.add(id); notifReadInflight.add(id); });
    fetch(`${API_BASE}/api/notifications/read`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: fresh })
    })
        .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); })
        .catch(err => console.warn('Gagal menyimpan status baca notifikasi:', err))
        .finally(() => fresh.forEach(id => notifReadInflight.delete(id)));
}

// Sekali per pemuatan: kirim status baca lama dari localStorage (versi sebelumnya) ke server, lalu hapus
function notifMigrateLegacyRead() {
    if (notifLegacyChecked) return;
    notifLegacyChecked = true;
    let legacy = [];
    try { legacy = JSON.parse(localStorage.getItem(NOTIF_LEGACY_READ_KEY) || '[]'); } catch (e) { legacy = []; }
    if (!Array.isArray(legacy) || !legacy.length) return;
    const ids = [...new Set(legacy.map(String))].slice(-500);
    fetch(`${API_BASE}/api/notifications/read`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids })
    }).then(r => {
        if (!r.ok) return;  // dicoba lagi saat halaman dimuat berikutnya
        try { localStorage.removeItem(NOTIF_LEGACY_READ_KEY); } catch (e) { /* abaikan */ }
        ids.forEach(id => notifReadSet.add(id));
        allNotifications.forEach(n => { if (notifReadSet.has(n.id)) n.unread = false; });
        renderNotificationList();
    }).catch(() => { /* dicoba lagi saat halaman dimuat berikutnya */ });
}

// Kabar live permintaan dan persetujuan domain. Mengembalikan toast (atau null) dan apakah lonceng disegarkan.
// - Permintaan baru: toast hanya untuk superadmin (yang memutuskan); lonceng admin & superadmin disegarkan.
// - Disetujui / ditolak: toast hanya untuk admin yang mengajukan; lonceng admin & superadmin disegarkan.
// - Role user tidak menerima notifikasi domain.
function liveDomainNotice(data, user) {
    const none = { toast: null, refreshBell: false };
    if (!user || user.role === 'user') return none;
    const domain = data.domain_name || 'domain';
    if (data.event === 'pending_domain_created') {
        return {
            toast: user.role === 'superadmin'
                ? { title: 'Permintaan domain baru', message: `${domain} diajukan oleh ${data.requested_by || 'admin'}. Menunggu persetujuan Anda.`, type: 'info' }
                : null,
            refreshBell: true
        };
    }
    if (data.event === 'domain_approval_result') {
        const mine = data.requested_by && data.requested_by === user.username;
        const approved = data.action === 'approved';
        return {
            toast: mine
                ? (approved
                    ? { title: 'Domain disetujui', message: `${domain} sudah masuk Domain Inventory.`, type: 'success' }
                    : { title: 'Domain ditolak', message: `${domain} ditolak oleh ${data.rejected_by || 'Super Admin'}.`, type: 'warning' })
                : null,
            refreshBell: true
        };
    }
    return none;
}

// Dibaca di tab atau perangkat lain milik akun yang sama
function notifApplyRemoteRead(ids) {
    (ids || []).map(String).forEach(id => {
        notifReadSet.add(id);
        const scanToast = document.getElementById(`scan-toast-${id}`);
        if (scanToast) scanToast.remove();
        const nightToast = document.getElementById(`overnight-toast-${id}`);
        if (nightToast) nightToast.remove();
        if (activeOvernightToastTimers[id]) {
            clearTimeout(activeOvernightToastTimers[id]);
            delete activeOvernightToastTimers[id];
        }
    });
    allNotifications.forEach(n => { if (notifReadSet.has(n.id)) n.unread = false; });
    renderNotificationList();
}
function notifDeletedIds() { return JSON.parse(localStorage.getItem('dsti_deleted_notifs_v3') || '[]'); }

function notifShortTime(ts) {
    const d = new Date(ts);
    if (!ts || isNaN(d)) return '';
    const now = new Date();
    const diffMin = Math.floor((now - d) / 60000);
    const hhmm = d.toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit' }).replace('.', ':');
    if (diffMin < 1) return 'Baru saja';
    if (diffMin < 60) return `${diffMin} mnt`;
    const startToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    if (d >= startToday) return hhmm;
    if (d >= new Date(startToday - 86400000)) return `Kemarin ${hhmm}`;
    return d.toLocaleDateString('id-ID', { day: 'numeric', month: 'short' });
}

function notifGroupLabel(ts) {
    const d = new Date(ts);
    if (!ts || isNaN(d)) return 'LEBIH LAMA';
    const now = new Date();
    const startToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    if (d >= startToday) return 'HARI INI';
    if (d >= new Date(startToday - 86400000)) return 'KEMARIN';
    return 'LEBIH LAMA';
}

function updateNotificationBadge() {
    const badge = document.getElementById('notificationBadge');
    const unreadCount = allNotifications.filter(n => n.unread).length;
    if (badge) {
        badge.textContent = unreadCount > 99 ? '99+' : unreadCount;
        badge.style.display = unreadCount > 0 ? 'flex' : 'none';
    }
    const pill = document.getElementById('notifNewPill');
    if (pill) {
        pill.hidden = unreadCount === 0;
        pill.textContent = `${unreadCount} baru`;
    }
    const all = document.getElementById('notifCountAll');
    const unread = document.getElementById('notifCountUnread');
    if (all) all.textContent = allNotifications.length;
    if (unread) unread.textContent = unreadCount;
    const markAll = document.getElementById('notifMarkAllBtn');
    if (markAll) markAll.disabled = unreadCount === 0;
    const clearRead = document.getElementById('notifClearReadBtn');
    if (clearRead) clearRead.disabled = !allNotifications.some(n => !n.unread);
}

function clearBadge() {
    updateNotificationBadge();
}

function renderNotificationList() {
    const listContainer = document.getElementById('notificationList');
    if (!listContainer) return;
    updateNotificationBadge();

    document.querySelectorAll('[data-notif-tab]').forEach(t => {
        const active = t.dataset.notifTab === notifActiveTab;
        t.classList.toggle('active', active);
        t.setAttribute('aria-selected', active ? 'true' : 'false');
    });

    const items = notifActiveTab === 'unread' ? allNotifications.filter(n => n.unread) : allNotifications;
    if (items.length === 0) {
        listContainer.innerHTML = `
            <div class="nd-empty">
                <span class="nd-empty-icon">${notifIconHtml('success')}</span>
                <strong>${notifActiveTab === 'unread' ? 'Semua sudah dibaca' : 'Tidak ada notifikasi'}</strong>
                <span>${notifActiveTab === 'unread' ? 'Tidak ada notifikasi baru saat ini.' : 'Notifikasi scan dan domain akan muncul di sini.'}</span>
            </div>`;
        return;
    }

    const isSuperAdmin = currentUser && currentUser.role === 'superadmin';
    let html = '';
    let lastGroup = null;
    items.forEach(n => {
        const group = notifGroupLabel(n.timestamp);
        if (group !== lastGroup) {
            html += `<div class="nd-group">${group}</div>`;
            lastGroup = group;
        }
        let kind = NOTIF_KIND[n.type] || NOTIF_KIND.info;
        const msgText = n.message || (n.domain ? `Scan untuk ${n.domain} telah selesai.` : 'Pesan sistem terbaru.');
        if (n.type === 'domain_approval_result' && /ditolak/i.test(`${n.title} ${n.message}`)) {
            kind = { icon: 'rejected', tone: 'nd-tone-danger' };
        }
        const id = escapeHtml(n.id);
        let extra = '';
        if (n.type === 'scan_finished' || n.type === 'scan_complete') {
            const risk = (/risk level\s*:\s*(\w+)/i.exec(msgText) || [])[1];
            const riskUp = String(risk || '').toUpperCase();
            const riskCls = { CRITICAL: 'nd-chip-crit', HIGH: 'nd-chip-high', MEDIUM: 'nd-chip-med', LOW: 'nd-chip-low', INFO: 'nd-chip-info', SAFE: 'nd-chip-safe' }[riskUp];
            // Warna ikon mengikuti risk level, bukan selalu hijau
            const tone = { CRITICAL: 'nd-tone-danger', HIGH: 'nd-tone-danger', MEDIUM: 'nd-tone-warn' }[riskUp];
            if (tone) kind = { ...kind, tone };
            extra = `${risk ? `<div class="nd-chips"><span class="nd-chip ${riskCls || ''}">Risk ${escapeHtml(risk.toUpperCase())}</span></div>` : ''}
                <span class="nd-link">Lihat hasil scan →</span>`;
        } else if (n.type === 'domain_found') {
            extra = '<span class="nd-link">Tinjau di Domain Inventory →</span>';
        } else if (n.type === 'domain_request' && isSuperAdmin && /^pending_dom_\d+$/.test(n.id)) {
            extra = `<div class="nd-actions">
                <button type="button" class="nd-btn nd-btn-primary" data-notif-approve="${id}">Setujui</button>
                <button type="button" class="nd-btn" data-notif-reject="${id}">Tolak</button>
            </div>`;
        }
        const showMsg = !(n.type === 'scan_finished' && /^risk level\s*:/i.test(msgText));
        html += `
            <div class="nd-item${n.unread ? ' unread' : ''}" role="button" tabindex="0" data-notif-id="${id}">
                <span class="nd-icon ${kind.tone}">${notifIconHtml(kind.icon)}</span>
                <div class="nd-content">
                    <div class="nd-title-row">
                        <span class="nd-title">${escapeHtml(n.title || 'Notifikasi Sistem')}</span>
                        <span class="nd-time" title="${escapeHtml(n.timestamp ? new Date(n.timestamp).toLocaleString('id-ID') : '')}">${escapeHtml(notifShortTime(n.timestamp))}</span>
                        ${n.unread ? '<span class="nd-dot" aria-label="Belum dibaca"></span>' : ''}
                        <button type="button" class="nd-delete" data-notif-delete="${id}" aria-label="Hapus notifikasi">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M18 6 6 18"></path><path d="m6 6 12 12"></path></svg>
                        </button>
                    </div>
                    ${showMsg ? `<div class="nd-message">${escapeHtml(msgText)}</div>` : ''}
                    ${extra}
                </div>
            </div>`;
    });
    listContainer.innerHTML = html;
}

function toggleNotificationDropdown(e) {
    if (e) e.stopPropagation();
    const dropdown = document.getElementById('notificationDropdown');
    const bell = document.getElementById('notificationBellBtn');
    const isHidden = dropdown.style.display === 'none';
    dropdown.style.display = isHidden ? 'flex' : 'none';
    if (bell) {
        bell.classList.toggle('active', isHidden);
        bell.setAttribute('aria-expanded', isHidden ? 'true' : 'false');
    }
    if (isHidden) renderNotificationList();
}

function closeNotificationDropdown() {
    const dropdown = document.getElementById('notificationDropdown');
    const bell = document.getElementById('notificationBellBtn');
    if (dropdown) dropdown.style.display = 'none';
    if (bell) {
        bell.classList.remove('active');
        bell.setAttribute('aria-expanded', 'false');
    }
}

document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('notificationDropdown');
    const bellBtn = document.getElementById('notificationBellBtn');
    if (!dropdown || dropdown.style.display === 'none') return;
    if (e.target && !e.target.isConnected) return;
    if (!dropdown.contains(e.target) && !(bellBtn && bellBtn.contains(e.target))) closeNotificationDropdown();
});

document.addEventListener('keydown', (e) => {
    const dropdown = document.getElementById('notificationDropdown');
    if (e.key === 'Escape' && dropdown && dropdown.style.display !== 'none') {
        closeNotificationDropdown();
        document.getElementById('notificationBellBtn')?.focus();
    }
});

(function initNotificationDropdown() {
    const dropdown = document.getElementById('notificationDropdown');
    if (!dropdown) return;
    dropdown.addEventListener('click', (e) => {
        const tab = e.target.closest('[data-notif-tab]');
        if (tab) {
            notifActiveTab = tab.dataset.notifTab;
            renderNotificationList();
            return;
        }
        const del = e.target.closest('[data-notif-delete]');
        if (del) { deleteNotification(del.dataset.notifDelete, e); return; }
        const approve = e.target.closest('[data-notif-approve]');
        const reject = e.target.closest('[data-notif-reject]');
        if (approve || reject) {
            e.stopPropagation();
            const id = (approve || reject).dataset[approve ? 'notifApprove' : 'notifReject'];
            const n = allNotifications.find(x => x.id === id);
            const domainId = parseInt(id.replace('pending_dom_', ''), 10);
            if (!n || isNaN(domainId)) return;
            if (approve) triggerApproveDomain(domainId, n.domain || '');
            else triggerRejectDomain(domainId, n.domain || '');
            return;
        }
        const item = e.target.closest('[data-notif-id]');
        if (item) markAsRead(item.dataset.notifId);
    });
    dropdown.addEventListener('keydown', (e) => {
        const item = e.target.closest && e.target.closest('[data-notif-id]');
        if (item && e.target === item && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            markAsRead(item.dataset.notifId);
        }
    });
})();

function markAllNotificationsRead(e) {
    if (e) e.stopPropagation();
    const readNotifs = notifReadIds();
    allNotifications.forEach(n => {
        if (n.unread && !readNotifs.includes(n.id)) readNotifs.push(n.id);
        n.unread = false;
    });
    notifSaveRead(readNotifs);
    renderNotificationList();
}

// Dipertahankan untuk pemanggil lama
async function markAllNotificationsAsRead(e) {
    markAllNotificationsRead(e);
}

function clearReadNotifications(e) {
    if (e) e.stopPropagation();
    const readOnes = allNotifications.filter(n => !n.unread);
    if (readOnes.length === 0) return;
    const before = notifDeletedIds();
    const deleted = [...before];
    readOnes.forEach(n => { if (!deleted.includes(n.id)) deleted.push(n.id); });
    localStorage.setItem('dsti_deleted_notifs_v3', JSON.stringify(deleted));
    allNotifications = allNotifications.filter(n => n.unread);
    renderNotificationList();
    showToast(`${readOnes.length} notifikasi dihapus dari daftar.`, 'info', null, {
        title: 'Notifikasi dihapus',
        duration: 6000,
        actions: [{
            label: 'Urungkan', onClick: () => {
                localStorage.setItem('dsti_deleted_notifs_v3', JSON.stringify(before));
                fetchNotifications();
            }
        }]
    });
}

async function fetchNotifications() {
    try {
        const res = await fetch(`${API_BASE}/api/notifications`);
        const data = await res.json();
        if (data.status === 'success') {
            const allowedTypes = ['success', 'scan_complete', 'scan_finished', 'scan_failed', 'domain_found', 'info', 'domain_request', 'domain_approval_result']; 
            const deletedNotifs = JSON.parse(localStorage.getItem('dsti_deleted_notifs_v3') || '[]');
            if (Array.isArray(data.read_ids)) {
                // yang masih dalam perjalanan ke server tetap dianggap dibaca
                notifReadSet = new Set([...data.read_ids.map(String), ...notifReadInflight]);
            }
            const readNotifs = notifReadIds();

            allNotifications = data.data
                .filter(n => allowedTypes.includes(n.type) && !deletedNotifs.includes(String(n.id)))
                .map(n => ({
                    id: String(n.id),
                    title: n.title,
                    message: n.message,
                    type: n.type,
                    timestamp: n.created_at,
                    unread: !n.is_read && !readNotifs.includes(String(n.id)),
                    domain: n.domain,
                    time: n.time || n.created_at
                }));

            const pendingOsint = JSON.parse(localStorage.getItem('dsti_pending_osint') || '[]');
            pendingOsint.forEach(notif => {
                if (!deletedNotifs.includes(String(notif.id))) {
                    allNotifications.push({
                        id: String(notif.id),
                        title: notif.title,
                        message: notif.message,
                        type: notif.type,
                        timestamp: notif.created_at,
                        unread: !readNotifs.includes(String(notif.id)), 
                        new_domains: notif.new_domains
                    });
                }
            });

            allNotifications.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

            renderNotificationList();
            notifMigrateLegacyRead();
        }
    } catch (e) {
        console.error('Gagal fetch notifikasi', e);
    }
}



async function markAsRead(notifId) {
    const notif = allNotifications.find(n => n.id === notifId);
    if (!notif) return;

    // Tandai sebagai read, jangan dihapus
    const readNotifs = notifReadIds();
    if (!readNotifs.includes(notifId)) readNotifs.push(notifId);
    notifSaveRead(readNotifs);

    notif.unread = false;
    renderNotificationList();

    // Tindakan spesifik ketika notifikasi diklik
    if (notif) {
        closeNotificationDropdown();

        if (notif.type === 'scan_finished') {
            await loadVulnerabilities(true);
            jumpToScanDetail(notif.time, notif.domain, false);

            // Coba buka modal scan berdasarkan ID scan (jika ID numerik)
            const scanId = notif.id && !isNaN(Number(notif.id)) ? String(notif.id) : null;
            if (scanId && typeof openScanModalByScanId === 'function') {
                if (openScanModalByScanId(scanId)) return;
            }

            // Coba buka modal scan berdasarkan nama domain
            if (notif.domain && typeof openScanModalByDomainName === 'function') {
                if (openScanModalByDomainName(notif.domain)) return;
            }

            // Fallback jumpToScanDetail
            jumpToScanDetail(notif.time, notif.domain, false, scanId);
        } else if (notif.type === 'domain_found') {
            if (typeof switchView === 'function') switchView('inventory');
            if (notif.new_domains && notif.new_domains.length > 0) {
                const searchInput = document.getElementById('domainSearchInput');
                if (searchInput) {
                    searchInput.value = notif.new_domains.map(d => `"${d}"`).join(" "); 
                    domainCurrentPage = 1;
                    if (typeof loadDomains === 'function') loadDomains();
                }
            }
        }
    }
}

// WebSockets Client
function connectLiveWebSocket(sessionId) {
    if (wsLive) {
        wsLive.close();
    }

    let wsUrl = `${API_BASE}/ws/live?session_id=${sessionId}`;
    wsUrl = wsUrl.replace(/^http/, 'ws');

    wsLive = new WebSocket(wsUrl);

    wsLive.onopen = () => {
        console.log("[WebSocket] Terkoneksi ke Live Session.");
        if (wsEverConnected) {
            // Tersambung kembali: kabar selama terputus mungkin terlewat
            refreshData(true);
            if (typeof loadOverview === 'function') loadOverview();
            // Notifikasi yang datang saat terputus juga diambil ulang
            if (currentUser) fetchNotifications();
        }
        wsEverConnected = true;
    };

    wsLive.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);

            if (data.event === 'new_notification' && data.notification && data.notification.type === 'scan_finished') {
                // Scan selesai: untuk semua role (user boleh melihat Scan History)
                if (currentUser) {
                    showScanFinishedToast(data.notification);
                    fetchNotifications();
                }
            } else if (data.event === 'new_notification') {
                if (currentUser && (currentUser.role === 'admin' || currentUser.role === 'superadmin')) {
                    if (data.notification.type === 'domain_found' || data.notification.type === 'info') {
                        let pendingOsint = JSON.parse(localStorage.getItem('dsti_pending_osint') || '[]');
                        if (!pendingOsint.find(n => n.id === data.notification.id)) {
                            pendingOsint.push(data.notification);
                            localStorage.setItem('dsti_pending_osint', JSON.stringify(pendingOsint));
                        }
                        
                        if (data.notification.type === 'domain_found') {
                            showDomainFoundToast(data.notification);
                        } else {
                            showToast(data.notification.title, data.notification.message, "");
                        }
                    } else {
                        showToast(data.notification.title, data.notification.message, "");
                    }
                    fetchNotifications();
                }
            } else if (data.event === 'user_login') {
                if (currentUser && (currentUser.role === 'admin' || currentUser.role === 'superadmin') && data.username !== currentUser.username) {
                    const activeNav = document.querySelector('.sidebar-nav .nav-item.active');
                    if (activeNav && activeNav.getAttribute('onclick').includes('admin')) {
                        loadAdminUsers();
                        fetchNotifications();
                    }
                }
            } else if (data.event === 'scan_finished') {
                // Scan selesai: riwayat, tabel, angka KPI, dan grafik Overview diperbarui tanpa refresh
                if (typeof fetchActiveScans === 'function' && currentUser && currentUser.role !== 'user') fetchActiveScans();
                if (typeof refreshData === 'function') refreshData(true);
                if (typeof loadOverview === 'function') loadOverview();
            } else if (data.event === 'pending_domain_created' || data.event === 'domain_approval_result') {
                const notice = liveDomainNotice(data, currentUser);
                if (notice.toast) showToast(notice.toast.title, notice.toast.message, '', { type: notice.toast.type });
                if (notice.refreshBell) fetchNotifications();
            } else if (data.event === 'notifs_read') {
                notifApplyRemoteRead(data.ids);
            } else if (data.event === 'data_changed') {
                // Domain atau jadwal diubah (di browser ini atau lain): muat ulang bagian terkait sekali
                clearTimeout(dataChangedTimer);
                dataChangedTimer = setTimeout(() => {
                    const what = data.what || [];
                    if (what.includes('domains') && typeof loadDomains === 'function') loadDomains(true);
                    if (what.includes('schedules') && typeof fetchScheduledScans === 'function' && currentUser && currentUser.role !== 'user') fetchScheduledScans();
                    if (typeof renderLowerGrid === 'function') renderLowerGrid();
                }, 400);
            } else if (data.event === 'force_logout') {
                window.kickedReason = 'force_logout';
                showToast("Sesi Diakhiri", "Anda telah dipaksa keluar oleh Administrator.", "️");
                setTimeout(() => {
                    handleLogout();
                }, 1000);
            } else if (data.event === 'timeout') {
                window.kickedReason = 'timeout';
                showToast("Akun Ditangguhkan", "Akun Anda telah ditangguhkan oleh Administrator.", "");
                setTimeout(() => {
                    handleLogout();
                }, 1000);
            } else if (data.event === 'system_settings_updated') {
                window.systemSettings = data.settings;
                const viewSettingEl = document.getElementById('view-system-settings');
                if (viewSettingEl && !viewSettingEl.classList.contains('hidden')) {
                    loadSystemSettings();
                }
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
        } else if (e.code === 4000) {
            // Jika kode 4000, berarti user di-kick (force logout / timeout)
            if (!window.kickedReason) {
                showToast("Sesi Diakhiri", "Anda telah dikeluarkan oleh sistem.", "️");
                setTimeout(() => {
                    handleLogout();
                }, 500);
            }
            window.kickedReason = null;
        }
    };
}



window.copyToClipboard = function(text, event, label = 'IP Address') {
    if (event) event.stopPropagation();
    if (!text || text === '-' || text.trim() === '') {
        showToast('Info', 'Tidak ada data untuk disalin', 'ℹ️');
        return;
    }

    const cleanText = text.trim();
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(cleanText).then(() => {
            showToast('Tersalin', `${label} ${cleanText} berhasil disalin ke clipboard!`, '');
        }).catch(err => {
            console.error('Clipboard error:', err);
            fallbackCopyText(cleanText, label);
        });
    } else {
        fallbackCopyText(cleanText, label);
    }
};

function fallbackCopyText(text, label) {
    try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast('Tersalin', `${label} ${text} berhasil disalin ke clipboard!`, '');
    } catch (e) {
        showToast('Error', 'Gagal menyalin ke clipboard', '');
    }
}

// Toast notifikasi pagi (07:00 WIB) & sinkronisasi status dibaca
let activeOvernightToastTimers = {};

function markNotificationReadByScanId(scanId) {
    if (!scanId) return;
    const strId = String(scanId);
    const readNotifs = notifReadIds();
    if (!readNotifs.includes(strId)) {
        readNotifs.push(strId);
        notifSaveRead(readNotifs);
    }

    // Perbarui state lokal notifikasi di memori (jika ada)
    if (typeof allNotifications !== 'undefined' && Array.isArray(allNotifications)) {
        allNotifications.forEach(n => {
            if (String(n.id) === strId) {
                n.unread = false;
            }
        });
    }

    // Batalkan timer retry 5 menit jika ada
    if (activeOvernightToastTimers[strId]) {
        clearTimeout(activeOvernightToastTimers[strId]);
        delete activeOvernightToastTimers[strId];
    }

    updateNotificationBadge();
    if (typeof renderNotificationList === 'function') {
        renderNotificationList();
    }
}
let lastOvernightCheckTime = 0;

async function checkOvernightNotifications() {
    if (!currentUser) return; 

    const nowObj = new Date();
    const utcTime = nowObj.getTime() + (nowObj.getTimezoneOffset() * 60000);
    const wibTime = new Date(utcTime + (3600000 * 7));
    if (wibTime.getHours() < 7) return;

    const now = Date.now();
    if (now - lastOvernightCheckTime < 10000) return;
    lastOvernightCheckTime = now;

    try {
        const res = await fetch(`${API_BASE}/api/notifications/overnight-scans`);
        const data = await res.json();
        
        if (data.status === 'success' && data.data && data.data.length > 0) {
            const readNotifs = notifReadIds();
            
            const unreadOvernightScans = data.data.filter(scan => !readNotifs.includes(String(scan.id)));

            if (unreadOvernightScans.length > 0) {
                const primaryScan = unreadOvernightScans[0];
                const scanIdStr = String(primaryScan.id);

                const isCurrentlyOnScreen = document.getElementById(`overnight-toast-${scanIdStr}`);

                if (!activeOvernightToastTimers[scanIdStr] && !isCurrentlyOnScreen) {
                    showOvernightToastNotification(unreadOvernightScans);
                }
            }
        }
    } catch (e) {
        console.error('Gagal mengecek notifikasi overnight:', e);
    }
}

function showOvernightToastNotification(scanData) {
    if (!currentUser) return; // Jangan tampilkan toast jika pengguna belum login
    const unreadScans = Array.isArray(scanData) ? scanData : [scanData];
    if (unreadScans.length === 0) return;


    const primaryScan = unreadScans[0];
    const scanIdStr = String(primaryScan.id);
    const domainName = primaryScan.domain_name || primaryScan.domains?.domain_name || '';

    // Hapus toast sebelumnya jika masih ada di DOM atau cegah duplikasi jika toast domain ini sudah aktif
    const existingById = document.getElementById(`overnight-toast-${scanIdStr}`);
    if (existingById) existingById.remove();

    const existingByDomain = domainName ? document.querySelector(`.toast-notification[data-domain="${domainName}"]`) : null;
    if (existingByDomain) return;

    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.id = `overnight-toast-${scanIdStr}`;
    if (domainName) toast.setAttribute('data-domain', domainName);
    toast.className = 'toast-notification overnight-toast';

    let toastMessage = '';
    const isSingleScan = unreadScans.length === 1;

    if (isSingleScan) {
        const domainName = primaryScan.domain_name || primaryScan.domains?.domain_name || 'Target';
        const riskLvl = (primaryScan.risk_level || 'HIGH').toUpperCase();
        toastMessage = `Ditemukan 1 hasil scan berisiko <strong>${riskLvl}</strong> pada domain <strong>${escapeHtml(domainName)}</strong> dari auto-scan semalam. Cek detail`;
    } else {
        toastMessage = `Ditemukan <strong>${unreadScans.length} hasil scan</strong> berisiko HIGH & CRITICAL dari auto-scan semalam. Cek detail`;
    }



    toast.innerHTML = `
        <div class="toast-icon">️</div>
        <div class="toast-body" style="width: 100%;">
            <div class="toast-title">Auto Scan Dini Hari (HIGH & CRITICAL)</div>
            <div class="toast-message">${toastMessage}</div>
            <div class="toast-actions-row">
                <button class="toast-btn toast-btn-primary" id="btnCekDetail-${scanIdStr}">Cek Detail</button>
                <button class="toast-btn toast-btn-secondary" id="btnCloseNotif-${scanIdStr}">Tutup </button>
            </div>
        </div>
    `;

    container.appendChild(toast);

    // Otomatis tutup setelah 60 detik (1 menit) jika tidak diklik
    const autoDismissTimer = setTimeout(() => {
        if (toast.parentNode) {
            toast.remove();
        }
        scheduleOvernightRetry(primaryScan);
    }, 60000);

    // Tombol "Cek Detail"
    const btnCekDetail = document.getElementById(`btnCekDetail-${scanIdStr}`);
    if (btnCekDetail) {
        btnCekDetail.onclick = (e) => {
            e.stopPropagation();
            clearTimeout(autoDismissTimer);
            toast.remove();
            
            unreadScans.forEach(s => markNotificationReadByScanId(s.id));

            if (isSingleScan) {
                // JIKA HANYA 1 SCAN: Langsung buka modal scan detail tanpa navigasi ke scan history
                openScanModal(primaryScan);
            } else {
                // JIKA LEBIH DARI 1 SCAN: Pindah ke Scan History, pasang filter tanggal & filter HIGH/CRITICAL
                window.overnightRiskFilter = true;

                if (typeof switchView === 'function') {
                    switchView('vulnerabilities');
                }

                let scanDateStr = '';
                if (primaryScan.scan_date) {
                    const d = new Date(primaryScan.scan_date);
                    if (!isNaN(d.getTime())) {
                        const year = d.getFullYear();
                        const month = String(d.getMonth() + 1).padStart(2, '0');
                        const day = String(d.getDate()).padStart(2, '0');
                        scanDateStr = `${year}-${month}-${day}`;
                    }
                }

                const startInput = document.getElementById('vulnStartDate');
                const endInput = document.getElementById('vulnEndDate');
                if (startInput && scanDateStr) startInput.value = scanDateStr;
                if (endInput && scanDateStr) endInput.value = scanDateStr;
                rpSyncFromInputs('scanHistory');

                if (typeof applyVulnFilters === 'function') {
                    applyVulnFilters();
                }
            }
        };
    }

    // Tombol "Tutup "
    const btnClose = document.getElementById(`btnCloseNotif-${scanIdStr}`);
    if (btnClose) {
        btnClose.onclick = (e) => {
            e.stopPropagation();
            clearTimeout(autoDismissTimer);
            toast.remove();
            
            scheduleOvernightRetry(primaryScan);
        };
    }
}


function scheduleOvernightRetry(scan) {
    const scanIdStr = String(scan.id);
    if (activeOvernightToastTimers[scanIdStr]) {
        clearTimeout(activeOvernightToastTimers[scanIdStr]);
    }

    // Jadwalkan pengulangan notifikasi setelah 5 menit (300.000 ms)
    activeOvernightToastTimers[scanIdStr] = setTimeout(() => {
        delete activeOvernightToastTimers[scanIdStr];
        const readNotifs = notifReadIds();
        if (!readNotifs.includes(scanIdStr)) {
            showOvernightToastNotification(scan);
        }
    }, 300000);
}

function initOvernightNotificationScheduler() {
    // Mengecek setiap 60 detik apakah waktu lokal berada pada / setelah jam 07:00 WIB
    setInterval(() => {
        const now = new Date();
        const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
        const wibTime = new Date(utc + (3600000 * 7));
        const hours = wibTime.getHours();
        
        if (hours >= 7) {
            checkOvernightNotifications();
        }
    }, 60000);

    // Cek awal saat aplikasi baru saja dibuka
    setTimeout(() => {
        checkOvernightNotifications();
    }, 2000);
}

// =========================================================
// SYSTEM SETTINGS v2
// - 4 pengaturan: force logout Super Admin, Admin, durasi sesi User, jam Overnight Scan.
// - Nilai diedit sebagai draf. Bar simpan muncul hanya bila draf berbeda dari yang tersimpan.
// - Tiap baris menjelaskan akibatnya (pengguna online, hitung mundur, domain aktif).
// =========================================================
const SS_DEFAULTS = { sa: '19:00', adm: '16:00', usr: '60', scan: '00:00' };
const SS_KEYS = { sa: 'force_logout_superadmin', adm: 'force_logout_admin', usr: 'force_logout_user_minutes', scan: 'scheduled_scan_hour' };
const SS_PER_NIGHT = 5; // sama dengan batch_size Overnight Scan di backend
const SS_FIELDS = {
    sa: { label: 'Super Admin dikeluarkan pukul', tag: ['SUPER ADMIN', 'is-sa'], desc: 'Setiap hari pada jam ini semua sesi Super Admin diakhiri.', type: 'time', presets: ['17:00', '18:00', '19:00', '20:00', '21:00', '22:00'], short: 'Super Admin dikeluarkan pukul' },
    adm: { label: 'Admin dikeluarkan pukul', tag: ['ADMIN', 'is-adm'], desc: 'Setiap hari pada jam ini semua sesi Admin diakhiri.', type: 'time', presets: ['14:00', '15:00', '16:00', '17:00', '18:00'], short: 'Admin dikeluarkan pukul' },
    usr: { label: 'Batas sesi User', tag: ['USER', 'is-usr'], desc: 'User biasa dikeluarkan setelah login selama durasi ini.', type: 'minutes', presets: ['15', '30', '45', '60', '90', '120'], short: 'Batas sesi User' },
    scan: { label: 'Mulai scan pukul', desc: 'Overnight Scan dimulai setiap hari pada jam ini.', type: 'time', presets: ['22:00', '23:00', '00:00', '01:00', '02:00', '03:00'], short: 'Overnight Scan mulai pukul' }
};
const SS_ICON = {
    clock: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>',
    timer: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="10" y1="2" x2="14" y2="2"></line><line x1="12" y1="14" x2="15" y2="11"></line><circle cx="12" cy="14" r="8"></circle></svg>',
    chev: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"></polyline></svg>',
    info: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>',
    alert: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>',
    undo: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 14 4 9l5-5"></path><path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H11"></path></svg>',
    check: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"></polyline></svg>',
    pencil: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"></path></svg>',
    out: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>',
    moon: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"></path></svg>'
};

let ssSaved = { ...SS_DEFAULTS };
let ssDraft = { ...SS_DEFAULTS };
let ssRaw = { ...SS_DEFAULTS }; // teks yang sedang diketik (bisa belum valid)
let ssUsers = null;
let ssDomains = null;
let ssSaveState = 'idle'; // idle | saving | error
let ssMenuKey = null;
let ssBuilt = false;
let ssTick = null;

window.systemSettings = null;

// "9" -> 09:00, "930" -> 09:30, "9.30" / "9:3" -> 09:30. null bila tidak valid.
function ssNormTime(v) {
    let s = String(v || '').trim().replace(/[.,\s]/g, ':');
    if (/^\d{1,2}$/.test(s)) s += ':00';
    else if (/^\d{3,4}$/.test(s)) s = s.slice(0, -2) + ':' + s.slice(-2);
    const m = s.match(/^(\d{1,2}):(\d{1,2})$/);
    if (!m) return null;
    const h = +m[1], mi = +m[2];
    if (h > 23 || mi > 59) return null;
    return `${String(h).padStart(2, '0')}:${String(mi).padStart(2, '0')}`;
}

function ssNormMinutes(v) {
    const s = String(v || '').trim();
    if (!/^\d+$/.test(s)) return null;
    const n = parseInt(s, 10);
    return n >= 1 && n <= 1440 ? String(n) : null;
}

function ssNorm(key, v) {
    return SS_FIELDS[key].type === 'minutes' ? ssNormMinutes(v) : ssNormTime(v);
}

function ssFmt(key, v) {
    return SS_FIELDS[key].type === 'minutes' ? `${v} menit` : `${v}`;
}

function ssMinutesOf(t) {
    const [h, m] = String(t).split(':').map(Number);
    return h * 60 + m;
}

function ssDuration(mins) {
    const h = Math.floor(mins / 60), m = mins % 60;
    if (h && m) return `${h} jam ${m} menit`;
    if (h) return `${h} jam`;
    return `${m} menit`;
}

// Kejadian berikutnya untuk jam harian HH:MM: { mins: menit dari sekarang, when: 'hari ini' | 'malam ini' | 'besok' }
function ssNext(t, now = new Date()) {
    const target = ssMinutesOf(t);
    const cur = now.getHours() * 60 + now.getMinutes();
    let diff = target - cur;
    let when = 'hari ini';
    if (diff <= 0) {
        diff += 1440;
        when = target < 6 * 60 && cur >= 18 * 60 ? 'malam ini' : 'besok';
    }
    return { mins: diff, when };
}

function ssInvalid() {
    return Object.keys(SS_FIELDS).filter(k => ssNorm(k, ssRaw[k]) === null);
}

function ssChanges() {
    return Object.keys(SS_FIELDS).filter(k => ssDraft[k] !== ssSaved[k]);
}

function ssDirty() {
    return ssChanges().length > 0 || ssInvalid().length > 0;
}
window.ssDirty = ssDirty;

// ---------- Render ----------
function ssBuildRows() {
    document.querySelectorAll('[data-ss-row]').forEach(row => {
        const key = row.dataset.ssRow;
        const f = SS_FIELDS[key];
        const unit = f.type === 'minutes' ? 'menit' : 'WIB';
        row.innerHTML = `
            <div class="ss-row-left">
                <div class="ss-row-label"><label for="ssInput-${key}">${f.label}</label>${f.tag ? `<span class="ss-tag ${f.tag[1]}">${f.tag[0]}</span>` : ''}</div>
                <p class="ss-row-desc" id="ssDesc-${key}">${f.desc}</p>
            </div>
            <div class="ss-row-right">
                <div class="ss-control">
                    <span class="ss-changed" id="ssChanged-${key}" hidden></span>
                    <div class="ss-field" id="ssField-${key}">
                        <span class="ss-field-icon">${f.type === 'minutes' ? SS_ICON.timer : SS_ICON.clock}</span>
                        <input type="text" id="ssInput-${key}" data-ss-input="${key}" inputmode="numeric" autocomplete="off" spellcheck="false"
                            maxlength="${f.type === 'minutes' ? 4 : 5}" placeholder="${f.type === 'minutes' ? '60' : 'HH:MM'}"
                            role="combobox" aria-autocomplete="none" aria-expanded="false" aria-controls="ssMenu-${key}" aria-describedby="ssDesc-${key} ssNote-${key}">
                        <span class="ss-field-unit">${unit}</span>
                        <button type="button" class="ss-field-btn" data-ss-open="${key}" tabindex="-1" aria-label="Pilihan cepat ${f.label}">${SS_ICON.chev}</button>
                        <div class="ss-menu" id="ssMenu-${key}" role="listbox" hidden></div>
                    </div>
                </div>
                <p class="ss-note" id="ssNote-${key}"></p>
            </div>`;
    });
    ssBuilt = true;
}

function ssRenderRow(key) {
    const input = document.getElementById(`ssInput-${key}`);
    if (!input) return;
    const row = document.querySelector(`[data-ss-row="${key}"]`);
    const field = document.getElementById(`ssField-${key}`);
    const changed = document.getElementById(`ssChanged-${key}`);
    const note = document.getElementById(`ssNote-${key}`);
    if (document.activeElement !== input) input.value = ssRaw[key];
    const invalid = ssNorm(key, ssRaw[key]) === null;
    const isChanged = !invalid && ssDraft[key] !== ssSaved[key];
    row.classList.toggle('is-edited', isChanged || invalid);
    field.classList.toggle('is-edited', isChanged);
    field.classList.toggle('is-invalid', invalid);
    input.setAttribute('aria-invalid', String(invalid));
    changed.hidden = !(isChanged || invalid);
    changed.innerHTML = `<span>Sebelumnya ${escapeHtml(ssFmt(key, ssSaved[key]))}</span><button type="button" class="ss-undo" data-ss-undo="${key}">${SS_ICON.undo}Kembalikan</button>`;
    note.classList.toggle('is-error', invalid);
    note.innerHTML = invalid
        ? `${SS_ICON.alert}<span>${SS_FIELDS[key].type === 'minutes' ? 'Isi angka 1 sampai 1440 menit.' : 'Isi jam 00:00 sampai 23:59, contoh 19:30.'}</span>`
        : `${SS_ICON.info}<span>${escapeHtml(ssConsequence(key))}</span>`;
}

function ssConsequence(key) {
    const v = ssDraft[key];
    const users = ssUsers || [];
    if (key === 'sa' || key === 'adm') {
        const role = key === 'sa' ? 'superadmin' : 'admin';
        const name = key === 'sa' ? 'Super Admin' : 'Admin';
        const all = users.filter(u => u.role === role);
        const online = all.filter(u => u.is_online).length;
        const nx = ssNext(v);
        if (!ssUsers) return `Berikutnya ${nx.when} pukul ${v}, ${ssDuration(nx.mins)} lagi.`;
        if (online) return `${online === all.length ? online : `${online} dari ${all.length}`} ${name} sedang online, dikeluarkan ${ssDuration(nx.mins)} lagi.`;
        return `Berlaku untuk ${all.length} akun ${name}. Berikutnya ${nx.when} pukul ${v}.`;
    }
    if (key === 'usr') {
        const end = (8 * 60 + parseInt(v, 10)) % 1440;
        const hh = String(Math.floor(end / 60)).padStart(2, '0'), mm = String(end % 60).padStart(2, '0');
        const n = users.filter(u => u.role === 'user').length;
        return `Contoh: login 08:00, dikeluarkan ${hh}:${mm}.${ssUsers && n ? ` Berlaku untuk ${n} akun User.` : ''}`;
    }
    const nx = ssNext(v);
    return `Berikutnya ${nx.when} pukul ${v}, ${ssDuration(nx.mins)} lagi.`;
}

function ssRenderTimeline() {
    const el = document.getElementById('ssTimeline');
    if (!el) return;
    const pct = t => (ssMinutesOf(t) / 1440) * 100;
    const marks = [
        { key: 'scan', label: 'Overnight Scan', cls: 'is-scan', icon: SS_ICON.moon },
        { key: 'adm', label: 'Admin logout', cls: 'is-adm', icon: SS_ICON.out },
        { key: 'sa', label: 'Super Admin logout', cls: 'is-sa', icon: SS_ICON.out }
    ].map(m => ({ ...m, t: ssDraft[m.key], p: pct(ssDraft[m.key]) })).sort((a, b) => a.p - b.p);
    const ticks = [0, 3, 6, 9, 12, 15, 18, 21, 24];
    el.innerHTML = `
        <div class="ss-tl-track"></div>
        ${ticks.map(h => `<span class="ss-tl-tick" style="left:${(h / 24) * 100}%"><span>${String(h % 24).padStart(2, '0')}:00</span></span>`).join('')}
        ${marks.map(m => {
            return `<span class="ss-tl-mark ${m.cls}" style="left:${m.p}%">
                <span class="ss-tl-pill">${m.icon}${m.t} · ${m.label}</span>
                <span class="ss-tl-stem"></span><span class="ss-tl-dot"></span>
            </span>`;
        }).join('')}`;
    el.setAttribute('aria-label', `Jadwal harian: ${marks.map(m => `${m.label} ${m.t}`).join(', ')}.`);
    // Label yang bertumpuk dipindah ke baris kedua (diukur dari lebar label sebenarnya)
    const placed = [];
    const box = el.getBoundingClientRect();
    el.querySelectorAll('.ss-tl-mark').forEach(mark => {
        const pill = mark.querySelector('.ss-tl-pill');
        let r = pill.getBoundingClientRect();
        // Label di tepi kanan/kiri dibalik arahnya supaya tidak keluar kartu
        if (r.right > box.right + 24) { pill.classList.add('is-end'); r = pill.getBoundingClientRect(); }
        else if (r.left < box.left - 24) { pill.classList.add('is-start'); r = pill.getBoundingClientRect(); }
        if (placed.some(q => r.left < q.right + 8 && r.right > q.left - 8)) mark.classList.add('is-row2');
        else placed.push(r);
    });
    const note = document.getElementById('ssTimelineNote');
    if (note) note.innerHTML = `${SS_ICON.timer}<span>User biasa tidak punya jam tetap: sesi berakhir ${escapeHtml(ssDraft.usr)} menit setelah login.</span>`;
}

function ssRenderStats() {
    const el = document.getElementById('ssScanStats');
    if (!el) return;
    const active = ssDomains ? ssDomains.filter(d => d.is_active === true && d.approval_status !== 'pending').length : null;
    const nights = active ? Math.ceil(active / SS_PER_NIGHT) : 0;
    el.innerHTML = `
        <div class="ss-stat"><strong>${active === null ? '-' : active}</strong><span>domain Aktif Overnight Scan</span></div>
        <div class="ss-stat"><strong>${SS_PER_NIGHT}</strong><span>domain di-scan per malam</span></div>
        <div class="ss-stat"><strong>${active ? `${nights} malam` : '-'}</strong><span>${active ? 'semua domain tergilir' : 'belum ada domain yang aktif'}</span></div>
        <button type="button" class="ss-stat-link" onclick="ssGoInventory()">Atur domain di Domain Inventory
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg></button>`;
}

function ssRenderSaveBar() {
    const bar = document.getElementById('ssSaveBar');
    if (!bar) return;
    const changes = ssChanges();
    const invalid = ssInvalid();
    bar.hidden = !changes.length && !invalid.length;
    if (bar.hidden) { bar.innerHTML = ''; return; }
    let title, sub, actions;
    if (invalid.length) {
        title = 'Perbaiki isian dulu';
        sub = invalid.map(k => SS_FIELDS[k].short).join(', ') + ' belum benar.';
        actions = `<button type="button" class="ss-sb-btn" data-ss-act="discard">Batalkan</button><button type="button" class="ss-sb-btn is-primary" disabled>${SS_ICON.check}Simpan perubahan</button>`;
    } else if (ssSaveState === 'error') {
        title = 'Gagal menyimpan';
        sub = ssSaveBar_err || 'Server tidak merespons. Perubahan masih ada.';
        actions = `<button type="button" class="ss-sb-btn" data-ss-act="discard">Batalkan</button><button type="button" class="ss-sb-btn is-primary" data-ss-act="save">Coba lagi</button>`;
    } else {
        title = `${changes.length} perubahan belum disimpan`;
        sub = changes.map(k => `${SS_FIELDS[k].short} ${ssFmt(k, ssSaved[k])} → ${ssFmt(k, ssDraft[k])}`).join(' · ');
        const saving = ssSaveState === 'saving';
        actions = `<button type="button" class="ss-sb-btn" data-ss-act="discard" ${saving ? 'disabled' : ''}>Batalkan</button><button type="button" class="ss-sb-btn is-primary" data-ss-act="save" ${saving ? 'disabled' : ''}>${SS_ICON.check}${saving ? 'Menyimpan...' : 'Simpan perubahan'}</button>`;
    }
    bar.classList.toggle('is-error', ssSaveState === 'error' || invalid.length > 0);
    bar.innerHTML = `<span class="ss-sb-icon">${invalid.length || ssSaveState === 'error' ? SS_ICON.alert : SS_ICON.pencil}</span>
        <div class="ss-sb-text"><strong>${title}</strong><span>${escapeHtml(sub)}</span></div>
        <div class="ss-sb-actions">${actions}</div>`;
}
let ssSaveBar_err = '';

function ssRenderAll() {
    if (!ssBuilt) ssBuildRows();
    Object.keys(SS_FIELDS).forEach(ssRenderRow);
    ssRenderTimeline();
    ssRenderStats();
    ssRenderSaveBar();
}

// ---------- Menu pilihan cepat ----------
function ssCloseMenu() {
    if (!ssMenuKey) return;
    const menu = document.getElementById(`ssMenu-${ssMenuKey}`);
    const input = document.getElementById(`ssInput-${ssMenuKey}`);
    if (menu) menu.hidden = true;
    if (input) { input.setAttribute('aria-expanded', 'false'); input.removeAttribute('aria-activedescendant'); }
    ssMenuKey = null;
}

function ssOpenMenu(key) {
    ssCloseMenu();
    const menu = document.getElementById(`ssMenu-${key}`);
    const input = document.getElementById(`ssInput-${key}`);
    if (!menu || !input) return;
    const f = SS_FIELDS[key];
    menu.innerHTML = f.presets.map((p, i) => {
        const on = p === ssDraft[key];
        return `<div class="ss-opt${on ? ' is-on' : ''}" role="option" id="ssOpt-${key}-${i}" aria-selected="${on}" data-ss-pick="${p}">
            <span>${f.type === 'minutes' ? `${p} menit` : `${p} WIB`}</span>${on ? SS_ICON.check : ''}${p === ssSaved[key] && !on ? '<em>tersimpan</em>' : ''}</div>`;
    }).join('') + `<p class="ss-menu-hint">${f.type === 'minutes' ? 'Angka lain bisa diketik langsung (1-1440).' : 'Jam lain bisa diketik langsung, contoh 19:30.'}</p>`;
    menu.hidden = false;
    input.setAttribute('aria-expanded', 'true');
    ssMenuKey = key;
    const idx = Math.max(0, f.presets.indexOf(ssDraft[key]));
    ssMenuActive(idx);
}

function ssMenuActive(i) {
    const opts = [...document.querySelectorAll(`#ssMenu-${ssMenuKey} .ss-opt`)];
    if (!opts.length) return;
    const n = (i + opts.length) % opts.length;
    opts.forEach((o, k) => o.classList.toggle('is-active', k === n));
    document.getElementById(`ssInput-${ssMenuKey}`)?.setAttribute('aria-activedescendant', opts[n].id);
    opts[n].scrollIntoView?.({ block: 'nearest' });
}

function ssSet(key, raw) {
    ssRaw[key] = raw;
    const v = ssNorm(key, raw);
    if (v !== null) ssDraft[key] = v;
    if (ssSaveState === 'error') ssSaveState = 'idle';
    ssRenderRow(key);
    ssRenderTimeline();
    ssRenderSaveBar();
}

function ssPick(key, v) {
    const input = document.getElementById(`ssInput-${key}`);
    ssRaw[key] = v;
    if (input) input.value = v;
    ssSet(key, v);
    ssCloseMenu();
    input?.focus();
}

function ssBind() {
    const view = document.getElementById('view-system-settings');
    if (!view || view.dataset.ssBound) return;
    view.dataset.ssBound = '1';
    view.addEventListener('input', (e) => {
        const key = e.target.dataset?.ssInput;
        if (key) ssSet(key, e.target.value);
    });
    view.addEventListener('focusout', (e) => {
        const key = e.target.dataset?.ssInput;
        if (!key) return;
        // Rapikan tampilan saat keluar kolom: "930" menjadi "09:30"
        const v = ssNorm(key, ssRaw[key]);
        if (v !== null) { ssRaw[key] = v; e.target.value = v; }
        setTimeout(() => { if (ssMenuKey === key && !document.getElementById(`ssField-${key}`)?.contains(document.activeElement)) ssCloseMenu(); }, 150);
        ssRenderRow(key);
    });
    view.addEventListener('keydown', (e) => {
        const key = e.target.dataset?.ssInput;
        if (!key) return;
        const open = ssMenuKey === key;
        const opts = open ? [...document.querySelectorAll(`#ssMenu-${key} .ss-opt`)] : [];
        const cur = opts.findIndex(o => o.classList.contains('is-active'));
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            if (!open) ssOpenMenu(key); else ssMenuActive(cur + (e.key === 'ArrowDown' ? 1 : -1));
        } else if (e.key === 'Enter') {
            if (open && cur >= 0) { e.preventDefault(); ssPick(key, opts[cur].dataset.ssPick); }
        } else if (e.key === 'Escape') {
            if (open) { e.preventDefault(); ssCloseMenu(); }
        }
    });
    view.addEventListener('mousedown', (e) => {
        // Pilih opsi sebelum input kehilangan fokus
        const opt = e.target.closest('[data-ss-pick]');
        if (opt) { e.preventDefault(); ssPick(ssMenuKey, opt.dataset.ssPick); }
    });
    view.addEventListener('click', (e) => {
        const openBtn = e.target.closest('[data-ss-open]');
        if (openBtn) {
            const key = openBtn.dataset.ssOpen;
            if (ssMenuKey === key) ssCloseMenu(); else { document.getElementById(`ssInput-${key}`)?.focus(); ssOpenMenu(key); }
            return;
        }
        const field = e.target.closest('.ss-field');
        if (field && e.target.matches('input')) {
            const key = e.target.dataset.ssInput;
            if (ssMenuKey !== key) ssOpenMenu(key);
            return;
        }
        const undo = e.target.closest('[data-ss-undo]');
        if (undo) { ssPick(undo.dataset.ssUndo, ssSaved[undo.dataset.ssUndo]); return; }
        const act = e.target.closest('[data-ss-act]')?.dataset.ssAct;
        if (act === 'save') saveSystemSettings();
        if (act === 'discard') ssDiscard();
    });
    document.addEventListener('mousedown', (e) => {
        if (ssMenuKey && !e.target.closest(`#ssField-${ssMenuKey}`)) ssCloseMenu();
    });
    let rz = null;
    window.addEventListener('resize', () => {
        clearTimeout(rz);
        rz = setTimeout(() => { if (!view.classList.contains('hidden')) ssRenderTimeline(); }, 150);
    });
    window.addEventListener('beforeunload', (e) => {
        if (currentUser && currentUser.role === 'superadmin' && ssDirty()) { e.preventDefault(); e.returnValue = ''; }
    });
}

function ssDiscard() {
    ssDraft = { ...ssSaved };
    ssRaw = { ...ssSaved };
    ssSaveState = 'idle';
    Object.keys(SS_FIELDS).forEach(k => { const i = document.getElementById(`ssInput-${k}`); if (i) i.value = ssRaw[k]; });
    ssRenderAll();
}
window.ssDiscard = ssDiscard;

window.ssGoInventory = function () {
    switchView('inventory');
    if (typeof invApplyTile === 'function') invApplyTile('active');
};

// Dipanggil switchView: konfirmasi bila meninggalkan halaman dengan perubahan belum disimpan.
// Mengembalikan true bila perpindahan ditahan.
function ssGuardLeave(targetView) {
    const view = document.getElementById('view-system-settings');
    if (!view || view.classList.contains('hidden') || targetView === 'system-settings' || !ssDirty()) return false;
    customConfirm({
        title: 'Tinggalkan halaman?',
        message: `${ssChanges().length || 1} perubahan di System Settings belum disimpan dan akan hilang.`,
        confirmText: 'Tinggalkan',
        cancelText: 'Tetap di sini',
        variant: 'danger'
    }).then(ok => {
        if (!ok) { if (typeof syncHashForView === 'function') syncHashForView('system-settings'); return; }
        ssDiscard();
        switchView(targetView);
    });
    return true;
}
window.ssGuardLeave = ssGuardLeave;

// Kompatibilitas tautan lama #/system-settings/auto-scan: gulir ke kartu Overnight Scan
function switchSettingsTab(tab) {
    if (tab !== 'auto-scan') return;
    setTimeout(() => document.getElementById('ssScanSection')?.scrollIntoView({ block: 'start' }), 50);
}
window.switchSettingsTab = switchSettingsTab;

function ssApplySaved(data) {
    const next = {};
    Object.entries(SS_KEYS).forEach(([k, api]) => {
        next[k] = ssNorm(k, data && data[api] != null ? String(data[api]) : '') || SS_DEFAULTS[k];
    });
    const wasDirty = ssDirty();
    ssSaved = next;
    // Perubahan yang sedang diedit tidak ditimpa bila ada update dari Super Admin lain
    if (!wasDirty) { ssDraft = { ...next }; ssRaw = { ...next }; }
}

function ssRenderMeta(meta) {
    const el = document.getElementById('ssLastUpdated');
    if (!el) return;
    if (!meta || !meta.updated_at) { el.hidden = true; return; }
    const d = new Date(meta.updated_at);
    const when = isNaN(d) ? '' : d.toLocaleString('id-ID', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }).replace('.', ':');
    el.hidden = false;
    el.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path><path d="M3 3v5h5"></path><path d="M12 7v5l4 2"></path></svg>Terakhir diubah ${escapeHtml(meta.updated_by || '-')}${when ? ` · ${escapeHtml(when)}` : ''}`;
}

async function loadSystemSettings() {
    if (!currentUser || currentUser.role !== 'superadmin') return;
    ssBind();
    if (!ssBuilt) ssBuildRows();
    ssRenderAll();
    const getJson = (url) => fetch(`${API_BASE}${url}`).then(r => (r.ok ? r.json() : null)).catch(() => null);
    const [settings, meta, users, domains] = await Promise.all([
        getJson('/api/system-settings'),
        getJson('/api/system-settings/meta'),
        getJson('/api/admin/users'),
        (allDomains && allDomains.length) ? Promise.resolve({ data: allDomains }) : getJson('/api/domains')
    ]);
    if (settings) {
        window.systemSettings = settings;
        ssApplySaved(settings);
    }
    ssRenderMeta(meta && meta.data);
    if (users) ssUsers = users.data || [];
    if (domains) ssDomains = Array.isArray(domains) ? domains : (domains.data || []);
    ssRenderAll();
    // Hitung mundur di catatan tiap baris diperbarui tiap menit selama halaman terbuka
    clearInterval(ssTick);
    ssTick = setInterval(() => {
        const view = document.getElementById('view-system-settings');
        if (!view || view.classList.contains('hidden')) { clearInterval(ssTick); ssTick = null; return; }
        Object.keys(SS_FIELDS).forEach(k => { if (document.activeElement?.dataset?.ssInput !== k) ssRenderRow(k); });
    }, 60000);
}

async function saveSystemSettings() {
    if (!currentUser || currentUser.role !== 'superadmin') {
        showToast('Akses Ditolak', 'Hanya Super Admin yang berhak mengubah konfigurasi sistem.', '');
        return;
    }
    if (ssInvalid().length || !ssChanges().length || ssSaveState === 'saving') return;
    const payload = {
        force_logout_superadmin: ssDraft.sa,
        force_logout_admin: ssDraft.adm,
        force_logout_user_minutes: ssDraft.usr,
        scheduled_scan_hour: ssDraft.scan
    };
    ssSaveState = 'saving';
    ssRenderSaveBar();
    try {
        const resp = await fetch(`${API_BASE}/api/system-settings`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const resData = await resp.json().catch(() => ({}));
        if (resp.ok) {
            window.systemSettings = payload;
            const n = ssChanges().length;
            ssSaved = { ...ssDraft };
            ssRaw = { ...ssDraft };
            ssSaveState = 'idle';
            ssRenderAll();
            ssRenderMeta({ updated_by: currentUser.username || currentUser.email, updated_at: new Date().toISOString() });
            showToast(`${n} pengaturan disimpan.`, 'success');
        } else {
            ssSaveState = 'error';
            ssSaveBar_err = resData.detail ? `${resData.detail} Perubahan masih ada.` : 'Server menolak perubahan. Perubahan masih ada.';
            ssRenderSaveBar();
        }
    } catch (err) {
        ssSaveState = 'error';
        ssSaveBar_err = 'Server tidak merespons. Perubahan masih ada.';
        ssRenderSaveBar();
    }
}
window.saveSystemSettings = saveSystemSettings;

function initRoleSessionTimer() {
    setInterval(() => {
        if (!currentUser) return;

        const role = currentUser.role || 'user';
        if (role !== 'user') return;

        const settings = window.systemSettings || {};
        const usrMinutes = parseInt(settings.force_logout_user_minutes || '60', 10) || 60;
        const sessionStart = parseInt(localStorage.getItem('dsti_session_start') || '0', 10);

        if (sessionStart && (Date.now() - sessionStart) > (usrMinutes * 60 * 1000)) {
            window.kickedReason = 'force_logout';
            showToast("Sesi Diakhiri", `Batas durasi sesi untuk User adalah ${usrMinutes} menit. Sesi Anda telah berakhir.`, "");
            setTimeout(() => { handleLogout(); }, 1500);
        }
    }, 30000);
}

// Helper testing dari console browser
window.testForceLogout = function(roleTarget) {
    const role = roleTarget || (currentUser ? currentUser.role : 'user');
    console.log(`[TEST] Pengujian instan Force Logout untuk role: ${role}`);
    
    if (role === 'superadmin') {
        window.kickedReason = 'force_logout';
        showToast("Sesi Diakhiri", "[TEST] Batas waktu operasional Super Admin adalah jam 19:00 WIB (7 malam). Sesi Anda telah diakhiri.", "⚠️");
        setTimeout(() => { handleLogout(); }, 1500);
    } else if (role === 'admin') {
        window.kickedReason = 'force_logout';
        showToast("Sesi Diakhiri", "[TEST] Batas waktu operasional Admin adalah jam 16:00 WIB (4 sore). Sesi Anda telah diakhiri.", "⚠️");
        setTimeout(() => { handleLogout(); }, 1500);
    } else if (role === 'user') {
        localStorage.setItem('dsti_session_start', Date.now() - (61 * 60 * 1000));
        window.kickedReason = 'force_logout';
        showToast("Sesi Diakhiri", "[TEST] Batas durasi sesi untuk User adalah 1 jam (60 menit). Sesi Anda telah berakhir.", "⚠️");
        setTimeout(() => { handleLogout(); }, 1500);
    }
};
window.testOvernightToast = function() {
    fetch(`${API_BASE}/api/notifications/overnight-scans`)
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success' && data.data && data.data.length > 0) {
                showOvernightToastNotification(data.data);
                console.log("[TEST] Toast Notifikasi Dini Hari dipicu untuk", data.data.length, "scan.");
            } else {
                console.warn("[TEST] Tidak ditemukan data scan overnight berisiko HIGH/CRITICAL.");
            }
        });
};


window.resetNotificationReadStatus = function() {
    // Hanya mengosongkan salinan di browser ini; status baca di server tidak diubah
    notifReadSet = new Set();
    console.log("[TEST] Status baca notifikasi di browser ini dikosongkan (data di server tetap).");
    allNotifications.forEach(n => { n.unread = true; });
    renderNotificationList();
};



// =========================================================
// Generate Report: satu jendela untuk jenis, format, filter,
// lalu unduh ke perangkat atau kirim lewat email.
// =========================================================
const GR_FILTERS = [
    ['reproduce', 'How to reproduce'],
    ['informational', 'Informational'],
    ['false_positives', 'False Positives'],
    ['ignored', 'Ignored'],
    ['not_verified', 'Not Verified'],
    ['accepted', 'Accepted'],
    ['fixed', 'Fixed']
];
const GR_FILTER_DEFAULTS = { reproduce: false, informational: true, false_positives: false, ignored: false, not_verified: true, accepted: true, fixed: true };
const GR_FILTER_KEY = 'gr_filters_v1';
const GR_EMAIL_RE = /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/;

function grParseRecipients(text) {
    const valid = [];
    const invalid = [];
    const seen = new Set();
    String(text || '').split(/[\s,;]+/).map(s => s.trim()).filter(Boolean).forEach(s => {
        if (!GR_EMAIL_RE.test(s)) { invalid.push(s); return; }
        const k = s.toLowerCase();
        if (seen.has(k)) return;
        seen.add(k);
        valid.push(s);
    });
    return { valid, invalid };
}

function grFilterSummary(filters) {
    const order = ['reproduce', 'informational', 'false_positives', 'ignored', 'not_verified', 'accepted', 'fixed'];
    const names = Object.fromEntries(GR_FILTERS);
    const on = order.filter(k => filters && filters[k]).map(k => names[k]);
    return on.length ? `Filters: ${on.join(', ')}` : 'Filters: tidak ada tambahan';
}

function grFileName(domain, date, format) {
    const ext = String(format || 'pdf').toLowerCase();
    const safe = String(domain || '').trim().replace(/[^A-Za-z0-9._-]+/g, '_');
    if (!safe) return `laporan_scan.${ext}`;
    const m = String(date || '').match(/^(\d{4}-\d{2}-\d{2})/);
    return m ? `laporan_${safe}_${m[1]}.${ext}` : `laporan_${safe}.${ext}`;
}

function grCtaLabel(state) {
    if (state.delivery === 'email') {
        const n = state.count || 0;
        if (state.busy) return `Mengirim ke ${n} email...`;
        return n ? `Kirim ke ${n} email` : 'Kirim lewat email';
    }
    if (state.busy) return 'Menyiapkan laporan...';
    return `Unduh ${String(state.format || 'pdf').toUpperCase()}`;
}

let grRecipients = [];
let grBusy = false;
let grMeta = { domain: '', date: null };

function grForm() { return document.getElementById('generateReportForm'); }
function grDelivery() { return grForm()?.querySelector('input[name="gr_delivery"]:checked')?.value || 'download'; }
function grRadio(name, fallback) { return grForm()?.querySelector(`input[name="${name}"]:checked`)?.value || fallback; }
function grFormat() { return grRadio('report_format', 'pdf'); }
function grReadFilters() {
    const f = grForm();
    const out = {};
    GR_FILTERS.forEach(([k]) => { out[k] = !!f?.querySelector(`input[name="filter_${k}"]`)?.checked; });
    return out;
}
function grWriteFilters(values) {
    const f = grForm();
    GR_FILTERS.forEach(([k]) => { const el = f?.querySelector(`input[name="filter_${k}"]`); if (el) el.checked = !!values[k]; });
}
function grLoadFilters() {
    try {
        const saved = JSON.parse(localStorage.getItem(GR_FILTER_KEY) || 'null');
        if (saved && typeof saved === 'object') return { ...GR_FILTER_DEFAULTS, ...saved };
    } catch (e) { /* penyimpanan browser tidak tersedia */ }
    return { ...GR_FILTER_DEFAULTS };
}
function grSaveFilters() {
    try { localStorage.setItem(GR_FILTER_KEY, JSON.stringify(grReadFilters())); } catch (e) { /* abaikan */ }
}

function grSetFilterOpen(open) {
    const panel = document.getElementById('grFilterPanel');
    const toggle = document.getElementById('grFilterToggle');
    if (!panel || !toggle) return;
    panel.hidden = !open;
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    toggle.textContent = open ? 'Tutup' : 'Ubah';
    document.getElementById('grFilters')?.classList.toggle('is-open', open);
}

function grPendingText() { return (document.getElementById('grEmailInput')?.value || '').trim(); }

function grRender() {
    const delivery = grDelivery();
    const format = grFormat();
    const summary = document.getElementById('grFilterSummary');
    if (summary) summary.textContent = grFilterSummary(grReadFilters());

    const fileHint = document.getElementById('grFileHint');
    const emailWrap = document.getElementById('grEmailWrap');
    if (fileHint) {
        fileHint.hidden = delivery !== 'download';
        fileHint.textContent = `File: ${grFileName(grMeta.domain, grMeta.date, format)}`;
    }
    if (emailWrap) emailWrap.hidden = delivery !== 'email';
    const note = document.getElementById('grEmailNote');
    if (note) note.textContent = `Email berisi pesan pengantar dan lampiran laporan ${format.toUpperCase()}.`;

    // chip penerima
    const box = document.getElementById('grRecipients');
    const input = document.getElementById('grEmailInput');
    if (box && input) {
        box.querySelectorAll('.gr-chip').forEach(c => c.remove());
        grRecipients.forEach(email => {
            const chip = document.createElement('span');
            chip.className = 'gr-chip';
            chip.dataset.email = email;
            chip.innerHTML = `<span>${escapeHtml(email)}</span><button type="button" aria-label="Hapus ${escapeHtml(email)}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>`;
            box.insertBefore(chip, input);
        });
    }

    // validasi teks yang belum jadi chip
    const pending = grPendingText();
    const bad = pending ? grParseRecipients(pending).invalid : [];
    const err = document.getElementById('grEmailError');
    const showErr = delivery === 'email' && bad.length > 0 && input?.dataset.touched === '1';
    if (err) {
        err.hidden = !showErr;
        err.textContent = showErr ? `"${bad[0]}" bukan alamat email. Contoh: nama@undip.ac.id` : '';
    }
    if (input) input.setAttribute('aria-invalid', showErr ? 'true' : 'false');
    box?.classList.toggle('is-invalid', showErr);

    const btn = document.getElementById('btnSubmitReport');
    if (btn) {
        const blocked = delivery === 'email' && (grRecipients.length === 0 || bad.length > 0);
        btn.disabled = grBusy || blocked;
        const label = grCtaLabel({ delivery, format, count: grRecipients.length, busy: grBusy });
        const span = btn.querySelector('.gr-cta-text');
        if (span) span.textContent = label; else btn.textContent = label;
        btn.classList.toggle('is-busy', grBusy);
    }
}

function grCommitInput() {
    const input = document.getElementById('grEmailInput');
    if (!input) return;
    const { valid, invalid } = grParseRecipients(input.value);
    const have = new Set(grRecipients.map(e => e.toLowerCase()));
    valid.forEach(e => { if (!have.has(e.toLowerCase())) { grRecipients.push(e); have.add(e.toLowerCase()); } });
    input.value = invalid.join(', ');
    input.dataset.touched = invalid.length ? '1' : '';
    grRender();
}

function grShowStatus(kind, title, text) {
    const box = document.getElementById('grStatus');
    if (!box) return;
    if (!kind) { box.hidden = true; box.classList.remove('is-error'); return; }
    box.hidden = false;
    box.classList.toggle('is-error', kind === 'error');
    document.getElementById('grStatusTitle').textContent = title;
    document.getElementById('grStatusText').textContent = text;
}

function openGenerateReportModal(historyId, meta) {
    document.getElementById('reportHistoryId').value = historyId;
    const m = meta || currentScanMeta || {};
    grMeta = { domain: m.domain || '', date: m.date || null };
    const sub = document.getElementById('grSubtitle');
    if (sub) {
        const parts = [];
        if (grMeta.domain) parts.push(grMeta.domain);
        if (grMeta.date) parts.push(`scan ${formatDate(grMeta.date)}`);
        sub.textContent = parts.join(' · ');
        sub.hidden = parts.length === 0;
    }
    if (!grBusy) {
        grWriteFilters(grLoadFilters());
        const dl = grForm()?.querySelector('input[name="gr_delivery"][value="download"]');
        if (dl) dl.checked = true;
        grRecipients = [];
        const input = document.getElementById('grEmailInput');
        if (input) { input.value = ''; input.dataset.touched = ''; }
        grShowStatus(null);
    }
    grSetFilterOpen(false);
    grRender();
    const overlay = document.getElementById('generateReportModalOverlay');
    overlay.classList.add('active');
    setTimeout(() => overlay.querySelector('.modal-dialog')?.focus(), 50);
}

function closeGenerateReportModal() {
    document.getElementById('generateReportModalOverlay')?.classList.remove('active');
}

function grBuildPayload() {
    const f = grReadFilters();
    return {
        history_id: parseInt(document.getElementById('reportHistoryId').value, 10),
        report_type: grRadio('report_type', 'raw_scan_results'),
        report_format: grRadio('report_format', 'pdf'),
        group_findings_by: grRadio('group_by', 'target'),
        include_reproduce: f.reproduce,
        include_informational: f.informational,
        include_false_positives: f.false_positives,
        include_ignored: f.ignored,
        include_not_verified: f.not_verified,
        include_accepted: f.accepted,
        include_fixed: f.fixed
    };
}

async function grReadError(resp, fallback) {
    try {
        const data = await resp.json();
        return (data && data.detail) || fallback;
    } catch (e) {
        return fallback;
    }
}

async function submitGenerateReport() {
    if (grBusy) return;
    if (grDelivery() === 'email' && grPendingText()) grCommitInput();
    const btn = document.getElementById('btnSubmitReport');
    if (btn && btn.disabled) return;
    const historyId = document.getElementById('reportHistoryId').value;
    if (!historyId) return;

    const delivery = grDelivery();
    const payload = grBuildPayload();
    const emails = [...grRecipients];
    const fileName = grFileName(grMeta.domain, grMeta.date, payload.report_format);
    grBusy = true;
    grShowStatus('busy', 'Pentest-Tools sedang menyusun laporan...',
        'Sistem menunggu Pentest-Tools paling lama sekitar 3 menit. Jendela ini boleh ditutup selama halaman tetap terbuka; hasilnya muncul sebagai notifikasi.');
    grRender();

    try {
        if (delivery === 'download') {
            const resp = await fetch(`${API_BASE}/api/reports/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (!resp.ok) throw new Error(await grReadError(resp, 'Laporan gagal dibuat.'));
            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
            showToast('Laporan diunduh', fileName, '');
        } else {
            const resp = await fetch(`${API_BASE}/api/reports/share`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ...payload, emails })
            });
            if (!resp.ok) throw new Error(await grReadError(resp, 'Email gagal dikirim.'));
            const data = await resp.json().catch(() => ({}));
            showToast('Laporan dikirim', data.message || `Laporan dikirim ke ${emails.length} email.`, '');
            grRecipients = [];
        }
        grBusy = false;
        grShowStatus(null);
        closeGenerateReportModal();
        grRender();
    } catch (err) {
        grBusy = false;
        const msg = (err && err.message) || 'Terjadi kesalahan.';
        grShowStatus('error', delivery === 'email' ? 'Email belum terkirim' : 'Laporan belum bisa diunduh', msg);
        grRender();
        if (!document.getElementById('generateReportModalOverlay')?.classList.contains('active')) {
            showToast('Error', msg, '');
        }
    }
}

// Ctrl/⌘ + Enter = proses, Escape / klik di luar = tutup
document.addEventListener('keydown', (e) => {
    const overlay = document.getElementById('generateReportModalOverlay');
    if (!overlay || !overlay.classList.contains('active')) return;
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        submitGenerateReport();
    } else if (e.key === 'Escape') {
        closeGenerateReportModal();
    }
});
document.getElementById('generateReportModalOverlay')?.addEventListener('click', (e) => {
    if (e.target.id === 'generateReportModalOverlay') closeGenerateReportModal();
});
document.getElementById('closeGenerateReportModalBtn')?.addEventListener('click', closeGenerateReportModal);
document.getElementById('btnCancelReport')?.addEventListener('click', closeGenerateReportModal);
document.getElementById('grFilterToggle')?.addEventListener('click', () => {
    grSetFilterOpen(document.getElementById('grFilterPanel').hidden);
});
document.getElementById('grFilterReset')?.addEventListener('click', () => {
    grWriteFilters(GR_FILTER_DEFAULTS);
    grSaveFilters();
    grRender();
});
document.getElementById('generateReportForm')?.addEventListener('change', (e) => {
    if (e.target.name && e.target.name.startsWith('filter_')) grSaveFilters();
    if (e.target.name === 'gr_delivery') grShowStatus(null);
    grRender();
});
document.getElementById('generateReportForm')?.addEventListener('submit', (e) => {
    e.preventDefault();
    submitGenerateReport();
});
(function grBindEmail() {
    const input = document.getElementById('grEmailInput');
    const box = document.getElementById('grRecipients');
    if (!input || !box) return;
    input.addEventListener('input', () => {
        if (/[,;\s]$/.test(input.value) && input.value.trim()) { grCommitInput(); return; }
        if (!input.value.trim()) input.dataset.touched = '';
        grRender();
    });
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.ctrlKey && !e.metaKey) {
            e.preventDefault();
            if (input.value.trim()) grCommitInput();
        } else if (e.key === 'Backspace' && !input.value && grRecipients.length) {
            grRecipients.pop();
            grRender();
        }
    });
    input.addEventListener('blur', () => { if (input.value.trim()) grCommitInput(); });
    input.addEventListener('paste', (e) => {
        const text = e.clipboardData && e.clipboardData.getData('text');
        if (!text) return;
        e.preventDefault();
        input.value = `${input.value} ${text}`;
        grCommitInput();
    });
    box.addEventListener('click', (e) => {
        const del = e.target.closest('.gr-chip button');
        if (del) {
            const email = del.closest('.gr-chip').dataset.email;
            grRecipients = grRecipients.filter(x => x !== email);
            grRender();
            input.focus();
        } else if (e.target === box) {
            input.focus();
        }
    });
})();

// --- Web Scanner & Scheduled Scans Logic ---
let activeScansInterval = null;
let allScheduledScans = [];
let scheduledWebScans = [];
let scheduledNetworkScans = [];

function fetchScheduledScans() {
    fetch(`${API_BASE}/api/scans/schedules`)
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success' || data.status === 'ok') {
                allScheduledScans = (data.data || []).map(item => ({ ...item, is_scheduled: true }));
                scheduledWebScans = allScheduledScans.filter(s => (s.scan_category || 'web') === 'web');
                scheduledNetworkScans = allScheduledScans.filter(s => s.scan_category === 'network');

                if (typeof applyWebFilters === 'function') applyWebFilters(true);
                if (typeof applyNetworkFilters === 'function') applyNetworkFilters(true);

                // Saat ada jadwal yang sedang berjalan, muat ulang riwayat scan (maks. tiap 30 detik)
                // agar hasil tiap eksekusi langsung muncul di bawah jadwalnya tanpa reload halaman.
                if (allScheduledScans.some(s => s.status === 'running')) refreshScheduledResults();
            }
        })
        .catch(err => {
            console.error('Error fetching scheduled scans:', err);
        });
}

let scheduledResultsRefreshedAt = 0;
let scheduledResultsLoading = false;
async function refreshScheduledResults() {
    if (scheduledResultsLoading || Date.now() - scheduledResultsRefreshedAt < 30000) return;
    scheduledResultsLoading = true;
    try {
        await loadVulnerabilities(true);
        if (typeof processNetworkScans === 'function') processNetworkScans(true);
        if (typeof processWebScans === 'function') processWebScans(true);
        scheduledResultsRefreshedAt = Date.now();
    } catch (err) {
        console.error('Gagal memperbarui hasil jadwal:', err);
    } finally {
        scheduledResultsLoading = false;
    }
}

async function cancelScheduledScan(scheduleId, status = '') {
    let stopActive = false;

    if (status === 'running') {
        const choice = await customConfirm({
            title: 'Pembatalan Scan Berjalan',
            message: 'Jadwal scan ini sedang BERJALAN di latar belakang. Silakan pilih opsi pembatalan:',
            confirmText: 'Hentikan Jadwal & Pemindaian',
            secondaryText: 'Hanya Batalkan Jadwal',
            cancelText: 'Batal',
            variant: 'danger'
        });

        if (choice === 'cancel' || !choice) {
            return;
        }

        if (choice === 'confirm') {
            stopActive = true;
        } else if (choice === 'secondary') {
            stopActive = false;
        }
    } else {
        const isConfirmed = await customConfirm({
            title: 'Batalkan Jadwal Scan',
            message: 'Apakah Anda yakin ingin membatalkan jadwal scan ini?',
            confirmText: 'Ya, Batalkan Jadwal',
            cancelText: 'Batal',
            variant: 'danger'
        });

        if (!isConfirmed) return;
    }

    fetch(`${API_BASE}/api/scans/schedules/${scheduleId}?stop_active=${stopActive}`, {
        method: 'DELETE'
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success' || data.status === 'ok') {
                showToast('Success', data.message || 'Jadwal scan berhasil dibatalkan.', '');
                fetchScheduledScans();
                if (typeof fetchActiveScans === 'function') fetchActiveScans();
            } else {
                showToast('Error', data.detail || data.message || 'Gagal membatalkan jadwal scan.', '');
            }
        })
        .catch(err => {
            console.error('Error cancelling scheduled scan:', err);
            showToast('Error', 'Gagal membatalkan jadwal scan.', '');
        });
}

function fetchActiveScans() {
    fetch(`${API_BASE}/api/scans/active`)
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const allLive = data.data || [];

                // Filter cerdas: ID 350 atau 385 adalah Network Scanner. Sisanya lempar ke Web Scanner.
                liveNetworkScans = allLive.filter(s => s.type.includes('350') || s.type.includes('385') || s.type.toLowerCase().includes('network'));
                liveWebScans = allLive.filter(s => !liveNetworkScans.includes(s));
                updateRunningIndicator();

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

// Web scanner

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

// =========================================================
// Pencocokan scan LAMA (tanpa schedule_id / is_scheduled) ke jadwal Automated.
// Dipakai bersama oleh tab Automated (sub-baris jadwal) dan tab Manual (agar hasil jadwal tidak tampil di sana).
// Scan baru selalu punya penanda dari backend, jadi aturan ini hanya untuk data sebelum perbaikan.
// =========================================================
function schedNormTarget(t) {
    return String(t || '').toLowerCase().replace('http://', '').replace('https://', '').replace(/\/$/, '').trim();
}

function schedTimeWindow(sc) {
    const start = new Date(sc.scheduled_at || sc.created_at).getTime() - 5 * 60 * 1000;
    const end = sc.window_end_at
        ? new Date(sc.window_end_at).getTime() + 10 * 60 * 1000
        : new Date(sc.last_run_at || sc.scheduled_at || sc.created_at).getTime() + 15 * 60 * 1000;
    return [start, end];
}

function legacyScanMatchesSchedule(scan, sc) {
    if (scan.is_scheduled !== undefined || scan.raw_json?.is_scheduled !== undefined) return false;
    // Jadwal yang belum pernah berjalan tidak mungkin punya hasil
    if (!(sc.status === 'running' || sc.status === 'completed' || sc.last_run_at)) return false;
    const dom = schedNormTarget(scan.domains?.domain_name || scan.domain_name);
    if (!dom) return false;
    const targets = (Array.isArray(sc.targets) ? sc.targets : []).map(schedNormTarget).filter(Boolean);
    if (!targets.some(t => dom.includes(t) || t.includes(dom))) return false;
    const t = new Date(scan.scan_date).getTime();
    const [start, end] = schedTimeWindow(sc);
    return !isNaN(t) && t >= start && t <= end;
}

function isLegacyScheduledRun(scan, schedules) {
    return (schedules || []).some(sc => legacyScanMatchesSchedule(scan, sc));
}

// =========================================================
// HALAMAN WEBSITE SCANS & NETWORK SCANS (desain baru, satu renderer untuk keduanya)
// Manual   : TARGET | STATUS | SUMMARY | DATE | aksi
// Automated: TARGET | SCHEDULE | FREQUENCY | STATUS | RESULTS | aksi (+ sub-baris eksekusi)
// =========================================================
const SP_CFG = {
    web: {
        label: 'Website', pre: 'web', tbody: 'webScannerTableBody', pag: 'webPaginationControls',
        mode: () => window.currentWebScanMode, list: () => filteredWebScans,
        page: () => webCurrentPage, setPage: (v) => { webCurrentPage = v; }, rows: () => webRowsPerPage, setRows: (v) => { webRowsPerPage = v; },
        apply: () => applyWebFilters(true), schedules: () => scheduledWebScans, live: () => liveWebScans, db: () => webScans,
        newScan: () => openWebScanModal()
    },
    network: {
        label: 'Network', pre: 'network', tbody: 'networkScansTableBody', pag: 'networkPaginationControls',
        mode: () => window.currentNetworkScanMode, list: () => filteredNetworkScans,
        page: () => netCurrentPage, setPage: (v) => { netCurrentPage = v; }, rows: () => netRowsPerPage, setRows: (v) => { netRowsPerPage = v; },
        apply: () => applyNetworkFilters(true), schedules: () => scheduledNetworkScans, live: () => liveNetworkScans, db: () => networkScans,
        newScan: () => openNetworkScanModal()
    }
};
const spState = { web: { schedStatus: 'ALL' }, network: { schedStatus: 'ALL' } };
const SP_FREQ = { once: 'Once', daily: 'Daily', weekly: 'Weekly', window: 'Repeat in window' };
const SP_STATUS = {
    pending: ['Pending', 'is-pending'], running: ['Running', 'is-running'],
    completed: ['Completed', 'is-completed'], cancelled: ['Cancelled', 'is-cancelled']
};
const SP_ICON = {
    check: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="m9 12 2 2 4-4"></path></svg>',
    chevron: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 18 15 12 9 6"></polyline></svg>',
    moon: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"></path></svg>'
};

function spDate(d) {
    return `${d.getDate()} ${SH_MONTHS[d.getMonth()]} ${d.getFullYear()}, ${shTime(d)}`;
}

function spDay(d) {
    return `${d.getDate()} ${SH_MONTHS[d.getMonth()]} ${d.getFullYear()}`;
}

// Waktu mulai scan live dari Pentest-Tools (zona EEST bila tanpa offset)
function spLiveDate(scan) {
    if (!scan.start_time) return null;
    let raw = String(scan.start_time).replace(' ', 'T');
    if (!raw.includes('+') && !raw.includes('Z')) raw += '+03:00';
    const d = new Date(raw);
    return isNaN(d) ? null : d;
}

// Filter tambahan dari bar filter (dipanggil applyWebFilters / applyNetworkFilters)
// Rentang dari pemilih kalender (input tersembunyi <pre>StartDate/<pre>EndDate), akhir hari ikut.
// null bila "Semua tanggal".
function spDateRange(cat) {
    const pre = SP_CFG[cat].pre;
    const start = document.getElementById(`${pre}StartDate`)?.value || '';
    const end = document.getElementById(`${pre}EndDate`)?.value || '';
    if (!start && !end) return null;
    const [ys, ms, dsd] = (start || end).split('-').map(Number);
    const [ye, me, de] = (end || start).split('-').map(Number);
    return { from: new Date(ys, ms - 1, dsd).getTime(), to: new Date(ye, me - 1, de + 1).getTime() - 1 };
}

function spFilterLists(cat, lists) {
    const pre = SP_CFG[cat].pre;
    const status = document.getElementById(`${pre}StatusFilter`)?.value || 'ALL';
    const range = spDateRange(cat);
    const inRange = t => !isNaN(t) && t >= range.from && t <= range.to;
    let { scheduled, live, db } = lists;
    if (range) {
        db = db.filter(s => inRange(new Date(s.scan_date).getTime()));
        live = live.filter(s => { const d = spLiveDate(s); return !d || inRange(d.getTime()); });
    }
    // Jumlah untuk chip tab Manual: dihitung sebelum filter status, sesudah pencarian dan tanggal
    spState[cat].manualCounts = { ALL: live.length + db.length, running: live.length, completed: db.length };
    if (status === 'completed') live = [];
    if (status === 'running') db = [];
    // Tab Automated: Completed dan Cancelled menurut tanggal jadwal; Pending dan Running selalu tampil
    if (range) {
        scheduled = scheduled.filter(s => {
            if (s.status === 'pending' || s.status === 'running') return true;
            return inRange(new Date(s.scheduled_at || s.created_at).getTime());
        });
    }
    spState[cat].schedCounts = { ALL: scheduled.length, pending: 0, running: 0, completed: 0, cancelled: 0 };
    scheduled.forEach(s => { if (s.status in spState[cat].schedCounts) spState[cat].schedCounts[s.status]++; });
    const st = spState[cat].schedStatus;
    if (st !== 'ALL') scheduled = scheduled.filter(s => s.status === st);
    return { scheduled, live, db };
}

function spFiltersActive(cat) {
    const pre = SP_CFG[cat].pre;
    const search = document.getElementById(cat === 'web' ? 'webScannerSearch' : 'netSearchInput')?.value.trim();
    if (search) return true;
    const dateOn = !!spDateRange(cat);
    if (SP_CFG[cat].mode() === 'scheduled') return spState[cat].schedStatus !== 'ALL' || dateOn;
    return (document.getElementById(`${pre}StatusFilter`)?.value || 'ALL') !== 'ALL' || dateOn;
}

// Tombol Reset seragam di semua halaman: "Reset (n)", tersembunyi bila tidak ada filter aktif
const FLT_RESET_ICON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"></path><path d="M3 3v5h5"></path></svg>';
function fltResetLabel(btn, n) {
    if (!btn) return;
    btn.hidden = n === 0;
    btn.innerHTML = `${FLT_RESET_ICON}<span>Reset (${n})</span>`;
    btn.setAttribute('aria-label', `Hapus ${n} filter`);
}

// Jumlah filter aktif di Website/Network Scans. Status yang dihitung mengikuti tab yang terbuka.
function spActiveFilterCount(cat) {
    const pre = SP_CFG[cat].pre;
    let n = 0;
    if ((document.getElementById(cat === 'web' ? 'webScannerSearch' : 'netSearchInput')?.value || '').trim()) n++;
    if (SP_CFG[cat].mode() === 'scheduled') {
        if (spState[cat].schedStatus !== 'ALL') n++;
    } else if ((document.getElementById(`${pre}StatusFilter`)?.value || 'ALL') !== 'ALL') {
        n++;
    }
    if (spDateRange(cat)) n++;
    return n;
}

function spResetFilters(cat) {
    const pre = SP_CFG[cat].pre;
    const s = document.getElementById(cat === 'web' ? 'webScannerSearch' : 'netSearchInput');
    if (s) s.value = '';
    const st = document.getElementById(`${pre}StatusFilter`); if (st) st.value = 'ALL';
    ['StartDate', 'EndDate'].forEach(k => { const el = document.getElementById(pre + k); if (el) el.value = ''; });
    rpSyncFromInputs(`${cat}Scans`);
    spState[cat].schedStatus = 'ALL';
    SP_CFG[cat].apply();
}

// Hasil (scan selesai + scan live) milik satu jadwal. Aturan sama dengan tab Manual (lihat legacyScanMatchesSchedule).
function scheduleRuns(sc, cat) {
    const targets = (Array.isArray(sc.targets) ? sc.targets : []).map(schedNormTarget).filter(Boolean);
    const domOk = (d) => { const x = schedNormTarget(d); return x && targets.some(t => x.includes(t) || t.includes(x)); };
    const db = (SP_CFG[cat].db() || []).filter(s => {
        if (s.is_manual === true || s.raw_json?.is_manual === true || s.is_scheduled === false) return false;
        const id = s.schedule_id ?? s.raw_json?.schedule_id;
        if (id !== undefined && id !== null) return String(id) === String(sc.id);
        if (!domOk(s.domains?.domain_name)) return false;
        if (s.is_scheduled === true || s.raw_json?.is_scheduled === true) return true;
        return legacyScanMatchesSchedule(s, sc);
    }).sort((a, b) => new Date(a.scan_date) - new Date(b.scan_date));
    const live = sc.status === 'running' ? (SP_CFG[cat].live() || []).filter(s => {
        if (s.is_manual === true || s.is_scheduled === false) return false;
        const id = s.schedule_id ?? s.raw_json?.schedule_id;
        if (id !== undefined && id !== null) return String(id) === String(sc.id);
        return (s.is_scheduled === true || s.raw_json?.is_scheduled === true) && domOk(s.domain);
    }) : [];
    return { db, live };
}

// Temuan unik dari beberapa eksekusi (domain + judul + severity; jumlah = terbanyak dalam satu eksekusi)
function uniqueScheduleFindings(dbRuns) {
    const map = new Map();
    dbRuns.forEach(run => {
        const dom = schedNormTarget(run.domains?.domain_name || '');
        const per = new Map();
        (run.vulnerabilities || []).forEach(v => {
            const sev = String(v.severity || v.risk_level || 'INFO').toUpperCase();
            const key = `${dom}|${String(v.title || v.name || '').trim().toLowerCase()}|${sev}`;
            const e = per.get(key) || { n: 0, v };
            e.n += 1;
            per.set(key, e);
        });
        per.forEach((e, key) => { const prev = map.get(key); if (!prev || e.n > prev.n) map.set(key, e); });
    });
    const out = [];
    map.forEach(e => { for (let i = 0; i < e.n; i++) out.push(e.v); });
    return out;
}

function spStatusBadge(kind, extra = '') {
    const [label, cls] = SP_STATUS[kind] || [kind, ''];
    return `<span class="sp-status ${cls}">${kind === 'completed' ? SP_ICON.check : '<span class="sp-dot"></span>'}${label}${extra}</span>`;
}

function spProgress(p) {
    const v = Math.max(0, Math.min(100, parseInt(p, 10) || 0));
    return `<span class="sp-progress" role="progressbar" aria-valuenow="${v}" aria-valuemin="0" aria-valuemax="100"><span style="width:${v}%"></span></span>`;
}

function spRenderHead(cat, mode) {
    const thead = document.getElementById(`${SP_CFG[cat].pre}ScanThead`);
    if (!thead) return;
    thead.innerHTML = mode === 'scheduled'
        ? `<tr><th class="sp-col-target">Target</th><th class="sp-col-sched">Schedule</th><th class="sp-col-freq">Frequency</th><th class="sp-col-status">Status</th><th class="sp-col-results">Results</th><th class="sp-col-action"><span class="sr-only">Aksi</span></th></tr>`
        : `<tr><th class="sp-col-target">Target</th><th class="sp-col-status">Status</th><th class="sp-col-summary">Summary</th><th class="sp-col-date">Date</th><th class="sp-col-action"><span class="sr-only">Aksi</span></th></tr>`;
}

function spRenderChips(cat) {
    const el = document.getElementById(`${SP_CFG[cat].pre}SchedChips`);
    if (!el) return;
    const c = spState[cat].schedCounts || { ALL: 0, pending: 0, running: 0, completed: 0, cancelled: 0 };
    const items = [['ALL', 'All'], ['pending', 'Pending'], ['running', 'Running'], ['completed', 'Completed'], ['cancelled', 'Cancelled']];
    el.innerHTML = items.map(([k, label]) => {
        const on = spState[cat].schedStatus === k;
        return `<button type="button" class="sp-chip${on ? ' is-active' : ''}" aria-pressed="${on}" data-sp-chip="${k}">${label}<span class="sp-chip-n">${c[k] || 0}</span></button>`;
    }).join('');
    el.onclick = (e) => {
        const b = e.target.closest('[data-sp-chip]');
        if (!b) return;
        spState[cat].schedStatus = b.dataset.spChip;
        SP_CFG[cat].apply();
    };
}

function spRenderManualChips(cat) {
    const pre = SP_CFG[cat].pre;
    const el = document.getElementById(`${pre}ManualChips`);
    const sel = document.getElementById(`${pre}StatusFilter`);
    if (!el || !sel) return;
    const c = spState[cat].manualCounts || { ALL: 0, running: 0, completed: 0 };
    const current = sel.value || 'ALL';
    el.innerHTML = [['ALL', 'All'], ['running', 'Running'], ['completed', 'Completed']].map(([k, label]) => {
        const on = current === k;
        return `<button type="button" class="sp-chip${on ? ' is-active' : ''}" aria-pressed="${on}" data-sp-manual="${k}">${label}<span class="sp-chip-n">${c[k] || 0}</span></button>`;
    }).join('');
    el.onclick = (e) => {
        const b = e.target.closest('[data-sp-manual]');
        if (!b) return;
        sel.value = b.dataset.spManual;
        SP_CFG[cat].apply();
    };
}

function spRenderNote(cat) {
    const el = document.getElementById(`${SP_CFG[cat].pre}OvernightNote`);
    if (!el) return;
    const canOpen = currentUser && currentUser.role === 'superadmin';
    el.innerHTML = `${SP_ICON.moon}<span>Scan malam untuk semua domain aktif (Overnight Scan) adalah fitur terpisah dan diatur di System Settings.</span>${canOpen ? `<a href="#/system-settings" class="sp-link" onclick="switchView('system-settings', event)">Buka System Settings</a>` : ''}`;
}

function spMessage(tbody, cols, title, sub, btnHtml, cls = '') {
    tbody.innerHTML = `<tr class="sp-message-row"><td colspan="${cols}"><div class="sp-message ${cls}"><strong>${title}</strong>${sub ? `<span>${sub}</span>` : ''}${btnHtml || ''}</div></td></tr>`;
}

function spManualRows(list) {
    return list.map(scan => {
        if (scan.live_status !== undefined) {
            const d = spLiveDate(scan);
            const dom = escapeHtml(String(scan.domain || 'Unknown Target').replace(/^https?:\/\//, '').replace(/\/$/, ''));
            return `<tr class="sp-row is-live">
                <td class="sp-col-target"><div class="sp-target"><strong>${dom}</strong><span>${escapeHtml(scan.target || 'Scan berjalan')}</span></div></td>
                <td class="sp-col-status">${spStatusBadge('running', ` ${parseInt(scan.progress, 10) || 0}%`)}</td>
                <td class="sp-col-summary">${spProgress(scan.progress)}</td>
                <td class="sp-col-date">${d ? spDate(d) : '-'}</td>
                <td class="sp-col-action"><button type="button" class="sp-btn sp-btn-danger" data-sp-stop="${escapeHtml(String(scan.scan_id))}">Stop</button></td>
            </tr>`;
        }
        const idx = allVulns.indexOf(scan);
        const d = new Date(scan.scan_date);
        const dom = escapeHtml(scan.domains?.domain_name || 'Unknown Target');
        return `<tr class="sp-row" tabindex="0" data-sp-open="${idx}" aria-label="Buka laporan ${dom}">
            <td class="sp-col-target"><div class="sp-target"><strong>${dom}</strong><span>${escapeHtml(scan.domains?.ip_address || '-')}</span></div></td>
            <td class="sp-col-status">${spStatusBadge('completed')}</td>
            <td class="sp-col-summary">${renderSevSummary(scan.vulnerabilities)}</td>
            <td class="sp-col-date">${isNaN(d) ? '-' : spDate(d)}</td>
            <td class="sp-col-action"><button type="button" class="sp-btn" data-sp-open="${idx}">View Report</button></td>
        </tr>`;
    }).join('');
}

function spScheduleRows(cat, list) {
    return list.map(sc => {
        const { db, live } = scheduleRuns(sc, cat);
        const runs = db.length + live.length;
        const collapsed = isScheduleCollapsed(sc);
        const start = new Date(sc.scheduled_at || sc.created_at);
        const end = sc.window_end_at ? new Date(sc.window_end_at) : null;
        const freq = sc.frequency || (end ? 'window' : 'once');
        const targets = (Array.isArray(sc.targets) ? sc.targets : []);
        const targetText = targets.length > 2 ? `${targets.slice(0, 2).join(', ')}, +${targets.length - 2}` : targets.join(', ');
        const uniq = uniqueScheduleFindings(db);
        let results;
        if (db.length) results = `<div class="sp-results"><span class="sp-results-note">${db.length} scan · ${uniq.length} temuan unik</span>${renderSevSummary(uniq)}</div>`;
        else if (live.length) results = `<span class="sp-muted">Eksekusi pertama sedang berjalan</span>`;
        else if (sc.status === 'pending') results = `<span class="sp-muted">Mulai ${isNaN(start) ? '-' : spDate(start)}</span>`;
        else results = `<span class="sp-muted">Belum ada scan</span>`;
        const canCancel = sc.status === 'pending' || sc.status === 'running';
        let html = `<tr class="sp-sched-row${collapsed ? '' : ' is-open'}">
            <td class="sp-col-target">
                <div class="sp-sched-target">
                    <button type="button" class="sp-expand" data-sp-toggle="${sc.id}" data-sp-collapsed="${collapsed}" aria-expanded="${!collapsed}" aria-label="${collapsed ? 'Tampilkan' : 'Sembunyikan'} eksekusi jadwal #${sc.id}" ${runs ? '' : 'disabled'}>${SP_ICON.chevron}</button>
                    <div class="sp-target"><strong title="${escapeHtml(targets.join(', '))}">${escapeHtml(targetText || '-')}</strong><span>${(sc.scan_type || 'deep') === 'light' ? 'Light scan' : 'Deep scan'} · Jadwal #${sc.id}</span></div>
                </div>
            </td>
            <td class="sp-col-sched"><div class="sp-target"><strong>${isNaN(start) ? '-' : spDay(start)}</strong><span>${isNaN(start) ? '' : shTime(start)}${end ? ` - ${shTime(end)}` : ''} WIB</span></div></td>
            <td class="sp-col-freq">${SP_FREQ[freq] || freq}</td>
            <td class="sp-col-status">${spStatusBadge(sc.status)}</td>
            <td class="sp-col-results">${results}</td>
            <td class="sp-col-action"><div class="sp-actions">
                ${canCancel ? `<button type="button" class="sp-btn sp-btn-danger" data-sp-cancel="${sc.id}" data-sp-status="${sc.status}">Cancel</button>` : ''}
                ${runs ? `<button type="button" class="sp-btn" data-sp-toggle="${sc.id}" data-sp-collapsed="${collapsed}">${collapsed ? `Show runs (${runs})` : 'Hide runs'}</button>` : ''}
            </div></td>
        </tr>`;
        if (!collapsed) {
            db.forEach((run, i) => {
                const idx = allVulns.indexOf(run);
                const d = new Date(run.scan_date);
                html += `<tr class="sp-run-row" tabindex="0" data-sp-open="${idx}">
                    <td class="sp-col-target"><div class="sp-run-target"><span class="sp-run-chip">Scan ${i + 1}</span><span>${escapeHtml(run.domains?.domain_name || '-')}</span></div></td>
                    <td class="sp-col-sched" colspan="2">${isNaN(d) ? '-' : spDate(d)}</td>
                    <td class="sp-col-status">${spStatusBadge('completed')}</td>
                    <td class="sp-col-results">${renderSevSummary(run.vulnerabilities)}</td>
                    <td class="sp-col-action"><button type="button" class="sp-btn" data-sp-open="${idx}">View Report</button></td>
                </tr>`;
            });
            live.forEach((run, i) => {
                const d = spLiveDate(run);
                html += `<tr class="sp-run-row is-live">
                    <td class="sp-col-target"><div class="sp-run-target"><span class="sp-run-chip">Scan ${db.length + i + 1}</span><span>${escapeHtml(String(run.domain || '-'))}</span></div></td>
                    <td class="sp-col-sched" colspan="2">${d ? spDate(d) : '-'}</td>
                    <td class="sp-col-status">${spStatusBadge('running', ` ${parseInt(run.progress, 10) || 0}%`)}</td>
                    <td class="sp-col-results">${spProgress(run.progress)}</td>
                    <td class="sp-col-action"><button type="button" class="sp-btn sp-btn-danger" data-sp-stop="${escapeHtml(String(run.scan_id))}">Stop</button></td>
                </tr>`;
            });
        }
        return html;
    }).join('');
}

function spBind(cat, tbody) {
    if (tbody.dataset.spBound) return;
    tbody.dataset.spBound = '1';
    const open = (el) => { const i = parseInt(el.dataset.spOpen, 10); if (i >= 0) openScanModalIndex(i); };
    tbody.addEventListener('click', (e) => {
        const t = e.target;
        const stop = t.closest('[data-sp-stop]');
        if (stop) { e.stopPropagation(); stopActiveScan(stop.dataset.spStop); return; }
        const cancel = t.closest('[data-sp-cancel]');
        if (cancel) { e.stopPropagation(); cancelScheduledScan(parseInt(cancel.dataset.spCancel, 10), cancel.dataset.spStatus); return; }
        const tog = t.closest('[data-sp-toggle]');
        if (tog) { e.stopPropagation(); toggleScheduleCollapse(parseInt(tog.dataset.spToggle, 10), tog.dataset.spCollapsed === 'true'); return; }
        const reset = t.closest('[data-sp-reset]');
        if (reset) { spResetFilters(cat); return; }
        const newScan = t.closest('[data-sp-new]');
        if (newScan) { SP_CFG[cat].newScan(); return; }
        const retry = t.closest('[data-sp-retry]');
        if (retry) { loadVulnerabilities(); return; }
        const row = t.closest('[data-sp-open]');
        if (row) open(row);
    });
    tbody.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        if (e.target.closest('button')) return;
        const row = e.target.closest('tr[data-sp-open]');
        if (row) { e.preventDefault(); open(row); }
    });
}

function spRenderPagination(cat, total, totalPages, start, end) {
    const el = document.getElementById(SP_CFG[cat].pag);
    if (!el) return;
    if (!total) { el.innerHTML = ''; return; }
    const cfg = SP_CFG[cat];
    const page = cfg.page();
    const noun = cfg.mode() === 'scheduled' ? 'jadwal' : 'scan';
    el.innerHTML = `
        <div class="sp-pag-left">
            <span>Menampilkan ${start + 1}-${end} dari ${total} ${noun}</span>
            <label class="sp-pag-rows">Per halaman
                <select data-sp-rows>${[10, 15, 25, 50].map(n => `<option value="${n}" ${cfg.rows() === n ? 'selected' : ''}>${n}</option>`).join('')}</select>
            </label>
        </div>
        <div class="sp-pag-right">
            <button type="button" class="sp-btn" data-sp-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>Sebelumnya</button>
            <span>Halaman ${page} dari ${totalPages}</span>
            <button type="button" class="sp-btn" data-sp-page="${page + 1}" ${page >= totalPages ? 'disabled' : ''}>Selanjutnya</button>
        </div>`;
    el.onclick = (e) => {
        const b = e.target.closest('[data-sp-page]');
        if (!b || b.disabled) return;
        cfg.setPage(parseInt(b.dataset.spPage, 10));
        renderScanPage(cat);
    };
    const sel = el.querySelector('[data-sp-rows]');
    if (sel) sel.onchange = () => { cfg.setRows(parseInt(sel.value, 10)); cfg.setPage(1); renderScanPage(cat); };
}

function renderScanPage(cat) {
    const cfg = SP_CFG[cat];
    const tbody = document.getElementById(cfg.tbody);
    if (!tbody) return;
    const card = document.getElementById(`${cfg.pre}ScanCard`);
    const mode = cfg.mode() === 'scheduled' ? 'scheduled' : 'single';
    if (card) card.dataset.mode = mode;
    spBind(cat, tbody);
    spRenderHead(cat, mode);
    spRenderChips(cat);
    spRenderManualChips(cat);
    spRenderNote(cat);
    fltResetLabel(document.getElementById(`${cfg.pre}ResetBtn`), spActiveFilterCount(cat));
    const cols = mode === 'scheduled' ? 6 : 5;

    // Memuat pertama kali: kerangka dari HTML tetap tampil
    if (vulnLoadState !== 'ready' && vulnLoadState !== 'error' && !allVulns.length && !(cfg.schedules() || []).length) {
        spRenderPagination(cat, 0);
        return;
    }
    if (vulnLoadState === 'error' && !allVulns.length) {
        spMessage(tbody, cols, 'Gagal memuat data scan', 'Server tidak merespons. Coba lagi beberapa saat.', '<button type="button" class="sp-btn" data-sp-retry>Coba lagi</button>', 'is-error');
        spRenderPagination(cat, 0);
        return;
    }

    const list = (cfg.list() || []).filter(s => mode === 'scheduled' ? s.is_scheduled === true : s.is_scheduled !== true);
    if (!list.length) {
        if (spFiltersActive(cat)) {
            spMessage(tbody, cols, mode === 'scheduled' ? 'Tidak ada jadwal yang cocok' : 'Tidak ada scan yang cocok', 'Coba ubah kata kunci, status, atau rentang tanggal.', '<button type="button" class="sp-btn" data-sp-reset>Reset filter</button>');
        } else if (mode === 'scheduled') {
            spMessage(tbody, cols, 'Belum ada jadwal scan', `Buat jadwal ${cfg.label} Scan, misalnya sekali di jam tertentu atau berulang dari 15:00 sampai 17:00.`, `<button type="button" class="sp-btn sp-btn-primary" data-sp-new>New ${cfg.label} Scan</button>`);
        } else {
            spMessage(tbody, cols, `Belum ada ${cfg.label.toLowerCase()} scan manual`, 'Jalankan scan pertama untuk domain aktif di Domain Inventory.', `<button type="button" class="sp-btn sp-btn-primary" data-sp-new>New ${cfg.label} Scan</button>`);
        }
        spRenderPagination(cat, 0);
        return;
    }

    const total = list.length;
    const totalPages = Math.ceil(total / cfg.rows()) || 1;
    if (cfg.page() > totalPages) cfg.setPage(totalPages);
    if (cfg.page() < 1) cfg.setPage(1);
    const start = (cfg.page() - 1) * cfg.rows();
    const end = Math.min(start + cfg.rows(), total);
    const pageItems = list.slice(start, end);
    tbody.innerHTML = mode === 'scheduled' ? spScheduleRows(cat, pageItems) : spManualRows(pageItems);
    spRenderPagination(cat, total, totalPages, start, end);
}

function applyWebFilters(preservePage = false) {
    const searchInput = document.getElementById('webScannerSearch')?.value.toLowerCase() || '';

    let scheduledFiltered = scheduledWebScans.filter(scan => {
        const targetsStr = (scan.targets || []).join(' ').toLowerCase();
        if (searchInput && !targetsStr.includes(searchInput)) return false;
        return true;
    });

    const scheduledTargets = new Set();
    scheduledWebScans.forEach(s => {
        (s.targets || []).forEach(t => {
            const cleanT = String(t).toLowerCase().replace('http://', '').replace('https://', '').replace(/\/$/, '').trim();
            if (cleanT) scheduledTargets.add(cleanT);
        });
    });

    let liveFiltered = liveWebScans.filter(scan => {
        const isSubRun = scan.is_scheduled === true || scan.raw_json?.is_scheduled === true || scan.schedule_id || scan.raw_json?.schedule_id;
        if (isSubRun) return false;
        const domainName = (scan.domain || '').toLowerCase().replace('http://', '').replace('https://', '').replace(/\/$/, '').trim();
        if (searchInput && !domainName.includes(searchInput)) return false;
        return true;
    });

    let dbFiltered = webScans.filter(scan => {
        const isSubRun = scan.is_scheduled === true || scan.raw_json?.is_scheduled === true || scan.schedule_id || scan.raw_json?.schedule_id;
        if (isSubRun) return false;
        if (isLegacyScheduledRun(scan, scheduledWebScans)) return false;
        const domainName = (scan.domains?.domain_name || '').toLowerCase().replace('http://', '').replace('https://', '').replace(/\/$/, '').trim();
        const ip = (scan.domains?.ip_address || '').toLowerCase();
        if (searchInput && !domainName.includes(searchInput) && !ip.includes(searchInput)) return false;
        return true;
    });

    ({ scheduled: scheduledFiltered, live: liveFiltered, db: dbFiltered } = spFilterLists('web', { scheduled: scheduledFiltered, live: liveFiltered, db: dbFiltered }));

    if (window.currentWebScanMode === 'single') {
        filteredWebScans = [...liveFiltered, ...dbFiltered];
    } else if (window.currentWebScanMode === 'scheduled') {
        filteredWebScans = [...scheduledFiltered];
    } else {
        filteredWebScans = [...scheduledFiltered, ...liveFiltered, ...dbFiltered];
    }

    if (!preservePage) {
        webCurrentPage = 1;
    }
    renderWebScannerTable();
}

function renderWebScannerTable() {
    renderScanPage('web');
    if (typeof window.syncWebSelectAll === 'function') window.syncWebSelectAll();
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

let selectedDomainIds = new Set();
let isSelectionModeActive = false;

window.toggleSelectionMode = function (event) {
    if (event) event.stopPropagation();
    isSelectionModeActive = !isSelectionModeActive;
    if (!isSelectionModeActive) {
        selectedDomainIds.clear();
    }
    updateSelectionModeUI();
    renderInventoryList();
};

function updateSelectionModeUI() {
    const btn = document.getElementById('toggleSelectionModeBtn');
    const text = document.getElementById('selectionModeBtnText');
    if (btn) {
        if (isSelectionModeActive) {
            btn.style.background = 'var(--primary)';
            btn.style.color = '#ffffff';
            btn.style.borderColor = 'var(--primary)';
            if (text) text.textContent = 'Keluar Mode Seleksi';
        } else {
            btn.style.background = 'white';
            btn.style.color = 'var(--text-primary)';
            btn.style.borderColor = 'var(--color-border)';
            if (text) text.textContent = 'Mode Seleksi';
        }
    }
    updateDirectBulkBar();
}

window.handleRowClick = function (domainId, event) {
    if (isSelectionModeActive || (event && (event.ctrlKey || event.shiftKey || event.metaKey))) {
        if (event) {
            event.preventDefault();
            event.stopPropagation();
        }
        if (selectedDomainIds.has(domainId)) {
            selectedDomainIds.delete(domainId);
        } else {
            selectedDomainIds.add(domainId);
            isSelectionModeActive = true;
        }
        updateSelectionModeUI();
        renderInventoryList();
    }
};

window.handleIpCopyClick = function (ip, domainId, event) {
    if (isSelectionModeActive) {
        if (event) {
            event.preventDefault();
            event.stopPropagation();
        }
        if (domainId) handleRowClick(domainId, event);
        return;
    }
    if (event) event.stopPropagation();
    copyToClipboard(ip, event, 'IP Address');
};

function updateDirectBulkBar() {
    const bar = document.getElementById('directBulkBar');
    const countEl = document.getElementById('directBulkCount');
    if (!bar) return;

    const count = selectedDomainIds.size;
    if (countEl) countEl.textContent = count;

    if (count > 0) {
        bar.style.visibility = 'visible';
        bar.style.opacity = '1';
        bar.style.transform = 'translateX(-50%) translateY(0)';
    } else {
        bar.style.visibility = 'hidden';
        bar.style.opacity = '0';
        bar.style.transform = 'translateX(-50%) translateY(120px)';
    }
}

window.clearDirectSelection = function () {
    selectedDomainIds.clear();
    isSelectionModeActive = false;
    updateSelectionModeUI();
    renderInventoryList();
};

window.selectAllCurrentRowsToggle = function () {
    const paged = typeof getFilteredAndSortedDomains === 'function' ? getFilteredAndSortedDomains() : (allDomains || []);
    const allSelected = paged.length > 0 && paged.every(d => selectedDomainIds.has(d.id));

    if (allSelected) {
        paged.forEach(d => selectedDomainIds.delete(d.id));
    } else {
        paged.forEach(d => selectedDomainIds.add(d.id));
        isSelectionModeActive = true;
    }
    updateSelectionModeUI();
    renderInventoryList();
};

window.directBulkToggleActive = async function (targetStatus) {
    if (selectedDomainIds.size === 0) return;
    const targets = (allDomains || []).filter(d => selectedDomainIds.has(d.id));
    if (targets.length === 0) return;

    const confirmed = await customConfirm({
        title: `${targetStatus ? 'Aktifkan' : 'Nonaktifkan'} Overnight Scan?`,
        message: `Overnight Scan akan ${targetStatus ? 'diaktifkan' : 'dinonaktifkan'} untuk ${targets.length} domain terpilih.`,
        confirmText: `${targetStatus ? 'Aktifkan' : 'Nonaktifkan'} ${targets.length} domain`,
        cancelText: 'Batal',
        variant: targetStatus ? 'info' : 'warning'
    });
    if (!confirmed) return;

    const previous = new Map(targets.map(d => [d.id, d.is_active]));
    targets.forEach(d => d.is_active = targetStatus);
    renderInventoryList();

    // Simpan satu per satu dan periksa jawaban server; hanya yang tersimpan yang dihitung berhasil
    const results = await Promise.all(targets.map(d =>
        fetch(`${API_BASE}/api/domains/${d.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                domain_name: d.domain_name,
                ip_address: d.ip_address,
                is_active: targetStatus
            })
        }).then(r => r.ok).catch(() => false)
    ));
    const failed = targets.filter((d, i) => !results[i]);
    failed.forEach(d => { d.is_active = previous.get(d.id); });
    const saved = targets.length - failed.length;
    const label = targetStatus ? 'aktif' : 'nonaktif';
    if (!failed.length) {
        showToast(`Overnight Scan ${label} untuk ${saved} domain.`, 'success');
        clearDirectSelection();
    } else {
        renderInventoryList();
        showToast(saved
            ? `Overnight Scan ${label} untuk ${saved} domain. ${failed.length} gagal disimpan: ${failed.map(d => d.domain_name).join(', ')}.`
            : `Gagal menyimpan. Overnight Scan tidak berubah untuk ${failed.length} domain.`, 'error');
    }
};

window.directBulkLaunchScan = function (type) {
    if (selectedDomainIds.size === 0) return;
    const targets = (allDomains || []).filter(d => selectedDomainIds.has(d.id));
    const targetNames = targets.map(d => d.domain_name);

    openNewScan({ category: type === 'network' ? 'network' : 'web', targets: targetNames });
    clearDirectSelection();
};

window.directBulkDeleteDomains = async function () {
    if (selectedDomainIds.size === 0) return;
    const targets = (allDomains || []).filter(d => selectedDomainIds.has(d.id));
    const confirmed = await customConfirm({
        title: `Hapus ${targets.length} domain beserta riwayat scan-nya?`,
        message: `${targets.slice(0, 3).map(d => d.domain_name).join(', ')}${targets.length > 3 ? `, dan ${targets.length - 3} lainnya` : ''} akan dihapus beserta seluruh riwayat scan-nya. Tindakan ini tidak bisa dibatalkan.`,
        confirmText: `Hapus ${targets.length} domain`,
        cancelText: 'Batal',
        variant: 'danger'
    });
    if (!confirmed) return;

    try {
        await Promise.all(targets.map(d =>
            fetch(`${API_BASE}/api/domains/${d.id}`, { method: 'DELETE' })
        ));
        allDomains = allDomains.filter(d => !selectedDomainIds.has(d.id));
        showToast(`Berhasil menghapus ${targets.length} domain.`, 'success');
        clearDirectSelection();
        if (typeof loadDomains === 'function') loadDomains(true);
    } catch (err) {
        console.error('Error deleting domains:', err);
        showToast('Gagal menghapus beberapa domain.', 'error');
    }
};

let batchStatusSearchQuery = '';

window.openBatchStatusModal = function (event) {
    if (event && event.stopPropagation) {
        event.stopPropagation();
    }

    const modal = document.getElementById('batchStatusModalOverlay');
    if (modal) {
        modal.style.display = 'flex';
        modal.style.opacity = '1';
        modal.style.visibility = 'visible';
        modal.classList.add('active');
    }

    batchStatusSearchQuery = '';
    const input = document.getElementById('batchStatusSearchInput');
    if (input) input.value = '';

    renderBatchStatusTargetList();

    if (!allDomains || allDomains.length === 0) {
        fetch(`${API_BASE}/api/domains`)
            .then(res => res.json())
            .then(data => {
                allDomains = Array.isArray(data) ? data : (data.domains || []);
                renderBatchStatusTargetList();
            })
            .catch(e => console.error("Error fetching domains for batch modal:", e));
    }
};

window.closeBatchStatusModal = function (event) {
    if (event && event.stopPropagation) {
        event.stopPropagation();
    }
    const modal = document.getElementById('batchStatusModalOverlay');
    if (modal) {
        modal.classList.remove('active');
        modal.style.opacity = '0';
        modal.style.visibility = 'hidden';
        modal.style.display = 'none';
    }
};

function onBatchStatusSearch(val) {
    batchStatusSearchQuery = val;
    renderBatchStatusTargetList();
    const input = document.getElementById('batchStatusSearchInput');
    if (input) {
        input.focus();
        input.setSelectionRange(val.length, val.length);
    }
}

function renderBatchStatusTargetList() {
    const container = document.getElementById('batchStatusListContainer');
    const countLabel = document.getElementById('batchStatusResultCount');
    if (!container) return;

    if (!allDomains || allDomains.length === 0) {
        container.innerHTML = '<div style="padding: 16px; text-align: center; color: var(--color-muted); font-size: 13px;">Tidak ada domain di inventory</div>';
        if (countLabel) countLabel.textContent = '0 Domain';
        return;
    }

    const q = batchStatusSearchQuery.trim().toLowerCase();
    const filtered = allDomains.filter(d => {
        const dName = (d.domain_name || '').toLowerCase();
        const ip = (d.ip_address || '').toLowerCase();
        return !q || dName.includes(q) || ip.includes(q);
    });

    if (countLabel) {
        countLabel.textContent = q ? `${filtered.length} dari ${allDomains.length} domain cocok` : `Seluruh Domain Inventory (${allDomains.length})`;
    }

    if (filtered.length === 0) {
        container.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--color-muted); font-size: 13px;">Tidak ada domain/IP yang cocok dengan pencarian</div>';
        return;
    }

    container.innerHTML = filtered.map(d => `
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; border-radius: 8px; background: var(--color-surface); border: 1px solid var(--color-border); transition: all 0.15s;">
            <div>
                <span style="font-size: 13px; font-weight: 600; color: var(--color-ink); display: block;">${escapeHtml(d.domain_name)}</span>
                ${d.ip_address ? `<span style="font-size: 11px; color: var(--color-muted); font-family: inherit;">${escapeHtml(d.ip_address)}</span>` : ''}
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
                <button type="button"
                        onclick="toggleDomainActiveInModal(${d.id}, ${d.is_active ? 'false' : 'true'})"
                        class="badge-toggle-btn ${d.is_active ? 'is-active' : 'is-inactive'}"
                        style="padding: 4px 12px; font-size: 11px;">
                    ${d.is_active ? 'ACTIVE' : 'INACTIVE'}
                </button>
            </div>
        </div>
    `).join('');
}

async function toggleDomainActiveInModal(domainId, newStatus) {
    const domain = (allDomains || []).find(item => item.id === domainId);
    if (!domain) return;

    domain.is_active = newStatus;
    renderBatchStatusTargetList();
    renderInventoryList();

    try {
        await fetch(`${API_BASE}/api/domains/${domainId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                domain_name: domain.domain_name,
                ip_address: domain.ip_address,
                is_active: newStatus
            })
        });
        showToast(
            'Status Target',
            `Domain ${domain.domain_name} sekarang ${newStatus ? 'ACTIVE' : 'INACTIVE'}.`,
            newStatus ? 'Active' : 'Inactive'
        );
    } catch (err) {
        console.error('Error toggling status:', err);
        showToast('Error', 'Gagal memperbarui status domain.', '');
    }
}

async function triggerBatchSetStatus(targetStatus) {
    const q = batchStatusSearchQuery.trim().toLowerCase();
    const filtered = (allDomains || []).filter(d => {
        const dName = (d.domain_name || '').toLowerCase();
        const ip = (d.ip_address || '').toLowerCase();
        return !q || dName.includes(q) || ip.includes(q);
    });

    if (filtered.length === 0) {
        showToast('Info', 'Tidak ada target domain yang dipilih untuk diubah.', 'ℹ️');
        return;
    }

    const actionText = targetStatus ? 'mengaktifkan' : 'menonaktifkan';
    const confirmed = await customConfirm({
        title: `${targetStatus ? 'Aktifkan' : 'Nonaktifkan'} Domain Cocok Pencarian`,
        message: `Apakah Anda yakin ingin ${actionText} ${filtered.length} domain target yang cocok dengan pencarian?`,
        confirmText: `Ya, ${targetStatus ? 'Aktifkan' : 'Nonaktifkan'}`,
        cancelText: 'Batal',
        variant: targetStatus ? 'info' : 'warning'
    });
    if (!confirmed) return;

    filtered.forEach(d => d.is_active = targetStatus);
    renderBatchStatusTargetList();
    renderInventoryList();

    try {
        await Promise.all(filtered.map(d => 
            fetch(`${API_BASE}/api/domains/${d.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    domain_name: d.domain_name,
                    ip_address: d.ip_address,
                    is_active: targetStatus
                })
            })
        ));
        showToast(`Berhasil ${targetStatus ? 'mengaktifkan' : 'menonaktifkan'} ${filtered.length} domain.`, 'success');
    } catch (err) {
        console.error('Error batch setting status:', err);
        showToast('Gagal memperbarui beberapa status domain.', 'error');
    }
}

async function stopActiveScan(scanId) {
    const confirmed = await customConfirm({
        title: 'Hentikan Pemindaian',
        message: 'Apakah Anda yakin ingin menghentikan pemindaian yang sedang berjalan ini?',
        confirmText: 'Ya, Hentikan Scan',
        cancelText: 'Batal',
        variant: 'warning'
    });
    if (!confirmed) return;

    fetch(`${API_BASE}/api/scans/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanId })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                showToast(data.message || 'Pemindaian dihentikan.', 'success');
                fetchActiveScans();
            } else {
                showToast('Error', data.detail || data.message, '');
            }
        })
        .catch(err => {
            console.error('Error stopping scan:', err);
            showToast('Error', 'An error occurred while stopping the scan.', '');
        });
}

// (Web Scanner polling is handled inside switchView directly)

// =========================================================
// JENDELA "SCAN BARU": jenis + tipe, domain, kapan dijalankan
// - Sekarang: POST /api/scans/launch-now
// - Jadwalkan sekali: POST /api/scans/schedule (frequency once)
// - Jadwalkan + "Scan berulang terus sampai jam": frequency window (scan diulang sampai jam selesai)
// =========================================================
const NSM_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];
const NSM_SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
let nsm = null;
let nsmReturnFocus = null;

const nsmPad = (n) => String(n).padStart(2, '0');
const nsmIsoDate = (d) => `${d.getFullYear()}-${nsmPad(d.getMonth() + 1)}-${nsmPad(d.getDate())}`;
const nsmHm = (d) => `${nsmPad(d.getHours())}:${nsmPad(d.getMinutes())}`;
const nsmFmtDate = (iso) => { const [y, m, d] = String(iso).split('-').map(Number); return y && m && d ? `${d} ${NSM_MONTHS[m - 1]} ${y}` : '-'; };
const nsmAt = (date, hm) => { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date || ''); const t = /^(\d{1,2}):(\d{2})$/.exec(hm || ''); return m && t ? new Date(+m[1], +m[2] - 1, +m[3], +t[1], +t[2]) : null; };

// Default jadwal: jam mulai satu jam dari sekarang (dibulatkan ke atas 5 menit), selesai dua jam setelahnya
function nsmDefaultTimes(now = new Date()) {
    const s = new Date(now.getTime() + 3600000);
    s.setSeconds(0, 0);
    s.setMinutes(Math.ceil(s.getMinutes() / 5) * 5);
    let e = new Date(s.getTime() + 2 * 3600000);
    if (nsmIsoDate(e) !== nsmIsoDate(s)) e = new Date(s.getFullYear(), s.getMonth(), s.getDate(), 23, 55);
    return { date: nsmIsoDate(s), start: nsmHm(s), end: nsmHm(e) };
}

function nsmValidate(state, now = new Date()) {
    if (!state.selected || !state.selected.size) return { ok: false, field: 'domains', msg: 'Pilih minimal satu domain.' };
    if (state.when !== 'schedule') return { ok: true };
    const start = nsmAt(state.date, state.start);
    if (!start) return { ok: false, field: 'start', msg: 'Isi tanggal dan jam mulai.' };
    if (start <= now) return { ok: false, field: 'start', msg: 'Jam mulai sudah lewat. Pilih waktu setelah sekarang.' };
    if (state.repeat) {
        const end = nsmAt(state.date, state.end);
        if (!end || end <= start) return { ok: false, field: 'end', msg: 'Jam selesai harus setelah jam mulai.' };
    }
    return { ok: true };
}

function nsmPayload(state) {
    const targets = Array.from(state.selected);
    if (state.when !== 'schedule') {
        return { url: '/api/scans/launch-now', body: { targets, scan_type: state.scanType, scan_category: state.category } };
    }
    return {
        url: '/api/scans/schedule',
        body: {
            scan_category: state.category,
            scan_type: state.scanType,
            targets,
            scheduled_at: `${state.date}T${state.start}:00`,
            window_end_at: state.repeat ? `${state.date}T${state.end}:00` : null,
            frequency: state.repeat ? 'window' : 'once'
        }
    };
}

function nsmCtaLabel(state) {
    const n = state.selected.size;
    if (state.when !== 'schedule') return `Mulai scan ${n} domain`;
    return state.repeat ? `Jadwalkan ${state.start} sampai ${state.end}` : `Jadwalkan ${n} domain`;
}

function nsmWhenText(state) {
    if (state.when !== 'schedule') return 'Scan dimulai begitu tombol ditekan. Progresnya terlihat di penanda "scan sedang berjalan" di topbar.';
    const d = nsmFmtDate(state.date);
    return state.repeat
        ? `${d} pukul ${state.start} sampai ${state.end}, domain di-scan ulang terus (scan baru dimulai begitu scan sebelumnya selesai). Setelah ${state.end} jadwal selesai.`
        : `${d} pukul ${state.start}, domain di-scan satu kali.`;
}

// Domain yang bisa di-scan (sudah disetujui) + info scan terakhir dari riwayat
function nsmDomains() {
    const latest = typeof invLatestScans === 'function' ? invLatestScans() : {};
    return (allDomains || []).filter(d => d.approval_status !== 'pending').map(d => {
        const l = latest[schedNormTarget(d.domain_name)];
        let last = null;
        if (l) {
            const sevs = new Set((l.scan.vulnerabilities || []).map(v => String(v.severity || '').toUpperCase()));
            const lvl = NSM_SEV.find(s => sevs.has(s));
            last = { date: nsmIsoDate(new Date(l.t)), level: lvl ? lvl.charAt(0) + lvl.slice(1).toLowerCase() : 'Safe' };
        } else if (d.last_scan_date && d.last_scan_status) {
            const s = String(d.last_scan_status);
            last = { date: nsmIsoDate(new Date(d.last_scan_date)), level: s.charAt(0) + s.slice(1).toLowerCase() };
        }
        return { name: d.domain_name, ip: d.ip_address || '', last };
    });
}

function nsmVisible(list) {
    const q = nsm.query.trim().toLowerCase();
    return list.filter(d => (nsm.filter === 'never' ? !d.last : true)
        && (!q || d.name.toLowerCase().includes(q) || d.ip.toLowerCase().includes(q)));
}

function nsmRenderList() {
    const box = document.getElementById('nsmList');
    if (!box || !nsm) return;
    const all = nsmDomains();
    document.querySelector('[data-nsm-filter="all"] .nsm-chip-n').textContent = all.length;
    document.querySelector('[data-nsm-filter="never"] .nsm-chip-n').textContent = all.filter(d => !d.last).length;
    document.querySelectorAll('[data-nsm-filter]').forEach(b => {
        const on = b.dataset.nsmFilter === nsm.filter;
        b.classList.toggle('is-active', on);
        b.setAttribute('aria-pressed', String(on));
    });
    const vis = nsmVisible(all);
    if (nsm.loading) box.innerHTML = '<p class="nsm-empty">Memuat daftar domain...</p>';
    else if (!all.length) box.innerHTML = '<p class="nsm-empty">Belum ada domain. Tambahkan dulu di Domain Inventory.</p>';
    else if (!vis.length) box.innerHTML = '<p class="nsm-empty">Tidak ada domain yang cocok.</p>';
    else {
        box.innerHTML = vis.map(d => {
            const on = nsm.selected.has(d.name);
            return `<label class="nsm-row${on ? ' is-on' : ''}">
                <input type="checkbox" value="${escapeHtml(d.name)}" ${on ? 'checked' : ''}>
                <span class="nsm-row-main"><strong>${escapeHtml(d.name)}</strong><span>${d.ip ? escapeHtml(d.ip) : 'IP belum diisi'}</span></span>
                <span class="nsm-row-last${d.last ? '' : ' is-never'}">${d.last ? `Scan terakhir ${nsmFmtDate(d.last.date)} · ${escapeHtml(d.last.level)}` : 'Belum pernah di-scan'}</span>
            </label>`;
        }).join('');
    }
    const all2 = document.getElementById('nsmSelectAll');
    const visSel = vis.filter(d => nsm.selected.has(d.name)).length;
    all2.disabled = !vis.length;
    all2.checked = vis.length > 0 && visSel === vis.length;
    all2.indeterminate = visSel > 0 && visSel < vis.length;
    document.getElementById('nsmCount').textContent = `${nsm.selected.size} dipilih`;
    nsmRenderFooter();
}

function nsmRenderWhen() {
    const sched = nsm.when === 'schedule';
    document.getElementById('nsmScheduleFields').hidden = !sched;
    document.getElementById('nsmEndWrap').hidden = !nsm.repeat;
    document.querySelectorAll('.nsm-when-card').forEach(c => c.classList.toggle('is-on', c.querySelector('input').checked));
    nsmRenderFooter();
}

function nsmRenderFooter() {
    const v = nsmValidate(nsm);
    const btn = document.getElementById('nsmSubmit');
    const hint = document.getElementById('nsmSubmitHint');
    const err = document.getElementById('nsmTimeError');
    document.getElementById('nsmWhenHint').textContent = nsmWhenText(nsm);
    const timeErr = !v.ok && (v.field === 'start' || v.field === 'end') ? v.msg : '';
    err.textContent = timeErr;
    err.hidden = !timeErr;
    document.getElementById('nsmStart').setAttribute('aria-invalid', String(v.field === 'start'));
    document.getElementById('nsmEnd').setAttribute('aria-invalid', String(v.field === 'end'));
    hint.textContent = v.ok ? 'Hasil muncul di Scan History setelah selesai.' : v.msg;
    hint.classList.toggle('is-warn', !v.ok);
    btn.disabled = !v.ok || nsm.sending;
    btn.querySelector('.nsm-cta-text').textContent = nsm.sending
        ? (nsm.when === 'schedule' ? 'Menyimpan...' : 'Memulai...')
        : nsmCtaLabel(nsm);
}

function openNewScan(opts = {}) {
    const overlay = document.getElementById('newScanModalOverlay');
    if (!overlay) return;
    nsmReturnFocus = document.activeElement;
    nsm = {
        category: opts.category === 'network' ? 'network' : 'web',
        scanType: 'deep',
        selected: new Set((opts.targets || []).map(String).filter(Boolean)),
        query: '',
        filter: 'all',
        when: 'now',
        repeat: false,
        sending: false,
        loading: false,
        ...nsmDefaultTimes()
    };
    overlay.querySelector(`input[name="nsmCategory"][value="${nsm.category}"]`).checked = true;
    overlay.querySelector('input[name="nsmScanType"][value="deep"]').checked = true;
    overlay.querySelector('input[name="nsmWhen"][value="now"]').checked = true;
    document.getElementById('nsmSearch').value = '';
    document.getElementById('nsmDate').value = nsm.date;
    document.getElementById('nsmDate').min = nsmIsoDate(new Date());
    document.getElementById('nsmStart').value = nsm.start;
    document.getElementById('nsmEnd').value = nsm.end;
    document.getElementById('nsmRepeat').checked = false;
    nsmSyncCategoryCards();
    nsmRenderWhen();
    nsmRenderList();
    overlay.classList.add('active');
    overlay.querySelector('.nsm-body').scrollTop = 0;
    setTimeout(() => overlay.querySelector('.modal-dialog')?.focus(), 30);
    // Daftar domain belum dimuat (misalnya Domain Inventory belum dibuka)
    if (!(allDomains || []).length && typeof ovFetchDomains === 'function') {
        nsm.loading = true;
        nsmRenderList();
        ovFetchDomains().then(list => {
            if (Array.isArray(list) && list.length && !(allDomains || []).length) allDomains = list;
            if (nsm) { nsm.loading = false; nsmRenderList(); }
        });
    }
}

function closeNewScan() {
    document.getElementById('newScanModalOverlay')?.classList.remove('active');
    if (nsmReturnFocus && document.body.contains(nsmReturnFocus)) nsmReturnFocus.focus({ preventScroll: true });
    nsmReturnFocus = null;
}

function nsmSyncCategoryCards() {
    document.querySelectorAll('.nsm-type-card').forEach(c => c.classList.toggle('is-on', c.querySelector('input').checked));
    document.querySelectorAll('.nsm-depth-opt').forEach(c => c.classList.toggle('is-on', c.querySelector('input').checked));
}

async function nsmSubmit() {
    if (!nsm || nsm.sending) return;
    const v = nsmValidate(nsm);
    if (!v.ok) { nsmRenderFooter(); return; }
    const { url, body } = nsmPayload(nsm);
    const n = nsm.selected.size;
    const sched = nsm.when === 'schedule';
    nsm.sending = true;
    nsmRenderFooter();
    try {
        const res = await fetch(`${API_BASE}${url}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const data = await res.json().catch(() => ({}));
        if (res.ok && (data.status === 'success' || data.status === 'ok')) {
            showToast(sched ? `Jadwal tersimpan untuk ${n} domain.` : `Scan dimulai untuk ${n} domain.`, 'success');
            nsm.sending = false;
            closeNewScan();
            if (sched && typeof fetchScheduledScans === 'function') fetchScheduledScans();
            if (!sched && typeof fetchActiveScans === 'function') fetchActiveScans();
            return;
        }
        showToast(data.detail || data.message || (sched ? 'Gagal menyimpan jadwal.' : 'Gagal memulai scan.'), 'error');
    } catch (e) {
        showToast('Server tidak merespons. Pilihan Anda masih ada, coba lagi.', 'error');
    }
    if (nsm) { nsm.sending = false; nsmRenderFooter(); }
}

(function nsmBind() {
    const ov = document.getElementById('newScanModalOverlay');
    if (!ov) return;
    ov.addEventListener('change', (e) => {
        if (!nsm) return;
        const t = e.target;
        if (t.name === 'nsmCategory') { nsm.category = t.value; nsmSyncCategoryCards(); }
        else if (t.name === 'nsmScanType') { nsm.scanType = t.value; nsmSyncCategoryCards(); }
        else if (t.name === 'nsmWhen') { nsm.when = t.value; nsmRenderWhen(); }
        else if (t.id === 'nsmRepeat') { nsm.repeat = t.checked; nsmRenderWhen(); }
        else if (t.id === 'nsmDate' || t.id === 'nsmStart' || t.id === 'nsmEnd') { nsm[{ nsmDate: 'date', nsmStart: 'start', nsmEnd: 'end' }[t.id]] = t.value; nsmRenderFooter(); }
        else if (t.id === 'nsmSelectAll') {
            nsmVisible(nsmDomains()).forEach(d => (t.checked ? nsm.selected.add(d.name) : nsm.selected.delete(d.name)));
            nsmRenderList();
        } else if (t.closest('#nsmList') && t.type === 'checkbox') {
            t.checked ? nsm.selected.add(t.value) : nsm.selected.delete(t.value);
            t.closest('.nsm-row')?.classList.toggle('is-on', t.checked);
            const vis = nsmVisible(nsmDomains());
            const visSel = vis.filter(d => nsm.selected.has(d.name)).length;
            const sa = document.getElementById('nsmSelectAll');
            sa.checked = visSel === vis.length;
            sa.indeterminate = visSel > 0 && visSel < vis.length;
            document.getElementById('nsmCount').textContent = `${nsm.selected.size} dipilih`;
            nsmRenderFooter();
        }
    });
    ov.addEventListener('input', (e) => {
        if (!nsm) return;
        if (e.target.id === 'nsmSearch') { nsm.query = e.target.value; nsmRenderList(); }
        else if (['nsmDate', 'nsmStart', 'nsmEnd'].includes(e.target.id)) { nsm[{ nsmDate: 'date', nsmStart: 'start', nsmEnd: 'end' }[e.target.id]] = e.target.value; nsmRenderFooter(); }
    });
    ov.addEventListener('click', (e) => {
        if (e.target === ov) { closeNewScan(); return; }
        const f = e.target.closest('[data-nsm-filter]');
        if (f && nsm) { nsm.filter = f.dataset.nsmFilter; nsmRenderList(); return; }
        if (e.target.closest('#nsmSubmit')) nsmSubmit();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && ov.classList.contains('active')) closeNewScan();
    });
})();

// Pintu masuk lama diarahkan ke jendela baru
function openSelectScanTypeModal() { openNewScan(); }
function openWebScanModal() { openNewScan({ category: 'web' }); }
function openNetworkScanModal() { openNewScan({ category: 'network' }); }
window.openNewScan = openNewScan;
window.closeNewScan = closeNewScan;
window.nsmValidate = nsmValidate;
window.nsmPayload = nsmPayload;
window.nsmCtaLabel = nsmCtaLabel;


async function openLastScanModal(domainName, event, lastScanId = null) {
    if (event) event.stopPropagation();

    // Pastikan allVulns sudah terisi, jika belum fetch otomatis dari API
    if (!allVulns || allVulns.length === 0) {
        try {
            const resp = await fetch(`${API_BASE}/api/scan-history?limit=1000`);
            const data = await resp.json();
            allVulns = normalizeInfoRisk(data.data || []);
        } catch (err) {
            console.error("Gagal memuat scan history:", err);
        }
    }

    let scan = null;
    if (lastScanId && allVulns) {
        scan = allVulns.find(s => String(s.id) === String(lastScanId));
    }
    if (!scan && allVulns) {
        scan = allVulns.find(s => {
            const dName = s.domains?.domain_name || s.domain_name;
            return dName && dName.toLowerCase() === domainName.toLowerCase();
        });
    }

    if (scan) {
        openScanModal(scan);
    } else if (lastScanId) {
        try {
            const res = await fetch(`${API_BASE}/api/scan-history/${lastScanId}`);
            const data = await res.json();
            if (data.status === 'success' && data.data) {
                openScanModal(data.data);
                return;
            }
        } catch (e) {}
        showToast('Info', `Laporan scan untuk ${domainName} tidak ditemukan.`, 'ℹ️');
    } else {
        showToast('Info', `Laporan scan untuk ${domainName} tidak ditemukan.`, 'ℹ️');
    }
}

window.triggerSingleNetworkScan = async function (domainName) {
    showToast('Scan Jaringan', `Memulai network scan untuk ${domainName}...`, '');
    try {
        const resp = await fetch(`${API_BASE}/api/network-scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targets: [domainName] })
        });

        if (resp.status === 200 || resp.status === 201 || resp.status === 202) {
            showToast('Scan Diantrekan', `Scan untuk ${domainName} sedang berjalan di server.`, '');
            // Minta tabel diperbarui sesaat lagi
            setTimeout(() => refreshData(true), 2000);
        } else {
            const data = await resp.json();
            showToast('Gagal', data.detail || 'Gagal memulai scan jaringan.', '');
        }
    } catch (err) {
        showToast('Error Koneksi', 'Tidak dapat terhubung ke server.', '');
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
        row.style.backgroundColor = 'var(--color-surface)';
        row.style.borderRadius = '6px';
        row.style.border = '1px solid var(--color-border)';
        row.style.cursor = 'pointer';
        row.style.transition = 'background 0.2s, border-color 0.2s';

        row.onmouseover = () => {
            row.style.backgroundColor = 'var(--bg-surface-hover)';
            row.style.borderColor = 'var(--primary)';
        };
        row.onmouseout = () => {
            row.style.backgroundColor = 'var(--color-surface)';
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
            row.style.backgroundColor = 'var(--color-surface)';
            row.style.borderRadius = '6px';
            row.style.border = '1px solid var(--color-border)';
            row.style.cursor = 'pointer';
            row.style.transition = 'background 0.2s, border-color 0.2s';

            row.onmouseover = () => {
                row.style.backgroundColor = 'var(--bg-surface-hover)';
                row.style.borderColor = 'var(--primary)';
            };
            row.onmouseout = () => {
                row.style.backgroundColor = 'var(--color-surface)';
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
function jumpToScanDetail(isoDateString, targetName, isSeverity = false, scanId = null) {
    if (!isoDateString && !scanId) {
        showToast("Info", "Data riwayat scan belum termuat.", "ℹ️");
        return;
    }

    // Cari berdasarkan scanId persis jika ada
    if (scanId && typeof allVulns !== 'undefined' && allVulns) {
        const foundById = allVulns.find(s => String(s.id) === String(scanId));
        if (foundById) {
            openScanModal(foundById);
            return;
        }
    }

    // Jika scanId tidak ada / belum di allVulns, fetch spesifik scan oleh API
    if (scanId) {
        fetch(`${API_BASE}/api/scan-history/${scanId}`)
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success' && data.data) {
                    openScanModal(data.data);
                } else {
                    jumpToScanDetailByDate(isoDateString, targetName, isSeverity);
                }
            })
            .catch(() => {
                jumpToScanDetailByDate(isoDateString, targetName, isSeverity);
            });
        return;
    }

    jumpToScanDetailByDate(isoDateString, targetName, isSeverity);
}

function jumpToScanDetailByDate(isoDateString, targetName, isSeverity = false) {
    if ((!isoDateString && !targetName) || typeof allVulns === 'undefined' || !allVulns) {
        showToast("Info", "Data riwayat scan belum termuat.", "ℹ️");
        return;
    }

    const targetTime = isoDateString ? new Date(isoDateString).getTime() : 0;
    let closestScan = null;
    let minDiff = Infinity;

    allVulns.forEach(scan => {
        if (!scan.scan_date) return;

        // Pastikan scan sesuai dengan kriteria yang diklik
        if (isSeverity) {
            let hasSeverity = false;
            if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
                hasSeverity = scan.vulnerabilities.some(v => (v.severity || '').toUpperCase() === (targetName || '').toUpperCase());
            }
            if (!hasSeverity) return;
        } else if (targetName && targetName !== 'Others' && targetName !== 'Semua Domain') {
            const rawDomain = scan.domains?.domain_name || scan.domain_name || scan.target || '';
            const cleanDomain = String(rawDomain).toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '').trim();
            const cleanTarget = String(targetName).toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '').trim();
            if (cleanDomain !== cleanTarget) return;
        }

        const scanTime = new Date(scan.scan_date).getTime();
        const diff = targetTime ? Math.abs(scanTime - targetTime) : 0;
        if (diff < minDiff) {
            minDiff = diff;
            closestScan = scan;
        }
    });

    if (!closestScan && targetName && typeof openScanModalByDomainName === 'function') {
        if (openScanModalByDomainName(targetName)) {
            return;
        }
    }

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

    if (overlay) {
        // Overlay punya class "hidden" (display:none !important) di HTML; hapus agar modal bisa tampil
        overlay.classList.remove('hidden');
        overlay.classList.add('active');
    }
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
            modalBody.innerHTML = '<div class="tc-modal"><div class="tc-modal-top"><div class="tc-dd" id="enlargedChartDropdown"></div></div><div class="tc-modal-canvas"><canvas id="enlargedChartCanvas"></canvas></div><div class="tc-legend tc-legend-below" id="enlargedChartLegend"></div></div>';
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
    trendState.enlarged = trendRender('vuln', ctx.canvas, document.getElementById('enlargedChartLegend'), { enlarged: true, ddEl: document.getElementById('enlargedChartDropdown') });
    enlargedChartInstance = trendState.enlarged ? trendState.enlarged.chart : null;
};

window.renderEnlargedSevChart = function (ctx) {
    trendState.enlarged = trendRender('sev', ctx.canvas, document.getElementById('enlargedChartLegend'), { enlarged: true });
    enlargedChartInstance = trendState.enlarged ? trendState.enlarged.chart : null;
};

window.closeChartModal = function () {
    closeTrendPanel();
    const wasTrend = !!trendState.enlarged;
    trendState.enlarged = null;
    // Pilihan legenda di modal ikut diterapkan ke grafik utama
    if (wasTrend) {
        if (window.renderVulnTrendChart) window.renderVulnTrendChart();
        if (window.renderSevTrendChart) window.renderSevTrendChart();
    }
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
        document.querySelectorAll('.nav-dropdown.expanded').forEach(d => d.classList.remove('expanded'));
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

// Notifikasi persisten: scan selesai
function showScanFinishedToast(notif) {
    if (!currentUser) return; 

    const notifId = String(notif.id || '');
    const domainName = String(notif.domain || '');

    // Cek apakah notifikasi ini sudah pernah ditekan "Cek Detail"
    const readNotifs = notifReadIds();
    if (notifId && readNotifs.includes(notifId)) return;

    // Cek apakah notifikasi sudah tampil di layar (berdasarkan ID atau Domain) untuk mencegah duplikasi
    const existingById = notifId ? document.getElementById(`scan-toast-${notifId}`) : null;
    const existingByDomain = domainName ? document.querySelector(`.toast-notification[data-domain="${domainName}"]`) : null;
    if (existingById || existingByDomain) return;

    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.id = `scan-toast-${notifId || Date.now()}`;
    if (domainName) toast.setAttribute('data-domain', domainName);
    if (notifId) toast.setAttribute('data-notif-id', notifId);
    toast.className = 'toast-notification overnight-toast';

    toast.innerHTML = `
        <div class="toast-icon">️</div>
        <div class="toast-body" style="width: 100%;">
            <div class="toast-title">${escapeHtml(notif.title || 'Scan Selesai')}</div>
            <div class="toast-message">Hasil scan baru untuk <strong>${escapeHtml(notif.domain || 'Domain')}</strong>${notif.risk_level ? `, Risk Level <strong>${escapeHtml(notif.risk_level)}</strong>` : ''}.</div>
            <div class="toast-actions-row">
                <button class="toast-btn toast-btn-primary" id="btnCekDetailScan-${notif.id}">Cek Detail</button>
                <button class="toast-btn toast-btn-secondary" id="btnCloseScanNotif-${notif.id}">Tutup </button>
            </div>
        </div>
    `;

    container.appendChild(toast);

    // --- AKSI: TOMBOL CEK DETAIL ---
    const btnCekDetail = document.getElementById(`btnCekDetailScan-${notifId || notif.id}`);
    if (btnCekDetail) {
        btnCekDetail.onclick = (e) => {
            e.stopPropagation();
            toast.remove();
            
            // Catat ke Local Storage agar tidak muncul lagi selamanya
            const currentRead = notifReadIds();
            const idToSave = notifId || String(notif.id || '');
            if (idToSave && !currentRead.includes(idToSave)) {
                currentRead.push(idToSave);
                notifSaveRead(currentRead);
            }

            // Perbarui angka bel notifikasi di sudut kanan atas
            if (typeof fetchNotifications === 'function') fetchNotifications();

            // Buka Modal Laporan Scan Langsung (Bukan ke Domain Inventory Search)
            if (domainName && openScanModalByDomainName(domainName)) {
                return;
            }
            if (notifId && typeof openScanModalByScanId === 'function') {
                openScanModalByScanId(notifId);
                return;
            }

            // Fallback: Arahkan ke Scan History jika scan belum dimuat di memory
            if (typeof switchView === 'function') {
                switchView('scan-history');
            }
        };
    }

    // --- AKSI: TOMBOL TUTUP ---
    const btnClose = document.getElementById(`btnCloseScanNotif-${notif.id}`);
    if (btnClose) {
        btnClose.onclick = (e) => {
            e.stopPropagation();
            toast.remove();
            // Catatan: Disengaja TIDAK menyimpan status baca ke local storage
            // agar saat halaman di-refresh, notifikasi ini akan muncul kembali!
        };
    }
}

// Notifikasi persisten: domain baru dari OSINT
let activeOsintToastTimers = {};

function showDomainFoundToast(notif) {
    if (!currentUser) return; 

    const readNotifs = notifReadIds();
    if (readNotifs.includes(notif.id)) return;

    const existingToast = document.getElementById(`domain-toast-${notif.id}`);
    if (existingToast) return;

    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.id = `domain-toast-${notif.id}`;
    toast.className = 'toast-notification overnight-toast';

    toast.innerHTML = `
        <div class="toast-icon"></div>
        <div class="toast-body" style="width: 100%;">
            <div class="toast-title">${escapeHtml(notif.title)}</div>
            <div class="toast-message">${escapeHtml(notif.message)}</div>
            <div class="toast-actions-row">
                <button class="toast-btn toast-btn-primary" id="btnCekDomain-${notif.id}">Cek Detail</button>
                <button class="toast-btn toast-btn-secondary" id="btnCloseDomain-${notif.id}">Tutup </button>
            </div>
        </div>
    `;

    container.appendChild(toast);

    const autoDismissTimer = setTimeout(() => {
        if (toast.parentNode) {
            toast.remove();
        }
        scheduleOsintRetry(notif);
    }, 60000);

    const btnCekDetail = document.getElementById(`btnCekDomain-${notif.id}`);
    if (btnCekDetail) {
        btnCekDetail.onclick = (e) => {
            e.stopPropagation();
            clearTimeout(autoDismissTimer);

            if (activeOsintToastTimers[String(notif.id)]) {
                clearTimeout(activeOsintToastTimers[String(notif.id)]);
                delete activeOsintToastTimers[String(notif.id)];
            }
            
            toast.remove();

            const currentRead = notifReadIds();
            if (!currentRead.includes(notif.id)) {
                currentRead.push(notif.id);
                notifSaveRead(currentRead);
            }

            if (typeof fetchNotifications === 'function') fetchNotifications();

            if (typeof switchView === 'function') {
                switchView('inventory');
            }

            if (notif.new_domains && notif.new_domains.length > 0) {
                const searchInput = document.getElementById('domainSearchInput');
                if (searchInput) {
                    searchInput.value = notif.new_domains.map(d => `"${d}"`).join(" ");
                    domainCurrentPage = 1;
                    if (typeof loadDomains === 'function') {
                        loadDomains();
                    }
                }
            }
        };
    }

    const btnClose = document.getElementById(`btnCloseDomain-${notif.id}`);
    if (btnClose) {
        btnClose.onclick = (e) => {
            e.stopPropagation();
            clearTimeout(autoDismissTimer);
            toast.remove();
            
            scheduleOsintRetry(notif);
        };
    }
}

// === FUNGSI PENJADWALAN ULANG OSINT ===
function scheduleOsintRetry(notif) {
    const notifIdStr = String(notif.id);
    
    if (activeOsintToastTimers[notifIdStr]) {
        clearTimeout(activeOsintToastTimers[notifIdStr]);
    }

    // Jadwalkan pengulangan notifikasi setelah 5 menit (300.000 ms)
    activeOsintToastTimers[notifIdStr] = setTimeout(() => {
        delete activeOsintToastTimers[notifIdStr];
        const readNotifs = notifReadIds();
        
        // Cek lagi, pastikan user belum membacanya dari menu lonceng
        if (!readNotifs.includes(notifIdStr)) {
            showDomainFoundToast(notif);
        }
    }, 300000);
}

// Dark/light mode & warna Chart.js

// Daftarkan Plugin Global Chart.js 
// (Gunakan beforeUpdate agar warna ditimpa SEBELUM teks dan skala dihitung)
Chart.register({
    id: 'themeAutoUpdater',
    beforeUpdate: (chart) => {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

        const textColor = isDark ? '#94a3b8' : '#64748b';    

        // WARNA GRID: #cbd5e1 (jelas & elegan di Light Mode), rgba transparan di Dark Mode
        const gridColor = isDark ? 'rgba(255, 255, 255, 0.06)' : '#cbd5e1'; 

        const tooltipBg = isDark ? '#1e293b' : '#ffffff';    
        const tooltipTitle = isDark ? '#f8fafc' : '#1f2937'; 
        const tooltipBody = isDark ? '#e2e8f0' : '#374151';  
        const tooltipBorder = isDark ? '#334155' : '#e5e7eb';

        if (chart.options.scales.x) {
            if (!chart.options.scales.x.ticks) chart.options.scales.x.ticks = {};
            chart.options.scales.x.ticks.color = textColor;
            if (chart.options.scales.x.grid) chart.options.scales.x.grid.color = isDark ? 'rgba(255, 255, 255, 0.04)' : '#f1f5f9';
        }
        if (chart.options.scales.y) {
            if (!chart.options.scales.y.ticks) chart.options.scales.y.ticks = {};
            chart.options.scales.y.ticks.color = textColor;
            if (chart.options.scales.y.grid) {
                chart.options.scales.y.grid.color = gridColor;
                chart.options.scales.y.grid.borderDash = [5, 5];
            }
        }
        if (chart.options.plugins.legend) {
            if (!chart.options.plugins.legend.labels) chart.options.plugins.legend.labels = {};
            chart.options.plugins.legend.labels.color = textColor;
        }
        if (chart.options.plugins.tooltip) {
            chart.options.plugins.tooltip.backgroundColor = tooltipBg;
            chart.options.plugins.tooltip.titleColor = tooltipTitle;
            chart.options.plugins.tooltip.bodyColor = tooltipBody;
            chart.options.plugins.tooltip.borderColor = tooltipBorder;
        }
    }
});

function initTheme() {
    const savedTheme = localStorage.getItem('dsti_theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
    
    // Terapkan default text color global ke Chart.js
    const isDark = savedTheme === 'dark';
    Chart.defaults.color = isDark ? '#94a3b8' : '#64748b';
}

function toggleTheme() {
    const htmlEl = document.documentElement;
    const currentTheme = htmlEl.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    htmlEl.setAttribute('data-theme', newTheme);
    localStorage.setItem('dsti_theme', newTheme);
    updateThemeIcon(newTheme);
    
    // Tentukan warna grid yang kontras dan pas untuk masing-masing mode
    const activeGridColor = newTheme === 'dark' ? 'rgba(255, 255, 255, 0.08)' : '#cbd5e1';
    const activeXGridColor = newTheme === 'dark' ? 'rgba(255, 255, 255, 0.04)' : '#f1f5f9';
    
    // Secara otomatis mendeteksi dan memperbarui SEMUA grafik yang ada di halaman
    const allCharts = Chart.instances;
    if (allCharts) {
        // Chart.instances bisa berupa objek atau array tergantung versi Chart.js
        const chartList = Array.isArray(allCharts) ? allCharts : Object.values(allCharts);
        
        chartList.forEach(chart => {
            if (chart && chart.options && chart.options.scales) {
                // Perbarui sumbu Y (garis horizontal)
                if (chart.options.scales.y && chart.options.scales.y.grid) {
                    chart.options.scales.y.grid.color = activeGridColor;
                    chart.options.scales.y.grid.borderDash = [5, 5];
                }
                // Perbarui sumbu X
                if (chart.options.scales.x && chart.options.scales.x.grid) {
                    chart.options.scales.x.grid.color = activeXGridColor;
                }
                chart.update();
            }
        });
    }
}

function updateThemeIcon(theme) {
    // Tangkap kedua tombol (di dashboard dan di halaman login)
    const dashboardIcon = document.getElementById('themeIcon');
    const loginIcon = document.getElementById('loginThemeIcon');
    
    let svgContent = '';
    
    if (theme === 'dark') {
        // Ikon Matahari (Sun)
        svgContent = '<circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>';
    } else {
        // Ikon Bulan (Moon)
        svgContent = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';
    }

    // Terapkan SVG ke tombol mana pun yang tersedia di layar
    if (dashboardIcon) dashboardIcon.innerHTML = svgContent;
    if (loginIcon) loginIcon.innerHTML = svgContent;
}

// Jalankan saat file dimuat
initTheme();

// Persetujuan penambahan domain (superadmin)
window.openPendingDomainsModal = async function() {
    const modal = document.getElementById('pendingDomainsModalOverlay');
    const container = document.getElementById('pendingDomainsContainer');
    if (!modal || !container) return;

    container.innerHTML = `
        <div style="text-align:center; padding:24px; color:var(--text-secondary); font-size:13px;">
            Memuat daftar permintaan domain...
        </div>
    `;
    modal.classList.add('active');

    try {
        const resp = await fetch(`${API_BASE}/api/domains/pending-requests`);
        const res = await resp.json();
        const pendingList = res.data || [];

        if (pendingList.length === 0) {
            container.innerHTML = `
                <div style="text-align:center; padding:32px; color:var(--text-secondary); font-size:13px;">
                    Tidak ada permintaan domain yang menunggu persetujuan saat ini.
                </div>
            `;
        } else {
            container.innerHTML = `
                <table class="modern-table" style="width:100%; font-size:13px;">
                    <thead>
                        <tr style="background:var(--color-surface-hover);">
                            <th style="padding:10px 12px; text-align:left;">Domain</th>
                            <th style="padding:10px 12px; text-align:left;">Diajukan Oleh</th>
                            <th style="padding:10px 12px; text-align:center;">Aksi</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${pendingList.map(req => `
                            <tr style="border-bottom:1px solid var(--color-border);">
                                <td style="font-weight:600; padding:10px 12px; color:var(--text-primary);">${escapeHtml(req.domain_name)}</td>
                                <td style="padding:10px 12px; color:var(--text-secondary);">${escapeHtml(req.requested_by || 'Admin')}</td>
                                <td style="padding:10px 12px; text-align:center;">
                                    <div style="display:flex; justify-content:center; gap:6px;">
                                        <button class="btn-approve-domain" onclick="triggerApproveDomain(${req.id}, '${escapeHtml(req.domain_name)}')">Setujui</button>
                                        <button class="btn-reject-domain" onclick="triggerRejectDomain(${req.id}, '${escapeHtml(req.domain_name)}')">Tolak</button>
                                    </div>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }
    } catch (err) {
        container.innerHTML = `<div style="text-align:center; padding:20px; color:#ef4444;">Gagal mengambil data permintaan domain.</div>`;
    }
};

window.closePendingDomainsModal = function() {
    const modal = document.getElementById('pendingDomainsModalOverlay');
    if (modal) modal.classList.remove('active');
};

window.triggerApproveDomain = async function(domainId, domainName) {
    const confirmed = await customConfirm({
        title: 'Setujui Permintaan Domain',
        message: `Apakah Anda yakin ingin menyetujui domain '${domainName}'? Domain akan langsung ditambahkan ke inventory aktif.`,
        confirmText: 'Ya, Setujui',
        cancelText: 'Batal',
        variant: 'info'
    });
    if (!confirmed) return;

    try {
        const resp = await fetch(`${API_BASE}/api/domains/${domainId}/approve`, { method: 'POST' });
        const data = await resp.json();
        if (resp.status === 200) {
            showToast(`Domain '${domainName}' telah disetujui dan aktif.`, "success");
            closePendingDomainsModal();
            loadDomains();
            if (typeof fetchNotifications === 'function') fetchNotifications();
        } else {
            showToast(data.detail || "Gagal menyetujui domain.", "error");
        }
    } catch (err) {
        showToast("Gagal menghubungi server.", "error");
    }
};

window.triggerRejectDomain = async function(domainId, domainName) {
    const confirmed = await customConfirm({
        title: 'Tolak Permintaan Domain',
        message: `Apakah Anda yakin ingin menolak dan menghapus permintaan domain '${domainName}'?`,
        confirmText: 'Ya, Tolak Permintaan',
        cancelText: 'Batal',
        variant: 'danger'
    });
    if (!confirmed) return;

    try {
        const resp = await fetch(`${API_BASE}/api/domains/${domainId}/reject`, { method: 'POST' });
        const data = await resp.json();
        if (resp.status === 200) {
            showToast(`Permintaan domain '${domainName}' telah ditolak.`, "info");
            closePendingDomainsModal();
            loadDomains();
            if (typeof fetchNotifications === 'function') fetchNotifications();
        } else {
            showToast(data.detail || "Gagal menolak domain.", "error");
        }
    } catch (err) {
        showToast("Gagal menghubungi server.", "error");
    }
};

async function submitScanRequest() {
    // Tarik data dari elemen UI Anda
    const selectedDomains = getSelectedDomainsList(); // Fungsi untuk mengambil array ["domain1.com", "domain2.com"]
    const scanType = document.querySelector('input[name="scanType"]:checked').value; // 'deep' atau 'light'
    const executionTime = document.querySelector('input[name="executionTime"]:checked').value; // 'now' atau 'schedule'
    
    let endpoint = "";
    let payload = {
        targets: selectedDomains,
        scan_type: scanType,
        scan_category: "web" // atau "network", sesuaikan dengan UI
    };

    // Routing logika berdasarkan pilihan pengguna
    if (executionTime === "now") {
        // TIPE 1: EKSEKUSI LANGSUNG
        endpoint = "/api/scans/launch-now";
        
    } else if (executionTime === "schedule") {
        const scheduleMode = document.querySelector('.active-tab').dataset.mode; // 'once' atau 'recurring'
        const scheduledDateTime = getSelectedDateTimeISO(); // Ambil dari input kalender, format: "2026-08-28T17:15:00Z"
        
        if (scheduleMode === "once") {
            // TIPE 2: 1 KALI EKSEKUSI
            endpoint = "/api/scans/schedule-eta";
            payload.scheduled_time = scheduledDateTime;
        } else {
            // TIPE 3: PEMINDAIAN BERULANG (DURASI)
            endpoint = "/api/scans/schedule-recurring";
            payload.start_time = scheduledDateTime;
            payload.duration_hours = parseInt(document.getElementById('durationInput').value); // Ambil angka "3" jam
        }
    }

    // Kirim Payload ke FastAPI
    try {
        const response = await fetch(endpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            alert("Berhasil: " + result.message);
            closeModal(); // Tutup popup UI
        } else {
            alert("Gagal: " + result.detail);
        }
    } catch (error) {
        console.error("Terjadi kesalahan jaringan:", error);
    }
}