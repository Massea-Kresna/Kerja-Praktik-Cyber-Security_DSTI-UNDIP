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
    const vulnTrendResetIconBtn = document.getElementById('vulnTrendResetIconBtn'); // Tambahan
    
    const resetVulnTrend = async () => {
        if (vulnTrendStart) vulnTrendStart.value = '';
        if (vulnTrendEnd) vulnTrendEnd.value = '';
        const lbl = document.getElementById('vulnTrendDateLabel');
        if (lbl) lbl.textContent = '24 Jam';
        await loadVulnTrendData();
    };

    if (vulnTrendResetBtn) vulnTrendResetBtn.addEventListener('click', resetVulnTrend);
    if (vulnTrendResetIconBtn) vulnTrendResetIconBtn.addEventListener('click', resetVulnTrend); // Tambahan

    // Sev Trend Date Range Logic
    const sevTrendStart = document.getElementById('sevTrendStartDate');
    const sevTrendEnd = document.getElementById('sevTrendEndDate');
    const sevTrendResetBtn = document.getElementById('sevTrendResetBtn');
    const sevTrendResetIconBtn = document.getElementById('sevTrendResetIconBtn'); // Tambahan

    const resetSevTrend = async () => {
        if (sevTrendStart) sevTrendStart.value = '';
        if (sevTrendEnd) sevTrendEnd.value = '';
        const lbl = document.getElementById('sevTrendDateLabel');
        if (lbl) lbl.textContent = '24 Jam';
        await loadSevTrendData();
    };

    if (sevTrendResetBtn) sevTrendResetBtn.addEventListener('click', resetSevTrend);
    if (sevTrendResetIconBtn) sevTrendResetIconBtn.addEventListener('click', resetSevTrend); // Tambahan

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

// --- Toast Notification System & Custom Confirm Dialog ---

function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast-item toast-${type}`;

    const icons = {
        success: '✓',
        error: '⚠️',
        warning: '⚡',
        info: 'ℹ️'
    };

    const iconStr = icons[type] || 'ℹ️';

    toast.innerHTML = `
        <div class="toast-icon">${iconStr}</div>
        <div class="toast-content">
            <div class="toast-message">${message}</div>
        </div>
        <button type="button" class="toast-close-btn" aria-label="Tutup">&times;</button>
        <div class="toast-progress"></div>
    `;

    container.appendChild(toast);

    const progressBar = toast.querySelector('.toast-progress');
    const closeBtn = toast.querySelector('.toast-close-btn');

    let startTime = Date.now();
    let remainingTime = duration;
    let timer = null;
    let animFrame = null;

    const startDismissTimer = () => {
        startTime = Date.now();
        timer = setTimeout(() => {
            dismiss();
        }, remainingTime);

        const updateProgress = () => {
            const elapsed = Date.now() - startTime;
            const percentage = Math.max(0, 1 - (elapsed / remainingTime));
            if (progressBar) {
                progressBar.style.transform = `scaleX(${percentage})`;
            }
            if (percentage > 0) {
                animFrame = requestAnimationFrame(updateProgress);
            }
        };
        animFrame = requestAnimationFrame(updateProgress);
    };

    const pauseDismissTimer = () => {
        clearTimeout(timer);
        cancelAnimationFrame(animFrame);
        remainingTime -= (Date.now() - startTime);
    };

    const dismiss = () => {
        clearTimeout(timer);
        cancelAnimationFrame(animFrame);
        toast.classList.add('toast-leaving');
        toast.addEventListener('animationend', () => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        });
    };

    toast.addEventListener('mouseenter', pauseDismissTimer);
    toast.addEventListener('mouseleave', () => {
        if (remainingTime > 0) startDismissTimer();
    });

    if (closeBtn) {
        closeBtn.addEventListener('click', dismiss);
    }

    startDismissTimer();
}

function customConfirm({
    title = 'Konfirmasi Aksi',
    message = 'Apakah Anda yakin ingin melanjutkan tindakan ini?',
    confirmText = 'Ya, Lanjutkan',
    cancelText = 'Batal',
    variant = 'danger'
} = {}) {
    return new Promise((resolve) => {
        const modal = document.getElementById('customConfirmModal');
        const titleEl = document.getElementById('customModalTitle');
        const msgEl = document.getElementById('customModalMessage');
        const iconBadge = document.getElementById('customModalIconBadge');
        const iconEl = document.getElementById('customModalIcon');
        const confirmBtn = document.getElementById('customModalConfirmBtn');
        const cancelBtn = document.getElementById('customModalCancelBtn');

        if (!modal || !confirmBtn || !cancelBtn) {
            resolve(window.confirm(message));
            return;
        }

        if (titleEl) titleEl.textContent = title;
        if (msgEl) msgEl.textContent = message;
        if (confirmBtn) confirmBtn.textContent = confirmText;
        if (cancelBtn) cancelBtn.textContent = cancelText;

        const iconMap = {
            danger: '🗑️',
            warning: '⚠️',
            info: 'ℹ️',
            success: '✓'
        };

        if (iconBadge) iconBadge.className = `custom-modal-icon-badge ${variant}`;
        if (iconEl) iconEl.textContent = iconMap[variant] || 'ℹ️';

        if (confirmBtn) {
            confirmBtn.className = `btn custom-modal-btn ${variant === 'danger' ? 'btn-danger-solid' : 'btn-primary-solid'}`;
        }

        modal.classList.add('open');

        const cleanup = (result) => {
            modal.classList.remove('open');
            confirmBtn.removeEventListener('click', onConfirm);
            cancelBtn.removeEventListener('click', onCancel);
            document.removeEventListener('keydown', onKeyDown);
            resolve(result);
        };

        const onConfirm = () => cleanup(true);
        const onCancel = () => cleanup(false);
        const onKeyDown = (e) => {
            if (e.key === 'Escape') onCancel();
            if (e.key === 'Enter') onConfirm();
        };

        confirmBtn.addEventListener('click', onConfirm);
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
    const end = new Date();
    const start = new Date();
    start.setDate(end.getDate() - days + 1);

    const startStr = start.toISOString().split('T')[0];
    const endStr = end.toISOString().split('T')[0];

    const state = getCalendarState(chartPrefix);
    state.start = startStr;
    state.end = endStr;
    state.hover = null;
    state.month = start.getMonth();
    state.year = start.getFullYear();

    const startEl = document.getElementById(`${chartPrefix}StartDate`);
    const endEl = document.getElementById(`${chartPrefix}EndDate`);
    if (startEl) startEl.value = startStr;
    if (endEl) endEl.value = endStr;

    let labelText = `${days} Hari`;
    if (days === 1) labelText = '24 Jam';

    const labelEl = document.getElementById(`${chartPrefix}DateLabel`);
    if (labelEl) labelEl.textContent = labelText;

    renderInteractiveCalendar(chartPrefix);

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
                            const scanId = rawTrendData.scan_ids ? rawTrendData.scan_ids[index] : null;
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
                                jumpToScanDetail(rawTrendData.raw_labels[index], lastActiveLabel, false, scanId);
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
                        grid: { 
                            borderDash: [5, 5] // Memastikan garis putus-putus tetap aktif
                        },
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
                            color: () => document.documentElement.getAttribute('data-theme') === 'dark' ? '#94a3b8' : '#64748b',
                            generateLabels: (chart) => {
                                const legendTextColor = document.documentElement.getAttribute('data-theme') === 'dark' ? '#94a3b8' : '#64748b';
                                return chart.data.datasets.map((dataset, i) => ({
                                    text: dataset.label,
                                    fillStyle: dataset.borderColor,
                                    fontColor: legendTextColor,
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
                            const scanId = rawSevTrendData.scan_ids ? rawSevTrendData.scan_ids[index] : null;
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
                                    jumpToScanDetail(rawSevTrendData.raw_labels[index], item.domain, false, scanId);
                                } else {
                                    jumpToScanDetail(rawSevTrendData.raw_labels[index], item.severity, true, scanId);
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
                        grid: { 
                            borderDash: [5, 5] // Memastikan garis putus-putus tetap aktif
                        },
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
                            color: () => document.documentElement.getAttribute('data-theme') === 'dark' ? '#94a3b8' : '#64748b',
                            generateLabels: (chart) => {
                                const legendTextColor = document.documentElement.getAttribute('data-theme') === 'dark' ? '#94a3b8' : '#64748b';
                                return chart.data.datasets.map((dataset, i) => ({
                                    text: dataset.label,
                                    fillStyle: dataset.borderColor,
                                    fontColor: legendTextColor,
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

    renderSeverityChips();

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

let calendarCurrentYear = new Date().getFullYear();
let calendarCurrentMonth = new Date().getMonth();
const calendarStates = {
    scanHistory: { year: new Date().getFullYear(), month: new Date().getMonth(), start: null, end: null, hover: null, activeFocus: 'end' },
    vulnTrend: { year: new Date().getFullYear(), month: new Date().getMonth(), start: null, end: null, hover: null, activeFocus: 'end' },
    sevTrend: { year: new Date().getFullYear(), month: new Date().getMonth(), start: null, end: null, hover: null, activeFocus: 'end' }
};

function getCalendarState(prefix = 'scanHistory') {
    if (!calendarStates[prefix]) {
        calendarStates[prefix] = { year: new Date().getFullYear(), month: new Date().getMonth(), start: null, end: null, hover: null, activeFocus: 'end' };
    }
    return calendarStates[prefix];
}

function getCalendarElementIds(prefix = 'scanHistory') {
    if (prefix === 'scanHistory') {
        return {
            grid: 'calendarDaysGrid',
            status: 'calendarSelectionStatus',
            monthSelect: 'calendarMonthSelect',
            yearSelect: 'calendarYearSelect',
            startManual: 'manualStartDateInput',
            endManual: 'manualEndDateInput',
            startInput: 'vulnStartDate',
            endInput: 'vulnEndDate',
            label: 'scanHistoryDateLabel',
            dropdown: 'scanHistoryDateDropdown'
        };
    }
    return {
        grid: `${prefix}CalendarDaysGrid`,
        status: `${prefix}CalendarSelectionStatus`,
        monthSelect: `${prefix}CalendarMonthSelect`,
        yearSelect: `${prefix}CalendarYearSelect`,
        startManual: `${prefix}ManualStartDateInput`,
        endManual: `${prefix}ManualEndDateInput`,
        startInput: `${prefix}StartDate`,
        endInput: `${prefix}EndDate`,
        label: `${prefix}DateLabel`,
        dropdown: `${prefix}DateDropdown`
    };
}

function initCalendarHeaderDropdowns(prefix = 'scanHistory') {
    const ids = getCalendarElementIds(prefix);
    const yearSelect = document.getElementById(ids.yearSelect);
    if (yearSelect && yearSelect.options.length === 0) {
        const currentYear = new Date().getFullYear();
        let options = '';
        for (let y = currentYear - 5; y <= currentYear + 5; y++) {
            options += `<option value="${y}">${y}</option>`;
        }
        yearSelect.innerHTML = options;
    }
}

function onCalendarHeaderDropdownChange(event, prefix = 'scanHistory') {
    if (event) event.stopPropagation();
    const ids = getCalendarElementIds(prefix);
    const state = getCalendarState(prefix);
    const monthSelect = document.getElementById(ids.monthSelect);
    const yearSelect = document.getElementById(ids.yearSelect);

    if (monthSelect) state.month = parseInt(monthSelect.value, 10);
    if (yearSelect) state.year = parseInt(yearSelect.value, 10);

    renderInteractiveCalendar(prefix);
}

function formatDateToDDMMYYYY(dateStr) {
    if (!dateStr) return '';
    const parts = dateStr.split('-');
    if (parts.length === 3) {
        return `${parts[2]}/${parts[1]}/${parts[0]}`;
    }
    return dateStr;
}

function parseDDMMYYYYToDateStr(formattedStr) {
    if (!formattedStr) return null;
    const parts = formattedStr.trim().split('/');
    if (parts.length === 3) {
        const d = parts[0].padStart(2, '0');
        const m = parts[1].padStart(2, '0');
        const y = parts[2];
        if (y.length === 4 && parseInt(m, 10) >= 1 && parseInt(m, 10) <= 12 && parseInt(d, 10) >= 1 && parseInt(d, 10) <= 31) {
            return `${y}-${m}-${d}`;
        }
    }
    return null;
}

function onManualInputFocus(focusTarget, prefix = 'scanHistory') {
    const state = getCalendarState(prefix);
    state.activeFocus = focusTarget; // 'start' or 'end'
    highlightActiveDateInput(prefix);
}

function highlightActiveDateInput(prefix = 'scanHistory') {
    const ids = getCalendarElementIds(prefix);
    const state = getCalendarState(prefix);
    const startManual = document.getElementById(ids.startManual);
    const endManual = document.getElementById(ids.endManual);

    if (startManual) {
        if (state.activeFocus === 'start') {
            startManual.style.borderColor = 'var(--primary)';
            startManual.style.boxShadow = '0 0 0 2px rgba(59, 130, 246, 0.25)';
        } else {
            startManual.style.borderColor = '#cbd5e1';
            startManual.style.boxShadow = 'none';
        }
    }

    if (endManual) {
        if (state.activeFocus === 'end') {
            endManual.style.borderColor = 'var(--primary)';
            endManual.style.boxShadow = '0 0 0 2px rgba(59, 130, 246, 0.25)';
        } else {
            endManual.style.borderColor = '#cbd5e1';
            endManual.style.boxShadow = 'none';
        }
    }
}

function syncManualDateInputs(prefix = 'scanHistory') {
    const ids = getCalendarElementIds(prefix);
    const state = getCalendarState(prefix);
    const startManual = document.getElementById(ids.startManual);
    const endManual = document.getElementById(ids.endManual);

    if (startManual && document.activeElement !== startManual) {
        startManual.value = formatDateToDDMMYYYY(state.start);
    }
    if (endManual && document.activeElement !== endManual) {
        endManual.value = formatDateToDDMMYYYY(state.end);
    }
    highlightActiveDateInput(prefix);
}

function onManualDateInputChange(event, prefix = 'scanHistory') {
    if (event) event.stopPropagation();
    const ids = getCalendarElementIds(prefix);
    const state = getCalendarState(prefix);
    const startVal = document.getElementById(ids.startManual)?.value || '';
    const endVal = document.getElementById(ids.endManual)?.value || '';

    const parsedStart = parseDDMMYYYYToDateStr(startVal);
    const parsedEnd = parseDDMMYYYYToDateStr(endVal);

    if (parsedStart) {
        state.start = parsedStart;
        const parts = parsedStart.split('-');
        state.year = parseInt(parts[0], 10);
        state.month = parseInt(parts[1], 10) - 1;
    } else if (!startVal) {
        state.start = null;
    }

    if (parsedEnd) {
        state.end = parsedEnd;
    } else if (!endVal) {
        state.end = null;
    }

    renderInteractiveCalendar(prefix);
    applyInteractiveRangeCalendar(prefix);
}

function renderInteractiveCalendar(prefix = 'scanHistory') {
    initCalendarHeaderDropdowns(prefix);
    const ids = getCalendarElementIds(prefix);
    const state = getCalendarState(prefix);

    const grid = document.getElementById(ids.grid);
    const status = document.getElementById(ids.status);
    const monthSelect = document.getElementById(ids.monthSelect);
    const yearSelect = document.getElementById(ids.yearSelect);

    if (monthSelect) monthSelect.value = state.month;
    if (yearSelect) yearSelect.value = state.year;

    if (!grid) return;

    const daysOfWeek = ['Mg', 'Sn', 'Sl', 'Rb', 'Km', 'Jm', 'Sb'];
    let html = daysOfWeek.map(d => `<div style="font-size: 11px; font-weight: 700; color: #94a3b8; padding: 4px 0;">${d}</div>`).join('');

    const firstDayIndex = new Date(state.year, state.month, 1).getDay();
    const totalDaysInMonth = new Date(state.year, state.month + 1, 0).getDate();

    for (let i = 0; i < firstDayIndex; i++) {
        html += `<div></div>`;
    }

    for (let day = 1; day <= totalDaysInMonth; day++) {
        const dateStr = `${state.year}-${String(state.month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
        
        let isStart = state.start === dateStr;
        let isEnd = state.end === dateStr;
        let isInRange = false;
        let isHoverRange = false;

        if (state.start && state.end) {
            isInRange = dateStr > state.start && dateStr < state.end;
        } else if (state.start && !state.end && state.hover) {
            const minD = state.start < state.hover ? state.start : state.hover;
            const maxD = state.start < state.hover ? state.hover : state.start;
            isHoverRange = dateStr > minD && dateStr < maxD;
            if (dateStr === state.hover && dateStr !== state.start) {
                isEnd = true;
            }
        }

        let bg = 'transparent';
        let color = '#334155';
        let borderRadius = '4px';
        let fontWeight = '500';

        if (isStart || isEnd) {
            bg = 'var(--primary)';
            color = '#ffffff';
            fontWeight = '700';
            borderRadius = isStart && isEnd ? '4px' : (isStart ? '4px 0 0 4px' : '0 4px 4px 0');
        } else if (isInRange) {
            bg = '#eff6ff';
            color = '#1e40af';
            borderRadius = '0';
        } else if (isHoverRange) {
            bg = 'rgba(59, 130, 246, 0.15)';
            color = '#1d4ed8';
            borderRadius = '0';
        }

        html += `
            <div onclick="selectCalendarDate('${dateStr}', event, '${prefix}')"
                 onmouseover="hoverCalendarDate('${dateStr}', '${prefix}')"
                 style="padding: 6px 0; font-size: 12px; cursor: pointer; background: ${bg}; color: ${color}; border-radius: ${borderRadius}; font-weight: ${fontWeight}; transition: all 0.1s;">
                ${day}
            </div>
        `;
    }

    const totalFilledCells = firstDayIndex + totalDaysInMonth;
    const totalGridCells = totalFilledCells > 35 ? 42 : 35;
    const trailingEmptyCells = totalGridCells - totalFilledCells;
    for (let t = 0; t < trailingEmptyCells; t++) {
        html += `<div></div>`;
    }

    grid.innerHTML = html;

    if (status) {
        if (state.start && state.end) {
            status.textContent = `${formatDateToDDMMYYYY(state.start)} - ${formatDateToDDMMYYYY(state.end)}`;
        } else if (state.start) {
            status.textContent = `Pilih Tanggal Akhir... (${formatDateToDDMMYYYY(state.start)})`;
        } else {
            status.textContent = prefix === 'scanHistory' ? 'Semua Tanggal' : '24 Jam';
        }
    }

    syncManualDateInputs(prefix);
}

function navigateCalendarMonth(delta, event, prefix = 'scanHistory') {
    if (event) event.stopPropagation();
    const state = getCalendarState(prefix);
    state.month += delta;
    if (state.month < 0) {
        state.month = 11;
        state.year--;
    } else if (state.month > 11) {
        state.month = 0;
        state.year++;
    }
    renderInteractiveCalendar(prefix);
}

function selectCalendarDate(dateStr, event, prefix = 'scanHistory') {
    if (event) event.stopPropagation();
    const state = getCalendarState(prefix);

    // Google Analytics / Stripe Pattern:
    // If no start date OR if a full range (start & end) already exists, start a fresh range!
    if (!state.start || (state.start && state.end)) {
        state.start = dateStr;
        state.end = null;
        state.hover = null;
        renderInteractiveCalendar(prefix);
        return;
    }

    // If start date exists and waiting for end date:
    if (state.start && !state.end) {
        if (dateStr < state.start) {
            state.end = state.start;
            state.start = dateStr;
        } else {
            state.end = dateStr;
        }
        state.hover = null;
        renderInteractiveCalendar(prefix);
        applyInteractiveRangeCalendar(prefix);
    }
}

function hoverCalendarDate(dateStr, prefix = 'scanHistory') {
    const state = getCalendarState(prefix);
    if (state.start && !state.end) {
        if (state.hover !== dateStr) {
            state.hover = dateStr;
            renderInteractiveCalendar(prefix);
        }
    }
}

function leaveCalendarGrid(prefix = 'scanHistory') {
    const state = getCalendarState(prefix);
    if (state.start && !state.end && state.hover) {
        state.hover = null;
        renderInteractiveCalendar(prefix);
    }
}

function applyInteractiveRangeCalendar(prefix = 'scanHistory') {
    const ids = getCalendarElementIds(prefix);
    const state = getCalendarState(prefix);
    const startInput = document.getElementById(ids.startInput);
    const endInput = document.getElementById(ids.endInput);
    const label = document.getElementById(ids.label);

    if (startInput) startInput.value = state.start || '';
    if (endInput) endInput.value = state.end || '';

    if (label) {
        if (state.start && state.end) {
            label.textContent = `${formatDateToDDMMYYYY(state.start)} - ${formatDateToDDMMYYYY(state.end)}`;
        } else if (state.start) {
            label.textContent = `>= ${formatDateToDDMMYYYY(state.start)}`;
        } else {
            label.textContent = prefix === 'scanHistory' ? 'Semua Tanggal' : '24 Jam';
        }
    }

    if (prefix === 'scanHistory') {
        applyVulnFilters();
    } else if (prefix === 'vulnTrend') {
        loadVulnTrendData();
    } else if (prefix === 'sevTrend') {
        loadSevTrendData();
    }
}

function resetInteractiveRangeCalendar(event, prefix = 'scanHistory') {
    if (event) event.stopPropagation();
    const state = getCalendarState(prefix);
    state.start = null;
    state.end = null;
    state.hover = null;
    if (prefix === 'scanHistory') {
        setQuickScanHistoryDate(0, event);
    } else {
        setQuickDate(prefix, 1, `${prefix}DateDropdown`);
    }
}

function setQuickScanHistoryMonthForPrefix(prefix = 'scanHistory') {
    const now = new Date();
    const y = now.getFullYear();
    const m = now.getMonth();
    const firstDay = `${y}-${String(m + 1).padStart(2, '0')}-01`;
    const lastDayNum = new Date(y, m + 1, 0).getDate();
    const lastDay = `${y}-${String(m + 1).padStart(2, '0')}-${String(lastDayNum).padStart(2, '0')}`;

    const state = getCalendarState(prefix);
    state.start = firstDay;
    state.end = lastDay;
    state.hover = null;
    state.month = m;
    state.year = y;

    if (prefix === 'scanHistory') {
        calendarRangeStart = firstDay;
        calendarRangeEnd = lastDay;
        const startInput = document.getElementById('vulnStartDate');
        const endInput = document.getElementById('vulnEndDate');
        const label = document.getElementById('scanHistoryDateLabel');
        if (startInput) startInput.value = firstDay;
        if (endInput) endInput.value = lastDay;
        if (label) label.textContent = 'Bulan Ini';
        renderInteractiveCalendar('scanHistory');
        applyVulnFilters();
    } else {
        renderInteractiveCalendar(prefix);
        applyInteractiveRangeCalendar(prefix);
    }
}

function setQuickScanHistoryMonth() {
    setQuickScanHistoryMonthForPrefix('scanHistory');
}

function setQuickScanHistoryDate(days, event) {
    if (event) event.stopPropagation();
    const startInput = document.getElementById('vulnStartDate');
    const endInput = document.getElementById('vulnEndDate');
    const label = document.getElementById('scanHistoryDateLabel');
    const state = getCalendarState('scanHistory');

    if (days === 0) {
        calendarRangeStart = null;
        calendarRangeEnd = null;
        state.start = null;
        state.end = null;
        state.hover = null;
        if (startInput) startInput.value = '';
        if (endInput) endInput.value = '';
        if (label) label.textContent = 'Semua Tanggal';
    } else {
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(endDate.getDate() - days + 1);

        const endStr = endDate.toISOString().split('T')[0];
        const startStr = startDate.toISOString().split('T')[0];

        calendarRangeStart = startStr;
        calendarRangeEnd = endStr;

        state.start = startStr;
        state.end = endStr;
        state.hover = null;
        state.month = startDate.getMonth();
        state.year = startDate.getFullYear();

        if (startInput) startInput.value = startStr;
        if (endInput) endInput.value = endStr;
        if (label) {
            label.textContent = days === 1 ? '24 Jam Terakhir' : `${days} Hari Terakhir`;
        }
    }

    renderInteractiveCalendar('scanHistory');
    applyVulnFilters();
}

function onCustomScanHistoryDateChange() {
    const startInput = document.getElementById('vulnStartDate')?.value;
    const endInput = document.getElementById('vulnEndDate')?.value;
    const label = document.getElementById('scanHistoryDateLabel');

    if (label) {
        if (startInput && endInput) {
            label.textContent = `${formatDateShort(startInput)} - ${formatDateShort(endInput)}`;
        } else if (startInput) {
            label.textContent = `>= ${formatDateShort(startInput)}`;
        } else if (endInput) {
            label.textContent = `<= ${formatDateShort(endInput)}`;
        } else {
            label.textContent = 'Semua Tanggal';
        }
    }

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

function renderSeverityChips() {
    const container = document.getElementById('vulnSeverityChipsContainer');
    if (!container) return;

    if (!allVulns || allVulns.length === 0) {
        container.innerHTML = '';
        return;
    }

    const counts = { ALL: allVulns.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0 };
    allVulns.forEach(scan => {
        const risk = (scan.risk_level || 'SAFE').toUpperCase();
        if (counts[risk] !== undefined) {
            counts[risk]++;
        } else {
            counts.SAFE++;
        }
    });

    const chips = [
        { id: 'ALL', label: 'All Severities', count: counts.ALL, bg: '#f1f5f9', color: '#475569', border: '#cbd5e1' },
        { id: 'CRITICAL', label: 'Critical', count: counts.CRITICAL, bg: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '#fca5a5' },
        { id: 'HIGH', label: 'High', count: counts.HIGH, bg: 'rgba(249, 115, 22, 0.1)', color: '#f97316', border: '#fdba74' },
        { id: 'MEDIUM', label: 'Medium', count: counts.MEDIUM, bg: 'rgba(234, 179, 8, 0.1)', color: '#eab308', border: '#fde047' },
        { id: 'LOW', label: 'Low', count: counts.LOW, bg: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', border: '#93c5fd' },
        { id: 'SAFE', label: 'Safe', count: counts.SAFE, bg: 'rgba(16, 185, 129, 0.1)', color: '#10b981', border: '#6ee7b7' }
    ];

    container.innerHTML = `
        <span style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-right: 6px;">Filter Level:</span>
        ${chips.map(c => {
            const isActive = selectedSeverityFilter === c.id;
            const activeStyle = isActive 
                ? `background: ${c.color}; color: #ffffff; border-color: ${c.color}; box-shadow: 0 2px 6px rgba(0,0,0,0.15);`
                : `background: ${c.bg}; color: ${c.color}; border-color: ${c.border};`;
            return `
                <button type="button" 
                        onclick="filterBySeverity('${c.id}')"
                        style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 16px; font-size: 11px; font-weight: 600; cursor: pointer; border: 1px solid; transition: all 0.2s; outline: none; ${activeStyle}">
                    <span>${c.label}</span>
                </button>
            `;
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
    const label = document.getElementById('scanHistoryDateLabel');

    if (startInput) startInput.value = '';
    if (endInput) endInput.value = '';
    if (domainSearchInput) domainSearchInput.value = '';
    if (typeFilter) typeFilter.value = 'ALL';
    if (label) label.textContent = 'Semua Tanggal';

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
            scanIdLabel = 'Network Scan';
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
                <tr style="cursor: default; transition: background 0.2s;">
                    <td style="padding: 16px; min-width: 140px;">
                        <div style="display:flex; align-items:center; gap:8px; color: #2563eb; font-weight: 500; font-size: 14px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                            ${scanIdLabel}
                        </div>
                    </td>
                    <td style="padding: 16px;">${statusHtml}</td>
                    <td style="padding: 16px;">
                        <div style="font-weight: 500; font-size: 13px; color: #334155; margin-bottom: 4px;">${escapeHtml(domainName)}</div>
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
            scanIdLabel = 'Network Scan';

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
               <tr onclick="openScanModalIndex(${actualIndex})" style="cursor: pointer; transition: background 0.2s;">
                    <td style="padding: 16px; min-width: 140px;">
                        <div style="display:flex; align-items:center; gap:8px; color: #64748b; font-weight: 500; font-size: 14px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                            ${scanIdLabel}
                        </div>
                    </td>
                    <td style="padding: 16px;">${statusHtml}</td>
                    <td style="padding: 16px;">
                        <div style="font-weight: 500; font-size: 13px; color: #334155; margin-bottom: 4px;">${escapeHtml(domainName)}</div>
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
        let warningTag = '🟢 Standard Web';
        
        if ([3306, 5432, 27017, 6379, 1433].includes(pNum)) {
            riskClass = 'port-badge-red';
            warningTag = '🚨 DB Exposed!';
        } else if ([22, 21, 23, 3389].includes(pNum)) {
            riskClass = 'port-badge-yellow';
            warningTag = '⚠️ Restriksi IP';
        } else if ([8080, 8443, 8000].includes(pNum)) {
            riskClass = 'port-badge-yellow';
            warningTag = '⚠️ Dev Port';
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

// Render Lower Dashboard Grid (Target Risk Ranking & Monitored Domains)
function renderLowerGrid() {
    const alertsBody = document.getElementById('recentAlertsBody');
    const domainsList = document.getElementById('monitoredDomainsList');

    if (!allVulns || allVulns.length === 0) {
        if (alertsBody) alertsBody.innerHTML = `<tr><td colspan="5" class="empty-state">No alerts found.</td></tr>`;
        if (domainsList) domainsList.innerHTML = `<li class="domain-item" style="justify-content: center;"><span class="empty-state">Tidak ada domain terpantau.</span></li>`;
        return;
    }

    // 1. Process Target Risk Ranking
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
            alertsBody.innerHTML = `<tr><td colspan="5" class="empty-state">No high/critical alerts found.</td></tr>`;
        } else {
            alertsBody.innerHTML = topAlerts.map((alert, idx) => {
                const sevClass = getSeverityClass(alert.severity);
                return `
                    <tr onclick="openScanModalByGlobalIndex(${alert.globalIndex})" style="cursor: pointer;">
                        <td style="text-align: center; font-weight: 600; color: var(--color-muted);">${idx + 1}</td>
                        <td class="font-mono" style="font-size: 12px; font-weight: 600; color: var(--color-ink);">${escapeHtml(alert.target)}</td>
                        <td style="font-size: 12px; font-weight: 500;">
                            <span style="font-weight: 700; color: var(--primary);">${alert.vulnCount}</span> Vulns
                        </td>
                        <td><span class="badge badge-${sevClass}" style="font-weight: 700;">${alert.severity}</span></td>
                        <td style="color: var(--color-muted); font-size: 11px;">${formatDate(alert.rawDate)}</td>
                    </tr>
                `;
            }).join('');
        }
    }

    // 2. Process Monitored Domains List
    if (domainsList) {
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
                const currentWeight = DOMAIN_RISK_WEIGHT[domainMap[domainName].risk] || 0;
                const newWeight = DOMAIN_RISK_WEIGHT[riskLevel] || 0;
                if (newWeight > currentWeight) {
                    domainMap[domainName].risk = riskLevel;
                }
                if (scanDate > domainMap[domainName].date) {
                    domainMap[domainName].date = scanDate;
                    domainMap[domainName].ip = scan.domains?.ip_address || '-';
                }
            }
        });

        const topDomains = Object.values(domainMap).sort((a, b) => {
            const wA = DOMAIN_RISK_WEIGHT[a.risk] || 0;
            const wB = DOMAIN_RISK_WEIGHT[b.risk] || 0;
            if (wA !== wB) return wB - wA;
            return b.date - a.date;
        }).slice(0, 5);

        if (topDomains.length === 0) {
            domainsList.innerHTML = `<li class="domain-item" style="justify-content: center;"><span class="empty-state">Tidak ada domain terpantau.</span></li>`;
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

                const safeDomainName = escapeHtml(d.domain);
                return `
                    <li class="domain-item" onclick="filterHistoryFromMonitoredDomain('${safeDomainName}', event)" style="cursor: pointer; transition: background 0.15s;" title="Klik untuk memfilter Scan History">
                        <div class="domain-icon"><svg class="icon"><use href="#icon-globe"/></svg></div>
                        <div class="domain-info">
                            <p class="domain-name" style="font-weight: 600;">${safeDomainName}</p>
                            <p class="domain-desc">${escapeHtml(d.ip)}</p>
                        </div>
                        <div class="domain-status" style="align-items: flex-end; gap: 2px;">
                            <span class="status-label ${statusClass}" style="font-weight: 700; font-size: 10px;">${statusLabel}</span>
                            <span class="domain-score" style="font-size: 11px;">Risk: ${d.risk}</span>
                        </div>
                    </li>
                `;
            }).join('');
        }
    }
}

window.quickScanFromMonitoredDomain = function (domainName, event) {
    if (event) event.stopPropagation();
    window.selectedWebScans = new Set([domainName]);
    if (typeof openWebScanModal === 'function') {
        openWebScanModal();
        showToast(`Menyiapkan pemindaian untuk target: ${domainName}`, 'info');
    }
};

window.filterHistoryFromMonitoredDomain = function (domainName, event) {
    if (event) event.stopPropagation();
    const domainSearchInput = document.getElementById('vulnDomainSearch');
    if (domainSearchInput) {
        domainSearchInput.value = domainName;
        applyVulnFilters();
    }
    const scanHistorySection = document.getElementById('scanHistoryHeaders') || document.getElementById('vulnListContainer');
    if (scanHistorySection) {
        scanHistorySection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    showToast(`Daftar Scan History difilter untuk: ${domainName}`, 'info');
};

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
                const isPending = data.approval_status === 'pending';
                showToast(
                    isPending ? 'Permintaan Terkirim' : 'Sukses', 
                    data.message || 'Domain berhasil disimpan', 
                    isPending ? '⏳' : '✅'
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
        title: 'Hapus Domain',
        message: 'Apakah Anda yakin ingin menghapus domain ini dari sistem?',
        confirmText: 'Ya, Hapus',
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
        ip_address: d.ip_address || '',
        last_scan_type: d.last_scan_type || '',
        last_scan_status: d.last_scan_status || 'Belum Scan',
        last_scan_date: d.last_scan_date || null
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
                'Status Target',
                `Domain ${domain.domain_name} sekarang ${newStatus ? 'ACTIVE' : 'INACTIVE'}.`,
                newStatus ? '✅' : 'ℹ️'
            );
        } else {
            // Revert on error
            domain.is_active = !newStatus;
            renderInventoryList();
            const data = await resp.json();
            showToast('Error', data.detail || 'Gagal mengubah status domain', '❌');
        }
    } catch (err) {
        console.error('Error toggling domain status:', err);
        domain.is_active = !newStatus;
        renderInventoryList();
        showToast('Error', 'Koneksi terputus dari server', '❌');
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

function renderInventoryList() {
    const tbody = document.getElementById('inventoryTableBody');
    const paginationControls = document.getElementById('domainPaginationControls');
    const countText = document.getElementById('selectedDomainCount');

    if (countText) {
        const activeCount = (allDomains || []).filter(d => d.is_active).length;
        countText.textContent = `Total ${(allDomains || []).length} domain (${activeCount} aktif)`;
    }

    if (typeof updateSecurityPostureScore === 'function') {
        updateSecurityPostureScore();
    }

    // Render UI Kosong jika tidak ada data dari backend
    if (!allDomains || allDomains.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No domains found.</td></tr>`;
        if (paginationControls) paginationControls.style.display = 'none';
        return;
    }

    // Filtering logic dengan fitur Exact Match ("")
    const rawSearchVal = document.getElementById('domainSearchInput')?.value || '';
    
    if (rawSearchVal.trim() === '') {
        filteredDomains = [...allDomains]; 
    } else {
        const searchTerms = rawSearchVal.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
        
        filteredDomains = allDomains.filter(d => {
            const dName = (d.domain_name || '').toLowerCase();
            const dIp = (d.ip_address || '').toLowerCase();
            
            return searchTerms.some(term => {
                if (term.startsWith('"') && term.endsWith('"') && term.length >= 2) {
                    const exactTerm = term.slice(1, -1).toLowerCase();
                    return dName === exactTerm || dIp === exactTerm;
                } else {
                    const lowerTerm = term.toLowerCase();
                    return dName.includes(lowerTerm) || dIp.includes(lowerTerm);
                }
            });
        });
    }

    // Filter berdasarkan Target Status (ALL, ACTIVE, INACTIVE)
    const statusFilterVal = document.getElementById('domainStatusFilter')?.value || 'ALL';
    if (statusFilterVal === 'ACTIVE') {
        filteredDomains = filteredDomains.filter(d => d.is_active);
    } else if (statusFilterVal === 'INACTIVE') {
        filteredDomains = filteredDomains.filter(d => !d.is_active);
    }

    // Filter berdasarkan Last Scan Status (ALL, SCANNED, NOT_SCANNED, HIGH, MEDIUM, SAFE)
    const scanFilterVal = document.getElementById('domainLastScanFilter')?.value || 'ALL';
    if (scanFilterVal === 'SCANNED') {
        filteredDomains = filteredDomains.filter(d => d.last_scan_date && d.last_scan_status);
    } else if (scanFilterVal === 'NOT_SCANNED') {
        filteredDomains = filteredDomains.filter(d => !d.last_scan_date || !d.last_scan_status);
    } else if (scanFilterVal === 'HIGH') {
        filteredDomains = filteredDomains.filter(d => d.last_scan_status && ['HIGH', 'CRITICAL'].includes(d.last_scan_status.toUpperCase()));
    } else if (scanFilterVal === 'MEDIUM') {
        filteredDomains = filteredDomains.filter(d => d.last_scan_status && d.last_scan_status.toUpperCase() === 'MEDIUM');
    } else if (scanFilterVal === 'SAFE') {
        filteredDomains = filteredDomains.filter(d => d.last_scan_status && ['SAFE', 'LOW', 'INFO'].includes(d.last_scan_status.toUpperCase()));
    }

    // Sort Domain Inventory (Domain, IP, Status, Last Scan)
    filteredDomains.sort((a, b) => {
        let valA, valB;

        if (domainSortCol === 'domain') {
            valA = (a.domain_name || '').toLowerCase();
            valB = (b.domain_name || '').toLowerCase();
        } else if (domainSortCol === 'ip') {
            valA = (a.ip_address || '').toLowerCase();
            valB = (b.ip_address || '').toLowerCase();
        } else if (domainSortCol === 'status') {
            valA = a.is_active ? 1 : 0;
            valB = b.is_active ? 1 : 0;
        } else if (domainSortCol === 'last_scan') {
            const LAST_SCAN_SEV_WEIGHT = {
                'CRITICAL': 6,
                'HIGH': 5,
                'MEDIUM': 4,
                'LOW': 3,
                'INFO': 3,
                'SAFE': 2
            };

            const getWeight = (domain) => {
                if (!domain.last_scan_date || !domain.last_scan_status) return 1; // Belum Scan
                const st = String(domain.last_scan_status).toUpperCase();
                return LAST_SCAN_SEV_WEIGHT[st] !== undefined ? LAST_SCAN_SEV_WEIGHT[st] : 2;
            };

            const weightA = getWeight(a);
            const weightB = getWeight(b);

            if (weightA !== weightB) {
                valA = weightA;
                valB = weightB;
            } else {
                valA = a.last_scan_date ? new Date(a.last_scan_date).getTime() : 0;
                valB = b.last_scan_date ? new Date(b.last_scan_date).getTime() : 0;
            }
        }

        if (valA < valB) return domainSortDesc ? 1 : -1;
        if (valA > valB) return domainSortDesc ? -1 : 1;
        return (a.domain_name || '').localeCompare(b.domain_name || '');
    });

    updateDomainSortIcons();

    const actionTh = document.getElementById('inventoryActionTh');
    if (actionTh) {
        actionTh.style.display = isSelectionModeActive ? 'none' : 'table-cell';
    }

    if (filteredDomains.length === 0) {
        const colSpanCount = isSelectionModeActive ? 4 : 5;
        tbody.innerHTML = `<tr><td colspan="${colSpanCount}" class="empty-state">No domains match your search.</td></tr>`;
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

    // Cetak Tabel tanpa checkbox, klik baris untuk toggle target status
    tbody.innerHTML = paginatedDomains.map(d => {
        let lastScanCell = `<span class="badge badge-inactive">BELUM SCAN</span>`;
        if (d.last_scan_date && d.last_scan_status) {
            const sevClass = getSeverityClass(d.last_scan_status);
            const formattedDate = formatDate(d.last_scan_date);
            const scanTypeHtml = d.last_scan_type ? `<span style="font-size: 12px; font-weight: 500; color: var(--text-primary);">${escapeHtml(d.last_scan_type)}</span>` : '';
            const scanIdArg = d.last_scan_id ? d.last_scan_id : 'null';
            lastScanCell = `
                <div onclick="if (isSelectionModeActive) { handleRowClick(${d.id}, event); } else { openLastScanModal('${escapeHtml(d.domain_name)}', event, ${scanIdArg}); }" 
                     title="${isSelectionModeActive ? '' : 'Klik untuk membuka laporan hasil scan terbaru (' + escapeHtml(d.domain_name) + ')'}"
                     style="display: flex; flex-direction: column; gap: 2px; cursor: pointer; padding: 4px 6px; border-radius: 6px; transition: background 0.15s;"
                     onmouseover="if (!isSelectionModeActive) this.style.background='rgba(0, 88, 189, 0.08)';"
                     onmouseout="if (!isSelectionModeActive) this.style.background='transparent';">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="badge badge-${sevClass}">${escapeHtml(d.last_scan_status.toUpperCase())}</span>
                        ${scanTypeHtml}
                    </div>
                    <small style="color:var(--text-secondary); font-size: 11px;">${escapeHtml(formattedDate)}</small>
                </div>`;
        }

        // Cek status approval & buat status badge button interaktif ultra-clean
        let statusBadge;
        if (d.approval_status === 'pending') {
            statusBadge = `<span class="badge badge-pending-approval" title="Menunggu persetujuan Super Admin (Diajukan oleh: ${escapeHtml(d.requested_by || 'Admin')})">MENUNGGU APPROVAL</span>`;
        } else {
            statusBadge = `
                <button type="button"
                        onclick="if (isSelectionModeActive) { handleRowClick(${d.id}, event); } else { toggleDomainActive(${d.id}, event); }"
                        title="${isSelectionModeActive ? '' : (d.is_active ? 'Klik untuk menonaktifkan status target' : 'Klik untuk mengaktifkan status target')}"
                        class="badge-toggle-btn ${d.is_active ? 'is-active' : 'is-inactive'}">
                    ${d.is_active ? 'ACTIVE' : 'INACTIVE'}
                </button>
            `;
        }
        let actionButtons = `
            <div style="display: flex; align-items: center; justify-content: center; gap: 12px;">
                <button class="icon-btn action-edit" onclick='openEditDomainModal(${JSON.stringify(d).replace(/'/g, "&#39;")}); event.stopPropagation();' title="Edit">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
                </button>
                <button class="icon-btn action-delete" onclick="deleteDomain(${d.id}); event.stopPropagation();" title="Hapus">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                </button>
            </div>
        `;

        if (d.approval_status === 'pending') {
            statusBadge = `<span class="badge badge-pending-approval" title="Menunggu persetujuan Super Admin (Diajukan oleh: ${escapeHtml(d.requested_by || 'Admin')})">MENUNGGU APPROVAL</span>`;
            if (currentUser && currentUser.role === 'superadmin') {
                actionButtons = `
                    <div style="display: flex; align-items: center; justify-content: center; gap: 6px;">
                        <button class="btn-approve-domain" onclick="triggerApproveDomain(${d.id}, '${escapeHtml(d.domain_name)}'); event.stopPropagation();" title="Setujui Domain">Setujui</button>
                        <button class="btn-reject-domain" onclick="triggerRejectDomain(${d.id}, '${escapeHtml(d.domain_name)}'); event.stopPropagation();" title="Tolak Domain">Tolak</button>
                    </div>
                `;
            } else {
                actionButtons = `<span style="font-size: 11px; color: #d97706; font-style: italic;">Pending Approval</span>`;
            }
        }

        const isSelected = selectedDomainIds.has(d.id);
        const rowStyle = isSelected
            ? 'background: #eff6ff; border-left: 4px solid #2563eb; cursor: pointer; transition: all 0.15s;'
            : (isSelectionModeActive ? 'cursor: pointer; transition: all 0.15s;' : 'transition: background 0.2s;');

        const ipContentHtml = d.ip_address
            ? `<span onclick="handleIpCopyClick('${escapeHtml(d.ip_address)}', ${d.id}, event)"
                     title="${isSelectionModeActive ? '' : 'Klik tepat pada teks untuk menyalin IP: ' + escapeHtml(d.ip_address)}"
                     style="font-family:var(--font-mono); color:var(--text-secondary); cursor: pointer; display: inline-flex; align-items: center; gap: 6px; padding: 2px 6px; border-radius: 4px; transition: all 0.15s ease;"
                     onmouseover="if (!isSelectionModeActive) { this.style.color='var(--primary)'; this.style.background='rgba(37,99,235,0.08)'; }"
                     onmouseout="if (!isSelectionModeActive) { this.style.color='var(--text-secondary)'; this.style.background='transparent'; }">
                   <span>${escapeHtml(d.ip_address)}</span>
                   <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="opacity: 0.5;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                </span>`
            : `<span style="font-family:var(--font-mono); color:var(--text-secondary);">-</span>`;

        const actionTdHtml = isSelectionModeActive ? '' : `<td style="text-align: center;">${actionButtons}</td>`;

        return `
        <tr class="${isSelected ? 'selected-row' : ''}" style="${rowStyle}" onclick="handleRowClick(${d.id}, event)">
            <td style="font-weight:500; color:var(--primary)">
                <a href="http://${escapeHtml(d.domain_name)}" target="_blank" onclick="if (isSelectionModeActive) { event.preventDefault(); event.stopPropagation(); handleRowClick(${d.id}, event); } else { event.stopPropagation(); }" style="text-decoration: none; color: inherit;">${escapeHtml(d.domain_name)}</a>
            </td>
            <td>
                ${ipContentHtml}
            </td>
            <td>${statusBadge}</td>
            <td>${lastScanCell}</td>
            ${actionTdHtml}
        </tr>`;
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
}

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
function openThreatModal(vuln) {
    document.getElementById('threatModalOverlay').classList.add('active');

    // Mengisi data inti
    document.getElementById('modalTitle').textContent = vuln.title || 'Vulnerability Alert';
    document.getElementById('modalRuleId').textContent = vuln.check_type || 'Unknown Scanner';

    document.getElementById('modalDesc').textContent = vuln.description || 'No description available.';
    document.getElementById('modalRecommendation').textContent = vuln.recommendation || 'No recommendation provided.';

    // Menangani Classification Section
    let hasClassification = false;
    
    if (vuln.epss_score) {
        document.getElementById('class_epss_score_container').style.display = 'block';
        document.getElementById('modalEpssScore').textContent = vuln.epss_score;
        hasClassification = true;
    } else {
        document.getElementById('class_epss_score_container').style.display = 'none';
    }

    if (vuln.epss_percentile) {
        document.getElementById('class_epss_percentile_container').style.display = 'block';
        document.getElementById('modalEpssPercentile').textContent = vuln.epss_percentile;
        hasClassification = true;
    } else {
        document.getElementById('class_epss_percentile_container').style.display = 'none';
    }

    if (vuln.cisa_kev !== undefined && vuln.cisa_kev !== null) {
        document.getElementById('class_cisa_kev_container').style.display = 'block';
        document.getElementById('modalCisaKev').textContent = vuln.cisa_kev ? 'True' : 'False';
        hasClassification = true;
    } else {
        document.getElementById('class_cisa_kev_container').style.display = 'none';
    }

    let validCve = vuln.cve && vuln.cve.trim() !== '' && vuln.cve.trim() !== '{}';

    if (validCve) {
        document.getElementById('class_cve_container').style.display = 'block';
        
        // Parse and generate hyperlinks for CVEs
        const cves = vuln.cve.split(',').map(c => c.trim()).filter(c => c && c !== '{}');
        const cveHtml = cves.map(c => `<a href="https://nvd.nist.gov/vuln/detail/${c}" target="_blank" style="color: #0d6efd; text-decoration: underline;">${c}</a>`).join(', ');
        
        document.getElementById('modalCve').innerHTML = cveHtml;
        hasClassification = true;
    } else {
        document.getElementById('class_cve_container').style.display = 'none';
    }

    if (vuln.cvss_v3) {
        document.getElementById('class_cvss_v3_container').style.display = 'block';
        document.getElementById('modalCvssV3').textContent = vuln.cvss_v3;
        hasClassification = true;
    } else {
        document.getElementById('class_cvss_v3_container').style.display = 'none';
    }

    if (vuln.cwe) {
        document.getElementById('class_cwe_container').style.display = 'block';
        
        // Parse and generate hyperlinks for CWEs
        const cwes = vuln.cwe.split(',').map(c => c.trim()).filter(c => c);
        const cweHtml = cwes.map(c => {
            // Extract the number from CWE-XXX
            const match = c.match(/CWE-(\d+)/i);
            if (match) {
                return `<a href="https://cwe.mitre.org/data/definitions/${match[1]}.html" target="_blank" style="color: #0d6efd; text-decoration: underline;">${c}</a>`;
            }
            return c; // fallback if regex fails
        }).join(', ');
        
        document.getElementById('modalCwe').innerHTML = cweHtml;
        hasClassification = true;
    } else {
        document.getElementById('class_cwe_container').style.display = 'none';
    }

    // Display the Classification section if there is at least one classification item (CWE, CVE, CVSS, etc.)
    document.getElementById('modalClassificationSection').style.display = hasClassification ? 'block' : 'none';

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

    // Render Evidence
    const evidenceContainer = document.getElementById('evidenceContainer');
    if (evidenceContainer) {
        evidenceContainer.innerHTML = ''; // clear

        if (vuln.evidence && vuln.evidence.trim() !== '') {
            try {
                const evJson = JSON.parse(vuln.evidence);
                if (evJson.type === 'instances' && Array.isArray(evJson.data)) {
                    evJson.data.forEach((inst) => {
                        evidenceContainer.appendChild(createEvidenceCard(inst));
                    });
                } else if (evJson.type === 'text') {
                    evidenceContainer.innerHTML = `<div class="evidence-card"><div class="evidence-desc" style="white-space: pre-wrap;">${linkify(escapeHtml(evJson.data))}</div></div>`;
                } else if (evJson.type === 'vuln_evidence' && evJson.data && evJson.data.type === 'table') {
                    const tableData = evJson.data.data;
                    if (tableData && tableData.headers && tableData.rows) {
                        let html = '<div class="evidence-card" style="padding: 0; overflow: hidden; border: 1px solid #d1d5db; border-radius: 8px;"><div style="overflow-x: auto;"><table style="width: 100%; border-collapse: collapse; font-size: 0.9em; text-align: left;">';
                        
                        html += '<thead style="background-color: #374151; color: #ffffff;"><tr>';
                        tableData.headers.forEach(h => {
                            html += `<th style="padding: 10px 15px; border-bottom: 2px solid #1f2937; font-weight: 600;">${escapeHtml(h)}</th>`;
                        });
                        html += '</tr></thead><tbody>';
                        
                        tableData.rows.forEach((r, rowIdx) => {
                            const rowBg = rowIdx % 2 === 0 ? '#ffffff' : '#f9fafb';
                            html += `<tr style="border-bottom: 1px solid #e5e7eb; background-color: ${rowBg};">`;
                            r.forEach((c, idx) => {
                                let cellContent = escapeHtml(c);
                                if (typeof c === 'string' && c.endsWith(' Request / Response')) {
                                    cellContent = escapeHtml(c.replace(' Request / Response', ''));
                                }
                                cellContent = linkify(cellContent);
                                html += `<td style="padding: 10px 15px; color: #1f2937; word-break: break-word;">${cellContent}</td>`;
                            });
                            html += '</tr>';
                        });
                        
                        html += '</tbody></table></div></div>';
                        evidenceContainer.innerHTML = html;
                    } else {
                        evidenceContainer.innerHTML = `<div class="evidence-card"><div class="evidence-desc" style="color: #6b7280; font-style: italic;">No specific HTTP trace/evidence attached for this vulnerability by the scanner. \n(Signature: ${escapeHtml(vuln.title)})</div></div>`;
                    }
                } else if (evJson.type === 'vuln_evidence' && evJson.data && evJson.data.type === 'text') {
                    evidenceContainer.innerHTML = `
                    <div class="evidence-card">
                        <div class="evidence-desc" style="white-space: pre-wrap; font-family: monospace; background: #f8fafc; padding: 12px; border-radius: 6px; border: 1px solid #e2e8f0; color: #334155;">${linkify(escapeHtml(evJson.data.data))}</div>
                    </div>`;
                } else {
                    // Jika ada format JSON lain, fallback
                    evidenceContainer.innerHTML = `<div class="evidence-card"><div class="evidence-desc" style="white-space: pre-wrap;">${linkify(escapeHtml(JSON.stringify(evJson)))}</div></div>`;
                }
            } catch (e) {
                // Fallback for old data or plain text
                evidenceContainer.innerHTML = `<div class="evidence-card"><div class="evidence-desc" style="white-space: pre-wrap;">${linkify(escapeHtml(vuln.evidence))}</div></div>`;
            }
        } else {
            evidenceContainer.innerHTML = `<div class="evidence-card"><div class="evidence-desc" style="color: #6b7280; font-style: italic;">No specific HTTP trace/evidence attached for this vulnerability by the scanner. \n(Signature: ${escapeHtml(vuln.title)})</div></div>`;
        }
    }
}

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
                <div style="font-size:0.9rem; color:var(--color-text);">${escapeHtml(inst.parameter)}</div>
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
        html = `<div class="evidence-desc" style="white-space: pre-wrap; font-family: monospace;">${escapeHtml(JSON.stringify(inst, null, 2))}</div>`;
    }
    
    card.innerHTML = html;
    return card;
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

    // Otomatis tandai notifikasi terkait sebagai DIBACA saat detail scan dibuka (dari history / manual / toast)
    if (scan && scan.id) {
        markNotificationReadByScanId(scan.id);
    }

    const domainName = scan.domains?.domain_name || scan.domain_name || '';
    document.getElementById('scanModalDomain').textContent = domainName || '-';
    document.getElementById('scanModalIp').textContent = scan.domains?.ip_address || scan.ip_address || '-';
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
}

function setScanFilter(sev) {
    currentScanVulnsFilter = sev;
    renderScanFilters();
    renderScanVulnsTable();
}

function renderScanFilters() {
    const filtersContainer = document.getElementById('scanModalFilters');
    if (!filtersContainer) return;

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
    if (!tbody) return;

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
            `;
    }).join('');

    updateInventoryBulkBar();
}

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


// ==========================================
// LOGIKA LUPA PASSWORD
// ==========================================
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
        showToast("Informasi", data.message, "📧");
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
    if (user.role === 'superadmin' || user.role === 'admin') {
        if (user.role === 'superadmin') {
            roleEl.innerHTML = `<span class="badge-superadmin-role">SUPER ADMIN</span>`;
        } else {
            roleEl.innerHTML = `<span class="badge-admin-role">ADMIN</span>`;
        }
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
        checkOvernightNotifications();
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

    const errorMsg = document.getElementById('createUserErrorMsg');
    if (errorMsg) {
        errorMsg.style.display = 'none';
    }

    const roleSelect = document.getElementById('createUserRole');
    if (roleSelect) {
        if (currentUser && currentUser.role === 'superadmin') {
            roleSelect.innerHTML = `
                <option value="user">User</option>
                <option value="admin">Admin</option>
            `;
            roleSelect.disabled = false;
        } else {
            roleSelect.innerHTML = `
                <option value="user">User</option>
            `;
            roleSelect.value = 'user';
            roleSelect.disabled = true;
        }
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
    const roleSelect = document.getElementById('createUserRole');
    const role = roleSelect ? roleSelect.value : "user";
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
        const isProtectedSuperAdmin = u.role === 'superadmin' && currentUser.role !== 'superadmin';
        const isSuperAdminCaller = currentUser && currentUser.role === 'superadmin';
        
        let roleBadge = `<span class="badge-user-role">User</span>`;
        if (u.role === 'superadmin') {
            if (isSuperAdminCaller) {
                roleBadge = `
                    <span class="badge-superadmin-role clickable-role-badge" onclick="showRoleInfoModal('${escapeHtml(u.username)}')" title="Klik untuk lihat detail Super Admin">
                        Super Admin
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-left:3px; opacity:0.85;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                    </span>`;
            } else {
                roleBadge = `<span class="badge-superadmin-role">Super Admin</span>`;
            }
        } else if (u.role === 'admin') {
            if (isSuperAdminCaller) {
                roleBadge = `
                    <span class="badge-admin-role clickable-role-badge" onclick="showRoleInfoModal('${escapeHtml(u.username)}')" title="Klik untuk lihat user yang dibuat oleh admin ini">
                        Admin
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-left:3px; opacity:0.85;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                    </span>`;
            } else {
                roleBadge = `<span class="badge-admin-role">Admin</span>`;
            }
        } else {
            if (isSuperAdminCaller) {
                roleBadge = `
                    <span class="badge-user-role clickable-role-badge" onclick="showRoleInfoModal('${escapeHtml(u.username)}')" title="Klik untuk lihat admin pembuat user ini">
                        User
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-left:3px; opacity:0.85;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                    </span>`;
            } else {
                roleBadge = `<span class="badge-user-role">User</span>`;
            }
        }

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
        } else if (isProtectedSuperAdmin) {
            actionButtons = `<span style="color: #c084fc; font-weight: 600; font-size: 12px; font-style: italic;">Super Admin (Terproteksi)</span>`;
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
                        <div style="font-size:16px; font-weight:700; color:#1e293b;">
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

async function triggerDeleteUser(username) {
    const confirmed = await customConfirm({
        title: 'Hapus Akun User',
        message: `Apakah Anda yakin ingin menghapus user '${username}' secara permanen? Akun ini tidak akan bisa login kembali.`,
        confirmText: 'Ya, Hapus Permanen',
        cancelText: 'Batal',
        variant: 'danger'
    });
    if (!confirmed) return;

    try {
        const resp = await fetch(`${API_BASE}/api/admin/users/${username}`, {
            method: 'DELETE'
        });
        const data = await resp.json();
        if (resp.status === 200) {
            showToast(`User '${username}' berhasil dihapus dari sistem.`, "success");
            loadAdminUsers();
            fetchNotifications();
        } else {
            showToast(data.detail || "Gagal menghapus user.", "error");
        }
    } catch (err) {
        showToast("Gagal menghubungi server.", "error");
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

    const confirmed = await customConfirm({
        title: 'Hapus Semua Notifikasi',
        message: 'Apakah Anda yakin ingin menghapus semua notifikasi dari daftar?',
        confirmText: 'Ya, Bersihkan',
        cancelText: 'Batal',
        variant: 'danger'
    });
    if (!confirmed) return;

    try {
        const deletedNotifs = JSON.parse(localStorage.getItem('dsti_deleted_notifs_v3') || '[]');
        allNotifications.forEach(n => {
            if (!deletedNotifs.includes(n.id)) deletedNotifs.push(n.id);
        });
        localStorage.setItem('dsti_deleted_notifs_v3', JSON.stringify(deletedNotifs));

        allNotifications = [];
        renderNotificationList();
        showToast("Semua notifikasi dibersihkan.", "success");
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
        const res = await fetch(`${API_BASE}/api/notifications`);
        const data = await res.json();
        if (data.status === 'success') {
            const allowedTypes = ['success', 'scan_complete', 'scan_finished', 'domain_found', 'info', 'domain_request', 'domain_approval_result']; 
            const deletedNotifs = JSON.parse(localStorage.getItem('dsti_deleted_notifs_v3') || '[]');
            const readNotifs = JSON.parse(localStorage.getItem('dsti_read_notifs') || '[]');

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
            
            // === TAMBAHAN KODE: BATAS WAKTU 24 JAM ===
            const now = new Date();
            const ONE_DAY_MS = 24 * 60 * 60 * 1000; // 24 jam dalam satuan milidetik

            allNotifications.forEach(n => {
                let isRecent = true;
                
                // Periksa usia notifikasi
                if (n.timestamp) {
                    const notifDate = new Date(n.timestamp);
                    // Jika selisih waktu sekarang dan waktu notifikasi lebih dari 1 hari, tandai false
                    if (!isNaN(notifDate.getTime()) && (now - notifDate) > ONE_DAY_MS) {
                        isRecent = false;
                    }
                }

                // Tampilkan pop-up HANYA jika statusnya unread DAN usianya di bawah 24 jam
                if (n.type === 'scan_finished' && n.unread && isRecent) {
                    showScanFinishedToast(n);
                } else if (n.type === 'domain_found' && n.unread && isRecent) {
                    showDomainFoundToast(n); 
                }
            });
            // =========================================
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
        
        // 1. Tentukan Icon
        let icon = '🔔';
        if (n.type === 'scan_complete' || n.type === 'success') icon = '✅';
        else if (n.type === 'scan_failed') icon = '❌';
        else if (n.type === 'user_login') icon = '👤';
        else if (n.type === 'scan_finished') icon = '🚀';
        else if (n.type === 'domain_found') icon = '🌐';
        else if (n.type === 'info') icon = 'ℹ️';

        let absoluteTime = '';
        if (n.timestamp) {
            const dateObj = new Date(n.timestamp);
            if (!isNaN(dateObj)) {
                const dateOpts = { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' };
                absoluteTime = dateObj.toLocaleString('id-ID', dateOpts);
            }
        }

        // 2. Fallback Judul & Pesan
        const safeTitle = n.title ? escapeHtml(n.title) : 'Notifikasi Sistem';
        const safeMessage = n.message ? escapeHtml(n.message) : (n.domain ? `Scan untuk ${escapeHtml(n.domain)} telah selesai.` : 'Pesan sistem terbaru.');

        // HTML Template yang sudah di-fix
        return `
            <div class="notif-item ${unreadClass}" onclick="markAsRead('${n.id}')">
                <div class="notif-unread-dot"></div>
                <div class="notif-avatar" style="background: transparent; font-size: 20px;">${icon}</div>
                <div class="notif-content">
                    <div class="notif-text" style="line-height: 1.4;">
                        <strong>${safeTitle}</strong><br>
                        <span style="color: #64748b; font-size: 13px;">${safeMessage}</span>
                    </div>
                    <div class="notif-time" style="margin-top: 4px;">${relativeTime} ${absoluteTime ? `(${absoluteTime})` : ''}</div>
                </div>
                <div class="notif-actions">
                    <button class="notif-action-btn" onclick="deleteNotification('${n.id}', event)" title="Hapus notifikasi">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
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
        const dropdown = document.getElementById('notificationDropdown');
        if (dropdown) dropdown.style.display = 'none';

        if (notif.type === 'scan_finished') {
            await loadVulnerabilities(true);
            jumpToScanDetail(notif.time, notif.domain, false);
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
    };

    wsLive.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);

            if (data.event === 'new_notification') {
                if (currentUser && (currentUser.role === 'admin' || currentUser.role === 'superadmin')) {
                    if (data.notification.type === 'scan_finished') {
                        showScanFinishedToast(data.notification);
                    } else if (data.notification.type === 'domain_found' || data.notification.type === 'info') {
                        let pendingOsint = JSON.parse(localStorage.getItem('dsti_pending_osint') || '[]');
                        if (!pendingOsint.find(n => n.id === data.notification.id)) {
                            pendingOsint.push(data.notification);
                            localStorage.setItem('dsti_pending_osint', JSON.stringify(pendingOsint));
                        }
                        
                        if (data.notification.type === 'domain_found') {
                            showDomainFoundToast(data.notification);
                        } else {
                            showToast(data.notification.title, data.notification.message, "🔔");
                        }
                    } else {
                        showToast(data.notification.title, data.notification.message, "🔔");
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
                // Refresh data if needed, but new_notification already handles the toast and notification list.
                if (typeof fetchActiveScans === 'function') fetchActiveScans();
                if (typeof refreshData === 'function') refreshData(true);
            } else if (data.event === 'force_logout') {
                window.kickedReason = 'force_logout';
                showToast("Sesi Diakhiri", "Anda telah dipaksa keluar oleh Administrator.", "⚠️");
                setTimeout(() => {
                    handleLogout();
                }, 1000);
            } else if (data.event === 'timeout') {
                window.kickedReason = 'timeout';
                showToast("Akun Ditangguhkan", "Akun Anda telah ditangguhkan oleh Administrator.", "⏳");
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
        } else if (e.code === 4000) {
            // Jika kode 4000, berarti user di-kick (force logout / timeout)
            if (!window.kickedReason) {
                showToast("Sesi Diakhiri", "Anda telah dikeluarkan oleh sistem.", "⚠️");
                setTimeout(() => {
                    handleLogout();
                }, 500);
            }
            window.kickedReason = null;
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
    }, 3500);
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
            showToast('Tersalin', `${label} ${cleanText} berhasil disalin ke clipboard!`, '📋');
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
        showToast('Tersalin', `${label} ${text} berhasil disalin ke clipboard!`, '📋');
    } catch (e) {
        showToast('Error', 'Gagal menyalin ke clipboard', '❌');
    }
}

// ==============================================================================
// LOGIK NOTIFIKASI TOAST DINI HARI (07:00 WIB) & SYNC READ STATUS
// ==============================================================================
let activeOvernightToastTimers = {};

function markNotificationReadByScanId(scanId) {
    if (!scanId) return;
    const strId = String(scanId);
    const readNotifs = JSON.parse(localStorage.getItem('dsti_read_notifs') || '[]');
    if (!readNotifs.includes(strId)) {
        readNotifs.push(strId);
        localStorage.setItem('dsti_read_notifs', JSON.stringify(readNotifs));
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

    const now = Date.now();
    if (now - lastOvernightCheckTime < 10000) return;
    lastOvernightCheckTime = now;

    try {
        const res = await fetch(`${API_BASE}/api/notifications/overnight-scans`);
        const data = await res.json();
        
        if (data.status === 'success' && data.data && data.data.length > 0) {
            const readNotifs = JSON.parse(localStorage.getItem('dsti_read_notifs') || '[]');
            
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

    // Hapus toast sebelumnya jika masih ada di DOM
    const existingToast = document.getElementById(`overnight-toast-${scanIdStr}`);
    if (existingToast) existingToast.remove();

    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.id = `overnight-toast-${scanIdStr}`;
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
        <div class="toast-icon">⚠️</div>
        <div class="toast-body" style="width: 100%;">
            <div class="toast-title">Auto Scan Dini Hari (HIGH & CRITICAL)</div>
            <div class="toast-message">${toastMessage}</div>
            <div class="toast-actions-row">
                <button class="toast-btn toast-btn-primary" id="btnCekDetail-${scanIdStr}">Cek Detail</button>
                <button class="toast-btn toast-btn-secondary" id="btnCloseNotif-${scanIdStr}">Tutup ✕</button>
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

                if (typeof applyVulnFilters === 'function') {
                    applyVulnFilters();
                }
            }
        };
    }

    // Tombol "Tutup ✕"
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
        const readNotifs = JSON.parse(localStorage.getItem('dsti_read_notifs') || '[]');
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

// ==============================================================================
// HELPER PENGUJIAN INSTAN (UNTUK TESTING DI CONSOLE BROWSER KAPAN SAJA)
// ==============================================================================
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
    localStorage.removeItem('dsti_read_notifs');
    console.log("[TEST] Status baca notifikasi (dsti_read_notifs) telah di-reset.");
    if (typeof fetchNotifications === 'function') fetchNotifications();
};



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
                <tr style="cursor: default; transition: background 0.2s;">
                    <td style="padding: 16px; min-width: 140px;">
                        <div style="display:flex; align-items:center; gap:8px; color: #2563eb; font-weight: 500; font-size: 14px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                            ${scanIdLabel}
                        </div>
                    </td>
                    <td style="padding: 16px;">${statusHtml}</td>
                    <td style="padding: 16px;">
                        <div style="font-weight: 500; font-size: 13px; color: #334155; margin-bottom: 4px;">${escapeHtml(domainName.replace(/^https?:\/\//, '').replace(/\/$/, ''))}</div>
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
            scanIdLabel = 'Website Scan';

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
                <tr onclick="openScanModalIndex(${actualIndex})" style="cursor: pointer; transition: background 0.2s;">
                    <td style="padding: 16px; min-width: 140px;">
                        <div style="display:flex; align-items:center; gap:8px; color: #64748b; font-weight: 500; font-size: 14px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                            ${scanIdLabel}
                        </div>
                    </td>
                    <td style="padding: 16px;">${statusHtml}</td>
                    <td style="padding: 16px;">
                        <div style="font-weight: 500; font-size: 13px; color: #334155; margin-bottom: 4px;">${escapeHtml(domainName)}</div>
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

    const actionText = targetStatus ? 'mengaktifkan' : 'menonaktifkan';
    const confirmed = await customConfirm({
        title: `${targetStatus ? 'Aktifkan' : 'Nonaktifkan'} Domain Terpilih`,
        message: `Apakah Anda yakin ingin ${actionText} ${targets.length} domain terpilih?`,
        confirmText: `Ya, ${targetStatus ? 'Aktifkan' : 'Nonaktifkan'}`,
        cancelText: 'Batal',
        variant: targetStatus ? 'info' : 'warning'
    });
    if (!confirmed) return;

    targets.forEach(d => d.is_active = targetStatus);
    renderInventoryList();

    try {
        await Promise.all(targets.map(d =>
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
        showToast(`Berhasil ${targetStatus ? 'mengaktifkan' : 'menonaktifkan'} ${targets.length} domain.`, 'success');
        clearDirectSelection();
    } catch (err) {
        console.error('Error direct bulk toggling status:', err);
        showToast('Gagal memperbarui beberapa status domain.', 'error');
    }
};

window.directBulkLaunchScan = function (type) {
    if (selectedDomainIds.size === 0) return;
    const targets = (allDomains || []).filter(d => selectedDomainIds.has(d.id));
    const targetNames = targets.map(d => d.domain_name);

    if (type === 'web') {
        window.selectedWebScans = new Set(targetNames);
        openWebScanModal();
    } else if (type === 'network') {
        window.selectedNetworkScans = new Set(targetNames);
        openNetworkScanModal();
    }
    clearDirectSelection();
};

window.directBulkDeleteDomains = async function () {
    if (selectedDomainIds.size === 0) return;
    const targets = (allDomains || []).filter(d => selectedDomainIds.has(d.id));
    const confirmed = await customConfirm({
        title: 'Hapus Domain Terpilih',
        message: `Apakah Anda yakin ingin MENGHAPUS ${targets.length} domain terpilih dari inventory? Tindakan ini tidak dapat dibatalkan.`,
        confirmText: 'Ya, Hapus Semua',
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
                ${d.ip_address ? `<span style="font-size: 11px; color: var(--color-muted); font-family: monospace;">${escapeHtml(d.ip_address)}</span>` : ''}
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
            newStatus ? '✅' : 'ℹ️'
        );
    } catch (err) {
        console.error('Error toggling status:', err);
        showToast('Error', 'Gagal memperbarui status domain.', '❌');
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
                showToast('Error', data.detail || data.message, '❌');
            }
        })
        .catch(err => {
            console.error('Error stopping scan:', err);
            showToast('Error', 'An error occurred while stopping the scan.', '❌');
        });
}

// (Web Scanner polling is handled inside switchView directly)

function openSelectScanTypeModal() {
    const modal = document.getElementById('selectScanTypeModalOverlay');
    if (modal) modal.classList.add('active');
}

function closeSelectScanTypeModal() {
    const modal = document.getElementById('selectScanTypeModalOverlay');
    if (modal) modal.classList.remove('active');
}

function openWebScanModal() {
    document.getElementById('webScanModalOverlay').classList.add('active');
    renderWebScanTargetList();

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
                    card.style.background = 'var(--color-surface)';
                }
            });
        });
    });
}

let webScanSearchQuery = '';
let networkScanSearchQuery = '';

async function openLastScanModal(domainName, event, lastScanId = null) {
    if (event) event.stopPropagation();

    // Pastikan allVulns sudah terisi, jika belum fetch otomatis dari API
    if (!allVulns || allVulns.length === 0) {
        try {
            const resp = await fetch(`${API_BASE}/api/scan-history?limit=1000`);
            const data = await resp.json();
            allVulns = data.data || [];
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

function updateSelectedWebTargetsCount() {
    const checkedCount = document.querySelectorAll('.web-target-checkbox:checked').length;
    const label = document.getElementById('webSelectedCountLabel');
    if (label) {
        label.textContent = `${checkedCount} domain terpilih`;
    }
}

function renderWebScanTargetList() {
    const container = document.getElementById('webScanTargetContainer');
    if (!container) return;

    if (!allDomains || allDomains.length === 0) {
        container.innerHTML = '<div style="padding: 12px; color: var(--color-muted); font-size: 13px;">Tidak ada domain di inventory</div>';
        return;
    }

    const q = webScanSearchQuery.trim().toLowerCase();
    const filtered = allDomains.filter(d => {
        const dName = (d.domain_name || '').toLowerCase();
        const ip = (d.ip_address || '').toLowerCase();
        return !q || dName.includes(q) || ip.includes(q);
    });

    container.innerHTML = `
        <div style="margin-bottom: 10px;">
            <div style="position: relative; margin-bottom: 8px;">
                <input type="text" 
                       id="webScanSearchInput"
                       value="${escapeHtml(webScanSearchQuery)}"
                       placeholder="Cari nama domain atau IP address..."
                       oninput="onWebScanSearch(this.value)"
                       style="width: 100%; padding: 8px 12px; padding-left: 32px; border: 1px solid var(--color-border); border-radius: 6px; font-size: 13px; outline: none; box-sizing: border-box; background: var(--color-surface); color: var(--color-ink);">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="position: absolute; left: 10px; top: 10px;">
                    <circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
            </div>
            <div style="padding-bottom: 6px; border-bottom: 1px solid var(--color-border); display: flex; justify-content: space-between; align-items: center;">
                <label style="font-size: 12px; font-weight: 600; color: var(--primary); cursor: pointer; display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="selectAllWebTargets" onchange="toggleAllWebTargets(this)" style="accent-color: var(--primary); width: 15px; height: 15px; cursor: pointer;">
                    <span>Pilih semua domain</span>
                </label>
                <span id="webSelectedCountLabel" style="font-size: 11px; color: var(--color-muted); font-weight: 500;">0 domain terpilih</span>
            </div>
        </div>
        <div style="max-height: 180px; overflow-y: auto; display: flex; flex-direction: column; gap: 4px; padding-right: 4px;">
            ${filtered.length === 0 ? '<div style="padding: 16px; text-align: center; color: var(--color-muted); font-size: 13px;">Tidak ada domain/IP yang cocok dengan pencarian</div>' : 
            filtered.map(d => `
                <label style="display: flex; align-items: center; justify-content: space-between; padding: 6px 10px; border-radius: 6px; background: var(--color-surface); cursor: pointer; border: 1px solid var(--color-border); transition: all 0.15s;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <input type="checkbox" name="webTargetDomain" value="${escapeHtml(d.domain_name)}" class="web-target-checkbox" onchange="updateSelectedWebTargetsCount()" style="accent-color: var(--primary); width: 15px; height: 15px; cursor: pointer;">
                        <div>
                            <span style="font-size: 13px; font-weight: 500; color: var(--color-ink); display: block;">${escapeHtml(d.domain_name)}</span>
                            ${d.ip_address ? `<span style="font-size: 11px; color: var(--color-muted); font-family: monospace;">${escapeHtml(d.ip_address)}</span>` : ''}
                        </div>
                    </div>
                    <span class="badge ${d.is_active ? 'badge-active' : 'badge-inactive'}" style="margin: 0; font-size: 10px; padding: 2px 6px;">
                        ${d.is_active ? 'ACTIVE' : 'INACTIVE'}
                    </span>
                </label>
            `).join('')}
        </div>
    `;
    updateSelectedWebTargetsCount();
}

function onWebScanSearch(val) {
    webScanSearchQuery = val;
    renderWebScanTargetList();
    const input = document.getElementById('webScanSearchInput');
    if (input) {
        input.focus();
        input.setSelectionRange(val.length, val.length);
    }
}

function toggleAllWebTargets(masterCheckbox) {
    const checkboxes = document.querySelectorAll('.web-target-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = masterCheckbox.checked;
    });
    updateSelectedWebTargetsCount();
}

function submitWebScan() {
    const selectedCheckboxes = document.querySelectorAll('.web-target-checkbox:checked');
    const selectedDomains = Array.from(selectedCheckboxes).map(cb => cb.value);

    if (selectedDomains.length === 0) {
        showToast('Error', 'Pilih minimal satu domain target dari inventory.', '❌');
        return;
    }

    const scanTypeElement = document.querySelector('input[name="webScanType"]:checked');
    const selectedScanType = scanTypeElement ? scanTypeElement.value : 'deep';

    const btnSubmit = document.getElementById('btnSubmitWebScan');
    btnSubmit.disabled = true;
    btnSubmit.style.opacity = '0.5';
    btnSubmit.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="animation: spin 1s linear infinite;"><circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="8"></circle></svg>
        Launching (${selectedDomains.length} target)...
    `;

    fetch(`${API_BASE}/api/web-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets: selectedDomains, scan_type: selectedScanType })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success' || data.status === 'ok') {
                showToast('Success', data.message || `Pemindaian web berhasil dimulai untuk ${selectedDomains.length} domain.`, '✅');
                document.getElementById('webScanModalOverlay').classList.remove('active');
                if (typeof fetchActiveScans === 'function') fetchActiveScans();
            } else {
                showToast('Error', data.detail || data.message || 'Gagal memulai pemindaian web.', '❌');
            }
        })
        .catch(err => {
            console.error('Error starting web scan:', err);
            showToast('Error', 'Koneksi terputus dari server', '❌');
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
    renderNetworkScanTargetList();

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
                    card.style.background = 'var(--color-surface)';
                }
            });
        });
    });
}

function updateSelectedNetworkTargetsCount() {
    const checkedCount = document.querySelectorAll('.network-target-checkbox:checked').length;
    const label = document.getElementById('networkSelectedCountLabel');
    if (label) {
        label.textContent = `${checkedCount} domain terpilih`;
    }
}

function renderNetworkScanTargetList() {
    const container = document.getElementById('networkScanTargetContainer');
    if (!container) return;

    if (!allDomains || allDomains.length === 0) {
        container.innerHTML = '<div style="padding: 12px; color: var(--color-muted); font-size: 13px;">Tidak ada domain di inventory</div>';
        return;
    }

    const q = networkScanSearchQuery.trim().toLowerCase();
    const filtered = allDomains.filter(d => {
        const dName = (d.domain_name || '').toLowerCase();
        const ip = (d.ip_address || '').toLowerCase();
        return !q || dName.includes(q) || ip.includes(q);
    });

    container.innerHTML = `
        <div style="margin-bottom: 10px;">
            <div style="position: relative; margin-bottom: 8px;">
                <input type="text" 
                       id="networkScanSearchInput"
                       value="${escapeHtml(networkScanSearchQuery)}"
                       placeholder="Cari nama domain atau IP address..."
                       oninput="onNetworkScanSearch(this.value)"
                       style="width: 100%; padding: 8px 12px; padding-left: 32px; border: 1px solid var(--color-border); border-radius: 6px; font-size: 13px; outline: none; box-sizing: border-box; background: var(--color-surface); color: var(--color-ink);">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="position: absolute; left: 10px; top: 10px;">
                    <circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
            </div>
            <div style="padding-bottom: 6px; border-bottom: 1px solid var(--color-border); display: flex; justify-content: space-between; align-items: center;">
                <label style="font-size: 12px; font-weight: 600; color: var(--primary); cursor: pointer; display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="selectAllNetworkTargets" onchange="toggleAllNetworkTargets(this)" style="accent-color: var(--primary); width: 15px; height: 15px; cursor: pointer;">
                    <span>Pilih semua domain</span>
                </label>
                <span id="networkSelectedCountLabel" style="font-size: 11px; color: var(--color-muted); font-weight: 500;">0 domain terpilih</span>
            </div>
        </div>
        <div style="max-height: 180px; overflow-y: auto; display: flex; flex-direction: column; gap: 4px; padding-right: 4px;">
            ${filtered.length === 0 ? '<div style="padding: 16px; text-align: center; color: var(--color-muted); font-size: 13px;">Tidak ada domain/IP yang cocok dengan pencarian</div>' : 
            filtered.map(d => `
                <label style="display: flex; align-items: center; justify-content: space-between; padding: 6px 10px; border-radius: 6px; background: var(--color-surface); cursor: pointer; border: 1px solid var(--color-border); transition: all 0.15s;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <input type="checkbox" name="networkTargetDomain" value="${escapeHtml(d.domain_name)}" class="network-target-checkbox" onchange="updateSelectedNetworkTargetsCount()" style="accent-color: var(--primary); width: 15px; height: 15px; cursor: pointer;">
                        <div>
                            <span style="font-size: 13px; font-weight: 500; color: var(--color-ink); display: block;">${escapeHtml(d.domain_name)}</span>
                            ${d.ip_address ? `<span style="font-size: 11px; color: var(--color-muted); font-family: monospace;">${escapeHtml(d.ip_address)}</span>` : ''}
                        </div>
                    </div>
                    <span class="badge ${d.is_active ? 'badge-active' : 'badge-inactive'}" style="margin: 0; font-size: 10px; padding: 2px 6px;">
                        ${d.is_active ? 'ACTIVE' : 'INACTIVE'}
                    </span>
                </label>
            `).join('')}
        </div>
    `;
    updateSelectedNetworkTargetsCount();
}

function onNetworkScanSearch(val) {
    networkScanSearchQuery = val;
    renderNetworkScanTargetList();
    const input = document.getElementById('networkScanSearchInput');
    if (input) {
        input.focus();
        input.setSelectionRange(val.length, val.length);
    }
}

function toggleAllNetworkTargets(masterCheckbox) {
    const checkboxes = document.querySelectorAll('.network-target-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = masterCheckbox.checked;
    });
    updateSelectedNetworkTargetsCount();
}

function submitNetworkScan() {
    const selectedCheckboxes = document.querySelectorAll('.network-target-checkbox:checked');
    const selectedDomains = Array.from(selectedCheckboxes).map(cb => cb.value);

    if (selectedDomains.length === 0) {
        showToast('Error', 'Pilih minimal satu domain target dari inventory.', '❌');
        return;
    }

    const scanTypeElement = document.querySelector('input[name="networkScanType"]:checked');
    const selectedScanType = scanTypeElement ? scanTypeElement.value : 'deep';

    const btnSubmit = document.getElementById('btnSubmitNetworkScan');
    btnSubmit.disabled = true;
    btnSubmit.style.opacity = '0.5';
    btnSubmit.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="animation: spin 1s linear infinite;"><circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="8"></circle></svg>
        Launching (${selectedDomains.length} target)...
    `;

    fetch(`${API_BASE}/api/network-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            targets: selectedDomains,
            scan_type: selectedScanType
        })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success' || data.status === 'ok') {
                showToast('Success', data.message || `Pemindaian network berhasil dimulai untuk ${selectedDomains.length} domain.`, '✅');
                document.getElementById('networkScanModalOverlay').classList.remove('active');
                if (typeof refreshData === 'function') refreshData(true);
            } else {
                showToast('Error', data.detail || data.message || 'Gagal memulai pemindaian network.', '❌');
            }
        })
        .catch(err => {
            console.error('Error starting network scan:', err);
            showToast('Error', 'Koneksi terputus dari server', '❌');
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

    // 1. Cari berdasarkan scanId persis jika ada
    if (scanId && typeof allVulns !== 'undefined' && allVulns) {
        const foundById = allVulns.find(s => String(s.id) === String(scanId));
        if (foundById) {
            openScanModal(foundById);
            return;
        }
    }

    // 2. Jika scanId tidak ada / belum di allVulns, fetch spesifik scan oleh API
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
                ticks: { precision: 0 },
                grid: { 
                    borderDash: [5, 5] // Memastikan garis putus-putus tetap aktif
                },
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
                    color: () => document.documentElement.getAttribute('data-theme') === 'dark' ? '#94a3b8' : '#64748b',
                    font: { size: 15, weight: '500' },
                    padding: 20,
                    generateLabels: (chart) => {
                        const legendTextColor = document.documentElement.getAttribute('data-theme') === 'dark' ? '#94a3b8' : '#64748b';
                        return chart.data.datasets.map((dataset, i) => ({
                            text: dataset.label,
                            fillStyle: dataset.borderColor,
                            fontColor: legendTextColor,
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

// ==============================================================================
// LOGIKA NOTIFIKASI PERSISTEN: HASIL SCAN SELESAI
// ==============================================================================
function showScanFinishedToast(notif) {
    if (!currentUser) return; 

    // Cek apakah notifikasi ini sudah pernah ditekan "Cek Detail"
    const readNotifs = JSON.parse(localStorage.getItem('dsti_read_notifs') || '[]');
    if (readNotifs.includes(notif.id)) return;

    // Cek apakah notifikasi sudah tampil di layar untuk mencegah duplikasi
    const existingToast = document.getElementById(`scan-toast-${notif.id}`);
    if (existingToast) return;

    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.id = `scan-toast-${notif.id}`;
    // Meminjam gaya (style) CSS yang sudah ada dari overnight-toast
    toast.className = 'toast-notification overnight-toast';

    toast.innerHTML = `
        <div class="toast-icon">⚠️</div>
        <div class="toast-body" style="width: 100%;">
            <div class="toast-title">${escapeHtml(notif.title || 'Scan Selesai')}</div>
            <div class="toast-message">Ditemukan hasil pemindaian baru untuk target <strong>${escapeHtml(notif.domain || 'Domain')}</strong>. Cek detail sekarang.</div>
            <div class="toast-actions-row">
                <button class="toast-btn toast-btn-primary" id="btnCekDetailScan-${notif.id}">Cek Detail</button>
                <button class="toast-btn toast-btn-secondary" id="btnCloseScanNotif-${notif.id}">Tutup ✕</button>
            </div>
        </div>
    `;

    container.appendChild(toast);

    // --- AKSI: TOMBOL CEK DETAIL ---
    const btnCekDetail = document.getElementById(`btnCekDetailScan-${notif.id}`);
    if (btnCekDetail) {
        btnCekDetail.onclick = (e) => {
            e.stopPropagation();
            toast.remove();
            
            // 1. Catat ke Local Storage agar tidak muncul lagi selamanya
            const currentRead = JSON.parse(localStorage.getItem('dsti_read_notifs') || '[]');
            if (!currentRead.includes(notif.id)) {
                currentRead.push(notif.id);
                localStorage.setItem('dsti_read_notifs', JSON.stringify(currentRead));
            }

            // 2. Perbarui angka bel notifikasi di sudut kanan atas
            if (typeof fetchNotifications === 'function') fetchNotifications();

            // 3. Arahkan pengguna ke Domain Inventory
            if (typeof switchView === 'function') {
                switchView('inventory');
            }

            // 4. (Opsional) Otomatis mencari domain tersebut di tabel
            const searchInput = document.getElementById('domainSearchInput');
            if (searchInput && notif.domain) {
                searchInput.value = notif.domain;
                if (typeof renderInventoryList === 'function') renderInventoryList();
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

// ==============================================================================
// LOGIKA NOTIFIKASI PERSISTEN: DOMAIN BARU DITEMUKAN (OSINT)
// ==============================================================================
let activeOsintToastTimers = {};

function showDomainFoundToast(notif) {
    if (!currentUser) return; 

    const readNotifs = JSON.parse(localStorage.getItem('dsti_read_notifs') || '[]');
    if (readNotifs.includes(notif.id)) return;

    const existingToast = document.getElementById(`domain-toast-${notif.id}`);
    if (existingToast) return;

    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.id = `domain-toast-${notif.id}`;
    toast.className = 'toast-notification overnight-toast';

    toast.innerHTML = `
        <div class="toast-icon">🌐</div>
        <div class="toast-body" style="width: 100%;">
            <div class="toast-title">${escapeHtml(notif.title)}</div>
            <div class="toast-message">${escapeHtml(notif.message)}</div>
            <div class="toast-actions-row">
                <button class="toast-btn toast-btn-primary" id="btnCekDomain-${notif.id}">Cek Detail</button>
                <button class="toast-btn toast-btn-secondary" id="btnCloseDomain-${notif.id}">Tutup ✕</button>
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

            const currentRead = JSON.parse(localStorage.getItem('dsti_read_notifs') || '[]');
            if (!currentRead.includes(notif.id)) {
                currentRead.push(notif.id);
                localStorage.setItem('dsti_read_notifs', JSON.stringify(currentRead));
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
        const readNotifs = JSON.parse(localStorage.getItem('dsti_read_notifs') || '[]');
        
        // Cek lagi, pastikan user belum membacanya dari menu lonceng
        if (!readNotifs.includes(notifIdStr)) {
            showDomainFoundToast(notif);
        }
    }, 300000);
}

// ==========================================
// LOGIKA DARK MODE / LIGHT MODE & CHART.JS FIX
// ==========================================

// 1. Daftarkan Plugin Global Chart.js 
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

// =========================================================
// 🔔 FEATURE: DOMAIN ADDITION APPROVAL (SUPERADMIN)
// =========================================================
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