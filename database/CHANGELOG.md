# Catatan Perubahan Database

Semua perubahan tabel, kolom, constraint, dan data dicatat di sini, dari yang terbaru.
Kolom **Lokal** dan **Server UNDIP** menunjukkan di mana perubahan sudah berlaku.
Cara memeriksa server: jalankan `python database/check_schema.py` di server lalu bandingkan.

Jenis perubahan:
- **Struktur otomatis**: dibuat sendiri oleh `ensure_database_schema()` di `db_manager.py` saat aplikasi start. Cukup deploy kode lalu restart.
- **Data manual**: file SQL di `database/migrations/`, harus dijalankan sendiri setelah backup.
- **Usulan**: belum diterapkan di kode maupun database.

## Usulan (belum diterapkan)

| Usulan | Jenis | Alasan | Lokal | Server UNDIP |
|---|---|---|---|---|
| `users.reset_token TEXT` dan `users.token_expiry TIMESTAMPTZ` (boleh kosong) | Struktur otomatis | Dipakai `save_reset_token`, `verify_reset_token`, dan `reset_user_password`, tapi tidak pernah dibuat. Akibatnya fitur Lupa Password gagal untuk akun yang hanya ada di PostgreSQL. | Belum | Belum |
| ~~`scan_history.schedule_id INTEGER`~~ | Digantikan | Tidak jadi menambah kolom. Diganti penanda `schedule_id` di dalam `raw_json` (lihat 2026-11-14 di bawah). | - | - |

## 2026-11-15

| Perubahan | Jenis | Detail | Lokal | Server UNDIP |
|---|---|---|---|---|
| Tabel baru `notification_reads` | Struktur otomatis (atas izin) | Status baca notifikasi per akun, supaya sama di semua perangkat (sebelumnya disimpan di localStorage per browser). Kolom: `user_id UUID` (FK ke `users.id`, ikut terhapus bila akun dihapus), `notif_key TEXT` berisi id notifikasi seperti di dashboard: `156` (scan selesai, = `scan_history.id`), `sys_18` (= `system_notifications.id` 18), `pending_dom_5` (permintaan domain), maks. 100 karakter. `read_at TIMESTAMPTZ`. Primary key `(user_id, notif_key)`, index `idx_notification_reads_read_at`. Dibuat oleh `ensure_database_schema()`. Baris lebih tua dari 90 hari dihapus sekali sehari oleh `automated_midnight_scan_worker` (`prune_notification_reads()`). Status baca lama dari localStorage tiap browser dikirim sekali ke akun yang pertama login di browser itu. Kolom lama `system_notifications.is_read` (berlaku untuk semua akun) tidak dipakai lagi untuk lonceng, tetapi tidak dihapus. Tidak mengubah tabel lain. | Sudah (dibuat manual dengan SQL yang sama, 0 baris) | Dibuat otomatis saat restart setelah `git pull` |
| `scan_result.cvss_v3` dan `scan_result.cisa_kev` mulai terisi | Format data (tanpa kolom baru) | `extract_finding_classification()` di `db_manager.py` membaca nama field API yang benar: `cvssv3` dan `in_cisa_catalog` (sebelumnya membaca `cvss_v3`/`cisa_kev`, yang tidak ada di output API, sehingga 674 baris lokal semuanya NULL). Dicek terhadap output asli scan 44932511. Hanya berlaku untuk scan **baru**; baris lama tetap NULL dan tidak diubah. | Kode siap, aktif setelah restart | Ikut saat deploy |
| Penanda `-1` tidak lagi disimpan di `scan_result.cve` | Format data (tanpa kolom baru) | Pentest-Tools mengirim `cve: ["-1"]` untuk temuan tanpa CVE. Nilai itu sekarang dibuang sebelum disimpan (jadi `{}`). Baris lama berisi `{-1}` (16 baris lokal) tidak diubah. | Kode siap, aktif setelah restart | Ikut saat deploy |
| Hasil scan deep `aroomi.undip.id` dimasukkan manual | Data manual (atas izin) | Scan Pentest-Tools 46211401 selesai 15 Nov 16.12 WIB, tetapi pemantaunya mati saat server lokal di-restart, sehingga hasilnya tidak tersimpan. Dimasukkan lewat `save_pentest_tools_result()` dari output asli API: `scan_history.id` 156 (HIGH, skor 3,1) dan 12 baris `scan_result`. Ditambah 1 baris `system_notifications` (id 18, "Web Scan Selesai: aroomi.undip.id") lewat `add_system_notification()`. Tidak ada baris lain yang diubah. | Sudah | Tidak perlu (data lokal) |

## 2026-11-14

| Perubahan | Jenis | Detail | Lokal | Server UNDIP |
|---|---|---|---|---|
| Nilai baru `INFO` di `scan_history.risk_level` | Format data (tanpa kolom baru) | Scan yang hanya berisi temuan Info sekarang disimpan `INFO`, sebelumnya `LOW` (`scanner/risk_calculator.py`). Kolom `VARCHAR(50)` tanpa constraint, jadi tidak perlu ubah struktur. Baris lama tetap `LOW` di database dan dikoreksi saat dibaca oleh `normalize_info_risk()` di `get_scan_history_list`. Catatan: `last_scan_status` di daftar domain dan query `WHERE risk_level IN ('HIGH','CRITICAL')` tidak terpengaruh. | Kode siap, aktif setelah restart | Ikut saat deploy |
| Penanda jadwal di `scan_history.raw_json` | Format data (tanpa kolom baru) | Scan baru menyimpan `schedule_id` dan `is_scheduled: true` (dari jadwal Automated) atau `is_scheduled: false` (manual / Overnight) di objek `raw_json` yang sudah ada. Baris lama tidak diubah dan dicocokkan ke jadwal lewat waktu scan. Hanya berlaku untuk scan yang disimpan setelah server di-restart dengan kode baru. | Kode siap, aktif setelah restart | Ikut saat deploy |
| Low/Info dari `raw_json` objek ikut dibaca | Kode (tanpa perubahan tabel) | `get_scan_history_list` sekarang menambahkan `raw_json.low_info_vulns` ke daftar temuan. Sebelumnya terlewat untuk semua scan yang punya `pt_scan_id` (di lokal: 184 temuan Low/Info dari 87 scan). Data tidak diubah, hanya cara membacanya. | Kode siap, aktif setelah restart | Ikut saat deploy |
| Nama domain dibersihkan (tanpa `www.`, huruf kecil) | Data manual | `database/migrations/2026-11-14_001_normalize_domain_names.sql`. Di lokal mengubah 1 baris: id 1 `www.lib.pdsmk.fk.undip.ac.id` menjadi `lib.pdsmk.fk.undip.ac.id`. | Sudah | Belum |
| Pencarian domain juga mengecek versi `www.` | Kode (tanpa perubahan tabel) | `get_domain_by_name` dan `save_pentest_tools_result` mencari `x` atau `www.x`, supaya server yang belum menjalankan migrasi di atas tidak membuat domain duplikat. Boleh dihapus setelah migrasi berjalan di semua database. | Sudah | Ikut saat deploy |
| Normalisasi nama domain saat simpan | Kode (tanpa perubahan tabel) | `normalize_domain_name()` dipakai saat tambah, edit, scrapper, dan trigger scan. | Sudah | Ikut saat deploy |

## Sebelum catatan ini dibuat

Diambil dari riwayat git file `db_manager.py`. Semuanya **struktur otomatis**.

| Tanggal (commit) | Perubahan |
|---|---|
| 2026-09-01 (92cd66d) | Tabel `system_settings` (key, value, updated_at, updated_by). Kolom `users.session_created_at`. |
| 2026-08-24 (4a3470e) | Kolom `scheduled_scans.window_end_at` (Jam B untuk scan berulang dalam rentang waktu). |
| 2026-08-24 (4c63c0d) | Constraint `users_role_check`: role hanya `superadmin`, `admin`, `user`. |
| 2026-08-24 (fff6c52) | Kolom `users.created_by`. |
| 2026-08-21 (3c9d50f) | Tabel `scheduled_scans`. |
| 2026-08-18 (ffb60b6) | Kolom `domains.approval_status` dan `domains.requested_by`. Tabel `system_notifications`. |
| Awal | Tabel `domains`, `scan_history`, `scan_result`, `users` (lihat `schema_pentest_dashboard.sql`, file ini sudah tidak lengkap). |
