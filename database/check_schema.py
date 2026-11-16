"""Cetak struktur database PostgreSQL yang sedang dipakai (READ-ONLY, tidak mengubah apa pun).

Dipakai untuk membandingkan database lokal dengan database di server UNDIP:
    python database/check_schema.py              # tampilkan di terminal
    python database/check_schema.py > skema.md   # simpan lalu bandingkan (mis. dengan diff)

Koneksi memakai pengaturan yang sama dengan aplikasi (file .env: PG_HOST, PG_PORT, PG_USER, PG_PASSWORD, PG_DATABASE).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(ROOT, '.env'))
import db_manager  # noqa: E402

# Kolom yang dibutuhkan kode aplikasi (lihat database/CHANGELOG.md). Dipakai untuk menandai kolom yang hilang.
EXPECTED = {
    'domains': ['id', 'domain_name', 'ip_address', 'discovered_at', 'is_active', 'approval_status', 'requested_by'],
    'scan_history': ['id', 'domain_id', 'scan_date', 'risk_score', 'risk_level', 'raw_json'],
    'scan_result': ['id', 'history_id', 'severity', 'check_type', 'title', 'description', 'recommendation',
                    'epss_score', 'epss_percentile', 'cisa_kev', 'cve', 'cvss_v3', 'cwe', 'evidence'],
    'users': ['id', 'username', 'password', 'role', 'is_online', 'last_online', 'timeout_until', 'session_id',
              'session_created_at', 'created_at', 'created_by', 'reset_token', 'token_expiry'],
    'system_notifications': ['id', 'title', 'message', 'notif_type', 'target_user', 'created_at', 'is_read'],
    'scheduled_scans': ['id', 'scan_category', 'scan_type', 'targets', 'scheduled_at', 'window_end_at', 'frequency',
                        'status', 'created_by', 'created_at', 'last_run_at'],
    'system_settings': None,  # isi kolom tidak dicek
    'notification_reads': ['user_id', 'notif_key', 'read_at'],
}


def main():
    conn = db_manager.get_db_connection()
    if not conn:
        print('Gagal terhubung ke database. Periksa .env')
        sys.exit(1)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT table_name, column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema = 'public'
                ORDER BY table_name, ordinal_position
            """)
            rows = cur.fetchall()
            cur.execute("SELECT current_database(), inet_server_addr()::text, version()")
            dbname, host, version = cur.fetchone()
    finally:
        conn.close()

    tables = {}
    for table, col, dtype, nullable, default in rows:
        tables.setdefault(table, []).append((col, dtype, nullable, default))

    print(f'# Skema database `{dbname}` ({host or "socket lokal"})\n')
    print(f'PostgreSQL: {version.split(",")[0]}\n')
    missing_total = 0
    for table in sorted(set(tables) | set(EXPECTED)):
        cols = tables.get(table)
        print(f'## {table}')
        if not cols:
            print('\n**TABEL TIDAK ADA** (akan dibuat otomatis saat aplikasi start, kecuali tabel ini tidak dikelola kode)\n')
            missing_total += 1
            continue
        print('\n| Kolom | Tipe | Null | Default |\n|---|---|---|---|')
        for col, dtype, nullable, default in cols:
            print(f'| {col} | {dtype} | {nullable} | {default or ""} |')
        expected = EXPECTED.get(table)
        if expected:
            have = {c[0] for c in cols}
            missing = [c for c in expected if c not in have]
            if missing:
                missing_total += len(missing)
                print(f'\n**Kolom yang dibutuhkan kode tapi belum ada:** {", ".join(missing)}')
        print()
    print(f'Ringkasan: {missing_total} tabel/kolom yang dibutuhkan kode belum ada.' if missing_total
          else 'Ringkasan: semua tabel dan kolom yang dibutuhkan kode sudah ada.')


if __name__ == '__main__':
    main()
