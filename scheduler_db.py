import psycopg2
from datetime import datetime, timedelta, timezone
import config

class SchedulerDB:
    def __init__(self):
        self.init_db()

    def get_connection(self):
        # Jika user memasukkan URL Supabase, gunakan itu
        if config.SUPABASE_DB_URL and config.SUPABASE_DB_URL.strip() != "":
            return psycopg2.connect(config.SUPABASE_DB_URL)
        else:
            return psycopg2.connect(
                host=config.PG_HOST,
                port=config.PG_PORT,
                user=config.PG_USER,
                password=config.PG_PASSWORD,
                dbname=config.PG_DATABASE
            )

    def init_db(self):
        """Membuat tabel scan_schedules jika belum ada."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    id SERIAL PRIMARY KEY,
                    domain_name TEXT UNIQUE NOT NULL,
                    interval_days INTEGER DEFAULT 7,
                    last_scan_time TEXT,
                    next_scan_time TEXT NOT NULL,
                    scan_status TEXT DEFAULT 'Idle',
                    current_scan_id INTEGER,
                    error_log TEXT
                )
            """)
            conn.commit()

    def register_domains(self, domains, interval_days=7):
        """Mendaftarkan domain baru dari aset_aktif ke database scheduler."""
        now = datetime.now(timezone.utc)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for domain in domains:
                # Masukkan domain baru, abaikan jika sudah terdaftar
                cursor.execute("""
                    INSERT INTO scan_schedules 
                    (domain_name, interval_days, next_scan_time)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (domain_name) DO NOTHING
                """, (domain, interval_days, now.isoformat()))
            conn.commit()

    def get_due_domains(self):
        """Mengambil daftar domain yang jadwal scannya sudah jatuh tempo (due)."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT domain_name, interval_days, current_scan_id FROM scan_schedules
                WHERE next_scan_time <= %s AND scan_status != 'Running'
            """, (now,))
            return cursor.fetchall()

    def update_scan_start(self, domain_name, scan_id):
        """Mencatat bahwa scan di Pentest-Tools API telah dimulai."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scan_schedules
                SET scan_status = 'Running', current_scan_id = %s, error_log = NULL
                WHERE domain_name = %s
            """, (scan_id, domain_name))
            conn.commit()

    def update_scan_success(self, domain_name, interval_days):
        """Mencatat bahwa scan sukses dan menghitung jadwal scan berikutnya."""
        now = datetime.now(timezone.utc)
        next_scan = now + timedelta(days=interval_days)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scan_schedules
                SET scan_status = 'Idle', 
                    last_scan_time = %s, 
                    next_scan_time = %s, 
                    current_scan_id = NULL
                WHERE domain_name = %s
            """, (now.isoformat(), next_scan.isoformat(), domain_name))
            conn.commit()

    def update_scan_failed(self, domain_name, error_msg):
        """Mencatat kegagalan scan untuk ditinjau oleh administrator."""
        # Jadwal di-delay 1 hari untuk retry otomatis
        retry_time = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scan_schedules
                SET scan_status = 'Failed', 
                    next_scan_time = %s, 
                    error_log = %s
                WHERE domain_name = %s
            """, (retry_time, error_msg, domain_name))
            conn.commit()
