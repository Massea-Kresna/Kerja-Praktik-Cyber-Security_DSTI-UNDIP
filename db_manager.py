import config
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor

LOCAL_USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users_db.json')

def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=config.PG_HOST,
            port=config.PG_PORT,
            user=config.PG_USER,
            password=config.PG_PASSWORD,
            dbname=config.PG_DATABASE,
            connect_timeout=5
        )
        return conn
    except Exception as e:
        print(f'[!] Warning: Gagal menginisialisasi PostgreSQL. Detail: {e}')
        return None

def ensure_domain_approval_columns():
    conn = get_db_connection()
    if not conn: return
    try:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE public.domains ADD COLUMN IF NOT EXISTS approval_status VARCHAR(50) DEFAULT 'approved'")
            cur.execute("ALTER TABLE public.domains ADD COLUMN IF NOT EXISTS requested_by TEXT")
            cur.execute("UPDATE public.domains SET approval_status = 'approved' WHERE approval_status IS NULL")
            try:
                cur.execute("SELECT setval('domains_id_seq', COALESCE((SELECT MAX(id) FROM domains), 1))")
            except Exception:
                pass

            # Ensure users table role constraint allows superadmin
            try:
                cur.execute("ALTER TABLE public.users DROP CONSTRAINT IF EXISTS users_role_check")
                cur.execute("ALTER TABLE public.users ADD CONSTRAINT users_role_check CHECK (role IN ('superadmin', 'admin', 'user'))")
            except Exception:
                pass

            conn.commit()
    except Exception as e:
        if conn: conn.rollback()
    finally:
        conn.close()

def ensure_database_schema():
    conn = get_db_connection()
    if not conn: return
    try:
        with conn.cursor() as cur:
            # 1. UUID Extension
            try:
                cur.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";')
            except Exception:
                pass

            # 2. Table: domains
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.domains (
                    id SERIAL PRIMARY KEY,
                    domain_name VARCHAR(255) NOT NULL UNIQUE,
                    ip_address VARCHAR(45),
                    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT true,
                    approval_status VARCHAR(50) DEFAULT 'approved',
                    requested_by TEXT
                )
            """)
            cur.execute("ALTER TABLE public.domains ADD COLUMN IF NOT EXISTS approval_status VARCHAR(50) DEFAULT 'approved'")
            cur.execute("ALTER TABLE public.domains ADD COLUMN IF NOT EXISTS requested_by TEXT")
            cur.execute("UPDATE public.domains SET approval_status = 'approved' WHERE approval_status IS NULL")

            # 3. Table: scan_history
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.scan_history (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES public.domains(id) ON DELETE CASCADE,
                    scan_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    risk_score DOUBLE PRECISION DEFAULT 0.0,
                    risk_level VARCHAR(50) DEFAULT 'SAFE',
                    raw_json JSONB
                )
            """)

            # 4. Table: scan_result
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.scan_result (
                    id SERIAL PRIMARY KEY,
                    history_id INTEGER NOT NULL REFERENCES public.scan_history(id) ON DELETE CASCADE,
                    severity VARCHAR(20) NOT NULL,
                    check_type VARCHAR(100),
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    recommendation TEXT,
                    epss_score DOUBLE PRECISION,
                    epss_percentile DOUBLE PRECISION,
                    cisa_kev BOOLEAN DEFAULT false,
                    cve VARCHAR(100),
                    cvss_v3 VARCHAR(50),
                    cwe VARCHAR(255),
                    evidence TEXT
                )
            """)

            # 5. Table: users
            try:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS public.users (
                        id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        role TEXT NOT NULL CHECK (role IN ('superadmin', 'admin', 'user')),
                        is_online BOOLEAN DEFAULT false,
                        last_online TIMESTAMP WITH TIME ZONE,
                        timeout_until TIMESTAMP WITH TIME ZONE,
                        session_id TEXT,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        created_by TEXT
                    )
                """)
            except Exception:
                pass

            cur.execute("ALTER TABLE public.users ADD COLUMN IF NOT EXISTS created_by TEXT")
            cur.execute("ALTER TABLE public.users ADD COLUMN IF NOT EXISTS is_online BOOLEAN DEFAULT false")
            cur.execute("ALTER TABLE public.users ADD COLUMN IF NOT EXISTS last_online TIMESTAMPTZ")
            cur.execute("ALTER TABLE public.users ADD COLUMN IF NOT EXISTS timeout_until TIMESTAMPTZ")
            cur.execute("ALTER TABLE public.users ADD COLUMN IF NOT EXISTS session_id TEXT")

            # 6. Table: system_notifications
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.system_notifications (
                    id SERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    notif_type VARCHAR(50) DEFAULT 'info',
                    target_user TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    is_read BOOLEAN DEFAULT false
                )
            """)

            # 7. Table: scheduled_scans
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.scheduled_scans (
                    id SERIAL PRIMARY KEY,
                    scan_category VARCHAR(50) NOT NULL,
                    scan_type VARCHAR(50) NOT NULL DEFAULT 'deep',
                    targets JSONB NOT NULL,
                    scheduled_at TIMESTAMPTZ NOT NULL,
                    window_end_at TIMESTAMPTZ,
                    frequency VARCHAR(50) NOT NULL DEFAULT 'once',
                    status VARCHAR(50) NOT NULL DEFAULT 'pending',
                    created_by VARCHAR(100),
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    last_run_at TIMESTAMPTZ
                )
            """)
            cur.execute("ALTER TABLE public.scheduled_scans ADD COLUMN IF NOT EXISTS window_end_at TIMESTAMPTZ")
            
            # Sequence setvals for smooth auto-increment
            sequences = [
                ('domains_id_seq', 'domains'),
                ('scan_history_id_seq', 'scan_history'),
                ('scan_result_id_seq', 'scan_result'),
                ('system_notifications_id_seq', 'system_notifications'),
                ('scheduled_scans_id_seq', 'scheduled_scans')
            ]
            for seq_name, table_name in sequences:
                try:
                    cur.execute(f"SELECT setval('public.{seq_name}', COALESCE((SELECT MAX(id) FROM public.{table_name}), 1))")
                except Exception:
                    pass

            conn.commit()
    except Exception as e:
        if conn: conn.rollback()
        print(f"[-] Error ensure_database_schema: {e}")
    finally:
        conn.close()
    
    ensure_scheduled_scans_table()

def check_db_connection():
    conn = get_db_connection()
    if conn:
        conn.close()
        ensure_database_schema()
        return True
    return False

def save_reset_token(email: str, token: str):
    expiry = datetime.now(timezone.utc) + timedelta(minutes=15)
    saved_to_db = False
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET reset_token = %s, token_expiry = %s WHERE username = %s", (token, expiry, email))
                conn.commit()
                saved_to_db = True
        except Exception as e:
            conn.rollback()
        finally:
            conn.close()
            
    users = _read_local_users()
    for u in users:
        if u['username'] == email:
            u['reset_token'] = token
            u['token_expiry'] = expiry.isoformat()
            _write_local_users(users)
            return True
    return saved_to_db

def verify_reset_token(token: str):
    now = datetime.now(timezone.utc)
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT username, token_expiry FROM users WHERE reset_token = %s", (token,))
                res = cur.fetchone()
                if res:
                    exp = res['token_expiry']
                    if exp:
                        if exp.tzinfo is None:
                            exp = exp.replace(tzinfo=timezone.utc)
                        if exp > now:
                            return {"username": res['username']}
        except Exception as e:
            pass
        finally:
            conn.close()
            
    users = _read_local_users()
    for u in users:
        if u.get('reset_token') == token:
            try:
                exp_time = datetime.fromisoformat(u['token_expiry'])
                if exp_time.tzinfo is None: exp_time = exp_time.replace(tzinfo=timezone.utc)
                if exp_time > now: return {"username": u['username']}
            except Exception: pass
    return None

def reset_user_password(username: str, new_hashed_password: str):
    saved_to_db = False
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET password = %s, reset_token = NULL, token_expiry = NULL WHERE username = %s", (new_hashed_password, username))
                conn.commit()
                saved_to_db = True
        except Exception as e:
            conn.rollback()
        finally:
            conn.close()
            
    users = _read_local_users()
    for u in users:
        if u['username'] == username:
            u['password'] = new_hashed_password
            u['reset_token'] = None
            u['token_expiry'] = None
            _write_local_users(users)
            return True
    return saved_to_db

# ==============================================================================
# AUTH & USER MANAGEMENT (SUDAH DIKUNCI ANTI-GHOST USER)
# ==============================================================================

def hash_password(password: str, salt: str = None) -> str:
    if not salt: salt = uuid.uuid4().hex
    hashed = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return f'{salt}${hashed}'

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        if not stored_hash or '$' not in stored_hash: return False
        salt, hashed = stored_hash.split('$', 1)
        return hash_password(password, salt) == stored_hash
    except Exception: return False

def _read_local_users():
    if not os.path.exists(LOCAL_USERS_FILE): return []
    try:
        with open(LOCAL_USERS_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except Exception: return []

def _write_local_users(users):
    try:
        with open(LOCAL_USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=4, default=str)
        return True
    except Exception: return False

def get_user_by_username(username: str):
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM users WHERE username = %s LIMIT 1', (username,))
                res = cur.fetchone()
                return dict(res) if res else None # Tidak ada lagi fallback JSON jika DB jalan!
        except Exception as e:
            print(f'[-] Postgres get_user error: {e}')
            return None
        finally:
            conn.close()
            
    users = _read_local_users()
    for u in users:
        if u['username'] == username: return u
    return None

def create_user(username: str, password_plain: str, role: str, created_by: str = None):
    hashed_pw = hash_password(password_plain)
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT id FROM users WHERE username = %s', (username,))
                if cur.fetchone(): raise Exception('Username sudah digunakan')
                    
                cur.execute(
                    'INSERT INTO users (username, password, role, is_online, created_by) VALUES (%s, %s, %s, %s, %s) RETURNING *',
                    (username, hashed_pw, role, False, created_by)
                )
                res = cur.fetchone()
                conn.commit()
                if res: return dict(res)
        except Exception as e:
            if conn: conn.rollback()
            raise e
        finally:
            conn.close()

    users = _read_local_users()
    for u in users:
        if u['username'] == username: raise Exception('Username sudah digunakan')
            
    new_user = {
        'username': username, 'password': hashed_pw, 'role': role, 'is_online': False,
        'last_online': None, 'timeout_until': None, 'session_id': None,
        'created_at': datetime.now(timezone.utc).isoformat(), 'created_by': created_by
    }
    users.append(new_user)
    _write_local_users(users)
    return new_user

def update_user_session(username: str, session_id: str or None, is_online: bool):
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if is_online:
                    cur.execute('UPDATE users SET session_id = %s, is_online = %s, last_online = %s WHERE username = %s RETURNING *', (session_id, is_online, now_iso, username))
                else:
                    cur.execute('UPDATE users SET session_id = %s, is_online = %s WHERE username = %s RETURNING *', (session_id, is_online, username))
                res = cur.fetchone()
                conn.commit()
                return dict(res) if res else None
        except Exception as e:
            if conn: conn.rollback()
            return None
        finally:
            conn.close()
            
    users = _read_local_users()
    for u in users:
        if u['username'] == username:
            u['session_id'] = session_id
            u['is_online'] = is_online
            if is_online: u['last_online'] = now_iso
            _write_local_users(users)
            return u
    return None

def update_user_online_status(username: str, is_online: bool):
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if is_online:
                    cur.execute('UPDATE users SET is_online = %s, last_online = %s WHERE username = %s RETURNING *', (is_online, now_iso, username))
                else:
                    cur.execute('UPDATE users SET is_online = %s WHERE username = %s RETURNING *', (is_online, username))
                res = cur.fetchone()
                conn.commit()
                return dict(res) if res else None
        except Exception as e:
            if conn: conn.rollback()
            return None
        finally:
            conn.close()
            
    users = _read_local_users()
    for u in users:
        if u['username'] == username:
            u['is_online'] = is_online
            if is_online: u['last_online'] = now_iso
            _write_local_users(users)
            return u
    return None

def update_user_timeout(username: str, timeout_until: str or None):
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('UPDATE users SET timeout_until = %s, session_id = NULL, is_online = FALSE WHERE username = %s RETURNING *', (timeout_until, username))
                res = cur.fetchone()
                conn.commit()
                return dict(res) if res else None
        except Exception as e:
            if conn: conn.rollback()
            return None
        finally:
            conn.close()
            
    users = _read_local_users()
    for u in users:
        if u['username'] == username:
            u['timeout_until'] = timeout_until
            u['session_id'] = None
            u['is_online'] = False
            _write_local_users(users)
            return u
    return None

def list_all_users():
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT id, username, role, is_online, last_online, timeout_until, created_at, created_by FROM users ORDER BY username ASC')
                res = cur.fetchall()
                return [dict(row) for row in res] if res else []
        except Exception as e:
            print(f'[-] Postgres list_all_users error: {e}')
            return []
        finally:
            conn.close()
            
    users = _read_local_users()
    filtered = []
    for u in users:
        filtered.append({
            'username': u['username'], 'role': u['role'], 'is_online': u['is_online'],
            'last_online': u.get('last_online'), 'timeout_until': u.get('timeout_until'),
            'created_at': u.get('created_at'), 'created_by': u.get('created_by')
        })
    return sorted(filtered, key=lambda x: x['username'])

def delete_user(username: str) -> bool:
    is_deleted = False
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM users WHERE username = %s RETURNING id', (username,))
                res = cur.fetchone()
                conn.commit()
                if res: is_deleted = True
        except Exception as e:
            if conn: conn.rollback()
        finally:
            conn.close()
            
    # Sikat tuntas dari JSON lokal agar tidak ada celah login
    users = _read_local_users()
    filtered_users = [u for u in users if u['username'] != username]
    if len(users) != len(filtered_users):
        _write_local_users(filtered_users)
        is_deleted = True
        
    return is_deleted

def get_user_by_session_id(session_id: str):
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM users WHERE session_id = %s LIMIT 1', (session_id,))
                res = cur.fetchone()
                return dict(res) if res else None
        except Exception as e:
            return None
        finally:
            conn.close()
            
    users = _read_local_users()
    for u in users:
        if u.get('session_id') == session_id: return u
    return None

def seed_default_admin():
    import config
    admin_username = config.ADMIN_EMAIL if config.ADMIN_EMAIL else 'admin'
    try:
        admin_user = get_user_by_username(admin_username)
        if not admin_user:
            create_user(admin_username, 'admin123', 'superadmin')
            print(f'[+] Seeding Sukses: User default {admin_username} dengan password admin123 telah ditambahkan.')
    except Exception as e:
        pass

# ==============================================================================
# SCAN SAVING METHODS
# ==============================================================================

def upsert_domain(domain_name, ip_address):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                INSERT INTO domains (domain_name, ip_address, is_active)
                VALUES (%s, %s, %s)
                ON CONFLICT (domain_name) 
                DO UPDATE SET ip_address = EXCLUDED.ip_address
                RETURNING id
            """, (domain_name, ip_address, False))
            res = cur.fetchone()
            conn.commit()
            return res['id'] if res else None
    except Exception as e:
# --- [Bagian penutup try-except yang terpotong dari kode di atasnya] ---
        # 1. Penutup dari fungsi upsert_domain (dari Patch-17)
        print(f'[-] Error upsert_domain: {e}')
        if conn: conn.rollback()
        return None
    finally:
        conn.close()

        # 2. Penutup dari fungsi seeding admin (dari main)
        # Catatan: Pastikan indentasi sebaris ini sejajar dengan blok except-mu di atasnya
        # print(f"[-] Gagal melakukan seeding admin: {e}")

# ==============================================================================
# FUNGSI DATABASE POSTGRESQL (DARI PATCH-17)
# ==============================================================================

def create_scan_history(domain_id, risk_score, risk_level, raw_json=None, scan_date=None):
    if not scan_date:
        scan_date = datetime.now(timezone(timedelta(hours=7))).isoformat()
    
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            raw_json_str = json.dumps(raw_json) if raw_json else None
            cur.execute("""
                INSERT INTO scan_history (domain_id, risk_score, risk_level, scan_date, raw_json)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (domain_id, risk_score, risk_level, scan_date, raw_json_str))
            res = cur.fetchone()
            conn.commit()
            return res['id'] if res else None
    except Exception as e:
        print(f'[-] Error create_scan_history: {e}')
        if conn: conn.rollback()
        return None
    finally:
        conn.close()

def insert_open_ports(history_id, open_ports):
    if not open_ports: return
    conn = get_db_connection()
    if not conn: return
    try:
        with conn.cursor() as cur:
            data = [(history_id, p['port'], p['service']) for p in open_ports]
            cur.executemany(
                'INSERT INTO open_ports (history_id, port_number, service_name) VALUES (%s, %s, %s)',
                data
            )
            conn.commit()
    except Exception as e:
        print(f'[-] Error insert_open_ports: {e}')
        if conn: conn.rollback()
    finally:
        conn.close()

def insert_technologies(history_id, tech_data):
    if not tech_data: return
    conn = get_db_connection()
    if not conn: return
    try:
        with conn.cursor() as cur:
            web_server = tech_data.get('web_server', 'Unknown')
            cms = tech_data.get('cms', 'Unknown')
            cur.execute(
                'INSERT INTO technologies (history_id, web_server, cms) VALUES (%s, %s, %s)',
                (history_id, web_server, cms)
            )
            conn.commit()
    except Exception as e:
        print(f'[-] Error insert_technologies: {e}')
        if conn: conn.rollback()
    finally:
        conn.close()

def insert_scan_result(history_id, scan_result):
    if not scan_result: return
    conn = get_db_connection()
    if not conn: return
    try:
        with conn.cursor() as cur:
            data = [(
                history_id,
                v.get('severity', 'LOW'),
                v.get('check', 'UNKNOWN'),
                v.get('title', ''),
                v.get('detail', ''),
                v.get('recommendation', ''),
                v.get('epss_score'),
                v.get('epss_percentile'),
                v.get('cisa_kev'),
                v.get('cve'),
                v.get('cvss_v3'),
                v.get('cwe'),
                v.get('evidence')
            ) for v in scan_result]
            cur.executemany(
                'INSERT INTO scan_result (history_id, severity, check_type, title, description, recommendation, epss_score, epss_percentile, cisa_kev, cve, cvss_v3, cwe, evidence) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                data
            )
            conn.commit()
    except Exception as e:
        print(f'[-] Error insert_scan_result: {e}')
        if conn: conn.rollback()
    finally:
        conn.close()

def save_all_results(domain_list, port_results, tech_results, vuln_results):
    print(f"\n{'-'*60}")
    print('  MENYIMPAN HASIL KE POSTGRESQL (LOKAL)')
    print(f"{'-'*60}")
    
    if not check_db_connection():
        print('[-] SKIP DATABASE: Gagal terhubung ke PostgreSQL.')
        return False
        
    try:
        port_map = {r['domain_name']: r.get('open_ports', []) for r in port_results}
        tech_map = {r['domain_name']: r.get('technologies', {}) for r in tech_results}
        vuln_map = {r['domain_name']: r for r in vuln_results}
        
        saved_count = 0
        for domain_info in domain_list:
            domain_name = domain_info['domain_name']
            ip_address = domain_info.get('ip_address', '')
            
            domain_id = upsert_domain(domain_name, ip_address)
            if not domain_id: continue
            
            v_data = vuln_map.get(domain_name, {})
            risk_score = v_data.get('risk_score', 0.0)
            risk_level = v_data.get('risk_level', 'SAFE')
            vulns_list = v_data.get('scan_result', [])
            
            low_info_vulns = []
            for v in vulns_list:
                if v.get('severity', '').upper() not in ['MEDIUM', 'HIGH', 'CRITICAL']:
                    low_info_vulns.append({
                        'severity': v.get('severity', 'LOW'),
                        'check_type': v.get('check', 'UNKNOWN'),
                        'title': v.get('title', ''),
                        'description': v.get('detail', ''),
                        'recommendation': v.get('recommendation', '')
                    })
            
            raw_v_data = low_info_vulns if low_info_vulns else None
            history_id = create_scan_history(domain_id, risk_score, risk_level, raw_v_data)
            if not history_id: continue
            
            insert_open_ports(history_id, port_map.get(domain_name, []))
            insert_technologies(history_id, tech_map.get(domain_name, {}))
            
            filtered_vulns = [v for v in vulns_list if v.get('severity', '').upper() in ['MEDIUM', 'HIGH', 'CRITICAL']]
            insert_scan_result(history_id, filtered_vulns)
            
            saved_count += 1
            
        print(f'[+] Sukses: {saved_count} domain berhasil dimasukkan ke Postgres!')
        return True
    except Exception as e:
        print(f'[-] ERROR saat menyimpan ke Postgres: {e}')
        return False

def save_pentest_tools_result(domain_name, report_json, scanner_type='Web Scanner', pt_scan_id=None, scan_date=None):
    print(f'[*] Parse & Save ke DB: {domain_name} ({scanner_type})')
    
    conn = get_db_connection()
    if not conn:
        print('  [!] Gagal menyimpan ke Postgres: Client tidak tersedia.')
        return None
        
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT id FROM domains WHERE domain_name = %s LIMIT 1', (domain_name,))
            res = cur.fetchone()
            if not res:
                print(f'  [-] Domain {domain_name} tidak ditemukan di tabel domains.')
                return None
            domain_id = res['id']
            
        findings = report_json.get('findings', [])
        if not findings and 'output_data' in report_json:
            findings = report_json.get('output_data', {}).get('findings', [])
        if not findings and 'data' in report_json:
            data_block = report_json.get('data', {})
            findings = data_block.get('findings', [])
            if not findings and 'output_data' in data_block:
                findings = data_block.get('output_data', {}).get('findings', [])
                
        risk_score = 0.0
        high_count = 0
        med_count = 0
        low_count = 0
        
        scan_result = []
        low_info_vulns = []
        for f in findings:
            severity = str(f.get('severity', '')).upper()
            if not severity and 'risk_level' in f:
                risk_mapping = {0: 'INFO', 1: 'LOW', 2: 'MEDIUM', 3: 'HIGH', 4: 'CRITICAL'}
                severity = risk_mapping.get(f.get('risk_level'), 'LOW')
            elif not severity:
                severity = 'LOW'
                
            title = f.get('title', f.get('name', 'Unknown Vulnerability'))
            desc = f.get('description', '')
            if not desc:
                desc = f.get('risk_description', '')
            if not desc:
                desc = f.get('output', '')
            if not desc:
                desc = f.get('details', '')
            recom = f.get('remediation', f.get('recommendation', ''))
            
            # Ekstraksi atribut klasifikasi baru
            epss_score = f.get('epss_score')
            epss_percentile = f.get('epss_percentile')
            cisa_kev = f.get('cisa_kev')
            
            cve_val = f.get('cve', '')
            if not cve_val:
                cves = f.get('cves', [])
                if isinstance(cves, list) and cves:
                    cve_val = ', '.join(str(c) for c in cves)
            
            cvss_v3 = f.get('cvss_v3')
            if not cvss_v3:
                cvss_v3 = f.get('cvss3_score')
            
            cwe_val = f.get('cwe', '')
            if not cwe_val:
                cwes = f.get('cwes', [])
                if isinstance(cwes, list) and cwes:
                    cwe_val = ', '.join(str(c) for c in cwes)
            
            # Ekstraksi Evidence (Simpan sebagai JSON agar UI baru dapat melakukan render komponen card)
            evidence_val = ''
            instances = f.get('instances', [])
            
            if isinstance(instances, list) and instances:
                evidence_val = json.dumps({"type": "instances", "data": instances})
            elif 'vuln_evidence' in f:
                evidence_val = json.dumps({"type": "vuln_evidence", "data": f['vuln_evidence']})
            else:
                req = f.get('request', f.get('http_request', f.get('raw_request', '')))
                res = f.get('response', f.get('http_response', f.get('raw_response', '')))
                if req or res:
                    evidence_val = json.dumps({"type": "instances", "data": [{"request": req, "response": res}]})
                else:
                    fallback_txt = f.get('output', '')
                    if not fallback_txt:
                        fallback_txt = f.get('details', '')
                    if not fallback_txt:
                        fallback_txt = f.get('proof', '')
                    
                    if fallback_txt:
                        evidence_val = json.dumps({"type": "text", "data": fallback_txt})
                    else:
                        evidence_val = ''
            
            vuln_obj = {
                'severity': severity,
                'check': scanner_type,
                'title': title,
                'detail': desc,
                'recommendation': recom,
                'epss_score': epss_score,
                'epss_percentile': epss_percentile,
                'cisa_kev': cisa_kev,
                'cve': cve_val,
                'cvss_v3': cvss_v3,
                'cwe': cwe_val,
                'evidence': evidence_val
            }
            
            # Masukkan SEMUA kerentanan (termasuk LOW dan INFO) ke dalam scan_result
            scan_result.append(vuln_obj)
            
            if severity in ['HIGH', 'CRITICAL']:
                risk_score += 3.0
                high_count += 1
            elif severity == 'MEDIUM':
                risk_score += 2.0
                med_count += 1
            elif severity == 'LOW' or severity == 'INFO':
                risk_score += 1.0
                low_count += 1
                
        if risk_score >= 10.0 or high_count > 0:
            risk_level = 'HIGH'
        elif risk_score >= 5.0 or med_count > 0:
            risk_level = 'MEDIUM'
        elif risk_score > 0.0 or low_count > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'SAFE'
            
        final_risk_score = min(risk_score, 10.0)
        
        raw_json_data = low_info_vulns if low_info_vulns else []
        if pt_scan_id:
            raw_json_data = {'low_info_vulns': raw_json_data, 'pt_scan_id': pt_scan_id}
        else:
            raw_json_data = low_info_vulns if low_info_vulns else None

        history_id = create_scan_history(domain_id, final_risk_score, risk_level, raw_json_data, scan_date=scan_date)
        if not history_id: return None
        
        if scan_result:
            insert_scan_result(history_id, scan_result)
            
        print(f'  [+] Tersimpan ke Postgres (Risk: {risk_level}, Temuan: {len(scan_result)})')
        return history_id
    except Exception as e:
        print(f'  [-] ERROR saat mem-parsing hasil Pentest-Tools ke Postgres: {e}')
        return None
    finally:
        if conn: conn.close()

# ==============================================================================
# WRAPPERS UNTUK WEB_APP.PY (PENGGANTI SUPABASE REST API)
# ==============================================================================

def get_all_domains():
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    d.id, 
                    d.domain_name, 
                    d.ip_address, 
                    d.is_active,
                    sh.scan_date AS last_scan_date,
                    sh.risk_level AS last_scan_status,
                    sh.risk_score AS last_risk_score,
                    sr.check_type AS last_scan_type
                FROM domains d
                LEFT JOIN LATERAL (
                    SELECT id, scan_date, risk_level, risk_score
                    FROM scan_history
                    WHERE domain_id = d.id
                    ORDER BY scan_date DESC, id DESC
                    LIMIT 1
                ) sh ON true
                LEFT JOIN LATERAL (
                    SELECT check_type
                    FROM scan_result
                    WHERE history_id = sh.id AND check_type IS NOT NULL
                    LIMIT 1
                ) sr ON true
                ORDER BY d.domain_name ASC
            """)
            res = cur.fetchall()
            return [dict(row) for row in res]
    except Exception as e:
        print(f'[-] Error get_all_domains: {e}')
        return []
    finally:
        conn.close()

def get_active_domains():
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT id, domain_name, ip_address FROM domains WHERE is_active = TRUE ORDER BY domain_name ASC')
            res = cur.fetchall()
            return [dict(row) for row in res]
    except Exception as e:
        print(f'[-] Error get_active_domains: {e}')
        return []
    finally:
        conn.close()

def get_domain_by_name(domain_name):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT * FROM domains WHERE domain_name = %s LIMIT 1', (domain_name,))
            res = cur.fetchone()
            return dict(res) if res else None
    except Exception as e:
        print(f'[-] Error get_domain_by_name: {e}')
        return None
    finally:
        conn.close()

def create_domain(domain_name, ip_address, approval_status='approved', requested_by=None):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            try:
                cur.execute("ALTER TABLE public.domains ADD COLUMN IF NOT EXISTS approval_status VARCHAR(50) DEFAULT 'approved'")
                cur.execute("ALTER TABLE public.domains ADD COLUMN IF NOT EXISTS requested_by TEXT")
                conn.commit()
            except Exception:
                if conn: conn.rollback()

            is_active_val = True if approval_status == 'approved' else False
            cur.execute(
                'INSERT INTO domains (domain_name, ip_address, is_active, approval_status, requested_by) VALUES (%s, %s, %s, %s, %s) RETURNING *',
                (domain_name, ip_address, is_active_val, approval_status, requested_by)
            )
            res = cur.fetchone()
            conn.commit()
            return dict(res) if res else None
    except Exception as e:
        print(f'[-] Error create_domain: {e}')
        if conn: conn.rollback()
        return None
    finally:
        conn.close()

def approve_domain(domain_id: int):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "UPDATE domains SET approval_status = 'approved', is_active = True WHERE id = %s RETURNING *",
                (domain_id,)
            )
            res = cur.fetchone()
            conn.commit()
            return dict(res) if res else None
    except Exception as e:
        print(f'[-] Error approve_domain: {e}')
        if conn: conn.rollback()
        return None
    finally:
        conn.close()

def reject_domain(domain_id: int):
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM domains WHERE id = %s RETURNING id", (domain_id,))
            res = cur.fetchone()
            conn.commit()
            return bool(res)
    except Exception as e:
        print(f'[-] Error reject_domain: {e}')
        if conn: conn.rollback()
        return False
    finally:
        conn.close()

def get_pending_domain_requests():
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id, domain_name, ip_address, requested_by, discovered_at FROM domains WHERE approval_status = 'pending' ORDER BY discovered_at DESC"
            )
            res = cur.fetchall()
            return [dict(r) for r in res]
    except Exception as e:
        print(f'[-] Error get_pending_domain_requests: {e}')
        return []
    finally:
        conn.close()

def update_domain(domain_id, domain_name, ip_address, is_active):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                'UPDATE domains SET domain_name = %s, ip_address = %s, is_active = %s WHERE id = %s RETURNING *',
                (domain_name, ip_address, is_active, domain_id)
            )
            res = cur.fetchone()
            conn.commit()
            return dict(res) if res else None
    except Exception as e:
        print(f'[-] Error update_domain: {e}')
        if conn: conn.rollback()
        return None
    finally:
        conn.close()

def delete_domain(domain_id):
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM domains WHERE id = %s RETURNING id', (domain_id,))
            res = cur.fetchone()
            conn.commit()
            return bool(res)
    except Exception as e:
        print(f'[-] Error delete_domain: {e}')
        if conn: conn.rollback()
        return False
    finally:
        conn.close()

def get_total_domains():
    conn = get_db_connection()
    if not conn: return 0
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(id) FROM domains')
            res = cur.fetchone()
            return res[0] if res else 0
    except: return 0
    finally: conn.close()

def get_total_vulnerabilities():
    conn = get_db_connection()
    if not conn: return 0
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(id) FROM scan_result')
            res = cur.fetchone()
            return res[0] if res else 0
    except: return 0
    finally: conn.close()

def get_recent_scans_history(limit=10):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT sh.id, sh.risk_score, sh.risk_level, sh.scan_date, d.domain_name 
                FROM scan_history sh
                LEFT JOIN domains d ON sh.domain_id = d.id
                ORDER BY sh.scan_date DESC
                LIMIT %s
            """, (limit,))
            res = cur.fetchall()
            result = []
            for row in res:
                row_dict = dict(row)
                row_dict['domains'] = {'domain_name': row_dict.pop('domain_name')}
                if isinstance(row_dict['scan_date'], datetime):
                    row_dict['scan_date'] = row_dict['scan_date'].isoformat()
                result.append(row_dict)
            return result
    except Exception as e:
        print(f'[-] Error get_recent_scans_history: {e}')
        return []
    finally:
        conn.close()

def get_recent_risk_levels(limit=100):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT risk_level FROM scan_history ORDER BY scan_date DESC LIMIT %s', (limit,))
            res = cur.fetchall()
            return [dict(row) for row in res]
    except Exception as e:
        print(f'[-] Error get_recent_risk_levels: {e}')
        return []
    finally:
        conn.close()

def get_trend_scans(start_time_iso, end_time_iso):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT sh.id, sh.scan_date, sh.raw_json, d.domain_name 
                FROM scan_history sh
                LEFT JOIN domains d ON sh.domain_id = d.id
                WHERE sh.scan_date >= %s AND sh.scan_date <= %s
                ORDER BY sh.scan_date ASC
            """, (start_time_iso, end_time_iso))
            h_res = cur.fetchall()
            
            if not h_res: return []
            
            h_ids = tuple([h['id'] for h in h_res])
            
            cur.execute("""
                SELECT id, history_id, severity FROM scan_result WHERE history_id IN %s
            """, (h_ids,))
            sr_res = cur.fetchall()
            
            sr_map = {}
            for sr in sr_res:
                hid = sr['history_id']
                if hid not in sr_map: sr_map[hid] = []
                sr_map[hid].append(dict(sr))
                
            result = []
            for h in h_res:
                row_dict = dict(h)
                row_dict['domains'] = {'domain_name': row_dict.pop('domain_name')}
                if isinstance(row_dict['scan_date'], datetime):
                    row_dict['scan_date'] = row_dict['scan_date'].isoformat()
                row_dict['scan_result'] = sr_map.get(row_dict['id'], [])
                
                if isinstance(row_dict.get('raw_json'), dict) or isinstance(row_dict.get('raw_json'), list):
                    pass
                elif isinstance(row_dict.get('raw_json'), str):
                    try:
                        row_dict['raw_json'] = json.loads(row_dict['raw_json'])
                    except:
                        pass
                
                result.append(row_dict)
            return result
    except Exception as e:
        print(f'[-] Error get_trend_scans: {e}')
        return []
    finally:
        conn.close()

def get_scan_history_for_domain(domain_id, limit=10):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, scan_date 
                FROM scan_history 
                WHERE domain_id = %s 
                ORDER BY scan_date DESC LIMIT %s
            """, (domain_id, limit))
            res = cur.fetchall()
            result = []
            for r in res:
                d = dict(r)
                if isinstance(d['scan_date'], datetime):
                    d['scan_date'] = d['scan_date'].isoformat()
                result.append(d)
            return result
    except Exception as e:
        print(f'[-] Error get_scan_history_for_domain: {e}')
        return []
    finally:
        conn.close()

def get_open_ports_for_history(history_id):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT port_number, service_name FROM open_ports WHERE history_id = %s', (history_id,))
            res = cur.fetchall()
            return [dict(r) for r in res]
    except Exception as e:
        print(f'[-] Error get_open_ports_for_history: {e}')
        return []
    finally:
        conn.close()

def get_technologies_for_history(history_id):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT web_server, cms FROM technologies WHERE history_id = %s', (history_id,))
            res = cur.fetchall()
            return [dict(r) for r in res]
    except Exception as e:
        print(f'[-] Error get_technologies_for_history: {e}')
        return []
    finally:
        conn.close()

def get_scan_results_for_history(history_id):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT severity, check_type, title, description, recommendation, epss_score, epss_percentile, cisa_kev, cve, cvss_v3, cwe, evidence FROM scan_result WHERE history_id = %s', (history_id,))
            res = cur.fetchall()
            return [dict(r) for r in res]
    except Exception as e:
        print(f'[-] Error get_scan_results_for_history: {e}')
        return []
    finally:
        conn.close()

def get_domain_scan_history_summary(domain_name):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT sh.id, sh.risk_score, sh.risk_level, sh.scan_date, sh.raw_json
                FROM scan_history sh
                JOIN domains d ON sh.domain_id = d.id
                WHERE d.domain_name = %s
                ORDER BY sh.scan_date DESC
                LIMIT 1
            """, (domain_name,))
            res = cur.fetchone()
            if not res: return []
            d = dict(res)
            if isinstance(d['scan_date'], datetime):
                d['scan_date'] = d['scan_date'].isoformat()
            
            if isinstance(d.get('raw_json'), str):
                try: d['raw_json'] = json.loads(d['raw_json'])
                except: pass

            return [d]
    except Exception as e:
        print(f'[-] Error get_domain_scan_history_summary: {e}')
        return []
    finally:
        conn.close()

def get_domains_list(search=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            query = """
                SELECT 
                    d.id, 
                    d.domain_name, 
                    d.ip_address, 
                    d.is_active,
                    COALESCE(d.approval_status, 'approved') AS approval_status,
                    d.requested_by,
                    sh.scan_date AS last_scan_date,
                    sh.risk_level AS last_scan_status,
                    sh.risk_score AS last_risk_score,
                    sr.check_type AS last_scan_type
                FROM domains d
                LEFT JOIN LATERAL (
                    SELECT id, scan_date, risk_level, risk_score
                    FROM scan_history
                    WHERE domain_id = d.id
                    ORDER BY scan_date DESC, id DESC
                    LIMIT 1
                ) sh ON true
                LEFT JOIN LATERAL (
                    SELECT check_type
                    FROM scan_result
                    WHERE history_id = sh.id AND check_type IS NOT NULL
                    LIMIT 1
                ) sr ON true
            """
            if search:
                query += " WHERE d.domain_name ILIKE %s ORDER BY d.domain_name ASC"
                cur.execute(query, (f'%{search}%',))
            else:
                query += " ORDER BY d.domain_name ASC"
                cur.execute(query)
            res = cur.fetchall()
            return [dict(row) for row in res]
    except Exception as e:
        print(f'[-] Error get_domains_list: {e}')
        ensure_domain_approval_columns()
        try:
            conn_fallback = get_db_connection()
            if conn_fallback:
                with conn_fallback.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("SELECT id, domain_name, ip_address, is_active, 'approved' AS approval_status, requested_by FROM domains ORDER BY domain_name ASC")
                    res = cur.fetchall()
                    conn_fallback.close()
                    return [dict(row) for row in res]
        except Exception as ex:
            print(f'[-] Error fallback get_domains_list: {ex}')
        return []
    finally:
        if conn: conn.close()

def get_domain_by_id(domain_id: int):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM domains WHERE id = %s LIMIT 1", (domain_id,))
            res = cur.fetchone()
            return dict(res) if res else None
    except Exception as e:
        print(f"[-] Error get_domain_by_id: {e}")
        return None
    finally:
        conn.close()

SYSTEM_NOTIFS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'notifications_db.json')

def _read_local_notifs():
    if not os.path.exists(SYSTEM_NOTIFS_FILE):
        return []
    try:
        with open(SYSTEM_NOTIFS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def _write_local_notifs(notifs):
    try:
        with open(SYSTEM_NOTIFS_FILE, 'w', encoding='utf-8') as f:
            json.dump(notifs, f, indent=4, default=str)
        return True
    except Exception:
        return False

def add_system_notification(title: str, message: str, notif_type: str = 'info', target_user: str = None):
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS public.system_notifications (
                        id SERIAL PRIMARY KEY,
                        title TEXT NOT NULL,
                        message TEXT NOT NULL,
                        notif_type VARCHAR(50) DEFAULT 'info',
                        target_user TEXT,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        is_read BOOLEAN DEFAULT false
                    )
                """)
                cur.execute(
                    "INSERT INTO system_notifications (title, message, notif_type, target_user) VALUES (%s, %s, %s, %s)",
                    (title, message, notif_type, target_user)
                )
                conn.commit()
        except Exception as e:
            print(f"[-] Error add_system_notification PG: {e}")
            if conn: conn.rollback()
        finally:
            conn.close()

    # Backup lokal JSON
    notifs = _read_local_notifs()
    new_n = {
        "id": f"notif_{uuid.uuid4().hex[:8]}",
        "title": title,
        "message": message,
        "type": notif_type,
        "target_user": target_user,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_read": False
    }
    notifs.insert(0, new_n)
    _write_local_notifs(notifs[:50])
    return new_n

def get_system_notifications(limit=20):
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id, title, message, notif_type as type, created_at, is_read FROM system_notifications ORDER BY created_at DESC LIMIT %s", (limit,))
                res = cur.fetchall()
                if res:
                    out = []
                    for r in res:
                        d = dict(r)
                        if hasattr(d['created_at'], 'isoformat'):
                            d['created_at'] = d['created_at'].isoformat()
                        d['id'] = str(d['id'])
                        out.append(d)
                    return out
        except Exception as e:
            print(f"[-] Error get_system_notifications PG: {e}")
        finally:
            conn.close()

    return _read_local_notifs()

def get_scan_history_list(limit=20):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT sh.id, sh.risk_score, sh.risk_level, sh.scan_date, sh.raw_json, 
                       sh.domain_id, d.domain_name, d.ip_address
                FROM scan_history sh
                JOIN domains d ON sh.domain_id = d.id
                ORDER BY sh.scan_date DESC
                LIMIT %s
            """, (limit,))
            h_res = cur.fetchall()
            if not h_res: return []
            
            h_ids = tuple([h['id'] for h in h_res])
            cur.execute('SELECT history_id, title, severity, check_type, description, recommendation, epss_score, epss_percentile, cisa_kev, cve, cvss_v3, cwe, evidence FROM scan_result WHERE history_id IN %s', (h_ids,))
            sr_res = cur.fetchall()
            
            sr_map = {}
            for sr in sr_res:
                hid = sr['history_id']
                if hid not in sr_map: sr_map[hid] = []
                sr_map[hid].append(dict(sr))
                
            result = []
            import json
            for h in h_res:
                row = dict(h)
                row['domains'] = {'domain_name': row.pop('domain_name'), 'ip_address': row.pop('ip_address')}
                if hasattr(row['scan_date'], 'isoformat'):
                    row['scan_date'] = row['scan_date'].isoformat()
                row['vulnerabilities'] = sr_map.get(row['id'], [])
                
                raw_json = row.get('raw_json')
                if isinstance(raw_json, str):
                    try: raw_json = json.loads(raw_json)
                    except: raw_json = []
                if isinstance(raw_json, list):
                    row['vulnerabilities'].extend(raw_json)
                row.pop('raw_json', None)
                result.append(row)
            return result
    except Exception as e:
        print(f'[-] Error get_scan_history_list: {e}')
        return []
    finally:
        conn.close()

def get_vulnerabilities_list(severity=None, limit=50):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            query = """
                SELECT sr.id, sr.severity, sr.check_type, sr.title, sr.description, sr.recommendation, 
                       sr.epss_score, sr.epss_percentile, sr.cisa_kev, sr.cve, sr.cvss_v3, sr.cwe, sr.evidence,
                       sr.history_id, sh.scan_date, sh.domain_id, d.domain_name
                FROM scan_result sr
                JOIN scan_history sh ON sr.history_id = sh.id
                JOIN domains d ON sh.domain_id = d.id
            """
            params = []
            if severity:
                query += ' WHERE sr.severity = %s'
                params.append(severity.upper())
            query += ' ORDER BY sh.scan_date DESC LIMIT %s'
            params.append(limit)
            
            cur.execute(query, tuple(params))
            res = cur.fetchall()
            result = []
            for r in res:
                row = dict(r)
                row['scan_history'] = {
                    'scan_date': row.pop('scan_date').isoformat() if hasattr(row.get('scan_date'), 'isoformat') else row.pop('scan_date'),
                    'domain_id': row.pop('domain_id'),
                    'domains': {'domain_name': row.pop('domain_name')}
                }
                result.append(row)
            return result
    except Exception as e:
        print(f'[-] Error get_vulnerabilities_list: {e}')
        return []
    finally:
        conn.close()

def get_overnight_high_critical_scans(limit=20):
    """
    Mengambil riwayat scan yang memiliki temuan risk HIGH atau CRITICAL.
    Biasanya dipakai untuk notifikasi auto-scan malam hari (jam 07:00 WIB).
    """
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT sh.id, sh.risk_score, sh.risk_level, sh.scan_date, sh.raw_json, 
                       sh.domain_id, d.domain_name, d.ip_address
                FROM scan_history sh
                JOIN domains d ON sh.domain_id = d.id
                WHERE UPPER(sh.risk_level) IN ('HIGH', 'CRITICAL')
                  AND DATE(sh.scan_date) = (
                      SELECT DATE(scan_date) 
                      FROM scan_history 
                      WHERE UPPER(risk_level) IN ('HIGH', 'CRITICAL')
                      ORDER BY scan_date DESC LIMIT 1
                  )
                ORDER BY sh.scan_date DESC
                LIMIT %s
            """, (limit,))


            h_res = cur.fetchall()
            if not h_res: return []

            
            h_ids = tuple([h['id'] for h in h_res])
            cur.execute('SELECT history_id, title, severity, check_type, description, recommendation, epss_score, epss_percentile, cisa_kev, cve, cvss_v3, cwe, evidence FROM scan_result WHERE history_id IN %s', (h_ids,))
            sr_res = cur.fetchall()
            
            sr_map = {}
            for sr in sr_res:
                hid = sr['history_id']
                if hid not in sr_map: sr_map[hid] = []
                sr_map[hid].append(dict(sr))
                
            result = []
            import json
            for h in h_res:
                row = dict(h)
                domain_name = row.pop('domain_name')
                ip_address = row.pop('ip_address')
                row['domains'] = {'domain_name': domain_name, 'ip_address': ip_address}
                row['domain_name'] = domain_name
                row['ip_address'] = ip_address
                
                if hasattr(row['scan_date'], 'isoformat'):
                    row['scan_date'] = row['scan_date'].isoformat()
                    
                vulns = sr_map.get(row['id'], [])
                raw_json = row.get('raw_json')
                if isinstance(raw_json, str):
                    try: raw_json = json.loads(raw_json)
                    except: raw_json = []
                if isinstance(raw_json, list):
                    vulns.extend(raw_json)
                row.pop('raw_json', None)
                row['vulnerabilities'] = vulns
                
                # Hitung statistik HIGH & CRITICAL
                crit_cnt = sum(1 for v in vulns if str(v.get('severity', '')).upper() == 'CRITICAL')
                high_cnt = sum(1 for v in vulns if str(v.get('severity', '')).upper() == 'HIGH')
                row['critical_count'] = crit_cnt
                row['high_count'] = high_cnt
                row['total_high_critical'] = crit_cnt + high_cnt
                
                result.append(row)
            return result
    except Exception as e:
        print(f'[-] Error get_overnight_high_critical_scans: {e}')
        return []
    finally:
        conn.close()

# ==============================================================================
# SCHEDULED SCANS MANAGEMENT (FEAT: SCAN SCHEDULING WEB & NETWORK)
# ==============================================================================

def ensure_scheduled_scans_table():
    conn = get_db_connection()
    if not conn: return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.scheduled_scans (
                    id SERIAL PRIMARY KEY,
                    scan_category VARCHAR(50) NOT NULL,
                    scan_type VARCHAR(50) NOT NULL DEFAULT 'deep',
                    targets JSONB NOT NULL,
                    scheduled_at TIMESTAMPTZ NOT NULL,
                    window_end_at TIMESTAMPTZ,
                    frequency VARCHAR(50) NOT NULL DEFAULT 'once',
                    status VARCHAR(50) NOT NULL DEFAULT 'pending',
                    created_by VARCHAR(100),
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    last_run_at TIMESTAMPTZ
                )
            """)
            cur.execute("""
                ALTER TABLE public.scheduled_scans 
                ADD COLUMN IF NOT EXISTS window_end_at TIMESTAMPTZ
            """)
            try:
                cur.execute("SELECT setval('public.scheduled_scans_id_seq', COALESCE((SELECT MAX(id) FROM public.scheduled_scans), 1))")
            except Exception:
                pass
            conn.commit()
    except Exception as e:
        if conn: conn.rollback()
        print(f"[-] Error ensure_scheduled_scans_table: {e}")
    finally:
        conn.close()

def create_scheduled_scan(scan_category, scan_type, targets, scheduled_at, window_end_at=None, frequency='once', created_by='Admin'):
    ensure_scheduled_scans_table()
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            targets_json = json.dumps(targets) if isinstance(targets, list) else targets
            cur.execute("""
                INSERT INTO public.scheduled_scans (scan_category, scan_type, targets, scheduled_at, window_end_at, frequency, status, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, 'pending', %s)
                RETURNING *
            """, (scan_category, scan_type, targets_json, scheduled_at, window_end_at, frequency, created_by))
            res = cur.fetchone()
            conn.commit()
            if res:
                row = dict(res)
                if hasattr(row.get('scheduled_at'), 'isoformat'):
                    row['scheduled_at'] = row['scheduled_at'].isoformat()
                if hasattr(row.get('window_end_at'), 'isoformat') and row.get('window_end_at'):
                    row['window_end_at'] = row['window_end_at'].isoformat()
                if hasattr(row.get('created_at'), 'isoformat'):
                    row['created_at'] = row['created_at'].isoformat()
                return row
            return None
    except Exception as e:
        print(f"[-] Error create_scheduled_scan: {e}")
        if conn: conn.rollback()
        return None
    finally:
        conn.close()

def get_scheduled_scans_list():
    ensure_scheduled_scans_table()
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM public.scheduled_scans ORDER BY scheduled_at DESC LIMIT 100")
            res = cur.fetchall()
            result = []
            for r in (res or []):
                row = dict(r)
                if hasattr(row.get('scheduled_at'), 'isoformat'):
                    row['scheduled_at'] = row['scheduled_at'].isoformat()
                if hasattr(row.get('window_end_at'), 'isoformat') and row.get('window_end_at'):
                    row['window_end_at'] = row['window_end_at'].isoformat()
                if hasattr(row.get('created_at'), 'isoformat'):
                    row['created_at'] = row['created_at'].isoformat()
                if hasattr(row.get('last_run_at'), 'isoformat') and row.get('last_run_at'):
                    row['last_run_at'] = row['last_run_at'].isoformat()
                result.append(row)
            return result
    except Exception as e:
        print(f"[-] Error get_scheduled_scans_list: {e}")
        return []
    finally:
        conn.close()

def delete_scheduled_scan(schedule_id):
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE public.scheduled_scans SET status = 'cancelled' WHERE id = %s RETURNING id", (schedule_id,))
            res = cur.fetchone()
            conn.commit()
            return bool(res)
    except Exception as e:
        if conn: conn.rollback()
        print(f"[-] Error delete_scheduled_scan: {e}")
        return False
    finally:
        conn.close()

def get_scheduled_scan_by_id(schedule_id):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM public.scheduled_scans WHERE id = %s", (schedule_id,))
            res = cur.fetchone()
            if not res: return None
            row = dict(res)
            if hasattr(row.get('scheduled_at'), 'isoformat'):
                row['scheduled_at'] = row['scheduled_at'].isoformat()
            if hasattr(row.get('window_end_at'), 'isoformat') and row.get('window_end_at'):
                row['window_end_at'] = row['window_end_at'].isoformat()
            return row
    except Exception as e:
        print(f"[-] Error get_scheduled_scan_by_id: {e}")
        return None
    finally:
        conn.close()

def get_pending_scheduled_scans_due():
    ensure_scheduled_scans_table()
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM public.scheduled_scans 
                WHERE status = 'pending' AND scheduled_at <= CURRENT_TIMESTAMP
            """)
            res = cur.fetchall()
            result = []
            for r in (res or []):
                row = dict(r)
                if hasattr(row.get('scheduled_at'), 'isoformat'):
                    row['scheduled_at'] = row['scheduled_at'].isoformat()
                if hasattr(row.get('window_end_at'), 'isoformat') and row.get('window_end_at'):
                    row['window_end_at'] = row['window_end_at'].isoformat()
                result.append(row)
            return result
    except Exception as e:
        print(f"[-] Error get_pending_scheduled_scans_due: {e}")
        return []
    finally:
        conn.close()

def mark_scheduled_scan_running(schedule_id):
    conn = get_db_connection()
    if not conn: return
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE public.scheduled_scans SET status = 'running' WHERE id = %s", (schedule_id,))
            conn.commit()
    except Exception as e:
        if conn: conn.rollback()
    finally:
        conn.close()

def mark_scheduled_scan_completed(schedule_id):
    conn = get_db_connection()
    if not conn: return
    now_iso = datetime.now(timezone(timedelta(hours=7))).isoformat()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE public.scheduled_scans SET status = 'completed', last_run_at = %s WHERE id = %s", (now_iso, schedule_id))
            conn.commit()
    except Exception as e:
        if conn: conn.rollback()
    finally:
        conn.close()

def update_scheduled_scan_last_run(schedule_id):
    conn = get_db_connection()
    if not conn: return
    now_iso = datetime.now(timezone(timedelta(hours=7))).isoformat()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE public.scheduled_scans SET last_run_at = %s WHERE id = %s", (now_iso, schedule_id))
            conn.commit()
    except Exception as e:
        if conn: conn.rollback()
    finally:
        conn.close()

def update_scheduled_scan_after_run(schedule_id, frequency):
    conn = get_db_connection()
    if not conn: return
    now_iso = datetime.now(timezone(timedelta(hours=7))).isoformat()
    try:
        with conn.cursor() as cur:
            if frequency == 'daily':
                cur.execute("""
                    UPDATE public.scheduled_scans 
                    SET status = 'pending', scheduled_at = scheduled_at + INTERVAL '1 day', last_run_at = %s 
                    WHERE id = %s
                """, (now_iso, schedule_id))
            elif frequency == 'weekly':
                cur.execute("""
                    UPDATE public.scheduled_scans 
                    SET status = 'pending', scheduled_at = scheduled_at + INTERVAL '7 days', last_run_at = %s 
                    WHERE id = %s
                """, (now_iso, schedule_id))
            else:
                cur.execute("""
                    UPDATE public.scheduled_scans 
                    SET status = 'completed', last_run_at = %s 
                    WHERE id = %s
                """, (now_iso, schedule_id))
            conn.commit()
    except Exception as e:
        if conn: conn.rollback()
        print(f"[-] Error update_scheduled_scan_after_run: {e}")
    finally:
        conn.close()