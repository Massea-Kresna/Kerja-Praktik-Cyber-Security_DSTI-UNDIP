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

def check_db_connection():
    conn = get_db_connection()
    if conn:
        conn.close()
        return True
    return False

# ==============================================================================
# AUTH & USER MANAGEMENT (LOCAL POSTGRES DENGAN JSON FALLBACK)
# ==============================================================================

def hash_password(password: str, salt: str = None) -> str:
    if not salt:
        salt = uuid.uuid4().hex
    hashed = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return f'{salt}${hashed}'

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        if not stored_hash or '$' not in stored_hash:
            return False
        salt, hashed = stored_hash.split('$', 1)
        return hash_password(password, salt) == stored_hash
    except Exception:
        return False

def _read_local_users():
    if not os.path.exists(LOCAL_USERS_FILE):
        return []
    try:
        with open(LOCAL_USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def _write_local_users(users):
    try:
        with open(LOCAL_USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=4, default=str)
        return True
    except Exception:
        return False

def get_user_by_username(username: str):
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM users WHERE username = %s LIMIT 1', (username,))
                res = cur.fetchone()
                if res:
                    return dict(res)
        except Exception as e:
            print(f'[-] Postgres get_user error, fallback ke lokal: {e}')
        finally:
            conn.close()
            
    # Fallback lokal
    users = _read_local_users()
    for u in users:
        if u['username'] == username:
            return u
    return None

def create_user(username: str, password_plain: str, role: str):
    hashed_pw = hash_password(password_plain)
    
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT id FROM users WHERE username = %s', (username,))
                if cur.fetchone():
                    raise Exception('Username sudah digunakan')
                    
                cur.execute(
                    'INSERT INTO users (username, password, role, is_online) VALUES (%s, %s, %s, %s) RETURNING *',
                    (username, hashed_pw, role, False)
                )
                res = cur.fetchone()
                conn.commit()
                if res:
                    return dict(res)
        except Exception as e:
            print(f'[-] Postgres create_user error, fallback ke lokal: {e}')
            if conn:
                conn.rollback()
        finally:
            conn.close()

    users = _read_local_users()
    for u in users:
        if u['username'] == username:
            raise Exception('Username sudah digunakan')
            
    new_user = {
        'username': username,
        'password': hashed_pw,
        'role': role,
        'is_online': False,
        'last_online': None,
        'timeout_until': None,
        'session_id': None,
        'created_at': datetime.now(timezone.utc).isoformat()
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
                    cur.execute(
                        'UPDATE users SET session_id = %s, is_online = %s, last_online = %s WHERE username = %s RETURNING *',
                        (session_id, is_online, now_iso, username)
                    )
                else:
                    cur.execute(
                        'UPDATE users SET session_id = %s, is_online = %s WHERE username = %s RETURNING *',
                        (session_id, is_online, username)
                    )
                res = cur.fetchone()
                conn.commit()
                if res:
                    return dict(res)
        except Exception as e:
            print(f'[-] Postgres update_user_session error, fallback ke lokal: {e}')
            if conn:
                conn.rollback()
        finally:
            conn.close()
            
    users = _read_local_users()
    for u in users:
        if u['username'] == username:
            u['session_id'] = session_id
            u['is_online'] = is_online
            if is_online:
                u['last_online'] = now_iso
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
                    cur.execute(
                        'UPDATE users SET is_online = %s, last_online = %s WHERE username = %s RETURNING *',
                        (is_online, now_iso, username)
                    )
                else:
                    cur.execute(
                        'UPDATE users SET is_online = %s WHERE username = %s RETURNING *',
                        (is_online, username)
                    )
                res = cur.fetchone()
                conn.commit()
                if res:
                    return dict(res)
        except Exception as e:
            print(f'[-] Postgres update_user_online_status error, fallback ke lokal: {e}')
            if conn:
                conn.rollback()
        finally:
            conn.close()
            
    users = _read_local_users()
    for u in users:
        if u['username'] == username:
            u['is_online'] = is_online
            if is_online:
                u['last_online'] = now_iso
            _write_local_users(users)
            return u
    return None

def update_user_timeout(username: str, timeout_until: str or None):
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    'UPDATE users SET timeout_until = %s, session_id = NULL, is_online = FALSE WHERE username = %s RETURNING *',
                    (timeout_until, username)
                )
                res = cur.fetchone()
                conn.commit()
                if res:
                    return dict(res)
        except Exception as e:
            print(f'[-] Postgres update_user_timeout error, fallback ke lokal: {e}')
            if conn:
                conn.rollback()
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
                cur.execute('SELECT id, username, role, is_online, last_online, timeout_until, created_at FROM users ORDER BY username ASC')
                res = cur.fetchall()
                if res:
                    return [dict(row) for row in res]
        except Exception as e:
            print(f'[-] Postgres list_all_users error, fallback ke lokal: {e}')
        finally:
            conn.close()
            
    users = _read_local_users()
    filtered = []
    for u in users:
        filtered.append({
            'username': u['username'],
            'role': u['role'],
            'is_online': u['is_online'],
            'last_online': u.get('last_online'),
            'timeout_until': u.get('timeout_until'),
            'created_at': u.get('created_at')
        })
    return sorted(filtered, key=lambda x: x['username'])

def delete_user(username: str) -> bool:
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM users WHERE username = %s RETURNING id', (username,))
                res = cur.fetchone()
                conn.commit()
                if res:
                    return True
        except Exception as e:
            print(f'[-] Postgres delete_user error, fallback ke lokal: {e}')
            if conn:
                conn.rollback()
        finally:
            conn.close()
            
    users = _read_local_users()
    filtered_users = [u for u in users if u['username'] != username]
    if len(users) != len(filtered_users):
        return _write_local_users(filtered_users)
    return False

def get_user_by_session_id(session_id: str):
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM users WHERE session_id = %s LIMIT 1', (session_id,))
                res = cur.fetchone()
                if res:
                    return dict(res)
        except Exception as e:
            pass
        finally:
            conn.close()
            
    users = _read_local_users()
    for u in users:
        if u.get('session_id') == session_id:
            return u
    return None

def seed_default_admin():
    import config
    admin_username = config.ADMIN_EMAIL if config.ADMIN_EMAIL else 'admin'
    try:
        admin_user = get_user_by_username(admin_username)
        if not admin_user:
            create_user(admin_username, 'admin123', 'admin')
            print(f'[+] Seeding Sukses: User default {admin_username} dengan password admin123 telah ditambahkan.')
    except Exception as e:
        print(f'[-] Gagal melakukan seeding admin: {e}')

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
            """, (domain_name, ip_address, True))
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
            cur.execute('SELECT id, domain_name, ip_address, is_active FROM domains ORDER BY domain_name ASC')
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

def create_domain(domain_name, ip_address):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                'INSERT INTO domains (domain_name, ip_address, is_active) VALUES (%s, %s, %s) RETURNING *',
                (domain_name, ip_address, True)
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
            if search:
                cur.execute('SELECT id, domain_name, ip_address, is_active FROM domains WHERE domain_name ILIKE %s ORDER BY domain_name ASC', (f'%{search}%',))
            else:
                cur.execute('SELECT id, domain_name, ip_address, is_active FROM domains ORDER BY domain_name ASC')
            res = cur.fetchall()
            return [dict(row) for row in res]
    except Exception as e:
        print(f'[-] Error get_domains_list: {e}')
        return []
    finally:
        conn.close()

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

# ==============================================================================
# NOTIFICATIONS MANAGEMENT (LOCAL JSON) - Dihapus karena menggunakan riwayat scan
# ==============================================================================