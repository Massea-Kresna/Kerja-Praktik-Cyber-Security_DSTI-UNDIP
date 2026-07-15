import config
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import uuid
try:
    from supabase import create_client, Client
except ImportError:
    print("[!] Modul 'supabase' belum diinstal. Jalankan: pip install supabase")

def get_supabase_client():
    """Menginisialisasi client Supabase menggunakan URL dan Service Role Key"""
    if not config.SUPABASE_URL or not config.SUPABASE_KEY:
        return None
    try:
        return create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
    except Exception as e:
        print(f"[!] Warning: Gagal menginisialisasi Supabase Client. Detail: {e}")
        return None

def upsert_domain(supabase, domain_name, ip_address):
    """Memasukkan atau memperbarui domain (Upsert)"""
    data = {
        "domain_name": domain_name,
        "ip_address": ip_address,
        "is_active": True
    }
    response = supabase.table("domains").upsert(data, on_conflict="domain_name").execute()
    # Mengembalikan ID domain yang baru saja di-upsert
    return response.data[0]['id'] if response.data else None

def create_scan_history(supabase, domain_id, risk_score, risk_level, raw_json=None, scan_date=None):
    """Mencatat histori scan baru"""
    if not scan_date:
        scan_date = datetime.now(timezone(timedelta(hours=7))).isoformat()
        
    data = {
        "domain_id": domain_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "scan_date": scan_date,
        "raw_json": raw_json
    }
    response = supabase.table("scan_history").insert(data).execute()
    return response.data[0]['id'] if response.data else None

def insert_open_ports(supabase, history_id, open_ports):
    """Menyimpan data port terbuka secara massal (bulk insert)"""
    if not open_ports:
        return
    
    data = [
        {
            "history_id": history_id, 
            "port_number": p["port"], 
            "service_name": p["service"]
        } 
        for p in open_ports
    ]
    supabase.table("open_ports").insert(data).execute()

def insert_technologies(supabase, history_id, tech_data):
    """Menyimpan data teknologi"""
    if not tech_data:
        return
        
    data = {
        "history_id": history_id,
        "web_server": tech_data.get("web_server", "Unknown"),
        "cms": tech_data.get("cms", "Unknown")
    }
    supabase.table("technologies").insert(data).execute()

def insert_scan_result(supabase, history_id, scan_result):
    """Menyimpan data kerentanan secara massal"""
    if not scan_result:
        return
        
    data = [
        {
            "history_id": history_id, 
            "severity": v.get("severity", "LOW"),
            "check_type": v.get("check", "UNKNOWN"),
            "title": v.get("title", ""),
            "description": v.get("detail", ""),
            "recommendation": v.get("recommendation", "")
        } 
        for v in scan_result
    ]
    supabase.table("scan_result").insert(data).execute()

def save_all_results(domain_list, port_results, tech_results, vuln_results):
    """
    Mengorkestrasikan penyimpanan semua laporan hasil scan ke Supabase (REST API).
    """
    supabase = get_supabase_client()
    if not supabase:
        print("[!] SKIP DATABASE: Supabase belum dikonfigurasi di .env atau tidak valid.")
        return False
        
    print(f"\n{'-'*60}")
    print("  MENYIMPAN HASIL KE SUPABASE (REST API)")
    print(f"{'-'*60}")
    
    try:
        # Cek apakah tabel domains sudah ada dengan mencoba mengambil 1 baris
        try:
            supabase.table("domains").select("id").limit(1).execute()
        except Exception:
            print("[-] SKIP DATABASE: Tabel belum dibuat di Supabase (Jalankan SQL script dulu).")
            return False
            
        # Konversi array menjadi map
        port_map = {r["domain_name"]: r.get("open_ports", []) for r in port_results}
        tech_map = {r["domain_name"]: r.get("technologies", {}) for r in tech_results}
        vuln_map = {r["domain_name"]: r for r in vuln_results}
        
        saved_count = 0
        
        # Proses per domain secara berurutan
        for domain_info in domain_list:
            domain_name = domain_info["domain_name"]
            ip_address = domain_info.get("ip_address", "")
            
            # 1. Simpan/Update Domain
            domain_id = upsert_domain(supabase, domain_name, ip_address)
            if not domain_id:
                continue
                
            # 2. Ambil data kerentanan
            v_data = vuln_map.get(domain_name, {})
            risk_score = v_data.get("risk_score", 0.0)
            risk_level = v_data.get("risk_level", "SAFE")
            vulns_list = v_data.get("scan_result", [])
            
            # Pisahkan LOW/INFO untuk disimpan di raw_json
            low_info_vulns = []
            for v in vulns_list:
                if v.get("severity", "").upper() not in ["MEDIUM", "HIGH", "CRITICAL"]:
                    # Format ulang sedikit agar sesuai dengan struktur kolom di tabel scan_result
                    low_info_vulns.append({
                        "severity": v.get("severity", "LOW"),
                        "check_type": v.get("check", "UNKNOWN"),
                        "title": v.get("title", ""),
                        "description": v.get("detail", ""),
                        "recommendation": v.get("recommendation", "")
                    })
            
            # 3. Buat History (Simpan list LOW/INFO ke raw_json)
            # Dump list low_info_vulns ke raw_json (disimpan sebagai object JSON agar bisa diparsing)
            raw_v_data = low_info_vulns if low_info_vulns else None
            history_id = create_scan_history(supabase, domain_id, risk_score, risk_level, raw_v_data)
            if not history_id:
                continue
                
            # 4. Simpan relasi (Ports, Techs, Vulns)
            insert_open_ports(supabase, history_id, port_map.get(domain_name, []))
            insert_technologies(supabase, history_id, tech_map.get(domain_name, {}))
            # Filter: Hanya simpan scan_result dengan severity MEDIUM ke atas
            filtered_vulns = [v for v in vulns_list if v.get("severity", "").upper() in ["MEDIUM", "HIGH", "CRITICAL"]]
            insert_scan_result(supabase, history_id, filtered_vulns)
            
            saved_count += 1
            
        print(f"[+] Sukses: {saved_count} domain berhasil dimasukkan ke Supabase!")
        return True
        
    except Exception as e:
        print(f"[-] ERROR saat menyimpan ke Supabase: {e}")
        return False

def save_pentest_tools_result(domain_name, report_json, scanner_type="Web Scanner", scan_date=None):
    """
    Mengadaptasi laporan dari Pentest-Tools API dan menyimpannya ke Supabase.
    """
    print(f"[*] Parse & Save ke DB: {domain_name} ({scanner_type})")
    supabase = get_supabase_client()
    if not supabase:
        print("  [!] Gagal menyimpan ke Supabase: Client tidak tersedia.")
        return False
        
    try:
        # 1. Cari domain_id
        response = supabase.table("domains").select("id").eq("domain_name", domain_name).limit(1).execute()
        if not response.data:
            print(f"  [-] Domain {domain_name} tidak ditemukan di tabel domains.")
            return False
            
        domain_id = response.data[0]['id']
        
        # 2. Hitung Risk Score (Ekstrak findings)
        findings = report_json.get("findings", [])
        
        # Format baru: report_json = data (tanpa wrapper)
        if not findings and "output_data" in report_json:
            findings = report_json.get("output_data", {}).get("findings", [])
            
        # Format lama: masih ada wrapper "data"
        if not findings and "data" in report_json:
            data_block = report_json.get("data", {})
            findings = data_block.get("findings", [])
            if not findings and "output_data" in data_block:
                findings = data_block.get("output_data", {}).get("findings", [])
            
        risk_score = 0.0
        high_count = 0
        med_count = 0
        low_count = 0
        
        # Menerjemahkan findings ke struktur database kita
        scan_result = []
        low_info_vulns = []
        for f in findings:
            # Pentest-Tools v2 memakai integer risk_level (0=INFO, 1=LOW, 2=MED, 3=HIGH, 4=CRIT)
            severity = str(f.get("severity", "")).upper()
            if not severity and "risk_level" in f:
                risk_mapping = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
                severity = risk_mapping.get(f.get("risk_level"), "LOW")
            elif not severity:
                severity = "LOW"
                
            title = f.get("title", f.get("name", "Unknown Vulnerability"))
            desc = f.get("description", "")
            recom = f.get("remediation", f.get("recommendation", ""))
            
            vuln_obj = {
                "severity": severity,
                "check": scanner_type,
                "title": title,
                "detail": desc,
                "recommendation": recom
            }
            
            # Filter: Pisahkan MEDIUM+ dan LOW/INFO
            if severity in ["MEDIUM", "HIGH", "CRITICAL"]:
                scan_result.append(vuln_obj)
            else:
                # Format untuk raw_json (disamakan dengan response web_app.py)
                low_info_vulns.append({
                    "severity": severity,
                    "check_type": scanner_type,
                    "title": title,
                    "description": desc,
                    "recommendation": recom
                })
            
            if severity in ["HIGH", "CRITICAL"]:
                risk_score += 3.0
                high_count += 1
            elif severity == "MEDIUM":
                risk_score += 2.0
                med_count += 1
            elif severity == "LOW" or severity == "INFO":
                risk_score += 1.0
                low_count += 1
                
        # Tentukan Risk Level
        if risk_score >= 10.0 or high_count > 0:
            risk_level = "HIGH"
        elif risk_score >= 5.0 or med_count > 0:
            risk_level = "MEDIUM"
        elif risk_score > 0.0 or low_count > 0:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"
            
        # Batasi max risk score ke 10.0
        final_risk_score = min(risk_score, 10.0)
            
        if risk_level not in ["MEDIUM", "HIGH", "CRITICAL"]:
            print(f"  [*] Menyimpan history ke Supabase tanpa detail scan_result DB (Risk Level: {risk_level})")
            
        # 3. Buat History (Simpan LOW/INFO ke raw_json)
        history_id = create_scan_history(supabase, domain_id, final_risk_score, risk_level, low_info_vulns if low_info_vulns else None, scan_date=scan_date)
        if not history_id:
            return False
            
        # 4. Simpan Scan_result
        if scan_result:
            insert_scan_result(supabase, history_id, scan_result)
        
        print(f"  [+] Tersimpan ke Supabase (Risk: {risk_level}, Temuan: {len(scan_result)})")
        return True
        
    except Exception as e:
        print(f"  [-] ERROR saat mem-parsing hasil Pentest-Tools ke Supabase: {e}")
        return False

# ==============================================================================
# USER MANAGEMENT & MULTI-ROLE METHODS (SUPABASE / LOCAL JSON FALLBACK)
# ==============================================================================

LOCAL_USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users_db.json")

def hash_password(password: str, salt: str = None) -> str:
    """Hash password menggunakan SHA-256 dan salt unik"""
    if not salt:
        salt = uuid.uuid4().hex
    hashed = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return f"{salt}${hashed}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verifikasi kecocokan password dengan hash yang disimpan"""
    try:
        if not stored_hash or "$" not in stored_hash:
            return False
        salt, hashed = stored_hash.split('$', 1)
        return hash_password(password, salt) == stored_hash
    except Exception:
        return False

def _read_local_users():
    """Membaca daftar user dari file JSON lokal"""
    if not os.path.exists(LOCAL_USERS_FILE):
        return []
    try:
        with open(LOCAL_USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def _write_local_users(users):
    """Menyimpan daftar user ke file JSON lokal"""
    try:
        with open(LOCAL_USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=4, default=str)
        return True
    except Exception:
        return False

def get_user_by_username(username: str):
    """Mendapatkan data user berdasarkan username"""
    supabase = get_supabase_client()
    if supabase:
        try:
            resp = supabase.table("users").select("*").eq("username", username).limit(1).execute()
            if resp.data:
                return resp.data[0]
        except Exception as e:
            print(f"[-] Supabase get_user error, fallback ke lokal: {e}")
    
    # Fallback lokal
    users = _read_local_users()
    for u in users:
        if u["username"] == username:
            return u
    return None

def create_user(username: str, password_plain: str, role: str):
    """Membuat user baru"""
    hashed_pw = hash_password(password_plain)
    
    supabase = get_supabase_client()
    if supabase:
        try:
            data = {
                "username": username,
                "password": hashed_pw,
                "role": role,
                "is_online": False,
                "last_online": None,
                "timeout_until": None,
                "session_id": None
            }
            resp = supabase.table("users").insert(data).execute()
            if resp.data:
                return resp.data[0]
        except Exception as e:
            print(f"[-] Supabase create_user error, fallback ke lokal: {e}")
            
    # Fallback lokal
    users = _read_local_users()
    for u in users:
        if u["username"] == username:
            raise Exception("Username sudah digunakan")
            
    new_user = {
        "username": username,
        "password": hashed_pw,
        "role": role,
        "is_online": False,
        "last_online": None,
        "timeout_until": None,
        "session_id": None,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    users.append(new_user)
    _write_local_users(users)
    return new_user

def update_user_session(username: str, session_id: str or None, is_online: bool):
    """Memperbarui status session dan online/offline user"""
    now_iso = datetime.now(timezone.utc).isoformat()
    
    supabase = get_supabase_client()
    if supabase:
        try:
            data = {
                "session_id": session_id,
                "is_online": is_online
            }
            if is_online:
                data["last_online"] = now_iso
            resp = supabase.table("users").update(data).eq("username", username).execute()
            if resp.data:
                return resp.data[0]
        except Exception as e:
            print(f"[-] Supabase update_user_session error, fallback ke lokal: {e}")
            
    # Fallback lokal
    users = _read_local_users()
    for u in users:
        if u["username"] == username:
            u["session_id"] = session_id
            u["is_online"] = is_online
            if is_online:
                u["last_online"] = now_iso
            _write_local_users(users)
            return u
    return None

def update_user_timeout(username: str, timeout_until: str or None):
    """Menyetel waktu timeout (tangguh) untuk user dan men-force logout mereka"""
    supabase = get_supabase_client()
    if supabase:
        try:
            data = {
                "timeout_until": timeout_until,
                "session_id": None,
                "is_online": False
            }
            resp = supabase.table("users").update(data).eq("username", username).execute()
            if resp.data:
                return resp.data[0]
        except Exception as e:
            print(f"[-] Supabase update_user_timeout error, fallback ke lokal: {e}")
            
    # Fallback lokal
    users = _read_local_users()
    for u in users:
        if u["username"] == username:
            u["timeout_until"] = timeout_until
            u["session_id"] = None
            u["is_online"] = False
            _write_local_users(users)
            return u
    return None

def list_all_users():
    """Mengambil daftar seluruh user (kecuali password)"""
    supabase = get_supabase_client()
    if supabase:
        try:
            resp = supabase.table("users").select("id, username, role, is_online, last_online, timeout_until, created_at").execute()
            if resp.data:
                return sorted(resp.data, key=lambda x: x["username"])
        except Exception as e:
            print(f"[-] Supabase list_all_users error, fallback ke lokal: {e}")
            
    # Fallback lokal
    users = _read_local_users()
    filtered = []
    for u in users:
        filtered.append({
            "username": u["username"],
            "role": u["role"],
            "is_online": u["is_online"],
            "last_online": u.get("last_online"),
            "timeout_until": u.get("timeout_until"),
            "created_at": u.get("created_at")
        })
    return sorted(filtered, key=lambda x: x["username"])

def delete_user(username: str) -> bool:
    """Menghapus user berdasarkan username"""
    supabase = get_supabase_client()
    if supabase:
        try:
            resp = supabase.table("users").delete().eq("username", username).execute()
            if resp.data:
                return True
        except Exception as e:
            print(f"[-] Supabase delete_user error, fallback ke lokal: {e}")
            
    # Fallback lokal
    users = _read_local_users()
    filtered_users = [u for u in users if u["username"] != username]
    if len(users) != len(filtered_users):
        return _write_local_users(filtered_users)
    return False

def seed_default_admin():
    """Melakukan seeding admin default (admin / admin123) jika database masih kosong"""
    try:
        admin_user = get_user_by_username("admin")
        if not admin_user:
            create_user("admin", "admin123", "admin")
            print("[+] Seeding Sukses: User default 'admin' dengan password 'admin123' telah ditambahkan.")
    except Exception as e:
        print(f"[-] Gagal melakukan seeding admin: {e}")