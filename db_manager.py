import config
from datetime import datetime, timezone, timedelta
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

def create_scan_history(supabase, domain_id, risk_score, risk_level, raw_json=None):
    """Mencatat histori scan baru"""
    data = {
        "domain_id": domain_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "scan_date": datetime.now(timezone(timedelta(hours=7))).isoformat(),
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

def insert_vulnerabilities(supabase, history_id, vulnerabilities):
    """Menyimpan data kerentanan secara massal"""
    if not vulnerabilities:
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
        for v in vulnerabilities
    ]
    supabase.table("vulnerabilities").insert(data).execute()

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
            vulns_list = v_data.get("vulnerabilities", [])
            
            # 3. Buat History
            raw_v_data = v_data if v_data else None
            history_id = create_scan_history(supabase, domain_id, risk_score, risk_level, raw_v_data)
            if not history_id:
                continue
                
            # 4. Simpan relasi (Ports, Techs, Vulns)
            insert_open_ports(supabase, history_id, port_map.get(domain_name, []))
            insert_technologies(supabase, history_id, tech_map.get(domain_name, {}))
            insert_vulnerabilities(supabase, history_id, vulns_list)
            
            saved_count += 1
            
        print(f"[+] Sukses: {saved_count} domain berhasil dimasukkan ke Supabase!")
        return True
        
    except Exception as e:
        print(f"[-] ERROR saat menyimpan ke Supabase: {e}")
        return False

def save_pentest_tools_result(domain_name, report_json):
    """
    Mengadaptasi laporan dari Pentest-Tools API dan menyimpannya ke Supabase.
    """
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
        vulnerabilities = []
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
            
            vulnerabilities.append({
                "severity": severity,
                "check": "Pentest-Tools",
                "title": title,
                "detail": desc,
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
            
        # 3. Buat History (Simpan raw JSON)
        history_id = create_scan_history(supabase, domain_id, final_risk_score, risk_level, report_json)
        if not history_id:
            return False
            
        # 4. Simpan Vulnerabilities
        if vulnerabilities:
            insert_vulnerabilities(supabase, history_id, vulnerabilities)
        
        print(f"  [+] Tersimpan ke Supabase (Risk: {risk_level}, Temuan: {len(vulnerabilities)})")
        return True
        
    except Exception as e:
        print(f"  [-] ERROR saat mem-parsing hasil Pentest-Tools ke Supabase: {e}")
        return False
