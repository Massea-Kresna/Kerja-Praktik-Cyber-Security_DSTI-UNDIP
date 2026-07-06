import config
from datetime import datetime, timezone
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

def create_scan_history(supabase, domain_id, risk_score, risk_level):
    """Mencatat histori scan baru"""
    data = {
        "domain_id": domain_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "scan_date": datetime.now(timezone.utc).isoformat()
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
        
    print(f"\n{'─'*60}")
    print("  MENYIMPAN HASIL KE SUPABASE (REST API)")
    print(f"{'─'*60}")
    
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
            history_id = create_scan_history(supabase, domain_id, risk_score, risk_level)
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
