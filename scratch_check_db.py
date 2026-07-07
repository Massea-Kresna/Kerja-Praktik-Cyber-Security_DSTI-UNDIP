import config
import db_manager

supabase = db_manager.get_supabase_client()
if supabase:
    print("[+] Supabase connection OK")
    
    # Cek jumlah data
    doms = supabase.table("domains").select("id", count="exact").execute()
    print(f"Total domains di DB: {doms.count if hasattr(doms, 'count') and doms.count is not None else len(doms.data)}")
    
    vulns = supabase.table("vulnerabilities").select("id", count="exact").execute()
    print(f"Total vulnerabilities di DB: {vulns.count if hasattr(vulns, 'count') and vulns.count is not None else len(vulns.data)}")
    
    # Cek isi vulnerabilities
    if (vulns.count if hasattr(vulns, 'count') and vulns.count is not None else len(vulns.data)) > 0:
        v = supabase.table("vulnerabilities").select("title").limit(5).execute()
        print("Contoh judul kerentanan:", [x["title"] for x in v.data])
else:
    print("[-] Supabase connection failed")
