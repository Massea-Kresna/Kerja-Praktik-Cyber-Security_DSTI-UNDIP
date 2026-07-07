import json
import asyncio
import os
import config
import db_manager

async def sync_domains():
    print("[*] Memulai sinkronisasi dari aset_aktif_undip.json ke Supabase...")
    
    if not os.path.exists(config.INPUT_FILE):
        print(f"[-] File {config.INPUT_FILE} tidak ditemukan.")
        return

    with open(config.INPUT_FILE, "r") as f:
        assets = json.load(f)

    supabase = db_manager.get_supabase_client()
    if not supabase:
        print("[-] Gagal koneksi ke Supabase. Cek .env")
        return

    count = 0
    for asset in assets:
        domain_name = asset.get("domain_name")
        ip_address = asset.get("ip_address", "")
        
        if domain_name:
            # Gunakan fungsi upsert yang sudah ada di db_manager
            db_manager.upsert_domain(supabase, domain_name, ip_address)
            count += 1
            print(f"  [+] Synced: {domain_name}")

    print(f"\n[+] Selesai! Berhasil mensinkronkan {count} domain ke tabel 'domains' di Supabase.")

if __name__ == "__main__":
    asyncio.run(sync_domains())
