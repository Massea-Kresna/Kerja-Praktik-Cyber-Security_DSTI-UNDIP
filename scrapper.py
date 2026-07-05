import asyncio
import aiohttp
import socket
import sys
import requests
import json

# Perbaikan khusus untuk error Event Loop di Windows
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

async def fetch_from_crtsh(root_domain):
    print(f"[*] Menarik data intelijen OSINT dari crt.sh untuk: {root_domain}...")
    url = f"https://crt.sh/?q={root_domain}&output=json"
    
    subdomains = set() 
    
    # Menggunakan ThreadedResolver untuk mencegah bug DNS di Windows
    resolver = aiohttp.ThreadedResolver()
    connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False, resolver=resolver)
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }
    
    try:
        async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
            async with session.get(url, timeout=20) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for entry in data:
                        name_val = entry.get("name_value", "")
                        for name in name_val.split("\n"):
                            name = name.strip().lower()
                            if not name.startswith("*") and name.endswith(root_domain):
                                subdomains.add(name)
                                
                    print(f"[+] Berhasil menemukan {len(subdomains)} subdomain mentah yang pernah dibuat.")
                    return list(subdomains)
                else:
                    print(f"[-] API crt.sh menolak permintaan (Status: {response.status}).")
    except Exception as e:
        print(f"[-] Gagal terhubung ke crt.sh: {str(e)}")
        
    return []

async def check_and_resolve_domain(session, raw_domain, semaphore):
    # KATUP PENGAMAN: Menunggu giliran jika sudah ada 50 proses berjalan
    async with semaphore:
        loop = asyncio.get_running_loop()
        
        # Fase Sanitasi
        domain = raw_domain.replace("http://", "").replace("https://", "").split("/")[0]
        
        try:
            # 1. Tahap DNS
            addr_info = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
            ip_address = addr_info[0][4][0]
            
            # 2. Tahap HTTP/HTTPS
            url = f"https://{domain}" 
            
            # Timeout dinaikkan sedikit menjadi 10 detik agar lebih toleran pada server lambat
            async with session.get(url, timeout=10, ssl=False) as response: 
                if response.status in [200, 301, 302, 400, 401, 403]:
                    print(f"[+] SUKSES: {domain} ({ip_address}) - Status: {response.status}")
                    return {
                        "domain_name": domain,
                        "ip_address": ip_address
                    }
        except asyncio.TimeoutError:
            print(f"[-] TIMEOUT: {domain}")
        except socket.gaierror:
            pass # Abaikan diam-diam jika DNS memang mati
        except Exception:
            pass # Abaikan error koneksi lainnya
            
        return None

async def process_all_domains(domain_list):
    active_assets = []
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    resolver = aiohttp.ThreadedResolver()
    connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False, resolver=resolver, limit=0)
    
    semaphore = asyncio.Semaphore(50)
    
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        # Menyelipkan semaphore ke dalam setiap tugas
        tasks = [check_and_resolve_domain(session, domain, semaphore) for domain in domain_list]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res is not None:
                active_assets.append(res)
                
    return active_assets

if __name__ == "__main__":
    target_utama = "undip.ac.id"
    API_DATABASE_URL = "http://127.0.0.1:8000/api/domains/add"
    
    async def jalankan_sistem():
        print("="*60)
        print(" AUTOMATED DISCOVERY ENGINE - STARTING")
        print("="*60)

        domain_kotor = await fetch_from_crtsh(target_utama)
        
        if not domain_kotor:
            print("[-] Tidak ada data OSINT. Membatalkan eksekusi.")
            return
            
        print(f"\n[*] Memulai validasi asinkron dengan batas 50 koneksi serentak...")

        hasil_bersih = await process_all_domains(domain_kotor)
        
        print("\n" + "="*60)
        print(f" HASIL AKHIR: {len(hasil_bersih)} Aset Aktif dari {len(domain_kotor)} Mentah")
        print("="*60)
        
        if not hasil_bersih:
            print("[-] Tidak ada aset aktif yang ditemukan.")
            return
            
        nama_file = "aset_aktif_undip.json"
        print(f"\n[*] Menyimpan backup data ke file lokal ({nama_file})...")
        try:
            # Membuka file dengan mode 'w' (write). 
            # Jika file belum ada, Python akan otomatis membuatnya.
            with open(nama_file, "w") as outfile:
                # indent=4 digunakan agar format JSON rapi dan mudah dibaca manusia
                json.dump(hasil_bersih, outfile, indent=4)
            print(f"[+] BINGO! File {nama_file} berhasil dibuat di folder proyekmu.")
        except Exception as e:
            print(f"[-] Gagal menyimpan file JSON lokal: {str(e)}")

        print(f"\n[*] Mengirim payload JSON ke Backend ({API_DATABASE_URL})...")
        try:
            response = requests.post(API_DATABASE_URL, json=hasil_bersih, timeout=10)
            
            if response.status_code in [200, 201]:
                print("[+] BINGO! Data berhasil disetorkan ke Database.")
            else:
                print(f"[-] Gagal mengirim. Backend merespons dengan status: {response.status_code}")
                print(f"    Pesan Error: {response.text}")
        except requests.exceptions.ConnectionError:
            print("[-] GAGAL KONEKSI: Server Backend belum aktif. (Gunakan file backup JSON untuk sementara waktu).")
        except Exception as e:
            print(f"[-] Terjadi kesalahan saat pengiriman: {str(e)}")

    # Jalankan program
    asyncio.run(jalankan_sistem())