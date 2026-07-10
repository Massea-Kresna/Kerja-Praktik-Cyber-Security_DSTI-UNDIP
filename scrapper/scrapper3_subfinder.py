import os
import asyncio
import aiohttp
import socket
import sys
import requests
import json
# import sublist3r
import subprocess
import datetime

# Perbaikan khusus untuk error Event Loop di Windows
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# =======================================================================
# TIER 1: OSINT UTAMA (crt.sh dengan Retry Mechanism)
# =======================================================================
async def fetch_from_crtsh(root_domain, max_retries=3):
    print(f"[*] [TIER 1] Menarik data intelijen dari crt.sh untuk: {root_domain}...")
    url = f"https://crt.sh/?q={root_domain}&output=json"
    subdomains = set() 
    
    resolver = aiohttp.ThreadedResolver()
    connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False, resolver=resolver)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }
    
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        for attempt in range(1, max_retries + 1):
            try:
                async with session.get(url, timeout=25) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name_val = entry.get("name_value", "")
                            for name in name_val.split("\n"):
                                name = name.strip().lower()
                                if not name.startswith("*") and name.endswith(root_domain):
                                    subdomains.add(name)
                        print(f"[+] [TIER 1] BINGO! crt.sh menemukan {len(subdomains)} subdomain mentah.")
                        return list(subdomains)
                    elif response.status in [502, 503, 504]:
                        print(f"[-] crt.sh sedang kelebihan beban (Status: {response.status}). Percobaan {attempt}/{max_retries}...")
                    else:
                        print(f"[-] API crt.sh menolak permintaan (Status: {response.status}). Percobaan {attempt}/{max_retries}...")
            except asyncio.TimeoutError:
                print(f"[-] API crt.sh tidak merespons (Timeout). Percobaan {attempt}/{max_retries}...")
            except Exception as e:
                print(f"[-] Gagal terhubung ke crt.sh: {str(e)}. Percobaan {attempt}/{max_retries}...")
            
            if attempt < max_retries:
                waktu_tunggu = 5 * attempt
                print(f"[*] Bersabar... Menunggu {waktu_tunggu} detik sebelum mencoba lagi...\n")
                await asyncio.sleep(waktu_tunggu)
                
    print("[-] [TIER 1] crt.sh lumpuh total hari ini.")
    return []

# =======================================================================
# TIER 2: OSINT CADANGAN (HackerTarget API)
# =======================================================================
# Ganti dengan ini agar lebih tahan banting terhadap error DNS di Windows
async def fetch_from_hackertarget(root_domain):
    print(f"\n[!] [TIER 2] Mengaktifkan mesin cadangan (HackerTarget) untuk: {root_domain}...")
    url = f"https://api.hackertarget.com/hostsearch/?q={root_domain}"
    subdomains = set()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        # Menggunakan asyncio.to_thread agar requests.get yang sinkron tidak membekukan program
        response = await asyncio.to_thread(requests.get, url, headers=headers, timeout=20)
        
        if response.status_code == 200:
            for line in response.text.strip().split('\n'):
                if ',' in line:
                    name = line.split(',')[0].strip().lower()
                    if not name.startswith("*") and name.endswith(root_domain):
                        subdomains.add(name)
            print(f"[+] [TIER 2] BINGO! HackerTarget menemukan {len(subdomains)} subdomain mentah.")
            return list(subdomains)
        elif response.status_code == 429:
            print("[-] HackerTarget memblokir IP kita (Terlalu banyak request).")
        else:
            print(f"[-] HackerTarget menolak permintaan (Status: {response.status_code}).")
    except Exception as e:
        print(f"[-] Gagal terhubung ke HackerTarget: {str(e)}")
        
    return []

# =======================================================================
# TIER 3: OSINT SENJATA BERAT (Subfinder via Subprocess & Threading)
# =======================================================================
async def fetch_from_subfinder(root_domain):
    print(f"\n[*] [TIER 3] Mengaktifkan mesin Subfinder (ProjectDiscovery) untuk: {root_domain}...")
    
    try:
        # 1. Dapatkan lokasi absolut file subfinder.exe
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # 2. Deteksi OS untuk menentukan nama file executable
        if sys.platform == 'win32':
            nama_eksekusi = "subfinder.exe"
        else:
            nama_eksekusi = "subfinder" # Linux/macOS tidak pakai .exe

        subfinder_path = os.path.join(current_dir, nama_eksekusi)
        
        # 2. Fungsi sinkron untuk menjalankan Subfinder
        def jalankan_program():
            # subprocess.run jauh lebih stabil di Windows
            return subprocess.run(
                [subfinder_path, '-d', root_domain, '-silent', '-all'],
                capture_output=True,
                text=True, # Otomatis mengubah output menjadi string (tidak perlu di-decode)
                check=True # Memunculkan error jika file .exe gagal dieksekusi
            )
            
        # 3. Jalankan fungsi di atas pada thread terpisah (Asynchronous)
        process = await asyncio.to_thread(jalankan_program)
        
        # 4. Tangkap dan olah output-nya
        if process.stdout:
            subdomains = process.stdout.strip().split('\n')
            hasil_bersih = list(set([sub.strip().lower() for sub in subdomains if sub.strip()]))
            
            print(f"[+] [TIER 3] BINGO! Subfinder berhasil menjaring {len(hasil_bersih)} subdomain mentah.")
            return hasil_bersih
        else:
            print("[-] Subfinder selesai, tetapi tidak menemukan domain tambahan.")
            return []
            
    except FileNotFoundError:
        print("[-] Error: Windows tidak dapat menemukan 'subfinder.exe' di path tersebut.")
        return []
    except subprocess.CalledProcessError as e:
        print(f"[-] Error internal dari Subfinder. Kode Exit: {e.returncode}")
        return []
    except Exception as e:
        print(f"[-] Gagal menjalankan mesin Subfinder: {str(e)}")
        return []

# =======================================================================
# MODUL 2: VALIDASI & RESOLUSI DNS
# =======================================================================
async def check_and_resolve_domain(session, raw_domain, semaphore):
    async with semaphore:
        loop = asyncio.get_running_loop()
        domain = raw_domain.replace("http://", "").replace("https://", "").split("/")[0]
        
        try:
            addr_info = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
            ip_address = addr_info[0][4][0]
            url = f"https://{domain}" 
            
            async with session.get(url, timeout=10, ssl=False) as response: 
                if response.status in [200, 301, 302, 400, 401, 403]:
                    print(f"[+] HIDUP: {domain} ({ip_address})")
                    return {
                        "domain_name": domain,
                        "ip_address": ip_address
                    }
        except asyncio.TimeoutError:
            pass
        except socket.gaierror:
            pass
        except Exception:
            pass
            
        return None

async def process_all_domains(domain_list):
    active_assets = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    resolver = aiohttp.ThreadedResolver()
    connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False, resolver=resolver, limit=0)
    semaphore = asyncio.Semaphore(50) # Maksimal 50 koneksi serentak
    
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        tasks = [check_and_resolve_domain(session, domain, semaphore) for domain in domain_list]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res is not None:
                active_assets.append(res)
                
    return active_assets

# # =======================================================================
# # MODUL 3: ORKESTRASI & PENYERAHAN DATA (HANDOFF)
# # =======================================================================
# if __name__ == "__main__":
#     target_utama = "undip.ac.id"
#     API_SATRIA_URL = "http://127.0.0.1:8000/api/domains/add"
    
#     async def jalankan_sistem():
#         print("="*70)
#         print("AUTOMATED DISCOVERY ENGINE - INITIATED")
#         print("="*70)
        
#         # 1. Eksekusi Tier 1 (Crt.sh)
#         domain_kotor_cepat = await fetch_from_crtsh(target_utama)
        
#         # Eksekusi Tier 2 (Fallback) jika Tier 1 Gagal
#         if not domain_kotor_cepat:
#             domain_kotor_cepat = await fetch_from_hackertarget(target_utama)
            
#         # 2. Eksekusi Tier 3 (Sublist3r)
#         domain_kotor_dalam = await fetch_from_subfinder(target_utama)
        
#         # 3. Penggabungan Data & Eliminasi Duplikat Antar-Mesin
#         total_domain_mentah = list(set(domain_kotor_cepat + domain_kotor_dalam))
        
#         if not total_domain_mentah:
#             print("\n[-] SELURUH MESIN OSINT GAGAL. Membatalkan eksekusi hari ini.")
#             return
            
#         print(f"\n[*] Total {len(total_domain_mentah)} domain mentah terkumpul dari semua mesin intelijen.")
#         print("[*] Memulai radar validasi asinkron (Mendeteksi server aktif)...")
#         print("-"*70)
        
#         # 4. Validasi Jaringan
#         hasil_bersih = await process_all_domains(total_domain_mentah)
        
#         print("\n" + "="*70)
#         print(f"✅ HASIL AKHIR: {len(hasil_bersih)} Aset Aktif Siap Retas dari {len(total_domain_mentah)} Mentah")
#         print("="*70)
        
#         if not hasil_bersih:
#             print("[-] Tidak ada aset aktif yang ditemukan.")
#             return
            
#         # 5. Backup Lokal ke JSON
#         nama_file = "subfinder_aset_aktif_undip.json"
#         try:
#             with open(nama_file, "w") as outfile:
#                 json.dump(hasil_bersih, outfile, indent=4)
#             print(f"[*] Backup diamankan: {nama_file}")
#         except Exception as e:
#             print(f"[-] Gagal menyimpan file lokal: {str(e)}")

#         # 6. Handoff ke Backend Satria
#         print(f"[*] Mencoba sinkronisasi ke Database Internal ({API_SATRIA_URL})...")
#         try:
#             response = requests.post(API_SATRIA_URL, json=hasil_bersih, timeout=10)
#             if response.status_code in [200, 201]:
#                 print("[+] SINKRONISASI BERHASIL! Data disetorkan ke Satria.")
#             else:
#                 print(f"[-] Sinkronisasi Gagal. Status Backend: {response.status_code}")
#         except requests.exceptions.ConnectionError:
#             print("[-] GAGAL KONEKSI: Backend Satria belum aktif. Gunakan file JSON untuk sementara.")
#         except Exception as e:
#             print(f"[-] Kesalahan pengiriman: {str(e)}")

#     # Jalankan keseluruhan orkestrasi
#     asyncio.run(jalankan_sistem())

# INI KALO PAKE CELERY SAMA REDIS JADI KEK DIBAWAH:
async def jalankan_sistem():
    target_utama = "undip.ac.id"
    API_DATABASE_URL = "http://127.0.0.1:8000/api/domains/add"
    print("="*70)
    print(" AUTOMATED DISCOVERY ENGINE - STARTING")
    print("="*70)

    # tier 1
    domain_kotor_cepat = await fetch_from_crtsh(target_utama)
    
    # tier 2 (fallback kalo tier 1 error)
    if not domain_kotor_cepat:
        domain_kotor_cepat = await fetch_from_hackertarget(target_utama)
    
    # tier 3 (Sublist3r)
    domain_kotor_dalam = await fetch_from_subfinder(target_utama)

    total_domain_mentah = list(set(domain_kotor_cepat + domain_kotor_dalam))

    if not total_domain_mentah:
        print("\n[-] SELURUH MESIN OSINT GAGAL. Membatalkan eksekusi hari ini.")
        return
    
    print(f"\n[*] Total {len(total_domain_mentah)} domain mentah terkumpul dari semua mesin intelijen.")
    print("[*] Memulai radar validasi asinkron (Mendeteksi server aktif)...")
    print("-"*70)
        
    #validasi Jaringan
    hasil_bersih = await process_all_domains(total_domain_mentah)

    print("\n" + "="*70)
    print(f" HASIL AKHIR: {len(hasil_bersih)} Aset Aktif dari {len(total_domain_mentah)} Mentah")
    print("="*70)
        
    if not hasil_bersih:
        print("[-] Tidak ada aset aktif yang ditemukan.")
        return

    # export json ke folder backup
    tanggal_hari_ini = datetime.datetime.now().strftime("%Y-%m-%d")
    nama_file_dinamis = f"sub_domain_aktif_undip_{tanggal_hari_ini}.json"

    current_dir = os.path.dirname(os.path.abspath(__file__))
    backup_folder = os.path.join(current_dir, "..", "backup_data")

    os.makedirs(backup_folder, exist_ok=True)
    nama_file = os.path.join(backup_folder, nama_file_dinamis)

    print(f"\n[*] Menyimpan backup data ke file lokal ({nama_file})...")
    try:
        # Membuka file dengan mode 'w' (write). 
        # Jika file belum ada, Python akan otomatis membuatnya.
        with open(nama_file, "w") as outfile:
            # indent=4 digunakan agar format JSON rapi dan mudah dibaca manusia
            json.dump(hasil_bersih, outfile, indent=4)
        print(f"[+] BINGO! File {nama_file} berhasil dibuat di folder {backup_folder}.")
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
    # Blok ini memastikan skrip hanya jalan mandiri jika diklik langsung, dan tidak otomatis tereksekusi saat di-import oleh Celery.
if __name__ == "__main__":
    asyncio.run(jalankan_sistem())