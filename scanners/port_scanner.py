"""
=======================================================================
MODUL 2: ASYNCHRONOUS PORT SCANNER
=======================================================================
Melakukan TCP connect scan pada setiap subdomain aktif.
Fitur: Async scanning, banner grabbing, rate limiting via semaphore.
=======================================================================
"""

import asyncio
import json
import sys
import os
from datetime import datetime, timezone, timedelta

# Tambahkan parent directory ke path agar bisa import config
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


async def grab_banner(reader, timeout=None):
    """
    Mencoba membaca banner dari service yang terbuka.
    Banyak service (SSH, FTP, SMTP) mengirim banner saat koneksi pertama kali dibuat.
    """
    if timeout is None:
        timeout = config.BANNER_GRAB_TIMEOUT
    try:
        banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        # Decode dan bersihkan banner dari karakter non-printable
        banner = banner_bytes.decode("utf-8", errors="ignore").strip()
        # Batasi panjang banner agar output tetap bersih
        return banner[:200] if banner else ""
    except Exception:
        return ""


async def scan_single_port(ip_address, port, semaphore, timeout=None):
    """
    Scan satu port pada satu IP address.
    Menggunakan TCP connect scan (full 3-way handshake).
    
    Returns:
        dict dengan info port jika terbuka, None jika tertutup/filtered.
    """
    if timeout is None:
        timeout = config.PORT_SCAN_TIMEOUT

    async with semaphore:
        try:
            # Buka koneksi TCP ke IP:port
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip_address, port),
                timeout=timeout
            )

            # Port terbuka! Coba ambil banner
            banner = await grab_banner(reader)

            # Tutup koneksi dengan aman
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            service_name = config.COMMON_PORTS.get(port, "Unknown")

            return {
                "port": port,
                "state": "open",
                "service": service_name,
                "banner": banner
            }

        except asyncio.TimeoutError:
            # Port filtered (firewall drop, tidak ada respons)
            return None
        except ConnectionRefusedError:
            # Port tertutup (RST diterima)
            return None
        except OSError:
            # Error jaringan lainnya (unreachable, dll)
            return None
        except Exception:
            return None


async def scan_domain(domain_info, semaphore, ports=None):
    """
    Scan semua port yang ditentukan pada satu domain/IP.
    
    Args:
        domain_info: dict dengan 'domain_name' dan 'ip_address'
        semaphore: asyncio.Semaphore untuk rate limiting
        ports: list port yang akan di-scan (default: semua di config.COMMON_PORTS)
    
    Returns:
        dict hasil scan untuk domain ini
    """
    domain_name = domain_info["domain_name"]
    ip_address = domain_info["ip_address"]

    if ports is None:
        ports = list(config.COMMON_PORTS.keys())

    print(f"  [*] Scanning {domain_name} ({ip_address}) - {len(ports)} ports...")

    # Buat tasks untuk scan setiap port secara paralel
    tasks = [
        scan_single_port(ip_address, port, semaphore)
        for port in ports
    ]

    results = await asyncio.gather(*tasks)

    # Filter hanya port yang terbuka
    open_ports = [r for r in results if r is not None]

    # Hitung waktu sekarang dengan timezone WIB (UTC+7)
    wib = timezone(timedelta(hours=7))
    timestamp = datetime.now(wib).isoformat()

    status_icon = "+" if open_ports else "-"
    print(f"  [{status_icon}] {domain_name}: {len(open_ports)} port terbuka")

    return {
        "domain_name": domain_name,
        "ip_address": ip_address,
        "open_ports": open_ports,
        "total_ports_scanned": len(ports),
        "scan_timestamp": timestamp
    }


async def scan_all(domain_list, max_concurrent=None, ports=None):
    """
    Menjalankan port scan pada seluruh daftar domain.
    
    Args:
        domain_list: list of dict, masing-masing berisi 'domain_name' dan 'ip_address'
        max_concurrent: batas koneksi serentak (default: dari config)
        ports: list port yang akan di-scan (default: semua di config.COMMON_PORTS)
    
    Returns:
        list of dict hasil scan
    """
    if max_concurrent is None:
        max_concurrent = config.MAX_CONCURRENT_CONNECTIONS

    semaphore = asyncio.Semaphore(max_concurrent)

    print(f"\n{'='*60}")
    print(f"  MODUL 2: PORT SCANNER - Memulai Scan")
    print(f"  Target: {len(domain_list)} subdomain")
    print(f"  Ports per target: {len(ports or config.COMMON_PORTS)} ports")
    print(f"  Max concurrent: {max_concurrent}")
    print(f"{'='*60}\n")

    # Scan semua domain secara paralel (dibatasi oleh semaphore)
    tasks = [
        scan_domain(domain_info, semaphore, ports)
        for domain_info in domain_list
    ]

    results = await asyncio.gather(*tasks)

    # Ringkasan
    total_open = sum(len(r["open_ports"]) for r in results)
    domains_with_open = sum(1 for r in results if r["open_ports"])

    print(f"\n{'='*60}")
    print(f"  PORT SCAN SELESAI")
    print(f"  {domains_with_open}/{len(results)} domain memiliki port terbuka")
    print(f"  Total port terbuka: {total_open}")
    print(f"{'='*60}\n")

    return results


def save_results(results, output_path=None):
    """Simpan hasil scan ke file JSON."""
    if output_path is None:
        output_path = config.PORT_SCAN_OUTPUT

    # Pastikan directory ada
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    
    print(f"[+] Hasil port scan disimpan ke: {output_path}")


# =======================================================================
# Standalone execution untuk testing
# =======================================================================
if __name__ == "__main__":
    import argparse

    # Perbaikan Event Loop Windows
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    parser = argparse.ArgumentParser(description="Async Port Scanner - Modul 2")
    parser.add_argument("--input", default=config.INPUT_FILE,
                        help="Path ke file JSON input (default: aset_aktif_undip.json)")
    parser.add_argument("--output", default=config.PORT_SCAN_OUTPUT,
                        help="Path file output JSON")
    parser.add_argument("--limit", type=int, default=0,
                        help="Batasi jumlah domain yang di-scan (0 = semua)")
    parser.add_argument("--concurrent", type=int,
                        default=config.MAX_CONCURRENT_CONNECTIONS,
                        help="Batas koneksi serentak")
    parser.add_argument("--test", action="store_true",
                        help="Mode test: scan hanya 3 domain pertama")
    args = parser.parse_args()

    # Load data domain
    with open(args.input, "r") as f:
        domain_list = json.load(f)

    # Mode test atau limit
    if args.test:
        domain_list = domain_list[:3]
        print("[!] MODE TEST: Hanya scan 3 domain pertama")
    elif args.limit > 0:
        domain_list = domain_list[:args.limit]
        print(f"[!] LIMIT: Hanya scan {args.limit} domain pertama")

    # Jalankan scan
    results = asyncio.run(scan_all(domain_list, max_concurrent=args.concurrent))

    # Simpan hasil
    save_results(results, args.output)
