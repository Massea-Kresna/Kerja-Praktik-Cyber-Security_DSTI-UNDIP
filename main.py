"""
=======================================================================
MAIN PIPELINE ORCHESTRATOR
=======================================================================
Menjalankan seluruh pipeline pentest secara berurutan:
  1. Subdomain Discovery (scrapper.py) — atau load dari file
  2. Port Scanning
  3. Technology Fingerprinting
  4. Vulnerability Assessment
  5. Meng-copy hasil ke dashboard/ untuk visualisasi
=======================================================================
"""

import asyncio
import json
import sys
import os
import shutil
import argparse
from datetime import datetime, timezone, timedelta

# Perbaikan Event Loop Windows
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import config
from scanners import port_scanner, tech_fingerprint, vuln_scanner
import db_manager


def load_domain_list(input_path=None):
    """Load daftar domain dari file JSON."""
    if input_path is None:
        input_path = config.INPUT_FILE
    
    if not os.path.exists(input_path):
        print(f"[-] File input tidak ditemukan: {input_path}")
        print(f"[*] Jalankan scrapper.py terlebih dahulu untuk generate data subdomain.")
        return None

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"[+] Loaded {len(data)} domain dari {input_path}")
    return data


async def run_pipeline(args):
    """Menjalankan seluruh pipeline."""

    wib = timezone(timedelta(hours=7))
    start_time = datetime.now(wib)

    print("=" * 60)
    print("  AUTOMATED PENTEST PIPELINE - STARTING")
    print(f"  Target: {config.TARGET_DOMAIN}")
    print(f"  Waktu: {start_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print("=" * 60)

    # ===================================================================
    # STEP 1: Load Subdomain Data
    # ===================================================================
    print(f"\n{'-'*60}")
    print("  STEP 1/4: Loading Subdomain Data")
    print(f"{'-'*60}")

    domain_list = load_domain_list()
    if domain_list is None:
        return

    if args.limit > 0:
        domain_list = domain_list[:args.limit]
        print(f"[!] LIMIT AKTIF: Hanya proses {args.limit} domain")

    if args.dry_run:
        print(f"\n[DRY RUN] Pipeline akan memproses {len(domain_list)} domain.")
        print(f"[DRY RUN] Modul: Port Scan -> Tech Fingerprint -> Vuln Assessment")
        print(f"[DRY RUN] Output: {config.OUTPUT_DIR}")
        print(f"[DRY RUN] Dashboard: {config.DASHBOARD_DIR}")
        print(f"\n[DRY RUN] Selesai. Jalankan tanpa --dry-run untuk eksekusi nyata.")
        return

    # Pastikan output directory ada
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)

    # ===================================================================
    # STEP 2: Port Scanning
    # ===================================================================
    if not args.skip_portscan:
        print(f"\n{'-'*60}")
        print("  STEP 2/4: Port Scanning")
        print(f"{'-'*60}")

        port_results = await port_scanner.scan_all(
            domain_list,
            max_concurrent=args.concurrent
        )
        port_scanner.save_results(port_results)
    else:
        print(f"\n[SKIP] Port Scanning dilewati.")
        # Coba load dari file yang sudah ada
        if os.path.exists(config.PORT_SCAN_OUTPUT):
            with open(config.PORT_SCAN_OUTPUT, "r") as f:
                port_results = json.load(f)
            print(f"[+] Loaded existing port scan: {len(port_results)} entries")
        else:
            port_results = []

    # ===================================================================
    # STEP 3: Technology Fingerprinting
    # ===================================================================
    if not args.skip_fingerprint:
        print(f"\n{'-'*60}")
        print("  STEP 3/4: Technology Fingerprinting")
        print(f"{'-'*60}")

        tech_results = await tech_fingerprint.analyze_all(
            domain_list,
            max_concurrent=args.concurrent
        )
        tech_fingerprint.save_results(tech_results)
    else:
        print(f"\n[SKIP] Tech Fingerprinting dilewati.")
        if os.path.exists(config.TECH_FINGERPRINT_OUTPUT):
            with open(config.TECH_FINGERPRINT_OUTPUT, "r") as f:
                tech_results = json.load(f)
            print(f"[+] Loaded existing fingerprint: {len(tech_results)} entries")
        else:
            tech_results = []

    # ===================================================================
    # STEP 4: Vulnerability Assessment
    # ===================================================================
    if not args.skip_vulnscan:
        print(f"\n{'-'*60}")
        print("  STEP 4/4: Vulnerability Assessment")
        print(f"{'-'*60}")

        if not tech_results:
            print("[-] Tidak ada data fingerprint. Vulnerability scan memerlukan data dari Modul 3.")
        else:
            vuln_results = await vuln_scanner.assess_all(
                tech_results,
                port_scan_data=port_results,
                max_concurrent=args.concurrent
            )
            vuln_scanner.save_results(vuln_results)
    else:
        print(f"\n[SKIP] Vulnerability Scan dilewati.")

    # ===================================================================
    # STEP 5: Simpan ke PostgreSQL
    # ===================================================================
    print(f"\n{'-'*60}")
    print("  STEP 5/6: Menyimpan ke Database PostgreSQL")
    print(f"{'-'*60}")
    
    # Hanya jalankan jika kita punya setidaknya list domain
    if not args.dry_run and domain_list:
        db_manager.save_all_results(
            domain_list=domain_list,
            port_results=port_results if not args.skip_portscan else [],
            tech_results=tech_results if not args.skip_fingerprint else [],
            vuln_results=vuln_results if not args.skip_vulnscan else []
        )

    # ===================================================================
    # SELESAI
    # ===================================================================
    end_time = datetime.now(wib)
    duration = end_time - start_time

    print(f"\n{'='*60}")
    print("  PIPELINE SELESAI!")
    print(f"  Durasi total: {duration}")
    print(f"  Reports tersimpan di: {config.OUTPUT_DIR}")
    print(f"  Dashboard: Buka {config.DASHBOARD_DIR}/index.html di browser")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Automated Pentest Pipeline - DSTI UNDIP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  python main.py                       # Jalankan full pipeline
  python main.py --dry-run             # Simulasi tanpa eksekusi
  python main.py --limit 5             # Hanya 5 domain pertama
  python main.py --skip-portscan       # Skip port scan, langsung fingerprint
  python main.py --concurrent 30       # Turunkan concurrency (lebih aman)
        """
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulasi pipeline tanpa menjalankan scan")
    parser.add_argument("--limit", type=int, default=0,
                        help="Batasi jumlah domain yang diproses (0 = semua)")
    parser.add_argument("--concurrent", type=int,
                        default=config.MAX_CONCURRENT_CONNECTIONS,
                        help=f"Batas koneksi serentak (default: {config.MAX_CONCURRENT_CONNECTIONS})")
    parser.add_argument("--skip-portscan", action="store_true",
                        help="Skip modul port scanning")
    parser.add_argument("--skip-fingerprint", action="store_true",
                        help="Skip modul tech fingerprinting")
    parser.add_argument("--skip-vulnscan", action="store_true",
                        help="Skip modul vulnerability scanning")
    
    args = parser.parse_args()
    asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    main()
