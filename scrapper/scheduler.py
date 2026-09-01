import asyncio
from scrapper.scrapper3_subfinder import jalankan_sistem

async def run_automated_discovery():
    """Tugas ASYNCIO Native: Memulai OSINT Discovery Engine."""
    print("\n[!] ASYNCIO WORKER: Memulai Discovery Engine...")
    try:
        await jalankan_sistem()
        print("[!] ASYNCIO WORKER: Tugas OSINT Selesai dieksekusi.\n")
    except Exception as e:
        print(f"[!] ASYNCIO WORKER ERROR: {str(e)}\n")

async def osint_scheduler_loop(interval_hours=24):
    """Loop penjadwalan asyncio native tanpa Celery."""
    print("[*] ASYNCIO OSINT Scheduler Started.")
    while True:
        try:
            await run_automated_discovery()
        except Exception as e:
            print(f"[-] Error in osint_scheduler_loop: {e}")
        await asyncio.sleep(interval_hours * 3600)

if __name__ == "__main__":
    asyncio.run(osint_scheduler_loop())