import asyncio
from celery import Celery
from celery.schedules import crontab
from scrapper import jalankan_sistem
# from scrapper3_subfinder import jalankan_sistem 

# Inisialisasi Celery App (Menghubungkan ke Redis lokal)
app = Celery('asm_discovery', broker='redis://127.0.0.1:6379/0')

#definisi tugas (worker)
@app.task(name='eksekusi_osint_undip')
def run_automated_discovery():
    print("\n[!] CELERY WORKER: Memulai Discovery Engine...")
    
    # Menjalankan fungsi asinkron (jalankan_sistem) di dalam fungsi sinkron Celery
    try:
        asyncio.run(jalankan_sistem())
        print("[!] CELERY WORKER: Tugas OSINT Selesai dieksekusi.\n")
    except Exception as e:
        print(f"[!] CELERY WORKER ERROR: {str(e)}\n")

#definisi jadwal (beat)
app.conf.beat_schedule = {
    'jadwal-mingguan-osint-undip': {
        'task': 'eksekusi_osint_undip',
        # Jadwal: Setiap Hari Minggu (sun) jam 00:00 Tengah Malam
        # 'schedule': crontab(minute=0, hour=0, day_of_week='sun'),
        
        #jika ingin menguji coba sekarang agar jalan setiap 1 menit, 
        #command baris di atas, dan aktifkan baris di bawah ini:
        'schedule': crontab(minute='*/3'), #(*) 
    },
}

# Sesuaikan zona waktu dengan Indonesia
app.conf.timezone = 'Asia/Jakarta'