# ============================================================
# SETUP SCHEDULER - Mendaftarkan Scan Otomatis di Windows
# ============================================================
# Script ini mendaftarkan tugas terjadwal di Windows Task Scheduler
# agar pipeline pentest berjalan otomatis setiap hari/minggu.
#
# CARA PAKAI:
#   Klik kanan file ini > "Run with PowerShell"
#   ATAU jalankan di terminal: powershell -ExecutionPolicy Bypass -File setup_scheduler.ps1
# ============================================================

# --- Konfigurasi ---
$TaskName = "PentestPipeline_UNDIP"
$TaskDescription = "Menjalankan pipeline pentest otomatis untuk aset UNDIP"

# Path ke Python dan script utama
$PythonPath = (Get-Command python).Source
$ScriptPath = Join-Path $PSScriptRoot "main.py"
$WorkingDir = $PSScriptRoot

# --- Pilih Interval ---
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SETUP PENJADWALAN SCAN OTOMATIS" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Pilih interval scan:"
Write-Host "  [1] Setiap HARI (jam 02:00 pagi)"
Write-Host "  [2] Setiap MINGGU (Senin, jam 02:00 pagi)"
Write-Host "  [3] Setiap 12 JAM"
Write-Host ""

$choice = Read-Host "Masukkan pilihan (1/2/3)"

switch ($choice) {
    "1" {
        $Trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
        $IntervalDesc = "Setiap HARI jam 02:00"
    }
    "2" {
        $Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "02:00"
        $IntervalDesc = "Setiap SENIN jam 02:00"
    }
    "3" {
        # Setiap 12 jam: mulai sekarang, ulangi setiap 12 jam tanpa batas
        $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 12)
        $IntervalDesc = "Setiap 12 JAM"
    }
    default {
        Write-Host "[!] Pilihan tidak valid. Menggunakan default: Setiap HARI jam 02:00" -ForegroundColor Yellow
        $Trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
        $IntervalDesc = "Setiap HARI jam 02:00 (default)"
    }
}

# --- Buat Action (perintah yang dijalankan) ---
$Action = New-ScheduledTaskAction `
    -Execute $PythonPath `
    -Argument "`"$ScriptPath`"" `
    -WorkingDirectory $WorkingDir

# --- Pengaturan Tambahan ---
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

# --- Hapus task lama jika ada ---
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "[*] Task lama '$TaskName' dihapus." -ForegroundColor Yellow
}

# --- Daftarkan Task Baru ---
try {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Description $TaskDescription `
        -Trigger $Trigger `
        -Action $Action `
        -Settings $Settings `
        -RunLevel Highest `
        -Force | Out-Null

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "  BERHASIL! Scan otomatis telah dijadwalkan." -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Nama Task  : $TaskName"
    Write-Host "  Interval   : $IntervalDesc"
    Write-Host "  Python     : $PythonPath"
    Write-Host "  Script     : $ScriptPath"
    Write-Host ""
    Write-Host "  Untuk melihat/mengelola jadwal:"
    Write-Host "    1. Buka 'Task Scheduler' di Windows"
    Write-Host "    2. Cari task bernama '$TaskName'"
    Write-Host ""
    Write-Host "  Untuk MENGHAPUS jadwal:"
    Write-Host "    Unregister-ScheduledTask -TaskName '$TaskName'"
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "[ERROR] Gagal mendaftarkan task: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "TIPS: Coba jalankan PowerShell sebagai Administrator (Run as Administrator)." -ForegroundColor Yellow
}

Read-Host "Tekan Enter untuk menutup"
