"""
=======================================================================
DSTI UNDIP - Telegram Bot Notifier
=======================================================================
Modul untuk mengirim notifikasi aktivitas user (login, logout, dll)
ke grup/channel Telegram melalui Bot API.

Penggunaan:
  - Pastikan TELEGRAM_BOT_TOKEN dan TELEGRAM_CHAT_ID sudah diisi di .env
  - Import dan panggil fungsi notify_* dari web_app.py
=======================================================================
"""

import httpx
import config
from datetime import datetime, timezone, timedelta


# Timezone WIB (UTC+7)
WIB = timezone(timedelta(hours=7))

# Telegram Bot API base URL
_TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"


async def send_telegram_message(text: str) -> bool:
    """
    Mengirim pesan teks ke chat Telegram yang dikonfigurasi.
    Mengembalikan True jika berhasil, False jika gagal.
    Fungsi ini bersifat fire-and-forget — kegagalan tidak akan
    mengganggu alur utama aplikasi.
    """
    token = config.TELEGRAM_BOT_TOKEN
    chat_id = config.TELEGRAM_CHAT_ID

    if not token or not chat_id:
        # Telegram belum dikonfigurasi, lewati tanpa error
        return False

    url = _TELEGRAM_API_URL.format(token=token)
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                return True
            else:
                print(f"[Telegram] Gagal mengirim pesan. Status: {resp.status_code}, Body: {resp.text}")
                return False
    except Exception as e:
        print(f"[Telegram] Error saat mengirim pesan: {e}")
        return False


def _format_waktu_wib() -> str:
    """Menghasilkan string waktu WIB yang terformat rapi."""
    now = datetime.now(WIB)
    return now.strftime("%d %b %Y, %H:%M WIB")


async def notify_login(username: str, role: str, ip_address: str = "N/A"):
    """
    Mengirim notifikasi login berhasil ke Telegram.
    """
    waktu = _format_waktu_wib()
    text = (
        "🔐 <b>LOGIN — Pentest Dashboard DSTI UNDIP</b>\n"
        "\n"
        f"👤 User: <code>{username}</code>\n"
        f"🎭 Role: {role.capitalize()}\n"
        f"🌐 IP: <code>{ip_address}</code>\n"
        f"🕐 Waktu: {waktu}"
    )
    await send_telegram_message(text)


async def notify_logout(username: str, reason: str = "Logout mandiri"):
    """
    Mengirim notifikasi logout ke Telegram.
    reason bisa berupa: "Logout mandiri", "Force-logout oleh admin",
    "Timeout oleh admin", dll.
    """
    waktu = _format_waktu_wib()
    text = (
        "🚪 <b>LOGOUT — Pentest Dashboard DSTI UNDIP</b>\n"
        "\n"
        f"👤 User: <code>{username}</code>\n"
        f"📋 Alasan: {reason}\n"
        f"🕐 Waktu: {waktu}"
    )
    await send_telegram_message(text)


async def notify_failed_login(username: str, ip_address: str = "N/A"):
    """
    Mengirim notifikasi percobaan login gagal ke Telegram.
    Berguna untuk mendeteksi brute-force.
    """
    waktu = _format_waktu_wib()
    text = (
        "⚠️ <b>LOGIN GAGAL — Pentest Dashboard DSTI UNDIP</b>\n"
        "\n"
        f"👤 Username: <code>{username}</code>\n"
        f"🌐 IP: <code>{ip_address}</code>\n"
        f"🕐 Waktu: {waktu}"
    )
    await send_telegram_message(text)

async def notify_high_risk_scan(domain: str, risk_level: str):
    """
    Mengirim notifikasi ke Telegram jika hasil scan menunjukkan risiko MEDIUM, HIGH, atau CRITICAL.
    """
    waktu = _format_waktu_wib()
    
    # Emoji based on risk
    icon = "🔥" if risk_level.upper() == "CRITICAL" else "⚠️"
    
    text = (
        f"{icon} <b>PERINGATAN KEAMANAN — {risk_level.upper()} RISK</b>\n"
        "\n"
        f"🎯 Target: <code>{domain}</code>\n"
        f"🔴 Tingkat Risiko: <b>{risk_level.upper()}</b>\n"
        f"🕐 Waktu: {waktu}\n"
        "\n"
        "Segera periksa dashboard untuk detail lebih lanjut dan lakukan mitigasi."
    )
    await send_telegram_message(text)
