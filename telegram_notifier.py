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

# Paksa IPv4. api.telegram.org punya alamat IPv6, tetapi di banyak jaringan (termasuk WSL)
# IPv6 tidak tersambung sehingga koneksi menggantung sampai timeout dan pesan tidak terkirim.
def _async_client():
    return httpx.AsyncClient(timeout=10.0, transport=httpx.AsyncHTTPTransport(local_address="0.0.0.0", retries=1))


# Chat ID pengganti bila grup berubah menjadi supergroup (disimpan di memori sampai server restart)
_migrated_chat_id = None


def _explain_error(status: int, data: dict, chat_id: str) -> str:
    desc = (data or {}).get("description", "")
    low = desc.lower()
    if "chat not found" in low:
        return (f"Chat ID {chat_id} tidak ditemukan. Bot belum ada di grup itu atau ID salah. "
                "Jalankan: python telegram_notifier.py cari-chat")
    if "kicked" in low or "not a member" in low or status == 403:
        return f"Bot sudah dikeluarkan atau tidak punya akses ke chat {chat_id}. Masukkan lagi bot ke grup."
    if status == 401:
        return "Token bot tidak valid. Minta token baru di @BotFather lalu ganti TELEGRAM_BOT_TOKEN di .env."
    return f"Status {status}: {desc or 'tidak diketahui'}"


async def send_telegram_message(text: str) -> bool:
    """
    Mengirim pesan teks ke chat Telegram yang dikonfigurasi.
    Mengembalikan True jika berhasil, False jika gagal. Kegagalan tidak mengganggu alur utama aplikasi.
    Bila grup sudah berubah menjadi supergroup, pesan dikirim ulang ke Chat ID baru
    dan log memberi tahu nilai yang harus ditulis ke .env.
    """
    global _migrated_chat_id
    token = config.TELEGRAM_BOT_TOKEN
    chat_id = _migrated_chat_id or config.TELEGRAM_CHAT_ID

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
        async with _async_client() as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                return True
            try:
                data = resp.json()
            except Exception:
                data = {}
            new_id = ((data or {}).get("parameters") or {}).get("migrate_to_chat_id")
            if new_id:
                _migrated_chat_id = str(new_id)
                print(f"[Telegram] Grup sudah berubah menjadi supergroup. Chat ID baru: {new_id}. "
                      f"Ganti TELEGRAM_CHAT_ID di .env menjadi {new_id} supaya permanen.")
                payload["chat_id"] = _migrated_chat_id
                retry = await client.post(url, json=payload)
                return retry.status_code == 200
            print(f"[Telegram] Gagal mengirim pesan. {_explain_error(resp.status_code, data, chat_id)}")
            return False
    except Exception as e:
        print(f"[Telegram] Tidak bisa menghubungi api.telegram.org: {e}")
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
        "🔐 <b>LOGIN: Pentest Dashboard DSTI UNDIP</b>\n"
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
        "🚪 <b>LOGOUT: Pentest Dashboard DSTI UNDIP</b>\n"
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
        "⚠️ <b>LOGIN GAGAL: Pentest Dashboard DSTI UNDIP</b>\n"
        "\n"
        f"👤 Username: <code>{username}</code>\n"
        f"🌐 IP: <code>{ip_address}</code>\n"
        f"🕐 Waktu: {waktu}"
    )
    await send_telegram_message(text)

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _esc(text) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_high_risk_message(domain: str, risk_level: str, waktu: str, summary: dict = None) -> str:
    """Susun pesan peringatan scan HIGH/CRITICAL (format HTML Telegram).

    Baris pertama berisi tingkat risiko dan domain karena itu yang tampil di
    pratinjau notifikasi. Angka dan judul temuan hanya ditulis bila `summary`
    tersedia, supaya pesan tidak pernah berisi data karangan.
    """
    lines = [f"<b>{_esc(str(risk_level).upper())}</b> · <code>{_esc(domain)}</code>"]
    if not summary:
        lines.append(f"Scan selesai {waktu}")
    else:
        jenis = "Network scan" if "network" in str(summary.get("scan_type") or "").lower() else "Website scan"
        lines.append(f"{jenis}, {waktu}")
        counts = summary.get("counts") or {}
        parts = [f"{counts[k]} {k.capitalize()}" for k in _SEV_ORDER if counts.get(k)]
        if parts:
            lines += ["", "Temuan: " + ", ".join(parts)]
        top = summary.get("top") or []
        for item in top[:3]:
            cves = [str(c) for c in (item.get("cve") or [])]
            cve_txt = ""
            if cves:
                shown = ", ".join(cves[:3]) + (f", +{len(cves) - 3} lain" if len(cves) > 3 else "")
                cve_txt = f" ({_esc(shown)})"
            lines.append(f"{str(item.get('severity', '')).capitalize()}: {_esc(item.get('title', ''))}{cve_txt}")
        if len(top) > 3:
            lines.append(f"dan {len(top) - 3} temuan {str(risk_level).capitalize()} lain")
    lines += ["", "Rincian dan rekomendasi perbaikan ada di dashboard, menu Scan History."]
    return "\n".join(lines)


def _latest_scan_summary(domain: str, risk_level: str):
    """Ringkasan scan terbaru sebuah domain (hanya membaca database). None bila tidak cocok atau gagal."""
    try:
        import db_manager
        conn = db_manager.get_db_connection()
        if not conn:
            return None
        try:
            with conn.cursor(cursor_factory=db_manager.RealDictCursor) as cur:
                cur.execute(
                    """SELECT h.id, h.risk_level FROM scan_history h JOIN domains d ON h.domain_id = d.id
                       WHERE d.domain_name = %s AND h.scan_date > NOW() - INTERVAL '6 hours'
                       ORDER BY h.scan_date DESC LIMIT 1""",
                    (db_manager.normalize_domain_name(domain),),
                )
                row = cur.fetchone()
                if not row or str(row["risk_level"]).upper() != str(risk_level).upper():
                    return None
                cur.execute("SELECT severity, check_type, title, cve FROM scan_result WHERE history_id = %s", (row["id"],))
                results = cur.fetchall()
        finally:
            conn.close()
    except Exception as e:
        print(f"[-] Ringkasan scan untuk Telegram gagal dibaca: {e}")
        return None
    if not results:
        return None

    def cve_list(v):
        if isinstance(v, (list, tuple)):
            items = v
        else:
            items = str(v or "").strip("{}").split(",")
        return [str(c).strip().strip('"') for c in items if str(c).strip().strip('"') not in ("", "-1")]

    counts = {}
    for r in results:
        k = str(r["severity"] or "").lower()
        counts[k] = counts.get(k, 0) + 1
    level = str(risk_level).upper()
    seen, top = set(), []
    for r in results:
        if str(r["severity"] or "").upper() == level and r["title"] not in seen:
            seen.add(r["title"])
            top.append({"severity": level, "title": r["title"], "cve": cve_list(r["cve"])})
    return {"scan_type": results[0].get("check_type"), "counts": counts, "top": top}


async def notify_high_risk_scan(domain: str, risk_level: str):
    """
    Mengirim notifikasi ke Telegram jika hasil scan menunjukkan risiko HIGH atau CRITICAL.
    """
    if str(risk_level).upper() not in ["HIGH", "CRITICAL"]:
        return

    summary = _latest_scan_summary(domain, risk_level)
    text = build_high_risk_message(domain, risk_level, _format_waktu_wib(), summary)
    await send_telegram_message(text)



# =======================================================================
# Perintah bantu untuk menyambungkan bot dari BotFather
#   python telegram_notifier.py cek        cek token dan Chat ID di .env
#   python telegram_notifier.py cari-chat  tampilkan Chat ID dari pesan terbaru ke bot
#   python telegram_notifier.py uji        kirim pesan uji ke Chat ID di .env
# =======================================================================
def _cli():
    import sys
    import asyncio

    token = config.TELEGRAM_BOT_TOKEN
    chat_id = config.TELEGRAM_CHAT_ID
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cek"
    api = f"https://api.telegram.org/bot{token}"

    if not token:
        print("TELEGRAM_BOT_TOKEN di .env masih kosong. Isi dengan token dari @BotFather.")
        return

    def call(method, **params):
        try:
            with httpx.Client(timeout=15, transport=httpx.HTTPTransport(local_address="0.0.0.0")) as cl:
                r = cl.get(f"{api}/{method}", params=params)
            return r.json()
        except Exception as e:
            print(f"Tidak bisa menghubungi api.telegram.org: {e}")
            print("Cek koneksi internet server, atau apakah jaringan kantor memblokir Telegram.")
            sys.exit(1)

    me = call("getMe")
    if not me.get("ok"):
        print(f"Token ditolak Telegram: {me.get('description', 'tidak diketahui')}")
        print("Minta token baru di @BotFather (/mybots > pilih bot > API Token) lalu ganti di .env.")
        return
    print(f"Token valid. Bot: @{me['result'].get('username')}")

    if cmd == "cari-chat":
        upd = call("getUpdates")
        chats = {}
        for u in upd.get("result", []):
            msg = u.get("message") or u.get("channel_post") or u.get("my_chat_member") or {}
            chat = msg.get("chat") or {}
            if chat.get("id") is not None:
                chats[chat["id"]] = (chat.get("type"), chat.get("title") or chat.get("first_name") or "")
        if not chats:
            print("Belum ada pesan. Kirim pesan apa saja ke bot (atau ke grup yang berisi bot), lalu jalankan lagi.")
            return
        print("Chat yang terlihat oleh bot (salin ID ke TELEGRAM_CHAT_ID di .env):")
        for cid, (typ, name) in chats.items():
            print(f"  {cid}  [{typ}]  {name}")
        return

    if not chat_id:
        print("TELEGRAM_CHAT_ID di .env masih kosong. Jalankan: python telegram_notifier.py cari-chat")
        return
    chat = call("getChat", chat_id=chat_id)
    new_id = (chat.get("parameters") or {}).get("migrate_to_chat_id")
    if new_id:
        print(f"Grup sudah berubah menjadi supergroup. Chat ID lama {chat_id} tidak berlaku lagi.")
        print(f"Ganti TELEGRAM_CHAT_ID di .env menjadi: {new_id}")
        return
    if not chat.get("ok"):
        print(f"Chat ID {chat_id} tidak bisa diakses bot: {chat.get('description')}")
        print("Pastikan bot sudah dimasukkan ke grup, lalu jalankan: python telegram_notifier.py cari-chat")
        return
    res = chat["result"]
    print(f"Chat ID valid: {res.get('title') or res.get('first_name')} [{res.get('type')}]")

    if cmd == "uji":
        ok = asyncio.run(send_telegram_message(
            "✅ <b>Uji koneksi Pentest Dashboard DSTI UNDIP</b>\n\n"
            f"Bot berhasil tersambung.\n🕐 {_format_waktu_wib()}"
        ))
        print("Pesan uji terkirim. Cek Telegram." if ok else "Pesan uji gagal dikirim, lihat pesan error di atas.")


if __name__ == "__main__":
    _cli()
