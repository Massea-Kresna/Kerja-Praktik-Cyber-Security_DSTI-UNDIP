"""
=======================================================================
DSTI UNDIP - Pentest Dashboard API & Web Server
=======================================================================
FastAPI backend yang melayani:
  1. API endpoints (query dari Supabase DB)
  2. Static files untuk dashboard frontend
  3. Fallback ke file JSON lokal jika Supabase belum dikonfigurasi
=======================================================================
"""

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query, Depends, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import db_manager
import config
import asyncio
import aiohttp
import httpx
import uuid
import os
import json
import requests
from typing import List, Optional

from datetime import datetime, timedelta, timezone
from scanner.pentest_tools_scheduler import process_domain_scan
from scanner.pentest_tools_scheduler import process_network_scan
from typing import List

app = FastAPI(title="DSTI UNDIP Pentest Dashboard API")

# Seeding admin secara otomatis saat file dimuat
db_manager.seed_default_admin()

class LoginRequest(BaseModel):
    username: str
    password: str
    recaptcha_token: Optional[str] = None
    remember_me: Optional[bool] = False

class VerifyOTPRequest(BaseModel):
    username: str
    otp: str
    remember_me: Optional[bool] = False

# ===================================================================
# In-Memory OTP Storage
# ===================================================================
OTP_STORE = {}

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import random

def send_otp_email(to_email: str, otp: str):
    if not config.SMTP_USERNAME or not config.SMTP_PASSWORD:
        print("[-] SMTP tidak dikonfigurasi. Lewati pengiriman email.")
        return False
        
    msg = MIMEMultipart()
    # Mengatur nama pengirim agar terlihat profesional
    msg['From'] = f"UNDIP Security Dashboard <{config.SMTP_USERNAME}>"
    msg['To'] = to_email
    msg['Subject'] = "Kode OTP Login Pentest Dashboard"
    
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Kode Autentikasi Login</h2>
        <p>Anda mencoba untuk login ke Pentest Dashboard. Berikut adalah kode OTP Anda:</p>
        <div style="background-color: #f3f4f6; padding: 16px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 4px; border-radius: 8px;">
            {otp}
        </div>
        <p style="color: #6b7280; font-size: 12px; margin-top: 16px;">Kode ini akan kadaluarsa dalam 5 menit. Jika Anda tidak meminta kode ini, abaikan email ini.</p>
    </div>
    """
    msg.attach(MIMEText(html_content, 'html'))
    
    try:
        if config.SMTP_PORT == 465:
            # Menggunakan SSL secara implisit (biasanya untuk port 465)
            server = smtplib.SMTP_SSL(config.SMTP_SERVER, config.SMTP_PORT)
        else:
            # Menggunakan koneksi biasa lalu di-upgrade dengan TLS (biasanya port 587)
            server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
            server.starttls() 
            
        server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[-] Gagal mengirim email OTP: {e}")
        return False

# ===================================================================
# WebSocket Connection Manager untuk Admin & Session Live Updates
# ===================================================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.user_info: dict[WebSocket, dict] = {}

    def connect_user(self, websocket: WebSocket, username: str, role: str):
        self.active_connections.append(websocket)
        self.user_info[websocket] = {"username": username, "role": role}

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.user_info:
            del self.user_info[websocket]

    async def broadcast_to_admins(self, message: dict):
        for conn in list(self.active_connections):
            info = self.user_info.get(conn)
            if info and info.get("role") == "admin":
                try:
                    await conn.send_json(message)
                except Exception:
                    pass

    async def kick_user(self, username: str, reason: str = "force_logout"):
        for conn in list(self.active_connections):
            info = self.user_info.get(conn)
            if info and info.get("username") == username:
                try:
                    await conn.send_json({"event": reason})
                    await conn.close(code=4000)
                except Exception:
                    pass

manager = ConnectionManager()

# ===================================================================
# Pydantic Schemas untuk Auth
# ===================================================================
class UserRegister(BaseModel):
    username: str
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class TimeoutRequest(BaseModel):
    minutes: int
    remember_me: Optional[bool] = False

# ===================================================================
# Auth Dependencies
# ===================================================================
def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="Session tidak ditemukan. Silakan login kembali.")
    
    # Cari user berdasarkan session_id
    user = db_manager.get_user_by_session_id(session_id)
                
    if not user:
        raise HTTPException(status_code=401, detail="Session tidak valid atau telah berakhir. Silakan login kembali.")
        
    # Cek apakah user sedang dalam timeout
    timeout_until_str = user.get("timeout_until")
    if timeout_until_str:
        try:
            # Menggunakan timezone-aware datetime parsing
            # Python 3.11+ mendukung format ISO dengan offset Z/+07:00 via fromisoformat
            timeout_until = datetime.fromisoformat(timeout_until_str.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            if timeout_until > now:
                # Force logout
                db_manager.update_user_session(user["username"], None, False)
                
                # Format waktu sisa penangguhan untuk respon yang ramah
                sisa_detik = int((timeout_until - now).total_seconds())
                menit = sisa_detik // 60
                detik = sisa_detik % 60
                detail_msg = f"Admin telah menangguhkan akun anda, hubungi admin untuk informasi lebih lanjut.\nWaktu sisa penangguhan: {menit} menit {detik} detik"
                raise HTTPException(status_code=403, detail=detail_msg)
        except HTTPException as he:
            raise he
        except Exception as e:
            print(f"[-] Parse timeout_until error: {e}")
            
    # Perbarui last_online ke waktu sekarang
    db_manager.update_user_session(user["username"], session_id, True)
    return user

def get_current_admin(user = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Akses ditolak. Endpoint ini hanya untuk Admin.")
    return user


# ===================================================================
# CORS Middleware — agar frontend bisa mengakses API
# ===================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===================================================================
# Static Files — melayani dashboard frontend
# ===================================================================
DASHBOARD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard")
os.makedirs(DASHBOARD_PATH, exist_ok=True)


def _get_supabase_or_none():
    """Mendapatkan status koneksi database (Postgres)"""
    return db_manager.check_db_connection()


# ===================================================================
# API: Authentication & Session Endpoints
# ===================================================================
@app.post("/api/auth/register")
def register_user(user_data: UserRegister, admin_user = Depends(get_current_admin)):
    """Mendaftarkan user baru"""
    # Cek apakah username sudah ada
    existing = db_manager.get_user_by_username(user_data.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username sudah terdaftar.")
        
    try:
        db_manager.create_user(user_data.username, user_data.password, user_data.role)
        return {"status": "ok", "message": "Pendaftaran berhasil."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gagal melakukan registrasi: {str(e)}")

@app.post("/api/auth/login")
async def login(credentials: LoginRequest, response: Response):
    # 1. Validasi reCAPTCHA ke Google
    secret_key = config.RECAPTCHA_SECRET_KEY
    verify_url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {
        "secret": secret_key,
        "response": credentials.recaptcha_token
    }
    
    # Ubah nama variabel agar tidak bentrok dengan 'response' bawaan FastAPI
    recaptcha_result = requests.post(verify_url, data=payload).json()
    
    # TAMBAHKAN BARIS INI UNTUK DEBUGGING:
    print("Jawaban dari Google:", recaptcha_result)
    
    if not recaptcha_result.get("success"):
        error_codes = recaptcha_result.get("error-codes", [])
        raise HTTPException(status_code=400, detail=f"Verifikasi reCAPTCHA gagal. Google Error: {error_codes}")
    
    # 2. Cek Username dan Password ke Database (Menggunakan fungsi bawaan db_manager)
    user = db_manager.get_user_by_username(credentials.username)
    
    # Cek apakah user ditemukan dan apakah password hash-nya cocok
    if not user or not db_manager.verify_password(credentials.password, user.get("password")):
        raise HTTPException(status_code=401, detail="Username atau password salah.")
        
    # 3. Cek timeout
    timeout_until_str = user.get("timeout_until")
    if timeout_until_str:
        try:
            timeout_until = datetime.fromisoformat(timeout_until_str.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            if timeout_until > now:
                sisa_detik = int((timeout_until - now).total_seconds())
                menit = sisa_detik // 60
                detik = sisa_detik % 60
                raise HTTPException(status_code=403, detail=f"Admin telah menangguhkan akun anda, hubungi admin untuk informasi lebih lanjut.\nWaktu sisa penangguhan: {menit} menit {detik} detik")
        except HTTPException as he:
            raise he
        except Exception:
            pass
    # 4. Cek Role. OTP hanya untuk admin
    user_role = user.get("role", "user")
    if user_role == "admin":
        # 5a. Generate OTP untuk Admin
        otp_code = str(random.randint(100000, 999999))
        OTP_STORE[credentials.username] = {
            "otp": otp_code,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
        }
        
        # Kirim OTP Email
        target_email = credentials.username
        if target_email == "admin":
            target_email = config.ADMIN_EMAIL if config.ADMIN_EMAIL else "admin@undip.ac.id"
            
        success = send_otp_email(target_email, otp_code)
        
        if not success:
            print(f"[!] Email gagal dikirim ke {target_email}. OTP untuk {credentials.username} adalah: {otp_code}")
            
        return {"status": "otp_required", "message": "Kode OTP telah dikirim ke email Anda."}
    else:
        # 5b. Bypass OTP untuk User Biasa
        session_id = str(uuid.uuid4())
        db_manager.update_user_session(credentials.username, session_id, True)
        
        cookie_max_age = 2592000 if credentials.remember_me else 86400
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=cookie_max_age
        )
        
        return {
            "status": "success",
            "message": "Login berhasil",
            "user": {
                "username": user["username"],
                "role": user["role"],
                "session_id": session_id
            }
        }

@app.post("/api/auth/verify_otp")
async def verify_otp(req: VerifyOTPRequest, response: Response):
    # Cek ketersediaan OTP
    if req.username not in OTP_STORE:
        raise HTTPException(status_code=400, detail="Sesi OTP tidak ditemukan atau sudah kadaluarsa. Silakan login kembali.")
        
    otp_data = OTP_STORE[req.username]
    
    # Cek kedaluwarsa
    if datetime.now(timezone.utc) > otp_data["expires_at"]:
        del OTP_STORE[req.username]
        raise HTTPException(status_code=400, detail="Kode OTP sudah kadaluarsa. Silakan login kembali.")
        
    # Cek kecocokan OTP
    if otp_data["otp"] != req.otp:
        raise HTTPException(status_code=401, detail="Kode OTP salah.")
        
    # OTP Valid! Hapus dari store
    del OTP_STORE[req.username]
    
    # Buat session baru
    session_id = str(uuid.uuid4())
    db_manager.update_user_session(req.username, session_id, True)
    
    # Simpan di cookie
    cookie_max_age = 2592000 if req.remember_me else 86400
    response.set_cookie(
        key="session_id", 
        value=session_id, 
        httponly=True, 
        max_age=cookie_max_age, 
        samesite="lax",
        path="/"
    )
    
    # Dapatkan role user untuk kembalian
    user_data = db_manager.get_user_by_username(req.username)
    role = user_data["role"] if user_data else "admin"
    
    # Broadcast User Login event (to update user tables etc)
    await manager.broadcast_to_admins({
        "event": "user_login",
        "username": req.username,
        "session_id": session_id,
        "login_time": datetime.now(config.WIB).isoformat()
    })
    
    return {"username": req.username, "role": role, "session_id": session_id}

@app.post("/api/auth/logout")
def logout_user(response: Response, current_user = Depends(get_current_user)):
    """Mengakhiri session login user"""
    db_manager.update_user_session(current_user["username"], None, False)
    response.delete_cookie(key="session_id", path="/")
    return {"status": "ok", "message": "Logout berhasil."}

@app.get("/api/auth/me")
def get_me(current_user = Depends(get_current_user)):
    """Mendapatkan profil login aktif"""
    return {
        "username": current_user["username"],
        "role": current_user["role"],
        "session_id": current_user["session_id"]
    }

# ===================================================================
# API: Admin Panel Endpoints (Hanya untuk Admin)
# ===================================================================
@app.get("/api/admin/users")
def get_users(admin_user = Depends(get_current_admin)):
    """Mendapatkan daftar seluruh user untuk Admin Page"""
    users = db_manager.list_all_users()
    return {"status": "ok", "data": users}

@app.post("/api/admin/users/{target_username}/force-logout")
async def force_logout(target_username: str, admin_user = Depends(get_current_admin)):
    """Memaksa logout salah satu user"""
    db_manager.update_user_session(target_username, None, False)
    await manager.kick_user(target_username, "force_logout")
    return {"status": "ok", "message": f"User '{target_username}' berhasil di-force logout."}

@app.post("/api/admin/users/{target_username}/timeout")
async def put_user_timeout(target_username: str, req: TimeoutRequest, admin_user = Depends(get_current_admin)):
    """Menangguhkan user selama rentang waktu tertentu"""
    timeout_time = (datetime.now(timezone.utc) + timedelta(minutes=req.minutes)).isoformat()
    db_manager.update_user_timeout(target_username, timeout_time)
    await manager.kick_user(target_username, "timeout")
    return {"status": "ok", "message": f"User '{target_username}' ditangguhkan selama {req.minutes} menit."}

@app.post("/api/admin/users/{target_username}/remove-timeout")
def remove_user_timeout(target_username: str, admin_user = Depends(get_current_admin)):
    """Mencabut penangguhan (timeout) user"""
    db_manager.update_user_timeout(target_username, None)
    return {"status": "ok", "message": f"Timeout untuk user '{target_username}' berhasil dicabut."}

@app.delete("/api/admin/users/{target_username}")
async def delete_user_endpoint(target_username: str, admin_user = Depends(get_current_admin)):
    """Menghapus user secara permanen"""
    if target_username == admin_user["username"]:
        raise HTTPException(status_code=400, detail="Anda tidak dapat menghapus akun Anda sendiri.")
        
    success = db_manager.delete_user(target_username)
    if not success:
        raise HTTPException(status_code=404, detail=f"User '{target_username}' tidak ditemukan.")
        
    # Kick target user out immediately if they are online
    await manager.kick_user(target_username, "force_logout")
    return {"status": "ok", "message": f"User '{target_username}' berhasil dihapus."}

# ===================================================================
# WebSocket: Real-time Live Session Updates (Admin & Users)
# ===================================================================
@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket, session_id: Optional[str] = Query(None)):
    """Koneksi WebSocket untuk real-time updates (admin notif & user force logout/timeout)"""
    await websocket.accept()
    
    if not session_id:
        await websocket.close(code=4003)
        return
        
    # Validasi session_id
    user = db_manager.get_user_by_session_id(session_id)
                
    if not user:
        await websocket.close(code=4003)
        return
        
    manager.connect_user(websocket, user["username"], user["role"])
    try:
        while True:
            # Jaga agar WebSocket tetap terbuka (ping/pong)
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

# ===================================================================
# ROOT — Redirect ke dashboard
# ===================================================================
@app.get("/")
def root():
    """Redirect ke dashboard"""
    return RedirectResponse(url="/dashboard/index.html")


# ===================================================================
# API: Health Check
# ===================================================================
@app.get("/api/health")
def health_check():
    """Health check endpoint — cek status server dan koneksi database"""
    db_connected = db_manager.check_db_connection()
    return {
        "status": "ok",
        "database": {
            "connected": db_connected,
            "message": "Terhubung ke PostgreSQL" if db_connected else "Gagal terhubung ke PostgreSQL"
        },
        "data_source": "postgresql"
    }



# ===================================================================
# API: Dashboard Stats (dari Supabase, fallback ke lokal)
# ===================================================================
@app.get("/api/dashboard-stats")
def get_dashboard_stats(current_user = Depends(get_current_user)):
    """Mengambil statistik dasar dan riwayat scan terbaru"""
    if not db_manager.check_db_connection():
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        total_domains = db_manager.get_total_domains()
        total_vulns = db_manager.get_total_vulnerabilities()
        recent_scans = db_manager.get_recent_scans_history(10)
        stats_resp = db_manager.get_recent_risk_levels(100)
        
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
        for row in stats_resp:
            r_level = row.get("risk_level", "SAFE")
            if r_level in stats:
                stats[r_level] += 1

        return {
            "source": "postgresql",
            "total_domains": total_domains,
            "total_vulnerabilities": total_vulns,
            "risk_distribution": stats,
            "recent_scans": recent_scans
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ===================================================================
# API: Trend Stats (Line Chart) - By Domain
# ===================================================================
@app.get("/api/trend-stats")
def get_trend_stats(start_date: str | None = Query(None), end_date: str | None = Query(None), current_user = Depends(get_current_user)):
    """Mengambil data tren kerentanan per domain"""
    if not db_manager.check_db_connection():
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        import math
        wib_tz = timezone(timedelta(hours=7))
        now_utc = datetime.now(timezone.utc)
        now_wib = now_utc.astimezone(wib_tz)
        
        if not start_date or not end_date:
            days_diff = 1
            interval_minutes = 30
            num_buckets = 48
            minute_snapped = 30 if now_wib.minute >= 30 else 0
            end_snapped_wib = now_wib.replace(minute=minute_snapped, second=0, microsecond=0)
            start_snapped_wib = end_snapped_wib - timedelta(hours=24)
            date_format = "%H:%M"
        else:
            try:
                start_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=wib_tz)
                end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=wib_tz)
                if end_dt > now_wib:
                    end_dt = now_wib
                    
                delta = end_dt - start_dt
                days_diff = delta.total_seconds() / 86400
                
                if days_diff <= 1:
                    interval_minutes = 30
                    date_format = "%H:%M"
                elif days_diff <= 3:
                    interval_minutes = 60
                    date_format = "%d %b %H:%M"
                elif days_diff <= 7:
                    interval_minutes = 4 * 60
                    date_format = "%d %b %H:%M"
                elif days_diff <= 14:
                    interval_minutes = 12 * 60
                    date_format = "%d %b %H:%M"
                else:
                    interval_minutes = 24 * 60
                    date_format = "%d %b %Y"

                if days_diff <= 14:
                    num_buckets = int(math.ceil((days_diff * 24 * 60) / interval_minutes))
                    if interval_minutes < 60:
                        minute_snapped = 30 if end_dt.minute >= 30 else 0
                        end_snapped_wib = end_dt.replace(minute=minute_snapped, second=0, microsecond=0)
                    else:
                        hour_interval = interval_minutes // 60
                        hour_snapped = (end_dt.hour // hour_interval) * hour_interval
                        end_snapped_wib = end_dt.replace(hour=hour_snapped, minute=0, second=0, microsecond=0)
                    start_snapped_wib = end_snapped_wib - timedelta(minutes=num_buckets * interval_minutes)
                else:
                    num_buckets = max(1, math.ceil(days_diff))
                    end_snapped_wib = end_dt.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
                    start_snapped_wib = end_snapped_wib - timedelta(days=num_buckets)
            except ValueError:
                raise HTTPException(status_code=400, detail="Format tanggal tidak valid. Gunakan YYYY-MM-DD.")
        
        start_time_iso = start_snapped_wib.astimezone(timezone.utc).isoformat()
        end_time_iso = end_snapped_wib.astimezone(timezone.utc).isoformat()
        
        scans = db_manager.get_trend_scans(start_time_iso, end_time_iso)
        
        labels = []
        raw_labels = []
        for i in range(num_buckets + 1):
            bucket_time_wib = start_snapped_wib + timedelta(minutes=i*interval_minutes)
            labels.append(bucket_time_wib.strftime(date_format))
            raw_labels.append(bucket_time_wib.isoformat())
            
        all_domains = [d.get("domain_name") for d in db_manager.get_all_domains()]
            
        domains_data = {domain: [0] * (num_buckets + 1) for domain in all_domains}
        
        for scan in scans:
            domain_name = scan.get("domains", {}).get("domain_name", "Unknown")
            scan_date_str = scan.get("scan_date")
            if not scan_date_str:
                continue
            try:
                scan_date_utc = datetime.fromisoformat(scan_date_str)
                scan_date_wib = scan_date_utc.astimezone(wib_tz)
            except Exception:
                continue
                
            delta = scan_date_wib - start_snapped_wib
            bucket_index = int(delta.total_seconds() // (interval_minutes * 60))
            
            if 0 <= bucket_index <= num_buckets:
                if domain_name not in domains_data:
                    domains_data[domain_name] = [0] * (num_buckets + 1)
                
                vuln_count = len(scan.get("scan_result") or [])
                raw_json = scan.get("raw_json")
                if isinstance(raw_json, list):
                    vuln_count += len(raw_json)
                domains_data[domain_name][bucket_index] += vuln_count

        return {
            "source": "postgresql",
            "labels": labels,
            "raw_labels": raw_labels,
            "datasets": [
                {
                    "label": domain,
                    "data": data,
                }
                for domain, data in domains_data.items()
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ===================================================================
# API: Severity Trend Stats (Line Chart)
# ===================================================================
@app.get("/api/severity-trend-stats")
def get_severity_trend_stats(start_date: str | None = Query(None), end_date: str | None = Query(None), current_user = Depends(get_current_user)):
    """Mengambil data tren kerentanan berdasarkan severity"""
    if not db_manager.check_db_connection():
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        import math
        wib_tz = timezone(timedelta(hours=7))
        now_utc = datetime.now(timezone.utc)
        now_wib = now_utc.astimezone(wib_tz)
        
        if not start_date or not end_date:
            days_diff = 1
            interval_minutes = 30
            num_buckets = 48
            minute_snapped = 30 if now_wib.minute >= 30 else 0
            end_snapped_wib = now_wib.replace(minute=minute_snapped, second=0, microsecond=0)
            start_snapped_wib = end_snapped_wib - timedelta(hours=24)
            date_format = "%H:%M"
        else:
            try:
                start_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=wib_tz)
                end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=wib_tz)
                if end_dt > now_wib:
                    end_dt = now_wib
                    
                delta = end_dt - start_dt
                days_diff = delta.total_seconds() / 86400
                
                if days_diff <= 1:
                    interval_minutes = 30
                    date_format = "%H:%M"
                elif days_diff <= 3:
                    interval_minutes = 60
                    date_format = "%d %b %H:%M"
                elif days_diff <= 7:
                    interval_minutes = 4 * 60
                    date_format = "%d %b %H:%M"
                elif days_diff <= 14:
                    interval_minutes = 12 * 60
                    date_format = "%d %b %H:%M"
                else:
                    interval_minutes = 24 * 60
                    date_format = "%d %b %Y"

                if days_diff <= 14:
                    num_buckets = int(math.ceil((days_diff * 24 * 60) / interval_minutes))
                    if interval_minutes < 60:
                        minute_snapped = 30 if end_dt.minute >= 30 else 0
                        end_snapped_wib = end_dt.replace(minute=minute_snapped, second=0, microsecond=0)
                    else:
                        hour_interval = interval_minutes // 60
                        hour_snapped = (end_dt.hour // hour_interval) * hour_interval
                        end_snapped_wib = end_dt.replace(hour=hour_snapped, minute=0, second=0, microsecond=0)
                    start_snapped_wib = end_snapped_wib - timedelta(minutes=num_buckets * interval_minutes)
                else:
                    num_buckets = max(1, math.ceil(days_diff))
                    end_snapped_wib = end_dt.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
                    start_snapped_wib = end_snapped_wib - timedelta(days=num_buckets)
            except ValueError:
                raise HTTPException(status_code=400, detail="Format tanggal tidak valid. Gunakan YYYY-MM-DD.")
        
        start_time_iso = start_snapped_wib.astimezone(timezone.utc).isoformat()
        end_time_iso = end_snapped_wib.astimezone(timezone.utc).isoformat()
        
        scans = db_manager.get_trend_scans(start_time_iso, end_time_iso)
        
        labels = []
        raw_labels = []
        for i in range(num_buckets + 1):
            bucket_time_wib = start_snapped_wib + timedelta(minutes=i*interval_minutes)
            labels.append(bucket_time_wib.strftime(date_format))
            raw_labels.append(bucket_time_wib.isoformat())
            
        severities_data = {
            "CRITICAL": [0] * (num_buckets + 1),
            "HIGH": [0] * (num_buckets + 1),
            "MEDIUM": [0] * (num_buckets + 1),
            "LOW": [0] * (num_buckets + 1),
            "INFO": [0] * (num_buckets + 1),
        }
        
        domains_by_sev = {
            "CRITICAL": [{} for _ in range(num_buckets + 1)],
            "HIGH": [{} for _ in range(num_buckets + 1)],
            "MEDIUM": [{} for _ in range(num_buckets + 1)],
            "LOW": [{} for _ in range(num_buckets + 1)],
            "INFO": [{} for _ in range(num_buckets + 1)],
        }
        
        for scan in scans:
            domain_name = scan.get("domains", {}).get("domain_name", "Unknown")
            scan_date_str = scan.get("scan_date")
            if not scan_date_str:
                continue
            try:
                scan_date_utc = datetime.fromisoformat(scan_date_str)
                scan_date_wib = scan_date_utc.astimezone(wib_tz)
            except Exception:
                continue
                
            delta = scan_date_wib - start_snapped_wib
            bucket_index = int(delta.total_seconds() // (interval_minutes * 60))
            
            if 0 <= bucket_index <= num_buckets:
                vulns = scan.get("scan_result") or []
                for v in vulns:
                    sev = (v.get("severity") or "").upper()
                    if sev in severities_data:
                        severities_data[sev][bucket_index] += 1
                        domains_by_sev[sev][bucket_index][domain_name] = domains_by_sev[sev][bucket_index].get(domain_name, 0) + 1
                        
                raw_json = scan.get("raw_json")
                if isinstance(raw_json, list):
                    for v in raw_json:
                        sev = (v.get("severity") or "").upper()
                        if sev in severities_data:
                            severities_data[sev][bucket_index] += 1
                            domains_by_sev[sev][bucket_index][domain_name] = domains_by_sev[sev][bucket_index].get(domain_name, 0) + 1

        return {
            "source": "postgresql",
            "labels": labels,
            "raw_labels": raw_labels,
            "datasets": [
                {
                    "label": sev.capitalize(),
                    "data": data,
                    "domains": domains_by_sev[sev]
                }
                for sev, data in severities_data.items()
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ===================================================================
# API: Daftar Semua Domain (dari Supabase)
# ===================================================================
@app.get("/api/domains")
def get_domains(search: Optional[str] = Query(None, description="Filter domain by name"), current_user = Depends(get_current_user)):
    """Mengambil daftar semua domain dari database"""
    if not db_manager.check_db_connection():
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        data = db_manager.get_domains_list(search)
        return {"source": "postgresql", "data": data, "total": len(data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class DomainCreate(BaseModel):
    domain_name: str
    ip_address: Optional[str] = ""
    is_active: Optional[bool] = True

class DomainUpdate(BaseModel):
    domain_name: Optional[str] = None
    ip_address: Optional[str] = None
    is_active: Optional[bool] = None

@app.post("/api/domains")
def create_domain(payload: DomainCreate, current_user = Depends(get_current_user)):
    """Menambahkan domain baru"""
    if not db_manager.check_db_connection():
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        existing = db_manager.get_domain_by_name(payload.domain_name)
        if existing:
            raise HTTPException(status_code=400, detail="Domain sudah terdaftar")
            
        new_dom = db_manager.create_domain(payload.domain_name, payload.ip_address)
        return {"status": "ok", "message": "Domain berhasil ditambahkan", "data": new_dom}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/domains/{domain_id}")
def update_domain(domain_id: int, payload: DomainUpdate, current_user = Depends(get_current_user)):
    """Memperbarui data domain"""
    if not db_manager.check_db_connection():
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        if payload.domain_name is not None:
            existing = db_manager.get_domain_by_name(payload.domain_name)
            if existing and str(existing["id"]) != str(domain_id):
                raise HTTPException(status_code=400, detail="Nama domain sudah digunakan")
                
        updated = db_manager.update_domain(domain_id, payload.domain_name, payload.ip_address, payload.is_active)
        if not updated:
            raise HTTPException(status_code=404, detail="Domain tidak ditemukan")
        return {"status": "ok", "message": "Domain berhasil diperbarui", "data": updated}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/domains/{domain_id}")
def delete_domain(domain_id: int, current_user = Depends(get_current_user)):
    """Menghapus domain"""
    if not db_manager.check_db_connection():
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        success = db_manager.delete_domain(domain_id)
        if not success:
            raise HTTPException(status_code=404, detail="Domain tidak ditemukan")
        return {"status": "ok", "message": "Domain berhasil dihapus"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# ===================================================================
# API: Detail Domain (scan history, ports, tech, vulns dari Supabase)
# ===================================================================
@app.get("/api/domains/{domain_name}/detail")
def get_domain_detail(domain_name: str, current_user = Depends(get_current_user)):
    """Mengambil detail lengkap 1 domain: scan history, ports, teknologi, kerentanan"""
    if not db_manager.check_db_connection():
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        domain = db_manager.get_domain_by_name(domain_name)
        if not domain:
            raise HTTPException(status_code=404, detail=f"Domain '{domain_name}' tidak ditemukan")

        domain_id = domain["id"]

        history_list = db_manager.get_scan_history_for_domain(domain_id, 10)

        scans = []
        for scan in history_list:
            scan_id = scan["id"]

            ports = db_manager.get_open_ports_for_history(scan_id)
            tech = db_manager.get_technologies_for_history(scan_id)
            vulns = db_manager.get_scan_results_for_history(scan_id)

            # To avoid extra queries to fetch raw_json, I'll let it be mostly high/critical vulns.
            # (If raw_json wasn't fetched in get_scan_history_for_domain, we can fetch it via another wrapper or just leave it)

            scans.append({
                **scan,
                "open_ports": ports,
                "technologies": tech[0] if tech else {},
                "vulnerabilities": vulns
            })

        return {
            "source": "postgresql",
            "domain": domain,
            "scans": scans
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ===================================================================
# API: Scan History (dari Supabase)
# ===================================================================
@app.get("/api/scan-history")
def get_scan_history(limit: int = Query(20, ge=1, le=1000)):
    """Mengambil histori scan terbaru dari database"""
    if not db_manager.check_db_connection():
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        data = db_manager.get_scan_history_list(limit)
        return {"source": "postgresql", "data": data, "total": len(data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ===================================================================
# API: Semua Vulnerabilities (dari Supabase)
# ===================================================================
@app.get("/api/vulnerabilities")
def get_vulnerabilities(
    severity: Optional[str] = Query(None, description="Filter by severity (HIGH, MEDIUM, LOW)"),
    limit: int = Query(50, ge=1, le=200)
):
    """Mengambil daftar kerentanan dari database"""
    if not db_manager.check_db_connection():
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        data = db_manager.get_vulnerabilities_list(severity, limit)
        return {"source": "postgresql", "data": data, "total": len(data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ===================================================================
# API: Trigger Pentest Scan (sudah ada, diperbaiki)
# ===================================================================
async def run_pentest_tools_background(domain_name: str):
    """Menjalankan scan via Pentest-Tools API di background"""
    print(f"[*] [BACKGROUND] Memulai scan Pentest-Tools untuk: {domain_name}")
    semaphore = asyncio.Semaphore(1)
    async with aiohttp.ClientSession() as session:
        await process_domain_scan(session, domain_name, semaphore)
    print(f"[+] [BACKGROUND] Scan Pentest-Tools selesai untuk: {domain_name}")
    await manager.broadcast_to_admins({
        "event": "scan_finished",
        "domain": domain_name,
        "time": datetime.now(config.WIB).isoformat()
    })

# ===================================================================
# Simpan Jadwal
# ===================================================================
class SchedulePayload(BaseModel):
    targets: List[str]

@app.post("/api/schedule-scan")
async def schedule_scan(payload: SchedulePayload):
    """Memprioritaskan domain ke dalam antrean Supabase untuk dieksekusi Celery Beat"""
    if not db_manager.check_db_connection():
        raise HTTPException(status_code=503, detail="Database Supabase belum terkoneksi!")

    try:
        for domain in payload.targets:
            dom = db_manager.get_domain_by_name(domain)
            if dom:
                db_manager.update_domain(dom['id'], dom['domain_name'], dom['ip_address'], True)
            
        print(f"[!] MARKAS: {len(payload.targets)} target dimasukkan ke radar aktif Celery.")
        
        return {
            "status": "success", 
            "message": f"{len(payload.targets)} target disiapkan dalam antrean rotasi Celery."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/trigger-pentest")
async def trigger_pentest(domain_name: str, background_tasks: BackgroundTasks, current_user = Depends(get_current_user)):
    """Men-trigger scan Pentest-Tools untuk domain tertentu"""
    if not domain_name:
        raise HTTPException(status_code=400, detail="Domain name is required")

    try:
        dom = db_manager.get_domain_by_name(domain_name)
        if not dom:
            db_manager.upsert_domain(domain_name, "")
    except Exception:
        pass

    # Masukkan ke antrean background task FastAPI
    background_tasks.add_task(run_pentest_tools_background, domain_name)

    return JSONResponse(status_code=202, content={
        "message": f"Scan untuk {domain_name} telah dimulai di latar belakang.",
        "status": "queued"
    })

class NetworkScanRequest(BaseModel):
    targets: List[str]
    scan_type: Optional[str] = "deep"

async def run_network_scan_background(targets: List[str], scan_type: str = "deep"):
    """Fungsi latar belakang untuk menjalankan Network Scan pada beberapa target."""
    semaphore = asyncio.Semaphore(5)
    async with aiohttp.ClientSession() as session:
        tasks = [process_network_scan(session, target, semaphore, scan_type) for target in targets]
        if tasks:
            results = await asyncio.gather(*tasks)
            success_count = sum(1 for r in results if r)
            failed_count = len(results) - success_count
            print(f"[+] Network Scan Selesai: {success_count} sukses, {failed_count} gagal.")
            await asyncio.gather(*tasks)
            for target in targets:
                await manager.broadcast_to_admins({
                    "event": "scan_finished",
                    "domain": target,
                    "time": datetime.now(config.WIB).isoformat()
                })

async def run_web_scan_background(targets: List[str], scan_type: str = "deep"):
    """Fungsi latar belakang untuk menjalankan Web Scan pada beberapa target."""
    semaphore = asyncio.Semaphore(5)
    async with aiohttp.ClientSession() as session:
        tasks = [process_domain_scan(session, target, semaphore, scan_type) for target in targets]
        if tasks:
            results = await asyncio.gather(*tasks)
            success_count = sum(1 for r in results if r)
            failed_count = len(results) - success_count
            print(f"[+] Web Scan Selesai: {success_count} sukses, {failed_count} gagal.")
            await asyncio.gather(*tasks)
            for target in targets:
                await manager.broadcast_to_admins({
                    "event": "scan_finished",
                    "domain": target,
                    "time": datetime.now(config.WIB).isoformat()
                })

class WebScanRequest(BaseModel):
    targets: List[str]
    scan_type: Optional[str] = "deep"

@app.post("/api/network-scan")
async def trigger_network_scan(payload: NetworkScanRequest, background_tasks: BackgroundTasks):
    """Memicu proses Network Scan."""
    if not payload.targets:
        raise HTTPException(status_code=400, detail="Tidak ada target yang diberikan.")
        
    background_tasks.add_task(run_network_scan_background, payload.targets, payload.scan_type)
    
    return {"status": "success", "message": f"Network Scan via Pentest-Tools diluncurkan untuk {len(payload.targets)} aset."}

@app.post("/api/web-scan")
@app.post("/api/web-scan")
async def trigger_web_scan(
    payload: WebScanRequest, 
    background_tasks: BackgroundTasks, 
    current_user = Depends(get_current_user)
):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Anda tidak memiliki izin untuk melakukan aksi ini.")

    if not payload.targets:
        raise HTTPException(status_code=400, detail="Tidak ada target yang diberikan.")

    background_tasks.add_task(run_web_scan_background, payload.targets, payload.scan_type)
    
    return {"status": "success", "message": f"Web Scan via Pentest-Tools diluncurkan untuk {len(payload.targets)} aset."}

@app.get("/api/scans/active")
async def get_active_scans(current_user = Depends(get_current_user)):
    """Mendapatkan daftar scan yang sedang berjalan langsung dari API Pentest-Tools."""
    headers = {
        "Authorization": f"Bearer {config.PENTEST_TOOLS_API_KEY}",
        "Content-Type": "application/json"
    }
    
    result = []
    try:
        async with aiohttp.ClientSession() as session:
            # Fetch all scans
            scans_url = f"{config.PENTEST_TOOLS_BASE_URL}/scans"
            async with session.get(scans_url, headers=headers, timeout=10) as resp:
                if resp.status != 200:
                    return {"status": "error", "data": [], "message": f"Gagal mengambil scan: {resp.status}"}
                scans_data = await resp.json()
                all_scans = scans_data.get("data", [])
            
            # Fetch all targets to map target_id to domain name
            targets_url = f"{config.PENTEST_TOOLS_BASE_URL}/targets"
            targets_map = {}
            async with session.get(targets_url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    targets_data = await resp.json()
                    for t in targets_data.get("data", []):
                        targets_map[t["id"]] = t.get("name", "Unknown")

            # Filter only active scans
            active_statuses = ["waiting", "running", "queued"]
            for scan in all_scans:
                if scan.get("status_name") in active_statuses:
                    # Mapping data to frontend expected format
                    target_id = scan.get("target_id")
                    domain = targets_map.get(target_id, f"Target ID: {target_id}")
                    
                    # Convert HTTP URL to domain if needed, but it's fine to display raw target
                    result.append({
                        "scan_id": scan.get("id"),
                        "type": f"Pentest Tool {scan.get('tool_id')}",
                        "domain": domain,
                        "start_time": scan.get("start_time", "N/A"),
                        "live_status": scan.get("status_name"),
                        "progress": scan.get("progress", 0)
                    })
    except Exception as e:
        print(f"Error fetching live scans: {e}")
        return {"status": "error", "data": [], "message": str(e)}

    return {"status": "success", "data": result}

class StopScanRequest(BaseModel):
    scan_id: int

@app.post("/api/scans/stop")
async def stop_active_scan(req: StopScanRequest, current_user = Depends(get_current_user)):
    """Menghentikan scan yang sedang berjalan di Pentest-Tools."""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Anda tidak memiliki izin untuk melakukan aksi ini.")
    
    scan_id = req.scan_id
    url = f"{config.PENTEST_TOOLS_BASE_URL}/scans/{scan_id}/stop"
    headers = {
        "Authorization": f"Bearer {config.PENTEST_TOOLS_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, timeout=15) as resp:
                if resp.status in (200, 201, 202, 204):
                    return {"status": "success", "message": f"Scan {scan_id} berhasil dihentikan."}
                else:
                    err = await resp.text()
                    raise HTTPException(status_code=resp.status, detail=f"Gagal menghentikan scan: {err}")
    except Exception as e:
        if isinstance(e, HTTPException): raise
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/dashboard/reports/{filename}")
async def get_pdf_report(filename: str, current_user = Depends(get_current_user)):
    """Melayani file PDF report, atau membuatnya secara dinamis jika belum ada."""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Anda tidak memiliki izin untuk melakukan aksi ini.")
    
    reports_dir = os.path.join(DASHBOARD_PATH, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, filename)
    
    if os.path.exists(pdf_path):
        return FileResponse(pdf_path, media_type="application/pdf", filename=filename)
    
        
    if filename.startswith("pentest_tools_") and filename.endswith(".pdf"):
        domain_part = filename[len("pentest_tools_"):-4]
        # Cari domain name yang cocok (ubah underscore kembali ke titik)
        conn = db_manager.get_db_connection()
        target_domain = None
        if conn:
            try:
                with conn.cursor(cursor_factory=db_manager.RealDictCursor) as cur:
                    cur.execute('SELECT domain_name FROM domains')
                    res = cur.fetchall()
                    for d in res:
                        dname = d.get("domain_name", "")
                        if dname.replace(".", "_") == domain_part:
                            target_domain = dname
                            break
            finally:
                conn.close()
        
        if not target_domain:
            target_domain = domain_part.replace("_", ".")
            
        # Coba ambil report langsung dari Pentest-Tools API jika API Key terkonfigurasi
        api_key = config.PENTEST_TOOLS_API_KEY
        if api_key and api_key != "YOUR_API_KEY_HERE":
            print(f"[*] Mencoba mendownload PDF Report asli dari Pentest-Tools API untuk {target_domain}")
            try:
                headers = {"Authorization": f"Bearer {api_key}"}
                async with aiohttp.ClientSession() as session:
                    # 1. Cari target_id untuk domain ini
                    async with session.get("https://app.pentest-tools.com/api/v2/targets", headers=headers) as t_resp:
                        if t_resp.status == 200:
                            targets_data = await t_resp.json()
                            target_id = None
                            for t in targets_data.get("data", []):
                                t_name = t.get("name", "").replace("https://", "").replace("http://", "").split(":")[0].strip("/")
                                if t_name == target_domain or t.get("name") == target_domain:
                                    target_id = t["id"]
                                    break
                            
                            if target_id:
                                # 2. Cari scan_id terakhir yang sudah finished
                                async with session.get("https://app.pentest-tools.com/api/v2/scans", headers=headers) as s_resp:
                                    if s_resp.status == 200:
                                        scans_data = await s_resp.json()
                                        scans = [s for s in scans_data.get("data", []) if s.get("target_id") == target_id and s.get("status_name") in ["finished", "completed"]]
                                        scans.sort(key=lambda x: x.get("id", 0), reverse=True)
                                        if scans:
                                            scan_id = scans[0]["id"]
                                            # 3. Minta pembuatan PDF Report
                                            payload = {
                                                "source": "scans",
                                                "resources": [scan_id],
                                                "format": "pdf",
                                                "group_by": "target"
                                            }
                                            async with session.post("https://app.pentest-tools.com/api/v2/reports", headers=headers, json=payload) as r_resp:
                                                if r_resp.status in (200, 201, 202):
                                                    report_json = await r_resp.json()
                                                    report_id = report_json["data"]["report_id"]
                                                    
                                                    # 4. Polling untuk download
                                                    dl_url = f"https://app.pentest-tools.com/api/v2/reports/{report_id}/download"
                                                    for _ in range(15):
                                                        async with session.get(dl_url, headers=headers) as dl_resp:
                                                            if dl_resp.status == 200:
                                                                pdf_data = await dl_resp.read()
                                                                with open(pdf_path, "wb") as f:
                                                                    f.write(pdf_data)
                                                                print(f"[+] Berhasil mengunduh PDF asli Pentest-Tools untuk {target_domain}")
                                                                return FileResponse(pdf_path, media_type="application/pdf", filename=filename)
                                                            elif dl_resp.status == 202:
                                                                await asyncio.sleep(2)
                                                            else:
                                                                break
            except Exception as e:
                print(f"[-] Gagal mengambil PDF dari Pentest-Tools API: {e}")
            
        # Fallback: Dapatkan data kerentanan terbaru untuk domain ini
        open_ports = []
        technologies = {}
        vulnerabilities = []
        risk_level = "LOW"
        risk_score = 3.0
        ip_address = ""
        scan_date = datetime.now(timezone(timedelta(hours=7))).strftime("%Y-%m-%d %H:%M:%S")
        
        conn = db_manager.get_db_connection()
        if conn:
            try:
                with conn.cursor(cursor_factory=db_manager.RealDictCursor) as cur:
                    cur.execute('SELECT id, domain_name, ip_address FROM domains WHERE domain_name = %s LIMIT 1', (target_domain,))
                    dom = cur.fetchone()
                    if dom:
                        ip_address = dom.get("ip_address", "")
                        cur.execute('SELECT id, risk_score, risk_level, scan_date, raw_json FROM scan_history WHERE domain_id = %s ORDER BY scan_date DESC LIMIT 1', (dom["id"],))
                        scan = cur.fetchone()
                        if scan:
                            risk_score = scan.get("risk_score", 3.0)
                            risk_level = scan.get("risk_level", "LOW")
                            scan_date = scan.get("scan_date")
                            if hasattr(scan_date, 'isoformat'):
                                scan_date = scan_date.isoformat()
                            
                            cur.execute('SELECT port_number, service_name FROM open_ports WHERE history_id = %s', (scan["id"],))
                            open_ports = cur.fetchall()
                            
                            cur.execute('SELECT web_server, cms FROM technologies WHERE history_id = %s', (scan["id"],))
                            tech_resp = cur.fetchall()
                            technologies = tech_resp[0] if tech_resp else {}
                            
                            cur.execute('SELECT severity, check_type, title, description, recommendation FROM scan_result WHERE history_id = %s', (scan["id"],))
                            vulns_resp = cur.fetchall()
                            
                            low_info_vulns = scan.get("raw_json", [])
                            if isinstance(low_info_vulns, str):
                                import json
                                try: low_info_vulns = json.loads(low_info_vulns)
                                except: low_info_vulns = []
                            elif isinstance(low_info_vulns, dict):
                                low_info_vulns = low_info_vulns.get("low_info_vulns", [])

                            if not isinstance(low_info_vulns, list):
                                low_info_vulns = []
                            vulnerabilities = vulns_resp + low_info_vulns
            except Exception as e:
                print(f"[-] Gagal mengambil detail domain untuk PDF: {e}")
            finally:
                conn.close()
                
        # Jika sama sekali tidak ada scan history di DB, kita masih buat PDF kosong/informasional
        # agar user mendapat report bahwa domain belum discan
        if not vulnerabilities:
            vulnerabilities = [
                {
                    "severity": "info",
                    "check_type": "Web Scanner",
                    "title": "No Scan History Found",
                    "description": "Tidak ada data kerentanan yang ditemukan untuk target ini karena belum pernah dilakukan scan atau data tidak lengkap.",
                    "recommendation": "Silakan lakukan pemindaian (Web Scan atau Network Scan) pada dashboard terlebih dahulu."
                }
            ]
            
        try:
            from scanner.pdf_generator import generate_pdf_report
            generate_pdf_report(target_domain, ip_address, scan_date, risk_level, risk_score, open_ports, technologies, vulnerabilities, pdf_path)
            if os.path.exists(pdf_path):
                return FileResponse(pdf_path, media_type="application/pdf", filename=filename)
        except Exception as e:
            print(f"[-] Gagal generate PDF report: {e}")
            raise HTTPException(status_code=500, detail=f"Gagal memproduksi PDF report secara dinamis: {e}")

    raise HTTPException(status_code=404, detail="File PDF report tidak ditemukan.")

# ===================================================================
# Mount Static Files — HARUS di bawah semua route API
# ===================================================================
app.mount("/dashboard", StaticFiles(directory=DASHBOARD_PATH, html=True), name="dashboard")


# ===================================================================
# Main
# ===================================================================
class GenerateReportRequest(BaseModel):
    history_id: int
    report_type: str = "pentest_report"
    report_format: str = "pdf"
    group_findings_by: str = "target"
    include_reproduce: bool = False
    include_informational: bool = True
    include_false_positives: bool = False
    include_ignored: bool = False
    include_not_verified: bool = True
    include_accepted: bool = True
    include_fixed: bool = True

class ShareReportRequest(GenerateReportRequest):
    emails: list[str]

@app.post("/api/reports/generate")
async def generate_report(req: GenerateReportRequest, current_user = Depends(get_current_user)):
    """Generate on-demand Pentest-Tools report based on UI modal filters."""
    conn = db_manager.get_db_connection()
    if not conn:
        raise HTTPException(status_code=503, detail="Database not configured")

    # 1. Look up the history_id to get the pt_scan_id
    try:
        with conn.cursor(cursor_factory=db_manager.RealDictCursor) as cur:
            cur.execute('SELECT raw_json FROM scan_history WHERE id = %s', (req.history_id,))
            res = cur.fetchone()
            if not res:
                raise HTTPException(status_code=404, detail="Scan history not found")
            raw_json = res['raw_json']
    finally:
        conn.close()
        pt_scan_id = None
        # Ensure raw_json is parsed if it's a string
        if isinstance(raw_json, str):
            import json
            try:
                raw_json = json.loads(raw_json)
            except:
                raw_json = None
                
        # Determine pt_scan_id based on raw_json structure
        if isinstance(raw_json, dict) and "pt_scan_id" in raw_json:
            pt_scan_id = raw_json["pt_scan_id"]
        elif isinstance(raw_json, list):
            # Fallback if somehow it's old structure, we can't generate it easily unless we parse it.
            pass
            
        if not pt_scan_id:
            raise HTTPException(status_code=400, detail="Cannot generate report for this history because it does not contain a valid Pentest-Tools scan ID (pt_scan_id).")
        
    # 2. Call Pentest-Tools API to Generate Report
    url = f"{config.PENTEST_TOOLS_BASE_URL}/reports"
    headers = {
        "Authorization": f"Bearer {config.PENTEST_TOOLS_API_KEY}",
        "Content-Type": "application/json"
    }
    
    # Map filters
    severities = ["critical", "high", "medium", "low"]
    if req.include_informational:
        severities.append("info")
        
    status_filters = []
    if req.include_false_positives: status_filters.append("false positive")
    if req.include_ignored: status_filters.append("ignored")
    if req.include_not_verified: status_filters.append("not verified")
    if req.include_accepted: status_filters.append("accepted risk")
    if req.include_fixed: status_filters.append("fixed")
    
    payload = {
        "source": "scans",
        "resources": [pt_scan_id],
        "format": req.report_format.lower(),
        "type": req.report_type,
        "group_by": req.group_findings_by,
        "filters": {
            "include_how_to_reproduce": req.include_reproduce,
            "severity": severities,
            "status": status_filters
        }
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=payload, timeout=30) as resp:
            if resp.status not in (200, 201, 202):
                err = await resp.text()
                raise HTTPException(status_code=resp.status, detail=f"Gagal membuat report: {err}")
                
            resp_json = await resp.json()
            report_id = resp_json["data"]["report_id"]
            
        # 3. Poll for completion
        download_url = f"{config.PENTEST_TOOLS_BASE_URL}/reports/{report_id}/download"
        
        for _ in range(40): # Wait up to 200 seconds
            async with session.get(download_url, headers={"Authorization": f"Bearer {config.PENTEST_TOOLS_API_KEY}"}) as dl_resp:
                if dl_resp.status == 200:
                    pdf_data = await dl_resp.read()
                    
                    format_file = req.report_format.lower()
                    filename = f"security_report_{req.history_id}.{format_file}"
                    return pdf_data, filename
                    
                elif dl_resp.status == 202:
                    await asyncio.sleep(5)
                else:
                    err = await dl_resp.text()
                    raise HTTPException(status_code=dl_resp.status, detail=f"Gagal mengunduh report: {err}")
                    
        raise HTTPException(status_code=408, detail="Timeout saat menunggu pembuatan report selesai.")

@app.post("/api/reports/generate")
async def generate_report_endpoint(req: GenerateReportRequest, current_user = Depends(get_current_user)):
    """Endpoint untuk mendownload PDF Report langsung"""
    try:
        # Panggil fungsi helper pembangun file bytes
        file_data, filename = await _generate_report_bytes(req)
        
        # Kembalikan sebagai unduhan
        return Response(
            content=file_data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/reports/share")
async def share_report_endpoint(req: ShareReportRequest, current_user = Depends(get_current_user)):
    """Endpoint untuk mengirim PDF Report via Email"""
    # Pastikan kredensial SMTP tersedia
    if not config.SMTP_USERNAME or not config.SMTP_PASSWORD:
        raise HTTPException(status_code=500, detail="SMTP server belum dikonfigurasi. Tidak dapat mengirim email.")
        
    try:
        # Panggil fungsi helper pembangun file bytes
        file_data, filename = await _generate_report_bytes(req)
        
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.application import MIMEApplication
        
        # Siapkan email
        msg = MIMEMultipart()
        msg['From'] = f"UNDIP Security Dashboard <{config.SMTP_USERNAME}>"
        msg['To'] = ", ".join(req.emails)
        msg['Subject'] = f"Security Scan Report - UNDIP CSIRT"
        
        # Isi body email
        body = "Halo,\n\nTerlampir adalah dokumen laporan hasil security scan otomatis (Pentest-Tools) yang di-generate dari UNDIP Security Dashboard.\n\nSalam,\nUNDIP CSIRT"
        msg.attach(MIMEText(body, 'plain'))
        
        # Sisipkan file (PDF/HTML/CSV/dsb)
        attachment = MIMEApplication(file_data, Name=filename)
        attachment['Content-Disposition'] = f'attachment; filename="{filename}"'
        msg.attach(attachment)
        
        # Kirim email
        if config.SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(config.SMTP_SERVER, config.SMTP_PORT)
        else:
            server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
            server.starttls()
            
        server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return {"status": "success", "message": f"Laporan berhasil dikirim ke {len(req.emails)} email."}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gagal mengirim email: {str(e)}")

# ==============================================================================
# NOTIFICATIONS ROUTES
# ==============================================================================
@app.get("/api/notifications")
async def api_get_notifications():
    """Mengambil semua notifikasi lokal"""
    try:
        notifs = db_manager.get_notifications()
        return {"status": "success", "data": notifs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/notifications/{notif_id}/read")
async def api_mark_notification_read(notif_id: str):
    """Menandai satu notifikasi telah dibaca"""
    try:
        success = db_manager.mark_notification_as_read(notif_id)
        if success:
            return {"status": "success"}
        raise HTTPException(status_code=404, detail="Notification not found")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/notifications/read-all")
async def api_mark_all_notifications_read():
    """Menandai semua notifikasi telah dibaca"""
    try:
        db_manager.mark_all_notifications_as_read()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/notifications/{notif_id}")
async def api_delete_notification(notif_id: str):
    """Menghapus satu notifikasi"""
    try:
        success = db_manager.delete_notification(notif_id)
        if success:
            return {"status": "success"}
        raise HTTPException(status_code=404, detail="Notification not found")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))

class InternalNotifyRequest(BaseModel):
    title: str
    message: str
    notif_type: str = "info"

@app.post("/api/internal/webhook-notify")
async def webhook_notify(req: InternalNotifyRequest, request: Request):
    """Webhook internal untuk menerima notifikasi dari Celery/Proses lain"""
    # Hanya izinkan localhost
    client_host = request.client.host
    if client_host not in ("127.0.0.1", "localhost", "::1"):
        raise HTTPException(status_code=403, detail="Forbidden")
        
    try:
        notif = db_manager.create_notification(
            title=req.title,
            message=req.message,
            notif_type=req.notif_type
        )
        
        await manager.broadcast_to_admins({
            "event": "new_notification",
            "notification": notif
        })
        
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  DSTI UNDIP Pentest Dashboard")
    print("  Buka browser: http://localhost:8000")
    print("=" * 60)
    uvicorn.run("web_app:app", host="0.0.0.0", port=8000, reload=True)