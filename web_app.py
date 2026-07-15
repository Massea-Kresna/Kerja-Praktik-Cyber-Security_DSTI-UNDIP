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
from typing import List, Optional

from datetime import datetime, timedelta, timezone
from scanner.pentest_tools_scheduler import process_domain_scan
from scanner.pentest_tools_scheduler import process_network_scan
from typing import List

app = FastAPI(title="DSTI UNDIP Pentest Dashboard API")

# Seeding admin secara otomatis saat file dimuat
db_manager.seed_default_admin()

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
    remember_me: Optional[bool] = False

# ===================================================================
# Auth Dependencies
# ===================================================================
def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="Session tidak ditemukan. Silakan login kembali.")
    
    # Cari user berdasarkan session_id
    user = None
    supabase = db_manager.get_supabase_client()
    if supabase:
        try:
            resp = supabase.table("users").select("*").eq("session_id", session_id).limit(1).execute()
            if resp.data:
                user = resp.data[0]
        except Exception:
            pass
            
    if not user:
        users = db_manager._read_local_users()
        for u in users:
            if u.get("session_id") == session_id:
                user = u
                break
                
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
    """Mendapatkan Supabase client, return None jika belum dikonfigurasi"""
    try:
        return db_manager.get_supabase_client()
    except Exception:
        return None


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
async def login_user(user_data: UserLogin, response: Response):
    """Proses login user, menghasilkan cookie session_id"""
    user = db_manager.get_user_by_username(user_data.username)
    if not user or not db_manager.verify_password(user_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Username atau password salah.")
        
    # Cek timeout
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
            
    # Buat session baru
    session_id = str(uuid.uuid4())
    db_manager.update_user_session(user["username"], session_id, True)
    
    # Simpan di cookie (maksimal aktif 30 hari jika remember me)
    cookie_max_age = 2592000 if user_data.remember_me else 86400
    response.set_cookie(
        key="session_id", 
        value=session_id, 
        httponly=True, 
        max_age=cookie_max_age, 
        samesite="lax",
        path="/"
    )
    
    # Kirim notifikasi real-time via WebSocket ke semua admin yang terkoneksi
    await manager.broadcast_to_admins({
        "event": "user_login",
        "username": user["username"],
        "role": user["role"],
        "time": datetime.now(timezone(timedelta(hours=7))).strftime("%H:%M:%S")
    })
    
    return {"username": user["username"], "role": user["role"], "session_id": session_id}

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
async def put_user_timeout(target_username: str, admin_user = Depends(get_current_admin)):
    """Menangguhkan user selama 2 jam"""
    # 2 jam dari sekarang
    timeout_time = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    db_manager.update_user_timeout(target_username, timeout_time)
    await manager.kick_user(target_username, "timeout")
    return {"status": "ok", "message": f"User '{target_username}' ditangguhkan selama 2 jam."}

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
    user = None
    supabase = db_manager.get_supabase_client()
    if supabase:
        try:
            resp = supabase.table("users").select("*").eq("session_id", session_id).limit(1).execute()
            if resp.data:
                user = resp.data[0]
        except Exception:
            pass
            
    if not user:
        users = db_manager._read_local_users()
        for u in users:
            if u.get("session_id") == session_id:
                user = u
                break
                
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
    supabase = _get_supabase_or_none()
    db_connected = False
    db_message = "Supabase belum dikonfigurasi"

    if supabase:
        try:
            supabase.table("domains").select("id").limit(1).execute()
            db_connected = True
            db_message = "Terhubung ke Supabase"
        except Exception as e:
            db_message = f"Supabase error: {str(e)}"

    return {
        "status": "ok",
        "database": {
            "connected": db_connected,
            "message": db_message
        },
        "data_source": "supabase"
    }


# ===================================================================
# API: Dashboard Stats (dari Supabase, fallback ke lokal)
# ===================================================================
@app.get("/api/dashboard-stats")
def get_dashboard_stats(current_user = Depends(get_current_user)):
    """Mengambil statistik dasar dan riwayat scan terbaru"""
    supabase = _get_supabase_or_none()

    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        # Ambil total domain
        domains_resp = supabase.table("domains").select("id", count="exact").execute()
        total_domains = domains_resp.count if hasattr(domains_resp, 'count') and domains_resp.count is not None else len(domains_resp.data)

        # Ambil history scan terbaru
        history_resp = (
            supabase.table("scan_history")
            .select("id, risk_score, risk_level, scan_date, domains(domain_name)")
            .order("scan_date", desc=True)
            .limit(10)
            .execute()
        )
        recent_scans = history_resp.data

        # Hitung statistik dari 100 scan terakhir
        stats_resp = (
            supabase.table("scan_history")
            .select("risk_level")
            .order("scan_date", desc=True)
            .limit(100)
            .execute()
        )
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
        for row in stats_resp.data:
            r_level = row.get("risk_level", "SAFE")
            if r_level in stats:
                stats[r_level] += 1

        # Hitung total vulnerabilities
        vuln_resp = supabase.table("scan_result").select("id", count="exact").execute()
        total_vulns = vuln_resp.count if hasattr(vuln_resp, 'count') and vuln_resp.count is not None else len(vuln_resp.data)

        return {
            "source": "supabase",
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
    supabase = _get_supabase_or_none()

    if not supabase:
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
                    num_buckets = 48
                    minute_snapped = 30 if end_dt.minute >= 30 else 0
                    end_snapped_wib = end_dt.replace(minute=minute_snapped, second=0, microsecond=0)
                    start_snapped_wib = end_snapped_wib - timedelta(hours=24)
                    date_format = "%H:%M"
                elif days_diff <= 7:
                    interval_minutes = 6 * 60
                    num_buckets = int((days_diff * 24) // 6)
                    hour_snapped = (end_dt.hour // 6) * 6
                    end_snapped_wib = end_dt.replace(hour=hour_snapped, minute=0, second=0, microsecond=0)
                    start_snapped_wib = end_snapped_wib - timedelta(minutes=num_buckets * interval_minutes)
                    date_format = "%d %b %H:%M"
                else:
                    interval_minutes = 24 * 60
                    num_buckets = max(1, math.ceil(days_diff))
                    end_snapped_wib = end_dt.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
                    start_snapped_wib = end_snapped_wib - timedelta(days=num_buckets)
                    date_format = "%d %b %Y"
            except ValueError:
                raise HTTPException(status_code=400, detail="Format tanggal tidak valid. Gunakan YYYY-MM-DD.")
        
        start_time_iso = start_snapped_wib.astimezone(timezone.utc).isoformat()
        end_time_iso = end_snapped_wib.astimezone(timezone.utc).isoformat()
        
        resp = (
            supabase.table("scan_history")
            .select("id, scan_date, raw_json, domains(domain_name), scan_result(id)")
            .gte("scan_date", start_time_iso)
            .lte("scan_date", end_time_iso)
            .order("scan_date", desc=False)
            .execute()
        )
        scans = resp.data
        
        labels = []
        for i in range(num_buckets + 1):
            bucket_time_wib = start_snapped_wib + timedelta(minutes=i*interval_minutes)
            labels.append(bucket_time_wib.strftime(date_format))
            
        domains_resp = supabase.table("domains").select("domain_name").execute()
        all_domains = [d.get("domain_name") for d in domains_resp.data if d.get("domain_name")]
            
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
                if isinstance(raw_json, str):
                    import json
                    try:
                        raw_json = json.loads(raw_json)
                    except:
                        raw_json = []
                if isinstance(raw_json, list):
                    vuln_count += len(raw_json)
                domains_data[domain_name][bucket_index] = vuln_count

        return {
            "source": "supabase",
            "labels": labels,
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
    supabase = _get_supabase_or_none()

    if not supabase:
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
                    num_buckets = 48
                    minute_snapped = 30 if end_dt.minute >= 30 else 0
                    end_snapped_wib = end_dt.replace(minute=minute_snapped, second=0, microsecond=0)
                    start_snapped_wib = end_snapped_wib - timedelta(hours=24)
                    date_format = "%H:%M"
                elif days_diff <= 7:
                    interval_minutes = 6 * 60
                    num_buckets = int((days_diff * 24) // 6)
                    hour_snapped = (end_dt.hour // 6) * 6
                    end_snapped_wib = end_dt.replace(hour=hour_snapped, minute=0, second=0, microsecond=0)
                    start_snapped_wib = end_snapped_wib - timedelta(minutes=num_buckets * interval_minutes)
                    date_format = "%d %b %H:%M"
                else:
                    interval_minutes = 24 * 60
                    num_buckets = max(1, math.ceil(days_diff))
                    end_snapped_wib = end_dt.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
                    start_snapped_wib = end_snapped_wib - timedelta(days=num_buckets)
                    date_format = "%d %b %Y"
            except ValueError:
                raise HTTPException(status_code=400, detail="Format tanggal tidak valid. Gunakan YYYY-MM-DD.")
        
        start_time_iso = start_snapped_wib.astimezone(timezone.utc).isoformat()
        end_time_iso = end_snapped_wib.astimezone(timezone.utc).isoformat()
        
        resp = (
            supabase.table("scan_history")
            .select("id, scan_date, raw_json, scan_result(severity), domains(domain_name)")
            .gte("scan_date", start_time_iso)
            .lte("scan_date", end_time_iso)
            .order("scan_date", desc=False)
            .execute()
        )
        scans = resp.data
        
        labels = []
        for i in range(num_buckets + 1):
            bucket_time_wib = start_snapped_wib + timedelta(minutes=i*interval_minutes)
            labels.append(bucket_time_wib.strftime(date_format))
            
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
                # Hitung dari tabel vulnerabilities (Medium/High/Critical)
                vulns = scan.get("scan_result") or []
                for v in vulns:
                    sev = (v.get("severity") or "").upper()
                    if sev in severities_data:
                        severities_data[sev][bucket_index] += 1
                        domains_by_sev[sev][bucket_index][domain_name] = domains_by_sev[sev][bucket_index].get(domain_name, 0) + 1
                        
                # Hitung dari raw_json (Low/Info)
                raw_json = scan.get("raw_json")
                if isinstance(raw_json, str):
                    import json
                    try:
                        raw_json = json.loads(raw_json)
                    except:
                        raw_json = []
                if isinstance(raw_json, list):
                    for v in raw_json:
                        sev = (v.get("severity") or "").upper()
                        if sev in severities_data:
                            severities_data[sev][bucket_index] += 1
                            domains_by_sev[sev][bucket_index][domain_name] = domains_by_sev[sev][bucket_index].get(domain_name, 0) + 1

        return {
            "source": "supabase",
            "labels": labels,
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
    supabase = _get_supabase_or_none()

    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        query = supabase.table("domains").select("id, domain_name, ip_address, is_active")

        if search:
            query = query.ilike("domain_name", f"%{search}%")

        query = query.order("domain_name")
        resp = query.execute()

        return {"source": "supabase", "data": resp.data, "total": len(resp.data)}
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
    supabase = _get_supabase_or_none()
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
        
    try:
        existing = supabase.table("domains").select("id").eq("domain_name", payload.domain_name).execute()
        if existing.data:
            raise HTTPException(status_code=400, detail="Domain sudah terdaftar")
            
        data = {
            "domain_name": payload.domain_name,
            "ip_address": payload.ip_address,
            "is_active": payload.is_active
        }
        resp = supabase.table("domains").insert(data).execute()
        return {"status": "ok", "message": "Domain berhasil ditambahkan", "data": resp.data[0] if resp.data else None}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/domains/{domain_id}")
def update_domain(domain_id: int, payload: DomainUpdate, current_user = Depends(get_current_user)):
    """Memperbarui data domain"""
    supabase = _get_supabase_or_none()
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
        
    try:
        data = {}
        if payload.domain_name is not None:
            existing = supabase.table("domains").select("id").eq("domain_name", payload.domain_name).execute()
            if existing.data and str(existing.data[0]["id"]) != str(domain_id):
                raise HTTPException(status_code=400, detail="Nama domain sudah digunakan")
            data["domain_name"] = payload.domain_name
        if payload.ip_address is not None:
            data["ip_address"] = payload.ip_address
        if payload.is_active is not None:
            data["is_active"] = payload.is_active
            
        if not data:
            return {"status": "ok", "message": "Tidak ada perubahan"}
            
        resp = supabase.table("domains").update(data).eq("id", domain_id).execute()
        if not resp.data:
            raise HTTPException(status_code=404, detail="Domain tidak ditemukan")
        return {"status": "ok", "message": "Domain berhasil diperbarui", "data": resp.data[0]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/domains/{domain_id}")
def delete_domain(domain_id: int, current_user = Depends(get_current_user)):
    """Menghapus domain"""
    supabase = _get_supabase_or_none()
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
        
    try:
        resp = supabase.table("domains").delete().eq("id", domain_id).execute()
        if not resp.data:
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
    supabase = _get_supabase_or_none()

    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        # Cari domain
        domain_resp = (
            supabase.table("domains")
            .select("id, domain_name, ip_address, is_active")
            .eq("domain_name", domain_name)
            .limit(1)
            .execute()
        )
        if not domain_resp.data:
            raise HTTPException(status_code=404, detail=f"Domain '{domain_name}' tidak ditemukan")

        domain = domain_resp.data[0]
        domain_id = domain["id"]

        # Ambil scan history terbaru
        history_resp = (
            supabase.table("scan_history")
            .select("id, risk_score, risk_level, scan_date, raw_json")
            .eq("domain_id", domain_id)
            .order("scan_date", desc=True)
            .limit(10)
            .execute()
        )

        scans = []
        for scan in history_resp.data:
            scan_id = scan["id"]

            # Open ports
            ports_resp = (
                supabase.table("open_ports")
                .select("port_number, service_name")
                .eq("history_id", scan_id)
                .execute()
            )

            # Technologies
            tech_resp = (
                supabase.table("technologies")
                .select("web_server, cms")
                .eq("history_id", scan_id)
                .execute()
            )

            # Vulnerabilities
            vulns_resp = (
                supabase.table("scan_result")
                .select("id, check_type, severity, title, description, recommendation")
                .eq("history_id", scan_id)
                .execute()
            )

            # Ambil low/info vulnerabilities dari raw_json
            low_info_vulns = scan.get("raw_json", [])
            if not isinstance(low_info_vulns, list):
                low_info_vulns = []
                
            all_vulns = (vulns_resp.data or []) + low_info_vulns
            scan.pop("raw_json", None)

            scans.append({
                **scan,
                "open_ports": ports_resp.data,
                "technologies": tech_resp.data[0] if tech_resp.data else {},
                "vulnerabilities": all_vulns
            })

        return {
            "source": "supabase",
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
    supabase = _get_supabase_or_none()

    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        resp = (
            supabase.table("scan_history")
            .select("id, risk_score, risk_level, scan_date, raw_json, domain_id, domains(domain_name, ip_address), scan_result(title, severity, check_type, description, recommendation)")
            .order("scan_date", desc=True)
            .limit(limit)
            .execute()
        )
        
        data = resp.data
        for scan in data:
            if "scan_result" in scan:
                scan["vulnerabilities"] = scan.pop("scan_result")
            else:
                scan["vulnerabilities"] = []
                
            if scan.get("raw_json") and isinstance(scan["raw_json"], list):
                if not scan.get("vulnerabilities"):
                    scan["vulnerabilities"] = []
                scan["vulnerabilities"].extend(scan["raw_json"])
            # Hapus raw_json agar payload lebih ringan
            scan.pop("raw_json", None)
            
        return {"source": "supabase", "data": data, "total": len(data)}
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
    supabase = _get_supabase_or_none()

    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        query = (
            supabase.table("scan_result")
            .select("id, severity, check_type, title, description, recommendation, history_id, scan_history(scan_date, domain_id, domains(domain_name))")
        )
        if severity:
            query = query.eq("severity", severity.upper())

        resp = query.limit(limit).execute()
        return {"source": "supabase", "data": resp.data, "total": len(resp.data)}
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

# ===================================================================
# Simpan Jadwal
# ===================================================================
class SchedulePayload(BaseModel):
    targets: List[str]

@app.post("/api/schedule-scan")
async def schedule_scan(payload: SchedulePayload):
    """Memprioritaskan domain ke dalam antrean Supabase untuk dieksekusi Celery Beat"""
    supabase = _get_supabase_or_none()
    
    if not supabase:
        raise HTTPException(status_code=503, detail="Database Supabase belum terkoneksi!")

    try:
        # Kita tidak lagi menggunakan JSON lokal.
        # Langsung update status 'is_active' menjadi True di database 
        # agar Celery otomatis menangkapnya di siklus berikutnya.
        for domain in payload.targets:
            supabase.table("domains").update({"is_active": True}).eq("domain_name", domain).execute()
            
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

    # Validasi jika domain ada di database
    supabase = _get_supabase_or_none()
    if supabase:
        try:
            resp = supabase.table("domains").select("id").eq("domain_name", domain_name).limit(1).execute()
            if not resp.data:
                db_manager.upsert_domain(supabase, domain_name, "")
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

async def run_network_scan_background(targets: List[str]):
    """Fungsi latar belakang untuk menjalankan Network Scan pada beberapa target."""
    semaphore = asyncio.Semaphore(5)
    async with aiohttp.ClientSession() as session:
        tasks = [process_network_scan(session, target, semaphore) for target in targets]
        if tasks:
            await asyncio.gather(*tasks)

async def run_web_scan_background(targets: List[str]):
    """Fungsi latar belakang untuk menjalankan Web Scan pada beberapa target."""
    semaphore = asyncio.Semaphore(5)
    async with aiohttp.ClientSession() as session:
        tasks = [process_domain_scan(session, target, semaphore) for target in targets]
        if tasks:
            await asyncio.gather(*tasks)

class WebScanRequest(BaseModel):
    targets: List[str]

@app.post("/api/web-scan")
async def trigger_web_scan(payload: WebScanRequest, background_tasks: BackgroundTasks):
    """Memicu proses Web Scan."""
    if not payload.targets:
        raise HTTPException(status_code=400, detail="Tidak ada target yang diberikan.")
        
    background_tasks.add_task(run_web_scan_background, payload.targets)
    
    return {"status": "success", "message": f"Web Scan via Pentest-Tools diluncurkan untuk {len(payload.targets)} aset."}

@app.post("/api/network-scan")
async def trigger_network_scan(payload: NetworkScanRequest, background_tasks: BackgroundTasks):
    """Memicu proses Network Scan."""
    if not payload.targets:
        raise HTTPException(status_code=400, detail="Tidak ada target yang diberikan.")
        
    background_tasks.add_task(run_network_scan_background, payload.targets)
    
    return {"status": "success", "message": f"Network Scan via Pentest-Tools diluncurkan untuk {len(payload.targets)} aset."}

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

@app.post("/api/reports/generate")
async def generate_report(req: GenerateReportRequest, current_user = Depends(get_current_user)):
    """Generate on-demand Pentest-Tools report based on UI modal filters."""
    supabase = _get_supabase_or_none()
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")

    # 1. Look up the history_id to get the pt_scan_id
    try:
        resp = supabase.table("scan_history").select("raw_json").eq("id", req.history_id).limit(1).execute()
        if not resp.data:
            raise HTTPException(status_code=404, detail="Scan history not found")
        raw_json = resp.data[0].get("raw_json")
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
    except Exception as e:
        if isinstance(e, HTTPException): raise
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
        
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
                    
                    # Simpan ke folder dashboard/reports agar ada cache / archive (opsional)
                    reports_dir = os.path.join(config.DASHBOARD_DIR, "reports")
                    os.makedirs(reports_dir, exist_ok=True)
                    
                    filename = f"on_demand_report_{req.history_id}_{report_id}.{req.report_format.lower()}"
                    file_path = os.path.join(reports_dir, filename)
                    with open(file_path, "wb") as f:
                        f.write(pdf_data)
                        
                    return {"status": "success", "file_url": f"/dashboard/reports/{filename}"}
                    
                elif dl_resp.status == 202:
                    await asyncio.sleep(5)
                else:
                    err = await dl_resp.text()
                    raise HTTPException(status_code=dl_resp.status, detail=f"Gagal mengunduh report: {err}")
                    
        raise HTTPException(status_code=408, detail="Timeout saat menunggu pembuatan report selesai.")

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  DSTI UNDIP Pentest Dashboard")
    print("  Buka browser: http://localhost:8000")
    print("=" * 60)
    uvicorn.run("web_app:app", host="0.0.0.0", port=8000, reload=True)