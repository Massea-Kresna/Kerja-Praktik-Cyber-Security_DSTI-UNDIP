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

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import db_manager
import config
import asyncio
import aiohttp
import json
import os
from typing import Optional
from datetime import datetime, timedelta, timezone
from pentest_tools_scheduler import process_domain_scan

app = FastAPI(title="DSTI UNDIP Pentest Dashboard API")

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
def get_dashboard_stats():
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
        vuln_resp = supabase.table("vulnerabilities").select("id", count="exact").execute()
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
# API: Trend Stats (Line Chart)
# ===================================================================
@app.get("/api/trend-stats")
def get_trend_stats():
    """Mengambil data tren kerentanan per domain (24 jam terakhir, interval 30 menit)"""
    supabase = _get_supabase_or_none()

    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        # Gunakan zona waktu lokal WIB (UTC+7)
        wib_tz = timezone(timedelta(hours=7))
        now_utc = datetime.now(timezone.utc)
        now_wib = now_utc.astimezone(wib_tz)
        
        # Snap ke interval 30 menit ke bawah (misal: 09:12 -> 09:00, 09:45 -> 09:30)
        minute_snapped = 30 if now_wib.minute >= 30 else 0
        snapped_wib = now_wib.replace(minute=minute_snapped, second=0, microsecond=0)
        
        # Ambil 24 jam ke belakang dari waktu yg sudah di-snap (48 bucket + 1 untuk sekarang)
        start_time_wib = snapped_wib - timedelta(hours=24)
        
        # Kembalikan ke format UTC untuk query Supabase
        start_time_utc = start_time_wib.astimezone(timezone.utc)
        start_time_iso = start_time_utc.isoformat()
        
        resp = (
            supabase.table("scan_history")
            .select("id, scan_date, domains(domain_name), vulnerabilities(id)")
            .gte("scan_date", start_time_iso)
            .order("scan_date", desc=False)
            .execute()
        )
        scans = resp.data
        
        # Kita buat 49 label agar menutupi tepat 24 jam (48 interval)
        labels = []
        for i in range(49):
            bucket_time_wib = start_time_wib + timedelta(minutes=i*30)
            labels.append(bucket_time_wib.strftime("%H:%M"))
            
        domains_data = {}
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
                
            delta = scan_date_wib - start_time_wib
            bucket_index = int(delta.total_seconds() // 1800)
            
            if 0 <= bucket_index < 49:
                if domain_name not in domains_data:
                    domains_data[domain_name] = [None] * 49
                
                vuln_count = len(scan.get("vulnerabilities", []))
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
# API: Daftar Semua Domain (dari Supabase)
# ===================================================================
@app.get("/api/domains")
def get_domains(search: Optional[str] = Query(None, description="Filter domain by name")):
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


# ===================================================================
# API: Detail Domain (scan history, ports, tech, vulns dari Supabase)
# ===================================================================
@app.get("/api/domains/{domain_name}/detail")
def get_domain_detail(domain_name: str):
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
                supabase.table("vulnerabilities")
                .select("severity, check_type, title, description, recommendation")
                .eq("history_id", scan_id)
                .execute()
            )

            scans.append({
                **scan,
                "open_ports": ports_resp.data,
                "technologies": tech_resp.data[0] if tech_resp.data else {},
                "vulnerabilities": vulns_resp.data
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
def get_scan_history(limit: int = Query(20, ge=1, le=100)):
    """Mengambil histori scan terbaru dari database"""
    supabase = _get_supabase_or_none()

    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        resp = (
            supabase.table("scan_history")
            .select("id, risk_score, risk_level, scan_date, raw_json, domain_id, domains(domain_name, ip_address), vulnerabilities(title, severity, check_type, description, recommendation)")
            .order("scan_date", desc=True)
            .limit(limit)
            .execute()
        )
        return {"source": "supabase", "data": resp.data, "total": len(resp.data)}
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
            supabase.table("vulnerabilities")
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


@app.post("/api/trigger-pentest")
async def trigger_pentest(domain_name: str, background_tasks: BackgroundTasks):
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


# ===================================================================
# Mount Static Files — HARUS di bawah semua route API
# ===================================================================
app.mount("/dashboard", StaticFiles(directory=DASHBOARD_PATH, html=True), name="dashboard")


# ===================================================================
# Main
# ===================================================================
if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  DSTI UNDIP Pentest Dashboard")
    print("  Buka browser: http://localhost:8000")
    print("=" * 60)
    uvicorn.run("web_app:app", host="0.0.0.0", port=8000, reload=True)
