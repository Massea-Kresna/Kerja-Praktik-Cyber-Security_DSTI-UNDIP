# =======================================================================
# KONFIGURASI GLOBAL - Pentest Tools Pipeline
# =======================================================================

import os
from dotenv import load_dotenv
from datetime import timezone, timedelta

# Load API keys and secrets dari .env
load_dotenv()
# Target utama
TARGET_DOMAIN = "undip.ac.id"

# --- Pengaturan Koneksi ---
MAX_CONCURRENT_CONNECTIONS = 3     # Batas koneksi serentak (Semaphore) jadi 50 domain masuk buat di scan, trus sisanya (50++) nunggu dari 50 domain selesai dulu baru bisa masuk satu satu
PORT_SCAN_TIMEOUT = 3               # Timeout per port (detik)
BANNER_GRAB_TIMEOUT = 2             # Timeout banner grabbing (detik)
HTTP_TIMEOUT = 10                   # Timeout per HTTP request (detik)

# --- Pengaturan Scanning ---
# Top ports yang akan di-scan (IANA + commonly attacked ports)
COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1434: "MSSQL-Browser",
    1521: "Oracle-DB",
    1723: "PPTP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2086: "WHM",
    2087: "WHM-SSL",
    2095: "Webmail",
    2096: "Webmail-SSL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9090: "WebConsole",
    9200: "Elasticsearch",
    9443: "WSO2",
    27017: "MongoDB",
}

# --- Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(BASE_DIR, "aset_aktif_undip.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "reports")
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")
TRACKER_FILE = os.path.join(BASE_DIR, ".celery_pentest_tracker.json")
WIB = timezone(timedelta(hours=7))

# Output files
PORT_SCAN_OUTPUT = os.path.join(OUTPUT_DIR, "port_scan_results.json")
TECH_FINGERPRINT_OUTPUT = os.path.join(OUTPUT_DIR, "tech_fingerprint.json")
VULN_REPORT_OUTPUT = os.path.join(OUTPUT_DIR, "vuln_report.json")

# --- Backend API (Opsional) ---
API_BACKEND_URL = "http://127.0.0.1:8000/api"

# --- HTTP Headers ---
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# --- Admin Path yang dicek untuk Exposed Admin Panels ---
ADMIN_PATHS = [
    "/wp-admin",
    "/wp-login.php",
    "/admin",
    "/administrator",
    "/phpmyadmin",
    "/cpanel",
    "/webmail",
    "/login",
    "/user/login",
    "/admin/login",
]

# --- Security Headers yang harus ada ---
EXPECTED_SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# =======================================================================
# KONFIGURASI PENJADWALAN & PENTEST-TOOLS API
# =======================================================================
# Silakan masukkan/ganti API Key Pentest-Tools Anda di bawah ini
PENTEST_TOOLS_API_KEY = os.environ.get("PENTEST_TOOLS_API_KEY", "uk_wP9sfQiudWph9GX63pTFXAgYgZ27rrm1E6bI0CJU121d7985")
PENTEST_TOOLS_BASE_URL = "https://app.pentest-tools.com/api/v2"

# ID Tool Pentest-Tools
from enum import IntEnum

class Tool(IntEnum):
    """Available scanning tools and their IDs"""
    SUBDOMAIN_FINDER = 20
    WHOIS_LOOKUP = 30
    PORT_SCANNER = 70
    URL_FUZZER = 90
    VHOSTS_FINDER = 160
    WEBSITE_SCANNER = 170
    ICMP_PING = 240
    SHAREPOINT_SCANNER = 260
    WORDPRESS_SCANNER = 270
    DRUPAL_SCANNER = 280
    JOOMLA_SCANNER = 290
    WEBSITE_RECON = 310
    SUBDOMAIN_TAKEOVER = 320
    NETWORK_SCANNER = 350
    SQLI_EXPLOITER = 380
    DOMAIN_FINDER = 390
    PASSWORD_AUDITOR = 400
    SSL_SCANNER = 450
    SNIPER = 490
    WAF_DETECTOR = 500
    API_SCANNER = 510
    CLOUD_SCANNER = 520
    PEOPLE_HUNTER = 530
    KUBERNETES_SCANNER = 540
    LIGHT_NETWORK =385

PENTEST_TOOLS_DEFAULT_TOOL_ID = Tool.WEBSITE_SCANNER
PENTEST_TOOLS_NETWORK_TOOL_ID = Tool.NETWORK_SCANNER
# Batas Concurrency API agar tidak membebani limit rate akun
MAX_CONCURRENT_API_SCANS = 3

# Waktu Tunggu Polling Status (dalam detik)
API_POLLING_INTERVAL = 60  # Cek status scan setiap 1 menit

# =======================================================================
# KONFIGURASI DATABASE PENJADWALAN (SUPABASE FRAMEWORK)
# =======================================================================
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

# Supabase Direct DB Connection (untuk scheduler_db.py via psycopg2)
# Format: postgresql://postgres.[project-ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres
SUPABASE_DB_URL = os.environ.get("SUPABASE_DB_URL", "")

# Fallback: Koneksi PostgreSQL manual (jika tidak pakai SUPABASE_DB_URL)
PG_HOST = os.environ.get("PG_HOST", "localhost")
PG_PORT = os.environ.get("PG_PORT", "5432")
PG_USER = os.environ.get("PG_USER", "postgres")
PG_PASSWORD = os.environ.get("PG_PASSWORD", "")
PG_DATABASE = os.environ.get("PG_DATABASE", "postgres")