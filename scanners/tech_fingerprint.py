"""
=======================================================================
MODUL 3: TECHNOLOGY FINGERPRINTING
=======================================================================
Mengidentifikasi teknologi yang digunakan setiap subdomain melalui:
- HTTP Response Header Analysis
- Cookie Analysis (CMS detection)
- HTML Meta Tag Analysis
- Security Header Audit
- SSL/TLS Certificate Analysis
=======================================================================
"""

import asyncio
import aiohttp
import socket
import ssl
import sys
import os
import json
import re
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


# =======================================================================
# Database Signature untuk deteksi CMS dan Framework
# =======================================================================
CMS_SIGNATURES = {
    # Cookie-based detection
    "cookies": {
        "wordpress_": "WordPress",
        "wp-settings": "WordPress",
        "joomla_": "Joomla",
        "drupal": "Drupal",
        "laravel_session": "Laravel",
        "ci_session": "CodeIgniter",
        "csrftoken": "Django",
        "PHPSESSID": "PHP Application",
        "JSESSIONID": "Java Application",
        "ASP.NET_SessionId": "ASP.NET",
        "connect.sid": "Node.js/Express",
    },
    # HTML body patterns (regex)
    "html_patterns": [
        (r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d.]*)', "WordPress"),
        (r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla[!]?\s*([\d.]*)', "Joomla"),
        (r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal\s*([\d.]*)', "Drupal"),
        (r'wp-content/', "WordPress"),
        (r'wp-includes/', "WordPress"),
        (r'/media/jui/', "Joomla"),
        (r'sites/default/files', "Drupal"),
        (r'Moodle', "Moodle LMS"),
        (r'/theme/starter/', "Moodle LMS"),
        (r'csrfmiddlewaretoken', "Django"),
    ],
    # Header-based detection
    "headers": {
        "X-Powered-By": {
            "PHP": "PHP",
            "ASP.NET": "ASP.NET",
            "Express": "Node.js/Express",
            "Servlet": "Java Servlet",
        },
        "X-Drupal-Cache": "Drupal",
        "X-Generator": {
            "WordPress": "WordPress",
            "Joomla": "Joomla",
            "Drupal": "Drupal",
        },
    }
}


async def analyze_http_headers(session, domain, port=443):
    """
    Menganalisis HTTP response headers untuk fingerprinting.
    
    Returns:
        dict berisi informasi teknologi yang terdeteksi
    """
    result = {
        "web_server": "Unknown",
        "programming_language": "Unknown",
        "cms": "Unknown",
        "framework": "Unknown",
        "os_hint": "Unknown",
        "other_tech": [],
    }

    # Coba HTTPS dulu, fallback ke HTTP
    protocols = [f"https://{domain}", f"http://{domain}"]
    
    for url in protocols:
        try:
            async with session.get(url, timeout=config.HTTP_TIMEOUT, 
                                   ssl=False, allow_redirects=True) as response:
                headers = response.headers

                # --- Web Server ---
                server = headers.get("Server", "")
                if server:
                    result["web_server"] = server
                    # Deteksi OS dari Server header
                    server_lower = server.lower()
                    if "ubuntu" in server_lower or "debian" in server_lower:
                        result["os_hint"] = "Ubuntu/Debian Linux"
                    elif "centos" in server_lower or "red hat" in server_lower:
                        result["os_hint"] = "CentOS/RHEL Linux"
                    elif "win" in server_lower:
                        result["os_hint"] = "Windows Server"
                    elif "unix" in server_lower:
                        result["os_hint"] = "Unix-based"

                # --- Programming Language ---
                x_powered = headers.get("X-Powered-By", "")
                if x_powered:
                    result["programming_language"] = x_powered
                
                # Deteksi PHP dari header lain
                if "X-Powered-By" in headers and "PHP" in headers["X-Powered-By"]:
                    result["programming_language"] = headers["X-Powered-By"]

                # --- ASP.NET Detection ---
                if "X-AspNet-Version" in headers:
                    result["framework"] = f"ASP.NET {headers['X-AspNet-Version']}"
                    result["programming_language"] = "ASP.NET"
                if "X-AspNetMvc-Version" in headers:
                    result["framework"] = f"ASP.NET MVC {headers['X-AspNetMvc-Version']}"

                # --- CMS dari Headers ---
                for header_name, patterns in CMS_SIGNATURES["headers"].items():
                    if header_name in headers:
                        if isinstance(patterns, dict):
                            for key, cms_name in patterns.items():
                                if key.lower() in headers[header_name].lower():
                                    result["cms"] = cms_name
                        elif isinstance(patterns, str):
                            result["cms"] = patterns

                # --- Cookie Analysis ---
                cookies_str = headers.get("Set-Cookie", "")
                for cookie_key, cms_name in CMS_SIGNATURES["cookies"].items():
                    if cookie_key.lower() in cookies_str.lower():
                        if result["cms"] == "Unknown":
                            result["cms"] = cms_name
                        elif cms_name not in result["cms"]:
                            result["other_tech"].append(cms_name)

                # --- HTML Body Analysis ---
                try:
                    body = await response.text(encoding="utf-8", errors="ignore")
                    # Limit body size untuk efisiensi
                    body_snippet = body[:50000]

                    for pattern, cms_name in CMS_SIGNATURES["html_patterns"]:
                        match = re.search(pattern, body_snippet, re.IGNORECASE)
                        if match:
                            version = match.group(1) if match.lastindex else ""
                            detected = f"{cms_name} {version}".strip()
                            if result["cms"] == "Unknown":
                                result["cms"] = detected
                            break  # Ambil yang pertama match saja
                except Exception:
                    pass

                # Berhasil mendapatkan data, tidak perlu coba protocol lain
                return result

        except Exception:
            continue

    return result


async def audit_security_headers(session, domain):
    """
    Mengaudit keberadaan security headers yang direkomendasikan.
    
    Returns:
        dict mapping header_name -> "PRESENT" | "MISSING" beserta nilainya
    """
    security_audit = {}

    url = f"https://{domain}"
    try:
        async with session.get(url, timeout=config.HTTP_TIMEOUT,
                               ssl=False, allow_redirects=True) as response:
            headers = response.headers

            for header_name in config.EXPECTED_SECURITY_HEADERS:
                value = headers.get(header_name)
                if value:
                    security_audit[header_name] = {
                        "status": "PRESENT",
                        "value": value
                    }
                else:
                    security_audit[header_name] = {
                        "status": "MISSING",
                        "value": None
                    }
    except Exception:
        # Jika gagal konek, tandai semua sebagai UNKNOWN
        for header_name in config.EXPECTED_SECURITY_HEADERS:
            security_audit[header_name] = {
                "status": "UNKNOWN",
                "value": None
            }

    return security_audit


def analyze_ssl_certificate(domain, port=443, timeout=5):
    """
    Menganalisis sertifikat SSL/TLS pada domain.
    Ini menggunakan blocking call karena ssl module tidak mendukung async secara native.
    
    Returns:
        dict berisi informasi SSL/TLS
    """
    ssl_info = {
        "protocol": "Unknown",
        "issuer": "Unknown",
        "subject": "Unknown",
        "expires": "Unknown",
        "days_until_expiry": -1,
        "serial_number": "Unknown",
        "has_ssl": False,
        "issues": []
    }

    try:
        # Buat SSL context yang tidak memverifikasi (untuk pentest, kita ingin lihat semua)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                ssl_info["has_ssl"] = True
                ssl_info["protocol"] = ssock.version() or "Unknown"

                # Ambil certificate info
                cert = ssock.getpeercert(binary_form=False)
                
                if cert:
                    # Issuer
                    issuer_parts = []
                    for rdn in cert.get("issuer", []):
                        for attr_type, attr_value in rdn:
                            if attr_type == "organizationName":
                                issuer_parts.append(attr_value)
                            elif attr_type == "commonName":
                                issuer_parts.append(attr_value)
                    ssl_info["issuer"] = " / ".join(issuer_parts) if issuer_parts else "Unknown"

                    # Subject
                    subject_parts = []
                    for rdn in cert.get("subject", []):
                        for attr_type, attr_value in rdn:
                            if attr_type == "commonName":
                                subject_parts.append(attr_value)
                    ssl_info["subject"] = ", ".join(subject_parts) if subject_parts else "Unknown"

                    # Expiry
                    not_after = cert.get("notAfter")
                    if not_after:
                        # Format: 'Sep 30 12:00:00 2026 GMT'
                        try:
                            expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            ssl_info["expires"] = expiry_date.strftime("%Y-%m-%d")
                            days_left = (expiry_date - datetime.utcnow()).days
                            ssl_info["days_until_expiry"] = days_left

                            if days_left < 0:
                                ssl_info["issues"].append("EXPIRED")
                            elif days_left < 30:
                                ssl_info["issues"].append("EXPIRING_SOON")
                        except ValueError:
                            ssl_info["expires"] = not_after

                    # Serial Number
                    serial = cert.get("serialNumber")
                    if serial:
                        ssl_info["serial_number"] = serial

                # Deteksi protocol lemah
                protocol = ssl_info["protocol"]
                if protocol in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    ssl_info["issues"].append(f"WEAK_PROTOCOL_{protocol}")
                    
    except ssl.SSLCertVerificationError:
        ssl_info["has_ssl"] = True
        ssl_info["issues"].append("CERT_VERIFICATION_FAILED")
    except ssl.SSLError as e:
        ssl_info["issues"].append(f"SSL_ERROR: {str(e)[:100]}")
    except socket.timeout:
        ssl_info["issues"].append("TIMEOUT")
    except ConnectionRefusedError:
        ssl_info["issues"].append("CONNECTION_REFUSED")
    except OSError:
        ssl_info["issues"].append("CONNECTION_FAILED")
    except Exception as e:
        ssl_info["issues"].append(f"ERROR: {str(e)[:100]}")

    return ssl_info


async def fingerprint_domain(session, domain_info, semaphore):
    """
    Menjalankan semua teknik fingerprinting pada satu domain.
    
    Args:
        session: aiohttp.ClientSession
        domain_info: dict dari port scan results (atau aset_aktif)
        semaphore: asyncio.Semaphore untuk rate limiting
    """
    async with semaphore:
        domain = domain_info["domain_name"]
        ip_address = domain_info.get("ip_address", "Unknown")

        print(f"  [*] Fingerprinting: {domain}...")

        # 1. HTTP Header & Technology Analysis
        tech_info = await analyze_http_headers(session, domain)

        # 2. Security Header Audit
        security_headers = await audit_security_headers(session, domain)

        # 3. SSL/TLS Analysis (blocking, dijalankan di thread pool)
        loop = asyncio.get_running_loop()
        ssl_info = await loop.run_in_executor(None, analyze_ssl_certificate, domain)

        # Hitung skor keamanan sederhana
        missing_headers = sum(
            1 for h in security_headers.values() 
            if h["status"] == "MISSING"
        )
        ssl_issues = len(ssl_info.get("issues", []))

        print(f"  [+] {domain}: Server={tech_info['web_server']}, "
              f"CMS={tech_info['cms']}, "
              f"Missing Headers={missing_headers}, "
              f"SSL Issues={ssl_issues}")

        wib = timezone(timedelta(hours=7))
        timestamp = datetime.now(wib).isoformat()

        return {
            "domain_name": domain,
            "ip_address": ip_address,
            "technologies": tech_info,
            "security_headers": security_headers,
            "ssl_info": ssl_info,
            "scan_timestamp": timestamp
        }


async def analyze_all(domain_list, max_concurrent=None):
    """
    Menjalankan fingerprinting pada seluruh daftar domain.
    
    Args:
        domain_list: list of dict (bisa dari aset_aktif.json atau port_scan_results.json)
        max_concurrent: batas koneksi serentak
    
    Returns:
        list of dict hasil fingerprinting
    """
    if max_concurrent is None:
        max_concurrent = config.MAX_CONCURRENT_CONNECTIONS

    semaphore = asyncio.Semaphore(max_concurrent)

    print(f"\n{'='*60}")
    print(f"  MODUL 3: TECHNOLOGY FINGERPRINTING")
    print(f"  Target: {len(domain_list)} subdomain")
    print(f"  Max concurrent: {max_concurrent}")
    print(f"{'='*60}\n")

    resolver = aiohttp.ThreadedResolver()
    connector = aiohttp.TCPConnector(
        family=socket.AF_INET,
        ssl=False,
        resolver=resolver,
        limit=0
    )

    async with aiohttp.ClientSession(
        headers=config.DEFAULT_HEADERS,
        connector=connector
    ) as session:
        tasks = [
            fingerprint_domain(session, domain_info, semaphore)
            for domain_info in domain_list
        ]
        results = await asyncio.gather(*tasks)

    # Ringkasan
    cms_count = {}
    server_count = {}
    for r in results:
        cms = r["technologies"]["cms"]
        if cms != "Unknown":
            cms_count[cms] = cms_count.get(cms, 0) + 1
        
        server = r["technologies"]["web_server"]
        if server != "Unknown":
            # Ambil nama server saja (tanpa versi detail)
            server_base = server.split("/")[0] if "/" in server else server
            server_count[server_base] = server_count.get(server_base, 0) + 1

    print(f"\n{'='*60}")
    print(f"  FINGERPRINTING SELESAI")
    print(f"  Web Servers: {dict(sorted(server_count.items(), key=lambda x: x[1], reverse=True))}")
    print(f"  CMS Detected: {dict(sorted(cms_count.items(), key=lambda x: x[1], reverse=True))}")
    print(f"{'='*60}\n")

    return results


def save_results(results, output_path=None):
    """Simpan hasil fingerprinting ke file JSON."""
    if output_path is None:
        output_path = config.TECH_FINGERPRINT_OUTPUT

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    
    print(f"[+] Hasil fingerprinting disimpan ke: {output_path}")


# =======================================================================
# Standalone execution
# =======================================================================
if __name__ == "__main__":
    import argparse

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    parser = argparse.ArgumentParser(description="Technology Fingerprinter - Modul 3")
    parser.add_argument("--input", default=config.INPUT_FILE,
                        help="Path ke file JSON input")
    parser.add_argument("--output", default=config.TECH_FINGERPRINT_OUTPUT,
                        help="Path file output JSON")
    parser.add_argument("--limit", type=int, default=0,
                        help="Batasi jumlah domain (0 = semua)")
    parser.add_argument("--target", type=str, default="",
                        help="Scan satu domain spesifik (contoh: ft.undip.ac.id)")
    parser.add_argument("--test", action="store_true",
                        help="Mode test: scan 3 domain pertama")
    args = parser.parse_args()

    # Load data
    with open(args.input, "r") as f:
        domain_list = json.load(f)

    # Filter
    if args.target:
        domain_list = [d for d in domain_list if d["domain_name"] == args.target]
        if not domain_list:
            print(f"[-] Domain '{args.target}' tidak ditemukan di input file.")
            sys.exit(1)
    elif args.test:
        domain_list = domain_list[:3]
        print("[!] MODE TEST: Hanya fingerprint 3 domain pertama")
    elif args.limit > 0:
        domain_list = domain_list[:args.limit]

    results = asyncio.run(analyze_all(domain_list))
    save_results(results, args.output)
