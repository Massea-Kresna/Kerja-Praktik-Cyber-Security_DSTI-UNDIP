"""
=======================================================================
MODUL 4: VULNERABILITY SCANNER
=======================================================================
Mendeteksi kerentanan berdasarkan data dari Modul 2 (Port Scan) dan 
Modul 3 (Tech Fingerprint). 

PENTING: Modul ini HANYA melakukan passive detection berdasarkan
versi software dan konfigurasi. TIDAK ada active exploitation.

Checks:
  1. Outdated Software Version (CVE mapping)
  2. Missing Security Headers
  3. SSL/TLS Issues
  4. Exposed Admin Panels
  5. Information Disclosure
  6. Open Dangerous Ports
  7. HTTP tanpa redirect ke HTTPS
=======================================================================
"""

import asyncio
import aiohttp
import socket
import sys
import os
import json
import re
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


# =======================================================================
# Database CVE - Mapping versi software ke kerentanan yang diketahui
# =======================================================================
# Format: "software_prefix": [{"max_safe_version": ..., "cves": [...], "description": ...}]
# Catatan: Ini adalah subset representatif, bukan database lengkap.

KNOWN_VULNERABILITIES = {
    "Apache": [
        {
            "affected_below": "2.4.58",
            "cves": ["CVE-2023-45802", "CVE-2023-43622", "CVE-2023-31122"],
            "severity": "HIGH",
            "description": "HTTP/2 stream handling, DoS via HTTP/2, mod_macro buffer overflow"
        },
        {
            "affected_below": "2.4.55",
            "cves": ["CVE-2022-37436", "CVE-2022-36760"],
            "severity": "HIGH",
            "description": "Response splitting via mod_proxy, HTTP request smuggling"
        },
    ],
    "nginx": [
        {
            "affected_below": "1.25.4",
            "cves": ["CVE-2024-24989", "CVE-2024-24990"],
            "severity": "HIGH",
            "description": "HTTP/3 QUIC vulnerability, use-after-free in HTTP/3"
        },
        {
            "affected_below": "1.24.0",
            "cves": ["CVE-2023-44487"],
            "severity": "HIGH",
            "description": "HTTP/2 Rapid Reset Attack (DoS)"
        },
    ],
    "PHP": [
        {
            "affected_below": "8.3.4",
            "cves": ["CVE-2024-2756", "CVE-2024-3096"],
            "severity": "HIGH",
            "description": "Cookie bypass, password_verify bypass"
        },
        {
            "affected_below": "8.1.28",
            "cves": ["CVE-2024-2757"],
            "severity": "MEDIUM",
            "description": "mb_encode_mimeheader infinite loop"
        },
    ],
    "OpenSSH": [
        {
            "affected_below": "9.6",
            "cves": ["CVE-2023-51385", "CVE-2023-51384"],
            "severity": "MEDIUM",
            "description": "OS command injection via PKCS#11, agent forwarding restriction bypass"
        },
        {
            "affected_below": "9.3",
            "cves": ["CVE-2023-38408"],
            "severity": "HIGH",
            "description": "Remote code execution via ssh-agent PKCS#11"
        },
    ],
    "WordPress": [
        {
            "affected_below": "6.5",
            "cves": ["CVE-2024-31210"],
            "severity": "HIGH",
            "description": "Remote code execution via plugin upload"
        },
        {
            "affected_below": "6.4.3",
            "cves": ["CVE-2024-21738"],
            "severity": "MEDIUM",
            "description": "Object injection via POP chain"
        },
    ],
    "jQuery": [
        {
            "affected_below": "3.5.0",
            "cves": ["CVE-2020-11022", "CVE-2020-11023"],
            "severity": "MEDIUM",
            "description": "XSS via HTML parsing in jQuery.htmlPrefilter"
        },
    ],
}

# Port-port yang dianggap berbahaya jika terbuka ke publik
DANGEROUS_PORTS = {
    23: ("Telnet", "HIGH", "Telnet mengirim data dalam plaintext, termasuk kredensial"),
    135: ("MSRPC", "MEDIUM", "Microsoft RPC sering menjadi target exploitasi"),
    139: ("NetBIOS", "MEDIUM", "NetBIOS dapat mengekspos informasi sistem"),
    445: ("SMB", "HIGH", "SMB rentan terhadap EternalBlue dan serangan lainnya"),
    1433: ("MSSQL", "HIGH", "Database MSSQL tidak boleh terbuka ke publik"),
    3306: ("MySQL", "HIGH", "Database MySQL tidak boleh terbuka ke publik"),
    3389: ("RDP", "HIGH", "RDP sering menjadi target brute-force dan BlueKeep"),
    5432: ("PostgreSQL", "HIGH", "Database PostgreSQL tidak boleh terbuka ke publik"),
    5900: ("VNC", "HIGH", "VNC sering tidak terenkripsi dan rentan brute-force"),
    6379: ("Redis", "CRITICAL", "Redis sering berjalan tanpa autentikasi"),
    9200: ("Elasticsearch", "HIGH", "Elasticsearch tanpa auth dapat mengekspos data"),
    27017: ("MongoDB", "HIGH", "MongoDB tanpa auth dapat mengekspos seluruh database"),
    2082: ("cPanel", "MEDIUM", "Panel kontrol hosting terbuka ke publik"),
    2083: ("cPanel-SSL", "MEDIUM", "Panel kontrol hosting terbuka ke publik"),
    2086: ("WHM", "MEDIUM", "WebHost Manager terbuka ke publik"),
    2087: ("WHM-SSL", "MEDIUM", "WebHost Manager terbuka ke publik"),
}


def _parse_version(version_str):
    """
    Mengekstrak dan membandingkan versi dari string.
    Contoh: "Apache/2.4.41 (Ubuntu)" -> (2, 4, 41)
    """
    if not version_str:
        return None
    
    # Cari pattern versi (angka.angka.angka)
    match = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', str(version_str))
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) else 0
        return (major, minor, patch)
    return None


def _version_lt(v1, v2_str):
    """Cek apakah versi v1 (tuple) kurang dari v2_str (string)."""
    v2 = _parse_version(v2_str)
    if not v1 or not v2:
        return False
    return v1 < v2


def check_outdated_software(tech_info):
    """
    CHECK 1: Mencocokkan versi software dengan database CVE.
    
    Args:
        tech_info: dict dari tech_fingerprint (field 'technologies')
    
    Returns:
        list of vulnerability dicts
    """
    vulns = []
    
    # Cek Web Server
    web_server = tech_info.get("web_server", "")
    for software, vuln_list in KNOWN_VULNERABILITIES.items():
        if software.lower() in web_server.lower():
            detected_version = _parse_version(web_server)
            if detected_version:
                for vuln in vuln_list:
                    if _version_lt(detected_version, vuln["affected_below"]):
                        vulns.append({
                            "check": "OUTDATED_SOFTWARE",
                            "title": f"Outdated {software} Version Detected",
                            "severity": vuln["severity"],
                            "detail": f"Versi terdeteksi: {web_server}. "
                                     f"Rentan terhadap: {vuln['description']}",
                            "cve_references": vuln["cves"],
                            "recommendation": f"Update {software} ke versi >= {vuln['affected_below']}"
                        })
                        break  # Satu CVE cukup per software

    # Cek Programming Language
    prog_lang = tech_info.get("programming_language", "")
    for software, vuln_list in KNOWN_VULNERABILITIES.items():
        if software.lower() in prog_lang.lower():
            detected_version = _parse_version(prog_lang)
            if detected_version:
                for vuln in vuln_list:
                    if _version_lt(detected_version, vuln["affected_below"]):
                        vulns.append({
                            "check": "OUTDATED_SOFTWARE",
                            "title": f"Outdated {software} Version Detected",
                            "severity": vuln["severity"],
                            "detail": f"Versi terdeteksi: {prog_lang}. "
                                     f"Rentan terhadap: {vuln['description']}",
                            "cve_references": vuln["cves"],
                            "recommendation": f"Update {software} ke versi >= {vuln['affected_below']}"
                        })
                        break

    # Cek CMS
    cms = tech_info.get("cms", "")
    for software, vuln_list in KNOWN_VULNERABILITIES.items():
        if software.lower() in cms.lower():
            detected_version = _parse_version(cms)
            if detected_version:
                for vuln in vuln_list:
                    if _version_lt(detected_version, vuln["affected_below"]):
                        vulns.append({
                            "check": "OUTDATED_SOFTWARE",
                            "title": f"Outdated {software} Version Detected",
                            "severity": vuln["severity"],
                            "detail": f"Versi terdeteksi: {cms}. "
                                     f"Rentan terhadap: {vuln['description']}",
                            "cve_references": vuln["cves"],
                            "recommendation": f"Update {software} ke versi terbaru"
                        })
                        break

    return vulns


def check_missing_security_headers(security_headers):
    """
    CHECK 2: Mengaudit security headers yang hilang.
    """
    vulns = []

    severity_map = {
        "Content-Security-Policy": "HIGH",
        "Strict-Transport-Security": "HIGH",
        "X-Frame-Options": "MEDIUM",
        "X-Content-Type-Options": "MEDIUM",
        "X-XSS-Protection": "LOW",
        "Referrer-Policy": "LOW",
        "Permissions-Policy": "LOW",
    }

    recommendation_map = {
        "Content-Security-Policy": "Tambahkan header CSP untuk mencegah XSS dan injection attacks",
        "Strict-Transport-Security": "Tambahkan HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "X-Frame-Options": "Tambahkan header: X-Frame-Options: DENY atau SAMEORIGIN",
        "X-Content-Type-Options": "Tambahkan header: X-Content-Type-Options: nosniff",
        "X-XSS-Protection": "Tambahkan header: X-XSS-Protection: 1; mode=block",
        "Referrer-Policy": "Tambahkan header: Referrer-Policy: strict-origin-when-cross-origin",
        "Permissions-Policy": "Tambahkan header Permissions-Policy untuk membatasi fitur browser",
    }

    missing_count = 0
    for header_name, info in security_headers.items():
        if info.get("status") == "MISSING":
            missing_count += 1

    # Hanya laporkan jika ada header yang hilang
    if missing_count > 0:
        missing_headers = [
            h for h, info in security_headers.items() 
            if info.get("status") == "MISSING"
        ]
        
        # Kelompokkan by severity
        for header in missing_headers:
            vulns.append({
                "check": "MISSING_SECURITY_HEADER",
                "title": f"Missing Security Header: {header}",
                "severity": severity_map.get(header, "LOW"),
                "detail": f"Header keamanan '{header}' tidak ditemukan pada respons HTTP",
                "cve_references": [],
                "recommendation": recommendation_map.get(header, f"Tambahkan header {header}")
            })

    return vulns


def check_ssl_issues(ssl_info):
    """
    CHECK 3: Mendeteksi masalah SSL/TLS.
    """
    vulns = []

    if not ssl_info.get("has_ssl"):
        vulns.append({
            "check": "SSL_ISSUE",
            "title": "No SSL/TLS Detected",
            "severity": "HIGH",
            "detail": "Domain tidak menggunakan SSL/TLS. Semua traffic dikirim dalam plaintext.",
            "cve_references": [],
            "recommendation": "Implementasikan SSL/TLS menggunakan Let's Encrypt (gratis)"
        })
        return vulns

    issues = ssl_info.get("issues", [])
    
    for issue in issues:
        if issue == "EXPIRED":
            vulns.append({
                "check": "SSL_ISSUE",
                "title": "SSL Certificate Expired",
                "severity": "CRITICAL",
                "detail": f"Sertifikat SSL sudah kedaluwarsa sejak {ssl_info.get('expires', 'unknown')}",
                "cve_references": [],
                "recommendation": "Perbarui sertifikat SSL segera"
            })
        elif issue == "EXPIRING_SOON":
            vulns.append({
                "check": "SSL_ISSUE",
                "title": "SSL Certificate Expiring Soon",
                "severity": "MEDIUM",
                "detail": f"Sertifikat SSL akan kedaluwarsa dalam {ssl_info.get('days_until_expiry', '?')} hari "
                         f"({ssl_info.get('expires', 'unknown')})",
                "cve_references": [],
                "recommendation": "Perbarui sertifikat SSL sebelum kedaluwarsa"
            })
        elif "WEAK_PROTOCOL" in issue:
            protocol = issue.replace("WEAK_PROTOCOL_", "")
            vulns.append({
                "check": "SSL_ISSUE",
                "title": f"Weak SSL/TLS Protocol: {protocol}",
                "severity": "HIGH",
                "detail": f"Server masih mendukung {protocol} yang sudah deprecated dan rentan",
                "cve_references": ["CVE-2014-3566"] if "SSLv3" in protocol else [],
                "recommendation": f"Nonaktifkan {protocol}, gunakan minimal TLS 1.2"
            })
        elif "CERT_VERIFICATION_FAILED" in issue:
            vulns.append({
                "check": "SSL_ISSUE",
                "title": "SSL Certificate Verification Failed",
                "severity": "MEDIUM",
                "detail": "Sertifikat SSL gagal diverifikasi (mungkin self-signed atau chain tidak lengkap)",
                "cve_references": [],
                "recommendation": "Gunakan sertifikat dari CA terpercaya dan pastikan certificate chain lengkap"
            })

    return vulns


def check_dangerous_open_ports(open_ports):
    """
    CHECK 6: Mendeteksi port berbahaya yang terbuka ke publik.
    """
    vulns = []

    for port_info in open_ports:
        port_num = port_info.get("port")
        if port_num in DANGEROUS_PORTS:
            service, severity, description = DANGEROUS_PORTS[port_num]
            vulns.append({
                "check": "DANGEROUS_OPEN_PORT",
                "title": f"Dangerous Port Open: {port_num}/{service}",
                "severity": severity,
                "detail": f"Port {port_num} ({service}) terbuka ke publik. {description}",
                "cve_references": [],
                "recommendation": f"Tutup port {port_num} dari akses publik menggunakan firewall, "
                                 f"atau batasi akses hanya dari IP yang diizinkan"
            })

    return vulns


def check_information_disclosure(tech_info):
    """
    CHECK 5: Mendeteksi kebocoran informasi melalui headers.
    """
    vulns = []
    
    web_server = tech_info.get("web_server", "")
    prog_lang = tech_info.get("programming_language", "")

    # Versi web server terekspos
    if web_server and web_server != "Unknown":
        # Cek apakah versi lengkap terekspos (bukan hanya nama)
        if re.search(r'\d+\.\d+', web_server):
            vulns.append({
                "check": "INFO_DISCLOSURE",
                "title": "Server Version Disclosed in Headers",
                "severity": "LOW",
                "detail": f"Header 'Server' menampilkan versi lengkap: {web_server}. "
                         f"Ini memudahkan attacker mencari exploit spesifik.",
                "cve_references": [],
                "recommendation": "Sembunyikan versi server. Untuk Apache: ServerTokens Prod. "
                                 "Untuk Nginx: server_tokens off;"
            })

    # Versi bahasa pemrograman terekspos
    if prog_lang and prog_lang != "Unknown":
        if re.search(r'\d+\.\d+', prog_lang):
            vulns.append({
                "check": "INFO_DISCLOSURE",
                "title": "Programming Language Version Disclosed",
                "severity": "LOW",
                "detail": f"Header 'X-Powered-By' menampilkan: {prog_lang}. "
                         f"Informasi ini membantu attacker mengidentifikasi attack surface.",
                "cve_references": [],
                "recommendation": "Hapus header X-Powered-By. Untuk PHP: expose_php = Off di php.ini"
            })

    return vulns


async def check_admin_panels(session, domain, semaphore):
    """
    CHECK 4: Mendeteksi panel admin yang terekspos ke publik.
    """
    vulns = []

    async with semaphore:
        for path in config.ADMIN_PATHS:
            url = f"https://{domain}{path}"
            try:
                async with session.get(url, timeout=5, ssl=False, 
                                       allow_redirects=False) as response:
                    # Status 200, 301, 302, 401, 403 = panel ada (mungkin dilindungi)
                    if response.status in [200, 301, 302]:
                        severity = "MEDIUM"
                        if response.status == 200:
                            severity = "HIGH"
                        
                        vulns.append({
                            "check": "EXPOSED_ADMIN_PANEL",
                            "title": f"Admin Panel Accessible: {path}",
                            "severity": severity,
                            "detail": f"Panel admin ditemukan di {url} (HTTP {response.status}). "
                                     f"Ini memperbesar attack surface.",
                            "cve_references": [],
                            "recommendation": f"Batasi akses ke {path} menggunakan IP whitelist, "
                                             f"VPN, atau tambahkan 2FA"
                        })
            except Exception:
                continue

    return vulns


def _calculate_risk_score(vulnerabilities):
    """
    Menghitung skor risiko (0-10) berdasarkan temuan kerentanan.
    """
    if not vulnerabilities:
        return 0.0, "SAFE"

    severity_weights = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1
    }

    total_weight = sum(
        severity_weights.get(v.get("severity", "LOW"), 1)
        for v in vulnerabilities
    )

    # Normalisasi ke skala 0-10 (cap at 10)
    score = min(total_weight / 3, 10.0)
    score = round(score, 1)

    if score >= 8:
        level = "CRITICAL"
    elif score >= 6:
        level = "HIGH"
    elif score >= 3:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "SAFE"

    return score, level


async def assess_domain(session, domain_data, semaphore):
    """
    Menjalankan semua vulnerability checks pada satu domain.
    
    Args:
        session: aiohttp.ClientSession
        domain_data: dict dari tech_fingerprint results
        semaphore: asyncio.Semaphore
    
    Returns:
        dict hasil assessment
    """
    domain = domain_data["domain_name"]
    ip_address = domain_data.get("ip_address", "Unknown")

    print(f"  [*] Assessing: {domain}...")

    all_vulns = []

    # CHECK 1: Outdated Software
    tech_info = domain_data.get("technologies", {})
    all_vulns.extend(check_outdated_software(tech_info))

    # CHECK 2: Missing Security Headers
    security_headers = domain_data.get("security_headers", {})
    all_vulns.extend(check_missing_security_headers(security_headers))

    # CHECK 3: SSL/TLS Issues
    ssl_info = domain_data.get("ssl_info", {})
    all_vulns.extend(check_ssl_issues(ssl_info))

    # CHECK 4: Exposed Admin Panels (async)
    admin_vulns = await check_admin_panels(session, domain, semaphore)
    all_vulns.extend(admin_vulns)

    # CHECK 5: Information Disclosure
    all_vulns.extend(check_information_disclosure(tech_info))

    # CHECK 6: Dangerous Open Ports (jika ada data port scan)
    open_ports = domain_data.get("open_ports", [])
    all_vulns.extend(check_dangerous_open_ports(open_ports))

    # Hitung risk score
    risk_score, risk_level = _calculate_risk_score(all_vulns)

    # Beri ID unik pada setiap vulnerability
    for i, vuln in enumerate(all_vulns, 1):
        vuln["id"] = f"VULN-{domain.replace('.', '-')}-{i:03d}"

    severity_summary = {}
    for v in all_vulns:
        sev = v["severity"]
        severity_summary[sev] = severity_summary.get(sev, 0) + 1

    print(f"  [{'!' if risk_score >= 6 else '+'}] {domain}: "
          f"Score={risk_score}/10 ({risk_level}) — "
          f"{len(all_vulns)} findings {severity_summary}")

    wib = timezone(timedelta(hours=7))
    timestamp = datetime.now(wib).isoformat()

    return {
        "domain_name": domain,
        "ip_address": ip_address,
        "vulnerabilities": all_vulns,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_findings": len(all_vulns),
        "severity_summary": severity_summary,
        "scan_timestamp": timestamp
    }


async def assess_all(tech_fingerprint_data, port_scan_data=None, max_concurrent=None):
    """
    Menjalankan vulnerability assessment pada seluruh domain.
    
    Args:
        tech_fingerprint_data: list dari hasil Modul 3
        port_scan_data: opsional, list dari hasil Modul 2 (untuk merge open_ports)
        max_concurrent: batas koneksi serentak
    """
    if max_concurrent is None:
        max_concurrent = config.MAX_CONCURRENT_CONNECTIONS

    semaphore = asyncio.Semaphore(max_concurrent)

    # Merge port scan data ke fingerprint data jika tersedia
    if port_scan_data:
        port_map = {d["domain_name"]: d.get("open_ports", []) for d in port_scan_data}
        for entry in tech_fingerprint_data:
            domain = entry["domain_name"]
            if domain in port_map:
                entry["open_ports"] = port_map[domain]

    print(f"\n{'='*60}")
    print(f"  MODUL 4: VULNERABILITY SCANNER")
    print(f"  Target: {len(tech_fingerprint_data)} subdomain")
    print(f"  Checks: Outdated SW, Headers, SSL, Admin Panels, InfoDisclosure, Ports")
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
            assess_domain(session, data, semaphore)
            for data in tech_fingerprint_data
        ]
        results = await asyncio.gather(*tasks)

    # Ringkasan akhir
    total_vulns = sum(r["total_findings"] for r in results)
    critical_domains = [r for r in results if r["risk_level"] in ["CRITICAL", "HIGH"]]
    
    global_severity = {}
    for r in results:
        for sev, count in r["severity_summary"].items():
            global_severity[sev] = global_severity.get(sev, 0) + count

    print(f"\n{'='*60}")
    print(f"  VULNERABILITY ASSESSMENT SELESAI")
    print(f"  Total Findings: {total_vulns}")
    print(f"  Severity Breakdown: {global_severity}")
    print(f"  Domain berisiko tinggi: {len(critical_domains)}/{len(results)}")
    print(f"{'='*60}\n")

    return results


def save_results(results, output_path=None):
    """Simpan hasil vulnerability assessment ke file JSON."""
    if output_path is None:
        output_path = config.VULN_REPORT_OUTPUT

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    
    print(f"[+] Vulnerability report disimpan ke: {output_path}")


# =======================================================================
# Standalone execution
# =======================================================================
if __name__ == "__main__":
    import argparse

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    parser = argparse.ArgumentParser(description="Vulnerability Scanner - Modul 4")
    parser.add_argument("--fingerprint-input", 
                        default=config.TECH_FINGERPRINT_OUTPUT,
                        help="Path ke file tech_fingerprint.json")
    parser.add_argument("--port-input",
                        default=config.PORT_SCAN_OUTPUT,
                        help="Path ke file port_scan_results.json (opsional)")
    parser.add_argument("--output", default=config.VULN_REPORT_OUTPUT,
                        help="Path file output JSON")
    parser.add_argument("--limit", type=int, default=0,
                        help="Batasi jumlah domain (0 = semua)")
    parser.add_argument("--test", action="store_true",
                        help="Mode test: assess 3 domain pertama")
    args = parser.parse_args()

    # Load tech fingerprint data
    with open(args.fingerprint_input, "r") as f:
        tech_data = json.load(f)

    # Load port scan data (opsional)
    port_data = None
    if os.path.exists(args.port_input):
        with open(args.port_input, "r") as f:
            port_data = json.load(f)

    # Filter
    if args.test:
        tech_data = tech_data[:3]
        if port_data:
            port_data = port_data[:3]
        print("[!] MODE TEST: Hanya assess 3 domain pertama")
    elif args.limit > 0:
        tech_data = tech_data[:args.limit]
        if port_data:
            port_data = port_data[:args.limit]

    results = asyncio.run(assess_all(tech_data, port_data))
    save_results(results, args.output)
