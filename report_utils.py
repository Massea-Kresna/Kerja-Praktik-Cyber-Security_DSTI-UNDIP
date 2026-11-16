"""Bantuan kecil untuk laporan Pentest-Tools (tanpa akses database)."""
import re
from datetime import datetime, timezone, timedelta

WIB = timezone(timedelta(hours=7))


def report_filename(domain, scan_date, fmt):
    """Nama file laporan: laporan_<domain>_<YYYY-MM-DD>.<ext>, tanggal dalam WIB.

    Aturannya sama dengan grFileName() di dashboard/app.js, jadi file yang
    diunduh dan lampiran email bernama sama.
    """
    ext = str(fmt or 'pdf').lower()
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', str(domain or '').strip())
    if not safe:
        return f"laporan_scan.{ext}"

    day = None
    if isinstance(scan_date, str):
        try:
            scan_date = datetime.fromisoformat(scan_date)
        except ValueError:
            m = re.match(r'(\d{4}-\d{2}-\d{2})', scan_date)
            day = m.group(1) if m else None
            scan_date = None
    if isinstance(scan_date, datetime):
        if scan_date.tzinfo is not None:
            scan_date = scan_date.astimezone(WIB)
        day = scan_date.strftime('%Y-%m-%d')

    return f"laporan_{safe}_{day}.{ext}" if day else f"laporan_{safe}.{ext}"
