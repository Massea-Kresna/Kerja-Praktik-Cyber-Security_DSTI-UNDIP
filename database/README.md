# Database

## Cara skema dikelola

- **Sumber kebenaran struktur tabel** adalah fungsi `ensure_database_schema()` di `db_manager.py`.
  Fungsi ini dipanggil saat aplikasi start (`web_app.py`) dan hanya **menambah**:
  `CREATE TABLE IF NOT EXISTS` dan `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`.
  Tidak ada tabel atau kolom yang dihapus, dan data yang ada tidak diubah.
- **Perubahan data** (misalnya merapikan nama domain) **tidak** dijalankan otomatis.
  Filenya ada di `database/migrations/` dan dijalankan manual.
- `schema_pentest_dashboard.sql` di root proyek hanya berisi 4 tabel awal dan sudah tidak lengkap.
  Gunakan `ensure_database_schema()` sebagai acuan.
- Setiap perubahan dicatat di [`CHANGELOG.md`](CHANGELOG.md), termasuk statusnya di lokal dan di server UNDIP.

## Memeriksa struktur database

```bash
python database/check_schema.py
```

Script ini **hanya membaca**. Isinya daftar tabel dan kolom yang sebenarnya, lalu menandai kolom
yang dibutuhkan kode tapi belum ada. Jalankan di lokal dan di server, lalu bandingkan hasilnya.

## Checklist deploy ke server UNDIP (SSH)

1. **Backup dulu**, sebelum `git pull`:
   ```bash
   pg_dump -h <host> -U <user> -d <database> -Fc -f backup_$(date +%F_%H%M).dump
   ```
2. Catat kondisi sebelum deploy: `python database/check_schema.py > sebelum.md`
3. `git pull`, lalu restart aplikasi. Tabel dan kolom baru dibuat otomatis saat start.
4. Buka `CHANGELOG.md`. Untuk setiap baris **Data manual** yang statusnya "Belum" di server,
   jalankan file migrasinya, urut dari tanggal paling lama:
   ```bash
   psql -h <host> -U <user> -d <database> -f database/migrations/<nama-file>.sql
   ```
   Setiap file menampilkan apa yang akan diubah dan sisa yang bentrok.
5. Periksa lagi: `python database/check_schema.py > sesudah.md`, pastikan ringkasannya
   "semua tabel dan kolom yang dibutuhkan kode sudah ada".
6. Ubah status di `CHANGELOG.md` menjadi "Sudah" untuk server, lalu commit.

Kalau ada yang salah, pulihkan dari backup:
```bash
pg_restore -h <host> -U <user> -d <database> --clean backup_<tanggal>.dump
```

## Aturan saat menambah perubahan database

- Struktur: tambahkan di `ensure_database_schema()` dengan `IF NOT EXISTS`, kolom baru boleh kosong
  (nullable) atau punya default, supaya data lama tetap valid.
- Data: buat file baru `database/migrations/YYYY-MM-DD_NNN_deskripsi.sql` yang aman dijalankan
  berkali-kali dan tidak menimpa data yang bentrok.
- Selalu tambahkan baris di `CHANGELOG.md` dengan status "Sudah" atau "Belum" untuk lokal dan server.
