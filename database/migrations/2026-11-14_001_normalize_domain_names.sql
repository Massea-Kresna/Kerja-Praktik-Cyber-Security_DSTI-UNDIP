-- 2026-11-14_001_normalize_domain_names.sql
-- Tujuan : samakan nama domain lama dengan aturan baru normalize_domain_name() di db_manager.py
--          (huruf kecil, tanpa awalan "www.").
-- Jenis  : perubahan DATA (bukan struktur). Tidak dijalankan otomatis oleh aplikasi.
-- Aman   : boleh dijalankan berkali-kali. Domain yang bentrok (versi tanpa www sudah ada) TIDAK diubah,
--          tapi ditampilkan di akhir supaya bisa digabung manual.
-- Riwayat scan tetap aman karena scan_history terhubung lewat domain_id, bukan lewat nama.
--
-- Cara pakai di server (setelah backup, lihat database/README.md):
--   psql -h <host> -U <user> -d <database> -f database/migrations/2026-11-14_001_normalize_domain_names.sql

BEGIN;

-- 1) Lihat dulu apa yang akan berubah
SELECT id, domain_name AS sebelum, lower(regexp_replace(domain_name, '^(www\.)+', '', 'i')) AS sesudah
FROM public.domains
WHERE domain_name <> lower(regexp_replace(domain_name, '^(www\.)+', '', 'i'));

-- 2) Ubah hanya yang tidak bentrok dengan domain lain
UPDATE public.domains d
SET domain_name = lower(regexp_replace(d.domain_name, '^(www\.)+', '', 'i'))
WHERE d.domain_name <> lower(regexp_replace(d.domain_name, '^(www\.)+', '', 'i'))
  AND NOT EXISTS (
      SELECT 1 FROM public.domains x
      WHERE x.id <> d.id
        AND x.domain_name = lower(regexp_replace(d.domain_name, '^(www\.)+', '', 'i'))
  );

-- 3) Sisa yang bentrok (harus 0 baris. Kalau ada, gabungkan manual lalu jalankan ulang)
SELECT id, domain_name AS belum_diubah_karena_bentrok
FROM public.domains
WHERE domain_name <> lower(regexp_replace(domain_name, '^(www\.)+', '', 'i'));

COMMIT;
