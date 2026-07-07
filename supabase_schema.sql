-- =================================================================================
-- SUPABASE DATABASE SCHEMA UNTUK PENTEST PIPELINE DSTI UNDIP
-- =================================================================================
-- Cara Penggunaan:
-- 1. Buka dashboard Supabase project Anda
-- 2. Masuk ke menu "SQL Editor"
-- 3. Paste seluruh script ini dan klik "Run"
-- =================================================================================

-- Mengaktifkan ekstensi UUID (secara default sudah aktif di Supabase)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------------------------------------
-- 1. Tabel DOMAINS
-- Menyimpan informasi domain/subdomain yang menjadi target scan
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_name TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------------
-- 2. Tabel SCAN_HISTORY
-- Menyimpan histori atau rekaman hasil dari sebuah sesi scan untuk domain tertentu
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scan_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id UUID NOT NULL REFERENCES public.domains(id) ON DELETE CASCADE,
    risk_score NUMERIC DEFAULT 0.0,
    risk_level TEXT DEFAULT 'SAFE',
    scan_date TIMESTAMPTZ DEFAULT NOW(),
    raw_json JSONB
);

-- Index untuk mempercepat query berdasarkan domain_id
CREATE INDEX IF NOT EXISTS idx_scan_history_domain_id ON public.scan_history(domain_id);

-- ---------------------------------------------------------------------------------
-- 3. Tabel OPEN_PORTS
-- Menyimpan data port yang terbuka dari hasil port scanning
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.open_ports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    history_id UUID NOT NULL REFERENCES public.scan_history(id) ON DELETE CASCADE,
    port_number INTEGER NOT NULL,
    service_name TEXT
);

CREATE INDEX IF NOT EXISTS idx_open_ports_history_id ON public.open_ports(history_id);

-- ---------------------------------------------------------------------------------
-- 4. Tabel TECHNOLOGIES
-- Menyimpan data teknologi (Web Server, CMS) dari hasil tech fingerprinting
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.technologies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    history_id UUID NOT NULL REFERENCES public.scan_history(id) ON DELETE CASCADE,
    web_server TEXT,
    cms TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_technologies_history_id ON public.technologies(history_id);

-- ---------------------------------------------------------------------------------
-- 5. Tabel VULNERABILITIES
-- Menyimpan data kerentanan yang ditemukan dari hasil vuln assessment
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    history_id UUID NOT NULL REFERENCES public.scan_history(id) ON DELETE CASCADE,
    severity TEXT DEFAULT 'LOW',
    check_type TEXT,
    title TEXT,
    description TEXT,
    recommendation TEXT
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_history_id ON public.vulnerabilities(history_id);

-- =================================================================================
-- SETTING RLS (Row Level Security)
-- =================================================================================
-- Mengaktifkan RLS namun mengizinkan Service Role (API Key) untuk bypass.
-- Ini aman karena db_manager.py menggunakan Service Role Key / autentikasi backend.

ALTER TABLE public.domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.open_ports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.technologies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerabilities ENABLE ROW LEVEL SECURITY;

-- Memberikan full access untuk anon/authenticated KETIKA menggunakan service key
-- Anda bisa menyesuaikan policy ini jika frontend Anda butuh akses langsung
CREATE POLICY "Allow Service Role full access to domains" ON public.domains FOR ALL USING (true);
CREATE POLICY "Allow Service Role full access to scan_history" ON public.scan_history FOR ALL USING (true);
CREATE POLICY "Allow Service Role full access to open_ports" ON public.open_ports FOR ALL USING (true);
CREATE POLICY "Allow Service Role full access to technologies" ON public.technologies FOR ALL USING (true);
CREATE POLICY "Allow Service Role full access to vulnerabilities" ON public.vulnerabilities FOR ALL USING (true);

-- =================================================================================
-- SELESAI
-- =================================================================================