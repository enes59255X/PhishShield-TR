-- PhishShield TR Veritabanu Schema
-- SQLite 3.x

-- 1. Site Analizleri
CREATE TABLE IF NOT EXISTS site_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    threat_type TEXT,
    reasons TEXT, -- JSON array
    recommendations TEXT, -- JSON array
    sub_scores TEXT, -- JSON object
    analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    ip_address TEXT,
    is_phishing BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Resmi Domain'ler (Beyaz Liste)
CREATE TABLE IF NOT EXISTS official_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    category TEXT NOT NULL, -- 'government', 'education', 'bank', 'ecommerce'
    subcategory TEXT,
    description TEXT,
    is_active BOOLEAN DEFAULT 1,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Phishing Domain'ler (Kara Liste)
CREATE TABLE IF NOT EXISTS phishing_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    threat_level INTEGER DEFAULT 1, -- 1-10 scale
    pattern_type TEXT, -- 'exact', 'wildcard', 'regex'
    source TEXT, -- 'manual', 'usom', 'user_report', 'ai_detection'
    confidence_score REAL DEFAULT 0.0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    notes TEXT
);

-- 4. Kullanici Bildirimleri
CREATE TABLE IF NOT EXISTS user_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    user_score INTEGER,
    user_risk_level TEXT,
    feedback TEXT,
    user_agent TEXT,
    ip_address TEXT,
    is_confirmed BOOLEAN DEFAULT 0,
    reviewed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. Sistem Istatistikleri
CREATE TABLE IF NOT EXISTS system_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE UNIQUE NOT NULL,
    total_analyzed INTEGER DEFAULT 0,
    threats_detected INTEGER DEFAULT 0,
    safe_sites INTEGER DEFAULT 0,
    high_risk INTEGER DEFAULT 0,
    critical_risk INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    accuracy_rate REAL DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. Gerçek Zamanli Aktivite Log'lari
CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    action TEXT NOT NULL, -- 'analyze', 'phishing_detected', 'safe_confirmed'
    score INTEGER,
    risk_level TEXT,
    processing_time_ms INTEGER,
    source TEXT, -- 'extension', 'api', 'manual'
    metadata TEXT, -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 7. Cache Tablosu (Performans için)
CREATE TABLE IF NOT EXISTS analysis_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_hash TEXT UNIQUE NOT NULL,
    url TEXT NOT NULL,
    result TEXT NOT NULL, -- JSON
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index'ler
CREATE INDEX IF NOT EXISTS idx_site_analyses_url ON site_analyses(url);
CREATE INDEX IF NOT EXISTS idx_site_analyses_domain ON site_analyses(domain);
CREATE INDEX IF NOT EXISTS idx_site_analyses_created_at ON site_analyses(created_at);
CREATE INDEX IF NOT EXISTS idx_phishing_domains_domain ON phishing_domains(domain);
CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_analysis_cache_expires_at ON analysis_cache(expires_at);

-- Trigger'lar
CREATE TRIGGER IF NOT EXISTS update_official_domains_updated_at
    AFTER UPDATE ON official_domains
    FOR EACH ROW
BEGIN
    UPDATE official_domains SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_phishing_domains_last_seen
    AFTER UPDATE ON phishing_domains
    FOR EACH ROW
BEGIN
    UPDATE phishing_domains SET last_seen = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
