-- PhishShield TR - PostgreSQL Initialization Script

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create custom types
DO $$ BEGIN
    CREATE TYPE user_tier AS ENUM ('free', 'basic', 'premium', 'enterprise');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create schema migrations table
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Initial migration
INSERT INTO schema_migrations (version) VALUES (1);

-- Create analysis_records table
CREATE TABLE IF NOT EXISTS analysis_records (
    id SERIAL PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    domain VARCHAR(512) NOT NULL,
    decision VARCHAR(20) NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence INTEGER NOT NULL,
    components JSONB,
    reasons JSONB,
    recommendations JSONB,
    threat_match BOOLEAN DEFAULT FALSE,
    threat_sources JSONB,
    ml_probability REAL,
    ml_model_version VARCHAR(50),
    analysis_duration_ms INTEGER,
    client_ip VARCHAR(45),
    client_id VARCHAR(128),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_analysis_url ON analysis_records(url);
CREATE INDEX IF NOT EXISTS idx_analysis_domain ON analysis_records(domain);
CREATE INDEX IF NOT EXISTS idx_analysis_client_id ON analysis_records(client_id);
CREATE INDEX IF NOT EXISTS idx_analysis_decision ON analysis_records(decision);
CREATE INDEX IF NOT EXISTS idx_analysis_created_at ON analysis_records(created_at);
CREATE INDEX IF NOT EXISTS idx_analysis_domain_created ON analysis_records(domain, created_at);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(128) UNIQUE NOT NULL,
    email VARCHAR(512) UNIQUE,
    tier user_tier DEFAULT 'free',
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    api_requests_today INTEGER DEFAULT 0,
    api_requests_total INTEGER DEFAULT 0,
    last_request_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Create api_keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    key_hash VARCHAR(64) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(256),
    tier user_tier DEFAULT 'free',
    is_active BOOLEAN DEFAULT TRUE,
    requests_count INTEGER DEFAULT 0,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);

-- Create feedback table
CREATE TABLE IF NOT EXISTS feedback (
    id SERIAL PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    domain VARCHAR(512) NOT NULL,
    original_decision VARCHAR(20) NOT NULL,
    original_score INTEGER NOT NULL,
    feedback_type VARCHAR(50) NOT NULL,
    correct_label VARCHAR(50),
    message TEXT,
    user_id INTEGER REFERENCES users(id),
    resolved BOOLEAN DEFAULT FALSE,
    used_for_training BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_feedback_url ON feedback(url);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at);

-- Create alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    title VARCHAR(512) NOT NULL,
    message TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(50),
    source VARCHAR(256),
    metadata JSONB,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP,
    resolved_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(128) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(512),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Create learning_samples table
CREATE TABLE IF NOT EXISTS learning_samples (
    id SERIAL PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    domain VARCHAR(512) NOT NULL,
    label VARCHAR(50) NOT NULL,
    source VARCHAR(50) NOT NULL,
    features JSONB NOT NULL,
    risk_score INTEGER NOT NULL,
    ml_probability REAL,
    reviewed BOOLEAN DEFAULT FALSE,
    reviewed_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_learning_label ON learning_samples(label);
CREATE INDEX IF NOT EXISTS idx_learning_created ON learning_samples(created_at);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for users table
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO phishshield;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO phishshield;

-- Vacuum analyze for performance
VACUUM ANALYZE;
