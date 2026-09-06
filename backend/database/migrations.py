"""
Database Migrations - PhishShield TR V3

Migration scripts for database schema changes.
"""

from typing import Dict, Callable
from dataclasses import dataclass


@dataclass
class Migration:
    """Migration definition"""
    version: int
    description: str
    up: str
    down: str


MIGRATIONS: Dict[int, Migration] = {}


def register_migration(version: int, description: str):
    """Decorator to register a migration"""
    def decorator(func: Callable[[], str]):
        sql = func()
        MIGRATIONS[version] = Migration(
            version=version,
            description=description,
            up=sql,
            down=""
        )
        return func
    return decorator


# Migration 001: Initial Schema
@register_migration(1, "Initial schema")
def migration_001() -> str:
    return """
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
    """


# Migration 002: Users and API Keys
@register_migration(2, "Add users and API keys")
def migration_002() -> str:
    return """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(128) UNIQUE NOT NULL,
        email VARCHAR(512) UNIQUE,
        tier VARCHAR(20) DEFAULT 'free',
        is_active BOOLEAN DEFAULT TRUE,
        is_admin BOOLEAN DEFAULT FALSE,
        api_requests_today INTEGER DEFAULT 0,
        api_requests_total INTEGER DEFAULT 0,
        last_request_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS api_keys (
        id SERIAL PRIMARY KEY,
        key_hash VARCHAR(64) UNIQUE NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(256),
        tier VARCHAR(20) DEFAULT 'free',
        is_active BOOLEAN DEFAULT TRUE,
        requests_count INTEGER DEFAULT 0,
        last_used_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
    CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
    """


# Migration 003: Feedback and Learning
@register_migration(3, "Add feedback and learning samples")
def migration_003() -> str:
    return """
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
    
    CREATE INDEX IF NOT EXISTS idx_feedback_url ON feedback(url);
    CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at);
    CREATE INDEX IF NOT EXISTS idx_learning_label ON learning_samples(label);
    CREATE INDEX IF NOT EXISTS idx_learning_created ON learning_samples(created_at);
    """


# Migration 004: Alerts and Sessions
@register_migration(4, "Add alerts and sessions")
def migration_004() -> str:
    return """
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
    
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved);
    CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
    CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    """


class MigrationManager:
    """
    Manages database migrations.
    """
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.migrations = MIGRATIONS
    
    def get_current_version(self) -> int:
        """Get current migration version"""
        from sqlalchemy import text
        try:
            with self.db.engine.connect() as conn:
                result = conn.execute(
                    text("SELECT MAX(version) FROM schema_migrations")
                ).scalar()
                return result or 0
        except:
            return 0
    
    def get_pending_migrations(self) -> list:
        """Get migrations that need to be applied"""
        current = self.get_current_version()
        return [
            m for v, m in sorted(self.migrations.items())
            if v > current
        ]
    
    def apply_all(self):
        """Apply all pending migrations"""
        for migration in self.get_pending_migrations():
            print(f"Applying migration {migration.version}: {migration.description}")
            self.db.apply_migration(migration.version, migration.up)
    
    def migrate_to(self, target_version: int):
        """Migrate to specific version"""
        current = self.get_current_version()
        
        if target_version > current:
            for migration in self.get_pending_migrations():
                if migration.version <= target_version:
                    print(f"Applying migration {migration.version}")
                    self.db.apply_migration(migration.version, migration.up)
        
        elif target_version < current:
            print("Downgrade not implemented")
