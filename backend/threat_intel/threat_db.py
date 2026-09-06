"""
PhishShield TR - Threat Database
Sprint 4: SQLite database for threat intelligence storage
"""

import sqlite3
import os
from datetime import datetime
from typing import List, Optional, Dict
from contextlib import contextmanager

from .models import ThreatMatch, ThreatStats


class ThreatDatabase:
    """
    SQLite database for threat intelligence.
    
    Tables:
        - threat_domains: Known malicious domains
        - threat_sources: Feed source status
        - threat_cache: Recent lookups cache
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "database", "threat.db")
        
        self.db_path = db_path
        self._ensure_db_dir()
        self._init_db()
    
    def _ensure_db_dir(self):
        """Ensure database directory exists"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    @contextmanager
    def _get_conn(self):
        """Get database connection with context manager"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database schema"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            
            # Threat domains table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL,
                    category TEXT DEFAULT 'phishing',
                    severity TEXT DEFAULT 'medium',
                    confidence REAL DEFAULT 0.8,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    tags TEXT DEFAULT '',
                    reference_url TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create index for fast domain lookup
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_domain 
                ON threat_domains(domain, is_active)
            """)
            
            # Threat sources table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    status TEXT DEFAULT 'unknown',
                    last_update TEXT,
                    last_error TEXT,
                    domains_loaded INTEGER DEFAULT 0,
                    is_enabled INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Threat cache table (for recent lookups)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    lookup_result TEXT NOT NULL,
                    looked_up_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    expires_at TEXT NOT NULL
                )
            """)
            
            # Create index for cache
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_domain 
                ON threat_cache(domain, expires_at)
            """)
    
    def add_threat(
        self,
        domain: str,
        source: str,
        category: str = "phishing",
        severity: str = "medium",
        confidence: float = 0.8,
        tags: List[str] = None,
        reference_url: str = None
    ) -> bool:
        """
        Add a domain to the threat database.
        
        Returns:
            True if added, False if already exists or error
        """
        now = datetime.now().isoformat()
        tags_str = ",".join(tags) if tags else ""
        domain_lower = domain.lower()
        
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                # Check if exists first
                cursor.execute("SELECT domain FROM threat_domains WHERE domain = ?", (domain_lower,))
                exists = cursor.fetchone() is not None
                
                if exists:
                    # Update existing
                    cursor.execute("""
                        UPDATE threat_domains 
                        SET last_seen = ?,
                            source = COALESCE(?, source),
                            severity = COALESCE(?, severity),
                            confidence = MAX(confidence, ?),
                            updated_at = CURRENT_TIMESTAMP
                        WHERE domain = ?
                    """, (now, source, severity, confidence, domain_lower))
                else:
                    # Insert new
                    cursor.execute("""
                        INSERT INTO threat_domains 
                        (domain, source, category, severity, confidence, first_seen, last_seen, tags, reference_url)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (domain_lower, source, category, severity, confidence, now, now, tags_str, reference_url))
                return True
        except Exception as e:
            # Silently ignore errors
            return False
    
    def is_threat(self, domain: str) -> Optional[ThreatMatch]:
        """
        Check if a domain is in the threat database.
        
        Returns:
            ThreatMatch if found, None if not found
        """
        domain_lower = domain.lower()
        
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM threat_domains 
                WHERE (domain = ? OR domain LIKE ? OR ? LIKE '%' || domain)
                AND is_active = 1
                ORDER BY confidence DESC
                LIMIT 1
            """, (domain_lower, domain_lower, domain_lower))
            
            row = cursor.fetchone()
            if row:
                return ThreatMatch(
                    is_threat=True,
                    domain=row["domain"],
                    source=row["source"],
                    category=row["category"],
                    severity=row["severity"],
                    confidence=row["confidence"],
                    first_seen=datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None,
                    last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
                    tags=row["tags"].split(",") if row["tags"] else [],
                    reference_url=row["reference_url"]
                )
        
        return None
    
    def check_subdomain(self, domain: str) -> Optional[ThreatMatch]:
        """
        Check if any parent domain is a known threat.
        E.g., evil.google.com -> google.com threat check.
        
        Returns:
            ThreatMatch if parent domain is a threat, None otherwise
        """
        parts = domain.lower().split(".")
        for i in range(len(parts)):
            parent = ".".join(parts[i:])
            result = self.is_threat(parent)
            if result:
                return result
        return None
    
    def get_stats(self) -> ThreatStats:
        """Get threat database statistics"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            
            # Total count
            cursor.execute("SELECT COUNT(*) as count FROM threat_domains WHERE is_active = 1")
            total = cursor.fetchone()["count"]
            
            # By source
            cursor.execute("""
                SELECT source, COUNT(*) as count 
                FROM threat_domains WHERE is_active = 1 
                GROUP BY source
            """)
            by_source = {row["source"]: row["count"] for row in cursor.fetchall()}
            
            # By category
            cursor.execute("""
                SELECT category, COUNT(*) as count 
                FROM threat_domains WHERE is_active = 1 
                GROUP BY category
            """)
            by_category = {row["category"]: row["count"] for row in cursor.fetchall()}
            
            # By severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM threat_domains WHERE is_active = 1 
                GROUP BY severity
            """)
            by_severity = {row["severity"]: row["count"] for row in cursor.fetchall()}
            
            return ThreatStats(
                total_domains=total,
                by_source=by_source,
                by_category=by_category,
                by_severity=by_severity
            )
    
    def update_source_status(self, source: str, status: str, error: str = None, domains_loaded: int = 0):
        """Update threat source status"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO threat_sources (name, status, last_error, domains_loaded, last_update)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    status = excluded.status,
                    last_error = excluded.last_error,
                    domains_loaded = excluded.domains_loaded,
                    last_update = excluded.last_update,
                    updated_at = CURRENT_TIMESTAMP
            """, (source, status, error, domains_loaded, datetime.now().isoformat()))
    
    def get_source_status(self) -> Dict:
        """Get status of all threat sources"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM threat_sources ORDER BY name")
            rows = cursor.fetchall()
            return {
                row["name"]: {
                    "status": row["status"],
                    "last_update": row["last_update"],
                    "last_error": row["last_error"],
                    "domains_loaded": row["domains_loaded"],
                    "is_enabled": bool(row["is_enabled"])
                }
                for row in rows
            }
    
    def bulk_add(self, threats: List[Dict]) -> int:
        """
        Bulk add threats from a list of dictionaries.
        
        Args:
            threats: List of dicts with domain, source, category, severity, confidence
        
        Returns:
            Number of threats added
        """
        added = 0
        for t in threats:
            if self.add_threat(
                domain=t["domain"],
                source=t["source"],
                category=t.get("category", "phishing"),
                severity=t.get("severity", "medium"),
                confidence=t.get("confidence", 0.8),
                tags=t.get("tags", []),
                reference_url=t.get("reference_url")
            ):
                added += 1
        return added
    
    def get_domains_by_source(self, source: str) -> List[str]:
        """Get all active domains from a specific source"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT domain FROM threat_domains 
                WHERE source = ? AND is_active = 1
            """, (source,))
            return [row["domain"] for row in cursor.fetchall()]

    def clear_expired_cache(self):
        """Clear expired cache entries"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM threat_cache 
                WHERE expires_at < ?
            """, (datetime.now().isoformat(),))


# Singleton instance
threat_db = ThreatDatabase()
