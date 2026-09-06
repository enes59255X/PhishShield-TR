#!/usr/bin/env python3
"""
PhishShield TR - Database Manager
SQLite veritabanu yönetimi ve operasyonlar
"""

import sqlite3
import json
import asyncio
import aiosqlite
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import hashlib
import os

class DatabaseManager:
    def __init__(self, db_path: str = "phishshield.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Veritabanini baslat ve tablolari olustur"""
        with sqlite3.connect(self.db_path) as conn:
            # Schema dosyasini oku ve calistir
            schema_path = os.path.join(os.path.dirname(__file__), 'database_schema.sql')
            if os.path.exists(schema_path):
                with open(schema_path, 'r', encoding='utf-8') as f:
                    schema_sql = f.read()
                conn.executescript(schema_sql)
            else:
                # Schema dosyasi yoksa manuel olustur
                self._create_tables_manually(conn)
            conn.commit()
    
    def _create_tables_manually(self, conn):
        """Manuel tablo olusturma (fallback)"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS site_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                threat_type TEXT,
                reasons TEXT,
                recommendations TEXT,
                sub_scores TEXT,
                analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT,
                ip_address TEXT,
                is_phishing BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS official_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                subcategory TEXT,
                description TEXT,
                is_active BOOLEAN DEFAULT 1,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS phishing_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                threat_level INTEGER DEFAULT 1,
                pattern_type TEXT,
                source TEXT,
                confidence_score REAL DEFAULT 0.0,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                notes TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS user_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                feedback_type TEXT NOT NULL, -- 'false_positive', 'false_negative', 'general'
                is_official_site BOOLEAN DEFAULT 0,
                user_id TEXT, -- browser fingerprint veya session id
                user_comment TEXT,
                screenshot_path TEXT,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed BOOLEAN DEFAULT 0,
                review_result TEXT,
                reviewed_at TIMESTAMP,
                UNIQUE(url, user_id) -- Her kullanıcı bir URL için 1 kez
            )
            """,
            """
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
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                action TEXT NOT NULL,
                score INTEGER,
                risk_level TEXT,
                processing_time_ms INTEGER,
                source TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        ]
        
        for table_sql in tables:
            conn.execute(table_sql)
    
    async def save_analysis(self, analysis_data: Dict) -> int:
        """Site analizini kaydet"""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("""
                INSERT INTO site_analyses 
                (url, domain, score, risk_level, threat_type, reasons, recommendations, 
                 sub_scores, user_agent, ip_address, is_phishing)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis_data['url'],
                analysis_data['domain'],
                analysis_data['score'],
                analysis_data['risk_level'],
                analysis_data.get('threat_type'),
                json.dumps(analysis_data.get('reasons', [])),
                json.dumps(analysis_data.get('recommendations', [])),
                json.dumps(analysis_data.get('sub_scores', {})),
                analysis_data.get('user_agent'),
                analysis_data.get('ip_address'),
                analysis_data.get('is_phishing', False)
            ))
            await conn.commit()
            return cursor.lastrowid
    
    async def log_activity(self, activity_data: Dict) -> int:
        """Aktivite log'u kaydet"""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("""
                INSERT INTO activity_logs 
                (url, domain, action, score, risk_level, processing_time_ms, source, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                activity_data['url'],
                activity_data['domain'],
                activity_data['action'],
                activity_data.get('score'),
                activity_data.get('risk_level'),
                activity_data.get('processing_time_ms'),
                activity_data.get('source', 'extension'),
                json.dumps(activity_data.get('metadata', {}))
            ))
            await conn.commit()
            return cursor.lastrowid
    
    async def get_recent_activities(self, limit: int = 10) -> List[Dict]:
        """Son aktiviteleri getir"""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("""
                SELECT url, domain, action, score, risk_level, created_at
                FROM activity_logs 
                ORDER BY created_at DESC 
                LIMIT ?
            """, (limit,))
            
            rows = await cursor.fetchall()
            return [
                {
                    'url': row[0],
                    'domain': row[1],
                    'action': row[2],
                    'score': row[3],
                    'risk_level': row[4],
                    'timestamp': row[5]
                }
                for row in rows
            ]
    
    async def get_statistics(self) -> Dict:
        """Sistem istatistiklerini getir"""
        async with aiosqlite.connect(self.db_path) as conn:
            # Bugünün istatistikleri
            today = datetime.now().date()
            cursor = await conn.execute("""
                SELECT total_analyzed, threats_detected, safe_sites, high_risk, critical_risk
                FROM system_stats 
                WHERE date = ?
            """, (today,))
            
            row = await cursor.fetchone()
            
            if row:
                return {
                    'total_analyzed': row[0],
                    'threats_detected': row[1],
                    'safe_sites': row[2],
                    'high_risk': row[3],
                    'critical_risk': row[4]
                }
            else:
                # Bugün için kayit yoksa genel istatistikleri hesapla
                cursor = await conn.execute("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as threats,
                        SUM(CASE WHEN is_phishing = 0 THEN 1 ELSE 0 END) as safe,
                        SUM(CASE WHEN score >= 60 AND score < 80 THEN 1 ELSE 0 END) as high,
                        SUM(CASE WHEN score >= 80 THEN 1 ELSE 0 END) as critical
                    FROM site_analyses 
                    WHERE created_at >= date('now')
                """)
                
                row = await cursor.fetchone()
                return {
                    'total_analyzed': row[0] or 0,
                    'threats_detected': row[1] or 0,
                    'safe_sites': row[2] or 0,
                    'high_risk': row[3] or 0,
                    'critical_risk': row[4] or 0
                }
    
    async def get_official_domains(self) -> List[str]:
        """Resmi domain'leri getir"""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("""
                SELECT domain FROM official_domains WHERE is_active = 1
            """)
            rows = await cursor.fetchall()
            return [row[0] for row in rows]
    
    async def get_phishing_domains(self) -> List[str]:
        """Phishing domain'lerini getir"""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("""
                SELECT domain FROM phishing_domains WHERE is_active = 1
            """)
            rows = await cursor.fetchall()
            return [row[0] for row in rows]
    
    async def add_official_domain(self, domain: str, category: str, description: str = ""):
        """Resmi domain ekle"""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                INSERT OR REPLACE INTO official_domains 
                (domain, category, description)
                VALUES (?, ?, ?)
            """, (domain, category, description))
            await conn.commit()
    
    async def add_phishing_domain(self, domain: str, threat_level: int = 1, source: str = "manual", notes: str = ""):
        """Phishing domain ekle"""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                INSERT OR REPLACE INTO phishing_domains 
                (domain, threat_level, source, last_seen, notes)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)
            """, (domain, threat_level, source, notes))
            await conn.commit()
    
    async def update_daily_stats(self):
        """Günlük istatistikleri güncelle"""
        today = datetime.now().date()
        async with aiosqlite.connect(self.db_path) as conn:
            # Bugünün analizlerini hesapla
            cursor = await conn.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as threats,
                    SUM(CASE WHEN is_phishing = 0 THEN 1 ELSE 0 END) as safe,
                    SUM(CASE WHEN score >= 60 AND score < 80 THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN score >= 80 THEN 1 ELSE 0 END) as critical
                FROM site_analyses 
                WHERE DATE(created_at) = ?
            """, (today,))
            
            row = await cursor.fetchone()
            
            if row and row[0] > 0:
                accuracy = (row[2] / row[0]) * 100 if row[0] > 0 else 0
                await conn.execute("""
                    INSERT OR REPLACE INTO system_stats 
                    (date, total_analyzed, threats_detected, safe_sites, high_risk, critical_risk, accuracy_rate)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (today, row[0], row[1], row[2], row[3], row[4], accuracy))
                await conn.commit()
    
    async def add_user_feedback(self, url: str, domain: str, feedback_type: str, user_id: str, 
                                 is_official_site: bool = False, user_comment: str = "", 
                                 screenshot_path: str = "") -> bool:
        """Kullanıcı geri bildirimi ekle - her kullanıcı bir URL için 1 kez"""
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                await conn.execute("""
                    INSERT OR REPLACE INTO user_feedback 
                    (url, domain, feedback_type, user_id, is_official_site, user_comment, screenshot_path, submitted_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (url, domain, feedback_type, user_id, is_official_site, user_comment, screenshot_path))
                await conn.commit()
                return True
        except Exception as e:
            print(f"Feedback ekleme hatası: {e}")
            return False
    
    async def check_user_feedback_exists(self, url: str, user_id: str) -> bool:
        """Kullanıcı bu URL için daha önce feedback vermiş mi?"""
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                cursor = await conn.execute("""
                    SELECT COUNT(*) FROM user_feedback 
                    WHERE url = ? AND user_id = ?
                """, (url, user_id))
                row = await cursor.fetchone()
                return row[0] > 0
        except:
            return False
    
    async def get_user_feedback_stats(self, user_id: str = None) -> Dict:
        """Kullanıcı geri bildirim istatistikleri"""
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                if user_id:
                    cursor = await conn.execute("""
                        SELECT COUNT(*) FROM user_feedback WHERE user_id = ?
                    """, (user_id,))
                else:
                    cursor = await conn.execute("""
                        SELECT COUNT(*) FROM user_feedback
                    """)
                row = await cursor.fetchone()
                return {"total_feedback": row[0]}
        except:
            return {"total_feedback": 0}
    
    async def get_pending_feedback_reviews(self) -> List[Dict]:
        """İncelenmemiş geri bildirimleri getir"""
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                cursor = await conn.execute("""
                    SELECT url, domain, feedback_type, is_official_site, user_comment, submitted_at
                    FROM user_feedback 
                    WHERE reviewed = 0
                    ORDER BY submitted_at DESC
                """)
                rows = await cursor.fetchall()
                return [
                    {
                        'url': row[0],
                        'domain': row[1],
                        'feedback_type': row[2],
                        'is_official_site': row[3],
                        'user_comment': row[4],
                        'submitted_at': row[5]
                    }
                    for row in rows
                ]
        except:
            return []

# Singleton instance
db_manager = DatabaseManager()
