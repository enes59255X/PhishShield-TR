import aiosqlite
import os
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent.parent / "phishshield.db"

async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                findings TEXT,
                recommendations TEXT,
                features TEXT, -- JSON structure for ML features
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                vote INTEGER NOT NULL,
                user_reputation REAL DEFAULT 1.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS threat_feeds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                source TEXT,
                confidence REAL DEFAULT 0.5,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                action TEXT,
                details TEXT,
                severity TEXT DEFAULT 'INFO',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_analyses_url ON analyses(url);
            CREATE INDEX IF NOT EXISTS idx_threat_url ON threat_feeds(url);
            CREATE INDEX IF NOT EXISTS idx_whitelist ON whitelist(domain);
        """)
        await db.commit()

async def save_analysis_async(data: dict):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO analyses (url, score, risk_level, threat_type, findings, recommendations, features)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["url"],
                data["score"],
                data["risk_level"],
                data["threat_type"],
                "\n".join(data.get("reasons", [])),
                "\n".join(data.get("recommendations", [])),
                data.get("features_json", "{}")
            )
        )
        await db.commit()

async def save_feedback_async(url: str, vote: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO feedback (url, vote) VALUES (?, ?)",
            (url, vote)
        )
        await db.commit()

async def is_blacklisted(url: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT 1 FROM threat_feeds WHERE url = ?", (url,)) as cursor:
            return await cursor.fetchone() is not None

async def add_to_blacklist(url: str, source: str = "manual"):
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                "INSERT OR IGNORE INTO threat_feeds (url, source) VALUES (?, ?)",
                (url, source)
            )
            await db.commit()
        except:
            pass

async def log_security_event(ip: str, action: str, details: str, severity: str = "INFO"):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO security_logs (ip, action, details, severity) VALUES (?, ?, ?, ?)",
            (ip, action, details, severity)
        )
        await db.commit()

async def is_whitelisted(domain: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        # Check specific domain or generic suffix (like .gov.tr)
        async with db.execute(
            "SELECT 1 FROM whitelist WHERE ? LIKE '%' || domain OR domain = ?", 
            (domain, domain)
        ) as cursor:
            return await cursor.fetchone() is not None

async def add_to_whitelist(domain: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO whitelist (domain) VALUES (?)", (domain,))
        await db.commit()
