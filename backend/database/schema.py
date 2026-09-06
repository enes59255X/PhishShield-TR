"""
Database Schema - PhishShield TR V3

Database schema creation and management utilities.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from typing import Optional
import logging


logger = logging.getLogger(__name__)


def get_connection_string(
    host: str = "localhost",
    port: int = 5432,
    database: str = "phishshield",
    username: str = "postgres",
    password: str = ""
) -> str:
    """
    Build PostgreSQL connection string.
    
    Args:
        host: Database host
        port: Database port
        database: Database name
        username: Username
        password: Password
        
    Returns:
        Connection string
    """
    return f"postgresql://{username}:{password}@{host}:{port}/{database}"


def create_tables(engine, base):
    """
    Create all database tables.
    
    Args:
        engine: SQLAlchemy engine
        base: Declarative base class
    """
    base.metadata.create_all(engine)
    logger.info("Database tables created successfully")


def drop_tables(engine, base):
    """
    Drop all database tables.
    
    Args:
        engine: SQLAlchemy engine
        base: Declarative base class
    """
    base.metadata.drop_all(engine)
    logger.info("Database tables dropped successfully")


def get_schema_sql(base) -> str:
    """
    Get SQL for creating all tables.
    
    Args:
        base: Declarative base class
        
    Returns:
        SQL string for table creation
    """
    from sqlalchemy.schema import CreateTable
    
    statements = []
    for table in base.metadata.sorted_tables:
        statements.append(str(CreateTable(table).compile()))
    
    return "\n\n".join(statements)


class DatabaseManager:
    """
    Database connection and session management.
    """
    
    def __init__(
        self,
        connection_string: Optional[str] = None,
        echo: bool = False
    ):
        self.connection_string = connection_string or get_connection_string()
        self.echo = echo
        self._engine = None
        self._session_factory = None
    
    @property
    def engine(self):
        """Get or create SQLAlchemy engine"""
        if self._engine is None:
            self._engine = create_engine(
                self.connection_string,
                echo=self.echo,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
            )
        return self._engine
    
    @property
    def session_factory(self):
        """Get or create session factory"""
        if self._session_factory is None:
            self._session_factory = sessionmaker(
                bind=self.engine,
                autocommit=False,
                autoflush=False,
            )
        return self._session_factory
    
    def get_session(self) -> Session:
        """Get a new database session"""
        return self.session_factory()
    
    def close(self):
        """Close database connection"""
        if self._engine:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None


class DatabaseMigrations:
    """
    Simple database migrations manager.
    
    Tracks applied migrations and applies new ones.
    """
    
    MIGRATIONS_TABLE = "schema_migrations"
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self._ensure_migrations_table()
    
    def _ensure_migrations_table(self):
        """Create migrations tracking table if not exists"""
        with self.db.engine.connect() as conn:
            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS {self.MIGRATIONS_TABLE} (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.commit()
    
    def get_applied_migrations(self) -> list:
        """Get list of applied migration versions"""
        with self.db.engine.connect() as conn:
            result = conn.execute(
                text(f"SELECT version FROM {self.MIGRATIONS_TABLE}")
            )
            return [row[0] for row in result]
    
    def apply_migration(self, version: int, migration_sql: str):
        """Apply a migration"""
        with self.db.engine.connect() as conn:
            conn.execute(text(migration_sql))
            conn.execute(
                text(f"INSERT INTO {self.MIGRATIONS_TABLE} (version) VALUES (:v)"),
                {"v": version}
            )
            conn.commit()
        self.db.engine.dispose()
    
    def rollback_migration(self, version: int):
        """Rollback a migration"""
        with self.db.engine.connect() as conn:
            conn.execute(
                text(f"DELETE FROM {self.MIGRATIONS_TABLE} WHERE version = :v"),
                {"v": version}
            )
            conn.commit()
