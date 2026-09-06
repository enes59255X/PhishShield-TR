"""
Database Module - PhishShield TR V3

PostgreSQL database models and schema management.
"""

from database.models import (
    AnalysisRecord,
    User,
    APIKey,
    Feedback,
    Alert,
    Session,
    Base,
)
from database.schema import (
    create_tables,
    drop_tables,
    get_schema_sql,
)
from database.migrations import MigrationManager

__all__ = [
    "AnalysisRecord",
    "User",
    "APIKey",
    "Feedback",
    "Alert",
    "Session",
    "Base",
    "create_tables",
    "drop_tables",
    "get_schema_sql",
    "MigrationManager",
]
