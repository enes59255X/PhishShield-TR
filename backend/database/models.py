"""
Database Models - PhishShield TR V3

SQLAlchemy models for PostgreSQL database.
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, 
    Text, JSON, Float, ForeignKey, Index, Enum as SQLEnum
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
import enum


Base = declarative_base()


class UserTier(enum.Enum):
    """User subscription tiers"""
    FREE = "free"
    BASIC = "basic"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"


class AnalysisRecord(Base):
    """
    Analysis result record.
    
    Stores all URL analysis results for audit and learning.
    """
    __tablename__ = "analysis_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    domain = Column(String(512), nullable=False, index=True)
    
    decision = Column(String(20), nullable=False)
    risk_score = Column(Integer, nullable=False)
    confidence = Column(Integer, nullable=False)
    
    components = Column(JSON, nullable=True)
    reasons = Column(JSON, nullable=True)
    recommendations = Column(JSON, nullable=True)
    
    threat_match = Column(Boolean, default=False)
    threat_sources = Column(JSON, nullable=True)
    
    ml_probability = Column(Float, nullable=True)
    ml_model_version = Column(String(50), nullable=True)
    
    analysis_duration_ms = Column(Integer, nullable=True)
    
    client_ip = Column(String(45), nullable=True)
    client_id = Column(String(128), nullable=True, index=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index("idx_analysis_domain_created", "domain", "created_at"),
        Index("idx_analysis_decision_created", "decision", "created_at"),
    )


class User(Base):
    """
    User account model.
    
    Stores user information and authentication data.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(128), unique=True, nullable=False, index=True)
    email = Column(String(512), unique=True, nullable=True)
    
    tier = Column(SQLEnum(UserTier), default=UserTier.FREE)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    api_requests_today = Column(Integer, default=0)
    api_requests_total = Column(Integer, default=0)
    
    last_request_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    feedback = relationship("Feedback", back_populates="user", cascade="all, delete-orphan")


class APIKey(Base):
    """
    API Key model.
    
    Stores API keys for authentication.
    """
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="api_keys")
    
    name = Column(String(256), nullable=True)
    tier = Column(SQLEnum(UserTier), default=UserTier.FREE)
    
    is_active = Column(Boolean, default=True)
    
    requests_count = Column(Integer, default=0)
    last_used_at = Column(DateTime, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)


class Feedback(Base):
    """
    User feedback model.
    
    Stores user corrections and feedback on analysis results.
    """
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    
    url = Column(String(2048), nullable=False, index=True)
    domain = Column(String(512), nullable=False)
    
    original_decision = Column(String(20), nullable=False)
    original_score = Column(Integer, nullable=False)
    
    feedback_type = Column(String(50), nullable=False)
    correct_label = Column(String(50), nullable=True)
    
    message = Column(Text, nullable=True)
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="feedback")
    
    resolved = Column(Boolean, default=False)
    used_for_training = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime, nullable=True)


class Alert(Base):
    """
    System alert model.
    
    Stores security alerts and system notifications.
    """
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    
    title = Column(String(512), nullable=False)
    message = Column(Text, nullable=False)
    
    severity = Column(String(20), nullable=False, index=True)
    category = Column(String(50), nullable=True)
    
    source = Column(String(256), nullable=True)
    alert_metadata = Column(JSON, nullable=True)
    
    resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index("idx_alerts_severity_created", "severity", "created_at"),
    )


class Session(Base):
    """
    User session model.
    
    Stores active user sessions for JWT refresh.
    """
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    
    session_id = Column(String(128), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    refresh_token_hash = Column(String(64), nullable=False)
    
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity_at = Column(DateTime, default=datetime.utcnow)


class LearningSample(Base):
    """
    Learning sample model.
    
    Stores labeled samples for ML model training.
    """
    __tablename__ = "learning_samples"

    id = Column(Integer, primary_key=True, autoincrement=True)
    
    url = Column(String(2048), nullable=False, index=True)
    domain = Column(String(512), nullable=False)
    
    label = Column(String(50), nullable=False, index=True)
    source = Column(String(50), nullable=False)
    
    features = Column(JSON, nullable=False)
    risk_score = Column(Integer, nullable=False)
    ml_probability = Column(Float, nullable=True)
    
    reviewed = Column(Boolean, default=False)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index("idx_learning_label_created", "label", "created_at"),
    )
