"""
PhishShield TR - Threat Intelligence Models
Sprint 4: Data models for threat intelligence
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List
from enum import Enum


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatCategory(Enum):
    """Threat categories"""
    PHISHING = "phishing"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    C2 = "c2"
    BOTNET = "botnet"
    SPAM = "spam"
    SCAM = "scam"
    UNKNOWN = "unknown"


class ThreatSource(Enum):
    """Threat intelligence sources"""
    USOM = "usom"
    OPENPHISH = "openphish"
    URLHAUS = "urlhaus"
    MANUAL = "manual"
    INTERNAL = "internal"


@dataclass
class ThreatMatch:
    """
    Result of a threat intelligence lookup.
    
    Attributes:
        is_threat: Whether the URL/domain is a known threat
        domain: The domain that was checked
        source: The source that reported the threat
        category: Type of threat (phishing, malware, etc.)
        severity: Severity level
        confidence: Confidence score (0.0 - 1.0)
        first_seen: When the threat was first seen
        last_seen: When the threat was last seen
        tags: Additional tags/categories
        reference_url: Original reference URL if available
    """
    is_threat: bool = False
    domain: str = ""
    source: Optional[str] = None
    category: str = "unknown"
    severity: str = "medium"
    confidence: float = 0.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    reference_url: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "is_threat": self.is_threat,
            "domain": self.domain,
            "source": self.source,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "tags": self.tags,
            "reference_url": self.reference_url
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ThreatMatch":
        """Create from dictionary"""
        first_seen = None
        if data.get("first_seen"):
            first_seen = datetime.fromisoformat(data["first_seen"])
        
        last_seen = None
        if data.get("last_seen"):
            last_seen = datetime.fromisoformat(data["last_seen"])
        
        return cls(
            is_threat=data.get("is_threat", False),
            domain=data.get("domain", ""),
            source=data.get("source"),
            category=data.get("category", "unknown"),
            severity=data.get("severity", "medium"),
            confidence=data.get("confidence", 0.0),
            first_seen=first_seen,
            last_seen=last_seen,
            tags=data.get("tags", []),
            reference_url=data.get("reference_url")
        )


@dataclass
class ThreatStats:
    """Statistics about threat database"""
    total_domains: int = 0
    by_source: dict = field(default_factory=dict)
    by_category: dict = field(default_factory=dict)
    by_severity: dict = field(default_factory=dict)
    last_update: Optional[datetime] = None
    
    def to_dict(self) -> dict:
        return {
            "total_domains": self.total_domains,
            "by_source": self.by_source,
            "by_category": self.by_category,
            "by_severity": self.by_severity,
            "last_update": self.last_update.isoformat() if self.last_update else None
        }
