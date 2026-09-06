"""
Learning System - Feedback Handler
PhishShield TR V3

Handles user feedback on analysis results.
"""

import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


class FeedbackType(Enum):
    """Type of feedback"""
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    CORRECT = "correct"
    INCORRECT = "incorrect"
    REVIEW_REQUEST = "review_request"


@dataclass
class FeedbackEntry:
    """Single feedback entry"""
    url: str
    domain: str
    feedback_type: str
    original_score: int
    original_decision: str
    user_label: Optional[str]
    message: Optional[str]
    timestamp: float
    source: str
    resolved: bool = False
    used_for_training: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeedbackEntry":
        return cls(**data)


class FeedbackHandler:
    """
    Handles user feedback on phishing analysis.
    
    Accepts feedback via:
    - Browser extension
    - API
    - Dashboard
    
    Processes feedback to:
    - Correct training labels
    - Improve future analysis
    - Track user trust
    """

    def __init__(self, storage_path: str = "data/feedback.jsonl"):
        self.storage_path = storage_path
        self._feedback_list: List[FeedbackEntry] = []
        self._feedback_by_domain: Dict[str, List[FeedbackEntry]] = {}
        self._stats = {
            "total_feedback": 0,
            "by_type": {},
            "resolved": 0,
            "used_for_training": 0
        }
        self._load()

    def _load(self):
        """Load existing feedback"""
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        entry = FeedbackEntry.from_dict(eval(line))
                        self._feedback_list.append(entry)
                        self._update_stats(entry)
        except Exception:
            pass

    def _save(self, entry: FeedbackEntry):
        """Save feedback entry"""
        try:
            with open(self.storage_path, "a", encoding="utf-8") as f:
                f.write(str(entry.to_dict()) + "\n")
        except Exception:
            pass

    def _update_stats(self, entry: FeedbackEntry):
        """Update statistics"""
        self._stats["total_feedback"] += 1
        self._stats["by_type"][entry.feedback_type] = \
            self._stats["by_type"].get(entry.feedback_type, 0) + 1
        if entry.resolved:
            self._stats["resolved"] += 1
        if entry.used_for_training:
            self._stats["used_for_training"] += 1

    def submit_feedback(
        self,
        url: str,
        domain: str,
        feedback_type: str,
        original_score: int,
        original_decision: str,
        user_label: Optional[str] = None,
        message: Optional[str] = None,
        source: str = "api"
    ) -> FeedbackEntry:
        """
        Submit user feedback.
        
        Args:
            url: Analyzed URL
            domain: Domain name
            feedback_type: Type of feedback
            original_score: Original risk score
            original_decision: Original decision
            user_label: User's correct label (optional)
            message: User message (optional)
            source: Feedback source
            
        Returns:
            Created FeedbackEntry
        """
        entry = FeedbackEntry(
            url=url,
            domain=domain,
            feedback_type=feedback_type,
            original_score=original_score,
            original_decision=original_decision,
            user_label=user_label,
            message=message,
            timestamp=time.time(),
            source=source
        )

        self._feedback_list.append(entry)
        
        if domain not in self._feedback_by_domain:
            self._feedback_by_domain[domain] = []
        self._feedback_by_domain[domain].append(entry)

        self._update_stats(entry)
        self._save(entry)

        return entry

    def get_feedback_for_domain(self, domain: str) -> List[FeedbackEntry]:
        """Get all feedback for a domain"""
        return self._feedback_by_domain.get(domain, [])

    def get_unresolved(self) -> List[FeedbackEntry]:
        """Get unresolved feedback entries"""
        return [f for f in self._feedback_list if not f.resolved]

    def resolve_feedback(self, url: str, used_for_training: bool = True) -> bool:
        """
        Mark feedback as resolved.
        
        Args:
            url: URL of feedback
            used_for_training: Whether to use for training
            
        Returns:
            True if found and resolved
        """
        for entry in self._feedback_list:
            if entry.url == url and not entry.resolved:
                entry.resolved = True
                entry.used_for_training = used_for_training
                self._stats["resolved"] += 1
                if used_for_training:
                    self._stats["used_for_training"] += 1
                return True
        return False

    def get_training_corrections(self) -> List[Dict[str, Any]]:
        """
        Get feedback entries suitable for training corrections.
        
        Returns:
            List of correction dictionaries
        """
        corrections = []
        
        for entry in self._feedback_list:
            if (entry.resolved and entry.used_for_training 
                and entry.user_label):
                corrections.append({
                    "url": entry.url,
                    "domain": entry.domain,
                    "original_label": self._get_original_label(entry),
                    "correct_label": entry.user_label,
                    "confidence": self._calculate_confidence(entry),
                    "timestamp": entry.timestamp
                })
        
        return corrections

    def _get_original_label(self, entry: FeedbackEntry) -> str:
        """Determine original label from decision"""
        if entry.original_decision == "SAFE":
            return "safe"
        elif entry.original_decision == "DANGER":
            return "phishing"
        return "unknown"

    def _calculate_confidence(self, entry: FeedbackEntry) -> float:
        """Calculate confidence in the correction"""
        base = 0.5
        
        if entry.feedback_type == FeedbackType.FALSE_POSITIVE.value:
            base = 0.8
        elif entry.feedback_type == FeedbackType.FALSE_NEGATIVE.value:
            base = 0.7
        elif entry.feedback_type == FeedbackType.CORRECT.value:
            base = 0.9
            
        if entry.message:
            base += 0.1
            
        return min(base, 1.0)

    def get_stats(self) -> Dict[str, Any]:
        """Get feedback statistics"""
        return {
            **self._stats,
            "recent_count": len(self._feedback_list[-100:]),
            "domain_count": len(self._feedback_by_domain)
        }

    def auto_resolve_duplicates(self) -> int:
        """
        Auto-resolve duplicate feedback for same URL.
        
        Returns:
            Number of duplicates resolved
        """
        by_url: Dict[str, List[FeedbackEntry]] = {}
        
        for entry in self._feedback_list:
            if entry.url not in by_url:
                by_url[entry.url] = []
            by_url[entry.url].append(entry)

        resolved = 0
        for url, entries in by_url.items():
            if len(entries) > 1:
                keep = max(entries, key=lambda e: (
                    e.used_for_training,
                    len(e.message or ""),
                    e.timestamp
                ))
                
                for entry in entries:
                    if entry is not keep and not entry.resolved:
                        entry.resolved = True
                        resolved += 1

        return resolved

    def export_corrections(self, filepath: str) -> int:
        """
        Export corrections for model training.
        
        Args:
            filepath: Output file path
            
        Returns:
            Number of corrections exported
        """
        import json
        
        corrections = self.get_training_corrections()
        
        with open(filepath, "w", encoding="utf-8") as f:
            for corr in corrections:
                f.write(json.dumps(corr, ensure_ascii=False) + "\n")
        
        return len(corrections)
