"""
Learning System - Data Collector
PhishShield TR V3

Collects analysis results for model improvement.
"""

import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


class SampleLabel(Enum):
    """Sample labeling types"""
    SAFE = "safe"
    PHISHING = "phishing"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    REVIEWED = "reviewed"
    UNKNOWN = "unknown"


@dataclass
class LearningSample:
    """A single learning sample"""
    url: str
    domain: str
    label: str
    features: Dict[str, Any]
    risk_score: int
    ml_probability: float
    final_decision: str
    timestamp: float
    source: str
    feedback_source: Optional[str] = None
    reviewed: bool = False
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LearningSample":
        return cls(**data)


class LearningCollector:
    """
    Collects samples from analysis for later training.
    
    Collects:
    - All analyzed URLs
    - Final decisions
    - Feature vectors
    - User feedback
    """

    def __init__(self, storage_path: str = "data/learning_samples.jsonl"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._samples: List[LearningSample] = []
        self._stats = {
            "total_collected": 0,
            "by_label": {label.value: 0 for label in SampleLabel},
            "by_source": {},
        }
        self._load_existing()

    def _load_existing(self):
        """Load existing samples from storage"""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            sample = LearningSample.from_dict(json.loads(line))
                            self._samples.append(sample)
                            self._update_stats(sample)
            except Exception:
                pass

    def _save_sample(self, sample: LearningSample):
        """Save a single sample to storage"""
        try:
            with open(self.storage_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(sample.to_dict(), ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _update_stats(self, sample: LearningSample):
        """Update statistics"""
        self._stats["total_collected"] += 1
        self._stats["by_label"][sample.label] = self._stats["by_label"].get(sample.label, 0) + 1
        
        source = sample.source or "unknown"
        self._stats["by_source"][source] = self._stats["by_source"].get(source, 0) + 1

    def collect(
        self,
        url: str,
        domain: str,
        features: Dict[str, Any],
        risk_score: int,
        ml_probability: float,
        final_decision: str,
        source: str = "auto"
    ) -> LearningSample:
        """
        Collect a sample from analysis.
        
        Args:
            url: Analyzed URL
            domain: Extracted domain
            features: Feature dictionary
            risk_score: Final risk score (0-100)
            ml_probability: ML model probability
            final_decision: Final decision (SAFE/DANGER/REVIEW)
            source: Collection source
            
        Returns:
            Created LearningSample
        """
        if risk_score >= 70:
            label = SampleLabel.PHISHING.value
        elif risk_score <= 30:
            label = SampleLabel.SAFE.value
        else:
            label = SampleLabel.UNKNOWN.value

        sample = LearningSample(
            url=url,
            domain=domain,
            label=label,
            features=features,
            risk_score=risk_score,
            ml_probability=ml_probability,
            final_decision=final_decision,
            timestamp=time.time(),
            source=source
        )

        self._samples.append(sample)
        self._update_stats(sample)
        self._save_sample(sample)

        return sample

    def collect_feedback(
        self,
        url: str,
        domain: str,
        features: Dict[str, Any],
        risk_score: int,
        ml_probability: float,
        final_decision: str,
        correct_label: str,
        feedback_source: str = "user",
        notes: Optional[str] = None
    ) -> LearningSample:
        """
        Collect a user feedback sample.
        
        Args:
            url: Analyzed URL
            domain: Extracted domain
            features: Feature dictionary
            risk_score: Original risk score
            ml_probability: ML probability
            final_decision: Original decision
            correct_label: Correct label from user
            feedback_source: Source of feedback
            notes: Optional notes
            
        Returns:
            Created LearningSample
        """
        sample = LearningSample(
            url=url,
            domain=domain,
            label=correct_label,
            features=features,
            risk_score=risk_score,
            ml_probability=ml_probability,
            final_decision=final_decision,
            timestamp=time.time(),
            source="feedback",
            feedback_source=feedback_source,
            reviewed=True,
            notes=notes
        )

        self._samples.append(sample)
        self._update_stats(sample)
        self._save_sample(sample)

        return sample

    def get_samples(
        self,
        label: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 1000
    ) -> List[LearningSample]:
        """
        Get collected samples with optional filtering.
        
        Args:
            label: Filter by label
            source: Filter by source
            limit: Maximum samples to return
            
        Returns:
            List of LearningSample
        """
        samples = self._samples

        if label:
            samples = [s for s in samples if s.label == label]
        if source:
            samples = [s for s in samples if s.source == source]

        return samples[-limit:]

    def get_training_data(
        self,
        min_samples: int = 100,
        balanced: bool = True
    ) -> List[LearningSample]:
        """
        Get samples suitable for training.
        
        Args:
            min_samples: Minimum samples per label
            balanced: Balance sample counts across labels
            
        Returns:
            List of training samples
        """
        samples_by_label: Dict[str, List[LearningSample]] = {}
        
        for sample in self._samples:
            if sample.label not in samples_by_label:
                samples_by_label[sample.label] = []
            samples_by_label[sample.label].append(sample)

        if balanced:
            min_count = min(
                len(samples) for samples in samples_by_label.values()
            )
            if min_count >= min_samples:
                return [
                    s for samples in samples_by_label.values()
                    for s in samples[:min_count]
                ]

        return self._samples

    def get_stats(self) -> Dict[str, Any]:
        """Get collection statistics"""
        return {
            **self._stats,
            "samples_loaded": len(self._samples)
        }

    def export_dataset(self, filepath: str) -> int:
        """
        Export samples to a dataset file.
        
        Args:
            filepath: Output file path
            
        Returns:
            Number of samples exported
        """
        samples = self.get_training_data(balanced=False)
        
        with open(filepath, "w", encoding="utf-8") as f:
            for sample in samples:
                f.write(json.dumps(sample.to_dict(), ensure_ascii=False) + "\n")
        
        return len(samples)

    def clear_old_samples(self, days: int = 30) -> int:
        """
        Clear samples older than specified days.
        
        Args:
            days: Age threshold in days
            
        Returns:
            Number of samples cleared
        """
        cutoff = time.time() - (days * 86400)
        old_samples = [s for s in self._samples if s.timestamp < cutoff]
        
        self._samples = [s for s in self._samples if s.timestamp >= cutoff]
        
        return len(old_samples)
