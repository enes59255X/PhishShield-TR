"""
Learning System - Dataset Manager
PhishShield TR V3

Manages datasets for ML training.
"""

import json
import time
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
import random


@dataclass
class DatasetEntry:
    """Single entry in the dataset"""
    url: str
    domain: str
    features: Dict[str, Any]
    label: int
    label_name: str
    source: str
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DatasetEntry":
        return cls(**data)


class DatasetManager:
    """
    Manages ML training datasets.
    
    Responsibilities:
    - Store labeled samples
    - Balance datasets
    - Split train/test
    - Export for training
    """

    LABEL_MAP = {
        "safe": 0,
        "phishing": 1,
        "false_positive": 0,
        "false_negative": 1,
        "reviewed": -1,
        "unknown": -1
    }

    REVERSE_LABEL_MAP = {v: k for k, v in LABEL_MAP.items() if v != -1}

    def __init__(self, dataset_path: str = "data/dataset.jsonl"):
        self.dataset_path = Path(dataset_path)
        self.dataset_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._entries: List[DatasetEntry] = []
        self._load()

    def _load(self):
        """Load existing dataset"""
        if self.dataset_path.exists():
            try:
                with open(self.dataset_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            entry = DatasetEntry.from_dict(json.loads(line))
                            self._entries.append(entry)
            except Exception:
                pass

    def _save(self):
        """Save dataset to file"""
        try:
            with open(self.dataset_path, "w", encoding="utf-8") as f:
                for entry in self._entries:
                    f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        except Exception:
            pass

    def add_entry(
        self,
        url: str,
        domain: str,
        features: Dict[str, Any],
        label: str,
        source: str = "auto"
    ) -> DatasetEntry:
        """
        Add a new entry to the dataset.
        
        Args:
            url: URL address
            domain: Domain name
            features: Feature dictionary
            label: Label name (safe/phishing/etc)
            source: Data source
            
        Returns:
            Created DatasetEntry
        """
        numeric_label = self.LABEL_MAP.get(label, -1)
        
        entry = DatasetEntry(
            url=url,
            domain=domain,
            features=features,
            label=numeric_label,
            label_name=label,
            source=source,
            timestamp=time.time()
        )

        self._entries.append(entry)
        self._save()

        return entry

    def get_entries(
        self,
        label: Optional[str] = None,
        limit: int = 10000
    ) -> List[DatasetEntry]:
        """Get dataset entries with optional filtering"""
        entries = self._entries

        if label:
            numeric = self.LABEL_MAP.get(label)
            if numeric is not None:
                entries = [e for e in entries if e.label == numeric]

        return entries[:limit]

    def get_balanced_split(
        self,
        test_ratio: float = 0.2,
        min_samples: int = 50
    ) -> Tuple[List[DatasetEntry], List[DatasetEntry]]:
        """
        Get balanced train/test split.
        
        Args:
            test_ratio: Ratio of test set (0.0-1.0)
            min_samples: Minimum samples per class
            
        Returns:
            Tuple of (train_entries, test_entries)
        """
        by_label: Dict[int, List[DatasetEntry]] = {}
        
        for entry in self._entries:
            if entry.label not in by_label:
                by_label[entry.label] = []
            by_label[entry.label].append(entry)

        valid_labels = [l for l, entries in by_label.items() 
                       if len(entries) >= min_samples]

        if len(valid_labels) < 2:
            return self._entries[:], []

        train_entries = []
        test_entries = []

        for label in valid_labels:
            entries = by_label[label]
            random.shuffle(entries)
            
            split_idx = int(len(entries) * (1 - test_ratio))
            train_entries.extend(entries[:split_idx])
            test_entries.extend(entries[split_idx:])

        return train_entries, test_entries

    def get_feature_matrix(self) -> Tuple[List[Dict[str, Any]], List[int]]:
        """
        Get features and labels as lists for training.
        
        Returns:
            Tuple of (features_list, labels_list)
        """
        valid_entries = [e for e in self._entries if e.label >= 0]
        
        features = [e.features for e in valid_entries]
        labels = [e.label for e in valid_entries]
        
        return features, labels

    def get_stats(self) -> Dict[str, Any]:
        """Get dataset statistics"""
        total = len(self._entries)
        by_label: Dict[str, int] = {}
        
        for entry in self._entries:
            name = entry.label_name
            by_label[name] = by_label.get(name, 0) + 1

        return {
            "total_entries": total,
            "by_label": by_label,
            "valid_labels": {k: v for k, v in by_label.items() if v > 0}
        }

    def remove_duplicates(self) -> int:
        """Remove duplicate URLs, keeping most recent"""
        seen: Dict[str, int] = {}
        to_remove: List[int] = []

        for i, entry in enumerate(self._entries):
            if entry.url in seen:
                if entry.timestamp > self._entries[seen[entry.url]].timestamp:
                    to_remove.append(seen[entry.url])
                    seen[entry.url] = i
                else:
                    to_remove.append(i)
            else:
                seen[entry.url] = i

        self._entries = [e for i, e in enumerate(self._entries) if i not in to_remove]
        self._save()

        return len(to_remove)

    def filter_low_quality(self, min_features: int = 10) -> int:
        """
        Remove entries with insufficient features.
        
        Args:
            min_features: Minimum number of features
            
        Returns:
            Number of entries removed
        """
        before = len(self._entries)
        self._entries = [
            e for e in self._entries 
            if e.label >= 0 and len(e.features) >= min_features
        ]
        self._save()
        
        return before - len(self._entries)

    def export_for_training(self, filepath: str) -> int:
        """
        Export dataset in training format.
        
        Args:
            filepath: Output file path
            
        Returns:
            Number of entries exported
        """
        train_entries, test_entries = self.get_balanced_split()

        export_data = {
            "train": [e.to_dict() for e in train_entries],
            "test": [e.to_dict() for e in test_entries],
            "metadata": {
                "train_size": len(train_entries),
                "test_size": len(test_entries),
                "exported_at": time.time()
            }
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        return len(train_entries) + len(test_entries)
