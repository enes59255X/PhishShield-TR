"""
PhishShield TR - Dataset Collector
Sprint 6: Collects and stores analysis history for ML training
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import sqlite3


@dataclass
class AnalysisRecord:
    """Single analysis record for ML training"""
    id: Optional[int]
    url: str
    features: str  # JSON string of features
    final_decision: str  # SAFE, CAUTION, DANGER
    risk_score: int
    confidence: int
    threat_intel_match: bool
    primary_pattern: str
    timestamp: str
    user_feedback: Optional[str] = None
    is_learned: bool = False


class DatasetCollector:
    """
    Collects analysis records for ML training dataset.
    
    Features:
    - Stores all analysis records
    - Supports user feedback for false positive learning
    - Generates training datasets
    - Tracks label distribution
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "database", "ml_history.db")
        
        self.db_path = db_path
        self._ensure_db_dir()
        self._init_db()
    
    def _ensure_db_dir(self):
        """Ensure database directory exists"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    def _init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                features TEXT NOT NULL,
                final_decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                confidence INTEGER NOT NULL,
                threat_intel_match INTEGER DEFAULT 0,
                primary_pattern TEXT DEFAULT '',
                timestamp TEXT NOT NULL,
                user_feedback TEXT,
                is_learned INTEGER DEFAULT 0
            )
        """)
        
        # Indexes
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_decision 
            ON analysis_history(final_decision)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON analysis_history(timestamp)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_learned 
            ON analysis_history(is_learned)
        """)
        
        conn.commit()
        conn.close()
    
    def record(
        self,
        url: str,
        features: Dict[str, Any],
        final_decision: str,
        risk_score: int,
        confidence: int,
        threat_intel_match: bool = False,
        primary_pattern: str = ""
    ) -> int:
        """
        Record an analysis for future ML training.
        
        Args:
            url: Analyzed URL
            features: Feature dict from FeatureExtractor
            final_decision: SAFE, CAUTION, or DANGER
            risk_score: Final risk score (0-100)
            confidence: Confidence level (0-100)
            threat_intel_match: Whether threat intel matched
            primary_pattern: Primary attack pattern if detected
        
        Returns:
            Record ID
        """
        features_json = json.dumps(features, default=str)
        timestamp = datetime.now().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO analysis_history 
            (url, features, final_decision, risk_score, confidence, threat_intel_match, primary_pattern, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (url, features_json, final_decision, risk_score, confidence, 
              int(threat_intel_match), primary_pattern, timestamp))
        
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return record_id
    
    def add_feedback(self, record_id: int, feedback: str):
        """
        Add user feedback to a record.
        
        Args:
            record_id: ID of the record
            feedback: User feedback (CORRECT, FALSE_POSITIVE, FALSE_NEGATIVE)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE analysis_history 
            SET user_feedback = ?, is_learned = 1
            WHERE id = ?
        """, (feedback, record_id))
        
        conn.commit()
        conn.close()
    
    def get_training_data(
        self,
        min_samples: int = 100,
        include_feedback_only: bool = False
    ) -> List[Dict]:
        """
        Get labeled data for ML training.
        
        Args:
            min_samples: Minimum samples per class
            include_feedback_only: Only use records with user feedback
        
        Returns:
            List of labeled records
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if include_feedback_only:
            cursor.execute("""
                SELECT * FROM analysis_history 
                WHERE user_feedback IS NOT NULL
                ORDER BY timestamp DESC
            """)
        else:
            # Get all records with decisions
            cursor.execute("""
                SELECT * FROM analysis_history 
                WHERE final_decision IN ('SAFE', 'DANGER')
                ORDER BY timestamp DESC
            """)
        
        rows = cursor.fetchall()
        conn.close()
        
        records = []
        for row in rows:
            record = {
                "id": row["id"],
                "url": row["url"],
                "features": json.loads(row["features"]),
                "label": 1 if row["final_decision"] == "DANGER" else 0,
                "decision": row["final_decision"],
                "risk_score": row["risk_score"],
                "user_feedback": row["user_feedback"]
            }
            records.append(record)
        
        return records
    
    def get_stats(self) -> Dict:
        """Get dataset statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total count
        cursor.execute("SELECT COUNT(*) as count FROM analysis_history")
        total = cursor.fetchone()[0]
        
        # By decision
        cursor.execute("""
            SELECT final_decision, COUNT(*) as count 
            FROM analysis_history 
            GROUP BY final_decision
        """)
        by_decision = {row[0]: row[1] for row in cursor.fetchall()}
        
        # With feedback
        cursor.execute("""
            SELECT COUNT(*) as count FROM analysis_history 
            WHERE user_feedback IS NOT NULL
        """)
        with_feedback = cursor.fetchone()[0]
        
        # Learned (used for training)
        cursor.execute("""
            SELECT COUNT(*) as count FROM analysis_history 
            WHERE is_learned = 1
        """)
        learned = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_records": total,
            "by_decision": by_decision,
            "with_feedback": with_feedback,
            "learned": learned
        }
    
    def export_training_dataset(self, filepath: str, format: str = "json"):
        """
        Export training dataset to file.
        
        Args:
            filepath: Output file path
            format: Output format (json, csv)
        """
        records = self.get_training_data()
        
        if format == "json":
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2, default=str)
        elif format == "csv":
            import csv
            if not records:
                return
            
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                # Get all feature keys
                feature_keys = set()
                for r in records:
                    feature_keys.update(r["features"].keys())
                
                fieldnames = ["id", "url", "label", "decision", "risk_score"] + sorted(feature_keys)
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for record in records:
                    row = {
                        "id": record["id"],
                        "url": record["url"],
                        "label": record["label"],
                        "decision": record["decision"],
                        "risk_score": record["risk_score"]
                    }
                    row.update(record["features"])
                    writer.writerow(row)
        
        return len(records)


# Singleton instance
dataset_collector = DatasetCollector()
