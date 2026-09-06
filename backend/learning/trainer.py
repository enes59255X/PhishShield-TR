"""
Learning System - Model Trainer
PhishShield TR V3

Trains and updates ML models based on collected data.
"""

import os
import pickle
import time
import random
import json
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


@dataclass
class TrainingConfig:
    """Configuration for model training"""
    model_type: str = "random_forest"
    n_estimators: int = 100
    max_depth: Optional[int] = None
    min_samples_split: int = 2
    test_ratio: float = 0.2
    random_state: int = 42
    class_weight: Optional[str] = "balanced"


@dataclass
class TrainingResult:
    """Result of a training run"""
    success: bool
    model_path: str
    train_accuracy: float
    test_accuracy: float
    samples_used: int
    training_time: float
    feature_count: int
    label_distribution: Dict[str, int]
    message: str


class ModelTrainer:
    """
    Trains ML models for phishing detection.
    
    Features:
    - Trains Random Forest models
    - Validates on test set
    - Tracks model history
    - Feature importance analysis
    """

    def __init__(self, model_dir: str = "ml/models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.model_path = self.model_dir / "phishing_rf.pkl"
        self.history_path = self.model_dir / "training_history.json"
        
        self._current_model = None
        self._feature_names: List[str] = []
        self._load_model()

    def _load_model(self):
        """Load existing model if available"""
        if self.model_path.exists():
            try:
                with open(self.model_path, "rb") as f:
                    data = pickle.load(f)
                    self._current_model = data.get("model")
                    self._feature_names = data.get("feature_names", [])
            except Exception:
                pass

    def _save_model(self, model, feature_names: List[str]):
        """Save trained model"""
        data = {
            "model": model,
            "feature_names": feature_names,
            "trained_at": time.time(),
            "version": self._get_version()
        }
        
        with open(self.model_path, "wb") as f:
            pickle.dump(data, f)

    def _get_version(self) -> str:
        """Get model version from history"""
        history = self._load_history()
        return f"v{len(history) + 1}"

    def _load_history(self) -> List[Dict[str, Any]]:
        """Load training history"""
        if self.history_path.exists():
            try:
                with open(self.history_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_history(self, history: List[Dict[str, Any]]):
        """Save training history"""
        with open(self.history_path, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, indent=2)

    def _extract_features(self, samples: List[Dict[str, Any]]) -> Tuple[List[List], List[str]]:
        """
        Extract feature vectors from samples.
        
        Args:
            samples: List of feature dictionaries
            
        Returns:
            Tuple of (feature_matrix, feature_names)
        """
        if not samples:
            return [], []

        all_features = set()
        for sample in samples:
            if isinstance(sample, dict) and "features" in sample:
                all_features.update(sample["features"].keys())
            elif isinstance(sample, dict):
                all_features.update(sample.keys())

        feature_names = sorted(list(all_features))
        feature_matrix = []

        for sample in samples:
            if isinstance(sample, dict) and "features" in sample:
                features = sample["features"]
            else:
                features = sample
                
            vector = []
            for name in feature_names:
                value = features.get(name, 0)
                if isinstance(value, bool):
                    value = 1 if value else 0
                elif isinstance(value, str):
                    value = hash(value) % 1000
                vector.append(float(value))
            feature_matrix.append(vector)

        return feature_matrix, feature_names

    def train(
        self,
        samples: List[Dict[str, Any]],
        labels: List[int],
        config: Optional[TrainingConfig] = None
    ) -> TrainingResult:
        """
        Train a new model.
        
        Args:
            samples: List of feature dictionaries
            labels: List of labels (0=safe, 1=phishing)
            config: Training configuration
            
        Returns:
            TrainingResult with metrics
        """
        if not HAS_SKLEARN:
            return TrainingResult(
                success=False,
                model_path=str(self.model_path),
                train_accuracy=0.0,
                test_accuracy=0.0,
                samples_used=0,
                training_time=0.0,
                feature_count=0,
                label_distribution={},
                message="scikit-learn not installed"
            )

        if not samples:
            return TrainingResult(
                success=False,
                model_path=str(self.model_path),
                train_accuracy=0.0,
                test_accuracy=0.0,
                samples_used=0,
                training_time=0.0,
                feature_count=0,
                label_distribution={},
                message="No samples provided"
            )

        if config is None:
            config = TrainingConfig()

        start_time = time.time()

        X, feature_names = self._extract_features(samples)
        y = labels

        if len(X) < 10:
            return TrainingResult(
                success=False,
                model_path=str(self.model_path),
                train_accuracy=0.0,
                test_accuracy=0.0,
                samples_used=len(X),
                training_time=time.time() - start_time,
                feature_count=len(feature_names),
                label_distribution={},
                message="Insufficient samples for training"
            )

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=config.test_ratio, random_state=config.random_state
        )

        model = RandomForestClassifier(
            n_estimators=config.n_estimators,
            max_depth=config.max_depth,
            min_samples_split=config.min_samples_split,
            class_weight=config.class_weight,
            random_state=config.random_state
        )

        model.fit(X_train, y_train)

        train_pred = model.predict(X_train)
        test_pred = model.predict(X_test)

        train_acc = accuracy_score(y_train, train_pred)
        test_acc = accuracy_score(y_test, test_pred)

        self._current_model = model
        self._feature_names = feature_names
        self._save_model(model, feature_names)

        label_dist = {
            "safe": sum(1 for l in y if l == 0),
            "phishing": sum(1 for l in y if l == 1)
        }

        history = self._load_history()
        history.append({
            "version": self._get_version(),
            "timestamp": time.time(),
            "samples_used": len(samples),
            "train_accuracy": train_acc,
            "test_accuracy": test_acc,
            "feature_count": len(feature_names),
            "config": {
                "n_estimators": config.n_estimators,
                "max_depth": config.max_depth
            }
        })
        self._save_history(history)

        return TrainingResult(
            success=True,
            model_path=str(self.model_path),
            train_accuracy=train_acc,
            test_accuracy=test_acc,
            samples_used=len(samples),
            training_time=time.time() - start_time,
            feature_count=len(feature_names),
            label_distribution=label_dist,
            message="Training completed successfully"
        )

    def get_feature_importance(self, top_n: int = 10) -> List[Tuple[str, float]]:
        """
        Get feature importance rankings.
        
        Args:
            top_n: Number of top features to return
            
        Returns:
            List of (feature_name, importance) tuples
        """
        if self._current_model is None:
            return []

        importances = self._current_model.feature_importances_
        
        paired = list(zip(self._feature_names, importances))
        paired.sort(key=lambda x: x[1], reverse=True)
        
        return paired[:top_n]

    def predict(self, features: Dict[str, Any]) -> Tuple[int, float]:
        """
        Predict using current model.
        
        Args:
            features: Feature dictionary
            
        Returns:
            Tuple of (prediction, probability)
        """
        if self._current_model is None:
            return 0, 0.5

        vector = []
        for name in self._feature_names:
            value = features.get(name, 0)
            if isinstance(value, bool):
                value = 1 if value else 0
            elif isinstance(value, str):
                value = hash(value) % 1000
            vector.append(float(value))

        pred = self._current_model.predict([vector])[0]
        prob = self._current_model.predict_proba([vector])[0]
        
        return int(pred), float(max(prob))

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about current model"""
        if self._current_model is None:
            return {"loaded": False, "message": "No model loaded"}

        history = self._load_history()
        last_training = history[-1] if history else None

        return {
            "loaded": True,
            "version": self._get_version(),
            "feature_count": len(self._feature_names),
            "n_estimators": self._current_model.n_estimators,
            "last_training": last_training
        }

    def retrain_on_feedback(
        self,
        feedback_corrections: List[Dict[str, Any]],
        config: Optional[TrainingConfig] = None
    ) -> TrainingResult:
        """
        Retrain model on feedback corrections.
        
        Args:
            feedback_corrections: List of correction dicts from FeedbackHandler
            config: Training configuration
            
        Returns:
            TrainingResult
        """
        if not feedback_corrections:
            return TrainingResult(
                success=False,
                model_path=str(self.model_path),
                train_accuracy=0.0,
                test_accuracy=0.0,
                samples_used=0,
                training_time=0.0,
                feature_count=0,
                label_distribution={},
                message="No feedback corrections provided"
            )

        samples = []
        labels = []
        
        for corr in feedback_corrections:
            if "features" in corr and "label" in corr:
                samples.append(corr["features"])
                labels.append(1 if corr["label"] == "phishing" else 0)

        return self.train(samples, labels, config)
