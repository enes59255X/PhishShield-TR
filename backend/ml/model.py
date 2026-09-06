"""
PhishShield TR - ML Model
Sprint 6: RandomForest-based phishing detection model
"""

import os
import json
import pickle
from typing import Dict, List, Optional, Tuple
from datetime import datetime

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class PhishingMLModel:
    """
    ML model for phishing probability prediction.
    
    Uses RandomForest for:
    - Fast inference
    - Feature importance
    - Robust to overfitting
    - Works with small datasets
    """
    
    MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "database", "models")
    MODEL_FILE = os.path.join(MODEL_DIR, "phishing_model.pkl")
    FEATURE_ORDER_FILE = os.path.join(MODEL_DIR, "feature_order.json")
    
    def __init__(self):
        self.model = None
        self.feature_names = None
        self.is_trained = False
        self.model_type = "random_forest"
        self._ensure_model_dir()
        self._load_model()
    
    def _ensure_model_dir(self):
        """Ensure model directory exists"""
        if not os.path.exists(self.MODEL_DIR):
            os.makedirs(self.MODEL_DIR, exist_ok=True)
    
    def _load_model(self):
        """Load existing model if available"""
        if os.path.exists(self.MODEL_FILE) and os.path.exists(self.FEATURE_ORDER_FILE):
            try:
                with open(self.MODEL_FILE, "rb") as f:
                    self.model = pickle.load(f)
                with open(self.FEATURE_ORDER_FILE, "r") as f:
                    self.feature_names = json.load(f)
                self.is_trained = True
            except Exception as e:
                print(f"Warning: Could not load model: {e}")
                self.model = None
                self.is_trained = False
    
    def _save_model(self):
        """Save model to disk"""
        if self.model is None:
            return
        
        with open(self.MODEL_FILE, "wb") as f:
            pickle.dump(self.model, f)
        
        if self.feature_names:
            with open(self.FEATURE_ORDER_FILE, "w") as f:
                json.dump(self.feature_names, f)
    
    def train(
        self,
        X: List[List[float]],
        y: List[int],
        feature_names: List[str],
        test_size: float = 0.2
    ) -> Dict:
        """
        Train the ML model.
        
        Args:
            X: Feature vectors
            y: Labels (1 = phishing, 0 = safe)
            feature_names: List of feature names in order
            test_size: Fraction for test split
        
        Returns:
            Training metrics dict
        """
        if not HAS_SKLEARN:
            return {
                "error": "scikit-learn not installed",
                "status": "skipped"
            }
        
        if len(X) < 10:
            return {
                "error": "Not enough training samples",
                "min_samples": 10,
                "current_samples": len(X)
            }
        
        # Save feature order
        self.feature_names = feature_names
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Train RandomForest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced"  # Handle imbalanced classes
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        
        metrics = {
            "status": "trained",
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, zero_division=0),
            "recall": recall_score(y_test, y_pred, zero_division=0),
            "f1": f1_score(y_test, y_pred, zero_division=0)
        }
        
        # Cross-validation
        if len(X) >= 20:
            cv_scores = cross_val_score(self.model, X, y, cv=5, scoring="f1")
            metrics["cv_f1_mean"] = float(cv_scores.mean())
            metrics["cv_f1_std"] = float(cv_scores.std())
        
        # Feature importance
        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
            feature_importance = sorted(
                zip(feature_names, importances),
                key=lambda x: x[1],
                reverse=True
            )[:10]  # Top 10
            metrics["top_features"] = [
                {"name": name, "importance": float(imp)}
                for name, imp in feature_importance
            ]
        
        self.is_trained = True
        self._save_model()
        
        return metrics
    
    def predict(self, X: List[List[float]]) -> List[float]:
        """
        Predict phishing probability.
        
        Args:
            X: Feature vectors (list of lists)
        
        Returns:
            List of probabilities (0.0 - 1.0)
        """
        if not self.is_trained or self.model is None:
            # Return default (0.5) if no model
            return [0.5] * len(X)
        
        try:
            # Ensure X is 2D
            if not isinstance(X[0], list):
                X = [[x] for x in X]
            
            # Predict probabilities
            proba = self.model.predict_proba(X)
            
            # Return probability of phishing (class 1)
            return [p[1] for p in proba]
        except Exception as e:
            print(f"Prediction error: {e}")
            return [0.5] * len(X)
    
    def predict_single(self, features: List[float]) -> Tuple[float, str]:
        """
        Predict for a single sample.
        
        Args:
            features: Feature vector
        
        Returns:
            Tuple of (phishing_probability, risk_level)
        """
        proba = self.predict([features])[0]
        
        # Determine risk level
        if proba >= 0.8:
            risk = "CRITICAL"
        elif proba >= 0.6:
            risk = "HIGH"
        elif proba >= 0.4:
            risk = "MEDIUM"
        else:
            risk = "LOW"
        
        return proba, risk
    
    def get_feature_importance(self) -> List[Dict]:
        """Get feature importance scores"""
        if not self.is_trained or self.model is None:
            return []
        
        if not hasattr(self.model, "feature_importances_"):
            return []
        
        importances = self.model.feature_importances_
        return [
            {"name": name, "importance": float(imp)}
            for name, imp in sorted(
                zip(self.feature_names, importances),
                key=lambda x: x[1],
                reverse=True
            )
        ]
    
    def is_ready(self) -> bool:
        """Check if model is ready for prediction"""
        return self.is_trained and self.model is not None


# Singleton instance
phishing_model = PhishingMLModel()
