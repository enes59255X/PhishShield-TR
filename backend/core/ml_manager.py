import lightgbm as lgb
import os
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
import asyncio

MODEL_PATH = Path(__file__).parent.parent / "models" / "phish_model.pkl"

class MLManager:
    def __init__(self):
        self.model = None
        self.feature_names = [
            "url_length", "entropy", "subdomain_count", 
            "suspicious_keywords", "has_login_form", 
            "password_input", "external_form", "iframe_usage"
        ]
        self._load_model()

    def _load_model(self):
        if MODEL_PATH.exists():
            try:
                with open(MODEL_PATH, 'rb') as f:
                    self.model = pickle.load(f)
            except Exception as e:
                print(f"Error loading model: {e}")
                self.model = None
        else:
            print("No model found. Running in heuristic mode until first training.")

    async def predict_async(self, features: dict) -> float:
        """
        Predicts phishing probability (0.0 to 1.0).
        """
        if self.model is None:
            # Fallback to a very simple internal scoring if model not ready
            return self._heuristic_fallback(features)
        
        try:
            # Reorder features to match training schema
            input_data = [features.get(name, 0) for name in self.feature_names]
            prediction = self.model.predict([input_data])[0]
            return float(prediction)
        except Exception as e:
            print(f"Prediction error: {e}")
            return self._heuristic_fallback(features)

    def _heuristic_fallback(self, features: dict) -> float:
        score = 0
        if features.get("password_input"): score += 0.4
        if features.get("external_form"): score += 0.3
        if features.get("suspicious_keywords", 0) > 0: score += 0.2
        return min(0.9, score)

    async def train_self_learning(self, training_data: list):
        """
        training_data: List of dicts, each containing features and a label (1=phishing, 0=safe)
        """
        if not training_data or len(training_data) < 10:
            return False

        try:
            df = pd.DataFrame(training_data)
            X = df[self.feature_names]
            y = df['label']

            # Basic LightGBM regressor for probability estimation
            model = lgb.LGBMRegressor(
                n_estimators=100,
                learning_rate=0.05,
                num_leaves=31,
                random_state=42,
                verbose=-1
            )
            
            # Run training in thread pool to not block async loop
            await asyncio.to_thread(model.fit, X, y)
            
            self.model = model
            
            # Save model
            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(MODEL_PATH, 'wb') as f:
                pickle.dump(model, f)
            
            return True
        except Exception as e:
            print(f"Training error: {e}")
            return False

# Global instance
ml_manager = MLManager()
