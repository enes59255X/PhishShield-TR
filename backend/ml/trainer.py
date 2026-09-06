"""
PhishShield TR - ML Trainer
Sprint 10: RandomForest model training for phishing detection

Purpose:
- Train RandomForest classifier on phishing/safe features
- Generate synthetic training data based on real patterns
- Export trained model for production use
"""

import os
import pickle
import numpy as np
from typing import List, Tuple, Optional
from dataclasses import dataclass

from ml.feature_schema import FeatureSchema, FeatureVector


@dataclass
class TrainingData:
    """Container for training data"""
    X: np.ndarray  # Feature vectors
    y: np.ndarray  # Labels (0=safe, 1=phishing)


class ModelTrainer:
    """
    Trains RandomForest model for phishing detection.

    Uses synthetic training data based on real phishing patterns.
    """

    def __init__(self, model_path: str = None):
        """
        Initialize trainer.

        Args:
            model_path: Path to save/load trained model
        """
        if model_path is None:
            model_path = os.path.join(
                os.path.dirname(__file__),
                "models",
                "phishing_rf.pkl"
            )
        self.model_path = model_path
        self.model = None
        self._ensure_model_dir()

    def _ensure_model_dir(self):
        """Ensure model directory exists"""
        model_dir = os.path.dirname(self.model_path)
        if model_dir and not os.path.exists(model_dir):
            os.makedirs(model_dir, exist_ok=True)

    def generate_training_data(self, n_samples: int = 5000) -> TrainingData:
        """
        Generate synthetic training data.

        Creates realistic phishing and safe samples based on
        observed patterns in real phishing attacks.

        Args:
            n_samples: Number of samples to generate

        Returns:
            TrainingData with features and labels
        """
        n_phishing = n_samples // 2
        n_safe = n_samples - n_phishing

        # Generate phishing samples
        phishing_features = self._generate_phishing_samples(n_phishing)

        # Generate safe samples
        safe_features = self._generate_safe_samples(n_safe)

        # Combine
        X = np.vstack([safe_features, phishing_features])
        y = np.array([0] * n_safe + [1] * n_phishing)

        return TrainingData(X=X, y=y)

    def _generate_phishing_samples(self, n: int) -> np.ndarray:
        """Generate synthetic phishing samples"""
        samples = []

        for _ in range(n):
            features = np.zeros(FeatureSchema.FEATURE_COUNT)

            # Domain features (phishing typically has suspicious TLDs, new domains)
            features[0] = np.random.randint(1, 90)  # domain_age_days (new)
            features[1] = np.random.randint(15, 40)   # domain_length
            features[2] = np.random.randint(0, 4)    # subdomain_count
            features[3] = np.random.randint(2, 6)    # hyphen_count (suspicious)
            features[4] = np.random.randint(0, 5)    # number_count
            features[5] = 0.9 if np.random.random() > 0.2 else 0.0  # suspicious_tld
            features[6] = 0.0  # is_ip_based
            features[7] = 0.8 if np.random.random() > 0.2 else 0.0  # is_new_domain

            # Threat features
            features[8] = 0.7 if np.random.random() > 0.3 else 0.0  # threat_matched
            features[9] = np.random.uniform(0.7, 0.99)  # threat_confidence
            features[10] = 0.2 if np.random.random() > 0.2 else 0.0  # usom_match
            features[11] = 0.6 if np.random.random() > 0.4 else 0.0  # openphish_match
            features[12] = 0.2 if np.random.random() > 0.8 else 0.0  # urlhaus_match

            # Brand features (often impersonates banks)
            features[13] = 0.8 if np.random.random() > 0.2 else 0.0  # brand_matched
            features[14] = np.random.uniform(0.7, 0.95)  # brand_similarity
            features[15] = 0.7 if np.random.random() > 0.3 else 0.0  # is_banking_brand
            features[16] = 0.1 if np.random.random() > 0.9 else 0.0  # is_gov_brand
            features[17] = 0.2 if np.random.random() > 0.8 else 0.0  # is_payment_brand

            # Form features (credential harvesting)
            features[18] = 0.85 if np.random.random() > 0.15 else 0.0  # has_login_form
            features[19] = 0.9 if np.random.random() > 0.1 else 0.0   # has_password_field
            features[20] = 0.7 if np.random.random() > 0.3 else 0.0  # has_credential_fields
            features[21] = 0.15 if np.random.random() > 0.85 else 0.0  # has_payment_fields
            features[22] = 0.75 if np.random.random() > 0.25 else 0.0  # has_external_submit
            features[23] = float(np.random.randint(0, 3))  # hidden_field_count
            features[24] = 0.6 if np.random.random() > 0.4 else 0.0  # autocomplete_disabled
            features[25] = float(np.random.randint(1, 4))  # form_count

            # Content features
            features[26] = 0.6 if np.random.random() > 0.4 else 0.0  # has_urgency
            features[27] = 0.3 if np.random.random() > 0.7 else 0.0  # has_sms_style
            features[28] = float(np.random.randint(0, 6))   # bank_word_count
            features[29] = float(np.random.randint(0, 3))  # cargo_word_count
            features[30] = float(np.random.randint(0, 4))  # reward_word_count
            features[31] = 0.2 if np.random.random() > 0.8 else 0.0  # has_obfuscation
            features[32] = float(np.random.randint(0, 3))  # phone_count
            features[33] = 0.4 if np.random.random() > 0.6 else 0.0  # has_english_text
            features[34] = float(np.random.randint(0, 5))  # external_script_count

            # Behavior features
            features[35] = float(np.random.randint(0, 3))  # redirect_count
            features[36] = 0.2 if np.random.random() > 0.8 else 0.0  # has_meta_refresh
            features[37] = 0.4 if np.random.random() > 0.6 else 0.0  # right_click_disabled
            features[38] = 0.3 if np.random.random() > 0.7 else 0.0  # text_copy_disabled
            features[39] = float(np.random.randint(0, 2))  # popup_count

            # SSL features (often poor on phishing sites)
            features[40] = 0.7 if np.random.random() > 0.3 else 0.0  # has_ssl
            features[41] = 0.3 if np.random.random() > 0.7 else 0.0  # ssl_valid
            features[42] = 0.5 if np.random.random() > 0.5 else 0.0  # ssl_self_signed
            features[43] = 0.3 if np.random.random() > 0.7 else 0.0  # ssl_expires_soon
            features[44] = 0.2 if np.random.random() > 0.8 else 0.0  # ssl_issuer_trusted

            # Meta features
            features[45] = float(np.random.randint(3, 10))  # signal_count
            features[46] = float(np.random.randint(0, 4))   # rule_count
            features[47] = 0.0  # trust_level (phishing never trusted)

            samples.append(features)

        return np.array(samples, dtype=np.float32)

    def _generate_safe_samples(self, n: int) -> np.ndarray:
        """Generate synthetic safe samples"""
        samples = []

        for _ in range(n):
            features = np.zeros(FeatureSchema.FEATURE_COUNT)

            # Domain features (safe domains are older, legitimate TLDs)
            features[0] = np.random.randint(180, 3650)  # domain_age_days (old)
            features[1] = np.random.randint(8, 25)      # domain_length
            features[2] = np.random.randint(0, 2)     # subdomain_count
            features[3] = np.random.randint(0, 2)      # hyphen_count
            features[4] = np.random.randint(0, 2)       # number_count
            features[5] = 0.1 if np.random.random() > 0.9 else 0.0  # suspicious_tld
            features[6] = 0.0  # is_ip_based
            features[7] = 0.05 if np.random.random() > 0.95 else 0.0  # is_new_domain

            # Threat features
            features[8] = 0.0  # threat_matched
            features[9] = 0.0  # threat_confidence
            features[10] = 0.0  # usom_match
            features[11] = 0.0  # openphish_match
            features[12] = 0.0  # urlhaus_match

            # Brand features
            features[13] = 0.05 if np.random.random() > 0.95 else 0.0  # brand_matched
            features[14] = np.random.uniform(0.0, 0.3)  # brand_similarity
            features[15] = 0.05 if np.random.random() > 0.95 else 0.0  # is_banking_brand
            features[16] = 0.05 if np.random.random() > 0.95 else 0.0  # is_gov_brand
            features[17] = 0.05 if np.random.random() > 0.95 else 0.0  # is_payment_brand

            # Form features (normal forms, no external submit)
            features[18] = 0.3 if np.random.random() > 0.7 else 0.0  # has_login_form
            features[19] = 0.2 if np.random.random() > 0.8 else 0.0  # has_password_field
            features[20] = 0.1 if np.random.random() > 0.9 else 0.0  # has_credential_fields
            features[21] = 0.05 if np.random.random() > 0.95 else 0.0  # has_payment_fields
            features[22] = 0.05 if np.random.random() > 0.95 else 0.0  # has_external_submit
            features[23] = 0.0  # hidden_field_count
            features[24] = 0.1 if np.random.random() > 0.9 else 0.0  # autocomplete_disabled
            features[25] = float(np.random.randint(0, 3))  # form_count

            # Content features
            features[26] = 0.05 if np.random.random() > 0.95 else 0.0  # has_urgency
            features[27] = 0.0  # has_sms_style
            features[28] = float(np.random.randint(0, 2))   # bank_word_count
            features[29] = float(np.random.randint(0, 2))  # cargo_word_count
            features[30] = float(np.random.randint(0, 2))  # reward_word_count
            features[31] = 0.0  # has_obfuscation
            features[32] = float(np.random.randint(0, 2))  # phone_count
            features[33] = 0.2 if np.random.random() > 0.8 else 0.0  # has_english_text
            features[34] = float(np.random.randint(0, 10))  # external_script_count

            # Behavior features
            features[35] = float(np.random.randint(0, 2))  # redirect_count
            features[36] = 0.0  # has_meta_refresh
            features[37] = 0.05 if np.random.random() > 0.95 else 0.0  # right_click_disabled
            features[38] = 0.0  # text_copy_disabled
            features[39] = float(np.random.randint(0, 2))  # popup_count

            # SSL features (safe sites usually have valid SSL)
            features[40] = 0.95 if np.random.random() > 0.05 else 0.0  # has_ssl
            features[41] = 0.9 if np.random.random() > 0.1 else 0.0  # ssl_valid
            features[42] = 0.05 if np.random.random() > 0.95 else 0.0  # ssl_self_signed
            features[43] = 0.05 if np.random.random() > 0.95 else 0.0  # ssl_expires_soon
            features[44] = 0.8 if np.random.random() > 0.2 else 0.0  # ssl_issuer_trusted

            # Meta features
            features[45] = float(np.random.randint(0, 3))  # signal_count
            features[46] = 0.0  # rule_count
            features[47] = 0.5 if np.random.random() > 0.5 else 0.0  # trust_level

            samples.append(features)

        return np.array(samples, dtype=np.float32)

    def train(self, n_samples: int = 5000, **kwargs) -> "RandomForestClassifier":
        """
        Train RandomForest model.

        Args:
            n_samples: Number of training samples
            **kwargs: Additional arguments for RandomForest

        Returns:
            Trained RandomForestClassifier
        """
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
        except ImportError:
            raise ImportError("scikit-learn is required for training. Install with: pip install scikit-learn")

        # Generate training data
        print(f"Generating {n_samples} training samples...")
        data = self.generate_training_data(n_samples)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            data.X, data.y, test_size=0.2, random_state=42, stratify=data.y
        )

        # Train model
        default_kwargs = {
            'n_estimators': 100,
            'max_depth': 15,
            'min_samples_split': 5,
            'min_samples_leaf': 2,
            'random_state': 42,
            'n_jobs': -1,
        }
        default_kwargs.update(kwargs)

        print("Training RandomForest model...")
        self.model = RandomForestClassifier(**default_kwargs)
        self.model.fit(X_train, y_train)

        # Evaluate
        train_score = self.model.score(X_train, y_train)
        test_score = self.model.score(X_test, y_test)

        print(f"Training accuracy: {train_score:.4f}")
        print(f"Test accuracy: {test_score:.4f}")

        return self.model

    def save_model(self):
        """Save trained model to disk"""
        if self.model is None:
            raise ValueError("No model to save. Train first.")

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"Model saved to {self.model_path}")

    def load_model(self) -> bool:
        """Load model from disk"""
        if not os.path.exists(self.model_path):
            return False

        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            print(f"Model loaded from {self.model_path}")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False

    def get_feature_importance(self) -> List[Tuple[str, float]]:
        """Get feature importance scores"""
        if self.model is None:
            return []

        importances = self.model.feature_importances_
        pairs = list(zip(FeatureSchema.ALL_FEATURES, importances))
        return sorted(pairs, key=lambda x: x[1], reverse=True)


# Singleton trainer instance
model_trainer = ModelTrainer()
