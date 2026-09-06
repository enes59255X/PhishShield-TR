"""
PhishShield TR - Content Feature Collector
Sprint 7.1: Collects content/text analysis features
"""

import re
from typing import Dict
from ml.features import ContentFeatures


class ContentFeatureCollector:
    """
    Collects content and text analysis features.
    """

    URGENCY_WORDS = [
        "acil", "hemen", "son", "warning", "urgent", "immediate", "süre",
        "bitiş", "expires", "limited", "fırsat", "kaçır", "bekleme", "sonuc",
        "ödül", "cekilis", "kazandin"
    ]

    BANK_WORDS = [
        "garanti", "akbank", "isbank", "ziraat", "halkbank", "vakifbank",
        "qnb", "ing", "teb", "hsbc", "banka", "kredi", "kart", "hesap",
        "iban", "swift", "transfer"
    ]

    CARGO_WORDS = [
        "kargo", "cargo", "gonderi", "teslimat", "ptt", "aras", "yurtici",
        "mng", "ups", "dhl", "fedex", "kurye", "gönderi", "takip"
    ]

    REWARD_WORDS = [
        "odul", "hediye", "cekilis", "kazan", "promosyon", "indirim",
        "reward", "gift", "prize", "winner", "lottery", "free", "kazandın"
    ]

    INVESTMENT_WORDS = [
        "yatirim", "faiz", "kazanc", "hisse", "bitcoin", "crypto",
        "ethereum", "trading", "borsa", "forex"
    ]

    def collect(self, analysis_result: Dict) -> ContentFeatures:
        """
        Collect content features.

        Args:
            analysis_result: Main analysis result

        Returns:
            ContentFeatures object
        """
        features = ContentFeatures()

        reasons = analysis_result.get("reasons", [])
        sub_scores = analysis_result.get("sub_scores", {})
        threat_type = analysis_result.get("threat_type", "")

        # Combine all text
        all_text = " ".join(reasons) + " " + threat_type
        all_text_lower = all_text.lower()

        # Count urgency words
        features.urgency_word_count = sum(1 for w in self.URGENCY_WORDS if w in all_text_lower)
        features.has_urgency = features.urgency_word_count > 0

        # SMS style detection
        features.has_sms_style = self._detect_sms_style(all_text)

        # Count keyword categories
        features.bank_word_count = sum(1 for w in self.BANK_WORDS if w in all_text_lower)
        features.cargo_word_count = sum(1 for w in self.CARGO_WORDS if w in all_text_lower)
        features.reward_word_count = sum(1 for w in self.REWARD_WORDS if w in all_text_lower)
        features.investment_word_count = sum(1 for w in self.INVESTMENT_WORDS if w in all_text_lower)

        # External scripts
        external_script_count = sum(1 for r in reasons if "external script" in r.lower())
        features.external_script_count = external_script_count

        # Iframes
        iframe_count = sum(1 for r in reasons if "iframe" in r.lower())
        features.iframe_count = iframe_count

        # JS obfuscation
        features.has_obfuscation = sub_scores.get("js_obfuscation", 0) > 10

        # Phone numbers
        phone_pattern = r"\b\d{10,}\b"
        phone_matches = re.findall(phone_pattern, all_text)
        features.phone_count = len(phone_matches)

        # English text (low confidence signal)
        english_indicators = ["login", "password", "verify", "account", "confirm", "suspended"]
        features.has_english_text = any(w in all_text_lower for w in english_indicators)

        return features

    def _detect_sms_style(self, text: str) -> bool:
        """Detect if text is formatted like SMS phishing"""
        sms_indicators = [
            r"\b\d{10,}\b",  # Long number sequences
            r"(?:sayın|sevgili|degerli)",  # Turkish SMS greetings
            r"(?:teslimat|kargo|gonderi)",  # Cargo-related
            r"(?:odeme|odemeniz|bakiye)",  # Payment-related
            r"(?:sonuc|cekilis|kazandin)",  # Lottery result
        ]

        for pattern in sms_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False
