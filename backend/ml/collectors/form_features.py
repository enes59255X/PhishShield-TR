"""
PhishShield TR - Form Feature Collector
Sprint 7.1: Collects form analysis features
"""

from typing import Dict, Optional
from ml.features import FormFeatures


class FormFeatureCollector:
    """
    Collects form analysis features.
    """

    CREDENTIAL_KEYWORDS = ["tc", "kimlik", "tckimlik", "tckn", "tckn"]
    PAYMENT_KEYWORDS = ["kart", "card", "cvv", "iban", "odeme", "kredi karti"]
    OTP_KEYWORDS = ["otp", "dogrulama", "sms", "sms kod"]

    def collect(self, analysis_result: Dict, form_result: Optional[Dict] = None) -> FormFeatures:
        """
        Collect form features.

        Args:
            analysis_result: Main analysis result
            form_result: Form analyzer result (optional)

        Returns:
            FormFeatures object
        """
        features = FormFeatures()

        # Get from form_result if available
        if form_result:
            features.has_login_form = form_result.get("has_login_form", False)
            features.has_password_field = form_result.get("has_password_field", False)
            features.has_credential_fields = form_result.get("has_credential_fields", False)
            features.has_payment_fields = form_result.get("has_payment_fields", False)
            features.has_otp_field = form_result.get("has_otp_field", False)
            features.has_external_submit = form_result.get("has_external_submit", False)
            features.external_domain = form_result.get("external_domain")
            features.hidden_field_count = len(form_result.get("hidden_fields", []))
            features.autocomplete_disabled = form_result.get("autocomplete_disabled", False)
            features.form_count = form_result.get("form_count", 0)
            features.form_risk_score = self._calculate_form_risk(form_result)

        # Extract from analysis result
        reasons = analysis_result.get("reasons", [])
        signals = analysis_result.get("signals", [])
        sub_scores = analysis_result.get("sub_scores", {})
        reasons_text = " ".join(reasons).lower()

        # Form analysis score
        form_score = sub_scores.get("form_analysis", 0)

        if not features.has_login_form and form_score > 20:
            features.has_login_form = True

        # Password field detection
        if not features.has_password_field:
            if any(k in reasons_text for k in ["sifre", "parola", "password"]):
                features.has_password_field = True
            # Also check signals
            elif any(s in signals for s in ["password_field", "credential_harvest", "credential_harvesting_external_post"]):
                features.has_password_field = True
                if "credential_harvesting_external_post" in signals:
                    features.has_external_submit = True

        # Credential fields
        if not features.has_credential_fields:
            if any(k in reasons_text for k in self.CREDENTIAL_KEYWORDS):
                features.has_credential_fields = True
            # Also check signals
            elif any(s in signals for s in ["credential_field", "credential_harvest", "has_credential_fields"]):
                features.has_credential_fields = True

        # Payment fields
        if not features.has_payment_fields:
            if any(k in reasons_text for k in self.PAYMENT_KEYWORDS):
                features.has_payment_fields = True

        # External submit
        if not features.has_external_submit:
            if any("dış adrese" in r.lower() or "external" in r.lower() for r in reasons):
                features.has_external_submit = True
            # Also check signals
            elif any(s in signals for s in ["external_post_action", "external_submit",
                                              "credential_harvesting_external_post"]):
                features.has_external_submit = True

        # Hidden fields
        if features.hidden_field_count == 0:
            if "hidden" in reasons_text:
                features.hidden_field_count = 1

        # Calculate form risk score if not set
        if features.form_risk_score == 0:
            features.form_risk_score = self._calculate_form_risk_from_analysis(
                features, reasons_text
            )

        return features

    def _calculate_form_risk(self, form_result: Dict) -> int:
        """Calculate form risk score from form result"""
        score = 0

        if form_result.get("has_password_field"):
            score += 30
        if form_result.get("has_external_submit"):
            score += 40
        if form_result.get("has_credential_fields"):
            score += 25
        if form_result.get("has_payment_fields"):
            score += 35
        if form_result.get("has_otp_field"):
            score += 20
        if len(form_result.get("hidden_fields", [])) > 0:
            score += 15

        return min(100, score)

    def _calculate_form_risk_from_analysis(self, features: FormFeatures, reasons_text: str) -> int:
        """Calculate form risk score from analysis"""
        score = 0

        if features.has_password_field:
            score += 30
        if features.has_external_submit:
            score += 40
        if features.has_credential_fields:
            score += 25
        if features.has_payment_fields:
            score += 35
        if features.has_otp_field:
            score += 20
        if features.hidden_field_count > 0:
            score += 15

        return min(100, score)
