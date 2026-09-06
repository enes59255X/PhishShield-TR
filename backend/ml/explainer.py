"""
PhishShield TR - ML Explainer
Sprint 12: Human-readable explanations for ML decisions

Purpose:
- Explain WHY the ML model made a prediction
- Show feature importance in decision
- Provide actionable insights
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional


@dataclass
class FeatureExplanation:
    """Explanation for a single feature"""
    feature_name: str
    feature_value: Any
    contribution: float  # Positive = phishing signal, Negative = safe signal
    description: str
    risk_indicator: str  # "high_risk", "medium_risk", "low_risk", "safe"


@dataclass
class ExplanationResult:
    """Complete explanation for an analysis result"""
    # Summary
    summary: str
    decision: str
    risk_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"

    # Feature contributions
    top_risk_features: List[FeatureExplanation]
    top_safe_features: List[FeatureExplanation]

    # Component breakdown
    threat_intel_explanation: str
    brand_explanation: str
    form_explanation: str
    domain_explanation: str
    content_explanation: str
    ml_explanation: str

    # Actionable advice
    actionable_advice: List[str]

    # Technical details
    score_breakdown: Dict[str, Any]


class MLExplainer:
    """
    Generates human-readable explanations for phishing decisions.

    Takes complex analysis results and explains them in simple Turkish
    so users can understand WHY a site was flagged.
    """

    FEATURE_DESCRIPTIONS = {
        # Domain features
        "domain_length": "Domain uzunluğu",
        "hyphen_count": "Tire sayısı",
        "subdomain_count": "Alt domain sayısı",
        "digit_count": "Rakam sayısı",
        "is_suspicious_tld": "Şüpheli alan adı uzantısı",
        "is_new_domain": "Yeni domain",
        "is_ip_based": "IP tabanlı domain",
        "is_punycode": "Unicode domain",
        "has_https": "HTTPS kullanıyor",
        "tld": "Domain uzantısı",

        # Brand features
        "is_impostor": "Marka taklidi",
        "similarity_score": "Benzerlik skoru",
        "brand_name": "Taklit edilen marka",
        "brand_category": "Marka kategorisi",

        # Form features
        "has_external_submit": "Harici form gönderimi",
        "has_password_field": "Parola alanı var",
        "has_credential_fields": "Kimlik bilgisi alanları",
        "has_hidden_fields": "Gizli alanlar",
        "external_submit_url": "Gönderim adresi",

        # Content features
        "has_urgency": "Aciliyet hissettirme",
        "has_sms_style": "SMS tarzı içerik",
        "bank_word_count": "Banka kelime sayısı",
        "cargo_word_count": "Kargo kelime sayısı",
        "reward_word_count": "Ödül kelime sayısı",

        # Threat features
        "threat_matched": "Tehdit eşleşmesi",
        "threat_source": "Tehdit kaynağı",
        "threat_confidence": "Tehdit güvenilirliği",

        # ML-specific
        "ml_probability": "ML phishing olasılığı",
        "ml_confidence": "ML güven skoru",

        # Component scores
        "threat_score": "Tehdit puanı",
        "brand_score": "Marka puanı",
        "form_score": "Form puanı",
        "domain_score": "Domain puanı",
        "content_score": "İçerik puanı",
        "fusion_score": "Füzyon skoru",
        "final_score": "Final skoru",
    }

    RISK_THRESHOLDS = {
        "CRITICAL": 85,
        "HIGH": 70,
        "MEDIUM": 50,
        "LOW": 25,
        "SAFE": 0,
    }

    def explain(
        self,
        decision: str,
        final_score: int,
        fusion_score: int,
        ml_probability: float,
        ml_confidence: float,
        component_scores: Dict[str, int],
        features: Any,
        reasons: List[str]
    ) -> ExplanationResult:
        """
        Generate complete explanation for an analysis result.

        Args:
            decision: SAFE, CAUTION, or DANGER
            final_score: Final risk score (0-100)
            fusion_score: Score from fusion engine
            ml_probability: ML model phishing probability
            ml_confidence: ML model confidence
            component_scores: Dict of component scores
            features: SiteFeatures object
            reasons: List of reason strings

        Returns:
            ExplanationResult with human-readable explanations
        """
        risk_level = self._get_risk_level(final_score)

        # Generate component explanations
        threat_exp = self._explain_threat(features, component_scores)
        brand_exp = self._explain_brand(features, component_scores)
        form_exp = self._explain_form(features, component_scores)
        domain_exp = self._explain_domain(features, component_scores)
        content_exp = self._explain_content(features, component_scores)
        ml_exp = self._explain_ml(ml_probability, ml_confidence)

        # Get feature contributions
        top_risk, top_safe = self._get_top_features(features, component_scores)

        # Generate summary
        summary = self._generate_summary(
            decision, final_score, risk_level, features, reasons
        )

        # Generate actionable advice
        advice = self._generate_advice(decision, features, reasons)

        # Score breakdown
        breakdown = {
            "final_score": final_score,
            "fusion_score": fusion_score,
            "ml_probability": f"{ml_probability:.1%}",
            "ml_confidence": f"{ml_confidence:.1%}",
            "fusion_weight": "70%",
            "ml_weight": "30%",
            "components": component_scores,
        }

        return ExplanationResult(
            summary=summary,
            decision=decision,
            risk_level=risk_level,
            top_risk_features=top_risk,
            top_safe_features=top_safe,
            threat_intel_explanation=threat_exp,
            brand_explanation=brand_exp,
            form_explanation=form_exp,
            domain_explanation=domain_exp,
            content_explanation=content_exp,
            ml_explanation=ml_exp,
            actionable_advice=advice,
            score_breakdown=breakdown,
        )

    def _get_risk_level(self, score: int) -> str:
        """Get risk level from score"""
        if score >= self.RISK_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        elif score >= self.RISK_THRESHOLDS["HIGH"]:
            return "HIGH"
        elif score >= self.RISK_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        elif score >= self.RISK_THRESHOLDS["LOW"]:
            return "LOW"
        return "SAFE"

    def _explain_threat(self, features: Any, scores: Dict[str, int]) -> str:
        """Explain threat intelligence findings"""
        if features is None or not hasattr(features, 'threat'):
            return "Tehdit analizi yapılmadı"

        threat = features.threat

        if threat.matched:
            source_names = {
                "usom": "USOM (TR)",
                "openphish": "OpenPhish",
                "urlhaus": "URLhaus",
                "phishTank": "PhishTank",
            }
            source = source_names.get(threat.source, threat.source)
            conf = int(threat.confidence * 100)
            return (
                f"⚠️ TEHLİT BULUNDU! "
                f"{source} veritabanında eşleşme tespit edildi. "
                f"Güvenilirlik: %{conf}. "
                f"Bu site daha önce phishing amaçlı kullanılmış."
            )

        if scores.get("threat", 0) > 0:
            return f"Tehdit analizi: {scores['threat']} puan - şüpheli sinyaller var"

        return "✅ Tehdit veritabanında eşleşme yok"

    def _explain_brand(self, features: Any, scores: Dict[str, int]) -> str:
        """Explain brand impersonation findings"""
        if features is None or not hasattr(features, 'brand'):
            return "Marka analizi yapılmadı"

        brand = features.brand

        if brand.is_impostor:
            brand_name = brand.brand_name or "bilinmeyen marka"
            similarity = int(brand.similarity_score * 100)
            category = brand.brand_category or "genel"

            category_names = {
                "BANKING": "💰 Bankacılık",
                "GOVERNMENT": "🏛️ Kamu kurumu",
                "PAYMENT": "💳 Ödeme sistemi",
                "ECOMMERCE": "🛒 E-ticaret",
                "CARGO": "📦 Kargo",
                "SOCIAL": "📱 Sosyal medya",
                "EMAIL": "📧 E-posta",
            }
            cat_name = category_names.get(category, category)

            return (
                f"🚨 MARK A TAKLİDİ TESPİT EDİLDİ! "
                f"'{brand_name}' kurumsal kimliği taklit ediliyor. "
                f"Benzerlik: %{similarity}. "
                f"Kategori: {cat_name}. "
                f"Bu, kimlik avı saldırısının açık göstergesidir."
            )

        if scores.get("brand", 0) > 0:
            return f"Marka analizi: {scores['brand']} puan - bazı marka sinyalleri"

        return "✅ Resmi marka tespit edilmedi"

    def _explain_form(self, features: Any, scores: Dict[str, int]) -> str:
        """Explain form behavior findings"""
        if features is None or not hasattr(features, 'form'):
            return "Form analizi yapılmadı"

        form = features.form
        signals = []

        if form.has_external_submit:
            submit_url = form.external_submit_url or "bilinmeyen adres"
            signals.append(f"form verisi harici adrese gönderiliyor: {submit_url}")

        if form.has_password_field:
            signals.append("parola giriş alanı tespit edildi")

        if form.has_credential_fields:
            signals.append("kimlik bilgisi alanları mevcut")

        if form.has_hidden_fields:
            signals.append(f"{form.hidden_field_count} adet gizli alan var")

        if signals:
            return (
                "🚨 FORM ANALİZİ: " +
                " | ".join(signals) +
                ". Bu form, kullanıcı bilgilerini toplamak için tasarlanmış olabilir."
            )

        return "✅ Form analizi temiz - şüpheli form davranışı yok"

    def _explain_domain(self, features: Any, scores: Dict[str, int]) -> str:
        """Explain domain intelligence findings"""
        if features is None or not hasattr(features, 'domain_features'):
            return "Domain analizi yapılmadı"

        df = features.domain_features
        signals = []

        if df.is_suspicious_tld:
            signals.append(f"şüpheli uzantı: .{df.tld}")

        if df.is_new_domain:
            signals.append("yeni kayıtlı domain (birkaç gün/hafta)")

        if df.is_ip_based:
            signals.append("IP adresi kullanılıyor (normal siteler domain kullanır)")

        if df.is_punycode:
            signals.append("Unicode/Punycode domain - dikkatli olun")

        if df.hyphen_count > 3:
            signals.append(f"çok sayıda tire ({df.hyphen_count} adet)")

        if df.subdomain_count > 3:
            signals.append(f"çok sayıda alt domain ({df.subdomain_count} adet)")

        if signals:
            return (
                "⚠️ DOMAIN ANALİZİ: " +
                " | ".join(signals) +
                ". Bu özellikler phishing sitelerinde sıkça görülür."
            )

        return "✅ Domain analizi temiz"

    def _explain_content(self, features: Any, scores: Dict[str, int]) -> str:
        """Explain content signal findings"""
        if features is None or not hasattr(features, 'content'):
            return "İçerik analizi yapılmadı"

        content = features.content
        signals = []

        if content.has_urgency:
            signals.append("aciliyet hissettirme ( فوری! , URGENT, vb.)")

        if content.has_sms_style:
            signals.append("SMS tarzı içerik - kısa ve acil mesaj")

        if content.bank_word_count > 3:
            signals.append(f"çok sayıda banka kelimesi ({content.bank_word_count})")

        if content.cargo_word_count > 2:
            signals.append(f"kargo kelimeleri tespit edildi ({content.cargo_word_count})")

        if content.reward_word_count > 2:
            signals.append(f"ödül/piyango kelimeleri ({content.reward_word_count})")

        if signals:
            return (
                "⚠️ İÇERİK ANALİZİ: " +
                " | ".join(signals) +
                ". Bu içerikler sosyal mühendislik taktiklerini işaret edebilir."
            )

        return "✅ İçerik analizi temiz"

    def _explain_ml(self, probability: float, confidence: float) -> str:
        """Explain ML model prediction"""
        prob_pct = int(probability * 100)
        conf_pct = int(confidence * 100)

        if probability > 0.8:
            assessment = (
                f"ML modeli bu siteyi %{prob_pct} olasılıkla phishing olarak sınıflandırdı. "
                f"Model güveni: %{conf_pct}. "
                f"Makine öğrenmesi modeli, 1000+ özellik üzerinden eğitildi ve "
                f"çeşitli phishing kalıplarını tanımayı öğrendi."
            )
        elif probability > 0.5:
            assessment = (
                f"ML modeli %{prob_pct} olasılıkla phishing şüphesi bildirdi. "
                f"Model güveni: %{conf_pct}. "
                f"Ek manuel analiz önerilir."
            )
        elif probability > 0.3:
            assessment = (
                f"ML modeli %{prob_pct} oranında şüpheli buldu. "
                f"Güven skoru: %{conf_pct}. "
                f"Çoğunlukla güvenli görünüyor."
            )
        else:
            assessment = (
                f"ML modeli bu siteyi güvenli olarak değerlendirdi (phishing olasılığı: %{prob_pct}). "
                f"Model güveni: %{conf_pct}. "
                f"Makine öğrenmesi kalıpları temiz görünüyor."
            )

        return assessment

    def _get_top_features(
        self,
        features: Any,
        scores: Dict[str, int]
    ) -> tuple:
        """Get top risk and safe features"""
        top_risk = []
        top_safe = []

        if features is None or not hasattr(features, 'domain_features'):
            return top_risk, top_safe

        # Risk indicators
        risk_features = []

        if features.domain_features.is_new_domain:
            risk_features.append(FeatureExplanation(
                feature_name="is_new_domain",
                feature_value=True,
                contribution=30,
                description="Yeni kayıtlı domain",
                risk_indicator="high_risk"
            ))

        if features.domain_features.is_suspicious_tld:
            risk_features.append(FeatureExplanation(
                feature_name="is_suspicious_tld",
                feature_value=features.domain_features.tld,
                contribution=25,
                description=f"Şüpheli TLD: .{features.domain_features.tld}",
                risk_indicator="high_risk"
            ))

        if features.domain_features.is_ip_based:
            risk_features.append(FeatureExplanation(
                feature_name="is_ip_based",
                feature_value=True,
                contribution=40,
                description="IP adresi kullanılıyor",
                risk_indicator="high_risk"
            ))

        if features.domain_features.hyphen_count > 3:
            risk_features.append(FeatureExplanation(
                feature_name="hyphen_count",
                feature_value=features.domain_features.hyphen_count,
                contribution=15,
                description=f"Fazla tire kullanımı ({features.domain_features.hyphen_count} adet)",
                risk_indicator="medium_risk"
            ))

        if hasattr(features, 'brand') and features.brand.is_impostor:
            risk_features.append(FeatureExplanation(
                feature_name="is_impostor",
                feature_value=True,
                contribution=50,
                description=f"Marka taklidi: {features.brand.brand_name}",
                risk_indicator="high_risk"
            ))

        if hasattr(features, 'form') and features.form.has_external_submit:
            risk_features.append(FeatureExplanation(
                feature_name="has_external_submit",
                feature_value=True,
                contribution=40,
                description="Form harici adrese gönderim yapıyor",
                risk_indicator="high_risk"
            ))

        if hasattr(features, 'form') and features.form.has_password_field:
            risk_features.append(FeatureExplanation(
                feature_name="has_password_field",
                feature_value=True,
                contribution=25,
                description="Parola alanı tespit edildi",
                risk_indicator="medium_risk"
            ))

        if hasattr(features, 'threat') and features.threat.matched:
            risk_features.append(FeatureExplanation(
                feature_name="threat_matched",
                feature_value=True,
                contribution=100,
                description=f"Tehdit veritabanında bulundu: {features.threat.source}",
                risk_indicator="high_risk"
            ))

        # Sort by contribution
        risk_features.sort(key=lambda x: x.contribution, reverse=True)
        top_risk = risk_features[:5]

        # Safe indicators
        if hasattr(features, 'domain_features') and features.domain_features.has_https and not features.domain_features.is_punycode:
            top_safe.append(FeatureExplanation(
                feature_name="has_https",
                feature_value=True,
                contribution=-20,
                description="HTTPS sertifikası var",
                risk_indicator="safe"
            ))

        if (hasattr(features, 'brand') and hasattr(features, 'form') and
            not features.brand.is_impostor and not features.form.has_external_submit):
            if features.brand.brand_name:
                top_safe.append(FeatureExplanation(
                    feature_name="legitimate_brand",
                    feature_value=features.brand.brand_name,
                    contribution=-15,
                    description=f"Yasal marka: {features.brand.brand_name}",
                    risk_indicator="safe"
                ))

        return top_risk, top_safe

    def _generate_summary(
        self,
        decision: str,
        score: int,
        risk_level: str,
        features: Any,
        reasons: List[str]
    ) -> str:
        """Generate overall summary"""
        if decision == "DANGER" or risk_level in ["CRITICAL", "HIGH"]:
            return (
                f"🚨 TEHLİKE OLASILIĞI YÜKSEK! "
                f"Final risk skoru: {score}/100 ({risk_level}). "
                f"Bu site, phishing veya dolandırıcılık amacıyla kullanılıyor olabilir. "
                f"Kişisel bilgilerinizi girmeyin!"
            )

        if decision == "CAUTION" or risk_level == "MEDIUM":
            return (
                f"⚠️ DİKKAT GEREKLİ! "
                f"Final risk skoru: {score}/100 ({risk_level}). "
                f"Bu site bazı şüpheli özellikler içeriyor. "
                f"Devam etmeden önce dikkatlice kontrol edin."
            )

        if risk_level == "LOW":
            return (
                f"🟡 DÜŞÜK RİSK. "
                f"Final skoru: {score}/100. "
                f"Bazı küçük şüpheli işaretler var ama genel olarak güvenli görünüyor."
            )

        return (
            f"✅ GÜVENLİ GÖRÜNÜYOR. "
            f"Final skoru: {score}/100. "
            f"Bu site, analiz edilen tehdit kalıplarıyla eşleşmedi."
        )

    def _generate_advice(
        self,
        decision: str,
        features: Any,
        reasons: List[str]
    ) -> List[str]:
        """Generate actionable advice"""
        advice = []

        if decision == "DANGER":
            advice.append("🚫 Kişisel veya finansal bilgilerinizi girmeyin")
            advice.append("🚫 Parola veya PIN girmeyin")
            advice.append("💡 Orijinal siteyi tarayıcınıza manuel olarak yazın")
            advice.append("💡 Bankanızı veya kurumu doğrudan arayın")

        if decision == "CAUTION":
            advice.append("🔍 Site adresini dikkatlice kontrol edin")
            advice.append("🔍 URL'nin gerçek markayla eşleştiğinden emin olun")
            advice.append("💡 HTTPS sertifikasını inceleyin")
            advice.append("💡 Şüphe durumunda tarayıcıyı kapatın")

        if features is not None and hasattr(features, 'threat') and features.threat.matched:
            advice.append("⚠️ Bu site tehdit veritabanlarında kayıtlı!")

        if features is not None and hasattr(features, 'brand') and features.brand.is_impostor:
            brand_name = features.brand.brand_name or "bilinmeyen"
            advice.append(f"⚠️ '{brand_name}' taklit ediliyor - orijinal siteyi arayın")

        if features is not None and hasattr(features, 'form') and features.form.has_external_submit:
            advice.append("⚠️ Form verisi harici adrese gönderiliyor")

        if not advice:
            advice.append("✅ Şu an için özel bir uyarı yok")
            advice.append("💡 Yine de bilinmeyen linklere tıklamaktan kaçının")

        return advice


# Singleton instance
ml_explainer = MLExplainer()
