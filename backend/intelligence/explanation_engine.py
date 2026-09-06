"""
PhishShield TR - Explanation Engine
Sprint 12: Unified explanations for all analysis results

Purpose:
- Generate human-readable explanations for phishing decisions
- Explain contribution of each analysis component
- Provide actionable security advice
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from ml.explainer import MLExplainer, ExplanationResult as MLExplanationResult
from intelligence.fusion_engine import FusionResult


@dataclass
class ComponentExplanation:
    """Explanation for a single analysis component"""
    component: str  # threat_intel, brand, form, domain, content, ml
    score: int
    max_score: int
    percentage: float
    verdict: str  # safe, caution, danger
    summary: str
    details: List[str]


@dataclass
class ExplanationEngineResult:
    """Complete explanation for a phishing analysis decision"""
    # Overview
    decision: str  # SAFE, CAUTION, DANGER
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW, SAFE
    final_score: int

    # Human-readable summary
    headline: str
    summary: str
    immediate_advice: str

    # Component breakdowns
    threat_intel: ComponentExplanation
    brand_protection: ComponentExplanation
    form_behavior: ComponentExplanation
    domain_analysis: ComponentExplanation
    content_analysis: ComponentExplanation
    ml_analysis: ComponentExplanation

    # Score breakdown
    score_contributions: Dict[str, float]

    # Actionable steps
    recommended_actions: List[str]
    red_flags: List[str]

    # Technical details
    confidence: int
    confidence_level: str
    factors: Dict[str, Any]


class ExplanationEngine:
    """
    Unified Explanation Engine

    Takes analysis results from Fusion Engine and Hybrid Analyzer
    and produces clear, actionable explanations in Turkish.
    """

    def __init__(self):
        self.ml_explainer = MLExplainer()

    def explain(
        self,
        fusion_result: FusionResult,
        hybrid_result: Any,  # HybridResult
        features: Any
    ) -> ExplanationEngineResult:
        """
        Generate comprehensive explanation for analysis results.

        Args:
            fusion_result: Result from FusionEngine
            hybrid_result: Result from HybridAnalyzer (if available)
            features: SiteFeatures object

        Returns:
            ExplanationEngineResult with complete explanation
        """
        # Determine overall decision
        decision = hybrid_result.decision if hybrid_result else fusion_result.decision
        final_score = hybrid_result.final_score if hybrid_result else fusion_result.final_score

        # Calculate risk level
        risk_level = self._calculate_risk_level(final_score)

        # Generate headlines
        headline = self._generate_headline(decision, risk_level, features)
        immediate_advice = self._generate_immediate_advice(decision, risk_level, features)

        # Build component explanations
        threat_exp = self._explain_threat_intel(fusion_result, features)
        brand_exp = self._explain_brand(fusion_result, features)
        form_exp = self._explain_form(fusion_result, features)
        domain_exp = self._explain_domain(fusion_result, features)
        content_exp = self._explain_content(fusion_result, features)
        ml_exp = self._explain_ml(fusion_result, hybrid_result, features)

        # Calculate contributions
        contributions = self._calculate_contributions(fusion_result, hybrid_result)

        # Generate recommended actions
        recommended_actions = self._generate_recommended_actions(
            decision, risk_level, features, fusion_result
        )

        # Identify red flags
        red_flags = self._identify_red_flags(fusion_result, features)

        # Confidence
        confidence = hybrid_result.confidence if hybrid_result else fusion_result.confidence
        confidence_level = self._get_confidence_level(confidence)

        return ExplanationEngineResult(
            decision=decision,
            risk_level=risk_level,
            final_score=final_score,
            headline=headline,
            summary=self._generate_summary(decision, risk_level, features, fusion_result),
            immediate_advice=immediate_advice,
            threat_intel=threat_exp,
            brand_protection=brand_exp,
            form_behavior=form_exp,
            domain_analysis=domain_exp,
            content_analysis=content_exp,
            ml_analysis=ml_exp,
            score_contributions=contributions,
            recommended_actions=recommended_actions,
            red_flags=red_flags,
            confidence=confidence,
            confidence_level=confidence_level,
            factors=self._extract_factors(fusion_result, features)
        )

    def _calculate_risk_level(self, score: int) -> str:
        """Calculate risk level from score"""
        if score >= 85:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 25:
            return "LOW"
        return "SAFE"

    def _get_confidence_level(self, confidence: int) -> str:
        """Get confidence level name"""
        if confidence >= 90:
            return "ÇOK YÜKSEK"
        elif confidence >= 70:
            return "YÜKSEK"
        elif confidence >= 50:
            return "ORTA"
        elif confidence >= 30:
            return "DÜŞÜK"
        return "ÇOK DÜŞÜK"

    def _generate_headline(
        self,
        decision: str,
        risk_level: str,
        features: Any
    ) -> str:
        """Generate attention-grabbing headline"""
        if decision == "DANGER" or risk_level == "CRITICAL":
            if features.threat.matched:
                return "🚨 TEHLİT! Bu site bilinen phishing adresi!"
            if features.brand.is_impostor:
                brand = features.brand.brand_name or "bilinmeyen"
                return f"🚨 UYARI! {brand} taklit ediliyor!"
            if features.form.has_external_submit:
                return "🚨 RİSKLİ! Form verileriniz çalınabilir!"
            return "🚨 TEHLİKLİ SİTE TESPİT EDİLDİ!"

        if decision == "CAUTION" or risk_level == "HIGH":
            return "⚠️ ŞÜPHELİ SİTE - Dikkatli olun!"

        if risk_level == "MEDIUM":
            return "🟡 ORTA RİSK - İnceleme gerekebilir"

        if risk_level == "LOW":
            return "🟢 DÜŞÜK RİSK - Genel olarak güvenli"

        return "✅ GÜVENLİ - Tehdit tespit edilmedi"

    def _generate_immediate_advice(self, decision: str, risk_level: str, features: Any) -> str:
        """Generate immediate actionable advice"""
        if decision == "DANGER" or risk_level == "CRITICAL":
            return (
                "⛔ HEMEN UZAKLAŞIN! "
                "Kişisel bilgilerinizi (şifre, kredi kartı, TC kimlik) GİRM EYİN! "
                "Bankanızı veya ilgili kurumu DOĞRUDAN arayın."
            )

        if decision == "CAUTION" or risk_level == "HIGH":
            return (
                "⚠️ DİKKATLİ OLUN! "
                "Site adresiniManuel olarak kontrol edin. "
                "Şüphe duyarsanız tarayıcıyı kapatın."
            )

        if risk_level == "MEDIUM":
            return "🔍 Kontrol etmeden bilgi girmeyin. Şüpheli görünüyor."

        return "✅ Bilgi girmeniz güvenli görünüyor ama yine de dikkatli olun."

    def _generate_summary(
        self,
        decision: str,
        risk_level: str,
        features: Any,
        fusion_result: FusionResult
    ) -> str:
        """Generate detailed summary"""
        score = fusion_result.final_score

        summary_parts = []

        # Overall assessment
        if decision == "DANGER":
            summary_parts.append(
                f"Bu site, {score}/100 risk skoru ile yüksek riskli olarak değerlendirildi."
            )
        elif decision == "CAUTION":
            summary_parts.append(
                f"Bu site, {score}/100 risk skoru ile şüpheli özellikler taşıyor."
            )
        else:
            summary_parts.append(
                f"Bu site, {score}/100 risk skoru ile güvenli görünüyor."
            )

        # Key findings
        findings = []

        if features.threat.matched:
            findings.append(f"tehdit veritabanında tespit edildi ({features.threat.source})")

        if features.brand.is_impostor:
            brand = features.brand.brand_name or "bilinmeyen"
            findings.append(f"marka taklidi: {brand}")

        if features.form.has_external_submit:
            findings.append("form verisi başkalarına gönderiliyor")

        if features.domain_features.is_new_domain:
            findings.append("yeni kayıtlı domain")

        if features.domain_features.is_suspicious_tld:
            findings.append(f"şüpheli uzantı: .{features.domain_features.tld}")

        if findings:
            summary_parts.append("Ana bulgular: " + ", ".join(findings) + ".")

        return " ".join(summary_parts)

    def _explain_threat_intel(
        self,
        fusion_result: FusionResult,
        features: Any
    ) -> ComponentExplanation:
        """Explain threat intelligence findings"""
        score = fusion_result.threat_score
        matched = features.threat.matched
        source = features.threat.source
        confidence = features.threat.confidence

        if matched:
            summary = f"Tehdit veritabanında eşleşme: {source}"
            details = [
                f"Kaynak: {source}",
                f"Güvenilirlik: %{int(confidence * 100)}",
                "Bu site daha önce phishing için kullanıldı"
            ]
            verdict = "danger"
        elif score > 0:
            summary = "Şüpheli tehdit sinyalleri"
            details = [f"Tehdit skoru: {score}/100"]
            verdict = "caution"
        else:
            summary = "Tehdit veritabanında eşleşme yok"
            details = ["Bilinen tehditlerle eşleşmedi"]
            verdict = "safe"

        return ComponentExplanation(
            component="Tehdit İstihbaratı",
            score=score,
            max_score=100,
            percentage=score,
            verdict=verdict,
            summary=summary,
            details=details
        )

    def _explain_brand(
        self,
        fusion_result: FusionResult,
        features: Any
    ) -> ComponentExplanation:
        """Explain brand protection findings"""
        score = fusion_result.brand_score
        is_impostor = features.brand.is_impostor
        brand_name = features.brand.brand_name
        similarity = features.brand.similarity_score
        category = features.brand.brand_category

        if is_impostor:
            cat_text = {
                "BANKING": "Bankacılık",
                "GOVERNMENT": "Kamu/Kurum",
                "PAYMENT": "Ödeme",
                "ECOMMERCE": "E-ticaret",
                "CARGO": "Kargo",
            }.get(category, "genel")

            summary = f"Marka taklidi tespit edildi: {brand_name}"
            details = [
                f"Taklit edilen marka: {brand_name}",
                f"Kategori: {cat_text}",
                f"Benzerlik: %{int(similarity * 100)}",
                "Bu, kimlik avı saldırısının açık göstergesidir"
            ]
            verdict = "danger"
        elif score > 0:
            summary = f"Marka sinyalleri: {brand_name or 'bilinmeyen'}"
            details = [
                f"Marka: {brand_name or 'tespit edilemedi'}",
                f"Benzerlik skoru: %{int(similarity * 100)}" if similarity else "Belirlenemedi"
            ]
            verdict = "caution"
        else:
            summary = "Marka taklidi tespit edilmedi"
            details = ["Yasal markalarla eşleşme yok"]
            verdict = "safe"

        return ComponentExplanation(
            component="Marka Koruma",
            score=score,
            max_score=100,
            percentage=score,
            verdict=verdict,
            summary=summary,
            details=details
        )

    def _explain_form(
        self,
        fusion_result: FusionResult,
        features: Any
    ) -> ComponentExplanation:
        """Explain form behavior analysis"""
        score = fusion_result.form_score
        form = features.form

        details = []

        if form.has_external_submit:
            details.append(f"Form harici adrese gönderim: {form.external_domain or 'bilinmeyen'}")

        if form.has_password_field:
            details.append("Parola alanı var")

        if form.has_credential_fields:
            details.append("Kimlik bilgisi alanları mevcut")

        if form.has_payment_fields:
            details.append("Ödeme alanları mevcut")

        if form.hidden_field_count > 0:
            details.append(f"{form.hidden_field_count} gizli alan tespit edildi")

        if not details:
            details.append("Şüpheli form davranışı yok")

        if form.has_external_submit:
            summary = "Tehlikeli: Form verisi başkasına gidiyor!"
            verdict = "danger"
        elif form.has_password_field and form.has_credential_fields:
            summary = "Riskli: Kimlik bilgisi toplama formu"
            verdict = "caution"
        elif details:
            summary = "Form analizi: Bazı dikkat noktaları var"
            verdict = "caution"
        else:
            summary = "Form analizi: Temiz"
            verdict = "safe"

        return ComponentExplanation(
            component="Form Analizi",
            score=score,
            max_score=100,
            percentage=score,
            verdict=verdict,
            summary=summary,
            details=details
        )

    def _explain_domain(
        self,
        fusion_result: FusionResult,
        features: Any
    ) -> ComponentExplanation:
        """Explain domain intelligence"""
        score = fusion_result.domain_score
        df = features.domain_features

        details = []

        if df.is_suspicious_tld:
            details.append(f"Şüpheli TLD: .{df.tld}")

        if df.is_new_domain:
            details.append("Yeni kayıtlı domain")

        if df.is_ip_based:
            details.append("IP adresi kullanılıyor (domain yerine)")

        if df.is_punycode:
            details.append("Unicode/Punycode domain")

        if df.hyphen_count > 3:
            details.append(f"Fazla tire sayısı: {df.hyphen_count}")

        if df.subdomain_count > 3:
            details.append(f"Çok sayıda alt domain: {df.subdomain_count}")

        if not details:
            details.append("Domain özellikleri normal")

        if df.is_new_domain or df.is_suspicious_tld or df.is_ip_based:
            summary = "Riskli domain özellikleri tespit edildi"
            verdict = "caution"
        elif details:
            summary = "Domain analizi: Bazı dikkat noktaları"
            verdict = "caution"
        else:
            summary = "Domain analizi: Temiz"
            verdict = "safe"

        return ComponentExplanation(
            component="Domain İstihbaratı",
            score=score,
            max_score=100,
            percentage=score,
            verdict=verdict,
            summary=summary,
            details=details
        )

    def _explain_content(
        self,
        fusion_result: FusionResult,
        features: Any
    ) -> ComponentExplanation:
        """Explain content analysis"""
        score = fusion_result.content_score
        content = features.content

        details = []

        if content.has_urgency:
            details.append("Aciliyet hissettirme taktikleri")

        if content.has_sms_style:
            details.append("SMS tarzı içerik (kısa, acil)")

        if content.bank_word_count > 3:
            details.append(f"Banka kelimeleri: {content.bank_word_count}")

        if content.cargo_word_count > 2:
            details.append(f"Kargo kelimeleri: {content.cargo_word_count}")

        if content.reward_word_count > 2:
            details.append(f"Ödül/piyango kelimeleri: {content.reward_word_count}")

        if not details:
            details.append("Sosyal mühendislik içeriği yok")

        if content.has_urgency or content.has_sms_style:
            summary = "Sosyal mühendislik içeriği tespit edildi!"
            verdict = "caution"
        elif details:
            summary = "İçerik analizi: Dikkat noktaları mevcut"
            verdict = "caution"
        else:
            summary = "İçerik analizi: Temiz"
            verdict = "safe"

        return ComponentExplanation(
            component="İçerik Analizi",
            score=score,
            max_score=100,
            percentage=score,
            verdict=verdict,
            summary=summary,
            details=details
        )

    def _explain_ml(
        self,
        fusion_result: FusionResult,
        hybrid_result: Any,
        features: Any
    ) -> ComponentExplanation:
        """Explain ML model prediction"""
        if hybrid_result:
            ml_prob = hybrid_result.ml_probability
            ml_conf = hybrid_result.ml_confidence
            score = int(ml_prob * 100)
        else:
            ml_prob = 0.5
            ml_conf = 0.5
            score = 50

        prob_pct = int(ml_prob * 100)
        conf_pct = int(ml_conf * 100)

        if ml_prob > 0.8:
            summary = f"ML: %{prob_pct} phishing şüphesi"
            details = [
                f"Phishing olasılığı: %{prob_pct}",
                f"Model güveni: %{conf_pct}",
                "ML modeli bu kalıbı tanıdı"
            ]
            verdict = "danger"
        elif ml_prob > 0.5:
            summary = f"ML: %{prob_pct} şüpheli"
            details = [
                f"Phishing olasılığı: %{prob_pct}",
                f"Model güveni: %{conf_pct}",
                "Ek analiz önerilir"
            ]
            verdict = "caution"
        else:
            summary = f"ML: %{prob_pct} güvenli"
            details = [
                f"Phishing olasılığı: %{prob_pct}",
                f"Model güveni: %{conf_pct}",
                "ML kalıpları temiz"
            ]
            verdict = "safe"

        return ComponentExplanation(
            component="Makine Öğrenmesi",
            score=score,
            max_score=100,
            percentage=score,
            verdict=verdict,
            summary=summary,
            details=details
        )

    def _calculate_contributions(
        self,
        fusion_result: FusionResult,
        hybrid_result: Any
    ) -> Dict[str, float]:
        """Calculate score contributions from each component"""
        if hybrid_result:
            return {
                "fusion_engine": hybrid_result.fusion_contribution * 100,
                "ml_model": hybrid_result.ml_contribution * 100,
                "threat_intel": fusion_result.threat_score * 0.35,
                "brand": fusion_result.brand_score * 0.25,
                "form": fusion_result.form_score * 0.20,
                "domain": fusion_result.domain_score * 0.10,
                "content": fusion_result.content_score * 0.10,
            }

        return {
            "threat_intel": fusion_result.threat_score * 0.35,
            "brand": fusion_result.brand_score * 0.25,
            "form": fusion_result.form_score * 0.20,
            "domain": fusion_result.domain_score * 0.10,
            "content": fusion_result.content_score * 0.10,
        }

    def _generate_recommended_actions(
        self,
        decision: str,
        risk_level: str,
        features: Any,
        fusion_result: FusionResult
    ) -> List[str]:
        """Generate recommended actions based on findings"""
        actions = []

        if decision == "DANGER" or risk_level == "CRITICAL":
            actions.append("⛔ Bilgilerinizi GİRMEYİN")
            actions.append("⛔ Parola, PIN, kredi kartı bilgisi vermeyin")
            actions.append("💡 Tarayıcıyı KAPATIN")
            actions.append("💡 Orijinal siteyi manuel olarak yazın")
            actions.append("💡 Bankanızı doğrudan arayın")

        if decision == "CAUTION" or risk_level == "HIGH":
            actions.append("🔍 Site adresini kontrol edin")
            actions.append("🔍 URL'nin gerçek markayla eşleştiğini doğrulayın")
            actions.append("💡 Şüphe durumunda işlemi YAPMAYIN")

        if features.threat.matched:
            source = features.threat.source
            actions.append(f"⚠️ Bu site {source} veritabanında kayıtlı!")

        if features.brand.is_impostor:
            brand = features.brand.brand_name or "bilinmeyen"
            actions.append(f"⚠️ '{brand}' taklit ediliyor - orijinal siteyi arayın")

        if features.form.has_external_submit:
            actions.append("⚠️ Form verisi başka birine gönderiliyor!")

        if not actions:
            actions.append("✅ Şu an için özel bir işlem gerekmiyor")
            actions.append("💡 Bilinmeyen linklere dikkatlice tıklayın")

        return actions

    def _identify_red_flags(
        self,
        fusion_result: FusionResult,
        features: Any
    ) -> List[str]:
        """Identify specific red flags"""
        flags = []

        if features.threat.matched:
            flags.append(f"Tehdit veritabanında ({features.threat.source})")

        if features.brand.is_impostor:
            brand = features.brand.brand_name or "bilinmeyen"
            flags.append(f"Marka taklidi: {brand}")

        if features.form.has_external_submit:
            flags.append("Form verisi harici adrese gönderiliyor")

        if features.domain_features.is_new_domain:
            flags.append("Yeni kayıtlı domain")

        if features.domain_features.is_ip_based:
            flags.append("IP adresi kullanılıyor")

        if features.domain_features.is_punycode:
            flags.append("Unicode/Punycode domain")

        if features.form.has_password_field and features.form.has_external_submit:
            flags.append("Parola alanı + harici gönderim")

        if features.content.has_urgency:
            flags.append("Aciliyet hissettirme taktikleri")

        if features.content.has_sms_style:
            flags.append("SMS tarzı içerik - dolandırıcılık belirtisi")

        return flags

    def _extract_factors(
        self,
        fusion_result: FusionResult,
        features: Any
    ) -> Dict[str, Any]:
        """Extract technical factors for debugging"""
        return {
            "threat_score": fusion_result.threat_score,
            "brand_score": fusion_result.brand_score,
            "form_score": fusion_result.form_score,
            "domain_score": fusion_result.domain_score,
            "content_score": fusion_result.content_score,
            "rule_score": fusion_result.rule_score,
            "final_score": fusion_result.final_score,
            "confidence": fusion_result.confidence,
            "indicators": fusion_result.indicators,
            "patterns": fusion_result.threat_patterns,
            "weights": fusion_result.weights,
        }


# Singleton instance
explanation_engine = ExplanationEngine()
