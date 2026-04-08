import asyncio
import json
from core.features import extract_features_async, fetch_page_async
from core.ml_manager import ml_manager
from core.intel_manager import intel_manager

async def analyze_url_full(url: str) -> dict:
    from db.database import is_whitelisted
    from urllib.parse import urlparse
    
    # --- 0. WHITELIST CHECK (Priority) ---
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if await is_whitelisted(domain):
        return {
            "url": url,
            "score": 0,
            "risk_level": "Güvenli (Resmi Kurum)",
            "threat_type": "Doğrulanmış Resmi Site",
            "reasons": ["Bu site resmi bir devlet kurumu veya doğrulanmış güvenli bir kuruluştur."],
            "recommendations": ["Resmi kanalları kullanmaya devam edebilirsiniz."],
            "sub_scores": {"ml_prediction": 0, "rule_base": 0, "intel": 0}
        }

    all_findings = []
    sub_scores = {}
    
    # 1. Threat Intel Check (Instant)
    intel_res = await intel_manager.check_url_intel(url)
    if intel_res["found"]:
        return {
            "url": url,
            "score": 100,
            "risk_level": "Kritik Risk",
            "threat_type": "Bilinen Phishing (Blacklist)",
            "reasons": ["Sistem veritabanında bilinen zararlı URL olarak kayıtlı."],
            "recommendations": ["Bu siteyi derhal kapatın.", "Hiçbir bilgi girmeyin."],
            "sub_scores": {"intel": 100}
        }

    # 2. Fetch Content
    html, meta = await fetch_page_async(url)
    if meta.get("error"):
        all_findings.append(f"Siteye erişilemedi: {meta['error']}")
    
    # 3. Extract Features
    features = await extract_features_async(url, html)
    
    # 4. ML Prediction
    ml_score_prob = await ml_manager.predict_async(features)
    ml_score = int(ml_score_prob * 100)
    
    # 5. Hybrid Scoring Strategy
    # Final Score = 0.5 * ML + 0.3 * Rule Engine + 0.2 * Threat Intel
    # Since we are here, Threat Intel was 0.
    
    # Simple Rule Engine components for demonstration
    rule_score = 0
    if features.get("password_input"):
        rule_score += 40
        all_findings.append("Şifre giriş alanı tespit edildi.")
    if features.get("external_form"):
        rule_score += 30
        all_findings.append("Veriler harici bir adrese gönderiliyor.")
    if features.get("url_length", 0) > 80:
        rule_score += 10
        all_findings.append("Anormal derecede uzun URL.")
    
    final_score = int((0.7 * ml_score) + (0.3 * min(100, rule_score)))
    
    # Risk Level
    risk_level = "Düşük Risk"
    if final_score >= 80: risk_level = "Kritik Risk"
    elif final_score >= 50: risk_level = "Yüksek Risk"
    elif final_score >= 20: risk_level = "Orta Risk"

    # Recommendations
    recommendations = ["URL'yi dikkatlice kontrol edin."]
    if final_score >= 20:
        recommendations.append("Kişisel bilgilerinizi girmeden önce iki kez düşünün.")
    if final_score >= 50:
        recommendations.append("Resmi kanallar üzerinden doğrulama yapın.")
        recommendations.append("Bu siteye güvenmeyin.")

    return {
        "url": url,
        "score": final_score,
        "risk_level": risk_level,
        "threat_type": "Phishing Analizi" if final_score > 20 else "Güvenli Analiz",
        "reasons": all_findings if all_findings else ["Belirgin bir şüpheli özellik tespit edilmedi."],
        "recommendations": recommendations,
        "sub_scores": {
            "ml_prediction": ml_score,
            "rule_base": rule_score
        },
        "features_json": json.dumps(features)
    }
