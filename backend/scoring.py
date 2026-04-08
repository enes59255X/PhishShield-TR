def calculate_risk_level(score: int) -> str:
    if score <= 9:
        return "Düşük Risk"
    elif score <= 24:
        return "Orta Risk"
    elif score <= 44:
        return "Yüksek Risk"
    else:
        return "Kritik Risk"

def determine_threat_type(sub_scores: dict, findings: list) -> str:
    """
    Alt skorlar ve bulgulara bakarak baskın tehdit türünü belirle.
    """
    findings_lower = " ".join(findings).lower()
    
    # Sosyal mühendislik baskın mı?
    social_eng_keywords = ["acil", "uyarı", "kazandın", "ücretsiz", "doğrula", "askıya", "son gün", "ödül"]
    social_score = sum(1 for kw in social_eng_keywords if kw in findings_lower)
    
    # Form/veri toplama baskın mı?
    form_keywords = ["şifre", "kart", "cvv", "iban", "e-posta", "telefon", "tc kimlik"]
    form_score = sum(1 for kw in form_keywords if kw in findings_lower)
    
    # Domain taklidi baskın mı?
    domain_keywords = ["taklit", "typo", "benzer", "marka"]
    domain_score = sum(1 for kw in domain_keywords if kw in findings_lower)
    
    # Alt skorlara bak
    url_intel_score = sub_scores.get("url_intel", 0)
    form_analysis_score = sub_scores.get("form_analysis", 0)
    content_analysis_score = sub_scores.get("content_analysis", 0)
    
    # En yüksek risk türünü belirle
    scores = {
        "Kimlik Avı (Phishing)": url_intel_score + domain_score * 10,
        "Sahte Giriş Sayfası": form_analysis_score + form_score * 10,
        "Sosyal Mühendislik": content_analysis_score + social_score * 10,
        "Finansal Dolandırıcılık": form_analysis_score + (10 if "banka" in findings_lower or "kart" in findings_lower else 0),
    }
    
    dominant = max(scores, key=scores.get)
    
    # Eğer hiçbiri belirgin değilse
    if max(scores.values()) == 0:
        return "Genel Şüpheli Site"
    
    return dominant

def combine_scores(sub_scores: dict) -> int:
    """Alt skorları ağırlıklı olarak birleştir, 0-100 arasında döndür."""
    
    # PRIORITY 1: URL Intelligence (Domain analysis) - MOST IMPORTANT
    url_intel = sub_scores.get("url_intel", 0)
    
    # If url_intel is HIGH (fake site detected), use it directly as main score
    if url_intel >= 60:
        return min(100, url_intel + 20)  # Add some for other detections
    
    # If url_intel is very LOW (real safe site), use weighted average
    if url_intel <= 10:
        weights = {
            "url_intel": 0.15,
            "form_analysis": 0.20,
            "content_analysis": 0.20,
            "behavior_analysis": 0.20,
            "js_obfuscation": 0.05,
            "external_scripts": 0.10,
            "ssl_cert": 0.05,
            "screenshot_logo": 0.05,
        }
    else:
        # Normal weighted average for medium risk
        weights = {
            "url_intel": 0.30,
            "form_analysis": 0.20,
            "content_analysis": 0.15,
            "behavior_analysis": 0.15,
            "js_obfuscation": 0.05,
            "external_scripts": 0.10,
            "ssl_cert": 0.02,
            "screenshot_logo": 0.03,
        }
    
    total = 0.0
    for key, weight in weights.items():
        score = sub_scores.get(key, 0)
        total += score * weight
    
    return min(100, int(total))
    
    return min(100, int(total))

def generate_recommendations(risk_level: str, threat_type: str, findings: list) -> list:
    base_recs = []
    
    findings_lower = " ".join(findings).lower()
    
    if risk_level in ("Kritik Risk", "Yüksek Risk"):
        base_recs.append("Bu siteye kişisel bilgi GİRMEYİN.")
        base_recs.append("Sayfayı hemen kapatmanız önerilir.")
    
    if "şifre" in findings_lower or "giriş" in findings_lower:
        base_recs.append("Şifrenizi bu sitede kesinlikle girmeyin.")
    
    if "kart" in findings_lower or "iban" in findings_lower or "finansal" in threat_type.lower():
        base_recs.append("Banka kartı veya finansal bilgilerinizi paylaşmayın.")
        base_recs.append("Gerçek banka sitesine doğrudan tarayıcıdan gidin.")
    
    if "taklit" in findings_lower or "marka" in findings_lower:
        base_recs.append("Bu site tanınan bir markayı taklit ediyor olabilir.")
        base_recs.append("Adres çubuğundaki URL'yi dikkatlice kontrol edin.")
    
    if "sosyal mühendislik" in threat_type.lower() or "acil" in findings_lower:
        base_recs.append("Aciliyet veya ödül vaadi içeren mesajlara şüpheyle yaklaşın.")
    
    if risk_level == "Orta Risk":
        base_recs.append("Siteyi kullanmadan önce URL'yi dikkatlice kontrol edin.")
        base_recs.append("Şüpheli durumlarda ilgili kurum/kuruluşu resmi kanallardan arayın.")
    
    if risk_level == "Düşük Risk":
        base_recs.append("Site düşük riskli görünmektedir, yine de dikkatli olun.")
    
    if not base_recs:
        base_recs.append("Kişisel bilgilerinizi paylaşmadan önce site güvenilirliğini doğrulayın.")
    
    return list(dict.fromkeys(base_recs))  # Tekrarları kaldır
