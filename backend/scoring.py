RISK_THRESHOLDS = {
    "low": 19,
    "medium": 39,
    "high": 69,
    "critical": 100
}

def calculate_risk_level(score: int) -> str:
    if score <= RISK_THRESHOLDS["low"]:
        return "Düşük Risk"
    elif score <= RISK_THRESHOLDS["medium"]:
        return "Orta Risk"
    elif score <= RISK_THRESHOLDS["high"]:
        return "Yüksek Risk"
    else:
        return "Kritik Risk"

def determine_threat_type(sub_scores: dict, findings: list, total_score: int = 0) -> str:
    if total_score <= 19:
        findings_lower = " ".join(findings).lower()
        if "ssl" in findings_lower or "sertifika" in findings_lower:
            return "SSL Uyarısı (Düşük Risk)"
        return "Normal Site"

    if total_score <= 39:
        findings_lower = " ".join(findings).lower()
        if any(kw in findings_lower for kw in ["şifre", "kart", "cvv", "iban"]):
            return "Veri Toplama Formu (Orta Risk)"
        if any(kw in findings_lower for kw in ["ssl", "sertifika", "http"]):
            return "Güvenlik Uyarısı (Orta Risk)"
        return "Şüpheli Özellikler"

    findings_lower = " ".join(findings).lower()

    social_score = sum(1 for kw in ["acil", "uyarı", "kazandın", "ücretsiz", "doğrula", "askıya", "ödül"] if kw in findings_lower)
    form_score = sum(1 for kw in ["şifre", "kart", "cvv", "iban", "e-posta", "telefon", "tc kimlik"] if kw in findings_lower)
    domain_score = sum(1 for kw in ["taklit", "typo", "benzer", "marka", "fake", "sahte"] if kw in findings_lower)

    url_intel = sub_scores.get("url_intel", 0)
    form_analysis = sub_scores.get("form_analysis", 0)
    content_analysis = sub_scores.get("content_analysis", 0)

    scores = {
        "Kimlik Avı (Phishing)": url_intel + domain_score * 10,
        "Sahte Giriş Sayfası": form_analysis + form_score * 10,
        "Sosyal Mühendislik": content_analysis + social_score * 10,
        "Finansal Dolandırıcılık": form_analysis + (10 if "banka" in findings_lower or "kart" in findings_lower else 0),
    }

    dominant = max(scores, key=scores.get)
    if max(scores.values()) == 0:
        return "Şüpheli Site"

    return dominant

def combine_scores(sub_scores: dict) -> int:
    """Alt skorları ağırlıklı olarak birleştir, 0-100 arasında döndür."""

    url_intel = sub_scores.get("url_intel", 0)
    form_analysis = sub_scores.get("form_analysis", 0)
    content_analysis = sub_scores.get("content_analysis", 0)

    if url_intel >= 80:
        return min(100, url_intel)

    weights = {
        "url_intel": 0.30,
        "form_analysis": 0.20,
        "content_analysis": 0.20,
        "behavior_analysis": 0.10,
        "js_obfuscation": 0.05,
        "external_scripts": 0.05,
        "ssl_cert": 0.05,
        "screenshot_logo": 0.05,
    }

    total = 0.0
    for key, weight in weights.items():
        score = sub_scores.get(key, 0)
        total += score * weight

    return min(100, int(total))

def generate_recommendations(risk_level: str, threat_type: str, findings: list) -> list:
    base_recs = []
    
    findings_lower = " ".join(findings).lower()
    
    # Piranntech/Piran Tech taklitleri için özel öneriler
    if "piran" in findings_lower and "tech" in findings_lower:
        base_recs.append("🚨 BU SİTE DOLANDIRICIDIR - ALIŞVERİŞ YAPMAYIN!")
        base_recs.append("💳 Kredi kartı bilgilerinizi kesinlikle girmeyin!")
        base_recs.append("📵 Kargo Direktörü vaadiyle dolandırıcılık yapılıyor!")
        base_recs.append("🔍 İnternette 'piranntech şikayet' araması yapın - yüzlerce şikayet var!")
        base_recs.append("💰 Para tuzağı - Ürün gönderilmiyor!")
        return base_recs  # Piran için diğer önerileri atla
    
    # UYAP/Adalet Bakanlığı taklitleri için özel öneriler
    if "uyap" in findings_lower or "adalet" in findings_lower or "adliye" in findings_lower:
        base_recs.append("🚨 BU SİTE GERÇEK UYAP/ADALET BAKANLIĞI DEĞİL!")
        base_recs.append("Resmi UYAP sitesi: uyap.gov.tr veya uygulama üzerinden erişin.")
        base_recs.append("Hiçbir evrak bilgisi, TC kimlik no veya dava bilgisi GİRMEYİN.")
        base_recs.append("Gerçek UYAP'a ulaşmak için tarayıcıdan uyap.gov.tr yazın.")
    
    if risk_level in ("Kritik Risk", "Yüksek Risk"):
        base_recs.append("Bu siteye kişisel bilgi GİRMEYİN.")
        base_recs.append("Sayfayı hemen kapatmanız önerilir.")
    
    if "şifre" in findings_lower or "giriş" in findings_lower:
        base_recs.append("Şifrenizi bu sitede kesinlikle girmeyin.")
    
    if "kart" in findings_lower or "iban" in findings_lower or "finansal" in threat_type.lower():
        base_recs.append("Banka kartı veya finansal bilgilerinizi paylaşmayın.")
        base_recs.append("Gerçek banka sitesine doğrudan tarayıcıdan gidin.")
    
    if "taklit" in findings_lower or "marka" in findings_lower or "fake" in findings_lower:
        base_recs.append("Bu site tanınan bir markayı taklit ediyor olabilir.")
        base_recs.append("Adres çubuğundaki URL'yi dikkatlice kontrol edin.")
    
    if "sosyal mühendislik" in threat_type.lower() or "acil" in findings_lower:
        base_recs.append("Aciliyet veya ödül vaadi içeren mesajlara şüpheyle yaklaşın.")
    
    if "hükümet" in findings_lower or "gov.tr" in findings_lower:
        base_recs.append("Resmi devlet siteleri .gov.tr ile biter.")
        base_recs.append("Şüpheliyseniz ilgili kurumu resmi telefonlarından arayın.")
    
    if risk_level == "Orta Risk":
        base_recs.append("Siteyi kullanmadan önce URL'yi dikkatlice kontrol edin.")
        base_recs.append("Şüpheli durumlarda ilgili kurum/kuruluşu resmi kanallardan arayın.")
    
    if risk_level == "Düşük Risk":
        base_recs.append("Site düşük riskli görünmektedir, yine de dikkatli olun.")
    
    if not base_recs:
        base_recs.append("Kişisel bilgilerinizi paylaşmadan önce site güvenilirliğini doğrulayın.")
    
    return list(dict.fromkeys(base_recs))  # Tekrarları kaldır
