import re
import requests
from urllib.parse import urlparse
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from utils import sanitize_url, extract_domain, extract_tld
from intel import analyze_domain_intel
from scoring import (
    calculate_risk_level, determine_threat_type,
    combine_scores, generate_recommendations
)

# --- İçerik Analizi ---

SOCIAL_ENG_PATTERNS_TR = [
    r"hesab[ıi]n[ıi]z?\s*(askıya|askiya|donduruldu|engellendi|kapatıldı)",
    r"(acil|hemen|şimdi|son\s*[0-9]+\s*saat|son\s*gün)",
    r"(ödül|odul|para\s*kazand[ıi]n|çekiliş|çekilis|hediye)",
    r"(ücretsiz|bedava|fırsatı\s*kaçırmayın|kampanya)",
    r"(kimliğinizi\s*doğrulayın|kimlik\s*doğrulama|hesabınızı\s*onaylayın)",
    r"(şifrenizi\s*(girin|yenileyin)|parolanızı\s*(girin|sıfırlayın))",
    r"(banka|kredi\s*kartı|iban|tc\s*kimlik)\s*(bilgilerinizi|numaranızı)",
    r"(güncelleme\s*gerekiyor|bilgilerinizi\s*güncelleyin)",
    r"(hesabınız\s*güvende\s*değil|güvenlik\s*uyarısı)",
]

SOCIAL_ENG_PATTERNS_EN = [
    r"your\s+account\s+(has\s+been\s+)?(suspended|blocked|locked|compromised)",
    r"(urgent|immediately|act\s+now|limited\s+time)",
    r"(you\s+have\s+won|congratulations|prize|reward|free\s+gift)",
    r"(verify\s+your\s+(identity|account)|confirm\s+your\s+information)",
    r"(enter\s+your\s+password|update\s+your\s+credentials)",
    r"(credit\s+card|bank\s+account|social\s+security)",
    r"(security\s+alert|your\s+account\s+is\s+not\s+secure)",
]

SENSITIVE_FORM_FIELDS = [
    "password", "passwd", "pwd", "sifre", "şifre", "parola",
    "card", "kart", "cardnumber", "ccnumber", "cvv", "cvc",
    "email", "mail", "eposta", "e-posta",
    "phone", "telefon", "tel", "gsm",
    "iban", "bic", "swift",
    "tc", "tckimlik", "kimlik", "identity", "ssn",
    "username", "kullanici", "kullanıcı",
    "pin", "otp", "verification",
]

def fetch_page_content(url: str) -> tuple[str, dict]:
    """Sayfanın HTML içeriğini indir. (timeout ile)"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishShieldBot/1.0"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=7, allow_redirects=True, verify=False)
        final_url = resp.url
        content = resp.text
        return content, {"final_url": final_url, "status_code": resp.status_code}
    except requests.exceptions.SSLError:
        return "", {"error": "SSL hatası - geçersiz sertifika", "ssl_error": True}
    except requests.exceptions.ConnectionError:
        return "", {"error": "Bağlantı kurulamadı"}
    except requests.exceptions.Timeout:
        return "", {"error": "Zaman aşımı"}
    except Exception as e:
        return "", {"error": str(e)}

def analyze_forms(html: str) -> dict:
    """HTML içindeki form alanlarını analiz et."""
    findings = []
    score = 0
    
    if not html:
        return {"score": 0, "findings": []}
    
    html_lower = html.lower()
    
    found_fields = []
    for field in SENSITIVE_FORM_FIELDS:
        pattern = rf'(name|id|type)\s*=\s*["\']?{re.escape(field)}["\']?'
        if re.search(pattern, html_lower):
            found_fields.append(field)
    
    if found_fields:
        score += min(len(found_fields) * 10, 40)
        findings.append(f"Hassas form alanları tespit edildi: {', '.join(found_fields[:6])}")
    
    # Action'ı farklı domain'e gönderen form
    action_pattern = re.findall(r'action\s*=\s*["\']([^"\']+)["\']', html_lower)
    for action in action_pattern:
        if action.startswith("http") and not action.startswith("javascript"):
            score += 15
            findings.append(f"Form verisi dış adrese gönderiliyor: {action[:60]}")
            break
    
    # Password alanı var mı?
    if 'type="password"' in html_lower or "type='password'" in html_lower:
        score += 10
        findings.append("Şifre giriş alanı tespit edildi")
    
    # Fake e-commerce form detection
    fake_ecommerce_patterns = [
        (r'ad.*soyad.*telefon', "E-ticaret kişisel bilgi formu"),
        (r'adres.*kargo.*bilgileri', "E-ticaret adres formu"),
        (r'kart.*bilgileri.*cvv', "Kart bilgileri formu"),
        (r'iban.*hesap.*numarası', "Banka hesap bilgileri formu"),
        (r'tc.*kimlik.*doğum', "TC kimlik bilgileri formu"),
    ]
    
    for pattern, msg in fake_ecommerce_patterns:
        if re.search(pattern, html_lower):
            score += 20
            findings.append(f"ŞÜPHELİ E-TİCARET FORMU! {msg}")
    
    return {"score": min(score, 100), "findings": findings}

def analyze_content(html: str) -> dict:
    """Sosyal mühendislik içeriklerini analiz et."""
    findings = []
    score = 0
    
    if not html:
        return {"score": 0, "findings": []}
    
    html_text = re.sub(r'<[^>]+>', ' ', html)
    html_lower = html_text.lower()
    
    # Brand impersonation detection
    brand_patterns = [
        (r'piran.*tech', "Piran teknoloji markası taklidi"),
        (r'pirantek', "PiranTek markası taklidi"),
        (r'tekno.*piran', "Teknoloji piran markası taklidi"),
        (r'piran.*shop', "Piran shop markası taklidi"),
        (r'piran.*store', "Piran store markası taklidi"),
        (r'piran.*market', "Piran market markası taklidi"),
        (r'piran.*pazar', "Piran pazar markası taklidi"),
        (r'piran.*urun', "Piran ürün markası taklidi"),
        (r'piran.*kutu', "Piran kutu markası taklidi"),
        (r'piran.*servis', "Piran servis markası taklidi"),
    ]
    
    for pattern, msg in brand_patterns:
        if re.search(pattern, html_lower):
            score += 35
            findings.append(f"🚨 MARKA TAKLİDİ! {msg}")
            break
    
    # Fake site indicators
    fake_indicators = [
        (r'vakum.*çalış.*makinesi', "Vakum makinesi satışı taklidi"),
        (r'vakum.*cleaner', "Vakum cleaner taklidi"),
        (r'indirim.*%.*90', "Abartılı indirim (%90+)") ,
        (r'bedava.*kargo.*hepsi', "Şüpheli bedava kargo vaadi"),
        (r'son.*gün.*fırsat', "Aciliyet baskısı"),
        (r'son.*24.*saat', "24 saat aciliyet baskısı"),
        (r'kargo.*bedava.*her.*ürün', "Şüpheli kargo vaadi"),
        (r'kapıda.*ödeme.*tüm*', "Şüpheli kapıda ödeme vaadi"),
        (r'garanti.*2.*yıl', "Abartılı garanti vaadi"),
        (r'orijinal.*ürün.*garanti', "Şüpheli orijinallik vaadi"),
    ]
    
    for pattern, msg in fake_indicators:
        if re.search(pattern, html_lower):
            score += 25
            findings.append(f"ŞÜPHELİ İÇERİK! {msg}")
    
    # Contact information analysis
    contact_patterns = [
        (r'0555.*\d{7}', "Şüpheli telefon numarası formatı"),
        (r'0\d{3}.*111.*222', "Şüpheli telefon numarası"),
        (r'[a-zA-Z0-9._%+-]+@gmail\.com.*destek', "Gmail destek adresi"),
        (r'[a-zA-Z0-9._%+-]+@hotmail\.com.*müşteri', "Hotmail müşteri hizmetleri"),
        (r'whatsapp.*\d{10,}', "WhatsApp iletişim zorunluluğu"),
    ]
    
    for pattern, msg in contact_patterns:
        if re.search(pattern, html_lower):
            score += 15
            findings.append(f"Şüpheli iletişim bilgisi: {msg}")
    
    # Türkçe pattern'lar
    for pattern in SOCIAL_ENG_PATTERNS_TR:
        match = re.search(pattern, html_lower)
        if match:
            score += 12
            findings.append(f"Sosyal mühendislik metni: '...{html_lower[max(0,match.start()-10):match.end()+10].strip()}...'")
    
    # İngilizce pattern'lar (uluslararası phishing için)
    for pattern in SOCIAL_ENG_PATTERNS_EN:
        match = re.search(pattern, html_lower)
        if match:
            score += 8
            findings.append(f"Şüpheli İngilizce metin tespit edildi")
            break  # Birini bulduysa yeter
    
    return {"score": min(score, 100), "findings": findings}

def analyze_behavior(html: str, fetch_meta: dict) -> dict:
    """Yönlendirme ve davranış analizi."""
    findings = []
    score = 0
    
    if not html:
        # Sayfa yüklenemedi ama URL açıktı
        if fetch_meta.get("ssl_error"):
            score += 20
            findings.append("SSL sertifikası geçersiz veya yok (HTTPS şifrelemesi güvenilmez)")
        return {"score": score, "findings": findings}
    
    html_lower = html.lower()
    
    # Meta refresh yönlendirme
    if re.search(r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\']', html_lower):
        score += 15
        findings.append("Meta refresh yönlendirme tespit edildi")
    
    # JS yönlendirme
    if re.search(r'window\.(location|href)\s*=', html_lower):
        score += 10
        findings.append("JavaScript yönlendirme davranışı tespit edildi")
    
    # SSL hatası
    if fetch_meta.get("ssl_error"):
        score += 20
        findings.append("SSL sertifikası hatası - bağlantı güvenli değil")
    
    # Final URL farklı mı? (yönlendirme)
    # Bu URL'i caller'da karşılaştırır
    
    # iframe kullanımı
    if "<iframe" in html_lower:
        score += 8
        findings.append("Gizli iframe(s) tespit edildi")
    
    # Disable right-click
    if "contextmenu" in html_lower and "preventdefault" in html_lower:
        score += 5
        findings.append("Sağ tık engelleme tespit edildi")
    
    return {"score": min(score, 100), "findings": findings}


def analyze_js_obfuscation(html: str) -> dict:
    """JavaScript obfuscation tespiti."""
    findings = []
    score = 0
    
    if not html:
        return {"score": 0, "findings": []}
    
    html_lower = html.lower()
    
    patterns = [
        (r'eval\s*\(', "eval() fonksiyonu tespit edildi"),
        (r'atob\s*\(', "atob() fonksiyonu tespit edildi"),
        (r'String\.fromCharCode', "String.fromCharCode encoding tespit edildi"),
        (r'uneval\s*\(', "uneval() fonksiyonu tespit edildi"),
        (r'decodeURIComponent\s*\(', "decodeURIComponent tespit edildi"),
        (r'document\.write\s*\(', "document.write kullanımı tespit edildi"),
        (r'setTimeout\s*\(\s*["\']', "setTimeout ile dinamik kod çalıştırma"),
    ]
    
    for pattern, msg in patterns:
        if re.search(pattern, html_lower):
            score += 10
            findings.append(msg)
    
    return {"score": min(score, 70), "findings": findings}

def analyze_external_scripts(html: str) -> dict:
    """Harici script kaynaklarını analiz et."""
    findings = []
    score = 0
    
    if not html:
        return {"score": 0, "findings": []}
    
    html_lower = html.lower()
    
    script_pattern = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_lower)
    external_pattern = re.findall(r'<script[^>]+src=["\'](https?://[^"\']+)["\']', html_lower)
    
    if len(script_pattern) > 3:
        score += 5
        findings.append(f"Çok sayıda script (>3) tespit edildi")
    
    for src in external_pattern[:5]:
        score += 10
        findings.append(f"Harici script: {src[:60]}")
    
    if external_pattern:
        score += min(len(external_pattern) * 10, 30)
    
    return {"score": min(score, 70), "findings": findings}

def analyze_screenshot(url: str) -> dict:
    """Screenshot ve logo analizi (stub - gerçek görsel işleme için harici API gerekli)."""
    findings = []
    score = 0
    
    parsed = urlparse(url)
    domain = parsed.netloc or ""
    
    known_logos = {
        "google": ["google", "gstatic"],
        "facebook": ["facebook", "fbcdn"],
        "microsoft": ["microsoft", "windows"],
        "apple": ["apple", "icloud"],
        "amazon": ["amazon", "aws"],
        "garanti": ["garanti", "garantibbva"],
        "akbank": ["akbank"],
        "ziraat": ["ziraat", "ziraatbank"],
        "isbank": ["isbank", "isnet"],
    }
    
    for brand, keywords in known_logos.items():
        if any(kw in domain.lower() for kw in keywords):
            findings.append(f"{brand} logosu tespit edildi (marka eşleşmesi)")
            score += 5
            break
    
    if not findings:
        findings.append("Bilinir marka logosu tespit edilmedi")
    
    return {"score": min(score, 30), "findings": findings}

def analyze_ssl_cert(url: str) -> dict:
    """SSL sertifika detay analizi."""
    findings = []
    score = 0
    
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"score": 0, "findings": []}
    
    try:
        import ssl
        import socket
        
        hostname = parsed.hostname
        port = parsed.port or 443
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                
                if "issue" in issuer.get("organizationName", "").lower() or "issue" in subject.get("commonName", "").lower():
                    score += 25
                    findings.append(f"SSL issuer: {issuer.get('organizationName', 'Bilinmiyor')}")
                
                if not_before and not_after:
                    from datetime import datetime
                    try:
                        not_before_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                        not_after_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (not_after_dt - datetime.now()).days
                        if days_left < 30:
                            score += 15
                            findings.append(f"SSL sertifikası {days_left} gün içinde süresi doluyor")
                    except:
                        pass
    except Exception as e:
        findings.append(f"SSL analizi yapılamadı: {str(e)}")
    
    return {"score": min(score, 50), "findings": findings}

def analyze_url(url: str) -> dict:
    """Ana analiz fonksiyonu."""
    
    is_safe, normalized_url, error = sanitize_url(url)
    
    if not is_safe:
        return {
            "url": url,
            "score": 0,
            "risk_level": "Analiz Edilemedi",
            "threat_type": "Bilinmiyor",
            "reasons": [error],
            "recommendations": ["Geçerli bir URL girin."],
            "sub_scores": {}
        }
    
    domain = extract_domain(normalized_url)
    all_findings = []
    sub_scores = {}
    
    # 1. URL & Domain Intelligence
    intel_result = analyze_domain_intel(normalized_url, domain)
    sub_scores["url_intel"] = intel_result["score"]
    all_findings.extend(intel_result["findings"])
    
    # 2. Sayfa içeriğini çek
    html, fetch_meta = fetch_page_content(normalized_url)
    
    # 3. Form Analizi
    form_result = analyze_forms(html)
    sub_scores["form_analysis"] = form_result["score"]
    all_findings.extend(form_result["findings"])
    
    # 4. İçerik Analizi
    content_result = analyze_content(html)
    sub_scores["content_analysis"] = content_result["score"]
    all_findings.extend(content_result["findings"])
    
    # 5. Davranış Analizi
    behavior_result = analyze_behavior(html, fetch_meta)
    sub_scores["behavior_analysis"] = behavior_result["score"]
    all_findings.extend(behavior_result["findings"])
    
    # 6. JavaScript Obfuscation Analizi
    js_obf_result = analyze_js_obfuscation(html)
    sub_scores["js_obfuscation"] = js_obf_result["score"]
    all_findings.extend(js_obf_result["findings"])
    
    # 7. Harici Script Analizi
    ext_script_result = analyze_external_scripts(html)
    sub_scores["external_scripts"] = ext_script_result["score"]
    all_findings.extend(ext_script_result["findings"])
    
    # 8. SSL Sertifika Analizi
    ssl_result = analyze_ssl_cert(normalized_url)
    sub_scores["ssl_cert"] = ssl_result["score"]
    all_findings.extend(ssl_result["findings"])
    
    # 9. Screenshot/Logo Analizi
    screenshot_result = analyze_screenshot(normalized_url)
    sub_scores["screenshot_logo"] = screenshot_result["score"]
    all_findings.extend(screenshot_result["findings"])
    
    # Toplam skor
    total_score = combine_scores(sub_scores)
    
    # Risk seviyesi
    risk_level = calculate_risk_level(total_score)
    
    # Tehdit türü
    threat_type = determine_threat_type(sub_scores, all_findings)
    
    # Öneriler
    recommendations = generate_recommendations(risk_level, threat_type, all_findings)
    
    # Bulgular boşsa güvenli mesajı ver
    if not all_findings:
        all_findings = ["Belirgin bir şüpheli özellik tespit edilmedi."]
    
    return {
        "url": normalized_url,
        "score": total_score,
        "risk_level": risk_level,
        "threat_type": threat_type,
        "reasons": all_findings,
        "recommendations": recommendations,
        "sub_scores": {
            "url_domain_analizi": sub_scores.get("url_intel", 0),
            "form_analizi": sub_scores.get("form_analysis", 0),
            "icerik_analizi": sub_scores.get("content_analysis", 0),
            "davranis_analizi": sub_scores.get("behavior_analysis", 0),
            "js_obfuscation": sub_scores.get("js_obfuscation", 0),
            "external_scripts": sub_scores.get("external_scripts", 0),
            "ssl_cert": sub_scores.get("ssl_cert", 0),
            "screenshot_logo": sub_scores.get("screenshot_logo", 0),
        }
    }
