import re
from difflib import SequenceMatcher
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".link", ".gq", ".tk", ".ml", ".cf", ".ga",
    ".pw", ".ru", ".cn", ".su", ".cc", ".to", ".ws", ".biz", ".info",
    ".online", ".site", ".website", ".space", ".fun", ".icu", ".rest",
    ".org", ".net", ".club", ".tech", ".live"
]

# Known FAKE sites - MAXIMUM SCORE
KNOWN_FAKE_SITES = [
    "cimeruzlasma", "cimerxyz", "cimernet", "cimergir", "cimerportal",
    "edevletgir", "edevletz", "edevletpro", "garantigiris", "garantioyna",
    "isbankgir", "isbanksifre", "akbankgir", "ziraatgir", "hambankgir", 
    "parayatir", "paparaoyna", "paparaoyun", "tinkoyun", "trendyolgift",
    "piranntech", "pirantech", "piran-tech", "pirantec", "piranntech",
    "teknopiran", "pirantechno", "piranservis", "piranshop", "piranstore",
    "teknopirant", "pirankutu", "piranpazar", "piranmarket", "piranurun"
]

# REAL SAFE government domains - EXCEPTIONS
KNOWN_GOV_DOMAINS = [
    "cimer.gov.tr", "turkiye.gov.tr", "gov.tr", "basbakanlik.gov.tr",
    "sgk.gov.tr", "gelirler.gov.tr", "vergidairesi.gov.tr",
    "tcmb.gov.tr", "mb.gov.tr", "btk.gov.tr"
]

# Official company domains - TRUSTED
KNOWN_OFFICIAL_DOMAINS = [
    "google.com", "google.com.tr", "facebook.com", "instagram.com", 
    "twitter.com", "x.com", "youtube.com", "amazon.com", "amazon.com.tr",
    "microsoft.com", "apple.com", "paypal.com", "netflix.com",
    "linkedin.com", "whatsapp.com", "telegram.org", "tiktok.com",
    "akbank.com", "ziraatbank.com.tr", "garantibbva.com.tr", "isbank.com.tr",
    "vakifbank.com.tr", "halkbank.com.tr", "enpara.com", "papara.com",
    "yapikredi.com.tr", "denizbank.com", "ingbank.com.tr", "turkcell.com.tr",
    "vodafone.com.tr", "turktelekom.com.tr", "ttnet.com.tr", "trendyol.com",
    "hepsiburada.com", "n11.com", "gittigidiyor.com", "ciceksepeti.com",
    "sahibinden.com", "yemeksepeti.com", "getir.com", "migros.com.tr",
    "a101.com.tr", "bim.com.tr", "sokmarket.com.tr", "araskargo.com.tr",
    "yurticikargo.com", "ptt.gov.tr", "pttavm.com"
]

# Government impersonation keywords (only flagged if NOT in safe domains)
GOVERNMENT_IMPERSONATION = [
    "cimer", "e-devlet", "edevlet", "gib", "gelir", "vergidairesi",
    "sgk", "turkiye", "türkiye", "adliye", "mahkeme",
    "polis", "jandarma", "askeri", "savci", "cumhuriyet",
    "basbakanlik", "tcmb", "ch", "cati"
]

TRUSTED_BRANDS = [
    "google", "facebook", "instagram", "twitter", "youtube", "amazon",
    "microsoft", "apple", "paypal", "netflix", "linkedin", "whatsapp",
    "telegram", "tiktok", "ebay", "alibaba", "dropbox", "github",
    "akbank", "ziraat", "garanti", "isbank", "vakifbank", "halkbank",
    "enpara", "papara", "ykb", "yapi", "denizbank", "ing",
    "turkcell", "vodafone", "turktekom", "ttnet", "superonline",
    "edevlet", "turkiye", "btk", "ptt", "trendyol", "hepsiburada",
    "n11", "gittigidiyor", "ciceksepeti", "sahibinden", "yemeksepeti",
    "getir", "migros", "a101", "bim", "sok", "kargo", "aras", "yurtici",
    # Turkish government sites
    "cimer", "basbakanlik", "tcmb", "sgk", "gelirsler", "vergidairesi",
    "e-sgk", "turkiye.gov", "gov.tr", "cati", "ch", "cumhuriyet"
]

SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "secure", "verify", "account", "update", "confirm",
    "banking", "payment", "invoice", "billing", "support", "help", "free",
    "bonus", "prize", "win", "reward", "click", "urgent", "suspend",
    "giris", "giriş", "hesap", "dogrula", "doğrula", "güncelle", "guncelle",
    "odeme", "ödeme", "güvenli", "guvenli", "destek", "ücretsiz", "ucretsiz",
    "kazandin", "kazandınız", "ödül", "odul", "acil", "askiya", "askıya",
    "banka", "kredi", "kargo", "fatura", "iban", "şifre", "sifre"
]

def check_suspicious_tld(domain: str) -> tuple[bool, str]:
    domain_lower = domain.lower()
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return True, f"Şüpheli TLD tespit edildi: {tld}"
    return False, ""

def check_typosquatting(domain: str) -> tuple[bool, list]:
    findings = []
    domain_lower = domain.lower()
    parts = domain_lower.split(".")
    domain_core = parts[0] if len(parts) > 0 else domain_lower
    
    for brand in TRUSTED_BRANDS:
        if brand in domain_lower and brand != domain_core:
            findings.append(f"'{brand}' markasını taklit edebilir")
            continue
        
        ratio = SequenceMatcher(None, domain_core, brand).ratio()
        if 0.75 <= ratio < 1.0 and len(brand) > 4:
            findings.append(f"'{brand}' markasına benzer domain: {domain_core}")
    
    return len(findings) > 0, findings

def check_suspicious_url_keywords(url: str) -> list:
    url_lower = url.lower()
    found = []
    for kw in SUSPICIOUS_URL_KEYWORDS:
        if kw in url_lower:
            found.append(kw)
    return found

def check_ip_in_url(url: str) -> bool:
    ip_pattern = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}')
    return bool(ip_pattern.match(url))

def check_at_symbol(url: str) -> bool:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return "@" in (parsed.netloc or "")

def check_multiple_subdomains(domain: str) -> tuple[bool, int]:
    parts = domain.split(".")
    subdomain_count = len(parts) - 2
    return subdomain_count > 2, subdomain_count

def check_url_length(url: str) -> tuple[bool, int]:
    length = len(url)
    return length > 100, length

def check_domain_hyphens(domain: str) -> tuple[bool, int]:
    parts = domain.split(".")
    main = parts[0] if parts else domain
    count = main.count("-")
    return count > 2, count

def check_encoded_chars(url: str) -> bool:
    return url.count("%") > 3

def analyze_domain_intel(url: str, domain: str) -> dict:
    results = {"score": 0, "findings": []}
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    # 1. CHECK OFFICIAL DOMAINS FIRST - PRIORITY 1
    is_official = False
    for official in KNOWN_OFFICIAL_DOMAINS:
        if domain_lower == official or domain_lower.endswith('.' + official):
            results["score"] = 0
            results["findings"] = ["✅ Resmi şirket sitesi - GÜVENLİ"]
            is_official = True
            break
    
    if is_official:
        return results
    
    # 2. CHECK KNOWN FAKE SITES FIRST - CRITICAL PRIORITY
    # This MUST be checked BEFORE anything else
    found_fake = False
    for fake in KNOWN_FAKE_SITES:
        if fake in url_lower:
            results["score"] += 80  # MAXIMUM score for known fake
            results["findings"].append(f"🚨 CRITICAL! Bilinen DOLANDIRICI sitesi: {fake}")
            found_fake = True
            break
    
    # If fake site found, skip ALL other checks
    if found_fake:
        # Still run other checks but don't reduce score
        is_sus_tld, tld_msg = check_suspicious_tld(domain)
        if is_sus_tld:
            results["score"] += 15
            results["findings"].append(tld_msg)
        sus_kws = check_suspicious_url_keywords(url)
        if sus_kws:
            results["score"] += min(len(sus_kws) * 5, 20)
            results["findings"].append(f"Şüpheli URL: {', '.join(sus_kws[:5])}")
        return results
    
    # 2. Check REAL SAFE government domains (MUST match exact .gov.tr)
    is_safe_gov = False
    for safe_domain in KNOWN_GOV_DOMAINS:
        if domain_lower == safe_domain or domain_lower.endswith('.' + safe_domain):
            is_safe_gov = True
            break
    
    if is_safe_gov:
        results["score"] = 0
        results["findings"] = ["✅ Resmi gov.tr sitesi - GÜVENLİ"]
        return results
    
    # 3. Advanced fake site pattern detection
    fake_patterns = [
        (r'pira.*tech', "Piran teknoloji taklidi"),
        (r'tekno.*pira', "Teknoloji piran taklidi"),
        (r'.*shop.*tech', "Shop teknoloji taklidi"),
        (r'.*store.*tech', "Store teknoloji taklidi"),
        (r'.*market.*tech', "Market teknoloji taklidi"),
        (r'.*pazar.*tech', "Pazar teknoloji taklidi"),
        (r'.*urun.*tech', "Ürün teknoloji taklidi"),
        (r'.*kutu.*tech', "Kutu teknoloji taklidi"),
        (r'.*servis.*tech', "Servis teknoloji taklidi"),
    ]
    
    for pattern, msg in fake_patterns:
        if re.search(pattern, domain_lower):
            results["score"] += 50
            results["findings"].append(f"🚨 TEHLİKELİ! {msg}")
            break
    
    # 4. Government impersonation check (fake government sites)
    for kw in GOVERNMENT_IMPERSONATION:
        if kw in url_lower:
            results["score"] += 60
            results["findings"].append(f"🚨 TEHLİKELİ! Hükümet taklidi: {kw}")
    
    # 4. Suspicious TLD
    is_sus_tld, tld_msg = check_suspicious_tld(domain)
    if is_sus_tld:
        results["score"] += 20
        results["findings"].append(tld_msg)
    
    is_typo, typo_msgs = check_typosquatting(domain)
    if is_typo:
        results["score"] += 25
        results["findings"].extend(typo_msgs)
    
    if check_ip_in_url(url):
        results["score"] += 20
        results["findings"].append("URL'de IP adresi kullanılmış")
    
    if check_at_symbol(url):
        results["score"] += 20
        results["findings"].append("URL'de @ sembolü tespit edildi")
    
    too_many_sub, sub_count = check_multiple_subdomains(domain)
    if too_many_sub:
        results["score"] += 10
        results["findings"].append(f"Anormal sayıda subdomain: {sub_count}")
    
    too_long, url_len = check_url_length(url)
    if too_long:
        results["score"] += 5
        results["findings"].append(f"Çok uzun URL: {url_len}")
    
    too_many_hyphens, hyphen_count = check_domain_hyphens(domain)
    if too_many_hyphens:
        results["score"] += 5
        results["findings"].append(f"Domain'de fazla tire: {hyphen_count}")
    
    if check_encoded_chars(url):
        results["score"] += 5
        results["findings"].append("URL'de fazla encoded karakter")
    
    sus_kws = check_suspicious_url_keywords(url)
    if sus_kws:
        results["score"] += min(len(sus_kws) * 5, 20)
        results["findings"].append(f"Şüpheli URL anahtar kelimeleri: {', '.join(sus_kws[:5])}")
    
    return results