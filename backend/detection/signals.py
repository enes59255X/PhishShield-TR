"""
PhishShield TR - Signal Severity Definitions
Signals are categorized by their severity and threat weight
"""

from enum import Enum

class SignalSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class ThreatCategory(Enum):
    BANKING = "BANKING"
    CARGO = "CARGO"
    ECOMMERCE = "ECOMMERCE"
    EGOV = "EGOV"
    GOVERNMENT = "GOVERNMENT"
    TELECOM = "TELECOM"
    CRYPTO = "CRYPTO"
    SOCIAL_MEDIA = "SOCIAL_MEDIA"
    JOB_SCAM = "JOB_SCAM"
    INVESTMENT = "INVESTMENT"
    LOTTERY = "LOTTERY"
    REFUND = "REFUND"
    TAX = "TAX"
    LEGAL = "LEGAL"
    GENERAL = "GENERAL"

SIGNAL_DEFINITIONS = {
    # CRITICAL SIGNALS (+80 points)
    "threat_intel_match": {
        "severity": SignalSeverity.CRITICAL,
        "weight": 100,
        "category": ThreatCategory.GENERAL,
        "description": "Tehdit istihbarat veritabaninda eslesme",
        "auto_decision": "DANGER",
        "threat_intel_bonus": {
            "usom": 40,
            "openphish": 35,
            "urlhaus": 25
        }
    },
    "usom_listed": {
        "severity": SignalSeverity.CRITICAL,
        "weight": 100,
        "category": ThreatCategory.GENERAL,
        "description": "USOM tarafindan engellenmis domain",
        "auto_decision": "DANGER"
    },
    "known_phishing_domain": {
        "severity": SignalSeverity.CRITICAL,
        "weight": 100,
        "category": ThreatCategory.GENERAL,
        "description": "Bilinen phishing domain",
        "auto_decision": "DANGER"
    },
    "bank_impostor_with_mismatch": {
        "severity": SignalSeverity.CRITICAL,
        "weight": 95,
        "category": ThreatCategory.BANKING,
        "description": "Banka taklidi + domain uyusmazligi",
        "requires": ["brand_impostor", "domain_mismatch"]
    },
    "egov_impostor_with_credential_request": {
        "severity": SignalSeverity.CRITICAL,
        "weight": 95,
        "category": ThreatCategory.EGOV,
        "description": "e-Devlet/UYAP taklidi + kimlik bilgisi talebi",
        "requires": ["gov_impostor", "credential_form"]
    },
    "credential_harvesting_external_post": {
        "severity": SignalSeverity.CRITICAL,
        "weight": 90,
        "category": ThreatCategory.GENERAL,
        "description": "Form verisi harici domaine gonderiliyor",
        "requires": ["has_login_form", "external_post_action"]
    },
    
    # Sprint 5: Form Behavior Signals
    "credential_harvesting_external": {
        "severity": SignalSeverity.CRITICAL,
        "weight": 95,
        "category": ThreatCategory.GENERAL,
        "description": "Kimlik bilgileri harici adrese gonderiliyor",
        "auto_decision": "DANGER"
    },
    "payment_fields": {
        "severity": SignalSeverity.CRITICAL,
        "weight": 45,
        "category": ThreatCategory.GENERAL,
        "description": "Odeme form alanlari tespit edildi"
    },
    "hidden_form_fields": {
        "severity": SignalSeverity.HIGH,
        "weight": 30,
        "category": ThreatCategory.GENERAL,
        "description": "Gizli form alanlari bulundu (skimmer olabilir)"
    },
    "autocomplete_disabled": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 15,
        "category": ThreatCategory.GENERAL,
        "description": "Formda autocomplete kapatilmis"
    },
    "login_form_detected": {
        "severity": SignalSeverity.HIGH,
        "weight": 30,
        "category": ThreatCategory.GENERAL,
        "description": "Giris formu tespit edildi"
    },
    "credential_fields": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 20,
        "category": ThreatCategory.GENERAL,
        "description": "Kimlik bilgi alanlari tespit edildi"
    },
    
    # Sprint 5: Brand Impersonation Signals
    "brand_impostor": {
        "severity": SignalSeverity.HIGH,
        "weight": 50,
        "category": ThreatCategory.GENERAL,
        "description": "Marka/organizasyon taklidi tespit edildi"
    },
    "bank_brand_match": {
        "severity": SignalSeverity.CRITICAL,
        "weight": 55,
        "category": ThreatCategory.BANKING,
        "description": "Banka markasi taklidi tespit edildi",
        "auto_decision": "DANGER"
    },
    "gov_brand_match": {
        "severity": SignalSeverity.CRITICAL,
        "weight": 60,
        "category": ThreatCategory.GOVERNMENT,
        "description": "Devlet/kurum markasi taklidi tespit edildi",
        "auto_decision": "DANGER"
    },
    "ecommerce_brand_match": {
        "severity": SignalSeverity.HIGH,
        "weight": 40,
        "category": ThreatCategory.ECOMMERCE,
        "description": "E-ticaret markasi taklidi tespit edildi"
    },
    "cargo_brand_match": {
        "severity": SignalSeverity.HIGH,
        "weight": 40,
        "category": ThreatCategory.CARGO,
        "description": "Kargo firma taklidi tespit edildi"
    },
    "fake_login_page": {
        "severity": SignalSeverity.HIGH,
        "weight": 45,
        "category": ThreatCategory.GENERAL,
        "description": "Sashte giris sayfasi tespit edildi"
    },
    
    # Sprint 5: Domain Intelligence Signals
    "new_domain": {
        "severity": SignalSeverity.HIGH,
        "weight": 35,
        "category": ThreatCategory.GENERAL,
        "description": "Yeni kayitli domain (< 30 gun)"
    },
    "recent_domain": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 15,
        "category": ThreatCategory.GENERAL,
        "description": "Yeni saylabilecek domain (< 90 gun)"
    },
    "domain_age_anomaly": {
        "severity": SignalSeverity.HIGH,
        "weight": 25,
        "category": ThreatCategory.GENERAL,
        "description": "Domain yasi suphe verici"
    },
    
    # Sprint 5: Content/Behavior Signals
    "urgency_text": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 15,
        "category": ThreatCategory.GENERAL,
        "description": "Acele/tedbir hissettirme metni"
    },
    "sms_style_text": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 20,
        "category": ThreatCategory.GENERAL,
        "description": "SMS tarzi mesaj bicimi"
    },
    "hidden_iframe": {
        "severity": SignalSeverity.HIGH,
        "weight": 35,
        "category": ThreatCategory.GENERAL,
        "description": "Gizli iframe tespit edildi"
    },

    # HIGH SIGNALS (+40-60 points)
    "brand_impostor": {
        "severity": SignalSeverity.HIGH,
        "weight": 50,
        "category": ThreatCategory.GENERAL,
        "description": "Marka/organizasyon taklidi tespit edildi",
        "requires": ["brand_keyword", "suspicious_domain"]
    },
    "gov_impostor": {
        "severity": SignalSeverity.HIGH,
        "weight": 55,
        "category": ThreatCategory.GOVERNMENT,
        "description": "Devlet/kurum taklidi tespit edildi",
        "requires": ["gov_keyword", "non_gov_domain"]
    },
    "typosquatting": {
        "severity": SignalSeverity.HIGH,
        "weight": 45,
        "category": ThreatCategory.GENERAL,
        "description": "Typosquatting/alfabetik hile tespit edildi"
    },
    "fake_login_page": {
        "severity": SignalSeverity.HIGH,
        "weight": 50,
        "category": ThreatCategory.GENERAL,
        "description": "Sashte giris sayfasi tespit edildi",
        "requires": ["has_password_field", "suspicious_domain"]
    },
    "external_credential_endpoint": {
        "severity": SignalSeverity.HIGH,
        "weight": 45,
        "category": ThreatCategory.GENERAL,
        "description": "Kimlik bilgileri harici adrese gonderiliyor"
    },
    "urgency_with_credential_request": {
        "severity": SignalSeverity.HIGH,
        "weight": 40,
        "category": ThreatCategory.GENERAL,
        "description": "Acele/tedbir hissettirme + kimlik talebi",
        "requires": ["urgency_text", "has_credential_request"]
    },
    "fake_cargo_brand": {
        "severity": SignalSeverity.HIGH,
        "weight": 50,
        "category": ThreatCategory.CARGO,
        "description": "Sahte kargo firması taklidi"
    },
    "fake_ecommerce": {
        "severity": SignalSeverity.HIGH,
        "weight": 45,
        "category": ThreatCategory.ECOMMERCE,
        "description": "Sahte e-ticaret sitesi"
    },
    "suspicious_tld": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 20,
        "category": ThreatCategory.GENERAL,
        "description": "Supheli TLD (.xyz, .top, .click vb.)"
    },
    "punycode_domain": {
        "severity": SignalSeverity.HIGH,
        "weight": 50,
        "category": ThreatCategory.GENERAL,
        "description": "Punycode/idn domain tespit edildi"
    },
    "ip_based_url": {
        "severity": SignalSeverity.HIGH,
        "weight": 40,
        "category": ThreatCategory.GENERAL,
        "description": "URL'de IP adresi kullanilmis"
    },
    "excessive_subdomains": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 15,
        "category": ThreatCategory.GENERAL,
        "description": "Cok fazla subdomain"
    },

    # MEDIUM SIGNALS (+15-25 points)
    "suspicious_iframe": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 20,
        "category": ThreatCategory.GENERAL,
        "description": "Supheli iframe tespit edildi"
    },
    "external_scripts": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 15,
        "category": ThreatCategory.GENERAL,
        "description": "Harici script kaynaklari"
    },
    "suspicious_form_fields": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 20,
        "category": ThreatCategory.GENERAL,
        "description": "Supheli form alanlari (TC, IBAN, kart)"
    },
    "domain_age_anomaly": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 15,
        "category": ThreatCategory.GENERAL,
        "description": "Domain yasi supheli (cok yeni)"
    },
    "unusual_redirects": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 20,
        "category": ThreatCategory.GENERAL,
        "description": "Supheli yonlendirme Zinciri"
    },
    "ssl_error": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 25,
        "category": ThreatCategory.GENERAL,
        "description": "SSL sertifika hatasi"
    },
    "no_https": {
        "severity": SignalSeverity.LOW,
        "weight": 10,
        "category": ThreatCategory.GENERAL,
        "description": "HTTPS kullanilmiyor"
    },
    "right_click_disabled": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 10,
        "category": ThreatCategory.GENERAL,
        "description": "Sag tik engellenmis"
    },
    "meta_refresh_redirect": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 15,
        "category": ThreatCategory.GENERAL,
        "description": "Meta refresh yonlendirmesi"
    },
    "js_obfuscation": {
        "severity": SignalSeverity.MEDIUM,
        "weight": 15,
        "category": ThreatCategory.GENERAL,
        "description": "JavaScript sifreleme/bulaniklik"
    },

    # LOW SIGNALS (+2-5 points)
    "contact_phone": {
        "severity": SignalSeverity.LOW,
        "weight": 3,
        "category": ThreatCategory.GENERAL,
        "description": "Telefon numarasi (tek basina onemli degil)",
        "informational": True
    },
    "contact_whatsapp": {
        "severity": SignalSeverity.LOW,
        "weight": 2,
        "category": ThreatCategory.GENERAL,
        "description": "WhatsApp iletisimi (tek basina onemli degil)",
        "informational": True
    },
    "english_content": {
        "severity": SignalSeverity.LOW,
        "weight": 1,
        "category": ThreatCategory.GENERAL,
        "description": "Ingilizce icerik (tek basina onemli degil)",
        "informational": True
    },
    "generic_urgency": {
        "severity": SignalSeverity.LOW,
        "weight": 3,
        "category": ThreatCategory.GENERAL,
        "description": "Genel aciliyet hissettirme",
        "informational": True
    },
    "social_media_links": {
        "severity": SignalSeverity.LOW,
        "weight": 2,
        "category": ThreatCategory.SOCIAL_MEDIA,
        "description": "Sosyal medya linkleri",
        "informational": True
    },
    "known_safe_domain": {
        "severity": SignalSeverity.LOW,
        "weight": -50,
        "category": ThreatCategory.GENERAL,
        "description": "Bilinen guvenli domain",
        "auto_decision": "SAFE"
    },

    # POSITIVE SIGNALS (reduce risk)
    "official_domain": {
        "severity": SignalSeverity.LOW,
        "weight": -40,
        "category": ThreatCategory.GENERAL,
        "description": "Resmi domain (.gov.tr, bilinen sirket)",
        "auto_decision": "SAFE"
    },
    "valid_ssl": {
        "severity": SignalSeverity.LOW,
        "weight": -10,
        "category": ThreatCategory.GENERAL,
        "description": "Gecerli SSL sertifikasi"
    },
    "domain_age_ok": {
        "severity": SignalSeverity.LOW,
        "weight": -5,
        "category": ThreatCategory.GENERAL,
        "description": "Domain yasi normal"
    },
}

def get_signal_weight(signal_name: str) -> int:
    return SIGNAL_DEFINITIONS.get(signal_name, {}).get("weight", 0)

def get_signal_severity(signal_name: str) -> SignalSeverity:
    return SIGNAL_DEFINITIONS.get(signal_name, {}).get("severity", SignalSeverity.LOW)

def is_critical_signal(signal_name: str) -> bool:
    return get_signal_severity(signal_name) == SignalSeverity.CRITICAL

def is_high_signal(signal_name: str) -> bool:
    return get_signal_severity(signal_name) == SignalSeverity.HIGH

def is_informational_signal(signal_name: str) -> bool:
    return SIGNAL_DEFINITIONS.get(signal_name, {}).get("informational", False)
