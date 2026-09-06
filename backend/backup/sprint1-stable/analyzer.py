"""
PhishShield TR - Analysis Module
Main analysis coordinator that integrates all detection components
"""

import re
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse

from detection import (
    calculate_signal_score,
    make_final_decision,
    format_popup_response,
    generate_technical_report,
    SignalSeverity,
    Decision
)

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analyzer import (
    fetch_page_content,
    analyze_forms,
    analyze_content,
    analyze_behavior,
    analyze_js_obfuscation,
    analyze_external_scripts,
    analyze_screenshot,
    analyze_ssl_cert,
    analyze_url as old_analyze_url
)

from intel import analyze_domain_intel, TRUSTED_BRANDS, KNOWN_OFFICIAL_DOMAINS
from utils import sanitize_url, extract_domain
from intelligence import classify_site_type, SiteType


class SignalExtractor:
    """Extracts signals from analysis results"""
    
    def __init__(self):
        self.signals: List[str] = []
        self.signal_details: Dict[str, str] = {}
    
    def extract(self, analysis_result: Dict) -> Tuple[List[str], Dict]:
        """Extract signals from analysis result"""
        self.signals = []
        self.signal_details = {}
        
        url = analysis_result.get("url", "")
        sub_scores = analysis_result.get("sub_scores", {})
        reasons = analysis_result.get("reasons", [])
        total_score = analysis_result.get("score", 0)
        threat_type = analysis_result.get("threat_type", "")
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        domain_lower = domain.lower()
        
        # === DOMAIN-BASED SIGNALS ===
        
        # Known safe domains - ONLY if domain ends with known safe TLD and brand match
        # Must be more strict to avoid false positives
        known_safe_tlds = ['.com', '.com.tr', '.gov.tr', '.org', '.net', '.io', '.ai', '.co']
        domain_tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        
        trusted_match = False
        for trusted in TRUSTED_BRANDS:
            # Only consider safe if domain EQUALS or ENDS with the trusted brand
            if (domain == trusted or domain.endswith('.' + trusted) or 
                domain.endswith(trusted + '.com') or domain.endswith(trusted + '.com.tr')):
                trusted_match = True
                break
        
        if trusted_match and domain_tld in known_safe_tlds:
            self.signals.append("known_safe_domain")
            self.signal_details["known_safe_domain"] = "Bilinen guvenli domain"
        
        # Official domains - only if ends with gov.tr or known official
        official_match = False
        for official in KNOWN_OFFICIAL_DOMAINS:
            if domain.endswith(official) or domain == official:
                official_match = True
                break
        
        if official_match:
            self.signals.append("official_domain")
            self.signal_details["official_domain"] = "Resmi domain tespit edildi"
        
        # Bank impersonation - only if domain contains bank keyword but is NOT the official domain
        bank_keywords = ["garanti", "akbank", "isbank", "ziraat", "halkbank", "vakifbank", 
                        "kuveytturk", "denizbank", "ingbank", "teb", "qnb", "fibabanka"]
        
        official_bank_domains = ['garanti.com.tr', 'akbank.com', 'isbank.com.tr', 'ziraat.com.tr',
                                'halkbank.com.tr', 'vakifbank.com.tr', 'kuveytturk.com.tr',
                                'denizbank.com', 'ingbank.com.tr']
        
        is_bank_related = any(bank in domain_lower for bank in bank_keywords)
        is_official_bank = any(bank_domain in domain_lower for bank_domain in official_bank_domains)
        
        if is_bank_related and not is_official_bank:
            self.signals.append("bank_impostor")
            self.signal_details["bank_impostor"] = "Banka taklidi: " + domain
        
        # Gov impersonation
        gov_keywords = ["edevlet", "eyapikayit", "türkiye.gov", "usom", "gib", "sgk", 
                       "osym", "eba", "meb", "cimer"]
        is_gov_related = any(gov in domain_lower for gov in gov_keywords)
        if is_gov_related and not any(official in domain_lower for official in ["gov.tr", "turkiye.gov.tr"]):
            self.signals.append("gov_impostor")
            self.signal_details["gov_impostor"] = "Devlet kurumu taklidi: " + domain
        
        # Cargo brand impersonation
        cargo_keywords = ["yurtici", "aras", "ptt", "ups", "dhl", "fedex", "surat"]
        is_cargo_related = any(cargo in domain_lower for cargo in cargo_keywords)
        if is_cargo_related and "kargo" in domain_lower or "gonderi" in domain_lower:
            self.signals.append("cargo_brand")
            self.signal_details["cargo_brand"] = "Kargo firması taklidi"
        
        # E-commerce impersonation
        ecommerce_keywords = ["trendyol", "hepsiburada", "n11", "gittigidiyor", "amazon", "n11"]
        if any(ec in domain_lower for ec in ecommerce_keywords):
            if not any(official in domain_lower for official in ["trendyol.com", "hepsiburada.com"]):
                self.signals.append("ecommerce_brand")
                self.signal_details["ecommerce_brand"] = "E-ticaret platformu taklidi"
        
        # Suspicious TLD
        suspicious_tlds = [".xyz", ".top", ".click", ".loan", ".work", ".date", ".racing", 
                          ".download", ".bid", ".win", ".review", ".stream", ".click", ".online"]
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        if tld in suspicious_tlds:
            self.signals.append("suspicious_tld")
            self.signal_details["suspicious_tld"] = f"Supheli TLD: {tld}"
        
        # IP-based URL
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            self.signals.append("ip_based_url")
            self.signal_details["ip_based_url"] = "IP adresi kullanan URL"
        
        # Punycode/IDN domain
        if domain.startswith("xn--"):
            self.signals.append("punycode_domain")
            self.signal_details["punycode_domain"] = "Punycode domain tespit edildi"
        
        # Typosquatting patterns
        typosquat_patterns = [
            (r"g00gle", "google"),
            (r"garantti", "garanti"),
            (r"akbannk", "akbank"),
            (r"isbanck", "isbank"),
        ]
        for pattern, brand in typosquat_patterns:
            if re.search(pattern, domain_lower):
                self.signals.append("typosquatting")
                self.signal_details["typosquatting"] = f"Typosquatting: {brand}"
                break
        
        # Excessive subdomains
        if domain.count(".") > 3:
            self.signals.append("excessive_subdomains")
            self.signal_details["excessive_subdomains"] = "Cok fazla subdomain"
        
        # Domain mismatch with content
        if analysis_result.get("threat_type") in ["Kimlik Avı (Phishing)", "Sahte Site"]:
            self.signals.append("domain_mismatch")
            self.signal_details["domain_mismatch"] = "Domain ve icerik uyumsuz"
        
        # === CONTENT-BASED SIGNALS ===
        
        # Has password field
        if any("password" in r.lower() or "sifre" in r.lower() or "parola" in r.lower() for r in reasons):
            self.signals.append("password_field")
            self.signal_details["password_field"] = "Sifre alani tespit edildi"
        
        # Has login form
        if sub_scores.get("form_analysis", 0) > 20:
            self.signals.append("has_login_form")
            self.signal_details["has_login_form"] = "Giris formu tespit edildi"
        
        # Has credential form
        credential_keywords = ["tc", "kimlik", "tckimlik", "tckn"]
        if any(kw in " ".join(reasons).lower() for kw in credential_keywords):
            self.signals.append("has_credential_form")
            self.signal_details["has_credential_form"] = "Kimlik bilgi formu tespit edildi"
        
        # Has payment form
        payment_keywords = ["kart", "card", "cvv", "iban", "odeme"]
        if any(kw in " ".join(reasons).lower() for kw in payment_keywords):
            self.signals.append("payment_form")
            self.signal_details["payment_form"] = "Odeme formu tespit edildi"
        
        # Bank account field
        if "iban" in " ".join(reasons).lower() or "hesap" in " ".join(reasons).lower():
            self.signals.append("bank_account_field")
            self.signal_details["bank_account_field"] = "Banka hesap alani tespit edildi"
        
        # External post action
        if any("dış adrese" in r.lower() or "external" in r.lower() for r in reasons):
            self.signals.append("external_post_action")
            self.signal_details["external_post_action"] = "Form verisi harici domaine"
        
        # === BEHAVIOR-BASED SIGNALS ===
        
        if sub_scores.get("behavior_analysis", 0) > 20:
            self.signals.append("suspicious_redirect")
            self.signal_details["suspicious_redirect"] = "Supheli yonlendirme davranisi"
        
        if sub_scores.get("js_obfuscation", 0) > 10:
            self.signals.append("js_obfuscation")
            self.signal_details["js_obfuscation"] = "JavaScript sifreleme tespit edildi"
        
        if sub_scores.get("external_scripts", 0) > 15:
            self.signals.append("external_scripts")
            self.signal_details["external_scripts"] = "Harici script kaynaklari"
        
        # === THREAT TYPE SIGNALS ===
        
        reasons_text = " ".join(reasons).lower()
        threat_type_lower = threat_type.lower()
        
        if "piran" in reasons_text or "piran" in threat_type_lower:
            self.signals.append("piran_scam")
            self.signal_details["piran_scam"] = "Piran Tech SOCAL/dolandiricilik"
        
        if "kimlik avı" in threat_type_lower or "phishing" in threat_type_lower:
            self.signals.append("brand_impostor")
            self.signal_details["brand_impostor"] = "Marka taklitli phishing"
        
        # Fake/critical scam detection
        if any(word in reasons_text for word in ["dolandırıc", "dolandırıcılık", "dolandirici", "fake", "sahte", "tuşak"]):
            self.signals.append("known_phishing_domain")
            self.signal_details["known_phishing_domain"] = "Bilinen dolandırıcılık sitesi"
        
        # === TEXT-BASED SIGNALS (LOW WEIGHT) ===
        
        all_text = " ".join(reasons).lower()
        
        # Contact info (informational only)
        if "telefon" in all_text or "whatsapp" in all_text:
            self.signals.append("contact_phone")
            self.signal_details["contact_phone"] = "Telefon numarasi bulundu"
        
        if "whatsapp" in all_text:
            self.signals.append("contact_whatsapp")
            self.signal_details["contact_whatsapp"] = "WhatsApp iletisimi"
        
        # Urgency
        urgency_keywords = ["acil", "hemen", "son", "firsat", "kacirmayin", "odul", "cekilis"]
        if any(kw in all_text for kw in urgency_keywords):
            self.signals.append("urgency_text")
            self.signal_details["urgency_text"] = "Aciliyet hissettirme"
        
        # Investment keywords
        invest_keywords = ["yatirim", "faiz", "kazanc", "hisse", "bitcoin", "crypto"]
        if any(kw in all_text for kw in invest_keywords):
            self.signals.append("investment_keyword")
            self.signal_details["investment_keyword"] = "Yatirim dolandiliciligi"
        
        # Refund keywords
        refund_keywords = ["iade", "para iadesi", "refund"]
        if any(kw in all_text for kw in refund_keywords):
            self.signals.append("refund_keyword")
            self.signal_details["refund_keyword"] = "Iade dolandiliciligi"
        
        # Lottery keywords
        lottery_keywords = ["cekilis", "piyango", "odul", "kazandin"]
        if any(kw in all_text for kw in lottery_keywords):
            self.signals.append("lottery_keyword")
            self.signal_details["lottery_keyword"] = "Piyango/odul dolandi"
        
        # Job keywords
        job_keywords = ["is ilani", "is basvurusu", "calisma", "maas"]
        if any(kw in all_text for kw in job_keywords):
            self.signals.append("job_keyword")
            self.signal_details["job_keyword"] = "Is ilani dolandi"
        
        # Tracking keyword
        if "takip" in all_text or "kargo" in all_text:
            self.signals.append("tracking_keyword")
            self.signal_details["tracking_keyword"] = "Kargo/teslimat"
        
        # Payment request
        if "odeme" in all_text or "kredi karti" in all_text:
            self.signals.append("payment_request")
            self.signal_details["payment_request"] = "Odeme talebi"
        
        return self.signals, self.signal_details


def run_new_analysis(url: str) -> Dict:
    """
    Run new signal-based analysis
    """
    # Run traditional analysis
    old_result = old_analyze_url(url)
    old_score = old_result.get("score", 0)
    
    # Extract domain for site type classification
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # Classify site type (Phase 2: Trust Classification)
    site_type, matched_domain = classify_site_type(domain)
    
    # Extract signals
    extractor = SignalExtractor()
    signals, signal_details = extractor.extract(old_result)
    
    # Calculate signal-based score
    score_result = calculate_signal_score(signals)
    new_score = score_result["final_score"]
    
    # Blend old score with new signal score for robustness
    # Old score is based on comprehensive analysis, new signals add semantic layer
    if old_score >= 80:
        # High old score = definitely dangerous, preserve it
        final_score = max(old_score, new_score)
    elif old_score >= 50:
        # Medium-high old score, use weighted blend
        final_score = int(old_score * 0.7 + new_score * 0.3)
    elif old_score >= 20:
        # Medium old score, use new signal score primarily
        final_score = max(old_score, new_score)
    else:
        # Low old score, use new score unless signals say otherwise
        final_score = new_score if new_score > old_score else old_score
    
    # Ensure critical signals override
    critical_signals = ["known_phishing_domain", "piran_scam", "bank_impostor", "gov_impostor"]
    if any(s in signals for s in critical_signals):
        final_score = max(final_score, 80)
    
    final_score = min(100, max(0, final_score))
    
    # Make final decision
    decision_result = make_final_decision(
        risk_score=final_score,
        signals=signals,
        correlation_bonus=score_result["correlation_bonus"],
        applied_rules=score_result["applied_rules"],
        brand_match=any("impostor" in s for s in signals),
        known_safe="known_safe_domain" in signals or "official_domain" in signals
    )
    
    # Format popup response
    popup_response = format_popup_response(decision_result)
    
    # Build combined result
    result = {
        **old_result,
        **popup_response,
        "signals": signals,
        "signal_details": signal_details,
        "correlation_rules_applied": score_result["applied_rules"],
        "correlation_bonus": score_result["correlation_bonus"],
        "confidence": decision_result.confidence,
        "technical_report": generate_technical_report(decision_result, signals) if popup_response["is_danger"] else None,
        
        # Phase 2: Site Type Classification
        "site_type": site_type.value,
        "site_type_match": matched_domain,
        "domain": domain,
    }
    
    return result


def analyze_url(url: str) -> Dict:
    """Main entry point - uses new analysis"""
    return run_new_analysis(url)


def analyze_url_legacy(url: str) -> Dict:
    """Legacy analysis for comparison"""
    return old_analyze_url(url)
