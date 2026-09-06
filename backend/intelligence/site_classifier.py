"""
PhishShield TR - Site Type Classification
Phase 2: Trust Classification for V3

Classifies domains into proper SiteType categories:
- OFFICIAL_GOVERNMENT: Government domains (.gov.tr, official government portals)
- OFFICIAL_COMPANY: Banks, telecom, major corporations
- TRUSTED_PLATFORM: Social media, search engines, known platforms
- TRUSTED_SERVICE: Email providers, cloud services
- UNKNOWN: Unclassified domains
- SUSPICIOUS: Suspicious but not confirmed malicious
- BRAND_IMPERSONATION: Confirmed brand impersonation
"""

from enum import Enum
from typing import Optional
import re

class SiteType(Enum):
    """Site classification types"""
    OFFICIAL_GOVERNMENT = "OFFICIAL_GOVERNMENT"
    OFFICIAL_COMPANY = "OFFICIAL_COMPANY"
    TRUSTED_PLATFORM = "TRUSTED_PLATFORM"
    TRUSTED_SERVICE = "TRUSTED_SERVICE"
    UNKNOWN = "UNKNOWN"
    SUSPICIOUS = "SUSPICIOUS"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"


# Government domains - ONLY .gov.tr and official government portals
GOVERNMENT_DOMAINS = {
    # Turkey government
    "gov.tr",
    "turkiye.gov.tr",
    "cimer.gov.tr",
    "eba.gov.tr",
    "aof.gov.tr",
    "sgk.gov.tr",
    "gib.gov.tr",
    "mevzuat.gov.tr",
    "tbmm.gov.tr",
    "basbakanlik.gov.tr",
    "msbmeb.gov.tr",
    "btk.gov.tr",
    "tcmb.gov.tr",
    "mb.gov.tr",
    "spo.gov.tr",
    "yok.gov.tr",
    "osym.gov.tr",
    "ikg.gov.tr",
    "shgm.gov.tr",
    "saglik.gov.tr",
    "kulturturizm.gov.tr",
    "uab.gov.tr",
    "tarim.gov.tr",
    "csb.gov.tr",
    "aii.gov.tr",
    "ua.gov.tr",
    "uyap.gov.tr",
    "nvi.gov.tr",
    "egm.gov.tr",
    "polisan.gov.tr",
    "jandarma.gov.tr",
    "msb.gov.tr",
    "bombafirini.gov.tr",
    
    # Turkish Education - Universities
    "anadolu.edu.tr",
    "istanbul.edu.tr",
    "ankara.edu.tr",
    " hacettepe.edu.tr",
    "iyte.edu.tr",
    "itu.edu.tr",
    "gtu.edu.tr",
    "bau.edu.tr",
    "sabanci.edu.tr",
    "koc.edu.tr",
    "bilkent.edu.tr",
    "ozyegin.edu.tr",
    "dogus.edu.tr",
    
    # Student/Teacher portals
    "ogrenci.gov.tr",
    "ogretmen.gov.tr",
    "mektep.gov.tr",
    
    # Official turkish portals
    "trt.net.tr",
    "trtavaz.com.tr",
}


# Trusted platforms - Social media, search, video, etc.
TRUSTED_PLATFORMS = {
    # Social media
    "facebook.com",
    "fb.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "whatsapp.com",
    "telegram.org",
    "tiktok.com",
    "snapchat.com",
    "threads.net",
    "mastodon.social",
    "reddit.com",
    "pinterest.com",
    "tumblr.com",
    
    # AI Platforms (NEW)
    "chatgpt.com",
    "chat.openai.com",
    "openai.com",
    "claude.ai",
    "gemini.google.com",
    "perplexity.ai",
    "copilot.microsoft.com",
    "bard.google.com",
    
    # Tech platforms
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "microsoft.com",
    "apple.com",
    "dropbox.com",
    "drive.google.com",
    "icloud.com",
    "aws.amazon.com",
    
    # Search & Video
    "google.com",
    "google.com.tr",
    "youtube.com",
    "googlevideo.com",
    "bing.com",
    "yahoo.com",
    "yandex.com",
    "duckduckgo.com",
    
    # Messaging & Communication
    "messenger.com",
    "zoom.us",
    "teams.microsoft.com",
    "slack.com",
    "discord.com",
    "skype.com",
    "viber.com",
    "line.me",
    
    # Email providers
    "outlook.com",
    "hotmail.com",
    "live.com",
    "mail.google.com",
    "protonmail.com",
    "tutanota.com",
    "yandex.com",
    "mail.yahoo.com",
}


# Trusted services - Cloud, productivity, etc.
TRUSTED_SERVICES = {
    # Cloud & Productivity
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "npmjs.com",
    "pypi.org",
    "docker.com",
    "aws.amazon.com",
    "cloud.google.com",
    "azure.microsoft.com",
    "digitalocean.com",
    "heroku.com",
    "vercel.com",
    "netlify.com",
    
    # Office & Documents
    "microsoft.com",
    "office.com",
    "sharepoint.com",
    "dropbox.com",
    "drive.google.com",
    "icloud.com",
    "box.com",
    
    # Shopping & Payments
    "amazon.com",
    "amazon.com.tr",
    "paypal.com",
    "stripe.com",
    "shopify.com",
    "aliexpress.com",
    "trendyol.com",
    "hepsiburada.com",
    "n11.com",
    "gittigidiyor.com",
    "sahibinden.com",
    
    # Entertainment
    "netflix.com",
    "spotify.com",
    "apple.com",
    "playstation.com",
    "xbox.com",
    "steam.com",
    "twitch.tv",
    
    # News & Media
    "bbc.com",
    "cnn.com",
    "reuters.com",
    "apnews.com",
    "nytimes.com",
    "hurriyet.com.tr",
    "sabah.com.tr",
    "milliyet.com.tr",
    "sozcu.com.tr",
    "cnnturk.com",
}


# Official company domains - Banks, Telecom, etc.
OFFICIAL_COMPANY_DOMAINS = {
    # Banks
    "garantibbva.com.tr",
    "akbank.com",
    "akbank.com.tr",
    "isbank.com.tr",
    "ziraatbank.com.tr",
    "halkbank.com.tr",
    "vakifbank.com.tr",
    "yapikredi.com.tr",
    "kuveytturk.com.tr",
    "denizbank.com",
    "ingbank.com.tr",
    "teb.com.tr",
    "cepteteb.com.tr",
    "qnb.com.tr",
    "fibabanka.com.tr",
    "albaraka.com.tr",
    "turkiyefinans.com.tr",
    "bankpozitif.com.tr",
    
    # Telecom
    "turkcell.com.tr",
    "turktcell.com",
    "vodafone.com.tr",
    "türk Telekom.com.tr",
    "ttnet.com.tr",
    "superonline.com",
    "dsmart.com.tr",
    
    # Insurance
    "anadolusigorta.com.tr",
    "axa.com.tr",
    "mapfre.com.tr",
    "groupama.com.tr",
    
    # E-commerce
    "trendyol.com",
    "hepsiburada.com",
    "n11.com",
    "gittigidiyor.com",
    "amazon.com.tr",
    "pazarama.com",
    
    # Utilities
    "akdeniz.com.tr",
    "bosch.com.tr",
    "siemens.com.tr",
}


def classify_site_type(domain: str) -> tuple[SiteType, Optional[str]]:
    """
    Classify a domain into a SiteType.
    
    Returns:
        Tuple of (SiteType, matched_domain or None)
    
    Examples:
        classify_site_type("turkiye.gov.tr")  → (OFFICIAL_GOVERNMENT, "turkiye.gov.tr")
        classify_site_type("linkedin.com")     → (TRUSTED_PLATFORM, "linkedin.com")
        classify_site_type("garantibbva.com.tr") → (OFFICIAL_COMPANY, "garantibbva.com.tr")
        classify_site_type("unknown-site.xyz")  → (UNKNOWN, None)
    """
    if not domain:
        return SiteType.UNKNOWN, None
    
    domain = domain.lower()
    
    # Remove www. prefix for matching
    if domain.startswith("www."):
        domain_no_www = domain[4:]
    else:
        domain_no_www = domain
    
    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]
        domain_no_www = domain_no_www.split(":")[0]
    
    # Check exact matches first (most specific)
    exact_checks = [
        (domain, GOVERNMENT_DOMAINS, SiteType.OFFICIAL_GOVERNMENT),
        (domain, TRUSTED_PLATFORMS, SiteType.TRUSTED_PLATFORM),
        (domain, TRUSTED_SERVICES, SiteType.TRUSTED_SERVICE),
        (domain, OFFICIAL_COMPANY_DOMAINS, SiteType.OFFICIAL_COMPANY),
    ]
    
    for check_domain, domain_set, site_type in exact_checks:
        if check_domain in domain_set:
            return site_type, check_domain
    
    # Check without www prefix
    www_checks = [
        (domain_no_www, GOVERNMENT_DOMAINS, SiteType.OFFICIAL_GOVERNMENT),
        (domain_no_www, TRUSTED_PLATFORMS, SiteType.TRUSTED_PLATFORM),
        (domain_no_www, TRUSTED_SERVICES, SiteType.TRUSTED_SERVICE),
        (domain_no_www, OFFICIAL_COMPANY_DOMAINS, SiteType.OFFICIAL_COMPANY),
    ]
    
    for check_domain, domain_set, site_type in www_checks:
        if check_domain in domain_set:
            return site_type, check_domain
    
    # Check suffix matches (e.g., domain ends with .gov.tr)
    suffix_checks = [
        (domain, ".gov.tr", GOVERNMENT_DOMAINS, SiteType.OFFICIAL_GOVERNMENT),
    ]
    
    for check_domain, tld, domain_set, site_type in suffix_checks:
        if domain.endswith(tld):
            for gov_domain in domain_set:
                if domain.endswith(gov_domain) or domain == gov_domain:
                    return site_type, gov_domain
    
    # Check for brand impersonation indicators
    impersonation_keywords = [
        "garanti-giris", "garanti-login", "garantigiris", "garanti-sifre", "fake-garanti",
        "akbank-giris", "akbank-login", "akbankgir", "akbank-sifre", "akbank-secure", "fake-akbank",
        "isbank-giris", "isbank-login", "isbankgir", "isbank-sifre", "fake-isbank",
        "ziraat-giris", "ziraat-login", "ziraatgir", "fake-ziraat",
        "edevlet-giris", "edevlet-login", "edevletgir", "edevlet-sifre", "fake-edevlet",
        "uyap-giris", "uyap-login", "uyapgir", "fake-uyap",
    ]
    
    for keyword in impersonation_keywords:
        if keyword in domain:
            return SiteType.BRAND_IMPERSONATION, None
    
    # Default to UNKNOWN
    return SiteType.UNKNOWN, None


def is_trusted_domain(domain: str) -> bool:
    """Check if domain is trusted (any category)"""
    site_type, _ = classify_site_type(domain)
    return site_type in [
        SiteType.OFFICIAL_GOVERNMENT,
        SiteType.OFFICIAL_COMPANY,
        SiteType.TRUSTED_PLATFORM,
        SiteType.TRUSTED_SERVICE,
    ]


def get_trust_level(domain: str) -> str:
    """Get a human-readable trust level"""
    site_type, matched = classify_site_type(domain)
    
    if site_type == SiteType.OFFICIAL_GOVERNMENT:
        return "Resmi Devlet Kurumu"
    elif site_type == SiteType.OFFICIAL_COMPANY:
        return "Resmi Şirket"
    elif site_type == SiteType.TRUSTED_PLATFORM:
        return "Güvenilir Platform"
    elif site_type == SiteType.TRUSTED_SERVICE:
        return "Güvenilir Hizmet"
    elif site_type == SiteType.BRAND_IMPERSONATION:
        return "Marka Taklidi"
    else:
        return "Bilinmeyen"
