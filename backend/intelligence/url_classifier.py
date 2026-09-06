"""
PhishShield TR - URL Classifier
Sprint 6.5: Trust Layer Stabilization

Purpose:
- Extract domain and path from URL
- Classify URL type BEFORE analysis
- Enable Trust-First Pipeline
"""

from urllib.parse import urlparse
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class SiteType(Enum):
    TRUSTED_PLATFORM = "TRUSTED_PLATFORM"
    OFFICIAL_GOVERNMENT = "OFFICIAL_GOVERNMENT"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    LOOKALIKE_GOV = "LOOKALIKE_GOV"
    UNKNOWN = "UNKNOWN"


@dataclass
class URLClassification:
    """Result of URL classification"""
    original_url: str
    domain: str
    root_domain: str
    path: str
    site_type: SiteType
    matched_domain: Optional[str] = None
    is_path_based: bool = False


TRUSTED_PLATFORM_DOMAINS = {
    # AI Platforms
    "chatgpt.com",
    "chat.openai.com",
    "openai.com",
    "claude.ai",
    "claude.ai",
    "anthropic.com",
    "midjourney.com",
    "stability.ai",
    "huggingface.co",

    # Social/Professional
    "linkedin.com",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "threads.net",
    "tiktok.com",

    # Development
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "npmjs.com",
    "pypi.org",
    "packagist.org",

    # Communication
    "whatsapp.com",
    "telegram.org",
    "signal.org",
    "discord.com",
    "slack.com",
    "zoom.us",
    "teams.microsoft.com",

    # E-commerce
    "amazon.com",
    "amazon.com.tr",
    "trendyol.com",
    "hepsiburada.com",
    "n11.com",
    "gittigidiyor.com",

    # Payments
    "paypal.com",
    "stripe.com",
    "shopify.com",

    # Media
    "youtube.com",
    "vimeo.com",
    "twitch.tv",
    "spotify.com",
    "netflix.com",

    # Tech
    "google.com",
    "microsoft.com",
    "apple.com",
    "dropbox.com",
    "drive.google.com",

    # News/Info
    "wikipedia.org",
    "bbc.com",
    "reuters.com",
    "apnews.com",
}

GOVERNMENT_DOMAINS = {
    # Official gov.tr domains only
    "turkiye.gov.tr",
    "cimer.gov.tr",
    "eba.gov.tr",
    "gib.gov.tr",
    "usom.gov.tr",
    "siberguvenlik.gov.tr",
    "sibg.gov.tr",
    "esg.tubitak.gov.tr",
    "浴室.gov.tr",
}

# Suspicious patterns that might trick government domain detection
GOV_TR_KEYWORDS = ["gov.tr", "govtr", "goverment", "turkiye", "devlet", "kanun"]


def extract_domain_parts(url: str) -> Tuple[str, str]:
    """
    Extract domain and root_domain from URL.

    Returns:
        (domain, root_domain)
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]

    # Remove www prefix for classification
    if domain.startswith("www."):
        domain = domain[4:]

    # Calculate root domain (last two parts for typical TLDs)
    parts = domain.split(".")
    if len(parts) >= 2:
        # Handle .com.tr, .co.uk, etc.
        if domain.endswith(".com.tr") or domain.endswith(".co.uk"):
            root_domain = ".".join(parts[-3:]) if len(parts) >= 3 else domain
        else:
            root_domain = ".".join(parts[-2:])
    else:
        root_domain = domain

    return domain, root_domain


def classify_url_fast(url: str) -> URLClassification:
    """
    Classify URL type BEFORE full analysis.

    This is the Trust-First Pipeline:
    1. Parse URL
    2. Extract domain
    3. Check if trusted platform (exact or proper subdomain)
    4. Check government domains (STRICT matching only)
    5. Detect lookalike attempts
    6. Unknown → Full Analysis
    """
    from .domain_validator import is_valid_domain_match, is_gov_tr_domain
    
    parsed = urlparse(url)
    domain, root_domain = extract_domain_parts(url)
    path = parsed.path

    # Check for lookalike domains (subdomain tricks)
    # chatgpt.com.fake-site.com vs chatgpt.com/c/12345
    for trusted in TRUSTED_PLATFORM_DOMAINS:
        if domain.endswith("." + trusted):
            # Subdomain takeover attempt
            return URLClassification(
                original_url=url,
                domain=domain,
                root_domain=root_domain,
                path=path,
                site_type=SiteType.BRAND_IMPERSONATION,
                matched_domain=trusted
            )

    # Check exact match for root domain (TRUSTED_PLATFORM)
    if domain in TRUSTED_PLATFORM_DOMAINS or root_domain in TRUSTED_PLATFORM_DOMAINS:
        return URLClassification(
            original_url=url,
            domain=domain,
            root_domain=root_domain,
            path=path,
            site_type=SiteType.TRUSTED_PLATFORM,
            matched_domain=domain if domain in TRUSTED_PLATFORM_DOMAINS else root_domain
        )

    # Check government domains with STRICT validation
    # V4 FIX: Only match if domain actually ends with .gov.tr
    if is_gov_tr_domain(domain) or is_gov_tr_domain(root_domain):
        # Verify it's in our government list
        if domain in GOVERNMENT_DOMAINS or root_domain in GOVERNMENT_DOMAINS:
            return URLClassification(
                original_url=url,
                domain=domain,
                root_domain=root_domain,
                path=path,
                site_type=SiteType.OFFICIAL_GOVERNMENT,
                matched_domain=domain if domain in GOVERNMENT_DOMAINS else root_domain
            )
        else:
            # Has .gov.tr but not in our trusted list - potential phishing
            return URLClassification(
                original_url=url,
                domain=domain,
                root_domain=root_domain,
                path=path,
                site_type=SiteType.LOOKALIKE_GOV,
                matched_domain=None
            )

    # Check for suspicious government-like domain patterns
    # e.g., turkiye-gov.tr.com, gov-tr-login.com, havenistanbul.net
    domain_lower = domain.lower()
    for keyword in GOV_TR_KEYWORDS:
        if keyword in domain_lower and not domain.endswith(".gov.tr"):
            # Contains gov.tr keyword but not actual gov.tr domain - suspicious
            return URLClassification(
                original_url=url,
                domain=domain,
                root_domain=root_domain,
                path=path,
                site_type=SiteType.LOOKALIKE_GOV,
                matched_domain=None
            )

    # Unknown - needs full analysis
    return URLClassification(
        original_url=url,
        domain=domain,
        root_domain=root_domain,
        path=path,
        site_type=SiteType.UNKNOWN,
        matched_domain=None
    )


def is_trusted_platform(url: str) -> bool:
    """Quick check if URL is a trusted platform"""
    classification = classify_url_fast(url)
    return classification.site_type == SiteType.TRUSTED_PLATFORM


def get_trusted_explanation(domain: str) -> str:
    """Get explanation text for trusted platform"""
    explanations = {
        "chatgpt.com": "ChatGPT resmi yapay zeka platformu",
        "openai.com": "OpenAI resmi platformu",
        "chat.openai.com": "OpenAI resmi platformu",
        "claude.ai": "Claude yapay zeka platformu",
        "github.com": "GitHub güvenilir yazılım geliştirme platformu",
        "gitlab.com": "GitLab güvenilir yazılım geliştirme platformu",
        "linkedin.com": "LinkedIn güvenilir profesyonel ağ platformu",
        "twitter.com": "X (Twitter) güvenilir sosyal medya platformu",
        "x.com": "X (Twitter) güvenilir sosyal medya platformu",
        "facebook.com": "Facebook Meta'nın güvenilir sosyal medya platformu",
        "instagram.com": "Instagram Meta'nın güvenilir sosyal medya platformu",
        "whatsapp.com": "WhatsApp Meta'nın güvenilir mesajlaşma platformu",
        "youtube.com": "YouTube Google'ın güvenilir video platformu",
        "google.com": "Google güvenilir arama motoru",
        "microsoft.com": "Microsoft güvenilir teknoloji şirketi",
        "apple.com": "Apple güvenilir teknoloji şirketi",
        "amazon.com": "Amazon güvenilir e-ticaret platformu",
        "paypal.com": "PayPal güvenilir ödeme platformu",
        "turkiye.gov.tr": "Türkiye Cumhuriyeti resmi devlet portalı",
        "cimer.gov.tr": "CİMER resmi devlet iletişim platformu",
        "eba.gov.tr": "EBA resmi eğitim platformu",
    }

    # Check exact domain first
    if domain in explanations:
        return explanations[domain]

    # Check root domain
    _, root = extract_domain_parts(domain)
    if root in explanations:
        return explanations[root]

    return "Güvenilir platform olarak doğrulandı"
