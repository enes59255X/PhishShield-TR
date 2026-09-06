"""
PhishShield TR - Domain Validator
V4 Stabilization: Trust Layer Security Fix

Domain validation with strict matching rules:
- Exact domain match
- Valid subdomain match
- Prevents lookalike/takeover attacks
"""

from typing import List, Optional


def is_valid_domain_match(domain: str, trusted: str) -> bool:
    """
    Check if domain is a valid match for trusted domain.
    
    Rules:
    - Exact match: domain == trusted
    - Valid subdomain: domain.endswith("." + trusted)
    
    DOES NOT MATCH:
    - gov-tr-login.com (contains gov.tr but not subdomain)
    - turkiye.gov.tr.fake.com (fake suffix)
    - havenistanbul.net (contains istanbul but not gov.tr)
    
    Args:
        domain: The domain to check
        trusted: The trusted domain pattern
        
    Returns:
        True if valid match, False otherwise
    """
    domain = domain.lower().strip()
    trusted = trusted.lower().strip()
    
    if not domain or not trusted:
        return False
    
    # Exact match
    if domain == trusted:
        return True
    
    # Valid subdomain (domain.trusted)
    # e.g., www.turkiye.gov.tr matches turkiye.gov.tr
    if domain.endswith("." + trusted):
        return True
    
    return False


def validate_domain_list(domain: str, trusted_list: List[str]) -> tuple[bool, Optional[str]]:
    """
    Validate domain against a list of trusted domains.
    
    Returns:
        (is_matched, matched_trusted_domain)
    """
    domain = domain.lower().strip()
    
    for trusted in trusted_list:
        if is_valid_domain_match(domain, trusted):
            return True, trusted
    
    return False, None


def is_suspicious_subdomain(domain: str, trusted: str) -> bool:
    """
    Detect potential subdomain takeover/lookalike attempt.
    
    Example:
        fake.turkiye.gov.tr.fake.com -> SUSPICIOUS
        www.turkiye.gov.tr -> VALID
        
    Returns:
        True if suspicious pattern detected
    """
    domain = domain.lower()
    trusted = trusted.lower()
    
    # If domain contains trusted but NOT as suffix of subdomain
    if trusted in domain:
        # Check if it's a proper subdomain
        if domain.endswith("." + trusted):
            return False  # Valid subdomain
        if domain == trusted:
            return False  # Exact match
        
        # Contains but not as proper suffix - suspicious
        return True
    
    return False


def extract_root_domain(domain: str) -> str:
    """
    Extract root domain from full domain.
    
    Examples:
        www.turkiye.gov.tr -> turkiye.gov.tr
        tracker.siberguvenlik.gov.tr -> siberguvenlik.gov.tr
        fake.turkiye.gov.tr.fake.com -> fake.com (invalid)
    """
    parts = domain.lower().split(".")
    
    if len(parts) >= 2:
        # Handle .com.tr, .co.uk, etc.
        if domain.endswith(".com.tr"):
            if len(parts) >= 3:
                return ".".join(parts[-3:])
        elif domain.endswith(".co.uk"):
            if len(parts) >= 3:
                return ".".join(parts[-3:])
        else:
            return ".".join(parts[-2:])
    
    return domain


def is_gov_tr_domain(domain: str) -> bool:
    """
    Strict check for legitimate gov.tr domains.
    
    Only matches domains that:
    1. End with .gov.tr
    2. Are not followed by another TLD
    """
    domain = domain.lower().strip()
    
    if not domain.endswith(".gov.tr"):
        return False
    
    # Ensure it's not followed by another TLD (e.g., .com, .net)
    # e.g., gov.tr.fake.com should fail
    valid_suffixes = [".gov.tr", ".gov.tr:"]  # : for port handling
    
    for suffix in valid_suffixes:
        if domain == suffix or domain.endswith(suffix):
            return True
    
    # Check if followed by nothing or port only
    remaining = domain.replace(".gov.tr", "")
    if "." not in remaining:
        return True
        
    return False


def validate_trust_classification(domain: str, site_type: str, matched_domain: Optional[str] = None) -> dict:
    """
    Validate that a trust classification is correct.
    
    Returns validation result with error if mismatch found.
    """
    result = {
        "is_valid": True,
        "error": None,
        "warning": None
    }
    
    domain = domain.lower()
    
    if site_type == "OFFICIAL_GOVERNMENT":
        # Must be gov.tr domain
        if not is_gov_tr_domain(domain):
            result["is_valid"] = False
            result["error"] = f"Classification mismatch: {domain} classified as OFFICIAL_GOVERNMENT but is not gov.tr domain"
            return result
        
        # If matched_domain provided, verify it's consistent
        if matched_domain:
            if not is_valid_domain_match(domain, matched_domain):
                result["is_valid"] = False
                result["error"] = f"Domain {domain} doesn't match trusted pattern {matched_domain}"
                return result
    
    elif site_type == "TRUSTED_PLATFORM":
        # Trusted platforms should be well-known domains
        if matched_domain:
            if not is_valid_domain_match(domain, matched_domain):
                result["is_valid"] = False
                result["error"] = f"Domain {domain} doesn't match trusted platform {matched_domain}"
                return result
    
    return result
