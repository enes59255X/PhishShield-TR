import re
import ipaddress
from urllib.parse import urlparse

PRIVATE_IP_RANGES = [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
    "127.", "::1", "localhost"
]

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return all([parsed.scheme in ("http", "https"), parsed.netloc])
    except Exception:
        return False

def is_private_ip(url: str) -> bool:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        for prefix in PRIVATE_IP_RANGES:
            if host.startswith(prefix):
                return True
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private
        except ValueError:
            pass
    except Exception:
        pass
    return False

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host
    except Exception:
        return ""

def extract_tld(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return "." + parts[-1]
    return ""

def sanitize_url(url: str) -> tuple[bool, str, str]:
    """
    Returns (is_safe_to_analyze, normalized_url, error_message)
    """
    url = normalize_url(url)
    
    if not is_valid_url(url):
        return False, url, "Geçersiz URL formatı."
    
    if is_private_ip(url):
        return False, url, "Özel/yerel IP adreslerine analiz yapılmaz."
    
    return True, url, ""
