import re
import math
import httpx
from urllib.parse import urlparse
import tldextract
from datetime import datetime
import asyncio

async def extract_features_async(url: str, html_content: str = None) -> dict:
    features = {}
    
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    
    # 1. URL Length
    features["url_length"] = len(url)
    
    # 2. Entropy
    features["entropy"] = calculate_entropy(url)
    
    # 3. Subdomain Count
    ext = tldextract.extract(url)
    features["subdomain_count"] = len(ext.subdomain.split('.')) if ext.subdomain else 0
    
    # 4. Suspicious Keywords in URL
    keywords = ["login", "verify", "account", "update", "bank", "secure", "confirm", "giris", "sifre"]
    features["suspicious_keywords"] = sum(1 for kw in keywords if kw in url.lower())
    
    # 5. Domain Age (Simplified placeholder or async whois)
    # real whois is slow, we might want to do this in background
    features["domain_age_days"] = 0  # To be filled by background worker
    
    if html_content:
        html_lower = html_content.lower()
        
        # 6. Has Login Form
        features["has_login_form"] = 1 if re.search(r'<form', html_lower) else 0
        
        # 7. Password Input
        features["password_input"] = 1 if 'type="password"' in html_lower or "type='password'" in html_lower else 0
        
        # 8. External Form Action
        action_match = re.search(r'action\s*=\s*["\'](https?://[^"\']+)["\']', html_lower)
        if action_match:
            action_url = action_match.group(1)
            features["external_form"] = 1 if domain not in action_url else 0
        else:
            features["external_form"] = 0
            
        # 9. Iframe Usage
        features["iframe_usage"] = 1 if '<iframe' in html_lower else 0
        
        # 10. Brand Similarity (Dummy logic for now, improved in intel_manager)
        features["brand_similarity"] = 0 
    else:
        features["has_login_form"] = 0
        features["password_input"] = 0
        features["external_form"] = 0
        features["iframe_usage"] = 0
        features["brand_similarity"] = 0

    return features

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    probabilities = [float(text.count(c)) / len(text) for c in set(text)]
    entropy = -sum(p * math.log(p, 2) for p in probabilities)
    return entropy

async def fetch_page_async(url: str) -> tuple[str, dict]:
    headers = {"User-Agent": "PhishShield-TR/2.0 (Autonomous Defense)"}
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            return resp.text, {"final_url": str(resp.url), "status_code": resp.status_code}
    except Exception as e:
        return "", {"error": str(e)}
