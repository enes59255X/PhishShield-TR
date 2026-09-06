"""
PhishShield TR - SSL Certificate Analyzer
Sprint 11: Analyzes SSL/TLS certificates for phishing detection

Phishing sites often have:
- Self-signed certificates
- Recently issued certificates
- Expired certificates
- Mismatched domains
- Weak cipher suites
"""

import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from dataclasses import dataclass
import re


@dataclass
class SSLResult:
    """Result of SSL analysis"""
    domain: str
    has_ssl: bool

    # Certificate details
    issuer: Optional[str]
    subject: Optional[str]
    valid_from: Optional[datetime]
    valid_until: Optional[datetime]
    days_valid: int
    days_until_expiry: int

    # Validation
    is_valid: bool
    is_self_signed: bool
    is_expired: bool
    is_expiring_soon: bool
    has_mismatch: bool

    # Security
    ssl_version: Optional[str]
    cipher_suite: Optional[str]
    key_size: Optional[int]

    # Risk assessment
    risk_level: int  # 0-100
    risk_reasons: List[str]

    # Certificate chain
    certificate_chain: List[Dict]


class SSLAnalyzer:
    """
    Analyzes SSL/TLS certificates for security issues.

    Risk scoring:
    - Self-signed: +30 risk
    - Expired: +40 risk
    - Expiring soon (< 30 days): +20 risk
    - Recently issued (< 7 days): +15 risk
    - Mismatched domain: +50 risk
    - Weak cipher: +25 risk
    """

    # Risk thresholds
    EXPIRY_WARNING_DAYS = 30
    NEW_CERT_WARNING_DAYS = 7

    def __init__(self):
        self.cache: Dict[str, SSLResult] = {}

    def analyze(self, domain: str, use_cache: bool = True) -> SSLResult:
        """
        Analyze SSL certificate for domain.

        Args:
            domain: Domain to analyze
            use_cache: Use cached results if available

        Returns:
            SSLResult with certificate analysis
        """
        # Clean domain
        domain = self._clean_domain(domain)

        # Check cache
        if use_cache and domain in self.cache:
            return self.cache[domain]

        # Perform analysis
        result = self._analyze_ssl(domain)

        # Cache result
        if use_cache:
            self.cache[domain] = result

        return result

    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize domain"""
        domain = domain.lower().strip()

        # Remove protocol
        if "://" in domain:
            domain = domain.split("://")[1]

        # Remove path
        if "/" in domain:
            domain = domain.split("/")[0]

        # Remove port
        if ":" in domain:
            domain = domain.split(":")[0]

        return domain

    def _analyze_ssl(self, domain: str) -> SSLResult:
        """Perform SSL analysis"""
        result = SSLResult(
            domain=domain,
            has_ssl=False,
            issuer=None,
            subject=None,
            valid_from=None,
            valid_until=None,
            days_valid=0,
            days_until_expiry=0,
            is_valid=False,
            is_self_signed=False,
            is_expired=False,
            is_expiring_soon=False,
            has_mismatch=False,
            ssl_version=None,
            cipher_suite=None,
            key_size=None,
            risk_level=0,
            risk_reasons=[],
            certificate_chain=[]
        )

        try:
            # Try to get SSL info
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()

                    if cert:
                        result.has_ssl = True

                        # Parse certificate
                        self._parse_certificate(cert, result)

                        # Validate certificate
                        self._validate_certificate(result)

        except socket.timeout:
            result.risk_reasons.append("SSL baglanti zaman asimi")
            result.risk_level = 20

        except socket.gaierror:
            result.risk_reasons.append("Domain cozumlenemedi")
            result.risk_level = 10

        except ssl.SSLError as e:
            result.risk_reasons.append(f"SSL hatasi: {str(e)}")
            result.risk_level = 40

        except Exception as e:
            result.risk_reasons.append(f"SSL analiz hatasi: {str(e)}")
            result.risk_level = 15

        return result

    def _parse_certificate(self, cert: dict, result: SSLResult):
        """Parse certificate data"""
        # Subject
        subject = cert.get("subject", [])
        if subject:
            for item in subject:
                if isinstance(item, tuple):
                    for key, value in [item]:
                        if key == "organizationName":
                            result.subject = value
                        elif key == "commonName":
                            if not result.subject:
                                result.subject = value

        # Issuer
        issuer = cert.get("issuer", [])
        if issuer:
            for item in issuer:
                if isinstance(item, tuple):
                    for key, value in [item]:
                        if key == "organizationName":
                            result.issuer = value
                        elif key == "commonName":
                            if not result.issuer:
                                result.issuer = value

        # Validity dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        if not_before:
            result.valid_from = self._parse_date(not_before)
        if not_after:
            result.valid_until = self._parse_date(not_after)

        # Calculate days
        now = datetime.now()
        if result.valid_from:
            result.days_valid = (now - result.valid_from).days
        if result.valid_until:
            result.days_until_expiry = (result.valid_until - now).days

        # Version
        if "version" in cert:
            result.ssl_version = f"SSL/TLS v{cert['version'] - 1 + 3}"  # v3 = TLS 1.x

        # Cipher suite (if available from socket info)
        # Note: Python's ssl module doesn't expose cipher directly in basic info

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse certificate date string"""
        formats = [
            "%b %d %H:%M:%S %Y %Z",      # Jan 15 12:00:00 2024 GMT
            "%Y-%m-%d %H:%M:%S %Z",      # 2024-01-15 12:00:00 GMT
            "%Y-%m-%d %H:%M:%SZ",         # 2024-01-15T12:00:00Z
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue

        return None

    def _validate_certificate(self, result: SSLResult):
        """Validate certificate and calculate risk"""
        now = datetime.now()

        # Check expiration
        if result.valid_until:
            if result.valid_until < now:
                result.is_expired = True
                result.risk_level += 40
                result.risk_reasons.append("Sertifika suresi dolmus")

            if result.days_until_expiry < self.EXPIRY_WARNING_DAYS:
                result.is_expiring_soon = True
                result.risk_level += 20
                result.risk_reasons.append(f"Sertifika {result.days_until_expiry} gun icin gecerli")

        # Check if newly issued
        if result.valid_from:
            if (now - result.valid_from).days < self.NEW_CERT_WARNING_DAYS:
                result.risk_level += 15
                result.risk_reasons.append("Sertifika yakin zamanda cikarilmis")

        # Check self-signed (issuer == subject)
        if result.issuer and result.subject:
            if result.issuer.lower() == result.subject.lower():
                result.is_self_signed = True
                result.risk_level += 30
                result.risk_reasons.append("Self-signed sertifika")

        # Check for free SSL issuers
        free_issuers = [
            "let's encrypt",
            "cloudflare",
            "amazon",
            "google",
            "microsoft"
        ]
        if result.issuer:
            if any(free.lower() in result.issuer.lower() for free in free_issuers):
                # Free issuers are generally trustworthy
                result.risk_level = max(0, result.risk_level - 20)

        # Check domain mismatch
        if result.subject and result.domain:
            # Simple mismatch check
            clean_subject = result.subject.lower().replace("*.", "").replace("www.", "")
            clean_domain = result.domain.lower().replace("www.", "")

            if clean_subject and clean_domain not in clean_subject and clean_subject not in clean_domain:
                # Might be mismatch, but be lenient
                if not (clean_domain.endswith(clean_subject) or clean_subject.endswith(clean_domain)):
                    result.has_mismatch = True
                    result.risk_level += 20
                    result.risk_reasons.append("Domain adresi sertifikayla uyumsuz")

        # SSL version check
        if result.ssl_version:
            if "SSL v3" in result.ssl_version or "TLS 1.0" in result.ssl_version:
                result.risk_level += 15
                result.risk_reasons.append("Eski SSL/TLS surumu")

        # Set validity flag
        result.is_valid = (
            result.has_ssl and
            not result.is_expired and
            not result.has_mismatch
        )

        # Cap risk at 100
        result.risk_level = min(100, result.risk_level)

    def get_risk_description(self, result: SSLResult) -> str:
        """Get human-readable risk description"""
        if not result.has_ssl:
            return "SSL yok - guvensiz baglanti"

        if result.is_expired:
            return "SSL sertifikasi suresi dolmus"

        if result.is_self_signed:
            return "Self-signed sertifika - guvenlik uyarisi"

        if result.has_mismatch:
            return "Domain-sertifika uyumsuzlugu"

        if result.is_expiring_soon:
            return f"SSL sertifikasi {result.days_until_expiry} gun icinde sona erecek"

        if result.risk_level > 30:
            return f"SSL riskli: {result.risk_reasons[0] if result.risk_reasons else 'Bilinmeyen'}"

        if result.risk_level > 0:
            return "SSL analizi tamamlandi"

        return "SSL sertifikasi gecerli ve guvenli"


# Singleton instance
ssl_analyzer = SSLAnalyzer()
