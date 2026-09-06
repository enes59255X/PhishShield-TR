"""
PhishShield TR - Domain Entropy Analyzer
Sprint 11: Detects typosquatting and lookalike domains

Uses Shannon entropy to detect random-looking domains:
- High entropy = suspicious (randomly generated)
- Low entropy = legitimate (meaningful words)

Also performs brand-specific typosquat detection.
"""

import math
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import Counter


@dataclass
class EntropyResult:
    """Result of entropy analysis"""
    domain: str
    sld: str  # Second-level domain (e.g., "google" from "google.com")

    # Entropy scores
    char_entropy: float  # Shannon entropy of characters
    entropy_z_score: float  # Z-score vs known domains

    # Typosquat detection
    is_typosquat: bool
    typosquat_type: Optional[str]  # "hyphen", "substitution", "omission", "addition", " combo"
    target_brand: Optional[str]  # Brand being impersonated

    # Similar domains
    similar_domains: List[str]  # Known similar legitimate domains

    # Risk assessment
    risk_level: int  # 0-100
    risk_reasons: List[str]


class EntropyAnalyzer:
    """
    Analyzes domain entropy and detects typosquatting.

    Legitimate domains typically:
    - Have meaningful words (low entropy)
    - Use dictionary words
    - Follow naming conventions

    Phishing domains often:
    - Use random-looking strings (high entropy)
    - Add hyphens to separate words
    - Use lookalike characters (l vs 1, O vs 0)
    """

    # Known brands for typosquat detection
    KNOWN_BRANDS = {
        # Banking
        "garanti": ["garanti.com.tr", "garantibbva.com.tr"],
        "akbank": ["akbank.com", "akbank.com.tr"],
        "isbank": ["isbank.com.tr", "isbank.com"],
        "ziraat": ["ziraatbank.com.tr"],
        "halkbank": ["halkbank.com.tr"],
        "qnb": ["qnb.com.tr", "qnbfinansbank.com"],
        "teb": ["teb.com.tr"],
        "kuveytturk": ["kuveytturk.com.tr"],
        "denizbank": ["denizbank.com"],

        # Government
        "edevlet": ["edevlet.gov.tr", "edevletkapisi.gov.tr"],
        "gib": ["gib.gov.tr"],
        "turkiye": ["turkiye.gov.tr"],
        "eba": ["eba.gov.tr"],
        "meb": ["meb.gov.tr"],

        # E-commerce
        "trendyol": ["trendyol.com"],
        "hepsiburada": ["hepsiburada.com"],
        "amazon": ["amazon.com", "amazon.com.tr"],

        # Social/Tech
        "google": ["google.com"],
        "facebook": ["facebook.com"],
        "instagram": ["instagram.com"],
        "microsoft": ["microsoft.com"],
        "apple": ["apple.com"],
        "netflix": ["netflix.com"],
        "paypal": ["paypal.com"],
        "twitter": ["twitter.com", "x.com"],
        "linkedin": ["linkedin.com"],
    }

    # Suspicious patterns
    SUSPICIOUS_CHARS = {
        "0": "O",  # Zero vs O
        "1": "l",  # One vs lowercase L
        "5": "S",  # Five vs S
        "rn": "m",  # rn vs m
        "vv": "w",  # vv vs w
    }

    # Character frequencies for entropy calculation (English)
    CHAR_FREQUENCY = {
        'e': 0.1270, 't': 0.0906, 'a': 0.0817, 'o': 0.0751, 'i': 0.0697,
        'n': 0.0675, 's': 0.0633, 'h': 0.0609, 'r': 0.0599, 'd': 0.0425,
        'l': 0.0403, 'c': 0.0278, 'u': 0.0276, 'm': 0.0241, 'w': 0.0236,
        'f': 0.0223, 'g': 0.0202, 'y': 0.0197, 'p': 0.0193, 'b': 0.0129,
        'v': 0.0098, 'k': 0.0077, 'j': 0.0015, 'x': 0.0015, 'q': 0.0010,
        'z': 0.0007
    }

    def __init__(self):
        self.cache: Dict[str, EntropyResult] = {}

    def analyze(self, domain: str, use_cache: bool = True) -> EntropyResult:
        """
        Analyze domain entropy and typosquat patterns.

        Args:
            domain: Domain to analyze
            use_cache: Use cached results if available

        Returns:
            EntropyResult with analysis
        """
        # Clean domain
        domain = self._clean_domain(domain)

        # Check cache
        if use_cache and domain in self.cache:
            return self.cache[domain]

        # Perform analysis
        result = self._analyze_domain(domain)

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

        # Remove www prefix
        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    def _analyze_domain(self, domain: str) -> EntropyResult:
        """Perform entropy analysis"""
        # Extract SLD
        parts = domain.split(".")
        sld = parts[0] if parts else domain

        # Calculate character entropy
        char_entropy = self._calculate_entropy(sld)

        # Calculate entropy z-score
        entropy_z_score = self._calculate_z_score(char_entropy, len(sld))

        # Detect typosquat
        is_typosquat, typosquat_type, target_brand = self._detect_typosquat(sld, domain)

        # Find similar domains
        similar_domains = self._find_similar_domains(sld)

        # Calculate risk
        risk_level, risk_reasons = self._calculate_risk(
            sld, char_entropy, entropy_z_score, is_typosquat, typosquat_type
        )

        return EntropyResult(
            domain=domain,
            sld=sld,
            char_entropy=char_entropy,
            entropy_z_score=entropy_z_score,
            is_typosquat=is_typosquat,
            typosquat_type=typosquat_type,
            target_brand=target_brand,
            similar_domains=similar_domains,
            risk_level=risk_level,
            risk_reasons=risk_reasons
        )

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0

        # Count characters
        counter = Counter(text.lower())
        length = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _calculate_z_score(self, entropy: float, length: int) -> float:
        """
        Calculate z-score of entropy vs expected for domain length.

        Returns how many standard deviations above/below expected entropy.
        """
        # Expected entropy for random strings of this length
        # For truly random: entropy = log2(n) where n = character set size
        # For English-like: entropy is lower

        # Expected entropy for domain-like strings (26 letters + numbers + hyphen)
        max_entropy = math.log2(37)  # ~5.19

        # Expected for English words (rough approximation)
        expected_entropy = 4.0  # Lower for meaningful words

        # Standard deviation estimate
        std_dev = 0.5

        z_score = (entropy - expected_entropy) / std_dev

        return z_score

    def _detect_typosquat(
        self, sld: str, full_domain: str
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Detect if domain is typosquatting a known brand.

        Returns:
            Tuple of (is_typosquat, type, target_brand)
        """
        sld_lower = sld.lower()

        for brand, legitimate_domains in self.KNOWN_BRANDS.items():
            for legit in legitimate_domains:
                legit_sld = legit.split(".")[0]

                # Check for each typosquat type
                typosquat_type = self._check_typosquat_type(sld_lower, legit_sld)
                if typosquat_type:
                    return True, typosquat_type, brand

        return False, None, None

    def _check_typosquat_type(self, sld: str, target: str) -> Optional[str]:
        """
        Check if sld is a typosquat of target.

        Returns type of typosquat or None.
        """
        # Skip if too different
        if abs(len(sld) - len(target)) > 4:
            return None

        # 1. Addition (garanti-login vs garanti)
        if target in sld and sld != target:
            if sld.replace(target, "") in ["login", "secure", "account", "online", "verify"]:
                return "addition"

        # 2. Hyphen insertion (garanti-login vs garanti)
        if "-" in sld and target in sld.replace("-", ""):
            return "hyphen"

        # 3. Character substitution
        for original, replacement in self.SUSPICIOUS_CHARS.items():
            if original in target and replacement in sld:
                # Check if swapping makes them match
                swapped = target.replace(original, replacement)
                if sld == swapped or sld == swapped + "1":
                    return "substitution"

        # 4. Common substitutions (l vs 1, O vs 0)
        common_subs = [
            ("o", "0"), ("0", "o"),
            ("l", "1"), ("1", "l"),
            ("s", "5"), ("5", "s"),
        ]

        for a, b in common_subs:
            target_variant = target.replace(a, b)
            if sld == target_variant:
                return "substitution"

        # 5. Omission (gooogle vs google)
        if len(sld) == len(target) - 1:
            # Check if one character was removed
            for i in range(len(target)):
                variant = target[:i] + target[i+1:]
                if sld == variant:
                    return "omission"

        # 6. Character swap (goolge vs google)
        if len(sld) == len(target):
            diff_positions = []
            for i in range(len(sld)):
                if sld[i] != target[i]:
                    diff_positions.append(i)

            if len(diff_positions) == 2:
                # Check if it's a transposition
                i, j = diff_positions
                if sld[i] == target[j] and sld[j] == target[i]:
                    return "transposition"

        # 7. Combo (garanti-login-secure-xyz)
        if len(sld) > len(target) + 5 and target in sld:
            parts = sld.replace("-", " ").split()
            if len(parts) >= 2 and any(len(p) > 3 for p in parts):
                return "combo"

        return None

    def _find_similar_domains(self, sld: str) -> List[str]:
        """Find known legitimate domains similar to this SLD"""
        similar = []

        for brand, legitimate_domains in self.KNOWN_BRANDS.items():
            for legit in legitimate_domains:
                legit_sld = legit.split(".")[0]

                # Check similarity
                similarity = self._string_similarity(sld, legit_sld)

                if similarity > 0.6 and similarity < 1.0:
                    similar.append(legit)

        return similar[:3]  # Return top 3

    def _string_similarity(self, s1: str, s2: str) -> float:
        """Calculate Jaccard similarity between two strings"""
        if not s1 or not s2:
            return 0.0

        set1 = set(s1.lower())
        set2 = set(s2.lower())

        intersection = len(set1 & set2)
        union = len(set1 | set2)

        return intersection / union if union > 0 else 0.0

    def _calculate_risk(
        self,
        sld: str,
        entropy: float,
        z_score: float,
        is_typosquat: bool,
        typosquat_type: Optional[str]
    ) -> Tuple[int, List[str]]:
        """Calculate risk score from entropy analysis"""
        risk = 0
        reasons = []

        # High entropy = higher risk
        if entropy > 4.5:
            risk += 30
            reasons.append("Yukssek domain entropisi - rastgele karakterler")

        if entropy > 5.0:
            risk += 20
            reasons.append("Cok yukssek entropi - domain otomatik olusturulmus olabilir")

        # Z-score
        if z_score > 2:
            risk += 25
            reasons.append("Entropi ortalamadan yuksek")

        # Typosquat detected
        if is_typosquat:
            risk += 60
            reasons.append(f"Marka taklidi tespit edildi ({typosquat_type})")

        # Many hyphens (suspicious)
        hyphen_count = sld.count("-")
        if hyphen_count >= 2:
            risk += 15
            reasons.append(f"Coklu cizgi ({hyphen_count} adet) - ayiriyor gibi")

        if hyphen_count >= 3:
            risk += 15
            reasons.append("Fazla sayida alt domain - dikkatli olun")

        # Numbers in suspicious positions
        if re.search(r"[a-z]-[0-9]", sld) or re.search(r"[0-9]-[a-z]", sld):
            risk += 10
            reasons.append("Numara ve harf karisimi")

        # All numbers
        if sld.isdigit():
            risk += 20
            reasons.append("Sadece numaralardan olusan domain")

        return min(100, risk), reasons

    def get_risk_description(self, result: EntropyResult) -> str:
        """Get human-readable risk description"""
        if result.is_typosquat:
            return f"Typosquat tespit edildi: {result.target_brand} taklidi ({result.typosquat_type})"

        if result.char_entropy > 5.0:
            return "Cok yuksek entropi - domain rastgele olusturulmus olabilir"

        if result.char_entropy > 4.5:
            return "Yukssek entropi - supheli domain yapisi"

        if result.risk_level > 30:
            return f"Supheklilik: {', '.join(result.risk_reasons[:2])}"

        return "Normal domain yapisi"


# Singleton instance
entropy_analyzer = EntropyAnalyzer()
