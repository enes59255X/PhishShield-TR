"""
PhishShield TR - Trust Layer Security Tests
V4 Stabilization: Regression tests for trust classification

Tests:
1. Valid government domains should be SAFE
2. Fake government-like domains should NOT be classified as government
3. Fake government domains with lookalike TLDs should be DANGER/CAUTION
4. Content references to government domains should be marked as external
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.url_classifier import classify_url_fast, SiteType, TRUSTED_PLATFORM_DOMAINS, GOVERNMENT_DOMAINS
from intelligence.domain_validator import is_valid_domain_match, is_gov_tr_domain, validate_trust_classification


class TestTrustLayerSecurity:
    """Test suite for Trust Layer Security"""
    
    def test_valid_gov_domain(self):
        """Test 1: https://turkiye.gov.tr should be SAFE OFFICIAL_GOVERNMENT"""
        result = classify_url_fast("https://turkiye.gov.tr")
        assert result.site_type == SiteType.OFFICIAL_GOVERNMENT, f"Expected OFFICIAL_GOVERNMENT, got {result.site_type}"
        assert result.matched_domain == "turkiye.gov.tr", f"Expected turkiye.gov.tr, got {result.matched_domain}"
    
    def test_valid_gov_subdomain(self):
        """Test: https://giris.turkiye.gov.tr should be SAFE OFFICIAL_GOVERNMENT"""
        result = classify_url_fast("https://giris.turkiye.gov.tr")
        assert result.site_type == SiteType.OFFICIAL_GOVERNMENT, f"Expected OFFICIAL_GOVERNMENT, got {result.site_type}"
    
    def test_fake_gov_lookalike(self):
        """Test 2: https://havenistanbul.net should NOT be OFFICIAL_GOVERNMENT"""
        result = classify_url_fast("https://havenistanbul.net")
        assert result.site_type != SiteType.OFFICIAL_GOVERNMENT, \
            f"havenistanbul.net should NOT be OFFICIAL_GOVERNMENT, got {result.site_type}"
        # Should be UNKNOWN or LOOKALIKE_GOV
        assert result.site_type in [SiteType.UNKNOWN, SiteType.LOOKALIKE_GOV], \
            f"Expected UNKNOWN or LOOKALIKE_GOV, got {result.site_type}"
    
    def test_fake_gov_suffix(self):
        """Test 3: https://turkiye.gov.tr.fake.com should be LOOKALIKE_GOV (contains gov.tr keyword)"""
        result = classify_url_fast("https://turkiye.gov.tr.fake.com")
        assert result.site_type in [SiteType.LOOKALIKE_GOV, SiteType.BRAND_IMPERSONATION], \
            f"Expected LOOKALIKE_GOV or BRAND_IMPERSONATION, got {result.site_type}"
    
    def test_gov_tr_domain_validation(self):
        """Test: is_gov_tr_domain should only match actual .gov.tr domains"""
        # Valid
        assert is_gov_tr_domain("turkiye.gov.tr") == True
        assert is_gov_tr_domain("www.turkiye.gov.tr") == True
        assert is_gov_tr_domain("giris.turkiye.gov.tr") == True
        
        # Invalid
        assert is_gov_tr_domain("havenistanbul.net") == False
        assert is_gov_tr_domain("turkiye.gov.tr.fake.com") == False
        assert is_gov_tr_domain("gov-tr-login.com") == False
    
    def test_domain_match_validation(self):
        """Test: is_valid_domain_match should only match exact or proper subdomain"""
        # Valid matches
        assert is_valid_domain_match("turkiye.gov.tr", "turkiye.gov.tr") == True
        assert is_valid_domain_match("www.turkiye.gov.tr", "turkiye.gov.tr") == True
        assert is_valid_domain_match("giris.turkiye.gov.tr", "turkiye.gov.tr") == True
        
        # Invalid matches
        assert is_valid_domain_match("turkiye.gov.tr.fake.com", "turkiye.gov.tr") == False
        assert is_valid_domain_match("havenistanbul.net", "turkiye.gov.tr") == False
        assert is_valid_domain_match("gov-tr-login.com", "gov.tr") == False
    
    def test_trusted_platform_not_gov(self):
        """Test: Trusted platforms should NOT be classified as government"""
        # These are trusted platforms, not government
        trusted_urls = [
            "https://google.com",
            "https://chatgpt.com",
            "https://github.com",
            "https://whatsapp.com",
        ]
        for url in trusted_urls:
            result = classify_url_fast(url)
            assert result.site_type != SiteType.OFFICIAL_GOVERNMENT, \
                f"{url} should NOT be OFFICIAL_GOVERNMENT"
    
    def test_fake_garanti_lookalike(self):
        """Test: fake-garanti.xyz should be detected as brand impersonation"""
        result = classify_url_fast("https://fake-garanti.xyz")
        assert result.site_type == SiteType.BRAND_IMPERSONATION, \
            f"Expected BRAND_IMPERSONATION, got {result.site_type}"
    
    def test_lookalike_keyword_detection(self):
        """Test: Domains with gov.tr keywords but not actual gov.tr should be caught"""
        suspicious_urls = [
            "https://gov-tr-login.com",
            "https://turkiye-gov.com",
            "https://fakegov.site",
        ]
        for url in suspicious_urls:
            result = classify_url_fast(url)
            # These should NOT be OFFICIAL_GOVERNMENT
            assert result.site_type != SiteType.OFFICIAL_GOVERNMENT, \
                f"{url} should NOT be OFFICIAL_GOVERNMENT, got {result.site_type}"


class TestTrustClassificationValidation:
    """Test trust classification validation"""
    
    def test_validate_official_government(self):
        """Test: Classification validation should catch mismatches"""
        # Valid classification
        result = validate_trust_classification(
            "turkiye.gov.tr",
            "OFFICIAL_GOVERNMENT",
            "turkiye.gov.tr"
        )
        assert result["is_valid"] == True
        
        # Invalid classification - domain is not actually gov.tr
        result = validate_trust_classification(
            "havenistanbul.net",
            "OFFICIAL_GOVERNMENT",
            "turkiye.gov.tr"
        )
        assert result["is_valid"] == False
        assert result["error"] is not None


def run_tests():
    """Run all tests"""
    test_instance = TestTrustLayerSecurity()
    validation_tests = TestTrustClassificationValidation()
    
    all_passed = True
    failed_tests = []
    
    # Run TestTrustLayerSecurity tests
    test_methods = [m for m in dir(test_instance) if m.startswith('test_')]
    for method_name in test_methods:
        try:
            method = getattr(test_instance, method_name)
            method()
            print(f"✓ {method_name}")
        except AssertionError as e:
            print(f"✗ {method_name}: {e}")
            all_passed = False
            failed_tests.append(method_name)
        except Exception as e:
            print(f"✗ {method_name}: Unexpected error: {e}")
            all_passed = False
            failed_tests.append(method_name)
    
    # Run validation tests
    val_methods = [m for m in dir(validation_tests) if m.startswith('test_')]
    for method_name in val_methods:
        try:
            method = getattr(validation_tests, method_name)
            method()
            print(f"✓ {method_name}")
        except AssertionError as e:
            print(f"✗ {method_name}: {e}")
            all_passed = False
            failed_tests.append(method_name)
        except Exception as e:
            print(f"✗ {method_name}: Unexpected error: {e}")
            all_passed = False
            failed_tests.append(method_name)
    
    print("\n" + "="*50)
    if all_passed:
        print("✓ ALL TESTS PASSED")
    else:
        print(f"✗ {len(failed_tests)} TEST(S) FAILED:")
        for test in failed_tests:
            print(f"  - {test}")
    
    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
