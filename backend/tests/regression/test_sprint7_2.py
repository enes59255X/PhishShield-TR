"""
PhishShield TR - Sprint 7.2 Fusion Engine Tests
Tests Intelligence Fusion Engine
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from intelligence.fusion_engine import FusionEngine, fusion_engine, ThreatSource
from ml.features import SiteFeatures, DomainFeatures, ThreatFeatures, BrandFeatures, FormFeatures
from ml.feature_collector import feature_collector


def test_fusion_engine_trusted_platform():
    """Test: Trusted platform returns SAFE with high confidence"""
    print("Test: Fusion engine trusted platform...")

    analysis_result = {
        "url": "https://chatgpt.com/c/12345",
        "score": 0,
        "reasons": [],
        "sub_scores": {},
        "signals": ["trusted_platform"],
        "correlation_rules_applied": [],
        "correlation_bonus": 0,
        "site_type": "TRUSTED_PLATFORM",
        "trust_fast_path": True,
        "domain": "chatgpt.com"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    result = fusion_engine.fuse(features)

    assert result.decision == "SAFE"
    assert result.final_score == 0
    assert result.confidence == 99

    print("  PASSED")


def test_fusion_engine_bank_phishing():
    """Test: Bank phishing gets high score"""
    print("Test: Fusion engine bank phishing...")

    analysis_result = {
        "url": "https://garanti-login-secure.xyz/login",
        "score": 80,
        "reasons": ["Banka taklidi", "Sifre alani"],
        "sub_scores": {},
        "signals": ["bank_impostor", "password_field", "suspicious_tld"],
        "correlation_rules_applied": ["BANK_PHISHING"],
        "correlation_bonus": 25,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "garanti-login-secure.xyz"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    result = fusion_engine.fuse(features)

    assert result.decision == "DANGER", f"Expected DANGER, got {result.decision}"
    assert result.final_score > 0
    assert result.brand_score > 0
    assert "Banka kimlik avı" in result.threat_patterns or result.brand_score > 0

    print("  PASSED")


def test_fusion_engine_credential_harvest():
    """Test: Credential harvesting pattern detected"""
    print("Test: Fusion engine credential harvest...")

    analysis_result = {
        "url": "https://fake-site.com/login",
        "score": 65,
        "reasons": ["Kimlik bilgi formu", "Harici adres"],
        "sub_scores": {},
        "signals": ["credential_harvesting_external_post", "has_credential_fields"],
        "correlation_rules_applied": ["CREDENTIAL_HARVEST"],
        "correlation_bonus": 20,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "fake-site.com"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    result = fusion_engine.fuse(features)

    assert result.decision == "DANGER", f"Expected DANGER, got {result.decision}"
    assert result.final_score > 0
    assert result.form_score > 0

    print("  PASSED")


def test_fusion_engine_low_risk():
    """Test: Low risk site returns SAFE/CAUTION"""
    print("Test: Fusion engine low risk...")

    analysis_result = {
        "url": "https://example.com",
        "score": 15,
        "reasons": [],
        "sub_scores": {},
        "signals": [],
        "correlation_rules_applied": [],
        "correlation_bonus": 0,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "example.com"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    result = fusion_engine.fuse(features)

    assert result.final_score < 30
    assert result.decision in ["SAFE", "CAUTION"]

    print("  PASSED")


def test_fusion_engine_component_scores():
    """Test: Component scores are calculated"""
    print("Test: Component scores...")

    analysis_result = {
        "url": "https://garanti-fake.xyz/login",
        "score": 70,
        "reasons": ["Banka taklidi", "Yeni domain"],
        "sub_scores": {},
        "signals": ["bank_impostor", "password_field", "external_post_action", "suspicious_tld"],
        "correlation_rules_applied": ["BANK_PHISHING"],
        "correlation_bonus": 20,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "garanti-fake.xyz"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    result = fusion_engine.fuse(features)

    # Check all component scores exist
    assert hasattr(result, 'threat_score')
    assert hasattr(result, 'brand_score')
    assert hasattr(result, 'form_score')
    assert hasattr(result, 'domain_score')

    # Brand and form should have scores for this case
    assert result.brand_score > 0
    assert result.form_score > 0

    print("  PASSED")


def test_fusion_engine_weights():
    """Test: Custom weights can be applied"""
    print("Test: Custom weights...")

    # Create engine with custom weights
    custom_weights = {
        ThreatSource.THREAT_INTEL: 0.50,  # Higher weight for threat intel
        ThreatSource.BRAND_IMPERSONATION: 0.20,
        ThreatSource.FORM_BEHAVIOR: 0.15,
        ThreatSource.DOMAIN_INTELLIGENCE: 0.10,
        ThreatSource.CONTENT_SIGNALS: 0.05,
    }

    engine = FusionEngine(weights=custom_weights)

    analysis_result = {
        "url": "https://test.com",
        "score": 50,
        "reasons": [],
        "sub_scores": {},
        "signals": [],
        "correlation_rules_applied": [],
        "correlation_bonus": 0,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "test.com"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    result = engine.fuse(features)

    assert result.weights == custom_weights

    print("  PASSED")


def test_fusion_engine_indicators():
    """Test: Threat indicators are built"""
    print("Test: Threat indicators...")

    analysis_result = {
        "url": "https://garanti-login.xyz",
        "score": 75,
        "reasons": ["Banka taklidi"],
        "sub_scores": {},
        "signals": ["bank_impostor", "password_field"],
        "correlation_rules_applied": [],
        "correlation_bonus": 0,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "garanti-login.xyz"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    result = fusion_engine.fuse(features)

    assert len(result.indicators) > 0

    print("  PASSED")


def test_fusion_engine_suspicious_tld():
    """Test: Suspicious TLD increases domain score"""
    print("Test: Suspicious TLD scoring...")

    analysis_result = {
        "url": "https://test-site.xyz/page",
        "score": 20,
        "reasons": [],
        "sub_scores": {},
        "signals": ["suspicious_tld"],
        "correlation_rules_applied": [],
        "correlation_bonus": 0,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "test-site.xyz"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    result = fusion_engine.fuse(features)

    assert result.domain_score > 0

    print("  PASSED")


def run_all_tests():
    """Run all regression tests"""
    print("=" * 60)
    print("Sprint 7.2 Fusion Engine Tests")
    print("=" * 60)
    print()

    tests = [
        test_fusion_engine_trusted_platform,
        test_fusion_engine_bank_phishing,
        test_fusion_engine_credential_harvest,
        test_fusion_engine_low_risk,
        test_fusion_engine_component_scores,
        test_fusion_engine_weights,
        test_fusion_engine_indicators,
        test_fusion_engine_suspicious_tld,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
