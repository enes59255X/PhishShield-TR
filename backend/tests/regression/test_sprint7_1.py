"""
PhishShield TR - Sprint 7.1 Feature Pipeline Tests
Tests Feature Extraction Pipeline
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from ml.feature_collector import FeatureCollector, feature_collector
from ml.features import (
    SiteFeatures,
    DomainFeatures,
    ThreatFeatures,
    BrandFeatures,
    FormFeatures,
    ContentFeatures,
    ThreatLevel,
)
from ml.collectors import (
    DomainFeatureCollector,
    ThreatFeatureCollector,
    BrandFeatureCollector,
    FormFeatureCollector,
    ContentFeatureCollector,
)


def test_feature_collector():
    """Test: Feature collector produces unified SiteFeatures"""
    print("Test: Feature collector...")

    # Mock analysis result
    analysis_result = {
        "url": "https://garanti-login-secure.xyz/login",
        "score": 75,
        "risk_level": "Yuksek Risk",
        "reasons": ["Supheli domain", "Banka ismi bulundu", "Sifre alani tespit edildi"],
        "sub_scores": {
            "js_obfuscation": 15,
            "ssl_cert": 80
        },
        "signals": ["bank_impostor", "password_field", "suspicious_tld"],
        "correlation_rules_applied": ["BANK_PHISHING"],
        "correlation_bonus": 20,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "garanti-login-secure.xyz"
    }

    collector = FeatureCollector()
    features = collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    assert isinstance(features, SiteFeatures), "Should be SiteFeatures"
    assert features.url == "https://garanti-login-secure.xyz/login", "URL mismatch"
    assert features.domain == "garanti-login-secure.xyz", "Domain mismatch"
    assert features.raw_risk_score == 75, "Score mismatch"

    # Check feature groups exist and have correct types
    assert isinstance(features.domain_features, DomainFeatures), f"DomainFeatures expected, got {type(features.domain_features)}"
    assert isinstance(features.threat, ThreatFeatures), f"ThreatFeatures expected, got {type(features.threat)}"
    assert isinstance(features.brand, BrandFeatures), f"BrandFeatures expected, got {type(features.brand)}"
    assert isinstance(features.form, FormFeatures), f"FormFeatures expected, got {type(features.form)}"
    assert isinstance(features.content, ContentFeatures), f"ContentFeatures expected, got {type(features.content)}"

    print("  PASSED")


def test_domain_features():
    """Test: Domain features are collected correctly"""
    print("Test: Domain features...")

    collector = DomainFeatureCollector()

    analysis_result = {
        "sub_scores": {}
    }

    features = collector.collect(
        url="https://garanti-login-secure2026.xyz/very/long/path",
        analysis_result=analysis_result
    )

    assert features.length > 0
    assert features.hyphen_count > 0
    assert features.is_suspicious_tld == True  # .xyz
    assert features.subdomain_count >= 0

    print("  PASSED")


def test_threat_features():
    """Test: Threat features are collected correctly"""
    print("Test: Threat features...")

    collector = ThreatFeatureCollector()

    analysis_result = {
        "threat_intel": {
            "matched": True,
            "source": "openphish",
            "category": "phishing",
            "confidence": 0.95
        },
        "signals": ["threat_intel_match"]
    }

    features = collector.collect(analysis_result)

    assert features.matched == True
    assert features.source == "openphish"
    assert features.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]

    print("  PASSED")


def test_brand_features():
    """Test: Brand features are collected correctly"""
    print("Test: Brand features...")

    collector = BrandFeatureCollector()

    # Test with impostor signal
    analysis_result = {
        "signals": ["bank_impostor"],
        "domain": "garanti-login-secure.xyz"
    }

    features = collector.collect(analysis_result)

    assert features.matched == True
    assert features.is_impostor == True
    assert features.brand_category == "BANKING"

    print("  PASSED")


def test_form_features():
    """Test: Form features are collected correctly"""
    print("Test: Form features...")

    collector = FormFeatureCollector()

    analysis_result = {
        "reasons": ["Sifre alani tespit edildi", "Form verisi harici adrese"],
        "sub_scores": {"form_analysis": 30},
        "signals": ["password_field", "external_post_action"]
    }

    features = collector.collect(analysis_result)

    assert features.has_password_field == True
    assert features.has_external_submit == True
    assert features.form_risk_score > 0

    print("  PASSED")


def test_content_features():
    """Test: Content features are collected correctly"""
    print("Test: Content features...")

    collector = ContentFeatureCollector()

    analysis_result = {
        "reasons": ["Garanti bankasi emniyet uyarisi", "Hemen sifrenizi degistirin"],
        "sub_scores": {},
        "threat_type": ""
    }

    features = collector.collect(analysis_result)

    assert features.has_urgency == True
    assert features.bank_word_count > 0
    assert features.urgency_word_count > 0

    print("  PASSED")


def test_trusted_platform_features():
    """Test: Trusted platform has minimal risk score"""
    print("Test: Trusted platform features...")

    analysis_result = {
        "url": "https://chatgpt.com/c/6a99b3e3-5a24-83ed-80ab-d02698788bc0",
        "score": 0,
        "risk_level": "Guvenli",
        "reasons": ["Güvenilir platform: chatgpt.com"],
        "sub_scores": {},
        "signals": ["trusted_platform"],
        "correlation_rules_applied": [],
        "correlation_bonus": 0,
        "site_type": "TRUSTED_PLATFORM",
        "trust_fast_path": True,
        "domain": "chatgpt.com"
    }

    collector = FeatureCollector()
    features = collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    assert features.trust_fast_path == True
    assert features.is_trusted == True
    assert features.get_risk_score() == 0
    assert features.threat.matched == False

    print("  PASSED")


def test_to_dict():
    """Test: SiteFeatures can be serialized to dict"""
    print("Test: SiteFeatures to_dict...")

    analysis_result = {
        "url": "https://example.com",
        "score": 10,
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
        url="https://example.com",
        analysis_result=analysis_result
    )

    features_dict = features.to_dict()

    assert isinstance(features_dict, dict)
    assert "domain_features" in features_dict
    assert "threat_features" in features_dict
    assert "brand_features" in features_dict
    assert "form_features" in features_dict
    assert "content_features" in features_dict

    print("  PASSED")


def test_threat_indicators():
    """Test: Get threat indicators from features"""
    print("Test: Threat indicators...")

    analysis_result = {
        "url": "https://fake-garanti.com",
        "score": 85,
        "reasons": ["Banka taklidi"],
        "sub_scores": {},
        "signals": ["bank_impostor", "password_field"],
        "correlation_rules_applied": [],
        "correlation_bonus": 0,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "fake-garanti.com",
        "threat_intel": {"matched": False}
    }

    features = feature_collector.collect(
        url="https://fake-garanti.com",
        analysis_result=analysis_result
    )

    indicators = features.get_threat_indicators()

    assert len(indicators) > 0
    assert any("brand" in i for i in indicators)

    print("  PASSED")


def run_all_tests():
    """Run all regression tests"""
    print("=" * 60)
    print("Sprint 7.1 Feature Pipeline Tests")
    print("=" * 60)
    print()

    tests = [
        test_feature_collector,
        test_domain_features,
        test_threat_features,
        test_brand_features,
        test_form_features,
        test_content_features,
        test_trusted_platform_features,
        test_to_dict,
        test_threat_indicators,
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
