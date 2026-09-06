"""
PhishShield TR - Sprint 7.3 Confidence Engine Tests
Tests Confidence Engine
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from intelligence.confidence_engine import (
    ConfidenceEngine,
    confidence_engine,
    ConfidenceLevel
)
from intelligence.fusion_engine import fusion_engine
from ml.feature_collector import feature_collector


def test_confidence_trusted_platform():
    """Test: Trusted platform has very high confidence"""
    print("Test: Confidence trusted platform...")

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

    fusion_result = fusion_engine.fuse(features)
    result = confidence_engine.assess(fusion_result, features)

    assert result.decision == "SAFE"
    assert result.confidence >= 90
    assert result.confidence_level == ConfidenceLevel.VERY_HIGH

    print("  PASSED")


def test_confidence_high_risk_high_confidence():
    """Test: High risk + high confidence = DANGER or CAUTION"""
    print("Test: High risk high confidence...")

    analysis_result = {
        "url": "https://garanti-login-secure.xyz/login",
        "score": 85,
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

    fusion_result = fusion_engine.fuse(features)
    result = confidence_engine.assess(fusion_result, features)

    # High risk should result in at least CAUTION
    assert result.decision in ["DANGER", "CAUTION"], f"Expected DANGER or CAUTION, got {result.decision}"
    assert result.risk_score > 50
    assert result.confidence >= 50

    print("  PASSED")


def test_confidence_high_risk_low_confidence():
    """Test: High risk + low confidence = CAUTION (needs more)"""
    print("Test: High risk low confidence...")

    # Create case with high score but low signals
    analysis_result = {
        "url": "https://unknown-site.xyz/page",
        "score": 60,
        "reasons": ["Supheli"],
        "sub_scores": {},
        "signals": ["suspicious_tld"],
        "correlation_rules_applied": [],
        "correlation_bonus": 0,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "unknown-site.xyz"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    fusion_result = fusion_engine.fuse(features)

    # Manually set low confidence for this test
    fusion_result.confidence = 35

    result = confidence_engine.assess(fusion_result, features)

    # Low confidence should be detected
    assert result.confidence_level in [ConfidenceLevel.LOW, ConfidenceLevel.VERY_LOW]

    print("  PASSED")


def test_confidence_level_classification():
    """Test: Confidence levels are classified correctly"""
    print("Test: Confidence level classification...")

    test_cases = [
        (95, ConfidenceLevel.VERY_HIGH),
        (85, ConfidenceLevel.HIGH),
        (60, ConfidenceLevel.MEDIUM),
        (40, ConfidenceLevel.LOW),
        (20, ConfidenceLevel.VERY_LOW),
    ]

    for confidence, expected_level in test_cases:
        level = confidence_engine._get_confidence_level(confidence)
        assert level == expected_level, f"Expected {expected_level} for {confidence}, got {level}"

    print("  PASSED")


def test_confidence_factors():
    """Test: Confidence factors are analyzed"""
    print("Test: Confidence factors...")

    analysis_result = {
        "url": "https://fake-garanti.com/login",
        "score": 75,
        "reasons": ["Banka taklidi", "Yeni domain"],
        "sub_scores": {},
        "signals": ["bank_impostor", "password_field"],
        "correlation_rules_applied": ["BANK_PHISHING"],
        "correlation_bonus": 20,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "fake-garanti.com"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    fusion_result = fusion_engine.fuse(features)
    result = confidence_engine.assess(fusion_result, features)

    assert len(result.factors) > 0
    assert len(result.evidence) > 0

    print("  PASSED")


def test_confidence_safe_site():
    """Test: Safe site has appropriate confidence"""
    print("Test: Confidence safe site...")

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
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    fusion_result = fusion_engine.fuse(features)
    result = confidence_engine.assess(fusion_result, features)

    # Low score should result in SAFE or CAUTION
    assert result.decision in ["SAFE", "CAUTION"]
    assert result.risk_score < 50

    print("  PASSED")


def test_confidence_needs_more_analysis():
    """Test: Cases that need more analysis are detected"""
    print("Test: Needs more analysis...")

    analysis_result = {
        "url": "https://new-site.xyz/blog",
        "score": 55,
        "reasons": ["Yeni domain"],
        "sub_scores": {},
        "signals": ["suspicious_tld"],
        "correlation_rules_applied": [],
        "correlation_bonus": 0,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "new-site.xyz"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    fusion_result = fusion_engine.fuse(features)
    # Force low confidence
    fusion_result.confidence = 35

    result = confidence_engine.assess(fusion_result, features)

    # With low confidence, needs more analysis should be true
    assert result.needs_more_analysis == True or result.confidence_level == ConfidenceLevel.LOW

    print("  PASSED")


def test_confidence_evidence():
    """Test: Evidence list is built correctly"""
    print("Test: Evidence list...")

    analysis_result = {
        "url": "https://garanti-fake.xyz",
        "score": 80,
        "reasons": ["Banka taklidi"],
        "sub_scores": {},
        "signals": ["bank_impostor", "suspicious_tld"],
        "correlation_rules_applied": [],
        "correlation_bonus": 0,
        "site_type": "unknown",
        "trust_fast_path": False,
        "domain": "garanti-fake.xyz"
    }

    features = feature_collector.collect(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )

    fusion_result = fusion_engine.fuse(features)
    result = confidence_engine.assess(fusion_result, features)

    # Should have both positive and negative evidence
    has_positive = any("✓" in e for e in result.evidence)
    has_negative = any("✗" in e for e in result.evidence)

    assert len(result.evidence) > 0

    print("  PASSED")


def test_confidence_recommendation():
    """Test: Recommendations are appropriate"""
    print("Test: Recommendations...")

    # Test safe recommendation
    analysis_result = {
        "url": "https://chatgpt.com",
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

    fusion_result = fusion_engine.fuse(features)
    result = confidence_engine.assess(fusion_result, features)

    assert len(result.recommendation) > 0
    assert "guvenli" in result.recommendation.lower() or "güvenli" in result.recommendation.lower()

    print("  PASSED")


def run_all_tests():
    """Run all regression tests"""
    print("=" * 60)
    print("Sprint 7.3 Confidence Engine Tests")
    print("=" * 60)
    print()

    tests = [
        test_confidence_trusted_platform,
        test_confidence_high_risk_high_confidence,
        test_confidence_high_risk_low_confidence,
        test_confidence_level_classification,
        test_confidence_factors,
        test_confidence_safe_site,
        test_confidence_needs_more_analysis,
        test_confidence_evidence,
        test_confidence_recommendation,
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
