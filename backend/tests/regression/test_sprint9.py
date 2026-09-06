"""
PhishShield TR - Sprint 9 Intelligence Fusion Tests
Tests the complete intelligence pipeline from features to decision
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import asyncio


def test_intelligence_pipeline_components():
    """Test: All pipeline components are present and functional"""
    print("Test: Intelligence pipeline components...")

    from intelligence.confidence_engine import confidence_engine, ConfidenceEngine, ConfidenceLevel
    from intelligence.fusion_engine import fusion_engine, FusionEngine
    from ml.feature_collector import feature_collector, FeatureCollector

    assert confidence_engine is not None
    assert fusion_engine is not None
    assert feature_collector is not None

    print("  PASSED")


def test_fusion_engine_bank_phishing():
    """Test: Fusion engine correctly identifies bank phishing"""
    print("Test: Fusion engine bank phishing...")

    from intelligence.fusion_engine import fusion_engine
    from ml.feature_collector import feature_collector

    analysis = {
        'url': 'https://garanti-login-secure.xyz/online',
        'score': 85,
        'reasons': ['Banka taklidi'],
        'signals': ['bank_impostor', 'password_field', 'suspicious_tld', 'threat_intel_match'],
        'correlation_rules_applied': ['BANK_PHISHING'],
        'correlation_bonus': 25,
        'domain': 'garanti-login-secure.xyz',
        'site_type': 'unknown',
        'trust_fast_path': False,
        'threat_intel': {
            'matched': True,
            'source': 'openphish',
            'category': 'phishing',
            'confidence': 0.95
        }
    }

    features = feature_collector.collect(analysis['url'], analysis)
    result = fusion_engine.fuse(features)

    # Should have high threat and brand scores
    assert result.threat_score >= 90
    assert result.brand_score >= 70
    assert result.final_score >= 60

    print("  PASSED")


def test_fusion_engine_trusted_platform():
    """Test: Fusion engine fast path for trusted platforms"""
    print("Test: Fusion engine trusted platform...")

    from intelligence.fusion_engine import fusion_engine
    from ml.feature_collector import feature_collector

    analysis = {
        'url': 'https://accounts.google.com',
        'score': 5,
        'reasons': [],
        'signals': [],
        'correlation_rules_applied': [],
        'correlation_bonus': 0,
        'domain': 'accounts.google.com',
        'site_type': 'login',
        'trust_fast_path': True
    }

    features = feature_collector.collect(analysis['url'], analysis)
    result = fusion_engine.fuse(features)

    assert result.final_score == 0
    assert result.decision == "SAFE"
    assert result.confidence >= 90

    print("  PASSED")


def test_confidence_engine_danger():
    """Test: Confidence engine correctly identifies danger"""
    print("Test: Confidence engine danger detection...")

    from intelligence.confidence_engine import confidence_engine
    from intelligence.fusion_engine import fusion_engine
    from ml.feature_collector import feature_collector

    analysis = {
        'url': 'https://garanti-login-secure.xyz/online',
        'score': 85,
        'reasons': ['Banka taklidi'],
        'signals': ['bank_impostor', 'password_field', 'suspicious_tld', 'threat_intel_match'],
        'correlation_rules_applied': ['BANK_PHISHING'],
        'correlation_bonus': 25,
        'domain': 'garanti-login-secure.xyz',
        'site_type': 'unknown',
        'trust_fast_path': False,
        'threat_intel': {
            'matched': True,
            'source': 'openphish',
            'category': 'phishing',
            'confidence': 0.95
        }
    }

    features = feature_collector.collect(analysis['url'], analysis)
    fusion = fusion_engine.fuse(features)
    result = confidence_engine.assess(fusion, features)

    assert result.decision in ["DANGER", "CAUTION"]
    assert result.confidence >= 70
    assert result.risk_score >= 50

    print("  PASSED")


def test_confidence_engine_safe():
    """Test: Confidence engine correctly identifies safe"""
    print("Test: Confidence engine safe detection...")

    from intelligence.confidence_engine import confidence_engine
    from intelligence.fusion_engine import fusion_engine
    from ml.feature_collector import feature_collector

    analysis = {
        'url': 'https://accounts.google.com',
        'score': 5,
        'reasons': [],
        'signals': [],
        'correlation_rules_applied': [],
        'correlation_bonus': 0,
        'domain': 'accounts.google.com',
        'site_type': 'login',
        'trust_fast_path': True
    }

    features = feature_collector.collect(analysis['url'], analysis)
    fusion = fusion_engine.fuse(features)
    result = confidence_engine.assess(fusion, features)

    assert result.decision == "SAFE"
    assert result.risk_score < 30

    print("  PASSED")


def test_component_scores():
    """Test: Component scores are calculated correctly"""
    print("Test: Component scores calculation...")

    from intelligence.fusion_engine import fusion_engine
    from ml.feature_collector import feature_collector

    analysis = {
        'url': 'https://garanti-login-secure.xyz/online',
        'score': 85,
        'reasons': ['Banka taklidi'],
        'signals': ['bank_impostor', 'password_field', 'suspicious_tld', 'threat_intel_match'],
        'correlation_rules_applied': ['BANK_PHISHING'],
        'correlation_bonus': 25,
        'domain': 'garanti-login-secure.xyz',
        'site_type': 'unknown',
        'trust_fast_path': False,
        'threat_intel': {
            'matched': True,
            'source': 'openphish',
            'category': 'phishing',
            'confidence': 0.95
        }
    }

    features = feature_collector.collect(analysis['url'], analysis)
    result = fusion_engine.fuse(features)

    # Check that all component scores exist
    assert hasattr(result, 'threat_score')
    assert hasattr(result, 'brand_score')
    assert hasattr(result, 'form_score')
    assert hasattr(result, 'domain_score')
    assert hasattr(result, 'content_score')
    assert hasattr(result, 'rule_score')

    # Threat should be high due to threat_intel match
    assert result.threat_score >= 90

    # Brand should be high due to bank_impostor signal
    assert result.brand_score >= 70

    print("  PASSED")


def test_confidence_levels():
    """Test: Confidence levels are properly classified"""
    print("Test: Confidence level classification...")

    from intelligence.confidence_engine import ConfidenceEngine, ConfidenceLevel

    engine = ConfidenceEngine()

    assert engine._get_confidence_level(95) == ConfidenceLevel.VERY_HIGH
    assert engine._get_confidence_level(80) == ConfidenceLevel.HIGH
    assert engine._get_confidence_level(60) == ConfidenceLevel.MEDIUM
    assert engine._get_confidence_level(40) == ConfidenceLevel.LOW
    assert engine._get_confidence_level(15) == ConfidenceLevel.VERY_LOW

    print("  PASSED")


def test_evidence_list():
    """Test: Evidence list is built correctly"""
    print("Test: Evidence list building...")

    from intelligence.confidence_engine import confidence_engine
    from intelligence.fusion_engine import fusion_engine
    from ml.feature_collector import feature_collector

    analysis = {
        'url': 'https://garanti-login-secure.xyz/online',
        'score': 85,
        'reasons': ['Banka taklidi'],
        'signals': ['bank_impostor', 'password_field', 'suspicious_tld', 'threat_intel_match'],
        'correlation_rules_applied': ['BANK_PHISHING'],
        'correlation_bonus': 25,
        'domain': 'garanti-login-secure.xyz',
        'site_type': 'unknown',
        'trust_fast_path': False,
        'threat_intel': {
            'matched': True,
            'source': 'openphish',
            'category': 'phishing',
            'confidence': 0.95
        }
    }

    features = feature_collector.collect(analysis['url'], analysis)
    fusion = fusion_engine.fuse(features)
    result = confidence_engine.assess(fusion, features)

    # Should have evidence list
    assert len(result.evidence) > 0

    # Should have threat match evidence
    has_threat_evidence = any('Tehdit veritabaninda' in e for e in result.evidence)
    assert has_threat_evidence

    print("  PASSED")


def test_recommendations():
    """Test: Recommendations are provided"""
    print("Test: Recommendations...")

    from intelligence.confidence_engine import confidence_engine
    from intelligence.fusion_engine import fusion_engine
    from ml.feature_collector import feature_collector

    analysis = {
        'url': 'https://garanti-login-secure.xyz/online',
        'score': 85,
        'reasons': ['Banka taklidi'],
        'signals': ['bank_impostor', 'password_field', 'suspicious_tld', 'threat_intel_match'],
        'correlation_rules_applied': ['BANK_PHISHING'],
        'correlation_bonus': 25,
        'domain': 'garanti-login-secure.xyz',
        'site_type': 'unknown',
        'trust_fast_path': False,
        'threat_intel': {
            'matched': True,
            'source': 'openphish',
            'category': 'phishing',
            'confidence': 0.95
        }
    }

    features = feature_collector.collect(analysis['url'], analysis)
    fusion = fusion_engine.fuse(features)
    result = confidence_engine.assess(fusion, features)

    # Should have recommendation
    assert result.recommendation is not None
    assert len(result.recommendation) > 0

    print("  PASSED")


def run_all_tests():
    """Run all Sprint 9 tests"""
    print("=" * 60)
    print("Sprint 9 Intelligence Fusion Tests")
    print("=" * 60)
    print()

    tests = [
        test_intelligence_pipeline_components,
        test_fusion_engine_bank_phishing,
        test_fusion_engine_trusted_platform,
        test_confidence_engine_danger,
        test_confidence_engine_safe,
        test_component_scores,
        test_confidence_levels,
        test_evidence_list,
        test_recommendations,
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
