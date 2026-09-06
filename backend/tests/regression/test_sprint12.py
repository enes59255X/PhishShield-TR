"""
PhishShield TR - Sprint 12 Explanation Engine Tests
Tests for human-readable explanations and actionable advice
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def safe_print(text):
    """Print text with proper encoding for Windows"""
    if isinstance(text, str):
        # Replace emojis and special chars with placeholders for Windows console
        import re
        text = re.sub(r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF]', '[emoji]', text)
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode('ascii', 'replace').decode('ascii'))


def test_ml_explainer_import():
    """Test: ML Explainer can be imported"""
    print("Test: ML Explainer import...")

    from ml.explainer import MLExplainer, ml_explainer

    assert MLExplainer is not None
    assert ml_explainer is not None

    print("  PASSED")


def test_explanation_engine_import():
    """Test: Explanation Engine can be imported"""
    print("Test: Explanation Engine import...")

    from intelligence.explanation_engine import ExplanationEngine, explanation_engine

    assert ExplanationEngine is not None
    assert explanation_engine is not None

    print("  PASSED")


def test_explanation_engine_components():
    """Test: Explanation engine has required methods"""
    print("Test: Explanation engine components...")

    from intelligence.explanation_engine import ExplanationEngine

    engine = ExplanationEngine()

    assert hasattr(engine, 'explain')
    assert hasattr(engine, '_generate_headline')
    assert hasattr(engine, '_generate_immediate_advice')
    assert hasattr(engine, '_generate_recommended_actions')

    print("  PASSED")


def test_ml_explainer_explain():
    """Test: ML Explainer generates explanations"""
    print("Test: ML Explainer explain...")

    from ml.explainer import MLExplainer

    explainer = MLExplainer()

    # Create mock data
    result = explainer.explain(
        decision="DANGER",
        final_score=85,
        fusion_score=80,
        ml_probability=0.9,
        ml_confidence=0.95,
        component_scores={
            "threat": 100,
            "brand": 70,
            "form": 60,
            "domain": 30,
            "content": 20
        },
        features=None,
        reasons=["Tehdit eslesmesi", "Marka taklidi"]
    )

    assert result is not None
    assert result.summary is not None
    assert len(result.summary) > 0
    assert result.decision == "DANGER"

    safe_print(f"  Summary: {result.summary}")
    print("  PASSED")


def test_explanation_risk_levels():
    """Test: Risk levels are assigned correctly"""
    print("Test: Risk level assignment...")

    from ml.explainer import MLExplainer

    explainer = MLExplainer()

    # Test different scores
    result_safe = explainer.explain(
        decision="SAFE",
        final_score=15,
        fusion_score=10,
        ml_probability=0.1,
        ml_confidence=0.9,
        component_scores={},
        features=None,
        reasons=[]
    )

    result_danger = explainer.explain(
        decision="DANGER",
        final_score=90,
        fusion_score=85,
        ml_probability=0.95,
        ml_confidence=0.98,
        component_scores={},
        features=None,
        reasons=["Tehdit eslesmesi"]
    )

    assert result_safe.risk_level in ["SAFE", "LOW", "MEDIUM"]
    assert result_danger.risk_level in ["HIGH", "CRITICAL"]

    print(f"  Safe risk: {result_safe.risk_level}")
    print(f"  Danger risk: {result_danger.risk_level}")
    print("  PASSED")


def test_explanation_components():
    """Test: Component explanations are generated"""
    print("Test: Component explanations...")

    from ml.explainer import MLExplainer

    explainer = MLExplainer()

    result = explainer.explain(
        decision="DANGER",
        final_score=85,
        fusion_score=80,
        ml_probability=0.9,
        ml_confidence=0.95,
        component_scores={
            "threat": 100,
            "brand": 70,
            "form": 60,
            "domain": 30,
            "content": 20
        },
        features=None,
        reasons=["Tehdit eslesmesi"]
    )

    # Check that explanations exist for each component
    assert result.threat_intel_explanation is not None
    assert result.brand_explanation is not None
    assert result.form_explanation is not None
    assert result.domain_explanation is not None
    assert result.content_explanation is not None
    assert result.ml_explanation is not None

    print(f"  Threat: {result.threat_intel_explanation[:50]}...")
    print(f"  ML: {result.ml_explanation[:50]}...")
    print("  PASSED")


def test_actionable_advice():
    """Test: Actionable advice is generated"""
    print("Test: Actionable advice...")

    from ml.explainer import MLExplainer

    explainer = MLExplainer()

    # Test danger decision
    result = explainer.explain(
        decision="DANGER",
        final_score=85,
        fusion_score=80,
        ml_probability=0.9,
        ml_confidence=0.95,
        component_scores={},
        features=None,
        reasons=["Tehdit eslesmesi"]
    )

    assert len(result.actionable_advice) > 0
    assert any("girmeyin" in advice.lower() or "verilmeyin" in advice.lower()
               for advice in result.actionable_advice)

    safe_print(f"  Advice: {result.actionable_advice[0]}")
    print("  PASSED")


def test_feature_explanations():
    """Test: Feature explanations are generated"""
    print("Test: Feature explanations...")

    from ml.explainer import MLExplainer

    explainer = MLExplainer()

    result = explainer.explain(
        decision="CAUTION",
        final_score=55,
        fusion_score=50,
        ml_probability=0.6,
        ml_confidence=0.7,
        component_scores={},
        features=None,
        reasons=[]
    )

    # Top risk and safe features should be generated
    assert hasattr(result, 'top_risk_features')
    assert hasattr(result, 'top_safe_features')

    print(f"  Top risk features: {len(result.top_risk_features)}")
    print(f"  Top safe features: {len(result.top_safe_features)}")
    print("  PASSED")


def test_score_breakdown():
    """Test: Score breakdown is generated"""
    print("Test: Score breakdown...")

    from ml.explainer import MLExplainer

    explainer = MLExplainer()

    result = explainer.explain(
        decision="DANGER",
        final_score=85,
        fusion_score=80,
        ml_probability=0.9,
        ml_confidence=0.95,
        component_scores={
            "threat": 100,
            "brand": 70,
            "form": 60,
            "domain": 30,
            "content": 20
        },
        features=None,
        reasons=[]
    )

    assert result.score_breakdown is not None
    assert "final_score" in result.score_breakdown
    assert "fusion_score" in result.score_breakdown
    assert result.score_breakdown["final_score"] == 85

    print(f"  Breakdown: {result.score_breakdown}")
    print("  PASSED")


def test_explanation_engine_explain():
    """Test: Full Explanation Engine explain method"""
    print("Test: Explanation Engine explain...")

    from intelligence.explanation_engine import ExplanationEngine
    from ml.features import (
        SiteFeatures, DomainFeatures, ThreatFeatures,
        BrandFeatures, FormFeatures, ContentFeatures
    )

    engine = ExplanationEngine()

    # Create mock features with proper structure
    features = SiteFeatures()
    features.threat.matched = True
    features.threat.source = "openphish"
    features.threat.confidence = 0.95
    features.brand.is_impostor = True
    features.brand.brand_name = "Garanti"
    features.brand.similarity_score = 0.85
    features.brand.brand_category = "BANKING"
    features.form.has_external_submit = True
    features.form.has_password_field = True
    features.form.has_credential_fields = True
    features.form.external_domain = "http://evil.com/submit"
    features.domain_features.is_suspicious_tld = False
    features.domain_features.is_new_domain = True
    features.domain_features.tld = "xyz"
    features.content.has_urgency = True

    # Create mock fusion result
    class MockFusionResult:
        def __init__(self):
            self.final_score = 75
            self.decision = "DANGER"
            self.confidence = 80
            self.threat_score = 100
            self.brand_score = 70
            self.form_score = 50
            self.domain_score = 30
            self.content_score = 20
            self.rule_score = 0
            self.indicators = ["Tehdit eslesmesi"]
            self.threat_patterns = ["Banka kimlik avi"]
            self.weights = {}

    # Create mock hybrid result
    class MockHybridResult:
        def __init__(self):
            self.decision = "DANGER"
            self.final_score = 75
            self.ml_probability = 0.85
            self.ml_confidence = 0.9
            self.confidence = 85
            self.threat_override = True
            self.fusion_contribution = 1.0
            self.ml_contribution = 0.0

    fusion = MockFusionResult()
    hybrid = MockHybridResult()

    result = engine.explain(fusion, hybrid, features)

    assert result is not None
    assert result.decision == "DANGER"
    assert result.final_score == 75
    assert result.headline is not None
    assert result.summary is not None

    safe_print(f"  Headline: {result.headline}")
    safe_print(f"  Summary: {result.summary[:60]}...")
    print("  PASSED")


def test_explanation_red_flags():
    """Test: Red flags are identified correctly"""
    print("Test: Red flags identification...")

    from intelligence.explanation_engine import ExplanationEngine
    from ml.features import SiteFeatures

    engine = ExplanationEngine()

    # Create proper features
    features = SiteFeatures()
    features.threat.matched = True
    features.threat.source = "openphish"
    features.threat.confidence = 0.9
    features.brand.is_impostor = True
    features.brand.brand_name = "Garanti"
    features.brand.similarity_score = 0.9
    features.brand.brand_category = "BANKING"
    features.form.has_external_submit = True
    features.form.has_password_field = True
    features.form.has_credential_fields = True
    features.form.hidden_field_count = 3
    features.form.external_domain = "http://malicious.com/post"
    features.domain_features.is_suspicious_tld = True
    features.domain_features.is_new_domain = True
    features.domain_features.is_ip_based = False
    features.domain_features.is_punycode = False
    features.domain_features.hyphen_count = 4
    features.domain_features.subdomain_count = 2
    features.domain_features.has_https = False
    features.domain_features.tld = "xyz"
    features.content.has_urgency = True
    features.content.has_sms_style = True
    features.content.bank_word_count = 6
    features.content.reward_word_count = 2

    class MockFusionResult:
        def __init__(self):
            self.final_score = 80
            self.decision = "DANGER"
            self.confidence = 85
            self.threat_score = 100
            self.brand_score = 70
            self.form_score = 60
            self.domain_score = 40
            self.content_score = 30
            self.rule_score = 0
            self.indicators = []
            self.threat_patterns = []
            self.weights = {}

    class MockHybridResult:
        def __init__(self):
            self.decision = "DANGER"
            self.final_score = 80
            self.ml_probability = 0.9
            self.ml_confidence = 0.95
            self.confidence = 85
            self.threat_override = False
            self.fusion_contribution = 0.7
            self.ml_contribution = 0.3

    result = engine.explain(MockFusionResult(), MockHybridResult(), features)

    assert len(result.red_flags) > 0
    assert len(result.recommended_actions) > 0

    print(f"  Red flags found: {len(result.red_flags)}")
    for flag in result.red_flags[:3]:
        print(f"    - {flag}")
    print("  PASSED")


def test_component_explanations():
    """Test: All component explanations are generated"""
    print("Test: Component explanations...")

    from intelligence.explanation_engine import ExplanationEngine
    from ml.features import SiteFeatures

    engine = ExplanationEngine()

    # Create proper features
    features = SiteFeatures()
    features.threat.matched = False
    features.threat.source = None
    features.threat.confidence = 0.0
    features.brand.is_impostor = False
    features.brand.brand_name = None
    features.brand.similarity_score = 0.0
    features.brand.brand_category = None
    features.form.has_external_submit = False
    features.form.has_password_field = True
    features.form.has_credential_fields = True
    features.form.hidden_field_count = 0
    features.form.external_domain = None
    features.domain_features.is_suspicious_tld = True
    features.domain_features.is_new_domain = True
    features.domain_features.is_ip_based = False
    features.domain_features.is_punycode = False
    features.domain_features.hyphen_count = 1
    features.domain_features.subdomain_count = 1
    features.domain_features.has_https = True
    features.domain_features.tld = "xyz"
    features.content.has_urgency = False
    features.content.has_sms_style = False
    features.content.bank_word_count = 1
    features.content.cargo_word_count = 0
    features.content.reward_word_count = 0

    class MockFusionResult:
        def __init__(self):
            self.final_score = 60
            self.decision = "CAUTION"
            self.confidence = 70
            self.threat_score = 0
            self.brand_score = 50
            self.form_score = 40
            self.domain_score = 30
            self.content_score = 20
            self.rule_score = 10
            self.indicators = []
            self.threat_patterns = []
            self.weights = {}

    class MockHybridResult:
        def __init__(self):
            self.decision = "CAUTION"
            self.final_score = 60
            self.ml_probability = 0.6
            self.ml_confidence = 0.7
            self.confidence = 70
            self.threat_override = False
            self.fusion_contribution = 0.7
            self.ml_contribution = 0.3

    result = engine.explain(MockFusionResult(), MockHybridResult(), features)

    # Check all component explanations exist
    assert result.threat_intel is not None
    assert result.brand_protection is not None
    assert result.form_behavior is not None
    assert result.domain_analysis is not None
    assert result.content_analysis is not None
    assert result.ml_analysis is not None

    print(f"  Threat intel: {result.threat_intel.summary}")
    print(f"  Brand: {result.brand_protection.summary}")
    print(f"  Form: {result.form_behavior.summary}")
    print("  PASSED")


def run_all_tests():
    """Run all Sprint 12 tests"""
    print("=" * 60)
    print("Sprint 12 Explanation Engine Tests")
    print("=" * 60)

    tests = [
        test_ml_explainer_import,
        test_explanation_engine_import,
        test_explanation_engine_components,
        test_ml_explainer_explain,
        test_explanation_risk_levels,
        test_explanation_components,
        test_actionable_advice,
        test_feature_explanations,
        test_score_breakdown,
        test_explanation_engine_explain,
        test_explanation_red_flags,
        test_component_explanations,
    ]

    passed = 0
    failed = 0
    skipped = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  FAILED: {e}")
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
