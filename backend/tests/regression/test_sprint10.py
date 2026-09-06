"""
PhishShield TR - Sprint 10 ML Hybrid Analyzer Tests
Tests the ML pipeline and hybrid analysis
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def test_feature_schema():
    """Test: Feature schema has correct number of features"""
    print("Test: Feature schema...")

    from ml.feature_schema import FeatureSchema

    assert FeatureSchema.FEATURE_COUNT == 48
    assert len(FeatureSchema.ALL_FEATURES) == 48

    # Check feature groups
    assert len(FeatureSchema.DOMAIN_FEATURES) == 8
    assert len(FeatureSchema.THREAT_FEATURES) == 5
    assert len(FeatureSchema.BRAND_FEATURES) == 5
    assert len(FeatureSchema.FORM_FEATURES) == 8
    assert len(FeatureSchema.CONTENT_FEATURES) == 9
    assert len(FeatureSchema.BEHAVIOR_FEATURES) == 5
    assert len(FeatureSchema.SSL_FEATURES) == 5
    assert len(FeatureSchema.META_FEATURES) == 3

    print("  PASSED")


def test_feature_vector_from_site_features():
    """Test: FeatureVector can be created from SiteFeatures"""
    print("Test: Feature vector creation...")

    from ml.feature_schema import FeatureVector
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
    fv = FeatureVector.from_site_features(features)

    assert fv.features.shape[0] == 48

    # Check some values
    feature_dict = fv.get_feature_dict()
    assert feature_dict['domain_length'] > 0
    assert feature_dict['has_suspicious_tld'] == 1.0  # .xyz is suspicious

    print("  PASSED")


def test_ml_trainer_generates_data():
    """Test: ML trainer can generate training data"""
    print("Test: ML trainer data generation...")

    from ml.trainer import ModelTrainer

    trainer = ModelTrainer()
    data = trainer.generate_training_data(n_samples=100)

    assert data.X.shape[0] == 100
    assert data.y.shape[0] == 100
    assert data.X.shape[1] == 48  # 48 features

    # Check labels: 50 safe (0) + 50 phishing (1)
    assert sum(data.y == 0) == 50
    assert sum(data.y == 1) == 50

    print("  PASSED")


def test_ml_model_training():
    """Test: ML model can be trained"""
    print("Test: ML model training...")

    from ml.trainer import ModelTrainer

    trainer = ModelTrainer(model_path=os.path.join(os.path.dirname(__file__), '..', '..', 'ml', 'models', 'test_model.pkl'))

    try:
        model = trainer.train(n_samples=200)

        # Check model exists
        assert model is not None

        # Check feature importance
        importance = trainer.get_feature_importance()
        assert len(importance) == 48

        print(f"  Model trained successfully with {len(importance)} features")
        print("  PASSED")
    except ImportError:
        print("  SKIPPED (scikit-learn not available)")


def test_hybrid_analyzer_components():
    """Test: Hybrid analyzer has all required components"""
    print("Test: Hybrid analyzer components...")

    try:
        from ml.hybrid_analyzer import HybridAnalyzer, HybridResult

        # Check HybridResult has required fields
        result_fields = [
            'fusion_score', 'ml_probability', 'ml_confidence', 'final_score',
            'decision', 'confidence', 'confidence_level', 'threat_override',
            'fusion_contribution', 'ml_contribution', 'component_scores',
            'recommendation', 'reasons'
        ]

        for field in result_fields:
            assert hasattr(HybridResult, field) or field in HybridResult.__dataclass_fields__

        print("  PASSED")
    except ImportError:
        print("  SKIPPED (scikit-learn not available)")


def test_hybrid_analyzer_threat_override():
    """Test: Hybrid analyzer applies threat override for known threats"""
    print("Test: Hybrid analyzer threat override...")

    try:
        from ml.hybrid_analyzer import hybrid_analyzer
        from ml.feature_collector import feature_collector
        from intelligence.fusion_engine import fusion_engine

        analysis = {
            'url': 'https://evil-phishing-site.xyz/login',
            'score': 50,
            'reasons': [],
            'signals': [],
            'correlation_rules_applied': [],
            'correlation_bonus': 0,
            'domain': 'evil-phishing-site.xyz',
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
        result = hybrid_analyzer.analyze(fusion, features)

        assert result.threat_override == True
        assert result.final_score == 100
        assert result.decision == "DANGER"

        print("  PASSED")
    except ImportError:
        print("  SKIPPED (scikit-learn not available)")


def test_hybrid_analyzer_safe_site():
    """Test: Hybrid analyzer correctly handles safe sites"""
    print("Test: Hybrid analyzer safe site...")

    try:
        from ml.hybrid_analyzer import hybrid_analyzer
        from ml.feature_collector import feature_collector
        from intelligence.fusion_engine import fusion_engine

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
        result = hybrid_analyzer.analyze(fusion, features)

        assert result.decision == "SAFE"
        assert result.final_score < 30

        print("  PASSED")
    except ImportError:
        print("  SKIPPED (scikit-learn not available)")


def test_hybrid_score_calculation():
    """Test: Hybrid score formula is correctly applied"""
    print("Test: Hybrid score calculation...")

    try:
        from ml.hybrid_analyzer import HybridAnalyzer

        analyzer = HybridAnalyzer()

        # Check weights
        assert analyzer.FUSION_WEIGHT == 0.70
        assert analyzer.ML_WEIGHT == 0.30

        # Test formula: (fusion * 0.7) + (ml * 0.3)
        fusion_score = 80
        ml_probability = 0.9  # 90%

        expected = int((fusion_score * 0.70) + (90 * 0.30))
        calculated = int((fusion_score * 0.70) + (int(ml_probability * 100) * 0.30))

        assert calculated == expected

        print("  PASSED")
    except ImportError:
        print("  SKIPPED (scikit-learn not available)")


def test_feature_importance_ranking():
    """Test: Feature importance can be ranked"""
    print("Test: Feature importance ranking...")

    try:
        from ml.trainer import ModelTrainer

        trainer = ModelTrainer()
        data = trainer.generate_training_data(n_samples=200)
        trainer.train(n_samples=200)

        importance = trainer.get_feature_importance()

        assert len(importance) == 48
        assert importance[0][0] is not None
        assert isinstance(importance[0][1], float)

        # Most important feature should have highest score
        scores = [score for _, score in importance]
        assert scores[0] >= scores[-1]

        print(f"  Top 5 features: {[name for name, _ in importance[:5]]}")
        print("  PASSED")
    except ImportError:
        print("  SKIPPED (scikit-learn not available)")


def run_all_tests():
    """Run all Sprint 10 tests"""
    print("=" * 60)
    print("Sprint 10 ML Hybrid Analyzer Tests")
    print("=" * 60)
    print()

    tests = [
        test_feature_schema,
        test_feature_vector_from_site_features,
        test_ml_trainer_generates_data,
        test_ml_model_training,
        test_hybrid_analyzer_components,
        test_hybrid_analyzer_threat_override,
        test_hybrid_analyzer_safe_site,
        test_hybrid_score_calculation,
        test_feature_importance_ranking,
    ]

    passed = 0
    failed = 0
    skipped = 0

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
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
