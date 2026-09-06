"""
PhishShield TR - Sprint 6 Regression Tests
Tests ML pipeline components
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from ml.extractor import feature_extractor
from ml.schema import get_feature_names, get_feature_schema


def test_feature_schema():
    """Test: Feature schema is correctly defined"""
    print("Test: Feature schema...")
    
    features = get_feature_names()
    assert len(features) > 30, f"Should have >30 features, got {len(features)}"
    assert "url_length" in features, "Should have url_length feature"
    assert "brand_similarity" in features, "Should have brand_similarity feature"
    assert "has_password_field" in features, "Should have has_password_field feature"
    
    print("  PASSED")


def test_feature_extraction():
    """Test: Feature extraction from analysis result"""
    print("Test: Feature extraction...")
    
    # Mock analysis result
    analysis_result = {
        "url": "https://garanti-login-secure.xyz/login",
        "score": 75,
        "risk_level": "Yuksek Risk",
        "reasons": ["Supheli domain", "Banka ismi bulundu"],
        "sub_scores": {
            "js_obfuscation": 15,
            "ssl_cert": 80
        }
    }
    
    brand_result = {
        "is_impostor": True,
        "brand_name": "Garanti BBVA",
        "brand_category": "BANKING",
        "similarity_score": 0.75,
        "match_type": "substring"
    }
    
    form_result = {
        "has_login_form": True,
        "has_password_field": True,
        "has_external_submit": True,
        "external_domain": "evil.com",
        "hidden_fields": ["csrf"],
        "form_count": 1
    }
    
    threat_result = {
        "is_threat": False
    }
    
    # Extract features
    features = feature_extractor.extract(
        url=analysis_result["url"],
        analysis_result=analysis_result,
        brand_result=brand_result,
        form_result=form_result,
        threat_result=threat_result
    )
    
    # Verify key features
    assert features["url_length"] > 0, "Should extract url_length"
    assert features["has_brand_match"] == True, "Should detect brand match"
    assert features["is_impostor"] == True, "Should detect impostor"
    assert features["has_password_field"] == True, "Should detect password field"
    assert features["has_external_submit"] == True, "Should detect external submit"
    assert features["domain_length"] > 0, "Should extract domain length"
    
    print("  PASSED")


def test_feature_vector():
    """Test: Feature vector conversion"""
    print("Test: Feature vector conversion...")
    
    features = {
        "url_length": 50,
        "domain_length": 20,
        "subdomain_count": 2,
        "has_brand_match": True,
        "has_password_field": True,
        "is_impostor": True
    }
    
    vector = feature_extractor.to_feature_vector(features)
    
    assert len(vector) > 0, "Should produce vector"
    assert all(isinstance(v, float) for v in vector), "All values should be floats"
    
    print("  PASSED")


def test_domain_features():
    """Test: Domain feature extraction"""
    print("Test: Domain features...")
    
    analysis_result = {
        "url": "https://garanti-login-secure2026.xyz/very/long/path",
        "score": 50,
        "reasons": [],
        "sub_scores": {}
    }
    
    features = feature_extractor.extract(
        url=analysis_result["url"],
        analysis_result=analysis_result
    )
    
    assert features["domain_length"] > 0, "Should extract domain length"
    assert features["has_underscore"] == False, "garanti-login-secure2026.xyz has no underscore"
    assert features["is_suspicious_tld"] == True, ".xyz is suspicious TLD"
    assert features["hyphen_count"] > 0, "Should count hyphens"
    
    print("  PASSED")


def test_brand_features():
    """Test: Brand feature extraction"""
    print("Test: Brand features...")
    
    analysis_result = {
        "url": "https://fake-akbank.com",
        "score": 60,
        "reasons": [],
        "sub_scores": {}
    }
    
    brand_result = {
        "is_impostor": True,
        "brand_name": "Akbank",
        "brand_category": "BANKING",
        "similarity_score": 0.85,
        "match_type": "substring"
    }
    
    features = feature_extractor.extract(
        url=analysis_result["url"],
        analysis_result=analysis_result,
        brand_result=brand_result
    )
    
    assert features["has_brand_match"] == True
    assert features["is_bank_brand"] == True, "Should be bank brand"
    assert features["is_impostor"] == True, "Should be impostor"
    assert features["brand_similarity"] == 0.85
    
    print("  PASSED")


def run_all_tests():
    """Run all regression tests"""
    print("=" * 60)
    print("Sprint 6 ML Pipeline Regression Tests")
    print("=" * 60)
    print()
    
    tests = [
        test_feature_schema,
        test_feature_extraction,
        test_feature_vector,
        test_domain_features,
        test_brand_features,
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
