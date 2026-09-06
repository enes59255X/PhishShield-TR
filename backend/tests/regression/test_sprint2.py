"""
PhishShield TR - Sprint 2 Regression Tests
Decision Integration + Trust Intelligence

These tests verify the Sprint 2 success criteria:
- Trusted platforms (chatgpt, github, etc.) -> SAFE, risk=0
- Government domains -> SAFE, OFFICIAL_GOVERNMENT
- Attack patterns (fake bank sites) -> DANGER, risk>=90
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

os.environ['PYTHONIOENCODING'] = 'utf-8'

# Force UTF-8 output on Windows
import io
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from analysis.analyzer import analyze_url


TRUSTED_PLATFORM_TESTS = [
    ("https://chatgpt.com", "SAFE", 0),
    ("https://openai.com", "SAFE", 0),
    ("https://github.com", "SAFE", 0),
    ("https://linkedin.com", "SAFE", 0),
    ("https://whatsapp.com", "SAFE", 0),
    ("https://youtube.com", "SAFE", 0),
    ("https://google.com", "SAFE", 0),
    ("https://microsoft.com", "SAFE", 0),
    ("https://apple.com", "SAFE", 0),
    ("https://claude.ai", "SAFE", 0),
]

GOVERNMENT_TESTS = [
    ("https://turkiye.gov.tr", "SAFE", 0),
    ("https://eba.gov.tr", "SAFE", 0),
    ("https://gib.gov.tr", "SAFE", 0),
]

DANGER_TESTS = [
    ("https://garanti-login.xyz", "DANGER", 90),
    ("https://akbank-secure.com", "DANGER", 90),
    ("https://edevlet-login.click", "DANGER", 90),
    ("https://fake-garanti.xyz/login", "DANGER", 80),
    ("https://isbank-giris.com", "DANGER", 90),
]


def test_trusted_platforms():
    """Test that trusted platforms are correctly classified as SAFE"""
    print("=" * 60)
    print("TESTING: Trusted Platforms")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for url, expected_decision, expected_score in TRUSTED_PLATFORM_TESTS:
        try:
            result = analyze_url(url)
            decision = result.get("status", "")
            score = result.get("risk_score", -1)
            site_type = result.get("site_type", "")
            confidence = result.get("confidence", 0)
            
            # Check decision
            decision_ok = "GÜVENLİ" in decision or "SAFE" in decision
            
            # Check score
            score_ok = score == expected_score
            
            # Check site type
            type_ok = site_type == "TRUSTED_PLATFORM"
            
            # Check confidence (should be high for trusted platforms)
            confidence_ok = confidence >= 0.90
            
            if decision_ok and score_ok and type_ok and confidence_ok:
                print(f"[PASS] {url}")
                print(f"   Decision: {decision}, Score: {score}, Type: {site_type}, Confidence: {confidence:.2f}")
                passed += 1
            else:
                print(f"[FAIL] {url}")
                print(f"   Expected: {expected_decision}, Score: {expected_score}, Type: TRUSTED_PLATFORM")
                print(f"   Got: {decision}, Score: {score}, Type: {site_type}, Confidence: {confidence:.2f}")
                if not decision_ok:
                    print(f"   ERROR: Wrong decision")
                if not score_ok:
                    print(f"   ERROR: Wrong score")
                if not type_ok:
                    print(f"   ERROR: Wrong site type")
                if not confidence_ok:
                    print(f"   ERROR: Low confidence")
                failed += 1
        except Exception as e:
            print(f"[ERROR] {url} - {e}")
            failed += 1
    
    print()
    return passed, failed


def test_government_domains():
    """Test that government domains are correctly classified"""
    print("=" * 60)
    print("TESTING: Government Domains")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for url, expected_decision, expected_score in GOVERNMENT_TESTS:
        try:
            result = analyze_url(url)
            decision = result.get("status", "")
            score = result.get("risk_score", -1)
            site_type = result.get("site_type", "")
            
            decision_ok = "GÜVENLİ" in decision or "SAFE" in decision
            score_ok = score == expected_score
            type_ok = site_type == "OFFICIAL_GOVERNMENT"
            
            if decision_ok and score_ok and type_ok:
                print(f"[PASS] {url}")
                print(f"   Decision: {decision}, Score: {score}, Type: {site_type}")
                passed += 1
            else:
                print(f"[FAIL] {url}")
                print(f"   Expected: {expected_decision}, Score: {expected_score}, Type: OFFICIAL_GOVERNMENT")
                print(f"   Got: {decision}, Score: {score}, Type: {site_type}")
                failed += 1
        except Exception as e:
            print(f"[ERROR] {url} - {e}")
            failed += 1
    
    print()
    return passed, failed


def test_danger_sites():
    """Test that attack patterns are correctly classified as DANGER"""
    print("=" * 60)
    print("TESTING: Attack Patterns (Danger Sites)")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for url, expected_decision, min_score in DANGER_TESTS:
        try:
            result = analyze_url(url)
            decision = result.get("status", "")
            score = result.get("risk_score", -1)
            site_type = result.get("site_type", "")
            
            decision_ok = "TEHLİKELİ" in decision or "DANGER" in decision
            score_ok = score >= min_score
            type_ok = site_type == "BRAND_IMPERSONATION"
            
            if decision_ok and score_ok and type_ok:
                print(f"[PASS] {url}")
                print(f"   Decision: {decision}, Score: {score}, Type: {site_type}")
                passed += 1
            else:
                print(f"[FAIL] {url}")
                print(f"   Expected: DANGER, Score >= {min_score}, Type: BRAND_IMPERSONATION")
                print(f"   Got: {decision}, Score: {score}, Type: {site_type}")
                if not decision_ok:
                    print(f"   ERROR: Wrong decision")
                if not score_ok:
                    print(f"   ERROR: Score too low")
                if not type_ok:
                    print(f"   ERROR: Wrong site type")
                failed += 1
        except Exception as e:
            print(f"[ERROR] {url} - {e}")
            failed += 1
    
    print()
    return passed, failed


def run_all_tests():
    """Run all regression tests"""
    print()
    print("=" * 60)
    print("PHISHSHIELD TR - SPRINT 2 REGRESSION TESTS")
    print("=" * 60)
    print()
    
    tp_passed, tp_failed = test_trusted_platforms()
    gov_passed, gov_failed = test_government_domains()
    dng_passed, dng_failed = test_danger_sites()
    
    total_passed = tp_passed + gov_passed + dng_passed
    total_failed = tp_failed + gov_failed + dng_failed
    total_tests = len(TRUSTED_PLATFORM_TESTS) + len(GOVERNMENT_TESTS) + len(DANGER_TESTS)
    
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Trusted Platforms: {tp_passed}/{len(TRUSTED_PLATFORM_TESTS)} passed")
    print(f"Government Domains: {gov_passed}/{len(GOVERNMENT_TESTS)} passed")
    print(f"Danger Sites: {dng_passed}/{len(DANGER_TESTS)} passed")
    print()
    print(f"TOTAL: {total_passed}/{total_tests} passed, {total_failed} failed")
    print("=" * 60)
    
    if total_failed == 0:
        print("ALL TESTS PASSED!")
        return 0
    else:
        print(f"{total_failed} TESTS FAILED")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
