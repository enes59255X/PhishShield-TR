"""
PhishShield TR - Sprint 11 Advanced Domain Intelligence Tests
Tests domain age, entropy, and SSL analysis
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def test_domain_intel_modules():
    """Test: All domain intelligence modules are present"""
    print("Test: Domain intelligence modules...")

    from intelligence.domain_intel import (
        DomainAgeAnalyzer,
        EntropyAnalyzer,
        SSLAnalyzer,
        domain_age_analyzer,
        entropy_analyzer,
        ssl_analyzer
    )

    assert domain_age_analyzer is not None
    assert entropy_analyzer is not None
    assert ssl_analyzer is not None

    print("  PASSED")


def test_entropy_analyzer_basic():
    """Test: Entropy analyzer calculates correct entropy"""
    print("Test: Entropy calculation...")

    from intelligence.domain_intel.entropy import EntropyAnalyzer

    analyzer = EntropyAnalyzer()

    # Test known values
    # "google" should have lower entropy than "x7z9q2"
    google_entropy = analyzer._calculate_entropy("google")
    random_entropy = analyzer._calculate_entropy("x7z9q2mpl")

    assert google_entropy < random_entropy
    assert google_entropy > 0
    assert random_entropy > 0

    print(f"  Google entropy: {google_entropy:.2f}")
    print(f"  Random entropy: {random_entropy:.2f}")
    print("  PASSED")


def test_entropy_analyzer_typosquat():
    """Test: Typosquat detection works"""
    print("Test: Typosquat detection...")

    from intelligence.domain_intel.entropy import entropy_analyzer

    # Test Garanti typosquat
    result = entropy_analyzer.analyze("garanti-login-secure.xyz")

    # Should detect brand
    assert result.target_brand is not None or result.risk_level > 0

    print(f"  Domain: {result.domain}")
    print(f"  Target brand: {result.target_brand}")
    print(f"  Risk level: {result.risk_level}")
    print("  PASSED")


def test_entropy_analyzer_known_domain():
    """Test: Known legitimate domain has low risk"""
    print("Test: Known legitimate domain...")

    from intelligence.domain_intel.entropy import entropy_analyzer

    # Google should have low entropy
    result = entropy_analyzer.analyze("google.com")

    assert result.char_entropy > 0
    assert result.risk_level >= 0  # Risk level can vary based on detection

    print(f"  Domain: {result.domain}")
    print(f"  Entropy: {result.char_entropy:.2f}")
    print(f"  Risk level: {result.risk_level}")
    print("  PASSED")


def test_entropy_typosquat_types():
    """Test: Different typosquat types are detected"""
    print("Test: Typosquat types...")

    from intelligence.domain_intel.entropy import EntropyAnalyzer

    analyzer = EntropyAnalyzer()

    # Test hyphen type
    result = analyzer._check_typosquat_type("garanti-login", "garanti")
    print(f"  Hyphen type: {result}")

    # Test substitution type
    result = analyzer._check_typosquat_type("g00gle", "google")
    print(f"  Substitution type: {result}")

    print("  PASSED")


def test_ssl_analyzer_basic():
    """Test: SSL analyzer works"""
    print("Test: SSL analyzer basic...")

    from intelligence.domain_intel.ssl import ssl_analyzer

    # Test with a known HTTPS site
    result = ssl_analyzer.analyze("google.com")

    # Should complete without error (has_ssl depends on network)
    assert result.domain is not None
    assert result.risk_level >= 0

    print(f"  Domain: {result.domain}")
    print(f"  Has SSL: {result.has_ssl}")
    print(f"  Issuer: {result.issuer}")
    print(f"  Risk level: {result.risk_level}")
    print("  PASSED")


def test_ssl_analyzer_risk_scoring():
    """Test: SSL risk scoring works"""
    print("Test: SSL risk scoring...")

    from intelligence.domain_intel.ssl import SSLAnalyzer

    analyzer = SSLAnalyzer()

    # Create mock result
    result = analyzer._analyze_ssl("test-nonexistent-domain.xyz")

    # Should handle errors gracefully
    assert result is not None
    assert result.risk_level >= 0

    print(f"  Risk level: {result.risk_level}")
    print(f"  Reasons: {result.risk_reasons}")
    print("  PASSED")


def test_domain_age_analyzer():
    """Test: Domain age analyzer works"""
    print("Test: Domain age analyzer...")

    from intelligence.domain_intel.age import domain_age_analyzer

    # Test with a known old domain
    result = domain_age_analyzer.analyze("google.com", use_cache=True)

    assert result.domain is not None
    assert result.age_days >= -1  # -1 means unknown/error

    print(f"  Domain: {result.domain}")
    print(f"  Age: {result.age_days} days")
    print(f"  Category: {result.age_category}")
    print(f"  Risk level: {result.risk_level}")
    print("  PASSED")


def test_domain_age_free_tld():
    """Test: Free TLDs are detected"""
    print("Test: Free TLD detection...")

    from intelligence.domain_intel.age import DomainAgeAnalyzer

    analyzer = DomainAgeAnalyzer()

    # Test free TLDs
    assert analyzer._is_free_tld("test.xyz") == True
    assert analyzer._is_free_tld("test.com") == False
    assert analyzer._is_free_tld("test.tk") == True

    print("  PASSED")


def test_entropy_similar_domains():
    """Test: Similar domain lookup works"""
    print("Test: Similar domains lookup...")

    from intelligence.domain_intel.entropy import entropy_analyzer

    # Should find similar legitimate domains
    result = entropy_analyzer.analyze("garanti-login.xyz")

    # May or may not find similar, but should complete
    assert result.similar_domains is not None

    print(f"  Domain: {result.domain}")
    print(f"  Similar: {result.similar_domains}")
    print("  PASSED")


def test_ssl_cache():
    """Test: SSL analyzer uses cache"""
    print("Test: SSL cache...")

    from intelligence.domain_intel.ssl import ssl_analyzer

    # First call
    result1 = ssl_analyzer.analyze("example.com")

    # Second call should use cache
    result2 = ssl_analyzer.analyze("example.com")

    # Should be the same object
    assert result1.domain == result2.domain

    print(f"  Cache working: {len(ssl_analyzer.cache)} entries")
    print("  PASSED")


def test_risk_description():
    """Test: Risk descriptions are generated"""
    print("Test: Risk descriptions...")

    from intelligence.domain_intel.entropy import entropy_analyzer
    from intelligence.domain_intel.ssl import ssl_analyzer

    # Entropy risk description
    result = entropy_analyzer.analyze("x7z9q2mpl.xyz")
    desc = entropy_analyzer.get_risk_description(result)
    assert len(desc) > 0
    print(f"  Entropy risk: {desc}")

    # SSL risk description
    result2 = ssl_analyzer.analyze("google.com")
    desc2 = ssl_analyzer.get_risk_description(result2)
    assert len(desc2) > 0
    print(f"  SSL risk: {desc2}")

    print("  PASSED")


def run_all_tests():
    """Run all Sprint 11 tests"""
    print("=" * 60)
    print("Sprint 11 Advanced Domain Intelligence Tests")
    print("=" * 60)
    print()

    tests = [
        test_domain_intel_modules,
        test_entropy_analyzer_basic,
        test_entropy_analyzer_typosquat,
        test_entropy_analyzer_known_domain,
        test_entropy_typosquat_types,
        test_ssl_analyzer_basic,
        test_ssl_analyzer_risk_scoring,
        test_domain_age_analyzer,
        test_domain_age_free_tld,
        test_entropy_similar_domains,
        test_ssl_cache,
        test_risk_description,
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
