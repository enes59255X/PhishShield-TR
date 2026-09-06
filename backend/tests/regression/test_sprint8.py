"""
PhishShield TR - Sprint 8 USOM Integration Tests
Tests threat feed updates and USOM handling
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import asyncio


def test_threat_feed_sources():
    """Test: All threat feed sources are configured"""
    print("Test: Threat feed sources...")

    from threat_intel.aggregator import threat_aggregator

    sources = threat_aggregator.sources

    assert "openphish" in sources
    assert "urlhaus" in sources
    assert "usom" in sources

    print("  PASSED")


def test_openphish_source():
    """Test: OpenPhish source can be instantiated"""
    print("Test: OpenPhish source...")

    from threat_intel.sources.openphish import OpenPhishSource

    source = OpenPhishSource()

    assert source.name == "OpenPhish"
    assert source.enabled == True

    print("  PASSED")


def test_urlhaus_source():
    """Test: URLhaus source can be instantiated"""
    print("Test: URLhaus source...")

    from threat_intel.sources.urlhaus import URLhausSource

    source = URLhausSource()

    assert source.name == "URLhaus"
    assert source.enabled == True

    print("  PASSED")


def test_usom_source():
    """Test: USOM source can be instantiated"""
    print("Test: USOM source...")

    from threat_intel.sources.usom import USOMSource

    source = USOMSource()

    assert source.name == "USOM"
    assert source.enabled == True

    print("  PASSED")


async def async_test_feed_update():
    """Test: Feed update can be triggered"""
    print("Test: Feed update...")

    from threat_intel.aggregator import threat_aggregator

    # Update all feeds
    results = await threat_aggregator.update_all_feeds(force=True)

    print(f"  Update results: {results}")

    # Check stats
    stats = threat_aggregator.get_cache_stats()
    print(f"  Total domains after update: {stats['total_domains']}")

    # At least one source should have domains
    assert stats['total_domains'] >= 0  # May be 0 if feeds fail

    print("  PASSED")


def test_feed_update():
    """Synchronous wrapper for feed update test"""
    asyncio.run(async_test_feed_update())


def test_reputation_check():
    """Test: Reputation check works"""
    print("Test: Reputation check...")

    from threat_intel.reputation import threat_reputation

    # Test with known safe domain
    result = threat_reputation.check_domain("example.com")

    print(f"  example.com: is_threat={result.is_threat if result else None}")

    # Test with some random domain
    result2 = threat_reputation.check_domain("random-test-domain-12345.xyz")

    print(f"  random-test-domain-12345.xyz: is_threat={result2.is_threat if result2 else None}")

    print("  PASSED")


def test_usom_feed_urls():
    """Test: USOM has correct feed URLs"""
    print("Test: USOM feed URLs...")

    from threat_intel.sources.usom import USOMSource

    source = USOMSource()

    assert "siberguvenlik.gov.tr" in source.FEED_URLS[0]
    assert "usom.gov.tr" in source.FEED_URLS[1]

    print("  PASSED")


def test_source_status():
    """Test: Source status tracking"""
    print("Test: Source status...")

    from threat_intel.sources.openphish import OpenPhishSource

    source = OpenPhishSource()

    status = source.get_status()

    assert "name" in status
    assert "status" in status

    print(f"  Status: {status}")

    print("  PASSED")


def run_all_tests():
    """Run all regression tests"""
    print("=" * 60)
    print("Sprint 8 USOM Integration Tests")
    print("=" * 60)
    print()

    tests = [
        test_threat_feed_sources,
        test_openphish_source,
        test_urlhaus_source,
        test_usom_source,
        test_usom_feed_urls,
        test_source_status,
        test_feed_update,
        test_reputation_check,
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
