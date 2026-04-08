#!/usr/bin/env python
"""Test script to verify system works"""
import sys
sys.path.insert(0, '.')

from app import app

def test_analyze():
    """Test analyze function directly"""
    try:
        from analyzer import analyze_url
        result = analyze_url("http://garanti-bankasi-giris.xyz/login")
        print("✓ analyze_url works!")
        print(f"  Score: {result.get('score')}")
        print(f"  Risk: {result.get('risk_level')}")
        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

if __name__ == "__main__":
    test_analyze()