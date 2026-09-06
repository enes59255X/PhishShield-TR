"""
Sprint 14 Browser Extension V2 Tests
PhishShield TR V3

Tests for:
- Extension manifest structure
- API client functionality
- Settings management
- Extension file integrity
"""

import sys
import os
import json
import tempfile
import shutil
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def run_tests():
    print("=" * 60)
    print("Sprint 14 Browser Extension V2 Tests")
    print("=" * 60)
    
    tests_passed = 0
    tests_failed = 0
    
    # Get the backend/tests/regression path and go up to project root
    backend_path = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    project_root = os.path.dirname(backend_path)
    ext_path = os.path.join(project_root, "extension")
    
    try:
        # Test 1: Extension directory exists
        print("\nTest: Extension directory exists...")
        assert os.path.exists(ext_path), "Extension directory not found"
        print(f"  Extension path: {ext_path}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 2: Manifest.json exists and is valid
        print("\nTest: Manifest.json valid...")
        manifest_path = os.path.join(ext_path, "manifest.json")
        assert os.path.exists(manifest_path), "manifest.json not found"
        
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        
        assert manifest["manifest_version"] == 3, "Must be MV3"
        assert "background" in manifest, "Background service worker required"
        assert "content_scripts" in manifest, "Content scripts required"
        assert "action" in manifest, "Browser action required"
        
        print(f"  Manifest version: {manifest['manifest_version']}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 3: Background service worker exists
        print("\nTest: Background service worker exists...")
        bg_path = os.path.join(ext_path, "background", "service_worker.js")
        assert os.path.exists(bg_path), "service_worker.js not found"
        
        with open(bg_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        assert "chrome.tabs.onUpdated" in content, "Tab update listener required"
        assert "phishShieldAPI" in content, "API client required"
        assert "ANALYSIS_RESULT" in content, "Message handling required"
        
        print("  Service worker has required event listeners")
        print("  PASSED")
        tests_passed += 1
        
        # Test 4: Content scripts exist
        print("\nTest: Content scripts exist...")
        detector_path = os.path.join(ext_path, "content", "detector.js")
        formguard_path = os.path.join(ext_path, "content", "form_guard.js")
        
        assert os.path.exists(detector_path), "detector.js not found"
        assert os.path.exists(formguard_path), "form_guard.js not found"
        
        with open(detector_path, "r", encoding="utf-8") as f:
            detector_content = f.read()
        
        assert "phishshield" in detector_content.lower(), "PhishShield branding required"
        assert "DANGER" in detector_content, "Danger state handling required"
        
        with open(formguard_path, "r", encoding="utf-8") as f:
            formguard_content = f.read()
        
        assert "form" in formguard_content.lower(), "Form handling required"
        
        print("  Detector and Form Guard scripts present")
        print("  PASSED")
        tests_passed += 1
        
        # Test 5: Popup files exist
        print("\nTest: Popup files exist...")
        popup_html = os.path.join(ext_path, "popup", "popup.html")
        popup_css = os.path.join(ext_path, "popup", "popup.css")
        popup_js = os.path.join(ext_path, "popup", "popup.js")
        
        assert os.path.exists(popup_html), "popup.html not found"
        assert os.path.exists(popup_css), "popup.css not found"
        assert os.path.exists(popup_js), "popup.js not found"
        
        with open(popup_html, "r", encoding="utf-8") as f:
            html_content = f.read()
        
        assert 'id="safe-state"' in html_content, "Safe state element required"
        assert 'id="danger-state"' in html_content, "Danger state element required"
        assert "PhishShield" in html_content, "PhishShield branding required"
        
        print("  Popup UI components present")
        print("  PASSED")
        tests_passed += 1
        
        # Test 6: API client structure
        print("\nTest: API client structure...")
        api_path = os.path.join(ext_path, "api", "client.js")
        assert os.path.exists(api_path), "client.js not found"
        
        with open(api_path, "r", encoding="utf-8") as f:
            api_content = f.read()
        
        assert "class PhishShieldClient" in api_content, "Client class required"
        assert "analyze" in api_content, "Analyze method required"
        assert "checkUrl" in api_content, "CheckUrl method required"
        assert "cache" in api_content.lower(), "Caching required"
        
        print("  API client has required methods")
        print("  PASSED")
        tests_passed += 1
        
        # Test 7: Settings manager
        print("\nTest: Settings manager...")
        settings_path = os.path.join(ext_path, "storage", "settings.js")
        assert os.path.exists(settings_path), "settings.js not found"
        
        with open(settings_path, "r", encoding="utf-8") as f:
            settings_content = f.read()
        
        assert "PhishShieldSettings" in settings_content, "Settings class required"
        assert "PhishShieldCache" in settings_content, "Cache class required"
        assert "protectionEnabled" in settings_content, "Protection setting required"
        
        print("  Settings management classes present")
        print("  PASSED")
        tests_passed += 1
        
        # Test 8: File structure completeness
        print("\nTest: File structure completeness...")
        required_files = [
            "manifest.json",
            "background/service_worker.js",
            "content/detector.js",
            "content/form_guard.js",
            "popup/popup.html",
            "popup/popup.css",
            "popup/popup.js",
            "api/client.js",
            "storage/settings.js"
        ]
        
        for file_path in required_files:
            full_path = os.path.join(ext_path, file_path)
            assert os.path.exists(full_path), f"Required file missing: {file_path}"
        
        print(f"  All {len(required_files)} required files present")
        print("  PASSED")
        tests_passed += 1
        
        # Test 9: Manifest permissions
        print("\nTest: Manifest permissions...")
        permissions = manifest.get("permissions", [])
        host_permissions = manifest.get("host_permissions", [])
        
        assert "tabs" in permissions, "Tabs permission required"
        assert "storage" in permissions, "Storage permission required"
        
        # Check for API URL in host_permissions
        api_found = any("127.0.0.1" in p or "*" in p for p in host_permissions)
        assert api_found, "API host permission required"
        
        print(f"  Permissions: {len(permissions)}")
        print(f"  Host permissions: {len(host_permissions)}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 10: Content script matches
        print("\nTest: Content script matches configuration...")
        content_scripts = manifest.get("content_scripts", [])
        assert len(content_scripts) > 0, "Content scripts required"
        
        cs = content_scripts[0]
        assert "<all_urls>" in cs.get("matches", []), "Must match all URLs"
        assert "content/detector.js" in cs.get("js", []), "Detector required"
        assert "content/form_guard.js" in cs.get("js", []), "Form guard required"
        
        print("  Content scripts configured correctly")
        print("  PASSED")
        tests_passed += 1
        
        # Test 11: JavaScript syntax check for service worker
        print("\nTest: Service worker JavaScript syntax...")
        with open(bg_path, "r", encoding="utf-8") as f:
            js_content = f.read()
        
        # Basic syntax checks
        assert js_content.count("{") == js_content.count("}"), "Brace mismatch in service worker"
        assert js_content.count("(") == js_content.count(")"), "Parenthesis mismatch in service worker"
        assert "chrome.runtime.onMessage" in js_content, "Message listener required"
        
        print("  Basic syntax checks passed")
        print("  PASSED")
        tests_passed += 1
        
        # Test 12: Form guard analysis logic
        print("\nTest: Form guard analysis logic...")
        with open(formguard_path, "r", encoding="utf-8") as f:
            fg_content = f.read()
        
        assert "analyzeForm" in fg_content, "Form analysis method required"
        assert "password" in fg_content.lower(), "Password field detection required"
        assert "external" in fg_content.lower(), "External submit detection required"
        
        print("  Form guard has required analysis logic")
        print("  PASSED")
        tests_passed += 1
        
        # Test 13: Popup state management
        print("\nTest: Popup state management...")
        with open(popup_js, "r", encoding="utf-8") as f:
            popup_content = f.read()
        
        assert "showState" in popup_content, "State management required"
        assert "safe" in popup_content and "danger" in popup_content, "State types required"
        assert "GET_ANALYSIS" in popup_content, "Analysis request required"
        
        print("  Popup state management present")
        print("  PASSED")
        tests_passed += 1
        
        # Test 14: API caching mechanism
        print("\nTest: API caching mechanism...")
        with open(api_path, "r", encoding="utf-8") as f:
            api_content = f.read()
        
        assert "cacheTTL" in api_content, "Cache TTL required"
        assert "getCached" in api_content, "Cache get method required"
        assert "setCached" in api_content, "Cache set method required"
        
        print("  Caching mechanism present")
        print("  PASSED")
        tests_passed += 1
        
        # Test 15: Extension has icons directory
        print("\nTest: Icons directory exists...")
        icons_path = os.path.join(ext_path, "icons")
        assert os.path.exists(icons_path), "Icons directory required"
        
        print("  Icons directory present")
        print("  PASSED")
        tests_passed += 1
        
    except Exception as e:
        print(f"  FAILED: {e}")
        import traceback
        traceback.print_exc()
        tests_failed += 1
    
    print("\n" + "=" * 60)
    print(f"Results: {tests_passed} passed, {tests_failed} failed, 0 skipped")
    print("=" * 60)
    
    return tests_failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
