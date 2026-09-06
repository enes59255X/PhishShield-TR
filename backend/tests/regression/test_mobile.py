"""
Sprint 15 Mobile App Tests
PhishShield TR V3

Tests for:
- Mobile app structure
- Models
- Services
- File integrity
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def run_tests():
    print("=" * 60)
    print("Sprint 15 Mobile App Tests")
    print("=" * 60)
    
    tests_passed = 0
    tests_failed = 0
    
    backend_path = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    project_root = os.path.dirname(backend_path)
    mobile_path = os.path.join(project_root, "mobile")

    try:
        # Test 1: Mobile directory exists
        print("\nTest: Mobile directory exists...")
        assert os.path.exists(mobile_path), "Mobile directory not found"
        print(f"  Mobile path: {mobile_path}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 2: pubspec.yaml exists
        print("\nTest: pubspec.yaml exists...")
        pubspec_path = os.path.join(mobile_path, "pubspec.yaml")
        assert os.path.exists(pubspec_path), "pubspec.yaml not found"
        
        with open(pubspec_path, "r", encoding="utf-8") as f:
            pubspec_content = f.read()
        
        assert "phishshield_tr" in pubspec_content, "App name required"
        assert "http:" in pubspec_content, "HTTP dependency required"
        assert "shared_preferences:" in pubspec_content, "Storage dependency required"
        
        print("  pubspec.yaml valid")
        print("  PASSED")
        tests_passed += 1
        
        # Test 3: Main.dart exists
        print("\nTest: Main.dart exists...")
        main_path = os.path.join(mobile_path, "lib", "main.dart")
        assert os.path.exists(main_path), "main.dart not found"
        
        with open(main_path, "r", encoding="utf-8") as f:
            main_content = f.read()
        
        assert "PhishShieldApp" in main_content, "App class required"
        assert "MainScreen" in main_content, "Main screen required"
        assert "ScannerScreen" in main_content, "Scanner screen required"
        
        print("  main.dart valid")
        print("  PASSED")
        tests_passed += 1
        
        # Test 4: Models exist
        print("\nTest: Models exist...")
        models_path = os.path.join(mobile_path, "lib", "models", "models.dart")
        assert os.path.exists(models_path), "models.dart not found"
        
        with open(models_path, "r", encoding="utf-8") as f:
            models_content = f.read()
        
        assert "class AnalysisResult" in models_content, "AnalysisResult model required"
        assert "class AppSettings" in models_content, "AppSettings model required"
        assert "class AlertItem" in models_content, "AlertItem model required"
        
        print("  Models present")
        print("  PASSED")
        tests_passed += 1
        
        # Test 5: API Service exists
        print("\nTest: API Service exists...")
        api_service_path = os.path.join(mobile_path, "lib", "services", "api_service.dart")
        assert os.path.exists(api_service_path), "api_service.dart not found"
        
        with open(api_service_path, "r", encoding="utf-8") as f:
            api_content = f.read()
        
        assert "class ApiService" in api_content, "ApiService class required"
        assert "analyzeUrl" in api_content, "AnalyzeUrl method required"
        assert "checkUrl" in api_content, "CheckUrl method required"
        
        print("  API Service valid")
        print("  PASSED")
        tests_passed += 1
        
        # Test 6: Storage Service exists
        print("\nTest: Storage Service exists...")
        storage_path = os.path.join(mobile_path, "lib", "services", "storage_service.dart")
        assert os.path.exists(storage_path), "storage_service.dart not found"
        
        with open(storage_path, "r", encoding="utf-8") as f:
            storage_content = f.read()
        
        assert "class StorageService" in storage_content, "StorageService class required"
        assert "getHistory" in storage_content, "History method required"
        assert "saveSettings" in storage_content, "Settings method required"
        
        print("  Storage Service valid")
        print("  PASSED")
        tests_passed += 1
        
        # Test 7: Scanner Screen exists
        print("\nTest: Scanner Screen exists...")
        scanner_path = os.path.join(mobile_path, "lib", "screens", "scanner_screen.dart")
        assert os.path.exists(scanner_path), "scanner_screen.dart not found"
        
        with open(scanner_path, "r", encoding="utf-8") as f:
            scanner_content = f.read()
        
        assert "class ScannerScreen" in scanner_content, "ScannerScreen class required"
        assert "_analyzeUrl" in scanner_content, "AnalyzeUrl method required"
        
        print("  Scanner Screen valid")
        print("  PASSED")
        tests_passed += 1
        
        # Test 8: History Screen exists
        print("\nTest: History Screen exists...")
        history_path = os.path.join(mobile_path, "lib", "screens", "history_screen.dart")
        assert os.path.exists(history_path), "history_screen.dart not found"
        
        with open(history_path, "r", encoding="utf-8") as f:
            history_content = f.read()
        
        assert "class HistoryScreen" in history_content, "HistoryScreen class required"
        assert "_loadHistory" in history_content, "LoadHistory method required"
        
        print("  History Screen valid")
        print("  PASSED")
        tests_passed += 1
        
        # Test 9: Alerts Screen exists
        print("\nTest: Alerts Screen exists...")
        alerts_path = os.path.join(mobile_path, "lib", "screens", "alerts_screen.dart")
        assert os.path.exists(alerts_path), "alerts_screen.dart not found"
        
        with open(alerts_path, "r", encoding="utf-8") as f:
            alerts_content = f.read()
        
        assert "class AlertsScreen" in alerts_content, "AlertsScreen class required"
        
        print("  Alerts Screen valid")
        print("  PASSED")
        tests_passed += 1
        
        # Test 10: Profile Screen exists
        print("\nTest: Profile Screen exists...")
        profile_path = os.path.join(mobile_path, "lib", "screens", "profile_screen.dart")
        assert os.path.exists(profile_path), "profile_screen.dart not found"
        
        with open(profile_path, "r", encoding="utf-8") as f:
            profile_content = f.read()
        
        assert "class ProfileScreen" in profile_content, "ProfileScreen class required"
        assert "_updateSettings" in profile_content, "UpdateSettings method required"
        
        print("  Profile Screen valid")
        print("  PASSED")
        tests_passed += 1
        
        # Test 11: All screens export exists
        print("\nTest: Screens export exists...")
        screens_export = os.path.join(mobile_path, "lib", "screens", "screens.dart")
        assert os.path.exists(screens_export), "screens.dart export not found"
        
        with open(screens_export, "r", encoding="utf-8") as f:
            export_content = f.read()
        
        assert "scanner_screen.dart" in export_content
        assert "history_screen.dart" in export_content
        assert "alerts_screen.dart" in export_content
        assert "profile_screen.dart" in export_content
        
        print("  All screens exported")
        print("  PASSED")
        tests_passed += 1
        
        # Test 12: Services export exists
        print("\nTest: Services export exists...")
        services_export = os.path.join(mobile_path, "lib", "services", "services.dart")
        assert os.path.exists(services_export), "services.dart export not found"
        
        with open(services_export, "r", encoding="utf-8") as f:
            services_content = f.read()
        
        assert "api_service.dart" in services_content
        assert "storage_service.dart" in services_content
        
        print("  All services exported")
        print("  PASSED")
        tests_passed += 1
        
        # Test 13: File structure completeness
        print("\nTest: File structure completeness...")
        required_files = [
            "pubspec.yaml",
            "lib/main.dart",
            "lib/models/models.dart",
            "lib/services/api_service.dart",
            "lib/services/storage_service.dart",
            "lib/screens/scanner_screen.dart",
            "lib/screens/history_screen.dart",
            "lib/screens/alerts_screen.dart",
            "lib/screens/profile_screen.dart",
        ]
        
        for file_path in required_files:
            full_path = os.path.join(mobile_path, file_path)
            assert os.path.exists(full_path), f"Required file missing: {file_path}"
        
        print(f"  All {len(required_files)} required files present")
        print("  PASSED")
        tests_passed += 1
        
        # Test 14: Bottom navigation in MainScreen
        print("\nTest: Bottom navigation implemented...")
        assert "_currentIndex" in main_content, "Index state required"
        assert "bottomNavigationBar" in main_content, "Bottom nav required"
        assert "qr_code_scanner" in main_content or "Scanner" in main_content, "Scanner tab required"
        assert "history" in main_content, "History tab required"
        assert "notifications" in main_content, "Alerts tab required"
        assert "person" in main_content or "settings" in main_content.lower(), "Profile tab required"
        
        print("  Bottom navigation present")
        print("  PASSED")
        tests_passed += 1
        
        # Test 15: Theme configuration
        print("\nTest: Theme configuration...")
        assert "Color(0xFF1a1a2e)" in main_content or "#1a1a2e" in main_content, "Dark theme color required"
        assert "Color(0xFF00d4ff)" in main_content or "#00d4ff" in main_content, "Primary color required"
        
        print("  Theme configured")
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
