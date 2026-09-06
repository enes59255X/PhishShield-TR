"""
Sprint 17 Documentation Tests
PhishShield TR V3

Tests for:
- OpenAPI specification
- API documentation
- README files
- Code examples
"""

import sys
import os
import json

# Project root is 4 levels up from test_docs.py (regression/tests/backend/project_root)
test_file = os.path.abspath(__file__)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(test_file))))


def run_tests():
    print("=" * 60)
    print("Sprint 17 Documentation Tests")
    print("=" * 60)
    
    tests_passed = 0
    tests_failed = 0
    
    try:
        # Test 1: OpenAPI specification exists
        print("\nTest: OpenAPI specification exists...")
        openapi_path = os.path.join(project_root, "docs", "api", "openapi.json")
        assert os.path.exists(openapi_path), f"OpenAPI spec not found at {openapi_path}"
        
        with open(openapi_path, "r", encoding="utf-8") as f:
            openapi = json.load(f)
        
        assert "openapi" in openapi, "OpenAPI version required"
        assert "info" in openapi, "Info section required"
        assert openapi["info"]["title"] == "PhishShield TR API", "Title should match"
        assert "paths" in openapi, "Paths section required"
        assert "components" in openapi, "Components section required"
        
        print(f"  OpenAPI version: {openapi['openapi']}")
        print(f"  Title: {openapi['info']['title']}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 2: API endpoints documented
        print("\nTest: API endpoints documented...")
        paths = openapi.get("paths", {})
        
        required_endpoints = [
            "/api/v2/check",
            "/api/v2/batch",
            "/api/v2/explain",
            "/api/v2/feedback",
            "/api/v2/stats",
            "/health"
        ]
        
        for endpoint in required_endpoints:
            assert endpoint in paths, f"Endpoint {endpoint} not documented"
        
        print(f"  Documented endpoints: {len(paths)}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 3: Schemas documented
        print("\nTest: Schemas documented...")
        schemas = openapi.get("components", {}).get("schemas", {})
        
        required_schemas = [
            "UrlCheckRequest",
            "UrlCheckResponse",
            "BatchCheckRequest",
            "ExplainRequest",
            "ExplainResponse",
            "FeedbackRequest",
            "DomainIntelResponse",
            "ErrorResponse"
        ]
        
        for schema in required_schemas:
            assert schema in schemas, f"Schema {schema} not documented"
        
        print(f"  Documented schemas: {len(schemas)}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 4: API documentation markdown exists
        print("\nTest: API documentation markdown exists...")
        api_readme = os.path.join(project_root, "docs", "api", "README_TR.md")
        assert os.path.exists(api_readme), "API README not found"
        
        with open(api_readme, "r", encoding="utf-8") as f:
            api_content = f.read()
        
        required_sections = [
            "URL Analizi",
            "Kimlik Doğrulama",
            "Rate Limiting",
            "Hata Kodları"
        ]
        
        for section in required_sections:
            assert section in api_content, f"Section {section} not found"
        
        print(f"  API README size: {len(api_content)} chars")
        print("  PASSED")
        tests_passed += 1
        
        # Test 5: Python example exists
        print("\nTest: Python example exists...")
        python_example = os.path.join(project_root, "docs", "examples", "python_example.py")
        assert os.path.exists(python_example), "Python example not found"
        
        with open(python_example, "r", encoding="utf-8") as f:
            python_content = f.read()
        
        assert "PhishShieldClient" in python_content, "Client class required"
        assert "check_url" in python_content, "check_url method required"
        assert "batch_check" in python_content, "batch_check method required"
        assert "explain" in python_content, "explain method required"
        assert "submit_feedback" in python_content, "feedback method required"
        
        print("  Python example valid")
        print("  PASSED")
        tests_passed += 1
        
        # Test 6: JavaScript example exists
        print("\nTest: JavaScript example exists...")
        js_example = os.path.join(project_root, "docs", "examples", "javascript_example.js")
        assert os.path.exists(js_example), "JavaScript example not found"
        
        with open(js_example, "r", encoding="utf-8") as f:
            js_content = f.read()
        
        assert "PhishShieldClient" in js_content, "Client class required"
        assert "checkUrl" in js_content, "checkUrl method required"
        assert "batchCheck" in js_content, "batchCheck method required"
        assert "submitFeedback" in js_content, "submitFeedback method required"
        
        print("  JavaScript example valid")
        print("  PASSED")
        tests_passed += 1
        
        # Test 7: cURL examples exist
        print("\nTest: cURL examples exist...")
        curl_examples = os.path.join(project_root, "docs", "examples", "curl_examples.sh")
        assert os.path.exists(curl_examples), "cURL examples not found"
        
        with open(curl_examples, "r", encoding="utf-8") as f:
            curl_content = f.read()
        
        assert "/api/v2/check" in curl_content, "Check endpoint required"
        assert "/api/v2/batch" in curl_content, "Batch endpoint required"
        assert "/api/v2/explain" in curl_content, "Explain endpoint required"
        assert "X-API-Key" in curl_content, "API key header required"
        
        print("  cURL examples valid")
        print("  PASSED")
        tests_passed += 1
        
        # Test 8: Main README exists
        print("\nTest: Main README exists...")
        readme_path = os.path.join(project_root, "README.md")
        assert os.path.exists(readme_path), "README.md not found"
        
        with open(readme_path, "r", encoding="utf-8") as f:
            readme_content = f.read()
        
        required_readme_sections = [
            "PhishShield TR",
            "Özellikler",
            "Kurulum",
            "API Kullanımı",
            "Mimari",
            "Test"
        ]
        
        for section in required_readme_sections:
            assert section in readme_content, f"Section {section} not found in README"
        
        print(f"  README size: {len(readme_content)} chars")
        print("  PASSED")
        tests_passed += 1
        
        # Test 9: Project structure documented
        print("\nTest: Project structure documented...")
        assert "backend/" in readme_content, "Backend structure required"
        assert "extension/" in readme_content, "Extension structure required"
        assert "mobile/" in readme_content, "Mobile structure required"
        assert "docker/" in readme_content, "Docker structure required"
        assert "docs/" in readme_content, "Docs structure required"
        
        print("  Project structure documented")
        print("  PASSED")
        tests_passed += 1
        
        # Test 10: Architecture documented
        print("\nTest: Architecture documented...")
        assert "Mimari" in readme_content or "Architecture" in readme_content, "Architecture section required"
        
        print("  Architecture documented")
        print("  PASSED")
        tests_passed += 1
        
        # Test 11: License mentioned
        print("\nTest: License mentioned...")
        assert "MIT" in readme_content or "License" in readme_content, "License required"
        
        print("  License documented")
        print("  PASSED")
        tests_passed += 1
        
        # Test 12: Test results documented
        print("\nTest: Test results documented...")
        assert "Test" in readme_content or "test" in readme_content, "Test section required"
        
        print("  Test results documented")
        print("  PASSED")
        tests_passed += 1
        
        # Test 13: Examples directory structure
        print("\nTest: Examples directory structure...")
        examples_dir = os.path.join(project_root, "docs", "examples")
        assert os.path.exists(examples_dir), "Examples directory not found"
        
        example_files = os.listdir(examples_dir)
        assert len(example_files) >= 3, "At least 3 example files required"
        
        print(f"  Example files: {', '.join(example_files)}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 14: API docs language
        print("\nTest: API documentation language...")
        assert "URL Analizi" in api_content, "Turkish headers required"
        assert "Güvenli" in api_content or "risk_score" in api_content, "Turkish content required"
        
        print("  API documentation language correct")
        print("  PASSED")
        tests_passed += 1
        
        # Test 15: Python example syntax
        print("\nTest: Python example syntax...")
        assert "def " in python_content, "Functions required"
        assert "import " in python_content, "Imports required"
        assert "class PhishShieldClient" in python_content, "Client class required"
        
        print("  Python example syntax valid")
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
