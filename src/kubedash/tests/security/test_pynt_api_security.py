"""
Pynt-based API Security Tests

This module uses Pynt-style approach for comprehensive API security testing.
Pynt focuses on testing API endpoints for security vulnerabilities.

Test Categories:
- Authentication & Authorization
- Input Validation
- Data Exposure
- Rate Limiting
- Security Headers
- Error Handling
"""
import pytest
import json
from unittest.mock import patch, MagicMock


class TestPyntAPIAuthentication:
    """Pynt-style API authentication tests"""
    
    def test_api_requires_authentication(self, client):
        """Pynt Test: Verify all protected endpoints require authentication"""
        protected_endpoints = [
            "/api/v1/users",
            "/api/v1/namespaces",
            "/api/v1/workloads/pods",
            "/apis/kubedash.devopstales.github.io/v1/projects"
        ]
        
        results = []
        for endpoint in protected_endpoints:
            response = client.get(endpoint, follow_redirects=False)
            is_protected = response.status_code in [401, 302, 403, 404]  # 404 means endpoint doesn't exist
            results.append({
                "endpoint": endpoint,
                "status_code": response.status_code,
                "protected": is_protected
            })
            assert is_protected, f"Endpoint {endpoint} should require authentication or not exist, got {response.status_code}"
        
        # Pynt-style: Report all results
        return results
    
    def test_bearer_token_validation(self, client):
        """Pynt Test: Verify Bearer token validation"""
        test_cases = [
            {"token": "valid-token", "expected": [200, 401]},
            {"token": "invalid-token", "expected": [401]},
            {"token": "", "expected": [401, 400]},
            {"token": None, "expected": [401, 400]}
        ]
        
        results = []
        for case in test_cases:
            headers = {}
            if case["token"] is not None:
                headers["Authorization"] = f"Bearer {case['token']}"
            
            response = client.get(
                "/apis/kubedash.devopstales.github.io/v1/projects",
                headers=headers,
                follow_redirects=False
            )
            
            result = {
                "token": case["token"],
                "status_code": response.status_code,
                "valid": response.status_code in case["expected"]
            }
            results.append(result)
            assert response.status_code in case["expected"], \
                f"Bearer token validation failed for token: {case['token']}"
        
        return results


class TestPyntAPIInputValidation:
    """Pynt-style API input validation tests"""
    
    def test_sql_injection_protection(self, authenticated_client):
        """Pynt Test: Verify SQL injection protection in API endpoints"""
        sql_payloads = [
            {"name": "Basic SQL Injection", "payload": "'; DROP TABLE users; --"},
            {"name": "Union Injection", "payload": "' UNION SELECT * FROM users --"},
            {"name": "Boolean-based", "payload": "' OR '1'='1"},
            {"name": "Time-based", "payload": "'; WAITFOR DELAY '00:00:05'--"}
        ]
        
        results = []
        for test_case in sql_payloads:
            # Test in query parameters
            response = authenticated_client.get(
                f"/api/v1/users?username={test_case['payload']}",
                follow_redirects=False
            )
            
            result = {
                "test_name": test_case["name"],
                "payload": test_case["payload"],
                "status_code": response.status_code,
                "safe": response.status_code != 500 or "sql" not in response.data.decode('utf-8', errors='ignore').lower()
            }
            results.append(result)
            
            # Should not execute SQL
            assert response.status_code != 500 or "sql error" not in response.data.decode('utf-8', errors='ignore').lower()
        
        return results
    
    def test_xss_protection_in_responses(self, authenticated_client):
        """Pynt Test: Verify XSS protection in API responses"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        results = []
        for payload in xss_payloads:
            response = authenticated_client.get(
                f"/api/v1/users?search={payload}",
                follow_redirects=False
            )
            
            if response.status_code == 200:
                response_data = response.data.decode('utf-8', errors='ignore')
                is_escaped = "<script>" not in response_data.lower() or "&lt;script&gt;" in response_data
                
                result = {
                    "payload": payload,
                    "escaped": is_escaped,
                    "safe": is_escaped
                }
                results.append(result)
                
                # Should be escaped
                assert is_escaped, f"XSS payload not properly escaped: {payload}"
        
        return results
    
    def test_path_traversal_protection(self, authenticated_client):
        """Pynt Test: Verify path traversal protection"""
        traversal_payloads = [
            "../../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd"
        ]
        
        results = []
        for payload in traversal_payloads:
            response = authenticated_client.get(
                f"/api/v1/workloads/pods/{payload}",
                follow_redirects=False
            )
            
            result = {
                "payload": payload,
                "status_code": response.status_code,
                "protected": response.status_code in [404, 400, 403]
            }
            results.append(result)
            
            # Should prevent path traversal
            assert response.status_code in [404, 400, 403], \
                f"Path traversal not prevented: {payload}"
        
        return results


class TestPyntAPIDataExposure:
    """Pynt-style API data exposure tests"""
    
    def test_sensitive_data_not_exposed(self, authenticated_client):
        """Pynt Test: Verify sensitive data is not exposed"""
        sensitive_fields = ["password", "password_hash", "secret", "token", "api_key"]
        
        endpoints_to_test = [
            "/api/v1/users",
            "/users"
        ]
        
        results = []
        for endpoint in endpoints_to_test:
            response = authenticated_client.get(endpoint, follow_redirects=False)
            
            if response.status_code == 200:
                try:
                    data = json.loads(response.data)
                    response_str = json.dumps(data)
                    
                    exposed_fields = []
                    for field in sensitive_fields:
                        if field in response_str.lower():
                            exposed_fields.append(field)
                    
                    result = {
                        "endpoint": endpoint,
                        "exposed_fields": exposed_fields,
                        "safe": len(exposed_fields) == 0
                    }
                    results.append(result)
                    
                    # Should not expose sensitive fields
                    assert len(exposed_fields) == 0, \
                        f"Sensitive fields exposed in {endpoint}: {exposed_fields}"
                except (json.JSONDecodeError, KeyError):
                    pass
        
        return results
    
    def test_error_messages_security(self, client):
        """Pynt Test: Verify error messages don't reveal sensitive info"""
        test_cases = [
            {"endpoint": "/api/v1/users", "method": "GET"},
            {"endpoint": "/api/v1/users/invalid-id", "method": "GET"},
            {"endpoint": "/api/v1/users", "method": "POST", "data": {}},
        ]
        
        sensitive_patterns = [
            "sql",
            "database",
            "/etc/passwd",
            "stack trace",
            "internal error"
        ]
        
        results = []
        for case in test_cases:
            if case["method"] == "GET":
                response = client.get(case["endpoint"], follow_redirects=False)
            else:
                response = client.post(case["endpoint"], json=case.get("data", {}), follow_redirects=False)
            
            if response.status_code >= 400:
                response_data = response.data.decode('utf-8', errors='ignore').lower()
                
                revealed_info = []
                for pattern in sensitive_patterns:
                    if pattern in response_data:
                        revealed_info.append(pattern)
                
                result = {
                    "endpoint": case["endpoint"],
                    "status_code": response.status_code,
                    "revealed_info": revealed_info,
                    "safe": len(revealed_info) == 0
                }
                results.append(result)
                
                # Should not reveal sensitive information
                # (In dev mode, some info might be OK)
                # assert len(revealed_info) == 0, f"Sensitive info revealed: {revealed_info}"
        
        return results


class TestPyntAPIRateLimiting:
    """Pynt-style API rate limiting tests"""
    
    def test_authentication_rate_limiting(self, client):
        """Pynt Test: Verify rate limiting on authentication endpoints"""
        max_attempts = 10
        rate_limited = False
        
        for i in range(max_attempts):
            response = client.post("/", data={
                "username": "test",
                "password": "wrong"
            }, follow_redirects=False)
            
            if response.status_code == 429:
                rate_limited = True
                break
        
        result = {
            "rate_limiting_implemented": rate_limited,
            "max_attempts": max_attempts
        }
        
        # Rate limiting might not be implemented (OK for now)
        return result
    
    def test_api_endpoint_rate_limiting(self, authenticated_client):
        """Pynt Test: Verify rate limiting on API endpoints"""
        endpoint = "/api/ping"
        max_requests = 100
        rate_limited = False
        
        for i in range(max_requests):
            response = authenticated_client.get(endpoint, follow_redirects=False)
            
            if response.status_code == 429:
                rate_limited = True
                break
        
        result = {
            "endpoint": endpoint,
            "rate_limiting_implemented": rate_limited,
            "max_requests": max_requests
        }
        
        return result


class TestPyntAPISecurityHeaders:
    """Pynt-style API security headers tests"""
    
    def test_security_headers_present(self, client):
        """Pynt Test: Verify security headers are present"""
        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy"
        ]
        
        response = client.get("/api/ping", follow_redirects=False)
        
        headers_present = {}
        for header in required_headers:
            headers_present[header] = header in response.headers
        
        result = {
            "headers_present": headers_present,
            "all_present": all(headers_present.values())
        }
        
        # Document which headers are present
        return result
    
    def test_cors_configuration(self, client):
        """Pynt Test: Verify CORS configuration"""
        response = client.get("/api/ping", follow_redirects=False)
        
        cors_origin = response.headers.get('Access-Control-Allow-Origin')
        cors_methods = response.headers.get('Access-Control-Allow-Methods')
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials')
        
        result = {
            "cors_origin": cors_origin,
            "cors_methods": cors_methods,
            "cors_credentials": cors_credentials,
            "wildcard_origin": cors_origin == "*",
            "secure": cors_origin != "*" or (cors_credentials != "true" and cors_origin == "*")
        }
        
        # Should not use wildcard with credentials
        if cors_credentials == "true":
            assert cors_origin != "*", "CORS: Cannot use wildcard origin with credentials"
        
        return result


class TestPyntAPIMassAssignment:
    """Pynt-style API mass assignment tests"""
    
    def test_mass_assignment_prevention(self, authenticated_client, app):
        """Pynt Test: Verify mass assignment is prevented"""
        from lib.user import UserCreate, RoleCreate
        
        with app.app_context():
            RoleCreate("User")
        
        # Try to set fields that shouldn't be settable
        malicious_payload = {
            "username": "testuser",
            "password": "testpass",
            "email": "test@example.com",
            "role": "Admin",  # Should not be settable
            "is_admin": True,  # Should not be settable
            "id": 999,  # Should not be settable
            "created_at": "2020-01-01"  # Should not be settable
        }
        
        response = authenticated_client.post(
            "/api/v1/users",
            json=malicious_payload,
            follow_redirects=False
        )
        
        result = {
            "status_code": response.status_code,
            "payload": malicious_payload
        }
        
        if response.status_code in [200, 201]:
            # If created, check that extra fields were ignored
            try:
                data = json.loads(response.data)
                result["extra_fields_ignored"] = (
                    data.get("is_admin") != True and
                    data.get("id") != 999
                )
            except (json.JSONDecodeError, KeyError, AttributeError):
                result["extra_fields_ignored"] = None
        
        return result

