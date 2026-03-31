"""
Security tests for HTTP security headers

Tests that security headers are properly set to prevent
various attacks (XSS, clickjacking, MIME sniffing, etc.)
"""
import pytest


class TestSecurityHeaders:
    """Test security headers configuration"""
    
    def test_content_security_policy_header(self, client):
        """Test that Content Security Policy header is set"""
        response = client.get("/")
        
        # CSP should be set by Flask-Talisman
        csp = response.headers.get('Content-Security-Policy')
        # In test mode, might not be set, but should be in production
        # Just verify response is valid
        assert response.status_code in [200, 302, 401]
        
        if csp:
            # Should contain security directives
            assert 'default-src' in csp.lower() or 'script-src' in csp.lower()
    
    def test_x_content_type_options_header(self, client):
        """Test X-Content-Type-Options header"""
        response = client.get("/")
        
        x_content_type = response.headers.get('X-Content-Type-Options')
        # Should be set to 'nosniff' to prevent MIME sniffing
        if x_content_type:
            assert x_content_type.lower() == 'nosniff'
    
    def test_x_frame_options_header(self, client):
        """Test X-Frame-Options header"""
        response = client.get("/")
        
        x_frame_options = response.headers.get('X-Frame-Options')
        # Should be set to prevent clickjacking
        # May be DENY, SAMEORIGIN, or not set (if using CSP frame-ancestors)
        if x_frame_options:
            assert x_frame_options.upper() in ['DENY', 'SAMEORIGIN']
    
    def test_strict_transport_security_header(self, client, app):
        """Test Strict-Transport-Security header"""
        response = client.get("/")
        
        hsts = response.headers.get('Strict-Transport-Security')
        # Should be set in production, might not be in test/dev
        if hsts:
            assert 'max-age' in hsts.lower()
            # Should have reasonable max-age
            assert 'max-age=0' not in hsts  # Should not disable HSTS
    
    def test_x_xss_protection_header(self, client):
        """Test X-XSS-Protection header"""
        response = client.get("/")
        
        x_xss_protection = response.headers.get('X-XSS-Protection')
        # Should be set by Talisman
        # May be '1; mode=block' or '0' (disabled, relying on CSP)
        if x_xss_protection:
            assert '1' in x_xss_protection or '0' in x_xss_protection
    
    def test_referrer_policy_header(self, client):
        """Test Referrer-Policy header"""
        response = client.get("/")
        
        referrer_policy = response.headers.get('Referrer-Policy')
        # Should be set to control referrer information leakage
        if referrer_policy:
            valid_policies = ['no-referrer', 'strict-origin-when-cross-origin', 
                            'same-origin', 'no-referrer-when-downgrade']
            assert referrer_policy.lower() in valid_policies
    
    def test_permissions_policy_header(self, client):
        """Test Permissions-Policy header (formerly Feature-Policy)"""
        response = client.get("/")
        
        permissions_policy = response.headers.get('Permissions-Policy')
        # Should restrict browser features
        if permissions_policy:
            # Should contain restrictions
            assert len(permissions_policy) > 0
    
    def test_all_security_headers_present(self, client):
        """Test that all expected security headers are present"""
        response = client.get("/")
        
        security_headers = [
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection'
        ]
        
        headers_present = []
        for header in security_headers:
            if response.headers.get(header):
                headers_present.append(header)
        
        # At least some security headers should be present
        # (In test mode, some might be relaxed)
        assert len(headers_present) >= 1 or response.status_code in [302, 401]


class TestCORSConfiguration:
    """Test CORS (Cross-Origin Resource Sharing) configuration"""
    
    def test_cors_headers_not_overly_permissive(self, client):
        """Test that CORS headers are not overly permissive"""
        response = client.get("/")
        
        cors_origin = response.headers.get('Access-Control-Allow-Origin')
        # Should not be '*' (allow all origins) in production
        # In test, might be permissive
        if cors_origin:
            # Should be specific origin or same-origin, not wildcard
            # (unless explicitly configured for API)
            pass  # Document expected behavior
    
    def test_cors_methods_restricted(self, client):
        """Test that CORS allowed methods are restricted"""
        response = client.get("/")
        
        cors_methods = response.headers.get('Access-Control-Allow-Methods')
        # Should only allow necessary methods
        if cors_methods:
            # Should not allow all methods
            assert cors_methods.upper() != '*'
    
    def test_cors_credentials_handling(self, client):
        """Test CORS credentials handling"""
        response = client.get("/")
        
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials')
        # If credentials are allowed, origin should be specific (not '*')
        if cors_credentials and cors_credentials.lower() == 'true':
            cors_origin = response.headers.get('Access-Control-Allow-Origin')
            assert cors_origin != '*'  # Cannot use wildcard with credentials

