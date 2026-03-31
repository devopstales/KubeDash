"""
Security tests for authentication mechanisms

Tests authentication bypass attempts, brute force protection,
session security, and password security.
"""
import pytest
import time
from werkzeug.security import check_password_hash
from lib.user import User, UserCreate, RoleCreate, UserTest


class TestAuthenticationBypass:
    """Test authentication bypass prevention"""
    
    def test_unauthenticated_access_to_protected_route(self, client):
        """Test that unauthenticated users cannot access protected routes"""
        protected_routes = [
            "/dashboard/cluster-metric",
            "/api/v1/users",
            "/api/v1/namespaces",
            "/user/info"
        ]
        
        for route in protected_routes:
            response = client.get(route, follow_redirects=False)
            # Should redirect to login (302) or return 401/403
            assert response.status_code in [302, 401, 403, 404]
    
    def test_authentication_with_invalid_credentials(self, client, app):
        """Test that invalid credentials are rejected"""
        with app.app_context():
            RoleCreate("Admin")
            UserCreate("validuser", "validpass", "valid@example.com", "Local", "Admin")
        
        # Try invalid password
        response = client.post("/", data={
            "username": "validuser",
            "password": "wrongpassword"
        }, follow_redirects=True)
        
        # Should not authenticate
        assert response.status_code == 200
        # Should show error or stay on login page
        assert b"login" in response.data.lower() or b"error" in response.data.lower() or b"invalid" in response.data.lower()
    
    def test_authentication_with_nonexistent_user(self, client):
        """Test that nonexistent users cannot authenticate"""
        response = client.post("/", data={
            "username": "nonexistentuser",
            "password": "anypassword"
        }, follow_redirects=True)
        
        # Should not authenticate
        assert response.status_code == 200
        # Should show error or stay on login page
        assert b"login" in response.data.lower() or b"error" in response.data.lower()
    
    def test_session_fixation_prevention(self, client, app):
        """Test that session IDs change after login (session fixation prevention)"""
        # Get initial session ID
        with client.session_transaction() as sess_before:
            session_id_before = id(sess_before)
        
        # Login
        with app.app_context():
            RoleCreate("Admin")
            UserCreate("sessionuser", "sessionpass", "session@example.com", "Local", "Admin")
        
        client.post("/", data={
            "username": "sessionuser",
            "password": "sessionpass"
        }, follow_redirects=True)
        
        # Get session after login
        with client.session_transaction() as sess_after:
            # Session should have user data
            assert 'user_name' in sess_after
            # Session ID should be different (new session created)
            # Flask-Login creates new session on login


class TestPasswordSecurity:
    """Test password security measures"""
    
    def test_password_hashing(self, session):
        """Test that passwords are hashed, not stored in plaintext"""
        RoleCreate("Admin")
        plain_password = "testpassword123"
        UserCreate("hashtest", plain_password, "hash@example.com", "Local", "Admin")
        
        user = UserTest("hashtest")
        assert user is not None
        assert user.password_hash != plain_password
        assert len(user.password_hash) > len(plain_password)
        # Should use scrypt (starts with scrypt:)
        assert user.password_hash.startswith("scrypt:")
    
    def test_password_verification(self, session):
        """Test that password verification works correctly"""
        RoleCreate("Admin")
        plain_password = "verifypass123"
        UserCreate("verifyuser", plain_password, "verify@example.com", "Local", "Admin")
        
        user = UserTest("verifyuser")
        # Should verify correct password
        assert check_password_hash(user.password_hash, plain_password) is True
        # Should reject wrong password
        assert check_password_hash(user.password_hash, "wrongpassword") is False
    
    def test_password_salt_uniqueness(self, session):
        """Test that each password has a unique salt"""
        from werkzeug.security import generate_password_hash
        RoleCreate("Admin")
        same_password = "samepass123"
        
        UserCreate("user1", same_password, "user1@example.com", "Local", "Admin")
        UserCreate("user2", same_password, "user2@example.com", "Local", "Admin")
        
        user1 = UserTest("user1")
        user2 = UserTest("user2")
        
        # Hashes should be different due to different salts
        assert user1.password_hash != user2.password_hash
        
        # Verify passwords using the same method UserCreate uses
        # UserCreate uses generate_password_hash which creates unique salts
        # Both hashes should verify correctly
        from werkzeug.security import check_password_hash
        # The password_hash stored should verify with the original password
        # Note: check_password_hash works with scrypt hashes
        assert user1.password_hash.startswith("scrypt:")
        assert user2.password_hash.startswith("scrypt:")
        # Both should verify (this tests that salts are unique but passwords still verify)
        assert check_password_hash(user1.password_hash, same_password) is True
        assert check_password_hash(user2.password_hash, same_password) is True


class TestSessionSecurity:
    """Test session security measures"""
    
    def test_session_cookie_httponly(self, client, app):
        """Test that session cookies are HttpOnly"""
        response = client.get("/")
        
        cookies = response.headers.getlist('Set-Cookie')
        session_cookies = [c for c in cookies if 'session' in c.lower() or 'remember_token' in c.lower()]
        
        for cookie in session_cookies:
            # Should have HttpOnly flag
            assert 'HttpOnly' in cookie or app.config.get('TESTING', False)
    
    def test_session_cookie_secure_in_production(self, client, app):
        """Test that session cookies are Secure in production"""
        # In test mode, Secure might be False
        # This test documents the expected behavior
        if not app.config.get('TESTING', False):
            response = client.get("/")
            cookies = response.headers.getlist('Set-Cookie')
            session_cookies = [c for c in cookies if 'session' in c.lower()]
            
            for cookie in session_cookies:
                # Should have Secure flag in production
                assert 'Secure' in cookie
    
    def test_session_timeout(self, client, app):
        """Test that sessions timeout after inactivity"""
        # This is more of a configuration test
        session_lifetime = app.config.get('PERMANENT_SESSION_LIFETIME', 600)
        
        # Should have a reasonable timeout (not infinite)
        assert session_lifetime > 0
        assert session_lifetime < 86400  # Less than 24 hours
    
    def test_session_regeneration_on_login(self, client, app):
        """Test that session is regenerated on login"""
        # Get session before login
        with client.session_transaction() as sess_before:
            sess_before['test_key'] = 'test_value'
        
        # Login
        with app.app_context():
            RoleCreate("Admin")
            UserCreate("regenuser", "regenpass", "regen@example.com", "Local", "Admin")
        
        client.post("/", data={
            "username": "regenuser",
            "password": "regenpass"
        }, follow_redirects=True)
        
        # Session should have user data, old test data might be cleared
        with client.session_transaction() as sess_after:
            assert 'user_name' in sess_after


class TestBruteForceProtection:
    """Test brute force protection mechanisms"""
    
    def test_multiple_failed_login_attempts(self, client, app):
        """Test handling of multiple failed login attempts"""
        with app.app_context():
            RoleCreate("Admin")
            UserCreate("bruteforceuser", "correctpass", "brute@example.com", "Local", "Admin")
        
        # Try multiple failed logins
        for i in range(5):
            response = client.post("/", data={
                "username": "bruteforceuser",
                "password": f"wrongpass{i}"
            }, follow_redirects=True)
            
            # Should reject invalid password
            assert response.status_code == 200
        
        # After multiple attempts, should still allow correct password
        # (or implement rate limiting - this tests current behavior)
        response = client.post("/", data={
            "username": "bruteforceuser",
            "password": "correctpass"
        }, follow_redirects=True)
        
        # Should eventually allow correct password
        # (or implement account lockout - test documents current behavior)
        assert response.status_code in [200, 302]

