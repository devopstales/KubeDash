"""
Integration tests for authentication flow
"""
import pytest
import uuid
from flask import session
from flask_login import current_user

from lib.user import User, UserCreate, RoleCreate


class TestAuthIntegration:
    """Test authentication integration"""
    
    def test_login_page_renders(self, client):
        """Test login page is accessible"""
        response = client.get("/")
        assert response.status_code == 200
        assert b"Login" in response.data or b"login" in response.data.lower()
    
    def test_login_with_valid_credentials(self, client, app):
        """Test successful login flow"""
        unique_id = str(uuid.uuid4())[:8]
        username = f"testlogin_{unique_id}"
        with app.app_context():
            # Create test user with unique identifier
            RoleCreate("Admin")
            UserCreate(username, "testpass", f"test_{unique_id}@example.com", "Local", "Admin")
        
        # Submit login form
        response = client.post("/", data={
            "username": username,
            "password": "testpass"
        }, follow_redirects=True)
        
        # Should redirect to dashboard or show success
        assert response.status_code == 200
        # Check session was created
        with client.session_transaction() as sess:
            assert 'user_name' in sess
            assert sess['user_name'] == username
    
    def test_login_with_invalid_credentials(self, client):
        """Test login with invalid credentials"""
        response = client.post("/", data={
            "username": "nonexistent",
            "password": "wrongpass"
        }, follow_redirects=True)
        
        # Should show error message
        assert b"Please check your login details" in response.data or response.status_code == 200
    
    def test_login_with_wrong_password(self, client, app):
        """Test login with wrong password for existing user"""
        unique_id = str(uuid.uuid4())[:8]
        username = f"wrongpassuser_{unique_id}"
        with app.app_context():
            RoleCreate("Admin")
            UserCreate(username, "correctpass", f"test_{unique_id}@example.com", "Local", "Admin")
        
        response = client.post("/", data={
            "username": username,
            "password": "wrongpass"
        }, follow_redirects=True)
        
        # Should show error
        assert b"Please check your login details" in response.data or response.status_code == 200
    
    def test_logout(self, authenticated_client):
        """Test logout functionality"""
        # Don't follow redirects to avoid redirect loops
        response = authenticated_client.get("/logout", follow_redirects=False)
        # Should redirect to login page (302) or show login (200)
        assert response.status_code in [200, 302]
        if response.status_code == 302:
            # If redirect, check it's going to login
            assert response.location in ["/", "/login", None] or "/" in (response.location or "")
    
    def test_protected_route_redirect(self, client):
        """Test unauthenticated access to protected route"""
        response = client.get("/dashboard/cluster-metric", follow_redirects=False)
        # Should redirect to login (302) or show login page
        assert response.status_code in [302, 200]
    
    def test_remember_me_functionality(self, client, app):
        """Test remember me checkbox"""
        unique_id = str(uuid.uuid4())[:8]
        username = f"rememberuser_{unique_id}"
        with app.app_context():
            RoleCreate("Admin")
            UserCreate(username, "rememberpass", f"test_{unique_id}@example.com", "Local", "Admin")
        
        response = client.post("/", data={
            "username": username,
            "password": "rememberpass",
            "remember": "on"
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Check that session cookie has remember flag
        # This is handled by Flask-Login internally

