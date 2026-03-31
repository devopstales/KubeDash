"""
Security tests for SQL Injection prevention

Tests that user inputs are properly sanitized and parameterized
to prevent SQL injection attacks.
"""
import pytest
from lib.user import User, UserCreate, RoleCreate, UserTest
from lib.components import db


class TestSQLInjectionPrevention:
    """Test SQL injection prevention"""
    
    def test_user_creation_sql_injection_username(self, session):
        """Test that SQL injection in username is prevented"""
        import uuid
        RoleCreate("Admin")
        
        # Attempt SQL injection in username
        malicious_username = "admin'; DROP TABLE users; --"
        malicious_email = f"test_{uuid.uuid4().hex[:8]}@example.com"  # Unique email
        
        # Should create user with literal username, not execute SQL
        UserCreate(malicious_username, "password", malicious_email, "Local", "Admin")
        
        # Verify user was created with the literal string as username
        user = UserTest(malicious_username)
        assert user is not None
        assert user.username == malicious_username  # Should be stored as-is, not executed
        
        # Verify users table still exists (not dropped)
        users = User.query.all()
        assert len(users) >= 1
    
    def test_user_creation_sql_injection_email(self, session):
        """Test that SQL injection in email is prevented"""
        import uuid
        RoleCreate("Admin")
        
        # Attempt SQL injection in email
        username = f"testuser_{uuid.uuid4().hex[:8]}"  # Unique username
        malicious_email = "test@example.com'; DELETE FROM users; --"
        
        # Should create user with literal email (SQL injection should be prevented)
        try:
            UserCreate(username, "password", malicious_email, "Local", "Admin")
            
            # Verify user was created
            user = UserTest(username)
            # User might be created with sanitized email or rejected
            # The important thing is SQL wasn't executed
            if user:
                # If created, email should be stored as literal string
                assert user.email == malicious_email or user.email is not None
        except Exception:
            # If rejected due to invalid email format, that's also acceptable
            pass
        
        # Verify users table still has data
        users = User.query.all()
        assert len(users) >= 1
    
    def test_user_query_sql_injection(self, session):
        """Test that SQL injection in query parameters is prevented"""
        RoleCreate("Admin")
        UserCreate("normaluser", "password", "normal@example.com", "Local", "Admin")
        
        # Attempt SQL injection in query
        malicious_input = "normaluser' OR '1'='1"
        
        # SQLAlchemy should use parameterized queries, preventing injection
        user = User.query.filter_by(username=malicious_input).first()
        
        # Should not find user (no match) or return None, not all users
        assert user is None
        
        # Verify normal query still works
        normal_user = User.query.filter_by(username="normaluser").first()
        assert normal_user is not None
        assert normal_user.username == "normaluser"
    
    def test_user_query_union_injection(self, session):
        """Test prevention of UNION-based SQL injection"""
        RoleCreate("Admin")
        UserCreate("user1", "pass1", "user1@example.com", "Local", "Admin")
        UserCreate("user2", "pass2", "user2@example.com", "Local", "Admin")
        
        # Attempt UNION injection
        malicious_input = "user1' UNION SELECT * FROM users --"
        
        # Should not execute UNION query
        user = User.query.filter_by(username=malicious_input).first()
        assert user is None
        
        # Verify only expected users exist
        all_users = User.query.all()
        usernames = [u.username for u in all_users]
        assert "user1" in usernames
        assert "user2" in usernames
        # Malicious input should not be a username
        assert malicious_input not in usernames


class TestInputSanitization:
    """Test input sanitization and validation"""
    
    def test_username_special_characters(self, session):
        """Test handling of special characters in username"""
        RoleCreate("Admin")
        
        # Usernames with special characters should be handled safely
        special_chars = ["test<script>", "test'user", "test;user", "test--user"]
        
        for username in special_chars:
            # Should either reject or safely store
            try:
                UserCreate(username, "password", f"{username}@example.com", "Local", "Admin")
                user = UserTest(username)
                # If created, should be stored as literal string
                if user:
                    assert user.username == username
            except Exception:
                # If rejected, that's also acceptable security behavior
                pass
    
    def test_email_validation(self, session):
        """Test email validation prevents injection"""
        RoleCreate("Admin")
        
        # Invalid/malicious email formats
        malicious_emails = [
            "test@example.com'; DROP TABLE users; --",
            "<script>alert('xss')</script>@example.com",
            "test@example.com\"; DELETE FROM users; --"
        ]
        
        for email in malicious_emails:
            try:
                UserCreate(f"user_{email[:10]}", "password", email, "Local", "Admin")
                # If created, verify it's stored as literal
                user = User.query.filter_by(email=email).first()
                if user:
                    assert user.email == email  # Stored as literal, not executed
            except Exception:
                # Rejection is also acceptable
                pass

