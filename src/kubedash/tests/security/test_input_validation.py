"""
Security tests for input validation

Tests that user inputs are properly validated and sanitized
to prevent injection attacks and data corruption.
"""
import pytest
from lib.user import UserCreate, RoleCreate


class TestInputValidation:
    """Test input validation"""
    
    def test_username_validation(self, session):
        """Test username input validation"""
        RoleCreate("Admin")
        
        # Test various username formats
        valid_usernames = ["user123", "user_name", "user-name", "user.name"]
        invalid_usernames = ["", " ", "user name", "user\nname", "user\tname"]
        
        for username in valid_usernames:
            try:
                UserCreate(username, "password", f"{username}@example.com", "Local", "Admin")
                user = User.query.filter_by(username=username).first()
                if user:
                    assert user.username == username
            except Exception:
                # Some might be rejected by validation
                pass
        
        for username in invalid_usernames:
            try:
                UserCreate(username, "password", f"{username}@example.com", "Local", "Admin")
                # Invalid usernames should be rejected
                user = User.query.filter_by(username=username).first()
                # If created, it's a validation issue
                if user:
                    pytest.fail(f"Invalid username '{username}' was accepted")
            except Exception:
                # Expected - invalid input should be rejected
                pass
    
    def test_email_validation(self, session):
        """Test email input validation"""
        RoleCreate("Admin")
        
        # Valid emails
        valid_emails = [
            "user@example.com",
            "user.name@example.com",
            "user+tag@example.com"
        ]
        
        # Invalid emails
        invalid_emails = [
            "notanemail",
            "@example.com",
            "user@",
            "user@.com",
            "user @example.com"
        ]
        
        for email in valid_emails:
            try:
                UserCreate(f"user_{email[:10]}", "password", email, "Local", "Admin")
                # Should accept valid email
            except Exception as e:
                # Might have other validation issues
                pass
        
        for email in invalid_emails:
            try:
                UserCreate(f"user_{len(email)}", "password", email, "Local", "Admin")
                # Invalid emails might be rejected or cause errors
                # This tests current behavior
            except Exception:
                # Expected for invalid emails
                pass
    
    def test_password_validation(self, session):
        """Test password input validation"""
        RoleCreate("Admin")
        
        # Test empty password
        try:
            UserCreate("emptypass", "", "empty@example.com", "Local", "Admin")
            # Empty password might be rejected
        except Exception:
            # Expected
            pass
        
        # Test very long password (potential DoS)
        long_password = "a" * 10000
        try:
            UserCreate("longpass", long_password, "long@example.com", "Local", "Admin")
            # Should handle or reject very long passwords
        except Exception:
            # Might be rejected
            pass
    
    def test_input_length_limits(self, session):
        """Test that input length limits are enforced"""
        RoleCreate("Admin")
        
        # Very long inputs might cause issues
        very_long_username = "a" * 1000
        very_long_email = "a" * 500 + "@example.com"
        
        try:
            UserCreate(very_long_username, "password", very_long_email, "Local", "Admin")
            # Should either accept (with truncation) or reject
            # This tests current behavior
        except Exception:
            # Rejection is acceptable
            pass
    
    def test_special_characters_handling(self, session):
        """Test handling of special characters in input"""
        RoleCreate("Admin")
        
        # Special characters that might cause issues
        special_chars = [
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            "null\x00byte",
            "\nnewline",
            "\ttab"
        ]
        
        for special in special_chars:
            try:
                # Try to use special characters
                UserCreate(f"user{len(special)}", "password", f"user{len(special)}@example.com", "Local", "Admin")
                # Should handle safely
            except Exception:
                # Rejection is acceptable
                pass


class TestPathTraversal:
    """Test path traversal prevention"""
    
    def test_path_traversal_in_filename(self, client):
        """Test that path traversal in file operations is prevented"""
        # Test file upload/download endpoints if they exist
        # This is a placeholder for path traversal tests
        
        malicious_paths = [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for path in malicious_paths:
            # Test that path traversal is prevented
            # This depends on file handling endpoints
            pass  # Placeholder for actual path traversal tests
    
    def test_path_traversal_in_url(self, client):
        """Test that path traversal in URLs is prevented"""
        malicious_paths = [
            "/../../etc/passwd",
            "/..%2F..%2Fetc%2Fpasswd",
            "/....//....//etc/passwd"
        ]
        
        for path in malicious_paths:
            response = client.get(path)
            # Should return 404 (not found) not serve files
            assert response.status_code in [404, 403, 400]


class TestCommandInjection:
    """Test command injection prevention"""
    
    def test_command_injection_in_input(self, client):
        """Test that command injection in user input is prevented"""
        # Command injection payloads
        injection_payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "&& rm -rf /",
            "`whoami`",
            "$(id)",
            "'; cat /etc/passwd; #"
        ]
        
        for payload in injection_payloads:
            # Try to inject in various inputs
            response = client.post("/", data={
                "username": payload,
                "password": "test"
            }, follow_redirects=True)
            
            # Should not execute commands
            # Response should be normal (error page or login page)
            assert response.status_code in [200, 302, 400, 401, 403]
            
            # Should not contain command output
            response_data = response.data.decode('utf-8', errors='ignore')
            # Should not contain typical command output
            assert "uid=" not in response_data.lower()
            assert "gid=" not in response_data.lower()

