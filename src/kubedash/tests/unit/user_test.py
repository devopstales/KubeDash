"""
Unit tests for user management functions
"""
import pytest
from werkzeug.security import check_password_hash

from lib.user import Role, User, UserCreate, UserDelete, UserTest, UsersRoles, RoleCreate


@pytest.mark.order("first")
def test_user_creation(client, app):
    """Test user creation with role assignment"""
    with app.app_context():
        RoleCreate("Admin")
        UserCreate("pytest", "pytest", None, "Local", "Admin")
        user = User.query.filter_by(username="pytest", user_type="Local").first()
        assert user
        assert user.password_hash != "pytest"
        assert check_password_hash(user.password_hash, "pytest")
        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        role = Role.query.filter_by(id=user_role.role_id).first()
        assert role.name == "Admin"


def test_user_creation_with_email(client, app):
    """Test user creation with email"""
    with app.app_context():
        RoleCreate("Admin")
        UserCreate("pytest_email", "pytest", "test@example.com", "Local", "Admin")
        user = User.query.filter_by(username="pytest_email").first()
        assert user
        assert user.email == "test@example.com"


def test_user_test_function(client, app):
    """Test UserTest function"""
    with app.app_context():
        RoleCreate("Admin")
        UserCreate("testuser", "pass", None, "Local", "Admin")
        user = UserTest("testuser")
        assert user is not None
        assert user.username == "testuser"
        
        # Test non-existent user
        nonexistent = UserTest("nonexistent")
        assert nonexistent is None


def test_user_deletion(client, app):
    """Test user deletion"""
    with app.app_context():
        RoleCreate("Admin")
        UserCreate("deleteuser", "pass", None, "Local", "Admin")
        user = UserTest("deleteuser")
        assert user is not None
        
        UserDelete("deleteuser")
        user = UserTest("deleteuser")
        assert user is None