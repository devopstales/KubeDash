"""
Integration tests for user management
"""
import pytest
import uuid
from werkzeug.security import check_password_hash

from lib.user import User, Role, UserCreate, UserDelete, UserTest, UsersRoles, RoleCreate


class TestUserManagement:
    """Test user management operations"""
    
    def test_user_creation(self, session):
        """Test creating a new user"""
        RoleCreate("TestRole")
        UserCreate(
            username="newuser",
            password="testpass123",
            email="newuser@example.com",
            user_type="Local",
            role="TestRole"
        )
        
        user = UserTest("newuser")
        assert user is not None
        assert user.username == "newuser"
        assert user.email == "newuser@example.com"
        assert user.user_type == "Local"
        assert check_password_hash(user.password_hash, "testpass123")
    
    def test_user_password_hashing(self, session):
        """Test password is properly hashed"""
        RoleCreate("HashRole")
        UserCreate(
            username="hashtest",
            password="plaintext",
            email="hash@test.com",
            user_type="Local",
            role="HashRole"
        )
        
        user = UserTest("hashtest")
        assert user.password_hash != "plaintext"
        assert user.password_hash.startswith("scrypt:")
        assert check_password_hash(user.password_hash, "plaintext")
    
    def test_user_role_assignment(self, session):
        """Test user role assignment"""
        unique_id = str(uuid.uuid4())[:8]
        role_name = f"UserRole_{unique_id}"
        username = f"roleuser_{unique_id}"
        email = f"role_{unique_id}@test.com"
        RoleCreate(role_name)
        UserCreate(
            username=username,
            password="pass",
            email=email,
            user_type="Local",
            role=role_name
        )
        
        user = UserTest(username)
        assert user is not None
        
        # Check role assignment
        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        assert user_role is not None
        
        role = Role.query.filter_by(id=user_role.role_id).first()
        assert role.name == role_name
    
    def test_duplicate_user_creation(self, session):
        """Test duplicate user handling"""
        RoleCreate("DupRole")
        UserCreate("dupuser", "pass", "dup@test.com", "Local", "DupRole")
        
        # Try to create duplicate
        UserCreate("dupuser", "pass2", "dup2@test.com", "Local", "DupRole")
        
        # Should only have one user
        users = User.query.filter_by(username="dupuser").all()
        assert len(users) == 1
    
    def test_user_deletion(self, session):
        """Test user deletion"""
        RoleCreate("DeleteRole")
        UserCreate("deleteuser", "pass", "del@test.com", "Local", "DeleteRole")
        
        user = UserTest("deleteuser")
        assert user is not None
        
        UserDelete("deleteuser")
        user = UserTest("deleteuser")
        assert user is None
    
    def test_user_query_by_type(self, session):
        """Test querying users by type"""
        RoleCreate("TypeRole")
        UserCreate("localuser", "pass", "local@test.com", "Local", "TypeRole")
        UserCreate("oidcuser", "pass", "oidc@test.com", "OpenID", "TypeRole")
        
        local_users = User.query.filter_by(user_type="Local").all()
        assert len(local_users) >= 1
        assert any(u.username == "localuser" for u in local_users)
        
        oidc_users = User.query.filter_by(user_type="OpenID").all()
        assert len(oidc_users) >= 1
        assert any(u.username == "oidcuser" for u in oidc_users)
    
    def test_user_email_uniqueness(self, session):
        """Test email uniqueness constraint"""
        unique_id = str(uuid.uuid4())[:8]
        role_name = f"EmailRole_{unique_id}"
        email = f"same_{unique_id}@test.com"
        RoleCreate(role_name)
        UserCreate(f"user1_{unique_id}", "pass", email, "Local", role_name)
        
        # Try to create user with same email - should fail with IntegrityError
        import pytest
        from sqlalchemy.exc import IntegrityError
        from lib.components import db
        with pytest.raises(IntegrityError):
            UserCreate(f"user2_{unique_id}", "pass", email, "Local", role_name)
        
        # Rollback the session after the exception to clear the error state
        db.session.rollback()
        
        # Check behavior - should only have one user
        users_with_email = User.query.filter_by(email=email).all()
        # Email constraint should be enforced
        assert len(users_with_email) == 1

