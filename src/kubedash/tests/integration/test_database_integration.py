"""
Integration tests for database operations
"""
import pytest
import uuid

from lib.components import db
from lib.user import User, Role, UsersRoles


class TestDatabaseIntegration:
    """Test database operations"""
    
    def test_user_role_relationship(self, app):
        """Test user-role relationship"""
        with app.app_context():
            unique_id = str(uuid.uuid4())[:8]
            # Create role with unique name
            role = Role(name=f"TestRole_{unique_id}")
            db.session.add(role)
            db.session.commit()
            
            # Create user with role
            user = User(
                username=f"roletest_{unique_id}",
                password_hash="hash",
                email=f"role_{unique_id}@test.com",
                user_type="Local"
            )
            user.roles.append(role)
            db.session.add(user)
            db.session.commit()
            
            # Verify relationship
            retrieved = User.query.filter_by(username=f"roletest_{unique_id}").first()
            assert retrieved is not None
            assert len(retrieved.roles) == 1
            assert retrieved.roles[0].name == f"TestRole_{unique_id}"
    
    def test_cascade_delete_user_roles(self, app):
        """Test cascade deletion of user-role relationships"""
        with app.app_context():
            unique_id = str(uuid.uuid4())[:8]
            # Setup user with role
            role = Role(name=f"CascadeRole_{unique_id}")
            db.session.add(role)
            
            user = User(
                username=f"cascadetest_{unique_id}",
                password_hash="hash",
                email=f"cascade_{unique_id}@test.com",
                user_type="Local"
            )
            user.roles.append(role)
            db.session.add(user)
            db.session.commit()
            
            user_id = user.id
            role_id = role.id
            
            # Delete user
            db.session.delete(user)
            db.session.commit()
            
            # Verify cascade - user_role mapping should be deleted
            user_role = UsersRoles.query.filter_by(user_id=user_id).first()
            assert user_role is None
            
            # Role should still exist
            role_check = Role.query.filter_by(id=role_id).first()
            assert role_check is not None
    
    def test_database_transaction_rollback(self, app):
        """Test database transaction rollback"""
        with app.app_context():
            unique_id = str(uuid.uuid4())[:8]
            # Create user
            user = User(
                username=f"rollbacktest_{unique_id}",
                password_hash="hash",
                email=f"rollback_{unique_id}@test.com",
                user_type="Local"
            )
            db.session.add(user)
            db.session.commit()
            
            user_id = user.id
            
            # Start nested transaction (savepoint) and rollback
            # Use begin_nested() to create a savepoint for rollback testing
            db.session.begin_nested()
            user.username = "changed"
            db.session.rollback()
            
            # Verify original data
            retrieved = User.query.filter_by(id=user_id).first()
            assert retrieved.username == f"rollbacktest_{unique_id}"
    
    def test_database_query_filtering(self, app):
        """Test database query filtering"""
        with app.app_context():
            unique_id = str(uuid.uuid4())[:8]
            # Create multiple users with unique identifiers
            users = [
                User(username=f"filteruser{i}_{unique_id}", password_hash="hash", 
                     email=f"filter{i}_{unique_id}@test.com", user_type="Local")
                for i in range(3)
            ]
            for user in users:
                db.session.add(user)
            db.session.commit()
            
            # Query with filter
            filtered = User.query.filter_by(user_type="Local").all()
            assert len(filtered) >= 3
            
            # Query specific user
            specific = User.query.filter_by(username=f"filteruser1_{unique_id}").first()
            assert specific is not None
            assert specific.email == f"filter1_{unique_id}@test.com"

