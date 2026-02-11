
import logging
import os

import flask_migrate
import pytest
from flask.testing import FlaskClient
from flask_login import login_user

# Set TESTING environment variable before importing to prevent module-level app creation
os.environ['FLASK_ENV'] = 'testing'

from kubedash import create_app
from lib.components import db
from lib.user import User, Role, UserCreate, UsersRoles


@pytest.fixture(scope='session')
def app():
    """Create and configure test application"""
    # Create app with testing configuration
    app = create_app("testing")

    # Run migrations before any database operations
    with app.app_context():
        try:
            flask_migrate.upgrade()
        except Exception as e:
            # If migrations fail, try to create all tables
            # This handles cases where migrations might not be set up
            db.create_all()
            app.logger.warning(f"Migration upgrade failed, using create_all: {e}")
        
    yield app
    
    # Cleanup after all tests
    with app.app_context():
        db.session.remove()
        # Don't drop_all in case we want to inspect the database after tests
        # db.drop_all()


@pytest.fixture(scope='function')
def client(app):
    """Create test client"""
    ctx = app.test_request_context()
    # file deepcode ignore DisablesCSRFProtection/test: <please specify a reason of ignoring this>
    ctx.push()
    app.test_client_class = FlaskClient
    yield app.test_client()
    ctx.pop()


@pytest.fixture(scope='function')
def session(app):
    """Create database session for each test with transaction rollback
    
    Note: SQLite has limited support for nested transactions. This fixture
    attempts to use savepoints, but tests should use unique identifiers
    (emails, usernames, etc.) to avoid conflicts if rollback doesn't work perfectly.
    """
    with app.app_context():
        # Start a transaction for this test
        # SQLite supports savepoints, so we can use begin_nested()
        # Check if we're already in a transaction by checking _transaction attribute
        try:
            # Try to create a savepoint (nested transaction)
            # This will work if we're already in a transaction
            db.session.begin_nested()
        except Exception:
            # If begin_nested fails, we're not in a transaction yet
            # Start a new transaction
            try:
                db.session.begin()
            except Exception:
                # If begin() also fails, the session might already be in autocommit mode
                # Just proceed - rollback will still work
                pass
        
        yield db.session
        
        # Rollback all changes made during the test
        try:
            db.session.rollback()
        except Exception:
            pass
        finally:
            db.session.remove()


@pytest.fixture
def authenticated_client(client, app):
    """Client with authenticated session"""
    with app.app_context():
        # Create test user if it doesn't exist
        user = User.query.filter_by(username="testuser").first()
        if not user:
            RoleCreate("Admin")
            UserCreate("testuser", "testpass", "test@example.com", "Local", "Admin")
            user = User.query.filter_by(username="testuser").first()
        
        # Login the user
        with client.session_transaction() as sess:
            login_user(user)
            sess['user_name'] = "testuser"
            sess['user_role'] = "Admin"
            sess['user_type'] = "Local"
            sess['ns_select'] = "default"
    
    return client


@pytest.fixture
def admin_user(app):
    """Create and return an admin user"""
    with app.app_context():
        RoleCreate("Admin")
        user = User.query.filter_by(username="admin").first()
        if not user:
            UserCreate("admin", "admin", "admin@example.com", "Local", "Admin")
            user = User.query.filter_by(username="admin").first()
        return user


@pytest.fixture
def regular_user(app):
    """Create and return a regular user"""
    with app.app_context():
        RoleCreate("User")
        user = User.query.filter_by(username="regularuser").first()
        if not user:
            UserCreate("regularuser", "userpass", "user@example.com", "Local", "User")
            user = User.query.filter_by(username="regularuser").first()
        return user


@pytest.fixture(autouse=True)
def clear_cache(app):
    """Clear cache before each test to avoid cache pollution between tests"""
    with app.app_context():
        from lib.components import cache
        try:
            cache.clear()
        except Exception:
            # Cache might not be initialized or might not support clear()
            pass
    yield
    # Clear cache after test as well
    with app.app_context():
        try:
            cache.clear()
        except Exception:
            pass