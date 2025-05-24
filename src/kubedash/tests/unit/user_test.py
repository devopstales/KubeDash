
import pytest
from werkzeug.security import check_password_hash

from lib.user import Role, User, UserCreate, UsersRoles


@pytest.mark.order("first")
def test_user_creation(client):
    UserCreate("pytest", "pytest", None, "Local", "Admin")
    user = User.query.filter_by(username="pytest", user_type = "Local").first()
    assert user
    assert user.password_hash != "pytest"
    assert check_password_hash(user.password_hash, "pytest")
    user_role = UsersRoles.query.filter_by(user_id=user.id).first()
    role = Role.query.filter_by(id=user_role.role_id).first()
    assert role.name == "Admin"