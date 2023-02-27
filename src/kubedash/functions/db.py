#!/usr/bin/env python3

class dbCreate():
    from functions.user import UserCreate, RoleCreate
    from kubedash import db, app
    from sqlalchemy_utils import database_exists

    # Roles
    roles = [
        "Admin",
        "User",
    ]

    if database_exists(app.config['SQLALCHEMY_DATABASE_URI']):
        for r in roles:
            RoleCreate(r)
        UserCreate("admin", "admin", None, "Local", "Admin")
    else:
        with app.app_context():
            db.create_all()
            for r in roles:
                RoleCreate(r)
            UserCreate("admin", "admin", None, "Local", "Admin")
