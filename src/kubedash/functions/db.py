#!/usr/bin/env python3
import os
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

def init_db(SQL_PATH):
    if not os.path.exists(SQL_PATH):
        from functions.db import dbCreate
        dbCreate()