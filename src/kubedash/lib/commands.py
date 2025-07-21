from flask import Blueprint

from lib.helper_functions import get_logger
from lib.user import UserCreate, UserDelete

cli = Blueprint("cli", __name__)
logger = get_logger()

@cli.cli.command('reset-password')
def reset_password():
    """Reset the default administrator password"""
    passwd = input("New password for default administrator (admin): ")
    print(passwd)
    UserDelete("admin")
    UserCreate("admin", passwd, None, "Local", "Admin")
    print("User Updated Successfully")
