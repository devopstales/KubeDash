from flask import Blueprint
from lib_functions.user import UserCreate, UserDelete
from lib_functions.helper_functions import get_logger

cli = Blueprint("cli", __name__)
logger = get_logger(__name__.split(".")[1])

@cli.cli.command('reset-password')
def reset_password():
    """Reset the default administrator password"""
    passwd = input("New password for default administrator (admin): ")
    print(passwd)
    UserDelete("admin")
    UserCreate("admin", passwd, None, "Local", "Admin")
    print("User Updated Successfully")
