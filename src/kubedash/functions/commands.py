from flask import Blueprint
from functions.user import UserCreate, UserDelete
from functions.helper_functions import get_logger

commands = Blueprint("commands", __name__)
logger = get_logger(__name__)

@commands.cli.command('reset-password')
def reset_password():
    passwd = input("New password for default administrator (admin): ")
    print(passwd)
    UserDelete("admin")
    UserCreate("admin", passwd, None, "Local", "Admin")
    print("User Updated Successfully")