import logging
from flask import Blueprint
from functions.user import UserCreate, UserDelete

commands = Blueprint("commands", __name__)
logger = logging.getLogger(__name__)
logging.basicConfig(
        level="INFO",
        format='[%(asctime)s] %(name)s        %(levelname)s %(message)s'
    )

@commands.cli.command('reset-password')
def reset_password():
    passwd = input("New password for default administrator (admin): ")
    print(passwd)
    UserDelete("admin")
    UserCreate("admin", passwd, None, "Local", "Admin")
    print("User Updated Successfully")