#!/usr/bin/env python3

from functions.components import db, login_manager
import re, logging
from flask_login import UserMixin
from werkzeug.security import generate_password_hash

##############################################################
## functions
##############################################################

logger = logging.getLogger(__name__)

def email_check(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if(re.fullmatch(regex, email)):
        return True
    else:
        return False

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define the User data model.
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(80), unique=True, nullable=True)
    roles = db.relationship('Role', secondary='users_roles',
                            backref=db.backref('users', lazy='dynamic'))
    user_type = db.Column(db.String(5), nullable=False)
    tokens = db.Column(db.Text, nullable=True)
    kubectl_config = db.relationship('kubectlConfig', secondary='users_kubectl',
                            backref=db.backref('users', lazy='dynamic'))

    def __repr__(self):
        return '<User %r>' % self.username

# Define the Role data model
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False, server_default=u'', unique=True)

# Define the UserRoles association model
class UsersRoles(db.Model):
    __tablename__ = 'users_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

def RoleCreate(name):
    role = Role.query.filter(Role.name == name).first()
    if not role:
        role_data = Role(name=name)
        db.session.add(role_data)
        db.session.commit()

def UserTest(username):
    user = User.query.filter_by(username=username).first()
    return user

def UserCreate(username, password, email, user_type, role=None, tokens=None, kubectl_config=None):
    user = UserTest(username)
    if not user:
        if password is None:
            user = User(
                username       = username,
                password_hash  = None,
                email          = email,
                user_type      = user_type,
                tokens         = tokens,
            )
        else:
            user = User(
                username       = username,
                password_hash  = generate_password_hash(password, method='sha256'),
                email          = email,
                user_type      = user_type,
                tokens         = tokens,
            )
        if role:
            role_data = Role.query.filter(Role.name == role).first()
            user.roles.append(role_data)
        if kubectl_config:
            kubectl = kubectlConfig.query.filter(kubectlConfig.name == kubectl_config).first()
            user.kubectl_config.append(kubectl)
        db.session.add(user)
        db.session.commit()

def UserUpdate(username, role, user_type):
    user = User.query.filter_by(username=username).first()
    if user:
        user.role = role
        user.user_type = user_type
        db.session.commit()

def UserDelete(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()

def UserCreateSSO(username, email, tokens, user_type):
    UserCreate(username, None, email, user_type, "User", tokens)

def UserUpdatePassword(username, password):
        user = User.query.filter_by(username=username).first()
        if user:
            user.password_hash = generate_password_hash(password, method='sha256')
            db.session.commit()
            return True
        else:
            return False
        
# Define the kubectlConfig data model
class kubectlConfig(db.Model):
    __tablename__ = 'kubectl_config'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False, server_default=u'', unique=False)
    private_key = db.Column(db.Text, nullable=True)
    user_certificate = db.Column(db.Text, nullable=True)

# Define the UsersKubectl association model
class UsersKubectl(db.Model):
    __tablename__ = 'users_kubectl'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('kubectl_config.id', ondelete='CASCADE'))

def KubectlConfigStore(name, private_key_base64, user_certificate_base64):
    kubectl = kubectlConfig.query.filter(kubectlConfig.name == name).first()
    if not kubectl:
        kubectl_config = kubectlConfig(
            name = name,
            private_key = private_key_base64,
            user_certificate = user_certificate_base64,
        )
        db.session.add(kubectl_config)
        db.session.commit()