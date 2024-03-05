#!/usr/bin/env python3

from functions.helper_functions import get_logger, email_check
from functions.components import db, login_manager, tracer
from contextlib import nullcontext
from flask_login import UserMixin
from werkzeug.security import generate_password_hash
from datetime import datetime
from pytz import timezone

##############################################################
## functions
##############################################################

logger = get_logger(__name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define the User data model.
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=True)
    email = db.Column(db.String(80), unique=True, nullable=True)
    user_type = db.Column(db.String(5), nullable=False)
    tokens = db.Column(db.Text, nullable=True)

    roles = db.relationship('Role', secondary='users_roles',
                            backref=db.backref('users', lazy='dynamic'))
    kubectl_config = db.relationship('KubectlConfig', secondary='users_kubectl',
                            backref=db.backref('users', lazy='dynamic'))
    sso_groups = db.relationship('SSOGroups', secondary='sso_user_group_mapping',
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
    with tracer.start_as_current_span("create-role") if tracer else nullcontext() as span:
        role = Role.query.filter(Role.name == name).first()
        if not role:
            if tracer and span.is_recording():
                span.set_attribute("role.name", name)
            role_data = Role(name=name)
            db.session.add(role_data)
            db.session.commit()

def UserTest(username):
    with tracer.start_as_current_span("test-user") if tracer else nullcontext() as span:
        user = User.query.filter_by(username=username).first()
        return user

def UserCreate(username, password, email, user_type, role=None, tokens=None):
    with tracer.start_as_current_span("create-user") if tracer else nullcontext() as span:
        user = UserTest(username)
        if not user:
            if tracer and span.is_recording():
                span.set_attribute("enduser.name", username)
                span.set_attribute("enduser.type", user_type)
                if email:
                    span.set_attribute("enduser.email", email)
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
                    password_hash  = generate_password_hash(password, method='scrypt'),
                    email          = email,
                    user_type      = user_type,
                    tokens         = tokens,
                )
            if role:
                if tracer and span.is_recording():
                    span.set_attribute("enduser.role", role)
                role_data = Role.query.filter(Role.name == role).first()
                user.roles.append(role_data)
            with db.session.no_autoflush:
                kubectl = KubectlConfig.query.filter(KubectlConfig.name == username).first()
            if kubectl:
                user.kubectl_config.append(kubectl)
            db.session.add(user)
            db.session.commit()

def UserUpdate(username, role, user_type):
    with tracer.start_as_current_span("update-user") if tracer else nullcontext() as span:
        user = User.query.filter_by(username=username).first()
        if user:
            kubectl = KubectlConfig.query.filter(KubectlConfig.name == username).first()
            if kubectl:
                user.kubectl_config.append(kubectl)
            if tracer and span.is_recording():
                span.set_attribute("enduser.name", username)
                span.set_attribute("enduser.role", role)
                span.set_attribute("enduser.type", user_type)
            user.role = role
            user.user_type = user_type
            db.session.commit()

def UserDelete(username):
    with tracer.start_as_current_span("delete-user") if tracer else nullcontext() as span:
        user = User.query.filter_by(username=username).first()
        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        role = Role.query.filter_by(id=user_role.role_id).first()
        user_kubectl = UsersKubectl.query.filter_by(user_id=user.id).first()
        kubectl_config = KubectlConfig.query.filter_by(name=username).first()
        if user:
            if tracer and span.is_recording():
                span.set_attribute("enduser.name", username)
                span.set_attribute("enduser.role", role.name)
                span.set_attribute("enduser.type", user.user_type)
            if user_role:
                db.session.delete(user_role)
            if user_kubectl:
                db.session.delete(user_kubectl)
            if kubectl_config:
                db.session.delete(kubectl_config)
            db.session.delete(user)
            db.session.commit()

def SSOUserCreate(username, email, tokens, user_type):
    with tracer.start_as_current_span("create-user-sso") if tracer else nullcontext() as span:
        if tracer and span.is_recording():
            span.set_attribute("enduser.name", username)
            span.set_attribute("enduser.type", user_type)
            if email:
                span.set_attribute("enduser.email", email)
        UserCreate(username, None, email, user_type, "User", tokens)

def SSOTokenUpdate(username, tokens):
    user = User.query.filter_by(username=username).first()
    if user:
        user.tokens = tokens
        db.session.commit()

def SSOTokenGet(username):
    user = User.query.filter_by(username=username).first()
    if user.tokens:
        return user.tokens

def UserUpdatePassword(username, password):
        user = User.query.filter_by(username=username).first()
        if user:
            user.password_hash = generate_password_hash(password, method='scrypt')
            db.session.commit()
            return True
        else:
            return False
        
########################################################################
# KubectlConfig
########################################################################
# Define the KubectlConfig data model
class KubectlConfig(db.Model):
    __tablename__ = 'kubectl_config'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False, server_default=u'', unique=False)
    cluster = db.Column(db.String(50), nullable=False, server_default=u'', unique=False)
    private_key = db.Column(db.Text, nullable=True)
    user_certificate = db.Column(db.Text, nullable=True)

# Define the UsersKubectl association model
class UsersKubectl(db.Model):
    __tablename__ = 'users_kubectl'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('kubectl_config.id', ondelete='CASCADE'))

def KubectlConfigStore(name, cluster, private_key_base64, user_certificate_base64):
    kubectl = KubectlConfig.query.filter_by(name=name).first()
    if not kubectl:
        kubectl_config = KubectlConfig(
            name = name,
            cluster = cluster,
            private_key = private_key_base64,
            user_certificate = user_certificate_base64,
        )
        db.session.add(kubectl_config)
        db.session.commit()

########################################################################
# SSO Groups
########################################################################

class SSOGroups(db.Model):
    __tablename__ = 'sso_groups'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False, server_default=u'', unique=True)
    created = db.Column(db.DateTime, default=datetime.now().astimezone(timezone('Europe/Budapest')), nullable=False)

class SSOUserGroups(db.Model):
    __tablename__ = 'sso_user_group_mapping'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    group_id = db.Column(db.Integer(), db.ForeignKey('sso_groups.id', ondelete='CASCADE'))

def SSOGroupCreateFromList(username, groups):
    for group in groups:
        SSOGroupsCreate(username, group)

def SSOGroupsUpdateFromList(username, groups):
    for group in groups:
        SSOGroupsUpdate(username, group)

def SSOGroupTest(group_name):
    with tracer.start_as_current_span("test-sso-group") if tracer else nullcontext() as span:
        group = SSOGroups.query.filter_by(name=group_name).first()
        return group

def SSOGroupsCreate(user_name, group_name):
    with tracer.start_as_current_span("create-sso-group") if tracer else nullcontext() as span:
        group = SSOGroupTest(group_name)
        user = UserTest(user_name)
        if user and not group:
            if tracer and span.is_recording():
                span.set_attribute("group.name", group_name)
                span.set_attribute("user.name", user_name)
            group = SSOGroups(name = group_name)
            logger.debug("SSOGroupsCreate: Create %s group" % group_name)
            db.session.add(group)
            db.session.commit()

def SSOGroupsUpdate(user_name, group_name):
    with tracer.start_as_current_span("update-sso-group") if tracer else nullcontext() as span:
        group = SSOGroupTest(group_name)
        user = UserTest(user_name)
        user_not_member = SSOUserGroups.query.filter(SSOUserGroups.group_id == group.id).filter(SSOUserGroups.user_id == user.id).all()
        if user and group and not user_not_member:
            if tracer and span.is_recording():
                span.set_attribute("group.name", group_name)
                span.set_attribute("user.name", user_name)
            logger.debug("SSOGroupsUpdate: Add %s user to %s group" % (user_name, group_name))
            user.sso_groups.append(group)

def SSOGroupsList():
    sso_groups = SSOGroups.query.all()
    sso_group_list = list()
    for group in sso_groups:
        group_data = {
            "name":    group.name,
            "created": group.created,
        }
        sso_group_list.append(group_data)
    return sso_group_list

def SSOGroupsMemberList(sso_group):
    sso_group_data = SSOGroups.query.filter(SSOGroups.name == sso_group).first()
    sso_users = SSOUserGroups.query.filter(SSOUserGroups.group_id == sso_group_data.id).all()
    user_list = list()
    for sso_user in sso_users:
        user = User.query.filter(User.id == sso_user.user_id).first()
        user_data = {
            "name": user.username,
            "email": user.email,
            "type": user.user_type,
        }
        user_list.append(user_data)
    return user_list