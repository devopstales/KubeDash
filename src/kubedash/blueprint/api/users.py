"""
Users API endpoints for user management operations.
"""

from contextlib import nullcontext
from flask import g, jsonify, request, session
from flask.views import MethodView
from flask_login import current_user, login_required
from flask_smorest import Blueprint
from werkzeug.security import check_password_hash

from lib.components import db
from lib.helper_functions import get_logger, email_check
from lib.k8s.certificate import k8sCreateUser
from lib.k8s.server import k8sServerContextsList
from lib.opentelemetry import get_tracer
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.security import (
    k8sClusterRoleBindingAdd, k8sClusterRoleBindingGroupGet,
    k8sRoleBindingAdd, k8sRoleBindingGroupGet,
    k8sUserClusterRoleTemplateListGet, k8sUserPriviligeList,
    k8sUserRoleTemplateListGet
)
from lib.audit import log_audit_event
from lib.sso import get_user_token
from lib.user import (
    User, UsersRoles, Role, KubectlConfigStore,
    UserCreate, UserUpdate, UserDelete, UserUpdatePassword,
    SSOGroupsList, SSOGroupsMemberList, SSOGroupsDelete
)

##############################################################
## Blueprint Definition
##############################################################

users_api_bp = Blueprint(
    "users_api",
    "users_api",
    url_prefix="/users",
    description="Users API endpoints - Manage application users, including local and SSO users, user roles, and kubectl configurations"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Users List
##############################################################

@users_api_bp.route('')
class UsersListResource(MethodView):
    """
    Users list endpoint.
    
    Returns a list of all users in the system.
    """
    
    @users_api_bp.response(200, description="Successfully retrieved users list")
    @users_api_bp.response(401, description="Unauthorized - User not authenticated")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def get(self):
        """
        List all users
        
        Retrieves a list of all users including their roles, types, and kubectl configurations.
        
        Returns:
            dict: List of users with metadata
        """
        with tracer.start_as_current_span(
            "users-list",
            attributes={
                "http.route": "/api/v1/users",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            users = User.query.all()
            user_roles = UsersRoles.query.all()
            roles = Role.query.all()
            k8s_contexts = k8sServerContextsList()
            
            # Build response
            users_data = []
            for user in users:
                user_role = next((ur for ur in user_roles if ur.user_id == user.id), None)
                role = next((r for r in roles if r.id == user_role.role_id), None) if user_role else None
                
                users_data.append({
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "user_type": user.user_type,
                    "role": role.name if role else None,
                    "kubectl_configs": [kc.name for kc in user.kubectl_config]
                })
            
            return jsonify({
                "data": users_data,
                "metadata": {
                    "count": len(users_data),
                    "available_roles": [r.name for r in roles],
                    "k8s_contexts": k8s_contexts
                }
            })


@users_api_bp.route('/<username>')
class UserResource(MethodView):
    """
    Individual user endpoint.
    
    Provides GET, PUT, and DELETE operations for a specific user.
    """
    
    @users_api_bp.response(200, description="Successfully retrieved user details")
    @users_api_bp.response(404, description="User not found")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def get(self, username):
        """
        Get user details
        
        Retrieves detailed information about a specific user.
        
        Path Parameters:
            username (str): Username of the user
        
        Returns:
            dict: User details including roles and configurations
        """
        user = User.query.filter_by(username=username).first()
        
        if not user:
            return jsonify({
                "error": "NotFound",
                "message": f"User '{username}' not found"
            }), 404
        
        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        role = Role.query.filter_by(id=user_role.role_id).first() if user_role else None
        
        return jsonify({
            "data": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "user_type": user.user_type,
                "role": role.name if role else None,
                "kubectl_configs": [kc.name for kc in user.kubectl_config]
            }
        })
    
    @users_api_bp.response(200, description="Successfully updated user")
    @users_api_bp.response(400, description="Bad request - Invalid input data")
    @users_api_bp.response(404, description="User not found")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def put(self, username):
        """
        Update user
        
        Updates user information including role and type.
        
        Path Parameters:
            username (str): Username of the user to update
        
        Request Body:
            dict: User update data:
                {
                    "role": str,
                    "type": str,
                    "email": str (optional)
                }
        
        Returns:
            dict: Updated user information
        """
        data = request.get_json() or {}
        role = data.get('role')
        user_type = data.get('type')
        email = data.get('email')
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            return jsonify({
                "error": "NotFound",
                "message": f"User '{username}' not found"
            }), 404
        
        # Update user
        actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
        if user_type != "Local":
            try:
                private_key_base64, user_certificate_base64 = k8sCreateUser(username)
                KubectlConfigStore(username, user_type, private_key_base64, user_certificate_base64)
                log_audit_event(
                    user_id=actor,
                    action="auth_cert_generate",
                    resource=f"user:{username}",
                    result="success",
                    trace_id=getattr(g, "correlation_id", None),
                    details={"context": "user_update"},
                )
            except Exception as e:
                log_audit_event(
                    user_id=actor,
                    action="auth_cert_generate",
                    resource=f"user:{username}",
                    result="failure",
                    trace_id=getattr(g, "correlation_id", None),
                    details={"context": "user_update", "error": str(e)},
                )
                raise
        UserUpdate(username, role, user_type)
        log_audit_event(
            user_id=actor,
            action="user_update",
            resource=f"user:{username}",
            result="success",
            trace_id=getattr(g, "correlation_id", None),
            details={"role": role, "user_type": user_type},
        )
        if email:
            user.email = email
            db.session.commit()
        
        return jsonify({
            "message": "User updated successfully",
            "data": {
                "username": username,
                "role": role,
                "type": user_type
            }
        })
    
    @users_api_bp.response(200, description="Successfully deleted user")
    @users_api_bp.response(404, description="User not found")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def delete(self, username):
        """
        Delete user
        
        Deletes a user from the system.
        
        Path Parameters:
            username (str): Username of the user to delete
        
        Returns:
            dict: Deletion confirmation
        """
        user = User.query.filter_by(username=username).first()
        
        if not user:
            return jsonify({
                "error": "NotFound",
                "message": f"User '{username}' not found"
            }), 404
        
        UserDelete(username)
        actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
        log_audit_event(
            user_id=actor,
            action="user_delete",
            resource=f"user:{username}",
            result="success",
            trace_id=getattr(g, "correlation_id", None),
        )
        return jsonify({
            "message": f"User '{username}' deleted successfully"
        })


@users_api_bp.route('', methods=['POST'])
class UserCreateResource(MethodView):
    """
    User creation endpoint.
    """
    
    @users_api_bp.response(201, description="Successfully created user")
    @users_api_bp.response(400, description="Bad request - Invalid input or user already exists")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def post(self):
        """
        Create user
        
        Creates a new user in the system.
        
        Request Body:
            dict: User creation data:
                {
                    "username": str,
                    "password": str (required for Local users),
                    "email": str,
                    "type": str,
                    "role": str
                }
        
        Returns:
            dict: Created user information
        """
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        user_type = data.get('type')
        role = data.get('role')
        
        # Validation
        if not username:
            return jsonify({
                "error": "BadRequest",
                "message": "Username is required"
            }), 400
        
        if user_type == "Local" and not password:
            return jsonify({
                "error": "BadRequest",
                "message": "Password is required for Local users"
            }), 400
        
        if user_type == "Local" and len(password) < 8:
            return jsonify({
                "error": "BadRequest",
                "message": "Password must be at least 8 characters"
            }), 400
        
        if email and not email_check(email):
            return jsonify({
                "error": "BadRequest",
                "message": "Invalid email format"
            }), 400
        
        # Check if user exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({
                "error": "Conflict",
                "message": f"User '{username}' already exists"
            }), 400
        
        # Create user
        actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
        if user_type != "Local":
            try:
                private_key_base64, user_certificate_base64 = k8sCreateUser(username)
                KubectlConfigStore(username, user_type, private_key_base64, user_certificate_base64)
                log_audit_event(
                    user_id=actor,
                    action="auth_cert_generate",
                    resource=f"user:{username}",
                    result="success",
                    trace_id=getattr(g, "correlation_id", None),
                    details={"context": "user_create"},
                )
            except Exception as e:
                log_audit_event(
                    user_id=actor,
                    action="auth_cert_generate",
                    resource=f"user:{username}",
                    result="failure",
                    trace_id=getattr(g, "correlation_id", None),
                    details={"context": "user_create", "error": str(e)},
                )
                raise
        UserCreate(username, password, email, user_type, role, None)
        log_audit_event(
            user_id=actor,
            action="user_create",
            resource=f"user:{username}",
            result="success",
            trace_id=getattr(g, "correlation_id", None),
            details={"user_type": user_type, "role": role},
        )
        return jsonify({
            "message": "User created successfully",
            "data": {
                "username": username,
                "email": email,
                "type": user_type,
                "role": role
            }
        }), 201


@users_api_bp.route('/<username>/password')
class UserPasswordResource(MethodView):
    """
    User password management endpoint.
    """
    
    @users_api_bp.response(200, description="Successfully updated password")
    @users_api_bp.response(400, description="Bad request - Invalid password or wrong current password")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def put(self, username):
        """
        Update user password
        
        Updates the password for a user. Requires the current password.
        
        Path Parameters:
            username (str): Username of the user
        
        Request Body:
            dict: Password update data:
                {
                    "old_password": str,
                    "new_password": str
                }
        
        Returns:
            dict: Update confirmation
        """
        data = request.get_json() or {}
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        
        if not old_password or not new_password:
            return jsonify({
                "error": "BadRequest",
                "message": "Both old_password and new_password are required"
            }), 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            return jsonify({
                "error": "NotFound",
                "message": f"User '{username}' not found"
            }), 404
        
        if not check_password_hash(user.password_hash, old_password):
            actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
            log_audit_event(
                user_id=actor,
                action="password_change",
                resource=f"user:{username}",
                result="failure",
                trace_id=getattr(g, "correlation_id", None),
                details={"reason": "wrong_current_password"},
            )
            return jsonify({
                "error": "Unauthorized",
                "message": "Wrong current password"
            }), 400
        
        updated = UserUpdatePassword(username, new_password)
        
        if updated:
            actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
            log_audit_event(
                user_id=actor,
                action="password_change",
                resource=f"user:{username}",
                result="success",
                trace_id=getattr(g, "correlation_id", None),
            )
            return jsonify({
                "message": "Password updated successfully"
            })
        else:
            actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
            log_audit_event(
                user_id=actor,
                action="password_change",
                resource=f"user:{username}",
                result="failure",
                trace_id=getattr(g, "correlation_id", None),
                details={"reason": "update_failed"},
            )
            return jsonify({
                "error": "InternalError",
                "message": "Could not update user password"
            }), 500


@users_api_bp.route('/sso/groups')
class SSOGroupsResource(MethodView):
    """
    SSO groups endpoint.
    
    Returns SSO groups and their members.
    """
    
    @users_api_bp.response(200, description="Successfully retrieved SSO groups")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def get(self):
        """
        List SSO groups
        
        Retrieves all SSO groups and optionally their members.
        
        Query Parameters:
            include_members (bool): If true, include group members (default: false)
        
        Returns:
            dict: List of SSO groups with optional members
        """
        include_members = request.args.get('include_members', 'false').lower() == 'true'
        
        groups = SSOGroupsList()
        
        groups_data = []
        for group in groups:
            # group is a dict, not an object
            group_name = group.get('name') if isinstance(group, dict) else group.name
            group_created = group.get('created') if isinstance(group, dict) else getattr(group, 'created', None)
            
            group_data = {
                "name": group_name,
                "created": group_created.strftime('%Y-%m-%d %H:%M:%S') if group_created else None,
                "description": group.get('description') if isinstance(group, dict) else getattr(group, 'description', None)
            }
            
            if include_members:
                members = SSOGroupsMemberList(group_name)
                # members is a list of dicts with 'name', 'email', 'type' keys
                group_data["members"] = [m.get('name') if isinstance(m, dict) else m.username for m in members]
            
            groups_data.append(group_data)
        
        return jsonify({
            "data": groups_data,
            "metadata": {
                "count": len(groups_data),
                "include_members": include_members
            }
        })


@users_api_bp.route('/sso/groups/<group_name>', methods=['DELETE'])
class SSOGroupResource(MethodView):
    """
    Single SSO group endpoint (delete).
    """

    @users_api_bp.response(200, description="Successfully deleted group")
    @users_api_bp.response(404, description="Group not found")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def delete(self, group_name):
        """
        Delete SSO group

        Path Parameters:
            group_name (str): Name of the SSO group to delete

        Returns:
            dict: Deletion confirmation
        """
        actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
        deleted = SSOGroupsDelete(group_name)
        if not deleted:
            log_audit_event(
                user_id=actor,
                action="group_delete",
                resource=f"group:{group_name}",
                result="failure",
                trace_id=getattr(g, "correlation_id", None),
                details={"reason": "not_found"},
            )
            return jsonify({
                "error": "NotFound",
                "message": f"Group '{group_name}' not found"
            }), 404
        log_audit_event(
            user_id=actor,
            action="group_delete",
            resource=f"group:{group_name}",
            result="success",
            trace_id=getattr(g, "correlation_id", None),
        )
        return jsonify({
            "message": f"Group '{group_name}' deleted successfully",
            "data": {"name": group_name}
        }), 200


##############################################################
## User Info
##############################################################

@users_api_bp.route('/info')
class UserInfoResource(MethodView):
    """
    Current user info endpoint.
    """
    
    @users_api_bp.response(200, description="Successfully retrieved user info")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def get(self):
        """
        Get current user info
        
        Returns information about the currently authenticated user.
        
        Returns:
            dict: Current user information
        """
        username = session.get('user_name')
        if not username:
            return jsonify({
                "error": "Unauthorized",
                "message": "User not authenticated"
            }), 401
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({
                "error": "NotFound",
                "message": f"User '{username}' not found"
            }), 404
        
        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        role = Role.query.filter_by(id=user_role.role_id).first() if user_role else None
        
        return jsonify({
            "data": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "user_type": user.user_type,
                "role": role.name if role else None
            }
        })


##############################################################
## User Privileges
##############################################################

@users_api_bp.route('/<username>/privileges')
class UserPrivilegesResource(MethodView):
    """
    User privileges endpoint.
    """
    
    @users_api_bp.response(200, description="Successfully retrieved user privileges")
    @users_api_bp.response(404, description="User not found")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def get(self, username):
        """
        Get user privileges
        
        Retrieves all Kubernetes RBAC privileges (roles and cluster roles) for a user.
        
        Path Parameters:
            username (str): Username of the user
        
        Returns:
            dict: User privileges including cluster roles and namespaced roles
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "user-privileges-get",
            attributes={
                "http.route": "/api/v1/users/{username}/privileges",
                "http.method": "GET",
                "user.username": username,
            }
        ) if tracer else nullcontext():
            user_cluster_roles, user_roles = k8sUserPriviligeList(
                session['user_role'], user_token, username
            )
            
            return jsonify({
                "data": {
                    "user_cluster_roles": user_cluster_roles,
                    "user_roles": user_roles
                },
                "metadata": {
                    "username": username
                }
            })


@users_api_bp.route('/<username>/privileges', methods=['POST'])
class UserPrivilegesUpdateResource(MethodView):
    """
    Update user privileges endpoint.
    """
    
    @users_api_bp.response(200, description="Successfully updated user privileges")
    @users_api_bp.response(400, description="Bad request - Invalid input data")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def post(self, username):
        """
        Update user privileges
        
        Updates Kubernetes RBAC privileges for a user.
        
        Path Parameters:
            username (str): Username of the user
        
        Request Body:
            dict: Privilege update data:
                {
                    "user_cluster_role": str (optional),
                    "user_namespaced_role_1": str (optional),
                    "user_all_namespaces_1": bool (optional),
                    "user_namespaces_1": list[str] (optional),
                    "user_namespaced_role_2": str (optional),
                    "user_all_namespaces_2": bool (optional),
                    "user_namespaces_2": list[str] (optional)
                }
        
        Returns:
            dict: Update confirmation
        """
        data = request.get_json() or request.form.to_dict()
        
        user_cluster_role = data.get('user_cluster_role')
        user_namespaced_role_1 = data.get('user_namespaced_role_1')
        user_all_namespaces_1 = data.get('user_all_namespaces_1')
        user_namespaces_1 = data.getlist('user_namespaces_1') if hasattr(data, 'getlist') else data.get('user_namespaces_1', [])
        user_namespaced_role_2 = data.get('user_namespaced_role_2')
        user_all_namespaces_2 = data.get('user_all_namespaces_2')
        user_namespaces_2 = data.getlist('user_namespaces_2') if hasattr(data, 'getlist') else data.get('user_namespaces_2', [])
        
        if user_cluster_role:
            k8sClusterRoleBindingAdd(user_cluster_role, username, None)
        
        if user_namespaced_role_1:
            if user_all_namespaces_1:
                k8sRoleBindingAdd(user_namespaced_role_1, username, None, None, user_all_namespaces_1)
            else:
                k8sRoleBindingAdd(user_namespaced_role_1, username, None, user_namespaces_1, user_all_namespaces_1)
        
        if user_namespaced_role_2:
            if user_all_namespaces_2:
                k8sRoleBindingAdd(user_namespaced_role_2, username, None, None, user_all_namespaces_2)
            else:
                k8sRoleBindingAdd(user_namespaced_role_2, username, None, user_namespaces_2, user_all_namespaces_2)

        actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
        log_audit_event(
            user_id=actor,
            action="user_privilege_update",
            resource=f"user:{username}",
            result="success",
            trace_id=getattr(g, "correlation_id", None),
        )
        return jsonify({
            "message": "User privileges updated successfully"
        })


@users_api_bp.route('/privileges/templates')
class UserPrivilegeTemplatesResource(MethodView):
    """
    User privilege templates endpoint.
    """
    
    @users_api_bp.response(200, description="Successfully retrieved privilege templates")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def get(self):
        """
        Get privilege templates
        
        Retrieves available role templates for assigning privileges.
        
        Returns:
            dict: Role templates including namespaced and cluster role templates
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "user-privilege-templates",
            attributes={
                "http.route": "/api/v1/users/privileges/templates",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
            
            if error:
                namespace_list = []
            
            user_role_template_list = k8sUserRoleTemplateListGet(session['user_role'], user_token)
            user_clusterRole_template_list = k8sUserClusterRoleTemplateListGet(session['user_role'], user_token)
            
            # Ensure templates exist
            if not user_clusterRole_template_list or not user_role_template_list:
                from lib.k8s import k8sClusterRolesAdd
                k8sClusterRolesAdd()
                user_role_template_list = k8sUserRoleTemplateListGet(session['user_role'], user_token)
                user_clusterRole_template_list = k8sUserClusterRoleTemplateListGet(session['user_role'], user_token)
            
            return jsonify({
                "data": {
                    "role_templates": user_role_template_list or [],
                    "cluster_role_templates": user_clusterRole_template_list or [],
                    "namespaces": namespace_list or []
                }
            })


##############################################################
## Group Privileges
##############################################################

@users_api_bp.route('/groups/<group_name>/privileges')
class GroupPrivilegesResource(MethodView):
    """
    Group privileges endpoint.
    """
    
    @users_api_bp.response(200, description="Successfully retrieved group privileges")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def get(self, group_name):
        """
        Get group privileges
        
        Retrieves all Kubernetes RBAC privileges for an SSO group.
        
        Path Parameters:
            group_name (str): Name of the SSO group
        
        Returns:
            dict: Group privileges including members, role bindings, and cluster role bindings
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "group-privileges-get",
            attributes={
                "http.route": "/api/v1/users/groups/{group_name}/privileges",
                "http.method": "GET",
                "group.name": group_name,
            }
        ) if tracer else nullcontext():
            groupe_member_list = SSOGroupsMemberList(group_name)
            group_cluster_role_binding = k8sClusterRoleBindingGroupGet(
                group_name, session['user_role'], user_token
            )
            group_role_binding = k8sRoleBindingGroupGet(
                group_name, session['user_role'], user_token
            )
            
            # groupe_member_list is a list of dicts with 'name', 'email', 'type' keys
            members_data = []
            for m in groupe_member_list:
                if isinstance(m, dict):
                    members_data.append({
                        "name": m.get('name'),
                        "email": m.get('email'),
                        "type": m.get('type')
                    })
                else:
                    # Fallback for object format (shouldn't happen, but just in case)
                    members_data.append({
                        "name": getattr(m, 'name', None),
                        "email": getattr(m, 'email', None),
                        "type": getattr(m, 'type', None)
                    })
            
            return jsonify({
                "data": {
                    "group_name": group_name,
                    "members": members_data,
                    "role_bindings": group_role_binding,
                    "cluster_role_bindings": group_cluster_role_binding
                }
            })


@users_api_bp.route('/groups/<group_name>/privileges', methods=['POST'])
class GroupPrivilegesUpdateResource(MethodView):
    """
    Update group privileges endpoint.
    """
    
    @users_api_bp.response(200, description="Successfully updated group privileges")
    @users_api_bp.response(400, description="Bad request - Invalid input data")
    @users_api_bp.doc(tags=['Users'])
    @login_required
    def post(self, group_name):
        """
        Update group privileges
        
        Updates Kubernetes RBAC privileges for an SSO group.
        
        Path Parameters:
            group_name (str): Name of the SSO group
        
        Request Body:
            dict: Privilege update data:
                {
                    "user_cluster_role": str (optional),
                    "user_namespaced_role_1": str (optional),
                    "user_all_namespaces_1": bool (optional),
                    "user_namespaces_1": list[str] (optional),
                    "user_namespaced_role_2": str (optional),
                    "user_all_namespaces_2": bool (optional),
                    "user_namespaces_2": list[str] (optional)
                }
        
        Returns:
            dict: Update confirmation
        """
        data = request.get_json() or request.form.to_dict()
        
        user_cluster_role = data.get('user_cluster_role')
        user_namespaced_role_1 = data.get('user_namespaced_role_1')
        user_all_namespaces_1 = data.get('user_all_namespaces_1')
        user_namespaces_1 = data.getlist('user_namespaces_1') if hasattr(data, 'getlist') else data.get('user_namespaces_1', [])
        user_namespaced_role_2 = data.get('user_namespaced_role_2')
        user_all_namespaces_2 = data.get('user_all_namespaces_2')
        user_namespaces_2 = data.getlist('user_namespaces_2') if hasattr(data, 'getlist') else data.get('user_namespaces_2', [])
        
        if user_cluster_role:
            k8sClusterRoleBindingAdd(user_cluster_role, None, group_name)
        
        if user_namespaced_role_1:
            if user_all_namespaces_1:
                k8sRoleBindingAdd(user_namespaced_role_1, None, group_name, None, user_all_namespaces_1)
            else:
                k8sRoleBindingAdd(user_namespaced_role_1, None, group_name, user_namespaces_1, user_all_namespaces_1)
        
        if user_namespaced_role_2:
            if user_all_namespaces_2:
                k8sRoleBindingAdd(user_namespaced_role_2, None, group_name, None, user_all_namespaces_2)
            else:
                k8sRoleBindingAdd(user_namespaced_role_2, None, group_name, user_namespaces_2, user_all_namespaces_2)

        actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
        log_audit_event(
            user_id=actor,
            action="group_privilege_update",
            resource=f"group:{group_name}",
            result="success",
            trace_id=getattr(g, "correlation_id", None),
        )
        return jsonify({
            "message": "Group privileges updated successfully"
        })

