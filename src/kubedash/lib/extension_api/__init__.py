#!/usr/bin/env python3
"""
Kubernetes Extension API Server Library

This module provides functionality for implementing a Kubernetes Extension API Server
that serves custom resources like Projects.
"""

from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer

##############################################################
## Module Setup
##############################################################

logger = get_logger()
tracer = get_tracer()

##############################################################
## Exports
##############################################################

from .helpers import (
    get_resource_version,
    build_project_object,
    build_project_list,
    build_status_response,
    build_not_found_response,
    build_forbidden_response,
    build_unauthorized_response,
    API_GROUP,
    API_VERSION,
    API_GROUP_VERSION,
)

from .authentication import (
    AuthenticatedUser,
    authenticate_request,
    extract_bearer_token,
    get_user_from_session_or_token,
)

from .authorization import (
    check_namespace_access,
    filter_namespaces_by_permission,
    can_user_list_all_namespaces,
    check_self_subject_access,
)

from .projects import (
    list_projects,
    get_project,
    create_project,
    update_project,
    delete_project,
    list_all_namespaces,
    get_namespace,
)

from .errors import (
    build_error_response,
    register_error_handlers,
    handle_bad_request,
    handle_unauthorized,
    handle_forbidden,
    handle_not_found,
    handle_method_not_allowed,
    handle_conflict,
    handle_internal_error,
    handle_unexpected_error,
)

__all__ = [
    # Helpers
    "get_resource_version",
    "build_project_object",
    "build_project_list",
    "build_status_response",
    "build_not_found_response",
    "build_forbidden_response",
    "build_unauthorized_response",
    "API_GROUP",
    "API_VERSION",
    "API_GROUP_VERSION",
    # Authentication
    "AuthenticatedUser",
    "authenticate_request",
    "extract_bearer_token",
    "get_user_from_session_or_token",
    # Authorization
    "check_namespace_access",
    "filter_namespaces_by_permission",
    "can_user_list_all_namespaces",
    "check_self_subject_access",
    # Projects
    "list_projects",
    "get_project",
    "create_project",
    "update_project",
    "delete_project",
    "list_all_namespaces",
    "get_namespace",
    # Error Handlers
    "build_error_response",
    "register_error_handlers",
    "handle_bad_request",
    "handle_unauthorized",
    "handle_forbidden",
    "handle_not_found",
    "handle_method_not_allowed",
    "handle_conflict",
    "handle_internal_error",
    "handle_unexpected_error",
    # Module vars
    "logger",
    "tracer",
]
