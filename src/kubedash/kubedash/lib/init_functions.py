
import configparser
import os
import string
from typing import List
import requests
from requests.exceptions import RequestException
from urllib.parse import urljoin
from flask import Flask

from itsdangerous import base64_encode
from sqlalchemy import create_engine, inspect

from .helper_functions import get_logger, string2list
from .k8s.security import (k8sClusterRolesAdd,
                           k8sUserClusterRoleTemplateListGet,
                           k8sUserRoleTemplateListGet)
from .k8s.server import (k8sServerConfigCreate, k8sServerConfigGet,
                         k8sServerConfigUpdate)
from .prometheus import (METRIC_DB_CONNECTION, METRIC_K8S_CONFIG_UPDATE,
                         METRIC_OIDC_CONFIG_UPDATE)
from .sso import SSOServerCreate, SSOServerTest, SSOServerUpdate
from .user import RoleCreate, UserCreate, UserTest

##############################################################
## Variables
##############################################################

# Roles
roles = [
    "Admin",
    "User",
]

logger = get_logger()

##############################################################
## Helper Functions
##############################################################

def validate_scopes(requested_scopes: List[str], issuer_url: str) -> List[str]:
    """
    Validate requested scopes against the IDP's supported scopes.
    
    Args:
        requested_scopes: List of scopes to validate
        issuer_url: OIDC issuer URL
        
    Returns:
        List of valid scopes
        
    Raises:
        ValueError: If scope validation fails
    """
    try:
        # Get OIDC discovery document
        if not issuer_url.endswith('/'):
            issuer_url += '/'
        well_known_url = urljoin(issuer_url, '.well-known/openid-configuration')   
        logger.debug(f"Fetching OIDC configuration from: {well_known_url}")
        response = requests.get(well_known_url, timeout=5)
        response.raise_for_status()
        oidc_config = response.json()
        
        # Get supported scopes (default to standard scopes if not specified)
        supported_scopes = set(oidc_config.get('scopes_supported', [
            'openid', 'profile', 'email', 'roles'
        ]))
        
        # Always include 'openid' scope
        supported_scopes.add('openid')
        
        # Filter invalid scopes
        valid_scopes = [s for s in requested_scopes if s in supported_scopes]
        
        if not valid_scopes:
            raise ValueError("No valid scopes found")
            
        return valid_scopes
        
    except RequestException as e:
        logger.warning(f"Failed to fetch OIDC configuration: {e}")
        # Fallback to basic openid scope if validation fails
        return ['openid']

##############################################################
## Init Functions
##############################################################

def db_init_roles(config: configparser.ConfigParser):
    """Create Roles and Users in the database
    
    Args:
        config (configparser.ConfigParser): Configuration
    """
    for r in roles:
        RoleCreate(r)
    admin_password = config.get('security', 'admin_password', fallback="admin")
    UserCreate("admin", admin_password, None, "Local", "Admin")

def connect_database() -> bool:
    """Test Databse Connection
    
    Returns:
        status (bool): A flag indicating if the database connection was successful
    """
    try:
        user = UserTest('admin')
        if user:
            return True
        else:
            return False
    except Exception:
        return False

def init_db_test(app) -> bool:
    """Initialize the database with basic data for testing, and add results to prometheus endpoint
    
    Args:
        SQLALCHEMY_DATABASE_URI (str): Database URI
        EXTERNAL_DATABASE_ENABLED (bool): Flag indicating if external database is enabled
        DATABASE_TYPE (str): Type of database (e.g., 'postgres', 'mysql')
    
    Returns:
        bool: A flag indicating if the database initialization was successful
    """
    SQLALCHEMY_DATABASE_URI = app.config['SQLALCHEMY_DATABASE_URI']
    database_type = app.config['kubedash.ini'].get('database', 'type', fallback=None)
    if database_type == 'postgres':
        EXTERNAL_DATABASE_ENABLED = True
    else:
        EXTERNAL_DATABASE_ENABLED = False
    
    engine = create_engine(SQLALCHEMY_DATABASE_URI)
    if inspect(engine).has_table("alembic_version"):
        METRIC_DB_CONNECTION.labels(EXTERNAL_DATABASE_ENABLED, database_type).set(1.0)
        return True
    else:
        METRIC_DB_CONNECTION.labels(EXTERNAL_DATABASE_ENABLED, database_type).set(0.0)
        return False
    
def oidc_init(config: configparser.ConfigParser):
    """Store OIDC configuration in database. Test the OIDC connection and add resoults to prometheus endpoint.
    
    Args:
        config (configparser.ConfigParser): Configuration
    """
    # https://github.com/requests/requests-oauthlib/issues/387
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = "1"
    OIDC_ISSUER_URL   = config.get('sso_settings', 'issuer_url', fallback=None)
    OICD_ISSUER_CA    = config.get('sso_settings', 'issuer_ca', fallback=None)
    OIDC_CLIENT_ID    = config.get('sso_settings', 'client_id', fallback=None)
    OIDC_SECRET       = config.get('sso_settings', 'secret', fallback=None)
    OIDC_SCOPE        = config.get('sso_settings', 'scope', fallback=None)
    OIDC_CALLBACK_URL = config.get('sso_settings', 'callback_url', fallback=None)
   
    # Convert and validate scopes
    logger.info("Initializing OIDC Provider")
    try:
        requested_scopes = string2list(OIDC_SCOPE)
        valid_scopes = validate_scopes(requested_scopes, OIDC_ISSUER_URL)
        
        logger.debug(f"\tRequested scopes: {requested_scopes}")
        logger.debug(f"\tValidated scopes: {valid_scopes}")
        
        if set(requested_scopes) != set(valid_scopes):
            logger.warning(
                f"\tScope mismatch. Requested: {requested_scopes}, "
                f"\tUsing validated: {valid_scopes}"
            )
            
    except Exception as e:
        logger.error(f"\tScope validation error: {e}")
        valid_scopes = ['openid']  # Fallback to minimal scope

    # Proceed with OIDC setup
    if all([OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_SECRET, OIDC_CALLBACK_URL]):
        oidc_test, OIDC_ISSUER_URL_OLD = SSOServerTest()
        
        try:
            if oidc_test:
                SSOServerUpdate(
                    OIDC_ISSUER_URL_OLD,
                    OIDC_ISSUER_URL, 
                    OICD_ISSUER_CA, 
                    OIDC_CLIENT_ID, 
                    OIDC_SECRET, 
                    OIDC_CALLBACK_URL, 
                    valid_scopes
                )
                logger.info("\tOIDC Provider updated")
                METRIC_OIDC_CONFIG_UPDATE.labels(
                    OIDC_ISSUER_URL, OIDC_CLIENT_ID
                ).set(1)
            else:
                SSOServerCreate(
                    OIDC_ISSUER_URL,
                    OICD_ISSUER_CA, 
                    OIDC_CLIENT_ID, 
                    OIDC_SECRET, 
                    OIDC_CALLBACK_URL, 
                    valid_scopes
                )
                logger.info("\tOIDC Provider created")
                METRIC_OIDC_CONFIG_UPDATE.labels(
                    OIDC_ISSUER_URL, OIDC_CLIENT_ID
                ).set(0)
                
        except Exception as e:
            logger.error(f"\tOIDC initialization failed: {e}")
            METRIC_OIDC_CONFIG_UPDATE.labels(
                OIDC_ISSUER_URL, OIDC_CLIENT_ID
            ).set(-1)
    else:
        logger.error("\tMissing OIDC configuration parameters")
        METRIC_OIDC_CONFIG_UPDATE.labels(
            OIDC_ISSUER_URL, OIDC_CLIENT_ID
        ).set(-1)    


def k8s_config_int(config: configparser.ConfigParser):
    """Store K8S Api connection configuration in database. Test the K8S API Connection and add resoults to prometheus endpoint.
    
    Args:
        config (configparser.ConfigParser): Configuration
    """
    K8S_CLUSTER_NAME = config.get('k8s', 'cluster_name', fallback="k8s-main")
    K8S_API_SERVER   = config.get('k8s', 'api_server', fallback=None)

    K8S_API_CA       = config.get('k8s', 'api_ca', fallback=None)
    if K8S_API_CA is None:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", 'r') as cert_file:
            cert_file_data = cert_file.read()
            base64_encoded_data = str(base64_encode(cert_file_data), "UTF-8")
            K8S_API_CA = base64_encoded_data

    if K8S_API_SERVER:
        k8sConfig = k8sServerConfigGet()
        if k8sConfig is None:
            k8sServerConfigCreate(K8S_API_SERVER, K8S_CLUSTER_NAME, K8S_API_CA)
            logger.info("Kubernetes Config created")
            METRIC_K8S_CONFIG_UPDATE.labels(K8S_CLUSTER_NAME, K8S_API_SERVER).set(0)
        else:
            k8sServerConfigUpdate(k8sConfig.k8s_context, K8S_API_SERVER, K8S_CLUSTER_NAME, K8S_API_CA)
            logger.info("Kubernetes Config updated")
            METRIC_K8S_CONFIG_UPDATE.labels(K8S_CLUSTER_NAME, K8S_API_SERVER).set(1)
    else:
        logger.error("Missing Kubernetes Config: K8S_API_SERVER, K8S_API_CA")

def k8s_roles_init():
    """
    Create Kubernetes Roles and ClusterRoles in K8S.
    """
    user_role_template_list = k8sUserRoleTemplateListGet("Admin", None)
    user_clusterRole_template_list = k8sUserClusterRoleTemplateListGet("Admin", None)

    if not bool(user_clusterRole_template_list) or not bool(user_role_template_list):
        logger.info("Kubernetes Roles created")
        k8sClusterRolesAdd()