
import configparser, os
from sqlalchemy import create_engine, inspect
from itsdangerous import base64_encode

from .helper_functions import string2list, get_logger
from .user import UserCreate, RoleCreate, UserTest
from .sso import SSOServerTest, SSOServerCreate, SSOServerUpdate
from .k8s import k8sServerConfigGet, k8sServerConfigCreate, k8sServerConfigUpdate, \
k8sUserRoleTemplateListGet, k8sUserClusterRoleTemplateListGet, k8sClusterRolesAdd
from .prometheus import METRIC_DB_CONNECTION, METRIC_K8S_CONFIG_UPDATE, METRIC_OIDC_CONFIG_UPDATE

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

def db_init_roles(config: configparser.ConfigParser):
    """Create Roles and Users in the database
    
    Args:
        config (configparser.ConfigParser): Configuration"""
    for r in roles:
        RoleCreate(r)
    admin_password = config.get('security', 'admin_password', fallback="admin")
    UserCreate("admin", admin_password, None, "Local", "Admin")

def connect_database() -> bool:
    """Test Databse Connection
    
    Returns:
        bool: A flag indicating if the database connection was successful
    """
    user = UserTest('Admin')
    if user:
        return True
    else:
        return False

def init_db_test(SQLALCHEMY_DATABASE_URI, EXTERNAL_DATABASE_ENABLED, DATABASE_TYPE) -> bool:
    """Initialize the database for testing and add results to prometheus endpoint
    
    Args:
        SQLALCHEMY_DATABASE_URI (str): Database URI
        EXTERNAL_DATABASE_ENABLED (bool): Flag indicating if external database is enabled
        DATABASE_TYPE (str): Type of database (e.g., 'postgres', 'mysql')
    
    Returns:
        bool: A flag indicating if the database initialization was successful
    """
    engine = create_engine(SQLALCHEMY_DATABASE_URI)
    if inspect(engine).has_table("alembic_version"):
        METRIC_DB_CONNECTION.labels(EXTERNAL_DATABASE_ENABLED, DATABASE_TYPE).set(1.0)
        return True
    else:
        METRIC_DB_CONNECTION.labels(EXTERNAL_DATABASE_ENABLED, DATABASE_TYPE).set(0.0)
        return False
    
def oidc_init(config: configparser.ConfigParser):
    """Store OIDC configuration in database. Test the OIDC connection and add resoults to prometheus endpoint.
    
    Args:
        config (configparser.ConfigParser): Configuration
    """
    # https://github.com/requests/requests-oauthlib/issues/387
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = "1"
    OIDC_ISSUER_URL   = config.get('sso_settings', 'issuer_url', fallback=None)
    OIDC_CLIENT_ID    = config.get('sso_settings', 'client_id', fallback=None)
    OIDC_SECRET       = config.get('sso_settings', 'secret', fallback=None)
    OIDC_SCOPE        = config.get('sso_settings', 'scope', fallback=None)
    OIDC_CALLBACK_URL = config.get('sso_settings', 'callback_url', fallback=None)

    if OIDC_ISSUER_URL and OIDC_CLIENT_ID and OIDC_SECRET and OIDC_SCOPE and OIDC_CALLBACK_URL:
        oidc_test, OIDC_ISSUER_URL_OLD = SSOServerTest()
        if oidc_test:
            SSOServerUpdate(OIDC_ISSUER_URL_OLD, OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_SECRET, OIDC_CALLBACK_URL, string2list(OIDC_SCOPE))
            logger.info("OIDC Provider updated")
            METRIC_OIDC_CONFIG_UPDATE.labels(OIDC_ISSUER_URL, OIDC_CLIENT_ID).set(1)
        else:
            SSOServerCreate(OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_SECRET, OIDC_CALLBACK_URL, string2list(OIDC_SCOPE))
            logger.info("OIDC Provider created")
            METRIC_OIDC_CONFIG_UPDATE.labels(OIDC_ISSUER_URL, OIDC_CLIENT_ID).set(0)

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
    """Create Kubernetes Roles and ClusterRoles in K8S.
    """
    user_role_template_list = k8sUserRoleTemplateListGet("Admin", None)
    user_clusterRole_template_list = k8sUserClusterRoleTemplateListGet("Admin", None)

    if not bool(user_clusterRole_template_list) or not bool(user_role_template_list):
        logger.info("Kubernetes Roles created")
        k8sClusterRolesAdd()