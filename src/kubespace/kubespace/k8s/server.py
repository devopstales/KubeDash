import urllib3, os
from itsdangerous import base64_decode

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.config import ConfigException

from kubespace.lib.helper_functions import get_logger

logger = get_logger()

###############################################################################x
#
###############################################################################
def k8sClientConfigGet(username_role, user_token=None):
    """Get a Kubernetes client configuration
    
    Args:
        username_role (str): "Admin" or "User"
        user_token (dict or str, optional): User token for impersonation
    """
    urllib3.disable_warnings()

    if username_role == "Admin":
        try:
            # Prefer local kubeconfig (dev)
            k8s_config.load_kube_config()
            logger.debug("Loaded local kube config for Admin")
        except Exception:
            try:
                # Fallback: in-cluster (prod)
                k8s_config.load_incluster_config()
                logger.debug("Loaded in-cluster config for Admin")
            except ConfigException:
                logger.error("Could not configure kubernetes python client")

    elif username_role == "User":
        if not user_token:
            logger.error("Missing user token")
            return

        logger.debug("Loading kube config for User")

        configuration = k8s_client.Configuration()

        try:
            # Try local kubeconfig first
            k8s_config.load_kube_config()
            base_config = k8s_client.Configuration.get_default_copy()
            configuration.host = base_config.host
            configuration.ssl_ca_cert = base_config.ssl_ca_cert
            logger.debug("Using local kube config for User")
        except Exception:
            # Fallback: in-cluster env vars
            host = os.getenv("KUBERNETES_SERVICE_HOST")
            port = os.getenv("KUBERNETES_SERVICE_PORT")
            if not host or not port:
                raise RuntimeError("Cannot determine Kubernetes server URL")
            configuration.host = f"https://{host}:{port}"
            configuration.ssl_ca_cert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
            logger.debug("Using in-cluster kube config for User")

        configuration.verify_ssl = True
        configuration.debug = False

        # Normalize token
        if isinstance(user_token, dict):
            token_value = user_token.get("access_token") or user_token.get("id_token")
        else:
            token_value = str(user_token)

        if not token_value:
            raise RuntimeError("User token is missing or invalid")

        configuration.api_key_prefix['authorization'] = 'Bearer'
        configuration.api_key['authorization'] = token_value

        # Apply
        k8s_client.Configuration.set_default(configuration)