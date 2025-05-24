
from flask_login import UserMixin
from itsdangerous import base64_decode
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client.rest import ApiException
from opentelemetry.trace.status import Status, StatusCode

from lib.components import db
from lib.helper_functions import NoFlashErrorHandler

from . import logger, tracer

##############################################################
## Kubernetes Cluster Config
##############################################################

class k8sConfig(UserMixin, db.Model):
    __tablename__ = 'k8s_cluster_config'
    id = db.Column(db.Integer, primary_key=True)
    k8s_server_url = db.Column(db.Text, unique=True, nullable=False)
    k8s_context = db.Column(db.Text, unique=True, nullable=False)
    k8s_server_ca = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Kubernetes Server URL %r>' % self.k8s_server_url

def k8sServerConfigGet():
    """Get Aktual Kubernetes Server Config from DB
    
    Returns:
        k8s_config (k8sConfig): Aktual Kubernetes Server Config
    """
    with tracer.start_as_current_span("list-cluster-configs") as span:
        k8s_config_list = k8sConfig.query
        if tracer and span.is_recording():
            span.set_attribute("k8s.cluster", k8s_config_list.k8s_context)
        return k8s_config_list[0]

def k8sServerConfigList():
    """List Kubernetes Server configuration from db
    
    Returns:
        k8s_config_list (list): List of Kubernetes Server Configs
        k8s_config_list_length (int): Length of Kubernetes Server Configs
    """
    k8s_config_list = k8sConfig.query
    k8s_config_list_length = k8sConfig.query.count()
    return k8s_config_list, k8s_config_list_length

def k8sServerConfigCreate(k8s_server_url, k8s_context, k8s_server_ca):
    """Add Kubernetes Server configuration to db
    
    Args:
        k8s_server_url (string): Kubernetes Server URL
        k8s_context (string): Kubernetes Context
        k8s_server_ca (string): Kubernetes Server CA
    """
    k8s = k8sConfig.query.filter_by(k8s_server_url=k8s_server_url).first()
    k8s_data = k8sConfig(
        k8s_server_url = k8s_server_url,
        k8s_context = k8s_context,
        k8s_server_ca = k8s_server_ca
    )
    if k8s is None:
        db.session.add(k8s_data)
        db.session.commit()

def k8sServerConfigDelete(k8s_context):
    """Delete Kubernetes Server configuration from db
    
    Args:
        k8s_context (string): Kubernetes Context"""
    k8s = k8sConfig.query.filter_by(k8s_context=k8s_context).first()
    if k8s:
        db.session.delete(k8s)
        db.session.commit()

def k8sServerConfigUpdate(k8s_context_old, k8s_server_url, k8s_context, k8s_server_ca):
    """Update Kubernetes Server configuration in db
    
    Args:
        k8s_context_old (string): Old Kubernetes Context
        k8s_context (string): New Kubernetes Context
        k8s_server_url (string): URL os the k8s server
        k8s_server_ca (string): Root CA of the k8s server
    """
    k8s = k8sConfig.query.filter_by(k8s_context=k8s_context_old).first()
    if k8s:
        k8s.k8s_server_url = k8s_server_url
        k8s.k8s_context = k8s_context
        k8s.k8s_server_ca = k8s_server_ca
        db.session.commit()
        
def k8sGetClusterStatus(username_role="Admin", user_token=None):
    """Gets the status of the Kubernetes cluster.

    Args:
        username_role (str, optional): The role of the user. Defaults to "Admin".
        user_token (optional): The user's token. Defaults to None.

    Returns:
        status (bool): Kubernetes connection status
    """
    k8sClientConfigGet(username_role, user_token)
    try:
        api = k8s_client.CoreV1Api()
        component_statuses = api.list_component_status(_request_timeout=1, timeout_seconds=1)

        return True

    except ApiException as e:
        NoFlashErrorHandler(logger, e, f"Error getting cluster status: {e}")
        return False
    except Exception as e:
        NoFlashErrorHandler(logger, e, f"Unexpected error getting cluster status: {e}")
        return False



def k8sServerContextsList():
    """List K8S server contexts from database
    
    Return:
        k8s_contexts (list[dict]): List of k8s contexts objects
    """
    k8s_contexts = []
    k8s_config_list = k8sConfig.query.all()
    for config in k8s_config_list:
        k8s_contexts.append(config.k8s_context)
    return k8s_contexts


##############################################################
## Kubernetes Client Config
##############################################################

def k8sClientConfigGet(username_role, user_token):
    """Get a Kubernetes client configuration
    
    Args:
        username_role (string): The role to get the client configuration
        user_token (string): The user_token to get the client configuration
    """
    import urllib3
    urllib3.disable_warnings()
    with tracer.start_as_current_span("load-client-configs") as span:
        if tracer and span.is_recording():
            span.set_attribute("user.role", username_role)
        if username_role == "Admin":
            try:
                k8s_config.load_kube_config()
                if tracer and span.is_recording():
                    span.set_attribute("client.config", "local")
            except Exception as error:
                try:
                    k8s_config.load_incluster_config()
                    if tracer and span.is_recording():
                        span.set_attribute("client.config", "incluster")
                except k8s_config.ConfigException as error:
                    NoFlashErrorHandler(logger, error, "Could not configure kubernetes python client")
                    if tracer and span.is_recording():
                        span.set_status(Status(StatusCode.ERROR, "Could not configure kubernetes python client: %s" % error))
        elif username_role == "User":
            if not user_token:
                NoFlashErrorHandler(logger, error, "Missing user token")
            k8sConfig = k8sServerConfigGet()
            if k8sConfig is None:
                logger.error("Kubectl Integration is not configured.")
            else:
                k8s_server_url = k8sConfig.k8s_server_url
                k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
                configuration = k8s_client.Configuration()
                if k8s_server_ca:
                    file = open("CA.crt", "w+")
                    file.write( k8s_server_ca )
                    file.close
                    configuration.ssl_ca_cert = 'CA.crt'
                else:
                    configuration.ssl_ca_cert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
                
                configuration.host = k8s_server_url
                configuration.verify_ssl = True
                configuration.debug = False
                configuration.api_key_prefix['authorization'] = 'Bearer'
                configuration.api_key["authorization"] = str(user_token["id_token"])
                if tracer and span.is_recording():
                    span.set_attribute("client.config", "oidc")
                k8s_client.Configuration.set_default(configuration)
