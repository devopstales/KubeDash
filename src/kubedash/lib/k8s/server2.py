
import kubernetes.config as k8s_config
import kubernetes.client as k8s_client

from itsdangerous import base64_decode
from opentelemetry.trace.status import Status, StatusCode


from lib.helper_functions import ErrorHandler

from . import tracer, logger
from .server import k8sServerConfigGet

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
                    ErrorHandler(logger, error, "Could not configure kubernetes python client")
                    if tracer and span.is_recording():
                        span.set_status(Status(StatusCode.ERROR, "Could not configure kubernetes python client: %s" % error))
        elif username_role == "User":
            if not user_token:
                ErrorHandler(logger, error, "Missing user token")
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
