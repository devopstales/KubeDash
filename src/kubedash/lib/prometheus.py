from prometheus_client import Gauge, Info

##############################################################
## Promatehus Endpoint
##############################################################

METRIC_APP_VERSION = Info(
    'app_version',
    'Application Version')

METRIC_DB_CONNECTION = Gauge(
    'app_databse_connection',
    'Database Info',
    ['external', 'type']
)

METRIC_OIDC_CONFIG_UPDATE = Gauge(
    'oidc_config_update',
    "OIDC Config Update",
    ['issuer', 'client_id'],
)

METRIC_K8S_CONFIG_UPDATE = Gauge(
    'k8s_config_update',
    "K8S Config Update",
    ['cluster_name', 'api'],
)
