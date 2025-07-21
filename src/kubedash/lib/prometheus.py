from prometheus_client import Gauge, Info, Counter, Histogram

##############################################################
## Promatehus Endpoint
##############################################################

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

REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP request latency in seconds',
    ['endpoint']
)
