from prometheus_client import Gauge, Info, Counter, Histogram

##############################################################
## Prometheus Metrics
##############################################################

# Database and configuration metrics
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

# HTTP metrics
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

##############################################################
## Leader Election Metrics (Section 6)
##############################################################

METRIC_LEADER_IS_LEADER = Gauge(
    'kubedash_leader_election_is_leader',
    'Whether this instance is the current leader',
    ['pod_name']
)

METRIC_LEADER_TRANSITIONS = Counter(
    'kubedash_leader_election_transitions_total',
    'Total number of leader election transitions',
    ['pod_name']
)

METRIC_LEADER_RENEWALS = Counter(
    'kubedash_leader_election_renewals_total',
    'Total number of successful lease renewals',
    ['pod_name']
)

##############################################################
## Session Metrics (Section 6)
##############################################################

METRIC_SESSION_OPERATIONS = Counter(
    'kubedash_session_operations_total',
    'Total number of session operations',
    ['operation']
)

METRIC_SESSION_REDIS_ERRORS = Counter(
    'kubedash_session_redis_errors_total',
    'Total number of Redis errors during session operations',
    ['operation']
)

##############################################################
## Leader Task Metrics (Section 6)
##############################################################

METRIC_LEADER_TASKS_EXECUTED = Counter(
    'kubedash_leader_tasks_executed_total',
    'Total number of leader-only tasks executed',
    ['task_name']
)

METRIC_LEADER_TASK_DURATION = Histogram(
    'kubedash_leader_task_duration_seconds',
    'Duration of leader-only task execution in seconds',
    ['task_name']
)

METRIC_LEADER_TASKS_SKIPPED = Counter(
    'kubedash_leader_tasks_skipped_total',
    'Total number of leader-only tasks skipped (follower replicas)',
    ['task_name']
)

##############################################################
## Replica Mode Metrics (Section 6)
##############################################################

METRIC_REPLICA_MODE_INFO = Gauge(
    'kubedash_replica_mode_info',
    'Replica mode information (1=single, 2=cluster)',
    ['mode']
)

METRIC_REPLICA_DESIRED = Gauge(
    'kubedash_replica_desired',
    'Desired number of replicas'
)

##############################################################
## Config Mode Metric (minimal-config-startup)
##############################################################

METRIC_CONFIG_MODE = Gauge(
    'kubedash_config_mode',
    'Configuration mode (1=full, 2=minimal)',
    ['mode']
)
