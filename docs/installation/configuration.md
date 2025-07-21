---
hide:
  - toc
---

# Configuration

Create a values file for your helm deploy:

```yaml
# -- Time Zone in container
TimeZone: "CET"
# -- Log level
logLevel: "INFO"
# -- flask environment: production or development
flaskConfig: "production"

serviceAccount:
  # -- Enable automatic serviceAccount creation
  create: true
  # -- Configure the name of the serviceAccount
  name: "kubedash-admin"

image:
  # -- The docker image repository to use
  repository: devopstales/kubedash
  # -- Configure the pull policy
  pullPolicy: Always
  # -- The docker image tag to use
  tag: 3.1.0

# -- pullsecrets
imagePullSecrets: []

# -- replica number - for multiple replicas you need to enable externalDatabase support
replicas: 1

# -- enable external postgresql support
externalDatabase:
  enabled: false
  host: ""
  port: 5432
  database: "kubedash"
  username: "kubedash-user"
  password: "kubedash-pass"
  secret:
    # -- Name of the secret storing EXTERNAL_DATABASE_PASSWORD.
    name: "kubedash-postgresql"
    # -- Secret must provide the following variables: EXTERNAL_DATABASE_PASSWORD.
    useExistingSecret: false

# -- deploy HA postgresql
postgresqlHa:
  enabled: false
  rbac:
    create: true
  persistence:
    enabled: true
#    storageClass: default
  postgresql:
    database: "kubedash"
    username: "kubedash-user"
    password: "kubedash-pass"
    repmgrPassword: "change-me"
    postgresPassword: "change-me"
  pgpool:
    replicaCount: 2
    adminPassword: "change-me"
  metrics:
    enabled: true
    serviceMonitor:
      enabled: false
# https://artifacthub.io/packages/helm/bitnami/postgresql-ha

# -- enable metrics-server
metricsServer:
  enabled: false
  args:
    - --kubelet-preferred-address-types=InternalIP
    - --kubelet-insecure-tls

# -- k8s connection information.
cluster:
  # -- k8s api url
  name: "k8s-cluster"
  # -- k8s api url
  apiUrl: "https://kubernetes.mydomain.intra:6443"
  # `apiServer` is the url for kubectl
  #   This is typically  https://api.fqdn
  # -- k8s ca cert
  caCert: |-
    -----BEGIN CERTIFICATE-----
    cert data here
    -----END CERTIFICATE-----
  # `caCrt` is the public / CA cert for the cluster
  # cat /etc/kubernetes/pki/ca.crt

# -- oidc connection information
oidc:
  # -- Enable oidc authentication
  enabled: false
  provider:
    # -- oidc issuer url
    oidcUrl: "https://sso.mydomain.intra/auth/realms/k8s"
    # -- oidc scope
    oidcScopes: "openid email"
    # -- oidc client id
    oidcClientId: ""
    # -- oidc client secret
    oidcSecret: ""
  secret:
    # -- Name of the secret storing OIDC_CLIENT_ID and OIDC_SECRET.
    name: "kubedash-oidc"
    # -- Secret must provide the following variables: OIDC_CLIENT_ID and OIDC_SECRET.
    useExistingSecret: false

# -- enable plugins
plugins:
  registryUi:
    # -- Enable registry UI plugin with set PLUGIN_REGISTRY_ENABLED
    enabled: false
  helmDashboard:
    # -- Enable helm dashboard plugin with set PLUGIN_HELM_ENABLED
    enabled: true

persistence:
  # -- Volumes for the pod
  enabled: true
  # -- Volumes mode
  accessMode: "ReadWriteOnce"
  # -- Volumes size
  size: "1Gi"
  # -- Volumes annotations
  annotations: {}
  ## database data Persistent Volume Storage Class
  ## If defined, storageClassName: <storageClass>
  ## If set to "-", storageClassName: "", which disables dynamic provisioning
  ## If undefined (the default) or set to null, no storageClassName spec is
  ##   set, choosing the default provisioner.  (gp2 on AWS, standard on
  ##   GKE, AWS & OpenStack)
  ##
  # storageClass: "-"

ingress:
  # -- Enable Ingress object creation
  enabled: true
  # -- Ingress class name
  className: "nginx"
  # -- URL of the Ingress object
  url: "kubedash.mydomain.intra"
  # -- Extra annotation to the Ingress object
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/server-snippets: |
      location / {
        proxy_set_header Upgrade $http_upgrade;
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $host;
        proxy_set_header Connection "upgrade";
        proxy_cache_bypass $http_upgrade;
      }
  tls:
    # -- Enable tls on Ingress object
    enabled: true
    # -- Name of the secret storing tls cert
    tlsSecret: ""
    certManager:
       # -- Enable certManager
      enabled: false
      # -- Name of the certManager cluster issuer to use
      clusterIssuer: "letsencrypt"
  whitelist:
    # -- Enable ip blocking on ingress
    enabled: false
    # -- List of ips to allow communication
    ips: []

route:
  # -- Enable OpenShift Route object creation
  enabled: false
  # -- URL of the OpenShift Route object
  url: "kubedash.mydomain.intra"
  # -- Extra annotation to the OpenShift Route object
  annotations: {}

# -- list of the pos's SecurityContexts
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 10001
  fsGroup: 10001
  fsGroupChangePolicy: "OnRootMismatch"

# -- list of the container's SecurityContexts
containerSecurityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["all"]

## Define which Nodes the Pods are scheduled on.
## ref: https://kubernetes.io/docs/user-guide/node-selection/
# -- Set nodeSelector for the pod
nodeSelector: {}

## Tolerations for use with node taints
## ref: https://kubernetes.io/docs/concepts/configuration/taint-and-toleration/
# -- Set tolerations for the pod
tolerations: []
# - key: "key"
#   operator: "Equal"
#   value: "value"
#   effect: "NoSchedule"

## Assign custom affinity rules to the trivy operator
## ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
##

## Assign custom affinity rules to the deployment
## ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
# -- Set the affinity for the pod.
affinity: {}
# nodeAffinity:
#   requiredDuringSchedulingIgnoredDuringExecution:
#     nodeSelectorTerms:
#     - matchExpressions:
#       - key: kubernetes.io/e2e-az-name
#         operator: In
#         values:
#         - e2e-az1
#         - e2e-az2
```

## Operator Configuration

The following tables lists configurable parameters of the trivy-operator chart and their default values.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| TimeZone | string | `"CET"` | Time Zone in container |
| affinity | object | `{}` | Set the affinity for the pod. |
| cluster | object | `{"apiUrl":"https://kubernetes.mydomain.intra:6443","name":"k8s-cluster"}` | k8s connection information. |
| cluster.apiUrl | string | `"https://kubernetes.mydomain.intra:6443"` | k8s api url |
| cluster.name | string | `"k8s-cluster"` | k8s api url |
| containerSecurityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["all"]}}` | list of the container's SecurityContexts |
| createClusterRole | bool | `true` | Enable ClusterRole creation. Disable if the role already exists. |
| dbui | object | `{"image":{"plugins":"tables-filter,adminer-auto-login","pullPolicy":"IfNotPresent","repository":"sosedoff/pgweb","tag":"latest"}}` | deploy ui for db |
| dbui.image.plugins | string | `"tables-filter,adminer-auto-login"` | adminer plugins |
| dbui.image.pullPolicy | string | `"IfNotPresent"` | adminer image pull policy |
| dbui.image.repository | string | `"sosedoff/pgweb"` | adminer image |
| dbui.image.tag | string | `"latest"` | adminer image tag |
| externalDatabase | object | `{"database":"kubedash","enabled":false,"host":"","password":"kubedash","port":5432,"secret":{"name":"kubedash-postgresql","useExistingSecret":false},"username":"kubedash"}` | enable external postgresql support |
| externalDatabase.database | string | `"kubedash"` | External postgresql database |
| externalDatabase.enabled | bool | `false` | Enable external postgresql |
| externalDatabase.host | string | `""` | External postgresql host |
| externalDatabase.password | string | `"kubedash"` | External postgresql password |
| externalDatabase.port | int | `5432` | External postgresql port |
| externalDatabase.secret.name | string | `"kubedash-postgresql"` | Name of the secret storing EXTERNAL_DATABASE_PASSWORD. |
| externalDatabase.secret.useExistingSecret | bool | `false` | Secret must provide the following variables: EXTERNAL_DATABASE_PASSWORD. |
| externalDatabase.username | string | `"kubedash"` | External postgresql username |
| flaskConfig | string | `"production"` | flask environment: production or development |
| image.pullPolicy | string | `"Always"` | The docker image pull policy |
| image.repository | string | `"devopstales/kubedash"` | The docker image repository to use |
| image.statsdExporter.repository | string | `"prom/statsd-exporter"` | The docker image repository to use |
| image.statsdExporter.tag | string | `"v0.22.4"` | The docker image tag to use |
| image.tag | string | `"3.1.0"` | The docker image tag to use |
| imagePullSecrets | list | `[]` | pullsecrets |
| ingress.annotations | object | `{"nginx.ingress.kubernetes.io/proxy-body-size":"10m","nginx.ingress.kubernetes.io/proxy-read-timeout":"3600","nginx.ingress.kubernetes.io/proxy-send-timeout":"3600","nginx.ingress.kubernetes.io/server-snippets":"location / {\n  proxy_set_header Upgrade $http_upgrade;\n  proxy_http_version 1.1;\n  proxy_set_header X-Forwarded-Host $http_host;\n  proxy_set_header X-Forwarded-Proto $scheme;\n  proxy_set_header X-Forwarded-For $remote_addr;\n  proxy_set_header Host $host;\n  proxy_set_header Connection \"upgrade\";\n  proxy_cache_bypass $http_upgrade;\n}\n"}` | Extra annotation to the Ingress object |
| ingress.className | string | `"nginx"` | Ingress class name |
| ingress.enabled | bool | `true` | Enable Ingress object creation |
| ingress.tls.certManager.clusterIssuer | string | `"letsencrypt"` | Name of the certManager cluster issuer to use |
| ingress.tls.certManager.enabled | bool | `false` | Enable certManager |
| ingress.tls.enabled | bool | `true` | Enable tls on Ingress object |
| ingress.tls.tlsSecret | string | `""` | Name of the secret storing tls cert |
| ingress.url | string | `"kubedash.mydomain.intra"` | URL of the Ingress object |
| ingress.whitelist.enabled | bool | `false` | Enable ip blocking on ingress |
| ingress.whitelist.ips | list | `[]` | List of ips to allow communication |
| logLevel | string | `"INFO"` | Log level |
| metrics.enabled | bool | `true` | Enable metrics |
| metrics.grafana.annotations.grafana_folder | string | `"KubeDash"` |  |
| metrics.grafana.enabled | bool | `true` | Enable grafana dashboard deploy |
| metrics.grafana.labels.grafana_dashboard | string | `"1"` |  |
| metrics.grafana.namespace | string | `"monitoring-system"` | Grafana dashboard namespace |
| metrics.serviceMonitor.annotations | object | `{}` | Prometheus service monitor annotations |
| metrics.serviceMonitor.enabled | bool | `false` | Enable prometheus service monitor |
| metrics.serviceMonitor.honorLabels | object | `{}` |  |
| metrics.serviceMonitor.interval | string | `"30s"` | Prometheus service monitor interval |
| metrics.serviceMonitor.jobLabel | object | `{}` | Prometheus service monitor job labels |
| metrics.serviceMonitor.labels | object | `{"release":"kube-prometheus-stack"}` | Prometheus service monitor labels |
| metrics.serviceMonitor.metricRelabelings | list | `[]` |  |
| metrics.serviceMonitor.relabelings | list | `[]` |  |
| metrics.serviceMonitor.scrapeTimeout | string | `"10s"` | Prometheus service monitor scrape timeout |
| metricsServer | object | `{"args":["--kubelet-preferred-address-types=InternalIP","--kubelet-insecure-tls"],"enabled":false}` | enable metrics-server |
| nodeSelector | object | `{}` | Set nodeSelector for the pod |
| oidc | object | `{"enabled":false,"provider":{"oidcClientId":"","oidcScopes":"openid email","oidcSecret":"","oidcUrl":"https://sso.mydomain.intra/auth/realms/k8s"},"secret":{"name":"kubedash-oidc","useExistingSecret":false}}` | oidc connection information |
| oidc.enabled | bool | `false` | Enable oidc authentication |
| oidc.provider.oidcClientId | string | `""` | oidc client id |
| oidc.provider.oidcScopes | string | `"openid email"` | oidc scope |
| oidc.provider.oidcSecret | string | `""` | oidc client secret |
| oidc.provider.oidcUrl | string | `"https://sso.mydomain.intra/auth/realms/k8s"` | oidc issuer url |
| oidc.secret.name | string | `"kubedash-oidc"` | Name of the secret storing OIDC_CLIENT_ID and OIDC_SECRET. |
| oidc.secret.useExistingSecret | bool | `false` | Secret must provide the following variables: OIDC_CLIENT_ID and OIDC_SECRET. |
| persistence | object | `{"accessMode":"ReadWriteOnce","annotations":{},"enabled":true,"size":"1Gi","storageClass":"-"}` | enable persistence |
| persistence.accessMode | string | `"ReadWriteOnce"` | Volumes mode |
| persistence.annotations | object | `{}` | Volumes annotations |
| persistence.enabled | bool | `true` | Volumes for the pod |
| persistence.size | string | `"1Gi"` | Volumes size |
| plugins | object | `{"certManager":{"enabled":true},"externalLoadbalancer":{"enabled":true},"flux":{"enabled":true},"helmDashboard":{"enabled":true},"registryUi":{"enabled":true}}` | enable plugins |
| plugins.certManager.enabled | bool | `true` | Enable helm dashboard plugin |
| plugins.externalLoadbalancer.enabled | bool | `true` | Enable external loadbalancer plugin |
| plugins.flux.enabled | bool | `true` | Enable flux plugin |
| plugins.helmDashboard.enabled | bool | `true` | Enable helm dashboard plugin |
| plugins.registryUi.enabled | bool | `true` | Enable registry UI plugin |
| podSecurityContext | object | `{"fsGroup":10001,"fsGroupChangePolicy":"OnRootMismatch","runAsNonRoot":true,"runAsUser":10001}` | list of the pos's SecurityContexts |
| postgresql | object | `{"auth":{"database":"kubedash","password":"kubedash","postgresPassword":"change-me","replicationPassword":"change-me","username":"kubedash"},"enabled":true,"metrics":{"enabled":true,"serviceMonitor":{"enabled":false,"honorLabels":{},"jobLabel":{},"labels":{"release":"kube-prometheus-stack"}}},"primary":{"persistence":{"size":"10Gi"}},"rbac":{"create":true},"readReplicas":{"replicaCount":0},"securityContext":{"enabled":false},"shmVolume":{"chmod":{"enabled":false}},"volumePermissions":{"enabled":false,"securityContext":{"runAsUser":"auto"}}}` | deploy postgresql |
| postgresql.auth.database | string | `"kubedash"` | Postgresql database |
| postgresql.auth.password | string | `"kubedash"` | Postgresql password |
| postgresql.auth.postgresPassword | string | `"change-me"` | Postgresql postgres user password |
| postgresql.auth.replicationPassword | string | `"change-me"` | Postgresql replication password |
| postgresql.auth.username | string | `"kubedash"` | Postgresql username |
| postgresql.enabled | bool | `true` | Enable postgresql |
| postgresql.metrics.enabled | bool | `true` | Enable postgresql metrics |
| postgresql.metrics.serviceMonitor.enabled | bool | `false` | Enable prometheus service monitor |
| postgresql.metrics.serviceMonitor.jobLabel | object | `{}` | Set serviceMonitor labels |
| postgresql.metrics.serviceMonitor.labels | object | `{"release":"kube-prometheus-stack"}` | Prometheus service monitor labels |
| postgresql.readReplicas.replicaCount | int | `0` | Number of read replicas to create |
| postgresql.securityContext.enabled | bool | `false` | Enable postgresql security context |
| postgresql.shmVolume.chmod | object | `{"enabled":false}` | Enable postgresql shared memory volume |
| postgresql.volumePermissions.enabled | bool | `false` | Enable init container to set permissions on data volume |
| redis | object | `{"architecture":"standalone","enabled":true,"metrics":{"enabled":true,"serviceMonitor":{"additionalLabels":{"release":"kube-prometheus-stack"},"enabled":false}}}` | enable redis for caching |
| redis.architecture | string | `"standalone"` | Redis cluster architecture |
| redis.enabled | bool | `true` | Enable redis |
| redis.metrics.enabled | bool | `true` | Enable redis metrics |
| redis.metrics.serviceMonitor.additionalLabels | object | `{"release":"kube-prometheus-stack"}` | Prometheus service monitor namespace namespace: "monitoring" |
| redis.metrics.serviceMonitor.enabled | bool | `false` | Enable prometheus service monitor |
| redisui | object | `{"image":{"pullPolicy":"Always","repository":"patrikx3/p3x-redis-ui","tag":"latest"},"resources":{}}` | redis ui |
| replicas | int | `1` | replica number - for multiple replicas you need to enable externalDatabase support |
| route.annotations | object | `{}` | Extra annotation to the OpenShift Route object |
| route.enabled | bool | `false` | Enable OpenShift Route object creation |
| route.url | string | `"kubedash.mydomain.intra"` | URL of the OpenShift Route object |
| serviceAccount.create | bool | `true` | Enable automatic serviceAccount creation |
| serviceAccount.name | string | `"kubedash-admin"` | Configure the name of the serviceAccount |
| tolerations | list | `[]` | Set tolerations for the pod |
