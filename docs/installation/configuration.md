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
  # -- The docker image pull policy
  pullPolicy: Always
  # -- The docker image tag to use
  tag: 2.0.0

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

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| TimeZone | string | `"CET"` | Time Zone in container |
| affinity | object | `{}` | Set the affinity for the pod. |
| cluster | object | `{"apiUrl":"https://kubernetes.mydomain.intra:6443","caCert":"-----BEGIN CERTIFICATE-----\ncert data here\n-----END CERTIFICATE-----","name":"k8s-cluster"}` | k8s connection information. |
| cluster.apiUrl | string | `"https://kubernetes.mydomain.intra:6443"` | k8s api url |
| cluster.caCert | string | `"-----BEGIN CERTIFICATE-----\ncert data here\n-----END CERTIFICATE-----"` | k8s ca cert |
| cluster.name | string | `"k8s-cluster"` | k8s api url |
| containerSecurityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["all"]}}` | list of the container's SecurityContexts |
| externalDatabase | object | `{"database":"kubedash","enabled":false,"host":"","password":"kubedash-pass","port":5432,"secret":{"name":"kubedash-postgresql","useExistingSecret":false},"username":"kubedash-user"}` | enable external postgresql support |
| externalDatabase.secret.name | string | `"kubedash-postgresql"` | Name of the secret storing EXTERNAL_DATABASE_PASSWORD. |
| externalDatabase.secret.useExistingSecret | bool | `false` | Secret must provide the following variables: EXTERNAL_DATABASE_PASSWORD. |
| flaskConfig | string | `"production"` | flask environment: production or development |
| image.pullPolicy | string | `"Always"` | The docker image pull policy |
| image.repository | string | `"devopstales/kubedash"` | The docker image repository to use |
| image.tag | string | `"2.0.0"` | The docker image tag to use |
| imagePullSecrets | list | `[]` | pullsecrets |
| ingress.annotations | object | `{"nginx.ingress.kubernetes.io/proxy-body-size":"10m"}` | Extra annotation to the Ingress object |
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
| persistence.accessMode | string | `"ReadWriteOnce"` | Volumes mode |
| persistence.annotations | object | `{}` | Volumes annotations |
| persistence.enabled | bool | `true` | Volumes for the pod |
| persistence.size | string | `"1Gi"` | Volumes size |
| plugins | object | `{"helmDashboard":{"enabled":true},"registryUi":{"enabled":false}}` | enable plugins |
| plugins.helmDashboard.enabled | bool | `true` | Enable helm dashboard plugin with set PLUGIN_HELM_ENABLED |
| plugins.registryUi.enabled | bool | `false` | Enable registry UI plugin with set PLUGIN_REGISTRY_ENABLED |
| podSecurityContext | object | `{"fsGroup":10001,"fsGroupChangePolicy":"OnRootMismatch","runAsNonRoot":true,"runAsUser":10001}` | list of the pos's SecurityContexts |
| postgresqlHa | object | `{"enabled":false,"metrics":{"enabled":true,"serviceMonitor":{"enabled":false}},"persistence":{"enabled":true},"pgpool":{"adminPassword":"change-me","replicaCount":2},"postgresql":{"database":"kubedash","password":"kubedash-pass","postgresPassword":"change-me","repmgrPassword":"change-me","username":"kubedash-user"},"rbac":{"create":true}}` | deploy HA postgresql |
| replicas | int | `1` | replica number - for multiple replicas you need to enable externalDatabase support |
| route.annotations | object | `{}` | Extra annotation to the OpenShift Route object |
| route.enabled | bool | `false` | Enable OpenShift Route object creation |
| route.url | string | `"kubedash.mydomain.intra"` | URL of the OpenShift Route object |
| serviceAccount.create | bool | `true` | Enable automatic serviceAccount creation |
| serviceAccount.name | string | `"kubedash-admin"` | Configure the name of the serviceAccount |
| tolerations | list | `[]` | Set tolerations for the pod |
