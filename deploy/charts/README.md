### KubeDash

![Version: 4.0.0](https://img.shields.io/badge/Version-4.0.0-informational?style=for-the-badge)
![Type: application](https://img.shields.io/badge/Type-application-informational?style=for-the-badge)
![AppVersion: 4.0.0](https://img.shields.io/badge/AppVersion-4.0.0-informational?style=for-the-badge)

![Alpine Linux 3.15.0](https://img.shields.io/badge/alpine_linux_3.15.0-0D597F?style=for-the-badge&logo=alpine-linux&logoColor=white)
![Helm](https://img.shields.io/badge/helm-0F1689?style=for-the-badge&logo=helm&logoColor=white)

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/minecraft-exporter&style=for-the-badge)](https://artifacthub.io/packages/helm/devopstales/kubedash)

## Description

KubeDash is a general purpose, web-based UI for Kubernetes clusters.

## Configuration

The following tables lists configurable parameters of the KubeDash chart and their default values.

<fill out>

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

**Homepage:** <https://github.com/devopstales/kubedash>

## Source Code

* <https://github.com/devopstales/kubedash>
* <https://github.com/devopstales/helm-charts>

## Documentation of Helm Chart

Generate docs with `helm-docs` command.

```
cd deploy/helm
helm-docs
```

The markdown generation is entirely go template driven. The tool parses metadata from charts and generates a number of sub-templates that can be referenced in a template file (by default `README.md.gotmpl`). If no template file is provided, the tool has a default internal template that will generate a reasonably formatted README.