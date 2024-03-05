### KubeDash

![Version: 3.0.0](https://img.shields.io/badge/Version-3.0.0-informational?style=for-the-badge)
![Type: application](https://img.shields.io/badge/Type-application-informational?style=for-the-badge)
![AppVersion: 2.0.0](https://img.shields.io/badge/AppVersion-2.0.0-informational?style=for-the-badge)

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