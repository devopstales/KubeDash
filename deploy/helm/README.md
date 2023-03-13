### KubeDash

![Version: 1.0.0](https://img.shields.io/badge/Version-1.0.0-informational?style=for-the-badge)
![Type: application](https://img.shields.io/badge/Type-application-informational?style=for-the-badge)
![AppVersion: 1.0.0](https://img.shields.io/badge/AppVersion-1.0.0-informational?style=for-the-badge)

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
| TimeZone | string | `"CET"` |  |
| containerSecurityContext.allowPrivilegeEscalation | bool | `false` |  |
| containerSecurityContext.capabilities.drop[0] | string | `"all"` |  |
| flaskConfig | string | `"production"` |  |
| image.pullPolicy | string | `"Always"` |  |
| image.repository | string | `"devopstales/kubedash"` |  |
| image.tag | string | `"0.1-devel"` |  |
| ingress.annotations."kubernetes.io/ingress.class" | string | `"nginx"` |  |
| ingress.annotations."nginx.ingress.kubernetes.io/proxy-body-size" | string | `"10m"` |  |
| ingress.enabled | bool | `true` |  |
| ingress.tls.certManager.clusterIssuer | string | `"letsencrypt"` |  |
| ingress.tls.certManager.enabled | bool | `false` |  |
| ingress.tls.enabled | bool | `true` |  |
| ingress.tls.tlsSecret | string | `""` |  |
| ingress.url | string | `"kubedash.mydomain.intra"` |  |
| ingress.whitelist.enabled | bool | `false` |  |
| ingress.whitelist.ips | list | `[]` |  |
| logLevel | string | `"INFO"` |  |
| podSecurityContext.runAsNonRoot | bool | `true` |  |
| podSecurityContext.runAsUser | int | `10001` |  |
| route.enabled | bool | `false` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `"kubedash-admin"` |  |

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