# Configuration

Create a values file for your helm deploy:

```yaml
TimeZone: "CET"
logLevel: "INFO"
flaskConfig: "production" #or development

serviceAccount:
  create: true
  name: "kubedash-admin"

image:
  repository: devopstales/kubedash
  tag: 0.1
  pullPolicy: Always

podSecurityContext:
  runAsNonRoot: true
  runAsUser: 10001

containerSecurityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["all"]

ingress:
  enabled: true
  url: "kubedash.mydomain.intra"
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    kubernetes.io/ingress.class: nginx
  tls:
    enabled: true
    tlsSecret: "mycert-tls"
    certManager:
      enabled: false
      clusterIssuer: "letsencrypt"
  whitelist:
    enabled: false
    ips: []
  
route:
  enabled: false

```

## Operator Configuration

The following tables lists configurable parameters of the trivy-operator chart and their default values.

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