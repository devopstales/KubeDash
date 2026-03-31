# TODO

## Security

Air gap mode [X]
- everything soud run in air gap mode

Missing Rate Limiting
- No rate limiting on authentication endpoints
- Recommendation: Add flask-limiter for brute-force protection

Internationalization (i18n)
- No i18n support visible
- Recommendation: Add Flask-Babel for multi-language support

MFA
-

passkey
-

## New Functions

About page
- branch
- Build Time ??
- git commit
- Database type
- redis connection
- opentelemtry connection
- openai connection
- pod name, namespace, pod ip

Redis Cluster Support Incomplete
- Config has cluster_enabled but no implementation visible
- Recommendation: Complete implementation or remove to avoid confusion

multi cluster
- table for k8s config
- CREATE TABLE `kube_configs` (`id` integer PRIMARY KEY AUTOINCREMENT,`content` text,`server` text,`user` text,`cluster` text,`namespace` text,`display_name` text,`access_key` text,`secret_access_key` text,`cluster_name` text,`region` text,`is_awseks` numeric,`token` text,`ca_cert` text,`proxy_url` text,`timeout` integer DEFAULT 30,`qps` real DEFAULT 200,`burst` integer DEFAULT 2000,`created_at` datetime,`updated_at` datetime)


multi-instance
- leader election plugin
- sqlight cluster

events dashboard
- centralized events dashboard ?

gitops: argocd plugin
- UI ?

Policy Management: Kyverno Plugin
- already planned

cost optimization
- kubecost integration

use as mcp server
-

k8sgpt plugin
- integrate k8sgpt mcp server ?

## Bugs

plugin integration
- opentelemetry tracing for all plugins
- cachhing for all plugins
- audit logging for all plugins

metrics [-]
- Optional: Change Metrics to pul prom prometheus.
- clsuter-metrics function runs 19.12s
- lsuter-metrics not used ThredidThicker cache
- add prometheus integration option

node labeling and annotation

### Docs

- Docs how to connect ollama clous with api token

---
* https://github.com/weibaohui/k8m/blob/main/README_en.md
* https://github.com/weibaohui/kom/blob/main/README_en.md