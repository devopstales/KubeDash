# Decisions

Project: kubedash

Live topic keys only. Superseded rows are omitted.

## architecture/5.0-stack

Locked 5.0 architecture: Flask backend + Vite/React frontend + Go kdlogin (decision)

## architecture/auth-transport

Migrated browser session to HttpOnly cookies (ADR-0025) (architecture)

## architecture/dashboard-metrics

Split metrics_denied from metrics_available on the cluster dashboard (bugfix)

## architecture/dev-server

Switched dev backend-run to Gunicorn (same server as prod) (decision)

## architecture/file-layout

Adopt src layout for KubeDash 5.0 backend + frontend (decision)

## architecture/flask-session-sqlalchemy-app-factory

flask-session + module-level SQLAlchemy: second create_app collides on sessions table (bugfix)

## architecture/flask-smorest-0x-route-pattern

Fixed smorest 0.47 bare-dict status inference on API blueprints (bugfix)

## architecture/frontend-store-persistence

Persisted cluster-scope store for ns_select (4.1 parity) (architecture)

## architecture/k8s-dual-mode-client

K8s dual-mode client: new_client_from_config (no adapt_kube_config in 29.x), stub _admin_configuration in unit tests (pattern)

## architecture/permissions-display-gate

Wired usePermissions into Namespaces view (replaced role checks) (pattern)

## architecture/phase-1-scope

Locked Phase 1 MVP scope: core resources + CRD browser, dual K8s auth, no plugin registry (decision)

## architecture/phase-2-4-cross-cutting

Locked Phase 2-4 scope + cross-cutting concerns (decision)

## architecture/phase2-oidc-issuer

Recorded ADR-0007: Phase 2 SSO = Authentik core + mkcert CA (decision)

## architecture/release-5.0-spec

release/5.0 branch has full 4-phase spec (docs-only, no code) (discovery)

## architecture/sa-token-auth-sso

SA token auth: V1-prefixed models, AuthenticationV1Api, SAR user=USERNAME not token (pattern)

## architecture/spa-react-migration

Decided SPA React migration architecture for KubeDash (decision)

## architecture/vpa-views

Executed vpa-views (TASK-049): VPA list+data views on the Cilium CRD seam (decision)

## backend/ca-based-local-user-kubeconfig

Ported 4.1 CA-based local-user kubeconfig: CSR mint + CA download + CA manual commands (decision)

## backend/gunicorn-wsgi-entrypoint-ini-config

dev-stack now runs Gunicorn (wsgi:wsgi) with INI-only config; fixed broken wsgi:main load target (architecture)

## backend/rq-work-horse-macos-fork-objc

RQ work-horse SIGABRT (ret_val=6) on macOS: fork-after-ObjC-init in multithreaded dev backend (bugfix)

## backend/wsgi-rq-worker-child-app

Fixed RQ worker child None-app crash (ADR-0028 missed the -c entry point) (bugfix)

## backlog/spec-status-2026-10-04

Validated backlog/spec status against code for 7 KubeDash epics (discovery)

## bugfix/k8s-raw-json-serialization

Fixed 500 + JSON.parse flash by stripping raw from all K8s API endpoints (bugfix)

## bugfix/otel-init-hardening

Hardened OTel init for TASK-011 monitoring (bugfix)

## bugfix/socketio-test-namespace

Fixed Flask-SocketIO test client namespace dispatch for /exec (bugfix)

## config/cocoindex-ollama

Fixed ccc index Ollama connection failure (bugfix)

## config/poetry-pins-and-test-invocation

Fix stale Poetry pins + src-layout test invocation (discovery)

## dev/demo-data-demo-broken

dev-stack demo-broken shows 2 ImagePullBackOff pods, not 1 crashlooping (discovery)

## dev/dev-stack-fe-cache-cni-register-order

dev-stack: fe build/sync cached, CNI install gated, kind-before-backend with register-after-backend (config)

## dev/dev-stack-kind-before-backend

dev-stack: kind/demo-data now runs BEFORE the backend; kills cover Gunicorn (config)

## dev/metrics-server-sar-delegation

Fixed metrics-server authorization delegation (cluster-scope SAR) + node-view metrics warning consistency (bugfix)

## env/git-hooks

Env gotcha: repo gitleaks wrapper bypassed, history scan slow (discovery)

## execution/2026-10-26-network-policy

Executed 2026-10-26-network-policy: 5 tasks + QA + final review, phase=qa (architecture)

## execution/ini-config-source

QA gate PASS for 2026-10-26-ini-config-source; report.md committed in archive (architecture)

## feature/logs-socketio

Added SocketIO /logs namespace for pod log follow (pattern)

## frontend/coreui-shell-verification

Verified KubeDash 5.0 frontend shell with mocked cluster APIs (discovery)

## frontend/events-table-message-wrap

Cluster-metric events table: Message wraps, Last seen keeps space (bugfix)

## init/docs/.skillgrid/ARCHITECTURE.md

ARCHITECTURE.md (architecture)

## init/docs/.skillgrid/ASSUMPTIONS.md

ASSUMPTIONS.md (architecture)

## init/docs/.skillgrid/artifacts/06-research-findings.md

06-research-findings.md (architecture)

## init/docs/.skillgrid/artifacts/README.md

README.md (architecture)

## init/docs/README.md

README.md (discovery)

## init/docs/docs/assets/javascripts/bundle.803ed251.min.js

bundle.803ed251.min.js (discovery)

## init/docs/docs/assets/javascripts/bundle.ba7fc6cf.min.js

bundle.ba7fc6cf.min.js (discovery)

## init/docs/docs/assets/javascripts/glightbox.min.js

glightbox.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.ar.min.js

lunr.ar.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.da.min.js

lunr.da.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.de.min.js

lunr.de.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.du.min.js

lunr.du.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.es.min.js

lunr.es.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.fi.min.js

lunr.fi.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.fr.min.js

lunr.fr.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.hi.min.js

lunr.hi.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.hu.min.js

lunr.hu.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.it.min.js

lunr.it.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.ja.min.js

lunr.ja.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.jp.min.js

lunr.jp.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.ko.min.js

lunr.ko.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.multi.min.js

lunr.multi.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.nl.min.js

lunr.nl.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.no.min.js

lunr.no.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.pt.min.js

lunr.pt.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.ro.min.js

lunr.ro.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.ru.min.js

lunr.ru.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.stemmer.support.min.js

lunr.stemmer.support.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.sv.min.js

lunr.sv.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.ta.min.js

lunr.ta.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.th.min.js

lunr.th.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.tr.min.js

lunr.tr.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.vi.min.js

lunr.vi.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/min/lunr.zh.min.js

lunr.zh.min.js (discovery)

## init/docs/docs/assets/javascripts/lunr/tinyseg.js

tinyseg.js (discovery)

## init/docs/docs/assets/javascripts/workers/search.6c7302c4.min.js

search.6c7302c4.min.js (discovery)

## init/docs/docs/assets/javascripts/workers/search.bb370e14.min.js

search.bb370e14.min.js (discovery)

## init/docs/docs/assets/stylesheets/glightbox.min.css

glightbox.min.css (discovery)

## init/docs/docs/assets/stylesheets/main.83929f28.min.css

main.83929f28.min.css (discovery)

## init/docs/docs/assets/stylesheets/main.dc5b59cc.min.css

main.dc5b59cc.min.css (discovery)

## init/docs/docs/assets/stylesheets/palette.6932e648.min.css

palette.6932e648.min.css (discovery)

## init/docs/docs/build/requirements.txt

requirements.txt (discovery)

## init/docs/docs/contributing.md

contributing.md (discovery)

## init/docs/docs/development/api-reference.md

api-reference.md (discovery)

## init/docs/docs/development/architecture.md

architecture.md (discovery)

## init/docs/docs/development/audit-logging.md

audit-logging.md (discovery)

## init/docs/docs/development/auth0-minikube.md

auth0-minikube.md (discovery)

## init/docs/docs/development/db-migrate.md

db-migrate.md (discovery)

## init/docs/docs/development/developer-guide.md

developer-guide.md (discovery)

## init/docs/docs/development/env.md

env.md (discovery)

## init/docs/docs/development/extension-api-examples.md

extension-api-examples.md (discovery)

## init/docs/docs/development/extension-api-reference.md

extension-api-reference.md (discovery)

## init/docs/docs/development/extension-api-testing.md

extension-api-testing.md (discovery)

## init/docs/docs/development/graceful-shutdown-testing.md

graceful-shutdown-testing.md (discovery)

## init/docs/docs/development/logging.md

logging.md (discovery)

## init/docs/docs/development/opentelemetry-integration.md

opentelemetry-integration.md (discovery)

## init/docs/docs/development/plugin-development.md

plugin-development.md (discovery)

## init/docs/docs/development/product-overview.md

product-overview.md (discovery)

## init/docs/docs/development/registry-ui.md

registry-ui.md (discovery)

## init/docs/docs/development/security.md

security.md (discovery)

## init/docs/docs/development/testing.md

testing.md (discovery)

## init/docs/docs/faq/technical.md

technical.md (discovery)

## init/docs/docs/functions/authentication.md

authentication.md (discovery)

## init/docs/docs/functions/autoscaling.md

autoscaling.md (discovery)

## init/docs/docs/functions/cluster-metrics.md

cluster-metrics.md (discovery)

## init/docs/docs/functions/cluster-permissions.md

cluster-permissions.md (discovery)

## init/docs/docs/functions/crds.md

crds.md (discovery)

## init/docs/docs/functions/features.md

features.md (discovery)

## init/docs/docs/functions/k8s-api.md

k8s-api.md (discovery)

## init/docs/docs/functions/kubectl-config.md

kubectl-config.md (discovery)

## init/docs/docs/functions/namespaces.md

namespaces.md (discovery)

## init/docs/docs/functions/network.md

network.md (discovery)

## init/docs/docs/functions/nodes.md

nodes.md (discovery)

## init/docs/docs/functions/pod-debugging.md

pod-debugging.md (discovery)

## init/docs/docs/functions/rbac.md

rbac.md (discovery)

## init/docs/docs/functions/resource-map.md

resource-map.md (discovery)

## init/docs/docs/functions/security.md

security.md (discovery)

## init/docs/docs/functions/storage.md

storage.md (discovery)

## init/docs/docs/functions/users.md

users.md (discovery)

## init/docs/docs/functions/workloads.md

workloads.md (discovery)

## init/docs/docs/index.md

index.md (discovery)

## init/docs/docs/installation/configuration.md

configuration.md (discovery)

## init/docs/docs/installation/installation.md

installation.md (discovery)

## init/docs/docs/installation/platforms.md

platforms.md (discovery)

## init/docs/docs/integrations/application-catalog.md

application-catalog.md (discovery)

## init/docs/docs/integrations/cert-manager.md

cert-manager.md (discovery)

## init/docs/docs/integrations/docker-registry.md

docker-registry.md (discovery)

## init/docs/docs/integrations/extension-api.md

extension-api.md (discovery)

## init/docs/docs/integrations/external-load-balancer.md

external-load-balancer.md (discovery)

## init/docs/docs/integrations/helm.md

helm.md (discovery)

## init/docs/docs/integrations/kubectl-plugin.md

kubectl-plugin.md (discovery)

## init/docs/docs/integrations/project-data.md

project-data.md (discovery)

## init/docs/docs/integrations/trivy-operator.md

trivy-operator.md (discovery)

## init/docs/docs/operations/README.md

README.md (discovery)

## init/docs/docs/operations/database-configuration.md

database-configuration.md (discovery)

## init/docs/docs/operations/database-connection-pool-tuning.md

database-connection-pool-tuning.md (discovery)

## init/docs/docs/operations/database-health-checks.md

database-health-checks.md (discovery)

## init/docs/docs/operations/database-mode-validation.md

database-mode-validation.md (discovery)

## init/docs/docs/operations/graceful-shutdown-deployment.md

graceful-shutdown-deployment.md (discovery)

## init/docs/docs/operations/graceful-shutdown-implementation.md

graceful-shutdown-implementation.md (discovery)

## init/docs/docs/operations/graceful-shutdown-troubleshooting.md

graceful-shutdown-troubleshooting.md (discovery)

## init/docs/docs/operations/graceful-shutdown.md

graceful-shutdown.md (discovery)

## init/docs/docs/operations/ha-configuration.md

ha-configuration.md (discovery)

## init/docs/docs/operations/leader-election-graceful-shutdown.md

leader-election-graceful-shutdown.md (discovery)

## init/docs/docs/operations/multi-replica-upgrade.md

multi-replica-upgrade.md (discovery)

## init/docs/docs/operations/postgres-ha.md

postgres-ha.md (discovery)

## init/docs/docs/operations/sqlite-to-postgres-migration.md

sqlite-to-postgres-migration.md (discovery)

## init/docs/docs/operations/staging-environment.md

staging-environment.md (discovery)

## init/docs/docs/plugins/ai-chat.md

ai-chat.md (discovery)

## init/docs/docs/plugins/application_catalog.md

application_catalog.md (discovery)

## init/docs/docs/plugins/cert_manager.md

cert_manager.md (discovery)

## init/docs/docs/plugins/external_loadbalancer.md

external_loadbalancer.md (discovery)

## init/docs/docs/plugins/flux.md

flux.md (discovery)

## init/docs/docs/plugins/gateway_api.md

gateway_api.md (discovery)

## init/docs/docs/plugins/helm.md

helm.md (discovery)

## init/docs/docs/plugins/iframe_proxy.md

iframe_proxy.md (discovery)

## init/docs/docs/plugins/registry.md

registry.md (discovery)

## init/docs/docs/plugins/trivy_operator.md

trivy_operator.md (discovery)

## kubedash-5.0/spec-layout

Split KubeDash 5.0 blueprint into per-phase spec folders (decision)

## learning/code-intel-tool-comparison

Compared mnemonic vs ccc vs codegraph: mnemonic wins semantic/explore/impact, ccc wins grep positions, codegraph solid caller-trail (learning)

## learning/mnemonic-tool-test-status

Round 6: ALL 3 BUGS CLOSED — rename now 3 files (workload.py occurrences:3 correct, blueprint:366 present), positions + metavariables still fixed (learning)

## loop/command_exec

Noted decision (decision)

## loop/file_write

Repeated edit /Users/paladm/git/kubedash_4/Taskfile.yml (pattern)

## pattern/k8s-lib-seam

Fixed k8s lib seam patching (import API classes directly) + keyword-only api param (bugfix)

## sdd-init/kubedash

Populated skillgrid artifacts and AGENTS.md from codebase (discovery)

## sdd/2026-10-05-mnemonic-scan-findings/briefing

Created scan-findings spec for skillgrid-v2 (decision)

## sdd/kubedash-5.0/explore

KubeDash 4.1 codebase research — full capability map (discovery)

## session/2026-10-28-network-policy-exec

Committed dirty rebase tree (7 commits) before network-policy execution (decision)

## skillgrid-init/KubeDash

KubeDash 5.0 onboarding — Go rewrite, Backlog.md tracker, T3 rigor (config)

## skillgrid-init/kubedash

KubeDash Skillgrid onboarding — project context (architecture)

## skillgrid/2026-10-21-cluster-dashboard/execution-progress

Node list progress matched to 4.1 prototype: thin 4px bars + big stat value (architecture)

## skillgrid/2026-10-24-tls-security-headers/ship

ship — 2026-10-24-tls-security-headers (architecture)

## skillgrid/2026-10-26-ini-config-source/ship

ship — 2026-10-26-ini-config-source (architecture)

## skillgrid/2026-10-26-network-policy/ship

ship — 2026-10-26-network-policy (architecture)

## skillgrid/KubeDash/issue_tracker

KubeDash issue tracker: Backlog.md local (config)

## skillgrid/KubeDash/testing-capabilities

KubeDash testing capabilities (config)

## skillgrid/artifacts-structure

Created missing .skillgrid/ARCHITECTURE.md (discovery)

## skillgrid/kubedash/issue_tracker

KubeDash tracker: Backlog.md local (config)

## skillgrid/kubedash/testing-capabilities

KubeDash testing capabilities table (config)

## spec/phase-1/acceptance

Authored Phase 1 acceptance.feature with 36 Gherkin scenarios (architecture)

## testing/minimal-config-tests

Added minimal-config unit tests + uv run recipe for broken .venv (learning)

## tracking/backlog-spec-changes

Published 7 Skillgrid spec changes to Backlog.md (decision)

## workflow/large-file-chunked-writes

Chunked large blueprint writes to avoid truncation (lesson)

