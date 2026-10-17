# KubeDash — Technical Terms

> Architecture / platform / protocol vocabulary. **Vocabulary only** — no
> implementation details, no specs, no scratch.

| Term | Definition |
|---|---|
| **Api** | A `flask_smorest.Api` subclass (domain-scoped REST resource). *Not* the skillgrid implementation plan (which lives at `blueprint.md` in a change folder). |
| **View** | A `src/views/<Name>/` folder (one per route), per the CoreUI free admin template convention. *Not* a "feature" folder. |
| **CoreUI shell** | The Header + Sidebar + Footer + `_nav` + `routes` scaffold adopted from `coreui/coreui-free-react-admin-template`. |
| **Leader** | The replica holding the `leader_lease`; runs the RQ worker. |
| **Follower** | A replica without the lease; serves HTTP only. |
| **RQ** | Redis Queue; the async task runner (in-process, leader-gated). |
| **Informer cache** | The per-cluster, in-memory dict of K8s resources maintained by long-lived watches. The read path for all UI + services. |
| **SSE stream** | A `text/event-stream` HTTP response used for server→client push (events, timeline, topology, logs). Client uses native `EventSource`. |
| **MCP** | Model Context Protocol; the `/mcp` endpoint that exposes KubeDash data + actions to AI agents. |
| **Credential plugin** | The kubectl exec credential plugin (`kubectl kubedash`) that authenticates via KubeDash-managed OIDC SSO. The kubeconfig contains only `--server` + `--cluster-name`; all SSO config is fetched from the server at auth time. |
| **ExecCredential** | The `client.authentication.k8s.io/v1` JSON object the plugin prints to stdout for kubectl to consume. |
| **SSOUser** | An `auth.kubedash.io/v1` object (cluster-admin only) showing a user's effective permissions, computed on-the-fly from RBAC objects. |
| **SSOGroup** | An `auth.kubedash.io/v1` object (cluster-admin only) showing a group's effective permissions. |
| **Aggregated API** | The KubeDash service registered as a K8s aggregated API server (kube-aggregator pattern). Serves `projects.kubedash.io/v1` + `auth.kubedash.io/v1` over mTLS on port 8443. Read-only; no data in etcd. |
| **APIService** | The `apiregistration.k8s.io/v1` object that registers the KubeDash aggregated API with the K8s API server. |
| **Drift detection** | The `rbac_drift_check` RQ task that compares cluster RBAC objects (labelled `kubedash.io/template`) against the Postgres templates, and enforces or warns on divergence. |
| **Tracer** | A distributed trace (Tempo/Jaeger). |
| **Session revocation propagation** | The property that ending a KubeDash web session (logout) immediately invalidates all derived credentials, via a Redis `jti` revocation set + OIDC RP-initiated logout + CSR revocation. (ADR-0014.) |
| **Verify endpoint** | The `/auth/verify` subrequest endpoint that ingress controllers call (NGINX `auth_request`, Traefik `forwardauth`, Istio `ext_authz`) to authenticate a request and forward `X-Remote-*` identity headers. (ADR-0019.) |
| **JIT** | Just-In-Time: provisioning that runs at login / elevation / NaaS approval. |
| **PKCE** | Proof Key for Code Exchange (S256) — the OIDC public-client flow the kubectl plugin uses (no `client_secret`). |
| **RP-initiated logout** | The OIDC `end_session_endpoint` flow that revokes the IdP refresh token on KubeDash logout. |
