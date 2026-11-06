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
| **kubedash.ini** | The operator-facing configuration file (4.1 format, minus plugins) read with `configparser` (interpolation off). The PRIMARY config source; `KUBEDASH_*` env is the higher-priority override; a missing required value fails fast at boot. (ADR-0028.) |
| **KUBEDASH_HOME** | The single anchor env var (app root): the INI is `<home>/kubedash.ini`, the built SPA `<home>/static`. Baked as `/app` in the container; in dev derived from `wsgi.py`'s own location, never set manually. (ADR-0028; replaces `KUBEDASH_STATIC_DIR`.) |
| **Cilium served version** | The `cilium.io` CRD version flagged `served: true` in the CRD's own `spec.versions` — resolved at read time, never hardcoded. (2026-10-26-network-policy.) |
| **CRD-absent degrade** | A 404 on a CRD or its resource list resolves to `[]` items (feature not installed = expected state, e.g. Cilium absent), while any other read failure raises `ClusterUnreachableError` → 502. (2026-10-26-network-policy.) |
| **Object ref** | The token-keyed `sessionStorage` entry (`kd_object_refs` registry + `kd_object_active` pointer, 15-min lazy self-expiry) that identifies the object a SPA tab has open. A pointer, not a privilege — the read stays SAR-gated. The URL never carries it. (ADR-0040.) |
| **Deep link (object)** | The cross-tab object share path: hidden same-origin form **POST** of the opaque token → SPA-fallback 303 bounce → one-shot `<meta name="kd-object-incoming">` (Redis `obj_incoming:<sub>`, TTL 60 s, GETDEL) → `localStorage` relay adoption. The fresh tab lands on the clean route with `location.search === ''`. (ADR-0040, amended 2026-11-04.) |
| **Object handoff** | The server-session delivery of the deep-link token: `backend/app/core/object_handoff.py` (SPA-fallback 303 POST bounce + `obj_incoming:<sub>` Redis stash + one-shot meta injection; injected document is no-store). |
| **SPA fallback** | The Flask catch-all route that serves `index.html` for non-API, non-asset paths (client-side routing) and, since ADR-0040, carries the object deep-link handoff (303 + one-shot meta). |
| **Observed tier** | The degraded, metrics-sourced view of a resource's runtime state (the PVC/PV `Usage` column over `/metrics/pvcs` → kubelet `/stats/summary`): a separate late-resolving read from the cached list, which degrades to "—" (never a row error) when the kubelet stats are unavailable or denied. (ADR-0003 two-tier; ADR-0010 read path.) |
