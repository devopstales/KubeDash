Feature: KubeDash 5.0 base structure tracer spine

  Background:
    Given a KubeDash app built by create_app() against Testcontainers Postgres and Redis

  Scenario: app boots and health probes report
    When GET /healthz is called
    Then the response is 200
    When GET /readyz is called with dependencies up
    Then the response is 200 with database "ok" and redis "ok"
    When GET /readyz is called with Redis down
    Then the response is 503 and the body names "redis"

  Scenario: OIDC login issues a JWT
    When an unauthenticated browser POSTs /api/v1/auth/login
    Then the response is 302 to the OIDC authorize URL
    When the callback completes with a valid code
    Then a users row is upserted by sub and a JWT (HS256, 15 min) plus a hashed refresh token are issued
    When GET /api/v1/auth/me is called with the JWT
    Then the response echoes the OIDC sub
    When GET /api/v1/clusters is called without a JWT
    Then the response is 401 {"error": {"code": "UNAUTHORIZED"}}
    When a refresh token is used twice
    Then the second use is 401 and the stored row is revoked

  Scenario: cluster register and health
    When an authenticated user POSTs /api/v1/clusters with a valid kubeconfig
    Then the kubeconfig is stored AES-256-GCM encrypted and the user is bound as admin
    When the same name is posted again
    Then the response is 409 CLUSTER_ALREADY_EXISTS
    When an unparseable kubeconfig is posted
    Then the response is 422 INVALID_KUBECONFIG and nothing is stored
    When a user without a binding lists clusters
    Then the cluster is absent
    When GET /api/v1/clusters/<id>/health is called against a live kind cluster
    Then the response is {"status": "up"}
    When the API server is down
    Then the response is 502 CLUSTER_UNREACHABLE within the probe timeout

  Scenario: list pods for a bound cluster
    When an authenticated, bound user GETs /api/v1/clusters/<id>/resources/pods?namespace=default
    Then the kind cluster's test pod is listed
    When the user's SAR denies list on pods
    Then the response is 403 RBAC_DENIED
    When the kind is unknown
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  Scenario: SPA shell renders cluster pods
    When pnpm build runs in frontend/
    Then the build exits 0 and dist/ contains the hashed assets
    When the SPA is served by Flask
    Then GET / and GET /clusters/123 return index.html (Cache-Control: no-cache)
    Then GET /assets/* is served Cache-Control: immutable
    Then /api/v1/* is never shadowed by the catch-all
    When the Playwright journey runs (login → clusters → pods)
    Then the pod table renders the kind cluster's test pod

  Scenario: chart renders deployment with replica id
    When helm template renders charts/kubedash
    Then the Deployment carries KUBEDASH_REPLICA_ID from fieldRef metadata.name
    Then KUBEDASH_ROLE is "leader" and OIDC env comes from values/secret
    When docker build runs on backend/Dockerfile
    Then the image builds, runs as UID 10001, and /healthz answers in-process

  Scenario: CLI version prints
    When ./kubedash version runs
    Then stdout is "kubedash 0.1.0"
    When ./kubedash get-token runs
    Then the exit code is 2 and stderr points at the kubectl-oidc-plugin blueprint

  Scenario: stub surface matches architecture
    When the file-map test diffs ARCHITECTURE.md §2 paths against the tree
    Then every backend/app/ path exists
    When a stub route (e.g. GET /api/v1/logs/query) is called
    Then the response is 501 NOT_IMPLEMENTED with the stable error shape

  Scenario: CI is green on the base structure
    When .github/workflows/ci.yaml runs on the change branch
    Then backend, frontend, cli, chart, and image jobs pass (incl. Trivy CRITICAL gate)
    When actionlint runs on the workflow YAMLs
    Then there are no findings

  Scenario: test fixtures boot
    When pytest runs the full suite with Docker available
    Then all unit + integration tests pass
    When pytest runs with -m "not integration"
    Then the suite passes without a kind cluster
