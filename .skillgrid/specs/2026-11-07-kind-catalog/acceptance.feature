Feature: Kind catalog - generic read engine (change A)

  The backend kind read path is catalog-driven: one `KINDS` registry
  (41 `KindSpec` rows), one generic `K8sClient.list`/`get` engine at the
  existing `K8sClientPool.factory` seam, and one catalog-driven `FakeK8s`
  behind per-kind fixture data. Behaviour is preserved except the one
  documented transport-mapping normalization (10 legacy 500 read paths
  become 502 CLUSTER_UNREACHABLE, user decision 2026-11-07).

  Background:
    Given the app runs with a client injected via K8sClientPool.factory
    And a bound cluster "local" is selected
    And the local admin's SAR is granted for every catalog kind

  # Task 1 - door check: catalog schema, engine, tracer kinds

  Scenario: tracer-kinds-catalog
    Given the catalog rows "ingressclasses", "secrets" and "gatewayclasses" have method None
    And the KINDS registry holds all 41 rows
    And resources.py has no "_KINDS" table and no "_GETTERS" table
    When I request GET /api/v1/clusters/local/resources/ingressclasses
    Then the response is 200 with the "ingressclasses" fixture items in snake_case shape
    And the SAR gate was asked before the read with ("list", "ingressclasses", None, None, "networking.k8s.io")
    When I request GET /api/v1/clusters/local/resources/gatewayclasses
    Then the response is 200 with the "gatewayclasses" fixture items in camelCase wire shape
    And the engine resolved the served version and scope from the CRD metadata before the read
    And the methods list_ingress_classes, get_ingress_class, list_secrets, get_secret, list_gateway_classes and get_gateway_class are deleted from k8s_client.py
    And uv run pytest -m "not integration" exits 0

  Scenario: engine-transport-failure-502
    Given a client whose API calls raise a transport ApiException
    When I request the list of an engine-served kind
    Then the response is 502 with error code CLUSTER_UNREACHABLE
    When I request an object by name and the read raises a non-404 ApiException
    Then the response is 502 with error code CLUSTER_UNREACHABLE
    When I request an object by name and the read raises a 404 ApiException
    Then the response is 200 with items: []
    When I read a CRD kind whose CRD exists but has no served version
    Then the response is 502 with error code CLUSTER_UNREACHABLE

  Scenario: crd-absent-degrade
    Given a client whose cluster has no installed CRD for kind "gatewayclasses"
    When I request GET /api/v1/clusters/local/resources/gatewayclasses
    Then the response is 200 with items: []
    And the served-version resolution returned None before any custom-object read

  Scenario: unknown-kind-404
    When I request GET /api/v1/clusters/local/resources/wormholes
    Then the response is 404 with error code RESOURCE_KIND_NOT_SUPPORTED
    And no client read was attempted
    When I request ?name=foo on the non-gettable kind "pods"
    Then the response is 404 with error code RESOURCE_KIND_NOT_SUPPORTED

  Scenario: get-name-semantics
    Given a gettable kind whose fixture holds an object "svc-1"
    When I request ?name=svc-1
    Then the response is 200 with items containing exactly "svc-1"
    When I request ?name=absent
    Then the response is 200 with items: []
    When I request ?name=db-creds on the kind "secrets"
    Then the returned secret keeps its data intact because projectors apply to the list path only

  Scenario: secrets-list-strips-data
    Given the "secrets" fixture items carry data and string_data keys
    When I request GET /api/v1/clusters/local/resources/secrets
    Then every item in the response has no data key and no string_data key

  # Task 2 - typed batch cutover (22 kinds)

  Scenario: typed-kinds-catalog
    Given the 22 typed batch kinds are catalog rows with method None
    When I request each batch kind's list route
    Then each response is 200 with the items the pre-existing per-kind route tests assert (no expectation changed)
    And the batch's per-kind list and get methods are deleted from k8s_client.py
    And the gateway_api get_ingress call-site uses client.get("ingresses", ns, name)
    And the metrics route uses client.list for nodes and pods
    And the crds instances route uses client.get("crds", None, name) while list_crd_instances stays a named client method
    And a transport failure on the 10 legacy 500 read paths now returns 502 CLUSTER_UNREACHABLE instead of 500 INTERNAL_ERROR
    And uv run pytest -m "not integration" exits 0

  Scenario: persistentvolumes-claim-namespace-filter
    Given the "persistentvolumes" fixture holds bound and free volumes
    When I request GET /api/v1/clusters/local/resources/persistentvolumes?namespace=team-a
    Then the response contains the PVs claimed in "team-a" and every free or unbound PV
    And it contains no PV claimed in another namespace

  Scenario: pods-label-selector-forwarded
    Given the "pods" kind forwards labelSelector to the namespaced list call only
    When I request pods in namespace "team-a" with ?labelSelector=app=web
    Then the fake records last_pod_label_selector "app=web"
    When I request pods without a namespace with ?labelSelector=app=web
    Then the fake records no label selector
    And a request for the kind "services" with ?labelSelector=app=web ignores it

  # Task 3 - CRD batch cutover (12 kinds)

  Scenario: crd-kinds-catalog
    Given the 12 CRD batch kinds are catalog rows with method None
    When I request each batch kind's list route
    Then each response is 200 with the camelCase wire-shape fixture items at the served version
    When I set the fake's crd_absent to one of the batch kinds
    Then that kind's list route returns 200 with items: [] and a transport failure on it returns 502 CLUSTER_UNREACHABLE
    And the batch's 12 list and 11 get methods are deleted from k8s_client.py
    And uv run pytest -m "not integration" exits 0

  # Task 4 - coverage recovery

  Scenario: every-kind-covered
    Given the parametrized suite iterates every row of KINDS
    When the suite runs
    Then every engine row returns 200 with items equal to the fixture data after its projector
    And every cluster-scoped row ignores a namespace=kube-system query
    And every gettable row answers ?name=present with one item and ?name=absent with items: []
    And every non-gettable row answers ?name= with 404 RESOURCE_KIND_NOT_SUPPORTED
    And the SAR gate was asked per row with (verb, spec.plural, ns, name, spec.group)
    And every crd row additionally degrades to items: [] when its CRD is absent
    And a meta test fails when any catalog row has no FIXTURES entry
    And the 4 external-LB override rows pass provider-detection tests: MetalLB present wins, MetalLB absent falls back to Cilium, both absent returns items: []

  # Task 5 - concept split

  Scenario: concepts-split
    Given kubeconfig_crypto.py, kubeconfig_binding.py and k8s_metrics.py exist as modules
    When I inspect the module seams
    Then kubeconfig_crypto exposes key, encrypt_kubeconfig and decrypt_kubeconfig
    And kubeconfig_binding exposes bound_cluster_or_404 and resolve_admin_source
    And k8s_metrics exposes node_metrics, node_usage, pvc_usage and parse_bytes
    And k8s_client.py keeps client construction, the engine, mutations, readyz and K8sClientPool
    And every importer of the moved names imports from the new module
    And uv run pytest -m "not integration", uv run ruff check . and uv run mypy app all exit 0
    And wc -l app/services/k8s_client.py is below 900

  # Task 6 - single shared double

  Scenario: one-double
    Given FakeK8s lives at tests/fakes/fake_k8s.py driven by KINDS and FIXTURES
    When I grep the test tree for "class _?Fake.*K8s"
    Then exactly one class remains: the shared FakeK8s
    And every suite injects it through pool.factory
    And uv run pytest -m "not integration" exits 0

  # Task 7 - green, measured, documented

  Scenario: green-and-measured
    Given all code tickets are committed
    When I run the full floor
    Then uv run pytest -m "not integration", uv run ruff check . and uv run mypy app all exit 0
    And k8s_client.py declares only the 4 external-LB override pairs and list_events as list/get methods
    And the jscpd health re-run is recorded against the 2026-11-07 baseline (health 32/E, k8s_client cx 393/2487L, test_resources cx 307/3938L)
    And ARCHITECTURE.md has a read-path section describing the as-built catalog, engine and five concepts
    And ARCHITECTURE.md documents the kind-addition procedure: one catalog row plus one fixture entry
