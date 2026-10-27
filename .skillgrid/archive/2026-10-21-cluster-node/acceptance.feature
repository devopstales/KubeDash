Feature: KubeDash cluster node view — Option 1 (node table + cluster metric tiles)
  # blueprint.md Tasks 1–5. ADR-0003 (query-only metrics.k8s.io), ADR-0004
  # (SAR key carries every attribute; the per-node series is a DERIVED rollup,
  # gated before it is computed), ADR-0005 (CoreUI), ADR-0010 (pool seam),
  # ADR-0020 (air gap), ADR-0023 (DataTables). The certainty rule (AGENTS.md)
  # is the load-bearing theme: a value the view cannot read renders "unknown",
  # never 0 or a healthy tone. Declared (capacity, role, labels) vs observed
  # (Ready, usage) state get distinct labels.
  # Scenario names are the SATISFIES oracle for the blueprint tasks and the
  # test titles (backend/tests/api + services, frontend/tests/views/node.test.tsx).
  # Each scenario's class (happy path / edge / failure) is the comment on its
  # first line.

  Background:
    Given the KubeDash single-page app with the API mocked
    And a registered cluster named "prod" is selected

  # ------------------------------------------------------- Task 1: list_nodes

  Scenario: node-list-returns-nodes
    # happy path — Task 1
    Given the cluster has a node named "node-1"
    When the K8sClient lists nodes
    Then the node list returns the node's to_dict form
    And the list is cluster-scoped (no namespace applied)

  # ------------------------------------------------------- Task 2: resources

  Scenario: node-endpoint-returns-list
    # happy path — Task 2
    Given a user who can cluster-wide list nodes
    When the API is asked for the cluster's node resources
    Then the API responds 200 with kind "nodes"
    And items holds the cluster-native node dicts

  Scenario: node-endpoint-rbac-denied
    # failure — Task 2 (ADR-0004: gate before the list)
    Given a user who cannot cluster-wide list nodes
    When the API is asked for the cluster's node resources
    Then the API responds 403 RBAC_DENIED and no nodes are returned

  # ------------------------------------------------------- Task 3: metrics

  Scenario: metrics-endpoint-available
    # happy path — Task 3
    Given the Metrics API reports usage for node-1
    And node-1 has core-v1 capacity of 8000 millicores CPU and 8Gi memory
    When the API is asked for the per-node metrics series
    Then metrics_available is true
    And the series item for node-1 shows cpu used, cpu capacity 8000, memory used and memory capacity
    And source is "metrics.k8s.io"

  Scenario: metrics-endpoint-unavailable-no-zero
    # edge — Task 3 (certainty rule)
    Given the Metrics API is unreachable (404 or 5xx)
    When the API is asked for the per-node metrics series
    Then metrics_available is false
    And items is empty, not a zero-filled series
    And the API does not respond 500

  Scenario: metrics-endpoint-rbac-denied
    # failure — Task 3 (derived data must not leak, ADR-0004)
    Given a user who cannot read nodes on metrics.k8s.io
    When the API is asked for the per-node metrics series
    Then the API responds 200 with metrics_available false and empty items
    And the node table still renders the declared state

  # ------------------------------------------------------- Task 4: the view

  Scenario: node-view-renders-tiles-and-table
    # happy path — Task 4
    Given the cluster has node-1 (Ready) and node-2 (NotReady)
    And the per-node metrics series has a metric for node-1 but not node-2
    When the node view is opened
    Then the four cluster metric tiles render: CPU usage, Memory usage, Pods, Storage
    And the node table renders with columns State, Name, Role, Version, IP, OS, CPU Usage, Memory Usage
    And node-1 shows a Ready badge and node-2 a NotReady badge
    And node-1's CPU and Memory usage show the used/capacity percentage

  Scenario: node-view-unknown-metric
    # edge — Task 4 (certainty rule)
    Given the cluster has node-1 in the node list
    And node-1 is absent from the per-node metrics series
    When the node view is opened
    Then node-1's CPU and Memory usage cells show "unknown"
    And the CPU and Memory tiles show "unknown"
    And no tile or cell shows 0 for a value that could not be read
    And the Storage tile shows "unknown" with a "no storage metrics source" note

  Scenario: node-view-no-cluster
    # edge — Task 4
    Given no cluster is selected
    When the node view is opened
    Then the view shows "No cluster selected."
    And no tiles or table rows are rendered

  Scenario: node-view-metrics-404-version-skew
    # edge — Task 4 (version skew: new frontend on an old backend)
    Given the cluster has node-1 in the node list
    And the per-node metrics endpoint 404s (old backend)
    When the node view is opened
    Then the node table still renders the declared columns for node-1
    And the CPU and Memory tiles show "unknown"
    And no red error is shown for the metrics call
