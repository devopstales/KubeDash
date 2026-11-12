Feature: PVC views (list + data + usage, namespaced)
  # briefing.md R1-R6. The load-bearing theme: the 4.1 PVC pages
  # (list: status/name/storage-class/volume/capacity/usage; data: status +
  # access mode + volume mode + capacity + storage class + bound volume +
  # labels + annotations) are ported to 5.0 as a real, SAR-gated, read-only
  # list + data pair under Storage (ADR-0022) — a namespaced core kind
  # (core v1), with the ratified 5.0 deltas (?name=&namespace= params, JSON
  # block, and the Usage column as a second query-only metrics fetch).

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user

  # --------------------------------------------------------- API: list (R1)

  Scenario: pvcs-list-200
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumeclaims?namespace=team-a
    Then the response is 200
    And the body kind is persistentvolumeclaims
    And the body cluster is the bound cluster name
    And every item is in to_dict snake_case form

  Scenario: pvcs-list-all-namespaces
    # edge — R1 (no ?namespace= -> the all-namespaces branch, the list_secrets pattern)
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumeclaims
    Then the response is 200
    And the K8s client used the all-namespaces list call

  Scenario: pvcs-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on persistentvolumeclaims (core, namespace team-a) denies
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumeclaims?namespace=team-a
    Then the response is 403 RBAC_DENIED naming the persistentvolumeclaims resource
    And the K8s client list call was never made

  Scenario: pvcs-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/persistentvolumeclaims?namespace=team-a
    Then the response is 404

  Scenario: pvc-kind-singular-rejected
    # edge — R1 (the 4.1 route name was "pvc"; the API kind is the plural)
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumeclaim
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED
    When a bound user requests GET /api/v1/clusters/1/resources/pvc
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: pvcs-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumeclaims?name=data-pvc&namespace=team-a
    Then the response is 200 with a one-item list containing the named pvc
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumeclaims?name=ghost&namespace=team-a
    Then the response is 200 with an empty items list

  # ------------------------------------------------- API: pvc usage (R3)

  Scenario: pvc-usage-happy-path
    # happy path — R3 (kubelet stats/summary, per-PVC aggregation by pvcRef)
    Given the kubelet stats report pod volumes referencing the namespace's pvcs
    When a bound user requests GET /api/v1/clusters/1/metrics/pvcs?namespace=team-a
    Then the response is 200
    And the body source is "kubelet stats/summary"
    And the body metrics_available is true
    And the body metrics_denied is false
    And each item has name, capacity_bytes, used_bytes, available_bytes, percentage_used
    And percentage_used is used over capacity times 100 for the pvc

  Scenario: pvc-usage-sar-denied
    # failure — R3 (ADR-0004: get nodes SAR before any stats call; degrades, never 403)
    Given the SAR check for get on nodes denies
    When a bound user requests GET /api/v1/clusters/1/metrics/pvcs?namespace=team-a
    Then the response is 200
    And the body metrics_denied is true
    And the body metrics_available is false
    And the body items is empty
    And no kubelet stats call was made

  Scenario: pvc-usage-kubelet-degrade
    # edge — R3 (ADR-0003: no node yields stats -> 200 empty, never 500)
    Given every node's stats/summary endpoint fails
    When a bound user requests GET /api/v1/clusters/1/metrics/pvcs?namespace=team-a
    Then the response is 200
    And the body metrics_available is false
    And the body items is empty

  Scenario: pvc-usage-partial-nodes
    # edge — R3 (a failing node is skipped; the healthy subset is returned)
    Given one node's stats/summary endpoint fails and the others succeed
    When a bound user requests GET /api/v1/clusters/1/metrics/pvcs?namespace=team-a
    Then the response is 200
    And the body metrics_available is true
    And the body items aggregate only the healthy nodes

  Scenario: pvc-usage-zero-capacity
    # edge — R3 (the 4.1 division-by-zero guard)
    Given a pvc with zero capacity bytes in the kubelet stats
    When a bound user requests GET /api/v1/clusters/1/metrics/pvcs?namespace=team-a
    Then the response is 200
    And that pvc's percentage_used is 0.0

  Scenario: pvc-usage-binding-404
    # edge — R3 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/metrics/pvcs?namespace=team-a
    Then the response is 404

  # ---------------------------------------------------- frontend: list (R4)

  Scenario: pvc-list-renders-rows-with-data-links
    # happy path — R4
    Given the cluster is selected
    And the selected namespace is team-a
    When the user opens /storage/pvc
    Then the card title is EXACTLY "Persistent Volume Claim List"
    And the fetch URL is /api/v1/clusters/1/resources/persistentvolumeclaims?namespace=team-a
    And every pvc name links to /storage/pvc/data?name=<name>&namespace=team-a
    And the columns are Status, Name, StorageClass, Volume, Capacity, Usage

  Scenario: pvc-list-usage-join
    # happy path — R4 (the second parallel fetch, joined by pvc name)
    Given the usage fetch returns an item for data-pvc with percentage_used 42.3
    When the user opens /storage/pvc
    Then the data-pvc row Usage cell is "42.3 %"
    And rows absent from the usage items show Usage "—"

  Scenario: pvc-list-usage-degrades-to-em-dash
    # edge — R4 (the observed tier never fails the list: unavailable, denied,
    # or a failed fetch all render "—")
    When the usage fetch reports metrics_available false
    Or the usage fetch reports metrics_denied true
    Or the usage fetch itself fails
    Then every Usage cell is "—"
    And the pvc rows still render

  Scenario: pvc-list-status-phase-badges
    # edge — R4 (4.1's three-tier badge pair)
    Given a bound pvc with phase Bound and an unbound pvc with phase Pending
    When the user opens /storage/pvc
    Then the Bound row shows a success badge
    And the Pending row shows a warning badge
    And a pvc without a phase shows "—"

  Scenario: pvc-list-empty-state
    # edge — R4
    Given the pvc list is empty
    When the user opens /storage/pvc
    Then the table shows "No persistent volume claims found"

  Scenario: pvc-list-no-cluster
    # edge — R4
    Given no cluster is selected
    When the user opens /storage/pvc
    Then the table shows "No cluster selected."
    And no fetch is made

  # ---------------------------------------------------- frontend: data (R5)

  Scenario: pvc-data-renders-detail
    # happy path — R5
    Given the cluster is selected
    When the user opens /storage/pvc/data?name=data-pvc&namespace=team-a
    Then exactly one fetch is made with name=data-pvc and namespace=team-a
    And the table shows the status, name, namespace, created, access mode, volume mode, capacity, storage class, and bound volume
    And the labels and annotations sub-tables render
    And the full object is rendered as a JSON-highlighted block

  Scenario: pvc-data-missing-optional-fields
    # edge — R5 (certainty rule: absent keys render "—", never crash)
    Given a pvc without volume_name, capacity, or phase
    When the user opens /storage/pvc/data?name=data-pvc&namespace=team-a
    Then the Persistent Volume, Capacity, and Status rows are "—"

  Scenario: pvc-data-not-found-state
    # edge — R5 (a miss is a state, not an error)
    Given the named pvc does not exist in the namespace
    When the user opens /storage/pvc/data?name=ghost&namespace=team-a
    Then the page shows "No PVC 'ghost' found"
    And the page does not show an error style for the miss

  Scenario: pvc-data-missing-name
    # edge — R5
    When the user opens /storage/pvc/data?namespace=team-a
    Then the page shows "Error: pvc name not provided"

  # ------------------------------------------------- routing (R6)

  Scenario: pvc-stub-removed-and-routes-wired
    # happy path — R6
    Given the pvc views are built
    Then /storage/pvc is not in the stub route list
    And /storage/pvc/data is not a nav entry
    And the _nav.tsx leaf is byte-identical to before the change
