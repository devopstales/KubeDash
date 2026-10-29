Feature: ConfigMap views (list + data, namespaced)
  # briefing.md R1-R5. The load-bearing theme: the 4.1 ConfigMap pages
  # (list: name/created; data: metadata + per-key data table) are ported to
  # 5.0 as a real, SAR-gated, read-only list + data pair under Storage
  # (ADR-0022) — a namespaced core kind (core v1), with the ratified 5.0
  # deltas (?name=&namespace= params, the Data Keys list column, the JSON
  # block, and the plain <pre><code> per-key value — no base64 decode, no
  # language detection).

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user

  # --------------------------------------------------------- API: list (R1)

  Scenario: configmaps-list-200
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/configmaps?namespace=team-a
    Then the response is 200
    And the body kind is configmaps
    And the body cluster is the bound cluster name
    And every item is in to_dict snake_case form
    And the first item's data field is present (NOT stripped, unlike secrets)

  Scenario: configmaps-list-all-namespaces
    # edge — R1 (no ?namespace= -> the all-namespaces branch, the list_secrets pattern)
    When a bound user requests GET /api/v1/clusters/1/resources/configmaps
    Then the response is 200
    And the K8s client used the all-namespaces list call

  Scenario: configmaps-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on configmaps (core, namespace team-a) denies
    When a bound user requests GET /api/v1/clusters/1/resources/configmaps?namespace=team-a
    Then the response is 403 RBAC_DENIED naming the configmaps resource
    And the K8s client list call was never made

  Scenario: configmaps-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/configmaps?namespace=team-a
    Then the response is 404

  Scenario: configmap-kind-singular-rejected
    # edge — R1 (the 4.1 route name was singular; the API kind is plural)
    When a bound user requests GET /api/v1/clusters/1/resources/configmap
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: configmaps-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/configmaps?name=app-config&namespace=team-a
    Then the response is 200 with a one-item list containing the named configmap
    And the item's data field is present
    When a bound user requests GET /api/v1/clusters/1/resources/configmaps?name=ghost&namespace=team-a
    Then the response is 200 with an empty items list

  # ---------------------------------------------------- frontend: list (R3)

  Scenario: configmap-list-renders-rows-with-data-links
    # happy path — R3
    Given the cluster is selected
    And the selected namespace is team-a
    When the user opens /storage/configmap
    Then the card title is EXACTLY "Configmaps List"
    And the fetch URL has namespace=team-a
    And every configmap name links to /storage/configmap/data?name=<name>&namespace=team-a
    And the columns are Name, Data Keys, Created

  Scenario: configmap-list-data-keys-column
    # happy path — R3 (the one ratified addition over 4.1's Name/Created-only list)
    Given a configmap with 2 data keys, one with an empty data object, and one with no data field
    When the user opens /storage/configmap
    Then the 2-key configmap row Data Keys is "2"
    And the empty-data configmap row Data Keys is "0"
    And the no-data configmap row Data Keys is "—"

  Scenario: configmap-list-never-counts-binarydata
    # edge — R3 (the count is data-only, not binaryData)
    Given a configmap with only binaryData (no data field)
    When the user opens /storage/configmap
    Then that configmap row Data Keys is "—"

  Scenario: configmap-list-empty-state
    # edge — R3
    Given the configmap list is empty
    When the user opens /storage/configmap
    Then the table shows "No configmaps found"

  Scenario: configmap-list-no-cluster
    # edge — R3
    Given no cluster is selected
    When the user opens /storage/configmap
    Then the table shows "No cluster selected."
    And no fetch is made

  # ---------------------------------------------------- frontend: data (R4)

  Scenario: configmap-data-renders-detail
    # happy path — R4
    Given the cluster is selected
    When the user opens /storage/configmap/data?name=app-config&namespace=team-a
    Then exactly one fetch is made with name=app-config and namespace=team-a
    And the table shows the name, namespace, kind, created, and version rows
    And the kind row is "ConfigMap"
    And the labels and annotations sub-tables render
    And the annotations sub-table includes last-applied-configuration (verbatim, NOT trimmed)
    And the data table renders one row per data entry
    And the full object is rendered as a JSON-highlighted block

  Scenario: configmap-data-value-is-plain-pre
    # happy path — R4 (no base64 decode, no language detection, no eye toggle)
    Given the named configmap has a data entry
    When the user opens /storage/configmap/data?name=app-config&namespace=team-a
    Then the data value is rendered in a pre > code block
    And the data value is NOT base64-decoded (rendered verbatim)
    And there is no eye or lock icon for the data value

  Scenario: configmap-data-missing-data
    # edge — R4 (no data field -> "No data", not an error)
    Given the named configmap has no data field
    When the user opens /storage/configmap/data?name=no-data-cm&namespace=team-a
    Then the data section shows "No data"

  Scenario: configmap-data-not-found-state
    # edge — R4 (a miss is a state, not an error)
    Given the named configmap does not exist in the namespace
    When the user opens /storage/configmap/data?name=ghost&namespace=team-a
    Then the page shows "No ConfigMap 'ghost' found"
    And the page does not show an error style for the miss

  Scenario: configmap-data-missing-name
    # edge — R4
    When the user opens /storage/configmap/data?namespace=team-a
    Then the page shows "Error: configmap name not provided"

  # ------------------------------------------------- routing (R5)

  Scenario: configmap-stub-removed-and-routes-wired
    # happy path — R5
    Given the configmap views are built
    Then /storage/configmap is not in the stub route list
    And /storage/configmap/data is not a nav entry
    And the _nav.tsx leaf is byte-identical to before the change
