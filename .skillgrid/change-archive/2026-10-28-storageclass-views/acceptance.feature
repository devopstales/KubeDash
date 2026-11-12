Feature: StorageClass views (list + data, cluster-scoped)
  # briefing.md R1-R5. The load-bearing theme: the 4.1 StorageClass pages
  # (list: name/default/reclaim-policy/binding-mode; data: metadata + reclaim
  # policy + binding mode + provisioner + parameters) are ported to 5.0 as a
  # real, SAR-gated, read-only list + data pair under Storage (ADR-0022) —
  # cluster-scoped core kind (storage/v1), with the ratified 5.0 deltas
  # (?name= param, JSON block, Volume Binding Mode label consistency).

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user

  # --------------------------------------------------------- API: list (R1)

  Scenario: storageclasses-list-200
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/storageclasses
    Then the response is 200
    And the body kind is storageclasses
    And the body cluster is the bound cluster name
    And every item is in to_dict snake_case form

  Scenario: storageclasses-list-ignores-namespace
    # edge — R1 (cluster-scoped: ?namespace= is accepted and ignored)
    When a bound user requests GET /api/v1/clusters/1/resources/storageclasses?namespace=team-a
    Then the response is 200
    And the K8s client used the cluster-scoped list call

  Scenario: storageclasses-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on storageclasses (storage.k8s.io) denies
    # (2026-11-05 review fix: the original "(core)" was a group error —
    # a core-group SAR never matches a storage.k8s.io grant)
    When a bound user requests GET /api/v1/clusters/1/resources/storageclasses
    Then the response is 403 RBAC_DENIED naming the storageclasses resource
    And the K8s client list call was never made

  Scenario: storageclasses-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/storageclasses
    Then the response is 404

  Scenario: storageclass-kind-singular-rejected
    # edge — R1 (the 4.1 route name was singular; the API kind is plural)
    When a bound user requests GET /api/v1/clusters/1/resources/storageclass
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: storageclasses-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/storageclasses?name=csi-fast
    Then the response is 200 with a one-item list containing the named class
    When a bound user requests GET /api/v1/clusters/1/resources/storageclasses?name=ghost
    Then the response is 200 with an empty items list

  # ---------------------------------------------------- frontend: list (R3)

  Scenario: storage-class-list-renders-rows-with-data-links
    # happy path — R3
    Given the cluster is selected
    When the /storage/storage-class view loads
    Then the card title is exactly Storage Classes List
    And the table shows Name, Default, Reclaim Policy and Volume Binding Mode columns
    And the fetch URL is /api/v1/clusters/1/resources/storageclasses
    And each storage class name links to /storage/storage-class/data?name=<name>

  Scenario: storage-class-list-default-policy-binding-cells
    # happy path — R3
    Given a storage class with the is-default-class annotation true, reclaimPolicy Delete and volumeBindingMode WaitForFirstConsumer
    When the /storage/storage-class view loads
    Then the Default cell shows true
    And the Reclaim Policy cell shows Delete
    And the Volume Binding Mode cell shows WaitForFirstConsumer

  Scenario: storage-class-list-missing-fields
    # edge — R3 (absent annotation / policy / binding mode render em dash)
    Given a storage class with no is-default-class annotation, no reclaimPolicy and no volumeBindingMode
    When the /storage/storage-class view loads
    Then the Default, Reclaim Policy and Volume Binding Mode cells all show —

  Scenario: storage-class-list-empty-state
    # edge — R3
    Given the cluster has no storage classes
    When the /storage/storage-class view loads
    Then the view shows No storage classes found

  # ------------------------------------------------ frontend: data (R4)

  Scenario: storage-class-data-renders-detail
    # happy path — R4
    Given the cluster is selected
    When the /storage/storage-class/data?name=csi-fast view loads
    Then the view issues a single GET with ?name=csi-fast
    And the CTable shows Name, Created, Reclaim Policy, Volume Binding Mode, Provisioner, Labels and Annotations
    And the Parameters table has a row per parameters entry
    And the full object is rendered as a JSON-highlighted block

  Scenario: storage-class-data-missing-parameters
    # edge — R4
    Given a storage class with no parameters
    When the /storage/storage-class/data?name=csi-fast view loads
    Then the view shows No parameters

  Scenario: storage-class-data-not-found-state
    # edge — R4 (a miss is a state, not an error)
    Given the cluster has no storage class named ghost
    When the /storage/storage-class/data?name=ghost view loads
    Then the view shows No StorageClass 'ghost' found
    And no error styling is shown

  Scenario: storage-class-data-missing-name
    # edge — R4
    When the /storage/storage-class/data view loads without a name parameter
    Then the view shows Error: storage class name not provided

  # ------------------------------------------------ routing (R5)

  Scenario: storage-class-stub-removed-and-routes-wired
    # happy path — R5
    When the SPA builds
    Then /storage/storage-class renders the StorageClass list view
    And /storage/storage-class/data renders the StorageClass data view
    And /storage/storage-class is absent from the stub route list
    And the StorageClass nav leaf is unchanged
