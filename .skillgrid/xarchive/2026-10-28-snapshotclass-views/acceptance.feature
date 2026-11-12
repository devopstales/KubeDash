Feature: SnapshotClass views (list + data, cluster-scoped CRD)
  # briefing.md R1-R5. The load-bearing theme: the 4.1 SnapshotClass pages
  # (list: name/default/deletion-policy/driver; data: metadata + deletion
  # policy + driver + parameters) are a cluster-scoped CRD
  # (volumesnapshotclasses.snapshot.storage.k8s.io) ported to 5.0 via the
  # Cilium full-custom-object seam (get_crd_served version authority,
  # CRD-absent -> empty) as a real, SAR-gated, read-only list + data pair
  # under Storage (ADR-0022), with the ratified 5.0 deltas (?name= param,
  # JSON block, version resolution, cluster-scoped getter).

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user
    And the VolumeSnapshotClass CRD is installed and served

  # --------------------------------------------------------- API: list (R1)

  Scenario: volumesnapshotclasses-list-200
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshotclasses
    Then the response is 200
    And the body kind is volumesnapshotclasses
    And the body cluster is the bound cluster name
    And every item is a full custom object with driver, deletionPolicy and parameters intact

  Scenario: volumesnapshotclasses-list-ignores-namespace
    # edge — R1 (cluster-scoped: ?namespace= is accepted and ignored)
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshotclasses?namespace=team-a
    Then the response is 200
    And the K8s client used the cluster-scoped custom-object list call

  Scenario: volumesnapshotclasses-crd-absent-is-empty
    # edge — R1 (the snapshot operator is optional; absence is a state, not an error)
    Given the VolumeSnapshotClass CRD is absent
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshotclasses
    Then the response is 200
    And the body items is an empty list

  Scenario: volumesnapshotclasses-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on volumesnapshotclasses (snapshot.storage.k8s.io) denies
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshotclasses
    Then the response is 403 RBAC_DENIED naming the volumesnapshotclasses resource
    And the K8s client list call was never made

  Scenario: volumesnapshotclasses-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/volumesnapshotclasses
    Then the response is 404

  Scenario: volumesnapshotclass-kind-singular-rejected
    # edge — R1 (the API kind is the plural)
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshotclass
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: volumesnapshotclasses-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshotclasses?name=csi-snap
    Then the response is 200 with a one-item list containing the named full object
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshotclasses?name=ghost
    Then the response is 200 with an empty items list

  # ---------------------------------------------------- frontend: list (R3)

  Scenario: snapshot-class-list-renders-rows-with-data-links
    # happy path — R3
    Given the cluster is selected
    When the /storage/snapshot-class view loads
    Then the card title is exactly Snapshot Classes List
    And the table shows Name, Default, Deletion Policy and Driver columns
    And the fetch URL is /api/v1/clusters/1/resources/volumesnapshotclasses
    And each snapshot class name links to /storage/snapshot-class/data?name=<name>

  Scenario: snapshot-class-list-default-policy-driver-cells
    # happy path — R3
    Given a snapshot class with the is-default-class annotation true, deletionPolicy Delete and driver csi.example.com
    When the /storage/snapshot-class view loads
    Then the Default cell shows true
    And the Deletion Policy cell shows Delete
    And the Driver cell shows csi.example.com

  Scenario: snapshot-class-list-missing-fields
    # edge — R3 (absent annotation / policy / driver render em dash)
    Given a snapshot class with no is-default-class annotation, no deletionPolicy and no driver
    When the /storage/snapshot-class view loads
    Then the Default, Deletion Policy and Driver cells all show —

  Scenario: snapshot-class-list-empty-state
    # edge — R3 (also the CRD-absent state)
    Given the cluster has no snapshot classes
    When the /storage/snapshot-class view loads
    Then the view shows No snapshot classes found

  # ------------------------------------------------ frontend: data (R4)

  Scenario: snapshot-class-data-renders-detail
    # happy path — R4
    Given the cluster is selected
    When the /storage/snapshot-class/data?name=csi-snap view loads
    Then the view issues a single GET with ?name=csi-snap
    And the CTable shows Name, Created, Deletion Policy, Driver, Labels and Annotations
    And the Parameters table has a row per parameters entry
    And the full object is rendered as a JSON-highlighted block

  Scenario: snapshot-class-data-missing-parameters
    # edge — R4
    Given a snapshot class with no parameters
    When the /storage/snapshot-class/data?name=csi-snap view loads
    Then the view shows No parameters

  Scenario: snapshot-class-data-not-found-state
    # edge — R4 (a miss is a state, not an error)
    Given the cluster has no snapshot class named ghost
    When the /storage/snapshot-class/data?name=ghost view loads
    Then the view shows No VolumeSnapshotClass 'ghost' found
    And no error styling is shown

  Scenario: snapshot-class-data-missing-name
    # edge — R4
    When the /storage/snapshot-class/data view loads without a name parameter
    Then the view shows Error: snapshot class name not provided

  # ------------------------------------------------ routing (R5)

  Scenario: snapshot-class-stub-removed-and-routes-wired
    # happy path — R5
    When the SPA builds
    Then /storage/snapshot-class renders the SnapshotClass list view
    And /storage/snapshot-class/data renders the SnapshotClass data view
    And /storage/snapshot-class is absent from the stub route list
    And the SnapshotClass nav leaf is unchanged
