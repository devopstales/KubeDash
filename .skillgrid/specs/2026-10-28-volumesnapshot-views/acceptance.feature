Feature: VolumeSnapshot views (list + data, namespaced CRD)
  # briefing.md R1-R5. The load-bearing theme: the 4.1 VolumeSnapshot list
  # (list: usable/name/snapshot-class/pvc/restore-size — a namespaced CRD,
  # volumesnapshots.snapshot.storage.k8s.io, with a hardcoded v1, a hardcoded
  # all-namespaces read, and a deep-index KeyError-500) is ported to 5.0 as a
  # real, SAR-gated, read-only list + data pair under Storage (ADR-0022), via
  # the Cilium full-custom-object seam (get_crd_served version + scope
  # authority, CRD-absent -> empty), with the ratified 5.0 deltas
  # (?name=&namespace= params, the NEW data page resolving 4.1's commented-out
  # dead link, the header-selected namespace, JSON block, "—" certainty rule).

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user
    And the VolumeSnapshot CRD is installed and served

  # --------------------------------------------------------- API: list (R1)

  Scenario: volumesnapshots-list-200-in-namespace
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshots?namespace=team-a
    Then the response is 200
    And the body kind is volumesnapshots
    And the body cluster is the bound cluster name
    And every item is a full custom object with spec and status intact
    And the K8s client read namespace team-a

  Scenario: volumesnapshots-list-honors-namespace
    # happy path — R1 (namespaced CRD: the namespace is forwarded, not ignored)
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshots?namespace=team-a
    Then the K8s client used the namespaced custom-object list call

  Scenario: volumesnapshots-list-all-namespaces-without-param
    # edge — R1 (the all-namespaces branch, kept for the API; the page always sends a namespace)
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshots
    Then the response is 200
    And the K8s client used the cluster-scoped custom-object list call

  Scenario: volumesnapshots-crd-absent-is-empty
    # edge — R1 (the snapshot operator is optional; absence is a state, not an error)
    Given the VolumeSnapshot CRD is absent
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshots?namespace=team-a
    Then the response is 200
    And the body items is an empty list

  Scenario: volumesnapshots-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on volumesnapshots (snapshot.storage.k8s.io, namespace team-a) denies
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshots?namespace=team-a
    Then the response is 403 RBAC_DENIED naming the volumesnapshots resource
    And the K8s client list call was never made

  Scenario: volumesnapshots-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/volumesnapshots?namespace=team-a
    Then the response is 404

  Scenario: volumesnapshot-kind-singular-rejected
    # edge — R1 (the API kind is the plural)
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshot
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: volumesnapshots-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshots?name=snap-a&namespace=team-a
    Then the response is 200 with a one-item list containing the named full object
    When a bound user requests GET /api/v1/clusters/1/resources/volumesnapshots?name=ghost&namespace=team-a
    Then the response is 200 with an empty items list

  # ---------------------------------------------------- frontend: list (R3)

  Scenario: volumesnapshot-list-renders-rows-with-data-links
    # happy path — R3 (the header-selected namespace; the list is the sole producer of the data-page query strings)
    Given the cluster is selected in namespace team-a
    When the /storage/volumesnapshot view loads
    Then the card title is exactly Volume Snapshot List
    And the table shows Name, Usable, SnapshotClass, VolumeClaim and Restore Size columns
    And the fetch URL is /api/v1/clusters/1/resources/volumesnapshots?namespace=team-a
    And each snapshot name links to /storage/volumesnapshot/data?name=<name>&namespace=<namespace>

  Scenario: volumesnapshot-list-ready-class-pvc-cells
    # happy path — R3
    Given a snapshot with readyToUse true, volumeSnapshotClassName csi-snap, source persistentVolumeClaimName pvc-snap-a and restoreSize 1Gi
    When the /storage/volumesnapshot view loads
    Then the Usable cell shows a Ready success badge
    And the SnapshotClass cell shows csi-snap
    And the VolumeClaim cell shows pvc-snap-a
    And the Restore Size cell shows 1Gi

  Scenario: volumesnapshot-list-missing-fields
    # edge — R3 (a SourceMode-less snapshot: 4.1's deep-index 500 renders "—")
    Given a snapshot with no persistentVolumeClaimName, no volumeSnapshotClassName and no status
    When the /storage/volumesnapshot view loads
    Then the Usable, SnapshotClass, VolumeClaim and Restore Size cells all show —
    And the row renders without an error

  Scenario: volumesnapshot-list-empty-state
    # edge — R3 (also the CRD-absent state)
    Given the cluster has no volume snapshots in namespace team-a
    When the /storage/volumesnapshot view loads
    Then the view shows No volume snapshots found

  Scenario: volumesnapshot-list-no-cluster-state
    # edge — R3
    When the /storage/volumesnapshot view loads without a selected cluster
    Then the view shows No cluster selected.
    And no fetch is made

  # ------------------------------------------------ frontend: data (R4)

  Scenario: volumesnapshot-data-renders-detail
    # happy path — R4 (single ?name=&namespace= fetch; 4.1 had no data page)
    Given the cluster is selected
    When the /storage/volumesnapshot/data?name=snap-a&namespace=team-a view loads
    Then the view issues a single GET with ?name=snap-a&namespace=team-a
    And the CTable shows Name, Created, Source, SnapshotClass, Ready To Use, Restore Size, Bound Content, Labels and Annotations
    And the full object is rendered as a JSON-highlighted block

  Scenario: volumesnapshot-data-missing-fields
    # edge — R4 (absent keys render em dash, never crash)
    Given a snapshot with no persistentVolumeClaimName, no volumeSnapshotClassName and no status
    When the /storage/volumesnapshot/data?name=snap-a&namespace=team-a view loads
    Then the Source, SnapshotClass, Ready To Use, Restore Size and Bound Content rows all show —

  Scenario: volumesnapshot-data-not-found-state
    # edge — R4 (a miss is a state, not an error)
    Given the cluster has no snapshot named ghost in namespace team-a
    When the /storage/volumesnapshot/data?name=ghost&namespace=team-a view loads
    Then the view shows No VolumeSnapshot 'ghost' found
    And no error styling is shown

  Scenario: volumesnapshot-data-missing-name
    # edge — R4
    When the /storage/volumesnapshot/data view loads without a name parameter
    Then the view shows Error: volume snapshot name not provided

  # ------------------------------------------------ routing (R5)

  Scenario: volumesnapshot-stub-removed-and-routes-wired
    # happy path — R5
    When the SPA builds
    Then /storage/volumesnapshot renders the VolumeSnapshot list view
    And /storage/volumesnapshot/data renders the VolumeSnapshot data view
    And /storage/volumesnapshot is absent from the stub route list
    And the VolumeSnapshot nav leaf is unchanged
