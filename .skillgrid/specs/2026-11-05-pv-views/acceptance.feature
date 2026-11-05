Feature: PV views (list + data, cluster-scoped, claim-namespace filtered)
  # briefing.md. The 4.1 PV pages (list: status/name/storage-class/
  # volume-claim/capacity; data: metadata + claim + csi/hostpath + volume
  # attributes) are ported to 5.0 as a real, SAR-gated, read-only list +
  # data pair under Storage (ADR-0022) — cluster-scoped core kind (v1),
  # with the 4.1 bugs fixed (hostPath visibility, unbound-PV crash), the
  # ADR-0040 object-ref navigation, and the trimAnnotations companion fix.

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user

  # --------------------------------------------------------- API: list (T1)

  Scenario: persistentvolumes-list-200
    # happy path — T1
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumes
    Then the response is 200
    And the body kind is persistentvolumes
    And every item is in to_dict snake_case form

  Scenario: persistentvolumes-claim-namespace-filter
    # happy path — T1 (4.1 parity: the list is filtered to the selected
    # namespace via claim_ref; free PVs are always visible)
    Given the cluster has a PV bound in team-a, a PV bound in team-b and a free PV
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumes?namespace=team-a
    Then the response is 200 with the team-a PV and the free PV, without the team-b PV

  Scenario: persistentvolumes-sar-denied
    # failure — T1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on persistentvolumes (core) denies
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumes
    Then the response is 403 RBAC_DENIED naming the persistentvolumes resource
    And the K8s client list call was never made

  Scenario: persistentvolumes-binding-404
    # edge — T1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/persistentvolumes
    Then the response is 404

  # ------------------------------------------------- API: name lookup (T1)

  Scenario: persistentvolumes-get-by-name
    # happy path — T1 (single read; the kind is cluster-scoped)
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumes?name=pv-1
    Then the response is 200 with a one-item list containing the named volume
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumes?name=ghost
    Then the response is 200 with an empty items list
    Given the SAR check for get on persistentvolumes (core) denies
    When a bound user requests GET /api/v1/clusters/1/resources/persistentvolumes?name=pv-1
    Then the response is 403 RBAC_DENIED naming the persistentvolumes resource

  # ---------------------------------------------------- frontend: list (T3)

  Scenario: pv-list-renders-rows-with-object-refs
    # happy path — T3
    Given the cluster is selected
    When the /storage/pv view loads
    Then the card title is exactly Persistent Volume List
    And the table shows Status, Name, StorageClass, VolumeClaim and Capacity columns
    And the bound PV row shows a success Bound badge
    And the PV name cell opens the pv object ref (no namespace)
    And the StorageClass cell opens the storageclass object ref
    And the VolumeClaim cell opens the pvc object ref carrying the claim namespace

  Scenario: pv-list-terminating-override
    # edge — T3 (4.1: deletion_timestamp flips the badge to Terminating/danger)
    Given a PV with a deletion timestamp
    When the /storage/pv view loads
    Then the row shows a danger Terminating badge

  Scenario: pv-list-free-pv-dashes
    # edge — T3 (certainty rule: absent optional values render —)
    Given a free PV without storage class
    When the /storage/pv view loads
    Then the VolumeClaim cell shows — and the StorageClass cell shows —

  # ---------------------------------------------------- frontend: data (T4)

  Scenario: pv-data-renders-4-1-rows
    # happy path — T4
    Given the pv object ref is active for pv-1
    When the /storage/pv view renders the detail
    Then the breadcrumb is Storage > PV > pv-1
    And the rows show Status, Name, Created, Annotations, Labels, StorageClass,
      Persistent Volume Claim, PVC Namespace, Access Mode, Volume Mode,
      Reclaim Policy and Capacity
    And the Persistent Volume Claim cell opens the pvc object ref
    And the JSON block renders the full to_dict object

  Scenario: pv-data-hostpath-vs-csi
    # edge — T4 (4.1 XOR: Local Path row only for hostPath PVs;
    # CSI Driver + Filesystem Type + Volume Attributes only for CSI PVs)
    Given a hostPath PV
    When the pv data view renders
    Then the Local Path row is shown and no CSI rows are shown
    Given a CSI PV with volume attributes
    When the pv data view renders
    Then the CSI Driver and Filesystem Type rows and the Volume Attributes table
      are shown and no Local Path row is shown

  Scenario: pv-data-not-found-is-state
    # edge — T4 (empty items is a not-found STATE, not an error)
    Given the pv object ref is active for a deleted pv
    When the pv data view loads
    Then the not-found state renders (no error banner)

  # ------------------------------------- companion fix: annotations (T2)

  Scenario: storage-data-annotations-trim-last-applied
    # user decision 2026-11-05 — 4.1's trimAnnotations, replicated
    Given a storage object whose annotations include kubectl.kubernetes.io/last-applied-configuration
    When any of the five storage data views renders (StorageClass, SnapshotClass,
      VolumeSnapshot, Pvc, ConfigMap) or the pv data view renders
    Then the annotations table omits kubectl.kubernetes.io/last-applied-configuration
      and autoscaling.alpha.kubernetes.io/conditions
    And the JSON block still contains the full annotations map

  # ---------------------------------------------------------- wiring (T5)

  Scenario: pv-stub-removed-real-route
    # happy path — T5
    When the /storage/pv route is visited
    Then the Stub view does not render (the route is a real ObjectRoute)
    And the e2e smoke asserts /storage/pv as a REAL route with the exact title
    And /storage/pv is no longer in Stub/routes.ts and is in the Stub.test
      viewPaths exclusion set
