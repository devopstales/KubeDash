@views @statefulsets-daemonsets-replicasets
Feature: StatefulSets + DaemonSets + ReplicaSets Views (List + Data)

  As a user of the KubeDash dashboard
  I want StatefulSet, DaemonSet and ReplicaSet list + data views
  So that I can inspect these workloads and their pod-template details per namespace

  Background:
    Given the "prod" cluster is selected
    And the namespace "team-a" is selected
    And the user is bound to the "prod" cluster
    And the user has RBAC permission for the resource

  # ── StatefulSets list ────────────────────────────────────────────────────

  @statefulsets
  Scenario: The statefulsets list resolves at /workload/statefulsets
    When I open /workload/statefulsets
    Then the page shows a table titled "Statefulset List"
    And the columns are "Name", "Desired", "Current", "Ready" and "Created"
    And the Desired cell shows status.replicas or 0
    And the Current cell shows status.current_replicas or 0
    And the Ready cell shows status.ready_replicas or 0
    And the Created cell shows the creation timestamp

  @statefulsets
  Scenario: The statefulsets list name links carry the namespace
    When the statefulsets list shows an item named "db"
    Then the "db" Name cell links to /workload/statefulsets/data?name=db&namespace=team-a

  @statefulsets
  Scenario: The statefulsets list empty state
    When the namespace has no statefulsets
    And I open /workload/statefulsets
    Then the page shows "No statefulsets found"

  @statefulsets
  Scenario: The statefulsets list no-cluster state
    Given no cluster is selected
    When I open /workload/statefulsets
    Then the page shows "No cluster selected."

  # ── StatefulSet data ─────────────────────────────────────────────────────

  @statefulset-data
  Scenario: The statefulset data page shows the five tabs + JSON (title bug fixed)
    When I open /workload/statefulsets/data?name=db&namespace=team-a
    Then the page shows a card titled "StatefulSet Data"
    And the page shows tabs "StatefulSet", "Containers", "Variables", "Security Contexts" and "Related Resources"
    And the StatefulSet tab shows "Namespace", "Name", "Created", "Replicas", "Annotations", "Labels" and "Selectors"
    And the Replicas row shows spec.replicas as plain text (no spinner)
    And the page shows a full-object JSON block

  @statefulset-data
  Scenario: The statefulset data page Related Resources deep-links secrets only
    Given a statefulset "db" with a volume secret "db-creds" and a configmap "app-cfg"
    When I open /workload/statefulsets/data?name=db&namespace=team-a
    Then the "db-creds" Secret row links to /security/secret/data?name=db-creds&namespace=team-a
    And the "app-cfg" Configmap row is plain text (no link)

  @statefulset-data
  Scenario: The statefulset data page not-found state
    When I open /workload/statefulsets/data?name=missing&namespace=team-a
    Then the page shows "No statefulset 'missing' found"
    And the message is not styled as an error

  @statefulset-data
  Scenario: The statefulset data page missing name
    When I open /workload/statefulsets/data?namespace=team-a
    Then the page shows "Error: statefulset name not provided"

  # ── StatefulSets API (SAR) ───────────────────────────────────────────────

  @statefulsets-api
  Scenario: The statefulsets list is SAR-gated on list in the namespace
    When I send GET /api/v1/clusters/prod/resources/statefulsets?namespace=team-a
    Then the response status is 200
    And the response body kind is "statefulsets"
    And the SAR was asked for "list" on "statefulsets" in group "apps" with namespace "team-a"

  @statefulsets-api
  Scenario: The statefulsets get-by-name returns 0 or 1 item
    Given a statefulset "db" in namespace "team-a"
    When I send GET /api/v1/clusters/prod/resources/statefulsets?namespace=team-a&name=db
    Then the response status is 200
    And the response body items length is 1
    When I send GET /api/v1/clusters/prod/resources/statefulsets?namespace=team-a&name=missing
    Then the response body items length is 0

  @statefulsets-api
  Scenario: The statefulsets list denies SAR
    Given the user lacks "list" on "statefulsets" in namespace "team-a"
    When I send GET /api/v1/clusters/prod/resources/statefulsets?namespace=team-a
    Then the response status is 403
    And the error code is "RBAC_DENIED"
    And the statefulsets list client call was not made

  @statefulsets-api
  Scenario: The statefulsets list is 404 when unbound
    Given the user is not bound to the "prod" cluster
    When I send GET /api/v1/clusters/prod/resources/statefulsets?namespace=team-a
    Then the response status is 404

  @statefulsets-api
  Scenario: The singular statefulset kind is rejected
    When I send GET /api/v1/clusters/prod/resources/statefulset?namespace=team-a
    Then the response status is 400
    And the error code is "RESOURCE_KIND_NOT_SUPPORTED"

  # ── DaemonSets list ──────────────────────────────────────────────────────

  @daemonsets
  Scenario: The daemonsets list resolves at /workload/daemonsets
    When I open /workload/daemonsets
    Then the page shows a table titled "DaemonSet List"
    And the columns are "Name", "Desired", "Current", "Ready" and "Created"
    And the Desired cell shows status.desired_number_scheduled or 0
    And the Current cell shows status.current_number_scheduled or 0
    And the Ready cell shows status.number_ready or 0

  @daemonsets
  Scenario: The daemonsets list name links carry the namespace
    When the daemonsets list shows an item named "fluentd"
    Then the "fluentd" Name cell links to /workload/daemonsets/data?name=fluentd&namespace=team-a

  @daemonsets
  Scenario: The daemonsets list empty state
    When the namespace has no daemonsets
    And I open /workload/daemonsets
    Then the page shows "No daemonsets found"

  # ── DaemonSet data ───────────────────────────────────────────────────────

  @daemonset-data
  Scenario: The daemonset data page shows the five tabs + JSON (title bug fixed)
    When I open /workload/daemonsets/data?name=fluentd&namespace=team-a
    Then the page shows a card titled "DaemonSet Data"
    And the page shows tabs "DaemonSet", "Containers", "Variables", "Security Contexts" and "Related Resources"
    And the DaemonSet tab shows "Namespace", "Name", "Created", "Desired", "Annotations", "Labels" and "Selectors"
    And the Desired row shows status.desired_number_scheduled as plain text (no spinner)
    And the page shows a full-object JSON block

  @daemonset-data
  Scenario: The daemonset data page not-found state
    When I open /workload/daemonsets/data?name=missing&namespace=team-a
    Then the page shows "No daemonset 'missing' found"
    And the message is not styled as an error

  @daemonset-data
  Scenario: The daemonset data page missing name
    When I open /workload/daemonsets/data?namespace=team-a
    Then the page shows "Error: daemonset name not provided"

  # ── DaemonSets API (SAR) ─────────────────────────────────────────────────

  @daemonsets-api
  Scenario: The daemonsets list is SAR-gated on list in the namespace
    When I send GET /api/v1/clusters/prod/resources/daemonsets?namespace=team-a
    Then the response status is 200
    And the response body kind is "daemonsets"
    And the SAR was asked for "list" on "daemonsets" in group "apps" with namespace "team-a"

  @daemonsets-api
  Scenario: The daemonsets get-by-name returns 0 or 1 item
    Given a daemonset "fluentd" in namespace "team-a"
    When I send GET /api/v1/clusters/prod/resources/daemonsets?namespace=team-a&name=fluentd
    Then the response body items length is 1
    When I send GET /api/v1/clusters/prod/resources/daemonsets?namespace=team-a&name=missing
    Then the response body items length is 0

  @daemonsets-api
  Scenario: The daemonsets list denies SAR
    Given the user lacks "list" on "daemonsets" in namespace "team-a"
    When I send GET /api/v1/clusters/prod/resources/daemonsets?namespace=team-a
    Then the response status is 403
    And the error code is "RBAC_DENIED"
    And the daemonsets list client call was not made

  @daemonsets-api
  Scenario: The singular daemonset kind is rejected
    When I send GET /api/v1/clusters/prod/resources/daemonset?namespace=team-a
    Then the response status is 400
    And the error code is "RESOURCE_KIND_NOT_SUPPORTED"

  # ── ReplicaSets list ─────────────────────────────────────────────────────

  @replicasets
  Scenario: The replicasets list resolves at /workload/replicasets
    When I open /workload/replicasets
    Then the page shows a table titled "ReplicaSet List"
    And the columns are "Name", "Desired", "Current", "Ready" and "Owner"
    And the Desired cell shows status.fully_labeled_replicas or 0
    And the Current cell shows status.available_replicas or 0
    And the Ready cell shows status.ready_replicas or 0
    And the Owner cell shows the owner kind/name or "—"

  @replicasets
  Scenario: The replicasets list owner is plain text (deployments view not landed)
    Given a replicaset "web-abc123" owned by Deployment "web"
    When I open /workload/replicasets
    Then the "web-abc123" Owner cell shows "deployment/web" as plain text (no link, the deployments view is not yet landed)

  @replicasets
  Scenario: The replicasets list name links are added (5.0 addition)
    When the replicasets list shows an item named "web-abc123"
    Then the "web-abc123" Name cell links to /workload/replicasets/data?name=web-abc123&namespace=team-a

  @replicasets
  Scenario: The replicasets list empty state
    When the namespace has no replicasets
    And I open /workload/replicasets
    Then the page shows "No replicasets found"

  # ── ReplicaSet data (5.0 addition) ───────────────────────────────────────

  @replicaset-data
  Scenario: The replicaset data page shows the five tabs + JSON (5.0 addition)
    When I open /workload/replicasets/data?name=web-abc123&namespace=team-a
    Then the page shows a card titled "ReplicaSet Data"
    And the page shows tabs "ReplicaSet", "Containers", "Variables", "Security Contexts" and "Related Resources"
    And the ReplicaSet tab shows "Namespace", "Name", "Created", "Desired", "Owner", "Annotations", "Labels" and "Selectors"
    And the Desired row shows status.fully_labeled_replicas as plain text
    And the Owner row shows the owner kind/name as plain text
    And the page shows a full-object JSON block

  @replicaset-data
  Scenario: The replicaset data page not-found state
    When I open /workload/replicasets/data?name=missing&namespace=team-a
    Then the page shows "No replicaset 'missing' found"
    And the message is not styled as an error

  @replicaset-data
  Scenario: The replicaset data page missing name
    When I open /workload/replicasets/data?namespace=team-a
    Then the page shows "Error: replicaset name not provided"

  # ── ReplicaSets API (SAR) ────────────────────────────────────────────────

  @replicasets-api
  Scenario: The replicasets list is SAR-gated on list in the namespace
    When I send GET /api/v1/clusters/prod/resources/replicasets?namespace=team-a
    Then the response status is 200
    And the response body kind is "replicasets"
    And the SAR was asked for "list" on "replicasets" in group "apps" with namespace "team-a"

  @replicasets-api
  Scenario: The replicasets get-by-name returns 0 or 1 item
    Given a replicaset "web-abc123" in namespace "team-a"
    When I send GET /api/v1/clusters/prod/resources/replicasets?namespace=team-a&name=web-abc123
    Then the response body items length is 1
    When I send GET /api/v1/clusters/prod/resources/replicasets?namespace=team-a&name=missing
    Then the response body items length is 0

  @replicasets-api
  Scenario: The replicasets list denies SAR
    Given the user lacks "list" on "replicasets" in namespace "team-a"
    When I send GET /api/v1/clusters/prod/resources/replicasets?namespace=team-a
    Then the response status is 403
    And the error code is "RBAC_DENIED"
    And the replicasets list client call was not made

  @replicasets-api
  Scenario: The singular replicaset kind is rejected
    When I send GET /api/v1/clusters/prod/resources/replicaset?namespace=team-a
    Then the response status is 400
    And the error code is "RESOURCE_KIND_NOT_SUPPORTED"

  # ── Routing ──────────────────────────────────────────────────────────────

  @routing
  Scenario: All three stubs are removed and the routes resolve
    When I open /workload/statefulsets
    Then the page is the statefulsets list view (not a stub)
    When I open /workload/daemonsets
    Then the page is the daemonsets list view (not a stub)
    When I open /workload/replicasets
    Then the page is the replicasets list view (not a stub)
    And /workload/statefulsets/data resolves to the statefulset data view
    And /workload/daemonsets/data resolves to the daemonset data view
    And /workload/replicasets/data resolves to the replicaset data view

  @routing
  Scenario: The nav leaves are unchanged (already present)
    When I open the sidebar Workloads group
    Then it contains a "StatefulSets" leaf linked to /workload/statefulsets
    And it contains a "DaemonSets" leaf linked to /workload/daemonsets
    And it contains a "ReplicaSets" leaf linked to /workload/replicasets
