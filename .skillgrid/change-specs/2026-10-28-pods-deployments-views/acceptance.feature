@views @pods-deployments
Feature: Pods + Deployments Views (List + Data)

  As a user of the KubeDash dashboard
  I want Pods and Deployments list + data views
  So that I can inspect workloads and their pod/deployment details per namespace

  Background:
    Given the "prod" cluster is selected
    And the namespace "team-a" is selected
    And the user is bound to the "prod" cluster
    And the user has RBAC permission for the resource

  # ── Pods list ────────────────────────────────────────────────────────────

  @pods
  Scenario: The pods list resolves at /workload/pods
    When I open /workload/pods
    Then the page shows a table titled "Pod List"
    And the columns are "Status", "Name", "Pod IP" and "Owner"
    And the Status cell shows the effective-phase badge
    And the Pod IP cell shows the pod IP or "—"
    And the Owner cell shows the owner kind/name or "—"

  @pods
  Scenario: The pods list status badge mapping
    Given a pod "web-1" with phase "Running"
    And a pod "web-2" with phase "Pending"
    And a pod "web-3" with a deletion timestamp
    When I open /workload/pods
    Then the "web-1" Status badge is green "Running"
    And the "web-2" Status badge is yellow "Pending"
    And the "web-3" Status badge is red "Terminated"

  @pods
  Scenario: The pods list owner cell is plain text
    Given a pod "web-1" owned by ReplicaSet "web"
    When I open /workload/pods
    Then the "web-1" Owner cell shows "replicaset/web" as plain text (no link)

  @pods
  Scenario: The pods list name links carry the namespace
    When the pods list shows an item named "web-1"
    Then the "web-1" Name cell links to /workload/pods/data?name=web-1&namespace=team-a

  @pods
  Scenario: The pods list empty state
    When the namespace has no pods
    And I open /workload/pods
    Then the page shows "No pods found"

  @pods
  Scenario: The pods list no-cluster state
    Given no cluster is selected
    When I open /workload/pods
    Then the page shows "No cluster selected."

  # ── Pod data ─────────────────────────────────────────────────────────────

  @pod-data
  Scenario: The pod data page shows the five tabs + JSON
    When I open /workload/pods/data?name=web-1&namespace=team-a
    Then the page shows tabs "Pod", "Containers", "Conditions", "Security Contexts" and "Related Resources"
    And the Pod tab shows "Namespace", "Name", "Status", "Restarts", "Created", "Node", "Owner", "Priority", "Priority Class", "Runtime Class", "Annotations" and "Labels"
    And the page shows a full-object JSON block

  @pod-data
  Scenario: The pod data Restarts is the sum of all container restart counts
    Given a pod "web-1" with two containers having restart counts 2 and 3
    When I open /workload/pods/data?name=web-1&namespace=team-a
    Then the Restarts row shows "5"

  @pod-data
  Scenario: The pod data Node cell deep-links to the Nodes view
    Given a pod "web-1" scheduled on node "node-1"
    When I open /workload/pods/data?name=web-1&namespace=team-a
    Then the Node cell links to /cluster/node/data?name=node-1

  @pod-data
  Scenario: The pod data Related Resources deep-links secrets only
    Given a pod "web-1" with a volume secret "db-creds", a configmap "app-cfg", and a pvc "data"
    When I open /workload/pods/data?name=web-1&namespace=team-a
    Then the "db-creds" Secret row links to /security/secret/data?name=db-creds&namespace=team-a
    And the "app-cfg" Configmap row is plain text (no link)
    And the "data" PVC row is plain text (no link)

  @pod-data
  Scenario: The pod data page not-found state
    When I open /workload/pods/data?name=missing&namespace=team-a
    Then the page shows "No pod 'missing' found"
    And the message is not styled as an error

  @pod-data
  Scenario: The pod data page missing name
    When I open /workload/pods/data?namespace=team-a
    Then the page shows "Error: pod name not provided"

  # ── Pods API (SAR) ───────────────────────────────────────────────────────

  @pods-api
  Scenario: The pods list is SAR-gated on list in the namespace
    When I send GET /api/v1/clusters/prod/resources/pods?namespace=team-a
    Then the response status is 200
    And the response body kind is "pods"
    And the SAR was asked for "list" on "pods" in group "" with namespace "team-a"

  @pods-api
  Scenario: The pods get-by-name returns 0 or 1 item
    Given a pod "web-1" in namespace "team-a"
    When I send GET /api/v1/clusters/prod/resources/pods?namespace=team-a&name=web-1
    Then the response status is 200
    And the response body items length is 1
    When I send GET /api/v1/clusters/prod/resources/pods?namespace=team-a&name=missing
    Then the response body items length is 0

  @pods-api
  Scenario: The pods list denies SAR
    Given the user lacks "list" on "pods" in namespace "team-a"
    When I send GET /api/v1/clusters/prod/resources/pods?namespace=team-a
    Then the response status is 403
    And the error code is "RBAC_DENIED"
    And the pods list client call was not made

  @pods-api
  Scenario: The pods list is 404 when unbound
    Given the user is not bound to the "prod" cluster
    When I send GET /api/v1/clusters/prod/resources/pods?namespace=team-a
    Then the response status is 404

  @pods-api
  Scenario: The singular pod kind is rejected
    When I send GET /api/v1/clusters/prod/resources/pod?namespace=team-a
    Then the response status is 400
    And the error code is "RESOURCE_KIND_NOT_SUPPORTED"

  # ── Deployments list ─────────────────────────────────────────────────────

  @deployments
  Scenario: The deployments list resolves at /workload/deployments
    When I open /workload/deployments
    Then the page shows a table titled "Deployments List"
    And the columns are "Name", "Status" and "Created"
    And the Status cell shows "<desired>/<ready>"

  @deployments
  Scenario: The deployments list status format
    Given a deployment "web" with 3 desired and 2 ready replicas
    When I open /workload/deployments
    Then the "web" Status cell shows "3/2"

  @deployments
  Scenario: The deployments list name links carry the namespace
    When the deployments list shows an item named "web"
    Then the "web" Name cell links to /workload/deployments/data?name=web&namespace=team-a

  @deployments
  Scenario: The deployments list empty state
    When the namespace has no deployments
    And I open /workload/deployments
    Then the page shows "No deployments found"

  @deployments
  Scenario: The deployments list no-cluster state
    Given no cluster is selected
    When I open /workload/deployments
    Then the page shows "No cluster selected."

  # ── Deployment data ──────────────────────────────────────────────────────

  @deployment-data
  Scenario: The deployment data page shows the six tabs + JSON
    When I open /workload/deployments/data?name=web&namespace=team-a
    Then the page shows tabs "Deployment", "Containers", "Variables", "Conditions", "Security Contexts" and "Related Resources"
    And the Deployment tab shows "Namespace", "Name", "Created", "Replicas", "Annotations", "Labels" and "Selectors"
    And the page shows a full-object JSON block

  @deployment-data
  Scenario: The deployment data Replicas is plain text (no spinner)
    Given a deployment "web" with 3 replicas
    When I open /workload/deployments/data?name=web&namespace=team-a
    Then the Replicas row shows "3" as plain text (no input control)

  @deployment-data
  Scenario: The deployment data Related Resources deep-links secrets only
    Given a deployment "web" with a volume secret "db-creds" and a configmap "app-cfg"
    When I open /workload/deployments/data?name=web&namespace=team-a
    Then the "db-creds" Secret row links to /security/secret/data?name=db-creds&namespace=team-a
    And the "app-cfg" Configmap row is plain text (no link)

  @deployment-data
  Scenario: The deployment data page not-found state
    When I open /workload/deployments/data?name=missing&namespace=team-a
    Then the page shows "No deployment 'missing' found"
    And the message is not styled as an error

  @deployment-data
  Scenario: The deployment data page missing name
    When I open /workload/deployments/data?namespace=team-a
    Then the page shows "Error: deployment name not provided"

  # ── Deployments API (SAR) ────────────────────────────────────────────────

  @deployments-api
  Scenario: The deployments list is SAR-gated on list in the namespace
    When I send GET /api/v1/clusters/prod/resources/deployments?namespace=team-a
    Then the response status is 200
    And the response body kind is "deployments"
    And the SAR was asked for "list" on "deployments" in group "apps" with namespace "team-a"

  @deployments-api
  Scenario: The deployments get-by-name returns 0 or 1 item
    Given a deployment "web" in namespace "team-a"
    When I send GET /api/v1/clusters/prod/resources/deployments?namespace=team-a&name=web
    Then the response status is 200
    And the response body items length is 1
    When I send GET /api/v1/clusters/prod/resources/deployments?namespace=team-a&name=missing
    Then the response body items length is 0

  @deployments-api
  Scenario: The deployments list denies SAR
    Given the user lacks "list" on "deployments" in namespace "team-a"
    When I send GET /api/v1/clusters/prod/resources/deployments?namespace=team-a
    Then the response status is 403
    And the error code is "RBAC_DENIED"
    And the deployments list client call was not made

  @deployments-api
  Scenario: The deployments list is 404 when unbound
    Given the user is not bound to the "prod" cluster
    When I send GET /api/v1/clusters/prod/resources/deployments?namespace=team-a
    Then the response status is 404

  @deployments-api
  Scenario: The singular deployment kind is rejected
    When I send GET /api/v1/clusters/prod/resources/deployment?namespace=team-a
    Then the response status is 400
    And the error code is "RESOURCE_KIND_NOT_SUPPORTED"

  # ── Routing, nav, orphan ─────────────────────────────────────────────────

  @routing
  Scenario: Both stubs are removed and the routes resolve
    When I open /workload/pods
    Then the page is the pods list view (not a stub)
    When I open /workload/deployments
    Then the page is the deployments list view (not a stub)
    And /workload/pods/data resolves to the pod data view
    And /workload/deployments/data resolves to the deployment data view

  @routing
  Scenario: The nav leaves are unchanged (already present)
    When I open the sidebar Workloads group
    Then it contains a "Pods" leaf linked to /workload/pods
    And it contains a "Deployments" leaf linked to /workload/deployments

  @routing
  Scenario: The orphan Cluster/Pods table is deleted
    Then the file frontend/src/views/Cluster/Pods.tsx does not exist
    And no file imports Cluster/Pods
