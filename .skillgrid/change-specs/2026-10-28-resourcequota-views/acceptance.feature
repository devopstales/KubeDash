Feature: ResourceQuota views (list + data, namespaced)
  # briefing.md R1-R5. TASK-047. The load-bearing theme: the 4.1
  # ResourceQuota pages (list: name/ns/request/limit badges; data: metadata
  # + scopes + labels/annotations + used-vs-hard status table) are ported to
  # 5.0 as a real, SAR-gated, read-only list + data pair under Other
  # Resources (ADR-0022) — namespaced (core group), with the ratified 5.0
  # deltas (?name=&namespace= params, JSON block, certainty rendering).

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user

  # --------------------------------------------------------- API: list (R1)

  Scenario: resourcequotas-list-200-in-namespace
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/resourcequotas?namespace=team-a
    Then the response is 200
    And the body kind is resourcequotas
    And the body cluster is the bound cluster name
    And every item belongs to namespace team-a

  Scenario: resourcequotas-list-all-namespaces-without-param
    # edge — R1 (the all-namespaces branch, the list_secrets pattern)
    When a bound user requests GET /api/v1/clusters/1/resources/resourcequotas
    Then the response is 200
    And the K8s client used the all-namespaces list call
    And items from multiple namespaces may be present

  Scenario: resourcequotas-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on resourcequotas (core, namespace team-a) denies
    When a bound user requests GET /api/v1/clusters/1/resources/resourcequotas?namespace=team-a
    Then the response is 403 RBAC_DENIED naming the resourcequotas resource
    And the K8s client list call was never made

  Scenario: resourcequotas-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/resourcequotas?namespace=team-a
    Then the response is 404

  Scenario: resourcequota-kind-singular-rejected
    # edge — R1 (the 4.1 route name was singular; the API kind is plural)
    When a bound user requests GET /api/v1/clusters/1/resources/resourcequota
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: resourcequotas-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/resourcequotas?name=compute&namespace=team-a
    Then the response is 200 with a one-item list containing the named quota in team-a
    When a bound user requests GET /api/v1/clusters/1/resources/resourcequotas?name=ghost&namespace=team-a
    Then the response is 200 with an empty items list

  # ---------------------------------------------------- frontend: list (R3)

  Scenario: resourcequota-list-renders-rows-with-data-links
    # happy path — R3
    Given the cluster is selected and the selected namespace is team-a
    When the /other-resource/resource-quota view loads
    Then the card title is exactly Resource Quota List
    And the table shows Name, Namespace, Requests, Limits and Created columns
    And the fetch URL is /api/v1/clusters/1/resources/resourcequotas?namespace=team-a
    And each quota name links to /other-resource/resource-quota/data?name=<name>&namespace=team-a

  Scenario: resourcequota-list-request-limit-cells
    # happy path — R3 (4.1's badge pairs)
    Given a quota with status used requests.cpu 2, requests.memory 4Gi, limits.cpu 4, limits.memory 8Gi
    And status hard requests.cpu 4, requests.memory 10Gi, limits.cpu 8, limits.memory 20Gi
    When the /other-resource/resource-quota view loads
    Then the Requests cell shows requests.cpu: 2 / 4 and requests.memory: 4Gi / 10Gi
    And the Limits cell shows limits.cpu: 4 / 8 and limits.memory: 8Gi / 20Gi

  Scenario: resourcequota-list-missing-status-keys
    # edge — R3 (certainty rule: never KeyError, render em dash)
    Given a quota with no limits.cpu in status.used and no requests.memory in status.hard
    When the /other-resource/resource-quota view loads
    Then the Limits cell shows limits.cpu: — / —
    And the Requests cell shows requests.memory: — / —

  Scenario: resourcequota-list-empty-state
    # edge — R3
    Given the selected namespace has no resource quotas
    When the /other-resource/resource-quota view loads
    Then the view shows No resource quotas found

  # ------------------------------------------------ frontend: data (R4)

  Scenario: resourcequota-data-renders-detail
    # happy path — R4
    Given the cluster is selected
    When the /other-resource/resource-quota/data?name=compute&namespace=team-a view loads
    Then the view issues a single GET with ?name=compute&namespace=team-a
    And the CTable shows Name, Created, Namespace, Scope, Labels and Annotations
    And the Status table shows Resource, Used and Hard Limit columns
    And the Status table has rows for limits.cpu, limits.memory, requests.cpu and requests.memory
    And the full object is rendered as a JSON-highlighted block

  Scenario: resourcequota-data-not-found-state
    # edge — R4 (a miss is a state, not an error)
    Given the namespace has no quota named ghost
    When the /other-resource/resource-quota/data?name=ghost&namespace=team-a view loads
    Then the view shows No ResourceQuota 'ghost' found
    And no error styling is shown

  Scenario: resourcequota-data-missing-name
    # edge — R4
    When the /other-resource/resource-quota/data view loads without a name parameter
    Then the view shows Error: resource quota name not provided

  # ------------------------------------------------ routing (R5)

  Scenario: resourcequota-stub-removed-and-routes-wired
    # happy path — R5
    When the SPA builds
    Then /other-resource/resource-quota renders the ResourceQuota list view
    And /other-resource/resource-quota/data renders the ResourceQuota data view
    And /other-resource/resource-quota is absent from the stub route list
    And the Resource Quota nav leaf is unchanged
