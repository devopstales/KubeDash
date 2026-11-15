Feature: PodDisruptionBudget views (list + data, namespaced)
  # briefing.md R1-R5. The load-bearing theme: the 4.1 PodDisruptionBudget
  # pages (list: name/ns/min/max/allowed-disruptions; data: policy metadata
  # + selector + eviction policy + labels/annotations + status + conditions)
  # are ported to 5.0 as a real, SAR-gated, read-only list + data pair under
  # Other Resources (ADR-0022) — namespaced (policy/v1), with the ratified
  # 5.0 deltas (?name=&namespace= params, JSON block, certainty rendering).

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user

  # --------------------------------------------------------- API: list (R1)

  Scenario: poddisruptionbudgets-list-200-in-namespace
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/poddisruptionbudgets?namespace=team-a
    Then the response is 200
    And the body kind is poddisruptionbudgets
    And the body cluster is the bound cluster name
    And every item belongs to namespace team-a

  Scenario: poddisruptionbudgets-list-all-namespaces-without-param
    # edge — R1 (the all-namespaces branch, the list_secrets pattern)
    When a bound user requests GET /api/v1/clusters/1/resources/poddisruptionbudgets
    Then the response is 200
    And the K8s client used the all-namespaces list call
    And items from multiple namespaces may be present

  Scenario: poddisruptionbudgets-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on poddisruptionbudgets (policy, namespace team-a) denies
    When a bound user requests GET /api/v1/clusters/1/resources/poddisruptionbudgets?namespace=team-a
    Then the response is 403 RBAC_DENIED naming the poddisruptionbudgets resource
    And the K8s client list call was never made

  Scenario: poddisruptionbudgets-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/poddisruptionbudgets?namespace=team-a
    Then the response is 404

  Scenario: poddisruptionbudget-kind-singular-rejected
    # edge — R1 (the 4.1 route name was singular; the API kind is plural)
    When a bound user requests GET /api/v1/clusters/1/resources/poddisruptionbudget
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: poddisruptionbudgets-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/poddisruptionbudgets?name=web&namespace=team-a
    Then the response is 200 with a one-item list containing the named budget in team-a
    When a bound user requests GET /api/v1/clusters/1/resources/poddisruptionbudgets?name=ghost&namespace=team-a
    Then the response is 200 with an empty items list

  # ---------------------------------------------------- frontend: list (R3)

  Scenario: pdb-list-renders-rows-with-data-links
    # happy path — R3
    Given the cluster is selected and the selected namespace is team-a
    When the /other-resource/pod-disruption-budget view loads
    Then the card title is exactly Pod Disruption Budget List
    And the table shows Name, Namespace, Min Available, Max Unavailable and Allowed Disruptions columns
    And the fetch URL is /api/v1/clusters/1/resources/poddisruptionbudgets?namespace=team-a
    And each budget name links to /other-resource/pod-disruption-budget/data?name=<name>&namespace=team-a

  Scenario: pdb-list-min-max-cells
    # happy path — R3 (spec has exactly one of min/max; 4.1's blank for the absent one)
    Given a budget with spec.min_available 3 and a budget with spec.max_unavailable 1
    When the /other-resource/pod-disruption-budget view loads
    Then the min-available budget row shows Min Available 3 and Max Unavailable —
    And the max-unavailable budget row shows Max Unavailable 1 and Min Available —

  Scenario: pdb-list-missing-status
    # edge — R3 (certainty rule: 4.1 UndefinedErrors on a fresh PDB's absent status)
    Given a budget with no status field
    When the /other-resource/pod-disruption-budget view loads
    Then the Allowed Disruptions cell shows —

  Scenario: pdb-list-empty-state
    # edge — R3
    Given the selected namespace has no pod disruption budgets
    When the /other-resource/pod-disruption-budget view loads
    Then the view shows No pod disruption budgets found

  # ------------------------------------------------ frontend: data (R4)

  Scenario: pdb-data-renders-detail
    # happy path — R4
    Given the cluster is selected
    When the /other-resource/pod-disruption-budget/data?name=web&namespace=team-a view loads
    Then the view issues a single GET with ?name=web&namespace=team-a
    And the CTable shows Name, Created, Namespace, Selector, Eviction Policy, Labels and Annotations
    And the Status table shows Allowed disruptions, Current healthy and Desired rows
    And the Conditions table has a row per status condition
    And the full object is rendered as a JSON-highlighted block

  Scenario: pdb-data-selector-and-eviction-policy
    # happy path — R4 (4.1's Selector + Eviction Policy rows)
    Given a budget with selector match_labels app web and tier frontend
    And spec.unhealthy_pod_eviction_policy AlwaysAllow
    When the /other-resource/pod-disruption-budget/data?name=web&namespace=team-a view loads
    Then the Selector row shows app: web and tier: frontend
    And the Eviction Policy row shows AlwaysAllow

  Scenario: pdb-data-not-found-state
    # edge — R4 (a miss is a state, not an error)
    Given the namespace has no budget named ghost
    When the /other-resource/pod-disruption-budget/data?name=ghost&namespace=team-a view loads
    Then the view shows No PodDisruptionBudget 'ghost' found
    And no error styling is shown

  Scenario: pdb-data-missing-name
    # edge — R4
    When the /other-resource/pod-disruption-budget/data view loads without a name parameter
    Then the view shows Error: pod disruption budget name not provided

  # ------------------------------------------------ routing (R5)

  Scenario: pdb-stub-removed-and-routes-wired
    # happy path — R5
    When the SPA builds
    Then /other-resource/pod-disruption-budget renders the PodDisruptionBudget list view
    And /other-resource/pod-disruption-budget/data renders the PodDisruptionBudget data view
    And /other-resource/pod-disruption-budget is absent from the stub route list
    And the Pod Disruption Budget nav leaf is unchanged
