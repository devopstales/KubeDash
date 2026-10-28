Feature: RuntimeClass views (list + data)
  # briefing.md R1-R5. TASK-046. The load-bearing theme: the 4.1 nav leaf
  # for Runtime Class was dead (no template); 5.0 resolves it to a real,
  # SAR-gated, read-only list + data pair under Other Resources (ADR-0022),
  # shaped on the ratified 5.0 PriorityClass precedent.
  #
  # Scenario names are the SATISFIES oracle for the blueprint tasks and the
  # test titles. Each scenario's class (happy path / edge / failure) is the
  # comment on its first line.

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user

  # --------------------------------------------------------- API: list (R1)

  Scenario: runtimeclasses-list-200
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/runtimeclasses
    Then the response is 200
    And the body kind is runtimeclasses
    And the body cluster is the bound cluster name

  Scenario: runtimeclasses-list-ignores-namespace
    # edge — R1 (cluster-scoped)
    When a bound user requests GET /api/v1/clusters/1/resources/runtimeclasses?namespace=team-a
    Then the response is 200
    And the namespace parameter does not filter the result

  Scenario: runtimeclasses-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on runtimeclasses (node.k8s.io) denies
    When a bound user requests GET /api/v1/clusters/1/resources/runtimeclasses
    Then the response is 403 RBAC_DENIED naming the runtimeclasses resource
    And the K8s client list call was never made

  Scenario: runtimeclasses-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/runtimeclasses
    Then the response is 404

  Scenario: runtimeclass-kind-singular-rejected
    # edge — R1 (the 4.1 route name was the singular; the API kind is plural)
    When a bound user requests GET /api/v1/clusters/1/resources/runtimeclass
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: runtimeclasses-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/runtimeclasses?name=runc
    Then the response is 200 with a one-item list containing the named RuntimeClass
    When a bound user requests GET /api/v1/clusters/1/resources/runtimeclasses?name=ghost
    Then the response is 200 with an empty items list

  # ---------------------------------------------------- frontend: list (R3)

  Scenario: runtimeclass-list-renders-rows-with-data-links
    # happy path — R3
    Given the cluster is selected
    When the /other-resource/runtimeclass view loads
    Then the card title is exactly Runtime Classes
    And the table shows Name, Handler, Overwrite Node Sel No Toleration, Pod Level Overhead and Created columns
    And each runtime class name links to /other-resource/runtimeclass/data?name=<name>

  Scenario: runtimeclass-list-overhead-rendering
    # edge — R3
    Given a runtime class with pod_level_overhead cpu 100m and memory 128Mi
    And a runtime class without pod_level_overhead
    When the /other-resource/runtimeclass view loads
    Then the first row shows Pod Level Overhead as 100m / 128Mi
    And the second row shows Pod Level Overhead as an em dash

  Scenario: runtimeclass-list-empty-state
    # edge — R3
    Given the cluster has no runtime classes
    When the /other-resource/runtimeclass view loads
    Then the view shows No runtime classes found

  # ------------------------------------------------ frontend: data (R4)

  Scenario: runtimeclass-data-renders-detail
    # happy path — R4
    Given the cluster is selected
    When the /other-resource/runtimeclass/data?name=runc view loads
    Then the view issues a single GET with ?name=runc and no namespace parameter
    And the CTable shows Name, Kind, Created, Handler, Overwrite Node Sel No Toleration, Pod Level Overhead, Labels and Annotations
    And the full object is rendered as a JSON-highlighted block

  Scenario: runtimeclass-data-not-found-state
    # edge — R4 (a miss is a state, not an error)
    Given the cluster has no runtime class named ghost
    When the /other-resource/runtimeclass/data?name=ghost view loads
    Then the view shows No RuntimeClass 'ghost' found
    And no error styling is shown

  Scenario: runtimeclass-data-missing-name
    # edge — R4
    When the /other-resource/runtimeclass/data view loads without a name parameter
    Then the view shows Error: runtime class name not provided

  # ------------------------------------------------ routing (R5)

  Scenario: runtimeclass-stub-removed-and-routes-wired
    # happy path — R5
    When the SPA builds
    Then /other-resource/runtimeclass renders the RuntimeClass list view
    And /other-resource/runtimeclass/data renders the RuntimeClass data view
    And /other-resource/runtimeclass is absent from the stub route list
    And the Runtime Class nav leaf is unchanged
