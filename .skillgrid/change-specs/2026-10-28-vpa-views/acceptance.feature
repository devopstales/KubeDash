Feature: VPAs (Vertical Pod Autoscaler) views (list + data, namespaced CRD)
  # briefing.md R1-R5. The load-bearing theme: the 4.1 VPA pages (list:
  # name/ns/target/update-mode/min-max-memory; data: metadata + target +
  # update mode + container policies + conditions) are a CRD
  # (verticalpodautoscalers.autoscaling.k8s.io) ported to 5.0 via the Cilium
  # full-custom-object seam (CRD-served version as authority, CRD-absent ->
  # empty), as a real, SAR-gated, read-only list + data pair under Other
  # Resources (ADR-0022), with the ratified 5.0 deltas (?name=&namespace=
  # params, JSON block, status.conditions fix, target link dropped).

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user
    And the VPA CRD is installed and served

  # --------------------------------------------------------- API: list (R1)

  Scenario: verticalpodautoscalers-list-200-in-namespace
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/verticalpodautoscalers?namespace=team-a
    Then the response is 200
    And the body kind is verticalpodautoscalers
    And the body cluster is the bound cluster name
    And every item is a full custom object with spec and status intact
    And every item belongs to namespace team-a

  Scenario: verticalpodautoscalers-list-all-namespaces-without-param
    # edge — R1 (the all-namespaces branch, the list_cilium_network_policies pattern)
    When a bound user requests GET /api/v1/clusters/1/resources/verticalpodautoscalers
    Then the response is 200
    And the K8s client used the all-namespaces custom-object list call
    And items from multiple namespaces may be present

  Scenario: verticalpodautoscalers-crd-absent-is-empty
    # edge — R1 (the VPA operator is optional; absence is a state, not an error)
    Given the VPA CRD is absent
    When a bound user requests GET /api/v1/clusters/1/resources/verticalpodautoscalers?namespace=team-a
    Then the response is 200
    And the body items is an empty list

  Scenario: verticalpodautoscalers-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on verticalpodautoscalers (autoscaling.k8s.io, namespace team-a) denies
    When a bound user requests GET /api/v1/clusters/1/resources/verticalpodautoscalers?namespace=team-a
    Then the response is 403 RBAC_DENIED naming the verticalpodautoscalers resource
    And the K8s client list call was never made

  Scenario: verticalpodautoscalers-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/verticalpodautoscalers?namespace=team-a
    Then the response is 404

  Scenario: verticalpodautoscaler-kind-singular-rejected
    # edge — R1 (the API kind is the plural)
    When a bound user requests GET /api/v1/clusters/1/resources/verticalpodautoscaler
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: verticalpodautoscalers-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/verticalpodautoscalers?name=web-vpa&namespace=team-a
    Then the response is 200 with a one-item list containing the named full object in team-a
    When a bound user requests GET /api/v1/clusters/1/resources/verticalpodautoscalers?name=ghost&namespace=team-a
    Then the response is 200 with an empty items list

  # ---------------------------------------------------- frontend: list (R3)

  Scenario: vpa-list-renders-rows-with-data-links
    # happy path — R3
    Given the cluster is selected and the selected namespace is team-a
    When the /other-resource/vertical-pod-autoscaler view loads
    Then the card title is exactly Vertical Pod Autoscaler List
    And the table shows Name, Namespace, Target Kind, Target Name, Update Mode, Min Memory, Max Memory and Created columns
    And the fetch URL is /api/v1/clusters/1/resources/verticalpodautoscalers?namespace=team-a
    And each VPA name links to /other-resource/vertical-pod-autoscaler/data?name=<name>&namespace=team-a

  Scenario: vpa-list-target-and-memory-cells
    # happy path — R3 (targetRef + container-policy memory)
    Given a VPA with targetRef kind Deployment name web
    And a container policy with minAllowed.memory 128Mi and maxAllowed.memory 1Gi
    When the /other-resource/vertical-pod-autoscaler view loads
    Then the Target Kind cell shows Deployment
    And the Target Name cell shows web as plain text
    And the Min Memory cell shows 128Mi
    And the Max Memory cell shows 1Gi

  Scenario: vpa-list-last-container-memory-semantics
    # edge — R3 (4.1's {% set %} overwrite: the LAST container with the key wins)
    Given a VPA with two container policies
    And the first has minAllowed.memory 64Mi and the second has minAllowed.memory 256Mi
    When the /other-resource/vertical-pod-autoscaler view loads
    Then the Min Memory cell shows 256Mi

  Scenario: vpa-list-missing-update-policy
    # edge — R3 (4.1's N/A literal)
    Given a VPA with no updatePolicy
    When the /other-resource/vertical-pod-autoscaler view loads
    Then the Update Mode cell shows N/A

  Scenario: vpa-list-empty-state
    # edge — R3 (also the CRD-absent state)
    Given the selected namespace has no vertical pod autoscalers
    When the /other-resource/vertical-pod-autoscaler view loads
    Then the view shows No vertical pod autoscalers found

  # ------------------------------------------------ frontend: data (R4)

  Scenario: vpa-data-renders-detail
    # happy path — R4
    Given the cluster is selected
    When the /other-resource/vertical-pod-autoscaler/data?name=web-vpa&namespace=team-a view loads
    Then the view issues a single GET with ?name=web-vpa&namespace=team-a
    And the CTable shows Name, Created, Namespace, Target (Owner), Update Mode, Labels and Annotations
    And the Container Policies table shows Container Name, Controlled Values, Mode, Min Allowed, Max Allowed and Controlled Resources columns
    And the Conditions table has a row per status condition
    And the full object is rendered as a JSON-highlighted block

  Scenario: vpa-data-conditions-from-status
    # happy path — R4 (4.1's top-level conditions was dead; 5.0 reads status.conditions)
    Given a VPA with status.conditions one entry type RecommendationProvided status True
    When the /other-resource/vertical-pod-autoscaler/data?name=web-vpa&namespace=team-a view loads
    Then the Conditions table shows a row RecommendationProvided True with its reason and message

  Scenario: vpa-data-container-policies
    # happy path — R4
    Given a VPA with a container policy app controlledValues cpu memory, mode Auto, minAllowed memory 128Mi, maxAllowed memory 1Gi, controlledResources cpu, memory
    When the /other-resource/vertical-pod-autoscaler/data?name=web-vpa&namespace=team-a view loads
    Then the Container Policies table shows a row for app with Controlled Values cpu memory, Mode Auto
    And the Min Allowed cell shows memory: 128Mi
    And the Max Allowed cell shows memory: 1Gi
    And the Controlled Resources cell shows cpu, memory

  Scenario: vpa-data-not-found-state
    # edge — R4 (a miss is a state, not an error)
    Given the namespace has no VPA named ghost
    When the /other-resource/vertical-pod-autoscaler/data?name=ghost&namespace=team-a view loads
    Then the view shows No VerticalPodAutoscaler 'ghost' found
    And no error styling is shown

  Scenario: vpa-data-missing-name
    # edge — R4
    When the /other-resource/vertical-pod-autoscaler/data view loads without a name parameter
    Then the view shows Error: vertical pod autoscaler name not provided

  # ------------------------------------------------ routing (R5)

  Scenario: vpa-stub-removed-and-routes-wired
    # happy path — R5
    When the SPA builds
    Then /other-resource/vertical-pod-autoscaler renders the VPA list view
    And /other-resource/vertical-pod-autoscaler/data renders the VPA data view
    And /other-resource/vertical-pod-autoscaler is absent from the stub route list
    And the VPAs nav leaf is unchanged
