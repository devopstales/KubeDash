Feature: HPAs (Horizontal Pod Autoscaler) views (list + data, namespaced)
  # briefing.md R1-R5. The load-bearing theme: the 4.1 HPA pages (list:
  # name/ns/owner/targets/min-max-replicas/replicas; data: metadata + owner +
  # metrics + replicas + conditions) are ported to 5.0 as a real, SAR-gated,
  # read-only list + data pair under Other Resources (ADR-0022) — namespaced
  # core kind (autoscaling/v1), with the ratified 5.0 deltas (?name=
  # &namespace= params, JSON block, min/max header-swap fix, typed conditions
  # from status.conditions + legacy-annotation fallback).

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user

  # --------------------------------------------------------- API: list (R1)

  Scenario: horizontalpodautoscalers-list-200-in-namespace
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/horizontalpodautoscalers?namespace=team-a
    Then the response is 200
    And the body kind is horizontalpodautoscalers
    And the body cluster is the bound cluster name
    And every item belongs to namespace team-a

  Scenario: horizontalpodautoscalers-list-all-namespaces-without-param
    # edge — R1 (the all-namespaces branch, the list_secrets pattern)
    When a bound user requests GET /api/v1/clusters/1/resources/horizontalpodautoscalers
    Then the response is 200
    And the K8s client used the all-namespaces list call
    And items from multiple namespaces may be present

  Scenario: horizontalpodautoscalers-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on horizontalpodautoscalers (core, namespace team-a) denies
    When a bound user requests GET /api/v1/clusters/1/resources/horizontalpodautoscalers?namespace=team-a
    Then the response is 403 RBAC_DENIED naming the horizontalpodautoscalers resource
    And the K8s client list call was never made

  Scenario: horizontalpodautoscalers-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/horizontalpodautoscalers?namespace=team-a
    Then the response is 404

  Scenario: horizontalpodautoscaler-kind-singular-rejected
    # edge — R1 (the 4.1 route name was singular; the API kind is plural)
    When a bound user requests GET /api/v1/clusters/1/resources/horizontalpodautoscaler
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: horizontalpodautoscalers-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/horizontalpodautoscalers?name=web-hpa&namespace=team-a
    Then the response is 200 with a one-item list containing the named HPA in team-a
    When a bound user requests GET /api/v1/clusters/1/resources/horizontalpodautoscalers?name=ghost&namespace=team-a
    Then the response is 200 with an empty items list

  # ---------------------------------------------------- frontend: list (R3)

  Scenario: hpa-list-renders-rows-with-data-links
    # happy path — R3
    Given the cluster is selected and the selected namespace is team-a
    When the /other-resource/horizontal-pod-autoscaler view loads
    Then the card title is exactly Horizontal Pod Autoscaler List
    And the table shows Name, Namespace, Owner, Targets, Min Replicas, Max Replicas and Replicas columns
    And the fetch URL is /api/v1/clusters/1/resources/horizontalpodautoscalers?namespace=team-a
    And each HPA name links to /other-resource/horizontal-pod-autoscaler/data?name=<name>&namespace=team-a

  Scenario: hpa-list-targets-and-replica-cells
    # happy path — R3 (4.1's CPU target + replicas; min/max header-swap corrected)
    Given an HPA with spec min_replicas 2 max_replicas 10 target_cpu_utilization_percentage 80
    And status current_replicas 3 current_cpu_utilization_percentage 50
    When the /other-resource/horizontal-pod-autoscaler view loads
    Then the Targets cell shows 50 / 80 %
    And the Min Replicas cell shows 2
    And the Max Replicas cell shows 10
    And the Replicas cell shows 3
    And the Owner cell shows the scale_target_ref name as plain text

  Scenario: hpa-list-unknown-cpu-target
    # edge — R3 (4.1's UNKNOWN literal for the absent legacy field)
    Given an HPA with no status.current_cpu_utilization_percentage
    When the /other-resource/horizontal-pod-autoscaler view loads
    Then the Targets cell shows UNKNOWN / 80 %

  Scenario: hpa-list-empty-state
    # edge — R3
    Given the selected namespace has no horizontal pod autoscalers
    When the /other-resource/horizontal-pod-autoscaler view loads
    Then the view shows No horizontal pod autoscalers found

  # ------------------------------------------------ frontend: data (R4)

  Scenario: hpa-data-renders-detail
    # happy path — R4
    Given the cluster is selected
    When the /other-resource/horizontal-pod-autoscaler/data?name=web-hpa&namespace=team-a view loads
    Then the view issues a single GET with ?name=web-hpa&namespace=team-a
    And the CTable shows Name, Created, Namespace, Owner, Metrics, Min Replicas, Max Replicas, Replicas, Labels and Annotations
    And the full object is rendered as a JSON-highlighted block

  Scenario: hpa-data-conditions-from-status
    # happy path — R4 (4.1 read the legacy annotation; 5.0 reads status.conditions)
    Given an HPA with status.conditions one entry type AbleToScale status True
    When the /other-resource/horizontal-pod-autoscaler/data?name=web-hpa&namespace=team-a view loads
    Then the Conditions table shows a row AbleToScale True with its last transition time, reason and message

  Scenario: hpa-data-conditions-from-legacy-annotation
    # edge — R4 (4.1's source: the autoscaling.alpha.kubernetes.io/conditions annotation)
    Given an HPA with no status.conditions
    And the autoscaling.alpha.kubernetes.io/conditions annotation is a JSON list of one condition
    When the /other-resource/horizontal-pod-autoscaler/data?name=web-hpa&namespace=team-a view loads
    Then the Conditions table shows that condition as a typed row

  Scenario: hpa-data-missing-conditions
    # edge — R4
    Given an HPA with no status.conditions and no legacy conditions annotation
    When the /other-resource/horizontal-pod-autoscaler/data?name=web-hpa&namespace=team-a view loads
    Then the view shows No conditions

  Scenario: hpa-data-not-found-state
    # edge — R4 (a miss is a state, not an error)
    Given the namespace has no HPA named ghost
    When the /other-resource/horizontal-pod-autoscaler/data?name=ghost&namespace=team-a view loads
    Then the view shows No HorizontalPodAutoscaler 'ghost' found
    And no error styling is shown

  Scenario: hpa-data-missing-name
    # edge — R4
    When the /other-resource/horizontal-pod-autoscaler/data view loads without a name parameter
    Then the view shows Error: horizontal pod autoscaler name not provided

  # ------------------------------------------------ routing (R5)

  Scenario: hpa-stub-removed-and-routes-wired
    # happy path — R5
    When the SPA builds
    Then /other-resource/horizontal-pod-autoscaler renders the HPA list view
    And /other-resource/horizontal-pod-autoscaler/data renders the HPA data view
    And /other-resource/horizontal-pod-autoscaler is absent from the stub route list
    And the HPAs nav leaf is unchanged
