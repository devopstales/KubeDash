Feature: LimitRange views (list + data)
  # briefing.md R1-R5. TASK-054. The load-bearing theme: 4.1 HAS both
  # templates for Limit Range (list + data with the Container Limits table);
  # 5.0 resolves the stub nav leaf to a real, SAR-gated, read-only list +
  # data pair under Other Resources (ADR-0022), shaped on the ratified 5.0
  # precedents — PriorityClass (view pair, ?name= single fetch, NOT_FOUND
  # state, JSON block) and Secret (namespaced-kind namespace handling).
  #
  # Scenario names are the SATISFIES oracle for the blueprint tasks and the
  # test titles. Each scenario's class (happy path / edge / failure) is the
  # comment on its first line.

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user

  # --------------------------------------------------------- API: list (R1)

  Scenario: limitranges-list-200
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/limitranges?namespace=team-a
    Then the response is 200
    And the body kind is limitranges
    And the body cluster is the bound cluster name
    And each item carries its namespace and spec limits

  Scenario: limitranges-list-respects-namespace
    # edge — R1 (namespaced kind — the contrast to priorityclasses' ignores-namespace)
    When a bound user requests GET /api/v1/clusters/1/resources/limitranges?namespace=team-a
    Then the K8s client list call was made with namespace team-a

  Scenario: limitranges-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on limitranges (core group) in namespace team-a denies
    When a bound user requests GET /api/v1/clusters/1/resources/limitranges?namespace=team-a
    Then the response is 403 RBAC_DENIED naming the limitranges resource
    And the K8s client list call was never made

  Scenario: limitranges-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/limitranges
    Then the response is 404

  Scenario: limitrange-kind-singular-rejected
    # edge — R1 (the 4.1 route name was the singular; the API kind is plural)
    When a bound user requests GET /api/v1/clusters/1/resources/limitrange
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: limitranges-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/limitranges?namespace=team-a&name=default
    Then the response is 200 with a one-item list containing the named LimitRange
    When a bound user requests GET /api/v1/clusters/1/resources/limitranges?namespace=team-a&name=ghost
    Then the response is 200 with an empty items list

  # ---------------------------------------------------- frontend: list (R3)

  Scenario: limitrange-list-renders-rows-with-data-links
    # happy path — R3
    Given the cluster is selected with namespace team-a
    When the /other-resource/limit-range view loads
    Then the card title is exactly Limit Ranges
    And the table shows Name, Namespace and Created columns
    And the fetch carries ?namespace=team-a
    And each limit range name links to /other-resource/limit-range/data?name=<name>&namespace=<namespace>

  Scenario: limitrange-list-empty-state
    # edge — R3
    Given the namespace has no limit ranges
    When the /other-resource/limit-range view loads
    Then the view shows No limit ranges found

  # ------------------------------------------------ frontend: data (R4)

  Scenario: limitrange-data-renders-detail
    # happy path — R4
    Given the cluster is selected
    When the /other-resource/limit-range/data?name=default&namespace=team-a view loads
    Then the view issues a single GET with ?name=default and ?namespace=team-a
    And the metadata CTable shows Name, Namespace, Kind, Created, Annotations and Labels
    And the full object is rendered as a JSON-highlighted block

  Scenario: limitrange-data-namespace-falls-back-to-store
    # edge — R4 (the SecretData resolution order: ?namespace= -> store -> default)
    Given the cluster is selected with namespace team-a
    When the /other-resource/limit-range/data?name=default view loads without a namespace parameter
    Then the view issues a single GET with ?namespace=team-a from the selected namespace

  Scenario: limitrange-data-limits-table
    # happy path — R4 (4.1 Container Limits parity)
    Given a limit range with one spec.limits entry of type Container
    And min cpu 500m memory 1Gi
    And max cpu 2 memory 4Gi
    When the /other-resource/limit-range/data?name=default&namespace=team-a view loads
    Then the Container Limits table shows a row with Resource Container
    And Minimum 500m / 1Gi
    And Maximum 2 / 4Gi
    And Default Limit, Default Request and Minimum Limit Request Ratio columns
    Given a limits entry with only a cpu max
    Then its absent fields render None

  Scenario: limitrange-data-not-found-state
    # edge — R4 (a miss is a state, not an error)
    Given the namespace has no limit range named ghost
    When the /other-resource/limit-range/data?name=ghost&namespace=team-a view loads
    Then the view shows No LimitRange 'ghost' found
    And no error styling is shown

  Scenario: limitrange-data-missing-name
    # edge — R4
    When the /other-resource/limit-range/data view loads without a name parameter
    Then the view shows Error: limit range name not provided

  # ------------------------------------------------ routing (R5)

  Scenario: limitrange-stub-removed-and-routes-wired
    # happy path — R5
    When the SPA builds
    Then /other-resource/limit-range renders the LimitRange list view
    And /other-resource/limit-range/data renders the LimitRange data view
    And /other-resource/limit-range is absent from the stub route list
    And the limit-range entry is moved to the e2e real-route list
    And the Limit Range nav leaf is unchanged
