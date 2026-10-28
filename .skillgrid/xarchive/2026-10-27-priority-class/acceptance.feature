Feature: KubeDash priority classes — 4.1 parity list + detail, moved to Other Resources
  # briefing.md R1-R4. ADR-0004 (SAR is the only gate; the cache key
  # carries every SAR attribute), ADR-0010 (reads through the pool seam;
  # the informer cache interposes later), ADR-0020 (air gap), ADR-0022
  # (retires one stub parity row; the placement under Other Resources is
  # a ratified deviation — 4.1's API already lived in other-resources).
  # The kind is cluster-scoped: namespace is accepted and ignored
  # everywhere, and the detail URL carries none.
  # Scenario names are the SATISFIES oracle for the blueprint tasks and
  # the test titles. Each scenario's class (happy path / edge / failure)
  # is the comment on its first line.

  Background:
    Given the KubeDash single-page app with the API mocked
    And a registered cluster named "prod" is selected

  # -------------------------------------------------- R1: the kind

  Scenario: priorityclasses-list-200
    # happy path - R1 (cluster-scoped list)
    Given the cluster has a PriorityClass named "high" with value 1000
    When the API is asked for cluster "prod" resources "priorityclasses"
    Then the API responds 200 with kind "priorityclasses" and one item
    And the item is the kubernetes to_dict form with spec value, preemption_policy, global_default and description intact

  Scenario: priorityclasses-list-ignores-namespace
    # edge - R1 (a namespace query is accepted and ignored)
    Given the cluster has one PriorityClass named "high"
    When the API is asked for cluster "prod" resources "priorityclasses" with namespace "team-a"
    Then the API responds 200 with the "high" item

  Scenario: priorityclasses-get-by-name
    # happy path - R1 (?name= contract, mirrors get_secret)
    Given the cluster has a PriorityClass named "high"
    When the API is asked for cluster "prod" resources "priorityclasses" with name "high"
    Then the API responds 200 with exactly one item named "high"
    When the API is asked for cluster "prod" resources "priorityclasses" with name "ghost"
    Then the API responds 200 with zero items

  Scenario: priorityclasses-sar-denied
    # failure - R1 (ADR-0004: the SAR is asked BEFORE the read)
    Given a user who cannot list priorityclasses in group "scheduling.k8s.io"
    When the API is asked for cluster "prod" resources "priorityclasses"
    Then the API responds 403 RBAC_DENIED naming "priorityclasses"
    And the SAR was asked with namespace None and group "scheduling.k8s.io"
    And no cluster read is attempted

  Scenario: priorityclasses-binding-404
    # failure - R1 (binding gate before the SAR)
    Given a user with no binding to cluster "prod"
    When the API is asked for cluster "prod" resources "priorityclasses"
    Then the API responds 404 CLUSTER_NOT_FOUND

  Scenario: priorityclasses-kind-singular-rejected
    # edge - R1 (the 4.1 route name is not a kind)
    When the API is asked for cluster "prod" resources "priorityclass"
    Then the API responds 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- R2: list view

  Scenario: list-renders-priority-classes
    # happy path - R2
    Given the mocked API returns one PriorityClass named "high" with value 1000
    When the user opens "/other-resource/priorityclass"
    Then the table shows the name, value, preemption policy, global default, description and the created timestamp in local time
    And the name links to "/other-resource/priorityclass/data" with name "high" and no namespace parameter

  Scenario: list-no-cluster-state
    # edge - R2
    Given no cluster is selected
    When the user opens "/other-resource/priorityclass"
    Then the page shows "No cluster selected." and no resource fetch is made

  Scenario: list-error-state
    # failure - R2
    Given the priorityclasses fetch rejects with RBAC_DENIED
    When the user opens "/other-resource/priorityclass"
    Then the page shows an error line with the message and no blank table

  # --------------------------------------------- R3: detail view

  Scenario: detail-renders-priority-class-yaml
    # happy path - R3 (single read, not 4.1's list-then-filter)
    Given the mocked API returns one item for the ?name= lookup
    When the user opens "/other-resource/priorityclass/data?name=high"
    Then the page fetches "/api/v1/clusters/<id>/resources/priorityclasses?name=high" with no namespace parameter
    And the class metadata is shown
    And the full object is rendered as highlighted YAML containing the class name

  Scenario: detail-not-found-state
    # edge - R3 (empty items upstream is a state, not an error)
    Given the mocked API returns an empty items list for the ?name= lookup
    When the user opens "/other-resource/priorityclass/data?name=ghost"
    Then the page shows a "not found" state naming "ghost"

  Scenario: detail-missing-name-client-error
    # edge - R3 (no name param: no fetch, error line)
    When the user opens "/other-resource/priorityclass/data"
    Then no resource fetch is made
    And the page shows an error line

  # ----------------------------------------- R4: nav move + stub

  Scenario: stub-route-retired-and-moved
    # happy path - R4
    When the router is rendered with the real views
    Then "/other-resource/priorityclass" resolves to the PriorityClass view, not the stub
    And the nav shows "Priority Classes" under the Other Resources group, not under Security
    And "/security/priorityclass" resolves to no route
    And the e2e smoke path for "/other-resource/priorityclass" still passes

  # ------------------------------------------- integration (kind-gated)

  Scenario: priorityclasses-list-on-kind
    # integration backstop - R1 (held-out test: the built-in
    # system-cluster-critical PriorityClass must come back)
    Given a kind cluster with its built-in PriorityClasses
    When the API is asked for the kind cluster resources "priorityclasses"
    Then the API responds 200 with the "system-cluster-critical" item
