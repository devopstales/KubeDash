Feature: Manage namespaces on the selected cluster
  # briefing.md. 4.1 namespace list + guarded create/delete + Namespace
  # Data object page on the header-selected cluster. Scenario names are
  # the SATISFIES oracle for TASK-028/TASK-029 and the Vitest/pytest titles.

  Background:
    Given the KubeDash single-page app with the API mocked
    And a registered cluster named "prod" is selected in the header

  Scenario: operator-lists-namespaces-on-the-selected-cluster
    # happy path
    Given the selected cluster contains namespaces
    When the operator opens "/cluster/namespace"
    Then the page shows Status, Namespace, Repository, Pipeline, Created, and Action
    And safe repository and pipeline annotations are links
    And each namespace name is a link to its Namespace Data page

  Scenario: authorized-admin-creates-a-namespace
    # happy path
    Given the operator is a KubeDash admin
    And Kubernetes authorizes namespace creation
    When the admin creates a valid namespace
    Then the namespace appears in the page and header namespace lists

  Scenario: authorized-admin-deletes-a-namespace
    # happy path
    Given the operator is a KubeDash admin
    And Kubernetes authorizes namespace deletion
    When the admin confirms deletion of a non-protected namespace
    Then the namespace disappears from the page and header namespace lists

  Scenario: empty-namespace-list-renders-without-the-table
    # edge
    Given the selected cluster has no namespaces
    When the operator opens "/cluster/namespace"
    Then the page shows "No namespaces found"
    And the namespace table is not rendered

  Scenario: javascript-annotation-is-not-a-link
    # edge
    Given a namespace has a javascript: pipeline annotation
    When the operator opens "/cluster/namespace"
    Then the pipeline value is not rendered as a link

  Scenario: non-admin-cannot-mutate-namespaces
    # failure
    Given the operator is not a KubeDash admin
    When the operator opens "/cluster/namespace"
    Then namespace mutation controls are hidden
    And direct namespace mutation requests are denied

  Scenario Outline: protected-namespace-cannot-be-deleted
    # failure
    Given the operator is a KubeDash admin
    When the admin attempts to delete "<namespace>"
    Then the request is rejected without calling Kubernetes

    Examples:
      | namespace         |
      | default           |
      | kube-system       |
      | kube-public       |
      | kube-node-lease   |

  Scenario: operator-opens-a-namespace-object-page
    # happy path
    Given the selected cluster contains namespaces
    When the operator opens a namespace name from the list
    Then the Namespace Data page shows status, name, created, annotations, and labels

  Scenario: namespace-object-page-without-a-name
    # edge
    When the operator opens the Namespace Data page without a name
    Then the page shows that the namespace name was not provided

  Scenario: namespace-object-page-missing-namespace
    # failure
    Given the selected cluster contains namespaces
    When the operator opens the Namespace Data page for a name that is not in the list
    Then the page shows that the namespace was not found

  Scenario: mutation-error-renders-inline
    # failure
    Given the operator is a KubeDash admin
    And creating a namespace is rejected as a duplicate
    When the admin creates that namespace
    Then the page shows the mutation error inline
