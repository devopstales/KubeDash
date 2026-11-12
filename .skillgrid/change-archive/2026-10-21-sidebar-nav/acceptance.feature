Feature: KubeDash sidebar — the 4.1 look and menu structure in the React shell
  # briefing.md R1–R7. ADR-0022 (4.1 menu parity, Plugins dropped), ADR-0005
  # (CoreUI React), ADR-0020 (no outbound URLs). 4.1 is a visual reference
  # only; nothing here renders a Jinja template.
  # Scenario names are the SATISFIES oracle for tasks.md and the Vitest test
  # titles. Each scenario's class (happy path / edge / failure) is the
  # comment on its first line.

  Background:
    Given the KubeDash single-page app with the API mocked
    And a registered cluster named "prod"

  # ---------------------------------------------------------------- R1 menu

  Scenario: menu-matches-4-1-without-plugins
    # happy path — R1
    Given an admin is signed in
    When the admin looks at the sidebar
    Then the sections read top to bottom: Dashboard, Permissions, Interface, Settings
    And the Permissions section lists Cluster Details, My access, User Management, and Cluster Permissions in that order
    And the Interface section lists Cluster, Workloads, Network, Storage, Security, and Other Resources in that order
    And every entry label matches the briefing's menu table

  Scenario: cluster-details-follows-selection
    # happy path — R1
    Given an admin is signed in
    And the cluster "prod" is selected in the header
    When the admin opens Cluster Details from the sidebar
    Then the cluster page for "prod" is shown

  Scenario: cluster-details-without-selection-opens-cluster-list
    # edge — R1
    Given a user is signed in
    And no cluster is selected
    When the user opens Cluster Details from the sidebar
    Then the cluster list is shown

  Scenario: plugin-entries-never-appear
    # failure — R1
    Given an admin is signed in
    When the admin looks at the sidebar
    Then there is no Plugins group
    And there are no entries named Cert-Manager, LoadBalancers, Gateway API, Trivy Operator, or Applications

  # ------------------------------------------------------------- R2 render

  Scenario: sidebar-shows-cluster-details-link
    # happy path — R2
    Given an admin is signed in
    And the cluster "prod" is selected in the header
    When the admin looks at the Permissions section
    Then its first entry is Cluster Details, linking to the cluster page for "prod"
    And the next entry is My access

  Scenario: workload-entry-shows-beta-badge
    # edge — R2
    Given a user is signed in
    When the user opens the Dashboard group
    Then the Workload entry carries a "Beta" badge
    And the Cluster Metrics entry carries no badge

  Scenario: settings-hidden-for-non-admin
    # failure — R2
    Given a user without the admin role is signed in
    When the user looks at the sidebar
    Then there is no Settings group
    And there are no entries named Auth Provider, Kubernetes Cluster, HA Status, or Audit Log

  # ------------------------------------------------------ R3 existing views

  Scenario: existing-views-still-open
    # happy path — R3
    Given a user is signed in
    When the user opens My access from the sidebar
    Then the My access page with the kubeconfig download is shown
    And it is not the placeholder page

  Scenario: cluster-metrics-and-kubernetes-cluster-share-cluster-list
    # edge — R3
    Given an admin is signed in
    When the admin opens Cluster Metrics from the sidebar
    Then the cluster list is shown
    When the admin opens Kubernetes Cluster from the sidebar
    Then the cluster list is shown

  Scenario: unknown-path-still-redirects-to-cluster-list
    # failure — R3
    Given a user is signed in
    When the user opens a page that no menu entry names
    Then the cluster list is shown

  # ---------------------------------------------------------- R4 admin tabs

  Scenario: audit-tab-opens-from-menu
    # happy path — R4
    Given an admin is signed in
    When the admin opens Audit Log from the sidebar
    Then the admin permissions page is shown with the Audit tab selected

  Scenario: unknown-tab-falls-back-to-users
    # edge — R4
    Given an admin is signed in
    When the admin opens the admin permissions page asking for a tab that does not exist
    Then the Users tab is selected

  Scenario: non-admin-cannot-open-audit-tab
    # failure — R4
    Given a user without the admin role is signed in
    When the user opens the admin permissions page asking for the Audit tab
    Then the user is sent to the home page
    And no audit content is shown

  # -------------------------------------------------------- R5 placeholders

  Scenario: stub-page-names-the-entry
    # happy path — R5
    Given a user is signed in
    When the user opens Pods from the sidebar
    Then a page titled "Pods" is shown
    And it says "This view is not available yet."

  Scenario Outline: every-stub-entry-has-a-page
    # edge — R5
    Given a user is signed in
    When the user opens <entry> from the sidebar
    Then a page titled "<entry>" is shown
    And the user is not sent to the cluster list

    Examples:
      | entry               |
      | Workload            |
      | Groups              |
      | ServiceAccounts     |
      | ClusterRoleBindings |
      | Namespaces          |
      | CRDs                |
      | Ingress             |
      | VolumeClaims        |
      | Network Policies    |
      | Runtime Class       |

  Scenario: settings-url-rejects-non-admin
    # failure — R5
    Given a user without the admin role is signed in
    When the user opens the Auth Provider settings page directly
    Then the user is sent to the home page
    And no page titled "Auth Provider" is shown

  # ------------------------------------------------------- R6 header toggle

  Scenario: header-toggler-hides-sidebar
    # happy path — R6
    Given a user is signed in
    And the sidebar is showing
    When the user presses the header menu button
    Then the sidebar is hidden

  Scenario: header-toggler-restores-sidebar
    # edge — R6
    Given a user is signed in
    And the user has hidden the sidebar with the header menu button
    When the user presses the header menu button again
    Then the sidebar is showing

  Scenario: folding-the-sidebar-does-not-hide-it
    # failure — R6
    Given a user is signed in
    And the sidebar is showing
    When the user presses the fold button in the sidebar footer
    Then the sidebar narrows to icons
    And the sidebar is still showing

  # ------------------------------------------------------------- R7 footer

  Scenario: footer-shows-4-1-labels
    # happy path — R7
    Given a user is signed in
    When the user looks at the page footer
    Then it reads "DevOpsTales - KubeDash Copyright © 2021-2026"
    And it reads "Powered by CoreUI UI Components"

  Scenario: footer-has-no-outbound-link
    # failure — R7
    Given a user is signed in
    When the user looks at the page footer
    Then the footer contains no links

  Scenario: bundle-passes-air-gap-check
    # edge — R7
    Given the frontend bundle is built
    When the air-gap check scans the bundle
    Then it reports no external or CDN URLs
