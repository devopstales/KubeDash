Feature: KubeDash cluster dashboard — Option C (concentric donuts + overcommit + events)
  # briefing.md R1–R5. ADR-0003 (query-only), ADR-0004 (SAR key carries every
  # attribute), ADR-0005 (CoreUI), ADR-0010 (pool seam; cache interposes later),
  # ADR-0020 (air gap), ADR-0023 (DataTables). The certainty rule (AGENTS.md)
  # is the load-bearing theme: a value the dashboard cannot read renders
  # unknown, never 0 or a healthy tone.
  # Scenario names are the SATISFIES oracle for the blueprint tasks and the
  # test titles. Each scenario's class (happy path / edge / failure) is the
  # comment on its first line.

  Background:
    Given the KubeDash single-page app with the API mocked
    And a registered cluster named "prod" is selected

  # ------------------------------------------------------- R1 + R2: metrics

  Scenario: summary-computes-overcommit
    # happy path — R1, R2
    Given the cluster has node capacity of 4000 millicores CPU and 8Gi memory
    And pods declare 2000 millicores of CPU requests with no limits
    And the Metrics API reports 800 millicores of CPU used
    When the API is asked for the cluster metrics summary
    Then the summary shows cpu capacity 4000, requests 2000, used 800 and limits 0
    And the summary shows memory capacity 8Gi and requests declared per pod spec
    And metrics_available is true

  Scenario: summary-metrics-unavailable-not-zero
    # edge — R1, R2 (certainty rule)
    Given the cluster has pods with declared requests
    And the Metrics API is unreachable
    When the API is asked for the cluster metrics summary
    Then metrics_available is false
    And the used fields are null, not zero
    And requests and limits are still returned from the declared pod specs

  Scenario: summary-endpoint-rbac-denied
    # failure — R1 (derived data must not leak, ADR-0004)
    Given a user who cannot cluster-wide list pods or nodes
    When the API is asked for the cluster metrics summary
    Then the API responds 403 RBAC_DENIED and no count is returned

  Scenario: summary-used-gated-separately-on-metrics-read
    # edge — R1 (used is a distinct source, distinct RBAC)
    Given a user who can cluster-wide list pods and nodes
    And the user cannot read nodes on metrics.k8s.io
    When the API is asked for the cluster metrics summary
    Then metrics_available is false and the used fields are null
    And requests and limits and capacity are still returned

  # ------------------------------------------------------------- R3: events

  Scenario: events-endpoint-lists
    # happy path — R3
    Given the cluster has recorded events with reasons and messages
    When the API is asked for the cluster events
    Then the events are returned newest first with type, reason, object, namespace, message and count

  Scenario: events-endpoint-rbac-denied
    # failure — R3
    Given a user who cannot cluster-wide list events
    When the API is asked for the cluster events
    Then the API responds 403 RBAC_DENIED

  # ------------------------------------------------------------- R4: view

  Scenario: dashboard-renders-rows
    # happy path — R4
    Given the metrics summary and events endpoints both succeed
    When the dashboard is opened at /dashboard/cluster-metric
    Then row one shows the CPU, Memory and Pods donuts
    And row two shows the events table
    And a red overflow bar is absent while requests are at or under capacity

  Scenario: donut-overcommit-red-bar
    # edge — R2, R4
    Given the metrics summary reports requests above capacity
    When the dashboard is opened at /dashboard/cluster-metric
    Then the over-capacity amount is shown as a red overflow bar sized to the excess

  Scenario: dashboard-unknown-used
    # edge — R2, R4 (certainty rule)
    Given the metrics summary reports metrics_available false
    When the dashboard is opened at /dashboard/cluster-metric
    Then the used value renders unknown, not zero and not a healthy tone
    And requests and limits still render from the declared pod specs

  Scenario: dashboard-metrics-404-unknown
    # edge — R4 (version skew: new frontend, old backend — AGENTS.md)
    Given the metrics summary endpoint responds 404
    When the dashboard is opened at /dashboard/cluster-metric
    Then the affected values render unknown
    And no red error is shown

  Scenario: dashboard-no-cluster
    # edge — R4
    Given no cluster is selected
    When the dashboard is opened
    Then the view says no cluster is selected and renders no donuts

  # ------------------------------------------------------------ R5: themes

  Scenario: dashboard-themes
    # happy path — R5
    Given the dashboard renders in light mode with correct chart colors
    When the theme is switched to dark
    Then the donut grid, ticks and legend redraw with dark-mode CoreUI token colors
    And the red overflow bar keeps the danger token in both themes

  # --------------------------------------------------------------- R4: nav

  Scenario: cluster-metrics-nav-opens-dashboard
    # happy path — R4 (retarget decision, 2026-10-22)
    Given a user is signed in
    When the user opens Cluster Metrics from the sidebar
    Then the dashboard at /dashboard/cluster-metric is shown
    And the Kubernetes Cluster entry still opens the cluster list at /clusters
