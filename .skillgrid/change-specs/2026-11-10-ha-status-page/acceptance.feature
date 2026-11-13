Feature: HA Status page (admin endpoint + settings view)
  # briefing.md R1-R6. The load-bearing theme: the pgEdge active-active
  # cluster's health — both replication directions, per-node reachability,
  # leader lease, task queue — is readable as ONE admin endpoint and
  # rendered at /settings/cluster-status. The page degrades (200 + reachable:false)
  # on a sick cluster; it never 500s on the thing it is there to diagnose.

  Background:
    Given the KubeDash Flask app under test
    And a two-node pgEdge active-active cluster (n1, n2) with both replication directions up

  # --------------------------------------------- API: the report (R1, R2)

  Scenario: ha-status-admin-200
    # happy path — R1
    When an admin requests GET /api/v1/admin/ha-status
    Then the response is 200
    And the body carries spock_version
    And the body nodes list every spock.node member (n1 and n2)
    And each node entry carries its own node_name, subscription status, lag, and conflict count
    And the body carries leader (replica_id, fence, heartbeat) and queue (counts by status)
    And the body status is healthy with no reasons

  Scenario: ha-status-both-directions-reported
    # F2/F3 — per-node local state: the connected node only sees its own half
    When an admin requests GET /api/v1/admin/ha-status
    Then the n1 entry reports the n2-to-n1 subscription as replicating
    And the n2 entry reports the n1-to-n2 subscription as replicating
    And each entry's subscription status was probed ON that entry's node

  Scenario: ha-status-non-admin-403
    # edge — R1 (admin-gated, like its /admin/* siblings)
    When a non-admin requests GET /api/v1/admin/ha-status
    Then the response is 403

  Scenario: ha-status-probe-is-read-only
    # R6 — autoddl replicates writes; the app must never write to spock.*
    When an admin requests GET /api/v1/admin/ha-status
    Then no INSERT, UPDATE, or DELETE statement touched any spock object

  # --------------------------------------- failure: sick cluster (R2, R4)

  Scenario: ha-status-node-unreachable-down
    # failure — R2/R4 (a diagnostic page degrades, it never 500s)
    Given node n2 is stopped
    When an admin requests GET /api/v1/admin/ha-status
    Then the response is 200
    And the n2 entry is reachable false with a short probe_error
    And the body status is down with reason node_unreachable:n2

  Scenario: ha-status-node-recovers
    Given node n2 was stopped and is started again
    When an admin requests GET /api/v1/admin/ha-status
    Then the body status is healthy with no reasons

  Scenario: ha-status-subscription-not-replicating-down
    # failure — R4
    Given the n1-to-n2 subscription is suspended
    When an admin requests GET /api/v1/admin/ha-status
    Then the body status is down with reason subscription_not_replicating on the owning node

  Scenario: ha-status-lag-exceeded-degraded
    # edge — R4
    Given node n2's receive lag exceeds 60 seconds
    When an admin requests GET /api/v1/admin/ha-status
    Then the body status is degraded with reason lag_exceeded:n2

  Scenario: ha-status-exceptions-degraded
    # edge — R4
    Given spock.exception_status holds pending conflict rows
    When an admin requests GET /api/v1/admin/ha-status
    Then the body status is degraded with an exceptions reason naming the node

  Scenario: ha-status-stale-heartbeat-degraded
    # edge — R4
    Given the leader_lease heartbeat is more than 10 seconds old
    When an admin requests GET /api/v1/admin/ha-status
    Then the body status is degraded with reason leader_heartbeat_stale

  Scenario: ha-status-worst-verity-wins
    # edge — R4 (combination: down beats degraded, all reasons listed)
    Given node n2 is stopped
    And node n1's receive lag exceeds 60 seconds
    When an admin requests GET /api/v1/admin/ha-status
    Then the body status is down
    And the reasons include both node_unreachable:n2 and lag_exceeded:n1

  # -------------------------------------- leader election (R1, R4)

  Scenario: ha-status-leader-election-report
    # happy path — R1 (lease row + lock verdict + candidates)
    When an admin requests GET /api/v1/admin/ha-status
    Then the leader section names the leader replica_id, its token, tenure, heartbeat age, and fence
    And the lock verdict is held on the leader's node with the holder pid and session state
    And the candidates count is the configured replica count (host-run dev backend: no K8s read — the [deployment] kubedash_replica_count fallback, dev = 1; never null)

  Scenario: ha-status-backend-stop-no-leader
    # failure — R4 (session-scoped lock releases with the process; fail-closed)
    Given the dev backend process is stopped
    When more than 10 seconds pass and an admin requests GET /api/v1/admin/ha-status
    Then the response is 200
    And the body status is degraded with reason no_leader
    When the dev backend is restarted and an admin requests GET /api/v1/admin/ha-status
    Then the body status is healthy
    And the fence is incremented by exactly 1 (it counts elections)

  Scenario: ha-status-lock-lease-mismatch
    # edge — R4
    Given the leader_lease heartbeat is fresh
    And the leader's advisory lock is held on no reachable node
    When an admin requests GET /api/v1/admin/ha-status
    Then the body status is degraded with reason lock_lease_mismatch

  Scenario: ha-status-lock-node-down-no-false-alarm
    # edge — F13 (the lock session is node-local; a down node simply cannot witness it)
    Given the leader's advisory lock session is on node n1
    And node n1 is stopped
    And the leader_lease heartbeat is still fresh
    When an admin requests GET /api/v1/admin/ha-status
    Then the body carries no lock reason (the heartbeat is fresh; the lock's node is down)
    And the body status reflects the node_unreachable condition, not a lock mismatch

  Scenario: ha-status-candidates-in-cluster
    # edge — R1/F14 (in-cluster: the owner-refs chain resolves the Deployment)
    Given the app runs in-cluster as a pod of a 3-replica KubeDash Deployment
    When an admin requests GET /api/v1/admin/ha-status
    Then the leader section reports 1 leader of 3 candidates
    Given the Deployment read fails
    When an admin requests GET /api/v1/admin/ha-status
    Then the response is 200 with candidates the configured replica count (the fallback — never null)

  # --------------------------------------------- DSN override (R3)

  Scenario: ha-status-dsn-override-honored
    # F8 — compose service names don't resolve on the dev host
    Given the INI sets [ha] node_dsn_overrides with n2 pointing at the reachable alt port
    When an admin requests GET /api/v1/admin/ha-status
    Then the n2 entry is reachable true
    And the n2 entry carries its own subscription status and lag

  Scenario: ha-status-dsn-override-malformed-fails-fast
    # ADR-0028 — no silent ignore of a mis-typed override
    Given the INI [ha] node_dsn_overrides contains a malformed entry
    When the app boots
    Then boot fails with a ConfigError naming the [ha] section

  # --------------------------------------------- frontend (R5, route rename)

  Scenario: ha-status-page-renders-healthy
    # happy path — R5
    Given the API returns a healthy report
    When an admin opens /settings/cluster-status
    Then the page shows a healthy banner
    And one card per node shows its name, replicating status, lag, and conflict count
    And the leader section shows replica_id, fence, and heartbeat age
    And the queue section shows counts by status
    And the page re-polls at about 5 second intervals

  Scenario: ha-status-page-shows-degraded-reasons
    # failure — R5
    Given the API reports n2 unreachable (status down)
    When an admin opens /settings/cluster-status
    Then the page shows a down banner listing node_unreachable:n2
    And the n2 card is marked unreachable

  Scenario: cluster-status-route-replaced-the-stub
    # route (user decision 2026-11-11): /settings/cluster-status is real
    When an admin opens /settings/cluster-status
    Then the real HA Status view renders (not the stub placeholder)
    And /settings/ha-status no longer matches a route
