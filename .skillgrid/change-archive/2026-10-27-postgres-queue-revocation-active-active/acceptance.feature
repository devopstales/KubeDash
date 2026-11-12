Feature: KubeDash Postgres task queue, session revocation, OIDC state, SAR cache, active-active Postgres
  # ADR-0029 (queue on Postgres), ADR-0030 (session revocation on Postgres),
  # ADR-0031 (active-active pgEdge Spock + strict fence). The SAR-cache and
  # OIDC-state moves extend ADR-0030's "Postgres replaces Redis for auth state"
  # to the two remaining Redis consumers (user-approved at the blueprint gate:
  # full Redis removal). Scenario names are the SATISFIES oracle for tasks.md.

  Background:
    Given a KubeDash app built by create_app() against Testcontainers Postgres
    And no Redis instance is reachable from the app

  # --- Task queue (ADR-0029) ---

  Scenario: enqueue-then-claim-returns-the-task-path
    # T1: the tracer core — a row is claimable after insert.
    Given the tasks table exists with a pending row for a task path
    When a worker claims with its replica id
    Then the claim returns that task path and the row is processing with the worker as locked_by

  Scenario: concurrent-claimers-never-double-claim
    # T2: FOR UPDATE SKIP LOCKED — the concurrency guarantee.
    Given 50 pending task rows
    And 10 concurrent workers each claiming once
    Then exactly 10 distinct rows are claimed and no row is claimed by two workers

  Scenario: failed-task-retries-with-backoff-then-dead-letters
    # T2: 3x backoff, dead-letter at attempts >= 3.
    Given a claimed task that raises on every run
    When the worker fails it three times
    Then each retry sets available_at to now() + LEAST(cap, base * 5^attempts)
    And after the third failure the row is status failed (dead-letter)

  Scenario: crashed-claim-is-requeued-by-the-time-based-reaper
    # T2: crash recovery is time-based (findings F7/runE), not lock-based.
    Given a processing task row whose locked_at is older than the reaper interval
    When the leader runs the reaper
    Then the row is re-queued to pending with backoff and the queue is not wedged

  # --- Leader fence (ADR-0031) ---

  Scenario: stale-leader-write-is-rejected-by-the-fence
    # T3: the cross-node LWW tiebreaker.
    Given two Leader objects A and B on the same engine
    When A acquires (fence 1) and then B acquires (fence 2)
    And A heartbeats with its stale fence
    Then A's update affects zero rows and A demotes to non-leader

  # --- Session revocation (ADR-0030) ---

  Scenario: logout-revokes-the-access-token-jti
    # T6: the deny-list is written on logout.
    Given an authenticated user with a valid access token
    When the user POSTs to auth logout
    Then the access token jti is inserted into revoked_jtis with an expiry

  Scenario: revoked-jti-is-rejected-on-the-verify-hook
    # T6: replay before expiry -> 401.
    Given an issued access token
    When its jti is in revoked_jtis and not yet expired
    Then verify_jwt raises 401 (token revoked)
    And the revocation lookup is a primary-key lookup with jti bound as a parameter

  # --- OIDC state (session store) ---

  Scenario: oidc-state-is-stored-and-consumed-once
    # T6: one-shot CSRF nonce in the kv table.
    Given a freshly generated OIDC state
    When the state is consumed once
    Then the kv row is deleted and a second consume raises StateMismatchError

  # --- SAR verdict cache (ADR-0004 key shape) ---

  Scenario: sar-cache-hit-never-reasks-the-cluster
    # T6: cache under the unchanged sar:<...> key; a hit never re-asks.
    Given a SAR verdict stored in kv under the full sar:<...> key
    When rbac.can is called for the same (user, cluster, verb, resource, ns, name)
    Then the verdict is served from kv and the cluster is not re-asked

  # --- Redis removal ---

  Scenario: no-module-imports-redis-client
    # T7: the dependency is gone.
    Given the app source tree
    When every module is scanned for the string redis_client
    Then no module references it and flask-redis is not in pyproject.toml

  # --- Dev topology (ADR-0031) ---

  Scenario: dev-up-brings-two-pgedge-nodes-with-no-redis
    # T7: the dev default is the active-active cluster.
    When task dev-up runs
    Then two pgedge/pgedge:pg17-latest containers are up and both in spock.node
    And no redis container is running
    And the backend passes its health check against node n1

  Scenario: migration-run-on-one-node-propagates-to-the-other
    # T7: autoddl DDL replication (findings F6b).
    Given an Alembic migration applied against node n1
    When node n2 is inspected
    Then the new tables exist on n2 without running the migration there
