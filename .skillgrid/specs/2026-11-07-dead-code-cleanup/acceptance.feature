Feature: Dead-Code Cleanup (Change D) - template leftovers + unused code
  # briefing.md R1-R5. The load-bearing theme: delete the CoreUI template
  # demo material + the individually verified unused code (pure deletions),
  # record the dynamic-wiring verdict for the 23 backend files, and migrate
  # the ~20 inline KubeDataTable test fakes onto one shared fake - zero
  # behaviour change, proven by the suites green at every commit.

  Background:
    Given the 2026-11-07 jscpd dead-code report (187 findings: 81 unused files, 79 unused imports, 20 unused symbols, 7 unused exports)
    And the verification floor: corepack pnpm test, task fe-build, task fe-check, uv run pytest -m "not integration"

  Scenario: deletion-list-verified
    # R1 - Task 1: no file is deleted without a recorded import-free proof
    When the verification pass re-generates the dead-code findings
    Then every frontend unused-file finding (the 58 + Pods.tsx) is grep-checked by import specifier or module path, not bare basename
    And a hit from a live file excludes the file from the list with a recorded exception
    And a hit only from a deletion-set file or a known-colliding identifier is a pass-with-note, not an exclusion
    And every unused-symbol candidate is verified the same way
    And the wsgi _rq_worker_main/_build_worker_app pair is recorded live-dynamic (the spawn string at wsgi.py:179), not as an exception
    And the verified list (file, grep command, zero-hit result, exceptions annotated) is ready to land in the first deletion commit body

  Scenario: template-bulk-deleted
    # R1+R2 - Task 2: the CoreUI demo bulk (components/forms/widgets/dashboard) is gone
    When the verified views/components, views/forms, views/widgets, views/dashboard files are deleted
    Then git status matches the verified list exactly
    And no import specifier for a deleted file remains in frontend/src, frontend/tests, or frontend/e2e
    And corepack pnpm test, task fe-build, and task fe-check are all green at this commit

  Scenario: template-tail-deleted
    # R1+R2 - Task 3: the remaining template files, Pods.tsx, and the docs helpers
    When the verified views/authentication, views/charts, views/icons, views/error-pages, docs-helper, store.js, and views/Cluster/Pods.tsx files are deleted
    Then Pods.tsx is re-verified against the route table (App.tsx lazy imports + stubRoutes) before deletion
    And the docs helpers are re-verified after the bulk deletion, their 37 importers now gone
    And no template demo page remains in frontend/src/views
    And corepack pnpm test, task fe-build, and task fe-check are all green at this commit

  Scenario: unused-code-removed
    # R1+R2+R3 - Task 4: the 79 unused imports + the verified unused symbols
    When the 79 unused-import findings are removed (frontend hand-deleted from the report, backend ruff F401 + manual diff review)
    Then a re-generated jscpd report lists no unused-import finding
    And the verified unused symbols are gone: gateway_convert leftovers, dead KIND/LIST_ROUTE constants, NodeData PROBE_CONDITIONS, ServiceAccountData SecretRef, unused lib types, the migration _has_unique, prometheus-push _METRIC_RE
    And the wsgi _rq_worker_main/_build_worker_app pair is still present (live-dynamic)
    And the test-only exports resetRefreshForTests, setLoginRedirectForTests, and getRegisteredNavigate are still present
    And the change diff is deletions plus import-cleanup lines only
    And corepack pnpm test, task fe-build, task fe-check, uv run pytest -m "not integration", uv run ruff check ., and uv run mypy app are all green at this commit

  Scenario: test-fake-fleet-migrated
    # R5 - Task 5: one shared KubeDataTable fake, no test behaviour change
    When the faithful init-time-capture fake is extracted from pvs.test.tsx into frontend/tests/components/kube-data-table.test-utils.tsx
    Then every view test that faked KubeDataTable inline (the grep list, ~20 files) imports the shared fake instead
    And each test keeps its own canned data with its expectations unedited
    And any test whose behaviour changed was stopped and reported, not silently adapted
    And corepack pnpm test and task fe-build are green with zero edited test expectations

  Scenario: backend-files-verified
    # R4 - Task 6: the 23 backend files get a per-file verdict, no deletions
    When each of the 23 backend files is checked for dynamic wiring with grep scoped to backend/ (wsgi scheduler + spawn string, test_file_map.py EXPECTED, sockets registration, models __init__, aggregated app factory)
    Then the backlog note carries a per-file verdict for all 23 files: live-dynamic (health.py, cluster_sync.py), stub-by-design (the rest), with the test_file_map.py string-pin recorded for every file
    And no backend file is deleted in this change
    And any proposed-deletion flag names the test_file_map.py and ARCHITECTURE.md section-2 updates it implies

  Scenario: dead-code-measured
    # R2 - Task 7: the full floor green + the jscpd re-run
    When the full verification floor runs (corepack pnpm test, task fe-build, task fe-check, task e2e, uv run pytest -m "not integration", uv run ruff check ., uv run mypy app)
    Then every suite is green
    And a re-generated jscpd report shows the 58 deleted template files, Pods.tsx, and the 79 unused imports gone from the findings
    And the dead-code percentage drops from the 16.6% baseline (187 findings) toward ~1%
    And no clone pairs remain in views/components, views/forms, or views/widgets
    And the new dead-code percentage and health are recorded in the commit body
