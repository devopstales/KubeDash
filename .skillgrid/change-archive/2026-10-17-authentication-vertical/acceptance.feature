Feature: Authentication vertical — local admin + SSO + offline bundle
  # ADR-0021 (local admin auth), air-gap per ADR-0020, single-container per ADR-0006.
  # Scenario names are frozen by the SATISFIES lines in tasks.md / blueprint.md.

  Background:
    Given a KubeDash backend running with the base-structure spine
    And the OIDC mock IdP available for the SSO path

  Scenario: local-admin-login-issues-jwt
    # T1, T2, T3: the door check of the whole change.
    Given KUBEDASH_BOOTSTRAP_ADMIN_EMAIL and KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD are set
    When POST /api/v1/auth/local with the bootstrap admin's email and password
    Then the response is a 302 to /?token=<jwt>&refresh=<token> exactly as issued
    And the JWT decodes to the bootstrap admin's claims
    When POST /api/v1/auth/local with the wrong password
    Then the response is 401 with code INVALID_CREDENTIALS
    When POST /api/v1/auth/local with an unknown email
    Then the response is 401 with code INVALID_CREDENTIALS
    When the bootstrap env is unset
    Then POST /api/v1/auth/local is 403 with code LOCAL_AUTH_DISABLED

  Scenario: admin-sees-local-cluster-from-config
    # T6, T7, T8, T9: the admin source + synthetic cluster.
    Given a local admin user with a valid JWT
    When GET /api/v1/clusters
    Then the list contains exactly one entry with id 0, name "local", source "admin"
    And a non-admin caller's list contains no id 0 entry
    When the admin GETs /api/v1/clusters/0/resources/pods against a kind cluster
    Then pods from the admin kubeconfig source are returned
    And a non-admin GET of the same path is 404 CLUSTER_NOT_FOUND
    When KUBEDASH_ADMIN_KUBECONFIG points at a missing file
    Then GET /readyz is 503 naming admin-kubeconfig
    When KUBEDASH_ADMIN_KUBECONFIG is empty
    Then GET /readyz has no admin-kubeconfig dependency

  Scenario: login-page-offers-sso-and-local
    # T10: the login page contract.
    Given GET /api/v1/auth/settings returns sso_enabled true and local_enabled true
    When the Login view renders
    Then the "Sign in with SSO" button is present
    And the local email/password form is present
    Given GET /api/v1/auth/settings returns sso_enabled false and local_enabled true
    When the Login view renders
    Then the SSO button is absent and the local form is present
    When the local form is submitted with valid credentials
    Then the 302 token pair is parked in localStorage and the app navigates to /profile
    When the local form is submitted with a 401 INVALID_CREDENTIALS
    Then the error message is shown inline

  Scenario: profile-page-shows-identity
    # T11: the post-login landing.
    Given a logged-in admin user
    When the Profile view renders at /profile
    Then the display name, email, groups, role badge, and auth-source badge are shown
    And last login is shown
    When the logout button is clicked
    Then POST /api/v1/auth/logout is called
    And kd_token and kd_refresh are cleared
    And the app navigates to /login

  Scenario: taskfile-fe-loop-serves-offline-bundle
    # T12, T13, T14: the offline frontend loop + air-gap proof.
    When task fe-install fe-build fe-sync runs from a clean checkout
    Then backend/static/index.html exists
    And task backend-run serves it at /
    When task fe-check runs on the current bundle
    Then it exits 0
    When a fixture dist/ contains https://cdn.example.com/lib.js
    Then task fe-check exits 1 printing the offending path
    And no asset in frontend/dist references https?:// or //cdn. outside the allow-list

  Scenario: adr-0021-local-mode-in-force
    # R6: the ADR bookkeeping.
    When the change is complete
    Then .skillgrid/ASSUMPTIONS.md LOCKED index contains row 0021 in force
    And the ADR-0020 row is annotated superseded-in-part by 0021
    And artifacts/04-adr-0021-local-admin-auth.md has status accepted
    And .backlog/decisions/decision-021.md exists
    And ARCHITECTURE.md section 11 notes the bootstrap-admin mode is implemented

  Scenario: oidc-login-still-issues-jwt
    # No-regression guard: the existing OIDC spine is unchanged.
    When the OIDC login flow completes via the mock IdP callback
    Then the response is a 302 to /?token=<jwt>&refresh=<token>
    And the users row is upserted with auth_source oidc and role user
    And the issued JWT passes /api/v1/auth/me
    And refresh rotation and reuse-detection behave as before the change
