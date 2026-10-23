Feature: HttpOnly session cookie transport
  # briefing.md R1-R6. ADR-0025. The load-bearing theme: credentials never
  # appear in a URL, a log line, or JavaScript-readable storage, while the
  # kubectl plugin keeps its Bearer credential.
  # Scenario names are the SATISFIES oracle for the blueprint tasks and the
  # test titles. Each scenario's class (happy path / edge / failure) is the
  # comment on its first line.

  Background:
    Given the KubeDash API with the mock OIDC provider
    And a bootstrap admin "admin@local" with password "correct-horse"

  # ------------------------------------------------------------- login

  Scenario: oidc-login-sets-cookies-and-no-token-in-url
    # happy path — R1, R2, R3
    When the browser completes the OIDC callback
    Then the response is a redirect to "/"
    And the Location header contains no token or refresh parameter
    And the response sets kd_access and kd_refresh cookies
    And both cookies are HttpOnly

  Scenario: local-login-sets-cookies-and-no-token-in-url
    # happy path — R1, R2, R3
    When the bootstrap admin posts valid credentials to the local login
    Then the response is a redirect to "/"
    And the Location header contains no token or refresh parameter
    And the response sets kd_access and kd_refresh cookies

  # ------------------------------------------------------------ session

  Scenario: cookie-alone-authorizes-api-calls
    # happy path — R2
    Given the browser holds a valid kd_access cookie
    When it requests the current user without an Authorization header
    Then the API responds 200 with the user identity

  Scenario: bearer-alone-still-authorizes-api-calls
    # happy path — R4
    Given a kubectl plugin client holds a valid access JWT
    When it requests the current user with only an Authorization bearer header
    Then the API responds 200 with the user identity

  Scenario: refresh-reads-the-refresh-cookie-and-rotates
    # happy path — R3
    Given the browser holds a valid kd_refresh cookie
    When it posts to the refresh endpoint with no body
    Then the API responds 200 with a new access token
    And the response re-sets kd_access and kd_refresh cookies

  # ------------------------------------------------------------- logout

  Scenario: logout-clears-cookies-and-revokes-refresh
    # failure — R6
    Given the browser holds a valid session
    When it logs out
    Then the response clears kd_access, kd_refresh, and kd_session
    And a refresh with the previous refresh token returns 401

  Scenario: missing-or-garbage-session-is-401
    # failure — R2, R4
    When an unauthenticated request reaches a domain API route
    Then the API responds 401 UNAUTHORIZED

  # ---------------------------------------------------------- frontend

  Scenario: dead-session-redirects-to-login
    # failure — R5
    Given the SPA holds a session hint but no valid cookies
    When an API call fails after the refresh attempt
    Then the browser is sent to /login

  Scenario: route-guard-uses-the-session-hint
    # happy path — R5
    Given the SPA has a kd_session hint cookie
    When a protected page is opened
    Then the page renders without reading a token from localStorage
