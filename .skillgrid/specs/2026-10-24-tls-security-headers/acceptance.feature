Feature: TLS edge + security headers
  # briefing.md R1-R6. ADR-0026. The load-bearing theme: the 5.0 rebase
  # restored the 4.1 security-header layer (CSP, HSTS, COOP/CORE, framing,
  # nosniff) and the TLS edge it depends on, so the ADR-0025 HttpOnly cookie
  # is honest end-to-end and the browser gets a defense against XSS-on-session.
  #
  # Scenario names are the SATISFIES oracle for the blueprint tasks and the
  # test titles. Each scenario's class (happy path / edge / failure) is the
  # comment on its first line.

  Background:
    Given the KubeDash Flask app under test

  # ------------------------------------------------------------ header layer

  Scenario: strict-csp-with-nonce-on-api-response
    # happy path — R3
    When an authenticated request reaches the user profile API
    Then the response carries a Content-Security-Policy header
    And the policy contains default-src 'self'
    And the policy contains script-src 'self' with a nonce
    And the policy contains no unsafe-eval

  Scenario: csp-nonce-changes-per-request
    # edge — R3
    When two authenticated requests reach the user profile API
    Then the two responses carry different CSP nonces

  Scenario: hsts-present-over-tls-and-absent-over-plain-http
    # edge — R3
    Given the app runs behind the TLS edge
    When a request reaches the health endpoint over TLS
    Then the response carries Strict-Transport-Security with max-age=31536000 and includeSubDomains
    When a request reaches the health endpoint over plain HTTP
    Then the response carries no Strict-Transport-Security header

  Scenario: static-security-headers-on-every-response
    # happy path — R3
    When an unauthenticated request reaches the API root
    Then the response carries X-Frame-Options DENY
    And the response carries X-Content-Type-Options nosniff
    And the response carries Referrer-Policy strict-origin-when-cross-origin
    And the response carries Cross-Origin-Opener-Policy same-origin
    And the response carries Cross-Origin-Embedder-Policy require-corp
    And the response carries Cross-Origin-Resource-Policy same-origin

  Scenario: api-responses-never-cached
    # happy path — R4
    When a request reaches any API route
    Then the response carries Cache-Control no-store
    And the response carries Pragma no-cache
    And the response carries Expires 0

  Scenario: static-asset-caching-preserved
    # edge — R4 (ADR-0006)
    When a request reaches a hashed asset under /assets
    Then the response carries Cache-Control immutable, max-age=31536000
    When a request reaches the SPA index at /
    Then the response carries Cache-Control no-cache

  # ---------------------------------------------------------- proxy + tls

  Scenario: proxyfix-applied-behind-edge
    # happy path — R2
    Given the app runs behind the TLS edge
    When a request arrives with X-Forwarded-Proto https
    Then the request is seen as secure by the application

  Scenario: proxyfix-inactive-without-edge
    # edge — R2 (test client + plain dev path unaffected)
    Given the app runs without the TLS edge
    When a request arrives with X-Forwarded-Proto https
    Then the request is not seen as secure by the application

  # ------------------------------------------------------- edge integration

  Scenario: tls-edge-serves-https-and-redirects-http
    # happy path — R1
    Given the dev stack runs with the TLS edge
    When a browser opens http://kubedash.local
    Then the browser is redirected to https://kubedash.local:443
    And the certificate is verified against the installed mkcert CA

  Scenario: secure-cookies-flow-end-to-end
    # backstop — R1, R2, R5 (runtime: full dev stack, not the test client)
    Given the dev stack runs with the TLS edge and the backend is Secure-cookie
    When the browser logs in over https://kubedash.local:443
    Then the kd_access cookie is set with the Secure attribute
    And the cookie round-trips on subsequent API calls
    And the profile page renders the identity
