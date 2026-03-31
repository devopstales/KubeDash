## ADDED Requirements

### Requirement: OIDC authorization flow uses PKCE

The server SHALL use PKCE (RFC 7636) for the OIDC authorization code flow. The authorization request SHALL include a code_challenge (S256) and the token request SHALL include the corresponding code_verifier. The code_verifier SHALL be generated per authorization and stored in session until the callback completes.

#### Scenario: Authorization request includes code_challenge

- **WHEN** the server redirects the user to the IdP authorization endpoint (e.g. from /kdlogin or SSO login)
- **THEN** the authorization URL SHALL include code_challenge and code_challenge_method=S256, and the server SHALL store the code_verifier in session (e.g. with oauth_state)

#### Scenario: Token request includes code_verifier

- **WHEN** the callback exchanges the authorization code for tokens
- **THEN** the token request SHALL include the code_verifier that corresponds to the code_challenge sent in the authorization request

### Requirement: Callback validates state parameter

The server SHALL validate the state parameter on the OIDC callback. If state is missing or does not match the value stored in session (e.g. session['oauth_state']), the server SHALL reject the request and SHALL NOT exchange the code for tokens. The server SHALL redirect to login or an error page and SHALL log the failure.

#### Scenario: Valid state

- **WHEN** the callback is invoked with a state query parameter that matches the value stored in session for this flow
- **THEN** the server SHALL proceed with the token exchange and user session creation as today

#### Scenario: Invalid or missing state

- **WHEN** the callback is invoked with a missing state or state that does not match session
- **THEN** the server SHALL NOT exchange the code, SHALL redirect to login or error, and SHALL log the validation failure

### Requirement: Configurable TLS verification for OIDC

The server SHALL support configurable TLS verification for requests to the IdP (discovery, token, userinfo). When issuer_ca (or equivalent) is configured, the server SHALL use it to verify the IdP TLS certificate. The server SHALL NOT use verify=False by default when a CA or verification option is available.

#### Scenario: TLS verification with configured CA

- **WHEN** issuer_ca (or equivalent) is configured for the OIDC provider
- **THEN** requests to the IdP (discovery, token, userinfo) SHALL use that CA for verification (or the system trust store when appropriate)

#### Scenario: Verification configurable per deployment

- **WHEN** deployment requires relaxed TLS (e.g. self-signed IdP in dev)
- **THEN** the system SHALL allow configuration to disable or relax verification only when explicitly set (e.g. via config); default SHALL be to verify when CA is available
