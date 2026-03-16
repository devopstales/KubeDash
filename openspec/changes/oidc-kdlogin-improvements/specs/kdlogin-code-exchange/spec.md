## ADDED Requirements

### Requirement: One-time code for kubeconfig when push fails

The system SHALL support delivering kubeconfig to the kdlogin plugin via a one-time code when the server cannot push to the client (e.g. when POST to client :8080 fails). The server SHALL generate a short-lived, unguessable code and store the same payload that would have been POSTed to the plugin. The user SHALL be able to retrieve the config by presenting the code to a dedicated endpoint or to the plugin.

#### Scenario: Server generates code after successful callback

- **WHEN** the OIDC callback completes successfully and kubeconfig would have been pushed to the plugin (and optionally when push is attempted and fails)
- **THEN** the server SHALL generate a one-time code, store the kubeconfig payload keyed by that code with a short TTL (e.g. 5 minutes), and SHALL redirect or display a success page that shows the code and instructions for using it with the plugin

#### Scenario: Config endpoint returns payload for valid code

- **WHEN** a client requests the kubeconfig with a valid one-time code (e.g. GET /api/v1/kdlogin/config?code=...)
- **THEN** the server SHALL return the stored payload (same structure as current POST body to plugin) with 200, and SHALL invalidate the code so it cannot be used again

#### Scenario: Config endpoint rejects invalid or expired code

- **WHEN** a client requests the kubeconfig with an invalid, expired, or already-used code
- **THEN** the server SHALL respond with 404 or 410 and SHALL NOT return the payload

#### Scenario: Plugin fetches config with code

- **WHEN** the user runs the plugin with a --code flag (e.g. kubectl kdlogin --code ABC12345 and optionally --base-url)
- **THEN** the plugin SHALL request the config from the server endpoint using the code (e.g. GET with code query), and on success SHALL build and write kubeconfig as it does when receiving the POST payload; the plugin SHALL NOT open the browser or start the local server for the push flow in this mode

### Requirement: One-time code security

One-time codes SHALL be single-use and SHALL have limited lifetime. The code endpoint SHALL be rate-limited to reduce brute-force or abuse. The code SHALL have sufficient entropy to be unguessable in practice (e.g. 8–12 or more characters from a cryptographically safe source).

#### Scenario: Code is single-use

- **WHEN** a valid code is used in a successful request to the config endpoint
- **THEN** the server SHALL invalidate the code so a subsequent request with the same code returns 404/410

#### Scenario: Rate limiting

- **WHEN** the config endpoint receives many requests (e.g. per IP or per code)
- **THEN** the server SHALL apply rate limiting so that abuse is limited (exact limits are implementation-defined)
