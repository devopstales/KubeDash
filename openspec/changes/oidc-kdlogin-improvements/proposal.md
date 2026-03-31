## Why

The current OIDC flow and kdlogin integration work but have security gaps (no PKCE, optional state validation, verify=False on TLS) and a reliability gap: when KubeDash cannot reach the user's machine (NAT/firewall), the server push of kubeconfig to the plugin fails and the user gets no config. This change hardens OIDC on the server, adds a one-time-code fallback so kdlogin works when push is not possible, and keeps the existing kdlogin integration (auth-provider=oidc remains supported; see reference doc on PR 102181).

## What Changes

- **OIDC (KubeDash server):** Add PKCE to the authorization code flow; validate `state` in the callback; use configurable TLS verification (honor issuer_ca, avoid verify=False by default). No change to high-level flow or API contract.
- **kdlogin when push fails:** Add a one-time-code flow: after successful OIDC callback, server may generate a short-lived one-time code and store the kubeconfig payload; redirect or show a success page with the code; new endpoint (e.g. GET /api/v1/kdlogin/config?code=...) returns the payload and invalidates the code. Plugin gains `kubectl kdlogin --code <code>` (and optional --base-url) to fetch config via that endpoint when push was not possible.
- **kdlogin plugin options:** Keep current behavior (browser + listen :8080, accept POST with OIDC/cert payload). Add configurable port (e.g. --port). Optionally support writing exec-based kubeconfig user (e.g. `kubectl kdlogin exec` returning token) for users who prefer it; auth-provider=oidc remains the default.
- **No breaking changes:** Existing push flow, auth-provider=oidc output, plugin name and discovery, and cert-based flow stay the same.

## Capabilities

### New Capabilities

- **oidc-server-hardening**: OIDC authorization code flow uses PKCE (code_verifier/code_challenge S256); callback validates `state` against session; TLS verification for discovery/token/userinfo is configurable (use issuer_ca when set, avoid verify=False by default).
- **kdlogin-code-exchange**: When kubeconfig cannot be pushed to the plugin (e.g. server cannot reach client :8080), user can obtain config via a one-time code: server generates and stores payload keyed by code, shows code on success page; plugin supports `--code` to fetch config from a new API endpoint; code is single-use and short-lived; endpoint is rate-limited.
- **kdlogin-plugin-options**: Plugin supports configurable listen port (e.g. --port). Optionally, plugin may write exec-based kubeconfig user (user.exec) and provide an exec subcommand that returns ExecCredential token; auth-provider=oidc remains the default output.

### Modified Capabilities

- None. Observable API and UX for existing flows are preserved; new behavior is additive (PKCE, state, code flow, port, optional exec).

## Impact

- **Affected code:** `lib/sso.py`, `lib/init_functions.py`, callback and kdlogin routes in `blueprint/settings/settings.py` and `blueprint/auth/auth.py` (OIDC + code generation); new API route for kdlogin config-by-code; `src/kdlogin/` (Go plugin: --code, --port, optional exec subcommand).
- **APIs:** New endpoint for kdlogin config exchange (e.g. GET /api/v1/kdlogin/config?code=...). Existing OIDC callback and auth routes unchanged in contract; internal behavior gains PKCE and state check.
- **Dependencies:** None new. requests_oauthlib supports PKCE. Optional: ensure Flask/cache or DB for one-time code storage.
- **Security:** PKCE and state reduce risk of code interception and CSRF; code endpoint must be rate-limited and code unguessable/short-lived.
