## 1. OIDC server hardening

- [x] 1.1 Add PKCE: generate code_verifier and code_challenge (S256) in authorization flow, store code_verifier in session with state, send code_challenge in authorization URL and code_verifier in token request (lib/sso.py and callback)
- [x] 1.2 In OIDC callback, validate state query parameter against session['oauth_state']; reject and redirect with error when missing or mismatch; log failure
- [x] 1.3 Make TLS verification configurable for IdP requests: use issuer_ca when set for discovery/token/userinfo; avoid verify=False by default; add or use existing config for relaxed verify when needed

## 1b. kdlogin server push (gating, logging, tracing, timeouts)

- [x] 1b.1 On kdlogin entry route (`/kdlogin` in settings SSO blueprint), set a session flag before redirect to IdP indicating kdlogin-initiated OIDC; clear flag after callback processes push (success or failure)
- [x] 1b.2 In OIDC callback (and `auth.py` paths that push to kdlogin), run GET `/info` and POST kubeconfig only when the session flag indicates kdlogin flow; do not probe loopback for standard browser login
- [x] 1b.3 Replace silent failure with structured logging: on connection error, timeout, non-200, or unexpected JSON, log at warning/error with phase (`info` vs `post`), remote address, and exception or HTTP status
- [x] 1b.4 Add OpenTelemetry span(s) around kdlogin push (parent span for push, optional child spans for GET info and POST); set attributes for outcome and HTTP status; record exceptions
- [x] 1b.5 Centralize timeouts for kdlogin GET and POST in config (with sensible defaults); use them in all requests to the plugin

## 2. KubeDash one-time code flow (kdlogin code exchange)

- [x] 2.1 Add storage for one-time codes: generate short-lived unguessable code (e.g. secrets.token_urlsafe), store payload (same as POST body to plugin) in cache or DB with TTL (e.g. 5 min); single-use (delete on read)
- [x] 2.2 Add endpoint (e.g. GET /api/v1/kdlogin/config?code=...) that returns stored payload for valid code and invalidates code; return 404/410 for invalid or expired; add rate limiting
- [x] 2.3 In OIDC callback (and optionally auth) when kubeconfig would be pushed: try existing push to client :8080; on failure or always, generate code and store payload; redirect or show success page with code and instructions (e.g. kubectl kdlogin --code X)
- [x] 2.4 Add success page or callback redirect target that displays the one-time code and usage instructions for the plugin

## 3. kdlogin plugin updates

- [x] 3.1 Add --code and optional --base-url flags: when --code is set, do not open browser or start local server; GET config from server endpoint with code; build and write kubeconfig as when receiving POST
- [x] 3.2 Add --port flag (default 8080) for the local HTTP server; listen on specified port for GET /info and POST /
- [ ] 3.3 (Optional) Add exec subcommand: when invoked by kubectl via user.exec, read stored refresh token (e.g. from ~/.kube/kdlogin-<context>.json), refresh id_token (KubeDash or IdP), print ExecCredential JSON to stdout
- [ ] 3.4 (Optional) Add option to write kubeconfig user with user.exec pointing at kdlogin exec subcommand instead of auth-provider=oidc; keep auth-provider=oidc as default

## 4. Verification and docs

- [x] 4.1 Verify OIDC flow with PKCE and state validation against a test IdP; verify callback rejects invalid state
- [x] 4.2 Verify code flow: after callback, obtain code from success page, run kubectl kdlogin --code <code> --base-url <url>, confirm kubeconfig is written
- [x] 4.3 Verify kdlogin gating: standard web login does not trigger GET :8080/info or POST; kdlogin plugin flow does; failures produce log lines and trace spans
- [x] 4.4 Update user-facing docs (e.g. kubectl-plugin.md, export-openid template) to mention --code flow when push fails and optional --port
