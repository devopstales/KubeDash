## Context

- **Current state:** OIDC flow uses requests_oauthlib; authorization URL is built with `oauth.authorization_url(auth_url, access_type="offline")`; callback exchanges code for token with `oauth.fetch_token(..., verify=False)` and fetches userinfo; state is stored in session but callback may not validate it explicitly. KubeDash pushes kubeconfig to kdlogin by POSTing to `http://<remote_addr>:8080/` when GET :8080/info returns `{"message":"kdlogin"}`; when the server cannot reach the client (NAT/firewall), push fails and the user gets no config. kdlogin (Go) listens on fixed port 8080 and writes auth-provider=oidc kubeconfig.
- **Constraints:** Preserve existing kdlogin integration (plugin name, push flow, auth-provider=oidc as default). No breaking changes to callback URL or API surface for existing clients. Reference: docs/analysis/openid-auth-flow-and-kdlogin-proposal.md and docs/reference/auth-provider-oidc-deprecation.md.

## Goals / Non-Goals

**Goals:**

- Harden OIDC server-side: PKCE (S256), state validation in callback, configurable TLS (honor issuer_ca; avoid verify=False by default).
- Add one-time-code flow so users can get kubeconfig when push fails: server generates code and exposes an endpoint; plugin supports `--code` to fetch config.
- Add plugin options: configurable port; optional exec-based kubeconfig output.

**Non-Goals:**

- Changing IdP or callback URL contract. Deprecating or removing auth-provider=oidc. Changing kubectl plugin discovery. Requiring exec credential for OIDC (it remains optional).

## Decisions

1. **PKCE implementation:** Use requests_oauthlib's PKCE support (code_verifier/code_challenge S256). Generate code_verifier per authorization request, store in session with state; send code_challenge in authorization URL and code_verifier in token request. **Rationale:** OAuth 2.1 / best practice; no change to redirect_uri or callback path. **Alternative:** Skip PKCE for confidential client only—rejected to align with current guidance.

2. **State validation:** In callback, require `state` in request args and validate `state == session.get('oauth_state')`; on mismatch or missing, reject (redirect to login with error) and log. **Rationale:** CSRF protection for authorization code flow. **Alternative:** Leave state optional—rejected for security.

3. **TLS verification:** Use a configurable verify flag or issuer_ca (PEM) when set: for discovery, token, and userinfo requests, pass verify=path_or_true and disable verify only when explicitly configured (e.g. dev). **Rationale:** Avoid verify=False by default to reduce MITM risk. **Alternative:** Always verify—may break deployments with self-signed IdP; so make it configurable.

4. **One-time code storage:** Store code → payload mapping in cache (e.g. Flask-Caching/Redis) or DB with short TTL (e.g. 5 min). Key: unguessable code (e.g. 8–12 chars from secrets.token_urlsafe). Single-use: delete on successful read. **Rationale:** Keeps server stateless for code endpoint; cache/DB already available. **Alternative:** In-memory only—fails across workers; so use shared cache or DB.

5. **Code endpoint auth:** No session or cookie required; the code is the auth. Rate-limit by IP and/or by code attempt to prevent brute-force. Return 404/410 for invalid or expired code. **Rationale:** Plugin cannot send browser cookies; code must be sufficient. **Alternative:** Require session—would force user to paste code in browser and then plugin to reuse session; more complex and not chosen.

6. **Plugin --port:** Add flag `--port` to kdlogin; default 8080. When present, listen on that port so server detection (GET /info) and push (POST /) use the same port. **Rationale:** Avoids conflict with other tools on 8080. **Alternative:** Env var only—flag is more discoverable.

7. **Exec credential optional:** If we add exec output, kdlogin stores refresh token (or similar) under a well-known path (e.g. ~/.kube/kdlogin-<context>.json) at login time; `kubectl kdlogin exec --base-url ... --context ...` reads it, refreshes id_token (via KubeDash or IdP), prints ExecCredential JSON. Kubeconfig user.exec points at that command. **Rationale:** Keeps auth-provider=oidc as default; exec is opt-in. **Alternative:** Switch default to exec—rejected to avoid breaking existing users.

## Risks / Trade-offs

- **[Code brute-force]** Short codes could be guessed. **Mitigation:** Use sufficient entropy (e.g. 12+ chars token_urlsafe); rate-limit endpoint; single-use and short TTL.
- **[PKCE/state breaking legacy]** Some IdPs or proxies might behave oddly. **Mitigation:** PKCE is widely supported; state is standard. Test with target IdPs; document config if verify must be relaxed.
- **[Code endpoint abuse]** Attacker could try to claim codes. **Mitigation:** Rate-limit; code unguessable; no PII in response beyond what the user would get from push (same payload).

## Migration Plan

- Deploy server changes (PKCE, state, TLS, code endpoint); existing clients and plugin continue to work (push flow unchanged). Deploy new plugin version; old plugin still works with server (no new required flags). Rollback: revert server and plugin; push-only flow and existing kubeconfigs unchanged.

## Open Questions

- None. Scope is bounded to hardening, code exchange, and optional plugin options.
