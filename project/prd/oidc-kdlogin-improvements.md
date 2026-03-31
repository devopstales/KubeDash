### PRD: OIDC + kdlogin Improvements

**OpenSpec change**: `openspec/changes/oidc-kdlogin-improvements/`  
**Status**: Proposed (see OpenSpec for canonical state)

#### Problem / Why

The existing OIDC flow between KubeDash, kdlogin, and the IdP:

- Lacks hardened security controls (no PKCE, optional/weak `state` validation, permissive TLS verification such as `verify=False`).
- Is brittle when KubeDash cannot reach the user’s machine (e.g. NAT/firewall), because kubeconfig is pushed over a callback to kdlogin listening on `:8080`. When that push fails, the user receives no kubeconfig.

We need to **raise the security bar** for OIDC and **make kdlogin more reliable** in real‑world network conditions, without breaking existing users.

#### Goals

- Harden the OIDC authorization code flow on the KubeDash server (PKCE, strict state validation, safer TLS).
- Provide a **fallback configuration retrieval path** so users can still obtain kubeconfigs even when server‑initiated push to kdlogin fails.
- Enhance kdlogin plugin usability via configurable options, while preserving the current default behavior.
- Avoid breaking changes to existing OIDC flows and kubeconfig shapes.

#### Non‑Goals

- Redesigning the entire auth system or replacing OIDC.
- Changing the default kubeconfig format away from `auth-provider=oidc`.

---

### User Stories

- **Security‑conscious admin**
  - *As a* KubeDash administrator
  - *I want* OIDC flows to use PKCE and strict state checking with proper TLS validation
  - *So that* my cluster dashboards are not exposed to common OAuth2/OIDC attack vectors (code interception, CSRF, MITM).

- **User behind NAT/firewall**
  - *As a* user whose machine is behind a corporate proxy, NAT, or firewall
  - *I want* a way to obtain my kubeconfig via a short‑lived one‑time code instead of a direct callback from the server
  - *So that* I can still use `kubectl` even when the push‑to‑kdlogin path is blocked.

- **CLI‑focused engineer**
  - *As a* developer who prefers CLI tooling
  - *I want* kdlogin to offer options like configurable listen ports and (optionally) exec‑based kubeconfig users
  - *So that* I can integrate KubeDash SSO more flexibly into my workflows without changing existing behavior by default.

---

### Functional Requirements

#### 1. OIDC Server Hardening (KubeDash)

- The OIDC authorization code flow **must support PKCE** (S256):
  - Generate a `code_verifier` and corresponding `code_challenge` per auth request.
  - Include `code_challenge` and `code_challenge_method=S256` in the `/authorize` request.
  - Include `code_verifier` in the token exchange.
- The OIDC callback must:
  - Validate `state` against session‑stored value.
  - Reject mismatched or missing `state`.
- TLS verification for discovery/token/userinfo requests must be:
  - Configurable based on an `issuer_ca` or similar setting.
  - Avoid `verify=False` by default; insecure behavior must be explicitly configured, not the default.

#### 2. kdlogin One‑Time‑Code Flow

- After successful OIDC callback, if KubeDash **cannot successfully push** kubeconfig to kdlogin (e.g. timeout, connection refused):
  - Server may generate a **short‑lived, single‑use code**.
  - Server must store the kubeconfig payload keyed by that code (in DB or cache).
  - Server must redirect or show a success page containing the code and instructions.
- A new API endpoint must be added, e.g.:
  - `GET /api/v1/kdlogin/config?code=<one-time-code>`
  - Behavior:
    - On valid code: return kubeconfig payload, then immediately invalidate the code.
    - On invalid/expired code: return an error (4xx) and do not leak whether code existed.
    - Must be rate‑limited.
- kdlogin plugin behavior:
  - Add `--code <code>` (and optional `--base-url`) to fetch kubeconfig from this endpoint when direct push cannot be used.

#### 3. kdlogin Plugin Options

- **Port configuration**:
  - kdlogin must support a configurable listen port (e.g. `--port 18080`) instead of hard‑coding `:8080`.
  - KubeDash and/or the kubectl plugin docs must clarify how to coordinate the port between browser flows and kdlogin.
- **Optional exec‑based kubeconfig**:
  - Optionally, kdlogin may support writing kubeconfig users using `user.exec` instead of `auth-provider=oidc`.
  - Provide an `exec` subcommand that returns a Kubernetes `ExecCredential` with a token.
  - Default output remains `auth-provider=oidc` to avoid breaking existing users.

---

### Non‑Functional Requirements

- **Security**
  - One‑time codes must be:
    - Random and unguessable.
    - Short‑lived (configurable TTL).
    - Single‑use; once redeemed, they must be invalidated.
  - The code retrieval endpoint must be rate‑limited and logged for audit.
  - PKCE + state must be enforced for all OIDC flows (unless explicitly disabled via config for legacy reasons).

- **Reliability**
  - When kdlogin callback fails, the user must be clearly informed of the fallback option and given a code.
  - Code storage must be robust (e.g. Redis/DB) and resilient to KubeDash restarts within the TTL window.

- **Backward compatibility**
  - Existing OIDC flows that rely on `auth-provider=oidc` formatted kubeconfigs must continue to work without changes.
  - Existing plugins and scripts that expect kdlogin’s current behavior must not break when not using new options.

---

### Scope / Affected Components

- **Python / KubeDash**
  - `lib/sso.py`
  - `lib/init_functions.py`
  - OIDC callback and kdlogin routes in:
    - `blueprint/settings/settings.py`
    - `blueprint/auth/auth.py`
  - New API route for kdlogin config‑by‑code.
- **Go / kdlogin**
  - `src/kdlogin/main.go` and related files:
    - Add `--code`, `--port`, and optional `exec` behavior.

---

### Implementation Tasks (from OpenSpec)

#### 1. OIDC Server Hardening

- [ ] 1.1 Add PKCE: generate `code_verifier` and `code_challenge` (S256) in authorization flow, store `code_verifier` in session with state, send `code_challenge` in authorization URL and `code_verifier` in token request (`lib/sso.py` and callback).
- [ ] 1.2 In OIDC callback, validate `state` query parameter against `session['oauth_state']`; reject and redirect with error when missing or mismatch; log failure.
- [ ] 1.3 Make TLS verification configurable for IdP requests: use `issuer_ca` when set for discovery/token/userinfo; avoid `verify=False` by default; add or use existing config for relaxed verify when needed.

#### 2. KubeDash One‑Time Code Flow (kdlogin Code Exchange)

- [ ] 2.1 Add storage for one‑time codes: generate short‑lived unguessable code (e.g. `secrets.token_urlsafe`), store payload (same as POST body to plugin) in cache or DB with TTL (e.g. 5 min); single‑use (delete on read).
- [ ] 2.2 Add endpoint (e.g. `GET /api/v1/kdlogin/config?code=...`) that returns stored payload for valid code and invalidates code; return 404/410 for invalid or expired; add rate limiting.
- [ ] 2.3 In OIDC callback (and optionally auth) when kubeconfig would be pushed: try existing push to client `:8080`; on failure or always, generate code and store payload; redirect or show success page with code and instructions (e.g. `kubectl kdlogin --code X`).
- [ ] 2.4 Add success page or callback redirect target that displays the one‑time code and usage instructions for the plugin.

#### 3. kdlogin Plugin Updates

- [ ] 3.1 Add `--code` and optional `--base-url` flags: when `--code` is set, do not open browser or start local server; GET config from server endpoint with code; build and write kubeconfig as when receiving POST.
- [ ] 3.2 Add `--port` flag (default 8080) for the local HTTP server; listen on specified port for `GET /info` and `POST /`.
- [ ] 3.3 (Optional) Add `exec` subcommand: when invoked by kubectl via `user.exec`, read stored refresh token (e.g. from `~/.kube/kdlogin-<context>.json`), refresh `id_token` (KubeDash or IdP), print `ExecCredential` JSON to stdout.
- [ ] 3.4 (Optional) Add option to write kubeconfig user with `user.exec` pointing at kdlogin `exec` subcommand instead of `auth-provider=oidc`; keep `auth-provider=oidc` as default.

#### 4. Verification and Docs

- [ ] 4.1 Verify OIDC flow with PKCE and state validation against a test IdP; verify callback rejects invalid state.
- [ ] 4.2 Verify code flow: after callback, obtain code from success page, run `kubectl kdlogin --code <code> --base-url <url>`, confirm kubeconfig is written.
- [ ] 4.3 Update user‑facing docs (e.g. `kubectl-plugin.md`, export‑openid template) to mention `--code` flow when push fails and optional `--port`.

---

### Open Questions / Follow‑Ups

- Decide the canonical storage layer for one‑time codes (Redis vs DB) and TTL defaults.
- Define exact rate‑limit policy for the `config?code=` endpoint.
- Decide whether insecure TLS for OIDC should be allowed at all in production, and how clearly to surface that risk in configuration and docs.

