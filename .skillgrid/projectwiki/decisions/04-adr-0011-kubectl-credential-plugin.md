# kubectl credential plugin with server-managed SSO config

---
status: "accepted"
date: 2026-10-17
backfilled: 2026-11-06
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

`kubelogin` (the dominant OSS kubectl OIDC plugin) puts **all** SSO
config in the kubeconfig — issuer, client_id — in a file that is 0644
by default: reconnaissance for anyone who reads `~/.kube/config`, and a
per-user edit every time the IdP or the client rotates. The question:
how does KubeDash let `kubectl` authenticate through the same OIDC SSO
as the web UI?

#### Decision Drivers

- **No SSO config in the kubeconfig.** The kubeconfig may carry only
  the KubeDash server URL + cluster name; issuer/client_id/scopes are
  fetched from the server at auth time.
- **The K8s API server is the trust anchor.** KubeDash brokers config
  and relays tokens, but the API server validates the id_token's
  `iss`/`aud`/signature against the IdP JWKS — KubeDash being
  compromised doesn't let it mint cluster access.
- **Server-side rotation.** Rotating the client or migrating IdPs is a
  server change, never a per-user kubeconfig edit.

#### Considered Options

- **kubelogin-style (config in kubeconfig).** Rejected: recon surface +
  per-user rotation pain — the problem being solved.
- **Embedded long-lived token in kubeconfig.** Rejected: a secret at
  rest in a 0644 file; revocation is per-token bookkeeping.
- **Server-managed config + exec credential plugin (CHOSEN).** The
  kubeconfig carries only `--server` + `--cluster-name`; the plugin
  does OIDC Authorization Code + PKCE (S256) against the config the
  server hands it, caches tokens in the OS keyring, and prints an
  `ExecCredential`.

#### Decision Outcome

**Chosen option: Go credential plugin (`cli/`) + server config
endpoint.**

- `GET /kubectl/auth/v1/config?cluster=<name>`
  (`backend/app/api/kubectl_auth.py`) — unauthenticated (the plugin is
  bootstrapping auth), TLS + rate-limited, **versioned at `/v1/`** as a
  plugin↔server contract; responds with `{issuer, client_id, token_url,
  auth_url, scopes, expiry}` (public by design in a PKCE flow).
- Plugin: Go 1.22+, `cobra`; loopback redirect `http://127.0.0.1:PORT/cb`
  (ephemeral port, `state` = 16 random bytes); token cache in the OS
  keyring (0600 file fallback); outputs
  `client.authentication.k8s.io/v1` `ExecCredential` JSON.
- Distribution: Krew / Homebrew / GitHub Releases with SHA256 (air-gap:
  the binary is distributed as a file — ADR-0020).

##### Consequences

- Good: zero SSO secrets in user files; server-side rotation; the web
  UI and kubectl share one SSO; trust chain stays IdP → API server.
- Bad: the config endpoint is unauthenticated (mitigated: TLS +
  rate-limit + non-secret payload); one more binary to version.
- Confirmation: `cli/` (`go test ./...`),
  `backend/app/api/kubectl_auth.py` + `backend/app/schemas/kubectl_auth.py`.

#### Linking Decisions and Constraints

- ADR-0014 — web logout must kill the kubectl session (revocation
  propagation).
- ADR-0025 — `Authorization: Bearer` is accepted on the API for the
  plugin (and API clients).
- ADR-0020 — offline distribution of the binary.

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §7.6; verified
against `cli/` and `backend/app/api/kubectl_auth.py` on 2026-11-06.
