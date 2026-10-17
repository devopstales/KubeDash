# KubeDash kubectl OIDC Plugin — Implementation Blueprint (steps, files, verification)

> **Status:** PROPOSED
> **Goal:** A Go-based `kubectl` credential plugin (`kubectl kubedash get-token`) that authenticates users via OIDC SSO, with **all SSO configuration managed server-side** so that users never see or store `client_id`, `issuer_url`, `client_secret`, or `scopes` in their kubeconfig.
> **Architecture:** Go binary (single, static) + KubeDash API endpoints (`/kubectl/auth/*`). The plugin is a thin client: it fetches auth config from the server, performs the OIDC PKCE flow locally, caches tokens in the OS keyring, and outputs `client.authentication.k8s.io/v1` JSON to stdout.
> **Tech Stack:** Go 1.22+, `golang.org/x/oauth2`, `coreos/go-oidc/v3`, `github.com/zalando/go-keyring`, `k8s.io/client-go` (for the credential-plugin protocol types only).
> **Spec:** `.skillgrid/specs/2026-10-17-kubectl-oidc-plugin/briefing.md` (to be written)
> **Build shape:** Tracer thread — a thin end-to-end path (plugin → server → OIDC → token → kubeconfig) works first, then thickens with keyring, refresh, and multi-cluster.
> **Change classification:** `risky` (new trust boundary: the plugin handles tokens; L2 + security review)

---

## Hypothesis

**Claim:** A kubectl credential plugin that fetches SSO config from the KubeDash server (not from kubeconfig flags) is secure, usable, and drop-in compatible with the `client.authentication.k8s.io/v1` protocol.
**Right condition:** `kubectl get pods` triggers the browser flow, returns a valid token, and the kubeconfig contains **no** `oidc-issuer-url` / `oidc-client-id` args — only `--server=<kubedash-url>` and `--cluster-name=<name>`.
**Wrong condition:** The user must set `--oidc-issuer-url` or `--oidc-client-id` in their kubeconfig, or the token is not accepted by the K8s API server.
**Thinnest MVP:** A Go binary that reads `--server` + `--cluster-name` from args, calls `GET /kubectl/auth/config?cluster=<name>`, performs a PKCE browser flow, and prints the `ExecCredential` JSON to stdout. No keyring, no refresh, no multi-cluster.
**Door check:** Task 1 — the plugin binary compiles, runs `get-token --server=... --cluster-name=...`, hits the mock server, and prints valid `ExecCredential` JSON. If the JSON shape is wrong, kubectl rejects it and the whole approach is re-examined.

---

## The Security Problem with kubelogin

`kubelogin` (2.4k stars) works by putting **all SSO config in the kubeconfig**:

```yaml
users:
  - name: oidc
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl
        args:
          - oidc-login
          - get-token
          - --oidc-issuer-url=https://accounts.google.com   # ← in kubeconfig
          - --oidc-client-id=123456789.apps.googleusercontent.com  # ← in kubeconfig
```

**Hazards:**

1. **`~/.kube/config` is world-readable by default** (0644). Anyone who reads it learns the `issuer_url` (which IdP the company uses) and the `client_id` (which OAuth app). This is a **reconnaissance** win for an attacker: they now know the IdP, the client, and can craft targeted phishing or token-forge attacks.
2. **`client_id` is a semi-secret.** In a public-client PKCE flow it's not a *secret* per se, but it identifies the OAuth app. If the app has a `client_secret` (confidential client), leaking the `client_id` narrows the brute-force surface.
3. **Multi-cluster noise.** Every cluster context in the kubeconfig repeats the same `--oidc-*` args. Rotating the `client_id` or migrating IdPs means editing every user's kubeconfig (or re-distributing a new one).
4. **No server-side revocation.** The server can't say "this client_id is deprecated, use the new one" without every user updating their kubeconfig.

**KubeDash's answer:** the kubeconfig contains **only** the KubeDash server URL and the cluster name. The plugin asks the server "how do I authenticate for cluster X?" and the server responds with the issuer, client_id, scopes, and (optionally) a short-lived signing nonce. The user never sees the SSO config.

```yaml
# KubeDash kubeconfig (what the user sees)
users:
  - name: kubedash
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl
        args:
          - kubedash
          - get-token
          - --server=https://kubedash.example.com   # ← only the server
          - --cluster-name=production               # ← only the cluster
```

---

## Must-Haves

### Truths

| # | Truth | Backstop? |
|---|---|---|
| T1 | `kubectl kubedash get-token --server=URL --cluster-name=NAME` prints valid `client.authentication.k8s.io/v1` JSON to stdout that kubectl accepts | yes — requires a real `kubectl` + K8s API server |
| T2 | The kubeconfig `exec.args` for the plugin contain **no** `--oidc-issuer-url`, `--oidc-client-id`, `--oidc-client-secret`, or `--oidc-scopes` flags | no — diff read |
| T3 | The server endpoint `GET /kubectl/auth/config?cluster=NAME` returns `{issuer, client_id, scopes, token_url, auth_url, expiry}` and is the **single source of truth** for SSO config | no — code read |
| T4 | The OIDC flow uses **PKCE** (S256) with a **loopback redirect** (`http://localhost:PORT/callback`). No `client_secret` is sent by the plugin (public client) | yes — network capture |
| T5 | Tokens are cached in the **OS keyring** (not a plain file). If the keyring is unavailable, the plugin falls back to a 0600 file at `~/.config/kubedash/tokens/` | yes — runtime |
| T6 | On token expiry, the plugin refreshes silently (no browser). On refresh failure, it opens the browser for re-auth | yes — runtime |
| T7 | The plugin validates the server's TLS certificate against the system CA store. `--insecure-skip-tls-verify` is available but **logged as a warning** to stderr | no — code read |
| T8 | The `ExecCredential` output includes `expirationTimestamp` (RFC3339) so kubectl can proactively re-auth before expiry | no — diff read |
| T9 | The server can **rotate** the `client_id` / `issuer` without users changing their kubeconfig. Old tokens remain valid until their natural expiry | yes — runtime |
| T10 | The plugin binary is a **single static binary** (CGO disabled) that runs on macOS (amd64, arm64), Linux (amd64, arm64), and Windows (amd64) with zero dependencies | yes — build + run on each OS |

### Artifacts

| # | Artifact |
|---|---|
| A1 | `cli/main.go` — entrypoint, cobra CLI, subcommands (`get-token`, `clean`, `setup`, `version`) |
| A2 | `cli/pkg/config/fetch.go` — `FetchAuthConfig(server, cluster) (AuthConfig, error)` |
| A3 | `cli/pkg/oidc/flow.go` — PKCE browser flow (auth code + PKCE S256, loopback redirect) |
| A4 | `cli/pkg/oidc/refresh.go` — silent token refresh |
| A5 | `cli/pkg/cache/keyring.go` — OS keyring read/write (with file fallback) |
| A6 | `cli/pkg/output/exec_credential.go` — `ExecCredential` JSON marshal |
| A7 | `backend/app/api/kubectl_auth.py` — Smorest `Api` for `/kubectl/auth/*` |
| A8 | `backend/app/services/kubectl_auth.py` — server-side SSO config resolution |
| A9 | `charts/kubedash/templates/kubectl-auth-configmap.yaml` — Helm: SSO config as ConfigMap |
| A10 | `Makefile` — cross-compile targets for 5 OS/arch combos |
| A11 | `.krew.yaml` — Krew manifest |
| A12 | `docs/setup.md` — user + admin setup guide |

### Key links

| # | Link |
|---|---|
| L1 | Plugin `get-token` → `GET /kubectl/auth/config` → OIDC provider → token → `ExecCredential` stdout → kubectl → K8s API server |
| L2 | Server `kubectl_auth` service → `clusters` table (which IdP config applies to which cluster) → `AuthConfig` response |
| L3 | Helm `kubectl-auth-configmap` → server env/config → `kubectl_auth` service (SSO config is set once by the admin, not per-user) |
| L4 | Plugin keyring cache → `get-token` (silent return if valid) → refresh → re-auth (browser) |

### One-way-door decisions

> ⚠ **OD-1:** The `ExecCredential` JSON shape is a **K8s API contract** (`client.authentication.k8s.io/v1`). Breaking it means kubectl rejects the token. The plugin must output exactly the shape defined by the K8s API. *Task 1 tests this.*
>
> ⚠ **OD-2:** The server endpoint `GET /kubectl/auth/config` response shape is a **plugin↔server contract**. Changing it is a breaking change for all installed plugins. Version the endpoint (`/kubectl/auth/v1/config`) from day one. *Task 3.*
>
> ⚠ **OD-3:** The keyring service name (`kubedash`) is **embedded in the user's OS keyring**. Changing it means orphaned entries. *Task 5.*

---

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| **TLS to server** | Applicable — the plugin talks to the KubeDash API over HTTPS | Validate cert against system CA store. `--insecure-skip-tls-verify` available but warns to stderr. No self-signed certs in prod. | Unit: mock server with self-signed cert → plugin fails without flag, succeeds with flag + warning |
| **OIDC redirect URI** | Applicable — PKCE loopback redirect must be bound to 127.0.0.1 only | Bind the callback HTTP server to `127.0.0.1:0` (ephemeral port). Reject non-loopback. | Unit: redirect to `http://192.168.1.5:PORT/cb` → plugin rejects |
| **Token at rest** | Applicable — ID + refresh tokens stored locally | OS keyring (encrypted at rest by the OS). Fallback: 0600 file in `~/.config/kubedash/tokens/`. Never in kubeconfig. | Unit: keyring mock stores token → file not created. Keyring unavailable → file created with 0600 perms |
| **Token in transit (plugin→kubectl)** | Applicable — `ExecCredential` JSON on stdout | kubectl reads stdout over a pipe (not a shared medium). The token is in memory only. No logging of the token to stderr. | Unit: capture stderr during `get-token` → no `id_token` or `refresh_token` substring |
| **SSO config leakage** | Applicable — the whole point of this design | `AuthConfig` is fetched over TLS from the server. Not in kubeconfig, not in args, not in env. The plugin does not print it (except `setup --debug`). | Unit: `get-token` args contain only `--server` + `--cluster-name`. `ps aux` shows no `oidc-` flags |
| **Server-side config tampering** | Applicable — an attacker who controls the KubeDash server can issue tokens | The server's OIDC `client_id` is registered with the IdP. The IdP validates the `aud` claim. The K8s API server validates the `iss` + `aud` + signature of the ID token. The server is a *proxy*, not the trust anchor. | Integration: server returns a token with wrong `aud` → K8s API rejects |
| **Binary tampering** | Applicable — a replaced plugin binary can exfiltrate tokens | Ship via Krew (checksummed), Homebrew (formula), GitHub Releases (SHA256). Document `shasum -a 256` verification. | Doc: install guide includes checksum verification step |
| **Concurrent `get-token` calls** | Applicable — kubectl may invoke the plugin in parallel | Use a file lock (or keyring CAS) on the token cache. Second call waits or returns the cached token. | Unit: two goroutines call `get-token` simultaneously → one does the flow, the other reads the cache |

---

## File Structure

```
KubeDash/
├── cli/                          ← NEW: Go kubectl plugin
│   ├── main.go                   ← cobra root, version, subcommands
│   ├── go.mod                    ← module: github.com/org/kubedash-cli
│   ├── go.sum
│   ├── pkg/
│   │   ├── config/
│   │   │   ├── fetch.go          ← FetchAuthConfig(server, cluster)
│   │   │   └── types.go          ← AuthConfig struct (server response)
│   │   ├── oidc/
│   │   │   ├── flow.go           ← PKCE browser flow (auth code + S256)
│   │   │   ├── refresh.go        ← silent token refresh
│   │   │   └── pkce.go           ← code_verifier + code_challenge (S256)
│   │   ├── cache/
│   │   │   ├── keyring.go        ← OS keyring (zalando/go-keyring)
│   │   │   ├── file.go           ← 0600 file fallback
│   │   │   └── cache.go          ← interface + selector (keyring > file)
│   │   ├── output/
│   │   │   └── exec_credential.go← ExecCredential JSON marshal
│   │   └── httpclient/
│   │       └── client.go         ← TLS-configured HTTP client
│   ├── cmd/
│   │   ├── get_token.go          ← "kubedash get-token" subcommand
│   │   ├── clean.go              ← "kubedash clean" (delete cache)
│   │   ├── setup.go              ← "kubedash setup" (debug: dump claims)
│   │   └── version.go            ← "kubedash version"
│   ├── internal/
│   │   └── testutil/
│   │       └── mock_oidc.go      ← in-process OIDC provider for tests
│   ├── testdata/
│   │   └── kubeconfig.yaml       ← sample kubeconfig for integration tests
│   ├── Makefile                  ← cross-compile (5 targets)
│   ├── .krew.yaml                ← Krew manifest
│   └── README.md
├── backend/
│   └── app/
│       ├── api/
│       │   └── kubectl_auth.py   ← NEW: Smorest Api for /kubectl/auth/*
│       ├── services/
│       │   └── kubectl_auth.py   ← NEW: SSO config resolution
│       └── schemas/
│           └── kubectl_auth.py   ← NEW: Pydantic AuthConfig model
├── charts/kubedash/
│   └── templates/
│       └── kubectl-auth-configmap.yaml  ← NEW: SSO config ConfigMap
└── docs/
    └── kubectl-plugin.md         ← NEW: user + admin setup guide
```

---

## Tasks

### Task 1 — Door check: plugin skeleton + ExecCredential output

**Goal:** A Go binary that accepts `--server` + `--cluster-name`, hits a mock server, and prints valid `ExecCredential` JSON. This proves the K8s credential-plugin protocol works.

**Files:**
- `cli/main.go` — cobra root, `get-token` subcommand stub
- `cli/cmd/get_token.go` — flag parsing, calls `runGetToken()`
- `cli/pkg/output/exec_credential.go` — `ExecCredential` struct + `Marshal()`
- `cli/pkg/config/types.go` — `AuthConfig` struct
- `cli/pkg/config/fetch.go` — `FetchAuthConfig()` (returns a hardcoded config for now)
- `cli/go.mod` — module init, deps

**Steps:**
1. `go mod init github.com/org/kubedash-cli`
2. Add deps: `cobra`, `k8s.io/client-authentication` (for `ExecCredential` types)
3. Define `ExecCredential` struct matching `client.authentication.k8s.io/v1`:
   ```go
   type ExecCredential struct {
       APIVersion string         `json:"apiVersion"` // "client.authentication.k8s.io/v1"
       Kind       string         `json:"kind"`       // "ExecCredential"
       Status     ExecStatus     `json:"status"`
   }
   type ExecStatus struct {
       Username            string `json:"username"`
       ExpirationTimestamp *string `json:"expirationTimestamp,omitempty"`
       Token               string `json:"token"`
   }
   ```
4. Implement `get-token` subcommand: parse `--server`, `--cluster-name`, call `FetchAuthConfig()`, print `ExecCredential` JSON to stdout.
5. **RED test:** run the binary, pipe stdout to `jq .`, verify `apiVersion` == `"client.authentication.k8s.io/v1"`, `kind` == `"ExecCredential"`, `status.token` is non-empty.
6. **GREEN:** make the test pass.

**Commit:** `feat(cli): plugin skeleton with ExecCredential output`

---

### Task 2 — Server endpoint: `GET /kubectl/auth/config`

**Goal:** The KubeDash API serves SSO config for a cluster. The admin configures it once (via Helm ConfigMap); the plugin fetches it per-cluster.

**Files:**
- `backend/app/schemas/kubectl_auth.py` — Pydantic `AuthConfig` model
- `backend/app/services/kubectl_auth.py` — `get_auth_config(cluster_name) -> AuthConfig`
- `backend/app/api/kubectl_auth.py` — Smorest `Api` for `/kubectl/auth/v1/config`
- `charts/kubedash/templates/kubectl-auth-configmap.yaml` — ConfigMap template

**Steps:**
1. Define `AuthConfig` Pydantic model:
   ```python
   class AuthConfig(BaseModel):
       issuer: str          # e.g. "https://login.example.com"
       client_id: str       # e.g. "kubedash-public-client"
       token_url: str
       auth_url: str
       scopes: list[str]    # e.g. ["openid", "email", "profile"]
       expiry: int          # seconds; how long the ID token is valid
   ```
2. Implement `kubectl_auth.py` service: read SSO config from the `clusters` table (column `oidc_config: JSONB`) or from a ConfigMap-mounted env var. Return the config for the given cluster name. 404 if cluster not found.
3. Implement the Smorest `Api`:
   ```python
   class KubectlAuthApi(Api):
       resources_namespace = "kubectl_auth"
       tags = ["Kubectl Auth"]
       
       @blp.route("/kubectl/auth/v1/config", methods=["GET"])
       @blp.arguments(ClusterQuery)  # {cluster: str}
       @blp.response(HTTPStatus.OK, AuthConfig)
       @blp.response(HTTPStatus.NOT_FOUND, "CLUSTER_NOT_FOUND")
       def get_config(self, args):
           return kubectl_auth.get_auth_config(args.cluster)
   ```
4. **No auth required** for this endpoint (the plugin may not have a token yet — it's *bootstrapping* auth). But it IS behind TLS + rate-limited. The config is not secret (issuer + client_id are public in a PKCE flow).
5. Helm ConfigMap:
   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: kubedash-kubectl-auth
   data:
     # JSON: cluster_name -> AuthConfig
     production: |
       {"issuer":"https://login.example.com","client_id":"kubedash-prod","token_url":"...","auth_url":"...","scopes":["openid","email"],"expiry":3600}
     staging: |
       {"issuer":"https://login-staging.example.com","client_id":"kubedash-staging",...}
   ```
6. **RED test:** `GET /kubectl/auth/v1/config?cluster=production` returns 200 + valid JSON. `?cluster=nonexistent` returns 404.
7. **GREEN:** make the test pass.

**Commit:** `feat(backend): /kubectl/auth/v1/config endpoint`

> ⚠ **OD-2:** The response shape is the plugin↔server contract. Versioned at `/v1/`.

---

### Task 3 — PKCE browser flow

**Goal:** The plugin performs a full OIDC Authorization Code + PKCE (S256) flow with a loopback redirect. No `client_secret`.

**Files:**
- `cli/pkg/oidc/pkce.go` — `GenerateCodeVerifier()`, `CodeChallenge(verifier)`
- `cli/pkg/oidc/flow.go` — `RunBrowserFlow(cfg AuthConfig) (IDToken, RefreshToken, error)`
- `cli/internal/testutil/mock_oidc.go` — in-process OIDC provider (for tests)

**Steps:**
1. Implement PKCE:
   ```go
   func GenerateCodeVerifier() (string, error)  // 43-128 chars, unreserved
   func CodeChallenge(verifier string) string    // BASE64URL(SHA256(verifier))
   ```
2. Implement the browser flow:
   - Generate `code_verifier` + `code_challenge`.
   - Generate `state` (16 random bytes, hex).
   - Start an HTTP listener on `127.0.0.1:0` (ephemeral port).
   - Build the auth URL: `cfg.auth_url?response_type=code&client_id=...&redirect_uri=http://127.0.0.1:PORT/cb&scope=...&state=...&code_challenge=...&code_challenge_method=S256`.
   - Open the browser (`github.com/pkg/browser`).
   - Wait for the callback (30 s timeout). Validate `state`. Extract `code`.
   - Exchange `code` + `code_verifier` at `cfg.token_url` for `id_token` + `refresh_token`.
   - Return the tokens.
3. **Security:**
   - Redirect URI is **always** `http://127.0.0.1:PORT/cb` (loopback only).
   - `state` is validated (CSRF).
   - `code_verifier` is never sent before the exchange.
   - The callback server closes immediately after one request.
4. **RED test (unit):**
   - Mock OIDC provider (in-process) issues an `id_token` + `refresh_token`.
   - `RunBrowserFlow` returns the tokens.
   - `code_challenge` in the auth URL == `BASE64URL(SHA256(code_verifier))`.
   - `state` in the callback matches the `state` in the auth URL.
   - Redirect to `192.168.1.5:PORT/cb` → error.
5. **GREEN:** make the tests pass.

**Commit:** `feat(cli): PKCE browser flow with loopback redirect`

---

### Task 4 — Token cache (keyring + file fallback)

**Goal:** Tokens are stored in the OS keyring. Fallback to a 0600 file if the keyring is unavailable.

**Files:**
- `cli/pkg/cache/cache.go` — `TokenCache` interface, `NewTokenCache()` selector
- `cli/pkg/cache/keyring.go` — `KeyringCache` (zalando/go-keyring)
- `cli/pkg/cache/file.go` — `FileCache` (0600, `~/.config/kubedash/tokens/`)

**Steps:**
1. Define the interface:
   ```go
   type TokenCache interface {
       Get(cluster string) (*TokenPair, error)
       Set(cluster string, tp *TokenPair) error
       Delete(cluster string) error
   }
   type TokenPair struct {
       IDToken      string
       RefreshToken string
       ExpiresAt    time.Time
   }
   ```
2. `KeyringCache`: uses `github.com/zalando/go-keyring`. Service = `"kubedash"`, User = `clusterName`.
   > ⚠ **OD-3:** Service name is `"kubedash"` — baked into the user's keyring.
3. `FileCache`: path = `~/.config/kubedash/tokens/<clusterName>.json`, perms `0600`. JSON: `{"id_token":"...","refresh_token":"...","expires_at":"RFC3339"}`.
4. `NewTokenCache()`: try keyring. If `go-keyring` reports "no keyring available" (headless Linux without a daemon), fall back to `FileCache`. Log the fallback to stderr.
5. **Concurrency:** use a `sync.Mutex` per cluster name. Second `get-token` call waits for the first to finish, then reads the cache.
6. **RED test:**
   - Keyring available → `Set` + `Get` round-trips. File not created.
   - Keyring unavailable → `Set` + `Get` round-trips via file. File perms == 0600.
   - Two goroutines `Set` simultaneously → no data race (run under `-race`).
7. **GREEN:** make the tests pass.

**Commit:** `feat(cli): token cache with keyring + file fallback`

---

### Task 5 — Silent refresh + re-auth

**Goal:** On token expiry, refresh silently. On refresh failure, open the browser.

**Files:**
- `cli/pkg/oidc/refresh.go` — `RefreshToken(cfg, refreshToken) (IDToken, NewRefreshToken, error)`
- `cli/cmd/get_token.go` — updated: check cache → refresh → re-auth

**Steps:**
1. Implement `RefreshToken`:
   - `POST cfg.token_url` with `grant_type=refresh_token`, `client_id`, `refresh_token`.
   - Return the new `id_token` (+ rotated `refresh_token` if present).
   - On 400/401 → return `ErrRefreshFailed` (caller opens browser).
2. Update `get-token` logic:
   ```
   1. cache.Get(cluster)
   2. if valid (not expired, > 30s margin): return ExecCredential
   3. if expired but refresh_token present: RefreshToken()
      - success: cache.Set(), return ExecCredential
      - failure: fall through to step 4
   4. RunBrowserFlow() → cache.Set() → return ExecCredential
   ```
3. **RED test:**
   - Cached token valid → no HTTP calls, returns immediately.
   - Cached token expired, refresh succeeds → 1 HTTP call (token_url), returns new token.
   - Cached token expired, refresh fails → browser flow opens (mock), returns new token.
4. **GREEN:** make the tests pass.

**Commit:** `feat(cli): silent token refresh with browser re-auth fallback`

---

### Task 6 — Wire it all together + `ExecCredential` output

**Goal:** `get-token` end-to-end: fetch config → check cache → refresh/re-auth → print `ExecCredential`.

**Files:**
- `cli/cmd/get_token.go` — full implementation
- `cli/pkg/httpclient/client.go` — TLS-configured `*http.Client`

**Steps:**
1. Implement `httpclient.New(serverURL, insecureSkipTLS bool)`:
   - Validate cert against system CA store.
   - `--insecure-skip-tls-verify` sets `InsecureSkipVerify: true` + logs a warning to stderr.
   - 30 s timeout.
2. Wire `get-token`:
   ```go
   func runGetToken(cmd *cobra.Command, args []string) error {
       server, _ := cmd.Flags().GetString("server")
       cluster, _ := cmd.Flags().GetString("cluster-name")
       insecure, _ := cmd.Flags().GetBool("insecure-skip-tls-verify")
       
       client := httpclient.New(server, insecure)
       cfg, err := config.FetchAuthConfig(client, cluster)
       // ...
       cache := cache.NewTokenCache()
       tp, err := cache.Get(cluster)
       // ... (refresh / re-auth logic from Task 5)
       
       cred := output.ExecCredential{
           APIVersion: "client.authentication.k8s.io/v1",
           Kind:       "ExecCredential",
           Status:     output.ExecStatus{
               Username:            extractSub(tp.IDToken),
               ExpirationTimestamp: rfc3339(tp.ExpiresAt),
               Token:               tp.IDToken,
           },
       }
       json.NewEncoder(os.Stdout).Encode(cred)
   }
   ```
3. **RED test (integration):**
   - Mock server + mock OIDC provider.
   - Run `kubedash get-token --server=http://localhost:PORT --cluster-name=test`.
   - Capture stdout. Parse as `ExecCredential`. Verify `apiVersion`, `kind`, `status.token` is a valid JWT (3 parts, base64).
   - Run `kubectl --kubeconfig=testdata/kubeconfig.yaml get pods` (against a kind cluster with the mock IdP). Verify it works.
4. **GREEN:** make the test pass.

**Commit:** `feat(cli): get-token end-to-end with ExecCredential output`

> ⚠ **OD-1:** The `ExecCredential` shape is a K8s API contract. This task verifies it against a real `kubectl`.

---

### Task 7 — `clean` + `setup` + `version` subcommands

**Goal:** Utility commands for the user.

**Files:**
- `cli/cmd/clean.go` — delete token cache for a cluster (or all)
- `cli/cmd/setup.go` — debug: fetch config, dump ID token claims
- `cli/cmd/version.go` — print version + commit + build date

**Steps:**
1. `clean`:
   - `kubedash clean` → delete all clusters.
   - `kubedash clean --cluster-name=prod` → delete one.
   - Prints "Deleted token cache for <cluster> from <keyring|file>".
2. `setup`:
   - `kubedash setup --server=URL --cluster-name=NAME`
   - Fetches `AuthConfig`, performs the flow, prints the ID token claims (JSON) to stdout.
   - `--debug` flag: also prints the `AuthConfig` (issuer, client_id, scopes).
3. `version`:
   - `kubedash version` → `kubedash v1.0.0 (commit: abc123, built: 2026-10-17)`.
   - Version info injected via `ldflags` at build time.
4. **RED tests:**
   - `clean` deletes the keyring entry. Verify with `go-keyring.Get`.
   - `setup` prints JSON claims. Verify `sub`, `iss`, `aud` fields.
   - `version` prints the injected version.
5. **GREEN:** make the tests pass.

**Commit:** `feat(cli): clean, setup, version subcommands`

---

### Task 8 — Cross-compile + Krew + release

**Goal:** Build static binaries for 5 targets. Ship via Krew + GitHub Releases.

**Files:**
- `cli/Makefile` — cross-compile targets
- `cli/.krew.yaml` — Krew manifest
- `.github/workflows/cli-release.yaml` — CI: build + checksums + GitHub Release

**Steps:**
1. `Makefile`:
   ```makefile
   VERSION ?= $(shell git describe --tags --always)
   COMMIT  ?= $(shell git rev-parse --short HEAD)
   DATE    ?= $(shell date -u +%Y-%m-%d)
   LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
   
   .PHONY: build
   build:
     go build -ldflags "$(LDFLAGS)" -o dist/kubectl-kubedash .
   
   .PHONY: cross
   cross:
     GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/kubectl-kubedash-darwin-amd64 .
     GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/kubectl-kubedash-darwin-arm64 .
     GOOS=linux  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/kubectl-kubedash-linux-amd64 .
     GOOS=linux  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/kubectl-kubedash-linux-arm64 .
     GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/kubectl-kubedash-windows-amd64.exe .
     sha256sum dist/* > dist/SHA256SUMS
   ```
   - `CGO_ENABLED=0` for all targets (static binary, no cgo deps).
2. `.krew.yaml`:
   ```yaml
   apiVersion: krew.googlecontainertools.github.com/v1alpha2
   kind: Plugin
   metadata:
     name: kubedash
     version: v1.0.0
     os: [darwin, linux, windows]
     arch: [amd64, arm64]
   spec:
     homepage: https://github.com/org/kubedash
     shortDescription: KubeDash OIDC SSO for kubectl
     description: Server-managed OIDC authentication for kubectl via KubeDash.
     platform:
     - selector: { os: darwin, arch: amd64 }
       url: https://github.com/org/kubedash/releases/download/v1.0.0/kubectl-kubedash-darwin-amd64
       sha256: <hash>
     # ... (other 4 targets)
   ```
3. CI workflow: on tag `cli/v*`, run `make cross`, upload `dist/` to GitHub Release, update `.krew.yaml` checksums.
4. **RED test:** run `make cross` in CI. Verify 5 binaries + SHA256SUMS. Run `file dist/*` → "ELF 64-bit" / "Mach-O 64-bit" / "PE32+".
5. **GREEN:** make the test pass.

**Commit:** `feat(cli): cross-compile + Krew manifest + release workflow`

---

### Task 9 — Admin setup guide + Helm wiring

**Goal:** The admin configures SSO once. The user installs the plugin and adds one kubeconfig entry.

**Files:**
- `docs/kubectl-plugin.md` — full guide
- `charts/kubedash/values.yaml` — `kubectlAuth` section
- `charts/kubedash/templates/kubectl-auth-configmap.yaml`

**Steps:**
1. Write `docs/kubectl-plugin.md`:
   - **Admin setup:**
     1. Register a public OIDC client with the IdP (redirect URI: `http://127.0.0.1/callback` — or a range of loopback URIs).
     2. Configure the K8s API server's `--oidc-*` flags (issuer, client-id, username-claim, etc.) to match the IdP.
     3. `helm upgrade kubedash ... --set kubectlAuth.production.issuer=... --set kubectlAuth.production.clientId=...`
   - **User setup:**
     1. `kubectl krew install kubedash` (or `brew install kubedash`)
     2. Add to `~/.kube/config`:
        ```yaml
        users:
          - name: kubedash
            user:
              exec:
                apiVersion: client.authentication.k8s.io/v1
                command: kubectl
                args:
                  - kubedash
                  - get-token
                  - --server=https://kubedash.example.com
                  - --cluster-name=production
        ```
     3. `kubectl get pods` → browser opens → log in → done.
   - **Security notes:**
     - No SSO config in kubeconfig.
     - Tokens in OS keyring.
     - Server is a proxy, not the trust anchor (IdP + K8s API server validate the token).
     - Checksum verification for the binary.
2. Helm `values.yaml`:
   ```yaml
   kubectlAuth:
     enabled: true
     clusters:
       production:
         issuer: https://login.example.com
         clientId: kubedash-prod
         scopes: [openid, email, profile]
         expiry: 3600
       staging:
         issuer: https://login-staging.example.com
         clientId: kubedash-staging
         scopes: [openid, email]
         expiry: 1800
   ```
3. ConfigMap template renders the `clusters` map as JSON in the ConfigMap. The backend reads it.
4. **RED test:** `helm template` renders the ConfigMap with the expected JSON. Backend test: `GET /kubectl/auth/v1/config?cluster=production` returns the config from the ConfigMap.
5. **GREEN:** make the test pass.

**Commit:** `docs: kubectl plugin setup guide + Helm wiring`

---

### Task 10 — Integration test: kubectl + kind + mock IdP

**Goal:** End-to-end: `kubectl get pods` triggers the plugin, which does the OIDC flow, and the K8s API server accepts the token.

**Files:**
- `cli/testdata/kubeconfig.yaml` — sample kubeconfig pointing at the plugin
- `cli/internal/testutil/mock_oidc.go` — full in-process OIDC provider (discovery, auth, token, userinfo)
- `cli/integration_test.go` — Go test that spawns `kubectl` against a kind cluster

**Steps:**
1. Build the mock OIDC provider:
   - `GET /.well-known/openid-configuration` → discovery doc.
   - `GET /auth` → 302 to callback with `code` + `state`.
   - `POST /token` → `id_token` (JWT, HS256, `sub`/`iss`/`aud`/`exp` claims) + `refresh_token`.
   - `GET /userinfo` → `{sub, email, name}`.
2. `integration_test.go`:
   - Skip if `KIND_CLUSTER` env is not set.
   - Start the mock OIDC provider on `localhost:9000`.
   - Start the KubeDash API (test mode) on `localhost:9001` with the mock config.
   - Create a kind cluster with `--oidc-issuer-url=http://localhost:9000` + `--oidc-client-id=kubedash-test`.
   - Run `kubectl --kubeconfig=testdata/kubeconfig.yaml get pods` with `BROWSER=true` (no-op browser).
   - Assert: exit code 0, stdout contains "NAME" (pod list header).
3. **RED test:** the integration test fails (no mock provider yet).
4. **GREEN:** make the test pass.

**Commit:** `test(cli): integration test with kubectl + kind + mock IdP`

---

## Self-Review

**1. Spec coverage:** The briefing (to be written) will specify: (a) server-managed SSO config, (b) PKCE flow, (c) keyring cache, (d) ExecCredential output, (e) cross-platform binary, (f) Krew distribution. All covered by Tasks 1–10.

**2. Must-haves coverage:**
- T1 → Task 1 + Task 10 (door check + integration)
- T2 → Task 9 (kubeconfig in docs has no `--oidc-*` args)
- T3 → Task 2 (server endpoint)
- T4 → Task 3 (PKCE + loopback)
- T5 → Task 4 (keyring + file fallback)
- T6 → Task 5 (refresh + re-auth)
- T7 → Task 6 (TLS validation + `--insecure-skip-tls-verify`)
- T8 → Task 1 (`expirationTimestamp` in `ExecCredential`)
- T9 → Task 2 (server rotates config; old tokens valid until expiry)
- T10 → Task 8 (cross-compile, 5 targets, CGO disabled)

**3. One-way-door completeness:**
- OD-1 (ExecCredential shape) → Task 1 + Task 10
- OD-2 (server endpoint contract) → Task 2
- OD-3 (keyring service name) → Task 4

**4. Placeholder scan:** No TBD, "implement later", or "similar to Task N" in any task.

**5. Type consistency:** `AuthConfig` is defined once in `cli/pkg/config/types.go` (Go) and `backend/app/schemas/kubectl_auth.py` (Python). Field names match: `issuer`, `client_id`, `token_url`, `auth_url`, `scopes`, `expiry`. `ExecCredential` is defined once in `cli/pkg/output/exec_credential.go`. `TokenPair` is defined once in `cli/pkg/cache/cache.go`.

---

## Owed-Decision Gate

**Every value the build must produce has a named source:**

| Value | Source |
|---|---|
| `issuer`, `client_id`, `token_url`, `auth_url`, `scopes`, `expiry` | Admin configures via Helm `kubectlAuth.clusters.<name>.*` → ConfigMap → server endpoint |
| `id_token`, `refresh_token` | OIDC provider (via PKCE flow) |
| `username` (in `ExecCredential`) | `sub` claim of the `id_token` (extracted by the plugin) |
| `expirationTimestamp` | `exp` claim of the `id_token` (extracted by the plugin) |
| Keyring service name | Hardcoded `"kubedash"` (OD-3) |
| Fallback file path | `~/.config/kubedash/tokens/<cluster>.json` (XDG convention) |
| Binary name | `kubectl-kubedash` (kubectl plugin naming convention) |

**No owed decisions.** The design is complete.

---

## Plan Review

**Verdict: READY FOR EXECUTION**

- The door check (Task 1) is concrete and falsifiable.
- Each task is independently testable with its own RED→GREEN cycle.
- The threat matrix covers all boundaries with concrete RED tests.
- No placeholders. Types are consistent across tasks.
- The one-way-door decisions are flagged and tested.

---

## Execution Handoff

**Slicing:** 10 tasks → invoke `skillgrid:slicing` to produce `tasks.md` with dependency edges and execution waves.

**Waves (suggested):**
- **Wave 1:** Task 1 (door check) — must pass before anything else.
- **Wave 2:** Task 2 (server endpoint) + Task 3 (PKCE flow) — independent.
- **Wave 3:** Task 4 (cache) + Task 7 (subcommands) — independent of each other.
- **Wave 4:** Task 5 (refresh) + Task 6 (wire together) — Task 6 depends on 2, 3, 4, 5.
- **Wave 5:** Task 8 (cross-compile) + Task 9 (docs + Helm) — independent.
- **Wave 6:** Task 10 (integration test) — depends on all.

**Execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks.
2. **Inline Execution** — batch execution with checkpoints.

**Which approach?**
