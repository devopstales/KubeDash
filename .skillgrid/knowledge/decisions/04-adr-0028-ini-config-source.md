# Configuration source: kubedash.ini as the primary config surface (4.1 format), env as override, no hard-coded defaults

---
status: "accepted"
date: 2026-10-26
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash 5.0 reads all configuration from environment variables (a
pydantic-settings `Settings` class, `backend/app/core/config.py`, `env_prefix=
KUBEDASH_`, optional `.env`) with hard-coded fallback defaults in the class body.
This diverges from the operator-facing 4.1 product, which is configured through
a single human-editable INI file, `src/kubedash/kubedash.ini` (template
`kubedash.ini.example`), read with `configparser` — with no environment
override path at all.

For a project whose stated direction is 4.1 information- and behavior-parity
(ADR-0022 sidebar, ADR-0023/0024 surfaces), the *configuration* story is the one
operator-facing surface that never got parity. An operator moving from 4.1 to
5.0 finds the file they know gone and a wall of `KUBEDASH_*` env vars in its
place. Two problems drive this decision:

1. **Continuity.** The 4.1 INI is the muscle memory. Re-introducing it as the
   primary surface keeps the upgrade path legible.
2. **Silent defaults are a foot-gun.** The current `Settings` carries dev
   fallbacks (a 32-byte dev JWT/encryption key, a localhost Postgres/Redis URL,
   `app_mode=development`). In production those silently-active defaults are
   exactly the kind of "forgot to set it" bug this codebase already guards
   against elsewhere (`cookie_secure` defaults `True` so a forgotten value fails
   closed — ADR-0025/0027). Configuration that *looks* configured but is really
   a default is the anti-pattern to eliminate.

The question this ADR decides: what is the configuration source of record for
5.0, and in what order are values resolved.

#### Decision Drivers

- **4.1 operator parity** — the INI sections an operator already knows
  (`[database]`, `[remote_cache]`, `[sso_settings]`, `[monitoring]`, `[security]`)
  must map 1:1 so an existing `kubedash.ini` carries over with minimal edits.
- **No silent defaults** — a configuration value must come from the INI or the
  environment, never from a hard-coded in-code fallback. A missing required
  value fails fast at boot, matching the fail-closed posture of ADR-0025/0027.
- **Keep the K8s 12-factor escape hatch** — the Helm chart (ADR-0006 single
  container) must be able to inject per-release values without re-rendering an
  INI in Git, so env remains a supported, *higher-priority* source than the
  file.
- **One-way-door keys stay first-class** — the kubeconfig encryption key
  (ADR-0002) and the JWT signing key must be explicit operator values, never a
  baked-in default.
- **Air-gap (ADR-0020)** — adding a `configparser` read introduces no runtime
  egress; no new dependency (stdlib only).
- **Testability** — tests must inject configuration without writing files; the
  existing `config_overrides` seam in `create_app` and the `monkeypatch.setenv`
  usage in the suite must keep working under the new resolution model.

#### Considered Options

- **INI as the only source (no env, no defaults).** Cleanest mental model and
  the most literal 4.1 parity. Rejected: it breaks the chart's ability to
  inject secrets and per-release values without templating an INI, and it
  removes the standard K8s env seam that the rest of the platform already
  relies on.

- **INI > env, no hard-coded defaults (chosen).** INI is the operator-facing
  primary surface (4.1 format). Env (`KUBEDASH_*`) overrides the INI and is the
  chart's injection path. Neither source may fall back to an in-code default; a
  missing required value fails fast at boot. Preserves 4.1 continuity *and* the
  12-factor path, and kills the silent-default foot-gun.

- **INI > env > keep current code defaults.** Least disruptive to the running
  dev loop and the existing test suite, but keeps the exact foot-gun this
  decision exists to remove, and is only half-parity with 4.1 (4.1 also has no
  silent defaults for operator keys). Rejected.

#### Decision Outcome

**Chosen option: INI > env, no hard-coded defaults.**

Configuration is resolved, per key, in this order:

1. **`kubedash.ini`** — the primary operator-facing source. Shipped as
   `kubedash.ini.example` (sane, commented, `app_mode=development`, empty
   operator secrets) and read from a configurable location
   (`KUBEDASH_CONFIG` / `KUBEDASH_CONFIG_FILE`, default `kubedash.ini`).
2. **Environment (`KUBEDASH_*`)** — overrides the INI for the same key. This is
   the chart's Secret/ConfigMap injection path. Env values are *not* a
   fallback: they win, but they do not fill a gap that the operator is expected
   to fill in the INI.
3. **No in-code default for operator values.** A required key absent from both
   sources fails boot with a named error. The only values that may carry a
   built-in default are *mode/behavior* knobs, not *identities/credentials*
   (e.g. `cookie_secure` may keep its fail-closed `True` default per
   ADR-0025; `app_mode` defaults to `development` in the shipped template).

INI schema (4.1 parity, minus the dropped plugin system):

| Section | Carries (5.0 field) | Notes |
|---|---|---|
| `[DEFAULT]` | `app_mode` → `flask_env` | `development` \| `production` |
| `[security]` | `admin_password` → bootstrap admin password; new `jwt_secret`, `secret_key` | JWT + kubeconfig-encryption keys move out of code defaults into the file |
| `[database]` | `type/host/name/user/password` (or `url`) → `database_url` | 5.0 is Postgres-only; `type=postgres`, sqlite dropped |
| `[remote_cache]` | redis host/port/db/password → `redis_url` | cache-time keys dropped (5.0 has no short/long cache) |
| `[sso_settings]` | `issuer_url/callback_url/scope/client_id/secret` → OIDC fields | 4.1 `secret` → `oidc_client_secret` |
| `[monitoring]` | `jaeger_enabled`, `jaeger_http_endpoint` | new 5.0 section (observability, ADR-0003) |
| `[k8s]` | **not 1:1** — see Consequences | 4.1 = one static cluster; 5.0 = multi-cluster registry (ADR-0002) |

The 5.0-only keys with no 4.1 home gain explicit INI sections rather than
staying env-only: `[deployment]` (`kubedash_role`, `kubedash_replica_id`,
`tls_edge`, `cookie_secure`, `plugin_server`) and `[bootstrap]`
(`bootstrap_admin_email`, `bootstrap_admin_password`) per ADR-0021. This
supersedes the *delivery mechanism* of ADR-0021 (env-driven bootstrap admin):
the values now live in the INI, env still overrides.

#### Consequences

- **Positive.** Operator parity with 4.1; a single editable file is the source
  of truth; silent-default bugs are class-eliminated (fail fast at boot); the
  chart keeps a clean env override path for secrets; stdlib-only, air-gap safe.

- **Negative / accepted trade-offs.**
  - **Migration cost.** The `Settings` class, the `create_app` override seam,
    every `get_settings()` consumer, the Taskfile, the chart, and the test
    fixtures (which inject env via `monkeypatch.setenv`) all change. This is a
    cross-cutting refactor, not a one-file swap.
  - **Two sources to reason about.** INI + env means precedence rules must be
    documented and the resolution code must be explicit and unit-tested.
  - **`[k8s]` is not 4.1.** 5.0's multi-cluster registry (clusters as DB rows,
    ADR-0002) has no single `[k8s]` cluster to configure. The 4.1 `[k8s]`
    section is **retired, not ported**: the admin cluster is still reached via
    `admin_kubeconfig` / in-cluster (ADR-0021), and member clusters are
    registered through the API/registry. We keep the *section name* documented
    as removed, so a 4.1 `kubedash.ini` that has `[k8s]` still loads (the
    section is simply ignored) instead of erroring.
  - **Secrets in a file.** `jwt_secret`, `secret_key`, OIDC secret, admin
    password now live in the INI. The chart must mount the file via a
    ConfigMap (non-secret) + Secret (secrets) or inject them via the env
    override path; the shipped example keeps them empty.

- **ADR interactions.** Supersedes-in-part the *delivery mechanism* of ADR-0021
  (bootstrap admin values: env → INI-primary, env-override). Does **not**
  supersede ADR-0002 (registry model), ADR-0006 (single container), ADR-0020
  (air-gap), or ADR-0025/0027 (cookie/TLS behavior — those fail-closed defaults
  are preserved as the only allowed in-code defaults). A new ADR is the right
  instrument: it is hard to reverse (touches every config consumer), surprising
  without context (why INI in a "modern" service?), and the product of a real
  trade-off (three precedence models considered).
