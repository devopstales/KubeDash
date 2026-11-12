# Plain-HTTP dev-stack default; TLS edge becomes the opt-in dev-stack-ssl

---
status: "accepted"
date: 2026-10-26
supersedes: ADR-0026
---

## Context and Problem Statement

ADR-0026 made the TLS edge the **default** `task dev-stack` path: the backend
serves :8443 over HTTPS, `KUBEDASH_COOKIE_SECURE=true`, `KUBEDASH_TLS_EDGE=true`,
and the cert files are a hard precondition — the stated point being that the
`Secure` cookie flag is honest in dev. That shipped two days before this ADR,
and the daily loop regressed:

1. **Cert friction is now in the critical path.** Every fresh checkout (and
   every cert regeneration) must run `task dev-tls-setup` (mkcert + a sudo
   `/etc/hosts` edit) before `task dev-stack` will start; otherwise it fails
   fast with a named fix. The plain-HTTP loop used to be zero-precondition.
2. **Host port collisions.** The edge binds host :443 and :80 — ports that
   are routinely occupied on a laptop (VPN clients, other containers), and
   that bind for **every** dev session, not just the TLS ones.
3. **The Secure-cookie argument applies only to the browser session leg.**
   The internal nginx→backend leg was HTTPS for the internal hop, but the
   flag the ADR was really protecting is the one the *browser* sees. On
   plain HTTP the honest state is `KUBEDASH_COOKIE_SECURE=false` (the flag
   off matches the transport); on TLS the honest state is `true`. Either
   mode can be honest — the flag follows the transport, not the default.

ADR-0026's *layers* (nginx edge, :8443 internal TLS, ProxyFix gated on
`KUBEDASH_TLS_EDGE`, the 4.1 security-header set) are all still correct and
staying. What is being revisited is only the **default**: which mode does a
bare `task dev-stack` start in.

## Considered Options

- **Keep ADR-0026's default (TLS edge on `dev-stack`).** Rejected for this
  stage of the project: the cert precondition and the :443/:80 host-port
  claims dominate the daily loop cost. The "honest Secure cookie" argument
  holds, but it can be had on demand instead of by default.
- **Plain HTTP as the default; TLS edge opt-in via a new `task dev-stack-ssl`.**
  Chosen. `dev-stack` starts :8080 plain (`KUBEDASH_COOKIE_SECURE=false` —
  honest for the transport, the same carve-out ADR-0026 already documented
  for `backend-run`), no cert precondition, no host :443/:80 bind. The
  existing TLS machinery (nginx service in compose, `dev/certs`, `:8443`
  backend, ProxyFix, headers) is reused as-is by `dev-stack-ssl`, which keeps
  ADR-0026's honest end-to-end TLS path available for the e2e-ssl backstop
  and for when the team wants the Strict-Transport-Security / Secure-cookie
  behavior in dev.
- **Keep both defaults and pick per-machine via env.** Rejected: two
  spellings for the same thing invites the "which one did I run" state; one
  default + one opt-in flag is the smaller surface.

## Decision Outcome

Chosen option: **plain-HTTP `dev-stack` default; TLS edge is the opt-in
`dev-stack-ssl`**, because the daily loop should have no preconditions and no
host :443/:80 binds, while the honest-TLS path stays one task away.

Concretely:

- `task dev-stack` — compose (data stores, **no** nginx) + `db upgrade` +
  leader backend on plain **http://localhost:8080** with
  `KUBEDASH_COOKIE_SECURE=false`, bootstrap admin, static dir. No cert check.
  Idempotent; leaves the backend running in the background.
- `task dev-stack-ssl` — same, but `compose up -d` **with** the nginx TLS
  edge, cert precondition (fail fast: `task dev-tls-setup`), leader backend
  on **:8443 over TLS** (`KUBEDASH_SSL_CERT/KEY`), `KUBEDASH_COOKIE_SECURE=true`,
  `KUBEDASH_TLS_EDGE=true`. Browser surface:
  `https://kubedash.dev.local:443`.
- `task dev-stack-down` — kills all dev backend ports (:8080, :8443, :8081,
  :8082) + `compose down`.
- The deleted `task dev-up-ssl` is subsumed: `dev-stack-ssl` already does the
  full `compose up -d`. `task dev-up` stays the data-stores-only fast path.
- `task e2e` targets the plain path (unchanged: :8080); `task e2e-ssl` targets
  the TLS path and now documents its `dev-stack-ssl` precondition.

### Consequences

- Good, because the zero-precondition daily loop is restored and host :443/:80
  are only bound when TLS is actually wanted.
- Good, because the `Secure` cookie stays honest in **both** modes — the flag
  now explicitly follows the transport (false on the plain path, true behind
  the edge), which is the invariant ADR-0026 was after, without forcing the
  whole edge on by default.
- Bad, because the default dev session no longer exercises HSTS / Secure
  cookies / ProxyFix; those are covered only when someone runs `dev-stack-ssl`
  + `e2e-ssl`. The e2e-ssl backstop exists for exactly that.
- Bad, because ADR-0026's Context argued the opposite default; its record is
  frozen and this ADR is the one that supersedes it (IRON RULE), so a future
  reader must read 0026 → 0027 in order.
