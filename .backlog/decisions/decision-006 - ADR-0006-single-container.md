---
id: decision-006
title: "ADR-0006 Single-container deployment (Gunicorn serves API + static SPA)"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/knowledge/decisions/04-adr-0006-single-container.md`

# Single-container deployment (Gunicorn serves API + static SPA)

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

Deployment shape for 5.0: a separate frontend container behind nginx,
or one container that serves both the API and the built SPA? The
product is one Helm install the operator runs; every extra container is
an extra failure mode, image, and cache layer.

#### Decision Drivers

- **The SPA is static.** A built `vite` bundle needs a file server, not
  a service.
- **One image, one upgrade unit.** The Helm chart deploys N replicas of
  a single Deployment; there is no separate UI workload to version.
- **The RQ worker must live with the app** (in-process, leader-gated —
  ADR-0007/0008), so a "backend container" already does two jobs.
- **No nginx inside the image.** TLS termination is an optional edge in
  front (ADR-0026/0027), not part of the container.

#### Considered Options

- **Multi-container** (frontend + API + worker). Rejected: extra
  images, CORS between UI and API origins, a cache layer in front of
  SSE, and three versioned artifacts for one product.
- **Single container (CHOSEN).** One multi-stage Dockerfile; Gunicorn
  serves `/api/v1/*` (Flask + Smorest), `/ws/*` (SocketIO), and the
  built SPA from `<KUBEDASH_HOME>/static` via a catch-all route
  (SPA fallback) registered after all API routes.

#### Decision Outcome

**Chosen option: single container; Gunicorn serves API + static SPA.**

- 3-stage Dockerfile: `frontend` (Node 20 → `vite build` → `dist/`),
  `deps` (Python 3.12 slim + uv frozen), `runtime` — which copies
  `dist/` → `static/`, runs non-root (`USER 10001`), and starts
  `gunicorn -w "$GUNICORN_WORKERS" --threads "$GUNICORN_THREADS"
  -b 0.0.0.0:8080 wsgi:wsgi`.
- The in-process RQ worker spawns from `wsgi.py` at startup, gated on
  `kubedash_role == "leader"` (ADR-0007/0008).
- Static caching: hashed assets served `Cache-Control: immutable`,
  `index.html` `no-cache` (SPA fallback); `/api/*` responses are
  `no-store` (ADR-0026/0027 header layer).

##### Consequences

- Good: one image/upgrade unit; no CORS (same origin for UI + API);
  trivial to run (`docker run` + PG + Redis).
- Bad: Gunicorn is the file server — asset serving and API share worker
  threads (mitigated by immutable asset caching); SSE must stay
  load-balancer-friendly (ADR-0009).
- Confirmation: `backend/tests/test_dockerfile.py` (USER/fixed-args
  pins), `test_static.py`, `test_app.py`.

#### Linking Decisions and Constraints

- ADR-0007 / ADR-0008 — the in-process, leader-gated RQ worker lives in
  this container.
- ADR-0025 — same-origin cookies make single-container the natural
  session shape.
- ADR-0027 — plain-HTTP dev-stack default vs. TLS edge opt-in.

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §7.1; verified against
`backend/Dockerfile` (stage names, `COPY --from=frontend /build/dist
./static`, CMD) on 2026-11-06.
