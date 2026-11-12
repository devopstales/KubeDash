---
id: decision-001
title: "ADR-0001 Flask + Flask-Smorest over FastAPI (sync WSGI, auto-OpenAPI, Pydantic-native schemas, SocketIO)"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/knowledge/decisions/04-adr-0001-flask-smorest.md`

# Flask + Flask-Smorest over FastAPI (sync WSGI, auto-OpenAPI, Pydantic-native schemas, SocketIO)

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

KubeDash 5.0 needed a REST framework for the multi-cluster dashboard
API. The 4.1 product was Flask + Jinja2 server-rendered; 5.0 moves the
UI to a React SPA but keeps the server stack recognizable to operators.
The question: which framework owns the API surface, and where does the
OpenAPI contract come from?

#### Decision Drivers

- **Sync WSGI is enough.** The workload is IO-bound fan-out to per-cluster
  `kubernetes` clients (a synchronous library) and to user-supplied
  observability backends. An event loop buys nothing while forcing
  `await` through a sync client library.
- **The OpenAPI contract must not drift.** The frontend TS types are
  generated from the spec (`openapi-typescript`), so the spec must be
  generated from the same Pydantic models the handlers validate against —
  not hand-maintained.
- **4.1 continuity.** Flask is the 4.1 runtime; operators know it, the
  deployment (Gunicorn) stays the same, and the error/audit conventions
  carry over.
- **Real-time still works.** Bidirectional exec/terminal needs WebSocket
  (SocketIO); SSE push is plain HTTP (ADR-0009).

#### Considered Options

- **FastAPI (async, Pydantic-native).** Rejected: the `kubernetes` client
  is synchronous; an async framework wraps it in thread pools anyway,
  and the 4.1→5.0 continuity argument falls away.
- **Flask + hand-written marshmallow schemas.** Rejected: two schema
  systems (Pydantic for validation, marshmallow for docs) would drift.
- **Flask 3 + Flask-Smorest (CHOSEN).** Smorest is a Flask extension that
  builds a REST API from `Api` subclasses with Pydantic-native
  `arguments`/`response` schemas and auto-generates OpenAPI 3.0. One
  schema system, one source of truth for validation *and* docs.

#### Decision Outcome

**Chosen option: Flask 3 + Flask-Smorest, Pydantic schemas, SocketIO for
bidirectional streams.**

- Every domain is one `flask_smorest.Api` subclass in
  `backend/app/api/<domain>.py` (≤ ~300 lines), registered on the app in
  `create_app()`; schemas live in `backend/app/schemas/`.
- The OpenAPI spec is rebuilt on every `create_app()`; served at
  `/api/docs` (Swagger UI) and `/api/openapi.json`.
- WebSocket endpoints (`/ws/*`) are registered on Flask-SocketIO
  directly, not through Smorest — Smorest owns synchronous HTTP/JSON
  only.
- API versioned `/api/v1/*` from day one; breaking changes bump the major
  version.
- **OIDC is the sole authN mode** — no proxy mode; KubeDash issues its
  own short-lived JWTs. Kerberos/SPNEGO is deferred (OIDC federation at
  the IdP edge, not natively).

##### Consequences

- Good: one schema system; spec can't drift from validation; sync code
  composes with the sync `kubernetes` client; 4.1 operators recognize the
  stack.
- Bad: no native async — long IO waits hold a worker thread (mitigated by
  Gunicorn thread pool sizing and per-cluster timeouts).
- Confirmation: `backend/tests/api/test_apidocs.py` (spec generation +
  vendored docs), `backend/tests/test_app.py`, and the per-domain API
  tests in `backend/tests/api/`.

#### Linking Decisions and Constraints

- ADR-0006 — single container: Gunicorn serves this API and the static
  SPA.
- ADR-0009 — SSE streams are plain Flask routes alongside Smorest.
- ADR-0025 — session transport (HttpOnly cookies) layered on this API.
- ADR-0028 — configuration surface (INI) for this stack.

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 (the 2026-10-17
initial-architecture ADR list) + §3.1–3.2; verified against the current
source (Smorest `Api` classes in `backend/app/api/`, SocketIO in
`backend/app/sockets/`) on 2026-11-06.
