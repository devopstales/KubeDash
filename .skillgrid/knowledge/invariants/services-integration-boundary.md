---
type: InvariantContract
title: "app/services is the Flask-free integration boundary (one documented function-local carve-out)"
description: "backend/app/services/ modules are pure Python with no module-level Flask imports; the single carve-out is a function-local 'from flask import g' in K8sClientPool.get for the ADR-0021 admin-source branch."
tags: [layering, services, integration-boundary]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: backend/app/services/__init__.py
      all_of: ['informer cache will interpose HERE later']
    - path: backend/app/services/k8s_client.py
      all_of: ['from flask import g', 'LOCAL_CLUSTER_ID']
claims:
  - subject: the sole Flask carve-out (function-local, admin-source branch)
    literal: 'from flask import g'
  - subject: the documented informer seam
    literal: 'informer cache will interpose HERE later'
---

# app/services is Flask-free (one documented carve-out)

`backend/app/services/` is the integration boundary: pure Python modules
that the Smorest `Api` layer (and the RQ tasks) call with explicit
arguments. No service module imports Flask at module level, so services
are testable without an app and reusable from the worker process.

**The contract.**

- A new service module must not add a module-level `import flask` /
  `from flask import ...`. If a service needs request context, the caller
  passes the value (e.g. `user`) in.
- **Sole carve-out:** `K8sClientPool.get()`
  (`backend/app/services/k8s_client.py`) does a **function-local**
  `from flask import g` inside the `cluster.id == LOCAL_CLUSTER_ID`
  branch — the synthetic local cluster (ADR-0021, C-NEW-2) routes to the
  admin client, and the per-caller role gate needs
  `g.current_user`. The import is deferred to call time so module import
  never pulls Flask; the docstring records the rationale.

**Verification (2026-11-06).** Grepped `import flask|from flask` across
`backend/app/services/`: exactly **one** hit — the carve-out at
`k8s_client.py` (function-local). Any other hit violates this invariant.

**Why.** Flask imports at module level couple services to the app
context: test isolation breaks, the worker process imports the web
stack, and the "services are pure" seam (where ADR-0010's informer cache
will interpose) stops being true.

**Pinned by.** The seam docstring in `backend/app/services/__init__.py`;
the rule's origin is `.skillgrid/specs/2026-10-21-cluster-node/blueprint.md`
("Never import Flask in `app/services/`").

**Related.** ADR-0001 (layering), ADR-0021 (admin-source branch),
ADR-0010 (the seam's future occupant).
