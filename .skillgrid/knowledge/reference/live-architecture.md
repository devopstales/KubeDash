---
type: Reference
title: "Live architecture document (ARCHITECTURE.md)"
description: "Pointer to .skillgrid/ARCHITECTURE.md — the live description of KubeDash's program structure (system overview, backend/frontend/multi-cluster/observability/deployment/security/testing/conventions). It is not a blueprint, spec, or decision record."
tags: [architecture, reference, pointer]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: .skillgrid/ARCHITECTURE.md
      all_of: ['## 12. ADR Index (pointer)', '## 13. Glossary pointer']
---

# Live architecture document

`.skillgrid/ARCHITECTURE.md` is the **live** description of the program
structure: updated as the codebase changes. It is *not* a blueprint,
*not* a spec, and *not* a decision record.

**Division of labor** (per the document's own header):

| Question | Where it lives |
|---|---|
| How is the program structured today? | `ARCHITECTURE.md` (this pointer) |
| Why was a load-bearing choice made? | `decisions/04-adr-NNNN-*.md` |
| What do terms mean? | `glossary/01-business-terms.md`, `02-technical-terms.md` |
| Which ADRs are in force? | `.skillgrid/ASSUMPTIONS.md` § LOCKED |
| What must always hold in the code? | `invariants/` (this bundle) |
| How do cross-package flows work? | `workflows/` (this bundle) |

**Known staleness (recorded 2026-11-06).** The document's header still
reads `Status: PROPOSED` / "React 18 + TypeScript" and §3.8 still
describes env-driven Pydantic config — both superseded by shipped
changes (React 19 in `frontend/package.json`; INI config per
ADR-0028). When editing the document, prefer current source over its
stale sections; the decisions in `decisions/` and the pins in
`invariants/` are the authoritative record.

**Sections worth routing to directly.** §3 Backend (app factory,
services seam, data model, auth flow, SSE/WS, RQ + leader, config) ·
§4 Frontend (stack, view folders, API client, object navigation §4.4.1)
· §5 Multi-cluster · §5A–5F Permission layer (aggregated API,
permission management, NaaS, PAM, JIT, SCIM) · §6 Observability ·
§7 Deployment (container, chart, CI, air-gap §7.7, kubectl plugin §7.6)
· §8 Security · §9 Testing · §10 Conventions · §11 Open/Deferred ·
§12 ADR index pointer · §13 Glossary pointer.
