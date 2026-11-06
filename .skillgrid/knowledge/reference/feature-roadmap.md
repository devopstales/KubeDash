---
type: Reference
title: "Feature roadmap and open/deferred items (ARCHITECTURE.md §7A / §11)"
description: "Pointer to the feature roadmap (v1.0 differentiators, v1.1-v1.2, v1.3+ informed by Radar) and the Open/Deferred list (GitOps, cost tracking, plugin system, Kerberos, no-IdP multi-user mode, Celery migration) in .skillgrid/ARCHITECTURE.md. As of 2026-11-06 the MCP server, AI investigations, change timeline, and workload-map research findings are captured in .skillgrid/specs/2026-11-06-*; the roadmap items themselves are unchanged."
tags: [roadmap, reference, pointer]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: .skillgrid/ARCHITECTURE.md
      all_of: ['## 7A. Feature Roadmap (informed by Radar)', '## 11. Open / Deferred']
---

# Feature roadmap + open/deferred

Two pointer sections of `.skillgrid/ARCHITECTURE.md`:

- **§7A — Feature Roadmap (informed by Radar).** High priority
  (v1.0 differentiators), medium (v1.1–v1.2), lower (v1.3+), plus the
  "architectural lessons from Radar" the existing sections should
  absorb.
- **§11 — Open / Deferred.** *Not decisions yet* — they become ADRs
  when they are. Currently listed: GitOps integration (Argo CD / Flux),
  cost tracking (Kubecost vs. native), a third-party plugin system,
  multi-tenancy beyond RBAC, mobile/tablet, offline cached mode,
  Kerberos/SPNEGO (OIDC-federated at the IdP edge, not native), custom
  provisioning task types, full SCIM filter grammar, no-IdP multi-user
  mode (superseded-in-part by ADR-0021's bootstrap admin), and the
  RQ → Celery migration trigger (fan-out / priorities beyond ~4
  periodic tasks).

**Roadmap research already in flight (2026-11-06).** Four roadmap
items have completed single-pass research findings in the spec zone
(state: `research` — findings only, no briefings yet; they are inputs
to future ADRs, the next number being 0041):

- **MCP server** (roadmap item 5) — `.skillgrid/specs/2026-11-06-mcp-server/findings.md`.
- **AI investigations** (consumes the MCP surface) — `.skillgrid/specs/2026-11-06-ai-investigations/findings.md`.
- **Change timeline** (roadmap item 2) — `.skillgrid/specs/2026-11-06-change-timeline/findings.md`.
- **Workload map** (roadmap item 1, the topology view) — `.skillgrid/specs/2026-11-06-workload-map/` (findings + a **draft** briefing; the 4.1 map is ownership-edges only; the 5.0 spec adds connections + a network-policy overlay).

These are evidence and scope, not commitments — the roadmap rule below
still applies.

**Rule for the agent.** Roadmap items are *not* constraints: an
implementation that touches one should record the decision as an ADR at
that time, not cite the roadmap as authority.
