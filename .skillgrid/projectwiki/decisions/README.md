---
type: Reference
title: "ADR index — all 33 decisions (29 in force, 4 superseded)"
status: stable
---

# ADR index

One file per decision, `ADR-NNNN-slug.md`. In-force rows: see
[ASSUMPTIONS.md](../ASSUMPTIONS.md) § LOCKED (the durable index). This page
lists every record, including superseded ones (frozen history — never edited
in place; a new decision supersedes via its `supersedes` frontmatter).

| ADR | Record | Status |
|---|---|---|
| 0001 | [[decisions/04-adr-0001-flask-smorest]] | in force |
| 0002 | [[decisions/04-adr-0002-multi-cluster-registry]] | in force |
| 0003 | [[decisions/04-adr-0003-observability-query-only]] | in force |
| 0004 | [[decisions/04-adr-0004-rbac-proxy-sar]] | in force |
| 0005 | [[decisions/04-adr-0005-coreui-react]] | in force |
| 0006 | [[decisions/04-adr-0006-single-container]] | in force |
| 0007 | [[decisions/04-adr-0007-rq-over-celery]] | superseded (by 0029) |
| 0008 | [[decisions/04-adr-0008-leader-election]] | superseded (by 0031) |
| 0009 | [[decisions/04-adr-0009-sse-over-websocket]] | in force |
| 0010 | [[decisions/04-adr-0010-informer-cache]] | in force |
| 0011 | [[decisions/04-adr-0011-kubectl-credential-plugin]] | in force |
| 0012 | [[decisions/04-adr-0012-aggregated-api]] | in force |
| 0013 | [[decisions/04-adr-0013-permission-management]] | in force |
| 0014 | [[decisions/04-adr-0014-session-revocation-propagation]] | superseded (by 0030) |
| 0015 | [[decisions/04-adr-0015-namespace-as-a-service]] | in force |
| 0016 | [[decisions/04-adr-0016-privileged-access-management]] | in force |
| 0017 | [[decisions/04-adr-0017-jit-login-provisioning]] | in force |
| 0018 | [[decisions/04-adr-0018-scim-2-0-gateway]] | in force |
| 0019 | [[decisions/04-adr-0019-ingress-auth-integration]] | in force |
| 0020 | [[decisions/04-adr-0020-air-gap-deployment]] | in force |
| 0021 | [[decisions/04-adr-0021-local-admin-auth]] | in force |
| 0022 | [[decisions/04-adr-0022-sidebar-nav-4-1-parity]] | in force |
| 0023 | [[decisions/04-adr-0023-datatables-react]] | in force |
| 0024 | [[decisions/04-adr-0024-secret-syntax-highlight]] | in force |
| 0025 | [[decisions/04-adr-0025-http-only-session-cookie]] | in force |
| 0026 | [[decisions/04-adr-0026-tls-edge-and-security-headers]] | superseded (by 0027) |
| 0027 | [[decisions/04-adr-0027-plain-http-dev-stack-default]] | in force |
| 0028 | [[decisions/04-adr-0028-ini-config-source]] | in force |
| 0029 | [[decisions/04-adr-0029-queue-on-postgres]] | in force |
| 0030 | [[decisions/04-adr-0030-session-revocation-on-postgres]] | in force |
| 0031 | [[decisions/04-adr-0031-active-active-pgedge-spock]] | in force |
| 0040 | [[decisions/04-adr-0040-session-object-navigation]] | in force |
| 0041 | [[decisions/04-adr-0041-kind-catalog]] | in force |

Next number: **0042** (4-digit monotonic, never reused; gap 0032–0039 unused).
Style: `madr-full` (`.skillgrid/config.yaml` `adr_style`). Every ADR also gets a
`.backlog/decisions/decision-NNN` copy (NNN = ADR number, zero-padded to 3).

## Related

- [[invariants/05-locked-constraints]] — the must-hold tokens the decisions pin
- [[decisions/04-adr-0029-queue-on-postgres]] — example of a superseding decision
