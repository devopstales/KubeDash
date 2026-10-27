---
id: m-2
title: "2026-10-27-postgres-queue-revocation-active-active"
---

## Description

Replace all four Redis consumers (RQ broker, jti revocation, OIDC state, SAR verdict cache) with Postgres — a tasks queue on FOR UPDATE SKIP LOCKED, a revoked_jtis deny-list, and a generic kv TTL table — add a strict fence to the leader election, and make the dev stack a two-node pgEdge active-active cluster with no Redis. Decisions: ADR-0029/0030/0031. Sliced: 7 tickets, 4 waves (W1 serial migration; W2 parallel pgqueue/fence/kvstore; W3 parallel wsgi/auth+rbac; W4 redis removal + pgEdge dev). High risk ~1400-1900 lines -> feature-branch-chain on rebase. Spec: .skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/
