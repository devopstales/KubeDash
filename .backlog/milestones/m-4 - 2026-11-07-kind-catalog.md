---
id: m-4
title: "2026-11-07-kind-catalog"
---

## Description

Replace the per-kind list/get methods + string kind tables + drifting test doubles with a typed kind catalog (41 KindSpec rows), one generic read engine, and one catalog-driven FakeK8s (ADR-0041). One documented behaviour change: legacy 500 read paths become 502 CLUSTER_UNREACHABLE (user decision 2026-11-07). Cutover is kind-by-kind, suite green at every commit. Landing order D -> A -> B -> C.
