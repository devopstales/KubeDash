---
id: m-5
title: "2026-11-07-frontend-kind-registry"
---

## Description

Replace the per-kind hand-written view pairs + App.tsx route blocks with a kind-hand-keyed registry (lib/kinds.ts, 21 standard rows + 6 legacyData storage rows) + shared ResourceListView/ResourceDataView components + generated routes. cert-manager and external-loadbalancer stay hand-written (scope call 2026-11-07). Fleet KubeDataTable test-fake migration lives in change D. Landing order D -> A -> B -> C.
