---
id: m-6
title: "2026-11-07-navigation-seam"
---

## Description

Replace the single-slot registerNavigate global in ObjectRoute.tsx with a kind-hand-keyed registry in lib/objectRef.ts; delete the 3 in-scope single-kind dispatchers (their registrations migrate to the seam) and re-point ~44 test files. cert-manager and external-LB seam registrations migrate while their components stay hand-written (B scope call). Relays, legacy redirects, and e2e stay green. Landing order D -> A -> B -> C.
