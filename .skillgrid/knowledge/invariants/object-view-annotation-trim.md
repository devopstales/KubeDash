---
type: InvariantContract
title: "Object data views trim machine-managed annotations before rendering"
description: "Every 5.0 object data view's Annotations table drops the two machine-managed keys 4.1's trimAnnotations removed (kubectl.kubernetes.io/last-applied-configuration, autoscaling.alpha.kubernetes.io/conditions); the full-object JSON block still renders them verbatim. The 2026-10-28 'render annotations verbatim' deviation is overridden (user decision 2026-11-04/05)."
tags: [frontend, data-view, 4.1-parity, annotations, override]
status: stable
generated: { by: skillgrid/kb-maintenance, at: 2026-11-06 }
verification:
  engine: ripgrep
  anchors:
    - path: frontend/src/views/Storage/PvData.tsx
      all_of: ["kubectl.kubernetes.io/last-applied-configuration", "autoscaling.alpha.kubernetes.io/conditions"]
    - path: frontend/src/views/Network/IngressData.tsx
      all_of: ["kubectl.kubernetes.io/last-applied-configuration", "autoscaling.alpha.kubernetes.io/conditions"]
    - path: frontend/src/views/OtherResource/HorizontalPodAutoscalerData.tsx
      all_of: ["kubectl.kubernetes.io/last-applied-configuration"]
claims:
  - subject: trimmed machine-managed key (kubectl)
    literal: "kubectl.kubernetes.io/last-applied-configuration"
  - subject: trimmed machine-managed key (autoscaling conditions)
    literal: "autoscaling.alpha.kubernetes.io/conditions"
---

# Object data views trim machine-managed annotations

**The contract.** In every object data view, the `Annotations`
Key/Value table is built from the metadata annotations with exactly two
keys filtered out before rendering:

1. `kubectl.kubernetes.io/last-applied-configuration` — the machine
   applied-configuration blob (the multi-KB base64-ish mess that
   swallows the table).
2. `autoscaling.alpha.kubernetes.io/conditions` — a second
   machine-managed key carried over from 4.1's trim list.

The full-object **JSON block** below the table renders the object
verbatim — both keys are still visible there. This is 4.1's
`trimAnnotations` behavior (`lib/helper_functions.py`), replicated.

**History (why this page exists).** The 2026-10-28 views batch
ratified "render all annotations verbatim" as a recorded deviation from
4.1. The user overrode it in two steps: HPA first (2026-11-04,
`46929a10` — "The HPA Data: Annotations data should be formatted. Like
in 4.1"), then the storage data views (2026-11-05, `f7c8223d`), then
the network views (2026-11-06, Ingress/IngressClass/GatewayClass/Gateway
API data views). The trim is now the shape for **every** object data
view, not a per-view choice.

**Currently trimming** (verified 2026-11-06): StorageClass,
SnapshotClass, VolumeSnapshot, PVC, PV, ConfigMap (storage);
HorizontalPodAutoscaler (other resources); Ingress, IngressClass,
GatewayClass, Gateway API (network). Views shipped before the override
that still render annotations verbatim are deviations from this
contract, not from 4.1 — port them when the view is next touched.

**Why.** The machine-managed keys are noise to a human reading an
object: the last-applied blob is a rediff artifact of `kubectl apply`,
not operator information. 4.1 hid them; 5.0's parity promise means
5.0 hides them too.

**Verification.** The two literals appear in each view's annotation
filter (anchored above); the full-object JSON block is unfiltered by
construction (it renders the raw item, not the filtered list).

**Related.** ADR-0022 (sidebar / 4.1 parity scope — parity is the
default, deviations are recorded), `frontend/STYLEGUIDE.md` (UI piece
for data views), `gotchas/kube-pvc-bounded-phase-not-condition.md`
(another 4.1-parity detail that bit the dev stack).
