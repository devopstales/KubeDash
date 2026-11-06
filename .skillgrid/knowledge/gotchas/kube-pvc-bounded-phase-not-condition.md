---
type: Reference
title: "PVC Bound is .status.phase, not a condition — kubectl wait --for=condition=Bound can never succeed"
description: "A bound PVC's .status.phase is 'Bound' while .status.conditions is empty; kubectl wait --for=condition=Bound therefore times out instead of passing. Wait on the phase: --for=jsonpath='{.status.phase}'=Bound. Bit the dev stack (demo-data.sh 120 s timeout, every run) until fixed in ce6d0b19 (2026-11-05, QA gate F1)."
tags: [gotcha, kubernetes, pvc, kubectl, dev-stack, wait]
status: stable
generated: { by: skillgrid/kb-maintenance, at: 2026-11-06 }
verification:
  engine: ripgrep
  anchors:
    - path: dev/scripts/demo-data.sh
      all_of: ["jsonpath='{.status.phase}'=Bound"]
---

# PVC Bound is a phase, not a condition

**The gotcha.** `kubectl wait --for=condition=Bound` on a PVC **can
never succeed**. The bound state lives in `.status.phase` (a
top-level string field on the PVC status); a plainly-bound PVC has an
**empty** `.status.conditions`. The condition form of `wait` polls the
conditions list, finds nothing, and times out — which is exactly what
happened on every `task dev-stack` run: `dev/scripts/demo-data.sh`
hung 120 s at the PVC wait before the storage work exposed it.

**The fix** (`ce6d0b19`, QA gate finding F1, storage batch
2026-11-05):

```sh
kubectl wait pvc/demo-pvc -n demo --for=jsonpath='{.status.phase}'=Bound
```

**Why it is subtle.** The kubectl examples and much of the ecosystem
documentation use `--for=condition=X` for pod-ready-style states;
PVCs are the outlier where the "condition" name matches a *phase*
value. `Lost`/`ReservedFor deletion` are also phases. Only
`--for=condition=...` on `metadata.deletionTimestamp`-style real
conditions (e.g. `Ready`-like ones) apply.

**Rule for the agent.** Waiting on a PVC: always the
`jsonpath='{.status.phase}'=` form. The same dev-cluster note applies
to the Usage column: the dev cluster runs the `csi-hostpath` CSI
driver precisely because `rancher.local-path`'s hostPath volumes never
reach the kubelet's `/stats/summary` (see `dev/csi-hostpath.yaml`
header) — the PVC wait is the other half of making that column show
real numbers in dev.

**Related.** `invariants/object-view-annotation-trim.md` (the dev
stack that this unblocked), `workflows/frontend-build-serve.md` (the
dev-loop entry `task dev-stack`).
