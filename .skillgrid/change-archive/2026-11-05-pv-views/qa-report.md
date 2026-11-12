# QA Report — Storage Views Batch (5 changes)

**Gate: PASS** (2026-11-05, QA gate re-executed at tip; 2 findings fixed at
the gate — F1: `demo-data.sh`'s PVC wait could never succeed, breaking
`task dev-stack`; F2: the batch's +3 ruff / +3 mypy lint debt. Floor
re-run after the fixes, results below.)

**Batch:** base `1d5bb5ba` (pre-storageclass) → tip `f9d4fc50`, branch `rebase`

| # | Change | Task | Commits |
|---|--------|------|---------|
| 1 | `2026-10-28-storageclass-views` | TASK-052 | 1d5bb5ba..08e37b50 |
| 2 | `2026-10-28-snapshotclass-views` | TASK-051 | 7279d411..2365cff8 |
| 3 | `2026-10-28-volumesnapshot-views` | TASK-053 | 2138db40..9af5180a |
| 4 | `2026-10-28-pvc-views` | TASK-065 | 43f7e6a8..1e453d31 (+ 9bba46d5, 320e2b4b closeout) |
| 5 | `2026-11-05-pv-views` | TASK-066 | 6c8c6946..9c733235 (+ b204fc50 usage column, bd22d840 dev csi-hostpath) |

Companion work in the batch: T2 trimAnnotations override for the five
storage data views (f7c8223d, 2026-11-05 user decision; adr.md override
notes in the five specs) + dev csi-hostpath CSI driver for real PVC/PV
Usage data (bd22d840).

## Fresh verification floor (re-executed at tip, 2026-11-05)

| Check | Result |
|---|---|
| `uv run pytest -m "not integration" -q` | **648 passed, 10 deselected, 0 failed** (136 s; = 640 at the batch floor + 8 from the user's concurrent ingressclass-gatewayclass work in the shared tree) |
| Targeted backend (`test_resources.py` + `test_k8s_pvs.py` + `test_k8s_client_volume_snapshots.py` + `test_metrics_pvcs.py`, `-m "not integration"`) | **154 passed, 6 deselected** |
| `corepack pnpm vitest run` (full) | **376 passed / 12 failed — the failures are exactly the declared baseline** (users/groups/admin_permissions/node-detail, W007; zero in storage) |
| Targeted frontend (13 files: 10 storage view tests + 2 configmap + `Stub.test.tsx`) | **85 passed (85)** |
| `task fe-build` (tsc --noEmit incl. tests + eslint + vite build) | green |
| `task fe-check` (air-gap assertion on `frontend/dist`) | green |
| `task e2e` (auth-smoke + ui-smoke; all six `/storage/*` paths REAL_ROUTES) | **19 passed (19)** |
| `task dev-stack` (compose + kind-up + demo-data + leader backend) | **exit 0** after the F1 fix (failed before it: 120 s PVC-wait timeout — see F1) |
| ruff vs baseline `1d5bb5ba` | **102 = 102 (flat)** after wrapping the 3 E501s the batch added (pre-fix tip was 105; the state.yaml "flat 105/81" note was measured against the wrong baseline — actual base 102/78) |
| mypy vs baseline | **73 < 78** — the batch's 3 new attr-defineds (metrics.py `pvc_usage`) resolved by typing `cluster_for`/`bound_cluster_or_404` as `Cluster`, which also removed 5 pre-existing of the same class (pre-fix tip was 81) |
| `git diff --name-only 1d5bb5ba..f9d4fc50` (66 files) | subset of the five blueprints' File Structure + their spec folders + `state.yaml` + `.backlog` task files + the concurrent configmap work (TASK-064, separate change) + the test-security Taskfile tasks (TASK-067) + AGENTS.md + the mnemonic cache; `frontend/src/_nav.tsx` **byte-identical**; dependency files (`package.json`, `pnpm-lock.yaml`, `pyproject.toml`, `uv.lock`) **empty diff** (ADR-0020 air-gap) |
| Live cluster (kind-kubedash-test, K8s 1.35, real data) | list + get-by-name for all five kinds: 3 storageclasses / csi-default snapshotclass / demo-snap (readyToUse) / demo-pvc (Bound) / 1 PV (claim-ns filter: bound PV visible for its claim ns, ghost lookups `[]`); `pvc_usage("kubedash-demo")` → demo-pvc 160.3 GB cap / 41.8 GB used / **26.0 %** (csi-hostpath `NodeGetVolumeStats`) |

Scope of derivations: traceability `COMPLETE` (all five `acceptance.feature`
files read in full); verification-gap audit `COMPLETE` (full
`1d5bb5ba..f9d4fc50` diff enumerated). Stale check: F1/F2 code-zone fixes
(`ce6d0b19`, `6368cc8b`) landed after the execution-phase floor; this run's
evidence (not the prior verdict) is what the gate rests on — e2e,
dev-stack, targeted tests, and ruff/mypy were all re-executed after the
fixes.

## QA findings disposition

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | CRITICAL | `dev/scripts/demo-data.sh` (bd22d840): `kubectl wait --for=condition=Bound pvc/demo-pvc` can **never** succeed — a PVC's bound state is a PHASE (`.status.phase`), not a condition; a plainly-bound PVC has an empty `.status.conditions` (verified live: `phase=Bound conditions=`), so every `task dev-stack` run timed out 120 s at the wait, after the pkill of the previous backend (reproduced twice: the dev-stack run + a direct 10 s wait against the already-Bound PVC) | **FIXED** (`ce6d0b19`) — `--for=jsonpath='{.status.phase}'=Bound` + explanatory comment. Wait now returns instantly; `task dev-stack` exit 0; e2e re-run against the freshly restarted backend 19/19 |
| F2 | WARNING | The batch added 3 ruff E501 (new test files: `test_resources.py` pv fake-client line, `test_k8s_client_volume_snapshots.py:58`, `test_k8s_pvs.py:86`) + 3 mypy attr-defined (metrics.py `pvc_usage` `cluster.name` sites) — lint debt against the flat-vs-baseline convention | **FIXED** (`6368cc8b`) — 3 line wraps; root-caused the attr-defined class: `cluster_for`/`bound_cluster_or_404` were typed `object` though both branches return a `Cluster` row — typed them, removing 3 new + 5 pre-existing errors. ruff 102 = baseline, mypy 73 < baseline |
| F3 | SUGGESTION | TDD execution notes: 2 unexpanded placeholder commit cells (TASK-052 T3 `<hash>`, TASK-065 T2 `$(git log --format=%h -1)`); all 25 real cited hashes resolve (`git cat-file -t`), RED→GREEN recorded per task unit (W015 precedent for the co-commit shape) | parked (W021) |

## Traceability (static, on tip)

85/85 scenarios across the five `acceptance.feature` files (15
storageclass + 16 snapshotclass + 18 volumesnapshot + 23 pvc + 13 pv)
mapped to named tests — backend: 5 new service files + `test_metrics_pvcs.py`
(6 route tests) + `test_resources.py` kind additions, all `[scenario]`
docstring-tagged; frontend: 10 view test files (85 tests) + `Stub.test.tsx`;
e2e: all six `/storage/*` paths in `ui-smoke` REAL_ROUTES (W008 partially
addressed). No UNTESTED, no FAILING, no PARTIAL. The data-link scenarios of
the four 2026-10-28 features were written against the superseded
query-string contract and are satisfied in the ADR-0040 shape (name cell
opens the object ref, detail renders at the list route) per each spec's
`NAVIGATION-SUPERSEDED.md` — the `/data` URLs never shipped for these kinds,
so no R7 redirect exists.

Assertion quality (20 test files: pattern scan + full reads of the backend
files and the complex frontend ones): **0 CRITICAL / 0 WARNING** — no
tautologies; no ghost loops (DOM loops iterate fixed label lists or
`findAllByText` results that throw when empty); `pre`-presence assertions
always paired with `textContent` value assertions; counter-tests present on
the SAR-denied and CRD-absent paths ("the list call was never made");
mock:assert ratios well under the 2:1 warning line (1 MSW handler vs 19–47
expects per frontend file; backend asserts 6–29 per file).

## Carried baselines (not findings)

- Frontend 12 pre-existing vitest failures (users/groups/
  admin_permissions/node-detail — W007, shrinking 13→12; datatables.net
  `window.alert` in jsdom) — owned by the in-flight users/groups pages, not
  this batch.
- Backend lint debt at tip: ruff 102 / mypy 73 (W013 — mypy improved 78→73
  by F2's typing fix; ruff unchanged).
- W008: the five other-resource kinds' REAL_ROUTES entries remain
  unit-level only (the storage batch added its six paths).
