# Sidebar navigation: 4.1 information-parity structure, Plugins group dropped

---
status: "accepted"
date: 2026-10-21
supersedes: none
---

**Decision-makers.** paladm (project owner)
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash 4.1 (Jinja2 server-rendered, `src/kubedash/templates/segments/partials/menu.html.j2`)
ships a well-established information architecture: a dark fixed CoreUI sidebar with
three sections — an ungrouped Dashboard group at top, a `Permissions` titled section
(User Management, Cluster Permissions), and an `Interface` titled section (Cluster,
Workloads, Network, Storage, Security, Other Resources), then an Admin-only `Settings`
group, and finally a `Plugins` group whose entries are gated on `config.plugins[*]`
(OCI Registry, Helm Charts, Flux CD, AI Chat, Cert-Manager, LoadBalancers, Gateway API,
Trivy Operator, App Catalog).

KubeDash 5.0 is a React SPA on the same CoreUI template (ADR-0005). Its current
`frontend/src/_nav.tsx` is a four-item stub (Clusters, Cluster detail, My access, Admin
permissions) — the CoreUI demo nav was dropped, and the 4.1 information architecture
was not carried forward. Users upgrading from 4.1 lose the muscle memory of the
resource grouping, and every future resource view (Pods, Deployments, Services, …)
needs a place in the menu. The navigation surface is a user-facing contract: it
determines discoverability and is hard to change late without retraining users.

#### Decision Drivers

- User continuity: 4.1 operators should find the same groups and entries in 5.0
- Discoverability of the (future) resource views without per-view menu churn
- The 5.0 plugin system does not exist yet — 4.1's `Plugins` group has no backend in 5.0
- Consistency with the existing CoreUI template (ADR-0005): same `CSidebarNav`/`CNavGroup`
  primitives, same dark theme, same section-divider pattern

#### Considered Options

- Full 4.1 parity including the Plugins group
- 4.1 parity minus the Plugins group (information structure only)
- Keep the 4-item stub and add entries ad hoc per resource view

#### Decision Outcome

Chosen option: "4.1 parity minus the Plugins group", because the 4.1 information
architecture (sections, group names, entry names, order, dividers, admin gating) is the
user contract to preserve, while the Plugins group references a 4.1 plugin system
(`config.plugins[*]`) that has no 5.0 counterpart — rendering it would produce dead
links. The structure is adopted as the navigation contract; each entry's route maps to
an existing 5.0 view where one exists and to a placeholder/stub route where it does not
yet.

The normative menu contract (entry text, section order, and 4.1 route → 5.0 route
mapping):

| 4.1 group | 4.1 entry | 4.1 route | 5.0 route | Status |
|---|---|---|---|---|
| *(top, no section)* Dashboard | Cluster Metrics | `/dashboard/cluster-metric` | `/clusters` (cluster-metric view) | exists |
| *(top, no section)* Dashboard | Workload `Beta` | `/dashboard/workload-map` | stub (route-only) | stub |
| **Permissions** User Management | Users | `/user/list` | `/admin/permissions` (Users tab) | exists |
| **Permissions** User Management | Groups | `/user/group` | stub (route-only) | stub |
| **Permissions** Cluster Permissions | ServiceAccounts | `/cluster-permission/service-account` | stub | stub |
| **Permissions** Cluster Permissions | Roles | `/cluster-permission/role` | stub | stub |
| **Permissions** Cluster Permissions | RoleBindings | `/cluster-permission/role-binding` | stub | stub |
| **Permissions** Cluster Permissions | ClusterRoles | `/cluster-permission/cluster-role` | stub | stub |
| **Permissions** Cluster Permissions | ClusterRoleBindings | `/cluster-permission/cluster-role-binding` | stub | stub |
| **Interface** Cluster | Namespaces | `/cluster/namespace` | stub | stub |
| **Interface** Cluster | Nodes | `/cluster/node` | stub | stub |
| **Interface** Cluster | CRDs | `/cluster/crd` | stub | stub |
| **Interface** Workloads | Pods | `/workload/pods` | stub | stub |
| **Interface** Workloads | Deployments | `/workload/deployments` | stub | stub |
| **Interface** Workloads | StatefulSets | `/workload/statefulsets` | stub | stub |
| **Interface** Workloads | DaemonSets | `/workload/daemonsets` | stub | stub |
| **Interface** Workloads | ReplicaSets | `/workload/replicasets` | stub | stub |
| **Interface** Network | Services | `/network/service` | stub | stub |
| **Interface** Network | Ingress | `/network/ingress` | stub | stub |
| **Interface** Storage | ConfigMaps | `/storage/configmap` | stub | stub |
| **Interface** Storage | Volumes | `/storage/pv` | stub | stub |
| **Interface** Storage | VolumeClaims | `/storage/pvc` | stub | stub |
| **Interface** Storage | VolumeSnapshot | `/storage/volumesnapshot` | stub | stub |
| **Interface** Storage | StorageClass | `/storage/storage-class` | stub | stub |
| **Interface** Storage | SnapshotClass | `/storage/snapshot-class` | stub | stub |
| **Interface** Security | Secrets | `/security/secret` | stub | stub |
| **Interface** Security | Network Policies | `/security/network-policy` | stub | stub |
| **Interface** Security | Priority Classes | `/security/priorityclass` | stub | stub |
| **Interface** Other Resources | HPAs | `/other-resource/horizontal-pod-autoscaler` | stub | stub |
| **Interface** Other Resources | VPAs | `/other-resource/vertical-pod-autoscaler` | stub | stub |
| **Interface** Other Resources | Pod Disruption Budget | `/other-resource/pod-disruption-budget` | stub | stub |
| **Interface** Other Resources | Resource Quota | `/other-resource/resource-quota` | stub | stub |
| **Interface** Other Resources | Limit Range | `/other-resource/limit-range` | stub | stub |
| **Interface** Other Resources | Runtime Class | `/other-resource/runtimeclass` | stub | stub |
| **Settings** (admin only) | Auth Provider | `/settings/sso-config` | stub | stub, admin-gated |
| **Settings** (admin only) | Kubernetes Cluster | `/settings/k8s-config` | `/clusters` (admin cluster view) | exists |
| **Settings** (admin only) | HA Status | `/settings/cluster-status` | stub | stub, admin-gated |
| **Settings** (admin only) | Audit Log | `/settings/audit-log` | `/admin/permissions` (Audit tab) | exists, admin-gated |
| **Plugins** *(entire group dropped)* | — | — | — | no 5.0 plugin system |

5.0-only entries that 4.1 does not have (carried forward, not part of the 4.1 parity
contract): `My access` (`/permissions`) stays in the Permissions section — it is the
self-service kubeconfig surface (ADR-0013) and has no 4.1 equivalent.

##### Consequences

- Good, because 4.1 operators land on a familiar information architecture; the
  navigation contract is frozen in this ADR so per-view tickets don't re-litigate it
- Good, because every future resource view has a pre-assigned menu slot (group + label)
  — views only need to swap the stub route for a real one
- Bad, because ~30 stub routes exist before their views do; the route table grows a
  placeholder surface that must be kept honest (stubs must not render broken 5.0 views)
- Bad, because the 4.1 `Plugins` group's gated entries (Cert-Manager, LoadBalancers,
  Gateway API, Trivy Operator, App Catalog) also disappear — if a 5.0 plugin system
  lands, this ADR must be superseded to restore the group
- Neutral, because the CoreUI primitives (`CNavGroup`, `CNavTitle`, `CNavItem`,
  `CNavLink`) already support the exact structure (nested groups, section titles,
  compact items, admin gating via the existing `AdminRoute` pattern)

##### Confirmation

`frontend/src/_nav.tsx` renders exactly the groups/entries/section titles/order above
(Plugins absent); `frontend/tests/` asserts the nav structure (group names, entry names,
order, admin gating of the Settings group); no nav entry points at a 4.1-only route
that has no 5.0 counterpart; the air-gap check (`task fe-check`) stays green (no new
external URLs introduced).

#### Pros and Cons of the Options

##### Full 4.1 parity including the Plugins group

- Good, because zero structural difference from 4.1
- Bad, because the Plugins group is config-gated on a 4.1 subsystem that does not exist
  in 5.0 — every entry would be a dead link until the plugin system lands

##### 4.1 parity minus the Plugins group (chosen)

- Good, because the user-facing information architecture is preserved where it is
  meaningful
- Good, because dead links are avoided; the group can be restored by supersedure when
  the 5.0 plugin system exists
- Bad, because the 4.1 plugin-gated entries inside other groups (Cert-Manager under
  Network, Trivy Operator under Security, App Catalog under Settings) are also dropped
  for the same reason — this is the price of parity without the plugin subsystem

##### Keep the 4-item stub, add entries ad hoc

- Good, because no up-front work
- Bad, because the 4.1 information architecture is lost; each resource view re-decides
  its menu placement; no continuity for 4.1 operators

#### More Information

- 4.1 source of truth: branch `4.1`,
  `src/kubedash/templates/segments/partials/menu.html.j2` (read 2026-10-21)
- 5.0 nav: `frontend/src/_nav.tsx`; template primitives per ADR-0005
- Revisit trigger: the 5.0 plugin system change supersedes this ADR to restore the
  Plugins group and the plugin-gated entries inside Network/Security/Settings
