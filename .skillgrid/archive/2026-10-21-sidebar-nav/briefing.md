# Sidebar — 4.1 shell and menu (requirements & intent)

> **STATUS:** `draft` (2026-10-21)
> **Tier:** T1 (assumption: single frontend concern, no migration, no new trust boundary; project config has no `rules.tiers.default`)

> **Role:** this is the *what* — problem, intent, requirements, success criteria.
> The companion `blueprint.md` is the *how*. Do not rename.

## Problem / Intent

KubeDash 4.1 (`src/kubedash/templates/segments/partials/menu.html.j2` on branch
`4.1`) is the operator's map of the product: a dark fixed CoreUI sidebar, a
header with a sidebar toggle and a scope selector, and a footer. The menu is
four blocks — Dashboard, **Permissions**, **Interface**, and an admin-only
**Settings** group — plus a **Plugins** group.

KubeDash 5.0 already uses that CoreUI shell (ADR-0005). `frontend/src/_nav.tsx`
does not: it is four flat items (Clusters, Cluster detail, My access, Admin
permissions). Operators coming from 4.1 cannot find Namespaces, Pods, or
Settings where they left them, and every later resource view has no agreed
slot.

The 4.1 templates are a **visual and information-architecture reference
only**. This change recreates the same look and menu structure in the existing
React/CoreUI SPA. It does not copy Jinja markup, render Jinja templates, or
add server-rendered frontend code.

The React implementation reproduces the 4.1 **shell behavior that is still
missing** and the **4.1 menu**, with two rulings:

- The **Plugins** group is absent, and so are the plugin-gated entries that
  4.1 nests inside other groups (Cert-Manager, LoadBalancers, Gateway API,
  Trivy Operator, Applications). There is no 5.0 plugin system. ADR-0022.
- **Cluster Details** sits in the **Permissions** section. 4.1 has no such
  entry. 5.0 already has the view at `/clusters/:id`. It is not a top-level
  item and it is not under Interface → Cluster.

Resource pages that do not exist yet are honest stubs. This change does not
build Pods, Nodes, metrics, or settings forms.

## Purpose & Success Criteria

- **Purpose:** a logged-in operator sees the 4.1 information architecture
  (same section titles, group names, entry names, and order), can open the
  views that already exist, and lands on a stub for every other entry.
  Cluster Details opens the selected cluster.
- **Success criteria:**
  - The sidebar lists the menu in [§ Menu](#menu) and nothing else. There is
    no Plugins group and no plugin-only entry.
  - **Cluster Details** is the first entry under the Permissions title. With
    a selected cluster it navigates to `/clusters/<id>`. With none selected
    it navigates to `/clusters`.
  - **My access** stays in Permissions and opens `/permissions`.
  - **Users** opens `/admin/permissions?tab=users`. **Audit Log** opens
    `/admin/permissions?tab=audit`. Both show that tab.
  - The Settings group is visible only when `me.role === 'admin'`. A
    non-admin who opens a `/settings/*` URL is redirected to `/`.
  - Every stub entry renders a page whose heading is the menu label and whose
    body is the sentence `This view is not available yet.` It does not render
    a broken existing view and it does not redirect to `/clusters`.
  - The header menu button shows and hides the same sidebar the brand and
    the footer toggler belong to. The footer toggler still collapses the
    sidebar to icons (unfoldable).
  - Footer text matches 4.1's wording with no outbound URL:
    `DevOpsTales - KubeDash Copyright © 2021-2026` and
    `Powered by CoreUI UI Components`.
  - `task fe-check` stays green. No `https://` or protocol-relative CDN URL
    is introduced. 4.1's GitHub, docs, and CoreUI documentation links are
    not copied (ADR-0020).
- **Out of scope:**
  - Copying or running any 4.1 Jinja template. All implementation remains in
    `frontend/src/` using React and CoreUI.
  - Implementing any stubbed resource, settings form, workload map, or
    cluster-metrics dashboard.
  - A plugin system, or restoring Plugins later (that supersedes ADR-0022).
  - Editing ADR-0022 in place. It stays the accepted record of "4.1 parity
    minus Plugins". This briefing adds the Cluster Details row on top of
    that record.
  - Backend routes, RBAC objects, or new dependencies.
  - Replacing the header cluster switcher with 4.1's namespace `<select>`.
    5.0's scope control is the cluster switcher already in `AppHeader`.

## Context

- **Fits existing patterns: yes.** `_nav` data drives `AppSidebarNav`
  (`CNavTitle`, `CNavGroup`, `CNavItem`, `CNavLink`, `CBadge`). Routes live
  in `App.tsx`. Admin gating is `AdminRoute` in `routes.tsx`. The selected
  cluster is `useClusterStore` (`id`, `name`). Identity is `useCluster().me`
  with `role === 'admin'`.
- **In-force decisions:**
  - ADR-0022 — menu sections, group names, entry names, order, admin gating
    of Settings, Plugins group dropped, plugin-gated entries inside Network,
    Security, and Settings dropped.
  - ADR-0005 — CoreUI React shell. Do not introduce Tailwind.
  - ADR-0020 — no outbound URLs in the bundle. Copy layout and labels, not
    4.1's external `href`s.
  - ADR-0013 — `/permissions` remains the self-service access page. This
    change only keeps its menu slot.
- **Visual reference read 2026-10-21 (not implementation source):** branch `4.1`,
  `src/kubedash/templates/segments/partials/menu.html.j2`,
  `header.html.j2`, `footer.html.j2`.
- **Shell already present:** dark fixed sidebar, brand, close button, footer
  unfold toggler, header cluster switcher, notifications, theme switcher,
  profile menu. This change does not restyle those. It wires the header
  toggler (today the button updates state nothing reads) and replaces the
  footer outbound CoreUI link with text.

## Approaches Considered

1. **4.1 menu minus Plugins, Cluster Details under Permissions** (chosen).
   Matches ADR-0022 and the placement asked for this change. Stubs keep the
   menu honest until each view is built.
2. **Full 4.1 menu including Plugins.** Rejected by ADR-0022: every plugin
   entry would be a dead link.
3. **Keep the four-item nav and add entries per view.** Rejected by
   ADR-0022: each future view would re-decide its slot.

Cluster Details placement options inside the chosen menu:

- First item in the Permissions section, sibling of the two groups (chosen).
  It is a 5.0 page, not a Kubernetes RBAC kind, so it does not go inside
  Cluster Permissions, and it does not go under Interface → Cluster
  (Namespaces, Nodes, CRDs).
- Inside Cluster Permissions. Rejected: that group is ServiceAccounts and
  Role objects.
- Left at the top level. Rejected: the request puts it under Permissions.

## Menu

Normative order, top to bottom. Labels are exact, including the Workload
badge text `Beta`. 4.1's `VolumeClames` is spelled **VolumeClaims**.

A row marked **view** renders an existing page. A row marked **stub** renders
the stub page. **admin** rows are omitted from the sidebar unless
`me.role === 'admin'`, and their URL is behind `AdminRoute`.

| # | Section | Group | Entry | Path | Kind |
|---|---|---|---|---|---|
| 1 | — | Dashboard | Cluster Metrics | `/clusters` | view |
| 2 | — | Dashboard | Workload | `/dashboard/workload-map` | stub, badge `Beta` |
| 3 | Permissions | — | Cluster Details | `/clusters/<selected id>` or `/clusters` when none is selected | view |
| 4 | Permissions | — | My access | `/permissions` | view |
| 5 | Permissions | User Management | Users | `/admin/permissions?tab=users` | view, admin route |
| 6 | Permissions | User Management | Groups | `/user/group` | stub |
| 7 | Permissions | Cluster Permissions | ServiceAccounts | `/cluster-permission/service-account` | stub |
| 8 | Permissions | Cluster Permissions | Roles | `/cluster-permission/role` | stub |
| 9 | Permissions | Cluster Permissions | RoleBindings | `/cluster-permission/role-binding` | stub |
| 10 | Permissions | Cluster Permissions | ClusterRoles | `/cluster-permission/cluster-role` | stub |
| 11 | Permissions | Cluster Permissions | ClusterRoleBindings | `/cluster-permission/cluster-role-binding` | stub |
| 12 | Interface | Cluster | Namespaces | `/cluster/namespace` | stub |
| 13 | Interface | Cluster | Nodes | `/cluster/node` | stub |
| 14 | Interface | Cluster | CRDs | `/cluster/crd` | stub |
| 15 | Interface | Workloads | Pods | `/workload/pods` | stub |
| 16 | Interface | Workloads | Deployments | `/workload/deployments` | stub |
| 17 | Interface | Workloads | StatefulSets | `/workload/statefulsets` | stub |
| 18 | Interface | Workloads | DaemonSets | `/workload/daemonsets` | stub |
| 19 | Interface | Workloads | ReplicaSets | `/workload/replicasets` | stub |
| 20 | Interface | Network | Services | `/network/service` | stub |
| 21 | Interface | Network | Ingress | `/network/ingress` | stub |
| 22 | Interface | Storage | ConfigMaps | `/storage/configmap` | stub |
| 23 | Interface | Storage | Volumes | `/storage/pv` | stub |
| 24 | Interface | Storage | VolumeClaims | `/storage/pvc` | stub |
| 25 | Interface | Storage | VolumeSnapshot | `/storage/volumesnapshot` | stub |
| 26 | Interface | Storage | StorageClass | `/storage/storage-class` | stub |
| 27 | Interface | Storage | SnapshotClass | `/storage/snapshot-class` | stub |
| 28 | Interface | Security | Secrets | `/security/secret` | stub |
| 29 | Interface | Security | Network Policies | `/security/network-policy` | stub |
| 30 | Interface | Security | Priority Classes | `/security/priorityclass` | stub |
| 31 | Interface | Other Resources | HPAs | `/other-resource/horizontal-pod-autoscaler` | stub |
| 32 | Interface | Other Resources | VPAs | `/other-resource/vertical-pod-autoscaler` | stub |
| 33 | Interface | Other Resources | Pod Disruption Budget | `/other-resource/pod-disruption-budget` | stub |
| 34 | Interface | Other Resources | Resource Quota | `/other-resource/resource-quota` | stub |
| 35 | Interface | Other Resources | Limit Range | `/other-resource/limit-range` | stub |
| 36 | Interface | Other Resources | Runtime Class | `/other-resource/runtimeclass` | stub |
| 37 | — | Settings | Auth Provider | `/settings/sso-config` | stub, admin |
| 38 | — | Settings | Kubernetes Cluster | `/clusters` | view, admin |
| 39 | — | Settings | HA Status | `/settings/cluster-status` | stub, admin |
| 40 | — | Settings | Audit Log | `/admin/permissions?tab=audit` | view, admin |

Section chrome, in order:

1. Dashboard group (no section title).
2. Divider.
3. Title `Permissions`, then rows 3–11.
4. Divider.
5. Title `Interface`, then rows 12–36.
6. Settings group (rows 37–40), no extra section title, only for admins.
7. No divider and no group after Settings. 4.1's trailing divider belonged
   to Plugins.

Dropped, and asserted absent:

- Group `Plugins` and entries OCI Registry, Helm Charts, Flux CD, AI Chat.
- Network: Cert-Manager, LoadBalancers, Gateway API.
- Security: Trivy Operator and its Namespace Reports / Cluster Reports.
- Settings: Applications.
- The current labels `Clusters`, `Cluster detail`, `Admin permissions`.

`Cluster Metrics` and `Kubernetes Cluster` both open `/clusters` until a
metrics view exists. That is the ADR-0022 mapping, not a second page.

## Requirements

1. **R1 — Menu contract.** `frontend/src/_nav.tsx` exports a function
   `navigation({ clusterId, isAdmin })` whose rendered labels, order,
   sections, badge, and paths equal [§ Menu](#menu). `isAdmin === false`
   omits the Settings group. `clusterId === null` makes Cluster Details
   point at `/clusters`; otherwise `/clusters/${clusterId}`.
   - **Acceptance:** a unit test imports `navigation` and compares the
     flattened labels and paths to the table for both `{ clusterId: 7,
     isAdmin: true }` and `{ clusterId: null, isAdmin: false }`. The
     non-admin result has no `Settings`, `Auth Provider`, `HA Status`, or
     `Audit Log`. Neither result contains `Plugins`, `Cert-Manager`,
     `LoadBalancers`, `Gateway API`, `Trivy Operator`, or `Applications`.

2. **R2 — Sidebar renders that contract.** `AppSidebar` passes
   `navigation(...)` to `AppSidebarNav`. Section titles use `CNavTitle`.
   Groups use `CNavGroup` with `compact`. Dividers are
   `border-top d-none d-md-flex` elements between Dashboard and Permissions
   and between Permissions and Interface. The Workload entry shows a
   warning badge whose text is `Beta`.
   - **Acceptance:** render the sidebar as admin with cluster id 7; the
     Permissions title is followed by a link named `Cluster Details` whose
     `href` ends in `/clusters/7`, then `My access`. Render as a non-admin;
     `Settings` is not in the document.

3. **R3 — Existing pages keep working.** These paths still render the
   current views, not the stub:
   - `/clusters` → `ClustersView`
   - `/clusters/:id` → `ClusterView`
   - `/permissions` → `PermissionsView`
   - `/admin/permissions` → `AdminPermissionsView` inside `AdminRoute`
   - **Acceptance:** the existing view tests stay green. Users and Audit
     Log links do not replace those views.

4. **R4 — Admin tab from the query string.** `AdminPermissionsView` reads
   `tab` from the URL. `users`, `templates`, and `audit` select that tab on
   load. Any other value, or no value, selects `users`. Changing tabs does
   not need to write the URL.
   - **Acceptance:** render at `/admin/permissions?tab=audit` and the Audit
     panel is the one showing; render at `?tab=users` and the Users table
     is the one showing.

5. **R5 — One stub page for every stub row.** A single view,
   `frontend/src/views/Stub/index.tsx`, receives the menu label and renders
   an `h1` with that label and a paragraph `This view is not available yet.`
   `App.tsx` registers one route per stub path in [§ Menu](#menu). Paths
   under `/settings/` are wrapped in `ProtectedRoute` and `AdminRoute`.
   Other stub paths are wrapped in `ProtectedRoute` only. The catch-all
   redirect to `/clusters` remains for unknown paths and must not swallow
   these routes.
   - **Acceptance:** `/workload/pods` shows heading `Pods` and the stub
     sentence; `/settings/sso-config` shows `Auth Provider` for an admin
     and redirects a non-admin to `/`.

6. **R6 — Header toggler controls the sidebar.** One store,
   `frontend/src/store/sidebar.ts`, holds `visible: boolean` (default
   `true`), `toggle`, and `setVisible`. `AppHeader`'s menu button calls
   `toggle`. `AppSidebar`'s `CSidebar` `visible` / `onVisibleChange` use
   the same store. The sidebar footer toggler still toggles `unfoldable`
   locally and does not flip `visible`.
   - **Acceptance:** a test renders header and sidebar together; after
     clicking the menu button the sidebar's CoreUI visible class is gone;
     clicking again brings it back.

7. **R7 — Footer labels, no outbound links.** `AppFooter` shows the two
   strings in the success criteria as text. It contains no `<a href>`.
   - **Acceptance:** a test reads both strings and
     `container.querySelectorAll('a')` has length 0. `task fe-check` passes.

## Risks

- About thirty stub routes will exist before their views. The stub sentence
  is the guard against a blank page or a wrong redirect. Replacing a stub
  later means swapping that one route's element, not editing the menu label.
- `Cluster Metrics` and `Kubernetes Cluster` share `/clusters` until a
  metrics page is a separate change. The labels stay different so the menu
  still matches 4.1.
- Hiding Settings in the nav is not the access control. `AdminRoute` is.
- ADR-0022's confirmation text says the nav is exactly its table. This
  briefing adds Cluster Details and My access on top of that table. The
  accepted ADR file is not edited.
