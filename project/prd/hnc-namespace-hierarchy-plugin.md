### PRD: HNC Namespace Hierarchy Plugin

**Status**: Proposed (plugin, optional per cluster)  

#### Problem / Why

Many users run the [Hierarchical Namespace Controller (HNC)](https://github.com/kubernetes-sigs/multi-tenancy/tree/master/incubator/hnc) to organize Kubernetes namespaces into parent/child trees and inherit policies across them. Today, KubeDash:

- Treats namespaces as a **flat list**, ignoring HNC hierarchy.
- Has no **visualization** of multi-level namespace relationships.
- Cannot perform **HNC-aware write operations** (e.g. creating subnamespaces) from the UI.

This makes KubeDash feel “blind” in HNC-enabled clusters and forces users back to `kubectl hns` and ad‑hoc tooling. We want an HNC-aware plugin that discovers namespace hierarchies, visualizes them clearly, and supports basic write flows, taking inspiration from `hnc-example-use-cases` (`https://github.com/sighupio/hnc-example-use-cases`).

#### Goals

- Provide an **optional HNC plugin** that can be enabled per deployment/cluster.
- **Augment the existing namespace view**, not replace it:
  - Add a dedicated **“Hierarchy” / “HNC” menu/section** under the namespace area of the UI.
- Implement a **multi-level namespace visualization**:
  - Table view with **breadcrumb**, **parent**, and **children** columns.
  - Support arbitrary hierarchy depth.
- Support **HNC write operations** for common flows:
  - Create a **subnamespace** under an existing namespace.
  - Re-parent / move a namespace (subject to HNC constraints).
- Remain **cloud-vendor agnostic**:
  - Work on any cluster where HNC CRDs and controller are installed, regardless of underlying provider.

#### Out of Scope (v1)

- Full HNC configuration management (e.g. editing `HNCConfiguration` or every aspect of policy propagation).
- Advanced policy editing UX (RBAC, NetworkPolicies, Quotas) in the hierarchy view.
- Multi-cluster awareness of HNC trees (v1 assumes a single cluster context at a time).
- Auto-installing HNC; the operator is responsible for deploying HNC and `kubectl-hns` equivalents.

#### Functional Requirements

- **Plugin & Capability Detection**
  - HNC support is implemented as a **plugin** that can be:
    - Enabled/disabled via KubeDash configuration (e.g. `plugins.hnc.enabled = true/false`).
    - Optionally auto-enabled when HNC CRDs are detected (e.g. `hierarchyconfigurations.hnc.x-k8s.io`).
  - When disabled or when CRDs are absent:
    - The UI must not show HNC-specific menus.
    - Namespace view behaves exactly as today.

- **Namespace Hierarchy Discovery**
  - Backend queries HNC state using the in-cluster Kubernetes API:
    - `HierarchyConfiguration` objects for parent/child relationships.
    - `SubnamespaceAnchor` objects for subnamespace definitions.
  - Build an in-memory **namespace tree model**:
    - For each namespace, compute:
      - `parent` (if any).
      - `children` (direct subnamespaces).
      - `path` / `breadcrumb` from root to leaf (e.g. `team-a / feature-x / canary`).
    - Handle multiple top-level roots (namespaces with no parent).
  - Keep discovery **read-only** and compatible with any provider that exposes HNC CRDs.

- **UI: Namespace Hierarchy Menu**
  - Under the existing namespace area of the KubeDash UI, add a **separate menu/section** (e.g. “Namespace Hierarchy” or “HNC”) that:
    - Lists namespaces in a **table layout** with at least:
      - Namespace name.
      - **Breadcrumb** (full hierarchy path).
      - **Parent** namespace (or “—” / “root”).
      - **Children count** and/or preview list (e.g. “3 children” with hover or expandable detail).
    - Allows filtering/searching by namespace name and/or breadcrumb.
  - Selecting a row should:
    - Highlight the corresponding namespace.
    - Provide a link back to the existing **namespace detail view** (reusing current UX).

- **Write Operations: Subnamespace Management**
  - From the hierarchy table or a namespace detail action menu, allow:
    - **Create subnamespace**:
      - User chooses a parent namespace and provides the subnamespace name.
      - Backend creates the appropriate `SubnamespaceAnchor` (and any required namespace resource), following HNC conventions.
      - On success, the new namespace appears as a child in the hierarchy view.
    - **Re-parent / Move namespace** (if permitted by HNC rules):
      - User selects a namespace and a new parent.
      - Backend updates the corresponding HNC objects to reflect the new parent.
      - Must handle and surface errors when HNC denies illegal moves.
  - All write operations must:
    - Validate inputs server-side (no trusting client-only validation).
    - Surface clear, non-verbose error messages in the UI (e.g. “HNC: cannot make a namespace its own ancestor”).
    - Log detailed errors with context for operators (namespaces, CRD types, API responses).

- **Integration with Existing Namespace View**
  - From the standard namespace list/detail views:
    - Provide a **“View in hierarchy”** action, which navigates to or focuses the hierarchy table and highlights the selected namespace.
  - The hierarchy plugin must not change existing namespace CRUD semantics outside of explicit HNC flows.

#### Non-Functional Requirements

- **Security**
  - Use the existing Kubernetes client configuration and RBAC; do not introduce separate credentials for HNC.
  - Respect user permissions:
    - Users without rights to modify HNC-related CRDs must see the hierarchy read-only (no write controls).
  - Do not leak internal CRD details in error messages; keep them in logs, not user-facing toasts.

- **Performance & Scalability**
  - Hierarchy discovery queries must be efficient:
    - Avoid per-namespace API calls; prefer list operations on HNC CRDs.
    - Cache hierarchy computations for a short TTL where appropriate, invalidating on write operations.
  - The table view should handle clusters with:
    - Hundreds of namespaces.
    - Multiple hierarchy levels (depth >= 4–5) without timeouts or extreme UI lag.

- **Compatibility**
  - Work across:
    - Managed Kubernetes offerings (GKE, EKS, AKS, etc.).
    - On-prem/self-managed clusters.
  - Assume only that the HNC CRDs and controller are installed and functioning; no other cloud-vendor specifics.

- **Observability**
  - Expose internal metrics for:
    - HNC hierarchy discovery latency and error counts.
    - HNC write operations (success/failure).
  - Log enough context to correlate UI actions with HNC CRD updates (namespaces, operation type, result).

#### Future Iterations (Nice to Have)

- Visual **tree/graph representation** of the hierarchy in addition to the table view.
- Inline indicators for **inherited vs overridden policies** (RBAC, NetworkPolicies, ResourceQuotas) per namespace.
- Bulk actions on subtrees (e.g. apply a label or annotation to a namespace and all descendants).
- Deeper alignment with example patterns from `hnc-example-use-cases` (e.g. namespace templates, self-provisioning flows).

