# Namespace Page — 4.1 Behavior in the React SPA

> **Status:** APPROVED
> **Route:** `/cluster/namespace`
> **Reference:** KubeDash branch `4.1`, `src/kubedash/templates/cluster/namespace.html.j2`

## Goal

Replace the Namespaces placeholder with the KubeDash 4.1 namespace-management
experience while preserving the current multi-cluster React and API
architecture. Users can list namespaces for the selected cluster. KubeDash
admins who also pass Kubernetes authorization can create and delete
namespaces.

## User Experience

The page uses a CoreUI card and the shared Bootstrap 5 `KubeDataTable`.
It contains the 4.1 columns in this order:

1. Status
2. Namespace
3. Repository
4. Pipeline
5. Created
6. Action

Status comes from `status.phase`. Created comes from
`metadata.creation_timestamp`. Repository and Pipeline read the
`kubedash.io/repository` and `kubedash.io/pipeline` namespace annotations.
Only HTTP(S) values render as links; missing or invalid values render as an
em dash.

The selected cluster comes from the shared cluster store. If no cluster is
selected, the page shows a prompt and does not make a resource request.
Loading, empty, and API-error states render inside the card.

Admins see:

- An Add control that opens a **New Namespace** modal.
- A Delete action for non-protected namespaces.
- A confirmation step before deletion.

Non-admin users see the list without mutation controls.

## API Design

Extend the existing cluster-resource namespace collection:

- `GET /api/v1/clusters/<id>/resources/namespaces`
- `POST /api/v1/clusters/<id>/resources/namespaces`
- `DELETE /api/v1/clusters/<id>/resources/namespaces/<name>`

The existing GET behavior remains compatible with the header namespace
selector. POST accepts a namespace name. DELETE identifies the namespace in
the path.

Mutations require both:

1. KubeDash admin status through `require_admin()`.
2. The existing Kubernetes authorization check for `create` or `delete` on
   the cluster-scoped `namespaces` resource.

`K8sClient` exposes focused create and delete namespace methods. Calls still
go through `K8sClientPool`; no per-request client construction is introduced.

## Validation and Safety

Namespace names must satisfy Kubernetes DNS-label rules. Validation runs in
the API and is mirrored in the modal for immediate feedback.

Deletion is blocked for:

- `default`
- `kube-system`
- `kube-public`
- `kube-node-lease`

Rejected protected-namespace deletion reuses the existing 409
`CLUSTER_ALREADY_EXISTS` carrier, following the current user/template conflict
precedent, and does not call Kubernetes. The message identifies the protected
namespace; no new stable code is added to the frozen v1 contract.

Existing error codes remain the contract:

- `403 RBAC_DENIED` for failed KubeDash or Kubernetes authorization.
- Existing `CLUSTER_NOT_FOUND` behavior from the cluster binding gate.
- `422 INVALID_KUBECONFIG` as the existing validation carrier for an invalid
  namespace name.
- `409 CLUSTER_ALREADY_EXISTS` for a duplicate name or protected namespace.
- `502 CLUSTER_UNREACHABLE` for non-semantic Kubernetes client failures.

DELETE is idempotent: Kubernetes 404 is treated as success. This avoids
inventing an inaccurate namespace-specific 404 code in the frozen contract
and makes retrying a timed-out delete safe.

No new dependency or stable error code is introduced.

## Frontend Data Flow

The view queries the selected cluster using the shared key
`['namespaces', clusterId]`, which is also used by the header selector.
After create or delete, it invalidates that key so both surfaces refresh.
If the deleted namespace is selected, the store selection is cleared.

The `/cluster/namespace` entry is removed from `stubRoutes` and replaced by a
lazy-loaded protected route. External annotation links use
`target="_blank"` and `rel="noreferrer"`.

## Verification

Write the acceptance feature before implementation. It covers:

- Listing namespaces in the selected cluster.
- Admin namespace creation.
- Admin namespace deletion with confirmation.
- Hidden mutation controls for non-admin users.
- Rejected deletion of protected namespaces.

Backend tests cover create/delete client calls, admin and Kubernetes
authorization gates, duplicate mapping, idempotent delete, protected
namespaces, and the absence of a client call on rejected deletion.

Frontend Vitest/MSW tests cover the six 4.1 columns, annotation links, add and
delete flows, query refresh, admin-only actions, loading/empty/error states,
and protected namespace behavior.

Final verification runs targeted backend and frontend tests, `task fe-build`,
`task fe-check`, and `qlty check --fix --level=low --trigger agent`.

## Out of Scope

- Namespace-as-a-Service requests and approvals.
- Repository or pipeline provisioning.
- Editing namespace labels or annotations.
- Bulk namespace deletion.
- Changes to the header namespace selector beyond shared cache refresh.
