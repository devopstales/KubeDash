# 4.1 Namespace Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `/cluster/namespace` with the 4.1 namespace list and admin create/delete behavior on the header-selected cluster.

**Architecture:** Extend the existing cluster resource API rather than introducing a second namespace domain. Namespace reads and writes go through `bound_cluster_or_404`, `rbac.can`, and `K8sClientPool`; the React view shares the `['namespaces', clusterId]` query with the header selector.

**Tech Stack:** Flask-Smorest, Marshmallow, Kubernetes Python client, pytest, React 18, TypeScript, CoreUI, TanStack Query, DataTables React, Vitest, RTL, and MSW.

## Global Constraints

- Keep `app/services/` free of Flask imports.
- Do not add dependencies or stable v1 error codes.
- Use the informer/resource seam already established by `ResourceApi`; do not create per-request Kubernetes clients.
- Protect `default`, `kube-system`, `kube-public`, and `kube-node-lease` from deletion.
- Render annotation links only for HTTP(S) URLs.
- Keep DELETE idempotent when Kubernetes returns 404.
- Author the acceptance feature before implementation.
- Commit spec-zone changes before code-zone changes.

## File Map

- Create `tests/features/namespace-management.feature`: executable behavior contract.
- Modify `backend/app/schemas/resource.py`: namespace mutation request/response schemas.
- Modify `backend/app/services/k8s_client.py`: create/delete namespace operations and Kubernetes error mapping.
- Modify `backend/app/api/resources.py`: namespace mutation routes, validation, admin gate, SAR gate, and protected-name guard.
- Modify `backend/tests/api/test_resources.py`: route behavior and authorization tests.
- Create `backend/tests/services/test_k8s_client_namespaces.py`: Kubernetes client mapping tests.
- Modify `frontend/src/lib/types.ts`: Kubernetes Namespace shape.
- Modify `frontend/src/components/AppHeader.jsx`: keep the shared namespace query value as raw resource items.
- Create `frontend/src/views/Cluster/Namespaces.tsx`: 4.1 list and mutation UI.
- Modify `frontend/src/App.tsx`: real protected route.
- Modify `frontend/src/views/Stub/routes.ts`: remove the namespace placeholder.
- Create `frontend/tests/views/namespaces.test.tsx`: view behavior tests.
- Modify `frontend/tests/views/Stub.test.tsx`: remove Namespaces from placeholder expectations.

---

### Task 1: Acceptance Contract

**Files:**
- Create: `tests/features/namespace-management.feature`

**Interfaces:**
- Consumes: approved behavior from `.skillgrid/specs/2026-10-21-namespace-page/briefing.md`.
- Produces: named scenarios referenced by backend and frontend tests.

- [ ] **Step 1: Write the acceptance feature**

```gherkin
Feature: Manage namespaces on the selected cluster
  As a KubeDash operator
  I want the 4.1 namespace list and guarded namespace mutations
  So that namespace administration remains available in the React SPA

  Scenario: An operator lists namespaces on the selected cluster
    Given the selected cluster contains namespaces
    When the operator opens "/cluster/namespace"
    Then the page shows Status, Namespace, Repository, Pipeline, Created, and Action
    And safe repository and pipeline annotations are links

  Scenario: An authorized admin creates a namespace
    Given the operator is a KubeDash admin
    And Kubernetes authorizes namespace creation
    When the admin creates a valid namespace
    Then the namespace appears in the page and header namespace lists

  Scenario: An authorized admin deletes a namespace
    Given the operator is a KubeDash admin
    And Kubernetes authorizes namespace deletion
    When the admin confirms deletion of a non-protected namespace
    Then the namespace disappears from the page and header namespace lists

  Scenario: A non-admin cannot mutate namespaces
    Given the operator is not a KubeDash admin
    When the operator opens "/cluster/namespace"
    Then namespace mutation controls are hidden
    And direct namespace mutation requests are denied

  Scenario Outline: A protected namespace cannot be deleted
    Given the operator is a KubeDash admin
    When the admin attempts to delete "<namespace>"
    Then the request is rejected without calling Kubernetes

    Examples:
      | namespace         |
      | default           |
      | kube-system       |
      | kube-public       |
      | kube-node-lease   |
```

- [ ] **Step 2: Commit the behavior contract**

```bash
git add tests/features/namespace-management.feature
git commit -m "test: specify namespace management"
```

---

### Task 2: Kubernetes Namespace Mutation Seam

**Files:**
- Modify: `backend/app/services/k8s_client.py:30-36,190-194`
- Create: `backend/tests/services/test_k8s_client_namespaces.py`

**Interfaces:**
- Consumes: `K8sClient._v1`, `_delete(kind, fn)`, and `_unreachable(kind, error)`.
- Produces:
  - `K8sClient.create_namespace(name: str) -> dict[str, Any]`
  - `K8sClient.delete_namespace(name: str) -> None`

- [ ] **Step 1: Write failing Kubernetes client tests**

```python
from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterAlreadyExistsError, ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(v1: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._v1 = v1
    return client


def test_create_namespace_returns_cluster_object() -> None:
    seen: list[object] = []
    namespace = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "team-a"}})
    v1 = SimpleNamespace(
        create_namespace=lambda body: (seen.append(body), namespace)[1],
    )
    result = _client(v1).create_namespace("team-a")
    assert result == {"metadata": {"name": "team-a"}}
    assert seen[0].metadata.name == "team-a"


def test_create_namespace_maps_409_to_conflict() -> None:
    def create_namespace(_body: object) -> None:
        raise ApiException(status=409)

    with pytest.raises(ClusterAlreadyExistsError):
        _client(SimpleNamespace(create_namespace=create_namespace)).create_namespace("team-a")


def test_create_namespace_maps_other_api_error_to_unreachable() -> None:
    def create_namespace(_body: object) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(create_namespace=create_namespace)).create_namespace("team-a")


def test_delete_namespace_is_idempotent_on_404() -> None:
    def delete_namespace(_name: str) -> None:
        raise ApiException(status=404)

    _client(SimpleNamespace(delete_namespace=delete_namespace)).delete_namespace("gone")
```

- [ ] **Step 2: Run the tests and confirm the missing methods**

Run:

```bash
uv run pytest backend/tests/services/test_k8s_client_namespaces.py -q
```

Expected: FAIL because `K8sClient` has no `create_namespace` or `delete_namespace`.

- [ ] **Step 3: Add the namespace client methods**

Add `ClusterAlreadyExistsError` to the existing error imports, then add:

```python
def create_namespace(self, name: str) -> dict[str, Any]:
    body = k8s_client.V1Namespace(metadata=k8s_client.V1ObjectMeta(name=name))
    try:
        return self._v1.create_namespace(body).to_dict()
    except ApiException as e:
        if e.status == 409:
            raise ClusterAlreadyExistsError(f"namespace '{name}' already exists") from e
        self._unreachable("create_namespace", e)
        raise AssertionError("unreachable")

def delete_namespace(self, name: str) -> None:
    self._delete("delete_namespace", lambda: self._v1.delete_namespace(name))
```

- [ ] **Step 4: Run the service tests**

Run:

```bash
uv run pytest backend/tests/services/test_k8s_client_namespaces.py -q
```

Expected: 4 passed.

- [ ] **Step 5: Commit the Kubernetes seam**

```bash
git add backend/app/services/k8s_client.py backend/tests/services/test_k8s_client_namespaces.py
git commit -m "feat(api): add namespace client mutations"
```

---

### Task 3: Namespace Mutation API

**Files:**
- Modify: `backend/app/schemas/resource.py`
- Modify: `backend/app/api/resources.py`
- Modify: `backend/tests/api/test_resources.py`

**Interfaces:**
- Consumes:
  - `K8sClient.create_namespace(name)`
  - `K8sClient.delete_namespace(name)`
  - `require_admin()`
  - `rbac.can(user, cluster, verb, resource, namespace, name, api_group)`
- Produces:
  - `POST /api/v1/clusters/<id>/resources/namespaces`
  - `DELETE /api/v1/clusters/<id>/resources/namespaces/<name>`

- [ ] **Step 1: Extend `FakeK8s` and write failing route tests**

Add this state and behavior to `FakeK8s`:

```python
def __init__(self, kubeconfig: bytes) -> None:
    self.kubeconfig = kubeconfig
    self.created_namespaces: list[str] = []
    self.deleted_namespaces: list[str] = []

def create_namespace(self, name: str) -> dict:
    self.created_namespaces.append(name)
    return {"metadata": {"name": name}}

def delete_namespace(self, name: str) -> None:
    self.deleted_namespaces.append(name)
```

Change the `fake_k8s` fixture to return the constructed fake so tests can inspect it:

```python
@pytest.fixture()
def fake_k8s(api_app, monkeypatch) -> FakeK8s:
    import importlib
    import app.services.k8s_client as kc

    fake = FakeK8s(b"unused")
    res = importlib.import_module("app.api.resources")
    fake_pool = kc.K8sClientPool(factory=lambda plain: fake)
    monkeypatch.setitem(res.__dict__, "pool", fake_pool)
    return fake
```

Add route tests:

```python
def test_admin_creates_namespace(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "team-b"},
        headers=h,
    )
    assert r.status_code == 201
    assert r.get_json()["name"] == "team-b"
    assert fake_k8s.created_namespaces == ["team-b"]


@pytest.mark.parametrize(
    "name", ["default", "kube-system", "kube-public", "kube-node-lease"]
)
def test_protected_namespace_delete_is_rejected_without_client_call(
    api_client, auth_client, fake_k8s, monkeypatch, name
) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.delete(
        f"/api/v1/clusters/1/resources/namespaces/{name}", headers=h
    )
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"
    assert fake_k8s.deleted_namespaces == []


def test_admin_deletes_namespace(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.delete(
        "/api/v1/clusters/1/resources/namespaces/team-b", headers=h
    )
    assert r.status_code == 200
    assert r.get_json() == {"name": "team-b"}
    assert fake_k8s.deleted_namespaces == ["team-b"]


def test_namespace_create_requires_admin(
    api_client, auth_client, api_app, fake_k8s, monkeypatch
) -> None:
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.binding import ClusterBinding
    from app.models.cluster import Cluster
    from app.models.user import User

    auth_client.login()
    admin_headers = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, admin_headers)
    with api_app.app_context():
        cluster = db.session.get(Cluster, 1)
        user = User(sub="plain-user", email="plain@example.com", role="user")
        db.session.add(user)
        db.session.flush()
        db.session.add(ClusterBinding(user_id=user.id, cluster_id=cluster.id, role="viewer"))
        db.session.commit()
        access, _ = issue_token_pair(user)
    _allow_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "team-b"},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert fake_k8s.created_namespaces == []


def test_namespace_create_asks_sar_for_create(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "team-b"},
        headers=h,
    )
    assert r.status_code == 403
    assert asked == [("create", "namespaces", None, None, "")]


def test_invalid_namespace_name_is_422(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "Not Valid"},
        headers=h,
    )
    assert r.status_code == 422
    assert r.get_json()["error"]["code"] == "INVALID_KUBECONFIG"
    assert fake_k8s.created_namespaces == []
```

- [ ] **Step 2: Run the route tests and confirm they fail**

Run:

```bash
uv run pytest backend/tests/api/test_resources.py -q
```

Expected: existing list tests pass; new POST/DELETE tests fail with method-not-allowed responses.

- [ ] **Step 3: Add mutation schemas**

Append to `backend/app/schemas/resource.py`:

```python
class NamespaceIn(Schema):
    name = String(required=True)


class NamespaceMutationOut(Schema):
    name = String(required=True)
```

- [ ] **Step 4: Add API validation, shared cluster resolution, and routes**

Add these imports and constants to `resources.py`:

```python
import re

from app.core.errors import (
    ClusterAlreadyExistsError,
    InvalidKubeconfigError,
    RbacDeniedError,
    ResourceKindNotSupportedError,
)
from app.core.security import require_admin
from app.schemas.resource import NamespaceIn, NamespaceMutationOut, ResourceListOut

_NAMESPACE_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_PROTECTED_NAMESPACES = frozenset(
    {"default", "kube-system", "kube-public", "kube-node-lease"}
)
```

Extract the existing local/registered cluster branch into:

```python
def _cluster_for(user: object, cluster_id: int) -> object:
    if cluster_id == LOCAL_CLUSTER_ID:
        from app.api.clusters import _local_cluster

        return _local_cluster()
    return bound_cluster_or_404(user, cluster_id)
```

Use `_cluster_for(g.current_user, cluster_id)` in `list_resources`, then add:

```python
@blp.route("/clusters/<int:cluster_id>/resources/namespaces", methods=["POST"])
@blp.arguments(NamespaceIn)
@blp.response(201, NamespaceMutationOut)
@blp.doc(
    responses={
        403: "RBAC_DENIED",
        404: "CLUSTER_NOT_FOUND",
        409: "CLUSTER_ALREADY_EXISTS",
        422: "INVALID_KUBECONFIG",
        502: "CLUSTER_UNREACHABLE",
    }
)
def create_namespace(
    self, args: dict[str, object], cluster_id: int
) -> tuple[dict[str, str], int]:
    require_admin()
    name = str(args["name"])
    if not _NAMESPACE_NAME.fullmatch(name):
        raise InvalidKubeconfigError("invalid Kubernetes namespace name")
    cluster = _cluster_for(g.current_user, cluster_id)
    if not rbac.can(g.current_user, cluster, "create", "namespaces", None, None, ""):
        raise RbacDeniedError("create on namespaces")
    pool.get(cluster).create_namespace(name)
    return {"name": name}, 201


@blp.route(
    "/clusters/<int:cluster_id>/resources/namespaces/<name>",
    methods=["DELETE"],
)
@blp.response(200, NamespaceMutationOut)
@blp.doc(
    responses={
        403: "RBAC_DENIED",
        404: "CLUSTER_NOT_FOUND",
        409: "CLUSTER_ALREADY_EXISTS (protected namespace)",
        502: "CLUSTER_UNREACHABLE",
    }
)
def delete_namespace(self, cluster_id: int, name: str) -> tuple[dict[str, str], int]:
    require_admin()
    if name in _PROTECTED_NAMESPACES:
        raise ClusterAlreadyExistsError(f"namespace '{name}' is protected")
    cluster = _cluster_for(g.current_user, cluster_id)
    if not rbac.can(g.current_user, cluster, "delete", "namespaces", None, name, ""):
        raise RbacDeniedError("delete on namespaces")
    pool.get(cluster).delete_namespace(name)
    return {"name": name}, 200
```

- [ ] **Step 5: Run backend tests**

Run:

```bash
uv run pytest backend/tests/api/test_resources.py backend/tests/services/test_k8s_client_namespaces.py -q
```

Expected: all selected tests pass.

- [ ] **Step 6: Commit the API**

```bash
git add backend/app/api/resources.py backend/app/schemas/resource.py backend/tests/api/test_resources.py
git commit -m "feat(api): add namespace mutation routes"
```

---

### Task 4: 4.1 Namespace React View

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Modify: `frontend/src/components/AppHeader.jsx`
- Create: `frontend/src/views/Cluster/Namespaces.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/views/Stub/routes.ts`
- Create: `frontend/tests/views/namespaces.test.tsx`
- Modify: `frontend/tests/views/Stub.test.tsx`

**Interfaces:**
- Consumes:
  - `ResourceList<K8sNamespace>`
  - `GET/POST /api/v1/clusters/<id>/resources/namespaces`
  - `DELETE /api/v1/clusters/<id>/resources/namespaces/<name>`
  - shared query key `['namespaces', clusterId]`
- Produces: protected `/cluster/namespace` view.

- [ ] **Step 1: Add the namespace API type**

Add to `frontend/src/lib/types.ts`:

```typescript
export interface K8sNamespace {
  metadata?: {
    name?: string
    creation_timestamp?: string | null
    annotations?: Record<string, string> | null
  }
  status?: {
    phase?: string | null
  }
  [key: string]: unknown
}
```

- [ ] **Step 2: Write failing view tests**

Create `frontend/tests/views/namespaces.test.tsx` with these imports and the
DataTable test double:

```tsx
import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '../msw'
import NamespacesView from '../../src/views/Cluster/Namespaces'
import { useClusterStore } from '../../src/store/cluster'

vi.mock('../../src/components/KubeDataTable', () => {
  const Column = () => null
  function KubeDataTable({
    data,
    children,
  }: {
    data: Record<string, unknown>[]
    children: React.ReactNode
  }) {
    const columns = React.Children.toArray(children)
      .filter(React.isValidElement)
      .map(
        (child) =>
          (child as React.ReactElement<{ title: string; data?: string | null; children?: unknown }>)
            .props,
      )
    return (
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.title}>{column.title}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, index) => (
            <tr key={index}>
              {columns.map((column) => {
                const value = column.data == null ? row : row[column.data]
                const node =
                  typeof column.children === 'function'
                    ? (column.children as (value: unknown) => React.ReactNode)(value)
                    : (value as React.ReactNode)
                return <td key={column.title}>{node ?? ''}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  return { default: KubeDataTable, Column }
})
```

Then add this fixture and render harness before the tests:

```typescript
const ITEMS = [
  {
    metadata: {
      name: 'team-a',
      creation_timestamp: '2026-10-20T10:00:00Z',
      annotations: {
        'kubedash.io/repository': 'https://git.example/team-a',
        'kubedash.io/pipeline': 'javascript:alert(1)',
      },
    },
    status: { phase: 'Active' },
  },
  {
    metadata: { name: 'default', creation_timestamp: '2026-10-19T10:00:00Z' },
    status: { phase: 'Active' },
  },
]

const renderNamespaces = (role: 'admin' | 'user') => {
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: null,
  })
  server.use(
    http.get('*/api/v1/auth/me', () =>
      HttpResponse.json({
        sub: `${role}-sub`,
        email: `${role}@example.com`,
        display_name: role,
        groups: [],
        role,
        auth_source: 'oidc',
        kubeconfig_source: null,
        last_login_at: null,
      }),
    ),
    http.get('*/api/v1/clusters', () =>
      HttpResponse.json({ items: [{ id: 1, name: 'prod' }] }),
    ),
    http.get('*/api/v1/clusters/1/resources/namespaces', () =>
      HttpResponse.json({ items: ITEMS, kind: 'namespaces', cluster: 'prod' }),
    ),
  )
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter>
        <NamespacesView />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  localStorage.setItem('kd_token', 'test-token')
})

afterEach(() => {
  localStorage.clear()
  vi.restoreAllMocks()
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})
```

Add these tests:

```typescript
test('renders-the-4.1-columns-and-safe-annotation-links', async () => {
  renderNamespaces('admin')
  expect(await screen.findByText('team-a')).toBeTruthy()
  for (const title of ['Status', 'Namespace', 'Repository', 'Pipeline', 'Created', 'Action']) {
    expect(screen.getByText(title)).toBeTruthy()
  }
  expect(screen.getByRole('link', { name: 'Repository' }).getAttribute('href')).toBe(
    'https://git.example/team-a',
  )
  expect(screen.queryByRole('link', { name: 'Pipeline' })).toBeNull()
})

test('admin-creates-a-namespace-and-refreshes-the-shared-query', async () => {
  const user = userEvent.setup()
  const posted = vi.fn()
  server.use(
    http.post('*/api/v1/clusters/1/resources/namespaces', async ({ request }) => {
      posted(await request.json())
      return HttpResponse.json({ name: 'team-b' }, { status: 201 })
    }),
  )
  renderNamespaces('admin')
  await user.click(await screen.findByRole('button', { name: /add namespace/i }))
  await user.type(screen.getByLabelText(/^namespace$/i), 'team-b')
  await user.click(screen.getByRole('button', { name: /^add namespace$/i }))
  await waitFor(() => expect(posted).toHaveBeenCalledWith({ name: 'team-b' }))
})

test('admin-confirms-delete-and-clears-the-selected-namespace', async () => {
  const user = userEvent.setup()
  const deleted = vi.fn()
  vi.spyOn(window, 'confirm').mockReturnValue(true)
  useClusterStore.setState({ selectedNamespace: 'team-a' })
  server.use(
    http.delete(
      '*/api/v1/clusters/1/resources/namespaces/team-a',
      () => (deleted(), HttpResponse.json({ name: 'team-a' })),
    ),
  )
  renderNamespaces('admin')
  await user.click(await screen.findByRole('button', { name: /delete team-a/i }))
  await waitFor(() => expect(deleted).toHaveBeenCalled())
  expect(useClusterStore.getState().selectedNamespace).toBeNull()
})

test('non-admin-does-not-see-mutation-controls', async () => {
  renderNamespaces('user')
  expect(await screen.findByText('team-a')).toBeTruthy()
  expect(screen.queryByRole('button', { name: /add namespace/i })).toBeNull()
  expect(screen.queryByRole('button', { name: /delete team-a/i })).toBeNull()
})

test('mutation-error-renders-inline', async () => {
  const user = userEvent.setup()
  server.use(
    http.post('*/api/v1/clusters/1/resources/namespaces', () =>
      HttpResponse.json(
        { error: { code: 'CLUSTER_ALREADY_EXISTS', message: 'namespace already exists' } },
        { status: 409 },
      ),
    ),
  )
  renderNamespaces('admin')
  await user.click(await screen.findByRole('button', { name: /add namespace/i }))
  await user.type(screen.getByLabelText(/^namespace$/i), 'team-a')
  await user.click(screen.getByRole('button', { name: /^add namespace$/i }))
  expect(await screen.findByText(/namespace already exists/i)).toBeTruthy()
})

test('list-error-renders-inline', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/namespaces', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list denied' } },
        { status: 403 },
      ),
    ),
  )
  renderNamespaces('user')
  expect(await screen.findByText(/list denied/i, { selector: '.text-danger' })).toBeTruthy()
})

test('empty-list-renders-without-the-table', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/namespaces', () =>
      HttpResponse.json({ items: [], kind: 'namespaces', cluster: 'prod' }),
    ),
  )
  renderNamespaces('user')
  expect(await screen.findByText('No namespaces found')).toBeTruthy()
  expect(screen.queryByRole('table')).toBeNull()
})
```

- [ ] **Step 3: Run the view test and confirm the missing module**

Run:

```bash
pnpm --dir frontend exec vitest run tests/views/namespaces.test.tsx
```

Expected: FAIL because `src/views/Cluster/Namespaces.tsx` does not exist.

- [ ] **Step 4: Implement the namespace view**

First change `AppHeader.jsx` so every consumer of the shared key stores raw
namespace resources rather than a component-specific projection:

```javascript
const namespacesQuery = useQuery({
  queryKey: ['namespaces', selectedCluster?.id],
  enabled: selectedCluster != null,
  queryFn: async () => {
    const r = await apiFetch(`/api/v1/clusters/${selectedCluster.id}/resources/namespaces`)
    if (r.error) throw new Error(r.error.message)
    return r.data?.items ?? []
  },
})
const namespaces = (namespacesQuery.data ?? [])
  .map((item) => item.metadata?.name)
  .filter(Boolean)
```

Then implement `Namespaces.tsx`:

```tsx
import React, { useState } from 'react'
import {
  CBadge,
  CBreadcrumb,
  CBreadcrumbItem,
  CButton,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CForm,
  CFormInput,
  CFormLabel,
  CModal,
  CModalBody,
  CModalFooter,
  CModalHeader,
  CModalTitle,
} from '@coreui/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'
import { useCluster } from '../../hooks/useCluster'
import { apiFetch } from '../../lib/api'
import type { K8sNamespace, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'

const PROTECTED = new Set(['default', 'kube-system', 'kube-public', 'kube-node-lease'])
const NAME_RE = /^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$/
const REPOSITORY = 'kubedash.io/repository'
const PIPELINE = 'kubedash.io/pipeline'

type NamespaceRow = {
  status: string
  name: string
  repository: string | null
  pipeline: string | null
  created: string
}

const safeHttpUrl = (value: string | undefined): string | null => {
  if (!value) return null
  try {
    const url = new URL(value)
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null
  } catch {
    return null
  }
}

const toRow = (namespace: K8sNamespace): NamespaceRow => {
  const annotations = namespace.metadata?.annotations ?? {}
  return {
    status: namespace.status?.phase ?? 'Unknown',
    name: namespace.metadata?.name ?? '',
    repository: safeHttpUrl(annotations[REPOSITORY]),
    pipeline: safeHttpUrl(annotations[PIPELINE]),
    created: namespace.metadata?.creation_timestamp ?? '',
  }
}

const NamespacesView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const selectedNamespace = useClusterStore((s) => s.selectedNamespace)
  const setSelectedNamespace = useClusterStore((s) => s.setSelectedNamespace)
  const { role } = useCluster()
  const queryClient = useQueryClient()
  const [modalOpen, setModalOpen] = useState(false)
  const [name, setName] = useState('')

  const query = useQuery<K8sNamespace[]>({
    queryKey: ['namespaces', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sNamespace>>(
        `/api/v1/clusters/${cluster!.id}/resources/namespaces`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data?.items ?? []
    },
  })

  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['namespaces', cluster!.id] })

  const createMutation = useMutation({
    mutationFn: async (namespace: string) => {
      const r = await apiFetch(`/api/v1/clusters/${cluster!.id}/resources/namespaces`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: namespace }),
      })
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
    },
    onSuccess: async () => {
      setModalOpen(false)
      setName('')
      await refresh()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (namespace: string) => {
      const r = await apiFetch(
        `/api/v1/clusters/${cluster!.id}/resources/namespaces/${encodeURIComponent(namespace)}`,
        { method: 'DELETE' },
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return namespace
    },
    onSuccess: async (deleted) => {
      if (selectedNamespace === deleted) setSelectedNamespace(null)
      await refresh()
    },
  })

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    if (NAME_RE.test(name)) createMutation.mutate(name)
  }

  const remove = (namespace: string) => {
    if (window.confirm(`Delete namespace ${namespace}?`)) {
      deleteMutation.mutate(namespace)
    }
  }

  const rows = (query.data ?? []).map(toRow)
  const externalLink = (label: string) => (url: string | null) =>
    url ? (
      <a href={url} target="_blank" rel="noreferrer">
        {label}
      </a>
    ) : (
      '\u2014'
    )

  return (
    <>
      <CCard className="shadow mb-4">
        <TopMenu>
          <CBreadcrumb className="my-0" aria-label="breadcrumb">
            <CBreadcrumbItem>Cluster</CBreadcrumbItem>
            <CBreadcrumbItem active>Namespaces</CBreadcrumbItem>
          </CBreadcrumb>
          {role === 'admin' ? (
            <CButton color="primary" onClick={() => setModalOpen(true)}>
              Add Namespace
            </CButton>
          ) : null}
        </TopMenu>
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">Namespace List</CCardTitle>
        </CCardHeader>
        <CCardBody>
          {!cluster ? (
            <div>No cluster selected.</div>
          ) : query.isLoading ? (
            <div>Loading namespaces...</div>
          ) : query.error ? (
            <div className="text-danger">Error loading namespaces: {query.error.message}</div>
          ) : rows.length === 0 ? (
            <div className="text-center text-muted">No namespaces found</div>
          ) : (
            <KubeDataTable data={rows}>
              <Column title="Status" data="status">
                {(status: string) => (
                  <CBadge color={status === 'Active' ? 'success' : 'secondary'}>{status}</CBadge>
                )}
              </Column>
              <Column title="Namespace" data="name" />
              <Column title="Repository" data="repository">
                {externalLink('Repository')}
              </Column>
              <Column title="Pipeline" data="pipeline">
                {externalLink('Pipeline')}
              </Column>
              <Column title="Created" data="created" />
              <Column title="Action" data={null}>
                {(row: NamespaceRow) =>
                  role === 'admin' && !PROTECTED.has(row.name) ? (
                    <CButton
                      color="danger"
                      size="sm"
                      aria-label={`Delete ${row.name}`}
                      onClick={() => remove(row.name)}
                    >
                      Delete
                    </CButton>
                  ) : null
                }
              </Column>
            </KubeDataTable>
          )}
          {createMutation.error ? (
            <div className="text-danger mt-3">{createMutation.error.message}</div>
          ) : null}
          {deleteMutation.error ? (
            <div className="text-danger mt-3">{deleteMutation.error.message}</div>
          ) : null}
        </CCardBody>
      </CCard>

      <CModal visible={modalOpen} onClose={() => setModalOpen(false)}>
        <CForm onSubmit={submit}>
          <CModalHeader>
            <CModalTitle>New Namespace</CModalTitle>
          </CModalHeader>
          <CModalBody>
            <CFormLabel htmlFor="namespace-name">Namespace</CFormLabel>
            <CFormInput
              id="namespace-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              invalid={name.length > 0 && !NAME_RE.test(name)}
            />
          </CModalBody>
          <CModalFooter>
            <CButton color="secondary" onClick={() => setModalOpen(false)}>
              Close
            </CButton>
            <CButton
              color="primary"
              type="submit"
              disabled={!NAME_RE.test(name) || createMutation.isPending}
            >
              Add Namespace
            </CButton>
          </CModalFooter>
        </CForm>
      </CModal>
    </>
  )
}

export default NamespacesView
```

- [ ] **Step 5: Wire the real route and remove the stub**

In `App.tsx`, add:

```typescript
const NamespacesView = React.lazy(() => import('./views/Cluster/Namespaces'))
```

and:

```tsx
<Route
  path="/cluster/namespace"
  element={
    <ProtectedRoute>
      <NamespacesView />
    </ProtectedRoute>
  }
/>
```

Remove the `/cluster/namespace` entry from `stubRoutes` and remove
`Namespaces` from `frontend/tests/views/Stub.test.tsx` placeholder assertions.

- [ ] **Step 6: Run frontend tests**

Run:

```bash
pnpm --dir frontend exec vitest run tests/views/namespaces.test.tsx tests/views/Stub.test.tsx
```

Expected: all selected tests pass.

- [ ] **Step 7: Commit the React view**

```bash
git add frontend/src/lib/types.ts frontend/src/components/AppHeader.jsx frontend/src/views/Cluster/Namespaces.tsx frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/tests/views/namespaces.test.tsx frontend/tests/views/Stub.test.tsx
git commit -m "feat(fe): add 4.1 namespace management"
```

---

### Task 5: Contract and Quality Verification

**Files:**
- Modify only files changed by formatters or fixes required by the checks.

**Interfaces:**
- Consumes: all previous task outputs.
- Produces: verified TASK-028 implementation.

- [ ] **Step 1: Run backend namespace tests**

```bash
uv run pytest backend/tests/api/test_resources.py backend/tests/services/test_k8s_client_namespaces.py -q
```

Expected: PASS.

- [ ] **Step 2: Run the frontend namespace tests**

```bash
pnpm --dir frontend exec vitest run tests/views/namespaces.test.tsx tests/views/Stub.test.tsx
```

Expected: PASS.

- [ ] **Step 3: Run the frontend build and air-gap check**

```bash
task fe-build
task fe-check
```

Expected: both commands exit 0.

- [ ] **Step 4: Run the repository quality gate**

```bash
qlty fmt
qlty check --fix --level=low --trigger agent
```

Expected: no unresolved findings in changed files.

- [ ] **Step 5: Re-run tests after automatic fixes**

```bash
uv run pytest backend/tests/api/test_resources.py backend/tests/services/test_k8s_client_namespaces.py -q
pnpm --dir frontend exec vitest run tests/views/namespaces.test.tsx tests/views/Stub.test.tsx
```

Expected: PASS.

- [ ] **Step 6: Commit formatter or quality fixes if any**

```bash
git add backend frontend tests/features/namespace-management.feature
git diff --cached --quiet || git commit -m "chore: satisfy namespace quality gate"
```

## Self-Review

- Spec coverage: list columns, annotation links, create/delete, two authorization gates, protected namespaces, shared cache refresh, selected namespace clearing, safe URLs, loading/empty/error states, and idempotent DELETE are all assigned to Tasks 2–4.
- Placeholder scan: no deferred implementation markers remain.
- Type consistency: backend methods use `name: str`; API and frontend mutation payloads use `{name: string}`; frontend reads Kubernetes `creation_timestamp`, annotations, and `status.phase`.
- Scope: NaaS requests, provisioning, annotation editing, and bulk delete remain excluded.
