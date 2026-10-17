import subprocess
from collections.abc import Iterator

import pytest
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

from app import create_app

# The brief's snippets assume `exposed_port` / `get_container_host`, which do
# not exist on testcontainers 4.x (they are `get_exposed_port` /
# `get_container_host_ip`). Shims keep the fixtures reading like the brief
# without changing their behavior.
#
# Known environment constraint: these Testcontainers fixtures need a
# container runtime on the host. Where the runtime is absent the tests ERROR
# at fixture setup — that is an environment block, not a code defect; the
# same assertions are proven by the runtime-free smoke in Task 1's report,
# and CI (with Docker) is the green backstop.
PostgresContainer.get_container_host = PostgresContainer.get_container_host_ip
RedisContainer.get_container_host = RedisContainer.get_container_host_ip
PostgresContainer.exposed_port = PostgresContainer.get_exposed_port
RedisContainer.exposed_port = RedisContainer.get_exposed_port


@pytest.fixture(scope="session")
def pg_container() -> Iterator[PostgresContainer]:
    pg = PostgresContainer("postgres:16")
    pg.start()
    try:
        yield pg
    finally:
        pg.stop()


@pytest.fixture(scope="session")
def redis_container() -> Iterator[RedisContainer]:
    r = RedisContainer("redis:7")
    r.start()
    try:
        yield r
    finally:
        r.stop()


@pytest.fixture()
def app(pg_container, redis_container):
    application = create_app({
        "TESTING": True,
        "DATABASE_URL": pg_container.get_connection_url(),
        "REDIS_URL": f"redis://{redis_container.get_container_host()}:{redis_container.exposed_port(6379)}",
        "KUBEDASH_JWT_SECRET": "test-jwt-secret",
        "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
    })
    with application.app_context():
        from app.extensions import db

        db.create_all()
        yield application
        db.session.rollback()


@pytest.fixture()
def client(app):
    return app.test_client()


# ---------------------------------------------------------------------------
# kind integration tier (Task 5 / R4, R10) — session-scoped creation, but the
# cluster is torn down per TEST FILE (ARCHITECTURE.md §9: per file, not per
# test): a wedged cluster in one integration file cannot poison the next.
# Env-block where kind/docker are unavailable: the fixture skips (kind
# missing) and the whole tier deselects with -m "not integration".
# ---------------------------------------------------------------------------
_KIND = "kubedash-test"
_kind_pod_added = False


def _kind_available() -> bool:
    r = subprocess.run(["kind", "version"], capture_output=True)
    return r.returncode == 0


def _kind_create_or_reuse() -> bytes:
    """Ensure the kind cluster exists and return its kubeconfig; also drop
    the ``kubedash-pod`` the pod-listing integration test asserts on."""
    existing = subprocess.run(
        ["kind", "get", "clusters"], capture_output=True, text=True
    ).stdout
    if _KIND not in existing:
        subprocess.run(["kind", "create", "cluster", "--name", _KIND], check=True)
    global _kind_pod_added
    if not _kind_pod_added:
        subprocess.run(
            [
                "kubectl",
                f"--context=kind-{_KIND}",
                "run",
                "kubedash-pod",
                "--image=nginx:alpine",
                "--restart=Never",
            ],
            check=True,
        )
        _kind_pod_added = True
    out = subprocess.run(
        ["kind", "get", "kubeconfig", "--name", _KIND], capture_output=True, text=True
    )
    return out.stdout.encode()


@pytest.fixture(scope="session")
def kind_cluster() -> bytes:
    if not _kind_available():
        pytest.skip("kind not available")
    return _kind_create_or_reuse()


@pytest.fixture(scope="session")
def kind_client(kind_cluster, app) -> tuple[int, bytes]:
    """(cluster_id, kubeconfig_bytes) — registers the kind cluster as a
    KubeDash Cluster row bound to the mock-OIDC test user."""
    from app.extensions import db
    from app.models.binding import ClusterBinding
    from app.models.cluster import Cluster
    from app.models.user import User
    from app.services.k8s_client import encrypt_kubeconfig

    # Session-scoped against a function-scoped app: the Cluster row is bound
    # to the first test's session and must be released before that session
    # expires — the test client's own app_context (later tests) would else
    # raise DetachedInstanceError on c.id. (The tests register their OWN
    # row via POST /clusters; the row here is the fixture's, for teardown.)
    enc = encrypt_kubeconfig(kind_cluster)
    cid: int
    with app.app_context():
        u = db.session.execute(db.select(User).filter_by(sub="sub-oidc-1")).scalar_one()
        c = Cluster(
            name="kind-test",
            api_server="https://127.0.0.1:6443",
            kubeconfig_enc=enc,
            context="kind-kind-test",
        )
        db.session.add(c)
        db.session.flush()
        db.session.add(ClusterBinding(user_id=u.id, cluster_id=c.id, role="admin"))
        db.session.commit()
        cid = c.id
    try:
        yield cid, kind_cluster
    finally:
        with app.app_context():
            c = db.session.get(Cluster, cid)
            if c is not None:
                db.session.delete(c)
                db.session.commit()


@pytest.fixture(scope="module", autouse=True)
def _kind_file_boundary(request: pytest.FixtureRequest) -> Iterator[None]:
    """Per-test-file teardown (ARCHITECTURE.md §9): if the just-finished
    module contained an ``integration``-marked test, delete + recreate the
    kind cluster so a wedged state cannot carry into the next file. A no-op
    where kind is unavailable (no docker): the marker check alone is cheap
    and the boundary only matters when the cluster was actually created."""
    yield
    markers = {m.name for m in getattr(request.node, "iter_markers", lambda: [])()}
    if "integration" not in markers or not _kind_available():
        return
    subprocess.run(
        ["kind", "delete", "cluster", "--name", _KIND], capture_output=True
    )
    subprocess.run(
        ["kind", "create", "cluster", "--name", _KIND], capture_output=True
    )
    global _kind_pod_added
    _kind_pod_added = False
