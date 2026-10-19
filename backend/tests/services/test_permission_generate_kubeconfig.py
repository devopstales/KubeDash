"""ADR-0011 (TICKET-05, tracer 2) — ``permission.generate_kubeconfig``.

Service tier: the shared Testcontainers app (``app``/``db_sess`` — Docker
required, like the rest of the services tier; CI is the backstop where the
runtime is absent). The CA-extraction corner cases (data vs file-path vs
absent) are pinned at the ``_ca_from_kubeconfig`` seam — the pure unit tier
for the shape itself is ``tests/services/test_kubeconfig_render.py``.

SATISFIES: user-downloads-a-multi-cluster-kubeconfig (service half —
grouping, CA extraction, per-binding contexts);
user-with-no-bindings-gets-a-404 (service half — NoBindingsError).
"""
import base64
import secrets
from types import SimpleNamespace

import pytest
import yaml

import app.services.kubeconfig_render as _kr
import app.services.permission as _pm
from app.core.errors import InternalError, NoBindingsError
from app.models.binding import ClusterBinding
from app.models.cluster import Cluster
from app.models.user import User
from app.services import permission
from app.services.k8s_client import encrypt_kubeconfig

CA_PEM = b"FAKE-CA-PEM"
CA2_PEM = b"FAKE-CA2-PEM"
SERVER = "https://kubedash.example.com"

#: The registry kubeconfig shape: CA inline (certificate-authority-data).
_KC_DATA = (
    "apiVersion: v1\nkind: Config\nclusters:\n"
    f"- name: c\n  cluster:\n    server: https://api.prod.example.com:6443\n"
    f"    certificate-authority-data: {base64.b64encode(CA_PEM).decode()}\n"
    "contexts:\n- name: c\n  context:\n    cluster: c\n    user: u\n"
    "current-context: c\nusers:\n- name: u\n  user: {}\n"
)


def _settings(plugin_server: str | None = SERVER) -> SimpleNamespace:
    return SimpleNamespace(plugin_server=plugin_server)


def _seed(db, suffix: str) -> SimpleNamespace:
    """Two clusters (distinct CAs/servers) + one user."""
    u = User(sub=f"kc-{suffix}", status="active")
    db.session.add(u)
    c1 = Cluster(
        name=f"prod-{suffix}",
        api_server="https://api.prod.example.com:6443",
        kubeconfig_enc=encrypt_kubeconfig(_KC_DATA.encode()),
        context="c",
    )
    db.session.add(c1)
    db.session.commit()
    return SimpleNamespace(u_id=u.id, c1_id=c1.id)


def _kc_file_form(path: str) -> str:
    """The registry kubeconfig shape: CA as a file PATH (certificate-authority)."""
    return (
        "apiVersion: v1\nkind: Config\nclusters:\n"
        "- name: c\n  cluster:\n    server: https://api.staging.example.com:6443\n"
        f"    certificate-authority: {path}\n"
        "contexts:\n- name: c\n  context:\n    cluster: c\n    user: u\n"
        "current-context: c\nusers:\n- name: u\n  user: {}\n"
    )


def _kc_no_ca() -> str:
    """The registry kubeconfig shape: NO CA at all (insecure/other-auth)."""
    return (
        "apiVersion: v1\nkind: Config\nclusters:\n"
        "- name: c\n  cluster:\n    server: https://api.noca.example.com:6443\n"
        "contexts:\n- name: c\n  context:\n    cluster: c\n    user: u\n"
        "current-context: c\nusers:\n- name: u\n  user: {}\n"
    )


@pytest.fixture()
def _unique() -> str:
    return secrets.token_hex(4)


# ---------------------------------------------------------------------------
# CA extraction seam — the three corner cases (data / file-path / absent).
# ---------------------------------------------------------------------------


def test_ca_from_data_field() -> None:
    """CA case 1: ``certificate-authority-data`` → passed through as-is
    (already base64)."""
    enc = encrypt_kubeconfig(_KC_DATA.encode())
    server, ca = permission._ca_from_kubeconfig(enc, "https://fallback.example.com:6443")
    assert server == "https://api.prod.example.com:6443"
    assert ca == base64.b64encode(CA_PEM).decode()


def test_ca_from_file_path(tmp_path) -> None:
    """CA case 2: ``certificate-authority`` is a file PATH — read the file's
    bytes and base64 them."""
    ca_file = tmp_path / "ca.crt"
    ca_file.write_bytes(CA2_PEM)
    enc = encrypt_kubeconfig(_kc_file_form(str(ca_file)).encode())
    server, ca = permission._ca_from_kubeconfig(enc, "https://fallback.example.com:6443")
    assert server == "https://api.staging.example.com:6443"
    assert ca == base64.b64encode(CA2_PEM).decode()


def test_ca_absent_is_empty_string() -> None:
    """CA case 3: neither field → ``""`` (the renderer omits the key)."""
    enc = encrypt_kubeconfig(_kc_no_ca().encode())
    server, ca = permission._ca_from_kubeconfig(enc, "https://fallback.example.com:6443")
    assert server == "https://api.noca.example.com:6443"
    assert ca == ""


def test_ca_missing_server_uses_caller_fallback() -> None:
    """The registry kubeconfig's cluster entry has no ``server`` → the caller's
    ``api_server_fallback`` (the ``Cluster.api_server`` column) is used — the
    value is passed IN (no session lookup inside the pure function)."""
    kc_no_server = (
        "apiVersion: v1\nkind: Config\nclusters:\n"
        "- name: c\n  cluster:\n"
        "    certificate-authority-data: Zm9vCg==\n"
        "contexts:\n- name: c\n  context:\n    cluster: c\n    user: u\n"
        "current-context: c\nusers:\n- name: u\n  user: {}\n"
    )
    enc = encrypt_kubeconfig(kc_no_server.encode())
    server, ca = permission._ca_from_kubeconfig(enc, "https://column.example.com:6443")
    assert server == "https://column.example.com:6443"
    assert ca == base64.b64encode(b"foo\n").decode()


def test_ca_non_mapping_doc_raises_value_error() -> None:
    """A registry kubeconfig that parses to a non-mapping (corrupt row) →
    explicit ``ValueError`` (→ 500), NOT a stripped assert / AttributeError."""
    enc = encrypt_kubeconfig(b"- just\n- a\n- list\n")
    with pytest.raises(ValueError) as exc:
        permission._ca_from_kubeconfig(enc, "https://fallback.example.com:6443")
    assert "not a YAML mapping" in str(exc.value)


# ---------------------------------------------------------------------------
# generate_kubeconfig
# ---------------------------------------------------------------------------


def test_no_bindings_raises_no_bindings_error(app, db_sess, _unique: str) -> None:
    """SATISFIES user-with-no-bindings-gets-a-404 (service half)."""
    p = _seed(db_sess, _unique)
    with pytest.raises(NoBindingsError):
        permission.generate_kubeconfig(
            user_sub=f"kc-{_unique}", db_session=db_sess.session, settings=_settings(),
        )
    assert p.u_id is not None  # the user exists — it is simply unbound


def test_plugin_server_unset_is_internal_error(app, db_sess, _unique: str) -> None:
    """A bound user + ``KUBEDASH_PLUGIN_SERVER`` unset → InternalError (500),
    never an empty ``--server=``."""
    p = _seed(db_sess, _unique)
    db_sess.session.add(
        ClusterBinding(user_id=p.u_id, cluster_id=p.c1_id, role="viewer",
                       namespace="ns-a", template="viewer")
    )
    db_sess.session.commit()
    with pytest.raises(InternalError) as exc:
        permission.generate_kubeconfig(
            user_sub=f"kc-{_unique}", db_session=db_sess.session,
            settings=_settings(plugin_server=None),
        )
    assert "KUBEDASH_PLUGIN_SERVER" in exc.value.message


def test_multi_cluster_multi_namespace_kubeconfig(app, db_sess, _unique: str) -> None:
    """SATISFIES user-downloads-a-multi-cluster-kubeconfig (service half):
    two clusters + a second binding on the first cluster (two namespaces) →
    2 cluster entries, 3 contexts (one PER BINDING), one shared exec user."""
    p = _seed(db_sess, _unique)
    kc2 = _KC_DATA.replace("api.prod.example.com", "api.staging.example.com").replace(
        base64.b64encode(CA_PEM).decode(), base64.b64encode(CA2_PEM).decode()
    )
    c2 = Cluster(
        name=f"staging-{_unique}",
        api_server="https://api.staging.example.com:6443",
        kubeconfig_enc=encrypt_kubeconfig(kc2.encode()),
        context="c",
    )
    db_sess.session.add(c2)
    db_sess.session.flush()  # ids are read into the bindings below
    db_sess.session.add(
        ClusterBinding(user_id=p.u_id, cluster_id=p.c1_id, role="viewer",
                       namespace="ns-a", template="viewer")
    )
    db_sess.session.add(
        ClusterBinding(user_id=p.u_id, cluster_id=p.c1_id, role="viewer",
                       namespace="ns-b", template="viewer")
    )
    db_sess.session.add(
        ClusterBinding(user_id=p.u_id, cluster_id=c2.id, role="viewer",
                       namespace="ns-c", template="viewer")
    )
    db_sess.session.commit()

    yml = permission.generate_kubeconfig(
        user_sub=f"kc-{_unique}", db_session=db_sess.session, settings=_settings(),
    )
    doc = yaml.safe_load(yml)
    assert [c["name"] for c in doc["clusters"]] == [
        f"kubedash-prod-{_unique}", f"kubedash-staging-{_unique}",
    ]
    assert doc["clusters"][0]["cluster"]["certificate-authority-data"] == base64.b64encode(CA_PEM).decode()
    assert doc["clusters"][1]["cluster"]["certificate-authority-data"] == base64.b64encode(CA2_PEM).decode()
    # One context PER BINDING — same cluster, two namespaces → two contexts.
    assert len(doc["contexts"]) == 3
    assert [c["context"]["namespace"] for c in doc["contexts"]] == ["ns-a", "ns-b", "ns-c"]
    assert doc["contexts"][0]["context"]["cluster"] == f"kubedash-prod-{_unique}"
    assert doc["contexts"][1]["context"]["cluster"] == f"kubedash-prod-{_unique}"
    assert doc["contexts"][2]["context"]["cluster"] == f"kubedash-staging-{_unique}"
    assert doc["current-context"] == f"kubedash-prod-{_unique}"
    # ADR-0011: the one shared exec user, no token.
    assert len(doc["users"]) == 1
    user = doc["users"][0]["user"]
    assert set(user) == {"exec"}
    assert user["exec"]["args"] == ["kubedash", "get-token", f"--server={SERVER}"]


def test_cluster_scoped_binding_omits_namespace(app, db_sess, _unique: str) -> None:
    """A cluster-scoped binding (namespace=None) → its context has NO
    ``namespace`` key (the renderer omits it; the service passes '')."""
    p = _seed(db_sess, _unique)
    db_sess.session.add(
        ClusterBinding(user_id=p.u_id, cluster_id=p.c1_id, role="viewer",
                       namespace=None, template="viewer")
    )
    db_sess.session.commit()
    yml = permission.generate_kubeconfig(
        user_sub=f"kc-{_unique}", db_session=db_sess.session, settings=_settings(),
    )
    doc = yaml.safe_load(yml)
    ctx = doc["contexts"][0]["context"]
    assert "namespace" not in ctx
    assert ctx == {"cluster": f"kubedash-prod-{_unique}", "user": "kubedash"}


def test_file_form_ca_is_embedded(app, db_sess, _unique: str, tmp_path) -> None:
    """End-to-end CA case 2: a registry kubeconfig whose CA is a file PATH is
    inlined as base64 ``certificate-authority-data`` in the downloaded YAML."""
    p = _seed(db_sess, _unique)
    ca_file = tmp_path / "ca.crt"
    ca_file.write_bytes(CA2_PEM)
    c2 = Cluster(
        name=f"fileca-{_unique}",
        api_server="https://api.staging.example.com:6443",
        kubeconfig_enc=encrypt_kubeconfig(_kc_file_form(str(ca_file)).encode()),
        context="c",
    )
    db_sess.session.add(c2)
    db_sess.session.flush()  # id is read into the binding below
    db_sess.session.add(
        ClusterBinding(user_id=p.u_id, cluster_id=c2.id, role="viewer",
                       namespace="ns", template="viewer")
    )
    db_sess.session.commit()
    yml = permission.generate_kubeconfig(
        user_sub=f"kc-{_unique}", db_session=db_sess.session, settings=_settings(),
    )
    doc = yaml.safe_load(yml)
    assert doc["clusters"][0]["cluster"]["certificate-authority-data"] == base64.b64encode(CA2_PEM).decode()


def test_no_ca_is_omitted(app, db_sess, _unique: str) -> None:
    """End-to-end CA case 3: a registry kubeconfig with no CA → the
    ``certificate-authority-data`` key is ABSENT from the downloaded YAML."""
    p = _seed(db_sess, _unique)
    c2 = Cluster(
        name=f"noca-{_unique}",
        api_server="https://api.noca.example.com:6443",
        kubeconfig_enc=encrypt_kubeconfig(_kc_no_ca().encode()),
        context="c",
    )
    db_sess.session.add(c2)
    db_sess.session.flush()  # id is read into the binding below
    db_sess.session.add(
        ClusterBinding(user_id=p.u_id, cluster_id=c2.id, role="viewer",
                       namespace="ns", template="viewer")
    )
    db_sess.session.commit()
    yml = permission.generate_kubeconfig(
        user_sub=f"kc-{_unique}", db_session=db_sess.session, settings=_settings(),
    )
    doc = yaml.safe_load(yml)
    assert "certificate-authority-data" not in doc["clusters"][0]["cluster"]


# --- service purity (AST-based, per the Task 5 review fix): walk EVERY import
# statement in BOTH modules — module-level AND function-local — and fail on
# any `flask*` or `app.extensions` import. The name-string heuristic
# (vars(module) scan) cannot see a function-local `from app.extensions import
# db` (app.extensions imports Flask transitively), which is exactly the
# defect the reviewer found in _ca_from_kubeconfig; the AST walk catches it.
# Module-level = checked at import time, so a regression fails the suite
# before any test body runs. ---
import ast

for _mod in (_kr, _pm):
    _tree = ast.parse(open(_mod.__file__).read())
    _bad: list[str] = []
    for _node in ast.walk(_tree):
        if isinstance(_node, ast.Import):
            _bad.extend(
                a.name for a in _node.names
                if a.name == "flask" or a.name.startswith("flask.")
                or a.name.startswith("flask_") or a.name.startswith("app.extensions")
            )
        elif isinstance(_node, ast.ImportFrom) and _node.module:
            _m = _node.module
            if (_m == "flask" or _m.startswith("flask.") or _m.startswith("flask_")
                    or _m == "app.extensions" or _m.startswith("app.extensions.")):
                _bad.append(_m)
    assert not _bad, (_mod.__name__, _bad)
