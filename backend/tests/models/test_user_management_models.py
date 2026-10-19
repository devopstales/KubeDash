"""TICKET-01 (user-management, ADR-0013): foundation — the two new stable
error codes, the ``KUBEDASH_PLUGIN_SERVER`` setting, the un-stub
``RBACTemplate`` / ``AuditLog`` models on ``db.metadata``, and the extended
``ClusterBinding`` schema (one-way-door; the migration is TICKET-02)."""
import pytest
from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB

from app.extensions import db


def test_new_error_codes_are_frozen_at_14():
    """The error contract grows from 12 to 14: BUILTIN_TEMPLATE_PROTECTED
    (409) and NO_BINDINGS (404) join CODES with their HTTP statuses."""
    import app.core.errors as errors

    assert len(errors.CODES) == 14
    assert len({cls.error_code for cls in errors.CODES}) == 14
    assert errors.BuiltinTemplateProtectedError in errors.CODES
    assert errors.NoBindingsError in errors.CODES
    # HTTP status + envelope name per the frozen contract.
    assert errors.BuiltinTemplateProtectedError("x").code == 409
    assert (
        errors.BuiltinTemplateProtectedError("x").error_code == "BUILTIN_TEMPLATE_PROTECTED"
    )
    assert errors.NoBindingsError("x").code == 404
    assert errors.NoBindingsError("x").error_code == "NO_BINDINGS"
    assert (
        errors.BuiltinTemplateProtectedError("builtin templates are immutable").as_dict()["code"]
        == "BUILTIN_TEMPLATE_PROTECTED"
    )


def test_plugin_server_setting_defaults_to_none():
    """KUBEDASH_PLUGIN_SERVER is optional — unset until Task 5's kubeconfig
    render consumes it (500 INTERNAL_ERROR when unset at request time)."""
    from app.core.config import Settings

    s = Settings(_env_file=None)
    assert s.plugin_server is None


def test_rbac_template_is_on_db_metadata(app, db_sess):
    """Un-stubbed (ADR-0013): the table is registered so db.create_all() and
    Alembic autogenerate see it — columns per ARCHITECTURE.md §5B."""
    from app.models.rbac_template import RBACTemplate

    t = db.metadata.tables["rbac_templates"]
    cols = {c.name for c in t.columns}
    assert cols == {
        "id",
        "name",
        "description",
        "scope",
        "rules",
        "created_by",
        "created_at",
        "builtin",
    }
    name_col = t.columns["name"]
    assert name_col.unique is True
    assert not name_col.nullable
    rules_col = t.columns["rules"]
    assert isinstance(rules_col.type, JSONB)
    # ORM-side default: callable producing a fresh list (not a shared object).
    assert callable(rules_col.default.arg) and rules_col.default.arg(ctx=object()) == []
    assert t.columns["description"].default.arg == ""
    assert t.columns["builtin"].default.arg is False
    assert t.columns["created_by"].nullable is True  # pre-SSO / legacy rows
    assert not t.columns["created_at"].nullable
    assert not hasattr(RBACTemplate, "STUB")  # un-stubbed


def test_audit_log_is_on_db_metadata(app, db_sess):
    """Un-stubbed: the owning change (user-management) imports AuditLog into
    app/models/__init__.py; the live-table reconciliation itself is the
    later migration, so this test asserts the model's declared columns."""
    from app.models.audit import AuditLog

    t = db.metadata.tables["audit_log"]
    cols = {c.name for c in t.columns}
    assert cols == {
        "id",
        "action",
        "actor_sub",
        "target",
        "cluster",
        "namespace",
        "template",
        "at",
    }
    for nullable in ("cluster", "namespace", "template"):
        assert t.columns[nullable].nullable is True
    assert not t.columns["at"].nullable
    assert not hasattr(AuditLog, "STUB")  # un-stubbed


def test_cluster_binding_gains_namespace_template_created_at_and_unique(
    app, db_sess,
):
    """ADR-0002 one-way-door (model only; migration is TICKET-02): bindings
    carry the bound namespace + role template, and (user, cluster, namespace,
    template) is unique. Postgres treats NULL namespaces as distinct in the
    constraint — accepted per the brief (cluster-scoped rows)."""
    from app.models.binding import ClusterBinding

    t = db.metadata.tables["cluster_bindings"]
    cols = {c.name for c in t.columns}
    assert {"namespace", "template", "created_at"} <= cols
    assert t.columns["namespace"].nullable is True
    assert t.columns["namespace"].index is True
    assert t.columns["template"].nullable is True
    assert not t.columns["created_at"].nullable
    # role stays but becomes template-derived, default "viewer".
    assert t.columns["role"].default.arg == "viewer"
    ucs = [
        c for c in t.constraints if isinstance(c, UniqueConstraint)
        and {col.name for col in c.columns}
        == {"user_id", "cluster_id", "namespace", "template"}
    ]
    assert len(ucs) == 1
    # The existing __init__ still validates role and accepts the new kwargs.
    b = ClusterBinding(
        user_id=1, cluster_id=1, role="viewer", namespace="prod", template="developer"
    )
    assert b.namespace == "prod"
    assert b.template == "developer"
    with pytest.raises(ValueError):
        ClusterBinding(user_id=1, cluster_id=1, role="superuser")
