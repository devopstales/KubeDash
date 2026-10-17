"""Task 2 — core model round-trips and validation (Postgres-backed via conftest)."""
import pytest


def test_user_and_binding_roundtrip(app):
    from app.extensions import db
    from app.models.binding import ClusterBinding
    from app.models.cluster import Cluster
    from app.models.user import User

    with app.app_context():
        u = User(sub="sub-1", email="jdoe@example.com", display_name="J Doe", role="user")
        c = Cluster(
            name="prod", api_server="https://1.2.3.4:6443", kubeconfig_enc=b"enc", context="prod"
        )
        db.session.add_all([u, c])
        db.session.flush()
        b = ClusterBinding(user_id=u.id, cluster_id=c.id, role="viewer")
        db.session.add(b)
        db.session.commit()
        assert ClusterBinding.query.filter_by(user_id=u.id).first().role == "viewer"


def test_binding_rejects_unknown_role(app):
    from app.extensions import db
    from app.models.binding import ClusterBinding
    from app.models.user import User

    with app.app_context():
        u = User(sub="sub-2", email="x@example.com", display_name="X")
        db.session.add(u)
        db.session.flush()
        with pytest.raises(ValueError):
            db.session.add(ClusterBinding(user_id=u.id, cluster_id=1, role="superuser"))


def test_refresh_token_stores_hash_not_raw(app):
    from app.extensions import db
    from app.models.token import RefreshToken
    from app.models.user import User

    with app.app_context():
        u = User(sub="sub-3", email="t@example.com", display_name="T")
        db.session.add(u)
        db.session.flush()
        tok = RefreshToken(user_id=u.id, token_hash=RefreshToken.hash_token("raw-token-abc"))
        db.session.add(tok)
        db.session.commit()
        assert tok.token_hash != "raw-token-abc"
        assert RefreshToken.hash_token("raw-token-abc") == RefreshToken.hash_token("raw-token-abc")
