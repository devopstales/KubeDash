"""SQLAlchemy models.

Importing this package registers every table on ``db.metadata`` — required
before ``db.create_all()`` (conftest) and Alembic autogenerate (flask db
migrate). The ``leader_lease`` import is the second line of the two-revision
OD-3 split: keep it commented out while generating revision 1, restore it for
revision 2 (see the Task 2 brief).

Stub models stay UNIMPORTED here on purpose until their owning change adds
both the import and the migration: ``namespace_request``, ``access_request``,
``scim_map`` (R9). ``rbac_template`` and ``audit`` were un-stubbed by the
user-management change (TICKET-01): imported here, their tables are on
``db.metadata`` now, and the later TICKET-02 migration creates/reconciles
the live tables.
"""
from app.models.audit import AuditLog
from app.models.binding import ClusterBinding
from app.models.cluster import Cluster
from app.models.leader_lease import LeaderLease
from app.models.rbac_template import RBACTemplate
from app.models.token import RefreshToken
from app.models.user import User

__all__ = [
    "AuditLog",
    "ClusterBinding",
    "Cluster",
    "LeaderLease",
    "RBACTemplate",
    "RefreshToken",
    "User",
]
