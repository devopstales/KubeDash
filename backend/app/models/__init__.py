"""SQLAlchemy models.

Importing this package registers every table on ``db.metadata`` — required
before ``db.create_all()`` (conftest) and Alembic autogenerate (flask db
migrate). The ``leader_lease`` import is the second line of the two-revision
OD-3 split: keep it commented out while generating revision 1, restore it for
revision 2 (see the Task 2 brief).
"""
from app.models.binding import ClusterBinding
from app.models.cluster import Cluster
from app.models.leader_lease import LeaderLease
from app.models.token import RefreshToken
from app.models.user import User

__all__ = ["ClusterBinding", "Cluster", "LeaderLease", "RefreshToken", "User"]
