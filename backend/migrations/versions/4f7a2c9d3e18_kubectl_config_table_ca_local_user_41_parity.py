"""kubectl_config table — CA-based kubeconfig for local users (4.1 parity).

Revision ID: 4f7a2c9d3e18
Revises: 2eb286befb21
Create Date: 2026-10-27 16:00:00.000000

A local (non-OIDC) user can download a CA-based kubeconfig instead of the
credential-plugin exec (ADR-0011). ``KubectlConfig.mint()`` creates a K8s CSR
signed by the cluster CA (signer ``kubernetes.io/kube-apiserver-client``),
then stores the private key + certificate + cluster CA + API server URL here
so ``GET /kubeconfig`` renders a self-contained CA file for that user —
mirroring 4.1's ``KubectlConfigStore`` / ``type: cert`` branch.

One-way-door (ADR-0002): the ``name`` (CN) is the user identity, unique per
row.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "4f7a2c9d3e18"
down_revision = "2eb286befb21"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("kubectl_config"):
        op.create_table(
            "kubectl_config",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=50), nullable=False),
            sa.Column("private_key", sa.Text(), nullable=True),
            sa.Column("user_certificate", sa.Text(), nullable=True),
            sa.Column("k8s_server_ca", sa.Text(), nullable=True),
            sa.Column("k8s_server_url", sa.String(length=255), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("kubectl_config"):
        op.drop_table("kubectl_config")
