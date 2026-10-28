"""CA-based kubeconfig for a local (non-OIDC) user — 4.1 parity.

4.1 minted a client certificate for each non-SSO user via a K8s CSR
(``KubectlConfig``), so a local user downloaded a CA-based kubeconfig and
"Authenticate Manually" printed CA ``set-cluster``/``set-credentials``
commands. This repo's local users (ADR-0021 bootstrap admin, and later
permission-management local users) otherwise only get the credential-plugin
exec (ADR-0011). This table stores the minted key + cert + cluster CA so
``GET /kubeconfig`` can render a CA-based file for a local user who has one,
mirroring 4.1's ``KubectlConfigStore`` / ``type: cert`` branch.
"""
from app.extensions import db


class KubectlConfig(db.Model):
    __tablename__ = "kubectl_config"

    id = db.Column(db.Integer, primary_key=True)
    # One row per local user. The CN is the user identity (email prefix for
    # email names, raw name otherwise) — the same subject the CSR signs, so
    # the cluster's CA trusts ``CN=<name>`` for client auth.
    name = db.Column(db.String(50), nullable=False, unique=True)
    # RSA private key + the CA-signed certificate, both base64-PEM (the 4.1
    # column shape; the download base64-decodes them into the kubeconfig).
    private_key = db.Column(db.Text)
    user_certificate = db.Column(db.Text)
    # The cluster's server CA (base64-PEM) captured at mint time, so the
    # kubeconfig is self-contained (``certificate-authority-data``) without a
    # second read of the admin kubeconfig at download time.
    k8s_server_ca = db.Column(db.Text)
    # The target cluster's API server URL (``https://host:port``), captured at
    # mint time for the kubeconfig ``server`` field.
    k8s_server_url = db.Column(db.String(255))

    def __repr__(self) -> str:  # pragma: no cover
        return f"<KubectlConfig name={self.name!r}>"
