"""CA-based kubeconfig minting for local users — 4.1 parity.

4.1 minted a client certificate for each non-SSO user by submitting a
``CertificateSigningRequest`` the cluster CA signs (``k8sCreateUser``), stored
the key + cert in a ``KubectlConfig`` row, and served a CA-based kubeconfig on
download (``type: cert``). This repo's local users (ADR-0021 bootstrap admin,
later permission-management local users) otherwise only get the
credential-plugin exec (ADR-0011). This service reproduces the 4.1 path:
create + approve a CSR against the cluster's admin CA, then persist the
resulting key/cert + cluster CA + API server URL on a ``KubectlConfig`` row
so ``GET /kubeconfig`` can render a self-contained CA file for that user.

Pure Python (no Flask imports): the ``db_session`` is a SQLAlchemy session,
the ``settings`` is the app Settings, and the k8s client is built from the
admin kubeconfig (ADR-0021) via ``k8s_client.build_admin_client``.
"""
import base64
import time
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.extensions import db
from app.models.kubectl_config import KubectlConfig
from app.services import k8s_client

#: The signer a kind/prod cluster CA actually has for client certs. (4.1 used a
#: custom signer ``kubernetes.io/kubedash-apiserver-client``; a standard cluster
#: only guarantees the built-in ``kubernetes.io/kube-apiserver-client``, which
#: signs with the cluster CA and is what a kubeconfig's server CA will verify.)
_CLIENT_SIGNER = "kubernetes.io/kube-apiserver-client"
_CSR_USAGES = ["digital signature", "key encipherment", "client auth"]
_CSR_TTL = 315360000  # 10 years, the 4.1 value
_CSR_NAME_PREFIX = "kubedash-user-"
_CSR_NAME_MAX = 253  # DNS1123 subdomain limit (the CSR is a cluster-scoped name)


def _cn_for(username: str) -> str:
    """The CSR subject CN. 4.1: an email name signs as its local part
    (``a@b`` -> ``a``); anything else signs as-is."""
    return username.split("@")[0] if "@" in username else username


def _csr_name(username: str) -> str:
    """A unique, DNS-safe cluster-scoped CSR name for this user."""
    cn = _cn_for(username)
    base = f"{_CSR_NAME_PREFIX}{cn}"
    # Keep under the DNS1123 limit; a hash suffix makes re-mints (after the CSR
    # is deleted) unique without colliding with a still-pending CSR of the same
    # user (the delete at the end of mint removes the prior one).
    if len(base) <= _CSR_NAME_MAX:
        return base
    tail = base[: _CSR_NAME_MAX - 9]
    return f"{tail}-{int(time.time()) % 100_000_000:08d}"[:_CSR_NAME_MAX]


def _csr_api(client: Any):
    """The CertificatesV1 client + the kubernetes model module (the CSR is
    submitted as generated model objects, not raw dicts)."""
    from kubernetes import client as k8s_client

    return k8s_client.CertificatesV1Api(client._api_client), k8s_client


def _approve_csr(client: Any, csr_name: str) -> None:
    """Approve a CSR via ``kubectl certificate approve``.

    The kubernetes client's generated CSR status calls are unreliable here:
    ``replace_certificate_signing_request`` silently drops a client-added
    ``Approved`` condition, and the ``/approval`` subresource PUT the client
    issues 400s on this cluster. ``kubectl certificate approve`` is the
    proven path (it signs the CSR and the controller issues the cert).

    Auth follows the admin-source seam (ADR-0021): when the admin client was
    built from a kubeconfig FILE, approve with that same file (``--kubeconfig``);
    in-cluster, approve with the pod's projected SA token. ``client`` is the
    admin ``K8sClient`` (the CSR was created against it); the approval must use
    the SAME identity.
    """
    import os
    import subprocess

    src = client.source
    if src == "kubeconfig-file":
        from app.core.config import get_settings

        path = get_settings().admin_kubeconfig
        if not path or not os.path.isfile(path):
            raise RuntimeError(f"admin kubeconfig not found for CSR approval: {path!r}")
        cmd = ["kubectl", "--kubeconfig", path, "certificate", "approve", csr_name]
    else:
        # local-kubeconfig / in-cluster: the pod's own context.
        cmd = ["kubectl", "certificate", "approve", csr_name]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError as e:
        raise RuntimeError("kubectl not found; cannot approve the user CSR") from e
    if proc.returncode != 0:
        raise RuntimeError(
            f"kubectl certificate approve {csr_name} failed "
            f"({proc.returncode}): {(proc.stderr or proc.stdout).strip()}"
        )



def mint(
    *,
    username: str,
    db_session: Any,
    settings: Any,
) -> KubectlConfig:
    """Create + approve a client-cert CSR and persist a ``KubectlConfig``.

    ``username`` is the local user's identity (email or name). The CN is the
    email's local part (4.1 rule). The CSR is signed by the cluster's admin CA
    (``build_admin_client``), so the returned certificate is verified by the
    same CA that signs the kubeconfig's ``certificate-authority-data``.

    Idempotent per user: a fresh CSR is minted (the prior CSR object is deleted
    at the end of the previous mint; the stored key/cert are overwritten).
    """
    client = k8s_client.build_admin_client(settings)
    cn = _cn_for(username)

    # 1. Key + CSR (4.1 k8sCreateUser, via ``cryptography`` — this repo has no
    #    pyOpenSSL; the CSR carries only the CN, the 4.1 subject).
    pkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = pkey.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    req = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(pkey, hashes.SHA256())
    )
    csr_pem = req.public_bytes(serialization.Encoding.PEM)

    # 2. Create the CSR (idempotent: delete a leftover with the same name).
    csr_name = _csr_name(username)
    certs, k8s_client_lib = _csr_api(client)
    try:
        certs.create_certificate_signing_request(
            k8s_client_lib.models.V1CertificateSigningRequest(
                metadata=k8s_client_lib.models.V1ObjectMeta(name=csr_name),
                spec=k8s_client_lib.models.V1CertificateSigningRequestSpec(
                    request=base64.b64encode(csr_pem).decode("ascii"),
                    signer_name=_CLIENT_SIGNER,
                    usages=_CSR_USAGES,
                    expiration_seconds=_CSR_TTL,
                ),
            )
        )
    except Exception as e:  # noqa: BLE001 - a 409 (already exists) is retryable
        if "409" not in str(e):
            raise
        certs.delete_certificate_signing_request(csr_name)
        certs.create_certificate_signing_request(
            k8s_client_lib.models.V1CertificateSigningRequest(
                metadata=k8s_client_lib.models.V1ObjectMeta(name=csr_name),
                spec=k8s_client_lib.models.V1CertificateSigningRequestSpec(
                    request=base64.b64encode(csr_pem).decode("ascii"),
                    signer_name=_CLIENT_SIGNER,
                    usages=_CSR_USAGES,
                    expiration_seconds=_CSR_TTL,
                ),
            )
        )

    # 3. Approve via the CSR's /approval subresource (the raw body
    #    ``kubectl certificate approve`` PUTs). The kubernetes 37 generated
    #    ``replace_certificate_signing_request`` silently drops a freshly-added
    #    ``Approved`` condition (only server-managed conditions survive a client
    #    replace), so a generated replace leaves the CSR pending forever. A raw
    #    PUT of ``status.approval = {type: Approved, status: True}`` is what the
    #    API server accepts and what triggers the controller to sign.
    _approve_csr(client, csr_name)

    # 4. Poll for the issued certificate.
    cert_b64 = None
    for _ in range(20):
        csr = certs.read_certificate_signing_request(csr_name)
        status = getattr(csr, "status", None)
        cert_b64 = getattr(status, "certificate", None) if status else None
        if cert_b64:
            break
        time.sleep(0.5)
    if not cert_b64:
        # Clean up the CSR so a re-mint isn't blocked by a stale object.
        try:
            certs.delete_certificate_signing_request(csr_name)
        except Exception:
            pass
        raise RuntimeError(f"CSR {csr_name} was not issued by the cluster CA")

    # 5. Capture the cluster CA + API server URL from the admin client config.
    cfg = client._config
    ssl_ca = getattr(cfg, "ssl_ca_cert", None)
    server_ca_b64 = ""
    if isinstance(ssl_ca, str) and ssl_ca:
        try:
            with open(ssl_ca, "rb") as fh:
                server_ca_b64 = base64.b64encode(fh.read()).decode("ascii")
        except OSError:
            server_ca_b64 = ""
    server_url = getattr(cfg, "host", "") or ""

    # 6. Delete the CSR (4.1 deletes it after reading the cert).
    try:
        certs.delete_certificate_signing_request(csr_name)
    except Exception:
        pass

    # 7. Persist (upsert on the unique name).
    row = (
        db_session.query(KubectlConfig)
        .filter_by(name=cn)
        .with_for_update()
        .one_or_none()
    )
    if row is None:
        row = KubectlConfig(name=cn)
        db_session.add(row)
    row.private_key = base64.b64encode(private_key_pem).decode("ascii")
    row.user_certificate = cert_b64
    row.k8s_server_ca = server_ca_b64
    row.k8s_server_url = server_url
    db_session.commit()
    db_session.refresh(row)
    return row


def get_by_cn(db_session: Any, cn: str) -> KubectlConfig | None:
    """The stored CA config for a local user's CN, or ``None``."""
    return (
        db_session.query(KubectlConfig).filter_by(name=cn).one_or_none()
    )
