"""Permission service — per .skillgrid/artifacts/04-adr-0013-permission-management.md.
bind/unbind (template apply, idempotent), template management, multi-cluster
kubeconfig generation. Lands with the permission-management change."""
from app.core.errors import NotImplementedError_


def bind(username: str, cluster: str, namespace: str, template_name: str) -> None:
    raise NotImplementedError_("permission bind not implemented in base structure")


def unbind(username: str, cluster: str, namespace: str) -> None:
    raise NotImplementedError_("permission unbind not implemented in base structure")


def generate_kubeconfig(username: str) -> str:
    raise NotImplementedError_("kubeconfig generation not implemented in base structure")
