"""NaaS provisioning pipeline (§ 5C) — per
.skillgrid/artifacts/04-adr-0015-namespace-as-a-service.md.
Idempotent namespace provisioning via the role-template service +
optional TTL'd grants. Lands with the NaaS change."""
from app.core.errors import NotImplementedError_


def provision(cluster: str, namespace: str, template_name: str, **kw: object) -> None:
    raise NotImplementedError_("namespace provisioning not implemented in base structure")
