"""SSOGroup computation — per .skillgrid/artifacts/04-adr-0012-aggregated-api.md
(ADR-0012): group-scoped RBAC walk. Stub."""
from app.core.errors import NotImplementedError_


def compute(group: str, cluster: str) -> dict[str, object]:
    raise NotImplementedError_("sso_group computation not implemented in base structure")
