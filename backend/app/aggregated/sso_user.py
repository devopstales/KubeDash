"""SSOUser computation — per .skillgrid/artifacts/04-adr-0012-aggregated-api.md
(ADR-0012): effective-permission RBAC walk. Stub."""
from app.core.errors import NotImplementedError_


def compute(user: str, cluster: str) -> dict[str, object]:
    raise NotImplementedError_("sso_user computation not implemented in base structure")
