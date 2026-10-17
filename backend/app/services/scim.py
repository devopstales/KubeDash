"""SCIM 2.0 resource CRUD + filtering (§ 5F) — per
.skillgrid/artifacts/04-adr-0018-scim-2-0-gateway.md.
IdP/HR push of users/groups, identity decoupled from bindings
(scim_mappings table). Lands with the SCIM change."""
from app.core.errors import NotImplementedError_


def upsert(external_id: str, kind: str, attributes: dict[str, object]) -> None:
    raise NotImplementedError_("scim upsert not implemented in base structure")
