"""JIT login provisioning task engine (§ 5E) — per
.skillgrid/artifacts/04-adr-0017-jit-login-provisioning.md.
Helm-declared builtin pipeline runs on login / elevation / NaaS triggers.
Lands with the JIT provisioning change."""
from app.core.errors import NotImplementedError_


def run_pipeline(trigger: str, **kw: object) -> None:
    raise NotImplementedError_("provisioning pipeline not implemented in base structure")
