"""RBAC drift detection — per .skillgrid/artifacts/04-adr-0013-permission-management.md.
Runs every 10 min on the leader once templates exist. Stub: RQ-callable no-op."""
import logging

log = logging.getLogger(__name__)


def run() -> None:
    log.info("rbac_drift: stub no-op (base structure)")
