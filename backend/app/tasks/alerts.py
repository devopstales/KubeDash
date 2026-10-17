"""Alert evaluation (leader, 1 min) — per
.skillgrid/artifacts/04-adr-0003-observability-query-only.md + §3.7
RQ task table. Stub: RQ-callable no-op that logs."""
import logging

log = logging.getLogger(__name__)


def evaluate() -> None:
    log.info("alerts: stub no-op (base structure)")
