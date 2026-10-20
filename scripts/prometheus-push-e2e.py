#!/usr/bin/env python3
"""Push a Playwright JSON test report to the dev Prometheus Pushgateway.

The pytest plugin (pytest-prometheus-pushgateway) can only hook the pytest
runner, so the TypeScript e2e suite (test-smoke / test-e2e) needs a separate
pusher. This reads Playwright's ``--reporter=json`` output and pushes the same
shape the pytest plugin produces: one gauge per test (0/1) under a job grouping
key, plus run-level total/duration gauges. Prometheus scrapes the gateway and
retains the last push, so the last e2e result stays queryable after the run.

Usage:
  python scripts/prometheus-push-e2e.py --report playwright-report.json --job kubedash-smoke

Env (read by prometheus_client.Pushgateway):
  PROMETHEUS_PUSHGATEWAY_URL    e.g. http://localhost:9091   (required)

Silent no-op (exit 0) when PROMETHEUS_PUSHGATEWAY_URL is unset or the gateway
is unreachable, so the e2e loop still works on a host without the dev stack.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

METRIC_PREFIX = "kubedash_test_"


def _safe_name(name: str) -> str:
    """Prometheus metric names must match [a-zA-Z_:][a-zA-Z0-9_:]*."""
    return "".join(c if c.isalnum() or c in "_:" else "_" for c in name)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", required=True, help="Path to the Playwright JSON report")
    p.add_argument("--job", required=True, help="Pushgateway grouping key / job label (e.g. kubedash-smoke)")
    p.add_argument("--gateway-url", default=None, help="Override PROMETHEUS_PUSHGATEWAY_URL")
    return p.parse_args()


def _load_stats(report: dict[str, Any]) -> dict[str, Any]:
    stats = report.get("stats", {})
    return {
        "expected": int(stats.get("expected", 0)),
        "unexpected": int(stats.get("unexpected", 0)),
        "skipped": int(stats.get("skipped", 0)),
        "duration_ms": float(stats.get("duration", 0.0)),
    }


def _iter_tests(report: dict[str, Any]):
    """Yield (file, title, status) for every test in the JSON report.

    Playwright nests suites; walk recursively. A test result's outcome is
    "expected" (passed), "unexpected" (failed), or "flaky". Skipped tests carry
    a "skipped" status. We surface passed / failed / skipped only.
    """
    def walk(suites: list[dict[str, Any]], file: str) -> None:
        for suite in suites:
            for spec in suite.get("specs", []):
                title = spec.get("title", "unknown")
                status = "skipped"
                for res in spec.get("tests", []):
                    for r in res.get("results", []):
                        if r.get("status") in ("passed", "failed", "timedOut", "skipped"):
                            status = "passed" if r["status"] == "passed" else (
                                "skipped" if r["status"] == "skipped" else "failed"
                            )
                            break
                yield file, title, status
            walk(suite.get("suites", []), file)

    for top in report.get("suites", []):
        yield from walk([top], "")


def main() -> int:
    args = _parse_args()
    url = args.gateway_url or os.environ.get("PROMETHEUS_PUSHGATEWAY_URL", "").strip()
    if not url:
        print("prometheus-push-e2e: no PROMETHEUS_PUSHGATEWAY_URL set; skipping push", file=sys.stderr)
        return 0

    try:
        from prometheus_client import CollectorRegistry, Gauge, pushadd_to_gateway
    except ImportError:
        print("prometheus-push-e2e: prometheus-client not installed; skipping push", file=sys.stderr)
        return 0

    try:
        with open(args.report, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"prometheus-push-e2e: could not read report {args.report!r}: {exc}", file=sys.stderr)
        return 0

    stats = _load_stats(report)
    registry = CollectorRegistry()

    total = Gauge(
        f"{METRIC_PREFIX}total", "Total e2e tests in the run", ["job"], registry=registry
    )
    passed = Gauge(
        f"{METRIC_PREFIX}passed", "E2E tests that passed", ["job"], registry=registry
    )
    failed = Gauge(
        f"{METRIC_PREFIX}failed", "E2E tests that failed", ["job"], registry=registry
    )
    skipped = Gauge(
        f"{METRIC_PREFIX}skipped", "E2E tests that were skipped", ["job"], registry=registry
    )
    duration = Gauge(
        f"{METRIC_PREFIX}duration_seconds", "E2E run duration (seconds)", ["job"], registry=registry
    )
    per_test = Gauge(
        f"{METRIC_PREFIX}result",
        "E2E per-test outcome (1=passed, 0=failed)",
        ["job", "test"],
        registry=registry,
    )

    passed_n = stats["expected"]
    failed_n = stats["unexpected"]
    skipped_n = stats["skipped"]

    total.labels(job=args.job).set(passed_n + failed_n + skipped_n)
    passed.labels(job=args.job).set(passed_n)
    failed.labels(job=args.job).set(failed_n)
    skipped.labels(job=args.job).set(skipped_n)
    duration.labels(job=args.job).set(round(stats["duration_ms"] / 1000.0, 3))

    for _file, title, status in _iter_tests(report):
        label = f"{args.job}::{_safe_name(title)}"
        per_test.labels(job=args.job, test=label).set(1 if status == "passed" else 0)

    try:
        pushadd_to_gateway(
            url.rstrip("/"), job=args.job, registry=registry,
            grouping_key={"job": args.job},
        )
    except Exception as exc:  # noqa: BLE001 - report, never fail the e2e run
        print(f"prometheus-push-e2e: push to {url} failed: {exc}", file=sys.stderr)
        return 0

    print(
        f"prometheus-push-e2e: pushed {args.job} "
        f"({passed_n} passed, {failed_n} failed, {skipped_n} skipped, "
        f"{stats['duration_ms'] / 1000.0:.1f}s) -> {url}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
