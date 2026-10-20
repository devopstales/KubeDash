#!/usr/bin/env python3
"""Push code-quality / security tool results to the dev Prometheus Pushgateway.

The four scanners (ruff, mypy, trivy, jscpd) each emit a different output
format. This is a small stdlib-only pusher: the calling task (or a thin wrapper
script) reduces each tool's output to a list of {name, labels, value} gauge
samples, writes them to a JSON file, and this script pushes them to the
Pushgateway using the Prometheus text exposition format (no prometheus_client
dependency — keeps the loop light and avoids version churn).

Shape of the input file (a JSON list):
  [
    {"name": "kubedash_ruff_violations", "labels": {"job": "kubedash-lint", "rule": "E501"}, "value": 3},
    {"name": "kubedash_mypy_errors",     "labels": {"job": "kubedash-lint"}, "value": 0}
  ]

Usage:
  python scripts/prometheus-push.py --input /tmp/results.json --job kubedash-lint

Env:
  PROMETHEUS_PUSHGATEWAY_URL   e.g. http://localhost:9091  (required)

The --job is added to every sample's labels (and used as the grouping key) so
a single script can push several tools under distinct jobs. A sample that
already sets its own "job" label keeps it; otherwise --job wins.

Silent no-op (exit 0) when PROMETHEUS_PUSHGATEWAY_URL is unset or the gateway
is unreachable, so the task still works on a host without the dev stack.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request

_METRIC_RE = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")


def _safe_metric(name: str) -> str:
    """Metric names must match [a-zA-Z_:][a-zA-Z0-9_:]*; replace the rest."""
    return re.sub(r"[^a-zA-Z0-9_:]", "_", name)


def _escape_label_value(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _render(text: list[str], samples: list[dict]) -> str:
    """Render samples in Prometheus text exposition format, deduped by
    (name, frozenset(labels)). A name/label combo that repeats keeps the last
    value (later samples win), matching pushgateway's replace-on-push."""
    seen: dict[tuple, tuple[str, float, dict]] = {}
    for s in samples:
        name = _safe_metric(s["name"])
        labels = {str(k): str(v) for k, v in (s.get("labels") or {}).items()}
        key = (name, frozenset(labels.items()))
        seen[key] = (name, float(s["value"]), labels)
    for name, value, labels in seen.values():
        if labels:
            pairs = ",".join(f'{k}="{_escape_label_value(v)}"' for k, v in sorted(labels.items()))
            text.append(f"{name}{{{pairs}}} {value}")
        else:
            text.append(f"{name} {value}")
    return "\n".join(text) + "\n"


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True, help="Path to a JSON file of gauge samples")
    p.add_argument("--job", required=True, help="Default job label + pushgateway grouping key")
    p.add_argument("--gateway-url", default=None, help="Override PROMETHEUS_PUSHGATEWAY_URL")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    url = (args.gateway_url or os.environ.get("PROMETHEUS_PUSHGATEWAY_URL", "")).strip()
    if not url:
        print("prometheus-push: no PROMETHEUS_PUSHGATEWAY_URL set; skipping push", file=sys.stderr)
        return 0

    try:
        with open(args.input, encoding="utf-8") as fh:
            samples = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"prometheus-push: could not read {args.input!r}: {exc}", file=sys.stderr)
        return 0
    if not isinstance(samples, list):
        print("prometheus-push: input must be a JSON list of samples", file=sys.stderr)
        return 0

    # Stamp the default job label onto samples that don't set their own.
    for s in samples:
        s.setdefault("labels", {})
        s["labels"].setdefault("job", args.job)

    body = _render([], samples).encode("utf-8")
    # Pushgateway: PUT to /metrics/job/<job> (grouping key = job).
    path = urllib.parse.quote(f"metrics/job/{args.job}", safe="/")
    req = urllib.request.Request(f"{url.rstrip('/')}/{path}", data=body, method="PUT",
                                 headers={"Content-Type": "text/plain; version=0.0.4"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 201, 202, 204):
                raise RuntimeError(f"unexpected status {resp.status}")
    except Exception as exc:  # noqa: BLE001 - report, never fail the task
        print(f"prometheus-push: push to {url} failed: {exc}", file=sys.stderr)
        return 0

    print(f"prometheus-push: pushed {len(samples)} samples as job={args.job} -> {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
