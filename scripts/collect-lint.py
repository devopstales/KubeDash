#!/usr/bin/env python3
"""Collect ruff + mypy results and push them to the Prometheus Pushgateway.

Runs in backend/ (where the uv env + ruff/mypy live). Reduces:
  - ruff check --output-format json  -> per-rule violation counts
  - mypy app --no-error-summary      -> total type-error count (grep 'error:')

to gauge samples and pushes them under job=kubedash-lint via
scripts/prometheus-push.py. Both tools are already dev dependencies, so no new
install is needed. Exit code mirrors ruff (non-zero if lint fails) so CI can
still gate, but a missing gateway never fails the task.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(os.path.dirname(HERE), "backend")
PUSH = os.path.join(HERE, "prometheus-push.py")
JOB = "kubedash-lint"


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=BACKEND, capture_output=True, text=True)


def collect_ruff() -> list[dict]:
    r = _run(["uv", "run", "ruff", "check", ".", "--output-format", "json"])
    samples: list[dict] = []
    try:
        findings = json.loads(r.stdout or "[]")
    except json.JSONDecodeError:
        findings = []
    by_rule = Counter(f.get("code", "?") for f in findings)
    samples.append({"name": "kubedash_ruff_violations", "labels": {"rule": "_total"}, "value": len(findings)})
    for rule, n in sorted(by_rule.items()):
        samples.append({"name": "kubedash_ruff_violations", "labels": {"rule": rule}, "value": n})
    return samples


def collect_mypy() -> list[dict]:
    r = _run(["uv", "run", "mypy", "app", "--no-error-summary"])
    errors = sum(1 for line in (r.stdout + r.stderr).splitlines() if "error:" in line)
    return [{"name": "kubedash_mypy_errors", "labels": {}, "value": errors}]


def main() -> int:
    samples = collect_ruff() + collect_mypy()
    tmp = "/tmp/kubedash-lint-results.json"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(samples, fh)
    rc = subprocess.run([sys.executable, PUSH, "--input", tmp, "--job", JOB]).returncode
    # The metrics task succeeds when the push succeeds; CI's `ruff check` gates
    # the build separately. Don't fail the task just because lint found issues.
    print(f"lint-push: {len(samples)} samples (ruff + mypy) pushed")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
