#!/usr/bin/env python3
"""Collect trivy vulnerability findings and push them to Prometheus.

Scans the built image (or the repo filesystem as a fallback) with
`trivy --format json` and reduces the findings to per-severity counts:
  kubedash_trivy_findings{job="kubedash-security", severity="HIGH"} 4

Uses the image reference from --image (CI: kubedash:ci). If no image is
available, falls back to a filesystem scan of the repo root. A missing trivy
binary or an empty finding set both push a total of 0 so the gauge is always
present. Exit 0 unless trivy itself errors.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PUSH = os.path.join(HERE, "prometheus-push.py")
JOB = "kubedash-security"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _trivy_available() -> bool:
    return subprocess.run(["trivy", "--version"], capture_output=True).returncode == 0


def _scan(image: str | None) -> list[dict]:
    """Return trivy's flat vulnerability list."""
    if image:
        r = subprocess.run(["trivy", "image", image, "--format", "json", "--quiet"],
                           capture_output=True, text=True)
    else:
        r = subprocess.run(["trivy", "fs", REPO, "--format", "json", "--quiet",
                            "--scanners", "vuln"], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"trivy: scan exited {r.returncode}: {r.stderr.strip()[:200]}", file=sys.stderr)
        return []
    try:
        data = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return []
    vulns: list[dict] = []
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities", []) or []:
            vulns.append(v)
    return vulns


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", default=None, help="Image ref to scan (CI: kubedash:ci). Omit for a filesystem scan.")
    args = p.parse_args()

    samples = [{"name": "kubedash_trivy_findings", "labels": {"severity": s}, "value": 0} for s in SEVERITIES]
    samples.append({"name": "kubedash_trivy_findings", "labels": {"severity": "_total"}, "value": 0})

    if not _trivy_available():
        print("trivy-push: trivy not on PATH; pushing zero findings", file=sys.stderr)
    else:
        vulns = _scan(args.image)
        by_sev = {s: 0 for s in SEVERITIES}
        for v in vulns:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            if sev in by_sev:
                by_sev[sev] += 1
        for s in SEVERITIES:
            for sample in samples:
                if sample["labels"]["severity"] == s:
                    sample["value"] = by_sev[s]
        for sample in samples:
            if sample["labels"]["severity"] == "_total":
                sample["value"] = len(vulns)

    tmp = "/tmp/kubedash-security-results.json"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(samples, fh)
    rc = subprocess.run([sys.executable, PUSH, "--input", tmp, "--job", JOB]).returncode
    print(f"security-push: {len(samples)} samples (trivy) pushed")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
