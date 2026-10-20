#!/usr/bin/env python3
"""Collect jscpd duplication metrics and push them to Prometheus.

Runs jscpd over the frontend (the air-gapped React app, where duplication
matters most) with --reporters json and reduces the report to:
  kubedash_code_duplication_pct{job="kubedash-quality"}   12.5
  kubedash_code_clones{job="kubedash-quality"}            42

The duplication % comes from the report's stats (duplicatedLines / totalLines).
A missing jscpd binary or an empty scan pushes zeros so the gauge is present.
Exit 0 unless jscpd itself errors.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FRONTEND = os.path.join(REPO, "frontend")
PUSH = os.path.join(HERE, "prometheus-push.py")
JOB = "kubedash-quality"
REPORT = "/tmp/kubedash-jscpd-report.json"


def _jscpd_available() -> bool:
    return subprocess.run(["jscpd", "--version"], capture_output=True).returncode == 0


def main() -> int:
    samples = [
        {"name": "kubedash_code_duplication_pct", "labels": {}, "value": 0.0},
        {"name": "kubedash_code_clones", "labels": {}, "value": 0},
    ]

    if not _jscpd_available():
        print("jscpd-push: jscpd not on PATH; pushing zero metrics", file=sys.stderr)
    else:
        r = subprocess.run(
            ["jscpd", "--reporters", "json", "--output", "/tmp/jscpd-out",
             "--report-file", "jscpd-report", FRONTEND],
            capture_output=True, text=True, cwd=REPO)
        # jscpd writes <output>/jscpd-report.json (report-file base name).
        path = REPORT
        alt = "/tmp/jscpd-out/jscpd-report.json"
        if not os.path.exists(path) and os.path.exists(alt):
            path = alt
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    rep = json.load(fh)
                # jscpd report shape: {duplicates: [...], statistics: {formats: {<fmt>: {duplicatedLines, lines, clones, ...}}}}
                stats = rep.get("statistics", {}) or {}
                formats = stats.get("formats", {}) or {}
                dup = sum(int(f.get("duplicatedLines", 0)) for f in formats.values())
                total = sum(int(f.get("lines", 0)) for f in formats.values())
                samples[0]["value"] = round(100.0 * dup / total, 2) if total else 0.0
                samples[1]["value"] = len(rep.get("duplicates", []) or [])
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                print(f"jscpd-push: could not parse report: {exc}", file=sys.stderr)
        else:
            print(f"jscpd-push: report not found at {path}; jscpd rc={r.returncode}", file=sys.stderr)

    tmp = "/tmp/kubedash-quality-results.json"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(samples, fh)
    rc = subprocess.run([sys.executable, PUSH, "--input", tmp, "--job", JOB]).returncode
    print(f"quality-push: {len(samples)} samples (jscpd) pushed")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
