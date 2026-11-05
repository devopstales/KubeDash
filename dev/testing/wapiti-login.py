#!/usr/bin/env python3
"""Authenticated Wapiti DAST scan of the running KubeDash API (spec T11).

Bootstrap contract (dev loop, ADR-0021 bootstrap admin):
  1. The stack must be up (GET /healthz) and ``wapiti`` must be on PATH,
     otherwise the suite reports ``skipped`` and exits 0.
  2. Log in via POST /api/v1/auth/local and pre-flight GET /api/v1/auth/me
     with the session cookie — a bootstrap failure is a test failure
     (exit 1), not a skip.
  3. Run Wapiti against the SPA root with the OpenAPI swagger so API
     endpoints are crawled (the built SPA HTML has no links for the
     crawler to follow), authenticated with the kd_access cookie.
  4. Reduce the findings to per-severity/type counts, print a summary, and
     push kubedash_security_vulns_total{tool=wapiti,severity,type} to the
     Pushgateway when PROMETHEUS_PUSHGATEWAY_URL is set (silent no-op
     otherwise — same contract as scripts/prometheus-push.py).

Findings are advisory: exit 0 after a completed scan regardless of
findings; non-zero only for bootstrap/scan failure.

Env:
  DAST_URL             base URL (default http://localhost:8080)
  DAST_ADMIN_EMAIL     bootstrap admin (default admin@local)
  DAST_ADMIN_PASSWORD  bootstrap password (default admin)
  DAST_MAX_SCAN_TIME   seconds (default 600)
  PROMETHEUS_PUSHGATEWAY_URL   e.g. http://localhost:9091
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PUSH = os.path.join(REPO, "scripts", "prometheus-push.py")
ARTIFACT = os.path.join(REPO, "tmp", "testing", "security-wapiti.json")

MODULES = "sql,xss,exec,file,xxe,crlf,csrf,http_headers,cookieflags,csp,redirect"
EXCLUSIONS = ["/assets", "/api/docs", "/img"]
# Wapiti finding levels: 1 = low, 2 = medium/high.
LEVEL_SEVERITY = {1: "low", 2: "high"}


def _get(url: str, cookie: str | None = None, timeout: float = 5.0) -> int:
    req = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.URLError:  # HTTPError is a subclass — covers both
        return 0


def _skip(reason: str) -> int:
    print(f"dast: skipped — {reason}")
    return 0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return the 302 itself — the session cookies ride in its Set-Cookie."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N803
        return None


def _login(base: str, email: str, password: str) -> str:
    """Log in and return the kd_access cookie value; raise on failure."""
    req = urllib.request.Request(
        f"{base}/api/v1/auth/local",
        data=json.dumps({"email": email, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=10) as resp:
            status, set_cookie = resp.status, resp.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as e:
        # With redirects disabled, a 30x arrives as an HTTPError; the
        # session cookies ride in its headers.
        status, set_cookie = e.code, e.headers.get("Set-Cookie", "")
        if status not in (301, 302, 303, 307, 308):
            raise RuntimeError(f"login -> {status}: {e.read()[:200]!r}") from None
    if status not in (301, 302, 303, 307, 308):
        raise RuntimeError(f"login -> {status}: no redirect (check credentials)")
    m = re.search(r"kd_access=([^;]+)", set_cookie)
    if not m:
        raise RuntimeError("no kd_access cookie in login response")
    return m.group(1)


def _reduce(report: dict) -> list[dict]:
    """Count findings per (severity, module) and print a summary."""
    samples: list[dict] = []
    for title, items in (report.get("vulnerabilities") or {}).items():
        if not items:
            continue
        mod = items[0].get("module") or title
        by_sev: dict[str, int] = {}
        for it in items:
            sev = LEVEL_SEVERITY.get(it.get("level"), "high")
            by_sev[sev] = by_sev.get(sev, 0) + 1
        for sev, n in sorted(by_sev.items()):
            samples.append({"name": "kubedash_security_vulns_total",
                            "labels": {"tool": "wapiti", "severity": sev, "type": mod},
                            "value": n})
        print(f"dast: {title}: {len(items)} finding(s) — "
              + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())))
    for name, items in (report.get("anomalies") or {}).items():
        if not items:
            continue
        samples.append({"name": "kubedash_security_vulns_total",
                        "labels": {"tool": "wapiti", "severity": "unknown", "type": "anomaly"},
                        "value": len(items)})
        print(f"dast: anomaly: {name} ({len(items)})")
    return samples


def main() -> int:
    base = os.environ.get("DAST_URL", "http://localhost:8080").rstrip("/")
    email = os.environ.get("DAST_ADMIN_EMAIL", "admin@local")
    password = os.environ.get("DAST_ADMIN_PASSWORD", "admin")
    max_scan = int(os.environ.get("DAST_MAX_SCAN_TIME", "600"))

    if _get(f"{base}/healthz") != 200:
        return _skip(f"stack not running at {base} (task dev-stack)")
    if shutil.which("wapiti") is None:
        return _skip("wapiti not on PATH")

    try:
        cookie = _login(base, email, password)
        if _get(f"{base}/api/v1/auth/me", cookie=f"kd_access={cookie}") != 200:
            raise RuntimeError("preflight /api/v1/auth/me did not return 200")
    except (RuntimeError, OSError) as exc:
        print(f"dast: bootstrap failed: {exc}", file=sys.stderr)
        return 1
    print(f"dast: logged in as {email} (preflight /auth/me 200)")

    os.makedirs(os.path.dirname(ARTIFACT), exist_ok=True)
    args = ["wapiti", "-u", f"{base}/", "--scope", "folder",
            "--swagger", f"{base}/api/openapi.json",
            "-C", f"kd_access={cookie}",
            "-m", MODULES,
            "-f", "json", "-o", ARTIFACT,
            "--max-scan-time", str(max_scan)]
    for pat in EXCLUSIONS:
        args += ["--exclude", f"{base}{pat}"]
    r = subprocess.run(args, capture_output=True, text=True)
    if not os.path.exists(ARTIFACT):
        print(f"dast: scan failed (wapiti exit {r.returncode}): "
              f"{r.stderr.strip()[:300]}", file=sys.stderr)
        return 1

    with open(ARTIFACT, encoding="utf-8") as fh:
        report = json.load(fh)
    samples = _reduce(report)

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(samples, fh)
        tmp = fh.name
    try:
        subprocess.run([sys.executable, PUSH, "--input", tmp, "--job", "kubedash-dast"])
    finally:
        os.unlink(tmp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
