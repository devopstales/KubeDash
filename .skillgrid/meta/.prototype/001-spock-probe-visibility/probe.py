#!/usr/bin/env python3
"""001-spock-probe-visibility — throwaway experiment (NOT production code).

Questions (see prototype.md):
  Q1 (data shape): does ONE node's spock views expose BOTH replication
     directions, or must the HA report fan out a probe to every node?
  Q2 (down-node mechanics): does a SQLAlchemy probe with
     connect_timeout=3 s against a stopped pgEdge node return fast with a
     classifiable error (never hang), create/dispose the engine cleanly,
     and execute only SELECTs?

Run:  cd backend && uv run python ../.skillgrid/meta/.prototype/001-spock-probe-visibility/probe.py
UI:   http://127.0.0.1:8099  (Re-probe button; Stop/Start buttons per node)
API:  GET /api/probe  POST /api/node/stop|start {"name": "n2"}
"""

import json
import re
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from sqlalchemy import create_engine, text

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent.parent.parent / "specs" / "2026-11-10-ha-status-page" / "modules"))
from ha_derive import NodeProbeData, LeaseState, derive_status  # noqa: E402

# Dev stack (merged compose, 2026-11-11): n1 on :5432, n2 on :16433.
NODES = {
    "n1": "postgresql://kubedash:kubedash@localhost:5432/kubedash",
    "n2": "postgresql://kubedash:kubedash@localhost:16433/kubedash",
}
CONTAINERS = {"n1": "kdpg-n1", "n2": "kdpg-n2"}
APP_DSN = NODES["n1"]  # catalog reads come from the app's own node

PROBE_SQL = {
    "local_node_name": "SELECT n.node_name FROM spock.local_node l JOIN spock.node n ON n.node_id = l.node_id",
    "subscriptions": "SELECT sub_name FROM spock.subscription",
    "lag_tracker": "SELECT origin_name, receiver_name, replication_lag_bytes, replication_lag FROM spock.lag_tracker",
    "apply_workers": "SELECT worker_pid, worker_subid, worker_status FROM spock.get_apply_worker_status()",
    "channel_totals": (
        "SELECT coalesce(sum(n_tup_ins),0) ins, coalesce(sum(n_tup_upd),0) upd, "
        "coalesce(sum(n_tup_del),0) dels, coalesce(sum(n_conflict),0) conflicts, "
        "coalesce(sum(n_dca),0) dca FROM spock.get_channel_stats()"
    ),
    "exceptions": "SELECT count(*) n, coalesce(max(retry_errored_at), min(remote_commit_ts)) last FROM spock.exception_status",
}
LOCK_SQL = (
    "SELECT l.pid, l.granted, a.state FROM pg_locks l "
    "JOIN pg_stat_activity a ON a.pid = l.pid "
    "WHERE l.locktype = 'advisory' AND l.classid = 4294967295::oid "
    "AND l.objid = hashtext(:rid)::oid AND l.objsubid = 1"
)
SUB_STATUS_SQL = "SELECT subscription_name, status, provider_node, slot_name FROM spock.sub_show_status(:name)"


def classify_error(exc: BaseException) -> str:
    chain = [exc]
    while chain[-1].__cause__ is not None:
        chain.append(chain[-1].__cause__)
    for e in chain:
        if isinstance(e, ConnectionRefusedError):
            return "connection_refused"
        msg = str(e).lower()
        if isinstance(e, TimeoutError) or "timed out" in msg or "timeout" in msg:
            return "timeout"
        if "password" in msg or "insufficient" in msg or "auth" in msg:
            return "auth"
        if "connection refused" in msg:
            return "connection_refused"
        if "server closed" in msg or "connection reset" in msg or "broken pipe" in msg:
            return "server_down"
    return f"other:{type(exc).__name__}"


def run_sql(conn, label: str, sql: str, params: dict | None = None, statements: list | None = None):
    if statements is not None:
        statements.append(sql)
    return conn.execute(text(sql), params or {}).fetchall()


def probe_node(dsn: str, replica_id: str, timeout_s: float = 3.0) -> dict:
    t0 = time.monotonic()
    statements: list[str] = []
    result = {
        "reachable": False, "probe_error": None, "node_name": None,
        "sub_statuses": [], "lag_bytes": 0, "lag_interval_s": 0.0,
        "apply_workers": 0, "workers_streaming": False,
        "conflicts": 0, "exceptions_pending": 0, "exceptions_last": None,
        "lock_held_locally": False, "lock_holder_pid": None, "lock_holder_state": None,
        "elapsed_ms": 0, "statements": statements,
    }
    engine = create_engine(dsn, connect_args={"connect_timeout": timeout_s})
    try:
        with engine.connect() as conn:
            (row,) = run_sql(conn, "local_node_name", PROBE_SQL["local_node_name"], statements=statements)
            result["node_name"] = row[0]
            for (sub,) in run_sql(conn, "subscriptions", PROBE_SQL["subscriptions"], statements=statements):
                for r in run_sql(conn, f"sub_status:{sub}", SUB_STATUS_SQL, {"name": sub}, statements=statements):
                    result["sub_statuses"].append({"name": r[0], "status": r[1]})
            for r in run_sql(conn, "lag_tracker", PROBE_SQL["lag_tracker"], statements=statements):
                result["lag_bytes"] = int(r[2] or 0)
                iv = r[3]
                secs = (iv.days * 86400 + iv.seconds) if iv is not None else 0
                result["lag_interval_s"] = round(secs + (iv.microseconds / 1e6 if iv else 0), 3)
            for r in run_sql(conn, "apply_workers", PROBE_SQL["apply_workers"], statements=statements):
                result["apply_workers"] += 1
                if r[2] == "running":
                    result["workers_streaming"] = True
            (r,) = run_sql(conn, "channel_totals", PROBE_SQL["channel_totals"], statements=statements)
            result["conflicts"] = int(r[3] or 0)
            (r,) = run_sql(conn, "exceptions", PROBE_SQL["exceptions"], statements=statements)
            result["exceptions_pending"] = int(r[0] or 0)
            result["exceptions_last"] = str(r[1]) if r[1] else None
            for r in run_sql(conn, "lock_check", LOCK_SQL, {"rid": replica_id}, statements=statements):
                if r[1]:  # granted
                    result["lock_held_locally"] = True
                    result["lock_holder_pid"] = int(r[0])
                    result["lock_holder_state"] = r[2]
        result["reachable"] = True
    except Exception as exc:  # noqa: BLE001 — classification is the point
        result["probe_error"] = classify_error(exc)
    finally:
        engine.dispose()
        result["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
    return result


def read_catalog() -> dict:
    engine = create_engine(APP_DSN, connect_args={"connect_timeout": 3})
    try:
        with engine.connect() as conn:
            (row,) = conn.execute(text("SELECT spock.spock_version()")).fetchall()
            version = row[0]
            members = [r[0] for r in conn.execute(text("SELECT node_name FROM spock.node ORDER BY node_name")).fetchall()]
            ifaces = {r[0]: r[1] for r in conn.execute(text("SELECT if_name, if_dsn FROM spock.node_interface")).fetchall()}
            lease_rows = conn.execute(
                text("SELECT replica_id, token, acquired_at, heartbeat_at, fence FROM leader_lease WHERE id = 1")
            ).fetchall()
            now = conn.execute(text("SELECT now()")).scalar()
            lease = None
            if lease_rows:
                (rid, token, acquired_at, heartbeat_at, fence) = lease_rows[0]
                lease = {
                    "replica_id": rid, "token": str(token), "fence": fence,
                    "acquired_at": str(acquired_at),
                    "heartbeat_age_s": round((now - heartbeat_at).total_seconds(), 1),
                }
    finally:
        engine.dispose()
    return {"spock_version": version, "members": members, "interfaces": ifaces, "lease": lease}


def full_probe() -> dict:
    catalog = read_catalog()
    rid = catalog["lease"]["replica_id"] if catalog["lease"] else None
    probes = {name: probe_node(dsn, rid or "?") for name, dsn in NODES.items()}
    node_data = [
        NodeProbeData(
            node_name=n, reachable=p["reachable"], probe_error=p["probe_error"],
            sub_statuses=tuple((s["name"], s["status"]) for s in p["sub_statuses"]),
            lag_bytes=p["lag_bytes"], lag_interval_s=p["lag_interval_s"],
            apply_workers=p["apply_workers"], workers_streaming=p["workers_streaming"],
            conflicts=p["conflicts"], exceptions_pending=p["exceptions_pending"],
            lock_held_locally=p["lock_held_locally"],
            lock_holder_pid=p["lock_holder_pid"], lock_holder_state=p["lock_holder_state"],
            elapsed_ms=p["elapsed_ms"],
        )
        for n, p in probes.items()
    ]
    lease = LeaseState(
        present=catalog["lease"] is not None,
        replica_id=catalog["lease"]["replica_id"] if catalog["lease"] else None,
        fence=catalog["lease"]["fence"] if catalog["lease"] else None,
        heartbeat_age_s=catalog["lease"]["heartbeat_age_s"] if catalog["lease"] else None,
    )
    der = derive_status(node_data, lease)
    return {
        "probed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "spock_version": catalog["spock_version"],
        "members": catalog["members"],
        "interfaces": catalog["interfaces"],
        "lease": catalog["lease"],
        "nodes": probes,
        "derivation": {
            "status": der.status,
            "reasons": list(der.reasons),
            "leader": der.leader.__dict__ if der.leader else None,
            "database": {"status": der.database.status, "reasons": list(der.database.reasons)},
            "election": {"status": der.election.status, "reasons": list(der.election.reasons)},
        },
    }


def docker_ctl(action: str, node: str) -> dict:
    if node not in CONTAINERS:
        return {"ok": False, "error": f"unknown node {node!r}"}
    t0 = time.monotonic()
    proc = subprocess.run(["docker", action, CONTAINERS[node]], capture_output=True, text=True, timeout=60)
    return {
        "ok": proc.returncode == 0,
        "node": node,
        "container": CONTAINERS[node],
        "elapsed_ms": int((time.monotonic() - t0) * 1000),
        "output": (proc.stdout + proc.stderr).strip()[:200],
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/probe":
            try:
                self._send(200, json.dumps(full_probe()).encode(), "application/json")
            except Exception as exc:  # noqa: BLE001
                self._send(500, json.dumps({"error": f"{type(exc).__name__}: {exc}"}).encode(), "application/json")
        elif self.path in ("/", "/index.html"):
            self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path in ("/api/node/stop", "/api/node/start"):
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}")
            action = "stop" if self.path.endswith("stop") else "start"
            res = docker_ctl(action, payload.get("name", ""))
            self._send(200, json.dumps(res).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 8099), Handler)
    print("prototype 001 UI on http://127.0.0.1:8099", flush=True)
    srv.serve_forever()
