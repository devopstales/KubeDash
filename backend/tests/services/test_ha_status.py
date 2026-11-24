"""HA status service (spec 2026-11-10-ha-status-page) — unit tier.

Covers the derivation matrix (the F12-F17 nuances: lock cross-check,
F17's lag_bytes>0 requirement, "not seen while a node is unreachable" is
NOT an alarm), the probe seam against a fake engine, the INI DSN-override
parse, and the best-effort candidates read. No live Postgres (that is the
kind-gated integration backstop).
"""

from __future__ import annotations

import pytest

from app.core import ini_config
from app.core.ini_config import ConfigError
from app.services import ha_status
from app.services.ha_status import (
    LeaseState,
    NodeProbeData,
    build_report,
    classify_error,
    derive_status,
    probe_node,
)

D1 = "postgresql://u:p@n1:5432/kubedash"
D2 = "postgresql://u:p@n2:5432/kubedash"


# --- helpers -----------------------------------------------------------------


def node(
    name: str,
    *,
    reachable: bool = True,
    sub_statuses: tuple[tuple[str, str], ...] = (("sub-1", "replicating"),),
    lag_bytes: int = 0,
    lag_s: float = 0.0,
    exceptions_pending: int = 0,
    lock: bool = False,
) -> NodeProbeData:
    return NodeProbeData(
        node_name=name,
        reachable=reachable,
        sub_statuses=sub_statuses,
        lag_bytes=lag_bytes,
        lag_interval_s=lag_s,
        exceptions_pending=exceptions_pending,
        lock_held_locally=lock,
        lock_holder_pid=7899 if lock else None,
        lock_holder_state="idle" if lock else None,
    )


def fresh_lease(rid: str = "replica-1") -> LeaseState:
    return LeaseState(present=True, replica_id=rid, fence=3, heartbeat_age_s=0.5)


def stale_lease(rid: str = "replica-1", age: float = 15.0) -> LeaseState:
    return LeaseState(present=True, replica_id=rid, fence=3, heartbeat_age_s=age)


# --- derivation matrix ---------------------------------------------------------


def test_healthy_baseline() -> None:
    nodes = [node("n1"), node("n2", lock=True)]
    der = derive_status(nodes, fresh_lease())
    assert der["status"] == "healthy"
    assert der["reasons"] == []
    assert der["database"]["status"] == "healthy"
    assert der["election"]["status"] == "healthy"
    assert der["leader"]["lock_verdict"] == "held on n2 (pid 7899, idle)"
    assert der["leader"]["replica_id"] == "replica-1"
    assert der["leader"]["fence"] == 3


def test_down_node_unreachable() -> None:
    nodes = [node("n1"), node("n2", reachable=False)]
    der = derive_status(nodes, fresh_lease())
    assert der["status"] == "down"
    assert "node_unreachable:n2" in der["reasons"]
    assert der["database"]["status"] == "down"


def test_down_subscription_not_replicating() -> None:
    nodes = [
        node("n1"),
        node("n2", sub_statuses=(("sub-1", "streaming"),)),
    ]
    der = derive_status(nodes, fresh_lease())
    assert der["status"] == "down"
    assert "subscription_not_replicating:n2" in der["reasons"]


def test_degraded_lag_exceeded() -> None:
    nodes = [node("n1", lag_bytes=1000, lag_s=120.0), node("n2", lock=True)]
    der = derive_status(nodes, fresh_lease())
    assert der["status"] == "degraded"
    assert "lag_exceeded:n1" in der["reasons"]
    assert der["election"]["status"] == "healthy"


def test_f17_zero_bytes_lag_is_not_lag() -> None:
    # F17: the lag_interval alone does not fire — the tracker reports a
    # non-zero interval with zero bytes while the subscription is idle.
    nodes = [node("n1", lag_bytes=0, lag_s=120.0), node("n2", lock=True)]
    der = derive_status(nodes, fresh_lease())
    assert der["status"] == "healthy"
    assert "lag_exceeded:n1" not in der["reasons"]


def test_degraded_exceptions_pending() -> None:
    nodes = [node("n1", exceptions_pending=3), node("n2", lock=True)]
    der = derive_status(nodes, fresh_lease())
    assert der["status"] == "degraded"
    assert "exceptions_pending:n1" in der["reasons"]


def test_degraded_lock_lease_mismatch_all_reachable() -> None:
    # F13: heartbeat fresh, no lock on ANY reachable node, and every node
    # IS reachable -> the lock should be visible; it is not.
    nodes = [node("n1"), node("n2")]
    der = derive_status(nodes, fresh_lease())
    assert der["status"] == "degraded"
    assert "lock_lease_mismatch" in der["reasons"]
    assert der["leader"]["lock_verdict"] == "not seen on any reachable node"


def test_f12_no_alarm_while_a_node_is_unreachable() -> None:
    # F12: heartbeat fresh, no lock seen, but n2 is unreachable — the
    # session-local lock may sit on the unreachable node. NO election alarm
    # (the database section is down, though).
    nodes = [node("n1"), node("n2", reachable=False)]
    der = derive_status(nodes, fresh_lease())
    assert der["status"] == "down"
    assert der["election"]["status"] == "healthy"
    assert der["election"]["reasons"] == []
    assert der["leader"]["lock_verdict"] == "not seen on any reachable node"


def test_degraded_lock_without_heartbeat() -> None:
    # F14: stale heartbeat + a granted lock on a reachable node — the
    # session is alive, the process is wedged.
    nodes = [node("n1", lock=True), node("n2")]
    der = derive_status(nodes, stale_lease())
    assert der["status"] == "degraded"
    assert "leader_heartbeat_stale" in der["reasons"]
    assert "lock_without_heartbeat" in der["reasons"]


def test_degraded_no_leader() -> None:
    # Stale heartbeat + no lock on any reachable node: fail-closed.
    nodes = [node("n1"), node("n2")]
    der = derive_status(nodes, stale_lease())
    assert der["status"] == "degraded"
    assert "leader_heartbeat_stale" in der["reasons"]
    assert "no_leader" in der["reasons"]


def test_degraded_lease_missing() -> None:
    nodes = [node("n1"), node("n2", lock=True)]
    der = derive_status(nodes, LeaseState(present=False))
    assert der["status"] == "degraded"
    assert "leader_lease_missing" in der["reasons"]
    assert der["leader"]["replica_id"] == "?"
    assert der["leader"]["fence"] == 0


def test_no_reachable_node_to_check() -> None:
    nodes = [node("n1", reachable=False), node("n2", reachable=False)]
    der = derive_status(nodes, fresh_lease())
    assert der["status"] == "down"
    assert der["leader"]["lock_verdict"] == "no reachable node to check"


def test_overall_is_worst_section_reasons_db_first() -> None:
    # database down + election degraded -> overall down; reasons list the
    # database section first.
    nodes = [
        node("n1", reachable=False, exceptions_pending=2),
        node("n2"),
    ]
    der = derive_status(nodes, stale_lease())
    assert der["status"] == "down"
    assert der["reasons"][0] == "node_unreachable:n1"
    assert "leader_heartbeat_stale" in der["reasons"]


def test_election_failure_is_never_down() -> None:
    nodes = [node("n1", lock=True), node("n2")]
    der = derive_status(nodes, LeaseState(present=False))
    assert der["election"]["status"] == "degraded"
    assert der["status"] in ("healthy", "degraded")


def test_lock_double_holder_is_degraded() -> None:
    # Split brain: both reachable nodes claim the leader lock (W049a).
    nodes = [node("n1", lock=True), node("n2", lock=True)]
    der = derive_status(nodes, fresh_lease())
    assert der["election"]["status"] == "degraded"
    assert "lock_double_holder" in der["election"]["reasons"]
    verdict = der["leader"]["lock_verdict"]
    # The verdict names BOTH holders, not just the first.
    assert "n1" in verdict and "n2" in verdict and "SPLIT BRAIN" in verdict


# --- probe seam (fake engine) ---------------------------------------------------


class _FakeResult:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _FakeConn:
    """Returns canned rows keyed by a SQL substring, in call order."""

    def __init__(self, by_sql: dict[str, list]) -> None:
        self._by_sql = by_sql
        self.executed: list[str] = []

    def execute(self, stmt, params=None):
        sql = stmt.text if hasattr(stmt, "text") else str(stmt)
        self.executed.append(sql)
        for key, rows in self._by_sql.items():
            if key in sql:
                return _FakeResult(rows)
        raise AssertionError(f"unexpected SQL: {sql}")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeEngine:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn
        self.disposed = False

    def connect(self):
        return self._conn

    def dispose(self):
        self.disposed = True


def _healthy_conn(lock: bool = False) -> _FakeConn:
    lock_rows = [(7899, True, "idle")] if lock else []
    return _FakeConn(
        {
            "FROM spock.local_node": [("n1",)],
            "FROM spock.subscription": [("sub-1",)],
            "spock.sub_show_status": [("sub-1", "replicating", "n2", "slot1")],
            "FROM spock.lag_tracker": [("n2", "n1", 100, None)],
            "spock.get_apply_worker_status": [(11, 1, "running")],
            "spock.get_channel_stats": [(5, 0, 0, 0, 0)],
            "FROM spock.exception_status": [(0, None)],
            "pg_locks": lock_rows,
        }
    )


def test_probe_node_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _healthy_conn(lock=True)
    engine = _FakeEngine(conn)
    monkeypatch.setattr(ha_status, "create_engine", lambda dsn, **kw: engine)

    probe = probe_node(D1, "replica-1")

    assert probe.reachable is True
    assert probe.node_name == "n1"
    assert probe.sub_statuses == (("sub-1", "replicating"),)
    assert probe.lag_bytes == 100
    assert probe.apply_workers == 1
    assert probe.workers_streaming is True
    assert probe.conflicts == 0
    assert probe.exceptions_pending == 0
    assert probe.lock_held_locally is True
    assert probe.lock_holder_pid == 7899
    assert probe.lock_holder_state == "idle"
    assert engine.disposed is True
    # read-only invariant: every executed statement is a SELECT / function call
    assert all(s.lstrip().upper().startswith("SELECT") for s in conn.executed)


def test_probe_node_unreachable_is_a_result(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Down(_FakeEngine):
        def connect(self):
            raise ConnectionRefusedError("Connection refused")

    engine = _Down(_healthy_conn())
    monkeypatch.setattr(ha_status, "create_engine", lambda dsn, **kw: engine)

    probe = probe_node(D1, "replica-1")

    assert probe.reachable is False
    assert probe.probe_error == "connection_refused"
    assert probe.sub_statuses == ()


def test_probe_node_not_joined_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    # spock.local_node is empty — the node is reachable (TCP + auth OK) but
    # has never joined the cluster. A NAMED classification, not
    # other:ValueError (W049b); the remaining SQL set is skipped because an
    # unjoined node's tables are not authoritative.
    conn = _FakeConn({"FROM spock.local_node": []})
    engine = _FakeEngine(conn)
    monkeypatch.setattr(ha_status, "create_engine", lambda dsn, **kw: engine)

    probe = probe_node(D1, "replica-1")

    assert probe.reachable is False
    assert probe.probe_error == "node_not_joined"
    assert len(conn.executed) == 1  # only the local-node read ran
    assert engine.disposed is True


def test_classify_error() -> None:
    assert classify_error(ConnectionRefusedError()) == "connection_refused"
    assert classify_error(TimeoutError()) == "timeout"
    assert classify_error(Exception("password authentication failed")) == "auth"
    assert classify_error(Exception("connection reset by peer")) == "server_down"
    assert classify_error(ValueError("weird")) == "other:ValueError"


# --- INI DSN override parse ------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_ini():
    ini_config.reset()
    yield
    ini_config.reset()


def _override(value: str) -> None:
    ini_config._overrides["ha_node_dsn_overrides"] = value


def test_dsn_overrides_empty_default() -> None:
    assert ini_config.resolve_ha_node_dsn_overrides() == {}


def test_dsn_overrides_parse() -> None:
    _override("n1=postgresql://u:p@localhost:5432/kubedash; n2=postgresql://u:p@localhost:16433/kubedash")
    out = ini_config.resolve_ha_node_dsn_overrides()
    assert out == {
        "n1": "postgresql://u:p@localhost:5432/kubedash",
        "n2": "postgresql://u:p@localhost:16433/kubedash",
    }


@pytest.mark.parametrize(
    "value",
    [
        "n1",  # no =
        "=postgresql://u:p@h:5432/db",  # empty name
        "n 1=postgresql://u:p@h:5432/db",  # bad name
        "n1=mysql://u:p@h:3306/db",  # not postgresql
        "n1=postgresql://h:5432/db;n1=postgresql://h:5433/db",  # duplicate
    ],
)
def test_dsn_overrides_malformed_raises(value: str) -> None:
    _override(value)
    with pytest.raises(ConfigError):
        ini_config.resolve_ha_node_dsn_overrides()


# --- report assembly ----------------------------------------------------------------


def _catalog() -> dict:
    return {
        "spock_version": "5.0.1",
        "members": ["n1", "n2"],
        "interfaces": {"n1": D1, "n2": D2},
        "lease": {
            "replica_id": "replica-1",
            "token": "tok",
            "acquired_at": "2026-11-11 10:00:00",
            "heartbeat_at": "2026-11-11 10:04:59",
            "heartbeat_age_s": 0.5,
            "fence": 3,
        },
        "queue": {
            "pending": 1,
            "processing": 0,
            "done": 7,
            "oldest_pending_at": "2026-11-11 10:01:00",
        },
    }


def test_build_report_merges_overrides_and_assembles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ha_status, "_read_catalog", lambda engine: _catalog())
    seen: list[str] = []

    def _fake_probe(dsn: str, rid: str, timeout_s: float = 3.0, **_kw) -> NodeProbeData:
        seen.append(dsn)
        # One lock holder only (n1) — both holding would be split brain
        # (lock_double_holder, degraded), which this test does not exercise.
        return node(dsn.split("@")[1].split(":")[0], lock=dsn == D1)

    monkeypatch.setattr(ha_status, "probe_node", _fake_probe)

    report = build_report(
        engine=None,
        dsn_overrides={"n2": "postgresql://u:p@localhost:16433/kubedash"},
        admin_client=None,
    )

    # the override wins for n2; n1 keeps its interface DSN
    assert seen == [D1, "postgresql://u:p@localhost:16433/kubedash"]
    assert report["spock_version"] == "5.0.1"
    assert [n["name"] for n in report["nodes"]] == ["n1", "n2"]
    # credentials never leak: dsn is host:port only
    assert report["nodes"][0]["dsn"] == "n1:5432"
    assert report["nodes"][1]["dsn"] == "localhost:16433"
    assert report["leader"]["candidates"] is None
    assert report["leader"]["token"] == "tok"
    # lease-object fields for the page (renewTime + leaseDurationSeconds)
    assert report["leader"]["renew_at"] == "2026-11-11 10:04:59"
    assert report["leader"]["lease_duration_s"] == ha_status.LEASE_DURATION_S
    assert report["queue"]["done"] == 7
    assert report["status"] == "healthy"


def test_build_report_falls_back_to_configured_replica_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No Deployment read (host dev / RBAC) -> the configured count, not null:
    a single-node run reports 1, a 3-replica Deployment reports 3."""
    monkeypatch.setattr(ha_status, "_read_catalog", lambda engine: _catalog())
    monkeypatch.setattr(
        ha_status, "probe_node", lambda dsn, rid, timeout_s=3.0, **_kw: node("n1", lock=True)
    )

    single = build_report(engine=None, admin_client=None, replica_count=1)
    assert single["leader"]["candidates"] == 1

    multi = build_report(engine=None, admin_client=None, replica_count=3)
    assert multi["leader"]["candidates"] == 3


def test_build_report_detected_replicas_win_over_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ha_status, "_read_catalog", lambda engine: _catalog())
    monkeypatch.setattr(
        ha_status, "probe_node", lambda dsn, rid, timeout_s=3.0, **_kw: node("n1", lock=True)
    )
    client = _FakeAdminClient(
        [_pod_with_rs("local", "kubedash-abc12-def34")],
        [{"spec": {"replicas": 2}}],
    )

    report = build_report(
        engine=None, admin_client=client, replica_count=1
    )

    assert report["leader"]["candidates"] == 2


def test_build_report_member_without_dsn_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = _catalog()
    catalog["interfaces"] = {"n1": D1}  # n2 has no interface row
    monkeypatch.setattr(ha_status, "_read_catalog", lambda engine: catalog)
    monkeypatch.setattr(
        ha_status, "probe_node", lambda dsn, rid, timeout_s=3.0, **_kw: node("n1")
    )

    report = build_report(engine=None)

    n2 = report["nodes"][1]
    assert n2["reachable"] is False
    assert n2["probe_error"] == "no_dsn"
    assert "node_unreachable:n2" in report["reasons"]


def test_build_report_warns_on_unknown_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A typo'd override name (not in spock.node) is dead config — the
    # report must say so (W049d). Known names warn nothing.
    monkeypatch.setattr(ha_status, "_read_catalog", lambda engine: _catalog())
    monkeypatch.setattr(
        ha_status, "probe_node", lambda dsn, rid, timeout_s=3.0, **_kw: node("n1")
    )

    report = build_report(
        engine=None,
        dsn_overrides={"n1": D1, "typo": "postgresql://u:p@h:5433/kubedash"},
    )
    assert report["warnings"] == [
        "node_dsn_overrides: unknown node name 'typo' (not in spock.node)"
    ]

    report = build_report(engine=None, dsn_overrides={"n2": D2})
    assert report["warnings"] == []


def test_build_report_failed_probe_reason_carries_member_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A stopped node cannot report its own local name — probe_node returns
    # node_name="" — but the reason string must still carry the member name
    # from spock.node (acceptance: node_unreachable:n2, never the bare
    # "node_unreachable:").
    catalog = _catalog()
    monkeypatch.setattr(ha_status, "_read_catalog", lambda engine: catalog)
    monkeypatch.setattr(
        ha_status,
        "probe_node",
        lambda dsn, rid, timeout_s=3.0, **_kw: (
            node("n1")
            if dsn == D1
            else NodeProbeData(
                node_name="", reachable=False, probe_error="connection_refused"
            )
        ),
    )

    report = build_report(engine=None)

    assert report["status"] == "down"
    assert "node_unreachable:n2" in report["reasons"]
    assert not any(r == "node_unreachable:" for r in report["reasons"])


# --- candidates (best-effort owner-refs chain) ---------------------------------------


class _FakeAdminClient:
    def __init__(self, pod: list[dict] | None, dep: list[dict] | None) -> None:
        self._pod = pod
        self._dep = dep

    def get_pod(self, ns: str, name: str) -> list[dict]:
        return self._pod if self._pod is not None else []

    def get_deployment(self, ns: str, name: str) -> list[dict]:
        return self._dep if self._dep is not None else []


def _pod_with_rs(name: str, rs: str) -> dict:
    return {
        "metadata": {
            "name": name,
            "ownerReferences": [{"kind": "ReplicaSet", "name": rs}],
        }
    }


def test_candidate_count_full_chain() -> None:
    client = _FakeAdminClient(
        [_pod_with_rs("kubedash-abc12", "kubedash-abc12-def34")],
        [{"spec": {"replicas": 3}}],
    )
    assert ha_status._candidate_count(client, "kubedash-abc12") == 3


def test_candidate_count_pod_missing() -> None:
    client = _FakeAdminClient([], [{"spec": {"replicas": 3}}])
    assert ha_status._candidate_count(client, "x") is None


def test_candidate_count_no_replicaset_owner() -> None:
    pod = [{"metadata": {"name": "x", "ownerReferences": [{"kind": "Job", "name": "j"}]}}]
    assert ha_status._candidate_count(_FakeAdminClient(pod, None), "x") is None


def test_candidate_count_transport_failure_is_none() -> None:
    class _Boom:
        def get_pod(self, ns: str, name: str):
            raise RuntimeError("apiserver down")

    assert ha_status._candidate_count(_Boom(), "x") is None


def test_candidate_count_null_replica_id() -> None:
    assert ha_status._candidate_count(_FakeAdminClient([_pod_with_rs("a", "a-b")], None), "?") is None
    assert ha_status._candidate_count(None, "x") is None


def test_dsn_display() -> None:
    assert ha_status._dsn_display("postgresql://u:p@host:5432/db") == "host:5432"
    assert ha_status._dsn_display(None) == ""
    assert ha_status._dsn_display("postgresql://u:p@kdp-n2/db") == "kdp-n2"


# --- review fixes (2026-11-13 code review, round 1) -----------------------------


def test_dsn_display_keyword_format() -> None:
    # The in-cluster default (spock.node_interface) is libpq KEYWORD format;
    # only host:port may reach the UI — user=/password= never.
    dsn = "host=n1 port=5432 dbname=kubedash user=pgedge"
    assert ha_status._dsn_display(dsn) == "n1:5432"
    shown = ha_status._dsn_display(dsn + " password=secret")
    assert shown == "n1:5432"
    assert "password" not in shown and "pgedge" not in shown


def test_probe_engine_keyword_dsn_substitutes_app_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The keyword path probes with the APP's own DB credentials, not the
    # cluster's internal admin (pgedge, password-less) — the interface DSN
    # user is the cluster admin and probing as-is fails auth.
    from sqlalchemy.engine import URL

    captured: dict = {}

    def _capture(url, **kw):
        captured.update(url=url, kw=kw)
        return object()

    monkeypatch.setattr(ha_status, "create_engine", _capture)
    app_url = URL.create("postgresql", "kubedash", "app-pass", host="h", port=5432, database="kdb")
    ha_status._probe_engine("host=n1 port=5432 dbname=kdb user=pgedge", 3.0, app_url)
    url = captured["url"]
    assert url.host == "n1" and url.port == 5432 and url.database == "kdb"
    assert url.username == "kubedash" and url.password == "app-pass"
    assert captured["kw"]["connect_args"]["connect_timeout"] == 3.0


def test_probe_engine_statement_timeout_bounds_wedged_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A wedged node (connect accepted, query stuck) must be bounded by
    # statement_timeout too — connect_timeout only bounds the TCP phase.
    captured: dict = {}

    def _capture(url, **kw):
        captured.update(kw=kw)
        return object()

    monkeypatch.setattr(ha_status, "create_engine", _capture)
    ha_status._probe_engine(D1, 3.0)
    assert "statement_timeout=3000" in captured["kw"]["connect_args"]["options"]
    ha_status._probe_engine("host=n1 port=5432 dbname=kdb user=pgedge", 2.5)
    assert "statement_timeout=2500" in captured["kw"]["connect_args"]["options"]


def test_probe_node_malformed_dsn_is_a_result(monkeypatch: pytest.MonkeyPatch) -> None:
    # A malformed catalog DSN is cluster state, not app config: the probe
    # degrades to a classified result (never raises a 500 out of the probe).
    def _boom(url, **kw):
        raise ValueError("Invalid IPv6 URL")

    monkeypatch.setattr(ha_status, "create_engine", _boom)
    probe = probe_node("host=n1 port=abc dbname=kdb user=u", "replica-1")
    assert probe.reachable is False
    assert probe.probe_error == "other:ValueError"


def test_probe_worst_lag_wins_across_subscriptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An N-node cluster carries N-1 inbound subscriptions per node — the
    # WORST lag decides the display and the alarm (no last-row-wins).
    conn = _healthy_conn()
    conn._by_sql["FROM spock.lag_tracker"] = [
        ("n3", "n1", 100, None),
        ("n2", "n1", 500, None),
    ]
    monkeypatch.setattr(ha_status, "create_engine", lambda dsn, **kw: _FakeEngine(conn))
    probe = probe_node(D1, "replica-1")
    assert probe.lag_bytes == 500


def test_lock_sql_classid_follows_hashtext_sign() -> None:
    # pg_advisory_lock(bigint) stores the sign-extended upper 32 bits in
    # classid: 4294967295 for negative hashtext, 0 for positive — the filter
    # must follow the hash sign or the lock is invisible for ~half of all
    # replica_ids (verified live against the dev cluster 2026-11-13).
    assert "CASE WHEN hashtext(:rid) < 0" in ha_status._LOCK_SQL
    assert "4294967295::oid ELSE 0::oid" in ha_status._LOCK_SQL


def test_interval_to_seconds_timedelta() -> None:
    from datetime import timedelta

    assert ha_status._interval_to_seconds(timedelta(seconds=90)) == 90.0
    assert ha_status._interval_to_seconds(timedelta(days=1, seconds=5)) == 86405.0
    assert ha_status._interval_to_seconds(timedelta(seconds=90, microseconds=500_000)) == 90.5


def test_build_report_queue_carries_failed_dead_letters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # pgqueue.fail() dead-letters a row to status='failed' after
    # MAX_ATTEMPTS — the terminal count must reach the wire (the queue
    # section shows counts by status).
    catalog = _catalog()
    catalog["queue"]["failed"] = 3
    monkeypatch.setattr(ha_status, "_read_catalog", lambda engine: catalog)
    monkeypatch.setattr(
        ha_status, "probe_node", lambda dsn, rid, timeout_s=3.0, **_kw: node("n1")
    )
    report = build_report(engine=None, admin_client=None)
    assert report["queue"]["failed"] == 3
