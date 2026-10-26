#!/usr/bin/env bash
# KubeDash multi-instance backend driver — leader-election test helper.
#
# Spawns two leader-role replicas (distinct KUBEDASH_REPLICA_ID, ports 8081/8082)
# so the advisory-lock election in app/core/leader.py can be observed live:
#   - one takes the lock at startup, the other polls every 1 s as a follower
#   - kill the leader -> the follower promotes within ~10 s (stale_seconds)
#
# State lives under <repo>/tmp (gitignored) so commands are idempotent:
#   up        kill any previous run, then start both instances (backgrounded)
#   down      stop both instances
#   logs      tail both instance logs
#   failover  kill the CURRENT LEADER (SIGKILL — hard-kill path: no advisory
#             lock release, no lease-row deletion, so the follower promotes
#             purely via the 10 s stale_seconds threshold)
#
# Invoked by the root Taskfile:  task multi-up / multi-down / multi-logs
set -euo pipefail

# Repo root: this file lives in dev/scripts/, the Taskfile resolves this
# script via {{.TASKFILE_DIR}}/dev/scripts/mux.sh. Derive the root from the
# script's own path so the driver works even if moved.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE="$ROOT/tmp"
PY="$ROOT/backend/.venv/bin/python"

start() {
  mkdir -p "$STATE"
  pkill -f "kubedash-mux instance-" 2>/dev/null || true
  sleep 0.5

  local i
  for i in 1 2; do
    # "kubedash-mux instance-N" is the pkill pattern; the env assignment makes
    # it visible in the python process's argv (env prefix + command string).
    (
      cd "$ROOT/backend"
      exec env "kubedash-mux instance-$i" \
        "KUBEDASH_ROLE=leader" \
        "KUBEDASH_REPLICA_ID=instance-$i" \
        "KUBEDASH_COOKIE_SECURE=false" \
        "FLASK_RUN_PORT=$((8080 + i))" \
        "$PY" wsgi.py \
        >> "$STATE/backend-instance-$i.log" 2>&1
    ) &
    echo "$!" > "$STATE/backend-instance-$i.pid"
  done

  sleep 1
  echo "started 2 instances:"
  echo "  instance-1  :8081  (KUBEDASH_REPLICA_ID=instance-1)  log: tmp/backend-instance-1.log"
  echo "  instance-2  :8082  (KUBEDASH_REPLICA_ID=instance-2)  log: tmp/backend-instance-2.log"
  echo
  echo "watch leadership:   task multi-logs"
  echo "observe the lease:  task db-shell   (SELECT replica_id, heartbeat_at FROM leader_lease)"
  echo "failover test:      kill one instance, the other promotes within ~10 s"
}

stop() {
  if pkill -f "kubedash-mux instance-"; then
    sleep 0.5
    echo "stopped multi-instance backends"
  else
    echo "no running multi-instance backends"
  fi
}

logs() {
  local missing=0
  local i
  for i in 1 2; do
    [ -f "$STATE/backend-instance-$i.log" ] || missing=1
  done
  if [ "$missing" -eq 1 ]; then
    echo "no logs yet — run: task multi-up" >&2
    exit 1
  fi
  tail -f "$STATE/backend-instance-1.log" "$STATE/backend-instance-2.log"
}

# Find the leader from the logs: the last instance to log "leader-gated RQ
# worker started" holds the lock. A clean kill (SIGTERM) never reaches a
# Python SIGTERM handler here — wsgi.py installs none, so the CPython default
# terminates the process and _release() never runs; the lock is dropped by
# connection close and the lease row goes stale. SIGKILL makes the same path
# explicit and unambiguous.
failover() {
  local leader=""
  local i
  for i in 2 1; do
    if [ -f "$STATE/backend-instance-$i.log" ] && \
       grep -q "leader-gated RQ worker started" "$STATE/backend-instance-$i.log"; then
      leader=$i
      break
    fi
  done
  if [ -z "$leader" ]; then
    echo "no leader found in logs — run: task multi-up (election may still be settling)" >&2
    exit 1
  fi

  local pidfile="$STATE/backend-instance-$leader.pid"
  local pid
  if [ -f "$pidfile" ]; then
    pid="$(cat "$pidfile")"
  else
    pid="$(pgrep -f "kubedash-mux instance-$leader" | head -1)"
  fi
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    echo "leader instance-$leader is not running" >&2
    exit 1
  fi

  echo "leader is instance-$leader (pid $pid) — sending SIGKILL"
  kill -9 "$pid"
  rm -f "$pidfile"
  echo "killed. The follower promotes within ~10 s (stale_seconds)."
  echo "watch: task multi-logs   |   lease row: task db-shell (SELECT * FROM leader_lease)"
}

case "${1:-}" in
  up) start ;;
  down) stop ;;
  logs) logs ;;
  failover) failover ;;
  *) echo "usage: mux.sh up|down|logs|failover" >&2; exit 2 ;;
esac
