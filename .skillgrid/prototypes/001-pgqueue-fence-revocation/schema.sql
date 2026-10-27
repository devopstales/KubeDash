-- Prototype 001: Postgres queue + fence + revocation SQL validation.
-- Throwaway schema for the experiment (not the real migration).
\set ON_ERROR_STOP on

DROP TABLE IF EXISTS tasks CASCADE;
DROP TABLE IF EXISTS revoked_jtis CASCADE;
DROP TABLE IF EXISTS leader_lease CASCADE;

-- ADR-0029: the task queue
CREATE TABLE tasks (
  id           BIGSERIAL PRIMARY KEY,
  path         TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending',
  attempts     INT  NOT NULL DEFAULT 0,
  enqueued_at  timestamptz NOT NULL DEFAULT now(),
  locked_at    timestamptz,
  locked_by    TEXT,
  available_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tasks_pending_idx ON tasks (enqueued_at)
  WHERE status = 'pending';

-- ADR-0030: the session-revocation deny-list
CREATE TABLE revoked_jtis (
  jti        UUID PRIMARY KEY,
  expires_at timestamptz NOT NULL
);
-- NOTE (finding F1): a PARTIAL index `WHERE expires_at > now()` is INVALID in
-- Postgres — `now()` is STABLE, and index predicates require IMMUTABLE. The
-- table is small (bounded by the leader reaper deleting expired rows), so a
-- plain index on expires_at suffices for the reaper's scan. The hot-path
-- lookup is a PK hit (jti) and does not use this index.
CREATE INDEX revoked_jtis_expires_idx ON revoked_jtis (expires_at);

-- ADR-0008/0031: the leader lease, + the strict fence column
CREATE TABLE leader_lease (
  id           INTEGER PRIMARY KEY,
  replica_id   TEXT NOT NULL,
  token        UUID NOT NULL,
  acquired_at  timestamptz NOT NULL,
  heartbeat_at timestamptz NOT NULL,
  fence        INTEGER NOT NULL DEFAULT 0
);
-- the single lease row, seeded unowned (fence 0 = no current leader)
INSERT INTO leader_lease (id, replica_id, token, acquired_at, heartbeat_at, fence)
VALUES (1, '', gen_random_uuid(), now(), now(), 0);
