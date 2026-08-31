-- 15_partition_audit_logs.sql
-- Converts audit_logs to native Postgres range partitioning on `timestamp`,
-- one partition per calendar year, as prep for the archival job added in the
-- same change (see JobManager.checkAndArchiveAuditPartitions and
-- 16_audit_archive_registry.sql).
--
-- WHY: audit_logs is pure append-only today — every login, consent event, PII
-- reveal, purge event, etc. writes a row and nothing ever removes one. At
-- current scale (196 rows / 320KB as of 2026-08-13) this is not an urgent
-- problem, but the table has no bound on growth. The fix is a 2-year
-- retention policy: keep the current + prior ~2 years of audit history in
-- the live table, archive anything older. Yearly partitions (not monthly)
-- are the right grain for that: once the archive job actually runs, the live
-- table holds only ~2-3 partitions at any time, forever — partition count
-- does not grow unboundedly, it stays roughly constant.
--
-- WHY NOT DELETE: audit_logs.current_log_hash chains every row to the one
-- immediately before it (Audit.calculateHash(), a tamper-evident hash chain
-- per BSA S.62), and Legal.fetchValidatedTrail() walks that chain per-subject
-- to generate evidence certificates. Deleting old rows would break
-- verifiability of everything after the deletion point. So old partitions
-- are DETACHED and renamed, never dropped — they remain fully intact,
-- queryable standalone tables; see 16_audit_archive_registry.sql for how
-- Audit.java/Legal.java find them again for cross-boundary searches.
--
-- SAFETY: this is a live-data migration (thankfully still tiny: two-digit-ms
-- COPY). The original table is renamed to audit_logs_old and kept, NOT
-- dropped, as a one-deploy-cycle safety net — drop it manually only after
-- confirming row counts match and the hash chain still verifies (see the
-- verification queries at the bottom of this file).
--
-- Postgres requires a partitioned table's primary key to include the
-- partition key column, so the PK becomes composite (id, timestamp) instead
-- of just (id). Confirmed safe: no other table has a foreign key referencing
-- audit_logs.id (evidence_certificates stores a JSONB snapshot, not an FK).

BEGIN;

ALTER TABLE audit_logs RENAME TO audit_logs_old;

-- Renaming the table does NOT rename its indexes — they keep their original names and would
-- collide with the same-named indexes created below on the new partitioned table. Rename them
-- out of the way; they get dropped automatically whenever audit_logs_old is eventually dropped.
ALTER INDEX audit_logs_pkey RENAME TO audit_logs_old_pkey;
ALTER INDEX idx_audit_fiduciary_logs RENAME TO idx_audit_fiduciary_logs_old;
ALTER INDEX idx_audit_hash_traversal RENAME TO idx_audit_hash_traversal_old;
ALTER INDEX idx_audit_logs_fid_action_timestamp RENAME TO idx_audit_logs_fid_action_timestamp_old;
ALTER INDEX idx_audit_logs_service_timestamp RENAME TO idx_audit_logs_service_timestamp_old;
ALTER INDEX idx_audit_logs_user_timestamp RENAME TO idx_audit_logs_user_timestamp_old;
ALTER INDEX idx_audit_principal_trace RENAME TO idx_audit_principal_trace_old;

CREATE TABLE audit_logs (
    id                UUID NOT NULL DEFAULT uuid_generate_v4(),
    fiduciary_id      UUID,
    timestamp         TIMESTAMP NOT NULL,
    user_id           VARCHAR(255) NOT NULL,
    service_type      VARCHAR(100) NOT NULL,
    service_id        UUID,
    audit_action      VARCHAR(100) NOT NULL,
    context_details   TEXT,
    prev_log_hash     VARCHAR(64),
    current_log_hash  VARCHAR(64),
    digital_signature TEXT,
    system_metadata   JSONB,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- One partition per calendar year, from the earliest existing row's year
-- through next year (buffer so inserts never fail across a Dec 31 -> Jan 1
-- rollover before the archival job's pre-create step has run). Adjust the
-- start year here if this is ever re-run against a dataset older than 2026.
CREATE TABLE audit_logs_y2025 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
CREATE TABLE audit_logs_y2026 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
CREATE TABLE audit_logs_y2027 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-01-01') TO ('2028-01-01');

-- Recreate the indexes that existed on the plain table — these propagate
-- automatically to every current and future partition.
CREATE INDEX idx_audit_fiduciary_logs ON audit_logs (fiduciary_id, "timestamp" DESC);
CREATE INDEX idx_audit_hash_traversal ON audit_logs (current_log_hash);
CREATE INDEX idx_audit_logs_fid_action_timestamp ON audit_logs (fiduciary_id, audit_action, "timestamp" DESC);
CREATE INDEX idx_audit_logs_service_timestamp ON audit_logs (service_type, "timestamp" DESC);
CREATE INDEX idx_audit_logs_user_timestamp ON audit_logs (user_id, "timestamp" DESC);
CREATE INDEX idx_audit_principal_trace ON audit_logs (user_id, "timestamp" DESC);

-- Migrate existing data across.
INSERT INTO audit_logs (id, fiduciary_id, "timestamp", user_id, service_type, service_id,
                         audit_action, context_details, prev_log_hash, current_log_hash,
                         digital_signature, system_metadata)
SELECT id, fiduciary_id, "timestamp", user_id, service_type, service_id,
       audit_action, context_details, prev_log_hash, current_log_hash,
       digital_signature, system_metadata
FROM audit_logs_old;

COMMIT;

-- ============================================================
-- Verification (run manually before dropping audit_logs_old)
-- ============================================================
-- Row counts must match:
--   SELECT (SELECT count(*) FROM audit_logs) AS new_count,
--          (SELECT count(*) FROM audit_logs_old) AS old_count;
--
-- Confirm partition routing works for new inserts:
--   -- (after app restart) SELECT tableoid::regclass, id, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 1;
--
-- Confirm the hash chain still reads back identically (spot check a few rows):
--   SELECT id, prev_log_hash, current_log_hash FROM audit_logs ORDER BY timestamp DESC LIMIT 5;
--   -- compare against the same query run on audit_logs_old before cutover
--
-- Once satisfied, drop the safety copy manually:
--   DROP TABLE audit_logs_old;
