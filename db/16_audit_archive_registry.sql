-- 16_audit_archive_registry.sql
-- Tracks which yearly audit_logs partitions have been detached and archived
-- (see JobManager.checkAndArchiveAuditPartitions, 15_partition_audit_logs.sql
-- for the partitioning this builds on). Archived partitions are renamed
-- standalone tables in this same database, never dropped — this registry is
-- how Audit.java/Legal.java rediscover them to search across the 2-year
-- retention boundary (e.g. an evidence certificate covering an older case).

CREATE TABLE IF NOT EXISTS audit_log_archive_registry (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    partition_name VARCHAR(100) NOT NULL UNIQUE, -- the archived table's actual name, e.g. audit_logs_y2024_archive
    period_start   TIMESTAMP NOT NULL,
    period_end     TIMESTAMP NOT NULL,
    archived_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    row_count      INTEGER
);
