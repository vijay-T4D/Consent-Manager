package org.tsicoop.dpdpcms.job;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import org.json.simple.JSONObject;
import org.tsicoop.dpdpcms.ces.CESService;
import org.tsicoop.dpdpcms.framework.PoolDB;
import org.tsicoop.dpdpcms.framework.SystemConfig;
import org.tsicoop.dpdpcms.framework.DbEncryption;
import org.tsicoop.dpdpcms.framework.InputProcessor;
import org.tsicoop.dpdpcms.service.v1.Audit;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.sql.*;
import java.sql.Date;
import java.time.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * JobManager orchestrates background tasks like CES and Bulk Exports.
 * It uses a single executor thread to process jobs sequentially from the 'jobs' table.
 */
@WebListener
public class JobManager implements ServletContextListener {

    private ScheduledExecutorService scheduler;
    private volatile boolean running = true;
    private static final String EXPORT_DIR = System.getenv("TSI_EXPORT_PATH") != null
            ? System.getenv("TSI_EXPORT_PATH")
            : "/var/lib/tsi/exports/";
    private static final int BATCH_SIZE = 10; // Fixed number of principals to fetch at a time
    private static final String NIGHTLY_CES_JOB_NAME = "CES_NIGHTLY_FULL";
    // Policy number, not a secret — default-with-override rather than DbEncryption's fail-fast
    // pattern. How long audit_logs history stays in the live partitioned table before its
    // partition gets detached (never deleted) to a standalone "_archive" table. See
    // 15_partition_audit_logs.sql / 16_audit_archive_registry.sql for the schema this operates on.
    private static final int AUDIT_RETENTION_MONTHS = System.getenv("AUDIT_RETENTION_MONTHS") != null
            ? Integer.parseInt(System.getenv("AUDIT_RETENTION_MONTHS"))
            : 24;
    private static final java.util.regex.Pattern AUDIT_PARTITION_NAME = java.util.regex.Pattern.compile("^audit_logs_y(\\d{4})$");

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        System.out.println("TSI DPDP CMS: Starting Background Job Manager...");

        // Ensure export directory exists
        File dir = new File(EXPORT_DIR);
        if (!dir.exists()) dir.mkdirs();

        // Single thread is enough to prevent concurrent DB lock contention
        scheduler = Executors.newSingleThreadScheduledExecutor();

        // Schedule the polling task every 2 minutes
        scheduler.scheduleAtFixedRate(this::checkAndExecuteJobs, 1, 2, TimeUnit.MINUTES);

        // Audit-log partition maintenance — cheap no-op most days, only acts once a year's
        // partition actually crosses the retention boundary or a new year needs a partition ahead
        // of the Dec 31 -> Jan 1 rollover.
        scheduler.scheduleAtFixedRate(this::checkAndArchiveAuditPartitions, 1, 24, TimeUnit.HOURS);
    }

    /**
     * Audit-log retention: ensures the partition for next year already exists (so inserts never
     * fail across a year rollover), then detaches — never deletes — any yearly partition whose
     * entire range is older than AUDIT_RETENTION_MONTHS, renaming it to a standalone
     * "<name>_archive" table and recording it in audit_log_archive_registry. Archived data stays
     * fully intact and queryable; Audit.getArchivedTableNames() is how Audit.java/Legal.java find
     * it again for searches/evidence certificates that span the retention boundary.
     */
    private void checkAndArchiveAuditPartitions() {
        PoolDB pool = null;
        Connection conn = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();

            int nextYear = LocalDate.now().getYear() + 1;
            ensureAuditYearPartitionExists(conn, nextYear);

            LocalDate cutoff = LocalDate.now().minusMonths(AUDIT_RETENTION_MONTHS);

            List<String> currentPartitions = new ArrayList<>();
            try (PreparedStatement pstmt = conn.prepareStatement(
                    "SELECT c.relname FROM pg_inherits i " +
                            "JOIN pg_class c ON i.inhrelid = c.oid " +
                            "JOIN pg_class p ON i.inhparent = p.oid " +
                            "WHERE p.relname = 'audit_logs'");
                 ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) currentPartitions.add(rs.getString("relname"));
            }

            for (String partitionName : currentPartitions) {
                java.util.regex.Matcher m = AUDIT_PARTITION_NAME.matcher(partitionName);
                if (!m.matches()) continue; // already archived (renamed with _archive suffix) or not ours
                int year = Integer.parseInt(m.group(1));
                LocalDate periodStart = LocalDate.of(year, 1, 1);
                LocalDate periodEnd = LocalDate.of(year + 1, 1, 1);
                if (!periodEnd.isAfter(cutoff)) { // the whole partition's range is before the cutoff
                    archiveAuditPartition(conn, partitionName, periodStart, periodEnd);
                }
            }
        } catch (Exception e) {
            System.err.println("[JobManager] Audit partition maintenance failed: " + e.getMessage());
        } finally {
            if (pool != null) try { pool.cleanup(null, null, conn); } catch (Exception ignored) {}
        }
    }

    private void ensureAuditYearPartitionExists(Connection conn, int year) throws SQLException {
        String name = "audit_logs_y" + year;
        try (PreparedStatement check = conn.prepareStatement(
                "SELECT 1 FROM information_schema.tables WHERE table_name = ?")) {
            check.setString(1, name);
            try (ResultSet rs = check.executeQuery()) {
                if (rs.next()) return; // already exists
            }
        }
        String from = year + "-01-01";
        String to = (year + 1) + "-01-01";
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE " + name + " PARTITION OF audit_logs FOR VALUES FROM ('" + from + "') TO ('" + to + "')");
        }
        System.out.println("[JobManager] Created audit_logs partition " + name + " ahead of the year rollover.");
    }

    /**
     * DETACH (never DELETE) + rename + register. The renamed table falls out of the
     * AUDIT_PARTITION_NAME pattern so it's never reconsidered by this method again.
     */
    private void archiveAuditPartition(Connection conn, String partitionName, LocalDate periodStart, LocalDate periodEnd) throws SQLException {
        String archivedName = partitionName + "_archive";

        try (Statement stmt = conn.createStatement()) {
            stmt.execute("ALTER TABLE audit_logs DETACH PARTITION " + partitionName);
            stmt.execute("ALTER TABLE " + partitionName + " RENAME TO " + archivedName);
        }

        int rowCount = 0;
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT count(*) FROM " + archivedName)) {
            if (rs.next()) rowCount = rs.getInt(1);
        }

        try (PreparedStatement ins = conn.prepareStatement(
                "INSERT INTO audit_log_archive_registry (partition_name, period_start, period_end, row_count) VALUES (?, ?, ?, ?)")) {
            ins.setString(1, archivedName);
            ins.setObject(2, java.sql.Timestamp.valueOf(periodStart.atStartOfDay()));
            ins.setObject(3, java.sql.Timestamp.valueOf(periodEnd.atStartOfDay()));
            ins.setInt(4, rowCount);
            ins.executeUpdate();
        }

        System.out.println("[JobManager] Archived audit_logs partition " + partitionName + " -> " + archivedName + " (" + rowCount + " rows, never deleted).");
    }

    private void checkAndExecuteJobs() {
        try {
            scheduleNightlyFullRun();
            processNextPendingJob();
            new Audit().logEvents();
        } catch (Exception e) {
            System.err.println("[JobManager] Periodic run failed: " + e.getMessage());
        }
    }



    /**
     * Atomically claims today's nightly run via job_schedule_state so that
     * concurrent app instances don't double-schedule, and so a run missed
     * during downtime is caught up on the next poll rather than skipped
     * (no longer gated to the 00:00 hour).
     */
    private boolean claimNightlyRun(Connection conn, LocalDate today) throws SQLException {
        String claimSql = "INSERT INTO job_schedule_state (job_name, last_run_date) VALUES (?, ?) " +
                "ON CONFLICT (job_name) DO UPDATE SET last_run_date = EXCLUDED.last_run_date " +
                "WHERE job_schedule_state.last_run_date < EXCLUDED.last_run_date " +
                "RETURNING last_run_date";
        try (PreparedStatement pstmt = conn.prepareStatement(claimSql)) {
            pstmt.setString(1, NIGHTLY_CES_JOB_NAME);
            pstmt.setObject(2, today);
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Checks if today's nightly run hasn't been claimed yet, and if so,
     * fetches all active fiduciaries and inserts a CES FULL job for each.
     */
    private void scheduleNightlyFullRun() {
        LocalDate today = LocalDate.now();

        PoolDB pool = null;
        Connection conn = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();

            if (!claimNightlyRun(conn, today)) {
                return; // Already claimed by this or another instance for today
            }

            System.out.println("[JobManager] Initiating Nightly Full CES Run for: " + today);

            // 1. Fetch all active Fiduciary IDs
            List<UUID> activeFiduciaries = new ArrayList<>();
            // Assuming 'status' column exists or similar active check, defaulting to all for now
            String fidSql = "SELECT id FROM fiduciaries where status='ACTIVE'";
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(fidSql)) {
                while (rs.next()) {
                    activeFiduciaries.add((UUID) rs.getObject("id"));
                }
            }

            if (activeFiduciaries.isEmpty()) {
                System.out.println("[JobManager] No active fiduciaries found. Skipping scheduling.");
                return;
            }

            // 2. Insert CES Job for each Fiduciary
            String insertSql = "INSERT INTO jobs (id, job_type, subtype, status, fiduciary_id, created_at) VALUES (?, 'CES', 'FULL', 'PENDING', ?, NOW())";
            int scheduledCount = 0;

            try (PreparedStatement pstmt = conn.prepareStatement(insertSql)) {
                for (UUID fid : activeFiduciaries) {
                    pstmt.setObject(1, UUID.randomUUID());
                    pstmt.setObject(2, fid);
                    pstmt.addBatch();
                    scheduledCount++;
                }
                pstmt.executeBatch();
            }

            System.out.println("[JobManager] Nightly jobs successfully queued for " + scheduledCount + " fiduciaries.");

        } catch (SQLException e) {
            System.err.println("[JobManager] Failed to schedule nightly job batch: " + e.getMessage());
        } finally {
            if (pool != null && conn != null) pool.cleanup(null, null, conn);
        }
    }

    private void processNextPendingJob() {
        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        UUID jobId = null;
        UUID fiduciaryId = null;
        String type = null;
        String subtype = null;
        Date startDate = null;
        Date endDate = null;
        String inputPayload = null;
        boolean pending = false;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();

            // Fetch the oldest pending job
            String selectSql = "SELECT * FROM jobs WHERE status = 'PENDING' ORDER BY created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED";
            pstmt = conn.prepareStatement(selectSql);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                jobId = (UUID) rs.getObject("id");
                fiduciaryId = (UUID) rs.getObject("fiduciary_id");
                type = rs.getString("job_type");
                subtype = rs.getString("subtype");
                startDate = rs.getDate("start_date");
                endDate = rs.getDate("end_date");
                inputPayload = rs.getString("input_payload");
                pending = true;
            }
        } catch (Exception e) {
            System.err.println("[JobManager] DB Polling error: " + e.getMessage());
        } finally {
            if (pool != null) pool.cleanup(rs, pstmt, conn);
        }

        if(pending) {
            updateJobStatus(jobId, "RUNNING", null);

            try {
                if ("CES".equalsIgnoreCase(type)) {
                    executeCESJob(fiduciaryId, subtype);
                } else if ("EXPORT".equalsIgnoreCase(type)) {
                    executeExportJob(fiduciaryId, jobId, subtype, startDate, endDate);
                } else if ("BREACH_NOTIFY".equalsIgnoreCase(type)) {
                    executeBreachNotifyJob(fiduciaryId, UUID.fromString(subtype), inputPayload);
                }
                updateJobStatus(jobId, "COMPLETED", EXPORT_DIR + jobId + ".csv");
            } catch (Exception jobEx) {
                updateJobStatus(jobId, "FAILED", jobEx.getMessage());
            }
        }
    }

    /**
     * Parses an uploaded single-column CSV of affected principal IDs and notifies each
     * one, recording them against the breach and reconciling the affected-principal
     * count. Runs off the request thread so a large CSV can't time out report_breach.
     */
    private void executeBreachNotifyJob(UUID fiduciaryId, UUID breachId, String csvPayload) throws SQLException {
        if (csvPayload == null || csvPayload.trim().isEmpty()) return;

        List<String> userIds = new ArrayList<>();
        for (String line : csvPayload.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) userIds.add(trimmed);
        }
        if (userIds.isEmpty()) return;

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        String notificationType = null;

        try {
            conn = pool.getConnection();

            pstmt = conn.prepareStatement("SELECT notification_type FROM breach_incidents WHERE id = ?");
            pstmt.setObject(1, breachId);
            rs = pstmt.executeQuery();
            if (rs.next()) notificationType = rs.getString("notification_type");
            rs.close();
            pstmt.close();
            if (notificationType == null) notificationType = "BREACH_NOTIFICATION";

            pstmt = conn.prepareStatement(
                    "INSERT INTO breach_affected_principals (breach_id, user_id_enc, user_id_hmac) VALUES (?, " +
                            DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ") " +
                            "ON CONFLICT (breach_id, user_id_hmac) DO NOTHING");
            for (String userId : userIds) {
                pstmt.setObject(1, breachId);
                int idx = DbEncryption.bindEncrypt(pstmt, 2, userId);
                DbEncryption.bindHmac(pstmt, idx, userId);
                pstmt.addBatch();
            }
            pstmt.executeBatch();
            pstmt.close();

            pstmt = conn.prepareStatement(
                    "UPDATE breach_incidents SET affected_principal_count = " +
                            "(SELECT COUNT(*) FROM breach_affected_principals WHERE breach_id = ?), last_updated_at = NOW() WHERE id = ?");
            pstmt.setObject(1, breachId);
            pstmt.setObject(2, breachId);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        CESService cesService = new CESService();
        for (String userId : userIds) {
            try {
                cesService.insertNotification("PRINCIPAL", userId, fiduciaryId.toString(), notificationType);
            } catch (SQLException e) {
                e.printStackTrace(); // One failed notification must not fail the rest of the batch
            }
        }

        new Audit().logEventAsync("SYSTEM", fiduciaryId, org.tsicoop.dpdpcms.util.Constants.SERVICE_TYPE_SYSTEM, null,
                "BREACH_CSV_NOTIFIED", "breach_id=" + breachId + " principals=" + userIds.size());
    }

    private void executeCESJob(UUID fiduciaryId, String target) {
        System.out.println("[JobManager] Executing Compliance Enforcement Run at "+ LocalDateTime.now()+" Target:"+target+" Pool Status:"+PoolDB.getPoolStatus());
        this.enforce(fiduciaryId, target);
    }

    public void enforce(UUID fiduciaryId, String target) {
        JSONObject principal = null;
        CESService cesService = null;
        try {
            cesService = new CESService();
            // 1. Iterate through all active data principals in batches
            int offset = 0;
            boolean hasMore = true;

            while (hasMore) {
                List<JSONObject> principals = cesService.getPrincipalsBatch(fiduciaryId, target, BATCH_SIZE, offset);

                if (principals.isEmpty()) {
                    hasMore = false;
                } else {
                    Iterator<JSONObject> it = principals.iterator();
                    while(it.hasNext()){
                        principal = (JSONObject) it.next();
                        //System.out.println(principal);
                        // Identify and execute necessary purge requests
                        cesService.processPrincipal(   (String) principal.get("fiduciary_id"),
                                (String) principal.get("user_id"),
                                (Timestamp) principal.get("last_ces_run"),
                                (String) principal.get("consent_mechanism"));
                    }
                    offset += BATCH_SIZE;
                    //System.out.println("Processed batch ending at offset: " + offset);
                }
            }
            //System.out.println("CES execution completed successfully at " + LocalDateTime.now());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Compliance Batch failed due to Database Error: " + e.getMessage(), e);
        }
    }

    /**
     * Returns a java.sql.Date representing the next day of the given date.
     * Uses the local time zone via Calendar.
     * * @param currentDate The starting java.sql.Date
     * @return java.sql.Date representing (currentDate + 1 day)
     */

    public static java.sql.Date getNextDate(java.sql.Date currentDate) {
        if (currentDate == null) {
            return null;
        }

        // Use Calendar to handle month/year transitions (e.g., Dec 31 to Jan 1)
        java.util.Calendar cal = java.util.Calendar.getInstance();
        cal.setTime(currentDate);
        cal.add(java.util.Calendar.DATE, 1);

        return new java.sql.Date(cal.getTimeInMillis());
    }

    private void executeExportJob(UUID fiduciaryId, UUID jobId, String subtype, Date start, Date end) throws Exception {
        System.out.println("[JobManager] Executing Export: " + subtype+"-"+start+"-"+end);
        String sql = "";
        // Number of DbEncryption.decryptCol(...) fragments used in the SQL below for this subtype —
        // each one consumes one leading '?' bind slot (the decrypt key) that must be bound before
        // fiduciary_id/start/end. This is the DPO's authorised bulk-export path (see
        // executeExportJob's caller for the operator-role gate) — it deliberately emits plaintext,
        // unlike every console/API read path elsewhere, which masks by default.
        int decryptKeyCount = 0;

        // Define SQL based on subtype
        switch (subtype.toUpperCase()) {
            case "CONSENT":
                sql = "SELECT " + DbEncryption.decryptCol("user_id_enc") + " as principal, policy_id, jurisdiction, language_selected as language, consent_mechanism as action, " + DbEncryption.decryptCol("ip_address_enc") + " as ip_address, user_agent, data_point_consents as consents, is_active_consent as active, created_at, last_updated_at, verification_log_id FROM consent_records WHERE fiduciary_id=? AND timestamp BETWEEN ? AND ?";
                decryptKeyCount = 2;
                break;
            case "PRINCIPAL":
                sql = "SELECT " + DbEncryption.decryptCol("user_id_enc") + " as principal, created_at, last_consent_mechanism as last_action, last_ces_run FROM data_principal WHERE fiduciary_id=? AND created_at BETWEEN ? AND ?";
                decryptKeyCount = 1;
                break;
            case "COMPLIANCE":
                sql = "SELECT " + DbEncryption.decryptCol("pr.user_id_enc") + " as user_id, pr.purpose_id, COALESCE(a.name, 'No Linked Processor') AS name, pr.trigger_event, pr.status, pr.initiated_at, pr.details FROM purge_requests pr LEFT JOIN apps a ON pr.app_id = a.id WHERE pr.fiduciary_id=? AND pr.initiated_at BETWEEN ? AND ?";
                decryptKeyCount = 1;
                break;
            case "GRIEVANCE":
                sql = "SELECT " + DbEncryption.decryptCol("user_id_enc") + " as principal, type, subject, description, submission_timestamp, status, resolution_details FROM grievances WHERE fiduciary_id=? AND submission_timestamp BETWEEN ? AND ?";
                decryptKeyCount = 1;
                break;
            case "AUDIT":
                // audit_logs.user_id is a one-way hash (LookupHasher), not pgcrypto-encrypted —
                // never touched by this feature (see 13_principal_pii_encryption.sql header). No
                // decrypt fragment applies here; exported as-is, same as every other audit_logs read.
                sql = "SELECT timestamp, user_id as principal, audit_action as action, context_details FROM audit_logs WHERE fiduciary_id=? AND timestamp BETWEEN ? AND ?";
                decryptKeyCount = 0;
                break;
            case "PARENT_CONSENT":
                sql = "SELECT id, verified_at, " + DbEncryption.decryptCol("child_principal_id_enc") + " as principal, " + DbEncryption.decryptCol("guardian_principal_id_enc") + " as guardian, verification_mechanism, provider_name, " + DbEncryption.decryptCol("verification_ref_id_enc") + " as verification_ref_id, " + DbEncryption.decryptCol("proof_metadata_enc") + " as proof_metadata FROM parental_verification_logs WHERE fiduciary_id=? AND verified_at BETWEEN ? AND ?";
                decryptKeyCount = 4;
                break;
            case "ADMIN_LOGS":
                sql = "SELECT timestamp, user_id as user, audit_action as action, context_details as details FROM audit_logs WHERE service_type='ADMIN_CONSOLE' AND fiduciary_id=? AND timestamp BETWEEN ? AND ? ORDER BY timestamp asc";
                decryptKeyCount = 0;
                break;
            case "ROPA_REPORT":
                sql = "SELECT r.activity_name, r.source_purpose_id as purpose_id, r.purpose, r.legal_basis, " +
                      "cp.id as policy_id, " +
                      "cr.data_principal, cr.consent_status_general as consent_status, " +
                      "cr.consent_mechanism, " +
                      "cr.timestamp as consent_timestamp, cr.jurisdiction, cr.language_selected " +
                      "FROM ropa_entries r " +
                      "JOIN consent_policies cp ON r.linked_policy_ids @> jsonb_build_array(cp.id) " +
                      "JOIN LATERAL (" +
                      "  SELECT DISTINCT ON (cri.user_id_hmac) " + DbEncryption.decryptCol("cri.user_id_enc") + " as data_principal, cri.consent_status_general, cri.consent_mechanism, " +
                      "         cri.timestamp, cri.jurisdiction, cri.language_selected " +
                      "  FROM consent_records cri, jsonb_array_elements(cri.data_point_consents) AS dp " +
                      "  WHERE cri.policy_id = cp.id AND cri.fiduciary_id = r.fiduciary_id " +
                      "    AND dp->>'data_point_id' = r.source_purpose_id " +
                      "  ORDER BY cri.user_id_hmac, cri.created_at DESC" +
                      ") cr ON TRUE " +
                      "WHERE r.fiduciary_id = ? AND r.status = 'active' " +
                      "AND cr.timestamp BETWEEN ? AND ? " +
                      "ORDER BY r.id, cr.timestamp DESC";
                decryptKeyCount = 1; // the decrypt fragment sits inside the LATERAL subquery, evaluated once per outer row — still just 1 '?' in the SQL text
                break;
            default:
                throw new Exception("Unknown Export Subtype: " + subtype);
        }
        File outFile = new File(EXPORT_DIR + jobId + ".csv");
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PrintWriter pw = null;
        ResultSetMetaData meta = null;
        end =  getNextDate(end); // to make sure that the current

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            int idx = 1;
            for (int k = 0; k < decryptKeyCount; k++) {
                idx = DbEncryption.bindKey(pstmt, idx);
            }
            pstmt.setObject(idx++, fiduciaryId);
            pstmt.setTimestamp(idx++, new Timestamp(start.getTime()));
            pstmt.setTimestamp(idx++, new Timestamp(end.getTime()));

            rs = pstmt.executeQuery();
            pw = new PrintWriter(new FileWriter(outFile));

            meta = rs.getMetaData();
            int cols = meta.getColumnCount();

            // Write Header
            for (int i = 1; i <= cols; i++) {
                pw.print(meta.getColumnName(i) + (i < cols ? "," : ""));
            }
            pw.println();

            // Write Rows
            while (rs.next()) {
                for (int i = 1; i <= cols; i++) {
                    String val = rs.getString(i);
                    pw.print((val == null ? "" : "\"" + val.replace("\"", "\"\"") + "\"") + (i < cols ? "," : ""));
                }
                pw.println();
            }
        }catch(Exception e) {
            e.printStackTrace();
        }finally
        {
            pool.cleanup(rs,pstmt,conn);
            if(pw!=null)pw.close();
        }
        System.out.println(outFile.getAbsolutePath()+" created");
    }


    private void updateJobStatus(UUID jobId, String status, String info) {
        Connection conn = null;
        PoolDB pool = null;
        PreparedStatement pstmt = null;
        String sql = "UPDATE jobs SET status = ?, started_at = CASE WHEN ? = 'RUNNING' THEN NOW() ELSE started_at END, " +
                "completed_at = CASE WHEN ? IN ('COMPLETED', 'FAILED') THEN NOW() ELSE completed_at END, ";

        if ("FAILED".equals(status)) {
            sql += "error_message = ? WHERE id = ?";
        } else {
            sql += "output_file_path = ? WHERE id = ?";
        }

        try{
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, status);
            pstmt.setString(2, status);
            pstmt.setString(3, status);
            pstmt.setString(4, info);
            pstmt.setObject(5, jobId);
            pstmt.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }finally{
            pool.cleanup(null,pstmt,conn);
        }

    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        running = false;
        new Audit().logEvents();
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }
}
