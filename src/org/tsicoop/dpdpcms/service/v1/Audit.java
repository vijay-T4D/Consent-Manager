package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Audit Service for managing immutable DPDP compliance logs.
 * Implements Hash Chaining for tamper-evidence as per BSA Section 62.
 */
public class Audit implements Action {

    // Thread-safe in-memory cache for incoming audit events
    private static final Queue<AuditEntry> auditCache = new ConcurrentLinkedQueue<>();
    
    // Tracks the hash of the previous successfully persisted record
    private static String lastKnownHash = null;

    /**
     * DTO to hold audit data in memory before batch writing.
     */
    private static class AuditEntry {
        String userId;
        UUID fiduciaryId;
        String serviceType;
        UUID serviceId;
        String auditAction;
        String contextDetails;
        Timestamp eventtime;

        AuditEntry(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails, Timestamp eventtime) {
            this.userId = userId;
            this.fiduciaryId = fiduciaryId;
            this.serviceType = serviceType;
            this.serviceId = serviceId;
            this.auditAction = auditAction;
            this.contextDetails = contextDetails;
            this.eventtime = eventtime;
        }
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            req.setCharacterEncoding("UTF-8");
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing _func.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "log_event":
                    handleLogRequest(input, res, req);
                    break;
                case "list_audit_logs":
                    handleListLogs(input, res, req);
                    break;
                case "get_audit_log":
                    handleGetLog(input, res, req);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown function: " + func, req.getRequestURI());
                    break;
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    private void handleListLogs(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String search = (String) input.get("search");
        String fidFilter = (String) input.get("fiduciary_id");
        String actFilter = (String) input.get("action_filter");

        if (fidFilter == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "fiduciary_id required.", req.getRequestURI());
            return;
        }

        int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
        int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 50;

        JSONArray outputArray = listAuditLogsFromDb(search, UUID.fromString(fidFilter), actFilter, page, limit);
        OutputProcessor.send(res, 200, outputArray);
    }
   
    private void handleLogRequest(JSONObject input, HttpServletResponse res, HttpServletRequest req) {
        String userId = (String) input.get("user_id");
        String fidStr = (String) input.get("fiduciary_id");
        String serviceType = (String) input.get("service_type");
        String sidStr = (String) input.get("service_id");
        String action = (String) input.get("audit_action");

        Object contextObj = input.get("context_details");
        String details = (contextObj instanceof JSONObject) ? ((JSONObject)contextObj).toJSONString() : (String)contextObj;

        if (userId == null || fidStr == null || serviceType == null || action == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing parameters.", req.getRequestURI());
            return;
        }

        UUID fiduciaryId = UUID.fromString(fidStr);
        UUID serviceId = (sidStr != null && !sidStr.isEmpty()) ? UUID.fromString(sidStr) : null;

        logEventAsync(userId, fiduciaryId, serviceType, serviceId, action, details);

        JSONObject output = new JSONObject();
        output.put("success", true);
        output.put("message", "Audit event buffered in memory cache.");
        OutputProcessor.send(res, 202, output);
    }

    public void logEventAsync(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails) {
        auditCache.add(new AuditEntry(userId, fiduciaryId, serviceType, serviceId, auditAction, contextDetails, Timestamp.from(Instant.now())));
    }

    /**
     * Batch writes all buffered logs and maintains the Hash Chain.
     */
    public synchronized void logEvents() {
        if (auditCache.isEmpty()) return;

        PoolDB pool = null;
        Connection conn = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();

            // Ensure we have the last known hash from the DB if memory is empty (e.g. after restart)
            if (lastKnownHash == null) {
                initLastKnownHash(conn);
            }

            // Build a hasher once per batch; null if TSI_LOOKUP_SALT is not configured.
            LookupHasher hasher = null;
            try {
                hasher = new LookupHasher();
            } catch (IllegalStateException ignored) {
                // Warning logged once per execution if salt missing
            }

            while (!auditCache.isEmpty()) {
                List<AuditEntry> batch = new ArrayList<>();
                AuditEntry entry;
                while ((entry = auditCache.poll()) != null) {
                    batch.add(entry);
                    if (batch.size() >= 500) break;
                }

                if (batch.isEmpty()) break;

                String sql = "INSERT INTO audit_logs (id, fiduciary_id, timestamp, user_id, service_type, service_id, audit_action, context_details, prev_log_hash, current_log_hash) " +
                        "VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, ?, ?, ?)";

                try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                    conn.setAutoCommit(false);

                    for (AuditEntry log : batch) {
                        // Use a local variable for the stored ID to avoid double-hashing if the batch is re-queued on failure
                        String storedUserId = log.userId;
                        if (hasher != null) {
                            try {
                                storedUserId = hasher.hashData(log.userId != null ? log.userId : "");
                            } catch (Exception ignored) {}
                        }

                        String prevHash = lastKnownHash;
                        String currentHash = calculateHash(log, storedUserId, prevHash);

                        pstmt.setObject(1, log.fiduciaryId);
                        pstmt.setTimestamp(2, log.eventtime);
                        pstmt.setString(3, storedUserId);
                        pstmt.setString(4, log.serviceType);
                        pstmt.setObject(5, log.serviceId);
                        pstmt.setString(6, log.auditAction);
                        pstmt.setString(7, log.contextDetails);
                        pstmt.setString(8, prevHash);
                        pstmt.setString(9, currentHash);
                        pstmt.addBatch();

                        lastKnownHash = currentHash;
                    }

                    pstmt.executeBatch();
                    conn.commit();
                } catch (Exception e) {
                    conn.rollback();
                    System.err.println("CRITICAL: Failed to write audit batch: " + e.getMessage());
                    // Re-queue on failure for retry
                    for (AuditEntry failed : batch) auditCache.add(failed);
                    lastKnownHash = null; // Force re-init from DB on next attempt
                    break; // Exit the loop on failure
                }
            }
        } catch (Exception e) {
            System.err.println("Audit Flush Error: " + e.getMessage());
        } finally {
            if (pool != null && conn != null) pool.cleanup(null, null, conn);
        }
    }

    /**
     * Initializes the hash chain state by fetching the most recent record from the database.
     */
    private void initLastKnownHash(Connection conn) throws SQLException {
        String sql = "SELECT current_log_hash FROM audit_logs ORDER BY timestamp DESC LIMIT 1";
        try (Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                lastKnownHash = rs.getString(1);
            } else {
                lastKnownHash = "GENESIS_BLOCK"; // Default starting point for empty table
            }
        }
    }

    /**
     * Calculates SHA-256 hash of (Current Record Data + Previous Record Hash).
     */
    private String calculateHash(AuditEntry entry, String storedUserId, String prevHash) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String dataToHash = prevHash + 
                            entry.fiduciaryId.toString() + 
                            storedUserId + 
                            entry.auditAction + 
                            entry.eventtime.getTime() + 
                            (entry.contextDetails != null ? entry.contextDetails : "");
        
        byte[] hashBytes = digest.digest(dataToHash.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    // --- List and Detail Methods (Unchanged Logic, added hash retrieval) ---

    /**
     * Names of audit_logs partitions that have been detached and archived (see
     * JobManager.checkAndArchiveAuditPartitions, 16_audit_archive_registry.sql). Archived data is
     * never deleted — it's a standalone table with the exact same columns as the live audit_logs,
     * just outside the live partitioned parent. Callers UNION these back in so a search or an
     * evidence-certificate trail (Legal.fetchValidatedTrail) can still span the retention boundary.
     */
    public static List<String> getArchivedTableNames(Connection conn) throws SQLException {
        List<String> names = new ArrayList<>();
        try (PreparedStatement pstmt = conn.prepareStatement(
                "SELECT partition_name FROM audit_log_archive_registry ORDER BY period_start");
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) names.add(rs.getString("partition_name"));
        } catch (SQLException e) {
            // Registry table not present yet (e.g. pre-16_audit_archive_registry.sql deploy) —
            // fail open to "no archives exist" rather than breaking every audit read.
        }
        return names;
    }

    /** A UNION ALL of the live audit_logs table plus every archived partition, so every read path
     *  below transparently searches the full history regardless of the 2-year retention cutoff. */
    // Package-visible (not private) — Consent.getConsentAuditEntryFromDb reuses this to
    // cross-reference a live consent_records row against its tamper-evident audit_logs entry,
    // regardless of whether that entry has since aged into an archived partition.
    static String auditLogsUnionSource(Connection conn) throws SQLException {
        List<String> tables = new ArrayList<>();
        tables.add("audit_logs");
        tables.addAll(getArchivedTableNames(conn));
        if (tables.size() == 1) return "audit_logs"; // common case, no archives yet — skip the UNION
        StringBuilder sb = new StringBuilder("(");
        for (int i = 0; i < tables.size(); i++) {
            if (i > 0) sb.append(" UNION ALL ");
            sb.append("SELECT * FROM ").append(tables.get(i));
        }
        sb.append(") audit_logs_all");
        return sb.toString();
    }

    protected JSONArray listAuditLogsFromDb(String search, UUID fiduciaryId, String action, int page, int limit) throws SQLException {
        JSONArray logs = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            StringBuilder sql = new StringBuilder("SELECT * FROM " + auditLogsUnionSource(conn) + " WHERE fiduciary_id = ?");
            List<Object> params = new ArrayList<>();
            params.add(fiduciaryId);

            if (action != null && !action.isEmpty()) { sql.append(" AND audit_action = ?"); params.add(action); }
            if (search != null && !search.isEmpty()) {
                // Bug fix (2026-08-13): user_id here has always been a one-way SHA-256 hash
                // (LookupHasher, see the INSERT in logEvents() below) — `user_id ILIKE '%term%'` can
                // never match a base64 hash, so this half of the OR has been silently dead since
                // LookupHasher was introduced. Fixed the same way Legal.fetchValidatedTrail already
                // handles this: hash the search term server-side and match it exactly.
                String hashedSearch = null;
                try {
                    hashedSearch = new LookupHasher().hashData(search);
                } catch (Exception ignored) {
                    // TSI_LOOKUP_SALT not set — fall back to a search term that can never match,
                    // same fail-safe-closed behavior as the dead ILIKE it replaces.
                }
                sql.append(" AND (user_id = ? OR context_details ILIKE ?)");
                params.add(hashedSearch != null ? hashedSearch : "");
                params.add("%" + search + "%");
            }

            sql.append(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
            params.add(limit);
            params.add((page - 1) * limit);

            pstmt = conn.prepareStatement(sql.toString());
            for (int i = 0; i < params.size(); i++) pstmt.setObject(i + 1, params.get(i));

            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject log = new JSONObject();
                log.put("id", rs.getObject("id").toString());
                log.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                log.put("user_id", rs.getString("user_id"));
                log.put("service_type", rs.getString("service_type"));
                log.put("audit_action", rs.getString("audit_action"));
                log.put("context_details", rs.getString("context_details"));
                log.put("current_hash", rs.getString("current_log_hash")); // Exposed for auditor verification
                logs.add(log);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return logs;
    }

    private void handleGetLog(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String logIdStr = (String) input.get("id");
        if (logIdStr == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Log ID required.", req.getRequestURI());
            return;
        }

        Optional<JSONObject> logEntry = getAuditLogEntryFromDb(UUID.fromString(logIdStr));
        if (logEntry.isPresent()) OutputProcessor.send(res, 200, logEntry.get());
        else OutputProcessor.errorResponse(res, 404, "Not Found", "Audit log not found.", req.getRequestURI());
    }

    private Optional<JSONObject> getAuditLogEntryFromDb(UUID id) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM " + auditLogsUnionSource(conn) + " WHERE id = ?");
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject log = new JSONObject();
                log.put("id", rs.getObject("id").toString());
                log.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                log.put("user_id", rs.getString("user_id"));
                log.put("service_type", rs.getString("service_type"));
                log.put("audit_action", rs.getString("audit_action"));
                log.put("prev_hash", rs.getString("prev_log_hash"));
                log.put("current_hash", rs.getString("current_log_hash"));

                String details = rs.getString("context_details");
                try { log.put("context_details", new org.json.simple.parser.JSONParser().parse(details)); } 
                catch (Exception e) { log.put("context_details", details); }
                return Optional.of(log);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return Optional.empty();
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res);
    }
}