package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.tsicoop.dpdpcms.util.Constants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Single, shared "reveal full PII" endpoint for every console page that
 * displays a masked Data Principal identifier (Principals, Grievances,
 * Compliance/Purge Requests, and — as of the parental-verification-evidence
 * fix — the guardian-verification "ref_id"/"proof_metadata" evidence
 * fields). Never reachable via an API key — see the route registration note
 * below and InterceptingFilter.CLIENT_ALLOWED_FUNCS, which intentionally
 * does not include "reveal_user_id".
 *
 * Every reveal is synchronously audit-logged (Audit.logEvents() forced
 * flush) BEFORE the plaintext value is returned, so a reveal that never
 * makes it into audit_logs can never happen — "on need basis, verifiable"
 * was the explicit requirement behind this endpoint.
 */
public class Pii implements Action {

    /**
     * One entry per revealable source: which table/PK to key off, which encrypted column(s) to
     * decrypt and under what output key, and (for audit purposes only — never exposed in the
     * response) which encrypted column identifies the Data Principal this reveal is "about", so
     * every PII_REVEALED audit row is still traceable to a subject the way every other audit
     * action is.
     */
    private static final class SourceSpec {
        final String table;
        final String pkColumn;      // null => no single-row PK (data_principal-style lookup by ref)
        final String[][] fields;    // {encryptedColumn, outputKey} pairs to decrypt and return
        final String subjectEncColumn; // encrypted column to decrypt for the audit-log subject only

        SourceSpec(String table, String pkColumn, String[][] fields, String subjectEncColumn) {
            this.table = table;
            this.pkColumn = pkColumn;
            this.fields = fields;
            this.subjectEncColumn = subjectEncColumn;
        }
    }

    private static final String[][] USER_ID_FIELD = {{"user_id_enc", "user_id"}};
    // consent_record reveals both the principal and the IP together — ip_address was previously
    // one-way hashed (LookupHasher, genuinely irreversible) and is now reversibly encrypted the
    // same as every other identifier, so a single reveal click on a consent record unmasks both.
    private static final String[][] CONSENT_RECORD_FIELDS = {{"user_id_enc", "user_id"}, {"ip_address_enc", "ip_address"}};

    /** source -> spec. Hardcoded whitelist — never interpolate a client-supplied table/column
     *  name into SQL. */
    private static final Map<String, SourceSpec> SOURCE_MAP = new HashMap<>();
    static {
        SOURCE_MAP.put("consent_record", new SourceSpec("consent_records", "id", CONSENT_RECORD_FIELDS, "user_id_enc"));
        SOURCE_MAP.put("grievance",      new SourceSpec("grievances", "id", USER_ID_FIELD, "user_id_enc"));
        SOURCE_MAP.put("purge_request",  new SourceSpec("purge_requests", "id", USER_ID_FIELD, "user_id_enc"));
        SOURCE_MAP.put("data_principal", new SourceSpec("data_principal", null, USER_ID_FIELD, "user_id_enc"));
        // Guardian-verification evidence: guardian_id (the parent/guardian's own identifier),
        // verification_ref_id (meant to be an opaque pointer, e.g. an S3 key for a scanned
        // document), and proof_metadata (descriptive-only JSON) — all encrypted, guardian_id
        // because it's PII the console never has the caller's own plaintext for, the other two
        // because nothing stops a caller from putting real identity-document data straight into
        // either field. Audit subject is the child principal, not any of these three fields,
        // matching how every other reveal ties back to a Data Principal.
        SOURCE_MAP.put("parental_verification", new SourceSpec("parental_verification_logs", "id",
                new String[][]{{"guardian_principal_id_enc", "guardian_id"}, {"verification_ref_id_enc", "verification_ref_id"}, {"proof_metadata_enc", "proof_metadata"}},
                "child_principal_id_enc"));
    }

    // Simple per-operator rate limit: 20 reveals / rolling minute. Local, in-memory —
    // adequate for this single-node deployment; a multi-node deployment would need a
    // shared store, but the guardrail here is against a scripted loop reconstructing
    // the whole principal list through the console session, not distributed abuse.
    private static final int RATE_LIMIT_PER_MINUTE = 20;
    private static final Map<String, long[]> rateWindow = new ConcurrentHashMap<>(); // operatorId -> {windowStartEpochSec, count}

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input;
        try {
            input = InputProcessor.getInput(req);
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Could not parse input.", req.getRequestURI());
            return;
        }

        String func = (String) input.get("_func");
        if (!"reveal_user_id".equalsIgnoreCase(func)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unsupported '_func'.", req.getRequestURI());
            return;
        }

        UUID loginUserId = InputProcessor.getAuthenticatedUserId(req);
        String callerRole = InputProcessor.getVerifiedRole(req);
        if (loginUserId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Operator authentication required.", req.getRequestURI());
            return;
        }

        if (!withinRateLimit(loginUserId.toString())) {
            // jakarta.servlet.http.HttpServletResponse has no SC_TOO_MANY_REQUESTS constant (that's
            // RFC 6585 / HTTP 429, added after the original HttpServletResponse status constants).
            OutputProcessor.errorResponse(res, 429, "Too Many Requests",
                    "Reveal rate limit exceeded (" + RATE_LIMIT_PER_MINUTE + "/min). Try again shortly.", req.getRequestURI());
            return;
        }

        String source = (String) input.get("source");
        String fiduciaryIdStr = (String) input.get("fiduciary_id");
        String recordId = (String) input.get("id");
        String userRef = (String) input.get("user_ref");

        SourceSpec spec = SOURCE_MAP.get(source);
        if (spec == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown 'source'.", req.getRequestURI());
            return;
        }
        if (fiduciaryIdStr == null || fiduciaryIdStr.trim().isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required.", req.getRequestURI());
            return;
        }

        UUID fiduciaryId;
        try {
            fiduciaryId = UUID.fromString(fiduciaryIdStr);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id'.", req.getRequestURI());
            return;
        }

        if (spec.pkColumn == null) {
            // data_principal: no single-row PK, must key off (user_id_hmac, fiduciary_id)
            if (userRef == null || userRef.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_ref' is required for source=data_principal.", req.getRequestURI());
                return;
            }
        } else if (recordId == null || recordId.trim().isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'id' is required for source=" + source + ".", req.getRequestURI());
            return;
        }

        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        Map<String, String> revealed = null;
        String subjectValue = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();

            // SELECT <decrypt(field1)> AS key1, <decrypt(field2)> AS key2, ..., <decrypt(subject)>
            // AS subject FROM <table> WHERE <pk|hmac ref> = ? AND fiduciary_id = ?
            StringBuilder sql = new StringBuilder("SELECT ");
            for (String[] f : spec.fields) {
                sql.append(DbEncryption.decryptCol(f[0])).append(" AS ").append(f[1]).append(", ");
            }
            sql.append(DbEncryption.decryptCol(spec.subjectEncColumn)).append(" AS reveal_subject FROM ").append(spec.table).append(" WHERE ");
            if (spec.pkColumn == null) {
                // truncated hmac ref (first 16 hex chars) -> exact-match against the leading
                // substring of the stored hmac, still scoped by fiduciary_id
                sql.append("user_id_hmac LIKE ? AND fiduciary_id = ?");
            } else {
                sql.append(spec.pkColumn).append(" = ? AND fiduciary_id = ?");
            }

            pstmt = conn.prepareStatement(sql.toString());
            int idx = 1;
            for (int i = 0; i < spec.fields.length; i++) {
                idx = DbEncryption.bindKey(pstmt, idx);
            }
            idx = DbEncryption.bindKey(pstmt, idx); // subject decrypt key
            if (spec.pkColumn == null) {
                pstmt.setString(idx++, userRef + "%");
            } else {
                pstmt.setObject(idx++, UUID.fromString(recordId));
            }
            pstmt.setObject(idx++, fiduciaryId);

            rs = pstmt.executeQuery();
            if (rs.next()) {
                revealed = new HashMap<>();
                for (String[] f : spec.fields) {
                    revealed.put(f[1], rs.getString(f[1]));
                }
                subjectValue = rs.getString("reveal_subject");
            }

            if (revealed == null) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found",
                        "No matching record for the given source/id/fiduciary_id.", req.getRequestURI());
                return;
            }

            // Audit BEFORE responding — a reveal that isn't durably logged before the
            // plaintext leaves this method is not "verifiable". Never put the revealed
            // plaintext itself into context_details.
            JSONObject ctx = new JSONObject();
            ctx.put("source", source);
            ctx.put("record_id", recordId);
            ctx.put("operator_id", loginUserId.toString());
            ctx.put("operator_role", callerRole);
            ctx.put("client_ip", req.getRemoteAddr());

            new Audit().logEventAsync(subjectValue, fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE,
                    loginUserId, "PII_REVEALED", ctx.toJSONString());
            new Audit().logEvents(); // force synchronous flush before returning plaintext

            JSONObject out = new JSONObject();
            for (Map.Entry<String, String> entry : revealed.entrySet()) {
                if ("proof_metadata".equals(entry.getKey()) && entry.getValue() != null) {
                    try {
                        out.put(entry.getKey(), new org.json.simple.parser.JSONParser().parse(entry.getValue()));
                        continue;
                    } catch (Exception ignored) {
                        // fall through to raw string if it's somehow not valid JSON
                    }
                }
                out.put(entry.getKey(), entry.getValue());
            }
            out.put("source", source);
            out.put("record_id", recordId);
            out.put("revealed_at", Timestamp.from(Instant.now()).toString());
            OutputProcessor.send(res, HttpServletResponse.SC_OK, out);

        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "Reveal failed.", req.getRequestURI());
        } finally {
            try { if (rs != null) rs.close(); } catch (Exception ignore) {}
            try { if (pstmt != null) pstmt.close(); } catch (Exception ignore) {}
            try { if (conn != null) conn.close(); } catch (Exception ignore) {}
        }
    }

    private boolean withinRateLimit(String operatorId) {
        long nowSec = Instant.now().getEpochSecond();
        long[] window = rateWindow.computeIfAbsent(operatorId, k -> new long[]{nowSec, 0});
        synchronized (window) {
            if (nowSec - window[0] >= 60) {
                window[0] = nowSec;
                window[1] = 0;
            }
            if (window[1] >= RATE_LIMIT_PER_MINUTE) {
                return false;
            }
            window[1]++;
            return true;
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method);
    }
}
