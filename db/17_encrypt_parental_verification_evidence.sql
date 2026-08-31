-- 17_encrypt_parental_verification_evidence.sql
-- Extends the pgcrypto encryption already applied to
-- parental_verification_logs.child_principal_id/.guardian_principal_id
-- (13_principal_pii_encryption.sql) to the two "evidence" columns on the
-- same table: verification_ref_id and proof_metadata.
--
-- WHY: these are meant to hold an OPAQUE pointer (e.g. an S3 object key for
-- a scanned guardianship document) and purely descriptive metadata about the
-- verification event — never the identity document's own contents. But
-- nothing in the schema or application code enforces that shape today;
-- proof_metadata is arbitrary JSONB supplied by the calling app, so a caller
-- that (incorrectly) embeds a real government ID (e.g. a voter ID number)
-- directly in proof_metadata would previously have stored it in plaintext,
-- with none of this session's masking/reveal protections applying to it.
--
-- No _hmac columns here — unlike user_id/guardian_id, neither field is ever
-- looked up by exact-match WHERE clause anywhere in the codebase (confirmed
-- via grep), so there's no lookup requirement to preserve.
--
-- Access model (per explicit decision): same audited-reveal pattern as
-- everything else — encrypted at rest, decrypted only via Pii.java's
-- reveal_user_id endpoint (new "parental_verification" source), which
-- synchronously audit-logs every reveal before responding.

BEGIN;

ALTER TABLE parental_verification_logs
    ADD COLUMN IF NOT EXISTS verification_ref_id_enc TEXT,
    ADD COLUMN IF NOT EXISTS proof_metadata_enc TEXT;

UPDATE parental_verification_logs
SET
    verification_ref_id_enc = CASE WHEN verification_ref_id IS NOT NULL
        THEN encode(pgp_sym_encrypt(verification_ref_id, current_setting('app.enc_key')), 'base64')
        ELSE NULL END,
    proof_metadata_enc = CASE WHEN proof_metadata IS NOT NULL
        THEN encode(pgp_sym_encrypt(proof_metadata::text, current_setting('app.enc_key')), 'base64')
        ELSE NULL END
WHERE verification_ref_id_enc IS NULL AND proof_metadata_enc IS NULL;

-- Drop plaintext immediately — this table has negligible live row count
-- (confirmed: 1 row, our own test data, as of this migration) and no other
-- read path depends on the old columns surviving a transition window,
-- unlike the bigger principal-identifier cutover in 13/14 which needed a
-- staged rollout across many call sites.
ALTER TABLE parental_verification_logs
    DROP COLUMN verification_ref_id,
    DROP COLUMN proof_metadata;

COMMIT;

-- ============================================================
-- Verification (run manually)
-- ============================================================
-- SELECT id,
--        pgp_sym_decrypt(decode(verification_ref_id_enc,'base64'), current_setting('app.enc_key')) AS ref_id,
--        pgp_sym_decrypt(decode(proof_metadata_enc,'base64'), current_setting('app.enc_key'))::jsonb AS metadata
-- FROM parental_verification_logs;
