-- 13_principal_pii_encryption.sql
-- Extends the pgcrypto pattern from 04_gaps.sql (DbEncryption.java) to every
-- table that stores a Data Principal's raw identifier (email/mobile passed
-- in as `user_id` by the Data Fiduciary's own application, per
-- record_consent.jschema). Today these are plaintext VARCHAR columns,
-- rendered in clear text throughout the DPO console and REST API.
--
-- This script is ADDITIVE ONLY — it does not rename or drop any plaintext
-- column, and does not change any Java-facing query shape. Existing plaintext
-- reads/writes keep working after this script runs. The Java cutover (writes
-- go to *_enc/*_hmac, reads switch to *_hmac lookups + decrypt-on-reveal,
-- console/API responses mask by default) ships in the same deploy that this
-- migration precedes, per the big-bang rollout in the approved plan. Once
-- that Java build is verified against production data (see the parity query
-- at the bottom of this file), run 14_drop_principal_plaintext.sql to remove
-- the plaintext columns and repoint constraints permanently.
--
-- ============================================================
-- PREREQUISITE
-- ============================================================
--   Same key as 04_gaps.sql / DbEncryption.java — already persisted via
--   db/03z_enc_key.sh at container init:
--       ALTER DATABASE <dbname> SET app.enc_key = '<value-of-DB_ENCRYPTION_KEY>';
--   Verify it actually ran (03z_enc_key.sh has a documented history of
--   silently failing due to a missing executable bit — see CLAUDE.md) with:
--       SHOW app.enc_key;
--   before running the UPDATEs below. A mismatched/blank key here will not
--   error — it will silently backfill hmac columns that never match anything
--   the running application computes, and every console read will come back
--   empty with no exception.
--
-- ============================================================
-- ENCRYPTION SCHEME (identical to 04_gaps.sql)
-- ============================================================
--   Write path : encode(pgp_sym_encrypt(plaintext, key), 'base64')  → TEXT column *_enc
--   Read path  : pgp_sym_decrypt(decode(ciphertext, 'base64'), key) → TEXT
--   Lookup path: encode(hmac(lower(trim(value)), key, 'sha256'), 'hex') → TEXT column *_hmac
--                Deterministic, so it preserves WHERE/ORDER BY/DISTINCT ON/GROUP BY
--                semantics identically to the plaintext column it replaces.
--
-- ============================================================
-- AFFECTED TABLES / COLUMNS
-- ============================================================
--   consent_records.user_id
--   data_principal.user_id, data_principal.guardian_id
--   grievances.user_id
--   purge_requests.user_id
--   consent_validations.user_id
--   breach_affected_principals.user_id
--   parental_verification_logs.child_principal_id, .guardian_principal_id
--   notifications.recipient_id   (only when recipient_type = 'PRINCIPAL' —
--                                  DPO/APP recipient_ids are internal UUIDs,
--                                  not PII, but hmac/enc of a UUID is harmless
--                                  and keeps the column uniform)
--
-- audit_logs.user_id is deliberately NOT touched — it is already a one-way
-- SHA-256 hash (LookupHasher, keyed by TSI_LOOKUP_SALT, a different key from
-- app.enc_key) and feeds the tamper-evident audit hash chain
-- (Audit.calculateHash). Any migration of that column would silently
-- invalidate every downstream current_log_hash.
--
-- ============================================================
-- ROLLBACK
-- ============================================================
--   Purely additive — drop the new columns/indexes to roll back. Plaintext
--   columns are untouched by this script.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- TABLE: consent_records
-- ============================================================
ALTER TABLE consent_records
    ADD COLUMN IF NOT EXISTS user_id_enc  TEXT,
    ADD COLUMN IF NOT EXISTS user_id_hmac TEXT;

UPDATE consent_records
SET
    user_id_enc  = encode(pgp_sym_encrypt(user_id, current_setting('app.enc_key')), 'base64'),
    user_id_hmac = encode(hmac(lower(trim(user_id)), current_setting('app.enc_key'), 'sha256'), 'hex')
WHERE user_id_enc IS NULL;

-- Mirrors idx_unique_active_consent / idx_consent_records_active_lookup / idx_consent_records_history
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_active_consent_hmac
    ON consent_records (user_id_hmac, fiduciary_id) WHERE is_active_consent IS TRUE;
CREATE INDEX IF NOT EXISTS idx_consent_records_active_lookup_hmac
    ON consent_records (user_id_hmac, fiduciary_id) WHERE (is_active_consent = TRUE);
CREATE INDEX IF NOT EXISTS idx_consent_records_history_hmac
    ON consent_records (user_id_hmac, fiduciary_id, timestamp DESC);

-- ============================================================
-- TABLE: data_principal
-- ============================================================
ALTER TABLE data_principal
    ADD COLUMN IF NOT EXISTS user_id_enc      TEXT,
    ADD COLUMN IF NOT EXISTS user_id_hmac     TEXT,
    ADD COLUMN IF NOT EXISTS guardian_id_enc  TEXT,
    ADD COLUMN IF NOT EXISTS guardian_id_hmac TEXT;

UPDATE data_principal
SET
    user_id_enc      = encode(pgp_sym_encrypt(user_id, current_setting('app.enc_key')), 'base64'),
    user_id_hmac     = encode(hmac(lower(trim(user_id)), current_setting('app.enc_key'), 'sha256'), 'hex'),
    guardian_id_enc  = CASE WHEN guardian_id IS NOT NULL
                            THEN encode(pgp_sym_encrypt(guardian_id, current_setting('app.enc_key')), 'base64')
                            ELSE NULL END,
    guardian_id_hmac = CASE WHEN guardian_id IS NOT NULL
                            THEN encode(hmac(lower(trim(guardian_id)), current_setting('app.enc_key'), 'sha256'), 'hex')
                            ELSE NULL END
WHERE user_id_enc IS NULL;

-- Becomes the new ON CONFLICT arbiter ahead of 14_drop_principal_plaintext.sql
-- repointing the actual PRIMARY KEY. Kept as a plain unique index (not yet
-- the PK) so the Java cutover can target it before the plaintext PK is dropped.
CREATE UNIQUE INDEX IF NOT EXISTS idx_data_principal_hmac_pk
    ON data_principal (user_id_hmac, fiduciary_id);
CREATE INDEX IF NOT EXISTS idx_data_principal_auth_link_hmac
    ON data_principal (user_id_hmac, fiduciary_id, verification_status);

-- ============================================================
-- TABLE: grievances
-- ============================================================
ALTER TABLE grievances
    ADD COLUMN IF NOT EXISTS user_id_enc  TEXT,
    ADD COLUMN IF NOT EXISTS user_id_hmac TEXT;

UPDATE grievances
SET
    user_id_enc  = encode(pgp_sym_encrypt(user_id, current_setting('app.enc_key')), 'base64'),
    user_id_hmac = encode(hmac(lower(trim(user_id)), current_setting('app.enc_key'), 'sha256'), 'hex')
WHERE user_id_enc IS NULL;

CREATE INDEX IF NOT EXISTS idx_grievances_fid_user_timestamp_hmac
    ON grievances (fiduciary_id, user_id_hmac, submission_timestamp DESC);

-- ============================================================
-- TABLE: purge_requests
-- ============================================================
ALTER TABLE purge_requests
    ADD COLUMN IF NOT EXISTS user_id_enc  TEXT,
    ADD COLUMN IF NOT EXISTS user_id_hmac TEXT;

UPDATE purge_requests
SET
    user_id_enc  = encode(pgp_sym_encrypt(user_id, current_setting('app.enc_key')), 'base64'),
    user_id_hmac = encode(hmac(lower(trim(user_id)), current_setting('app.enc_key'), 'sha256'), 'hex')
WHERE user_id_enc IS NULL;

-- Mirrors idx_purge_requests_user_search (exact-match only from now on —
-- substring search on this field is no longer possible, see Compliance.java
-- ILIKE fix in the same deploy).
CREATE INDEX IF NOT EXISTS idx_purge_requests_user_search_hmac ON purge_requests (user_id_hmac);

-- ============================================================
-- TABLE: consent_validations
-- ============================================================
ALTER TABLE consent_validations
    ADD COLUMN IF NOT EXISTS user_id_enc  TEXT,
    ADD COLUMN IF NOT EXISTS user_id_hmac TEXT;

UPDATE consent_validations
SET
    user_id_enc  = encode(pgp_sym_encrypt(user_id, current_setting('app.enc_key')), 'base64'),
    user_id_hmac = encode(hmac(lower(trim(user_id)), current_setting('app.enc_key'), 'sha256'), 'hex')
WHERE user_id_enc IS NULL;

CREATE INDEX IF NOT EXISTS idx_consent_validations_user_hmac
    ON consent_validations (user_id_hmac, fiduciary_id, purpose_id);

-- ============================================================
-- TABLE: breach_affected_principals
-- ============================================================
ALTER TABLE breach_affected_principals
    ADD COLUMN IF NOT EXISTS user_id_enc  TEXT,
    ADD COLUMN IF NOT EXISTS user_id_hmac TEXT;

UPDATE breach_affected_principals
SET
    user_id_enc  = encode(pgp_sym_encrypt(user_id, current_setting('app.enc_key')), 'base64'),
    user_id_hmac = encode(hmac(lower(trim(user_id)), current_setting('app.enc_key'), 'sha256'), 'hex')
WHERE user_id_enc IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_breach_affected_hmac_pk
    ON breach_affected_principals (breach_id, user_id_hmac);

-- ============================================================
-- TABLE: parental_verification_logs
-- ============================================================
ALTER TABLE parental_verification_logs
    ADD COLUMN IF NOT EXISTS child_principal_id_enc      TEXT,
    ADD COLUMN IF NOT EXISTS child_principal_id_hmac     TEXT,
    ADD COLUMN IF NOT EXISTS guardian_principal_id_enc   TEXT,
    ADD COLUMN IF NOT EXISTS guardian_principal_id_hmac  TEXT;

UPDATE parental_verification_logs
SET
    child_principal_id_enc     = encode(pgp_sym_encrypt(child_principal_id, current_setting('app.enc_key')), 'base64'),
    child_principal_id_hmac    = encode(hmac(lower(trim(child_principal_id)), current_setting('app.enc_key'), 'sha256'), 'hex'),
    guardian_principal_id_enc  = encode(pgp_sym_encrypt(guardian_principal_id, current_setting('app.enc_key')), 'base64'),
    guardian_principal_id_hmac = encode(hmac(lower(trim(guardian_principal_id)), current_setting('app.enc_key'), 'sha256'), 'hex')
WHERE child_principal_id_enc IS NULL;

-- Mirrors idx_guardian_child
CREATE INDEX IF NOT EXISTS idx_guardian_child_hmac
    ON parental_verification_logs (guardian_principal_id_hmac, child_principal_id_hmac);

-- ============================================================
-- TABLE: notifications
-- ============================================================
ALTER TABLE notifications
    ADD COLUMN IF NOT EXISTS recipient_id_enc  TEXT,
    ADD COLUMN IF NOT EXISTS recipient_id_hmac TEXT;

UPDATE notifications
SET
    recipient_id_enc  = encode(pgp_sym_encrypt(recipient_id, current_setting('app.enc_key')), 'base64'),
    recipient_id_hmac = encode(hmac(lower(trim(recipient_id)), current_setting('app.enc_key'), 'sha256'), 'hex')
WHERE recipient_id_enc IS NULL;

-- Mirrors idx_notifications_recipient_created
CREATE INDEX IF NOT EXISTS idx_notifications_recipient_created_hmac
    ON notifications (recipient_id_hmac, created_at DESC);

-- ============================================================
-- Verification (run manually before proceeding to 14_drop_principal_plaintext.sql)
-- ============================================================
-- Must return 0 for every table below. Repeat the pattern for
-- data_principal/guardian_id, grievances, purge_requests, consent_validations,
-- breach_affected_principals, parental_verification_logs (both id columns),
-- notifications/recipient_id.
--
-- SELECT count(*) FROM consent_records
--  WHERE user_id_enc IS NULL
--     OR user_id_hmac <> encode(hmac(lower(trim(user_id)), current_setting('app.enc_key'),'sha256'),'hex')
--     OR pgp_sym_decrypt(decode(user_id_enc,'base64'), current_setting('app.enc_key')) <> user_id;
