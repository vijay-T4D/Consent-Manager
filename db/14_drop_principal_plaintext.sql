-- 14_drop_principal_plaintext.sql
-- Contract phase of the 13_principal_pii_encryption.sql migration.
--
-- DO NOT RUN THIS until:
--   1. 13_principal_pii_encryption.sql has been applied and its parity
--      verification query returns 0 for every affected table/column.
--   2. The Java build that reads/writes exclusively via *_hmac/*_enc
--      (Consent.java, Grievance.java, Compliance.java, CESService.java,
--      JobManager.java, Wallet.java, Breach.java, Ropa.java,
--      Notification.java — see plan §7) has been deployed and manually
--      verified end-to-end (plan §9).
--
-- After this script runs, the plaintext user_id/guardian_id/recipient_id
-- columns are gone. This is IRREVERSIBLE WITHOUT THE DB_ENCRYPTION_KEY:
-- if that key is ever lost, every row in these tables becomes permanently
-- unattributable to a Data Principal — including the ability to honour a
-- DPDP erasure request tied to that identity. Confirm key backup/custody
-- before running this.

-- ============================================================
-- TABLE: consent_records
-- ============================================================
DROP INDEX IF EXISTS idx_unique_active_consent;              -- old plaintext-keyed unique index
DROP INDEX IF EXISTS idx_consent_records_active_lookup;
DROP INDEX IF EXISTS idx_consent_records_history;
ALTER TABLE consent_records
    ALTER COLUMN user_id_enc  SET NOT NULL,
    ALTER COLUMN user_id_hmac SET NOT NULL;
ALTER TABLE consent_records DROP COLUMN user_id;

-- ============================================================
-- TABLE: data_principal
-- ============================================================
ALTER TABLE data_principal DROP CONSTRAINT IF EXISTS data_principal_pkey;
DROP INDEX IF EXISTS idx_data_principal_hmac_pk;              -- replaced by the new PK below
DROP INDEX IF EXISTS idx_data_principal_auth_link;             -- old plaintext-keyed index
ALTER TABLE data_principal
    ALTER COLUMN user_id_enc  SET NOT NULL,
    ALTER COLUMN user_id_hmac SET NOT NULL;
ALTER TABLE data_principal ADD PRIMARY KEY (user_id_hmac, fiduciary_id);
ALTER TABLE data_principal DROP COLUMN user_id;
ALTER TABLE data_principal DROP COLUMN guardian_id;

-- ============================================================
-- TABLE: grievances
-- ============================================================
DROP INDEX IF EXISTS idx_grievances_fid_user_timestamp;        -- old plaintext-keyed index
ALTER TABLE grievances
    ALTER COLUMN user_id_enc  SET NOT NULL,
    ALTER COLUMN user_id_hmac SET NOT NULL;
ALTER TABLE grievances DROP COLUMN user_id;

-- ============================================================
-- TABLE: purge_requests
-- ============================================================
DROP INDEX IF EXISTS idx_purge_requests_user_search;           -- old plaintext-keyed index
ALTER TABLE purge_requests
    ALTER COLUMN user_id_enc  SET NOT NULL,
    ALTER COLUMN user_id_hmac SET NOT NULL;
ALTER TABLE purge_requests DROP COLUMN user_id;

-- ============================================================
-- TABLE: consent_validations
-- ============================================================
ALTER TABLE consent_validations
    ALTER COLUMN user_id_enc  SET NOT NULL,
    ALTER COLUMN user_id_hmac SET NOT NULL;
ALTER TABLE consent_validations DROP COLUMN user_id;

-- ============================================================
-- TABLE: breach_affected_principals
-- ============================================================
ALTER TABLE breach_affected_principals DROP CONSTRAINT IF EXISTS breach_affected_principals_pkey;
DROP INDEX IF EXISTS idx_breach_affected_hmac_pk;
ALTER TABLE breach_affected_principals
    ALTER COLUMN user_id_enc  SET NOT NULL,
    ALTER COLUMN user_id_hmac SET NOT NULL;
ALTER TABLE breach_affected_principals ADD PRIMARY KEY (breach_id, user_id_hmac);
ALTER TABLE breach_affected_principals DROP COLUMN user_id;

-- ============================================================
-- TABLE: parental_verification_logs
-- ============================================================
DROP INDEX IF EXISTS idx_guardian_child;                       -- old plaintext-keyed index
ALTER TABLE parental_verification_logs
    ALTER COLUMN child_principal_id_enc      SET NOT NULL,
    ALTER COLUMN child_principal_id_hmac     SET NOT NULL,
    ALTER COLUMN guardian_principal_id_enc   SET NOT NULL,
    ALTER COLUMN guardian_principal_id_hmac  SET NOT NULL;
ALTER TABLE parental_verification_logs DROP COLUMN child_principal_id;
ALTER TABLE parental_verification_logs DROP COLUMN guardian_principal_id;

-- ============================================================
-- TABLE: notifications
-- ============================================================
DROP INDEX IF EXISTS idx_notifications_recipient_created;      -- old plaintext-keyed index
ALTER TABLE notifications
    ALTER COLUMN recipient_id_enc  SET NOT NULL,
    ALTER COLUMN recipient_id_hmac SET NOT NULL;
ALTER TABLE notifications DROP COLUMN recipient_id;

-- ============================================================
-- Post-drop sanity check — every table should now report zero columns
-- named user_id / guardian_id / recipient_id (only the _enc/_hmac variants
-- remain):
-- ============================================================
-- SELECT table_name, column_name FROM information_schema.columns
--  WHERE column_name IN ('user_id','guardian_id','recipient_id',
--                         'child_principal_id','guardian_principal_id')
--    AND table_schema = 'public';
