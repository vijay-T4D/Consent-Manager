-- 18_encrypt_consent_ip_address.sql
-- Switches consent_records.ip_address from a one-way SHA-256 hash
-- (LookupHasher, applied before this session's work — see
-- Consent.recordConsentToDb's "hash IP before storage" comment) to reversible
-- pgcrypto encryption, matching every other identifier in this system.
--
-- WHY: IP address was previously stored genuinely irreversibly — nothing,
-- not even an authorized DPO reveal, could ever recover it. That was a
-- stronger privacy stance than everything else in the system, but it meant
-- the console's Provenance card could show a hash with zero way to verify
-- or investigate it later (e.g. tying a consent event to a specific
-- session/device during an abuse investigation). Switching to the same
-- encrypt-at-rest + audited-reveal pattern as user_id/guardian_id/etc.
-- brings it in line and makes it actually useful forensic data again,
-- while still masking it by default.
--
-- No _hmac column — ip_address is never looked up by exact match anywhere
-- in the codebase (confirmed via grep), so there's no lookup requirement.
--
-- CAVEAT: any row written before this migration already has an
-- IRREVERSIBLE hash in its ip_address column — that hash is all that was
-- ever stored, so encrypting it here just carries the opaque hash forward
-- as ciphertext; it does not and cannot recover the real IP for old rows.
-- Only rows written after the Java cutover (recordConsentToDb, withdrawConsent,
-- Wallet.java) store genuinely reversible ciphertext of the real IP.

BEGIN;

ALTER TABLE consent_records
    ADD COLUMN IF NOT EXISTS ip_address_enc TEXT;

UPDATE consent_records
SET ip_address_enc = encode(pgp_sym_encrypt(ip_address, current_setting('app.enc_key')), 'base64')
WHERE ip_address_enc IS NULL;

ALTER TABLE consent_records
    ALTER COLUMN ip_address_enc SET NOT NULL,
    DROP COLUMN ip_address;

COMMIT;

-- Verification:
-- SELECT pgp_sym_decrypt(decode(ip_address_enc,'base64'), current_setting('app.enc_key')) FROM consent_records LIMIT 5;
