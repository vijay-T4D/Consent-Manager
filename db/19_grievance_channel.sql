-- 19_grievance_channel.sql
--
-- Adds a `channel` column to `grievances` so the DPO console can log a grievance that arrived
-- outside the fiduciary's own app (email, phone call, letter, walk-in) without conflating it with
-- principal-self-submitted ones. Every existing row (all submitted via `submit_grievance` through
-- the fiduciary's client app/API key) is backfilled as 'PORTAL'. New DPO-logged rows set this
-- explicitly to EMAIL/PHONE/LETTER/IN_PERSON/OTHER at insert time.
--
-- Who actually recorded it is already captured separately and correctly by the existing
-- audit trail (`GRIEVANCE_SUBMITTED` event's service_type: APP when submitted via API key,
-- DPO_CONSOLE when submitted by an authenticated operator) — this column only answers "how did
-- the grievance reach us", not "who typed it into the system", which are different questions.

ALTER TABLE grievances
    ADD COLUMN IF NOT EXISTS channel VARCHAR(20) NOT NULL DEFAULT 'PORTAL';

COMMENT ON COLUMN grievances.channel IS
    'How the grievance reached the fiduciary: PORTAL (principal-submitted via app/API), EMAIL, PHONE, LETTER, IN_PERSON, OTHER (DPO-logged on the principal''s behalf).';
