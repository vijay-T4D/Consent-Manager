# TSI DPDP Consent Management System — Feature Documentation

This document is in two parts:
- **Part 1 — Core Features**: what the platform does, as a baseline consent-management system (the capability set from the upstream `tsi-coop/tsi-dpdp-cms` project).
- **Part 2 — Enhancements Made in This Deployment**: everything built, hardened, or fixed on top of that baseline during local evaluation on this machine — not present upstream.

For local dev setup and day-to-day commands, see [CLAUDE.md](CLAUDE.md).

---

# Part 1 — Core Features

## 1. Multi-Tenancy Model

| Concept | Class | Meaning |
|---|---|---|
| **Fiduciary** | `Fiduciary.java` | The tenant boundary — an organization ("Data Fiduciary" under DPDP). Every policy, RoPA entry, consent record, and app is scoped by `fiduciary_id`. Onboarding captures name, domain, DPO contact, DPB registration, and a "significant fiduciary" flag; domain ownership is verified via a DNS TXT token. |
| **App** | `App.java` | A named integration/system the fiduciary registers (e.g. "Educate Girls Website"). Its `app_id` is stamped onto every consent record for provenance. |
| **API Key** | `ApiKey.java` | The bearer credential (`X-API-Key` + `X-API-Secret` headers) a client app presents. Carries a permission set (`READ`/`WRITE`/`PURGE`); resolves back to `app_id`/`fiduciary_id` on every request. Revocation is instant and permanent. |
| **Operator** | `Operator.java` | A CMS backend user account — see [Roles & Permissions](#9-roles--permissions-rbac) below. |

Three distinct caller identities exist throughout the API surface:
1. **Client apps** — authenticate via API key, act on behalf of the fiduciary's own integration.
2. **DPO/Operator console users** — authenticate via a role-bearing JWT (`Operator.login`).
3. **Data principals** — authenticate via a short-lived Principal JWT (`Principal.principal_login`, OTP-based) or a signed Wallet sync token; scoped strictly to their own data.

## 2. Consent Management (`Consent.java`)

The core consent ledger.

- **`record_consent`** — grants/updates/withdraws granular, purpose-level consent against a published policy. Every purpose/data-point is tracked individually, not as a single yes/no.
- **`validate_consent`** — the runtime gate: a client app calls this before processing any data for a purpose, to confirm consent is currently active.
- **`get_active_consent` / `get_consent_record_details` / `list_consent_history`** — read the current or historical consent state for a principal.
- **`get_consent_audit_trail`** — cross-references a live consent record against its own audit log entry.
- **`withdraw_consent`** — full or partial withdrawal; a single purpose can be revoked without touching the rest of a principal's consent.
- **`erasure_request`** — records a request to erase all data under a policy (distinct from consent withdrawal — see [Erasure/Purge](#4-erasure--purge-requests-compliancejava)).
- **`link_user`** — reconciles an anonymous session's consent trail to a now-authenticated identity, and (for minors) records `age_category`/`guardian_id`.
- **`list_principals`** — the DPO console's Principals search.

### Minor / Guardian Consent
- **`record_parent_consent`** logs a parental/guardian verification event — verification mechanism, provider, and an evidence pointer (e.g. an S3 reference) — **never raw ID documents themselves**. The system has no file-storage capability; it only holds a pointer to evidence stored externally.
- **`link_user`** then marks the principal `age_category: MINOR` and sets `guardian_id`, and `record_consent` carries the same `verification_log_id`, creating a real FK-linked chain: `consent_records → parental_verification_logs`.
- `verification_status` is currently cosmetic — displayed in the console but not enforced anywhere.

## 3. Policy & RoPA Management

### Policy (`Policy.java`)
Consent-notice documents with a draft → active → archived lifecycle.
- `create_policy` / `update_policy` (DRAFT only) / `publish_policy` (activates, auto-deactivates the prior version) / `delete_policy` — **DPO/Admin only**.
- `list_active_policies` / `get_policy` / `get_active_policy` — read access for client apps and the principal rights portal.

### Records of Processing Activities — RoPA (`Ropa.java`)
The DPDP-mandated processing-activity register.
- `create_entry` / `update_entry` / `publish_entry` (validates completeness first) / `retire_entry` — **DPO/Admin only**.
- `derive_from_policy` — auto-generates a RoPA draft from an existing published policy, so the two don't drift independently.
- `validate_completeness` — checks required fields without publishing.
- `export_ropa` — CSV export (with live consent counts per entry) for regulatory reporting.

## 4. Erasure / Purge Requests (`Compliance.java`)

Tracks fulfillment of erasure obligations end-to-end, independent of the consent-withdrawal flag itself.

- A `purge_requests` row is created (trigger event: erasure request, retention-clock expiry, or consent withdrawal) with status `PENDING`.
- **`update_purge_status`** drives it through `IN_PROGRESS → COMPLETED / FAILED / UNDER_LEGAL_HOLD`. Every update notifies the principal and fires an outbound webhook to the fiduciary's own systems.
- **`assign_purge_request`** delegates a request to a specific Operator (DPO/Admin only); Operators only see/act on their own assigned queue.
- **`list_purge_requests` / `get_purge_request`** — read access, scoped by role.

## 5. Grievance Redressal (`Grievance.java`)

Full DPDP Act grievance-handling lifecycle.

- **`submit_grievance`** — creates a grievance/rights request, principal-initiated via the fiduciary's own app (API key).
- **SLA**: due date is computed automatically at submission — **7 days** for an `ERASURE_REQUEST` type, **30 days** for everything else.
- **`assign_grievance`** — DPO/Admin delegates a grievance to a specific Operator; Operators may only view/close grievances explicitly assigned to them.
- **`update_grievance_status`** — moves through `NEW → IN_PROGRESS → RESOLVED/ESCALATED`, with free-text `resolution_details`. No file/evidence attachment is required or enforced at any stage.
- **`list_user_grievances`** — principal's own self-service view of their filed grievances.

Every state transition is audited and select transitions (submission, resolution, escalation, assignment) trigger a notification.

## 6. Breach Notification (`Breach.java`)

Implements the DPDP Act §8(6) breach-notification workflow. Detection is manual (no automated scanning):

- **`report_breach`** — DPO/Admin records an incident and resolves the affected principals three ways: an explicit ID list, a bulk CSV, and/or everyone holding active consent for an affected purpose.
- Each affected principal is notified via a templated notification (`BREACH_NOTIFICATION`, or a DPO-defined subtype like `BREACH_NOTIFICATION_PHISHING`).
- **`update_breach_status`** tracks the incident through to `CONTAINED`/`RESOLVED`.
- **`download_breach_report`** — generates a PDF suitable for management or Data Protection Board review, once the incident reaches `CONTAINED` or `RESOLVED`.
- There is no coded 72-hour regulator-deadline timer — only the status lifecycle and audit trail.

## 7. Audit Trail & Legal Evidence

Every significant action — consent events, grievance/purge/breach lifecycle changes, logins — is written to `audit_logs` with `user_id`, `service_type`/`service_id` (who acted), `audit_action`, and free-text `context_details`. Each row's hash is chained to the previous row's hash (`calculateHash()`), making the log tamper-evident: any retroactive edit or deletion breaks every hash after it.

**`Legal.generate_certificate`** produces a digitally-signed "Evidence Certificate" for a given principal: walks their complete validated audit trail, captures chain-of-custody metadata, and signs the payload — intended as admissible evidence for legal/regulatory proceedings. **DPO/Admin only**, generated on demand — not automatically on grievance resolution or erasure completion.

## 8. Notifications, Webhooks & Background Jobs

- Notification rows are created by other services (grievance/purge/breach events) and delivered to the affected principal or operator.
- **`set_notification_message` / `set_webhook_config` / `set_rights_app_config`** — DPO configures message templates, outbound webhook endpoints (`NOTIFICATION`/`PURGE`/`OTP` categories), and the rights portal's OTP/QR behavior.
- **`create_job`** queues `CES` (compliance-evaluation scan) or `EXPORT` jobs (CSV exports of Consent/Principal/Compliance/Grievance/Audit/RoPA data) — DPO/Admin only. `JobManager` polls every 2 minutes and also runs nightly CES scans per active fiduciary.

## 9. Roles & Permissions (RBAC)

| Role | Scope |
|---|---|
| **ADMIN** | Unrestricted, platform-wide. Only ADMIN can create another ADMIN or act across fiduciary boundaries. |
| **DPO** | Scoped to their own fiduciary. Full authoring rights (policies, RoPA, breach reports) and manages OPERATOR accounts within that fiduciary. |
| **OPERATOR** | Most restricted. Blocked from all governance-authoring actions (policy/RoPA authoring, breach reporting, plaintext exports). Sees only their own assigned queue on grievances/purge requests. |

Enforcement is via the operator's **database** role, not any client-asserted claim.

## 10. Data Principal Self-Service

### Rights Portal (`Principal.java` + `web/rights/`)
Public entry point: pick a fiduciary, OTP-login (`request_principal_otp` / `principal_login`), then — scoped to the principal's own JWT — view active/historical consent, read policy text, grant/update preferences, withdraw consent, request erasure, and file/track grievances.

### DPDP Wallet (`Wallet.java`)
A portable, cross-fiduciary consent app the principal "carries" — authenticated by a signed sync token, not a bearer JWT.
- Import a fiduciary relationship by QR scan; see current consent state (`GET_FIDUCIARY_NAME`, `GET_CONSENT_DETAILS`).
- **`REVOKE_PURPOSE`** — revoke one specific purpose from the wallet.
- **`GLOBAL_ERASURE`** — deactivate all active consent for that fiduciary relationship in one action.

Presented as demonstrating DPDP Act §6 (withdrawal) and §12 (erasure) rights from a single portable interface.

## 11. Admin & DPO Console

| Page | Backed by |
|---|---|
| Dashboard | `AdminDash.java` — fiduciary-scoped metrics, pending-grievance widget |
| Policies | `Policy.java` |
| RoPA | `Ropa.java` |
| Principals | `Consent.java` — search, drill-down |
| Compliance | `Compliance.java` — purge request queue |
| Grievances | `Grievance.java` — queue, assignment, resolution |
| Breach | `Breach.java` |
| Audit | `Audit.java` |
| Legal | `Legal.java` — evidence certificate generation |
| Reports | `Job.java` — export job monitor/download |
| Team | `Operator.java` — operator account management |
| Settings | `Notification.java` — message templates, webhooks, rights-app config |

A separate platform-level Admin surface (`Fiduciary.java`, `App.java`, `ApiKey.java`) manages fiduciary onboarding, registered apps, and API key issuance/revocation.

## Not in scope (by design)

- **No file/document storage.** Guardian-verification evidence, breach CSVs, and grievance attachments are optional metadata pointers or transient inputs — the system never becomes the system of record for the underlying document.
- **No automated breach detection.** Breach reporting is DPO-initiated.
- **No automatic evidence certification.** Certificates are generated on demand by a DPO, not automatically on grievance/erasure closure.

---

# Part 2 — Enhancements Made in This Deployment

Everything below was built, hardened, or fixed locally on top of the upstream baseline — none of it exists in the stock `tsi-coop/tsi-dpdp-cms` repo.

## A. PII Protection Overhaul

The stock system stored data-principal identifiers (email/mobile used as `user_id`) as **plaintext**, rendered in clear text everywhere — DPO console, APIs, CSV exports — with no masking or access control.

- **Reversible encryption + masking-by-default**, applied to every table holding a principal identifier: `consent_records`, `data_principal` (+ `guardian_id`), `grievances`, `purge_requests`, `consent_validations`, `breach_affected_principals`, `parental_verification_logs` (child + guardian), `notifications.recipient_id`. Plaintext columns dropped after backfill and verification.
- **New shared reveal endpoint** (`Pii.java` / `reveal_user_id`) — the only way to see a plaintext identifier: DPO/Operator console only (never via API key), hardcoded table/column whitelist, rate-limited (20/min/operator), and **synchronously** audit-logged before the plaintext is returned — so a reveal can never be lost to a crash between logging and responding.
- **Extended to consent-record IP addresses** — previously one-way hashed (unrevealable even to an authorized DPO); switched to reversible encryption with the same audited-reveal pattern.
- **Extended to guardian/parental-verification evidence** (`verification_ref_id`, `proof_metadata`) — the fields that can hold a pointer to sensitive evidence like a voter ID scan.
- **`audit_logs.context_details` leak fix** — 7 call sites across `CESService.java`, `Consent.java`, and `Principal.java` were embedding raw identifiers into audit free-text (bypassing the masking above entirely); all now write a masked value. Historical rows already written are left as-is (the tamper-evident hash chain means retroactively editing them would need a full chain recomputation — flagged as a known, accepted limitation, not fixed).
- **Opaque `user_ref` drill-down** — masked API responses include a truncated HMAC reference so the console can navigate a principal's history without ever handling plaintext.

## B. Audit Log Retention & Archival

The stock system had **no retention or archival mechanism** for `audit_logs` — a pure, unbounded, append-only table.

- Converted to **native yearly range partitioning**.
- New **daily background job** (`JobManager.checkAndArchiveAuditPartitions`): pre-creates next year's partition ahead of the Dec 31 → Jan 1 rollover, and **detaches** (never deletes) any partition fully older than a configurable retention window (`AUDIT_RETENTION_MONTHS`, default 24 months) — renamed to `<name>_archive` and recorded in a new `audit_log_archive_registry` table.
- All read paths (console audit search, legal evidence certificate generation) transparently `UNION ALL` the live table with every archived table, so nothing is ever unsearchable — only moved out of the hot table.

## C. Grievance Enhancements

- **DPO-console grievance logging** — a **"+ Log Grievance"** button/form on the Grievances page, for a complaint that arrived by email, phone, letter, or in person rather than through the fiduciary's own app. New `channel` field (`PORTAL`/`EMAIL`/`PHONE`/`LETTER`/`IN_PERSON`/`OTHER`) tags how each grievance arrived, shown as a column in the list and detail view, while sharing the exact same SLA/audit/assignment/resolution pipeline as principal-submitted ones.
- **Dashboard deep-link** — the Dashboard's "Urgent: Pending DPO Action" table previously had no way to open a grievance's detail; rows now link straight to the Grievances page with that record's detail modal pre-opened.
- **Per-purpose revoke from the Principals page** — a "Revoke" button next to each granted purpose, so a DPO can act on a grievance requesting revocation of just one purpose without withdrawing everything (backed by the pre-existing but previously console-inaccessible partial-withdrawal capability in `withdraw_consent`).

## D. Console Bug Fixes & Consistency

- **Failed-search fallback bug** — searching for a principal that doesn't exist previously fell back to showing an unrelated "Recent Principals" list; now shows a clear "not found" message instead.
- **`link_user` cross-fiduciary bug** — the relink query had no `fiduciary_id` filter, so it could relink an identifier across unrelated fiduciaries; fixed to scope by fiduciary.
- **Dead audit search fixed** — `audit_logs` search was comparing a plaintext term against an already-hashed `user_id` column (could never match); now hashes the search term server-side first.
- **Console-wide date format** — every record date/timestamp across the DPO console (Dashboard, Principals, Grievances, Breach, Compliance, Audit, Reports, Legal, Policies, RoPA) now renders consistently as **dd/mm/yyyy** (and dd/mm/yyyy HH:mm:ss for timestamps), instead of the browser-locale-dependent format that could silently render as mm/dd/yyyy.

## E. Miscellaneous Fixes (carried from `CLAUDE.md`)

Smaller correctness fixes found and applied during local evaluation, not upstreamed:
1. `db/03z_enc_key.sh` missing its executable bit — silently aborted every migration after it.
2. Hardcoded `http://localhost:8080` in several frontend pages instead of `window.location.origin` — broke the app on any non-default port.
3. Policy edit payload missing `fiduciary_id` — editing any policy via the console failed outright.
4. CORS `Access-Control-Allow-Origin` echoed the entire raw multi-origin config verbatim (invalid per spec) instead of just the matching origin.
5. CORS `Access-Control-Allow-Headers` was missing `X-API-Secret`, breaking browser-based client integrations using both auth headers.
6. `record_consent` ignored the client-supplied `consent_mechanism` and always stored a fixed literal, defeating any WEB_FORM/VOICE/IN_PERSON distinction in the audit trail.
7. Stale in-memory policy cache never invalidated after create/update/publish/delete — `get_policy` could keep serving pre-publish content indefinitely.
