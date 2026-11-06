# TrustVault Threat Model & Mitigations

This document outlines the threat vectors evaluated during the design and development of TrustVault (DocShare), their cryptographic and architectural mitigations, and the test suites that prove them.

---

## 🛡️ Threat Mitigation Matrix

| # | Threat Vector | Cryptographic & Architectural Mitigation | Proven by Test Suite |
|---|---|---|---|
| **1** | A user reads, downloads, edits, or deletes another user's document without authorization | Single-chokepoint `can()` and `require()` authorization engine; deny-by-default; non-existent and forbidden docs answer HTTP 404 to prevent enumeration. | `test_access.py`, `test_isolation.py` |
| **2** | A developer introduces a new route and forgets the permission check | Dynamic route discovery reflects every `{doc_id}` route from FastAPI OpenAPI schema and executes attacks as an unauthenticated stranger, an unauthorized peer, and a revoked user. | `test_stranger_routes.py` |
| **3** | A viewer copies document text and leaks it to external public forums | Multi-layer forensic watermarking: Visible custody header stamp + Invisible zero-width unicode steganography (`\u200B`, `\u200C`, `\u200D`) injected into the text stream. | `test_watermark.py` |
| **4** | An attacker steals an exfiltrated snippet and claims it came from someone else | Forensic extraction console (`/admin/verify-watermark`) extracts the embedded zero-width token and matches user ID, IP address, and exact download timestamp against immutable audit records. | `test_watermark.py` |
| **5** | A delegate hands out higher permissions than they personally possess | Delegation capping: level and download rights are strictly bounded by the granter's own held rights; `can_share` cannot be re-delegated beyond 1 step. | `test_delegation.py` |
| **6** | A revoked user retains access via forwarded secondary shares | Recursive DAG traversal: `revoke_descendants` automatically cascades revocation down the entire sharing tree when an intermediate grant is revoked. | `test_delegation.py` |
| **7** | A user self-assigns an escalated role (Owner or Admin) during registration | Registration API accepts only email and password; all users register as `viewer` by default; role elevation requires an Admin. | `test_auth.py`, `test_download_permission.py` |
| **8** | An Admin exploits root access to read confidential document contents | Zero-Trust Principle: Admin role is strictly forbidden from document content access (`can()` returns False for Admin); promotion to Admin immediately revokes all previously held shares. | `test_admin_boundary.py`, `test_access.py` |
| **9** | A deleted document remains accessible via cached URLs or disk remnants | Soft-delete status marks document as permanently denied (`deleted_at`), and file payload on disk is unlinked immediately. | `test_isolation.py`, `test_download_permission.py` |
| **10** | Malicious file upload (extension spoofing, oversized payload, path traversal) | MIME magic byte sniffing (`sniff()`), strict allow-list (PDF, PNG, JPG, TXT, DOCX), Word package structure validation, 10 MB ceiling, and randomized UUID filenames on disk. | `test_upload_validation.py`, `test_hardening.py` |
| **11** | Dangerous executable upload disguised as text (`run.bat` or `.exe`) | Document file extensions are strictly immutable and tied to actual content type; renaming cannot alter extension; replacing content requires identical MIME type. | `test_upload_validation.py` |
| **12** | JWT tampering, signature forgery, or `alg: none` exploit | Cryptographic HMAC-SHA256 signature verification with minimum 32-character key requirement; algorithm pinning; user status re-validated from DB on every request. | `test_isolation.py`, `test_hardening.py` |
| **13** | Credential stuffing and distributed password brute-forcing | Argon2id password hashing with unique salt; exponential audit-log-backed throttling (max 5 failures per account/IP within 15 mins). | `test_hardening.py` |
| **14** | Unmonitored document tampering or silent version updates | Version replacement preserves Document UUID and lineage metadata, while automatically broadcasting update alerts to all active recipients via In-App Mailbox and Telegram. | `test_messages.py`, `test_mailbox.py` |
| **15** | Data tampering or race conditions during server upgrade / maintenance | System Maintenance Mode: Emergency freeze or IST-scheduled maintenance window enforces read-only operations across all write endpoints (`check_maintenance_write_allowed`). | `test_maintenance.py` |
| **16** | Scheduled maintenance window expires without resuming normal operations | Background Lifespan Monitor: Auto-clears maintenance mode upon window expiry and broadcasts completion notifications in IST to all user inboxes and Telegram. | `test_maintenance.py` |
| **17** | Search filter manipulation to enumerate hidden documents | Permission filtering is applied at SQL level before query execution; LIKE wildcard characters (`%`, `_`) are escaped literally. | `test_search_filters.py` |
| **18** | Insider threat exfiltrating sensitive PII (credit cards, passwords, SSNs) | Integrated DLP Scanner: Scans document contents for high-risk privacy violations before distribution. | `test_ai.py` |
| **19** | Malicious or non-compliant document circulation requiring immediate freeze | Admin Document Suspension: Freezes document access for all users (including owner) with mandatory written justification, preserving audit trail. | `test_views_and_suspend.py` |
| **20** | Cross-Site Scripting (XSS) via stored filenames or user metadata | Vanilla JS UI renders dynamic content strictly via `textContent` and `createElement`; strict Content-Security-Policy (CSP) headers applied. | `test_auth.py` |

---

## 🔍 Found While Building (and Resolved)

1. **Double Timezone Shift on Naive Datetime Strings:** Browser datetime-local inputs in IST were parsed by Python as UTC and re-shifted by +5:30. Resolved with explicit IST parsing.
2. **Naive UTC Timestamps Displaying Incorrect Client Times:** Database UTC timestamps were treated by browsers as local time (01:37 AM vs 07:07 AM IST). Resolved with ISO-8601 UTC timezone markers (`+00:00`).
3. **Admin Could Read Previously Shared Files After Promotion:** Promotion to Admin did not clear held shares. Resolved by stripping all permissions upon role elevation to Admin.
4. **Silent Document Version Replacements:** Viewers were unaware of content updates. Resolved by adding automatic In-App Mailbox and Telegram broadcasts upon file replacement.
5. **Early Maintenance Reset Notifications:** Early resets failed to notify users. Resolved by dispatching rich IST completion notices when admin resets maintenance early.
