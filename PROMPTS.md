# How AI was Used & Issues Caught During Development

This document tracks how AI coding assistance (Antigravity & Claude) was utilized throughout the design, implementation, and hardening of TrustVault (DocShare), detailing architectural decisions, subtle bugs caught, and how they were resolved.

---

## 🛠️ Key Issues Caught and Resolved

### 1. Missing Authorization Helper
- **Issue:** Early code called an undefined `get_permission()` function.
- **Resolution:** Replaced with an explicit, index-optimized SQLAlchemy query joined on user and document IDs.

### 2. Download as a Role Level vs. Separate Discretionary Right
- **Issue:** Early implementation lumped "download" into access tiers (`read`, `edit`, `download`), which blurred viewing from copying.
- **Resolution:** Decoupled `can_download` into an independent boolean flag, allowing owners to grant read-only viewing without granting file download rights.

### 3. Timing Attack on Login Endpoint
- **Issue:** If an email did not exist, the server returned immediately without checking passwords, creating a measurable timing disparity compared to existing accounts.
- **Resolution:** Added a dummy password hash verification step so non-existent accounts take the exact same cryptographic processing time.

### 4. Renaming Extension Spoofing
- **Issue:** Renaming a file allowed altering the file extension (e.g. changing `contract.txt` to `contract.bat`).
- **Resolution:** Enforced immutable file extensions tied directly to the verified MIME type sniffed during initial upload.

### 5. Admin Zero-Trust Share Leak
- **Issue:** Users could share documents to the Admin account, allowing an administrator to view sensitive document contents.
- **Resolution:** Enforced strict zero-trust boundary: sharing to admins is rejected (400), and promoting any user to Admin automatically revokes all existing shares they held.

### 6. Double Timezone Offset on Scheduled Maintenance (IST Bug)
- **Issue:** HTML `<input type="datetime-local">` outputs naive local strings (e.g., `2026-11-06T07:07`). When Python parsed this string and applied `.astimezone(IST_TZ)`, Python assumed the naive string was UTC and added +5:30 a second time, shifting 7:07 AM to 12:39 PM.
- **Resolution:** Implemented `_parse_iso()` in `app/maintenance.py` to parse naive datetime-local strings as explicit IST before converting to UTC storage.

### 7. Naive UTC Timestamps Displaying 01:37 AM Instead of 07:07 AM IST
- **Issue:** SQLite stores `created_at` in naive UTC (`01:37:00`). When sent over the REST API without timezone markers, client browsers' `new Date()` parsed it as local time, rendering delivery at 1:37 AM instead of 7:07 AM IST.
- **Resolution:** Updated `/mailbox/messages` to return timezone-aware ISO strings with explicit `+00:00` UTC offsets, ensuring browser `Intl.DateTimeFormat` converts cleanly to Indian Standard Time.

### 8. Maintenance Early Reset Notification Gap
- **Issue:** When maintenance was scheduled for 1 hour but work finished early in 30 minutes, admin clicking reset did not dispatch a completion notice because `notify_users` was hardcoded to `false`.
- **Resolution:** Updated `resetBtn` in `app/static/app.js` and `toggle_maintenance` in `app/routes/admin.py` to invoke `notify_maintenance_completed` with exact IST timestamps and status notes.

### 9. Scheduled Maintenance Natural Window Auto-Expiry
- **Issue:** If a scheduled window ended naturally, the system remained in read-only mode until an admin manually clicked a button.
- **Resolution:** Added a 5-second asynchronous monitoring task in FastAPI's `lifespan()` context manager to automatically check window expiry and broadcast completion notices.

### 10. Silent Document Content Replacement
- **Issue:** When a document owner uploaded a new revised version via "Replace File (Same Type)", recipients were not alerted.
- **Resolution:** Updated `replace_content` in `app/routes/documents.py` to broadcast an update notice to all active recipients via In-App Mailbox and Telegram.

---

## 🧪 Verification & Proof of Robustness

- Removing the `require()` authorization call causes 17 tests in `tests/test_access.py` to fail immediately.
- Tampering with zero-width characters in `tests/test_watermark.py` causes forensic steganography extraction tests to fail loudly.
- All **121 automated unit tests** pass with 100% success rate across all security domains.
