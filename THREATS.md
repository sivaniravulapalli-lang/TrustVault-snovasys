# Threat Model — TrustVault

This document tracks identified attack vectors, mitigations, and test verifications as the system evolves.

| # | Threat | Mitigation | Proven by | Status |
|---|---|---|---|---|
| 1 | Credential Guessing / Brute-Force | Rate limiting derived from audit logs (5 failed attempts per IP/account window), Argon2 password hashing. | `tests/test_auth.py` | Closed |
| 2 | User Enumeration via Login Timing | Login verification executes a dummy Argon2 hash check even when the user is not found, keeping response time constant. | `tests/test_auth.py` | Closed |
| 3 | Token Forgery / Weak Secrets | Application enforces at least 32-character high-entropy `SECRET_KEY` on startup, rejecting default/weak keys. | `tests/test_auth.py` | Closed |
| 4 | Self-Assigned Admin/Owner Privilege at Registration | Registration endpoint binds role strictly to `viewer`; role escalation is only possible by an admin. | `tests/test_auth.py` | Closed |
| 5 | Tampered or Expired JWT Tokens | JWT expiration pinned to 60 minutes with strict cryptographic signature verification on every protected route. | `tests/test_auth.py` | Closed |
| 6 | Malicious File Upload via Extension Masquerading (e.g. `.exe` disguised as `.pdf`) | Deep content inspection (`sniff()`) verifies true magic bytes against whitelist (`%PDF-`, `\x89PNG`, `\xff\xd8\xff`, ZIP structure for DOCX). Rejects mismatches with `415`. | `tests/test_upload_validation.py` | Closed |
| 7 | Client-Side MIME Confusion / Stored XSS via Content Sniffing | Client-supplied `Content-Type` is ignored; server enforces stored MIME type, adds `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`. | `tests/test_upload_validation.py` | Closed |
| 8 | Path Traversal / Arbitrary Overwrite via Malicious Filenames (`../../evil.pdf`) | User filenames are sanitized for display only; actual storage uses random `uuid4().hex` on disk, completely isolating user paths. | `tests/test_upload_validation.py` | Closed |
| 9 | Denial of Service via Huge Payloads or Decompression Bombs (DOCX) | Immediate hard cap at `MAX_UPLOAD_BYTES` (413), empty file rejection (400), and zip safety limit checks (max 2000 entries, 50MB decompressed). | `tests/test_upload_validation.py` | Closed |
| 10 | Unauthorized File Upload by Viewer Role | Role-based gatekeeper rejects non-owners with `403 Forbidden` and unauthenticated requests with `401 Unauthorized`. | `tests/test_upload_validation.py` | Closed |

## Known Trade-offs Accepted for Day 1 & Day 2

- **Stateless Tokens**: JWTs cannot be blacklisted prior to the 60-minute expiry without maintaining a centralized redis/cache layer. We compensate by verifying user status and permissions directly in the database on every document request.
- **Synchronous Upload Validation**: Magic byte checks and DOCX zip-header parsing are executed synchronously in the request path. While this avoids background worker complexity, upload processing is bound to the worker thread for the duration of the read.
