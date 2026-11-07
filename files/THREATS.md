# Threats

| # | Threat | Mitigation | Proven by |
|---|---|---|---|
| 1 | A user reads, downloads, edits or deletes another user's document (including another owner) | one `can()`/`require()` for every action; deny by default; refusal answers 404 | `test_access.py`, `test_isolation.py` |
| 2 | A new route forgets the permission check | the test discovers every `{doc_id}` route from the app and tries each as a stranger, as someone whose access was removed, and anonymously | `test_stranger_routes.py` |
| 3 | A viewer with read access copies the file | `download` is a separate permission; read only shows the file in the app | `test_download_permission.py` |
| 4 | A delegate hands out more than they hold | level and download capped at the delegate's own; `can_share` cannot be passed on | `test_delegation.py` |
| 5 | A revoked person keeps access through someone they were forwarded by | cascade revoke of everything the revoked person granted | `test_delegation.py` |
| 6 | A user picks their own role at registration | no role field; everyone registers as viewer | `test_download_permission.py` |
| 7 | The admin reads confidential content, or is handed a document, or keeps access after promotion | admin is denied every document action; admin cannot be granted shares; promotion removes held shares; an owner with documents cannot be promoted | `test_admin_boundary.py`, `test_access.py` |
| 8 | A deleted document stays reachable | deleted = denied for everyone, file removed from disk | `test_isolation.py`, `test_download_permission.py` |
| 9 | Malicious upload (wrong type, fake content, huge file, path tricks) | allow-list, content check per type, 10 MB limit, request-size limit, random stored name, cleaned name | `test_upload_validation.py`, `test_hardening.py` |
| 10 | A harmless-looking text file is renamed to a script (`run.bat`) and downloaded | the extension of a document is fixed by its real type; replacing a file must keep the type | `test_upload_validation.py` |
| 11 | Forged, expired or unknown-user login tokens, `alg: none` | signature and expiry checked, algorithm pinned, user looked up on every request | `test_isolation.py` |
| 12 | Password guessing, one account from one address, many accounts from one address | throttling with 429, password not even checked while locked; same for the Swagger form login | `test_hardening.py` |
| 13 | Mass registration | 20 per address per hour, registrations audited | `test_hardening.py` |
| 14 | Weak signing key or admin password in production | server refuses to start / seed refuses | `test_hardening.py` |
| 15 | Search used to find documents the user cannot see | permission filter applied in SQL before any filter; filters only narrow; wildcard characters taken literally | `test_search_filters.py` |
| 16 | Actions leave no trace | upload, view, download, edit, delete, grant, revoke, role change, refused attempts, failed logins, registrations are logged in the same transaction as the action; no API can change or remove audit rows | `test_audit.py`, `test_audit_events.py` |
| 17 | Information leak through error pages or API listing | generic 500; `/docs` and `/openapi.json` off in production | `test_hardening.py` |
| 18 | Script injection through names shown in the test page | user data written with textContent only; strict CSP; test that the script never uses innerHTML | `test_auth.py` |
| 19 | A harmful or illegal document is uploaded and the admin may not read or delete it | admin can suspend it (reason required): frozen for everyone, file kept, restorable; every step audited | `test_views_and_suspend.py` |
| 20 | Someone tries to hand out more than they hold, or to change access they did not give | refused with 403/400 and recorded as `grant_refused` with what was wanted and what they hold | `test_views_and_suspend.py` |
| 21 | Admin cannot tell who can reach a document | read-only "who has access" view (rights, who granted, since when; never content) | `test_views_and_suspend.py` |

## Found while building (and fixed)
- An admin could be given a document and then read it; promotion to admin kept old shares. Fixed (row 7).
- Renaming a document could change its file type (`.txt` to `.bat`). Fixed (row 10).
- A `.docx` check that accepted any zip. Fixed (row 9).

## Still open
- Token revocation (logout), e-mail verification, e-mail one-time code for download.
- Audit table can be filled by repeated refused attempts (throttling limits it only for logins).
- Files are stored on the server's disk: on a platform with a temporary disk they must move to persistent storage.
- Granting access reveals whether an e-mail address has an account (to the owner only).
