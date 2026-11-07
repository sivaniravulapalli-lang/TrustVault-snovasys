# DocShare

A small document-sharing service: owners upload documents and give named people read, edit, download and re-share rights; every action is audited; an admin watches activity but never touches documents.

## Demo & Test Accounts

| Role | Email | Password | What to test |
|---|---|---|---|
| **Admin** | `admin@docshare.com` | `AdminDocShare2026!` | View full audit log, view all user permissions, suspend/restore documents (cannot read file contents). |
| **Document Owner** | `owner@docshare.com` | `OwnerDocShare2026!` | Upload new files, view own documents (`welcome_contract.txt`), share with viewers, revoke access. |
| **Viewer** | `viewer@docshare.com` | `ViewerDocShare2026!` | View shared documents (`welcome_contract.txt`), download copy. Cannot upload or delete. |

## Roles and permissions

**App roles** (everyone starts as viewer; only an admin changes roles):

| Role | Can do | Cannot do |
|---|---|---|
| admin | change user roles; see the audit log and permission changes; see metadata of all documents and who can reach each one (rights only); suspend and restore a document | read, view, download, edit, share or delete any document, even one shared with them or one they owned before promotion |
| owner | upload documents; give, change and take back access on their own documents; edit and delete them | touch documents of others without a grant |
| viewer | see and use only the documents shared with them, up to the permissions given | upload; delete; see anything not shared with them |

The admin account is created only by `python -m app.seed`. Registration never offers a role: everyone registers as viewer and an admin promotes. An owner who still has documents cannot be promoted to admin (409): an admin has no power over documents, so nobody could manage them. Promoting a user to admin also removes every share they held, together with everything they had forwarded from it.

**Per-document permissions** (given by the owner, per person, per document):

| Permission | Meaning |
|---|---|
| read | view the document inside the app |
| edit | rename, change category, upload a new version of the same file type (includes read) |
| download | take a copy of the file (needs read; NOT implied by edit) |
| can_share | pass access on to others, up to the level the sharer has themselves |

Delete is never delegated: only the owner can delete.

Office wording from the brief: Manager = owner; Assistant Manager = a viewer with `can_share` on that document; Employee = viewer. "Assistant Manager" is not a role, it is a permission on one document, so the same person can be an Assistant Manager on one document and an Employee on another.

**Suspending.** An admin who hears that a document is harmful can suspend it with a written reason, without reading it. A suspended document is frozen for everyone, the owner included (the owner still sees it in the list, marked suspended), and its file stays on disk. The admin can restore it. Suspending and restoring are audited and appear in the permission-changes page.

## Pages
- **My documents** (owners): what I uploaded, to whom I gave access and with which rights.
- **Shared with me** (owners and viewers): what others gave me, who owns it and what I may do with it. An owner who is given someone else's document is only a viewer of that document and sees it here, not under My documents.
- **Admin**: users and roles, audit log, permission changes, all documents (metadata) with who can reach each, suspend and restore.

## Delegation rules
- A person with `can_share` can give at most their own level, and `download` only if they have it.
- They cannot pass on `can_share` (the chain is one step).
- They can only revoke what they granted, and cannot change what the owner granted.
- If the owner reduces or removes a delegate's access, everything that delegate handed out is removed too (audit detail `cascade`).

## How access is decided
One function, `can()` in `app/authz.py`, used through `require()` by every route that touches a document. It denies by default (unknown action = deny, deleted document = deny, admin = deny). A refusal always answers `404`, so the existence of a document is not revealed; the attempt is written to the audit log as `access_denied`. Permissions are read from the database on every request, so revoking takes effect immediately even though the login token is still valid.

## Other protections
- Passwords: Argon2. Login by JWT (HS256, 60 minutes). The server refuses to start with a `SECRET_KEY` shorter than 32 characters.
- Login throttling from the audit log: 5 failures per account and address, 30 per address, 30 per account within 15 minutes, then `429`. A locked login does not check the password at all. Registration: 20 per address per hour.
- Uploads: allow-list (pdf, png, jpg, txt, docx), real content must match the type (a .docx must be a real Word package), 10 MB limit (huge requests refused before reading), random stored file name, names cleaned, the extension of a document can never be changed by renaming.
- The audit log says what changed (old and new name or category, size and fingerprint of a replaced file, new / changed / unchanged access) and also records attempts to hand out more than one holds (`grant_refused`).
- Security headers on every response; `/docs` and `/openapi.json` are off unless `ENABLE_DOCS=1`.
- The test page at `/ui/` writes user data with textContent only, and has a strict Content-Security-Policy.

## Run it locally (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env      # then fill in SECRET_KEY, ADMIN_EMAIL, ADMIN_PASSWORD
python -m app.seed
uvicorn app.main:app --reload
```
Open `http://127.0.0.1:8000/` for the test page. Set `ENABLE_DOCS=1` in `.env` to get `/docs`.
---

## 🌐 Live Deployment

**Live Application:** [SNOVASYS TRUSTVAULT](https://trustvault-snovasys.onrender.com)

**Platform:** Render

**Local Development:** http://127.0.0.1:8000/

---

## Tests
```powershell
pytest -q
```
The suite proves, among other things, that one user cannot reach another user's documents: every route that takes a document id is discovered from the app itself and tried by a stranger, by a person whose access was taken back, and by an anonymous caller (`tests/test_stranger_routes.py`, `tests/test_isolation.py`).

## Known limits
- A file already downloaded cannot be taken back or tracked. Mitigations: view-only by default, download is a separate permission, every view and download is audited.
- Deleting a document is a soft delete: the database row and audit entries stay, the stored file is removed from disk. There is no restore and no version history.
- Demoting an owner to viewer does not take away ownership of their existing documents (ownership is `owner_id`, not role).
- No malware scanning; a PDF may contain active content (it is shown by the browser's own PDF viewer).
- Search covers the document name, owner, category and upload date, not the file content; at most 100 results.
- Audit entries show the document's current name, not its name at the time. Audit rows are only added, never changed, but anyone with database access could change them.
- Login tokens cannot be revoked before they expire; there is no e-mail verification.
- Granting access answers differently for an unknown e-mail address (400) than for a known one (201): the owner can learn whether an address has an account.
- Not built on purpose: access by public link without login (the brief asks for named people, and anonymous access would make the audit trail meaningless).
