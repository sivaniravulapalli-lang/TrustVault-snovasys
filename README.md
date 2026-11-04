# TrustVault (DocShare) — Secure Document Sharing Platform

TrustVault is a zero-trust document sharing platform with strict per-document permissions, fine-grained delegation, and an append-only audit trail.

## Live Deployment & Demo Accounts

- **Live URL**: `https://trustvault-snovasys.onrender.com`

| Role | Email | Password | Intended Role Scope |
|---|---|---|---|
| **Admin** | `admin@docshare.com` | `AdminDocShare2026!` | Views system activity, audits, user permissions, suspends documents. Cannot read document contents. |
| **Document Owner** | `owner@docshare.com` | `OwnerDocShare2026!` | Uploads files, assigns per-document read/edit/download rights, revokes access. |
| **Viewer** | `viewer@docshare.com` | `ViewerDocShare2026!` | Accesses only documents explicitly shared with them. Cannot upload or delete. |

## Core Architectural Principles
1. **Server-Enforced Access Control**: Permissions are evaluated in the database on every request, ensuring instant revocation.
2. **Deny-by-Default**: Unknown actions or unshared files result in immediate `404 Not Found` responses to prevent IDOR and enumeration.
3. **Argon2 Password Hashing & JWT**: Industry-standard cryptographic authentication with constant-time dummy verifications against timing attacks.
4. **Append-Only Audit Trail**: Every sensitive action and refusal is recorded.
5. **Content-Verified File Storage**: Client MIME headers and file extensions are never trusted. Magic bytes are validated server-side, and storage names are randomized to prevent path traversal and arbitrary code execution.

## Local Setup (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# Edit .env: Provide SECRET_KEY (min 32 chars) and ADMIN_PASSWORD
python -m app.seed
uvicorn app.main:app --reload
```

## Running Tests

### Day 1: Authentication Suite
```powershell
pytest tests/test_auth.py -v
```

### Day 2: Upload Validation & Magic Byte Suite
```powershell
pytest tests/test_upload_validation.py -v
```
