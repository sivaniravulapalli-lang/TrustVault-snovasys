# SNOVASYS TRUSTVAULT (DocShare)
> **Enterprise Document Sharing with Zero-Trust RBAC, Forensic Watermarking, and Immutable Audit Trails**

TrustVault is an enterprise-grade document sharing, custody, and exfiltration tracking platform. Document owners upload confidential files and grant granular, delegable permissions (read, edit, download, and re-share). Every single interaction is cryptographically audited, and an administrator oversees system governance, forensic verification, and maintenance without ever having access to raw document contents.

---

## 🚀 Key Features & Architectural Highlights

1. **Zero-Trust Role-Based Access Control (RBAC):**
   - **Admin:** Infrastructure governance, user role assignment, immutable audit inspection, forensic leak verification, and system maintenance. Strictly blocked from viewing, downloading, or managing document contents (HTTP 403 Forbidden).
   - **Document Owner:** Full lifecycle control over their own files (upload, metadata modification, version replacement, sharing delegation, and deletion).
   - **Viewer:** Restricted consumer permitted only to view inside the secure in-browser reader or download with forensic watermarks (if explicitly granted).

2. **Multi-Layer Forensic Watermarking & Exfiltration Tracking:**
   - **Layer 1 (Visual Overlay):** In-browser viewer and exported headers display recipient email, download timestamp in IST, and client IP address.
   - **Layer 2 (Invisible Zero-Width Steganography):** Injects invisible zero-width Unicode characters (`\u200B`, `\u200C`, `\u200D`) into document text encoding user ID and cryptographic custody tokens. Survives raw copy-pasting across external platforms.
   - **Layer 3 (SOC Forensic Extraction Console):** Security teams can paste leaked paragraphs or upload leaked files at `/admin/verify-watermark` to immediately identify the exfiltrating user, timestamp, and IP address.

3. **Cascading Delegation & Recursive Revocation:**
   - Owners can grant `can_share` (forward-delegation) to trusted recipients.
   - When an owner revokes access from an intermediate delegate, TrustVault's Directed Acyclic Graph (DAG) traversal engine recursively and automatically revokes access for all downstream recipients who received forwarded shares (`revoke_descendants`).

4. **Multi-Channel Real-Time Alerting Engine:**
   - **DocShare In-App Mailbox:** Built-in internal email client for all users with unread badge counters, instant dispatch on share, revoke, version replace, and maintenance notices.
   - **Telegram Bot Integration:** Webhook and polling integration providing instant push notifications for document events, role modifications, and SOC security alerts.

5. **System Maintenance Engine (IST Synchronized):**
   - **Immediate Emergency Freeze:** Locks the server into read-only mode during security incidents.
   - **Scheduled Maintenance Window:** Automated read-only enforcement during planned upgrade windows with Indian Standard Time (IST) accuracy.
   - **Background Auto-Expiry Loop:** Lifespan background task monitors window expiration every 5 seconds, auto-restoring operations and dispatching completion notices.
   - **Early Reset Broadcast:** If scheduled for 1 hour but maintenance concludes in 30 minutes, an admin can click `Reset / Resume Normal Operations` to immediately unblock the server and broadcast completion alerts in IST to all user inboxes and Telegram.

6. **AI-Powered Threat Intelligence & DLP:**
   - **AI Executive Summary:** Automatic 2-line executive briefing generation without exposing raw content.
   - **Data Loss Prevention (DLP Scan):** Scans file contents for sensitive PII, credit card patterns, passwords, and private keys before sharing.
   - **SOC Threat Log Analyzer:** Analyzes audit trail anomalies, privilege escalation attempts, and suspicious access patterns.

---

## 👥 Demo & Test Accounts

| Role | Email | Password | Primary Capabilities to Test |
|---|---|---|---|
| **System Admin** | `admin@docshare.com` | `AdminDocShare2026!` | Audit log inspection, user role promotions, forensic leak verification, system maintenance controls. |
| **Document Owner** | `owner@docshare.com` | `OwnerDocShare2026!` | Upload documents (`welcome_contract.txt`), edit metadata, replace versions, grant/revoke shares. |
| **Viewer** | `viewer@docshare.com` | `ViewerDocShare2026!` | View shared documents, watermarked downloads, in-app mailbox notifications. |

---

## 🔐 Per-Document Permissions Matrix

| Permission | Meaning & Security Boundary |
|---|---|
| **read** | Allows viewing the document inside the browser memory with real-time watermark overlay. |
| **edit** | Rename, change category, or upload a new version of the same file type (includes read). |
| **download** | Allows taking a local copy of the file with embedded zero-width steganography (separate from read/edit). |
| **can_share** | Forward-delegation: allows passing access to other users up to the level the sharer holds. |

*Note: Delete is never delegated; only the original document owner can delete.*

---

## 🔄 Replace File (Same Type) vs. Delete & Re-upload

| Action | Document UUID | Existing Recipient Access | Audit History Lineage |
|---|---|---|---|
| **Delete & Re-upload** | ❌ Destroyed | ❌ 404 Broken links for all viewers | ❌ Lineage broken |
| **Replace File (Same Type)** | ✅ **Preserved** | ✅ **100% Intact**; viewers receive new version | ✅ **Full SHA-256 lineage logged** + recipients notified via Mailbox & Telegram |

---

## 🛠️ Local Setup & Execution (Windows PowerShell)

```powershell
# 1. Activate Virtual Environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install Dependencies
pip install -r requirements.txt

# 3. Environment Configuration
copy .env.example .env

# 4. Seed Database & Admin Account
python -m app.seed

# 5. Run Uvicorn Server
uvicorn app.main:app --reload
```
Navigate to `http://127.0.0.1:8000/` for the web UI.

---
---

## 🌐 Live Deployment

**Live Application:** [SNOVASYS TRUSTVAULT](https://trustvault-snovasys.onrender.com)

**Platform:** Render



---

## 🧪 Comprehensive Automated Test Suite

Run the full 121 automated tests:
```powershell
pytest -q
```
**Results:** `121 passed in ~140s (100% pass rate)`

The test suite rigorously verifies:
- Stranger route discovery & access denial isolation (`test_stranger_routes.py`, `test_isolation.py`)
- Forensic watermarking & zero-width steganography integrity (`test_watermark.py`)
- Cascading revocation & delegation capping (`test_delegation.py`)
- System maintenance read-only enforcement & auto-expiry (`test_maintenance.py`)
- In-app mailbox messaging & notification dispatch (`test_messages.py`, `test_mailbox.py`)
- Admin zero-trust boundary & role transition cleanup (`test_admin_boundary.py`)
