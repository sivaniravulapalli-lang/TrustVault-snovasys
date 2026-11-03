# PROMPTS & AI Interaction Log

This document records the prompts used, AI responses, errors caught, and security fixes made throughout development.

---

### Entry 1: Authentication & Constant-Time Login Check
- **Date:** 2026-11-02
- **Prompt:**
  > "Generate a FastAPI JWT authentication module using passlib and python-jose with user registration and login endpoints."
- **What it produced:**
  The AI provided a basic login function that queried the user by email, and if `user is None`, immediately returned `HTTPException(status_code=401, detail="Invalid credentials")`.
- **What was wrong with it:**
  *User Enumeration via Timing Leak.* When an email did not exist in the database, the code returned in under 2ms. When an email existed, `pwd.verify()` ran Argon2 taking ~80ms. An attacker could measure request response times to reliably enumerate registered email addresses.
- **What I did instead:**
  Introduced a dummy password hash verification (`pwd.verify(password, DUMMY_HASH)`) when `user is None`. This ensures that every login attempt consumes identical processing time regardless of whether the email exists. Added a test in `tests/test_auth.py` to verify this behavior.
  *Fix Commit Reference:* `f63938d`

---

### Entry 2: Token Secret Key Validation
- **Date:** 2026-11-02
- **Prompt:**
  > "Add configuration loading with python-dotenv for SECRET_KEY and DATABASE_URL."
- **What it produced:**
  `SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")`.
- **What was wrong with it:**
  In a production environment, if the operator forgets to specify `SECRET_KEY`, the application silently falls back to a well-known default string. Anyone could forge admin tokens.
- **What I did instead:**
  Wrote `check_secret(key)` in `app/config.py` that raises a `RuntimeError` on startup if `SECRET_KEY` is missing, under 32 characters, or matches common weak values (`"secret"`, `"changeme"`).
  *Fix Commit Reference:* `f63938d`

---

### Entry 3: File Upload MIME-Type & Magic Byte Validation
- **Date:** 2026-11-03
- **Prompt:**
  > "Implement a FastAPI file upload endpoint for documents that checks the file extension against a whitelist and checks file.content_type."
- **What it produced:**
  The AI wrote validation that relied on `Path(file.filename).suffix` and `file.content_type == "application/pdf"`.
- **What was wrong with it:**
  *Client-Controlled Spoofing.* The `Content-Type` header and file extension are entirely controlled by the client. An attacker could upload a Windows executable (`payload.exe`) with header `Content-Type: application/pdf` or named `payload.pdf`, bypassing the check and planting malware on the server.
- **What I did instead:**
  Ignored the client's `Content-Type` header completely. Implemented deep magic byte inspection in `sniff(data, ext)`:
  - PDF: must begin with `%PDF-`
  - PNG: must begin with `\x89PNG\r\n\x1a\n`
  - JPG: must begin with `\xff\xd8\xff`
  - DOCX: must be a valid ZIP archive containing `[Content_Types].xml` and `word/` entries, with zip bomb protections (max 2000 entries, 50MB decompressed).
  - TXT: must be valid UTF-8 containing no null bytes (`\x00`).
  Verified via `tests/test_upload_validation.py`.

---

### Entry 4: Path Traversal Prevention & Safe Storage Naming
- **Date:** 2026-11-03
- **Prompt:**
  > "Write a function to save the uploaded document to disk using the original filename."
- **What it produced:**
  ```python
  with open(os.path.join(UPLOAD_DIR, file.filename), "wb") as f:
      f.write(data)
  ```
- **What was wrong with it:**
  *Arbitrary File Overwrite & Path Traversal.* Filenames containing directory traversal sequences (such as `../../etc/cron.d/malicious` or `..\\..\\windows\\system32\\evil.dll`) could write files outside the intended uploads folder, or overwrite existing critical user files.
- **What I did instead:**
  Separated the display name from the physical storage name:
  - Physical files on disk are named using random UUIDs: `uuid.uuid4().hex + ext`. The client-supplied filename never touches the server filesystem.
  - Display names are sanitized using regex (`re.sub(r"[^\w.\- ]", "_", ...)`) and pinned to the verified extension.
  - Downloads are forced with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
  Verified via `tests/test_upload_validation.py`.
