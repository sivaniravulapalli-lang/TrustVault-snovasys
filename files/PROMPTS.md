# How I used AI, and where it was wrong

DRAFT written from our chat history. Edit every entry so it says exactly what you did and saw, and be ready to explain each one in the interview.

I used Claude as a pair programmer: it wrote code and tests, I ran everything on my machine, read the results and decided. These are mistakes I caught.

## 1. A function that did not exist
The first `can()` called `get_permission()`, which was never defined. Caught when the code was read and run; replaced by an explicit query.

## 2. Wrong permission table
The `LEVELS` table listed "download" as a level. Download is a separate right, so this blurred "view" and "copy". Fixed by making `can_download` its own permission.

## 3. Login timing leak
When the e-mail did not exist, the first login code skipped the password hash check, so a wrong e-mail answered faster than a wrong password. Fixed with a dummy hash.

## 4. Unknown actions allowed for owners
The first `can()` let an owner do any action name, including misspelled ones. Fixed with `KNOWN_ACTIONS`: unknown means deny.

## 5. Refusals rolled back
The first version did not commit the "access denied" audit row before raising 404, so the row vanished. Fixed by committing before raising.

## 6. A full-file answer deleted my change
Claude gave me a complete `documents.py` built from its old copy and it would have removed the `.docx` support I had added. I noticed and asked; it then asked for my real file before replacing whole files.

## 7. Renaming could change the file type
The code Claude wrote let a document be renamed to anything, so a `.txt` could become `run.bat`. Found when we reviewed upload validation; a test failed first, then the fix (the extension is fixed by the real type).

## 8. Weak `.docx` check
Claude's first check accepted any zip starting with `PK`. Replaced by a check for the Word package structure and a size limit.

## 9. Admin could read what was shared with them
The first admin design only blocked reading by role, so sharing a document to an admin, or promoting someone who already had shares, gave the admin access. Found while reviewing requirement 5; fixed so admin is denied every document action, shares to admins are refused and promotion removes held shares.

## 10. Patches that did not compile
Two of Claude's patches forgot an import (`Role` in `shares.py`, `Permission` in `admin.py`). The test run showed dozens of failures with one cause, which I traced from the error message.

## 11. A test that tested nothing
Claude's first "every route" test found zero routes with my FastAPI version (the check `len(routes) >= 9` made it fail loudly instead of passing empty). Fixed by reading routes from the OpenAPI listing.

## What I checked myself
I removed the `require()` line from `download` and 17 tests failed, which showed the tests really guard it.
