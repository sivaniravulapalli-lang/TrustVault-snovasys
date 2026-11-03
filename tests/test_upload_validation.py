import io
import zipfile
from pathlib import Path

from app.config import MAX_UPLOAD_BYTES, UPLOAD_DIR
from app.models import Role
from .conftest import PDF

PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 20
JPG = b"\xff\xd8\xff" + b"0" * 20
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name in entries:
            z.writestr(name, "<x/>")
    return buf.getvalue()


DOCX = make_zip(["[Content_Types].xml", "word/document.xml"])


def up(c, who, name, data, ctype="application/octet-stream"):
    return c.post("/documents", files={"file": (name, data, ctype)}, headers=who)


def test_each_allowed_type_is_accepted_with_the_right_mime(client, make_user):
    alice = make_user("alice@x.com")
    cases = [("a.pdf", b"%PDF-1.4 x", "application/pdf"), ("a.png", PNG, "image/png"),
             ("a.jpg", JPG, "image/jpeg"), ("a.jpeg", JPG, "image/jpeg"),
             ("a.txt", b"hello", "text/plain"), ("a.docx", DOCX, DOCX_MIME)]
    for name, data, mime in cases:
        r = up(client, alice, name, data)
        assert r.status_code == 201, (name, r.text)
        assert r.json()["mime"] == mime


def test_extension_case_does_not_matter_and_name_keeps_a_clean_extension(client, make_user):
    alice = make_user("alice@x.com")
    r = up(client, alice, "REPORT.PDF", b"%PDF-1.4 x")
    assert r.status_code == 201 and r.json()["name"] == "REPORT.pdf"


def test_content_must_match_the_claimed_type(client, make_user):
    alice = make_user("alice@x.com")
    bad = [("a.pdf", PNG), ("a.png", b"%PDF-1.4 x"), ("a.jpg", b"hello"),
           ("a.docx", b"%PDF-1.4 x"), ("a.docx", b"PK\x03\x04 just a header"),
           ("a.docx", make_zip(["a.txt"])),                      # a zip, but not a Word file
           ("a.txt", b"\xff\xfe\x00 not utf-8"), ("a.txt", b"has\x00nul")]
    for name, data in bad:
        assert up(client, alice, name, data).status_code == 415, name


def test_other_extensions_and_missing_extensions_are_refused(client, make_user):
    alice = make_user("alice@x.com")
    for name in ("a.exe", "a.html", "a.svg", "a.php", "noext", "a.pdf.exe", ".pdf"):
        assert up(client, alice, name, b"%PDF-1.4 x").status_code == 415, name


def test_the_clients_content_type_header_is_ignored(client, make_user):
    alice = make_user("alice@x.com")
    assert up(client, alice, "a.exe", b"MZ...", "application/pdf").status_code == 415
    r = up(client, alice, "a.pdf", b"%PDF-1.4 x", "text/html")
    assert r.status_code == 201 and r.json()["mime"] == "application/pdf"


def test_size_limit_and_empty_files(client, make_user):
    alice = make_user("alice@x.com")
    just_fits = b"%PDF-" + b"0" * (MAX_UPLOAD_BYTES - 5)
    assert up(client, alice, "ok.pdf", just_fits).status_code == 201
    assert up(client, alice, "big.pdf", just_fits + b"0").status_code == 413
    assert up(client, alice, "empty.pdf", b"").status_code == 400


def test_path_tricks_in_the_filename_do_nothing(client, make_user):
    alice = make_user("alice@x.com")
    for name in ("../../evil.pdf", "..\\..\\evil.pdf", "/etc/evil.pdf"):
        r = up(client, alice, name, b"%PDF-1.4 x")
        assert r.status_code == 201, name
        assert "/" not in r.json()["name"] and "\\" not in r.json()["name"]
    assert not any("evil" in p.name for p in Path(UPLOAD_DIR).iterdir())   # stored under random names


def test_renaming_cannot_change_the_file_type(client, make_user):
    alice = make_user("alice@x.com")
    d = up(client, alice, "notes.txt", b"echo hi").json()["id"]
    for wanted in ("run.bat", "x.pdf.exe", "noext", "../../a.sh", "evil.ps1"):
        r = client.patch(f"/documents/{d}", json={"name": wanted}, headers=alice)
        assert r.status_code == 200
        assert r.json()["name"].endswith(".txt"), (wanted, r.json()["name"])


def test_replacing_content_must_keep_the_same_type(client, make_user):
    alice = make_user("alice@x.com")
    d = up(client, alice, "a.pdf", b"%PDF-1.4 x").json()["id"]
    assert client.put(f"/documents/{d}/content", files={"file": ("a.png", PNG, "image/png")},
                      headers=alice).status_code == 415
    assert client.put(f"/documents/{d}/content", files={"file": PDF}, headers=alice).status_code == 200


def test_only_owners_can_upload(client, make_user):
    viewer = make_user("v@x.com", Role.viewer)
    assert up(client, viewer, "a.pdf", b"%PDF-1.4 x").status_code == 403
    assert client.post("/documents", files={"file": PDF}).status_code == 401


def test_download_is_an_attachment_with_the_stored_type_and_nosniff(client, make_user):
    alice = make_user("alice@x.com")
    d = up(client, alice, "a.pdf", b"%PDF-1.4 x").json()["id"]
    r = client.get(f"/documents/{d}/download", headers=alice)
    assert r.headers["content-type"].startswith("application/pdf")
    assert "attachment" in r.headers["content-disposition"]
    assert r.headers["x-content-type-options"] == "nosniff"