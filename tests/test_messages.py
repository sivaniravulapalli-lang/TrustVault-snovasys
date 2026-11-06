"""Error messages must explain the problem without leaking anything (no account enumeration)."""
from app.config import LOGIN_MAX_PER_EMAIL_AND_IP
from .conftest import PW


def login(c, email, password):
    return c.post("/auth/login", json={"email": email, "password": password})


def test_failed_login_says_why_and_counts_down(client, make_user):
    make_user("alice@x.com")
    first = login(client, "alice@x.com", "wrong-password-1")
    assert first.status_code == 401
    assert first.json()["detail"] == (
        f"The email or password is incorrect. {LOGIN_MAX_PER_EMAIL_AND_IP - 1} of "
        f"{LOGIN_MAX_PER_EMAIL_AND_IP} attempts left.")
    second = login(client, "alice@x.com", "wrong-password-1")
    assert f"{LOGIN_MAX_PER_EMAIL_AND_IP - 2} of" in second.json()["detail"]


def test_last_failed_attempt_says_wait_then_locked(client, make_user):
    make_user("alice@x.com")
    for _ in range(LOGIN_MAX_PER_EMAIL_AND_IP - 1):
        login(client, "alice@x.com", "wrong-password-1")
    last = login(client, "alice@x.com", "wrong-password-1")
    assert last.status_code == 401 and "No attempts left" in last.json()["detail"]
    locked = login(client, "alice@x.com", PW)
    assert locked.status_code == 429 and "Try again in" in locked.json()["detail"]


def test_unknown_email_gets_exactly_the_same_message_as_wrong_password(client, make_user):
    make_user("alice@x.com")
    wrong_pw = login(client, "alice@x.com", "wrong-password-1")
    no_user = login(client, "ghost@x.com", "wrong-password-1")
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()      # same text, same count: nothing to learn


def test_rejected_upload_says_which_formats_are_allowed(client, make_user):
    h = make_user("alice@x.com")
    r = client.post("/documents", headers=h,
                    files={"file": ("old.doc", b"\xd0\xcf\x11\xe0 fake", "application/msword")})
    assert r.status_code == 415
    d = r.json()["detail"]
    assert ".doc files are not accepted" in d and "PDF, PNG, JPG, TXT, DOCX" in d


def test_fake_content_upload_says_so(client, make_user):
    h = make_user("alice@x.com")
    r = client.post("/documents", headers=h,
                    files={"file": ("x.pdf", b"not a pdf at all", "application/pdf")})
    assert r.status_code == 415 and "not a real PDF file" in r.json()["detail"]
