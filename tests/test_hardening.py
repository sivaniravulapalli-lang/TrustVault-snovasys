import pytest

from app.config import (LOGIN_MAX_PER_EMAIL_AND_IP, LOGIN_MAX_PER_IP, MAX_REQUEST_BYTES,
                        REGISTER_MAX_PER_IP_PER_HOUR, check_admin_password, check_secret)
from app.models import Role
from .conftest import PW


def login(c, email, password):
    return c.post("/auth/login", json={"email": email, "password": password})


def test_weak_secret_keys_are_refused():
    for bad in ("", "change-me", "short", "x" * 31, "please-change-me-" + "x" * 30):
        with pytest.raises(RuntimeError):
            check_secret(bad)
    assert check_secret("k" * 32) == "k" * 32


def test_weak_admin_passwords_are_refused():
    for bad in ("", "Admin@123", "short-pw-11"):
        with pytest.raises(SystemExit):
            check_admin_password(bad)
    assert check_admin_password("a-long-enough-pw") == "a-long-enough-pw"


def test_repeated_wrong_passwords_lock_that_login_even_for_the_right_password(client, make_user):
    make_user("alice@x.com")
    make_user("bob@x.com")
    for _ in range(LOGIN_MAX_PER_EMAIL_AND_IP):
        assert login(client, "alice@x.com", "wrong-password-1").status_code == 401
    r = login(client, "alice@x.com", PW)
    assert r.status_code == 429 and "retry-after" in r.headers
    assert login(client, "bob@x.com", PW).status_code == 200          # other accounts unaffected


def test_one_address_guessing_many_accounts_is_stopped(client, make_user):
    make_user("alice@x.com")
    for i in range(LOGIN_MAX_PER_IP):
        assert login(client, f"nobody{i}@x.com", "wrong-password-1").status_code == 401
    assert login(client, "alice@x.com", PW).status_code == 429


def test_the_form_login_used_by_swagger_is_throttled_too(client, make_user):
    make_user("alice@x.com")
    for _ in range(LOGIN_MAX_PER_EMAIL_AND_IP):
        client.post("/auth/token", data={"username": "alice@x.com", "password": "wrong-password-1"})
    r = client.post("/auth/token", data={"username": "alice@x.com", "password": PW})
    assert r.status_code == 429


def test_registration_is_limited_per_address_and_recorded(client, make_user):
    admin = make_user("admin@x.com", Role.admin)                       # counts as the first one
    for i in range(REGISTER_MAX_PER_IP_PER_HOUR - 1):
        r = client.post("/auth/register", json={"email": f"u{i}@x.com", "password": PW})
        assert r.status_code == 201
    r = client.post("/auth/register", json={"email": "one-too-many@x.com", "password": PW})
    assert r.status_code == 429
    rows = client.get("/admin/audit?action=register&limit=500", headers=admin).json()
    assert len(rows) == REGISTER_MAX_PER_IP_PER_HOUR


def test_oversized_request_is_refused_before_it_is_read(client, make_user):
    alice = make_user("alice@x.com")
    big = b"0" * (MAX_REQUEST_BYTES + 1)
    r = client.post("/documents", content=big,
                    headers={**alice, "Content-Type": "application/octet-stream"})
    assert r.status_code == 413


def test_docs_and_schema_are_off_and_security_headers_are_set(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "max-age" in r.headers["strict-transport-security"]
