from pathlib import Path

from app.models import Role
from .conftest import PW


def test_me_returns_current_user(client, make_user):
    h = make_user("ram@x.com", Role.owner)
    r = client.get("/auth/me", headers=h)
    assert r.status_code == 200
    assert r.json()["email"] == "ram@x.com" and r.json()["role"] == "owner"


def test_me_requires_login(client):
    assert client.get("/auth/me").status_code == 401


def test_swagger_form_login_works_and_failures_are_logged(client, make_user):
    make_user("ram@x.com")
    ok = client.post("/auth/token", data={"username": "ram@x.com", "password": PW})
    assert ok.status_code == 200 and ok.json()["access_token"]
    bad = client.post("/auth/token", data={"username": "ram@x.com", "password": "wrong-password-1"})
    assert bad.status_code == 401


def test_ui_is_served_with_strict_csp(client):
    r = client.get("/ui/")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "unsafe-inline" not in csp
    assert client.get("/ui/app.js").status_code == 200


def test_ui_never_writes_user_data_with_innerhtml():
    js = (Path(__file__).parent.parent / "app" / "static" / "app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "outerHTML" not in js and "insertAdjacentHTML" not in js
