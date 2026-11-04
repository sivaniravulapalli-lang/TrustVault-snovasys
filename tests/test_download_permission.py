from pathlib import Path

import pytest

from .conftest import PDF
from app.config import UPLOAD_DIR
from app.models import Role


@pytest.fixture()
def setup(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com", Role.viewer)
    admin = make_user("admin@x.com", Role.admin)
    doc = client.post("/documents", files={"file": PDF}, headers=alice).json()["id"]
    return client, alice, bob, admin, doc


def grant(c, d, who, email, **kw):
    body = {"email": email, "level": "read", **kw}
    return c.post(f"/documents/{d}/shares", json=body, headers=who)


def test_read_only_can_view_but_not_download(setup):
    c, alice, bob, admin, d = setup
    grant(c, d, alice, "bob@x.com")
    assert c.get(f"/documents/{d}/view", headers=bob).status_code == 200
    assert c.get(f"/documents/{d}/download", headers=bob).status_code == 404


def test_edit_does_not_imply_download(setup):
    c, alice, bob, admin, d = setup
    grant(c, d, alice, "bob@x.com", level="edit")
    assert c.patch(f"/documents/{d}", json={"name": "n.pdf"}, headers=bob).status_code == 200
    assert c.get(f"/documents/{d}/download", headers=bob).status_code == 404


def test_download_flag_allows_download(setup):
    c, alice, bob, admin, d = setup
    grant(c, d, alice, "bob@x.com", can_download=True)
    assert c.get(f"/documents/{d}/download", headers=bob).status_code == 200


def test_view_is_inline_download_is_attachment(setup):
    c, alice, bob, admin, d = setup
    assert "inline" in c.get(f"/documents/{d}/view", headers=alice).headers["content-disposition"]
    assert "attachment" in c.get(f"/documents/{d}/download", headers=alice).headers["content-disposition"]


def test_stranger_and_admin_cannot_view(setup):
    c, alice, bob, admin, d = setup
    assert c.get(f"/documents/{d}/view", headers=bob).status_code == 404
    assert c.get(f"/documents/{d}/view", headers=admin).status_code == 404
    assert c.get(f"/documents/{d}/view").status_code == 401


def test_view_and_download_are_audited_separately(setup):
    c, alice, bob, admin, d = setup
    grant(c, d, alice, "bob@x.com", can_download=True)
    c.get(f"/documents/{d}/view", headers=bob)
    c.get(f"/documents/{d}/download", headers=bob)
    actions = [r["action"] for r in c.get("/admin/audit", headers=admin).json()]
    assert "view" in actions and "download" in actions


def test_removing_download_takes_effect_immediately(setup):
    c, alice, bob, admin, d = setup
    grant(c, d, alice, "bob@x.com", can_download=True)
    assert c.get(f"/documents/{d}/download", headers=bob).status_code == 200
    grant(c, d, alice, "bob@x.com", can_download=False)
    assert c.get(f"/documents/{d}/download", headers=bob).status_code == 404
    assert c.get(f"/documents/{d}/view", headers=bob).status_code == 200


def test_registration_always_gives_viewer_and_viewer_cannot_upload(client):
    r = client.post("/auth/register", json={"email": "new@x.com", "password": "correct-horse-battery"})
    assert r.json()["role"] == "viewer"
    tok = client.post("/auth/login", json={"email": "new@x.com",
                                           "password": "correct-horse-battery"}).json()["access_token"]
    assert client.post("/documents", files={"file": PDF},
                       headers={"Authorization": f"Bearer {tok}"}).status_code == 403


def test_admin_promotes_viewer_to_owner(client, make_user):
    admin = make_user("admin@x.com", Role.admin)
    client.post("/auth/register", json={"email": "m@x.com", "password": "correct-horse-battery"})
    mid = next(u["id"] for u in client.get("/admin/users", headers=admin).json()
               if u["email"] == "m@x.com")
    assert client.patch(f"/admin/users/{mid}/role", json={"role": "owner"},
                        headers=admin).status_code == 200
    tok = client.post("/auth/login", json={"email": "m@x.com",
                                           "password": "correct-horse-battery"}).json()["access_token"]
    assert client.post("/documents", files={"file": PDF},
                       headers={"Authorization": f"Bearer {tok}"}).status_code == 201


def test_delete_removes_file_from_disk(setup):
    c, alice, bob, admin, d = setup
    before = {p.name for p in Path(UPLOAD_DIR).iterdir()}
    assert c.delete(f"/documents/{d}", headers=alice).status_code == 204
    after = {p.name for p in Path(UPLOAD_DIR).iterdir()}
    assert len(after) == len(before) - 1
