import pytest
from .conftest import PDF
from app.models import Role


@pytest.fixture()
def setup(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com", Role.viewer)
    admin = make_user("admin@x.com", Role.admin)
    doc = client.post("/documents", files={"file": PDF}, headers=alice).json()["id"]
    return client, alice, bob, admin, doc


def test_stranger_cannot_touch_document(setup):
    c, alice, bob, admin, d = setup
    assert c.get(f"/documents/{d}", headers=bob).status_code == 404
    assert c.get(f"/documents/{d}/download", headers=bob).status_code == 404
    assert c.patch(f"/documents/{d}", json={"name": "x"}, headers=bob).status_code == 404
    assert c.put(f"/documents/{d}/content", files={"file": PDF}, headers=bob).status_code == 404
    assert c.delete(f"/documents/{d}", headers=bob).status_code == 404
    assert c.get(f"/documents/{d}/shares", headers=bob).status_code == 404
    assert c.post(f"/documents/{d}/shares", json={"email": "bob@x.com", "level": "edit"},
                  headers=bob).status_code == 404
    assert c.get(f"/documents/{d}/download", headers=alice).status_code == 200


def test_stranger_does_not_see_it_in_search(setup):
    c, alice, bob, admin, d = setup
    assert c.get("/documents", headers=bob).json() == []
    assert c.get("/documents?q=a", headers=bob).json() == []
    assert len(c.get("/documents", headers=alice).json()) == 1


def test_unauthenticated_rejected(setup):
    c, *_, d = setup
    assert c.get(f"/documents/{d}/download").status_code == 401
    assert c.get("/documents").status_code == 401


def test_read_grant_allows_download_not_edit(setup):
    c, alice, bob, admin, d = setup
    c.post(f"/documents/{d}/shares",
           json={"email": "bob@x.com", "level": "read", "can_download": True}, headers=alice)
    assert c.get(f"/documents/{d}/download", headers=bob).status_code == 200
    assert c.patch(f"/documents/{d}", json={"name": "x"}, headers=bob).status_code == 404
    assert c.delete(f"/documents/{d}", headers=bob).status_code == 404


def test_edit_grant_allows_edit_not_delete_or_share(setup):
    c, alice, bob, admin, d = setup
    c.post(f"/documents/{d}/shares", json={"email": "bob@x.com", "level": "edit"}, headers=alice)
    assert c.patch(f"/documents/{d}", json={"name": "new.pdf"}, headers=bob).status_code == 200
    assert c.delete(f"/documents/{d}", headers=bob).status_code == 404
    assert c.post(f"/documents/{d}/shares", json={"email": "admin@x.com", "level": "read"},
                  headers=bob).status_code == 404


def test_revoke_takes_access_back(setup):
    c, alice, bob, admin, d = setup
    c.post(f"/documents/{d}/shares",
           json={"email": "bob@x.com", "level": "edit", "can_download": True}, headers=alice)
    assert c.get(f"/documents/{d}/download", headers=bob).status_code == 200
    bob_id = next(u["id"] for u in c.get("/admin/users", headers=admin).json()
                  if u["email"] == "bob@x.com")
    assert c.delete(f"/documents/{d}/shares/{bob_id}", headers=alice).status_code == 204
    assert c.get(f"/documents/{d}/download", headers=bob).status_code == 404


def test_admin_cannot_read_or_delete_but_sees_metadata(setup):
    c, alice, bob, admin, d = setup
    assert c.get(f"/documents/{d}/download", headers=admin).status_code == 404
    assert c.get(f"/documents/{d}/view", headers=admin).status_code == 404
    assert any(x["id"] == d for x in c.get("/admin/documents", headers=admin).json())
    assert c.delete(f"/documents/{d}", headers=admin).status_code == 404
    assert c.get(f"/documents/{d}/download", headers=alice).status_code == 200


def test_non_admin_cannot_use_admin_endpoints(setup):
    c, alice, bob, admin, d = setup
    for h in (alice, bob):
        assert c.get("/admin/audit", headers=h).status_code == 403
        assert c.get("/admin/documents", headers=h).status_code == 403
        assert c.patch("/admin/users/1/role", json={"role": "admin"}, headers=h).status_code == 403


def test_register_cannot_choose_role(client):
    r = client.post("/auth/register", json={"email": "m@x.com",
                                            "password": "correct-horse-battery",
                                            "role": "admin"})
    assert r.json()["role"] == "viewer"


def test_upload_validation(client, make_user):
    alice = make_user("alice@x.com")
    bad = [("evil.exe", b"MZ...", "application/octet-stream"),
           ("fake.pdf", b"not a pdf", "application/pdf"),
           ("empty.pdf", b"", "application/pdf")]
    for f in bad:
        assert client.post("/documents", files={"file": f}, headers=alice).status_code in (400, 415)


def test_audit_trail_records_actions(setup):
    c, alice, bob, admin, d = setup
    c.post(f"/documents/{d}/shares",
           json={"email": "bob@x.com", "level": "read", "can_download": True}, headers=alice)
    c.get(f"/documents/{d}/download", headers=bob)
    actions = {r["action"] for r in c.get("/admin/audit", headers=admin).json()}
    assert {"upload", "grant", "download"} <= actions
