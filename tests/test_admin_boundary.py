from .conftest import PDF
from app.models import Role


def upload(c, who):
    return c.post("/documents", files={"file": PDF}, headers=who).json()["id"]


def user_id(c, admin, email):
    return next(u["id"] for u in c.get("/admin/users", headers=admin).json()
                if u["email"] == email)


def test_cannot_grant_access_to_an_admin(client, make_user):
    alice = make_user("alice@x.com")
    make_user("admin@x.com", Role.admin)
    d = upload(client, alice)
    r = client.post(f"/documents/{d}/shares",
                    json={"email": "admin@x.com", "level": "read"}, headers=alice)
    assert r.status_code == 400


def test_user_promoted_to_admin_loses_shared_access(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com", Role.viewer)
    admin = make_user("admin@x.com", Role.admin)
    d = upload(client, alice)
    client.post(f"/documents/{d}/shares",
                json={"email": "bob@x.com", "level": "read", "can_download": True}, headers=alice)
    assert client.get(f"/documents/{d}/view", headers=bob).status_code == 200
    r = client.patch(f"/admin/users/{user_id(client, admin, 'bob@x.com')}/role",
                     json={"role": "admin"}, headers=admin)
    assert r.status_code == 200
    assert client.get(f"/documents/{d}/view", headers=bob).status_code == 404
    assert client.get(f"/documents/{d}/download", headers=bob).status_code == 404


def test_owner_with_documents_cannot_become_admin_until_they_delete_them(client, make_user):
    alice = make_user("alice@x.com")
    admin = make_user("admin@x.com", Role.admin)
    d = upload(client, alice)
    aid = user_id(client, admin, "alice@x.com")
    r = client.patch(f"/admin/users/{aid}/role", json={"role": "admin"}, headers=admin)
    assert r.status_code == 409
    assert client.get(f"/documents/{d}/view", headers=alice).status_code == 200   # still hers
    assert client.delete(f"/documents/{d}", headers=alice).status_code == 204
    r = client.patch(f"/admin/users/{aid}/role", json={"role": "admin"}, headers=admin)
    assert r.status_code == 200
    assert client.get(f"/documents/{d}/view", headers=alice).status_code == 404