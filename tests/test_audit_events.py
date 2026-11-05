from app.main import app
from app.models import Role
from .conftest import PDF


def user_id(c, admin, email):
    return next(u["id"] for u in c.get("/admin/users", headers=admin).json()
                if u["email"] == email)


def test_every_kind_of_document_action_is_recorded(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com", Role.viewer)
    admin = make_user("admin@x.com", Role.admin)
    d = client.post("/documents", files={"file": PDF}, headers=alice).json()["id"]
    client.post(f"/documents/{d}/shares", headers=alice,
                json={"email": "bob@x.com", "level": "read", "can_download": True})
    client.get(f"/documents/{d}/view", headers=bob)
    client.get(f"/documents/{d}/download", headers=bob)
    client.patch(f"/documents/{d}", json={"name": "new.pdf"}, headers=alice)
    client.put(f"/documents/{d}/content", files={"file": PDF}, headers=alice)
    client.delete(f"/documents/{d}/shares/{user_id(client, admin, 'bob@x.com')}", headers=alice)
    client.delete(f"/documents/{d}", headers=alice)
    rows = client.get("/admin/audit?limit=500", headers=admin).json()
    seen = {(r["action"], r["actor_email"]) for r in rows}
    assert {("upload", "alice@x.com"), ("grant", "alice@x.com"), ("view", "bob@x.com"),
            ("download", "bob@x.com"), ("edit", "alice@x.com"), ("revoke", "alice@x.com"),
            ("delete", "alice@x.com")} <= seen
    edits = [r["detail"] for r in rows if r["action"] == "edit"]
    assert any(e.startswith("name: a.pdf -> new.pdf") for e in edits)
    assert any(e.startswith("content:") for e in edits)
    assert all(r["ip"] for r in rows if r["document_id"])


def test_role_change_is_recorded_with_old_and_new_role(client, make_user):
    admin = make_user("admin@x.com", Role.admin)
    make_user("bob@x.com", Role.viewer)
    client.patch(f"/admin/users/{user_id(client, admin, 'bob@x.com')}/role",
                 json={"role": "owner"}, headers=admin)
    rows = client.get("/admin/permission-changes", headers=admin).json()
    assert any(r["action"] == "role_change" and r["detail"] == "viewer->owner"
               and r["actor_email"] == "admin@x.com" and r["target_email"] == "bob@x.com"
               for r in rows)


def test_history_survives_document_deletion(client, make_user):
    alice = make_user("alice@x.com")
    admin = make_user("admin@x.com", Role.admin)
    d = client.post("/documents", files={"file": PDF}, headers=alice).json()["id"]
    assert client.delete(f"/documents/{d}", headers=alice).status_code == 204
    rows = client.get(f"/admin/audit?document_id={d}", headers=admin).json()
    assert {"upload", "delete"} <= {r["action"] for r in rows}
    assert all(r["document_name"] == "a.pdf" for r in rows)


def test_audit_api_is_read_only():
    found = 0
    for path, ops in app.openapi()["paths"].items():
        if path.startswith("/admin/audit") or path.startswith("/admin/permission-changes"):
            found += 1
            assert set(ops) == {"get"}, path
    assert found >= 2