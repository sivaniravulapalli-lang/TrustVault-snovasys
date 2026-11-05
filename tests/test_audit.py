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


def test_denied_attempt_is_logged_with_emails(setup):
    c, alice, bob, admin, d = setup
    assert c.get(f"/documents/{d}/download", headers=bob).status_code == 404
    rows = c.get("/admin/audit?action=access_denied", headers=admin).json()
    assert len(rows) == 1
    assert rows[0]["actor_email"] == "bob@x.com"
    assert rows[0]["document_id"] == d and rows[0]["detail"] == "download"


def test_failed_login_is_logged(client, make_user):
    admin = make_user("admin@x.com", Role.admin)
    client.post("/auth/login", json={"email": "ghost@x.com", "password": "wrong-password-1"})
    rows = client.get("/admin/audit?action=login_failed", headers=admin).json()
    assert len(rows) == 1 and rows[0]["detail"] == "ghost@x.com"
    assert "wrong-password-1" not in str(rows)


def test_permission_changes_view(setup):
    c, alice, bob, admin, d = setup
    c.post(f"/documents/{d}/shares", json={"email": "bob@x.com", "level": "read"}, headers=alice)
    bob_id = next(u["id"] for u in c.get("/admin/users", headers=admin).json()
                  if u["email"] == "bob@x.com")
    c.delete(f"/documents/{d}/shares/{bob_id}", headers=alice)
    c.get(f"/documents/{d}/download", headers=alice)      # not a permission change
    rows = c.get("/admin/permission-changes", headers=admin).json()
    assert {r["action"] for r in rows} == {"grant", "revoke"}
    assert all(r["actor_email"] == "alice@x.com" and r["target_email"] == "bob@x.com"
               and r["document_name"] == "a.pdf" for r in rows)


def test_audit_date_filter(setup):
    c, alice, bob, admin, d = setup
    assert len(c.get("/admin/audit?date_from=2000-01-01", headers=admin).json()) >= 1
    assert c.get("/admin/audit?date_from=2999-01-01", headers=admin).json() == []
    assert c.get("/admin/audit?date_to=2000-01-01", headers=admin).json() == []


def test_permission_changes_admin_only(setup):
    c, alice, bob, admin, d = setup
    for h in (alice, bob):
        assert c.get("/admin/permission-changes", headers=h).status_code == 403
