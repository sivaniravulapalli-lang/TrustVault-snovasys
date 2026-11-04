import pytest
from .conftest import PDF
from app.models import Role


@pytest.fixture()
def world(client, make_user):
    h = {
        "alice": make_user("alice@x.com"),                 # owner
        "mgr": make_user("mgr@x.com", Role.viewer),         # manager
        "emp": make_user("emp@x.com", Role.viewer),         # employee
        "emp2": make_user("emp2@x.com", Role.viewer),
        "eve": make_user("eve@x.com", Role.viewer),         # stranger
        "admin": make_user("admin@x.com", Role.admin),
    }
    ids = {u["email"].split("@")[0]: u["id"]
           for u in client.get("/admin/users", headers=h["admin"]).json()}
    doc = client.post("/documents", files={"file": PDF}, headers=h["alice"]).json()["id"]
    return client, h, ids, doc


def share(c, d, who, email, level="read", can_share=False, can_download=True):
    return c.post(f"/documents/{d}/shares", headers=who,
                  json={"email": email, "level": level, "can_share": can_share,
                        "can_download": can_download})


def dl(c, d, who):
    return c.get(f"/documents/{d}/download", headers=who).status_code


def make_manager(c, h, d, level="read"):
    assert share(c, d, h["alice"], "mgr@x.com", level, True).status_code == 201


def test_manager_can_forward_to_employee(world):
    c, h, ids, d = world
    make_manager(c, h, d)
    assert dl(c, d, h["emp"]) == 404
    assert share(c, d, h["mgr"], "emp@x.com").status_code == 201
    assert dl(c, d, h["emp"]) == 200


def test_manager_cannot_grant_more_than_they_have(world):
    c, h, ids, d = world
    make_manager(c, h, d, "read")
    assert share(c, d, h["mgr"], "emp@x.com", "edit").status_code == 403
    assert dl(c, d, h["emp"]) == 404


def test_manager_cannot_pass_on_the_forward_right(world):
    c, h, ids, d = world
    make_manager(c, h, d)
    assert share(c, d, h["mgr"], "emp@x.com", "read", True).status_code == 403


def test_employee_and_plain_viewer_cannot_share(world):
    c, h, ids, d = world
    make_manager(c, h, d)
    share(c, d, h["mgr"], "emp@x.com")
    assert share(c, d, h["emp"], "emp2@x.com").status_code == 404
    share(c, d, h["alice"], "emp2@x.com")                  # read, no can_share
    assert share(c, d, h["emp2"], "eve@x.com").status_code == 404
    assert share(c, d, h["eve"], "eve@x.com").status_code == 404


def test_revoking_manager_also_revokes_employees(world):
    c, h, ids, d = world
    make_manager(c, h, d)
    share(c, d, h["mgr"], "emp@x.com")
    assert dl(c, d, h["emp"]) == 200
    assert c.delete(f"/documents/{d}/shares/{ids['mgr']}", headers=h["alice"]).status_code == 204
    assert dl(c, d, h["mgr"]) == 404
    assert dl(c, d, h["emp"]) == 404
    log = c.get("/admin/audit?action=revoke", headers=h["admin"]).json()
    assert any(r["detail"] == "cascade" and r["target_email"] == "emp@x.com" for r in log)


def test_removing_can_share_also_revokes_employees(world):
    c, h, ids, d = world
    make_manager(c, h, d)
    share(c, d, h["mgr"], "emp@x.com")
    share(c, d, h["alice"], "mgr@x.com", "read", False)    # owner takes forward right away
    assert dl(c, d, h["mgr"]) == 200
    assert dl(c, d, h["emp"]) == 404


def test_manager_revokes_only_their_own_grants(world):
    c, h, ids, d = world
    make_manager(c, h, d)
    share(c, d, h["mgr"], "emp@x.com")
    share(c, d, h["alice"], "emp2@x.com")                  # owner's own grant
    assert c.delete(f"/documents/{d}/shares/{ids['emp2']}", headers=h["mgr"]).status_code == 404
    assert dl(c, d, h["emp2"]) == 200
    assert c.delete(f"/documents/{d}/shares/{ids['emp']}", headers=h["mgr"]).status_code == 204
    assert dl(c, d, h["emp"]) == 404


def test_manager_cannot_overwrite_someone_elses_grant(world):
    c, h, ids, d = world
    make_manager(c, h, d, "edit")
    share(c, d, h["alice"], "emp@x.com", "read")           # owner gave read
    assert share(c, d, h["mgr"], "emp@x.com", "edit").status_code == 400
    assert c.patch(f"/documents/{d}", json={"name": "z"}, headers=h["emp"]).status_code == 404


def test_manager_cannot_target_owner_or_do_owner_things(world):
    c, h, ids, d = world
    make_manager(c, h, d, "edit")
    assert share(c, d, h["mgr"], "alice@x.com").status_code == 400
    assert c.delete(f"/documents/{d}", headers=h["mgr"]).status_code == 404
    assert dl(c, d, h["alice"]) == 200


def test_manager_lists_only_own_grants(world):
    c, h, ids, d = world
    make_manager(c, h, d)
    share(c, d, h["mgr"], "emp@x.com")
    share(c, d, h["alice"], "emp2@x.com")
    mine = c.get(f"/documents/{d}/shares", headers=h["mgr"]).json()
    assert [r["email"] for r in mine] == ["emp@x.com"]
    assert len(c.get(f"/documents/{d}/shares", headers=h["alice"]).json()) == 3


def test_forwarding_is_audited_with_who_did_it(world):
    c, h, ids, d = world
    make_manager(c, h, d)
    share(c, d, h["mgr"], "emp@x.com")
    rows = c.get("/admin/permission-changes", headers=h["admin"]).json()
    fwd = [r for r in rows if r["target_email"] == "emp@x.com"]
    assert fwd and fwd[0]["actor_email"] == "mgr@x.com"


def test_delegate_cannot_grant_download_they_lack(world):
    c, h, ids, d = world
    assert share(c, d, h["alice"], "mgr@x.com", "read", True, can_download=False).status_code == 201
    assert share(c, d, h["mgr"], "emp@x.com", "read", can_download=True).status_code == 403
    assert share(c, d, h["mgr"], "emp@x.com", "read", can_download=False).status_code == 201
    assert dl(c, d, h["emp"]) == 404                       # can view, cannot download


def test_removing_manager_download_revokes_employees(world):
    c, h, ids, d = world
    make_manager(c, h, d)                                  # manager has download
    share(c, d, h["mgr"], "emp@x.com")
    assert dl(c, d, h["emp"]) == 200
    share(c, d, h["alice"], "mgr@x.com", "read", True, can_download=False)
    assert dl(c, d, h["emp"]) == 404                       # invariant: child <= parent
