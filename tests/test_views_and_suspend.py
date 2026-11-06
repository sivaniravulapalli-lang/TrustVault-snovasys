from app.models import Role
from .conftest import PDF
from .test_stranger_routes import call, doc_routes


def put(c, who, category=None):
    data = {"category": category} if category else None
    r = c.post("/documents", files={"file": PDF}, data=data, headers=who)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def give(c, d, who, email, level="read", can_share=False, can_download=False):
    return c.post(f"/documents/{d}/shares", headers=who,
                  json={"email": email, "level": level, "can_share": can_share,
                        "can_download": can_download})


def user_id(c, admin, email):
    return next(u["id"] for u in c.get("/admin/users", headers=admin).json() if u["email"] == email)


def test_scope_separates_my_documents_from_shared_with_me(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com")                            # also an owner
    carol = make_user("carol@x.com", Role.viewer)
    mine = put(client, alice)
    theirs = put(client, bob)
    give(client, theirs, bob, "alice@x.com")
    ids = lambda who, q="": sorted(d["id"] for d in client.get("/documents" + q, headers=who).json())
    assert ids(alice, "?scope=mine") == [mine]
    assert ids(alice, "?scope=shared") == [theirs]
    assert ids(alice) == sorted([mine, theirs])
    assert ids(carol, "?scope=mine") == []
    assert client.get("/documents?scope=everything", headers=alice).status_code == 422


def test_each_row_names_the_owner_and_says_what_my_access_is(client, make_user):
    alice = make_user("alice@x.com")
    carol = make_user("carol@x.com", Role.viewer)
    d = put(client, alice)
    give(client, d, alice, "carol@x.com", can_download=True)
    row = client.get("/documents?scope=shared", headers=carol).json()[0]
    assert row["owner_email"] == "alice@x.com"
    assert row["my_access"] == {"owner": False, "level": "read", "can_share": False,
                                "can_download": True, "can_delete": False}
    assert client.get("/documents?scope=mine", headers=alice).json()[0]["my_access"]["owner"] is True


def test_owner_sees_who_has_access_but_others_only_see_what_they_gave(client, make_user):
    alice = make_user("alice@x.com")
    carol = make_user("carol@x.com", Role.viewer)
    dave = make_user("dave@x.com", Role.viewer)
    d = put(client, alice)
    give(client, d, alice, "carol@x.com", can_share=True, can_download=True)
    give(client, d, carol, "dave@x.com")
    emails = lambda who: sorted(s["email"] for s in client.get("/documents", headers=who).json()[0]["shared_with"])
    assert emails(alice) == ["carol@x.com", "dave@x.com"]
    assert emails(carol) == ["dave@x.com"]
    assert emails(dave) == []


def test_admin_can_freeze_a_document_for_everyone_and_restore_it(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com", Role.viewer)
    admin = make_user("admin@x.com", Role.admin)
    d = put(client, alice)
    give(client, d, alice, "bob@x.com", can_download=True)
    r = client.post(f"/admin/documents/{d}/suspend", json={"reason": "reported as harmful"}, headers=admin)
    assert r.status_code == 200
    for who in (alice, bob, admin):
        for method, path in doc_routes():
            assert call(client, method, path, d, who).status_code == 404, (method, path)
    row = client.get("/documents?scope=mine", headers=alice).json()[0]
    assert row["suspended"] is True                          # the owner can see why it vanished
    assert client.get("/documents?scope=shared", headers=bob).json() == []
    assert client.post(f"/admin/documents/{d}/unsuspend", headers=admin).status_code == 200
    assert client.get(f"/documents/{d}/download", headers=alice).status_code == 200
    assert client.get(f"/documents/{d}/download", headers=bob).status_code == 200
    rows = client.get("/admin/permission-changes", headers=admin).json()
    assert any(r["action"] == "suspend" and r["detail"] == "reported as harmful" for r in rows)
    assert any(r["action"] == "unsuspend" for r in rows)


def test_suspend_rules(client, make_user):
    alice = make_user("alice@x.com")
    admin = make_user("admin@x.com", Role.admin)
    d = put(client, alice)
    assert client.post(f"/admin/documents/{d}/suspend", json={"reason": "not allowed"}, headers=alice).status_code == 403
    assert client.post(f"/admin/documents/{d}/suspend", json={}, headers=admin).status_code == 422
    assert client.post(f"/admin/documents/{d}/suspend", json={"reason": "bad file"}, headers=admin).status_code == 200
    assert client.post(f"/admin/documents/{d}/suspend", json={"reason": "bad file"}, headers=admin).status_code == 409
    assert client.post(f"/admin/documents/{d}/unsuspend", headers=admin).status_code == 200
    assert client.post(f"/admin/documents/{d}/unsuspend", headers=admin).status_code == 409
    ghost = "00000000-0000-4000-8000-000000000000"
    assert client.post(f"/admin/documents/{ghost}/suspend", json={"reason": "bad file"}, headers=admin).status_code == 404


def test_admin_sees_who_can_reach_a_document_but_never_the_content(client, make_user):
    alice = make_user("alice@x.com")
    make_user("bob@x.com", Role.viewer)
    admin = make_user("admin@x.com", Role.admin)
    d = put(client, alice)
    give(client, d, alice, "bob@x.com", level="edit", can_download=True)
    r = client.get(f"/admin/documents/{d}/access", headers=admin)
    assert r.status_code == 200
    body = r.json()
    assert body["owner_email"] == "alice@x.com"
    assert [(p["email"], p["level"], p["can_download"], p["granted_by"]) for p in body["access"]] \
        == [("bob@x.com", "edit", True, "alice@x.com")]
    assert not {"content", "stored_name", "sha256"} & set(body)
    assert client.get(f"/documents/{d}/download", headers=admin).status_code == 404
    assert client.get(f"/admin/documents/{d}/access", headers=alice).status_code == 403
    listing = client.get("/admin/documents", headers=admin).json()
    assert listing[0]["owner_email"] == "alice@x.com"


def test_audit_says_what_changed(client, make_user):
    alice = make_user("alice@x.com")
    make_user("bob@x.com", Role.viewer)
    admin = make_user("admin@x.com", Role.admin)
    d = put(client, alice)
    client.patch(f"/documents/{d}", json={"name": "new.pdf", "category": "finance"}, headers=alice)
    client.put(f"/documents/{d}/content", headers=alice,
               files={"file": ("a.pdf", b"%PDF-1.4 a different and longer body", "application/pdf")})
    give(client, d, alice, "bob@x.com")
    give(client, d, alice, "bob@x.com", level="edit")
    give(client, d, alice, "bob@x.com", level="edit")
    rows = client.get("/admin/audit?limit=500", headers=admin).json()
    edits = [r["detail"] for r in rows if r["action"] == "edit"]
    assert any("name: a.pdf -> new.pdf" in e and "category:  -> finance" in e for e in edits)
    assert any(e.startswith("content: ") and " B -> " in e and "sha256" in e for e in edits)
    grants = [r["detail"] for r in reversed([r for r in rows if r["action"] == "grant"])]
    assert grants == ["new: read", "changed: read -> edit", "unchanged: edit"]


def test_trying_to_hand_out_more_than_you_hold_is_recorded(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com", Role.viewer)
    make_user("carol@x.com", Role.viewer)
    admin = make_user("admin@x.com", Role.admin)
    d = put(client, alice)
    give(client, d, alice, "bob@x.com", can_share=True)                       # read only, may share
    assert give(client, d, bob, "carol@x.com", level="edit").status_code == 403
    assert give(client, d, bob, "carol@x.com", can_share=True).status_code == 403
    assert give(client, d, bob, "carol@x.com", can_download=True).status_code == 403
    rows = [r for r in client.get("/admin/permission-changes", headers=admin).json()
            if r["action"] == "grant_refused"]
    assert len(rows) == 3
    assert all(r["actor_email"] == "bob@x.com" and r["target_email"] == "carol@x.com" for r in rows)
    assert any("wanted edit; has read,can_share" in r["detail"] for r in rows)
