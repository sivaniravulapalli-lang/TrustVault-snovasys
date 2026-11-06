from app.main import app
from app.models import Role
from .conftest import PDF


def doc_routes():
    """Every route that takes a document id, read from the app's own OpenAPI listing."""
    for path, ops in app.openapi()["paths"].items():
        if path.startswith("/documents/{doc_id}"):
            for method in sorted(ops):
                if method in ("get", "post", "put", "patch", "delete"):
                    yield method.upper(), path


def call(client, method, path, doc_id, headers=None):
    url = path.replace("{doc_id}", doc_id).replace("{user_id}", "1")
    kw = {"headers": headers or {}}
    if method == "PUT":
        kw["files"] = {"file": PDF}
    elif method in ("POST", "PATCH"):
        kw["json"] = {"email": "someone@x.com", "level": "read", "name": "x"}
    return client.request(method, url, **kw)


def upload(client, who):
    return client.post("/documents", files={"file": PDF}, headers=who).json()["id"]


def test_every_document_route_refuses_a_stranger(client, make_user):
    alice = make_user("alice@x.com")
    eve = make_user("eve@x.com", Role.viewer)
    d = upload(client, alice)
    routes = list(doc_routes())
    assert len(routes) >= 9                      # guards against finding nothing
    for method, path in routes:
        r = call(client, method, path, d, eve)
        assert r.status_code == 404, (method, path, r.status_code)
    assert client.get(f"/documents/{d}/download", headers=alice).status_code == 200


def test_every_document_route_needs_login(client, make_user):
    alice = make_user("alice@x.com")
    d = upload(client, alice)
    for method, path in doc_routes():
        r = call(client, method, path, d)
        assert r.status_code == 401, (method, path, r.status_code)


def test_after_access_is_taken_back_every_door_is_closed(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com", Role.viewer)
    d = upload(client, alice)
    client.post(f"/documents/{d}/shares", headers=alice,
                json={"email": "bob@x.com", "level": "edit", "can_share": True,
                      "can_download": True})
    assert client.get(f"/documents/{d}/download", headers=bob).status_code == 200
    bob_id = client.get(f"/documents/{d}/shares", headers=alice).json()[0]["user_id"]
    assert client.delete(f"/documents/{d}/shares/{bob_id}", headers=alice).status_code == 204
    for method, path in doc_routes():
        r = call(client, method, path, d, bob)
        assert r.status_code == 404, (method, path, r.status_code)


def test_unknown_document_looks_the_same_as_a_forbidden_one(client, make_user):
    alice = make_user("alice@x.com")
    eve = make_user("eve@x.com", Role.viewer)
    d = upload(client, alice)
    ghost = "00000000-0000-4000-8000-000000000000"
    real = client.get(f"/documents/{d}", headers=eve)
    fake = client.get(f"/documents/{ghost}", headers=eve)
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json()


def test_read_only_cannot_replace_content(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com", Role.viewer)
    d = upload(client, alice)
    client.post(f"/documents/{d}/shares", json={"email": "bob@x.com", "level": "read"}, headers=alice)
    assert client.put(f"/documents/{d}/content", files={"file": PDF}, headers=bob).status_code == 404
    assert client.patch(f"/documents/{d}", json={"name": "z"}, headers=bob).status_code == 404