import base64
import json
import time

from jose import jwt

from app.config import SECRET_KEY
from app.models import Role
from .conftest import PDF
from .test_stranger_routes import call, doc_routes


def upload(client, who):
    return client.post("/documents", files={"file": PDF}, headers=who).json()["id"]


def test_two_owners_cannot_touch_each_others_documents(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com")                       # also an owner: peers, not strangers by role
    da, db = upload(client, alice), upload(client, bob)
    for method, path in doc_routes():
        assert call(client, method, path, da, bob).status_code == 404, ("bob->alice", method, path)
        assert call(client, method, path, db, alice).status_code == 404, ("alice->bob", method, path)
    for who, d in ((alice, da), (bob, db)):            # nothing was damaged by the attempts
        r = client.get(f"/documents/{d}/download", headers=who)
        assert r.status_code == 200 and r.content == PDF[1]


def test_sharing_one_document_does_not_expose_the_owners_other_documents(client, make_user):
    alice = make_user("alice@x.com")
    carol = make_user("carol@x.com", Role.viewer)
    shared, private = upload(client, alice), upload(client, alice)
    client.post(f"/documents/{shared}/shares", json={"email": "carol@x.com", "level": "edit",
                                                     "can_share": True, "can_download": True},
                headers=alice)
    for method, path in doc_routes():
        assert call(client, method, path, private, carol).status_code == 404, (method, path)
    assert [d["id"] for d in client.get("/documents", headers=carol).json()] == [shared]


def test_deleted_document_is_gone_for_everyone(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com", Role.viewer)
    d = upload(client, alice)
    client.post(f"/documents/{d}/shares", json={"email": "bob@x.com", "level": "edit",
                                                "can_share": True, "can_download": True},
                headers=alice)
    assert client.delete(f"/documents/{d}", headers=alice).status_code == 204
    for who in (alice, bob):
        for method, path in doc_routes():
            assert call(client, method, path, d, who).status_code == 404, (method, path)
    assert client.get("/documents", headers=alice).json() == []
    assert client.get("/documents", headers=bob).json() == []


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_forged_expired_and_unknown_user_tokens_are_refused(client, make_user):
    make_user("alice@x.com")                           # user id 1 exists
    later, earlier = int(time.time()) + 600, int(time.time()) - 600
    tokens = {
        "wrong secret": jwt.encode({"sub": "1", "exp": later}, "x" * 40, algorithm="HS256"),
        "alg none": _b64({"alg": "none", "typ": "JWT"}) + "." + _b64({"sub": "1", "exp": later}) + ".",
        "expired": jwt.encode({"sub": "1", "exp": earlier}, SECRET_KEY, algorithm="HS256"),
        "no such user": jwt.encode({"sub": "99999", "exp": later}, SECRET_KEY, algorithm="HS256"),
        "garbage": "not-a-token",
    }
    for label, tok in tokens.items():
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 401, label
    good = jwt.encode({"sub": "1", "exp": later}, SECRET_KEY, algorithm="HS256")
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {good}"}).status_code == 200