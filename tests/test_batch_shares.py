import pytest
from .conftest import PDF
from app.models import Role


@pytest.fixture()
def batch_world(client, make_user):
    h = {
        "alice": make_user("alice_bworld@x.com"),             # owner
        "user1": make_user("user1_bworld@x.com", Role.viewer),
        "user2": make_user("user2_bworld@x.com", Role.viewer),
        "user3": make_user("user3_bworld@x.com", Role.viewer),
        "admin": make_user("admin_bworld@x.com", Role.admin),
    }
    doc = client.post("/documents", files={"file": PDF}, headers=h["alice"]).json()["id"]
    return client, h, doc


def test_batch_share_candidates(batch_world):
    client, h, doc = batch_world
    res = client.get(f"/documents/{doc}/shares/candidates", headers=h["alice"])
    assert res.status_code == 200
    candidates = res.json()
    emails = [c["email"] for c in candidates]
    assert "user1_bworld@x.com" in emails
    assert "user2_bworld@x.com" in emails
    assert "user3_bworld@x.com" in emails
    assert "admin_bworld@x.com" not in emails   # admin should not be in candidates
    assert "alice_bworld@x.com" not in emails   # owner should not be in candidates


def test_batch_share_grant_success(batch_world):
    client, h, doc = batch_world
    payload = {
        "emails": ["user1_bworld@x.com", "user2_bworld@x.com"],
        "level": "read",
        "can_share": False,
        "can_download": True,
    }
    res = client.post(f"/documents/{doc}/shares/batch", headers=h["alice"], json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["total_granted"] == 2
    assert len(data["successful"]) == 2
    assert len(data["failed"]) == 0

    # Verify both users can now download
    assert client.get(f"/documents/{doc}/download", headers=h["user1"]).status_code == 200
    assert client.get(f"/documents/{doc}/download", headers=h["user2"]).status_code == 200
    assert client.get(f"/documents/{doc}/download", headers=h["user3"]).status_code == 404


def test_batch_share_mixed_valid_and_invalid(client, make_user):
    alice = make_user("alice_mix@x.com")
    u_valid = make_user("user_valid_mix@x.com", Role.viewer)
    admin = make_user("admin_mix@x.com", Role.admin)
    doc = client.post("/documents", files={"file": PDF}, headers=alice).json()["id"]

    payload = {
        "emails": ["user_valid_mix@x.com", "nonexistent@x.com", "admin_mix@x.com"],
        "level": "edit",
        "can_share": True,
        "can_download": True,
    }
    res = client.post(f"/documents/{doc}/shares/batch", headers=alice, json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["total_granted"] == 1
    assert data["successful"][0]["email"] == "user_valid_mix@x.com"
    assert len(data["failed"]) == 2

    # u_valid now has edit rights
    shares = client.get(f"/documents/{doc}/shares", headers=alice).json()
    u_share = next(s for s in shares if s["email"] == "user_valid_mix@x.com")
    assert u_share["level"] == "edit"
    assert u_share["can_share"] is True