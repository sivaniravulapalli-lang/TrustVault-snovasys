from .conftest import PDF
from app.models import Role


def upload(c, who, category):
    return c.post("/documents", files={"file": PDF}, data={"category": category},
                  headers=who).json()["id"]


def test_category_filter_is_case_insensitive(client, make_user):
    alice = make_user("alice@x.com")
    upload(client, alice, "Finance")
    assert len(client.get("/documents?category=finance", headers=alice).json()) == 1
    assert len(client.get("/documents?category=FINANCE", headers=alice).json()) == 1
    assert client.get("/documents?category=hr", headers=alice).json() == []


def test_categories_only_list_what_the_user_can_see(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com", Role.viewer)
    fin = upload(client, alice, "Finance")
    upload(client, alice, "Legal")
    client.post(f"/documents/{fin}/shares", json={"email": "bob@x.com", "level": "read"},
                headers=alice)
    assert client.get("/documents/categories", headers=alice).json() == ["finance", "legal"]
    assert client.get("/documents/categories", headers=bob).json() == ["finance"]


def test_categories_for_a_stranger_is_empty_and_needs_login(client, make_user):
    alice = make_user("alice@x.com")
    carol = make_user("carol@x.com", Role.viewer)
    upload(client, alice, "Finance")
    assert client.get("/documents/categories", headers=carol).json() == []
    assert client.get("/documents/categories").status_code == 401