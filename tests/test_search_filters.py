from datetime import datetime, timedelta, timezone

from app.models import Role


def put(c, who, name, category=None):
    data = {"category": category} if category else None
    r = c.post("/documents", files={"file": (name, b"%PDF-1.4 x", "application/pdf")},
               data=data, headers=who)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def names(c, who, query=""):
    return sorted(d["name"] for d in c.get("/documents" + query, headers=who).json())


def test_name_filter_matches_part_of_the_name_ignoring_case(client, make_user):
    alice = make_user("alice@x.com")
    put(client, alice, "Salary-2026.pdf")
    put(client, alice, "Contract.pdf")
    assert names(client, alice, "?q=salary") == ["Salary-2026.pdf"]
    assert names(client, alice, "?q=ACT") == ["Contract.pdf"]
    assert names(client, alice, "?q=zzz") == []


def test_wildcard_characters_in_the_search_are_taken_literally(client, make_user):
    alice = make_user("alice@x.com")
    put(client, alice, "a_b.pdf")
    put(client, alice, "axb.pdf")
    assert names(client, alice, "?q=a_b") == ["a_b.pdf"]
    assert names(client, alice, "?q=_") == ["a_b.pdf"]
    assert names(client, alice, "?q=%25") == []          # "%" must not mean "everything"


def test_owner_filter_and_it_never_widens_what_a_user_can_see(client, make_user):
    alice = make_user("alice@x.com")
    bob = make_user("bob@x.com")
    carol = make_user("carol@x.com", Role.viewer)
    eve = make_user("eve@x.com", Role.viewer)
    for who, name in ((alice, "from-alice.pdf"), (bob, "from-bob.pdf")):
        d = put(client, who, name)
        client.post(f"/documents/{d}/shares", json={"email": "carol@x.com", "level": "read"},
                    headers=who)
    assert names(client, carol) == ["from-alice.pdf", "from-bob.pdf"]
    assert names(client, carol, "?owner=alice@x.com") == ["from-alice.pdf"]
    assert names(client, carol, "?owner=ALICE@X.COM") == ["from-alice.pdf"]
    assert names(client, eve, "?owner=alice@x.com") == []        # no access, nothing found


def test_category_filter_ignores_case_and_combines_with_name(client, make_user):
    alice = make_user("alice@x.com")
    put(client, alice, "one.pdf", "Finance")
    put(client, alice, "two.pdf", "Legal")
    assert names(client, alice, "?category=finance") == ["one.pdf"]
    assert names(client, alice, "?category=legal&q=two") == ["two.pdf"]
    assert names(client, alice, "?category=legal&q=one") == []


def test_date_filters_include_today_and_exclude_other_days(client, make_user):
    alice = make_user("alice@x.com")
    put(client, alice, "today.pdf")
    today = datetime.now(timezone.utc).date()
    day = timedelta(days=1)
    assert names(client, alice, f"?date_from={today}") == ["today.pdf"]
    assert names(client, alice, f"?date_to={today}") == ["today.pdf"]
    assert names(client, alice, f"?date_from={today - day}&date_to={today + day}") == ["today.pdf"]
    assert names(client, alice, f"?date_from={today + day}") == []
    assert names(client, alice, f"?date_to={today - day}") == []


def test_deleted_documents_are_not_found(client, make_user):
    alice = make_user("alice@x.com")
    d = put(client, alice, "gone.pdf")
    assert names(client, alice) == ["gone.pdf"]
    client.delete(f"/documents/{d}", headers=alice)
    assert names(client, alice) == []
    assert names(client, alice, "?q=gone") == []


def test_search_rejects_a_malformed_date(client, make_user):
    alice = make_user("alice@x.com")
    assert client.get("/documents?date_from=not-a-date", headers=alice).status_code == 422