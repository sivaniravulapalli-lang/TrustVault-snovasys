from app.models import Role, User


def test_telegram_status_lifecycle(client, make_user):
    user_hdr = make_user("owner@test.com", Role.owner)

    # 1. Initially unlinked
    r = client.get("/telegram/status", headers=user_hdr)
    assert r.status_code == 200
    data = r.json()
    assert data["connected"] is False

    # 2. Connect with valid numeric chat ID
    connect_r = client.post("/telegram/connect", json={"chat_id": "987654321"}, headers=user_hdr)
    assert connect_r.status_code == 200
    assert connect_r.json()["connected"] is True
    assert "98" in connect_r.json()["chat_id_masked"]

    # 3. Status should now show connected
    r2 = client.get("/telegram/status", headers=user_hdr)
    assert r2.status_code == 200
    assert r2.json()["connected"] is True

    # 4. Disconnect
    disc_r = client.post("/telegram/disconnect", headers=user_hdr)
    assert disc_r.status_code == 200
    assert disc_r.json()["connected"] is False

    # 5. Status returns unlinked
    r3 = client.get("/telegram/status", headers=user_hdr)
    assert r3.json()["connected"] is False


def test_telegram_invalid_chat_id(client, make_user):
    user_hdr = make_user("viewer@test.com", Role.viewer)
    bad_r = client.post("/telegram/connect", json={"chat_id": "not-a-number"}, headers=user_hdr)
    assert bad_r.status_code == 400


def test_telegram_1click_webhook(client, make_user):
    user_hdr = make_user("deep@test.com", Role.owner)

    # Generate 1-click token
    token_r = client.get("/telegram/link-code", headers=user_hdr)
    assert token_r.status_code == 200
    code = token_r.json()["code"]
    assert len(code) == 8

    # Simulate Telegram /start <token> webhook callback
    webhook_payload = {
        "message": {
            "text": f"/start {code}",
            "chat": {"id": 5544332211}
        }
    }
    wh_r = client.post("/telegram/webhook", json=webhook_payload)
    assert wh_r.status_code == 200

    # User should now be automatically connected
    st = client.get("/telegram/status", headers=user_hdr)
    assert st.status_code == 200
    assert st.json()["connected"] is True
