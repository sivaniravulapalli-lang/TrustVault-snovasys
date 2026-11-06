from app.email_service import _send_sync
from app.models import Role


def test_inbox_lifecycle(client, make_user):
    user_hdr = make_user("bob_inbox@test.com", Role.viewer)

    # 1. Empty initially
    r = client.get("/mailbox/messages", headers=user_hdr)
    assert r.status_code == 200
    assert len(r.json()) == 0

    # 2. Simulate email delivery
    ok = _send_sync("bob_inbox@test.com", "Test Shared Document", "Alice shared 'Spec.pdf' with you.")
    assert ok is True

    # 3. Check message in inbox
    r2 = client.get("/mailbox/messages", headers=user_hdr)
    assert r2.status_code == 200
    msgs = r2.json()
    assert len(msgs) == 1
    assert msgs[0]["subject"] == "Test Shared Document"
    assert msgs[0]["is_read"] is False

    # 4. Check unread count
    cnt_r = client.get("/mailbox/unread-count", headers=user_hdr)
    assert cnt_r.status_code == 200
    assert cnt_r.json()["unread"] == 1

    # 5. Mark read
    read_r = client.post("/mailbox/read-all", headers=user_hdr)
    assert read_r.status_code == 200
    cnt_r2 = client.get("/mailbox/unread-count", headers=user_hdr)
    assert cnt_r2.json()["unread"] == 0

    # 6. Clear mailbox
    clear_r = client.post("/mailbox/clear", headers=user_hdr)
    assert clear_r.status_code == 200
    msgs_after = client.get("/mailbox/messages", headers=user_hdr).json()
    assert len(msgs_after) == 0
