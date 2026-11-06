import pytest
from app.maintenance import get_maintenance_status, set_maintenance_mode


def test_maintenance_default_inactive(client):
    r = client.get("/maintenance/status")
    assert r.status_code == 200
    assert r.json()["enabled"] is False


def test_non_admin_cannot_toggle_maintenance(client, make_user):
    owner = make_user("maint_owner@docshare.com", role="owner")
    r = client.post("/admin/maintenance", headers=owner, json={"enabled": True})
    assert r.status_code == 403


def test_maintenance_workflow(client, make_user):
    admin = make_user("maint_admin@docshare.com", role="admin")
    owner = make_user("maint_owner2@docshare.com", role="owner")

    # 1. Enable maintenance mode
    r = client.post("/admin/maintenance", headers=admin, json={
        "enabled": True,
        "reason": "Emergency Database Upgrade & Patching",
        "notify_users": True
    })
    assert r.status_code == 200
    assert r.json()["enabled"] is True
    assert "Emergency Database Upgrade" in r.json()["reason"]

    # Status check confirms enabled
    status = client.get("/maintenance/status").json()
    assert status["enabled"] is True

    # 2. Owner upload blocked during maintenance (423)
    files = {"file": ("test.txt", b"secret text content", "text/plain")}
    r_upload = client.post("/documents", headers=owner, files=files)
    assert r_upload.status_code == 423
    assert "System Maintenance Active" in r_upload.json()["detail"]

    # 3. Disable maintenance mode
    r_off = client.post("/admin/maintenance", headers=admin, json={"enabled": False})
    assert r_off.status_code == 200
    assert r_off.json()["enabled"] is False

    # 4. Owner upload succeeds after maintenance is turned off
    files = {"file": ("test.txt", b"secret text content", "text/plain")}
    r_upload_ok = client.post("/documents", headers=owner, files=files)
    assert r_upload_ok.status_code == 201

    # Cleanup state
    set_maintenance_mode(False)


def test_scheduled_maintenance_window(client, make_user):
    from datetime import datetime, timezone, timedelta
    admin = make_user("maint_admin_sched@docshare.com", role="admin")
    owner = make_user("maint_owner_sched@docshare.com", role="owner")

    # 1. Schedule maintenance in the future (1 hour from now to 2 hours from now)
    future_start = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    future_end = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    r = client.post("/admin/maintenance", headers=admin, json={
        "enabled": False,
        "reason": "Scheduled cluster upgrade",
        "scheduled_start": future_start,
        "scheduled_end": future_end,
    })
    assert r.status_code == 200
    data = r.json()
    assert data["is_scheduled"] is True
    assert data["enabled"] is False  # Not active yet!

    # Status check confirms not active yet, write should be allowed
    status = client.get("/maintenance/status").json()
    assert status["enabled"] is False
    assert status["is_scheduled"] is True

    files = {"file": ("sched_test.txt", b"allowed before window", "text/plain")}
    r_up = client.post("/documents", headers=owner, files=files)
    assert r_up.status_code == 201

    # 2. Window is active right now (start 10 mins ago, end 50 mins from now)
    active_start = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    active_end = (datetime.now(timezone.utc) + timedelta(minutes=50)).isoformat()
    r_active = client.post("/admin/maintenance", headers=admin, json={
        "enabled": False,
        "reason": "Current scheduled window",
        "scheduled_start": active_start,
        "scheduled_end": active_end,
    })
    assert r_active.status_code == 200
    assert r_active.json()["enabled"] is True

    # Owner upload should now be blocked (423 Locked)
    files2 = {"file": ("sched_test2.txt", b"blocked during window", "text/plain")}
    r_blocked = client.post("/documents", headers=owner, files=files2)
    assert r_blocked.status_code == 423
    assert "System Maintenance Active" in r_blocked.json()["detail"]

    # 3. Clean up
    set_maintenance_mode(False)
