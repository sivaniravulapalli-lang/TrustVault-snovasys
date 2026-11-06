from .conftest import PDF
from app.models import Role


def upload(c, who):
    return c.post("/documents", files={"file": PDF}, headers=who).json()["id"]


def test_admin_ai_threat_analysis(client, make_user):
    admin = make_user("admin@docshare.com", Role.admin)
    viewer = make_user("viewer@docshare.com", Role.viewer)

    # 1. Admin can run AI threat analysis
    r = client.get("/admin/ai-threat-analysis", headers=admin)
    assert r.status_code == 200
    data = r.json()
    assert "threat_level" in data
    assert "anomalies" in data
    assert "recommendations" in data
    assert data["threat_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    # 2. Non-admin is strictly forbidden from running threat analysis
    r_bad = client.get("/admin/ai-threat-analysis", headers=viewer)
    assert r_bad.status_code == 403


def test_ai_document_summarize_and_dlp_authorized(client, make_user):
    alice = make_user("alice@docshare.com", Role.owner)
    bob = make_user("bob@docshare.com", Role.viewer)

    doc_id = upload(client, alice)

    # Share with bob
    client.post(f"/documents/{doc_id}/shares",
                json={"email": "bob@docshare.com", "level": "read"}, headers=alice)

    # 1. Alice (Owner) can run summarize and DLP scan
    r_sum = client.post(f"/documents/{doc_id}/summarize", headers=alice)
    assert r_sum.status_code == 200
    sum_data = r_sum.json()
    assert "summary" in sum_data
    assert "key_topics" in sum_data

    r_dlp = client.post(f"/documents/{doc_id}/scan-dlp", headers=alice)
    assert r_dlp.status_code == 200
    dlp_data = r_dlp.json()
    assert "classification" in dlp_data
    assert "findings" in dlp_data

    # 2. Bob (Authorized Viewer) can run summarize
    r_bob = client.post(f"/documents/{doc_id}/summarize", headers=bob)
    assert r_bob.status_code == 200


def test_ai_rbac_guardrail_unauthorized_denied(client, make_user):
    alice = make_user("alice@docshare.com", Role.owner)
    stranger = make_user("stranger@docshare.com", Role.viewer)
    admin = make_user("admin@docshare.com", Role.admin)

    doc_id = upload(client, alice)

    # 1. Stranger without permission cannot summarize (Denied 404/403)
    r_stranger = client.post(f"/documents/{doc_id}/summarize", headers=stranger)
    assert r_stranger.status_code in (403, 404)

    # 2. Stranger cannot run DLP scan (Denied 404/403)
    r_stranger_dlp = client.post(f"/documents/{doc_id}/scan-dlp", headers=stranger)
    assert r_stranger_dlp.status_code in (403, 404)

    # 3. Admin Boundary: Administrator CANNOT summarize or DLP scan documents (Admin cannot read documents!)
    r_admin_sum = client.post(f"/documents/{doc_id}/summarize", headers=admin)
    assert r_admin_sum.status_code == 404

    r_admin_dlp = client.post(f"/documents/{doc_id}/scan-dlp", headers=admin)
    assert r_admin_dlp.status_code == 404
