from app.email_service import (
    is_configured,
    notify_doc_access_email,
    notify_doc_suspend_email,
    notify_role_change_email,
    notify_security_lockout_email,
    notify_share_email,
    send_email_async,
)


def test_email_service_unconfigured_graceful():
    # In test environment, SMTP_HOST is unset, so is_configured should be False
    assert is_configured() is False

    # Dispatching async email should not throw or fail
    send_email_async("test@example.com", "Test Subject", "Test Body")


def test_email_notification_helpers_run_cleanly():
    # Verify all role-based email triggers fire without exceptions
    notify_role_change_email("user@test.com", "owner", "admin@test.com", ["admin@test.com"])
    notify_share_email("granter@test.com", "recip@test.com", "Doc.pdf", "read, download", "owner@test.com")
    notify_doc_access_email("download", "Doc.pdf", "viewer@test.com", "owner@test.com")
    notify_security_lockout_email("hacker@test.com", "127.0.0.1", ["admin@test.com"])
    notify_doc_suspend_email("Doc.pdf", "owner@test.com", "admin@test.com", "policy check", suspended=True)
    notify_doc_suspend_email("Doc.pdf", "owner@test.com", "admin@test.com", suspended=False)
