import logging
import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Iterable, Optional

from .config import SMTP_FROM, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_USER

logger = logging.getLogger("trustvault.email")


def is_configured() -> bool:
    return bool(SMTP_HOST)


def _send_sync(to_email: str, subject: str, body_text: str) -> bool:
    if not to_email:
        return False

    to_addr = to_email.strip().lower()

    # Always persist to in-app mailbox so users can inspect notifications immediately
    try:
        from .db import SessionLocal, get_db
        from .models import InboxMessage
        session_maker = None
        try:
            from .main import app
            if get_db in app.dependency_overrides:
                gen = app.dependency_overrides[get_db]()
                db = next(gen)
            else:
                db = SessionLocal()
        except Exception:
            db = SessionLocal()

        try:
            db.add(InboxMessage(to_email=to_addr,
                                from_email=SMTP_FROM,
                                subject=subject,
                                body=body_text))
            db.commit()
        finally:
            db.close()
    except Exception as e:
        logger.debug("Could not persist to InboxMessage: %s", e)

    # If SMTP is not set up in .env, log cleanly for developer inspection
    if not is_configured():
        logger.info(
            "[EMAIL PREVIEW (SMTP unconfigured)]\nTo: %s\nSubject: %s\n---\n%s\n---",
            to_addr, subject, body_text
        )
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = SMTP_FROM
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.attach(MIMEText(body_text, "plain", "utf-8"))

        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5.0)
        server.ehlo()
        if SMTP_PORT == 587:
            server.starttls()
            server.ehlo()
        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)

        server.sendmail(SMTP_FROM, [to_addr], msg.as_string())
        server.quit()
        logger.info("Email delivered to %s (Subject: %s)", to_addr, subject)
        return True
    except Exception as exc:
        logger.warning("Failed to send email to %s: %s", to_addr, exc)
        return False


def send_email_async(to_email: Optional[str], subject: str, body_text: str):
    """Non-blocking asynchronous email dispatch in a daemon thread."""
    if not to_email:
        return
    t = threading.Thread(target=_send_sync, args=(to_email.strip(), subject, body_text), daemon=True)
    t.start()


def broadcast_email_async(emails: Iterable[str], subject: str, body_text: str):
    for em in set(emails or []):
        if em:
            send_email_async(em, subject, body_text)


# ---------------------------------------------------------------------------
# High-Level Event Notification Helpers
# ---------------------------------------------------------------------------

def notify_role_change_email(user_email: str, new_role: str, actor_email: str,
                             admin_emails: Optional[Iterable[str]] = None):
    subject_user = "TrustVault: Your Role Has Been Updated"
    body_user = (
        f"Hello,\n\n"
        f"Your platform role on TrustVault has been updated to {new_role.upper()}.\n"
        f"Updated by: {actor_email}\n\n"
        f"— TrustVault Security"
    )
    send_email_async(user_email, subject_user, body_user)

    if admin_emails:
        subject_admin = f"TrustVault Audit: Role Changed ({user_email})"
        body_admin = (
            f"Security Audit Notification:\n\n"
            f"• Target User: {user_email}\n"
            f"• New Role: {new_role.upper()}\n"
            f"• Performed By: {actor_email}\n\n"
            f"— TrustVault Audit Log"
        )
        broadcast_email_async(admin_emails, subject_admin, body_admin)


def notify_share_email(granter_email: str, recipient_email: str, doc_name: str,
                       permissions: str, owner_email: Optional[str] = None):
    # 1. Notify Recipient
    subject_recip = f"Document Shared With You: '{doc_name}'"
    body_recip = (
        f"Hello,\n\n"
        f"{granter_email} has shared a document with you on TrustVault.\n\n"
        f"• Document: {doc_name}\n"
        f"• Permissions: {permissions}\n\n"
        f"Log in to your account to access this document.\n\n"
        f"— TrustVault"
    )
    send_email_async(recipient_email, subject_recip, body_recip)

    # 2. Notify Owner / Granter confirmation
    if owner_email and owner_email == granter_email:
        # Owner shared their own document -> Confirmation receipt
        subject_owner = f"Document Shared Successfully: '{doc_name}'"
        body_owner = (
            f"Hello,\n\n"
            f"You have successfully shared your document '{doc_name}' with {recipient_email}.\n\n"
            f"• Recipient: {recipient_email}\n"
            f"• Granted Permissions: {permissions}\n\n"
            f"You can manage or revoke access at any time from your TrustVault dashboard.\n\n"
            f"— TrustVault Security"
        )
        send_email_async(owner_email, subject_owner, body_owner)
    elif owner_email and owner_email != granter_email:
        # Someone with delegate rights shared the owner's document
        subject_owner = f"Share Activity on Your Document: '{doc_name}'"
        body_owner = (
            f"Hello,\n\n"
            f"Your document '{doc_name}' was shared with {recipient_email} by {granter_email}.\n"
            f"• Permissions: {permissions}\n\n"
            f"— TrustVault Security"
        )
        send_email_async(owner_email, subject_owner, body_owner)


def notify_doc_access_email(action: str, doc_name: str, actor_email: str, owner_email: str):
    if actor_email == owner_email:
        return
    verb = "downloaded" if action == "download" else "viewed"
    subject = f"Document {verb.capitalize()}: '{doc_name}'"
    body = (
        f"Hello,\n\n"
        f"User {actor_email} has {verb} your document '{doc_name}'.\n\n"
        f"— TrustVault Activity Monitoring"
    )
    send_email_async(owner_email, subject, body)


def notify_security_lockout_email(email: str, ip: Optional[str], admin_emails: Optional[Iterable[str]]):
    if not admin_emails:
        return
    subject = f"SECURITY ALERT: Account Locked ({email})"
    body = (
        f"Critical Security Alert:\n\n"
        f"Account {email} has been locked after 5 consecutive failed login attempts.\n"
        f"Client IP: {ip or 'unknown'}\n"
        f"A 15-minute cooldown is currently active.\n\n"
        f"— TrustVault Security Operations"
    )
    broadcast_email_async(admin_emails, subject, body)


def notify_doc_suspend_email(doc_name: str, owner_email: str, admin_email: str,
                             reason: Optional[str] = None, suspended: bool = True):
    if suspended:
        subject = f"TrustVault Notice: Document Suspended ('{doc_name}')"
        body = (
            f"Hello,\n\n"
            f"Your document '{doc_name}' has been temporarily frozen by an administrator ({admin_email}).\n"
            f"Reason: {reason or 'Under review'}\n\n"
            f"While suspended, the document cannot be viewed or downloaded.\n\n"
            f"— TrustVault Governance"
        )
    else:
        subject = f"TrustVault Notice: Document Restored ('{doc_name}')"
        body = (
            f"Hello,\n\n"
            f"Your document '{doc_name}' has been un-suspended by an administrator ({admin_email}).\n"
            f"It is active and accessible once again.\n\n"
            f"— TrustVault Governance"
        )
    send_email_async(owner_email, subject, body)
