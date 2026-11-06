import json
import logging
import threading
import urllib.request
import urllib.error
from typing import Iterable, Optional

from .config import TELEGRAM_BOT_TOKEN

logger = logging.getLogger("trustvault.telegram")


def is_configured() -> bool:
    return bool(TELEGRAM_BOT_TOKEN)


def _send_sync(chat_id: str, text: str) -> bool:
    if not TELEGRAM_BOT_TOKEN or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "TrustVault-Alerts/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            return resp.status == 200
    except Exception as exc:
        logger.debug("Telegram alert dispatch failed for %s: %s", chat_id, exc)
        return False


def send_message_async(chat_id: Optional[str], text: str):
    """Fire-and-forget telegram message dispatch in a daemon thread (non-blocking)."""
    if not is_configured() or not chat_id:
        return
    t = threading.Thread(target=_send_sync, args=(str(chat_id), text), daemon=True)
    t.start()


def broadcast_async(chat_ids: Iterable[str], text: str):
    for cid in set(chat_ids or []):
        if cid:
            send_message_async(cid, text)


# ---------------------------------------------------------------------------
# High-level Role-Based Event Helpers
# ---------------------------------------------------------------------------

def notify_role_change(user_email: str, new_role: str, actor_email: str,
                       user_chat_id: Optional[str] = None,
                       admin_chat_ids: Optional[Iterable[str]] = None):
    """
    1. Alert the user whose role changed.
    2. Alert admins that a role modification occurred.
    """
    if user_chat_id:
        msg = (
            f"ℹ️ *TrustVault Role Update*\n\n"
            f"Your platform role has been updated to *{new_role.upper()}* by `{actor_email}`."
        )
        send_message_async(user_chat_id, msg)

    if admin_chat_ids:
        admin_msg = (
            f"🛠️ *Admin Action: Role Changed*\n\n"
            f"• Target User: `{user_email}`\n"
            f"• New Role: *{new_role.upper()}*\n"
            f"• Updated By: `{actor_email}`"
        )
        broadcast_async(admin_chat_ids, admin_msg)


def notify_share(granter_email: str, recipient_email: str, doc_name: str,
                 permissions: str, recipient_chat_id: Optional[str] = None,
                 owner_email: Optional[str] = None, owner_chat_id: Optional[str] = None):
    """
    1. Alert recipient: file shared with them and with what permissions.
    2. Alert owner: confirmation that their file was shared.
    """
    if recipient_chat_id:
        msg = (
            f"📁 *TrustVault: Document Shared With You*\n\n"
            f"• Document: *{doc_name}*\n"
            f"• Shared by: `{granter_email}`\n"
            f"• Permissions: `{permissions}`"
        )
        send_message_async(recipient_chat_id, msg)

    if owner_chat_id:
        owner_msg = (
            f"✅ *TrustVault: Share Confirmation*\n\n"
            f"• Document: *{doc_name}*\n"
            f"• Recipient: `{recipient_email}`\n"
            f"• Granted by: `{granter_email}`\n"
            f"• Permissions: `{permissions}`"
        )
        send_message_async(owner_chat_id, owner_msg)


def notify_doc_access(action: str, doc_name: str, actor_email: str,
                      owner_email: str, owner_chat_id: Optional[str] = None):
    """
    Alert document owner when a viewer opens/views or downloads their document.
    """
    if not owner_chat_id or actor_email == owner_email:
        return

    icon = "⬇️" if action == "download" else "👁️"
    verb = "downloaded" if action == "download" else "viewed"
    msg = (
        f"{icon} *TrustVault: Document {action.capitalize()}ed*\n\n"
        f"• Document: *{doc_name}*\n"
        f"• Action: `{actor_email}` {verb} your document."
    )
    send_message_async(owner_chat_id, msg)


def notify_security_lockout(email: str, ip: Optional[str], admin_chat_ids: Optional[Iterable[str]]):
    """Alert admins when an account is locked due to repeated failed logins."""
    if not admin_chat_ids:
        return
    msg = (
        f"🚨 *SECURITY ALERT: Account Locked*\n\n"
        f"• Target Email: `{email}`\n"
        f"• Reason: 5 consecutive failed login attempts\n"
        f"• Client IP: `{ip or 'unknown'}`\n"
        f"• Protection: Cooldown active (15 minutes)"
    )
    broadcast_async(admin_chat_ids, msg)


def notify_security_alert(alert_text: str, admin_chat_ids: Optional[Iterable[str]]):
    """General security broadcast to admins."""
    if not admin_chat_ids:
        return
    msg = f"🚨 *SECURITY ALERT*\n\n{alert_text}"
    broadcast_async(admin_chat_ids, msg)


def notify_doc_suspend(doc_name: str, owner_email: str, owner_chat_id: Optional[str],
                       admin_email: str, reason: Optional[str] = None, suspended: bool = True):
    """Notify document owner when an admin freezes/unfreezes a document."""
    if suspended:
        if owner_chat_id:
            owner_msg = (
                f"⚠️ *TrustVault Notice: Document Suspended*\n\n"
                f"• Document: *{doc_name}*\n"
                f"• Action: Temporarily frozen by Admin (`{admin_email}`)\n"
                f"• Reason: *{reason or 'Policy / Security review'}*\n"
                f"• Status: Access is paused until un-suspended."
            )
            send_message_async(owner_chat_id, owner_msg)
    else:
        if owner_chat_id:
            owner_msg = (
                f"✅ *TrustVault Notice: Document Restored*\n\n"
                f"• Document: *{doc_name}*\n"
                f"• Action: Un-suspended by Admin (`{admin_email}`)\n"
                f"• Status: Your document is active and accessible again."
            )
            send_message_async(owner_chat_id, owner_msg)


def notify_access_denied(actor_email: str, doc_name_or_id: str, action: str,
                         admin_chat_ids: Optional[Iterable[str]]):
    """Alert admins when an unauthorized user attempts to access or perform an action on a doc."""
    if not admin_chat_ids:
        return
    msg = (
        f"⛔ *SECURITY NOTICE: Access Denied*\n\n"
        f"• Actor: `{actor_email}`\n"
        f"• Target: `{doc_name_or_id}`\n"
        f"• Action Attempted: `{action}`\n"
        f"• Outcome: Denied and logged to audit trail."
    )
    broadcast_async(admin_chat_ids, msg)
