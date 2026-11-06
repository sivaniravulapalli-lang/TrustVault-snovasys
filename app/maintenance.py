"""System Maintenance Mode State & Enforcer for TrustVault."""
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
from fastapi import HTTPException
from .models import Role, User

IST_TZ = timezone(timedelta(hours=5, minutes=30))

_maintenance_state: Dict[str, Any] = {
    "enabled": False,
    "reason": "Scheduled Server Upgrade & Security Maintenance",
    "enabled_at": None,
    "enabled_by": None,
    "scheduled_start": None,
    "scheduled_end": None,
    "is_scheduled": False,
    "completion_notified": False,
    "was_window_active": False,
}


def _parse_iso(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    try:
        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=IST_TZ)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def is_maintenance_active() -> bool:
    # If immediate freeze is enabled
    if _maintenance_state["enabled"]:
        return True
    
    # If scheduled window is configured
    if _maintenance_state.get("is_scheduled"):
        start = _parse_iso(_maintenance_state.get("scheduled_start"))
        end = _parse_iso(_maintenance_state.get("scheduled_end"))
        now = datetime.now(timezone.utc)
        if start and end and start <= now <= end:
            _maintenance_state["was_window_active"] = True
            return True
        elif end and now > end:
            # Auto-expired after window ends
            _maintenance_state["is_scheduled"] = False
            return False
            
    return False


def get_maintenance_status() -> Dict[str, Any]:
    check_and_notify_scheduled_expiry()
    active = is_maintenance_active()
    res = dict(_maintenance_state)
    res["active"] = active
    res["enabled"] = active
    return res


def set_maintenance_mode(
    enabled: bool,
    reason: str = "",
    enabled_by: str = "",
    scheduled_start: Optional[str] = None,
    scheduled_end: Optional[str] = None,
) -> Dict[str, Any]:
    _maintenance_state["enabled"] = bool(enabled)
    _maintenance_state["reason"] = reason or "Scheduled Server Upgrade & Security Maintenance"
    _maintenance_state["enabled_by"] = enabled_by if (enabled or scheduled_start) else None
    
    if scheduled_start and scheduled_end:
        _maintenance_state["is_scheduled"] = True
        _maintenance_state["scheduled_start"] = scheduled_start
        _maintenance_state["scheduled_end"] = scheduled_end
        _maintenance_state["completion_notified"] = False
        _maintenance_state["was_window_active"] = False
    else:
        _maintenance_state["is_scheduled"] = False
        _maintenance_state["scheduled_start"] = None
        _maintenance_state["scheduled_end"] = None
        _maintenance_state["was_window_active"] = False

    if enabled or _maintenance_state["is_scheduled"]:
        _maintenance_state["enabled_at"] = datetime.now(timezone.utc).isoformat()
    else:
        _maintenance_state["enabled_at"] = None

    return get_maintenance_status()


def notify_maintenance_completed(db_session=None, admin_email: str = ""):
    from .db import SessionLocal
    from .models import User, InboxMessage, Role
    from .telegram_service import notify_security_alert

    db = db_session or SessionLocal()
    close_db = db_session is None
    try:
        now_ist = datetime.now(timezone.utc).astimezone(IST_TZ).strftime("%d-%b-%Y %I:%M %p IST")
        restored_by_txt = f"Maintenance ended early by Administrator ({admin_email})" if admin_email else "Scheduled maintenance window has concluded"
        subj = "✅ System Maintenance Completed - TrustVault"
        msg_body = (
            f"Attention: System maintenance has concluded and normal operations have been restored.\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"✅ SYSTEM STATUS: OPERATIONAL (RESTORED)\n"
            f"   • Restored At  : {now_ist}\n"
            f"   • Status Note  : {restored_by_txt}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"All document uploads, modifications, and sharing permissions are now fully active.\n"
            f"Thank you for your patience and cooperation."
        )
        tg_text = (
            f"✅ System Maintenance Completed\n"
            f"Restored At: {now_ist}\n"
            f"Note: {restored_by_txt}\n"
            f"Status: Normal operations fully restored."
        )

        users = db.query(User).all()
        for u in users:
            db.add(InboxMessage(
                to_email=u.email,
                from_email="admin@docshare.com",
                subject=subj,
                body=msg_body,
            ))
        
        admin_chats = [u.telegram_chat_id for u in users if u.role == Role.admin and u.telegram_chat_id]
        notify_security_alert(tg_text, admin_chats)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        if close_db:
            db.close()


def check_and_notify_scheduled_expiry():
    """Checks if a scheduled maintenance window has ended and notifies all users."""
    if not _maintenance_state.get("is_scheduled") and not _maintenance_state.get("was_window_active"):
        return
    end = _parse_iso(_maintenance_state.get("scheduled_end"))
    now = datetime.now(timezone.utc)
    if end and now > end:
        _maintenance_state["is_scheduled"] = False
        _maintenance_state["enabled"] = False
        if not _maintenance_state.get("completion_notified"):
            _maintenance_state["completion_notified"] = True
            _maintenance_state["was_window_active"] = False
            notify_maintenance_completed(admin_email="")


def check_maintenance_write_allowed(user: User):
    """
    If maintenance is active (either immediate or active scheduled window):
    - Admin users are exempt.
    - Regular users (owners, viewers) are blocked from mutating operations.
    """
    if is_maintenance_active() and user.role != Role.admin:
        reason = _maintenance_state.get("reason") or "Scheduled maintenance in progress"
        raise HTTPException(
            status_code=423,
            detail=f"System Maintenance Active: {reason}. All write and modify operations are temporarily paused."
        )
