from datetime import timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import current_user
from ..config import SMTP_USER
from ..db import get_db
from ..models import InboxMessage, Role, User

router = APIRouter(prefix="/mailbox", tags=["mailbox"])


def _user_emails(user: User) -> list[str]:
    emails = [user.email.lower()]
    # If the user is an admin, also allow seeing emails routed to generic admin addresses
    if user.role == Role.admin:
        emails.extend(["admin@docshare.com", "admin@example.com"])
        if SMTP_USER:
            emails.append(SMTP_USER.lower())
    return list(set(emails))


@router.get("/messages")
def get_messages(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Fetch all in-app emails for the current logged-in user."""
    emails = _user_emails(user)
    rows = (db.query(InboxMessage)
            .filter(InboxMessage.to_email.in_(emails))
            .order_by(InboxMessage.created_at.desc())
            .limit(50).all())
    return [
        {
            "id": r.id,
            "to": r.to_email,
            "from": r.from_email,
            "subject": r.subject,
            "body": r.body,
            "is_read": r.is_read,
            "created_at": (
                r.created_at.replace(tzinfo=timezone.utc).isoformat()
                if r.created_at and r.created_at.tzinfo is None
                else (r.created_at.isoformat() if r.created_at else "")
            ),
        }
        for r in rows
    ]


@router.get("/unread-count")
def get_unread_count(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Quick badge polling for unread emails."""
    emails = _user_emails(user)
    count = (db.query(InboxMessage)
             .filter(InboxMessage.to_email.in_(emails), InboxMessage.is_read == False)
             .count())
    return {"unread": count}


@router.post("/read-all")
def mark_read(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Mark all emails for this user as read."""
    emails = _user_emails(user)
    (db.query(InboxMessage)
     .filter(InboxMessage.to_email.in_(emails), InboxMessage.is_read == False)
     .update({"is_read": True}, synchronize_session=False))
    db.commit()
    return {"ok": True}


@router.post("/clear")
def clear_inbox(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Wipe messages for testing/cleanup."""
    emails = _user_emails(user)
    db.query(InboxMessage).filter(InboxMessage.to_email.in_(emails)).delete(synchronize_session=False)
    db.commit()
    return {"ok": True}
