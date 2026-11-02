from fastapi import HTTPException
from sqlalchemy.orm import Session

from .audit import log
from .models import Document, Permission, Role, User

KNOWN_ACTIONS = {"read", "download", "edit", "delete", "share"}
# action -> which permission levels allow it
ALLOWED = {
    "read":     {"read", "edit"},
    "download": {"read", "edit"},
    "edit":     {"edit"},
}
# "delete" is owner-only. "share" needs the owner, or a
# permission row with can_share=True.


def can(user: User, doc: Document, action: str, db: Session) -> bool:
    if action not in KNOWN_ACTIONS:
        return False                     # unknown action = deny by default
    if doc is None or doc.deleted_at is not None or doc.suspended_at is not None:
        return False                     # gone or frozen by an admin: nobody gets in
    if user.role == Role.admin:
        return False                     # admin manages users and watches activity, never touches documents
    if doc.owner_id == user.id:
        return True
    if action == "delete":
        return False
    perm = (db.query(Permission)
            .filter(Permission.document_id == doc.id, Permission.user_id == user.id)
            .first())
    if perm is None:
        return False
    if action == "share":
        return bool(perm.can_share)
    if action == "download":
        # viewing is not downloading: the owner must grant download explicitly
        return bool(perm.can_download) and perm.level.value in ALLOWED["download"]
    return perm.level.value in ALLOWED[action]


def require(user: User, doc: Document, action: str, db: Session,
            request=None) -> Document:
    if not can(user, doc, action, db):
        # record the refused attempt (visible to admin only), then answer 404
        detail = action if doc is not None else f"{action} (no such document)"
        log(db, user, "access_denied", request, doc, detail=detail)
        db.commit()
        raise HTTPException(404, "Not found")   # 404 so existence is not revealed
    return doc
