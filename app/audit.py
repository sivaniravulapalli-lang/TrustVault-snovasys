from fastapi import Request
from sqlalchemy.orm import Session
from .models import AuditLog


def log(db: Session, actor, action, request: Request = None,
        doc=None, target_user_id=None, detail=None):
    db.add(AuditLog(
        actor_id=actor.id if actor else None, action=action,
        document_id=doc.id if doc else None,
        target_user_id=target_user_id, detail=detail,
        ip=request.client.host if request and request.client else None,
    ))
    # caller commits: the action and its log entry share one transaction
