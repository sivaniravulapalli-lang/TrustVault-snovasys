import uuid
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, aliased

from ..audit import log
from ..auth import require_role
from ..db import get_db
from ..models import AuditLog, Document, Permission, Role, User
from .shares import revoke_descendants

# every route in this router is admin-only
router = APIRouter(prefix="/admin", tags=["admin"],
                   dependencies=[Depends(require_role(Role.admin))])

PERMISSION_ACTIONS = ("grant", "revoke", "role_change", "grant_refused", "suspend", "unsuspend")


def _rows(db, actions=None, action=None, document_id=None, actor_id=None,
          date_from: Optional[date] = None, date_to: Optional[date] = None,
          limit=100, offset=0):
    Actor, Target = aliased(User), aliased(User)
    q = (db.query(AuditLog, Actor.email, Target.email, Document.name)
         .outerjoin(Actor, Actor.id == AuditLog.actor_id)
         .outerjoin(Target, Target.id == AuditLog.target_user_id)
         .outerjoin(Document, Document.id == AuditLog.document_id))
    if actions:
        q = q.filter(AuditLog.action.in_(actions))
    if action:
        q = q.filter(AuditLog.action == action)
    if document_id:
        q = q.filter(AuditLog.document_id == document_id)
    if actor_id:
        q = q.filter(AuditLog.actor_id == actor_id)
    if date_from:
        q = q.filter(AuditLog.created_at >= datetime.combine(
            date_from, datetime.min.time(), timezone.utc))
    if date_to:
        q = q.filter(AuditLog.created_at <= datetime.combine(
            date_to, datetime.max.time(), timezone.utc))
    rows = q.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return [{"id": r.id, "action": r.action, "at": r.created_at,
             "actor_id": r.actor_id, "actor_email": a,
             "target_user_id": r.target_user_id, "target_email": t,
             "document_id": str(r.document_id) if r.document_id else None,
             "document_name": n, "detail": r.detail, "ip": r.ip}
            for r, a, t, n in rows]


@router.get("/audit")
def audit(action: Optional[str] = None, document_id: Optional[uuid.UUID] = None,
          actor_id: Optional[int] = None,
          date_from: Optional[date] = None, date_to: Optional[date] = None,
          limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
          db: Session = Depends(get_db)):
    return _rows(db, None, action, document_id, actor_id, date_from, date_to, limit, offset)


@router.get("/permission-changes")   # grants, revokes and role changes in one view
def permission_changes(document_id: Optional[uuid.UUID] = None,
                       actor_id: Optional[int] = None,
                       date_from: Optional[date] = None, date_to: Optional[date] = None,
                       limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                       db: Session = Depends(get_db)):
    return _rows(db, PERMISSION_ACTIONS, None, document_id, actor_id,
                 date_from, date_to, limit, offset)


@router.get("/documents")   # metadata only, never content
def all_documents(db: Session = Depends(get_db)):
    rows = (db.query(Document, User.email).join(User, User.id == Document.owner_id)
            .order_by(Document.created_at.desc()).limit(500).all())
    return [{"id": str(d.id), "name": d.name, "owner_id": d.owner_id, "owner_email": email,
             "category": d.category, "size": d.size, "created_at": d.created_at,
             "suspended_at": d.suspended_at, "deleted_at": d.deleted_at} for d, email in rows]


@router.get("/documents/{doc_id}/access")   # who can reach a document: people and rights, no content
def document_access(doc_id: uuid.UUID, db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if not doc:
        raise HTTPException(404, "Not found")
    Granter = aliased(User)
    rows = (db.query(Permission, User.email, Granter.email)
            .join(User, User.id == Permission.user_id)
            .join(Granter, Granter.id == Permission.granted_by)
            .filter(Permission.document_id == doc.id)
            .order_by(Permission.created_at).all())
    return {"id": str(doc.id), "name": doc.name, "category": doc.category,
            "owner_id": doc.owner_id, "owner_email": doc.owner.email,
            "suspended_at": doc.suspended_at, "deleted_at": doc.deleted_at,
            "access": [{"user_id": p.user_id, "email": e, "level": p.level.value,
                        "can_share": p.can_share, "can_download": p.can_download,
                        "granted_by": g, "since": p.created_at} for p, e, g in rows]}


class SuspendIn(BaseModel):
    reason: str = Field(min_length=3, max_length=200)


@router.post("/documents/{doc_id}/suspend")
def suspend(doc_id: uuid.UUID, body: SuspendIn, request: Request,
            admin: User = Depends(require_role(Role.admin)), db: Session = Depends(get_db)):
    """Freeze a document for everyone, the owner included, without reading or deleting it."""
    doc = db.get(Document, doc_id)
    if not doc or doc.deleted_at is not None:
        raise HTTPException(404, "Not found")
    if doc.suspended_at is not None:
        raise HTTPException(409, "Already suspended")
    doc.suspended_at = datetime.now(timezone.utc)
    log(db, admin, "suspend", request, doc, detail=body.reason)
    db.commit()
    return {"id": str(doc.id), "suspended": True}


@router.post("/documents/{doc_id}/unsuspend")
def unsuspend(doc_id: uuid.UUID, request: Request,
              admin: User = Depends(require_role(Role.admin)), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if not doc or doc.deleted_at is not None:
        raise HTTPException(404, "Not found")
    if doc.suspended_at is None:
        raise HTTPException(409, "Not suspended")
    doc.suspended_at = None
    log(db, admin, "unsuspend", request, doc)
    db.commit()
    return {"id": str(doc.id), "suspended": False}


@router.get("/users")
def users(db: Session = Depends(get_db)):
    return [{"id": u.id, "name": u.name, "email": u.email, "role": u.role}
            for u in db.query(User).order_by(User.id).all()]


class RoleIn(BaseModel):
    role: Role


@router.patch("/users/{user_id}/role")
def set_role(user_id: int, body: RoleIn, request: Request,
             admin: User = Depends(require_role(Role.admin)),
             db: Session = Depends(get_db)):
    if user_id == admin.id:
        raise HTTPException(400, "Cannot change your own role")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "Not found")
    if body.role == Role.admin:
        owns = (db.query(Document.id)
                .filter(Document.owner_id == target.id, Document.deleted_at.is_(None))
                .first())
        if owns:
            # an admin may not touch documents, so nobody could manage these any more
            raise HTTPException(409, "User still owns documents; they must delete them first")
    old = target.role.value
    target.role = body.role
    log(db, admin, "role_change", request, target_user_id=target.id,
        detail=f"{old}->{body.role.value}")
    if body.role == Role.admin:
        # an admin never touches documents: drop every share they held,
        # and everything they had handed out from those shares
        held = db.query(Permission).filter(Permission.user_id == target.id).all()
        for p in held:
            doc = db.get(Document, p.document_id)
            forwarded = revoke_descendants(db, p.document_id, target.id)
            db.delete(p)
            log(db, admin, "revoke", request, doc, target.id, detail="role_change")
            for uid in forwarded:
                log(db, admin, "revoke", request, doc, uid, detail="cascade")
    db.commit()
    return {"id": target.id, "role": target.role}
