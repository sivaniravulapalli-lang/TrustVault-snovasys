import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from ..audit import log
from ..auth import current_user
from ..authz import require
from ..db import get_db
from ..email_service import notify_share_email
from ..maintenance import check_maintenance_write_allowed
from ..models import Document, Level, Permission, Role, User
from ..telegram_service import notify_share

router = APIRouter(prefix="/documents/{doc_id}/shares", tags=["shares"])

RANK = {Level.read: 1, Level.edit: 2}


def describe(level, can_share: bool, can_download: bool) -> str:
    """Short text for the audit log, e.g. "read,can_download"."""
    return (getattr(level, "value", level) + (",can_share" if can_share else "")
            + (",can_download" if can_download else ""))


def refuse(db: Session, user: User, request: Request, doc: Document, target, status: int,
           message: str, why: str):
    """Record an attempt to hand out more than allowed, then answer with the error."""
    log(db, user, "grant_refused", request, doc, target.id if target else None, detail=why[:500])
    db.commit()
    raise HTTPException(status, message)


class GrantIn(BaseModel):
    email: EmailStr
    level: Level
    can_share: bool = False      # only the owner may set this
    can_download: bool = False   # delegates may only pass on what they have


class BatchGrantIn(BaseModel):
    emails: Optional[list[EmailStr]] = None
    email: Optional[EmailStr] = None
    level: Level = Level.read
    can_share: bool = False
    can_download: bool = False


def revoke_descendants(db: Session, doc_id, user_id: int) -> list:
    """Remove every permission handed out (directly or through others) by user_id.
    This is what makes revoking a manager also revoke the manager's employees."""
    removed, seen, frontier = [], {user_id}, [user_id]
    while frontier:
        rows = (db.query(Permission)
                .filter(Permission.document_id == doc_id,
                        Permission.granted_by.in_(frontier)).all())
        frontier = []
        for p in rows:
            removed.append(p.user_id)
            db.delete(p)
            if p.user_id not in seen:
                seen.add(p.user_id)
                frontier.append(p.user_id)
    return removed


@router.post("", status_code=201)
def grant(doc_id: uuid.UUID, body: GrantIn, request: Request,
          user: User = Depends(current_user), db: Session = Depends(get_db)):
    check_maintenance_write_allowed(user)
    # owner, or someone the owner allowed to share (can_share)
    doc = require(user, db.get(Document, doc_id), "share", db, request)
    is_owner = doc.owner_id == user.id
    mine = None if is_owner else (
        db.query(Permission).filter_by(document_id=doc.id, user_id=user.id).one())

    target = db.query(User).filter(User.email == body.email.lower()).first()
    if (not target or target.id == user.id or target.id == doc.owner_id
            or target.role == Role.admin):
        raise HTTPException(400, "Cannot share with that user")

    wanted = describe(body.level, body.can_share, body.can_download)
    if not is_owner:
        have = describe(mine.level, mine.can_share, mine.can_download)
        if body.can_share:
            refuse(db, user, request, doc, target, 403, "Only the owner can allow re-sharing",
                   f"re-share right is owner-only; wanted {wanted}")
        if RANK[body.level] > RANK[mine.level]:
            refuse(db, user, request, doc, target, 403, "Cannot grant more than you have",
                   f"wanted {wanted}; has {have}")
        if body.can_download and not mine.can_download:
            refuse(db, user, request, doc, target, 403, "Cannot grant more than you have",
                   f"wanted {wanted}; has {have}")

    perm = db.query(Permission).filter_by(document_id=doc.id, user_id=target.id).first()
    if perm and not is_owner and perm.granted_by != user.id:
        refuse(db, user, request, doc, target, 400, "Cannot share with that user",
               "tried to change access the owner or someone else gave")   # not yours to change

    cascaded = []
    before = describe(perm.level, perm.can_share, perm.can_download) if perm else None
    if perm:
        # owner shrinking a manager's rights also shrinks what the manager handed out
        if perm.can_share and (not body.can_share
                               or RANK[body.level] < RANK[perm.level]
                               or (perm.can_download and not body.can_download)):
            cascaded = revoke_descendants(db, doc.id, target.id)
        perm.level, perm.can_share, perm.granted_by = body.level, body.can_share, user.id
        perm.can_download = body.can_download
    else:
        db.add(Permission(document_id=doc.id, user_id=target.id, level=body.level,
                          can_share=body.can_share, can_download=body.can_download,
                          granted_by=user.id))

    if before is None:
        detail = f"new: {wanted}"
    elif before == wanted:
        detail = f"unchanged: {wanted}"
    else:
        detail = f"changed: {before} -> {wanted}"
    log(db, user, "grant", request, doc, target.id, detail=detail)
    for uid in cascaded:
        log(db, user, "revoke", request, doc, uid, detail="cascade")
    db.commit()

    # Dispatch Telegram share alerts to recipient and doc owner
    owner = db.get(User, doc.owner_id)
    perms_str = f"level={body.level.value}, download={'yes' if body.can_download else 'no'}, share={'yes' if body.can_share else 'no'}"
    notify_share(
        granter_email=user.email,
        recipient_email=target.email,
        doc_name=doc.name,
        permissions=perms_str,
        recipient_chat_id=target.telegram_chat_id,
        owner_email=owner.email if owner else None,
        owner_chat_id=owner.telegram_chat_id if owner else None,
    )
    notify_share_email(
        granter_email=user.email,
        recipient_email=target.email,
        doc_name=doc.name,
        permissions=perms_str,
        owner_email=owner.email if owner else None,
    )

    return {"user_id": target.id, "level": body.level, "can_share": body.can_share,
            "can_download": body.can_download}


@router.post("/batch", status_code=200)
def batch_grant(doc_id: uuid.UUID, body: BatchGrantIn, request: Request,
                user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Grant permissions to multiple users simultaneously in a single transaction."""
    check_maintenance_write_allowed(user)
    doc = require(user, db.get(Document, doc_id), "share", db, request)
    is_owner = doc.owner_id == user.id
    mine = None if is_owner else (
        db.query(Permission).filter_by(document_id=doc.id, user_id=user.id).one())

    wanted = describe(body.level, body.can_share, body.can_download)
    if not is_owner:
        have = describe(mine.level, mine.can_share, mine.can_download)
        if body.can_share:
            refuse(db, user, request, doc, None, 403, "Only the owner can allow re-sharing",
                   f"re-share right is owner-only; wanted {wanted}")
        if RANK[body.level] > RANK[mine.level]:
            refuse(db, user, request, doc, None, 403, "Cannot grant more than you have",
                   f"wanted {wanted}; has {have}")
        if body.can_download and not mine.can_download:
            refuse(db, user, request, doc, None, 403, "Cannot grant more than you have",
                   f"wanted {wanted}; has {have}")

    successful = []
    failed = []

    target_emails = list(body.emails or [])
    if body.email and body.email not in target_emails:
        target_emails.append(body.email)
    if not target_emails:
        raise HTTPException(400, "No emails provided")

    for raw_email in target_emails:
        clean_email = str(raw_email).strip().lower()
        target = db.query(User).filter(User.email == clean_email).first()
        if (not target or target.id == user.id or target.id == doc.owner_id
                or target.role == Role.admin):
            failed.append({"email": clean_email, "reason": "Invalid user or cannot share with admin/self"})
            continue

        perm = db.query(Permission).filter_by(document_id=doc.id, user_id=target.id).first()
        if perm and not is_owner and perm.granted_by != user.id:
            failed.append({"email": clean_email, "reason": "Cannot change access given by another user"})
            continue

        cascaded = []
        before = describe(perm.level, perm.can_share, perm.can_download) if perm else None
        if perm:
            if perm.can_share and (not body.can_share
                                   or RANK[body.level] < RANK[perm.level]
                                   or (perm.can_download and not body.can_download)):
                cascaded = revoke_descendants(db, doc.id, target.id)
            perm.level, perm.can_share, perm.granted_by = body.level, body.can_share, user.id
            perm.can_download = body.can_download
        else:
            db.add(Permission(document_id=doc.id, user_id=target.id, level=body.level,
                              can_share=body.can_share, can_download=body.can_download,
                              granted_by=user.id))

        if before is None:
            detail = f"batch new: {wanted}"
        elif before == wanted:
            detail = f"batch unchanged: {wanted}"
        else:
            detail = f"batch changed: {before} -> {wanted}"
        log(db, user, "grant", request, doc, target.id, detail=detail)
        for uid in cascaded:
            log(db, user, "revoke", request, doc, uid, detail="cascade")

        owner = db.get(User, doc.owner_id)
        perms_str = f"level={body.level.value}, download={'yes' if body.can_download else 'no'}, share={'yes' if body.can_share else 'no'}"
        notify_share(
            granter_email=user.email,
            recipient_email=target.email,
            doc_name=doc.name,
            permissions=perms_str,
            recipient_chat_id=target.telegram_chat_id,
            owner_email=owner.email if owner else None,
            owner_chat_id=owner.telegram_chat_id if owner else None,
        )
        notify_share_email(
            granter_email=user.email,
            recipient_email=target.email,
            doc_name=doc.name,
            permissions=perms_str,
            owner_email=owner.email if owner else None,
        )
        successful.append({"email": target.email, "user_id": target.id, "level": body.level.value})

    db.commit()
    return {
        "success": True,
        "total_granted": len(successful),
        "successful": successful,
        "failed": failed,
    }


@router.get("/candidates")
def list_candidates(doc_id: uuid.UUID, request: Request,
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Return all non-admin eligible users with their current permission status on this document."""
    doc = require(user, db.get(Document, doc_id), "share", db, request)
    perms = {p.user_id: p.level.value for p in db.query(Permission).filter_by(document_id=doc.id).all()}
    candidates = (db.query(User)
                  .filter(User.role != Role.admin, User.id != doc.owner_id, User.id != user.id)
                  .order_by(User.email).all())
    return [
        {
            "id": u.id,
            "email": u.email,
            "name": u.name or u.email.split("@")[0],
            "current_level": perms.get(u.id),
        }
        for u in candidates
    ]


@router.get("")
def list_shares(doc_id: uuid.UUID, request: Request,
                user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = require(user, db.get(Document, doc_id), "share", db, request)
    q = (db.query(Permission, User.email).join(User, User.id == Permission.user_id)
         .filter(Permission.document_id == doc.id))
    if doc.owner_id != user.id:                 # a delegate sees only what they gave
        q = q.filter(Permission.granted_by == user.id)
    return [{"user_id": p.user_id, "email": e, "level": p.level,
             "can_share": p.can_share, "can_download": p.can_download,
             "granted_by": p.granted_by} for p, e in q.all()]


@router.delete("/{user_id}", status_code=204)
def revoke(doc_id: uuid.UUID, user_id: int, request: Request,
           user: User = Depends(current_user), db: Session = Depends(get_db)):
    check_maintenance_write_allowed(user)
    doc = require(user, db.get(Document, doc_id), "share", db, request)
    perm = db.query(Permission).filter_by(document_id=doc.id, user_id=user_id).first()
    if not perm:
        raise HTTPException(404, "Not found")
    if doc.owner_id != user.id and perm.granted_by != user.id:
        raise HTTPException(404, "Not found")   # delegates revoke only their own grants
    cascaded = revoke_descendants(db, doc.id, perm.user_id)
    db.delete(perm)
    log(db, user, "revoke", request, doc, user_id)
    for uid in cascaded:
        log(db, user, "revoke", request, doc, uid, detail="cascade")
    db.commit()