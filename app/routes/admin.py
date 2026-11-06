import uuid
from datetime import date, datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, aliased

from ..ai_service import analyze_threat_logs
from ..audit import log
from ..auth import require_role
from ..db import get_db
from ..email_service import notify_doc_suspend_email, notify_role_change_email
from ..maintenance import get_maintenance_status, set_maintenance_mode, notify_maintenance_completed
from ..models import AuditLog, Document, InboxMessage, Permission, Role, User
from ..telegram_service import notify_doc_suspend, notify_role_change, notify_security_alert
from ..watermark_service import verify_watermark_token, extract_invisible_watermark, extract_binary_watermark
from fastapi import File, UploadFile
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
def permission_changes(action: Optional[str] = None,
                       document_id: Optional[uuid.UUID] = None,
                       actor_id: Optional[int] = None,
                       date_from: Optional[date] = None, date_to: Optional[date] = None,
                       limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                       db: Session = Depends(get_db)):
    return _rows(db, PERMISSION_ACTIONS, action, document_id, actor_id,
                 date_from, date_to, limit, offset)


@router.get("/ai-threat-analysis")
def ai_threat_analysis(request: Request,
                       admin: User = Depends(require_role(Role.admin)),
                       db: Session = Depends(get_db)):
    """Run AI SOC Threat Analysis on recent audit trail records."""
    logs = _rows(db, limit=100)
    report = analyze_threat_logs(logs)
    log(db, admin, "ai_threat_analysis", request, detail=f"threat_level={report.get('threat_level')}")
    db.commit()
    return report


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

    owner = db.get(User, doc.owner_id)
    if owner:
        notify_doc_suspend(doc.name, owner.email, owner.telegram_chat_id, admin.email, body.reason, suspended=True)
        notify_doc_suspend_email(doc.name, owner.email, admin.email, body.reason, suspended=True)

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

    owner = db.get(User, doc.owner_id)
    if owner:
        notify_doc_suspend(doc.name, owner.email, owner.telegram_chat_id, admin.email, suspended=False)
        notify_doc_suspend_email(doc.name, owner.email, admin.email, suspended=False)

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

    # Trigger Telegram & Email notifications if users have linked accounts
    admin_users = db.query(User).filter(User.role == Role.admin).all()
    admin_chat_ids = [u.telegram_chat_id for u in admin_users if u.telegram_chat_id]
    admin_emails = [u.email for u in admin_users if u.email]
    notify_role_change(
        user_email=target.email,
        new_role=body.role.value,
        actor_email=admin.email,
        user_chat_id=target.telegram_chat_id,
        admin_chat_ids=admin_chat_ids,
    )
    notify_role_change_email(
        user_email=target.email,
        new_role=body.role.value,
        actor_email=admin.email,
        admin_emails=admin_emails,
    )

    return {"id": target.id, "role": target.role}


class WatermarkVerifyIn(BaseModel):
    token: str = Field(..., min_length=1, max_length=100000, description="Leaked snippet, body, or token")


@router.post("/verify-watermark")
def verify_forensic_watermark(body: WatermarkVerifyIn, db: Session = Depends(get_db)):
    """
    Forensic Verification Endpoint:
    Allows SOC/Admins to paste a leaked document token or signature to trace
    the exact user, document ID, IP address, and timestamp of the exfiltration.
    """
    token_str = body.token.strip()
    # Check 1: Did the admin paste the document content containing an invisible Zero-Width watermark?
    stealth = extract_invisible_watermark(body.token)
    if stealth:
        u_id = int(stealth["user_id"])
        actor = db.get(User, u_id)
        doc = db.get(Document, uuid.UUID(stealth["doc_id"])) if stealth.get("doc_id") else None
        
        # Cross-reference with audit log
        matching_log = (db.query(AuditLog)
                        .filter(AuditLog.action == "download",
                                AuditLog.actor_id == u_id,
                                AuditLog.detail.ilike(f"%{stealth['sig_prefix']}%"))
                        .order_by(AuditLog.created_at.desc()).first())

        # Check if this document has full lineage history (multi-hop)
        lineage = []
        if doc and doc.lineage_meta:
            import json
            try:
                lineage = json.loads(doc.lineage_meta)
            except Exception:
                lineage = []

        return {
            "valid": True,
            "verified_by": "Zero-Width Steganography (Invisible Watermark Extracted From Document Body)",
            "details": {
                "user_id": u_id,
                "email": actor.email if actor else "unknown",
                "doc_id": stealth["doc_id"],
                "doc_name": doc.name if doc else (matching_log.document.name if matching_log and matching_log.document else "unknown"),
                "timestamp": matching_log.created_at.isoformat() if matching_log and matching_log.created_at else "Found in hidden payload",
                "ip": matching_log.ip if matching_log else "Hidden payload validated",
                "lineage": lineage,
                "note": "⚠️ VISIBLE FOOTER WAS DELETED, BUT USER WAS CAUGHT VIA INVISIBLE STEGANOGRAPHY!"
            },
            "status": "VALID_STEGANOGRAPHY_EXTRACTION"
        }

    if "." in token_str:
        parts = token_str.split(".", 1)
        payload_b64, signature = parts[0], parts[1]
    else:
        # Check if they passed a signature or custody ID
        cleaned = token_str.replace("TV-", "").replace("-", "").lower()
        # Find matching audit log detail
        matching_log = (db.query(AuditLog)
                        .filter(AuditLog.action == "download",
                                AuditLog.detail.ilike(f"%{cleaned[:8]}%"))
                        .order_by(AuditLog.created_at.desc()).first())
        if matching_log:
            actor = db.get(User, matching_log.actor_id)
            doc = db.get(Document, matching_log.document_id)
            return {
                "valid": True,
                "verified_by": "AuditLog Lookup",
                "details": {
                    "user_id": matching_log.actor_id,
                    "email": actor.email if actor else "unknown",
                    "doc_id": str(matching_log.document_id),
                    "doc_name": doc.name if doc else "unknown",
                    "timestamp": matching_log.created_at.isoformat() if matching_log.created_at else "",
                    "ip": matching_log.ip,
                },
                "status": "VALID_AUDIT_MATCH"
            }
        raise HTTPException(400, "Invalid token format. Expected '<payload_b64>.<signature>' or valid TV Custody Key.")

    is_valid, data, status = verify_watermark_token(payload_b64, signature)
    if not is_valid:
        raise HTTPException(400, f"Forensic verification failed: {status}")

    # Log text token investigation to audit trail
    u_id = data.get("user_id")
    actor = db.get(User, u_id) if u_id else None
    doc_id = data.get("doc_id")
    doc = db.get(Document, uuid.UUID(doc_id)) if doc_id else None
    log(db, None, "forensic_trace", None, doc, u_id, detail=f"type=token; exfiltrator={data.get('email', 'unknown')}")
    db.commit()

    return {
        "valid": True,
        "verified_by": "Cryptographic HMAC-SHA256",
        "details": data,
        "status": status
    }


@router.post("/verify-watermark-file")
async def verify_forensic_watermark_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Forensic Leaked File Upload Verification:
    Admins can upload an actual leaked file (image .png/.jpg, document .txt, or .pdf).
    The system extracts the forensic custody trailer or invisible steganography directly.
    """
    raw_data = await file.read()
    
    # 1. Check binary trailer (images / pdf / docx)
    binary_info = extract_binary_watermark(raw_data)
    if binary_info:
        u_id = binary_info["user_id"]
        actor = db.get(User, u_id)
        doc = db.get(Document, uuid.UUID(binary_info["doc_id"])) if binary_info.get("doc_id") else None
        
        matching_log = (db.query(AuditLog)
                        .filter(AuditLog.action == "download",
                                AuditLog.actor_id == u_id)
                        .order_by(AuditLog.created_at.desc()).first())

        # Log this forensic investigation into the immutable audit trail!
        log(db, None, "forensic_trace", None, doc, u_id, detail=f"file={file.filename}; type=binary; exfiltrator={actor.email if actor else u_id}")
        db.commit()

        lineage = []
        if doc and doc.lineage_meta:
            import json
            try:
                lineage = json.loads(doc.lineage_meta)
            except Exception:
                lineage = []

        return {
            "valid": True,
            "verified_by": "Binary File Forensic Trailer (Found in file binary structure)",
            "details": {
                "user_id": u_id,
                "email": actor.email if actor else binary_info.get("email", "unknown"),
                "doc_id": binary_info["doc_id"],
                "doc_name": doc.name if doc else file.filename,
                "timestamp": matching_log.created_at.isoformat() if matching_log and matching_log.created_at else "",
                "ip": matching_log.ip if matching_log else "Verified via binary trailer",
                "lineage": lineage,
                "note": f"🎯 Detected directly from uploaded binary file '{file.filename}'!"
            },
            "status": "VALID_BINARY_FORENSIC_MATCH"
        }

    # 2. Check text-based zero-width steganography or token
    try:
        text_str = raw_data.decode("utf-8", errors="ignore")
        stealth = extract_invisible_watermark(text_str)
        if stealth:
            u_id = int(stealth["user_id"])
            actor = db.get(User, u_id)
            doc = db.get(Document, uuid.UUID(stealth["doc_id"])) if stealth.get("doc_id") else None
            
            matching_log = (db.query(AuditLog)
                            .filter(AuditLog.action == "download",
                                    AuditLog.actor_id == u_id)
                            .order_by(AuditLog.created_at.desc()).first())

            # Log this forensic investigation into the immutable audit trail!
            log(db, None, "forensic_trace", None, doc, u_id, detail=f"file={file.filename}; type=text_stego; exfiltrator={actor.email if actor else u_id}")
            db.commit()

            lineage = []
            if doc and doc.lineage_meta:
                import json
                try:
                    lineage = json.loads(doc.lineage_meta)
                except Exception:
                    lineage = []

            return {
                "valid": True,
                "verified_by": "Zero-Width Steganography (Extracted from uploaded text file)",
                "details": {
                    "user_id": u_id,
                    "email": actor.email if actor else "unknown",
                    "doc_id": stealth["doc_id"],
                    "doc_name": doc.name if doc else file.filename,
                    "timestamp": matching_log.created_at.isoformat() if matching_log and matching_log.created_at else "",
                    "ip": matching_log.ip if matching_log else "Verified via stealth tag",
                    "lineage": lineage,
                    "note": f"🎯 Detected from uploaded text file '{file.filename}'!"
                },
                "status": "VALID_STEGANOGRAPHY_EXTRACTION"
            }
    except Exception:
        pass

    raise HTTPException(400, "No TrustVault forensic watermark or custody signature was found in the uploaded file.")


class MaintenanceToggleIn(BaseModel):
    enabled: bool
    reason: Optional[str] = "Scheduled Server Upgrade & Security Maintenance"
    notify_users: Optional[bool] = True
    scheduled_start: Optional[str] = None
    scheduled_end: Optional[str] = None


def _format_ist(iso_str: Optional[str]) -> str:
    if not iso_str:
        return ""
    try:
        # Datetime-local inputs from browser (e.g. 2026-11-06T07:07) are already in user's IST time
        if "T" in iso_str and not iso_str.endswith("Z") and "+" not in iso_str and "-" not in iso_str[10:]:
            dt = datetime.fromisoformat(iso_str)
            return dt.strftime("%d-%b-%Y %I:%M %p IST")
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        ist_tz = timezone(timedelta(hours=5, minutes=30))
        return dt.astimezone(ist_tz).strftime("%d-%b-%Y %I:%M %p IST")
    except Exception:
        return iso_str


@router.get("/maintenance")
def get_maintenance(user: User = Depends(require_role(Role.admin))):
    return get_maintenance_status()


@router.post("/maintenance")
def toggle_maintenance(body: MaintenanceToggleIn, request: Request,
                       user: User = Depends(require_role(Role.admin)),
                       db: Session = Depends(get_db)):
    state = set_maintenance_mode(
        body.enabled,
        body.reason or "",
        user.email,
        body.scheduled_start,
        body.scheduled_end,
    )
    
    if body.notify_users:
        users = db.query(User).all()
        is_scheduled = state.get("is_scheduled")
        is_active = state.get("active", body.enabled)

        if is_scheduled:
            start_fmt = _format_ist(body.scheduled_start)
            end_fmt = _format_ist(body.scheduled_end)
            subj = f"📅 Scheduled Maintenance: {start_fmt} - {end_fmt}"
            msg_body = (
                f"Attention: Scheduled system maintenance has been planned.\n\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"⏰ SERVER MAINTENANCE WINDOW (IST):\n"
                f"   • Start Time : {start_fmt}\n"
                f"   • End Time   : {end_fmt}\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"🔧 Reason: {body.reason or 'Scheduled Server Upgrade & Security Maintenance'}\n\n"
                f"⚠️ Server Impact & Operations Notice:\n"
                f"• Server will enter read-only maintenance mode between {start_fmt} and {end_fmt}.\n"
                f"• Document uploads, modifications, and sharing permissions are temporarily paused.\n"
                f"• Document viewing and verified downloads will remain fully operational.\n\n"
                f"All normal operations will automatically resume as soon as the maintenance window expires."
            )
            tg_text = (
                f"📅 System Maintenance Scheduled\n"
                f"Admin: {user.email}\n"
                f"Window: {start_fmt} to {end_fmt}\n"
                f"Reason: {body.reason or 'Scheduled Maintenance'}\n"
                f"Mode: Read-only during window"
            )
        elif is_active:
            subj = "🚨 Urgent: System Maintenance Active - TrustVault"
            msg_body = (
                f"Attention: Emergency system maintenance has been activated.\n\n"
                f"• Reason: {body.reason or 'Emergency Maintenance & Patching'}\n\n"
                f"All write and modify operations (uploads, edits, sharing) are temporarily paused. Document viewing and verified downloads remain operational."
            )
            tg_text = (
                f"🚨 System Maintenance ACTIVATED (Immediate)\n"
                f"Admin: {user.email}\n"
                f"Reason: {body.reason or 'Emergency Maintenance'}"
            )
        else:
            notify_maintenance_completed(db_session=db, admin_email=user.email)
            log(db, user, "maintenance", request, detail="status=disabled; reason=Manual Reset by Admin")
            return state

        for u in users:
            db.add(InboxMessage(
                to_email=u.email,
                from_email="admin@docshare.com",
                subject=subj,
                body=msg_body,
            ))
        
        admin_chats = [u.telegram_chat_id for u in users if u.role == Role.admin and u.telegram_chat_id]
        notify_security_alert(tg_text, admin_chats)
    
    log(db, user, "maintenance", request, detail=f"status={'enabled' if body.enabled else 'disabled'}; reason={(body.reason or '')[:300]}")
    db.commit()
    return state


