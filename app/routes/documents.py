import hashlib
import re
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

import io
import os
import zipfile

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session, joinedload

from ..audit import log
from ..auth import current_user, require_role
from ..authz import require
from ..config import MAX_UPLOAD_BYTES, UPLOAD_DIR
from ..db import get_db
from ..models import Document, Permission, Role, User

router = APIRouter(prefix="/documents", tags=["documents"])

FILE_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".txt": "text/plain",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
# shown in error messages; the upload form in app/static/app.js shows the same list
ACCEPTED = "PDF, PNG, JPG, TXT, DOCX"
MAX_MB = MAX_UPLOAD_BYTES // (1024 * 1024)


def is_docx(data: bytes) -> bool:
    """A real Word file is a zip with [Content_Types].xml and a word/ folder."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            if "[Content_Types].xml" not in names or not any(n.startswith("word/") for n in names):
                return False
            return len(names) <= 2000 and sum(i.file_size for i in z.infolist()) <= 50 * 1024 * 1024
    except zipfile.BadZipFile:
        return False


def sniff(data: bytes, ext: str) -> bool:
    """Check the real bytes match the claimed type (never trust the filename)."""
    if ext == ".pdf":
        return data.startswith(b"%PDF-")
    if ext == ".png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if ext == ".jpg":
        return data.startswith(b"\xff\xd8\xff")
    if ext == ".docx":
        return is_docx(data)
    if ext == ".txt":
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return b"\x00" not in data
    return False


def read_validated(file: UploadFile):
    ext = Path(file.filename or "").suffix.lower()
    if ext == ".jpeg":
        ext = ".jpg"
    if ext not in FILE_TYPES:
        shown = ext[:10] if ext else "Files without an extension"
        raise HTTPException(415, f"{shown} files are not accepted. Allowed: {ACCEPTED}.")
    data = file.file.read(MAX_UPLOAD_BYTES + 1)
    if not data:
        raise HTTPException(400, "The file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"The file is larger than {MAX_MB} MB, the maximum allowed.")
    if not sniff(data, ext):
        raise HTTPException(415, f"The file content is not a real {ext[1:].upper()} file "
                                 "(renamed or damaged file).")
    return data, ext


def save_file(data: bytes, ext: str) -> str:
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    name = uuid.uuid4().hex + ext      # user-supplied name never touches the disk
    (Path(UPLOAD_DIR) / name).write_bytes(data)
    return name


def clean_name(filename: str) -> str:
    return re.sub(r"[^\w.\- ]", "_", Path(filename or "file").name)[:200]


def named(filename: str, ext: str) -> str:
    """Safe display name that always ends with the real file extension."""
    stem = Path(clean_name(filename)).stem[:150] or "file"
    return stem + ext


def out(d: Document) -> dict:
    return {"id": str(d.id), "name": d.name, "category": d.category,
            "owner_id": d.owner_id, "owner_email": d.owner.email if d.owner else None,
            "mime": d.mime, "size": d.size, "suspended": d.suspended_at is not None,
            "created_at": d.created_at, "updated_at": d.updated_at}


def load(db: Session, doc_id) -> Optional[Document]:
    return db.get(Document, doc_id)


@router.post("", status_code=201)
def upload(request: Request, file: UploadFile = File(...),
           category: Optional[str] = Form(None, max_length=100),
           user: User = Depends(require_role(Role.owner)),
           db: Session = Depends(get_db)):
    data, ext = read_validated(file)
    doc = Document(owner_id=user.id, name=named(file.filename,ext),
                   category=category, stored_name=save_file(data, ext),
                   mime=FILE_TYPES[ext], size=len(data),
                   sha256=hashlib.sha256(data).hexdigest())
    db.add(doc)
    db.flush()
    log(db, user, "upload", request, doc)
    db.commit()
    return out(doc)


def visible(db: Session, user: User, scope: Optional[str] = None):
    """Documents this user may see, filtered in SQL.
    mine   = documents they own (a suspended one still shows, marked as suspended)
    shared = documents others gave them (hidden while suspended)
    None   = both"""
    shared = db.query(Permission.document_id).filter(Permission.user_id == user.id)
    mine = Document.owner_id == user.id
    theirs = and_(Document.id.in_(shared), Document.suspended_at.is_(None))
    where = mine if scope == "mine" else theirs if scope == "shared" else or_(mine, theirs)
    return (db.query(Document).join(User, User.id == Document.owner_id)
            .filter(Document.deleted_at.is_(None), where))


def annotate(db: Session, user: User, docs: list) -> list:
    """Add what the caller may do (my_access) and, for documents where they handed
    access out, to whom (shared_with). One extra query for the whole page."""
    rows = []
    if docs:
        rows = (db.query(Permission, User.email)
                .join(User, User.id == Permission.user_id)
                .filter(Permission.document_id.in_([d.id for d in docs])).all())
    mine, given = {}, {}
    owned = {d.id for d in docs if d.owner_id == user.id}
    for p, email in rows:
        if p.user_id == user.id:
            mine[p.document_id] = p
        if p.document_id in owned or p.granted_by == user.id:     # owner sees all, a delegate only their own
            given.setdefault(p.document_id, []).append(
                {"user_id": p.user_id, "email": email, "level": p.level.value,
                 "can_share": p.can_share, "can_download": p.can_download})
    result = []
    for d in docs:
        p = mine.get(d.id)
        if d.owner_id == user.id:
            access = {"owner": True, "level": "edit", "can_share": True,
                      "can_download": True, "can_delete": True}
        else:
            access = {"owner": False, "level": p.level.value if p else "read",
                      "can_share": bool(p and p.can_share),
                      "can_download": bool(p and p.can_download), "can_delete": False}
        result.append({**out(d), "my_access": access, "shared_with": given.get(d.id, [])})
    return result


@router.get("")
def search(q: Optional[str] = None, owner: Optional[str] = None,
           category: Optional[str] = None,
           date_from: Optional[date] = None, date_to: Optional[date] = None,
           scope: Optional[str] = Query(None, pattern="^(mine|shared)$"),
           user: User = Depends(current_user), db: Session = Depends(get_db)):
    query = visible(db, user, scope)
    # permission filter is applied in SQL first; later filters can only narrow it
    if q:
        esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(Document.name.ilike(f"%{esc}%", escape="\\"))
    if owner:
        query = query.filter(User.email == owner.lower())
    if category:
        query = query.filter(func.lower(Document.category) == category.strip().lower())
    if date_from:
        query = query.filter(Document.created_at >= datetime.combine(
            date_from, datetime.min.time(), timezone.utc))
    if date_to:
        query = query.filter(Document.created_at <= datetime.combine(
            date_to, datetime.max.time(), timezone.utc))
    docs = (query.options(joinedload(Document.owner))
            .order_by(Document.created_at.desc()).limit(100).all())
    return annotate(db, user, docs)


# must stay above "/{doc_id}", otherwise "categories" is read as a document id
@router.get("/categories")
def categories(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Categories of the documents this user can see (lower-case, no duplicates)."""
    rows = (visible(db, user)
            .filter(Document.category.isnot(None), Document.category != "")
            .with_entities(func.lower(Document.category))
            .distinct().order_by(func.lower(Document.category)).all())
    return [r[0] for r in rows]


@router.get("/{doc_id}")
def get_one(doc_id: uuid.UUID, request: Request, user: User = Depends(current_user),
            db: Session = Depends(get_db)):
    return out(require(user, load(db, doc_id), "read", db, request))


@router.get("/{doc_id}/view")
def view(doc_id: uuid.UUID, request: Request,
         user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Show the file inside the browser. Needs read only; every view is audited."""
    doc = require(user, load(db, doc_id), "read", db, request)
    path = Path(UPLOAD_DIR) / doc.stored_name
    if not path.is_file():
        raise HTTPException(404, "Not found")
    log(db, user, "view", request, doc)
    db.commit()
    return FileResponse(path, media_type=doc.mime, filename=doc.name,
                        content_disposition_type="inline")


@router.get("/{doc_id}/download")
def download(doc_id: uuid.UUID, request: Request,
             user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = require(user, load(db, doc_id), "download", db, request) 
   
    path = Path(UPLOAD_DIR) / doc.stored_name
    if not path.is_file():
        raise HTTPException(404, "Not found")
    log(db, user, "download", request, doc)
    db.commit()
    return FileResponse(path, media_type=doc.mime, filename=doc.name,
                        content_disposition_type="attachment")


class PatchIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    category: Optional[str] = Field(None, max_length=100)


@router.patch("/{doc_id}")
def edit_meta(doc_id: uuid.UUID, body: PatchIn, request: Request,
              user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = require(user, load(db, doc_id), "edit", db, request)
    changes = []
    if body.name:
        new_name = named(body.name, Path(doc.stored_name).suffix)
        if new_name != doc.name:
            changes.append(f"name: {doc.name} -> {new_name}")
        doc.name = new_name
    if body.category is not None:
        if body.category != (doc.category or ""):
            changes.append(f"category: {doc.category or ''} -> {body.category}")
        doc.category = body.category
    log(db, user, "edit", request, doc, detail=("; ".join(changes) or "no change")[:500])
    db.commit()
    return out(doc)


@router.put("/{doc_id}/content")
def replace_content(doc_id: uuid.UUID, request: Request, file: UploadFile = File(...),
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = require(user, load(db, doc_id), "edit", db, request)
    data, ext = read_validated(file)
    if ext != Path(doc.stored_name).suffix:
        raise HTTPException(415, "New version must be the same file type")
    old = Path(UPLOAD_DIR) / doc.stored_name
    old_size, old_sha = doc.size, doc.sha256
    doc.stored_name, doc.mime, doc.size = save_file(data, ext), FILE_TYPES[ext], len(data)
    doc.sha256 = hashlib.sha256(data).hexdigest()
    log(db, user, "edit", request, doc,
        detail=f"content: {old_size} B -> {doc.size} B, sha256 {old_sha[:8]} -> {doc.sha256[:8]}")
    db.commit()
    old.unlink(missing_ok=True)
    return out(doc)


@router.delete("/{doc_id}", status_code=204)
def delete(doc_id: uuid.UUID, request: Request,
           user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = require(user, load(db, doc_id), "delete", db, request)
    doc.deleted_at = datetime.now(timezone.utc)
    log(db, user, "delete", request, doc)
    db.commit()
    # the row stays (audit trail); the bytes do not
    (Path(UPLOAD_DIR) / doc.stored_name).unlink(missing_ok=True)
