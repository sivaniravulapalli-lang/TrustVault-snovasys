import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (Boolean, Column, DateTime, Enum, ForeignKey, Integer, String,
                        Text, UniqueConstraint, Uuid, false)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def now():
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    admin = "admin"
    owner = "owner"
    viewer = "viewer"


class Level(str, enum.Enum):
    read = "read"
    edit = "edit"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=True)   # display name given at registration
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(Role), nullable=False, default=Role.viewer)
    created_at = Column(DateTime(timezone=True), default=now)
    telegram_chat_id = Column(String(50), nullable=True)
    telegram_link_code = Column(String(64), nullable=True, index=True)
    reset_otp = Column(String(10), nullable=True)
    reset_otp_expires_at = Column(DateTime(timezone=True), nullable=True)
    email_alerts_enabled = Column(Boolean, default=True)


class Document(Base):
    __tablename__ = "documents"
    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    category = Column(String(100), index=True)
    stored_name = Column(String(64), nullable=False, unique=True)
    mime = Column(String(100), nullable=False)
    size = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, index=True)
    updated_at = Column(DateTime(timezone=True), default=now, onupdate=now)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    suspended_at = Column(DateTime(timezone=True), nullable=True)   # set by an admin
    parent_doc_id = Column(Uuid(as_uuid=True), ForeignKey("documents.id"), nullable=True, index=True)
    lineage_meta = Column(Text, nullable=True)  # JSON trail: [{"user_id": ..., "email": ..., "action": ...}]
    owner = relationship("User")


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("document_id", "user_id", name="uq_doc_user"),)
    id = Column(Integer, primary_key=True)
    document_id = Column(Uuid(as_uuid=True), ForeignKey("documents.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    level = Column(Enum(Level), nullable=False)
    # may this person pass access on (at their own level or lower)?
    can_share = Column(Boolean, nullable=False, default=False, server_default=false())
    # may this person take a copy of the file? (separate from read = view in the app)
    can_download = Column(Boolean, nullable=False, default=False, server_default=false())
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(50), nullable=False, index=True)
    document_id = Column(Uuid(as_uuid=True), nullable=True, index=True)
    target_user_id = Column(Integer, nullable=True)
    detail = Column(String(500))
    ip = Column(String(45))
    created_at = Column(DateTime(timezone=True), default=now, index=True)


class InboxMessage(Base):
    """In-app mailbox storing delivered DocShare notifications."""
    __tablename__ = "inbox_messages"
    id = Column(Integer, primary_key=True)
    to_email = Column(String(255), nullable=False, index=True)
    from_email = Column(String(255), nullable=False, default="no-reply@docshare.com")
    subject = Column(String(255), nullable=False)
    body = Column(String(2000), nullable=False)
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, index=True)
