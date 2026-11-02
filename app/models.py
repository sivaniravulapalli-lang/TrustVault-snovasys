import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (Boolean, Column, DateTime, Enum, ForeignKey, Integer, String,
                        UniqueConstraint, Uuid, false)
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
