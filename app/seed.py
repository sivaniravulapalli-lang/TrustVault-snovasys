import hashlib
import os
import secrets
from pathlib import Path

from .auth import pwd
from .config import UPLOAD_DIR, check_admin_password
from .db import SessionLocal, add_missing_columns, engine
from .models import Base, Document, Level, Permission, Role, User

Base.metadata.create_all(bind=engine)
add_missing_columns()
db = SessionLocal()

# 1. Admin account
admin_email = os.environ.get("ADMIN_EMAIL", "admin@docshare.com").lower()
admin_pw = check_admin_password(os.environ.get("ADMIN_PASSWORD", "AdminDocShare2026!"))
admin_user = db.query(User).filter(User.email == admin_email).first()
if not admin_user:
    admin_user = User(email=admin_email, name="Admin", password_hash=pwd.hash(admin_pw), role=Role.admin)
    db.add(admin_user)
    db.commit()
    print(f"Admin created: {admin_email}")
else:
    print(f"Admin already exists: {admin_email}")

# 2. Document Owner account
owner_email = os.environ.get("OWNER_EMAIL", "owner@docshare.com").lower()
owner_pw = os.environ.get("OWNER_PASSWORD", "OwnerDocShare2026!")
owner_user = db.query(User).filter(User.email == owner_email).first()
if not owner_user:
    owner_user = User(email=owner_email, name="Document Owner", password_hash=pwd.hash(owner_pw), role=Role.owner)
    db.add(owner_user)
    db.commit()
    print(f"Owner created: {owner_email}")
else:
    print(f"Owner already exists: {owner_email}")

# 3. Viewer account
viewer_email = os.environ.get("VIEWER_EMAIL", "viewer@docshare.com").lower()
viewer_pw = os.environ.get("VIEWER_PASSWORD", "ViewerDocShare2026!")
viewer_user = db.query(User).filter(User.email == viewer_email).first()
if not viewer_user:
    viewer_user = User(email=viewer_email, name="Viewer", password_hash=pwd.hash(viewer_pw), role=Role.viewer)
    db.add(viewer_user)
    db.commit()
    print(f"Viewer created: {viewer_email}")
else:
    print(f"Viewer already exists: {viewer_email}")

# 4. Sample Seed Document (Uploaded by Owner, shared with Viewer)
sample_doc_name = "welcome_contract.txt"
existing_doc = db.query(Document).filter(Document.name == sample_doc_name, Document.owner_id == owner_user.id).first()
if not existing_doc:
    upload_folder = Path(UPLOAD_DIR)
    upload_folder.mkdir(parents=True, exist_ok=True)
    content = b"Welcome to TrustVault!\nThis is a confidential sample document demonstrating secure document sharing."
    stored_name = secrets.token_hex(16) + ".txt"
    file_path = upload_folder / stored_name
    file_path.write_bytes(content)

    doc = Document(
        owner_id=owner_user.id,
        name=sample_doc_name,
        category="Contracts",
        stored_name=stored_name,
        mime="text/plain",
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest()
    )
    db.add(doc)
    db.commit()

    # Share with viewer (read + download)
    perm = Permission(
        document_id=doc.id,
        user_id=viewer_user.id,
        level=Level.read,
        can_share=False,
        can_download=True,
        granted_by=owner_user.id
    )
    db.add(perm)
    db.commit()
    print("Sample document and share permission created!")
