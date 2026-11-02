import os
import tempfile

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "test-secret-key-test-secret-key-0123456789"
os.environ["UPLOAD_DIR"] = tempfile.mkdtemp()
os.environ["ENABLE_DOCS"] = "0"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import get_db
from app.main import app
from app.models import Base, Role, User

PW = "correct-horse-battery"
PDF = ("a.pdf", b"%PDF-1.4 hello", "application/pdf")


@pytest.fixture()
def Session():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False},
                        poolclass=StaticPool)
    Base.metadata.create_all(eng)
    yield sessionmaker(bind=eng, autoflush=False)
    Base.metadata.drop_all(eng)


@pytest.fixture()
def client(Session):
    def _db():
        db = Session()
        try:
            yield db
        finally:
            db.close()
    app.dependency_overrides[get_db] = _db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture()
def make_user(client, Session):
    def make(email, role=Role.owner):
        client.post("/auth/register", json={"email": email, "password": PW})
        if role:
            db = Session()
            db.query(User).filter(User.email == email).one().role = role
            db.commit()
            db.close()
        tok = client.post("/auth/login", json={"email": email, "password": PW}).json()["access_token"]
        return {"Authorization": f"Bearer {tok}"}
    return make
