from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from .audit import log
from .config import SECRET_KEY, TOKEN_MINUTES
from .db import get_db
from .models import Role, User

router = APIRouter(prefix="/auth", tags=["auth"])
pwd = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")
ALGO = "HS256"
DUMMY = pwd.hash("dummy-password-for-timing")


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    # no role field: everyone registers as viewer; only an admin can promote


class LoginIn(BaseModel):
    email: EmailStr
    password: str


def make_token(user: User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_MINUTES)
    return jwt.encode({"sub": str(user.id), "exp": exp}, SECRET_KEY, algorithm=ALGO)


def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    try:
        uid = int(jwt.decode(token, SECRET_KEY, algorithms=[ALGO])["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(401, "Invalid token")
    user = db.get(User, uid)
    if not user:
        raise HTTPException(401, "Invalid token")
    return user


def require_role(*roles: Role):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Forbidden")
        return user
    return dep


@router.post("/register", status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    email = data.email.lower()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(400, "Registration failed")
    user = User(email=email, password_hash=pwd.hash(data.password), role=Role.viewer)
    db.add(user)
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role}


def _authenticate(email: str, password: str, request: Request, db: Session) -> dict:
    user = db.query(User).filter(User.email == email.lower()).first()
    ok = pwd.verify(password, user.password_hash if user else DUMMY)
    if not user or not ok:
        # never log the password; the attempted email is truncated
        log(db, None, "login_failed", request, detail=email[:100])
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    return {"access_token": make_token(user), "token_type": "bearer"}


@router.post("/login")
def login(data: LoginIn, request: Request, db: Session = Depends(get_db)):
    return _authenticate(data.email, data.password, request, db)


@router.post("/token", include_in_schema=False)   # only for the /docs Authorize button
def token(request: Request, form: OAuth2PasswordRequestForm = Depends(),
          db: Session = Depends(get_db)):
    return _authenticate(form.username, form.password, request, db)


@router.get("/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "role": user.role}
