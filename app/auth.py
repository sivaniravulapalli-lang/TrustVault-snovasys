from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from .audit import log
from .config import (LOGIN_MAX_PER_EMAIL, LOGIN_MAX_PER_EMAIL_AND_IP, LOGIN_MAX_PER_IP,
                     REGISTER_MAX_PER_IP_PER_HOUR, SECRET_KEY, THROTTLE_WINDOW_MINUTES,
                     TOKEN_MINUTES)
from .db import get_db
from .models import AuditLog, Role, User

router = APIRouter(prefix="/auth", tags=["auth"])
pwd = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")
ALGO = "HS256"
DUMMY = pwd.hash("dummy-password-for-timing")


class RegisterIn(BaseModel):
    name: str = Field(default="", max_length=100)
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


def _ip(request: Request):
    return request.client.host if request.client else None


def _count(db: Session, action: str, since: datetime, **equals) -> int:
    q = db.query(func.count(AuditLog.id)).filter(AuditLog.action == action,
                                                 AuditLog.created_at >= since)
    for column, value in equals.items():
        q = q.filter(getattr(AuditLog, column) == value)
    return q.scalar() or 0


def _too_many(minutes: int, what: str = "attempts") -> HTTPException:
    return HTTPException(429, f"Too many {what}. Try again in {minutes} minutes.",
                         headers={"Retry-After": str(minutes * 60)})


def _attempts_left(db: Session, request: Request, key: str) -> int:
    """Failed logins still allowed in the window (the tightest of the three limits).
    Counted the same way whether or not the e-mail has an account, so it reveals nothing."""
    since = datetime.now(timezone.utc) - timedelta(minutes=THROTTLE_WINDOW_MINUTES)
    ip = _ip(request)
    return max(0, min(
        LOGIN_MAX_PER_EMAIL_AND_IP - _count(db, "login_failed", since, detail=key, ip=ip),
        LOGIN_MAX_PER_IP - _count(db, "login_failed", since, ip=ip),
        LOGIN_MAX_PER_EMAIL - _count(db, "login_failed", since, detail=key)))


def _check_login_throttle(db: Session, request: Request, key: str) -> None:
    """Checked BEFORE the password is looked at, so a locked login learns nothing."""
    if _attempts_left(db, request, key) <= 0:
        raise _too_many(THROTTLE_WINDOW_MINUTES, "failed login attempts")


@router.post("/register", status_code=201)
def register(data: RegisterIn, request: Request, db: Session = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    if _count(db, "register", since, ip=_ip(request)) >= REGISTER_MAX_PER_IP_PER_HOUR:
        raise _too_many(60)
    email = data.email.lower()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(400, "Registration failed")
    user = User(email=email, name=data.name.strip() or None,
                password_hash=pwd.hash(data.password), role=Role.viewer)
    db.add(user)
    db.flush()
    log(db, user, "register", request)
    db.commit()
    return {"id": user.id, "name": user.name, "email": user.email, "role": user.role}


def _authenticate(email: str, password: str, request: Request, db: Session) -> dict:
    email = email.lower()
    key = email[:100]                      # what the audit log stores for failed attempts
    _check_login_throttle(db, request, key)
    user = db.query(User).filter(User.email == email).first()
    ok = pwd.verify(password, user.password_hash if user else DUMMY)
    if not user or not ok:
        # never log the password
        log(db, None, "login_failed", request, detail=key)
        db.commit()
        left = _attempts_left(db, request, key)
        # same wording whether the e-mail or the password was wrong (no account enumeration)
        msg = "Incorrect email or password. "
        msg += (f"{left} of {LOGIN_MAX_PER_EMAIL_AND_IP} attempts left." if left
                else f"No attempts left. Try again in {THROTTLE_WINDOW_MINUTES} minutes.")
        raise HTTPException(401, msg)
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
