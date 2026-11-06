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
import random
import secrets
from .email_service import notify_security_lockout_email, send_email_async
from .models import AuditLog, Role, User
from .telegram_service import notify_security_lockout

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
        raise HTTPException(400, "Email already registered. Please log in or use forgot password.")
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
        if left <= 0:
            admin_users = db.query(User).filter(User.role == Role.admin).all()
            admin_chat_ids = [u.telegram_chat_id for u in admin_users if u.telegram_chat_id]
            admin_emails = [u.email for u in admin_users if u.email]
            notify_security_lockout(email, _ip(request), admin_chat_ids)
            notify_security_lockout_email(email, _ip(request), admin_emails)
        # same wording whether the e-mail or the password was wrong (no account enumeration)
        msg = "The email or password is incorrect. "
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
    return {"id": user.id, "name": user.name, "email": user.email, "role": user.role,
            "telegram_connected": bool(user.telegram_chat_id)}


class ForgotPasswordIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    email: EmailStr
    otp: str = Field(min_length=6, max_length=6)
    new_password: str = Field(min_length=10, max_length=128)


@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordIn, request: Request, db: Session = Depends(get_db)):
    email = data.email.lower()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        # Prevent user enumeration, pretend OTP was dispatched
        return {"message": "If this email is registered, a 6-digit OTP has been sent."}

    # Generate 6-digit OTP
    otp = f"{random.randint(100000, 999999)}"
    user.reset_otp = otp
    user.reset_otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    db.commit()

    # Send via Email / In-App Mailbox
    subject = "TrustVault: Your Password Reset OTP"
    body = (
        f"Hello {user.name or ''},\n\n"
        f"You requested to reset your password on TrustVault.\n\n"
        f"Your 6-Digit Password Reset OTP is: {otp}\n\n"
        f"This OTP is valid for 15 minutes. If you did not make this request, please ignore this email.\n\n"
        f"— TrustVault Security"
    )
    send_email_async(user.email, subject, body)
    log(db, user, "forgot_password_requested", request)
    db.commit()

    return {"message": "A 6-digit verification OTP has been sent to your email."}


@router.post("/reset-password")
def reset_password(data: ResetPasswordIn, request: Request, db: Session = Depends(get_db)):
    email = data.email.lower()
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.reset_otp:
        raise HTTPException(400, "Invalid reset request or expired OTP.")

    # Check expiry
    if not user.reset_otp_expires_at or datetime.now(timezone.utc) > user.reset_otp_expires_at:
        user.reset_otp = None
        user.reset_otp_expires_at = None
        db.commit()
        raise HTTPException(400, "OTP has expired. Please request a new one.")

    if not secrets.compare_digest(user.reset_otp, data.otp.strip()):
        raise HTTPException(400, "Invalid OTP code.")

    # Update password and clear OTP
    user.password_hash = pwd.hash(data.new_password)
    user.reset_otp = None
    user.reset_otp_expires_at = None
    log(db, user, "password_reset_success", request)
    db.commit()

    return {"message": "Password updated successfully. You can now log in with your new password."}

