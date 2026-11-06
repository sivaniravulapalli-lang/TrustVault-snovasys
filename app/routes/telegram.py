import secrets
import re
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import current_user
from ..config import TELEGRAM_BOT_TOKEN, TELEGRAM_BOT_USERNAME
from ..db import get_db
from ..models import User
from ..telegram_service import is_configured, send_message_async

router = APIRouter(prefix="/telegram", tags=["telegram"])


class ConnectIn(BaseModel):
    chat_id: str = Field(min_length=3, max_length=50)


def mask_chat_id(cid: str | None) -> str | None:
    if not cid:
        return None
    s = str(cid)
    if len(s) <= 4:
        return s
    return s[:2] + "****" + s[-2:]


@router.get("/status")
def telegram_status(user: User = Depends(current_user)):
    """Check whether Telegram alerting is enabled, and if this user is linked."""
    return {
        "configured": is_configured(),
        "bot_username": TELEGRAM_BOT_USERNAME,
        "connected": bool(user.telegram_chat_id),
        "chat_id_masked": mask_chat_id(user.telegram_chat_id),
    }


@router.get("/link-code")
def generate_link_code(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """
    Generate a unique short code for 1-Click Telegram Deep Linking.
    Deep link format: https://t.me/<BOT_USERNAME>?start=<LINK_CODE>
    """
    code = secrets.token_hex(4).upper()  # 8 character code
    user.telegram_link_code = code
    db.commit()

    deep_link = None
    if TELEGRAM_BOT_USERNAME:
        deep_link = f"https://t.me/{TELEGRAM_BOT_USERNAME}?start={code}"

    return {
        "code": code,
        "bot_username": TELEGRAM_BOT_USERNAME,
        "deep_link": deep_link,
    }


@router.post("/connect")
def connect_manual(data: ConnectIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """
    Manually save Telegram Chat ID and send a test confirmation alert immediately.
    """
    cid = data.chat_id.strip()
    if not re.match(r"^-?\d+$", cid):
        raise HTTPException(400, "Invalid Telegram Chat ID: must contain only digits")

    user.telegram_chat_id = cid
    db.commit()

    # Send confirmation message immediately
    role_title = user.role.value.upper()
    display_name = user.name or user.email.split("@")[0]
    welcome_text = (
        f"🎉 *TrustVault Connected Successfully!*\n\n"
        f"Hello *{display_name}*, your Telegram is now linked to TrustVault as *{role_title}*.\n\n"
        f"You will receive real-time security and document activity notifications here."
    )
    send_message_async(cid, welcome_text)

    return {"ok": True, "connected": True, "chat_id_masked": mask_chat_id(cid)}


@router.post("/disconnect")
def disconnect_telegram(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Unlink Telegram from user profile."""
    old_cid = user.telegram_chat_id
    user.telegram_chat_id = None
    user.telegram_link_code = None
    db.commit()

    if old_cid:
        farewell = "ℹ️ *TrustVault Notice*\nYour Telegram account has been disconnected from TrustVault."
        send_message_async(old_cid, farewell)

    return {"ok": True, "connected": False}


@router.post("/webhook")
async def telegram_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Handles Telegram Bot webhook events. When user clicks START with deep-link token,
    Telegram delivers: {"message": {"text": "/start <CODE>", "chat": {"id": 123456789}}}
    """
    try:
        body = await request.json()
    except Exception:
        return {"ok": True}

    msg = body.get("message") or body.get("edited_message")
    if not msg:
        return {"ok": True}

    text = (msg.get("text") or "").strip()
    chat = msg.get("chat") or {}
    chat_id = str(chat.get("id", ""))

    if text.startswith("/start ") and chat_id:
        token = text.split(" ", 1)[1].strip()
        user = db.query(User).filter(User.telegram_link_code == token).first()
        if user:
            user.telegram_chat_id = chat_id
            user.telegram_link_code = None
            db.commit()

            role_title = user.role.value.upper()
            display_name = user.name or user.email.split("@")[0]
            welcome_text = (
                f"🎉 *TrustVault 1-Click Link Verified!*\n\n"
                f"Hello *{display_name}*, your account has been successfully linked with role: *{role_title}*.\n\n"
                f"You will now receive instant audit and security notifications."
            )
            send_message_async(chat_id, welcome_text)

    return {"ok": True}
