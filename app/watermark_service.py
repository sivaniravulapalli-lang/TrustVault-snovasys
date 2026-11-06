import hmac
import hashlib
import json
import base64
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any
from .config import SECRET_KEY

# Key separation using SHA256 derivation
FORENSIC_KEY = hashlib.sha256(f"forensic-watermark-key:{SECRET_KEY}".encode()).digest()

def generate_watermark_token(
    user_id: int,
    user_email: str,
    doc_id: str,
    doc_name: str,
    ip_address: Optional[str] = None
) -> Tuple[str, str]:
    """
    Generate a cryptographic HMAC-SHA256 signature and tamper-evident payload.
    Returns: (token_payload_b64, hex_signature)
    """
    ts = datetime.now(timezone.utc).isoformat()
    payload = {
        "user_id": user_id,
        "email": user_email.lower().strip(),
        "doc_id": str(doc_id),
        "doc_name": doc_name,
        "timestamp": ts,
        "ip": ip_address or "unknown",
        "system": "TrustVault-Forensics/v1.0"
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    sig = hmac.new(FORENSIC_KEY, canonical_json.encode("utf-8"), hashlib.sha256).hexdigest()
    encoded_payload = base64.urlsafe_b64encode(canonical_json.encode("utf-8")).decode("ascii").rstrip("=")
    
    return encoded_payload, sig


def verify_watermark_token(encoded_payload: str, signature: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Verify the cryptographic custody stamp of a leaked document.
    Returns: (is_valid, decoded_payload, status_reason)
    """
    try:
        # Re-pad base64
        rem = len(encoded_payload) % 4
        padded = encoded_payload + ("=" * (4 - rem) if rem else "")
        raw_json = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        
        # Verify HMAC signature in constant time
        expected_sig = hmac.new(FORENSIC_KEY, raw_json.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, signature):
            return False, None, "INVALID_SIGNATURE (Document provenance has been tampered with or key mismatch)"
        
        data = json.loads(raw_json)
        return True, data, "VALID_SIGNATURE"
    except Exception as e:
        return False, None, f"DECODE_ERROR: {str(e)}"


def format_text_stamp(email: str, user_id: int, ts: str, ip: str, payload_b64: str, sig: str) -> str:
    """Format clear forensic watermark footer for text/plain files."""
    return (
        f"\n\n"
        f"--------------------------------------------------------------------------------\n"
        f"[ TRUSTVAULT CRYPTOGRAPHIC CHAIN OF CUSTODY & FORENSIC WATERMARK ]\n"
        f"Downloaded By : {email} (User #{user_id})\n"
        f"Timestamp     : {ts}\n"
        f"Source IP     : {ip}\n"
        f"Custody Key   : TV-{sig[:16].upper()}-{sig[-16:].upper()}\n"
        f"Audit Token   : {payload_b64}.{sig}\n"
        f"SECURITY NOTICE: This document is tracked. Tampering with this cryptographic\n"
        f"marker invalidates authenticity and constitutes unauthorized policy breach.\n"
        f"--------------------------------------------------------------------------------\n"
    )


# ---------------------------------------------------------------------------
# Zero-Width Steganography Engine (Invisible Watermarking for Text)
# ---------------------------------------------------------------------------
ZW_0 = "\u200b"
ZW_1 = "\u200c"
ZW_START = "\u200d"
ZW_END = "\u200e"

def embed_invisible_watermark(text: str, user_id: int, doc_id: str, sig_prefix: str) -> str:
    compact_payload = f"{user_id}:{doc_id}:{sig_prefix[:8]}"
    bits = "".join(f"{ord(c):08b}" for c in compact_payload)
    encoded_bits = "".join(ZW_1 if b == "1" else ZW_0 for b in bits)
    invisible_tag = f"{ZW_START}{encoded_bits}{ZW_END}"
    
    if "\n" in text:
        idx = text.find("\n")
        return text[:idx] + invisible_tag + text[idx:]
    elif " " in text:
        idx = text.find(" ")
        return text[:idx] + invisible_tag + text[idx:]
    else:
        return invisible_tag + text


def extract_invisible_watermark(text: str) -> Optional[Dict[str, str]]:
    start_pos = text.find(ZW_START)
    end_pos = text.find(ZW_END)
    if start_pos == -1 or end_pos == -1 or start_pos >= end_pos:
        return None

    encoded_bits = text[start_pos + 1:end_pos]
    bits = ""
    for ch in encoded_bits:
        if ch == ZW_0:
            bits += "0"
        elif ch == ZW_1:
            bits += "1"
        else:
            continue

    if len(bits) % 8 != 0 or not bits:
        return None

    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        chars.append(chr(int(byte, 2)))
    
    decoded_str = "".join(chars)
    parts = decoded_str.split(":", 2)
    if len(parts) == 3:
        return {
            "user_id": parts[0],
            "doc_id": parts[1],
            "sig_prefix": parts[2],
            "steganography_detected": True
        }
    return None


# ---------------------------------------------------------------------------
# Binary / Image / PDF Watermark Embedding & Extraction
# ---------------------------------------------------------------------------
MAGIC_TRAILER = b"\x00\x00__TRUSTVAULT_FORENSIC__\x00\x00"

def embed_binary_watermark(data: bytes, user_id: int, user_email: str, doc_id: str, sig: str) -> bytes:
    """
    Appends a forensic custody payload at the end of a binary file (PNG, JPG, PDF, DOCX).
    PNG, JPG, PDF parsers ignore data after standard end-of-file markers (IEND, %EOF, etc).
    """
    payload = {
        "user_id": user_id,
        "email": user_email.lower().strip(),
        "doc_id": str(doc_id),
        "sig": sig,
        "magic": "TV-FORENSIC-v1"
    }
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8"))
    trailer = MAGIC_TRAILER + encoded + MAGIC_TRAILER
    return data + trailer


def extract_binary_watermark(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Scans raw bytes of an uploaded image/PDF to find the embedded custody trailer.
    """
    if MAGIC_TRAILER not in data:
        return None
    try:
        parts = data.split(MAGIC_TRAILER)
        if len(parts) >= 3:
            raw_b64 = parts[-2]
            payload_json = base64.b64decode(raw_b64).decode("utf-8")
            parsed = json.loads(payload_json)
            if parsed.get("magic") == "TV-FORENSIC-v1":
                return parsed
    except Exception:
        pass
    return None
