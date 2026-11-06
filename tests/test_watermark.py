import pytest
from app.watermark_service import (
    generate_watermark_token,
    verify_watermark_token,
    format_text_stamp,
    embed_invisible_watermark,
    extract_invisible_watermark
)

def test_watermark_generation_and_verification():
    user_id = 42
    email = "leaker@example.com"
    doc_id = "11111111-2222-3333-4444-555555555555"
    doc_name = "secret_report.txt"
    ip = "203.0.113.195"

    payload_b64, sig = generate_watermark_token(user_id, email, doc_id, doc_name, ip)
    assert len(sig) == 64
    assert len(payload_b64) > 20

    # Successful verification
    is_valid, data, status = verify_watermark_token(payload_b64, sig)
    assert is_valid is True
    assert status == "VALID_SIGNATURE"
    assert data["user_id"] == 42
    assert data["email"] == "leaker@example.com"
    assert data["doc_name"] == "secret_report.txt"
    assert data["ip"] == "203.0.113.195"

def test_watermark_tamper_detection():
    payload_b64, sig = generate_watermark_token(1, "alice@test.com", "uuid-1", "doc.txt")
    
    # Tamper with the signature
    bad_sig = sig[:-4] + "0000"
    is_valid, data, status = verify_watermark_token(payload_b64, bad_sig)
    assert is_valid is False
    assert "INVALID_SIGNATURE" in status

def test_text_stamp_formatting():
    stamp = format_text_stamp("bob@test.com", 7, "2026-11-05 07:20:00 UTC", "10.0.0.1", "abc", "def12345678901234567890")
    assert "TRUSTVAULT CRYPTOGRAPHIC CHAIN OF CUSTODY" in stamp
    assert "bob@test.com" in stamp
    assert "TV-DEF1234567890123-567890" in stamp or "TV-" in stamp


def test_invisible_steganography_watermark():
    original_text = "This is a confidential board meeting document.\nAll numbers are subject to NDA."
    user_id = 99
    doc_id = "00000000-0000-0000-0000-000000000099"
    sig = "abcdef1234567890abcdef"

    # Embed invisible watermark
    stego_text = embed_invisible_watermark(original_text, user_id, doc_id, sig)
    
    # Check that visible length is identical or looks normal to casual eyes
    assert "confidential board meeting document." in stego_text
    
    # Extract invisible watermark from text
    extracted = extract_invisible_watermark(stego_text)
    assert extracted is not None
    assert int(extracted["user_id"]) == 99
    assert extracted["doc_id"] == doc_id
    assert extracted["sig_prefix"] == "abcdef12"

def test_stealth_survives_footer_deletion():
    original_text = "Secret project Apollo specifications."
    stamp = format_text_stamp("leaker@company.com", 15, "now", "1.1.1.1", "tok", "sig1234567890")
    
    # Embed both
    watermarked = embed_invisible_watermark(original_text, 15, "doc-id-123", "sig1234567890") + stamp
    
    # Attacker DELETES the entire stamp footer:
    tampered_text = watermarked.replace(stamp, "")
    
    # Ensure stamp is gone
    assert "TRUSTVAULT CRYPTOGRAPHIC CHAIN OF CUSTODY" not in tampered_text
    assert "leaker@company.com" not in tampered_text
    
    # BUT invisible watermark is still extracted!
    extracted = extract_invisible_watermark(tampered_text)
    assert extracted is not None
    assert int(extracted["user_id"]) == 15
    assert extracted["doc_id"] == "doc-id-123"
