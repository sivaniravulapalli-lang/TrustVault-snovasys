import json
import logging
import re
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from .config import GEMINI_API_KEY

logger = logging.getLogger("trustvault.ai")

GEMINI_MODEL = "gemini-1.5-flash"


def is_configured() -> bool:
    return bool(GEMINI_API_KEY)


def _call_gemini_api(prompt: str, system_instruction: str) -> Optional[str]:
    """
    Calls Google Gemini API with low temperature (0.1) for strictly deterministic,
    grounded, non-hallucinating responses.
    """
    if not GEMINI_API_KEY:
        return None

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": f"{system_instruction}\n\nTask and Input:\n{prompt}"}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,  # Strict grounding, anti-hallucination
            "topP": 0.8,
            "maxOutputTokens": 1024,
        }
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "TrustVault-AI/1.0"},
    )

    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "").strip()
    except Exception as exc:
        logger.warning("Gemini API call failed: %s", exc)

    return None


# ---------------------------------------------------------------------------
# Feature 1: AI SOC Threat Analyzer (for Admin)
# ---------------------------------------------------------------------------

def analyze_threat_logs(logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyzes audit logs to detect security threats (brute-force, probing, privilege escalation).
    Strict Guardrails: Analysis must be strictly derived from the provided log lines.
    """
    if not logs:
        return {
            "threat_level": "LOW",
            "summary": "No audit records found to analyze.",
            "anomalies": [],
            "recommendations": ["Maintain continuous audit monitoring."],
            "engine": "rule-based"
        }

    # Format compact log digest for Gemini
    log_lines = []
    failed_logins = 0
    denials = 0
    suspends = 0
    role_changes = 0

    for l in logs[:60]:
        action = l.get("action", "")
        actor = l.get("actor_email") or "anonymous"
        target = l.get("target_email") or ""
        doc = l.get("document_name") or ""
        detail = l.get("detail") or ""
        ip = l.get("ip") or "unknown"
        ts = l.get("created_at") or ""

        if action == "login_failed": failed_logins += 1
        elif action in ("access_denied", "grant_refused"): denials += 1
        elif action == "suspend": suspends += 1
        elif action == "role_change": role_changes += 1

        log_lines.append(f"[{ts}] action={action} actor={actor} target={target} doc={doc} ip={ip} detail={detail}")

    logs_text = "\n".join(log_lines)

    system_prompt = (
        "You are an expert SOC Analyst and Cybersecurity Investigator for TrustVault.\n"
        "STRICT GUARDRAILS & ANTI-HALLUCINATION RULES:\n"
        "1. Base your analysis SOLELY on the literal log events provided. Do NOT fabricate, assume, or hallucinate users, IPs, or events.\n"
        "2. If no malicious behavior is evident, classify threat_level as LOW and state that normal operations were observed.\n"
        "3. Output MUST be valid JSON with keys: threat_level (LOW|MEDIUM|HIGH|CRITICAL), summary (string), anomalies (list of strings), recommendations (list of strings)."
    )

    prompt = (
        f"Audit logs to analyze ({len(log_lines)} events):\n{logs_text}\n\n"
        "Return pure JSON:"
    )

    raw_ai = _call_gemini_api(prompt, system_prompt)
    if raw_ai:
        try:
            # Strip markdown code blocks if any
            clean_json = re.sub(r"^```json\s*|\s*```$", "", raw_ai.strip())
            parsed = json.loads(clean_json)
            parsed["engine"] = f"Gemini ({GEMINI_MODEL})"
            return parsed
        except Exception:
            pass

    # Deterministic Rule-Based Fallback (100% reliable, zero hallucination)
    anomalies = []
    level = "LOW"
    recommendations = ["Continue standard audit trail log retention."]

    if failed_logins >= 5:
        level = "HIGH"
        anomalies.append(f"Detected {failed_logins} failed login attempts (possible brute-force attack).")
        recommendations.append("Enforce temporary IP cooldowns and review lockout durations.")
    elif failed_logins > 0:
        anomalies.append(f"Recorded {failed_logins} failed login attempt(s).")

    if denials >= 3:
        level = "HIGH" if level != "CRITICAL" else level
        anomalies.append(f"Observed {denials} unauthorized access refusals (potential permission probing).")
        recommendations.append("Audit user access permissions and inspect client IPs.")
    elif denials > 0:
        anomalies.append(f"Recorded {denials} access refusal event(s).")

    if suspends > 0:
        anomalies.append(f"Administrator suspended {suspends} document(s) for security review.")

    if role_changes > 0:
        anomalies.append(f"{role_changes} user role modification(s) audited.")

    summary = (
        f"Audited {len(logs)} security events. Threat posture evaluated as {level} based on "
        f"{failed_logins} failed logins and {denials} access refusals."
    )

    return {
        "threat_level": level,
        "summary": summary,
        "anomalies": anomalies or ["All audited activities conform to expected baseline."],
        "recommendations": recommendations,
        "engine": "Deterministic SOC Engine"
    }


# ---------------------------------------------------------------------------
# Feature 2: DLP & Privacy Risk Scanner (for Uploads)
# ---------------------------------------------------------------------------

def scan_document_dlp(doc_name: str, content_text: str) -> Dict[str, Any]:
    """
    Scans document text for sensitive data (PII, credentials, financial records).
    Strict Guardrails: Flags ONLY items that literally appear in content.
    """
    text_sample = content_text[:4000] if content_text else ""

    system_prompt = (
        "You are an Enterprise Data Loss Prevention (DLP) and Privacy Compliance Scanner.\n"
        "STRICT GUARDRAILS & ANTI-HALLUCINATION RULES:\n"
        "1. Strictly analyze ONLY the text provided below. NEVER invent or hallucinate sensitive data or PII.\n"
        "2. If no sensitive data exists, classification MUST be PUBLIC or INTERNAL with zero findings.\n"
        "3. Output pure JSON with keys: classification (PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED), risk_level (LOW|MEDIUM|HIGH), findings (list of strings with redacted examples), sharing_advisory (string)."
    )

    prompt = (
        f"Document Name: {doc_name}\n"
        f"Document Text Content:\n{text_sample}\n\n"
        "Return pure JSON:"
    )

    raw_ai = _call_gemini_api(prompt, system_prompt)
    if raw_ai:
        try:
            clean_json = re.sub(r"^```json\s*|\s*```$", "", raw_ai.strip())
            parsed = json.loads(clean_json)
            parsed["engine"] = f"Gemini ({GEMINI_MODEL})"
            return parsed
        except Exception:
            pass

    # Deterministic Regex-based DLP Fallback
    findings = []
    classification = "INTERNAL"
    risk = "LOW"

    # 1. API Keys / Secrets regex
    if re.search(r"(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{8,}['\"]", text_sample, re.I):
        findings.append("Potential API Key, Secret, or Password detected in plaintext.")
        classification = "RESTRICTED"
        risk = "HIGH"

    # 2. Credit Card number pattern (13-19 digits, with or without spaces/dashes)
    if re.search(r"\b(?:\d[ -]*?){13,19}\b", text_sample) and re.search(r"(?:card|debit|credit|visa|mastercard|amex)", text_sample, re.I):
        findings.append("Detected payment card / debit card number pattern.")
        classification = "RESTRICTED"
        risk = "HIGH"
    elif re.search(r"\b(?:\d{4}[-\s]?){3}\d{4}\b", text_sample):
        findings.append("Detected 16-digit payment card number pattern.")
        classification = "RESTRICTED"
        risk = "HIGH"

    # 3. Aadhaar Number pattern (12 digits, e.g. 6243 3224 1234 or 624332241234)
    if re.search(r"(?:aadhaar|uidai|aadhar)[\s\w:]*\b\d{4}\s*\d{4}\s*\d{4}\b", text_sample, re.I) or re.search(r"\b[2-9]\d{3}\s+\d{4}\s+\d{4}\b", text_sample):
        findings.append("Detected 12-digit Indian Aadhaar Card (UIDAI) PII pattern.")
        classification = "RESTRICTED"
        risk = "HIGH"

    # 4. PAN Card (Indian Permanent Account Number)
    if re.search(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", text_sample, re.I):
        findings.append("Detected Indian PAN Card identifier pattern.")
        if risk == "LOW":
            classification = "CONFIDENTIAL"
            risk = "MEDIUM"

    # 5. Email patterns
    emails = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text_sample)
    if len(emails) >= 3:
        findings.append(f"Contains {len(emails)} email addresses (PII disclosure risk).")
        if risk == "LOW":
            classification = "CONFIDENTIAL"
            risk = "MEDIUM"

    # 6. Indian Phone number pattern
    if re.search(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b", text_sample):
        findings.append("Detected contact phone number pattern.")
        if risk == "LOW":
            classification = "CONFIDENTIAL"
            risk = "MEDIUM"

    advisory = (
        "Restricted content detected: ensure re-sharing rights ('can_share') are NOT granted to unauthorized third parties."
        if risk == "HIGH" else
        "Standard internal document: safe for internal team sharing."
    )

    return {
        "classification": classification,
        "risk_level": risk,
        "findings": findings or ["No sensitive credentials, payment cards, or PII patterns detected."],
        "sharing_advisory": advisory,
        "engine": "Deterministic DLP Engine"
    }


# ---------------------------------------------------------------------------
# Feature 3: RBAC-Guarded Document Summarizer (for Owner & Viewer)
# ---------------------------------------------------------------------------

def summarize_document(doc_name: str, content_text: str) -> Dict[str, Any]:
    """
    Summarizes document content for authorized readers.
    Strict Guardrails: Factual summary ONLY from text; no outside assumptions.
    """
    text_sample = content_text[:5000] if content_text else ""
    if not text_sample.strip():
        return {
            "summary": ["Document contains no extractable text or is a binary file."],
            "key_topics": ["Binary / Non-text"],
            "reading_time_saved_minutes": 0,
            "engine": "grounded"
        }

    word_count = len(text_sample.split())
    time_saved = max(1, round(word_count / 150))

    system_prompt = (
        "You are an Executive Document Intelligence Assistant.\n"
        "STRICT GUARDRAILS & ANTI-HALLUCINATION RULES:\n"
        "1. Factual grounding: Rely ONLY on the facts stated directly in the text. Do NOT assume, extrapolate, or hallucinate.\n"
        "2. If information is not in the text, do not invent it.\n"
        "3. Output pure JSON with keys: summary (list of max 3 concise bullet strings), key_topics (list of max 4 short topic tags)."
    )

    prompt = (
        f"Document Name: {doc_name}\n"
        f"Content:\n{text_sample}\n\n"
        "Return pure JSON:"
    )

    raw_ai = _call_gemini_api(prompt, system_prompt)
    if raw_ai:
        try:
            clean_json = re.sub(r"^```json\s*|\s*```$", "", raw_ai.strip())
            parsed = json.loads(clean_json)
            parsed["reading_time_saved_minutes"] = time_saved
            parsed["engine"] = f"Gemini ({GEMINI_MODEL})"
            return parsed
        except Exception:
            pass

    # Deterministic Extractive Summarizer Fallback
    sentences = [s.strip() for s in re.split(r"[.\n]\s*", text_sample) if len(s.strip()) > 15]
    top_bullets = sentences[:3] if sentences else ["Document review complete: brief content."]

    words = re.findall(r"\b[a-zA-Z]{5,}\b", text_sample.lower())
    stopwords = {"which", "there", "their", "about", "would", "these", "other", "document"}
    freq = {}
    for w in words:
        if w not in stopwords:
            freq[w] = freq.get(w, 0) + 1
    top_topics = [w.capitalize() for w, _ in sorted(freq.items(), key=lambda x: x[1], reverse=True)[:4]]

    return {
        "summary": top_bullets,
        "key_topics": top_topics or ["General"],
        "reading_time_saved_minutes": time_saved,
        "engine": "Extractive Intelligence Engine"
    }
