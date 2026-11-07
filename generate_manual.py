import os
import docx
from docx.shared import Inches, Pt, RGBColor

doc = docx.Document()

# Page Margins
for section in doc.sections:
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.8)
    section.left_margin = Inches(0.8)
    section.right_margin = Inches(0.8)

# Title
p_title = doc.add_paragraph()
r_title = p_title.add_run('TRUSTVAULT: ARCHITECTURE & INTERVIEW DEFENSE MANUAL')
r_title.bold = True
r_title.font.size = Pt(20)
r_title.font.color.rgb = RGBColor(11, 107, 140)

p_sub = doc.add_paragraph()
r_sub = p_sub.add_run('Comprehensive UI Block Walkthrough, Security Architecture & Judge Q&A Guide')
r_sub.italic = True
r_sub.font.size = Pt(11)
r_sub.font.color.rgb = RGBColor(100, 116, 139)

doc.add_paragraph('=' * 85)

sections_data = [
    {
        'title': '1. Top Navigation & Identity Bar (Header & Session Management)',
        'purpose': 'Brand identity display, session context tracking, self-contained in-app mailbox access, and client-side session termination.',
        'design': 'In-Memory JWT Storage: Tokens reside strictly in JavaScript memory closure, never in localStorage/sessionStorage to block token-scraping XSS attacks. Background polling targets lightweight unread counts without heavy DB overhead. Zero Knowledge admin separation ensures administrators cannot access document contents.',
        'script': 'In the header, user identity is maintained through memory-bound JWT tokens. By intentionally avoiding localStorage, we neutralize token-scraping XSS attacks. The top bar also integrates our self-contained In-App Mailbox, guaranteeing that security notifications, role-change alerts, and audit dispatches are visible even in an air-gapped evaluation environment without third-party email dependencies.',
        'pos_q': 'Why avoid storing the token in localStorage or cookies?',
        'pos_a': 'LocalStorage is globally readable by any script running on the page, making it susceptible to XSS token theft. While HttpOnly cookies mitigate XSS access, they expose the API to CSRF. In-memory JWTs combined with strict CORS and a rigid Content Security Policy (no unsafe-inline) provide the highest baseline security posture.',
        'neg_q': 'If you store tokens in memory, what happens when the user refreshes the page?',
        'neg_a': 'The user is required to authenticate again. In high-assurance security environments like banking terminals or confidential document vaults, session persistence across browser refreshes is deliberately discouraged to prevent session hijacking on unattended workstations.'
    },
    {
        'title': '2. Authentication View (Log In, Sign Up & 2-Step OTP Password Reset)',
        'purpose': 'Account creation, secure authentication against memory-hard password hashes, self-service OTP password recovery, and brute-force throttling.',
        'design': 'Argon2id password hashing provides state-of-the-art resistance to GPU/ASIC cracking. Dynamic 2-step OTP flow only shows verification boxes after successful email dispatch. Anti-enumeration defense ensures identical messaging and timing-balanced verification using dummy hashes.',
        'script': 'Our authentication module was built with anti-enumeration and brute-force defenses at its core. We use Argon2id password hashing, which resists GPU-based offline cracking. Failed logins show a contextual tooltip displaying remaining attempts derived from our sliding-window database audit logs. To prevent timing attacks, we verify against a dummy hash when an email does not exist, preventing attackers from probing valid accounts through response latency.',
        'pos_q': 'How does the lockout system withstand distributed brute-force attacks across multiple IPs?',
        'pos_a': 'We implement a dual-constraint sliding window via our database-backed audit log: max 5 failed attempts per email-and-IP pair, but also an aggregated cap of 30 attempts per email across all IPs, and 30 attempts per IP across all accounts. This blocks distributed botnet attacks targeting a single account, as well as password-spraying attacks from a single source.',
        'neg_q': 'Is not displaying remaining attempts helpful to the attacker?',
        'neg_a': 'It provides legitimate users with fair warning before an account lockout occurs, preventing accidental denial-of-service. Because our threshold is low (5 attempts) and our password entropy rule requires 10+ characters, 5 attempts provide negligible brute-force surface while significantly improving the user experience.'
    },
    {
        'title': '3. Document Repository View (My Documents & Shared With Me)',
        'purpose': 'Partitioned workspaces for master uploads vs delegated documents, magic-byte sniffing validation, multi-parametric search, and dedicated document workspace navigation.',
        'design': 'MIME and byte-level sniffing inspects raw headers (%PDF-, PNG, ZIP headers) rather than trusting filenames. SQL scope partitioning isolates owner records from active, non-suspended shares. Collision-free file persistence prevents directory traversal.',
        'script': 'The repository implements strict content validation and server-enforced isolation. When a document is ingested, we do not trust the HTTP Content-Type header or the file extension; we inspect the raw byte magic numbers to prevent malicious uploads. The workspace cleanly separates ownership from delegation, and selecting any record transitions the user to an isolated document workspace.',
        'pos_q': 'How does the system ensure an admin cannot sneak into this list and read files?',
        'pos_a': 'Zero Knowledge Architecture. The visible() database query specifically excludes admins from document listings unless an explicit permission or ownership record exists. Furthermore, document fetch routes verify permission boundaries through our require() authorization gateway, which strictly rejects admin access to file bodies.',
        'neg_q': 'Why limit uploads to 10 MB and a handful of extensions?',
        'neg_a': '10 MB aligns with typical enterprise documentation profiles while mitigating Denial-of-Service (DoS) attacks via memory exhaustion. Restricting extensions to common, auditable business formats allows us to implement reliable magic-byte sniffing without relying on external dependencies.'
    },
    {
        'title': '4. Single Document Detail Workspace (The Dedicated Document Hub)',
        'purpose': 'In-place document management, privileged View vs Download action controls, AI synopsis, DLP compliance scan, and hierarchical access delegation.',
        'design': 'Fine-grained RBAC gates View vs Download. Hierarchical DAG enforcement blocks unauthorized re-sharing. Cascading revocation automatically crawls and prunes subordinate access branches when a manager is revoked.',
        'script': 'The Document Workspace reflects our Least-Privilege philosophy. Actions are rendered conditionally based on the users evaluated permissions. We differentiate between in-browser viewing and persistent local storage through our privileged can_download gate. When permissions are delegated, our backend enforces a strict access hierarchy: delegates cannot grant rights greater than their own. If a managers access is revoked, our cascading revocation algorithm traverses the permission graph and automatically revokes access for all downstream delegates.',
        'pos_q': 'Explain how Cascading Revocation works when access is revoked.',
        'pos_a': 'In revoke_descendants(), we execute a Breadth-First Search across the permissions table using the revoked user ID as the root. Any child permissions with granted_by == current_node are appended to the deletion list and enqueued. This cascades iteratively until the branch is pruned, ensuring orphaned permissions cannot persist.',
        'neg_q': 'If you allow in-browser viewing, what stops an unauthorized user from downloading the file via developer tools?',
        'neg_a': 'Viewing and Downloading use distinct API endpoints with separate authorization policies. The /view endpoint returns ephemeral, display-optimized inline representations. The raw file payload is only accessible through the /download endpoint, which verifies the can_download permission on the backend. Client-side inspection cannot bypass backend authorization.'
    },
    {
        'title': '5. Forensic Watermark & Multi-Hop Lineage Engine',
        'purpose': 'Exfiltration attribution, dual-layer forensic tracking (visible footer + invisible zero-width steganography + binary trailers), and multi-hop lineage reconstruction.',
        'design': 'Cryptographic HMAC-SHA256 signature binding user ID, timestamp, and IP. Zero-width Unicode encoding embeds invisible bits directly in text bodies that survive footer deletion. Binary trailers attach custody tokens past EOF markers for images/PDFs. Every decoder lookup is permanently recorded in the audit trail.',
        'script': 'To counter document exfiltration, we built a dual-layer forensic watermarking engine. When a privileged user downloads a file, we generate an HMAC-SHA256 custody token bound to their user ID, IP address, and timestamp. In text files, this metadata is inserted as both a visible footer and an invisible zero-width steganographic payload embedded directly in the text body. If an adversary deletes the visible footer, the invisible Unicode sequence survives and can still be decoded. For binary files like images and PDFs, we inject an unforgeable custody trailer beyond the files natural EOF marker. When an administrator uploads a leaked file to our Forensic Decoder, the system parses the hidden markers and reconstructs the full multi-hop lineage, linking the leaker back to the original author.',
        'pos_q': 'How does the binary trailer avoid corrupting images or PDFs?',
        'pos_a': 'Format specifications define explicit EOF terminating markers—such as IEND in PNG, 0xFF 0xD9 in JPEG, and %%EOF in PDF. Standard image decoders cease processing once this marker is encountered. We append our cryptographic trailer past this byte offset, ensuring the image remains viewable while carrying the underlying custody payload.',
        'neg_q': 'What if the adversary takes a screenshot or prints the document to PDF, stripping both zero-width characters and binary trailers?',
        'neg_a': 'Screen capture operates outside of file-based provenance tracking. However, we address this through three complementary controls: 1. Strict Download Isolation: Only users with explicit can_download authorization can export files, reducing the suspect pool. 2. Non-Repudiation Audit Logs: Every download logs the user ID, timestamp, and IP address to an append-only audit trail. If a document leaks, the download logs provide definitive evidence of who retrieved the file. 3. Absence as Tampering Evidence: Under corporate compliance policies, removing forensic markers constitutes evidence of willful policy violation, shifting liability to authorized downloaders.'
    },
    {
        'title': '6. AI Intelligence Center (DLP Scanner, Document Summarizer & SOC Threat Analysis)',
        'purpose': 'Data Loss Prevention (DLP) compliance scan, RBAC-guarded executive summarizer, and automated SOC audit log threat analysis.',
        'design': 'Defense-in-depth pre-ingestion redaction masks PII/secrets before sending to Gemini API. Deterministic offline fallback using local regex engines ensures 100% availability. Strict system prompts with temperature=0.1 eliminate hallucination risks.',
        'script': 'We implemented our AI features following strict security and privacy standards. In our DLP scanner, document contents are analyzed using a dual-engine architecture: an enterprise LLM (Gemini 1.5 Flash) constrained by rigid anti-hallucination guardrails (temperature=0.1), backed by an air-gapped deterministic regex scanner. To prevent data leakage via AI ingestion, sensitive tokens like Aadhaar or payment card numbers are redacted locally before API dispatch. Furthermore, all AI endpoints inherit our RBAC controls—meaning administrators cannot view or summarize documents without explicit user delegation.',
        'pos_q': 'How do you guarantee the AI will not hallucinate a breach when analyzing SOC audit logs?',
        'pos_a': 'We combine low temperature settings (0.1) with a two-pass constraint system. The system prompt restricts findings to literal log events provided in the prompt context. If the API returns invalid or unstructured output, our parser fails over to our deterministic log analyzer, ensuring zero-hallucination guarantees in production.',
        'neg_q': 'Why permit third-party LLM processing on sensitive corporate documents?',
        'neg_a': 'In enterprise deployments, document ingestion connects to an air-gapped or private VPC instance (such as Google Vertex AI with Zero Data Retention). For environments that prohibit external cloud processing, our deterministic DLP and rule-based SOC engines run entirely locally, requiring zero external network calls.'
    }
]

for sec in sections_data:
    h = doc.add_heading(sec['title'], level=1)
    h.paragraph_format.space_before = Pt(14)
    h.paragraph_format.space_after = Pt(6)
    
    # Purpose
    p = doc.add_paragraph()
    r_label = p.add_run('Purpose & Functionality: ')
    r_label.bold = True
    r_label.font.color.rgb = RGBColor(15, 23, 42)
    p.add_run(sec['purpose'])
    
    # Architecture
    p = doc.add_paragraph()
    r_label = p.add_run('Design & Engineering: ')
    r_label.bold = True
    r_label.font.color.rgb = RGBColor(15, 23, 42)
    p.add_run(sec['design'])
    
    # Interview Script
    p = doc.add_paragraph()
    r_label = p.add_run('Interview Presentation Script: ')
    r_label.bold = True
    r_label.font.color.rgb = RGBColor(3, 105, 161)
    script_text = '"' + sec['script'] + '"'
    r_text = p.add_run(script_text)
    r_text.italic = True
    
    # Positive Q&A
    p = doc.add_paragraph()
    pos_q_text = '• Positive / Deep Question: "' + sec['pos_q'] + '"\n'
    r_q = p.add_run(pos_q_text)
    r_q.bold = True
    r_q.font.color.rgb = RGBColor(22, 101, 52)
    r_a_label = p.add_run('  Answer: ')
    r_a_label.bold = True
    p.add_run(sec['pos_a'])
    
    # Negative Q&A
    p = doc.add_paragraph()
    neg_q_text = '• Negative / Critical Question: "' + sec['neg_q'] + '"\n'
    r_q = p.add_run(neg_q_text)
    r_q.bold = True
    r_q.font.color.rgb = RGBColor(153, 27, 27)
    r_a_label = p.add_run('  Answer: ')
    r_a_label.bold = True
    p.add_run(sec['neg_a'])
    
    doc.add_paragraph('-' * 70)

# Master Architecture Table
doc.add_heading('7. Master Architectural Summary for Interview Judges', level=1)
table = doc.add_table(rows=1, cols=3)
table.style = 'Light Shading Accent 1'
hdr_cells = table.rows[0].cells
hdr_cells[0].text = 'Dimension'
hdr_cells[1].text = 'Implementation in TrustVault'
hdr_cells[2].text = 'Security Significance'

rows_content = [
    ('Authentication', 'Argon2id + Memory-Bound JWT', 'Neutralizes token-scraping XSS and GPU-based hash cracking.'),
    ('Session Persistence', 'In-Memory Only (Lost on Refresh)', 'Prevents session hijacking on unattended workstations.'),
    ('Authorization Model', 'Hierarchical RBAC + DAG Traversal', 'Prevents privilege escalation; prunes orphaned delegate rights.'),
    ('Data Ingestion', 'Byte Magic-Number Sniffing', 'Blocks malicious payloads masquerading under false extensions.'),
    ('DLP & Privacy', 'Local Regex Masking + Gemini Fallback', 'Prevents raw credential leakage to external LLM providers.'),
    ('Forensic Attribution', 'Zero-Width Steganography + Binary Trailers', 'Traces leaked files to user/IP even if footers are stripped.'),
    ('Audit Trails', 'Immutable Append-Only Logging', 'Maintains cryptographic chain of custody for legal compliance.'),
    ('Fault Tolerance', 'Self-Contained In-App Mailbox', 'Enables 100% offline evaluation without external mail dependencies.')
]

for dim, impl, sec in rows_content:
    row_cells = table.add_row().cells
    row_cells[0].text = dim
    row_cells[1].text = impl
    row_cells[2].text = sec

downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads', 'TrustVault_Interview_Manual.docx')
doc.save(downloads_path)
print('SUCCESS_SAVED:', downloads_path)
