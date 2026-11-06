"use strict";
// Test UI for DocShare. The token lives only in this variable (lost on refresh).
// All user data is inserted with textContent/createTextNode, never injected as raw HTML.
let token = null, me = null, tab = null, current = null;

const $ = (s) => document.querySelector(s);

function h(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) {
    if (c == null || c === false) continue;
    e.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return e;
}

let sayTimer = null;
function say(text, ok = true) {
  const m = $("#msg");
  m.textContent = text;
  m.className = ok ? "ok" : "err";
  if (sayTimer) clearTimeout(sayTimer);
  if (text && ok) {
    sayTimer = setTimeout(() => {
      if (m.textContent === text) {
        m.textContent = "";
        m.className = "";
      }
    }, 4000);
  }
}

async function api(path, { method = "GET", json, form, blob } = {}) {
  const headers = {};
  let body;
  if (token) headers.Authorization = "Bearer " + token;
  if (json) { headers["Content-Type"] = "application/json"; body = JSON.stringify(json); }
  else if (form) body = form;
  const r = await fetch(path, { method, headers, body });
  if (r.status === 401 && token) { logout(); throw new Error("401 Session ended, log in again"); }
  if (!r.ok) {
    let detail = "";
    try { const d = await r.json(); detail = typeof d.detail === "string" ? d.detail : "invalid input"; } catch (e) {}
    throw new Error(r.status + " " + detail);
  }
  if (blob) return r.blob();
  return r.status === 204 ? null : r.json();
}

// run an action, show its result or its error (the server decides what is allowed)
async function act(fn, okText) {
  try { const r = await fn(); if (okText) say(okText); return r; }
  catch (e) { say(e.message, false); }
}

function logout() { token = me = tab = current = null; say(""); render(); }

function table(cols, rows) {
  return h("div", { class: "scroll" }, h("table", {},
    h("tr", {}, cols.map((c) => h("th", {}, c))),
    rows.map((r) => h("tr", {}, r.map((v) => h("td", {}, v))))));
}

// "read, download, share" for an access record from the server
function accessText(a) {
  if (a.owner) return "owner (everything)";
  return a.level + (a.can_download ? ", download" : "") + (a.can_share ? ", share" : "");
}

// ---------- login / register ----------
let authMode = "login";            // which of the two forms is shown: "login" or "register"

function makeEyeSvg(slash = false) {
  const NS = "http://www.w3.org/2000/svg";
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("width", "18");
  s.setAttribute("height", "18");
  s.setAttribute("fill", "none");
  s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "2");
  s.setAttribute("stroke-linecap", "round");
  s.setAttribute("stroke-linejoin", "round");
  if (!slash) {
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", "M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z");
    const c = document.createElementNS(NS, "circle");
    c.setAttribute("cx", "12");
    c.setAttribute("cy", "12");
    c.setAttribute("r", "3");
    s.append(p, c);
  } else {
    const p1 = document.createElementNS(NS, "path");
    p1.setAttribute("d", "M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24");
    const l = document.createElementNS(NS, "line");
    l.setAttribute("x1", "1");
    l.setAttribute("y1", "1");
    l.setAttribute("x2", "23");
    l.setAttribute("y2", "23");
    s.append(p1, l);
  }
  return s;
}

function passwordBox(autocomplete) {
  const pw = h("input", { type: "password", placeholder: "password (10+ characters)", autocomplete });
  const toggle = h("button", {
    type: "button", class: "eye", title: "Show password",
    onclick: (e) => {
      e.preventDefault();
      const show = pw.type === "password";
      pw.type = show ? "text" : "password";
      toggle.replaceChildren(makeEyeSvg(show));
      toggle.title = show ? "Hide password" : "Show password";
    }
  }, makeEyeSvg(false));
  return { pw, box: h("div", { class: "pwbox" }, pw, toggle) };
}

function authView(prefillEmail = "") {
  const switcher = h("div", { class: "row tabs" },
    h("button", { class: authMode === "login" ? "on" : "", onclick: () => { authMode = "login"; say(""); render(); } }, "Log In"),
    h("button", { class: authMode === "register" ? "on" : "", onclick: () => { authMode = "register"; say(""); render(); } }, "Sign Up"));

  if (authMode === "forgot") {
    let step = 1; // 1: enter email, 2: enter otp & new password
    const email = h("input", { type: "email", placeholder: "Enter your registered email", autocomplete: "username", value: prefillEmail });
    const otpInput = h("input", { placeholder: "Enter 6-digit OTP from email" });
    const { pw, box: pwBox } = passwordBox("new-password");
    const msgTooltip = h("div", { class: "inline-error-tooltip" });
    const dynamicStack = h("div", { class: "stack" }, email);

    const btn = h("button", { onclick: async () => {
      msgTooltip.className = "inline-error-tooltip";
      msgTooltip.textContent = "";

      if (step === 1) {
        if (!email.value.trim() || !email.value.includes("@")) {
          msgTooltip.textContent = "Please enter a valid email address.";
          msgTooltip.className = "inline-error-tooltip visible";
          return;
        }
        try {
          const res = await api("/auth/forgot-password", { method: "POST", json: { email: email.value.trim() } });
          msgTooltip.textContent = res.message || "OTP sent! Check your email / in-app inbox.";
          msgTooltip.className = "inline-error-tooltip visible success";
          step = 2;
          email.readOnly = true;
          email.style.opacity = "0.7";
          dynamicStack.replaceChildren(email, otpInput, pwBox, btn);
          btn.textContent = "Reset Password";
        } catch (err) {
          msgTooltip.textContent = err.message.replace(/^\d+ /, "");
          msgTooltip.className = "inline-error-tooltip visible";
        }
      } else {
        if (!otpInput.value.trim() || otpInput.value.trim().length !== 6) {
          msgTooltip.textContent = "Please enter the 6-digit verification OTP.";
          msgTooltip.className = "inline-error-tooltip visible";
          return;
        }
        if (!pw.value || pw.value.length < 10) {
          msgTooltip.textContent = "New password must be at least 10 characters.";
          msgTooltip.className = "inline-error-tooltip visible";
          return;
        }
        try {
          const res = await api("/auth/reset-password", {
            method: "POST",
            json: { email: email.value.trim(), otp: otpInput.value.trim(), new_password: pw.value }
          });
          authMode = "login";
          $("#app").replaceChildren(authView(email.value.trim()));
          const loginTooltip = $("#app .inline-error-tooltip");
          if (loginTooltip) {
            loginTooltip.textContent = "Password reset successful! Please log in with your new password.";
            loginTooltip.className = "inline-error-tooltip visible success";
          }
        } catch (err) {
          msgTooltip.textContent = err.message.replace(/^\d+ /, "");
          msgTooltip.className = "inline-error-tooltip visible";
        }
      }
    } }, "Send Verification OTP");

    dynamicStack.append(btn);

    return h("div", { class: "card auth" },
      switcher,
      h("h2", {}, "Reset Password"),
      msgTooltip,
      dynamicStack,
      h("p", { class: "muted", style: "font-size: 13px; text-align: center; margin-top: 14px;" },
        "Remembered your password? ",
        h("a", { href: "#", onclick: (e) => { e.preventDefault(); authMode = "login"; say(""); render(); } }, "Log In")
      )
    );
  }

  if (authMode === "register") {
    const name = h("input", { placeholder: "Full Name", autocomplete: "name" });
    const email = h("input", { type: "email", placeholder: "Email address", autocomplete: "username" });
    const { pw, box } = passwordBox("new-password");
    const regTooltip = h("div", { class: "inline-error-tooltip" });

    const register = async () => {
      regTooltip.className = "inline-error-tooltip";
      regTooltip.textContent = "";

      if (!name.value.trim()) {
        regTooltip.textContent = "Please enter your full name.";
        regTooltip.className = "inline-error-tooltip visible";
        return;
      }
      if (!email.value.trim() || !email.value.includes("@")) {
        regTooltip.textContent = "Please enter a valid email address.";
        regTooltip.className = "inline-error-tooltip visible";
        return;
      }
      if (!pw.value || pw.value.length < 10) {
        regTooltip.textContent = "Password must be at least 10 characters long.";
        regTooltip.className = "inline-error-tooltip visible";
        return;
      }

      try {
        await api("/auth/register", {
          method: "POST",
          json: { name: name.value.trim(), email: email.value.trim(), password: pw.value }
        });
        authMode = "login";
        $("#app").replaceChildren(authView(email.value.trim()));
        const loginTooltip = $("#app .inline-error-tooltip");
        if (loginTooltip) {
          loginTooltip.textContent = "Account successfully registered! Please log in.";
          loginTooltip.className = "inline-error-tooltip visible success";
        }
      } catch (err) {
        const cleanMsg = err.message.replace(/^\d+ /, "");
        regTooltip.textContent = cleanMsg;
        regTooltip.className = "inline-error-tooltip visible";
      }
    };
    return h("div", { class: "card auth" },
      switcher,
      h("h2", {}, "Sign Up for TrustVault"),
      regTooltip,
      h("div", { class: "stack" }, name, email, box, h("button", { onclick: register }, "Sign Up")),
      h("p", { class: "muted", style: "font-size: 13px; text-align: center; margin-top: 14px;" },
        "Already have an account? ",
        h("a", { href: "#", onclick: (e) => { e.preventDefault(); authMode = "login"; say(""); render(); } }, "Log In")
      )
    );
  }

  const email = h("input", { type: "email", placeholder: "Email address", autocomplete: "username", value: prefillEmail });
  const { pw, box } = passwordBox("current-password");
  const inlineError = h("div", { class: "inline-error-tooltip" });

  const login = async () => {
    inlineError.className = "inline-error-tooltip";
    inlineError.textContent = "";

    if (!email.value.trim() || !email.value.includes("@")) {
      inlineError.textContent = "Please enter a valid email address.";
      inlineError.className = "inline-error-tooltip visible";
      return;
    }
    if (!pw.value) {
      inlineError.textContent = "Please enter your password.";
      inlineError.className = "inline-error-tooltip visible";
      return;
    }

    let t;
    try {
      t = await api("/auth/login", { method: "POST", json: { email: email.value.trim(), password: pw.value } });
    } catch (e) {
      const cleanMsg = e.message.replace(/^\d+ /, "");
      inlineError.textContent = cleanMsg;
      inlineError.className = "inline-error-tooltip visible";
      return; // Do not call say() to prevent duplicate message
    }
    token = t.access_token;
    me = await act(() => api("/auth/me"));
    tab = null;
    say("Logged in successfully");
    render();
  };
  return h("div", { class: "card auth" },
    switcher,
    h("h2", {}, "Log In to TrustVault"),
    inlineError,
    h("div", { class: "stack" },
      email,
      box,
      h("div", { style: "text-align: right; margin-top: -4px;" },
        h("a", {
          href: "#",
          style: "font-size: 12px; color: #38bdf8; text-decoration: none;",
          onclick: (e) => { e.preventDefault(); authMode = "forgot"; say(""); render(); }
        }, "Forgot password?")
      ),
      h("button", { onclick: login }, "Log In")
    ),
    h("p", { class: "muted", style: "font-size: 13px; text-align: center; margin-top: 14px;" },
      "Don't have an account? ",
      h("a", { href: "#", onclick: (e) => { e.preventDefault(); authMode = "register"; say(""); render(); } }, "Sign Up")
    )
  );
}

// ---------- documents (My documents / Shared with me) ----------
// Same list and limit as FILE_TYPES / MAX_UPLOAD_BYTES on the server. This check only saves
// the user a wasted upload; the server validates every file again and has the final say.
const ACCEPT_EXT = [".pdf", ".png", ".jpg", ".jpeg", ".txt", ".docx"];
const MAX_MB = 10;
const UPLOAD_HINT = `Accepted: PDF, PNG, JPG, TXT, DOCX · Max ${MAX_MB} MB`;

function precheck(f) {
  const dot = f.name.lastIndexOf(".");
  const ext = dot >= 0 ? f.name.slice(dot).toLowerCase() : "";
  if (!ACCEPT_EXT.includes(ext))
    return `${ext || "Files without an extension"} files are not accepted. ${UPLOAD_HINT}`;
  if (f.size > MAX_MB * 1024 * 1024)
    return `The file is ${(f.size / 1048576).toFixed(1)} MB. Maximum is ${MAX_MB} MB.`;
  if (f.size === 0) return "The file is empty.";
  return null;
}

function uploadForm() {
  const file = h("input", { type: "file", accept: ACCEPT_EXT.join(",") });
  const cat = h("input", { placeholder: "category (optional)" });
  const note = h("p", { class: "muted hint" }, UPLOAD_HINT);
  const fail = (text) => { note.textContent = text; note.className = "hint err"; say(text, false); };
  const go = async () => {
    const chosen = file.files[0];
    if (!chosen) return fail("Choose a file first.");
    const problem = precheck(chosen);
    if (problem) return fail(problem);
    const f = new FormData();
    f.append("file", chosen);
    if (cat.value) f.append("category", cat.value);
    try {
      await api("/documents", { method: "POST", form: f });
    } catch (e) { return fail("Upload failed: " + e.message.replace(/^\d+ /, "")); }
    note.textContent = UPLOAD_HINT; note.className = "muted hint";
    file.value = ""; cat.value = "";
    say("Uploaded");
    loadDocs();
  };
  return h("div", { class: "card" }, h("h2", {}, "Upload"),
    h("div", { class: "row" }, file, cat, h("button", { onclick: go }, "Upload")), note);
}

function searchForm() {
  const f = {
    q: h("input", { placeholder: "name contains" }),
    category: h("input", { placeholder: "category" }),
    date_from: h("input", { type: "date", title: "from" }),
    date_to: h("input", { type: "date", title: "to" }),
  };
  if (tab === "shared") f.owner = h("input", { placeholder: "owner email" });
  const go = () => loadDocs(Object.fromEntries(Object.entries(f).filter(([, el]) => el.value).map(([k, el]) => [k, el.value])));
  return h("div", { class: "row" }, Object.values(f), h("button", { onclick: go }, "Search"));
}

function sharedWithCell(list) {
  if (!list.length) return h("span", { class: "muted" }, "nobody");
  return h("div", {}, list.map((s) => h("div", {}, `${s.email}: ${accessText({ ...s, owner: false })}`)));
}

async function loadDocs(params = {}) {
  const docs = await act(() => api("/documents?" + new URLSearchParams({ scope: tab, ...params })));
  if (!docs) return;
  const open = (d) => h("button", { class: "ghost", onclick: () => openDoc(d) }, "Open");
  const nameCell = (d) => d.suspended ? [d.name, " ", h("span", { class: "badge" }, "suspended")] : d.name;
  const box = $("#doclist");
  if (!docs.length) {
    box.replaceChildren(h("p", { class: "muted" }, tab === "mine" ? "You have not uploaded anything yet." : "Nothing has been shared with you."));
  } else if (tab === "mine") {
    box.replaceChildren(table(["Name", "Category", "Size", "Created", "Shared with (and their rights)", ""],
      docs.map((d) => [nameCell(d), d.category || "", d.size, d.created_at.slice(0, 10), sharedWithCell(d.shared_with), open(d)])));
  } else {
    box.replaceChildren(table(["Name", "Category", "Owner", "My rights", "Size", "Created", ""],
      docs.map((d) => [nameCell(d), d.category || "", d.owner_email, accessText(d.my_access), d.size, d.created_at.slice(0, 10), open(d)])));
  }
}

function docsView() {
  const wrap = h("div", { class: "stack" });
  if (tab === "mine") wrap.append(uploadForm());
  wrap.append(h("div", { class: "card" },
    h("h2", {}, tab === "mine" ? "My documents" : "Shared with me"), searchForm(), h("div", { id: "doclist" })));
  wrap.append(h("div", { id: "detail" }));
  setTimeout(() => loadDocs());
  return wrap;
}

async function fetchBlob(d, kind) { return act(() => api(`/documents/${d.id}/${kind}`, { blob: true })); }

async function showAiSummaryModal(d) {
  function closeModal() {
    const m = $("#ai-modal");
    if (m) m.remove();
  }

  const modalBox = h("div", { class: "card tg-modal-content", style: "max-width: 540px;" },
    h("div", { class: "modal-header" },
      h("h3", {}, `🤖 AI Summary: ${d.name}`),
      h("button", { class: "ghost close-btn", onclick: closeModal }, "✕")
    ),
    h("div", { class: "muted", style: "text-align: center; padding: 20px 0;" }, "Analyzing document with Gemini AI...")
  );

  const backdrop = h("div", {
    id: "ai-modal",
    class: "modal-backdrop",
    onclick: (e) => { if (e.target === backdrop) closeModal(); }
  }, modalBox);

  const existing = $("#ai-modal");
  if (existing) existing.remove();
  document.body.append(backdrop);

  try {
    const res = await api(`/documents/${d.id}/summarize`, { method: "POST" });
    const bullets = (res.summary || []).map(s => h("li", { style: "margin-bottom: 6px;" }, s));
    const tags = (res.key_topics || []).map(t => h("span", { class: "topic-tag" }, t));

    modalBox.replaceChildren(
      h("div", { class: "modal-header" },
        h("h3", {}, `🤖 AI Summary: ${d.name}`),
        h("button", { class: "ghost close-btn", onclick: closeModal }, "✕")
      ),
      h("div", { class: "row between", style: "margin-bottom: 12px; font-size: 12px;" },
        h("span", { class: "muted" }, `Engine: ${res.engine || "Gemini"}`),
        res.reading_time_saved_minutes ? h("span", { style: "color: #34d399;" }, `⏱️ ~${res.reading_time_saved_minutes} min read saved`) : null
      ),
      h("div", { class: "mail-body-text", style: "margin-bottom: 12px;" },
        h("strong", {}, "Executive Summary:"),
        h("ul", { style: "margin: 8px 0 4px 18px; padding: 0;" }, bullets)
      ),
      h("div", { style: "margin-bottom: 16px;" },
        h("strong", { style: "font-size: 12px; margin-right: 8px;" }, "Key Topics:"),
        tags
      ),
      h("div", { class: "muted", style: "font-size: 11px; margin-bottom: 14px;" },
        "🔒 Grounding Guardrail: Analysis strictly restricted to literal document text with zero hallucination guarantee."
      ),
      h("div", { class: "row", style: "justify-content: flex-end;" },
        h("button", { onclick: closeModal }, "Close")
      )
    );
  } catch (err) {
    modalBox.replaceChildren(
      h("div", { class: "modal-header" },
        h("h3", {}, "AI Summary Error"),
        h("button", { class: "ghost close-btn", onclick: closeModal }, "✕")
      ),
      h("p", { class: "hint err" }, err.message),
      h("button", { onclick: closeModal }, "Close")
    );
  }
}

async function showAiDlpModal(d) {
  function closeModal() {
    const m = $("#ai-modal");
    if (m) m.remove();
  }

  const modalBox = h("div", { class: "card tg-modal-content", style: "max-width: 540px;" },
    h("div", { class: "modal-header" },
      h("h3", {}, `🛡️ DLP Compliance Scan: ${d.name}`),
      h("button", { class: "ghost close-btn", onclick: closeModal }, "✕")
    ),
    h("div", { class: "muted", style: "text-align: center; padding: 20px 0;" }, "Scanning for sensitive credentials & PII...")
  );

  const backdrop = h("div", {
    id: "ai-modal",
    class: "modal-backdrop",
    onclick: (e) => { if (e.target === backdrop) closeModal(); }
  }, modalBox);

  const existing = $("#ai-modal");
  if (existing) existing.remove();
  document.body.append(backdrop);

  try {
    const res = await api(`/documents/${d.id}/scan-dlp`, { method: "POST" });
    const findingsList = (res.findings || []).map(f => h("li", { style: "margin-bottom: 4px;" }, f));

    modalBox.replaceChildren(
      h("div", { class: "modal-header" },
        h("h3", {}, `🛡️ DLP Compliance Scan: ${d.name}`),
        h("button", { class: "ghost close-btn", onclick: closeModal }, "✕")
      ),
      h("div", { class: "row between", style: "margin-bottom: 12px;" },
        h("div", {},
          h("span", { class: "muted", style: "font-size: 12px; margin-right: 8px;" }, "Classification:"),
          h("span", { class: "threat-badge " + (res.classification === "RESTRICTED" ? "HIGH" : res.classification === "CONFIDENTIAL" ? "MEDIUM" : "LOW") }, res.classification)
        ),
        h("span", { class: "muted", style: "font-size: 12px;" }, `Risk: ${res.risk_level}`)
      ),
      h("div", { class: "mail-body-text", style: "margin-bottom: 12px;" },
        h("strong", {}, "Sensitive Data Findings:"),
        h("ul", { style: "margin: 8px 0 4px 18px; padding: 0;" }, findingsList)
      ),
      h("div", { class: "tg-status-box", style: "margin-bottom: 14px; font-size: 12px;" },
        h("strong", {}, "Sharing Advisory: "),
        h("span", {}, res.sharing_advisory)
      ),
      h("div", { class: "row between" },
        h("span", { class: "muted", style: "font-size: 11px;" }, `Engine: ${res.engine || "Gemini"}`),
        h("button", { onclick: closeModal }, "Close")
      )
    );
  } catch (err) {
    modalBox.replaceChildren(
      h("div", { class: "modal-header" },
        h("h3", {}, "DLP Scan Error"),
        h("button", { class: "ghost close-btn", onclick: closeModal }, "✕")
      ),
      h("p", { class: "hint err" }, err.message),
      h("button", { onclick: closeModal }, "Close")
    );
  }
}

async function openDoc(d) {
  current = d;
  const a = d.my_access;
  if (d.suspended) {
    $("#detail").replaceChildren(h("div", { class: "card" }, h("h2", {}, d.name),
      h("p", { class: "muted" }, "This document is suspended by an administrator. Nobody can open it until it is restored.")));
    return;
  }
  const rename = h("input", { placeholder: "new name" });
  const newCat = h("input", { placeholder: "new category" });
  const replace = h("input", { type: "file", accept: ACCEPT_EXT.join(",") });

  const view = async () => {
    if (d.name.toLowerCase().endsWith(".docx") || (d.mime && d.mime.includes("wordprocessingml"))) {
      $("#preview").replaceChildren(
        h("p", { class: "muted" }, "ఈ రకం ఫైల్‌ను preview చేయలేం, దయచేసి Download బటన్ వాడండి.")
      );
      say("Word documents cannot be previewed in browser", false);
      return;
    }
    const b = await fetchBlob(d, "view");
    if (!b) return;
    const url = URL.createObjectURL(b);
    $("#preview").replaceChildren(b.type.startsWith("image/")
      ? h("img", { src: url, alt: d.name }) : h("iframe", { src: url, title: d.name }));
    say("Viewing (read permission is enough)");
  };
  const download = async () => {
    const b = await fetchBlob(d, "download");
    if (!b) return;
    const url = URL.createObjectURL(b);
    const link = h("a", { href: url, download: d.name });
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    say("Download started");
  };
  const edit = async () => {
    const json = {};
    if (rename.value) json.name = rename.value;
    if (newCat.value) json.category = newCat.value;
    const r = await act(() => api(`/documents/${d.id}`, { method: "PATCH", json }), "Details updated");
    if (r) { loadDocs(); openDoc({ ...d, ...r }); }
  };
  const swap = async () => {
    if (!replace.files[0]) return say("Choose a file first", false);
    const f = new FormData(); f.append("file", replace.files[0]);
    if (await act(() => api(`/documents/${d.id}/content`, { method: "PUT", form: f }), "File replaced successfully! New version uploaded.")) {
      replace.value = "";
      loadDocs();
    }
  };
  const del = async () => {
    if (!confirm("Delete this document for everyone? This cannot be undone.")) return;
    if (await act(() => api(`/documents/${d.id}`, { method: "DELETE" }), "Deleted")) {
      current = null;
      render();
    }
  };

  const buttons = [h("button", { onclick: view }, "View")];
  if (a.can_download) buttons.push(h("button", { onclick: download }, "Download"));
  buttons.push(h("button", { class: "ai-btn", onclick: () => showAiSummaryModal(d) }, "🤖 AI Summary"));
  if (a.owner) buttons.push(h("button", { class: "ai-btn dlp", onclick: () => showAiDlpModal(d) }, "🛡️ DLP Scan"));
  if (a.can_delete) buttons.push(h("button", { class: "danger", onclick: del }, "Delete"));

  const editPanel = a.level === "edit" ? h("div", { class: "doc-section-panel" },
    h("h3", {}, "✏️ Edit Metadata & Properties"),
    h("div", { class: "doc-grid-row" },
      rename,
      newCat,
      h("button", { onclick: edit }, "Save Changes")
    ),
    h("hr", { style: "margin: 14px 0 12px; border: 0; border-top: 1px dashed var(--line);" }),
    h("h3", {}, "🔄 Replace File (Same Type)"),
    h("div", { class: "row", style: "gap: 10px;" },
      replace,
      h("button", { onclick: swap }, "Upload new version")
    )
  ) : null;

  const sharePanel = a.can_share ? h("div", { class: "doc-section-panel" },
    h("h3", {}, "👥 Manage Document Access & Sharing"),
    h("div", { id: "shares" })
  ) : null;

  const backBtn = h("button", {
    class: "ghost",
    style: "margin-bottom: 12px; display: inline-flex; align-items: center; gap: 6px;",
    onclick: () => {
      current = null;
      render();
    }
  }, "← Back to document list");

  $("#app").replaceChildren(
    h("div", { class: "stack" },
      backBtn,
      h("div", { class: "doc-detail-card" },
        h("div", { class: "doc-detail-header" },
          h("div", { class: "doc-detail-title-box" },
            h("h2", {}, d.name),
            h("div", { class: "muted", style: "font-size: 13px;" },
              `Owner: ${d.owner_email} · ${d.mime} · ${(d.size / 1024).toFixed(1)} KB`
            ),
            h("div", { class: "doc-meta-badge" }, `🔑 Your rights: ${accessText(a)}`)
          ),
          h("div", { class: "doc-action-bar" }, buttons)
        ),
        editPanel,
        sharePanel,
        h("div", { id: "preview" })
      )
    )
  );
  if (a.can_share) loadShares(d);
}

async function loadShares(d) {
  const a = d.my_access;
  const box = $("#shares");
  const email = h("input", { type: "email", placeholder: "person's email" });
  // a person who was given sharing rights can only hand out what they hold themselves
  const level = h("select", {}, h("option", { value: "read" }, "read"),
    a.level === "edit" ? h("option", { value: "edit" }, "edit") : null);
  const cs = h("input", { type: "checkbox" }), cd = h("input", { type: "checkbox" });
  const grant = async () => {
    const json = { email: email.value, level: level.value, can_share: cs.checked, can_download: cd.checked };
    if (await act(() => api(`/documents/${d.id}/shares`, { method: "POST", json }), "Access saved")) { loadShares(d); loadDocs(); }
  };
  let rows = null;                      // quiet: a 404 here just means "not yours to manage"
  try { rows = await api(`/documents/${d.id}/shares`); } catch (e) {}
  box.replaceChildren(
    rows ? (rows.length ? table(["Person", "Level", "Share", "Download", ""], rows.map((r) => [
        r.email, r.level, String(r.can_share), String(r.can_download),
        h("button", { class: "danger", onclick: async () => {
          if (await act(() => api(`/documents/${d.id}/shares/${r.user_id}`, { method: "DELETE" }), "Access removed")) { loadShares(d); loadDocs(); }
        } }, "Revoke")]))
      : h("p", { class: "muted", style: "margin: 4px 0 10px;" }, "You have not given access to anyone yet."))
      : h("p", { class: "muted" }, "You cannot manage sharing on this document."),
    h("div", { class: "doc-share-box" },
      email,
      level,
      a.owner ? h("label", { class: "chk" }, cs, "can share") : null,
      a.can_download ? h("label", { class: "chk" }, cd, "can download") : null,
      h("button", { onclick: grant }, "Grant Access")
    )
  );
}

// ---------- admin ----------
let adminSubTab = "users";

function adminView() {
  const wrap = h("div", { class: "stack" });
  const users = h("div", { class: "card" }), audit = h("div", { class: "card" });
  const changes = h("div", { class: "card" }), docs = h("div", { class: "card" });
  const access = h("div", { id: "access" });

  const activePane = h("div", { class: "admin-active-pane" });

  const subTabs = [
    ["users", "👥 Users and roles"],
    ["audit", "📜 Audit log"],
    ["changes", "🔑 Permission changes"],
    ["docs", "📄 Documents"]
  ];

  const renderAdminPane = () => {
    access.replaceChildren();
    if (adminSubTab === "users") activePane.replaceChildren(users);
    else if (adminSubTab === "audit") activePane.replaceChildren(audit);
    else if (adminSubTab === "changes") activePane.replaceChildren(changes);
    else if (adminSubTab === "docs") activePane.replaceChildren(docs, access);
  };

  const subTabsBar = h("div", { class: "row tabs admin-subtabs", style: "margin-bottom: 14px;" },
    subTabs.map(([id, label]) =>
      h("button", {
        class: id === adminSubTab ? "on" : "",
        onclick: (e) => {
          adminSubTab = id;
          subTabsBar.querySelectorAll("button").forEach(b => b.classList.remove("on"));
          e.currentTarget.classList.add("on");
          renderAdminPane();
        }
      }, label)
    )
  );

  wrap.append(subTabsBar, activePane);

  const loadMaintenance = async () => {
    try {
      const state = await api("/admin/maintenance");
      maintenanceInfo = state;
      const isEnabled = state && state.enabled;
      maintenanceCard.replaceChildren(
        h("div", { class: "row between", style: "align-items: center; margin-bottom: 8px;" },
          h("h2", { style: "margin: 0;" }, "🔧 System Maintenance Mode & Emergency Lock"),
          h("span", {
            class: "threat-badge " + (isEnabled ? "HIGH" : "LOW"),
            style: "font-size: 12px; padding: 4px 10px;"
          }, isEnabled ? "🔴 MAINTENANCE ACTIVE" : "🟢 SYSTEM OPERATIONAL")
        ),
        h("p", { class: "muted", style: "font-size: 13px; margin: 4px 0 14px;" },
          "Safely freeze document uploads, edits, and sharing while performing database upgrades or security patches. Viewing and downloading remain active."
        ),
        isEnabled ? h("div", { class: "doc-section-panel", style: "border-color: #f59e0b; background: rgba(245, 158, 11, 0.08);" },
          h("div", { style: "font-weight: 600; color: #fbbf24; margin-bottom: 6px;" }, `⚠️ Active Reason: ${state.reason || "Scheduled Maintenance"}`),
          h("div", { class: "muted", style: "font-size: 12px; margin-bottom: 12px;" },
            `Activated by ${state.enabled_by || "admin"} at ${state.enabled_at ? toIST(state.enabled_at) : "now"}`
          ),
          h("button", {
            class: "ai-btn",
            style: "background: #10b981; color: white;",
            onclick: async () => {
              if (await act(() => api("/admin/maintenance", { method: "POST", json: { enabled: false } }), "Maintenance mode deactivated!")) {
                loadMaintenance();
                checkMaintenanceStatus();
              }
            }
          }, "✅ Deactivate Maintenance & Resume Normal Operations")
        ) : h("div", { class: "doc-grid-row", style: "gap: 10px; align-items: center;" },
          (() => {
            const reasonInput = h("input", {
              placeholder: "Maintenance Reason (e.g. Scheduled Database Migration & Security Patches)",
              style: "flex: 1;"
            });
            const notifyChk = h("label", { class: "chk", style: "font-size: 12px; cursor: pointer; white-space: nowrap;" },
              h("input", { type: "checkbox", checked: true }),
              " Broadcast alerts to all users"
            );
            return [
              reasonInput,
              notifyChk,
              h("button", {
                class: "danger",
                onclick: async () => {
                  const reason = reasonInput.value.trim() || "Scheduled Server Upgrade & Security Maintenance";
                  const shouldNotify = notifyChk.querySelector("input").checked;
                  if (!confirm(`Are you sure you want to ACTIVATE Maintenance Mode?\nReason: ${reason}`)) return;
                  if (await act(() => api("/admin/maintenance", {
                    method: "POST",
                    json: { enabled: true, reason, notify_users: shouldNotify }
                  }), "Maintenance mode activated! All write actions are paused.")) {
                    loadMaintenance();
                    checkMaintenanceStatus();
                  }
                }
              }, "🔒 Activate Maintenance Mode")
            ];
          })()
        )
      );
    } catch (e) {}
  };

  const loadUsers = async () => {
    const list = await act(() => api("/admin/users"));
    if (!list) return;
    users.replaceChildren(h("h2", {}, "Users and roles"), table(["Id", "User name", "User email", "Role", ""], list.map((u) => {
      const sel = h("select", {}, ["viewer", "owner", "admin"].map((r) => h("option", { value: r, selected: r === u.role }, r)));
      return [u.id, u.name || "—", u.email, sel, h("button", { onclick: async () => {
        if (await act(() => api(`/admin/users/${u.id}/role`, { method: "PATCH", json: { role: sel.value } }), "Role changed")) loadUsers();
      } }, "Save")];
    })));
  };
  const toIST = (iso) => {
    if (!iso) return "";
    const d = new Date(iso.endsWith("Z") ? iso : iso + "Z");
    if (isNaN(d)) return iso;
    const ist = new Date(d.getTime() + 19800000); // UTC to IST (+5:30)
    return ist.toISOString().replace("T", " ").slice(0, 19);
  };
  const logTable = (list) => table(["When (IST)", "Action", "By", "Target", "Document", "Detail", "IP"],
    list.map((r) => [toIST(r.at), r.action, r.actor_email || "", r.target_email || "",
      r.document_name || "", r.detail || "", r.ip || ""]));
  const runAiThreatAnalysis = async () => {
    const box = $("#ai-threat-box");
    if (!box) return;
    box.replaceChildren(h("p", { class: "muted" }, "Running AI SOC threat analysis on recent audit trail events..."));
    try {
      const res = await api("/admin/ai-threat-analysis");
      const anomalies = (res.anomalies || []).map(a => h("li", { style: "margin-bottom: 4px;" }, a));
      const recs = (res.recommendations || []).map(r => h("li", { style: "margin-bottom: 4px;" }, r));

      box.replaceChildren(
        h("div", { class: "ai-threat-card " + (res.threat_level || "LOW") },
          h("div", { class: "row between", style: "margin-bottom: 10px;" },
            h("div", { class: "row", style: "gap: 10px; align-items: center;" },
              h("strong", { style: "font-size: 13.5px;" }, "🛡️ AI SOC Threat Posture:"),
              h("span", { class: "threat-badge " + (res.threat_level || "LOW") }, res.threat_level || "LOW")
            ),
            h("span", { class: "muted", style: "font-size: 11.5px;" }, `Engine: ${res.engine || "Gemini"}`)
          ),
          h("p", { style: "margin: 0 0 10px; font-size: 13px; line-height: 1.5;" }, res.summary),
          h("div", { style: "margin-top: 8px;" },
            h("strong", { style: "font-size: 12px; color: #f87171;" }, "Detected Anomalies:"),
            h("ul", { style: "margin: 4px 0 8px 18px; padding: 0; font-size: 12.5px;" }, anomalies)
          ),
          h("div", { style: "margin-top: 8px;" },
            h("strong", { style: "font-size: 12px; color: #38bdf8;" }, "SOC Recommendations:"),
            h("ul", { style: "margin: 4px 0 0 18px; padding: 0; font-size: 12.5px;" }, recs)
          )
        )
      );
    } catch (err) {
      box.replaceChildren(h("p", { class: "hint err" }, "Threat analysis failed: " + err.message));
    }
  };

  const showForensicVerifierModal = () => {
    let activeTab = "file"; // "file" or "text"
    const fileInput = h("input", { type: "file", style: "margin-top: 8px; width: 100%;" });
    const tokenInput = h("textarea", {
      rows: 4,
      style: "width: 100%; box-sizing: border-box; font-family: monospace; font-size: 12px; margin-top: 8px;",
      placeholder: "Paste leaked text snippet, Custody Key (e.g. TV-A1B2C3D4...), or full payload.signature here..."
    });
    const resultBox = h("div", { style: "margin-top: 12px;" });

    const renderResult = (res) => {
      const d = res.details;
      const lineageElements = (d.lineage && d.lineage.length) ? [
        h("hr", { style: "margin: 10px 0; border: 0; border-top: 1px dashed #cbd5e1;" }),
        h("h4", { style: "margin: 4px 0 8px; color: #b45309;" }, "🧬 Multi-Hop Document Lineage (Full Audit Trail):"),
        h("div", { style: "display: flex; flex-direction: column; gap: 6px;" },
          d.lineage.map(item =>
            h("div", { class: "card", style: "background: #fff; padding: 6px 10px; font-size: 12px; border-left: 3px solid #f59e0b;" },
              h("strong", {}, `Hop #${item.hop}: `),
              h("span", { style: "text-transform: capitalize;" }, item.action.replace(/_/g, " ")),
              h("span", {}, " by "),
              h("strong", {}, item.email),
              h("span", { class: "muted", style: "margin-left: 8px;" }, `[${item.timestamp.slice(0, 19).replace('T', ' ')}]`)
            )
          )
        )
      ] : [];

      resultBox.replaceChildren(
        h("div", { class: "card", style: "border-left: 4px solid var(--accent); background: #fdfbf7; margin-top: 8px;" },
          h("h3", { style: "margin: 0 0 8px 0; color: #166534;" }, "✅ PROVENANCE VERIFIED"),
          h("p", { style: "margin: 4px 0;" }, h("strong", {}, "Exfiltrated / Downloaded By: "), d.email, ` (User ID: ${d.user_id})`),
          h("p", { style: "margin: 4px 0;" }, h("strong", {}, "Document: "), d.doc_name, ` [${d.doc_id}]`),
          h("p", { style: "margin: 4px 0;" }, h("strong", {}, "Timestamp (UTC): "), d.timestamp),
          h("p", { style: "margin: 4px 0;" }, h("strong", {}, "Source IP: "), d.ip),
          d.note ? h("p", { style: "margin: 6px 0; color: #b45309; font-weight: bold; font-size: 12px;" }, d.note) : null,
          lineageElements,
          h("p", { class: "muted", style: "margin-top: 8px; font-size: 11px;" }, `Verified via: ${res.verified_by} (${res.status})`)
        )
      );
    };

    const renderError = (msg) => {
      resultBox.replaceChildren(
        h("div", { class: "card", style: "border-left: 4px solid var(--warn); background: #fff5f5; margin-top: 8px;" },
          h("h3", { style: "margin: 0 0 6px 0; color: #991b1b;" }, "❌ VERIFICATION FAILED"),
          h("p", { style: "margin: 0; font-size: 13px;" }, msg)
        )
      );
    };

    const runVerify = async () => {
      resultBox.replaceChildren(h("p", { class: "hint" }, "Scanning file forensics & verifying cryptographic custody..."));
      if (activeTab === "file") {
        const file = fileInput.files[0];
        if (!file) return renderError("Please choose a leaked file (.png, .jpg, .pdf, .txt, .docx) to trace.");
        const f = new FormData();
        f.append("file", file);
        try {
          const res = await api("/admin/verify-watermark-file", { method: "POST", form: f });
          renderResult(res);
          loadAudit(); // Automatically refresh audit log table
        } catch (err) {
          renderError(err.message);
        }
      } else {
        const val = tokenInput.value.trim();
        if (!val) return renderError("Please paste a watermark token, custody key, or text snippet.");
        try {
          const res = await api("/admin/verify-watermark", { method: "POST", json: { token: val } });
          renderResult(res);
          loadAudit(); // Automatically refresh audit log table
        } catch (err) {
          renderError(err.message);
        }
      }
    };

    const modeContainer = h("div", {}, fileInput);

    const btnFileMode = h("button", {
      class: "tabs-btn on",
      onclick: () => {
        activeTab = "file";
        btnFileMode.className = "tabs-btn on";
        btnTextMode.className = "tabs-btn";
        modeContainer.replaceChildren(
          h("p", { class: "muted", style: "font-size: 12px; margin: 4px 0;" }, "Upload the actual leaked image (.png, .jpg), PDF, or text file:"),
          fileInput
        );
      }
    }, "📁 Upload Leaked File (Images / PDF / Text)");

    const btnTextMode = h("button", {
      class: "tabs-btn",
      onclick: () => {
        activeTab = "text";
        btnTextMode.className = "tabs-btn on";
        btnFileMode.className = "tabs-btn";
        modeContainer.replaceChildren(
          h("p", { class: "muted", style: "font-size: 12px; margin: 4px 0;" }, "Paste leaked text snippet, key, or token:"),
          tokenInput
        );
      }
    }, "📝 Paste Snippet / Key");

    const modal = h("div", { class: "modal-backdrop" },
      h("div", { class: "modal-card", style: "max-width: 600px;" },
        h("div", { class: "row between", style: "align-items: center;" },
          h("h3", { style: "margin: 0;" }, "🔍 Forensic Watermark & Leaked File Decoder"),
          h("button", { class: "btn-secondary", onclick: () => modal.remove() }, "✕ Close")
        ),
        h("p", { class: "muted", style: "font-size: 13px; margin: 8px 0;" },
          "Upload any leaked document or image directly, or paste a snippet. TrustVault will extract the embedded cryptographic custody trailer and identify the exact user."
        ),
        h("div", { class: "row", style: "gap: 8px; margin: 10px 0;" }, btnFileMode, btnTextMode),
        modeContainer,
        h("div", { class: "row", style: "margin-top: 12px; justify-content: flex-end; gap: 8px;" },
          h("button", { onclick: runVerify }, "Trace Originator")
        ),
        resultBox
      )
    );
    document.body.appendChild(modal);
  };

  const loadAudit = async (action = "") => {
    const list = await act(() => api("/admin/audit?" + new URLSearchParams(action ? { action } : {})));
    if (!list) return;
    const f = h("input", { placeholder: "filter by action, e.g. access_denied", value: action });
    audit.replaceChildren(
      h("div", { class: "row between", style: "align-items: center; margin-bottom: 12px;" },
        h("h2", { style: "margin: 0;" }, "Audit log"),
        h("div", { class: "row", style: "gap: 8px;" },
          h("button", { class: "ai-btn", onclick: runAiThreatAnalysis }, "🤖 AI SOC Threat Analysis")
        )
      ),
      h("div", { id: "ai-threat-box" }),
      h("div", { class: "row" }, f, h("button", { onclick: () => loadAudit(f.value.trim()) }, "Filter")),
      logTable(list)
    );
  };
  const loadChanges = async (action = "") => {
    const list = await act(() => api("/admin/permission-changes?" + new URLSearchParams(action ? { action } : {})));
    if (!list) return;
    const f = h("input", { placeholder: "filter by action, e.g. grant, revoke, role_change", value: action });
    changes.replaceChildren(
      h("h2", {}, "Permission changes (grants, revokes, refused attempts, role changes, suspensions)"),
      h("div", { class: "row" }, f, h("button", { onclick: () => loadChanges(f.value.trim()) }, "Filter")),
      logTable(list));
  };
  const showAccess = async (d) => {
    const r = await act(() => api(`/admin/documents/${d.id}/access`));
    if (!r) return;
    access.replaceChildren(h("div", { class: "card" }, h("h2", {}, `Who can reach: ${r.name}`),
      h("p", { class: "muted" }, `Owner ${r.owner_email}. Rights only, never the content.`),
      r.access.length ? table(["Person", "Level", "Share", "Download", "Given by", "Since"], r.access.map((p) => [
        p.email, p.level, String(p.can_share), String(p.can_download), p.granted_by, p.since.slice(0, 10)]))
        : h("p", { class: "muted" }, "Nobody besides the owner.")));
  };
  const loadDocsAdmin = async () => {
    const list = await act(() => api("/admin/documents"));
    if (!list) return;
    const state = (d) => d.deleted_at ? "deleted" : d.suspended_at ? "suspended" : "active";
    docs.replaceChildren(
      h("div", { class: "row between", style: "align-items: center; margin-bottom: 12px;" },
        h("h2", { style: "margin: 0;" }, "Documents"),
        h("button", { class: "btn-secondary", onclick: showForensicVerifierModal }, "🔍 Forensic Watermark & Leaked File Decoder")
      ),
      table(["Name", "Owner", "Category", "Size", "State", ""], list.map((d) => [
        d.name, d.owner_email, d.category || "", d.size, state(d),
        d.deleted_at ? "" : h("div", { class: "row" },
          h("button", { class: "ghost", onclick: () => showAccess(d) }, "Who has access"),
          d.suspended_at
            ? h("button", { onclick: async () => {
                if (await act(() => api(`/admin/documents/${d.id}/unsuspend`, { method: "POST" }), "Document restored")) { loadDocsAdmin(); loadChanges(); }
              } }, "Restore")
            : h("button", { class: "danger", onclick: async () => {
                const reason = prompt("Why is this document being suspended? (3 to 200 characters)");
                if (!reason) return;
                if (await act(() => api(`/admin/documents/${d.id}/suspend`, { method: "POST", json: { reason } }), "Document suspended")) { loadDocsAdmin(); loadChanges(); }
              } }, "Suspend"))])));
  };
  setTimeout(() => { loadUsers(); loadAudit(); loadChanges(); loadDocsAdmin(); renderAdminPane(); });
  return wrap;
}

// ---------- maintenance modal ----------
async function openMaintenanceModal() {
  let state = { enabled: false, reason: "", scheduled_start: "", scheduled_end: "", is_scheduled: false };
  try {
    state = await api("/admin/maintenance");
  } catch (e) {}
  
  const isOnline = !(state.enabled || state.active);
  let mode = state.is_scheduled ? "scheduled" : "immediate";

  const modal = h("div", { class: "modal-backdrop" });
  
  const statusBox = h("div", {
    class: "doc-section-panel",
    style: isOnline ? "background: rgba(16, 185, 129, 0.08); border-color: rgba(16, 185, 129, 0.4);"
                    : "background: rgba(245, 158, 11, 0.12); border-color: rgba(245, 158, 11, 0.5);"
  },
    h("div", { class: "row between", style: "align-items: center;" },
      h("div", {},
        h("div", { style: "font-weight: 700; font-size: 14px; color: " + (isOnline ? "#10b981" : "#f59e0b") },
          isOnline ? "🟢 SYSTEM OPERATIONAL (NORMAL STATE)" : "🔴 MAINTENANCE ACTIVE (WRITES PAUSED)"
        ),
        h("div", { class: "muted", style: "font-size: 11.5px; margin-top: 3px;" },
          isOnline ? "All file uploads, edits, downloads, and sharing permissions are fully operational."
                   : `Active Reason: ${state.reason || "Scheduled Maintenance"}`
        )
      ),
      h("span", {
        class: "threat-badge " + (isOnline ? "LOW" : "HIGH"),
        style: "font-size: 11px; padding: 3px 8px;"
      }, isOnline ? "ONLINE" : "PAUSED")
    )
  );

  const btnSched = h("button", {
    class: "tabs-btn" + (mode === "scheduled" ? " on" : ""),
    onclick: () => setMode("scheduled")
  }, "📅 Scheduled Window (Date & Time)");

  const btnImmed = h("button", {
    class: "tabs-btn" + (mode === "immediate" ? " on" : ""),
    onclick: () => setMode("immediate")
  }, "🚨 Immediate Emergency Freeze");

  const now = new Date();
  const defStart = new Date(now.getTime() + 5 * 60000);
  const defEnd = new Date(now.getTime() + 65 * 60000);
  const toLocalISO = (d) => {
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Asia/Kolkata',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', hour12: false
    }).formatToParts(d);
    const get = (t) => (parts.find(p => p.type === t) || {}).value || '00';
    return `${get('year')}-${get('month')}-${get('day')}T${get('hour')}:${get('minute')}`;
  };

  const startInput = h("input", { type: "datetime-local", value: state.scheduled_start || toLocalISO(defStart) });
  const endInput = h("input", { type: "datetime-local", value: state.scheduled_end || toLocalISO(defEnd) });

  const schedForm = h("div", { class: "doc-section-panel", style: "display: " + (mode === "scheduled" ? "block" : "none") },
    h("div", { class: "doc-grid-row", style: "gap: 12px; margin-bottom: 8px;" },
      h("div", {}, h("label", { style: "font-size: 11.5px; color: #94a3b8; display: block; margin-bottom: 4px;" }, "Start Date & Time (IST)"), startInput),
      h("div", {}, h("label", { style: "font-size: 11.5px; color: #94a3b8; display: block; margin-bottom: 4px;" }, "End Date & Time (IST)"), endInput)
    ),
    h("div", { class: "muted", style: "font-size: 11px;" }, "Server will enter read-only mode during this window and auto-resume after expiry.")
  );

  const reasonInput = h("input", {
    placeholder: "Maintenance Reason (e.g. Scheduled Database Migration & Kernel Patching)",
    value: state.reason || "Scheduled Server Upgrade & Security Maintenance",
    style: "width: 100%; margin: 8px 0;"
  });

  const notifyChk = h("label", { class: "chk", style: "font-size: 12px; cursor: pointer; margin: 6px 0;" },
    h("input", { type: "checkbox", checked: true }),
    " Broadcast alerts to all users via in-app mailbox & Telegram"
  );

  const applyBtn = h("button", {
    class: "ai-btn",
    style: "background: #f59e0b; color: #000; font-weight: 700;",
    onclick: async () => {
      const reason = reasonInput.value.trim() || "Scheduled Server Upgrade";
      const shouldNotify = notifyChk.querySelector("input").checked;
      const isSched = mode === "scheduled";
      const start = startInput.value;
      const end = endInput.value;

      if (isSched) {
        if (!start || !end) {
          say("Please select both Start Date & Time and End Date & Time.", false);
          return;
        }
        if (new Date(start) >= new Date(end)) {
          say("End Date & Time must be after Start Date & Time.", false);
          return;
        }
        if (new Date(end) <= new Date()) {
          say("End Date & Time cannot be in the past! Please select a future time.", false);
          return;
        }
      }
      
      const payload = {
        enabled: !isSched,
        reason: reason,
        notify_users: shouldNotify,
        scheduled_start: isSched && start ? start : null,
        scheduled_end: isSched && end ? end : null
      };

      if (await act(() => api("/admin/maintenance", { method: "POST", json: payload }), "Maintenance settings updated!")) {
        modal.remove();
        checkMaintenanceStatus();
        render();
      }
    }
  }, mode === "scheduled" ? "🔒 Apply Scheduled Window" : "🚨 Lock Server Immediately");

  const resetBtn = h("button", {
    class: "reset-maint-btn",
    style: "background: #0284c7; color: #ffffff; border: none; padding: 7px 14px; border-radius: 6px; font-weight: 600; font-size: 12.5px; cursor: pointer; display: flex; align-items: center; gap: 6px;",
    onclick: async () => {
      const shouldNotify = notifyChk.querySelector("input") ? notifyChk.querySelector("input").checked : true;
      if (await act(() => api("/admin/maintenance", {
        method: "POST",
        json: { enabled: false, notify_users: shouldNotify, reason: "Manual Reset by Admin" }
      }), "System restored to normal operations!")) {
        modal.remove();
        checkMaintenanceStatus();
        render();
      }
    }
  }, "✅ Reset / Resume Normal Operations");

  function setMode(m) {
    mode = m;
    btnSched.className = "tabs-btn" + (m === "scheduled" ? " on" : "");
    btnImmed.className = "tabs-btn" + (m === "immediate" ? " on" : "");
    schedForm.style.display = m === "scheduled" ? "block" : "none";
    applyBtn.textContent = m === "scheduled" ? "🔒 Apply Scheduled Window" : "🚨 Lock Server Immediately";
  }

  const card = h("div", { class: "modal-card", style: "max-width: 580px;" },
    h("div", { class: "row between", style: "align-items: center; margin-bottom: 12px;" },
      h("h3", { style: "margin: 0;" }, "🔧 System Maintenance Window"),
      h("button", { class: "btn-secondary", onclick: () => modal.remove() }, "✕ Close")
    ),
    statusBox,
    h("div", { class: "row", style: "gap: 8px; margin: 12px 0 8px;" }, btnSched, btnImmed),
    schedForm,
    h("div", { style: "margin-top: 8px;" },
      h("label", { style: "font-size: 11.5px; color: #94a3b8; display: block; margin-bottom: 2px;" }, "Maintenance Description / Reason:"),
      reasonInput
    ),
    notifyChk,
    h("div", { class: "row between", style: "margin-top: 14px; align-items: center;" },
      resetBtn,
      h("div", { class: "row", style: "gap: 8px;" },
        h("button", { class: "ghost", onclick: () => modal.remove() }, "Cancel"),
        applyBtn
      )
    )
  );

  modal.appendChild(card);
  document.body.appendChild(modal);
}

// ---------- telegram modal ----------
let tgStatus = null;

async function openTelegramModal() {
  try {
    tgStatus = await api("/telegram/status");
  } catch (err) {
    say("Telegram status error: " + err.message, false);
    return;
  }

  function closeModal() {
    const m = $("#tg-modal");
    if (m) m.remove();
  }

  const modalBox = h("div", { class: "card tg-modal-content" },
    h("div", { class: "modal-header" },
      h("h3", {}, "✈️ Telegram Alerts"),
      h("button", { class: "ghost close-btn", onclick: closeModal }, "✕")
    )
  );

  if (tgStatus.connected) {
    modalBox.append(
      h("div", { class: "tg-status-box" },
        h("div", {}, h("strong", {}, "✅ Status: Connected & Receiving Alerts")),
        h("div", { class: "muted", style: "margin-top: 4px; font-size: 12px;" }, `Linked Chat ID: ${tgStatus.chat_id_masked || "Active"}`),
        h("div", { class: "muted", style: "font-size: 12px;" }, `Receiving alerts for role: ${me.role.toUpperCase()}`)
      ),
      h("div", { class: "row", style: "margin-top: 16px;" },
        h("button", {
          class: "danger",
          onclick: async () => {
            try {
              await api("/telegram/disconnect", { method: "POST" });
              say("Telegram disconnected");
              me.telegram_connected = false;
              closeModal();
              render();
            } catch (err) {
              say(err.message, false);
            }
          }
        }, "Disconnect Telegram")
      )
    );
  } else {
    let linkCodeData = null;
    try {
      linkCodeData = await api("/telegram/link-code");
    } catch (e) {}

    const deepLinkUrl = linkCodeData && linkCodeData.deep_link;
    const manualInput = h("input", {
      type: "text",
      placeholder: "e.g. 987654321",
      style: "width: 100%; margin: 8px 0;"
    });

    const opt1Kids = [
      h("div", {}, h("strong", {}, "Option 1: 1-Click Connect")),
      h("p", { class: "muted", style: "font-size: 12px; margin: 4px 0 10px;" }, "Opens Telegram bot. Press START in Telegram to link instantly!")
    ];
    if (deepLinkUrl) {
      opt1Kids.push(
        h("a", {
          href: deepLinkUrl,
          target: "_blank",
          class: "tg-btn-link"
        }, "🚀 Open Bot in Telegram ↗")
      );
    } else {
      opt1Kids.push(
        h("span", { class: "muted", style: "font-size: 11px;" }, "(Set TELEGRAM_BOT_USERNAME in .env for 1-click deep link)")
      );
    }

    modalBox.append(
      h("p", { class: "muted", style: "margin-top: 0; font-size: 12.5px;" },
        "Receive instant notifications for your role (document shares, downloads, role updates, and security alerts)."
      ),
      h("div", { class: "tg-option-box" }, ...opt1Kids),
      h("div", { class: "tg-divider" }, "— OR MANUALLY ENTER CHAT ID —"),
      h("div", { class: "tg-option-box" },
        h("div", {}, h("strong", {}, "Option 2: Enter Telegram Chat ID")),
        h("p", { class: "muted", style: "font-size: 12px; margin: 4px 0 8px;" },
          "Tip: Message @userinfobot in Telegram to view your numeric Chat ID."
        ),
        manualInput,
        h("button", {
          onclick: async () => {
            const val = manualInput.value.trim();
            if (!val) { say("Please enter a numeric Chat ID", false); return; }
            try {
              await api("/telegram/connect", {
                method: "POST",
                json: { chat_id: val }
              });
              say("Telegram linked! Test alert sent.");
              me.telegram_connected = true;
              closeModal();
              render();
            } catch (err) {
              say(err.message, false);
            }
          }
        }, "🔗 Save & Verify Alert")
      )
    );
  }

  const backdrop = h("div", {
    id: "tg-modal",
    class: "modal-backdrop",
    onclick: (e) => { if (e.target === backdrop) closeModal(); }
  }, modalBox);

  const existing = $("#tg-modal");
  if (existing) existing.remove();
  document.body.append(backdrop);
}

// ---------- docshare in-app mailbox modal ----------
let unreadMailCount = 0;

async function checkMailCount() {
  if (!me) return;
  try {
    const res = await api("/mailbox/unread-count");
    unreadMailCount = res.unread || 0;
    const badge = $("#inbox-btn-badge");
    if (badge) {
      badge.textContent = unreadMailCount > 0 ? ` (${unreadMailCount})` : "";
      if (badge.parentElement) {
        badge.parentElement.className = "inbox-btn" + (unreadMailCount > 0 ? " has-unread" : "");
      }
    }
  } catch (e) {}
}

async function openMailboxModal() {
  function closeMailbox() {
    const m = $("#mailbox-modal");
    if (m) m.remove();
    checkMailCount();
  }

  let messages = [];
  try {
    messages = await api("/mailbox/messages");
  } catch (err) {
    say("Failed to load inbox: " + err.message, false);
    return;
  }

  const listContainer = h("div", { class: "mailbox-list" });

  function renderList(msgs) {
    listContainer.replaceChildren();
    if (!msgs || msgs.length === 0) {
      listContainer.append(
        h("div", { class: "muted", style: "text-align: center; padding: 30px 10px;" },
          "📭 Your DocShare Mailbox is empty.\nNotifications for document shares, downloads, and security events will arrive here."
        )
      );
      return;
    }
    for (const m of msgs) {
      const card = h("div", { class: "mail-card" + (!m.is_read ? " unread" : "") },
        h("div", { class: "mail-card-header" },
          h("div", { class: "mail-subject" }, (!m.is_read ? "● " : "") + m.subject),
          h("div", { class: "mail-time" }, (() => {
          if (!m.created_at) return "";
          const iso = (m.created_at.endsWith("Z") || m.created_at.includes("+"))
            ? m.created_at
            : m.created_at.replace(" ", "T") + "Z";
          const d = new Date(iso);
          if (isNaN(d)) return m.created_at;
          return d.toLocaleTimeString('en-IN', {
            timeZone: 'Asia/Kolkata',
            hour: '2-digit',
            minute: '2-digit',
            hour12: true
          }) + " IST";
        })())
        ),
        h("div", { class: "mail-from" }, `From: ${m.from}`),
        h("div", { class: "mail-body-text" }, m.body)
      );
      listContainer.append(card);
    }
  }

  renderList(messages);

  const actionsBar = h("div", { class: "row between", style: "margin-top: 14px; gap: 8px;" },
    h("div", { class: "row", style: "gap: 8px;" },
      h("button", {
        class: "ghost",
        onclick: async () => {
          try {
            await api("/mailbox/read-all", { method: "POST" });
            messages.forEach(m => m.is_read = true);
            renderList(messages);
            checkMailCount();
          } catch (e) {}
        }
      }, "Mark all read"),
      h("button", {
        class: "ghost danger",
        onclick: async () => {
          try {
            await api("/mailbox/clear", { method: "POST" });
            messages = [];
            renderList(messages);
            checkMailCount();
          } catch (e) {}
        }
      }, "Clear mailbox")
    ),
    h("button", { onclick: closeMailbox }, "Close")
  );

  const modalBox = h("div", { class: "mailbox-modal-content" },
    h("div", { class: "modal-header" },
      h("h3", {}, "📬 DocShare Mailbox"),
      h("button", { class: "ghost close-btn", onclick: closeMailbox }, "✕")
    ),
    h("div", { class: "muted", style: "font-size: 12px; margin-bottom: 6px;" },
      `In-app email client for ${me.email}`
    ),
    listContainer,
    actionsBar
  );

  const backdrop = h("div", {
    id: "mailbox-modal",
    class: "modal-backdrop",
    onclick: (e) => { if (e.target === backdrop) closeMailbox(); }
  }, modalBox);

  const existing = $("#mailbox-modal");
  if (existing) existing.remove();
  document.body.append(backdrop);
}

// ---------- shell ----------
function render() {
  const who = $("#who"), app = $("#app");
  who.replaceChildren();
  if (!me) { app.replaceChildren(authView()); return; }
  
  // If the display name already contains the role (e.g. "Document Owner", "Admin", "Viewer"),
  // avoid repeating "[owner]" to prevent redundant text on screen.
  let userLabel = "";
  if (me.name) {
    const hasRole = me.name.toLowerCase().includes(me.role.toLowerCase());
    userLabel = hasRole ? `${me.name} (${me.email}) ` : `${me.name} (${me.email}) [${me.role}] `;
  } else {
    userLabel = `${me.email} (${me.role}) `;
  }

  const inboxBtn = h("button", {
    class: "inbox-btn" + (unreadMailCount > 0 ? " has-unread" : ""),
    onclick: openMailboxModal
  }, "📬 Inbox", h("span", { id: "inbox-btn-badge" }, unreadMailCount > 0 ? ` (${unreadMailCount})` : ""));

  const tgBtn = h("button", {
    class: "tg-pill" + (me.telegram_connected ? " active" : ""),
    onclick: openTelegramModal
  }, me.telegram_connected ? "✈️ Alerts Active ✅" : "✈️ Connect Telegram");

  const maintBtn = me.role === "admin" ? h("button", {
    class: "maint-pill-btn",
    onclick: openMaintenanceModal
  }, "🔧 System Maintenance", h("span", {
    class: "maint-status-dot " + (maintenanceInfo && (maintenanceInfo.active || maintenanceInfo.enabled) ? "active" : "normal")
  })) : null;

  const userBox = h("div", { class: "user-profile-badge" },
    h("span", { class: "user-email-line" }, me.email),
    h("span", { class: "user-role-line" }, `(${me.role})`)
  );

  who.append(
    ...(maintBtn ? [maintBtn] : []),
    inboxBtn,
    tgBtn,
    userBox,
    h("button", { class: "ghost", onclick: logout }, "Log out")
  );
  setTimeout(checkMailCount, 100);
  const tabs = me.role === "admin" ? [["admin", "Admin"]]
    : me.role === "owner" ? [["mine", "My documents"], ["shared", "Shared with me"]]
    : [["shared", "Shared with me"]];
  if (!tabs.some(([id]) => id === tab)) tab = tabs[0][0];
  const bar = h("div", { class: "row tabs" }, tabs.map(([id, label]) =>
    h("button", { class: id === tab ? "on" : "", onclick: () => { tab = id; current = null; render(); } }, label)));
  app.replaceChildren(bar, tab === "admin" ? adminView() : docsView());
}

render();

let maintenanceInfo = { enabled: false, reason: "" };

async function checkMaintenanceStatus() {
  try {
    const res = await fetch("/maintenance/status");
    if (res.ok) {
      maintenanceInfo = await res.json();
      const existing = $("#maintenance-banner");
      if (maintenanceInfo.enabled) {
        if (!existing) {
          const banner = h("div", {
            id: "maintenance-banner",
            class: "maintenance-banner",
          }, `⚠️ SYSTEM MAINTENANCE IN PROGRESS: ${maintenanceInfo.reason || "All file uploads & modifications are temporarily paused."}`);
          const hdr = $("header");
          if (hdr) hdr.after(banner);
        } else {
          existing.textContent = `⚠️ SYSTEM MAINTENANCE IN PROGRESS: ${maintenanceInfo.reason || "All file uploads & modifications are temporarily paused."}`;
        }
      } else if (existing) {
        existing.remove();
      }
    }
  } catch (e) {}
}

setInterval(checkMaintenanceStatus, 8000);
checkMaintenanceStatus();
