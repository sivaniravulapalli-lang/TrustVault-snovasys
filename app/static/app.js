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

function passwordBox(autocomplete) {
  const pw = h("input", { type: "password", placeholder: "password (10+ characters)", autocomplete });
  const toggle = h("button", {
    type: "button", class: "eye", title: "Show/Hide password",
    onclick: (e) => {
      e.preventDefault();
      const show = pw.type === "password";
      pw.type = show ? "text" : "password";
      toggle.textContent = show ? "🙈" : "👁️";
    }
  }, "👁️");
  return { pw, box: h("div", { class: "pwbox" }, pw, toggle) };
}

function authView(prefillEmail = "") {
  const switcher = h("div", { class: "row tabs" },
    h("button", { class: authMode === "login" ? "on" : "", onclick: () => { authMode = "login"; say(""); render(); } }, "Login"),
    h("button", { class: authMode === "register" ? "on" : "", onclick: () => { authMode = "register"; say(""); render(); } }, "Register"));

  if (authMode === "register") {
    const name = h("input", { placeholder: "full name", autocomplete: "name" });
    const email = h("input", { type: "email", placeholder: "email", autocomplete: "username" });
    const { pw, box } = passwordBox("new-password");
    const register = async () => {
      if (!name.value.trim()) return say("Please enter your name", false);
      const r = await act(() => api("/auth/register", { method: "POST",
        json: { name: name.value.trim(), email: email.value, password: pw.value } }));
      if (!r) return;
      authMode = "login";                      // go straight to the login form
      $("#app").replaceChildren(authView(email.value));
      say("You are registered successfully! Please log in.");
    };
    return h("div", { class: "card auth" }, switcher, h("h2", {}, "Create an account"),
      h("div", { class: "stack" }, name, email, box, h("button", { onclick: register }, "Register")));
  }

  const email = h("input", { type: "email", placeholder: "email", autocomplete: "username", value: prefillEmail });
  const { pw, box } = passwordBox("current-password");
  const login = async () => {
    let t;
    try {
      t = await api("/auth/login", { method: "POST", json: { email: email.value, password: pw.value } });
    } catch (e) { return say(e.message.replace(/^\d+ /, ""), false); }   // server gives reason + attempts left
    token = t.access_token;
    me = await act(() => api("/auth/me"));
    tab = null;
    say("Logged in");
    render();
  };
  return h("div", { class: "card auth" }, switcher, h("h2", {}, "Log in"),
    h("div", { class: "stack" }, email, box, h("button", { onclick: login }, "Login")));
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
    if (await act(() => api(`/documents/${d.id}/content`, { method: "PUT", form: f }), "File replaced")) loadDocs();
  };
  const del = async () => {
    if (!confirm("Delete this document for everyone? This cannot be undone.")) return;
    if (await act(() => api(`/documents/${d.id}`, { method: "DELETE" }), "Deleted")) {
      current = null; $("#detail").replaceChildren(); loadDocs();
    }
  };

  const buttons = [h("button", { onclick: view }, "View")];
  if (a.can_download) buttons.push(h("button", { onclick: download }, "Download"));
  if (a.can_delete) buttons.push(h("button", { class: "danger", onclick: del }, "Delete"));

  $("#detail").replaceChildren(h("div", { class: "card" },
    h("h2", {}, d.name),
    h("p", { class: "muted" }, `Owner ${d.owner_email} · ${d.mime} · ${d.size} bytes`),
    h("p", {}, `Your rights: ${accessText(a)}`),
    h("div", { class: "row" }, buttons),
    a.level === "edit" ? [
      h("h3", {}, "Edit details"), h("div", { class: "row" }, rename, newCat, h("button", { onclick: edit }, "Save")),
      h("h3", {}, "Replace file (same type)"), h("div", { class: "row" }, replace, h("button", { onclick: swap }, "Upload new version")),
    ] : null,
    h("div", { id: "preview" }),
    a.can_share ? [h("h3", {}, "Sharing"), h("div", { id: "shares" })] : null));
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
      : h("p", { class: "muted" }, "You have not given access to anyone yet."))
      : h("p", { class: "muted" }, "You cannot manage sharing on this document."),
    h("div", { class: "row" }, email, level,
      a.owner ? h("label", { class: "chk" }, cs, "can share") : null,
      a.can_download ? h("label", { class: "chk" }, cd, "can download") : null,
      h("button", { onclick: grant }, "Give access")));
}

// ---------- admin ----------
function adminView() {
  const wrap = h("div", { class: "stack" });
  const users = h("div", { class: "card" }), audit = h("div", { class: "card" });
  const changes = h("div", { class: "card" }), docs = h("div", { class: "card" });
  const access = h("div", { id: "access" });
  wrap.append(users, audit, changes, docs, access);

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
  const loadAudit = async (action = "") => {
    const list = await act(() => api("/admin/audit?" + new URLSearchParams(action ? { action } : {})));
    if (!list) return;
    const f = h("input", { placeholder: "filter by action, e.g. access_denied", value: action });
    audit.replaceChildren(h("h2", {}, "Audit log"),
      h("div", { class: "row" }, f, h("button", { onclick: () => loadAudit(f.value.trim()) }, "Filter")), logTable(list));
  };
  const loadChanges = async () => {
    const list = await act(() => api("/admin/permission-changes"));
    if (list) changes.replaceChildren(h("h2", {}, "Permission changes (grants, revokes, refused attempts, role changes, suspensions)"), logTable(list));
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
    docs.replaceChildren(h("h2", {}, "All documents (metadata only)"),
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
  setTimeout(() => { loadUsers(); loadAudit(); loadChanges(); loadDocsAdmin(); });
  return wrap;
}

// ---------- shell ----------
function render() {
  const who = $("#who"), app = $("#app");
  who.replaceChildren();
  if (!me) { app.replaceChildren(authView()); return; }
  who.append(`${me.email} (${me.role}) `, h("button", { class: "ghost", onclick: logout }, "Log out"));
  const tabs = me.role === "admin" ? [["admin", "Admin"]]
    : me.role === "owner" ? [["mine", "My documents"], ["shared", "Shared with me"]]
    : [["shared", "Shared with me"]];
  if (!tabs.some(([id]) => id === tab)) tab = tabs[0][0];
  const bar = h("div", { class: "row tabs" }, tabs.map(([id, label]) =>
    h("button", { class: id === tab ? "on" : "", onclick: () => { tab = id; current = null; render(); } }, label)));
  app.replaceChildren(bar, tab === "admin" ? adminView() : docsView());
}

render();
