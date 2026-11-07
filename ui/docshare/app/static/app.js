"use strict";
// Test UI for DocShare. The token lives only in this variable (lost on refresh).
// All user data is inserted with textContent/createTextNode, never innerHTML.
let token = null, me = null, tab = "docs", current = null;

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

function say(text, ok = true) {
  const m = $("#msg");
  m.textContent = text;
  m.className = ok ? "ok" : "err";
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

function logout() { token = me = current = null; render(); }

function table(cols, rows) {
  return h("div", { class: "scroll" }, h("table", {},
    h("tr", {}, cols.map((c) => h("th", {}, c))),
    rows.map((r) => h("tr", {}, r.map((v) => h("td", {}, v))))));
}

// ---------- login / register ----------
function authView() {
  const email = h("input", { type: "email", placeholder: "email", autocomplete: "username" });
  const pw = h("input", { type: "password", placeholder: "password (10+ characters)", autocomplete: "current-password" });
  const login = async () => {
    const t = await act(() => api("/auth/login", { method: "POST", json: { email: email.value, password: pw.value } }));
    if (!t) return;
    token = t.access_token;
    me = await act(() => api("/auth/me"));
    tab = me && me.role === "admin" ? "admin" : "docs";
    say("Logged in");
    render();
  };
  const register = () => act(() => api("/auth/register", { method: "POST", json: { email: email.value, password: pw.value } }),
    "Registered as viewer. An admin must promote you to owner to upload.");
  return h("div", { class: "card" }, h("h2", {}, "Log in or register"),
    h("div", { class: "row" }, email, pw, h("button", { onclick: login }, "Log in"),
      h("button", { class: "ghost", onclick: register }, "Register")));
}

// ---------- documents ----------
function uploadForm() {
  const file = h("input", { type: "file" });
  const cat = h("input", { placeholder: "category (optional)" });
  const go = async () => {
    if (!file.files[0]) return say("Choose a file first", false);
    const f = new FormData();
    f.append("file", file.files[0]);
    if (cat.value) f.append("category", cat.value);
    if (await act(() => api("/documents", { method: "POST", form: f }), "Uploaded")) loadDocs();
  };
  return h("div", { class: "card" }, h("h2", {}, "Upload (owners only)"),
    h("div", { class: "row" }, file, cat, h("button", { onclick: go }, "Upload")));
}

function searchForm() {
  const f = {
    q: h("input", { placeholder: "name contains" }),
    owner: h("input", { placeholder: "owner email" }),
    category: h("input", { placeholder: "category" }),
    date_from: h("input", { type: "date", title: "from" }),
    date_to: h("input", { type: "date", title: "to" }),
  };
  const go = () => loadDocs(Object.fromEntries(Object.entries(f).filter(([, el]) => el.value).map(([k, el]) => [k, el.value])));
  return h("div", { class: "row" }, Object.values(f), h("button", { onclick: go }, "Search"));
}

async function loadDocs(params = {}) {
  const docs = await act(() => api("/documents?" + new URLSearchParams(params)));
  if (!docs) return;
  const box = $("#doclist");
  box.replaceChildren(docs.length
    ? table(["Name", "Category", "Owner id", "Size", "Created", ""], docs.map((d) => [
        d.name, d.category || "", d.owner_id, d.size, d.created_at.slice(0, 10),
        h("button", { class: "ghost", onclick: () => openDoc(d) }, "Open")]))
    : h("p", { class: "muted" }, "No documents visible to you."));
}

function docsView() {
  const wrap = h("div", { class: "stack" });
  if (me.role === "owner") wrap.append(uploadForm());
  wrap.append(h("div", { class: "card" }, h("h2", {}, "Documents"), searchForm(), h("div", { id: "doclist" })));
  wrap.append(h("div", { id: "detail" }));
  setTimeout(() => { loadDocs(); if (current) openDoc(current); });
  return wrap;
}

async function fetchBlob(d, kind) { return act(() => api(`/documents/${d.id}/${kind}`, { blob: true })); }

async function openDoc(d) {
  current = d;
  const rename = h("input", { placeholder: "new name" });
  const newCat = h("input", { placeholder: "new category" });
  const replace = h("input", { type: "file" });

  const view = async () => {
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
    const a = h("a", { href: url, download: d.name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    say("Download started");
  };
  const edit = async () => {
    const json = {};
    if (rename.value) json.name = rename.value;
    if (newCat.value) json.category = newCat.value;
    const r = await act(() => api(`/documents/${d.id}`, { method: "PATCH", json }), "Details updated");
    if (r) { current = r; loadDocs(); openDoc(r); }
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

  $("#detail").replaceChildren(h("div", { class: "card" },
    h("h2", {}, d.name), h("p", { class: "muted" }, `id ${d.id} · ${d.mime} · ${d.size} bytes`),
    h("p", { class: "muted" }, "All buttons are always shown: the server decides what you may do (404 = not allowed)."),
    h("div", { class: "row" },
      h("button", { onclick: view }, "View"), h("button", { onclick: download }, "Download"),
      h("button", { class: "danger", onclick: del }, "Delete")),
    h("h3", {}, "Edit details"), h("div", { class: "row" }, rename, newCat, h("button", { onclick: edit }, "Save")),
    h("h3", {}, "Replace file"), h("div", { class: "row" }, replace, h("button", { onclick: swap }, "Upload new version")),
    h("div", { id: "preview" }),
    h("h3", {}, "Sharing"), h("div", { id: "shares" })));
  loadShares(d);
}

async function loadShares(d) {
  const box = $("#shares");
  const email = h("input", { type: "email", placeholder: "person's email" });
  const level = h("select", {}, h("option", { value: "read" }, "read"), h("option", { value: "edit" }, "edit"));
  const cs = h("input", { type: "checkbox" }), cd = h("input", { type: "checkbox" });
  const grant = async () => {
    const json = { email: email.value, level: level.value, can_share: cs.checked, can_download: cd.checked };
    if (await act(() => api(`/documents/${d.id}/shares`, { method: "POST", json }), "Access saved")) loadShares(d);
  };
  let rows = null;                      // quiet: a 404 here just means "not yours to manage"
  try { rows = await api(`/documents/${d.id}/shares`); } catch (e) {}
  box.replaceChildren(
    rows ? (rows.length ? table(["Person", "Level", "Share", "Download", ""], rows.map((r) => [
        r.email, r.level, String(r.can_share), String(r.can_download),
        h("button", { class: "danger", onclick: async () => {
          if (await act(() => api(`/documents/${d.id}/shares/${r.user_id}`, { method: "DELETE" }), "Access removed")) loadShares(d);
        } }, "Revoke")]))
      : h("p", { class: "muted" }, "Not shared with anyone you granted."))
      : h("p", { class: "muted" }, "You cannot manage sharing on this document."),
    h("div", { class: "row" }, email, level,
      h("label", { class: "chk" }, cs, "can share"), h("label", { class: "chk" }, cd, "can download"),
      h("button", { onclick: grant }, "Give access")));
}

// ---------- admin ----------
function adminView() {
  const wrap = h("div", { class: "stack" });
  const users = h("div", { class: "card" }), audit = h("div", { class: "card" });
  const changes = h("div", { class: "card" }), docs = h("div", { class: "card" });
  wrap.append(users, audit, changes, docs);

  const loadUsers = async () => {
    const list = await act(() => api("/admin/users"));
    if (!list) return;
    users.replaceChildren(h("h2", {}, "Users and roles"), table(["Id", "Email", "Role", ""], list.map((u) => {
      const sel = h("select", {}, ["viewer", "owner", "admin"].map((r) => h("option", { value: r, selected: r === u.role }, r)));
      return [u.id, u.email, sel, h("button", { onclick: async () => {
        if (await act(() => api(`/admin/users/${u.id}/role`, { method: "PATCH", json: { role: sel.value } }), "Role changed")) loadUsers();
      } }, "Save")];
    })));
  };
  const logTable = (list) => table(["When (UTC)", "Action", "By", "Target", "Document", "Detail", "IP"],
    list.map((r) => [r.at.replace("T", " ").slice(0, 19), r.action, r.actor_email || "", r.target_email || "",
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
    if (list) changes.replaceChildren(h("h2", {}, "Permission changes"), logTable(list));
  };
  const loadDocsAdmin = async () => {
    const list = await act(() => api("/admin/documents"));
    if (list) docs.replaceChildren(h("h2", {}, "All documents (metadata only)"),
      table(["Name", "Owner id", "Category", "Size", "Deleted"], list.map((d) => [
        d.name, d.owner_id, d.category || "", d.size, d.deleted_at ? "yes" : ""])));
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
  const tabs = [["docs", "Documents"]];
  if (me.role === "admin") tabs.push(["admin", "Admin"]);
  const bar = h("div", { class: "row tabs" }, tabs.map(([id, label]) =>
    h("button", { class: id === tab ? "on" : "", onclick: () => { tab = id; render(); } }, label)));
  app.replaceChildren(bar, tab === "admin" ? adminView() : docsView());
}

render();
