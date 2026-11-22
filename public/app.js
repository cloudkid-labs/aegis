const KEY_STORAGE = "aegisKey";
function getKey() { return localStorage.getItem(KEY_STORAGE) || ""; }
function authHeaders() { return { authorization: `Bearer ${getKey()}`, "content-type": "application/json" }; }

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { ...authHeaders(), ...(opts.headers || {}) } });
  if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
  return res.status === 204 ? null : res.json();
}

function el(tag, text, attrs = {}) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  return node;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

async function loadScans() {
  const tbody = document.querySelector("#scans-table tbody");
  clear(tbody);
  const phaseFilter = document.querySelector("#filter-phase").value;
  const statusFilter = document.querySelector("#filter-status").value;
  try {
    const { scans } = await api("/api/scans");
    const filtered = scans.filter((s) => (!phaseFilter || s.phase === phaseFilter) && (!statusFilter || s.status === statusFilter));
    for (const s of filtered) {
      const tr = el("tr");
      const statusTd = el("td", s.status);
      statusTd.className = `status-${s.status}`;
      tr.append(el("td", s.id.slice(0, 8)), el("td", s.target), el("td", s.phase), statusTd, el("td", s.assetCount ?? "—"), el("td", s.createdAt.slice(0, 16).replace("T", " ")));
      const actions = el("td");
      const view = el("button", "View");
      view.addEventListener("click", () => showDetail(s.id));
      actions.append(view);
      if (s.status === "queued" || s.status === "running") {
        const cancel = el("button", "Cancel");
        cancel.addEventListener("click", async () => { await api(`/api/scans/${s.id}/cancel`, { method: "POST" }); loadScans(); });
        actions.append(cancel);
      }
      tr.append(actions);
      tbody.append(tr);
    }
    if (filtered.length === 0) tbody.append(el("tr")).append(el("td", "No scans yet.", { colspan: "7" }));
  } catch (err) {
    tbody.append(el("tr")).append(el("td", String(err.message), { colspan: "7" }));
  }
}

async function showDetail(id) {
  document.querySelector("#list-section").hidden = true;
  document.querySelector("#create-section").hidden = true;
  const detail = document.querySelector("#detail-section");
  detail.hidden = false;
  document.querySelector("#detail-title").textContent = `Scan ${id.slice(0, 8)}`;
  const { scan, events } = await api(`/api/scans/${id}`);
  const meta = document.querySelector("#detail-meta");
  clear(meta);
  meta.append(el("p", `${scan.target} | ${scan.phase} | ${scan.status} | ${scan.createdAt}`));
  for (const ev of events || []) meta.append(el("p", `${ev.createdAt} — ${ev.event}${ev.detail ? ": " + ev.detail : ""}`));
  const { assets } = await api(`/api/scans/${id}/assets`);
  const tbody = document.querySelector("#assets-table tbody");
  clear(tbody);
  for (const a of assets) {
    const tr = el("tr");
    let metaStr = "";
    if (a.metadata) { try { const m = JSON.parse(a.metadata); metaStr = Object.entries(m).filter(([, v]) => v != null).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`).join(" | "); } catch {} }
    tr.append(el("td", a.type), el("td", a.value), el("td", metaStr));
    tbody.append(tr);
  }
  if (assets.length === 0) tbody.append(el("tr")).append(el("td", "No assets discovered.", { colspan: "3" }));
}

document.querySelector("#key-form").addEventListener("submit", (e) => {
  e.preventDefault();
  localStorage.setItem(KEY_STORAGE, document.querySelector("#api-key").value.trim());
  loadScans();
});

document.querySelector("#create-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = document.querySelector("#create-status");
  status.textContent = "Starting…";
  const tools = [...document.querySelectorAll('input[name="tool"]:checked')].map((c) => c.value);
  try {
    const body = { target: document.querySelector("#target").value, phase: "explore", options: { depth: Number(document.querySelector("#depth").value), tools } };
    const { id } = await api("/api/scans", { method: "POST", body: JSON.stringify(body) });
    status.textContent = `Started ${id.slice(0, 8)}`;
    loadScans();
  } catch (err) { status.textContent = `Error: ${err.message}`; }
});

document.querySelector("#back-btn").addEventListener("click", () => {
  document.querySelector("#detail-section").hidden = true;
  document.querySelector("#list-section").hidden = false;
  document.querySelector("#create-section").hidden = false;
  loadScans();
});

document.querySelector("#filter-phase").addEventListener("change", loadScans);
document.querySelector("#filter-status").addEventListener("change", loadScans);
document.querySelector("#api-key").value = getKey();
loadScans();
setInterval(() => { if (!document.querySelector("#list-section").hidden) loadScans(); }, 5000);