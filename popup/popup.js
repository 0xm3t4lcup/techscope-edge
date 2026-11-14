/* popup.js — tabs (Technologies / Security / History), filter, rescan,
 * copy-to-clipboard, and JSON export. */
const $ = (id) => document.getElementById(id);
let current = { url: "", results: [], security: null };

const palette = [
  "#4254f5", "#2e9e6b", "#c77800", "#c0392b", "#8e44ad",
  "#1f9bb3", "#d6336c", "#5c7cfa", "#637a2a", "#a6611a",
];
const colorFor = (s) => palette[[...s].reduce((a, c) => a + c.charCodeAt(0), 0) % palette.length];
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// ---- tabs ------------------------------------------------------------------
document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $("panel-" + t.dataset.tab).classList.add("active");
    if (t.dataset.tab === "history") loadHistory();
  });
});

// ---- technologies ----------------------------------------------------------
function renderTech(filter = "") {
  const box = $("results");
  const f = filter.trim().toLowerCase();
  let items = current.results;
  if (f) items = items.filter((r) =>
    r.name.toLowerCase().includes(f) || r.categories.some((c) => c.name.toLowerCase().includes(f)));

  if (!items.length) {
    box.innerHTML = `<div class="empty">${current.results.length ? "No match." : "No technologies detected."}</div>`;
    return;
  }
  const groups = new Map();
  for (const r of items) {
    const cat = r.categories.slice().sort((a, b) => b.priority - a.priority)[0] || { name: "Other" };
    if (!groups.has(cat.name)) groups.set(cat.name, []);
    groups.get(cat.name).push(r);
  }
  let html = "";
  for (const [catName, techs] of groups) {
    html += `<div class="cat-head">${esc(catName)}</div>`;
    for (const t of techs) {
      const ver = t.version ? `<span class="ver">${esc(t.version)}</span>` : "";
      const conf = t.confidence < 100 ? `<span class="conf">${t.confidence}%</span>` : "";
      const tag = t.website ? "a" : "div";
      const href = t.website ? ` href="${esc(t.website)}" target="_blank" rel="noopener"` : "";
      html += `<${tag} class="tech"${href}><span class="dot" style="background:${colorFor(t.name)}"></span><span class="name">${esc(t.name)}</span>${ver}${conf}</${tag}>`;
    }
  }
  box.innerHTML = html;
}

// ---- security --------------------------------------------------------------
function renderSecurity() {
  const box = $("security");
  const s = current.security;
  if (!s) { box.innerHTML = `<div class="empty">No header data (reload the page).</div>`; return; }
  let html = `<div class="grade">
    <div class="letter g-${s.grade}">${s.grade}</div>
    <div class="meta">${s.score} of ${s.total} security headers present</div>
  </div>`;
  for (const c of s.checks) {
    html += `<div class="sec-row">
      <span class="mark ${c.present ? "ok" : "no"}">${c.present ? "✓" : "✗"}</span>
      <div><div class="lbl">${esc(c.label)}</div>${c.present && c.value ? `<div class="val">${esc(c.value.slice(0, 140))}</div>` : ""}</div>
    </div>`;
  }
  box.innerHTML = html;
}

// ---- history ---------------------------------------------------------------
async function loadHistory() {
  const box = $("history");
  const resp = await chrome.runtime.sendMessage({ type: "history" }).catch(() => null);
  const hist = (resp && resp.history) || {};
  const rows = Object.entries(hist).sort((a, b) => b[1].ts - a[1].ts);
  if (!rows.length) { box.innerHTML = `<div class="empty">No history yet.</div>`; return; }
  box.innerHTML = rows.map(([host, h]) =>
    `<div class="hist-row" data-names="${esc((h.names || []).join(", "))}">
      <span class="dot" style="background:${colorFor(host)}"></span>
      <span class="h-host">${esc(host)}</span>
      <span class="h-count">${h.count}</span>
    </div>`).join("");
  box.querySelectorAll(".hist-row").forEach((el) => {
    el.addEventListener("click", () => {
      const names = el.dataset.names;
      el.querySelector(".h-host").textContent = names ? names : "(none detected)";
    });
  });
}
$("clearHistBtn").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "clearHistory" }).catch(() => {});
  loadHistory();
});

// ---- load / actions --------------------------------------------------------
async function load(force = false) {
  $("results").innerHTML = `<div class="empty">Scanning…</div>`;
  const resp = await chrome.runtime.sendMessage({ type: "analyze", force }).catch(() => null);
  current = resp || { url: "", results: [], security: null };
  try { $("host").textContent = new URL(current.url).hostname.replace(/^www\./, ""); } catch { $("host").textContent = "—"; }
  $("count").textContent = current.results.length;
  renderTech($("search").value);
  renderSecurity();
}

$("search").addEventListener("input", (e) => renderTech(e.target.value));
$("rescanBtn").addEventListener("click", () => load(true));

$("copyBtn").addEventListener("click", async () => {
  const host = (() => { try { return new URL(current.url).hostname; } catch { return "page"; } })();
  const lines = [`# Tech stack — ${host}`];
  for (const r of current.results) lines.push(`- ${r.name}${r.version ? " " + r.version : ""} (${r.categories.map((c) => c.name).join(", ")})`);
  if (current.security) lines.push(`\nSecurity headers: ${current.security.grade} (${current.security.score}/${current.security.total})`);
  try { await navigator.clipboard.writeText(lines.join("\n")); flash($("copyBtn")); } catch {}
});

$("exportBtn").addEventListener("click", () => {
  const data = JSON.stringify({ url: current.url, detected: current.results, security: current.security, exported: new Date().toISOString() }, null, 2);
  const url = URL.createObjectURL(new Blob([data], { type: "application/json" }));
  const host = (() => { try { return new URL(current.url).hostname; } catch { return "page"; } })();
  const a = document.createElement("a");
  a.href = url; a.download = `techscope-${host}.json`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

function flash(btn) { const t = btn.textContent; btn.textContent = "✓"; setTimeout(() => (btn.textContent = t), 900); }

chrome.runtime.sendMessage({ type: "meta" }).then((r) => {
  if (r?.meta) $("dbinfo").textContent = `${r.meta.techCount} techs`;
}).catch(() => {});

load();
