/* popup.js — compact quick view (Technologies / Security / History) with a
 * button to pop out the full side panel (Shodan, VirusTotal, Settings). */
import { renderTech, renderSecurity, copyText, colorFor, esc, hostOf } from "../ui.js";

const $ = (id) => document.getElementById(id);
let current = { url: "", results: [], security: null };
const send = (m) => chrome.runtime.sendMessage(m).catch(() => null);

document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel-view").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $("panel-" + t.dataset.tab).classList.add("active");
    if (t.dataset.tab === "history") loadHistory();
  });
});

async function load(force = false) {
  $("results").innerHTML = `<div class="empty">Scanning…</div>`;
  current = (await send({ type: "analyze", force })) || { url: "", results: [], security: null };
  $("host").textContent = hostOf(current.url) || "—";
  $("count").textContent = current.results.length;
  renderTech($("results"), current.results, $("search").value);
  renderSecurity($("security"), current.security);
}

async function loadHistory() {
  const resp = await send({ type: "history" });
  const hist = (resp && resp.history) || {};
  const rows = Object.entries(hist).sort((a, b) => b[1].ts - a[1].ts);
  const box = $("history");
  if (!rows.length) { box.innerHTML = `<div class="empty">No history yet.</div>`; return; }
  box.innerHTML = rows.map(([host, h]) =>
    `<div class="hist-row" data-names="${esc((h.names || []).join(", "))}">
      <span class="dot" style="background:${colorFor(host)}"></span>
      <span class="h-host">${esc(host)}</span><span class="h-count">${h.count}</span></div>`).join("");
  box.querySelectorAll(".hist-row").forEach((el) => el.addEventListener("click", () => {
    el.querySelector(".h-host").textContent = el.dataset.names || "(none detected)";
  }));
}

$("search").addEventListener("input", (e) => renderTech($("results"), current.results, e.target.value));
$("rescanBtn").addEventListener("click", () => load(true));
$("clearHistBtn").addEventListener("click", async () => { await send({ type: "clearHistory" }); loadHistory(); });
$("copyBtn").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(copyText(current)); flash($("copyBtn")); } catch {}
});
$("exportBtn").addEventListener("click", () => {
  const data = JSON.stringify({ url: current.url, detected: current.results, security: current.security, exported: new Date().toISOString() }, null, 2);
  const url = URL.createObjectURL(new Blob([data], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url; a.download = `techscope-${hostOf(current.url) || "page"}.json`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$("panelBtn").addEventListener("click", async () => {
  try {
    const win = await chrome.windows.getCurrent();
    await chrome.sidePanel.open({ windowId: win.id });
    window.close();
  } catch (e) { /* older build without sidePanel.open */ }
});

function flash(btn) { const t = btn.textContent; btn.textContent = "✓"; setTimeout(() => (btn.textContent = t), 900); }

load();
