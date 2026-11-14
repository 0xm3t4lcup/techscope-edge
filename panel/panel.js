/* panel.js — side-panel UI: Technologies, Security, Shodan, VirusTotal,
 * History, and Settings. */
import { renderTech, renderSecurity, copyText, colorFor, esc, hostOf } from "../ui.js";

const $ = (id) => document.getElementById(id);
let current = { url: "", results: [], security: null };
const send = (m) => chrome.runtime.sendMessage(m).catch(() => null);

// tabs
document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel-view").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $("panel-" + t.dataset.tab).classList.add("active");
    if (t.dataset.tab === "history") loadHistory();
    if (t.dataset.tab === "settings") loadKeyStatus();
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

$("search").addEventListener("input", (e) => renderTech($("results"), current.results, e.target.value));
$("rescanBtn").addEventListener("click", () => load(true));
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

// ---- Shodan ----------------------------------------------------------------
$("shodanBtn").addEventListener("click", async () => {
  const host = $("shodanTarget").value.trim() || hostOf(current.url);
  if (!host) return;
  $("shodan").innerHTML = `<div class="empty">Querying ${esc(host)}…</div>`;
  const d = await send({ type: "shodan", host });
  if (!d || d.error) { $("shodan").innerHTML = `<div class="err">${esc(d?.error || "Lookup failed")}</div>`; return; }
  let html = "";
  const kv = (k, v) => v ? `<div class="kv"><span class="k">${k}</span><span class="v">${esc(v)}</span></div>` : "";
  html += kv("IP", d.ip);
  html += kv("Source", d.source === "internetdb" ? "Shodan InternetDB (keyless)" : "Shodan");
  html += kv("Organization", d.org);
  html += kv("Country", d.country);
  html += kv("OS", d.os);
  if (d.ports?.length) html += `<div class="kv"><span class="k">Open ports</span><span class="v">${d.ports.map((p) => `<span class="chip">${p}</span>`).join("")}</span></div>`;
  if (d.vulns?.length) html += `<div class="kv"><span class="k">Vulnerabilities</span><span class="v">${d.vulns.slice(0, 60).map((v) => `<span class="chip bad">${esc(v)}</span>`).join("")}</span></div>`;
  if (d.hostnames?.length) html += kv("Hostnames", d.hostnames.join(", "));
  if (d.tags?.length) html += `<div class="kv"><span class="k">Tags</span><span class="v">${d.tags.map((t) => `<span class="chip">${esc(t)}</span>`).join("")}</span></div>`;
  if (d.services?.length) html += `<div class="cat-head">Services</div>` + d.services.map((s) =>
    `<div class="kv"><span class="k">:${s.port}${s.transport ? "/" + s.transport : ""}</span><span class="v">${esc(s.product || "—")}</span></div>`).join("");
  if (d.cpes?.length) html += `<div class="cat-head">CPEs</div>` + `<div class="kv"><span class="v">${d.cpes.slice(0, 40).map((c) => `<span class="chip">${esc(c)}</span>`).join("")}</span></div>`;
  if (d.note) html += `<div class="note">${esc(d.note)}</div>`;
  $("shodan").innerHTML = html || `<div class="empty">No data.</div>`;
});

// ---- VirusTotal ------------------------------------------------------------
$("vtBtn").addEventListener("click", async () => {
  const host = $("vtTarget").value.trim() || hostOf(current.url);
  if (!host) return;
  $("vt").innerHTML = `<div class="empty">Querying ${esc(host)}…</div>`;
  const d = await send({ type: "vt", domain: host });
  if (!d || d.error) { $("vt").innerHTML = `<div class="err">${esc(d?.error || "Lookup failed")}</div>`; return; }
  const s = d.stats || {};
  const mal = s.malicious || 0, susp = s.suspicious || 0, harm = s.harmless || 0;
  const cls = mal > 0 ? "g-F" : susp > 0 ? "g-C" : "g-A";
  const letter = mal > 0 ? "!" : susp > 0 ? "?" : "✓";
  let html = `<div class="grade"><div class="letter ${cls}">${letter}</div>
    <div class="meta">${mal} malicious · ${susp} suspicious · ${harm} harmless<br>reputation ${d.reputation}</div></div>`;
  const kv = (k, v) => v ? `<div class="kv"><span class="k">${k}</span><span class="v">${esc(v)}</span></div>` : "";
  html += kv("Registrar", d.registrar);
  html += kv("Created", d.created);
  const cats = Object.values(d.categories || {});
  if (cats.length) html += `<div class="kv"><span class="k">Categories</span><span class="v">${[...new Set(cats)].map((c) => `<span class="chip">${esc(c)}</span>`).join("")}</span></div>`;
  $("vt").innerHTML = html;
});

// ---- history ---------------------------------------------------------------
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
$("clearHistBtn").addEventListener("click", async () => { await send({ type: "clearHistory" }); loadHistory(); });

// ---- settings --------------------------------------------------------------
async function loadKeyStatus() {
  const r = await send({ type: "getKeys" });
  $("shodanStatus").textContent = r?.shodanSet ? "key saved ✓" : "not set";
  $("vtStatus").textContent = r?.vtSet ? "key saved ✓" : "not set";
}
$("saveKeysBtn").addEventListener("click", async () => {
  await send({ type: "setKeys", shodanKey: $("shodanKey").value, vtKey: $("vtKey").value });
  $("shodanKey").value = ""; $("vtKey").value = "";
  loadKeyStatus();
  flash($("saveKeysBtn"));
});

function flash(btn) { const t = btn.textContent; btn.textContent = "✓"; setTimeout(() => (btn.textContent = t), 900); }

send({ type: "meta" }).then((r) => { if (r?.meta) $("dbinfo").textContent = `${r.meta.techCount} techs`; });
load();
