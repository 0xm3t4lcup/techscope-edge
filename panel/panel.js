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

  const kv = (k, v) => v ? `<div class="kv"><span class="k">${k}</span><span class="v">${esc(v)}</span></div>` : "";
  const chips = (k, arr, cls = "") => arr && arr.length
    ? `<div class="kv"><span class="k">${k}</span><span class="v">${arr.map((x) => `<span class="chip ${cls}">${esc(x)}</span>`).join("")}</span></div>` : "";
  let html = "";

  // Overview
  html += `<div class="cat-head">Overview</div>`;
  html += kv("Query", d.query);
  html += kv("IP", d.ip);
  html += kv("Source", d.source === "internetdb" ? "Shodan InternetDB (keyless)" : "Shodan (full)");
  html += kv("Organization", d.org);
  html += kv("ISP", d.isp);
  html += kv("ASN", d.asn);
  html += kv("OS", d.os);
  html += kv("Location", [d.city, d.country].filter(Boolean).join(", "));
  html += kv("Last seen", d.lastUpdate ? d.lastUpdate.slice(0, 19).replace("T", " ") : "");
  html += chips("Hostnames", d.hostnames);
  html += chips("Domains", d.domains);
  html += chips("Tags", d.tags);
  html += chips("CPEs", d.cpes);

  // DNS / domain
  if (d.dns) {
    html += `<div class="cat-head">DNS records</div>`;
    if (d.dns.records?.length) html += d.dns.records.map((r) =>
      `<div class="kv"><span class="k">${esc(r.type)}</span><span class="v">${esc(r.value)}</span></div>`).join("");
    else html += `<div class="empty">No records.</div>`;
    if (d.dns.subdomains?.length) html += chips("Subdomains", d.dns.subdomains.slice(0, 60));
  }

  // Ports & vulns
  html += chips("Open ports", d.ports?.map(String));
  html += chips("Vulnerabilities (CVE)", d.vulns?.slice(0, 80), "bad");

  // SSL certificates (per-service, from Shodan)
  const sslSvcs = (d.services || []).filter((s) => s.ssl);
  if (sslSvcs.length) {
    html += `<div class="cat-head">TLS / SSL certificates</div>`;
    for (const s of sslSvcs) {
      html += `<div class="svc"><div class="svc-h">:${s.port} — ${esc(s.ssl.subject || "cert")}</div>`;
      html += kv("Issuer", s.ssl.issuer);
      html += kv("Valid", [s.ssl.issued, s.ssl.expires].filter(Boolean).join("  →  "));
      html += chips("TLS versions", s.ssl.versions);
      html += kv("Cipher", s.ssl.cipher);
      html += chips("SANs", s.ssl.sans);
      html += kv("Sig alg", s.ssl.sigAlg);
      html += kv("JARM", s.ssl.jarm);
      html += kv("SHA-256", s.ssl.sha256);
      html += `</div>`;
    }
  }

  // Certificate Transparency (crt.sh, keyless)
  if (d.dns?.certs?.length) {
    html += `<div class="cat-head">Certificates (CT logs · crt.sh)</div>`;
    for (const c of d.dns.certs) {
      html += `<div class="svc"><div class="svc-h">${esc(c.issuer)}</div>`;
      html += kv("Valid", [c.notBefore, c.notAfter].filter(Boolean).join("  →  "));
      html += chips("Names", c.names);
      html += `</div>`;
    }
  }

  // Services
  if (d.services?.length) {
    html += `<div class="cat-head">Services</div>`;
    for (const s of d.services) {
      const label = [s.product, s.version].filter(Boolean).join(" ") || s.module || "—";
      html += `<div class="svc"><div class="svc-h">:${s.port}${s.transport ? "/" + s.transport : ""} — ${esc(label)}</div>`;
      if (s.http) { html += kv("HTTP server", s.http.server); html += kv("Title", s.http.title); }
      html += `</div>`;
    }
  }

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
