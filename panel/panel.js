/* panel.js — side-panel UI: Technologies, Security, Shodan, VirusTotal,
 * History, and Settings. */
import { renderTech, renderSecurity, copyText, colorFor, esc, hostOf } from "../ui.js";

const $ = (id) => document.getElementById(id);
let current = { url: "", results: [], security: null };
const send = (m) => chrome.runtime.sendMessage(m).catch(() => null);

// tabs
function activateTab(name) {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === name));
  document.querySelectorAll(".panel-view").forEach((x) => x.classList.remove("active"));
  const p = $("panel-" + name);
  if (p) p.classList.add("active");
  if (name === "history") loadHistory();
  if (name === "settings") loadKeyStatus();
}
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => activateTab(t.dataset.tab)));

// Right-click → "Send to TechScope" leaves a pending query for us to run.
async function checkPending() {
  let pending;
  try { pending = (await chrome.storage.session.get("pending")).pending; } catch { return; }
  if (!pending || Date.now() - pending.ts > 30000) return;
  try { await chrome.storage.session.remove("pending"); } catch {}
  if (pending.type === "shodan") { activateTab("shodan"); $("shodanTarget").value = pending.query; runShodan(false); }
  else { activateTab("vt"); $("vtTarget").value = pending.query; runVt(false); }
}
chrome.storage.onChanged.addListener((ch, area) => { if (area === "session" && ch.pending?.newValue) checkPending(); });

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
let lastShodan = null;

async function runShodan(fresh) {
  const host = $("shodanTarget").value.trim() || hostOf(current.url);
  if (!host) return;
  $("shodan").innerHTML = `<div class="empty">Querying ${esc(host)}…</div>`;
  const d = await send({ type: "shodan", host, fresh });
  if (!d || d.error) { lastShodan = null; $("shodan").innerHTML = `<div class="err">${esc(d?.error || "Lookup failed")}</div>`; return; }
  lastShodan = d;

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
  if (d.cached) html += `<div class="note">Served from cache (within 10 min) — use ⟳ refresh to re-query.</div>`;

  // Geolocation map (keyless OpenStreetMap embed)
  if (typeof d.lat === "number" && typeof d.lon === "number") {
    const lat = d.lat, lon = d.lon;
    const bbox = [lon - 0.4, lat - 0.3, lon + 0.4, lat + 0.3].join("%2C");
    html += `<div class="cat-head">Location</div>
      <div class="map"><iframe loading="lazy" referrerpolicy="no-referrer"
        src="https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${lat}%2C${lon}"></iframe></div>
      <div class="note"><a href="https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=10/${lat}/${lon}" target="_blank" rel="noopener">Open larger map</a> · ${lat.toFixed(3)}, ${lon.toFixed(3)}</div>`;
  }

  // Registration (WHOIS / RDAP, keyless)
  if (d.rdap) {
    html += `<div class="cat-head">Domain registration (RDAP)</div>`;
    html += kv("Registrar", d.rdap.registrar);
    html += kv("Created", (d.rdap.created || "").slice(0, 10));
    html += kv("Expires", (d.rdap.expires || "").slice(0, 10));
    html += kv("Updated", (d.rdap.updated || "").slice(0, 10));
    html += chips("Status", d.rdap.status);
    html += chips("Nameservers", d.rdap.nameservers);
  }
  if (d.rdapIp && (d.rdapIp.name || d.rdapIp.org || d.rdapIp.cidr)) {
    html += `<div class="cat-head">IP network (RDAP)</div>`;
    html += kv("Network", d.rdapIp.name);
    html += kv("Owner", d.rdapIp.org);
    html += kv("Range", d.rdapIp.cidr);
    html += kv("Country", d.rdapIp.country);
  }

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

  // Related hosts / servers connected to the domain
  if (d.related && d.related.length) {
    html += `<div class="cat-head">Related hosts / servers (${d.related.length})</div>`;
    for (const h of d.related) {
      const extra = [h.org, h.product, h.port ? ":" + h.port : ""].filter(Boolean).join(" · ");
      html += `<div class="svc"><div class="svc-h">${esc(h.ip)} <span class="chip">${esc(h.source)}</span></div>`;
      if (h.hostnames?.length) html += `<div class="kv"><span class="v">${esc(h.hostnames.join(", "))}</span></div>`;
      if (extra) html += `<div class="kv"><span class="v">${esc(extra)}</span></div>`;
      html += `</div>`;
    }
  }

  if (d.note) html += `<div class="note">${esc(d.note)}</div>`;
  $("shodan").innerHTML = html || `<div class="empty">No data.</div>`;
}

$("shodanBtn").addEventListener("click", () => runShodan(false));
$("shodanRefreshBtn").addEventListener("click", () => runShodan(true));
$("shodanExportBtn").addEventListener("click", () => {
  if (!lastShodan) return;
  const name = String(lastShodan.query || lastShodan.ip || "report").replace(/[^a-z0-9.\-]/gi, "_");
  const url = URL.createObjectURL(new Blob([JSON.stringify(lastShodan, null, 2)], { type: "application/json" }));
  const a = document.createElement("a"); a.href = url; a.download = `shodan-${name}.json`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$("shodanCopyBtn").addEventListener("click", async () => {
  if (!lastShodan) return;
  try { await navigator.clipboard.writeText(shodanReport(lastShodan)); flash($("shodanCopyBtn")); } catch {}
});

function shodanReport(d) {
  const L = [`# Shodan report — ${d.query || d.ip}`, `IP: ${d.ip}  (source: ${d.source})`];
  if (d.org) L.push(`Org: ${d.org}`);
  if (d.isp) L.push(`ISP: ${d.isp}`);
  if (d.asn) L.push(`ASN: ${d.asn}`);
  if (d.city || d.country) L.push(`Location: ${[d.city, d.country].filter(Boolean).join(", ")}`);
  if (typeof d.lat === "number") L.push(`Coords: ${d.lat}, ${d.lon}`);
  if (d.rdap) L.push(`Registrar: ${d.rdap.registrar} (created ${(d.rdap.created || "").slice(0, 10)}, expires ${(d.rdap.expires || "").slice(0, 10)})`);
  if (d.ports?.length) L.push(`Open ports: ${d.ports.join(", ")}`);
  if (d.vulns?.length) L.push(`CVEs: ${d.vulns.join(", ")}`);
  if (d.dns?.records?.length) { L.push(`\nDNS:`); for (const r of d.dns.records) L.push(`  ${r.type} ${r.value}`); }
  if (d.related?.length) { L.push(`\nRelated hosts:`); for (const h of d.related) L.push(`  ${h.ip}  ${h.hostnames.join(", ")}${h.org ? "  [" + h.org + "]" : ""}`); }
  if (d.services?.length) { L.push(`\nServices:`); for (const s of d.services) L.push(`  :${s.port} ${[s.product, s.version].filter(Boolean).join(" ")}${s.ssl ? "  SSL:" + s.ssl.subject : ""}`); }
  return L.join("\n");
}

// ---- VirusTotal ------------------------------------------------------------
async function runVt(fresh) {
  const target = $("vtTarget").value.trim() || hostOf(current.url);
  if (!target) return;
  $("vt").innerHTML = `<div class="empty">Querying ${esc(target)}…</div>`;
  const d = await send({ type: "vt", target, fresh });
  if (!d || d.error) { $("vt").innerHTML = `<div class="err">${esc(d?.error || "Lookup failed")}</div>`; return; }
  const s = d.stats || {};
  const mal = s.malicious || 0, susp = s.suspicious || 0, harm = s.harmless || 0, undet = s.undetected || 0;
  const cls = mal > 0 ? "g-F" : susp > 0 ? "g-C" : "g-A";
  const letter = mal > 0 ? "!" : susp > 0 ? "?" : "✓";
  const kv = (k, v) => v ? `<div class="kv"><span class="k">${k}</span><span class="v">${esc(v)}</span></div>` : "";
  let html = `<div class="grade"><div class="letter ${cls}">${letter}</div>
    <div class="meta">${mal} malicious · ${susp} suspicious · ${harm} harmless · ${undet} undetected<br>${esc(d.kind)} · reputation ${d.reputation}</div></div>`;
  if (d.cached) html += `<div class="note">Served from cache (within 10 min) — ⟳ refresh to re-query.</div>`;
  if (d.kind === "file") {
    html += kv("Name", d.name);
    html += kv("Type", d.typeDesc);
    html += kv("Threat label", d.threatLabel);
    html += kv("Size", d.size ? d.size.toLocaleString() + " bytes" : "");
    html += kv("First seen", d.firstSeen);
    html += kv("SHA-256", d.sha256);
    html += kv("MD5", d.md5);
    if (d.names?.length) html += kv("Other names", d.names.join(", "));
    html += `<button id="vtDownloadBtn" class="scan-btn" data-hash="${esc(d.sha256 || d.query)}">⤓ Download sample (VT Premium)</button>`;
    html += `<button id="mbDownloadBtn" class="scan-btn" data-hash="${esc(d.sha256 || d.query)}">⤓ MalwareBazaar (keyless)</button>`;
    html += `<div class="note">VirusTotal download needs a Premium key; MalwareBazaar is keyless and returns a ZIP (password: <code>infected</code>). Live samples — handle only in an isolated/sandboxed environment.</div>`;
  } else if (d.kind === "ip") {
    html += kv("AS owner", d.asOwner);
    html += kv("ASN", d.asn);
    html += kv("Country", d.country);
  } else {
    html += kv("Registrar", d.registrar);
    html += kv("Created", d.created);
    const cats = [...new Set(Object.values(d.categories || {}))];
    if (cats.length) html += `<div class="kv"><span class="k">Categories</span><span class="v">${cats.map((c) => `<span class="chip">${esc(c)}</span>`).join("")}</span></div>`;
  }
  html += `<div class="note"><a href="https://www.virustotal.com/gui/search/${encodeURIComponent(d.query)}" target="_blank" rel="noopener">Open on VirusTotal</a></div>`;
  $("vt").innerHTML = html;

  const dl = $("vtDownloadBtn");
  if (dl) dl.addEventListener("click", async () => {
    dl.disabled = true; const label = dl.textContent; dl.textContent = "Downloading…";
    const r = await send({ type: "vtDownload", hash: dl.dataset.hash });
    dl.disabled = false;
    if (r?.ok) { dl.textContent = "✓ Download started"; }
    else { dl.textContent = label; const e = document.createElement("div"); e.className = "err"; e.textContent = r?.error || "Download failed"; $("vt").appendChild(e); }
  });

  const mb = $("mbDownloadBtn");
  if (mb) mb.addEventListener("click", async () => {
    const label = mb.textContent; mb.disabled = true; mb.textContent = "Downloading…";
    try {
      const { mbKey = "" } = await chrome.storage.local.get("mbKey");
      const fd = new FormData();
      fd.append("query", "get_file");
      fd.append("sha256_hash", mb.dataset.hash);
      const headers = {}; if (mbKey.trim()) headers["Auth-Key"] = mbKey.trim();
      const r = await fetch("https://mb-api.abuse.ch/api/v1/", { method: "POST", body: fd, headers });
      const ct = r.headers.get("content-type") || "";
      if (ct.includes("json") || ct.includes("text")) {
        const j = await r.json().catch(() => ({}));
        throw new Error(j.query_status === "file_not_found"
          ? "Not found on MalwareBazaar."
          : (j.query_status || "MalwareBazaar error — it may now require a free Auth-Key (add it in Settings)."));
      }
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = mb.dataset.hash + ".zip"; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1500);
      mb.textContent = "✓ Downloaded (zip pw: infected)";
    } catch (e) {
      mb.textContent = label;
      const n = document.createElement("div"); n.className = "err"; n.textContent = String(e.message || e); $("vt").appendChild(n);
    } finally { mb.disabled = false; }
  });
}
$("vtBtn").addEventListener("click", () => runVt(false));
$("vtRefreshBtn").addEventListener("click", () => runVt(true));

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
  $("mbStatus").textContent = r?.mbSet ? "key saved ✓" : "not set (keyless downloads still work)";
}
$("saveKeysBtn").addEventListener("click", async () => {
  await send({ type: "setKeys", shodanKey: $("shodanKey").value, vtKey: $("vtKey").value, mbKey: $("mbKey").value });
  $("shodanKey").value = ""; $("vtKey").value = ""; $("mbKey").value = "";
  loadKeyStatus();
  flash($("saveKeysBtn"));
});

function flash(btn) { const t = btn.textContent; btn.textContent = "✓"; setTimeout(() => (btn.textContent = t), 900); }

send({ type: "meta" }).then((r) => { if (r?.meta) $("dbinfo").textContent = `${r.meta.techCount} techs`; });
load();
checkPending();
