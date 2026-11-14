/* background.js (module service worker)
 * Orchestrates detection: captures main-document response headers, injects the
 * page collectors (DOM/meta/scripts/cookies + JS globals), runs the engine, and
 * publishes results to the badge, the popup, and per-site history.
 */
import { loadDataset, detect } from "./engine.js";

// ---- page collectors (injected; must be self-contained) --------------------

function collectSignals(domSelectors) {
  const metas = {};
  document.querySelectorAll("meta").forEach((m) => {
    const n = (m.getAttribute("name") || m.getAttribute("property") || "").toLowerCase();
    if (n) metas[n] = m.getAttribute("content") || "";
  });
  const scriptSrc = [];
  let scripts = "";
  document.querySelectorAll("script").forEach((s) => {
    if (s.src) scriptSrc.push(s.src);
    else if (s.textContent && scripts.length < 80000) scripts += s.textContent + "\n";
  });
  const cookies = {};
  (document.cookie || "").split(";").forEach((c) => {
    const i = c.indexOf("=");
    if (i > 0) cookies[c.slice(0, i).trim()] = c.slice(i + 1).trim();
  });
  const domMatches = {};
  for (const sel of domSelectors) { try { if (document.querySelector(sel)) domMatches[sel] = true; } catch {} }
  return {
    url: location.href,
    html: document.documentElement.outerHTML.slice(0, 200000),
    metas, scriptSrc, scripts: scripts.slice(0, 100000), cookies, domMatches,
  };
}

function probeJs(jsPaths) {
  const out = {};
  for (const path of jsPaths) {
    try {
      let o = window;
      for (const part of path.split(".")) { if (o == null) { o = undefined; break; } o = o[part]; }
      if (o !== undefined) {
        let v = "";
        try { v = (typeof o === "object" || typeof o === "function") ? "" : String(o); } catch {}
        out[path] = v;
      }
    } catch {}
  }
  return out;
}

// ---- header capture --------------------------------------------------------

chrome.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (d.type !== "main_frame" || d.tabId < 0) return;
    const h = {};
    for (const x of d.responseHeaders || []) h[x.name.toLowerCase()] = x.value;
    chrome.storage.session.set({ ["hdr" + d.tabId]: h });
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["responseHeaders"]
);

// ---- analysis --------------------------------------------------------------

function buildSecurity(headers) {
  const h = headers || {};
  const csp = h["content-security-policy"] || "";
  const checks = [
    { label: "HTTPS / HSTS", present: !!h["strict-transport-security"], value: h["strict-transport-security"] || "" },
    { label: "Content-Security-Policy", present: !!csp, value: csp },
    { label: "X-Content-Type-Options", present: !!h["x-content-type-options"], value: h["x-content-type-options"] || "" },
    { label: "Framing protection", present: !!h["x-frame-options"] || /frame-ancestors/i.test(csp), value: h["x-frame-options"] || (/frame-ancestors/i.test(csp) ? "CSP frame-ancestors" : "") },
    { label: "Referrer-Policy", present: !!h["referrer-policy"], value: h["referrer-policy"] || "" },
    { label: "Permissions-Policy", present: !!h["permissions-policy"], value: h["permissions-policy"] || "" },
  ];
  const score = checks.filter((c) => c.present).length;
  const grade = ["F", "F", "D", "C", "B", "A", "A"][score];
  return { checks, score, total: checks.length, grade };
}

function buildResults(foundMap, ds) {
  const cats = ds.categories;
  const out = [];
  for (const [name, info] of foundMap) {
    const t = ds.byName.get(name);
    if (!t) continue;
    const categories = (t.cats || []).map((id) => ({
      id, name: cats[id]?.name || "Other", priority: cats[id]?.priority || 0,
    }));
    out.push({
      name, version: info.version || "", confidence: info.confidence,
      website: t.website, icon: t.icon, categories,
    });
  }
  out.sort((a, b) => {
    const pa = Math.max(0, ...a.categories.map((c) => c.priority));
    const pb = Math.max(0, ...b.categories.map((c) => c.priority));
    return pb - pa || a.name.localeCompare(b.name);
  });
  return out;
}

async function analyze(tabId, url) {
  if (!/^https?:/i.test(url || "")) return null;
  const ds = await loadDataset();

  let signals = {};
  try {
    const [s] = await chrome.scripting.executeScript({ target: { tabId }, func: collectSignals, args: [ds.domSelectors] });
    signals = s?.result || {};
  } catch { return null; } // restricted page

  let jsValues = {};
  try {
    const [p] = await chrome.scripting.executeScript({ target: { tabId }, world: "MAIN", func: probeJs, args: [ds.jsPaths] });
    jsValues = p?.result || {};
  } catch {}

  const headers = (await chrome.storage.session.get("hdr" + tabId))["hdr" + tabId] || {};
  const results = buildResults(detect(ds.compiled, signals, headers, jsValues), ds);
  const security = buildSecurity(headers);

  await chrome.storage.session.set({ ["res" + tabId]: { url: signals.url || url, results, security, ts: Date.now() } });
  setBadge(tabId, results.length);
  saveHistory(signals.url || url, results);
  return { url: signals.url || url, results, security };
}

function setBadge(tabId, n) {
  chrome.action.setBadgeBackgroundColor({ color: "#4254f5" });
  chrome.action.setBadgeText({ tabId, text: n ? String(n) : "" });
}

async function saveHistory(url, results) {
  let host;
  try { host = new URL(url).hostname.replace(/^www\./, ""); } catch { return; }
  const { history = {} } = await chrome.storage.local.get("history");
  history[host] = { ts: Date.now(), count: results.length, names: results.map((r) => r.name) };
  const hosts = Object.keys(history);
  if (hosts.length > 300) { // trim oldest
    hosts.sort((a, b) => history[a].ts - history[b].ts).slice(0, hosts.length - 300).forEach((h) => delete history[h]);
  }
  await chrome.storage.local.set({ history });
}

// ---- Shodan / VirusTotal lookups -------------------------------------------
// Keys are stored locally and only ever sent to Shodan / VirusTotal directly.
async function getKeys() {
  const { shodanKey = "", vtKey = "" } = await chrome.storage.local.get(["shodanKey", "vtKey"]);
  return { shodanKey: shodanKey.trim(), vtKey: vtKey.trim() };
}

const isIp = (s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || (s.includes(":") && /^[0-9a-f:]+$/i.test(s));

// Resolve a hostname to an IP. Uses Shodan's resolver if a key is set, else a
// keyless DNS-over-HTTPS lookup (dns.google) so the InternetDB fallback works.
async function resolveIp(host, shodanKey) {
  if (isIp(host)) return host;
  if (shodanKey) {
    try {
      const r = await fetch(`https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(host)}&key=${encodeURIComponent(shodanKey)}`);
      if (r.ok) { const ip = (await r.json())[host]; if (ip) return ip; }
    } catch {}
  }
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`);
    if (r.ok) { const a = ((await r.json()).Answer || []).filter((x) => x.type === 1).map((x) => x.data); if (a.length) return a[0]; }
  } catch {}
  return null;
}

// Keyless fallback: Shodan InternetDB (no API key, rate-limited, basic data).
async function internetDb(ip, prefix) {
  try {
    const r = await fetch(`https://internetdb.shodan.io/${ip}`);
    if (r.status === 404) return { source: "internetdb", ip, ports: [], vulns: [], note: (prefix || "") + "No data indexed for this IP." };
    if (!r.ok) throw new Error("InternetDB HTTP " + r.status);
    const d = await r.json();
    return {
      source: "internetdb", ip,
      ports: (d.ports || []).sort((a, b) => a - b),
      vulns: d.vulns || [], cpes: d.cpes || [], hostnames: d.hostnames || [], tags: d.tags || [],
      note: (prefix || "") + "Keyless (Shodan InternetDB) — add an API key in Settings for full data.",
    };
  } catch (e) { return { error: String(e.message || e) }; }
}

async function shodanLookup(target) {
  const host = (target || "").trim();
  if (!host) return { error: "No target host/IP." };
  const { shodanKey } = await getKeys();
  const ip = await resolveIp(host, shodanKey);
  if (!ip) return { error: "Could not resolve to an IP." };

  if (shodanKey) {
    try {
      const r = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${encodeURIComponent(shodanKey)}`);
      if (r.status === 401) return { error: "Invalid Shodan API key." };
      if (r.status === 404) return internetDb(ip, "No full Shodan record — "); // graceful fallback
      if (r.ok) {
        const d = await r.json();
        return {
          source: "shodan", ip, org: d.org || d.isp || "", country: d.country_name || "", os: d.os || "",
          ports: (d.ports || []).sort((a, b) => a - b),
          vulns: Array.isArray(d.vulns) ? d.vulns : Object.keys(d.vulns || {}),
          services: (d.data || []).slice(0, 30).map((s) => ({
            port: s.port, transport: s.transport || "",
            product: s.product || (s._shodan && s._shodan.module) || "",
          })),
        };
      }
    } catch { /* fall through to keyless */ }
  }
  return internetDb(ip); // no key, or the authed call failed
}

async function vtLookup(domain) {
  const { vtKey } = await getKeys();
  if (!vtKey) return { error: "No VirusTotal API key set (Settings tab)." };
  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, { headers: { "x-apikey": vtKey } });
    if (r.status === 401) return { error: "Invalid VirusTotal API key." };
    if (r.status === 429) return { error: "VirusTotal rate limit reached (free tier = 4/min)." };
    if (!r.ok) throw new Error("HTTP " + r.status);
    const a = (await r.json()).data?.attributes || {};
    return {
      reputation: a.reputation ?? 0,
      stats: a.last_analysis_stats || {},
      categories: a.categories || {},
      registrar: a.registrar || "",
      created: a.creation_date ? new Date(a.creation_date * 1000).toISOString().slice(0, 10) : "",
    };
  } catch (e) { return { error: String(e.message || e) }; }
}

// ---- auto-reload when the scheduled task refreshes the dataset -------------
async function readBuildVersion() {
  try {
    const r = await fetch(chrome.runtime.getURL("build-version.txt"), { cache: "no-store" });
    if (!r.ok) return null;
    return (await r.text()).trim();
  } catch { return null; }
}
async function checkForDatasetUpdate() {
  const v = await readBuildVersion();
  if (!v) return;
  const { buildVersion } = await chrome.storage.local.get("buildVersion");
  if (buildVersion === undefined) { await chrome.storage.local.set({ buildVersion: v }); return; }
  if (v !== buildVersion) {
    await chrome.storage.local.set({ buildVersion: v }); // set BEFORE reload to avoid a loop
    chrome.runtime.reload();
  }
}
chrome.alarms.create("datasetUpdate", { delayInMinutes: 1, periodInMinutes: 360 });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === "datasetUpdate") checkForDatasetUpdate(); });
chrome.runtime.onStartup.addListener(() => checkForDatasetUpdate());

// ---- events ----------------------------------------------------------------

chrome.webNavigation.onCompleted.addListener((d) => {
  if (d.frameId === 0) analyze(d.tabId, d.url).catch(() => {});
}, { url: [{ schemes: ["http", "https"] }] });

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg?.type === "analyze") {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) return sendResponse({ results: [], url: "" });
      const cached = (await chrome.storage.session.get("res" + tab.id))["res" + tab.id];
      if (cached && !msg.force && cached.url === tab.url) return sendResponse(cached);
      const out = await analyze(tab.id, tab.url);
      sendResponse(out || { results: [], url: tab.url, security: null });
    } else if (msg?.type === "history") {
      const { history = {} } = await chrome.storage.local.get("history");
      sendResponse({ history });
    } else if (msg?.type === "clearHistory") {
      await chrome.storage.local.set({ history: {} });
      sendResponse({ ok: true });
    } else if (msg?.type === "getKeys") {
      const { shodanKey, vtKey } = await getKeys();
      sendResponse({ shodanSet: !!shodanKey, vtSet: !!vtKey }); // never echo the keys
    } else if (msg?.type === "setKeys") {
      const patch = {};
      if (typeof msg.shodanKey === "string") patch.shodanKey = msg.shodanKey.trim();
      if (typeof msg.vtKey === "string") patch.vtKey = msg.vtKey.trim();
      await chrome.storage.local.set(patch);
      sendResponse({ ok: true });
    } else if (msg?.type === "shodan") {
      sendResponse(await shodanLookup(msg.host));
    } else if (msg?.type === "vt") {
      sendResponse(await vtLookup(msg.domain));
    } else if (msg?.type === "meta") {
      const ds = await loadDataset();
      sendResponse({ meta: ds.meta });
    } else {
      sendResponse({ ok: false });
    }
  })();
  return true;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(["hdr" + tabId, "res" + tabId]);
});
