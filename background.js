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

function extractSans(cert) {
  try {
    const ext = (cert.extensions || []).find((e) => e.name === "subjectAltName");
    if (ext && ext.data) return ext.data.replace(/DNS:/g, "").split(/,\s*/).filter(Boolean).slice(0, 25);
  } catch {}
  return [];
}

function parseServices(data) {
  return (data || []).slice(0, 40).map((s) => {
    const svc = {
      port: s.port, transport: s.transport || "",
      product: s.product || "", version: s.version || "",
      module: (s._shodan && s._shodan.module) || "",
    };
    if (s.http) svc.http = { server: s.http.server || "", title: s.http.title || "", status: s.http.status || "" };
    if (s.ssl && s.ssl.cert) {
      const c = s.ssl.cert;
      svc.ssl = {
        subject: (c.subject && c.subject.CN) || "",
        issuer: (c.issuer && (c.issuer.CN || c.issuer.O)) || "",
        issued: c.issued || "", expires: c.expires || "",
        sigAlg: c.sig_alg || "", sha256: (c.fingerprint && c.fingerprint.sha256) || "",
        versions: s.ssl.versions || [],
        cipher: s.ssl.cipher ? `${s.ssl.cipher.name || ""} (${s.ssl.cipher.bits || "?"} bit)` : "",
        jarm: s.ssl.jarm || "",
        sans: extractSans(c),
      };
    }
    return svc;
  });
}

async function doh(name, type) {
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`);
    if (!r.ok) return [];
    return ((await r.json()).Answer || []).map((a) => ({ type, name: a.name, value: a.data }));
  } catch { return []; }
}

// Domain intelligence: subdomains + DNS records (Shodan DNS if keyed, else DoH)
// plus Certificate-Transparency certs from crt.sh (keyless).
async function domainLookup(domain, key) {
  const out = { subdomains: [], records: [], certs: [] };
  let gotShodanDns = false;
  if (key) {
    try {
      const r = await fetch(`https://api.shodan.io/dns/domain/${encodeURIComponent(domain)}?key=${encodeURIComponent(key)}`);
      if (r.ok) {
        const d = await r.json();
        out.subdomains = (d.subdomains || []).slice(0, 100);
        out.records = (d.data || []).slice(0, 100).map((x) => ({
          type: x.type, name: (x.subdomain ? x.subdomain + "." : "") + domain, value: x.value,
        }));
        gotShodanDns = true;
      }
    } catch {}
  }
  if (!gotShodanDns) {
    for (const t of ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]) out.records.push(...(await doh(domain, t)));
    out.records = out.records.slice(0, 100);
  }
  try { // crt.sh certificate transparency (keyless)
    const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`);
    if (r.ok) {
      const arr = await r.json();
      const seen = new Set();
      for (const c of arr) {
        const k = (c.issuer_name || "") + "|" + (c.not_after || "");
        if (seen.has(k)) continue; seen.add(k);
        out.certs.push({
          issuer: c.issuer_name || "", names: String(c.name_value || "").split("\n").slice(0, 6),
          notBefore: c.not_before || "", notAfter: c.not_after || "",
        });
        if (out.certs.length >= 8) break;
      }
    }
  } catch {}
  return out;
}

// Keyless WHOIS-equivalent via RDAP (rdap.org bootstraps to the right registry).
function vcardFn(entity) {
  try {
    const v = entity.vcardArray && entity.vcardArray[1];
    if (v) { const fn = v.find((x) => x[0] === "fn"); if (fn) return fn[3]; }
  } catch {}
  return "";
}
async function rdapDomain(domain) {
  try {
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    if (!r.ok) return null;
    const d = await r.json();
    const ev = {}; for (const e of d.events || []) ev[e.eventAction] = e.eventDate;
    let registrar = "";
    for (const en of d.entities || []) {
      if ((en.roles || []).includes("registrar")) registrar = vcardFn(en) || (en.publicIds?.[0]?.identifier) || "";
    }
    return {
      registrar, created: ev.registration || "", expires: ev.expiration || "", updated: ev["last changed"] || "",
      status: (d.status || []).slice(0, 10),
      nameservers: (d.nameservers || []).map((n) => n.ldhName).filter(Boolean).slice(0, 12),
    };
  } catch { return null; }
}
async function rdapIp(ip) {
  try {
    const r = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`);
    if (!r.ok) return null;
    const d = await r.json();
    let org = "";
    for (const en of d.entities || []) { const fn = vcardFn(en); if (fn) { org = fn; break; } }
    const c0 = d.cidr0_cidrs?.[0];
    const cidr = c0 ? `${c0.v4prefix || c0.v6prefix}/${c0.length}` : (d.startAddress && d.endAddress ? `${d.startAddress} – ${d.endAddress}` : "");
    return { name: d.name || "", handle: d.handle || "", country: d.country || "", cidr, org };
  } catch { return null; }
}

async function shodanHost(ip, key) {
  const r = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${encodeURIComponent(key)}`);
  if (r.status === 401) return { error: "Invalid Shodan API key." };
  if (r.status === 404) return { notFound: true };
  if (!r.ok) throw new Error("host HTTP " + r.status);
  const d = await r.json();
  return {
    source: "shodan", ip, org: d.org || "", isp: d.isp || "", asn: d.asn || "", os: d.os || "",
    city: d.city || "", country: d.country_name || "", lastUpdate: d.last_update || "",
    hostnames: d.hostnames || [], domains: d.domains || [], tags: d.tags || [],
    ports: (d.ports || []).sort((a, b) => a - b),
    vulns: Array.isArray(d.vulns) ? d.vulns : Object.keys(d.vulns || {}),
    services: parseServices(d.data),
  };
}

async function shodanLookup(target) {
  const host = (target || "").trim();
  if (!host) return { error: "No target host/IP." };
  const { shodanKey } = await getKeys();
  const ip = await resolveIp(host, shodanKey);
  if (!ip) return { error: "Could not resolve to an IP." };

  let out;
  if (shodanKey) {
    try {
      const rec = await shodanHost(ip, shodanKey);
      if (rec.error) return rec;
      out = rec.notFound ? await internetDb(ip, "No full Shodan record — ") : rec;
    } catch { out = await internetDb(ip); }
  } else {
    out = await internetDb(ip);
  }
  out.query = host;

  // Enrich in parallel: IP RDAP (always), plus domain DNS + domain RDAP for hosts.
  out.rdapIp = null;
  const jobs = [rdapIp(ip).then((r) => { out.rdapIp = r; })];
  if (!isIp(host)) {
    jobs.push(domainLookup(host, shodanKey).then((r) => { out.dns = r; }));
    jobs.push(rdapDomain(host).then((r) => { out.rdap = r; }));
  }
  await Promise.all(jobs);

  // Backfill org/country from RDAP when the keyless source didn't provide them.
  if (!out.org && out.rdapIp?.org) out.org = out.rdapIp.org;
  if (!out.country && out.rdapIp?.country) out.country = out.rdapIp.country;
  return out;
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
