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

// Second detection method for servers/versions: parse response headers directly,
// so the server name + version show even when the fingerprint dataset misses them.
function catByName(ds, name) {
  for (const id in ds.categories) if (ds.categories[id].name === name) return { id: +id, name, priority: ds.categories[id].priority || 0 };
  return { id: 0, name, priority: 0 };
}
function parseNameVer(token) {
  token = String(token || "").trim();
  const m = token.match(/^([A-Za-z0-9 .+\-_]+?)[\/ ]v?(\d[\w.\-]*)/);
  if (m) return { name: m[1].trim(), version: m[2] };
  return { name: token.replace(/\s*\(.*$/, "").trim(), version: "" };
}
function enrichFromHeaders(results, headers, ds) {
  const have = new Map(results.map((r) => [r.name.toLowerCase(), r]));
  const add = (name, version, catName) => {
    if (!name) return;
    const ex = have.get(name.toLowerCase());
    if (ex) { if (version && !ex.version) ex.version = version; return; }
    const t = { name, version: version || "", confidence: 100, website: "", icon: "", categories: [catByName(ds, catName)], fromHeader: true };
    results.push(t); have.set(name.toLowerCase(), t);
  };
  const H = headers || {};
  if (H.server) for (const p of H.server.split(",")) { const { name, version } = parseNameVer(p); add(name, version, "Web servers"); }
  if (H["x-powered-by"]) for (const p of H["x-powered-by"].split(",")) { const { name, version } = parseNameVer(p); add(name, version, "Web frameworks"); }
  if (H["x-aspnet-version"]) add("ASP.NET", H["x-aspnet-version"], "Web frameworks");
  if (H["x-aspnetmvc-version"]) add("ASP.NET MVC", H["x-aspnetmvc-version"], "Web frameworks");
  if (H["x-generator"]) { const { name, version } = parseNameVer(H["x-generator"]); add(name, version, "Miscellaneous"); }
  if (H["x-drupal-cache"] || H["x-drupal-dynamic-cache"]) add("Drupal", "", "CMS");
  results.sort((a, b) => {
    const pa = Math.max(0, ...a.categories.map((c) => c.priority));
    const pb = Math.max(0, ...b.categories.map((c) => c.priority));
    return pb - pa || a.name.localeCompare(b.name);
  });
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
  const results = buildResults(detect(ds.compiled, signals, headers, jsValues, ds.byName), ds);
  enrichFromHeaders(results, headers, ds); // server name/version + powered-by fallback
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
  const { shodanKey = "", vtKey = "", mbKey = "" } = await chrome.storage.local.get(["shodanKey", "vtKey", "mbKey"]);
  return { shodanKey: shodanKey.trim(), vtKey: vtKey.trim(), mbKey: mbKey.trim() };
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

// Keyless IP geolocation (ipwho.is): coordinates + city/country + org/ISP/ASN.
async function ipGeo(ip) {
  try {
    const r = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (!r.ok) return null;
    const d = await r.json();
    if (d.success === false) return null;
    const c = d.connection || {};
    return {
      city: d.city || "", region: d.region || "", country: d.country || "", countryCode: d.country_code || "",
      lat: d.latitude, lon: d.longitude,
      org: c.org || c.isp || "", isp: c.isp || "", asn: c.asn ? "AS" + c.asn : "",
    };
  } catch { return null; }
}

// Pivot on a domain: find the IPs/servers associated with it. Keyless path
// resolves the domain + its subdomains + cert (SAN) names via DoH; with a key it
// also runs a Shodan host-search for authoritative org/port/product per IP.
async function relatedHosts(domain, dns, key) {
  const names = new Set([domain]);
  for (const s of (dns?.subdomains || [])) names.add(s.includes(".") ? s : s + "." + domain);
  for (const c of (dns?.certs || [])) for (const n of (c.names || [])) {
    const h = n.replace(/^\*\./, "");
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(h)) names.add(h.toLowerCase());
  }
  const list = [...names].filter((n) => !n.includes("*")).slice(0, 40);

  const ipMap = new Map(); // ip -> Set(hostnames)
  await Promise.all(list.map(async (n) => {
    for (const a of await doh(n, "A")) {
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(a.value)) continue;
      if (!ipMap.has(a.value)) ipMap.set(a.value, new Set());
      ipMap.get(a.value).add(n);
    }
  }));
  const byIp = new Map();
  for (const [ip, hs] of ipMap) byIp.set(ip, { ip, hostnames: [...hs].slice(0, 8), source: "dns" });

  if (key) {
    try {
      const r = await fetch(`https://api.shodan.io/shodan/host/search?key=${encodeURIComponent(key)}&query=${encodeURIComponent("hostname:" + domain)}&minify=true`);
      if (r.ok) {
        const d = await r.json();
        for (const m of (d.matches || []).slice(0, 60)) {
          const ip = m.ip_str; if (!ip) continue;
          const e = byIp.get(ip) || { ip, hostnames: [], source: "shodan" };
          if (e.source === "dns") e.source = "dns+shodan";
          e.org = m.org || e.org || "";
          if (m.port) e.port = m.port;
          if (m.product) e.product = m.product;
          if (m.hostnames) e.hostnames = [...new Set([...(e.hostnames || []), ...m.hostnames])].slice(0, 8);
          byIp.set(ip, e);
        }
      }
    } catch {}
  }
  return [...byIp.values()].slice(0, 80);
}

async function shodanHost(ip, key) {
  let r;
  try { r = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${encodeURIComponent(key)}`); }
  catch (e) { return { httpError: 0, message: String(e.message || e) }; }
  if (r.status === 401) return { error: "Invalid Shodan API key." };
  if (r.status === 404) return { notFound: true };
  if (!r.ok) return { httpError: r.status }; // 403 = needs paid Shodan membership
  const d = await r.json();
  return {
    source: "shodan", ip, org: d.org || "", isp: d.isp || "", asn: d.asn || "", os: d.os || "",
    city: d.city || "", country: d.country_name || "", lastUpdate: d.last_update || "",
    lat: typeof d.latitude === "number" ? d.latitude : null, lon: typeof d.longitude === "number" ? d.longitude : null,
    hostnames: d.hostnames || [], domains: d.domains || [], tags: d.tags || [],
    ports: (d.ports || []).sort((a, b) => a - b),
    vulns: Array.isArray(d.vulns) ? d.vulns : Object.keys(d.vulns || {}),
    services: parseServices(d.data),
  };
}

async function shodanLookup(target, fresh) {
  const host = (target || "").trim();
  if (!host) return { error: "No target host/IP." };
  const { shodanKey } = await getKeys();
  // Cache key includes key-state so adding/removing a key invalidates stale results.
  const ck = "sc:" + (shodanKey ? "k" : "n") + ":" + host.toLowerCase();
  if (!fresh) {
    const c = (await chrome.storage.session.get(ck))[ck];
    if (c && Date.now() - c.ts < 600000) return { ...c.data, cached: true }; // 10-min cache
  }
  const ip = await resolveIp(host, shodanKey);
  if (!ip) return { error: "Could not resolve to an IP." };

  let out;
  if (shodanKey) {
    const rec = await shodanHost(ip, shodanKey);
    if (rec.error) return rec; // invalid key → surface it
    if (rec.source === "shodan") {
      out = rec;
    } else {
      out = await internetDb(ip);
      out.note = rec.notFound
        ? "Shodan has no full host record for this IP — showing keyless InternetDB data."
        : `Your Shodan key worked, but the /shodan/host endpoint returned HTTP ${rec.httpError} — that endpoint needs a paid Shodan membership (a free API key can't use it). Showing keyless InternetDB data.`;
    }
  } else {
    out = await internetDb(ip);
  }
  out.query = host;

  // Enrich in parallel: IP RDAP + geolocation (always), plus domain DNS + RDAP.
  out.rdapIp = null; out.geo = null;
  const jobs = [
    rdapIp(ip).then((r) => { out.rdapIp = r; }),
    ipGeo(ip).then((g) => { out.geo = g; }),
  ];
  if (!isIp(host)) {
    jobs.push(domainLookup(host, shodanKey).then((r) => { out.dns = r; }));
    jobs.push(rdapDomain(host).then((r) => { out.rdap = r; }));
  }
  await Promise.all(jobs);

  // Backfill from geolocation / RDAP when the keyless host source lacked fields.
  const g = out.geo;
  if (g) {
    if (!out.city && g.city) out.city = g.city;
    if (!out.country && g.country) out.country = g.country;
    if (!out.org && g.org) out.org = g.org;
    if (!out.isp && g.isp) out.isp = g.isp;
    if (!out.asn && g.asn) out.asn = g.asn;
    if (out.lat == null && typeof g.lat === "number") { out.lat = g.lat; out.lon = g.lon; }
  }
  if (!out.org && out.rdapIp?.org) out.org = out.rdapIp.org;
  if (!out.country && out.rdapIp?.country) out.country = out.rdapIp.country;

  // Related hosts / servers connected to the domain.
  if (!isIp(host)) out.related = await relatedHosts(host, out.dns, shodanKey);

  try { await chrome.storage.session.set({ [ck]: { data: out, ts: Date.now() } }); } catch {}
  return out;
}

async function vtLookup(target, fresh) {
  const q = (target || "").trim();
  if (!q) return { error: "No target." };
  const { vtKey } = await getKeys();
  if (!vtKey) return { error: "No VirusTotal API key set (Settings tab)." };

  const ck = "vt:" + (vtKey ? "k" : "n") + ":" + q.toLowerCase();
  if (!fresh) {
    const c = (await chrome.storage.session.get(ck))[ck];
    if (c && Date.now() - c.ts < 600000) return { ...c.data, cached: true };
  }

  // Auto-detect the target type: file hash (MD5/SHA-1/SHA-256), IP, or domain.
  let kind, path;
  if (/^[a-f0-9]{64}$|^[a-f0-9]{40}$|^[a-f0-9]{32}$/i.test(q)) { kind = "file"; path = "files/" + q; }
  else if (isIp(q)) { kind = "ip"; path = "ip_addresses/" + q; }
  else { kind = "domain"; path = "domains/" + encodeURIComponent(q); }

  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/${path}`, { headers: { "x-apikey": vtKey } });
    if (r.status === 401) return { error: "Invalid VirusTotal API key." };
    if (r.status === 404) return { error: `Not found on VirusTotal (${kind}).` };
    if (r.status === 429) return { error: "VirusTotal rate limit reached (free tier = 4/min)." };
    if (!r.ok) throw new Error("HTTP " + r.status);
    const a = (await r.json()).data?.attributes || {};
    const out = { kind, query: q, reputation: a.reputation ?? 0, stats: a.last_analysis_stats || {} };
    if (kind === "domain") {
      out.categories = a.categories || {};
      out.registrar = a.registrar || "";
      out.created = a.creation_date ? new Date(a.creation_date * 1000).toISOString().slice(0, 10) : "";
    } else if (kind === "ip") {
      out.asOwner = a.as_owner || "";
      out.country = a.country || "";
      out.asn = a.asn ? "AS" + a.asn : "";
    } else {
      out.name = a.meaningful_name || (a.names && a.names[0]) || "";
      out.names = (a.names || []).slice(0, 8);
      out.typeDesc = a.type_description || "";
      out.size = a.size || 0;
      out.sha256 = a.sha256 || "";
      out.md5 = a.md5 || "";
      out.threatLabel = a.popular_threat_classification?.suggested_threat_label || "";
      out.firstSeen = a.first_submission_date ? new Date(a.first_submission_date * 1000).toISOString().slice(0, 10) : "";
    }
    try { await chrome.storage.session.set({ [ck]: { data: out, ts: Date.now() } }); } catch {}
    return out;
  } catch (e) { return { error: String(e.message || e) }; }
}

// Download a sample by hash (VirusTotal Premium/Enterprise keys only).
async function vtDownload(hash) {
  const { vtKey } = await getKeys();
  if (!vtKey) return { error: "No VirusTotal API key set." };
  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}/download_url`, { headers: { "x-apikey": vtKey } });
    if (r.status === 403) return { error: "File download requires a VirusTotal Premium/Enterprise API key — the free API can't download samples." };
    if (r.status === 404) return { error: "File not found on VirusTotal." };
    if (!r.ok) return { error: "HTTP " + r.status };
    const url = (await r.json()).data;
    if (!url) return { error: "No download URL returned." };
    const id = await chrome.downloads.download({ url, filename: `vt-sample-${hash}.bin`, saveAs: true });
    return { ok: true, id };
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

// ---- context menu: send a selected value to the side panel -----------------
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    // Selected text (hash / domain / IP)
    chrome.contextMenus.create({ id: "ts-vt", title: 'TechScope: Scan "%s" on VirusTotal', contexts: ["selection"] });
    chrome.contextMenus.create({ id: "ts-shodan", title: 'TechScope: Look up "%s" on Shodan', contexts: ["selection"] });
    // Links (uses the link's host/domain)
    chrome.contextMenus.create({ id: "ts-vt-link", title: "TechScope: Scan this link's domain on VirusTotal", contexts: ["link"] });
    chrome.contextMenus.create({ id: "ts-shodan-link", title: "TechScope: Look up this link's host on Shodan", contexts: ["link"] });
  });
});
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  let q = "";
  if (String(info.menuItemId).endsWith("-link")) {
    try { q = new URL(info.linkUrl).hostname.replace(/^www\./, ""); } catch {}
  } else {
    q = (info.selectionText || "").trim();
  }
  if (!q) return;
  const type = String(info.menuItemId).startsWith("ts-shodan") ? "shodan" : "vt";
  await chrome.storage.session.set({ pending: { type, query: q, ts: Date.now() } });
  try { await chrome.sidePanel.open({ windowId: tab.windowId }); } catch {}
});

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
      const { shodanKey, vtKey, mbKey } = await getKeys();
      sendResponse({ shodanSet: !!shodanKey, vtSet: !!vtKey, mbSet: !!mbKey }); // never echo the keys
    } else if (msg?.type === "setKeys") {
      const patch = {};
      if (typeof msg.shodanKey === "string") patch.shodanKey = msg.shodanKey.trim();
      if (typeof msg.vtKey === "string") patch.vtKey = msg.vtKey.trim();
      if (typeof msg.mbKey === "string") patch.mbKey = msg.mbKey.trim();
      await chrome.storage.local.set(patch);
      sendResponse({ ok: true });
    } else if (msg?.type === "shodan") {
      sendResponse(await shodanLookup(msg.host, msg.fresh));
    } else if (msg?.type === "vt") {
      sendResponse(await vtLookup(msg.target || msg.domain, msg.fresh));
    } else if (msg?.type === "vtDownload") {
      sendResponse(await vtDownload(msg.hash));
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
