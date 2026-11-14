/* engine.js — technology detection engine (Wappalyzer-style).
 * Pure functions (compile/detect/resolveVersion) are testable without a browser;
 * loadDataset() is the service-worker loader that fetches the bundled data.
 */

// ---- pattern parsing -------------------------------------------------------

// A Wappalyzer pattern is "regex\;version:\1\;confidence:50"; fields are joined
// by a literal backslash-semicolon.
export function parsePattern(pattern) {
  const parts = String(pattern).split("\\;");
  let version = "", confidence = 100;
  for (let i = 1; i < parts.length; i++) {
    const p = parts[i];
    if (p.startsWith("version:")) version = p.slice(8);
    else if (p.startsWith("confidence:")) confidence = parseInt(p.slice(11), 10) || 100;
  }
  // Regex is compiled lazily (see rxOf) so patterns whose signal is absent — the
  // vast majority of header/cookie/meta/js patterns — never cost a RegExp build.
  const src = parts[0];
  return { src, version, confidence, empty: src === "", _rx: undefined };
}

// Lazily compile (and memoize) a pattern's RegExp; null if it never compiles.
function rxOf(pat) {
  if (pat._rx !== undefined) return pat._rx;
  if (!pat.src) return (pat._rx = null);
  try { return (pat._rx = new RegExp(pat.src, "i")); }
  catch { try { return (pat._rx = new RegExp(pat.src.replace(/[^\x00-\x7F]/g, ""), "i")); } catch { return (pat._rx = null); } }
}

// Resolve "\1" / "\1?a:b" version templates against a regex match.
export function resolveVersion(tpl, m) {
  if (!tpl) return "";
  return tpl.replace(/\\(\d)(?:\?([^:]+):([^)]*))?/g, (_all, g, a, b) => {
    const val = (m && m[+g]) || "";
    if (a !== undefined) return val ? a : (b || "");
    return val;
  }).trim();
}

const toArr = (x) => (x == null ? [] : Array.isArray(x) ? x : [x]);

// ---- compilation -----------------------------------------------------------

function compilePair(obj) {
  const out = [];
  if (!obj) return out;
  for (const name of Object.keys(obj)) out.push({ name, pat: parsePattern(obj[name]) });
  return out;
}
function compileList(val) { return toArr(val).map(parsePattern); }

function compileDom(dom) {
  const sels = [];
  if (!dom) return sels;
  if (typeof dom === "string") sels.push({ selector: dom });
  else if (Array.isArray(dom)) dom.forEach((s) => { if (typeof s === "string") sels.push({ selector: s }); });
  else if (typeof dom === "object") for (const selector of Object.keys(dom)) sels.push({ selector });
  return sels;
}

export function compile(technologies) {
  const compiled = [];
  for (const name of Object.keys(technologies)) {
    const t = technologies[name] || {};
    compiled.push({
      name,
      cats: t.cats || [],
      website: t.website || "",
      icon: t.icon || "",
      implies: toArr(t.implies),
      excludes: toArr(t.excludes),
      headers: compilePair(t.headers),
      cookies: compilePair(t.cookies),
      meta: compilePair(t.meta),
      js: compilePair(t.js),
      html: compileList(t.html),
      scripts: compileList(t.scripts),
      scriptSrc: compileList(t.scriptSrc),
      url: compileList(t.url),
      dom: compileDom(t.dom),
    });
  }
  return compiled;
}

export function jsPathsOf(compiled) {
  const s = new Set();
  for (const t of compiled) for (const j of t.js) s.add(j.name);
  return [...s];
}
export function domSelectorsOf(compiled) {
  const s = new Set();
  for (const t of compiled) for (const d of t.dom) s.add(d.selector);
  return [...s];
}

// ---- detection -------------------------------------------------------------

function testValue(pat, value) {
  // returns {matched, version} or null
  if (value == null) return null;
  if (pat.empty) return { matched: true, version: "" };
  const rx = rxOf(pat);
  if (!rx) return null;
  const m = rx.exec(String(value));
  if (!m) return null;
  return { matched: true, version: resolveVersion(pat.version, m) };
}

export function detect(compiled, signals, headers, jsValues, byName) {
  const found = new Map(); // name -> { confidence, version }
  const lcHeaders = {};
  for (const k in (headers || {})) lcHeaders[k.toLowerCase()] = headers[k];

  const add = (name, confidence, version) => {
    const e = found.get(name) || { confidence: 0, version: "" };
    e.confidence = Math.min(100, e.confidence + (confidence || 100));
    if (version && !e.version) e.version = version;
    found.set(name, e);
  };

  for (const t of compiled) {
    const tryPairs = (pairs, lookup) => {
      for (const { name, pat } of pairs) {
        const r = testValue(pat, lookup(name));
        if (r) add(t.name, pat.confidence, r.version);
      }
    };
    const tryList = (list, values) => {
      for (const pat of list) for (const v of values) {
        const r = testValue(pat, v);
        if (r) { add(t.name, pat.confidence, r.version); break; }
      }
    };

    tryPairs(t.headers, (n) => lcHeaders[n.toLowerCase()]);
    tryPairs(t.cookies, (n) => (signals.cookies || {})[n]);
    tryPairs(t.meta, (n) => (signals.metas || {})[n.toLowerCase()]);
    tryPairs(t.js, (n) => (jsValues || {})[n]);
    tryList(t.html, [signals.html || ""]);
    tryList(t.scripts, [signals.scripts || ""]);
    tryList(t.scriptSrc, signals.scriptSrc || []);
    tryList(t.url, [signals.url || ""]);
    for (const d of t.dom) if ((signals.domMatches || {})[d.selector]) add(t.name, 100, "");
  }

  // implies (chained) + excludes — reuse the prebuilt index when provided.
  byName = byName || new Map(compiled.map((t) => [t.name, t]));
  let changed = true, guard = 0;
  while (changed && guard++ < 10) {
    changed = false;
    for (const name of [...found.keys()]) {
      const t = byName.get(name);
      if (!t) continue;
      for (const imp of t.implies) {
        const p = parsePattern(imp); // implies may carry \;confidence:
        const impName = String(imp).split("\\;")[0];
        if (!found.has(impName)) { add(impName, p.confidence, ""); changed = true; }
      }
    }
  }
  for (const name of [...found.keys()]) {
    const t = byName.get(name);
    if (!t) continue;
    for (const exc of t.excludes) found.delete(String(exc).split("\\;")[0]);
  }

  return found; // Map name -> {confidence, version}
}

// ---- service-worker dataset loader ----------------------------------------

let _cache = null;
export async function loadDataset() {
  if (_cache) return _cache;
  const get = async (f) => (await fetch(chrome.runtime.getURL("data/" + f))).json();
  const [technologies, categories, groups, meta] = await Promise.all(
    ["technologies.json", "categories.json", "groups.json", "meta.json"].map(get)
  );
  const compiled = compile(technologies);
  _cache = {
    compiled, categories, groups, meta,
    jsPaths: jsPathsOf(compiled),
    domSelectors: domSelectorsOf(compiled),
    byName: new Map(compiled.map((t) => [t.name, t])),
  };
  return _cache;
}
export function clearCache() { _cache = null; }
