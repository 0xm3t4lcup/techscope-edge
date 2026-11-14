/* popup.js — asks the service worker to analyze the active tab, renders the
 * detected stack grouped by category, with filter / rescan / export.
 */
const $ = (id) => document.getElementById(id);
let current = { url: "", results: [] };

const palette = [
  "#4254f5", "#2e9e6b", "#c77800", "#c0392b", "#8e44ad",
  "#1f9bb3", "#d6336c", "#5c7cfa", "#637a2a", "#a6611a",
];
const colorFor = (s) => palette[[...s].reduce((a, c) => a + c.charCodeAt(0), 0) % palette.length];

function render(filter = "") {
  const box = $("results");
  const f = filter.trim().toLowerCase();
  let items = current.results;
  if (f) items = items.filter((r) =>
    r.name.toLowerCase().includes(f) || r.categories.some((c) => c.name.toLowerCase().includes(f)));

  if (!items.length) {
    box.innerHTML = `<div class="empty">${current.results.length ? "No match." : "No technologies detected on this page."}</div>`;
    return;
  }

  // group by top (highest-priority) category
  const groups = new Map();
  for (const r of items) {
    const cat = r.categories.slice().sort((a, b) => b.priority - a.priority)[0] || { name: "Other" };
    if (!groups.has(cat.name)) groups.set(cat.name, []);
    groups.get(cat.name).push(r);
  }

  const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  let html = "";
  for (const [catName, techs] of groups) {
    html += `<div class="cat-head">${esc(catName)}</div>`;
    for (const t of techs) {
      const ver = t.version ? `<span class="ver">${esc(t.version)}</span>` : "";
      const conf = t.confidence < 100 ? `<span class="conf">${t.confidence}%</span>` : "";
      const href = t.website ? ` href="${esc(t.website)}" target="_blank" rel="noopener"` : "";
      const tag = t.website ? "a" : "div";
      html += `<${tag} class="tech"${href}>
        <span class="dot" style="background:${colorFor(t.name)}"></span>
        <span class="name">${esc(t.name)}</span>${ver}${conf}
      </${tag}>`;
    }
  }
  box.innerHTML = html;
}

async function load(force = false) {
  $("results").innerHTML = `<div class="empty">Scanning…</div>`;
  const resp = await chrome.runtime.sendMessage({ type: "analyze", force }).catch(() => null);
  current = resp || { url: "", results: [] };
  try { $("host").textContent = new URL(current.url).hostname.replace(/^www\./, ""); } catch { $("host").textContent = "—"; }
  $("count").textContent = current.results.length;
  render($("search").value);
}

$("search").addEventListener("input", (e) => render(e.target.value));
$("rescanBtn").addEventListener("click", () => load(true));
$("exportBtn").addEventListener("click", () => {
  const data = JSON.stringify({ url: current.url, detected: current.results, exported: new Date().toISOString() }, null, 2);
  const url = URL.createObjectURL(new Blob([data], { type: "application/json" }));
  const host = (() => { try { return new URL(current.url).hostname; } catch { return "page"; } })();
  const a = document.createElement("a");
  a.href = url; a.download = `techscope-${host}.json`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

chrome.runtime.sendMessage({ type: "meta" }).then((r) => {
  if (r?.meta) $("dbinfo").textContent = `${r.meta.techCount} techs`;
}).catch(() => {});

load();
