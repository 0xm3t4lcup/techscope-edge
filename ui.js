/* ui.js — shared render helpers used by both the popup and the side panel. */

export const palette = [
  "#4254f5", "#2e9e6b", "#c77800", "#c0392b", "#8e44ad",
  "#1f9bb3", "#d6336c", "#5c7cfa", "#637a2a", "#a6611a",
];
export const colorFor = (s) => palette[[...String(s)].reduce((a, c) => a + c.charCodeAt(0), 0) % palette.length];
export const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

export function renderTech(box, results, filter = "") {
  const f = filter.trim().toLowerCase();
  let items = results;
  if (f) items = items.filter((r) =>
    r.name.toLowerCase().includes(f) || r.categories.some((c) => c.name.toLowerCase().includes(f)));
  if (!items.length) {
    box.innerHTML = `<div class="empty">${results.length ? "No match." : "No technologies detected."}</div>`;
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

export function renderSecurity(box, security) {
  if (!security) { box.innerHTML = `<div class="empty">No header data (reload the page).</div>`; return; }
  let html = `<div class="grade">
    <div class="letter g-${security.grade}">${security.grade}</div>
    <div class="meta">${security.score} of ${security.total} security headers present</div>
  </div>`;
  for (const c of security.checks) {
    html += `<div class="sec-row">
      <span class="mark ${c.present ? "ok" : "no"}">${c.present ? "✓" : "✗"}</span>
      <div><div class="lbl">${esc(c.label)}</div>${c.present && c.value ? `<div class="val">${esc(c.value.slice(0, 160))}</div>` : ""}</div>
    </div>`;
  }
  box.innerHTML = html;
}

export function copyText(current) {
  let host; try { host = new URL(current.url).hostname; } catch { host = "page"; }
  const lines = [`# Tech stack — ${host}`];
  for (const r of current.results) lines.push(`- ${r.name}${r.version ? " " + r.version : ""} (${r.categories.map((c) => c.name).join(", ")})`);
  if (current.security) lines.push(`\nSecurity headers: ${current.security.grade} (${current.security.score}/${current.security.total})`);
  return lines.join("\n");
}

export function hostOf(url) { try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return ""; } }
