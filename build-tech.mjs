#!/usr/bin/env node
/*
 * build-tech.mjs — download the open Wappalyzer-style fingerprint dataset
 * (enthec/webappanalyzer, MIT) and merge it into data files the extension loads.
 *
 *   node build-tech.mjs --fetch
 *
 * Output:
 *   data/technologies.json   { "<name>": { cats, website, icon, headers, ... } }
 *   data/categories.json     { "<id>": { name, groups, priority } }
 *   data/groups.json         { "<id>": { name } }
 *   data/meta.json           { version, built, techCount }
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const OUT = join(ROOT, "data");
mkdirSync(OUT, { recursive: true });

const BASE = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/";

if (!process.argv.includes("--fetch")) {
  console.warn("! run with --fetch to download the fingerprint dataset");
  process.exit(0);
}

async function getJson(path) {
  process.stdout.write(`  ${path} ... `);
  for (let a = 1; a <= 3; a++) {
    try {
      const r = await fetch(BASE + path, { redirect: "follow" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = JSON.parse(await r.text());
      console.log("ok");
      return j;
    } catch (e) {
      if (a === 3) { console.log(`FAILED (${e.message})`); return null; }
    }
  }
}

const categories = (await getJson("categories.json")) || {};
const groups = (await getJson("groups.json")) || {};

const letters = ["_", ..."abcdefghijklmnopqrstuvwxyz".split("")];
const technologies = {};
for (const l of letters) {
  const chunk = await getJson(`technologies/${l}.json`);
  if (chunk) Object.assign(technologies, chunk);
}

writeFileSync(join(OUT, "categories.json"), JSON.stringify(categories));
writeFileSync(join(OUT, "groups.json"), JSON.stringify(groups));
writeFileSync(join(OUT, "technologies.json"), JSON.stringify(technologies));
writeFileSync(join(OUT, "meta.json"), JSON.stringify({
  built: new Date().toISOString(),
  techCount: Object.keys(technologies).length,
  categoryCount: Object.keys(categories).length,
}));
// Version stamp: the service worker watches this and reloads the extension when
// the scheduled task refreshes the dataset.
writeFileSync(join(ROOT, "build-version.txt"), String(Date.now()) + "\n");

console.log(`\n✓ ${Object.keys(technologies).length} technologies, ${Object.keys(categories).length} categories, ${Object.keys(groups).length} groups`);
console.log("done.");
