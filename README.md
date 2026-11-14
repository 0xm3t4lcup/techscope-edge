# TechScope — website technology profiler (Edge, MV3)

Detects the technologies a website is built with — CMS, JS frameworks, analytics,
web servers, CDNs, ecommerce, programming languages, and more — the same way
Wappalyzer does, entirely **client-side**.

## How it works (the Wappalyzer method)

Each technology has a **fingerprint** (patterns against headers, cookies, meta
tags, HTML, script URLs, inline scripts, JS globals, DOM, and URL). On each page
TechScope gathers those signals and matches them against **7,699 technologies**
across **109 categories**, with **version extraction**, **confidence scores**, and
`implies` chains (e.g. WordPress ⇒ PHP ⇒ MySQL).

| Signal | Source | Example |
|--------|--------|---------|
| Response headers | `webRequest` on the main document | `Server: cloudflare` ⇒ Cloudflare |
| Meta tags | injected DOM collector | `<meta name=generator content="WordPress 6.4">` |
| Script URLs | injected DOM collector | `jquery-3.6.0.min.js` ⇒ jQuery 3.6.0 |
| Inline scripts / HTML | injected DOM collector | markup/code patterns |
| Cookies | injected DOM collector | `XSRF-TOKEN` ⇒ Laravel/Angular |
| JS globals | injected **MAIN-world** probe | `window.React` ⇒ React |
| DOM | injected DOM collector | selector presence |

### About "Pro" features
Wappalyzer's paid tier is mostly its **backend** (company/contact enrichment, lead
lists, bulk lookups) which requires their servers and cannot be replicated locally.
Every **client-side** capability is here: full detection + versions + confidence,
all categories, per-site history, filtering, and JSON export.

## Files

| File | Purpose |
|------|---------|
| `manifest.json` | MV3 config (scripting, webRequest, storage, webNavigation) |
| `build-tech.mjs` | Downloads + merges the fingerprint dataset into `data/` |
| `data/*.json` | `technologies`, `categories`, `groups`, `meta` (generated) |
| `engine.js` | Pattern parsing, compilation, and detection (pure + SW loader) |
| `background.js` | Header capture, injects collectors, runs engine, badge + history |
| `popup/` | UI: grouped results, filter, rescan, export |

## Install

> **Fresh clone?** The fingerprint dataset isn't committed (it's fetched from
> upstream). Run `node build-tech.mjs --fetch` once before loading the extension.

1. `node build-tech.mjs --fetch`  (populates `data/`)
2. Open `edge://extensions` → **Developer mode** on → **Load unpacked**
3. Select `C:\Users\ShivamUpadhyay\Tools\TechScope`
4. Visit any site and click the TechScope icon. The toolbar badge shows how many
   technologies were detected; the popup lists them by category.

## Updating the fingerprints

```powershell
node build-tech.mjs --fetch
```
Then reload the extension in `edge://extensions`.

## Data source & license
Fingerprints: [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer)
(MIT) — the maintained open fork of Wappalyzer's technology dataset.
