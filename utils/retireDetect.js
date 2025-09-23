// utils/retireDetect.js
import fetch from "node-fetch";
import repo from "./retire-js-repo.json" assert { type: "json" };

// ---- Tunables ----
const MAX_BYTES = 1.5 * 1024 * 1024;   // cap per file (1.5 MB)
const REQ_TIMEOUT_MS = 7000;           // 7s per file
const MAX_FILES = 6;                   // scan at most N files per page

// Build compact detector list from Retire.js repo
const DETECTORS = Object.entries(repo).map(([libName, spec]) => ({
  libName,
  files: (spec?.js?.file || []).map((p) => new RegExp(p, "i")),
  contents: (spec?.js?.content || []).map((p) => new RegExp(p, "i")),
  vulns: spec?.vulnerabilities || []
}));

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms)),
  ]);
}

// Fetch text (bounded by size + time)
async function fetchText(url) {
  const res = await withTimeout(fetch(url, { redirect: "follow" }), REQ_TIMEOUT_MS);
  if (!res.ok) throw new Error(`fetch ${url} -> ${res.status}`);
  const buf = await res.arrayBuffer();
  const slice = buf.byteLength > MAX_BYTES ? buf.slice(0, MAX_BYTES) : buf;
  return new TextDecoder("utf-8").decode(slice);
}

// Try to extract a version from filename/url using any matching regex’ capture groups
function extractVersionFromUrl(u, regexList) {
  for (const rx of regexList) {
    const m = u.match(rx);
    if (m && m.length > 1) {
      // find last captured group that looks like x.y or x.y.z
      const g = [...m].reverse().find(s => /\d+(?:\.\d+){1,3}/.test(String(s)));
      if (g) return String(g).match(/\d+(?:\.\d+){1,3}/)[0];
    }
  }
  return null;
}

/**
 * Run Retire.js filename + (optionally) content detection against a set of candidate JS URLs.
 * @param {string[]} urls  Candidate script URLs (e.g., <script src> + Performance entries)
 * @param {{fetchContent?: boolean}} opts  When true, download up to MAX_FILES and run content regex
 * @returns {Promise<Array<{name, version, source, url, retireVulns}>>}
 */
export async function detectWithRetire(urls, opts = { fetchContent: true }) {
  try {
    // 1) Filter to JS files and pick a few likely bundles
    const candidates = Array.from(new Set(urls || []))
      .filter(u => /\.js(\?|$)/i.test(u))
      .filter(u => /(main|vendor|bundle|app|runtime|polyfills|chunk|client)/i.test(u) || u.length < 200)
      .slice(0, MAX_FILES);

    const hits = [];

    // 2) For each candidate, check filename patterns first, then (optionally) content
    for (const u of candidates) {
      for (const det of DETECTORS) {
        const fileHit = det.files.some(rx => rx.test(u));
        let version = fileHit ? extractVersionFromUrl(u, det.files) : null;

        let contentHit = false;
        if (!version && opts.fetchContent) {
          try {
            const text = await fetchText(u);
            // If any content regex matches, it's a hit; try to pull version from capture groups
            for (const rx of det.contents) {
              const m = text.match(rx);
              if (m) {
                contentHit = true;
                if (!version && m.length > 1) {
                  const g = [...m].reverse().find(s => /\d+(?:\.\d+){1,3}/.test(String(s)));
                  if (g) version = String(g).match(/\d+(?:\.\d+){1,3}/)[0];
                }
                if (version) break;
              }
            }
          } catch (_) {
            // ignore per-file fetch/timeout errors
          }
        }

        if (fileHit || contentHit) {
          hits.push({
            name: det.libName,
            version: version || "unknown",
            source: fileHit ? "retire-url" : "retire-content",
            url: u,
            retireVulns: det.vulns.map(v => ({
              identifiers: v?.identifiers,   // may contain CVE/GHSA ids
              info: v?.info,                  // advisory links
              below: v?.below,                // vulnerable if detectedVersion < below
              atOrAbove: v?.atOrAbove,        // lower bound when present
              severity: v?.severity || null
            }))
          });
        }
      }
    }

    // 3) Deduplicate by (name, version), prefer entries with a known version
    const map = new Map();
    for (const r of hits) {
      const k = `${r.name}::${r.version}`;
      if (!map.has(k)) map.set(k, r);
      else if (map.get(k).version === "unknown" && r.version !== "unknown") map.set(k, r);
    }
    return Array.from(map.values());
  } catch {
    return []; // NEVER return undefined
  }
}
