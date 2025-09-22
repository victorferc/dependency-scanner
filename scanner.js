// scanner.js
import fetch from "node-fetch";
import * as cheerio from "cheerio";
import tls from "tls";
import url from "url";

import { determineIfLatestVersion } from "./utils/versionCheck.js";
import { determineVulnerabilities } from "./utils/vulnCheck.js";
import { runtimeDetect } from "./utils/runtimeDetect.js";

// Map detected names -> real npm package names for registry/OSV lookups
const npmNameMap = {
    jquery: "jquery",
    // Angular (v2+): the public “name” is “angular” but npm package is @angular/core
    angular: "@angular/core",
    angularjs: "angular",         // AngularJS 1.x is the "angular" npm package
    react: "react",
    "react-dom": "react-dom",
    vue: "vue",
    lodash: "lodash",
    "chart.js": "chart.js",
    bootstrap: "bootstrap",
  };
  const toNpm = (n) => npmNameMap[n.toLowerCase()] ?? n.toLowerCase();
  
  async function enrichLib(lib) {
    const pkg = toNpm(lib.name);
    let latest = null, outdated = null, diff = "unknown";
    let vulnCount = null, vulns = [];
  
    try {
      const r = await determineIfLatestVersion(pkg, lib.version);
      latest = r.latest;
      outdated = r.isOutdated;
      diff = r.diff;
    } catch (e) {
      // ignore; keep fields null/unknown
    }
  
    try {
      const v = await determineVulnerabilities(pkg, lib.version);
      vulnCount = v.vulnCount;
      vulns = (v.vulns || []).slice(0, 5).map(x => ({ id: x.id, severity: x.severity, summary: x.summary }));
    } catch (e) {}
  
    return { ...lib, npm: pkg, latest, outdated, diff, vulnCount, vulns };
  }

// --- 1. Fetch page and extract headers + scripts ---
async function fetchPage(targetUrl) {
    const res = await fetch(targetUrl, { redirect: "follow" });
    const html = await res.text();
    const headers = Object.fromEntries(res.headers);

    // Parse HTML
    const $ = cheerio.load(html);
    const scripts = [];
    $("script[src]").each((i, element) => {
        scripts.push($(element).attr("src"));
    });

    return { headers, scripts };
}

function detectLibraries(scripts) {
    const knownLibNames = [
        "jquery",
        "react",
        "react-dom",
        "vue",
        "angular",
        "ember",
        "bootstrap",
        "foundation",
        "uikit",
        "bulma",
        "lodash",
        "underscore",
        "moment",
        "dayjs",
        "rxjs",
        "d3",
        "chart.js",
        "highcharts",
        "three.js",
        "leaflet",
        "axios"
    ];

    // Escape regex metacharacters (., +, *, ?, etc.)
    const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    const libs = [];

    for (const script of scripts) {
        for (const lib of knownLibNames) {
            const safeName = escapeRegex(lib);
            const regex = new RegExp(`${safeName}[-.]?(\\d+(?:\\.\\d+)+)`, "i");

            if (regex.test(script)) {
                const match = script.match(regex);
                libs.push({
                    name: lib.charAt(0).toUpperCase() + lib.slice(1),
                    version: match ? match[1] : "unknown",
                    source: script
                });
            }
        }
    }

    return libs;
}


// --- 3. TLS expiry check ---
function getTlsExpiry(targetUrl) {
    return new Promise((resolve, reject) => {
        const { hostname } = new URL(targetUrl);
        const socket = tls.connect(443, hostname, { servername: hostname }, () => {
            const cert = socket.getPeerCertificate();
            socket.end();
            if (!cert || !cert.valid_to) return resolve(null);
            const expiry = new Date(cert.valid_to);
            const daysLeft = Math.round((expiry - Date.now()) / (1000 * 60 * 60 * 24));
            resolve({ validTo: expiry, daysLeft });
        });
        socket.on("error", reject);
    });
}

function dedupeLibs(libs) {
    // prefer versions over "unknown", and prefer runtime over URL match
    const key = (n) => n.name.toLowerCase();
    const map = new Map();
    for (const lib of libs) {
        const k = key(lib);
        const existing = map.get(k);
        if (!existing) { map.set(k, lib); continue; }

        const haveVer = (x) => x.version && x.version !== "unknown";
        // Prefer a lib that has a version
        if (!haveVer(existing) && haveVer(lib)) { map.set(k, lib); continue; }
        // Prefer runtime over static if both have versions
        if (existing.source !== "runtime" && lib.source === "runtime") { map.set(k, lib); continue; }
    }
    return Array.from(map.values());
}

async function scan(targetUrl) {
    console.log(`Scanning: ${targetUrl}`);

    const { headers, scripts } = await fetchPage(targetUrl);
    const staticLibs = detectLibraries(scripts);              // URL-based
    const runtimeLibs = await runtimeDetect(targetUrl);       // Puppeteer-based

    const libs = dedupeLibs([...staticLibs, ...runtimeLibs]); // merge

    const tlsExpiry = await getTlsExpiry(targetUrl);

    // (Optionally enrich each lib with latest/outdated + OSV here, like before)
    const enrichedLibs = await Promise.all(libs.map(enrichLib));

    const report = {
        url: targetUrl,
        headers: {
            "Strict-Transport-Security": headers["strict-transport-security"] || "missing",
            "Content-Security-Policy": headers["content-security-policy"] || "missing",
            "X-Frame-Options": headers["x-frame-options"] || "missing",
        },
        libraries: enrichedLibs, // libs or enrichedLibs
        tls: tlsExpiry,
    };

    console.log(JSON.stringify(report, null, 2));
}
// --- 5. CLI entry ---
const target = process.argv[2];
if (!target) {
    console.error("Usage: node scanner.js <url>");
    process.exit(1);
}
scan(target);
