// scanner.js
import fetch from "node-fetch";
import * as cheerio from "cheerio";
import tls from "tls";
import url from "url";

import { determineIfLatestVersion } from "./utils/versionCheck.js";
import { determineVulnerabilities } from "./utils/vulnCheck.js";

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

// --- 4. Run scan ---
async function scan(targetUrl) {
    console.log(`Scanning: ${targetUrl}`);
    const { headers, scripts } = await fetchPage(targetUrl);
    const libs = detectLibraries(scripts);
    const tlsExpiry = await getTlsExpiry(targetUrl);

    // enrich libraries with latest + vuln info (in parallel)
    const enrichedLibs = await Promise.all(libs.map(async (lib) => {
        let latest = null, outdated = null, diff = "unknown", vulnCount = null, vulns = [];
        try {
            const ver = await determineIfLatestVersion(lib.name, lib.version);
            latest = ver.latest;
            outdated = ver.isOutdated;
            diff = ver.diff;
        } catch (_) { }

        try {
            const v = await determineVulnerabilities(lib.name, lib.version);
            vulnCount = v.vulnCount;
            // keep it tight: id + short summary
            vulns = v.vulns.map(x => ({ id: x.id, severity: x.severity, summary: x.summary })).slice(0, 5);
        } catch (_) { }

        return { ...lib, latest, outdated, diff, vulnCount, vulns };
    }));

    const report = {
        url: targetUrl,
        headers: {
            "Strict-Transport-Security": headers["strict-transport-security"] || "missing",
            "Content-Security-Policy": headers["content-security-policy"] || "missing",
            "X-Frame-Options": headers["x-frame-options"] || "missing",
        },
        libraries: enrichedLibs,
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
