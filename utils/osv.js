// utils/osv.js
import { exec as _exec } from "child_process";
import { promisify } from "util";
const exec = promisify(_exec);

// pick highest CVSS v3/v4 score if present
function highestCvss(severity = []) {
  let best = null;
  for (const s of severity) {
    if ((s.type === "CVSS_V3" || s.type === "CVSS_V4") && s.score) {
      const score = parseFloat(String(s.score).split("/").pop() || s.score);
      if (!isNaN(score)) {
        if (!best || score > best.score) best = { type: s.type, score };
      }
    }
  }
  return best; // { type, score } or null
}

/**
 * Query OSV for vulns affecting a specific npm package@version
 * returns: { vulns: [{ id, summary, severity, affected }, ...] }
 */
export async function queryOsvNpmVulns(pkgName, version) {
  const body = JSON.stringify({
    package: { ecosystem: "npm", name: String(pkgName) },
    version: String(version),
  });

  const cmd = `curl -sL -H "Content-Type: application/json" -X POST https://api.osv.dev/v1/query -d '${body.replace(/'/g, "'\\''")}'`;
  const { stdout } = await exec(cmd);

  let data;
  try { data = JSON.parse(stdout); } catch { data = { vulns: [] }; }

  const results = (data.vulns || []).map(v => {
    const cvss = highestCvss(v.severity);
    return {
      id: v.id,                               // e.g., CVE-2020-11022 or GHSA-...
      summary: v.summary || v.details || "",
      severity: cvss ? `${cvss.type}:${cvss.score}` : (v.severity?.[0]?.type || "UNKNOWN"),
      affected: v.affected?.map(a => a.package?.name).filter(Boolean) || []
    };
  });

  return { vulns: results };
}
