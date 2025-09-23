import { queryOsvNpmVulns } from "./osv.js";// utils/vulnCheck.js

/**
 * determineVulnerabilities("jquery", "3.5.1")
 * -> { name, version, vulnCount, vulns: [{id, summary, severity}] }
 */
export async function determineVulnerabilities(depName, scannedVersion) {
  const npmName = String(depName).toLowerCase().trim();
  const { vulns } = await queryOsvNpmVulns(npmName, scannedVersion);
  return {
    name: depName,
    version: scannedVersion,
    vulnCount: vulns.length,
    vulns: vulns.slice(0, 5), // trim output for now
  };
}
