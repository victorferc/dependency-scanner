// utils/versionCheck.js
import { exec as _exec } from "child_process";
import { promisify } from "util";
const exec = promisify(_exec);

// Coerce things like "3.5.1." -> "3.5.1"
function coerceSemver(v) {
  if (!v) return "0.0.0";
  const match = String(v).match(/\d+(?:\.\d+){0,3}/);
  return match ? match[0] : "0.0.0";
}

function parseSemver(v) {
  const [maj = "0", min = "0", pat = "0"] = coerceSemver(v).split(".");
  return [Number(maj), Number(min), Number(pat)];
}

function compareSemver(a, b) {
  const [A, B] = [parseSemver(a), parseSemver(b)];
  for (let i = 0; i < 3; i++) {
    if (A[i] > B[i]) return 1;
    if (A[i] < B[i]) return -1;
  }
  return 0;
}

function diffType(scanned, latest) {
  const [sMaj, sMin, sPat] = parseSemver(scanned);
  const [lMaj, lMin, lPat] = parseSemver(latest);
  if (lMaj > sMaj) return "major";
  if (lMaj === sMaj && lMin > sMin) return "minor";
  if (lMaj === sMaj && lMin === sMin && lPat > sPat) return "patch";
  return "none";
}

/**
 * determineIfLatestVersion("jquery", "3.5.1")
 * -> { name, scannedVersion, latest, isLatest, isOutdated, diff }
 */
export async function determineIfLatestVersion(depName, scannedVersion) {
  const pkg = String(depName).toLowerCase().trim();

  // Use curl as requested
  const url = `https://registry.npmjs.org/${pkg}/latest`;
  const { stdout } = await exec(`curl -sL ${url}`);
  let latest = "0.0.0";
  try {
    const meta = JSON.parse(stdout);
    latest = meta.version || meta?.["dist-tags"]?.latest || latest;
  } catch {
    // keep default latest if JSON parse fails
  }

  const scanned = coerceSemver(scannedVersion);
  const cmp = compareSemver(scanned, latest);

  return {
    name: depName,
    scannedVersion: scanned,
    latest,
    isLatest: cmp === 0,
    isOutdated: cmp < 0,
    diff: cmp < 0 ? diffType(scanned, latest) : "none",
  };
}
