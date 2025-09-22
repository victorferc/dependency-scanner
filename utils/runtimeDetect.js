import puppeteer from "puppeteer";

/**
 * Launches a headless browser, loads the URL, and inspects runtime globals/DOM
 * to infer framework/library versions that don't appear in script URLs.
 */
export async function runtimeDetect(url) {
  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--disable-setuid-sandbox"], // helpful on Kali/CI
  });

  const page = await browser.newPage();
  // Don't wait forever on slow sites
  await page.goto(url, { waitUntil: "networkidle2", timeout: 30000 }).catch(() => {});

  // Evaluate in the page context
  const result = await page.evaluate(() => {
    // Helper to read attr safely
    const q = (sel, attr) => document.querySelector(sel)?.getAttribute(attr) || null;

    const out = {};

    // jQuery (classic)
    if (window.jQuery?.fn?.jquery) out.jquery = window.jQuery.fn.jquery;

    // AngularJS (1.x)
    if (window.angular?.version?.full) out["angularjs"] = window.angular.version.full;

    // Angular (2+): Angular sets ng-version on root elements
    const ngVer = q("[ng-version]", "ng-version");
    if (ngVer) out["angular"] = ngVer;

    // React: global React is rare when bundled; try a few hints
    if (window.React?.version) out["react"] = window.React.version;
    // Some builds expose preact instead
    if (window.preact?.version) out["preact"] = window.preact.version;

    // Vue
    if (window.Vue?.version) out["vue"] = window.Vue.version;

    // Ember
    if (window.Ember?.VERSION) out["ember"] = window.Ember.VERSION;

    // Svelte doesn’t expose a global; ignore for now.

    // Bootstrap 5 exposes global "bootstrap" (no version), skip.
    // You can optionally glean versions by scanning script text in a later pass.

    return out;
  }).catch(() => ({}));

  await browser.close();

  // Normalize to your library shape
  const libs = Object.entries(result).map(([name, version]) => ({
    name,
    version: String(version),
    source: "runtime",
  }));

  return libs;
}
