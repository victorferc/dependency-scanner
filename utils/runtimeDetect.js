// utils/runtimeDetect.js
import puppeteer from "puppeteer";

export async function runtimeDetect(url) {
  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });
  const page = await browser.newPage();

  // Block heavy resources
  await page.setRequestInterception(true);
  page.on("request", (req) => {
    const type = req.resourceType();
    if (["image","media","font","stylesheet"].includes(type)) return req.abort();
    // optional: block obvious ad domains
    if (/doubleclick|googletag|adservice|adnxs|criteo/i.test(req.url())) return req.abort();
    req.continue();
  });

  await page.setUserAgent(
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36"
  );
  page.setDefaultNavigationTimeout(15000); // 15s nav timeout

  try {
    // Faster: we only need the DOM and initial scripts
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
  } catch (_) {}

  // Small idle window
  try { await page.waitForTimeout(1200); } catch {}

  const runtimeMap = await page.evaluate(() => {
    const attr = (sel, a) => document.querySelector(sel)?.getAttribute(a) || null;
    const out = {};
    if (window.jQuery?.fn?.jquery) out.jquery = window.jQuery.fn.jquery;
    if (window.angular?.version?.full) out.angularjs = window.angular.version.full;
    const ng = attr("[ng-version]", "ng-version"); if (ng) out.angular = ng;
    if (window.React?.version) out.react = window.React.version;
    if (window.preact?.version) out.preact = window.preact.version;
    if (window.Vue?.version) out.vue = window.Vue.version;
    if (window.Ember?.VERSION) out.ember = window.Ember.VERSION;
    return out;
  }).catch(() => ({}));

  const jsUrls = await page.evaluate(() =>
    Array.from(new Set(
      performance.getEntriesByType("resource")
        .filter(e => e.initiatorType === "script" || /\.js(\?|$)/i.test(e.name))
        .map(e => e.name)
    ))
  ).catch(() => []);

  await browser.close();

  const libs = Object.entries(runtimeMap).map(([name, version]) => ({
    name, version: String(version), source: "runtime",
  }));
  return { libs, jsUrls };
}
