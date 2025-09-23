export async function collectJsResourceUrls(page) {
    // Works without hooking CDP: uses Performance API
    const entries = await page.evaluate(() =>
      performance.getEntriesByType('resource')
        .filter(e => e.initiatorType === 'script' || e.name.endsWith('.js'))
        .map(e => e.name)
    );
    // De-dup & return
    return Array.from(new Set(entries));
  }
  