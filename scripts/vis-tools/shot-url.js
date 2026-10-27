const { chromium } = require('playwright-core');
(async () => {
  const [url, out] = process.argv.slice(2);
  const browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
  const ctx = browser.contexts()[0];
  const page = await ctx.newPage();
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(2500);
  await page.setViewportSize({ width: 1536, height: 864 });
  await page.screenshot({ path: out });
  console.log('shot ok', page.url());
  await page.close();
  await browser.close();
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
