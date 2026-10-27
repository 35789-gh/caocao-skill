const { chromium } = require('playwright-core');
(async () => {
  const [ph, val, out] = process.argv.slice(2);
  const browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
  const ctx = browser.contexts()[0];
  const page = ctx.pages().find(p => p.url().includes('5173'));
  const inp = page.locator(`input[placeholder*="${ph}"]`).first();
  await inp.fill(val);
  await page.waitForTimeout(300);
  await page.locator('button:has-text("搜索")').first().click();
  await page.waitForTimeout(1500);
  await page.screenshot({ path: out });
  console.log('shot ok', page.url());
  await browser.close();
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
