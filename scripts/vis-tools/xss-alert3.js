// XSS 弹窗截图 rev3：不 dismiss 弹窗（dismiss 会立即关掉），goto 前先挂 dialog 只记录不处理；等待渲染后截图再关闭
const { chromium } = require('playwright-core');
(async () => {
  const url = process.argv[2], out = process.argv[3];
  const browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
  const ctx = browser.contexts()[0];
  const page = await ctx.newPage();
  await page.setViewportSize({ width: 1536, height: 864 });
  let msg = null;
  page.on('dialog', d => { msg = d.message(); /* 不处理，让弹窗留在画面上 */ });
  await page.goto(url, { waitUntil: 'commit' });
  await page.waitForTimeout(3000);  // alert 停在画面
  await page.screenshot({ path: out });
  console.log('shot ok | dialog msg:', msg);
  await page.close();  // 关页顺带清弹窗
  await browser.close();
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
