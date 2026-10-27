// shot-page.js — headless Chrome 视口截图（单帧版 record-page，双会话并行分家用）
// 独立 headless 进程，不占屏幕、不抢 Zcode 内置浏览器、无需锁；视口固定最大 1536x864
// 用法: node shot-page.js <url> <out.png> [waitMs] [--full]
//   --full 可选整页截图（默认视口帧）
// 依赖: playwright-core + 系统 Chrome（channel:'chrome'，无需 PLAYWRIGHT_BROWSERS_PATH/ffmpeg）
const { chromium } = require('playwright-core');

(async () => {
  const args = process.argv.slice(2).filter(a => a !== '--full');
  const full = process.argv.includes('--full');
  const [url, out, waitMs] = args;
  if (!url || !out) { console.error('usage: node shot-page.js <url> <out.png> [waitMs] [--full]'); process.exit(2); }
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1536, height: 864 } });
  await page.goto(url, { waitUntil: 'commit', timeout: 25000 }).catch(e => console.log('goto warn:', e.message.slice(0, 60)));
  await page.waitForTimeout(parseInt(waitMs || '2000'));
  await page.screenshot({ path: out, fullPage: full });
  console.log('shot saved:', out);
  await browser.close();
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
