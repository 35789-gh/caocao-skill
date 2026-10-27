// record-page.js — 内嵌形态录屏（㊷）：headless Chrome recordVideo 录页面视频
// 不占屏幕、不抢 CDP 9222、无需 shotlock——双会话并行时的优先录屏形态
// 用法（必须先设 PLAYWRIGHT_BROWSERS_PATH 桥接系统 ffmpeg，见 README）:
//   PLAYWRIGHT_BROWSERS_PATH=E:/Temp/pw-ffmpeg node record-page.js "<url1>|<url2>|..." <输出.webm> [每页停留ms] [点击选择器|选择器]
// 依赖: playwright-core + 系统 Chrome（channel:'chrome'）
const { chromium } = require('playwright-core');
const fs = require('fs');
const path = require('path');
const os = require('os');
const VIDTMP = path.join(os.tmpdir(), 'vid-tmp-' + Date.now());

(async () => {
  if (!process.env.PLAYWRIGHT_BROWSERS_PATH) {
    console.error('先设 PLAYWRIGHT_BROWSERS_PATH=E:/Temp/pw-ffmpeg（桥接系统 ffmpeg，一次性建好可复用，见 README §五）');
    process.exit(2);
  }
  const [urlsArg, out, stayMs, clicksArg] = process.argv.slice(2);
  if (!urlsArg || !out) { console.error('usage: node record-page.js "<url|url>" <out.webm> [stayMs] [clicks]'); process.exit(2); }
  fs.mkdirSync(VIDTMP, { recursive: true });
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const ctx = await browser.newContext({
    viewport: { width: 1536, height: 864 },
    recordVideo: { dir: VIDTMP, size: { width: 1536, height: 864 } },
  });
  const page = await ctx.newPage();
  const stay = parseInt(stayMs || '3000');
  for (const u of urlsArg.split('|')) {
    await page.goto(u, { waitUntil: 'commit', timeout: 20000 }).catch(e => console.log('goto warn:', e.message.slice(0, 60)));
    await page.waitForTimeout(stay);
  }
  if (clicksArg) for (const sel of clicksArg.split('|')) { await page.click(sel, { timeout: 5000 }).catch(() => {}); await page.waitForTimeout(stay); }
  await ctx.close(); // 关闭触发视频落盘
  await browser.close();
  const files = fs.readdirSync(VIDTMP).filter(f => f.endsWith('.webm'))
    .map(f => ({ f, t: fs.statSync(path.join(VIDTMP, f)).mtimeMs })).sort((a, b) => b.t - a.t);
  if (!files.length) { console.error('ERR no video produced'); process.exit(1); }
  fs.copyFileSync(path.join(VIDTMP, files[0].f), out);
  console.log('video saved:', out, fs.statSync(out).size, 'bytes');
  try { fs.rmSync(VIDTMP, { recursive: true, force: true }); } catch (e) {}
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
