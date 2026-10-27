// 驱动本机有头 Chrome（CDP 9222）操作 RuoYi 前端
const { chromium } = require('playwright-core');
const BASE = 'http://127.0.0.1:5173';
(async () => {
  const browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
  const ctx = browser.contexts()[0];
  let page = ctx.pages().find(p => p.url().includes('127.0.0.1:5173'));
  if (!page) { page = await ctx.newPage(); }
  const cmd = process.argv[2] || 'probe';
  const arg = process.argv[3] || '';
  try {
    if (cmd === 'probe') {
      await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(1500);
      const inputs = await page.locator('input').evaluateAll(els => els.map(e => ({ ph: e.placeholder, type: e.type, name: e.name, cls: e.className.slice(0, 40) })));
      const buttons = await page.locator('button').evaluateAll(els => els.map(e => e.textContent.trim()).filter(Boolean));
      console.log(JSON.stringify({ url: page.url(), inputs, buttons }, null, 1));
    } else if (cmd === 'login') {
      const [user, pass] = arg.split('|');
      await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(1200);
      const uin = page.locator('input[type="text"]').first();
      await uin.fill('');
      await uin.type(user, { delay: 60 });
      const pin = page.locator('input[type="password"]').first();
      await pin.fill('');
      await pin.type(pass, { delay: 60 });
      await page.waitForTimeout(400);
      await page.locator('button.submit-button').click();
      await page.waitForTimeout(2500);
      console.log('after login url =', page.url());
    } else if (cmd === 'goto') {
      await page.goto(BASE + arg, { waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(1800);
      console.log('url =', page.url());
    } else if (cmd === 'text') {
      const body = await page.locator('body').innerText();
      console.log(body.slice(0, 3000));
    } else if (cmd === 'click') {
      await page.getByText(arg, { exact: false }).first().click();
      await page.waitForTimeout(1200);
      console.log('clicked', arg, 'url =', page.url());
    } else if (cmd === 'reload') {
      await page.reload({ waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(2000);
      console.log('reloaded', page.url());
    } else if (cmd === 'shot') {
      await page.screenshot({ path: arg });
      console.log('shot ->', arg);
    } else if (cmd === 'logout') {
      await page.goto(BASE + '/index', { waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(1800);
      // 头像区域：hover 触发下拉
      const avatar = page.locator('.avatar-container, .right-menu-item:has(img), img.user-avatar, .right-menu img').first();
      await avatar.hover({ timeout: 5000 }).catch(() => {});
      await page.waitForTimeout(900);
      const item = page.locator('li:has-text("退出登录"), .el-dropdown-menu__item:has-text("退出登录")').first();
      await item.click({ timeout: 5000 }).catch(async () => {
        console.log('hover menu missed, retrying click avatar');
        await avatar.click({ timeout: 3000 }).catch(() => {});
        await page.waitForTimeout(800);
        await page.locator('li:has-text("退出登录"), .el-dropdown-menu__item:has-text("退出登录")').first().click({ timeout: 4000 });
      });
      await page.waitForTimeout(900);
      // 确认弹窗
      const confirm = page.locator('.el-message-box button:has-text("确定"), .el-popconfirm button:has-text("确定")').first();
      await confirm.click({ timeout: 3000 }).catch(() => {});
      // 状态机自检：必须到达登录页
      for (let i = 0; i < 10; i++) {
        if (page.url().includes('/login')) break;
        await page.waitForTimeout(700);
      }
      if (!page.url().includes('/login')) throw new Error('logout failed, still at ' + page.url());
      console.log('after logout url =', page.url());
    }
  } finally {
    await browser.close();  // 只断开 CDP 连接，不关浏览器
  }
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
