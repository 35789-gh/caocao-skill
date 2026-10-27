// hook-capture.js — 运行态捕获（混淆藏得再深，运行时发出去的请求一定是明文）。
// 连本机 CDP 9222（外部真浏览器，认 RF-IMG-14 通道与 shotlock 互斥纪律），注入
// fetch / XHR / FormData / sendBeacon 钩子 + 加密库探测，落 window.__audit_capture。
// 用法（在 scripts/vis-tools/ 下）:
//   node hook-capture.js install            对当前所有页注入 + 对后续导航生效（addInitScript）
//   node hook-capture.js dump <out.json>    收集各页 __audit_capture 合并落盘（去重）
//   node hook-capture.js status             看注入状态与抓取条数
//   node hook-capture.js clear              清空各页捕获缓冲
// 产物 runtime-capture.json 用途：与 deobf-report / js-collection 做静态×运行态差集对账
//（运行时有而静态无的接口=解析漏了回补；静态 unresolved 运行时抓到=补账升级 proven）。
// playwright-core 解析：标准 require 失败时按 PLAYWRIGHT_CORE_PATH / E:\Temp\node_modules
//（vis-tools 实战环境同款）兜底；都没有给安装提示退出。
let chromium;
try {
  ({ chromium } = require('playwright-core'));
} catch (e) {
  const fs = require('fs');
  const candidates = ['E:/Temp/node_modules/playwright-core', process.env.PLAYWRIGHT_CORE_PATH].filter(Boolean);
  for (const c of candidates) {
    try { if (fs.existsSync(c)) { ({ chromium } = require(c)); break; } } catch (e2) {}
  }
  if (!chromium) {
    console.error('ERR 缺 playwright-core：在 E:\\Temp 下 npm i playwright-core（vis-tools 实战环境同款），或 npm i -g 后设 PLAYWRIGHT_CORE_PATH 指到包目录');
    process.exit(1);
  }
}

const HOOK_FN = () => {
  if (window.__audit_capture_installed) return 'already';
  window.__audit_capture_installed = true;
  window.__audit_capture = [];
  const rec = (kind, data) => {
    try { if (window.__audit_capture.length < 5000) window.__audit_capture.push({ t: Date.now(), kind, ...data }); } catch (e) {}
  };
  const of = window.fetch;
  if (of) window.fetch = function (input, init) {
    try {
      // r16: URL 实例只有 .href 无 .url——旧版 (input && input.url) || '' 会把
      // fetch(new URL(...)) 记成空串；补 .href 取值
      const url = typeof input === 'string' ? input : (input && (input.url || input.href)) || '';
      const method = (init && init.method) || (input && input.method) || 'GET';
      // FormData/Blob body 走 String() 只能拿到 '[object FormData]' 类占位——审计取舍：
      // 保体积上限与字段名（formdata 钩子补内容），不在此展开序列化，行为不改
      let body = init && init.body;
      if (body && typeof body !== 'string') { try { body = JSON.stringify(body); } catch (e) { body = String(body); } }
      rec('fetch', { url: String(url).slice(0, 1000), method, body: body ? String(body).slice(0, 2000) : null });
    } catch (e) {}
    return of.apply(this, arguments);
  };
  const oo = XMLHttpRequest.prototype.open, os = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, u) { this.__am = m; this.__au = u; return oo.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function (b) {
    try { rec('xhr', { url: String(this.__au || '').slice(0, 1000), method: this.__am, body: b ? String(b).slice(0, 2000) : null }); } catch (e) {}
    return os.apply(this, arguments);
  };
  const oa = FormData.prototype.append;
  FormData.prototype.append = function (k, v) {
    try { rec('formdata', { field: String(k), value: typeof v === 'string' ? v.slice(0, 1000) : ((v && v.name) || String(v)).slice(0, 200) }); } catch (e) {}
    return oa.apply(this, arguments);
  };
  if (navigator.sendBeacon) {
    const ob = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (u, d) { try { rec('beacon', { url: String(u).slice(0, 1000), body: d ? String(d).slice(0, 1000) : null }); } catch (e) {} return ob(u, d); };
  }
  // r16: 删 'crypto'——浏览器原生 window.crypto 恒存在，留着会让 detected 恒含
  // crypto，库探测信号失真（原生 WebCrypto 与 CryptoJS 等库无法靠此区分）
  const libs = ['CryptoJS', 'JSEncrypt', 'jsencrypt', 'sm2', 'sm3', 'sm4', 'aesjs', 'forge', 'axios'];
  rec('libs', { detected: libs.filter(k => window[k] !== undefined) });
  return 'installed';
};

async function pages(browser) {
  const ctx = browser.contexts()[0];
  if (!ctx) throw new Error('CDP 9222 无 context');
  return ctx;
}

(async () => {
  const [cmd, arg] = process.argv.slice(2);
  if (!['install', 'dump', 'status', 'clear'].includes(cmd)) {
    console.error('ERR 用法: node hook-capture.js install | dump <out.json> | status | clear');
    process.exit(2);
  }
  const browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
  const ctx = await pages(browser);
  const open = ctx.pages();
  if (cmd === 'install') {
    await ctx.addInitScript(HOOK_FN);
    for (const p of open) { try { await p.evaluate(HOOK_FN); } catch (e) {} }
    console.log(JSON.stringify({ ok: true, cmd: 'install', pages: open.length, note: '当前页已注入；addInitScript 对后续导航生效。SPA 前端导航不刷新页面，登录后如换页需重新 install。' }));
  } else if (cmd === 'status') {
    const st = [];
    for (const p of open) {
      try { st.push({ url: p.url().slice(0, 120), installed: await p.evaluate(() => !!window.__audit_capture_installed), count: await p.evaluate(() => (window.__audit_capture || []).length) }); } catch (e) { st.push({ url: p.url().slice(0, 120), err: e.message.slice(0, 80) }); }
    }
    console.log(JSON.stringify({ ok: true, cmd: 'status', pages: st }));
  } else if (cmd === 'dump') {
    if (!arg) throw new Error('dump 需要 out.json 路径');
    let all = [];
    for (const p of open) {
      try {
        const items = await p.evaluate(() => JSON.parse(JSON.stringify(window.__audit_capture || [])));
        for (const it of items) all.push({ page: p.url().slice(0, 200), ...it });
      } catch (e) {}
    }
    const seen = new Set();
    all = all.filter(x => { const k = `${x.kind}|${x.url || x.field}|${x.body || ''}`; if (seen.has(k)) return false; seen.add(k); return true; });
    require('fs').writeFileSync(arg, JSON.stringify({
      schema_version: '1.0', candidate_only: true,
      captured_at: new Date().toISOString(), count: all.length, items: all,
      note: '运行态真值账。与 deobf-report / js-collection 差集对账：'
          + '运行时有而静态无=解析漏了回补清单；静态 unresolved 此处抓到=补账；静态有此处无=标注（可能死代码）。密钥静态候选与此处同值=交叉验证成立。',
    }, null, 1), 'utf-8');
    console.log(JSON.stringify({ ok: true, cmd: 'dump', out: arg, count: all.length }));
  } else if (cmd === 'clear') {
    for (const p of open) { try { await p.evaluate(() => { window.__audit_capture = []; }); } catch (e) {} }
    console.log(JSON.stringify({ ok: true, cmd: 'clear', pages: open.length }));
  } else {
    throw new Error('命令: install | dump <out.json> | status | clear');
  }
  await browser.close();
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
