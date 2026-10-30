#!/usr/bin/env node
// Harvest `cf_clearance` with a real Chrome so the engine can reuse it.
//
//   node tools/harvest-clearance.js <url> [seconds] [file]
//   PROFILE=/tmp/my-profile node tools/harvest-clearance.js https://target/
//
// The clearance is bound to the holder's TLS fingerprint, exit address and
// browser version. The engine presents as Chrome 151 with an identical JA4, so
// it accepts a clearance taken here. Verified on
// `scrapingcourse.com/cloudflare-challenge`: "Just a moment…" without it, the
// page itself with it.
//
// The browser is headed (DISPLAY=:0): headless does noticeably worse on the
// managed challenge. Nothing is injected into the page: only the network and
// the cookie list are read.
//
// Then hand the clearance to the engine:
//
//   nokk --load https://target/ --session-store ./sess --session cf \
//        --import-cookies cf_clearance.json
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');

const PORT = +(process.env.PORT || 9340);
const URL_ = process.argv[2];
const TIMEOUT = +(process.argv[3] || 40) * 1000;
const OUT_FILE = process.argv[4] || 'cf_clearance.json';
if (!URL_) {
  console.error('usage: node tools/harvest-clearance.js <url> [seconds] [file]');
  process.exit(2);
}

const chrome = spawn('google-chrome', [
  `--remote-debugging-port=${PORT}`,
  `--user-data-dir=${process.env.PROFILE || '/tmp/nokk-harvest'}`,
  '--no-first-run', '--no-default-browser-check', '--window-size=1280,900',
  ...(process.env.PROXY ? [`--proxy-server=${process.env.PROXY}`] : []),
  'about:blank',
], { env: { ...process.env, DISPLAY: process.env.DISPLAY || ':0' }, stdio: 'ignore' });

const get = (path) => new Promise((res, rej) => {
  const attempt = (n) => http.get({ host: '127.0.0.1', port: PORT, path }, (r) => {
    let b = ''; r.on('data', (d) => b += d); r.on('end', () => res(JSON.parse(b)));
  }).on('error', (e) => (n > 0 ? setTimeout(() => attempt(n - 1), 400) : rej(e)));
  attempt(50);
});

const finish = (code) => {
  try { chrome.kill(); } catch (e) {}
  // Exiting right after the write truncates output redirected to a file.
  setTimeout(() => process.exit(code), 60);
};

(async () => {
  const targets = await get('/json/list');
  const tab = targets.find((t) => t.type === 'page');
  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  let id = 0;
  const pending = new Map();
  const send = (method, params = {}) => new Promise((res) => {
    const i = ++id; pending.set(i, res);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result); pending.delete(m.id); }
  });
  await new Promise((r) => ws.addEventListener('open', r));
  await send('Network.enable');
  await send('Page.enable');
  await send('Page.navigate', { url: URL_ });

  // Leave as soon as the clearance appears: every extra hit on the challenge
  // costs the address reputation.
  const host = new URL(URL_).hostname;
  const root = host.split('.').slice(-2).join('.');
  const deadline = Date.now() + TIMEOUT;
  let clearance = null, cookies = [];
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1000));
    const { cookies: all } = await send('Network.getAllCookies');
    cookies = all.filter((c) => c.domain.replace(/^\./, '').endsWith(root));
    clearance = cookies.find((c) => c.name === 'cf_clearance') || null;
    if (clearance) break;
  }

  const jar = {};
  for (const c of cookies) jar[c.name] = c.value;
  fs.writeFileSync(OUT_FILE, JSON.stringify({ cookies: jar, domain: host, url: URL_ }, null, 1));
  const names = cookies.map((c) => c.name).join(', ');
  // The cookie's own expiry (a year) means little: Cloudflare also checks
  // address and fingerprint. Use `--fail-on-challenge` to test it for real.
  const expiry = clearance && clearance.expires > 0
    ? `, cookie expires ${new Date(clearance.expires * 1000).toISOString().replace('T', ' ').slice(0, 19)}`
    : '';
  process.stdout.write(
    `cookies for ${root}: ${cookies.length} (${names})\n`
    + (clearance ? `cf_clearance: ${clearance.value.slice(0, 32)}…${expiry} → ${OUT_FILE}\n`
             : `no cf_clearance within ${TIMEOUT / 1000} s; file has the other cookies only\n`),
    () => finish(clearance ? 0 : 1),
  );
})().catch((e) => {
  process.stdout.write(`error: ${e.message}\n`, () => finish(2));
});
