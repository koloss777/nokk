#!/usr/bin/env node
// Put the same instrumentation into a real Chrome that `NOKK_TRACE_HOOKS=1` puts
// into the engine, and print the same tape of events: the challenge's callback
// tables as its program calls them, XHR sends with their sizes, blobs and
// workers as they are made. Two tapes side by side answer in a minute what
// otherwise costs an evening — where our run stops matching a browser's.
//
//   node tools/chrome-compare.js <url> [ms]
//   NOKK_TRACE_HOOKS=1 nokk --load <url> --solve-challenge 40 --eval 1
//
// Needs google-chrome, and DISPLAY for a visible window (a headless Chrome is
// blocked outright by some of the targets worth comparing on).
const { spawn } = require('child_process');
const http = require('http');

const PORT = 9333, URL_ = process.argv[2], WAIT = +(process.argv[3] || 40000);
const chrome = spawn('google-chrome', [
  `--remote-debugging-port=${PORT}`, '--user-data-dir=/tmp/cdp-profile', '--no-first-run',
  '--no-default-browser-check', '--window-size=1280,900', 'about:blank',
], { env: { ...process.env, DISPLAY: ':0' }, stdio: 'ignore' });

const get = (path) => new Promise((res, rej) => {
  const tryOnce = (n) => http.get({ host: '127.0.0.1', port: PORT, path }, (r) => {
    let b = ''; r.on('data', (d) => b += d); r.on('end', () => res(JSON.parse(b)));
  }).on('error', (e) => n > 0 ? setTimeout(() => tryOnce(n - 1), 500) : rej(e));
  tryOnce(40);
});

const HOOK = `(() => {
  const tag = () => { try { return location.host + location.pathname.slice(0, 24); } catch (e) { return '?'; } };
  try {
    const S = XMLHttpRequest.prototype.send, O = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (m, u) { this.__u = String(u); return O.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function (b) {
      console.log('[send] ' + tag() + ' bytes=' + ((b && b.length) || 0) + ' url=' + String(this.__u || '').slice(-40));
      return S.apply(this, arguments);
    };
  } catch (e) {}
  try {
    const B = globalThis.Blob;
    if (B) globalThis.Blob = function (parts, opts) {
      let n = 0; try { for (const p of (parts || [])) n += (p && p.length) || (p && p.byteLength) || 0; } catch (e) {}
      console.log('[blob] ' + tag() + ' parts=' + ((parts || []).length) + ' bytes=' + n + ' type=' + ((opts && opts.type) || ''));
      return new B(parts, opts);
    };
    const W = globalThis.Worker;
    if (W) globalThis.Worker = function (u, o) { console.log('[worker] ' + tag() + ' ' + String(u).slice(0, 60)); return new W(u, o); };
    const P = globalThis.postMessage;
  } catch (e) {}
  for (const name of ['RItcy2', 'HuCI0']) {
    let store;
    try {
      Object.defineProperty(globalThis, name, { configurable: true,
        get() { return store; },
        set(v) {
          if (v && typeof v === 'object') {
            for (const k of Object.keys(v)) { const f = v[k];
              if (typeof f === 'function') v[k] = function () { console.log('[hook] ' + tag() + ' ' + name + '.' + k); return f.apply(this, arguments); }; }
          }
          store = v;
        } });
    } catch (e) {}
  }
})();`;

(async () => {
  const list = await get('/json/list');
  const page = list.find((t) => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 0; const send = (method, params = {}, sessionId) =>
    ws.send(JSON.stringify({ id: ++id, method, params, ...(sessionId ? { sessionId } : {}) }));
  const lines = [];
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.method === 'Runtime.consoleAPICalled') {
      const t = (m.params.args || []).map((a) => a.value).join(' ');
      if (/^\[(send|hook|hookerr|blob|worker)\]/.test(String(t))) lines.push(t);
    }
    if (m.method === 'Target.attachedToTarget') {
      const s = m.params.sessionId;
      lines.push('[target] ' + (m.params.targetInfo && m.params.targetInfo.url || '').slice(0, 60));
      send('Runtime.enable', {}, s);
      send('Page.enable', {}, s);
      send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK }, s);
      send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, s);
      send('Runtime.runIfWaitingForDebugger', {}, s);
    }
  });
  ws.addEventListener('open', async () => {
    send('Runtime.enable'); send('Page.enable');
    send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
    send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK });
    setTimeout(() => send('Page.navigate', { url: URL_ }), 400);
    setTimeout(async () => {
      console.log(lines.join('\n') || '(no instrumented output)');
      ws.close(); chrome.kill(); process.exit(0);
    }, WAIT);
  });
})();
