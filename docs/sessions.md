# Persistent sessions

Start nokk with a session store, then bind a browser context to a **session name**. Its
cookie jar — login state, `cf_clearance`, session cookies and all — persists to
`<store>/<name>.json` and reloads automatically, even in a new process. Warm a session once
and re-attach it later instead of re-solving a challenge every run:

```bash
nokk --port 9222 --session-store ./sessions
```

```js
const browser = await puppeteer.connect({
  browserWSEndpoint: 'ws://127.0.0.1:9222/devtools/browser/nokk',
});
// `sessionName` is a nokk extension to Target.createBrowserContext, sent via raw CDP.
const cdp = await browser.target().createCDPSession();
const { browserContextId } = await cdp.send('Target.createBrowserContext', {
  sessionName: 'acme',
  // proxyServer: 'http://user:pass@host:port',   // optional, per-session IP
});
```

Every page opened in that context shares the named jar; it flushes to disk when the context
closes. Distinct session names are fully isolated. Without `--session-store`, sessions are
in-memory only. From the Rust API this is `Engine::new_context_with_session(name, proxy)`.

A `cf_clearance` earned in a real browser can be imported into a session with
`--import-cookies`; see [Cloudflare challenges](cloudflare.md#replaying-a-cf_clearance-from-a-real-browser).

## From the command line

```bash
nokk --load https://gated.example/ --solve-challenge 60 \
     --session-store ./sessions --session s1 \
     --export-cookies cookies.txt --json
```

- `--session` + `--session-store` keep the jar in `./sessions/s1.json`. Beside it,
  `s1.browser.json` records the browser the session was earned with: the Chrome version,
  the User-Agent, the platform and `--ip-version`. A later run on the same session takes the
  version and the address family from there unless given; a different `--chrome-version`
  prints a warning, since a clearance is only good from the browser that earned it.
- `--export-cookies FILE` writes the page's cookies at the end: Netscape `cookies.txt` for a
  `.txt` name (curl `-b`, wget, yt-dlp), otherwise the JSON shape `--import-cookies` reads,
  with every cookie in full under `records`.
- `--json` prints one object: `ok`, `final_url`, the HTTP `status` of the document, `title`,
  `challenge` (`found`, `result`, `elapsed_ms`, `presses`, `still_up`), `cf_clearance`,
  `cookies` and the `--eval` result. A failure prints `{"ok": false, "error": {"kind",
  "message"}}`, where `kind` is `dns`, `proxy`, `tls`, `refused`, `reset`, `timeout`,
  `unreachable`, `connect` or `error`, and exits 1.
