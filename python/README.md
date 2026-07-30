# nokk (Python)

**Undetectable headless-browser engine, one `pip install` away.**

`nokk` is a lightweight, Chrome-fingerprinted headless-browser engine (V8 + a
minimal DOM, no rendering) that speaks the Chrome DevTools Protocol. This package
**embeds the prebuilt `nokk` binary** — there is no browser to download, no Rust
toolchain to install, and no Docker. `pip install nokk`, call `launch()`, and
connect your existing Playwright or pyppeteer script over CDP.

```bash
pip install nokk
```

> **Alpha:** prebuilt wheels are currently **Linux x86_64** only. macOS/Windows
> wheels are on the roadmap.

## Quick start

### Playwright

```python
import nokk
from playwright.sync_api import sync_playwright

with nokk.launch() as server, sync_playwright() as pw:
    browser = pw.chromium.connect_over_cdp(server.ws_endpoint)
    page = browser.new_page()
    page.goto("https://example.com")
    print(page.title())
```

### pyppeteer

```python
import asyncio, nokk
from pyppeteer import connect

async def main():
    with nokk.launch() as server:
        browser = await connect(browserWSEndpoint=server.ws_endpoint)
        page = await browser.newPage()
        await page.goto("https://example.com")
        print(await page.title())

asyncio.run(main())
```

## `launch()` options

`nokk.launch()` starts the CDP server on a free port and returns a `NokkServer`
(a context manager). All arguments are keyword-only:

| Argument | Default | Meaning |
|---|---|---|
| `host` | `"127.0.0.1"` | Address to bind. |
| `port` | `0` | TCP port; `0` picks a free one. |
| `workers` | engine default | Isolate worker threads. |
| `max_contexts` | engine default | Cap on concurrent contexts before backpressure. |
| `proxy` | `None` | Upstream proxy, e.g. `socks5://host:1080` or `http://user:pass@host:port`. |
| `session_store` | `None` | Directory for persistent named-session cookie jars. |
| `rotate_fingerprint` | `False` | Give each browser context its own coherent fingerprint (OS/UA/screen/WebGL + matching TLS). |
| `geoip_timezone` | `False` | Derive each context's timezone/locale from its proxy's exit IP. |
| `allow_trackers` | `False` | Load ad/analytics/tracker subresources (blocked by default). |
| `args` | `None` | Extra raw CLI arguments passed to the binary. |
| `timeout` | `30.0` | Seconds to wait for the server to accept connections. |

```python
# Each browser context looks like a different machine, timezone matched to its proxy.
with nokk.launch(rotate_fingerprint=True, geoip_timezone=True) as server:
    ...
```

The server also shuts down automatically at interpreter exit; `with` or
`server.close()` stops it immediately.

Point at a locally built binary during development with the `NOKK_BINARY`
environment variable.

## Links

- Source & docs: <https://github.com/koloss777/nokk>
- Issues: <https://github.com/koloss777/nokk/issues>

Licensed under either of MIT or Apache-2.0, at your option.
