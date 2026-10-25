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

> **Alpha.** Prebuilt wheels: Linux x86_64 and aarch64, macOS on Apple Silicon,
> Windows x64.

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

### Async launcher

`launch()` is a quick synchronous call. In an async program, use
`launch_async()` so nothing blocks the event loop:

```python
import asyncio, nokk
from playwright.async_api import async_playwright

async def main():
    async with await nokk.launch_async() as server, async_playwright() as pw:
        browser = await pw.chromium.connect_over_cdp(server.ws_endpoint)
        page = await browser.new_page()
        await page.goto("https://example.com")
        print(await page.title())

asyncio.run(main())
```

## Give an AI agent a stealth browser (MCP)

`nokk` ships an [MCP](https://modelcontextprotocol.io) server, so an AI agent
(Claude Desktop, Claude Code, …) can browse and scrape through nokk's
fingerprinted engine instead of a headful browser that anti-bots flag. With
[uv](https://docs.astral.sh/uv/), register `uvx nokk-mcp`:

```json
{
  "mcpServers": {
    "nokk": { "command": "uvx", "args": ["nokk-mcp", "--rotate-fingerprint"] }
  }
}
```

Without uv, install the extra and register it:

```bash
pip install "nokk[mcp]"
```

```json
{
  "mcpServers": {
    "nokk": { "command": "python", "args": ["-m", "nokk.mcp", "--rotate-fingerprint"] }
  }
}
```

Use the `python` from the environment where you installed `nokk[mcp]` (its full
path if the client doesn't share your shell). Tools: `open`, `snapshot`, `read_text`,
`read_html`, `click`, `fill`, `evaluate`, `links`, `solve_challenge`,
`challenge_state`, `reset`. Run it directly with `python -m nokk.mcp`; it
accepts `--proxy`, `--rotate-fingerprint`, `--geoip-timezone`,
`--session-store`, `--workers`, `--no-auto-solve`.

Cloudflare challenges are solved on the way by default: `open` returns the page
behind "Just a moment…", and its `challenge` field says what it met.

## Cloudflare challenges

With `auto_solve=True`, a navigation that lands on Cloudflare's "Just a
moment…" page or a Turnstile widget returns only once it is through.

```python
with nokk.launch(auto_solve=True) as server, sync_playwright() as pw:
    page = pw.chromium.connect_over_cdp(server.ws_endpoint).new_page()
    page.goto("https://www.scrapingcourse.com/cloudflare-challenge")
    print(page.title())  # the page behind the challenge
```

Or on demand, for a Playwright page (`solve_challenge_async` /
`challenge_state_async` for the async API):

```python
state = nokk.challenge_state(page)
# {"kind": "cloudflare-interstitial" | "turnstile-widget" | "datadome" | "none", "solvable": …}
if state["solvable"]:
    r = nokk.solve_challenge(page, timeout=30)
    # {"status": "cleared" | "token-issued" | "cleared-but-stuck" | "timeout" | "needs-human", "solved": …, "presses": …}
```

Nobody passes selectors: the engine finds and presses the checkbox itself.

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
| `no_images` | `False` | Do not load images (`<img>`, CSS backgrounds, image preloads). |
| `auto_solve` | `None` | Solve Cloudflare challenges on every navigation; `True` = 30 s budget, a number = seconds. |
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
