<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/nokk-logo-dark.png">
  <img src="docs/nokk-logo.png" alt="nokk" width="360">
</picture>

**A stealth headless browser engine in Rust. Passes Cloudflare without Chromium.**

Real V8 and a DOM, a Chrome TLS/HTTP fingerprint (JA3/JA4) and JS-level stealth,
driven over the Chrome DevTools Protocol: Puppeteer and Playwright connect as usual.
Also an MCP server for AI agents.

[![CI](https://github.com/koloss777/nokk/actions/workflows/ci.yml/badge.svg)](https://github.com/koloss777/nokk/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/koloss777/nokk?include_prereleases)](https://github.com/koloss777/nokk/releases/latest)
[![PyPI](https://img.shields.io/pypi/v/nokk.svg)](https://pypi.org/project/nokk/)
[![npm](https://img.shields.io/npm/v/@koloss777/nokk.svg)](https://www.npmjs.com/package/@koloss777/nokk)
[![Docker](https://img.shields.io/badge/ghcr.io-koloss777%2Fnokk-blue)](https://github.com/koloss777/nokk/pkgs/container/nokk)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Status: alpha](https://img.shields.io/badge/status-alpha-yellow.svg)](#project-status)

<img src="docs/demo.svg" alt="curl gets 403 from a Cloudflare test page; nokk loads it, clears the challenge and prints the page behind it in about 5 seconds" width="760">

<sub>scrapingcourse.com's Cloudflare test page, one run from a home connection; medians across sites are in the tables below.</sub>

<sub><i>The nøkk is a shapeshifting water-spirit of Norse myth that takes on a
familiar shape to pass unnoticed. This one takes the shape of Chrome.</i></sub>

</div>

---

## Install

```bash
pip install nokk                    # Python: the prebuilt binary is in the wheel
npm install @koloss777/nokk         # Node: run it with `npx nokk`
docker run --rm -p 9222:9222 ghcr.io/koloss777/nokk:latest
```

No browser to download. Prebuilt for Linux (x86_64, ARM64), macOS on Apple Silicon and
Windows x64; anything else [builds from source](docs/BUILD.md).

## Quick start

```bash
# Load a page behind Cloudflare, clear the challenge, print what is behind it
nokk --load https://www.scrapingcourse.com/cloudflare-challenge --solve-challenge 30 \
     --eval "document.querySelector('h2').textContent.trim()"

# Or run the CDP server and drive it from any client
nokk --port 9222 --auto-solve   # ws://127.0.0.1:9222/devtools/browser/nokk
```

```python
import nokk
from playwright.sync_api import sync_playwright

with nokk.launch(auto_solve=True) as server, sync_playwright() as pw:
    page = pw.chromium.connect_over_cdp(server.ws_endpoint).new_page()
    page.goto("https://www.scrapingcourse.com/cloudflare-challenge")
    print(page.title())
```

For AI agents, `uvx nokk-mcp` runs it as an [MCP server](#for-ai-agents-mcp).
Puppeteer, Node, sessions and the Cloudflare options are [below](#usage).

## Why nokk

Puppeteer and Playwright drive a real Chromium, and anti-bot systems spot it through
`navigator.webdriver`, CDP artifacts and a headless TLS handshake. nokk is built to
look like Chrome from the TLS handshake to the JavaScript environment, and has no
rendering engine at all.

| | nokk 0.1.35 | Chrome 151 (Puppeteer / Playwright) |
|---|---|---|
| Start until CDP answers | ~0.05 s | ~0.2 s |
| Idle memory (PSS) | ~60 MB, 1 process | ~330 MB, 12–14 processes |
| Cloudflare solve, median wall time | 12.4 s | 12.4 s |
| Slowest solve | 15.6 s | 27.8 s |
| CPU per solve | 6.4 s | 9.5 s |
| Peak memory per solve | ~570 MB | ~720 MB |
| Solved | 24/24 | 24/24 |
| TLS fingerprint (JA3/JA4) | matches Chrome 151 | Chrome |
| Screenshots, PDF, layout | no | yes |
| CDP coverage | the common path | full |

<sub>Measured on nokk 0.1.35, an 8-core Linux box, October 2026. Cloudflare row: 8 production sites × 3 runs
through one proxy, nokk with <code>--until-clearance</code>, Chrome driven by a
checkbox-clicking harness; a solve counts only if the site then opens with the cookie.</sub>

**Not for you if** you need screenshots, PDFs, layout or paint, or the whole
Playwright/CDP surface: nokk has no rendering engine by design, and its CDP coverage
is the path Puppeteer and Playwright use for navigation and scripting.

## Measured on public pages

Three runs per page from the CLI with `--solve-challenge 30` and no proxy, on an 8-core
Linux box (October 2026). The time is the whole command, from process start to the printed
result. Run them yourself with `tools/cf-check.sh`.

| Page | Challenge | Solved | Median | Slowest |
|---|---|---|---|---|
| `chess.com/login` | invisible Turnstile widget on a live site | 3/3 | 7 s | 9 s |
| `scrapingcourse.com/cloudflare-challenge` | managed interstitial | 3/3 | 5 s | 7 s |
| `peet.ws/turnstile-test/managed.html` | managed widget | 3/3 | 7 s | 8 s |
| `peet.ws/turnstile-test/non-interactive.html` | non-interactive widget | 3/3 | 3 s | 4 s |
| `nopecha.com/demo/cloudflare` | interactive interstitial with a checkbox | 3/3 | 10 s | 11 s |

On production sites behind Cloudflare the result is in the [comparison above](#why-nokk):
8 sites, 24 of 24 solved. Those sites are not named here.

## Usage

### Command line

```bash
nokk --fetch https://tls.browserleaks.com/json                   # Chrome TLS + HTTP/2 fingerprint
nokk --load https://example.com --eval 'document.title'          # run the page, query the DOM
nokk --load https://quotes.toscrape.com --dump-requests          # every request the page makes
nokk --load https://target --proxy socks5://host:1080            # through a proxy
nokk --port 9222 --rotate-fingerprint --geoip-timezone           # CDP server, a machine per context
```

Ad, analytics and tracker requests are dropped by default; `--allow-trackers` loads them.
Anti-bot vendors are never blocked, because they must run to hand out a token.

### Puppeteer

```js
import puppeteer from 'puppeteer';

const browser = await puppeteer.connect({
  browserWSEndpoint: 'ws://127.0.0.1:9222/devtools/browser/nokk',   // nokk --port 9222
});
const page = await browser.newPage();
await page.goto('https://example.com');
console.log(await page.title());
```

### Node and Python

Both packages carry the prebuilt binary and start the CDP server for you.

```js
const server = await require("@koloss777/nokk").launch({ autoSolve: true });
// server.wsEndpoint -> puppeteer.connect / chromium.connectOverCDP
```

```python
with nokk.launch(auto_solve=True) as server:   # or: await nokk.launch_async()
    ...  # server.ws_endpoint -> connect_over_cdp
```

### crawl4ai, Scrapy, Playwright MCP and other CDP tools

Anything that drives Chrome over CDP can drive nokk instead. crawl4ai, stopped by
Cloudflare with its own Chromium, gets the page behind it through nokk:
`BrowserConfig(browser_mode="custom", cdp_url=server.ws_endpoint)`. Scrapy
(scrapy-playwright's `PLAYWRIGHT_CDP_URL`) and Playwright MCP (`--cdp-endpoint`)
work the same way. See [docs/integrations.md](docs/integrations.md).

### For AI agents (MCP)

nokk runs as a [Model Context Protocol](https://modelcontextprotocol.io) server, so an agent
such as Claude Desktop or Claude Code browses through the fingerprinted engine. With
[uv](https://docs.astral.sh/uv/) nothing needs installing first:

```json
{ "mcpServers": { "nokk": { "command": "uvx", "args": ["nokk-mcp", "--rotate-fingerprint"] } } }
```

Without uv: `pip install "nokk[mcp]"`, then `"command": "python", "args": ["-m", "nokk.mcp"]`.
Tools: `open`, `snapshot`, `read_text`, `read_html`, `click`, `fill`, `evaluate`, `links`, `solve_challenge`,
`challenge_state`, `reset`.

### Cloudflare challenges

nokk clears Turnstile by itself: the invisible widget, the managed interstitial and the
interactive *Verify you are human* checkbox. Nothing is configured per site. Where a widget
needs a press, the engine presses it like a person would.

- `--solve-challenge N` sets the time budget, and `--fail-on-challenge` exits `3` if a gate is still up.
- `--until-clearance` stops at a fresh `cf_clearance` and skips the heavy page behind the gate.
- `--auto-solve` does the same for every `page.goto()` over CDP; `Nokk.solveChallenge` does it on demand.
- A `cf_clearance` from a real browser can be imported, because nokk's JA4 matches Chrome 151.

Details, the CDP methods and events: [docs/cloudflare.md](docs/cloudflare.md).

### Persistent sessions

`--session-store ./sessions` saves each named session's cookie jar, `cf_clearance` included,
to disk and reloads it in a new process. Warm a session once and reuse it instead of
solving the challenge on every run. See [docs/sessions.md](docs/sessions.md).

### Rotating fingerprints

`--rotate-fingerprint` gives every browser context its own coherent machine: TLS emulation,
User-Agent, client hints, platform, screen and WebGL all agree. `--geoip-timezone` matches the
timezone and languages to the proxy's exit IP. See [docs/fingerprints.md](docs/fingerprints.md).

## Builds

| Build | What it adds | Where |
|---|---|---|
| light (default) | everything above; canvas and WebGL pixels are synthesised | pip, npm, `ghcr.io/koloss777/nokk:latest`, `nokk-*.tar.gz` |
| render | real canvas 2D and WebGL rasterisation, about 100 MB more at peak | `:render` image, `nokk-render-*.tar.gz`, `--features render,webgl` |

Prebuilt for Linux x86_64 and ARM64, macOS on Apple Silicon and Windows x64; the render build
for Linux x86_64. Docker variants, the archives and building from source are in
[docs/install.md](docs/install.md).

## How it works

A Cargo workspace of small crates: a V8 isolate pool, a Chrome-fingerprinted HTTP client on
BoringSSL, an `html5ever` DOM, the stealth layer and a CDP server. Concurrency is one isolate
per thread with many contexts each, all IO runs on `tokio` off the isolate threads, and the
JS fingerprint and the TLS fingerprint always agree. More in [docs/architecture.md](docs/architecture.md).

## Project status

**Alpha.** The engine is real and end-to-end: V8 executes page JS against a parsed DOM,
the fingerprinted transport clears Cloudflare's TLS/HTTP checks, the engine solves
Turnstile on live sites — invisible, managed and interactive — and Puppeteer and Playwright connect
over CDP to open a page, navigate, and evaluate.

What is **not** done yet, and where the sharp edges are:

- **JS-fingerprint hardening is ongoing.** Much of the hardening is in place — native
  `toString` masking, internals hidden from `Object.getOwnPropertyNames`, `navigator`/`screen`
  as real prototype instances, an IP-coherent timezone, and per-context coherent fingerprint
  rotation, Web Workers, canvas/WebGL/WebGPU/audio with Chrome's pixels and samples,
  Trusted Types and CSP. nokk solves Cloudflare's challenges today, and the comparison
  against Chrome section by section is how the remaining tells get found; it is **not**
  yet a match for a dedicated fingerprinting suite like CreepJS. See the
  [roadmap](ROADMAP.md).
- **CDP coverage is the common path**, not the whole protocol. Puppeteer and Playwright
  connect over CDP: navigation, `evaluate`, `$` / `$eval` / `$$eval`, `title()`, `url()`,
  new pages and CDP sessions are tested; less-common domains are not implemented yet.
- **Per-context cookie isolation and per-session persistence** work (each browser context
  gets its own jar; named sessions persist across runs); **per-host / per-proxy / global
  connection limits** are not yet enforced (Phase 7).
- No rendering — screenshots, PDF, and layout/paint are out of scope by design.

See [ROADMAP.md](ROADMAP.md) for the phased plan and the concrete hardening backlog.

## Contributing

Issues and PRs are welcome — the hardening backlog in the roadmap is a good place to start.
Before sending a change:

```bash
cargo fmt
cargo clippy --all-targets
cargo test
```

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

Unless you explicitly state otherwise, any contribution you submit for inclusion in this
work, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any
additional terms or conditions.

---

<div align="center">
<sub>nokk is an independent research project and is not affiliated with Google, Chrome, or any anti-bot vendor. Use it only against systems you are authorized to test.</sub>
