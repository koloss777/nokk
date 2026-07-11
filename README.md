<div align="center">

# nokk

**An undetectable headless browser engine, written in Rust.**

Real V8 JavaScript and a full DOM, with a Chrome TLS/HTTP fingerprint and JS-level
stealth — driven over the Chrome DevTools Protocol, so your existing Puppeteer code
just connects. No Chromium process, no rendering, no `navigator.webdriver`.

<sub><i>The nøkk is a shapeshifting water-spirit of Norse myth that takes on a
familiar shape to pass unnoticed. This one takes the shape of Chrome.</i></sub>

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org)
[![Status: alpha](https://img.shields.io/badge/status-alpha-yellow.svg)](#project-status)

</div>

---

## Why nokk

Puppeteer and Playwright drive a real Chromium — which anti-bot systems (Cloudflare,
DataDome, PerimeterX, Akamai) are very good at spotting: the automation leaks through
`navigator.webdriver`, CDP artifacts, a headless TLS handshake, and dozens of other
tells. The usual answer is a stack of stealth plugins bolted onto a 300 MB browser.

**nokk takes the opposite approach: build the browser to be indistinguishable from
the ground up, and skip the rendering engine entirely.**

- 🛡️ **One coherent profile, TLS to JS.** The network layer emits a byte-exact
  current-Chrome ClientHello (JA3/JA4) and HTTP/2 SETTINGS, and the JavaScript environment
  (`navigator`, `screen`, canvas/WebGL/audio, `window.chrome`) is spoofed from the *same*
  profile — so the wire fingerprint and the JS one agree (UA, platform, versions all line
  up). Closing the remaining JS-level tells is active work; see the [roadmap](ROADMAP.md).
- ⚡ **Lightweight by construction.** No Chromium, no compositor, no rendering — just V8
  and a DOM, so a context is inherently far cheaper than a real browser tab. The design
  targets sub-100 ms start and ~30–50 MB per context; these aren't benchmarked yet.
- 🧩 **Drop-in for Puppeteer.** nokk speaks CDP over WebSocket. Point
  `puppeteer.connect()` at it and drive pages, navigate, and `evaluate()` as usual.
- 🔬 **Real JS, real DOM.** Google's V8 runs page scripts against an HTML-parsed DOM,
  with timers, microtasks, `fetch`, and `XMLHttpRequest` — enough to clear JS challenges
  and run client-rendered pages.
- 🕸️ **Built-in request interception.** Every request a page makes — the document,
  every `<script>`, every `fetch`/XHR — flows through Rust and is logged, so scraping
  a site's internal JSON API needs no proxy plumbing.
- 🚀 **Built around concurrency.** The core is a pool of V8 isolates (one per thread,
  each multiplexing several contexts) with semaphore backpressure on live contexts, so
  memory stays bounded. Scaling this to hundreds or thousands of concurrent contexts is
  the explicit design target — but that's a goal on the [roadmap](ROADMAP.md), not a
  proven number yet.

> **Keywords:** undetectable headless browser · anti-bot bypass · Cloudflare bypass ·
> JA3/JA4 TLS fingerprint · browser fingerprint spoofing · stealth web scraping ·
> Puppeteer-compatible · headless Chrome alternative · Rust.

## Quick start

### Prerequisites

nokk's fingerprinted transport is backed by BoringSSL (via `wreq`), so the first build
compiles it from source. You need a C/C++ toolchain, `cmake`, and `libclang`. On
Debian/Ubuntu:

```bash
sudo apt install build-essential cmake clang libclang-dev
```

> No root? BoringSSL can be bootstrapped from user-space `pip` packages — see
> [`docs/BUILD.md`](docs/BUILD.md) for the `cmake` + `libclang` + `.cargo/config.toml`
> recipe used to build this repo without sudo.

### Build

```bash
git clone https://github.com/koloss/nokk
cd nokk
cargo build --release
```

### Use it from the command line

```bash
# Fetch a URL with a full Chrome fingerprint (JA3/JA4 + HTTP/2)
cargo run --release --bin nokk -- --fetch https://tls.browserleaks.com/json

# Navigate a real page, run its scripts, and probe the resulting DOM
cargo run --release --bin nokk -- --load https://example.com --eval 'document.title'

# Prove the automation flag is gone
cargo run --release --bin nokk -- --eval 'navigator.webdriver'   # -> false

# Scrape a page's internal API: dump every request it makes, then one body
cargo run --release --bin nokk -- --load https://quotes.toscrape.com --dump-requests
cargo run --release --bin nokk -- --load https://some.site --dump-request '/api/'

# Route through a proxy (essential for IP rotation against WAFs)
cargo run --release --bin nokk -- --load https://target --proxy socks5://host:1080
```

### Drive it from Puppeteer

Run nokk as a CDP server, then connect any existing Puppeteer script to it:

```bash
cargo run --release --bin nokk -- --port 9222 --workers 4 --max-contexts 64
```

```js
import puppeteer from 'puppeteer';

const browser = await puppeteer.connect({
  browserWSEndpoint: 'ws://127.0.0.1:9222/devtools/browser/nokk',
});
const page = await browser.newPage();
await page.goto('https://example.com');
console.log(await page.title());
await browser.close();
```

## How it works

nokk is a Cargo workspace of small, single-responsibility crates:

| Crate            | Responsibility |
|------------------|----------------|
| `nokk`         | Public `Engine`/`BrowserContext` API; ties the layers together |
| `nokk-pool`    | Isolate worker pool + backpressure (one V8 isolate per thread) |
| `nokk-net`     | Chrome-fingerprinted HTTP client (BoringSSL), connection pool, proxy |
| `nokk-dom`     | HTML parsing (`html5ever`) → DOM tree |
| `nokk-stealth` | The spoofed JS environment + fingerprint hardening |
| `nokk-cdp`     | Chrome DevTools Protocol WebSocket server (Puppeteer-compatible) |
| `nokk-cli`     | The `nokk` binary |

Three constraints shape every design decision:

1. **V8 isolates are single-threaded.** Concurrency is a pool of OS threads, one isolate
   each, every isolate multiplexing several contexts ("tabs"). Contexts are pinned to a
   thread and never move; a crash in one must not take down the pool.
2. **Network is non-blocking and off the isolate threads.** All IO runs on `tokio` over a
   shared connection pool, so a slow request never occupies a JS worker.
3. **Fingerprint coherence is sacred.** The JS-level fingerprint and the TLS/HTTP
   fingerprint must always agree — changing one without the other is what gets you caught.

The DOM, timers, `fetch`, and most stealth shims are implemented in JavaScript injected
into each context, bridged to Rust through a handful of hidden globals — so the browser
surface a page sees is real JS objects, not native bindings a detector can trivially probe.

## Project status

**Alpha.** The engine is real and end-to-end: V8 executes page JS against a parsed DOM,
the fingerprinted transport clears Cloudflare's TLS/HTTP checks and the "Just a moment…"
JS challenge on live sites, and Puppeteer can connect over CDP to open a page, navigate,
and evaluate.

What is **not** done yet, and where the sharp edges are:

- **JS-fingerprint hardening is ongoing.** Several detectable tells remain (e.g.
  `Function.prototype.toString` masking, hiding internals from `Object.getOwnPropertyNames`,
  making `navigator`/`screen` real prototype instances, timezone coherence). nokk passes
  mainstream WAF challenges today but is **not** yet a match for a dedicated fingerprinting
  suite like CreepJS. See the [roadmap](ROADMAP.md).
- **CDP coverage is the Puppeteer happy path**, not the whole protocol. `page.$`/`$eval`
  via Puppeteer's injected query utilities and Playwright are not supported yet; use
  `page.evaluate()`.
- **Per-context network limits and cookie isolation** are not yet enforced (Phase 7).
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
</div>
