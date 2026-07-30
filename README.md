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
  and a DOM. Measured on an 8-core Linux box: **~4 ms** engine start, **~20 MB** idle, and
  **~0.5 MB per context** (contexts share an isolate) — 100 live contexts fit in ~65 MB,
  versus 30–50 MB for a *single* real Chrome tab.
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
  memory stays bounded. At ~0.5 MB/context the memory headroom for hundreds of contexts is
  real; hardening *sustained* thousand-context churn is still on the [roadmap](ROADMAP.md).

> **Keywords:** undetectable headless browser · anti-bot bypass · Cloudflare bypass ·
> JA3/JA4 TLS fingerprint · browser fingerprint spoofing · stealth web scraping ·
> Puppeteer-compatible · headless Chrome alternative · Rust.

## Quick start

### Run with Docker (no build required)

The published image bundles the binary, glibc, and TLS roots — nothing to compile.
`:latest` is a tiny [distroless](https://github.com/GoogleContainerTools/distroless)
image (~62 MB, ~22 MB compressed):

```bash
docker run --rm -p 9222:9222 ghcr.io/koloss777/nokk:latest
```

That starts the CDP server; point Puppeteer at `ws://localhost:9222/devtools/browser/nokk`.
One-shot modes work too — just override the args:

```bash
docker run --rm ghcr.io/koloss777/nokk:latest --eval 'navigator.webdriver'   # -> false
docker run --rm ghcr.io/koloss777/nokk:latest --load https://example.com --eval 'document.title'
```

Two variants are published per release:

| Tag | Base | Notes |
|-----|------|-------|
| `:latest`, `:<version>`, `:distroless` | distroless | Smallest; no shell. The default. |
| `:debian`, `:<version>-debian` | debian-slim | Larger, but has a shell for `docker exec` debugging. |

Or build the image yourself from a checkout: `docker build -t nokk .` (add
`--target debian` for the debian variant).

### Run the prebuilt binary

Grab the Linux x86_64 tarball from the [latest release](../../releases/latest):

```bash
tar -xzf nokk-*-linux-x86_64.tar.gz
./nokk --eval 'navigator.webdriver'
```

### Build from source

nokk's fingerprinted transport is backed by BoringSSL (via `wreq`), so the first build
compiles it from source. You need a C/C++ toolchain, `cmake`, and `libclang`. On
Debian/Ubuntu:

```bash
sudo apt install build-essential cmake clang libclang-dev
git clone https://github.com/koloss777/nokk
cd nokk
cargo build --release
```

> No root? BoringSSL can be bootstrapped from user-space `pip` packages — see
> [`docs/BUILD.md`](docs/BUILD.md) for the `cmake` + `libclang` + `.cargo/config.toml`
> recipe used to build this repo without sudo.

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

# Give every browser context its own coherent machine, with its timezone/locale
# matched to the proxy's exit IP
cargo run --release --bin nokk -- --port 9222 --rotate-fingerprint --geoip-timezone
```

Ad/analytics/tracker subresources are dropped by default (trimming the passive-fingerprinting
surface and speeding loads); pass `--allow-trackers` to load them. Anti-bot vendors are never
blocked — they must run to hand out a token.

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

### Persistent sessions (warm up once, resume anytime)

Start nokk with a session store, then bind a browser context to a **session name**. Its
cookie jar — login state, `cf_clearance`, session cookies and all — persists to
`<store>/<name>.json` and reloads automatically, even in a new process. Warm a session once
and re-attach it later instead of re-solving a challenge every run:

```bash
cargo run --release --bin nokk -- --port 9222 --session-store ./sessions
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

### Rotating fingerprints across contexts

With `--rotate-fingerprint`, every browser context presents its **own coherent machine** —
not just a different User-Agent, but a matched set of `{ TLS/JA3 emulation OS + UA +
navigator.userAgentData + sec-ch-ua + platform + screen + hardwareConcurrency + WebGL }`
where every layer agrees. The profile is chosen deterministically from the context's identity
(the Puppeteer browser-context id), so a given context is the **same** machine across runs,
and distinct contexts look like distinct devices. Naive UA rotation is a *net negative* — a UA
that contradicts the TLS handshake or the client hints is itself a detection signal — so nokk
rotates the whole identity or nothing.

```js
// Two contexts → two self-consistent, distinct machines (Chrome on Linux / Windows / macOS)
const a = await browser.createBrowserContext();
const b = await browser.createBrowserContext();
```

Add `--geoip-timezone` to derive each context's `Intl` timezone and `navigator.languages`
from its **proxy's exit IP** (one lookup per proxy, made through that proxy and cached), so a
context routed through a German proxy reports `Europe/Berlin` and `de-DE` — a browser whose
timezone disagrees with its IP is a classic tell. Both flags are off by default, so a single
context stays deterministic. From the Rust API these are `EngineConfig::rotate_fingerprint`
and `EngineConfig::geoip_timezone`.

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

- **JS-fingerprint hardening is ongoing.** Much of the hardening is in place — native
  `toString` masking, internals hidden from `Object.getOwnPropertyNames`, `navigator`/`screen`
  as real prototype instances, an IP-coherent timezone, and per-context coherent fingerprint
  rotation — but tells remain (no Web Workers / `OffscreenCanvas`). nokk passes mainstream WAF
  challenges today but is **not** yet a match for a dedicated fingerprinting suite like
  CreepJS. See the [roadmap](ROADMAP.md).
- **CDP coverage is the Puppeteer happy path**, not the whole protocol. `page.$` /
  `$eval` / `$$eval` and `page.evaluate()` work; Playwright and less-common CDP domains
  are not supported yet.
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
</div>
