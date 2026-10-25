# AGENTS.md

Notes for AI coding agents working on this repository. People are welcome to read
them too; the README is the place to start for using nokk.

## What this is

nokk is a headless browser engine in Rust: V8 runs page JavaScript against an
`html5ever` DOM, requests go out with Chrome 151's TLS and HTTP/2 fingerprint
(BoringSSL via `wreq`), and clients drive it over the Chrome DevTools Protocol.
There is no rendering engine. The goal of almost every change is that a page
cannot tell nokk from Chrome 151 on Linux.

## Layout

| Path | What lives there |
|---|---|
| `crates/core` | `Engine` / `BrowserContext`: navigation, the event loop, frames, workers, the challenge solver. Most tests live in `crates/core/src/lib.rs` (`mod tests`). |
| `crates/pool` | V8 isolates on worker threads, snapshots, natives (crypto, canvas via the Skia port, audio, ICU data) |
| `crates/dom` | HTML parsing and the DOM runtime (`dom_runtime.js`) |
| `crates/stealth` | The browser environment in JS: navigator, fetch/XHR, timers, Intl fallback, the fingerprint profile |
| `crates/net` | The Chrome-fingerprinted HTTP client, cookie jar and sessions, proxies |
| `crates/cdp` | The CDP server (Puppeteer and Playwright connect here), plus `Nokk.*` methods |
| `crates/cli` | The `nokk` binary |
| `python/`, `npm/` | Thin wrappers that ship the binary |
| `docs/` | Longer documentation; `docs/architecture.md` explains the design |

## Build and test

```bash
sudo apt install build-essential cmake clang libclang-dev   # BoringSSL needs these
cargo build --release
cargo test --release --workspace
cargo clippy --release --workspace --all-targets
```

- Minimum Rust is 1.88; CI checks it. No root? See `docs/BUILD.md`.
- The first build fetches a prebuilt V8 (~185 MB) and compiles BoringSSL.
- Unit tests must not need the internet. When a test needs a server, start one on
  `127.0.0.1:0` inside the test and build the engine with `use_real_network: true`
  (see `a_hung_request_does_not_hold_the_page`).
- `tools/cf-check.sh` runs five public Cloudflare pages against a built binary.
  It uses the live network; do not run it alongside `cargo test` or other heavy
  work, because a challenge under CPU pressure can run out of time.

## Rules of the code

- **Behave like Chrome 151, not like a reasonable browser.** When unsure, compare
  with a real Chrome 151 on the same machine. A plausible but different answer is
  a detectable difference.
- **The page must not see the engine.** Internal helpers are `__pt_*` globals kept
  out of enumeration; never add page-visible names, properties or stack frames.
  Functions exposed to pages must look native (`toString`, `name`, `length`,
  prototype).
- **One fingerprint, every layer.** The TLS profile, the User-Agent, client hints
  and the JS environment must agree. Change them together or not at all.
- **Fix the general mechanism, not the site.** A fix that only works for one
  challenge or one domain is the wrong fix.
- **Comments in English, short, and only where the code does not say it.** Explain
  why, especially when the reason is "Chrome does this" or "this page broke".
- **Identifiers are Latin; no non-ASCII text in code.**

## Using nokk from an agent

- **MCP:** `uvx nokk-mcp` (or `pip install "nokk[mcp]"`, then `python -m nokk.mcp`).
  Tools: `open`, `snapshot`, `read_text`, `read_html`, `click`, `fill`, `evaluate`, `links`,
  `solve_challenge`, `challenge_state`, `reset`.
- **CDP:** run `nokk --port 9222 --auto-solve` and connect to
  `ws://127.0.0.1:9222/devtools/browser/nokk`. Use the `ws://` address: an
  `http://` one goes through `HTTP_PROXY` if that is set. A server started with `--token`
  (or `NOKK_TOKEN`) wants `?token=…` on that address.
- **Frames:** `Nokk.frames` lists frames with their `executionContextId` for
  `Runtime.evaluate { contextId }`.
- **Challenges:** `Nokk.challengeState` and `Nokk.solveChallenge` report and clear
  them. `Nokk.press` and `Nokk.type` press and type the way a person does, inside
  frames too.
