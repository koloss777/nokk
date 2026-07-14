# Roadmap

nokk is built in phases. The engine is real and end-to-end today (alpha); the work
ahead is hardening the fingerprint, broadening protocol coverage, and proving out
concurrency at scale.

Legend: ✅ done · 🟡 partial / in progress · ⬜ planned

## Where we are

| Phase | Area | Status |
|-------|------|--------|
| 0 | Workspace scaffold, threading model, public API | ✅ |
| 1 | Embed V8 (isolate pool, contexts, eval, event loop) | ✅ |
| 2 | Network + Chrome TLS/HTTP fingerprint (BoringSSL, JA3/JA4, HTTP/2) | ✅ |
| 3 | HTML parsing → DOM | ✅ |
| 4 | JS ↔ DOM bridge (`document`, events, timers, `fetch`/XHR) | ✅ |
| 5 | CDP WebSocket server (Puppeteer connect / navigate / evaluate) | 🟡 |
| 6 | JS-level stealth (canvas/WebGL/audio, `window.chrome`, hardening) | 🟡 |
| 7 | Scaling & concurrency (100–1000 contexts under a memory ceiling) | ⬜ |
| 8 | Testing, benchmarks, fingerprint regression suite | 🟡 |
| 9 | Packaging & release (crates.io, Docker, prebuilt binaries) | ⬜ |

## Near-term: fingerprint hardening (Phase 6)

These are the concrete tells a dedicated fingerprinting suite (CreepJS, FingerprintJS)
would flag today. Closing them is the top priority — coherence is the whole point.

- ✅ **Patch `Function.prototype.toString` itself** — a Proxy apply-trap + native
  registry makes every masked function (DOM/canvas/WebGL/permissions/timers/fetch…)
  report `[native code]` through *all* routes, closing the
  `Function.prototype.toString.call(fn)` bypass; the patch hides itself and page
  functions stay unmasked. Regression-tested.
- ⬜ **Hide engine internals from `Object.getOwnPropertyNames` / `Reflect.ownKeys`**, not
  only from `Object.keys` (they are currently non-enumerable, but still listed).
- ⬜ **Make `navigator` / `screen` / `location` / `history` real prototype instances**, so
  `Object.keys(navigator)` is empty, the prototype chain is correct, and
  `navigator instanceof Navigator` holds.
- ⬜ **Timezone coherence** — shim `Date.prototype.getTimezoneOffset` / `toString` /
  `toLocaleString` so `Date` and `Intl` agree on the profile's zone.
- ⬜ **Put canvas/WebGL/audio methods on their prototypes** (not as own properties), and
  expose `PluginArray` / `MimeTypeArray` / `Plugin` types rather than plain arrays.
- ⬜ **`performance.now()` / `timeOrigin` / `performance.timing`** coherent with wall clock.
- ⬜ **Fingerprint regression tests** — snapshot the JS fingerprint and fail the build on
  drift, so hardening never silently regresses.

## Architecture: move detectable surfaces to native (Rust)

Our DOM/stealth is injected JavaScript, which is fast to iterate and gives real JS
semantics — but page-visible methods read as JS source, not `[native code]`, and are
introspectable. Where a native implementation is inherently *more authentic* than a JS
shim, move it to Rust (native functions appear as `[native code]` for free and expose
no readable source). Where JS is the advantage (control of the environment, iteration
speed, no FFI overhead), keep it.

Move to native (Rust):
- ⬜ **`crypto.subtle` (WebCrypto)** — replace the JS shim with real Rust crypto
  (aes-gcm/sha2/hmac/pbkdf2/hkdf), so it is correct, fast, and native-looking. (This is
  what obscura does.)
- ⬜ **Hot / most-probed DOM + graphics methods as native functions** — at minimum the
  ones fingerprinters read (`getContext`, `getParameter`, `toDataURL`, `getImageData`,
  `querySelector`), so `Function.prototype.toString` on them is `[native code]` without
  a masking layer. (Interim: the Phase 6 toString mask above.)

Keep in JS (the advantage is real):
- Environment assembly (navigator/window/screen/timers), the virtual-time event loop,
  and the fetch/XHR queue orchestration — control and iteration speed outweigh a native
  rewrite, and none of it is a `[native code]` tell in the same way.

## Near-term: protocol & DOM completeness (Phase 5)

- 🟡 **CDP registry lifecycle** — honor `removeScriptToEvaluateOnNewDocument` and
  `releaseObjectGroup`; bound per-connection registry growth.
- ⬜ **Puppeteer `page.$` / `$eval` / `$$eval`** — support the injected query utilities
  (currently `page.evaluate()` only).
- ⬜ **CSS selector engine** — descendant/child combinators and attribute operators
  (`^=`, `*=`, `$=`, `~=`) in `querySelector`/`matches`/`closest`.
- ⬜ **`window`-targeted `DOMContentLoaded`** and a more complete event path.
- ⬜ **Playwright compatibility** (`newPage`, its CDP dialect).

## Scaling & concurrency (Phase 7)

- ⬜ **Enforce per-host / per-proxy / global connection limits** in the network layer.
- ⬜ **Per-context cookie isolation** (each context its own jar; no cross-context bleed).
- ⬜ **Context recycling & isolate churn** under sustained 100–1000 concurrent load.
- ⬜ **Navigation task queue + per-proxy concurrency caps** with fair scheduling.
- ⬜ Settle fetches dropped past the per-navigation cap instead of leaving promises pending.

## Testing & benchmarks (Phase 8)

- ⬜ Start-time and per-context memory benchmarks against the < 100 ms / 30–50 MB targets.
- ⬜ A fixture-based WAF-challenge test suite (offline replay of real challenge pages).
- ⬜ Load test: sustained thousand-context throughput and tail latency.

## Packaging & release (Phase 9)

- 🟡 Prebuilt Linux binary + Docker image (`ghcr.io`), built by the tag-triggered
  [release workflow](.github/workflows/release.yml). (macOS/Windows binaries: planned.)
- ⬜ Publish crates to crates.io.
- ⬜ Getting-started guide and API docs on docs.rs.

---

Have a detection you'd like nokk to beat, or a site it fails on? Open an issue with the
fingerprint/challenge details — concrete failures drive the hardening backlog.
