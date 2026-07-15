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
- ✅ **Hide engine internals from all introspection** — `__pt_*`/`__out` are filtered out
  of `Object.getOwnPropertyNames`, `Reflect.ownKeys`, `Object.keys`,
  `getOwnPropertyDescriptor(s)` and `hasOwnProperty` (and kept non-enumerable), while
  staying callable by name. Filters read native (#1). Regression-tested.
- ✅ **`navigator` / `screen` / `location` / `history` are real prototype instances** —
  `Navigator`/`Screen`/`Location`/`History` constructors exist, all properties are getters
  on the prototype, so `Object.keys(navigator)` is `[]`, the prototype chain and
  `constructor` are right, `instanceof` holds, and `webdriver` is a prototype getter (no
  own descriptor). Getters read native (#1). Regression-tested.
- ✅ **Timezone coherence** — a DST-aware `Date` shim derives `getTimezoneOffset`, the
  local getters, and `toString`/`toDateString`/`toTimeString`/`toLocale*` from the
  profile's UTC offset (US/EU DST rules), so `Date` and `Intl` always agree instead of
  `Date` leaking V8's process (UTC) zone. Methods read native (#1). Regression-tested.
- ✅ **`PluginArray` / `MimeTypeArray` / `Plugin` / `MimeType` types** — `navigator.plugins`
  and `mimeTypes` are real typed instances (`Object.prototype.toString` tag, `instanceof`,
  named access + iterator), entries are `Plugin`/`MimeType`; `connection.type` (mobile-only)
  removed. Methods read native (#1). Regression-tested. (Canvas/WebGL method-on-prototype
  placement still open.)
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
- ✅ **Puppeteer `page.$` / `$eval` / `$$eval`** — work now. The blocker was
  `Runtime.getProperties` reporting non-enumerable props (an array's `length`) as
  enumerable, which made Puppeteer's query-iterator drain loop forever; it now reports
  real descriptor flags. Verified end-to-end against `page.$`/`$eval`/`$$eval`.
- ✅ **CSS selector engine** — attribute operators (`^= $= *= ~= |= =`) parse correctly,
  and `matches()`/`closest()` honor descendant/child combinators (right-to-left match with
  backtracking) instead of testing only the rightmost compound. `querySelector`/`All`
  already handled combinators. Regression-tested. (Sibling `+`/`~` and `:pseudo` classes
  still unimplemented.)
- ✅ **`document.write` / `writeln`** — insert parsed markup at the calling script's
  position (`document.currentScript` tracked per script), so the classic
  `<script>document.write(x)</script>` idiom populates in place instead of no-op'ing.
  (Dynamically written `<script>` tags are inserted but not executed.)
- ⬜ **`window`-targeted `DOMContentLoaded`** and a more complete event path.
- ⬜ **Playwright compatibility** (`newPage`, its CDP dialect).

## Scaling & concurrency (Phase 7)

Measured on a real 208-site sweep (8-core box): after the CDP concurrency fix the engine
loads real sites at **~88% OK when concurrency ≤ worker count** (avg 1–4 s), but degrades
to ~49% when hammered at concurrency 10 on 8 workers — pure contention, not per-site
weight. Current guidance: keep client concurrency ≤ `--workers`. The items below lift that
ceiling.

- ✅ **`Target.createTarget` runs off the read loop.** It spawns `new_context()` and hands
  the finished target back through a registration channel; the read loop (a `select!` over
  frames + registrations) registers it. No inline await → effective concurrency scales
  cleanly to `--workers` (a 24-site sweep at concurrency 8 held ~88%, vs the old collapse).
- ✅ **Per-context identity: proxy + cookie jar per context.** `Engine::new_context_with_proxy`
  selects a per-context client, pooled by proxy (contexts sharing a proxy share one pool +
  cookie jar). Exposed via CDP `Target.createBrowserContext({ proxyServer })` +
  `createTarget({ browserContextId })` — i.e. `browser.createBrowserContext({ proxyServer })`
  in Puppeteer. Verified end-to-end.
- ⬜ **Enforce per-host / per-proxy / global connection limits** in the network layer.
- ⬜ **Context recycling & isolate churn** under sustained 100–1000 concurrent load.
- ⬜ **Navigation task queue + per-proxy concurrency caps** with fair scheduling.
- ⬜ Settle fetches dropped past the per-navigation cap instead of leaving promises pending.

## Testing & benchmarks (Phase 8)

- 🟡 Start-time and per-context memory measured (8-core Linux): ~4 ms engine start, ~20 MB
  idle, ~0.5 MB/context (100 contexts ≈ 65 MB) — well past the < 100 ms / 30–50 MB targets.
  A committed, repeatable benchmark harness is still to come.
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
