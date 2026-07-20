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
- ✅ **DOM instances expose no own properties.** A real node, event or `document`
  reports `Object.getOwnPropertyNames(…) === []` — ours were leaking their guts
  (`nodeType`, `childNodes`, `parentNode`, `ownerDocument`, `_listeners`, `tagName`,
  `localName`, `_attrs`, `style`, and every `Event`/`MouseEvent` field). All state now
  lives in `__pt`-prefixed backing fields (which the introspection filter already hides)
  behind prototype accessors named so `toString` reads `function get nodeType() {
  [native code] }`. `document`'s `defaultView`/`visibilityState`/`hidden`/`currentScript`
  moved to the prototype too, and the DOM's event constructors are now masked as native.
- ✅ **Canvas output depends on what was drawn.** `toDataURL()` returned one fixed
  string and `getImageData` fixed noise, so an empty canvas and an elaborate drawing
  hashed *identically* — and canvas fingerprinting is precisely a differential probe
  (draw, hash, compare), so that was caught instantly. The 2D context now keeps a real
  pixel buffer: `fillRect`/`clearRect`/`putImageData` render exactly (fill red, read the
  pixel back, get red), and operations we cannot rasterise — text, paths, images — stamp a
  deterministic pattern over the area they cover, derived from the draw-operation log plus
  the per-session seed. So different drawings differ, an identical drawing stays stable
  (which fingerprint consistency needs), and results vary across sessions the way device
  text rendering does. `toDataURL` is a genuine PNG, encoded natively in Rust. Verified
  against the canonical BrowserLeaks canvas routine. (Text/paths are still not truly
  rasterised: a probe checking specific glyph pixels would see synthesised content.)
- ✅ **WebGL readback reflects what was rendered.** Every GL call was a no-op, so
  `readPixels` returned zeroes whatever the scene was and two different renders compared
  equal — the same differential tell as the 2D canvas, and WebGL fingerprints are probed
  just as often. The context now shares the canvas pixel surface: `clearColor`+`clear`
  render exactly (clear to red, read back red), draws stamp a pattern keyed by the shader
  source, geometry and uniforms behind them, and `readPixels`/`toDataURL` read that buffer.
  A canvas also keeps the first context type it was given, so asking for a conflicting one
  returns `null` as a real browser does. The identity surface (vendor/renderer, ANGLE
  `UNMASKED_*`, `MAX_*`, extensions) was already Chrome-shaped and is now pinned too.
- ✅ **Fingerprint regression tests** — a probe asserts the whole surface: no own
  properties on DOM/event/document/navigator instances, no `__pt_*` bridge global
  reachable via `getOwnPropertyNames`/`ownKeys`/`getOwnPropertyDescriptor`/`hasOwnProperty`
  (while staying callable), `webdriver` false and not an own property, `[native code]` for
  every page-visible function and accessor, and intact `instanceof` chains. Verified to
  *fail* on reintroduced drift, so hardening can't silently regress.
- ✅ **`performance` coherent with the wall clock.** Was a bare object with
  `timeOrigin === 0` and `now()` pinned to the virtual-timer clock — trivially caught by
  the standard cross-check. Now a real `Performance` instance (no own properties,
  `[object Performance]`, `instanceof`) whose `timeOrigin` is the context's epoch ms and
  whose `now()` is a monotonic, 0.1 ms-coarsened `DOMHighResTimeStamp` off the same clock,
  so `timeOrigin + now()` tracks `Date.now()` exactly. Adds ordered legacy
  `timing`/`navigation` milestones, Chrome's `memory`, and the `getEntries*`/`mark`/
  `measure` surface; `requestAnimationFrame` now passes a real high-res timestamp.
  Regression-tested (verified to fail on `timeOrigin === 0`).
  (Collapsed virtual-time timers still don't advance the shared clock — a page that times
  its own `setTimeout` sees it fire early; that is inherent to the virtual-time design.)

## Architecture: move detectable surfaces to native (Rust)

Our DOM/stealth is injected JavaScript, which is fast to iterate and gives real JS
semantics — but page-visible methods read as JS source, not `[native code]`, and are
introspectable. Where a native implementation is inherently *more authentic* than a JS
shim, move it to Rust (native functions appear as `[native code]` for free and expose
no readable source). Where JS is the advantage (control of the environment, iteration
speed, no FFI overhead), keep it.

Move to native (Rust):
- ✅ **`crypto.subtle` (WebCrypto) is real.** There was no shim at all —
  `crypto.subtle` was simply *absent*, which every browser on a secure origin exposes, and
  `getRandomValues` was a seeded xorshift rather than randomness. V8 contexts now host
  native Rust bindings ([`natives.rs`](crates/pool/src/natives.rs), the first use of this
  mechanism): SHA-1/256/384/512, HMAC, PBKDF2, HKDF, AES-GCM, AES-CBC and OS randomness.
  On top of them the JS layer exposes real `Crypto`/`SubtleCrypto`/`CryptoKey` interfaces
  (`digest`, `importKey`/`exportKey`, `sign`/`verify`, `encrypt`/`decrypt`,
  `deriveBits`/`deriveKey`, `generateKey`) — promise-based, correct `[object …]` tags, no
  own properties, `[native code]`, and spec-shaped rejections. Pinned by known-answer
  vectors, so a page that digests a known input and checks the result sees what Chrome
  would; verified live in a page using `crypto.subtle` + `TextEncoder`.
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
- 🟡 **Playwright compatibility** (`chromium.connectOverCDP`) — the read *and* interaction
  surface works: `newPage`, `goto`, `evaluate` (with args), `$eval`/`$$eval`, `getAttribute`,
  `textContent`, `content`, `count`, `waitForSelector` (incl. default `visible`), `isVisible`,
  `boundingBox`, **`click`**, and **`fill`**. Connecting took two Chrome-accuracy fixes:
  (1) `Target.createTarget` emits `targetCreated`/`attachedToTarget` **before** the reply
  (Playwright reads `_crPages` the instant it lands); (2) `Runtime.evaluate`/`callFunctionOn`
  run the source as a *script* via indirect `eval` (its IIFE-with-trailing-`;` and
  `//# sourceURL=` forms broke inline splicing). Interaction took the synthetic layout + `Input`
  domain below. A concurrency race was also fixed: overlapping `awaitPromise` evaluates shared
  one global and clobbered each other — each now gets a unique result slot.
  **Still open:** `page.innerText` via the locator API times out (the `$eval`/`textContent`
  paths work), and Playwright's full actionability (stability/occlusion) is only approximated.
- ✅ **Interaction: synthetic layout + `Input` domain.** With no renderer, every rendered
  element gets a deterministic one-row box (`getBoundingClientRect`/`getClientRects`/`offset*`/
  `clientWidth/Height`), and `document.elementFromPoint` reverses a coordinate back to an
  element. On top of that: CDP `DOM.getBoxModel`/`getContentQuads`/`focus`,
  `Page.getLayoutMetrics`, and `Input.dispatchMouseEvent`/`dispatchKeyEvent`/`insertText`, which
  hit-test a point to an element and fire real DOM `pointer`/`mouse`/`keyboard`/`input` events
  (plus `focus`/`activeElement`, `MouseEvent`/`KeyboardEvent`/… constructors, `isConnected`,
  `Node` type constants, and the form-field surface `value`/`type`/`disabled`/…). Verified live:
  Puppeteer `click`+`type` and Playwright `click`+`fill`+`isVisible` drive a real page.

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
- ✅ **Per-context identity: proxy + cookie jar per context.** Clients keyed by identity
  (the Puppeteer browser-context id) so contexts are cookie-isolated even when they share
  or omit a proxy; `Engine::new_context_with_identity(id, proxy)` /
  `new_context_with_proxy(proxy)`. Exposed via CDP
  `Target.createBrowserContext({ proxyServer })` + `createTarget({ browserContextId })`
  (`browser.createBrowserContext({ proxyServer })` in Puppeteer). Verified end-to-end.
- ✅ **Persistent / named sessions — warm up once, resume anytime.** Give a session a name
  and its cookie jar (incl. session-only cookies and `cf_clearance`) persists to
  `<store>/<name>.json`, so a session warmed up once (log in, clear a challenge) re-attaches
  later — a fresh context *or a new process* — instead of re-solving every run. A
  serializable [`SessionJar`](crates/net/src/session.rs) (implements wreq's `CookieStore`)
  backs the client; `Engine::new_context_with_session(name, proxy)` loads it on first use and
  it flushes to disk when a session context closes (or via `Engine::save_session`). Driven
  over CDP by naming a browser context —
  `Target.createBrowserContext({ sessionName, proxyServer })` — and enabled with
  `--session-store <dir>` (`NOKK_SESSION_STORE`). Verified end-to-end: a cookie warmed in one
  process resumes in a *restarted* process, and distinct session names stay isolated.
  (Follow-up: CDP `Network.getCookies`/`setCookie` for manual save/restore from page code.)
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
