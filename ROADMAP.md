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
| 5 | CDP WebSocket server (Puppeteer + Playwright: connect / navigate / evaluate / cookies / Network events) | 🟡 |
| 6 | JS-level stealth (canvas/WebGL/audio, `window.chrome`, hardening) | 🟡 |
| 7 | Scaling & concurrency (100–1000 contexts under a memory ceiling) | ⬜ |
| 8 | Testing, benchmarks, fingerprint regression suite | 🟡 |
| — | Performance: less memory and faster than Chrome on the same machine | 🟡 |
| 9 | Packaging & release (crates.io, Docker, prebuilt binaries) | 🟡 |

## Cloudflare challenges ✅

As of v0.1.28-alpha nokk clears Cloudflare on its own, headless, with no
selectors from the user: the managed "Just a moment…" interstitial (with or
without the checkbox), the interactive interstitial that wants a press, and
Turnstile widgets embedded in a site's own page (interaction-only, managed and
non-interactive). The five public targets in [`tools/cf-check.sh`](tools/cf-check.sh)
pass on every run.

- ✅ **Solver in the core** (`BrowserContext::solve_challenge`, `challenge_state`):
  it finds the widget inside its closed shadow root in a cross-origin frame and
  presses it the way a person would; a driver only gives a time budget.
- ✅ **Every entry point uses it.** CLI `--solve-challenge`; CDP server
  `--auto-solve` (or `autoSolve` per browser context) so `page.goto()` returns the
  page behind the challenge; `Nokk.solveChallenge` / `Nokk.challengeState` on
  demand and a `Nokk.challenge` event; npm `launch({ autoSolve })` +
  `solveChallenge(page)`; Python `launch(auto_solve=…)` + `solve_challenge(page)`;
  the MCP server solves during `open` by default.
- ✅ **What it took**, in short: the challenge's report had to match Chrome field by
  field — Trusted Types in the challenge's sandbox, `history.replaceState`
  rules, error stacks, the widget's layout and the click's coordinates, and
  resource timing that hides cross-origin detail without `Timing-Allow-Origin`.
- ⬜ Other vendors: DataDome is recognised (`challengeState` names it) but not
  solved; other widgets get at most their checkbox pressed.

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
- ✅ **Audio output depends on the graph.** `OfflineAudioContext.startRendering()`
  returned a fixed sine keyed only on the session seed, so a 10 kHz oscillator and a 440 Hz
  one rendered identically — the same differential tell as canvas/WebGL, and audio is the
  third classic fingerprint (FingerprintJS/CreepJS render an oscillator through a compressor
  and hash the samples). Nodes now record their `AudioParam`s, connections are tracked, and
  the rendered buffer is synthesised from the actual graph: the oscillator's waveform at its
  frequency/type, shaped by any compressor, plus per-session jitter. `AnalyserNode`'s
  frequency/time data derive from the graph too, `oncomplete` fires (async, as the classic
  routine waits on) alongside the promise, and the interfaces carry the right
  `[object AudioContext]` tag. Different graphs differ, an identical graph is stable.
  Verified live against the FingerprintJS routine. (Not a real DSP: the compressor is a
  soft-clip approximation, so a probe modelling exact ScriptProcessor output would diverge.)
- ✅ **Fingerprint regression tests** — a probe asserts the whole surface: no own
  properties on DOM/event/document/navigator instances, no `__pt_*` bridge global
  reachable via `getOwnPropertyNames`/`ownKeys`/`getOwnPropertyDescriptor`/`hasOwnProperty`
  (while staying callable), `webdriver` false and not an own property, `[native code]` for
  every page-visible function and accessor, and intact `instanceof` chains. Verified to
  *fail* on reintroduced drift, so hardening can't silently regress.
- ✅ **Tracker/ad/analytics blocking.** Subresource requests (external scripts,
  `fetch`/XHR) to ~3.5k known ad/analytics/tracker domains (Peter Lowe's list) are dropped
  before they hit the wire, so those scripts never load or run — trimming the passive
  fingerprinting surface a page can probe us with, and speeding loads. Matches exact host +
  parent domain; on by default (`--allow-trackers` / `NOKK_ALLOW_TRACKERS` to disable).
  Deliberately *not* an anti-bot-vendor list (DataDome/PerimeterX/hCaptcha/Cloudflare must
  run to hand out a token). Verified: a page's `google-analytics.com`/`doubleclick.net`
  scripts fetch 0 bytes with blocking on, the real 52 KB/116 KB files with it off.
- ✅ **`performance` coherent with the wall clock.** Was a bare object with
  `timeOrigin === 0` and `now()` pinned to the virtual-timer clock — trivially caught by
  the standard cross-check. Now a real `Performance` instance (no own properties,
  `[object Performance]`, `instanceof`) whose `timeOrigin` is the context's epoch ms and
  whose `now()` is a monotonic, 0.1 ms-coarsened `DOMHighResTimeStamp` off the same clock,
  so `timeOrigin + now()` tracks `Date.now()` exactly. Adds ordered legacy
  `timing`/`navigation` milestones, Chrome's `memory`, and the `getEntries*`/`mark`/
  `measure` surface; `requestAnimationFrame` now passes a real high-res timestamp.
  Regression-tested (verified to fail on `timeOrigin === 0`).
- ✅ **Timers wait out their real delays.** They used to collapse: a virtual clock jumped
  to each due time, so `setTimeout(fn, 4000)` returned instantly while `Date.now()` kept
  wall time. Measured on the old build: `setTimeout(…, 500)` fired in **0 ms**,
  `setInterval(…, 900)` ticked **150 times in 2 s**, `requestAnimationFrame` ran at
  ~4000 fps. Any page that times itself caught us in one line, and watchdogs simply broke
  — Cloudflare's Turnstile gives its widget 46 ticks of a 900 ms interval to answer, and
  we burned all 46 in a millisecond, so `api.js` declared the widget hung (error
  **300030**), reloaded it as `crashed_retry`, and looped: 48 367 errors and 364 iframes
  in six seconds. Now the queue is due-time based (`__pt_runNextTimer` runs only what is
  due, `__pt_nextTimerDelay` tells the driver how long to sleep), with Chrome's
  nested-timer clamp. `NOKK_FAST_TIMERS=1` restores collapsing for bulk scraping of pages
  that don't watch the clock. Regression-tested.
- ✅ **A frame gets turns while the page is busy, and connects with its subtree.** Two
  defects that only showed together. Frames were pumped only once the page went idle, and
  a page with any `setInterval` never goes idle — so a widget in an iframe never ran. And
  a frame only became a browsing context if the `<iframe>` itself was the node inserted:
  Turnstile builds its iframe inside a *detached* closed shadow root and inserts the host,
  so the frame stayed inert, `contentWindow` unreachable, forever. Frames now pump on a
  clock of their own (20 ms) and every frame in an inserted subtree connects (shadow trees
  included). The queued frame ops are capped too — the same widget once drove RSS past
  **5 GB** and the process was killed. Regression-tested.
- ✅ **Tree traversal, the document's collections, and `blob:` URLs.** With the above fixed,
  the Turnstile widget still said nothing — and the reason was a single missing global.
  Its loader answers the widget's `requestExtraParams` with a page report that walks the
  document through `createTreeWalker`; `NodeFilter is not defined` threw *inside a `message`
  listener*, where the exception is swallowed by design, so the reply was never sent and the
  widget waited forever, answering heartbeats and explaining nothing. Added `NodeFilter`,
  `TreeWalker`, `NodeIterator`, `createTreeWalker`/`createNodeIterator`, the document
  collections the same report reads (`scripts`, `forms`, `images`, `links`, `anchors`,
  `embeds`, `styleSheets`) and a string `document.referrer`. Behind that came the next one:
  `URL.createObjectURL` handed out a fabricated URL with no registry, so `fetch(blobUrl)`
  reached the network client and failed with *invalid authority* — and the challenge builds
  its payload as a Blob and reads it back. `blob:` and `data:` are now answered from the
  page's own memory. The challenge runs end to end after this: it takes its parameters,
  starts its VM and opens its POST to the challenge platform. Regression-tested.

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
- 🟡 **Hot / most-probed DOM + graphics methods as native functions** — deprioritized:
  an empirical probe (2026-08) shows the Phase-6 toString mask already reports
  `[native code]` for `getContext`/`querySelector`/`getParameter` and survives the
  self-reference bypass (`Function.prototype.toString.call(toString)`), so moving them to
  native Rust is marginal. The measured real tell was missing Web Workers — now **fixed**.
- ✅ **A worker is a context, not a shim.** `typeof Worker === "undefined"` was the
  one real remaining passive tell, and the shim that answered it was worse than the
  gap: it ran the worker's code in the page's own realm under `with(self)`, so a
  fingerprint collected in there found `document`, `window`, `localStorage` and the
  page's `Navigator` — a "worker" no browser has ever produced. A worker now gets a
  V8 context of its own, shaped into a worker global before a line of its code runs
  (334 own names, `DedicatedWorkerGlobalScope` → `WorkerGlobalScope` → `EventTarget`,
  `WorkerNavigator`, `WorkerLocation`), with its own timers, its own `fetch`, and a
  port that delivers each message exactly once. Frames start workers of their own —
  which is where a challenge collects — and a worker ends when it calls `close()`,
  when its frame goes, or when the page navigates. `OffscreenCanvas` maps to a
  detached `<canvas>`, reusing its 2D/WebGL contexts. `SharedWorker` is real too
  (`SharedWorkerGlobalScope`, `connect`, a port), one instance per page; it is not yet
  shared between pages of the same origin.
- ✅ **`WebSocket` in the page.** Was the top gap in both senses: a socket-driven
  app loaded, executed and then silently did nothing, while `typeof WebSocket ===
  'undefined'` separated us from every browser since 2011 in one line. Now real, per
  [docs/websockets.md](docs/websockets.md): the socket lives in Rust
  (`crates/net/src/websocket.rs`, one task each over wreq's `client.websocket()`, so
  the upgrade carries the *same* JA3/JA4, cookie jar and proxy as every fetch — two
  fingerprints from one "browser" would have been a louder tell than none), the
  spec surface in JS, and the two meet through the queue/callback seam `fetch`
  already uses. The load-bearing change was the event loop: an open socket now means
  "not idle", frames arrive unprompted, and a 50 ms tick in the CDP server pumps
  *only* pages holding a socket — bounded at 64 sockets per page and 256 frames per
  round so one context can't monopolise a shared worker. Attributes are prototype
  accessors, so `Object.keys(ws)` is `[]` and everything reads `[native code]`.
  Tested against an in-process echo server (open → send → echo → server push →
  clean 1000) and a dead port (`error` then `close` 1006). Left: `bufferedAmount`,
  overflow backpressure, and CDP `Network.webSocket*` events (P1), then
  `EventSource` (P2).
- 🟡 **Optional real rendering (`render` / `webgl` Cargo features)** — off-screen
  **rasterization** bridged via `natives.rs`, **off by default** so the standard build stays
  light and a feature build produces genuine pixels for harder anti-bot. `render` (2D, done):
  tiny-skia + `ab_glyph` fills, glyph text, vector paths, gradients, image data — only
  `drawImage` still stamps. `webgl` (done): a real headless GL context (surfaceless EGL +
  Mesa) behind `getContext('webgl')` — shaders, buffers, uniforms, draws, textures,
  render-to-texture framebuffers, `readPixels`; `getParameter`/extensions stay synthesized so
  the reported GPU string never contradicts llvmpipe's pixels. On by default in the
  release binary; Cloudflare reads the canvas blocks and they match Chrome byte for
  byte. Full spec:
  [docs/rendering.md](docs/rendering.md).

Keep in JS (the advantage is real):
- Environment assembly (navigator/window/screen/timers), the event loop,
  and the fetch/XHR queue orchestration — control and iteration speed outweigh a native
  rewrite, and none of it is a `[native code]` tell in the same way.

## Near-term: protocol & DOM completeness (Phase 5)

- 🔲 **Origin of srcdoc and about:blank frames.** A `srcdoc` frame inherits its
  parent's origin in Chrome (`http://host`); nokk reports `null`, so IndexedDB is
  refused inside it with a SecurityError.
- 🔲 **Named properties of the document and the window.** A form answers its controls
  by name and index as in Chrome, and `document.forms`, `images`, `links`, `embeds`,
  `scripts`, `anchors` and `select.options` by name; but `document.login` (a form,
  image, embed or object by name), `window.someId` (any element by id) and named
  members of `children` and `getElementsByTagName` are undefined. `document.forms`
  is a new list on every read (`document.forms === document.forms` is false), and
  a strict-mode `form[0] = x` is ignored where Chrome throws.

- ✅ **A fresh global per document.** Every navigation builds a new V8 context, so
  one page's `var`s and patched built-ins no longer show through on the next.
  `localStorage`, `sessionStorage` and IndexedDB are carried per origin, as Chrome
  keeps them (they had been one store shared by every site a tab visited), along
  with the tab's history length.
- ✅ **Documents the page moves to by itself reach the client.** A form the page
  submits, a challenge that clears, a script that sets `location`: the CDP server
  announces the new document (`frameNavigated`, fresh contexts), so Playwright's
  `page.url()` / `page.title()` and Puppeteer's handles follow it. Handles into a
  document the page has left are refused as Chrome refuses them.
- ✅ **Current clients connect.** Puppeteer 25 (`Audits.enable`, a CDP session looked
  up the moment `attachToTarget` replies) and Playwright 1.58–1.63
  (`Browser.getWindowForTarget`).

All four entries below came from a field report against a live Akamai-protected,
WebSocket-driven app — the run where nokk *cleared a challenge headless Chrome
failed* and then couldn't use the session. All are now closed, each verified
against live Puppeteer and Playwright.

- ✅ **Unimplemented CDP methods say so.** The dispatcher ended in `_ => ok(id, {})`,
  so anything nokk did not implement returned an empty *success* — indistinguishable
  from "nothing to report", which is why a client waited forever or crashed on a
  shape that never came. This was the root cause behind the three below. Unknown
  methods now answer `-32601` as Chrome does, unknown sessions `-32001`, and an
  explicit allow-list keeps the configure-only calls (which a client sends for
  effect and ignores) as honest no-ops. The list was built from traces of both
  clients driving a full session.
- ✅ **`Network` domain emits events.** `requestWillBeSent` / `responseReceived` /
  `loadingFinished` (and `loadingFailed` for a request that never got a response),
  published from the engine's existing request log. Two Chrome behaviours had to
  match exactly for a client to make sense of them: a navigation's document request
  carries the same id as its loader, and that loader id is the one `Page.navigate`
  reported. With both, Playwright's `page.goto()` returns a real response instead
  of `None`.
- ✅ **`Network.getCookies` / `Storage.getCookies` return real cookies**, HttpOnly
  included — the only way to export a warmed session. The jar used to be
  unreachable by construction (wreq's internal store); every client now keeps one
  we own. Playwright asks at browser level, with no session, so that form is
  answered before per-page dispatch.
- ✅ **`/json`, `/json/list`** list the real pages, following navigation and
  disappearing with the connection that owns them; **`/json/new`** says plainly that
  it cannot create one rather than answering `[]`.
- ✅ **`Target.attachToBrowserTarget` / `attachToTarget`.** The first returned no
  session id, so Playwright's `new_cdp_session` registered `undefined` and killed
  its driver; the second reused the page's existing session and announced it at
  root, so a second attach built a duplicate session object and replies landed on
  the wrong one. Each attach now mints a fresh session, announced on the session
  that asked, and a page resolves commands arriving on any of its sessions.
- 🟡 **CDP registry lifecycle** — honor `removeScriptToEvaluateOnNewDocument` and
  `releaseObjectGroup`; bound per-connection registry growth.
- ✅ **Puppeteer `page.$` / `$eval` / `$$eval`** — work now. The blocker was
  `Runtime.getProperties` reporting non-enumerable props (an array's `length`) as
  enumerable, which made Puppeteer's query-iterator drain loop forever; it now reports
  real descriptor flags. Verified end-to-end against `page.$`/`$eval`/`$$eval`.
- ✅ **CSS selector engine** — attribute operators (`^= $= *= ~= |= =`) parse correctly,
  and `matches()`/`closest()` honor descendant/child combinators (right-to-left match with
  backtracking) instead of testing only the rightmost compound. `querySelector`/`All`
  already handled combinators. Regression-tested. Sibling combinators, structural and
  state pseudo-classes, `:is()`/`:where()`/`:not()`/`:has()` followed.
- ✅ **`document.write` / `writeln`** — insert parsed markup at the calling script's
  position (`document.currentScript` tracked per script), so the classic
  `<script>document.write(x)</script>` idiom populates in place instead of no-op'ing.
  A `<script>` written this way runs.
- ✅ **The event path as in the DOM spec.** Listener options (`once`, `passive`,
  `signal`, `handleEvent`), one listener per callback, removal during dispatch;
  `DOMContentLoaded` reaches a window listener once, by bubbling from the document; an
  uncaught error is one trusted `error` event and `window.onerror` gets its five
  arguments; `MessagePort`, `BroadcastChannel` and `WebSocket` dispatch real events.
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
- ✅ **Per-context coherent fingerprint profiles (rotation).** Requested in
  [#1](https://github.com/koloss777/nokk/issues/1) — done. Rotates the *whole* fingerprint
  per browser context, not just the User-Agent: a context's identity (the Puppeteer
  browser-context id the CDP layer already threads in) deterministically selects a
  [`FingerprintProfile`](crates/stealth/src/lib.rs) preset, and that one choice drives a
  matched set of `{ wreq TLS emulation OS + UA + navigator.userAgentData + sec-ch-ua +
  platform + screen + hardwareConcurrency + WebGL }` where every layer agrees. Naive UA
  rotation is a *net negative* — a UA that doesn't match the TLS/JA3 handshake or the client
  hints is itself a documented detection signal — so the TLS emulation OS is derived from the
  chosen profile, never contradicting the UA. Ships three hand-verified coherent presets
  (Chrome/Linux, Chrome/Windows, Chrome/macOS); opt-in via `EngineConfig.rotate_fingerprint`
  (`--rotate-fingerprint` / `NOKK_ROTATE_FINGERPRINT`), off by default so single-context runs
  stay deterministic. The default (empty-identity) context keeps the engine default so its
  shared client stays coherent. End-to-end: `browser.createBrowserContext()` yields a
  self-consistent, distinct machine per context. Timezone/locale are derived from the proxy's
  geoIP (opt-in `--geoip-timezone` / `NOKK_GEOIP_TIMEZONE`): one lookup per proxy, made
  *through* that proxy and cached, moves a context's `Intl` timezone + `navigator.languages`
  to match its exit IP (a mismatch is a documented tell — a technique clearcote uses).
  Best-effort: a failed lookup or an uncarried zone keeps the profile's coherent default.
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
- ✅ No fetch is dropped past a per-round cap: a round's requests all go out, in
  batches, and each answer reaches the page as it arrives.

## Performance: lighter and faster than Chrome

The goal: on the same machine, every page nokk loads costs less memory **and is ready
sooner** than in Chrome 151. Memory is already ahead; speed is not, on heavy pages.

Measured 2026-10-12 with [`tools/bench/bench.py`](tools/bench/bench.py) on an 8-core Linux
box at load average ~2: median of three runs, peak PSS of the whole process tree (for
Chrome only its own processes) and wall time from start to a loaded page, nokk against
Chrome 151 headless. The early-October baseline is in brackets.

| Page | nokk memory | Chrome memory | nokk time | Chrome time |
|---|---|---|---|---|
| example.com | 76 MB (74) | 318 MB | 0.4 s (0.3) | 1.6 s |
| Hacker News | 92 MB (82) | 378 MB | 1.4 s (1.2) | 2.3 s |
| Wikipedia article | 338 MB (245) | 464 MB | 5.1 s (5.4) | 2.2 s |
| github.com | 281 MB (200) | 525 MB | 4.6 s (5.5) | 2.5 s |
| bbc.com/news | 294 MB (395) | 624 MB | 9.0 s (10.6) | 5.9 s |

Memory is still well under Chrome everywhere. Wikipedia and GitHub gained 80–90 MB on
the baseline: the load event now waits for fonts, as in Chrome, so the cascade is built
during load (the early-October build never built it on GitHub). That cost has since been
cut by 25–50 MB per page (below).

### Memory

- ✅ **A JS context costs 4.0 MB, was 8.3.** Every page, frame, worker and challenge
  sandbox is one. The loader's functions read as native through one script mark instead
  of a registry; stubs share one value store and get one function each instead of a
  stub plus a guard; data tables reach templates as `JSON.parse` (literals kept a
  boilerplate copy and allocation sites); load-time tables are released when their
  layer ends. A Cloudflare interstitial solve peaks at ~400 MB (Chrome ~720 MB).
- ✅ **Heavy pages keep styles between layout passes**, collect under memory pressure, and
  spare frames follow demand (a large Elementor page: live heap 197 → 128 MB).
- ✅ **No runaway allocation on facebook.com / instagram.com.** The layout memo stored a
  subtree's nodes with duplicates, doubling at each flex level. Held open for 40 s, both
  pages now stay flat at ~320 MB and drop to ~240 MB once idle.
- ✅ **CSS rules cost nothing until read.** A rule keeps its source text; its
  declarations, selector and `cssText` are built on first use, and rules and sheets
  carry no own properties (as in Chrome). GitHub's 15,000 rules: 0.6 s → 0.09 s.
- ⬜ **Lazy interfaces, as in Blink.** Build an interface's prototype and its members on
  first access rather than all ~1000 at context creation; the floor now is ~110 bytes per
  member function. Target: under 2 MB per context.
- ⬜ **Per-page heap on heavy pages** (target: half of Chrome's): DOM nodes as fewer JS
  objects, subresource bodies not kept after use, script sources dropped once compiled.
- ⬜ **Backpressure**: new contexts wait while the machine is low on memory instead of
  pushing it into the OOM killer.

### Speed

Done:
- ✅ **Layout kept between passes.** A mutation marks its subtree dirty and only that is
  laid out again; subtrees move by offsets settled once per pass instead of being copied
  at every level. Wikipedia: a mutation plus layout 2.6 s → 13–42 ms, a full layout
  2.9 s → 1 s.
- ✅ **`:has()` invalidation.** A mutation restyles only the anchors a `:has()` argument
  can match, keyed by tag, class, id and attribute (azure.microsoft.com: full drops per
  pass 43 → 2).
- ✅ **Rule index.** Rules are bucketed by the id, class, tag or attribute of their
  rightmost compound, `:is()`/`:where()` by their arguments' keys; elements alike in tag,
  id, classes and attribute names share one candidate list; an ancestor Bloom filter
  rejects most of the rest. Computed style is live and lazy (values on read, layout only
  for sizes).
- ✅ **`window.length` / `frames[i]`** read a live list of frames (20,000 reads:
  3973 ms → 1 ms).
- ✅ **The engine reads node fields directly.** Its own style, selector and layout code went
  through the page-facing accessors (with their brand checks): 5.6 million calls per
  GitHub load, now 0.18 million.
- ✅ **Requests go out when asked.** A round's requests leave before its scripts and
  `import()` chunks, requests queued while the document's scripts run leave between them,
  and `import()` roots load in parallel.
- ✅ **IndexedDB in Rust, timers in a heap, messages as engine tasks** (10,000 port
  messages in 35 ms, were 2,000 in 11.5 s).
- ✅ **Less matching per element.** The ancestor filter holds tags and attribute names as
  well as ids and classes (1024 bits) and reads ancestors past `+`/`~`; rules that cannot
  match here (pseudo-elements, states the engine never has) are no candidates. GitHub:
  rules passing the filter 161,000 → 68,000 per load, matched set unchanged.
- ✅ **Style sharing between alike siblings**: one cascade for siblings with the same tag,
  id, classes and attributes when the few rules that could tell them apart (position,
  `+`/`~`, `:empty`, focus, form state) agree for each of them.
- ✅ **Targeted restyles.** An added or removed sheet restyles only the elements its rules
  are keyed by (as Blink's rule-set invalidation), unless a rule has no key or `:has()`;
  a focus change restyles the elements losing and gaining focus (it restyled nothing
  before: `input:focus` did not apply after `focus()`).
- ✅ **`compareDocumentPosition` by ancestor chains** instead of a walk over the whole
  tree per call (jQuery's sort on Wikipedia was quadratic: 0.3 s of a load).
- ✅ **Fewer full restyles.** A sheet whose rules have no key (`.a > *`) restyles the
  elements those rules match now; keyed `:has()` rules restyle by their key; rules that
  never match here change nothing; defining a custom element restyles its elements, and
  only when a rule reads `:defined` (it restyled everything, or nothing until the next
  mutation: `x-a:not(:defined)` kept applying after `define`); `:has(~ x)` walks each
  parent's children once per pass instead of giving up past 64 siblings (GitHub's
  `<head>` has more, so every inserted `<style>` restyled the page). Ten added sheets on a
  saved Wikipedia article: 108,000 cascades and 2.3–3.6 s → 9,000 and 0.6–0.8 s.
- ✅ **No style objects for the engine's own reads.** The cascade and the box test read a
  `style` attribute parsed by its text (shared between alike elements), not a page-facing
  declaration with 700 properties built for each element; rule gathering keeps each
  rule's split selectors and specificities.
- ✅ **A change restyles what the rules read.** Matching marks a parent whose children
  were tested by position (`:first-child`, `:nth-*`) or by sibling (`+`, `~`), and an
  element tested with `:empty`; an inserted child restyles alone unless its parent is
  marked (every `appendChild` into `<body>` restyled the page). A class, id or `data-*`
  that no rule names restyles nothing (a class on `<html>` cost a full restyle and
  relayout: 300 ms on a saved Wikipedia article, 250–430 ms on GitHub; now 35 and 7 ms).
  A changed rule recomputes the elements it is keyed by, and their subtrees only when
  the result differs. Live bbc.com/news: 10,000 cascades to 4,600.
- ✅ **A restyle stops where nothing below changed.** An element whose own matching
  changed (a class on `<html>` named in a subject, a shifted sibling, a changed rule)
  is cascaded again at once; below it only cascades that copy a parent value or read
  variables are recomputed, and only when its result differs (Blink's local vs
  subtree style change). A class on an ancestor restyles the elements the rules
  naming it select; a shifted sibling restyles itself and the elements that rules
  reading positions left of their subject select (`li:first-child a`); a `:root`
  variable change leaves cascades that do not read variables alone. Flipping classes
  on `<html>` and inserting siblings on a saved Wikipedia article with such rules:
  145,000 cascades and 4.7–5.8 s to 17,000 and 1.5–1.7 s; live Wikipedia load 95,000
  dropped styles to 10,000.
- ✅ **`selectorText` as Chrome prints it.** A serializer instead of regexes: attribute
  values double-quoted, An+B shortest, names re-escaped, pseudo and type names
  lowercased, comments dropped. The old one spaced `~=` like a combinator, so
  `[typeof~='mw:File/Thumb']` never matched (Wikipedia's figures were not tables) and
  each such rule restyled the whole page when added.
- ✅ **Markup is parsed by the HTML parser.** `innerHTML`, `outerHTML`,
  `insertAdjacentHTML`, `document.write` and `DOMParser` used a hand-written JS tokenizer
  (40 named references, `<` inside `<script>` read as a tag, no foster parenting or
  adoption agency): 21 of 31 tricky snippets built a tree unlike Chrome's. They now go to
  html5ever with the right context element and quirks mode, all 31 as in Chrome 151;
  `DOMParser` keeps the doctype, comments and mode; the page's own document keeps the
  comments and processing instructions around its root. The parse is written as JSON
  directly (a `serde_json::Value` tree first cost 300 ms on a 1.2 MB article): a saved
  Wikipedia article loads in 1.24 s of CPU instead of 1.49. `<?target data?>` is a
  processing instruction as in Chrome 151 (`vendor/html5ever`, see its PATCHES.md), with
  `createProcessingInstruction` and the data read as attributes.
- ✅ **Text nodes, observers and serialization as in Chrome.** `CharacterData`'s
  `appendData`/`insertData`/`deleteData`/`replaceData`/`substringData` and `Text`'s
  `splitText`/`wholeText` were stubs; `MutationObserver` reported no text changes, gave
  every observer the old value, wrote to the page's options object, built plain objects
  instead of `MutationRecord`s, swallowed callback errors, missed removed subtrees and
  kept every observer forever; `moveBefore` did nothing; `document.doctype` had ten own
  properties; script and style text was escaped in `innerHTML` and U+00A0 was not.
- ✅ **Deep trees answer as in Chrome.** Layout goes 64 levels per band and lays out
  what lies below from a shallow stack into the kept layouts (467 nested blocks threw
  RangeError; Chrome's tab crashes at 2,500); cascades, ancestor filters, inherited
  values, `textContent`, `innerHTML`, `cloneNode`, tree queries and rule gathering
  walk without a frame per level (Chrome answers at 20,000 levels; we overflowed at
  1,500-4,500); a 10,000-step cap left deeper elements without style. Inserting a node
  under itself or a descendant throws `HierarchyRequestError` in every insertion method
  with Chrome's wording (`insertBefore`, `replaceChild` and the convenience methods made
  a cycle that hung the engine); `isConnected` is remembered for the last nodes, so a
  20,000-deep chain builds in 0.2 s instead of 7.5 and clones in 0.2 s instead of 15.7.
  `textContent` skips comments, as in Chrome.
- ✅ **A layout is a third cheaper.** A kept layout is a tree (the element's result and
  its children's entries) instead of a flat copy of the whole subtree per element:
  228,000 records for 12,800 elements on a Wikipedia article. Font sizes fold down
  from the parent's instead of walking every ancestor per element; lengths are
  parsed once per value text; word widths are kept per font, then per word. The one
  layout a live Wikipedia load needs (to find the lazy images in view): 416 to 292 ms;
  peak memory 350 to 328 MB.

Open:
- ⬜ **Processing instruction attributes come in source order**; Chrome keeps them in a
  hash map (rapidhash over WTF's open addressing), so with two or more its
  `getAttributeNames()` order differs (`a="1" c="2"` gives `c, a`).
- ⬜ **Lone surrogates in markup become U+FFFD**: `innerHTML` and `DOMParser` hand the
  string to the parser as UTF-8; Chrome keeps them.
- ⬜ **Layout differences found on a font-size page** (Chrome 151, same page): text
  before a block child makes no line (`<div>a<div>b</div></div>` is 34px shorter);
  a `0.67em` heading margin is not snapped to 1/64 px, so later boxes sit off the
  grid and move by 36.988 instead of 37 when a 37px block is inserted above; `<pre>`
  under a `calc()`-sized 26px parent is 13px (Chrome 26px); `font-size` prints 4
  decimals (`8.3333px`, Chrome `8.33333px`).
- ⬜ **Matching is still the cascade's main cost** (GitHub ~0.08 ms per element, Chrome
  well under that); siblings differ in attribute values often enough (links) that
  sharing reaches a few percent of elements. Next: a matched-properties cache (one
  computed result per matched rule set and parent), then native matching.
- ⬜ **Two cascade differences found on the way, both older than this work:** a percentage
  `max-width` on a GitHub image differs between an incremental and a full style pass,
  and a sheet inserted before the others with only `@layer b, a;` reorders layers here
  but not in Chrome 151 (which keeps the old order until reload).
- ⬜ **Style, selectors and layout in Rust.** They run in JS on one thread today; native
  data structures and parallel style would close most of the gap to Chrome on heavy
  pages. A large change, planned after the current release line settles.
- ✅ **A committed benchmark**: [`tools/bench/bench.py`](tools/bench/bench.py) loads fixed
  pages in nokk and Chrome on the same machine and prints the table above. Left: run it
  for every release.
- ✅ **Why Wikipedia and GitHub took 80–90 MB more than in early October.** The cascade
  is now built during load. Its parse kept the parser's scope alive in every selector
  test, names were built one character at a time (chains of cons strings), pushed-to
  arrays kept room for 17 entries, and moved layout boxes were copied into dictionary
  mode. Live heap after a GitHub load 98 → 66 MB, Wikipedia 107 → 92 MB; peak
  296 → 248 MB on GitHub, 272 → 246 MB on BBC, 333 → 317 MB on Wikipedia, same time.

## Testing & benchmarks (Phase 8)

- 🟡 Memory and start time: ~0.2 s cold start with the cached V8 snapshot, 4.0 MB per
  JS context, a Cloudflare interstitial solve at ~400 MB peak. Per-page numbers against
  Chrome are in [Performance](#performance-lighter-and-faster-than-chrome).
- 🟡 Live challenge check: [`tools/cf-check.sh`](tools/cf-check.sh) runs the five public
  Cloudflare targets and prints a verdict, time and final title for each.
- 🟡 Anti-bot corpus: 126 public sites across 15 categories, nokk against headless Chrome
  and curl from the same IP (a page passes at 15 KB of real content without a vendor
  gate). The harness is not in the repository yet.
- ✅ The whole test suite passes on Linux x64 (every push), and on Linux arm64, macOS on
  Apple Silicon and Windows x64 (on build and dependency changes, and on demand).
- ⬜ A fixture-based WAF-challenge test suite (offline replay of real challenge pages).
- ⬜ Load test: sustained thousand-context throughput and tail latency.

## Packaging & release (Phase 9)

Already shipping:
- ✅ Prebuilt binaries for Linux x64 and arm64, macOS on Apple Silicon and Windows x64, a
  Linux build with real canvas/WebGL pixels, and Docker images (`ghcr.io`), built by the
  tag-triggered [release workflow](.github/workflows/release.yml).

> ⚠️ **RC dependency.** After the Chrome-emulation bump 137→148 (needed for `cf_clearance`
> replay), the workspace depends on **release-candidate** crates: `wreq = "6.0.0-rc.29"` and
> `wreq-util = "3.0.0-rc.14"` (wreq-util 2.x capped at Chrome 137). Prebuilt-binary/Docker
> releases are fine (they bundle the locked versions), but **move to wreq 6.0 stable before a
> crates.io publish or a stable release tag** — then re-run build/test/clippy for any final
> API drift. Checked 2026-10-12: no stable 6.0 yet (latest `6.0.0-rc.31`); a move to
> another RC would gain nothing and risks the TLS fingerprint, which matches Chrome 151
> today.

### Distribution channels

nokk is driven over CDP, so it is useful to every scraping ecosystem, not just Rust.
The plan is to meet users in the registry they already use. Roughly by
value-to-effort:

- ⬜ **crates.io** (Rust, native). Publish the workspace crates in dependency order
  (`nokk-net`/`nokk-pool`/`nokk-dom`/`nokk-stealth` → `nokk-cdp` → `nokk` → `nokk-cli`),
  each with complete `description`/`license`/`repository`/`keywords`/`readme`. First step
  is to **claim the `nokk` / `nokk-*` names** (they are global and permanent) with an alpha
  publish, even before the API settles. Unlocks `cargo add nokk` and free docs.rs.
  *Build note: pulls prebuilt `v8` + BoringSSL, so consumers still need cmake/libclang —
  document it.*
- ⬜ **docs.rs** (Rust API docs). Free and automatic once on crates.io; needs the public
  API documented and a `[package.metadata.docs.rs]` config for the heavy build deps.
- 🟡 **npm** (Node) — the **highest-value** channel (primary driver is Puppeteer/Playwright).
  **Published**: [`npm install @koloss777/nokk`](https://www.npmjs.com/package/@koloss777/nokk)
  works, and every `v*` tag publishes automatically with npm provenance
  ([`npm-publish.yml`](.github/workflows/npm-publish.yml)) — the version is synced from the
  tag. The package **downloads the prebuilt binary on install** (postinstall pulls the
  matching GitHub Release asset) and exposes `launch(opts)` → `server.wsEndpoint` for
  `puppeteer.connect` / `chromium.connectOverCDP`, plus `npx nokk` to run the server and a
  `.d.ts`. `launch({ autoSolve })` and `solveChallenge(page)` / `challengeState(page)` take
  Cloudflare challenges on (Puppeteer page, Playwright page or a raw CDP session). Binaries
  for Linux x64/arm64, macOS on Apple Silicon and Windows x64.
- 🟡 **PyPI** (`pip`) — **published**: [`pip install nokk`](https://pypi.org/project/nokk/)
  works (name claimed, published on every `v*` tag by
  [`python-wheels.yml`](.github/workflows/python-wheels.yml), which syncs the PEP 440 version
  from the tag). A thin launcher wheel in [`python/`](python/) bundles
  the binary (the `ruff`/`uv` pattern), built with `maturin` (`bindings = "bin"`,
  `manifest-path` → `crates/cli`) so each wheel embeds the `nokk` binary — no toolchain, no
  BoringSSL build, no Docker. `nokk.launch(…)` / async `nokk.launch_async(…)` spawn the CDP
  server, wait on `/json/version`, and return a self-cleaning server whose `ws_endpoint` goes
  to `playwright`/`pyppeteer` `connect_over_cdp`. Also ships an **MCP server** — see below.
  `launch(auto_solve=…)` and `solve_challenge(page)` / `challenge_state(page)` (+ `_async`)
  take Cloudflare challenges on. The wheel and the release binary are built in Debian
  bullseye ([`.github/bullseye-build.Dockerfile`](.github/bullseye-build.Dockerfile)) —
  manylinux_2_31, glibc floor 2.30 — and published on tag; only the very first release went out as a
  manual `twine upload`. Native PyO3 bindings are
  a heavier follow-up with unclear benefit (the interface is CDP). Wheels for Linux
  x64/arm64, macOS on Apple Silicon and Windows x64.
- 🟡 **MCP server** (`nokk[mcp]`) — nokk as a [Model Context Protocol](https://modelcontextprotocol.io)
  stdio server (`python -m nokk.mcp`), so an AI agent (Claude Desktop/Code, …)
  browses through the stealth engine instead of a headful browser anti-bots flag. A minimal
  async CDP client ([`python/nokk/_cdp.py`](python/nokk/_cdp.py)) — no Playwright dependency —
  backs `open`/`read_text`/`read_html`/`click`/`fill`/`evaluate`/`links`/`solve_challenge`/
  `challenge_state`/`reset` over stdio; built on `launch_async`. Cloudflare challenges are
  solved during `open` by default (`--no-auto-solve` turns that off). Validated end-to-end against a local binary (SDK v2 `MCPServer`
  with a v1 `FastMCP` fallback). Follow-up: richer tools (wait-for, screenshots are N/A
  without rendering), and `click`/`fill` via the CDP `Input` domain for `isTrusted` events
  (currently JS-dispatched).
- ⬜ **cargo-binstall** — near-free once on crates.io + GitHub Releases: `cargo binstall
  nokk` fetches the prebuilt binary instead of compiling. Needs the release-artifact
  naming `binstall` expects.
- ⬜ **Docker Hub** mirror of the GHCR images (wider discovery than GHCR alone).
- ⬜ **Homebrew** tap/formula (macOS/Linux CLI): `brew install nokk` (the macOS binary is
  in every release).
- ⬜ **AUR / Debian** packaging — lower priority, community-driven.

Cross-cutting prerequisite: a stable CLI/endpoint contract the wrappers can depend on.

- ⬜ Getting-started guide (README expansion + per-channel quickstarts).

---

Have a detection you'd like nokk to beat, or a site it fails on? Open an issue with the
fingerprint/challenge details — concrete failures drive the hardening backlog.
