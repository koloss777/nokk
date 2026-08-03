# Passing interactive Cloudflare Turnstile — research

Scope: how a managed Cloudflare Turnstile challenge actually works, why solving it
*inside* a from-scratch engine (nokk) is the wrong target, and the architecture
`nokk-cf` takes instead.

## 1. What the managed challenge is

The full-page “Verify you are human” is Cloudflare’s **WAF-level managed
challenge**, using Turnstile under the hood. Flow:

1. Origin request → the edge decides to challenge (IP reputation, fingerprint,
   path, security level) and returns **HTTP 403** with a challenge HTML page.
2. That page loads an obfuscated orchestration script from
   `/cdn-cgi/challenge-platform/…` and a Turnstile widget in a cross-origin iframe
   (`challenges.cloudflare.com`).
3. The script runs a **custom bytecode VM**, collects a large signal set, and
   POSTs results to `/cdn-cgi/challenge-platform/…/flow` endpoints.
4. On success the edge sets **`cf_clearance`** and redirects to the origin content.
   Subsequent requests carrying the cookie skip the challenge until it expires.

`cf_clearance` is validated against **client IP + User-Agent** (and, increasingly,
the TLS/JA3-JA4 fingerprint). Replaying it requires matching all of those.

## 2. Signal surface the VM probes

- **Execution faithfulness** — it runs *its own* bytecode; you must execute
  arbitrary, rotating JS correctly, not hardcode answers.
- **Web Workers / OffscreenCanvas** — work is offloaded there.
- **Canvas / WebGL / AudioContext** — differential fingerprints from real
  rasterisation (text metrics, blending, shader output, oscillator+compressor).
- **Environment** — `window.chrome.*`, `navigator.userAgentData`, plugins,
  permissions, WebGL vendor/renderer/params/extensions/precision, fonts, Intl,
  `Error.stack` shape, `Function.prototype.toString`, prototype chains,
  `iframe.contentWindow` behaviour.
- **Behaviour** — pointer movement, click timing, `event.isTrusted`, focus/blur.
- **Edge-side** — JA3/JA4 + HTTP/2 fingerprint vs the claimed UA; proof-of-work.

## 3. Why not solve it inside nokk

nokk is a no-render V8 + minimal DOM engine. The challenge is designed to detect
exactly that: it needs real Workers, cross-origin iframe execution, and genuine
canvas/WebGL/audio rasterisation — all of which nokk fakes or lacks. Matching it
means rebuilding a browser, and Cloudflare rotates the VM logic weekly, so a
passing config decays within days. This is why production scrapers use a **real
browser** (or a paid solver that runs one) for the solve step. Verdict: out of
scope for the engine; correct as a **separate component**.

## 4. Architecture options

| # | Approach | Verdict |
|---|----------|---------|
| 1 | Full environment fidelity inside nokk (Workers + iframe + real render + fresh fp) | ❌ rebuilds a browser; loses the arms race |
| 2 | **Real patched Chromium harvester** → emit `cf_clearance`, nokk replays it | ✅ **chosen** |
| 3 | Reverse-engineer + reimplement the challenge VM in a mocked-DOM sandbox | 🔬 “purest” solve; extreme RE + perpetual upkeep (what CapSolver/2Captcha do) |

**Hybrid = 2:** nokk scrapes at scale; a small pool of real browsers only solves
challenges and feeds cookies back. Prior art: FlareSolverr (now largely defeated
by modern Turnstile); current tooling: `nodriver`, `rebrowser-patches`,
`camoufox`, `patchright`, plus residential/mobile proxies.

## 5. Plan

1. **Capture** the challenge flow for a target: HAR + the challenge-platform
   script + the `/flow` exchange.
2. **Baseline** the signal surface — instrument a real Chrome, dump what it
   reports, diff against nokk (canvas/WebGL/Worker/`window.chrome`/UA).
3. **Prototype** the harvester (this repo): `nodriver` + residential proxy →
   extract `cf_clearance` + the exact UA. *(scaffolded)*
4. **Validate replay** in a nokk named session: bind IP + UA + JA; measure whether
   the cookie holds. This is where nokk’s stale Chrome emulation must be bumped so
   its UA/fingerprint match the harvester’s browser.
5. **Measure** success rate, cookie TTL, and how often Cloudflare’s rotation
   breaks the flow.

## 6. Open problems / caveats

- **Proxy auth**: Chromium `--proxy-server` has no auth; needs an auth-less
  endpoint or a local forwarder (e.g. a small mitm/relay) for user:pass proxies.
- **Headful requirement**: managed challenges pass far more reliably headful; run
  under Xvfb on servers.
- **Cookie binding**: IP + UA (+ TLS) must all match on replay, or nokk is
  re-challenged — the tightest real constraint on the hybrid.
- **Legality/ToS**: solving anti-bot challenges may violate a site’s terms; use
  only where you’re authorised.
