# Cloudflare challenges

nokk clears Cloudflare's Turnstile on its own — the invisible kind, the managed
interstitial ("Just a moment…"), and the interactive one with the *Verify you are human*
checkbox. There is nothing to configure and nothing to point at: the engine knows no
particular challenge. It waits while the page works, and if a widget puts up a control
it presses it the way a person would, with the pointer moving in from a distance and the
events a real click produces. The control sits in a closed shadow root inside a
cross-origin frame, where page script (and a CSS selector from a driver) cannot reach —
which is exactly why the press lives in the engine. A cleared interstitial then submits
its form and walks on to the real page by itself.

```bash
# one-shot: load, solve whatever comes up, print the page
nokk --load https://gated.example/ --solve-challenge 25 --fail-on-challenge
```

`--fail-on-challenge` turns the outcome into an exit code (`0` the site, `3` still the
gate), and `--solve-challenge N` is the time budget. Times and pass rates on public pages are in the
[README](../README.md#measured-on-public-pages). A standalone widget counts as solved when
its token lands in `cf-turnstile-response`.

## Only the cookie

`--until-clearance` stops the moment Cloudflare hands out a
fresh `cf_clearance` and does not load the site behind the gate — on a heavy site that
page is most of a solve. Take the cookie from `--session-store` and use it from any
client on the same exit IP and Chrome version:

```bash
nokk --load https://gated.example/ --solve-challenge 60 --until-clearance \
     --fail-on-challenge --session-store ./sessions --session s1
# ./sessions/s1.json now holds cf_clearance; the process exits 0
```

Measured through one proxy on three heavy production sites (October 2026): wall time
31–42 s → 9–11 s, and on one of them CPU 40 s → 9 s. The site's own bundles, not the
challenge, were the cost.

## Over CDP

It is the same engine with three ways in:

```bash
nokk --port 9222 --auto-solve        # every page.goto() that lands on a gate solves it first
```

```js
// per browser context, regardless of the server flag
const { browserContextId } = await cdp.send('Target.createBrowserContext', { autoSolve: true });

// on demand, from a page session
const state = await session.send('Nokk.challengeState');
// → { kind: 'cloudflare-interstitial' | 'turnstile-widget' | 'recaptcha-widget' | 'datadome' | 'none',
//     title, url, cleared, token, solvable }
const out = await session.send('Nokk.solveChallenge', { timeoutMs: 30000 });
// → { status: 'cleared' | 'token-issued' | 'cleared-but-stuck' | 'timeout' | 'needs-human', solved,
//     presses, elapsedMs, remaining, title, url }
```

Whenever a navigation lands on a gate, the page session also gets a `Nokk.challenge`
event — `{ kind, solved, attempted, status, remaining, title, url }` — so a page that
still shows a gate never looks like an ordinary load. A gate nokk does not solve
(DataDome, image puzzles) is reported by kind; the way through those is a session
warmed in a real browser (see [below](#replaying-a-cf_clearance-from-a-real-browser)), not a selector.

## Replaying a `cf_clearance` from a real browser

A clearance earned elsewhere can be imported too. The cookie is bound to the exit IP **and to the TLS fingerprint of the
browser that earned it**, so the two have to match: nokk emulates Chrome 151 and its JA4
is byte-identical to the real browser's, which is what makes the handoff work.

```bash
# 1. earn it in a real browser (visible window; nothing is injected into the page)
node tools/harvest-clearance.js https://gated.example/ 40 cf_clearance.json

# 2. hand it to nokk
nokk --load https://gated.example/ \
     --session-store ./sessions --session cf --import-cookies cf_clearance.json
```

A clearance expires, and `--fail-on-challenge` says when it did (don't trust the
cookie's own `expires` — Cloudflare decides validity on its side, against the IP and the
TLS fingerprint too).

Two flags keep the replay on the same footing as the solve:

- `--chrome-version <MAJOR>` sets the UA, the client hints and the TLS handshake together
  (ML-DSA signature algorithms from 150 on, as in Chrome). A version nokk has no faithful
  handshake for falls back to the default as a whole.
- `--ip-version 4|6` (or `--local-address <IP>`): on a dual-stack machine the site may see
  either address, and a clearance earned over one is refused over the other.
