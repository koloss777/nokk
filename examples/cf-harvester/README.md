# Example: Cloudflare `cf_clearance` harvester

**Harvest a Cloudflare `cf_clearance` cookie with a real browser, so [nokk](../../)
can replay it** — the honest way past an *interactive/managed* Turnstile.

A full-page “Verify you are human” challenge is solved by genuinely running the
challenge — Web Workers, canvas/WebGL probes, a proof-of-work VM — in a **real
browser**. A lightweight, no-render engine like nokk can’t do that. So instead of
solving it inside nokk, this example lets a real, undetected Chromium
([`nodriver`](https://github.com/ultrafunkamsterdam/nodriver)) solve it once, then
hands the `cf_clearance` cookie to nokk to **replay**.

> **Status — validated end-to-end.** The harvest → replay hybrid is proven: a cookie
> harvested here replays through nokk (matching Chrome version, same exit IP) to
> **HTTP 200** past a live managed-Turnstile site. See [docs/RESEARCH.md](docs/RESEARCH.md).
>
> **The auto-click works** — verified solving a live managed Turnstile autonomously. It
> locates the widget through the CDP **DOM** domain (`DOM.getDocument(pierce=True)` +
> `DOM.getBoxModel`) and clicks the checkbox by coordinate with a real `Input` mouse
> event (`isTrusted`). Piercing matters: Cloudflare renders the widget inside a
> **closed** shadow root, where `element.shadowRoot` is null, so a JS walker sees zero
> iframes and only the hidden 0x0 `input#cf-chl-widget-*_response` — the JS probe is
> kept as a fallback for layouts without the iframe. A **manual click** in the opened
> window still works if both miss (the poll loop picks up the cookie either way). Use
> `--headless` at your own risk — managed challenges are far more reliable headful
> (run under Xvfb on a server).

## The hybrid, and why not “solve it in nokk”

`cf_clearance` is bound to the exit **IP + the browser's TLS/JA3 fingerprint** (a
`curl` with the exact cookie + UA + IP still gets 403 — verified). The honest
architecture is a split:

- **nokk** scrapes at scale (lightweight, many contexts), replaying the cookie.
- **this harvester** runs a real browser that only solves challenges and emits
  cookies. nokk must present the **same Chrome major** (`--chrome-version`) and exit
  the **same IP**, or Cloudflare rejects the clearance.

Solving inside nokk means rebuilding a browser (Workers, iframe execution, real
rasterisation) and still losing an arms race Cloudflare rotates weekly.

## Install

```bash
pip install nodriver websockets    # + a real Chrome/Chromium on the machine
```

## Harvest

```bash
# Opens a real browser; solve the challenge (click the checkbox), it captures the
# cookie. Headful is far more reliable — use Xvfb on a server.
python -m nokk_cf harvest https://www.example-protected.com/ --out cf_clearance.json
# add --proxy scheme://host:port for a residential exit IP
```

Writes `cf_clearance.json`: the cookie(s), the **exact `user_agent`** it was minted
under (so you can match nokk's `--chrome-version`), domain, and origin.

## Replay it in nokk

nokk imports the harvested cookies into a named session and replays them — present
the same Chrome version and exit from the same IP:

```bash
nokk --load https://www.example-protected.com/ \
     --chrome-version 148 \
     --session cf --import-cookies cf_clearance.json
# → [document] GET … → 200   (past the Turnstile gate)
```

Set `--chrome-version` to the major in the harvested `user_agent`. `cf_clearance`
also has a short TTL, so re-harvest when it expires.

## License

MIT OR Apache-2.0, matching nokk.
