---
name: nokk
description: Fetch and read web pages that block ordinary tools — Cloudflare "Just a moment…" checks, Turnstile, JavaScript-rendered pages — with nokk, a headless browser with Chrome's fingerprint. Use when curl, requests or a plain fetch get a 403, a challenge page or an empty shell, or when a page has to be read as Markdown, scraped, or driven with Puppeteer or Playwright.
---

# nokk: read pages that block bots

nokk is a headless browser engine (V8 with its own DOM, Chrome's TLS and HTTP/2
fingerprint, no Chromium). It runs the page's JavaScript and solves Cloudflare's
challenge itself.

## Install

```bash
pip install nokk        # or: npm i -g @koloss777/nokk
nokk --version
```

## Read a page

The page's main content as Markdown (no menus, footers or cookie banners):

```bash
nokk --load https://example.com/article --solve-challenge 30 --markdown
```

- `--solve-challenge 30` waits up to 30 s for a Cloudflare check to clear; harmless on a page without one.
- The log goes to stderr, the Markdown to stdout.

Other outputs from the same load:

```bash
nokk --load URL --solve-challenge 30 --eval 'document.title'   # any JavaScript expression
nokk --load URL --solve-challenge 30 --json                    # status, challenge result, cookies
nokk --load URL --solve-challenge 30 --export-cookies c.txt    # cookies for curl -b / wget / yt-dlp
```

`--json` prints one object: `ok`, `final_url`, `status`, `title`, `challenge`
(`found`, `result`, `still_up`), `cf_clearance`, `cookies`, plus `eval` and
`markdown` when asked. A failure prints `{"ok": false, "error": {"kind", "message"}}`
with `kind` such as `dns`, `proxy`, `tls`, `refused` or `timeout`.

## When it still fails

- `challenge.still_up` true, or a page titled "Attention Required!" / "Access denied":
  the address is blocked, not the browser. Retry through a residential proxy:
  `--proxy http://user:pass@host:port` (datacenter addresses are often blocked outright).
- Add `--geoip-timezone` with a proxy so the timezone and languages match its country.
- Keep a clearance between runs: `--session-store ./sessions --session NAME`; the same
  Chrome version and address family are reused automatically.

## Drive it like Chrome

```bash
nokk --port 9222 --auto-solve
```

Connect Puppeteer (`browserWSEndpoint: 'ws://127.0.0.1:9222/devtools/browser/nokk'`)
or Playwright (`chromium.connect_over_cdp`) to it. An MCP server is also available:
`uvx nokk-mcp` (tools `open`, `read_page`, `snapshot`, `click`, `fill`, …).

## Use

Only on sites you are allowed to access. nokk does not get around logins, paywalls
or rate limits, and it is alpha software: CDP coverage is partial.
