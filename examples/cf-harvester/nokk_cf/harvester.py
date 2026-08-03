"""Cloudflare `cf_clearance` harvester.

The honest way past an *interactive/managed* Cloudflare Turnstile challenge is to
let a **real browser** solve it — it renders the widget, runs the challenge VM
(Web Workers, canvas/WebGL probes, proof-of-work) and gets issued a `cf_clearance`
cookie. This module drives an undetected Chromium ([`nodriver`]) through that flow
(optionally behind a residential proxy), then hands the cookie — and the exact
User-Agent it was minted under — back so a lightweight engine like `nokk` can
*reuse* it instead of solving the challenge itself.

`cf_clearance` is bound to the client **IP + User-Agent** (and increasingly the
TLS/JA fingerprint), so the consumer MUST replay it from the same proxy IP and
present the same UA — hence we return `user_agent` alongside the cookie.

Implementation note: nodriver launches and navigates the browser, but cookies and
the UA are read over a **raw CDP websocket** to the browser endpoint
(`Storage.getCookies` / `Browser.getVersion`). nodriver's own cookie call was
observed to stall on a mid-challenge page; a fresh browser-level CDP connection
does not. So: nodriver for the *undetected launch*, raw CDP for the *reads*.

[`nodriver`]: https://github.com/ultrafunkamsterdam/nodriver
"""

from __future__ import annotations

import asyncio
import dataclasses
import itertools
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import nodriver as uc
    import websockets
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "nokk-cf needs `nodriver` and `websockets`: pip install nodriver websockets"
    ) from exc


def _log(msg: str) -> None:
    """Progress to stderr (flushed), so a run is observable while it polls."""
    print(f"[nokk-cf] {msg}", file=sys.stderr, flush=True)


# Returns the page's iframes (src + viewport-relative rect) and any Turnstile
# container elements, so auto_solve can find the widget and we can log coordinates.
# Cloudflare renders the Turnstile widget inside a **shadow DOM**, so a plain
# querySelectorAll misses it — we walk shadow roots recursively.
_DOM_PROBE_JS = (
    "(()=>{const frames=[],cont=[];"
    "const walk=(root)=>{if(!root||!root.querySelectorAll)return;"
    "root.querySelectorAll('iframe').forEach(f=>{const r=f.getBoundingClientRect();"
    "frames.push({src:((f.src||(f.getAttribute&&f.getAttribute('src'))||'')+'').slice(0,90),"
    "x:r.x,y:r.y,w:r.width,h:r.height,vis:r.width>0&&r.height>0});});"
    "root.querySelectorAll('*').forEach(e=>{"
    "if(/turnstile|cf-chl|challenge/i.test((e.className+' '+e.id)+'')){"
    "const r=e.getBoundingClientRect();"
    "cont.push({tag:e.tagName,x:r.x,y:r.y,w:r.width,h:r.height});}"
    "if(e.shadowRoot)walk(e.shadowRoot);});};"
    "walk(document);"
    "return{dpr:window.devicePixelRatio,vw:innerWidth,vh:innerHeight,frames,cont};})()"
)


@dataclass
class ClearanceResult:
    """A harvested clearance — everything a consumer needs to *replay* it."""

    cf_clearance: str
    user_agent: str
    domain: str
    url: str
    proxy: Optional[str] = None
    expires: Optional[float] = None
    #: Every cookie on the domain (the origin may need more than cf_clearance).
    cookies: Dict[str, str] = field(default_factory=dict)

    def write_json(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(dataclasses.asdict(self), f, indent=2)
            f.write("\n")


async def _await(coro, timeout: float):
    """Await `coro` bounded by `timeout` — nothing may block indefinitely."""
    return await asyncio.wait_for(coro, timeout)


class _CDP:
    """A minimal raw CDP client over one browser-level websocket."""

    def __init__(self, ws):
        self._ws = ws
        self._ids = itertools.count(1)

    @classmethod
    async def connect(cls, ws_url: str, timeout: float = 15.0) -> "_CDP":
        return cls(await _await(websockets.connect(ws_url, max_size=None), timeout))

    async def call(
        self,
        method: str,
        params: Optional[dict] = None,
        timeout: float = 15.0,
        session_id: Optional[str] = None,
    ) -> dict:
        mid = next(self._ids)
        frame = {"id": mid, "method": method, "params": params or {}}
        if session_id:  # flatten routing: page-domain calls over the browser ws
            frame["sessionId"] = session_id
        await self._ws.send(json.dumps(frame))

        async def _recv_matching() -> dict:
            while True:
                msg = json.loads(await self._ws.recv())
                if msg.get("id") == mid:  # skip unrelated events / other replies
                    if "error" in msg:
                        raise RuntimeError(msg["error"])
                    return msg.get("result", {})

        return await _await(_recv_matching(), timeout)

    async def close(self) -> None:
        try:
            await self._ws.close()
        except Exception:
            pass


async def harvest(
    url: str,
    *,
    proxy: Optional[str] = None,
    headless: bool = False,
    timeout: float = 180.0,
    cookie_name: str = "cf_clearance",
    out_path: Optional[str] = None,
    auto_click: bool = True,
    browser_args: Optional[list] = None,
) -> ClearanceResult:
    """Solve the challenge at ``url`` in a real browser and return the clearance.

    :param proxy: ``scheme://host:port`` proxy (no auth — see docs/RESEARCH.md).
    :param headless: managed challenges pass far more reliably **headful** (default).
    :param timeout: overall budget; the whole run, incl. startup, is bounded by it.
    :param out_path: if set, the clearance JSON is written here the instant the
        cookie appears (so a kill can't lose it).
    :raises TimeoutError: if no clearance cookie is issued in time.
    """
    args = list(browser_args or [])
    if proxy:
        args.append(f"--proxy-server={proxy}")

    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout  # set BEFORE startup so it bounds everything

    _log(f"starting browser (headless={headless}, proxy={proxy or 'none'})")
    browser = await _await(uc.start(headless=headless, browser_args=args), 60)
    try:
        _log(f"navigating to {url}")
        await _await(browser.get(url), 60)
        _log("solve the challenge in the window (click 'Verify you are human'); polling…")

        cdp = await _CDP.connect(browser.websocket_url)
        try:
            try:
                user_agent = (await cdp.call("Browser.getVersion", timeout=5)).get("userAgent", "")
            except Exception:
                user_agent = ""

            # Attach to the page target so we can dispatch real input into it.
            page_session = ""
            try:
                targets = (await cdp.call("Target.getTargets")).get("targetInfos", [])
                page_target = next((t for t in targets if t.get("type") == "page"), None)
                if page_target:
                    page_session = (
                        await cdp.call(
                            "Target.attachToTarget",
                            {"targetId": page_target["targetId"], "flatten": True},
                        )
                    ).get("sessionId", "")
            except Exception as e:
                _log(f"attach failed ({e!r}); manual click still works")

            last_click = 0.0
            frames_logged = False

            async def _probe_dom() -> dict:
                res = await cdp.call(
                    "Runtime.evaluate",
                    {"expression": _DOM_PROBE_JS, "returnByValue": True},
                    timeout=5,
                    session_id=page_session,
                )
                return (res.get("result") or {}).get("value") or {}

            def _pick_widget(frames: list) -> Optional[dict]:
                # Prefer a Turnstile/challenge iframe by src; else the smallest
                # visible widget-sized box (the outer challenge iframe is large —
                # clicking its centre misses the checkbox, which was the bug).
                for f in frames:
                    if f["vis"] and re.search(
                        r"turnstile|challenges\.cloudflare|cdn-cgi/challenge", f["src"], re.I
                    ):
                        return f
                sized = [f for f in frames if f["vis"] and 120 <= f["w"] <= 450 and 40 <= f["h"] <= 130]
                sized.sort(key=lambda f: f["w"] * f["h"])
                return sized[0] if sized else None

            async def auto_solve() -> None:
                """Best-effort: click the Turnstile checkbox by coordinate. A real
                `Input` mouse event (isTrusted) into a genuine browser often clears
                the interactive widget; if not, the manual click is the fallback."""
                nonlocal last_click, frames_logged
                if not (auto_click and page_session):
                    return
                now = loop.time()
                if now - last_click < 12:  # let a click settle before retrying
                    return

                dom = await _probe_dom()
                frames = dom.get("frames", [])
                conts = dom.get("cont", [])
                # Log the layout the first time anything Turnstile-ish shows up
                # (the widget appears a couple seconds in, not on the first probe).
                if (frames or conts) and not frames_logged:
                    _log(f"viewport {dom.get('vw')}x{dom.get('vh')} dpr={dom.get('dpr')}")
                    for f in frames:
                        _log(f"  iframe {f['w']:.0f}x{f['h']:.0f} @({f['x']:.0f},{f['y']:.0f}) "
                             f"vis={f['vis']} src={f['src']!r}")
                    for c in conts:
                        _log(f"  turnstile-el <{c['tag']}> {c['w']:.0f}x{c['h']:.0f} @({c['x']:.0f},{c['y']:.0f})")
                    frames_logged = True

                # Prefer a real, visible widget with non-zero height (the iframe);
                # only fall back to a collapsed container if that's all there is.
                target = _pick_widget(frames)
                if not target:
                    visible = [c for c in conts if c["w"] > 0 and c["h"] > 0]
                    target = visible[0] if visible else next((c for c in conts if c["w"] > 0), None)
                if not target:
                    _log("no Turnstile widget located yet; retrying (or click manually)")
                    return

                # Checkbox sits ~30px from the widget's left. Use the widget's
                # vertical centre; for a collapsed (h==0) container, nudge down to
                # where the checkbox row renders.
                cy = target["y"] + (target["h"] / 2 if target["h"] > 0 else 33)
                x, y = target["x"] + 30, cy
                for ev, buttons in (("mouseMoved", 0), ("mousePressed", 1), ("mouseReleased", 0)):
                    await cdp.call(
                        "Input.dispatchMouseEvent",
                        {"type": ev, "x": x, "y": y, "button": "left",
                         "buttons": buttons, "clickCount": 1},
                        timeout=5,
                        session_id=page_session,
                    )
                last_click = now
                _log(f"auto-clicked at ({x:.0f},{y:.0f}) [widget {target['w']:.0f}x{target['h']:.0f}]")

            while loop.time() < deadline:
                try:
                    await auto_solve()
                except Exception as e:
                    _log(f"auto-click attempt failed ({e!r})")
                try:
                    cookies: List[dict] = (await cdp.call("Storage.getCookies")).get("cookies", [])
                except Exception as e:
                    _log(f"cookie read failed ({e!r}); reconnecting")
                    await cdp.close()
                    cdp = await _CDP.connect(browser.websocket_url)
                    await asyncio.sleep(1.0)
                    continue

                clearance = next(
                    (c for c in cookies if c.get("name") == cookie_name and c.get("value")), None
                )
                if clearance:
                    result = ClearanceResult(
                        cf_clearance=clearance["value"],
                        user_agent=user_agent,
                        domain=clearance["domain"],
                        url=url,
                        proxy=proxy,
                        expires=clearance.get("expires"),
                        cookies={c["name"]: c["value"] for c in cookies},
                    )
                    _log(f"got {cookie_name} (len={len(clearance['value'])}) on {clearance['domain']}")
                    if out_path:
                        result.write_json(out_path)
                        _log(f"wrote {out_path}")
                    return result

                await asyncio.sleep(1.5)
        finally:
            await cdp.close()

        raise TimeoutError(
            f"no `{cookie_name}` within {timeout:.0f}s — challenge not solved "
            "(try headful, a cleaner residential IP, or a fresher browser build)"
        )
    finally:
        try:
            browser.stop()
        except Exception:
            pass
