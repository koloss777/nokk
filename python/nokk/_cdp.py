"""A minimal async Chrome DevTools Protocol client for driving nokk.

Just enough CDP to open a page, navigate, and run JavaScript against it — the
handful of methods nokk implements (Target / Page / Runtime). It exists so the
MCP server (and any Python caller) can drive nokk without pulling in a full
browser-automation stack; nokk *is* the browser, this is a thin wire client.

Requires the ``websockets`` package (installed via the ``nokk[mcp]`` extra).
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
from typing import Any, Callable, Dict, List, Optional

try:
    import websockets
except ImportError as exc:  # pragma: no cover - guarded at call sites
    raise ImportError(
        "the CDP client needs the `websockets` package; install the extra: "
        "`pip install nokk[mcp]`"
    ) from exc


class CDPError(RuntimeError):
    """A CDP command returned an error, or a page evaluation threw."""


class CDP:
    """A CDP connection to nokk's browser endpoint.

    One background task reads frames and routes them: command replies resolve
    their pending future; events wake any matching waiter.
    """

    def __init__(self, ws: "websockets.WebSocketClientProtocol"):
        self._ws = ws
        self._ids = itertools.count(1)
        self._pending: Dict[int, "asyncio.Future[dict]"] = {}
        self._event_waiters: List[tuple] = []  # (predicate, Future)
        self._reader: Optional["asyncio.Task[None]"] = None

    @classmethod
    async def connect(cls, ws_endpoint: str) -> "CDP":
        ws = await websockets.connect(ws_endpoint, max_size=None)
        self = cls(ws)
        self._reader = asyncio.ensure_future(self._read_loop())
        return self

    async def _read_loop(self) -> None:
        try:
            async for raw in self._ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        if "error" in msg:
                            fut.set_exception(CDPError(str(msg["error"])))
                        else:
                            fut.set_result(msg.get("result", {}))
                else:  # a protocol event
                    for pred, fut in list(self._event_waiters):
                        if not fut.done() and pred(msg):
                            fut.set_result(msg)
                            with contextlib.suppress(ValueError):
                                self._event_waiters.remove((pred, fut))
        except Exception:
            pass  # connection closed; fail any stragglers below
        finally:
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(CDPError("CDP connection closed"))
            self._pending.clear()

    async def send(
        self,
        method: str,
        params: Optional[dict] = None,
        *,
        session_id: Optional[str] = None,
        timeout: float = 30.0,
    ) -> dict:
        mid = next(self._ids)
        payload: Dict[str, Any] = {"id": mid, "method": method, "params": params or {}}
        if session_id:
            payload["sessionId"] = session_id
        fut: "asyncio.Future[dict]" = asyncio.get_event_loop().create_future()
        self._pending[mid] = fut
        await self._ws.send(json.dumps(payload))
        return await asyncio.wait_for(fut, timeout)

    async def wait_event(
        self,
        method: str,
        *,
        session_id: Optional[str] = None,
        timeout: float = 30.0,
    ) -> dict:
        loop = asyncio.get_event_loop()
        fut: "asyncio.Future[dict]" = loop.create_future()

        def pred(m: dict) -> bool:
            return m.get("method") == method and (
                session_id is None or m.get("sessionId") == session_id
            )

        entry = (pred, fut)
        self._event_waiters.append(entry)
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            with contextlib.suppress(ValueError):
                self._event_waiters.remove(entry)

    async def close(self) -> None:
        if self._reader:
            self._reader.cancel()
            # CancelledError is a BaseException, so suppress it explicitly.
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader
        with contextlib.suppress(Exception):
            await self._ws.close()


class Page:
    """A single page (target) opened over a :class:`CDP` connection."""

    def __init__(self, cdp: CDP, session_id: str, target_id: str):
        self._cdp = cdp
        self._session = session_id
        self.target_id = target_id

    @classmethod
    async def create(cls, cdp: CDP) -> "Page":
        target = await cdp.send("Target.createTarget", {"url": "about:blank"})
        target_id = target["targetId"]
        attach = await cdp.send(
            "Target.attachToTarget", {"targetId": target_id, "flatten": True}
        )
        session_id = attach["sessionId"]
        await cdp.send("Page.enable", session_id=session_id)
        await cdp.send("Runtime.enable", session_id=session_id)
        return cls(cdp, session_id, target_id)

    async def navigate(self, url: str, *, timeout: float = 30.0) -> Dict[str, str]:
        """Go to ``url`` and wait for the load event. Returns ``{url, title}``."""
        # Arm the waiter before navigating so a fast load can't race past it.
        waiter = asyncio.ensure_future(
            self._cdp.wait_event(
                "Page.loadEventFired", session_id=self._session, timeout=timeout
            )
        )
        try:
            await self._cdp.send(
                "Page.navigate", {"url": url}, session_id=self._session, timeout=timeout
            )
            with contextlib.suppress(asyncio.TimeoutError):
                await waiter
        finally:
            if not waiter.done():
                waiter.cancel()
        return await self.evaluate("({url: location.href, title: document.title})")

    async def evaluate(self, expression: str, *, timeout: float = 30.0) -> Any:
        """Evaluate a JS expression in the page and return its value.

        Awaits promises and returns by value; raises :class:`CDPError` if the
        expression throws.
        """
        result = await self._cdp.send(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": True,
                "userGesture": True,
            },
            session_id=self._session,
            timeout=timeout,
        )
        details = result.get("exceptionDetails")
        if details:
            exc = details.get("exception") or {}
            raise CDPError(exc.get("description") or details.get("text") or "eval error")
        res = result.get("result", {})
        if "value" in res:
            return res["value"]
        return res.get("description")

    # --- convenience wrappers used by the MCP tools ------------------------- #

    async def read_text(self, selector: Optional[str] = None) -> Optional[str]:
        sel = json.dumps(selector) if selector else "null"
        return await self.evaluate(
            f"(() => {{ const s = {sel}; const el = s ? document.querySelector(s) : document.body;"
            f" return el ? el.innerText : null; }})()"
        )

    async def read_html(self, selector: Optional[str] = None) -> Optional[str]:
        sel = json.dumps(selector) if selector else "null"
        return await self.evaluate(
            f"(() => {{ const s = {sel};"
            f" const el = s ? document.querySelector(s) : document.documentElement;"
            f" return el ? el.outerHTML : null; }})()"
        )

    async def click(self, selector: str) -> bool:
        sel = json.dumps(selector)
        return await self.evaluate(
            f"(() => {{ const el = document.querySelector({sel});"
            f" if (!el) throw new Error('no element matches ' + {sel}); el.click(); return true; }})()"
        )

    async def fill(self, selector: str, value: str) -> bool:
        sel, val = json.dumps(selector), json.dumps(value)
        return await self.evaluate(
            f"(() => {{ const el = document.querySelector({sel});"
            f" if (!el) throw new Error('no element matches ' + {sel});"
            f" el.focus(); el.value = {val};"
            f" el.dispatchEvent(new Event('input', {{bubbles: true}}));"
            f" el.dispatchEvent(new Event('change', {{bubbles: true}})); return true; }})()"
        )

    async def links(self) -> List[str]:
        # Resolve against the document URL via getAttribute (nokk doesn't expose
        # the anchor `.href` IDL getter), and drop anything unparseable.
        return await self.evaluate(
            "[...document.querySelectorAll('a[href]')]"
            ".map(a => { try { return new URL(a.getAttribute('href'), location.href).href; }"
            " catch (e) { return null; } }).filter(Boolean)"
        )
