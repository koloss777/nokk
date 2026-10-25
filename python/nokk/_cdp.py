"""A minimal async Chrome DevTools Protocol client for driving nokk.

Just enough CDP to open a page, navigate, and run JavaScript against it — the
handful of methods nokk implements (Target / Page / Runtime), plus nokk's own
``Nokk.solveChallenge`` / ``Nokk.challengeState`` and ``Nokk.challenge`` event. It exists so the
MCP server (and any Python caller) can drive nokk without pulling in a full
browser-automation stack; nokk *is* the browser, this is a thin wire client.

Requires the ``websockets`` package (installed via the ``nokk[mcp]`` extra).
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import re
from typing import Any, Callable, Dict, List, Optional

try:
    import websockets
except ImportError as exc:  # pragma: no cover - guarded at call sites
    raise ImportError(
        "the CDP client needs the `websockets` package; install the extra: "
        "`pip install nokk[mcp]`"
    ) from exc


_REF = re.compile(r"e([1-9][0-9]*)")


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
        # The last `Nokk.challenge` event per session: a navigation that met a
        # gate reports it just ahead of its load event.
        self.challenges: Dict[Optional[str], dict] = {}
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
                    if msg.get("method") == "Nokk.challenge":
                        self.challenges[msg.get("sessionId")] = msg.get("params", {})
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
        # The remote array behind the last snapshot: [outline, el1, el2, ...].
        self._snapshot_id: Optional[str] = None

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

    async def navigate(self, url: str, *, timeout: float = 30.0) -> Dict[str, Any]:
        """Go to ``url`` and wait for the load event. Returns ``{url, title}``,
        plus ``challenge`` when the navigation met a Cloudflare gate: the
        server's ``Nokk.challenge`` report (``kind``, ``solved``, ``remaining``,
        ``status``, ``presses``, ``elapsedMs``…)."""
        self._cdp.challenges.pop(self._session, None)
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
        out = await self.evaluate("({url: location.href, title: document.title})")
        challenge = self._cdp.challenges.pop(self._session, None)
        if challenge is not None:
            out["challenge"] = challenge
        return out

    async def solve_challenge(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Solve the challenge the page shows now, pressing its checkbox if it
        puts one up. ``timeout`` is the budget in seconds."""
        params = {} if timeout is None else {"timeoutMs": int(timeout * 1000)}
        budget = (timeout or 30.0) + 15.0
        return await self._cdp.send(
            "Nokk.solveChallenge", params, session_id=self._session, timeout=budget
        )

    async def challenge_state(self) -> Dict[str, Any]:
        """What gate the page shows: ``{kind, title, url, cleared, token, solvable}``."""
        return await self._cdp.send("Nokk.challengeState", session_id=self._session)

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

    async def snapshot(self, selector: Optional[str] = None, max_chars: int = 20000) -> Optional[str]:
        """The page as an outline: text in reading order, controls numbered
        ``[e1]``, ``[e2]``… for :meth:`click` and :meth:`fill`. ``None`` when
        ``selector`` matches nothing."""
        from ._snapshot import SNAPSHOT_JS

        expr = f"({SNAPSHOT_JS})({json.dumps(selector or None)}, {int(max_chars)})"
        result = await self._cdp.send(
            "Runtime.evaluate",
            {"expression": expr, "returnByValue": False},
            session_id=self._session,
        )
        details = result.get("exceptionDetails")
        if details:
            exc = details.get("exception") or {}
            raise CDPError(exc.get("description") or details.get("text") or "snapshot error")
        object_id = result.get("result", {}).get("objectId")
        if not object_id:
            raise CDPError("snapshot returned no object")
        old, self._snapshot_id = self._snapshot_id, object_id
        if old:
            with contextlib.suppress(Exception):
                await self._cdp.send("Runtime.releaseObject", {"objectId": old}, session_id=self._session)
        return await self._call_on_snapshot("function () { return this[0]; }")

    async def _call_on_snapshot(self, fn: str, *args: Any) -> Any:
        result = await self._cdp.send(
            "Runtime.callFunctionOn",
            {
                "functionDeclaration": fn,
                "objectId": self._snapshot_id,
                "arguments": [{"value": a} for a in args],
                "returnByValue": True,
                "awaitPromise": True,
                "userGesture": True,
            },
            session_id=self._session,
        )
        details = result.get("exceptionDetails")
        if details:
            exc = details.get("exception") or {}
            # Our own message, without the stack and the `Error: ` prefix.
            msg = (exc.get("description") or details.get("text") or "eval error").split("\n")[0]
            raise CDPError(msg[len("Error: "):] if msg.startswith("Error: ") else msg)
        return result.get("result", {}).get("value")

    async def _on_element(self, target: str, body: str, *args: Any) -> Any:
        """Run ``body`` with ``el`` bound to ``target``: a snapshot ref such as
        ``e12`` or a CSS selector. Extra ``args`` arrive as ``a0``, ``a1``…."""
        params = ", ".join(f"a{i}" for i in range(len(args)))
        m = _REF.fullmatch(target.strip())
        if m:
            if not self._snapshot_id:
                raise CDPError(f"no snapshot yet: call snapshot before using {target}")
            fn = (
                f"function (i{', ' if params else ''}{params}) {{ const el = this[i];"
                f" if (!el || !el.isConnected) throw new Error('{target} is gone: call snapshot again');"
                f" {body} }}"
            )
            try:
                return await self._call_on_snapshot(fn, int(m.group(1)), *args)
            except CDPError as e:
                if "Could not find object" in str(e):
                    raise CDPError(f"{target} is from an earlier page: call snapshot again") from None
                raise
        sel = json.dumps(target)
        fn = (
            f"function ({params}) {{ const el = document.querySelector({sel});"
            f" if (!el) throw new Error('no element matches ' + {sel}); {body} }}"
        )
        args_js = ", ".join(json.dumps(a) for a in args)
        return await self.evaluate(f"({fn})({args_js})")

    async def click(self, target: str) -> bool:
        return await self._on_element(target, "el.click(); return true;")

    async def fill(self, target: str, value: str) -> bool:
        return await self._on_element(
            target,
            "el.focus(); el.value = a0;"
            " el.dispatchEvent(new Event('input', {bubbles: true}));"
            " el.dispatchEvent(new Event('change', {bubbles: true})); return true;",
            value,
        )

    async def links(self) -> List[str]:
        # Resolve against the document URL via getAttribute (nokk doesn't expose
        # the anchor `.href` IDL getter), and drop anything unparseable.
        return await self.evaluate(
            "[...document.querySelectorAll('a[href]')]"
            ".map(a => { try { return new URL(a.getAttribute('href'), location.href).href; }"
            " catch (e) { return null; } }).filter(Boolean)"
        )
