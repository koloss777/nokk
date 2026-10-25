"""nokk as an MCP server — give an AI agent a stealth browser.

Exposes nokk over the Model Context Protocol (stdio), so an MCP client (Claude
Desktop, Claude Code, …) can navigate and scrape the web through nokk's
Chrome-fingerprinted engine instead of a headful browser that anti-bots flag.

Cloudflare challenges are solved on the way by default: ``open`` returns once
the page behind "Just a moment…" (or a Turnstile widget's token) is there, and
says what it met. ``--no-auto-solve`` turns that off; the ``solve_challenge``
tool still works on demand.

Run it::

    python -m nokk.mcp
    python -m nokk.mcp --rotate-fingerprint --proxy socks5://host:1080

Register with an MCP client (example ``mcpServers`` entry; use the ``python`` from
the environment where you installed the extra)::

    {
      "mcpServers": {
        "nokk": { "command": "python", "args": ["-m", "nokk.mcp", "--rotate-fingerprint"] }
      }
    }

Install the extra first: ``pip install "nokk[mcp]"``.
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import inspect
import os
from typing import Annotated, Any, Dict, List, Optional

from pydantic import Field

import nokk
from nokk._cdp import CDP, CDPError, Page

# The MCP SDK's high-level server is `MCPServer` in v2, `FastMCP` in v1 — both
# share the `.tool()` decorator + `.run()` API this module uses.
try:
    try:
        from mcp.server import MCPServer as _Server  # SDK >= 2.0
        from mcp.server.mcpserver.exceptions import ToolError
    except ImportError:
        from mcp.server.fastmcp import FastMCP as _Server  # SDK 1.x
        from mcp.server.fastmcp.exceptions import ToolError
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "nokk-mcp needs the Model Context Protocol SDK. Install the extra: "
        'pip install "nokk[mcp]"'
    ) from exc


_INSTRUCTIONS = (
    "A headless browser with Chrome's fingerprint. Call `open` first; the other "
    "tools act on the page it opened. Cloudflare challenges are solved during `open`. "
    "`snapshot` shows the page compactly with numbered controls (`e12`) that `click` "
    "and `fill` accept."
)
# SDK 2.x reports a server version; 1.x has no such argument.
_server_kwargs: Dict[str, Any] = {"instructions": _INSTRUCTIONS}
if "version" in inspect.signature(_Server.__init__).parameters:
    _server_kwargs["version"] = nokk.__version__
mcp = _Server("nokk", **_server_kwargs)


def _tool(fn):
    """Register ``fn`` as a tool whose page errors reach the agent as text.
    SDK 2.x hides any exception but ``ToolError`` behind "Error executing tool"."""

    @functools.wraps(fn)
    async def run(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except (CDPError, asyncio.TimeoutError) as e:
            raise ToolError(str(e) or type(e).__name__) from e

    return mcp.tool()(run)

_Target = Annotated[
    str,
    Field(description="A ref from the last `snapshot`, e.g. `e12`, or a CSS selector, e.g. `#price`, `form input[name=q]`."),
]
_OptionalSelector = Annotated[
    str,
    Field(description="CSS selector of one element; empty for the whole page."),
]

# Lazily-created singletons: one nokk server + one page, shared across tool calls
# so the agent can navigate, then click, then read within one session. A lock
# serialises tool calls so overlapping navigate/read can't interleave.
_launch_kwargs: Dict[str, object] = {}
# A navigation that meets a challenge returns only once it is solved, so give
# it the solve budget on top of an ordinary load.
_NAV_TIMEOUT = 90.0
_state: Dict[str, object] = {}
_lock: Optional[asyncio.Lock] = None


async def _get_page() -> Page:
    global _lock
    if _lock is None:  # no await before assignment -> race-free on one loop
        _lock = asyncio.Lock()
    async with _lock:
        if "page" not in _state:
            server = await nokk.launch_async(**_launch_kwargs)  # type: ignore[arg-type]
            cdp = await CDP.connect(server.ws_endpoint)
            page = await Page.create(cdp)
            _state.update(server=server, cdp=cdp, page=page)
        return _state["page"]  # type: ignore[return-value]


@_tool
async def open(
    url: Annotated[str, Field(description="Absolute address to load, e.g. `https://example.com/`.")],
) -> Dict[str, Any]:
    """Load a page in the browser and wait until it has loaded. Returns the final
    `url` and `title`. A Cloudflare challenge on the way is solved first (unless the
    server runs with `--no-auto-solve`); `challenge` then reports `kind`, `solved`
    and `remaining` (`"none"` once through). Call this before the other tools."""
    page = await _get_page()
    return await page.navigate(url, timeout=_NAV_TIMEOUT)


@_tool
async def solve_challenge(
    timeout_seconds: Annotated[float, Field(description="How long to wait for the challenge to clear, in seconds.")] = 30,
) -> Dict[str, Any]:
    """Solve the Cloudflare challenge on the current page: the "Just a moment..."
    page or a Turnstile widget, pressing its checkbox if it shows one. Only needed
    when `open` ran with auto-solve off or a widget appeared later. Returns
    `status`, `solved`, `remaining`, `title` and `url`."""
    page = await _get_page()
    return await page.solve_challenge(timeout_seconds)


@_tool
async def challenge_state() -> Dict[str, Any]:
    """Report whether the current page is behind a bot check. `kind` is `"none"`
    when the page itself is shown, else the kind of check (`"cloudflare-interstitial"`,
    `"turnstile-widget"`, `"aws-waf"` and others); `solvable` says whether
    `solve_challenge` can clear it."""
    page = await _get_page()
    return await page.challenge_state()


@_tool
async def snapshot(
    selector: _OptionalSelector = "",
    max_chars: Annotated[int, Field(description="Cut the outline after this many characters.")] = 20000,
) -> Optional[str]:
    """Show the current page as a compact outline: headings and text in reading
    order, and every link, button and form field numbered (`[e12]`) with its
    name, address or value. Pass a ref to `click` or `fill`. Far smaller than
    `read_html`; take a new snapshot after the page changes. `null` when
    `selector` matches nothing."""
    page = await _get_page()
    return await page.snapshot(selector or None, max_chars)


@_tool
async def read_text(selector: _OptionalSelector = "") -> Optional[str]:
    """Return the visible text of the current page, or of the first element
    matching `selector`. `null` when no element matches."""
    page = await _get_page()
    return await page.read_text(selector or None)


@_tool
async def read_html(selector: _OptionalSelector = "") -> Optional[str]:
    """Return the HTML of the current page as it is now (after its scripts ran),
    or the outer HTML of the first element matching `selector`. `null` when no
    element matches."""
    page = await _get_page()
    return await page.read_html(selector or None)


@_tool
async def click(target: _Target) -> bool:
    """Click an element: a ref from `snapshot` or the first match of a CSS
    selector. Returns `true`; fails when nothing matches or the ref is stale."""
    page = await _get_page()
    return await page.click(target)


@_tool
async def fill(
    target: _Target,
    value: Annotated[str, Field(description="Text to put in the field.")],
) -> bool:
    """Type `value` into a form field: a ref from `snapshot` or the first match
    of a CSS selector (its `input` and `change` events fire, as when a person
    types). Returns `true`; fails when nothing matches or the ref is stale."""
    page = await _get_page()
    return await page.fill(target, value)


@_tool
async def evaluate(
    expression: Annotated[str, Field(description="JavaScript expression, e.g. `document.title` or `[...document.querySelectorAll('h2')].map(e => e.textContent)`.")],
) -> object:
    """Run a JavaScript expression in the current page and return its value as
    JSON (a promise is awaited). For data the other tools do not read."""
    page = await _get_page()
    return await page.evaluate(expression)


@_tool
async def links() -> List[str]:
    """Return the absolute addresses of all links on the current page."""
    page = await _get_page()
    return await page.links()


@_tool
async def reset() -> str:
    """Close the browser session: cookies and page state are dropped, and the
    next `open` starts a fresh one."""
    cdp = _state.pop("cdp", None)
    server = _state.pop("server", None)
    _state.pop("page", None)
    if cdp is not None:
        await cdp.close()  # type: ignore[union-attr]
    if server is not None:
        await server.aclose()  # type: ignore[union-attr]
    return "reset"


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str) -> Optional[int]:
    val = os.environ.get(name)
    return int(val) if val and val.isdigit() else None


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nokk-mcp",
        description="Run nokk as a stealth-browser MCP server (stdio transport).",
    )
    parser.add_argument(
        "--proxy",
        default=os.environ.get("NOKK_PROXY"),
        help="upstream proxy, e.g. socks5://host:1080 or http://user:pass@host:port",
    )
    parser.add_argument(
        "--rotate-fingerprint",
        action="store_true",
        default=_env_bool("NOKK_ROTATE_FINGERPRINT"),
        help="give each browsing session its own coherent fingerprint",
    )
    parser.add_argument(
        "--geoip-timezone",
        action="store_true",
        default=_env_bool("NOKK_GEOIP_TIMEZONE"),
        help="match timezone/locale to the proxy's exit IP",
    )
    parser.add_argument(
        "--session-store",
        default=os.environ.get("NOKK_SESSION_STORE"),
        help="directory for persistent named-session cookie jars",
    )
    parser.add_argument(
        "--no-auto-solve",
        action="store_true",
        default=_env_bool("NOKK_NO_AUTO_SOLVE"),
        help="do not solve Cloudflare challenges during navigation "
        "(the solve_challenge tool still works)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=_env_int("NOKK_WORKERS"),
        help="isolate worker threads",
    )
    args = parser.parse_args()

    _launch_kwargs.update(
        proxy=args.proxy,
        rotate_fingerprint=args.rotate_fingerprint,
        geoip_timezone=args.geoip_timezone,
        session_store=args.session_store,
        workers=args.workers,
        auto_solve=None if args.no_auto_solve else True,
    )
    mcp.run()


if __name__ == "__main__":
    main()
