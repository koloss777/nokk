"""nokk as an MCP server — give an AI agent a stealth browser.

Exposes nokk over the Model Context Protocol (stdio), so an MCP client (Claude
Desktop, Claude Code, …) can navigate and scrape the web through nokk's
Chrome-fingerprinted engine instead of a headful browser that anti-bots flag.

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
import os
from typing import Dict, List, Optional

import nokk
from nokk._cdp import CDP, Page

# The MCP SDK's high-level server is `MCPServer` in v2, `FastMCP` in v1 — both
# share the `.tool()` decorator + `.run()` API this module uses.
try:
    try:
        from mcp.server import MCPServer as _Server  # SDK >= 2.0
    except ImportError:
        from mcp.server.fastmcp import FastMCP as _Server  # SDK 1.x
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "nokk-mcp needs the Model Context Protocol SDK. Install the extra: "
        'pip install "nokk[mcp]"'
    ) from exc


mcp = _Server("nokk")

# Lazily-created singletons: one nokk server + one page, shared across tool calls
# so the agent can navigate, then click, then read within one session. A lock
# serialises tool calls so overlapping navigate/read can't interleave.
_launch_kwargs: Dict[str, object] = {}
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


@mcp.tool()
async def open(url: str) -> Dict[str, str]:
    """Navigate the stealth browser to ``url``. Returns the final ``{url, title}``."""
    page = await _get_page()
    return await page.navigate(url)


@mcp.tool()
async def read_text(selector: str = "") -> Optional[str]:
    """Visible text of the current page, or of the first element matching the CSS
    ``selector`` if given."""
    page = await _get_page()
    return await page.read_text(selector or None)


@mcp.tool()
async def read_html(selector: str = "") -> Optional[str]:
    """Outer HTML of the current page, or of the first element matching the CSS
    ``selector`` if given."""
    page = await _get_page()
    return await page.read_html(selector or None)


@mcp.tool()
async def click(selector: str) -> bool:
    """Click the first element matching the CSS ``selector``."""
    page = await _get_page()
    return await page.click(selector)


@mcp.tool()
async def fill(selector: str, value: str) -> bool:
    """Set the value of the form field matching ``selector`` and fire input/change."""
    page = await _get_page()
    return await page.fill(selector, value)


@mcp.tool()
async def evaluate(expression: str) -> object:
    """Evaluate a JavaScript expression in the current page and return its value."""
    page = await _get_page()
    return await page.evaluate(expression)


@mcp.tool()
async def links() -> List[str]:
    """All absolute hyperlink URLs on the current page."""
    page = await _get_page()
    return await page.links()


@mcp.tool()
async def reset() -> str:
    """Discard the current browsing session (a fresh, coherent identity is used
    for the next navigation)."""
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
    )
    mcp.run()


if __name__ == "__main__":
    main()
