"""nokk — launch the undetectable browser-engine CDP server and connect to it.

``nokk`` is a lightweight, Chrome-fingerprinted headless-browser engine driven
over the Chrome DevTools Protocol. This package embeds the prebuilt ``nokk``
binary, so there is nothing to build and no browser to download — ``pip install
nokk`` and go.

Basic use with Playwright::

    import nokk
    from playwright.sync_api import sync_playwright

    with nokk.launch() as server, sync_playwright() as pw:
        browser = pw.chromium.connect_over_cdp(server.ws_endpoint)
        page = browser.new_page()
        page.goto("https://example.com")
        print(page.title())

Or with pyppeteer::

    import asyncio, nokk
    from pyppeteer import connect

    async def main():
        with nokk.launch() as server:
            browser = await connect(browserWSEndpoint=server.ws_endpoint)
            page = await browser.newPage()
            await page.goto("https://example.com")
            print(await page.title())

    asyncio.run(main())
"""

from __future__ import annotations

import atexit
import contextlib
import os
import shutil
import socket
import subprocess
import sys
import sysconfig
import time
import urllib.request
from pathlib import Path
from typing import Mapping, Optional, Sequence, Union

__all__ = ["launch", "NokkServer", "binary_path", "__version__"]

try:  # populated from the installed distribution metadata
    from importlib.metadata import PackageNotFoundError, version as _pkg_version

    try:
        __version__ = _pkg_version("nokk")
    except PackageNotFoundError:  # running from a source checkout
        __version__ = "0.0.0"
except Exception:  # pragma: no cover - importlib.metadata always present on 3.8+
    __version__ = "0.0.0"

_EXE = "nokk.exe" if os.name == "nt" else "nokk"


def binary_path() -> str:
    """Absolute path to the bundled ``nokk`` binary.

    Set ``NOKK_BINARY`` to override (e.g. to point at a locally built binary
    during development). Otherwise the binary installed alongside the wheel is
    used, falling back to one found on ``PATH``.
    """
    override = os.environ.get("NOKK_BINARY")
    if override:
        p = Path(override)
        if p.is_file():
            return str(p)
        raise FileNotFoundError(f"NOKK_BINARY points at a missing file: {override}")

    candidates = []
    scripts = sysconfig.get_path("scripts")
    if scripts:
        candidates.append(Path(scripts) / _EXE)
    # pip install --user lands the script in the user base's scripts dir.
    with contextlib.suppress(Exception):
        user_scheme = f"{os.name}_user"
        user_scripts = sysconfig.get_path("scripts", user_scheme)
        if user_scripts:
            candidates.append(Path(user_scripts) / _EXE)
    candidates.append(
        Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin") / _EXE
    )
    on_path = shutil.which("nokk")
    if on_path:
        candidates.append(Path(on_path))

    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return str(c)

    raise FileNotFoundError(
        "the bundled `nokk` binary was not found. Reinstall the package "
        "(`pip install --force-reinstall nokk`), or set NOKK_BINARY to a "
        "`nokk` executable. Note: prebuilt wheels are currently Linux x86_64 only."
    )


def _free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


class NokkServer:
    """A running ``nokk`` CDP server. Returned by :func:`launch`.

    Use it as a context manager, or call :meth:`close` when done. The server is
    also registered to shut down at interpreter exit as a safety net.
    """

    def __init__(self, process: "subprocess.Popen[bytes]", host: str, port: int):
        self._process = process
        self.host = host
        self.port = port

    @property
    def ws_endpoint(self) -> str:
        """``browserWSEndpoint`` to pass to ``connect_over_cdp`` / ``connect``."""
        return f"ws://{self.host}:{self.port}/devtools/browser/nokk"

    @property
    def http_endpoint(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def pid(self) -> int:
        return self._process.pid

    def _wait_until_ready(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        last_err: Optional[BaseException] = None
        url = f"{self.http_endpoint}/json/version"
        while time.monotonic() < deadline:
            code = self._process.poll()
            if code is not None:
                raise RuntimeError(f"nokk exited before becoming ready (code {code})")
            try:
                with urllib.request.urlopen(url, timeout=1.0) as resp:
                    if resp.status == 200:
                        return
            except Exception as e:  # connection refused until the port is up
                last_err = e
            time.sleep(0.05)
        raise TimeoutError(
            f"nokk did not become ready within {timeout:.1f}s ({last_err})"
        )

    def close(self, timeout: float = 5.0) -> None:
        """Stop the server. Idempotent."""
        proc = self._process
        if proc.poll() is not None:
            return
        with contextlib.suppress(Exception):
            proc.terminate()
        try:
            proc.wait(timeout)
        except Exception:
            with contextlib.suppress(Exception):
                proc.kill()
            with contextlib.suppress(Exception):
                proc.wait(timeout)

    def __enter__(self) -> "NokkServer":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        alive = self._process.poll() is None
        state = "running" if alive else "stopped"
        return f"<NokkServer {self.host}:{self.port} ({state}) pid={self.pid}>"


def launch(
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    workers: Optional[int] = None,
    max_contexts: Optional[int] = None,
    proxy: Optional[str] = None,
    session_store: Optional[Union[str, "os.PathLike[str]"]] = None,
    rotate_fingerprint: bool = False,
    geoip_timezone: bool = False,
    allow_trackers: bool = False,
    args: Optional[Sequence[str]] = None,
    env: Optional[Mapping[str, str]] = None,
    timeout: float = 30.0,
) -> NokkServer:
    """Start a ``nokk`` CDP server and return a :class:`NokkServer`.

    :param host: address to bind (default loopback).
    :param port: TCP port; ``0`` (default) picks a free one.
    :param workers: isolate worker threads (default: nokk's own default).
    :param max_contexts: cap on concurrent live contexts before backpressure.
    :param proxy: upstream proxy URL, e.g. ``socks5://host:1080`` or
        ``http://user:pass@host:port``.
    :param session_store: directory for persistent named-session cookie jars.
    :param rotate_fingerprint: give each browser context its own coherent
        fingerprint (OS/UA/screen/WebGL + matching TLS emulation).
    :param geoip_timezone: derive each context's timezone/locale from its
        proxy's exit IP.
    :param allow_trackers: load ad/analytics/tracker subresources (blocked by
        default).
    :param args: extra raw CLI arguments passed through to the binary.
    :param env: extra environment variables for the server process.
    :param timeout: seconds to wait for the server to accept connections.
    :raises TimeoutError: if the server does not become ready in ``timeout``.
    """
    resolved_port = port or _free_port(host)
    cmd = [binary_path(), "--host", host, "--port", str(resolved_port)]
    if workers is not None:
        cmd += ["--workers", str(workers)]
    if max_contexts is not None:
        cmd += ["--max-contexts", str(max_contexts)]
    if proxy:
        cmd += ["--proxy", proxy]
    if session_store is not None:
        cmd += ["--session-store", os.fspath(session_store)]
    if rotate_fingerprint:
        cmd.append("--rotate-fingerprint")
    if geoip_timezone:
        cmd.append("--geoip-timezone")
    if allow_trackers:
        cmd.append("--allow-trackers")
    if args:
        cmd += list(args)

    proc_env = dict(os.environ)
    if env:
        proc_env.update(env)

    process = subprocess.Popen(cmd, env=proc_env)
    server = NokkServer(process, host, resolved_port)
    try:
        server._wait_until_ready(timeout)
    except BaseException:
        server.close()
        raise
    atexit.register(server.close)
    return server
