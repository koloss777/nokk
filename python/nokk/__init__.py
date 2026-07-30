"""nokk — launch the undetectable browser-engine CDP server and connect to it.

``nokk`` is a lightweight, Chrome-fingerprinted headless-browser engine driven
over the Chrome DevTools Protocol. This package embeds the prebuilt ``nokk``
binary, so there is nothing to build and no browser to download — ``pip install
nokk`` and go.

Synchronous::

    import nokk
    from playwright.sync_api import sync_playwright

    with nokk.launch() as server, sync_playwright() as pw:
        browser = pw.chromium.connect_over_cdp(server.ws_endpoint)
        page = browser.new_page()
        page.goto("https://example.com")
        print(page.title())

Asynchronous (never blocks the event loop)::

    import asyncio, nokk
    from playwright.async_api import async_playwright

    async def main():
        async with await nokk.launch_async() as server, async_playwright() as pw:
            browser = await pw.chromium.connect_over_cdp(server.ws_endpoint)
            page = await browser.new_page()
            await page.goto("https://example.com")
            print(await page.title())

    asyncio.run(main())
"""

from __future__ import annotations

import asyncio
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
from typing import List, Mapping, Optional, Sequence, Union

__all__ = [
    "launch",
    "launch_async",
    "NokkServer",
    "AsyncNokkServer",
    "binary_path",
    "__version__",
]

try:  # populated from the installed distribution metadata
    from importlib.metadata import PackageNotFoundError, version as _pkg_version

    try:
        __version__ = _pkg_version("nokk")
    except PackageNotFoundError:  # running from a source checkout
        __version__ = "0.0.0"
except Exception:  # pragma: no cover - importlib.metadata always present on 3.8+
    __version__ = "0.0.0"

_EXE = "nokk.exe" if os.name == "nt" else "nokk"

PathLike = Union[str, "os.PathLike[str]"]


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


def _build_command(
    host: str,
    port: int,
    *,
    workers: Optional[int],
    max_contexts: Optional[int],
    proxy: Optional[str],
    session_store: Optional[PathLike],
    rotate_fingerprint: bool,
    geoip_timezone: bool,
    allow_trackers: bool,
    args: Optional[Sequence[str]],
) -> List[str]:
    cmd = [binary_path(), "--host", host, "--port", str(port)]
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
    return cmd


def _merged_env(env: Optional[Mapping[str, str]]) -> "dict[str, str]":
    proc_env = dict(os.environ)
    if env:
        proc_env.update(env)
    return proc_env


def _terminate_quiet(process: "asyncio.subprocess.Process") -> None:
    """Best-effort, exception-free terminate — safe to call from ``atexit``.

    ``Process.terminate`` only sends the signal (no await), so this is fine even
    though the loop is gone by interpreter-exit time.
    """
    with contextlib.suppress(Exception):
        if process.returncode is None:
            process.terminate()


# --------------------------------------------------------------------------- #
# Synchronous API
# --------------------------------------------------------------------------- #


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
        state = "running" if self._process.poll() is None else "stopped"
        return f"<NokkServer {self.host}:{self.port} ({state}) pid={self.pid}>"


def launch(
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    workers: Optional[int] = None,
    max_contexts: Optional[int] = None,
    proxy: Optional[str] = None,
    session_store: Optional[PathLike] = None,
    rotate_fingerprint: bool = False,
    geoip_timezone: bool = False,
    allow_trackers: bool = False,
    args: Optional[Sequence[str]] = None,
    env: Optional[Mapping[str, str]] = None,
    timeout: float = 30.0,
) -> NokkServer:
    """Start a ``nokk`` CDP server and return a :class:`NokkServer`.

    See :func:`launch_async` for an equivalent that never blocks the event loop.

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
    cmd = _build_command(
        host,
        resolved_port,
        workers=workers,
        max_contexts=max_contexts,
        proxy=proxy,
        session_store=session_store,
        rotate_fingerprint=rotate_fingerprint,
        geoip_timezone=geoip_timezone,
        allow_trackers=allow_trackers,
        args=args,
    )
    process = subprocess.Popen(cmd, env=_merged_env(env))
    server = NokkServer(process, host, resolved_port)
    try:
        server._wait_until_ready(timeout)
    except BaseException:
        server.close()
        raise
    atexit.register(server.close)
    return server


# --------------------------------------------------------------------------- #
# Asynchronous API
# --------------------------------------------------------------------------- #


async def _ready_async(host: str, port: int, timeout: float) -> bool:
    """Whether the CDP HTTP endpoint answers 200, without blocking the loop."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
    except Exception:
        return False
    try:
        writer.write(
            f"GET /json/version HTTP/1.0\r\nHost: {host}:{port}\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), timeout)
        return b" 200 " in status
    except Exception:
        return False
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


class AsyncNokkServer:
    """A running ``nokk`` CDP server managed on the asyncio loop.

    Returned by :func:`launch_async`. Use ``async with`` or :meth:`aclose`.
    """

    def __init__(self, process: "asyncio.subprocess.Process", host: str, port: int):
        self._process = process
        self.host = host
        self.port = port

    @property
    def ws_endpoint(self) -> str:
        return f"ws://{self.host}:{self.port}/devtools/browser/nokk"

    @property
    def http_endpoint(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def pid(self) -> int:
        return self._process.pid

    async def _wait_until_ready(self, timeout: float) -> None:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if self._process.returncode is not None:
                raise RuntimeError(
                    f"nokk exited before becoming ready (code {self._process.returncode})"
                )
            if await _ready_async(self.host, self.port, 1.0):
                return
            await asyncio.sleep(0.05)
        raise TimeoutError(f"nokk did not become ready within {timeout:.1f}s")

    async def aclose(self, timeout: float = 5.0) -> None:
        """Stop the server. Idempotent."""
        proc = self._process
        if proc.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout)
        except Exception:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()

    async def __aenter__(self) -> "AsyncNokkServer":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        state = "running" if self._process.returncode is None else "stopped"
        return f"<AsyncNokkServer {self.host}:{self.port} ({state}) pid={self.pid}>"


async def launch_async(
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    workers: Optional[int] = None,
    max_contexts: Optional[int] = None,
    proxy: Optional[str] = None,
    session_store: Optional[PathLike] = None,
    rotate_fingerprint: bool = False,
    geoip_timezone: bool = False,
    allow_trackers: bool = False,
    args: Optional[Sequence[str]] = None,
    env: Optional[Mapping[str, str]] = None,
    timeout: float = 30.0,
) -> AsyncNokkServer:
    """Async equivalent of :func:`launch` — spawns the server and awaits
    readiness without blocking the event loop. Same keyword arguments.
    """
    resolved_port = port or _free_port(host)
    cmd = _build_command(
        host,
        resolved_port,
        workers=workers,
        max_contexts=max_contexts,
        proxy=proxy,
        session_store=session_store,
        rotate_fingerprint=rotate_fingerprint,
        geoip_timezone=geoip_timezone,
        allow_trackers=allow_trackers,
        args=args,
    )
    process = await asyncio.create_subprocess_exec(*cmd, env=_merged_env(env))
    server = AsyncNokkServer(process, host, resolved_port)
    try:
        await server._wait_until_ready(timeout)
    except BaseException:
        await server.aclose()
        raise
    atexit.register(_terminate_quiet, process)
    return server
