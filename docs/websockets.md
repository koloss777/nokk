# Design: `WebSocket` (and friends) inside the page

Status: **P0 shipped** — text and binary frames work end to end, both directions,
including server-pushed frames. `EventSource` is still absent (P2 below). The
analysis that follows is what decided the shape; the "Phasing" section at the end
tracks what is left.

## What exists today

Two different things wear the name "WebSocket" in this repo, and only one of them
exists:

- **Outbound, as the CDP transport — done.** [`crates/cdp/src/server.rs`](../crates/cdp/src/server.rs)
  is a real WebSocket *server* (hand-rolled HTTP parse + handshake, then
  tokio-tungstenite). That is how Puppeteer connects to us.
- **Inside the page, as a JS API — absent.** Probed against the live engine
  (`nokk --eval`):

  ```json
  {"ws":"undefined","es":"undefined","fetch":"function","xhr":"function","worker":"function"}
  ```

  `WebSocket` and `EventSource` are not stubbed — they are *undefined*.

That costs us twice. **Functionally**, any page whose content arrives over a
socket (chats, live prices, notification streams) simply doesn't work, and
`new WebSocket(...)` throws `ReferenceError`. **As a fingerprint**, the absence
is itself the tell: every browser since 2011 has `typeof WebSocket === 'function'`,
so a one-line probe separates us from every real client — the same class of
differential tell the canvas and WebGL work spent months closing.

### Confirmed against a live target

A field report from a real deployment (a WebSocket-driven live-casino launcher
behind **Akamai Bot Manager**) puts a sharp edge on it. nokk *cleared the Akamai
challenge that headless Chrome failed* — 452 KB of the real app, a genuine
authenticated session from an in-page `fetch`, a 334 KB inline ES module with
top-level `await` executing correctly. Then the page loaded and did nothing at
all, because everything after the handshake travels over a socket: **one** request
in 40 seconds, and that one was injected by the tester.

That is the shape of the gap. The hard part — the fingerprint that gets you past
the bouncer — already works better than headless Chrome. The easy part, having a
socket to talk over, is what makes the engine unusable for the workload. It is
the single highest-value thing in the tracker right now.

## Rust or JavaScript?

**Both, along the seam this codebase already uses:** the socket and its frames in
Rust, the spec surface in JS. Neither half is optional, and the split is not a
matter of taste — two things force it.

**The isolate has no I/O.** JS in a context can't open a connection; it can only
enqueue an intention and be called back. That is exactly how `fetch`/XHR already
work ([`crates/stealth/src/lib.rs`](../crates/stealth/src/lib.rs)): `fetch()`
pushes onto a JS array and returns a Promise, Rust drains the array with
`__pt_drainFetchQueue()`, performs the request off the isolate thread, then
evaluates `__pt_fetchResolve(...)` back on the worker. A WebSocket is the same
shape with one addition — the server also speaks unprompted.

**The handshake must carry the browser's fingerprint.** A WebSocket upgrade is an
HTTP request over TLS, so it has a JA3/JA4 and a header order like any other. If
we opened it with a stock tokio-tungstenite + rustls stack, one "browser" would
present *two different TLS fingerprints* — the BoringSSL Chrome one for `fetch`,
a Rust-flavoured one for the socket. That is a louder tell than having no
WebSocket at all. Fortunately `wreq` (already our client) ships a `ws` feature:

```rust
client.websocket(uri).protocols([...]).emulation(...).send().await?
```

`WebSocketRequestBuilder` hangs off the same `Client`, so it inherits the
emulation profile, the per-context proxy, and the cookie jar for free — and
tokio-tungstenite is already in our tree via `nokk-cdp`, so the dependency weight
is a feature flag, not a new stack.

So: **Rust owns** the connection, the frame queues, and the lifecycle.
**JS owns** the `WebSocket` class, `readyState`, the event objects
(`MessageEvent`/`CloseEvent`), `binaryType`, `addEventListener` plumbing, and the
`[native code]` masking — where iteration is cheap and the masking machinery
already lives.

### What the sibling project does (nothing — check it anyway)

[obscura](https://github.com/h4ckf0r0day/obscura), the closest comparable engine,
has **no page-level `WebSocket` either**: no `WebSocket` in its `bootstrap.js`, no
`op_ws*` in its ops table, no `deno_websocket` extension, and `tokio-tungstenite`
appears only for its own CDP server — exactly our situation. So there is nothing
to borrow here, and shipping it makes nokk the first of the two to have it.

Their runtime is worth noting anyway, because it explains why this is cheaper for
them than for us: obscura is built on **`deno_core`**, so JS awaits Rust directly
(`await Deno.core.ops.op_fetch_url(...)`, `#[op2(async)]` on the Rust side) and the
event loop is a real futures executor. A long-lived socket there is an extension
with an async op and a resource table entry. We drive rusty_v8 ourselves with a
turn-based pump, which buys the fine-grained fairness and watchdog control our
concurrency story depends on — and is precisely what makes server-push a design
problem rather than a library call. That tradeoff is the next section.

## The actual hard part: the event loop

Not the socket. The pump.

Today's loop ([`crates/core/src/lib.rs`](../crates/core/src/lib.rs),
`pump_event_loop`) is shaped for *load-time* async: run timers, drain the fetch
queue, perform requests, settle promises, and **stop as soon as a round is idle**
(`ran == 0 && reqs.is_empty()`), under a ~3s wall-clock budget. That budget is
deliberately short because the worker is *shared*: a page with endless
`setInterval`s would otherwise starve every other context pinned to the same
thread — the documented dominant cause of timeouts under concurrent load.

A socket breaks both assumptions. It is **long-lived** (an idle round no longer
means "done") and **server-driven** (frames arrive with nothing on the JS side to
drain). Concretely, the loop needs:

1. **A liveness signal.** "Idle" becomes "no timers ran, no requests queued, *and*
   no open sockets" — otherwise the first quiet moment tears the connection down.
2. **An inbound path.** Rust holds a bounded per-context frame queue; each round
   drains it into `__pt_wsMessage(id, …)` calls, the mirror image of
   `__pt_fetchResolve`. Start with polling (latency = one round); a wakeup channel
   that re-arms the pump when a frame lands is the natural follow-up, not the
   starting point.
3. **A fairness policy.** An open socket must not let one context hold a shared
   worker indefinitely: a separate, larger budget for socket-bearing contexts,
   plus a cap on open sockets per context, plus a bounded inbound queue that
   closes the socket (code 1009) instead of growing without limit.

That policy — not the wire protocol — is the part worth designing carefully.

## Shape of the implementation

Mirroring the fetch machinery, so there is one pattern to learn:

| Layer | Piece |
|---|---|
| JS | `WebSocket` class: `send`/`close`/`readyState`/`url`/`protocol`/`bufferedAmount`/`binaryType`, `on{open,message,close,error}` + `addEventListener`, the four constants, masked native |
| JS→Rust | `__pt_drainWsQueue()` — opens, sends, closes the page asked for |
| Rust | one task per socket off the isolate thread; `wreq` `client.websocket()`; split into sink/stream |
| Rust→JS | `__pt_wsOpen(id, protocol)`, `__pt_wsMessage(id, data, isBinary)`, `__pt_wsClose(id, code, reason, wasClean)`, `__pt_wsError(id, msg)` |
| Engine | liveness + fairness in `pump_event_loop`, per-context socket table, tracker filter applied to `ws://`/`wss://` URLs too |

Details that have to be right to be worth doing at all: `Origin` on the upgrade
(a browser always sends it), subprotocol negotiation, `permessage-deflate`,
`binaryType` defaulting to `'blob'`, `CloseEvent.code` fidelity (1000/1006
distinction is observable), and `url` normalization (`ws:`/`wss:` only, a
`SyntaxError` otherwise). Where the engine has no real network (`use_real_network
= false`), the constructor must still exist and the connection must fail
*asynchronously* with an error event — matching a real browser that can't reach
the host, rather than a class that throws on construction.

## Neighbours

- **`EventSource` (SSE)** — cheap once the above exists: a long-lived HTTP GET of
  `text/event-stream` reusing the same liveness/drain machinery, plus a tiny line
  parser. Also currently `undefined`, also a tell. Do it in the same pass.
- **WebRTC** — `RTCPeerConnection` is already a JS stub, which is the right call:
  a *real* implementation would leak the host's local IPs, the classic WebRTC
  leak. Keep it a stub; make sure it enumerates no devices and gathers no
  candidates.
- **WebTransport / raw TCP-UDP** — out of scope. Browsers expose no raw sockets,
  and WebTransport needs HTTP/3; absence is not currently a meaningful tell.

## Phasing

1. **P0 — sockets end to end. ✅ done.** `crates/net/src/websocket.rs` (one task
   per socket over `client.websocket()`), the socket table + `apply_ws_ops` /
   `deliver_ws_events` in `crates/core/src/lib.rs`, the JS class in
   `crates/stealth/src/lib.rs`, and a 50 ms tick in the CDP server that pumps only
   pages holding a socket. Both directions, text and binary, `Origin` sent,
   subprotocols negotiated, tracker filter extended to `ws(s)://`, 64 sockets per
   page and 256 frames per round as the fairness bounds. Tested against an
   in-process echo server: open → send → echo → *unprompted server push* → clean
   close with code 1000, plus a dead-port connection that fires `error` then
   `close` with 1006 like a browser.
2. **P1 — robustness and visibility.** Real `bufferedAmount` (0 today),
   backpressure with an overflow close (1009), `Blob` frames read back through a
   real `Blob` rather than the shim, and CDP `Network.webSocketCreated` /
   `webSocketFrame*` events so Puppeteer's inspector sees the traffic — which
   needs the `Network` domain to emit anything at all first (see ROADMAP Phase 5).
3. **P2 — `EventSource`**, on the same rails.
