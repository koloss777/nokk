//! WebSocket connections for the page's `WebSocket` object.
//!
//! The upgrade runs through the *same* [`wreq`] client as every `fetch`, so the
//! socket carries the same BoringSSL ClientHello (JA3/JA4), the same emulated
//! header order, the same cookie jar and the same proxy. That coherence is the
//! whole point: a "browser" whose sockets present a different TLS fingerprint
//! than its HTTP requests is a louder tell than one with no WebSocket at all.
//! See docs/websockets.md.
//!
//! The API here is deliberately channel-shaped rather than async: the isolate
//! that owns the page cannot await anything, so opening a socket spawns a task
//! and hands back a sender for outbound frames plus a receiver the engine drains
//! into JS between event-loop turns. Connecting never fails synchronously —
//! failures arrive as [`WsEvent::Error`], matching the spec, where `new
//! WebSocket(bad_url)` does not throw but fires an error event.

use tokio::sync::mpsc;

use crate::{Client, NetError};

/// Something the socket produced, on its way to the page.
#[derive(Debug, Clone)]
pub enum WsEvent {
    /// The upgrade succeeded; carries the negotiated subprotocol, if any.
    Open { protocol: String },
    Text(String),
    Binary(Vec<u8>),
    /// The peer (or we) closed it. `clean` is false for a dropped connection,
    /// which the page must see as code 1006 — the distinction is observable.
    Closed {
        code: u16,
        reason: String,
        clean: bool,
    },
    /// The connection failed before or during the upgrade.
    Error(String),
}

/// Something the page asked the socket to do.
#[derive(Debug, Clone)]
pub enum WsCommand {
    Text(String),
    Binary(Vec<u8>),
    Close { code: u16, reason: String },
}

/// The engine's handle on one open socket: an outbound channel plus the details
/// the page needs to answer for itself.
#[derive(Debug)]
pub struct WsHandle {
    tx: mpsc::UnboundedSender<WsCommand>,
}

impl WsHandle {
    /// Queue a frame. Returns false once the socket task is gone (closed or
    /// failed), which the caller reports as a closed socket rather than an error.
    pub fn send(&self, cmd: WsCommand) -> bool {
        self.tx.send(cmd).is_ok()
    }
}

/// Open `url` through `client`, returning the handle and the event stream.
///
/// `protocols` become `Sec-WebSocket-Protocol`; `origin` is sent as `Origin`,
/// which a browser always includes for a page-initiated socket and whose absence
/// some servers (and every attentive bot filter) will notice.
pub fn open(
    client: &Client,
    url: &str,
    protocols: &[String],
    origin: &str,
) -> (WsHandle, mpsc::UnboundedReceiver<WsEvent>) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel();

    match client {
        // No real network (the stub): report a failed connection the way a
        // browser would when the host is unreachable — asynchronously.
        Client::Stub(_) => {
            let _ = evt_tx.send(WsEvent::Error(NetError::Unimplemented.to_string()));
        }
        Client::Fingerprint(c) => {
            let inner = c.inner().clone();
            let (url, origin) = (url.to_string(), origin.to_string());
            let protocols = protocols.to_vec();
            tokio::spawn(async move { run(inner, url, protocols, origin, cmd_rx, evt_tx).await });
        }
    }
    (WsHandle { tx: cmd_tx }, evt_rx)
}

/// Own the socket for its whole life: connect, then shuttle frames both ways
/// until either side closes. One task per socket, off the isolate thread.
async fn run(
    client: wreq::Client,
    url: String,
    protocols: Vec<String>,
    origin: String,
    mut cmd_rx: mpsc::UnboundedReceiver<WsCommand>,
    evt_tx: mpsc::UnboundedSender<WsEvent>,
) {
    let mut builder = client.websocket(&url);
    if !protocols.is_empty() {
        builder = builder.protocols(protocols);
    }
    if !origin.is_empty() {
        builder = builder.header("origin", origin);
    }
    let resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            let _ = evt_tx.send(WsEvent::Error(e.to_string()));
            return;
        }
    };
    let mut socket = match resp.into_websocket().await {
        Ok(s) => s,
        Err(e) => {
            let _ = evt_tx.send(WsEvent::Error(e.to_string()));
            return;
        }
    };
    let protocol = socket
        .protocol()
        .and_then(|p| p.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if evt_tx.send(WsEvent::Open { protocol }).is_err() {
        return; // the context went away between connect and open
    }

    // `clean` stays false until a close frame actually arrives, so a dropped
    // connection surfaces as 1006 like it does in a browser.
    let mut closed = WsEvent::Closed {
        code: 1006,
        reason: String::new(),
        clean: false,
    };
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break }; // page dropped the socket
                let msg = match cmd {
                    WsCommand::Text(t) => wreq::ws::message::Message::text(t),
                    WsCommand::Binary(b) => wreq::ws::message::Message::binary(b),
                    WsCommand::Close { code, reason } => {
                        let _ = socket.close(code, reason.clone()).await;
                        closed = WsEvent::Closed { code, reason, clean: true };
                        break;
                    }
                };
                if let Err(e) = socket.send(msg).await {
                    let _ = evt_tx.send(WsEvent::Error(e.to_string()));
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(msg)) => match msg {
                        wreq::ws::message::Message::Text(t) => {
                            if evt_tx.send(WsEvent::Text(t.as_str().to_owned())).is_err() { return; }
                        }
                        wreq::ws::message::Message::Binary(b) => {
                            if evt_tx.send(WsEvent::Binary(b.to_vec())).is_err() { return; }
                        }
                        wreq::ws::message::Message::Close(frame) => {
                            let (code, reason) = frame
                                .map(|f| (u16::from(f.code), f.reason.as_str().to_owned()))
                                .unwrap_or((1005, String::new()));
                            closed = WsEvent::Closed { code, reason, clean: true };
                            break;
                        }
                        // Ping/Pong are answered by the transport; the page never
                        // sees them (nor does it in a browser).
                        _ => {}
                    },
                    Some(Err(e)) => {
                        let _ = evt_tx.send(WsEvent::Error(e.to_string()));
                        break;
                    }
                    None => break, // stream ended without a close frame -> 1006
                }
            }
        }
    }
    let _ = evt_tx.send(closed);
}
