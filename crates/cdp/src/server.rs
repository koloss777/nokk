//! CDP WebSocket server (Phase 5).
//!
//! Speaks enough of the Chrome DevTools Protocol for a real Puppeteer client to
//! `connect`, open a page, navigate, and evaluate JS against our engine. It is a
//! thin translator: a CDP command → a call on [`nokk::BrowserContext`],
//! plus the lifecycle/attach events Puppeteer waits for.
//!
//! Transport: one TCP listener serves both the HTTP discovery endpoints
//! (`/json/version`, `/json`) and the WebSocket upgrade (`/devtools/...`). We do
//! the HTTP parse + WS handshake by hand and hand the raw socket to tungstenite.
//!
//! Uses Puppeteer's "flatten" model: a single browser WebSocket carries all
//! messages; page-scoped messages carry a `sessionId`. No rendering, so visual
//! domains (screenshots, layout) are absent by design.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use nokk::{BrowserContext, Engine, ProxyConfig, ProxyScheme};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;

static IDS: AtomicU64 = AtomicU64::new(1);
fn next_id(prefix: &str) -> String {
    format!("{prefix}{:X}", IDS.fetch_add(1, Ordering::Relaxed))
}

/// CDP server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
}

/// Serve the CDP protocol until the listener errors. `engine` must be built with
/// real networking for navigation to work.
pub async fn serve(engine: Engine, config: ServerConfig) -> std::io::Result<()> {
    let listener = TcpListener::bind(config.addr).await?;
    let port = config.addr.port();
    tracing::info!(%config.addr, "CDP server listening — ws://{}/devtools/browser/nokk", config.addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        let engine = engine.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, engine, port).await {
                tracing::debug!(%peer, error = %e, "cdp connection ended");
            }
        });
    }
}

/// Read the HTTP request head (up to the blank line).
async fn read_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).await? != 0 {
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.len() > 32 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .find(|l| {
            l.to_ascii_lowercase()
                .starts_with(&format!("{}:", name.to_ascii_lowercase()))
        })
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim())
}

async fn handle_conn(mut stream: TcpStream, engine: Engine, port: u16) -> std::io::Result<()> {
    let head = read_head(&mut stream).await?;
    let request_line = head.lines().next().unwrap_or("");
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    let is_ws = header(&head, "upgrade")
        .map(|u| u.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if !is_ws {
        return serve_http(&mut stream, path, port).await;
    }

    // WebSocket upgrade handshake.
    let key = match header(&head, "sec-websocket-key") {
        Some(k) => k,
        None => {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return Ok(());
        }
    };
    let accept = derive_accept_key(key.as_bytes());
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(response.as_bytes()).await?;

    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    run_session(ws, engine).await;
    Ok(())
}

async fn serve_http(stream: &mut TcpStream, path: &str, port: u16) -> std::io::Result<()> {
    let ws_url = format!("ws://127.0.0.1:{port}/devtools/browser/nokk");
    let body = match path {
        p if p.starts_with("/json/version") => json!({
            "Browser": "Chrome/137.0.0.0",
            "Protocol-Version": "1.3",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
            "V8-Version": "13.7",
            "WebKit-Version": "537.36",
            "webSocketDebuggerUrl": ws_url,
        }),
        p if p.starts_with("/json") => json!([]),
        _ => json!({"error": "not found"}),
    };
    let body = body.to_string();
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await
}

/// Per-page state: the engine context plus its CDP identifiers.
struct Target {
    target_id: String,
    session_id: String,
    /// `Arc` so slow engine work (navigate/evaluate) can be handed to a spawned
    /// task and run concurrently, without holding up the connection's read loop.
    ctx: Arc<BrowserContext>,
    exec_ctx_id: i64,
    url: String,
    /// Puppeteer's isolated "utility" worlds: (worldName, current context id).
    /// Re-created on each navigation so isolated-realm evaluates resolve.
    iso_worlds: Vec<(String, i64)>,
    /// `Page.addScriptToEvaluateOnNewDocument` sources — Puppeteer injects its
    /// query utilities (`cssQuerySelector`, …) this way; we run them on every nav.
    init_scripts: Vec<String>,
    /// The Puppeteer browser context this page belongs to (`None` = default).
    browser_context_id: Option<String>,
}

struct Conn {
    engine: Engine,
    auto_attach: bool,
    targets: Vec<Target>,
    /// Puppeteer browser contexts (`browser.createBrowserContext`) → the proxy
    /// each one routes through. Targets created in a context inherit its proxy,
    /// giving per-identity (IP + cookie jar) isolation.
    browser_contexts: HashMap<String, Option<ProxyConfig>>,
}

/// Parse a CDP `proxyServer` string (`scheme://[user:pass@]host:port`, scheme
/// optional → http) into a [`ProxyConfig`].
fn parse_proxy_server(s: &str) -> Option<ProxyConfig> {
    let (scheme, rest) = s.split_once("://").unwrap_or(("http", s));
    let scheme = match scheme {
        "http" | "https" => ProxyScheme::Http,
        "socks5" | "socks5h" | "socks" => ProxyScheme::Socks5,
        _ => return None,
    };
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((a, hp)) => (Some(a), hp),
        None => (None, rest),
    };
    let (host, port) = hostport.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let (username, password) = match auth {
        Some(a) => match a.split_once(':') {
            Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
            None => (Some(a.to_string()), None),
        },
        None => (None, None),
    };
    Some(ProxyConfig {
        scheme,
        host: host.to_string(),
        port,
        username,
        password,
    })
}

/// A `Target.createTarget` whose context is being built off the read loop. The
/// engine work runs on a spawned task; the read loop registers the finished
/// target and sends the reply, so a slow/queued `new_context()` (under worker
/// saturation) never stalls the other commands on this connection.
struct PendingTarget {
    id: i64,
    session: Option<String>,
    result: Result<BrowserContext, String>,
    target_id: String,
    session_id: String,
    url: String,
    auto_attach: bool,
    browser_context_id: Option<String>,
}

async fn run_session<S>(ws: tokio_tungstenite::WebSocketStream<S>, engine: Engine)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut write, mut read) = ws.split();
    // All outgoing frames funnel through one channel + writer task, so responses
    // from concurrently-running command tasks (and the read loop) can interleave
    // safely on the single socket.
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if write.send(m).await.is_err() {
                break;
            }
        }
    });

    // `Target.createTarget` builds its context off the read loop and hands the
    // finished target back through this channel; the read loop then registers it
    // (targets stay single-threaded here) and replies.
    let (reg_tx, mut reg_rx) = mpsc::unbounded_channel::<PendingTarget>();

    let mut conn = Conn {
        engine,
        auto_attach: false,
        targets: Vec::new(),
        browser_contexts: HashMap::new(),
    };

    loop {
        tokio::select! {
            msg = read.next() => {
                let Some(Ok(msg)) = msg else { break };
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Close(_) => break,
                    Message::Ping(p) => {
                        let _ = tx.send(Message::Pong(p));
                        continue;
                    }
                    _ => continue,
                };
                let cmd: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                // dispatch does the connection-state work synchronously and hands
                // slow engine work (navigate/evaluate/createTarget/…) to spawned
                // tasks that reply via `tx`/`reg_tx`, so nothing blocks the loop.
                let out = conn.dispatch(&cmd, &tx, &reg_tx).await;
                for m in out {
                    if tx.send(Message::Text(m.to_string())).is_err() {
                        break;
                    }
                }
            }
            Some(pending) = reg_rx.recv() => {
                for m in conn.register_target(pending) {
                    let _ = tx.send(Message::Text(m.to_string()));
                }
            }
        }
    }
    drop(tx);
    let _ = writer.await;
}

impl Conn {
    /// Register a target whose context finished building off the read loop, and
    /// produce its `Target.createTarget` reply + `targetCreated` (+ attach) events.
    fn register_target(&mut self, pending: PendingTarget) -> Vec<Value> {
        let PendingTarget {
            id,
            session,
            result,
            target_id,
            session_id,
            url,
            auto_attach,
            browser_context_id,
        } = pending;
        match result {
            Ok(ctx) => {
                let t = Target {
                    target_id: target_id.clone(),
                    session_id: session_id.clone(),
                    ctx: Arc::new(ctx),
                    exec_ctx_id: IDS.fetch_add(1, Ordering::Relaxed) as i64,
                    url,
                    iso_worlds: Vec::new(),
                    init_scripts: Vec::new(),
                    browser_context_id,
                };
                let info = target_info(&t);
                self.targets.push(t);
                let mut out = vec![
                    ok(id, &session, json!({ "targetId": target_id })),
                    event("Target.targetCreated", &None, json!({ "targetInfo": info })),
                ];
                if auto_attach {
                    out.push(event(
                        "Target.attachedToTarget",
                        &None,
                        json!({ "sessionId": session_id, "targetInfo": info, "waitingForDebugger": false }),
                    ));
                }
                out
            }
            Err(e) => vec![err(id, &session, -32000, &format!("createTarget: {e}"))],
        }
    }

    async fn dispatch(
        &mut self,
        cmd: &Value,
        tx: &UnboundedSender<Message>,
        reg_tx: &UnboundedSender<PendingTarget>,
    ) -> Vec<Value> {
        let id = cmd.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
        let method = cmd.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = cmd.get("params").cloned().unwrap_or(json!({}));
        let session = cmd
            .get("sessionId")
            .and_then(|v| v.as_str())
            .map(String::from);
        tracing::debug!(method, session = session.is_some(), "cdp <<");

        match method {
            // ---- Browser ----
            "Browser.getVersion" => vec![ok(
                id,
                &session,
                json!({
                    "protocolVersion": "1.3",
                    "product": "Chrome/137.0.0.0",
                    "revision": "@nokk",
                    "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                    "jsVersion": "13.7",
                }),
            )],

            // ---- Target (browser-level) ----
            "Target.setDiscoverTargets" => vec![ok(id, &session, json!({}))],
            "Target.setAutoAttach" => {
                if session.is_none() {
                    self.auto_attach = params
                        .get("autoAttach")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                }
                vec![ok(id, &session, json!({}))]
            }
            "Target.getBrowserContexts" => {
                let ids: Vec<&String> = self.browser_contexts.keys().collect();
                vec![ok(id, &session, json!({ "browserContextIds": ids }))]
            }
            "Target.createBrowserContext" => {
                // Puppeteer's `browser.createBrowserContext({ proxyServer })`: a new
                // isolated context (its own proxy + cookie jar). Pages created in it
                // route through that proxy.
                let proxy = params
                    .get("proxyServer")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .and_then(parse_proxy_server);
                let bcid = next_id("BC");
                self.browser_contexts.insert(bcid.clone(), proxy);
                vec![ok(id, &session, json!({ "browserContextId": bcid }))]
            }
            "Target.disposeBrowserContext" => {
                if let Some(bc) = params.get("browserContextId").and_then(|v| v.as_str()) {
                    self.browser_contexts.remove(bc);
                }
                vec![ok(id, &session, json!({ "success": true }))]
            }
            "Target.getTargets" => {
                let infos: Vec<Value> = self.targets.iter().map(target_info).collect();
                vec![ok(id, &session, json!({ "targetInfos": infos }))]
            }
            "Target.createTarget" => {
                let url = params
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("about:blank")
                    .to_string();
                // Route this page through its browser context's proxy, if any.
                let browser_context_id = params
                    .get("browserContextId")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let proxy = browser_context_id
                    .as_deref()
                    .and_then(|bc| self.browser_contexts.get(bc).cloned())
                    .flatten();
                let target_id = next_id("T");
                let session_id = next_id("S");
                let engine = self.engine.clone();
                let auto_attach = self.auto_attach;
                let session = session.clone();
                let reg = reg_tx.clone();
                // Build the context off the read loop; the read loop registers it
                // and replies via `register_target` once it's ready.
                tokio::spawn(async move {
                    let result = engine
                        .new_context_with_proxy(proxy)
                        .await
                        .map_err(|e| e.to_string());
                    let _ = reg.send(PendingTarget {
                        id,
                        session,
                        result,
                        target_id,
                        session_id,
                        url,
                        auto_attach,
                        browser_context_id,
                    });
                });
                vec![]
            }
            "Target.attachToTarget" => {
                let tid = params
                    .get("targetId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if let Some(t) = self.targets.iter().find(|t| t.target_id == tid) {
                    let sid = t.session_id.clone();
                    let info = target_info(t);
                    vec![
                        ok(id, &session, json!({ "sessionId": sid })),
                        event(
                            "Target.attachedToTarget",
                            &None,
                            json!({ "sessionId": sid, "targetInfo": info, "waitingForDebugger": false }),
                        ),
                    ]
                } else {
                    vec![err(id, &session, -32000, "no such target")]
                }
            }
            "Target.closeTarget" => {
                let tid = params
                    .get("targetId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                // Emit the destruction events Puppeteer's `page.close()` awaits
                // (it resolves its close deferred on `detachedFromTarget` /
                // `targetDestroyed`); without them the client hangs. Only emit
                // for a target we actually held.
                let sid = self
                    .targets
                    .iter()
                    .find(|t| t.target_id == tid)
                    .map(|t| t.session_id.clone());
                self.targets.retain(|t| t.target_id != tid);
                let mut out = vec![ok(id, &session, json!({ "success": true }))];
                if let Some(sid) = sid {
                    out.push(event(
                        "Target.detachedFromTarget",
                        &None,
                        json!({ "sessionId": sid, "targetId": tid }),
                    ));
                    out.push(event(
                        "Target.targetDestroyed",
                        &None,
                        json!({ "targetId": tid }),
                    ));
                }
                out
            }
            "Target.activateTarget" | "Target.setRemoteLocations" => {
                vec![ok(id, &session, json!({}))]
            }

            // ---- session-scoped domains ----
            _ => self.dispatch_session(id, method, &params, &session, tx).await,
        }
    }

    async fn dispatch_session(
        &mut self,
        id: i64,
        method: &str,
        params: &Value,
        session: &Option<String>,
        tx: &UnboundedSender<Message>,
    ) -> Vec<Value> {
        // Resolve the target for this session.
        let idx = match session
            .as_deref()
            .and_then(|s| self.targets.iter().position(|t| t.session_id == s))
        {
            Some(i) => i,
            None => {
                // Browser-level or unknown: be lenient (empty result).
                return vec![ok(id, session, json!({}))];
            }
        };

        match method {
            "Runtime.enable" => {
                let (ctx_id, frame_id) = {
                    let t = &self.targets[idx];
                    (t.exec_ctx_id, t.target_id.clone())
                };
                vec![
                    ok(id, session, json!({})),
                    event(
                        "Runtime.executionContextCreated",
                        session,
                        json!({ "context": {
                            "id": ctx_id, "origin": "", "name": "",
                            "uniqueId": format!("{ctx_id}.1"),
                            "auxData": { "isDefault": true, "type": "default", "frameId": frame_id }
                        }}),
                    ),
                ]
            }
            "Page.enable"
            | "Network.enable"
            | "DOM.enable"
            | "Log.enable"
            | "Performance.enable"
            | "Runtime.runIfWaitingForDebugger"
            | "Page.setLifecycleEventsEnabled"
            | "Emulation.setDeviceMetricsOverride"
            | "Network.setUserAgentOverride"
            | "Runtime.addBinding" => {
                vec![ok(id, session, json!({}))]
            }
            "Page.addScriptToEvaluateOnNewDocument" => {
                if let Some(src) = params.get("source").and_then(|v| v.as_str()) {
                    self.targets[idx].init_scripts.push(src.to_string());
                }
                let ident = format!("initscript-{}", self.targets[idx].init_scripts.len());
                vec![ok(id, session, json!({ "identifier": ident }))]
            }
            "Page.createIsolatedWorld" => {
                let world_name = params
                    .get("worldName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("__isolated__")
                    .to_string();
                let iso_id = IDS.fetch_add(1, Ordering::Relaxed) as i64;
                let frame_id = self.targets[idx].target_id.clone();
                self.targets[idx]
                    .iso_worlds
                    .push((world_name.clone(), iso_id));
                vec![
                    ok(id, session, json!({ "executionContextId": iso_id })),
                    event(
                        "Runtime.executionContextCreated",
                        session,
                        json!({ "context": {
                            "id": iso_id, "origin": "", "name": world_name,
                            "uniqueId": format!("{iso_id}.1"),
                            "auxData": { "isDefault": false, "type": "isolated", "frameId": frame_id }
                        }}),
                    ),
                ]
            }
            "Page.getFrameTree" => {
                let t = &self.targets[idx];
                vec![ok(
                    id,
                    session,
                    json!({ "frameTree": {
                        "frame": { "id": t.target_id, "loaderId": "L1", "url": t.url,
                                   "domainAndRegistry": "", "securityOrigin": "://", "mimeType": "text/html" },
                        "childFrames": []
                    }}),
                )]
            }
            "Page.getNavigationHistory" => {
                let t = &self.targets[idx];
                vec![ok(
                    id,
                    session,
                    json!({ "currentIndex": 0, "entries": [
                        { "id": 0, "url": t.url, "userTypedURL": t.url, "title": "", "transitionType": "typed" }
                    ]}),
                )]
            }
            "Page.navigate" => {
                let url = params
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("about:blank")
                    .to_string();
                let loader = next_id("L");
                let new_ctx = IDS.fetch_add(1, Ordering::Relaxed) as i64;
                // Connection-state work is done synchronously here (in the read
                // loop): swap the target's execution context and re-key its
                // isolated worlds. The slow part (fetch + DOM + scripts) is then
                // run on a spawned task so it can't block other commands.
                let (target_id, scripts, iso_worlds) = {
                    let t = &mut self.targets[idx];
                    t.url = url.clone();
                    t.exec_ctx_id = new_ctx;
                    for w in t.iso_worlds.iter_mut() {
                        w.1 = IDS.fetch_add(1, Ordering::Relaxed) as i64;
                    }
                    (
                        t.target_id.clone(),
                        t.init_scripts.clone(),
                        t.iso_worlds.clone(),
                    )
                };
                let ctx = self.targets[idx].ctx.clone();
                let session = session.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    // Drive the real navigation, then Puppeteer's init scripts.
                    let nav = ctx.navigate(&url).await;
                    let nav_error = nav.as_ref().err().map(|e| e.to_string());
                    if let Some(e) = &nav_error {
                        tracing::debug!(error = %e, "Page.navigate error");
                    }
                    for src in &scripts {
                        let _ = ctx.evaluate(src).await;
                    }
                    let ev = |name: &str, params: Value| event(name, &session, params);
                    let lifecycle = |name: &str| {
                        ev(
                            "Page.lifecycleEvent",
                            json!({ "frameId": target_id, "loaderId": loader, "name": name, "timestamp": 0.0 }),
                        )
                    };
                    let nav_result = match &nav_error {
                        Some(e) => json!({ "frameId": target_id, "loaderId": loader, "errorText": e }),
                        None => json!({ "frameId": target_id, "loaderId": loader }),
                    };
                    let frame = json!({
                        "id": target_id, "loaderId": loader, "url": url,
                        "domainAndRegistry": "", "securityOrigin": "://", "mimeType": "text/html"
                    });
                    let mut out = vec![
                        ok(id, &session, nav_result),
                        ev("Page.frameStartedLoading", json!({ "frameId": target_id })),
                        ev("Page.frameNavigated", json!({ "frame": frame, "type": "Navigation" })),
                        ev("Runtime.executionContextsCleared", json!({})),
                        ev("Runtime.executionContextCreated", json!({ "context": {
                            "id": new_ctx, "origin": url, "name": "", "uniqueId": format!("{new_ctx}.1"),
                            "auxData": { "isDefault": true, "type": "default", "frameId": target_id }
                        }})),
                    ];
                    for (name, nid) in &iso_worlds {
                        out.push(ev("Runtime.executionContextCreated", json!({ "context": {
                            "id": nid, "origin": url, "name": name, "uniqueId": format!("{nid}.1"),
                            "auxData": { "isDefault": false, "type": "isolated", "frameId": target_id }
                        }})));
                    }
                    out.push(lifecycle("init"));
                    out.push(lifecycle("DOMContentLoaded"));
                    out.push(ev("Page.domContentEventFired", json!({ "timestamp": 0.0 })));
                    out.push(lifecycle("load"));
                    out.push(ev("Page.loadEventFired", json!({ "timestamp": 0.0 })));
                    out.push(ev("Page.frameStoppedLoading", json!({ "frameId": target_id })));
                    for m in out {
                        let _ = tx.send(Message::Text(m.to_string()));
                    }
                });
                vec![]
            }
            "Runtime.evaluate" => {
                let expr = params.get("expression").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let by_value = params.get("returnByValue").and_then(|v| v.as_bool()).unwrap_or(false);
                let await_promise = params.get("awaitPromise").and_then(|v| v.as_bool()).unwrap_or(false);
                let (ctx, session, tx) = (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let ro = remote_eval(&ctx, &expr, by_value, await_promise).await;
                    let _ = tx.send(Message::Text(ok(id, &session, json!({ "result": ro })).to_string()));
                });
                vec![]
            }
            "Runtime.callFunctionOn" => {
                let decl = params.get("functionDeclaration").and_then(|v| v.as_str()).unwrap_or("");
                let by_value = params.get("returnByValue").and_then(|v| v.as_bool()).unwrap_or(false);
                let await_promise = params.get("awaitPromise").and_then(|v| v.as_bool()).unwrap_or(false);
                // `this` is the handle's object (by objectId) or the global.
                let this_js = match params.get("objectId").and_then(|v| v.as_str()) {
                    Some(oid) => format!("__pt_objGet({})", js_str(oid)),
                    None => "globalThis".to_string(),
                };
                // Resolve each argument: a handle (objectId) or a literal value.
                let args_js: Vec<String> = params
                    .get("arguments")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|o| match o.get("objectId").and_then(|v| v.as_str()) {
                                Some(oid) => format!("__pt_objGet({})", js_str(oid)),
                                None => serde_json::to_string(
                                    &o.get("value").cloned().unwrap_or(Value::Null),
                                )
                                .unwrap_or_else(|_| "undefined".into()),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let expr = format!("({decl}).apply({this_js}, [{}])", args_js.join(","));
                let (ctx, session, tx) = (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let ro = remote_eval(&ctx, &expr, by_value, await_promise).await;
                    let _ = tx.send(Message::Text(ok(id, &session, json!({ "result": ro })).to_string()));
                });
                vec![]
            }
            "Runtime.getProperties" => {
                let oid = params.get("objectId").and_then(|v| v.as_str()).map(str::to_string);
                let (ctx, session, tx) = (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let props = match oid {
                        Some(oid) => {
                            let js = format!("JSON.stringify(__pt_getProps({}))", js_str(&oid));
                            match ctx.evaluate(&js).await {
                                Ok(Value::String(s)) => serde_json::from_str(&s).unwrap_or(json!([])),
                                _ => json!([]),
                            }
                        }
                        None => json!([]),
                    };
                    let _ = tx.send(Message::Text(ok(id, &session, json!({ "result": props })).to_string()));
                });
                vec![]
            }
            "Runtime.releaseObject" => {
                let oid = params.get("objectId").and_then(|v| v.as_str()).map(str::to_string);
                let (ctx, session, tx) = (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    if let Some(oid) = oid {
                        let _ = ctx.evaluate(&format!("__pt_release({})", js_str(&oid))).await;
                    }
                    let _ = tx.send(Message::Text(ok(id, &session, json!({})).to_string()));
                });
                vec![]
            }
            "Runtime.releaseObjectGroup" => vec![ok(id, session, json!({}))],
            "DOM.describeNode" => {
                let oid = params.get("objectId").and_then(|v| v.as_str()).map(str::to_string);
                let (ctx, session, tx) = (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let node = match oid {
                        Some(oid) => {
                            let js = format!("JSON.stringify(__pt_describe(__pt_objGet({})))", js_str(&oid));
                            match ctx.evaluate(&js).await {
                                Ok(Value::String(s)) => serde_json::from_str(&s).unwrap_or(Value::Null),
                                _ => Value::Null,
                            }
                        }
                        None => Value::Null,
                    };
                    let _ = tx.send(Message::Text(ok(id, &session, json!({ "node": node })).to_string()));
                });
                vec![]
            }
            "DOM.resolveNode" => {
                let bid = params.get("backendNodeId").and_then(|v| v.as_i64());
                let (ctx, session, tx) = (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let obj = match bid {
                        Some(bid) => {
                            let js = format!("JSON.stringify(__pt_wrap(__pt_nodeById({bid}), false))");
                            match ctx.evaluate(&js).await {
                                Ok(Value::String(s)) => serde_json::from_str(&s).unwrap_or(json!({ "type": "undefined" })),
                                _ => json!({ "type": "undefined" }),
                            }
                        }
                        None => json!({ "type": "undefined" }),
                    };
                    let _ = tx.send(Message::Text(ok(id, &session, json!({ "object": obj })).to_string()));
                });
                vec![]
            }
            "DOM.getDocument" => vec![ok(
                id,
                session,
                json!({ "root": {
                    "nodeId": 1, "backendNodeId": 1, "nodeType": 9, "nodeName": "#document",
                    "localName": "", "nodeValue": "", "childNodeCount": 1
                }}),
            )],
            // Lenient default: empty result keeps Puppeteer's promise chain alive.
            _ => vec![ok(id, session, json!({}))],
        }
    }
}

/// Evaluate `expr` and return a CDP `RemoteObject` — by value (JSON) or as an
/// `objectId` handle (via the JS `__pt_wrap` registry), matching `by_value`.
/// Drives the event loop when awaiting a Promise.
async fn remote_eval(
    ctx: &BrowserContext,
    expr: &str,
    by_value: bool,
    await_promise: bool,
) -> Value {
    let by = if by_value { "true" } else { "false" };
    let js = if await_promise {
        // Resolve the (possibly-Promise) value via the event loop, then wrap it.
        let setup = format!("globalThis.__cdp = ({expr});");
        if ctx.evaluate(&setup).await.is_err() {
            return json!({ "type": "undefined" });
        }
        let _ = ctx
            .evaluate("Promise.resolve(globalThis.__cdp).then(v => { globalThis.__cdp = v; }, e => { globalThis.__cdp = String(e); });")
            .await;
        let _ = ctx.run_event_loop().await;
        format!("JSON.stringify(__pt_wrap(globalThis.__cdp, {by}))")
    } else {
        format!(
            "(() => {{ try {{ return JSON.stringify(__pt_wrap(({expr}), {by})); }} \
               catch (e) {{ return JSON.stringify(__pt_wrap(String(e), true)); }} }})()"
        )
    };
    match ctx.evaluate(&js).await {
        Ok(Value::String(s)) => serde_json::from_str(&s).unwrap_or(json!({ "type": "undefined" })),
        _ => json!({ "type": "undefined" }),
    }
}

/// A JS string literal for `s` (safely quoted/escaped).
fn js_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn target_info(t: &Target) -> Value {
    json!({
        "targetId": t.target_id, "type": "page", "title": "", "url": t.url,
        "attached": true, "canAccessOpener": false,
        "browserContextId": t.browser_context_id.as_deref().unwrap_or("default")
    })
}

fn ok(id: i64, session: &Option<String>, result: Value) -> Value {
    let mut m = json!({ "id": id, "result": result });
    if let Some(s) = session {
        m["sessionId"] = json!(s);
    }
    m
}

fn err(id: i64, session: &Option<String>, code: i64, message: &str) -> Value {
    let mut m = json!({ "id": id, "error": { "code": code, "message": message } });
    if let Some(s) = session {
        m["sessionId"] = json!(s);
    }
    m
}

fn event(method: &str, session: &Option<String>, params: Value) -> Value {
    let mut m = json!({ "method": method, "params": params });
    if let Some(s) = session {
        m["sessionId"] = json!(s);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use nokk::{EngineConfig, PoolConfig};

    // V8 pool create/teardown must not overlap across tests in this binary (see
    // pool crate); serialise each test's engine lifetime.
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn test_conn() -> Conn {
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: false,
            ..Default::default()
        })
        .expect("engine");
        Conn {
            engine,
            auto_attach: false,
            targets: Vec::new(),
            browser_contexts: HashMap::new(),
        }
    }

    fn cmd(id: i64, method: &str, params: Value) -> Value {
        json!({ "id": id, "method": method, "params": params })
    }

    /// A drained outgoing-message sink for `dispatch` in tests.
    fn sink() -> UnboundedSender<Message> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        tx
    }

    /// A drained target-registration sink (used by dispatch calls that aren't
    /// createTarget and so never register a target).
    fn reg_sink() -> UnboundedSender<PendingTarget> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        tx
    }

    /// Drive `Target.createTarget` end to end: dispatch queues the async
    /// `new_context`; the server's read loop registers the finished target — here
    /// we do that inline and return the createTarget reply batch.
    async fn create_target(conn: &mut Conn, id: i64) -> Vec<Value> {
        let (reg_tx, mut reg_rx) = mpsc::unbounded_channel();
        conn.dispatch(
            &cmd(id, "Target.createTarget", json!({ "url": "about:blank" })),
            &sink(),
            &reg_tx,
        )
        .await;
        let pending = reg_rx.recv().await.expect("pending target");
        conn.register_target(pending)
    }

    /// The response object (has a matching `id`) from a dispatch batch.
    fn response(out: &[Value], id: i64) -> &Value {
        out.iter()
            .find(|m| m.get("id").and_then(|v| v.as_i64()) == Some(id))
            .expect("no response with that id")
    }

    /// Whether the batch contains an event with `method`.
    fn has_event(out: &[Value], method: &str) -> bool {
        out.iter()
            .any(|m| m.get("method").and_then(|v| v.as_str()) == Some(method))
    }

    #[test]
    fn parse_proxy_server_forms() {
        let p = super::parse_proxy_server("http://user:pass@10.0.0.1:8080").unwrap();
        assert_eq!(p.scheme, ProxyScheme::Http);
        assert_eq!(p.host, "10.0.0.1");
        assert_eq!(p.port, 8080);
        assert_eq!(p.username.as_deref(), Some("user"));
        assert_eq!(p.password.as_deref(), Some("pass"));
        // scheme optional -> http; socks5; no-auth
        assert_eq!(super::parse_proxy_server("host:3128").unwrap().scheme, ProxyScheme::Http);
        assert_eq!(super::parse_proxy_server("socks5://h:1080").unwrap().scheme, ProxyScheme::Socks5);
        assert!(super::parse_proxy_server("host:3128").unwrap().username.is_none());
        assert!(super::parse_proxy_server("ftp://h:1").is_none());
        assert!(super::parse_proxy_server("no-port").is_none());
    }

    #[tokio::test]
    async fn create_target_returns_id_and_emits_created() {
        let _s = SERIAL.lock().await;
        let mut conn = test_conn();
        let out = create_target(&mut conn, 1).await;
        let tid = response(&out, 1)["result"]["targetId"]
            .as_str()
            .expect("targetId")
            .to_string();
        assert!(!tid.is_empty());
        assert!(has_event(&out, "Target.targetCreated"));
        assert_eq!(conn.targets.len(), 1);
    }

    #[tokio::test]
    async fn close_target_emits_destroyed_and_drops_it() {
        let _s = SERIAL.lock().await;
        let mut conn = test_conn();
        let created = create_target(&mut conn, 1).await;
        let tid = response(&created, 1)["result"]["targetId"]
            .as_str()
            .unwrap()
            .to_string();

        let out = conn
            .dispatch(
                &cmd(2, "Target.closeTarget", json!({ "targetId": tid })),
                &sink(),
                &reg_sink(),
            )
            .await;
        // Puppeteer's page.close() hangs without these two events.
        assert!(has_event(&out, "Target.targetDestroyed"));
        assert!(has_event(&out, "Target.detachedFromTarget"));
        assert_eq!(response(&out, 2)["result"]["success"], json!(true));
        assert!(conn.targets.is_empty());
    }

    #[tokio::test]
    async fn get_targets_lists_open_targets() {
        let _s = SERIAL.lock().await;
        let mut conn = test_conn();
        create_target(&mut conn, 1).await;
        let out = conn
            .dispatch(&cmd(2, "Target.getTargets", json!({})), &sink(), &reg_sink())
            .await;
        let infos = response(&out, 2)["result"]["targetInfos"]
            .as_array()
            .expect("targetInfos array");
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0]["type"], json!("page"));
    }
}
