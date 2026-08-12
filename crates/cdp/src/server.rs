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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use nokk::{reason_phrase, BrowserContext, Engine, ProxyConfig, ProxyScheme};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;

/// Open pages, shared across every connection so the HTTP discovery endpoints
/// can answer. Targets themselves stay owned by the connection that made them
/// (they die with it); this is the index a client browses over `/json/list`.
#[derive(Clone, Default)]
struct TargetRegistry(Arc<std::sync::Mutex<Vec<Value>>>);

impl TargetRegistry {
    fn add(&self, entry: Value) {
        if let Ok(mut v) = self.0.lock() {
            v.push(entry);
        }
    }
    fn remove(&self, target_id: &str) {
        if let Ok(mut v) = self.0.lock() {
            v.retain(|e| e["id"] != target_id);
        }
    }
    fn set_url(&self, target_id: &str, url: &str) {
        if let Ok(mut v) = self.0.lock() {
            if let Some(e) = v.iter_mut().find(|e| e["id"] == target_id) {
                e["url"] = json!(url);
            }
        }
    }
    fn list(&self) -> Vec<Value> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

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
    let registry = TargetRegistry::default();
    tracing::info!(%config.addr, "CDP server listening — ws://{}/devtools/browser/nokk", config.addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        let engine = engine.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, engine, port, registry).await {
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

async fn handle_conn(
    mut stream: TcpStream,
    engine: Engine,
    port: u16,
    registry: TargetRegistry,
) -> std::io::Result<()> {
    let head = read_head(&mut stream).await?;
    let request_line = head.lines().next().unwrap_or("");
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    let is_ws = header(&head, "upgrade")
        .map(|u| u.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if !is_ws {
        return serve_http(&mut stream, path, port, &registry).await;
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
    run_session(ws, engine, port, registry).await;
    Ok(())
}

async fn serve_http(
    stream: &mut TcpStream,
    path: &str,
    port: u16,
    registry: &TargetRegistry,
) -> std::io::Result<()> {
    let ws_url = format!("ws://127.0.0.1:{port}/devtools/browser/nokk");
    let body = match path {
        p if p.starts_with("/json/version") => json!({
            "Browser": "Chrome/148.0.0.0",
            "Protocol-Version": "1.3",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
            "V8-Version": "13.7",
            "WebKit-Version": "537.36",
            "webSocketDebuggerUrl": ws_url,
        }),
        // The real page list. Every entry's debugger URL is the browser endpoint:
        // nokk uses CDP's flatten model, where one browser socket carries every
        // page and a client picks a page with `Target.attachToTarget`.
        p if p.starts_with("/json/list") || p == "/json" || p == "/json/" => {
            json!(registry.list())
        }
        // Creating a page without a connection to own it is not something this
        // server can do — pages live and die with the CDP connection that opened
        // them. Say so, rather than answering `[]` and leaving the client to
        // wonder (which is precisely what it used to do).
        p if p.starts_with("/json/new") => json!({
            "error": "not supported: open pages over the browser WebSocket with Target.createTarget",
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
    /// Set whenever page JS ran, so the tick below pumps the event loop once
    /// afterwards. `Runtime.evaluate` does not drive the loop itself (it must
    /// answer immediately), so without this the I/O that evaluated code queues —
    /// a `fetch`, or the *opening* of a WebSocket — would sit untouched until
    /// some later command happened to pump. That was a chicken-and-egg for
    /// sockets: the tick only pumps pages holding one, and holding one requires
    /// a pump.
    ran_js: Arc<AtomicBool>,
    /// The loader id of the navigation in flight. A client ties the document
    /// request to the navigation by *this* id, not by the frame's — Playwright's
    /// `page.goto()` waits for a response whose `loaderId` matches the one
    /// `Page.navigate` reported, and answers `None` when nothing ever does.
    loader_id: Arc<std::sync::Mutex<String>>,
    /// Extra sessions attached to this same page. Chrome mints a *fresh* session
    /// for every `Target.attachToTarget`, and a client that gets its existing one
    /// back sees an attach event for a session it already knows — which is what
    /// killed Playwright's driver on `new_cdp_session`. Commands may arrive on
    /// any of them.
    extra_sessions: Vec<String>,
}

struct Conn {
    engine: Engine,
    auto_attach: bool,
    targets: Vec<Target>,
    /// Shared page index behind `/json/list` (see [`TargetRegistry`]), plus the
    /// port so entries can carry a working debugger URL.
    registry: TargetRegistry,
    port: u16,
    /// Sessions attached to the *browser* rather than a page
    /// (`Target.attachToBrowserTarget`). Commands arriving on one are handled at
    /// browser level, exactly as if they carried no session at all.
    browser_sessions: Vec<String>,
    /// Puppeteer browser contexts (`browser.createBrowserContext`) → their config
    /// (proxy + optional persistent-session name). Targets created in a context
    /// inherit it, giving per-identity (IP + cookie jar) isolation and, when a
    /// `sessionName` was supplied, a jar that persists across runs.
    browser_contexts: HashMap<String, BrowserContextCfg>,
}

/// Per-browser-context configuration carried from `Target.createBrowserContext`
/// to the `Target.createTarget` calls made inside it.
#[derive(Clone, Default)]
struct BrowserContextCfg {
    proxy: Option<ProxyConfig>,
    /// A `sessionName` (non-standard param): routes pages through a named,
    /// persistent session jar (warm up once, resume later) instead of a
    /// per-connection in-memory identity.
    session: Option<String>,
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

/// A JS expression resolving the CDP node referenced by `params` (an `objectId`
/// handle or a `backendNodeId`/`nodeId`) to its live DOM node, or `null`.
fn node_ref(params: &Value) -> String {
    if let Some(oid) = params.get("objectId").and_then(|v| v.as_str()) {
        format!("__pt_objGet({})", js_str(oid))
    } else if let Some(bid) = params
        .get("backendNodeId")
        .or_else(|| params.get("nodeId"))
        .and_then(|v| v.as_i64())
    {
        format!("__pt_nodeById({bid})")
    } else {
        "null".to_string()
    }
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

async fn run_session<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    engine: Engine,
    port: u16,
    registry: TargetRegistry,
) where
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
        registry,
        port,
        browser_sessions: Vec::new(),
    };

    // Delivers server-pushed WebSocket frames between commands (see the tick arm
    // below). 20 Hz: fast enough that a page's `onmessage` feels immediate,
    // cheap enough to skip entirely when no page holds a socket.
    let mut socket_pump = tokio::time::interval(std::time::Duration::from_millis(50));
    socket_pump.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

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
            // A page holding a WebSocket receives frames nobody asked for, and the
            // engine's event loop only runs when a command drives it — so without
            // this tick a pushed frame would sit in the queue until the client
            // happened to evaluate something. Only pages with a live socket are
            // pumped, so the idle case costs one cheap check per tick.
            _ = socket_pump.tick() => { conn.pump_live_pages().await; }
        }
    }
    // Pages die with the connection that opened them, so drop them from the
    // shared index too or `/json/list` would advertise targets nobody can reach.
    for t in &conn.targets {
        conn.registry.remove(&t.target_id);
    }
    drop(tx);
    let _ = writer.await;
}

impl Conn {
    /// Give the event loop a turn on every page that needs one: either it holds a
    /// WebSocket (frames may be waiting, and nothing else would fetch them) or it
    /// just ran JS that could have queued I/O. Called on a timer by the session
    /// loop; pages with neither cost one atomic read.
    async fn pump_live_pages(&self) {
        for t in &self.targets {
            if t.ran_js.swap(false, Ordering::Relaxed) || t.ctx.has_open_sockets().await {
                let ctx = t.ctx.clone();
                tokio::spawn(async move {
                    let _ = ctx.run_event_loop().await;
                });
            }
        }
    }

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
                    ran_js: Arc::new(AtomicBool::new(false)),
                    loader_id: Arc::new(std::sync::Mutex::new(String::new())),
                    extra_sessions: Vec::new(),
                };
                let info = target_info(&t);
                self.registry.add(json!({
                    "id": t.target_id,
                    "type": "page",
                    "title": "",
                    "url": t.url,
                    "webSocketDebuggerUrl": format!("ws://127.0.0.1:{}/devtools/browser/nokk", self.port),
                    "devtoolsFrontendUrl": "",
                }));
                self.targets.push(t);
                // Emit the target lifecycle events *before* the createTarget reply.
                // Real Chrome fires `targetCreated`/`attachedToTarget` before the
                // command returns, and Playwright's `doCreateNewPage` relies on it:
                // it reads `_crPages.get(targetId)` the instant the reply arrives, so
                // the attach event must have populated that map first. (Puppeteer
                // awaits `targetCreated` separately, so the order is safe for it too.)
                let mut out = vec![event(
                    "Target.targetCreated",
                    &None,
                    json!({ "targetInfo": info }),
                )];
                if auto_attach {
                    out.push(event(
                        "Target.attachedToTarget",
                        &None,
                        json!({ "sessionId": session_id, "targetInfo": info, "waitingForDebugger": false }),
                    ));
                }
                out.push(ok(id, &session, json!({ "targetId": target_id })));
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

        // A browser-attached session is browser level; so is no session at all.
        let browser_level = match session.as_deref() {
            None => true,
            Some(s) => self.browser_sessions.iter().any(|b| b == s),
        };

        match method {
            // ---- Browser ----
            // Playwright's `new_cdp_session` opens a browser session first and
            // registers it by the id we hand back. Answering `{}` (the old
            // catch-all) made it register `undefined` and then trip an assertion
            // that killed its driver outright.
            "Target.getTargetInfo" => {
                let tid = params.get("targetId").and_then(|v| v.as_str());
                let info = match tid {
                    Some(t) => self
                        .targets
                        .iter()
                        .find(|x| x.target_id == t)
                        .map(target_info),
                    // No id means "the target this session is attached to"; at
                    // browser level that is the browser itself.
                    None => session
                        .as_deref()
                        .and_then(|s| {
                            self.targets.iter().find(|t| {
                                t.session_id == s || t.extra_sessions.iter().any(|e| e == s)
                            })
                        })
                        .map(target_info),
                };
                let info = info.unwrap_or_else(|| {
                    json!({ "targetId": "browser", "type": "browser", "title": "nokk",
                            "url": "", "attached": true, "canAccessOpener": false })
                });
                vec![ok(id, &session, json!({ "targetInfo": info }))]
            }
            "Target.attachToBrowserTarget" => {
                let sid = next_id("SB");
                self.browser_sessions.push(sid.clone());
                vec![ok(id, &session, json!({ "sessionId": sid }))]
            }
            // Playwright asks for cookies at *browser* level, with no sessionId
            // (`BrowserContext.cookies()`), so this has to answer before the
            // per-target dispatch below — which is why it used to fall through to
            // the catch-all and hand back `{}`, crashing the client on
            // `undefined.map`. Cookies come from the pages of the browser context
            // named in the params, or from every page when none is named.
            "Storage.getCookies" | "Network.getAllCookies" if browser_level => {
                let want = params
                    .get("browserContextId")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let mut seen = std::collections::HashSet::new();
                let mut cookies = Vec::new();
                for t in &self.targets {
                    if want.is_some() && t.browser_context_id != want {
                        continue;
                    }
                    for c in t.ctx.cookies(&[]) {
                        // Pages in one context share a jar; don't report twice.
                        let key = (c.name.clone(), c.domain.clone(), c.path.clone());
                        if seen.insert(key) {
                            cookies.push(cdp_cookie(c));
                        }
                    }
                }
                vec![ok(id, &session, json!({ "cookies": cookies }))]
            }
            "Browser.getVersion" => vec![ok(
                id,
                &session,
                json!({
                    "protocolVersion": "1.3",
                    "product": "Chrome/148.0.0.0",
                    "revision": "@nokk",
                    "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
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
                // route through that proxy. The non-standard `sessionName` param
                // (sent via raw CDP) additionally binds it to a named persistent
                // session, so its cookies survive across runs.
                let proxy = params
                    .get("proxyServer")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .and_then(parse_proxy_server);
                let session_name = params
                    .get("sessionName")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                let bcid = next_id("BC");
                self.browser_contexts.insert(
                    bcid.clone(),
                    BrowserContextCfg {
                        proxy,
                        session: session_name,
                    },
                );
                vec![ok(id, &session, json!({ "browserContextId": bcid }))]
            }
            "Target.disposeBrowserContext" => {
                let mut out = Vec::new();
                if let Some(bc) = params.get("browserContextId").and_then(|v| v.as_str()) {
                    self.browser_contexts.remove(bc);
                    // Close (drop) every page in this context, freeing its engine
                    // context, and tell the client — otherwise the targets leak.
                    let closing: Vec<String> = self
                        .targets
                        .iter()
                        .filter(|t| t.browser_context_id.as_deref() == Some(bc))
                        .map(|t| t.target_id.clone())
                        .collect();
                    self.targets
                        .retain(|t| t.browser_context_id.as_deref() != Some(bc));
                    for tid in closing {
                        out.push(event(
                            "Target.targetDestroyed",
                            &None,
                            json!({ "targetId": tid }),
                        ));
                    }
                }
                out.push(ok(id, &session, json!({ "success": true })));
                out
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
                // Route this page through its browser context's proxy + session.
                let browser_context_id = params
                    .get("browserContextId")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let cfg = browser_context_id
                    .as_deref()
                    .and_then(|bc| self.browser_contexts.get(bc).cloned())
                    .unwrap_or_default();
                let proxy = cfg.proxy;
                let target_id = next_id("T");
                let session_id = next_id("S");
                let engine = self.engine.clone();
                let auto_attach = self.auto_attach;
                let session = session.clone();
                let reg = reg_tx.clone();
                // Identity = the browser context id, so every page in a browser
                // context shares its cookie jar while distinct contexts stay
                // isolated (Puppeteer semantics); the default context (empty id)
                // uses the engine's shared default client.
                let identity = browser_context_id.clone().unwrap_or_default();
                let session_name = cfg.session;
                // Build the context off the read loop; the read loop registers it
                // and replies via `register_target` once it's ready. A named
                // browser context uses a persistent session jar; otherwise the
                // per-connection identity jar.
                tokio::spawn(async move {
                    let result = match session_name {
                        Some(name) => engine.new_context_with_session(name, proxy).await,
                        None => engine.new_context_with_identity(identity, proxy).await,
                    }
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
                if let Some(t) = self.targets.iter_mut().find(|t| t.target_id == tid) {
                    // A page may be attached to more than once (Playwright's
                    // `new_cdp_session` does exactly that on a page it already
                    // drives); each attach is its own session, as in Chrome.
                    let sid = if t.session_id.is_empty() {
                        t.session_id = next_id("S");
                        t.session_id.clone()
                    } else {
                        let extra = next_id("S");
                        t.extra_sessions.push(extra.clone());
                        extra
                    };
                    let info = target_info(t);
                    vec![
                        ok(id, &session, json!({ "sessionId": sid })),
                        // On the session that asked, not the root: in the flatten
                        // model the attach event belongs to the parent session, and
                        // a client that receives it on the root builds a *second*
                        // session object for the same id — after which replies land
                        // on the wrong one and its assertions fire.
                        event(
                            "Target.attachedToTarget",
                            &session,
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
                self.registry.remove(tid);
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
            _ => {
                self.dispatch_session(id, method, &params, &session, tx)
                    .await
            }
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
        // A configure-only method is a no-op at either level, so this is checked
        // before a page is resolved: clients send some of them with a session and
        // some without, and the answer is the same either way.
        if is_configuration_noop(method) {
            return vec![ok(id, session, json!({}))];
        }

        // Resolve the target for this session.
        let idx = match session.as_deref().and_then(|s| {
            self.targets
                .iter()
                .position(|t| t.session_id == s || t.extra_sessions.iter().any(|e| e == s))
        }) {
            Some(i) => i,
            None => {
                // Nothing above claimed it, and there is no page to route it to.
                return match session {
                    // A session id we do not know: Chrome's own code for it, and
                    // the one clients quietly tolerate (Playwright ignores -32001
                    // by design, since sessions die asynchronously).
                    Some(_) => vec![err(id, session, -32001, "Session with given id not found.")],
                    // Browser level, unimplemented. Say so.
                    None => vec![err(
                        id,
                        session,
                        -32601,
                        &format!("'{method}' wasn't found"),
                    )],
                };
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
            // The jar the engine actually sends, HttpOnly included — `document.cookie`
            // cannot see the ones that matter (a `cf_clearance`, Akamai's `bm_s*`),
            // so this is the only route for handing a warmed session to another
            // process. `Storage.getCookies` is the browser-wide spelling of the
            // same thing; both answer from this page's client.
            "Network.getCookies" | "Network.getAllCookies" | "Storage.getCookies" => {
                let urls: Vec<String> = params
                    .get("urls")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let cookies: Vec<Value> = self.targets[idx]
                    .ctx
                    .cookies(&urls)
                    .into_iter()
                    .map(cdp_cookie)
                    .collect();
                vec![ok(id, session, json!({ "cookies": cookies }))]
            }
            // Chrome only reports network activity after `enable`, and a client
            // that never calls it must not be flooded — so the subscription is
            // set up here, not at target creation.
            "Network.enable" => {
                let ctx = self.targets[idx].ctx.clone();
                let mut rx = ctx.subscribe_network();
                let (frame, sess, out, loader) = (
                    self.targets[idx].target_id.clone(),
                    session.clone(),
                    tx.clone(),
                    self.targets[idx].loader_id.clone(),
                );
                tokio::spawn(async move {
                    while let Some(rec) = rx.recv().await {
                        let loader_id = loader.lock().map(|l| l.clone()).unwrap_or_default();
                        for m in network_events(&rec, &frame, &loader_id, &sess) {
                            if out.send(Message::Text(m.to_string())).is_err() {
                                return;
                            }
                        }
                    }
                });
                vec![ok(id, session, json!({}))]
            }
            "Page.enable"
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
                if let Ok(mut slot) = self.targets[idx].loader_id.lock() {
                    slot.clone_from(&loader);
                }
                self.registry.set_url(&self.targets[idx].target_id, &url);
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
                        Some(e) => {
                            json!({ "frameId": target_id, "loaderId": loader, "errorText": e })
                        }
                        None => json!({ "frameId": target_id, "loaderId": loader }),
                    };
                    let frame = json!({
                        "id": target_id, "loaderId": loader, "url": url,
                        "domainAndRegistry": "", "securityOrigin": "://", "mimeType": "text/html"
                    });
                    let mut out = vec![
                        ok(id, &session, nav_result),
                        ev("Page.frameStartedLoading", json!({ "frameId": target_id })),
                        ev(
                            "Page.frameNavigated",
                            json!({ "frame": frame, "type": "Navigation" }),
                        ),
                        ev("Runtime.executionContextsCleared", json!({})),
                        ev(
                            "Runtime.executionContextCreated",
                            json!({ "context": {
                                "id": new_ctx, "origin": url, "name": "", "uniqueId": format!("{new_ctx}.1"),
                                "auxData": { "isDefault": true, "type": "default", "frameId": target_id }
                            }}),
                        ),
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
                    out.push(ev(
                        "Page.frameStoppedLoading",
                        json!({ "frameId": target_id }),
                    ));
                    for m in out {
                        let _ = tx.send(Message::Text(m.to_string()));
                    }
                });
                vec![]
            }
            "Runtime.evaluate" => {
                let expr = params
                    .get("expression")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let by_value = params
                    .get("returnByValue")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let await_promise = params
                    .get("awaitPromise")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                // Whatever this evaluate queued (a fetch, a socket) gets pumped by
                // the tick; the reply itself must not wait for the event loop.
                self.targets[idx].ran_js.store(true, Ordering::Relaxed);
                tokio::spawn(async move {
                    let ro = remote_eval(&ctx, &expr, by_value, await_promise).await;
                    let _ = tx.send(Message::Text(
                        ok(id, &session, json!({ "result": ro })).to_string(),
                    ));
                });
                vec![]
            }
            "Runtime.callFunctionOn" => {
                let decl = params
                    .get("functionDeclaration")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let by_value = params
                    .get("returnByValue")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let await_promise = params
                    .get("awaitPromise")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
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
                // Newline-isolate the declaration too — Playwright's function
                // sources can carry a trailing `//# sourceURL=` comment.
                let expr = format!("(\n{decl}\n).apply({this_js}, [{}])", args_js.join(","));
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                // Whatever this evaluate queued (a fetch, a socket) gets pumped by
                // the tick; the reply itself must not wait for the event loop.
                self.targets[idx].ran_js.store(true, Ordering::Relaxed);
                tokio::spawn(async move {
                    let ro = remote_eval(&ctx, &expr, by_value, await_promise).await;
                    let _ = tx.send(Message::Text(
                        ok(id, &session, json!({ "result": ro })).to_string(),
                    ));
                });
                vec![]
            }
            "Runtime.getProperties" => {
                let oid = params
                    .get("objectId")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let props = match oid {
                        Some(oid) => {
                            let js = format!("JSON.stringify(__pt_getProps({}))", js_str(&oid));
                            match ctx.evaluate(&js).await {
                                Ok(Value::String(s)) => {
                                    serde_json::from_str(&s).unwrap_or(json!([]))
                                }
                                _ => json!([]),
                            }
                        }
                        None => json!([]),
                    };
                    let _ = tx.send(Message::Text(
                        ok(id, &session, json!({ "result": props })).to_string(),
                    ));
                });
                vec![]
            }
            "Runtime.releaseObject" => {
                let oid = params
                    .get("objectId")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    if let Some(oid) = oid {
                        let _ = ctx
                            .evaluate(&format!("__pt_release({})", js_str(&oid)))
                            .await;
                    }
                    let _ = tx.send(Message::Text(ok(id, &session, json!({})).to_string()));
                });
                vec![]
            }
            "Runtime.releaseObjectGroup" => vec![ok(id, session, json!({}))],
            "DOM.describeNode" => {
                let oid = params
                    .get("objectId")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let node = match oid {
                        Some(oid) => {
                            let js = format!(
                                "JSON.stringify(__pt_describe(__pt_objGet({})))",
                                js_str(&oid)
                            );
                            match ctx.evaluate(&js).await {
                                Ok(Value::String(s)) => {
                                    serde_json::from_str(&s).unwrap_or(Value::Null)
                                }
                                _ => Value::Null,
                            }
                        }
                        None => Value::Null,
                    };
                    let _ = tx.send(Message::Text(
                        ok(id, &session, json!({ "node": node })).to_string(),
                    ));
                });
                vec![]
            }
            "DOM.resolveNode" => {
                let bid = params.get("backendNodeId").and_then(|v| v.as_i64());
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let obj = match bid {
                        Some(bid) => {
                            let js =
                                format!("JSON.stringify(__pt_wrap(__pt_nodeById({bid}), false))");
                            match ctx.evaluate(&js).await {
                                Ok(Value::String(s)) => serde_json::from_str(&s)
                                    .unwrap_or(json!({ "type": "undefined" })),
                                _ => json!({ "type": "undefined" }),
                            }
                        }
                        None => json!({ "type": "undefined" }),
                    };
                    let _ = tx.send(Message::Text(
                        ok(id, &session, json!({ "object": obj })).to_string(),
                    ));
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
            // Box model / content quads: the synthetic layout's box for a node, so
            // Puppeteer/Playwright can compute a clickable point. An empty box
            // (hidden/detached) → the "not clickable" errors the drivers expect.
            "DOM.getBoxModel" => {
                let nref = node_ref(params);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let js = format!("JSON.stringify(__pt_boxModel({nref}))");
                    let msg = match ctx.evaluate(&js).await {
                        Ok(Value::String(ref s)) if s != "null" => {
                            match serde_json::from_str::<Value>(s) {
                                Ok(model) if !model.is_null() => {
                                    ok(id, &session, json!({ "model": model }))
                                }
                                _ => err(id, &session, -32000, "Could not compute box model."),
                            }
                        }
                        _ => err(id, &session, -32000, "Could not compute box model."),
                    };
                    let _ = tx.send(Message::Text(msg.to_string()));
                });
                vec![]
            }
            "DOM.getContentQuads" => {
                let nref = node_ref(params);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let js = format!("JSON.stringify(__pt_contentQuads({nref}))");
                    let quads = match ctx.evaluate(&js).await {
                        Ok(Value::String(s)) => serde_json::from_str(&s).unwrap_or(json!([])),
                        _ => json!([]),
                    };
                    let _ = tx.send(Message::Text(
                        ok(id, &session, json!({ "quads": quads })).to_string(),
                    ));
                });
                vec![]
            }
            "DOM.focus" => {
                let nref = node_ref(params);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let _ = ctx.evaluate(&format!("__pt_focusNode({nref})")).await;
                    let _ = tx.send(Message::Text(ok(id, &session, json!({})).to_string()));
                });
                vec![]
            }
            "DOM.scrollIntoViewIfNeeded" => vec![ok(id, session, json!({}))],
            "Page.getLayoutMetrics" => {
                let vp =
                    json!({ "pageX": 0, "pageY": 0, "clientWidth": 1280, "clientHeight": 720 });
                let visual = json!({ "offsetX": 0, "offsetY": 0, "pageX": 0, "pageY": 0,
                    "clientWidth": 1280, "clientHeight": 720, "scale": 1, "zoom": 1 });
                let content = json!({ "x": 0, "y": 0, "width": 1280, "height": 720 });
                vec![ok(
                    id,
                    session,
                    json!({
                        "layoutViewport": vp, "visualViewport": visual, "contentSize": content,
                        "cssLayoutViewport": vp, "cssVisualViewport": visual, "cssContentSize": content,
                    }),
                )]
            }
            // Input domain: translate coordinate/key events into DOM events via the
            // synthetic layout's point→element hit-test (see __pt_mouse/__pt_key).
            "Input.dispatchMouseEvent" => {
                let mtype = params
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let x = params.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let y = params.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let button = params
                    .get("button")
                    .and_then(|v| v.as_str())
                    .unwrap_or("left")
                    .to_string();
                let clicks = params
                    .get("clickCount")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(1);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let js = format!(
                        "__pt_mouse({}, {}, {}, {}, {})",
                        js_str(&mtype),
                        x,
                        y,
                        js_str(&button),
                        clicks
                    );
                    let _ = ctx.evaluate(&js).await;
                    let _ = ctx.run_event_loop().await; // let click handlers settle
                    let _ = tx.send(Message::Text(ok(id, &session, json!({})).to_string()));
                });
                vec![]
            }
            "Input.dispatchKeyEvent" => {
                let ktype = params
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let key = params
                    .get("key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let code = params
                    .get("code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let kc = params
                    .get("windowsVirtualKeyCode")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let text = params
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let js = format!(
                        "__pt_key({}, {{ key: {}, code: {}, keyCode: {}, text: {} }})",
                        js_str(&ktype),
                        js_str(&key),
                        js_str(&code),
                        kc,
                        js_str(&text)
                    );
                    let _ = ctx.evaluate(&js).await;
                    let _ = ctx.run_event_loop().await;
                    let _ = tx.send(Message::Text(ok(id, &session, json!({})).to_string()));
                });
                vec![]
            }
            "Input.insertText" => {
                let text = params
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let _ = ctx
                        .evaluate(&format!("__pt_insertText({})", js_str(&text)))
                        .await;
                    let _ = ctx.run_event_loop().await;
                    let _ = tx.send(Message::Text(ok(id, &session, json!({})).to_string()));
                });
                vec![]
            }
            // Lenient default: empty result keeps Puppeteer's promise chain alive.
            // Everything else genuinely is not implemented, and says so the way
            // Chrome does. Answering an empty *success* (as this used to) is
            // indistinguishable from "nothing to report", so a client cannot tell
            // a gap from an empty result and waits forever — the single defect
            // behind most of the field report.
            _ => vec![err(
                id,
                session,
                -32601,
                &format!("'{method}' wasn't found"),
            )],
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
    // Evaluate the caller's source as a *script* via indirect `eval`, taking its
    // completion value — exactly what CDP `Runtime.evaluate` does, and in global
    // scope. Splicing the source inline as a sub-expression (`__pt_wrap((SRC),…)`)
    // breaks on the statement forms Puppeteer/Playwright actually send: an IIFE
    // with a trailing `;` becomes `(…;)` (illegal semicolon in parens) and a
    // trailing `//# sourceURL=` comment swallows the wrapper's `)`. Passing the
    // source as a string sidesteps both. `(0, eval)` forces the indirect/global
    // form rather than a scoped direct eval.
    let src = js_str(expr);
    let js = if await_promise {
        // Resolve the (possibly-Promise) value via the event loop, then wrap it.
        // The await path spans several `evaluate` calls with event-loop turns in
        // between, during which *other* concurrently-dispatched commands run on
        // the same context. A shared global would be clobbered mid-flight (two
        // overlapping evaluates racing on it), so each call gets a unique slot.
        let slot = format!("__cdp_{}", IDS.fetch_add(1, Ordering::Relaxed));
        let setup = format!("globalThis.{slot} = (0, eval)({src});");
        if ctx.evaluate(&setup).await.is_err() {
            return json!({ "type": "undefined" });
        }
        let _ = ctx
            .evaluate(&format!(
                "Promise.resolve(globalThis.{slot}).then(v => {{ globalThis.{slot} = v; }}, e => {{ globalThis.{slot} = String(e); }});"
            ))
            .await;
        let _ = ctx.run_event_loop().await;
        format!(
            "(() => {{ const v = globalThis.{slot}; delete globalThis.{slot}; return JSON.stringify(__pt_wrap(v, {by})); }})()"
        )
    } else {
        format!(
            "(() => {{ try {{ return JSON.stringify(__pt_wrap((0, eval)({src}), {by})); }} \
               catch (e) {{ return JSON.stringify(__pt_wrap(String(e), true)); }} }})()"
        )
    };
    match ctx.evaluate(&js).await {
        Ok(Value::String(s)) => serde_json::from_str(&s).unwrap_or(json!({ "type": "undefined" })),
        _ => json!({ "type": "undefined" }),
    }
}

/// Expand one completed request into the CDP events a client expects to see for
/// it. Chrome spreads these over the request's lifetime; we know the outcome
/// before we report anything, so they go out together — every field is real, the
/// timings are just coarser. Playwright builds `page.goto()`'s response object
/// out of `responseReceived`, which is why its absence made `goto` return `None`.
fn network_events(
    rec: &nokk::NetworkRecord,
    frame_id: &str,
    loader_id: &str,
    session: &Option<String>,
) -> Vec<Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default();
    let kind = match rec.resource_type.as_str() {
        "document" => "Document",
        "script" => "Script",
        "websocket" => "WebSocket",
        "image" => "Image",
        "beacon" | "fetch" => "Fetch",
        _ => "Other",
    };
    // Chrome gives a navigation's document request the *same* id as its loader,
    // and both Playwright and Puppeteer identify the navigation that way
    // (`requestId === loaderId && type === 'Document'`). Without it `page.goto()`
    // never finds its response and answers `None`.
    let request_id = if kind == "Document" && !loader_id.is_empty() {
        loader_id.to_string()
    } else {
        rec.request_id.clone()
    };
    let mut out = vec![event(
        "Network.requestWillBeSent",
        session,
        json!({
            "requestId": request_id,
            "loaderId": loader_id,
            "documentURL": rec.url,
            "request": { "url": rec.url, "method": rec.method, "headers": {},
                         "initialPriority": "High", "referrerPolicy": "strict-origin-when-cross-origin" },
            "timestamp": now,
            "wallTime": now,
            "initiator": { "type": if kind == "Document" { "other" } else { "parser" } },
            "type": kind,
            "frameId": frame_id,
            "hasUserGesture": false,
        }),
    )];
    // Status 0 means the request never produced a response — a blocked tracker,
    // a DNS failure, a reset. Chrome reports that as a loading failure, not as a
    // response, and a client that waits for one would otherwise wait forever.
    if rec.status == 0 {
        out.push(event(
            "Network.loadingFailed",
            session,
            json!({
                "requestId": request_id,
                "timestamp": now,
                "type": kind,
                "errorText": "net::ERR_FAILED",
                "canceled": false,
            }),
        ));
        return out;
    }
    let mime = rec
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_string())
        .unwrap_or_else(|| "text/plain".to_string());
    out.push(event(
        "Network.responseReceived",
        session,
        json!({
            "requestId": request_id,
            "loaderId": loader_id,
            "timestamp": now,
            "type": kind,
            "frameId": frame_id,
            "response": {
                "url": rec.url,
                "status": rec.status,
                "statusText": reason_phrase(rec.status),
                "headers": rec.headers,
                "mimeType": mime,
                "connectionReused": false,
                "connectionId": 0,
                "encodedDataLength": rec.body.len(),
                "securityState": if rec.url.starts_with("https") { "secure" } else { "insecure" },
                "protocol": "h2",
            },
        }),
    ));
    out.push(event(
        "Network.loadingFinished",
        session,
        json!({
            "requestId": request_id,
            "timestamp": now,
            "encodedDataLength": rec.body.len(),
        }),
    ));
    out
}

/// A jar entry in CDP's `Network.Cookie` shape. `expires` is -1 for a session
/// cookie (CDP's convention, not `null`), and `size` is what Chrome reports:
/// the name and value lengths added together.
fn cdp_cookie(c: nokk::CookieRecord) -> Value {
    let domain = c.domain.clone().unwrap_or_default();
    let path = c.path.clone().unwrap_or_else(|| "/".to_string());
    let size = c.name.len() + c.value.len();
    let mut out = json!({
        "name": c.name,
        "value": c.value,
        "domain": domain,
        "path": path,
        "expires": c.expires.unwrap_or(-1.0),
        "size": size,
        "httpOnly": c.http_only,
        "secure": c.secure,
        "session": c.expires.is_none(),
    });
    if let Some(s) = c.same_site {
        // CDP capitalises them: Strict / Lax / None.
        let mut chars = s.chars();
        let cap = match chars.next() {
            Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
            None => s,
        };
        out["sameSite"] = json!(cap);
    }
    out
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

/// Methods that only *configure* something this engine does not model. A client
/// sends them for effect and ignores the reply, so an empty success is honest —
/// there is nothing to report. This list is the dividing line: anything that
/// would *return data* must either be implemented or say it is missing, because
/// an empty success there is indistinguishable from "nothing to report" and
/// leaves the caller waiting forever.
fn is_configuration_noop(method: &str) -> bool {
    matches!(
        method,
        "Browser.setDownloadBehavior"
            | "DOM.disable"
            | "Emulation.setDefaultBackgroundColorOverride"
            | "Emulation.setEmulatedMedia"
            | "Emulation.setFocusEmulationEnabled"
            | "Emulation.setPageScaleFactor"
            | "Emulation.setScriptExecutionDisabled"
            | "Emulation.setTouchEmulationEnabled"
            | "Fetch.disable"
            | "Log.clear"
            | "Log.disable"
            | "Network.disable"
            | "Network.setCacheDisabled"
            | "Network.setExtraHTTPHeaders"
            | "Page.disable"
            | "Page.setBypassCSP"
            | "Page.setInterceptFileChooserDialog"
            | "Page.stopLoading"
            | "Performance.disable"
            | "Runtime.discardConsoleEntries"
            | "Runtime.disable"
            | "Target.detachFromTarget"
            | "Target.setDiscoverTargets"
    )
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
            registry: TargetRegistry::default(),
            port: 0,
            browser_sessions: Vec::new(),
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
        assert_eq!(
            super::parse_proxy_server("host:3128").unwrap().scheme,
            ProxyScheme::Http
        );
        assert_eq!(
            super::parse_proxy_server("socks5://h:1080").unwrap().scheme,
            ProxyScheme::Socks5
        );
        assert!(super::parse_proxy_server("host:3128")
            .unwrap()
            .username
            .is_none());
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
    async fn create_target_emits_lifecycle_events_before_the_reply() {
        // Real Chrome fires `targetCreated`/`attachedToTarget` before the
        // `createTarget` result. Playwright's `doCreateNewPage` reads
        // `_crPages.get(targetId)` the instant the reply lands, so the attach
        // event must have populated that map first — otherwise `newPage()` throws
        // "reading '_page'". Lock the ordering in.
        let _s = SERIAL.lock().await;
        let mut conn = test_conn();
        conn.auto_attach = true;
        let out = create_target(&mut conn, 7).await;
        let idx = |m: &str| {
            out.iter()
                .position(|v| v.get("method").and_then(|x| x.as_str()) == Some(m))
        };
        let reply = out
            .iter()
            .position(|v| v.get("id").and_then(|x| x.as_i64()) == Some(7))
            .expect("createTarget reply");
        let created = idx("Target.targetCreated").expect("targetCreated event");
        let attached = idx("Target.attachedToTarget").expect("attachedToTarget event");
        assert!(created < reply, "targetCreated must precede the reply");
        assert!(attached < reply, "attachedToTarget must precede the reply");
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
            .dispatch(
                &cmd(2, "Target.getTargets", json!({})),
                &sink(),
                &reg_sink(),
            )
            .await;
        let infos = response(&out, 2)["result"]["targetInfos"]
            .as_array()
            .expect("targetInfos array");
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0]["type"], json!("page"));
    }

    /// A socket opened from `Runtime.evaluate` must actually be acted on.
    ///
    /// `Runtime.evaluate` answers without driving the event loop, so the `open`
    /// operation the page queued only moves when something pumps — and the pump
    /// used to run solely for pages that *already* held a socket, which no page
    /// could reach. The result was a `WebSocket` stuck in CONNECTING forever, and
    /// no unit test below this level could see it.
    #[tokio::test]
    async fn a_socket_opened_via_cdp_evaluate_gets_pumped() {
        let _s = SERIAL.lock().await;
        let mut conn = test_conn();
        create_target(&mut conn, 1).await;
        let session = conn.targets[0].session_id.clone();
        conn.dispatch(
            &json!({ "id": 2, "sessionId": session, "method": "Runtime.evaluate", "params": {
                "expression": "globalThis.__w = new WebSocket('ws://127.0.0.1:1/');"
            }}),
            &sink(),
            &reg_sink(),
        )
        .await;

        // This engine has no real network, so the connection fails — the point is
        // that it *resolves at all* rather than sitting in the queue.
        let ctx = conn.targets[0].ctx.clone();
        let mut state = String::new();
        for _ in 0..40 {
            conn.pump_live_pages().await;
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            if let Ok(v) = ctx
                .evaluate("String(globalThis.__w && __w.readyState)")
                .await
            {
                state = v.as_str().unwrap_or_default().to_string();
                if state == "3" {
                    break;
                }
            }
        }
        assert_eq!(
            state, "3",
            "the queued socket was drained and settled (CLOSED), not left CONNECTING"
        );
    }
}
