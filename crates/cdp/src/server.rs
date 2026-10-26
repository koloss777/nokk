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

/// How long an `awaitPromise` evaluate will drive the page waiting for its
/// promise. A promise that never settles is the caller's bug, but hanging a
/// worker on it forever is ours; Puppeteer's own protocol timeout is longer, so
/// the client sees a result rather than a dropped command.
const AWAIT_PROMISE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Longest nap between checks while waiting for that promise — short enough that
/// one settled by the network is noticed promptly.
const AWAIT_PROMISE_POLL: std::time::Duration = std::time::Duration::from_millis(25);

/// CDP server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    /// Solve a challenge transparently on every `Page.navigate` that lands on
    /// one, with this much time; `None` leaves navigation as it is (a context
    /// created with `autoSolve: true` still solves).
    pub auto_solve: Option<std::time::Duration>,
    /// Required from every client when set: `?token=` on the URL or an
    /// `Authorization: Bearer` header. Whoever reaches the port drives the browser,
    /// so a server bound beyond loopback should have one.
    pub token: Option<String>,
}

/// Whether the request carries the configured token. Constant time over the token.
fn authorized(head: &str, path: &str, token: Option<&str>) -> bool {
    let Some(want) = token else { return true };
    let eq = |got: &str| {
        got.len() == want.len()
            && got.bytes().zip(want.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    };
    let from_query = path
        .split_once('?')
        .map(|(_, q)| q.split('&').filter_map(|kv| kv.strip_prefix("token=")).any(eq))
        .unwrap_or(false);
    let from_header = header(head, "authorization")
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .map(|t| eq(t.trim()))
        .unwrap_or(false);
    from_query || from_header
}

/// How long an automatic solve may take when the caller named no budget.
const AUTO_SOLVE_DEFAULT: std::time::Duration = std::time::Duration::from_secs(30);

/// Serve the CDP protocol until the listener errors. `engine` must be built with
/// real networking for navigation to work.
pub async fn serve(engine: Engine, config: ServerConfig) -> std::io::Result<()> {
    let listener = TcpListener::bind(config.addr).await?;
    let port = config.addr.port();
    let auto_solve = config.auto_solve;
    let token: Option<std::sync::Arc<str>> = config.token.as_deref().map(std::sync::Arc::from);
    let registry = TargetRegistry::default();
    tracing::info!(%config.addr, "CDP server listening — ws://{}/devtools/browser/nokk", config.addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        let engine = engine.clone();
        let registry = registry.clone();
        let token = token.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, engine, port, registry, auto_solve, token.as_deref()).await {
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
    auto_solve: Option<std::time::Duration>,
    token: Option<&str>,
) -> std::io::Result<()> {
    let head = read_head(&mut stream).await?;
    let request_line = head.lines().next().unwrap_or("");
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    if !authorized(&head, path, token) {
        let body = r#"{"error":"a token is required: ?token=... or Authorization: Bearer ..."}"#;
        let resp = format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    let is_ws = header(&head, "upgrade")
        .map(|u| u.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if !is_ws {
        return serve_http(&mut stream, path, port, &registry, token).await;
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
    run_session(ws, engine, port, registry, auto_solve).await;
    Ok(())
}

async fn serve_http(
    stream: &mut TcpStream,
    path: &str,
    port: u16,
    registry: &TargetRegistry,
    token: Option<&str>,
) -> std::io::Result<()> {
    let ws_url = format!("ws://127.0.0.1:{port}/devtools/browser/nokk");
    // The addresses handed out carry the token, so a client that found the server
    // through discovery can connect.
    let ws_url = match token {
        Some(t) => format!("{ws_url}?token={t}"),
        None => ws_url,
    };
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
        p if p.starts_with("/json/list") || p == "/json" || p.starts_with("/json?") || p == "/json/" => {
            let mut list = json!(registry.list());
            if let Some(entries) = list.as_array_mut() {
                for e in entries {
                    e["webSocketDebuggerUrl"] = json!(ws_url);
                }
            }
            list
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
    /// Worlds a child frame can have, by name; the position numbers the
    /// world's context in every frame. `true`: a new frame gets it by itself,
    /// as Chrome does for `addScriptToEvaluateOnNewDocument`'s `worldName`
    /// (Playwright's utility world); `false`: only on `createIsolatedWorld`.
    frame_worlds: Vec<(String, bool)>,
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
    /// Whether a pump spawned by the tick is still running. A turn of the loop can
    /// now wait out a timer, so it may outlive the tick that started it; without
    /// this every tick would pile another loop onto the same page.
    pumping: Arc<AtomicBool>,
    /// The loader id of the navigation in flight. A client ties the document
    /// request to the navigation by *this* id, not by the frame's — Playwright's
    /// `page.goto()` waits for a response whose `loaderId` matches the one
    /// `Page.navigate` reported, and answers `None` when nothing ever does.
    loader_id: Arc<std::sync::Mutex<String>>,
    /// Requests held for the driver (`Fetch.requestPaused`), by interception id.
    fetch_held: Arc<std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<nokk::Decision>>>>,
    /// Requests announced while held: engine request id -> the id the driver saw.
    net_ids: Arc<std::sync::Mutex<HashMap<String, String>>>,
    /// Frames already announced to the client, so each is reported once. Frames
    /// come into being asynchronously (a page inserts an `<iframe>`, the engine
    /// builds it), so the tick compares this against the live set rather than
    /// waiting for a command to notice.
    known_frames: std::collections::HashSet<u32>,
    /// Set while a `Page.navigate` is in flight: it announces its own document.
    navigating: Arc<AtomicBool>,
    /// The engine's document count (`document_seq`) as last announced. When the
    /// page moves on by itself — a form it submitted, a challenge that cleared,
    /// a script that set `location` — the tick sees the count change and tells
    /// the client, as Chrome would. A client never told keeps the old document
    /// in mind: Playwright then holds the new one's request as "pending" and
    /// answers `page.title()` with "Loading <url>", `page.url()` with the old one.
    announced_seq: Arc<std::sync::atomic::AtomicU64>,
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
    /// Server-wide automatic solving (`--auto-solve`), with its budget.
    auto_solve: Option<std::time::Duration>,
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
    /// `autoSolve` (non-standard param): solve challenges on navigation for
    /// pages of this context, regardless of the server-wide setting.
    auto_solve: Option<bool>,
    /// Cookies set on the context before it had a page (`Storage.setCookies`,
    /// Playwright's `addCookies`), stored when its first page is created.
    pending_cookies: Vec<(String, String)>,
}

/// A CDP cookie param (`Network.CookieParam`) as a `Set-Cookie` line and the URL
/// it is set from. Without `url`, the URL is built from `domain` and `path`.
fn cookie_param(c: &Value) -> Option<(String, String)> {
    let name = c.get("name")?.as_str()?;
    let value = c.get("value").and_then(|v| v.as_str()).unwrap_or("");
    let domain = c.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let path = c.get("path").and_then(|v| v.as_str()).unwrap_or("/");
    let secure = c.get("secure").and_then(|v| v.as_bool()).unwrap_or(false);
    let url = match c.get("url").and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None if !domain.is_empty() => format!(
            "{}://{}{}",
            if secure { "https" } else { "http" },
            domain.trim_start_matches('.'),
            path
        ),
        None => return None,
    };
    let mut line = format!("{name}={value}; Path={path}");
    if domain.starts_with('.') {
        line.push_str(&format!("; Domain={domain}"));
    }
    if secure {
        line.push_str("; Secure");
    }
    if c.get("httpOnly").and_then(|v| v.as_bool()).unwrap_or(false) {
        line.push_str("; HttpOnly");
    }
    if let Some(ss) = c.get("sameSite").and_then(|v| v.as_str()) {
        line.push_str(&format!("; SameSite={ss}"));
    }
    if let Some(exp) = c.get("expires").and_then(|v| v.as_f64()).filter(|e| *e > 0.0) {
        line.push_str(&format!("; Max-Age={}", (exp - now_secs()).max(0.0) as i64));
    }
    Some((line, url))
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
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
    let (host, port) = hostport.trim_end_matches('/').rsplit_once(':')?;
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
/// The frame it lives in comes along: a frame's handles and nodes are marked.
fn node_ref(params: &Value) -> (Option<u32>, String) {
    if let Some(oid) = params.get("objectId").and_then(|v| v.as_str()) {
        let (f, raw) = split_oid(oid);
        (f, format!("__pt_objGet({})", js_str(raw)))
    } else if let Some(bid) = params
        .get("backendNodeId")
        .or_else(|| params.get("nodeId"))
        .and_then(|v| v.as_i64())
    {
        let (f, bid) = split_node_id(bid);
        (f, format!("__pt_nodeById({bid})"))
    } else {
        (None, "null".to_string())
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
    auto_solve: Option<std::time::Duration>,
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
        auto_solve,
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
            _ = socket_pump.tick() => { conn.pump_live_pages(&tx).await; }
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
    async fn pump_live_pages(&mut self, tx: &UnboundedSender<Message>) {
        for t in &mut self.targets {
            // A document the page moved to by itself: announce it before its frames,
            // and before anything below that may wait on a lock the page holds.
            if !t.navigating.load(Ordering::Acquire) {
                let seq = t.ctx.document_seq();
                if seq != t.announced_seq.load(Ordering::Acquire) {
                    tracing::debug!(seq, url = %t.ctx.document_url(), "announcing a document the page moved to");
                    for m in announce_document(t) {
                        let _ = tx.send(Message::Text(m.to_string()));
                    }
                    t.announced_seq.store(seq, Ordering::Release);
                } else if t.url != "about:blank" || seq > 1 {
                    // `Page.navigate` keeps what was asked for; the frame tree
                    // and target info should show where the page landed.
                    let landed = t.ctx.document_url();
                    if !landed.is_empty() && t.url != landed {
                        t.url = landed;
                    }
                }
            }

            // A page whose timer has come due is doing something, even with no
            // socket and no frame: delays are real now, so an interval only ticks
            // while someone drives the loop. Asking the context costs an atomic
            // read of a deadline it already knows, so an idle page still costs
            // nothing, and a page with a slow timer is woken when it is due rather
            // than twenty times a second.
            let wants_pump = t.ran_js.swap(false, Ordering::Relaxed)
                || t.ctx.has_work_left()
                || t.ctx.timer_due()
                || t.ctx.has_frames()
                || t.ctx.has_open_sockets().await;
            if wants_pump && !t.pumping.swap(true, Ordering::Relaxed) {
                let (ctx, pumping) = (t.ctx.clone(), t.pumping.clone());
                tokio::spawn(async move {
                    let _ = ctx.run_event_loop().await;
                    pumping.store(false, Ordering::Relaxed);
                });
            }

            // Announce frames as they appear and disappear. Without this a client
            // never learns a page has any: `page.frames()` shows one, and there is
            // no execution context to evaluate inside.
            // Not while a navigation's own events are still to go out: its
            // frameNavigated and executionContextsCleared would drop a frame
            // announced first (Playwright then calls it detached).
            if t.navigating.load(Ordering::Acquire) {
                continue;
            }
            let live = t.ctx.frame_list();
            let session = Some(t.session_id.clone());
            for f in &live {
                if !t.known_frames.insert(f.id) {
                    continue;
                }
                let fid = child_frame_id(&t.target_id, f.id);
                for m in [
                    event(
                        "Page.frameAttached",
                        &session,
                        json!({ "frameId": fid, "parentFrameId": t.target_id,
                                "stack": { "callFrames": [] } }),
                    ),
                    event(
                        "Page.frameNavigated",
                        &session,
                        json!({ "type": "Navigation", "frame": {
                            "id": fid, "parentId": t.target_id,
                            "loaderId": format!("LF{}", f.id), "url": f.url,
                            "domainAndRegistry": "", "securityOrigin": f.origin,
                            "mimeType": "text/html",
                        }}),
                    ),
                    event(
                        "Runtime.executionContextCreated",
                        &session,
                        json!({ "context": {
                            "id": frame_ctx_id(f.id), "origin": f.origin, "name": "",
                            "uniqueId": format!("{}.1", frame_ctx_id(f.id)),
                            // The frame's main world: `isDefault` is what Playwright and
                            // Puppeteer wait for before `frame.evaluate`, as Chrome sends it.
                            "auxData": { "isDefault": true, "type": "default", "frameId": fid },
                        }}),
                    ),
                ] {
                    let _ = tx.send(Message::Text(m.to_string()));
                }
                for (k, (name, _)) in t.frame_worlds.iter().enumerate().filter(|(_, (_, auto))| *auto) {
                    let m = frame_world_created(&session, f.id, k, name, &f.origin, &fid);
                    let _ = tx.send(Message::Text(m.to_string()));
                }
            }
            let gone: Vec<u32> = t
                .known_frames
                .iter()
                .copied()
                .filter(|id| !live.iter().any(|f| f.id == *id))
                .collect();
            for id in gone {
                t.known_frames.remove(&id);
                let fid = child_frame_id(&t.target_id, id);
                for k in 0..t.frame_worlds.len() {
                    let m = event(
                        "Runtime.executionContextDestroyed",
                        &session,
                        json!({ "executionContextId": frame_world_ctx_id(id, k) }),
                    );
                    let _ = tx.send(Message::Text(m.to_string()));
                }
                for m in [
                    event(
                        "Runtime.executionContextDestroyed",
                        &session,
                        json!({ "executionContextId": frame_ctx_id(id) }),
                    ),
                    event(
                        "Page.frameDetached",
                        &session,
                        json!({ "frameId": fid, "reason": "remove" }),
                    ),
                ] {
                    let _ = tx.send(Message::Text(m.to_string()));
                }
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
                    frame_worlds: Vec::new(),
                    init_scripts: Vec::new(),
                    browser_context_id,
                    ran_js: Arc::new(AtomicBool::new(false)),
                    pumping: Arc::new(AtomicBool::new(false)),
                    loader_id: Arc::new(std::sync::Mutex::new(String::new())),
                    fetch_held: Arc::default(),
                    net_ids: Arc::default(),
                    extra_sessions: Vec::new(),
                    known_frames: std::collections::HashSet::new(),
                    navigating: Arc::new(AtomicBool::new(false)),
                    announced_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                };
                t.announced_seq.store(t.ctx.document_seq(), Ordering::Relaxed);
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
            // Playwright's `addCookies`: at browser level, for a browser context that
            // may not have a page yet. Its pages share one jar, so one page is enough;
            // with none, the cookies wait for the first.
            "Storage.setCookies" if browser_level => {
                let want = params.get("browserContextId").and_then(|v| v.as_str()).map(String::from);
                let cookies: Vec<(String, String)> = params
                    .get("cookies")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(cookie_param).collect())
                    .unwrap_or_default();
                match self.targets.iter().find(|t| t.browser_context_id == want) {
                    Some(t) => {
                        for (line, url) in &cookies {
                            t.ctx.set_cookie(line, url);
                        }
                    }
                    None => {
                        let key = want.clone().unwrap_or_default();
                        self.browser_contexts.entry(key).or_default().pending_cookies.extend(cookies);
                    }
                }
                vec![ok(id, &session, json!({}))]
            }
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
            // The window a page lives in. Playwright asks for it on every page of
            // a browser it takes for headful; the bounds are the ones the page
            // itself reports (`screenX`/`outerWidth`…), so client and site agree.
            "Browser.getWindowForTarget" => {
                let by_id = params.get("targetId").and_then(|v| v.as_str());
                let t = self.targets.iter().find(|t| match (by_id, session.as_deref()) {
                    (Some(tid), _) => t.target_id == tid,
                    (None, Some(s)) => t.session_id == s || t.extra_sessions.iter().any(|e| e == s),
                    (None, None) => false,
                });
                let Some(t) = t else {
                    return vec![err(id, &session, -32000, "No target with given id found")];
                };
                let (ctx, session, tx) = (t.ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let dims = ctx
                        .evaluate("JSON.stringify([screenX, screenY, outerWidth, outerHeight])")
                        .await
                        .ok()
                        .and_then(|v| v.as_str().and_then(|s| serde_json::from_str::<Vec<i64>>(s).ok()))
                        .filter(|d| d.len() == 4)
                        .unwrap_or_else(|| vec![0, 0, 1280, 720]);
                    let m = ok(id, &session, json!({
                        "windowId": 1,
                        "bounds": { "left": dims[0], "top": dims[1], "width": dims[2],
                                    "height": dims[3], "windowState": "normal" },
                    }));
                    let _ = tx.send(Message::Text(m.to_string()));
                });
                vec![]
            }
            "Browser.setWindowBounds" => vec![ok(id, &session, json!({}))],
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
                let auto_solve = params.get("autoSolve").and_then(|v| v.as_bool());
                let bcid = next_id("BC");
                self.browser_contexts.insert(
                    bcid.clone(),
                    BrowserContextCfg {
                        proxy,
                        session: session_name,
                        auto_solve,
                        pending_cookies: Vec::new(),
                    },
                );
                vec![ok(id, &session, json!({ "browserContextId": bcid }))]
            }
            "Target.disposeBrowserContext" => self.dispose_browser_context(id, &params, &session),
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
                let pending_cookies = browser_context_id
                    .as_deref()
                    .or(Some(""))
                    .and_then(|bc| self.browser_contexts.get_mut(bc))
                    .map(|c| std::mem::take(&mut c.pending_cookies))
                    .unwrap_or_default();
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
                    if let Ok(ctx) = &result {
                        for (line, url) in &pending_cookies {
                            ctx.set_cookie(line, url);
                        }
                    }
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
                        // On the session that asked, not the root: in the flatten
                        // model the attach event belongs to the parent session, and
                        // a client that receives it on the root builds a *second*
                        // session object for the same id — after which replies land
                        // on the wrong one and its assertions fire. And ahead of the
                        // reply, as Chrome sends it: Puppeteer's `createCDPSession`
                        // looks the session up the moment the reply arrives.
                        event(
                            "Target.attachedToTarget",
                            &session,
                            json!({ "sessionId": sid, "targetInfo": info, "waitingForDebugger": false }),
                        ),
                        ok(id, &session, json!({ "sessionId": sid })),
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

    /// Drop a browser context: forget its config, close its pages, and evict the
    /// identity's pooled client. Without the eviction every disposed context
    /// would leave its wreq client (cookie jar, connection pool) in the engine
    /// for good. Named sessions keep theirs by design — the jar is shared for
    /// the engine's lifetime.
    fn dispose_browser_context(
        &mut self,
        id: i64,
        params: &Value,
        session: &Option<String>,
    ) -> Vec<Value> {
        let mut out = Vec::new();
        if let Some(bc) = params.get("browserContextId").and_then(|v| v.as_str()) {
            let named = self.browser_contexts.get(bc).and_then(|c| c.session.clone());
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
            if named.is_none() && !bc.is_empty() {
                self.engine.release_identity(bc);
            }
        }
        out.push(ok(id, session, json!({ "success": true })));
        out
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
            "Network.setCookies" | "Storage.setCookies" | "Network.setCookie" => {
                let list: Vec<Value> = match params.get("cookies").and_then(|v| v.as_array()) {
                    Some(a) => a.clone(),
                    None => vec![params.clone()],
                };
                let mut stored = 0;
                for (line, url) in list.iter().filter_map(cookie_param) {
                    self.targets[idx].ctx.set_cookie(&line, &url);
                    stored += 1;
                }
                if method == "Network.setCookie" {
                    vec![ok(id, session, json!({ "success": stored > 0 }))]
                } else {
                    vec![ok(id, session, json!({}))]
                }
            }
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
                let (frame, sess, out, loader, ids) = (
                    self.targets[idx].target_id.clone(),
                    session.clone(),
                    tx.clone(),
                    self.targets[idx].loader_id.clone(),
                    self.targets[idx].net_ids.clone(),
                );
                tokio::spawn(async move {
                    // Loaders whose document request has gone out. A page that
                    // navigates itself before its first load finishes (AWS WAF's
                    // challenge reloads at once) sends a second document under the
                    // same loader; with the loader's id it overwrote the first, and
                    // its in-flight state reached `page.goto` as `net::ERR_FAILED`.
                    let mut loaders_used: std::collections::HashSet<String> = std::collections::HashSet::new();
                    while let Some(rec) = rx.recv().await {
                        let loader_id = loader.lock().map(|l| l.clone()).unwrap_or_default();
                        let mut held_id = if rec.announced {
                            ids.lock().ok().and_then(|mut m| m.remove(&rec.request_id))
                        } else {
                            None
                        };
                        if rec.frame.is_none() && rec.resource_type == "document" && held_id.is_none()
                            && !loaders_used.insert(loader_id.clone())
                        {
                            held_id = Some(rec.request_id.clone());
                        }
                        // A frame's requests belong to that frame and its own document.
                        let (fid, lid) = match rec.frame {
                            Some(f) => (child_frame_id(&frame, f), format!("LF{f}")),
                            None => (frame.clone(), loader_id),
                        };
                        for m in network_events(&rec, &fid, &lid, held_id.as_deref(), &sess) {
                            if out.send(Message::Text(m.to_string())).is_err() {
                                return;
                            }
                        }
                    }
                });
                vec![ok(id, session, json!({}))]
            }
            // Request interception (Playwright `page.route`, Puppeteer
            // `setRequestInterception`): each request is announced, then held
            // until the driver continues, fails or fulfills it.
            "Fetch.enable" => {
                let patterns = FetchPatterns::from_params(params);
                let mut rx = self.targets[idx].ctx.intercept_requests();
                let page = self.targets[idx].ctx.clone();
                let (frame, sess, out, loader, held, ids) = (
                    self.targets[idx].target_id.clone(),
                    session.clone(),
                    tx.clone(),
                    self.targets[idx].loader_id.clone(),
                    self.targets[idx].fetch_held.clone(),
                    self.targets[idx].net_ids.clone(),
                );
                tokio::spawn(async move {
                    // A navigation's document request carries its loader's id, once.
                    let mut loader_taken = String::new();
                    while let Some(p) = rx.recv().await {
                        // Only a request one of the patterns matches is paused; the
                        // rest go out as they are, announced as before.
                        let pause = patterns.pauses(&p.url, p.resource_type);
                        // A frame's request belongs to that frame and its own document.
                        let in_frame = p.context.and_then(|c| page.frame_of_context(c)).or_else(|| {
                            (p.resource_type == "Document").then(|| page.frame_for_document(&p.url)).flatten()
                        });
                        let (frame, loader_id) = match in_frame {
                            Some(f) => (child_frame_id(&frame, f), format!("LF{f}")),
                            None => (frame.clone(), loader.lock().map(|l| l.clone()).unwrap_or_default()),
                        };
                        let net_id = if in_frame.is_none() && p.resource_type == "Document" && !loader_id.is_empty() && loader_taken != loader_id {
                            loader_taken.clone_from(&loader_id);
                            loader_id.clone()
                        } else {
                            p.id.clone()
                        };
                        if let Ok(mut m) = ids.lock() {
                            m.insert(p.id.clone(), net_id.clone());
                        }
                        let mut request = json!({
                            "url": p.url, "method": p.method, "headers": p.headers,
                            "initialPriority": "High", "referrerPolicy": "strict-origin-when-cross-origin",
                        });
                        if !p.body.is_empty() {
                            request["postData"] = json!(String::from_utf8_lossy(&p.body));
                            request["hasPostData"] = json!(true);
                        }
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs_f64())
                            .unwrap_or_default();
                        let job = next_id("interception-job-");
                        let sent = event(
                            "Network.requestWillBeSent",
                            &sess,
                            json!({
                                "requestId": net_id, "loaderId": loader_id, "documentURL": p.url,
                                "request": request, "timestamp": now, "wallTime": now,
                                "initiator": { "type": if p.resource_type == "Document" { "other" } else { "parser" } },
                                "type": p.resource_type, "frameId": frame, "hasUserGesture": false,
                            }),
                        );
                        let paused = event(
                            "Fetch.requestPaused",
                            &sess,
                            json!({
                                "requestId": job, "request": request, "frameId": frame,
                                "resourceType": p.resource_type, "networkId": net_id,
                            }),
                        );
                        if !pause {
                            let _ = p.reply.send(nokk::Decision::Continue { url: None, method: None, headers: None, body: None });
                            if out.send(Message::Text(sent.to_string())).is_err() {
                                return;
                            }
                            continue;
                        }
                        if let Ok(mut h) = held.lock() {
                            h.insert(job, p.reply);
                        }
                        if out.send(Message::Text(sent.to_string())).is_err()
                            || out.send(Message::Text(paused.to_string())).is_err()
                        {
                            return;
                        }
                    }
                });
                vec![ok(id, session, json!({}))]
            }
            "Fetch.disable" => {
                self.targets[idx].ctx.stop_intercepting();
                // Dropping the held answers lets those requests go out unchanged.
                if let Ok(mut h) = self.targets[idx].fetch_held.lock() {
                    h.clear();
                }
                vec![ok(id, session, json!({}))]
            }
            "Fetch.continueRequest" | "Fetch.continueWithAuth" | "Fetch.failRequest" | "Fetch.fulfillRequest" => {
                let job = params.get("requestId").and_then(|v| v.as_str()).unwrap_or_default();
                let Some(reply) = self.targets[idx].fetch_held.lock().ok().and_then(|mut h| h.remove(job)) else {
                    return vec![err(id, session, -32602, "Invalid InterceptionId.")];
                };
                let decision = fetch_decision(method, params);
                let _ = reply.send(decision);
                vec![ok(id, session, json!({}))]
            }
            "Page.enable"
            | "DOM.enable"
            | "Log.enable"
            | "Performance.enable"
            // Puppeteer 25 turns issue reporting on for every page it opens.
            | "Audits.enable"
            | "Audits.disable"
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
                    // "On new document" means before the document's own scripts,
                    // in the page and in every frame — Chrome applies these to the
                    // whole tree, and applying them afterwards defeats the purpose.
                    self.targets[idx].ctx.add_init_script(src.to_string());
                    self.targets[idx].ctx.add_frame_init_script(src.to_string());
                }
                if let Some(w) = params.get("worldName").and_then(|v| v.as_str()).filter(|w| !w.is_empty()) {
                    let worlds = &mut self.targets[idx].frame_worlds;
                    match worlds.iter_mut().find(|(n, _)| n == w) {
                        Some(e) => e.1 = true,
                        None => worlds.push((w.to_string(), true)),
                    }
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
                // A world inside a child frame: a context of its own, announced as
                // Chrome does. There are no separate isolated realms per frame
                // here, so it evaluates in the frame's main world.
                if let Some(fid) = params.get("frameId").and_then(|v| v.as_str()) {
                    if let Some(f) = self.targets[idx]
                        .ctx
                        .frame_list()
                        .into_iter()
                        .find(|f| child_frame_id(&self.targets[idx].target_id, f.id) == fid)
                    {
                        let worlds = &mut self.targets[idx].frame_worlds;
                        let k = match worlds.iter().position(|(n, _)| *n == world_name) {
                            Some(k) => k,
                            None => {
                                worlds.push((world_name.clone(), false));
                                worlds.len() - 1
                            }
                        };
                        return vec![
                            ok(id, session, json!({ "executionContextId": frame_world_ctx_id(f.id, k) })),
                            frame_world_created(session, f.id, k, &world_name, &f.origin, fid),
                        ];
                    }
                }
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
                let children: Vec<Value> = t
                    .ctx
                    .frame_list()
                    .into_iter()
                    .map(|f| {
                        json!({ "frame": {
                            "id": child_frame_id(&t.target_id, f.id),
                            "parentId": t.target_id,
                            "loaderId": format!("LF{}", f.id),
                            "url": f.url,
                            "domainAndRegistry": "",
                            "securityOrigin": f.origin,
                            "mimeType": "text/html",
                        }})
                    })
                    .collect();
                vec![ok(
                    id,
                    session,
                    json!({ "frameTree": {
                        "frame": { "id": t.target_id, "loaderId": "L1", "url": t.url,
                                   "domainAndRegistry": "", "securityOrigin": "://", "mimeType": "text/html" },
                        "childFrames": children
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
            // Non-standard, nokk's own: drive a challenge on demand, or ask
            // what gate the page shows. Both answer asynchronously, like
            // `Page.navigate`, since solving takes seconds.
            "Nokk.solveChallenge" => {
                let budget = params
                    .get("timeoutMs")
                    .and_then(|v| v.as_u64())
                    .map(std::time::Duration::from_millis)
                    .or(self.auto_solve)
                    .unwrap_or(AUTO_SOLVE_DEFAULT);
                let (ctx, session, tx) = (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                let announced = self.targets[idx].announced_seq.clone();
                tokio::spawn(async move {
                    let outcome = ctx.solve_challenge(budget).await;
                    // A challenge that cleared moved the page to a new document;
                    // let the tick announce it before the reply, so a client acting
                    // on the reply already sees that document.
                    for _ in 0..200 {
                        if !ctx.is_loading() && announced.load(Ordering::Acquire) == ctx.document_seq() {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                    }
                    let after = ctx.challenge_state().await;
                    let m = ok(id, &session, json!({
                        "status": outcome.status.as_str(),
                        "solved": outcome.status.is_success(),
                        "presses": outcome.presses,
                        "elapsedMs": outcome.elapsed_ms,
                        "remaining": after.kind.as_str(),
                        "title": after.title, "url": after.url,
                        "cleared": after.cleared, "token": after.token,
                    }));
                    let _ = tx.send(Message::Text(m.to_string()));
                });
                vec![]
            }
            // The page's frames with the execution context each evaluates in: for
            // `Runtime.evaluate { contextId }` into a frame (a widget's challenge frame)
            // without tracking context events.
            "Nokk.frames" => {
                let target_id = self.targets[idx].target_id.clone();
                let frames: Vec<Value> = self.targets[idx]
                    .ctx
                    .frame_list()
                    .iter()
                    .map(|f| json!({
                        "frameId": child_frame_id(&target_id, f.id), "url": f.url,
                        "origin": f.origin, "executionContextId": frame_ctx_id(f.id),
                    }))
                    .collect();
                vec![ok(id, &session, json!({ "frames": frames }))]
            }
            // Press an element the way a hand does (pointer trail, held press), in the
            // frame whose URL contains `frameUrl` or in the page: { pressed }.
            // Type into one key by key: { typed }.
            "Nokk.press" | "Nokk.type" => {
                let typing = method == "Nokk.type";
                let frame_url = params.get("frameUrl").and_then(|v| v.as_str()).map(str::to_string);
                let selector = params.get("selector").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let text = params.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let (ctx, session, tx) = (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                self.targets[idx].ran_js.store(true, Ordering::Relaxed);
                tokio::spawn(async move {
                    let r = if typing {
                        ctx.type_selector(frame_url.as_deref(), &selector, &text).await
                    } else {
                        ctx.press_selector(frame_url.as_deref(), &selector).await
                    };
                    let m = match r {
                        Ok(done) => ok(id, &session, if typing { json!({ "typed": done }) } else { json!({ "pressed": done }) }),
                        Err(e) => err(id, &session, -32000, &e.to_string()),
                    };
                    let _ = tx.send(Message::Text(m.to_string()));
                });
                vec![]
            }
            "Nokk.challengeState" => {
                let (ctx, session, tx) = (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let st = ctx.challenge_state().await;
                    let m = ok(id, &session, json!({
                        "kind": st.kind.as_str(), "title": st.title, "url": st.url,
                        "cleared": st.cleared, "token": st.token,
                        "solvable": matches!(st.kind, nokk::ChallengeKind::CloudflareInterstitial | nokk::ChallengeKind::TurnstileWidget | nokk::ChallengeKind::AwsWaf),
                    }));
                    let _ = tx.send(Message::Text(m.to_string()));
                });
                vec![]
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
                let (navigating, announced) = (
                    self.targets[idx].navigating.clone(),
                    self.targets[idx].announced_seq.clone(),
                );
                navigating.store(true, Ordering::Release);
                // Solve on arrival: server-wide (`--auto-solve`) or per browser
                // context (`autoSolve`), the context's word winning.
                let per_ctx = self.targets[idx]
                    .browser_context_id
                    .as_deref()
                    .and_then(|bc| self.browser_contexts.get(bc))
                    .and_then(|c| c.auto_solve);
                let solve_budget = match per_ctx {
                    Some(true) => Some(self.auto_solve.unwrap_or(AUTO_SOLVE_DEFAULT)),
                    Some(false) => None,
                    None => self.auto_solve,
                };
                tokio::spawn(async move {
                    // Drive the real navigation, then Puppeteer's init scripts.
                    let nav = ctx.navigate(&url).await;
                    let nav_error = nav.as_ref().err().map(|e| e.to_string());
                    if let Some(e) = &nav_error {
                        tracing::debug!(error = %e, "Page.navigate error");
                    }
                    // A gate on the page: solve it now if asked to, and in any
                    // case tell the client what stands in the way — silently
                    // handing over a "Just a moment…" page would look like an
                    // ordinary load.
                    let mut challenge_event = None;
                    if nav_error.is_none() {
                        let state = ctx.challenge_state().await;
                        if state.kind != nokk::ChallengeKind::None {
                            let outcome = match solve_budget {
                                Some(budget) => Some(ctx.solve_challenge(budget).await),
                                None => None,
                            };
                            let after = ctx.challenge_state().await;
                            let solved = outcome.as_ref().map(|o| o.status.is_success()).unwrap_or(false);
                            challenge_event = Some(json!({
                                "kind": state.kind.as_str(),
                                "title": after.title, "url": after.url,
                                "solved": solved,
                                "remaining": after.kind.as_str(),
                                "attempted": outcome.is_some(),
                                "status": outcome.as_ref().map(|o| o.status.as_str()),
                                "presses": outcome.as_ref().map(|o| o.presses),
                                "elapsedMs": outcome.as_ref().map(|o| o.elapsed_ms),
                            }));
                        }
                    }
                    // The init scripts already ran inside the navigation, ahead of
                    // the document's own; running them again here would double every
                    // side effect a client's hook has.
                    let _ = &scripts;
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
                    // Where the page landed, after redirects and a challenge that
                    // moved on — what Chrome reports, not what was asked for.
                    let landed = if nav_error.is_none() { ctx.document_url() } else { url.clone() };
                    let frame = json!({
                        "id": target_id, "loaderId": loader, "url": landed,
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
                    if let Some(c) = challenge_event {
                        out.push(ev("Nokk.challenge", c));
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
                    announced.store(ctx.document_seq(), Ordering::Release);
                    navigating.store(false, Ordering::Release);
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
                // `contextId` picks the realm: a frame's own context when the
                // client is talking to a frame (that is how `page.frames()[1]
                // .evaluate(…)` reaches the right document), the page otherwise.
                let frame = params
                    .get("contextId")
                    .and_then(|v| v.as_i64())
                    .and_then(frame_of_ctx_id);
                let expr = dev_value(&expr);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                // Whatever this evaluate queued (a fetch, a socket) gets pumped by
                // the tick; the reply itself must not wait for the event loop.
                self.targets[idx].ran_js.store(true, Ordering::Relaxed);
                tokio::spawn(async move {
                    let ro = match frame {
                        Some(f) => frame_eval(&ctx, f, &expr, by_value, await_promise).await,
                        None => remote_eval(&ctx, &expr, by_value, await_promise).await,
                    };
                    let _ = tx.send(Message::Text(
                        ok(id, &session, ro).to_string(),
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
                // `this` is the handle's object (by objectId) or the global. A
                // handle from a frame carries the frame, and the call goes there.
                let (this_frame, this_js) = match params.get("objectId").and_then(|v| v.as_str()) {
                    Some(oid) => {
                        let (f, raw) = split_oid(oid);
                        (f, format!("__pt_objGet({})", js_str(raw)))
                    }
                    None => (None, "globalThis".to_string()),
                };
                // Resolve each argument: a handle (objectId) or a literal value.
                let args_js: Vec<String> = params
                    .get("arguments")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|o| match o.get("objectId").and_then(|v| v.as_str()) {
                                Some(oid) => format!("__pt_objGet({})", js_str(split_oid(oid).1)),
                                None => serde_json::to_string(
                                    &o.get("value").cloned().unwrap_or(Value::Null),
                                )
                                .unwrap_or_else(|_| "undefined".into()),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                // Compiled as DevTools code and called by the engine, so the
                // call leaves no frame (`__pt_devCall`).
                let expr = format!("__pt_devCall({}, {this_js}, [{}])", js_str(decl), args_js.join(","));
                // Same realm rule as `Runtime.evaluate`: a frame's context id sends
                // the call into that frame. This is how `frame.evaluate(…)` reaches
                // the right document — a client calls a function, it does not
                // evaluate a string.
                // Without a context id the call runs where its object lives, as
                // in Chrome: Playwright makes its helper in a frame by
                // `Runtime.evaluate` and then calls methods on that handle alone.
                let frame = params
                    .get("executionContextId")
                    .and_then(|v| v.as_i64())
                    .and_then(frame_of_ctx_id)
                    .or(this_frame);
                // A handle from a document the page has since left: Chrome's
                // answer, which clients take as "re-resolve", not a value.
                if frame.is_none() {
                    let mut ids = params.get("objectId").and_then(|v| v.as_str()).into_iter().chain(
                        params
                            .get("arguments")
                            .and_then(|v| v.as_array())
                            .into_iter()
                            .flatten()
                            .filter_map(|o| o.get("objectId").and_then(|v| v.as_str())),
                    );
                    let page = self.targets[idx].ctx.index();
                    if ids.any(|oid| object_is_stale(oid, page)) {
                        return vec![err(id, &session, -32000, "Could not find object with given id")];
                    }
                }
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                // Whatever this evaluate queued (a fetch, a socket) gets pumped by
                // the tick; the reply itself must not wait for the event loop.
                self.targets[idx].ran_js.store(true, Ordering::Relaxed);
                tokio::spawn(async move {
                    let ro = match frame {
                        Some(f) => frame_eval(&ctx, f, &expr, by_value, await_promise).await,
                        None => remote_eval(&ctx, &expr, by_value, await_promise).await,
                    };
                    let _ = tx.send(Message::Text(
                        ok(id, &session, ro).to_string(),
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
                            let (f, raw) = split_oid(&oid);
                            let js = format!("JSON.stringify(__pt_getProps({}))", js_str(raw));
                            let mut props = match run_in(&ctx, f, &js).await {
                                Ok(Value::String(s)) => {
                                    serde_json::from_str(&s).unwrap_or(json!([]))
                                }
                                _ => json!([]),
                            };
                            if let Some(f) = f {
                                tag_frame_refs(&mut props, f);
                            }
                            props
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
                        let (f, raw) = split_oid(&oid);
                        let _ = run_in(&ctx, f, &format!("__pt_release({})", js_str(raw))).await;
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
                let target_id = self.targets[idx].target_id.clone();
                tokio::spawn(async move {
                    let node = match oid {
                        Some(oid) => {
                            let (f, raw) = split_oid(&oid);
                            let js = format!(
                                "JSON.stringify(__pt_describe(__pt_objGet({})))",
                                js_str(raw)
                            );
                            let mut node = match run_in(&ctx, f, &js).await {
                                Ok(Value::String(s)) => {
                                    serde_json::from_str(&s).unwrap_or(Value::Null)
                                }
                                _ => Value::Null,
                            };
                            if let Some(f) = f {
                                tag_frame_refs(&mut node, f);
                            }
                            // An <iframe>'s own frame, by the id frames are
                            // announced under (`frame_locator` waits for it).
                            if let Some(m) = node.as_object_mut() {
                                if let Some(inner) = m.remove("ptFrame").and_then(|v| v.as_u64()) {
                                    m.insert("frameId".into(), json!(child_frame_id(&target_id, inner as u32)));
                                }
                            }
                            node
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
                            let (f, bid) = split_node_id(bid);
                            let js =
                                format!("JSON.stringify(__pt_wrap(__pt_nodeById({bid}), false))");
                            let mut obj = match run_in(&ctx, f, &js).await {
                                Ok(Value::String(s)) => serde_json::from_str(&s)
                                    .unwrap_or(json!({ "type": "undefined" })),
                                _ => json!({ "type": "undefined" }),
                            };
                            if let Some(f) = f {
                                tag_frame_refs(&mut obj, f);
                            }
                            obj
                        }
                        None => json!({ "type": "undefined" }),
                    };
                    let _ = tx.send(Message::Text(
                        ok(id, &session, json!({ "object": obj })).to_string(),
                    ));
                });
                vec![]
            }
            // The <iframe> element a frame lives in: Playwright checks a click
            // point in a frame against it.
            "DOM.getFrameOwner" => {
                let fid = params.get("frameId").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let t = &self.targets[idx];
                let Some(f) = t.ctx.frame_list().into_iter().find(|f| child_frame_id(&t.target_id, f.id) == fid) else {
                    return vec![err(id, session, -32000, "Frame with the given id was not found.")];
                };
                let (ctx, session, tx) = (t.ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let bid = run_in(&ctx, None, &format!("__pt_frameOwner({})", f.id))
                        .await
                        .ok()
                        .and_then(|v| v.as_i64().or_else(|| v.as_str()?.parse().ok()))
                        .unwrap_or(0);
                    let msg = if bid > 0 {
                        ok(id, &session, json!({ "backendNodeId": bid, "nodeId": 0 }))
                    } else {
                        err(id, &session, -32000, "Frame with the given id was not found.")
                    };
                    let _ = tx.send(Message::Text(msg.to_string()));
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
                let (frame, nref) = node_ref(params);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let js = format!("JSON.stringify(__pt_boxModel({nref}))");
                    let msg = match run_in(&ctx, frame, &js).await {
                        Ok(Value::String(ref s)) if s != "null" => {
                            match serde_json::from_str::<Value>(s) {
                                Ok(mut model) if !model.is_null() => {
                                    if let Some(f) = frame {
                                        let (dx, dy) = frame_offset(&ctx, f).await;
                                        shift_quads(&mut model, dx, dy);
                                    }
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
                let (frame, nref) = node_ref(params);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let js = format!("JSON.stringify(__pt_contentQuads({nref}))");
                    let mut quads = match run_in(&ctx, frame, &js).await {
                        Ok(Value::String(s)) => serde_json::from_str(&s).unwrap_or(json!([])),
                        _ => json!([]),
                    };
                    if let Some(f) = frame {
                        let (dx, dy) = frame_offset(&ctx, f).await;
                        shift_quads(&mut quads, dx, dy);
                    }
                    let _ = tx.send(Message::Text(
                        ok(id, &session, json!({ "quads": quads })).to_string(),
                    ));
                });
                vec![]
            }
            "DOM.focus" => {
                let (frame, nref) = node_ref(params);
                let (ctx, session, tx) =
                    (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let _ = run_in(&ctx, frame, &format!("__pt_focusNode({nref})")).await;
                    let _ = tx.send(Message::Text(ok(id, &session, json!({})).to_string()));
                });
                vec![]
            }
            // Clients scroll an element into view before they click it.
            "DOM.scrollIntoViewIfNeeded" => {
                let (frame, nref) = node_ref(params);
                let (ctx, session, tx) = (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let js = format!("(n => {{ if (n && n.scrollIntoViewIfNeeded) n.scrollIntoViewIfNeeded(true); return ''; }})({nref})");
                    let _ = run_in(&ctx, frame, &js).await;
                    let _ = tx.send(Message::Text(ok(id, &session, json!({})).to_string()));
                });
                vec![]
            }
            // The page's own window and scroll position: a client checks a point is
            // inside the window before it clicks there.
            "Page.getLayoutMetrics" => {
                let (ctx, session, tx) = (self.targets[idx].ctx.clone(), session.clone(), tx.clone());
                tokio::spawn(async move {
                    let js = "JSON.stringify([innerWidth, innerHeight, scrollX, scrollY, document.documentElement ? document.documentElement.scrollWidth : innerWidth, document.documentElement ? document.documentElement.scrollHeight : innerHeight])";
                    let m: Vec<f64> = ctx
                        .evaluate(js)
                        .await
                        .ok()
                        .and_then(|v| v.as_str().and_then(|t| serde_json::from_str(t).ok()))
                        .filter(|v: &Vec<f64>| v.len() == 6)
                        .unwrap_or_else(|| vec![1280.0, 720.0, 0.0, 0.0, 1280.0, 720.0]);
                    let (w, h, sx, sy, cw, ch) = (m[0], m[1], m[2], m[3], m[4], m[5]);
                    let vp = json!({ "pageX": sx, "pageY": sy, "clientWidth": w, "clientHeight": h });
                    let visual = json!({ "offsetX": 0, "offsetY": 0, "pageX": sx, "pageY": sy,
                        "clientWidth": w, "clientHeight": h, "scale": 1, "zoom": 1 });
                    let content = json!({ "x": 0, "y": 0, "width": cw.max(w), "height": ch.max(h) });
                    let m = ok(id, &session, json!({
                        "layoutViewport": vp, "visualViewport": visual, "contentSize": content,
                        "cssLayoutViewport": vp, "cssVisualViewport": visual, "cssContentSize": content,
                    }));
                    let _ = tx.send(Message::Text(m.to_string()));
                });
                vec![]
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
                    // The context routes the point into the frame that owns it.
                    let _ = ctx.dispatch_mouse(&mtype, x, y, &button, clicks).await;
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
                    let frame = focused_frame(&ctx).await;
                    let _ = run_in(&ctx, frame, &js).await;
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
                    let frame = focused_frame(&ctx).await;
                    let _ = run_in(&ctx, frame, &format!("__pt_insertText({})", js_str(&text))).await;
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

/// `Runtime.evaluate` against a frame's own document. Same wrapper as the page
/// path so the result shape matches; a frame that has gone away answers
/// `undefined` rather than failing the command, since frames die on their own.
async fn frame_eval(ctx: &BrowserContext, frame: u32, value: &str, by_value: bool, await_promise: bool) -> Value {
    let by = if by_value { "true" } else { "false" };
    if await_promise {
        // As for the page: the settled value lands in a hidden slot of the
        // frame's global while the loop (frames included) runs.
        let slot = format!("__pt_cdp{}", IDS.fetch_add(1, Ordering::Relaxed));
        let setup = |value: &str| {
            format!(
                "(() => {{ Object.defineProperty(globalThis, '{slot}', {{ value: {{ done: false, v: undefined }}, configurable: true, enumerable: false, writable: true }}); \
                   let p; try {{ p = Promise.resolve({value}); }} catch (e) {{ globalThis.{slot}.sync = true; p = Promise.reject(e); }} \
                   p.then(v => {{ globalThis.{slot}.v = v; globalThis.{slot}.done = true; }}, \
                          e => {{ globalThis.{slot}.v = e; globalThis.{slot}.rej = true; globalThis.{slot}.done = true; }}); }})()"
            )
        };
        if ctx.evaluate_in_frame(frame, &setup(value)).await.is_err() {
            return json!({ "result": { "type": "undefined" } });
        }
        let deadline = std::time::Instant::now() + AWAIT_PROMISE_TIMEOUT;
        loop {
            let settled = matches!(
                ctx.evaluate_in_frame(frame, &format!("String(globalThis.{slot}.done)")).await,
                Ok(Value::String(ref s)) if s == "true"
            );
            if settled || std::time::Instant::now() >= deadline {
                break;
            }
            let _ = ctx.run_event_loop_idle(AWAIT_PROMISE_POLL).await;
            let nap = ctx
                .next_timer_in()
                .unwrap_or(AWAIT_PROMISE_POLL)
                .clamp(std::time::Duration::from_millis(1), AWAIT_PROMISE_POLL);
            tokio::time::sleep(nap).await;
        }
        let read = format!(
            "(() => {{ const s = globalThis.{slot}; delete globalThis.{slot}; \
               return JSON.stringify(s && s.rej ? __pt_exc(s.v, !s.sync, {by}) : __pt_wrap(s && s.done ? s.v : undefined, {by})); }})()"
        );
        let mut v = eval_reply(ctx.evaluate_in_frame(frame, &read).await.ok());
        tag_frame_refs(&mut v, frame);
        return v;
    }
    let wrap = |value: &str| {
        format!(
            "(() => {{ try {{ return JSON.stringify(__pt_wrap({value}, {by})); }} \
               catch (e) {{ return JSON.stringify(__pt_exc(e, false, {by})); }} }})()"
        )
    };
    let mut v = eval_reply(ctx.evaluate_in_frame(frame, &wrap(value)).await.ok());
    tag_frame_refs(&mut v, frame);
    v
}

/// The body of a `Runtime.evaluate`/`callFunctionOn` reply from the JSON the
/// page-side wrapper produced: `{result}`, or for a throw or a rejection
/// `{result, exceptionDetails}` as Chrome sends it, which is how Puppeteer and
/// Playwright know to raise instead of handing back a value.
fn eval_reply(js: Option<Value>) -> Value {
    let v = match js {
        Some(Value::String(s)) => serde_json::from_str(&s).unwrap_or(json!({ "type": "undefined" })),
        _ => json!({ "type": "undefined" }),
    };
    let Some(exc) = v.get("__ptExc") else {
        return json!({ "result": v });
    };
    json!({
        "result": exc["result"],
        "exceptionDetails": {
            "exceptionId": IDS.fetch_add(1, Ordering::Relaxed),
            "text": exc["text"],
            "lineNumber": 0,
            "columnNumber": 0,
            "exception": exc["exception"],
        },
    })
}

/// The JS that evaluates a client's `Runtime.evaluate` source: a script of its
/// own, taking its completion value as CDP does, in global scope. Splicing the
/// source inline (`__pt_wrap((SRC),…)`) breaks on the statement forms
/// Puppeteer and Playwright send (an IIFE with a trailing `;`, a trailing
/// `//# sourceURL=` comment); passed as a string, it does not.
fn dev_value(expr: &str) -> String {
    format!("__pt_devEval({})", js_str(expr))
}

/// Evaluate `expr` and return a CDP `RemoteObject` — by value (JSON) or as an
/// `objectId` handle (via the JS `__pt_wrap` registry), matching `by_value`.
/// Drives the event loop when awaiting a Promise.
async fn remote_eval(
    ctx: &BrowserContext,
    value: &str,
    by_value: bool,
    await_promise: bool,
) -> Value {
    let by = if by_value { "true" } else { "false" };
    let js = if await_promise {
        // Resolve the (possibly-Promise) value via the event loop, then wrap it.
        // The await path spans several `evaluate` calls with event-loop turns in
        // between, during which *other* concurrently-dispatched commands run on
        // the same context. A shared global would be clobbered mid-flight (two
        // overlapping evaluates racing on it), so each call gets a unique slot.
        // A hidden name: `__pt*` globals are kept out of the page's view, and
        // the slot lives on the page's global while it waits.
        let slot = format!("__pt_cdp{}", IDS.fetch_add(1, Ordering::Relaxed));
        let setup = format!(
            "(() => {{ Object.defineProperty(globalThis, '{slot}', {{ value: {{ done: false, v: undefined }}, configurable: true, enumerable: false, writable: true }}); \
             let p; try {{ p = Promise.resolve({value}); }} catch (e) {{ globalThis.{slot}.sync = true; p = Promise.reject(e); }} \
             p.then(\
               v => {{ globalThis.{slot}.v = v; globalThis.{slot}.done = true; }}, \
               e => {{ globalThis.{slot}.v = e; globalThis.{slot}.rej = true; globalThis.{slot}.done = true; }}); }})()"
        );
        if ctx.evaluate(&setup).await.is_err() {
            return json!({ "result": { "type": "undefined" } });
        }
        // Drive the loop until the promise settles. One turn used to be enough
        // because timers collapsed their delays; now `await new Promise(r =>
        // setTimeout(r, 1000))` — which is what every `waitForTimeout` compiles
        // down to — really does take a second, and reading the slot after a single
        // turn would hand the caller back an unsettled promise.
        // A value that was not a promise is settled already: answer at once,
        // as Chrome does, before any of the page's tasks run (a timer the
        // expression set — a navigation, say — fires after the reply).
        let deadline = std::time::Instant::now() + AWAIT_PROMISE_TIMEOUT;
        loop {
            let settled = matches!(
                ctx.evaluate(&format!("String(globalThis.{slot}.done)")).await,
                Ok(Value::String(ref s)) if s == "true"
            );
            if settled || std::time::Instant::now() >= deadline {
                break;
            }
            let _ = ctx.run_event_loop_idle(AWAIT_PROMISE_POLL).await;
            // Nothing runnable this instant: sleep until the page's next timer is
            // due (capped, so a promise settled by I/O is not missed for long).
            let nap = ctx
                .next_timer_in()
                .unwrap_or(AWAIT_PROMISE_POLL)
                .clamp(std::time::Duration::from_millis(1), AWAIT_PROMISE_POLL);
            tokio::time::sleep(nap).await;
        }
        format!(
            "(() => {{ const s = globalThis.{slot}; delete globalThis.{slot}; \
               return JSON.stringify(s.rej ? __pt_exc(s.v, !s.sync, {by}) : __pt_wrap(s.done ? s.v : undefined, {by})); }})()"
        )
    } else {
        format!(
            "(() => {{ try {{ return JSON.stringify(__pt_wrap({value}, {by})); }} \
               catch (e) {{ return JSON.stringify(__pt_exc(e, false, {by})); }} }})()"
        )
    };
    eval_reply(ctx.evaluate(&js).await.ok())
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
    held_id: Option<&str>,
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
    let request_id = if let Some(h) = held_id {
        h.to_string()
    } else if kind == "Document" && !loader_id.is_empty() {
        loader_id.to_string()
    } else {
        rec.request_id.clone()
    };
    let mut out = Vec::new();
    // A held request was announced when it paused.
    if !rec.announced {
        out.push(event(
        "Network.requestWillBeSent",
        session,
        json!({
            "requestId": request_id,
            "loaderId": loader_id,
            "documentURL": rec.url,
            "request": {
                "url": rec.url, "method": rec.method, "headers": {},
                "initialPriority": "High", "referrerPolicy": "strict-origin-when-cross-origin",
                // What the page sent up. Absent when there is no body, exactly as
                // Chrome reports it — a GET has no `postData` field at all.
                "postData": String::from_utf8_lossy(&rec.request_body),
                "hasPostData": !rec.request_body.is_empty(),
            },
            "timestamp": now,
            "wallTime": now,
            "initiator": { "type": if kind == "Document" { "other" } else { "parser" } },
            "type": kind,
            "frameId": frame_id,
            "hasUserGesture": false,
        }),
        ));
    }
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

/// The driver's answer to a held request. Headers come as `[{name, value}]`,
/// bodies as base64.
fn fetch_decision(method: &str, params: &Value) -> nokk::Decision {
    use base64::Engine as _;
    let b64 = |k: &str| {
        params.get(k).and_then(|v| v.as_str()).map(|s| base64::engine::general_purpose::STANDARD.decode(s).unwrap_or_default())
    };
    let headers = |k: &str| {
        params.get(k).and_then(|v| v.as_array()).map(|a| {
            a.iter()
                .filter_map(|h| Some((h.get("name")?.as_str()?.to_string(), h.get("value")?.as_str()?.to_string())))
                .collect::<std::collections::BTreeMap<_, _>>()
        })
    };
    let text = |k: &str| params.get(k).and_then(|v| v.as_str()).map(str::to_string);
    match method {
        "Fetch.failRequest" => nokk::Decision::Fail,
        "Fetch.fulfillRequest" => nokk::Decision::Fulfill {
            status: params.get("responseCode").and_then(|v| v.as_u64()).unwrap_or(200) as u16,
            headers: headers("responseHeaders").unwrap_or_default(),
            body: b64("body").unwrap_or_default(),
        },
        "Fetch.continueRequest" => nokk::Decision::Continue {
            url: text("url"),
            method: text("method"),
            headers: headers("headers"),
            body: b64("postData"),
        },
        _ => nokk::Decision::Continue { url: None, method: None, headers: None, body: None },
    }
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

/// A child frame's CDP id. Derived from the page's own so it is stable and
/// obviously related, which is what a client shows in its frame tree.
fn child_frame_id(target_id: &str, frame_id: u32) -> String {
    format!("{target_id}-F{frame_id}")
}

/// Tell the client the page is on a new document it did not navigate to: the
/// same events `Page.navigate` sends after a load, with fresh context ids for
/// the main world and every isolated world, so handles into the old document
/// are dropped and evaluates reach the new one.
fn announce_document(t: &mut Target) -> Vec<Value> {
    let session = Some(t.session_id.clone());
    let url = t.ctx.document_url();
    // The loader id its document request went out under: a client pairs the
    // request with the commit by it (Playwright keeps a request it cannot pair
    // as a navigation still pending, and its evaluates wait on that forever).
    let loader = t
        .loader_id
        .lock()
        .map(|l| l.clone())
        .unwrap_or_default();
    t.url = url.clone();
    t.exec_ctx_id = IDS.fetch_add(1, Ordering::Relaxed) as i64;
    for w in t.iso_worlds.iter_mut() {
        w.1 = IDS.fetch_add(1, Ordering::Relaxed) as i64;
    }
    let target_id = t.target_id.clone();
    let ev = |name: &str, params: Value| event(name, &session, params);
    let lifecycle = |name: &str| {
        ev(
            "Page.lifecycleEvent",
            json!({ "frameId": target_id, "loaderId": loader, "name": name, "timestamp": 0.0 }),
        )
    };
    let mut out = vec![
        ev("Page.frameStartedLoading", json!({ "frameId": target_id })),
        ev(
            "Page.frameNavigated",
            json!({ "type": "Navigation", "frame": {
                "id": target_id, "loaderId": loader, "url": url,
                "domainAndRegistry": "", "securityOrigin": "://", "mimeType": "text/html"
            }}),
        ),
        ev("Runtime.executionContextsCleared", json!({})),
        ev(
            "Runtime.executionContextCreated",
            json!({ "context": {
                "id": t.exec_ctx_id, "origin": url, "name": "", "uniqueId": format!("{}.1", t.exec_ctx_id),
                "auxData": { "isDefault": true, "type": "default", "frameId": target_id }
            }}),
        ),
    ];
    for (name, nid) in &t.iso_worlds {
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
    out
}

/// Whether a remote object id (`obj-<context>.<n>`) belongs to a context other
/// than the page's current one — a document the page has left.
fn object_is_stale(oid: &str, page_ctx: usize) -> bool {
    oid.strip_prefix("obj-")
        .and_then(|r| r.split_once('.'))
        .and_then(|(c, _)| c.parse::<usize>().ok())
        .map(|c| c != page_ctx)
        .unwrap_or(false)
}

// A handle or a node from a frame names its frame: `f<frame>:obj-…` and
// backend node ids past `(frame + 1) * NODE_STRIDE`. Context indices alone are
// per thread, and a frame on another thread can share the page's.
const NODE_STRIDE: i64 = 1 << 32;

/// The frame a handle comes from, and the handle as its document knows it.
fn split_oid(oid: &str) -> (Option<u32>, &str) {
    oid.strip_prefix('f')
        .and_then(|r| r.split_once(':'))
        .and_then(|(f, raw)| Some((Some(f.parse().ok()?), raw)))
        .unwrap_or((None, oid))
}

fn split_node_id(bid: i64) -> (Option<u32>, i64) {
    if bid >= NODE_STRIDE {
        (Some((bid / NODE_STRIDE - 1) as u32), bid % NODE_STRIDE)
    } else {
        (None, bid)
    }
}

/// Mark every handle and node in a frame's answer with the frame.
fn tag_frame_refs(v: &mut Value, frame: u32) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                match (k.as_str(), &*x) {
                    ("objectId", Value::String(s)) => *x = Value::String(format!("f{frame}:{s}")),
                    ("backendNodeId", Value::Number(n)) => {
                        if let Some(n) = n.as_i64() {
                            *x = json!((frame as i64 + 1) * NODE_STRIDE + n);
                        }
                    }
                    _ => tag_frame_refs(x, frame),
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| tag_frame_refs(x, frame)),
        _ => {}
    }
}

/// The frame that has keyboard focus, `None` for the page: whichever document
/// took focus last. A page and its frames are separate contexts, each with
/// its own active element.
async fn focused_frame(ctx: &BrowserContext) -> Option<u32> {
    // The engine hands script results back as text.
    let stamp = |v: Result<Value, nokk::EngineError>| {
        v.ok().and_then(|v| v.as_f64().or_else(|| v.as_str()?.parse().ok())).unwrap_or(0.0)
    };
    let mut best = (stamp(ctx.evaluate("__pt_focusAt()").await), None);
    for f in ctx.frame_list() {
        let at = stamp(ctx.evaluate_in_frame(f.id, "__pt_focusAt()").await);
        if at > best.0 {
            best = (at, Some(f.id));
        }
    }
    best.1
}

/// Run engine JS in the page or in one of its frames.
async fn run_in(ctx: &BrowserContext, frame: Option<u32>, js: &str) -> Result<Value, nokk::EngineError> {
    match frame {
        Some(f) => ctx.evaluate_in_frame(f, js).await,
        None => ctx.evaluate(js).await,
    }
}

/// Where a frame's `<iframe>` sits in the page: its content's coordinates plus
/// this are the page's, which is what Chrome reports for a node in a frame.
async fn frame_offset(ctx: &BrowserContext, frame: u32) -> (f64, f64) {
    let r = ctx.evaluate(&format!("__pt_frameRectById({frame})")).await.ok();
    let v: Value = r
        .as_ref()
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Null);
    (v["x"].as_f64().unwrap_or(0.0), v["y"].as_f64().unwrap_or(0.0))
}

/// Shift every point of quads (flat `[x1, y1, x2, y2, …]` arrays) by `(dx, dy)`.
fn shift_quads(v: &mut Value, dx: f64, dy: f64) {
    match v {
        Value::Array(a) if a.iter().all(|x| x.is_number()) => {
            for (i, x) in a.iter_mut().enumerate() {
                let n = x.as_f64().unwrap_or(0.0) + if i % 2 == 0 { dx } else { dy };
                *x = json!(n);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| shift_quads(x, dx, dy)),
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if k != "width" && k != "height" {
                    shift_quads(x, dx, dy);
                }
            }
        }
        _ => {}
    }
}

/// The frame behind an execution context id, if it names one: its main
/// world or one of its isolated worlds.
fn frame_of_ctx_id(ctx_id: i64) -> Option<u32> {
    (ctx_id >= 1_000_000).then(|| ((ctx_id - 1_000_000) % FRAME_WORLD_STRIDE) as u32)
}

/// Frame ids stay below this; world `k` of a frame is its main-world id plus
/// `(k + 1)` strides.
const FRAME_WORLD_STRIDE: i64 = 100_000_000;

fn frame_world_ctx_id(frame_id: u32, k: usize) -> i64 {
    frame_ctx_id(frame_id) + (k as i64 + 1) * FRAME_WORLD_STRIDE
}

/// `Runtime.executionContextCreated` for world `k` of a frame.
fn frame_world_created(session: &Option<String>, frame_id: u32, k: usize, name: &str, origin: &str, fid: &str) -> Value {
    let cid = frame_world_ctx_id(frame_id, k);
    event(
        "Runtime.executionContextCreated",
        session,
        json!({ "context": {
            "id": cid, "origin": origin, "name": name, "uniqueId": format!("{cid}.1"),
            "auxData": { "isDefault": false, "type": "isolated", "frameId": fid },
        }}),
    )
}

/// The execution context id a frame's evaluates run in. Kept in a range of its
/// own so it cannot collide with the page's contexts or its isolated worlds.
fn frame_ctx_id(frame_id: u32) -> i64 {
    1_000_000 + frame_id as i64
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

/// `Fetch.enable`'s patterns: a request is paused when one of them matches its
/// URL (`*` any run, `?` one character, a backslash escapes) and resource type,
/// at the request stage. No patterns given: every request; an empty list:
/// none (both as Chrome 151 answers).
struct FetchPatterns(Option<Vec<(String, Option<String>)>>);

impl FetchPatterns {
    fn from_params(params: &Value) -> Self {
        let Some(list) = params.get("patterns").and_then(|v| v.as_array()) else {
            return FetchPatterns(None);
        };
        let mut out = Vec::new();
        for p in list {
            // Only the request stage is intercepted here; a response-stage
            // pattern pauses nothing before the request goes out.
            let stage = p.get("requestStage").and_then(|v| v.as_str()).unwrap_or("Request");
            if stage != "Request" {
                continue;
            }
            let url = p.get("urlPattern").and_then(|v| v.as_str()).unwrap_or("*").to_string();
            let kind = p.get("resourceType").and_then(|v| v.as_str()).map(str::to_string);
            out.push((url, kind));
        }
        FetchPatterns(Some(out))
    }

    fn pauses(&self, url: &str, resource_type: &str) -> bool {
        let Some(list) = &self.0 else { return true };
        list.iter().any(|(pat, kind)| kind.as_deref().is_none_or(|k| k == resource_type) && wildcard_match(pat, url))
    }
}

/// CDP's URL wildcard: `*` matches any run of characters, `?` one, and a
/// backslash makes the next character literal.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut i, mut j) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while j < t.len() {
        if i < p.len() && p[i] == '*' {
            star = Some(i);
            i += 1;
            mark = j;
            continue;
        }
        if i < p.len() {
            let (lit, step) = if p[i] == '\\' && i + 1 < p.len() { (Some(p[i + 1]), 2) } else if p[i] == '?' { (None, 1) } else { (Some(p[i]), 1) };
            if lit.is_none_or(|c| c == t[j]) {
                i += step;
                j += 1;
                continue;
            }
        }
        match star {
            Some(s) => {
                i = s + 1;
                mark += 1;
                j = mark;
            }
            None => return false,
        }
    }
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
}

#[cfg(test)]
mod tests {
    // Fetch.enable pauses what its patterns match: wildcards as CDP has them,
    // the resource type when given, request stage only, everything without
    // patterns (a page's subresources were all paused by a pattern naming the
    // document alone).
    #[test]
    fn fetch_patterns_pause_only_what_they_match() {
        assert!(wildcard_match("https://a.com/x", "https://a.com/x"));
        assert!(!wildcard_match("https://a.com/x", "https://a.com/x.js"));
        assert!(wildcard_match("*", "https://a.com/x"));
        assert!(wildcard_match("*.js", "https://a.com/app.js"));
        assert!(wildcard_match("https://*.com/?", "https://a.com/x"));
        assert!(!wildcard_match("https://*.com/?", "https://a.com/xy"));
        assert!(wildcard_match(r"https://a.com/\*", "https://a.com/*"));
        assert!(!wildcard_match(r"https://a.com/\*", "https://a.com/b"));
        assert!(wildcard_match("*widget*", "https://www.example.com/widget/api2/demo"));
        let p = FetchPatterns::from_params(&json!({ "patterns": [{ "urlPattern": "https://www.example.com/widget/api2/demo", "requestStage": "Request" }] }));
        assert!(p.pauses("https://www.example.com/widget/api2/demo", "Document"));
        assert!(!p.pauses("https://www.example.com/widget/api.js", "Script"));
        let p = FetchPatterns::from_params(&json!({ "patterns": [{ "urlPattern": "*", "resourceType": "Image" }, { "urlPattern": "*", "requestStage": "Response" }] }));
        assert!(p.pauses("https://a.com/i.png", "Image"));
        assert!(!p.pauses("https://a.com/", "Document"));
        assert!(FetchPatterns::from_params(&json!({})).pauses("https://a.com/", "Document"));
        assert!(FetchPatterns::from_params(&json!({ "patterns": [{}] })).pauses("https://a.com/", "Script"));
        assert!(!FetchPatterns::from_params(&json!({ "patterns": [] })).pauses("https://a.com/", "Script"));
    }

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
            auto_solve: None,
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
    fn fetch_answers_become_decisions() {
        let d = fetch_decision("Fetch.fulfillRequest", &json!({
            "requestId": "j", "responseCode": 404,
            "responseHeaders": [{ "name": "Content-Type", "value": "text/plain" }],
            "body": "aGk=",
        }));
        assert!(matches!(d, nokk::Decision::Fulfill { status: 404, ref headers, ref body }
            if headers.get("Content-Type").map(String::as_str) == Some("text/plain") && body == b"hi"));
        let d = fetch_decision("Fetch.continueRequest", &json!({
            "requestId": "j", "method": "POST", "postData": "eD0x",
            "headers": [{ "name": "X-Test", "value": "1" }],
        }));
        assert!(matches!(d, nokk::Decision::Continue { url: None, method: Some(ref m), headers: Some(ref h), body: Some(ref b) }
            if m == "POST" && h.len() == 1 && b == b"x=1"));
        assert!(matches!(fetch_decision("Fetch.failRequest", &json!({ "errorReason": "Aborted" })), nokk::Decision::Fail));
        assert!(matches!(fetch_decision("Fetch.continueWithAuth", &json!({})), nokk::Decision::Continue { headers: None, .. }));
    }

    #[test]
    fn a_cdp_cookie_param_becomes_a_set_cookie_line() {
        let (line, url) = super::cookie_param(&json!({
            "name": "a", "value": "1", "url": "https://x.example/p"
        })).unwrap();
        assert_eq!((line.as_str(), url.as_str()), ("a=1; Path=/", "https://x.example/p"));
        let (line, url) = super::cookie_param(&json!({
            "name": "b", "value": "2", "domain": ".x.example", "path": "/q",
            "secure": true, "httpOnly": true, "sameSite": "Lax"
        })).unwrap();
        assert_eq!(url, "https://x.example/q");
        assert_eq!(line, "b=2; Path=/q; Domain=.x.example; Secure; HttpOnly; SameSite=Lax");
        assert!(super::cookie_param(&json!({ "name": "c", "value": "3" })).is_none(), "no url and no domain");
    }

    #[test]
    fn a_token_is_checked_on_the_url_or_the_header() {
        let head = "GET /json/version HTTP/1.1\r\nHost: x\r\n";
        assert!(super::authorized(head, "/json/version", None), "no token configured: open");
        assert!(!super::authorized(head, "/json/version", Some("s3cret")));
        assert!(super::authorized(head, "/json/version?token=s3cret", Some("s3cret")));
        assert!(super::authorized(head, "/devtools/browser/nokk?a=1&token=s3cret", Some("s3cret")));
        assert!(!super::authorized(head, "/json/version?token=s3cre", Some("s3cret")));
        let bearer = "GET /devtools/browser/nokk HTTP/1.1\r\nAuthorization: Bearer s3cret\r\n";
        assert!(super::authorized(bearer, "/devtools/browser/nokk", Some("s3cret")));
        let wrong = "GET / HTTP/1.1\r\nAuthorization: Bearer nope\r\n";
        assert!(!super::authorized(wrong, "/", Some("s3cret")));
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
        assert_eq!(super::parse_proxy_server("http://p.webshare.io:80/").unwrap().port, 80);
    }

    /// DevTools evaluation is not the page's code: Chrome runs it under any CSP.
    /// Playwright's evaluate on GitHub (script-src without 'unsafe-eval') got an
    /// EvalError; the page's own eval stays refused.
    #[tokio::test]
    async fn evaluate_runs_under_a_csp_without_unsafe_eval() {
        let _s = SERIAL.lock().await;
        let conn = test_conn();
        let ctx = conn.engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><head><meta http-equiv="Content-Security-Policy" content="script-src 'self' 'nonce-n'"></head><body><script nonce="n">try { eval('1'); globalThis.pageEval = 'ran'; } catch (e) { globalThis.pageEval = e.name; }</script></body></html>"#,
        )
        .await
        .unwrap();
        assert_eq!(remote_eval(&ctx, &dev_value("1 + 2"), true, false).await["result"]["value"], json!(3));
        assert_eq!(remote_eval(&ctx, &dev_value("Promise.resolve(globalThis.pageEval)"), true, true).await["result"]["value"], json!("EvalError"));
        // Still refused for the page after the evaluation.
        assert_eq!(
            ctx.evaluate("(() => { try { eval('1'); return 'ran'; } catch (e) { return e.name; } })()").await.unwrap(),
            json!("EvalError")
        );
    }

    /// `awaitPromise` with a frame's context waits for the promise, as with the
    /// page's: it answered `{}` for a pending promise.
    #[tokio::test]
    async fn a_frame_evaluate_awaits_its_promise() {
        let _s = SERIAL.lock().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 2048];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let body = if req.starts_with("GET /f") { "<html><body><b>x</b></body></html>" } else { r#"<html><body><iframe src="/f"></iframe></body></html>"# };
                    let out = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = stream.write_all(out.as_bytes()).await;
                });
            }
        });
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig { workers: 1, max_live_contexts: 4, max_heap_mb: None },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&format!("http://{addr}/")).await.unwrap();
        let mut frame = None;
        for _ in 0..50 {
            ctx.run_event_loop().await.unwrap();
            if let Some(f) = ctx.frame_list().first() {
                frame = Some(f.id);
                break;
            }
        }
        let frame = frame.expect("the frame");
        let expr = "(async () => { await new Promise(r => setTimeout(r, 50)); return document.body.textContent + 'y'; })()";
        let v = frame_eval(&ctx, frame, &dev_value(expr), true, true).await;
        assert_eq!(v, json!({ "result": { "type": "string", "value": "xy" } }));
        let v = frame_eval(&ctx, frame, &dev_value("Promise.reject(new Error('no'))"), true, true).await;
        assert_eq!(v["exceptionDetails"]["text"], json!("Uncaught (in promise) Error: no"));
        // Without awaitPromise a promise is an object, as in Chrome.
        assert_eq!(frame_eval(&ctx, frame, &dev_value(expr), true, false).await["result"]["type"], json!("object"));
        // A handle made in the frame leads a later call back to the frame,
        // which is how Playwright's frame.evaluate reaches it; the page's own
        // handles stay the page's.
        let v = frame_eval(&ctx, frame, &dev_value("({ where: document.body.textContent })"), false, false).await;
        let oid = v["result"]["objectId"].as_str().expect("a handle").to_string();
        let (f, raw) = split_oid(&oid);
        assert_eq!(f, Some(frame), "{oid}");
        let call = format!("__pt_devCall({}, __pt_objGet({}), [])", js_str("function () { return this.where; }"), js_str(raw));
        assert_eq!(frame_eval(&ctx, frame, &call, true, false).await["result"]["value"], json!("x"));
        let v = remote_eval(&ctx, &dev_value("({})"), false, false).await;
        assert_eq!(split_oid(v["result"]["objectId"].as_str().unwrap()).0, None);
        assert_eq!(split_node_id((frame as i64 + 1) * NODE_STRIDE + 7), (Some(frame), 7));
        assert_eq!(split_node_id(7), (None, 7));
        // Keyboard input goes to the document that took focus last.
        let focus = "(() => { const i = document.createElement('input'); document.body.append(i); i.focus(); return 1; })()";
        assert_eq!(focused_frame(&ctx).await, None);
        frame_eval(&ctx, frame, &dev_value(focus), true, false).await;
        assert_eq!(focused_frame(&ctx).await, Some(frame));
        remote_eval(&ctx, &dev_value(focus), true, false).await;
        assert_eq!(focused_frame(&ctx).await, None);
        // A same-origin frame is joined to its page, as in Chrome: each side
        // reaches the other's real window, document and element.
        let v = remote_eval(&ctx, &dev_value("(() => { const f = document.querySelector('iframe'); return [f.contentDocument.body.textContent, f.contentWindow.parent === window, window[0] === f.contentWindow].join(); })()"), true, false).await;
        assert_eq!(v["result"]["value"], json!("x,true,true"), "{v}");
        let v = frame_eval(&ctx, frame, &dev_value("[frameElement.tagName, frameElement.ownerDocument === parent.document, parent === top].join()"), true, false).await;
        assert_eq!(v["result"]["value"], json!("IFRAME,true,true"), "{v}");
        // A frame posting to its parent is the message's source.
        remote_eval(&ctx, &dev_value("addEventListener('message', (e) => { globalThis.got = [e.data, e.source === document.querySelector('iframe').contentWindow].join(); })"), true, false).await;
        frame_eval(&ctx, frame, &dev_value("parent.postMessage('up', '*')"), true, false).await;
        ctx.run_event_loop().await.unwrap();
        assert_eq!(remote_eval(&ctx, &dev_value("globalThis.got"), true, false).await["result"]["value"], json!("up,true"));
        // A frame's boxes move by where its <iframe> sits.
        let mut q = json!({ "content": [1, 2, 3, 4], "width": 5, "height": 6 });
        shift_quads(&mut q, 10.0, 20.0);
        assert_eq!(q, json!({ "content": [11.0, 22.0, 13.0, 24.0], "width": 5, "height": 6 }));
    }

    /// A throw or a rejection comes back as Chrome sends it: `exceptionDetails`
    /// beside the result. Puppeteer and Playwright raise on that field; without
    /// it `page.evaluate(() => { throw … })` handed back the string "Error: …".
    #[tokio::test]
    async fn a_throw_answers_with_exception_details() {
        let _s = SERIAL.lock().await;
        let conn = test_conn();
        let ctx = conn.engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>").await.unwrap();

        let v = remote_eval(&ctx, &dev_value("(() => { throw new TypeError('boom'); })()"), true, false).await;
        let d = &v["exceptionDetails"];
        assert_eq!(d["text"], json!("Uncaught"));
        assert_eq!(d["exception"]["subtype"], json!("error"));
        assert_eq!(d["exception"]["className"], json!("TypeError"));
        assert!(d["exception"]["description"].as_str().unwrap().starts_with("TypeError: boom"), "{v}");
        // A thrown object is a handle even when the value was asked for.
        assert!(v["result"]["objectId"].is_string(), "{v}");

        let v = remote_eval(&ctx, &dev_value("Promise.reject(new Error('no'))"), true, true).await;
        assert_eq!(v["exceptionDetails"]["text"], json!("Uncaught (in promise) Error: no"));
        let v = remote_eval(&ctx, &dev_value("Promise.reject(5)"), true, true).await;
        assert_eq!(v["exceptionDetails"]["text"], json!("Uncaught (in promise)"), "{v}");
        assert_eq!(v["result"], json!({ "type": "number", "value": 5 }));
        let v = remote_eval(&ctx, &dev_value("(() => { throw 'str'; })()"), true, true).await;
        assert_eq!(v["exceptionDetails"]["text"], json!("Uncaught"));
        assert_eq!(v["exceptionDetails"]["exception"], json!({ "type": "string", "value": "str" }));
        let v = remote_eval(&ctx, &dev_value("1 +"), false, false).await;
        assert_eq!(v["exceptionDetails"]["exception"]["className"], json!("SyntaxError"));

        // A value is still just a result.
        assert_eq!(remote_eval(&ctx, &dev_value("40 + 2"), true, false).await, json!({ "result": { "type": "number", "value": 42 } }));
        // Reporting the error runs none of the page's code.
        let v = remote_eval(
            &ctx,
            &dev_value("(() => { Object.defineProperty(Error, Symbol.hasInstance, { value: () => { globalThis.hooked = 1; return false; } }); \
               Error.prototype.toString = () => { globalThis.hooked = 2; return 'x'; }; throw new Error('e'); })()"),
            true,
            false,
        )
        .await;
        assert_eq!(v["exceptionDetails"]["exception"]["subtype"], json!("error"));
        assert_eq!(remote_eval(&ctx, &dev_value("globalThis.hooked"), true, false).await["result"], json!({ "type": "undefined" }));
    }

    /// DevTools code is a script named '' as in Chrome: its frames read
    /// `<anonymous>:1:7`, an eval inside it `eval at f (:1:24)`, and nothing
    /// names the engine. A function from `callFunctionOn` is called without a
    /// frame of ours, at its own line and column.
    #[tokio::test]
    async fn devtools_code_leaves_chromes_stack() {
        let _s = SERIAL.lock().await;
        let conn = test_conn();
        let ctx = conn.engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>").await.unwrap();

        let v = remote_eval(&ctx, &dev_value("new Error('top').stack"), true, false).await;
        assert_eq!(v["result"]["value"], json!("Error: top\n    at <anonymous>:1:1"));
        let v = remote_eval(&ctx, &dev_value("(function f() { return eval('new Error(1).stack'); })()"), true, false).await;
        assert_eq!(
            v["result"]["value"],
            json!("Error: 1\n    at eval (eval at f (:1:24), <anonymous>:1:1)\n    at f (<anonymous>:1:24)\n    at <anonymous>:1:54")
        );
        let call = format!("__pt_devCall({}, globalThis, [2])", js_str("function (n) { return new Error(n).stack; }"));
        let v = remote_eval(&ctx, &call, true, false).await;
        assert_eq!(v["result"]["value"], json!("Error: 2\n    at <anonymous>:1:24"));
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
            conn.pump_live_pages(&sink()).await;
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
