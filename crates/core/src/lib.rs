//! Engine core — the public API and orchestration layer.
//!
//! [`Engine`] ties together the isolate pool ([`nokk_pool`]), the network
//! layer ([`nokk_net`]) and the stealth profile ([`nokk_stealth`]).
//! It is the surface the CLI and the CDP server drive.
//!
//! The threading contract flows through here: each [`BrowserContext`] is pinned
//! to one isolate worker, holds a live-context permit for its whole lifetime
//! (backpressure), and dispatches all JS/DOM work onto its owning worker so V8
//! state is only ever touched from its home thread.
//!
//! Phase 0 status: context creation, placement and lifecycle are real;
//! [`BrowserContext::evaluate`] and [`BrowserContext::navigate`] plumb the call
//! through the correct machinery but return `NotImplemented` until Phases 1–2
//! land V8 and the networking stack.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use nokk_net::{
    Client, ClientConfig, FingerprintClient, HttpClient, NetError, Request, StubClient,
};
use nokk_pool::{IsolatePool, PoolError};
use nokk_stealth::StealthProfile;
use serde_json::Value;

// Re-export the types callers commonly need, so depending on `nokk`
// is sufficient to configure and drive an engine.
pub use nokk_net::{ProxyConfig, ProxyScheme, Response as HttpResponse};
pub use nokk_pool::{PoolConfig, WorkerId};

/// Errors surfaced by the engine.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Pool(#[from] PoolError),
    #[error("network error: {0}")]
    Net(#[from] NetError),
    #[error("JS error: {0}")]
    Js(String),
    #[error("navigation is not implemented yet (Phase 2)")]
    NavNotImplemented,
}

/// Top-level engine configuration.
#[derive(Debug, Clone, Default)]
pub struct EngineConfig {
    pub pool: PoolConfig,
    pub client: ClientConfig,
    pub stealth: StealthProfile,
    /// Use the real (temporary, non-fingerprinted) HTTP client instead of the
    /// stub. `false` keeps requests offline — the default so tests never touch
    /// the network implicitly.
    pub use_real_network: bool,
}

struct EngineInner {
    pool: IsolatePool,
    /// The default (no per-context proxy) client.
    client: Client,
    /// Base client configuration, cloned to build per-proxy clients.
    client_config: ClientConfig,
    use_real_network: bool,
    /// Fingerprint clients keyed by proxy, so contexts sharing a proxy share one
    /// connection pool (per-context identity without a client-per-context blow-up).
    client_pool: Mutex<HashMap<String, Client>>,
    stealth: StealthProfile,
    /// JS run in every new context before any page script: the spoofed
    /// `navigator`/`window`/`screen` environment. Built once from the profile.
    bootstrap: String,
}

impl EngineInner {
    /// The client for a context with a given identity `key` and optional `proxy`.
    /// An empty key (the default browser context) or the stub network always uses
    /// the shared default client. Otherwise the client is built once per key and
    /// pooled — so each identity gets its *own* cookie jar (Puppeteer browser
    /// contexts are isolated even when they share, or omit, a proxy).
    fn client_for(&self, key: &str, proxy: Option<ProxyConfig>) -> Result<Client, EngineError> {
        if key.is_empty() || !self.use_real_network {
            return Ok(self.client.clone());
        }
        if let Some(c) = self
            .client_pool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
        {
            return Ok(c.clone());
        }
        // Build the (BoringSSL) client outside the lock so concurrent first-use of
        // *different* identities don't serialise on it; re-check on insert.
        let mut cfg = self.client_config.clone();
        cfg.proxy = proxy;
        let client = Client::Fingerprint(FingerprintClient::new(&cfg)?);
        let mut pool = self.client_pool.lock().unwrap_or_else(|e| e.into_inner());
        Ok(pool.entry(key.to_string()).or_insert(client).clone())
    }
}

/// Pool key for a proxy (used by [`Engine::new_context_with_proxy`] to share one
/// client among contexts that route through the same proxy).
fn proxy_key(p: &ProxyConfig) -> String {
    format!(
        "proxy:{:?}|{}|{}|{}",
        p.scheme,
        p.host,
        p.port,
        p.username.as_deref().unwrap_or("")
    )
}

/// A running engine: owns the isolate worker pool and hands out contexts.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

impl Engine {
    /// Build an engine and spawn its worker threads.
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        let pool = IsolatePool::new(config.pool);
        let client = if config.use_real_network {
            Client::Fingerprint(FingerprintClient::new(&config.client)?)
        } else {
            Client::Stub(StubClient::new(config.client.clone()))
        };
        // Per-context bootstrap, in dependency order: the stealth environment
        // (navigator/window/screen/Intl/timers/fetch), then the DOM runtime
        // (document/Element/Event…), then the fingerprint hardening layer (which
        // patches HTMLElement.prototype + navigator, so it must run last).
        let bootstrap = format!(
            "{}\n{}\n{}",
            nokk_stealth::bootstrap_script(&config.stealth),
            nokk_dom::runtime_js(),
            nokk_stealth::fingerprint_script(&config.stealth),
        );
        tracing::info!(
            workers = pool.worker_count(),
            max_live_contexts = pool.max_live_contexts(),
            real_network = config.use_real_network,
            "engine started"
        );
        Ok(Self {
            inner: Arc::new(EngineInner {
                pool,
                client,
                client_config: config.client,
                use_real_network: config.use_real_network,
                client_pool: Mutex::new(HashMap::new()),
                stealth: config.stealth,
                bootstrap,
            }),
        })
    }

    /// Number of isolate worker threads.
    pub fn worker_count(&self) -> usize {
        self.inner.pool.worker_count()
    }

    /// Context slots currently free before backpressure kicks in.
    pub fn available_context_slots(&self) -> usize {
        self.inner.pool.available_context_slots()
    }

    /// Open a new context ("tab"). Awaits a free context slot (backpressure),
    /// places the context on the least-loaded worker, and creates it on that
    /// worker's isolate.
    pub async fn new_context(&self) -> Result<BrowserContext, EngineError> {
        self.new_context_with_identity(String::new(), None).await
    }

    /// Like [`new_context`](Self::new_context), but routes this context's network
    /// through `proxy` and its own cookie jar. Contexts routing through the *same*
    /// proxy share one client (jar + connection pool) — convenient for rotating
    /// proxies. For strict per-context isolation use
    /// [`new_context_with_identity`](Self::new_context_with_identity).
    pub async fn new_context_with_proxy(
        &self,
        proxy: Option<ProxyConfig>,
    ) -> Result<BrowserContext, EngineError> {
        let key = proxy.as_ref().map(proxy_key).unwrap_or_default();
        self.new_context_with_identity(key, proxy).await
    }

    /// Create a context bound to a named identity: all contexts sharing the same
    /// non-empty `identity` share one client (cookie jar + proxy + connection
    /// pool); distinct identities are fully isolated even with the same `proxy`.
    /// An empty identity uses the engine's shared default client. The CDP layer
    /// passes the Puppeteer browser-context id here so browser contexts are
    /// cookie-isolated.
    pub async fn new_context_with_identity(
        &self,
        identity: String,
        proxy: Option<ProxyConfig>,
    ) -> Result<BrowserContext, EngineError> {
        let client = self.inner.client_for(&identity, proxy)?;
        let permit = self.inner.pool.acquire_context().await?;
        let worker = self.inner.pool.pick_worker();
        let load = self.inner.pool.register_context(worker);
        let bootstrap = self.inner.bootstrap.clone();
        let index = self
            .inner
            .pool
            .dispatch(worker, move |iso| iso.create_context(&bootstrap))
            .await?
            .map_err(EngineError::Js)?;
        tracing::debug!(?worker, index, "context created");
        Ok(BrowserContext {
            engine: self.inner.clone(),
            client,
            worker,
            index,
            base_url: std::sync::Mutex::new("about:blank".to_string()),
            requests: std::sync::Mutex::new(Vec::new()),
            _permit: permit,
            _load: load,
        })
    }

    /// The stealth injection script for this engine's profile — the code the CDP
    /// layer will register to run before every new document.
    pub fn injection_script(&self) -> String {
        nokk_stealth::injection_script(&self.inner.stealth)
    }

    /// Perform a bare HTTP GET through the network layer, carrying the engine's
    /// stealth `User-Agent`. Runs entirely on the tokio runtime — it does not
    /// occupy an isolate worker thread. Errors with [`EngineError::NavNotImplemented`]
    /// if the engine was built without `use_real_network`.
    pub async fn fetch(&self, url: &str) -> Result<HttpResponse, EngineError> {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert(
            "User-Agent".to_string(),
            self.inner.stealth.user_agent.clone(),
        );
        headers.insert(
            "Accept-Language".to_string(),
            self.inner.stealth.languages.join(","),
        );
        let req = Request {
            method: "GET".into(),
            url: url.to_string(),
            headers,
            body: None,
        };
        match self.inner.client.send(req).await {
            Ok(resp) => Ok(resp),
            Err(NetError::Unimplemented) => Err(EngineError::NavNotImplemented),
            Err(e) => Err(EngineError::Net(e)),
        }
    }
}

/// One browser context / "tab", pinned to a single isolate worker.
///
/// Holds the live-context permit and load guard; dropping the context releases
/// both, freeing a slot for a queued navigation.
pub struct BrowserContext {
    engine: Arc<EngineInner>,
    /// This context's HTTP client — its own proxy + cookie jar when created with
    /// [`Engine::new_context_with_proxy`], else the engine default.
    client: Client,
    worker: WorkerId,
    index: usize,
    /// Document URL of the last `load_html`/`navigate`, used to resolve relative
    /// `fetch`/`XHR` URLs. `about:blank` until the first navigation.
    base_url: std::sync::Mutex<String>,
    /// Every network request the engine made for this context, in order — the
    /// built-in interception log (document + external scripts + page fetch/XHR).
    requests: std::sync::Mutex<Vec<NetworkRecord>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _load: nokk_pool::ContextLoadGuard,
}

impl Drop for BrowserContext {
    fn drop(&mut self) {
        // Dispose the V8 context on its owning worker so the isolate reclaims it.
        // Without this, create/close churn (every Puppeteer newPage/close) grows
        // the isolate's context table unbounded — a slow leak on a busy server.
        // Fire-and-forget: there's no caller to return to from Drop.
        let index = self.index;
        self.engine
            .pool
            .dispatch_detached(self.worker, move |iso| iso.dispose_context(index));
    }
}

/// One network request the engine performed on a page's behalf. Because page JS
/// calls into the engine's Rust network layer, *every* `fetch`/`XMLHttpRequest`
/// and subresource script flows through here — this is the interception point.
#[derive(Debug, Clone)]
pub struct NetworkRecord {
    pub method: String,
    pub url: String,
    /// HTTP status, or `0` when the request never got a response (DNS failure,
    /// connection reset, a blocked subresource) — the attempt is still logged so
    /// an audit of "what did this page try to contact" is complete.
    pub status: u16,
    /// `"document"`, `"script"`, or `"fetch"` (covers XHR, layered on fetch).
    pub resource_type: String,
    pub body: Vec<u8>,
}

impl BrowserContext {
    /// The worker this context is pinned to.
    pub fn worker(&self) -> WorkerId {
        self.worker
    }

    /// The context's index within its isolate.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Evaluate JavaScript in this context and return the result stringified.
    /// The call is dispatched onto the owning isolate thread, so V8 state is
    /// only ever touched from its home thread.
    pub async fn evaluate(&self, script: &str) -> Result<Value, EngineError> {
        let index = self.index;
        let source = script.to_string();
        let result = self
            .engine
            .pool
            .dispatch(self.worker, move |iso| iso.eval(index, &source))
            .await?;
        result.map(Value::String).map_err(EngineError::Js)
    }

    /// Navigate this context to `url`: fetch the document over the network, then
    /// [`load_html`](Self::load_html) it. Requires real networking (the stub
    /// client reports [`EngineError::NavNotImplemented`]).
    pub async fn navigate(&self, url: &str) -> Result<(), EngineError> {
        // Use the post-redirect URL as the document base, so `window.location`
        // and relative-URL resolution reflect where we actually landed.
        let (final_url, html) = self.fetch_text(url, "document").await?;
        self.load_html(&final_url, &html).await
    }

    /// Build the DOM from `html`, then run its scripts in document order and fire
    /// `DOMContentLoaded`/`load`. `base_url` resolves relative external script
    /// `src`s. Page scripts that throw are logged and skipped — a broken page
    /// script must not fail the load, matching browser behaviour.
    pub async fn load_html(&self, base_url: &str, html: &str) -> Result<(), EngineError> {
        if let Ok(mut b) = self.base_url.lock() {
            *b = base_url.to_string();
        }
        // Reflect the real URL into `window.location` before any script runs.
        if let Some(js) = location_setter(base_url) {
            let _ = self.evaluate(&js).await;
        }
        let page = nokk_dom::parse(html);

        // Install the parsed tree as `document`.
        self.evaluate(&page.install_script()).await?;

        // Execute scripts in order against the live document. `idx` matches the
        // document-order script list the DOM runtime built, so `__pt_beginScript`
        // can point `document.currentScript` at the running node (document.write
        // positioning); `__pt_endScript` clears it afterward.
        for (idx, script) in page.scripts.iter().enumerate() {
            let code = match script {
                nokk_dom::Script::Inline(code) => code.clone(),
                nokk_dom::Script::External(src) => match resolve_url(base_url, src) {
                    Some(abs) => match self.fetch_text(&abs, "script").await {
                        Ok((_, code)) => code,
                        Err(e) => {
                            tracing::warn!(url = %abs, error = %e, "external script fetch failed");
                            continue;
                        }
                    },
                    None => {
                        tracing::warn!(src, "could not resolve external script URL");
                        continue;
                    }
                },
            };
            let _ = self.evaluate(&format!("__pt_beginScript({idx})")).await;
            if let Err(e) = self.evaluate(&code).await {
                tracing::debug!(error = %e, "page script threw");
            }
            let _ = self.evaluate("__pt_endScript()").await;
        }

        // Fire lifecycle events, then drain the event loop so timers and async
        // continuations scheduled during load (and by the load handlers) run.
        self.evaluate("__pt_finishLoad();").await?;
        self.run_event_loop().await?;
        Ok(())
    }

    /// Drive this context's event loop until it goes idle: alternately pump
    /// timers (virtual time, on the isolate thread) and service the JS `fetch`
    /// queue (real network, on the tokio side, off the isolate thread), settling
    /// each Promise back in the isolate so resolved awaits can schedule more work.
    /// Returns the number of timer callbacks run. Bounded by a wall-clock deadline
    /// and a per-load fetch cap.
    pub async fn run_event_loop(&self) -> Result<u32, EngineError> {
        const TIMER_CAP: u32 = 10_000;
        const MAX_FETCHES: usize = 200;
        const MAX_ROUNDS: usize = 2_000;
        // Total wall-clock the post-load event loop may run. Kept short because it
        // executes on the (shared) isolate worker: a page with endless ad/tracker
        // `setInterval`s would otherwise monopolise a worker for the full budget
        // and starve every other context pinned to it — the dominant cause of
        // timeouts under concurrent load. The load-critical async (promise chains,
        // one-shot timers, initial fetches) normally settles well under a second.
        // Override with `NOKK_EVENT_LOOP_MS`.
        let budget_ms = std::env::var("NOKK_EVENT_LOOP_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(3_000);
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget_ms);
        let index = self.index;
        let base = self.base_url.lock().map(|b| b.clone()).unwrap_or_default();

        let mut total_timers = 0u32;
        let mut fetches_done = 0usize;

        for _ in 0..MAX_ROUNDS {
            if std::time::Instant::now() >= deadline {
                break;
            }

            // 1. Run timers to (virtual-time) exhaustion on the worker. TIMER_CAP
            //    is a *total* budget across rounds so a runaway `setInterval` is
            //    bounded overall, not merely per round.
            let remaining = TIMER_CAP.saturating_sub(total_timers);
            let ran = self
                .engine
                .pool
                .dispatch(self.worker, move |iso| {
                    // Short per-round grab so the worker is released back to other
                    // contexts frequently (fairness), rather than held for seconds.
                    iso.run_event_loop(index, remaining, std::time::Duration::from_millis(250))
                })
                .await?
                .map_err(EngineError::Js)?;
            total_timers += ran;

            // 2. Pull any fetch requests the JS queued.
            let qjson = self
                .engine
                .pool
                .dispatch(self.worker, move |iso| {
                    iso.eval(index, "__pt_drainFetchQueue()")
                })
                .await?
                .map_err(EngineError::Js)?;
            let reqs: Vec<Value> = serde_json::from_str(&qjson).unwrap_or_default();

            if ran == 0 && reqs.is_empty() {
                break; // idle: no timers ran and nothing to fetch
            }

            // 3. Perform each fetch off the isolate thread, then settle its
            //    Promise back on the worker.
            for r in reqs {
                if fetches_done >= MAX_FETCHES {
                    break;
                }
                fetches_done += 1;
                let settle = self.perform_fetch(&base, &r).await;
                self.engine
                    .pool
                    .dispatch(self.worker, move |iso| iso.eval(index, &settle))
                    .await?
                    .map_err(EngineError::Js)?;
            }
        }
        Ok(total_timers)
    }

    /// Run one queued `fetch` request and build the JS call that settles it.
    async fn perform_fetch(&self, base: &str, r: &Value) -> String {
        let id = r["id"].as_i64().unwrap_or(0);
        let raw_url = r["url"].as_str().unwrap_or("").to_string();
        let url = resolve_url(base, &raw_url).unwrap_or(raw_url);
        let method = r["method"].as_str().unwrap_or("GET").to_string();
        let mut headers = std::collections::BTreeMap::new();
        if let Some(obj) = r["headers"].as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    headers.insert(k.clone(), s.to_string());
                }
            }
        }
        // `x-pt-kind` is an internal tag (beacon/image) set by the JS shims — use
        // it as the resource type and strip it so it never hits the wire.
        let kind = headers
            .remove("x-pt-kind")
            .unwrap_or_else(|| "fetch".to_string());
        let body = r["body"].as_str().map(|s| s.as_bytes().to_vec());
        let req = Request {
            method,
            url: url.clone(),
            headers,
            body,
        };

        let method = req.method.clone();
        match self.client.send(req).await {
            Ok(resp) => {
                self.record(&method, &url, &kind, resp.status, &resp.body);
                let headers_js =
                    serde_json::to_string(&resp.headers).unwrap_or_else(|_| "{}".into());
                let body = String::from_utf8_lossy(&resp.body);
                // `response.url` is the final URL after redirects (fetch spec).
                let final_url = if resp.url.is_empty() { &url } else { &resp.url };
                format!(
                    "__pt_fetchResolve({}, {}, {}, {}, {}, {})",
                    id,
                    resp.status,
                    serde_json::to_string(reason_phrase(resp.status)).unwrap(),
                    headers_js,
                    serde_json::to_string(&*body).unwrap(),
                    serde_json::to_string(final_url).unwrap(),
                )
            }
            Err(e) => {
                // A transport failure is still an attempted request — log it with
                // status 0 so the interception log stays complete. (Skip the
                // "no real network" stub error, which never reached the wire.)
                if !matches!(e, NetError::Unimplemented) {
                    self.record(&method, &url, &kind, 0, &[]);
                }
                format!(
                    "__pt_fetchReject({}, {})",
                    id,
                    serde_json::to_string(&e.to_string()).unwrap()
                )
            }
        }
    }

    /// GET `url` and return `(final_url, body)` as text, using the engine's
    /// fingerprint headers, recording it under `resource_type`. `final_url` is the
    /// destination after any redirects — the caller uses it as the document base.
    /// Runs off the isolate thread.
    async fn fetch_text(
        &self,
        url: &str,
        resource_type: &str,
    ) -> Result<(String, String), EngineError> {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert(
            "User-Agent".to_string(),
            self.engine.stealth.user_agent.clone(),
        );
        headers.insert(
            "Accept-Language".to_string(),
            self.engine.stealth.languages.join(","),
        );
        let req = Request {
            method: "GET".into(),
            url: url.to_string(),
            headers,
            body: None,
        };
        match self.client.send(req).await {
            Ok(resp) => {
                self.record("GET", url, resource_type, resp.status, &resp.body);
                let final_url = if resp.url.is_empty() {
                    url.to_string()
                } else {
                    resp.url.clone()
                };
                Ok((final_url, String::from_utf8_lossy(&resp.body).into_owned()))
            }
            Err(NetError::Unimplemented) => Err(EngineError::NavNotImplemented),
            Err(e) => {
                // Log the failed attempt (status 0) before surfacing the error.
                self.record("GET", url, resource_type, 0, &[]);
                Err(EngineError::Net(e))
            }
        }
    }

    /// Append a request to this context's interception log.
    fn record(&self, method: &str, url: &str, resource_type: &str, status: u16, body: &[u8]) {
        if let Ok(mut log) = self.requests.lock() {
            log.push(NetworkRecord {
                method: method.to_string(),
                url: url.to_string(),
                status,
                resource_type: resource_type.to_string(),
                body: body.to_vec(),
            });
        }
    }

    /// All network requests the engine made for this context, in order — the
    /// document, external scripts, and every page `fetch`/`XHR`.
    pub fn requests(&self) -> Vec<NetworkRecord> {
        self.requests.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

/// Resolve a possibly-relative URL against a base document URL.
fn resolve_url(base: &str, rel: &str) -> Option<String> {
    url::Url::parse(base)
        .ok()?
        .join(rel)
        .ok()
        .map(|u| u.to_string())
}

/// Build the `__pt_setLocation({...})` call that populates `window.location`
/// from a navigated URL. Returns `None` if the URL doesn't parse.
fn location_setter(u: &str) -> Option<String> {
    let p = url::Url::parse(u).ok()?;
    let host = p.host_str().map(|h| match p.port() {
        Some(port) => format!("{h}:{port}"),
        None => h.to_string(),
    });
    let obj = serde_json::json!({
        "href": p.as_str(),
        "protocol": format!("{}:", p.scheme()),
        "host": host.clone().unwrap_or_default(),
        "hostname": p.host_str().unwrap_or(""),
        "port": p.port().map(|n| n.to_string()).unwrap_or_default(),
        "pathname": p.path(),
        "search": p.query().map(|q| format!("?{q}")).unwrap_or_default(),
        "hash": p.fragment().map(|f| format!("#{f}")).unwrap_or_default(),
        "origin": p.origin().unicode_serialization(),
    });
    Some(format!("__pt_setLocation({obj});"))
}

/// A short HTTP reason phrase for the common status codes `fetch` exposes as
/// `Response.statusText`. Unlisted codes get an empty string (browsers do too on
/// HTTP/2, which carries no reason phrase).
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::{Mutex, MutexGuard};

    // Serialise engine lifetimes across tests in this binary. The embedded V8 is
    // stable for the production pattern (one fixed pool, created once, disposed
    // once) but segfaults when isolate pools are created and torn down in
    // overlapping lifetimes across threads — which the default parallel test
    // harness does. Each test holds this for its whole body, so its engine is
    // fully disposed before the next test's engine is built. See the pool crate
    // for the underlying limitation (tracked for Phase 7).
    // Async-aware mutex so the guard can be held across `.await` (the whole point
    // — serialise each test's engine lifetime) without tripping `await_holding_lock`.
    static SERIAL: Mutex<()> = Mutex::const_new(());

    async fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().await
    }

    fn engine(workers: usize, max_ctx: usize) -> Engine {
        Engine::new(EngineConfig {
            pool: PoolConfig {
                workers,
                max_live_contexts: max_ctx,
                max_heap_mb: None,
            },
            ..Default::default()
        })
        .expect("stub engine never fails to build")
    }

    #[tokio::test]
    async fn dropping_a_context_disposes_it_on_the_isolate() {
        let _serial = serial().await;
        let engine = engine(1, 4);
        let ctx = engine.new_context().await.unwrap();
        let worker = ctx.worker();
        let before = engine
            .inner
            .pool
            .dispatch(worker, |iso| iso.context_count())
            .await
            .unwrap();
        drop(ctx); // fires the detached dispose job (FIFO before the count below)
        let after = engine
            .inner
            .pool
            .dispatch(worker, |iso| iso.context_count())
            .await
            .unwrap();
        assert_eq!(before, 1);
        assert_eq!(after, 0, "closed context must be disposed on the isolate");
    }

    #[tokio::test]
    async fn distinct_identities_get_isolated_clients() {
        let _serial = serial().await;
        // Real network so per-identity clients are actually built (no request is
        // made — building a client is offline).
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 8,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let _def = engine.new_context().await.unwrap(); // empty identity → default client, not pooled
        let _a = engine
            .new_context_with_identity("A".into(), None)
            .await
            .unwrap();
        let _b = engine
            .new_context_with_identity("B".into(), None)
            .await
            .unwrap();
        let _a2 = engine
            .new_context_with_identity("A".into(), None)
            .await
            .unwrap();
        // A and B each got their own client; A2 reused A's; the default is separate.
        assert_eq!(engine.inner.client_pool.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn new_context_places_on_a_worker() {
        let _serial = serial().await;
        let engine = engine(4, 8);
        let ctx = engine.new_context().await.unwrap();
        assert!(ctx.worker().0 < 4);
    }

    #[tokio::test]
    async fn context_holds_a_slot_until_dropped() {
        let _serial = serial().await;
        let engine = engine(2, 2);
        assert_eq!(engine.available_context_slots(), 2);
        let a = engine.new_context().await.unwrap();
        let b = engine.new_context().await.unwrap();
        assert_eq!(engine.available_context_slots(), 0);
        drop(a);
        assert_eq!(engine.available_context_slots(), 1);
        drop(b);
        assert_eq!(engine.available_context_slots(), 2);
    }

    #[tokio::test]
    async fn evaluate_runs_real_javascript() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        assert_eq!(
            ctx.evaluate("40 + 2").await.unwrap(),
            Value::String("42".into())
        );
    }

    #[tokio::test]
    async fn evaluate_surfaces_js_exceptions() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        assert!(matches!(
            ctx.evaluate("throw new Error('boom')").await,
            Err(EngineError::Js(msg)) if msg.contains("boom")
        ));
    }

    #[tokio::test]
    async fn stealth_navigator_reports_chrome() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        // The core anti-bot tell must be hidden.
        assert_eq!(
            ctx.evaluate("navigator.webdriver").await.unwrap(),
            Value::String("false".into())
        );
        // UA and platform come from the profile.
        let ua = ctx.evaluate("navigator.userAgent").await.unwrap();
        assert!(matches!(ua, Value::String(s) if s.contains("Chrome/")));
        assert_eq!(
            ctx.evaluate("navigator.hardwareConcurrency").await.unwrap(),
            Value::String("8".into())
        );
        assert_eq!(
            ctx.evaluate("window === window.self").await.unwrap(),
            Value::String("true".into())
        );
    }

    #[tokio::test]
    async fn navigate_reports_not_implemented_on_stub() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        assert!(matches!(
            ctx.navigate("https://example.com").await,
            Err(EngineError::NavNotImplemented)
        ));
    }

    #[tokio::test]
    async fn injection_script_reflects_profile() {
        let _serial = serial().await;
        let engine = engine(1, 1);
        assert!(engine.injection_script().contains("'webdriver', false"));
    }

    #[tokio::test]
    async fn load_html_builds_dom_and_runs_page_script() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        let html = r#"<!DOCTYPE html><html><head><title>Demo</title></head>
            <body>
              <ul id="list"></ul>
              <script>
                // A page script that reads the stealth navigator AND mutates the DOM.
                var ul = document.getElementById('list');
                ['a','b','c'].forEach(function(t) {
                  var li = document.createElement('li');
                  li.textContent = t + ':' + navigator.hardwareConcurrency;
                  ul.appendChild(li);
                });
                document.title = 'Loaded ' + document.querySelectorAll('#list li').length;
              </script>
            </body></html>"#;

        ctx.load_html("https://example.com/", html).await.unwrap();

        // The script ran against a real DOM: 3 <li> were created.
        assert_eq!(
            ctx.evaluate("document.querySelectorAll('#list li').length")
                .await
                .unwrap(),
            Value::String("3".into())
        );
        // ...and it could read the spoofed navigator while doing so.
        assert_eq!(
            ctx.evaluate("document.querySelector('#list li').textContent")
                .await
                .unwrap(),
            Value::String("a:8".into())
        );
        // ...and the title setter reflected back through the DOM.
        assert_eq!(
            ctx.evaluate("document.title").await.unwrap(),
            Value::String("Loaded 3".into())
        );
        // readyState advanced through the load lifecycle.
        assert_eq!(
            ctx.evaluate("document.readyState").await.unwrap(),
            Value::String("complete".into())
        );
    }

    #[tokio::test]
    async fn intl_is_shimmed_and_does_not_crash() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // Native Intl aborts the process on this V8 build; the shim must answer
        // with the profile's timezone instead.
        assert_eq!(
            ctx.evaluate("Intl.DateTimeFormat().resolvedOptions().timeZone")
                .await
                .unwrap(),
            Value::String("America/New_York".into())
        );
        // Date locale methods must not hit ICU either.
        assert!(matches!(
            ctx.evaluate("typeof new Date(0).toLocaleString()").await.unwrap(),
            Value::String(s) if s == "string"
        ));
    }

    #[tokio::test]
    async fn runaway_script_is_terminated_by_watchdog() {
        let _serial = serial().await;
        // Force a short watchdog so the test doesn't wait the 10s default.
        std::env::set_var("NOKK_EVAL_TIMEOUT_MS", "400");
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // An infinite loop must be force-terminated (Err), not hang forever, and
        // the isolate must remain usable afterward.
        let started = std::time::Instant::now();
        assert!(ctx.evaluate("while (true) {}").await.is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // Isolate still works after termination.
        assert_eq!(
            ctx.evaluate("1 + 1").await.unwrap(),
            Value::String("2".into())
        );
        std::env::remove_var("NOKK_EVAL_TIMEOUT_MS");
    }

    #[tokio::test]
    async fn event_loop_runs_timers_in_virtual_time_order() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // A 100ms timer and an async fn that awaits a 50ms timer. Nothing runs
        // until the loop is driven.
        ctx.evaluate(
            "globalThis.log = [];
             setTimeout(() => log.push('t100'), 100);
             (async () => { await new Promise(r => setTimeout(r, 50)); log.push('async50'); })();",
        )
        .await
        .unwrap();
        assert_eq!(
            ctx.evaluate("log.length").await.unwrap(),
            Value::String("0".into())
        );

        let ran = ctx.run_event_loop().await.unwrap();
        assert!(ran >= 2, "expected >=2 timer callbacks, got {ran}");
        // Virtual time orders 50ms before 100ms; the async continuation (a
        // microtask off the 50ms timer) runs before the 100ms timer.
        assert_eq!(
            ctx.evaluate("log.join(',')").await.unwrap(),
            Value::String("async50,t100".into())
        );
    }

    #[tokio::test]
    async fn event_loop_caps_runaway_interval() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // An interval that never stops must be bounded by the callback cap, not
        // hang the worker.
        ctx.evaluate("globalThis.n = 0; setInterval(() => { n++; }, 10);")
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let ran = ctx.run_event_loop().await.unwrap();
        assert!(ran > 0 && ran <= 10_000, "capped callback count, got {ran}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[tokio::test]
    async fn load_html_drains_deferred_dom_mutation() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // A script that mutates the DOM from a setTimeout — only visible if the
        // load drives the event loop.
        let html = r#"<html><body><div id="x">before</div>
            <script>setTimeout(function(){ document.getElementById('x').textContent = 'after'; }, 200);</script>
            </body></html>"#;
        ctx.load_html("https://example.com/", html).await.unwrap();
        assert_eq!(
            ctx.evaluate("document.getElementById('x').textContent")
                .await
                .unwrap(),
            Value::String("after".into())
        );
    }

    #[tokio::test]
    async fn fetch_plumbs_through_event_loop_and_settles() {
        let _serial = serial().await;
        // Stub client → every request is Unimplemented, so fetch must *reject*;
        // this still exercises the full queue→network→settle→Promise path offline.
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.evaluate(
            "globalThis.r = 'pending';
             fetch('https://example.com/api').then(() => r = 'ok', () => r = 'rejected');",
        )
        .await
        .unwrap();
        // Not settled until the loop services the queue.
        assert_eq!(
            ctx.evaluate("r").await.unwrap(),
            Value::String("pending".into())
        );
        ctx.run_event_loop().await.unwrap();
        assert_eq!(
            ctx.evaluate("r").await.unwrap(),
            Value::String("rejected".into())
        );
    }

    #[tokio::test]
    async fn xhr_layers_on_fetch() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.evaluate(
            "globalThis.done = 0;
             var x = new XMLHttpRequest();
             x.open('GET', 'https://example.com/x');
             x.onerror = () => { done = 1; };
             x.send();",
        )
        .await
        .unwrap();
        ctx.run_event_loop().await.unwrap();
        assert_eq!(
            ctx.evaluate("done").await.unwrap(),
            Value::String("1".into())
        );
    }

    #[tokio::test]
    async fn fingerprint_shims_report_chrome_values() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // WebGL unmasked renderer comes from the profile (coherent with the rest).
        let renderer = ctx
            .evaluate(
                "(() => { const g = document.createElement('canvas').getContext('webgl'); \
                  const e = g.getExtension('WEBGL_debug_renderer_info'); \
                  return g.getParameter(e.UNMASKED_RENDERER_WEBGL); })()",
            )
            .await
            .unwrap();
        assert!(matches!(renderer, Value::String(s) if s.contains("ANGLE")));
        // Canvas produces a PNG data URL.
        assert!(matches!(
            ctx.evaluate("document.createElement('canvas').toDataURL().slice(0,15)").await.unwrap(),
            Value::String(s) if s.starts_with("data:image/png")
        ));
        // Chrome's 5-plugin PDF set.
        assert_eq!(
            ctx.evaluate("navigator.plugins.length").await.unwrap(),
            Value::String("5".into())
        );
        // Patched functions still look native.
        assert!(matches!(
            ctx.evaluate("document.createElement('canvas').getContext.toString()").await.unwrap(),
            Value::String(s) if s.contains("[native code]")
        ));
    }

    #[tokio::test]
    async fn stealth_window_chrome_and_hidden_internals() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // window.chrome present (its absence is a classic headless tell).
        assert_eq!(
            ctx.evaluate("typeof window.chrome + ',' + typeof chrome.loadTimes")
                .await
                .unwrap(),
            Value::String("object,function".into())
        );
        // Extended surface exists.
        assert_eq!(
            ctx.evaluate("typeof navigator.getBattery + ',' + typeof RTCPeerConnection")
                .await
                .unwrap(),
            Value::String("function,function".into())
        );
        // Engine internals are NOT enumerable on window...
        assert_eq!(
            ctx.evaluate("Object.keys(window).filter(k => k.indexOf('__') === 0).length")
                .await
                .unwrap(),
            Value::String("0".into())
        );
        // ...yet the Rust bridge helper is still callable by name.
        assert_eq!(
            ctx.evaluate("typeof __pt_runNextTimer").await.unwrap(),
            Value::String("function".into())
        );
    }

    #[tokio::test]
    async fn load_html_survives_a_throwing_script() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // First script throws; second must still run.
        let html = r#"<html><body><div id="x"></div>
            <script>throw new Error('boom');</script>
            <script>document.getElementById('x').textContent = 'ok';</script>
            </body></html>"#;
        ctx.load_html("https://example.com/", html).await.unwrap();
        assert_eq!(
            ctx.evaluate("document.getElementById('x').textContent")
                .await
                .unwrap(),
            Value::String("ok".into())
        );
    }

    #[tokio::test]
    async fn function_tostring_masking_survives_the_bypass() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // A patched function must read `[native code]` through *every* route
        // (incl. the `Function.prototype.toString.call(fn)` bypass), the patch
        // must hide itself, identity must be preserved, and genuine page
        // functions must NOT be masked.
        let v = ctx
            .evaluate(
                r#"(() => {
                    const FTS = Function.prototype.toString;
                    const isNat = s => /\{\s*\[native code\]\s*\}/.test(s);
                    const q = navigator.permissions.query;
                    function pageFn(){ return 1; }
                    const cv = document.createElement('canvas');
                    const gl = cv.getContext('webgl');
                    return String(
                        isNat(FTS.call(q)) &&
                        isNat(FTS.call(document.querySelector)) &&
                        (!gl || isNat(FTS.call(gl.getParameter))) &&
                        isNat(FTS.toString()) &&
                        FTS.name === 'toString' && FTS.length === 0 &&
                        !isNat(pageFn.toString())
                    );
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(v, Value::String("true".into()));
    }

    #[tokio::test]
    async fn engine_internals_are_hidden_from_all_introspection() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // Load a page so the __pt_* bridge + DOM are fully installed, then assert
        // none of them leak via any introspection route — while staying callable.
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        let v = ctx
            .evaluate(
                r#"(() => {
                    const hidden = k => typeof k === 'string' && (k.indexOf('__pt') === 0 || k === '__out');
                    const g = globalThis;
                    const viaNames = Object.getOwnPropertyNames(g).some(hidden);
                    const viaOwnKeys = Reflect.ownKeys(g).filter(k => typeof k === 'string').some(hidden);
                    const viaDesc = Object.getOwnPropertyDescriptor(g, '__pt_runNextTimer') !== undefined;
                    const viaHasOwn = g.hasOwnProperty('__pt_runNextTimer');
                    const callable = typeof __pt_runNextTimer === 'function';
                    return String(!viaNames && !viaOwnKeys && !viaDesc && !viaHasOwn && callable);
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(v, Value::String("true".into()));
    }

    #[tokio::test]
    async fn navigator_and_friends_are_real_prototype_instances() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // Real Chrome host objects carry no own enumerable props (all live on the
        // constructor's prototype), have the right prototype/constructor, and
        // satisfy `instanceof`. A plain object literal fails all of these.
        let v = ctx
            .evaluate(
                r#"(() => String(
                    Object.keys(navigator).length === 0 &&
                    Object.getOwnPropertyNames(navigator).length === 0 &&
                    Object.getPrototypeOf(navigator) === Navigator.prototype &&
                    navigator.constructor.name === 'Navigator' &&
                    navigator instanceof Navigator &&
                    navigator.webdriver === false &&
                    Object.getOwnPropertyDescriptor(navigator, 'webdriver') === undefined &&
                    screen instanceof Screen && Object.keys(screen).length === 0 &&
                    location instanceof Location && history instanceof History &&
                    navigator.hardwareConcurrency > 0 && navigator.plugins.length > 0
                ))()"#,
            )
            .await
            .unwrap();
        assert_eq!(v, Value::String("true".into()));
    }

    #[tokio::test]
    async fn timezone_is_coherent_between_date_and_intl() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // Date must agree with the profile timezone reported by Intl, with DST
        // applied — not V8's process (UTC) timezone. Default profile is
        // America/New_York: EDT (240) in summer, EST (300) in winter.
        let v = ctx
            .evaluate(
                r#"(() => {
                    const jul = new Date('2025-07-15T16:00:00Z');
                    const jan = new Date('2025-01-15T16:00:00Z');
                    return String(
                        Intl.DateTimeFormat().resolvedOptions().timeZone === 'America/New_York' &&
                        jul.getTimezoneOffset() === 240 && jan.getTimezoneOffset() === 300 &&
                        jul.getHours() === 12 && jan.getHours() === 11 &&
                        jul.toString().indexOf('GMT-0400 (Eastern Daylight Time)') >= 0 &&
                        jan.toString().indexOf('GMT-0500 (Eastern Standard Time)') >= 0
                    );
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(v, Value::String("true".into()));
    }

    #[tokio::test]
    async fn plugins_are_real_plugin_array_types() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // navigator.plugins/mimeTypes must be PluginArray/MimeTypeArray with
        // Plugin/MimeType entries — not plain Arrays (an instant tell).
        let v = ctx
            .evaluate(
                r#"(() => {
                    const T = Object.prototype.toString;
                    return String(
                        T.call(navigator.plugins) === '[object PluginArray]' &&
                        T.call(navigator.mimeTypes) === '[object MimeTypeArray]' &&
                        navigator.plugins instanceof PluginArray &&
                        navigator.mimeTypes instanceof MimeTypeArray &&
                        navigator.plugins.length === 5 &&
                        navigator.plugins[0] instanceof Plugin &&
                        T.call(navigator.plugins[0]) === '[object Plugin]' &&
                        navigator.mimeTypes[0] instanceof MimeType &&
                        [...navigator.plugins].length === 5 &&
                        navigator.connection.type === undefined
                    );
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(v, Value::String("true".into()));
    }

    #[tokio::test]
    async fn document_write_inserts_at_the_calling_script() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // Each document.write must land next to the script that called it (the
        // in-parse idiom that many sites — and bot tests — rely on), not clear
        // the page or append everywhere.
        let html = r#"<html><body>
            <span id="c1"><script>document.write('X=' + (1 + 2))</script></span>
            <div id="after"><script>document.write('<b>bold</b>')</script></div>
        </body></html>"#;
        ctx.load_html("https://example.com/", html).await.unwrap();
        let v = ctx
            .evaluate(
                r#"(() => String(
                    document.getElementById('c1').textContent.indexOf('X=3') >= 0 &&
                    document.querySelector('#after b').textContent === 'bold' &&
                    document.currentScript === null
                ))()"#,
            )
            .await
            .unwrap();
        assert_eq!(v, Value::String("true".into()));
    }

    #[tokio::test]
    async fn get_props_reports_real_enumerable_flags() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // Runtime.getProperties must report the true `enumerable` flag: an array's
        // `length` is non-enumerable. Reporting it as enumerable made Puppeteer's
        // query iterator (page.$/$$/$eval), which stops when a batch yields 0
        // enumerable properties, loop forever.
        let v = ctx
            .evaluate(
                r#"(() => {
                    const w = __pt_wrap([10, 20], false);
                    const props = __pt_getProps(w.objectId);
                    const len = props.find(p => p.name === 'length');
                    const i0 = props.find(p => p.name === '0');
                    return String(!!len && len.enumerable === false && !!i0 && i0.enumerable === true);
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(v, Value::String("true".into()));
    }

    #[tokio::test]
    async fn css_selectors_operators_and_combinators() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        let html = r#"<html><body>
            <nav><ul><li><a id="a1" href="/api/x" class="btn primary" data-role="link">A</a></li></ul></nav>
            <div class="parent"><span class="child" title="foo bar">C</span></div>
            <a id="a2" href="/home">H</a>
        </body></html>"#;
        ctx.load_html("https://example.com/", html).await.unwrap();
        let v = ctx
            .evaluate(
                r#"(() => {
                    const q = s => document.querySelector(s);
                    const a1 = document.getElementById('a1');
                    const child = document.querySelector('.child');
                    return String(
                        // attribute operators (were broken: split on first '=')
                        q('a[href^="/api"]') === a1 &&
                        q('[class*="prim"]') === a1 &&
                        q('a[href$="/home"]').id === 'a2' &&
                        q('[data-role~="link"]') === a1 &&
                        document.querySelectorAll('a[href^="/"]').length === 2 &&
                        // descendant + child combinators in query
                        q('nav ul a').id === 'a1' &&
                        q('nav > ul > li > a').id === 'a1' &&
                        // matches()/closest() with combinators (were ignored)
                        a1.matches('nav a') === true &&
                        a1.matches('div a') === false &&
                        child.matches('.parent .child') === true &&
                        child.matches('.parent > .child') === true &&
                        child.closest('.parent') !== null &&
                        a1.closest('nav') !== null
                    );
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(v, Value::String("true".into()));
    }
}
