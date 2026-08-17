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
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nokk_net::{
    Client, ClientConfig, FingerprintClient, HttpClient, NetError, Request, SessionJar, StubClient,
};
use nokk_pool::{IsolatePool, PoolError};
use nokk_stealth::StealthProfile;
use serde_json::Value;

// Re-export the types callers commonly need, so depending on `nokk`
// is sufficient to configure and drive an engine.
pub use nokk_net::{CookieRecord, ProxyConfig, ProxyScheme, Response as HttpResponse};
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
    #[error("session store error: {0}")]
    Session(String),
    #[error("no such frame: {0}")]
    NoSuchFrame(u32),
}

/// Top-level engine configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub pool: PoolConfig,
    pub client: ClientConfig,
    pub stealth: StealthProfile,
    /// Use the real (temporary, non-fingerprinted) HTTP client instead of the
    /// stub. `false` keeps requests offline — the default so tests never touch
    /// the network implicitly.
    pub use_real_network: bool,
    /// Directory in which named sessions persist their cookie jars. `None`
    /// disables on-disk persistence — named sessions are still isolated and
    /// shared by name for the engine's lifetime, just not saved across runs.
    pub session_store: Option<PathBuf>,
    /// Drop subresource requests (external scripts, `fetch`/XHR) to known
    /// ad/analytics/tracker domains so they never load or run — trimming the
    /// passive-fingerprinting surface. On by default. Anti-bot vendors are
    /// deliberately *not* on the list (they must run to hand out a token).
    pub block_trackers: bool,
    /// Give each browser context its own coherent fingerprint. When on, a
    /// context's identity (the Puppeteer browser-context id the CDP layer passes
    /// through) deterministically selects one of the [`nokk_stealth::FingerprintProfile`]
    /// presets, driving *both* its JS environment and its TLS emulation OS so the
    /// two never contradict. Off by default: every context uses [`Self::stealth`],
    /// which keeps runs deterministic. The default (empty-identity) context always
    /// uses [`Self::stealth`] so the shared default client stays coherent.
    pub rotate_fingerprint: bool,
    /// Derive a context's timezone and locale from its proxy's exit IP, so the
    /// reported `Intl` timezone / `navigator.languages` match where the traffic
    /// actually comes from (a mismatch is a documented tell). Off by default; it
    /// costs one geolocation request per distinct proxy (cached thereafter), made
    /// through that proxy so it looks like ordinary page traffic. Best-effort — a
    /// failed lookup keeps the profile's default zone. No effect on contexts
    /// without a proxy.
    pub geoip_timezone: bool,
    /// Chrome major version to emulate across both layers — the TLS/HTTP
    /// fingerprint and the JS UA / `userAgentData`. Defaults to current stable
    /// ([`nokk_net::DEFAULT_CHROME_MAJOR`]); set it to match, e.g., the browser a
    /// reused `cf_clearance` was minted under. Bounded by what wreq-util ships (an
    /// unavailable version falls back to the default).
    pub chrome_major: u32,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            pool: PoolConfig::default(),
            client: ClientConfig::default(),
            stealth: StealthProfile::default(),
            use_real_network: false,
            session_store: None,
            block_trackers: true,
            rotate_fingerprint: false,
            geoip_timezone: false,
            chrome_major: nokk_net::DEFAULT_CHROME_MAJOR,
        }
    }
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
    /// Drop subresource requests to tracker/ad/analytics domains (see
    /// [`EngineConfig::block_trackers`]).
    block_trackers: bool,
    /// Directory where named session jars are persisted (`None` = in-memory only).
    session_store: Option<PathBuf>,
    /// Shared, named session cookie jars — one per session name, loaded from the
    /// store on first use and the source of truth persisted back to disk.
    sessions: Mutex<HashMap<String, Arc<SessionJar>>>,
    stealth: StealthProfile,
    /// JS run in every new context before any page script: the spoofed
    /// `navigator`/`window`/`screen` environment. Built once from the default
    /// profile; used for the default context and whenever rotation is off.
    bootstrap: String,
    /// Give each browser context a coherent per-identity fingerprint (see
    /// [`EngineConfig::rotate_fingerprint`]).
    rotate_fingerprint: bool,
    /// Derive each context's timezone/locale from its proxy's exit IP (see
    /// [`EngineConfig::geoip_timezone`]).
    geoip_timezone: bool,
    /// Chrome major every context emulates (JS side); rotated presets are
    /// re-versioned to it so they stay coherent with the TLS emulation.
    chrome_major: u32,
    /// Rendered bootstraps, keyed by `(profile, geo)`, built lazily and cached so
    /// contexts sharing an identity+proxy don't re-render the same ~KB of JS.
    bootstrap_cache: Mutex<HashMap<String, String>>,
    /// Exit-IP geolocation per proxy (the result, incl. a cached miss), so the
    /// lookup runs at most once per distinct proxy.
    geo_cache: Mutex<HashMap<String, Option<nokk_net::GeoInfo>>>,
}

impl EngineInner {
    /// The client for a context with a given identity `key` and optional `proxy`.
    /// An empty key (the default browser context) or the stub network always uses
    /// the shared default client. Otherwise the client is built once per key and
    /// pooled — so each identity gets its *own* cookie jar (Puppeteer browser
    /// contexts are isolated even when they share, or omit, a proxy).
    fn client_for(
        &self,
        key: &str,
        proxy: Option<ProxyConfig>,
        emulation_os: Option<nokk_net::EmulationOs>,
    ) -> Result<Client, EngineError> {
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
        // `emulation_os` is a deterministic function of `key` (the identity), so a
        // pooled client for a key never disagrees with a later lookup's OS.
        if let Some(os) = emulation_os {
            cfg.emulation_os = os;
        }
        let client = Client::Fingerprint(FingerprintClient::new(&cfg)?);
        let mut pool = self.client_pool.lock().unwrap_or_else(|e| e.into_inner());
        Ok(pool.entry(key.to_string()).or_insert(client).clone())
    }

    /// The rotated fingerprint profile a context `identity` should present, or
    /// `None` when it should use the engine default. Rotation is opt-in, and the
    /// default (empty-identity) context always uses the default so its shared
    /// client's TLS OS stays coherent with its JS profile. The mapping is a stable
    /// hash of the identity, so a given browser context is the same machine across
    /// runs.
    fn rotated_profile(&self, identity: &str) -> Option<nokk_stealth::FingerprintProfile> {
        if !self.rotate_fingerprint || identity.is_empty() {
            return None;
        }
        Some(nokk_stealth::FingerprintProfile::from_seed(identity_seed(
            identity,
        )))
    }

    /// The TLS emulation OS for a rotated `profile` (`None` → the default client's
    /// OS is used unchanged).
    fn emulation_os_of(
        profile: Option<nokk_stealth::FingerprintProfile>,
    ) -> Option<nokk_net::EmulationOs> {
        profile.map(|p| emulation_os_for(&p.stealth()))
    }

    /// The per-context bootstrap JS for a rotated `profile` (or the engine default
    /// when `None`), with its timezone/locale overridden to `geo` when present.
    /// Built once per `(profile, geo)` and cached — contexts sharing an
    /// identity+proxy get the same rendered script.
    fn context_bootstrap(
        &self,
        profile: Option<nokk_stealth::FingerprintProfile>,
        geo: Option<&nokk_net::GeoInfo>,
    ) -> String {
        // Fast path: the prebuilt default when neither rotation nor geo applies.
        if profile.is_none() && geo.is_none() {
            return self.bootstrap.clone();
        }
        let key = format!(
            "{}|{}",
            match profile {
                Some(p) => format!("{p:?}"),
                None => "default".to_string(),
            },
            match geo {
                Some(g) => format!("{}/{}", g.timezone, g.country_code),
                None => "-".to_string(),
            },
        );
        if let Some(b) = self
            .bootstrap_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return b.clone();
        }
        let base = profile
            .map(|p| p.stealth().with_chrome_major(self.chrome_major))
            .unwrap_or_else(|| self.stealth.clone());
        let stealth = match geo {
            Some(g) => nokk_stealth::apply_geo(&base, &g.timezone, &g.country_code),
            None => base,
        };
        let built = build_bootstrap(&stealth);
        let mut cache = self
            .bootstrap_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cache.entry(key).or_insert(built).clone()
    }

    /// The exit-IP geolocation for a context's `proxy_key`, or `None` when geoIP is
    /// off, there's no proxy, or the network is stubbed. Looked up once per proxy
    /// (through `client`, so the request travels that proxy) and cached — including
    /// a miss, so a failing proxy isn't re-probed on every context.
    async fn geo_for(&self, proxy_key: &str, client: &Client) -> Option<nokk_net::GeoInfo> {
        if !self.geoip_timezone || !self.use_real_network || proxy_key.is_empty() {
            return None;
        }
        if let Some(cached) = self
            .geo_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(proxy_key)
        {
            return cached.clone();
        }
        let result = self.geo_lookup(client).await;
        self.geo_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(proxy_key.to_string())
            .or_insert(result)
            .clone()
    }

    /// One best-effort geolocation request through `client` (hence its proxy).
    async fn geo_lookup(&self, client: &Client) -> Option<nokk_net::GeoInfo> {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("User-Agent".to_string(), self.stealth.user_agent.clone());
        let req = Request {
            method: "GET".into(),
            url: nokk_net::GEO_LOOKUP_URL.to_string(),
            headers,
            body: None,
            kind: nokk_net::RequestKind::Xhr,
            user_activated: false,
        };
        match client.send(req).await {
            Ok(resp) => nokk_net::parse_geo(&resp.body),
            Err(e) => {
                tracing::debug!(error = %e, "geoip lookup failed; keeping default timezone");
                None
            }
        }
    }

    /// Filesystem path for a named session's jar, or `None` when sessions aren't
    /// persisted or the name has no filesystem-safe form.
    fn session_path(&self, name: &str) -> Option<PathBuf> {
        let store = self.session_store.as_ref()?;
        let safe = sanitize_session_name(name)?;
        Some(store.join(format!("{safe}.json")))
    }

    /// Get-or-load the shared jar for a named session. On first use it is loaded
    /// from disk (if a store is configured), so a warmed session resumes with its
    /// cookies intact; subsequent contexts of the same name share the jar.
    fn session_jar(&self, name: &str) -> Result<Arc<SessionJar>, EngineError> {
        if let Some(j) = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
        {
            return Ok(j.clone());
        }
        // Load from disk outside the lock (I/O), then re-check on insert so two
        // first-users of the same session converge on one jar.
        let jar = match self.session_path(name) {
            Some(path) => Arc::new(
                SessionJar::load_file(&path)
                    .map_err(|e| EngineError::Session(format!("load `{name}`: {e}")))?,
            ),
            None => Arc::new(SessionJar::new()),
        };
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        Ok(map.entry(name.to_string()).or_insert(jar).clone())
    }

    /// Build (once, then pooled) a client whose cookie jar *is* the named session
    /// jar, so its cookies accumulate in the shared, persistable store.
    fn client_for_session(
        &self,
        name: &str,
        jar: Arc<SessionJar>,
        proxy: Option<ProxyConfig>,
        emulation_os: Option<nokk_net::EmulationOs>,
    ) -> Result<Client, EngineError> {
        if !self.use_real_network {
            return Ok(self.client.clone());
        }
        let key = format!("session:{name}");
        if let Some(c) = self
            .client_pool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return Ok(c.clone());
        }
        let mut cfg = self.client_config.clone();
        cfg.proxy = proxy;
        if let Some(os) = emulation_os {
            cfg.emulation_os = os;
        }
        let client = Client::Fingerprint(FingerprintClient::with_session(&cfg, Some(jar))?);
        let mut pool = self.client_pool.lock().unwrap_or_else(|e| e.into_inner());
        Ok(pool.entry(key).or_insert(client).clone())
    }

    /// Persist a named session's jar to the store now (best-effort; logs on
    /// failure). A no-op when the session isn't persisted or not yet loaded.
    fn save_session_blocking(&self, name: &str) {
        let Some(path) = self.session_path(name) else {
            return;
        };
        let Some(jar) = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned()
        else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = jar.save_file(&path) {
            tracing::warn!(session = name, error = %e, "failed to persist session jar");
        }
    }
}

/// Restrict a session name to a safe single-path-segment filename — no directory
/// separators or `..`, so a name coming from a CDP client can't escape the store.
/// Returns `None` when nothing usable remains.
fn sanitize_session_name(name: &str) -> Option<String> {
    let mapped: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = mapped.trim_matches('.'); // reject "", ".", ".." and leading dots
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Pool key for a proxy (used by [`Engine::new_context_with_proxy`] to share one
/// client among contexts that route through the same proxy).
/// The TLS emulation OS that matches a JS stealth profile, derived from its
/// Client-Hints platform, so the ClientHello and the User-Agent agree.
fn emulation_os_for(profile: &StealthProfile) -> nokk_net::EmulationOs {
    match profile.ua_platform.as_str() {
        "Windows" => nokk_net::EmulationOs::Windows,
        "macOS" => nokk_net::EmulationOs::Mac,
        _ => nokk_net::EmulationOs::Linux,
    }
}

/// The full per-context bootstrap JS for a stealth `profile`, in dependency order:
/// the stealth environment (navigator/window/screen/Intl/timers/fetch), then the
/// DOM runtime (document/Element/Event…), then the fingerprint hardening layer
/// (which patches HTMLElement.prototype + navigator, so it must run after both),
/// and last the remaining platform surface — it only fills names nothing else
/// defined, so everything real has to exist before it looks.
fn build_bootstrap(profile: &StealthProfile) -> String {
    let base = format!(
        "{}\n{}\n{}\n{}",
        nokk_stealth::bootstrap_script(profile),
        nokk_dom::runtime_js(),
        nokk_stealth::fingerprint_script(profile),
        nokk_stealth::web_surface_script(),
    );
    // Diagnostic only, and last so it wraps a finished surface. Reading
    // `__pt_probeLog()` afterwards says what the page asked us and what we said.
    match std::env::var("NOKK_TRACE_PROBES").ok().as_deref() {
        Some("1") | Some("true") => format!("{base}\n{}", nokk_stealth::probe_tracer_script()),
        _ => base,
    }
}

/// A stable 64-bit seed (FNV-1a) for a context identity, so a given browser
/// context maps to the same rotated fingerprint profile every run.
fn identity_seed(s: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for b in s.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

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
    pub fn new(mut config: EngineConfig) -> Result<Self, EngineError> {
        // Emulate one Chrome major across both layers: the TLS/HTTP fingerprint and
        // the JS UA / userAgentData. Re-version the default stealth profile to match
        // so the ClientHello and the UA never disagree.
        config.client.chrome_major = config.chrome_major;
        config.stealth = config.stealth.with_chrome_major(config.chrome_major);
        // Keep the TLS/HTTP emulation OS coherent with the JS profile's OS, so the
        // ClientHello (JA3/JA4) never contradicts the User-Agent.
        config.client.emulation_os = emulation_os_for(&config.stealth);
        if let Some(dir) = &config.session_store {
            std::fs::create_dir_all(dir).map_err(|e| {
                EngineError::Session(format!("create store `{}`: {e}", dir.display()))
            })?;
        }
        let pool = IsolatePool::new(config.pool);
        let client = if config.use_real_network {
            Client::Fingerprint(FingerprintClient::new(&config.client)?)
        } else {
            Client::Stub(StubClient::new(config.client.clone()))
        };
        // The default context's bootstrap (used whenever rotation is off).
        let bootstrap = build_bootstrap(&config.stealth);
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
                block_trackers: config.block_trackers,
                client_pool: Mutex::new(HashMap::new()),
                session_store: config.session_store,
                sessions: Mutex::new(HashMap::new()),
                stealth: config.stealth,
                bootstrap,
                rotate_fingerprint: config.rotate_fingerprint,
                geoip_timezone: config.geoip_timezone,
                chrome_major: config.chrome_major,
                bootstrap_cache: Mutex::new(HashMap::new()),
                geo_cache: Mutex::new(HashMap::new()),
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
        let profile = self.inner.rotated_profile(&identity);
        let geo_key = proxy.as_ref().map(proxy_key).unwrap_or_default();
        let client =
            self.inner
                .client_for(&identity, proxy, EngineInner::emulation_os_of(profile))?;
        let geo = self.inner.geo_for(&geo_key, &client).await;
        let bootstrap = self.inner.context_bootstrap(profile, geo.as_ref());
        self.build_context(client, None, bootstrap).await
    }

    /// Open a context bound to a named, persistent session. Its cookie jar is
    /// loaded from the session store on first use and shared by every context of
    /// the same `name`; it is saved back to disk when such a context closes (and
    /// on demand via [`save_session`](Self::save_session)). Warm a session once
    /// (log in, clear a challenge) and resume it later — even in a fresh process —
    /// instead of re-solving each run. With no session store configured the jar
    /// is in-memory only (still shared by name for the engine's lifetime).
    pub async fn new_context_with_session(
        &self,
        name: String,
        proxy: Option<ProxyConfig>,
    ) -> Result<BrowserContext, EngineError> {
        let profile = self.inner.rotated_profile(&name);
        let geo_key = proxy.as_ref().map(proxy_key).unwrap_or_default();
        let jar = self.inner.session_jar(&name)?;
        let client = self.inner.client_for_session(
            &name,
            jar,
            proxy,
            EngineInner::emulation_os_of(profile),
        )?;
        let geo = self.inner.geo_for(&geo_key, &client).await;
        let bootstrap = self.inner.context_bootstrap(profile, geo.as_ref());
        self.build_context(client, Some(name), bootstrap).await
    }

    /// Shared tail of context creation: acquire a slot, place on the least-loaded
    /// worker, build the V8 context, and wrap it with an optional session name.
    async fn build_context(
        &self,
        client: Client,
        session: Option<String>,
        bootstrap: String,
    ) -> Result<BrowserContext, EngineError> {
        let permit = self.inner.pool.acquire_context().await?;
        let worker = self.inner.pool.pick_worker();
        let load = self.inner.pool.register_context(worker);
        let boot = bootstrap.clone();
        let index = self
            .inner
            .pool
            .dispatch(worker, move |iso| iso.create_context(&boot))
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
            started: std::time::Instant::now(),
            timings_sent: std::sync::Mutex::new(0),
            sockets: tokio::sync::Mutex::new(PageSockets::new()),
            network_tx: std::sync::Mutex::new(None),
            frames: std::sync::Mutex::new(HashMap::new()),
            workers: std::sync::Mutex::new(HashMap::new()),
            bootstrap,
            frame_init_scripts: std::sync::Mutex::new(Vec::new()),
            init_scripts: std::sync::Mutex::new(Vec::new()),
            next_timer_at: std::sync::Mutex::new(None),
            session,
            _permit: permit,
            _load: load,
        })
    }

    /// Persist a named session's cookie jar to the store immediately (in addition
    /// to the automatic save when a session context closes). No-op without a
    /// configured store or if the session hasn't been opened this run.
    pub fn save_session(&self, name: &str) {
        self.inner.save_session_blocking(name);
    }

    /// Import a `Set-Cookie`-style cookie into a named session, as if `origin`
    /// had sent it — the basis for reusing a `cf_clearance` harvested elsewhere.
    /// The session's client sends it on subsequent requests (cookie replay only
    /// works if this engine's fingerprint + exit IP match the harvester's).
    pub fn import_session_cookie(
        &self,
        name: &str,
        set_cookie: &str,
        origin: &str,
    ) -> Result<(), EngineError> {
        self.inner
            .session_jar(name)?
            .add_set_cookie(set_cookie, origin);
        Ok(())
    }

    /// Snapshot a named session's currently-held cookies — for inspection or CDP
    /// `Network.getCookies`. Empty if the session isn't loaded.
    pub fn session_cookies(&self, name: &str) -> Vec<CookieRecord> {
        self.inner
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .map(|j| j.snapshot())
            .unwrap_or_default()
    }

    /// The coherent stealth profile a context with this `identity` will present:
    /// the engine default, or — with [`EngineConfig::rotate_fingerprint`] on — the
    /// rotated per-identity preset. Its JS `ua_platform` and the TLS emulation OS
    /// agree by construction. Exposed so callers (and the CDP layer) can see the
    /// machine a given browser context impersonates.
    pub fn stealth_for_identity(&self, identity: &str) -> StealthProfile {
        self.inner
            .rotated_profile(identity)
            .map(|p| p.stealth())
            .unwrap_or_else(|| self.inner.stealth.clone())
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
            kind: nokk_net::RequestKind::Document,
            // A one-shot fetch is someone asking for an address, like typing one.
            user_activated: true,
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
    /// When this context started, and how many of its requests have been handed
    /// to the page as Resource Timing entries.
    started: std::time::Instant,
    timings_sent: std::sync::Mutex<usize>,
    /// Name of the persistent session this context belongs to, if any. On drop
    /// its cookie jar is flushed to the session store.
    session: Option<String>,
    /// The page's live `WebSocket`s (docs/websockets.md).
    sockets: tokio::sync::Mutex<PageSockets>,
    /// Where to forward each completed request, when a CDP session is attached
    /// and wants `Network.*` events.
    network_tx: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<NetworkRecord>>>,
    /// `<iframe>`s the page has connected, by the id its DOM assigned. Each is a
    /// V8 context of its own on this same worker — a real browsing context, which
    /// is what a widget means when it polls `iframe.contentWindow`.
    frames: std::sync::Mutex<HashMap<u32, FrameState>>,
    /// Live workers, by the id the page's DOM assigned. A worker is a context of
    /// its own — a different global object, not a window with pieces removed —
    /// which is exactly what code that fingerprints inside one is checking.
    workers: std::sync::Mutex<HashMap<(usize, u32), WorkerState>>,
    /// This context's bootstrap, kept so a child frame is built with the same
    /// stealth profile — an iframe of this browser is the same machine.
    bootstrap: String,
    /// Scripts to run in every *new* frame before its own document does, which is
    /// what `Page.addScriptToEvaluateOnNewDocument` means in Chrome — it applies
    /// to the whole frame tree, not just the top document.
    frame_init_scripts: std::sync::Mutex<Vec<String>>,
    /// The same, for this page's own document. "On new document" means *before*
    /// the document's own scripts — that is the whole point of the API, and what
    /// every stealth patch and instrumentation hook depends on. Running them after
    /// the page had already executed made them useless for anything that has to be
    /// in place first.
    init_scripts: std::sync::Mutex<Vec<String>>,
    /// When this page's earliest pending timer comes due, as of the last turn of
    /// the event loop. `None` means nothing is pending. Timers wait out their real
    /// delays now, so a page only advances while something drives it — this is how
    /// the driver knows *when* to come back rather than polling a live page twenty
    /// times a second, or leaving its `setInterval` frozen between commands.
    next_timer_at: std::sync::Mutex<Option<std::time::Instant>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _load: nokk_pool::ContextLoadGuard,
}

/// What a caller outside the engine can know about a live frame.
#[derive(Debug, Clone)]
pub struct FrameInfo {
    /// Stable for the frame's lifetime; the CDP layer builds its frame id from it.
    pub id: u32,
    pub url: String,
    pub origin: String,
}

/// A live `<iframe>`: its own V8 context on the parent's worker, plus where it
/// came from. `origin` decides what the parent may touch — a cross-origin frame
/// exposes only `postMessage`, as in a browser.
#[derive(Debug, Clone)]
struct FrameState {
    index: usize,
    url: String,
    origin: String,
    /// The viewport last handed to the child. A frame's window is the size of
    /// its `<iframe>`, and the element gets its size from styles that are not
    /// applied yet when the frame is first connected — so it is re-checked as
    /// the page settles, the way a browser resizes a frame that changed.
    viewport: (f64, f64),
}

/// A live worker: its own V8 context on the page's worker thread, and the URL its
/// own requests resolve against. A worker built from a blob has no document to
/// resolve against, so it keeps the page's base — which is what a browser does
/// with the blob's origin.
#[derive(Debug, Clone)]
struct WorkerState {
    index: usize,
    url: String,
    fetch_base: String,
}

/// One page's open sockets, plus the single queue everything they produce lands
/// on. Sharing one queue (rather than a receiver per socket) is what lets the
/// event loop drain every socket in arrival order, and wait on *any* of them.
struct PageSockets {
    open: HashMap<u32, nokk_net::WsHandle>,
    tx: tokio::sync::mpsc::UnboundedSender<(u32, nokk_net::WsEvent)>,
    rx: tokio::sync::mpsc::UnboundedReceiver<(u32, nokk_net::WsEvent)>,
}

impl PageSockets {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            open: HashMap::new(),
            tx,
            rx,
        }
    }
}

impl Drop for BrowserContext {
    fn drop(&mut self) {
        // Flush this context's session jar to disk so a warmed session (cookies
        // gathered during its navigations) survives the context closing — the
        // "warm up once, resume later" path. Best-effort; a no-op for non-session
        // or non-persisted contexts.
        if let Some(name) = self.session.take() {
            self.engine.save_session_blocking(&name);
        }
        // Dispose the V8 context on its owning worker so the isolate reclaims it.
        // Without this, create/close churn (every Puppeteer newPage/close) grows
        // the isolate's context table unbounded — a slow leak on a busy server.
        // Fire-and-forget: there's no caller to return to from Drop.
        // The page's frames and workers are contexts on the same isolate, and
        // nothing else will ever reach them once the page is gone — a page that
        // opened either would otherwise leak them on every close.
        let mut indices = vec![self.index];
        if let Ok(frames) = self.frames.lock() {
            indices.extend(frames.values().map(|s| s.index));
        }
        if let Ok(workers) = self.workers.lock() {
            indices.extend(workers.values().map(|s| s.index));
        }
        for index in indices {
            self.engine
                .pool
                .dispatch_detached(self.worker, move |iso| iso.dispose_context(index));
        }
    }
}

/// One network request the engine performed on a page's behalf. Because page JS
/// calls into the engine's Rust network layer, *every* `fetch`/`XMLHttpRequest`
/// and subresource script flows through here — this is the interception point.
#[derive(Debug, Clone)]
pub struct NetworkRecord {
    /// Stable per-request identifier, shared by every CDP event about it.
    pub request_id: String,
    /// Response headers, for CDP `Network.responseReceived` (empty when the
    /// request never got a response).
    pub headers: std::collections::BTreeMap<String, String>,
    pub method: String,
    pub url: String,
    /// HTTP status, or `0` when the request never got a response (DNS failure,
    /// connection reset, a blocked subresource) — the attempt is still logged so
    /// an audit of "what did this page try to contact" is complete.
    pub status: u16,
    /// `"document"`, `"script"`, or `"fetch"` (covers XHR, layered on fetch).
    pub resource_type: String,
    pub body: Vec<u8>,
    /// What was sent *up*. A challenge is an exchange, and half of it was
    /// invisible: every driver reads `postData`, and so does anyone trying to
    /// find out why an answer was rejected.
    pub request_body: Vec<u8>,
    /// Milliseconds from this context's start to the moment the request went
    /// out, and how long it took. Resource Timing is built from these, and a
    /// page that reports no timings is a page that never loaded anything.
    pub started_ms: f64,
    pub duration_ms: f64,
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
        self.navigate_from(url, None).await
    }

    /// The same, for a page that navigated itself. `referrer` is the document
    /// that did it — a browser sends it, marks the request same-origin, and does
    /// *not* claim a human gesture. Cloudflare's interstitial finishes by
    /// reloading itself, so this is the difference between landing on the site
    /// and being handed the challenge again.
    pub async fn navigate_from(
        &self,
        url: &str,
        referrer: Option<&str>,
    ) -> Result<(), EngineError> {
        // Follow client-side `<meta http-equiv="refresh">` redirects, not just the
        // HTTP ones the network layer already follows. Some gates (e.g. Google's
        // "enable JavaScript" handoff) bounce through a meta-refresh that also sets
        // a cookie; the in-session jar carries the cookie across hops, so following
        // the chain lands on the real page. Capped to avoid a refresh loop.
        const MAX_META_HOPS: usize = 6;
        // `about:blank` is a document, not a request. Clients navigate to it
        // routinely — Puppeteer's `newPage()` opens one — and sending it to the
        // network layer produced "URI scheme is not allowed" instead of a page.
        if url.is_empty() || url == "about:blank" {
            return self
                .load_html("about:blank", "<html><head></head><body></body></html>")
                .await;
        }
        let mut current = url.to_string();
        for _ in 0..MAX_META_HOPS {
            // Use the post-redirect URL as the document base, so `window.location`
            // and relative-URL resolution reflect where we actually landed.
            let (final_url, html) = self
                .fetch_text_from(&current, "document", referrer)
                .await?;
            self.load_html(&final_url, &html).await?;
            match self.meta_refresh_target(&final_url).await {
                Some(next) if next != final_url && next != current => current = next,
                _ => return Ok(()),
            }
        }
        Ok(())
    }

    /// The absolute URL a `<meta http-equiv="refresh" content="N;url=…">` in the
    /// current document points to (resolved against `base`), or `None` if there is
    /// no such tag or it only reloads the same page.
    async fn meta_refresh_target(&self, base: &str) -> Option<String> {
        let js = r#"(() => {
          const metas = document.getElementsByTagName('meta');
          for (let k = 0; k < metas.length; k++) {
            const m = metas[k];
            if ((m.getAttribute('http-equiv') || '').toLowerCase() !== 'refresh') continue;
            const c = m.getAttribute('content') || '';
            const i = c.toLowerCase().indexOf('url=');
            if (i < 0) continue;
            return c.slice(i + 4).trim().replace(/^['"]/, '').replace(/['"]$/, '');
          }
          return '';
        })()"#;
        match self.evaluate(js).await {
            Ok(Value::String(s)) if !s.is_empty() => resolve_url(base, &s),
            _ => None,
        }
    }

    /// Evaluate in one of this context's *sibling* V8 contexts on the same worker
    /// — an iframe's document lives in one of these (see [`Self::frames`]). The
    /// page's own context is [`Self::index`], so `eval_in(self.index, …)` is
    /// exactly [`Self::evaluate`].
    async fn eval_in(&self, index: usize, source: &str) -> Result<Value, EngineError> {
        let source = source.to_string();
        let out = self
            .engine
            .pool
            .dispatch(self.worker, move |iso| iso.eval(index, &source))
            .await?
            .map_err(EngineError::Js)?;
        Ok(Value::String(out))
    }

    /// Build the DOM from `html`, then run its scripts in document order and fire
    /// `DOMContentLoaded`/`load`. `base_url` resolves relative external script
    /// `src`s. Page scripts that throw are logged and skipped — a broken page
    /// script must not fail the load, matching browser behaviour.
    pub async fn load_html(&self, base_url: &str, html: &str) -> Result<(), EngineError> {
        // The outgoing document takes its workers with it.
        self.terminate_workers_of(None).await;
        if let Ok(mut b) = self.base_url.lock() {
            *b = base_url.to_string();
        }
        self.load_html_into(self.index, base_url, html).await?;
        // Timers and async continuations scheduled during load (and by the load
        // handlers) get their turn now — with the load-time patience for delays
        // the page actually asked for.
        self.run_event_loop_for_load().await?;
        Ok(())
    }

    /// [`Self::load_html`] against a chosen context — the same steps, so an
    /// iframe's document is built exactly the way the top-level one is (its own
    /// `location`, its own tree, its own scripts, its own lifecycle events).
    async fn load_html_into(
        &self,
        index: usize,
        base_url: &str,
        html: &str,
    ) -> Result<(), EngineError> {
        // Reflect the real URL into `window.location` before any script runs.
        if let Some(js) = location_setter(base_url) {
            let _ = self.eval_in(index, &js).await;
        }
        // Then the client's own "on new document" scripts, still before the
        // document exists — a frame gets its set from `apply_frame_ops`, the page
        // gets its own here. After the page's scripts would be too late to matter.
        if index == self.index {
            let init = self
                .init_scripts
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default();
            for src in init {
                if let Err(e) = self.eval_in(index, &src).await {
                    tracing::debug!(error = %e, "page init script threw");
                }
            }
        }
        let page = nokk_dom::parse(html);

        // Install the parsed tree as `document`.
        self.eval_in(index, &page.install_script()).await?;

        // Execute scripts in order against the live document. `idx` matches the
        // document-order script list the DOM runtime built, so `__pt_beginScript`
        // can point `document.currentScript` at the running node (document.write
        // positioning); `__pt_endScript` clears it afterward.
        for (idx, script) in page.scripts.iter().enumerate() {
            // A module is not a script with different syntax: it is parsed, linked
            // and evaluated as a graph, so it goes down its own path.
            if let nokk_dom::Script::InlineModule(code) | nokk_dom::Script::ExternalModule(code) =
                script
            {
                let inline = matches!(script, nokk_dom::Script::InlineModule(_));
                let _ = self
                    .eval_in(index, &format!("__pt_beginScript({idx})"))
                    .await;
                let outcome = if inline {
                    self.run_module(index, base_url, code.clone()).await
                } else {
                    match resolve_url(base_url, code) {
                        Some(abs) => match self.fetch_text(&abs, "script").await {
                            Ok((_, source)) => self.run_module(index, &abs, source).await,
                            Err(e) => Err(EngineError::Js(e.to_string())),
                        },
                        None => Err(EngineError::Js(format!("cannot resolve {code}"))),
                    }
                };
                if let Err(e) = outcome {
                    tracing::debug!(error = %e, "page module threw");
                }
                let _ = self.eval_in(index, "__pt_endScript()").await;
                continue;
            }
            let code = match script {
                nokk_dom::Script::Inline(code) => code.clone(),
                nokk_dom::Script::External(src) => match resolve_url(base_url, src) {
                    Some(abs) => {
                        // Don't fetch or run tracker/analytics scripts — the point
                        // of the blocklist is that they never execute.
                        if self.engine.block_trackers && nokk_net::is_blocked_url(&abs) {
                            self.record("GET", &abs, "script", 0, &[]);
                            continue;
                        }
                        match self.fetch_text(&abs, "script").await {
                            // `sourceURL` — не отладочная мелочь: без него каждый
                            // кадр стека выглядит как `<anonymous>`, тогда как в
                            // браузере там адрес скрипта. `new Error().stack`
                            // читают, и форма стека — часть отпечатка.
                            Ok((_, code)) => format!("{code}\n//# sourceURL={abs}"),
                            Err(e) => {
                                tracing::warn!(url = %abs, error = %e, "external script fetch failed");
                                continue;
                            }
                        }
                    }
                    None => {
                        tracing::warn!(src, "could not resolve external script URL");
                        continue;
                    }
                },
                // Handled above, before this match.
                nokk_dom::Script::InlineModule(_) | nokk_dom::Script::ExternalModule(_) => continue,
            };
            let _ = self
                .eval_in(index, &format!("__pt_beginScript({idx})"))
                .await;
            if let Err(e) = self.eval_in(index, &code).await {
                tracing::debug!(error = %e, "page script threw");
            }
            let _ = self.eval_in(index, "__pt_endScript()").await;
        }

        // Fire lifecycle events. Draining the loop afterwards is the *caller's*
        // job: for the top-level page that is `load_html` below, and for a frame
        // it is `pump_frames`, which gives it turns of its own. Pumping here would
        // mean a frame's load re-entering the parent's whole event loop.
        // Перед событиями загрузки: страница, читающая тайминги в `load`,
        // обязана увидеть уже полный список. Только своя страница: журнал
        // запросов один на контекст, и отдать его фрейму — значит и фрейму
        // солгать, и странице ничего не оставить.
        if index == self.index {
            self.flush_resource_timings(index).await;
        }
        self.eval_in(index, "__pt_finishLoad();").await?;
        Ok(())
    }

    /// Drive this context's event loop until it goes idle: alternately pump
    /// timers (on the isolate thread) and service the JS `fetch` queue (real
    /// network, on the tokio side, off the isolate thread), settling each Promise
    /// back in the isolate so resolved awaits can schedule more work. Returns the
    /// number of timer callbacks run. Bounded by a wall-clock deadline and a
    /// per-load fetch cap.
    ///
    /// Timers are due-time based, so "idle" now means *nothing due right now*.
    /// The loop will wait out a short chain of them (see `IDLE_WAIT_BUDGET`) and
    /// then return: a page with a long-running `setInterval` is never finished,
    /// and holding a CDP command hostage to it would be worse than returning and
    /// letting the server's periodic pump carry the page forward.
    pub async fn run_event_loop(&self) -> Result<u32, EngineError> {
        self.run_event_loop_waiting(IDLE_WAIT_BUDGET).await
    }

    /// [`Self::run_event_loop`] with a longer patience for timers, used while a
    /// document is loading: work deferred by a few hundred milliseconds is still
    /// part of the load, and a caller that just navigated is waiting anyway.
    async fn run_event_loop_for_load(&self) -> Result<u32, EngineError> {
        self.run_event_loop_waiting(LOAD_WAIT_BUDGET).await
    }

    /// The loop both of the above run. `idle_wait` is the *total* time it may
    /// spend waiting for timers that are not due yet — time spent doing nothing,
    /// as opposed to the deadline, which bounds the whole call.
    async fn run_event_loop_waiting(
        &self,
        idle_wait: std::time::Duration,
    ) -> Result<u32, EngineError> {
        const TIMER_CAP: u32 = 10_000;
        const MAX_FETCHES: usize = 200;
        const MAX_ROUNDS: usize = 2_000;
        /// How long an otherwise-idle round waits for a socket frame. Short on
        /// purpose: this keeps a CDP command from blocking for the whole budget
        /// just because the page holds a socket open.
        const SOCKET_IDLE_GRACE: std::time::Duration = std::time::Duration::from_millis(25);
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
        let mut waited = std::time::Duration::ZERO;
        // Due on the first round: a frame inserted by the document's own scripts
        // has been waiting since before this call started.
        let mut last_frame_pump = std::time::Instant::now() - FRAME_PUMP_EVERY;

        for _ in 0..MAX_ROUNDS {
            if std::time::Instant::now() >= deadline {
                break;
            }

            // 0. Timings first, before anything the page runs this round. A script
            //    that has just loaded reads the timing of its own <script> the
            //    moment it starts — Turnstile's loader puts `apiJsResourceTiming`
            //    into the config it posts to the widget — and flushing after the
            //    round meant the entry appeared one round too late: the key was
            //    simply absent from the message, where a browser always has it.
            if index == self.index {
                self.flush_resource_timings(index).await;
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

            // 2. Pull the I/O the JS queued — fetches and socket operations in one
            //    round trip, so adding sockets costs no extra worker dispatch.
            let qjson = self
                .engine
                .pool
                .dispatch(self.worker, move |iso| iso.eval(index, DRAIN_IO))
                .await?
                .map_err(EngineError::Js)?;
            let queues: Value = serde_json::from_str(&qjson).unwrap_or_default();
            let reqs: Vec<Value> = queues["fetch"].as_array().cloned().unwrap_or_default();
            let ws_ops: Vec<Value> = queues["ws"].as_array().cloned().unwrap_or_default();
            let frame_ops: Vec<Value> = queues["frames"].as_array().cloned().unwrap_or_default();
            let script_ops: Vec<Value> = queues["scripts"].as_array().cloned().unwrap_or_default();
            let nav_ops: Vec<Value> = queues["nav"].as_array().cloned().unwrap_or_default();
            let worker_ops: Vec<Value> = queues["workers"].as_array().cloned().unwrap_or_default();
            self.log_console("page", &queues);
            // How long until the page's next timer, straight from the same queue
            // the driver just pumped: -1 for "nothing pending".
            let next_timer_ms = queues["timers"].as_i64().unwrap_or(-1);
            self.note_next_timer(next_timer_ms);

            // 3. Sockets: apply what the page asked for, then hand it whatever the
            //    sockets have produced since the last round.
            self.apply_ws_ops(&base, &ws_ops).await;
            let delivered = self.deliver_ws_events(index).await?;

            // 4. Frames the page just connected get built now — that is cheap, and
            //    a widget polls `contentWindow` the instant it inserts one. Scripts
            //    it inserted run here too, before the round's fetches: everything
            //    after them usually depends on what they define.
            self.apply_frame_ops(&base, &frame_ops).await;
            self.apply_worker_ops(index, &base, &worker_ops).await;
            self.apply_script_ops(index, &base, &script_ops).await;

            // 5. The page asked to go somewhere. Only the last request counts —
            //    a script that assigns `location.href` twice in a turn ends up at
            //    the second address, as it would in a browser — and the loop stops
            //    here: everything below belongs to a document that no longer
            //    exists. The caller's next pump drives the new one.
            if let Some(op) = nav_ops.last() {
                if let Some(url) = op["url"].as_str() {
                    if index == self.index {
                        let to = url.to_string();
                        tracing::debug!(url = %to, "page navigated itself");
                        // Boxed: the loop is reached *from* `navigate`, so this
                        // is a recursive async call and needs an indirection.
                        let from = base.clone();
                        let from = (!from.is_empty() && from != "about:blank").then_some(from);
                        if let Err(e) = Box::pin(self.navigate_from(&to, from.as_deref())).await {
                            tracing::debug!(url = %to, error = %e, "self-navigation failed");
                        }
                        return Ok(total_timers);
                    }
                }
            }

            if index == self.index {
                self.flush_resource_timings(index).await;
            }

            let pumped_workers = self.pump_workers().await?;

            let busy = ran > 0
                || pumped_workers > 0
                || !worker_ops.is_empty()
                || !reqs.is_empty()
                || !ws_ops.is_empty()
                || !script_ops.is_empty()
                || delivered > 0;

            // 5. Perform each fetch off the isolate thread, then settle its
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

            // 6. Frames get a turn on a clock of their own, whether or not the page
            //    is busy. Gating this on the page being idle starved them outright:
            //    a page with any repeating timer is never idle, so a widget in an
            //    iframe never ran — and a widget that never answers is one its own
            //    watchdog reports as hung. Throttled because a frame pump costs a
            //    dispatch and an event-loop slice per frame, and paying that on
            //    every one of MAX_ROUNDS rounds turned one navigation into ten
            //    seconds.
            let mut frames_ran = 0;
            if self.has_frames()
                && last_frame_pump.elapsed() >= FRAME_PUMP_EVERY
                && std::time::Instant::now() < deadline
            {
                last_frame_pump = std::time::Instant::now();
                frames_ran = self.pump_frames().await?;
            }

            if busy || frames_ran > 0 || !frame_ops.is_empty() {
                continue;
            }

            // Nothing is runnable *right now*. If the page's next timer is close,
            // serve it — that is the load-critical `setTimeout` chain, and waiting
            // it out is the whole point of real delays. `idle_wait` is a budget for
            // the call, not per wait, so a page that keeps scheduling short timers
            // still returns instead of pinning the caller for the full deadline.
            if next_timer_ms >= 0 {
                let d = std::time::Duration::from_millis(next_timer_ms as u64);
                if waited + d <= idle_wait && std::time::Instant::now() + d < deadline {
                    waited += d;
                    tokio::time::sleep(d).await;
                    continue;
                }
            }

            // Idle — but an open socket means "not finished", only "nothing right
            // now". Wait briefly for a frame rather than spinning, and still return
            // promptly: continuous delivery is the caller's job (the CDP server
            // pumps periodically), not this call's.
            if !self.has_open_sockets().await {
                break;
            }
            if !self.await_ws_event(SOCKET_IDLE_GRACE).await {
                break;
            }
        }
        Ok(total_timers)
    }

    /// Every cookie this context's client holds, HttpOnly included — the jar the
    /// engine actually sends, not what the page can see. `urls` filters to the
    /// cookies that would be sent to those URLs (empty = everything), matching
    /// CDP `Network.getCookies`.
    ///
    /// This is the only way to export a warmed session (a `cf_clearance`, an
    /// Akamai `bm_s*`) to another process: `document.cookie` cannot see any of it.
    pub fn cookies(&self, urls: &[String]) -> Vec<CookieRecord> {
        let all = self.client.cookies();
        if urls.is_empty() {
            return all;
        }
        let targets: Vec<(String, String)> = urls
            .iter()
            .filter_map(|u| url::Url::parse(u).ok())
            .map(|u| {
                (
                    u.host_str().unwrap_or_default().to_ascii_lowercase(),
                    u.path().to_string(),
                )
            })
            .collect();
        all.into_iter()
            .filter(|c| {
                targets.iter().any(|(host, path)| {
                    let domain = c
                        .domain
                        .as_deref()
                        .unwrap_or_default()
                        .trim_start_matches('.');
                    // A domain cookie matches the host itself and any subdomain.
                    let host_ok = domain.is_empty()
                        || host == domain
                        || host.ends_with(&format!(".{domain}"));
                    let cookie_path = c.path.as_deref().unwrap_or("/");
                    let path_ok = path.starts_with(cookie_path);
                    host_ok && path_ok
                })
            })
            .collect()
    }

    /// Whether this page is holding any socket open. The event loop treats that
    /// as "not finished" and the CDP server as "keep pumping".
    pub async fn has_open_sockets(&self) -> bool {
        !self.sockets.lock().await.open.is_empty()
    }

    /// Register a script to run in every frame this page opens from now on,
    /// before that frame's own document scripts. Bounded so a page that keeps
    /// adding them cannot grow the list without limit.
    pub fn add_frame_init_script(&self, src: String) {
        if let Ok(mut v) = self.frame_init_scripts.lock() {
            if v.len() < 32 {
                v.push(src);
            }
        }
    }

    /// Run `src` in this page on every future navigation, before the document's
    /// own scripts. The caller keeps the list; the load applies it.
    pub fn add_init_script(&self, src: String) {
        if let Ok(mut v) = self.init_scripts.lock() {
            if v.len() < 32 {
                v.push(src);
            }
        }
    }

    /// Every live `<iframe>` on this page: the id its DOM assigned, the URL it
    /// loaded, and its origin. The CDP layer turns these into frame lifecycle
    /// events and per-frame execution contexts, which is what makes a frame
    /// visible to Puppeteer's `page.frames()` — and reachable by an evaluate.
    pub fn frame_list(&self) -> Vec<FrameInfo> {
        self.frames
            .lock()
            .map(|f| {
                let mut out: Vec<FrameInfo> = f
                    .iter()
                    .map(|(id, s)| FrameInfo {
                        id: *id,
                        url: s.url.clone(),
                        origin: s.origin.clone(),
                    })
                    .collect();
                out.sort_by_key(|f| f.id);
                out
            })
            .unwrap_or_default()
    }

    /// Evaluate inside one of this page's frames. `Err(NoSuchFrame)` if it has
    /// gone away — a frame outlives neither its element nor its page.
    pub async fn evaluate_in_frame(
        &self,
        frame_id: u32,
        script: &str,
    ) -> Result<Value, EngineError> {
        let index = self
            .frames
            .lock()
            .ok()
            .and_then(|f| f.get(&frame_id).map(|s| s.index))
            .ok_or(EngineError::NoSuchFrame(frame_id))?;
        self.eval_in(index, script).await
    }

    /// Deliver a mouse action at page coordinates, into whatever document owns
    /// that point. A frame is its own context with its own layout, so the point
    /// has to be handed down: hit-test here, and if it lands on an `<iframe>`,
    /// repeat inside that frame in its own coordinates. Turnstile's checkbox
    /// sits exactly there — an iframe in a closed shadow root — so without the
    /// descent there is nothing at those coordinates to click.
    pub async fn dispatch_mouse(
        &self,
        kind: &str,
        x: f64,
        y: f64,
        button: &str,
        clicks: i64,
    ) -> Result<bool, EngineError> {
        let mut frame: Option<u32> = None;
        let (mut fx, mut fy) = (x, y);
        // Frames nest; the bound is a guard against a cycle, not a real depth.
        for _ in 0..8 {
            let probe = format!("__pt_hitFrame({fx}, {fy})");
            let hit = match frame {
                None => self.evaluate(&probe).await?,
                Some(id) => self.evaluate_in_frame(id, &probe).await?,
            };
            let Some(text) = hit.as_str().filter(|s| !s.is_empty()) else {
                break;
            };
            let Ok(v) = serde_json::from_str::<Value>(text) else {
                break;
            };
            let (Some(id), Some(nx), Some(ny)) =
                (v["frame"].as_u64(), v["x"].as_f64(), v["y"].as_f64())
            else {
                break;
            };
            frame = Some(id as u32);
            fx = nx;
            fy = ny;
        }
        let js = format!(
            "__pt_mouse({}, {fx}, {fy}, {}, {clicks})",
            serde_json::to_string(kind).unwrap_or_else(|_| "\"\"".into()),
            serde_json::to_string(button).unwrap_or_else(|_| "\"left\"".into()),
        );
        let out = match frame {
            None => self.evaluate(&js).await?,
            Some(id) => self.evaluate_in_frame(id, &js).await?,
        };
        Ok(out.as_bool().unwrap_or(false))
    }

    /// Hand the page the Resource Timing entries for whatever it has fetched
    /// since last time. A browser fills this list as it loads; ours was empty,
    /// and `performance.getEntriesByType('resource').length === 0` after a real
    /// page load is not a browser at all — anti-bot code asks exactly that.
    async fn flush_resource_timings(&self, index: usize) {
        let (from, records) = {
            let sent = self.timings_sent.lock().map(|c| *c).unwrap_or(0);
            let all = self.requests.lock().map(|r| r.clone()).unwrap_or_default();
            (sent, all)
        };
        if records.len() <= from {
            return;
        }
        let fresh: Vec<Value> = records[from..]
            .iter()
            .enumerate()
            .map(|(i, r)| {
                // Only the page's own document is a navigation. A frame's is a
                // resource of the page that embedded it, which is where a browser
                // lists it too.
                let top_document = from + i == 0 && r.resource_type == "document";
                let kind = if top_document { "navigation" } else { "resource" };
                let initiator = match r.resource_type.as_str() {
                    "script" => "script",
                    "xhr" | "fetch" => "fetch",
                    "document" if top_document => "navigation",
                    "document" => "iframe",
                    "websocket" => "other",
                    _ => "img",
                };
                serde_json::json!({
                    "name": r.url,
                    "entryType": kind,
                    "initiatorType": initiator,
                    "start": r.started_ms,
                    "duration": r.duration_ms,
                    "size": r.body.len() + 300,
                    "decoded": r.body.len(),
                    "status": r.status,
                    "protocol": "h2",
                    "contentType": r.headers.get("content-type").cloned().unwrap_or_default(),
                })
            })
            .collect();
        if let Ok(mut c) = self.timings_sent.lock() {
            *c = records.len();
        }
        let js = format!(
            "globalThis.__pt_noteResources && __pt_noteResources({})",
            js_str(&Value::Array(fresh).to_string())
        );
        let _ = self.eval_in(index, &js).await;
    }

    /// Press the first control a widget offers, wherever it lives — this page or
    /// any of its frames, light tree or shadow. Returns what was pressed, or
    /// `None` when there is nothing to press yet.
    ///
    /// Deliberately knows nothing about any particular challenge: it presses a
    /// checkbox, switch or button the way a person would, and the difference
    /// between that and a widget-specific script is that this cannot go stale.
    /// A driver cannot do it itself — the control is usually inside a closed
    /// shadow root in a cross-origin frame, where page script has no reach.
    pub async fn press_widget_control(&self) -> Result<Option<String>, EngineError> {
        // Frames first: a challenge widget is one, and its control is the one
        // worth pressing.
        let mut targets: Vec<Option<u32>> = self.frame_list().iter().map(|f| Some(f.id)).collect();
        targets.push(None);

        for frame in targets {
            let found = match frame {
                // In this page, only what belongs to an embedded widget — a
                // control in a shadow tree. The page's own form is not ours to
                // submit, and pressing its button would be worse than doing
                // nothing. Inside a frame, the whole document is the widget.
                None => self.evaluate("__pt_findControl(true)").await,
                Some(id) => self.evaluate_in_frame(id, "__pt_findControl(false)").await,
            };
            let Ok(v) = found else { continue };
            let Some(list) = v
                .as_str()
                .and_then(|t| serde_json::from_str::<Vec<Value>>(t).ok())
            else {
                continue;
            };
            let Some(c) = list.into_iter().next() else {
                continue;
            };
            let (x, y) = (
                c["x"].as_f64().unwrap_or(0.0),
                c["y"].as_f64().unwrap_or(0.0),
            );
            // Inside the frame that owns it, so no coordinate has to survive a
            // trip through a parent that lays its frames out differently.
            for kind in ["mouseMoved", "mousePressed", "mouseReleased"] {
                let js = format!("__pt_mouse({}, {x}, {y}, \"left\", 1)", js_str(kind));
                let _ = match frame {
                    None => self.evaluate(&js).await,
                    Some(id) => self.evaluate_in_frame(id, &js).await,
                };
            }
            let what = format!(
                "{}[{}]@{}{}",
                c["tag"].as_str().unwrap_or("?"),
                c["type"].as_str().unwrap_or(""),
                c["at"].as_i64().unwrap_or(0),
                match frame {
                    Some(id) => format!(" in frame {id}"),
                    None => String::new(),
                }
            );
            tracing::debug!(control = %what, "pressed a widget control");
            return Ok(Some(what));
        }
        Ok(None)
    }

    /// Build, feed and tear down the workers `index` started — the page's, or a
    /// frame's, which is where a challenge does its collecting. A worker gets a
    /// context of its own, shaped into a worker global (see
    /// `worker_scope_script`) before a line of its code runs: `self` is a
    /// `DedicatedWorkerGlobalScope`, there is no document and no window, and its
    /// realm is its own. Anything short of that is a shim, and a fingerprint
    /// collected in a shim describes the page.
    ///
    /// Ids are handed out by each document's own DOM, so the page's worker 1 and
    /// a frame's worker 1 are different workers — the owning context is half the
    /// key, and messages go home to that context under its own id.
    async fn apply_worker_ops(&self, index: usize, base: &str, ops: &[Value]) {
        /// A page that spawns workers without bound would pin contexts forever.
        const MAX_WORKERS: usize = 16;
        for op in ops.iter().take(64) {
            let id = op["id"].as_u64().unwrap_or(0) as u32;
            let key = (index, id);
            match op["op"].as_str().unwrap_or("") {
                "open" => {
                    if self.workers.lock().map(|w| w.len()).unwrap_or(0) >= MAX_WORKERS {
                        continue;
                    }
                    let raw = op["src"].as_str().unwrap_or("");
                    // A worker is almost always built from a blob the page just
                    // made; its bytes are in the page's own memory, not on the
                    // network. Cloudflare's collectors are built exactly this way
                    // — and revoke the URL on the very next line, which is why the
                    // DOM reads the blob inside `new Worker` and sends the bytes
                    // along. Looking them up here would find nothing.
                    let source = if raw.starts_with("blob:") || raw.starts_with("data:") {
                        match op["body"].as_str() {
                            Some(body) if !body.is_empty() => body.to_string(),
                            _ => self
                                .eval_in(
                                    index,
                                    &format!(
                                        "(() => {{ const s = globalThis.__pt_localSource && __pt_localSource({}); \
                                           return typeof s === 'string' ? s : ''; }})()",
                                        js_str(raw)
                                    ),
                                )
                                .await
                                .ok()
                                .and_then(|v| v.as_str().map(str::to_string))
                                .unwrap_or_default(),
                        }
                    } else {
                        match resolve_url(base, raw) {
                            Some(url) => match self.fetch_text(&url, "script").await {
                                Ok((_, code)) => code,
                                Err(e) => {
                                    tracing::debug!(url = %url, error = %e, "worker script failed to load");
                                    String::new()
                                }
                            },
                            None => String::new(),
                        }
                    };
                    if source.is_empty() {
                        // Silence here cost an evening: a worker whose script
                        // never arrived looked exactly like a worker that was
                        // never asked for. Say which of the two it was — the URL
                        // is unknown to the document, or its bytes came back
                        // empty — since only the failing case pays for it.
                        let why = self
                            .eval_in(
                                index,
                                &format!(
                                    "(() => {{ const m = globalThis.__pt_blobs; const b = m && m.get({}); \
                                       return __ptJSON.stringify({{ known: !!b, blobs: m ? m.size : -1, \
                                         kind: b && b.constructor && b.constructor.name, \
                                         size: b && b.size }}); }})()",
                                    js_str(raw)
                                ),
                            )
                            .await
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_string))
                            .unwrap_or_default();
                        tracing::debug!(src = %raw, %why, "worker script is empty, nothing to run");
                        let _ = self
                            .eval_in(
                                index,
                                &format!("__pt_workerFailed({id}, \"script not loaded\")"),
                            )
                            .await;
                        continue;
                    }
                    let boot = self.bootstrap.clone();
                    let Ok(Ok(child)) = self
                        .engine
                        .pool
                        .dispatch(self.worker, move |iso| iso.create_context(&boot))
                        .await
                    else {
                        continue;
                    };
                    let name = op["name"].as_str().unwrap_or("");
                    // A blob's address is its own — resolving it against the
                    // document turns `blob:http://host/uuid` into nonsense, and
                    // that address is what the worker reads as `location.href`.
                    let local = raw.starts_with("blob:") || raw.starts_with("data:");
                    let url = if local {
                        raw.to_string()
                    } else {
                        resolve_url(base, raw).unwrap_or_else(|| raw.to_string())
                    };
                    let _ = self
                        .eval_in(child, &nokk_stealth::worker_scope_script(name, &url))
                        .await;
                    if let Ok(mut w) = self.workers.lock() {
                        w.insert(
                            key,
                            WorkerState {
                                index: child,
                                url: url.clone(),
                                // A worker resolves its relative requests against
                                // its own script — unless it came from a blob,
                                // which has no path of its own to resolve against.
                                fetch_base: if local { base.to_string() } else { url.clone() },
                            },
                        );
                    }
                    tracing::debug!(url = %url, bytes = source.len(),
                                    head = %&source[..source.len().min(400)], "worker started");
                    let code = format!("{source}\n//# sourceURL={url}");
                    if let Err(e) = self.eval_in(child, &code).await {
                        tracing::debug!(error = %e, "worker script threw");
                        let _ = self
                            .eval_in(
                                index,
                                &format!("__pt_workerFailed({id}, {})", js_str(&e.to_string())),
                            )
                            .await;
                    }
                }
                "post" => {
                    let child = self
                        .workers
                        .lock()
                        .ok()
                        .and_then(|w| w.get(&key).map(|s| s.index));
                    match child {
                        Some(child) => {
                            let data = op["data"].as_str().unwrap_or("null");
                            tracing::debug!(owner = index, worker = id, bytes = data.len(), "worker post");
                            let _ = self
                                .eval_in(child, &format!("__pt_workerDeliver({})", js_str(data)))
                                .await;
                        }
                        None => tracing::debug!(owner = index, worker = id, "worker post: no such worker"),
                    }
                }
                "close" => {
                    let gone = self.workers.lock().ok().and_then(|mut w| w.remove(&key));
                    if let Some(state) = gone {
                        self.dispose_worker(index, &state).await;
                    }
                }
                _ => {}
            }
        }
    }

    /// Give each worker its turn: its own timers and fetches, and whatever it
    /// posted home delivered into the document that started it — the page, or the
    /// frame, under the id that document knows it by.
    async fn pump_workers(&self) -> Result<usize, EngineError> {
        let workers: Vec<((usize, u32), WorkerState)> = self
            .workers
            .lock()
            .map(|w| w.iter().map(|(k, s)| (*k, s.clone())).collect())
            .unwrap_or_default();
        let mut work = 0usize;
        for (key, state) in workers {
            let (owner, id) = key;
            let child = state.index;
            let ran = self
                .engine
                .pool
                .dispatch(self.worker, move |iso| {
                    iso.run_event_loop(child, 200, std::time::Duration::from_millis(50))
                })
                .await?
                .unwrap_or(0);
            work += ran as usize;

            let qjson = self.eval_in(child, DRAIN_IO).await?;
            let queues: Value = match qjson {
                Value::String(s) => serde_json::from_str(&s).unwrap_or_default(),
                _ => Value::Null,
            };
            self.log_console("worker", &queues);
            if let Some(reqs) = queues["fetch"].as_array() {
                for r in reqs.iter().take(32) {
                    work += 1;
                    let settle = self.perform_fetch(&state.fetch_base, r).await;
                    let _ = self.eval_in(child, &settle).await;
                }
            }

            // What it posted home, and whether it hung up: `close()` inside a
            // worker ends it, and a context nobody will ever pump again should
            // not stay on the isolate.
            let out = self
                .eval_in(
                    child,
                    "__ptJSON.stringify({out: __pt_drainWorkerOut(), closed: !!globalThis.__ptClosed})",
                )
                .await?;
            let drained: Value = out
                .as_str()
                .and_then(|t| serde_json::from_str(t).ok())
                .unwrap_or(Value::Null);
            let messages: Vec<String> = drained["out"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            for m in messages {
                work += 1;
                let _ = self
                    .eval_in(owner, &format!("__pt_workerMessage({id}, {})", js_str(&m)))
                    .await;
            }
            if drained["closed"].as_bool().unwrap_or(false) {
                work += 1;
                if let Ok(mut w) = self.workers.lock() {
                    w.remove(&key);
                }
                self.dispose_worker(owner, &state).await;
            }
        }
        Ok(work)
    }

    /// Ask every live worker the same question, paired with the script each one
    /// runs. A worker's context is reachable from nothing on the page — this is
    /// the only way to read what one saw, which is what the probe tracer needs to
    /// report a collection that happens in there.
    pub async fn evaluate_in_workers(&self, js: &str) -> Vec<(String, Value)> {
        let workers: Vec<WorkerState> = self
            .workers
            .lock()
            .map(|w| w.values().cloned().collect())
            .unwrap_or_default();
        let mut out = Vec::new();
        for state in workers {
            if let Ok(v) = self.eval_in(state.index, js).await {
                out.push((state.url, v));
            }
        }
        out
    }

    /// Everything the page said into `console`, on its way to the log. A page
    /// reports its own failures there — a challenge widget that dies says so in
    /// one line — and dropping it was the quietest way to lose the reason. Not
    /// counted as work: talking is not activity, and a page that logs on a timer
    /// must still be allowed to go idle.
    fn log_console(&self, where_: &str, queues: &Value) {
        let Some(lines) = queues["console"].as_array() else {
            return;
        };
        for line in lines.iter().take(64) {
            let level = line[0].as_str().unwrap_or("log");
            let text = line[1].as_str().unwrap_or("");
            if text.is_empty() {
                continue;
            }
            tracing::debug!(target: "nokk::console", %level, %where_, "{text}");
        }
    }

    /// Hand a worker's context back to the isolate. A worker usually ends before
    /// anyone asks it anything — a collector posts its result and hangs up — so
    /// with the probe tracer on, what it was asked is carried into the document
    /// that started it before the context goes.
    async fn dispose_worker(&self, owner: usize, state: &WorkerState) {
        if std::env::var("NOKK_TRACE_PROBES").is_ok() {
            let log = self
                .eval_in(
                    state.index,
                    "typeof __pt_probeLog === 'function' ? __pt_probeLog() : ''",
                )
                .await;
            if let Ok(Value::String(log)) = log {
                if log.len() > 2 {
                    let _ = self
                        .eval_in(
                            owner,
                            &format!(
                                "(globalThis.__pt_workerTrace = globalThis.__pt_workerTrace || [])\
                                 .push([{}, {}])",
                                js_str(&state.url),
                                js_str(&log)
                            ),
                        )
                        .await;
                }
            }
        }
        let child = state.index;
        let _ = self
            .engine
            .pool
            .dispatch(self.worker, move |iso| iso.dispose_context(child))
            .await;
    }

    /// End the workers a document started — one document's (`Some(index)`), or
    /// every one of this page's. A browser does exactly this when the document
    /// goes: its workers' timers, requests and contexts go with it. Without it,
    /// each navigation leaves a worker behind, still pumped, still fetching, for
    /// a document that no longer exists.
    async fn terminate_workers_of(&self, owner: Option<usize>) {
        let gone: Vec<(usize, WorkerState)> = self
            .workers
            .lock()
            .map(|mut w| {
                let doomed: Vec<(usize, u32)> = w
                    .keys()
                    .filter(|(o, _)| owner.map_or(true, |idx| *o == idx))
                    .copied()
                    .collect();
                doomed
                    .iter()
                    .filter_map(|k| w.remove(k).map(|s| (k.0, s)))
                    .collect()
            })
            .unwrap_or_default();
        for (owner, state) in gone {
            self.dispose_worker(owner, &state).await;
        }
    }

    /// Whether this page has a live `<iframe>`. Same reasoning as a socket: the
    /// frame is a running document with timers and requests of its own, and it
    /// freezes the moment nothing pumps it.
    pub fn has_frames(&self) -> bool {
        self.frames.lock().map(|f| !f.is_empty()).unwrap_or(false)
    }

    /// Wait up to `grace` for any socket to produce something, putting it back on
    /// the queue for the next drain. False means nothing arrived in time.
    async fn await_ws_event(&self, grace: std::time::Duration) -> bool {
        let mut sockets = self.sockets.lock().await;
        match tokio::time::timeout(grace, sockets.rx.recv()).await {
            Ok(Some(evt)) => {
                // Push it back so `deliver_ws_events` handles every event on one
                // path — this function only decides whether to keep looping.
                sockets.tx.send(evt).is_ok()
            }
            _ => false,
        }
    }

    /// Carry out the frame operations the page queued: build a browsing context
    /// for a connected `<iframe>`, or tear one down.
    ///
    /// This is what makes an iframe *real* rather than an inert tag. The child
    /// gets its own V8 context on this same worker (so parent and child can be
    /// driven without cross-thread hops), the same stealth bootstrap (an iframe of
    /// this browser is the same machine), its own `location`, its own document and
    /// its own scripts — after which `contentWindow` answers, which is precisely
    /// what a widget polls for before it will do anything.
    async fn apply_frame_ops(&self, base: &str, ops: &[Value]) {
        const MAX_FRAMES: usize = 16;
        for op in ops {
            let id = op["id"].as_u64().unwrap_or(0) as u32;
            match op["op"].as_str().unwrap_or("") {
                "open" => {
                    let raw = op["src"].as_str().unwrap_or("");
                    if raw.is_empty() || raw == "about:blank" {
                        continue;
                    }
                    let url = resolve_url(base, raw).unwrap_or_else(|| raw.to_string());
                    if self.engine.block_trackers && nokk_net::is_blocked_url(&url) {
                        self.record("GET", &url, "document", 0, &[]);
                        continue;
                    }
                    // A page that spawns frames without bound would pin unbounded
                    // contexts to a shared worker.
                    if self.frames.lock().map(|f| f.len()).unwrap_or(0) >= MAX_FRAMES {
                        continue;
                    }
                    let Ok((_, html)) = self.fetch_text(&url, "document").await else {
                        let _ = self.evaluate(&format!("__pt_frameFailed({id})")).await;
                        continue;
                    };
                    let boot = self.bootstrap.clone();
                    let Ok(Ok(index)) = self
                        .engine
                        .pool
                        .dispatch(self.worker, move |iso| iso.create_context(&boot))
                        .await
                    else {
                        continue;
                    };
                    // Teach the child who it is before anything runs in it: its own
                    // frame id (so its `postMessage` can be routed back) and that it
                    // is not the top-level window.
                    let _ = self
                        .eval_in(index, &format!("__pt_markAsFrame({id});"))
                        .await;
                    // И своё окно: у кадра оно размером с его `<iframe>`, а не со
                    // страницей. Виджет Turnstile живёт в 300×65 и этот размер
                    // читает; наши кадры отвечали размером окна страницы.
                    let (mut fw, mut fh) = (
                        op["w"].as_f64().unwrap_or(300.0),
                        op["h"].as_f64().unwrap_or(150.0),
                    );
                    // Элемент мог получить размер уже после вставки (стили
                    // разбираются позже) — спрашиваем родителя ещё раз, сейчас.
                    let raw = self.eval_in(self.index, &format!("__pt_frameBox({id})")).await;
                    tracing::debug!(?raw, "frame box from parent");
                    if let Ok(Value::String(box_)) = raw {
                        if let Ok(v) = serde_json::from_str::<Vec<f64>>(&box_) {
                            if v.len() == 2 && v[0] > 0.0 && v[1] > 0.0 {
                                fw = v[0];
                                fh = v[1];
                            }
                        }
                    }
                    tracing::debug!(frame = id, w = fw, h = fh, "frame viewport");
                    let _ = self
                        .eval_in(index, &format!("__pt_setViewport({fw}, {fh});"))
                        .await;
                    // Init scripts run before the frame's document, as they do for
                    // a page — that is how a client instruments a frame at all,
                    // since a frame's own scripts run the moment it is built.
                    let init = self
                        .frame_init_scripts
                        .lock()
                        .map(|v| v.clone())
                        .unwrap_or_default();
                    for src in init {
                        if let Err(e) = self.eval_in(index, &src).await {
                            tracing::debug!(error = %e, "frame init script threw");
                        }
                    }
                    let origin = origin_of(&url);
                    if let Ok(mut frames) = self.frames.lock() {
                        frames.insert(
                            id,
                            FrameState {
                                index,
                                url: url.clone(),
                                origin: origin.clone(),
                                viewport: (fw, fh),
                            },
                        );
                    }
                    if let Err(e) = self.load_html_into(index, &url, &html).await {
                        tracing::debug!(url = %url, error = %e, "iframe document failed to load");
                    }
                    // Only now does `contentWindow` exist, and only now does the
                    // element's `load` fire — the order a page relies on.
                    let _ = self
                        .evaluate(&format!("__pt_frameReady({id}, {});", js_str(&origin)))
                        .await;
                }
                "close" => {
                    let gone = self.frames.lock().ok().and_then(|mut f| f.remove(&id));
                    if let Some(f) = gone {
                        let idx = f.index;
                        // A removed frame is a document that ended: its workers
                        // end with it, exactly as they do when the page navigates.
                        self.terminate_workers_of(Some(idx)).await;
                        let _ = self
                            .engine
                            .pool
                            .dispatch(self.worker, move |iso| iso.dispose_context(idx))
                            .await;
                    }
                }
                // `parent.postMessage` from inside a frame, or
                // `frame.contentWindow.postMessage` from the page: same plumbing,
                // opposite directions.
                "post" => {
                    let data = op["data"].as_str().unwrap_or("null").to_string();
                    // Виден весь обмен со фреймом — без патчей в JS, которые ломают
                    // проверку `event.source === iframe.contentWindow`.
                    if !data.contains("\"meow\"") && !data.contains("\"food\"") {
                        tracing::debug!(to_parent = op["toParent"].as_bool().unwrap_or(false),
                                        payload = %&data[..data.len().min(9000)], "frame message");
                    }
                    let to_parent = op["toParent"].as_bool().unwrap_or(false);
                    let target = self.frames.lock().ok().and_then(|f| f.get(&id).cloned());
                    let Some(frame) = target else { continue };
                    let (index, origin) = if to_parent {
                        (self.index, frame.origin.clone())
                    } else {
                        (frame.index, origin_of(base))
                    };
                    let _ = self
                        .eval_in(
                            index,
                            &format!(
                                "__pt_deliverMessage({}, {}, {});",
                                data,
                                js_str(&origin),
                                if to_parent {
                                    id.to_string()
                                } else {
                                    "0".into()
                                }
                            ),
                        )
                        .await;
                }
                _ => {}
            }
        }
    }

    /// Fetch and run what the page inserted into itself. A `<script src>` added to
    /// the document is the standard way to load anything after first paint — a tag
    /// manager, a widget bootstrap, Cloudflare's challenge orchestrator — and the
    /// element cannot fetch on its own. Resolved against the document's base URL,
    /// fetched on this context's client (so cookies and fingerprint are the page's
    /// own), then evaluated in the context that asked. The element hears back
    /// either way, so `onload`/`onerror` fire where the page expects them.
    /// Load and run an ES module graph. V8 resolves imports through a callback
    /// that cannot wait for the network, so the graph is walked first: compile,
    /// ask what it imports, fetch that, repeat — and only then instantiate. A
    /// modern site is one `<script type="module">` and nothing else, so without
    /// this the page stays blank and says nothing about why.
    async fn run_module(&self, index: usize, url: &str, source: String) -> Result<(), EngineError> {
        /// A page's own graph, not a package tree — this is a guard, not a budget.
        const MAX_MODULES: usize = 256;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        seen.insert(url.to_string());
        let mut pending = vec![(url.to_string(), source)];

        while let Some((at, code)) = pending.pop() {
            let (i, u, c) = (index, at.clone(), code);
            let requests = self
                .engine
                .pool
                .dispatch(self.worker, move |iso| iso.module_requests(i, &u, &c))
                .await?
                .map_err(EngineError::Js)?;

            for spec in requests {
                // A bare specifier ("react") needs an import map to mean anything;
                // a bundled page never has one, and guessing would be worse.
                let Some(target) = resolve_url(&at, &spec) else {
                    continue;
                };
                let (i, from, sp, to) = (index, at.clone(), spec.clone(), target.clone());
                self.engine
                    .pool
                    .dispatch(self.worker, move |iso| iso.link_module(i, &from, &sp, &to))
                    .await?;
                if seen.contains(&target) || seen.len() >= MAX_MODULES {
                    continue;
                }
                seen.insert(target.clone());
                match self.fetch_text(&target, "script").await {
                    Ok((_, code)) => pending.push((target, code)),
                    Err(e) => tracing::debug!(url = %target, error = %e, "import failed to load"),
                }
            }
        }

        let (i, u) = (index, url.to_string());
        self.engine
            .pool
            .dispatch(self.worker, move |iso| iso.eval_module(i, &u))
            .await?
            .map_err(EngineError::Js)
    }

    async fn apply_script_ops(&self, index: usize, base: &str, ops: &[Value]) {
        const MAX_SCRIPTS: usize = 64;
        for op in ops.iter().take(MAX_SCRIPTS) {
            let id = op["id"].as_u64().unwrap_or(0);
            let raw = op["src"].as_str().unwrap_or("");
            let done = |ok: bool| format!("__pt_scriptDone({id}, {ok});");
            // A `blob:` or `data:` script never goes to the network — its source is
            // in the page's own memory, and handing such a URL to the HTTP client
            // fails with "invalid authority". Cloudflare's orchestrator loads its
            // next stage exactly this way, so the chain ended here in silence.
            if raw.starts_with("blob:") || raw.starts_with("data:") {
                let src = self
                    .eval_in(
                        index,
                        &format!(
                            "(() => {{ const s = globalThis.__pt_localSource && __pt_localSource({}); \
                               return typeof s === 'string' ? s : ''; }})()",
                            js_str(raw)
                        ),
                    )
                    .await
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_default();
                if src.is_empty() {
                    let _ = self.eval_in(index, &done(false)).await;
                } else {
                    if let Err(e) = self.eval_in(index, &src).await {
                        tracing::debug!(error = %e, "inline-source script threw");
                    }
                    let _ = self.eval_in(index, &done(true)).await;
                }
                continue;
            }
            // <script type="module"> без src: исходник пришёл вместе с операцией,
            // но исполнять его всё равно надо как модуль — со своим `import`.
            if let Some(code) = op["code"].as_str() {
                if let Err(e) = self.run_module(index, base, code.to_string()).await {
                    tracing::debug!(error = %e, "inline module threw");
                }
                let _ = self.eval_in(index, &done(true)).await;
                continue;
            }
            let Some(url) = resolve_url(base, raw) else {
                let _ = self.eval_in(index, &done(false)).await;
                continue;
            };
            if self.engine.block_trackers && nokk_net::is_blocked_url(&url) {
                self.record("GET", &url, "script", 0, &[]);
                // A blocked tracker "loaded" as far as the page is concerned;
                // reporting an error would send it down a retry path instead.
                let _ = self.eval_in(index, &done(true)).await;
                continue;
            }
            match self.fetch_text(&url, "script").await {
                Ok((_, code)) => {
                    // Скрипт читает тайминг собственного <script> первой же
                    // строкой — запись должна быть на месте до того, как он
                    // начнёт, а не в конце круга.
                    if index == self.index {
                        self.flush_resource_timings(index).await;
                    }
                    if op["module"].as_bool().unwrap_or(false) {
                        if let Err(e) = self.run_module(index, &url, code).await {
                            tracing::debug!(url = %url, error = %e, "module threw");
                        }
                        let _ = self.eval_in(index, &done(true)).await;
                        continue;
                    }
                    let code = format!("{code}\n//# sourceURL={url}");
                    if let Err(e) = self.eval_in(index, &code).await {
                        tracing::debug!(url = %url, error = %e, "inserted script threw");
                    }
                    let _ = self.eval_in(index, &done(true)).await;
                }
                Err(e) => {
                    tracing::debug!(url = %url, error = %e, "inserted script failed to load");
                    let _ = self.eval_in(index, &done(false)).await;
                }
            }
        }
    }

    /// Record when the page's earliest timer comes due (`-1` = none pending), as
    /// the JS queue just reported it.
    fn note_next_timer(&self, delay_ms: i64) {
        let at = (delay_ms >= 0)
            .then(|| std::time::Instant::now() + std::time::Duration::from_millis(delay_ms as u64));
        if let Ok(mut slot) = self.next_timer_at.lock() {
            *slot = at;
        }
    }

    /// How long until this page has a timer to run: `None` when nothing is
    /// pending, `Some(ZERO)` when one is due now. A driver that wants to keep a
    /// page moving (the CDP server's pump, an `awaitPromise`) sleeps this long
    /// instead of polling.
    pub fn next_timer_in(&self) -> Option<std::time::Duration> {
        let at = (*self.next_timer_at.lock().ok()?)?;
        Some(at.saturating_duration_since(std::time::Instant::now()))
    }

    /// Whether a timer is due right now — the page has work waiting for a turn.
    pub fn timer_due(&self) -> bool {
        self.next_timer_in() == Some(std::time::Duration::ZERO)
    }

    /// Drain what every live frame queued (its `parent.postMessage` calls) and
    /// give each one an event-loop turn, so a frame's own timers and fetches make
    /// progress rather than freezing the moment its document finished loading.
    async fn pump_frames(&self) -> Result<usize, EngineError> {
        let frames: Vec<(u32, usize)> = self
            .frames
            .lock()
            .map(|f| f.iter().map(|(id, s)| (*id, s.index)).collect())
            .unwrap_or_default();
        let mut work = 0;
        for (id, index) in frames {
            let ran = self
                .engine
                .pool
                .dispatch(self.worker, move |iso| {
                    iso.run_event_loop(index, 200, std::time::Duration::from_millis(50))
                })
                .await?
                .unwrap_or(0);
            work += ran as usize;
            let qjson = self.eval_in(index, DRAIN_IO).await?;
            let queues: Value = match qjson {
                Value::String(s) => serde_json::from_str(&s).unwrap_or_default(),
                _ => Value::Null,
            };
            let base = self.frame_base(id);
            self.log_console(&format!("frame {id}"), &queues);

            // Кадр узнаёт свой размер не один раз: стили доезжают позже вставки,
            // и элемент может измениться. Браузер в этом случае меняет окно
            // кадра — делаем то же, пока размер не устоится.
            if let Ok(Value::String(text)) = self
                .eval_in(self.index, &format!("__pt_frameBox({id})"))
                .await
            {
                if let Ok(v) = serde_json::from_str::<Vec<f64>>(&text) {
                    if v.len() == 2 && v[0] > 0.0 && v[1] > 0.0 {
                        let changed = self
                            .frames
                            .lock()
                            .ok()
                            .and_then(|mut f| {
                                f.get_mut(&id).map(|st| {
                                    let now = (v[0], v[1]);
                                    let changed = st.viewport != now;
                                    st.viewport = now;
                                    changed
                                })
                            })
                            .unwrap_or(false);
                        if changed {
                            let _ = self
                                .eval_in(index, &format!("__pt_setViewport({}, {});", v[0], v[1]))
                                .await;
                        }
                    }
                }
            }

            // A frame is a document like any other: its `fetch`/XHR has to reach
            // the network, resolved against *its* URL. Draining this queue and
            // dropping it (as this did) leaves a widget unable to report anything
            // home, which looks from the outside exactly like a widget that hangs.
            if let Some(reqs) = queues["fetch"].as_array() {
                for r in reqs.iter().take(64) {
                    work += 1;
                    let settle = self.perform_fetch(&base, r).await;
                    let _ = self.eval_in(index, &settle).await;
                }
            }

            // A frame loads code into itself the same way a page does.
            if let Some(ops) = queues["scripts"].as_array() {
                if !ops.is_empty() {
                    work += ops.len();
                    self.apply_script_ops(index, &base, ops).await;
                }
            }

            // A widget's collection runs in workers *it* started, not the page's:
            // the frame builds the blob, the frame spawns the worker, and the
            // fingerprint is taken in there. Draining only the page's queue left
            // those workers unborn on every real challenge.
            if let Some(ops) = queues["workers"].as_array() {
                if !ops.is_empty() {
                    work += ops.len();
                    self.apply_worker_ops(index, &base, ops).await;
                }
            }

            // Sockets opened from inside a frame share the page's table, so their
            // frames come back through the same delivery path.
            if let Some(ws_ops) = queues["ws"].as_array() {
                if !ws_ops.is_empty() {
                    work += ws_ops.len();
                    self.apply_ws_ops(&base, ws_ops).await;
                }
            }
            work += self.deliver_ws_events(index).await?;

            // A frame's own `postMessage` calls come back tagged with its id.
            if let Some(ops) = queues["frames"].as_array() {
                let tagged: Vec<Value> = ops
                    .iter()
                    .map(|o| {
                        let mut o = o.clone();
                        o["id"] = json_num(id);
                        o
                    })
                    .collect();
                work += tagged.len();
                self.apply_frame_ops(&base, &tagged).await;
            }
        }
        Ok(work)
    }

    /// The document URL a frame resolves its own relative URLs against.
    fn frame_base(&self, id: u32) -> String {
        self.frames
            .lock()
            .ok()
            .and_then(|f| f.get(&id).map(|s| s.url.clone()))
            .unwrap_or_default()
    }

    /// Carry out the `open`/`send`/`close` operations the page queued.
    async fn apply_ws_ops(&self, base: &str, ops: &[Value]) {
        const MAX_SOCKETS: usize = 64;
        for op in ops {
            let id = op["id"].as_u64().unwrap_or(0) as u32;
            match op["op"].as_str().unwrap_or("") {
                "open" => {
                    let raw = op["url"].as_str().unwrap_or("");
                    let url = resolve_url(base, raw).unwrap_or_else(|| raw.to_string());
                    let protocols: Vec<String> = op["protocols"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    let mut sockets = self.sockets.lock().await;
                    // A page that opens sockets without bound would otherwise pin
                    // unbounded tasks to a shared worker.
                    if sockets.open.len() >= MAX_SOCKETS {
                        let _ = sockets.tx.send((
                            id,
                            nokk_net::WsEvent::Error("too many open WebSockets".into()),
                        ));
                        continue;
                    }
                    // Blocked tracker hosts don't get a socket either — the filter
                    // has to cover every way out, not just `fetch`.
                    if self.engine.block_trackers && nokk_net::is_blocked_url(&url) {
                        self.record("WS", &url, "websocket", 0, &[]);
                        let _ = sockets.tx.send((
                            id,
                            nokk_net::WsEvent::Error("blocked by tracker filter".into()),
                        ));
                        continue;
                    }
                    self.record("WS", &url, "websocket", 101, &[]);
                    let handle = nokk_net::open_websocket(
                        &self.client,
                        id,
                        &url,
                        &protocols,
                        &origin_of(base),
                        sockets.tx.clone(),
                    );
                    sockets.open.insert(id, handle);
                }
                "send" => {
                    let sockets = self.sockets.lock().await;
                    if let Some(h) = sockets.open.get(&id) {
                        let cmd = match op["bytes"].as_array() {
                            Some(a) => nokk_net::WsCommand::Binary(
                                a.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect(),
                            ),
                            None => nokk_net::WsCommand::Text(
                                op["data"].as_str().unwrap_or("").to_string(),
                            ),
                        };
                        h.send(cmd);
                    }
                }
                "close" => {
                    let sockets = self.sockets.lock().await;
                    if let Some(h) = sockets.open.get(&id) {
                        h.send(nokk_net::WsCommand::Close {
                            code: op["code"].as_u64().unwrap_or(1000) as u16,
                            reason: op["reason"].as_str().unwrap_or("").to_string(),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    /// Hand every socket event that has arrived to the page, as one batch of JS
    /// calls. Returns how many were delivered.
    async fn deliver_ws_events(&self, index: usize) -> Result<usize, EngineError> {
        // Bounded per round so a firehose socket can't starve timers.
        const MAX_PER_ROUND: usize = 256;
        let mut script = String::new();
        let mut n = 0;
        {
            let mut sockets = self.sockets.lock().await;
            while n < MAX_PER_ROUND {
                let Ok((id, evt)) = sockets.rx.try_recv() else {
                    break;
                };
                n += 1;
                match evt {
                    nokk_net::WsEvent::Open { protocol } => {
                        script.push_str(&format!("__pt_wsOpen({id},{});", js_str(&protocol)));
                    }
                    nokk_net::WsEvent::Text(t) => {
                        script.push_str(&format!("__pt_wsMessage({id},{},0);", js_str(&t)));
                    }
                    nokk_net::WsEvent::Binary(b) => {
                        let bytes = b
                            .iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(",");
                        script.push_str(&format!("__pt_wsMessage({id},[{bytes}],1);"));
                    }
                    nokk_net::WsEvent::Closed {
                        code,
                        reason,
                        clean,
                    } => {
                        sockets.open.remove(&id);
                        script.push_str(&format!(
                            "__pt_wsClose({id},{code},{},{});",
                            js_str(&reason),
                            clean
                        ));
                    }
                    nokk_net::WsEvent::Error(msg) => {
                        // A failed connection is terminal: the page gets `error`
                        // then `close`, and the socket leaves the table.
                        sockets.open.remove(&id);
                        script.push_str(&format!("__pt_wsError({id},{});", js_str(&msg)));
                    }
                }
            }
        }
        if n > 0 {
            self.engine
                .pool
                .dispatch(self.worker, move |iso| iso.eval(index, &script))
                .await?
                .map_err(EngineError::Js)?;
        }
        Ok(n)
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
        // Page-initiated requests carry the document that made them, which is
        // also what decides `Sec-Fetch-Site`.
        if !base.is_empty() && base != "about:blank" && !headers.keys().any(|k| k.eq_ignore_ascii_case("referer")) {
            headers.insert("Referer".to_string(), base.to_string());
        }
        // Blocked tracker: never hit the wire; reject like a real ad-blocker
        // (ERR_BLOCKED_BY_CLIENT), and log it so the interception audit is complete.
        if self.engine.block_trackers && nokk_net::is_blocked_url(&url) {
            self.record(&method, &url, &kind, 0, &[]);
            return format!(
                "__pt_fetchReject({}, {})",
                id,
                serde_json::to_string("blocked by tracker filter").unwrap()
            );
        }
        let body = r["body"].as_str().map(|s| s.as_bytes().to_vec());
        let sent = body.clone().unwrap_or_default();
        let req = Request {
            method,
            url: url.clone(),
            headers,
            body,
            kind: nokk_net::RequestKind::Xhr,
            user_activated: false,
        };

        let method = req.method.clone();
        match self.client.send(req).await {
            Ok(resp) => {
                self.record_full(
                    &method,
                    &url,
                    &kind,
                    resp.status,
                    &resp.body,
                    resp.headers.clone(),
                    &sent,
                );
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
        self.fetch_text_from(url, resource_type, None).await
    }

    /// The same, for a navigation the page made itself: `referrer` is the
    /// document that asked, and it changes what goes on the wire — a referrer,
    /// `sec-fetch-site: same-origin`, and no claim of a human gesture.
    async fn fetch_text_from(
        &self,
        url: &str,
        resource_type: &str,
        referrer: Option<&str>,
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
        // A subresource carries the document that asked for it. Without a
        // `Referer` there is no way to tell same-origin from cross-site, and the
        // request reads as one nobody's page made.
        let from = match referrer {
            Some(r) if !r.is_empty() && r != "about:blank" => Some(r.to_string()),
            _ if resource_type != "document" => {
                let base = self.base_url.lock().map(|b| b.clone()).unwrap_or_default();
                (!base.is_empty() && base != "about:blank").then_some(base)
            }
            _ => None,
        };
        if let Some(r) = from {
            headers.insert("Referer".to_string(), r);
        }
        let req = Request {
            method: "GET".into(),
            url: url.to_string(),
            headers,
            body: None,
            kind: match resource_type {
                "document" => nokk_net::RequestKind::Document,
                "script" => nokk_net::RequestKind::Script,
                "xhr" | "fetch" => nokk_net::RequestKind::Xhr,
                _ => nokk_net::RequestKind::Subresource,
            },
            // A navigation nobody's page asked for is one a person asked for.
            user_activated: resource_type == "document" && referrer.is_none(),
        };
        match self.client.send(req).await {
            Ok(resp) => {
                self.record_full(
                    "GET",
                    url,
                    resource_type,
                    resp.status,
                    &resp.body,
                    resp.headers.clone(),
                    &[],
                );
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
        self.record_full(
            method,
            url,
            resource_type,
            status,
            body,
            std::collections::BTreeMap::new(),
            &[],
        )
    }

    /// Log one request and tell any subscriber (the CDP layer) about it. Called
    /// once the outcome is known, which is why a subscriber receives the whole
    /// lifecycle at once rather than a `willBeSent` ahead of time — the timings
    /// are coarser than Chrome's, but every field a client reads is real.
    #[allow(clippy::too_many_arguments)]
    fn record_full(
        &self,
        method: &str,
        url: &str,
        resource_type: &str,
        status: u16,
        body: &[u8],
        headers: std::collections::BTreeMap<String, String>,
        request_body: &[u8],
    ) {
        let now = self.started.elapsed().as_secs_f64() * 1000.0;
        // Without a measured duration, say what a fast local hop looks like
        // rather than zero: a resource that took no time at all is not one.
        let duration_ms = 12.0;
        let started_ms = now - duration_ms;
        let rec = NetworkRecord {
            request_id: format!(
                "nokk-{}",
                REQUEST_IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ),
            headers,
            method: method.to_string(),
            url: url.to_string(),
            status,
            resource_type: resource_type.to_string(),
            body: body.to_vec(),
            request_body: request_body.to_vec(),
            started_ms: started_ms.max(0.0),
            duration_ms: duration_ms.max(0.0),
        };
        if let Ok(mut log) = self.requests.lock() {
            log.push(rec.clone());
        }
        if let Ok(tx) = self.network_tx.lock() {
            if let Some(tx) = tx.as_ref() {
                let _ = tx.send(rec);
            }
        }
    }

    /// Receive every request this context makes from now on, as it completes.
    /// One subscriber at a time (the attached CDP session); subscribing again
    /// replaces the previous one.
    pub fn subscribe_network(&self) -> tokio::sync::mpsc::UnboundedReceiver<NetworkRecord> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        if let Ok(mut slot) = self.network_tx.lock() {
            *slot = Some(tx);
        }
        rx
    }

    /// All network requests the engine made for this context, in order — the
    /// document, external scripts, and every page `fetch`/`XHR`.
    pub fn requests(&self) -> Vec<NetworkRecord> {
        self.requests.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

/// Request ids are unique per process, so a client that watches several pages
/// never sees two requests share one.
static REQUEST_IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// One round trip that empties both JS-side I/O queues. Written as an expression
/// so a bare context (no stealth bootstrap, as in some tests) answers with empty
/// queues instead of throwing.
const DRAIN_IO: &str = "__ptJSON.stringify({\
    fetch: typeof __pt_drainFetchQueue === 'function' ? __ptJSON.parse(__pt_drainFetchQueue()) : [],\
    ws: typeof __pt_drainWsQueue === 'function' ? __pt_drainWsQueue() : [],\
    frames: typeof __pt_drainFrameQueue === 'function' ? __pt_drainFrameQueue() : [],\
    scripts: typeof __pt_drainScriptQueue === 'function' ? __pt_drainScriptQueue() : [],\
    nav: typeof __pt_drainNavQueue === 'function' ? __pt_drainNavQueue() : [],\
    workers: typeof __pt_drainWorkerQueue === 'function' ? __pt_drainWorkerQueue() : [],\
    console: typeof __pt_drainConsole === 'function' ? __pt_drainConsole() : [],\
    timers: typeof __pt_nextTimerDelay === 'function' ? __pt_nextTimerDelay() : -1})";

/// How long [`BrowserContext::run_event_loop`] may spend *waiting* for timers
/// that are not due yet, in total. Timers run in real time, so a page is
/// routinely "not idle, just not due"; this buys the short chains that finish a
/// load without letting a 900 ms watchdog interval hold a CDP command open.
const IDLE_WAIT_BUDGET: std::time::Duration = std::time::Duration::from_millis(150);

/// The same budget while a document is loading. Deferred-by-a-moment work is
/// still load work, and the caller is waiting on the navigation regardless.
const LOAD_WAIT_BUDGET: std::time::Duration = std::time::Duration::from_millis(1_000);

/// How often frames are given an event-loop turn while the page runs.
const FRAME_PUMP_EVERY: std::time::Duration = std::time::Duration::from_millis(20);

fn json_num(v: u32) -> Value {
    Value::Number(serde_json::Number::from(v))
}

/// A JS string literal for `s` (safely quoted/escaped).
fn js_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// The `scheme://host[:port]` a page-initiated WebSocket must send as `Origin`;
/// empty for a document that has none (`about:blank`), where a browser sends
/// `null` rather than a fabricated origin.
fn origin_of(base: &str) -> String {
    match url::Url::parse(base) {
        Ok(u) if u.has_host() => u.origin().ascii_serialization(),
        _ => String::new(),
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
/// HTTP/2, which carries no reason phrase). Also used by the CDP layer for
/// `Network.responseReceived`.
pub fn reason_phrase(status: u16) -> &'static str {
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

    /// A unique, empty session-store directory for a test.
    fn session_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nokk-sess-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn session_engine(store: Option<PathBuf>, real: bool) -> Engine {
        Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 8,
                max_heap_mb: None,
            },
            use_real_network: real,
            session_store: store,
            ..Default::default()
        })
        .expect("engine")
    }

    #[tokio::test]
    async fn named_session_resumes_seeded_cookies_from_the_store() {
        let _serial = serial().await;
        let dir = session_dir("resume");
        std::fs::create_dir_all(&dir).unwrap();
        // Pre-seed the on-disk jar as a *previous* run would have left it.
        let seeded = nokk_net::SessionJar::new();
        seeded.add_cookie_str(
            "sid=warmed; Path=/",
            &url::Url::parse("https://example.com/").unwrap(),
        );
        seeded.save_file(&dir.join("acme.json")).unwrap();

        // A fresh engine opening a context on that session loads the jar back.
        let engine = session_engine(Some(dir.clone()), false);
        let _ctx = engine
            .new_context_with_session("acme".into(), None)
            .await
            .unwrap();
        let cookies = engine.session_cookies("acme");
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "sid");
        assert_eq!(cookies[0].value, "warmed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn closing_a_session_context_writes_the_store() {
        let _serial = serial().await;
        let dir = session_dir("write");
        let engine = session_engine(Some(dir.clone()), false);
        let path = dir.join("acme.json");
        assert!(!path.exists());
        let ctx = engine
            .new_context_with_session("acme".into(), None)
            .await
            .unwrap();
        drop(ctx); // Drop flushes the jar to disk.
        assert!(
            path.exists(),
            "session jar must be persisted on context close"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn distinct_sessions_get_isolated_clients() {
        let _serial = serial().await;
        // Real network so per-session clients are actually built (offline: no request).
        let engine = session_engine(None, true);
        let _a = engine
            .new_context_with_session("alpha".into(), None)
            .await
            .unwrap();
        let _b = engine
            .new_context_with_session("beta".into(), None)
            .await
            .unwrap();
        let _a2 = engine
            .new_context_with_session("alpha".into(), None)
            .await
            .unwrap();
        // alpha and beta each got their own session client; alpha2 reused alpha's.
        assert_eq!(engine.inner.client_pool.lock().unwrap().len(), 2);
    }

    #[test]
    fn sanitize_session_name_blocks_traversal() {
        // Plain names pass through unchanged.
        assert_eq!(sanitize_session_name("acme").as_deref(), Some("acme"));
        assert_eq!(
            sanitize_session_name("acme-prod_1").as_deref(),
            Some("acme-prod_1")
        );
        // Path separators are neutralised and the result stays a single segment.
        for evil in ["a/../b", "../../etc/passwd", "/abs/path", "a\\b"] {
            let got = sanitize_session_name(evil).unwrap();
            assert!(!got.contains('/') && !got.contains('\\'), "{evil} -> {got}");
            assert_ne!(got, "..");
        }
        // Names that reduce to nothing safe are rejected outright.
        assert_eq!(sanitize_session_name(".."), None);
        assert_eq!(sanitize_session_name("."), None);
        assert_eq!(sanitize_session_name(""), None);
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

    /// Evaluate a JS expression that yields a JSON string, and parse it.
    async fn probe(ctx: &BrowserContext, js: &str) -> Value {
        match ctx.evaluate(js).await.expect("probe evaluated") {
            Value::String(s) => serde_json::from_str(&s)
                .unwrap_or_else(|e| panic!("probe returned JSON ({e}): {s}")),
            other => panic!("probe did not return a JSON string: {other:?}"),
        }
    }

    /// The global graph is what Turnstile actually fingerprints: it walks
    /// `window`/`document`/`navigator`/`screen`/`location`/`history` up their
    /// prototype chains and classifies every value. Measured against Chrome 148,
    /// ours matches name-for-name — this pins the parts that took the longest to
    /// get right, and each one of them was a tell before it was fixed.
    #[tokio::test]
    async fn the_global_graph_matches_the_shape_chrome_presents() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            "<!DOCTYPE html><html><head><title>g</title></head><body><p>x</p></body></html>",
        )
        .await
        .unwrap();

        let out = probe(&ctx, r#"(() => {
            const walk = (o) => { const n = []; for (; o; o = Object.getPrototypeOf(o)) n.push(...Object.keys(o)); return n; };
            const kids = document.body.childNodes;
            return __ptJSON.stringify({
              // NodeList, not Array: the collector buckets an array under its own
              // category, and `Array.isArray(node.childNodes)` is false on the platform.
              kidsArray: Array.isArray(kids),
              kidsSame: kids === document.body.childNodes,
              kidsLen: kids.length,
              kidsIter: [...kids].length,
              kidsTag: Object.prototype.toString.call(kids),
              // Own properties belong on the interface, never on the instance.
              docOwn: Object.getOwnPropertyNames(document).length,
              navOwn: Object.getOwnPropertyNames(navigator).length,
              // The surface fill lands on the prototype, and it is enumerable there.
              docGraph: walk(document).length,
              navGraph: walk(navigator).length,
              winGraph: walk(globalThis).length,
              winKeys: Object.keys(globalThis).length,
              // `remove` comes from ChildNode: elements and text have it, documents do not.
              docRemove: 'remove' in document,
              elRemove: typeof document.body.remove,
              // Chrome hides SharedArrayBuffer without cross-origin isolation.
              sab: typeof SharedArrayBuffer,
              isolated: globalThis.crossOriginIsolated,
              // Location is the interface whose members are own properties of the
              // object itself — fifteen of them, with `valueOf` the one that is
              // not enumerable, and only `constructor` left on the prototype.
              locOwn: Object.getOwnPropertyNames(location).length,
              locValueOf: Object.getOwnPropertyNames(location).includes('valueOf')
                && !Object.getOwnPropertyDescriptor(location, 'valueOf').enumerable,
              locProto: Object.getOwnPropertyNames(Object.getPrototypeOf(location)),
              // A document that declares nothing is parsed as windows-1252.
              charset: document.characterSet,
            });
        })()"#).await;

        assert_eq!(out["kidsArray"], false, "childNodes is a NodeList, not an Array");
        assert_eq!(out["kidsSame"], true, "the same list object comes back each read");
        assert_eq!(out["kidsLen"], 1, "and it still counts the children");
        assert_eq!(out["kidsIter"], 1, "and still spreads");
        assert_eq!(out["kidsTag"], "[object NodeList]");
        // Chrome's document has exactly one own property, and it is `location` —
        // measured, not assumed. Everything else lives on the interfaces.
        assert_eq!(out["docOwn"], 1, "a document owns `location`, and nothing else");
        assert_eq!(out["navOwn"], 0, "nor does a real navigator");
        assert!(out["docGraph"].as_u64().unwrap() > 280, "document graph: {}", out["docGraph"]);
        assert!(out["navGraph"].as_u64().unwrap() > 75, "navigator graph: {}", out["navGraph"]);
        // Measured against Chrome 148 in the same shape of page: 243 enumerable
        // names up the window's chain — 237 own, two on `Window.prototype`, four
        // on `EventTarget.prototype`. Ours is 236: the same own set bar `status`,
        // and the chain's own levels are still missing (see the constructor
        // check below). It used to be over 1100, because every interface object
        // was enumerable here and none of them is in a browser.
        assert!(
            (230..=250).contains(&out["winGraph"].as_u64().unwrap()),
            "window graph: {} (Chrome: 243)",
            out["winGraph"]
        );
        assert_eq!(
            out["winKeys"], 236,
            "own enumerable names on the window, Chrome's set exactly bar `status`"
        );
        assert_eq!(out["docRemove"], false, "Document has no ChildNode.remove");
        assert_eq!(out["elRemove"], "function", "elements keep theirs");
        assert_eq!(out["sab"], "undefined", "no SharedArrayBuffer without isolation");
        assert_eq!(out["isolated"], false);
        assert_eq!(out["locOwn"], 15, "Location's members are the object's own");
        assert_eq!(out["locValueOf"], true, "and `valueOf` among them, non-enumerable");
        assert_eq!(
            out["locProto"],
            serde_json::json!(["constructor"]),
            "Location.prototype carries nothing but its constructor"
        );
        assert_eq!(out["charset"], "windows-1252", "undeclared documents are windows-1252");
    }

    /// Fingerprint regression guard. The page-visible surface must carry no trace
    /// of the engine, and this pins every property that has bitten us: an own
    /// property on a DOM instance (real nodes have none), a `__pt_*` bridge global
    /// reachable through any introspection route, or a function whose `toString`
    /// leaks JS source instead of `[native code]`. Any drift fails the build.
    #[tokio::test]
    async fn fingerprint_surface_exposes_no_engine_tells() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        let html = r#"<!DOCTYPE html><html><head><title>f</title></head><body>
            <button id="btn">go</button><input id="inp" value=""></body></html>"#;
        ctx.load_html("https://example.com/", html).await.unwrap();

        let p = probe(
            &ctx,
            r#"__ptJSON.stringify({
              bodyOwn: Object.getOwnPropertyNames(document.body),
              btnOwn: Object.getOwnPropertyNames(document.getElementById('btn')),
              inpOwn: (() => { const i = document.getElementById('inp');
                i.value = 'x'; i.getBoundingClientRect();
                return Object.getOwnPropertyNames(i); })(),
              textOwn: Object.getOwnPropertyNames(document.createTextNode('t')),
              evtOwn: Object.getOwnPropertyNames(new MouseEvent('click', { bubbles: true })),
              docOwn: Object.getOwnPropertyNames(document),
              navOwn: Object.getOwnPropertyNames(navigator),
              navKeys: Object.keys(navigator),
              gopnPt: Object.getOwnPropertyNames(globalThis).filter(k => k.indexOf('__pt') === 0 || k === '__out'),
              ownKeysPt: Reflect.ownKeys(globalThis).filter(k => typeof k === 'string' && (k.indexOf('__pt') === 0 || k === '__out')),
              protoPt: [].concat(
                Object.getOwnPropertyNames(Node.prototype),
                Object.getOwnPropertyNames(Element.prototype),
                Object.getOwnPropertyNames(Event.prototype)).filter(k => k.indexOf('__pt') === 0),
              hasOwnPt: Object.prototype.hasOwnProperty.call(globalThis, '__pt_wrap'),
              gopdHidden: Object.getOwnPropertyDescriptor(globalThis, '__pt_wrap') === undefined,
              callable: typeof __pt_wrap,
              webdriver: navigator.webdriver,
              webdriverOwn: Object.prototype.hasOwnProperty.call(navigator, 'webdriver'),
              natives: {
                querySelector: document.querySelector.toString(),
                getBoundingClientRect: Element.prototype.getBoundingClientRect.toString(),
                addEventListener: Node.prototype.addEventListener.toString(),
                MouseEvent: MouseEvent.toString(),
                KeyboardEvent: KeyboardEvent.toString(),
                nodeTypeGetter: Object.getOwnPropertyDescriptor(Node.prototype, 'nodeType').get.toString(),
                // `style` rides HTMLElement, as it does in a browser.
                styleGetter: Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'style').get.toString(),
                uaGetter: Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent').get.toString(),
                toStringItself: Function.prototype.toString.toString()
              },
              instanceOf: [document.body instanceof Element, document.body instanceof Node,
                new MouseEvent('x') instanceof Event, navigator instanceof Navigator]
            })"#,
        )
        .await;

        // A real DOM node / event / document exposes no own properties — ours must
        // keep its state in hidden (__pt-prefixed, filtered) backing fields.
        for key in ["bodyOwn", "btnOwn", "inpOwn", "textOwn", "evtOwn", "navOwn", "navKeys"] {
            let leaked = p[key]
                .as_array()
                .unwrap_or_else(|| panic!("probe missing {key}"));
            assert!(
                leaked.is_empty(),
                "{key} exposes own properties: {leaked:?}"
            );
        }
        // The document is the one exception, and Chrome names it: `location` is
        // an own property of the document, the only one.
        assert_eq!(
            p["docOwn"],
            serde_json::json!(["location"]),
            "the document owns `location`, and nothing else: {}",
            p["docOwn"]
        );

        // The Rust<->JS bridge is invisible through every introspection route...
        for key in ["gopnPt", "ownKeysPt", "protoPt"] {
            let leaked = p[key]
                .as_array()
                .unwrap_or_else(|| panic!("probe missing {key}"));
            assert!(
                leaked.is_empty(),
                "{key} leaked engine internals: {leaked:?}"
            );
        }
        assert_eq!(
            p["hasOwnPt"], false,
            "hasOwnProperty revealed a bridge global"
        );
        assert_eq!(
            p["gopdHidden"], true,
            "getOwnPropertyDescriptor revealed a bridge global"
        );
        // ...yet stays callable by bare name, which the driver relies on.
        assert_eq!(
            p["callable"], "function",
            "bridge global is no longer callable"
        );

        // The classic tell, and that it is a prototype getter rather than an own prop.
        assert_eq!(p["webdriver"], false);
        assert_eq!(
            p["webdriverOwn"], false,
            "webdriver must not be an own property"
        );

        // Everything page-visible must report as native code.
        for (name, src) in p["natives"].as_object().expect("natives object") {
            let src = src.as_str().unwrap_or_default();
            assert!(
                src.contains("[native code]"),
                "{name} leaks JS source instead of [native code]: {src}"
            );
        }

        // Prototype chains still hold (masking must not break identity).
        assert_eq!(
            p["instanceOf"],
            serde_json::json!([true, true, true, true]),
            "instanceof relationships broken"
        );
    }

    /// `performance` must agree with the wall clock and look like Chrome's. The
    /// old shim was a bare object with `timeOrigin === 0` and a `now()` frozen at
    /// the virtual-timer clock — trivially detectable, since real Chrome satisfies
    /// `timeOrigin + now() ≈ Date.now()`.
    #[tokio::test]
    async fn performance_is_coherent_with_the_wall_clock() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();

        let p = probe(
            &ctx,
            r#"__ptJSON.stringify({
              own: Object.getOwnPropertyNames(performance),
              timingOwn: Object.getOwnPropertyNames(performance.timing),
              tag: Object.prototype.toString.call(performance),
              isInstance: performance instanceof Performance,
              timeOrigin: performance.timeOrigin,
              skew: Math.abs(performance.timeOrigin + performance.now() - Date.now()),
              monotonic: (() => { const a = performance.now(); return performance.now() >= a; })(),
              ordered: (t => t.loadEventEnd >= t.domComplete && t.domComplete >= t.domInteractive
                        && t.domInteractive >= t.responseEnd && t.responseEnd >= t.requestStart
                        && t.requestStart >= t.navigationStart)(performance.timing),
              navigationStartAtOrigin: performance.timing.navigationStart === performance.timeOrigin,
              navType: performance.navigation.type,
              heapLimit: performance.memory.jsHeapSizeLimit,
              entriesIsArray: Array.isArray(performance.getEntries()),
              natives: {
                now: performance.now.toString(),
                Performance: Performance.toString(),
                timeOriginGetter: Object.getOwnPropertyDescriptor(Performance.prototype, 'timeOrigin').get.toString()
              }
            })"#,
        )
        .await;

        // Like every other object we hand out, state lives on the prototype.
        for key in ["own", "timingOwn"] {
            let leaked = p[key]
                .as_array()
                .unwrap_or_else(|| panic!("probe missing {key}"));
            assert!(
                leaked.is_empty(),
                "{key} exposes own properties: {leaked:?}"
            );
        }
        assert_eq!(p["tag"], "[object Performance]");
        assert_eq!(p["isInstance"], true);

        // `timeOrigin` is a real epoch timestamp, not 0, and the pair tracks the
        // wall clock — the cross-check a fingerprinter actually runs.
        let origin = p["timeOrigin"].as_f64().expect("timeOrigin is a number");
        assert!(
            (1.7e12..4.0e12).contains(&origin),
            "timeOrigin is not a plausible epoch ms: {origin}"
        );
        let skew = p["skew"].as_f64().expect("skew is a number");
        assert!(
            skew < 50.0,
            "timeOrigin + now() drifts from Date.now() by {skew}ms"
        );
        assert_eq!(p["monotonic"], true, "performance.now() went backwards");

        // Legacy navigation timing: present, ordered, anchored at the origin.
        assert_eq!(
            p["ordered"], true,
            "performance.timing milestones are out of order"
        );
        assert_eq!(p["navigationStartAtOrigin"], true);
        assert_eq!(p["navType"], 0);
        assert!(
            p["heapLimit"].as_f64().unwrap_or(0.0) > 0.0,
            "performance.memory missing"
        );
        assert_eq!(p["entriesIsArray"], true);

        for (name, src) in p["natives"].as_object().expect("natives object") {
            let src = src.as_str().unwrap_or_default();
            assert!(src.contains("[native code]"), "{name} is not masked: {src}");
        }
    }

    /// WebCrypto must be *real*: `crypto.subtle` was previously absent altogether
    /// (an instant tell — every browser on a secure origin has it) and
    /// `getRandomValues` was a seeded xorshift. It is now backed by native Rust
    /// primitives, so a page that digests a known input and checks the answer sees
    /// what Chrome would. Known-answer vectors pin correctness; the shape checks
    /// pin that it still looks native.
    #[tokio::test]
    async fn webcrypto_is_real_and_looks_native() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();

        // SubtleCrypto is promise-based, so drive the event loop before reading.
        ctx.evaluate(
            r#"globalThis.__t = {};
            (async () => {
              const hex = (b) => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
              const abc = new Uint8Array([97,98,99]);
              const S = crypto.subtle;
              __t.sha256 = hex(await S.digest('SHA-256', abc));
              __t.sha1 = hex(await S.digest('SHA-1', abc));
              const hk = await S.importKey('raw', new Uint8Array([107,101,121]), { name:'HMAC', hash:'SHA-256' }, true, ['sign','verify']);
              const sig = await S.sign('HMAC', hk, abc);
              __t.verifyOk = await S.verify('HMAC', hk, sig, abc);
              __t.verifyBad = await S.verify('HMAC', hk, new Uint8Array(32), abc);
              const ak = await S.importKey('raw', new Uint8Array(16), 'AES-GCM', true, ['encrypt','decrypt']);
              const iv = crypto.getRandomValues(new Uint8Array(12));
              const ct = await S.encrypt({ name:'AES-GCM', iv }, ak, abc);
              __t.gcmRoundTrip = hex(await S.decrypt({ name:'AES-GCM', iv }, ak, ct));
              const pk = await S.importKey('raw', new Uint8Array([112,119]), 'PBKDF2', false, ['deriveBits']);
              __t.pbkdf2Bytes = (await S.deriveBits({ name:'PBKDF2', hash:'SHA-256', salt:new Uint8Array(8), iterations:10 }, pk, 256)).byteLength;
              const gk = await S.generateKey({ name:'AES-GCM', length:256 }, true, ['encrypt']);
              __t.generatedBytes = (await S.exportKey('raw', gk)).byteLength;
              __t.keyOwn = Object.getOwnPropertyNames(gk);
              __t.cryptoOwn = Object.getOwnPropertyNames(crypto);
              __t.tags = [Object.prototype.toString.call(crypto),
                          Object.prototype.toString.call(crypto.subtle),
                          Object.prototype.toString.call(gk)];
              __t.isSubtle = crypto.subtle instanceof SubtleCrypto;
              __t.uuid = crypto.randomUUID();
              __t.randomNonZero = crypto.getRandomValues(new Uint32Array(8)).some(x => x !== 0);
              __t.distinct = crypto.randomUUID() !== crypto.randomUUID();
              __t.natives = { digest: S.digest.toString(), getRandomValues: crypto.getRandomValues.toString() };
              __t.rejects = await S.digest('MD5', abc).then(() => 'resolved', e => e.name);
            })().catch(e => { __t.err = String(e); });"#,
        )
        .await
        .unwrap();
        ctx.run_event_loop().await.ok();
        let p = probe(&ctx, "__ptJSON.stringify(__t)").await;

        assert!(p.get("err").is_none(), "WebCrypto threw: {:?}", p["err"]);

        // Known-answer vectors — a fake implementation cannot produce these.
        assert_eq!(
            p["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(p["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(p["verifyOk"], true, "HMAC did not verify its own signature");
        assert_eq!(p["verifyBad"], false, "HMAC verified a bogus signature");
        assert_eq!(p["gcmRoundTrip"], "616263", "AES-GCM did not round-trip");
        assert_eq!(p["pbkdf2Bytes"], 32);
        assert_eq!(p["generatedBytes"], 32);

        // Randomness is real, not a seeded PRNG.
        assert_eq!(
            p["randomNonZero"], true,
            "getRandomValues produced all zeroes"
        );
        assert_eq!(p["distinct"], true, "randomUUID repeated itself");
        let uuid = p["uuid"].as_str().unwrap_or_default();
        assert_eq!(uuid.len(), 36, "randomUUID is malformed: {uuid}");
        assert_eq!(&uuid[14..15], "4", "randomUUID is not version 4: {uuid}");

        // ...and it still looks like a browser's.
        for key in ["keyOwn", "cryptoOwn"] {
            let leaked = p[key]
                .as_array()
                .unwrap_or_else(|| panic!("probe missing {key}"));
            assert!(
                leaked.is_empty(),
                "{key} exposes own properties: {leaked:?}"
            );
        }
        assert_eq!(
            p["tags"],
            serde_json::json!([
                "[object Crypto]",
                "[object SubtleCrypto]",
                "[object CryptoKey]"
            ])
        );
        assert_eq!(p["isSubtle"], true);
        for (name, src) in p["natives"].as_object().expect("natives object") {
            let src = src.as_str().unwrap_or_default();
            assert!(src.contains("[native code]"), "{name} is not masked: {src}");
        }
        // Unsupported algorithms reject the way the spec says, not silently.
        assert_eq!(p["rejects"], "NotSupportedError");
    }

    /// Canvas fingerprinting is differential: draw something, hash `toDataURL()`,
    /// compare. This used to return one fixed string, so an empty canvas and an
    /// elaborate drawing hashed identically — the probe catches that instantly.
    /// The output now derives from what was actually drawn, solid fills are
    /// rendered exactly, and an identical drawing still hashes the same (which
    /// fingerprint stability requires).
    #[tokio::test]
    async fn canvas_output_depends_on_what_was_drawn() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();

        let p = probe(
            &ctx,
            r#"(() => {
              const mk = (draw) => {
                const c = document.createElement('canvas');
                c.width = 200; c.height = 50;
                draw(c.getContext('2d'));
                return c;
              };
              const a = mk(g => { g.fillStyle = '#ff0000'; g.fillRect(0,0,100,50); g.fillText('hello', 10, 20); });
              const b = mk(g => { g.fillStyle = '#0000ff'; g.fillRect(0,0,10,10); g.fillText('COMPLETELY different', 2, 40); });
              const again = mk(g => { g.fillStyle = '#ff0000'; g.fillRect(0,0,100,50); g.fillText('hello', 10, 20); });
              const blank = mk(() => {});
              const filled = a.getContext('2d').getImageData(5, 5, 1, 1).data;
              const untouched = a.getContext('2d').getImageData(199, 49, 1, 1).data;
              return __ptJSON.stringify({
                differ: a.toDataURL() !== b.toDataURL(),
                blankDiffers: blank.toDataURL() !== a.toDataURL(),
                stable: a.toDataURL() === again.toDataURL(),
                isPng: a.toDataURL().slice(0, 22) === 'data:image/png;base64,',
                grows: a.toDataURL().length > blank.toDataURL().length,
                filledPixel: Array.from(filled),
                untouchedPixel: Array.from(untouched),
                dims: [a.width, a.height],
                canvasOwn: Object.getOwnPropertyNames(a)
              });
            })()"#,
        )
        .await;

        // The property the probe actually tests.
        assert_eq!(
            p["differ"], true,
            "two different drawings produced the same canvas hash"
        );
        assert_eq!(
            p["blankDiffers"], true,
            "an empty canvas hashed the same as a drawn one"
        );
        // ...without losing the stability a real fingerprint has.
        assert_eq!(
            p["stable"], true,
            "the same drawing hashed differently twice"
        );

        // A real PNG of the canvas, whose size tracks its content.
        assert_eq!(p["isPng"], true, "toDataURL is not a PNG data URL");
        assert_eq!(
            p["grows"], true,
            "drawn canvas did not encode larger than a blank one"
        );
        assert_eq!(
            p["dims"],
            serde_json::json!([200, 50]),
            "canvas dimensions not reflected"
        );

        // Solid fills are rendered exactly: filling red and reading the pixel back
        // returns red, and an untouched corner stays transparent.
        assert_eq!(
            p["filledPixel"],
            serde_json::json!([255, 0, 0, 255]),
            "fillRect did not render its colour"
        );
        assert_eq!(
            p["untouchedPixel"],
            serde_json::json!([0, 0, 0, 0]),
            "an undrawn pixel was not transparent"
        );

        // Setting width/height and taking a context must not leave own properties.
        let leaked = p["canvasOwn"].as_array().expect("canvasOwn");
        assert!(
            leaked.is_empty(),
            "canvas exposes own properties: {leaked:?}"
        );
    }

    /// WebGL fingerprinting renders a scene and reads it back. Every GL call used
    /// to be a no-op, so `readPixels` returned zeroes regardless and two different
    /// scenes compared equal — the same differential tell the 2D canvas had. The
    /// identity strings (vendor/renderer/ANGLE) were already right; this pins both.
    #[tokio::test]
    async fn webgl_readback_reflects_what_was_rendered() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();

        let p = probe(
            &ctx,
            r#"(() => {
              const mk = (r, g, b) => {
                const c = document.createElement('canvas'); c.width = 64; c.height = 64;
                const gl = c.getContext('webgl');
                gl.clearColor(r, g, b, 1); gl.clear(gl.COLOR_BUFFER_BIT);
                const out = new Uint8Array(16);
                gl.readPixels(0, 0, 2, 2, gl.RGBA, gl.UNSIGNED_BYTE, out);
                return { canvas: c, gl, px: Array.from(out) };
              };
              const red = mk(1, 0, 0), blue = mk(0, 0, 1), red2 = mk(1, 0, 0);
              const blank = document.createElement('canvas'); blank.width = 64; blank.height = 64;
              const dbg = red.gl.getExtension('WEBGL_debug_renderer_info');
              return __ptJSON.stringify({
                redPixels: red.px.slice(0, 4),
                differ: red.px.join() !== blue.px.join(),
                stable: red.px.join() === red2.px.join(),
                notBlank: red.canvas.toDataURL() !== blank.toDataURL(),
                vendor: red.gl.getParameter(red.gl.VENDOR),
                renderer: red.gl.getParameter(red.gl.RENDERER),
                unmasked: dbg ? red.gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : null,
                maxTexture: red.gl.getParameter(red.gl.MAX_TEXTURE_SIZE),
                extensions: (red.gl.getSupportedExtensions() || []).length,
                // A canvas keeps one context type, as in a real browser.
                conflictingContext: red.canvas.getContext('2d'),
                canvasOwn: Object.getOwnPropertyNames(red.canvas)
              });
            })()"#,
        )
        .await;

        // Clearing to red must read back red — the readback tracks the render.
        assert_eq!(
            p["redPixels"],
            serde_json::json!([255, 0, 0, 255]),
            "clearColor+clear did not show up in readPixels"
        );
        assert_eq!(
            p["differ"], true,
            "two differently-cleared contexts read back identically"
        );
        assert_eq!(
            p["stable"], true,
            "the same render read back differently twice"
        );
        assert_eq!(
            p["notBlank"], true,
            "a rendered WebGL canvas encoded the same as a blank one"
        );

        // The identity surface a fingerprinter reads stays Chrome-shaped.
        assert_eq!(p["vendor"], "WebKit");
        assert_eq!(p["renderer"], "WebKit WebGL");
        assert!(
            p["unmasked"].as_str().unwrap_or_default().contains("ANGLE"),
            "UNMASKED_RENDERER_WEBGL is not an ANGLE string: {:?}",
            p["unmasked"]
        );
        assert_eq!(p["maxTexture"], 16384);
        assert!(
            p["extensions"].as_u64().unwrap_or(0) > 20,
            "implausibly few WebGL extensions"
        );

        // Asking for a conflicting context type yields null, not a second context.
        assert!(
            p["conflictingContext"].is_null(),
            "canvas handed out a second context type"
        );
        let leaked = p["canvasOwn"].as_array().expect("canvasOwn");
        assert!(
            leaked.is_empty(),
            "canvas exposes own properties: {leaked:?}"
        );
    }

    /// Audio fingerprinting renders an oscillator through a compressor in an
    /// `OfflineAudioContext` and hashes the samples. The shim rendered a fixed
    /// sine keyed only on the seed, so every graph hashed the same — a 10 kHz and
    /// a 440 Hz oscillator were indistinguishable. The buffer now derives from the
    /// actual graph (node params + connections), so different graphs differ and an
    /// identical graph stays stable.
    #[tokio::test]
    async fn audio_render_depends_on_the_graph() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();

        // Drive the classic FingerprintJS shape, then stash a raw-sample hash of
        // each rendered buffer (what a real probe actually compares).
        let setup = r#"(() => {
          const render = (freq) => {
            const c = new OfflineAudioContext(1, 4410, 44100);
            const osc = c.createOscillator(); osc.type = 'triangle'; osc.frequency.value = freq;
            const comp = c.createDynamicsCompressor();
            comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
            comp.attack.value = 0; comp.release.value = 0.25;
            osc.connect(comp); comp.connect(c.destination); osc.start(0);
            return c.startRendering();
          };
          const hash = (buf) => {
            const d = buf.getChannelData(0); let h = 0;
            for (let i = 4000; i < 4400; i++) { h = (Math.imul(h, 31) + Math.round(d[i] * 1e7)) | 0; }
            return h;
          };
          let done = null; const ready = new Promise(r => { done = r; });
          Promise.all([render(10000), render(440), render(10000)]).then(([a, b, a2]) => {
            globalThis.__audio = {
              hashA: hash(a), hashB: hash(b), hashA2: hash(a2),
              nonSilent: (() => { const d = a.getChannelData(0); for (let i = 0; i < d.length; i++) if (d[i] !== 0) return true; return false; })(),
              len: a.length, sampleRate: a.sampleRate, channels: a.numberOfChannels, duration: a.duration,
              analyserByFreq: (() => {
                const mk = (f) => { const c = new OfflineAudioContext(1, 4410, 44100); const o = c.createOscillator(); o.frequency.value = f; const an = c.createAnalyser(); o.connect(an); const arr = new Float32Array(16); an.getFloatFrequencyData(arr); let s = ''; for (const x of arr) s += x + ','; return s; };
                return mk(1000) !== mk(9000);
              })(),
              tags: [Object.prototype.toString.call(new AudioContext()), typeof AudioContext, typeof OfflineAudioContext]
            };
            done(true);
          });
          return ready;
        })()"#;
        ctx.evaluate(setup).await.unwrap();
        ctx.run_event_loop().await.ok();
        let p = probe(&ctx, "__ptJSON.stringify(globalThis.__audio || null)").await;
        assert!(!p.is_null(), "audio render promise never resolved");

        // The property a fingerprinter checks: different graphs → different hash.
        assert_ne!(
            p["hashA"], p["hashB"],
            "a 10kHz and a 440Hz oscillator hashed identically"
        );
        // ...and the same graph is reproducible (fingerprint stability).
        assert_eq!(
            p["hashA"], p["hashA2"],
            "the same graph rendered two different hashes"
        );
        assert_eq!(p["nonSilent"], true, "rendered buffer was silent");
        assert_eq!(
            p["analyserByFreq"], true,
            "analyser output did not depend on the graph"
        );

        // Buffer shape is what was requested.
        assert_eq!(p["len"], 4410);
        assert_eq!(p["sampleRate"], 44100);
        assert_eq!(p["channels"], 1);

        // Interfaces present and correctly tagged under a Chrome UA.
        assert_eq!(p["tags"][0], "[object AudioContext]");
        assert_eq!(p["tags"][1], "function");
        assert_eq!(p["tags"][2], "function");
    }

    #[tokio::test]
    async fn tracker_scripts_are_blocked_but_benign_ones_run() {
        let _serial = serial().await;
        // Real network so external scripts are actually fetched; the tracker one is
        // dropped before the wire, the benign one 404s but is attempted.
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            block_trackers: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        let html = r#"<!DOCTYPE html><html><head></head><body>
            <script>window.__ran = 'inline';</script>
            <script src="https://www.google-analytics.com/analytics.js"></script>
            </body></html>"#;
        ctx.load_html("https://example.com/", html).await.unwrap();

        // The inline script ran normally.
        assert_eq!(
            ctx.evaluate("window.__ran").await.unwrap(),
            Value::String("inline".into())
        );
        // The tracker request never hit the wire — it's logged with status 0 and no
        // request to google-analytics.com produced a real (non-zero) response.
        let ga = ctx
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.url.contains("google-analytics.com"))
            .map(|r| r.status)
            .collect::<Vec<_>>();
        assert_eq!(
            ga,
            vec![0],
            "tracker script should be blocked (status 0), got {ga:?}"
        );
    }

    #[test]
    fn tls_emulation_os_follows_the_profile() {
        use nokk_stealth::FingerprintProfile;
        // Each JS profile's OS maps to the matching TLS emulation OS, so the
        // ClientHello never contradicts the User-Agent.
        assert_eq!(
            emulation_os_for(&FingerprintProfile::ChromeLinux.stealth()),
            nokk_net::EmulationOs::Linux
        );
        assert_eq!(
            emulation_os_for(&FingerprintProfile::ChromeWindows.stealth()),
            nokk_net::EmulationOs::Windows
        );
        assert_eq!(
            emulation_os_for(&FingerprintProfile::ChromeMac.stealth()),
            nokk_net::EmulationOs::Mac
        );
    }

    #[test]
    fn rotation_off_gives_every_context_the_default_profile() {
        let eng = Engine::new(EngineConfig::default()).unwrap();
        let d = StealthProfile::default();
        for id in ["", "ctx-a", "ctx-b", "session-x"] {
            assert_eq!(eng.stealth_for_identity(id).user_agent, d.user_agent);
            assert_eq!(eng.stealth_for_identity(id).platform, d.platform);
        }
    }

    #[test]
    fn rotation_is_per_identity_stable_and_coherent() {
        let eng = Engine::new(EngineConfig {
            rotate_fingerprint: true,
            ..Default::default()
        })
        .unwrap();

        // The default (empty-identity) context keeps the default profile so the
        // shared default client's TLS OS stays coherent with its JS profile.
        assert_eq!(
            eng.stealth_for_identity("").platform,
            StealthProfile::default().platform
        );

        // A given identity always resolves to the same machine (stable hash).
        assert_eq!(
            eng.stealth_for_identity("ctx-a").user_agent,
            eng.stealth_for_identity("ctx-a").user_agent
        );

        // Every resolved profile is internally coherent: its JS Client-Hints
        // platform and the TLS emulation OS it will use agree.
        for i in 0..40 {
            let id = format!("browser-context-{i}");
            let sp = eng.stealth_for_identity(&id);
            let os = emulation_os_for(&sp);
            let expected = match sp.ua_platform.as_str() {
                "Windows" => nokk_net::EmulationOs::Windows,
                "macOS" => nokk_net::EmulationOs::Mac,
                "Linux" => nokk_net::EmulationOs::Linux,
                other => panic!("unexpected ua_platform {other}"),
            };
            assert_eq!(os, expected, "TLS OS must match the JS platform for {id}");
        }

        // Rotation actually surfaces more than one OS across a spread of contexts.
        let seen: std::collections::HashSet<_> = (0..40)
            .map(|i| {
                eng.stealth_for_identity(&format!("browser-context-{i}"))
                    .ua_platform
            })
            .collect();
        assert!(
            seen.len() >= 2,
            "rotation should present multiple OS profiles, saw {seen:?}"
        );
    }

    #[test]
    fn geoip_is_off_by_default() {
        assert!(!EngineConfig::default().geoip_timezone);
    }

    #[test]
    fn geo_adjusted_bootstrap_reflects_the_exit_ip_zone() {
        // The geo override is applied when composing a context's bootstrap: an
        // exit IP in Germany moves the rendered Intl timezone + locale, while the
        // default (no-geo) bootstrap keeps the profile's own zone. This exercises
        // the pure composition path without a live lookup.
        let eng = Engine::new(EngineConfig {
            rotate_fingerprint: true,
            geoip_timezone: true,
            ..Default::default()
        })
        .unwrap();
        let profile = Some(nokk_stealth::FingerprintProfile::ChromeWindows);
        let geo = nokk_net::GeoInfo {
            timezone: "Europe/Berlin".to_string(),
            country_code: "DE".to_string(),
        };

        let with_geo = eng.inner.context_bootstrap(profile, Some(&geo));
        assert!(with_geo.contains("Europe/Berlin"));
        assert!(with_geo.contains("Central European Standard Time"));
        // Windows OS identity is untouched by the geo override.
        assert!(with_geo.contains(r#"platform: "Windows""#));

        let without_geo = eng.inner.context_bootstrap(profile, None);
        assert!(!without_geo.contains("Europe/Berlin"));
        assert_ne!(with_geo, without_geo);

        // Cached: same inputs return the identical rendering.
        assert_eq!(with_geo, eng.inner.context_bootstrap(profile, Some(&geo)));
    }

    #[tokio::test]
    async fn inner_text_excludes_script_and_style() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        let html = r#"<!DOCTYPE html><html><head><title>t</title><style>.x{color:red}</style></head>
            <body>Visible text<script>var s='HIDDEN_SCRIPT';</script><style>p{margin:0}</style><p>More</p></body></html>"#;
        ctx.load_html("https://example.com/", html).await.unwrap();
        match ctx.evaluate("document.body.innerText").await.unwrap() {
            Value::String(s) => {
                assert!(
                    s.contains("Visible text") && s.contains("More"),
                    "missing visible text: {s}"
                );
                assert!(
                    !s.contains("HIDDEN_SCRIPT"),
                    "script text leaked into innerText: {s}"
                );
                assert!(
                    !s.contains("margin") && !s.contains("color"),
                    "style text leaked into innerText: {s}"
                );
            }
            v => panic!("expected string, got {v:?}"),
        }
    }

    #[tokio::test]
    async fn meta_refresh_target_is_detected() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // Capital `Refresh` exercises the case-insensitive match the nav loop uses.
        let html = r#"<!DOCTYPE html><html><head>
            <meta http-equiv="Refresh" content="0; url=/next?x=1">
            </head><body>Please enable JavaScript</body></html>"#;
        ctx.load_html("https://example.com/search", html)
            .await
            .unwrap();
        let detect = r#"(() => {
          const metas = document.getElementsByTagName('meta');
          for (let k = 0; k < metas.length; k++) { const m = metas[k];
            if ((m.getAttribute('http-equiv')||'').toLowerCase() !== 'refresh') continue;
            const c = m.getAttribute('content')||''; const i = c.toLowerCase().indexOf('url=');
            if (i < 0) continue; return c.slice(i+4).trim().replace(/^['"]/,'').replace(/['"]$/,'');
          } return ''; })()"#;
        assert_eq!(
            ctx.evaluate(detect).await.unwrap(),
            Value::String("/next?x=1".into())
        );
    }

    #[tokio::test]
    async fn interaction_click_and_type_via_synthetic_layout() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        let html = r#"<!DOCTYPE html><html><head><title>i</title></head><body>
            <button id="btn">go</button><div id="out">idle</div>
            <input id="inp" type="text" value="">
            <script>
              document.getElementById('btn').addEventListener('click', function () {
                document.getElementById('out').textContent = 'clicked';
              });
            </script></body></html>"#;
        ctx.load_html("https://example.com/", html).await.unwrap();

        // Rendered elements report a non-empty synthetic box and are connected.
        assert_eq!(
            ctx.evaluate("document.getElementById('btn').getBoundingClientRect().width > 0")
                .await
                .unwrap(),
            Value::String("true".into())
        );
        assert_eq!(
            ctx.evaluate("document.getElementById('btn').isConnected")
                .await
                .unwrap(),
            Value::String("true".into())
        );

        // A synthetic mouse press+release at the button's centre hit-tests back to
        // it and fires its click handler.
        let click = "(() => { const r = document.getElementById('btn').getBoundingClientRect(); \
            const x = r.x + r.width / 2, y = r.y + r.height / 2; \
            __pt_mouse('mousePressed', x, y, 'left', 1); __pt_mouse('mouseReleased', x, y, 'left', 1); \
            return document.getElementById('out').textContent; })()";
        assert_eq!(
            ctx.evaluate(click).await.unwrap(),
            Value::String("clicked".into())
        );

        // Focusing the input and inserting text updates its value and fires input.
        let typing = "(() => { __pt_focusNode(document.getElementById('inp')); \
            __pt_insertText('hi'); return document.getElementById('inp').value; })()";
        assert_eq!(
            ctx.evaluate(typing).await.unwrap(),
            Value::String("hi".into())
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

    /// Delays are real, and the page can prove it: a timer that fires early is a
    /// tell (`Date.now()` keeps wall time whatever the timer queue does) and it
    /// breaks every watchdog written against the clock.
    #[tokio::test]
    async fn a_timer_waits_out_its_delay_on_the_wall_clock() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.evaluate(
            "globalThis.t0 = Date.now(); globalThis.measured = -1;
             setTimeout(() => { measured = Date.now() - t0; }, 120);",
        )
        .await
        .unwrap();

        let started = std::time::Instant::now();
        ctx.run_event_loop().await.unwrap();
        let measured = match ctx.evaluate("measured").await.unwrap() {
            Value::String(s) => s.parse::<i64>().unwrap_or(-1),
            v => panic!("expected a number, got {v:?}"),
        };
        assert!(
            measured >= 110,
            "the page must see the delay it asked for, measured {measured}ms"
        );
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(110),
            "and the loop must actually have spent that time"
        );
    }

    #[tokio::test]
    async fn event_loop_runs_timers_in_due_order() {
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
        // 50ms comes due before 100ms; the async continuation (a microtask off the
        // 50ms timer) runs before the 100ms timer.
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

    // With `--features render`, the canvas is backed by the real rasterizer, so
    // `fillText` must produce genuine glyph pixels (not the JS synthesis stamp) and
    // `measureText` must return a real font advance. Off by default; this only runs
    // for the render build.
    #[cfg(feature = "render")]
    #[tokio::test]
    async fn render_canvas_fill_text_makes_real_glyph_pixels() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        let probe = r#"(() => {
            const c = document.createElement('canvas'); c.width = 120; c.height = 40;
            const g = c.getContext('2d');
            g.fillStyle = '#ff0000'; g.font = '20px sans-serif';
            g.fillText('nokk', 4, 28);
            const d = g.getImageData(0, 0, 120, 40).data;
            let opaque = 0, red = 0;
            for (let i = 0; i < d.length; i += 4) {
                if (d[i + 3] > 0) { opaque++; if (d[i] > 100 && d[i + 1] < 80) red++; }
            }
            const w = g.measureText('nokk').width;
            return __ptJSON.stringify({ opaque, red, w: Math.round(w) });
        })()"#;
        let out = match ctx.evaluate(probe).await.unwrap() {
            Value::String(s) => s,
            v => panic!("expected string, got {v:?}"),
        };
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let opaque = v["opaque"].as_u64().unwrap();
        let red = v["red"].as_u64().unwrap();
        let w = v["w"].as_u64().unwrap();
        assert!(
            opaque > 30,
            "fillText must cover real glyph pixels, got {opaque}"
        );
        assert!(
            red > 20,
            "glyph pixels must carry the fill color, got {red} red of {opaque}"
        );
        assert!(
            w > 20 && w < 90,
            "measureText advance should be a real width, got {w}"
        );
    }

    // A filled arc (the classic canvas-fingerprint shape) must rasterize to a real
    // disc of pixels via native paths — not the deterministic bbox stamp.
    #[cfg(feature = "render")]
    #[tokio::test]
    async fn render_canvas_fill_arc_makes_a_real_disc() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        let probe = r#"(() => {
            const c = document.createElement('canvas'); c.width = 40; c.height = 40;
            const g = c.getContext('2d');
            g.fillStyle = '#00ff00';
            g.beginPath(); g.arc(20, 20, 15, 0, 2 * Math.PI); g.fill();
            const d = g.getImageData(0, 0, 40, 40).data;
            const at = (x, y) => d[(y * 40 + x) * 4 + 3]; // alpha
            let green = 0;
            for (let i = 0; i < d.length; i += 4) if (d[i + 1] > 100 && d[i + 3] > 0) green++;
            return __ptJSON.stringify({ center: at(20, 20), corner: at(1, 1), green });
        })()"#;
        let out = match ctx.evaluate(probe).await.unwrap() {
            Value::String(s) => s,
            v => panic!("expected string, got {v:?}"),
        };
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            v["center"].as_u64().unwrap() > 0,
            "arc center must be filled"
        );
        assert_eq!(
            v["corner"].as_u64().unwrap(),
            0,
            "outside the disc stays transparent"
        );
        // A r=15 disc is ~700px; well above any bbox-stamp artifact.
        assert!(
            v["green"].as_u64().unwrap() > 500,
            "filled disc must be green pixels, got {}",
            v["green"]
        );
    }

    // A linear-gradient fillRect must actually vary across the rect (red→blue),
    // proving the native gradient shader is wired, not a flat/stamped fill.
    #[cfg(feature = "render")]
    #[tokio::test]
    async fn render_canvas_linear_gradient_varies() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        let probe = r#"(() => {
            const c = document.createElement('canvas'); c.width = 60; c.height = 8;
            const g = c.getContext('2d');
            const grad = g.createLinearGradient(0, 0, 60, 0);
            grad.addColorStop(0, '#ff0000'); grad.addColorStop(1, '#0000ff');
            g.fillStyle = grad; g.fillRect(0, 0, 60, 8);
            const d = g.getImageData(0, 0, 60, 8).data;
            const px = (x) => { const i = (4 * 60 + x) * 4; return [d[i], d[i + 2], d[i + 3]]; };
            const l = px(2), r = px(57);
            return __ptJSON.stringify({ l, r });
        })()"#;
        let out = match ctx.evaluate(probe).await.unwrap() {
            Value::String(s) => s,
            v => panic!("expected string, got {v:?}"),
        };
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let l = &v["l"];
        let r = &v["r"];
        assert!(
            l[0].as_u64().unwrap() > 150 && l[1].as_u64().unwrap() < 100,
            "left edge red-ish, got {l:?}"
        );
        assert!(
            r[1].as_u64().unwrap() > 150 && r[0].as_u64().unwrap() < 100,
            "right edge blue-ish, got {r:?}"
        );
    }

    // End-to-end WebGL through the engine: a real page-style draw (compile shaders,
    // upload a triangle, drawArrays) must produce genuine pixels in readPixels via
    // the Mesa backend. Runs for real only where EGL is present (mesa container/CI);
    // the JS detects the absence of the natives and the assert on a green pixel
    // still holds because the fallback stamp is deterministic — so we gate the
    // strict color check on the natives being active.
    #[cfg(feature = "webgl")]
    #[tokio::test]
    async fn render_webgl_draw_triangle_via_engine() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        let probe = r#"(() => {
            const c = document.createElement('canvas'); c.width = 32; c.height = 32;
            const gl = c.getContext('webgl');
            const native = typeof __pt_glAvailable === 'function' && __pt_glAvailable();
            gl.clearColor(0, 0, 0, 1); gl.clear(gl.COLOR_BUFFER_BIT);
            const vs = gl.createShader(gl.VERTEX_SHADER);
            gl.shaderSource(vs, 'attribute vec2 p; void main(){ gl_Position = vec4(p,0.0,1.0); }');
            gl.compileShader(vs);
            const fs = gl.createShader(gl.FRAGMENT_SHADER);
            gl.shaderSource(fs, 'precision mediump float; void main(){ gl_FragColor = vec4(0.0,1.0,0.0,1.0); }');
            gl.compileShader(fs);
            const prog = gl.createProgram();
            gl.attachShader(prog, vs); gl.attachShader(prog, fs); gl.linkProgram(prog); gl.useProgram(prog);
            const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
            gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-0.8,-0.8, 0.8,-0.8, 0.0,0.8]), 0x88E4);
            const loc = gl.getAttribLocation(prog, 'p');
            gl.enableVertexAttribArray(loc);
            gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
            gl.drawArrays(0x0004, 0, 3);
            const px = new Uint8Array(32 * 32 * 4);
            gl.readPixels(0, 0, 32, 32, gl.RGBA, gl.UNSIGNED_BYTE, px);
            const center = 4 * (16 * 32 + 16);
            const compiled = native ? gl.getShaderParameter(vs, gl.COMPILE_STATUS) : true;
            return __ptJSON.stringify({ native, compiled, cg: px[center + 1], ca: px[center + 3] });
        })()"#;
        let out = match ctx.evaluate(probe).await.unwrap() {
            Value::String(s) => s,
            v => panic!("expected string, got {v:?}"),
        };
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        // Whether or not EGL is live, the pipeline must run without throwing.
        if v["native"].as_bool().unwrap() {
            assert!(
                v["compiled"].as_bool().unwrap(),
                "shader compiles on the GL backend"
            );
            assert!(
                v["cg"].as_u64().unwrap() > 150,
                "triangle center is green via real GL, got {}",
                v["cg"]
            );
        } else {
            eprintln!("skip strict check: webgl natives inactive (no EGL here)");
        }
    }

    /// A textured quad — the shape most WebGL fingerprint probes actually draw.
    /// With texturing stubbed the sampler reads black and every scene hashes the
    /// same, so this asserts the uploaded texels come back out.
    #[tokio::test]
    async fn render_webgl_texture_upload_via_engine() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        let probe = r#"(() => {
            const c = document.createElement('canvas'); c.width = 16; c.height = 16;
            const gl = c.getContext('webgl');
            const native = typeof __pt_glAvailable === 'function' && __pt_glAvailable();
            gl.clearColor(0, 0, 0, 1); gl.clear(gl.COLOR_BUFFER_BIT);
            const vs = gl.createShader(gl.VERTEX_SHADER);
            gl.shaderSource(vs, 'attribute vec2 p; varying vec2 uv;' +
              'void main(){ uv = p * 0.5 + 0.5; gl_Position = vec4(p,0.0,1.0); }');
            gl.compileShader(vs);
            const fs = gl.createShader(gl.FRAGMENT_SHADER);
            gl.shaderSource(fs, 'precision mediump float; uniform sampler2D t; varying vec2 uv;' +
              'void main(){ gl_FragColor = texture2D(t, uv); }');
            gl.compileShader(fs);
            const prog = gl.createProgram();
            gl.attachShader(prog, vs); gl.attachShader(prog, fs); gl.linkProgram(prog); gl.useProgram(prog);
            const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
            gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, 1,1]), 0x88E4);
            const loc = gl.getAttribLocation(prog, 'p');
            gl.enableVertexAttribArray(loc);
            gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

            const tex = gl.createTexture();
            const isTex = tex instanceof WebGLTexture;
            gl.activeTexture(0x84C0);
            gl.bindTexture(gl.TEXTURE_2D, tex);
            gl.pixelStorei(0x9240, true);                       // UNPACK_FLIP_Y_WEBGL
            gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 1, 1, 0, gl.RGBA, gl.UNSIGNED_BYTE,
              new Uint8Array([12, 220, 130, 255]));
            gl.texParameteri(gl.TEXTURE_2D, 0x2801, 0x2600);    // MIN_FILTER = NEAREST
            gl.texParameteri(gl.TEXTURE_2D, 0x2800, 0x2600);    // MAG_FILTER = NEAREST
            gl.uniform1i(gl.getUniformLocation(prog, 't'), 0);
            gl.drawArrays(0x0005, 0, 4);                        // TRIANGLE_STRIP

            const px = new Uint8Array(16 * 16 * 4);
            gl.readPixels(0, 0, 16, 16, gl.RGBA, gl.UNSIGNED_BYTE, px);
            const i = 4 * (8 * 16 + 8);
            gl.deleteTexture(tex);
            return __ptJSON.stringify({ native, isTex, r: px[i], g: px[i + 1], b: px[i + 2] });
        })()"#;
        let out = match ctx.evaluate(probe).await.unwrap() {
            Value::String(s) => s,
            v => panic!("expected string, got {v:?}"),
        };
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            v["isTex"].as_bool().unwrap(),
            "createTexture returns a WebGLTexture in either backend"
        );
        if v["native"].as_bool().unwrap() {
            assert_eq!(
                (
                    v["r"].as_u64().unwrap(),
                    v["g"].as_u64().unwrap(),
                    v["b"].as_u64().unwrap()
                ),
                (12, 220, 130),
                "the quad samples the texel that was uploaded"
            );
        } else {
            eprintln!("skip strict check: webgl natives inactive (no EGL here)");
        }
    }

    /// The page surface an anti-bot loader reads before it will talk to its own
    /// widget. Cloudflare's `api.js` answers the widget's `requestExtraParams`
    /// with a report built from exactly these, and a `ReferenceError` anywhere in
    /// it is invisible: it throws inside a `message` listener, where the exception
    /// is swallowed, and the widget then waits for a reply that never comes. That
    /// is what `NodeFilter` being undefined cost — every challenge, silently.
    #[tokio::test]
    async fn the_document_report_a_loader_builds_has_no_holes() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        let html = r#"<!DOCTYPE html><html><head><title>t</title>
            <style>b{color:red}</style><link rel="stylesheet" href="/a.css">
            </head><body>
              <img src="/i.png"><a href="/x">x</a><a name="anchor">n</a>
              <form></form><script>var a = 1;</script>
            </body></html>"#;
        ctx.load_html("https://example.com/", html).await.unwrap();

        let probe = r#"(() => {
            const w = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT, null);
            const tags = [];
            for (let n = w.nextNode(); n; n = w.nextNode()) tags.push(n.tagName);
            // A filter that keeps only <a>, exercised through the object form.
            const only = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT,
              { acceptNode: (n) => n.tagName === 'A' ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP });
            let links = 0;
            while (only.nextNode()) links++;
            const it = document.createNodeIterator(document.body, NodeFilter.SHOW_ELEMENT, null);
            let iterated = 0;
            while (it.nextNode()) iterated++;
            return __ptJSON.stringify({
              tags, links, iterated,
              scripts: document.scripts.length, forms: document.forms.length,
              images: document.images.length, docLinks: document.links.length,
              anchors: document.anchors.length, sheets: document.styleSheets.length,
              // Не массив, а коллекция — как на платформе: перебор, но без .map.
              sheetHref: Array.from(document.styleSheets).map(s => s.href || 'inline'),
              collection: [document.scripts.map, Array.isArray(document.forms)]
                .every(x => !x),
              referrer: typeof document.referrer,
              show: [NodeFilter.SHOW_ELEMENT, NodeFilter.SHOW_TEXT, NodeFilter.SHOW_COMMENT],
              walkerType: typeof document.createTreeWalker,
            });
        })()"#;
        let out = match ctx.evaluate(probe).await.unwrap() {
            Value::String(s) => serde_json::from_str::<Value>(&s).unwrap(),
            v => panic!("expected the report, got {v:?}"),
        };

        assert_eq!(
            out["collection"], true,
            "document.scripts/forms are collections, not arrays, as on the platform"
        );
        assert_eq!(
            out["tags"].as_array().unwrap().len(),
            5,
            "the walker visits every element under body: {}",
            out["tags"]
        );
        assert_eq!(out["links"], 2, "a filter that skips is honoured");
        // A NodeIterator yields its root as well; a TreeWalker starts *at* it and
        // only moves forward. Hence six against five over the same tree.
        assert_eq!(out["iterated"], 6, "createNodeIterator walks the same tree");
        assert_eq!(out["scripts"], 1);
        assert_eq!(out["forms"], 1);
        assert_eq!(out["images"], 1);
        assert_eq!(out["docLinks"], 1, "document.links is <a href>, not every <a>");
        assert_eq!(out["anchors"], 1, "and document.anchors is <a name>");
        assert_eq!(out["sheets"], 2, "a <style> and a stylesheet <link>");
        assert_eq!(out["referrer"], "string", "never undefined — it is read raw");
        assert_eq!(
            out["show"],
            serde_json::json!([1, 4, 128]),
            "NodeFilter's constants are the spec's, not invented"
        );
    }

    /// Elements inside a shadow root have geometry. Ours had none — the layout
    /// walked the document tree only — so anything a widget drew into its shadow
    /// tree reported a zero rect. Code that checks visibility before showing an
    /// interactive step reads that as hidden: Cloudflare's loader says so in as
    /// many words, `unexpectedHidden` with reason `zs` (zero size).
    #[tokio::test]
    async fn a_shadow_tree_has_geometry() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let probe = r#"(() => {
            const host = document.createElement('div');
            document.body.appendChild(host);
            const sr = host.attachShadow({ mode: 'closed' });
            const f = document.createElement('iframe');
            f.setAttribute('width', '300'); f.setAttribute('height', '65');
            sr.appendChild(f);
            const r = f.getBoundingClientRect();
            return __ptJSON.stringify({
              w: Math.round(r.width), h: Math.round(r.height),
              connected: f.isConnected, offset: [f.offsetWidth, f.offsetHeight],
            });
        })()"#;
        let out = match ctx.evaluate(probe).await.unwrap() {
            Value::String(s) => serde_json::from_str::<Value>(&s).unwrap(),
            v => panic!("expected the probe result, got {v:?}"),
        };
        assert_eq!(out["connected"], true);
        assert_eq!((out["w"].as_i64(), out["h"].as_i64()), (Some(300), Some(65)),
                   "an element in a closed shadow root is laid out like any other");
        assert_eq!(out["offset"], serde_json::json!([300, 65]));
    }

    /// An element that states its own size reports it. The row layout stands in
    /// for what the engine does not compute; it must not contradict what the page
    /// declared. A widget sized 300x65 answering 1280x20 reads as clipped, and
    /// code that measures before deciding whether it is visible — Cloudflare's
    /// loader measures its widget iframe exactly so — decides wrong.
    #[tokio::test]
    async fn a_declared_size_is_the_size_reported() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let probe = r#"(() => {
            const mk = (f) => { const e = document.createElement('iframe'); f(e); document.body.appendChild(e); return e; };
            const byAttr = mk(e => { e.setAttribute('width', '300'); e.setAttribute('height', '65'); });
            const byStyle = mk(e => { e.style.width = '300px'; e.style.height = '65px'; });
            const plain = mk(() => {});
            const box = (e) => { const r = e.getBoundingClientRect(); return [Math.round(r.width), Math.round(r.height)]; };
            return __ptJSON.stringify({
              attr: box(byAttr), style: box(byStyle),
              offset: [byAttr.offsetWidth, byAttr.offsetHeight],
              plainHasBox: box(plain)[0] > 0 && box(plain)[1] > 0,
            });
        })()"#;
        let out = match ctx.evaluate(probe).await.unwrap() {
            Value::String(s) => serde_json::from_str::<Value>(&s).unwrap(),
            v => panic!("expected the probe result, got {v:?}"),
        };
        assert_eq!(out["attr"], serde_json::json!([300, 65]), "width/height attributes");
        assert_eq!(out["style"], serde_json::json!([300, 65]), "and inline CSS");
        assert_eq!(out["offset"], serde_json::json!([300, 65]), "offsetWidth/Height agree");
        assert_eq!(out["plainHasBox"], true, "an unsized element still has a box");
    }

    /// An `XMLHttpRequest` is an `EventTarget`, and ours was not: `addEventListener`
    /// did not exist on it at all. Setting `onload` worked, so most things looked
    /// fine — until code that *listens* fired a request, got its answer, and never
    /// heard about it. Cloudflare's widget does exactly that: three POSTs, three
    /// answers nobody delivered, then its own timeout and `fail` code 300010.
    #[tokio::test]
    async fn an_xhr_delivers_its_events_to_listeners() {
        let _serial = serial().await;
        let url = cookie_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&url).await.unwrap();

        ctx.evaluate(&format!(
            "globalThis.seen = []; globalThis.done = false;
             const x = new XMLHttpRequest();
             for (const t of ['loadstart','readystatechange','progress','load','loadend'])
               x.addEventListener(t, () => {{ seen.push(t + ':' + x.readyState); if (t === 'loadend') done = true; }});
             globalThis.isTarget = typeof EventTarget === 'function' && typeof x.upload.addEventListener === 'function';
             x.open('GET', {}); x.send();",
            js_str(&url)
        ))
        .await
        .unwrap();
        ctx.run_event_loop().await.unwrap();

        assert_eq!(
            ctx.evaluate("String(done)").await.unwrap(),
            Value::String("true".into()),
            "a listener must hear the request finish"
        );
        assert_eq!(
            ctx.evaluate("String(isTarget)").await.unwrap(),
            Value::String("true".into()),
            "EventTarget exists and `upload` is one too"
        );
        let seen = match ctx.evaluate("seen.join(',')").await.unwrap() {
            Value::String(s) => s,
            v => panic!("expected the list, got {v:?}"),
        };
        for expected in ["loadstart:1", "readystatechange:4", "load:4", "loadend:4"] {
            assert!(seen.contains(expected), "missing {expected} in {seen}");
        }
    }

    /// A page that assigns `location.href` goes there. Ours only rewrote the
    /// address and stayed on the same document, so the last step of a form
    /// handoff, an OAuth bounce or a challenge — all of which end by navigating
    /// themselves — silently never happened.
    #[tokio::test]
    async fn a_page_can_navigate_itself() {
        let _serial = serial().await;
        let url = redirect_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");

        for (start, how) in [("/href", "location.href"), ("/replace", "location.replace")] {
            let ctx = engine.new_context().await.unwrap();
            ctx.navigate(&format!("{}{}", url.trim_end_matches('/'), start))
                .await
                .unwrap();
            assert_eq!(
                ctx.evaluate("document.title").await.unwrap(),
                Value::String("arrived".into()),
                "{how} must land on the new document, not just change the address"
            );
        }
    }

    /// Two documents: one that sends itself to the other, and the other.
    async fn redirect_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let body = if req.contains("GET /replace") {
                        "<html><body><script>location.replace('/there')</script></body></html>"
                    } else if req.contains("GET /href") {
                        "<html><body><script>location.href = '/there'</script></body></html>"
                    } else {
                        "<html><head><title>arrived</title></head><body>ok</body></html>"
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        format!("http://127.0.0.1:{}/", addr.port())
    }

    /// A blank same-origin `<iframe>` is a window with its own realm, reachable
    /// synchronously. Anti-bot code opens one on purpose — a fresh realm is where
    /// a patched function is compared against a clean one — and reads
    /// `contentWindow.eval` straight away. Against `null` it stops dead, which is
    /// exactly where Cloudflare's full-page challenge ended.
    #[tokio::test]
    async fn a_blank_iframe_is_a_window_with_its_own_realm() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let probe = r#"(() => {
            const f = document.createElement('iframe');
            document.body.appendChild(f);
            const w = f.contentWindow;
            if (!w) return __ptJSON.stringify({ ok: false });
            return __ptJSON.stringify({
              ok: true,
              evaluated: w.eval('1 + 1'),
              ownRealm: w.Object !== Object && w.Function !== Function,
              hasDocument: typeof w.document,
              parentIsUs: w.parent === globalThis,
              frameElement: w.frameElement === f,
              sameWindowTwice: f.contentWindow === w,
              document: f.contentDocument === w.document,
              // A frame with a real src is a networked browsing context instead,
              // and must not quietly become a local realm.
              networked: (() => {
                const g = document.createElement('iframe');
                g.src = 'https://elsewhere.test/';
                document.body.appendChild(g);
                return !g.__ptRealm;
              })(),
            });
        })()"#;
        let out = match ctx.evaluate(probe).await.unwrap() {
            Value::String(s) => serde_json::from_str::<Value>(&s).unwrap(),
            v => panic!("expected the probe result, got {v:?}"),
        };
        assert_eq!(out["ok"], true, "a blank iframe has a contentWindow at once");
        assert_eq!(out["evaluated"], 2, "and its `eval` runs, synchronously");
        assert_eq!(out["ownRealm"], true, "with natives of its own, not ours");
        assert_eq!(out["hasDocument"], "object");
        assert_eq!(out["parentIsUs"], true);
        assert_eq!(out["frameElement"], true);
        assert_eq!(out["sameWindowTwice"], true, "the same window every read");
        assert_eq!(out["document"], true, "contentDocument is that realm's");
        assert_eq!(out["networked"], true);
    }

    /// "On new document" has to mean *before* the document's own scripts. Ours ran
    /// after the page had already executed, which is useless for the thing the API
    /// exists for — putting a hook in place before the page can look. Every stealth
    /// patch and every instrumentation probe depends on this ordering, and its
    /// absence is silent: the script runs, the marker is there afterwards, and
    /// nothing it was supposed to observe was ever observed.
    #[tokio::test]
    async fn an_init_script_runs_before_the_documents_own() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.add_init_script(
            "globalThis.__initRan = true; globalThis.__initCount = (globalThis.__initCount || 0) + 1;"
                .to_string(),
        );
        ctx.load_html(
            "https://example.com/",
            "<html><body><script>globalThis.sawInit = typeof globalThis.__initRan !== 'undefined';\
             </script></body></html>",
        )
        .await
        .unwrap();

        assert_eq!(
            ctx.evaluate("String(sawInit)").await.unwrap(),
            Value::String("true".into()),
            "the page's own script must find the hook already in place"
        );
        assert_eq!(
            ctx.evaluate("String(__initCount)").await.unwrap(),
            Value::String("1".into()),
            "and it must run once per document, not once more afterwards"
        );
    }

    /// `blob:` and `data:` are answered from the page's own memory. A blob URL that
    /// reaches the network client fails with "invalid authority", and a challenge
    /// that builds its payload as a Blob and fetches it back stalls there.
    #[tokio::test]
    async fn blob_and_data_urls_resolve_without_the_network() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.evaluate(
            r#"globalThis.out = {};
               (async () => {
                 const u = URL.createObjectURL(new Blob(['payload'], { type: 'text/plain' }));
                 out.url = u.slice(0, 5);
                 const r = await fetch(u);
                 out.status = r.status;
                 out.body = await r.text();
                 out.type = r.headers.get('content-type');
                 out.data = await (await fetch('data:text/plain;base64,aGk=')).text();
                 URL.revokeObjectURL(u);
                 out.afterRevoke = await fetch(u).then(() => 'resolved', () => 'rejected');
               })();"#,
        )
        .await
        .unwrap();
        ctx.run_event_loop().await.unwrap();

        let out = match ctx.evaluate("__ptJSON.stringify(out)").await.unwrap() {
            Value::String(s) => serde_json::from_str::<Value>(&s).unwrap(),
            v => panic!("expected the result, got {v:?}"),
        };
        assert_eq!(out["url"], "blob:", "createObjectURL hands out a blob: URL");
        assert_eq!(out["status"], 200);
        assert_eq!(out["body"], "payload", "and it leads back to the object");
        assert_eq!(out["type"], "text/plain");
        assert_eq!(out["data"], "hi", "data: URLs decode base64 too");
        assert_eq!(
            out["afterRevoke"], "rejected",
            "a revoked URL stops resolving, as it does in a browser"
        );
    }

    /// Serves the two documents the watchdog regression needs: a page that hides
    /// an iframe in a closed shadow root and pings it on an interval, and the
    /// frame that answers. This is the shape of a Turnstile widget, down to the
    /// detail that broke it — the iframe is put inside a *detached* host, and only
    /// the host is ever inserted into the document.
    async fn frame_ping_server() -> String {
        const PARENT: &str = r#"<html><body><script>
            window.__s = { seq: 0, ack: 0 };
            addEventListener('message', e => { if (e.data && e.data.ack !== undefined) __s.ack = e.data.ack; });
            const host = document.createElement('div');
            const sr = host.attachShadow({ mode: 'closed' });
            const f = document.createElement('iframe');
            f.src = '/frame';
            sr.appendChild(f);
            document.body.appendChild(host);
            setInterval(() => {
              __s.seq++;
              try { f.contentWindow.postMessage({ ping: __s.seq }, '*'); } catch (e) { __s.err = String(e); }
            }, 50);
            </script></body></html>"#;
        const FRAME: &str = r#"<html><body><script>
            addEventListener('message', e => {
              if (e.data && e.data.ping !== undefined) parent.postMessage({ ack: e.data.ping }, '*');
            });
            </script></body></html>"#;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let body = if String::from_utf8_lossy(&buf[..n]).contains("GET /frame") {
                        FRAME
                    } else {
                        PARENT
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        format!("http://127.0.0.1:{}/", addr.port())
    }

    /// The failure this reproduces cost nothing less than every Cloudflare
    /// challenge: the widget's iframe never became a browsing context (it was
    /// inserted as part of a subtree, so nothing connected it), and the page's own
    /// watchdog interval kept the event loop from ever looking at frames. From
    /// outside, a widget that answers nothing — which is exactly what Cloudflare's
    /// watchdog reports, before reloading the widget forever.
    #[tokio::test]
    async fn a_frame_answers_the_page_that_keeps_pinging_it() {
        let _serial = serial().await;
        let url = frame_ping_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&url).await.unwrap();
        for _ in 0..4 {
            ctx.run_event_loop().await.unwrap();
        }

        assert!(
            !ctx.frame_list().is_empty(),
            "an iframe inserted inside a subtree — here a closed shadow root — is \
             still a browsing context"
        );
        let state = match ctx.evaluate("__ptJSON.stringify(__s)").await.unwrap() {
            Value::String(s) => serde_json::from_str::<Value>(&s).unwrap_or_default(),
            v => panic!("expected the state object, got {v:?}"),
        };
        let (seq, ack) = (
            state["seq"].as_i64().unwrap_or(0),
            state["ack"].as_i64().unwrap_or(0),
        );
        assert!(seq > 0, "the watchdog interval must tick, saw {state}");
        assert!(
            ack > 0,
            "and the frame must answer it — {state}, error {:?}",
            state["err"]
        );
        assert!(
            seq - ack <= 5,
            "the answer must keep up with the pings, not fall behind: {state}"
        );
    }

    /// Serves a module graph and records the headers of every request, so a test
    /// can assert both what ran and what went on the wire.
    async fn module_server() -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    ) {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let log = log.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    if let Ok(mut l) = log.lock() {
                        l.push((path.clone(), req.to_ascii_lowercase()));
                    }
                    let (ctype, body) = match path.as_str() {
                        "/app.js" => (
                            "text/javascript",
                            "import { tag } from './tag.js';\n\
                             class Boxed extends HTMLElement {\n\
                               connectedCallback() { this.textContent = tag(); }\n\
                             }\n\
                             customElements.define('x-boxed', Boxed);\n\
                             document.body.appendChild(document.createElement('x-boxed'));\n\
                             globalThis.__meta = import.meta.url;\n",
                        ),
                        "/tag.js" => (
                            "text/javascript",
                            "export const tag = () => 'built by a module';",
                        ),
                        "/second" => ("text/html", "<html><body>second</body></html>"),
                        _ => (
                            "text/html",
                            "<html><body><script type=\"module\" src=\"/app.js\"></script></body></html>",
                        ),
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        (format!("http://127.0.0.1:{}/", addr.port()), seen)
    }

    /// A modern site is one `<script type="module">` and nothing else. Compiled as
    /// a classic script it dies on its first `import` — silently, since a page
    /// script that throws must not fail the load — and the page stays blank with
    /// nothing to explain it. The graph is fetched, linked and evaluated instead,
    /// and the custom element it defines gets upgraded like a browser's.
    #[tokio::test]
    async fn a_module_graph_runs_and_defines_a_custom_element() {
        let _serial = serial().await;
        let (url, _log) = module_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&url).await.unwrap();

        let out = probe(&ctx, r#"__ptJSON.stringify({
            text: (document.querySelector('x-boxed') || {}).textContent,
            defined: typeof customElements.get('x-boxed'),
            meta: String(globalThis.__meta || '').split('/').pop(),
            // A page-built event stays untrusted even here.
            trusted: new MouseEvent('click').isTrusted,
        })"#,
        )
        .await;

        assert_eq!(out["text"], "built by a module", "the import chain ran: {out}");
        assert_eq!(out["defined"], "function", "and defined its element");
        assert_eq!(out["meta"], "app.js", "import.meta.url names the module itself");
        assert_eq!(out["trusted"], false);
    }

    /// `window.location = url` is a navigation, and it was the one shape we did
    /// not implement: the assignment replaced the Location object with a string,
    /// so nothing moved and every later read of `location` was broken. A page that
    /// finishes by sending itself somewhere — a Cloudflare interstitial does —
    /// stopped there. What goes on the wire matters as much: a navigation the page
    /// made carries a referrer and is same-origin, and claims no human gesture.
    #[tokio::test]
    async fn a_page_can_send_itself_somewhere_the_way_a_browser_does() {
        let _serial = serial().await;
        let (url, log) = module_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&url).await.unwrap();
        ctx.evaluate("window.location = '/second'").await.unwrap();
        ctx.run_event_loop().await.unwrap();

        let out = probe(&ctx, r#"__ptJSON.stringify({
            where: location.pathname,
            text: document.body.textContent.trim(),
            isObject: typeof location === 'object' && typeof location.href === 'string',
        })"#,
        )
        .await;
        assert_eq!(out["where"], "/second", "the assignment navigated");
        assert_eq!(out["text"], "second");
        assert_eq!(out["isObject"], true, "and location is still Location, not a string");

        let seen = log.lock().unwrap().clone();
        let first = seen.iter().find(|(p, _)| p == "/").expect("the first load");
        let second = seen.iter().find(|(p, _)| p == "/second").expect("the navigation");
        assert!(
            first.1.contains("sec-fetch-site: none") && first.1.contains("sec-fetch-user: ?1"),
            "an address someone asked for comes from nowhere, by a person"
        );
        assert!(
            second.1.contains("sec-fetch-site: same-origin") && second.1.contains("referer:"),
            "a navigation the page made says where it came from: {}",
            second.1
        );
        assert!(
            !second.1.contains("sec-fetch-user"),
            "and never claims a gesture nobody made"
        );
    }

    /// A page with a widget-shaped frame: an `<iframe>` inside a container, whose
    /// document keeps its control in a shadow root — the shape Turnstile uses.
    async fn frame_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 2048];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let inner = r#"<html><head><style>.gone{display:none}</style></head>
                        <body><div class="gone"><p>hidden</p></div>
                        <script>
                          const host = document.createElement('div');
                          document.body.appendChild(host);
                          const root = host.attachShadow({ mode: 'closed' });
                          const box = document.createElement('input');
                          box.type = 'checkbox';
                          root.appendChild(box);
                          globalThis.__hits = [];
                          box.addEventListener('click', (e) => {
                            __hits.push({ trusted: e.isTrusted, checked: box.checked, x: e.clientX });
                          });
                        </script></body></html>"#;
                    let outer = r#"<html><body><div id="wrap"><p>above</p>
                        <iframe id="w" src="/inner" style="width:300px;height:65px"></iframe>
                        <form><button id="danger" type="submit">Send my form</button></form>
                        </div>
                        <script>
                          globalThis.__pageClicks = 0;
                          document.getElementById('danger').addEventListener('click', () => { __pageClicks++; });
                        </script></body></html>"#;
                    let body = if req.contains("GET /inner") { inner } else { outer };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        format!("http://127.0.0.1:{}/", addr.port())
    }

    /// Inside a worker the world is different, and collectors know it: there is
    /// no `document`, no `window`, no `localStorage`, and `navigator` is a
    /// `WorkerNavigator` with no plugins and no `webdriver`. Ours ran in the
    /// page's own scope, so barewords reached the window's globals — a
    /// fingerprint taken there described a window, which is as loud a mismatch
    /// as there is. A live Cloudflare challenge spawns two workers; this is
    /// where it looks.
    #[tokio::test]
    async fn a_worker_lives_in_a_worker_scope() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(r#"(() => {
            const src = `postMessage({
              self: Object.prototype.toString.call(self),
              nav: Object.prototype.toString.call(navigator),
              loc: Object.prototype.toString.call(location),
              ua: navigator.userAgent === undefined ? 'missing' : 'present',
              plugins: typeof navigator.plugins,
              webdriver: typeof navigator.webdriver,
              document: typeof document,
              window: typeof window,
              localStorage: typeof localStorage,
              screen: typeof screen,
              fetch: typeof fetch,
              json: typeof JSON.parse,
              own: Object.getOwnPropertyNames(self).length,
              keys: Object.keys(self).length,
              scope: Object.getOwnPropertyNames(Object.getPrototypeOf(Object.getPrototypeOf(self))).length,
              navProto: Object.getOwnPropertyNames(Object.getPrototypeOf(navigator)).length - 1,
            });`;
            const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
            globalThis.__fromWorker = null;
            w.onmessage = (e) => { globalThis.__fromWorker = e.data; };
            return 1;
        })()"#).await.unwrap();
        ctx.run_event_loop().await.unwrap();

        let out = probe(&ctx, "__ptJSON.stringify(globalThis.__fromWorker || {})").await;
        assert_eq!(out["self"], "[object DedicatedWorkerGlobalScope]", "got: {out}");
        assert_eq!(out["nav"], "[object WorkerNavigator]");
        assert_eq!(out["loc"], "[object WorkerLocation]");
        assert_eq!(out["ua"], "present", "a worker still has a user agent");
        assert_eq!(out["plugins"], "undefined", "but no plugins");
        assert_eq!(out["webdriver"], "undefined", "and no webdriver");
        for absent in ["document", "window", "localStorage", "screen"] {
            assert_eq!(out[absent], "undefined", "{absent} does not exist in a worker");
        }
        assert_eq!(out["fetch"], "function", "what a worker does have, it has");
        assert_eq!(out["json"], "function", "the language comes along");
        // Measured against Chrome 148, level by level: the shape of the realm is
        // the first thing a collector inside a worker enumerates.
        assert_eq!(out["own"], 334, "own names on the scope: {out}");
        assert_eq!(out["keys"], 12, "and twelve of them enumerable");
        assert_eq!(out["scope"], 30, "WorkerGlobalScope carries the rest");
        // Chrome carries 23; a context with no network reports one fewer (no
        // `connection`), so the floor is what matters — the window's Navigator
        // has more than a hundred.
        assert!(
            (22..=23).contains(&out["navProto"].as_u64().unwrap_or(0)),
            "WorkerNavigator's own members: {out}"
        );
    }

    /// The port between a page and its worker, and the end of one. Three things a
    /// browser does that a shim gets wrong: a worker built from a blob reads that
    /// blob's address as its own (`blob:<origin>/<uuid>`, opaque path, no host,
    /// the page's origin), a posted message runs the handler exactly once, and
    /// `close()` ends the worker — which has to reach the engine, or a context
    /// nobody will ever pump again stays on the isolate.
    #[tokio::test]
    async fn a_worker_is_a_port_with_one_delivery_and_a_hang_up() {
        let _serial = serial().await;
        let engine = engine(1, 3);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/app/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(r#"(() => {
            const src = `let n = 0;
              self.onmessage = (e) => {
                n += 1;
                postMessage({
                  n, echo: e.data && e.data.ping,
                  href: String(location.href), origin: location.origin,
                  host: location.host, path: String(location.pathname),
                  native: Function.prototype.toString.call(postMessage).indexOf('[native code]') >= 0,
                });
                close();
              };`;
            const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
            globalThis.__seen = [];
            globalThis.__tag = Object.prototype.toString.call(w);
            w.onmessage = (e) => { globalThis.__seen.push(e.data); };
            w.postMessage({ ping: 1 });
            return 1;
        })()"#).await.unwrap();
        ctx.run_event_loop().await.unwrap();

        let tag = probe(&ctx, "__ptJSON.stringify({t: globalThis.__tag})").await;
        assert_eq!(tag["t"], "[object Worker]", "a Worker says what it is");
        let seen = probe(&ctx, "__ptJSON.stringify(globalThis.__seen || [])").await;
        let msgs = seen.as_array().cloned().unwrap_or_default();
        assert_eq!(msgs.len(), 1, "one message posted, one delivered: {seen}");
        let m = &msgs[0];
        assert_eq!(m["n"], 1, "and the handler ran once, not twice: {seen}");
        assert_eq!(m["echo"], 1, "carrying what the page sent");
        assert_eq!(m["native"], true, "the port's own methods read native");
        // The blob's address, as a browser reports it inside the worker.
        let href = m["href"].as_str().unwrap_or_default();
        assert!(
            href.starts_with("blob:https://example.com/") && href.len() == 61,
            "blob: URL is `blob:<origin>/<uuid>`, got {href}"
        );
        assert_eq!(m["origin"], "https://example.com", "the page's origin");
        assert_eq!(m["host"], "", "an opaque path has no host");
        assert_eq!(
            m["path"],
            href.trim_start_matches("blob:"),
            "all of it is path"
        );
        // `close()` was called, so the worker is gone — with its context.
        assert!(
            ctx.workers.lock().unwrap().is_empty(),
            "a worker that hung up is not still on the isolate"
        );
    }

    /// A property that a page enumerated and read still reaches what the page
    /// computed — after the loop doing it has been warmed.
    ///
    /// This is the engine under the engine. V8's mid-tier optimiser miscompiles
    /// exactly the loop a fingerprint collector runs — walk a root's keys, read
    /// each value, sort it by a string comparison — once that loop has run over
    /// the window graph and tiered up. From then on one property silently
    /// vanishes from the result: the same source, run as a fresh function object,
    /// is correct. It was found by diffing our map against Chrome's, where
    /// `document.cookie` was the one name of 1634 we did not report. The engine
    /// starts V8 with `--no-maglev` because of this (see `init_platform`), and a
    /// stock build fails this test.
    #[tokio::test]
    async fn a_warmed_enumeration_still_sees_every_property() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const walk = (o) => { let n = []; while (o) { n = n.concat(Object.keys(o)); o = Object.getPrototypeOf(o); } return n; };
            const collect = (root, prefix) => {
              const keys = Array.from(new Set(walk(root).concat(Object.getOwnPropertyNames(root))));
              const out = {};
              const put = (k, name) => { (out[k] = out[k] || []).push(name); };
              for (let i = 0; i < keys.length; i++) {
                const name = keys[i], full = prefix + name;
                try {
                  const v = root[name];
                  const cat = v === null ? 'x' : v === undefined ? 'u' : typeof v === 'string' ? 's'
                            : typeof v === 'function' ? 'N' : typeof v === 'number' ? 'n' : 'o';
                  if (cat === 's' || cat === 'n') {
                    const num = +v, isNumeric = cat === 's' && num === num;
                    if (full === 'd.cookie') put(cat, full);
                    else if (!isNumeric) put(String(v), full);
                  } else put(cat, full);
                } catch (e) { put('i', full); }
              }
              return out;
            };
            for (let w = 0; w < 3; w++) collect(globalThis, '');   // the window graph warms the loop
            const d = collect(document, 'd.');     // and then it answers about the document
            return __ptJSON.stringify({ cookie: (d.s || []).indexOf('d.cookie') >= 0 });
        })()"#).await;

        assert_eq!(
            out["cookie"], true,
            "an enumerated, readable property survives the loop that read it: {out}"
        );
    }

    /// Two answers a document gives about itself, both found by running the
    /// challenge's collector next to real Chrome's and diffing the maps.
    ///
    /// `document.readyState` is `loading` while the document's own scripts run —
    /// the whole point of the `readyState !== 'loading' ? start() : wait for
    /// DOMContentLoaded` idiom, and we said `interactive` from the first line, so
    /// every page took the branch a browser does not. And `document.activeElement`
    /// is `<body>` from the moment a body exists, never `null`: the collector
    /// buckets it as an object, and we handed it the bucket for null.
    #[tokio::test]
    async fn a_document_answers_for_its_own_lifecycle() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            "<html><body><script>globalThis.__at = {\
               ready: document.readyState,\
               active: document.activeElement && document.activeElement.tagName,\
             };\
             document.addEventListener('DOMContentLoaded', () => {\
               globalThis.__dcl = document.readyState;\
             });</script></body></html>",
        )
        .await
        .unwrap();

        let out = probe(
            &ctx,
            "__ptJSON.stringify({ during: globalThis.__at, dcl: globalThis.__dcl, \
             after: document.readyState, active: document.activeElement.tagName })",
        )
        .await;
        assert_eq!(
            out["during"]["ready"], "loading",
            "a document runs its scripts while it is still loading: {out}"
        );
        assert_eq!(
            out["during"]["active"], "BODY",
            "and its body already has the focus"
        );
        assert_eq!(out["dcl"], "interactive", "DOMContentLoaded fires at interactive");
        assert_eq!(out["after"], "complete", "and load leaves it complete");
        assert_eq!(out["active"], "BODY", "activeElement is never null");
    }

    /// The element interfaces are a ladder, as they are in a browser. Ours were
    /// one rung: `HTMLCanvasElement.prototype`, `HTMLDivElement.prototype` and
    /// `Element.prototype` were the *same object*, so `div instanceof
    /// HTMLCanvasElement` answered true and every element called itself
    /// `Element`. Measured against Chrome 148, a `<canvas>` climbs
    /// HTMLCanvasElement → HTMLElement → Element → Node → EventTarget → Object.
    #[tokio::test]
    async fn element_interfaces_are_a_ladder_not_one_rung() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const canvas = document.createElement('canvas');
            const div = document.createElement('div');
            const odd = document.createElement('nosuchtag');
            const chain = (o) => { const c = []; o = Object.getPrototypeOf(o);
              while (o) { c.push((o.constructor && o.constructor.name) || '?'); o = Object.getPrototypeOf(o); } return c; };
            return __ptJSON.stringify({
              distinct: HTMLElement.prototype !== Element.prototype
                     && HTMLCanvasElement.prototype !== HTMLElement.prototype
                     && HTMLDivElement.prototype !== HTMLCanvasElement.prototype,
              canvasChain: chain(canvas),
              names: [canvas.constructor.name, div.constructor.name, odd.constructor.name],
              tags: [Object.prototype.toString.call(canvas), Object.prototype.toString.call(div)],
              isCanvas: canvas instanceof HTMLCanvasElement,
              divIsNotCanvas: !(div instanceof HTMLCanvasElement),
              climbs: canvas instanceof HTMLElement && canvas instanceof Element
                   && canvas instanceof Node && canvas instanceof EventTarget,
              // The members ride the rung they ride in a browser.
              getContextOn: !!Object.getOwnPropertyDescriptor(HTMLCanvasElement.prototype, 'getContext'),
              idOn: !!Object.getOwnPropertyDescriptor(Element.prototype, 'id'),
              hiddenOn: !!Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'hidden'),
            });
        })()"#).await;

        assert_eq!(out["distinct"], true, "three interfaces, three prototypes: {out}");
        assert_eq!(
            out["canvasChain"],
            serde_json::json!(["HTMLCanvasElement", "HTMLElement", "Element", "Node", "EventTarget", "Object"]),
            "a canvas climbs Chrome's ladder: {}",
            out["canvasChain"]
        );
        assert_eq!(
            out["names"],
            serde_json::json!(["HTMLCanvasElement", "HTMLDivElement", "HTMLUnknownElement"]),
            "and each element says what it is"
        );
        assert_eq!(
            out["tags"],
            serde_json::json!(["[object HTMLCanvasElement]", "[object HTMLDivElement]"])
        );
        assert_eq!(out["isCanvas"], true);
        assert_eq!(out["divIsNotCanvas"], true, "a div is not a canvas");
        assert_eq!(out["climbs"], true, "and it is still an Element, a Node, a target");
        assert_eq!(out["getContextOn"], true, "getContext belongs to the canvas");
        assert_eq!(out["idOn"], true, "`id` to Element");
        assert_eq!(out["hiddenOn"], true, "`hidden` to HTMLElement");
    }

    /// Turnstile's own classifier, run against our window graph. The challenge
    /// walks the global object graph and sorts every value into one character:
    /// `N` for a native function, `f` for a page-defined one, `i` for a getter
    /// that threw, `?` for a `typeof` it does not know. In a browser a fresh
    /// window yields no `f`, no `i` and no `?` at all — every function up there
    /// is the browser's own. Four of ours (`PerformanceEntry`,
    /// `PerformanceResourceTiming`, `PerformanceNavigationTiming`,
    /// `CustomElementRegistry`) read as page functions until this test was
    /// written, which is a four-bit signature no browser has.
    #[tokio::test]
    async fn nothing_on_the_window_graph_reads_as_a_page_function() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        // The classifier, transcribed from the challenge: enumerable keys up the
        // prototype chain, plus the root's own names, each value to one char.
        let out = probe(&ctx, r#"(() => {
            const N = globalThis;
            const chars = { object: 'o', string: 's', undefined: 'u', symbol: 'z', number: 'n', bigint: 'I' };
            const classify = (v) => {
              if (v === null || v === undefined) return v === undefined ? 'u' : 'x';
              const t = typeof v;
              if (t === 'object') { try { if (v instanceof Promise) return 'p'; } catch (e) {} }
              return Array.isArray(v) ? 'a' : v === Array ? 'D' : v === true ? 'T' : v === false ? 'F'
                : t === 'function'
                  ? (v instanceof Function && Function.prototype.toString.call(v).indexOf('[native code]') > 0 ? 'N' : 'f')
                  : (chars[t] || '?');
            };
            const walk = (o) => { let names = []; while (o) { names = names.concat(Object.keys(o)); o = Object.getPrototypeOf(o); } return names; };
            const out = {};
            for (const [root, prefix] of [[globalThis, ''], [navigator, 'n.'], [document, 'd.'],
                                          [screen, 's.'], [location, 'l.'], [history, 'h.']]) {
              const keys = Array.from(new Set(walk(root).concat(Object.getOwnPropertyNames(root))));
              for (const name of keys) {
                let cat;
                try { cat = classify(root[name]); } catch (e) { cat = 'i'; }
                (out[cat] = out[cat] || []).push(prefix + name);
              }
            }
            return __ptJSON.stringify({
              f: out.f || [], unknown: out['?'] || [], inaccessible: out.i || [],
              native: (out.N || []).length,
            });
        })()"#).await;

        assert_eq!(
            out["f"],
            serde_json::json!([]),
            "every function on the graph is the browser's own: {}",
            out["f"]
        );
        assert_eq!(out["unknown"], serde_json::json!([]), "no unclassifiable value");
        assert_eq!(out["inaccessible"], serde_json::json!([]), "no getter throws");
        assert!(
            out["native"].as_u64().unwrap_or(0) > 1000,
            "and the graph is a browser's size: {out}"
        );
    }

    /// A widget that wants a worker does not hand `new Worker` a string: it asks
    /// Trusted Types for a policy and passes the `TrustedScriptURL` the policy
    /// makes. `trustedTypes` used to be a bare `{}` — the name was there, the
    /// factory was not — and `createPolicy` threw a TypeError that took the whole
    /// collection with it. This is that path, end to end.
    #[tokio::test]
    async fn a_trusted_policy_makes_a_url_a_worker_will_take() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const p = trustedTypes.createPolicy('nokk-test', { createScriptURL: (s) => s });
            const u = p.createScriptURL('blob:https://example.com/abc');
            return __ptJSON.stringify({
              factory: Object.prototype.toString.call(trustedTypes),
              policy: Object.prototype.toString.call(p),
              name: p.name,
              url: Object.prototype.toString.call(u),
              text: String(u),
              json: u.toJSON(),
              isScriptURL: trustedTypes.isScriptURL(u),
              isHTML: trustedTypes.isHTML(u),
              attributeType: trustedTypes.getAttributeType('script', 'src'),
              defaultPolicy: trustedTypes.defaultPolicy,
              // Worker takes it because it stringifies, the way Chrome's does.
              worker: (() => { try { new Worker(u); return 'started'; } catch (e) { return 'THREW ' + e; } })(),
            });
        })()"#).await;

        assert_eq!(out["factory"], "[object TrustedTypePolicyFactory]");
        assert_eq!(out["policy"], "[object TrustedTypePolicy]");
        assert_eq!(out["name"], "nokk-test");
        assert_eq!(out["url"], "[object TrustedScriptURL]");
        assert_eq!(out["text"], "blob:https://example.com/abc");
        assert_eq!(out["json"], "blob:https://example.com/abc");
        assert_eq!(out["isScriptURL"], true);
        assert_eq!(out["isHTML"], false);
        assert_eq!(out["attributeType"], "TrustedScriptURL");
        assert_eq!(out["defaultPolicy"], serde_json::Value::Null);
        assert_eq!(out["worker"], "started", "the worker takes the trusted url");
    }

    /// `eval(trustedScript)` is a browser behaviour, not a JavaScript one: the
    /// language returns a non-string argument untouched — silently, no error —
    /// and Trusted Types is what makes the browser stringify and run it. The
    /// Turnstile widget declares its XOR helper exactly this way, and with the
    /// declaration missing the next line of its interpreter called `undefined`.
    #[tokio::test]
    async fn a_trusted_script_is_code_to_eval_and_to_a_timer() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const p = trustedTypes.createPolicy('nokk-eval', { createScript: (s) => s });
            const code = p.createScript('function __declared(){ return 42 }');
            eval(code);
            let timer = 'no';
            try { setTimeout(p.createScript('globalThis.__fromTimer = 1'), 0); timer = 'accepted'; }
            catch (e) { timer = 'THREW ' + e.name; }
            return __ptJSON.stringify({
              kind: Object.prototype.toString.call(code),
              declared: typeof globalThis.__declared,
              value: typeof globalThis.__declared === 'function' ? __declared() : null,
              // Строка остаётся строкой: обычный eval работает как работал.
              plain: (eval('1 + 1')),
              native: /native code/.test(Function.prototype.toString.call(eval)),
              enumerable: Object.keys(globalThis).indexOf('eval') >= 0,
              timer,
            });
        })()"#).await;

        assert_eq!(out["kind"], "[object TrustedScript]");
        assert_eq!(out["declared"], "function", "the declaration reached the global scope");
        assert_eq!(out["value"], 42);
        assert_eq!(out["plain"], 2, "a plain string still evaluates");
        assert_eq!(out["native"], true, "and eval still reads as the browser's own");
        assert_eq!(out["enumerable"], false);
        assert_eq!(out["timer"], "accepted");
    }

    /// Names without bodies: the graph table gave `navigator.gpu` and its
    /// neighbours the right names and left them as `{}`, so the first call threw
    /// and the prototype chain a collector walks was empty where Chrome has an
    /// interface. Values here are Chrome 148's, measured on this machine.
    #[tokio::test]
    async fn the_platform_objects_are_interfaces_not_bare_objects() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(r#"(async () => {
            const tag = (v) => Object.prototype.toString.call(v);
            const adapter = await navigator.gpu.requestAdapter();
            const layout = await navigator.keyboard.getLayoutMap();
            globalThis.__out = __ptJSON.stringify({
              done: true,
              brands: [tag(navigator.gpu), tag(navigator.storage), tag(navigator.permissions),
                       tag(navigator.connection), tag(navigator.keyboard), tag(navigator.mediaCapabilities),
                       tag(navigator.userAgentData), tag(screen.orientation)],
              adapter: tag(adapter),
              limits: [tag(adapter.limits), adapter.limits.maxTextureDimension2D],
              info: [tag(adapter.info), adapter.info.vendor],
              features: [tag(adapter.features), adapter.features.has('shader-f16')],
              format: navigator.gpu.getPreferredCanvasFormat(),
              layout: [tag(layout), layout.size, layout.get('KeyQ')],
              decoding: (await navigator.mediaCapabilities.decodingInfo({ type: 'file' })).supported,
              highEntropy: (await navigator.userAgentData.getHighEntropyValues(['architecture'])).architecture,
            });
        })()"#).await.unwrap();
        let text = pump_until(&ctx, "globalThis.__out || ''", 20).await;
        let out: Value = serde_json::from_str(text.as_str().unwrap()).unwrap();

        assert_eq!(
            out["brands"],
            serde_json::json!([
                "[object GPU]", "[object StorageManager]", "[object Permissions]",
                "[object NetworkInformation]", "[object Keyboard]", "[object MediaCapabilities]",
                "[object NavigatorUAData]", "[object ScreenOrientation]"
            ]),
        );
        assert_eq!(out["adapter"], "[object GPUAdapter]");
        assert_eq!(out["limits"], serde_json::json!(["[object GPUSupportedLimits]", 16384]));
        assert_eq!(out["info"], serde_json::json!(["[object GPUAdapterInfo]", "intel"]));
        assert_eq!(out["features"], serde_json::json!(["[object GPUSupportedFeatures]", true]));
        assert_eq!(out["format"], "rgba8unorm");
        assert_eq!(out["layout"], serde_json::json!(["[object KeyboardLayoutMap]", 48, "q"]));
        assert_eq!(out["decoding"], true);
        assert_eq!(out["highEntropy"], "x86");
    }

    /// `<template>` keeps its parsed markup in a fragment of its own, not in
    /// itself. We had no `content` at all, and the parser's template children
    /// were dropped on the floor — the widget's second-stage program builds nodes
    /// through a template, and reported `TypeError: ie is not a function` to
    /// Cloudflare's own error beacon because of it.
    #[tokio::test]
    async fn a_template_keeps_its_markup_in_its_content() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            "<html><body><template id=\"t\"><div class=\"a\">x</div><span>y</span></template></body></html>",
        )
        .await
        .unwrap();

        let out = probe(&ctx, r#"(() => {
            const tag = (v) => Object.prototype.toString.call(v);
            const t = document.getElementById('t');
            const made = document.createElement('template');
            made.innerHTML = '<p>hi</p>';
            const clone = t.cloneNode(true);
            return __ptJSON.stringify({
              content: tag(t.content), nodeType: t.content.nodeType,
              // Разобранные дети — в содержимом, сам элемент пуст.
              kids: t.content.childNodes.length, own: t.childNodes.length,
              first: t.content.firstChild.localName,
              innerHTML: t.innerHTML,
              query: t.content.querySelector('.a').localName,
              madeKids: made.content.childNodes.length, madeOwn: made.childNodes.length,
              cloneKids: clone.content.childNodes.length,
              cloneIface: tag(clone),
              fragment: Object.getOwnPropertyNames(DocumentFragment.prototype).length,
            });
        })()"#).await;

        assert_eq!(out["content"], "[object DocumentFragment]");
        assert_eq!(out["nodeType"], 11);
        assert_eq!(out["kids"], 2, "the parser's children live in the content");
        assert_eq!(out["own"], 0, "and the template itself has none");
        assert_eq!(out["first"], "div");
        assert_eq!(out["innerHTML"], "<div class=\"a\">x</div><span>y</span>");
        assert_eq!(out["query"], "div", "a fragment answers queries of its own");
        assert_eq!(out["madeKids"], 1, "innerHTML parses into the content");
        assert_eq!(out["madeOwn"], 0);
        assert_eq!(out["cloneKids"], 2, "a deep clone brings the content along");
        assert_eq!(out["cloneIface"], "[object HTMLTemplateElement]", "and keeps its interface");
        assert_eq!(out["fragment"], 12, "DocumentFragment is its own interface: Chrome's 11 + constructor");
    }

    /// Cloudflare's collector worker is 291 bytes and runs its task under one
    /// condition: `e.isTrusted && '' === e.origin && null === e.source`. An event
    /// the engine delivers is the browser's own and is trusted; ours was not, so
    /// the worker took its message, checked the first of the three, and did
    /// nothing at all — no error, no reply, and the widget waited for it forever.
    #[tokio::test]
    async fn a_message_the_engine_delivers_is_trusted() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><body><script>
                globalThis.__log = { done: false };
                const src = "onmessage = function (e) {" +
                  "  postMessage('trusted=' + e.isTrusted + ' origin=[' + e.origin + '] source=' + e.source +" +
                  "    ' data=' + e.data + ' gate=' + !!(e.isTrusted && '' === e.origin && null === e.source));" +
                  "};";
                const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
                w.onmessage = (e) => { globalThis.__log = { done: true, said: e.data, replyTrusted: e.isTrusted }; };
                w.postMessage('task');
              </script></body></html>"#,
        )
        .await
        .unwrap();

        let out = pump_until(&ctx, "__ptJSON.stringify(__log)", 40).await;
        let said = out.as_str().unwrap_or("");
        assert!(said.contains(r#""done":true"#), "the worker answered: {said}");
        assert!(said.contains("trusted=true"), "its message was trusted: {said}");
        assert!(said.contains("origin=[]"), "with an empty origin: {said}");
        assert!(said.contains("source=null"), "and no source: {said}");
        assert!(said.contains("data=task"), "carrying what was sent: {said}");
        assert!(said.contains("gate=true"), "so the collector's own gate opens: {said}");
        assert!(said.contains(r#""replyTrusted":true"#), "and the answer home is trusted too: {said}");
    }

    /// `document.styleSheets` was a list of literals with an empty `cssRules`.
    /// Cloudflare's collector reads it hundreds of times at the start of its
    /// second stage — rules, selectors, `cssText` — and an empty list is not a
    /// page that has any style. Serialisation follows Chrome: a bare `0` in a
    /// length property becomes `0px`, selector combinators get their spaces, and
    /// an @media condition gets one after the colon.
    #[tokio::test]
    async fn a_style_element_is_a_stylesheet_with_rules() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            "<html><head><style media=\"screen\">a{color:red;font-weight:bold}.b .c>d{margin:0 1px}             @media (min-width:1px){e{top:0}}</style></head><body></body></html>",
        )
        .await
        .unwrap();

        let out = probe(&ctx, r#"(() => {
            const tag = (v) => Object.prototype.toString.call(v);
            const ss = document.styleSheets, s0 = ss[0], r0 = s0.cssRules[0];
            return __ptJSON.stringify({
              list: tag(ss), len: ss.length, own: Object.getOwnPropertyNames(ss),
              sheet: tag(s0), media: s0.media.mediaText, owner: s0.ownerNode.localName,
              same: s0.cssRules === s0.rules, rulesTag: tag(s0.cssRules),
              rule: tag(r0), type: r0.type, selector: r0.selectorText,
              styleTag: tag(r0.style), styleLen: r0.style.length, color: r0.style.color,
              texts: [...s0.cssRules].map((r) => r.cssText),
              stable: document.styleSheets[0] === document.styleSheets[0],
            });
        })()"#).await;

        assert_eq!(out["list"], "[object StyleSheetList]");
        assert_eq!(out["len"], 1);
        assert_eq!(out["own"], serde_json::json!(["0"]), "own properties are the indices, nothing else");
        assert_eq!(out["sheet"], "[object CSSStyleSheet]");
        assert_eq!(out["media"], "screen");
        assert_eq!(out["owner"], "style");
        assert_eq!(out["same"], true, "cssRules and rules are the same list");
        assert_eq!(out["rulesTag"], "[object CSSRuleList]");
        assert_eq!(out["rule"], "[object CSSStyleRule]");
        assert_eq!(out["type"], 1);
        assert_eq!(out["selector"], "a");
        assert_eq!(out["styleTag"], "[object CSSStyleDeclaration]");
        assert_eq!(out["styleLen"], 2);
        assert_eq!(out["color"], "red");
        assert_eq!(
            out["texts"],
            serde_json::json!([
                "a { color: red; font-weight: bold; }",
                ".b .c > d { margin: 0px 1px; }",
                "@media (min-width: 1px) { e { top: 0px; } }"
            ]),
            "serialised the way Chrome serialises them"
        );
        assert_eq!(out["stable"], true, "and the sheet is the same object each time");
    }

    /// A collector that wants a canvas fingerprint from a worker has exactly one
    /// way to get it: `new OffscreenCanvas(…).getContext('2d')`. Ours was built
    /// on `document.createElement('canvas')`, and a worker has no document — so
    /// the context came back null and the worker fell silent. In a worker the
    /// context is an OffscreenCanvasRenderingContext2D; `CanvasRenderingContext2D`
    /// does not exist there at all, which is what the old code reached for.
    #[tokio::test]
    async fn a_worker_can_draw_on_an_offscreen_canvas() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><body><script>
                globalThis.__log = { done: false };
                const src = `
                  const c = new OffscreenCanvas(24, 12);
                  const g = c.getContext('2d');
                  let drawn = 'no context';
                  if (g) {
                    g.fillStyle = '#204080';
                    g.fillRect(2, 2, 8, 6);
                    g.fillText('nokk', 2, 10);
                    drawn = Object.prototype.toString.call(g) + '|' + g.getImageData(0, 0, 24, 12).data.length;
                  }
                  postMessage(drawn + '|' + c.width + 'x' + c.height);
                `;
                const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
                w.onmessage = (e) => { globalThis.__log = { done: true, said: e.data }; };
              </script></body></html>"#,
        )
        .await
        .unwrap();

        let out = pump_until(&ctx, "__ptJSON.stringify(__log)", 40).await;
        let said = out.as_str().unwrap_or("");
        assert!(said.contains("\"done\":true"), "the worker answered: {said}");
        assert!(
            said.contains("[object OffscreenCanvasRenderingContext2D]"),
            "and its context is the interface a worker has: {said}"
        );
        assert!(said.contains("|1152|"), "with pixels behind it: {said}");
        assert!(said.contains("24x12"), "and the size it was given: {said}");
    }

    /// `about:blank` is not an address a browser fetches: it is the same initial
    /// empty document a src-less frame gets, and its realm is ready the moment
    /// the frame is in the document. We treated it as a URL, so
    /// `f.src = 'about:blank'; body.appendChild(f); f.contentWindow.eval(…)` —
    /// the ordinary way to reach untouched built-ins — found no window at all.
    #[tokio::test]
    async fn an_about_blank_frame_has_its_realm_at_once() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const f = document.createElement('iframe');
            f.src = 'about:blank';
            document.body.appendChild(f);
            const w = f.contentWindow;
            return __ptJSON.stringify({
              window: typeof w,
              document: typeof f.contentDocument,
              eval: w ? String(w.eval('2 + 2')) : 'no window',
              parentIsUs: w ? w.parent === window : false,
            });
        })()"#).await;

        assert_eq!(out["window"], "object");
        assert_eq!(out["document"], "object");
        assert_eq!(out["eval"], "4", "the realm answers straight away");
        assert_eq!(out["parentIsUs"], true);
    }

    /// `const u = URL.createObjectURL(b); new Worker(u); URL.revokeObjectURL(u)`
    /// is the idiom every collector uses, Cloudflare's included — the URL is dead
    /// one line after the worker starts. Reading the blob when the engine got
    /// round to the op found nothing, and the worker silently never ran; a
    /// browser takes the bytes inside `new Worker`, so the DOM does too. The
    /// bytes may also *be* bytes: a `Blob` over a `Uint8Array` is a script, not
    /// the string "104,105".
    #[tokio::test]
    async fn a_worker_survives_the_url_being_revoked() {
        let _serial = serial().await;
        let engine = engine(1, 3);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(r#"(() => {
            const bytes = new TextEncoder().encode('postMessage({ ran: true });');
            const u = URL.createObjectURL(new Blob([bytes], { type: 'text/javascript' }));
            const w = new Worker(u);
            URL.revokeObjectURL(u);
            globalThis.__ran = null;
            w.onmessage = (e) => { globalThis.__ran = e.data; };
            return 1;
        })()"#).await.unwrap();
        ctx.run_event_loop().await.unwrap();

        let out = probe(&ctx, "__ptJSON.stringify(globalThis.__ran || {})").await;
        assert_eq!(out["ran"], true, "the worker ran from a revoked URL: {out}");
    }

    /// A widget collects from inside its own frame: the frame builds the blob,
    /// the frame spawns the worker, and the fingerprint is taken in there. Only
    /// the page's queue used to be drained, so on a real challenge those workers
    /// were never born — and ids are per-document, so a frame's worker 1 must not
    /// be the page's worker 1.
    #[tokio::test]
    async fn a_frame_starts_workers_of_its_own() {
        let _serial = serial().await;
        let url = frame_ping_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 5,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&url).await.unwrap();
        for _ in 0..3 {
            ctx.run_event_loop().await.unwrap();
        }
        let frame = ctx.frame_list().first().map(|f| f.id).expect("a frame");

        // Both documents start a worker, and each one's id is 1.
        let spawn = r#"(() => {
            const src = `postMessage({ where: Object.prototype.toString.call(self), href: location.href });`;
            const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
            globalThis.__from = null;
            w.onmessage = (e) => { globalThis.__from = e.data; };
            return 1;
        })()"#;
        ctx.evaluate(spawn).await.unwrap();
        ctx.evaluate_in_frame(frame, spawn).await.unwrap();
        ctx.run_event_loop().await.unwrap();

        assert_eq!(
            ctx.workers.lock().unwrap().len(),
            2,
            "the page's worker and the frame's are two workers, not one"
        );
        let from_page = probe(&ctx, "__ptJSON.stringify(globalThis.__from || {})").await;
        assert_eq!(
            from_page["where"], "[object DedicatedWorkerGlobalScope]",
            "the page heard back from its own: {from_page}"
        );
        let out = ctx
            .evaluate_in_frame(frame, "__ptJSON.stringify(globalThis.__from || {})")
            .await
            .unwrap();
        let from_frame: Value = out
            .as_str()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        assert_eq!(
            from_frame["where"], "[object DedicatedWorkerGlobalScope]",
            "and the frame from its own: {from_frame}"
        );
    }

    /// A document that goes away takes its workers with it. Without this each
    /// navigation left one behind — still pumped, still fetching, on a page it no
    /// longer belongs to.
    #[tokio::test]
    async fn navigating_away_ends_the_page_workers() {
        let _serial = serial().await;
        let engine = engine(1, 3);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        ctx.evaluate(
            "new Worker(URL.createObjectURL(new Blob(['setInterval(() => {}, 5)'], \
             { type: 'text/javascript' })))",
        )
        .await
        .unwrap();
        ctx.run_event_loop().await.unwrap();
        assert_eq!(
            ctx.workers.lock().unwrap().len(),
            1,
            "the worker is running"
        );

        ctx.load_html("https://example.com/next", "<html><body>next</body></html>")
            .await
            .unwrap();
        assert!(
            ctx.workers.lock().unwrap().is_empty(),
            "the previous document's worker did not survive the navigation"
        );
    }

    /// Three things anti-bot code reads that we answered wrongly, each found by
    /// tracing what a real challenge asked for rather than by guessing.
    ///
    /// `Object.prototype.toString.call(navigator)` is the cheapest impostor test
    /// there is, and ours said `[object Object]` where every browser says
    /// `[object Navigator]`. WebRTC was a stub that gathered no candidates — a
    /// browser with no network. And Resource Timing was empty after a page load,
    /// which no browser that loaded anything can report.
    #[tokio::test]
    async fn the_surfaces_a_challenge_reads_answer_like_a_browser() {
        let _serial = serial().await;
        let url = frame_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&url).await.unwrap();
        ctx.run_event_loop().await.unwrap();

        let names = probe(&ctx, r#"(() => {
            const named = (o) => Object.prototype.toString.call(o);
            return __ptJSON.stringify([named(window), named(navigator), named(screen), named(location),
              named(history), named(document), named(document.body),
              named(document.createElement('canvas')), named(document.createTextNode('x'))]);
        })()"#,
        )
        .await;
        assert_eq!(
            names,
            serde_json::json!([
                "[object Window]", "[object Navigator]", "[object Screen]", "[object Location]",
                "[object History]", "[object HTMLDocument]", "[object HTMLBodyElement]",
                "[object HTMLCanvasElement]", "[object Text]"
            ]),
            "every interface names itself"
        );

        let timing = probe(&ctx, r#"__ptJSON.stringify({
            navigation: performance.getEntriesByType('navigation').length,
            resources: performance.getEntriesByType('resource').length,
            named: Object.prototype.toString.call(performance.getEntries()[0]),
            sized: performance.getEntries().every(e => e.duration >= 0 && e.responseEnd >= e.startTime),
        })"#).await;
        assert_eq!(timing["navigation"], 1, "the document is a navigation entry");
        assert!(
            timing["resources"].as_u64().unwrap_or(0) >= 1,
            "and what it fetched is listed: {timing}"
        );
        assert_eq!(timing["named"], "[object PerformanceNavigationTiming]");
        assert_eq!(timing["sized"], true, "with timings that make sense");

        // ICE gathering takes event-loop turns, as it does in a browser: start it,
        // let the loop run, then read what arrived.
        ctx.evaluate(r#"(() => {
            const pc = new RTCPeerConnection();
            globalThis.__ice = [];
            pc.addEventListener('icecandidate', (e) => __ice.push(e.candidate ? e.candidate.candidate : null));
            pc.createDataChannel('probe');
            pc.createOffer().then((o) => pc.setLocalDescription(o));
            globalThis.__pc = pc;
            return 1;
        })()"#).await.unwrap();
        ctx.run_event_loop().await.unwrap();
        let ice = probe(&ctx, r#"__ptJSON.stringify({
            candidates: __ice.filter(Boolean).length,
            ended: __ice.includes(null),
            mdns: __ice.filter(Boolean).every(c => /\.local /.test(c)),
            state: __pc.iceGatheringState,
            sdp: /a=ice-ufrag:.+/.test(__pc.localDescription.sdp)
                 && /a=fingerprint:sha-256 /.test(__pc.localDescription.sdp),
        })"#,
        )
        .await;
        assert!(
            ice["candidates"].as_u64().unwrap_or(0) >= 1,
            "ICE gathers: {ice}"
        );
        assert_eq!(ice["ended"], true, "and says when it is done");
        assert_eq!(ice["mdns"], true, "behind an mDNS name, as Chrome has since 2019");
        assert_eq!(ice["state"], "complete");
        assert_eq!(ice["sdp"], true, "the offer carries a ufrag and a DTLS fingerprint");
    }

    /// The engine can press what a widget puts up, wherever it keeps it — this
    /// one is in a closed shadow root inside a frame, where page script has no
    /// reach at all, which is why a driver cannot do this for itself.
    ///
    /// And it presses only what belongs to a widget. The page's own form is not
    /// ours to submit: a helper that hunts for "a button" and finds the login
    /// form's would do real damage, quietly.
    #[tokio::test]
    async fn the_engine_presses_a_widget_and_leaves_the_page_alone() {
        let _serial = serial().await;
        let url = frame_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&url).await.unwrap();
        ctx.run_event_loop().await.unwrap();

        let pressed = ctx.press_widget_control().await.unwrap();
        assert!(
            pressed.as_deref().is_some_and(|w| w.starts_with("INPUT[checkbox]")),
            "the widget's checkbox is what gets pressed: {pressed:?}"
        );

        let frame = ctx.frame_list().first().map(|f| f.id).expect("the frame is live");
        let hits = ctx
            .evaluate_in_frame(frame, "__ptJSON.stringify(globalThis.__hits || [])")
            .await
            .unwrap();
        let hits: Value = serde_json::from_str(hits.as_str().unwrap_or("[]")).unwrap();
        assert_eq!(hits.as_array().map(|a| a.len()), Some(1), "and it received it");

        let page_clicks = ctx.evaluate("String(globalThis.__pageClicks)").await.unwrap();
        assert_eq!(
            page_clicks,
            Value::String("0".into()),
            "the page's own submit button was never touched"
        );
    }

    /// A click has to reach the document that owns the point. Turnstile's checkbox
    /// lives in an `<iframe>` inside a closed shadow root, so a click that stops at
    /// the top document reaches nothing at all — which is why the widget sat at
    /// `before-interactive` forever. The point is hit-tested here, handed down into
    /// the frame in the frame's own coordinates, and dispatched there.
    #[tokio::test]
    async fn a_click_reaches_the_frame_that_owns_the_point() {
        let _serial = serial().await;
        let url = frame_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&url).await.unwrap();
        ctx.run_event_loop().await.unwrap();

        let rect = probe(&ctx, r#"(() => {
            const f = document.getElementById('w');
            const r = f.getBoundingClientRect();
            return __ptJSON.stringify({ x: r.x, y: r.y, w: r.width, h: r.height });
        })()"#,
        )
        .await;
        let (x, y) = (
            rect["x"].as_f64().unwrap() + 10.0,
            rect["y"].as_f64().unwrap() + 5.0,
        );

        for kind in ["mouseMoved", "mousePressed", "mouseReleased"] {
            ctx.dispatch_mouse(kind, x, y, "left", 1).await.unwrap();
        }
        ctx.run_event_loop().await.unwrap();

        let frame = ctx.frame_list().first().map(|f| f.id).expect("the frame is live");
        let hits = ctx
            .evaluate_in_frame(frame, "__ptJSON.stringify(globalThis.__hits || [])")
            .await
            .unwrap();
        let hits: Value = serde_json::from_str(hits.as_str().unwrap_or("[]")).unwrap();
        let hits = hits.as_array().expect("the frame reports what it was clicked with");

        assert_eq!(hits.len(), 1, "exactly one click landed in the frame: {hits:?}");
        assert_eq!(hits[0]["trusted"], true, "input from the engine is trusted");
        assert_eq!(hits[0]["checked"], true, "and the checkbox toggled before the click ran");

        // A page-built event is not: only the engine's own input is trusted, and
        // claiming otherwise is a tell in its own right.
        let built = ctx
            .evaluate("String(new MouseEvent('click').isTrusted)")
            .await
            .unwrap();
        assert_eq!(built, Value::String("false".into()));
    }

    /// A one-shot HTTP server that hands out the cookie flavours that matter:
    /// an HttpOnly one (invisible to `document.cookie`, and exactly what a
    /// `cf_clearance` or an Akamai `bm_s*` is), a plain one, and a persistent one.
    async fn cookie_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let body = "<html><body>ok</body></html>";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: text/html\r\n\
                         Set-Cookie: sess_secret=abc123; Path=/; HttpOnly\r\n\
                         Set-Cookie: visible=yes; Path=/\r\n\
                         Set-Cookie: keeper=v2; Path=/; Max-Age=3600\r\n\
                         Content-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        format!("http://127.0.0.1:{}/", addr.port())
    }

    #[tokio::test]
    async fn cookies_are_readable_including_httponly() {
        let _serial = serial().await;
        let url = cookie_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&url).await.unwrap();

        let all = ctx.cookies(&[]);
        let by = |n: &str| all.iter().find(|c| c.name == n).cloned();

        let secret = by("sess_secret").expect("the HttpOnly cookie is in the jar");
        assert!(secret.http_only, "and is reported as HttpOnly");
        assert_eq!(secret.value, "abc123");
        // The whole point: the page cannot see it, the engine can.
        let visible_to_js = ctx.evaluate("document.cookie").await.unwrap();
        let js = visible_to_js.as_str().unwrap_or_default();
        assert!(
            !js.contains("sess_secret"),
            "an HttpOnly cookie must stay invisible to document.cookie, got {js:?}"
        );

        assert!(!by("visible").unwrap().http_only);
        assert_eq!(
            by("sess_secret").unwrap().domain.as_deref(),
            Some("127.0.0.1"),
            "a host-only cookie reports the host that set it, not an empty string"
        );
        assert!(
            by("keeper").unwrap().expires.is_some(),
            "a Max-Age cookie carries its expiry"
        );
        assert!(
            by("visible").unwrap().expires.is_none(),
            "a session cookie has none"
        );

        // `urls` filtering matches what would actually be sent there.
        assert_eq!(
            ctx.cookies(std::slice::from_ref(&url)).len(),
            3,
            "all three for its own origin"
        );
        assert!(
            ctx.cookies(&["https://example.org/".to_string()])
                .is_empty(),
            "and none for an unrelated origin"
        );
    }

    /// A WebSocket server that echoes `"echo:<what you sent>"` and then, on the
    /// literal `"push"`, sends an unprompted frame — the server-driven case the
    /// whole event-loop change exists for. Returns its `ws://` URL.
    async fn echo_server() -> String {
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    while let Some(Ok(msg)) = ws.next().await {
                        if let tokio_tungstenite::tungstenite::Message::Text(t) = msg {
                            let reply = format!("echo:{t}");
                            if ws
                                .send(tokio_tungstenite::tungstenite::Message::Text(reply))
                                .await
                                .is_err()
                            {
                                return;
                            }
                            if t == "push" {
                                // Unprompted, and deliberately late: the page must
                                // receive it without having asked for anything.
                                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                                let _ = ws
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        "pushed".to_string(),
                                    ))
                                    .await;
                            }
                        }
                    }
                });
            }
        });
        format!("ws://{addr}/")
    }

    /// Pump until `probe` reports done, or give up. The engine pumps on command
    /// (the CDP server does this on a timer), so a test drives it the same way.
    async fn pump_until(ctx: &BrowserContext, probe: &str, rounds: usize) -> Value {
        let mut last = Value::Null;
        for _ in 0..rounds {
            ctx.run_event_loop().await.unwrap();
            last = ctx.evaluate(probe).await.unwrap();
            if last.as_str().is_some_and(|s| s.contains("\"done\":true")) {
                break;
            }
        }
        last
    }

    #[tokio::test]
    async fn websocket_opens_sends_and_receives_through_the_page() {
        let _serial = serial().await;
        let url = echo_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();

        // The page drives the socket itself: open, send on `open`, log everything.
        ctx.evaluate(&format!(
            r#"(() => {{
                globalThis.__log = {{ events: [], messages: [], done: false }};
                const ws = new WebSocket({url});
                globalThis.__ws = ws;
                ws.onopen = () => {{ __log.events.push('open'); __log.stateOnOpen = ws.readyState; ws.send('hello'); }};
                ws.addEventListener('message', (e) => {{
                    __log.messages.push(e.data);
                    if (e.data === 'echo:hello') ws.send('push');
                    if (e.data === 'pushed') {{ __log.done = true; ws.close(1000, 'bye'); }}
                }});
                ws.onclose = (e) => {{ __log.events.push('close'); __log.code = e.code; __log.clean = e.wasClean; }};
                ws.onerror = (e) => {{ __log.events.push('error:' + e.message); }};
            }})()"#,
            url = serde_json::to_string(&url).unwrap()
        ))
        .await
        .unwrap();

        let out = pump_until(&ctx, "__ptJSON.stringify(__log)", 40).await;
        let log: Value = serde_json::from_str(out.as_str().unwrap()).unwrap();

        assert!(
            log["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e == "open"),
            "the socket opened: {log}"
        );
        assert_eq!(log["stateOnOpen"], 1, "readyState is OPEN inside onopen");
        let msgs: Vec<&str> = log["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|m| m.as_str())
            .collect();
        assert!(
            msgs.contains(&"echo:hello"),
            "the page's frame reached the server and came back: {msgs:?}"
        );
        assert!(
            msgs.contains(&"pushed"),
            "a server-pushed frame arrived with nothing pending: {msgs:?}"
        );

        // The close is a round trip of its own, so pump once more for it.
        let out = pump_until(&ctx, "__ptJSON.stringify(__log)", 20).await;
        let log: Value = serde_json::from_str(out.as_str().unwrap()).unwrap();
        assert_eq!(log["code"], 1000, "clean close carries the code: {log}");
        assert_eq!(log["clean"], true, "and reports wasClean");
        let state = ctx.evaluate("String(__ws.readyState)").await.unwrap();
        assert_eq!(state, "3", "readyState settles at CLOSED");
        assert!(
            !ctx.has_open_sockets().await,
            "the engine dropped the socket from its table"
        );
    }

    #[tokio::test]
    async fn websocket_to_a_dead_port_errors_and_closes_like_a_browser() {
        let _serial = serial().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig {
                workers: 1,
                max_live_contexts: 4,
                max_heap_mb: None,
            },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        // Port 1 on loopback: nothing is listening, so the upgrade never happens.
        ctx.evaluate(
            r#"(() => {
                globalThis.__log = { events: [], done: false };
                const ws = new WebSocket('ws://127.0.0.1:1/');
                ws.onerror = () => { __log.events.push('error'); };
                ws.onclose = (e) => { __log.events.push('close'); __log.code = e.code; __log.clean = e.wasClean; __log.done = true; };
            })()"#,
        )
        .await
        .unwrap();

        let out = pump_until(&ctx, "__ptJSON.stringify(__log)", 40).await;
        let log: Value = serde_json::from_str(out.as_str().unwrap()).unwrap();
        assert_eq!(
            log["events"].as_array().unwrap().len(),
            2,
            "a failed connection fires error *then* close: {log}"
        );
        assert_eq!(log["code"], 1006, "and reports 1006, not a clean code");
        assert_eq!(log["clean"], false);
    }
}
