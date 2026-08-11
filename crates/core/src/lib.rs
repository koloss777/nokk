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
/// (which patches HTMLElement.prototype + navigator, so it must run last).
fn build_bootstrap(profile: &StealthProfile) -> String {
    format!(
        "{}\n{}\n{}",
        nokk_stealth::bootstrap_script(profile),
        nokk_dom::runtime_js(),
        nokk_stealth::fingerprint_script(profile),
    )
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
            sockets: tokio::sync::Mutex::new(PageSockets::new()),
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
    /// Name of the persistent session this context belongs to, if any. On drop
    /// its cookie jar is flushed to the session store.
    session: Option<String>,
    /// The page's live `WebSocket`s (docs/websockets.md).
    sockets: tokio::sync::Mutex<PageSockets>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _load: nokk_pool::ContextLoadGuard,
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
        // Follow client-side `<meta http-equiv="refresh">` redirects, not just the
        // HTTP ones the network layer already follows. Some gates (e.g. Google's
        // "enable JavaScript" handoff) bounce through a meta-refresh that also sets
        // a cookie; the in-session jar carries the cookie across hops, so following
        // the chain lands on the real page. Capped to avoid a refresh loop.
        const MAX_META_HOPS: usize = 6;
        let mut current = url.to_string();
        for _ in 0..MAX_META_HOPS {
            // Use the post-redirect URL as the document base, so `window.location`
            // and relative-URL resolution reflect where we actually landed.
            let (final_url, html) = self.fetch_text(&current, "document").await?;
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
                    Some(abs) => {
                        // Don't fetch or run tracker/analytics scripts — the point
                        // of the blocklist is that they never execute.
                        if self.engine.block_trackers && nokk_net::is_blocked_url(&abs) {
                            self.record("GET", &abs, "script", 0, &[]);
                            continue;
                        }
                        match self.fetch_text(&abs, "script").await {
                            Ok((_, code)) => code,
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

            // 3. Sockets: apply what the page asked for, then hand it whatever the
            //    sockets have produced since the last round.
            self.apply_ws_ops(&base, &ws_ops).await;
            let delivered = self.deliver_ws_events(index).await?;

            if ran == 0 && reqs.is_empty() && ws_ops.is_empty() && delivered == 0 {
                // Idle — but an open socket means "not finished", only "nothing
                // right now". Wait briefly for a frame rather than spinning, and
                // still return promptly: continuous delivery is the caller's job
                // (the CDP server pumps periodically), not this call's.
                if !self.has_open_sockets().await {
                    break;
                }
                if !self.await_ws_event(SOCKET_IDLE_GRACE).await {
                    break;
                }
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

    /// Whether this page is holding any socket open. The event loop treats that
    /// as "not finished" and the CDP server as "keep pumping".
    pub async fn has_open_sockets(&self) -> bool {
        !self.sockets.lock().await.open.is_empty()
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

/// One round trip that empties both JS-side I/O queues. Written as an expression
/// so a bare context (no stealth bootstrap, as in some tests) answers with empty
/// queues instead of throwing.
const DRAIN_IO: &str = "JSON.stringify({\
    fetch: typeof __pt_drainFetchQueue === 'function' ? JSON.parse(__pt_drainFetchQueue()) : [],\
    ws: typeof __pt_drainWsQueue === 'function' ? __pt_drainWsQueue() : []})";

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
            Value::String(s) => serde_json::from_str(&s).expect("probe returned JSON"),
            other => panic!("probe did not return a JSON string: {other:?}"),
        }
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
            r#"JSON.stringify({
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
                styleGetter: Object.getOwnPropertyDescriptor(Element.prototype, 'style').get.toString(),
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
        for key in [
            "bodyOwn", "btnOwn", "inpOwn", "textOwn", "evtOwn", "docOwn", "navOwn", "navKeys",
        ] {
            let leaked = p[key]
                .as_array()
                .unwrap_or_else(|| panic!("probe missing {key}"));
            assert!(
                leaked.is_empty(),
                "{key} exposes own properties: {leaked:?}"
            );
        }

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
            r#"JSON.stringify({
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
        let p = probe(&ctx, "JSON.stringify(__t)").await;

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
              return JSON.stringify({
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
              return JSON.stringify({
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
        let p = probe(&ctx, "JSON.stringify(globalThis.__audio || null)").await;
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
            return JSON.stringify({ opaque, red, w: Math.round(w) });
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
            return JSON.stringify({ center: at(20, 20), corner: at(1, 1), green });
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
            return JSON.stringify({ l, r });
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
            return JSON.stringify({ native, compiled, cg: px[center + 1], ca: px[center + 3] });
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
            return JSON.stringify({ native, isTex, r: px[i], g: px[i + 1], b: px[i + 2] });
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

        let out = pump_until(&ctx, "JSON.stringify(__log)", 40).await;
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
        let out = pump_until(&ctx, "JSON.stringify(__log)", 20).await;
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

        let out = pump_until(&ctx, "JSON.stringify(__log)", 40).await;
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
