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

mod intercept;
pub use intercept::{Decision, PausedRequest};
use intercept::PageClient;

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
            context: None,
            method: "GET".into(),
            url: nokk_net::GEO_LOOKUP_URL.to_string(),
            headers,
            body: None,
            kind: nokk_net::RequestKind::Xhr,
            third_party: false,
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
    // Implementation trace flags (`NOKK_TRACE_CANVAS`, `NOKK_TRACE_GPU`) go first so
    // they exist in every realm before page code: a probe set later misses early calls.
    let mut flags = String::new();
    for (env, name) in [("NOKK_TRACE_CANVAS", "__pt_canvasTrace"), ("NOKK_TRACE_GRID", "__pt_gridTrace"), ("NOKK_TRACE_GPU", "__pt_gpuTrace"), ("NOKK_TRACE_ENC", "__pt_encTrace"), ("NOKK_TRACE_SRCDOC", "__pt_srcdocTrace")] {
        if let Some(v) = std::env::var_os(env) {
            // The value reaches the tracer: `NOKK_TRACE_ENC=9000-9300,8600-8700` dumps
            // report chunks of those lengths in full.
            let v = v.to_string_lossy().replace(['\'', '\\', '\n'], "");
            flags.push_str(&format!("Object.defineProperty(globalThis, '{name}', {{ value: '{v}', configurable: true }});\n"));
        }
    }
    // `NOKK_TRACE_BOOT=1` logs each bootstrap layer's time to the console (`[boot]`).
    let timed = std::env::var_os("NOKK_TRACE_BOOT").is_some();
    let mark = |name: &str| -> String {
        if timed { format!("\n;(globalThis.__pt_bootT = globalThis.__pt_bootT || []).push(['{name}', Date.now()]);\n") } else { "\n".to_string() }
    };
    let pieces: Vec<(&str, String)> = vec![
        // The write helper first: every layer uses it, and read-only properties only
        // appear in the last one.
        ("write_helper", nokk_stealth::write_helper_script()),
        ("bootstrap", nokk_stealth::bootstrap_script(profile)),
        ("dom_runtime", nokk_dom::runtime_js().to_string()),
        ("fingerprint", nokk_stealth::fingerprint_script(profile)),
        ("web_surface", nokk_stealth::web_surface_script()),
        // Late interfaces, then naturalization (every member must look native), then the
        // snapshot of methods the engine itself uses: over all layers, before any page script.
        ("late_interfaces", nokk_stealth::late_interfaces_script()),
        // `NOKK_NO_PROTO_SHAPE=1` skips the shape layer, for bisection.
        ("proto_shape", if std::env::var_os("NOKK_NO_PROTO_SHAPE").is_some() { String::new() } else { nokk_stealth::proto_shape_script() }),
        ("naturalize", nokk_stealth::naturalize_script()),
        ("late_originals", nokk_stealth::late_originals_script()),
        ("shape_fixes", nokk_stealth::shape_fixes_script()),
        // Window name order last: enumeration follows creation order, and any layer
        // that defines a name shifts it.
        ("window_order", nokk_stealth::window_order_script()),
        // Only when building the V8 snapshot (the builder defines `__pt_lateNames`): what
        // V8 installs on restore (SharedArrayBuffer, WebAssembly, Float16Array,
        // DisposableStack…) the bootstrap never saw, so redo for it what it would have done.
        ("restore_hook", format!(
            "if (globalThis.__pt_lateNames) Object.defineProperty(globalThis, '__pt_afterRestore', {{ writable: true, configurable: true, value: () => {{\n\
             try {{ delete globalThis.SharedArrayBuffer; }} catch (e) {{}}\n\
             try {{ if (globalThis.__pt_wasmStreaming) __pt_wasmStreaming(); }} catch (e) {{}}\n\
             try {{ if (globalThis.__pt_lateShape) __pt_lateShape(); }} catch (e) {{}}\n{}\n}} }});\n",
            nokk_stealth::window_order_script()
        )),
    ];
    // Internal fields (`node.__ptKids = …`) assigned plainly are enumerable: `for…in`
    // and `Object.entries` see them and `JSON.stringify(div)` throws "circular
    // structure" (Chrome gives "{}"). A setter on Object.prototype per such name,
    // collected from the bootstrap sources, makes them non-enumerable.
    let hide = internal_field_setters(pieces.iter().map(|(_, js)| js.as_str()));
    let mut base = format!("{flags}{hide}{}", mark("start"));
    for (name, js) in pieces {
        base.push_str(&js);
        base.push_str(&mark(name));
    }
    // `NOKK_DUMP_BOOT=<path>`: the assembled bootstrap, to map profile and heap
    // snapshot line numbers back to sources.
    if let Ok(path) = std::env::var("NOKK_DUMP_BOOT") {
        let _ = std::fs::write(path, &base);
    }
    if timed {
        base.push_str("\n;try { const t = globalThis.__pt_bootT; const d = []; for (let i = 1; i < t.length; i++) d.push(t[i][0] + '=' + (t[i][1] - t[i - 1][1])); console.error('[boot] ' + d.join(' ') + ' total=' + (t[t.length - 1][1] - t[0][1])); } catch (e) {}\n");
    }
    // Diagnostic only, and last so it wraps a finished surface. Reading
    // `__pt_probeLog()` afterwards says what the page asked us and what we said.
    let base = match std::env::var("NOKK_TRACE_PROBES").ok().as_deref() {
        Some("1") | Some("true") => format!("{base}\n{}", nokk_stealth::probe_tracer_script()),
        _ => base,
    };
    // Marks the script so `__pt_isBoot` knows the engine's functions in any context.
    format!("{base}\n//# sourceMappingURL={}\n", nokk_pool::BOOT_SCRIPT_MARK)
}

/// For each `__pt…` name assigned anywhere in `sources` (`.__ptX = `), a setter on
/// Object.prototype that defines the field as an own non-enumerable property.
fn internal_field_setters<'a>(sources: impl Iterator<Item = &'a str>) -> String {
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for src in sources {
        let b = src.as_bytes();
        let mut i = 0;
        while let Some(off) = src[i..].find(".__pt") {
            let start = i + off + 1;
            let mut end = start;
            while end < b.len() && (b[end].is_ascii_alphanumeric() || b[end] == b'_' || b[end] == b'$') {
                end += 1;
            }
            let mut k = end;
            while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
                k += 1;
            }
            if k < b.len() && b[k] == b'=' && !(k + 1 < b.len() && (b[k + 1] == b'=' || b[k + 1] == b'>')) {
                names.insert(src[start..end].to_string());
            }
            i = end.max(start + 1);
        }
    }
    let list = serde_json::to_string(&names.into_iter().collect::<Vec<_>>()).unwrap_or_else(|_| "[]".into());
    format!(
        "(() => {{ const P = Object.prototype; const def = Object.defineProperty, own = Object.prototype.hasOwnProperty; \
         for (const n of {list}) {{ if (own.call(P, n)) continue; \
         def(P, n, {{ get: undefined, set(v) {{ if (this === null || (typeof this !== 'object' && typeof this !== 'function')) return; \
         try {{ def(this, n, {{ value: v, writable: true, enumerable: false, configurable: true }}); }} catch (e) {{}} }}, enumerable: false, configurable: true }}); }} }})();\n"
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
        // V8 and ICU data first: the bootstrap depends on ICU (native `Intl`), and by
        // default goes into the V8 snapshot pool isolates start from. A context from the
        // snapshot comes up in milliseconds instead of ~300 ms of bootstrap execution.
        nokk_pool::init_v8();
        nokk_stealth::set_native_intl(nokk_pool::icu_ready());
        match nokk_pool::build_snapshot(&build_bootstrap(&config.stealth)) {
            Ok(_) => {}
            Err(e) => tracing::debug!(error = %e, "v8 snapshot not used"),
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

    /// Drop the pooled client (cookie jar + connection pool) bound to an
    /// anonymous identity. Called when a CDP browser context is disposed:
    /// without this the per-identity client would outlive the context and
    /// accumulate for the engine's lifetime. Named sessions keep their pooled
    /// client by design, so the caller must not release those.
    pub fn release_identity(&self, identity: &str) {
        if identity.is_empty() {
            return;
        }
        self.inner
            .client_pool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(identity);
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
        // Pick the thread for future cross-origin frames now.
        let frame_worker = self.inner.pool.pick_worker_except(worker);
        Ok(BrowserContext {
            frame_worker: std::sync::Mutex::new(frame_worker),
            frame_pump_count: std::sync::atomic::AtomicUsize::new(0),
            last_frame_turn: std::sync::Mutex::new(std::time::Instant::now()),
            frames_live: std::sync::atomic::AtomicBool::new(false),
            engine: self.inner.clone(),
            client: PageClient::new(client),
            worker,
            index: std::sync::atomic::AtomicUsize::new(index),
            base_url: std::sync::Mutex::new("about:blank".to_string()),
            doc_seq: std::sync::atomic::AtomicU64::new(0),
            carry: std::sync::Mutex::new(HashMap::new()),
            nav_started: std::sync::Mutex::new(None),
            loading: std::sync::atomic::AtomicUsize::new(0),
            sheets_gave_up: std::sync::atomic::AtomicU64::new(0),
            stop_at_clearance: std::sync::atomic::AtomicBool::new(false),
            stopped_at_clearance: std::sync::atomic::AtomicBool::new(false),
            lock_at_doc: std::sync::Mutex::new(None),
            requests: std::sync::Mutex::new(Vec::new()),
            started: std::time::Instant::now(),
            timings_sent: std::sync::Mutex::new(HashMap::new()),
            nav_sent: std::sync::Mutex::new(std::collections::HashSet::new()),
            sockets: tokio::sync::Mutex::new(PageSockets::new()),
            network_tx: std::sync::Mutex::new(None),
            frames: std::sync::Mutex::new(HashMap::new()),
            frame_docs: std::sync::Mutex::new(HashMap::new()),
            doc_types: std::sync::Mutex::new(HashMap::new()),
            workers: std::sync::Mutex::new(HashMap::new()),
            bootstrap,
            frame_init_scripts: std::sync::Mutex::new(Vec::new()),
            worker_init_scripts: std::sync::Mutex::new(Vec::new()),
            init_scripts: std::sync::Mutex::new(Vec::new()),
            inflight: std::sync::Mutex::new(Vec::new()),
            port_ends: std::sync::Mutex::new(HashMap::new()),
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
            context: None,
            method: "GET".into(),
            url: url.to_string(),
            headers,
            body: None,
            kind: nokk_net::RequestKind::Document,
            // A one-shot fetch is someone asking for an address, like typing one.
            third_party: false,
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
fn req_method(req: &Request) -> String {
    req.method.clone()
}

/// Request ids for worker request records: outside the frame index range.
const WORKER_RECORD_BASE: usize = 1 << 40;

struct FetchInfo {
    context: usize,
    id: i64,
    url: String,
    method: String,
    kind: String,
    sent: Vec<u8>,
}

/// Where to deliver the result: a frame (by context index) or a worker.
enum Deliver {
    Frame(usize),
    Worker(nokk_pool::WorkerId, usize),
}

struct InFlight {
    deliver: Deliver,
    info: FetchInfo,
    handle: tokio::task::JoinHandle<Result<nokk_net::Response, NetError>>,
    /// The page document a page request belongs to; its reply is dropped once the page
    /// has moved on. `None` for frame and worker requests.
    doc: Option<u64>,
}

enum Prepared {
    Settled(String),
    Send(Box<Request>, FetchInfo),
}

pub struct BrowserContext {
    engine: Arc<EngineInner>,
    /// This context's HTTP client — its own proxy + cookie jar when created with
    /// [`Engine::new_context_with_proxy`], else the engine default — and its
    /// request interception.
    client: PageClient,
    worker: WorkerId,
    /// The page's context on its isolate. A new document gets a new context
    /// (see `load_html`), so this changes with every navigation.
    index: std::sync::atomic::AtomicUsize,
    /// Document URL of the last `load_html`/`navigate`, used to resolve relative
    /// `fetch`/`XHR` URLs. `about:blank` until the first navigation.
    base_url: std::sync::Mutex<String>,
    /// How many documents this page has loaded. A driver that did not start a
    /// navigation itself — a form the page submitted, a challenge that moved on,
    /// a link a script followed — learns of the new document by this changing.
    doc_seq: std::sync::atomic::AtomicU64,
    /// What outlives a document but not the tab, carried from one document's
    /// context to the next: per origin its `localStorage`, `sessionStorage` and
    /// IndexedDB (`{local, session, idb}`), and under `""` the tab's history
    /// length. Taken out of the outgoing context by `__pt_carryOut`, handed to the
    /// incoming one by `__pt_carryIn` before its first script.
    carry: std::sync::Mutex<HashMap<String, Value>>,
    /// When the navigation in flight started: a document's clock starts there,
    /// not when its context was built after the response arrived.
    nav_started: std::sync::Mutex<Option<std::time::Instant>>,
    /// How many top-level documents are being loaded right now. The address
    /// changes when a load starts, the document count when it ends; in between
    /// the page is neither the old document nor yet the new one.
    loading: std::sync::atomic::AtomicUsize,
    /// The document (`doc_seq + 1`) whose blocking stylesheets timed out once:
    /// its later scripts do not wait for them again.
    sheets_gave_up: std::sync::atomic::AtomicU64,
    /// Stop at the clearance: when a response hands out a new `cf_clearance`,
    /// do not load the page behind it (see `set_stop_at_clearance`).
    stop_at_clearance: std::sync::atomic::AtomicBool,
    /// Set when a navigation stopped at a fresh clearance.
    stopped_at_clearance: std::sync::atomic::AtomicBool,
    /// The `cf_clearance` in the jar when the current document was loaded
    /// (`None` inside: there was none). A navigation away from a document after
    /// a new lock arrived is the interstitial walking on to the site.
    lock_at_doc: std::sync::Mutex<Option<Option<String>>>,
    /// Every network request the engine made for this context, in order — the
    /// built-in interception log (document + external scripts + page fetch/XHR).
    requests: std::sync::Mutex<Vec<NetworkRecord>>,
    /// When this context started, and how many of its requests have been handed
    /// to the page as Resource Timing entries.
    started: std::time::Instant,
    /// Entries already handed to each context: the page and every frame have their own timeline.
    timings_sent: std::sync::Mutex<HashMap<usize, usize>>,
    /// Frames already given their navigation entry. A frame may have no entries of its
    /// own, so this needs a separate mark.
    nav_sent: std::sync::Mutex<std::collections::HashSet<usize>>,
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
    /// Documents being fetched for frames that have no context yet, by URL.
    frame_docs: std::sync::Mutex<HashMap<String, u32>>,
    /// The type of a text or JSON document just fetched, by URL, for its
    /// `document.contentType`.
    doc_types: std::sync::Mutex<HashMap<String, String>>,
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
    /// The same, for workers. A worker has its own realm and prototypes, so a hook set
    /// on the page cannot see what the worker builds.
    worker_init_scripts: std::sync::Mutex<Vec<String>>,
    /// The same, for this page's own document. "On new document" means *before*
    /// the document's own scripts — that is the whole point of the API, and what
    /// every stealth patch and instrumentation hook depends on. Running them after
    /// the page had already executed made them useless for anything that has to be
    /// in place first.
    init_scripts: std::sync::Mutex<Vec<String>>,
    /// Frame and worker requests still on the network: JS keeps running meanwhile, as in a browser.
    inflight: std::sync::Mutex<Vec<InFlight>>,
    /// Where each end of a MessageChannel sent across a frame boundary lives:
    /// `<id>:a` stayed with the sender, `<id>:b` went with the message.
    port_ends: std::sync::Mutex<HashMap<String, usize>>,
    /// When this page's earliest pending timer comes due, as of the last turn of
    /// the event loop. `None` means nothing is pending. Timers wait out their real
    /// delays now, so a page only advances while something drives it — this is how
    /// the driver knows *when* to come back rather than polling a live page twenty
    /// times a second, or leaving its `setInterval` frozen between commands.
    next_timer_at: std::sync::Mutex<Option<std::time::Instant>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _load: nokk_pool::ContextLoadGuard,    /// Frame pump counter: the expensive extras do not run on every pump.
    frame_pump_count: std::sync::atomic::AtomicUsize,
    /// When frames last got a turn, so they get one during long sequences such as
    /// loading the page's scripts too.
    last_frame_turn: std::sync::Mutex<std::time::Instant>,
    /// The thread cross-origin frames run on; re-picked when the pool drained it.
    frame_worker: std::sync::Mutex<nokk_pool::WorkerId>,
    /// Frames are being pumped while the page waits on the network: do not re-enter
    /// them from the same pump.
    frames_live: std::sync::atomic::AtomicBool,

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
    /// A frame on its own thread keeps that thread loaded while alive.
    _load: Option<std::sync::Arc<nokk_pool::ContextLoadGuard>>,
}

/// A live worker: its own V8 context on an isolate thread of its own, and the URL
/// its own requests resolve against. A worker built from a blob has no document to
/// resolve against, so it keeps the page's base — which is what a browser does
/// with the blob's origin.
#[derive(Debug, Clone)]
struct WorkerState {
    /// Pool thread whose isolate hosts the worker's context. It need not be the page's
    /// thread (a worker is its own thread in a browser), and context indices are
    /// per isolate, so a worker is addressed by the (thread, index) pair.
    worker: nokk_pool::WorkerId,
    index: usize,
    url: String,
    fetch_base: String,
    /// While alive, the pool counts the context as its thread's load, so least-loaded
    /// thread selection sees workers.
    _load: std::sync::Arc<nokk_pool::ContextLoadGuard>,
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
        let mut indices = vec![self.idx()];
        if let Ok(frames) = self.frames.lock() {
            indices.extend(frames.values().map(|s| s.index));
        }
        if let Ok(workers) = self.workers.lock() {
            indices.extend(workers.values().map(|s| s.index));
        }
        for index in indices {
            let (w, raw) = self.route(index);
            self.engine
                .pool
                .dispatch_detached(w, move |iso| iso.dispose_context(raw));
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
    /// Already announced while paused for interception (`Fetch`), under the
    /// same id: the driver has seen `requestWillBeSent`.
    pub announced: bool,
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
    /// Body bytes on the wire, before decompression. Feeds `encodedBodySize` (and
    /// `transferSize`, which adds headers); the server knows the exact number.
    pub encoded_len: usize,
    /// Wire content encoding (`br`, `gzip`); empty if none.
    pub content_encoding: String,
    /// Milliseconds from request start to the end of the last redirect; `None` if none.
    pub redirect_ms: Option<f64>,
    /// The requesting context: the page or one of its frames. Resource timings are
    /// handed out per context, since a frame has its own timeline in a browser.
    pub context: usize,
    /// The `<iframe>` that made the request (its `FrameInfo::id`), `None` for the
    /// page. A driver told a frame's document load came from the page takes it
    /// for a navigation of the page (Playwright then answers "Loading <url>").
    pub frame: Option<u32>,
}

/// What kind of gate the page currently shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    None,
    /// Cloudflare's "Just a moment…" page (managed challenge, with or without a checkbox).
    CloudflareInterstitial,
    /// A Turnstile widget embedded in a site's own page, no token yet.
    TurnstileWidget,
    /// DataDome's gate — not something this engine solves.
    DataDome,
    /// A reCAPTCHA checkbox, no token yet (Google's /sorry/ page). An image puzzle
    /// behind it is not something this engine solves.
    RecaptchaWidget,
}

impl ChallengeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeKind::None => "none",
            ChallengeKind::CloudflareInterstitial => "cloudflare-interstitial",
            ChallengeKind::TurnstileWidget => "turnstile-widget",
            ChallengeKind::DataDome => "datadome",
            ChallengeKind::RecaptchaWidget => "recaptcha-widget",
        }
    }
}

/// A snapshot of the page's challenge situation.
#[derive(Debug, Clone)]
pub struct ChallengeState {
    pub kind: ChallengeKind,
    pub title: String,
    pub url: String,
    /// A standalone widget has issued its token.
    pub token: bool,
    /// A `cf_clearance` cookie is in the jar.
    pub cleared: bool,
}

/// How a solve attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    /// Lock obtained and the interstitial moved on (or there was none to move).
    Cleared,
    /// A standalone widget issued its token.
    TokenIssued,
    /// Lock obtained, but the interstitial stayed on its own page.
    ClearedButStuck,
    /// Nothing cleared within the budget.
    Timeout,
    /// The page showed no gate at all: nothing to solve.
    NoChallenge,
    /// The press was answered with a task for a person (reCAPTCHA's image or audio
    /// puzzle, or its "try again later"): waiting out the budget changes nothing.
    NeedsHuman,
}

impl ChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeStatus::Cleared => "cleared",
            ChallengeStatus::TokenIssued => "token-issued",
            ChallengeStatus::ClearedButStuck => "cleared-but-stuck",
            ChallengeStatus::Timeout => "timeout",
            ChallengeStatus::NoChallenge => "none",
            ChallengeStatus::NeedsHuman => "needs-human",
        }
    }
    pub fn is_success(&self) -> bool {
        matches!(self, ChallengeStatus::Cleared | ChallengeStatus::TokenIssued | ChallengeStatus::NoChallenge)
    }
}

#[derive(Debug, Clone)]
pub struct ChallengeOutcome {
    pub status: ChallengeStatus,
    pub presses: usize,
    pub elapsed_ms: u64,
}

impl BrowserContext {
    /// The worker this context is pinned to.
    pub fn worker(&self) -> WorkerId {
        self.worker
    }

    /// The thread for cross-origin frames. The pool drains a thread whose last
    /// context closed, so a frame thread can vanish between two frames; pick a
    /// live one then.
    fn frame_worker(&self) -> WorkerId {
        let mut fw = self.frame_worker.lock().unwrap_or_else(|e| e.into_inner());
        if !self.engine.pool.is_live(*fw) {
            *fw = self.engine.pool.pick_worker_except(self.worker);
        }
        *fw
    }

    /// The context's index within its isolate.
    pub fn index(&self) -> usize {
        self.idx()
    }

    /// The current document's context index.
    fn idx(&self) -> usize {
        self.index.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Evaluate JavaScript in this context and return the result stringified.
    /// The call is dispatched onto the owning isolate thread, so V8 state is
    /// only ever touched from its home thread.
    pub async fn evaluate(&self, script: &str) -> Result<Value, EngineError> {
        let index = self.idx();
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
        self.navigate_inner(url, referrer, None).await
    }

    /// Navigation with a body: a POST form submit (`form.submit()`), which is how the
    /// Cloudflare interstitial carries the clearance to the original URL.
    async fn navigate_inner(
        &self,
        url: &str,
        referrer: Option<&str>,
        post: Option<(&str, &str)>,
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
        if let Ok(mut n) = self.nav_started.lock() {
            *n = Some(std::time::Instant::now());
        }
        let mut current = url.to_string();
        let mut post = post;
        for _ in 0..MAX_META_HOPS {
            // Use the post-redirect URL as the document base, so `window.location`
            // and relative-URL resolution reflect where we actually landed.
            let stop = self.stop_at_clearance.load(std::sync::atomic::Ordering::Acquire);
            // The lock as the current document saw it — the first navigation has
            // no document yet, so the jar as it stands (a stale imported cookie
            // must not count as a fresh one).
            let lock_before = if stop {
                self.lock_at_doc
                    .lock()
                    .ok()
                    .and_then(|l| l.clone())
                    .unwrap_or_else(|| self.clearance_value())
            } else {
                None
            };
            let (final_url, html) = match post.take() {
                Some((ctype, body)) => self.fetch_document_post(&current, referrer, ctype, body).await?,
                None => self.fetch_document_retrying(&current, referrer).await?,
            };
            // The lock is what a solve is for. A caller that takes the cookie
            // elsewhere (curl with the clearance, another client) has no use for
            // the site behind it — and loading a modern site is the long half of
            // a solve: indeed.com spent 16 s on its own React bundles after the
            // challenge had already cleared.
            if stop {
                let after = self.clearance_value();
                if after.is_some() && after != lock_before {
                    tracing::info!(target: "nokk", url = %final_url, "clearance received; not loading the page behind it");
                    self.stopped_at_clearance.store(true, std::sync::atomic::Ordering::Release);
                    return Ok(());
                }
            }
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
        let js = "typeof __pt_metaRefresh === 'function' ? __pt_metaRefresh() : ''";
        match self.evaluate(js).await {
            Ok(Value::String(s)) if !s.is_empty() => resolve_url(base, &s),
            _ => None,
        }
    }

    /// Evaluate in one of this context's *sibling* V8 contexts on the same worker
    /// — an iframe's document lives in one of these (see [`Self::frames`]). The
    /// page's own context is [`Self::index`], so `eval_in(self.idx(), …)` is
    /// exactly [`Self::evaluate`].
    async fn eval_in(&self, index: usize, source: &str) -> Result<Value, EngineError> {
        let (worker, raw) = self.route(index);
        self.eval_at(worker, raw, source).await
    }

    /// Thread and context index in its isolate. The page and same-origin frames live
    /// on the page's thread; a cross-origin frame on its own, as with site isolation.
    fn route(&self, index: usize) -> (nokk_pool::WorkerId, usize) {
        if index & OWN_THREAD != 0 {
            (nokk_pool::WorkerId((index >> 32) & 0xFFFF), index & 0xFFFF_FFFF)
        } else {
            (self.worker, index)
        }
    }

    /// Run a page script named by its URL. The name goes into `ScriptOrigin`, so it shows
    /// in the script's own stack frames and as the parent of nested `eval`/`new Function`;
    /// `//# sourceURL` does not cover the latter, which came out as `unknown source`.
    async fn eval_named_in(
        &self,
        index: usize,
        source: &str,
        name: &str,
    ) -> Result<Value, EngineError> {
        let source = source.to_string();
        let name = name.to_string();
        let (worker, index) = self.route(index);
        let out = self
            .engine
            .pool
            .dispatch(worker, move |iso| {
                iso.eval_named(index, &source, Some(name.as_str()))
            })
            .await?
            .map_err(EngineError::Js)?;
        Ok(Value::String(out))
    }

    /// Same, in a context on another pool thread. Context indices are per isolate, so a
    /// worker elsewhere is addressed by (thread, index); [`Self::eval_in`] is this call
    /// for the page's thread.
    async fn eval_at(
        &self,
        worker: nokk_pool::WorkerId,
        index: usize,
        source: &str,
    ) -> Result<Value, EngineError> {
        let source = source.to_string();
        let out = self
            .engine
            .pool
            .dispatch(worker, move |iso| iso.eval(index, &source))
            .await?
            .map_err(EngineError::Js)?;
        Ok(Value::String(out))
    }

    /// Build the DOM from `html`, then run its scripts in document order and fire
    /// `DOMContentLoaded`/`load`. `base_url` resolves relative external script
    /// `src`s. Page scripts that throw are logged and skipped — a broken page
    /// script must not fail the load, matching browser behaviour.
    pub async fn load_html(&self, base_url: &str, html: &str) -> Result<(), EngineError> {
        self.loading.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let r = self.load_html_now(base_url, html).await;
        self.loading.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        r
    }

    /// Whether a top-level document is being loaded right now.
    pub fn is_loading(&self) -> bool {
        self.loading.load(std::sync::atomic::Ordering::Acquire) > 0
    }

    async fn load_html_now(&self, base_url: &str, html: &str) -> Result<(), EngineError> {
        if let Ok(mut l) = self.lock_at_doc.lock() {
            *l = Some(self.clearance_value());
        }
        // The outgoing document takes its workers with it.
        self.terminate_workers_of(None).await;
        // And its realm: a browser gives every document a fresh global, so
        // nothing the last page left on `window` (its `var`s, its patches to
        // built-ins) is visible to the next. Only the first document reuses
        // the context the page was created with, which nothing has run in yet.
        if self.doc_seq.load(std::sync::atomic::Ordering::Acquire) > 0 {
            self.fresh_realm().await?;
        }
        if let Ok(mut b) = self.base_url.lock() {
            *b = base_url.to_string();
        }
        self.carry_in(base_url).await;
        self.load_html_into(self.idx(), base_url, html).await?;
        self.doc_seq.fetch_add(1, std::sync::atomic::Ordering::Release);
        // Timers and async continuations scheduled during load (and by the load
        // handlers) get their turn now — with the load-time patience for delays
        // the page actually asked for.
        self.run_event_loop_for_load().await?;
        Ok(())
    }

    /// Swap the page's context for a new one built from the same bootstrap:
    /// first take out what outlives a document (`carry`), end the outgoing
    /// document's frames, then dispose its context.
    async fn fresh_realm(&self) -> Result<(), EngineError> {
        let old = self.idx();
        let out = self
            .eval_in(old, "typeof __pt_carryOut === 'function' ? __pt_carryOut() : ''")
            .await
            .ok()
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()));
        if let Some(out) = out {
            let origin = origin_of(&self.document_url());
            if let Ok(mut c) = self.carry.lock() {
                if !origin.is_empty() {
                    c.insert(
                        origin,
                        serde_json::json!({ "storage": out["storage"], "idb": out["idb"] }),
                    );
                }
                if out["hist"].is_number() {
                    c.insert(String::new(), out["hist"].clone());
                }
            }
        }
        // The outgoing document's frames end with it.
        let frames: Vec<FrameState> = self
            .frames
            .lock()
            .map(|mut f| f.drain().map(|(_, s)| s).collect())
            .unwrap_or_default();
        for f in frames {
            self.terminate_workers_of(Some(f.index)).await;
            let (w, raw) = self.route(f.index);
            let _ = self
                .engine
                .pool
                .dispatch(w, move |iso| iso.dispose_context(raw))
                .await;
        }
        let boot = self.bootstrap.clone();
        let fresh = self
            .engine
            .pool
            .dispatch(self.worker, move |iso| iso.create_context(&boot))
            .await?
            .map_err(EngineError::Js)?;
        self.index.store(fresh, std::sync::atomic::Ordering::Release);
        // Its clock runs from the start of the navigation, as a frame's does.
        let started = self.nav_started.lock().ok().and_then(|mut n| n.take());
        if let Some(t) = started {
            let ago = t.elapsed().as_secs_f64() * 1000.0;
            let _ = self
                .eval_in(fresh, &format!("globalThis.__pt_shiftOrigin && __pt_shiftOrigin({ago:.3});"))
                .await;
        }
        let _ = self
            .engine
            .pool
            .dispatch(self.worker, move |iso| iso.dispose_context(old))
            .await;
        if let Ok(mut t) = self.timings_sent.lock() {
            t.remove(&old);
        }
        if let Ok(mut n) = self.nav_sent.lock() {
            n.remove(&old);
        }
        tracing::debug!(old, fresh, "new document, new realm");
        Ok(())
    }

    /// Hand the incoming document what its origin and its tab kept.
    async fn carry_in(&self, base_url: &str) {
        let v = {
            let Ok(c) = self.carry.lock() else { return };
            let mut v = c.get(&origin_of(base_url)).cloned().unwrap_or_else(|| serde_json::json!({}));
            if let Some(h) = c.get("") {
                v["hist"] = h.clone();
            }
            v
        };
        if v.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            return;
        }
        let js = format!(
            "typeof __pt_carryIn === 'function' && __pt_carryIn({})",
            js_str(&v.to_string())
        );
        let _ = self.eval_in(self.idx(), &js).await;
    }

    /// Stop at the clearance: once a response hands out a new `cf_clearance`,
    /// the navigation ends there instead of loading the page behind it, and the
    /// solver reports `cleared` at once. For callers that only want the cookie.
    pub fn set_stop_at_clearance(&self, on: bool) {
        self.stop_at_clearance.store(on, std::sync::atomic::Ordering::Release);
    }

    /// Whether a navigation stopped at a fresh clearance (stop-at-clearance
    /// mode): the page still shows the gate, and the lock is in the jar.
    pub fn stopped_at_clearance(&self) -> bool {
        self.stopped_at_clearance.load(std::sync::atomic::Ordering::Acquire)
    }

    fn clearance_value(&self) -> Option<String> {
        self.client.cookies().into_iter().find(|c| c.name == "cf_clearance").map(|c| c.value)
    }

    /// The number of documents this page has loaded so far (see `doc_seq`).
    pub fn document_seq(&self) -> u64 {
        self.doc_seq.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The address of the document on the page now, after redirects.
    pub fn document_url(&self) -> String {
        self.base_url.lock().map(|b| b.clone()).unwrap_or_default()
    }

    /// The document response's Content-Security-Policy header; applied to the context
    /// before its first script (`__pt_applyCsp`).
    fn document_csp(&self, url: &str) -> Option<String> {
        let log = self.requests.lock().ok()?;
        let r = log.iter().rev().find(|r| r.url == url)?;
        let v = r.headers.get("content-security-policy")?;
        if v.trim().is_empty() { None } else { Some(v.to_string()) }
    }

    /// Charset declared by the document response's `Content-Type`, if any.
    fn document_charset(&self, url: &str) -> Option<String> {
        let log = self.requests.lock().ok()?;
        let r = log.iter().rev().find(|r| r.url == url)?;
        let ct = r.headers.get("content-type")?.to_ascii_lowercase();
        let i = ct.find("charset=")?;
        let rest = &ct[i + 8..];
        let label: String = rest
            .trim_start_matches('"')
            .chars()
            .take_while(|c| !matches!(c, ';' | '"' | ' ' | ','))
            .collect();
        if label.is_empty() { None } else { Some(label) }
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
        let doc_type = self.doc_types.lock().ok().and_then(|mut t| t.remove(base_url));
        if let Some(mime) = doc_type {
            let js = format!(
                "Object.defineProperty(document, '__ptDocType', {{ value: {}, writable: true, configurable: true }});",
                serde_json::to_string(&mime).unwrap_or_default()
            );
            let _ = self.eval_in(index, &js).await;
        }
        // Then the client's own "on new document" scripts, still before the
        // document exists — a frame gets its set from `apply_frame_ops`, the page
        // gets its own here. After the page's scripts would be too late to matter.
        if index == self.idx() {
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
        let t_parse = std::time::Instant::now();
        tracing::debug!(target: "nokk::load", bytes = html.len(), "parse start");
        let page = nokk_dom::parse(html);
        tracing::debug!(target: "nokk::load", ms = t_parse.elapsed().as_millis() as u64, "parsed");
        let install = page.install_script();
        tracing::debug!(target: "nokk::load", bytes = install.len(), ms = t_parse.elapsed().as_millis() as u64, "install script built");

        // Install the parsed tree as `document`.
        self.eval_in(index, &install).await?;
        tracing::debug!(target: "nokk::load", ms = t_parse.elapsed().as_millis() as u64, "document installed");
        self.sync_cookie_mirror(index, base_url).await;
        if let Some(csp) = self.document_csp(base_url) {
            let js = format!("try {{ if (typeof __pt_applyCsp === 'function') __pt_applyCsp({}, 'header'); }} catch (e) {{}}", js_str(&csp));
            let _ = self.eval_in(index, &js).await;
        }
        // Charset from the response header: with `charset=utf-8` in Content-Type a browser
        // reports UTF-8 even when the markup says nothing.
        if let Some(charset) = self.document_charset(base_url) {
            let js = format!(
                "try {{ Object.defineProperty(document, '__ptCharset', {{ value: (typeof __normEncoding === 'function' ? __normEncoding({0}) : {0}), configurable: true, enumerable: false }}); }} catch (e) {{}}",
                js_str(&charset)
            );
            let _ = self.eval_in(index, &js).await;
        }

        // Execute scripts in order against the live document. `idx` matches the
        // document-order script list the DOM runtime built, so `__pt_beginScript`
        // can point `document.currentScript` at the running node (document.write
        // positioning); `__pt_endScript` clears it afterward.
        // Parser-executed scripts first, then `async` ones as they become ready, then
        // deferred ones in document order. Between them parsing ends and `readyState`
        // becomes `interactive`.
        let mode_of = |i: usize| {
            page.script_modes
                .get(i)
                .copied()
                .unwrap_or(nokk_dom::ScriptMode::Blocking)
        };
        let n = page.scripts.len();
        let blocking = (0..n).filter(|&i| mode_of(i) == nokk_dom::ScriptMode::Blocking);
        let later = (0..n)
            .filter(|&i| mode_of(i) == nokk_dom::ScriptMode::Async)
            .chain((0..n).filter(|&i| mode_of(i) == nokk_dom::ScriptMode::Defer));
        let plan: Vec<Option<usize>> = blocking
            .map(Some)
            .chain(std::iter::once(None))
            .chain(later.map(Some))
            .collect();
        // Preload scanner: a browser finds a document's external scripts while parsing and
        // requests them all at once, executing in its own order. Fetching each only when
        // its turn came chained chess.com's hundred files: a second from api.js start to
        // widget render vs 200-300 ms in Chrome, and that number goes into the first POST.
        let mut preload: HashMap<String, Preloaded> = HashMap::new();
        if index == self.idx() && std::env::var_os("NOKK_NO_PRELOAD").is_none() {
            for script in &page.scripts {
                let (nokk_dom::Script::External(src) | nokk_dom::Script::ExternalModule(src)) = script else {
                    continue;
                };
                let Some(abs) = resolve_url(base_url, src) else { continue };
                if preload.contains_key(&abs)
                    || (self.engine.block_trackers && nokk_net::is_blocked_url(&abs))
                {
                    continue;
                }
                let req = self.get_request(&abs, "script", None);
                let client = self.client.clone();
                let started = std::time::Instant::now();
                let handle = tokio::spawn(async move { client.send(req).await });
                preload.insert(abs, (started, handle));
            }
        }
        for step in plan {
            let Some(idx) = step else {
                let _ = self.eval_in(index, "__pt_parseDone()").await;
                continue;
            };
            let script = &page.scripts[idx];
            tracing::debug!(target: "nokk::load", idx, kind = match script {
                nokk_dom::Script::InlineModule(_) => "inline module",
                nokk_dom::Script::ExternalModule(_) => "module",
                nokk_dom::Script::Skipped => "skipped",
                _ => "script",
            }, "script step");
            // Give frames a turn before every document script: pages like chess.com load
            // dozens, modules included, and a module leaves this loop early.
            if index == self.idx() {
                self.frames_take_a_turn().await;
                let is_async = page.script_modes.get(idx) == Some(&nokk_dom::ScriptMode::Async);
                self.wait_for_blocking_sheets(index, if is_async { SHEETS_WAIT_ASYNC } else { SHEETS_WAIT }).await;
            }
            // `<script nomodule>` is addressed to a browser without modules. We
            // have them, so we are not the audience — and a site that ships both
            // halves (every Vite build does) runs its whole app twice if we take
            // the fallback as well.
            if matches!(script, nokk_dom::Script::Skipped) {
                continue;
            }
            // Document CSP: inline without a nonce, or a blocked URL, is skipped.
            if let Ok(v) = self
                .eval_in(index, &format!("(typeof __pt_cspScriptBlocked === 'function' && __pt_cspScriptBlocked({idx})) ? 'blocked' : ''"))
                .await
            {
                if v.as_str() == Some("blocked") {
                    continue;
                }
            }
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
                        Some(abs) => match self.with_frames_live(self.take_preloaded(preload.remove(&abs), &abs)).await {
                            Ok((_, source)) => self.run_module(index, &abs, source).await,
                            Err(e) => Err(EngineError::Js(e.to_string())),
                        },
                        None => Err(EngineError::Js(format!("cannot resolve {code}"))),
                    }
                };
                tracing::debug!(target: "nokk::load", idx, ok = outcome.is_ok(), "module done");
                if let Err(e) = outcome {
                    tracing::debug!(error = %e, "page module threw");
                }
                let _ = self.eval_in(index, "__pt_endScript()").await;
                continue;
            }
            // Which script it was, for the log below: an anonymous "a script
            // threw" says nothing on a page that runs forty of them.
            // The script's name is its URL; an inline script gets the page URL, as in a browser.
            let mut whose = if base_url.is_empty() {
                String::from("inline")
            } else {
                base_url.to_string()
            };
            let code = match script {
                // Inline scripts are named too: in a browser their stack frames carry the
                // document URL, not `<anonymous>`, and pages parse `new Error().stack`.
                nokk_dom::Script::Inline(code) if !base_url.is_empty() => code.clone(),
                nokk_dom::Script::Inline(code) => code.clone(),
                nokk_dom::Script::External(src) => match resolve_url(base_url, src) {
                    Some(abs) => {
                        // Don't fetch or run tracker/analytics scripts — the point
                        // of the blocklist is that they never execute.
                        if self.engine.block_trackers && nokk_net::is_blocked_url(&abs) {
                            self.record("GET", &abs, "script", 0, &[]);
                            continue;
                        }
                        match self.with_frames_live(self.take_preloaded(preload.remove(&abs), &abs)).await {
                            // `sourceURL` matters: without it every stack frame reads `<anonymous>` instead
                            // of the script URL, and the stack shape is part of the fingerprint.
                            Ok((_, code)) => {
                                whose = abs.clone();
                                code
                            }
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
                nokk_dom::Script::InlineModule(_)
                | nokk_dom::Script::ExternalModule(_)
                | nokk_dom::Script::Skipped => continue,
            };
            // The script's timing entry must be visible while it runs: in a browser the
            // response arrived before the script started. Turnstile's api.js looks up its own
            // entry on its first line and hands it to the widget.
            self.flush_resource_timings(index).await;
            let _ = self
                .eval_in(index, &format!("__pt_beginScript({idx})"))
                .await;
            let ran = if index == self.idx() {
                self.with_frames_live(self.eval_named_in(index, &code, &whose)).await
            } else {
                self.eval_named_in(index, &code, &whose).await
            };
            if let Err(e) = ran {
                // For an inline script the address is the page's, so name it by
                // its opening instead — enough to find it in the document.
                let head: String = code.chars().filter(|c| !c.is_control()).take(70).collect();
                tracing::debug!(error = %e, script = %whose, %head, "page script threw");
            }
            let _ = self.eval_in(index, "__pt_endScript()").await;
        }

        // Fire lifecycle events. Draining the loop afterwards is the *caller's*
        // job: for the top-level page that is `load_html` below, and for a frame
        // it is `pump_frames`, which gives it turns of its own. Pumping here would
        // mean a frame's load re-entering the parent's whole event loop.
        // Before the load events: a page reading timings in `load` must see the full list.
        // Top page only: the request log is per context, and handing it to a frame would
        // mislead the frame and leave nothing for the page.
        if index == self.idx() {
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
        self.run_event_loop_waiting(IDLE_WAIT_BUDGET, false).await
    }

    /// [`Self::run_event_loop`] with a longer patience for timers, used while a
    /// document is loading: work deferred by a few hundred milliseconds is still
    /// part of the load, and a caller that just navigated is waiting anyway.
    async fn run_event_loop_for_load(&self) -> Result<u32, EngineError> {
        self.run_event_loop_waiting(LOAD_WAIT_BUDGET, false).await
    }

    /// The loop both of the above run. `idle_wait` is the *total* time it may
    /// spend waiting for timers that are not due yet — time spent doing nothing,
    /// as opposed to the deadline, which bounds the whole call.
    async fn run_event_loop_waiting(
        &self,
        idle_wait: std::time::Duration,
        until_sheets: bool,
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
        let index = self.idx();
        let base = self.base_url.lock().map(|b| b.clone()).unwrap_or_default();

        let mut total_timers = 0u32;
        let mut waited = std::time::Duration::ZERO;
        // Due on the first round: a frame inserted by the document's own scripts
        // has been waiting since before this call started.
        let mut last_frame_pump = std::time::Instant::now() - FRAME_PUMP_EVERY;
        let mut last_spare_topup = std::time::Instant::now() - std::time::Duration::from_secs(1);

        for _ in 0..MAX_ROUNDS {
            if std::time::Instant::now() >= deadline {
                break;
            }
            // Stopped at a fresh clearance: the gate's page has nothing more to
            // give, and running its timers out only delayed the solver's answer
            // by a second and a half.
            if self.stopped_at_clearance.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }

            // 0. Timings first, before anything the page runs this round. A script
            //    that has just loaded reads the timing of its own <script> the
            //    moment it starts — Turnstile's loader puts `apiJsResourceTiming`
            //    into the config it posts to the widget — and flushing after the
            //    round meant the entry appeared one round too late: the key was
            //    simply absent from the message, where a browser always has it.
            if index == self.idx() {
                self.flush_resource_timings(index).await;
            }

            // 1. Run timers to (virtual-time) exhaustion on the worker. TIMER_CAP
            //    is a *total* budget across rounds so a runaway `setInterval` is
            //    bounded overall, not merely per round.
            let remaining = TIMER_CAP.saturating_sub(total_timers);
            // Workers run here too, not in a queue after the page: they live on other pool
            // threads, so neither waits for the other. Reply time then comes from message
            // latency, as in a browser.
            let page_slice = self.engine.pool.dispatch(self.worker, move |iso| {
                // Short per-round grab so the worker is released back to other
                // contexts frequently (fairness), rather than held for seconds.
                iso.run_event_loop(index, remaining, std::time::Duration::from_millis(250))
            });
            let (page, workers) = self
                .with_frames_live(async { tokio::join!(page_slice, self.pump_workers()) })
                .await;
            let ran = page?.map_err(EngineError::Js)?;
            let pumped_workers = workers?;
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
            let cookie_ops: Vec<Value> = queues["cookies"].as_array().cloned().unwrap_or_default();
            let worker_ops: Vec<Value> = queues["workers"].as_array().cloned().unwrap_or_default();
            self.log_console("page", &queues);
            // How long until the page's next timer, straight from the same queue
            // the driver just pumped: -1 for "nothing pending".
            // The queue clock is fractional now ("in 49.9 ms"): `as_i64` returned None,
            // meaning "no timers", and loading stopped waiting for them.
            let next_timer_ms = queues["timers"]
                .as_f64()
                .map(|v| if v < 0.0 { -1 } else { v.ceil() as i64 })
                .unwrap_or(-1);
            self.note_next_timer(next_timer_ms);

            // 3. Sockets: apply what the page asked for, then hand it whatever the
            //    sockets have produced since the last round.
            // Cookie writes first: the requests and the navigation below carry them.
            if self.apply_cookie_ops(&base, &cookie_ops) {
                self.sync_cookie_mirror(index, &base).await;
            }
            self.apply_ws_ops(&base, &ws_ops).await;
            let delivered = self.deliver_ws_events(index).await?;

            // 4. Frames the page just connected get built now — that is cheap, and
            //    a widget polls `contentWindow` the instant it inserts one. Scripts
            //    it inserted run here too, before the round's fetches: everything
            //    after them usually depends on what they define.
            self.apply_frame_ops(&base, &frame_ops).await;
            self.apply_worker_ops(index, &base, &worker_ops).await;
            self.apply_script_ops(index, &base, &script_ops).await;
            // `import()` asks the engine directly, bypassing the page's queues.
            self.serve_dynamic_imports().await;

            // 5. The page asked to go somewhere. Only the last request counts —
            //    a script that assigns `location.href` twice in a turn ends up at
            //    the second address, as it would in a browser — and the loop stops
            //    here: everything below belongs to a document that no longer
            //    exists. The caller's next pump drives the new one.
            if let Some(op) = nav_ops.last() {
                if let Some(url) = op["url"].as_str() {
                    if index == self.idx() {
                        let to = url.to_string();
                        let via = op["via"].as_str().unwrap_or("");
                        tracing::debug!(url = %to, via, method = op["method"].as_str().unwrap_or("GET"), body_len = op["body"].as_str().map(|b| b.len()).unwrap_or(0), "page navigated itself");
                        // Boxed: the loop is reached *from* `navigate`, so this
                        // is a recursive async call and needs an indirection.
                        let from = base.clone();
                        let from = (!from.is_empty() && from != "about:blank").then_some(from);
                        let post = (op["method"].as_str() == Some("POST")).then(|| (
                            op["contentType"].as_str().unwrap_or("application/x-www-form-urlencoded").to_string(),
                            op["body"].as_str().unwrap_or("").to_string(),
                        ));
                        let post_ref = post.as_ref().map(|(c, b)| (c.as_str(), b.as_str()));
                        if let Err(e) = Box::pin(self.navigate_inner(&to, from.as_deref(), post_ref)).await {
                            tracing::debug!(url = %to, error = %e, "self-navigation failed");
                        }
                        return Ok(total_timers);
                    }
                }
            }

            if index == self.idx() {
                self.flush_resource_timings(index).await;
            }

            let busy = ran > 0
                || pumped_workers > 0
                || !worker_ops.is_empty()
                || !reqs.is_empty()
                || !ws_ops.is_empty()
                || !script_ops.is_empty()
                || delivered > 0;

            // 5. Perform each fetch off the isolate thread, then settle its
            //    Promise back on the worker.
            // A round's requests go out together, as in a browser that does not wait for a
            // font to ask for a stylesheet; one by one cost a page with ten head links half a
            // second before its first script. The queue is already drained, so anything not
            // done here never settles: stake.com had 128 stylesheets behind 389 module
            // preloads and waited forever when only the first 200 were taken. All, in batches.
            // A request still out after PAGE_FETCH_GRACE stops holding the round and is
            // answered by a later one, as in a browser. Waiting for every request let one
            // dead host (a stylesheet that never connects) stall the page's JS for the
            // whole request timeout.
            let mut settles = Vec::with_capacity(reqs.len());
            for batch in reqs.chunks(MAX_FETCHES) {
                let started: Vec<_> = batch
                    .iter()
                    .map(|r| match self.prepare_fetch(index, &base, r) {
                        Prepared::Settled(js) => Err(js),
                        Prepared::Send(req, info) => {
                            let client = self.client.clone();
                            Ok((info, tokio::spawn(async move { client.send(*req).await })))
                        }
                    })
                    .collect();
                let all_done = async {
                    while started.iter().any(|s| matches!(s, Ok((_, h)) if !h.is_finished())) {
                        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                    }
                };
                let _ = self
                    .with_frames_live(tokio::time::timeout(PAGE_FETCH_GRACE, all_done))
                    .await;
                for s in started {
                    match s {
                        Err(js) => settles.push(js),
                        Ok((info, handle)) if handle.is_finished() => {
                            let res = match handle.await {
                                Ok(r) => r,
                                Err(e) => Err(NetError::Connect(format!("fetch task failed: {e}"))),
                            };
                            settles.push(self.settle_fetch(&info, res));
                        }
                        Ok((info, handle)) => {
                            tracing::debug!(target: "nokk::load", url = %info.url, "slow request left in flight");
                            let doc = Some(self.doc_seq.load(std::sync::atomic::Ordering::Acquire));
                            if let Ok(mut v) = self.inflight.lock() {
                                v.push(InFlight { deliver: Deliver::Frame(index), info, handle, doc });
                            }
                        }
                    }
                }
            }
            // A response's Set-Cookie is in the jar before the page sees the response.
            if !settles.is_empty() && index == self.idx() {
                self.sync_cookie_mirror(index, &base).await;
            }
            for settle in settles {
                let (w, raw) = self.route(index);
                self.engine
                    .pool
                    .dispatch(w, move |iso| iso.eval(raw, &settle))
                    .await?
                    .map_err(EngineError::Js)?;
                // Give frames turns between loads. While chess.com pulls a hundred files in
                // sequence, the widget's frame would stall (8 s on its own clock vs 1.5 s in a
                // browser, where the cross-origin frame has its own thread).
                if self.has_frames()
                    && last_frame_pump.elapsed() >= FRAME_PUMP_EVERY
                    && std::time::Instant::now() < deadline
                {
                    last_frame_pump = std::time::Instant::now();
                    self.pump_frames().await?;
                }
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
                let gap = last_frame_pump.elapsed().as_millis() as u64;
                last_frame_pump = std::time::Instant::now();
                let t = std::time::Instant::now();
                frames_ran = self.pump_frames().await?;
                tracing::debug!(target: "nokk::pace", gap_ms = gap,
                    pump_ms = t.elapsed().as_millis() as u64, frames_ran, "frame round");
            }

            // Only markup stylesheets were awaited and they arrived: run the next script
            // rather than everything the page has queued.
            if until_sheets {
                let left = self
                    .eval_in(index, "globalThis.__ptBlockingSheets | 0")
                    .await
                    .ok()
                    .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                    .unwrap_or(0);
                if left == 0 {
                    break;
                }
            }

            // A slow page request that has just answered is work for this round.
            let late = self.settle_inflight().await?;
            if busy || late > 0 || frames_ran > 0 || !frame_ops.is_empty() {
                continue;
            }
            // Frame and worker replies are still in flight: wait a bit and give frames a
            // turn instead of declaring idle. A slow page request is not waited for here;
            // it can take the whole request timeout.
            if self.inflight_awaited() && std::time::Instant::now() < deadline {
                tokio::time::sleep(FRAME_PUMP_EVERY).await;
                if self.has_frames() {
                    last_frame_pump = std::time::Instant::now();
                    self.pump_frames().await?;
                }
                let _ = self.settle_inflight().await?;
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
                    // Waiting for a page timer must not freeze frames: they run on their own clocks,
                    // and a widget needs its 200 ms ticks while the page waits a second. Sleeping
                    // the whole wait caused the second-long gaps.
                    let until = std::time::Instant::now() + d;
                    loop {
                        let left = until.saturating_duration_since(std::time::Instant::now());
                        if left.is_zero() {
                            break;
                        }
                        tokio::time::sleep(left.min(FRAME_PUMP_EVERY)).await;
                        if self.has_frames()
                            && last_frame_pump.elapsed() >= FRAME_PUMP_EVERY
                            && std::time::Instant::now() < deadline
                        {
                            last_frame_pump = std::time::Instant::now();
                                    self.pump_frames().await?;
                        }
                    }
                    continue;
                }
            }

            // Page idle: top up spare realms on its thread and one ready worker context on
            // each pool thread (at most every 500 ms: even an empty check is a queued task).
            if std::env::var_os("NOKK_NO_SPARE_REALMS").is_none() {
                self.engine.pool.dispatch_detached(self.worker, |iso| iso.top_up_realms(4, 1));
                if last_spare_topup.elapsed() >= std::time::Duration::from_millis(500) {
                    last_spare_topup = std::time::Instant::now();
                    for w in self.engine.pool.live_worker_ids() {
                        // Not on the page or frame threads: building occupies them for hundreds of
                        // milliseconds and page timers wait.
                        if w == self.worker || w == self.frame_worker() {
                            continue;
                        }
                        let boot = self.bootstrap.clone();
                        self.engine
                            .pool
                            .dispatch_detached(w, move |iso| iso.prewarm_contexts(&boot, 1));
                    }
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
    /// What `document.cookie` reads at `url`: the jar's cookies for it, HttpOnly
    /// left out (and Secure ones on plain http), longer paths first as Chrome lists them.
    fn document_cookie_for(&self, url: &str) -> String {
        let Ok(u) = url::Url::parse(url) else { return String::new() };
        if !matches!(u.scheme(), "http" | "https") {
            return String::new();
        }
        let https = u.scheme() == "https";
        let mut v: Vec<CookieRecord> = self
            .cookies(&[url.to_string()])
            .into_iter()
            .filter(|c| !c.http_only && (https || !c.secure))
            .collect();
        v.sort_by_key(|c| std::cmp::Reverse(c.path.as_deref().unwrap_or("/").len()));
        v.iter().map(|c| format!("{}={}", c.name, c.value)).collect::<Vec<_>>().join("; ")
    }

    /// Bring the document's `document.cookie` to what the jar holds.
    async fn sync_cookie_mirror(&self, index: usize, url: &str) {
        let js = format!(
            "typeof __pt_setCookieMirror === 'function' && __pt_setCookieMirror({})",
            js_str(&self.document_cookie_for(url))
        );
        let _ = self.eval_in(index, &js).await;
    }

    /// Put the page's `document.cookie` writes in the jar, before its next request.
    /// A script cannot replace an HttpOnly cookie. True if anything was stored.
    fn apply_cookie_ops(&self, url: &str, ops: &[Value]) -> bool {
        if !url.starts_with("http") {
            return false;
        }
        let mut stored = false;
        for raw in ops.iter().filter_map(Value::as_str) {
            let name = raw.split(';').next().unwrap_or("").split('=').next().unwrap_or("").trim();
            if self.cookies(&[url.to_string()]).iter().any(|c| c.http_only && c.name == name) {
                continue;
            }
            self.client.set_cookie(raw, url);
            stored = true;
        }
        stored
    }

    /// Store a cookie as if `Set-Cookie: <set_cookie>` had come from `url` (CDP
    /// `Network.setCookies`, Playwright's `addCookies`).
    pub fn set_cookie(&self, set_cookie: &str, url: &str) {
        self.client.set_cookie(set_cookie, url);
    }

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
        // Held means the page's loop is working its sockets right now: that is
        // a yes, and waiting for it would stall whoever asked (the cdp tick).
        match self.sockets.try_lock() {
            Ok(s) => !s.open.is_empty(),
            Err(_) => true,
        }
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

    /// Register a script to run in every worker this page starts, right after
    /// the worker's own stealth scope and before its script. Same bound as the
    /// frame list.
    pub fn add_worker_init_script(&self, src: String) {
        if let Ok(mut v) = self.worker_init_scripts.lock() {
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
    /// The `<iframe>` (its `FrameInfo::id`) whose context this is; `None` for the
    /// page and anything that is not a frame.
    pub fn frame_of_context(&self, context: usize) -> Option<u32> {
        self.frames
            .lock()
            .ok()
            .and_then(|f| f.iter().find(|(_, s)| s.index == context).map(|(id, _)| *id))
    }

    /// The `<iframe>` whose document is being fetched from `url`, before the
    /// frame has a context of its own.
    pub fn frame_for_document(&self, url: &str) -> Option<u32> {
        self.frame_docs.lock().ok().and_then(|d| d.get(url).copied())
    }

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
            let sent = self
                .timings_sent
                .lock()
                .map(|c| c.get(&index).copied().unwrap_or(0))
                .unwrap_or(0);
            // Each context gets only its own requests: a frame has its own timeline in a browser.
            let all: Vec<NetworkRecord> = self
                .requests
                .lock()
                .map(|r| r.iter().filter(|x| x.context == index).cloned().collect())
                .unwrap_or_default();
            (sent, all)
        };
        // A browser shows a frame's document twice: as an `initiatorType: "iframe"`
        // resource in the parent and as the frame's own navigation. There is one record,
        // so the frame gets it separately, first.
        let nav_due = index != self.idx()
            && self
                .nav_sent
                .lock()
                .map(|mut s| s.insert(index))
                .unwrap_or(false);
        if nav_due {
            let url = self
                .frames
                .lock()
                .ok()
                .and_then(|f| f.values().find(|s| s.index == index).map(|s| s.url.clone()));
            if let Some(url) = url {
                let doc = self
                    .requests
                    .lock()
                    .ok()
                    .and_then(|log| log.iter().find(|r| r.url == url).cloned());
                if let Some(r) = doc {
                    let entry = serde_json::json!({
                        "name": r.url,
                        "entryType": "navigation",
                        "initiatorType": "navigation",
                        "start": 0.0,
                        "duration": r.duration_ms,
                        "size": r.encoded_len + 300,
                        "decoded": r.body.len(),
                        "tao": r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("timing-allow-origin")).map(|(_, v)| v.clone()),
                    "encoding": r.content_encoding,
                        "status": r.status,
                        "protocol": "h2",
                        "contentType": r.headers.get("content-type").cloned().unwrap_or_default(),
                    });
                    let js = format!(
                        "globalThis.__pt_noteResources && __pt_noteResources({})",
                        js_str(&Value::Array(vec![entry]).to_string())
                    );
                    let _ = self.eval_in(index, &js).await;
                }
            }
        }
        if records.len() <= from {
            return;
        }
        let fresh: Vec<Value> = records[from..]
            .iter()
            .enumerate()
            .map(|(i, r)| {
                // Each document has its own navigation entry: the page's URL for the page, the
                // frame's for a frame. Everything else it requested is a resource.
                let top_document = from + i == 0 && r.resource_type == "document";
                let kind = if top_document { "navigation" } else { "resource" };
                // Initiator names as a browser gives them: `link` for a `<link>` stylesheet,
                // `xmlhttprequest` for XHR, `img` only for real images. Pages read this list.
                let initiator = match r.resource_type.as_str() {
                    "script" => "script",
                    "xhr" => "xmlhttprequest",
                    "fetch" => "fetch",
                    "document" if top_document => "navigation",
                    "document" => "iframe",
                    "stylesheet" => "link",
                    "css" => "css",
                    "img" | "image" => "img",
                    "font" => "css",
                    "websocket" | "beacon" => "other",
                    _ => "link",
                };
                serde_json::json!({
                    "name": r.url,
                    "entryType": kind,
                    "initiatorType": initiator,
                    // A browser's navigation entry always starts at 0: it is the origin for all the
                    // others.
                    "start": if top_document { 0.0 } else { r.started_ms },
                    "duration": r.duration_ms,
                    "size": r.encoded_len + 300,
                    "decoded": r.body.len(),
                    "tao": r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("timing-allow-origin")).map(|(_, v)| v.clone()),
                    "encoding": r.content_encoding,
                    "redirect": r.redirect_ms,
                    "status": r.status,
                    "protocol": "h2",
                    "contentType": r.headers.get("content-type").cloned().unwrap_or_default(),
                })
            })
            .collect();
        if let Ok(mut c) = self.timings_sent.lock() {
            c.insert(index, records.len());
        }
        // Entry times are on the page clock; a frame has its own (later timeOrigin), so it
        // gets the page's clock origin in epoch ms and converts.
        let page_epoch = if index != self.idx() {
            let since = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64() * 1000.0)
                .unwrap_or(0.0);
            since - self.started.elapsed().as_secs_f64() * 1000.0
        } else {
            0.0
        };
        let js = format!(
            "globalThis.__pt_noteResources && __pt_noteResources({}, {page_epoch})",
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
    /// Wait, keeping the page running. A pause with the event loop stopped is
    /// not a pause a page can feel — its timers would all fire at the far end.
    async fn settle(&self, how_long: std::time::Duration) {
        let until = std::time::Instant::now() + how_long;
        while std::time::Instant::now() < until {
            // While the page is busy sleep 0.5 ms between pumps, not 5: a browser's 1 ms timer
            // fires after 1 ms (we got 3, and 5 instead of 4 for nested ones). Frame rate and
            // nested-timer clamping are common engine probes.
            let worked = self.run_event_loop().await.unwrap_or(0);
            let nap = if worked > 0 { 500 } else { 5_000 };
            tokio::time::sleep(std::time::Duration::from_micros(nap)).await;
        }
    }

    /// What stands between the page and the site right now, as a driver would
    /// want to hear it: nothing, a Cloudflare interstitial ("Just a moment…"),
    /// a standalone Turnstile widget, or another vendor's gate (DataDome).
    pub async fn challenge_state(&self) -> ChallengeState {
        let js = "typeof __pt_gateInfo === 'function' ? __pt_gateInfo() : '{}'";
        let v = self.evaluate(js).await.ok();
        let parsed: Option<serde_json::Value> = v
            .as_ref()
            .and_then(|x| x.as_str())
            .and_then(|t| serde_json::from_str(t).ok());
        let g = |k: &str| parsed.as_ref().and_then(|o| o[k].as_bool()).unwrap_or(false);
        let cleared = self.cookies(&[]).iter().any(|c| c.name == "cf_clearance");
        let kind = if g("inter") {
            ChallengeKind::CloudflareInterstitial
        } else if g("datadome") {
            ChallengeKind::DataDome
        } else if g("widget") && !g("token") {
            ChallengeKind::TurnstileWidget
        } else if g("recaptcha") && !g("token") {
            ChallengeKind::RecaptchaWidget
        } else {
            ChallengeKind::None
        };
        ChallengeState {
            kind,
            title: parsed.as_ref().and_then(|o| o["title"].as_str()).unwrap_or("").to_string(),
            url: parsed.as_ref().and_then(|o| o["url"].as_str()).unwrap_or("").to_string(),
            token: g("token"),
            cleared,
        }
    }

    /// Wait for a challenge on the page to finish, pressing whatever it puts up
    /// (a checkbox, a switch) the way a person would, for at most `budget`.
    /// Deliberately knows nothing about any particular challenge. A cleared
    /// interstitial is given time to walk on to the real page.
    pub async fn solve_challenge(&self, budget: std::time::Duration) -> ChallengeOutcome {
        let t = std::time::Instant::now();
        let deadline = t + budget;
        /// A widget asks once or twice; more than this is a loop, not a user.
        const MAX_PRESSES: usize = 3;
        let mut pressed = 0usize;
        let mut seen_controls = std::collections::HashSet::new();
        let is_interstitial = |v: &serde_json::Value| matches!(v, serde_json::Value::String(s) if s.contains("Just a moment"));
        // A page with no gate has nothing to solve: waiting out the whole budget
        // there cost every unprotected site the full 30 s. Some grace first —
        // a widget can be inserted by script a moment after the load.
        const NO_GATE_GRACE: std::time::Duration = std::time::Duration::from_secs(4);
        let mut gate_last_seen = t;
        // In stop-at-clearance mode only a fresh lock counts: one already in the
        // jar may be the stale cookie that sent us to the gate.
        let lock_at_start = self.clearance_value();
        let mut gate_checked = t - std::time::Duration::from_secs(1);
        let mut last_press: Option<std::time::Instant> = None;
        let mut puzzle_checked = t;
        let status = loop {
            let worked = self.run_event_loop().await.unwrap_or(0);
            let cleared = self.cookies(&[]).iter().any(|c| c.name == "cf_clearance");
            // A standalone widget (not an interstitial) sets no cookie: its
            // success is the token in `cf-turnstile-response`.
            let token = self
                .evaluate("typeof __pt_widgetToken === 'function' && __pt_widgetToken() !== ''")
                .await
                .map(|v| v.as_bool().unwrap_or(false) || v.as_str() == Some("true"))
                .unwrap_or(false);
            if token && !cleared {
                tracing::info!(target: "nokk", elapsed_ms = t.elapsed().as_millis(), presses = pressed, "challenge complete: widget token issued");
                // The page's callback usually submits the form now (Google's /sorry/
                // does): give it the moment, so the result is where it leads.
                let until = std::time::Instant::now() + std::time::Duration::from_millis(1_500);
                while std::time::Instant::now() < until && !self.is_loading() {
                    let _ = self.run_event_loop().await;
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                break ChallengeStatus::TokenIssued;
            }
            if self.stop_at_clearance.load(std::sync::atomic::Ordering::Acquire)
                && (self.stopped_at_clearance.load(std::sync::atomic::Ordering::Acquire)
                    || (cleared && self.clearance_value() != lock_at_start))
            {
                tracing::info!(target: "nokk", elapsed_ms = t.elapsed().as_millis(), presses = pressed, "challenge cleared");
                break ChallengeStatus::Cleared;
            }
            if cleared {
                tracing::info!(target: "nokk", elapsed_ms = t.elapsed().as_millis(), presses = pressed, "challenge cleared");
                // The interstitial walks on to the original address by itself
                // once it holds the lock — give it the time, or the result is
                // the interstitial's page rather than the site's.
                let until = std::time::Instant::now() + std::time::Duration::from_secs(15);
                while std::time::Instant::now() < until
                    && is_interstitial(&self.evaluate("document.title").await.unwrap_or_default())
                {
                    let _ = self.run_event_loop().await;
                }
                if is_interstitial(&self.evaluate("document.title").await.unwrap_or_default()) {
                    tracing::warn!(target: "nokk", "cleared, but the interstitial did not move on");
                    break ChallengeStatus::ClearedButStuck;
                }
                tracing::info!(target: "nokk", elapsed_ms = t.elapsed().as_millis(), "interstitial moved on");
                break ChallengeStatus::Cleared;
            }
            if pressed == 0 && gate_checked.elapsed() >= std::time::Duration::from_millis(500) {
                gate_checked = std::time::Instant::now();
                if self.challenge_state().await.kind != ChallengeKind::None {
                    gate_last_seen = gate_checked;
                } else if gate_last_seen.elapsed() >= NO_GATE_GRACE {
                    tracing::info!(target: "nokk", elapsed_ms = t.elapsed().as_millis(), "no challenge on the page");
                    break ChallengeStatus::NoChallenge;
                }
            }
            if std::time::Instant::now() >= deadline {
                tracing::warn!(target: "nokk", presses = pressed, "challenge did not clear in time");
                break ChallengeStatus::Timeout;
            }
            // A pressed reCAPTCHA that answers with a puzzle is not going to clear by
            // itself. Give a checkbox-only pass its moment, then stop.
            if pressed > 0
                && last_press.is_some_and(|at| at.elapsed() >= std::time::Duration::from_secs(2))
                && puzzle_checked.elapsed() >= std::time::Duration::from_millis(500)
            {
                puzzle_checked = std::time::Instant::now();
                if self.recaptcha_wants_a_person().await {
                    tracing::info!(target: "nokk", elapsed_ms = t.elapsed().as_millis(), presses = pressed, "the widget asks for a person");
                    break ChallengeStatus::NeedsHuman;
                }
            }
            // Press only what is offered, once per control that appears: a
            // widget that ignores a press is not asking for another, and a
            // flurry of clicks is its own signature.
            if pressed < MAX_PRESSES && !self.stopped_at_clearance.load(std::sync::atomic::Ordering::Acquire) {
                if let Ok(Some(what)) = self.press_widget_control().await {
                    if seen_controls.insert(what.clone()) {
                        pressed += 1;
                        last_press = Some(std::time::Instant::now());
                        tracing::info!(target: "nokk", control = %what, "pressed the challenge widget");
                        // The second and a half after a press is work, not sleep:
                        // the widget counts in exactly that window, and an engine
                        // asleep then shows a gap no browser has.
                        let until = std::time::Instant::now() + std::time::Duration::from_millis(1_500);
                        while std::time::Instant::now() < until
                            && !self.stopped_at_clearance.load(std::sync::atomic::Ordering::Acquire)
                        {
                            let _ = self.run_event_loop().await;
                            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                        }
                    }
                }
            }
            // Two isolate visits per iteration (page clock and widget frame clock). Removing
            // them as debug code made the interactive interstitial stop passing: the visit
            // between the frame's slices seems to act as a pulse. Kept until the cause is known.
            let _ = self
                .evaluate("typeof __pt_nextTimerDelay === 'function' ? String(__pt_nextTimerDelay()) : 'nofn'")
                .await;
            if let Some(f) = self.frame_list().first() {
                let _ = self
                    .evaluate_in_frame(f.id, "typeof __pt_nextTimerDelay === 'function' ? String(__pt_nextTimerDelay()) : 'nofn'")
                    .await;
            }
            // A working page gets a millisecond between pumps; an idle one 25.
            if worked == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            } else {
                tokio::time::sleep(std::time::Duration::from_micros(500)).await;
            }
        };
        // A challenge that moved on is loading the page behind it: hand that
        // page over whole, not the moment its address changed.
        let settle = std::time::Instant::now();
        while self.is_loading() && settle.elapsed() < std::time::Duration::from_secs(15) {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        ChallengeOutcome { status, presses: pressed, elapsed_ms: t.elapsed().as_millis() as u64 }
    }

    /// Press at (`x`, `y`) in `frame` (or the page) the way a hand does: an arc in from
    /// a distance, a pause, a held press slightly off centre, a small drift after.
    async fn human_press(&self, frame: Option<u32>, x: f64, y: f64) {
        // Inside the frame that owns it, so no coordinate has to survive a
        // trip through a parent that lays its frames out differently.
        //
        // Three events in one tick is not a human press: the pointer appears dead centre
        // and presses and releases in zero time, and the challenge measures that. So:
        // approach along an arc, pause, hold, and land slightly off centre.
        let trace = std::env::var_os("NOKK_TRACE_CONTROLS").is_some();
        let press_t0 = std::time::Instant::now();
        let send = async |js: String| {
            let t = std::time::Instant::now();
            let _ = match frame {
                None => self.evaluate(&js).await,
                Some(id) => self.evaluate_in_frame(id, &js).await,
            };
            if trace {
                tracing::info!(target: "nokk::press", took_ms = t.elapsed().as_millis() as u64, at_ms = press_t0.elapsed().as_millis() as u64, what = %js.chars().take(40).collect::<String>(), "step");
            }
        };
        // Screen position of the document origin holding the checkbox: window plus browser
        // chrome plus the frame's position. Without it screenX/Y equalled clientX/Y, which
        // a real mouse never gives.
        let origin_js = match frame {
            None => "__pt_screenOrigin()".to_string(),
            Some(id) => format!(
                "(() => {{ const o = JSON.parse(__pt_screenOrigin()); let r = null; try {{ r = JSON.parse(__pt_frameRectById({id}) || 'null'); }} catch (e) {{}} return JSON.stringify([o[0] + (r ? r.x : 0), o[1] + (r ? r.y : 0)]); }})()"
            ),
        };
        let (ox, oy) = self
            .evaluate(&origin_js)
            .await
            .ok()
            .and_then(|v| v.as_str().and_then(|t| serde_json::from_str::<Vec<f64>>(t).ok()))
            .filter(|v| v.len() == 2)
            .map(|v| (v[0], v[1]))
            .unwrap_or((0.0, 0.0));
        // Spread derived from the coordinates: stable per target, different across
        // targets, no randomness.
        let spread = ((x + y * 7.0) as i64).unsigned_abs() % 5;
        let mut seed = ((x * 131.0 + y * 977.0) as i64).unsigned_abs() | 1;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % 10_000) as f64 / 10_000.0
        };
        let (tx, ty) = (x + 1.0 + spread as f64 * 0.37 + rnd() * 0.6, y - 1.0 + (spread % 3) as f64 * 0.41 + rnd() * 0.6);
        // Approach like a recorded hand in Chrome: about twenty points over half a second,
        // uneven steps (8-60 ms, occasionally longer), arcing in from afar and slowing near
        // the target.
        let steps = 18 + (spread as usize * 2) % 7;
        let (sx0, sy0) = (tx + 55.0 + rnd() * 20.0, ty + 18.0 + rnd() * 12.0);
        for i in 1..=steps {
            let t = i as f64 / steps as f64;
            let e = 1.0 - (1.0 - t).powi(3);
            let bow = (t * std::f64::consts::PI).sin();
            let px = sx0 + (tx - sx0) * e + bow * (4.0 + rnd() * 2.0);
            let py = sy0 + (ty - sy0) * e - bow * (6.0 + rnd() * 3.0);
            send(format!(
                "__pt_mouse(\"mouseMoved\", {px:.4}, {py:.4}, \"left\", 0, {ox:.4}, {oy:.4})"
            ))
            .await;
            let gap = if rnd() < 0.12 { 60.0 + rnd() * 120.0 } else { 8.0 + rnd() * 40.0 };
            self.settle(std::time::Duration::from_millis(gap as u64)).await;
        }
        self.settle(std::time::Duration::from_millis(90 + (rnd() * 140.0) as u64))
            .await;
        send(format!("__pt_mouse(\"mousePressed\", {tx:.4}, {ty:.4}, \"left\", 1, {ox:.4}, {oy:.4})")).await;
        self.settle(std::time::Duration::from_millis(85 + (rnd() * 50.0) as u64))
            .await;
        send(format!("__pt_mouse(\"mouseReleased\", {tx:.4}, {ty:.4}, \"left\", 1, {ox:.4}, {oy:.4})")).await;
        // The hand does not freeze after the press: a few points off to the side.
        for k in 1..=3 {
            self.settle(std::time::Duration::from_millis(30 + (rnd() * 60.0) as u64)).await;
            let (px, py) = (tx + k as f64 * (2.0 + rnd() * 3.0), ty + k as f64 * (4.0 + rnd() * 5.0));
            send(format!("__pt_mouse(\"mouseMoved\", {px:.4}, {py:.4}, \"left\", 0, {ox:.4}, {oy:.4})")).await;
        }
    }

    /// Press the first element matching `selector` in the frame whose URL contains
    /// `frame_url` (the page itself when `None`), with [`Self::human_press`]. A
    /// widget's own buttons (reCAPTCHA's audio, verify, reload) are read for the
    /// pointer trail that led to them; a script `click()` has none. False when
    /// there is no such frame or element.
    pub async fn press_selector(&self, frame_url: Option<&str>, selector: &str) -> Result<bool, EngineError> {
        let frame = match frame_url {
            Some(part) => match self.frame_list().into_iter().find(|f| f.url.contains(part)) {
                Some(f) => Some(f.id),
                None => return Ok(false),
            },
            None => None,
        };
        let js = format!(
            "(() => {{ const e = document.querySelector({}); if (!e) return ''; const r = e.getBoundingClientRect(); return JSON.stringify([r.x + r.width / 2, r.y + r.height / 2]); }})()",
            js_str(selector)
        );
        let at = match frame {
            Some(id) => self.evaluate_in_frame(id, &js).await?,
            None => self.evaluate(&js).await?,
        };
        let Some((x, y)) = at
            .as_str()
            .and_then(|t| serde_json::from_str::<Vec<f64>>(t).ok())
            .filter(|v| v.len() == 2)
            .map(|v| (v[0], v[1]))
        else {
            return Ok(false);
        };
        let target = format!("typeof __pt_setPressTarget === 'function' && __pt_setPressTarget({})", js_str(selector));
        let clear = "typeof __pt_setPressTarget === 'function' && __pt_setPressTarget(null)";
        match frame {
            Some(id) => { let _ = self.evaluate_in_frame(id, &target).await; }
            None => { let _ = self.evaluate(&target).await; }
        }
        self.human_press(frame, x, y).await;
        match frame {
            Some(id) => { let _ = self.evaluate_in_frame(id, clear).await; }
            None => { let _ = self.evaluate(clear).await; }
        }
        Ok(true)
    }

    /// Type `text` into the element matching `selector` in a frame (or the page):
    /// focus it, then a key down/up per character at a typing pace, so the page
    /// sees keystrokes rather than a value appearing.
    pub async fn type_selector(&self, frame_url: Option<&str>, selector: &str, text: &str) -> Result<bool, EngineError> {
        let frame = match frame_url {
            Some(part) => match self.frame_list().into_iter().find(|f| f.url.contains(part)) {
                Some(f) => Some(f.id),
                None => return Ok(false),
            },
            None => None,
        };
        let run = |js: String| async move {
            match frame {
                Some(id) => self.evaluate_in_frame(id, &js).await,
                None => self.evaluate(&js).await,
            }
        };
        let focused = run(format!("(e => e ? (e.focus(), 'ok') : '')(document.querySelector({}))", js_str(selector))).await?;
        if focused.as_str() != Some("ok") {
            return Ok(false);
        }
        let mut seed = (text.len() as u64).wrapping_mul(2654435761) | 1;
        for ch in text.chars() {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            let key = ch.to_string();
            let init = serde_json::json!({ "key": key, "text": key, "code": "" }).to_string();
            run(format!("__pt_key('keyDown', {init})")).await?;
            self.settle(std::time::Duration::from_millis(40 + seed % 60)).await;
            run(format!("__pt_key('keyUp', {init})")).await?;
            self.settle(std::time::Duration::from_millis(60 + (seed >> 8) % 140)).await;
        }
        Ok(true)
    }

    /// Whether a reCAPTCHA challenge frame shows a task for a person: the image
    /// grid, the audio task, or the "try again later" refusal.
    async fn recaptcha_wants_a_person(&self) -> bool {
        const JS: &str = "!!document.querySelector('.rc-imageselect-challenge .rc-imageselect-tile, .rc-imageselect-target, .rc-audiochallenge-response-field, .rc-doscaptcha-header')";
        for f in self.frame_list() {
            if !f.url.contains("/recaptcha/") || !f.url.contains("/bframe") {
                continue;
            }
            if let Ok(v) = self.evaluate_in_frame(f.id, JS).await {
                if v.as_bool() == Some(true) || v.as_str() == Some("true") {
                    return true;
                }
            }
        }
        false
    }

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
            if std::env::var_os("NOKK_TRACE_CONTROLS").is_some() {
                let dbg = match frame {
                    None => self.evaluate("typeof __pt_ctlDebug === 'function' ? __pt_ctlDebug() : ''").await,
                    Some(id) => self.evaluate_in_frame(id, "typeof __pt_ctlDebug === 'function' ? __pt_ctlDebug() : ''").await,
                };
                tracing::info!(target: "nokk::press", ?frame, found = ?found.as_ref().ok(), dbg = ?dbg.ok(), "controls");
            }
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
            self.human_press(frame, x, y).await;
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
                    // A worker gets its own thread, as in a browser: page and worker compute in
                    // parallel and a reply costs message latency, not "the page is free". On a shared
                    // isolate every worker turn was taken from the page.
                    let place = self.engine.pool.pick_worker_avoiding(&[self.worker, self.frame_worker()]);
                    let load = std::sync::Arc::new(self.engine.pool.register_context(place));
                    let t_create = std::time::Instant::now();
                    let Ok(Ok(child)) = self
                        .engine
                        .pool
                        .dispatch(place, {
                            let boot = boot.clone();
                            move |iso| iso.create_context_or_spare(&boot)
                        })
                        .await
                    else {
                        continue;
                    };

                    tracing::debug!(worker = id, place = place.0, context_ms = t_create.elapsed().as_millis() as u64, "worker context ready");
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
                        .eval_at(place, child, &nokk_stealth::worker_scope_script(name, &url))
                        .await;
                    // The worker scope inherits its creator's storage access
                    // (`sec-fetch-storage-access: active`), and a blob worker sends no referrer, as in Chrome.
                    let storage_access = self
                        .eval_in(index, "!!globalThis.__ptStorageAccess")
                        .await
                        .ok()
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let _ = self
                        .eval_at(
                            place,
                            child,
                            &format!("globalThis.__ptStorageAccess = {storage_access}; globalThis.__ptNoReferrer = {local}; \
                                      (() => {{ const N = globalThis.__pt_rawGOPN || Object.getOwnPropertyNames, D = globalThis.__pt_rawGOPD || Object.getOwnPropertyDescriptor; \
                                      for (const k of N(globalThis)) {{ if (k.charCodeAt(0) !== 95 || k.charCodeAt(1) !== 95) continue; \
                                      try {{ const d = D(globalThis, k); if (d && d.enumerable && d.configurable) {{ d.enumerable = false; Object.defineProperty(globalThis, k, d); }} }} catch (e) {{}} }} }})();"),
                        )
                        .await;
                    // Observer hooks right after the scope: the worker has its own realm, so nothing
                    // installed on the page applies here.
                    let winit = self
                        .worker_init_scripts
                        .lock()
                        .map(|v| v.clone())
                        .unwrap_or_default();
                    for src in winit {
                        if let Err(e) = self.eval_at(place, child, &src).await {
                            tracing::debug!(error = %e, "worker init script threw");
                        }
                    }
                    if let Ok(mut w) = self.workers.lock() {
                        w.insert(
                            key,
                            WorkerState {
                                worker: place,
                                index: child,
                                url: url.clone(),
                                // A worker resolves its relative requests against
                                // its own script — unless it came from a blob,
                                // which has no path of its own to resolve against.
                                fetch_base: if local { base.to_string() } else { url.clone() },
                                _load: load,
                            },
                        );
                    }
                    tracing::debug!(url = %url, bytes = source.len(), thread = place.0,
                                    head = %&source[..source.len().min(400)], "worker started");
                    let code = format!("{source}\n//# sourceURL={url}");
                    if let Err(e) = self.eval_at(place, child, &code).await {
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
                        .and_then(|w| w.get(&key).map(|s| (s.worker, s.index)));
                    match child {
                        Some((place, child)) => {
                            let data = op["data"].as_str().unwrap_or("null");
                            tracing::debug!(owner = index, worker = id, bytes = data.len(),
                                            head = %&data[..data.len().min(420)], "worker post");
                            // Dump the whole task to a file on request: the challenge sends the worker a
                            // multi-KB WebAssembly module that does not fit a log line and must be compared
                            // with the browser verbatim.
                            if let Ok(dir) = std::env::var("NOKK_DUMP_WORKER_TASKS") {
                                let n = WORKER_TASK_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let _ = std::fs::create_dir_all(&dir);
                                let _ = std::fs::write(
                                    std::path::Path::new(&dir).join(format!("task-{n:03}.js")),
                                    data.as_bytes(),
                                );
                            }
                            let _ = self
                                .eval_at(place, child, &format!("__pt_workerDeliver({})", js_str(data)))
                                .await;
                            // Give the worker a turn right away. The task usually sets a short timer and the
                            // challenge measures it ("reply in 55 ms"); waiting for the general round added
                            // our ~30 ms to it.
                            self.serve_worker_soon(index, id, place, child).await;
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

    /// Let the worker finish what is about to happen: a fresh message almost always
    /// sets a short timer, and the time until it fires is measured.
    async fn serve_worker_soon(
        &self,
        owner: usize,
        id: u32,
        place: nokk_pool::WorkerId,
        child: usize,
    ) {
        // Wait only for the near timer; long ones belong to the general round, or one
        // worker would delay everyone. The wait runs on the worker's thread: returning
        // here for every 5 ms step costs more than the step.
        const NEAR: std::time::Duration = std::time::Duration::from_millis(80);
        const TURN: std::time::Duration = std::time::Duration::from_millis(150);
        let _ = self
            .engine
            .pool
            .dispatch(place, move |iso| {
                iso.run_worker_loop(child, 400, TURN, NEAR)
            })
            .await;
        // Network requests the task queued (fetch from the worker) go out now: waiting for
        // the general round queued them for up to 1.5 s, which the challenge measured as
        // server response time.
        if let Ok(Value::String(qjson)) = self.eval_at(place, child, DRAIN_IO).await {
            let queues: Value = serde_json::from_str(&qjson).unwrap_or_default();
            self.log_console("worker", &queues);
            let fetch_base = self
                .workers
                .lock()
                .ok()
                .and_then(|w| w.get(&(owner, id)).map(|st| st.fetch_base.clone()))
                .unwrap_or_default();
            if let Some(reqs) = queues["fetch"].as_array() {
                for r in reqs.iter().take(32) {
                    if let Some(settle) = self.start_fetch(Deliver::Worker(place, child), owner, &fetch_base, r) {
                        let _ = self.eval_at(place, child, &settle).await;
                    }
                }
            }
        }
        // Deliver the reply home now, not on the next round: the challenge counts those
        // milliseconds into our response time.
        self.flush_worker_out(owner, id, place, child).await;
    }

    /// Deliver home everything the worker already posted. Separate from the general
    /// round because the time from post to page receipt is measured too.
    async fn flush_worker_out(
        &self,
        owner: usize,
        id: u32,
        place: nokk_pool::WorkerId,
        child: usize,
    ) {
        let Ok(out) = self
            .eval_at(place, child, "__ptJSON.stringify(__pt_drainWorkerOut())")
            .await
        else {
            return;
        };
        let messages: Vec<String> = out
            .as_str()
            .and_then(|t| serde_json::from_str::<Value>(t).ok())
            .and_then(|v| {
                v.as_array().map(|a| {
                    a.iter()
                        .filter_map(|m| m.as_str().map(str::to_string))
                        .collect()
                })
            })
            .unwrap_or_default();
        for m in messages {
            // Same log line as the general round, so a fast-path reply leaves a trace.
            tracing::debug!(worker = id, bytes = m.len(),
                            head = %&m[..m.len().min(420)], "worker reply delivered");
            let _ = self
                .eval_in(owner, &format!("__pt_workerMessage({id}, {})", js_str(&m)))
                .await;
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
            let (place, child) = (state.worker, state.index);
            // More slices while the worker has work (up to four in a row). One 50 ms slice per
            // parent iteration stretched a second of worker work over several wall seconds,
            // and the challenge declared itself expired.
            let turn_started = std::time::Instant::now();
            // Keep the turn while the worker has work now or soon. The budget bounds greed so
            // the page and other contexts do not wait forever. The worker waits on its own
            // thread: its collector is a chain of 55 ms timers, and a round trip per step costs
            // more than the step.
            const WORKER_TURN: std::time::Duration = std::time::Duration::from_millis(500);
            const NEAR: std::time::Duration = std::time::Duration::from_millis(80);
            let ran = self
                .engine
                .pool
                .dispatch(place, move |iso| {
                    iso.run_worker_loop(child, 2_000, WORKER_TURN, NEAR)
                })
                .await?
                .unwrap_or(0);
            let slices_ms = turn_started.elapsed().as_millis();
            work += ran as usize;
            // What an idle worker waits on: its own timer (and how soon), or nothing (a promise).
            let pending = self
                .eval_at(place, child, "typeof __pt_nextTimerDelay === 'function' ? __pt_nextTimerDelay() : -1")
                .await
                .ok()
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            tracing::debug!(worker = id, ran, slices_ms, pending, "worker turn");

            // The worker may have been stopped (its frame removed) between listing and turn:
            // that ends the worker, not the page navigation.
            let qjson = match self.eval_at(place, child, DRAIN_IO).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(worker = id, error = %e, "worker gone during turn");
                    continue;
                }
            };
            let queues: Value = match qjson {
                Value::String(s) => serde_json::from_str(&s).unwrap_or_default(),
                _ => Value::Null,
            };
            self.log_console("worker", &queues);
            if let Some(reqs) = queues["fetch"].as_array() {
                for r in reqs.iter().take(32) {
                    work += 1;
                    if let Some(settle) = self.start_fetch(Deliver::Worker(place, child), owner, &state.fetch_base, r) {
                        let _ = self.eval_at(place, child, &settle).await;
                    }
                }
            }
            work += self.settle_inflight().await?;

            // What it posted home, and whether it hung up: `close()` inside a
            // worker ends it, and a context nobody will ever pump again should
            // not stay on the isolate.
            // The fetches above were awaited, and the page may have ended the
            // worker meanwhile — the same end of a worker as above, not a
            // failed navigation.
            let out = match self
                .eval_at(
                    place,
                    child,
                    "__ptJSON.stringify({out: __pt_drainWorkerOut(), closed: !!globalThis.__ptClosed})",
                )
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(worker = id, error = %e, "worker gone after its fetches");
                    continue;
                }
            };
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
                tracing::debug!(worker = id, bytes = m.len(),
                                head = %&m[..m.len().min(420)], "worker reply delivered");
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
            if let Ok(v) = self.eval_at(state.worker, state.index, js).await {
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
        // No cap here: the queue itself is bounded (the page's `console` stops
        // recording past 256 lines between drains), and a second, smaller cap
        // only threw away the tail of a burst — the half of a probe's output
        // that mattered, silently.
        for line in lines.iter() {
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
                .eval_at(
                    state.worker,
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
            .dispatch(state.worker, move |iso| iso.dispose_context(child))
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
                    // Build spare realms on the frame thread while the frame document loads: the
                    // challenge program needs them immediately.
                    if origin_of(&url) != origin_of(base)
                        && std::env::var_os("NOKK_FRAMES_SHARED").is_none()
                        && std::env::var_os("NOKK_NO_SPARE_REALMS").is_none()
                    {
                        let boot = self.bootstrap.clone();
                        self.engine
                            .pool
                            .dispatch_detached(self.frame_worker(), {
                                let boot = boot.clone();
                                move |iso| iso.prewarm_realms(&boot, 3)
                            });
                        // And one ready worker context on each pool thread: the challenge program starts
                        // workers one after another and expects replies within hundreds of milliseconds.
                        for w in self.engine.pool.live_worker_ids() {
                            if w == self.worker || w == self.frame_worker() {
                                continue;
                            }
                            let boot = boot.clone();
                            self.engine
                                .pool
                                .dispatch_detached(w, move |iso| iso.prewarm_contexts(&boot, 1));
                        }
                    }
                    let nav_started = std::time::Instant::now();
                    // The frame has no context yet: say whose document this is.
                    if let Ok(mut docs) = self.frame_docs.lock() {
                        docs.insert(url.clone(), id);
                    }
                    // A form aimed at the frame posts its body; otherwise the frame GETs its `src`.
                    let fetched = if op["method"].as_str() == Some("POST") {
                        let from = (!base.is_empty() && base != "about:blank").then_some(base);
                        self.fetch_document_post(
                            &url,
                            from,
                            op["contentType"].as_str().unwrap_or("application/x-www-form-urlencoded"),
                            op["body"].as_str().unwrap_or(""),
                        )
                        .await
                    } else {
                        self.fetch_text(&url, "document").await
                    };
                    let Ok((_, html)) = fetched else {
                        let _ = self.evaluate(&format!("__pt_frameFailed({id})")).await;
                        continue;
                    };
                    let boot = self.bootstrap.clone();
                    // A cross-origin frame gets its own thread: in a browser it runs in its own process
                    // while the page is busy. On a shared thread the Turnstile widget waited for the
                    // page's hundred chunks, and its own clock showed intervals 3-5x Chrome's, which go
                    // into the first POST. A same-origin frame stays with the page.
                    let cross = origin_of(&url) != origin_of(base);
                    let place = if cross && std::env::var_os("NOKK_FRAMES_SHARED").is_none() {
                        self.frame_worker()
                    } else {
                        self.worker
                    };
                    let Ok(Ok(raw_index)) = self
                        .engine
                        .pool
                        .dispatch(place, move |iso| iso.create_context(&boot))
                        .await
                    else {
                        continue;
                    };
                    let (index, load) = if place == self.worker {
                        (raw_index, None)
                    } else {
                        (
                            own_thread_index(place, raw_index),
                            Some(std::sync::Arc::new(self.engine.pool.register_context(place))),
                        )
                    };
                    // The frame's clock starts at its navigation, not at context construction: the
                    // document has already arrived by now.
                    let ago = nav_started.elapsed().as_secs_f64() * 1000.0;
                    let _ = self
                        .eval_in(index, &format!("globalThis.__pt_shiftOrigin && __pt_shiftOrigin({ago:.3});"))
                        .await;
                    // Teach the child who it is before anything runs in it: its own
                    // frame id (so its `postMessage` can be routed back) and that it
                    // is not the top-level window.
                    let _ = self
                        .eval_in(index, &format!("__pt_markAsFrame({id}, {});", js_str(op["name"].as_str().unwrap_or(""))))
                        .await;
                    // Third-party status and referrer: in a third-party frame Chrome answers "denied"
                    // to permissions, and `document.referrer` under strict-origin-when-cross-origin is
                    // just the parent's origin.
                    let referrer = if cross {
                        format!("{}/", origin_of(base))
                    } else {
                        base.split('#').next().unwrap_or(base).to_string()
                    };
                    let _ = self
                        .eval_in(
                            index,
                            &format!(
                                "Object.defineProperty(globalThis, '__pt_crossSite', {{ value: {cross}, configurable: true }});\n\
                                 if ({cross}) globalThis.__ptStorageAccess = true;\n\
                                 Object.defineProperty(globalThis, '__pt_referrer', {{ value: {0}, configurable: true }});\n\
                                 try {{ document.referrer = {0}; }} catch (e) {{}}",
                                js_str(&referrer)
                            ),
                        )
                        .await;
                    // The frame's window is the size of its `<iframe>`, not the page: the Turnstile
                    // widget lives in 300x65 and reads it.
                    let (mut fw, mut fh) = (
                        op["w"].as_f64().unwrap_or(300.0),
                        op["h"].as_f64().unwrap_or(150.0),
                    );
                    // The element may get its size after insertion (styles parse later): ask the parent again now.
                    let raw = self.eval_in(self.idx(), &format!("__pt_frameBox({id})")).await;
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
                                _load: load,
                            },
                        );
                    }
                    // Before its document runs: it may look its siblings up at once.
                    self.tell_frames_their_siblings().await;
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
                        let (w, raw) = self.route(idx);
                        let _ = self
                            .engine
                            .pool
                            .dispatch(w, move |iso| iso.dispose_context(raw))
                            .await;
                        self.tell_frames_their_siblings().await;
                    }
                }
                // `parent.postMessage` from inside a frame, or
                // `frame.contentWindow.postMessage` from the page: same plumbing,
                // opposite directions.
                "post" => {
                    let data = op["data"].as_str().unwrap_or("null").to_string();
                    // The whole frame exchange is visible without JS patches, which would break
                    // `event.source === iframe.contentWindow`. The watchcat heartbeat every 900 ms
                    // would drown the rest, so it gets a separate line: what matters is that it flows,
                    // and in both directions.
                    let beat = data.contains("\"meow\"") || data.contains("\"food\"");
                    if beat {
                        tracing::debug!(to_parent = op["toParent"].as_bool().unwrap_or(false),
                                        payload = %&data[..data.len().min(120)], "watchcat");
                    } else {
                        tracing::debug!(to_parent = op["toParent"].as_bool().unwrap_or(false),
                                        payload = %&data[..data.len().min(9000)], "frame message");
                    }
                    let to_parent = op["toParent"].as_bool().unwrap_or(false);
                    let target = self.frames.lock().ok().and_then(|f| f.get(&id).cloned());
                    let Some(frame) = target else { continue };
                    // From one frame to a sibling (`parent.frames[name].postMessage`).
                    let sibling = op["toFrame"].as_u64().and_then(|to| {
                        self.frames.lock().ok().and_then(|f| f.get(&(to as u32)).map(|t| t.index))
                    });
                    if op["toFrame"].is_u64() && sibling.is_none() {
                        continue;
                    }
                    let (index, origin) = if let Some(to) = sibling {
                        (to, frame.origin.clone())
                    } else if to_parent {
                        (self.idx(), frame.origin.clone())
                    } else {
                        (frame.index, origin_of(base))
                    };
                    let ports: Vec<String> = op["ports"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                        .unwrap_or_default();
                    if !ports.is_empty() {
                        let sender = if to_parent || sibling.is_some() { frame.index } else { self.idx() };
                        if let Ok(mut ends) = self.port_ends.lock() {
                            for p in &ports {
                                // A port passed on again keeps its stayed end where it was.
                                ends.entry(format!("{p}:a")).or_insert(sender);
                                ends.insert(format!("{p}:b"), index);
                            }
                        }
                    }
                    let _ = self
                        .eval_in(
                            index,
                            &format!(
                                "__pt_deliverMessage({}, {}, {}, {});",
                                data,
                                js_str(&origin),
                                if to_parent || sibling.is_some() {
                                    id.to_string()
                                } else {
                                    "0".into()
                                },
                                serde_json::to_string(&ports).unwrap_or_else(|_| "[]".into())
                            ),
                        )
                        .await;
                }
                // A message on a port whose other end is in another frame.
                "portpost" => {
                    let end = op["end"].as_str().unwrap_or("").to_string();
                    let data = op["data"].as_str().unwrap_or("null").to_string();
                    let target = self.port_ends.lock().ok().and_then(|e| e.get(&end).copied());
                    if let Some(index) = target {
                        tracing::debug!(%end, payload = %&data[..data.len().min(200)], "port message");
                        let _ = self
                            .eval_in(index, &format!("__pt_portIn({}, {});", js_str(&end), data))
                            .await;
                    }
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

        // In waves: parse everything that arrived, collect new URLs, fetch them together.
        // A browser fetches the graph in parallel; one file at a time made Turnstile's
        // api.js on chess.com (a hundred modules) start loading at 4-8 s instead of under
        // 0.5 s, and that number goes to the widget (`apiJsResourceTiming.startTime`).
        while !pending.is_empty() {
            let wave = std::mem::take(&mut pending);
            let mut to_fetch: Vec<String> = Vec::new();
            for (at, code) in wave {
                let (mw, i) = self.route(index);
                let (u, c) = (at.clone(), code);
                let requests = self
                    .engine
                    .pool
                    .dispatch(mw, move |iso| iso.module_requests(i, &u, &c))
                    .await?
                    .map_err(EngineError::Js)?;

                for spec in requests {
                    // A bare specifier ("react") needs an import map to mean anything;
                    // a bundled page never has one, and guessing would be worse.
                    let Some(target) = resolve_url(&at, &spec) else {
                        continue;
                    };
                    let (from, sp, to) = (at.clone(), spec.clone(), target.clone());
                    self.engine
                        .pool
                        .dispatch(mw, move |iso| iso.link_module(i, &from, &sp, &to))
                        .await?;
                    if seen.contains(&target) || seen.len() >= MAX_MODULES {
                        continue;
                    }
                    seen.insert(target.clone());
                    // Do not refetch an already built module: a browser has one module map per realm
                    // with one entry per URL, however many chunks import it.
                    let u = target.clone();
                    if self
                        .engine
                        .pool
                        .dispatch(mw, move |iso| iso.has_module(i, &u))
                        .await
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    to_fetch.push(target);
                }
            }
            let got = self
                .with_frames_live(futures_util::future::join_all(
                    to_fetch.iter().map(|t| self.fetch_text_in(index, t, "script", None)),
                ))
                .await;
            for (target, res) in to_fetch.into_iter().zip(got) {
                match res {
                    Ok((_, code)) => pending.push((target, code)),
                    Err(e) => tracing::debug!(url = %target, error = %e, "import failed to load"),
                }
            }
        }

        let (mw, i) = self.route(index);
        let u = url.to_string();
        let run = self
            .engine
            .pool
            .dispatch(mw, move |iso| iso.eval_module(i, &u));
        let run = async move { run.await };
        let out = if index == self.idx() { self.with_frames_live(run).await } else { run.await };
        out?.map_err(EngineError::Js)
    }

    /// Serve the `import()` calls the isolate is waiting on.
    ///
    /// V8 has no loader of its own: it asks the embedder and waits on a promise.
    /// We never answered, so every dynamic import was rejected — and with it any
    /// page built in chunks, which is nearly all of them. Vite's `__vitePreload`
    /// catches the rejection, fires `vite:preloadError`, and a page listening for
    /// it reloads itself forever.
    async fn serve_dynamic_imports(&self) -> usize {
        let mut asked = match self
            .engine
            .pool
            .dispatch(self.worker, move |iso| iso.drain_dynamic_imports())
            .await
        {
            Ok(v) => v,
            Err(_) => return 0,
        };
        // Frames on their own threads come from their own isolates, and only ours.
        let away: Vec<usize> = self
            .frames
            .lock()
            .map(|f| f.values().map(|s| s.index).filter(|i| i & OWN_THREAD != 0).collect())
            .unwrap_or_default();
        for index in away {
            let (w, raw) = self.route(index);
            if let Ok(more) = self
                .engine
                .pool
                .dispatch(w, move |iso| iso.drain_dynamic_imports_for(&[raw]))
                .await
            {
                asked.extend(more.into_iter().map(|(id, _, r, sp)| (id, index, r, sp)));
            }
        }
        let mut served = 0;
        for (id, index, referrer, specifier) in asked {
            // The referrer is the address the module was compiled under, so a
            // relative specifier resolves against it exactly as in a browser.
            let outcome = match resolve_url(&referrer, &specifier) {
                None => Err(format!(
                    "Failed to resolve module specifier '{specifier}'"
                )),
                Some(target) => match self.with_frames_live(self.fetch_text_in(index, &target, "script", None)).await {
                    Err(e) => Err(format!("Failed to fetch dynamically imported module: {e}")),
                    Ok((final_url, code)) => match self.run_module(index, &final_url, code).await {
                        Err(e) => Err(e.to_string()),
                        Ok(()) => Ok(final_url),
                    },
                },
            };
            let settle = outcome.as_ref().map(|u| u.as_str()).map_err(Clone::clone);
            let owned: Result<String, String> = settle.map(str::to_string);
            let (w, raw) = self.route(index);
            let _ = self
                .engine
                .pool
                .dispatch(w, move |iso| {
                    iso.settle_dynamic_import(
                        id,
                        raw,
                        owned.as_ref().map(String::as_str).map_err(Clone::clone),
                    )
                })
                .await;
            served += 1;
        }
        served
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
            // <script type="module"> without src: the source came with the op, but it must
            // still run as a module, with its own `import`.
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
            match self.fetch_text_in(index, &url, "script", None).await {
                Ok((_, code)) => {
                    // A script reads its own <script> timing on its first line: the entry must exist
                    // before it starts, not at the end of the round.
                    if index == self.idx() {
                        self.flush_resource_timings(index).await;
                    }
                    if op["module"].as_bool().unwrap_or(false) {
                        if let Err(e) = self.run_module(index, &url, code).await {
                            tracing::debug!(url = %url, error = %e, "module threw");
                        }
                        let _ = self.eval_in(index, &done(true)).await;
                        continue;
                    }
                    // Classic script: `currentScript` is itself while it runs; its name is its URL in
                    // `ScriptOrigin`, not a comment.
                    let _ = self
                        .eval_in(index, &format!("__pt_scriptStart({id});"))
                        .await;
                    if let Err(e) = self.eval_named_in(index, &code, &url).await {
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

    /// Wait for markup stylesheets before running the next script, as a browser does.
    /// The wait is not idle: the page lives, its timers run, and the stylesheet
    /// requests are served by the same loop.
    async fn wait_for_blocking_sheets(&self, index: usize, cap: std::time::Duration) {
        // One deadline per document, not per script: a sheet that missed 15 s will not
        // arrive for the next script, and a SvelteKit page carries dozens (stake.com sat
        // like this for half an hour at 100% CPU).
        let doc = self.doc_seq.load(std::sync::atomic::Ordering::Acquire);
        if self.sheets_gave_up.load(std::sync::atomic::Ordering::Acquire) == doc + 1 {
            return;
        }
        let deadline = std::time::Instant::now() + cap;
        loop {
            let pending = self
                .eval_in(index, "globalThis.__ptBlockingSheets | 0")
                .await
                .ok()
                .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .unwrap_or(0);
            if pending == 0 {
                return;
            }
            if std::time::Instant::now() >= deadline {
                // A short wait running out says nothing about the sheets yet.
                if cap < SHEETS_WAIT {
                    return;
                }
                let urls = self
                    .eval_in(index, "JSON.stringify([...(globalThis.__ptBlockingSheetUrls || [])])")
                    .await
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                tracing::warn!(pending, %urls, "stylesheets never arrived; running the page's scripts without them");
                self.sheets_gave_up.store(doc + 1, std::sync::atomic::Ordering::Release);
                return;
            }
            // The loop may load a document itself, which then waits for sheets again.
            let worked = match Box::pin(self.run_event_loop_waiting(std::time::Duration::ZERO, true)).await {
                Ok(n) => n,
                Err(_) => return,
            };
            // Wait for the network rather than spin: without the pause this loop ate a whole core.
            if worked == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
    }

    /// Await `fut` without stopping frames. A cross-origin frame in a browser runs in its
    /// own process while the page loads its chunks; here it stalled meanwhile. The
    /// Turnstile widget times its stages with `Date.now`, and two of them came out 3-5x
    /// Chrome's, exactly the time the page spent loading. These go into the first POST.
    async fn with_frames_live<F: std::future::Future>(&self, fut: F) -> F::Output {
        use std::sync::atomic::Ordering;
        if !self.has_frames()
            || std::env::var_os("NOKK_FRAMES_WAIT").is_some()
            || self.frames_live.swap(true, Ordering::AcqRel)
        {
            return fut.await;
        }
        let mut fut = std::pin::pin!(fut);
        let out = loop {
            tokio::select! {
                biased;
                out = &mut fut => break out,
                _ = tokio::time::sleep(FRAME_PUMP_EVERY) => {
                    let _ = Box::pin(self.pump_frames()).await;
                }
            }
        };
        self.frames_live.store(false, Ordering::Release);
        out
    }

    /// Give frames a turn if enough time has passed. Called from the main document's
    /// long sequences: while the page fetches and runs its scripts one by one, the
    /// framed widget would otherwise stall for seconds (in a browser it has its own process).
    async fn frames_take_a_turn(&self) {
        if !self.has_frames() {
            return;
        }
        {
            let Ok(mut last) = self.last_frame_turn.lock() else {
                return;
            };
            if last.elapsed() < FRAME_PUMP_EVERY {
                return;
            }
            *last = std::time::Instant::now();
        }
        // Real recursion: a frame pump may load a document, which pumps frames again; hence boxed.
        let _ = Box::pin(self.pump_frames()).await;
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
            // A frame gets its own timing timeline before it starts: the first thing the
            // Turnstile widget program does is read `performance`, and an empty timeline means
            // "loaded nothing", impossible for a live document. Timeline and frame size are
            // refreshed only every 8th pump: each is a separate isolate visit, and together
            // they cost more than the frame's own work.
            let full = self.frame_pump_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 8 == 0;
            if full {
                self.flush_resource_timings(index).await;
            }
            let t_slice = std::time::Instant::now();
            // The frame may have vanished between listing and pumping (the page removed the
            // iframe): the frame's end, not a navigation error.
            let ran = match self
                .engine
                .pool
                .dispatch(self.route(index).0, {
                    let raw = self.route(index).1;
                    move |iso| iso.run_event_loop(raw, 200, std::time::Duration::from_millis(50))
                })
                .await
            {
                Ok(v) => v.unwrap_or(0),
                Err(e) => {
                    tracing::debug!(frame = id, error = %e, "frame gone during pump");
                    if let Ok(mut f) = self.frames.lock() { f.remove(&id); }
                    continue;
                }
            };
            work += ran as usize;
            tracing::debug!(target: "nokk::pace", frame = id, ran, slice_ms = t_slice.elapsed().as_millis() as u64, "frame slice");
            let qjson = match self.eval_in(index, DRAIN_IO).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(frame = id, error = %e, "frame gone during drain");
                    if let Ok(mut f) = self.frames.lock() { f.remove(&id); }
                    continue;
                }
            };
            let queues: Value = match qjson {
                Value::String(s) => serde_json::from_str(&s).unwrap_or_default(),
                _ => Value::Null,
            };
            // Idle frame: top up spare realms on its thread, but only if the next timer is far:
            // building a realm holds the thread ~300 ms, and the frame timer behind it was
            // late by as much (report sections stretched 3x).
            let next_timer = queues["timers"].as_f64().unwrap_or(-1.0);
            if ran == 0 && index & OWN_THREAD != 0 && (next_timer < 0.0 || next_timer > 400.0)
                && std::env::var_os("NOKK_NO_SPARE_REALMS").is_none()
            {
                let (w, _) = self.route(index);
                self.engine.pool.dispatch_detached(w, |iso| iso.top_up_realms(8, 1));
            }
            let base = self.frame_base(id);
            self.log_console(&format!("frame {id}"), &queues);
            if let Some(ops) = queues["cookies"].as_array() {
                if self.apply_cookie_ops(&base, ops) {
                    self.sync_cookie_mirror(index, &base).await;
                }
            }

            // A frame learns its size more than once: styles arrive after insertion and the
            // element can change. A browser then resizes the frame window; do the same until it settles.
            let boxed = if full {
                self.eval_in(self.idx(), &format!("__pt_frameBox({id})")).await
            } else {
                Ok(Value::Null)
            };
            if let Ok(Value::String(text)) = boxed
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
                    // To the network immediately: the frame's JS moves on and `settle_inflight`
                    // delivers the reply. While a request waited its turn, the challenge beacon held
                    // everything for seconds.
                    if let Some(settle) = self.start_fetch(Deliver::Frame(index), index, &base, r) {
                        let _ = self.eval_in(index, &settle).await;
                    }
                }
            }
            work += self.settle_inflight().await?;

            // A frame loads code into itself the same way a page does.
            if let Some(ops) = queues["scripts"].as_array() {
                if !ops.is_empty() {
                    work += ops.len();
                    self.apply_script_ops(index, &base, ops).await;
                }
            }

            // And `import()` the engine is waiting on: it asks through its own hook, not the
            // page queue, and the promise hangs until answered.
            work += self.serve_dynamic_imports().await;

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

    /// Give every frame the page's current frame list, so `parent.frames[name]` and
    /// `parent.frames[i]` inside one reach the others (reCAPTCHA's checkbox frame
    /// talks to its challenge frame this way).
    async fn tell_frames_their_siblings(&self) {
        let list = self
            .evaluate("typeof __pt_frameList === 'function' ? __pt_frameList() : '[]'")
            .await
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "[]".into());
        let targets: Vec<usize> = self
            .frames
            .lock()
            .map(|f| f.values().map(|s| s.index).collect())
            .unwrap_or_default();
        for index in targets {
            let _ = self
                .eval_in(index, &format!("typeof __pt_setSiblings === 'function' && __pt_setSiblings({list});"))
                .await;
        }
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
            let (w, index) = self.route(index);
            self.engine
                .pool
                .dispatch(w, move |iso| iso.eval(index, &script))
                .await?
                .map_err(EngineError::Js)?;
        }
        Ok(n)
    }

    /// Run one queued `fetch` request and build the JS call that settles it.
    /// Start a frame or worker request without waiting: `settle_inflight` picks the reply
    /// up on a later pump. An instantly settled one (blocked URL) is returned now.
    fn start_fetch(&self, deliver: Deliver, context: usize, base: &str, r: &Value) -> Option<String> {
        match self.prepare_fetch(context, base, r) {
            Prepared::Settled(js) => Some(js),
            Prepared::Send(req, mut info) => {
                // A worker's request goes on the worker's timeline, not its owner frame's: in
                // Chrome a worker fetch does not appear in the frame's performance entries.
                if matches!(deliver, Deliver::Worker(..)) {
                    info.context = WORKER_RECORD_BASE + context;
                }
                let client = self.client.clone();
                let handle = tokio::spawn(async move { client.send(*req).await });
                if let Ok(mut v) = self.inflight.lock() {
                    v.push(InFlight { deliver, info, handle, doc: None });
                }
                None
            }
        }
    }

    /// Frame and worker requests in flight, the ones an idle loop waits for.
    fn inflight_awaited(&self) -> bool {
        self.inflight.lock().map(|v| v.iter().any(|f| f.doc.is_none())).unwrap_or(false)
    }

    /// Deliver replies that have arrived: record the request and settle the promise
    /// where it was made.
    async fn settle_inflight(&self) -> Result<usize, EngineError> {
        let done: Vec<InFlight> = match self.inflight.lock() {
            Ok(mut v) => {
                let mut out = Vec::new();
                let mut i = 0;
                while i < v.len() {
                    if v[i].handle.is_finished() {
                        out.push(v.remove(i));
                    } else {
                        i += 1;
                    }
                }
                out
            }
            Err(_) => Vec::new(),
        };
        let mut n = 0;
        let doc_now = self.doc_seq.load(std::sync::atomic::Ordering::Acquire);
        for f in done {
            if f.doc.is_some_and(|d| d != doc_now) {
                continue;
            }
            let res = match f.handle.await {
                Ok(r) => r,
                Err(e) => Err(NetError::Connect(format!("fetch task failed: {e}"))),
            };
            let settle = self.settle_fetch(&f.info, res);
            match f.deliver {
                Deliver::Frame(index) => {
                    // A browser adds the resource entry before the page learns of the response
                    // (load/then), so flush first.
                    self.flush_resource_timings(index).await;
                    if index == self.idx() {
                        self.sync_cookie_mirror(index, &self.document_url()).await;
                    }
                    let _ = self.eval_in(index, &settle).await;
                }
                Deliver::Worker(place, child) => {
                    let _ = self.eval_at(place, child, &settle).await;
                }
            }
            n += 1;
        }
        Ok(n)
    }

    fn prepare_fetch(&self, context: usize, base: &str, r: &Value) -> Prepared {
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
        let no_referrer = r["noReferrer"].as_bool().unwrap_or(false);
        if !no_referrer && !base.is_empty() && base != "about:blank" && !headers.keys().any(|k| k.eq_ignore_ascii_case("referer")) {
            headers.insert("Referer".to_string(), base.to_string());
        }
        // Blocked tracker: never hit the wire; reject like a real ad-blocker
        // (ERR_BLOCKED_BY_CLIENT), and log it so the interception audit is complete.
        if self.engine.block_trackers && nokk_net::is_blocked_url(&url) {
            self.record_in(context, &method, &url, &kind, 0, &[]);
            return Prepared::Settled(format!(
                "__pt_fetchReject({}, {})",
                id,
                serde_json::to_string("blocked by tracker filter").unwrap()
            ));
        }
        let body = r["body"].as_str().map(|s| {
            if r["bodyB64"].as_bool() == Some(true) {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.decode(s).unwrap_or_default()
            } else {
                s.as_bytes().to_vec()
            }
        });
        let sent = body.clone().unwrap_or_default();
        let req = Request {
            context: Some(context),
            method,
            url: url.clone(),
            headers,
            body,
            kind: nokk_net::RequestKind::Xhr,
            // The frame was granted access to its cookies: from now on a browser marks its
            // requests with `sec-fetch-storage-access`.
            third_party: r["storageAccess"].as_bool().unwrap_or(false),
            user_activated: false,
        };
        let method = req_method(&req);
        Prepared::Send(Box::new(req), FetchInfo { context, id, url, method, kind, sent })
    }

    fn settle_fetch(&self, info: &FetchInfo, res: Result<nokk_net::Response, NetError>) -> String {
        let FetchInfo { context, id, url, method, kind, sent } = info;
        let (context, id) = (*context, *id);
        match res {
            Ok(resp) => {
                self.record_full(
                    context,
                    &method,
                    &url,
                    &kind,
                    resp.status,
                    &resp.body,
                    resp.headers.clone(),
                    &sent,
                    resp.encoded_len,
                    Some(resp.elapsed_ms),
                    &resp.content_encoding,
                    resp.redirect_ms,
                );
                let headers_js =
                    serde_json::to_string(&resp.headers).unwrap_or_else(|_| "{}".into());
                // An image's intrinsic size is knowable only here, where the raw
                // bytes are: the body reaches JS as lossy text. A loaded image
                // used to report no size at all — `naturalWidth` undefined,
                // `width` zero — and anything that measures what it drew, as the
                // challenge does with its beacon PNG, read a picture 0 by 0.
                // Detect images by their bytes, not by the requester: the challenge beacon arrives
                // as a `<link>` but is drawn as an image.
                let meta = if image_size(&resp.body).is_some() {
                    // Whether the server opened the image up to other origins
                    // decides whether drawing it costs the canvas its readability.
                    let cors = resp
                        .headers
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"));
                    image_size(&resp.body)
                        .map(|(w, h)| {
                            let quoted = serde_json::to_string(&url).unwrap();
                            // The pixels travel separately: the body reaches JS
                            // as lossy text, so a picture drawn on a canvas
                            // would be a guess. Base64 is the only road, and it
                            // is worth taking only up to a sane size.
                            let bytes = if resp.body.len() <= 4 * 1024 * 1024 {
                                use base64::Engine as _;
                                let b64 = base64::engine::general_purpose::STANDARD
                                    .encode(&resp.body);
                                format!(
                                    "typeof __pt_imageBytes === 'function' && __pt_imageBytes({quoted}, \"{b64}\");"
                                )
                            } else {
                                String::new()
                            };
                            format!("__pt_imageMeta({quoted}, {w}, {h}, {cors});{bytes}")
                        })
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let body = String::from_utf8_lossy(&resp.body);
                // `response.url` is the final URL after redirects (fetch spec).
                let url_s: &str = url;
                let final_url: &str = if resp.url.is_empty() { url_s } else { &resp.url };
                // Bytes that are not UTF-8 also go as themselves, for `arrayBuffer()`.
                let bytes64 = if std::str::from_utf8(&resp.body).is_err() {
                    use base64::Engine as _;
                    format!("\"{}\"", base64::engine::general_purpose::STANDARD.encode(&resp.body))
                } else {
                    "null".to_string()
                };
                format!(
                    "{}__pt_fetchResolve({}, {}, {}, {}, {}, {}, {})",
                    meta,
                    id,
                    resp.status,
                    serde_json::to_string(reason_phrase(resp.status)).unwrap(),
                    headers_js,
                    serde_json::to_string(&*body).unwrap(),
                    serde_json::to_string(final_url).unwrap(),
                    bytes64,
                )
            }
            Err(e) => {
                // A transport failure is still an attempted request — log it with
                // status 0 so the interception log stays complete. (Skip the
                // "no real network" stub error, which never reached the wire.)
                if !matches!(e, NetError::Unimplemented) {
                    self.record_in(context, method, url, kind, 0, &[]);
                }
                // An unroutable host must reject, not hang: Chrome on this machine rejects fetches
                // to the challenge's IPv6-only host, the challenge worker reports
                // `TypeError: Failed to fetch`, and only then starts its next phase.
                if let NetError::Unreachable(why) = &e {
                    tracing::debug!(url = %url, %why, "no route to host: rejecting, as the browser does");
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

    /// Same, but the request belongs to a frame: its document and scripts go on its own
    /// timeline, as in a browser.
    async fn fetch_text_in(
        &self,
        context: usize,
        url: &str,
        resource_type: &str,
        referrer: Option<&str>,
    ) -> Result<(String, String), EngineError> {
        self.fetch_text_at(context, url, resource_type, referrer).await
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
        self.fetch_text_at(self.idx(), url, resource_type, referrer).await
    }

    /// A document by GET, retried when the connection itself failed — no
    /// response at all: a proxy that refused the tunnel (`CONNECT … 503`), a
    /// reset, a timeout. Those come and go on rotating proxies, and a solve used
    /// to end there in a fraction of a second. Any HTTP answer, a 403 gate
    /// included, is returned as is; a POST is never repeated.
    async fn fetch_document_retrying(
        &self,
        url: &str,
        referrer: Option<&str>,
    ) -> Result<(String, String), EngineError> {
        const PAUSES_MS: [u64; 2] = [500, 1500];
        let mut attempt = 0;
        loop {
            match self.fetch_text_from(url, "document", referrer).await {
                Err(EngineError::Net(e @ (NetError::Connect(_) | NetError::Timeout)))
                    if attempt < PAUSES_MS.len() =>
                {
                    tracing::warn!(target: "nokk", %url, error = %e, attempt = attempt + 1, "document fetch failed; retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(PAUSES_MS[attempt])).await;
                    attempt += 1;
                }
                other => return other,
            }
        }
    }

    /// A document via POST: a document request with a form body.
    async fn fetch_document_post(
        &self,
        url: &str,
        referrer: Option<&str>,
        content_type: &str,
        body: &str,
    ) -> Result<(String, String), EngineError> {
        let mut req = self.get_request(url, "document", referrer);
        req.method = "POST".into();
        req.body = Some(body.as_bytes().to_vec());
        req.headers.insert("Content-Type".to_string(), content_type.to_string());
        let started = std::time::Instant::now();
        let sent = self.client.send(req).await;
        self.finish_text(self.idx(), url, "document", started, sent)
    }

    #[allow(clippy::too_many_arguments)]
    async fn fetch_text_at(
        &self,
        context: usize,
        url: &str,
        resource_type: &str,
        referrer: Option<&str>,
    ) -> Result<(String, String), EngineError> {
        let mut req = self.get_request(url, resource_type, referrer);
        req.context = Some(context);
        let started = std::time::Instant::now();
        let sent = self.client.send(req).await;
        self.finish_text(context, url, resource_type, started, sent)
    }

    /// A script requested by the preload scanner, or fetched now if it was not preloaded.
    async fn take_preloaded(
        &self,
        pre: Option<Preloaded>,
        url: &str,
    ) -> Result<(String, String), EngineError> {
        match pre {
            Some((started, handle)) => match handle.await {
                Ok(sent) => self.finish_text(self.idx(), url, "script", started, sent),
                Err(_) => self.fetch_text(url, "script").await,
            },
            None => self.fetch_text(url, "script").await,
        }
    }

    /// A `GET` as a document sends it: fingerprint headers, referrer, destination.
    fn get_request(&self, url: &str, resource_type: &str, referrer: Option<&str>) -> Request {
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
        Request {
            context: None,
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
            third_party: false,
            user_activated: resource_type == "document" && referrer.is_none(),
        }
    }

    /// Record the response (or failure) and return the text. `started` is when the
    /// request went out: for a preloaded script, the scanner's moment, not when its turn came.
    fn finish_text(
        &self,
        context: usize,
        url: &str,
        resource_type: &str,
        started: std::time::Instant,
        sent: Result<nokk_net::Response, NetError>,
    ) -> Result<(String, String), EngineError> {
        match sent {
            Ok(resp) => {
                // Duration from request start to response end, as in a browser; the entry is placed
                // at the start time.
                let measured = resp.elapsed_ms;
                let lag = started.elapsed().as_secs_f64() * 1000.0 - measured;
                self.record_full(
                    context,
                    "GET",
                    url,
                    resource_type,
                    resp.status,
                    &resp.body,
                    resp.headers.clone(),
                    &[],
                    resp.encoded_len,
                    Some(measured),
                    &resp.content_encoding,
                    resp.redirect_ms,
                );
                if lag > 1.0 {
                    self.shift_last_record(context, url, lag);
                }
                let final_url = if resp.url.is_empty() {
                    url.to_string()
                } else {
                    resp.url.clone()
                };
                let mut body = String::from_utf8_lossy(&resp.body).into_owned();
                // A text or JSON document is shown the way Chrome builds it; the
                // document then reports its real type.
                if resource_type == "document" {
                    let mime = resp
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
                        .unwrap_or_default();
                    if let Some(markup) = text_document_markup(&mime, &body) {
                        body = markup;
                        if let Ok(mut t) = self.doc_types.lock() {
                            t.insert(final_url.clone(), mime);
                        }
                    }
                }
                Ok((final_url, body))
            }
            Err(NetError::Unimplemented) => Err(EngineError::NavNotImplemented),
            Err(e) => {
                // Log the failed attempt (status 0) before surfacing the error.
                self.record_in(context, "GET", url, resource_type, 0, &[]);
                Err(EngineError::Net(e))
            }
        }
    }

    /// Move the start of the last record for `url` back by `lag` ms: the response
    /// arrived before it was taken.
    fn shift_last_record(&self, context: usize, url: &str, lag: f64) {
        if let Ok(mut log) = self.requests.lock() {
            if let Some(r) = log.iter_mut().rev().find(|r| r.context == context && r.url == url) {
                r.started_ms = (r.started_ms - lag).max(0.0);
            }
        }
    }

    /// Append a request to this context's interception log.
    fn record(&self, method: &str, url: &str, resource_type: &str, status: u16, body: &[u8]) {
        self.record_in(self.idx(), method, url, resource_type, status, body)
    }

    /// Same, on behalf of the frame or worker that made the request.
    fn record_in(
        &self,
        context: usize,
        method: &str,
        url: &str,
        resource_type: &str,
        status: u16,
        body: &[u8],
    ) {
        self.record_full(
            context,
            method,
            url,
            resource_type,
            status,
            body,
            std::collections::BTreeMap::new(),
            &[],
            body.len(),
            None,
            "",
            None,
        )
    }


    /// Log one request and tell any subscriber (the CDP layer) about it. Called
    /// once the outcome is known, which is why a subscriber receives the whole
    /// lifecycle at once rather than a `willBeSent` ahead of time — the timings
    /// are coarser than Chrome's, but every field a client reads is real.
    #[allow(clippy::too_many_arguments)]
    fn record_full(
        &self,
        context: usize,
        method: &str,
        url: &str,
        resource_type: &str,
        status: u16,
        body: &[u8],
        headers: std::collections::BTreeMap<String, String>,
        request_body: &[u8],
        encoded_len: usize,
        measured_ms: Option<f64>,
        content_encoding: &str,
        redirect_ms: Option<f64>,
    ) {
        let now = self.started.elapsed().as_secs_f64() * 1000.0;
        // Measured time, not one number for all: a browser gives each resource its own
        // duration and pages read them. Without a measurement (request failed) keep the
        // fast-local estimate: a zero-duration resource is not a resource.
        let duration_ms = measured_ms.unwrap_or(12.0);
        let started_ms = now - duration_ms;
        let announced = self.client.hold.take_id(url);
        let frame = self.frame_of_context(context).or_else(|| {
            (resource_type == "document")
                .then(|| self.frame_docs.lock().ok().and_then(|mut d| d.remove(url)))
                .flatten()
        });
        let rec = NetworkRecord {
            request_id: announced.clone().unwrap_or_else(next_request_id),
            announced: announced.is_some(),
            headers,
            method: method.to_string(),
            url: url.to_string(),
            status,
            resource_type: resource_type.to_string(),
            body: body.to_vec(),
            request_body: request_body.to_vec(),
            started_ms: started_ms.max(0.0),
            duration_ms: duration_ms.max(0.0),
            encoded_len,
            content_encoding: content_encoding.to_string(),
            redirect_ms,
            context,
            frame,
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

    /// Hold every request this context makes from now on until the receiver
    /// decides (CDP `Fetch.enable`). One interceptor at a time; dropping the
    /// receiver lets held and later requests go out unchanged.
    pub fn intercept_requests(&self) -> tokio::sync::mpsc::UnboundedReceiver<PausedRequest> {
        self.client.intercept()
    }

    /// Stop holding requests (CDP `Fetch.disable`).
    pub fn stop_intercepting(&self) {
        self.client.stop();
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
/// The document Chrome 151 builds for a text or JSON response, or `None` for
/// types it renders otherwise (HTML, XML, images) or downloads (CSV, YAML).
/// The parser drops one newline right after `<pre>`; Chrome builds this
/// document directly and keeps it, hence the extra one.
fn text_document_markup(mime: &str, body: &str) -> Option<String> {
    let json = mime == "application/json" || mime == "text/json" || (mime.starts_with("application/") && mime.ends_with("+json"));
    const SCRIPT: [&str; 4] = ["application/javascript", "application/x-javascript", "application/ecmascript", "application/x-ecmascript"];
    // Chrome downloads these instead of showing them.
    const DOWNLOADED: [&str; 19] = [
        "text/calendar", "text/x-calendar", "text/x-vcalendar", "text/vcalendar", "text/vcard", "text/x-vcard",
        "text/directory", "text/ldif", "text/qif", "text/x-qif", "text/x-csv", "text/x-vcf", "text/rtf",
        "text/comma-separated-values", "text/csv", "text/tab-separated-values", "text/tsv", "text/ofx",
        "text/vnd.sun.j2me.app-descriptor",
    ];
    let text = SCRIPT.contains(&mime)
        || (mime.starts_with("text/")
            && !matches!(mime, "text/html" | "text/xml" | "text/xsl")
            && !DOWNLOADED.contains(&mime));
    if !json && !text {
        return None;
    }
    let mut esc = String::with_capacity(body.len() + 16);
    if body.starts_with('\n') {
        esc.push('\n');
    }
    for c in body.chars() {
        match c {
            '&' => esc.push_str("&amp;"),
            '<' => esc.push_str("&lt;"),
            '>' => esc.push_str("&gt;"),
            _ => esc.push(c),
        }
    }
    Some(if json {
        format!("<html><head><meta name=\"color-scheme\" content=\"light dark\"><meta charset=\"utf-8\"></head><body><pre>{esc}</pre><div class=\"json-formatter-container\"></div></body></html>")
    } else {
        format!("<html><head><meta name=\"color-scheme\" content=\"light dark\"></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">{esc}</pre></body></html>")
    })
}

static REQUEST_IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub(crate) fn next_request_id() -> String {
    format!("nokk-{}", REQUEST_IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}

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
    cookies: typeof __pt_drainCookieQueue === 'function' ? __pt_drainCookieQueue() : [],\
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
// Every 4 ms, not 20: a frame's messages to its worker go through this queue, and
// the challenge times "set a 55 ms timer, reply". 20 ms delivery lag turned 55 into
// 79, and the widget retried the probe until it expired.
const FRAME_PUMP_EVERY: std::time::Duration = std::time::Duration::from_millis(4);
/// How long a round waits for the page's requests before leaving the slow ones in flight.
const PAGE_FETCH_GRACE: std::time::Duration = std::time::Duration::from_millis(1000);
/// How long a parser-blocking or deferred script waits for markup stylesheets.
const SHEETS_WAIT: std::time::Duration = std::time::Duration::from_secs(15);
/// An async script does not wait for stylesheets in a browser. It waits briefly here so
/// that a sheet already on its way still lands first, which is the common case there.
const SHEETS_WAIT_ASYNC: std::time::Duration = std::time::Duration::from_millis(1000);

/// A preloaded script: when it was requested and the task awaiting it.
type Preloaded = (
    std::time::Instant,
    tokio::task::JoinHandle<Result<nokk_net::Response, NetError>>,
);

/// Context index of a frame on its own pool thread. Indices are per isolate, so such
/// a frame is addressed by (thread, index) packed into one tagged number: anything
/// taking `index` works as before, and [`BrowserContext::route`] unpacks it.
const OWN_THREAD: usize = 1usize << 48;

fn own_thread_index(worker: nokk_pool::WorkerId, raw: usize) -> usize {
    OWN_THREAD | ((worker.0 & 0xFFFF) << 32) | (raw & 0xFFFF_FFFF)
}

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
/// The intrinsic size of an encoded image, read from its header alone.
///
/// Enough of each container to find the two numbers a browser reports as
/// `naturalWidth`/`naturalHeight`; no pixels are decoded. Unknown or truncated
/// data gives `None`, and the image then keeps the zero size it has before a
/// browser has finished decoding.
fn image_size(bytes: &[u8]) -> Option<(u32, u32)> {
    let be32 = |i: usize| -> Option<u32> {
        Some(u32::from_be_bytes(bytes.get(i..i + 4)?.try_into().ok()?))
    };
    let le32 = |i: usize| -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(i..i + 4)?.try_into().ok()?))
    };
    let be16 = |i: usize| -> Option<u32> {
        Some(u32::from(u16::from_be_bytes(
            bytes.get(i..i + 2)?.try_into().ok()?,
        )))
    };
    let le16 = |i: usize| -> Option<u32> {
        Some(u32::from(u16::from_le_bytes(
            bytes.get(i..i + 2)?.try_into().ok()?,
        )))
    };

    // PNG: the IHDR chunk is always first, at a fixed offset.
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") && bytes.get(12..16) == Some(b"IHDR") {
        return Some((be32(16)?, be32(20)?));
    }
    // GIF87a/89a: little-endian logical screen size.
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some((le16(6)?, le16(8)?));
    }
    // BMP: the DIB header carries a signed width/height.
    if bytes.starts_with(b"BM") {
        return Some((le32(18)?, le32(22)?.cast_signed().unsigned_abs()));
    }
    // WebP: three flavours, each keeping the size somewhere else.
    if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        return match bytes.get(12..16)? {
            b"VP8 " => Some((be16(26)?.swap_bytes() & 0x3fff, be16(28)?.swap_bytes() & 0x3fff)),
            b"VP8L" => {
                let b = u32::from_le_bytes(bytes.get(21..25)?.try_into().ok()?);
                Some(((b & 0x3fff) + 1, ((b >> 14) & 0x3fff) + 1))
            }
            b"VP8X" => {
                let w = u32::from(bytes[24]) | u32::from(bytes[25]) << 8 | u32::from(bytes[26]) << 16;
                let h = u32::from(bytes[27]) | u32::from(bytes[28]) << 8 | u32::from(bytes[29]) << 16;
                Some((w + 1, h + 1))
            }
            _ => None,
        };
    }
    // JPEG: walk the marker chain to the frame header that states the size.
    if bytes.starts_with(b"\xff\xd8") {
        let mut i = 2;
        while i + 9 < bytes.len() {
            if bytes[i] != 0xff {
                i += 1;
                continue;
            }
            let marker = bytes[i + 1];
            // Standalone markers carry no length.
            if (0xd0..=0xd9).contains(&marker) || marker == 0x01 || marker == 0xff {
                i += 2;
                continue;
            }
            let len = be16(i + 2)? as usize;
            // SOF0..SOF15, minus the two that are not frame headers.
            if (0xc0..=0xcf).contains(&marker) && marker != 0xc4 && marker != 0xcc {
                return Some((be16(i + 7)?, be16(i + 5)?));
            }
            i += 2 + len.max(2);
        }
    }
    None
}

/// Sequence number for dumped worker tasks (see `NOKK_DUMP_WORKER_TASKS`).
static WORKER_TASK_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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

    #[tokio::test]
    async fn releasing_an_identity_drops_its_pooled_client() {
        let _serial = serial().await;
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
        let _a = engine
            .new_context_with_identity("A".into(), None)
            .await
            .unwrap();
        assert_eq!(engine.inner.client_pool.lock().unwrap().len(), 1);
        engine.release_identity("A");
        assert!(
            engine.inner.client_pool.lock().unwrap().is_empty(),
            "a released identity must not keep its client pooled"
        );
        // Releasing an unknown identity is a harmless no-op.
        engine.release_identity("never-created");
        // Re-creating the identity builds a fresh client again.
        let _a2 = engine
            .new_context_with_identity("A".into(), None)
            .await
            .unwrap();
        assert_eq!(engine.inner.client_pool.lock().unwrap().len(), 1);
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

    /// Every document gets its own global: what one page left on `window` or
    /// patched into a built-in is gone on the next. What outlives a document —
    /// its origin's storage, the tab's history length — comes along, and only
    /// to a document of the same origin.
    #[tokio::test]
    async fn a_new_document_gets_a_fresh_global_but_keeps_its_storage() {
        let _serial = serial().await;
        let engine = engine(4, 6);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://a.example/", "<html><body></body></html>")
            .await
            .unwrap();
        ctx.evaluate(
            "var leaked = 1; Array.prototype.patched = 1; \
             localStorage.setItem('k', 'v'); sessionStorage.setItem('s', 'w'); \
             history.pushState({}, '', '#x');",
        )
        .await
        .unwrap();

        ctx.load_html("https://a.example/next", "<html><body></body></html>")
            .await
            .unwrap();
        let same = ctx
            .evaluate(
                "JSON.stringify([typeof leaked, [].patched === undefined, \
                 localStorage.getItem('k'), sessionStorage.getItem('s'), history.length])",
            )
            .await
            .unwrap();
        assert_eq!(same, Value::String(r#"["undefined",true,"v","w",3]"#.into()));

        ctx.load_html("https://b.example/", "<html><body></body></html>")
            .await
            .unwrap();
        let other = ctx
            .evaluate("JSON.stringify([localStorage.getItem('k'), sessionStorage.getItem('s')])")
            .await
            .unwrap();
        assert_eq!(other, Value::String("[null,null]".into()));
    }

    /// Three DOM rules a sign-in page's jQuery leans on: an `<html>` element's
    /// `innerHTML` parses into a `<head>` and a `<body>`; emptying a node leaves
    /// its old children parentless (jQuery's `buildFragment` empties a scratch
    /// `<div>`, then moves them); and `after`/`before`/`replaceWith`/
    /// `replaceChildren` move nodes on elements too.
    #[tokio::test]
    async fn dom_moves_nodes_as_a_browser_does() {
        let _serial = serial().await;
        let engine = engine(4, 6);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        let got = ctx
            .evaluate(
                r#"(() => {
                const r = [];
                const e = document.createElement('html');
                e.innerHTML = '<!DOCTYPE html><html><head><title>t</title></head><body><div id=api></div></body></html>';
                r.push([...e.children].map(c => c.tagName).join(','), e.querySelector('body #api') ? 'api' : 'none');
                const d = document.createElement('div');
                d.innerHTML = '<p>a</p>';
                const p = d.firstChild;
                d.textContent = '';
                r.push(String(p.parentNode));
                document.createDocumentFragment().appendChild(p);
                const m = () => { const x = document.createElement('div'); x.innerHTML = '<b>1</b><i>2</i>'; return x; };
                let x = m(); x.firstChild.after('x'); r.push(x.innerHTML);
                x = m(); x.lastChild.before('x'); r.push(x.innerHTML);
                x = m(); x.firstChild.replaceWith('x'); r.push(x.innerHTML);
                x = m(); x.replaceChildren('x'); r.push(x.innerHTML);
                return JSON.stringify(r);
            })()"#,
            )
            .await
            .unwrap();
        assert_eq!(
            got,
            Value::String(
                r#"["HEAD,BODY","api","null","<b>1</b>x<i>2</i>","<b>1</b>x<i>2</i>","x<i>2</i>","x"]"#
                    .into()
            )
        );
    }

    /// What survives the trip to a worker and back. A browser uses structured
    /// clone: binary stays binary, a `Map` stays a `Map`, a date a date. Going
    /// through JSON turned them into something else.
    #[tokio::test]
    async fn a_message_to_a_worker_keeps_its_shape() {
        let _serial = serial().await;
        let engine = engine(4, 6);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/app/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(
            r#"(() => {
            const src = "onmessage=function(e){ const d = e.data; postMessage({ \
                 kind: Object.prototype.toString.call(d.bytes), \
                 first: d.bytes && d.bytes[0], \
                 len: d.bytes && d.bytes.length, \
                 mapKind: Object.prototype.toString.call(d.map), \
                 dateKind: Object.prototype.toString.call(d.when), \
                 back: new Uint8Array([7, 8, 9]) }) }";
            const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
            globalThis.__got = null;
            w.onmessage = (e) => {
              globalThis.__got = {
                said: e.data,
                backKind: Object.prototype.toString.call(e.data && e.data.back),
                backFirst: e.data && e.data.back && e.data.back[0],
              };
            };
            w.postMessage({ bytes: new Uint8Array([1, 2, 3]), map: new Map([['a', 1]]), when: new Date(0) });
            return 1;
        })()"#,
        )
        .await
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            ctx.run_event_loop().await.unwrap();
            let n = probe(&ctx, "__ptJSON.stringify(globalThis.__got ? 1 : 0)").await;
            if n.as_u64().unwrap_or(0) == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let got = probe(&ctx, "__ptJSON.stringify(globalThis.__got)").await;
        assert_eq!(got["said"]["kind"], "[object Uint8Array]", "bytes arrive as bytes: {got}");
        assert_eq!(got["said"]["first"], 1, "{got}");
        assert_eq!(got["said"]["len"], 3, "{got}");
        assert_eq!(got["said"]["mapKind"], "[object Map]", "Map stays a Map: {got}");
        assert_eq!(got["said"]["dateKind"], "[object Date]", "a date stays a date: {got}");
        assert_eq!(got["backKind"], "[object Uint8Array]", "and back too: {got}");
        assert_eq!(got["backFirst"], 7, "{got}");
    }

    /// `DOMContentLoaded` bubbles from the document to the window, where it is usually
    /// heard; Turnstile's api.js sets up its auto-render there.
    #[tokio::test]
    async fn dom_content_loaded_reaches_the_window() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><head><script>
                 window.__log = { onWindow: false, onDocument: false, state: null, load: false };
                 addEventListener('DOMContentLoaded', () => { __log.onWindow = true; __log.state = document.readyState; });
                 document.addEventListener('DOMContentLoaded', () => { __log.onDocument = true; });
                 addEventListener('load', () => { __log.load = true; });
               </script></head><body></body></html>"#,
        )
        .await
        .unwrap();

        let out = probe(&ctx, "__ptJSON.stringify(window.__log)").await;
        assert_eq!(out["onWindow"], true, "the window hears the event: {out}");
        assert_eq!(out["onDocument"], true, "and the document too: {out}");
        // In a browser the document is already `interactive` during DOMContentLoaded.
        assert_eq!(out["state"], "interactive", "{out}");
        assert_eq!(out["load"], true, "{out}");
    }

    /// The whole Turnstile path on Cloudflare's own test keys: the widget builds, talks
    /// to the page, the engine clicks the checkbox for the interactive variant, and the
    /// page gets a token. Tests the machinery, not the fingerprint: keys `1x…AA` and
    /// `3x…FF` give a token to anyone who gets to the end.
    #[tokio::test]
    async fn a_turnstile_widget_runs_to_a_token() {
        let _serial = serial().await;
        const PAGE: &str = r#"<html><body><div id="box"></div><script>
            window.__state = { token: null, events: [] };
            addEventListener('message', (e) => {
              try { if (e.data && e.data.source === 'cloudflare-challenge') __state.events.push(e.data.event); } catch (x) {}
            });
            window.onTurnstileLoad = function () {
              window.turnstile.render('#box', {
                sitekey: '__KEY__',
                callback: (t) => { __state.token = String(t).slice(0, 30); },
              });
            };
            const s = document.createElement('script');
            s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileLoad&render=explicit';
            document.head.appendChild(s);
          </script></body></html>"#;

        for (key, interactive) in [
            ("1x00000000000000000000AA", false),
            ("3x00000000000000000000FF", true),
        ] {
            let html = PAGE.replace("__KEY__", key);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let body = html.clone();
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let body = body.clone();
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = [0u8; 1024];
                        let _ = stream.read(&mut buf).await;
                        let out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(out.as_bytes()).await;
                    });
                }
            });

            let engine = Engine::new(EngineConfig {
                pool: PoolConfig { workers: 2, max_live_contexts: 6, max_heap_mb: None },
                use_real_network: true,
                ..Default::default()
            })
            .expect("engine");
            let ctx = engine.new_context().await.unwrap();
            ctx.navigate(&format!("http://{addr}/")).await.unwrap();

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
            let mut token = Value::Null;
            while std::time::Instant::now() < deadline {
                ctx.run_event_loop().await.unwrap();
                let _ = ctx.press_widget_control().await;
                token = ctx
                    .evaluate("(globalThis.__state && __state.token) || ''")
                    .await
                    .unwrap_or(Value::Null);
                if token.as_str().map_or(false, |t| !t.is_empty()) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }

            let events = ctx
                .evaluate("((globalThis.__state && __state.events) || []).join(',')")
                .await
                .unwrap_or(Value::Null);
            let events = events.as_str().unwrap_or("").to_string();
            assert!(
                token.as_str().map_or(false, |t| t.contains("TOKEN")),
                "key {key} must yield a token: events [{events}]"
            );
            assert!(events.contains("complete"), "and report `complete`: [{events}]");
            if interactive {
                assert!(
                    events.contains("interactiveBegin") && events.contains("interactiveEnd"),
                    "the interactive variant goes through a click: [{events}]"
                );
            }
        }
    }

    /// Promises a collector waits on: WebGPU adapter, media decoding, keyboard layout,
    /// storage estimate, permissions. Any that never settles stalls its program silently.
    #[tokio::test]
    async fn the_promises_a_collector_waits_for_all_settle() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(
            r#"(() => {
              globalThis.__r = {};
              const note = (k, v) => { globalThis.__r[k] = v; };
              try {
                navigator.gpu.requestAdapter().then(
                  (a) => note('adapter', a ? Object.prototype.toString.call(a) : String(a)),
                  (e) => note('adapter', 'rejected'));
              } catch (e) { note('adapter', 'threw'); }
              try {
                navigator.mediaCapabilities.decodingInfo({ type: 'file',
                  video: { contentType: 'video/mp4; codecs="avc1.42E01E"', width: 640, height: 480, bitrate: 1000, framerate: 30 } })
                  .then((r) => note('mediaCaps', !!r), () => note('mediaCaps', 'rejected'));
              } catch (e) { note('mediaCaps', 'threw'); }
              try { navigator.keyboard.getLayoutMap().then((m) => note('layout', !!m), () => note('layout', 'rejected')); }
              catch (e) { note('layout', 'threw'); }
              try { navigator.storage.estimate().then((r) => note('estimate', !!r), () => note('estimate', 'rejected')); }
              catch (e) { note('estimate', 'threw'); }
              try { navigator.permissions.query({ name: 'notifications' }).then((s) => note('perm', s && s.state), () => note('perm', 'rejected')); }
              catch (e) { note('perm', 'threw'); }
              try { navigator.storage.getDirectory().then((d) => note('opfs', !!d), () => note('opfs', 'rejected')); }
              catch (e) { note('opfs', 'threw'); }
              return 1;
            })()"#,
        )
        .await
        .unwrap();
        for _ in 0..4 {
            ctx.run_event_loop().await.unwrap();
        }

        let out = probe(&ctx, "__ptJSON.stringify(globalThis.__r)").await;
        for key in ["adapter", "mediaCaps", "layout", "estimate", "perm", "opfs"] {
            assert!(out.get(key).is_some(), "promise `{key}` did not settle: {out}");
        }
    }

    /// SHA-256 via `crypto.subtle.digest`, which pages sign their collected data with.
    /// Known vector: "abc" hashes to ba 78 16 bf...
    #[tokio::test]
    async fn subtle_crypto_computes_a_real_digest() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(
            r#"(() => {
                globalThis.__h = null;
                crypto.subtle.digest('SHA-256', new TextEncoder().encode('abc')).then(
                  (b) => { globalThis.__h = Array.from(new Uint8Array(b)); },
                  (e) => { globalThis.__h = 'rejected: ' + e; });
                return 1;
              })()"#,
        )
        .await
        .unwrap();
        for _ in 0..3 {
            ctx.run_event_loop().await.unwrap();
        }

        let out = probe(&ctx, "__ptJSON.stringify(globalThis.__h)").await;
        let bytes = out.as_array().cloned().unwrap_or_default();
        assert_eq!(bytes.len(), 32, "expected 32 bytes: {out}");
        assert_eq!(bytes[0], 0xba, "{out}");
        assert_eq!(bytes[1], 0x78, "{out}");
        assert_eq!(bytes[2], 0x16, "{out}");
        assert_eq!(bytes[3], 0xbf, "{out}");
    }

    /// The CSS property list is an engine/version signature that collectors serialize
    /// whole. A browser keeps the names as own properties of the declaration (in its
    /// order) and the methods on the prototype. Values taken from Chrome 148.
    #[tokio::test]
    async fn a_style_declaration_is_shaped_like_a_browsers() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(
            &ctx,
            r#"(() => {
                const st = document.body.style;
                st.color = 'red';
                st.setProperty('background-color', 'blue');
                const cs = getComputedStyle(document.body);
                const names = Object.getOwnPropertyNames(st);
                return __ptJSON.stringify({
                  inlineOwn: names.length,
                  firstThree: names.slice(0, 3),
                  protoOwn: Object.getOwnPropertyNames(Object.getPrototypeOf(st)).length,
                  color: st.color,
                  background: st.getPropertyValue('background-color'),
                  cssText: st.cssText,
                  inlineLength: st.length,
                  computedLength: cs.length,
                  computedOwn: Object.getOwnPropertyNames(cs).length,
                  computedFirst: cs[0],
                  computedDashed: cs['background-color'],
                  sameProto: Object.getPrototypeOf(cs) === Object.getPrototypeOf(st),
                  // A browser's property descriptor is a data value, not an accessor.
                  inlineDesc: (() => { const d = Object.getOwnPropertyDescriptor(st, 'color');
                    return [typeof d.get, d.value, !!d.writable, !!d.enumerable, !!d.configurable]; })(),
                  computedDesc: (() => { const d = Object.getOwnPropertyDescriptor(cs, 'backgroundColor');
                    return [typeof d.get, d.value]; })(),
                  // The nine `-epub-` names have no descriptor: listed, but `in` says no and the
                  // value reads `undefined`.
                  epub: [names.includes('epubWordBreak'),
                         Object.getOwnPropertyDescriptor(st, 'epubWordBreak') === undefined,
                         'epubWordBreak' in st, String(st.epubWordBreak),
                         cs.getPropertyValue('-epub-word-break')],
                  epubAt: [names.indexOf('epubCaptionSide'), names[names.indexOf('epubCaptionSide') - 1]],
                })
              })()"#,
        )
        .await;

                // Two declarations: two index properties over 745 names. Nine are `-epub-`: listed
                // as own but without a descriptor, as in a browser. Browser order: indices first.
        assert_eq!(out["inlineOwn"], 747, "{out}");
        assert_eq!(
            out["firstThree"],
            serde_json::json!(["0", "1", "accentColor"]),
            "and in browser order: {out}"
        );
        assert_eq!(out["protoOwn"], 10, "{out}");
        // Shape aside, it must still work.
        assert_eq!(out["color"], "red", "{out}");
        assert_eq!(out["background"], "blue", "{out}");
        assert_eq!(out["inlineLength"], 2, "{out}");
        assert_eq!(out["cssText"], "color: red; background-color: blue;", "{out}");
        // Computed style: 475 indexed properties plus the same names, including the nine `-epub-`.
        assert_eq!(out["computedLength"], 475, "{out}");
        assert_eq!(out["computedOwn"], 1220, "{out}");
        assert_eq!(out["computedFirst"], "accent-color", "{out}");
        assert!(out["computedDashed"].is_string(), "dashed name reads: {out}");
        assert_eq!(out["sameProto"], true, "both declarations share an interface: {out}");
        assert_eq!(
            out["inlineDesc"],
            serde_json::json!(["undefined", "red", true, true, true]),
            "property is a data value, not an accessor: {out}"
        );
        assert_eq!(
            out["computedDesc"],
            serde_json::json!(["undefined", "rgb(0, 0, 255)"]),
            "computed one too, already resolved: {out}"
        );
        assert_eq!(
            out["epub"],
            serde_json::json!([true, true, false, "undefined", "normal"]),
            "name listed, no descriptor: {out}"
        );
        assert_eq!(
            out["epubAt"],
            serde_json::json!([195, "emptyCells"]),
            "at the same position as in a browser: {out}"
        );
    }

    /// An image is a request: `new Image().src = …` is a common way to send a GET, and
    /// a relative URL (the usual form) used to send nothing.
    #[tokio::test]
    async fn setting_an_image_source_makes_a_request() {
        let _serial = serial().await;
        let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    if let Some(path) = req.split_whitespace().nth(1) {
                        if let Ok(mut v) = seen.lock() {
                            v.push(path.to_string());
                        }
                    }
                    let body = if req.contains("GET /page") {
                        "<html><body><script>const i = new Image(); i.src = '/pixel.png?x=1';</script></body></html>"
                    } else {
                        "ok"
                    };
                    let out = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
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
        ctx.navigate(&format!("http://{addr}/page")).await.unwrap();
        ctx.run_event_loop().await.unwrap();

        let asked = hits.lock().map(|v| v.clone()).unwrap_or_default();
        assert!(
            asked.iter().any(|p| p.starts_with("/pixel.png")),
            "the image request must go out: {asked:?}"
        );
    }

    /// Origin private file system. The challenge asks for it in a worker, creates a
    /// file, takes a sync handle, writes a byte and times `flush()`; our
    /// `getDirectory()` rejected with "access denied", which Chrome never does in a
    /// secure context. Runs the exact probe the challenge sends.
    #[tokio::test]
    async fn the_origin_private_file_system_answers_from_a_worker() {
        let _serial = serial().await;
        let engine = engine(4, 6);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/app/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(
            r#"(() => {
            const src = "onmessage=function(e){ e.isTrusted && '' === e.origin && null === e.source && eval(e.data) }";
            const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
            globalThis.__got = [];
            w.onmessage = (e) => { globalThis.__got.push(e.data); };
            w.postMessage("~function(){navigator.storage.getDirectory().then(function(L){var i=`UQnV8`,j={};j[`create`]=!![],L.getFileHandle(i,j).then(function(y){return y.createSyncAccessHandle()}).then(function(y){var F=new Uint8Array(1),a={};a[`at`]=0,y.write(F,a);var t=performance.now();y.flush();var Z=performance.now()-t;y.close();var B={};B[`hnMoX4`]=Z,self.postMessage(B)}).catch(function(y){self.postMessage({\"CEnF0\":(y.message||String(y)).substring(0,100)})})}).catch(function(O){self.postMessage({\"CEnF0\":(O.message||String(O)).substring(0,100)})})}();");
            return 1;
        })()"#,
        )
        .await
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            ctx.run_event_loop().await.unwrap();
            let n = probe(&ctx, "__ptJSON.stringify((globalThis.__got || []).length)").await;
            if n.as_u64().unwrap_or(0) >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let got = probe(&ctx, "__ptJSON.stringify(globalThis.__got || [])").await;
        let list = got.as_array().cloned().unwrap_or_default();
        assert_eq!(list.len(), 1, "the worker must answer: {got}");
        // `hnMoX4` is how long `flush()` took. It must be a number, not a complaint in
        // `CEnF0`, which means no file system.
        assert!(
            list[0]["hnMoX4"].is_number(),
            "the probe ran to the end without failing: {got}"
        );
    }

    /// The challenge fingerprints by walking the global graph. Closing that graph
    /// by name was not enough: every interface object we made was an ordinary
    /// function, and an ordinary function owns `arguments` and `caller`, which no
    /// browser interface does. 834 of 947 carried them.
    #[tokio::test]
    async fn an_interface_object_has_a_browser_shape() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let bad = probe(
            &ctx,
            r#"__ptJSON.stringify((() => {
                const out = [];
                for (const n of Object.getOwnPropertyNames(globalThis)) {
                    if (!/^[A-Z]/.test(n)) continue;
                    let v; try { v = globalThis[n]; } catch (e) { continue; }
                    if (typeof v !== 'function') continue;
                    const own = Object.getOwnPropertyNames(v);
                    if (own.indexOf('arguments') >= 0 || own.indexOf('caller') >= 0) out.push(n);
                }
                return out;
            })())"#,
        )
        .await;
        assert_eq!(bad.as_array().map(Vec::len), Some(0), "not browser-shaped: {bad}");

        // And the statics that live on the interface itself, which a graph walk
        // reads on its first step.
        let statics = probe(
            &ctx,
            r#"__ptJSON.stringify([Event.AT_TARGET, DOMException.ABORT_ERR,
                KeyboardEvent.DOM_KEY_LOCATION_NUMPAD, typeof URL.canParse,
                Object.getOwnPropertyNames(NodeFilter).indexOf('prototype')])"#,
        )
        .await;
        let v = statics.as_array().expect("array");
        assert_eq!(v[0].as_i64(), Some(2));
        assert_eq!(v[1].as_i64(), Some(20));
        assert_eq!(v[2].as_i64(), Some(3));
        assert_eq!(v[3].as_str(), Some("function"));
        assert_eq!(v[4].as_i64(), Some(-1), "NodeFilter must have no prototype");
    }

    /// A browser's window is one rectangle: `innerWidth` and
    /// `documentElement.clientWidth` describe the same viewport. Ours answered
    /// 1280x720 to one and the profile's size to the other — a page that asks
    /// both saw two windows at once.
    #[tokio::test]
    async fn the_document_and_the_window_are_the_same_size() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body>hi</body></html>")
            .await
            .unwrap();
        let got = probe(
            &ctx,
            r#"__ptJSON.stringify({
                inner: [innerWidth, innerHeight],
                doc: [document.documentElement.clientWidth, document.documentElement.clientHeight],
                filter: document.createElement('canvas').getContext('2d').filter,
            })"#,
        )
        .await;
        assert_eq!(got["inner"], got["doc"], "window and document disagree: {got}");
        assert!(got["inner"][0].as_u64().unwrap_or(0) > 0, "{got}");
        // Also the one frame question we answered with nothing.
        assert_eq!(got["filter"], "none", "{got}");
    }

    /// The challenge counts the names on each interface prototype. Ours kept
    /// them on the object instead — `url.protocol`, `pc.iceGatheringState`,
    /// `mql.matches` — so `URL.prototype` had 3 names against Chrome's 15 and
    /// `RTCPeerConnection.prototype` had 15 against 46.
    #[tokio::test]
    async fn an_interface_keeps_its_members_on_the_prototype() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        let got = probe(
            &ctx,
            r#"__ptJSON.stringify({
                counts: [URL, RTCPeerConnection, AnalyserNode, MediaDevices,
                         MediaQueryList, TextDecoder, TextEncoder, SubtleCrypto]
                    .map((C) => Object.getOwnPropertyNames(C.prototype).length),
                url: (() => { const u = new URL('https://a.b:8443/p?q=1#h');
                    return [u.protocol, u.host, u.hash, u.search, u.origin, Object.keys(u).length]; })(),
            })"#,
        )
        .await;
        // Snapshot of Chrome 148, interface by interface.
        assert_eq!(got["counts"], serde_json::json!([15, 46, 10, 7, 6, 5, 4, 13]), "{got}");
        // And the members still answer — they read the object's own state, they
        // just live where the browser keeps them.
        assert_eq!(
            got["url"],
            serde_json::json!(["https:", "a.b:8443", "#h", "?q=1", "https://a.b:8443", 0]),
            "{got}"
        );
    }

    /// A load fires once, and the property handler takes its turn where it was
    /// set. Ours called `onload` itself *and* dispatched, so every image and
    /// every frame reported twice; and the handler always went last, where a
    /// browser runs it in registration order.
    #[tokio::test]
    async fn a_load_arrives_once_and_in_order() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        let got = probe(
            &ctx,
            r#"__ptJSON.stringify((() => {
                const order = (setup) => {
                    const seen = [];
                    const el = document.createElement('div');
                    setup(el, seen);
                    el.dispatchEvent(new Event('load'));
                    return seen;
                };
                return {
                    onFirst: order((el, seen) => {
                        el.onload = () => seen.push('on');
                        el.addEventListener('load', () => seen.push('lis'));
                    }),
                    listenerFirst: order((el, seen) => {
                        el.addEventListener('load', () => seen.push('lis'));
                        el.onload = () => seen.push('on');
                    }),
                };
            })())"#,
        )
        .await;
        assert_eq!(got["onFirst"], serde_json::json!(["on", "lis"]), "{got}");
        assert_eq!(got["listenerFirst"], serde_json::json!(["lis", "on"]), "{got}");
    }

    /// A picture drawn on a canvas has to be the picture. The bytes reach JS as
    /// lossy text, so they never left Rust and `drawImage` stamped a synthesized
    /// pattern instead — a page that draws and reads back, as a challenge does
    /// with the beacon it sends, saw noise where a browser shows the image.
    #[tokio::test]
    async fn a_drawn_picture_reads_back_as_itself() {
        let _serial = serial().await;
        // A 2x1 PNG: one red pixel, one blue.
        const PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAIAAAABCAYAAAD0In+KAAAADklEQVR4nGP4z8AAQv8BD/kD/YURmXYAAAAASUVORK5CYII=";
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        // Hand the pixels over the way a fetched image does.
        let got = probe(
            &ctx,
            &format!(
                r#"__ptJSON.stringify((() => {{
                    if (typeof __pt_imageBytes !== 'function') return 'no rasterizer';
                    const size = __pt_imageBytes('https://example.com/p.png', "{PNG_B64}");
                    const c = document.createElement('canvas'); c.width = 2; c.height = 1;
                    const x = c.getContext('2d');
                    const im = document.createElement('img');
                    im.src = 'https://example.com/p.png';
                    x.drawImage(im, 0, 0);
                    return {{ size: size, row: Array.from(x.getImageData(0, 0, 2, 1).data) }};
                }})())"#
            ),
        )
        .await;
        // Without the `render` feature there is no rasterizer and nothing to test.
        if got.as_str() == Some("no rasterizer") {
            return;
        }
        assert_eq!(got["size"], 2 << 16 | 1, "image size: {got}");
        assert_eq!(
            got["row"],
            serde_json::json!([255, 0, 0, 255, 0, 0, 255, 255]),
            "pixels read back unchanged: {got}"
        );
    }

    /// `import()` had no answer at all: V8 asks the embedder and waits, and we
    /// never replied, so every dynamic import was rejected. A page built in
    /// chunks — nearly every page now — loaded a fraction of its own code.
    #[tokio::test]
    async fn a_page_can_import_a_chunk_of_itself() {
        let _serial = serial().await;
        let (url, hits) = chunked_module_server().await;
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig { workers: 1, max_live_contexts: 4, max_heap_mb: None },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&format!("{}/index.html", url.trim_end_matches('/')))
            .await
            .unwrap();
        // The import settles a turn later, like any promise.
        for _ in 0..40 {
            ctx.run_event_loop().await.unwrap();
            if probe(&ctx, "__ptJSON.stringify(globalThis.__r || '')").await != "" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let got = probe(&ctx, "__ptJSON.stringify(globalThis.__r || '(silence)')").await;
        assert_eq!(got.as_str(), Some("loaded: \u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}"), "{got}");
        // And a module both chunks import is fetched once, as in a browser:
        // one module map per realm, one address in it.
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the shared dependency must load once"
        );
    }

    /// A page whose entry imports two chunks, both of which import one shared
    /// module — the shape that shows whether the module map works.
    async fn chunked_module_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counted = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                let counted = counted.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 2048];
                    let Ok(n) = sock.read(&mut buf).await else { return };
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let (kind, body) = match path.as_str() {
                        "/index.html" => ("text/html", concat!(
                            "<html><body><script type=\"module\">",
                            "import('./a.js').then(m => import('./b.js').then(n => {",
                            "  globalThis.__r = 'loaded: ' + m.hi() + n.tail();",
                            "}), e => { globalThis.__r = 'rejected: ' + e.message; });",
                            "</script></body></html>").to_string()),
                        "/a.js" => ("text/javascript",
                            "import { word } from './shared.js';\nexport function hi() { return word; }".to_string()),
                        "/b.js" => ("text/javascript",
                            "import { word } from './shared.js';\nexport function tail() { return word ? '' : '?'; }".to_string()),
                        "/shared.js" => {
                            counted.fetch_add(1, Ordering::SeqCst);
                            ("text/javascript", "export const word = '\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}';".to_string())
                        }
                        _ => ("text/plain", String::new()),
                    };
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {kind}; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(body.as_bytes()).await;
                });
            }
        });
        (format!("http://{addr}"), hits)
    }

    /// The challenge measures the clock's resolution: five thousand readings in
    /// a row, keeping the smallest positive difference. Chrome answers
    /// 0.09999996423721313, not a clean tenth, because it keeps the timestamp to
    /// 2^-24 ms. Ours answered 0.09999999999999432 — the same measurement, a
    /// different machine.
    #[tokio::test]
    async fn the_clock_sits_on_the_lattice_a_browser_uses() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        let got = probe(
            &ctx,
            r#"__ptJSON.stringify((() => {
                let a = 1, b = 1, c;
                for (let d = 0; d < 5000; d++) {
                    const e = performance.now(), f = performance.now();
                    if (e < f) { c = f - e; if (c > a && c < b) b = c; else if (c < a) { b = a; a = c; } }
                }
                const t = performance.now();
                return { min: a, onLattice: Math.floor(t * 16777216) / 16777216 === t };
            })())"#,
        )
        .await;
        // Chrome 148, measured on the same machine.
        // It answers 1677721/2^24. The last bit depends on which tick is measured
        // (subtracting two lattice points rounds differently), so compare within a couple
        // of ulps and check separately that it is not an even 0.1, as ours was.
        let min = got["min"].as_f64().expect("number");
        let want = 1_677_721.0 / 16_777_216.0;
        // Tolerance is one lattice step: the difference of two neighbouring ticks
        // sometimes rounds to the next one.
        let step = 1.0 / 16_777_216.0;
        assert!(
            (min - want).abs() < 2.0 * step,
            "clock resolution: {min} vs {want}"
        );
        assert!(
            (min - 0.1_f64).abs() > 1e-9,
            "an even 0.1 means a clock counting from zero: {min}"
        );
        assert_eq!(got["onLattice"], true, "{got}");
    }

    /// A wrong call is an answer too, and the browser's is exact. The challenge
    /// calls `getImageData()` with no arguments at all and reads what happens;
    /// ours handed back an empty set of pixels where Chrome throws.
    #[tokio::test]
    async fn a_wrong_call_to_the_canvas_is_refused_as_a_browser_refuses_it() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        let got = probe(
            &ctx,
            r#"__ptJSON.stringify((() => {
                const say = (f) => { try { f(); return 'answered'; }
                                     catch (e) { return e.name + ': ' + e.message; } };
                const c = document.createElement('canvas'); c.width = 4; c.height = 4;
                const x = c.getContext('2d');
                return {
                    noArgs: say(() => x.getImageData()),
                    zeroWidth: say(() => x.getImageData(0, 0, 0, 4)),
                    drawNoArgs: say(() => x.drawImage()),
                    drawBad: say(() => x.drawImage({}, 0, 0)),
                    putNoArgs: say(() => x.putImageData()),
                    createZero: say(() => x.createImageData(0, 0)),
                    toBlobNoArgs: say(() => c.toBlob()),
                };
            })())"#,
        )
        .await;
        // Chrome 148, word for word.
        assert_eq!(got["noArgs"], "TypeError: Failed to execute 'getImageData' on 'CanvasRenderingContext2D': 4 arguments required, but only 0 present.", "{got}");
        assert_eq!(got["zeroWidth"], "IndexSizeError: Failed to execute 'getImageData' on 'CanvasRenderingContext2D': The source width is 0.", "{got}");
        assert_eq!(got["drawNoArgs"], "TypeError: Failed to execute 'drawImage' on 'CanvasRenderingContext2D': 3 arguments required, but only 0 present.", "{got}");
        assert!(got["drawBad"].as_str().unwrap_or("").starts_with("TypeError: Failed to execute 'drawImage'"), "{got}");
        assert_eq!(got["putNoArgs"], "TypeError: Failed to execute 'putImageData' on 'CanvasRenderingContext2D': 3 arguments required, but only 0 present.", "{got}");
        assert_eq!(got["createZero"], "IndexSizeError: Failed to execute 'createImageData' on 'CanvasRenderingContext2D': The source width is zero or not a number.", "{got}");
        assert_eq!(got["toBlobNoArgs"], "TypeError: Failed to execute 'toBlob' on 'HTMLCanvasElement': 1 argument required, but only 0 present.", "{got}");
    }

    /// An element that is not rendered answers `innerText` with its whole
    /// `textContent` — styles, scripts and all. Ours answered with nothing,
    /// which is a different thing entirely.
    #[tokio::test]
    async fn a_hidden_element_reads_back_everything_it_holds() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        let got = probe(
            &ctx,
            r#"__ptJSON.stringify((() => {
                const hidden = document.createElement('div');
                hidden.innerHTML = '<style>.z{color:red}</style><b>\u0442\u0435\u043a\u0441\u0442</b>';
                hidden.style.display = 'none';
                document.body.appendChild(hidden);
                const shown = document.createElement('div');
                shown.innerHTML = '<style>.z{color:red}</style><b>\u0442\u0435\u043a\u0441\u0442</b>';
                document.body.appendChild(shown);
                return { hidden: hidden.innerText, shown: shown.innerText };
            })())"#,
        )
        .await;
        // Chrome 148, exactly.
        assert_eq!(got["hidden"], ".z{color:red}\u{442}\u{435}\u{43a}\u{441}\u{442}", "{got}");
        assert_eq!(got["shown"], "\u{442}\u{435}\u{43a}\u{441}\u{442}", "style is not rendered: {got}");
    }

    /// A call made wrongly is answered exactly, and the answer names the method
    /// and the interface. Ours either did the wrong thing quietly — `<<<` found
    /// an element, `matches('###')` said yes — or reported its own internals
    /// ("Cannot read properties of undefined"), which says the method is a plain
    /// function and not the browser's.
    #[tokio::test]
    async fn a_wrong_call_is_refused_the_way_a_browser_refuses_it() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        let got = probe(
            &ctx,
            r#"__ptJSON.stringify((() => {
                const say = (f) => { try { f(); return 'answered'; }
                                     catch (e) { return e.name + ': ' + e.message; } };
                const el = document.createElement('div');
                return {
                    badSelector: say(() => document.querySelector('<<<')),
                    badMatches: say(() => el.matches('###')),
                    noSelector: say(() => document.querySelector()),
                    noAttr: say(() => el.setAttribute()),
                    selfChild: say(() => el.appendChild(el)),
                    notMine: say(() => document.body.removeChild(el)),
                    badPosition: say(() => el.insertAdjacentHTML('nosuchplace', 'x')),
                    noListener: say(() => el.addEventListener()),
                    badUrl: say(() => new URL('not a url')),
                    noItem: say(() => localStorage.setItem()),
                    goodSelector: say(() => document.querySelector('body')),
                };
            })())"#,
        )
        .await;
        // Chrome 148, word for word.
        assert_eq!(got["badSelector"], "SyntaxError: Failed to execute 'querySelector' on 'Document': '<<<' is not a valid selector.", "{got}");
        assert_eq!(got["badMatches"], "SyntaxError: Failed to execute 'matches' on 'Element': '###' is not a valid selector.", "{got}");
        assert_eq!(got["noSelector"], "TypeError: Failed to execute 'querySelector' on 'Document': 1 argument required, but only 0 present.", "{got}");
        assert_eq!(got["noAttr"], "TypeError: Failed to execute 'setAttribute' on 'Element': 2 arguments required, but only 0 present.", "{got}");
        assert_eq!(got["selfChild"], "HierarchyRequestError: Failed to execute 'appendChild' on 'Node': The new child element contains the parent.", "{got}");
        assert_eq!(got["notMine"], "NotFoundError: Failed to execute 'removeChild' on 'Node': The node to be removed is not a child of this node.", "{got}");
        assert_eq!(got["noListener"], "TypeError: Failed to execute 'addEventListener' on 'EventTarget': 2 arguments required, but only 0 present.", "{got}");
        assert_eq!(got["badUrl"], "TypeError: Failed to construct 'URL': Invalid URL", "{got}");
        assert_eq!(got["noItem"], "TypeError: Failed to execute 'setItem' on 'Storage': 2 arguments required, but only 0 present.", "{got}");
        assert!(got["badPosition"].as_str().unwrap_or("").starts_with("SyntaxError: Failed to execute 'insertAdjacentHTML'"), "{got}");
        // And a call made properly is untouched.
        assert_eq!(got["goodSelector"], "answered", "{got}");
    }

    /// The challenge times exactly one call: `flush()` on an origin-private
    /// file. In a browser that is a write to the disk and a wait for it —
    /// about four milliseconds — and an empty function costs nothing at all,
    /// which no file system does.
    #[tokio::test]
    async fn flushing_a_file_costs_what_a_file_costs() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        ctx.evaluate(
            r#"(() => {
                const src = "onmessage=function(e){ eval(e.data) }";
                const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
                globalThis.__got = null;
                w.onmessage = (e) => { globalThis.__got = e.data; };
                w.postMessage("~function(){navigator.storage.getDirectory().then(function(a){var s={};s['create']=true;return a.getFileHandle('\u043f\u0440\u043e\u0431a',s)}).then(function(h){return h.createSyncAccessHandle()}).then(function(h){h.write(new Uint8Array(64),{at:0});var t=performance.now();h.flush();var d=performance.now()-t;h.close();postMessage({took:d})}).catch(function(e){postMessage({err:String(e)})})}()");
                return 1;
            })()"#,
        )
        .await
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
        while std::time::Instant::now() < deadline {
            ctx.run_event_loop().await.unwrap();
            if probe(&ctx, "__ptJSON.stringify(globalThis.__got !== null)").await == true {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let got = probe(&ctx, "__ptJSON.stringify(globalThis.__got)").await;
        // Built without the rasterizer there is no file behind the handle, and
        // nothing here to measure.
        let backed = probe(&ctx, "__ptJSON.stringify(typeof __pt_fsOpen === 'function')").await;
        if backed != true {
            return;
        }
        let took = got["took"].as_f64().unwrap_or(0.0);
        assert!(took > 0.2, "a disk write is never instant: {got}");
        assert!(took < 500.0, "nor endless: {got}");
    }

    /// A list sits directly on its own interface, with nothing in between.
    /// Ours kept an empty object of its own in the chain — the leftover of
    /// moving the members onto the interface — so every collection in the engine
    /// was one level deeper than a browser's, which a walk up the prototypes
    /// reads at once. And a shadow root's `styleSheets` was a plain Array.
    #[tokio::test]
    async fn a_collection_sits_on_its_own_interface() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body><div class='a b'></div></body></html>")
            .await
            .unwrap();
        let got = probe(
            &ctx,
            r#"__ptJSON.stringify((() => {
                const el = document.querySelector('div');
                const sr = el.attachShadow({ mode: 'open' });
                const on = (o, name) => Object.getPrototypeOf(o) === globalThis[name].prototype;
                return {
                    nodeList: on(document.querySelectorAll('div'), 'NodeList'),
                    live: on(document.body.childNodes, 'NodeList'),
                    collection: on(document.getElementsByTagName('div'), 'HTMLCollection'),
                    tokens: on(el.classList, 'DOMTokenList'),
                    attrs: on(el.attributes, 'NamedNodeMap'),
                    sheets: on(document.styleSheets, 'StyleSheetList'),
                    shadowSheets: on(sr.styleSheets, 'StyleSheetList'),
                    shadowNames: Object.getOwnPropertyNames(ShadowRoot.prototype).length,
                    stillWorks: [document.querySelectorAll('div').length, el.classList.contains('b')],
                };
            })())"#,
        )
        .await;
        for k in [
            "nodeList", "live", "collection", "tokens", "attrs", "sheets", "shadowSheets",
        ] {
            assert_eq!(got[k], true, "{k} must live on its own interface: {got}");
        }
        // Chrome 148 and 151 alike: 23 names, and none of them borrowed from
        // Element — a shadow root's chain never reaches it.
        assert_eq!(got["shadowNames"], 23, "{got}");
        assert_eq!(got["stillWorks"], serde_json::json!([1, true]), "{got}");
    }

    /// A fresh profile has been asked for nothing, so a browser answers `prompt`
    /// to almost every permission and `default` to `Notification.permission`.
    /// Ours handed out `granted` unasked and had no `permission` at all.
    #[tokio::test]
    async fn nothing_is_granted_that_was_never_asked() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        let got = probe(
            &ctx,
            r#"__ptJSON.stringify((() => {
                const e = new Event('x');
                return {
                    notification: Notification.permission,
                    composed: e.composed,
                    hevOrder: 'later',
                };
            })())"#,
        )
        .await;
        assert_eq!(got["notification"], "default", "{got}");
        // `composed` is a plain field of an event, false rather than absent.
        assert_eq!(got["composed"], false, "{got}");

        let perms = probe(
            &ctx,
            r#"__ptJSON.stringify(['camera', 'midi', 'geolocation', 'notifications']
                .map((n) => navigator.permissions.query({ name: n }).then((s) => s.state)))"#,
        )
        .await;
        // The promises are not awaited here; the states are checked through the
        // engine instead, one at a time.
        assert!(perms.is_array(), "{perms}");
        let one = probe(
            &ctx,
            r#"(() => { globalThis.__s = null;
                navigator.permissions.query({ name: 'camera' }).then((s) => { globalThis.__s = s.state; });
                return '""'; })()"#,
        )
        .await;
        let _ = one;
        ctx.run_event_loop().await.unwrap();
        let state = probe(&ctx, "__ptJSON.stringify(globalThis.__s)").await;
        assert_eq!(state, "prompt", "camera was never granted: {state}");
    }

    #[test]
    fn an_image_states_its_size_in_its_own_header() {
        // A one-pixel PNG, GIF and JPEG: the three a page is most likely to meet.
        let png = [
            0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, b'I', b'H', b'D', b'R',
            0, 0, 1, 0x10, 0, 0, 0, 0x5c,
        ];
        assert_eq!(image_size(&png), Some((272, 92)));
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[0x40, 0x01, 0x20, 0x00]);
        assert_eq!(image_size(&gif), Some((320, 32)));
        let jpeg = [
            0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00,
            0x5c, 0x01, 0x10, 0x03,
        ];
        assert_eq!(image_size(&jpeg), Some((272, 92)));
        // Not an image, and a truncated one: no answer rather than a wrong one.
        assert_eq!(image_size(b"<html>"), None);
        assert_eq!(image_size(&png[..12]), None);
    }

    #[tokio::test]
    async fn a_canvas_shown_a_foreign_image_stops_being_readable() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/app/", "<html><body></body></html>")
            .await
            .unwrap();
        // Nothing foreign has been drawn: the pixels are ours to read.
        let clean = probe(
            &ctx,
            r#"__ptJSON.stringify((() => {
                const c = document.createElement('canvas');
                const x = c.getContext('2d');
                x.fillStyle = '#f00'; x.fillRect(0, 0, 4, 4);
                try { x.getImageData(0, 0, 1, 1); return 'readable'; }
                catch (e) { return 'threw: ' + e.message; }
            })())"#,
        )
        .await;
        assert_eq!(clean.as_str(), Some("readable"));

        // An image from another origin, drawn without permission, costs the
        // canvas its readability — both ways out of it.
        let tainted = probe(
            &ctx,
            r#"__ptJSON.stringify((() => {
                const c = document.createElement('canvas');
                const x = c.getContext('2d');
                const im = document.createElement('img');
                im.src = 'https://cdn.example.org/logo.png';
                x.drawImage(im, 0, 0);
                const out = [];
                try { x.getImageData(0, 0, 1, 1); out.push('data returned'); }
                catch (e) { out.push(e.name + ': ' + e.message); }
                try { c.toDataURL(); out.push('image returned'); }
                catch (e) { out.push(e.name); }
                return out;
            })())"#,
        )
        .await;
        let out = tainted.as_array().expect("array");
        assert_eq!(
            out[0].as_str(),
            Some("SecurityError: Failed to execute 'getImageData' on 'CanvasRenderingContext2D': The canvas has been tainted by cross-origin data.")
        );
        assert_eq!(out[1].as_str(), Some("SecurityError"));

        // A same-origin image is no threat to it.
        let same = probe(
            &ctx,
            r#"__ptJSON.stringify((() => {
                const c = document.createElement('canvas');
                const x = c.getContext('2d');
                const im = document.createElement('img');
                im.src = 'https://example.com/app/logo.png';
                x.drawImage(im, 0, 0);
                try { x.getImageData(0, 0, 1, 1); return 'readable'; }
                catch (e) { return 'threw: ' + e.message; }
            })())"#,
        )
        .await;
        assert_eq!(same.as_str(), Some("readable"));
    }

    /// The challenge's first question to its worker: navigator fields, answered
    /// with one object message. Chrome answers at once; ours got lost while a timer
    /// from the same script arrived fine. Runs the exact script the challenge sends.
    #[tokio::test]
    async fn a_worker_answers_the_first_question_about_itself() {
        let _serial = serial().await;
        let engine = engine(4, 6);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/app/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(
            r#"(() => {
            const src = "onmessage=function(e){ e.isTrusted && '' === e.origin && null === e.source && eval(e.data) }";
            const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
            globalThis.__got = [];
            w.onmessage = (e) => { globalThis.__got.push(e.data); };
            w.postMessage("var n=self.navigator;postMessage({ KzOg4:n.platform,TzEx3:n.languages,Bwko4:n.hardwareConcurrency,ycmYm0:n.deviceMemory,EhUAu5:n.userAgent});setTimeout(function(){postMessage({ dnjTe7:1})},200)");
            return 1;
        })()"#,
        )
        .await
        .unwrap();
        // The worker's timer is longer than the near threshold, so keep pumping until it
        // fires, as a live page would.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            ctx.run_event_loop().await.unwrap();
            let n = probe(&ctx, "__ptJSON.stringify((globalThis.__got || []).length)").await;
            if n.as_u64().unwrap_or(0) >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let got = probe(&ctx, "__ptJSON.stringify(globalThis.__got || [])").await;
        let list = got.as_array().cloned().unwrap_or_default();
        assert!(
            list.len() >= 2,
            "both worker messages must arrive, the reply and the timer: {got}"
        );
        let first = &list[0];
        assert!(
            first["KzOg4"].as_str().unwrap_or("").starts_with("Linux"),
            "platform in the reply: {got}"
        );
        assert!(first["TzEx3"].is_array(), "languages as an array: {got}");
        assert!(first["Bwko4"].as_u64().unwrap_or(0) > 0, "cores: {got}");
        assert!(
            first["EhUAu5"].as_str().unwrap_or("").contains("Chrome/"),
            "user-agent: {got}"
        );
        assert_eq!(list[1]["dnjTe7"], 1, "and the timer after it: {got}");
    }

    /// A drawing context is an interface, not a bag of properties. In Chrome the
    /// context has no own properties: all 73 2D names and 442 WebGL names live on the
    /// prototype, which is what fingerprint collectors walk.
    #[tokio::test]
    async fn a_drawing_context_is_an_interface_not_a_bag_of_properties() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(
            &ctx,
            r#"(() => {
                const a = document.createElement('canvas');
                a.width = 60; a.height = 30;
                const x = a.getContext('2d');
                x.fillStyle = '#f60'; x.fillRect(0, 0, 40, 20);
                // Second context: the prototype accessors already exist, and building the
                // second implementation must not route into them.
                const b = document.createElement('canvas');
                const y = b.getContext('2d');
                y.fillStyle = '#0af'; y.fillRect(0, 0, 5, 5);
                const gl = document.createElement('canvas').getContext('webgl');
                const px = x.getImageData(1, 1, 1, 1).data;
                return __ptJSON.stringify({
                  own2d: Object.getOwnPropertyNames(x).length,
                  ownSecond: Object.getOwnPropertyNames(y).length,
                  proto2d: Object.getOwnPropertyNames(CanvasRenderingContext2D.prototype).length,
                  fillRect: typeof CanvasRenderingContext2D.prototype.fillRect,
                  isCtx: x instanceof CanvasRenderingContext2D,
                  canvasBack: x.canvas === a,
                  style: x.fillStyle, otherStyle: y.fillStyle,
                  painted: [px[0], px[1], px[2], px[3]],
                  differ: a.toDataURL() !== b.toDataURL(),
                  ownGl: Object.getOwnPropertyNames(gl).length,
                  protoGl: Object.getOwnPropertyNames(WebGLRenderingContext.prototype).length,
                  constOnProto: WebGLRenderingContext.prototype.DEPTH_BUFFER_BIT,
                  vendor: gl.getParameter(gl.VENDOR),
                })
              })()"#,
        )
        .await;

        // From Chrome 148: 73 names plus `constructor`, 436+6 plus it.
        assert_eq!(out["own2d"], 0, "{out}");
        assert_eq!(out["ownSecond"], 0, "{out}");
        assert_eq!(out["proto2d"], 74, "{out}");
        assert_eq!(out["fillRect"], "function", "{out}");
        assert_eq!(out["isCtx"], true, "{out}");
        assert_eq!(out["canvasBack"], true, "{out}");
        // Drawing still works, and the two canvases stay distinct.
        assert_eq!(out["style"], "#ff6600", "{out}");
        assert_eq!(out["otherStyle"], "#00aaff", "{out}");
        assert_eq!(out["painted"], serde_json::json!([255, 102, 0, 255]), "{out}");
        assert_eq!(out["differ"], true, "{out}");
        assert_eq!(out["ownGl"], 0, "{out}");
        assert_eq!(out["protoGl"], 443, "{out}");
        assert_eq!(out["constOnProto"], 256, "constants on the prototype too: {out}");
        assert_eq!(out["vendor"], "WebKit", "{out}");
    }

    /// An object the page builds names itself: 31 of 36 checked answered `[object Object]`,
    /// and `Object.prototype.toString.call(new Blob([]))` is in every check suite.
    /// Values from Chrome 148.
    #[tokio::test]
    async fn an_object_the_page_builds_names_itself() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(
            &ctx,
            r#"(() => {
                const tag = (v) => Object.prototype.toString.call(v);
                const blob = new Blob(['x'], { type: 'text/plain' });
                return __ptJSON.stringify({
                  blob: tag(blob),
                  blobOwn: Object.getOwnPropertyNames(blob).length,
                  blobSize: blob.size,
                  blobType: blob.type,
                  headers: tag(new Headers()),
                  form: tag(new FormData()),
                  params: tag(new URLSearchParams('a=1')),
                  url: tag(new URL('https://example.com/')),
                  response: tag(new Response('x')),
                  channel: tag(new MessageChannel()),
                  mql: tag(matchMedia('(min-width: 1px)')),
                  range: tag(document.createRange()),
                  audio: tag(new Audio()),
                  decoder: tag(new TextDecoder()),
                })
              })()"#,
        )
        .await;

        assert_eq!(out["blob"], "[object Blob]", "{out}");
        // A real Blob has no own properties: size and type come from the prototype and
        // the parts sit under a non-enumerable symbol.
        assert_eq!(out["blobOwn"], 0, "{out}");
        assert_eq!(out["blobSize"], 1, "{out}");
        assert_eq!(out["blobType"], "text/plain", "{out}");
        assert_eq!(out["headers"], "[object Headers]", "{out}");
        assert_eq!(out["form"], "[object FormData]", "{out}");
        assert_eq!(out["params"], "[object URLSearchParams]", "{out}");
        assert_eq!(out["url"], "[object URL]", "{out}");
        assert_eq!(out["response"], "[object Response]", "{out}");
        assert_eq!(out["channel"], "[object MessageChannel]", "{out}");
        assert_eq!(out["mql"], "[object MediaQueryList]", "{out}");
        assert_eq!(out["range"], "[object Range]", "{out}");
        // `Audio` is a factory, not an interface: it returns an element.
        assert_eq!(out["audio"], "[object HTMLAudioElement]", "{out}");
        assert_eq!(out["decoder"], "[object TextDecoder]", "{out}");
    }

    /// Storage must store. Ours returned `null` for a fresh write with `length` 0: the
    /// methods on the prototype read data via `this`, which is the page's Proxy, while
    /// the map lived on its target. The Turnstile widget writes `cf.turnstile.u` and
    /// reads it back.
    #[tokio::test]
    async fn what_the_page_stores_it_can_read_back() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(
            &ctx,
            r#"(() => {
                localStorage.setItem('cf.turnstile.u', 'abc123');
                localStorage.direct = 'via property';
                sessionStorage.setItem('other', 'x');
                return __ptJSON.stringify({
                  back: localStorage.getItem('cf.turnstile.u'),
                  viaProp: localStorage['cf.turnstile.u'],
                  fromProperty: localStorage.getItem('direct'),
                  len: localStorage.length,
                  key0: localStorage.key(0),
                  keys: Object.keys(localStorage),
                  separate: sessionStorage.getItem('cf.turnstile.u'),
                  gone: (localStorage.removeItem('direct'), localStorage.getItem('direct')),
                })
              })()"#,
        )
        .await;

        assert_eq!(out["back"], "abc123", "{out}");
        assert_eq!(out["viaProp"], "abc123", "a key reads as a property too: {out}");
        assert_eq!(out["fromProperty"], "via property", "and writes as a property: {out}");
        assert_eq!(out["len"], 2, "{out}");
        assert_eq!(out["key0"], "cf.turnstile.u", "{out}");
        assert_eq!(
            out["keys"],
            serde_json::json!(["cf.turnstile.u", "direct"]),
            "keys are own properties: {out}"
        );
        // Two storages, two separate buckets.
        assert_eq!(out["separate"], Value::Null, "{out}");
        assert_eq!(out["gone"], Value::Null, "{out}");
    }

    /// `IntersectionObserver` delivers the first observation by itself once observing
    /// starts. The real implementation lost to an empty name-table stub (`X = X || …`
    /// with the name already taken), and code awaiting the callback waited forever.
    #[tokio::test]
    async fn watching_an_element_reports_it_straight_away() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body><div id=t>x</div></body></html>")
            .await
            .unwrap();

        ctx.evaluate(
            r#"(() => {
                globalThis.__seen = [];
                const io = new IntersectionObserver((entries) => {
                  for (const e of entries) globalThis.__seen.push([e.target.id, e.isIntersecting]);
                });
                io.observe(document.getElementById('t'));
                return 1;
              })()"#,
        )
        .await
        .unwrap();
        ctx.run_event_loop().await.unwrap();

        let out = probe(
            &ctx,
            "__ptJSON.stringify({seen: globalThis.__seen, \
               tag: Object.prototype.toString.call(new IntersectionObserver(() => {}))})",
        )
        .await;
        assert_eq!(
            out["seen"],
            serde_json::json!([["t", true]]),
            "the observation arrives by itself: {out}"
        );
        assert_eq!(out["tag"], "[object IntersectionObserver]", "{out}");
    }

    /// A platform object names itself. Name-table stubs were empty objects answering
    /// `[object Object]` where Chrome says `[object VisualViewport]` or `[object BarProp]`,
    /// and collectors call `Object.prototype.toString` across the window first thing.
    /// Values from Chrome 148.
    #[tokio::test]
    async fn a_platform_object_says_what_it_is() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let tags = probe(
            &ctx,
            r#"__ptJSON.stringify({
                bar: Object.prototype.toString.call(locationbar),
                viewport: Object.prototype.toString.call(visualViewport),
                elements: Object.prototype.toString.call(customElements),
                idb: Object.prototype.toString.call(indexedDB),
                intl: Object.prototype.toString.call(Intl),
                css: Object.prototype.toString.call(CSS),
                channel: Object.prototype.toString.call(new RTCPeerConnection().createDataChannel('x')),
                sameBar: Object.getPrototypeOf(locationbar) === Object.getPrototypeOf(toolbar),
                isBar: locationbar instanceof BarProp,
                visible: locationbar.visible,
                order: Object.getOwnPropertyNames(BarProp.prototype).join(','),
                width: visualViewport.width === innerWidth,
                sameNavigator: clientInformation === navigator,
            })"#,
        )
        .await;

        assert_eq!(tags["bar"], "[object BarProp]", "{tags}");
        assert_eq!(tags["viewport"], "[object VisualViewport]", "{tags}");
        assert_eq!(tags["elements"], "[object CustomElementRegistry]", "{tags}");
        assert_eq!(tags["idb"], "[object IDBFactory]", "{tags}");
        assert_eq!(tags["intl"], "[object Intl]", "{tags}");
        assert_eq!(tags["css"], "[object CSS]", "{tags}");
        assert_eq!(tags["channel"], "[object RTCDataChannel]", "{tags}");
        // The six window bars share one interface, the same as in `instanceof`.
        assert_eq!(tags["sameBar"], true, "{tags}");
        assert_eq!(tags["isBar"], true, "{tags}");
        assert_eq!(tags["visible"], true, "{tags}");
        // Prototype name order is read too: members, then `constructor`.
        assert_eq!(tags["order"], "visible,constructor", "{tags}");
        assert_eq!(tags["width"], true, "the visual viewport is the window: {tags}");
        assert_eq!(tags["sameNavigator"], true, "one value under two names: {tags}");
    }

    /// Every Vite build ships twice: a module half and a `nomodule` fallback. A module
    /// browser takes the first and skips the second; we ran both, starting the app twice,
    /// which on 2captcha ended in an endless reload.
    #[tokio::test]
    async fn a_nomodule_script_does_not_run_and_the_page_says_it_has_modules() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();
        let html = r#"<!DOCTYPE html><html><body>
              <script>globalThis.ran = [];</script>
              <script nomodule>globalThis.ran.push('parsed-fallback');</script>
              <script>
                globalThis.ran.push('classic');
                var s = document.createElement('script');
                s.noModule = true;
                s.text = "globalThis.ran.push('inserted-fallback')";
                document.body.appendChild(s);
                globalThis.detect = ('noModule' in document.createElement('script'))
                  + '/' + s.hasAttribute('nomodule');
              </script>
            </body></html>"#;

        ctx.load_html("https://example.com/", html).await.unwrap();

        assert_eq!(
            ctx.evaluate("globalThis.ran.join(',')").await.unwrap(),
            Value::String("classic".into())
        );
        // `'noModule' in script` is how Vite decides which half to serve.
        assert_eq!(
            ctx.evaluate("globalThis.detect").await.unwrap(),
            Value::String("true/true".into())
        );
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
        // on `EventTarget.prototype`. The own set is now Chrome's exactly;
        // `status` was the last name missing from it. It used to be over 1100,
        // because every interface object was enumerable here and none of them is
        // in a browser.
        assert!(
            (230..=250).contains(&out["winGraph"].as_u64().unwrap()),
            "window graph: {} (Chrome: 243)",
            out["winGraph"]
        );
        assert_eq!(
            out["winKeys"], 237,
            "own enumerable names on the window — Chrome's set, exactly"
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
            // A browser event has one own property too: `isTrusted` ([LegacyUnforgeable]).
            if key == "evtOwn" {
                assert_eq!(leaked, &vec![serde_json::json!("isTrusted")], "evtOwn: {leaked:?}");
                continue;
            }
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
              // In Chrome navigationStart is whole milliseconds, timeOrigin fractional.
              navigationStartAtOrigin: Number.isInteger(performance.timing.navigationStart)
                && Math.abs(performance.timing.navigationStart - performance.timeOrigin) < 1,
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

    /// Text wraps into lines and a scroller knows its content. A 120 px paragraph
    /// reported 18 px height instead of 72, `Range.getClientRects()` was empty, and an
    /// `overflow: auto` box had no room for the scrollbar with `scrollWidth` equal to
    /// `clientWidth`. Numbers checked against Chrome 151. Line widths are real only with
    /// the `render` feature; without it wrapping falls on different words.
    #[cfg(feature = "render")]
    #[tokio::test]
    async fn text_wraps_and_a_scroll_box_knows_its_content() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            "<html><head><style>body{margin:8px;font:16px Arial}\
             #sc{width:100px;height:40px;overflow:auto}#sc div{width:300px;height:200px}\
             #wrap{width:120px}</style></head><body>\
             <div id=\"sc\"><div>x</div></div>\
             <p id=\"wrap\">one two three four five six seven eight nine ten</p>\
             </body></html>",
        )
        .await
        .unwrap();

        let p = probe(
            &ctx,
            r#"(() => {
              const q = (v) => Math.round(v * 1e4) / 1e4;
              const sc = document.getElementById('sc');
              const w = document.getElementById('wrap');
              const r = document.createRange();
              r.selectNodeContents(w.firstChild);
              return __ptJSON.stringify({
                scroll: [sc.clientWidth, sc.clientHeight, sc.scrollWidth, sc.scrollHeight],
                wrap: [q(w.getBoundingClientRect().width), q(w.getBoundingClientRect().height)],
                rects: [...r.getClientRects()].map((b) => [q(b.x), q(b.y), q(b.width), q(b.height)]),
                tag: Object.prototype.toString.call(r.getClientRects()),
                stack: document.elementsFromPoint(10, 70).map((n) => n.localName),
              });
            })()"#,
        )
        .await;

        // The scrollbar takes 15 px; content is 300x200.
        assert_eq!(p["scroll"], serde_json::json!([85, 25, 300, 200]));
        // Four lines of 18 px.
        assert_eq!(p["wrap"], serde_json::json!([120, 72]));
        assert_eq!(
            p["rects"],
            serde_json::json!([
                [8, 64, 96.9531, 17],
                [8, 82, 80.9219, 17],
                [8, 100, 116.5313, 17],
                [8, 118, 22.25, 17]
            ]),
            "one rectangle per line, exactly where Chrome puts them"
        );
        assert_eq!(p["tag"], "[object DOMRectList]");
        assert_eq!(
            p["stack"],
            serde_json::json!(["p", "body", "html"]),
            "the whole stack under the point, not just the topmost"
        );
    }

    /// The common audio fingerprint: a 10 kHz triangle through a compressor with default
    /// fields, sum of absolute samples 4500..5000. Chrome 151 gives 124.0435; we had 11.87
    /// (oscillator twice too loud and not band-limited, compressor ignoring the knee,
    /// the envelope detector and makeup gain).
    #[tokio::test]
    async fn the_audio_fingerprint_is_the_number_a_browser_produces() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();

        let p = probe(
            &ctx,
            r#"(() => {
              const oc = new OfflineAudioContext(1, 44100, 44100);
              const osc = oc.createOscillator();
              osc.type = 'triangle'; osc.frequency.value = 10000;
              const comp = oc.createDynamicsCompressor();
              comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
              comp.attack.value = 0; comp.release.value = 0.25;
              osc.connect(comp); comp.connect(oc.destination); osc.start(0);
              let out = null;
              oc.startRendering().then((b) => { out = b; });
              // Our rendering is synchronous but the promise resolves only after a microtask,
              // so take the buffer directly too.
              const b = out || oc.__ptRender(1, 44100);
              const d = b.getChannelData(0);
              let sum = 0;
              for (let i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
              const ac = new AudioContext();
              return __ptJSON.stringify({
                sum,
                joined: Array.from(d).join('|').length,
                mid: Array.from(d.slice(4500, 4504)),
                rate: ac.sampleRate,
                baseLatency: ac.baseLatency,
                state: ac.state,
                nyquist: [osc.frequency.minValue, osc.frequency.maxValue],
                outputs: ac.destination.numberOfOutputs,
              });
            })()"#,
        )
        .await;

        let sum = p["sum"].as_f64().expect("the sum is a number");
        // Bit-exact on the kind of machine the numbers were taken from: Chrome 151 on
        // x86_64 Linux. The compressor calls the host's libm on purpose, as Chrome does,
        // so another libm (aarch64 glibc gives 124.04347546336066, and so does a Pi)
        // lands an ulp off here and there, exactly as Chrome on that machine would.
        let exact = cfg!(all(target_os = "linux", target_arch = "x86_64"));
        let tolerance = if exact { 1e-12 } else { 1e-6 };
        assert!(
            (sum - 124.04347527516074).abs() < tolerance,
            "sum of abs {sum}, Chrome 151 has 124.04347527516074"
        );
        // The joined length reads every one of the 44100 samples' decimal
        // digits. The compressor calls the machine's libm for log10f/powf —
        // on purpose (see crates/pool/src/compressor.rs): nokk matches the
        // Chrome of the machine it runs on. On anything but the Linux box the
        // constants were recorded on, a few samples land one ulp off and spell
        // one character longer, so that exact length holds on Linux only.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(p["joined"], 882861, "joined samples length: {p}");
        let mid: Vec<f64> = p["mid"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_f64()).collect())
            .unwrap_or_default();
        let chrome = [-0.10808052122592926, -0.3909117579460144, -0.005692707374691963, 0.3892313539981842];
        assert_eq!(mid.len(), 4, "four samples: {p}");
        for (got, want) in mid.iter().zip(chrome) {
            assert!((got - want).abs() < tolerance, "samples bit for bit on x86_64 Linux: {p}");
        }
        // Live context: card rate, buffer latency, suspended until a gesture.
        assert_eq!(p["rate"], 48000);
        assert!((p["baseLatency"].as_f64().unwrap_or(0.0) - 512.0 / 48000.0).abs() < 1e-9);
        assert_eq!(p["state"], "suspended");
        assert_eq!(p["outputs"], 0, "the destination has no output");
        assert_eq!(
            p["nyquist"],
            serde_json::json!([-22050, 22050]),
            "an oscillator cannot be asked for more than half its context's sample rate"
        );
    }

    /// `drawImage` accepts every source a browser does. It rejected `OffscreenCanvas`
    /// and `ImageBitmap` (while its own error text listed them) and stamped a source
    /// canvas instead of copying pixels; Cloudflare's collector draws its own
    /// `OffscreenCanvas` this way. Real pixels only with the `render` feature.
    #[cfg(feature = "render")]
    #[tokio::test]
    async fn draw_image_takes_every_source_a_browser_takes() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();

        let p = probe(
            &ctx,
            r#"(() => {
              const px = (x, c, i, j) => Array.from(x.getImageData(i, j, 1, 1).data).join(',');
              const off = new OffscreenCanvas(16, 16);
              const oc = off.getContext('2d');
              oc.fillStyle = '#f00'; oc.fillRect(0, 0, 16, 16);
              const el = document.createElement('canvas');
              el.width = 8; el.height = 8;
              const ec = el.getContext('2d');
              ec.fillStyle = '#00f'; ec.fillRect(0, 0, 8, 8);
              const c = document.createElement('canvas');
              c.width = 48; c.height = 48;
              const x = c.getContext('2d');
              const out = { threw: [] };
              const draw = (what, src, dx, dy) => {
                try { x.drawImage(src, dx, dy); } catch (e) { out.threw.push(what + ': ' + e.name); }
              };
              draw('offscreen', off, 0, 0);
              draw('bitmap', off.transferToImageBitmap(), 16, 16);
              draw('canvas', el, 0, 32);
              out.offscreen = px(x, 0, 4, 4);
              out.bitmap = px(x, 0, 20, 20);
              out.canvas = px(x, 0, 2, 34);
              out.bitmapIsBitmap = Object.prototype.toString.call(off.transferToImageBitmap());
              return __ptJSON.stringify(out);
            })()"#,
        )
        .await;

        assert_eq!(
            p["threw"],
            serde_json::json!([]),
            "a source a browser accepts was refused"
        );
        assert_eq!(p["offscreen"], "255,0,0,255", "OffscreenCanvas pixels did not arrive");
        assert_eq!(p["bitmap"], "255,0,0,255", "ImageBitmap pixels did not arrive");
        assert_eq!(p["canvas"], "0,0,255,255", "canvas pixels did not arrive");
        assert_eq!(p["bitmapIsBitmap"], "[object ImageBitmap]");
    }

    /// `performance.memory` is a reading, not three constants: a page that allocates and
    /// rereads `usedJSHeapSize` sees it grow in a browser. The limit comes from physical
    /// memory via the same V8 function Chrome uses: 4 395 630 592 on a 16 GB machine.
    #[tokio::test]
    async fn the_heap_readings_move_when_the_page_allocates() {
        let _serial = serial().await;
        let engine = engine(2, 4);
        let ctx = engine.new_context().await.unwrap();

        let p = probe(
            &ctx,
            r#"(() => {
              const m = performance.memory;
              const before = m.usedJSHeapSize;
              const junk = [];
              // A million retained objects: a bootstrap GC mid-loop frees tens of MB, and a
              // smaller growth did not outweigh it.
              for (let i = 0; i < 1000000; i++) junk.push({ x: i, s: 'abc' + i });
              // Memory readings refresh at most every 50 ms, as in Chrome: on a fast machine the
              // loop fits in that window and an immediate reread returns the old value.
              const t0 = Date.now();
              while (Date.now() - t0 < 60) {}
              const after = m.usedJSHeapSize;
              return __ptJSON.stringify({
                before, after, total: m.totalJSHeapSize, limit: m.jsHeapSizeLimit,
                kept: junk.length,
                own: Object.getOwnPropertyNames(m).length,
                deviceMemory: navigator.deviceMemory,
              });
            })()"#,
        )
        .await;

        let before = p["before"].as_f64().expect("usedJSHeapSize is a number");
        let after = p["after"].as_f64().expect("usedJSHeapSize is a number");
        assert!(
            after > before,
            "usedJSHeapSize did not move after allocating: {before} → {after}"
        );
        let limit = p["limit"].as_f64().expect("jsHeapSizeLimit is a number");
        assert!(
            limit > after && limit > 1.0e9,
            "jsHeapSizeLimit is not a plausible Chrome limit: {limit}"
        );
        assert!(
            p["total"].as_f64().unwrap_or(0.0) >= after,
            "totalJSHeapSize is below what is in use"
        );
        // As with every object we expose, state lives on the prototype.
        assert_eq!(p["own"], 0, "MemoryInfo exposes own properties");
        // Chrome derives it from physical memory, rounded to a power of two; 8 is no longer the cap.
        let dm = p["deviceMemory"].as_u64().expect("deviceMemory is a number");
        assert!(
            dm.is_power_of_two() && (1..=64).contains(&dm),
            "deviceMemory is not a plausible Chrome value: {dm}"
        );
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
    async fn intl_answers_from_the_embedded_icu_data() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        // The binary carries Chrome's ICU data: no file next to it, and still
        // Chrome's answers. Without the data these came from the stub: "1234.5", "other".
        assert_eq!(
            ctx.evaluate(
                "new Intl.NumberFormat('de-DE', { style: 'currency', currency: 'EUR' }).format(1234.5) \
                 + ' | ' + new Intl.PluralRules('ru').select(2)"
            )
            .await
            .unwrap(),
            Value::String("1.234,50\u{a0}€ | few".into())
        );
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
    async fn another_frames_tostring_reads_engine_functions_as_native() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        // The registry of native functions was per window: an iframe's
        // `Function.prototype.toString` printed the parent's wrapper source.
        let v = ctx
            .evaluate(
                r#"(() => {
                    const f = document.createElement('iframe');
                    document.body.appendChild(f);
                    const W = f.contentWindow;
                    const isNat = s => /\{\s*\[native code\]\s*\}/.test(s);
                    const get = Object.getOwnPropertyDescriptor(Node.prototype, 'nodeType').get;
                    function pageFn() { return 1; }
                    return String(
                        isNat(W.Function.prototype.toString.call(document.querySelector)) &&
                        isNat(W.Function.prototype.toString.call(get)) &&
                        isNat(W.Function.prototype.toString.call(HTMLElement)) &&
                        isNat(Function.prototype.toString.call(W.document.querySelector)) &&
                        !isNat(W.Function.prototype.toString.call(pageFn)) &&
                        !isNat(String(W.eval('(function y() {})')))
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
        // Date's local time must be the one Intl reports for its own zone, in
        // summer and in winter, whatever zone the host runs in.
        let v = ctx
            .evaluate(
                r#"(() => {
                    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
                    const hour = (d) => Number(new Intl.DateTimeFormat('en-US',
                        { hour: 'numeric', hourCycle: 'h23', timeZone: tz }).format(d));
                    const jul = new Date('2025-07-15T16:00:00Z');
                    const jan = new Date('2025-01-15T16:00:00Z');
                    return String(typeof tz === 'string' && tz.length > 0 &&
                        jul.getHours() === hour(jul) && jan.getHours() === hour(jan));
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

    // The SVG text bbox is a separate measuring path, also fingerprinted. Numbers from
    // Chrome 151 on this machine: the box unites the ink box with the layout box (the
    // farther one to the right, only ink overhang to the left), height comes from font
    // metrics, origin from the `x` and `y` attributes. Edge spaces do not count; empty
    // text has no box.
    #[cfg(feature = "render")]
    #[tokio::test]
    async fn an_svg_text_box_is_the_one_a_browser_measures() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            "<html><body></body></html>",
        )
        .await
        .unwrap();
        let probe = r#"(() => {
            const NS = 'http://www.w3.org/2000/svg';
            const svg = document.createElementNS(NS, 'svg');
            document.body.appendChild(svg);
            const mk = (fs, fam, txt) => {
                const t = document.createElementNS(NS, 'text');
                t.setAttribute('x', '10'); t.setAttribute('y', '50');
                t.setAttribute('font-size', fs); t.setAttribute('font-family', fam);
                t.textContent = txt; svg.appendChild(t); return t;
            };
            const r = (t) => { const b = t.getBBox();
                return [+b.x.toFixed(3), +b.y.toFixed(3), +b.width.toFixed(3), +b.height.toFixed(3)]; };
            const jjj = mk('16px', 'Arial', 'jjj');
            const mono = mk('24px', 'monospace', 'mmmmmmmmmmlli');
            const spaced = mk('20px', 'Arial', '  ii  ');
            const tight = mk('20px', 'Arial', 'ii');
            const empty = mk('16px', 'Arial', '');
            return __ptJSON.stringify({
                jjj: r(jjj), mono: r(mono), spaced: r(spaced), tight: r(tight), empty: r(empty),
                length: +mono.getComputedTextLength().toFixed(3),
            });
        })()"#;
        let out = match ctx.evaluate(probe).await.unwrap() {
            Value::String(s) => s,
            v => panic!("expected string, got {v:?}"),
        };
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let box_of = |k: &str| -> Vec<f64> {
            v[k].as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_f64().unwrap())
                .collect()
        };
        // The ink of "jjj" starts a pixel left of the origin: the box follows and the width absorbs it.
        assert_eq!(box_of("jjj"), vec![9.0, 36.0, 11.672, 17.0], "box of \"jjj\"");
        // Monospace: ink is narrower than layout, so the layout is taken on the right.
        assert_eq!(
            box_of("mono"),
            vec![10.0, 24.0, 187.203, 33.0],
            "monospace line box"
        );
        assert_eq!(
            v["length"].as_f64().unwrap(),
            187.203,
            "line length is the layout width"
        );
        assert_eq!(
            box_of("spaced"),
            box_of("tight"),
            "edge spaces are not in the box"
        );
        assert_eq!(box_of("empty"), vec![0.0, 0.0, 0.0, 0.0], "empty text has no box");
    }

    /// A comma selector list returns elements in document order, not grouped by
    /// selector. Turnstile's api.js collects its form this way
    /// (`querySelectorAll("input, select, textarea, button")`).
    #[tokio::test]
    async fn a_selector_list_answers_in_document_order() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            "<html><body><form><button id=b1></button><input id=i1><select id=s1></select>\
             <div><input id=i2><div><textarea id=t1></textarea></div></div><button id=b2></button>\
             </form></body></html>",
        )
        .await
        .unwrap();
        let out = probe(
            &ctx,
            "__ptJSON.stringify({
               all: [...document.querySelectorAll('input, select, textarea, button')].map(e => e.id),
               two: [...document.querySelectorAll('button, input')].map(e => e.id),
               nested: [...document.querySelectorAll('div textarea, form > button')].map(e => e.id),
             })",
        )
        .await;
        assert_eq!(out["all"], serde_json::json!(["b1", "i1", "s1", "i2", "t1", "b2"]), "{out}");
        assert_eq!(out["two"], serde_json::json!(["b1", "i1", "i2", "b2"]), "{out}");
        assert_eq!(out["nested"], serde_json::json!(["b1", "t1", "b2"]), "{out}");
    }

    /// Pseudo-classes and all four combinators. The old engine read `:root` as a tag
    /// name, so variables from `:root { … }` reached no element.
    #[tokio::test]
    async fn selectors_know_pseudo_classes_and_siblings() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            "<html><body><ul><li id=a class=x></li><li id=b></li><li id=c class=x></li></ul>\
             <input id=d required><input id=e disabled value=v><p id=f></p></body></html>",
        )
        .await
        .unwrap();
        let out = probe(
            &ctx,
            "__ptJSON.stringify({
               root: document.documentElement.matches(':root'),
               html: document.querySelectorAll('html').length,
               first: [...document.querySelectorAll('li:first-child, li:last-child')].map(e => e.id),
               nth: [...document.querySelectorAll('li:nth-child(2n+1)')].map(e => e.id),
               not: [...document.querySelectorAll('li:not(.x)')].map(e => e.id),
               sib: [...document.querySelectorAll('#a + li, #a ~ .x')].map(e => e.id),
               is: [...document.querySelectorAll(':is(ul, p) > :where(#b), p:empty')].map(e => e.id),
               has: [...document.querySelectorAll('ul:has(> .x)')].length,
               form: [...document.querySelectorAll('input:invalid, input:disabled')].map(e => e.id),
               scope: document.querySelector('ul').querySelectorAll(':scope > li').length,
             })",
        )
        .await;
        assert_eq!(out["root"], true, "{out}");
        assert_eq!(out["html"], 1, "{out}");
        assert_eq!(out["first"], serde_json::json!(["a", "c"]), "{out}");
        assert_eq!(out["nth"], serde_json::json!(["a", "c"]), "{out}");
        assert_eq!(out["not"], serde_json::json!(["b"]), "{out}");
        assert_eq!(out["sib"], serde_json::json!(["b", "c"]), "{out}");
        assert_eq!(out["is"], serde_json::json!(["b", "f"]), "{out}");
        assert_eq!(out["has"], 1, "{out}");
        assert_eq!(out["form"], serde_json::json!(["d", "e"]), "{out}");
        assert_eq!(out["scope"], 3, "{out}");
    }

    /// Modern CSS values: `var()` with fallback, registered custom properties,
    /// `calc()`/`min()`/`clamp()`, `dvh`, root `rem`, `box-sizing: inherit` and grid
    /// with `gap`. Numbers from Chrome 151 on the same markup (1920x942 window).
    #[tokio::test]
    async fn modern_css_values_resolve_like_chrome() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            "<html><head><style>
               :root { --space-16: 1.6rem; box-sizing: border-box; }
               *, :before, :after { box-sizing: inherit; }
               html { font-size: 62.5%; }
               body { margin: 0; }
               #a { width: var(--W, 40rem); }
               #b { --Wide: 34rem; width: var(--Wide, 40rem); }
               #c { min-height: 100dvh; height: 10px; }
               #d { padding-left: clamp(1.2rem, 3vw, 2rem); }
               #e { width: min(50%, 300px); }
               #g { --x: 7px; margin-left: var(--x); }
               #h { width: 200px; padding: 0 20px; }
               #grid { display: grid; gap: var(--space-16); width: 320px; }
               #grid > div { height: 40px; }
             </style></head><body><div id=a></div><div id=b></div><div id=c></div><div id=d></div>\
             <div id=e></div><div id=g></div><div id=h></div>\
             <form id=grid><div></div><div></div><div></div></form></body></html>",
        )
        .await
        .unwrap();
        let out = probe(
            &ctx,
            "(() => { const q = (id) => document.getElementById(id);
               const cs = (id, p) => getComputedStyle(q(id))[p];
               const w = (id) => q(id).getBoundingClientRect().width;
               const g = q('grid');
               return __ptJSON.stringify({
                 a: [cs('a', 'width'), w('a')], b: [w('b'), getComputedStyle(q('b')).getPropertyValue('--Wide')],
                 c: q('c').getBoundingClientRect().height, d: cs('d', 'paddingLeft'), e: w('e'),
                 g: cs('g', 'marginLeft'), h: [w('h'), cs('h', 'width')],
                 grid: [g.getBoundingClientRect().height, cs('grid', 'rowGap'),
                        g.children[2].getBoundingClientRect().top - g.getBoundingClientRect().top],
               }); })()",
        )
        .await;
        assert_eq!(out["a"], serde_json::json!(["400px", 400]), "{out}");
        assert_eq!(out["b"], serde_json::json!([340, "34rem"]), "{out}");
        assert_eq!(out["c"], 942, "{out}");
        assert_eq!(out["d"], "20px", "{out}");
        assert_eq!(out["e"], 300, "{out}");
        assert_eq!(out["g"], "7px", "{out}");
        assert_eq!(out["h"], serde_json::json!([200, "200px"]), "{out}");
        assert_eq!(out["grid"], serde_json::json!([152, "16px", 112]), "{out}");
    }

    /// A page-inserted script sees itself as in a browser: `document.currentScript` is
    /// itself, and its Resource Timing entry exists while it runs. Turnstile's api.js
    /// looks it up on its first line and forwards it whole to the widget; without it
    /// the first POST body was six fields short.
    #[tokio::test]
    async fn an_inserted_script_sees_itself_and_its_timing() {
        let _serial = serial().await;
        const PAGE: &str = r#"<html><body><script>
            const s = document.createElement('script'); s.src = '/self.js';
            s.onload = () => { globalThis.__after = document.currentScript === null; };
            document.head.appendChild(s);
          </script></body></html>"#;
        const JS: &str = "(function () {
            var cs = document.currentScript;
            var all = performance.getEntriesByType('resource');
            var mine = all.filter(function (e) { return cs && e.name.indexOf(cs.src) >= 0; });
            globalThis.__self = {
              cs: !!cs, inst: mine.length ? mine[0] instanceof PerformanceResourceTiming : false,
              found: mine.length, keys: mine.length ? Object.keys(mine[0].toJSON()).slice(0, 8) : [],
              type: mine.length ? mine[0].contentType : null,
            };
          })();";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 2048];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let (ct, body) = if req.starts_with("GET /self.js") {
                        ("application/javascript; charset=UTF-8", JS)
                    } else {
                        ("text/html", PAGE)
                    };
                    let out = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(out.as_bytes()).await;
                });
            }
        });
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig { workers: 1, max_live_contexts: 2, max_heap_mb: None },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&format!("http://{addr}/")).await.unwrap();
        ctx.run_event_loop().await.unwrap();
        let out = probe(&ctx, "__ptJSON.stringify({ self: globalThis.__self, after: globalThis.__after })").await;
        assert_eq!(out["self"]["cs"], true, "currentScript is the script itself: {out}");
        assert_eq!(out["self"]["found"], 1, "its own entry is visible while running: {out}");
        assert_eq!(out["self"]["inst"], true, "{out}");
        assert_eq!(
            out["self"]["keys"],
            serde_json::json!(["name", "entryType", "startTime", "duration", "navigationId",
                               "initiatorType", "deliveryType", "nextHopProtocol"]),
            "fields in browser order: {out}"
        );
        assert_eq!(out["self"]["type"], "text/javascript", "MIME trimmed, as in a browser: {out}");
        assert_eq!(out["after"], true, "currentScript is null again afterwards: {out}");
    }

    /// Focus is four events, not two: `blur` and `focusout` on the old element, `focus`
    /// and `focusin` on the new, each with the other in `relatedTarget`. The browser
    /// sends them, so they are trusted even when a script asked for focus. Body means
    /// "nobody": `relatedTarget` is then null.
    #[tokio::test]
    async fn focus_moves_the_way_a_browser_moves_it() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><body><input id=a><input id=b><script>
              globalThis.__focusLog = [];
              for (const t of ['focus', 'blur', 'focusin', 'focusout']) {
                for (const id of ['a', 'b']) {
                  document.getElementById(id).addEventListener(t, (e) => {
                    __focusLog.push([id, t, e.isTrusted, e.relatedTarget ? e.relatedTarget.id : null,
                                Object.prototype.toString.call(e), e.bubbles]);
                  });
                }
              }
              document.getElementById('a').focus();
              document.getElementById('b').focus();
            </script></body></html>"#,
        )
        .await
        .unwrap();
        let out = probe(&ctx, "__ptJSON.stringify(globalThis.__focusLog)").await;
        assert_eq!(
            out,
            serde_json::json!([
                ["a", "focus", true, null, "[object FocusEvent]", false],
                ["a", "focusin", true, null, "[object FocusEvent]", true],
                ["a", "blur", true, "b", "[object FocusEvent]", false],
                ["a", "focusout", true, "b", "[object FocusEvent]", true],
                ["b", "focus", true, "a", "[object FocusEvent]", false],
                ["b", "focusin", true, "a", "[object FocusEvent]", true],
            ]),
            "order, trust and related target"
        );
    }

    /// Lifecycle events come from the engine, which here is the browser: real ones have
    /// `isTrusted` true, and pages read it first. Plus two that were missing:
    /// `readystatechange` at each readiness step and `pageshow` after `load`.
    #[tokio::test]
    async fn the_lifecycle_events_are_trusted_like_a_browsers() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><body><script>
              globalThis.__lifecycle = {};
              document.addEventListener('readystatechange', (e) => {
                __lifecycle['ready:' + document.readyState] = e.isTrusted;
              });
              document.addEventListener('DOMContentLoaded', (e) => { __lifecycle.dcl = e.isTrusted; });
              window.addEventListener('DOMContentLoaded', (e) => { __lifecycle.dclWindow = e.isTrusted; });
              window.addEventListener('load', (e) => { __lifecycle.load = e.isTrusted; });
              document.addEventListener('load', (e) => { __lifecycle.loadDocument = e.isTrusted; });
              window.addEventListener('pageshow', (e) => {
                __lifecycle.pageshow = e.isTrusted; __lifecycle.persisted = e.persisted;
              });
            </script></body></html>"#,
        )
        .await
        .unwrap();
        let out = probe(&ctx, "__ptJSON.stringify(globalThis.__lifecycle)").await;
        for key in ["dcl", "dclWindow", "load", "loadDocument", "pageshow"] {
            assert_eq!(out[key], true, "{key} must be trusted: {out}");
        }
        assert_eq!(out["ready:interactive"], true, "{out}");
        assert_eq!(out["ready:complete"], true, "{out}");
        assert_eq!(out["persisted"], false, "a normal load, not a back navigation: {out}");
    }

    // A member's descriptor kind reads as one string, and the challenge's graph walk
    // reads it that way. In a browser an interface attribute is an accessor (with a
    // setter if writable), a method an enumerable value, a constant non-writable and
    // non-configurable. Checked against Chrome 151 across all ~950 interfaces; here one
    // sample per kind.
    #[tokio::test]
    async fn an_interface_member_is_described_the_way_a_browser_describes_it() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();
        let out = probe(
            &ctx,
            r#"(() => {
                const kind = (o, n) => {
                    const d = Object.getOwnPropertyDescriptor(o, n);
                    if (!d) return 'none';
                    return (d.get || d.set)
                        ? 'a' + (d.get ? 'g' : '') + (d.set ? 's' : '')
                            + (d.enumerable ? 'e' : '') + (d.configurable ? 'c' : '')
                        : 'v' + (typeof d.value)[0] + (d.writable ? 'w' : '')
                            + (d.enumerable ? 'e' : '') + (d.configurable ? 'c' : '');
                };
                return __ptJSON.stringify({
                    namespaceURI: kind(Element.prototype, 'namespaceURI'),
                    title: kind(HTMLElement.prototype, 'title'),
                    ownerDocument: kind(Node.prototype, 'ownerDocument'),
                    appendChild: kind(Node.prototype, 'appendChild'),
                    elementNode: kind(Node.prototype, 'ELEMENT_NODE'),
                    geolocation: kind(Navigator.prototype, 'geolocation'),
                    body: kind(Document.prototype, 'body'),
                    svgPx: kind(SVGLength.prototype, 'SVG_LENGTHTYPE_PX'),
                    svgPxValue: SVGLength.SVG_LENGTHTYPE_PX,
                    // Internal writes still work: the page cannot write the field, the engine can.
                    lifecycle: (() => {
                        const d = document.createElement('i');
                        document.body.appendChild(d);
                        return [document.readyState, d.parentNode.nodeName,
                                d.ownerDocument === document, d.nodeType];
                    })(),
                });
            })()"#,
        )
        .await;
        assert_eq!(out["namespaceURI"], "agec", "read-only: {out}");
        assert_eq!(out["title"], "agsec", "read and write: {out}");
        assert_eq!(out["ownerDocument"], "agec", "{out}");
        assert_eq!(out["appendChild"], "vfwec", "a method is a value: {out}");
        assert_eq!(out["elementNode"], "vne", "a constant cannot be overwritten: {out}");
        assert_eq!(out["geolocation"], "agec", "{out}");
        assert_eq!(out["body"], "agsec", "{out}");
        assert_eq!(out["svgPx"], "vne", "{out}");
        assert_eq!(out["svgPxValue"], 5, "a constant is a number, not empty: {out}");
        assert_eq!(
            out["lifecycle"],
            serde_json::json!(["complete", "BODY", true, 1]),
            "internal writes still work for the engine: {out}"
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
              // A collection, not an array, as on the platform: iterable, but no .map.
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
        assert_eq!((out["w"].as_i64(), out["h"].as_i64()), (Some(304), Some(69)),
                   "an element in a closed shadow root is laid out like any other");
        assert_eq!(out["offset"], serde_json::json!([304, 69]));
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
        // The declared size is the content box: Chrome draws a 2 px border around an
        // `<iframe>`, so the outer box is 4 px larger. Chrome 151: a bare `<iframe>` gives
        // 304x154 for 300x150 content.
        assert_eq!(out["attr"], serde_json::json!([304, 69]), "width/height attributes");
        assert_eq!(out["style"], serde_json::json!([304, 69]), "and inline CSS");
        assert_eq!(out["offset"], serde_json::json!([304, 69]), "offsetWidth/Height agree");
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

    /// Playwright decides an element is visible with `checkVisibility()` and clicks
    /// after scrolling it into the window. `checkVisibility` answered nothing, so every
    /// element was hidden (its page snapshot came back empty), and nothing scrolled, so
    /// a click below the first screen was "outside of the viewport" forever.
    #[tokio::test]
    async fn elements_report_visibility_and_the_document_scrolls() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><body style="margin:0"><h1 id=h>top</h1><p id=gone style="display:none">x</p>
               <div style="height:3000px"></div><a id=far href="/far">far</a><div style="height:3000px"></div></body></html>"#,
        )
        .await
        .unwrap();
        let out = probe(&ctx, r#"(() => {
            const h = document.getElementById('h'), far = document.getElementById('far');
            const before = far.getBoundingClientRect().top;
            far.scrollIntoView({ block: 'center' });
            const after = far.getBoundingClientRect().top;
            const centred = Math.abs(after + far.getBoundingClientRect().height / 2 - innerHeight / 2) < 2;
            const y = scrollY;
            scrollTo(0, 0); scrollBy(0, 50);
            return __ptJSON.stringify({
              visible: h.checkVisibility(), hidden: document.getElementById('gone').checkVisibility(),
              moved: after < before, centred, scrolled: y > 0, by: scrollY, top: document.documentElement.scrollTop,
            });
        })()"#).await;
        assert_eq!(out["visible"], true, "{out}");
        assert_eq!(out["hidden"], false, "display:none is not visible: {out}");
        assert_eq!(out["moved"], true, "rects are relative to the window: {out}");
        assert_eq!(out["centred"], true, "{out}");
        assert_eq!(out["scrolled"], true, "{out}");
        assert_eq!(out["by"], 50, "scrollBy from 0: {out}");
        assert_eq!(out["top"], 50, "the root element reports the document's scroll: {out}");
    }

    /// A binary body leaves as its bytes. `String(new Uint8Array(…))` is "1,2,3", and that
    /// is what went out: reCAPTCHA's protobuf `reload` came back "Invalid API parameter(s)"
    /// and no token was ever issued.
    #[tokio::test]
    async fn a_binary_request_body_leaves_as_bytes() {
        let _serial = serial().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let mut got = 0;
                    loop {
                        let n = stream.read(&mut buf[got..]).await.unwrap_or(0);
                        if n == 0 { break; }
                        got += n;
                        let text = String::from_utf8_lossy(&buf[..got]).to_string();
                        if let Some(at) = text.find("\r\n\r\n") {
                            let len = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                            if got >= at + 4 + len { break; }
                        }
                    }
                    let text = String::from_utf8_lossy(&buf[..got]).to_string();
                    let reply = match text.find("\r\n\r\n") {
                        Some(at) if text.starts_with("POST") => buf[at + 4..got].iter().map(|b| format!("{b:02x}")).collect::<String>(),
                        _ => "<html><body>x</body></html>".to_string(),
                    };
                    let resp = format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{reply}", reply.len());
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig { workers: 1, max_live_contexts: 2, max_heap_mb: None },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&format!("http://127.0.0.1:{}/", addr.port())).await.unwrap();
        ctx.evaluate(r#"(() => {
            const u8 = new Uint8Array([0, 255, 1, 128, 10]);
            fetch('/p', { method: 'POST', body: u8 }).then(r => r.text()).then(t => { globalThis.__a = t; });
            fetch('/p', { method: 'POST', body: u8.subarray(1, 3) }).then(r => r.text()).then(t => { globalThis.__b = t; });
            fetch('/p', { method: 'POST', body: u8.buffer }).then(r => r.text()).then(t => { globalThis.__c = t; });
        })()"#).await.unwrap();
        for _ in 0..50 {
            ctx.run_event_loop().await.unwrap();
            if ctx.evaluate("typeof __c").await.unwrap() == Value::String("string".into()) { break; }
        }
        assert_eq!(ctx.evaluate("__a").await.unwrap(), Value::String("00ff01800a".into()));
        assert_eq!(ctx.evaluate("__b").await.unwrap(), Value::String("ff01".into()), "a view sends its own window");
        assert_eq!(ctx.evaluate("__c").await.unwrap(), Value::String("00ff01800a".into()));
    }

    /// The Turnstile VM calls `document.replaceChild(root, root)` and then looks for
    /// `script[nonce]`. Insert-then-remove dropped the root, the lookup came back
    /// empty, the VM's iframe never attached and the widget reported an error beacon
    /// (2026-10-07). `documentElement` also has to follow the children it reads.
    #[tokio::test]
    async fn replacing_the_root_with_itself_keeps_it() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><head></head><body><p id=p>x</p></body></html>")
            .await
            .unwrap();
        let out = probe(&ctx, r#"(() => {
            const de = document.documentElement, p = document.getElementById('p');
            const same = document.replaceChild(de, de) === de && document.documentElement === de && de.isConnected;
            const kept = p.parentNode.replaceChild(p, p) === p && p.isConnected;
            const n = document.createElement('html');
            n.append(document.createElement('head'), document.createElement('body'));
            document.replaceChild(n, de);
            const swapped = document.documentElement === n && document.body === n.lastChild && !de.isConnected;
            document.removeChild(n);
            const none = document.documentElement === null;
            document.appendChild(de);
            return __ptJSON.stringify({ same, kept, swapped, none, back: document.documentElement === de });
        })()"#).await;
        for k in ["same", "kept", "swapped", "none", "back"] {
            assert_eq!(out[k], true, "{k}: {out}");
        }
    }

    /// `document.cookie` and the network share one jar, as in a browser. They were two:
    /// the page never saw a header cookie, and a cookie set from script never left with
    /// a request, which breaks every challenge that sets a cookie and reloads (Google's
    /// SearchGuard among them).
    #[tokio::test]
    async fn document_cookie_and_the_network_share_one_jar() {
        let _serial = serial().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let resp = if req.starts_with("GET /echo") {
                        let cookie = req.lines().find_map(|l| l.strip_prefix("cookie: ").or_else(|| l.strip_prefix("Cookie: "))).unwrap_or("").to_string();
                        format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{cookie}", cookie.len())
                    } else {
                        let body = "<html><body>x</body></html>";
                        format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\nSet-Cookie: hdr=h1; Path=/\r\nSet-Cookie: ho=secret; Path=/; HttpOnly\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                    };
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig { workers: 1, max_live_contexts: 2, max_heap_mb: None },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        ctx.navigate(&format!("http://127.0.0.1:{}/", addr.port())).await.unwrap();
        assert_eq!(ctx.evaluate("document.cookie").await.unwrap(), Value::String("hdr=h1".into()), "a header cookie is visible, an HttpOnly one is not");
        ctx.evaluate(r#"(() => {
            document.cookie = 'js=v; path=/';
            document.cookie = 'hdr=; max-age=0; path=/';
            document.cookie = 'ho=hack; path=/; HttpOnly';
            fetch('/echo').then(r => r.text()).then(t => { globalThis.__sent = t; });
        })()"#).await.unwrap();
        for _ in 0..50 {
            ctx.run_event_loop().await.unwrap();
            if ctx.evaluate("typeof __sent").await.unwrap() == Value::String("string".into()) {
                break;
            }
        }
        let sent = ctx.evaluate("__sent").await.unwrap();
        let sent = sent.as_str().unwrap_or_default();
        assert!(sent.contains("js=v"), "a script cookie leaves with the next request: {sent}");
        assert!(sent.contains("ho=secret"), "script cannot replace an HttpOnly cookie: {sent}");
        assert!(!sent.contains("hdr="), "an expired write deletes: {sent}");
        assert_eq!(ctx.evaluate("document.cookie").await.unwrap(), Value::String("js=v".into()));
    }

    /// A host that accepts and never answers must not hold the page: in Chrome a hung
    /// stylesheet or fetch blocks nothing an async script or a timer does. Here every
    /// round waited for all its requests, and peet.ws (a dead stylesheet host) sat for
    /// the whole 30 s request timeout before Turnstile's async loader ran.
    #[tokio::test]
    async fn a_hung_request_does_not_hold_the_page() {
        let _serial = serial().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut hung = Vec::new();
            while let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let (ctype, body) = if req.contains("GET /dead") {
                    hung.push(stream);
                    continue;
                } else if req.contains("GET /a.js") {
                    ("text/javascript", "document.title += 'async;'; fetch('/dead-xhr'); setTimeout(() => { document.title += 'timer;'; }, 50);")
                } else {
                    ("text/html", "<html><head><title></title><link rel=stylesheet href=/dead.css><script async src=/a.js></script></head><body>x</body></html>")
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig { workers: 1, max_live_contexts: 2, max_heap_mb: None },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        let t = std::time::Instant::now();
        let _ = ctx.navigate(&format!("http://127.0.0.1:{}/", addr.port())).await;
        while t.elapsed() < std::time::Duration::from_secs(8)
            && ctx.evaluate("document.title").await.unwrap_or_default() != Value::String("async;timer;".into())
        {
            let _ = ctx.run_event_loop().await;
        }
        assert_eq!(ctx.evaluate("document.title").await.unwrap(), Value::String("async;timer;".into()));
        assert!(t.elapsed() < std::time::Duration::from_secs(8), "took {:?}", t.elapsed());
    }

    /// The engine's own work (cascade, layout, colors, stack formatting) must not run
    /// through `String.prototype` methods a page replaced. Klarna's script replaces
    /// `trim`; our layout called it thousands of times, visibly and 10x slower.
    #[tokio::test]
    async fn the_engine_does_not_call_string_methods_a_page_replaced() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><head></head><body></body></html>").await.unwrap();
        let out = probe(&ctx, r#"(() => {
            const n = {};
            for (const m of ['trim', 'toLowerCase', 'replace', 'split', 'slice', 'indexOf', 'charCodeAt']) {
              const f = String.prototype[m];
              String.prototype[m] = function () { n[m] = (n[m] || 0) + 1; return f.apply(this, arguments); };
            }
            const st = document.createElement('style');
            st.textContent = '.a { margin: 1em 2px; padding: calc(1rem + 2px); color: RGB(1, 2, 3); } div > .b { display: flex; }';
            document.head.appendChild(st);
            const d = document.createElement('div');
            d.innerHTML = '<p class=a style="width: 50%">x</p><span class=b>y</span>';
            document.body.appendChild(d);
            void d.offsetWidth;
            getComputedStyle(d.firstChild).marginTop;
            d.querySelector('.b').getBoundingClientRect();
            try { null.x; } catch (e) { void e.stack; }
            const c = document.createElement('canvas').getContext('2d');
            c.fillStyle = 'hsl(10, 20%, 30%)';
            return __ptJSON.stringify({ calls: n });
        })()"#).await;
        assert_eq!(out["calls"], serde_json::json!({}), "{out}");
    }

    /// A form aimed at a frame (`target` = the frame's name) loads its response in
    /// that frame; the page stays. Facebook's pixel posts this way, and nokk moved
    /// the whole page to facebook.com/tr.
    #[tokio::test]
    async fn a_form_aimed_at_a_frame_navigates_the_frame_not_the_page() {
        let _serial = serial().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let posts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = posts.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if req.starts_with("POST /tr") {
                    seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    "<html><body>ok</body></html>"
                } else {
                    "<html><head><title>home</title></head><body><iframe name=sink></iframe>\
                     <form id=f method=post action=/tr target=sink><input name=a value=1></form>\
                     <script>document.querySelector('iframe').addEventListener('load', () => { document.title += ' loaded'; });\
                     setTimeout(() => document.getElementById('f').submit(), 10);</script></body></html>"
                };
                let resp = format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig { workers: 1, max_live_contexts: 2, max_heap_mb: None },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        let home = format!("http://127.0.0.1:{}/", addr.port());
        let _ = ctx.navigate(&home).await;
        let t = std::time::Instant::now();
        while t.elapsed() < std::time::Duration::from_secs(5)
            && ctx.evaluate("document.title").await.unwrap_or_default() != Value::String("home loaded".into())
        {
            let _ = ctx.run_event_loop().await;
        }
        assert_eq!(ctx.evaluate("document.title").await.unwrap(), Value::String("home loaded".into()));
        assert_eq!(ctx.evaluate("location.href").await.unwrap(), Value::String(home));
        assert_eq!(posts.load(std::sync::atomic::Ordering::SeqCst), 1, "the form was posted once");
    }

    /// Text and JSON responses are shown as Chrome 151 builds them: a `<pre>` (styled
    /// for text, bare plus a formatter container for JSON), the leading newline
    /// kept, and the real `contentType`. Scrapers read this serialized DOM.
    #[test]
    fn text_and_json_documents_have_chromes_markup() {
        let t = text_document_markup("text/plain", "\nlead <b>&amp;</b>").unwrap();
        assert_eq!(t, "<html><head><meta name=\"color-scheme\" content=\"light dark\"></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">\n\nlead &lt;b&gt;&amp;amp;&lt;/b&gt;</pre></body></html>");
        let j = text_document_markup("application/ld+json", "{\"a\":1}").unwrap();
        assert_eq!(j, "<html><head><meta name=\"color-scheme\" content=\"light dark\"><meta charset=\"utf-8\"></head><body><pre>{\"a\":1}</pre><div class=\"json-formatter-container\"></div></body></html>");
        assert!(text_document_markup("text/javascript", "x").is_some());
        for other in ["text/html", "text/xml", "application/xml", "text/csv", "image/png", "application/octet-stream"] {
            assert!(text_document_markup(other, "x").is_none(), "{other}");
        }
    }

    /// A driver that intercepts (Playwright `page.route`) decides every request before it
    /// goes out: failed, answered in its place, or sent on with its own header. Each later
    /// record carries the id the request had while held, so the driver can pair them.
    #[tokio::test]
    async fn an_interceptor_decides_every_request() {
        let _serial = serial().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                let (ctype, body) = if req.starts_with("get /api") {
                    ("text/plain", if req.contains("x-test: yes") { "header" } else { "plain" }.to_string())
                } else {
                    ("text/html", "<html><head><title></title><script src=/a.js></script></head><body>\
                       <script>fetch('/gone').catch(() => document.title += 'failed;');\
                       fetch('/api').then((r) => r.text()).then((t) => document.title += t + ';');</script></body></html>".to_string())
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
        let engine = Engine::new(EngineConfig {
            pool: PoolConfig { workers: 1, max_live_contexts: 2, max_heap_mb: None },
            use_real_network: true,
            ..Default::default()
        })
        .expect("engine");
        let ctx = engine.new_context().await.unwrap();
        let mut held = ctx.intercept_requests();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Some(p) = held.recv().await {
                log.lock().unwrap().push((p.id.clone(), p.url.clone(), p.resource_type));
                let d = if p.url.ends_with("/a.js") {
                    Decision::Fulfill { status: 200, headers: Default::default(), body: b"document.title += 'fulfilled;';".to_vec() }
                } else if p.url.ends_with("/gone") {
                    Decision::Fail
                } else if p.url.ends_with("/api") {
                    let mut h = p.headers.clone();
                    h.insert("X-Test".into(), "yes".into());
                    Decision::Continue { url: None, method: None, headers: Some(h), body: None }
                } else {
                    Decision::Continue { url: None, method: None, headers: None, body: None }
                };
                let _ = p.reply.send(d);
            }
        });
        let _ = ctx.navigate(&format!("http://127.0.0.1:{}/", addr.port())).await;
        let t = std::time::Instant::now();
        let want = |v: &Value| v.as_str().is_some_and(|s| s.contains("failed;") && s.contains("header;"));
        while t.elapsed() < std::time::Duration::from_secs(8) && !want(&ctx.evaluate("document.title").await.unwrap()) {
            let _ = ctx.run_event_loop().await;
        }
        let title = ctx.evaluate("document.title").await.unwrap();
        assert!(want(&title) && title.as_str().unwrap().starts_with("fulfilled;"), "{title}");
        let seen = seen.lock().unwrap().clone();
        let kinds: Vec<_> = seen.iter().map(|(_, u, k)| (u.rsplit('/').next().unwrap().to_string(), *k)).collect();
        assert!(kinds.contains(&("".into(), "Document")) && kinds.contains(&("a.js".into(), "Script")), "{kinds:?}");
        for rec in ctx.requests() {
            let held = seen.iter().find(|(_, u, _)| *u == rec.url).expect("every request was held");
            assert!(rec.announced && rec.request_id == held.0, "{} {}", rec.url, rec.request_id);
        }
        ctx.stop_intercepting();
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
        // Measured against Chrome 151, level by level: the shape of the realm is
        // the first thing a collector inside a worker enumerates. 335 names,
        // including `FontFaceSet`: in a browser `self.fonts` is an interface instance.
        assert_eq!(out["own"], 335, "own names on the scope: {out}");
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

    /// Milliseconds from "page posted" to "page got the reply". The challenge measures
    /// it: the collector asks a worker to reply in 55 ms and checks the real time. A live
    /// browser stays around 60 because the worker is its own thread. Ten rounds here,
    /// with a deliberately loose threshold to catch an order-of-magnitude regression,
    /// not machine jitter.
    #[tokio::test]
    async fn a_message_to_a_worker_and_back_takes_about_a_frame() {
        let _serial = serial().await;
        let engine = engine(4, 6);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/app/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(
            r#"(() => {
            const src = `self.onmessage = (e) => { postMessage(e.data + 1); };`;
            const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
            // The page is busy meanwhile, like any live page. On a shared isolate the worker's
            // reply waited for it and the round grew by exactly its work.
            const burn = () => {
              const until = performance.now() + 15;
              while (performance.now() < until) {}
              if (globalThis.__rt.length < 10) setTimeout(burn, 1);
            };
            globalThis.__rt = [];
            globalThis.__mark = performance.now();
            w.onmessage = (e) => {
              const now = performance.now();
              globalThis.__rt.push(now - globalThis.__mark);
              globalThis.__mark = now;
              if (globalThis.__rt.length < 10) w.postMessage(e.data);
            };
            w.postMessage(0);
            setTimeout(burn, 1);
            return 1;
        })()"#,
        )
        .await
        .unwrap();
        ctx.run_event_loop().await.unwrap();

        let rt = probe(&ctx, "__ptJSON.stringify(globalThis.__rt || [])").await;
        let mut trips: Vec<f64> = rt
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_f64()).collect())
            .unwrap_or_default();
        assert_eq!(trips.len(), 10, "ten round trips completed: {rt}");
        trips.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = trips[trips.len() / 2];
        println!(
            "worker round trip: median {median:.0} ms, min {:.0}, max {:.0}",
            trips[0],
            trips[trips.len() - 1]
        );
        assert!(
            median < 250.0,
            "a round trip through a worker should cost tens of milliseconds, not hundreds: {rt}"
        );
    }

    /// A worker keeps its own time. Cloudflare's collector is a chain of short timers in
    /// a worker; on a shared isolate each step waited for the page, stretching a second
    /// of work over wall seconds until the challenge declared the collector hung. Here
    /// a 20-step chain of 5 ms runs against a busy page and must fit its own time.
    #[tokio::test]
    async fn a_worker_keeps_its_own_clock_while_the_page_is_busy() {
        let _serial = serial().await;
        let engine = engine(4, 6);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/app/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(
            r#"(() => {
            const src = `const t0 = performance.now();
              let n = 0;
              const step = () => {
                if (++n < 20) { setTimeout(step, 5); return; }
                postMessage(performance.now() - t0);
              };
              self.onmessage = () => setTimeout(step, 5);`;
            const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
            globalThis.__done = null;
            globalThis.__wall = performance.now();
            w.onmessage = (e) => {
              globalThis.__done = { inWorker: e.data, wall: performance.now() - globalThis.__wall };
            };
            w.postMessage(0);
            const burn = () => {
              const until = performance.now() + 15;
              while (performance.now() < until) {}
              if (!globalThis.__done) setTimeout(burn, 1);
            };
            setTimeout(burn, 1);
            return 1;
        })()"#,
        )
        .await
        .unwrap();
        ctx.run_event_loop().await.unwrap();

        let done = probe(&ctx, "__ptJSON.stringify(globalThis.__done)").await;
        let wall = done["wall"].as_f64().unwrap_or(f64::MAX);
        let inside = done["inWorker"].as_f64().unwrap_or(f64::MAX);
        println!("worker chain: {inside:.0} ms inside the worker, {wall:.0} ms of wall clock");
        // 20 steps of 5 ms is 100 ms of work. Loose threshold: catch a return to the old
        // order of magnitude, not jitter.
        assert!(
            wall < 600.0,
            "a worker's own timer chain must not wait for the page: {done}"
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
            // As in Chrome: indirect eval declares globally, direct eval sees the local scope
            // (a wrapper around eval turned direct calls into indirect ones).
            (0, eval)(code);
            const local = 5;
            const direct = eval(p.createScript('local * 2'));
            let timer = 'no';
            try { setTimeout(p.createScript('globalThis.__fromTimer = 1'), 0); timer = 'accepted'; }
            catch (e) { timer = 'THREW ' + e.name; }
            return __ptJSON.stringify({
              kind: Object.prototype.toString.call(code),
              declared: typeof globalThis.__declared,
              value: typeof globalThis.__declared === 'function' ? __declared() : null,
              // A string stays a string: plain eval works as before.
              plain: (eval('1 + 1')),
              native: /native code/.test(Function.prototype.toString.call(eval)),
              enumerable: Object.keys(globalThis).indexOf('eval') >= 0,
              timer,
              direct,
              evalOwn: Reflect.ownKeys(eval).join(','),
            });
        })()"#).await;

        assert_eq!(out["kind"], "[object TrustedScript]");
        assert_eq!(out["direct"], 10, "a direct eval of a TrustedScript sees the local scope");
        assert_eq!(out["evalOwn"], "length,name", "eval stays the engine's own function");
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

    /// Cloudflare's collector measures our clock with its own loop: five thousand
    /// consecutive `performance.now()` readings, keeping the smallest positive
    /// difference. A browser advances every 0.1 ms; ours was computed from
    /// `Date.now()`, which moves in whole milliseconds, so inside a single task
    /// the clock never moved at all — five thousand readings, one value.
    #[tokio::test]
    async fn the_clock_advances_the_way_a_browser_s_does() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            // Their loop, verbatim.
            let min;
            let advances = 0;
            for (let d = 0; d < 5000; d++) {
                const e = performance.now(), f = performance.now();
                if (e < f) { advances++; const g = f - e; if (min === undefined || g < min) min = g; }
            }
            const seen = new Set();
            for (let i = 0; i < 2000; i++) seen.add(performance.now());
            const values = [...seen];
            return __ptJSON.stringify({
              advances, min: min === undefined ? -1 : min, distinct: values.length,
              // Same step as Chrome and the same floating-point arithmetic.
              quantum: values.length > 1 ? Math.round((values[1] - values[0]) * 1000) / 1000 : -1,
              monotonic: values.every((v, i) => i === 0 || v > values[i - 1]),
              coherent: Math.abs(performance.timeOrigin + performance.now() - Date.now()) < 1000,
            });
        })()"#).await;

        assert!(out["advances"].as_u64().unwrap_or(0) > 0, "the clock moves inside one task: {out}");
        assert!(out["distinct"].as_u64().unwrap_or(0) > 1, "and successive readings differ: {out}");
        assert_eq!(out["quantum"], 0.1, "in Chrome's 0.1 ms steps");
        assert_eq!(out["monotonic"], true);
        assert_eq!(out["coherent"], true, "timeOrigin + now() still tracks the wall clock");
    }

    /// Font enumeration goes through `document.fonts.check('12px "Some Font"')`,
    /// and ours was a bare object from the graph table: the first call threw. A
    /// browser answers true for any family (a fallback always exists) and throws
    /// SyntaxError on a string that is not a font shorthand at all.
    #[tokio::test]
    async fn the_font_set_answers_and_a_lock_is_granted() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const bad = (() => { try { document.fonts.check('not-a-font'); return 'no throw'; }
                                 catch (e) { return e.name; } })();
            return __ptJSON.stringify({
              tag: Object.prototype.toString.call(document.fonts),
              size: document.fonts.size, status: document.fonts.status,
              known: document.fonts.check('12px sans-serif'),
              unknown: document.fonts.check('12px "No Such Font XYZ"'),
              bad,
              iterable: [...document.fonts].length,
              // Chrome does not publish this name on the window: interface, no global.
              global: typeof globalThis.FontFaceSet,
              locks: Object.prototype.toString.call(navigator.locks),
              lockMembers: Object.getOwnPropertyNames(Object.getPrototypeOf(navigator.locks))
                .filter((k) => k !== 'constructor').sort(),
            });
        })()"#).await;

        assert_eq!(out["tag"], "[object FontFaceSet]");
        assert_eq!(out["size"], 0);
        assert_eq!(out["status"], "loaded");
        assert_eq!(out["known"], true);
        assert_eq!(out["unknown"], true, "a fallback is always there, so any family checks out");
        assert_eq!(out["bad"], "SyntaxError");
        assert_eq!(out["iterable"], 0);
        // A browser does have the name on the window: `FontFaceSet` sits next to
        // `FontFaceSetLoadEvent`, and `document.fonts` is an instance.
        assert_eq!(out["global"], "function");
        assert_eq!(out["locks"], "[object LockManager]");
        assert_eq!(out["lockMembers"], serde_json::json!(["query", "request"]));
    }

    /// V8 does part of its own work on the platform's task queue — asynchronous
    /// WebAssembly compilation above all — and nothing pumped that queue here, so
    /// `WebAssembly.compile` returned a promise that never settled. Anything
    /// waiting on it waited forever: the challenge's collector sat for nine
    /// seconds and then declared itself overrun.
    #[tokio::test]
    async fn webassembly_compiles_and_the_promise_settles() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><body><script>
                globalThis.__log = { done: false };
                // The smallest legal module: header plus version.
                const bytes = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
                WebAssembly.compile(bytes).then(
                  (m) => { globalThis.__log = { done: true, kind: Object.prototype.toString.call(m) }; },
                  (e) => { globalThis.__log = { done: true, kind: 'REJECT ' + e }; });
              </script></body></html>"#,
        )
        .await
        .unwrap();

        let out = pump_until(&ctx, "__ptJSON.stringify(__log)", 40).await;
        let said = out.as_str().unwrap_or("");
        assert!(said.contains(r#""done":true"#), "the promise settled: {said}");
        assert!(said.contains("[object WebAssembly.Module]"), "with a module: {said}");
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
              // Parsed children go into the content; the element itself is empty.
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
    /// page that has any style. Serialisation follows Chrome, measured against
    /// its own widget stylesheet: a bare `0` in a length property becomes `0px`,
    /// selector combinators get their spaces, an @media condition gets one after
    /// the colon, a hex colour comes back as `rgb(…)`, `.9` as `0.9`, the
    /// `animation` shorthand as all eight longhands in spec order, a shorthand
    /// component equal to its initial value is dropped, and a rule with children
    /// is printed one child per indented line.
    #[tokio::test]
    async fn a_style_element_is_a_stylesheet_with_rules() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            "<html><head><style media=\"screen\">a{color:red;font-weight:bold}.b .c>d{margin:0 1px}             @media (min-width:1px){e{top:0}}\
             f{color:#f2f2f2;border:1px solid #b20f03;opacity:.9;flex-flow:column nowrap}\
             g{animation:spin 5s linear infinite}\
             @keyframes spin{100%{transform:rotate(360deg)}}</style></head><body></body></html>",
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
                "@media (min-width: 1px) {\n  e { top: 0px; }\n}",
                "f { color: rgb(242, 242, 242); border: 1px solid rgb(178, 15, 3); \
opacity: 0.9; flex-flow: column; }",
                "g { animation: 5s linear 0s infinite normal none running spin; }",
                "@keyframes spin { \n  100% { transform: rotate(360deg); }\n}"
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

    /// An error stack is part of the fingerprint. In a browser there is no JS frame
    /// between an event listener and the dispatch site; our dispatcher is JS, so any
    /// `new Error()` in a listener showed `fire`, `__ptDispatch` and a position in an
    /// unnamed script. Also an inline script must be named by the document URL.
    #[tokio::test]
    async fn a_stack_shows_the_page_and_not_the_engine() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><body><script>
              const out = {};
              const b = document.createElement('button');
              document.body.appendChild(b);
              b.addEventListener('click', () => { out.listener = new Error('\u0430\u0439').stack; });
              b.dispatchEvent(new MouseEvent('click'));
              out.builtin = [1].map(() => new Error().stack)[0];
              const mine = (e, sites) => sites.map((f) => typeof f.getFileName);
              Error.prepareStackTrace = mine;
              out.sites = new Error().stack;
              out.identity = Error.prepareStackTrace === mine;
              Error.prepareStackTrace = undefined;
              window.__stacks = out;
            </script></body></html>"#,
        )
        .await
        .unwrap();

        let out = probe(&ctx, "__ptJSON.stringify(window.__stacks)").await;
        let listener = out["listener"].as_str().unwrap_or_default();
        assert!(
            listener.starts_with("Error: \u{430}\u{439}\n    at "),
            "header and frames as in V8: {listener}"
        );
        assert!(
            listener.contains("https://example.com/:"),
            "the listener frame is named by the document URL: {listener}"
        );
        for engine_frame in ["__ptDispatch", "fire (", "dispatchEvent"] {
            assert!(
                !listener.contains(engine_frame),
                "no engine frames in the page stack ({engine_frame}): {listener}"
            );
        }
        assert!(
            !listener.contains("(<anonymous>:"),
            "nor unnamed scripts with a position: {listener}"
        );
        let builtin = out["builtin"].as_str().unwrap_or_default();
        assert!(
            builtin.contains("at Array.map (<anonymous>)"),
            "V8 builtins stay in the stack, as in a browser: {builtin}"
        );
        assert_eq!(
            out["identity"], true,
            "the page reads back its own `prepareStackTrace`"
        );
        assert_eq!(
            out["sites"][0], "function",
            "and gets real call sites, not strings"
        );
    }

    /// `importNode` was listed but returned nothing, so a page moving template content
    /// into the body (as the Cloudflare challenge does) failed on
    /// `replaceChild(undefined, …)`. Error messages are fingerprint surface too: foreign
    /// code misuses these methods on purpose and compares the text verbatim.
    #[tokio::test]
    async fn a_document_imports_a_node_and_complains_like_a_browser() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const say = (f) => { try { f(); return 'no error'; }
                                 catch (e) { return e.constructor.name + ': ' + e.message; } };
            const t = document.createElement('template');
            t.innerHTML = '<div id=a><span>x</span></div>';
            const div = document.createElement('div');
            document.body.appendChild(div);
            document.body.replaceChild(document.importNode(t.content, true), div);
            const loose = document.createElement('b');
            document.body.appendChild(loose);
            const taken = document.adoptNode(loose);
            return __ptJSON.stringify({
              imported: !!document.body.querySelector('#a'),
              shallow: document.importNode(t.content, false).childNodes.length,
              adopted: taken === loose && taken.parentNode === null,
              noArgs: say(() => document.importNode()),
              notNode: say(() => document.importNode(undefined, true)),
              wholeDoc: say(() => document.importNode(document, true)),
              replaceNothing: say(() => document.body.replaceChild(undefined, document.body.firstChild)),
              replaceStranger: say(() => document.body.replaceChild(div, document.createElement('i'))),
              insertOnce: say(() => document.body.insertBefore(div)),
            });
        })()"#).await;

        assert_eq!(out["imported"], true, "template content landed in the body");
        assert_eq!(out["shallow"], 0, "without `deep` only the node itself is copied");
        assert_eq!(out["adopted"], true);
        assert_eq!(
            out["noArgs"],
            "TypeError: Failed to execute 'importNode' on 'Document': 1 argument required, but only 0 present."
        );
        assert_eq!(
            out["notNode"],
            "TypeError: Failed to execute 'importNode' on 'Document': parameter 1 is not of type 'Node'."
        );
        assert_eq!(
            out["wholeDoc"],
            "DOMException: Failed to execute 'importNode' on 'Document': The node provided is a document, which may not be imported."
        );
        assert_eq!(
            out["replaceNothing"],
            "TypeError: Failed to execute 'replaceChild' on 'Node': parameter 1 is not of type 'Node'."
        );
        assert_eq!(
            out["replaceStranger"],
            "DOMException: Failed to execute 'replaceChild' on 'Node': The node to be replaced is not a child of this node."
        );
        assert_eq!(
            out["insertOnce"],
            "TypeError: Failed to execute 'insertBefore' on 'Node': 2 arguments required, but only 1 present."
        );
    }

    /// The codec poll goes into the challenge report whole, and our rule ("known
    /// container plus known codec") was three times wider than the browser's. Chrome
    /// checks the codec against the container, and MediaSource has its own list, not
    /// `canPlayType`'s. Both tables from 597 strings on Chrome 151; pinned here are the
    /// answers the old rule got wrong.
    #[tokio::test]
    async fn codecs_are_answered_container_by_container() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const v = document.createElement('video');
            const a = document.createElement('audio');
            const ask = (t) => (t.slice(0, 5) === 'audio' ? a : v).canPlayType(t);
            return __ptJSON.stringify({
              mp4ac3: ask('audio/mp4; codecs="ac-3"'),
              mp4ec3: ask('audio/mp4; codecs="ec-3"'),
              mp4vp8: ask('video/mp4; codecs="vp8"'),
              mp4avc: ask('video/mp4; codecs="avc1.42E01E"'),
              mp4pair: ask('video/mp4; codecs="avc1.42E01E, mp4a.40.2"'),
              webmAvc: ask('video/webm; codecs="avc1.42E01E"'),
              webmVp9: ask('video/webm; codecs="vp9"'),
              theora: ask('video/ogg; codecs="theora"'),
              mkvBare: ask('video/x-matroska;'),
              mkvVp8: ask('video/x-matroska; codecs="vp8"'),
              hls: ask('application/x-mpegurl;'),
              mpegBare: ask('audio/mpeg;'),
              mpegOpus: ask('audio/mpeg; codecs="opus"'),
              wavPcm: ask('audio/x-wav; codecs="1"'),
              mseTs: MediaSource.isTypeSupported('video/mp2t;'),
              mseMp4Mp3: MediaSource.isTypeSupported('video/mp4; codecs="mp3"'),
              mseMp4Avc: MediaSource.isTypeSupported('video/mp4; codecs="avc1.42E01E"'),
              mseMkv: MediaSource.isTypeSupported('video/x-matroska; codecs="vp8"'),
              mseAacBare: MediaSource.isTypeSupported('audio/aac;'),
              mseMp4Bare: MediaSource.isTypeSupported('audio/mp4;'),
            });
        })()"#).await;

        for (key, want) in [
            ("mp4ac3", ""),
            ("mp4ec3", ""),
            ("mp4vp8", ""),
            ("mp4avc", "probably"),
            ("mp4pair", "probably"),
            ("webmAvc", ""),
            ("webmVp9", "probably"),
            ("theora", ""),
            ("mkvBare", "maybe"),
            ("mkvVp8", "probably"),
            ("hls", "maybe"),
            ("mpegBare", "probably"),
            ("mpegOpus", ""),
            ("wavPcm", "probably"),
        ] {
            assert_eq!(out[key], want, "{key} answers unlike a browser: {out}");
        }
        assert_eq!(out["mseTs"], true, "MediaSource accepts MPEG-TS");
        assert_eq!(out["mseMp4Mp3"], false, "but not mp3 in mp4, though canPlayType says `probably`");
        assert_eq!(out["mseMp4Avc"], true);
        assert_eq!(out["mseMkv"], false, "MediaSource rejects Matroska entirely");
        assert_eq!(out["mseAacBare"], true);
        assert_eq!(out["mseMp4Bare"], false);
    }

    /// Our offscreen canvas is a real `<canvas>` underneath and did its work through
    /// page-visible names: a collector wrapping `HTMLCanvasElement.prototype.getContext`
    /// counted an extra call per offscreen canvas that a browser never makes.
    #[tokio::test]
    async fn an_offscreen_canvas_leaves_no_trace_on_the_page() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const seen = (window.__seen = []);
            const G = HTMLCanvasElement.prototype.getContext;
            HTMLCanvasElement.prototype.getContext = function (t) { seen.push('ctx:' + t); return G.apply(this, arguments); };
            const C = Document.prototype.createElement;
            Document.prototype.createElement = function (t) { seen.push('el:' + t); return C.apply(this, arguments); };
            const U = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function () { seen.push('url'); return U.apply(this, arguments); };
            const off = new OffscreenCanvas(16, 16);
            const g = off.getContext('2d');
            g.fillStyle = '#f0f';
            g.fillRect(0, 0, 8, 8);
            const px = Array.from(g.getImageData(0, 0, 1, 1).data);
            const bmp = off.transferToImageBitmap();
            // And what the engine does itself: `createImageBitmap` builds on its own canvas,
            // and our WebGPU sits on WebGL; the page must see neither.
            Promise.all([
              createImageBitmap(off, 0, 0, 4, 4),
              (navigator.gpu ? navigator.gpu.requestAdapter().then((a) => a && a.requestDevice()) : null),
            ]).then(([cut, dev]) => { window.__cut = cut.width + 'x' + cut.height; window.__gpu = !!dev; });
            return __ptJSON.stringify({
              seen, px, bmp: bmp.width + 'x' + bmp.height,
              tag: Object.prototype.toString.call(g),
            });
        })()"#).await;
        // Bitmap and device come as promises: let the event loop finish.
        ctx.run_event_loop().await.unwrap();
        let later = probe(
            &ctx,
            "__ptJSON.stringify({ cut: window.__cut || '', gpu: !!window.__gpu,                seen: (window.__seen || []).length })",
        )
        .await;

        assert_eq!(
            out["seen"].as_array().map(Vec::len),
            Some(0),
            "the page must see no calls: {out}"
        );
        assert_eq!(out["px"][0], 255, "and the offscreen canvas still draws: {out}");
        assert_eq!(out["px"][2], 255);
        assert_eq!(out["bmp"], "16x16");
        assert_eq!(out["tag"], "[object OffscreenCanvasRenderingContext2D]");
        assert_eq!(later["cut"], "4x4", "a cropped bitmap still works: {later}");
        assert_eq!(later["gpu"], true, "and WebGPU builds over our GL: {later}");
    }

    /// Markup parsing and the `new Image`/`new Audio` factories went through
    /// page-visible names: setting `innerHTML` showed dozens of
    /// `createElement`/`appendChild`/`setAttribute` calls to anyone wrapping them. In a
    /// browser this work is internal and invisible.
    #[tokio::test]
    async fn building_markup_does_not_call_the_page_back() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const seen = [];
            const wrap = (obj, name) => {
              const F = obj[name];
              obj[name] = function (...a) { seen.push(name); return F.apply(this, a); };
            };
            for (const n of ['createTextNode', 'createComment', 'createDocumentFragment'])
              wrap(Document.prototype, n);
            wrap(Node.prototype, 'appendChild');
            wrap(Node.prototype, 'insertBefore');
            wrap(Element.prototype, 'setAttribute');
            wrap(Element.prototype, 'getAttribute');
            wrap(Element.prototype, 'hasAttribute');
            wrap(Element.prototype, 'removeAttribute');
            wrap(Node.prototype, 'removeChild');
            const host = document.body;
            host.innerHTML = '<p class=x>\u043f\u0440\u0438\u0432\u0435\u0442 <b>\u043c\u0438\u0440</b><!--\u0442\u0443\u0442--></p>';
            const img = new Image(5, 7);
            const audio = new Audio('/x.mp3');
            // Reflected attributes, style, classes, text and markup insertion are native work
            // in a browser, invisible to the hook.
            const div = document.createElement('div');
            host.insertBefore(div, host.firstChild);
            div.style.color = 'red';
            div.classList.add('a');
            div.textContent = '\u043f\u0440\u0438\u0432\u0435\u0442';
            div.insertAdjacentHTML('beforeend', '<i>x</i>');
            img.src = 'https://example.com/x.png';
            const style = getComputedStyle(div).color;
            return __ptJSON.stringify({
              seen,
              markup: host.querySelector('p').outerHTML,
              img: img.width + 'x' + img.height,
              audio: audio.getAttribute('src'),
              colour: style,
              cls: div.className,
              text: div.innerHTML,
            });
        })()"#).await;

        // `host.insertBefore` and `audio.getAttribute` count, since the page called them;
        // everything else the engine must do silently.
        let seen: Vec<&str> = out["seen"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        assert_eq!(
            seen,
            vec!["insertBefore", "getAttribute"],
            "the page must not see the engine's internal calls: {out}"
        );
        assert_eq!(
            out["markup"], "<p class=\"x\">\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442} <b>\u{43c}\u{438}\u{440}</b><!--\u{442}\u{443}\u{442}--></p>",
            "and the markup still parses: {out}"
        );
        assert_eq!(out["img"], "5x7");
        assert_eq!(out["audio"], "/x.mp3");
        assert_eq!(
            out["colour"], "rgb(255, 0, 0)",
            "style is set and serialized as in a browser: {out}"
        );
        assert_eq!(out["cls"], "a");
        assert_eq!(out["text"], "\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}<i>x</i>");
    }

    /// The challenge captures the whole computed style, the largest part of its report.
    /// Ours was "almost": colours kept the author's form (`red`, `#0f0`, `hsl(...)`),
    /// shorthands were not expanded to longhands, and shorthands themselves showed up
    /// as extra names. Numbers from Chrome 151.
    #[tokio::test]
    async fn a_computed_style_answers_like_a_browser() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            concat!(r#"<html><head><style>
              body { font: 16px/1.4 system-ui, sans-serif; color: #111; }
              #w { display: flex; border: 1px solid #e0e0e0; border-radius: 4px;
                   box-shadow: 0 0 5px rgba(0,0,0,0.1); background: rgba(255,255,255,0.9); }
              #box { border: 2px solid rgb(0, 120, 212); background: blue; margin: 4px 8px;
                     outline: 1px dotted green; transition: all .2s ease-in-out;
                     font: italic small-caps bold 14px/1.5 Georgia, serif;
                     text-decoration: underline dotted red; }
              a { color: rebeccapurple; }
            </style></head><body>
              <div id=w><div id=box></div><a id=lnk href=#>"#, "\u{441}\u{441}\u{44b}\u{43b}\u{43a}\u{430}", r#"</a></div>
            </body></html>"#),
        )
        .await
        .unwrap();

        let out = probe(&ctx, r#"(() => {
            const cs = (id) => getComputedStyle(document.getElementById(id));
            const w = cs('w'), box = cs('box'), lnk = cs('lnk');
            let names = 0, shorthands = 0;
            for (let i = 0; i < box.length; i++) {
              names++;
              if (['font', 'background', 'border', 'margin', 'outline', 'flex', 'gap',
                   'overflow', 'inset', 'border-radius', 'padding', 'transition',
                   'list-style', 'place-items', 'grid-area'].includes(box[i])) shorthands++;
            }
            return __ptJSON.stringify({
              names, shorthands,
              bgW: w.backgroundColor, radiusW: w.borderStartStartRadius, shadowW: w.boxShadow,
              lineW: w.lineHeight, borderW: w.borderTopColor + '|' + w.borderTopStyle + '|' + w.borderTopWidth,
              logical: w.borderBlockStartColor,
              bgBox: box.backgroundColor, sizeBox: box.fontSize, lineBox: box.lineHeight,
              variantBox: box.fontVariant, styleBox: box.fontStyle,
              decorBox: box.textDecoration, outlineBox: box.outlineColor + '|' + box.outlineStyle,
              transBox: box.transitionDuration + '|' + box.transitionTimingFunction,
              minBox: box.minHeight, displayBox: box.display,
              caretBox: box.caretColor,
              colourLnk: lnk.color, cursorLnk: lnk.cursor, decorLnk: lnk.textDecorationLine,
              fontW: w.font, fontBox: box.font, transitionBox: box.transition,
              webkitBox: box.webkitBorderAfter, webkitAlias: w.webkitFlexDirection,
              strokeLnk: lnk.webkitTextStroke,
            });
        })()"#).await;

        assert_eq!(out["names"], 475, "as many names as a browser: {out}");
        assert_eq!(out["shorthands"], 0, "no shorthands among them");
        assert_eq!(out["bgW"], "rgba(255, 255, 255, 0.9)");
        assert_eq!(out["radiusW"], "4px", "logical corner mirrors the physical one");
        assert_eq!(out["shadowW"], "rgba(0, 0, 0, 0.1) 0px 0px 5px 0px");
        assert_eq!(out["lineW"], "22.4px", "a multiplier serializes in pixels");
        assert_eq!(out["borderW"], "rgb(224, 224, 224)|solid|1px");
        assert_eq!(out["logical"], "rgb(224, 224, 224)");
        assert_eq!(out["bgBox"], "rgb(0, 0, 255)");
        assert_eq!(out["sizeBox"], "14px", "font size from the `font` shorthand");
        assert_eq!(out["lineBox"], "21px");
        assert_eq!(out["variantBox"], "small-caps");
        assert_eq!(out["styleBox"], "italic");
        assert_eq!(out["decorBox"], "underline dotted rgb(255, 0, 0)");
        assert_eq!(out["outlineBox"], "rgb(0, 128, 0)|dotted");
        assert_eq!(out["transBox"], "0.2s|ease-in-out");
        assert_eq!(out["minBox"], "auto", "flex item: min is `auto`");
        assert_eq!(out["displayBox"], "block");
        assert_eq!(out["caretBox"], "rgb(17, 17, 17)", "`currentColor` is the element's colour");
        assert_eq!(out["colourLnk"], "rgb(102, 51, 153)");
        assert_eq!(out["fontW"], "16px / 22.4px system-ui, sans-serif",
                   "the `font` shorthand serializes whole, with line height: {out}");
        assert_eq!(out["fontBox"], "italic small-caps 700 14px / 21px Georgia, serif");
        assert_eq!(out["transitionBox"], "0.2s ease-in-out");
        assert_eq!(out["webkitBox"], "2px solid rgb(0, 120, 212)",
                   "vendor names of logical sides answer the same: {out}");
        assert_eq!(out["webkitAlias"], "row",
                   "`webkitFlexDirection` is just an alias of `flex-direction`");
        assert_eq!(out["strokeLnk"], "0px rgb(102, 51, 153)");
        assert_eq!(out["cursorLnk"], "pointer", "a link has its UA style");
        assert_eq!(out["decorLnk"], "underline");
    }

    /// `local("Name")` in `@font-face` is how pages enumerate installed fonts: the
    /// promise resolves for an existing name and rejects with a network error otherwise.
    /// Our `FontFace` constructor threw `TypeError`, dropping a whole report block (five
    /// families in a browser). fontconfig substitutes do not count: the browser matches
    /// the files' own names, so `Arial` is not found here and `Liberation Sans` is.
    #[tokio::test]
    async fn local_fonts_are_found_by_their_own_names() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(r#"(() => {
            window.__out = { shape: Object.getOwnPropertyNames(FontFace.prototype).sort().join(','),
                             len: FontFace.length,
                             tag: Object.prototype.toString.call(new FontFace('x', 'local("DejaVu Sans")')) };
            window.__out.native = typeof __pt_localFont === 'function';
            const names = ['DejaVu Sans', 'Liberation Sans', 'Arial', 'Zzz Quux'];
            const faces = names.map((n) => new FontFace('\u043f\u0440\u043e\u0431\u0430', 'local("' + n + '")'));
            window.__out.before = faces[0].status;
            Promise.all(faces.map((f, i) => f.load().then(() => names[i], (e) => e.name)))
              .then((r) => { window.__out.result = r; window.__out.after = faces.map((f) => f.status); });
            const set = document.fonts;
            set.add(faces[0]);
            window.__out.size = set.size;
            window.__out.has = set.has(faces[0]);
            set.delete(faces[0]);
            window.__out.sizeAfter = set.size;
        })()"#).await.unwrap();
        ctx.run_event_loop().await.unwrap();

        let out = probe(&ctx, "__ptJSON.stringify(window.__out)").await;
        assert_eq!(
            out["shape"],
            "ascentOverride,constructor,descentOverride,display,family,featureSettings,\
lineGapOverride,load,loaded,sizeAdjust,status,stretch,style,unicodeRange,variant,\
variationSettings,weight",
            "interface shape as in a browser: {out}"
        );
        assert_eq!(out["len"], 2);
        assert_eq!(out["tag"], "[object FontFace]");
        assert_eq!(out["before"], "unloaded");
        // A build without `render` knows no fonts: it rejects everything, so only the
        // shape is checked.
        if out["native"] == true {
            assert_eq!(
                out["result"],
                serde_json::json!(["DejaVu Sans", "Liberation Sans", "NetworkError", "NetworkError"]),
                "installed fonts found, substituted and made-up ones not: {out}"
            );
            assert_eq!(
                out["after"],
                serde_json::json!(["loaded", "loaded", "error", "error"])
            );
        } else {
            assert_eq!(
                out["result"],
                serde_json::json!(["NetworkError", "NetworkError", "NetworkError", "NetworkError"]),
                "without fonts everything rejects: {out}"
            );
        }
        assert_eq!(out["size"], 1, "the set is real: {out}");
        assert_eq!(out["has"], true);
        assert_eq!(out["sizeAfter"], 0);
    }

    /// The audio context renders the graph rather than a fixed synthesis: it used to
    /// always render oscillator plus compressor whatever the page connected. The
    /// compressor must also report `reduction` (a smoothed minimum in dB), which pages
    /// read. Numbers from Chrome 151 on the same graph.
    #[tokio::test]
    async fn an_audio_graph_is_rendered_node_by_node() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(r#"(() => {
            const run = async () => {
              const ac = new OfflineAudioContext(1, 8192, 44100);
              const buf = ac.createBuffer(1, 8192, 44100);
              const d = buf.getChannelData(0);
              for (let i = 0; i < 8192; i++) d[i] = Math.sin(i * 0.07) * (0.2 + 0.8 * Math.sin(i * 0.0004));
              const src = ac.createBufferSource();
              src.buffer = buf;
              const comp = ac.createDynamicsCompressor();
              comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
              comp.attack.value = 0; comp.release.value = 0.25;
              const gain = ac.createGain();
              gain.gain.value = 0.5;
              src.connect(comp); comp.connect(gain); gain.connect(ac.destination);
              src.start(0);
              const out = (await ac.startRendering()).getChannelData(0);
              // An unconnected graph is silent, as in a browser.
              const mute = new OfflineAudioContext(1, 128, 44100);
              const lone = mute.createOscillator();
              lone.start(0);
              const silence = (await mute.startRendering()).getChannelData(0);
              window.__audio = {
                samples: [out[500], out[1000], out[4000]],
                reduction: comp.reduction,
                silent: Array.from(silence).every((x) => x === 0),
              };
            };
            run();
        })()"#).await.unwrap();
        ctx.run_event_loop().await.unwrap();

        let out = probe(&ctx, "__ptJSON.stringify(window.__audio)").await;
        let got: Vec<f64> = out["samples"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_f64()).collect())
            .unwrap_or_default();
        // The gain is half the compressor's output, so the whole graph was traversed.
        let want = [-0.05188492, 0.11460970, -0.13615012];
        assert_eq!(got.len(), 3, "three samples: {out}");
        for (i, (a, b)) in got.iter().zip(want.iter()).enumerate() {
            assert!(
                (a - b).abs() < 1e-6,
                "sample {i}: {a} vs browser {b} ({out})"
            );
        }
        let reduction = out["reduction"].as_f64().unwrap_or_default();
        assert!(
            (reduction + 20.2256).abs() < 1e-3,
            "compressor reduction as in a browser: {reduction} ({out})"
        );
        assert_eq!(out["silent"], true, "an unconnected node is silent: {out}");
    }

    /// Things pages touch in passing and collectors on purpose, each checked against
    /// Chrome 151: `DOMParser` and `XMLSerializer` were empty name-table classes,
    /// FormData and URLSearchParams did not iterate, transfer did not detach the source
    /// buffer, `CSS.supports` accepted a made-up property, `TextDecoder` knew only Latin-1.
    #[tokio::test]
    async fn the_odds_and_ends_answer_like_a_browser() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const say = (f) => { try { return f(); } catch (e) { return 'threw ' + e.name; } };
            const p = new URLSearchParams('a=1&a=2&b=');
            const fd = new FormData();
            fd.append('a', '1'); fd.append('a', '2');
            const buf = new ArrayBuffer(8);
            const moved = structuredClone(buf, { transfer: [buf] });
            const doc = new DOMParser().parseFromString('<p>\u043f\u0440\u0438\u0432\u0435\u0442</p>', 'text/html');
            return __ptJSON.stringify({
              params: [p.getAll('a'), p.toString(), [...p].length, p.size],
              form: [[...fd.keys()], [...fd].length],
              transfer: [moved.byteLength, buf.byteLength],
              parsed: [doc.body.firstChild.tagName, doc.body.textContent, doc.contentType],
              xml: new XMLSerializer().serializeToString(document.createElement('div')),
              xmlVoid: new XMLSerializer().serializeToString(document.createElement('br')),
              supports: [CSS.supports('display', 'grid'), CSS.supports('display: flex'),
                         CSS.supports('foo: bar'), CSS.supports('--x: 1')],
              decoded: new TextDecoder('windows-1251').decode(new Uint8Array([207, 240, 232, 226, 229, 242])),
              koi: new TextDecoder('koi8-r').decode(new Uint8Array([208, 210, 201, 215, 197, 212])),
              labels: [new TextDecoder('cp1251').encoding, new TextDecoder('latin1').encoding],
              // The five windows-1252 "holes" (0x81, 0x8D, 0x8F, 0x90, 0x9D) are C1 controls per
              // the Encoding Standard, not U+FFFD: the challenge canvas is read byte by byte via this decoder.
              holes: [...new TextDecoder('windows-1252').decode(new Uint8Array([0x80, 0x81, 0x8d, 0x8f, 0x90, 0x9d, 0xff]))].map((c) => c.charCodeAt(0)),
              koiu: [...new TextDecoder('koi8-u').decode(new Uint8Array([0xae, 0xbe]))].map((c) => c.charCodeAt(0)),
              badLabel: say(() => { new TextDecoder('bogus'); return 'no throw'; }),
              requestType: new Request('https://example.com/x', { method: 'POST', body: 'b' })
                .headers.get('content-type'),
              entryTypes: PerformanceObserver.supportedEntryTypes.length,
            });
        })()"#).await;

        assert_eq!(out["params"], serde_json::json!([["1", "2"], "a=1&a=2&b=", 3, 3]));
        assert_eq!(out["form"], serde_json::json!([["a", "a"], 2]));
        assert_eq!(out["transfer"], serde_json::json!([8, 0]), "transfer detaches the source buffer");
        assert_eq!(out["parsed"], serde_json::json!(["P", "\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}", "text/html"]));
        assert_eq!(out["xml"], "<div xmlns=\"http://www.w3.org/1999/xhtml\"></div>");
        assert_eq!(out["xmlVoid"], "<br xmlns=\"http://www.w3.org/1999/xhtml\" />");
        assert_eq!(out["supports"], serde_json::json!([true, true, false, true]));
        assert_eq!(out["decoded"], "\u{41f}\u{440}\u{438}\u{432}\u{435}\u{442}");
        assert_eq!(out["koi"], "\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}");
        assert_eq!(out["labels"], serde_json::json!(["windows-1251", "windows-1252"]));
        assert_eq!(out["holes"], serde_json::json!([0x20ac, 0x81, 0x8d, 0x8f, 0x90, 0x9d, 0xff]));
        assert_eq!(out["koiu"], serde_json::json!([0x45e, 0x40e]));
        assert_eq!(out["badLabel"], "threw RangeError");
        assert_eq!(out["requestType"], "text/plain;charset=UTF-8");
        assert_eq!(out["entryTypes"], 15);
    }

    /// Second pass against Chrome 151: permissions, devices, intersection observer, media
    /// session, battery, network. An empty device list describes a machine without a
    /// sound card, `prompt` for a made-up permission an engine without a table, and a
    /// 0.71 charge a laptop where we claim to be a desktop.
    #[tokio::test]
    async fn permissions_and_devices_answer_like_a_browser() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(r#"(() => {
            const out = {};
            const ask = (n) => navigator.permissions.query({ name: n })
              .then((s) => s.state, (e) => 'threw ' + e.name);
            Promise.all([ask('geolocation'), ask('accelerometer'), ask('push'), ask('bogus'),
                         navigator.mediaDevices.enumerateDevices(), navigator.getBattery()])
              .then(([geo, accel, push, bad, devices, battery]) => {
                out.perms = [geo, accel, push, bad];
                out.devices = devices.map((d) => d.kind + ':' + d.deviceId + ':' + d.label);
                out.battery = [battery.charging, battery.level, battery.chargingTime,
                               battery.dischargingTime === Infinity ? 'forever' : battery.dischargingTime];
                const io = new IntersectionObserver(() => {}, { threshold: [0, 0.5], rootMargin: '10px' });
                out.io = [io.thresholds, io.rootMargin, io.root];
                out.session = [navigator.mediaSession.playbackState,
                               typeof navigator.mediaSession.setActionHandler];
                out.constraints = Object.keys(navigator.mediaDevices.getSupportedConstraints()).length;
                out.activation = [navigator.userActivation.hasBeenActive, navigator.userActivation.isActive];
                out.scheduling = typeof navigator.scheduling.isInputPending;
                window.__nav = out;
              });
        })()"#).await.unwrap();
        ctx.run_event_loop().await.unwrap();

        let out = probe(&ctx, "__ptJSON.stringify(window.__nav)").await;
        assert_eq!(
            out["perms"],
            serde_json::json!(["prompt", "granted", "threw NotSupportedError", "threw TypeError"]),
            "permission table as in a browser: {out}"
        );
        assert_eq!(
            out["devices"],
            serde_json::json!(["audioinput::", "videoinput::", "audiooutput::"]),
            "three unnamed devices, as a browser without permission: {out}"
        );
        assert_eq!(out["battery"], serde_json::json!([true, 1, 0, "forever"]));
        assert_eq!(out["io"], serde_json::json!([[0, 0.5], "10px 10px 10px 10px", null]));
        assert_eq!(out["session"], serde_json::json!(["none", "function"]));
        assert_eq!(out["constraints"], 36);
        assert_eq!(out["activation"], serde_json::json!([false, false]),
                   "false for both before a gesture: {out}");
        assert_eq!(out["scheduling"], "function");
    }

    /// Frame rate is a common engine probe: a browser puts the timestamp on the refresh
    /// grid rounded to 0.1 ms, so neighbours differ by 16.6 or 16.7. Ours was a jittery
    /// full-precision 16 ms timer ticking an even 16.667.
    #[tokio::test]
    async fn frames_land_on_the_refresh_grid() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<html><body></body></html>")
            .await
            .unwrap();

        ctx.evaluate(r#"(() => {
            const stamps = [];
            const step = (t) => { stamps.push(t); if (stamps.length < 8) requestAnimationFrame(step); };
            requestAnimationFrame(step);
            window.__stamps = stamps;
        })()"#).await.unwrap();
        for _ in 0..4 {
            ctx.run_event_loop().await.unwrap();
        }

        let out = probe(&ctx, r#"(() => {
            const s = window.__stamps;
            const d = [];
            for (let i = 1; i < s.length; i++) d.push(Math.round((s[i] - s[i - 1]) * 1000) / 1000);
            return __ptJSON.stringify({ count: s.length, deltas: d,
              tenths: s.every((x) => Math.abs(x * 10 - Math.round(x * 10)) < 1e-9) });
        })()"#).await;

        assert!(
            out["count"].as_u64().unwrap_or(0) >= 5,
            "frames arrive one after another: {out}"
        );
        assert_eq!(out["tenths"], true, "timestamp rounded to 0.1: {out}");
        for d in out["deltas"].as_array().cloned().unwrap_or_default() {
            let v = d.as_f64().unwrap_or_default();
            assert!(
                (v - 16.6).abs() < 0.06 || (v - 16.7).abs() < 0.06,
                "neighbouring timestamps differ by 16.6 or 16.7: {v} ({out})"
            );
        }
    }

    /// A rule serializes as a browser prints it: values normalized, an overwritten
    /// property moves to the end, a shorthand with an overridden part splits into
    /// longhands, separately written sides recombine. The challenge captures `cssText`
    /// of all its rules, identical on any machine. Numbers from Chrome 151.
    #[tokio::test]
    async fn a_rule_prints_the_way_the_browser_prints_it() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html("https://example.com/", "<!doctype html><html><body></body></html>")
            .await
            .unwrap();

        let out = probe(&ctx, r#"(() => {
            const st = document.createElement('style');
            st.textContent = `
              .a { box-shadow: inset 0 0 0 rgb(34, 139, 73); }
              .b { outline: 2px solid rgb(0, 81, 195); }
              .c { grid-area: 1/1; }
              .d { transform-origin: center; }
              .e { stroke-dasharray: 0,100,0; }
              .f { transition: all 0.1s ease-in; }
              .g { animation: none; }
              .h { transform: rotate(0) translateY(0) scale(1); }
              .i { border: solid rgb(196, 77, 14); border-width: 0 4px 4px 0; }
              .j { margin-top: 1px; margin-right: 2px; margin-bottom: 3px; margin-left: 4px; }
              .k { padding: 1px; padding-left: 9px; }
              .l { stroke-width: 1px; fill: red; stroke-width: 6px; }
              .m { background: red url(x.png); }
              .n { border: 1px solid red; border-top-color: blue; }
            `;
            document.documentElement.appendChild(st);
            return __ptJSON.stringify([...st.sheet.cssRules].map((r) => r.cssText));
        })()"#).await;

        let got: Vec<String> = out
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect())
            .unwrap_or_default();
        let want = [
            ".a { box-shadow: rgb(34, 139, 73) 0px 0px 0px inset; }",
            ".b { outline: rgb(0, 81, 195) solid 2px; }",
            ".c { grid-area: 1 / 1; }",
            ".d { transform-origin: center center; }",
            ".e { stroke-dasharray: 0, 100, 0; }",
            ".f { transition: 0.1s ease-in; }",
            ".g { animation: auto ease 0s 1 normal none running none; }",
            ".h { transform: rotate(0deg) translateY(0px) scale(1); }",
            ".i { border-style: solid; border-color: rgb(196, 77, 14); border-image: none; border-width: 0px 4px 4px 0px; }",
            ".j { margin: 1px 2px 3px 4px; }",
            ".k { padding: 1px 1px 1px 9px; }",
            ".l { fill: red; stroke-width: 6px; }",
            ".m { background: url(\"x.png\") red; }",
            ".n { border-width: 1px; border-style: solid; border-color: blue red red; border-image: none; }",
        ];
        assert_eq!(got.len(), want.len(), "all rules present: {got:?}");
        for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
            assert_eq!(g, w, "rule {i}");
        }
    }

    /// Adjacent block margins collapse, and a first/last child's margin escapes through
    /// the parent's empty edge; without it two paragraphs got twice the browser's gap.
    /// Also: parsing a fragment makes no `<html>`/`<body>` nodes, and a shorthand reads
    /// via longhand names. Numbers from Chrome 151 on the same markup.
    #[tokio::test]
    async fn margins_collapse_the_way_the_browser_collapses_them() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<!doctype html><html><head><style>body{margin:0;font:16px/19px system-ui}
               p{margin:16px 0}</style></head><body>
               <div id=a><p>a</p><p>b</p></div>
               <div id=b><div style="margin:8px"></div></div>
               <div id=c style="border:1px solid"><p>a</p></div>
               <div id=d></div>
               </body></html>"#,
        )
        .await
        .unwrap();

        let out = probe(&ctx, r#"(() => {
            document.getElementById('d').innerHTML = '<html><body></body></html>';
            const pick = (id) => { const e = document.getElementById(id);
              const base = e.getBoundingClientRect();
              return { h: parseFloat(getComputedStyle(e).height),
                kids: [...e.children].map((c) => Math.round(c.getBoundingClientRect().y - base.y)) };
            };
            return __ptJSON.stringify({ a: pick('a'), b: pick('b'), c: pick('c'), d: pick('d'),
              border: document.getElementById('c').style.borderTopWidth });
        })()"#).await;

        assert_eq!(out["a"]["h"], 54.0, "two paragraphs: 19 + 16 + 19: {out}");
        assert_eq!(out["a"]["kids"][0], 0.0, "the first child's margin escaped: {out}");
        assert_eq!(out["a"]["kids"][1], 35.0, "one margin between paragraphs, not two: {out}");
        assert_eq!(out["b"]["h"], 0.0, "an empty block collapses entirely: {out}");
        assert_eq!(out["c"]["h"], 51.0, "a border keeps the margin inside: {out}");
        assert_eq!(out["c"]["kids"][0], 17.0, "border plus margin: {out}");
        assert_eq!(out["d"]["h"], 0.0, "`<html>` in a fragment makes no node: {out}");
        assert_eq!(out["d"]["kids"].as_array().map(|a| a.len()), Some(0), "and no children: {out}");
        assert_eq!(out["border"], "1px", "the shorthand reads via the longhand: {out}");
    }

    /// Inline children share a line, wrap by width and sit on a common baseline; an
    /// empty inline box makes no line. Previously every child started a new line, and
    /// widget geometry (measured by rectangles) diverged.
    ///
    /// Relations are checked, not numbers: exact pixels need font metrics, available only
    /// with `render`. Chrome 151 here gives a 19 px line, words 16 and 18 wide,
    /// inline-blocks on the baseline at 6 and 2 px from the top, and two wraps of 19.
    #[tokio::test]
    async fn inline_children_share_a_line_like_a_browser() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<!doctype html><html><head><style>body{margin:0;width:756px;font:16px system-ui}</style></head>
               <body><div id=a><span>aa</span><span>bb</span></div>
               <div id=b><span></span></div>
               <div id=c><span style="display:inline-block;width:30px;height:10px"></span
                 ><span style="display:inline-block;width:20px;height:14px"></span></div>
               <div id=d><span style="display:inline-block;width:1000px"></span
                 ><span style="display:inline-block;width:1000px"></span></div>
               </body></html>"#,
        )
        .await
        .unwrap();

        let out = probe(&ctx, r#"(() => {
            const pick = (id) => { const d = document.getElementById(id);
              const base = d.getBoundingClientRect();
              return { h: parseFloat(getComputedStyle(d).height),
                kids: [...d.children].map((c) => { const r = c.getBoundingClientRect();
                  return [Math.round(r.x - base.x), Math.round(r.y - base.y),
                          Math.round(r.width), Math.round(r.height)]; }) };
            };
            return __ptJSON.stringify({ a: pick('a'), b: pick('b'), c: pick('c'), d: pick('d') });
        })()"#).await;

        let kids = |key: &str| -> Vec<Vec<f64>> {
            out[key]["kids"]
                .as_array()
                .map(|a| a.iter().map(|r| r.as_array().unwrap().iter()
                    .filter_map(|v| v.as_f64()).collect()).collect())
                .unwrap_or_default()
        };
        let h = |key: &str| out[key]["h"].as_f64().unwrap_or_default();

        let a = kids("a");
        assert_eq!(a.len(), 2, "both words present: {out}");
        assert_eq!(a[0][1], a[1][1], "both words on one line: {out}");
        assert_eq!(a[1][0], a[0][2], "the second starts where the first ended: {out}");
        assert_eq!(a[0][3], h("a"), "line height is the box height: {out}");

        assert_eq!(h("b"), 0.0, "an empty inline box makes no line: {out}");

        let c = kids("c");
        assert_eq!(c[0][0], 0.0, "first inline-block at the left edge: {out}");
        assert_eq!(c[1][0], 30.0, "second right after it: {out}");
        assert_eq!(c[0][1] + c[0][3], c[1][1] + c[1][3],
            "both bottoms on the common baseline: {out}");
        assert!(h("c") > c[0][1] + c[0][3], "descent remains below the baseline: {out}");

        let d = kids("d");
        assert_eq!(d[0][0], 0.0, "wrapped content starts at the left: {out}");
        assert_eq!(d[1][0], 0.0, "and the second too: {out}");
        assert!(d[1][1] > d[0][1], "the second moved to a new line: {out}");
        assert_eq!(h("d"), 2.0 * h("a"), "two lines of the same height: {out}");
    }

    /// The UA stylesheet: margins of body, headings and paragraphs, direction and
    /// monospace size. The challenge captures the whole computed style, and these are
    /// identical on any machine, so they can be checked offline. Numbers from Chrome 151.
    #[tokio::test]
    async fn the_browser_own_stylesheet_shows_through_computed_style() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><body><p>a</p><h1>b</h1><pre>c</pre><ul><li>d</li></ul>
               <blockquote>e</blockquote><input><div>f</div></body></html>"#,
        )
        .await
        .unwrap();

        let out = probe(&ctx, r#"(() => {
            const g = (sel) => { const cs = getComputedStyle(document.querySelector(sel));
              return [cs.marginTop, cs.marginLeft, cs.unicodeBidi, cs.fontSize]; };
            return __ptJSON.stringify({ body: g('body'), p: g('p'), h1: g('h1'), pre: g('pre'),
              ul: g('ul'), quote: g('blockquote'), input: g('input'), div: g('div'),
              h1w: getComputedStyle(document.querySelector('h1')).fontWeight });
        })()"#).await;

        let row = |key: &str| -> Vec<String> {
            out[key]
                .as_array()
                .map(|a| a.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect())
                .unwrap_or_default()
        };
        assert_eq!(row("body"), ["8px", "8px", "normal", "16px"], "body: {out}");
        assert_eq!(row("p"), ["16px", "0px", "isolate", "16px"], "paragraph: font size on top: {out}");
        assert_eq!(row("h1"), ["21.44px", "0px", "isolate", "32px"], "heading: fraction of font size: {out}");
        assert_eq!(out["h1w"], "700", "and UA font weight: {out}");
        assert_eq!(row("pre"), ["13px", "0px", "isolate", "13px"], "monospace: {out}");
        assert_eq!(row("ul"), ["16px", "0px", "isolate", "16px"], "list: {out}");
        assert_eq!(row("quote"), ["16px", "40px", "isolate", "16px"], "quote: {out}");
        assert_eq!(row("input"), ["0px", "0px", "normal", "13.3333px"], "input: {out}");
        assert_eq!(row("div"), ["0px", "0px", "isolate", "16px"], "div: {out}");
    }

    /// Style is computed against the element's own document. A page creates a frame and
    /// measures its body through the frame window; a browser answers with defaults since
    /// the host's sheets do not reach it. We answered with the host's colour and size.
    #[tokio::test]
    async fn a_frame_body_is_styled_by_its_own_document() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><head><style>
               body { font-size: 14px; color: rgb(10, 10, 10); font-family: Arial, sans-serif }
               </style></head><body></body></html>"#,
        )
        .await
        .unwrap();

        let out = probe(&ctx, r#"(() => {
            const f = document.createElement('iframe');
            document.body.appendChild(f);
            const cs = getComputedStyle(f.contentDocument.body);
            const own = getComputedStyle(document.body);
            return __ptJSON.stringify({ frame: [cs.color, cs.fontSize, cs.fontFamily, cs.marginTop],
              host: [own.color, own.fontSize] });
        })()"#).await;

        let frame = out["frame"].as_array().expect("frame body is measured");
        assert_eq!(frame[0], "rgb(0, 0, 0)", "default colour, not the host's: {out}");
        assert_eq!(frame[1], "16px", "default font size: {out}");
        assert_eq!(frame[2], "\"Times New Roman\"", "default font: {out}");
        assert_eq!(frame[3], "8px", "margin from the UA stylesheet: {out}");
        assert_eq!(out["host"][0], "rgb(10, 10, 10)", "the host document keeps its own: {out}");
    }

    /// Flex container: children in a row, free space split by `flex-grow`, cross-axis
    /// alignment per the container, height from the style's line height, not glyph ink.
    /// Widgets are nearly always flex and collectors measure them. Numbers from Chrome
    /// 151 on the same markup.
    #[tokio::test]
    async fn a_flex_row_places_its_children_like_a_browser() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            r#"<html><head><style>
              body { margin: 0; font: 16px/1.4 system-ui, sans-serif; }
              #w { width: 300px; height: 65px; border: 1px solid #000; padding: 0 12px;
                   display: flex; align-items: center; }
              #box { width: 24px; height: 24px; border: 2px solid #000; margin: 4px 8px; }
              #txt { flex: 1 1 auto; }
            </style></head><body>
              <div id=w><div id=box></div><span id=txt>x</span></div>
            </body></html>"#,
        )
        .await
        .unwrap();

        let out = probe(&ctx, r#"(() => {
            const r = (id) => { const b = document.getElementById(id).getBoundingClientRect();
              return [Math.round(b.x * 100) / 100, Math.round(b.y * 100) / 100,
                      Math.round(b.width * 100) / 100, Math.round(b.height * 100) / 100]; };
            const cs = getComputedStyle(document.getElementById('txt'));
            return __ptJSON.stringify({ w: r('w'), box: r('box'), txt: r('txt'),
              display: cs.display, grow: cs.flexGrow, line: cs.lineHeight });
        })()"#).await;

        let nums = |key: &str| -> Vec<f64> {
            out[key]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_f64()).collect())
                .unwrap_or_default()
        };
        assert_eq!(nums("w"), vec![0.0, 0.0, 326.0, 67.0], "container box: {out}");
        assert_eq!(
            nums("box"), vec![21.0, 19.5, 28.0, 28.0],
            "first child centred on the cross axis: {out}"
        );
        let txt = nums("txt");
        assert_eq!(txt[0], 57.0, "the second starts after the first: {out}");
        assert_eq!(txt[2], 256.0, "and grows into all free space: {out}");
        assert_eq!(txt[3], 22.39, "height is the style's line height: {out}");
        assert_eq!(out["display"], "block", "a flex item is blockified");
        assert_eq!(out["grow"], "1");
        assert_eq!(out["line"], "22.4px");
    }

    /// An external stylesheet brings rules, not just a request: we dropped the body, so
    /// `document.styleSheets[i].cssRules` was empty (Chrome has thousands on a real
    /// page) and the cascade saw none of it. Also `window.length` counts live frames,
    /// one of the first things asked about a page.
    #[tokio::test]
    async fn an_external_stylesheet_brings_its_rules() {
        let _serial = serial().await;
        let engine = engine(1, 2);
        let ctx = engine.new_context().await.unwrap();
        ctx.load_html(
            "https://example.com/",
            concat!(r#"<html><head>
               <link rel="stylesheet" href="data:text/css,p%7Bcolor%3A%20rgb(1%2C%202%2C%203)%7D">
               </head><body><p id=p>"#, "\u{442}\u{435}\u{43a}\u{441}\u{442}", r#"</p></body></html>"#),
        )
        .await
        .unwrap();
        ctx.run_event_loop().await.unwrap();

        let out = probe(&ctx, r#"(() => {
            const sheet = document.styleSheets[0];
            // A string ending in an escaped backslash used to swallow the rest of the file:
            // the following quote was treated as escaped.
            const tricky = document.createElement('style');
            tricky.textContent = '@charset "utf-8"; a:before{content:"\\\\"} b{color:red} i{color:blue}';
            document.head.appendChild(tricky);
            const f = document.createElement('iframe');
            f.src = 'about:blank';
            document.body.appendChild(f);
            return __ptJSON.stringify({
              sheets: document.styleSheets.length,
              rules: sheet ? sheet.cssRules.length : -1,
              href: sheet ? String(sheet.href).slice(0, 14) : '',
              first: sheet && sheet.cssRules[0] ? sheet.cssRules[0].selectorText : '',
              applied: getComputedStyle(document.getElementById('p')).color,
              frames: window.length,
              windowed: typeof window[0],
              escaped: (() => { let n = 0; for (const r of tricky.sheet.cssRules) if (r.selectorText === 'b' || r.selectorText === 'i') n++; return n; })(),
              charset: (() => { let n = 0; for (const r of tricky.sheet.cssRules) if (r.type === 1) n++; return tricky.sheet.cssRules.length - n; })(),
            });
        })()"#).await;

        assert_eq!(out["sheets"], 2, "external sheet and the added one: {out}");
        assert!(
            out["rules"].as_i64().unwrap_or(0) >= 1,
            "and its rules parsed: {out}"
        );
        assert_eq!(out["first"], "p", "selector reads: {out}");
        assert_eq!(out["escaped"], 2, "an escaped backslash string does not break parsing: {out}");
        assert_eq!(out["charset"], 0, "`@charset` is not in the rule list: {out}");
        assert_eq!(out["applied"], "rgb(1, 2, 3)", "and the rule applies to the element: {out}");
        assert_eq!(out["frames"], 1, "the frame is counted: {out}");
        assert_eq!(out["windowed"], "object", "and reachable by index: {out}");
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

    /// A frame has its own resource timeline. We filled only the page's, so a framed
    /// document's `performance.getEntries()` was empty ("loaded nothing"), and the
    /// Turnstile collector reads it in the widget frame first thing.
    #[tokio::test]
    async fn a_frame_has_a_resource_timeline_of_its_own() {
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

        let seen = ctx
            .evaluate_in_frame(
                frame,
                "__ptJSON.stringify({\
                   nav: performance.getEntriesByType('navigation').length,\
                   name: (performance.getEntriesByType('navigation')[0] || {}).name || '',\
                   kind: (performance.getEntriesByType('navigation')[0] || {}).entryType || '',\
                 })",
            )
            .await
            .expect("frame answered");
        let seen: Value = serde_json::from_str(seen.as_str().unwrap_or("{}")).unwrap_or_default();
        assert_eq!(seen["nav"], 1, "the frame knows its navigation: {seen}");
        // Its own URL, not the page's.
        assert!(
            seen["name"].as_str().unwrap_or("").ends_with("/frame"),
            "the frame's navigation is its document: {seen}"
        );
        assert_eq!(seen["kind"], "navigation", "{seen}");
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
            // Paint entries have no `responseEnd` or body, as in a browser; check timings only where present.
            sized: performance.getEntries().every(e => e.duration >= 0
              && (e.responseEnd === undefined || e.responseEnd >= e.startTime)),
            paint: performance.getEntriesByType('paint').map(e => e.name).join(','),
        })"#).await;
        assert_eq!(timing["navigation"], 1, "the document is a navigation entry");
        assert!(
            timing["resources"].as_u64().unwrap_or(0) >= 1,
            "and what it fetched is listed: {timing}"
        );
        assert_eq!(timing["named"], "[object PerformanceNavigationTiming]");
        assert_eq!(timing["sized"], true, "with timings that make sense");
        assert_eq!(
            timing["paint"], "first-paint,first-contentful-paint",
            "and two paint entries next to the navigation, as in a browser: {timing}"
        );

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
        // The checkbox is not in the frame corner: the body has an 8 px UA margin, and the
        // checkbox 3 px of its own.
        let (x, y) = (
            rect["x"].as_f64().unwrap() + 16.0,
            rect["y"].as_f64().unwrap() + 16.0,
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

        // Windows retries a refused connect for about two seconds before giving up.
        let out = pump_until(&ctx, "__ptJSON.stringify(__log)", 400).await;
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
