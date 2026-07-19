//! Network layer.
//!
//! Phase 2 fills this in with a real HTTP client whose TLS ClientHello and
//! HTTP/2 SETTINGS are byte-compatible with current Chrome (JA3/JA4), a
//! connection pool with per-host / per-proxy / global limits, cookie store,
//! redirects and gzip/br/zstd decompression. `fetch` and `XMLHttpRequest` in the
//! JS layer are built on top of [`HttpClient`].
//!
//! For Phase 0 this crate defines the configuration surface and the
//! [`HttpClient`] trait so the rest of the engine can be wired against it; the
//! bundled [`StubClient`] returns `Unimplemented`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

mod session;
pub use session::{CookieRecord, SessionJar};

/// Errors from the network layer.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("network layer not implemented yet (Phase 2)")]
    Unimplemented,
    #[error("request timed out")]
    Timeout,
    #[error("connection error: {0}")]
    Connect(String),
    #[error("all connection slots for host `{0}` are in use")]
    HostSaturated(String),
}

/// Which browser's network fingerprint to emulate. Must stay coherent with the
/// JS-level fingerprint chosen in the stealth layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FingerprintProfile {
    /// Track current stable Chrome on desktop Linux/Windows.
    #[default]
    ChromeDesktop,
}

/// A proxy the client can route through. Rotation is handled by the pool in the
/// scaling phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyScheme {
    Http,
    Socks5,
}

/// Connection-pool and concurrency limits. These are the network-side half of
/// the engine's global backpressure story.
#[derive(Debug, Clone)]
pub struct PoolLimits {
    /// Max concurrent connections to a single host.
    pub per_host: usize,
    /// Max concurrent connections routed through a single proxy.
    pub per_proxy: usize,
    /// Global cap on open connections across all hosts.
    pub global: usize,
    /// Idle keep-alive timeout before a pooled connection is closed.
    pub idle_timeout: Duration,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            per_host: 6, // Chrome's classic per-host cap
            per_proxy: 64,
            global: 256,
            idle_timeout: Duration::from_secs(90),
        }
    }
}

/// Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub fingerprint: FingerprintProfile,
    pub limits: PoolLimits,
    pub proxy: Option<ProxyConfig>,
    pub request_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            fingerprint: FingerprintProfile::default(),
            limits: PoolLimits::default(),
            proxy: None,
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// A minimal HTTP request. Header *order* is significant for fingerprinting and
/// is preserved by the eventual implementation, so the real request type will
/// carry an ordered header list rather than a map — this Phase 0 shape is a
/// placeholder.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
}

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    /// Final URL after any redirects were followed — the origin the body
    /// actually came from. Callers use it as the document base URL.
    pub url: String,
}

/// The engine talks to the network exclusively through this trait, so the TLS
/// implementation can evolve without touching callers.
pub trait HttpClient: Send + Sync {
    /// Perform a request, returning the response once fully received.
    fn send(
        &self,
        req: Request,
    ) -> impl std::future::Future<Output = Result<Response, NetError>> + Send;
}

/// Placeholder client used until Phase 2 lands. Every request fails with
/// [`NetError::Unimplemented`].
#[derive(Debug, Clone, Default)]
pub struct StubClient {
    pub config: ClientConfig,
}

impl StubClient {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }
}

impl HttpClient for StubClient {
    async fn send(&self, req: Request) -> Result<Response, NetError> {
        tracing::warn!(url = %req.url, "StubClient: network not implemented");
        Err(NetError::Unimplemented)
    }
}

/// A real HTTP client whose TLS ClientHello (JA3/JA4) and HTTP/2 fingerprint
/// match Chrome, backed by `wreq` (BoringSSL). This is the Phase 2 transport: it
/// emulates a full Chrome profile — cipher list, extension order, GREASE, ALPN,
/// HTTP/2 SETTINGS, and the coherent Chrome request-header set.
///
/// Because the emulation owns the fingerprint-sensitive headers (User-Agent,
/// Accept*, sec-ch-*, and their order), callers' versions of those are dropped;
/// keep [`nokk_stealth`]'s JS `navigator` in step with [`Self::EMULATION`].
#[derive(Clone)]
pub struct FingerprintClient {
    inner: wreq::Client,
}

/// Header names the emulation profile owns; caller-supplied values for these are
/// ignored so the on-the-wire fingerprint stays coherent.
const FP_OWNED_HEADERS: &[&str] = &[
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "host",
    "connection",
];

impl FingerprintClient {
    /// The Chrome version we impersonate; must agree with the stealth JS profile.
    /// Newer emulations track Chrome's current TLS + request-header set more
    /// closely (Cloudflare fingerprints header order, so accuracy matters).
    pub const EMULATION: wreq_util::Emulation = wreq_util::Emulation::Chrome137;
    /// The OS we impersonate. Pinned to Linux so the wire `User-Agent` /
    /// `sec-ch-ua-platform` match the stealth JS `navigator.platform` (Linux) —
    /// the emulation otherwise defaults to macOS, which would make the HTTP UA
    /// and the JS UA disagree (an instant anti-bot tell).
    pub const EMULATION_OS: wreq_util::EmulationOS = wreq_util::EmulationOS::Linux;

    pub fn new(config: &ClientConfig) -> Result<Self, NetError> {
        Self::with_session(config, None)
    }

    /// Like [`Self::new`], but backs the client's cookie jar with a persistent
    /// [`SessionJar`] instead of a fresh in-memory one. Cookies set by redirects
    /// or earlier requests (incl. any `cf_clearance`) accumulate in the shared
    /// jar, which the caller can save to disk and reload into a later client —
    /// the basis for warm-up-once, resume-anytime named sessions.
    pub fn with_session(
        config: &ClientConfig,
        session: Option<Arc<SessionJar>>,
    ) -> Result<Self, NetError> {
        let _ = config.fingerprint; // only ChromeDesktop today; see EMULATION
        let emulation = wreq_util::EmulationOption::builder()
            .emulation(Self::EMULATION)
            .emulation_os(Self::EMULATION_OS)
            .build();
        let mut builder = wreq::Client::builder().emulation(emulation);
        builder = match session {
            // A named/persistent session: cookies live in a jar the caller owns
            // (and can serialize). Shared across contexts of the same identity.
            Some(jar) => builder.cookie_provider(jar),
            // Default: a private in-memory jar, replayed within this engine only.
            None => builder.cookie_store(true),
        };
        builder = builder
            // Follow 3xx redirects like a real browser (wreq defaults to *none*).
            // Without this, navigating to e.g. `google.com` returns the `301
            // Moved` body instead of the destination page. Capped at 10 hops.
            .redirect(wreq::redirect::Policy::limited(10))
            .timeout(config.request_timeout);

        if let Some(p) = &config.proxy {
            let scheme = match p.scheme {
                ProxyScheme::Http => "http",
                ProxyScheme::Socks5 => "socks5",
            };
            let url = format!("{scheme}://{}:{}", p.host, p.port);
            let mut proxy = wreq::Proxy::all(&url).map_err(|e| NetError::Connect(e.to_string()))?;
            if let Some(user) = &p.username {
                proxy = proxy.basic_auth(user, p.password.as_deref().unwrap_or(""));
            }
            builder = builder.proxy(proxy);
        }

        let inner = builder
            .build()
            .map_err(|e| NetError::Connect(e.to_string()))?;
        Ok(Self { inner })
    }
}

impl HttpClient for FingerprintClient {
    async fn send(&self, req: Request) -> Result<Response, NetError> {
        // Normalise the method so a lowercase `fetch(url, {method:'get'})` from
        // page JS is accepted rather than reported as an unsupported method.
        let mut rb = match req.method.to_ascii_uppercase().as_str() {
            "GET" => self.inner.get(&req.url),
            "POST" => self.inner.post(&req.url),
            "PUT" => self.inner.put(&req.url),
            "DELETE" => self.inner.delete(&req.url),
            "HEAD" => self.inner.head(&req.url),
            "PATCH" => self.inner.patch(&req.url),
            "OPTIONS" => self.inner.request(wreq::Method::OPTIONS, &req.url),
            other => return Err(NetError::Connect(format!("unsupported method {other}"))),
        };
        // Forward only headers the emulation profile does not own, so the Chrome
        // fingerprint (values + order) is preserved.
        for (k, v) in &req.headers {
            let lk = k.to_ascii_lowercase();
            if FP_OWNED_HEADERS.contains(&lk.as_str()) || lk.starts_with("sec-") {
                continue;
            }
            rb = rb.header(k, v);
        }
        if let Some(body) = req.body {
            rb = rb.body(body);
        }
        let resp = rb.send().await.map_err(|e| {
            if e.is_timeout() {
                NetError::Timeout
            } else {
                NetError::Connect(e.to_string())
            }
        })?;
        let status = resp.status().as_u16();
        // Final URL after redirects — captured before `bytes()` consumes `resp`.
        let url = resp.url().to_string();
        let mut headers = BTreeMap::new();
        for (k, v) in resp.headers() {
            if let Ok(s) = v.to_str() {
                headers.insert(k.to_string(), s.to_string());
            }
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| NetError::Connect(e.to_string()))?
            .to_vec();
        Ok(Response {
            status,
            url,
            headers,
            body,
        })
    }
}

/// A client the engine can hold by value regardless of which implementation is
/// active. Needed because [`HttpClient`] returns `impl Future` and so is not
/// object-safe (`dyn HttpClient` is impossible).
#[derive(Clone)]
pub enum Client {
    Stub(StubClient),
    Fingerprint(FingerprintClient),
}

impl HttpClient for Client {
    async fn send(&self, req: Request) -> Result<Response, NetError> {
        match self {
            Client::Stub(c) => c.send(req).await,
            Client::Fingerprint(c) => c.send(req).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_match_chrome_per_host() {
        assert_eq!(PoolLimits::default().per_host, 6);
    }

    fn req(method: &str, url: &str) -> Request {
        Request {
            method: method.into(),
            url: url.into(),
            headers: BTreeMap::new(),
            body: None,
        }
    }

    #[tokio::test]
    async fn stub_client_reports_unimplemented() {
        let client = StubClient::default();
        assert!(matches!(
            client.send(req("GET", "https://example.com")).await,
            Err(NetError::Unimplemented)
        ));
    }

    #[tokio::test]
    async fn client_enum_delegates_to_stub() {
        let client = Client::Stub(StubClient::default());
        assert!(matches!(
            client.send(req("GET", "https://example.com")).await,
            Err(NetError::Unimplemented)
        ));
    }

    #[tokio::test]
    async fn fingerprint_client_rejects_unknown_method_without_network() {
        // The method check short-circuits before any socket I/O, so this stays
        // offline. A genuinely unsupported verb is a Connect error naming it.
        let client = FingerprintClient::new(&ClientConfig::default()).unwrap();
        let err = client.send(req("TRACE", "https://example.com")).await;
        match err {
            Err(NetError::Connect(msg)) => assert!(msg.contains("TRACE"), "got: {msg}"),
            other => panic!("expected unsupported-method Connect error, got {other:?}"),
        }
    }
}
