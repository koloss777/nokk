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

mod blocklist;
mod client_hints;
mod geoip;
mod session;
mod websocket;
pub use client_hints::HintValues;
pub use blocklist::{host_of, is_blocked, is_blocked_url};
pub use geoip::{parse_geo, GeoInfo, GEO_LOOKUP_URL};
pub use session::{CookieRecord, SessionJar};
pub use websocket::{open as open_websocket, WsCommand, WsEvent, WsHandle};

/// Errors from the network layer.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("network layer not implemented yet (Phase 2)")]
    Unimplemented,
    #[error("request timed out")]
    Timeout,
    #[error("connection error: {0}")]
    Connect(String),
    /// No route to the host (e.g. IPv6-only names here). Chrome does not fail
    /// such a request at once: it hangs until its own connect timeout, so the
    /// waiting page gets silence, not an error.
    #[error("host unreachable: {0}")]
    Unreachable(String),
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

/// Which desktop OS the TLS ClientHello (JA3/JA4) and HTTP/2 fingerprint emulate.
/// Must match the JS profile's OS and User-Agent, or the handshake contradicts the
/// UA — a documented anti-bot tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EmulationOs {
    #[default]
    Linux,
    Windows,
    Mac,
}

impl EmulationOs {
    fn to_platform(self) -> wreq_util::Platform {
        match self {
            Self::Linux => wreq_util::Platform::Linux,
            Self::Windows => wreq_util::Platform::Windows,
            Self::Mac => wreq_util::Platform::MacOS,
        }
    }
}

/// The Chrome major version emulated by default — current stable. Keep in step
/// with `nokk_stealth::CHROME_MAJOR`. The handshake itself uses the newest
/// profile `wreq-util` knows; see [`profile_for_major`].
pub const DEFAULT_CHROME_MAJOR: u32 = 151;

/// Rewrites the Chrome version in the profile headers: `user-agent` and the
/// `sec-ch-ua` brands must agree with `navigator.userAgent` and
/// `navigator.userAgentData.brands` in JS.
fn retag_chrome_version(headers: &mut wreq::header::HeaderMap, major: u32) {
    use wreq::header::{HeaderValue, HeaderName};
    if let Some(ua) = headers.get(wreq::header::USER_AGENT).cloned() {
        if let Ok(text) = ua.to_str() {
            // `Chrome/<n>.0.0.0` → `Chrome/<major>.0.0.0`, the rest untouched.
            let mut out = String::with_capacity(text.len());
            let mut rest = text;
            while let Some(at) = rest.find("Chrome/") {
                out.push_str(&rest[..at + "Chrome/".len()]);
                rest = &rest[at + "Chrome/".len()..];
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                out.push_str(&major.to_string());
                rest = &rest[digits.len()..];
            }
            out.push_str(rest);
            if let Ok(v) = HeaderValue::from_str(&out) {
                headers.insert(wreq::header::USER_AGENT, v);
            }
        }
    }
    // Same list as `userAgentData.brands`: GREASE brand first, then Chrome and
    // Chromium at the same version.
    let brands = format!(
        "\"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"{major}\", \"Chromium\";v=\"{major}\""
    );
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(b"sec-ch-ua"),
        HeaderValue::from_str(&brands),
    ) {
        if headers.contains_key(&name) {
            headers.insert(name, value);
        }
    }
}

/// Chrome majors nokk can emulate faithfully: a `wreq-util` profile exists
/// for each, and 150–152 send the same ClientHello as 149 plus ML-DSA.
fn has_emulation(major: u32) -> bool {
    matches!(major, 120 | 123 | 124 | 126..=152)
}

/// The Chrome major to emulate for a requested one. A version without a
/// faithful handshake falls back to [`DEFAULT_CHROME_MAJOR`] as a whole — UA,
/// client hints and TLS together — since a UA that names one version over the
/// handshake of another is itself a tell.
pub fn emulated_chrome_major(requested: u32) -> u32 {
    if has_emulation(requested) {
        return requested;
    }
    tracing::warn!(
        requested,
        fallback = DEFAULT_CHROME_MAJOR,
        "no emulation for this Chrome version; using the default for the UA and the handshake"
    );
    DEFAULT_CHROME_MAJOR
}

/// Map a Chrome major version to the matching wreq TLS/HTTP emulation profile.
/// Callers pass a version already checked by [`emulated_chrome_major`].
pub fn profile_for_major(major: u32) -> wreq_util::Profile {
    use wreq_util::Profile as P;
    match major {
        120 => P::Chrome120,
        123 => P::Chrome123,
        124 => P::Chrome124,
        126 => P::Chrome126,
        127 => P::Chrome127,
        128 => P::Chrome128,
        129 => P::Chrome129,
        130 => P::Chrome130,
        131 => P::Chrome131,
        132 => P::Chrome132,
        133 => P::Chrome133,
        134 => P::Chrome134,
        135 => P::Chrome135,
        136 => P::Chrome136,
        137 => P::Chrome137,
        138 => P::Chrome138,
        139 => P::Chrome139,
        140 => P::Chrome140,
        141 => P::Chrome141,
        142 => P::Chrome142,
        143 => P::Chrome143,
        144 => P::Chrome144,
        145 => P::Chrome145,
        146 => P::Chrome146,
        147 => P::Chrome147,
        148 => P::Chrome148,
        // `wreq-util` tops out at 149; 150–152 differ from it only in the
        // signature algorithms, added on top (see `CHROME_SIGALGS`).
        _ => P::Chrome149,
    }
}

/// Chrome turned ML-DSA signature algorithms on by default in 150
/// (`kTlsMldsaSignatures`, net/base/features.cc; off by default in 149, absent
/// before, unconditional from 153).
const MLDSA_FROM_MAJOR: u32 = 150;

/// Chrome 150+'s `signature_algorithms`, in its order: three post-quantum ones
/// first, then the usual eight. BoringSSL names; `mldsa*` exist only in our
/// vendored copy.
const CHROME_SIGALGS: &str = concat!(
    "mldsa44:mldsa65:mldsa87:",
    "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
    "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
    "rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
);

/// Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub fingerprint: FingerprintProfile,
    /// OS the TLS emulation impersonates; keep coherent with the JS profile.
    pub emulation_os: EmulationOs,
    /// Chrome major version the TLS/HTTP fingerprint emulates. Must match the JS
    /// profile's UA / `CHROME_MAJOR`. Mapped to a wreq profile by
    /// [`profile_for_major`]; an unavailable version falls back to the default.
    pub chrome_major: u32,
    pub limits: PoolLimits,
    pub proxy: Option<ProxyConfig>,
    pub request_timeout: Duration,
    /// What client hints report when a site asks for them (`Accept-CH`); keep
    /// in step with the JS profile.
    pub hints: HintValues,
    /// Local address every connection is bound to. Its family also picks the
    /// remote family: `0.0.0.0` connects over IPv4 only, `::` over IPv6 only.
    /// With a proxy it governs the connection to the proxy.
    pub local_address: Option<std::net::IpAddr>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            fingerprint: FingerprintProfile::default(),
            emulation_os: EmulationOs::default(),
            chrome_major: DEFAULT_CHROME_MAJOR,
            limits: PoolLimits::default(),
            proxy: None,
            request_timeout: Duration::from_secs(30),
            hints: HintValues::default(),
            local_address: None,
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
    /// What the page is fetching this for. A browser does not send one header set
    /// for everything: a navigation carries `upgrade-insecure-requests` and
    /// `sec-fetch-user`, a script asks for `*/*` and declares `sec-fetch-dest:
    /// script`, an image asks for image types. Sending the navigation set for all
    /// of them — which is what a single emulation profile does — contradicts the
    /// page's own behaviour on every subresource.
    pub kind: RequestKind,
    /// Whether a person started this navigation — typing an address, following a
    /// link — as opposed to the page's own script. Only the first carries
    /// `sec-fetch-user`, and the difference is readable: Cloudflare's interstitial
    /// reloads *itself*, and a reload that claims a human gesture is one no
    /// browser sends. Meaningless for anything but a navigation.
    pub user_activated: bool,
    /// The request comes from a frame whose origin differs from the top page.
    /// Chrome adds `sec-fetch-storage-access` there; the Cloudflare challenge
    /// runs in such a frame and its deciding first POST carries the header.
    pub third_party: bool,
    /// The engine's own tag for who asked (a frame's context); the network
    /// layer does not read it.
    pub context: Option<usize>,
    /// Client hints the requesting document asked for with
    /// `<meta http-equiv="Accept-CH">` (header values as written). They apply
    /// to its own same-origin subresources only and are not remembered.
    pub doc_hints: Vec<String>,
    /// Chrome's urgency (0 highest .. 4) when it depends on more than the
    /// kind: an `<img>` in the document is Medium, `new Image()` Low; a
    /// parser script High, an inserted one Low.
    pub urgency: Option<u8>,
    /// Sent without cookies and ignoring `Set-Cookie` (credentials `omit`:
    /// a manifest).
    pub omit_credentials: bool,
    /// The document that asked, when the `Referer` names something else (a
    /// stylesheet's imports, images and fonts). It decides `Sec-Fetch-Site`
    /// and `Origin`.
    pub initiator: Option<String>,
    /// The referrer policy in force (the document's `Referrer-Policy` header
    /// or `<meta name="referrer">`, or a `fetch()`'s own); `None` is Chrome's
    /// default, `strict-origin-when-cross-origin`.
    pub referrer_policy: Option<String>,
    /// A page `fetch`/XHR's credentials mode as it said (`include` is
    /// `credentials: 'include'` or `withCredentials`); `None` takes the
    /// destination's default (an image, a script or a stylesheet includes them).
    pub credentials_include: Option<bool>,
}

/// The destination a request is for, in the sense `Sec-Fetch-Dest` means it.
/// Each kind's headers were measured from Chrome 151 on one page that loads
/// every kind; the incremental flag of `priority` follows Blink's
/// `ShouldLoadIncremental`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequestKind {
    /// A top-level navigation.
    #[default]
    Document,
    /// A frame's document (`<iframe src>`): a navigation, but not the top one.
    Iframe,
    /// A classic `<script src>`.
    Script,
    /// A module script, a static or dynamic `import`, `modulepreload`.
    ModuleScript,
    /// `fetch()` / `XMLHttpRequest` from page JS.
    Xhr,
    /// `<link rel=preload as=fetch crossorigin>`.
    PreloadFetch,
    /// An image (`<img>`, `new Image()`, a CSS background, a tab icon).
    Subresource,
    /// A stylesheet (`<link rel=stylesheet>`, `@import`, `preload as=style`).
    Style,
    /// A web font (`@font-face`, `preload as=font`).
    Font,
    /// `<link rel=manifest>`.
    Manifest,
    /// `<link rel=prefetch>`.
    Prefetch,
    /// `navigator.sendBeacon`.
    Beacon,
    /// A dedicated or shared worker's script.
    Worker,
    /// `fetch(url, { mode: 'no-cors' })` across origins.
    XhrNoCors,
    /// An image with a `crossorigin` attribute: a CORS load.
    ImageCors,
    /// `<video>` and `<audio>` sources: a Range request for the whole file.
    Video,
    Audio,
    /// `<link rel=prerender>`: Chrome's no-state prefetch, a navigation's
    /// request marked `Sec-Purpose: prefetch`.
    Prerender,
    /// The CORS preflight (`OPTIONS`) before a non-simple cross-origin request.
    Preflight,
}

const DOC_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";

impl RequestKind {
    /// The `Accept` a browser sends for this destination.
    fn accept(self) -> &'static str {
        match self {
            RequestKind::Document | RequestKind::Iframe | RequestKind::Prefetch | RequestKind::Prerender => DOC_ACCEPT,
            RequestKind::Subresource | RequestKind::ImageCors => "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            RequestKind::Style => "text/css,*/*;q=0.1",
            _ => "*/*",
        }
    }

    /// `Sec-Fetch-Dest` / `-Mode`, measured from Chrome.
    fn sec_fetch(self) -> (&'static str, &'static str) {
        match self {
            RequestKind::Document | RequestKind::Prerender => ("document", "navigate"),
            RequestKind::Iframe => ("iframe", "navigate"),
            RequestKind::Script => ("script", "no-cors"),
            RequestKind::ModuleScript => ("script", "cors"),
            RequestKind::Xhr | RequestKind::PreloadFetch => ("empty", "cors"),
            RequestKind::Subresource => ("image", "no-cors"),
            RequestKind::ImageCors => ("image", "cors"),
            RequestKind::Video => ("video", "no-cors"),
            RequestKind::Audio => ("audio", "no-cors"),
            RequestKind::Style => ("style", "no-cors"),
            RequestKind::Font => ("font", "cors"),
            RequestKind::Manifest => ("manifest", "cors"),
            RequestKind::Prefetch | RequestKind::Beacon | RequestKind::XhrNoCors => ("empty", "no-cors"),
            RequestKind::Worker => ("worker", "same-origin"),
            RequestKind::Preflight => ("empty", "cors"),
        }
    }

    /// Chrome's urgency for this destination when the engine names none.
    fn urgency(self) -> u8 {
        match self {
            RequestKind::Document | RequestKind::Iframe | RequestKind::Style => 0,
            RequestKind::Script | RequestKind::ModuleScript | RequestKind::Xhr | RequestKind::PreloadFetch
            | RequestKind::Font | RequestKind::Worker | RequestKind::XhrNoCors | RequestKind::Preflight => 1,
            RequestKind::Subresource | RequestKind::ImageCors | RequestKind::Manifest => 2,
            RequestKind::Video | RequestKind::Audio => 3,
            RequestKind::Prefetch | RequestKind::Beacon | RequestKind::Prerender => 4,
        }
    }

    /// Blink's `ShouldLoadIncremental` (a navigation is incremental too).
    fn incremental(self) -> bool {
        !matches!(
            self,
            RequestKind::Script | RequestKind::ModuleScript | RequestKind::Style | RequestKind::Font | RequestKind::Manifest
        )
    }

    /// A navigation (top or frame): navigation headers and order.
    fn navigates(self) -> bool {
        matches!(self, RequestKind::Document | RequestKind::Iframe | RequestKind::Prerender)
    }

    /// Element-initiated CORS loads carry `Origin` even same-origin.
    fn always_origin(self) -> bool {
        matches!(self, RequestKind::ModuleScript | RequestKind::Font | RequestKind::PreloadFetch | RequestKind::ImageCors)
    }
}

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    /// Body bytes on the wire, before decompression. Pages see it as
    /// `encodedBodySize` (`transferSize` adds headers), and the server knows it.
    pub encoded_len: usize,
    /// Request duration in milliseconds, reported per resource.
    pub elapsed_ms: f64,
    /// Response `content-encoding` (`br`, `gzip`...), empty if uncompressed. The
    /// header is stripped after decoding; Chrome still reports the value in
    /// Resource Timing (`contentEncoding`).
    pub content_encoding: String,
    /// Milliseconds from start to the last redirect response; `None` if there
    /// was no redirect. Used for Resource Timing `redirectStart`/`redirectEnd`;
    /// Turnstile's api.js always arrives via a 302 and hands that entry to
    /// the widget.
    pub redirect_ms: Option<f64>,
    /// Final URL after any redirects were followed — the origin the body
    /// actually came from. Callers use it as the document base URL.
    pub url: String,
}


/// Decodes the body per `content-encoding`. Unknown/empty encoding or a broken
/// stream returns the body as is; a browser would not fail the load over it.
fn decode_body(encoding: &str, raw: Vec<u8>) -> Vec<u8> {
    use std::io::Read;
    if raw.is_empty() {
        return raw;
    }
    let out: Option<Vec<u8>> = match encoding {
        "br" => {
            let mut out = Vec::new();
            brotli::Decompressor::new(raw.as_slice(), 4096)
                .read_to_end(&mut out)
                .ok()
                .map(|_| out)
        }
        "gzip" | "x-gzip" => {
            let mut out = Vec::new();
            flate2::read::MultiGzDecoder::new(raw.as_slice())
                .read_to_end(&mut out)
                .ok()
                .map(|_| out)
        }
        "deflate" => {
            let mut out = Vec::new();
            flate2::read::ZlibDecoder::new(raw.as_slice())
                .read_to_end(&mut out)
                .ok()
                .map(|_| out)
                .or_else(|| {
                    let mut plain = Vec::new();
                    flate2::read::DeflateDecoder::new(raw.as_slice())
                        .read_to_end(&mut plain)
                        .ok()
                        .map(|_| plain)
                })
        }
        "zstd" => zstd::stream::decode_all(raw.as_slice()).ok(),
        _ => None,
    };
    out.unwrap_or(raw)
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
    /// The jar behind this client, kept on our side of the fence so its contents
    /// can be read back (CDP `Network.getCookies`, session export). wreq's own
    /// `cookie_store(true)` would hold them where nothing can look — and every
    /// cookie that matters for a warmed session (`cf_clearance`, Akamai's
    /// `bm_s*`) is HttpOnly, so `document.cookie` is no substitute.
    jar: Arc<SessionJar>,
    /// Hints each origin asked for with `Accept-CH`, and their values.
    hint_store: Arc<client_hints::HintStore>,
    hint_values: Arc<HintValues>,
    /// The emulation's own header values (User-Agent, Accept-Encoding,
    /// Accept-Language): a CORS preflight carries these and nothing else of
    /// the default set.
    defaults: Arc<wreq::header::HeaderMap>,
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
    /// The underlying `wreq` client, so a WebSocket upgrade rides the same
    /// emulation, cookie jar and proxy as every request (see [`crate::websocket`]).
    pub(crate) fn inner(&self) -> &wreq::Client {
        &self.inner
    }

    /// Every unexpired cookie this client holds, HttpOnly included.
    pub fn cookies(&self) -> Vec<CookieRecord> {
        self.jar.snapshot()
    }

    /// Store a cookie as if `Set-Cookie: <set_cookie>` had come from `url`.
    pub fn set_cookie(&self, set_cookie: &str, url: &str) {
        self.jar.add_set_cookie(set_cookie, url);
    }

    /// The default Chrome profile we impersonate; must agree with the stealth JS
    /// profile (its UA / sec-ch-ua / `CHROME_MAJOR`). Newer emulations track
    /// Chrome's current TLS + request-header set more closely, and a stale version
    /// is itself a Cloudflare tell — keep this on current stable. Per-client the
    /// version is chosen by [`profile_for_major`] from [`ClientConfig::chrome_major`].
    pub const EMULATION: wreq_util::Profile = wreq_util::Profile::Chrome148;
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
                                    // The TLS/HTTP2 OS must match the JS profile's OS (and its UA /
                                    // sec-ch-ua-platform), or the ClientHello contradicts the User-Agent.
        let emulation = wreq_util::Emulation::builder()
            .profile(profile_for_major(config.chrome_major))
            .platform(config.emulation_os.to_platform())
            .build();
        // The emulation's Chrome profile sends its HEADERS frame with a priority
        // weight of 220; Chrome 148 sends 256. The Akamai hash does not cover it,
        // the wire does, and a fingerprint that matches everywhere except one
        // number is still a fingerprint that does not match.
        let mut emulation = <wreq_util::Emulation as wreq::IntoEmulation>::into_emulation(emulation);
        if let Some(h2) = emulation.http2_options.as_mut() {
            h2.headers_stream_dependency = Some(wreq::http2::StreamDependency::new(
                wreq::http2::StreamId::zero(),
                255,
                true,
            ));
        }
        // Header version must match what JS reports: the `wreq-util` profile
        // says 149 while our `navigator` says 151. Rewrite only the version and
        // brand list; everything else comes from the profile.
        retag_chrome_version(&mut emulation.headers, config.chrome_major);
        // `priority` is an HTTP/2 and HTTP/3 header in Chrome: over HTTP/1.1
        // it sends none. The profile put it on every request; ours goes on
        // per request (see `send_once`).
        emulation.headers.remove("priority");
        let defaults = Arc::new(emulation.headers.clone());
        // Post-quantum sigalgs: Chrome 150+ advertises ML-DSA-44/65/87
        // (0904/0905/0906) first, `wreq-util` does not, so the third JA4 part
        // matched no real browser. Only our BoringSSL knows these names (see
        // `vendor/btls-sys/PATCHES.md`); a server cannot actually select them.
        // Older versions keep the profile's own list, as their Chrome did.
        if config.chrome_major >= MLDSA_FROM_MAJOR {
            if let Some(tls) = emulation.tls_options.as_mut() {
                tls.sigalgs_list = Some(CHROME_SIGALGS.into());
            }
        }
        let mut builder = wreq::Client::builder().emulation(emulation);
        // Decompress ourselves: the client would strip `content-encoding` and
        // `content-length` and lose the on-wire size. `accept-encoding` still
        // comes from the emulation profile, so the request looks the same.
        builder = builder.gzip(false).brotli(false).zstd(false).deflate(false);
        // Named session or not, the jar is ours: a named one is shared (and
        // serializable) across contexts of the same identity, an anonymous one is
        // private to this client. Either way its contents stay readable.
        let jar = session.unwrap_or_else(|| Arc::new(SessionJar::new()));
        builder = builder.cookie_provider(jar.clone());
        builder = builder
            // Follow 3xx redirects like a real browser (wreq defaults to *none*).
            // Without this, navigating to e.g. `google.com` returns the `301
            // Moved` body instead of the destination page. Capped at 10 hops.
            .redirect(wreq::redirect::Policy::limited(10))
            .timeout(config.request_timeout);
        if let Some(addr) = config.local_address {
            builder = builder.local_address(addr);
        }

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
        Ok(Self {
            inner,
            jar,
            hint_store: Arc::default(),
            hint_values: Arc::new(config.hints.clone()),
            defaults,
        })
    }
}


/// The URL's origin (scheme, host, port) as Chrome writes it in `Origin`.
fn origin_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://").map(|r| ("https", r))
        .or_else(|| url.strip_prefix("http://").map(|r| ("http", r)))?;
    let (scheme, tail) = rest;
    let host = tail.split(['/', '?', '#']).next()?;
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

/// The `Referer` sent under a referrer policy (Referrer Policy spec; Chrome's
/// default is `strict-origin-when-cross-origin`): the full address has no
/// fragment, the origin form ends in `/`, a downgrade is https to http.
fn referrer_for(referer: &str, url: &str, policy: Option<&str>) -> Option<String> {
    let full = referer.split('#').next().unwrap_or(referer);
    let from = origin_of(full)?;
    let same = origin_of(url).is_some_and(|o| o.eq_ignore_ascii_case(&from));
    let downgrade = full.starts_with("https://") && url.starts_with("http://");
    let origin = || Some(format!("{from}/"));
    let whole = || Some(full.to_string());
    match policy.unwrap_or("strict-origin-when-cross-origin") {
        "no-referrer" => None,
        "unsafe-url" => whole(),
        "origin" => origin(),
        "same-origin" => if same { whole() } else { None },
        "strict-origin" => if downgrade { None } else { origin() },
        "origin-when-cross-origin" => if same { whole() } else { origin() },
        "no-referrer-when-downgrade" => if downgrade { None } else { whole() },
        _ => if same { whole() } else if downgrade { None } else { origin() },
    }
}

/// The last policy token Chrome understands in a `Referrer-Policy` value (a
/// comma list; unknown tokens are skipped), lowercased.
pub fn referrer_policy_token(value: &str) -> Option<String> {
    const KNOWN: [&str; 8] = ["no-referrer", "no-referrer-when-downgrade", "same-origin", "origin",
        "strict-origin", "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url"];
    value
        .split(',')
        .map(|t| t.trim().to_ascii_lowercase())
        .rfind(|t| KNOWN.contains(&t.as_str()))
}

/// Whether two URLs are the same site: same scheme and the same registrable
/// domain by the public suffix list (or the same host where there is none, as
/// for an IP address).
fn same_site_of(a: &str, b: &str) -> bool {
    let parts = |u: &str| -> Option<(String, String)> {
        let parsed = url::Url::parse(u).ok()?;
        let host = parsed.host_str()?.to_ascii_lowercase();
        let site = match parsed.host()? {
            url::Host::Domain(d) => psl::domain_str(d).map(str::to_string).unwrap_or_else(|| d.to_string()),
            _ => host,
        };
        Some((parsed.scheme().to_string(), site))
    };
    matches!((parts(a), parts(b)), (Some(x), Some(y)) if x == y)
}

/// Whether `referer` and `url` are the same origin — the difference between
/// `sec-fetch-site: same-origin` and `cross-site`.
fn same_site(referer: &str, url: &str) -> bool {
    let origin = |s: &str| {
        let s = s.split("://").nth(1)?;
        Some(s.split('/').next()?.to_ascii_lowercase())
    };
    match (origin(referer), origin(url)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

impl HttpClient for FingerprintClient {
    async fn send(&self, req: Request) -> Result<Response, NetError> {
        // A navigation whose response marks a hint critical that was not sent
        // is restarted once with it, as Chrome does (`Critical-CH`).
        let retry = (req.kind == RequestKind::Document).then(|| req.clone());
        let (resp, restart) = self.send_once(req, false).await?;
        match (restart, retry) {
            (true, Some(again)) => Ok(self.send_once(again, true).await?.0),
            _ => Ok(resp),
        }
    }
}

impl FingerprintClient {
    async fn send_once(&self, req: Request, critical_retry: bool) -> Result<(Response, bool), NetError> {
        // Turnstile posts to `/eb/` when its own script throws: a script the
        // engine runs differently from Chrome. It still may pass, but this is
        // the first sign of a break (2026-10-07), so say it in plain logs.
        if req.url.contains("/cdn-cgi/challenge-platform/") && req.url.contains("/eb/") {
            tracing::warn!(url = %req.url, "challenge reported a script error (Cloudflare error beacon)");
        }
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
        // A CORS preflight is the network service's own request: no client
        // hints, no cookies, only the profile's identity headers (measured).
        let preflight = req.kind == RequestKind::Preflight;
        // A media load asks for the bytes as they are, from the start: Blink's
        // media loader puts `Accept-Encoding` in its header map and the
        // network service adds `Range` (measured).
        let media = matches!(req.kind, RequestKind::Video | RequestKind::Audio);
        if media {
            rb = rb.header("accept-encoding", "identity;q=1, *;q=0").header("range", "bytes=0-");
        }
        if preflight {
            rb = rb.default_headers(false);
            for name in ["user-agent", "accept-encoding", "accept-language"] {
                if let Some(v) = self.defaults.get(name) {
                    rb = rb.header(name, v.clone());
                }
            }
        }
        // The emulation ships one header set — a navigation's — for every request.
        // Correct the parts that vary by destination, and put them on the wire in
        // Chrome's order: `orig_headers` decides that, and without it our added
        // headers would trail after `priority`, in an order no browser produces.
        let (dest, mode) = req.kind.sec_fetch();
        let asker = req.initiator.as_deref().or_else(|| {
            req.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("referer"))
                .map(|(_, r)| r.as_str())
        });
        let same_origin = asker.map(|r| same_site(r, &req.url)).unwrap_or(false);
        let has_referer = req
            .headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("referer"));
        let site = match req.kind {
            // A navigation with no referrer came from outside the web — typed, or
            // opened by a driver. One the page made carries where it came from.
            RequestKind::Document if !has_referer => "none",
            _ if same_origin => "same-origin",
            _ if asker.is_some_and(|a| same_site_of(a, &req.url)) => "same-site",
            _ => "cross-site",
        };
        // `Accept` is the page's to set on `fetch`/XHR — it is not a forbidden
        // header — so ours is only the default when the caller named none. For a
        // navigation, a script or an image the page has no say, and the browser's
        // value is the only correct one.
        // Hints this origin asked for: on its navigations and on its own
        // same-origin subresources, never across origins or from a third-party
        // frame (Chrome's default delegation policy is `self`).
        let request_origin = origin_of(&req.url);
        let hint_scope = client_hints::secure(&req.url)
            && !preflight
            && !req.third_party
            && (req.kind == RequestKind::Document || same_origin);
        let mut extra_hints: Vec<&'static str> = match (&request_origin, hint_scope) {
            (Some(o), true) => self.hint_store.get(o),
            _ => Vec::new(),
        };
        // A document's `<meta http-equiv="Accept-CH">` adds to its own
        // subresources (Chrome's preload scanner honours it too).
        if hint_scope && req.kind != RequestKind::Document {
            for value in &req.doc_hints {
                for h in client_hints::parse(value) {
                    if !extra_hints.contains(&h) {
                        extra_hints.push(h);
                    }
                }
            }
        }
        for name in &extra_hints {
            if let Some(v) = self.hint_values.value(name) {
                rb = rb.header(*name, v);
            }
        }
        // An Accept the page set on a fetch/XHR is the page's, in Blink's map
        // with its other headers.
        let page_accept = req.headers.keys().any(|k| k.eq_ignore_ascii_case("accept"));
        let own_accept = !(page_accept && req.kind == RequestKind::Xhr);
        if own_accept {
            rb = rb.header("accept", req.kind.accept());
        }
        rb = rb
            .header("sec-fetch-site", site)
            .header("sec-fetch-mode", mode)
            .header("sec-fetch-dest", dest);
        // Over HTTP/1.1 Chrome sends `Host` and `Connection: keep-alive` first,
        // and no `priority`. ALPN decides the protocol, but plain `http://` is
        // almost always 1.1 and `https://` almost always 2 or 3.
        let plain_http = req.url.starts_with("http://");
        if !plain_http {
            let u = req.urgency.unwrap_or_else(|| req.kind.urgency()).min(4);
            let value = if req.kind.incremental() { format!("u={u}, i") } else { format!("u={u}") };
            rb = rb.header("priority", value);
        }
        if matches!(req.kind, RequestKind::Prefetch | RequestKind::Prerender) {
            rb = rb.header("sec-purpose", "prefetch");
        }
        // Credentials: a page's own request across origins goes without
        // cookies unless it asked (`credentials: 'include'`, `withCredentials`);
        // element loads in `no-cors` mode include them; a preflight never does.
        let include = req.credentials_include.unwrap_or(
            !matches!(req.kind, RequestKind::ModuleScript | RequestKind::Font | RequestKind::PreloadFetch
                | RequestKind::Xhr | RequestKind::XhrNoCors | RequestKind::ImageCors),
        ) && !preflight;
        if req.omit_credentials || preflight || (!same_origin && !include) {
            rb = rb.cookie_provider(Arc::new(wreq::cookie::Jar::default()));
        }
        if plain_http {
            rb = rb.header("connection", "keep-alive");
        }
        // Chrome sends `Origin` on every non-GET and every cross-origin
        // request; Cloudflare checks it first.
        // A `no-cors` load (an image, a script) carries none across origins.
        let wants_origin = req.method != "GET" && req.method != "HEAD"
            || (!same_origin && mode == "cors")
            || req.kind.always_origin();
        let page_origin = asker.and_then(origin_of);
        let mut sent_origin = false;
        if wants_origin && !req.kind.navigates() {
            if let Some(o) = page_origin.as_deref() {
                rb = rb.header("origin", o);
                sent_origin = true;
            }
        }
        let origin_in_map = sent_origin && req.kind.always_origin() && (req.method == "GET" || req.method == "HEAD");
        let mut order = wreq::header::OrigHeaderMap::new();
        if plain_http {
            order.insert("host");
            order.insert("connection");
        }
        // A navigation lists client hints in the browser's fixed order. A
        // subresource's page headers, hints and `user-agent` come out of
        // Blink's header hash map, in its slot order (see `client_hints`).
        let subresource = !req.kind.navigates();
        let sends_hint = |n: &str| client_hints::BASE.contains(&n) || extra_hints.contains(&n);
        if subresource {
            order.insert("content-length");
            let mut names: Vec<String> = req
                .headers
                .keys()
                .map(|k| k.to_ascii_lowercase())
                .filter(|k| {
                    (!FP_OWNED_HEADERS.contains(&k.as_str()) || (k == "accept" && !own_accept))
                        && !k.starts_with("sec-")
                        && !matches!(k.as_str(), "content-length" | "referer" | "origin" | "cookie" | "priority" | "upgrade-insecure-requests")
                })
                .collect();
            // An element's CORS load (module script, font) sets `Origin` in
            // Blink's map, as `rel=prefetch` sets `Sec-Purpose`; a beacon's or
            // a POST's `Origin` comes later, from the network service.
            if origin_in_map {
                names.push("origin".into());
            }
            if req.kind == RequestKind::Prefetch {
                names.push("sec-purpose".into());
            }
            if media {
                names.insert(0, "accept-encoding".into());
            }
            names.extend(client_hints::BLINK_INSERT_ORDER.iter().filter(|n| sends_hint(n)).map(|n| n.to_string()));
            names.push("user-agent".into());
            for name in client_hints::blink_map_order(&names) {
                order.insert(name);
            }
        } else if !critical_retry {
            for name in client_hints::NAVIGATION_ORDER.iter().filter(|n| sends_hint(n)) {
                order.insert(*name);
            }
        }
        let claims_user = req.kind == RequestKind::Document && req.user_activated;
        if req.kind.navigates() {
            // Only a navigation carries `upgrade-insecure-requests`, and its
            // absence is the difference between a browser and something replaying
            // cookies. `sec-fetch-user` is narrower still: it means a person did
            // this, so a script-driven navigation must not carry it.
            rb = rb.header("upgrade-insecure-requests", "1");
            order.insert("upgrade-insecure-requests");
            if claims_user {
                rb = rb.header("sec-fetch-user", "?1");
            }
        }
        if !subresource {
            order.insert("user-agent");
        }
        if own_accept {
            order.insert("accept");
        }
        if req.kind == RequestKind::Prerender {
            order.insert("sec-purpose");
        }
        // A restart for `Critical-CH` adds the hints after `accept`.
        if critical_retry && !subresource {
            for name in client_hints::BASE.iter().chain(client_hints::NAVIGATION_ORDER.iter().filter(|n| extra_hints.contains(n))) {
                order.insert(*name);
            }
        }
        if sent_origin && !origin_in_map {
            order.insert("origin");
        }
        // Storage access to own cookies inside a third-party frame: Chrome
        // sends a separate header there, never on a first-party page.
        // So does a cross-site request that carries cookies: Chrome 151 marks
        // it `active` (third-party cookies are allowed in its default profile).
        let storage_access = !req.kind.navigates()
            && ((req.third_party && same_origin)
                || (site == "cross-site" && include && !req.omit_credentials));
        if storage_access {
            rb = rb.header("sec-fetch-storage-access", "active");
        }
        for name in ["sec-fetch-site", "sec-fetch-mode"] {
            order.insert(name);
        }
        if claims_user {
            order.insert("sec-fetch-user");
        }
        order.insert("sec-fetch-dest");
        if storage_access {
            order.insert("sec-fetch-storage-access");
        }
        for name in [
            "referer",
            "accept-encoding",
            "accept-language",
            "priority",
        ] {
            if media && name == "accept-encoding" {
                continue;
            }
            order.insert(name);
        }
        if media {
            order.insert("range");
        }
        if preflight {
            order = wreq::header::OrigHeaderMap::new();
            if plain_http {
                order.insert("host");
                order.insert("connection");
            }
            for name in ["accept", "access-control-request-method", "access-control-request-headers", "origin",
                "user-agent", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "referer", "accept-encoding",
                "accept-language", "priority"] {
                order.insert(name);
            }
        }
        rb = rb.orig_headers(order);

        // Forward only headers the emulation profile does not own, so the Chrome
        // fingerprint (values + order) is preserved. The `sec-*` set is ours now,
        // decided above from the request's destination.
        for (k, v) in &req.headers {
            let lk = k.to_ascii_lowercase();
            // Forbidden header names: a page cannot set these, so a value that
            // arrived in one is ours to ignore, not to honour.
            // A fetch/XHR keeps the Accept its page set (GitHub's JSON
            // endpoints answer 406 to the navigation default).
            let page_owned = lk == "accept" && !own_accept;
            if (FP_OWNED_HEADERS.contains(&lk.as_str()) && !page_owned)
                || lk.starts_with("sec-")
                || lk == "priority"
                || lk == "upgrade-insecure-requests"
                || (lk == "accept" && own_accept)
            {
                continue;
            }
            if lk == "referer" {
                if let Some(r) = referrer_for(v, &req.url, req.referrer_policy.as_deref()) {
                    rb = rb.header(k, r);
                }
                continue;
            }
            rb = rb.header(k, v);
        }
        if let Some(body) = req.body {
            rb = rb.body(body);
        }
        // The only place the real outgoing headers are visible: emulation owns
        // some, the page others, and a conflict between them costs a 401.
        if tracing::enabled!(tracing::Level::TRACE) {
            let sent: Vec<String> = req
                .headers
                .iter()
                .map(|(k, v)| format!("{k}: {}", &v[..v.len().min(60)]))
                .collect();
            tracing::trace!(url = %req.url, method = %req.method, page_headers = %sent.join(" | "), "request");
        }
        let started = std::time::Instant::now();
        // Per-request redirect policy only to time the last redirect response.
        // Same limit: at most ten.
        let hop_at: Arc<std::sync::Mutex<Option<std::time::Instant>>> = Arc::default();
        {
            let hop_at = hop_at.clone();
            let limit = wreq::redirect::Policy::limited(10);
            rb = rb.redirect(wreq::redirect::Policy::custom(move |attempt| {
                if let Ok(mut t) = hop_at.lock() {
                    *t = Some(std::time::Instant::now());
                }
                limit.redirect(attempt)
            }));
        }
        let resp = rb.send().await.map_err(|e| {
            if e.is_timeout() {
                NetError::Timeout
            } else {
                // The cause is only visible deep in the source chain; the
                // top-level text is the same for every failure.
                let mut chain = Vec::new();
                let mut src: Option<&(dyn std::error::Error + 'static)> = Some(&e);
                while let Some(err) = src {
                    chain.push(err.to_string());
                    src = err.source();
                }
                let cause = chain.join(" <- ");
                tracing::debug!(url = %req.url, chain = %cause, "request failed");
                // "No route" differs from "refused" or "name not resolved":
                // Chrome reports those at once but keeps trying an
                // unreachable address.
                if cause.contains("Network is unreachable") || cause.contains("No route to host") {
                    NetError::Unreachable(e.to_string())
                } else {
                    NetError::Connect(e.to_string())
                }
            }
        })?;
        let status = resp.status().as_u16();
        // Final URL after redirects — captured before `bytes()` consumes `resp`.
        let url = resp.uri().to_string();
        let mut headers = BTreeMap::new();
        for (k, v) in resp.headers() {
            if let Ok(s) = v.to_str() {
                headers.insert(k.to_string(), s.to_string());
            }
        }
        // A secure top-level document sets its origin's hints; its own
        // subresources already carry them.
        let mut restart = false;
        if req.kind == RequestKind::Document && !req.third_party && client_hints::secure(&url) {
            if let (Some(origin), Some(value)) = (origin_of(&url), headers.get("accept-ch")) {
                let asked = client_hints::parse(value);
                if !critical_retry && Some(&origin) == request_origin.as_ref() {
                    if let Some(critical) = headers.get("critical-ch") {
                        restart = client_hints::parse(critical)
                            .iter()
                            .any(|h| asked.contains(h) && !extra_hints.contains(h));
                    }
                }
                self.hint_store.set(&origin, asked);
            }
        }
        // A bodyless response (204/304) is complete at the headers: Chrome
        // resolves `fetch` at once, while the challenge beacon keeps the stream
        // open until the page aborts it, so waiting for a body would time out.
        let raw = if status == 204 || status == 304 {
            Vec::new()
        } else {
            resp.bytes()
                .await
                .map_err(|e| NetError::Connect(e.to_string()))?
                .to_vec()
        };
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        let encoded_len = raw.len();
        // Our own decompression keeps the on-wire size known. The compression
        // headers are then dropped; Chrome hides them from the page too.
        let encoding = headers
            .get("content-encoding")
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let body = decode_body(&encoding, raw);
        let content_encoding = encoding.clone();
        let redirect_ms = hop_at
            .lock()
            .ok()
            .and_then(|t| *t)
            .map(|t| t.duration_since(started).as_secs_f64() * 1000.0);
        // Uncompressed, the length is still the body's and Chrome shows it.
        if !encoding.is_empty() {
            headers.remove("content-length");
        }
        headers.remove("content-encoding");
        Ok((
            Response {
                status,
                url,
                headers,
                body,
                encoded_len,
                elapsed_ms,
                content_encoding,
                redirect_ms,
            },
            restart,
        ))
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

impl Client {
    /// Every unexpired cookie this client holds — the real jar, HttpOnly
    /// included, which is the only way to hand a warmed session to another
    /// process. Empty for the stub (it never talks to a network).
    pub fn cookies(&self) -> Vec<CookieRecord> {
        match self {
            Client::Stub(_) => Vec::new(),
            Client::Fingerprint(c) => c.cookies(),
        }
    }

    /// Store a cookie as if `Set-Cookie: <set_cookie>` had come from `url`
    /// (`document.cookie = …`). The stub has no jar.
    pub fn set_cookie(&self, set_cookie: &str, url: &str) {
        if let Client::Fingerprint(c) = self {
            c.set_cookie(set_cookie, url);
        }
    }

    /// The client hints each origin asked for with `Accept-CH` (origin ->
    /// header names): a session keeps them, as a browser profile does.
    pub fn hint_preferences(&self) -> std::collections::HashMap<String, Vec<String>> {
        match self {
            Client::Stub(_) => Default::default(),
            Client::Fingerprint(c) => c.hint_store.snapshot(),
        }
    }

    /// Restore saved `Accept-CH` preferences.
    pub fn restore_hint_preferences(&self, saved: &std::collections::HashMap<String, Vec<String>>) {
        if let Client::Fingerprint(c) = self {
            c.hint_store.restore(saved);
        }
    }
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

    #[test]
    fn referrer_is_trimmed_as_chrome_does_by_default() {
        let page = "https://a.example/path/page?q=1#frag";
        assert_eq!(referrer_for(page, "https://a.example/x.png", None).as_deref(), Some("https://a.example/path/page?q=1"));
        assert_eq!(referrer_for(page, "https://cdn.example/x.png", None).as_deref(), Some("https://a.example/"));
        assert_eq!(referrer_for(page, "http://a.example/x.png", None), None);
        assert_eq!(referrer_for("http://127.0.0.1:8799/c?x", "http://localhost:8799/i.png", None).as_deref(), Some("http://127.0.0.1:8799/"));
        assert_eq!(referrer_for(page, "https://cdn.example/x.png", Some("unsafe-url")).as_deref(), Some("https://a.example/path/page?q=1"));
        assert_eq!(referrer_for(page, "https://a.example/x.png", Some("origin")).as_deref(), Some("https://a.example/"));
        assert_eq!(referrer_for(page, "https://cdn.example/x.png", Some("same-origin")), None);
        assert_eq!(referrer_for(page, "https://a.example/x.png", Some("no-referrer")), None);
        assert_eq!(referrer_policy_token("unsafe-url, bogus, origin").as_deref(), Some("origin"));
        assert_eq!(referrer_policy_token("bogus"), None);
    }

    #[test]
    fn sites_follow_the_public_suffix_list() {
        assert!(same_site_of("https://www.example.com/a", "https://static.example.com/b"));
        assert!(!same_site_of("http://www.example.com/", "https://www.example.com/"));
        assert!(same_site_of("https://a.example.co.uk/", "https://b.example.co.uk/"));
        assert!(!same_site_of("https://a.co.uk/", "https://b.co.uk/"));
        assert!(!same_site_of("https://alice.github.io/", "https://bob.github.io/"));
        assert!(!same_site_of("http://127.0.0.1:1/", "http://127.0.0.2:1/"));
        // A private-section suffix: each name under it is a site of its own,
        // and Chrome says `cross-site` between them (measured).
        assert!(!same_site_of("https://httpbin.org/", "https://www.httpbin.org/headers"));
    }

    fn req(method: &str, url: &str) -> Request {
        Request {
            context: None,
            method: method.into(),
            url: url.into(),
            headers: BTreeMap::new(),
            body: None,
            kind: RequestKind::default(),
            third_party: false,
            user_activated: true,
            doc_hints: Vec::new(),
            urgency: None,
            omit_credentials: false,
            initiator: None,
            referrer_policy: None,
            credentials_include: None,
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

    #[test]
    fn client_builds_for_each_emulation_os() {
        // Building a fingerprinted client is offline; each OS must produce a valid
        // client (a coherent Chrome-on-that-OS ClientHello).
        for os in [EmulationOs::Linux, EmulationOs::Windows, EmulationOs::Mac] {
            let cfg = ClientConfig {
                emulation_os: os,
                ..Default::default()
            };
            assert!(
                FingerprintClient::new(&cfg).is_ok(),
                "failed to build client for {os:?}"
            );
        }
    }

    #[test]
    fn an_unknown_chrome_major_falls_back_whole() {
        for known in [120u32, 131, 145, 149, 150, 151, 152] {
            assert_eq!(emulated_chrome_major(known), known);
        }
        for unknown in [0u32, 121, 125, 153, 160, 999] {
            assert_eq!(emulated_chrome_major(unknown), DEFAULT_CHROME_MAJOR);
        }
        assert!(has_emulation(DEFAULT_CHROME_MAJOR));
    }

    #[test]
    fn client_builds_for_a_custom_chrome_major() {
        // A supported version, and an unavailable one that must fall back rather
        // than fail — the caller can request any major and still get a client.
        for major in [131u32, 137, 148, 149, 999] {
            let cfg = ClientConfig {
                chrome_major: major,
                ..Default::default()
            };
            assert!(
                FingerprintClient::new(&cfg).is_ok(),
                "failed to build client for Chrome {major}"
            );
        }
    }
}
