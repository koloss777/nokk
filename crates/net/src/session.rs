//! Persistent, named cookie sessions.
//!
//! A [`SessionJar`] is a serializable cookie jar: warm a session once (log in,
//! clear a challenge, collect `cf_clearance`), [save](SessionJar::save_file) it,
//! and [load](SessionJar::load_file) it back into a later context or a fresh
//! process instead of re-solving every run. It implements wreq's
//! [`CookieStore`](wreq::cookie::CookieStore), so it plugs straight into a client
//! as its `cookie_provider`, replacing the default in-memory jar.

use std::path::Path;
use std::sync::RwLock;

use cookie_store::{CookieStore as RawStore, RawCookie};
use serde::{Deserialize, Serialize};
use url::Url;
use wreq::cookie::{CookieStore, Cookies};
use wreq::header::HeaderValue;
use wreq::{Uri, Version};

/// A serializable cookie jar backing a named, resumable session.
#[derive(Debug, Default)]
pub struct SessionJar(RwLock<RawStore>);

/// A single cookie, flattened for inspection / CDP `Network.getCookies`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieRecord {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    /// Expiry as a Unix timestamp in seconds; `None` for a session cookie.
    /// `#[serde(default)]` so jars written before this field still load.
    #[serde(default)]
    pub expires: Option<f64>,
    /// `Strict` / `Lax` / `None`, as the attribute was written.
    #[serde(default)]
    pub same_site: Option<String>,
}

impl SessionJar {
    pub fn new() -> Self {
        Self(RwLock::new(RawStore::default()))
    }

    /// Load a jar from a JSON file. A missing file yields an empty jar (a brand
    /// new session just starts cold); a present-but-corrupt file is an error, so
    /// a typo in the store path never silently discards a real session.
    pub fn load_file(path: &Path) -> std::io::Result<Self> {
        match std::fs::File::open(path) {
            Ok(f) => {
                let store =
                    cookie_store::serde::json::load(std::io::BufReader::new(f)).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;
                Ok(Self(RwLock::new(store)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(e),
        }
    }

    /// Serialize the jar to a JSON file, writing to a sibling temp file and
    /// renaming so a crash mid-write can't truncate an existing session.
    ///
    /// We deliberately persist *session* (non-persistent) cookies too — a login
    /// `sid` with no `Expires` is exactly the state a resumed session needs, and
    /// `json::save` alone would drop it. Expired cookies are also written but are
    /// filtered out on read ([`Self::len`], `get_request_values`), so they never
    /// leak into a request.
    pub fn save_file(&self, path: &Path) -> std::io::Result<()> {
        let mut buf = Vec::new();
        cookie_store::serde::json::save_incl_expired_and_nonpersistent(
            &self.0.read().unwrap(),
            &mut buf,
        )
        .map_err(std::io::Error::other)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &buf)?;
        std::fs::rename(&tmp, path)
    }

    /// Count of currently-unexpired cookies held by the jar.
    pub fn len(&self) -> usize {
        self.0.read().unwrap().iter_unexpired().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Inject a cookie as if `Set-Cookie: <set_cookie>` had arrived from `url`.
    /// Used to restore a saved session by hand (CDP `Network.setCookie`).
    pub fn add_cookie_str(&self, set_cookie: &str, url: &Url) {
        if let Ok(c) = RawCookie::parse(set_cookie.to_owned()) {
            self.0
                .write()
                .unwrap()
                .store_response_cookies(std::iter::once(c.into_owned()), url);
        }
    }

    /// Like [`Self::add_cookie_str`] but parses the origin from a string — handy
    /// for importing a harvested clearance whose origin is a plain URL string.
    /// A malformed URL is ignored (best-effort import).
    pub fn add_set_cookie(&self, set_cookie: &str, url: &str) {
        if let Ok(u) = Url::parse(url) {
            self.add_cookie_str(set_cookie, &u);
        }
    }

    /// Snapshot every unexpired cookie, for CDP `Network.getCookies` or session
    /// inspection.
    pub fn snapshot(&self) -> Vec<CookieRecord> {
        self.0
            .read()
            .unwrap()
            .iter_unexpired()
            .map(|c| CookieRecord {
                name: c.name().to_owned(),
                value: c.value().to_owned(),
                // The *effective* domain, not the raw attribute: a cookie set
                // without `Domain=` has none of its own, yet still belongs to the
                // host that set it, and reporting `""` would make it unusable to
                // anyone replaying the jar. A `Domain=` cookie gets Chrome's
                // leading dot, marking that it also matches subdomains.
                domain: match &c.domain {
                    cookie_store::CookieDomain::HostOnly(h) => Some(h.clone()),
                    cookie_store::CookieDomain::Suffix(s) => Some(format!(".{s}")),
                    _ => None,
                },
                path: c.path().map(str::to_owned),
                secure: c.secure().unwrap_or(false),
                http_only: c.http_only().unwrap_or(false),
                // From the store's own expiry, which is where a `Max-Age` lands —
                // the raw cookie only carries an explicit `Expires`.
                expires: match c.expires {
                    cookie_store::CookieExpiration::AtUtc(t) => Some(t.unix_timestamp() as f64),
                    cookie_store::CookieExpiration::SessionEnd => None,
                },
                same_site: c.same_site().map(|s| s.to_string()),
            })
            .collect()
    }
}

impl CookieStore for SessionJar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri) {
        let Some(url) = uri_to_url(uri) else {
            return;
        };
        let iter = cookie_headers.filter_map(|val| {
            std::str::from_utf8(val.as_bytes())
                .ok()
                .and_then(|s| RawCookie::parse(s.to_owned()).ok())
                .map(|c| c.into_owned())
        });
        self.0.write().unwrap().store_response_cookies(iter, &url);
    }

    fn cookies(&self, uri: &Uri, version: Version) -> Cookies {
        let Some(url) = uri_to_url(uri) else {
            return Cookies::Empty;
        };
        // Collect owned pairs so the store lock is released before building headers.
        let pairs: Vec<(String, String)> = {
            let lock = self.0.read().unwrap();
            lock.get_request_values(&url)
                .map(|(n, v)| (n.to_owned(), v.to_owned()))
                .collect()
        };
        if pairs.is_empty() {
            return Cookies::Empty;
        }
        // HTTP/2+ sends each cookie as its own header field; HTTP/1.1 combines
        // them into one `Cookie:` header (RFC 9113 §8.1.2.5 vs RFC 9112 §5.6.3).
        if matches!(version, Version::HTTP_2 | Version::HTTP_3) {
            let headers = pairs
                .iter()
                .filter_map(|(n, v)| HeaderValue::from_str(&format!("{n}={v}")).ok())
                .collect();
            Cookies::Uncompressed(headers)
        } else {
            let mut cookie = String::with_capacity(64);
            for (name, value) in &pairs {
                if !cookie.is_empty() {
                    cookie.push_str("; ");
                }
                cookie.push_str(name);
                cookie.push('=');
                cookie.push_str(value);
            }
            HeaderValue::from_str(&cookie)
                .map(Cookies::Compressed)
                .unwrap_or(Cookies::Empty)
        }
    }
}

/// Convert wreq's request [`Uri`] into the [`Url`] the cookie store matches on.
fn uri_to_url(uri: &Uri) -> Option<Url> {
    Url::parse(&uri.to_string()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_cookie(jar: &SessionJar, url: &str, header: &str) {
        let uri: Uri = url.parse().unwrap();
        let hv = HeaderValue::from_str(header).unwrap();
        let mut it = std::iter::once(&hv);
        jar.set_cookies(&mut it, &uri);
    }

    /// The combined HTTP/1.1 `Cookie:` header the jar would send to `url`.
    fn cookie_header(jar: &SessionJar, url: &str) -> Option<HeaderValue> {
        match jar.cookies(&url.parse::<Uri>().unwrap(), Version::HTTP_11) {
            Cookies::Compressed(h) => Some(h),
            _ => None,
        }
    }

    #[test]
    fn stores_and_serves_cookies_per_url() {
        let jar = SessionJar::new();
        set_cookie(&jar, "https://example.com/", "sid=abc; Path=/");
        assert_eq!(jar.len(), 1);
        let hdr = cookie_header(&jar, "https://example.com/x").unwrap();
        assert_eq!(hdr.to_str().unwrap(), "sid=abc");
        // A different host must not see it.
        assert!(cookie_header(&jar, "https://other.test/").is_none());
    }

    #[test]
    fn round_trips_through_a_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nokk-sessionjar-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let jar = SessionJar::new();
        set_cookie(&jar, "https://example.com/", "sid=abc; Path=/");
        set_cookie(&jar, "https://example.com/", "theme=dark; Path=/");
        jar.save_file(&path).unwrap();

        let reloaded = SessionJar::load_file(&path).unwrap();
        assert_eq!(reloaded.len(), 2);
        let hdr = cookie_header(&reloaded, "https://example.com/").unwrap();
        let s = hdr.to_str().unwrap();
        assert!(s.contains("sid=abc") && s.contains("theme=dark"), "got {s}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_loads_an_empty_jar() {
        let path = std::env::temp_dir().join("nokk-sessionjar-does-not-exist.json");
        let _ = std::fs::remove_file(&path);
        let jar = SessionJar::load_file(&path).unwrap();
        assert!(jar.is_empty());
    }

    #[test]
    fn snapshot_reflects_stored_cookies() {
        let jar = SessionJar::new();
        set_cookie(
            &jar,
            "https://example.com/",
            "sid=abc; Path=/; Secure; HttpOnly",
        );
        let snap = jar.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].name, "sid");
        assert_eq!(snap[0].value, "abc");
        assert!(snap[0].secure && snap[0].http_only);
    }
}
