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
use wreq::cookie::CookieStore;
use wreq::header::HeaderValue;

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
                let store = cookie_store::serde::json::load(std::io::BufReader::new(f))
                    .map_err(|e| {
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
                domain: c.domain().map(str::to_owned),
                path: c.path().map(str::to_owned),
                secure: c.secure().unwrap_or(false),
                http_only: c.http_only().unwrap_or(false),
            })
            .collect()
    }
}

impl CookieStore for SessionJar {
    fn set_cookies(&self, url: &Url, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>) {
        let iter = cookie_headers.filter_map(|val| {
            std::str::from_utf8(val.as_bytes())
                .ok()
                .and_then(|s| RawCookie::parse(s.to_owned()).ok())
                .map(|c| c.into_owned())
        });
        self.0.write().unwrap().store_response_cookies(iter, url);
    }

    fn cookies(&self, url: &Url) -> Option<HeaderValue> {
        let lock = self.0.read().unwrap();
        let mut iter = lock.get_request_values(url);
        let (first_name, first_value) = iter.next()?;
        let mut cookie = String::with_capacity(64);
        cookie.push_str(first_name);
        cookie.push('=');
        cookie.push_str(first_value);
        for (name, value) in iter {
            cookie.push_str("; ");
            cookie.push_str(name);
            cookie.push('=');
            cookie.push_str(value);
        }
        HeaderValue::from_str(&cookie).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_cookie(jar: &SessionJar, url: &str, header: &str) {
        let url = Url::parse(url).unwrap();
        let hv = HeaderValue::from_str(header).unwrap();
        let mut it = std::iter::once(&hv);
        jar.set_cookies(&url, &mut it);
    }

    #[test]
    fn stores_and_serves_cookies_per_url() {
        let jar = SessionJar::new();
        set_cookie(&jar, "https://example.com/", "sid=abc; Path=/");
        assert_eq!(jar.len(), 1);
        let hdr = jar
            .cookies(&Url::parse("https://example.com/x").unwrap())
            .unwrap();
        assert_eq!(hdr.to_str().unwrap(), "sid=abc");
        // A different host must not see it.
        assert!(jar
            .cookies(&Url::parse("https://other.test/").unwrap())
            .is_none());
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
        let hdr = reloaded
            .cookies(&Url::parse("https://example.com/").unwrap())
            .unwrap();
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
        set_cookie(&jar, "https://example.com/", "sid=abc; Path=/; Secure; HttpOnly");
        let snap = jar.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].name, "sid");
        assert_eq!(snap[0].value, "abc");
        assert!(snap[0].secure && snap[0].http_only);
    }
}
