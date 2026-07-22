//! Tracker / ad / analytics domain blocklist.
//!
//! When tracker-blocking is enabled, subresource requests (external scripts,
//! `fetch`/XHR) whose host is on this list are dropped before they are made, so
//! the tracker never loads or runs. That trims the passive-fingerprinting and
//! analytics surface a page can probe us with, and speeds loads up.
//!
//! Note: this is deliberately an *ads/analytics* list, **not** an anti-bot-vendor
//! list. Blocking a site's DataDome/PerimeterX/Cloudflare script would starve it
//! of the token it needs and get us blocked — those must run and pass, so they
//! are not here.

use std::collections::HashSet;
use std::sync::OnceLock;

/// The domain list, embedded at build time. See the file header for its source
/// and how to regenerate it.
const PGL_LIST: &str = include_str!("pgl_domains.txt");

fn blocklist() -> &'static HashSet<&'static str> {
    static BLOCKLIST: OnceLock<HashSet<&str>> = OnceLock::new();
    BLOCKLIST.get_or_init(|| {
        PGL_LIST
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    })
}

/// Whether `host` is a blocked tracker/ad/analytics domain.
///
/// Matches the exact host and every parent domain, so `www.google-analytics.com`
/// and `ssl.google-analytics.com` both match the listed `google-analytics.com`
/// without over-blocking a sibling like `analytics.example.com`.
pub fn is_blocked(host: &str) -> bool {
    let bl = blocklist();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if bl.contains(host.as_str()) {
        return true;
    }
    let mut domain = host.as_str();
    while let Some(pos) = domain.find('.') {
        domain = &domain[pos + 1..];
        if bl.contains(domain) {
            return true;
        }
    }
    false
}

/// The host component of a URL, lowercased, or `None` if it can't be parsed.
pub fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
}

/// Whether a full URL points at a blocked tracker domain.
pub fn is_blocked_url(url: &str) -> bool {
    host_of(url).map(|h| is_blocked(&h)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_trackers_are_blocked() {
        assert!(is_blocked("google-analytics.com"));
        assert!(is_blocked("doubleclick.net"));
        assert!(is_blocked("adnxs.com"));
        assert!(is_blocked("criteo.com"));
    }

    #[test]
    fn subdomains_match_the_parent() {
        assert!(is_blocked("www.google-analytics.com"));
        assert!(is_blocked("ssl.google-analytics.com"));
        assert!(is_blocked("stats.g.doubleclick.net"));
    }

    #[test]
    fn benign_hosts_are_not_blocked() {
        assert!(!is_blocked("google.com"));
        assert!(!is_blocked("github.com"));
        assert!(!is_blocked("example.com"));
        // A host that merely ends in a listed label but isn't a subdomain of it.
        assert!(!is_blocked("notdoubleclick.net"));
    }

    #[test]
    fn anti_bot_vendors_are_not_blocked() {
        // These must run to hand the site a token — never block them.
        for host in [
            "datadome.co",
            "perimeterx.net",
            "hcaptcha.com",
            "challenges.cloudflare.com",
        ] {
            assert!(!is_blocked(host), "{host} must not be blocked");
        }
    }

    #[test]
    fn url_and_host_helpers() {
        assert!(is_blocked_url(
            "https://www.google-analytics.com/analytics.js"
        ));
        assert!(!is_blocked_url("https://cdn.example.com/app.js"));
        assert_eq!(
            host_of("https://Www.Example.com/x").as_deref(),
            Some("www.example.com")
        );
    }

    #[test]
    fn list_is_substantial() {
        assert!(
            blocklist().len() > 3000,
            "blocklist unexpectedly small: {}",
            blocklist().len()
        );
    }
}
