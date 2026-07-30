//! Exit-IP geolocation, so a rotated fingerprint's timezone/locale can match the
//! proxy it routes through (a browser whose `Intl` timezone disagrees with its
//! IP is a documented tell).
//!
//! This module only *parses* a geo response; the request is made by the engine
//! through the context's own client, so the lookup travels the same proxy as the
//! traffic it describes (and looks like ordinary page traffic). Mapping the IANA
//! zone to a coherent `StealthProfile` lives in `nokk_stealth`.

use serde::Deserialize;

/// Where to resolve the exit IP's location. `ip-api.com` is free, needs no key,
/// speaks plain JSON, and returns the IANA timezone + ISO country directly. The
/// `fields` filter keeps the response tiny and avoids requesting anything we
/// don't use.
pub const GEO_LOOKUP_URL: &str = "http://ip-api.com/json/?fields=status,timezone,countryCode";

/// The location of the exit IP, as much as a rotated profile needs to stay
/// coherent with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoInfo {
    /// IANA timezone of the exit IP, e.g. `"Europe/Berlin"`.
    pub timezone: String,
    /// ISO-3166 alpha-2 country code of the exit IP, e.g. `"DE"`.
    pub country_code: String,
}

/// The `ip-api.com` JSON shape (only the fields we request).
#[derive(Deserialize)]
struct IpApiResponse {
    status: String,
    #[serde(default)]
    timezone: String,
    #[serde(default, rename = "countryCode")]
    country_code: String,
}

/// Parse an `ip-api.com` response body into [`GeoInfo`], or `None` if the lookup
/// failed or the payload is unusable. Best-effort: any parse error just means the
/// caller keeps the profile's default zone.
pub fn parse_geo(body: &[u8]) -> Option<GeoInfo> {
    let parsed: IpApiResponse = serde_json::from_slice(body).ok()?;
    if parsed.status != "success" || parsed.timezone.is_empty() {
        return None;
    }
    Some(GeoInfo {
        timezone: parsed.timezone,
        country_code: parsed.country_code.to_ascii_uppercase(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_successful_lookup() {
        let body = br#"{"status":"success","countryCode":"de","timezone":"Europe/Berlin"}"#;
        assert_eq!(
            parse_geo(body),
            Some(GeoInfo {
                timezone: "Europe/Berlin".into(),
                country_code: "DE".into(),
            })
        );
    }

    #[test]
    fn rejects_failures_and_junk() {
        assert_eq!(
            parse_geo(br#"{"status":"fail","message":"private range"}"#),
            None
        );
        assert_eq!(parse_geo(br#"{"status":"success","timezone":""}"#), None);
        assert_eq!(parse_geo(b"not json"), None);
        assert_eq!(parse_geo(b""), None);
    }

    #[test]
    fn country_is_normalised_uppercase() {
        let body = br#"{"status":"success","countryCode":"us","timezone":"America/New_York"}"#;
        assert_eq!(parse_geo(body).unwrap().country_code, "US");
    }
}
