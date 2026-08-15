//! Stealth: the JS-visible fingerprint.
//!
//! Phase 6 injects patches *before* any page script runs so automation is not
//! detectable: spoof `navigator` (userAgent, platform, languages,
//! hardwareConcurrency, `webdriver`), emulate canvas/WebGL/audio fingerprints,
//! and mask native functions so `Function.prototype.toString` on a patched API
//! still looks native.
//!
//! Crucially the values here MUST agree with the network fingerprint
//! (`nokk-net`): a Chrome userAgent over a Firefox TLS ClientHello is an
//! instant tell. This crate is pure data + script generation with no runtime
//! deps so it can be unit-tested and audited on its own.

use serde::{Deserialize, Serialize};

/// The identity presented to page JavaScript. Keep in lockstep with the network
/// `FingerprintProfile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthProfile {
    pub user_agent: String,
    pub platform: String,
    /// Language tags in `navigator.languages` order; `navigator.language` is the
    /// first entry.
    pub languages: Vec<String>,
    pub hardware_concurrency: u32,
    pub device_memory_gb: u32,
    /// Reported `navigator.vendor`.
    pub vendor: String,
    /// WebGL `UNMASKED_VENDOR_WEBGL` / `UNMASKED_RENDERER_WEBGL`.
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    /// IANA timezone reported by the `Intl` shim
    /// (`Intl.DateTimeFormat().resolvedOptions().timeZone`). A fingerprint vector,
    /// so it lives with the rest of the identity.
    pub timezone: String,
    /// Standard-time (non-DST) UTC offset in minutes, in `getTimezoneOffset`
    /// convention (positive = behind UTC). Must be coherent with [`Self::timezone`]
    /// — the `Date` shim derives every timezone-dependent value from it so
    /// `getTimezoneOffset()`, `Date.toString()` and `Intl` never disagree.
    pub timezone_offset_minutes: i32,
    /// DST rule: `"us"` (2nd Sun Mar → 1st Sun Nov), `"eu"` (last Sun Mar → last
    /// Sun Oct), or `"none"` (fixed offset). DST subtracts 60 from the offset.
    pub timezone_dst: String,
    /// Long zone names for `Date.toString()`, standard and DST
    /// (e.g. "Eastern Standard Time" / "Eastern Daylight Time").
    pub timezone_name_std: String,
    pub timezone_name_dst: String,
    /// `screen.width`/`.height` (and `availWidth` == width). A fingerprint vector,
    /// and it must be plausible for the OS.
    pub screen_width: u32,
    pub screen_height: u32,
    /// `screen.availHeight` (height minus the OS's menu/task bar).
    pub avail_height: u32,
    /// `screen.colorDepth`/`.pixelDepth`.
    pub color_depth: u32,
    /// `navigator.userAgentData.platform` — the Client Hints platform
    /// (`"Windows"`/`"macOS"`/`"Linux"`), which must agree with the UA and
    /// `navigator.platform`.
    pub ua_platform: String,
    /// Chrome major version reported by the UA / `userAgentData` brands. Must
    /// match the TLS emulation ([`nokk_net`]'s `chrome_major`). Change it via
    /// [`Self::with_chrome_major`] so the UA string and this field stay coherent.
    pub chrome_major: u32,
}

impl Default for StealthProfile {
    /// A recent stable Chrome on desktop Linux — the [`FingerprintProfile::ChromeLinux`]
    /// preset, so there is one source of truth for the default identity.
    fn default() -> Self {
        FingerprintProfile::ChromeLinux.stealth()
    }
}

impl StealthProfile {
    /// Re-version this profile to a different Chrome major: the UA's
    /// `Chrome/<n>.0.0.0` token and [`Self::chrome_major`] (which drives the
    /// `userAgentData` brand version in the bootstrap) are rewritten together, so
    /// the reported version stays coherent. Pair with `nokk_net`'s TLS emulation
    /// at the *same* major, or the UA and the ClientHello disagree.
    pub fn with_chrome_major(mut self, major: u32) -> Self {
        let old = format!("Chrome/{}.0.0.0", self.chrome_major);
        let new = format!("Chrome/{major}.0.0.0");
        self.user_agent = self.user_agent.replace(&old, &new);
        self.chrome_major = major;
        self
    }
}

/// The Chrome major version every profile's UA / client hints report. **Must**
/// match the TLS emulation (`nokk_net::FingerprintClient::EMULATION` = Chrome
/// 148) or the JS UA and the ClientHello disagree — an instant anti-bot tell.
pub const CHROME_MAJOR: &str = "148";

/// The OS a fingerprint profile emulates. The network layer maps this to a wreq
/// `EmulationOS` so the TLS ClientHello matches the profile's UA and platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileOs {
    Linux,
    Windows,
    Mac,
}

/// A named, internally-coherent fingerprint preset.
///
/// Rotating these per browser context makes distinct contexts look like distinct
/// machines — but *only* because every layer agrees. Naive User-Agent rotation is
/// a net negative: a UA that doesn't match the platform, the TLS/JA3 handshake, or
/// the `sec-ch-ua` client hints is itself a documented detection signal. Each
/// preset therefore drives the whole [`StealthProfile`] and names the OS the TLS
/// emulation must use ([`Self::os`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FingerprintProfile {
    ChromeLinux,
    ChromeWindows,
    ChromeMac,
}

impl FingerprintProfile {
    /// Every preset, for rotation.
    pub const ALL: [FingerprintProfile; 3] =
        [Self::ChromeLinux, Self::ChromeWindows, Self::ChromeMac];

    /// The OS this preset emulates (drives the TLS `EmulationOS`).
    pub fn os(self) -> ProfileOs {
        match self {
            Self::ChromeLinux => ProfileOs::Linux,
            Self::ChromeWindows => ProfileOs::Windows,
            Self::ChromeMac => ProfileOs::Mac,
        }
    }

    /// Deterministically pick a preset from a seed — a context's identity seed
    /// maps to a stable-but-varied profile for per-context rotation.
    pub fn from_seed(seed: u64) -> Self {
        Self::ALL[(seed % Self::ALL.len() as u64) as usize]
    }

    /// The coherent [`StealthProfile`] for this preset: every field
    /// (UA / platform / vendor / WebGL / concurrency) agrees with the OS, and the
    /// Chrome major matches the TLS emulation.
    pub fn stealth(self) -> StealthProfile {
        // Timezone is device- not OS-specific; keep one coherent US/Eastern zone
        // for all presets until geoIP-derived zones land.
        let tz = || {
            (
                "America/New_York".to_string(),
                300,
                "us".to_string(),
                "Eastern Standard Time".to_string(),
                "Eastern Daylight Time".to_string(),
            )
        };
        let (timezone, timezone_offset_minutes, timezone_dst, timezone_name_std, timezone_name_dst) =
            tz();
        // OS-derived, coherent by construction: navigator.platform, the Client
        // Hints platform, and a plausible screen for each OS.
        let (platform, ua_platform, sw, sh, avail_height, color_depth) = match self.os() {
            ProfileOs::Linux => ("Linux x86_64", "Linux", 1920u32, 1080u32, 1053u32, 24u32),
            ProfileOs::Windows => ("Win32", "Windows", 1920, 1080, 1032, 24),
            ProfileOs::Mac => ("MacIntel", "macOS", 1512, 982, 944, 30),
        };
        let common = |ua: &str, hw: u32, webgl_vendor: &str, webgl_renderer: &str| StealthProfile {
            user_agent: ua.to_string(),
            platform: platform.to_string(),
            ua_platform: ua_platform.to_string(),
            chrome_major: CHROME_MAJOR.parse().unwrap_or(148),
            languages: vec!["en-US".into(), "en".into()],
            hardware_concurrency: hw,
            device_memory_gb: 8, // Chrome caps navigator.deviceMemory at 8
            vendor: "Google Inc.".into(),
            webgl_vendor: webgl_vendor.to_string(),
            webgl_renderer: webgl_renderer.to_string(),
            screen_width: sw,
            screen_height: sh,
            avail_height,
            color_depth,
            timezone: timezone.clone(),
            timezone_offset_minutes,
            timezone_dst: timezone_dst.clone(),
            timezone_name_std: timezone_name_std.clone(),
            timezone_name_dst: timezone_name_dst.clone(),
        };
        match self {
            Self::ChromeLinux => common(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/148.0.0.0 Safari/537.36",
                8,
                "Google Inc. (Intel)",
                "ANGLE (Intel, Mesa Intel(R) UHD Graphics, OpenGL 4.6)",
            ),
            Self::ChromeWindows => common(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/148.0.0.0 Safari/537.36",
                16,
                "Google Inc. (NVIDIA)",
                "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            Self::ChromeMac => common(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                8,
                "Google Inc. (Apple)",
                "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)",
            ),
        }
    }
}

/// The timezone half of a [`StealthProfile`], resolved from an IANA zone name:
/// the standard-time offset and DST rule the `Date` shim needs, plus the long
/// zone names `Date.toString()` prints. See [`timezone_fields`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimezoneFields {
    /// Standard-time UTC offset in minutes, `getTimezoneOffset` convention
    /// (positive = behind UTC).
    pub offset_std_minutes: i32,
    /// DST rule the `Date` shim understands: `"us"`, `"eu"`, or `"none"`.
    pub dst_rule: &'static str,
    pub name_std: &'static str,
    pub name_dst: &'static str,
}

/// The coherent timezone fields for a common IANA zone, or `None` for a zone we
/// don't carry (the caller then keeps the profile's default zone rather than
/// half-applying an incoherent one).
///
/// The `Date` shim only models northern-hemisphere `"us"`/`"eu"` DST, so
/// southern-hemisphere zones (Sydney, Auckland, São Paulo…) are listed as
/// `"none"` at their standard offset — coherent year-round except during their
/// summer DST, a far smaller tell than an offset that contradicts the IP.
pub fn timezone_fields(iana: &str) -> Option<TimezoneFields> {
    // (offset_std_minutes, dst_rule, name_std, name_dst)
    let f = |offset_std_minutes, dst_rule, name_std, name_dst| {
        Some(TimezoneFields {
            offset_std_minutes,
            dst_rule,
            name_std,
            name_dst,
        })
    };
    match iana {
        // North America (US DST rule).
        "America/New_York" | "America/Toronto" => {
            f(300, "us", "Eastern Standard Time", "Eastern Daylight Time")
        }
        "America/Chicago" => f(360, "us", "Central Standard Time", "Central Daylight Time"),
        "America/Denver" => f(
            420,
            "us",
            "Mountain Standard Time",
            "Mountain Daylight Time",
        ),
        "America/Phoenix" => f(
            420,
            "none",
            "Mountain Standard Time",
            "Mountain Standard Time",
        ),
        "America/Los_Angeles" | "America/Vancouver" => {
            f(480, "us", "Pacific Standard Time", "Pacific Daylight Time")
        }
        "America/Anchorage" => f(540, "us", "Alaska Standard Time", "Alaska Daylight Time"),
        "America/Mexico_City" => f(
            360,
            "none",
            "Central Standard Time",
            "Central Standard Time",
        ),
        "America/Sao_Paulo" => f(
            180,
            "none",
            "Brasilia Standard Time",
            "Brasilia Standard Time",
        ),
        // Europe / Africa (EU DST rule, or none).
        "Europe/London" | "Europe/Dublin" | "Europe/Lisbon" => {
            f(0, "eu", "Greenwich Mean Time", "British Summer Time")
        }
        "Europe/Paris" | "Europe/Berlin" | "Europe/Madrid" | "Europe/Rome" | "Europe/Amsterdam"
        | "Europe/Brussels" | "Europe/Vienna" | "Europe/Zurich" | "Europe/Prague"
        | "Europe/Warsaw" | "Europe/Stockholm" | "Europe/Oslo" | "Europe/Copenhagen"
        | "Europe/Budapest" => f(
            -60,
            "eu",
            "Central European Standard Time",
            "Central European Summer Time",
        ),
        "Europe/Athens" | "Europe/Helsinki" | "Europe/Bucharest" | "Europe/Kyiv"
        | "Europe/Kiev" | "Europe/Riga" | "Europe/Sofia" => f(
            -120,
            "eu",
            "Eastern European Standard Time",
            "Eastern European Summer Time",
        ),
        "Europe/Istanbul" => f(-180, "none", "GMT+03:00", "GMT+03:00"),
        "Europe/Moscow" => f(-180, "none", "Moscow Standard Time", "Moscow Standard Time"),
        "Africa/Lagos" => f(
            -60,
            "none",
            "West Africa Standard Time",
            "West Africa Standard Time",
        ),
        "Africa/Johannesburg" => f(
            -120,
            "none",
            "South Africa Standard Time",
            "South Africa Standard Time",
        ),
        // Asia / Pacific (fixed offsets).
        "Asia/Dubai" => f(-240, "none", "Gulf Standard Time", "Gulf Standard Time"),
        "Asia/Karachi" => f(
            -300,
            "none",
            "Pakistan Standard Time",
            "Pakistan Standard Time",
        ),
        "Asia/Kolkata" | "Asia/Calcutta" => {
            f(-330, "none", "India Standard Time", "India Standard Time")
        }
        "Asia/Dhaka" => f(
            -360,
            "none",
            "Bangladesh Standard Time",
            "Bangladesh Standard Time",
        ),
        "Asia/Bangkok" | "Asia/Jakarta" => f(-420, "none", "Indochina Time", "Indochina Time"),
        "Asia/Shanghai" | "Asia/Hong_Kong" => {
            f(-480, "none", "China Standard Time", "China Standard Time")
        }
        "Asia/Singapore" => f(
            -480,
            "none",
            "Singapore Standard Time",
            "Singapore Standard Time",
        ),
        "Asia/Taipei" => f(-480, "none", "Taipei Standard Time", "Taipei Standard Time"),
        "Asia/Tokyo" => f(-540, "none", "Japan Standard Time", "Japan Standard Time"),
        "Asia/Seoul" => f(-540, "none", "Korean Standard Time", "Korean Standard Time"),
        "Australia/Sydney" | "Australia/Melbourne" => f(
            -600,
            "none",
            "Australian Eastern Standard Time",
            "Australian Eastern Standard Time",
        ),
        "Pacific/Auckland" => f(
            -720,
            "none",
            "New Zealand Standard Time",
            "New Zealand Standard Time",
        ),
        "UTC" | "Etc/UTC" | "Etc/GMT" => f(
            0,
            "none",
            "Coordinated Universal Time",
            "Coordinated Universal Time",
        ),
        _ => None,
    }
}

/// A plausible `navigator.languages` list for an ISO-3166 country code — so the
/// reported locale matches the exit IP's country. Defaults to US English for
/// countries we don't carry (English is a safe, common fallback and never
/// contradicts an unknown region the way a wrong specific locale would).
pub fn country_languages(country_code: &str) -> Vec<String> {
    let v = |tags: &[&str]| tags.iter().map(|s| s.to_string()).collect();
    match country_code.to_ascii_uppercase().as_str() {
        "US" => v(&["en-US", "en"]),
        "GB" => v(&["en-GB", "en"]),
        "CA" => v(&["en-CA", "fr-CA", "en"]),
        "AU" => v(&["en-AU", "en"]),
        "NZ" => v(&["en-NZ", "en"]),
        "IE" => v(&["en-IE", "en"]),
        "ZA" => v(&["en-ZA", "en"]),
        "DE" | "AT" => v(&["de-DE", "de", "en"]),
        "CH" => v(&["de-CH", "de", "fr", "en"]),
        "FR" => v(&["fr-FR", "fr", "en"]),
        "ES" => v(&["es-ES", "es", "en"]),
        "IT" => v(&["it-IT", "it", "en"]),
        "NL" => v(&["nl-NL", "nl", "en"]),
        "BE" => v(&["nl-BE", "fr-BE", "en"]),
        "PT" => v(&["pt-PT", "pt", "en"]),
        "PL" => v(&["pl-PL", "pl", "en"]),
        "SE" => v(&["sv-SE", "sv", "en"]),
        "NO" => v(&["nb-NO", "no", "en"]),
        "DK" => v(&["da-DK", "da", "en"]),
        "FI" => v(&["fi-FI", "fi", "en"]),
        "CZ" => v(&["cs-CZ", "cs", "en"]),
        "HU" => v(&["hu-HU", "hu", "en"]),
        "RO" => v(&["ro-RO", "ro", "en"]),
        "GR" => v(&["el-GR", "el", "en"]),
        "TR" => v(&["tr-TR", "tr", "en"]),
        "RU" => v(&["ru-RU", "ru"]),
        "UA" => v(&["uk-UA", "uk", "ru"]),
        "BR" => v(&["pt-BR", "pt", "en"]),
        "MX" => v(&["es-MX", "es", "en"]),
        "JP" => v(&["ja-JP", "ja"]),
        "KR" => v(&["ko-KR", "ko"]),
        "CN" => v(&["zh-CN", "zh"]),
        "TW" => v(&["zh-TW", "zh"]),
        "HK" => v(&["zh-HK", "zh", "en"]),
        "SG" => v(&["en-SG", "en", "zh"]),
        "IN" => v(&["en-IN", "en", "hi"]),
        "AE" => v(&["ar-AE", "ar", "en"]),
        "PK" => v(&["en-PK", "ur", "en"]),
        "BD" => v(&["bn-BD", "bn", "en"]),
        "TH" => v(&["th-TH", "th", "en"]),
        "ID" => v(&["id-ID", "id", "en"]),
        _ => v(&["en-US", "en"]),
    }
}

/// Return `profile` with its timezone and locale overridden to match an exit IP's
/// geolocation (IANA `timezone` + ISO `country_code`), leaving the OS-derived
/// identity (UA, platform, screen, WebGL) untouched. The timezone is only changed
/// when [`timezone_fields`] knows the zone, so the result is always coherent;
/// languages always follow the country ([`country_languages`] falls back to
/// English). This is how a rotated profile stays consistent with the proxy it
/// exits through.
pub fn apply_geo(profile: &StealthProfile, timezone: &str, country_code: &str) -> StealthProfile {
    let mut p = profile.clone();
    if let Some(tz) = timezone_fields(timezone) {
        p.timezone = timezone.to_string();
        p.timezone_offset_minutes = tz.offset_std_minutes;
        p.timezone_dst = tz.dst_rule.to_string();
        p.timezone_name_std = tz.name_std.to_string();
        p.timezone_name_dst = tz.name_dst.to_string();
    }
    p.languages = country_languages(country_code);
    p
}

/// Produce the JavaScript that must run before any page script. In Phase 5 this
/// is delivered via `Page.addScriptToEvaluateOnNewDocument`.
///
/// The scripts are intentionally small and composed at runtime from the profile
/// so a single source of truth (the [`StealthProfile`]) drives every spoofed
/// value.
pub fn injection_script(profile: &StealthProfile) -> String {
    let languages = json_string_array(&profile.languages);
    // Note: values are embedded via `json_escape` to stay valid JS strings.
    format!(
        r#"(() => {{
  const def = (obj, prop, value) => Object.defineProperty(obj, prop, {{ get: () => value, configurable: true }});
  // navigator.webdriver must be false/undefined, never true.
  def(navigator, 'webdriver', false);
  def(navigator, 'userAgent', "{ua}");
  def(navigator, 'platform', "{platform}");
  def(navigator, 'vendor', "{vendor}");
  def(navigator, 'language', "{lang0}");
  def(navigator, 'languages', Object.freeze({languages}));
  def(navigator, 'hardwareConcurrency', {hw});
  def(navigator, 'deviceMemory', {mem});
  // TODO(Phase 6): mask native toString, canvas/WebGL/audio noise, permissions,
  // plugins/mimeTypes to match {renderer}.
}})();"#,
        ua = json_escape(&profile.user_agent),
        platform = json_escape(&profile.platform),
        vendor = json_escape(&profile.vendor),
        lang0 = json_escape(
            profile
                .languages
                .first()
                .map(String::as_str)
                .unwrap_or("en-US")
        ),
        languages = languages,
        hw = profile.hardware_concurrency,
        mem = profile.device_memory_gb,
        renderer = json_escape(&profile.webgl_renderer),
    )
}

/// Build the JavaScript that establishes a spoofed browser environment inside a
/// bare V8 context: `window` (== `globalThis`), `navigator`, `screen`,
/// `location`, `history` and a no-op `console`. Every value derives from
/// `profile`, so the JS-visible fingerprint has a single source of truth and
/// stays coherent with the network fingerprint.
///
/// This is what makes JS fingerprint probes (e.g. those on
/// browserleaks.com/javascript) report Chrome values with `navigator.webdriver`
/// hidden. A real DOM (`document`, elements, events) arrives with Phases 3–4;
/// until then, page scripts that require the DOM will not run to completion.
pub fn bootstrap_script(profile: &StealthProfile) -> String {
    // `appVersion` is the userAgent without the leading "Mozilla/".
    let app_version = profile
        .user_agent
        .strip_prefix("Mozilla/")
        .unwrap_or(&profile.user_agent);

    let lang0 = quoted(
        profile
            .languages
            .first()
            .map(String::as_str)
            .unwrap_or("en-US"),
    );
    let env = ENVIRONMENT_TEMPLATE
        .replace("__UA__", &quoted(&profile.user_agent))
        .replace("__APPVERSION__", &quoted(app_version))
        .replace("__PLATFORM__", &quoted(&profile.platform))
        .replace("__VENDOR__", &quoted(&profile.vendor))
        .replace("__LANG0__", &lang0)
        .replace("__LANGS__", &json_string_array(&profile.languages))
        .replace("__HW__", &profile.hardware_concurrency.to_string())
        .replace("__MEM__", &profile.device_memory_gb.to_string())
        .replace("__WEBGL_VENDOR__", &quoted(&profile.webgl_vendor))
        .replace("__WEBGL_RENDERER__", &quoted(&profile.webgl_renderer))
        .replace("__CHROME_MAJOR__", &profile.chrome_major.to_string())
        .replace("__UA_PLATFORM__", &quoted(&profile.ua_platform))
        .replace("__SCREEN_W__", &profile.screen_width.to_string())
        .replace("__SCREEN_H__", &profile.screen_height.to_string())
        .replace("__AVAIL_H__", &profile.avail_height.to_string())
        .replace("__COLOR_DEPTH__", &profile.color_depth.to_string());

    // The Intl shim shadows the prebuilt V8's native Intl/Date-locale APIs, which
    // ICU-abort the whole process (this build lacks working ICU data). It also
    // pins timezone/locale to the profile — both fingerprint vectors.
    let intl = INTL_SHIM_TEMPLATE
        .replace("__TZ__", &quoted(&profile.timezone))
        .replace("__LANG0__", &lang0)
        .replace(
            "__TZ_OFFSET__",
            &profile.timezone_offset_minutes.to_string(),
        )
        .replace("__TZ_DST__", &quoted(&profile.timezone_dst))
        .replace("__TZ_NAME_STD__", &quoted(&profile.timezone_name_std))
        .replace("__TZ_NAME_DST__", &quoted(&profile.timezone_name_dst));

    let timers = TIMERS_TEMPLATE.replace(
        "__FAST_TIMERS__",
        if fast_timers() { "true" } else { "false" },
    );

    format!("{env}\n{intl}\n{timers}\n{PERFORMANCE_TEMPLATE}\n{CRYPTO_TEMPLATE}\n{FETCH_TEMPLATE}")
}

/// Whether timers collapse their delays instead of waiting them out
/// (`NOKK_FAST_TIMERS`). Off by default: a page that can measure a `setTimeout`
/// against `Date.now()` — every anti-bot watchdog does — must see the delay it
/// asked for. Worth turning on only for bulk scraping of pages that merely
/// *use* timers rather than time them, where collapsing the waits is the whole
/// point.
fn fast_timers() -> bool {
    std::env::var("NOKK_FAST_TIMERS")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false)
}

/// The environment template. Placeholders (`__UA__`, …) are substituted by
/// [`bootstrap_script`]. Kept as a raw string so the JS reads naturally without
/// brace-escaping.
const ENVIRONMENT_TEMPLATE: &str = r#"(() => {
  const win = globalThis;

  // Host objects the Chrome way: their properties live on a constructor's
  // prototype (as getters), so instances carry no own enumerable props —
  // `Object.keys(navigator)` is [], the prototype chain is correct, and
  // `navigator instanceof Navigator` holds. A plain object literal (the old
  // approach) fails all three, an instant headless tell.
  const defClass = (name) => {
    const Ctor = function () { throw new TypeError("Illegal constructor"); };
    try { Object.defineProperty(Ctor, "name", { value: name, configurable: true }); } catch (e) {}
    // Без этого `Object.prototype.toString.call(navigator)` отвечает
    // `[object Object]` вместо `[object Navigator]` — самая дешёвая проверка на
    // подделку из всех, и мы её не проходили.
    try {
      Object.defineProperty(Ctor.prototype, Symbol.toStringTag, { value: name, configurable: true });
    } catch (e) {}
    win[name] = Ctor;
    return Ctor.prototype;
  };
  // Define an accessor whose getter is named `get <key>` (matching Chrome's
  // reflection) and reads `read()`; an optional `write` makes it settable.
  const accessor = (proto, key, read, write) => {
    const holder = write
      ? { get [key]() { return read(); }, set [key](v) { write(v); } }
      : { get [key]() { return read(); } };
    Object.defineProperty(proto, key, Object.getOwnPropertyDescriptor(holder, key));
  };
  const staticProps = (proto, obj) => {
    for (const k of Object.keys(obj)) { const v = obj[k]; accessor(proto, k, () => v); }
  };
  const protoMethod = (proto, name, fn) => {
    try { Object.defineProperty(proto, name, { value: fn, enumerable: true, configurable: true, writable: true }); } catch (e) {}
  };

  // --- navigator --------------------------------------------------------
  const NavigatorProto = defClass("Navigator");
  staticProps(NavigatorProto, {
    userAgent: __UA__, appVersion: __APPVERSION__, appName: "Netscape", appCodeName: "Mozilla",
    platform: __PLATFORM__, product: "Gecko", productSub: "20030107", vendor: __VENDOR__, vendorSub: "",
    language: __LANG0__, languages: Object.freeze(__LANGS__), hardwareConcurrency: __HW__,
    deviceMemory: __MEM__, maxTouchPoints: 0, webdriver: false, onLine: true, cookieEnabled: true,
    doNotTrack: null, pdfViewerEnabled: true,
    userAgentData: { brands: [
      { brand: "Chromium", version: "__CHROME_MAJOR__" }, { brand: "Google Chrome", version: "__CHROME_MAJOR__" }, { brand: "Not.A/Brand", version: "24" }
    ], mobile: false, platform: __UA_PLATFORM__ },
  });
  win.navigator = Object.create(NavigatorProto);

  win.window = win; win.self = win; win.top = win; win.parent = win; win.frames = win;
  win.length = 0; win.name = ""; win.closed = false;

  // --- screen -----------------------------------------------------------
  const ScreenProto = defClass("Screen");
  staticProps(ScreenProto, {
    width: __SCREEN_W__, height: __SCREEN_H__, availWidth: __SCREEN_W__, availHeight: __AVAIL_H__, availTop: 0, availLeft: 0,
    colorDepth: __COLOR_DEPTH__, pixelDepth: __COLOR_DEPTH__, isExtended: false,
    orientation: { type: "landscape-primary", angle: 0 },
  });
  win.screen = Object.create(ScreenProto);
  win.innerWidth = 1920; win.innerHeight = 969;
  win.outerWidth = 1920; win.outerHeight = 1080;
  win.devicePixelRatio = 1;

  // --- location (getters read a backing store the Rust driver updates) --
  const LocationProto = defClass("Location");
  const locState = { href: "about:blank", protocol: "about:", host: "", hostname: "", port: "", pathname: "blank", search: "", hash: "", origin: "null" };
  // A page navigating itself is not a detail: `location.href = …`,
  // `location.replace(…)` and `location.reload()` are how a form handoff, an
  // OAuth bounce and — the reason this exists — a Cloudflare challenge finish.
  // Ours only rewrote the address bar, so the last step of those flows silently
  // never happened. The request goes to the driver, which performs a real
  // navigation of this context.
  const navQueue = [];
  const askNav = (raw, replace) => {
    const url = String(raw);
    if (!url) return;
    let abs = url;
    try { abs = new URL(url, locState.href).href; } catch (e) {}
    navQueue.push({ url: abs, replace: !!replace });
  };
  globalThis.__pt_drainNavQueue = () => navQueue.splice(0);

  for (const k of Object.keys(locState)) {
    accessor(LocationProto, k, () => locState[k], (v) => {
      // Assigning `href` navigates; the other parts navigate to the URL they
      // produce, which is what a browser does with `location.hash = …` too.
      if (k === 'href') { askNav(v, false); return; }
      locState[k] = String(v);
    });
  }
  protoMethod(LocationProto, "assign", function assign(u){ askNav(u, false); });
  protoMethod(LocationProto, "replace", function replace(u){ askNav(u, true); });
  protoMethod(LocationProto, "reload", function reload(){ askNav(locState.href, true); });
  protoMethod(LocationProto, "toString", function toString(){ return locState.href; });
  // `window.location = url` — такой же переход, как `location.href = url`, и
  // именно им завершают себя многие потоки (в том числе челлендж Cloudflare).
  // Данным свойством окно ловило строку вместо объекта: адрес затирался,
  // перехода не было, и страница дальше жила со сломанным `location`.
  const locationObject = Object.create(LocationProto);
  accessor(win, 'location', () => locationObject, (v) => {
    if (v !== locationObject) askNav(v, false);
  });
  // Rust calls this on navigation to populate `location` from the real URL —
  // a static `about:blank` is an instant tell (and breaks relative logic).
  globalThis.__pt_setLocation = (o) => { for (const k in o) if (k in locState) locState[k] = o[k]; };

  // --- history ----------------------------------------------------------
  const HistoryProto = defClass("History");
  staticProps(HistoryProto, { length: 1, scrollRestoration: "auto", state: null });
  for (const m of ["back", "forward", "go", "pushState", "replaceState"]) protoMethod(HistoryProto, m, function(){});
  win.history = Object.create(HistoryProto);

  // Окно называет себя окном: тег ставим собственным свойством, а не на
  // прототипе — прототип у глобального объекта общий с обычными объектами.
  try {
    Object.defineProperty(win, Symbol.toStringTag, { value: 'Window', configurable: true });
  } catch (e) {}

  // Консоль браузера — не один общий `() => {}` на все имена: там два десятка
  // методов, каждый со своим именем и `[native code]`, а сам объект зовётся
  // `[object console]`. И сказанное в неё не должно пропадать: страница,
  // сообщающая «[Cloudflare Turnstile] Unhandled error: …», говорит это именно
  // сюда, а у нас это был самый тихий способ потерять причину.
  const CONSOLE = ['assert', 'clear', 'context', 'count', 'countReset', 'createTask', 'debug',
    'dir', 'dirxml', 'error', 'group', 'groupCollapsed', 'groupEnd', 'info', 'log', 'profile',
    'profileEnd', 'table', 'time', 'timeEnd', 'timeLog', 'timeStamp', 'trace', 'warn'];
  const SPOKEN = { log: 1, info: 1, warn: 1, error: 1, debug: 1, trace: 1, assert: 1, dir: 1 };
  const said = [];
  globalThis.__pt_drainConsole = () => said.splice(0);
  const show = (v) => {
    try {
      if (typeof v === 'string') return v;
      if (v instanceof Error) return String(v.stack || v.message || v);
      if (typeof v === 'object' && v !== null) { try { return JSON.stringify(v); } catch (e) { return String(v); } }
      return String(v);
    } catch (e) { return '?'; }
  };
  const con = {};
  for (const name of CONSOLE) {
    con[name] = { [name]: function () {
      if (!SPOKEN[name] || said.length > 256) return undefined;
      const parts = [];
      for (let i = 0; i < arguments.length && i < 8; i++) parts.push(show(arguments[i]));
      said.push([name, parts.join(' ').slice(0, 600)]);
      return undefined;
    } }[name];
  }
  try { Object.defineProperty(con, Symbol.toStringTag, { value: 'console', configurable: true }); } catch (e) {}
  win.console = con;
})();"#;

/// Replacement `Intl` + `Date`/`String`/`Number` locale APIs. The prebuilt V8's
/// native ICU path aborts the process (see [`bootstrap_script`]), so we shadow
/// every locale-aware entry point with a non-ICU JS implementation that returns
/// values pinned to the profile. `__TZ__`/`__LANG0__` are substituted at build.
const INTL_SHIM_TEMPLATE: &str = r#"(() => {
  const TZ = __TZ__, LOCALE = __LANG0__;
  const norm = (l) => Array.isArray(l) ? (l[0] || LOCALE) : (l || LOCALE);
  const list = (l) => Array.isArray(l) ? l.slice() : (l == null ? [] : [l]);

  function DateTimeFormat(locale, opts) {
    opts = opts || {};
    const ro = Object.assign(
      { locale: norm(locale), calendar: 'gregory', numberingSystem: 'latn', timeZone: opts.timeZone || TZ },
      opts);
    const toDate = (d) => d == null ? new Date() : (d instanceof Date ? d : new Date(d));
    return {
      resolvedOptions: () => Object.assign({}, ro),
      format: (d) => toDate(d).toDateString(),
      formatToParts: (d) => [{ type: 'literal', value: toDate(d).toDateString() }],
      formatRange: (a, b) => toDate(a).toDateString() + ' – ' + toDate(b).toDateString(),
    };
  }
  DateTimeFormat.supportedLocalesOf = list;

  function NumberFormat(locale, opts) {
    const ro = Object.assign({ locale: norm(locale), numberingSystem: 'latn', style: 'decimal' }, opts);
    return {
      resolvedOptions: () => Object.assign({}, ro),
      format: (n) => String(n),
      formatToParts: (n) => [{ type: 'integer', value: String(n) }],
    };
  }
  NumberFormat.supportedLocalesOf = list;

  function Collator(locale, opts) {
    const ro = Object.assign({ locale: norm(locale), usage: 'sort', sensitivity: 'variant' }, opts);
    return { resolvedOptions: () => Object.assign({}, ro), compare: (a, b) => (a < b ? -1 : a > b ? 1 : 0) };
  }
  Collator.supportedLocalesOf = list;

  function passthru(extra) {
    return function (locale, opts) {
      const ro = Object.assign({ locale: norm(locale) }, opts);
      return Object.assign({ resolvedOptions: () => Object.assign({}, ro) }, extra);
    };
  }

  // `Intl.Locale` — не заглушка из двух полей: страницы вызывают `maximize()`,
  // чтобы узнать регион, и `getTextInfo()`, чтобы выбрать направление письма.
  // Отсутствующий метод роняет весь бандл (у CapSolver — ровно так), а полный
  // CLDR нам не нужен: хватает наиболее вероятных подтегов для живых языков и
  // списка языков с письмом справа налево.
  const RTL = new Set(['ar', 'arc', 'ckb', 'dv', 'fa', 'he', 'ks', 'ku', 'pnb', 'ps',
    'sd', 'ug', 'ur', 'yi']);
  const LIKELY = {
    ar: ['Arab', 'EG'], bg: ['Cyrl', 'BG'], cs: ['Latn', 'CZ'], da: ['Latn', 'DK'],
    de: ['Latn', 'DE'], el: ['Grek', 'GR'], en: ['Latn', 'US'], es: ['Latn', 'ES'],
    fa: ['Arab', 'IR'], fi: ['Latn', 'FI'], fr: ['Latn', 'FR'], he: ['Hebr', 'IL'],
    hi: ['Deva', 'IN'], hu: ['Latn', 'HU'], id: ['Latn', 'ID'], it: ['Latn', 'IT'],
    ja: ['Jpan', 'JP'], ko: ['Kore', 'KR'], nl: ['Latn', 'NL'], no: ['Latn', 'NO'],
    pl: ['Latn', 'PL'], pt: ['Latn', 'BR'], ro: ['Latn', 'RO'], ru: ['Cyrl', 'RU'],
    sv: ['Latn', 'SE'], th: ['Thai', 'TH'], tr: ['Latn', 'TR'], uk: ['Cyrl', 'UA'],
    ur: ['Arab', 'PK'], vi: ['Latn', 'VN'], zh: ['Hans', 'CN'],
  };

  function Locale(tag, options) {
    if (!(this instanceof Locale)) throw new TypeError("Constructor Intl.Locale requires 'new'");
    const parts = String(norm(tag) || 'en-US').split('-');
    const opts = options || {};
    const script = parts.find((p) => p.length === 4 && /^[A-Za-z]+$/.test(p));
    const region = parts.slice(1).find((p) => /^([A-Za-z]{2}|\d{3})$/.test(p));
    const set = (k, v) => Object.defineProperty(this, k, { value: v, enumerable: true, configurable: true });
    set('language', opts.language || parts[0].toLowerCase());
    set('script', opts.script || (script ? script[0].toUpperCase() + script.slice(1).toLowerCase() : undefined));
    set('region', opts.region || (region ? region.toUpperCase() : undefined));
    for (const k of ['calendar', 'caseFirst', 'collation', 'hourCycle', 'numeric', 'numberingSystem']) {
      set(k, opts[k]);
    }
    set('baseName', [this.language, this.script, this.region].filter(Boolean).join('-'));
  }
  Locale.prototype = {
    toString() { return this.baseName; },
    maximize() {
      const [script, region] = LIKELY[this.language] || ['Latn', (this.language || 'en').toUpperCase()];
      return new Locale([this.language, this.script || script, this.region || region].join('-'));
    },
    minimize() { return new Locale(this.language); },
    getTextInfo() { return { direction: RTL.has(this.language) ? 'rtl' : 'ltr' }; },
    getWeekInfo() { return { firstDay: 1, weekend: [6, 7], minimalDays: 1 }; },
    getCalendars() { return ['gregory']; },
    getCollations() { return ['default']; },
    getHourCycles() { return ['h12']; },
    getNumberingSystems() { return ['latn']; },
    getTimeZones() { return this.region ? [] : undefined; },
  };
  Object.defineProperty(Locale.prototype, 'constructor', { value: Locale, writable: true, configurable: true });
  try { Object.defineProperty(Locale.prototype, Symbol.toStringTag, { value: 'Intl.Locale', configurable: true }); } catch (e) {}

  globalThis.Intl = {
    DateTimeFormat, NumberFormat, Collator,
    RelativeTimeFormat: passthru({ format: (v, u) => v + ' ' + u, formatToParts: (v, u) => [{ type: 'literal', value: v + ' ' + u }] }),
    PluralRules: passthru({ select: () => 'other' }),
    ListFormat: passthru({ format: (a) => list(a).join(', '), formatToParts: (a) => list(a).map(v => ({ type: 'element', value: v })) }),
    DisplayNames: passthru({ of: (c) => String(c) }),
    Segmenter: passthru({ segment: (s) => [{ segment: String(s), index: 0, input: String(s) }] }),
    Locale: Locale,
    getCanonicalLocales: list,
    supportedValuesOf: () => [],
  };

  // --- timezone-coherent Date ------------------------------------------
  // V8's native Date reflects the *process* timezone (usually UTC), which
  // contradicts the profile timezone we report through Intl — a classic
  // cross-check tell (`getTimezoneOffset()` vs `resolvedOptions().timeZone`).
  // Derive every timezone-dependent value from the profile offset instead, so
  // Date and Intl always agree. DST is handled by rule (US/EU) so the offset is
  // right in both seasons.
  const TZ_OFFSET_STD = __TZ_OFFSET__, TZ_DST = __TZ_DST__;
  const TZ_NAME_STD = __TZ_NAME_STD__, TZ_NAME_DST = __TZ_NAME_DST__;
  // UTC ms of the Nth (1-based; -1 = last) `weekday` (0=Sun) in `month` (0-based).
  const nthWeekday = (year, month, weekday, n) => {
    if (n === -1) {
      const last = new Date(Date.UTC(year, month + 1, 0));
      return last.getTime() - ((last.getUTCDay() - weekday + 7) % 7) * 86400000;
    }
    const first = new Date(Date.UTC(year, month, 1));
    const offset = (weekday - first.getUTCDay() + 7) % 7;
    return first.getTime() + (offset + (n - 1) * 7) * 86400000;
  };
  // getTimezoneOffset() convention: minutes to add to local to reach UTC
  // (positive = behind UTC). DST subtracts 60. Boundaries are compared in the
  // zone's own standard time (STD offset applied), which is exact to the hour.
  const tzOffset = (utcMs) => {
    if (TZ_DST === 'none') return TZ_OFFSET_STD;
    const y = new Date(utcMs).getUTCFullYear();
    let start, end;
    if (TZ_DST === 'us') {
      start = nthWeekday(y, 2, 0, 2) + (2 * 60 + TZ_OFFSET_STD) * 60000; // 2nd Sun Mar 02:00 local
      end = nthWeekday(y, 10, 0, 1) + (2 * 60 + TZ_OFFSET_STD - 60) * 60000; // 1st Sun Nov 02:00 DST-local
    } else { // 'eu': transitions at 01:00 UTC
      start = nthWeekday(y, 2, 0, -1) + 60 * 60000;
      end = nthWeekday(y, 9, 0, -1) + 60 * 60000;
    }
    const inDst = utcMs >= start && utcMs < end;
    return inDst ? TZ_OFFSET_STD - 60 : TZ_OFFSET_STD;
  };

  const DP = Date.prototype, RAW = {};
  for (const m of ['getTime','getUTCFullYear','getUTCMonth','getUTCDate','getUTCDay','getUTCHours','getUTCMinutes','getUTCSeconds','getUTCMilliseconds']) RAW[m] = DP[m];
  // A Date shifted so that its UTC fields read as the profile-local wall clock.
  const localParts = function (self) { return new Date(RAW.getTime.call(self) - tzOffset(RAW.getTime.call(self)) * 60000); };
  const patch = (name, fn) => { try { Object.defineProperty(DP, name, { value: fn, configurable: true, writable: true }); } catch (e) {} };

  patch('getTimezoneOffset', function getTimezoneOffset() { return tzOffset(RAW.getTime.call(this)); });
  for (const [loc, utc] of [['getFullYear','getUTCFullYear'],['getMonth','getUTCMonth'],['getDate','getUTCDate'],['getDay','getUTCDay'],['getHours','getUTCHours'],['getMinutes','getUTCMinutes'],['getSeconds','getUTCSeconds'],['getMilliseconds','getUTCMilliseconds']]) {
    patch(loc, function () { return RAW[utc].call(localParts(this)); });
  }
  const WD = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'], MO = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const p2 = (n) => (n < 10 ? '0' + n : '' + n);
  const gmtStr = function (self) {
    const off = tzOffset(RAW.getTime.call(self)), sign = off > 0 ? '-' : '+', a = Math.abs(off);
    return 'GMT' + sign + p2((a / 60) | 0) + p2(a % 60);
  };
  const dateStr = function (self) { const l = localParts(self); return WD[RAW.getUTCDay.call(l)] + ' ' + MO[RAW.getUTCMonth.call(l)] + ' ' + p2(RAW.getUTCDate.call(l)) + ' ' + RAW.getUTCFullYear.call(l); };
  const timeStr = function (self) { const l = localParts(self); const off = tzOffset(RAW.getTime.call(self)); const name = (TZ_DST !== 'none' && off === TZ_OFFSET_STD - 60) ? TZ_NAME_DST : TZ_NAME_STD; return p2(RAW.getUTCHours.call(l)) + ':' + p2(RAW.getUTCMinutes.call(l)) + ':' + p2(RAW.getUTCSeconds.call(l)) + ' ' + gmtStr(self) + ' (' + name + ')'; };
  patch('toDateString', function toDateString() { return dateStr(this); });
  patch('toTimeString', function toTimeString() { return timeStr(this); });
  patch('toString', function toString() { return isNaN(RAW.getTime.call(this)) ? 'Invalid Date' : dateStr(this) + ' ' + timeStr(this); });
  patch('toLocaleString', function toLocaleString() { return this.toString(); });
  patch('toLocaleDateString', function toLocaleDateString() { return this.toDateString(); });
  patch('toLocaleTimeString', function toLocaleTimeString() { return this.toTimeString(); });

  String.prototype.localeCompare = function (other) { const a = String(this), b = String(other); return a < b ? -1 : a > b ? 1 : 0; };
  Number.prototype.toLocaleString = function () { return String(this); };
})();"#;

/// The JS-fingerprint hardening layer (Phase 6). Must run *after* the DOM
/// runtime (it patches `HTMLElement.prototype` and `navigator`), so `core`
/// appends it last, not part of [`bootstrap_script`]. Provides deterministic,
/// Chrome-coherent canvas / WebGL / audio fingerprints (this engine has no real
/// rendering), realistic `navigator.plugins`/`mimeTypes`, a `permissions` shim,
/// and masks patched functions so `fn.toString()` still reads `[native code]`.
pub fn fingerprint_script(profile: &StealthProfile) -> String {
    FINGERPRINT_TEMPLATE
        .replace("__WEBGL_VENDOR__", &quoted(&profile.webgl_vendor))
        .replace("__WEBGL_RENDERER__", &quoted(&profile.webgl_renderer))
}

/// Timer / event-loop APIs. A bare V8 isolate has no `setTimeout` — this defines
/// `setTimeout`/`setInterval`/`clearTimeout`/`clearInterval`/`queueMicrotask`/
/// `requestAnimationFrame`, backed by a due-time queue the Rust driver pulls
/// from: `__pt_runNextTimer` runs the earliest timer *that is due*, and
/// `__pt_nextTimerDelay` says how long until the next one is, so the driver can
/// wait exactly that long instead of guessing.
///
/// Delays are real. They used to collapse — a virtual clock jumped straight to
/// each due time, so `setTimeout(fn, 4000)` returned instantly and a worker was
/// never blocked. That is indefensible against anything that *times* the page:
/// `Date.now()` kept running at wall speed, so a 500 ms timer measured 0 ms, and
/// Cloudflare's watchdog (a 900 ms interval that gives a widget 46 ticks to
/// answer) burned its whole patience in a millisecond and declared the widget
/// hung, forever. `NOKK_FAST_TIMERS` brings the old behaviour back for bulk
/// scraping, where nothing is watching the clock.
const TIMERS_TEMPLATE: &str = r#"(() => {
  const FAST = __FAST_TIMERS__;
  let seq = 1;
  let virt = 0; // fast mode only: the clock that jumps to each due time
  const q = new Map(); // id -> {fn, delay, interval, due, cancelled, id, depth}
  const clock = () => (FAST ? virt : Date.now());

  // Chrome clamps a timer nested deeper than five levels to 4 ms. Without the
  // clamp a `setTimeout(f, 0)` chain spins the driver at CPU speed — which is
  // both a tell and a way to starve every other context on the worker.
  let depth = 0;

  const add = (fn, delay, interval, args) => {
    if (typeof fn !== 'function') return 0;
    let d = Number(delay);
    if (!(d > 0)) d = 0; // negative, NaN and undefined all mean "as soon as possible"
    if (depth > 5 && d < 4) d = 4;
    const id = seq++;
    q.set(id, { fn: () => fn.apply(globalThis, args), delay: d, interval,
                due: clock() + d, cancelled: false, id, depth: depth + 1 });
    return id;
  };
  globalThis.setTimeout = (fn, delay, ...args) => add(fn, delay, false, args);
  globalThis.setInterval = (fn, delay, ...args) => add(fn, delay, true, args);
  globalThis.clearTimeout = (id) => { const t = q.get(id); if (t) t.cancelled = true; q.delete(id); };
  globalThis.clearInterval = globalThis.clearTimeout;
  globalThis.queueMicrotask = (fn) => { Promise.resolve().then(fn); };
  globalThis.requestAnimationFrame = (fn) =>
    add(() => fn(globalThis.performance ? globalThis.performance.now() : clock()), 16, false, []);
  globalThis.cancelAnimationFrame = globalThis.clearTimeout;
  // No browser has `setImmediate`/`clearImmediate` — they are Node's, and we were
  // the ones putting them on the page. An extra global is as much a tell as a
  // missing one, and this pair is a well-known signature.

  // `performance` is defined by PERFORMANCE_TEMPLATE (wall-clock coherent); a
  // frame callback receives the same high-res timestamp a real browser passes.

  const earliest = () => {
    let best = null;
    for (const t of q.values()) {
      if (t.cancelled) continue;
      if (!best || t.due < best.due || (t.due === best.due && t.id < best.id)) best = t;
    }
    return best;
  };

  // Run the single earliest *due* timer. Returns 1 if one ran, 0 if the queue is
  // empty or nothing is due yet — either way the driver stops pumping and asks
  // `__pt_nextTimerDelay` what to do next. Microtasks scheduled by the callback
  // drain automatically when this returns to Rust.
  globalThis.__pt_runNextTimer = () => {
    const best = earliest();
    if (!best) return 0;
    const now = clock();
    if (best.due > now) {
      if (!FAST) return 0;
      virt = best.due; // fast mode: skip the wait rather than serve it
    }
    // An interval that fell behind (a long callback, a busy worker) schedules
    // its next tick from now, so it never fires a burst to catch up.
    if (best.interval) best.due = Math.max(clock(), best.due) + best.delay;
    else q.delete(best.id);
    const outer = depth;
    depth = best.depth;
    try { best.fn(); } catch (e) { /* timer callback threw */ }
    finally { depth = outer; }
    return 1;
  };

  // Milliseconds until the earliest pending timer: 0 = due now, -1 = nothing
  // pending. This is what lets the driver sleep for exactly as long as the page
  // asked for instead of polling.
  globalThis.__pt_nextTimerDelay = () => {
    const best = earliest();
    return best ? Math.max(0, best.due - clock()) : -1;
  };
  globalThis.__pt_pendingTimers = () => q.size;
})();"#;

/// The rest of the platform surface, by name.
///
/// Turnstile's VM fingerprints by walking `Object.keys` up every prototype chain
/// of `window`, `document`, `navigator`, `screen`, `location` and classifying each
/// value. Chrome presents 1634 properties there; we presented 380, and a graph a
/// quarter the size of a browser's is not a browser. This fills the rest in, with
/// the *category* each name has in Chrome — a native-looking function where Chrome
/// has one, `null` where Chrome has `null`, the same numbers — taken from a real
/// Chrome 148 measured with the collector recovered from the VM itself.
///
/// Nothing here overwrites an implemented property: the table is only consulted
/// for names we do not already have, so a real `document.body` stays real and only
/// the absent names are filled. These are stubs — they answer "does it exist and
/// what kind of thing is it", which is the question being asked. Behaviour behind
/// the ones that matter is implemented elsewhere, and each one that graduates from
/// this list to a real implementation simply stops being consulted.
/// The platform surface fill-in — see [`WEB_SURFACE_TEMPLATE`]. Runs last in the
/// bootstrap, after the DOM runtime and the fingerprint layer, so it only ever
/// adds what nothing else defined.
/// Diagnostic mode, off unless `NOKK_TRACE_PROBES=1`: record every read of the
/// fingerprint surface and what we answered with. Anti-bot code decides on the
/// *values* it collects, and until now we could only guess which ones it looked
/// at — this makes the interrogation itself readable, and a difference from a
/// real browser findable rather than theorised.
///
/// Never on by default: it wraps accessors, which is a change to the surface it
/// is measuring.
pub fn probe_tracer_script() -> String {
    r##"(() => {
  const log = new Map();
  const show = (v) => {
    try {
      if (typeof v === 'function') return 'fn ' + (v.name || '');
      if (v === null) return 'null';
      if (typeof v === 'object') {
        const tag = Object.prototype.toString.call(v);
        if (Array.isArray(v)) return 'array(' + v.length + ')';
        return tag;
      }
      const s = String(v);
      return s.length > 90 ? s.slice(0, 90) + '…' : s;
    } catch (e) { return '<threw>'; }
  };
  const note = (name, v) => {
    const e = log.get(name) || { n: 0, last: '' };
    e.n++; e.last = show(v);
    log.set(name, e);
    return v;
  };
  globalThis.__pt_probeLog = () => JSON.stringify([...log]
    .sort((a, b) => b[1].n - a[1].n)
    .map(([k, v]) => [k, v.n, v.last]));

  const native = globalThis.__pt_native || ((f) => f);
  const rename = (f, name) => {
    try { Object.defineProperty(f, 'name', { value: name, configurable: true }); } catch (e) {}
    return native(f);
  };

  // Конструктор оборачивать нельзя: обёртка теряет и статические методы, и
  // прототип, а `Object` в обёртке ломает вообще всё. Трогаем методы и геттеры.
  // Признак конструктора — заглавная буква в имени: `Proxy` и `Symbol` прототипа
  // в обычном смысле не имеют, а обёртку над ними страница не переживёт.
  const isConstructor = (v) => typeof v === 'function'
    && (/^[A-Z]/.test(v.name || '') || !!v.prototype);

  const trace = (obj, prefix) => {
    if (!obj) return;
    for (const key of Object.getOwnPropertyNames(obj)) {
      if (key === 'constructor' || key.lastIndexOf('__pt', 0) === 0) continue;
      if (key === 'eval' || key === 'Function' || key === 'Object' || key === 'Reflect') continue;
      let d;
      try { d = Object.getOwnPropertyDescriptor(obj, key); } catch (e) { continue; }
      if (!d || !d.configurable) continue;
      if (d.get) {
        const get = d.get;
        try {
          Object.defineProperty(obj, key, Object.assign({}, d, {
            get: rename(function () { return note(prefix + key, get.call(this)); }, 'get ' + key),
          }));
        } catch (e) {}
      } else if (typeof d.value === 'function' && !isConstructor(d.value)) {
        const fn = d.value;
        try {
          Object.defineProperty(obj, key, Object.assign({}, d, {
            value: rename(function (...args) {
              const out = fn.apply(this, args);
              return note(prefix + key + '(' + args.map(show).join(',').slice(0, 40) + ')', out);
            }, key),
          }));
        } catch (e) {}
      }
    }
  };

  // Перечисление — главный инструмент сборщика отпечатков: он идёт по
  // `Object.keys` вверх по цепочке прототипов и по именам решает, что перед ним.
  // Записываем, что именно перечисляли и сколько имён отдали.
  const nameOf = (o) => {
    try {
      if (o === globalThis) return 'window';
      if (o === null || o === undefined) return String(o);
      const tag = Object.prototype.toString.call(o).slice(8, -1);
      if (tag !== 'Object') return tag;
      const c = o.constructor && o.constructor.name;
      return c && c !== 'Object' ? c + '.prototype?' : 'Object';
    } catch (e) { return '?'; }
  };
  for (const [holder, key] of [[Object, 'keys'], [Object, 'getOwnPropertyNames'],
    [Object, 'getOwnPropertyDescriptors'], [Object, 'entries'], [Object, 'values'],
    [Object, 'getPrototypeOf'], [Reflect, 'ownKeys'], [Reflect, 'getPrototypeOf']]) {
    const orig = holder[key];
    if (typeof orig !== 'function') continue;
    try {
      Object.defineProperty(holder, key, {
        value: rename(function (target, ...rest) {
          const out = orig.call(this, target, ...rest);
          note('walk:' + key + '(' + nameOf(target) + ')', Array.isArray(out) ? out.length + ' имён' : out);
          return out;
        }, key),
        writable: true, configurable: true,
      });
    } catch (e) {}
  }

  // Код, который страница сочиняет на ходу, и потоки, в которых она прячет
  // сборку: и то и другое стоит видеть по имени.
  const origFunction = globalThis.Function;
  for (const name of ['Worker', 'SharedWorker', 'ServiceWorker']) {
    const C = globalThis[name];
    if (typeof C !== 'function') continue;
    try {
      globalThis[name] = new Proxy(C, {
        construct(t, args) { note('new ' + name + '(' + show(args[0]) + ')', 'создан'); return Reflect.construct(t, args); },
      });
    } catch (e) {}
  }
  try {
    const createURL = globalThis.URL && URL.createObjectURL;
    if (createURL) URL.createObjectURL = rename(function (o) {
      const url = createURL.call(this, o);
      note('URL.createObjectURL(' + nameOf(o) + ')', url);
      return url;
    }, 'createObjectURL');
  } catch (e) {}
  try {
    globalThis.Function = new Proxy(origFunction, {
      construct(t, args) {
        note('new Function(' + String(args[args.length - 1] || '').slice(0, 50) + ')', 'скомпилировано');
        return Reflect.construct(t, args);
      },
      apply(t, self, args) {
        note('Function(' + String(args[args.length - 1] || '').slice(0, 50) + ')', 'скомпилировано');
        return Reflect.apply(t, self, args);
      },
    });
  } catch (e) {}

  // Данные-свойства корней: обёртка геттеров их не видит, а сборщик читает.
  const traceData = (obj, prefix) => {
    if (!obj) return;
    for (const key of Object.getOwnPropertyNames(obj)) {
      if (key.lastIndexOf('__pt', 0) === 0) continue;
      let d;
      try { d = Object.getOwnPropertyDescriptor(obj, key); } catch (e) { continue; }
      if (!d || !d.configurable || d.get || typeof d.value === 'function') continue;
      const value = d.value;
      try {
        Object.defineProperty(obj, key, {
          get: rename(function () { return note(prefix + key, value); }, 'get ' + key),
          set: rename(function (v) { Object.defineProperty(obj, key, { value: v, writable: true, configurable: true, enumerable: d.enumerable }); }, 'set ' + key),
          enumerable: d.enumerable, configurable: true,
        });
      } catch (e) {}
    }
  };

  // Каждый корень отпечатка и каждая поверхность, по которой обычно судят:
  // рисование, звук, шрифты, время, устройство.
  const proto = (name) => globalThis[name] && globalThis[name].prototype;
  trace(globalThis, '');
  trace(Object.getPrototypeOf(globalThis) || {}, 'Window.');
  for (const [name, tag] of [
    ['Navigator', 'n.'], ['Screen', 's.'], ['Location', 'l.'], ['History', 'h.'],
    ['Document', 'd.'], ['Element', 'el.'], ['HTMLElement', 'html.'],
    ['HTMLCanvasElement', 'canvas.'], ['CanvasRenderingContext2D', 'ctx2d.'],
    ['WebGLRenderingContext', 'gl.'], ['WebGL2RenderingContext', 'gl2.'],
    ['AudioContext', 'audio.'], ['OfflineAudioContext', 'offlineAudio.'],
    ['AnalyserNode', 'analyser.'], ['Performance', 'perf.'],
    ['CSSStyleDeclaration', 'style.'], ['MediaQueryList', 'mql.'],
    ['Storage', 'storage.'], ['Crypto', 'crypto.'], ['Date', 'date.'],
    ['Intl', 'intl.'], ['RTCPeerConnection', 'rtc.'], ['SpeechSynthesis', 'speech.'],
  ]) {
    trace(proto(name), tag);
  }
  for (const [name, tag] of [['navigator', 'n.'], ['screen', 's.'], ['performance', 'perf.']]) {
    if (globalThis[name]) { trace(globalThis[name], tag + 'own.'); traceData(globalThis[name], tag); }
  }
  traceData(globalThis, 'win.');
})();"##
        .to_string()
}

/// Turn a freshly created context into a worker's global scope. A worker is not
/// a window with things missing — it is a different global object, and code that
/// collects a fingerprint inside one knows exactly what belongs there. Running it
/// in the page's realm, however carefully shimmed, gets the realm wrong; this
/// runs in a context of its own, and only reshapes what that context exposes.
/// Имена воркерной области, снятые с Chrome 148 (см. `worker_scope_script`).
const WORKER_OWN: &str = r#"["AbortController", "AbortSignal", "AggregateError", "Array", "ArrayBuffer", "AsyncDisposableStack", "Atomics", "AudioData", "AudioDecoder", "AudioEncoder", "BackgroundFetchManager", "BackgroundFetchRecord", "BackgroundFetchRegistration", "BigInt", "BigInt64Array", "BigUint64Array", "Blob", "Boolean", "BroadcastChannel", "ByteLengthQueuingStrategy", "CSSSkewX", "CSSSkewY", "Cache", "CacheStorage", "CanvasGradient", "CanvasPattern", "CloseEvent", "CompressionStream", "CountQueuingStrategy", "CreateMonitor", "CropTarget", "Crypto", "CryptoKey", "CustomEvent", "DOMException", "DOMMatrix", "DOMMatrixReadOnly", "DOMPoint", "DOMPointReadOnly", "DOMQuad", "DOMRect", "DOMRectReadOnly", "DOMStringList", "DataView", "Date", "DecompressionStream", "DedicatedWorkerGlobalScope", "DisposableStack", "EncodedAudioChunk", "EncodedVideoChunk", "Error", "ErrorEvent", "EvalError", "Event", "EventSource", "EventTarget", "File", "FileList", "FileReader", "FileReaderSync", "FileSystemDirectoryHandle", "FileSystemFileHandle", "FileSystemHandle", "FileSystemObserver", "FileSystemSyncAccessHandle", "FileSystemWritableFileStream", "FinalizationRegistry", "Float16Array", "Float32Array", "Float64Array", "FontFace", "FormData", "Function", "GPU", "GPUAdapter", "GPUAdapterInfo", "GPUBindGroup", "GPUBindGroupLayout", "GPUBuffer", "GPUBufferUsage", "GPUCanvasContext", "GPUColorWrite", "GPUCommandBuffer", "GPUCommandEncoder", "GPUCompilationInfo", "GPUCompilationMessage", "GPUComputePassEncoder", "GPUComputePipeline", "GPUDevice", "GPUDeviceLostInfo", "GPUError", "GPUExternalTexture", "GPUInternalError", "GPUMapMode", "GPUOutOfMemoryError", "GPUPipelineError", "GPUPipelineLayout", "GPUQuerySet", "GPUQueue", "GPURenderBundle", "GPURenderBundleEncoder", "GPURenderPassEncoder", "GPURenderPipeline", "GPUSampler", "GPUShaderModule", "GPUShaderStage", "GPUSupportedFeatures", "GPUSupportedLimits", "GPUTexture", "GPUTextureUsage", "GPUTextureView", "GPUUncapturedErrorEvent", "GPUValidationError", "HID", "HIDConnectionEvent", "HIDDevice", "HIDInputReportEvent", "Headers", "IDBCursor", "IDBCursorWithValue", "IDBDatabase", "IDBFactory", "IDBIndex", "IDBKeyRange", "IDBObjectStore", "IDBOpenDBRequest", "IDBRecord", "IDBRequest", "IDBTransaction", "IDBVersionChangeEvent", "IdleDetector", "ImageBitmap", "ImageBitmapRenderingContext", "ImageData", "ImageDecoder", "ImageTrack", "ImageTrackList", "Infinity", "Int16Array", "Int32Array", "Int8Array", "Intl", "Iterator", "JSON", "Lock", "LockManager", "Map", "Math", "MediaCapabilities", "MediaSource", "MediaSourceHandle", "MessageChannel", "MessageEvent", "MessagePort", "NaN", "NavigationPreloadManager", "NavigatorUAData", "NetworkInformation", "Notification", "Number", "Object", "Observable", "OffscreenCanvas", "OffscreenCanvasRenderingContext2D", "Origin", "Path2D", "Performance", "PerformanceEntry", "PerformanceMark", "PerformanceMeasure", "PerformanceObserver", "PerformanceObserverEntryList", "PerformanceResourceTiming", "PerformanceServerTiming", "PeriodicSyncManager", "PermissionStatus", "Permissions", "PressureObserver", "PressureRecord", "ProgressEvent", "Promise", "PromiseRejectionEvent", "Proxy", "PushManager", "PushSubscription", "PushSubscriptionOptions", "QuotaExceededError", "RTCDataChannel", "RTCEncodedAudioFrame", "RTCEncodedVideoFrame", "RTCRtpScriptTransformer", "RTCTransformEvent", "RangeError", "ReadableByteStreamController", "ReadableStream", "ReadableStreamBYOBReader", "ReadableStreamBYOBRequest", "ReadableStreamDefaultController", "ReadableStreamDefaultReader", "ReferenceError", "Reflect", "RegExp", "ReportBody", "ReportingObserver", "Request", "Response", "RestrictionTarget", "Scheduler", "SecurityPolicyViolationEvent", "Serial", "SerialPort", "ServiceWorkerRegistration", "Set", "SourceBuffer", "SourceBufferList", "StorageBucket", "StorageBucketManager", "StorageManager", "String", "Subscriber", "SubtleCrypto", "SuppressedError", "Symbol", "SyncManager", "SyntaxError", "TaskController", "TaskPriorityChangeEvent", "TaskSignal", "Temporal", "TextDecoder", "TextDecoderStream", "TextEncoder", "TextEncoderStream", "TextMetrics", "TransformStream", "TransformStreamDefaultController", "TrustedHTML", "TrustedScript", "TrustedScriptURL", "TrustedTypePolicy", "TrustedTypePolicyFactory", "TypeError", "URIError", "URL", "URLPattern", "URLSearchParams", "USB", "USBAlternateInterface", "USBConfiguration", "USBConnectionEvent", "USBDevice", "USBEndpoint", "USBInTransferResult", "USBInterface", "USBIsochronousInTransferPacket", "USBIsochronousInTransferResult", "USBIsochronousOutTransferPacket", "USBIsochronousOutTransferResult", "USBOutTransferResult", "Uint16Array", "Uint32Array", "Uint8Array", "Uint8ClampedArray", "UserActivation", "VideoColorSpace", "VideoDecoder", "VideoEncoder", "VideoFrame", "WGSLLanguageFeatures", "WeakMap", "WeakRef", "WeakSet", "WebAssembly", "WebGL2RenderingContext", "WebGLActiveInfo", "WebGLBuffer", "WebGLContextEvent", "WebGLFramebuffer", "WebGLObject", "WebGLProgram", "WebGLQuery", "WebGLRenderbuffer", "WebGLRenderingContext", "WebGLSampler", "WebGLShader", "WebGLShaderPrecisionFormat", "WebGLSync", "WebGLTexture", "WebGLTransformFeedback", "WebGLUniformLocation", "WebGLVertexArrayObject", "WebSocket", "WebSocketError", "WebSocketStream", "WebTransport", "WebTransportBidirectionalStream", "WebTransportDatagramDuplexStream", "WebTransportError", "Worker", "WorkerGlobalScope", "WorkerLocation", "WorkerNavigator", "WritableStream", "WritableStreamDefaultController", "WritableStreamDefaultWriter", "XMLHttpRequest", "XMLHttpRequestEventTarget", "XMLHttpRequestUpload", "cancelAnimationFrame", "close", "console", "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent", "escape", "eval", "globalThis", "isFinite", "isNaN", "name", "onmessage", "onmessageerror", "onrtctransform", "parseFloat", "parseInt", "postMessage", "requestAnimationFrame", "undefined", "unescape", "webkitRequestFileSystem", "webkitRequestFileSystemSync", "webkitResolveLocalFileSystemSyncURL", "webkitResolveLocalFileSystemURL"]"#;
const WORKER_ENUMERABLE: &str = r#"["cancelAnimationFrame", "close", "name", "onmessage", "onmessageerror", "onrtctransform", "postMessage", "requestAnimationFrame", "webkitRequestFileSystem", "webkitRequestFileSystemSync", "webkitResolveLocalFileSystemSyncURL", "webkitResolveLocalFileSystemURL"]"#;
const WORKER_NAVIGATOR: &str = r#"["appCodeName", "appName", "appVersion", "connection", "deviceMemory", "gpu", "hardwareConcurrency", "hid", "language", "languages", "locks", "mediaCapabilities", "onLine", "permissions", "platform", "product", "serial", "storage", "storageBuckets", "usb", "userAgent", "userAgentData"]"#;

/// Имена воркерной области, снятые с Chrome 148 (см. `worker_scope_script`).
const WORKER_SCOPE: &str = r#"["atob", "btoa", "caches", "clearInterval", "clearTimeout", "createImageBitmap", "crossOriginIsolated", "crypto", "fetch", "fonts", "importScripts", "indexedDB", "isSecureContext", "location", "navigator", "onerror", "onlanguagechange", "onrejectionhandled", "onunhandledrejection", "origin", "performance", "queueMicrotask", "reportError", "scheduler", "self", "setInterval", "setTimeout", "structuredClone", "trustedTypes"]"#;
const WORKER_SCOPE_ENUMERABLE: &str = r#"["atob", "btoa", "caches", "clearInterval", "clearTimeout", "createImageBitmap", "crossOriginIsolated", "crypto", "fetch", "fonts", "importScripts", "indexedDB", "isSecureContext", "location", "navigator", "onerror", "onlanguagechange", "onrejectionhandled", "onunhandledrejection", "origin", "performance", "queueMicrotask", "reportError", "scheduler", "self", "setInterval", "setTimeout", "structuredClone", "trustedTypes"]"#;

pub fn worker_scope_script(name: &str, url: &str) -> String {
    format!(
        r##"(() => {{
  const NAME = {name};
  const URL_ = {url};
  // Форма снята с настоящего воркера Chrome 148, уровень за уровнем: у самой
  // области 334 собственных имени (12 перечислимых), у WorkerGlobalScope — 30,
  // у DedicatedWorkerGlobalScope — TEMPORARY и PERSISTENT. Оконный контекст
  // отдаёт больше тысячи имён на первом же уровне, и перечисление `self` —
  // первое, что делает сборщик отпечатков внутри воркера.
  const OWN = new Set(__WORKER_OWN__);
  const OWN_ENUM = new Set(__WORKER_ENUM__);
  const SCOPE = __WORKER_SCOPE__;
  const SCOPE_ENUM = new Set(__WORKER_SCOPE_ENUM__);
  const NAV_KEYS = __WORKER_NAV__;

  // 1. Уровень WorkerGlobalScope: то, что в браузере лежит на прототипе, туда и
  //    переезжает вместе со своей реализацией.
  const EventTargetProto = (globalThis.EventTarget && EventTarget.prototype) || Object.prototype;
  const wgsProto = Object.create(EventTargetProto);
  for (const k of SCOPE) {{
    let d;
    try {{ d = Object.getOwnPropertyDescriptor(globalThis, k); }} catch (e) {{ continue; }}
    if (d) {{
      try {{ Object.defineProperty(wgsProto, k, Object.assign({{}}, d, {{ enumerable: SCOPE_ENUM.has(k) }})); }} catch (e) {{}}
      try {{ delete globalThis[k]; }} catch (e) {{}}
    }}
  }}

  // 2. Всё, чего в воркере нет вовсе — прочь. Интерфейсы DOM в том числе.
  for (const k of Object.getOwnPropertyNames(globalThis)) {{
    if (OWN.has(k) || k.lastIndexOf('__pt', 0) === 0 || k === '__out') continue;
    try {{ delete globalThis[k]; }} catch (e) {{}}
  }}
  for (const k of Object.getOwnPropertyNames(globalThis)) {{
    if (k.lastIndexOf('__pt', 0) === 0 || k === '__out') continue;
    try {{
      const d = Object.getOwnPropertyDescriptor(globalThis, k);
      if (d && d.configurable && !!d.enumerable !== OWN_ENUM.has(k)) {{
        Object.defineProperty(globalThis, k, Object.assign({{}}, d, {{ enumerable: OWN_ENUM.has(k) }}));
      }}
    }} catch (e) {{}}
  }}

  // 3. WorkerNavigator: то же устройство, обрезанный интерфейс.
  // Оконный navigator уже переехал на прототип на шаге 1 — значения берём оттуда.
  let win = null;
  try {{ win = wgsProto.navigator; }} catch (e) {{}}
  const navProto = {{}};
  for (const k of NAV_KEYS) {{
    let value;
    try {{ value = win && win[k]; }} catch (e) {{ continue; }}
    if (value === undefined) continue;
    Object.defineProperty(navProto, k, {{ get: () => value, enumerable: true, configurable: true }});
  }}
  try {{ Object.defineProperty(navProto, Symbol.toStringTag, {{ value: 'WorkerNavigator', configurable: true }}); }} catch (e) {{}}
  const WorkerNavigator = function WorkerNavigator() {{ throw new TypeError('Illegal constructor'); }};
  WorkerNavigator.prototype = navProto;
  Object.defineProperty(navProto, 'constructor', {{ value: WorkerNavigator, writable: true, configurable: true }});
  globalThis.WorkerNavigator = WorkerNavigator;
  const workerNavigator = Object.create(navProto);
  Object.defineProperty(wgsProto, 'navigator', {{ get: () => workerNavigator, enumerable: true, configurable: true }});

  // 4. WorkerLocation — адрес самого скрипта. У воркера из блоба схема
  //    непрозрачная: `href` — это `blob:<внутренний адрес>` целиком, `pathname`
  //    — весь остаток, хоста и порта нет вовсе, а `origin` берётся у страницы,
  //    которая блоб создала. Разбирать такой адрес как обычный `http:` — значит
  //    выдать `blob://http://…`, чего браузер не печатал никогда.
  const locProto = {{}};
  const opaque = URL_.lastIndexOf('blob:', 0) === 0 || URL_.lastIndexOf('data:', 0) === 0;
  let parts = null;
  if (opaque) {{
    const rest = URL_.slice(URL_.indexOf(':') + 1);
    let inner = '';
    try {{ inner = URL_.lastIndexOf('blob:', 0) === 0 ? new URL(rest).origin : 'null'; }} catch (e) {{ inner = 'null'; }}
    parts = {{
      href: URL_, origin: inner, protocol: URL_.slice(0, URL_.indexOf(':') + 1),
      host: '', hostname: '', port: '', pathname: rest, search: '', hash: '',
    }};
  }} else {{
    try {{ parts = new URL(URL_); }} catch (e) {{}}
  }}
  for (const k of ['href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash']) {{
    const v = parts ? String(parts[k] || '') : (k === 'href' ? URL_ : '');
    Object.defineProperty(locProto, k, {{ get: () => v, enumerable: true, configurable: true }});
  }}
  Object.defineProperty(locProto, 'toString', {{ value: function toString() {{ return this.href; }}, writable: true, configurable: true }});
  try {{ Object.defineProperty(locProto, Symbol.toStringTag, {{ value: 'WorkerLocation', configurable: true }}); }} catch (e) {{}}
  const WorkerLocation = function WorkerLocation() {{ throw new TypeError('Illegal constructor'); }};
  WorkerLocation.prototype = locProto;
  Object.defineProperty(locProto, 'constructor', {{ value: WorkerLocation, writable: true, configurable: true }});
  globalThis.WorkerLocation = WorkerLocation;
  const workerLocation = Object.create(locProto);
  Object.defineProperty(wgsProto, 'location', {{ get: () => workerLocation, enumerable: true, configurable: true }});

  // 5. Сама цепочка: globalThis → DedicatedWorkerGlobalScope → WorkerGlobalScope
  //    → EventTarget → Object, как в браузере.
  const WorkerGlobalScope = function WorkerGlobalScope() {{ throw new TypeError('Illegal constructor'); }};
  WorkerGlobalScope.prototype = wgsProto;
  Object.defineProperty(wgsProto, 'constructor', {{ value: WorkerGlobalScope, writable: true, configurable: true }});
  try {{ Object.defineProperty(wgsProto, Symbol.toStringTag, {{ value: 'WorkerGlobalScope', configurable: true }}); }} catch (e) {{}}
  Object.defineProperty(wgsProto, 'self', {{ get: () => globalThis, enumerable: true, configurable: true }});

  const dwgsProto = Object.create(wgsProto);
  const DedicatedWorkerGlobalScope = function DedicatedWorkerGlobalScope() {{ throw new TypeError('Illegal constructor'); }};
  DedicatedWorkerGlobalScope.prototype = dwgsProto;
  Object.defineProperty(dwgsProto, 'constructor', {{ value: DedicatedWorkerGlobalScope, writable: true, configurable: true }});
  Object.defineProperty(dwgsProto, 'TEMPORARY', {{ value: 0, enumerable: true, configurable: true }});
  Object.defineProperty(dwgsProto, 'PERSISTENT', {{ value: 1, enumerable: true, configurable: true }});
  try {{ Object.defineProperty(dwgsProto, Symbol.toStringTag, {{ value: 'DedicatedWorkerGlobalScope', configurable: true }}); }} catch (e) {{}}
  globalThis.WorkerGlobalScope = WorkerGlobalScope;
  globalThis.DedicatedWorkerGlobalScope = DedicatedWorkerGlobalScope;
  try {{ Object.setPrototypeOf(globalThis, dwgsProto); }} catch (e) {{}}
  // Окно называло себя окном — здесь это имя принадлежит прототипу области.
  try {{ delete globalThis[Symbol.toStringTag]; }} catch (e) {{}}

  // 6. Чего у нас не было вовсе — доставляем заглушками той же категории, что и
  //    в браузере: воркерные синхронные API и трансформы RTC.
  for (const [k, kind] of [['FileReaderSync', 'N'], ['FileSystemSyncAccessHandle', 'N'],
    ['RTCRtpScriptTransformer', 'N'], ['RTCTransformEvent', 'N'],
    ['webkitRequestFileSystemSync', 'N'], ['webkitResolveLocalFileSystemSyncURL', 'N'],
    ['onrtctransform', 'x']]) {{
    if (k in globalThis) continue;
    const value = kind === 'N' ? (() => {{
      const f = function () {{ throw new TypeError('Illegal constructor'); }};
      try {{ Object.defineProperty(f, 'name', {{ value: k, configurable: true }}); }} catch (e) {{}}
      return globalThis.__pt_native ? __pt_native(f) : f;
    }})() : null;
    try {{
      Object.defineProperty(globalThis, k, {{
        value, writable: true, configurable: true, enumerable: OWN_ENUM.has(k),
      }});
    }} catch (e) {{}}
  }}
  for (const k of ['importScripts']) {{
    if (k in wgsProto) continue;
    const f = function importScripts() {{}};
    try {{ Object.defineProperty(wgsProto, k, {{ value: globalThis.__pt_native ? __pt_native(f) : f, writable: true, configurable: true, enumerable: true }}); }} catch (e) {{}}
  }}
  if (!('fonts' in wgsProto)) {{
    const fonts = {{ ready: Promise.resolve(), check: () => true, load: () => Promise.resolve([]), size: 0 }};
    try {{ Object.defineProperty(wgsProto, 'fonts', {{ get: () => fonts, enumerable: true, configurable: true }}); }} catch (e) {{}}
  }}
  // Интерфейсы воркерной области перечислимыми не бывают.
  for (const k of ['WorkerGlobalScope', 'DedicatedWorkerGlobalScope', 'WorkerNavigator', 'WorkerLocation']) {{
    try {{
      const d = Object.getOwnPropertyDescriptor(globalThis, k);
      if (d) Object.defineProperty(globalThis, k, Object.assign({{}}, d, {{ enumerable: false }}));
    }} catch (e) {{}}
  }}

  // 7. Порт наружу. Обе стороны порта — родные методы области, и `toString`
  //    у них такой же, как у остальных: воркер, чей `postMessage` показывает
  //    исходник, — не воркер.
  globalThis.name = NAME;
  const native = (f) => (globalThis.__pt_native ? __pt_native(f) : f);
  const outbox = [];
  globalThis.__pt_drainWorkerOut = () => outbox.splice(0);
  globalThis.postMessage = native(function postMessage(data) {{
    try {{ outbox.push(JSON.stringify(data === undefined ? null : data)); }} catch (e) {{ outbox.push('null'); }}
  }});
  globalThis.close = native(function close() {{ globalThis.__ptClosed = true; }});
  globalThis.__pt_workerDeliver = (json) => {{
    let data = null;
    try {{ data = JSON.parse(json); }} catch (e) {{}}
    // У выделенного воркера `origin` пустой, а `source` — null: сообщение
    // пришло по порту, а не от окна.
    let ev;
    try {{ ev = new MessageEvent('message', {{ data, origin: '', lastEventId: '', source: null, ports: [] }}); }} catch (e) {{
      ev = {{ type: 'message', data, origin: '', lastEventId: '', source: null, ports: [] }};
    }}
    try {{ ev.target = globalThis; ev.currentTarget = globalThis; }} catch (e) {{}}
    // Одна доставка, а не две: `dispatchEvent` сам зовёт и слушателей, и
    // `onmessage`. Звать обоих — значит выполнить обработчик дважды, чего в
    // браузере не бывает и что ломает любой счётчик внутри воркера.
    if (typeof globalThis.dispatchEvent === 'function') {{
      try {{ globalThis.dispatchEvent(ev); return; }} catch (e) {{}}
    }}
    try {{ if (typeof globalThis.onmessage === 'function') globalThis.onmessage(ev); }} catch (e) {{}}
  }};
}})();"##,
        name = quoted(name),
        url = quoted(url),
    )
    .replace("__WORKER_OWN__", WORKER_OWN)
    .replace("__WORKER_ENUM__", WORKER_ENUMERABLE)
    .replace("__WORKER_SCOPE_ENUM__", WORKER_SCOPE_ENUMERABLE)
    .replace("__WORKER_SCOPE__", WORKER_SCOPE)
    .replace("__WORKER_NAV__", WORKER_NAVIGATOR)
}

pub fn web_surface_script() -> String {
    WEB_SURFACE_TEMPLATE.to_string()
}

const WEB_SURFACE_TEMPLATE: &str = r##"(() => {
  const T = {"window":{"#0":["TEMPORARY","pageXOffset","pageYOffset","scrollX","scrollY"],"#1":["PERSISTENT"],"#10":["screenLeft","screenTop","screenX","screenY"],"o":["GPUBufferUsage","GPUColorWrite","GPUMapMode","GPUShaderStage","GPUTextureUsage","Temporal","caches","clientInformation","cookieStore","crashReport","customElements","documentPictureInPicture","external","launchQueue","locationbar","menubar","navigation","personalbar","scheduler","scrollbars","sharedStorage","speechSynthesis","statusbar","styleMedia","toolbar","trustedTypes","viewport","visualViewport"],"F":["credentialless","crossOriginIsolated"],"x":["fence","frameElement","onabort","onafterprint","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onappinstalled","onauxclick","onbeforeinput","onbeforeinstallprompt","onbeforematch","onbeforeprint","onbeforetoggle","onbeforeunload","onbeforexrselect","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncuechange","ondblclick","ondevicemotion","ondeviceorientation","ondeviceorientationabsolute","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","ongamepadconnected","ongamepaddisconnected","ongotpointercapture","onhashchange","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onlanguagechange","onload","onloadeddata","onloadedmetadata","onloadstart","onlostpointercapture","onmessage","onmessageerror","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onoffline","ononline","onpagehide","onpagereveal","onpageshow","onpageswap","onpause","onplay","onplaying","onpointercancel","onpointerdown","onpointerenter","onpointerleave","onpointermove","onpointerout","onpointerover","onpointerrawupdate","onpointerup","onpopstate","onprogress","onratechange","onrejectionhandled","onreset","onresize","onscroll","onscrollend","onscrollsnapchange","onscrollsnapchanging","onsearch","onsecuritypolicyviolation","onseeked","onseeking","onselect","onselectionchange","onselectstart","onslotchange","onstalled","onstorage","onsubmit","onsuspend","ontimeupdate","ontoggle","ontransitioncancel","ontransitionend","ontransitionrun","ontransitionstart","onunhandledrejection","onunload","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","opener"],"u":["event"],"T":["isSecureContext","offscreenBuffering","originAgentCluster"],"N":["AbsoluteOrientationSensor","AbstractRange","Accelerometer","AnalyserNode","Animation","AnimationEffect","AnimationEvent","AnimationPlaybackEvent","AnimationTimeline","AnimationTrigger","AsyncDisposableStack","Attr","Audio","AudioBuffer","AudioBufferSourceNode","AudioData","AudioDecoder","AudioDestinationNode","AudioEncoder","AudioListener","AudioNode","AudioParam","AudioParamMap","AudioPlaybackStats","AudioProcessingEvent","AudioScheduledSourceNode","AudioSinkInfo","AudioWorklet","AudioWorkletNode","AuthenticatorAssertionResponse","AuthenticatorAttestationResponse","AuthenticatorResponse","BackgroundFetchManager","BackgroundFetchRecord","BackgroundFetchRegistration","BarProp","BaseAudioContext","BatteryManager","BeforeInstallPromptEvent","BeforeUnloadEvent","BiquadFilterNode","BlobEvent","BrowserCaptureMediaStreamTrack","ByteLengthQueuingStrategy","CDATASection","CSPViolationReportBody","CSSAnimation","CSSConditionRule","CSSContainerRule","CSSCounterStyleRule","CSSFontFaceRule","CSSFontFeatureValuesRule","CSSFontPaletteValuesRule","CSSFunctionDeclarations","CSSFunctionDescriptors","CSSFunctionRule","CSSGroupingRule","CSSImageValue","CSSImportRule","CSSKeyframeRule","CSSKeyframesRule","CSSKeywordValue","CSSLayerBlockRule","CSSLayerStatementRule","CSSMarginRule","CSSMathClamp","CSSMathInvert","CSSMathMax","CSSMathMin","CSSMathNegate","CSSMathProduct","CSSMathSum","CSSMathValue","CSSMatrixComponent","CSSMediaRule","CSSNamespaceRule","CSSNestedDeclarations","CSSNumericArray","CSSNumericValue","CSSPageRule","CSSPerspective","CSSPositionTryDescriptors","CSSPositionTryRule","CSSPositionValue","CSSPropertyRule","CSSRotate","CSSRule","CSSRuleList","CSSScale","CSSScopeRule","CSSSkew","CSSSkewX","CSSSkewY","CSSStartingStyleRule","CSSStyleDeclaration","CSSStyleRule","CSSStyleSheet","CSSStyleValue","CSSSupportsRule","CSSTransformComponent","CSSTransformValue","CSSTransition","CSSTranslate","CSSUnitValue","CSSUnparsedValue","CSSVariableReferenceValue","CSSViewTransitionRule","Cache","CacheStorage","CanvasCaptureMediaStreamTrack","CanvasGradient","CanvasPattern","CaptureController","CaretPosition","ChannelMergerNode","ChannelSplitterNode","ChapterInformation","CharacterBoundsUpdateEvent","CharacterData","Clipboard","ClipboardChangeEvent","ClipboardEvent","ClipboardItem","CloseEvent","CloseWatcher","CommandEvent","CompositionEvent","CompressionStream","ConstantSourceNode","ContentVisibilityAutoStateChangeEvent","ConvolverNode","CookieChangeEvent","CookieStore","CookieStoreManager","CountQueuingStrategy","CrashReportContext","CreateMonitor","Credential","CredentialsContainer","CropTarget","CustomElementRegistry","CustomStateSet","DOMError","DOMImplementation","DOMMatrix","DOMMatrixReadOnly","DOMParser","DOMPoint","DOMPointReadOnly","DOMQuad","DOMRect","DOMRectList","DOMRectReadOnly","DOMStringList","DOMStringMap","DOMTokenList","DataTransfer","DataTransferItem","DataTransferItemList","DecompressionStream","DelayNode","DelegatedInkTrailPresenter","DeviceMotionEvent","DeviceMotionEventAcceleration","DeviceMotionEventRotationRate","DeviceOrientationEvent","DevicePosture","DigitalCredential","DisposableStack","DocumentPictureInPicture","DocumentPictureInPictureEvent","DocumentTimeline","DocumentType","DragEvent","DynamicsCompressorNode","EditContext","ElementInternals","EncodedAudioChunk","EncodedVideoChunk","ErrorEvent","EventCounts","EventSource","External","FeaturePolicy","FederatedCredential","Fence","FencedFrameConfig","FetchLaterResult","FileList","FileSystemDirectoryHandle","FileSystemFileHandle","FileSystemHandle","FileSystemObserver","FileSystemWritableFileStream","Float16Array","FontData","FontFace","FontFaceSetLoadEvent","FormDataEvent","FragmentDirective","GPU","GPUAdapter","GPUAdapterInfo","GPUBindGroup","GPUBindGroupLayout","GPUBuffer","GPUCanvasContext","GPUCommandBuffer","GPUCommandEncoder","GPUCompilationInfo","GPUCompilationMessage","GPUComputePassEncoder","GPUComputePipeline","GPUDevice","GPUDeviceLostInfo","GPUError","GPUExternalTexture","GPUInternalError","GPUOutOfMemoryError","GPUPipelineError","GPUPipelineLayout","GPUQuerySet","GPUQueue","GPURenderBundle","GPURenderBundleEncoder","GPURenderPassEncoder","GPURenderPipeline","GPUSampler","GPUShaderModule","GPUSupportedFeatures","GPUSupportedLimits","GPUTexture","GPUTextureView","GPUUncapturedErrorEvent","GPUValidationError","GainNode","Gamepad","GamepadButton","GamepadEvent","GamepadHapticActuator","Geolocation","GeolocationCoordinates","GeolocationPosition","GeolocationPositionError","GravitySensor","Gyroscope","HID","HIDConnectionEvent","HIDDevice","HIDInputReportEvent","HTMLAllCollection","HTMLBaseElement","HTMLCollection","HTMLDListElement","HTMLDataElement","HTMLDirectoryElement","HTMLDocument","HTMLFencedFrameElement","HTMLFontElement","HTMLFormControlsCollection","HTMLFrameElement","HTMLFrameSetElement","HTMLGeolocationElement","HTMLMarqueeElement","HTMLMenuElement","HTMLOptionsCollection","HTMLParamElement","HTMLSelectedContentElement","HTMLTableCaptionElement","HTMLTableColElement","HTMLTrackElement","HashChangeEvent","Highlight","HighlightRegistry","IDBCursor","IDBCursorWithValue","IDBDatabase","IDBFactory","IDBIndex","IDBKeyRange","IDBObjectStore","IDBOpenDBRequest","IDBRecord","IDBRequest","IDBTransaction","IDBVersionChangeEvent","IIRFilterNode","IdentityCredential","IdentityCredentialError","IdentityProvider","IdleDeadline","IdleDetector","ImageBitmap","ImageBitmapRenderingContext","ImageCapture","ImageData","ImageDecoder","ImageTrack","ImageTrackList","Ink","InputDeviceCapabilities","InputDeviceInfo","IntegrityViolationReportBody","InterestEvent","IntersectionObserverEntry","Keyboard","KeyboardLayoutMap","KeyframeEffect","LanguageDetector","LanguageModel","LargestContentfulPaint","LaunchParams","LaunchQueue","LayoutShift","LayoutShiftAttribution","LinearAccelerationSensor","Lock","LockManager","MIDIAccess","MIDIConnectionEvent","MIDIInput","MIDIInputMap","MIDIMessageEvent","MIDIOutput","MIDIOutputMap","MIDIPort","MathMLElement","MediaCapabilities","MediaDeviceInfo","MediaDevices","MediaElementAudioSourceNode","MediaEncryptedEvent","MediaError","MediaKeyMessageEvent","MediaKeySession","MediaKeyStatusMap","MediaKeySystemAccess","MediaKeys","MediaList","MediaMetadata","MediaQueryList","MediaQueryListEvent","MediaRecorder","MediaSession","MediaSource","MediaSourceHandle","MediaStream","MediaStreamAudioDestinationNode","MediaStreamAudioSourceNode","MediaStreamEvent","MediaStreamTrack","MediaStreamTrackAudioStats","MediaStreamTrackEvent","MediaStreamTrackGenerator","MediaStreamTrackProcessor","MediaStreamTrackVideoStats","MutationRecord","NamedNodeMap","NavigateEvent","Navigation","NavigationActivation","NavigationCurrentEntryChangeEvent","NavigationDestination","NavigationHistoryEntry","NavigationPrecommitController","NavigationPreloadManager","NavigationTransition","NavigatorLogin","NavigatorManagedData","NavigatorUAData","NetworkInformation","NodeList","NotRestoredReasonDetails","NotRestoredReasons","Notification","OTPCredential","Observable","OfflineAudioCompletionEvent","OffscreenCanvasRenderingContext2D","Option","OrientationSensor","Origin","OscillatorNode","OverconstrainedError","PageRevealEvent","PageSwapEvent","PageTransitionEvent","PannerNode","PasswordCredential","Path2D","PaymentAddress","PaymentManager","PaymentMethodChangeEvent","PaymentRequest","PaymentRequestUpdateEvent","PaymentResponse","PerformanceElementTiming","PerformanceEntry","PerformanceEventTiming","PerformanceLongAnimationFrameTiming","PerformanceLongTaskTiming","PerformanceMark","PerformanceMeasure","PerformanceNavigationTiming","PerformanceObserverEntryList","PerformancePaintTiming","PerformanceResourceTiming","PerformanceScriptTiming","PerformanceServerTiming","PerformanceTimingConfidence","PeriodicSyncManager","PeriodicWave","PermissionStatus","Permissions","PictureInPictureEvent","PictureInPictureWindow","PopStateEvent","Presentation","PresentationAvailability","PresentationConnection","PresentationConnectionAvailableEvent","PresentationConnectionCloseEvent","PresentationConnectionList","PresentationReceiver","PresentationRequest","PressureObserver","PressureRecord","ProcessingInstruction","Profiler","ProgressEvent","PromiseRejectionEvent","ProtectedAudience","PublicKeyCredential","PushManager","PushSubscription","PushSubscriptionOptions","QuotaExceededError","RTCCertificate","RTCDTMFSender","RTCDTMFToneChangeEvent","RTCDataChannel","RTCDataChannelEvent","RTCDtlsTransport","RTCEncodedAudioFrame","RTCEncodedVideoFrame","RTCError","RTCErrorEvent","RTCIceCandidate","RTCIceTransport","RTCPeerConnectionIceErrorEvent","RTCPeerConnectionIceEvent","RTCRtpReceiver","RTCRtpScriptTransform","RTCRtpSender","RTCRtpTransceiver","RTCSctpTransport","RTCSessionDescription","RTCStatsReport","RTCTrackEvent","RadioNodeList","Range","ReadableByteStreamController","ReadableStreamBYOBReader","ReadableStreamBYOBRequest","ReadableStreamDefaultController","ReadableStreamDefaultReader","RelativeOrientationSensor","RemotePlayback","ReportBody","ReportingObserver","ResizeObserverEntry","ResizeObserverSize","RestrictionTarget","SVGAElement","SVGAngle","SVGAnimateElement","SVGAnimateMotionElement","SVGAnimateTransformElement","SVGAnimatedAngle","SVGAnimatedBoolean","SVGAnimatedEnumeration","SVGAnimatedInteger","SVGAnimatedLength","SVGAnimatedLengthList","SVGAnimatedNumber","SVGAnimatedNumberList","SVGAnimatedPreserveAspectRatio","SVGAnimatedRect","SVGAnimatedString","SVGAnimatedTransformList","SVGAnimationElement","SVGCircleElement","SVGClipPathElement","SVGComponentTransferFunctionElement","SVGDefsElement","SVGDescElement","SVGElement","SVGEllipseElement","SVGFEBlendElement","SVGFEColorMatrixElement","SVGFEComponentTransferElement","SVGFECompositeElement","SVGFEConvolveMatrixElement","SVGFEDiffuseLightingElement","SVGFEDisplacementMapElement","SVGFEDistantLightElement","SVGFEDropShadowElement","SVGFEFloodElement","SVGFEFuncAElement","SVGFEFuncBElement","SVGFEFuncGElement","SVGFEFuncRElement","SVGFEGaussianBlurElement","SVGFEImageElement","SVGFEMergeElement","SVGFEMergeNodeElement","SVGFEMorphologyElement","SVGFEOffsetElement","SVGFEPointLightElement","SVGFESpecularLightingElement","SVGFESpotLightElement","SVGFETileElement","SVGFETurbulenceElement","SVGFilterElement","SVGForeignObjectElement","SVGGElement","SVGGeometryElement","SVGGradientElement","SVGGraphicsElement","SVGImageElement","SVGLength","SVGLengthList","SVGLineElement","SVGLinearGradientElement","SVGMPathElement","SVGMarkerElement","SVGMaskElement","SVGMatrix","SVGMetadataElement","SVGNumber","SVGNumberList","SVGPathElement","SVGPatternElement","SVGPoint","SVGPointList","SVGPolygonElement","SVGPolylineElement","SVGPreserveAspectRatio","SVGRadialGradientElement","SVGRect","SVGRectElement","SVGSVGElement","SVGScriptElement","SVGSetElement","SVGStopElement","SVGStringList","SVGStyleElement","SVGSwitchElement","SVGSymbolElement","SVGTSpanElement","SVGTextContentElement","SVGTextElement","SVGTextPathElement","SVGTextPositioningElement","SVGTitleElement","SVGTransform","SVGTransformList","SVGUnitTypes","SVGUseElement","SVGViewElement","Sanitizer","Scheduler","Scheduling","ScreenDetailed","ScreenDetails","ScreenOrientation","ScriptProcessorNode","ScrollTimeline","SecurityPolicyViolationEvent","Selection","Sensor","SensorErrorEvent","Serial","SerialPort","ServiceWorker","ServiceWorkerContainer","ServiceWorkerRegistration","SharedStorage","SharedStorageAppendMethod","SharedStorageClearMethod","SharedStorageDeleteMethod","SharedStorageModifierMethod","SharedStorageSetMethod","SharedStorageWorklet","SnapEvent","SourceBuffer","SourceBufferList","SpeechGrammar","SpeechGrammarList","SpeechRecognition","SpeechRecognitionErrorEvent","SpeechRecognitionEvent","SpeechRecognitionPhrase","SpeechSynthesis","SpeechSynthesisErrorEvent","SpeechSynthesisEvent","SpeechSynthesisUtterance","SpeechSynthesisVoice","StaticRange","StereoPannerNode","Storage","StorageBucket","StorageBucketManager","StorageEvent","StorageManager","StylePropertyMap","StylePropertyMapReadOnly","StyleSheet","StyleSheetList","SubmitEvent","Subscriber","Summarizer","SuppressedError","SyncManager","TaskAttributionTiming","TaskController","TaskPriorityChangeEvent","TaskSignal","TextDecoderStream","TextEncoderStream","TextEvent","TextFormat","TextFormatUpdateEvent","TextMetrics","TextTrack","TextTrackCue","TextTrackCueList","TextTrackList","TextUpdateEvent","TimeRanges","TimelineTrigger","TimelineTriggerRange","TimelineTriggerRangeList","ToggleEvent","Touch","TouchEvent","TouchList","TrackEvent","TransformStreamDefaultController","TransitionEvent","Translator","TrustedHTML","TrustedScript","TrustedScriptURL","TrustedTypePolicy","TrustedTypePolicyFactory","URLPattern","USB","USBAlternateInterface","USBConfiguration","USBConnectionEvent","USBDevice","USBEndpoint","USBInTransferResult","USBInterface","USBIsochronousInTransferPacket","USBIsochronousInTransferResult","USBIsochronousOutTransferPacket","USBIsochronousOutTransferResult","USBOutTransferResult","UserActivation","VTTCue","ValidityState","VideoColorSpace","VideoDecoder","VideoEncoder","VideoFrame","VideoPlaybackQuality","ViewTimeline","ViewTransition","ViewTransitionTypeSet","Viewport","VirtualKeyboard","VirtualKeyboardGeometryChangeEvent","VisibilityStateEntry","VisualViewport","WGSLLanguageFeatures","WakeLock","WakeLockSentinel","WaveShaperNode","WebGLContextEvent","WebGLObject","WebGLQuery","WebGLSampler","WebGLShaderPrecisionFormat","WebGLSync","WebGLTransformFeedback","WebKitCSSMatrix","WebKitMutationObserver","WebSocketError","WebSocketStream","WebTransport","WebTransportBidirectionalStream","WebTransportDatagramDuplexStream","WebTransportError","WheelEvent","Window","WindowControlsOverlay","WindowControlsOverlayGeometryChangeEvent","Worklet","WritableStreamDefaultController","WritableStreamDefaultWriter","XMLDocument","XMLHttpRequestEventTarget","XMLHttpRequestUpload","XMLSerializer","XPathEvaluator","XPathExpression","XPathResult","XRAnchor","XRAnchorSet","XRBoundedReferenceSpace","XRCPUDepthInformation","XRCamera","XRCompositionLayer","XRCubeLayer","XRCylinderLayer","XRDOMOverlayState","XRDepthInformation","XREquirectLayer","XRFrame","XRHand","XRHitTestResult","XRHitTestSource","XRInputSource","XRInputSourceArray","XRInputSourceEvent","XRInputSourcesChangeEvent","XRJointPose","XRJointSpace","XRLayer","XRLayerEvent","XRLightEstimate","XRLightProbe","XRPlane","XRPlaneSet","XRPose","XRProjectionLayer","XRQuadLayer","XRRay","XRReferenceSpace","XRReferenceSpaceEvent","XRRenderState","XRRigidTransform","XRSession","XRSessionEvent","XRSpace","XRSubImage","XRSystem","XRTransientInputHitTestResult","XRTransientInputHitTestSource","XRView","XRViewerPose","XRViewport","XRVisibilityMaskChangeEvent","XRWebGLBinding","XRWebGLDepthInformation","XRWebGLLayer","XRWebGLSubImage","XSLTProcessor","alert","blur","captureEvents","close","confirm","createImageBitmap","fetchLater","find","focus","getScreenDetails","getSelection","moveBy","moveTo","open","postMessage","print","prompt","queryLocalFonts","releaseEvents","resizeBy","resizeTo","scroll","scrollBy","scrollTo","showDirectoryPicker","showOpenFilePicker","showSaveFilePicker","stop","webkitCancelAnimationFrame","webkitMediaStream","webkitRequestAnimationFrame","webkitRequestFileSystem","webkitResolveLocalFileSystemURL","webkitSpeechGrammar","webkitSpeechGrammarList","webkitSpeechRecognition","webkitSpeechRecognitionError","webkitSpeechRecognitionEvent","webkitURL","when"]},"document":{"#1":["DOCUMENT_POSITION_DISCONNECTED","childElementCount"],"#2":["DOCUMENT_POSITION_PRECEDING"],"#4":["DOCUMENT_POSITION_FOLLOWING"],"#5":["ENTITY_REFERENCE_NODE"],"#6":["ENTITY_NODE"],"#8":["DOCUMENT_POSITION_CONTAINS"],"#12":["NOTATION_NODE"],"#16":["DOCUMENT_POSITION_CONTAINED_BY"],"#32":["DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC"],"o":["applets","children","customElementRegistry","doctype","featurePolicy","firstElementChild","fonts","fragmentDirective","implementation","lastElementChild","scrollingElement","timeline"],"F":["fullscreen","prerendering","wasDiscarded","webkitHidden","webkitIsFullScreen","xmlStandalone"],"x":["activeViewTransition","fullscreenElement","nodeValue","onabort","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onauxclick","onbeforecopy","onbeforecut","onbeforeinput","onbeforematch","onbeforepaste","onbeforetoggle","onbeforexrselect","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncopy","oncuechange","oncut","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","onfreeze","onfullscreenchange","onfullscreenerror","ongotpointercapture","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onlostpointercapture","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpaste","onpause","onplay","onplaying","onpointercancel","onpointerdown","onpointerenter","onpointerleave","onpointerlockchange","onpointerlockerror","onpointermove","onpointerout","onpointerover","onpointerrawupdate","onpointerup","onprerenderingchange","onprogress","onratechange","onreadystatechange","onreset","onresize","onresume","onscroll","onscrollend","onscrollsnapchange","onscrollsnapchanging","onsearch","onsecuritypolicyviolation","onseeked","onseeking","onselect","onselectionchange","onselectstart","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","ontransitioncancel","ontransitionend","ontransitionrun","ontransitionstart","onvisibilitychange","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkitfullscreenchange","onwebkitfullscreenerror","onwebkittransitionend","onwheel","parentElement","pictureInPictureElement","pointerLockElement","rootElement","webkitCurrentFullScreenElement","webkitFullscreenElement","xmlEncoding","xmlVersion"],"u":["all"],"T":["fullscreenEnabled","pictureInPictureEnabled","webkitFullscreenEnabled"],"N":["adoptNode","append","ariaNotify","browsingTopics","captureEvents","caretPositionFromPoint","caretRangeFromPoint","clear","compareDocumentPosition","createAttribute","createAttributeNS","createCDATASection","createExpression","createNSResolver","createProcessingInstruction","createRange","evaluate","execCommand","exitFullscreen","exitPictureInPicture","exitPointerLock","getAnimations","getElementsByName","getElementsByTagNameNS","getSelection","hasFocus","hasPrivateToken","hasRedemptionRecord","hasStorageAccess","hasUnpartitionedCookieAccess","importNode","isDefaultNamespace","isEqualNode","isSameNode","lookupNamespaceURI","lookupPrefix","moveBefore","normalize","prepend","queryCommandEnabled","queryCommandIndeterm","queryCommandState","queryCommandSupported","queryCommandValue","releaseEvents","replaceChildren","requestStorageAccess","requestStorageAccessFor","startViewTransition","webkitCancelFullScreen","webkitExitFullscreen","when"]},"navigator":{"o":["clipboard","credentials","devicePosture","geolocation","gpu","hid","ink","keyboard","locks","login","managed","mediaCapabilities","mediaSession","presentation","protectedAudience","scheduling","serial","storageBuckets","usb","virtualKeyboard","wakeLock","webkitPersistentStorage","webkitTemporaryStorage","windowControlsOverlay","xr"],"F":["deprecatedRunAdAuctionEnforcesKAnonymity"],"N":["adAuctionComponents","canLoadAdAuctionFencedFrame","clearOriginJoinedAdInterestGroups","createAuctionNonce","deprecatedReplaceInURN","deprecatedURNToURL","getGamepads","getInstalledRelatedApps","getInterestGroupAdAuctionData","getUserMedia","javaEnabled","joinAdInterestGroup","leaveAdInterestGroup","registerProtocolHandler","requestMIDIAccess","requestMediaKeySystemAccess","runAdAuction","unregisterProtocolHandler","updateAdInterestGroups","webkitGetUserMedia"]},"location":{"o":["ancestorOrigins"],"N":["valueOf"]},"screen":{"x":["onchange"],"N":["addEventListener","dispatchEvent","removeEventListener","when"]}};
  const native = globalThis.__pt_native || ((f) => f);
  const stub = (name, cat) => {
    if (cat === 'N' || cat === 'f') {
      const f = function () {};
      try { Object.defineProperty(f, 'name', { value: name, configurable: true }); } catch (e) {}
      // An interface object carries a prototype whose members are enumerable and
      // whose `constructor` points back — that is what makes it look like one.
      try {
        Object.defineProperty(f.prototype, 'constructor', { value: f, writable: true, configurable: true });
      } catch (e) {}
      return cat === 'N' ? native(f) : f;
    }
    if (cat === 'x') return null;
    if (cat === 'u') return undefined;
    if (cat === 'o') return {};
    if (cat === 'a') return [];
    if (cat === 'T') return true;
    if (cat === 'F') return false;
    if (cat === 'D') return Array;
    if (cat === 'p') { const p = Promise.resolve(); p.catch(() => {}); return p; }
    if (cat.charCodeAt(0) === 35) return Number(cat.slice(1));  // '#12' → 12
    return undefined;
  };
  // SharedArrayBuffer страница видит только под cross-origin isolation, а мы
  // объявляем crossOriginIsolated=false. V8 отдаёт его всегда — убираем, иначе
  // пара «изоляции нет, но SAB есть» невозможна ни в одном настоящем Chrome.
  try { delete globalThis.SharedArrayBuffer; } catch (e) {}

  for (const root of Object.keys(T)) {
    const obj = root === 'window' ? globalThis : globalThis[root];
    if (!obj) continue;
    // Свойства интерфейса живут на прототипе: у настоящего `document` или
    // `navigator` собственных свойств нет вовсе, и наши тесты это стерегут.
    const proto = root === 'window' ? obj : (Object.getPrototypeOf(obj) || obj);
    const target = proto;
    // "Уже есть" — значит есть на самом интерфейсе, а не унаследовано от
    // Object.prototype: `location.valueOf` там как раз и прячется, из-за чего
    // собственного, перечислимого valueOf у Location не появлялось.
    const has = (name) => {
      for (let p = target; p && p !== Object.prototype; p = Object.getPrototypeOf(p)) {
        if (Object.prototype.hasOwnProperty.call(p, name)) return true;
      }
      return false;
    };
    for (const cat of Object.keys(T[root])) {
      for (const name of T[root][cat]) {
        if (has(name)) continue;                    // реализованное не трогаем
        try {
          Object.defineProperty(target, name, {
            value: stub(name, cat), writable: true, enumerable: true, configurable: true,
          });
        } catch (e) {}
      }
    }
  }
})();"##;

/// `fetch` + `XMLHttpRequest`, implemented as a queue the Rust event loop drains.
/// JS never touches the network: `fetch()` enqueues a request and returns a
/// Promise; the driver pulls the queue via `__pt_drainFetchQueue`, performs the
/// request on the (Chrome-fingerprinted, cookie-sharing) network client, and
/// settles the Promise via `__pt_fetchResolve`/`__pt_fetchReject`. Bodies are
/// treated as UTF-8 text (fine for HTML/JSON/challenge payloads).
/// `performance`, coherent with the wall clock. A bare `{ now: () => 0 }` with
/// `timeOrigin === 0` is an instant tell: real Chrome satisfies
/// `timeOrigin + now() ≈ Date.now()`, exposes a `Performance` *instance* (whose
/// own-property list is empty — everything lives on the prototype), reports a
/// coarsened monotonic `now()`, and carries the legacy `timing`/`navigation`
/// blocks plus Chrome's `memory`.
const PERFORMANCE_TEMPLATE: &str = r#"(() => {
  const ORIGIN = Date.now();

  // DOMHighResTimeStamp: 0.1 ms granularity (Chrome coarsens it against timing
  // attacks) and never decreasing. Derived from the same clock as `Date.now()`,
  // so `timeOrigin + now()` tracks it exactly.
  let last = 0;
  const nowMs = () => {
    const coarse = Math.round(Math.max(0, Date.now() - ORIGIN) * 10) / 10;
    if (coarse > last) last = coarse;
    return last;
  };

  // Plausible, correctly ordered navigation milestones anchored at the origin.
  const T = (d) => ORIGIN + d;
  const TIMING = {
    navigationStart: T(0), unloadEventStart: 0, unloadEventEnd: 0,
    redirectStart: 0, redirectEnd: 0,
    fetchStart: T(1), domainLookupStart: T(2), domainLookupEnd: T(6),
    connectStart: T(6), secureConnectionStart: T(12), connectEnd: T(24),
    requestStart: T(25), responseStart: T(70), responseEnd: T(78),
    domLoading: T(80), domInteractive: T(150),
    domContentLoadedEventStart: T(151), domContentLoadedEventEnd: T(160),
    domComplete: T(190), loadEventStart: T(191), loadEventEnd: T(196),
  };
  const NAVIGATION = { type: 0, redirectCount: 0 };
  // Chrome quantises these; absent `performance.memory` under a Chrome UA is
  // itself a tell.
  const MEMORY = { jsHeapSizeLimit: 2172649472, totalJSHeapSize: 12800000, usedJSHeapSize: 10600000 };

  // Expose a value bag as enumerable prototype getters, so instances stay free
  // of own properties (matching every other DOM object we hand out).
  const onProto = (proto, bag) => {
    for (const k of Object.keys(bag)) {
      const get = function () { return bag[k]; };
      try { Object.defineProperty(get, 'name', { value: 'get ' + k, configurable: true }); } catch (e) {}
      Object.defineProperty(proto, k, { get, configurable: true, enumerable: true });
    }
  };
  const tag = (proto, name) => {
    try { Object.defineProperty(proto, Symbol.toStringTag, { value: name, configurable: true }); } catch (e) {}
  };

  class PerformanceTiming { toJSON() { return Object.assign({}, TIMING); } }
  onProto(PerformanceTiming.prototype, TIMING);
  tag(PerformanceTiming.prototype, 'PerformanceTiming');

  class PerformanceNavigation { toJSON() { return Object.assign({}, NAVIGATION); } }
  onProto(PerformanceNavigation.prototype, NAVIGATION);
  onProto(PerformanceNavigation.prototype, { TYPE_NAVIGATE: 0, TYPE_RELOAD: 1, TYPE_BACK_FORWARD: 2, TYPE_RESERVED: 255 });
  tag(PerformanceNavigation.prototype, 'PerformanceNavigation');

  class MemoryInfo {}
  onProto(MemoryInfo.prototype, MEMORY);
  tag(MemoryInfo.prototype, 'MemoryInfo');

  const timing = new PerformanceTiming();
  const navigation = new PerformanceNavigation();
  const memory = new MemoryInfo();

  // Каждый запрос страницы оставляет запись Resource Timing, и после загрузки
  // их десятки. Пустой список — признак браузера, который ничего не грузил:
  // ровно на это смотрит анти-бот, спрашивая getEntriesByType('resource').
  // Записи кладёт сюда движок, по мере того как запросы завершаются.
  const entries = [];
  class PerformanceEntry {
    toJSON() { const o = {}; for (const k of Object.keys(this)) o[k] = this[k]; return o; }
  }
  tag(PerformanceEntry.prototype, 'PerformanceEntry');
  class PerformanceResourceTiming extends PerformanceEntry {}
  tag(PerformanceResourceTiming.prototype, 'PerformanceResourceTiming');
  class PerformanceNavigationTiming extends PerformanceEntry {}
  tag(PerformanceNavigationTiming.prototype, 'PerformanceNavigationTiming');
  globalThis.PerformanceEntry = PerformanceEntry;
  globalThis.PerformanceResourceTiming = PerformanceResourceTiming;
  globalThis.PerformanceNavigationTiming = PerformanceNavigationTiming;

  globalThis.__pt_noteResources = (json) => {
    let list;
    const fresh = [];
    try { list = JSON.parse(json); } catch (e) { return 0; }
    for (const r of list) {
      const Ctor = r.entryType === 'navigation' ? PerformanceNavigationTiming : PerformanceResourceTiming;
      const e = new Ctor();
      const start = Number(r.start) || 0;
      const end = start + (Number(r.duration) || 0);
      Object.assign(e, {
        name: String(r.name || ''), entryType: r.entryType || 'resource',
        startTime: start, duration: Number(r.duration) || 0,
        initiatorType: r.initiatorType || 'other', deliveryType: '',
        nextHopProtocol: r.protocol || 'h2', renderBlockingStatus: 'non-blocking',
        workerStart: 0, redirectStart: 0, redirectEnd: 0,
        fetchStart: start, domainLookupStart: start, domainLookupEnd: start,
        connectStart: start, secureConnectionStart: start, connectEnd: start,
        requestStart: start, responseStart: start + (Number(r.duration) || 0) * 0.8,
        firstInterimResponseStart: 0, responseEnd: end,
        transferSize: Number(r.size) || 0,
        encodedBodySize: Math.max(0, (Number(r.size) || 0) - 300),
        decodedBodySize: Number(r.decoded) || Math.max(0, (Number(r.size) || 0) - 300),
        responseStatus: Number(r.status) || 200,
        serverTiming: [], contentType: r.contentType || '',
      });
      if (r.entryType === 'navigation') {
        Object.assign(e, {
          unloadEventStart: 0, unloadEventEnd: 0, domInteractive: end,
          domContentLoadedEventStart: end, domContentLoadedEventEnd: end,
          domComplete: end, loadEventStart: end, loadEventEnd: end,
          type: 'navigate', redirectCount: 0, activationStart: 0, criticalCHRestart: 0,
          notRestoredReasons: null,
        });
      }
      entries.push(e);
      fresh.push(e);
    }
    __ptNotify(fresh);
    return entries.length;
  };

  // PerformanceObserver — не заглушка: страница подписывается на записи и ждёт
  // колбэка. Пустой `supportedEntryTypes` — сам по себе улика (у браузера там
  // дюжина имён), а наблюдатель, который никогда не срабатывает, подвешивает
  // любой код, который на него рассчитывает.
  const observers = [];
  class PerformanceObserverEntryList {
    constructor(list) { Object.defineProperty(this, '__ptList', { value: list, enumerable: false }); }
    getEntries() { return this.__ptList.slice(); }
    getEntriesByType(t) { return this.__ptList.filter((e) => e.entryType === String(t)); }
    getEntriesByName(n, t) { return this.__ptList.filter((e) => e.name === String(n) && (!t || e.entryType === String(t))); }
  }
  tag(PerformanceObserverEntryList.prototype, 'PerformanceObserverEntryList');
  class PerformanceObserver {
    constructor(cb) {
      if (typeof cb !== 'function') throw new TypeError("Failed to construct 'PerformanceObserver': parameter 1 is not of type 'Function'.");
      for (const [k, v] of [['__ptCb', cb], ['__ptTypes', []], ['__ptQueue', []], ['__ptOn', false]]) {
        Object.defineProperty(this, k, { value: v, writable: true, enumerable: false });
      }
    }
    observe(opts) {
      opts = opts || {};
      const types = opts.entryTypes ? Array.from(opts.entryTypes).map(String)
                  : opts.type ? [String(opts.type)] : [];
      for (const t of types) if (this.__ptTypes.indexOf(t) < 0) this.__ptTypes.push(t);
      if (!this.__ptOn) { this.__ptOn = true; observers.push(this); }
      // `buffered` — то, что уже случилось до подписки.
      if (opts.buffered) {
        const past = entries.filter((e) => this.__ptTypes.indexOf(e.entryType) >= 0);
        if (past.length) { this.__ptQueue.push(...past); __ptFlush(this); }
      }
    }
    disconnect() {
      this.__ptOn = false; this.__ptQueue.length = 0;
      const i = observers.indexOf(this); if (i >= 0) observers.splice(i, 1);
    }
    takeRecords() { return this.__ptQueue.splice(0); }
  }
  tag(PerformanceObserver.prototype, 'PerformanceObserver');
  // Порядок и состав — как у Chrome 148.
  PerformanceObserver.supportedEntryTypes = ['element', 'event', 'first-input',
    'largest-contentful-paint', 'layout-shift', 'long-animation-frame', 'longtask',
    'mark', 'measure', 'navigation', 'paint', 'resource'];
  globalThis.PerformanceObserver = PerformanceObserver;
  globalThis.PerformanceObserverEntryList = PerformanceObserverEntryList;

  // Колбэк приходит задачей, а не по ходу записи — как в браузере.
  const __ptFlush = (obs) => {
    Promise.resolve().then(() => {
      const batch = obs.__ptQueue.splice(0);
      if (!batch.length || !obs.__ptOn) return;
      try { obs.__ptCb(new PerformanceObserverEntryList(batch), obs); } catch (e) {}
    });
  };
  const __ptNotify = (fresh) => {
    for (const obs of observers.slice()) {
      const mine = fresh.filter((e) => obs.__ptTypes.indexOf(e.entryType) >= 0);
      if (mine.length) { obs.__ptQueue.push(...mine); __ptFlush(obs); }
    }
  };

  class Performance {
    now() { return nowMs(); }
    getEntries() { return entries.slice(); }
    getEntriesByType(type) { return entries.filter((e) => e.entryType === String(type)); }
    getEntriesByName(name, type) {
      return entries.filter((e) => e.name === String(name) && (!type || e.entryType === String(type)));
    }
    mark(name, opts) {
      const e = new PerformanceEntry();
      Object.assign(e, { name: String(name), entryType: 'mark',
        startTime: (opts && typeof opts.startTime === 'number') ? opts.startTime : nowMs(),
        duration: 0, detail: (opts && opts.detail) !== undefined ? opts.detail : null });
      entries.push(e); __ptNotify([e]); return e;
    }
    measure(name, startOrOpts, end) {
      const e = new PerformanceEntry();
      const from = typeof startOrOpts === 'string'
        ? (entries.filter((x) => x.name === startOrOpts).pop() || { startTime: 0 }).startTime
        : (startOrOpts && typeof startOrOpts.start === 'number') ? startOrOpts.start : 0;
      const to = typeof end === 'string'
        ? (entries.filter((x) => x.name === end).pop() || { startTime: nowMs() }).startTime
        : nowMs();
      Object.assign(e, { name: String(name), entryType: 'measure', startTime: from,
                         duration: Math.max(0, to - from), detail: null });
      entries.push(e); __ptNotify([e]); return e;
    }
    clearMarks() {}
    clearMeasures() {}
    clearResourceTimings() { entries.length = 0; }
    setResourceTimingBufferSize() {}
    addEventListener() {}
    removeEventListener() {}
    dispatchEvent() { return true; }
    toJSON() {
      return { timeOrigin: ORIGIN, timing: timing.toJSON(), navigation: navigation.toJSON() };
    }
  }
  onProto(Performance.prototype, { timeOrigin: ORIGIN, timing, navigation, memory });
  tag(Performance.prototype, 'Performance');

  globalThis.Performance = Performance;
  globalThis.PerformanceTiming = PerformanceTiming;
  globalThis.PerformanceNavigation = PerformanceNavigation;
  globalThis.performance = new Performance();
})();"#;

/// WebCrypto, backed by the native Rust primitives installed on every context
/// (see `nokk-pool`'s `natives` module). `crypto.subtle` was previously absent
/// entirely — an instant tell, since every browser on a secure origin exposes it —
/// and `getRandomValues` was a seeded xorshift rather than real randomness.
/// Results are genuine, so a page that digests a known input and checks the answer
/// sees what Chrome would.
const CRYPTO_TEMPLATE: &str = r#"(() => {
  const N = globalThis;
  const u8 = (d) => {
    if (d instanceof Uint8Array) return d;
    if (ArrayBuffer.isView(d)) return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
    if (d instanceof ArrayBuffer) return new Uint8Array(d);
    return new Uint8Array(0);
  };
  // WebCrypto hands back ArrayBuffers, not views.
  const buf = (a) => a.buffer.slice(a.byteOffset, a.byteOffset + a.byteLength);
  const fail = (name, msg) => { const e = new Error(msg || name); e.name = name; return Promise.reject(e); };
  const nameOf = (a) => String(typeof a === 'string' ? a : (a && a.name) || '').toUpperCase();
  const hashOf = (a) => { const h = a && a.hash; return String(typeof h === 'string' ? h : (h && h.name) || 'SHA-256').toUpperCase(); };
  const norm = (a) => {
    const o = { name: nameOf(a) };
    if (a && typeof a === 'object') {
      if (a.hash) o.hash = { name: hashOf(a) };
      if (a.length != null) o.length = a.length;
    }
    return o;
  };

  // Key material lives in a side table so a CryptoKey has no own properties.
  const KEYS = new WeakMap();
  class CryptoKey {}
  const keyGetter = (field) => {
    const get = function () { const r = KEYS.get(this); return r ? r[field] : undefined; };
    try { Object.defineProperty(get, 'name', { value: 'get ' + field, configurable: true }); } catch (e) {}
    return { get, configurable: true, enumerable: true };
  };
  Object.defineProperties(CryptoKey.prototype, {
    type: keyGetter('type'), extractable: keyGetter('extractable'),
    algorithm: keyGetter('algorithm'), usages: keyGetter('usages'),
  });
  try { Object.defineProperty(CryptoKey.prototype, Symbol.toStringTag, { value: 'CryptoKey', configurable: true }); } catch (e) {}

  const mkKey = (raw, algorithm, extractable, usages) => {
    const k = new CryptoKey();
    KEYS.set(k, { raw, algorithm, extractable: !!extractable, usages: (usages || []).slice(), type: 'secret' });
    return k;
  };
  const raw = (k) => { const r = KEYS.get(k); return r ? r.raw : null; };

  class SubtleCrypto {
    digest(alg, data) {
      const out = __pt_digest(nameOf(alg), u8(data));
      return out ? Promise.resolve(buf(out)) : fail('NotSupportedError', 'Unrecognized digest algorithm');
    }
    importKey(format, keyData, algorithm, extractable, usages) {
      if (String(format).toLowerCase() !== 'raw') return fail('NotSupportedError', 'Only raw import is supported');
      return Promise.resolve(mkKey(u8(keyData).slice(), norm(algorithm), extractable, usages));
    }
    exportKey(format, key) {
      const r = KEYS.get(key);
      if (!r) return fail('InvalidAccessError', 'Not a CryptoKey');
      if (String(format).toLowerCase() !== 'raw') return fail('NotSupportedError', 'Only raw export is supported');
      if (!r.extractable) return fail('InvalidAccessError', 'Key is not extractable');
      return Promise.resolve(buf(r.raw));
    }
    generateKey(algorithm, extractable, usages) {
      const a = norm(algorithm);
      const bits = a.length || (a.name === 'HMAC' ? 256 : 128);
      const bytes = __pt_randomBytes(Math.max(1, Math.ceil(bits / 8)));
      if (!bytes) return fail('OperationError', 'Key generation failed');
      return Promise.resolve(mkKey(bytes, a, extractable, usages));
    }
    sign(alg, key, data) {
      const k = raw(key);
      if (!k) return fail('InvalidAccessError', 'Not a CryptoKey');
      if (nameOf(alg) !== 'HMAC') return fail('NotSupportedError', 'Only HMAC signing is supported');
      const r = KEYS.get(key);
      const out = __pt_hmac(hashOf(r.algorithm), k, u8(data));
      return out ? Promise.resolve(buf(out)) : fail('OperationError', 'Signing failed');
    }
    verify(alg, key, signature, data) {
      return this.sign(alg, key, data).then((expected) => {
        const a = u8(expected), b = u8(signature);
        if (a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
      });
    }
    encrypt(alg, key, data) { return this.__op(true, alg, key, data); }
    decrypt(alg, key, data) { return this.__op(false, alg, key, data); }
    __op(enc, alg, key, data) {
      const k = raw(key);
      if (!k) return fail('InvalidAccessError', 'Not a CryptoKey');
      const n = nameOf(alg);
      let out = null;
      if (n === 'AES-GCM') out = __pt_aesgcm(enc, k, u8(alg && alg.iv), u8(alg && alg.additionalData), u8(data));
      else if (n === 'AES-CBC') out = __pt_aescbc(enc, k, u8(alg && alg.iv), u8(data));
      else return fail('NotSupportedError', 'Unrecognized cipher');
      return out ? Promise.resolve(buf(out)) : fail('OperationError', enc ? 'Encryption failed' : 'Decryption failed');
    }
    deriveBits(alg, key, length) {
      const k = raw(key);
      if (!k) return fail('InvalidAccessError', 'Not a CryptoKey');
      const bytes = Math.max(0, Math.ceil((length || 0) / 8));
      const n = nameOf(alg);
      let out = null;
      if (n === 'PBKDF2') out = __pt_pbkdf2(hashOf(alg), k, u8(alg && alg.salt), alg && alg.iterations || 1, bytes);
      else if (n === 'HKDF') out = __pt_hkdf(hashOf(alg), k, u8(alg && alg.salt), u8(alg && alg.info), bytes);
      else return fail('NotSupportedError', 'Unrecognized derivation');
      return out ? Promise.resolve(buf(out)) : fail('OperationError', 'Derivation failed');
    }
    deriveKey(alg, key, derivedAlg, extractable, usages) {
      const a = norm(derivedAlg);
      const bits = a.length || (a.name === 'HMAC' ? 256 : 128);
      return this.deriveBits(alg, key, bits)
        .then((b) => mkKey(new Uint8Array(b), a, extractable, usages));
    }
  }
  try { Object.defineProperty(SubtleCrypto.prototype, Symbol.toStringTag, { value: 'SubtleCrypto', configurable: true }); } catch (e) {}

  const subtle = new SubtleCrypto();

  class Crypto {
    getRandomValues(view) {
      if (!ArrayBuffer.isView(view)) { const e = new Error('Argument is not a TypedArray'); e.name = 'TypeMismatchError'; throw e; }
      if (view.byteLength > 65536) { const e = new Error('Requested too many bytes'); e.name = 'QuotaExceededError'; throw e; }
      const r = __pt_randomBytes(view.byteLength);
      if (r) new Uint8Array(view.buffer, view.byteOffset, view.byteLength).set(r);
      return view;
    }
    randomUUID() {
      const b = __pt_randomBytes(16);
      b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
      const h = Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
      return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
    }
  }
  Object.defineProperty(Crypto.prototype, 'subtle', {
    get: (() => { const g = function () { return subtle; };
      try { Object.defineProperty(g, 'name', { value: 'get subtle', configurable: true }); } catch (e) {}
      return g; })(),
    configurable: true, enumerable: true,
  });
  try { Object.defineProperty(Crypto.prototype, Symbol.toStringTag, { value: 'Crypto', configurable: true }); } catch (e) {}

  N.Crypto = Crypto;
  N.SubtleCrypto = SubtleCrypto;
  N.CryptoKey = CryptoKey;
  N.crypto = new Crypto();
})();"#;

const FETCH_TEMPLATE: &str = r#"(() => {
  let fid = 1;
  const pending = new Map(); // id -> {resolve, reject, url}
  const queue = [];          // [{id, url, method, headers, body}]

  const headerObj = (h) => {
    const out = {};
    if (!h) return out;
    if (typeof h.forEach === 'function') h.forEach((v, k) => { out[String(k)] = String(v); });
    else for (const k in h) out[k] = String(h[k]);
    return out;
  };

  // `blob:` and `data:` never reach the network — they are answered from the
  // page's own memory. A blob URL handed to the network client fails with
  // "invalid authority", which is how Turnstile's challenge stalls: its VM builds
  // its payload as a Blob, takes an object URL, and fetches it back. The registry
  // lives on `URL.createObjectURL` (see the URL shim); this reads it.
  const localResponse = (url) => {
    const s = String(url);
    if (s.slice(0, 5) === 'blob:') {
      const b = globalThis.__pt_blobs && globalThis.__pt_blobs.get(s);
      if (!b) return null;
      const body = typeof b.text === 'function' ? String(b) : String(b);
      return { body, type: b.type || '' };
    }
    if (s.slice(0, 5) === 'data:') {
      const comma = s.indexOf(',');
      if (comma < 0) return null;
      const meta = s.slice(5, comma), payload = s.slice(comma + 1);
      try {
        return { body: /;base64/i.test(meta) ? globalThis.atob(payload) : decodeURIComponent(payload),
                 type: meta.split(';')[0] || 'text/plain' };
      } catch (e) { return null; }
    }
    return null;
  };

  // The driver asks for these by name when a `<script src="blob:…">` is inserted:
  // the bytes live here, not on any server.
  globalThis.__pt_localSource = (u) => { const r = localResponse(u); return r ? r.body : null; };

  globalThis.fetch = (url, opts) => {
    opts = opts || {};
    const local = localResponse(url);
    if (local) {
      const id = fid++;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject, url: String(url) });
        globalThis.queueMicrotask(() => globalThis.__pt_fetchResolve(
          id, 200, 'OK', { 'content-type': local.type }, local.body, String(url)));
      });
    }
    const id = fid++;
    const req = {
      id, url: String(url),
      method: (opts.method || 'GET').toUpperCase(),
      headers: headerObj(opts.headers),
      body: opts.body != null ? String(opts.body) : null,
    };
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject, url: req.url });
      queue.push(req);
    });
  };

  // Rust hooks -------------------------------------------------------------
  globalThis.__pt_drainFetchQueue = () => { const q = queue.splice(0); return JSON.stringify(q); };
  globalThis.__pt_pendingFetches = () => pending.size;

  globalThis.__pt_fetchResolve = (id, status, statusText, headers, body, finalUrl) => {
    const p = pending.get(id); if (!p) return; pending.delete(id);
    const lower = {}; for (const k in headers) lower[k.toLowerCase()] = headers[k];
    const resp = {
      ok: status >= 200 && status < 300, status, statusText: statusText || '',
      url: finalUrl || p.url, redirected: false, type: 'basic', bodyUsed: false, _body: body,
      headers: {
        get: (k) => (k.toLowerCase() in lower ? lower[k.toLowerCase()] : null),
        has: (k) => k.toLowerCase() in lower,
        forEach: (f) => { for (const k in lower) f(lower[k], k); },
        entries: () => Object.entries(lower),
        keys: () => Object.keys(lower),
      },
      text() { this.bodyUsed = true; return Promise.resolve(this._body); },
      json() { this.bodyUsed = true; return Promise.resolve(JSON.parse(this._body)); },
      arrayBuffer() { this.bodyUsed = true; return Promise.resolve(new TextEncoder().encode(this._body).buffer); },
      clone() { return Object.assign({}, this); },
    };
    p.resolve(resp);
  };
  globalThis.__pt_fetchReject = (id, msg) => {
    const p = pending.get(id); if (!p) return; pending.delete(id);
    p.reject(new TypeError('Failed to fetch: ' + msg));
  };

  // XMLHttpRequest layered on the same queue -------------------------------
  // Every event surface a page listens on is an EventTarget, and ours was not:
  // `xhr.addEventListener('load', …)` — how modern code reads a response, and how
  // Cloudflare's challenge widget learns its POST succeeded — did not exist at
  // all. Setting `onload` worked, adding a listener did nothing, so the widget
  // fired three requests, got three answers it never heard about, waited out its
  // own timeout and reported failure (300010). A missing `EventTarget` global is
  // also a one-line tell in its own right.
  if (!globalThis.EventTarget) {
    globalThis.EventTarget = class EventTarget {
      constructor() { Object.defineProperty(this, '__ptLis', { value: Object.create(null), enumerable: false, writable: true }); }
      addEventListener(type, fn, opts) {
        if (!fn) return;
        if (!this.__ptLis) Object.defineProperty(this, '__ptLis', { value: Object.create(null), enumerable: false, writable: true });
        const l = (this.__ptLis[type] = this.__ptLis[type] || []);
        if (!l.some(e => e.fn === fn)) l.push({ fn, once: !!(opts && opts.once) });
      }
      removeEventListener(type, fn) {
        const l = this.__ptLis && this.__ptLis[type];
        if (l) this.__ptLis[type] = l.filter(e => e.fn !== fn);
      }
      dispatchEvent(ev) {
        const type = ev && ev.type;
        const l = (this.__ptLis && this.__ptLis[type]) || [];
        for (const e of l.slice()) {
          if (e.once) this.removeEventListener(type, e.fn);
          try { typeof e.fn === 'function' ? e.fn.call(this, ev) : (e.fn.handleEvent && e.fn.handleEvent(ev)); } catch (x) {}
        }
        const on = this['on' + type];
        if (typeof on === 'function') { try { on.call(this, ev); } catch (x) {} }
        return !ev || !ev.defaultPrevented;
      }
    };
  }

  globalThis.XMLHttpRequest = class XMLHttpRequest extends globalThis.EventTarget {
    constructor() {
      super();
      this.readyState = 0; this.status = 0; this.statusText = '';
      this.responseText = ''; this.response = ''; this.responseType = '';
      this.responseURL = ''; this.responseXML = null;
      this.withCredentials = false; this.timeout = 0;
      this._headers = {}; this._respHeaders = {}; this._aborted = false;
      this.upload = new globalThis.EventTarget();
      this.onreadystatechange = null; this.onload = null; this.onerror = null;
      this.onloadend = null; this.onloadstart = null; this.onprogress = null;
      this.onabort = null; this.ontimeout = null;
    }
    open(method, url) { this.method = String(method).toUpperCase(); this.url = String(url); this._set(1); }
    setRequestHeader(k, v) { this._headers[k] = String(v); }
    overrideMimeType() {}
    // Каждая строка кончается CRLF, включая последнюю: код, который делит по
    // '\r\n', в браузере получает пустой хвостовой элемент, а у нас не получал.
    getAllResponseHeaders() {
      const rows = Object.entries(this._respHeaders).map(([k, v]) => k + ': ' + v + '\r\n');
      return rows.join('');
    }
    getResponseHeader(k) { return this._respHeaders[k.toLowerCase()] ?? null; }
    abort() {
      this._aborted = true;
      this.readyState = 4; this.status = 0;
      this._fire('abort'); this._fire('loadend');
    }
    send(body) {
      this._fire('loadstart');
      fetch(this.url, { method: this.method, headers: this._headers, body })
        .then(async (r) => {
          if (this._aborted) return;
          this.status = r.status; this.statusText = r.statusText; this.responseURL = r.url || this.url;
          r.headers.forEach((v, k) => { this._respHeaders[k] = v; });
          this._set(2); this._set(3);
          this.responseText = await r.text();
          try { this.response = this.responseType === 'json' ? JSON.parse(this.responseText || 'null') : this.responseText; }
          catch (e) { this.response = null; }
          this._set(4);
          this._fire('progress', { lengthComputable: true, loaded: this.responseText.length, total: this.responseText.length });
          this._fire('load'); this._fire('loadend');
        })
        .catch(() => {
          if (this._aborted) return;
          this.status = 0; this._set(4);
          this._fire('error'); this._fire('loadend');
        });
    }
    // The order matters: `readystatechange` reaches both a property handler and
    // anything added as a listener, which is the whole point of this class.
    _set(s) { this.readyState = s; this._fire('readystatechange'); }
    _fire(type, extra) {
      const ev = Object.assign({
        type, target: this, currentTarget: this, isTrusted: true,
        lengthComputable: false, loaded: 0, total: 0, bubbles: false, cancelable: false,
      }, extra || {});
      this.dispatchEvent(ev);
    }
  };

  // Minimal Headers/TextEncoder if missing.
  if (!globalThis.TextEncoder) {
    globalThis.TextEncoder = class { encode(s) { s = String(s); const a = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i) & 0xff; return a; } };
  }

  // --- base64 and the other globals every browser has ---------------------
  // `atob` missing is not a nicety: Cloudflare's challenge script decodes base64
  // on its first line and dies with a ReferenceError, and any page doing the same
  // breaks just as silently. These are cheap and their absence is both a
  // functional break and something a probe can list in one line.
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  if (!globalThis.atob) {
    globalThis.atob = function atob(input) {
      const s = String(input).replace(/[ \t\n\f\r]/g, '');
      const body = s.replace(/=+$/, '');
      if (body.length % 4 === 1 || /[^A-Za-z0-9+/]/.test(body)) {
        throw new (globalThis.DOMException || Error)("Failed to execute 'atob' on 'Window': The string to be decoded is not correctly encoded.", 'InvalidCharacterError');
      }
      let out = '', bits = 0, acc = 0;
      for (const ch of body) {
        acc = (acc << 6) | B64.indexOf(ch);
        bits += 6;
        if (bits >= 8) { bits -= 8; out += String.fromCharCode((acc >> bits) & 0xff); }
      }
      return out;
    };
  }
  if (!globalThis.btoa) {
    globalThis.btoa = function btoa(input) {
      const s = String(input);
      let out = '';
      for (let i = 0; i < s.length; i += 3) {
        const c0 = s.charCodeAt(i), c1 = s.charCodeAt(i + 1), c2 = s.charCodeAt(i + 2);
        if (c0 > 255 || c1 > 255 || c2 > 255) {
          throw new (globalThis.DOMException || Error)("Failed to execute 'btoa' on 'Window': The string to be encoded contains characters outside of the Latin1 range.", 'InvalidCharacterError');
        }
        const n = (c0 << 16) | ((c1 || 0) << 8) | (c2 || 0);
        out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63]
          + (isNaN(c1) ? '=' : B64[(n >> 6) & 63])
          + (isNaN(c2) ? '=' : B64[n & 63]);
      }
      return out;
    };
  }
  // A deep clone that covers what pages actually pass through it.
  if (!globalThis.structuredClone) {
    globalThis.structuredClone = function structuredClone(v) {
      const seen = new Map();
      const walk = (x) => {
        if (x === null || typeof x !== 'object') return x;
        if (seen.has(x)) return seen.get(x);
        if (x instanceof Date) return new Date(x.getTime());
        if (x instanceof RegExp) return new RegExp(x.source, x.flags);
        if (ArrayBuffer.isView(x)) return new x.constructor(x);
        if (x instanceof ArrayBuffer) return x.slice(0);
        if (x instanceof Map) { const m = new Map(); seen.set(x, m); for (const [k, val] of x) m.set(walk(k), walk(val)); return m; }
        if (x instanceof Set) { const st = new Set(); seen.set(x, st); for (const val of x) st.add(walk(val)); return st; }
        if (Array.isArray(x)) { const a = []; seen.set(x, a); for (const val of x) a.push(walk(val)); return a; }
        const o = {}; seen.set(x, o);
        for (const k of Object.keys(x)) o[k] = walk(x[k]);
        return o;
      };
      return walk(v);
    };
  }
  if (!globalThis.reportError) globalThis.reportError = function reportError(e) { try { console.error(e); } catch (x) {} };
  if (!globalThis.AbortController) {
    globalThis.AbortSignal = globalThis.AbortSignal || class AbortSignal {
      constructor() { this.aborted = false; this.reason = undefined; this.onabort = null; this._ls = []; }
      addEventListener(t, fn) { if (t === 'abort' && typeof fn === 'function') this._ls.push(fn); }
      removeEventListener(t, fn) { const i = this._ls.indexOf(fn); if (i >= 0) this._ls.splice(i, 1); }
      dispatchEvent() { return true; }
      throwIfAborted() { if (this.aborted) throw this.reason; }
      static abort(reason) { const s = new globalThis.AbortSignal(); s.aborted = true; s.reason = reason; return s; }
    };
    globalThis.AbortController = class AbortController {
      constructor() { this.signal = new globalThis.AbortSignal(); }
      abort(reason) {
        const s = this.signal;
        if (s.aborted) return;
        s.aborted = true;
        s.reason = reason === undefined ? new Error('signal is aborted without reason') : reason;
        const ev = { type: 'abort', target: s, currentTarget: s };
        try { if (typeof s.onabort === 'function') s.onabort(ev); } catch (e) {}
        for (const fn of s._ls.slice()) { try { fn(ev); } catch (e) {} }
      }
    };
  }

  // --- DOMException, MessageChannel, and the fetch classes ----------------
  // All present in every browser and all absent here, which breaks pages in the
  // quietest possible way: a widget that opens a `MessageChannel` to talk to its
  // embedder, or constructs a `Request`, simply stops — no error, no output.
  if (!globalThis.DOMException) {
    globalThis.DOMException = class DOMException extends Error {
      constructor(message, name) {
        super(message === undefined ? '' : String(message));
        this.name = name === undefined ? 'Error' : String(name);
      }
      get code() {
        const codes = { IndexSizeError: 1, HierarchyRequestError: 3, WrongDocumentError: 4,
          InvalidCharacterError: 5, NotFoundError: 8, NotSupportedError: 9, InvalidStateError: 11,
          SyntaxError: 12, InvalidModificationError: 13, NamespaceError: 14, SecurityError: 18,
          NetworkError: 19, AbortError: 20, TimeoutError: 23, DataCloneError: 25 };
        return codes[this.name] || 0;
      }
    };
  }

  if (!globalThis.MessagePort) {
    // A pair of ports, each delivering to the other. Messages arrive in a
    // microtask (never synchronously), and a port that has not been `start`ed
    // queues them — both of which real code depends on.
    globalThis.MessagePort = class MessagePort {
      constructor() {
        Object.defineProperty(this, '__pt', {
          value: { peer: null, started: false, queue: [], onmessage: null, listeners: [] },
          enumerable: false,
        });
      }
      get onmessage() { return this.__pt.onmessage; }
      set onmessage(fn) { this.__pt.onmessage = fn; this.start(); }
      addEventListener(type, fn) {
        if (type !== 'message' || typeof fn !== 'function') return;
        this.__pt.listeners.push(fn);
        this.start();
      }
      removeEventListener(type, fn) {
        const l = this.__pt.listeners, i = l.indexOf(fn);
        if (i >= 0) l.splice(i, 1);
      }
      dispatchEvent() { return true; }
      start() {
        const st = this.__pt;
        if (st.started) return;
        st.started = true;
        for (const ev of st.queue.splice(0)) this.__ptDeliver(ev);
      }
      close() { this.__pt.peer = null; }
      postMessage(data) {
        const peer = this.__pt.peer;
        if (!peer) return;
        const ev = { type: 'message', data, origin: '', lastEventId: '', source: null, ports: [], isTrusted: true, target: peer, currentTarget: peer };
        queueMicrotask(() => {
          const st = peer.__pt;
          if (!st.started) { st.queue.push(ev); return; }
          peer.__ptDeliver(ev);
        });
      }
      __ptDeliver(ev) {
        const st = this.__pt;
        try { if (typeof st.onmessage === 'function') st.onmessage.call(this, ev); } catch (e) {}
        for (const fn of st.listeners.slice()) { try { fn.call(this, ev); } catch (e) {} }
      }
    };
    globalThis.MessageChannel = class MessageChannel {
      constructor() {
        const a = new globalThis.MessagePort(), b = new globalThis.MessagePort();
        a.__pt.peer = b; b.__pt.peer = a;
        Object.defineProperty(this, 'port1', { value: a, enumerable: true });
        Object.defineProperty(this, 'port2', { value: b, enumerable: true });
      }
    };
  }

  if (!globalThis.Headers) {
    globalThis.Headers = class Headers {
      constructor(init) {
        Object.defineProperty(this, '__h', { value: new Map(), enumerable: false });
        if (init) {
          const put = (k, v) => this.append(k, v);
          if (typeof init.forEach === 'function' && !Array.isArray(init)) init.forEach((v, k) => put(k, v));
          else if (Array.isArray(init)) for (const [k, v] of init) put(k, v);
          else for (const k of Object.keys(init)) put(k, init[k]);
        }
      }
      append(k, v) {
        const key = String(k).toLowerCase(), cur = this.__h.get(key);
        this.__h.set(key, cur === undefined ? String(v) : cur + ', ' + String(v));
      }
      set(k, v) { this.__h.set(String(k).toLowerCase(), String(v)); }
      get(k) { const v = this.__h.get(String(k).toLowerCase()); return v === undefined ? null : v; }
      has(k) { return this.__h.has(String(k).toLowerCase()); }
      delete(k) { this.__h.delete(String(k).toLowerCase()); }
      forEach(fn, thisArg) { for (const [k, v] of this.__h) fn.call(thisArg, v, k, this); }
      keys() { return this.__h.keys(); }
      values() { return this.__h.values(); }
      entries() { return this.__h.entries(); }
      [Symbol.iterator]() { return this.__h.entries(); }
    };
  }
  if (!globalThis.Request) {
    globalThis.Request = class Request {
      constructor(input, init) {
        init = init || {};
        this.url = String(input && input.url !== undefined ? input.url : input);
        this.method = String(init.method || (input && input.method) || 'GET').toUpperCase();
        this.headers = new globalThis.Headers(init.headers || (input && input.headers));
        this.credentials = init.credentials || 'same-origin';
        this.mode = init.mode || 'cors';
        this.cache = init.cache || 'default';
        this.redirect = init.redirect || 'follow';
        this.referrer = init.referrer === undefined ? 'about:client' : String(init.referrer);
        this.signal = init.signal || null;
        Object.defineProperty(this, '__body', { value: init.body === undefined ? null : init.body, enumerable: false });
        this.bodyUsed = false;
      }
      clone() { return new globalThis.Request(this); }
      text() { this.bodyUsed = true; return Promise.resolve(this.__body == null ? '' : String(this.__body)); }
      json() { return this.text().then(JSON.parse); }
      arrayBuffer() { return this.text().then(t => new TextEncoder().encode(t).buffer); }
    };
  }
  if (!globalThis.Response) {
    globalThis.Response = class Response {
      constructor(body, init) {
        init = init || {};
        this.status = init.status === undefined ? 200 : (init.status | 0);
        this.statusText = init.statusText === undefined ? '' : String(init.statusText);
        this.headers = new globalThis.Headers(init.headers);
        this.ok = this.status >= 200 && this.status < 300;
        this.redirected = false;
        this.type = 'default';
        this.url = '';
        this.bodyUsed = false;
        Object.defineProperty(this, '__body', { value: body == null ? '' : body, enumerable: false });
      }
      static error() { const r = new globalThis.Response(null, { status: 0 }); r.type = 'error'; return r; }
      static json(data, init) { return new globalThis.Response(JSON.stringify(data), init); }
      clone() { return new globalThis.Response(this.__body, { status: this.status, statusText: this.statusText, headers: this.headers }); }
      text() { this.bodyUsed = true; return Promise.resolve(String(this.__body)); }
      json() { return this.text().then(JSON.parse); }
      arrayBuffer() { return this.text().then(t => new TextEncoder().encode(t).buffer); }
      blob() { return this.text().then(t => new Blob([t])); }
    };
  }

  // --- streams, storage, channels, files, CSS -----------------------------
  // The rest of what a page assumes exists. Each is small; each one's absence
  // stops code dead without a word.
  if (!globalThis.ReadableStream) {
    globalThis.ReadableStream = class ReadableStream {
      constructor(source, strategy) {
        const st = { chunks: [], closed: false, error: null, locked: false, source: source || {} };
        Object.defineProperty(this, '__pt', { value: st, enumerable: false });
        const controller = {
          enqueue: (c) => st.chunks.push(c),
          close: () => { st.closed = true; },
          error: (e) => { st.error = e; st.closed = true; },
          get desiredSize() { return 1; },
        };
        st.controller = controller;
        try { if (typeof st.source.start === 'function') st.source.start(controller); } catch (e) { st.error = e; }
      }
      get locked() { return this.__pt.locked; }
      getReader() {
        const st = this.__pt;
        if (st.locked) throw new TypeError('ReadableStream is locked');
        st.locked = true;
        return {
          read: () => {
            if (st.error) return Promise.reject(st.error);
            if (st.chunks.length) return Promise.resolve({ value: st.chunks.shift(), done: false });
            // Give the source a chance to produce more before reporting the end.
            const pull = st.source.pull;
            const more = typeof pull === 'function'
              ? Promise.resolve(pull.call(st.source, st.controller)) : Promise.resolve();
            return more.then(() => st.chunks.length
              ? { value: st.chunks.shift(), done: false }
              : { value: undefined, done: true });
          },
          releaseLock: () => { st.locked = false; },
          cancel: (r) => { st.closed = true; try { st.source.cancel && st.source.cancel(r); } catch (e) {} return Promise.resolve(); },
          get closed() { return Promise.resolve(); },
        };
      }
      cancel(r) { const st = this.__pt; st.closed = true; try { st.source.cancel && st.source.cancel(r); } catch (e) {} return Promise.resolve(); }
      tee() { return [this, this]; }
      // Not decoration: Cloudflare's challenge gates on
      // `ReadableStream.prototype.pipeTo === undefined` and calls the browser
      // unsupported if it is — one missing method and the challenge never starts.
      pipeTo(dest, opts) {
        const reader = this.getReader();
        const writer = dest && typeof dest.getWriter === 'function' ? dest.getWriter() : null;
        const pump = () => reader.read().then(({ value, done }) => {
          if (done) {
            reader.releaseLock();
            if (writer && !(opts && opts.preventClose)) { try { return writer.close(); } catch (e) {} }
            return undefined;
          }
          if (writer) { try { writer.write(value); } catch (e) {} }
          return pump();
        });
        return pump();
      }
      pipeThrough(pair, opts) {
        if (!pair || !pair.writable || !pair.readable) throw new TypeError('pipeThrough needs a { writable, readable }');
        this.pipeTo(pair.writable, opts);
        return pair.readable;
      }
      [Symbol.asyncIterator]() {
        const reader = this.getReader();
        return { next: () => reader.read(), return: () => { reader.releaseLock(); return Promise.resolve({ done: true }); } };
      }
      values() { return this[Symbol.asyncIterator](); }
    };
  }

  // `pipeTo` needs somewhere to pipe *to*, and the same probes that ask for it
  // ask whether these exist at all.
  if (!globalThis.WritableStream) {
    globalThis.WritableStream = class WritableStream {
      constructor(sink, strategy) {
        const st = { chunks: [], closed: false, locked: false, sink: sink || {} };
        Object.defineProperty(this, '__pt', { value: st, enumerable: false });
        const controller = { error: (e) => { st.error = e; }, get signal() { return undefined; } };
        st.controller = controller;
        try { if (typeof st.sink.start === 'function') st.sink.start(controller); } catch (e) { st.error = e; }
      }
      get locked() { return this.__pt.locked; }
      getWriter() {
        const st = this.__pt;
        if (st.locked) throw new TypeError('WritableStream is locked');
        st.locked = true;
        const call = (name, arg) => {
          const f = st.sink[name];
          try { return Promise.resolve(typeof f === 'function' ? f.call(st.sink, arg, st.controller) : undefined); }
          catch (e) { return Promise.reject(e); }
        };
        return {
          write: (c) => { st.chunks.push(c); return call('write', c); },
          close: () => { st.closed = true; return call('close'); },
          abort: (r) => { st.closed = true; return call('abort', r); },
          releaseLock: () => { st.locked = false; },
          get desiredSize() { return 1; },
          get closed() { return Promise.resolve(); },
          get ready() { return Promise.resolve(); },
        };
      }
      close() { this.__pt.closed = true; return Promise.resolve(); }
      abort(r) { this.__pt.closed = true; return Promise.resolve(r); }
    };
  }

  if (!globalThis.TransformStream) {
    globalThis.TransformStream = class TransformStream {
      constructor(transformer) {
        const t = transformer || {};
        let enqueue = null;
        const readable = new globalThis.ReadableStream({ start(c) { enqueue = (v) => c.enqueue(v); } });
        const controller = { enqueue: (v) => enqueue && enqueue(v), terminate() {}, error() {} };
        const writable = new globalThis.WritableStream({
          write(chunk) {
            if (typeof t.transform === 'function') return t.transform(chunk, controller);
            controller.enqueue(chunk);
            return undefined;
          },
          close() { if (typeof t.flush === 'function') return t.flush(controller); return undefined; },
        });
        Object.defineProperty(this, '__pt', { value: { readable, writable }, enumerable: false });
        try { if (typeof t.start === 'function') t.start(controller); } catch (e) {}
      }
      get readable() { return this.__pt.readable; }
      get writable() { return this.__pt.writable; }
    };
  }

  if (!globalThis.BroadcastChannel) {
    const __bcRooms = new Map();
    globalThis.BroadcastChannel = class BroadcastChannel {
      constructor(name) {
        this.name = String(name);
        this.onmessage = null; this.onmessageerror = null;
        Object.defineProperty(this, '__pt', { value: { closed: false, listeners: [] }, enumerable: false });
        if (!__bcRooms.has(this.name)) __bcRooms.set(this.name, new Set());
        __bcRooms.get(this.name).add(this);
      }
      postMessage(data) {
        if (this.__pt.closed) throw new (globalThis.DOMException || Error)('channel is closed', 'InvalidStateError');
        const peers = __bcRooms.get(this.name);
        if (!peers) return;
        for (const p of peers) {
          if (p === this || p.__pt.closed) continue;   // never echoes to the sender
          queueMicrotask(() => {
            const ev = { type: 'message', data, origin: (globalThis.location && location.origin) || '', lastEventId: '', source: null, ports: [], isTrusted: true, target: p, currentTarget: p };
            try { if (typeof p.onmessage === 'function') p.onmessage(ev); } catch (e) {}
            for (const fn of p.__pt.listeners.slice()) { try { fn.call(p, ev); } catch (e) {} }
          });
        }
      }
      addEventListener(t, fn) { if (t === 'message' && typeof fn === 'function') this.__pt.listeners.push(fn); }
      removeEventListener(t, fn) { const l = this.__pt.listeners, i = l.indexOf(fn); if (i >= 0) l.splice(i, 1); }
      dispatchEvent() { return true; }
      close() { this.__pt.closed = true; const r = __bcRooms.get(this.name); if (r) r.delete(this); }
    };
  }

  if (!globalThis.CSS) {
    globalThis.CSS = {
      escape: (s) => String(s).replace(/[^a-zA-Z0-9_\u00a0-\uffff-]/g, (c) => '\\' + c),
      // Answering `true` to everything would be its own giveaway; a real engine
      // rejects nonsense. This accepts a well-formed declaration and no more.
      supports: (a, b) => {
        if (b !== undefined) return /^[-a-zA-Z]+$/.test(String(a)) && String(b).length > 0;
        return /^\s*[-a-zA-Z]+\s*:\s*[^;]+\s*$/.test(String(a));
      },
    };
  }

  // Minimal but genuinely working IndexedDB: pages use it to store and to probe
  // for storage at all, and `undefined` is the loudest possible answer.
  if (!globalThis.indexedDB) {
    const __idbData = new Map();   // dbName -> { version, stores: Map<name, Map> }
    const req = (run) => {
      const r = { readyState: 'pending', result: undefined, error: null,
        onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null,
        addEventListener(t, fn) { this['on' + t] = fn; }, removeEventListener() {}, dispatchEvent() { return true; } };
      queueMicrotask(() => {
        try {
          run(r);
          r.readyState = 'done';
          const ev = { type: 'success', target: r, currentTarget: r };
          if (typeof r.onsuccess === 'function') r.onsuccess(ev);
        } catch (e) {
          r.error = e; r.readyState = 'done';
          const ev = { type: 'error', target: r, currentTarget: r };
          if (typeof r.onerror === 'function') r.onerror(ev);
        }
      });
      return r;
    };
    const makeStore = (map, name) => ({
      name,
      put(v, k) { return req((r) => { map.set(String(k === undefined ? (v && v.id) : k), v); r.result = k; }); },
      add(v, k) { return this.put(v, k); },
      get(k) { return req((r) => { r.result = map.get(String(k)); }); },
      delete(k) { return req((r) => { map.delete(String(k)); }); },
      clear() { return req(() => map.clear()); },
      count() { return req((r) => { r.result = map.size; }); },
      getAll() { return req((r) => { r.result = [...map.values()]; }); },
      getAllKeys() { return req((r) => { r.result = [...map.keys()]; }); },
      createIndex() { return { name: 'idx' }; },
      deleteIndex() {},
      index() { return { get: (k) => req((r) => { r.result = map.get(String(k)); }) }; },
    });
    globalThis.indexedDB = {
      open(name, version) {
        const key = String(name);
        const fresh = !__idbData.has(key);
        if (fresh) __idbData.set(key, { version: 0, stores: new Map() });
        const entry = __idbData.get(key);
        const wanted = version === undefined ? Math.max(1, entry.version) : (version | 0);
        const db = {
          name: key,
          get version() { return entry.version; },
          objectStoreNames: { contains: (n) => entry.stores.has(String(n)), get length() { return entry.stores.size; }, item: (i) => [...entry.stores.keys()][i] || null },
          createObjectStore(n) { const m = new Map(); entry.stores.set(String(n), m); return makeStore(m, String(n)); },
          deleteObjectStore(n) { entry.stores.delete(String(n)); },
          transaction(names) {
            const tx = { objectStore: (n) => makeStore(entry.stores.get(String(n)) || new Map(), String(n)),
              abort() {}, commit() {}, oncomplete: null, onerror: null, onabort: null,
              addEventListener(t, fn) { this['on' + t] = fn; }, removeEventListener() {} };
            queueMicrotask(() => { if (typeof tx.oncomplete === 'function') tx.oncomplete({ type: 'complete', target: tx }); });
            return tx;
          },
          close() {}, onerror: null, onclose: null, onversionchange: null,
          addEventListener() {}, removeEventListener() {},
        };
        const r = { readyState: 'pending', result: undefined, error: null,
          onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null,
          addEventListener(t, fn) { this['on' + t] = fn; }, removeEventListener() {}, dispatchEvent() { return true; } };
        queueMicrotask(() => {
          r.result = db;
          r.readyState = 'done';
          if (wanted > entry.version) {
            const old = entry.version;
            entry.version = wanted;
            if (typeof r.onupgradeneeded === 'function') {
              r.onupgradeneeded({ type: 'upgradeneeded', target: r, oldVersion: old, newVersion: wanted, currentTarget: r });
            }
          }
          if (typeof r.onsuccess === 'function') r.onsuccess({ type: 'success', target: r, currentTarget: r });
        });
        return r;
      },
      deleteDatabase(name) { return req(() => { __idbData.delete(String(name)); }); },
      databases() { return Promise.resolve([...__idbData.keys()].map((n) => ({ name: n, version: __idbData.get(n).version }))); },
      cmp(a, b) { return a < b ? -1 : a > b ? 1 : 0; },
    };
  }

  // --- WebSocket ----------------------------------------------------------
  // Same shape as fetch above: JS owns the object and its state machine, Rust
  // owns the socket. Operations pile onto a queue the event loop drains
  // (`__pt_drainWsQueue`), and everything the socket produces comes back in as
  // `__pt_ws{Open,Message,Close,Error}`. See docs/websockets.md for why the
  // connection itself cannot live here (no I/O in the isolate) nor in a separate
  // client (it would present a second TLS fingerprint).
  //
  // Every field lives in a WeakMap rather than on the instance: WebIDL attributes
  // are accessors on the prototype, so a real socket has *no* own properties and
  // `Object.keys(ws)` is `[]`. Storing state on `this` would have been the same
  // kind of tell as the object itself missing.
  let wsid = 1;
  const wsOps = [];
  const wsLive = new Map();       // id -> socket
  const wsState = new WeakMap();  // socket -> internals

  const wsFire = (sock, type, evt) => {
    const st = wsState.get(sock); if (!st) return;
    evt = Object.assign({
      target: sock, currentTarget: sock, srcElement: sock, isTrusted: true,
      eventPhase: 2, bubbles: false, cancelable: false,
      timeStamp: globalThis.performance ? performance.now() : 0,
    }, evt);
    const on = st['on' + type];
    try { if (typeof on === 'function') on.call(sock, evt); } catch (e) {}
    for (const fn of (st.listeners.get(type) || []).slice()) {
      try { fn.call(sock, evt); } catch (e) {}
    }
  };

  globalThis.__pt_drainWsQueue = () => wsOps.splice(0);
  globalThis.__pt_wsOpen = (id, protocol) => {
    const sock = wsLive.get(id); if (!sock) return;
    const st = wsState.get(sock);
    st.readyState = 1; st.protocol = String(protocol || '');
    wsFire(sock, 'open', { type: 'open' });
  };
  globalThis.__pt_wsMessage = (id, data, isBinary) => {
    const sock = wsLive.get(id); if (!sock) return;
    const st = wsState.get(sock); if (st.readyState !== 1) return;
    let payload = data;
    if (isBinary) {
      const bytes = new Uint8Array(data);
      payload = st.binaryType === 'arraybuffer' ? bytes.buffer : new Blob([bytes]);
    }
    wsFire(sock, 'message', { type: 'message', data: payload, origin: st.origin, lastEventId: '', source: null, ports: [] });
  };
  globalThis.__pt_wsClose = (id, code, reason, clean) => {
    const sock = wsLive.get(id); if (!sock) return;
    wsLive.delete(id);
    wsState.get(sock).readyState = 3;
    wsFire(sock, 'close', { type: 'close', code: code | 0, reason: String(reason || ''), wasClean: !!clean });
  };
  globalThis.__pt_wsError = (id, msg) => {
    const sock = wsLive.get(id); if (!sock) return;
    wsLive.delete(id);
    wsState.get(sock).readyState = 3;
    wsFire(sock, 'error', { type: 'error', message: String(msg || '') });
    // A failed connection is always paired with a close event, code 1006.
    wsFire(sock, 'close', { type: 'close', code: 1006, reason: '', wasClean: false });
  };

  globalThis.WebSocket = class WebSocket {
    constructor(url, protocols) {
      if (arguments.length < 1) throw new TypeError("Failed to construct 'WebSocket': 1 argument required, but only 0 present.");
      // ws:/wss: only. http(s) is upgraded as the URL parser does; anything else
      // is a SyntaxError, exactly as in a browser.
      const base = globalThis.location ? String(location.href) : 'https://localhost/';
      let abs;
      try { abs = new globalThis.URL(String(url), base).href; } catch (e) { abs = String(url); }
      const scheme = String((/^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(abs) || [])[1] || '').toLowerCase();
      if (scheme === 'http') abs = 'ws' + abs.slice(4);
      else if (scheme === 'https') abs = 'wss' + abs.slice(5);
      else if (scheme !== 'ws' && scheme !== 'wss') {
        throw new SyntaxError("Failed to construct 'WebSocket': The URL's scheme must be either 'ws' or 'wss'. '" + scheme + ":' is not allowed.");
      }
      const list = protocols == null ? [] : (Array.isArray(protocols) ? protocols.map(String) : [String(protocols)]);
      const id = wsid++;
      wsState.set(this, {
        id, url: abs, protocol: '', extensions: '', binaryType: 'blob',
        bufferedAmount: 0, readyState: 0, listeners: new Map(),
        origin: abs.replace(/^ws/, 'http').replace(/^([a-z]+:\/\/[^/]*).*$/, '$1'),
        onopen: null, onmessage: null, onclose: null, onerror: null,
      });
      wsLive.set(id, this);
      wsOps.push({ op: 'open', id, url: abs, protocols: list });
    }
    send(data) {
      const st = wsState.get(this);
      if (st.readyState === 0) {
        const msg = "Failed to execute 'send' on 'WebSocket': Still in CONNECTING state.";
        throw (typeof DOMException === 'function' ? new DOMException(msg, 'InvalidStateError')
          : Object.assign(new Error(msg), { name: 'InvalidStateError' }));
      }
      if (st.readyState !== 1) return;                       // closing/closed: dropped
      if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
        const v = data instanceof ArrayBuffer ? new Uint8Array(data)
          : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
        wsOps.push({ op: 'send', id: st.id, bytes: Array.from(v) });
      } else {
        wsOps.push({ op: 'send', id: st.id, data: String(data) });
      }
    }
    close(code, reason) {
      const st = wsState.get(this);
      if (st.readyState === 2 || st.readyState === 3) return;
      st.readyState = 2;
      wsOps.push({ op: 'close', id: st.id, code: code == null ? 1000 : (code | 0), reason: reason == null ? '' : String(reason) });
    }
    addEventListener(type, fn) {
      if (typeof fn !== 'function') return;
      const st = wsState.get(this), k = String(type);
      if (!st.listeners.has(k)) st.listeners.set(k, []);
      st.listeners.get(k).push(fn);
    }
    removeEventListener(type, fn) {
      const l = wsState.get(this).listeners.get(String(type)); if (!l) return;
      const i = l.indexOf(fn); if (i >= 0) l.splice(i, 1);
    }
    dispatchEvent(evt) { wsFire(this, evt && evt.type, evt); return true; }
  };
  // WebIDL attributes: accessors on the prototype (enumerable there, absent from
  // the instance), so `Object.keys(ws)` is `[]` like a real socket's.
  for (const name of ['url', 'protocol', 'extensions', 'readyState', 'bufferedAmount']) {
    Object.defineProperty(globalThis.WebSocket.prototype, name, {
      get: function () { const st = wsState.get(this); return st ? st[name] : undefined; },
      enumerable: true, configurable: true,
    });
  }
  for (const name of ['binaryType', 'onopen', 'onmessage', 'onclose', 'onerror']) {
    Object.defineProperty(globalThis.WebSocket.prototype, name, {
      get: function () { const st = wsState.get(this); return st ? st[name] : undefined; },
      set: function (v) { const st = wsState.get(this); if (st) st[name] = v; },
      enumerable: true, configurable: true,
    });
  }
  for (const [k, v] of [['CONNECTING', 0], ['OPEN', 1], ['CLOSING', 2], ['CLOSED', 3]]) {
    Object.defineProperty(globalThis.WebSocket, k, { value: v, enumerable: true });
    Object.defineProperty(globalThis.WebSocket.prototype, k, { value: v, enumerable: true });
  }

})();"#;

/// Deterministic canvas / WebGL / audio fingerprints + plugins + permissions +
/// native-function masking. `__WEBGL_VENDOR__`/`__WEBGL_RENDERER__` are the only
/// substitutions; everything else is static. See [`fingerprint_script`].
const FINGERPRINT_TEMPLATE: &str = r#"(() => {
  const WEBGL_VENDOR = __WEBGL_VENDOR__;
  const WEBGL_RENDERER = __WEBGL_RENDERER__;

  // --- native-function masking ------------------------------------------
  // Patch Function.prototype.toString ITSELF (via a Proxy apply trap) so that
  // EVERY route — fn.toString(), Function.prototype.toString.call(fn),
  // Reflect.apply(...) — reports `function name() { [native code] }` for the
  // functions we register. This closes the classic
  // `Function.prototype.toString.call(patchedFn)` bypass that a per-function
  // `.toString` override misses. The proxy registers itself, so
  // `Function.prototype.toString.toString()` reads native too, and `.name`/
  // `.length` are forwarded from the original (both preserved).
  const __ptNative = new WeakSet();
  const __ptToStr = new Proxy(Function.prototype.toString, {
    apply(target, thisArg, args) {
      if (__ptNative.has(thisArg)) {
        return 'function ' + ((thisArg && thisArg.name) || '') + '() { [native code] }';
      }
      return Reflect.apply(target, thisArg, args);
    },
  });
  try {
    Object.defineProperty(Function.prototype, 'toString', {
      value: __ptToStr,
      configurable: true,
      writable: true,
    });
  } catch (e) {}
  __ptNative.add(__ptToStr);

  // Register a function as native, optionally renaming it. No longer sets an own
  // `toString` (the global patch above handles every call route).
  // Отдаём наружу под __pt-именем (фильтр интроспекции его прячет): поверхность
  // из WEB_SURFACE_TEMPLATE помечает свои функции нативными через него.
  globalThis.__pt_native = (fn) => { if (typeof fn === 'function') __ptNative.add(fn); return fn; };

  const mask = (fn, name) => {
    try {
      if (name) Object.defineProperty(fn, 'name', { value: name, configurable: true });
    } catch (e) {}
    if (typeof fn === 'function') __ptNative.add(fn);
    return fn;
  };

  // Mark every own function/accessor on a prototype as native — real DOM and
  // Web-API methods all report `[native code]`, so ours must too.
  const maskProto = (proto) => {
    if (!proto) return proto;
    for (const k of Object.getOwnPropertyNames(proto)) {
      try {
        const d = Object.getOwnPropertyDescriptor(proto, k);
        if (!d) continue;
        if (typeof d.value === 'function') __ptNative.add(d.value);
        if (typeof d.get === 'function') __ptNative.add(d.get);
        if (typeof d.set === 'function') __ptNative.add(d.set);
      } catch (e) {}
    }
    return proto;
  };

  const noop = () => {};

  // Per-session seed: gives canvas/audio a stable-within-session but
  // varies-across-sessions fingerprint, like a real device (not a fixed value
  // that could be blacklisted once and flag every instance at once).
  const SEED = (Math.floor(Math.random() * 0x7fffffff)) >>> 0;
  const seededByte = (i) => ((i * 1103515245 + 12345 + SEED) >>> 0) & 0xff;

  // Context constructor globals so `x instanceof WebGLRenderingContext` etc.
  // (which fingerprinters gate on) return true; our contexts get these protos.
  globalThis.WebGLRenderingContext = globalThis.WebGLRenderingContext || mask(class WebGLRenderingContext {}, 'WebGLRenderingContext');
  globalThis.WebGL2RenderingContext = globalThis.WebGL2RenderingContext || mask(class WebGL2RenderingContext {}, 'WebGL2RenderingContext');
  globalThis.CanvasRenderingContext2D = globalThis.CanvasRenderingContext2D || mask(class CanvasRenderingContext2D {}, 'CanvasRenderingContext2D');
  globalThis.HTMLCanvasElement = globalThis.HTMLCanvasElement || globalThis.Element;
  // The opaque GL object types. Every browser exposes them, and the handles we
  // hand back get these prototypes so `tex instanceof WebGLTexture` holds.
  for (const n of ['WebGLShader','WebGLProgram','WebGLBuffer','WebGLTexture','WebGLFramebuffer',
    'WebGLRenderbuffer','WebGLVertexArrayObject','WebGLUniformLocation','WebGLActiveInfo']) {
    // Not constructible, like the real interfaces — only the context hands them out.
    if (!globalThis[n]) globalThis[n] = mask(class { constructor() { throw new TypeError('Illegal constructor'); } }, n);
  }

  // --- Canvas 2D --------------------------------------------------------
  // A fixed, plausible PNG payload: consistent hash => looks like one device.
  const CANVAS_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAASwAAAAyCAYAAAAZ' +
    'UZThAAAGdElEQVR4nO3dz2sTQRTA8W+Spk1TQtOa1B9FRUEQ8SB48OBB8OBB8OBB8OBB8OBB8ODBg' +
    'wcPgncvXrx48eLFgwcPggcRBEEEQdQqiLZq09TUJk2TZpMdD5Nkk2yyu9nZ3dnk+8Fjs7Mzs+/N7' +
    'OzM7MJEBEREREREREREREREREREREREREREREREREREREREREREREREREREREZE/AZUqlQGVAZUBlQ' +
    'GVAZUBlQGVAZUBlQGVAZUBlQGVAZUBlQPUb+AXcBu4Dj4EnwFPgGfAceAG8BF4Br4E3wFvgHfAe+A';
  // Canvas fingerprinting hashes `toDataURL()` / `getImageData()`, and the
  // standard probe is differential: draw something, hash it, compare. Returning a
  // fixed value (as this did) makes an empty canvas and an elaborate drawing hash
  // identically — caught instantly. So the context keeps a real pixel buffer:
  // solid fills are rendered exactly, and operations we cannot rasterise (text,
  // paths, images) stamp a deterministic pattern derived from the operation log
  // plus the per-session seed. Different drawings therefore differ, an identical
  // drawing is stable, and results vary across sessions the way device text
  // rendering does.
  const parseColor = (c) => {
    c = String(c == null ? '#000000' : c).trim().toLowerCase();
    const named = { black: [0,0,0,255], white: [255,255,255,255], red: [255,0,0,255],
      lime: [0,255,0,255], green: [0,128,0,255], blue: [0,0,255,255],
      yellow: [255,255,0,255], transparent: [0,0,0,0] };
    if (named[c]) return named[c].slice();
    let m = /^#([0-9a-f]{3})$/.exec(c);
    if (m) return [parseInt(m[1][0] + m[1][0], 16), parseInt(m[1][1] + m[1][1], 16), parseInt(m[1][2] + m[1][2], 16), 255];
    m = /^#([0-9a-f]{6})$/.exec(c);
    if (m) return [parseInt(m[1].slice(0,2), 16), parseInt(m[1].slice(2,4), 16), parseInt(m[1].slice(4,6), 16), 255];
    m = /^rgba?\(([^)]+)\)$/.exec(c);
    if (m) {
      const p = m[1].split(',').map((x) => parseFloat(x));
      return [p[0] | 0, p[1] | 0, p[2] | 0, p.length > 3 ? Math.round(Math.max(0, Math.min(1, p[3])) * 255) : 255];
    }
    return [0, 0, 0, 255];
  };

  // With the optional `render` build, the `__pt_canvas*` natives back the surface
  // with a real tiny-skia rasterizer: fills and (crucially) text are genuine
  // glyph pixels, so canvas fingerprints look like a real device instead of a
  // synthesized pattern. Same method shape as the JS surface below, plus native
  // text/put. Paths and images we still cannot rasterize keep the deterministic
  // stamp (fill) so different drawings still differ and repeat exactly.
  const NATIVE_CANVAS = typeof __pt_canvasCreate === 'function';
  // Only take the native GL path when a real GL context can actually be created
  // (the `webgl` build *and* Mesa/EGL present); otherwise the synthesis fallback.
  const NATIVE_GL = typeof __pt_glAvailable === 'function' && __pt_glAvailable();
  const makeNativeSurface = (canvas) => {
    const id = (globalThis.__ptCanvasSeq = (globalThis.__ptCanvasSeq || 0) + 1);
    let W = -1, H = -1;
    let ops = 2166136261 >>> 0;                 // FNV-1a, drives the path/image stamp
    const sync = () => {
      const w = Math.max(0, canvas.width | 0), h = Math.max(0, canvas.height | 0);
      if (w !== W || h !== H) { W = w; H = h; __pt_canvasCreate(id, w, h); } // create resets
    };
    sync();
    return {
      native: true,
      note(s) {
        s = String(s);
        for (let i = 0; i < s.length; i++) { ops ^= s.charCodeAt(i); ops = Math.imul(ops, 16777619) >>> 0; }
      },
      solid(x, y, w, h, rgba) {
        sync();
        if ((rgba[3] | 0) === 0) __pt_canvasClearRect(id, x, y, w, h);
        else __pt_canvasFillRect(id, x, y, w, h, rgba[0], rgba[1], rgba[2], rgba[3]);
      },
      // Real glyphs. `y` is the alphabetic baseline, matching canvas semantics.
      text(t, x, y, size, rgba) { sync(); __pt_canvasFillText(id, String(t), x, y, size, rgba[0], rgba[1], rgba[2], rgba[3]); },
      width(t, size) { return __pt_canvasMeasureText(String(t), size); },
      // Real vector paths: JS tessellates curves/arcs to a move/line/close verb
      // stream, tiny-skia fills or strokes it.
      fillPath(verbs, evenOdd, rgba) { sync(); __pt_canvasFillPath(id, new Float32Array(verbs), evenOdd ? 1 : 0, rgba[0], rgba[1], rgba[2], rgba[3]); },
      fillPathGradient(verbs, evenOdd, grad) { sync(); __pt_canvasFillPathGradient(id, new Float32Array(verbs), evenOdd ? 1 : 0, new Float32Array(grad)); },
      strokePath(verbs, lw, rgba) { sync(); __pt_canvasStrokePath(id, new Float32Array(verbs), lw, rgba[0], rgba[1], rgba[2], rgba[3]); },
      // Images we still can't rasterize: a deterministic semi-transparent fill
      // keyed by the op-log, so the drawing still influences the pixels stably.
      stamp(x, y, w, h) {
        sync();
        let v = (ops ^ SEED) >>> 0;
        v = Math.imul(v ^ (v >>> 15), 2246822519) >>> 0; v = (v ^ (v >>> 13)) >>> 0;
        __pt_canvasFillRect(id, x, y, w, h, v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, 48);
      },
      put(data, x, y, w, h) { sync(); __pt_canvasPutImageData(id, x, y, w, h, data); },
      read(x, y, w, h, dst) {
        sync();
        const b = __pt_canvasGetImageData(id, x | 0, y | 0, w | 0, h | 0);
        dst.set(b.subarray(0, Math.min(b.length, dst.length)));
        return dst;
      },
      pixels() { sync(); return { w: W, h: H, data: __pt_canvasGetImageData(id, 0, 0, Math.max(0, W), Math.max(0, H)) }; },
    };
  };

  // A canvas-backed pixel surface, shared by the 2D and WebGL contexts: both have
  // to answer readback probes with something that actually reflects the drawing.
  const makeSurface = (canvas) => {
    if (NATIVE_CANVAS) return makeNativeSurface(canvas);
    let W = -1, H = -1, px = new Uint8ClampedArray(0);
    let ops = 2166136261 >>> 0;                 // FNV-1a over every draw call
    const sync = () => {
      const w = Math.max(0, canvas.width | 0), h = Math.max(0, canvas.height | 0);
      if (w !== W || h !== H) { W = w; H = h; px = new Uint8ClampedArray(w * h * 4); }
    };
    const clip = (x, y, w, h) => {
      x = Math.round(+x || 0); y = Math.round(+y || 0);
      w = Math.round(+w || 0); h = Math.round(+h || 0);
      if (w < 0) { x += w; w = -w; }
      if (h < 0) { y += h; h = -h; }
      return [Math.max(0, x), Math.max(0, y), Math.min(W, x + w), Math.min(H, y + h)];
    };
    return {
      note(s) {
        s = String(s);
        for (let i = 0; i < s.length; i++) { ops ^= s.charCodeAt(i); ops = Math.imul(ops, 16777619) >>> 0; }
      },
      // Exact rendering, for the operations we can honour precisely.
      solid(x, y, w, h, rgba) {
        sync(); const [x0, y0, x1, y1] = clip(x, y, w, h);
        for (let yy = y0; yy < y1; yy++) for (let xx = x0; xx < x1; xx++) {
          const i = (yy * W + xx) * 4;
          px[i] = rgba[0]; px[i + 1] = rgba[1]; px[i + 2] = rgba[2]; px[i + 3] = rgba[3];
        }
      },
      // Everything we cannot rasterise: a deterministic pattern keyed by the
      // operation log and the session seed, so different input gives different
      // pixels and identical input repeats exactly.
      stamp(x, y, w, h) {
        sync(); const [x0, y0, x1, y1] = clip(x, y, w, h);
        for (let yy = y0; yy < y1; yy++) for (let xx = x0; xx < x1; xx++) {
          let v = (ops ^ Math.imul(xx + 1, 2654435761) ^ Math.imul(yy + 1, 40503) ^ SEED) >>> 0;
          v = Math.imul(v ^ (v >>> 15), 2246822519) >>> 0;
          v = (v ^ (v >>> 13)) >>> 0;
          const i = (yy * W + xx) * 4;
          px[i] = v & 0xff; px[i + 1] = (v >>> 8) & 0xff; px[i + 2] = (v >>> 16) & 0xff;
          px[i + 3] = 255 - ((v >>> 24) & 0x3f);
        }
      },
      read(x, y, w, h, dst) {
        sync();
        for (let yy = 0; yy < h; yy++) for (let xx = 0; xx < w; xx++) {
          const sx = (x | 0) + xx, sy = (y | 0) + yy, di = (yy * w + xx) * 4;
          if (sx < 0 || sy < 0 || sx >= W || sy >= H) continue;
          const si = (sy * W + sx) * 4;
          dst[di] = px[si]; dst[di + 1] = px[si + 1]; dst[di + 2] = px[si + 2]; dst[di + 3] = px[si + 3];
        }
        return dst;
      },
      pixels() { sync(); return { w: W, h: H, data: px }; },
    };
  };

  const make2DContext = (canvas) => {
    const S = makeSurface(canvas);
    const note = S.note, solid = S.solid, stamp = S.stamp;
    let bx0 = 0, by0 = 0, bx1 = 0, by1 = 0;     // current path bounding box

    const pathPoint = (x, y) => {
      x = +x || 0; y = +y || 0;
      if (bx1 <= bx0 && by1 <= by0) { bx0 = x; by0 = y; bx1 = x; by1 = y; }
      bx0 = Math.min(bx0, x); by0 = Math.min(by0, y); bx1 = Math.max(bx1, x); by1 = Math.max(by1, y);
    };
    const paintPath = () => { stamp(bx0 - 1, by0 - 1, (bx1 - bx0) + 2, (by1 - by0) + 2); };

    // Path verb stream (0,x,y=move · 1,x,y=line · 4=close) for the native
    // rasterizer: curves and arcs are tessellated to line segments here so the
    // Rust side stays a trivial, robust decoder. Built only when the surface is
    // native; the JS fallback keeps using the bounding-box stamp above.
    let verbs = [], cx = 0, cy = 0, sub = false;
    const moveV = (x, y) => { x = +x || 0; y = +y || 0; verbs.push(0, x, y); cx = x; cy = y; sub = true; };
    const lineV = (x, y) => { x = +x || 0; y = +y || 0; if (!sub) return moveV(x, y); verbs.push(1, x, y); cx = x; cy = y; };
    const closeV = () => { if (sub) { verbs.push(4); sub = false; } };
    const sampleN = (fn) => { const N = 18; for (let k = 1; k <= N; k++) fn(k / N); };
    const cubicV = (c1x, c1y, c2x, c2y, x, y) => {
      const x0 = cx, y0 = cy;
      sampleN((t) => { const u = 1 - t;
        const bx = u*u*u*x0 + 3*u*u*t*c1x + 3*u*t*t*c2x + t*t*t*x;
        const by = u*u*u*y0 + 3*u*u*t*c1y + 3*u*t*t*c2y + t*t*t*y;
        lineV(bx, by); });
    };
    const quadV = (cpx, cpy, x, y) => {
      const x0 = cx, y0 = cy;
      sampleN((t) => { const u = 1 - t;
        lineV(u*u*x0 + 2*u*t*cpx + t*t*x, u*u*y0 + 2*u*t*cpy + t*t*y); });
    };
    const arcV = (x, y, r, a0, a1, ccw) => {
      x = +x || 0; y = +y || 0; r = +r || 0;
      let sweep = a1 - a0;
      if (!ccw && sweep < 0) sweep = (sweep % (2*Math.PI)) + 2*Math.PI;
      if (ccw && sweep > 0) sweep = (sweep % (2*Math.PI)) - 2*Math.PI;
      const steps = Math.max(2, Math.ceil(Math.abs(sweep) / (Math.PI / 16)));
      for (let k = 0; k <= steps; k++) {
        const a = a0 + sweep * (k / steps);
        const px = x + r * Math.cos(a), py = y + r * Math.sin(a);
        if (k === 0 && !sub) moveV(px, py); else lineV(px, py);
      }
    };

    const fontSize = (f) => { const m = /(\d+(?:\.\d+)?)px/.exec(String(f)); return m ? parseFloat(m[1]) : 10; };
    const drawText = function (t, x, y, rgba) {
      const size = fontSize(this.font);
      const w = this.measureText(t).width;
      let ox = +x || 0, oy = +y || 0;
      const a = this.textAlign;                 // shift origin for align/baseline
      if (a === 'center') ox -= w / 2; else if (a === 'right' || a === 'end') ox -= w;
      const b = this.textBaseline;
      if (b === 'top' || b === 'hanging') oy += size * 0.8;
      else if (b === 'middle') oy += size * 0.3;
      else if (b === 'bottom' || b === 'ideographic') oy -= size * 0.2;
      if (S.native) S.text(t, ox, oy, size, rgba);
      else stamp(ox, oy - size, w, size * 1.3);
    };

    // Gradient fillStyle/strokeStyle: real objects carrying coords + stops, flattened
    // to the [type,x0,y0,x1,y1,r0,r1,n,(pos,r,g,b,a)…] descriptor the native decoder
    // reads. A gradient object is detected by its `__ptGrad` marker.
    const makeGradient = (type, coords) => ({
      __ptGrad: { type, coords, stops: [] },
      addColorStop(pos, color) { note('stop|' + [pos, color]); this.__ptGrad.stops.push([+pos || 0, parseColor(color)]); },
    });
    const encodeGrad = (g) => {
      const a = [g.type, g.coords[0], g.coords[1], g.coords[2], g.coords[3], g.coords[4], g.coords[5], g.stops.length];
      for (let k = 0; k < g.stops.length; k++) { const s = g.stops[k]; a.push(s[0], s[1][0], s[1][1], s[1][2], s[1][3]); }
      return a;
    };
    const rectVerbs = (x, y, w, h) => { const X = +x || 0, Y = +y || 0, W2 = +w || 0, H2 = +h || 0; return [0, X, Y, 1, X + W2, Y, 1, X + W2, Y + H2, 1, X, Y + H2, 4]; };

    return maskProto(Object.assign(Object.create(globalThis.CanvasRenderingContext2D.prototype), {
      canvas,
      fillStyle: '#000000', strokeStyle: '#000000', font: '10px sans-serif',
      globalAlpha: 1.0, lineWidth: 1.0, textBaseline: 'alphabetic', textAlign: 'start',
      shadowColor: 'rgba(0, 0, 0, 0)', shadowBlur: 0, globalCompositeOperation: 'source-over',

      fillRect(x, y, w, h) {
        note('fillRect|' + [x, y, w, h, this.fillStyle]);
        const fs = this.fillStyle;
        if (S.native && fs && fs.__ptGrad) S.fillPathGradient(rectVerbs(x, y, w, h), false, encodeGrad(fs.__ptGrad));
        else solid(x, y, w, h, parseColor(fs));
      },
      clearRect(x, y, w, h) { note('clearRect|' + [x, y, w, h]); solid(x, y, w, h, [0, 0, 0, 0]); },
      strokeRect(x, y, w, h) {
        note('strokeRect|' + [x, y, w, h, this.strokeStyle, this.lineWidth]);
        const X = +x || 0, Y = +y || 0, W2 = +w || 0, H2 = +h || 0;
        if (S.native) {
          S.strokePath([0, X, Y, 1, X + W2, Y, 1, X + W2, Y + H2, 1, X, Y + H2, 4],
            Math.max(0, +this.lineWidth || 1), parseColor(this.strokeStyle));
          return;
        }
        const lw = Math.max(1, this.lineWidth | 0);
        stamp(X, Y, W2, lw); stamp(X, Y + H2 - lw, W2, lw);
        stamp(X, Y, lw, H2); stamp(X + W2 - lw, Y, lw, H2);
      },
      fillText(t, x, y) { note('fillText|' + [t, x, y, this.font, this.fillStyle, this.textAlign, this.textBaseline]); drawText.call(this, t, +x || 0, +y || 0, parseColor(this.fillStyle)); },
      strokeText(t, x, y) { note('strokeText|' + [t, x, y, this.font, this.strokeStyle]); drawText.call(this, t, +x || 0, +y || 0, parseColor(this.strokeStyle)); },

      beginPath() { note('beginPath'); bx0 = by0 = bx1 = by1 = 0; verbs = []; sub = false; },
      closePath() { note('closePath'); closeV(); },
      moveTo(x, y) { note('moveTo|' + [x, y]); pathPoint(x, y); moveV(x, y); },
      lineTo(x, y) { note('lineTo|' + [x, y]); pathPoint(x, y); lineV(x, y); },
      rect(x, y, w, h) {
        note('rect|' + [x, y, w, h]);
        const X = +x || 0, Y = +y || 0, W2 = +w || 0, H2 = +h || 0;
        pathPoint(X, Y); pathPoint(X + W2, Y + H2);
        moveV(X, Y); lineV(X + W2, Y); lineV(X + W2, Y + H2); lineV(X, Y + H2); closeV();
      },
      arc(x, y, r, a0, a1, ccw) {
        note('arc|' + [x, y, r, a0, a1, ccw]);
        pathPoint((+x || 0) - (+r || 0), (+y || 0) - (+r || 0)); pathPoint((+x || 0) + (+r || 0), (+y || 0) + (+r || 0));
        arcV(x, y, r, +a0 || 0, a1 === undefined ? 2 * Math.PI : +a1, !!ccw);
      },
      arcTo(x1, y1, x2, y2) { note('arcTo|' + [x1, y1, x2, y2]); pathPoint(x1, y1); pathPoint(x2, y2); lineV(x1, y1); lineV(x2, y2); },
      ellipse(x, y, rx, ry, rot, a0, a1, ccw) {
        note('ellipse|' + [x, y, rx, ry]);
        pathPoint((+x || 0) - (+rx || 0), (+y || 0) - (+ry || 0)); pathPoint((+x || 0) + (+rx || 0), (+y || 0) + (+ry || 0));
        // Approximate as a circle of radius rx then squash y — good enough, deterministic.
        const X = +x || 0, Y = +y || 0, RX = +rx || 0, RY = +ry || 0;
        const s0 = +a0 || 0, s1 = a1 === undefined ? 2 * Math.PI : +a1;
        let sweep = s1 - s0; if (!ccw && sweep < 0) sweep += 2 * Math.PI; if (ccw && sweep > 0) sweep -= 2 * Math.PI;
        const steps = Math.max(2, Math.ceil(Math.abs(sweep) / (Math.PI / 16)));
        for (let k = 0; k <= steps; k++) { const a = s0 + sweep * (k / steps);
          const px = X + RX * Math.cos(a), py = Y + RY * Math.sin(a);
          if (k === 0 && !sub) moveV(px, py); else lineV(px, py); }
      },
      bezierCurveTo(a, b, c, d, e, f) { note('bezierCurveTo|' + [a, b, c, d, e, f]); pathPoint(a, b); pathPoint(e, f); cubicV(+a || 0, +b || 0, +c || 0, +d || 0, +e || 0, +f || 0); },
      quadraticCurveTo(a, b, c, d) { note('quadraticCurveTo|' + [a, b, c, d]); pathPoint(a, b); pathPoint(c, d); quadV(+a || 0, +b || 0, +c || 0, +d || 0); },
      fill(rule) {
        note('fill|' + this.fillStyle);
        if (!S.native) return paintPath();
        const fs = this.fillStyle;
        if (fs && fs.__ptGrad) S.fillPathGradient(verbs, String(rule) === 'evenodd', encodeGrad(fs.__ptGrad));
        else S.fillPath(verbs, String(rule) === 'evenodd', parseColor(fs));
      },
      stroke() {
        note('stroke|' + [this.strokeStyle, this.lineWidth]);
        if (S.native) S.strokePath(verbs, Math.max(0, +this.lineWidth || 1), parseColor(this.strokeStyle));
        else paintPath();
      },
      clip() { note('clip'); },

      save() { note('save'); }, restore() { note('restore'); },
      translate(x, y) { note('translate|' + [x, y]); }, scale(x, y) { note('scale|' + [x, y]); },
      rotate(a) { note('rotate|' + a); },
      setTransform() { note('setTransform|' + [].slice.call(arguments)); },
      transform() { note('transform|' + [].slice.call(arguments)); },
      resetTransform() { note('resetTransform'); },
      setLineDash(d) { note('setLineDash|' + d); }, getLineDash() { return []; },

      drawImage(img, x, y, w, h) {
        note('drawImage|' + [x, y, w, h, img && (img.src || img.localName)]);
        stamp(x || 0, y || 0, w || (img && img.width) || 32, h || (img && img.height) || 32);
      },
      putImageData(data, x, y) {
        note('putImageData|' + [x, y, data && data.width, data && data.height]);
        if (!data || !data.data) return;
        if (S.native) { S.put(data.data, x | 0, y | 0, data.width | 0, data.height | 0); return; }
        const p = S.pixels(), W = p.w, H = p.h, px = p.data;
        const dw = data.width | 0, dh = data.height | 0;
        for (let yy = 0; yy < dh; yy++) for (let xx = 0; xx < dw; xx++) {
          const tx = (x | 0) + xx, ty = (y | 0) + yy;
          if (tx < 0 || ty < 0 || tx >= W || ty >= H) continue;
          const si = (yy * dw + xx) * 4, di = (ty * W + tx) * 4;
          px[di] = data.data[si]; px[di + 1] = data.data[si + 1];
          px[di + 2] = data.data[si + 2]; px[di + 3] = data.data[si + 3];
        }
      },
      isPointInPath() { return false; },
      measureText(t) {
        const size = fontSize(this.font);
        const w = S.native ? S.width(t, size) : String(t).length * 6.7;
        return { width: w, actualBoundingBoxLeft: 0, actualBoundingBoxRight: w, actualBoundingBoxAscent: size * 0.7, actualBoundingBoxDescent: size * 0.2, fontBoundingBoxAscent: size * 0.9, fontBoundingBoxDescent: size * 0.2 };
      },
      getImageData(x, y, w, h) {
        w = w | 0; h = h | 0;
        const out = S.read(x, y, w, h, new Uint8ClampedArray(Math.max(0, w * h * 4)));
        return { data: out, width: w, height: h, colorSpace: 'srgb' };
      },
      createImageData(w, h) { return { data: new Uint8ClampedArray(Math.max(0, (w | 0) * (h | 0) * 4)), width: w | 0, height: h | 0, colorSpace: 'srgb' }; },
      createLinearGradient(x0, y0, x1, y1) { note('linearGradient|' + [x0, y0, x1, y1]); return makeGradient(0, [+x0 || 0, +y0 || 0, +x1 || 0, +y1 || 0, 0, 0]); },
      createRadialGradient(x0, y0, r0, x1, y1, r1) { note('radialGradient|' + [x0, y0, r0, x1, y1, r1]); return makeGradient(1, [+x0 || 0, +y0 || 0, +x1 || 0, +y1 || 0, +r0 || 0, +r1 || 0]); },
      createPattern() { note('pattern'); return {}; },
      getContextAttributes() { return { alpha: true, colorSpace: 'srgb', desynchronized: false, willReadFrequently: false }; },
      // Hidden (filtered) accessor the canvas element uses to encode itself.
      __ptPixels() { return S.pixels(); },
    }));
  };

  // --- WebGL ------------------------------------------------------------
  const GL_EXTS = ['ANGLE_instanced_arrays','EXT_blend_minmax','EXT_color_buffer_half_float',
    'EXT_disjoint_timer_query','EXT_float_blend','EXT_frag_depth','EXT_shader_texture_lod',
    'EXT_texture_compression_bptc','EXT_texture_compression_rgtc','EXT_texture_filter_anisotropic',
    'EXT_sRGB','KHR_parallel_shader_compile','OES_element_index_uint','OES_fbo_render_mipmap',
    'OES_standard_derivatives','OES_texture_float','OES_texture_float_linear','OES_texture_half_float',
    'OES_texture_half_float_linear','OES_vertex_array_object','WEBGL_color_buffer_float',
    'WEBGL_compressed_texture_s3tc','WEBGL_compressed_texture_s3tc_srgb','WEBGL_debug_renderer_info',
    'WEBGL_debug_shaders','WEBGL_depth_texture','WEBGL_draw_buffers','WEBGL_lose_context',
    'WEBGL_multi_draw'];
  const makeGL = (canvas, ver) => {
    const P = {
      0x1F00: 'WebKit',                                   // VENDOR
      0x1F01: 'WebKit WebGL',                             // RENDERER
      0x1F02: ver === 2 ? 'WebGL 2.0 (OpenGL ES 3.0 Chromium)' : 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',
      0x8B8C: ver === 2 ? 'WebGL GLSL ES 3.00 (OpenGL ES GLSL ES 3.0 Chromium)' : 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)',
      0x9245: WEBGL_VENDOR,                               // UNMASKED_VENDOR_WEBGL
      0x9246: WEBGL_RENDERER,                             // UNMASKED_RENDERER_WEBGL
      0x0D33: 16384, 0x851C: 16384, 0x84E8: 16, 0x8B4C: 16, 0x8B4D: 32, 0x8869: 16,
      0x8DFB: 30, 0x8DFC: 32, 0x8DFD: 30, 0x8B4B: 1024, 0x0D3A: 32, 0x84E2: 32,
      0x846E: [1, 1], 0x0B21: 8192, 0x8073: 16, 0x8B9A: 35724,
    };
    // WebGL enum constants — fingerprinters read `gl.VENDOR` etc., not literals.
    const C = {
      VENDOR: 0x1F00, RENDERER: 0x1F01, VERSION: 0x1F02, SHADING_LANGUAGE_VERSION: 0x8B8C,
      MAX_TEXTURE_SIZE: 0x0D33, MAX_CUBE_MAP_TEXTURE_SIZE: 0x851C, MAX_RENDERBUFFER_SIZE: 0x84E8,
      MAX_VIEWPORT_DIMS: 0x0D3A, MAX_VERTEX_ATTRIBS: 0x8869, MAX_VERTEX_UNIFORM_VECTORS: 0x8DFB,
      MAX_VARYING_VECTORS: 0x8DFC, MAX_FRAGMENT_UNIFORM_VECTORS: 0x8DFD,
      MAX_VERTEX_TEXTURE_IMAGE_UNITS: 0x8B4C, MAX_COMBINED_TEXTURE_IMAGE_UNITS: 0x8B4D,
      MAX_TEXTURE_IMAGE_UNITS: 0x8872, MAX_TEXTURE_MAX_ANISOTROPY_EXT: 0x84FF,
      ALIASED_LINE_WIDTH_RANGE: 0x846E, ALIASED_POINT_SIZE_RANGE: 0x846D,
      RED_BITS: 0x0D52, GREEN_BITS: 0x0D53, BLUE_BITS: 0x0D54, ALPHA_BITS: 0x0D55,
      DEPTH_BITS: 0x0D56, STENCIL_BITS: 0x0D57, SAMPLES: 0x80A9, MAX_SAMPLES: 0x8D57,
      RGBA: 0x1908, RGB: 0x1907, TEXTURE_2D: 0x0DE1, FLOAT: 0x1406, UNSIGNED_BYTE: 0x1401,
      DEPTH_TEST: 0x0B71, VERTEX_SHADER: 0x8B31, FRAGMENT_SHADER: 0x8B30,
      HIGH_FLOAT: 0x8DF2, MEDIUM_FLOAT: 0x8DF1, LOW_FLOAT: 0x8DF0,
      HIGH_INT: 0x8DF5, MEDIUM_INT: 0x8DF4, LOW_INT: 0x8DF3,
      COLOR_BUFFER_BIT: 0x4000, DEPTH_BUFFER_BIT: 0x0100, ARRAY_BUFFER: 0x8892,
      COMPILE_STATUS: 0x8B81, LINK_STATUS: 0x8B82,
      MAX_3D_TEXTURE_SIZE: 0x8073, MAX_ARRAY_TEXTURE_LAYERS: 0x88FF,
      MAX_DRAW_BUFFERS: 0x8824, MAX_COLOR_ATTACHMENTS: 0x8CDF,
    };
    // Give MAX_* params sensible Chrome-ish values so `getParameter` answers.
    Object.assign(P, {
      [C.MAX_TEXTURE_SIZE]: 16384, [C.MAX_CUBE_MAP_TEXTURE_SIZE]: 16384, [C.MAX_RENDERBUFFER_SIZE]: 16384,
      [C.MAX_VIEWPORT_DIMS]: [32767, 32767], [C.MAX_VERTEX_ATTRIBS]: 16,
      [C.MAX_VERTEX_UNIFORM_VECTORS]: 4096, [C.MAX_VARYING_VECTORS]: 30, [C.MAX_FRAGMENT_UNIFORM_VECTORS]: 1024,
      [C.MAX_VERTEX_TEXTURE_IMAGE_UNITS]: 16, [C.MAX_COMBINED_TEXTURE_IMAGE_UNITS]: 32,
      [C.MAX_TEXTURE_IMAGE_UNITS]: 16, [C.MAX_TEXTURE_MAX_ANISOTROPY_EXT]: 16,
      [C.ALIASED_LINE_WIDTH_RANGE]: [1, 1], [C.ALIASED_POINT_SIZE_RANGE]: [1, 1024],
      [C.RED_BITS]: 8, [C.GREEN_BITS]: 8, [C.BLUE_BITS]: 8, [C.ALPHA_BITS]: 8,
      [C.DEPTH_BITS]: 24, [C.STENCIL_BITS]: 0, [C.SAMPLES]: 0, [C.MAX_SAMPLES]: 8,
      [C.MAX_3D_TEXTURE_SIZE]: 2048, [C.MAX_ARRAY_TEXTURE_LAYERS]: 2048,
      [C.MAX_DRAW_BUFFERS]: 8, [C.MAX_COLOR_ATTACHMENTS]: 8,
    });
    const glProto = (ver === 2 ? globalThis.WebGL2RenderingContext : globalThis.WebGLRenderingContext).prototype;
    const gl = Object.assign(Object.create(glProto), C, {
      canvas, drawingBufferWidth: canvas.width || 300, drawingBufferHeight: canvas.height || 150,
      drawingBufferColorSpace: 'srgb',
      getParameter(p){ return Object.prototype.hasOwnProperty.call(P, p) ? P[p] : (typeof p === 'number' ? 0 : null); },
      getExtension(name){ if (name === 'WEBGL_debug_renderer_info') return { UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246 }; return GL_EXTS.indexOf(name) >= 0 ? {} : null; },
      getSupportedExtensions(){ return GL_EXTS.slice(); },
      getContextAttributes(){ return { alpha: true, antialias: true, depth: true, desynchronized: false, failIfMajorPerformanceCaveat: false, powerPreference: 'default', premultipliedAlpha: true, preserveDrawingBuffer: false, stencil: false, xrCompatible: false }; },
      getShaderPrecisionFormat(){ return { rangeMin: 127, rangeMax: 127, precision: 23 }; },
      getContextAttributes_: null,
    });
    const iface = (n) => (globalThis[n] ? globalThis[n].prototype : Object.prototype);
    // WebGL fingerprinting renders a scene and reads it back (readPixels, or
    // toDataURL on the canvas). With every call a no-op the readback was all
    // zeroes no matter what was drawn, so two different scenes compared equal —
    // the same differential tell the 2D context had.
    if (NATIVE_GL) {
      // Real headless GL (the `webgl` feature): the drawing pipeline runs on a
      // Mesa context; getParameter/extensions above stay synthesized so the
      // reported GPU string stays coherent (we only borrow the pixels).
      const gid = (globalThis.__ptGlSeq = (globalThis.__ptGlSeq || 0) + 1);
      const GW = canvas.width || 300, GH = canvas.height || 150;
      __pt_glCreate(gid, GW, GH);
      __pt_glViewport(gid, 0, 0, GW, GH);
      const shProto = iface('WebGLShader'), prProto = iface('WebGLProgram'), bfProto = iface('WebGLBuffer');
      const txProto = iface('WebGLTexture'), fbProto = iface('WebGLFramebuffer');
      const rbProto = iface('WebGLRenderbuffer'), vaProto = iface('WebGLVertexArrayObject');
      let clearRGBA = [0, 0, 0, 0];
      const H = (o) => (o ? (o.__h | 0) : 0);              // JS wrapper -> native handle
      const L = (l) => (l && typeof l.__loc === 'number' ? l.__loc : -1);
      const bytesOf = (d) => (typeof d === 'number' ? new Uint8Array(Math.max(0, d)) : d);
      const obj = (p, h) => { const o = Object.create(p); o.__h = h; return o; };
      // WebGL's own unpack modes: the browser applies these on the CPU before the
      // upload (GL has no such state), so they ride along with each texImage2D.
      let flipY = 0, premul = 0;
      let boundFB = null;                                  // null = the drawing buffer
      const EMPTY = new Uint8Array(0);
      const texBytes = (d) => (d && (d.byteLength !== undefined || d.length !== undefined) ? d : EMPTY);
      // Pixels behind a texImage2D *source* argument (ImageData, another canvas,
      // an image). Anything we can't read still yields its dimensions, so the
      // texture is allocated at the right size instead of the call being dropped.
      const srcPixels = (s) => {
        if (!s) return { w: 0, h: 0, data: EMPTY };
        if (s.data && s.width !== undefined) return { w: s.width | 0, h: s.height | 0, data: s.data };
        const g = s.__ptC2d || s.__ptGl1 || s.__ptGl2;
        if (g && g.__ptPixels) { const p = g.__ptPixels(); return { w: p.w, h: p.h, data: p.data }; }
        const w = (s.naturalWidth || s.width || s.videoWidth || 0) | 0;
        const h = (s.naturalHeight || s.height || s.videoHeight || 0) | 0;
        return { w, h, data: EMPTY };
      };
      Object.assign(gl, {
        createShader(type) { const o = obj(shProto, __pt_glCreateShader(gid, type >>> 0)); o.__type = type; return o; },
        shaderSource(sh, src) { if (sh) sh.__src = String(src); },
        compileShader(sh) { if (sh) __pt_glCompileShader(gid, H(sh), sh.__src || ''); },
        getShaderParameter(sh, pn) { if (pn === C.COMPILE_STATUS) return __pt_glShaderCompiled(gid, H(sh)); if (pn === 0x8B4F) return sh && sh.__type; return true; },
        getShaderInfoLog(sh) { return __pt_glShaderInfoLog(gid, H(sh)); },
        createProgram() { return obj(prProto, __pt_glCreateProgram(gid)); },
        attachShader(p, sh) { __pt_glAttachShader(gid, H(p), H(sh)); },
        linkProgram(p) { __pt_glLinkProgram(gid, H(p)); },
        getProgramParameter(p, pn) { if (pn === C.LINK_STATUS) return __pt_glProgramLinked(gid, H(p)); return 0; },
        getProgramInfoLog() { return ''; },
        useProgram(p) { __pt_glUseProgram(gid, H(p)); },
        getAttribLocation(p, name) { return __pt_glAttribLocation(gid, H(p), String(name)); },
        getUniformLocation(p, name) {
          const l = __pt_glUniformLocation(gid, H(p), String(name));
          if (l < 0) return null;                            // as the spec says for an unknown name
          const o = Object.create(iface('WebGLUniformLocation')); o.__loc = l; return o;
        },
        createBuffer() { return obj(bfProto, __pt_glCreateBuffer(gid)); },
        bindBuffer(t, b) { __pt_glBindBuffer(gid, t >>> 0, H(b)); },
        bufferData(t, data, usage) { __pt_glBufferData(gid, t >>> 0, bytesOf(data), (usage || 0) >>> 0); },
        enableVertexAttribArray(i) { __pt_glEnableVertexAttribArray(gid, i >>> 0); },
        vertexAttribPointer(i, size, type, norm, stride, offset) { __pt_glVertexAttribPointer(gid, i >>> 0, size | 0, type >>> 0, norm ? 1 : 0, stride | 0, offset | 0); },
        uniform1f(l, x) { __pt_glUniformF(gid, L(l), new Float32Array([x])); },
        uniform2f(l, a, b) { __pt_glUniformF(gid, L(l), new Float32Array([a, b])); },
        uniform3f(l, a, b, c2) { __pt_glUniformF(gid, L(l), new Float32Array([a, b, c2])); },
        uniform4f(l, a, b, c2, d) { __pt_glUniformF(gid, L(l), new Float32Array([a, b, c2, d])); },
        uniform1i(l, x) { __pt_glUniform1i(gid, L(l), x | 0); },
        uniformMatrix4fv(l, transpose, v) { __pt_glUniformMatrix4(gid, L(l), transpose ? 1 : 0, new Float32Array(v)); },
        clearColor(r, g, b, a) { const q = (v) => Math.max(0, Math.min(255, Math.round((+v || 0) * 255))); clearRGBA = [q(r), q(g), q(b), q(a)]; },
        clear(mask) { __pt_glClear(gid, clearRGBA[0], clearRGBA[1], clearRGBA[2], clearRGBA[3], mask | 0); },
        viewport(x, y, w, h) { __pt_glViewport(gid, x | 0, y | 0, w | 0, h | 0); },
        enable(cap) { __pt_glEnable(gid, cap >>> 0, 1); },
        disable(cap) { __pt_glEnable(gid, cap >>> 0, 0); },
        blendFunc(s, d) { __pt_glBlendFunc(gid, s >>> 0, d >>> 0); },
        depthFunc(f) { __pt_glDepthFunc(gid, f >>> 0); },
        drawArrays(mode, first, count) { __pt_glDrawArrays(gid, mode >>> 0, first | 0, count | 0); },
        drawElements(mode, count, type, offset) { __pt_glDrawElements(gid, mode >>> 0, count | 0, type >>> 0, offset | 0); },
        // --- textures: the classic fingerprint scene is a textured quad, and a
        // stubbed sampler reads black, collapsing every scene to one readback.
        createTexture() { return obj(txProto, __pt_glCreateTexture(gid)); },
        bindTexture(t, tex) { __pt_glBindTexture(gid, t >>> 0, H(tex)); },
        activeTexture(u) { __pt_glActiveTexture(gid, u >>> 0); },
        texParameteri(t, pn, p) { __pt_glTexParameteri(gid, t >>> 0, pn >>> 0, p | 0); },
        texParameterf(t, pn, p) { __pt_glTexParameteri(gid, t >>> 0, pn >>> 0, p | 0); },
        generateMipmap(t) { __pt_glGenerateMipmap(gid, t >>> 0); },
        pixelStorei(pn, p) {
          if ((pn | 0) === 0x9240) flipY = p ? 1 : 0;        // UNPACK_FLIP_Y_WEBGL
          else if ((pn | 0) === 0x9241) premul = p ? 1 : 0;  // UNPACK_PREMULTIPLY_ALPHA_WEBGL
          // Row alignment is pinned to 1 natively (uploads cross tightly packed).
        },
        texImage2D(target, level, internalformat, a, b, c, d, e, f) {
          if (arguments.length >= 9) {                       // (…, w, h, border, format, type, pixels)
            __pt_glTexImage2D(gid, target >>> 0, level | 0, internalformat | 0, a | 0, b | 0, c | 0,
              d >>> 0, e >>> 0, texBytes(f), flipY, premul);
          } else {                                           // (…, format, type, source)
            const s = srcPixels(c);
            __pt_glTexImage2D(gid, target >>> 0, level | 0, internalformat | 0, s.w, s.h, 0,
              a >>> 0, b >>> 0, s.data, flipY, premul);
          }
        },
        texSubImage2D(target, level, xo, yo, a, b, c, d, e) {
          if (arguments.length >= 9) {                       // (…, w, h, format, type, pixels)
            __pt_glTexSubImage2D(gid, target >>> 0, level | 0, xo | 0, yo | 0, a | 0, b | 0,
              c >>> 0, d >>> 0, texBytes(e), flipY, premul);
          } else {                                           // (…, format, type, source)
            const s = srcPixels(c);
            __pt_glTexSubImage2D(gid, target >>> 0, level | 0, xo | 0, yo | 0, s.w, s.h,
              a >>> 0, b >>> 0, s.data, flipY, premul);
          }
        },
        // --- framebuffers: render-to-texture passes, and `null` means this
        // canvas' drawing buffer (an FBO here — there is no framebuffer 0).
        createFramebuffer() { return obj(fbProto, __pt_glCreateFramebuffer(gid)); },
        bindFramebuffer(t, fb) { boundFB = fb || null; __pt_glBindFramebuffer(gid, t >>> 0, H(fb)); },
        framebufferTexture2D(t, att, tt, tex, level) { __pt_glFramebufferTexture2D(gid, t >>> 0, att >>> 0, tt >>> 0, H(tex), level | 0); },
        checkFramebufferStatus(t) { return __pt_glCheckFramebufferStatus(gid, t >>> 0); },
        createRenderbuffer() { return obj(rbProto, __pt_glCreateRenderbuffer(gid)); },
        bindRenderbuffer(t, rb) { __pt_glBindRenderbuffer(gid, t >>> 0, H(rb)); },
        renderbufferStorage(t, fmt, w, h) { __pt_glRenderbufferStorage(gid, t >>> 0, fmt >>> 0, w | 0, h | 0); },
        framebufferRenderbuffer(t, att, rt, rb) { __pt_glFramebufferRenderbuffer(gid, t >>> 0, att >>> 0, rt >>> 0, H(rb)); },
        createVertexArray() { return obj(vaProto, __pt_glCreateVertexArray(gid)); },
        bindVertexArray(v) { __pt_glBindVertexArray(gid, H(v)); },
        deleteShader(o) { __pt_glDelete(gid, 0, H(o)); },
        deleteProgram(o) { __pt_glDelete(gid, 1, H(o)); },
        deleteBuffer(o) { __pt_glDelete(gid, 2, H(o)); },
        deleteTexture(o) { __pt_glDelete(gid, 3, H(o)); },
        deleteFramebuffer(o) { __pt_glDelete(gid, 4, H(o)); },
        deleteRenderbuffer(o) { __pt_glDelete(gid, 5, H(o)); },
        deleteVertexArray(o) { __pt_glDelete(gid, 6, H(o)); },
        readPixels(x, y, w, h, format, type, dst) {
          if (!dst) return dst;
          // Straight from the bound framebuffer (which may be an offscreen target
          // of its own size), bottom-up — exactly the order WebGL specifies.
          const px = __pt_glReadPixels(gid, x | 0, y | 0, w | 0, h | 0, 0);
          const n = Math.min(dst.length === undefined ? px.length : dst.length, px.length);
          for (let i = 0; i < n; i++) dst[i] = px[i];
          return dst;
        },
        // toDataURL is the *canvas*, so read the drawing buffer even mid-pass
        // with an offscreen framebuffer bound, then put the binding back.
        __ptPixels() {
          if (boundFB) __pt_glBindFramebuffer(gid, 0x8D40, 0);
          const data = __pt_glReadPixels(gid, 0, 0, GW, GH, 1);   // top-left origin
          if (boundFB) __pt_glBindFramebuffer(gid, 0x8D40, H(boundFB));
          return { w: GW, h: GH, data };
        },
      });
      // WebGL 1 reaches vertex arrays through the extension object, not the
      // context — hand back a working one instead of the usual empty stub.
      const getExt = gl.getExtension;
      gl.getExtension = function getExtension(name) {
        if (name === 'OES_vertex_array_object') return {
          VERTEX_ARRAY_BINDING_OES: 0x85B5,
          createVertexArrayOES: () => gl.createVertexArray(),
          bindVertexArrayOES: (v) => gl.bindVertexArray(v),
          deleteVertexArrayOES: (v) => gl.deleteVertexArray(v),
          isVertexArrayOES: (v) => !!(v && v.__h),
        };
        return getExt.call(this, name);
      };
    } else {
      // Fallback synthesis (no `webgl` feature): back the readback with the shared
      // surface — clears are exact, draws stamp a pattern keyed by the op log.
      const S = makeSurface(canvas);
      let clearRGBA = [0, 0, 0, 0];
      Object.assign(gl, {
        clearColor(r, g, b, a) {
          S.note('clearColor|' + [r, g, b, a]);
          const q = (v) => Math.max(0, Math.min(255, Math.round((+v || 0) * 255)));
          clearRGBA = [q(r), q(g), q(b), q(a)];
        },
        clear(mask) {
          S.note('clear|' + mask);
          if ((mask | 0) & C.COLOR_BUFFER_BIT) { const p = S.pixels(); S.solid(0, 0, p.w, p.h, clearRGBA); }
        },
        viewport(x, y, w, h) { S.note('viewport|' + [x, y, w, h]); },
        shaderSource(sh, src) { S.note('shaderSource|' + src); },
        bufferData(target, data) { S.note('bufferData|' + [target, data && (data.length || data.byteLength)]); },
        uniform1f(l, v) { S.note('uniform1f|' + v); },
        uniform2f(l, a, b) { S.note('uniform2f|' + [a, b]); },
        uniform3f(l, a, b, c2) { S.note('uniform3f|' + [a, b, c2]); },
        uniform4f(l, a, b, c2, d) { S.note('uniform4f|' + [a, b, c2, d]); },
        drawArrays(mode, first, count) {
          S.note('drawArrays|' + [mode, first, count]);
          const p = S.pixels(); S.stamp(0, 0, p.w, p.h);
        },
        drawElements(mode, count, type, offset) {
          S.note('drawElements|' + [mode, count, type, offset]);
          const p = S.pixels(); S.stamp(0, 0, p.w, p.h);
        },
        readPixels(x, y, w, h, format, type, dst) {
          S.note('readPixels|' + [x, y, w, h, format, type]);
          w = w | 0; h = h | 0;
          if (dst && dst.length >= w * h * 4) S.read(x, y, w, h, dst);
          return dst;
        },
        __ptPixels() { return S.pixels(); },
      });
    }

    // Whatever is left unimplemented, `createX` still has to hand back an opaque
    // object of the right type: a page that null-checks `createTexture()` (or
    // runs `instanceof`) would otherwise see straight through the context.
    for (const [m, n] of [['createShader','WebGLShader'],['createProgram','WebGLProgram'],
      ['createBuffer','WebGLBuffer'],['createTexture','WebGLTexture'],['createFramebuffer','WebGLFramebuffer'],
      ['createRenderbuffer','WebGLRenderbuffer'],['createVertexArray','WebGLVertexArrayObject']]) {
      if (!gl[m]) gl[m] = function () { return Object.create(iface(n)); };
    }
    // No-op the GL calls a fingerprinter drives before reading parameters.
    for (const m of ['viewport','clearColor','clear','enable','disable','createShader','shaderSource',
      'compileShader','createProgram','attachShader','linkProgram',
      'useProgram','createBuffer','bindBuffer','bufferData','getAttribLocation','vertexAttribPointer',
      'enableVertexAttribArray','getUniformLocation','uniform1f','uniform2f','uniform3f','uniform4f',
      'uniform1i','uniform2i','uniform3i','uniform4i','uniform1fv','uniform2fv','uniform3fv','uniform4fv',
      'uniformMatrix2fv','uniformMatrix3fv','uniformMatrix4fv','drawElements','drawArrays','deleteShader',
      'deleteProgram','deleteBuffer','activeTexture','bindTexture','createTexture','texParameteri','texParameterf',
      'texImage2D','texSubImage2D','generateMipmap','deleteTexture','framebufferTexture2D','bindFramebuffer',
      'createFramebuffer','deleteFramebuffer','bindRenderbuffer','renderbufferStorage','framebufferRenderbuffer',
      'deleteRenderbuffer','bindVertexArray','deleteVertexArray','blendFunc','readPixels','pixelStorei','depthFunc',
      'flush','finish']) {
      if (!gl[m]) gl[m] = function(){};
    }
    // Calls whose *return* has to be plausible: `undefined` from any of these is
    // a tell (and stops a page's render path dead at the framebuffer check).
    if (!gl.checkFramebufferStatus) gl.checkFramebufferStatus = function () { return 0x8CD5; };
    if (!gl.getError) gl.getError = function () { return 0; };
    if (!gl.isContextLost) gl.isContextLost = function () { return false; };
    if (!gl.getShaderInfoLog) gl.getShaderInfoLog = function () { return ''; };
    if (!gl.getProgramInfoLog) gl.getProgramInfoLog = function () { return ''; };
    if (!gl.getUniformLocation) gl.getUniformLocation = function () { return Object.create(iface('WebGLUniformLocation')); };
    // Shaders always compile and programs always link in a real browser — the
    // no-op fill above answered `undefined`, which reads as "compilation failed"
    // and stops a page (or tells a fingerprinter it is not talking to Chrome).
    if (!gl.getShaderParameter) gl.getShaderParameter = function (sh, pn) { return pn === 0x8B4F ? (sh && sh.__type) : true; };
    if (!gl.getProgramParameter) gl.getProgramParameter = function (p, pn) { return pn === C.LINK_STATUS ? true : 0; };
    return maskProto(gl);
  };

  // --- patch canvas element methods -------------------------------------
  const proto = globalThis.HTMLElement && globalThis.HTMLElement.prototype;
  if (proto) {
    proto.getContext = mask(function getContext(type) {
      if (this.localName !== 'canvas') return null;
      // A canvas keeps the first context type it was given; a real browser
      // returns null for a conflicting request rather than a second context.
      const t = type === 'experimental-webgl' ? 'webgl' : String(type);
      if (this.__ptCtxType && this.__ptCtxType !== t) return null;
      if (t !== '2d' && t !== 'webgl' && t !== 'webgl2') return null;
      this.__ptCtxType = t;
      if (t === '2d') return this.__ptC2d || (this.__ptC2d = make2DContext(this));
      if (t === 'webgl') return this.__ptGl1 || (this.__ptGl1 = makeGL(this, 1));
      return this.__ptGl2 || (this.__ptGl2 = makeGL(this, 2));
    }, 'getContext');
    proto.toDataURL = mask(function toDataURL() {
      if (this.localName !== 'canvas') return 'data:,';
      const g = this.__ptC2d || this.__ptGl1 || this.__ptGl2 || this.getContext('2d');
      const p = g && g.__ptPixels ? g.__ptPixels() : null;
      if (!p || !p.w || !p.h) return 'data:,';
      return __pt_pngDataUrl(p.w, p.h, p.data) || 'data:,';
    }, 'toDataURL');
    proto.toBlob = mask(function toBlob(cb) {
      if (typeof cb !== 'function') return;
      const url = this.toDataURL();
      cb({ size: Math.max(0, url.length - 22), type: 'image/png' });
    }, 'toBlob');
  }

  // --- Image (new Image(); img.src = ... fires onload) ------------------
  if (globalThis.document) {
    const ImageCtor = mask(function Image(w, h) {
      const img = document.createElement('img');
      if (w != null) img.width = w;
      if (h != null) img.height = h;
      img.complete = false; img.naturalWidth = 0; img.naturalHeight = 0;
      let src = '';
      Object.defineProperty(img, 'src', {
        get() { return src; },
        set(v) {
          src = String(v);
          img.complete = true;
          img.naturalWidth = img.width || 1; img.naturalHeight = img.height || 1;
          // Actually fetch http(s) images (tracking pixels / beacons) through the
          // engine so they're captured; skip data:/blob: (canvas fingerprints).
          if (/^https?:/i.test(src)) {
            try { globalThis.fetch(src, { headers: { 'x-pt-kind': 'image' } }).catch(() => {}); } catch (e) {}
          }
          // Fire onload asynchronously via the event loop, like a real load.
          setTimeout(() => { if (typeof img.onload === 'function') img.onload({ target: img }); }, 0);
        },
        configurable: true,
      });
      return img;
    }, 'Image');
    globalThis.Image = ImageCtor;
    if (!globalThis.HTMLImageElement) globalThis.HTMLImageElement = globalThis.Element;
  }

  // --- AudioContext -----------------------------------------------------
  // Audio fingerprinting renders a graph (an oscillator through a compressor) in
  // an OfflineAudioContext and hashes the output samples. The old shim rendered a
  // fixed sine keyed only on the session seed, so every graph produced the same
  // samples — the same differential tell canvas/WebGL had: a 10 kHz oscillator
  // and a 440 Hz one hashed identically. The nodes now record their parameters,
  // connections are tracked, and the rendered buffer is synthesised from the
  // actual graph, so different graphs differ, an identical graph is stable, and
  // the per-session seed adds device-like jitter.
  const audioParam = (v) => ({
    value: v, defaultValue: v, minValue: -3.4028235e38, maxValue: 3.4028235e38, automationRate: 'a-rate',
    setValueAtTime(x) { this.value = +x; return this; },
    linearRampToValueAtTime(x) { this.value = +x; return this; },
    exponentialRampToValueAtTime(x) { this.value = +x; return this; },
    setTargetAtTime() { return this; }, setValueCurveAtTime() { return this; },
    cancelScheduledValues() { return this; }, cancelAndHoldAtTime() { return this; },
  });
  const makeNode = (ctx, kind, extra) => {
    const node = Object.assign({
      context: ctx, numberOfInputs: 1, numberOfOutputs: 1, channelCount: 2,
      channelCountMode: 'max', channelInterpretation: 'speakers', __ptKind: kind,
      connect(dst) { ctx.__ptEdges.push(kind + '>' + (dst && dst.__ptKind || 'destination')); return dst && dst.connect ? dst : undefined; },
      disconnect() {}, start() {}, stop() {},
      addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; },
    }, extra || {});
    ctx.__ptNodes.push(node);
    return node;
  };
  // FNV-1a over every node parameter + the edge list: the graph's identity.
  const graphHash = (ctx) => {
    let h = 2166136261 >>> 0;
    const note = (s) => { s = String(s); for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; } };
    for (const n of ctx.__ptNodes) {
      note(n.__ptKind);
      if (n.type !== undefined) note('t' + n.type);
      for (const k of ['frequency', 'detune', 'gain', 'Q', 'threshold', 'knee', 'ratio', 'attack', 'release', 'pan', 'delayTime']) {
        if (n[k] && typeof n[k].value === 'number') note(k + n[k].value);
      }
    }
    note(ctx.__ptEdges.join(','));
    return h >>> 0;
  };
  const oscWave = (type, phase) => {
    const p = phase - Math.floor(phase);
    if (type === 'square') return p < 0.5 ? 1 : -1;
    if (type === 'sawtooth') return 2 * p - 1;
    if (type === 'triangle') return 4 * Math.abs(p - 0.5) - 1;
    return Math.sin(2 * Math.PI * p);
  };
  const bufferOf = (data, chans, len, rate) => {
    const b = {
      numberOfChannels: chans, length: len, sampleRate: rate, duration: len / rate,
      getChannelData(c) { return c ? new Float32Array(len) : data; },
      copyFromChannel(dst, c, start) { const s = c ? 0 : (start | 0); for (let i = 0; i < dst.length && s + i < len; i++) dst[i] = data[s + i]; },
      copyToChannel() {},
    };
    return b;
  };

  class BaseAudioContext {
    constructor() {
      this.sampleRate = 44100; this.currentTime = 0; this.state = 'running';
      this.__ptNodes = []; this.__ptEdges = [];
      this.destination = makeNode(this, 'destination', { maxChannelCount: 2 });
      this.listener = { positionX: audioParam(0), positionY: audioParam(0), positionZ: audioParam(0), setPosition() {}, setOrientation() {} };
      this.audioWorklet = { addModule() { return Promise.resolve(); } };
      this.onstatechange = null;
    }
    createOscillator() { return makeNode(this, 'oscillator', { type: 'sine', frequency: audioParam(440), detune: audioParam(0), onended: null, setPeriodicWave() {} }); }
    createGain() { return makeNode(this, 'gain', { gain: audioParam(1) }); }
    createAnalyser() {
      const ctx = this;
      return makeNode(this, 'analyser', {
        fftSize: 2048, frequencyBinCount: 1024, minDecibels: -100, maxDecibels: -30, smoothingTimeConstant: 0.8,
        getFloatFrequencyData(a) { const h = graphHash(ctx); for (let i = 0; i < a.length; i++) a[i] = -30 - (((h ^ Math.imul(i + 1, 2654435761)) >>> 0) % 7000) / 100; },
        getByteFrequencyData(a) { const h = graphHash(ctx); for (let i = 0; i < a.length; i++) a[i] = ((h ^ Math.imul(i + 1, 40503)) >>> 0) % 256; },
        getFloatTimeDomainData(a) { const h = graphHash(ctx); for (let i = 0; i < a.length; i++) a[i] = (((h ^ Math.imul(i + 1, 2246822519)) >>> 0) / 4294967295) * 2 - 1; },
        getByteTimeDomainData(a) { const h = graphHash(ctx); for (let i = 0; i < a.length; i++) a[i] = 128 + (((h ^ Math.imul(i + 1, 668265263)) >>> 0) % 128) - 64; },
      });
    }
    createDynamicsCompressor() { return makeNode(this, 'compressor', { threshold: audioParam(-24), knee: audioParam(30), ratio: audioParam(12), attack: audioParam(0.003), release: audioParam(0.25), reduction: 0 }); }
    createBiquadFilter() { return makeNode(this, 'biquad', { type: 'lowpass', frequency: audioParam(350), detune: audioParam(0), Q: audioParam(1), gain: audioParam(0), getFrequencyResponse() {} }); }
    createScriptProcessor() { return makeNode(this, 'scriptprocessor', { bufferSize: 4096, onaudioprocess: null }); }
    createBufferSource() { return makeNode(this, 'buffersource', { buffer: null, playbackRate: audioParam(1), detune: audioParam(0), loop: false, onended: null }); }
    createConvolver() { return makeNode(this, 'convolver', { buffer: null, normalize: true }); }
    createStereoPanner() { return makeNode(this, 'stereopanner', { pan: audioParam(0) }); }
    createDelay() { return makeNode(this, 'delay', { delayTime: audioParam(0) }); }
    createWaveShaper() { return makeNode(this, 'waveshaper', { curve: null, oversample: 'none' }); }
    createPanner() { return makeNode(this, 'panner', { positionX: audioParam(0), positionY: audioParam(0), positionZ: audioParam(0), setPosition() {} }); }
    createBuffer(ch, len, rate) { return bufferOf(new Float32Array(len), ch, len, rate || this.sampleRate); }
    createPeriodicWave() { return {}; }
    decodeAudioData(_d, cb) { const b = this.createBuffer(2, this.sampleRate, this.sampleRate); if (typeof cb === 'function') cb(b); return Promise.resolve(b); }
    resume() { this.state = 'running'; return Promise.resolve(); }
    suspend() { this.state = 'suspended'; return Promise.resolve(); }
    close() { this.state = 'closed'; return Promise.resolve(); }
    addEventListener() {} removeEventListener() {} dispatchEvent() { return true; }
    // Render the graph to one channel of samples: the oscillator's waveform at
    // its frequency, shaped by any compressor, plus tiny per-session jitter.
    __ptRender(chans, len) {
      const nodes = this.__ptNodes;
      const osc = nodes.find((n) => n.__ptKind === 'oscillator');
      const comp = nodes.find((n) => n.__ptKind === 'compressor');
      const gain = nodes.find((n) => n.__ptKind === 'gain');
      const freq = osc && osc.frequency ? osc.frequency.value : 440;
      const type = osc ? osc.type : 'sine';
      const amp = gain && gain.gain ? gain.gain.value : 1;
      const h = (graphHash(this) ^ SEED) >>> 0;
      const jitter = (h / 4294967295) * 1e-4;      // device-DSP-scale
      const jFreq = 1 + (h & 0x3ff) / 4096;
      const thr = comp ? Math.pow(10, (comp.threshold.value || -24) / 20) : 1;
      const ratio = comp ? (comp.ratio.value || 12) : 1;
      const data = new Float32Array(len);
      for (let i = 0; i < len; i++) {
        const t = i / this.sampleRate;
        let v = oscWave(type, freq * t) * 0.5 * amp;
        if (comp) { const s = v < 0 ? -1 : 1, m = Math.abs(v); v = s * (m > thr ? thr + (m - thr) / ratio : m); }
        data[i] = v + jitter * Math.sin(i * jFreq);
      }
      return bufferOf(data, chans, len, this.sampleRate);
    }
  }
  const audioTag = (Ctor, name) => { try { Object.defineProperty(Ctor.prototype, Symbol.toStringTag, { value: name, configurable: true }); } catch (e) {} return Ctor; };
  globalThis.AudioContext = audioTag(mask(class AudioContext extends BaseAudioContext {}, 'AudioContext'), 'AudioContext');
  globalThis.OfflineAudioContext = audioTag(mask(class OfflineAudioContext extends BaseAudioContext {
    constructor(ch, len, rate) {
      super();
      if (ch && typeof ch === 'object') { this.__ptChans = ch.numberOfChannels || 1; this.length = ch.length || 44100; if (ch.sampleRate) this.sampleRate = ch.sampleRate; }
      else { this.__ptChans = ch || 1; this.length = len || 44100; if (rate) this.sampleRate = rate; }
      this.oncomplete = null;
    }
    startRendering() {
      const buffer = this.__ptRender(this.__ptChans, this.length);
      // Fire the legacy `oncomplete` asynchronously (as the real API does; the
      // classic FingerprintJS routine waits on it) *and* resolve the promise.
      Promise.resolve().then(() => {
        if (typeof this.oncomplete === 'function') { try { this.oncomplete({ renderedBuffer: buffer, type: 'complete' }); } catch (e) {} }
      });
      return Promise.resolve(buffer);
    }
  }, 'OfflineAudioContext'), 'OfflineAudioContext');

  // --- navigator.plugins / mimeTypes (Chrome's PDF set, properly typed) --
  // Real Chrome exposes PluginArray / MimeTypeArray / Plugin / MimeType
  // interfaces: `Object.prototype.toString.call(navigator.plugins)` is
  // '[object PluginArray]', entries are real Plugin/MimeType instances, and
  // both satisfy `instanceof`. A plain Array (the old shape) is an instant tell.
  const iface = (name) => {
    const Ctor = function () { throw new TypeError('Illegal constructor'); };
    try { Object.defineProperty(Ctor, 'name', { value: name, configurable: true }); } catch (e) {}
    try { Object.defineProperty(Ctor.prototype, Symbol.toStringTag, { value: name, configurable: true }); } catch (e) {}
    globalThis[name] = Ctor;
    return Ctor.prototype;
  };
  const PluginProto = iface('Plugin'), MimeTypeProto = iface('MimeType');
  const PluginArrayProto = iface('PluginArray'), MimeTypeArrayProto = iface('MimeTypeArray');
  const arrayLike = (proto, keyOf) => {
    proto.item = function item(i) { return this[i] || null; };
    proto.namedItem = function namedItem(n) { for (let i = 0; i < this.length; i++) if (keyOf(this[i]) === n) return this[i]; return null; };
    proto[Symbol.iterator] = function () { let i = 0; const self = this; return { next: () => i < self.length ? { value: self[i++], done: false } : { value: undefined, done: true } }; };
  };
  arrayLike(PluginArrayProto, (p) => p && p.name);
  arrayLike(MimeTypeArrayProto, (m) => m && m.type);
  const fill = (arr, items, key) => {
    items.forEach((it, i) => { arr[i] = it; arr[it[key]] = it; });
    Object.defineProperty(arr, 'length', { value: items.length, enumerable: false, configurable: true });
    return arr;
  };
  const mkMime = (type, plugin) => Object.assign(Object.create(MimeTypeProto), { type, suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: plugin });
  const mkPlugin = (name) => {
    const p = Object.assign(Object.create(PluginProto), { name, filename: 'internal-pdf-viewer', description: 'Portable Document Format', length: 2 });
    return fill(p, [mkMime('application/pdf', p), mkMime('text/pdf', p)], 'type');
  };
  const plugins = ['PDF Viewer', 'Chrome PDF Viewer', 'Chromium PDF Viewer', 'Microsoft Edge PDF Viewer', 'WebKit built-in PDF'].map(mkPlugin);
  const pluginArray = fill(Object.create(PluginArrayProto), plugins, 'name');
  const mimeArray = fill(Object.create(MimeTypeArrayProto), [mkMime('application/pdf', plugins[0]), mkMime('text/pdf', plugins[0])], 'type');

  // Everything hangs off Navigator.prototype (as Chrome does), so the navigator
  // instance keeps zero own properties.
  const navProto = Object.getPrototypeOf(navigator);
  try {
    Object.defineProperty(navProto, 'plugins', { get: () => pluginArray, enumerable: true, configurable: true });
    Object.defineProperty(navProto, 'mimeTypes', { get: () => mimeArray, enumerable: true, configurable: true });
  } catch (e) {}

  // --- permissions ------------------------------------------------------
  const permissions = { query: mask(function query(desc){
    const name = desc && desc.name;
    const state = name === 'notifications' ? 'prompt' : (name === 'geolocation' ? 'prompt' : 'granted');
    return Promise.resolve({ state, name, onchange: null, addEventListener(){}, removeEventListener(){} });
  }, 'query') };
  try { Object.defineProperty(navProto, 'permissions', { get: () => permissions, enumerable: true, configurable: true }); } catch (e) {}

  // --- window.chrome (its absence/shape is a classic headless tell) -----
  if (!globalThis.chrome) {
    const ts = () => performance.now() / 1000;
    globalThis.chrome = {
      app: {
        isInstalled: false,
        InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
        RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
        getDetails: () => null, getIsInstalled: () => false, runningState: () => 'cannot_run',
      },
      runtime: {
        OnInstalledReason: { CHROME_UPDATE: 'chrome_update', INSTALL: 'install', SHARED_MODULE_UPDATE: 'shared_module_update', UPDATE: 'update' },
        OnRestartRequiredReason: { APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic' },
        PlatformArch: { ARM: 'arm', ARM64: 'arm64', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
        PlatformOs: { ANDROID: 'android', CROS: 'cros', LINUX: 'linux', MAC: 'mac', OPENBSD: 'openbsd', WIN: 'win' },
        connect: noop, sendMessage: noop, id: undefined,
      },
      loadTimes: () => ({ requestTime: ts(), startLoadTime: ts(), commitLoadTime: ts(), finishDocumentLoadTime: ts(), finishLoadTime: ts(), firstPaintTime: ts(), firstPaintAfterLoadTime: 0, navigationType: 'Other', wasFetchedViaSpdy: true, wasNpnNegotiated: true, npnNegotiatedProtocol: 'h2', wasAlternateProtocolAvailable: false, connectionInfo: 'h2' }),
      csi: () => ({ startE: Date.now(), onloadT: Date.now(), pageT: performance.now(), tran: 15 }),
    };
  }

  // --- extra navigator surface -----------------------------------------
  const navExtra = (name, value) => { try { Object.defineProperty(navProto, name, { value, enumerable: true, configurable: true, writable: true }); } catch (e) {} };
  navExtra('mediaDevices', {
    enumerateDevices: () => Promise.resolve([]),
    getUserMedia: () => Promise.reject(new Error('Permission denied')),
    getDisplayMedia: () => Promise.reject(new Error('Permission denied')),
    getSupportedConstraints: () => ({ aspectRatio: true, autoGainControl: true, brightness: true, channelCount: true, deviceId: true, echoCancellation: true, facingMode: true, frameRate: true, groupId: true, height: true, noiseSuppression: true, sampleRate: true, sampleSize: true, width: true }),
    ondevicechange: null, addEventListener: noop, removeEventListener: noop,
  });
  // Desktop Chrome's NetworkInformation omits `type` (it's mobile-only) — its
  // presence is a tell, so we leave it off.
  navExtra('connection', { effectiveType: '4g', rtt: 50, downlink: 10, saveData: false, onchange: null, addEventListener: noop, removeEventListener: noop });
  const batteryLevel = 0.7 + (SEED % 300) / 1000; // per-session, plausible
  navExtra('getBattery', mask(function getBattery() { return Promise.resolve({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: Math.round(batteryLevel * 100) / 100, onchargingchange: null, onchargingtimechange: null, ondischargingtimechange: null, onlevelchange: null, addEventListener: noop, removeEventListener: noop }); }, 'getBattery'));
  navExtra('storage', { estimate: () => Promise.resolve({ quota: 299977155072, usage: 0, usageDetails: {} }), persist: () => Promise.resolve(false), persisted: () => Promise.resolve(false) });
  navExtra('userActivation', { hasBeenActive: true, isActive: false });
  // sendBeacon really fires (POST) through the engine so analytics/telemetry
  // beacons are captured, not silently dropped.
  navExtra('sendBeacon', mask(function sendBeacon(url, data) {
    try {
      let body;
      if (data != null) body = typeof data === 'string' ? data : (data.toString ? data.toString() : '');
      globalThis.fetch(String(url), { method: 'POST', headers: { 'x-pt-kind': 'beacon' }, body }).catch(() => {});
    } catch (e) {}
    return true;
  }, 'sendBeacon'));
  navExtra('vibrate', mask(function vibrate() { return false; }, 'vibrate'));
  navExtra('clearAppBadge', mask(function clearAppBadge() { return Promise.resolve(); }, 'clearAppBadge'));
  navExtra('setAppBadge', mask(function setAppBadge() { return Promise.resolve(); }, 'setAppBadge'));

  // --- WebRTC present but leak-free -------------------------------------
  // WebRTC не декоративный: анти-бот открывает канал данных, делает предложение
  // и слушает `icecandidate`. Настоящий Chrome отвечает предложением с ufrag,
  // паролем и отпечатком DTLS, потом одним-двумя хостовыми кандидатами с mDNS-
  // именем (реальный адрес он прячет с 2019 года) и завершающим null. Пустышка,
  // которая молчит, — это браузер без сети, и вердикт по нему выносится сразу.
  const hex = (n) => {
    const out = [];
    const bytes = new Uint8Array(n);
    (globalThis.crypto && crypto.getRandomValues) ? crypto.getRandomValues(bytes) : bytes.fill(7);
    for (const b of bytes) out.push(b.toString(16).padStart(2, '0'));
    return out.join('');
  };
  const b64ish = (n) => {
    const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const bytes = new Uint8Array(n);
    (globalThis.crypto && crypto.getRandomValues) ? crypto.getRandomValues(bytes) : bytes.fill(7);
    return [...bytes].map((b) => abc[b & 63]).join('');
  };
  const dtlsPrint = () => {
    const bytes = new Uint8Array(32);
    (globalThis.crypto && crypto.getRandomValues) ? crypto.getRandomValues(bytes) : bytes.fill(7);
    return [...bytes].map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
  };

  globalThis.RTCPeerConnection = globalThis.RTCPeerConnection || mask(class RTCPeerConnection extends EventTarget {
    constructor(config) {
      super();
      const ufrag = b64ish(4), pwd = b64ish(24);
      Object.defineProperty(this, '__pt', {
        value: {
          ufrag, pwd, print: dtlsPrint(),
          // Имя mDNS вместо адреса — ровно то, что отдаёт Chrome.
          mdns: (globalThis.crypto && crypto.randomUUID ? crypto.randomUUID() : hex(16)) + '.local',
          mids: [], gathered: false, closed: false, config: config || {},
        },
        enumerable: false,
      });
      this.localDescription = null;
      this.remoteDescription = null;
      this.currentLocalDescription = null;
      this.pendingLocalDescription = null;
      this.iceGatheringState = 'new';
      this.iceConnectionState = 'new';
      this.connectionState = 'new';
      this.signalingState = 'stable';
      this.onicecandidate = null;
      this.onicegatheringstatechange = null;
      this.oniceconnectionstatechange = null;
      this.onconnectionstatechange = null;
      this.ondatachannel = null;
      this.onnegotiationneeded = null;
    }
    __ptFire(type, extra) {
      const ev = Object.assign({ type, target: this, currentTarget: this, isTrusted: true }, extra || {});
      const on = this['on' + type];
      if (typeof on === 'function') { try { on.call(this, ev); } catch (e) {} }
      try { this.dispatchEvent(ev); } catch (e) {}
    }
    __ptSdp(kind) {
      const st = this.__pt;
      const mid = st.mids.length ? st.mids : ['0'];
      return 'v=0\r\n'
        + 'o=- ' + hex(8).replace(/\D/g, '').padEnd(19, '3').slice(0, 19) + ' 2 IN IP4 127.0.0.1\r\n'
        + 's=-\r\nt=0 0\r\n'
        + 'a=group:BUNDLE ' + mid.join(' ') + '\r\n'
        + 'a=extmap-allow-mixed\r\na=msid-semantic: WMS\r\n'
        + 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n'
        + 'c=IN IP4 0.0.0.0\r\na=ice-ufrag:' + st.ufrag + '\r\na=ice-pwd:' + st.pwd + '\r\n'
        + 'a=ice-options:trickle\r\na=fingerprint:sha-256 ' + st.print + '\r\n'
        + 'a=setup:' + (kind === 'offer' ? 'actpass' : 'active') + '\r\n'
        + 'a=mid:' + mid[0] + '\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n';
    }
    createDataChannel(label, opts) {
      const st = this.__pt;
      if (!st.mids.length) st.mids.push('0');
      const channel = Object.assign(new EventTarget(), {
        label: String(label == null ? '' : label), ordered: !(opts && opts.ordered === false),
        readyState: 'connecting', bufferedAmount: 0, id: null, protocol: (opts && opts.protocol) || '',
        send() {}, close() { this.readyState = 'closed'; },
      });
      return channel;
    }
    async createOffer() {
      return { type: 'offer', sdp: this.__ptSdp('offer') };
    }
    async createAnswer() {
      return { type: 'answer', sdp: this.__ptSdp('answer') };
    }
    async setLocalDescription(desc) {
      const value = desc || { type: 'offer', sdp: this.__ptSdp('offer') };
      this.localDescription = value;
      this.currentLocalDescription = value;
      this.signalingState = value.type === 'offer' ? 'have-local-offer' : 'stable';
      this.__ptGather();
    }
    async setRemoteDescription(desc) {
      this.remoteDescription = desc || null;
      this.signalingState = 'stable';
    }
    __ptGather() {
      const st = this.__pt;
      if (st.gathered || st.closed) return;
      st.gathered = true;
      this.iceGatheringState = 'gathering';
      this.__ptFire('icegatheringstatechange');
      const st_ = st, self = this;
      // Сбор идёт не мгновенно: браузеру нужен цикл событий, и код, который
      // ждёт кандидата в обработчике, обязан успеть подписаться.
      setTimeout(() => {
        if (st_.closed) return;
        const foundation = String(Math.floor(Math.random() * 4000000000));
        const port = 50000 + Math.floor(Math.random() * 15000);
        const line = 'candidate:' + foundation + ' 1 udp 2113937151 ' + st_.mdns + ' ' + port
          + ' typ host generation 0 ufrag ' + st_.ufrag + ' network-cost 999';
        self.__ptFire('icecandidate', {
          candidate: {
            candidate: line, sdpMid: (st_.mids[0] || '0'), sdpMLineIndex: 0,
            foundation, component: 'rtp', protocol: 'udp', priority: 2113937151,
            address: st_.mdns, port, type: 'host', usernameFragment: st_.ufrag,
            relatedAddress: null, relatedPort: null, tcpType: null,
            toJSON() { return { candidate: line, sdpMid: this.sdpMid, sdpMLineIndex: 0, usernameFragment: this.usernameFragment }; },
          },
        });
        setTimeout(() => {
          if (st_.closed) return;
          self.iceGatheringState = 'complete';
          self.__ptFire('icecandidate', { candidate: null });
          self.__ptFire('icegatheringstatechange');
        }, 30);
      }, 20);
    }
    addIceCandidate() { return Promise.resolve(); }
    getStats() { return Promise.resolve(new Map()); }
    getSenders() { return []; }
    getReceivers() { return []; }
    getTransceivers() { return []; }
    getConfiguration() { return this.__pt.config; }
    setConfiguration(c) { this.__pt.config = c || {}; }
    restartIce() {}
    close() {
      this.__pt.closed = true;
      this.signalingState = 'closed';
      this.iceConnectionState = 'closed';
      this.connectionState = 'closed';
    }
  }, 'RTCPeerConnection');

  globalThis.webkitRTCPeerConnection = globalThis.RTCPeerConnection;

  // --- extra Web APIs so real sites' scripts run (and their trackers fire) --
  // A bare V8 has none of these; their absence makes analytics/framework code
  // throw before it does anything (incl. its network beacons).
  const makeStorage = () => {
    const m = new Map();
    const api = {
      getItem: (k) => (m.has(String(k)) ? m.get(String(k)) : null),
      setItem: (k, v) => { m.set(String(k), String(v)); },
      removeItem: (k) => { m.delete(String(k)); },
      clear: () => m.clear(),
      key: (i) => [...m.keys()][i] ?? null,
      get length() { return m.size; },
    };
    return new Proxy(api, {
      get: (t, p) => (p in t ? t[p] : (m.has(String(p)) ? m.get(String(p)) : undefined)),
      set: (t, p, v) => { if (p in t) return true; m.set(String(p), String(v)); return true; },
      has: (t, p) => p in t || m.has(String(p)),
      deleteProperty: (t, p) => { m.delete(String(p)); return true; },
    });
  };
  if (!globalThis.localStorage) globalThis.localStorage = makeStorage();
  if (!globalThis.sessionStorage) globalThis.sessionStorage = makeStorage();

  globalThis.IntersectionObserver = globalThis.IntersectionObserver || class IntersectionObserver {
    constructor(cb) { this._cb = cb; }
    observe(el) { const cb = this._cb, self = this; setTimeout(() => { try { cb([{ target: el, isIntersecting: true, intersectionRatio: 1, boundingClientRect: {}, intersectionRect: {}, rootBounds: null, time: 0 }], self); } catch (e) {} }, 0); }
    unobserve() {} disconnect() {} takeRecords() { return []; }
  };
  globalThis.MutationObserver = globalThis.MutationObserver || class MutationObserver { constructor(cb) { this._cb = cb; } observe() {} disconnect() {} takeRecords() { return []; } };
  globalThis.ResizeObserver = globalThis.ResizeObserver || class ResizeObserver { constructor(cb) { this._cb = cb; } observe() {} unobserve() {} disconnect() {} };
  globalThis.PerformanceObserver = globalThis.PerformanceObserver || class PerformanceObserver { constructor() {} observe() {} disconnect() {} takeRecords() { return []; } };
  if (!(globalThis.PerformanceObserver.supportedEntryTypes || []).length) {
    globalThis.PerformanceObserver.supportedEntryTypes = [];
  }

  // A media query that answers `false` to everything is not neutral, it is
  // impossible: exactly one of light/dark matches in any real browser, and a
  // widget with `theme: auto` asks both. Answer the handful that carry meaning —
  // colour scheme, motion, pointer, and the viewport dimensions we already
  // report — and stay `false` for the rest.
  globalThis.matchMedia = globalThis.matchMedia || function matchMedia(q) {
    const query = String(q);
    const num = (re) => { const m = re.exec(query); return m ? parseFloat(m[1]) : null; };
    const w = globalThis.innerWidth || 0, h = globalThis.innerHeight || 0;
    let matches = false;
    if (/prefers-color-scheme\s*:\s*light/i.test(query)) matches = true;
    else if (/prefers-color-scheme\s*:\s*dark/i.test(query)) matches = false;
    else if (/prefers-reduced-motion\s*:\s*no-preference/i.test(query)) matches = true;
    else if (/prefers-reduced-transparency\s*:\s*no-preference/i.test(query)) matches = true;
    else if (/prefers-contrast\s*:\s*no-preference/i.test(query)) matches = true;
    else if (/any-pointer\s*:\s*fine|[^-]pointer\s*:\s*fine/i.test(query)) matches = true;
    else if (/any-hover\s*:\s*hover|[^-]hover\s*:\s*hover/i.test(query)) matches = true;
    else if (/pointer\s*:\s*coarse|hover\s*:\s*none/i.test(query)) matches = false;
    else if (/orientation\s*:\s*landscape/i.test(query)) matches = w >= h;
    else if (/orientation\s*:\s*portrait/i.test(query)) matches = w < h;
    else {
      const maxW = num(/max-width\s*:\s*(\d+(?:\.\d+)?)px/i), minW = num(/min-width\s*:\s*(\d+(?:\.\d+)?)px/i);
      const maxH = num(/max-height\s*:\s*(\d+(?:\.\d+)?)px/i), minH = num(/min-height\s*:\s*(\d+(?:\.\d+)?)px/i);
      if (maxW !== null || minW !== null || maxH !== null || minH !== null) {
        matches = (maxW === null || w <= maxW) && (minW === null || w >= minW)
               && (maxH === null || h <= maxH) && (minH === null || h >= minH);
      }
    }
    const listeners = [];
    return {
      matches, media: query, onchange: null,
      addListener: (f) => { if (f) listeners.push(f); },
      removeListener: (f) => { const i = listeners.indexOf(f); if (i >= 0) listeners.splice(i, 1); },
      addEventListener: (t, f) => { if (t === 'change' && f) listeners.push(f); },
      removeEventListener: (t, f) => { const i = listeners.indexOf(f); if (i >= 0) listeners.splice(i, 1); },
      dispatchEvent: () => false,
    };
  };
  globalThis.getComputedStyle = globalThis.getComputedStyle || (() => ({ getPropertyValue: () => '', getPropertyPriority: () => '', length: 0, cssText: '', item: () => '', display: '', visibility: 'visible' }));
  globalThis.requestIdleCallback = globalThis.requestIdleCallback || ((cb) => setTimeout(() => cb({ didTimeout: false, timeRemaining: () => 50 }), 1));
  globalThis.cancelIdleCallback = globalThis.cancelIdleCallback || ((id) => clearTimeout(id));

  navExtra('serviceWorker', {
    register: () => Promise.resolve({ scope: '/', active: null, installing: null, waiting: null, update: () => Promise.resolve(), unregister: () => Promise.resolve(true), addEventListener: noop }),
    getRegistration: () => Promise.resolve(undefined),
    getRegistrations: () => Promise.resolve([]),
    ready: Promise.resolve({ active: { postMessage: noop } }),
    addEventListener: noop, removeEventListener: noop, controller: null,
  });

  try {
    // On the *prototype*, not the instance: a real `document` has no own
    // properties, so defining these on it would be a tell.
    const dproto = (globalThis.Document && globalThis.Document.prototype) || document;
    Object.defineProperty(dproto, 'visibilityState', { get: () => 'visible', configurable: true });
    Object.defineProperty(dproto, 'hidden', { get: () => false, configurable: true });
  } catch (e) {}

  if (!globalThis.TextDecoder) {
    globalThis.TextDecoder = class TextDecoder { constructor() { this.encoding = 'utf-8'; } decode(buf) { if (!buf) return ''; const a = buf instanceof Uint8Array ? buf : new Uint8Array(buf.buffer || buf); let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return s; } };
  }
  if (!globalThis.Blob) {
    // Части блоба — не только строки: браузер принимает буферы и их представления,
    // и склеивает байты. `String(new Uint8Array([104,105]))` даёт «104,105», а не
    // «hi», — и воркер, собранный из байтов, получал бы вместо кода список чисел.
    const blobPart = (x) => {
      try {
        if (x instanceof ArrayBuffer || ArrayBuffer.isView(x)) return new TextDecoder().decode(x);
      } catch (e) {}
      return String(x);
    };
    globalThis.Blob = class Blob { constructor(parts, opts) { this._p = (parts || []).map(blobPart); this.type = (opts && opts.type) || ''; this.size = this._p.reduce((n, x) => n + x.length, 0); } text() { return Promise.resolve(this._p.join('')); } arrayBuffer() { return Promise.resolve(new TextEncoder().encode(this._p.join('')).buffer); } slice() { return new Blob([]); } toString() { return this._p.join(''); } };
  }
  // Here rather than with the other web globals: `File` extends `Blob`, which is
  // defined just above, and a class body is evaluated where it is written.
  if (!globalThis.File) {
    globalThis.File = class File extends Blob {
      constructor(parts, name, opts) {
        super(parts, opts);
        this.name = String(name);
        this.lastModified = (opts && opts.lastModified) || 0;
        this.webkitRelativePath = '';
      }
    };
  }
  if (!globalThis.FileReader) {
    globalThis.FileReader = class FileReader {
      constructor() {
        this.readyState = 0; this.result = null; this.error = null;
        this.onload = null; this.onloadend = null; this.onerror = null; this.onprogress = null;
        Object.defineProperty(this, '__ls', { value: {}, enumerable: false });
      }
      addEventListener(t, fn) { (this.__ls[t] = this.__ls[t] || []).push(fn); }
      removeEventListener(t, fn) { const l = this.__ls[t]; if (!l) return; const i = l.indexOf(fn); if (i >= 0) l.splice(i, 1); }
      dispatchEvent() { return true; }
      abort() { this.readyState = 2; }
      __fire(type) {
        const ev = { type, target: this, currentTarget: this, isTrusted: true };
        try { if (typeof this['on' + type] === 'function') this['on' + type](ev); } catch (e) {}
        for (const fn of (this.__ls[type] || []).slice()) { try { fn.call(this, ev); } catch (e) {} }
      }
      __read(blob, make) {
        this.readyState = 1;
        Promise.resolve(blob && blob.text ? blob.text() : String(blob)).then((t) => {
          this.result = make(t); this.readyState = 2;
          this.__fire('load'); this.__fire('loadend');
        }, (e) => { this.error = e; this.readyState = 2; this.__fire('error'); this.__fire('loadend'); });
      }
      readAsText(b) { this.__read(b, (t) => t); }
      readAsDataURL(b) { this.__read(b, (t) => 'data:' + ((b && b.type) || 'application/octet-stream') + ';base64,' + btoa(t)); }
      readAsArrayBuffer(b) { this.__read(b, (t) => new TextEncoder().encode(t).buffer); }
      readAsBinaryString(b) { this.__read(b, (t) => t); }
    };
  }
  if (!globalThis.FormData) {
    globalThis.FormData = class FormData { constructor() { this._d = []; } append(k, v) { this._d.push([String(k), v]); } set(k, v) { this.delete(k); this.append(k, v); } get(k) { const e = this._d.find((x) => x[0] === k); return e ? e[1] : null; } getAll(k) { return this._d.filter((x) => x[0] === k).map((x) => x[1]); } has(k) { return this._d.some((x) => x[0] === k); } delete(k) { this._d = this._d.filter((x) => x[0] !== k); } forEach(f) { for (const [k, v] of this._d) f(v, k, this); } entries() { return this._d[Symbol.iterator](); } toString() { return this._d.map(([k, v]) => k + '=' + v).join('&'); } };
  }

  if (!globalThis.URLSearchParams) {
    globalThis.URLSearchParams = class URLSearchParams {
      constructor(init) { this._d = [];
        if (typeof init === 'string') { init.replace(/^[?]/, '').split('&').forEach((p) => { if (!p) return; const i = p.indexOf('='); const k = decodeURIComponent(i < 0 ? p : p.slice(0, i)); const v = i < 0 ? '' : decodeURIComponent(p.slice(i + 1).replace(/[+]/g, ' ')); this._d.push([k, v]); }); }
        else if (init && typeof init === 'object') { for (const k in init) this._d.push([k, String(init[k])]); } }
      get(k) { const e = this._d.find((x) => x[0] === k); return e ? e[1] : null; }
      getAll(k) { return this._d.filter((x) => x[0] === k).map((x) => x[1]); }
      has(k) { return this._d.some((x) => x[0] === k); }
      set(k, v) { const e = this._d.find((x) => x[0] === k); if (e) e[1] = String(v); else this._d.push([k, String(v)]); }
      append(k, v) { this._d.push([k, String(v)]); }
      delete(k) { this._d = this._d.filter((x) => x[0] !== k); }
      forEach(f) { for (const [k, v] of this._d) f(v, k, this); }
      keys() { return this._d.map((x) => x[0])[Symbol.iterator](); }
      values() { return this._d.map((x) => x[1])[Symbol.iterator](); }
      entries() { return this._d.map((x) => [x[0], x[1]])[Symbol.iterator](); }
      toString() { return this._d.map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&'); }
    };
  }
  if (!globalThis.URL || !globalThis.URL.prototype || !('searchParams' in (globalThis.URL.prototype || {}))) {
    const parse = (s) => { const m = /^([a-zA-Z][a-zA-Z0-9+.-]*:)?([/][/]([^/?#]*))?([^?#]*)([?][^#]*)?([#].*)?$/.exec(String(s)) || []; return { protocol: m[1] || '', authority: m[3] || '', path: m[4] || '', search: m[5] || '', hash: m[6] || '' }; };
    let blobSeq = 1;
    // UUID той же формы, что печатает браузер (версия 4, вариант 8..b), но
    // выведенный из семени профиля: один и тот же профиль — один и тот же ряд.
    const uuid4 = (n) => {
      let x = (SEED ^ (n * 0x9e3779b1)) >>> 0;
      const hex = [];
      for (let i = 0; i < 32; i++) {
        x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
        hex.push((x & 15).toString(16));
      }
      hex[12] = '4';
      hex[16] = ((parseInt(hex[16], 16) & 3) | 8).toString(16);
      const s = hex.join('');
      return s.slice(0, 8) + '-' + s.slice(8, 12) + '-' + s.slice(12, 16) + '-' + s.slice(16, 20) + '-' + s.slice(20);
    };
    globalThis.URL = class URL {
      constructor(url, base) {
        let p = parse(url);
        if (!p.protocol && base) { const b = parse(base); p.protocol = b.protocol; if (!p.authority) p.authority = b.authority; if (String(url)[0] !== '/') { p.path = b.path.replace(/[^/]*$/, '') + p.path; } }
        this.protocol = p.protocol || 'https:';
        const at = p.authority; const k = at.indexOf('@'); const hp = k >= 0 ? at.slice(k + 1) : at; const ui = k >= 0 ? at.slice(0, k) : '';
        const ci = hp.indexOf(':'); this.hostname = ci < 0 ? hp : hp.slice(0, ci); this.port = ci < 0 ? '' : hp.slice(ci + 1);
        this.host = hp; this.username = ui.split(':')[0] || ''; this.password = ui.split(':')[1] || '';
        this.pathname = p.path || '/'; this.search = p.search || ''; this.hash = p.hash || '';
        this.origin = this.protocol + '//' + this.host;
        this.searchParams = new globalThis.URLSearchParams(this.search);
      }
      get href() { const s = this.searchParams.toString(); return this.protocol + '//' + this.host + this.pathname + (s ? '?' + s : this.search) + this.hash; }
      set href(v) {}
      toString() { return this.href; }
      // The URL has to lead back to the object: a page that stores a Blob and
      // fetches its URL (or runs it as a Worker) expects its own bytes back, and
      // handing out a URL that resolves to nothing breaks that silently.
      static createObjectURL(obj) {
        // Форма адреса — часть отпечатка: в браузере это `blob:<origin>/<uuid>`,
        // а не короткий счётчик. Воркер видит этот адрес своим `location.href`,
        // и страница отправляет его сборщику вместе с остальным.
        const u = 'blob:' + (globalThis.location ? location.origin : 'null') + '/' + uuid4(blobSeq++);
        (globalThis.__pt_blobs || (globalThis.__pt_blobs = new Map())).set(u, obj);
        return u;
      }
      static revokeObjectURL(u) { if (globalThis.__pt_blobs) globalThis.__pt_blobs.delete(String(u)); }
    };
  }

  // Интерфейсы, определённые нами как классы, обязаны читаться нативными: в
  // браузере это `[native code]`, и сборщик отпечатка кладёт их в корзину `N`,
  // а пользовательскую функцию — в `f`. Разница видна одной строкой.
  for (const n of ['EventTarget', 'IntersectionObserver', 'MutationObserver', 'ResizeObserver',
    'PerformanceObserver', 'PerformanceObserverEntryList', 'PerformanceEntry',
    'PerformanceResourceTiming', 'PerformanceNavigationTiming',
    'NodeIterator', 'TreeWalker', 'ShadowRoot', 'URLSearchParams',
    'WritableStream', 'TransformStream', 'ReadableStream', 'Worker', 'SharedWorker',
    'OffscreenCanvas', 'BroadcastChannel', 'File', 'FileReader', 'Blob', 'DOMException',
    'MessageChannel', 'MessagePort', 'Headers', 'Request', 'Response', 'URL',
    'AbortController', 'AbortSignal', 'XMLHttpRequest', 'Node', 'Element', 'HTMLElement',
    'Document', 'Text', 'Comment', 'DocumentFragment', 'Event', 'UIEvent', 'MouseEvent',
    'PointerEvent', 'KeyboardEvent', 'InputEvent', 'FocusEvent', 'MessageEvent', 'CustomEvent',
    // Найдены коллектором самого челленджа: эти четыре читались как
    // пользовательские функции, то есть попадали в корзину `f` там, где браузер
    // даёт `N`. Четыре имени из тысячи — ровно тот разряд, которым отпечаток и
    // отличается.
    'PerformanceEntry', 'PerformanceResourceTiming', 'PerformanceNavigationTiming',
    'CustomElementRegistry']) {
    const c = globalThis[n];
    if (typeof c === 'function') { __ptNative.add(c); maskProto(c.prototype); }
  }
  for (const n of ['dispatchEvent', 'reportError', 'cancelIdleCallback', 'requestIdleCallback',
    'addEventListener', 'removeEventListener', 'queueMicrotask', 'structuredClone']) {
    if (typeof globalThis[n] === 'function') __ptNative.add(globalThis[n]);
  }
  // `console.log.toString()` читают так же, как всё остальное.
  try {
    for (const k of Object.getOwnPropertyNames(globalThis.console || {})) {
      const f = console[k];
      if (typeof f === 'function') __ptNative.add(f);
    }
  } catch (e) {}

  // `NodeFilter` — интерфейсный объект, то есть функция с константами на себе,
  // а не словарь: в браузере он попадает в ту же корзину `N`.
  try {
    const F = globalThis.NodeFilter;
    if (F && typeof F !== 'function') {
      const ctor = function NodeFilter() {};
      for (const k of Object.keys(F)) {
        Object.defineProperty(ctor, k, { value: F[k], enumerable: true, configurable: true });
      }
      __ptNative.add(ctor);
      globalThis.NodeFilter = ctor;
    }
  } catch (e) {}

  // `origin` есть у окна, `valueOf` — у location.
  if (!('origin' in globalThis)) {
    try { Object.defineProperty(globalThis, 'origin', { get: () => (globalThis.location && location.origin) || 'null', enumerable: true, configurable: true }); } catch (e) {}
  }
  try {
    const lp = globalThis.location && Object.getPrototypeOf(globalThis.location);
    if (lp && !('valueOf' in lp)) {
      Object.defineProperty(lp, 'valueOf', { value: __ptNative.add(function valueOf() { return this; }) ? function valueOf() { return this; } : undefined, enumerable: true, configurable: true });
    }
  } catch (e) {}

  // --- mask key patched globals so their toString reads native ----------
  for (const [obj, key] of [[globalThis, 'fetch'], [globalThis, 'setTimeout'], [globalThis, 'setInterval'],
    [globalThis, 'clearTimeout'], [globalThis, 'clearInterval'], [globalThis, 'queueMicrotask'],
    [globalThis, 'requestAnimationFrame'], [globalThis, 'cancelAnimationFrame'], [globalThis, 'requestIdleCallback'],
    [globalThis, 'XMLHttpRequest'], [globalThis, 'AudioContext'], [globalThis, 'Image'],
    [globalThis, 'getComputedStyle'], [globalThis, 'matchMedia'], [globalThis, 'TextEncoder'],
    [globalThis, 'TextDecoder'], [globalThis, 'Blob'], [globalThis, 'FormData'], [globalThis, 'URL'],
    [globalThis, 'WebSocket'], [globalThis, 'DOMException'], [globalThis, 'MessageChannel'],
    [globalThis, 'MessagePort'], [globalThis, 'Headers'], [globalThis, 'Request'],
    [globalThis, 'Response'], [globalThis, 'atob'], [globalThis, 'btoa'],
    [globalThis, 'structuredClone'], [globalThis, 'AbortController'], [globalThis, 'AbortSignal'],
    [globalThis, 'ReadableStream'], [globalThis, 'BroadcastChannel'], [globalThis, 'File'],
    [globalThis, 'FileReader']]) {
    if (obj[key]) mask(obj[key], key);
  }
  // `send`/`close`/`addEventListener` on a socket must read native too — the
  // class body is otherwise readable through `WebSocket.prototype.send.toString()`.
  if (globalThis.WebSocket) maskProto(globalThis.WebSocket.prototype);
  for (const n of ['MessagePort', 'Headers', 'Request', 'Response', 'DOMException']) {
    if (globalThis[n]) maskProto(globalThis[n].prototype);
  }
  // Real DOM/Web-API methods and accessors are all native — mark the ones on our
  // prototypes so `document.querySelector.toString()` and
  // `Object.getOwnPropertyDescriptor(Navigator.prototype,'userAgent').get.toString()`
  // read `[native code]`.
  for (const C of [globalThis.Node, globalThis.Element, globalThis.HTMLElement,
    globalThis.Document, globalThis.Event, globalThis.Navigator, globalThis.Screen,
    globalThis.Location, globalThis.History, globalThis.Date, globalThis.Plugin,
    globalThis.MimeType, globalThis.PluginArray, globalThis.MimeTypeArray,
    // Event interfaces the DOM runtime defines (an unmasked one leaks its whole
    // class body through `toString()` — an obvious tell).
    globalThis.CustomEvent, globalThis.UIEvent, globalThis.MouseEvent,
    globalThis.PointerEvent, globalThis.KeyboardEvent, globalThis.InputEvent,
    globalThis.FocusEvent, globalThis.MessageEvent, globalThis.Text, globalThis.Comment,
    globalThis.Performance, globalThis.PerformanceTiming, globalThis.PerformanceNavigation,
    globalThis.Crypto, globalThis.SubtleCrypto, globalThis.CryptoKey,
    // Web Workers / OffscreenCanvas (the DOM runtime's single-threaded shims).
    globalThis.Worker, globalThis.SharedWorker, globalThis.OffscreenCanvas]) {
    if (C) { mask(C, C.name); if (C.prototype) maskProto(C.prototype); }
  }

  // --- hide engine internals from ALL introspection ---------------------
  // Our Rust↔JS bridge helpers (__pt_*) and __out must never surface. Marking
  // them non-enumerable hides them from Object.keys / for-in, but
  // Object.getOwnPropertyNames, Reflect.ownKeys, getOwnPropertyDescriptor(s) and
  // hasOwnProperty still exposed them — an instant bot tell. Do both: keep them
  // non-enumerable AND filter them out at every introspection choke point. They
  // stay callable by bare name (the Rust driver's only need), which lookups by
  // name still resolve. The filters themselves are marked native (#1).
  const __ptHidden = (k) => typeof k === 'string' && (k.lastIndexOf('__pt', 0) === 0 || k === '__out');
  for (const k of Object.getOwnPropertyNames(globalThis)) {
    if (__ptHidden(k)) {
      try { Object.defineProperty(globalThis, k, { enumerable: false }); } catch (e) {}
    }
  }

  const origGOPN = Object.getOwnPropertyNames;
  const origOwnKeys = Reflect.ownKeys;
  const origKeys = Object.keys;
  const origGOPD = Object.getOwnPropertyDescriptor;
  const origGOPDs = Object.getOwnPropertyDescriptors;
  const origHOP = Object.prototype.hasOwnProperty;
  const drop = (arr) => arr.filter((k) => !__ptHidden(k));

  Object.getOwnPropertyNames = mask(function getOwnPropertyNames(o) { return drop(origGOPN(o)); }, 'getOwnPropertyNames');
  Reflect.ownKeys = mask(function ownKeys(o) { return drop(origOwnKeys(o)); }, 'ownKeys');
  Object.keys = mask(function keys(o) { return drop(origKeys(o)); }, 'keys');
  Object.getOwnPropertyDescriptor = mask(function getOwnPropertyDescriptor(o, k) {
    return __ptHidden(k) ? undefined : origGOPD(o, k);
  }, 'getOwnPropertyDescriptor');
  Object.getOwnPropertyDescriptors = mask(function getOwnPropertyDescriptors(o) {
    const d = origGOPDs(o);
    for (const k of origGOPN(d)) { if (__ptHidden(k)) delete d[k]; }
    return d;
  }, 'getOwnPropertyDescriptors');
  Object.defineProperty(Object.prototype, 'hasOwnProperty', {
    value: mask(function hasOwnProperty(k) { return __ptHidden(k) ? false : origHOP.call(this, k); }, 'hasOwnProperty'),
    configurable: true, writable: true,
  });
})();"#;

fn json_string_array(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| quoted(s)).collect();
    format!("[{}]", inner.join(","))
}

/// A JS double-quoted string literal for `s`, safely escaped.
fn quoted(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

/// Minimal escaping for embedding a Rust string inside a JS double-quoted
/// string literal.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_profiles_are_internally_coherent() {
        // Each preset's UA OS token must match its `navigator.platform`, its WebGL
        // renderer must match the OS's graphics stack, and every preset must report
        // the same Chrome major as the TLS emulation. A mismatch here is exactly the
        // tell coherent rotation exists to avoid.
        for p in FingerprintProfile::ALL {
            let s = p.stealth();
            assert!(
                s.user_agent.contains(&format!("Chrome/{CHROME_MAJOR}.")),
                "{p:?} UA is not Chrome {CHROME_MAJOR}: {}",
                s.user_agent
            );
            match p.os() {
                ProfileOs::Linux => {
                    assert!(s.user_agent.contains("Linux") && s.platform == "Linux x86_64");
                    assert!(s.webgl_renderer.contains("OpenGL"));
                }
                ProfileOs::Windows => {
                    assert!(s.user_agent.contains("Windows NT") && s.platform == "Win32");
                    assert!(s.webgl_renderer.contains("Direct3D11"));
                }
                ProfileOs::Mac => {
                    assert!(s.user_agent.contains("Mac OS X") && s.platform == "MacIntel");
                    assert!(s.webgl_renderer.contains("Metal"));
                }
            }
            // deviceMemory never exceeds Chrome's cap; vendor is always Google.
            assert!(s.device_memory_gb <= 8);
            assert_eq!(s.vendor, "Google Inc.");
        }
    }

    #[test]
    fn bootstrap_reflects_the_profile_os() {
        // The Windows preset must put Windows client-hints + its screen into the JS
        // environment; the Mac preset macOS + a retina-ish screen. If these were
        // still hardcoded, rotation would leak a Linux fingerprint under a Win/Mac UA.
        let win = bootstrap_script(&FingerprintProfile::ChromeWindows.stealth());
        assert!(
            win.contains(r#"platform: "Windows""#),
            "userAgentData.platform not Windows"
        );
        assert!(win.contains("width: 1920") && win.contains("height: 1080"));
        assert!(
            win.contains(r#"version: "148""#),
            "client-hints brand version not 148"
        );
        assert!(win.contains("Win32"), "navigator.platform not Win32");

        let mac = bootstrap_script(&FingerprintProfile::ChromeMac.stealth());
        assert!(mac.contains(r#"platform: "macOS""#));
        assert!(mac.contains("width: 1512") && mac.contains("height: 982"));
        assert!(mac.contains("MacIntel"));

        // Rotation actually changes the JS-visible fingerprint.
        assert_ne!(win, mac);
    }

    #[test]
    fn with_chrome_major_reversions_ua_and_brands_coherently() {
        let p = FingerprintProfile::ChromeLinux
            .stealth()
            .with_chrome_major(131);
        assert_eq!(p.chrome_major, 131);
        assert!(
            p.user_agent.contains("Chrome/131.0.0.0"),
            "UA: {}",
            p.user_agent
        );
        assert!(!p.user_agent.contains("Chrome/148"));
        // The bootstrap's userAgentData brand version follows the field.
        let js = bootstrap_script(&p);
        assert!(js.contains(r#"version: "131""#));
        assert!(!js.contains(r#"version: "148""#));
    }

    #[test]
    fn geo_override_keeps_the_os_identity_and_matches_the_zone() {
        // A Linux machine exiting through a Berlin IP: OS-derived identity stays
        // Linux, but timezone + locale move to Germany, coherently.
        let base = FingerprintProfile::ChromeLinux.stealth();
        let de = apply_geo(&base, "Europe/Berlin", "DE");
        assert_eq!(de.platform, base.platform, "OS identity must not change");
        assert_eq!(de.user_agent, base.user_agent);
        assert_eq!(de.screen_width, base.screen_width);
        assert_eq!(de.timezone, "Europe/Berlin");
        assert_eq!(de.timezone_offset_minutes, -60); // UTC+1 std
        assert_eq!(de.timezone_dst, "eu");
        assert_eq!(de.languages, vec!["de-DE", "de", "en"]);

        // The rendered Intl/Date shim reflects the new zone, not the default.
        let js = bootstrap_script(&de);
        assert!(js.contains("Europe/Berlin"));
        assert!(js.contains("Central European Standard Time"));
        assert!(!js.contains("America/New_York"));
    }

    #[test]
    fn geo_override_leaves_unknown_zones_coherent() {
        // An IANA zone we don't carry: keep the profile's default zone rather than
        // half-applying an incoherent one — but still adopt the country's locale.
        let base = FingerprintProfile::ChromeLinux.stealth();
        let out = apply_geo(&base, "Antarctica/Troll", "FR");
        assert_eq!(out.timezone, base.timezone, "unknown zone keeps default");
        assert_eq!(out.timezone_offset_minutes, base.timezone_offset_minutes);
        assert_eq!(out.languages, vec!["fr-FR", "fr", "en"]);
    }

    #[test]
    fn timezone_fields_are_self_consistent() {
        // Every carried zone has a real DST rule and non-empty names, and a
        // fixed-offset zone reuses one name for both seasons.
        for z in [
            "America/New_York",
            "Europe/London",
            "Europe/Paris",
            "Asia/Tokyo",
            "Australia/Sydney",
            "UTC",
        ] {
            let f = timezone_fields(z).unwrap_or_else(|| panic!("missing {z}"));
            assert!(matches!(f.dst_rule, "us" | "eu" | "none"));
            assert!(!f.name_std.is_empty() && !f.name_dst.is_empty());
            if f.dst_rule == "none" {
                assert_eq!(f.name_std, f.name_dst, "{z}: fixed zone, one name");
            }
        }
        assert!(timezone_fields("Not/AZone").is_none());
    }

    #[test]
    fn country_languages_default_to_english() {
        assert_eq!(country_languages("ZZ"), vec!["en-US", "en"]);
        assert_eq!(country_languages("jp"), vec!["ja-JP", "ja"]); // case-insensitive
    }

    #[test]
    fn default_is_the_linux_preset_and_seed_rotates() {
        // Backward-compat: the default identity is the Chrome/Linux preset.
        assert_eq!(
            StealthProfile::default().user_agent,
            FingerprintProfile::ChromeLinux.stealth().user_agent
        );
        // A seed maps to a stable preset, and sweeping seeds hits all of them.
        assert_eq!(
            FingerprintProfile::from_seed(0),
            FingerprintProfile::from_seed(3)
        );
        let seen: std::collections::HashSet<_> =
            (0..3u64).map(FingerprintProfile::from_seed).collect();
        assert_eq!(seen.len(), 3, "seed rotation did not cover all presets");
    }

    #[test]
    fn default_profile_hides_webdriver() {
        let script = injection_script(&StealthProfile::default());
        assert!(script.contains("'webdriver', false"));
        assert!(!script.contains("'webdriver', true"));
    }

    #[test]
    fn languages_render_as_js_array() {
        let profile = StealthProfile {
            languages: vec!["fr-FR".into(), "fr".into(), "en".into()],
            ..StealthProfile::default()
        };
        let script = injection_script(&profile);
        assert!(script.contains(r#"["fr-FR","fr","en"]"#));
        assert!(script.contains(r#"'language', "fr-FR""#));
    }

    #[test]
    fn bootstrap_substitutes_all_placeholders() {
        let script = bootstrap_script(&StealthProfile::default());
        for token in [
            "__UA__",
            "__APPVERSION__",
            "__PLATFORM__",
            "__VENDOR__",
            "__LANG0__",
            "__LANGS__",
            "__HW__",
            "__MEM__",
            "__WEBGL_VENDOR__",
            "__WEBGL_RENDERER__",
            "__TZ__",
            "__TZ_OFFSET__",
            "__TZ_DST__",
            "__TZ_NAME_STD__",
            "__TZ_NAME_DST__",
        ] {
            assert!(!script.contains(token), "unsubstituted placeholder {token}");
        }
        assert!(script.contains("webdriver: false"));
        assert!(script.contains("hardwareConcurrency: 8"));
        assert!(script.contains(r#"languages: Object.freeze(["en-US","en"])"#));
    }

    #[test]
    fn escaping_prevents_string_breakout() {
        let profile = StealthProfile {
            user_agent: r#"evil" + alert(1) + ""#.into(),
            ..StealthProfile::default()
        };
        let script = injection_script(&profile);
        // The quote must be escaped, not left to terminate the JS string.
        assert!(script.contains(r#"evil\" + alert(1) + \""#));
    }
}
