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
    /// The timezone was set for this context (from its proxy's exit IP), so it
    /// must win over the process's: native `Intl` only knows the OS zone, and the
    /// shim, which carries `timezone`, stays on.
    #[serde(default)]
    pub pin_timezone: bool,
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

/// The Chrome major version every profile's UA / client hints report.
///
/// Must match what the engine actually exposes: the property graph, computed
/// style order, WebGL limits etc. are captured from Chrome 151, and a browser
/// claiming 148 while shaped like 151 is visible through any property added
/// in between.
///
/// TLS uses the newest profile `wreq-util` knows (Chrome 149); ClientHello did
/// not change between 149 and 151, the property surface did.
pub const CHROME_MAJOR: &str = "151";
/// Full build version of the Chrome the fingerprint was captured from.
pub const CHROME_FULL: &str = "151.0.7922.173";

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
        // `navigator.deviceMemory` is not a constant 8: Chrome rounds physical
        // memory to the nearest power of two. Chrome 151 on a 16 GB machine
        // reports 16; the spec's cap of 8 is gone.
        fn device_memory_gb() -> u32 {
            // The pool asks the same question separately
            // (`nokk_pool::Isolate::physical_memory_bytes`); not worth linking
            // two crates for one line.
            #[cfg(target_os = "linux")]
            let bytes = std::fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find_map(|l| l.strip_prefix("MemTotal:"))
                        .and_then(|r| r.split_whitespace().next()?.parse::<u64>().ok())
                        .map(|kb| kb * 1024)
                })
                .unwrap_or(8 * 1024 * 1024 * 1024);
            #[cfg(not(target_os = "linux"))]
            let bytes: u64 = 8 * 1024 * 1024 * 1024;
            let gb = (bytes as f64) / (1024.0 * 1024.0 * 1024.0);
            let mut v = 1u32;
            while (v as f64) * 1.5 < gb && v < 64 {
                v *= 2;
            }
            v
        }

        let common = |ua: &str, hw: u32, webgl_vendor: &str, webgl_renderer: &str| StealthProfile {
            user_agent: ua.to_string(),
            platform: platform.to_string(),
            ua_platform: ua_platform.to_string(),
            chrome_major: CHROME_MAJOR.parse().unwrap_or(151),
            languages: vec!["en-US".into(), "en".into()],
            hardware_concurrency: hw,
            device_memory_gb: device_memory_gb(),
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
            pin_timezone: false,
        };
        match self {
            Self::ChromeLinux => common(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/151.0.0.0 Safari/537.36",
                8,
                "Google Inc. (Intel)",
                // Captured from Chrome 148 on a Mesa machine: ANGLE's form has the
                // chip model in parentheses and "OpenGL ES 3.2", not "OpenGL 4.6".
                "ANGLE (Intel, Mesa Intel(R) Xe Graphics (TGL GT2), OpenGL ES 3.2)",
            ),
            Self::ChromeWindows => common(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/151.0.0.0 Safari/537.36",
                16,
                "Google Inc. (NVIDIA)",
                "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            Self::ChromeMac => common(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
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
        p.pin_timezone = true;
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
/// Internal writes. Many interface properties are read-only to the page but
/// written by the engine via `__pt_write`: if the setter for a name was removed
/// (see [`IFACE_KINDS`]) it is found in the store, otherwise it falls back to
/// plain assignment. Shipped as a separate script that runs first (see
/// [`PT_WRITE_HELPER`]), since earlier layers call it too.
/// A data table for a template, as `JSON.parse("...")`. Written as a literal,
/// V8 keeps a boilerplate copy of it and an allocation site per nested literal
/// for as long as the function lives: about a megabyte per context.
fn json_table(table: &str) -> String {
    if serde_json::from_str::<serde_json::Value>(table).is_err() {
        return table.to_string();
    }
    match serde_json::to_string(table) {
        Ok(quoted) => format!("JSON.parse({quoted})"),
        Err(_) => table.to_string(),
    }
}

pub fn write_helper_script() -> String {
    PT_WRITE_HELPER.to_string()
}

const PT_WRITE_HELPER: &str = r#"(() => {
  if (globalThis.__pt_write) return;
  // Engine-thrown errors (binding TypeError, DOMException) are born in C++ in
  // the browser and take no stack frames. Ours are thrown from JS, and our own
  // frames ate into `Error.stackTraceLimit`. Capture extra; the formatter
  // (`__pt_formatStack`) hides our frames and trims to the page's limit.
  {
    const __Err = Error;
    let depth = 0;
    Object.defineProperty(globalThis, '__pt_mkErr', {
      value: (C, ...args) => {
        let lim; try { lim = __Err.stackTraceLimit; } catch (e) {}
        const bump = typeof lim === 'number' && lim >= 0 && lim < Infinity;
        if (bump) { try { __Err.stackTraceLimit = lim + 16; } catch (e) {} }
        depth++;
        try { return new C(...args); } finally { depth--; if (bump) { try { __Err.stackTraceLimit = lim; } catch (e) {} } }
      },
      writable: true, enumerable: false, configurable: true,
    });
    // Whether the engine is building an error right now: a DOMException created
    // by the page carries no stack in the browser, one thrown by a binding does.
    Object.defineProperty(globalThis, '__pt_errDepth', { value: () => depth, writable: true, enumerable: false, configurable: true });
  }
  // Stub members (declared by Chrome, not implemented here) keep their values
  // in one store and are told apart by the literal they were born from: a set
  // holding each of the thousands of stub functions cost 256 KB per context.
  // Only functions from stub-only literals may be added.
  {
    const loc = typeof globalThis.__pt_fnLocation === 'function' ? globalThis.__pt_fnLocation : null;
    const boot = typeof globalThis.__pt_isBoot === 'function' ? globalThis.__pt_isBoot : null;
    const sites = new Set(), other = new WeakSet();
    const site = (f) => { const l = loc(f); return l ? l[1] + ':' + l[2] : ''; };
    const kit = {
      slots: new WeakMap(),
      add(f) {
        if (typeof f !== 'function') return f;
        if (loc !== null && boot !== null && boot(f)) sites.add(site(f)); else other.add(f);
        return f;
      },
      has(f) {
        if (typeof f !== 'function') return false;
        if (other.has(f)) return true;
        return loc !== null && boot !== null && boot(f) && sites.has(site(f));
      },
    };
    Object.defineProperty(globalThis, '__pt_stubMembers', { value: kit, writable: true, enumerable: false, configurable: true });
  }
  // A method born with its name and length, calling `f`: editing either
  // afterwards turns a function into dictionary mode (~260 bytes each).
  {
    const HOLD = [
      (n, f) => ({ [n]() { return f.apply(this, arguments); } })[n],
      (n, f) => ({ [n](a) { return f.apply(this, arguments); } })[n],
      (n, f) => ({ [n](a, b) { return f.apply(this, arguments); } })[n],
      (n, f) => ({ [n](a, b, c) { return f.apply(this, arguments); } })[n],
      (n, f) => ({ [n](a, b, c, d) { return f.apply(this, arguments); } })[n],
      (n, f) => ({ [n](a, b, c, d, e) { return f.apply(this, arguments); } })[n],
      (n, f) => ({ [n](a, b, c, d, e, g) { return f.apply(this, arguments); } })[n],
    ];
    Object.defineProperty(globalThis, '__pt_method', {
      value: (n, f, len) => {
        const l = len === undefined ? f.length : len;
        const m = HOLD[l < HOLD.length ? l : 0](n, f);
        if (l >= HOLD.length) { try { Object.defineProperty(m, 'length', { value: l, configurable: true }); } catch (e) {} }
        return m;
      },
      writable: true, enumerable: false, configurable: true,
    });
  }
  const writers = new WeakMap();
  globalThis.__pt_writers = writers;
  globalThis.__pt_write = (obj, name, value) => {
    if (!obj) return;
    for (let p = obj; p; p = Object.getPrototypeOf(p)) {
      const w = writers.get(p);
      if (w && w[name]) { w[name].call(obj, value); return; }
      const d = Object.getOwnPropertyDescriptor(p, name);
      if (d) {
        if (d.set) { d.set.call(obj, value); return; }
        if (!d.get) { try { obj[name] = value; } catch (e) {} return; }
      }
    }
    try { obj[name] = value; } catch (e) {}
  };
})();
"#;

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
/// Whether V8's own `Intl` is usable. With ICU data it answers like the
/// browser (currencies, plurals, time zones); without it a stub stands in.
/// Set by the core once the pool reports the data is loaded.
static NATIVE_INTL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Marks native `Intl` as usable (see [`NATIVE_INTL`]).
pub fn set_native_intl(on: bool) {
    NATIVE_INTL.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Whether native `Intl` is usable.
pub fn native_intl() -> bool {
    NATIVE_INTL.load(std::sync::atomic::Ordering::Relaxed)
        || std::env::var("NOKK_NATIVE_INTL").is_ok()
}

/// Whether to show engine frames in `error.stack`. Normally not, the browser
/// has none (see [`STACK_TEMPLATE`]); `NOKK_STACK_RAW=1` keeps them for
/// debugging what a page script tripped on.
fn stack_raw() -> bool {
    std::env::var("NOKK_STACK_RAW").is_ok()
}

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
        .replace("__CHROME_FULL__", CHROME_FULL)
        .replace("__CHROME_MAJOR__", &profile.chrome_major.to_string())
        .replace("__UA_PLATFORM__", &quoted(&profile.ua_platform))
        .replace("__SCREEN_W__", &profile.screen_width.to_string())
        .replace("__SCREEN_H__", &profile.screen_height.to_string())
        .replace("__AVAIL_H__", &profile.avail_height.to_string())
        .replace("__COLOR_DEPTH__", &profile.color_depth.to_string());

    // The Intl shim shadows the prebuilt V8's native Intl/Date-locale APIs, which
    // ICU-abort the whole process (this build lacks working ICU data). It also
    // pins timezone/locale to the profile — both fingerprint vectors.
    // Installed when V8 has no ICU data, or when the context's timezone comes from
    // its proxy: native `Intl` answers like the browser but only in the OS zone.
    let intl = if native_intl() && !profile.pin_timezone {
        String::new()
    } else {
        INTL_SHIM_TEMPLATE
            .replace("__TZ__", &quoted(&profile.timezone))
            .replace("__LANG0__", &lang0)
            .replace(
                "__TZ_OFFSET__",
                &profile.timezone_offset_minutes.to_string(),
            )
            .replace("__TZ_DST__", &quoted(&profile.timezone_dst))
            .replace("__TZ_NAME_STD__", &quoted(&profile.timezone_name_std))
            .replace("__TZ_NAME_DST__", &quoted(&profile.timezone_name_dst))
    };

    let timers = TIMERS_TEMPLATE.replace(
        "__FAST_TIMERS__",
        if fast_timers() { "true" } else { "false" },
    );

    let stack = STACK_TEMPLATE.replace("__STACK_RAW__", if stack_raw() { "true" } else { "false" });

    format!("{env}\n{intl}\n{timers}\n{stack}\n{PERFORMANCE_TEMPLATE}\n{CRYPTO_TEMPLATE}\n{FETCH_TEMPLATE}")
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
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_replace = __sm(String.prototype.replace, 'replace'),
    __s_split = __sm(String.prototype.split, 'split');
  // Interface object shape. A sloppy function has own `arguments` and `caller`,
  // which browser interfaces lack (two extra names per interface in a graph
  // walk). A strict function has exactly `length, name, prototype` and, unlike
  // a class, throws "Illegal constructor" when called without `new` too.
  globalThis.__ptIllegal = (function () {
    'use strict';
    // Named at birth when a name is given: editing `name` turns a function
    // into dictionary mode.
    return function (n) {
      if (n === undefined) return function () { throw __pt_mkErr(TypeError, 'Illegal constructor'); };
      return ({ [n]: function () { throw __pt_mkErr(TypeError, 'Illegal constructor'); } })[n];
    };
  })();
  globalThis.__ptName = (f, n) => {
    if (f.name !== n) { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} }
    return f;
  };
  // JSON captured before any page code: the engine serializes its own queues
  // and must not go through the page's `JSON.stringify`, which the page could
  // replace to see emulator internals.
  if (!globalThis.__ptJSON) {
    Object.defineProperty(globalThis, "__ptJSON", {
      value: { stringify: JSON.stringify, parse: JSON.parse },
      enumerable: false, configurable: true, writable: true,
    });
  }
  const win = globalThis;

  // Host objects the Chrome way: their properties live on a constructor's
  // prototype (as getters), so instances carry no own enumerable props —
  // `Object.keys(navigator)` is [], the prototype chain is correct, and
  // `navigator instanceof Navigator` holds. A plain object literal (the old
  // approach) fails all three, an instant headless tell.
  const defClass = (name, proto) => {
    const Ctor = __ptIllegal(name);
    // Prototype from a V8 template (immutable, like Chrome's); see __pt_protoTemplates.
    if (proto) {
      try {
        Ctor.prototype = proto;
        Object.defineProperty(proto, 'constructor', { value: Ctor, writable: true, enumerable: false, configurable: true });
      } catch (e) {}
    }
    // Without this `Object.prototype.toString.call(navigator)` gives
    // `[object Object]` instead of `[object Navigator]`, the cheapest spoof check.
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
    // Same rule: a browser method is not a constructor and has no `prototype`.
    let m = fn;
    try {
      const methodish = /^[a-z_$]/.test(String(name))
        && Object.getOwnPropertyNames((fn && fn.prototype) || {}).length <= 1;
      if (typeof fn === 'function' && methodish && Object.getOwnPropertyDescriptor(fn, 'prototype')) {
        m = __pt_method(name, fn);
      }
    } catch (e) {}
    try { Object.defineProperty(proto, name, { value: m, enumerable: true, configurable: true, writable: true }); } catch (e) {}
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
      { brand: "Not=A?Brand", version: "99" }, { brand: "Google Chrome", version: "__CHROME_MAJOR__" }, { brand: "Chromium", version: "__CHROME_MAJOR__" }
    ], mobile: false, platform: __UA_PLATFORM__ },
  });
  win.navigator = Object.create(NavigatorProto);

  win.window = win; win.self = win; __pt_write(win, 'top', win); win.parent = win; win.frames = win;
  __pt_write(win, 'length', 0); win.name = ""; win.closed = false;

  // --- screen -----------------------------------------------------------
  const ScreenProto = defClass("Screen");
  staticProps(ScreenProto, {
    width: __SCREEN_W__, height: __SCREEN_H__, availWidth: __SCREEN_W__, availHeight: __AVAIL_H__, availTop: 0, availLeft: 0,
    colorDepth: __COLOR_DEPTH__, pixelDepth: __COLOR_DEPTH__, isExtended: false,
    orientation: { type: "landscape-primary", angle: 0 },
  });
  win.screen = Object.create(ScreenProto);
  // The window must fit the available screen area. A maximized window fills
  // it, and its content is 111 px shorter (Chrome's tab strip and toolbar).
  win.outerWidth = __SCREEN_W__; win.outerHeight = __AVAIL_H__;
  win.innerWidth = __SCREEN_W__; win.innerHeight = __AVAIL_H__ - 111;
  win.devicePixelRatio = 1;
  // Window position: a maximized full-width window starts at 0, so compute it.
  {
    const w = win.screen.width || win.outerWidth, h = win.screen.height || win.outerHeight;
    const left = win.outerWidth >= w ? 0 : Math.max(0, Math.round((w - win.outerWidth) / 2));
    const top = win.outerHeight >= h ? 0 : Math.max(0, Math.round((h - win.outerHeight) / 2));
    for (const [k, v] of [['screenX', left], ['screenLeft', left], ['screenY', top], ['screenTop', top]]) {
      try { Object.defineProperty(win, k, { get: () => v, enumerable: true, configurable: true }); } catch (e) {}
    }
  }

  // --- location (getters read a backing store the Rust driver updates) --
  const __T = (globalThis.__pt_protos !== undefined ? globalThis.__pt_protos : (() => { let t = null; try { if (typeof __pt_protoTemplates === 'function') t = __pt_protoTemplates() || null; } catch (e) {} try { Object.defineProperty(globalThis, '__pt_protos', { value: t, configurable: true }); } catch (e) {} return t; })());
  const LocationProto = defClass("Location", __T && __T.loc);
  const locState = { href: "about:blank", protocol: "about:", host: "", hostname: "", port: "", pathname: "blank", search: "", hash: "", origin: "null" };
  // A page navigating itself is not a detail: `location.href = …`,
  // `location.replace(…)` and `location.reload()` are how a form handoff, an
  // OAuth bounce and — the reason this exists — a Cloudflare challenge finish.
  // Ours only rewrote the address bar, so the last step of those flows silently
  // never happened. The request goes to the driver, which performs a real
  // navigation of this context.
  const navQueue = [];
  const askNav = (raw, replace, post) => {
    const url = String(raw);
    if (!url) return;
    let abs = url;
    try { abs = new URL(url, locState.href).href; } catch (e) {}
    // Top stack frames tell who navigated the page; sent with the request for
    // debugging unexpected reloads.
    let via = '';
    try { via = __s_slice(__s_slice(__s_split(String(new Error().stack || ''), '\n'), 1, 4).join(' | '), 0, 300); } catch (e) {}
    const op = { url: abs, replace: !!replace, via };
    if (post) { op.method = 'POST'; op.body = String(post.body); op.contentType = String(post.contentType); }
    navQueue.push(op);
  };
  globalThis.__pt_drainNavQueue = () => navQueue.splice(0);
  // Form submission (dom_runtime): GET puts the query in the URL, POST in the body.
  Object.defineProperty(globalThis, '__pt_navSubmit', { value: (url, method, body, contentType) => askNav(url, false, method === 'POST' ? { body, contentType } : null), writable: true, enumerable: false, configurable: true });

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
  // `window.location = url` navigates like `location.href = url` (many flows,
  // including the Cloudflare challenge, end this way). A data property here
  // would just overwrite `location` with a string.
  const locationObject = (__T && __T.location && Object.getPrototypeOf(__T.location) === LocationProto) ? __T.location : Object.create(LocationProto);
  accessor(win, 'location', () => locationObject, (v) => {
    if (v !== locationObject) askNav(v, false);
  });
  // Rust calls this on navigation to populate `location` from the real URL —
  // a static `about:blank` is an instant tell (and breaks relative logic).
  globalThis.__pt_setLocation = (o) => { for (const k in o) if (k in locState) locState[k] = o[k]; };

  // --- history ----------------------------------------------------------
  const HistoryProto = defClass("History");
  // The challenge calls `replaceState({}, '', 'https://example.org/')` and
  // records whether it throws SecurityError. Follows Chrome's
  // History::CanChangeToUrl: state is cloned, URL must be same origin and
  // scheme (about:/opaque: only the fragment may change), and on success the
  // document URL changes without navigation.
  // A tab opened by a user has already been through the new-tab page: Chrome's length is 2.
  const hist = { length: 2, scrollRestoration: 'auto', state: null };
  // History length belongs to the tab, not the document: carried over on
  // navigation (`__pt_carryOut`/`__pt_carryIn`).
  (globalThis.__pt_carryParts || (globalThis.__pt_carryParts = {})).hist = {
    out: () => hist.length,
    in: (n) => { if (typeof n === 'number' && n > 0) hist.length = n; },
  };
  accessor(HistoryProto, 'length', () => hist.length);
  accessor(HistoryProto, 'scrollRestoration', () => hist.scrollRestoration, (v) => {
    const s = String(v);
    if (s === 'auto' || s === 'manual') hist.scrollRestoration = s;
  });
  accessor(HistoryProto, 'state', () => hist.state);
  const stripHash = (u) => { const i = __s_indexOf(u, '#'); return i < 0 ? u : __s_slice(u, 0, i); };
  const canChangeTo = (u) => {
    const doc = locState.href;
    const docUrl = (() => { try { return new URL(doc); } catch (e) { return null; } })();
    // about:blank, about:srcdoc, data:, file:, opaque origin: Chrome only
    // allows changing the fragment.
    if (!docUrl || /^about:/.test(doc) || locState.origin === 'null' || docUrl.protocol === 'file:' || docUrl.protocol === 'data:') return stripHash(u.href) === stripHash(doc);
    if (u.protocol !== docUrl.protocol || u.host !== docUrl.host) return false;
    return u.origin !== 'null' && u.origin === docUrl.origin;
  };
  const stateObjectAdded = (method, args, push) => {
    if (args.length < 2) throw __pt_mkErr(TypeError, "Failed to execute '" + method + "' on 'History': 2 arguments required, but only " + args.length + ' present.');
    const data = args[0], url = args[2];
    let state;
    try { state = globalThis.structuredClone(data); } catch (e) {
      const why = __s_replace(String(e && e.message || ''), /^Failed to execute 'structuredClone' on 'Window': /, '');
      const err = __pt_mkErr(globalThis.DOMException || Error, "Failed to execute '" + method + "' on 'History': " + why, 'DataCloneError');
      throw err;
    }
    if (url !== undefined && url !== null && String(url) !== '') {
      const raw = String(url);
      let u = null;
      try { u = new URL(raw, locState.href); } catch (e) {}
      if (!u || !canChangeTo(u)) {
        // The document's origin, not `location.origin`: an empty frame inherits
        // it from the parent while its `location.origin` is "null".
        let docOrigin = locState.origin;
        try { if (docOrigin === 'null' && typeof globalThis.origin === 'string' && globalThis.origin !== 'null') docOrigin = globalThis.origin; } catch (e) {}
        throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute '" + method + "' on 'History': A history state object with URL '" + (u ? u.href : raw) + "' cannot be created in a document with origin '" + docOrigin + "' and URL '" + locState.href + "'.", 'SecurityError');
      }
      locState.href = u.href; locState.protocol = u.protocol; locState.host = u.host; locState.hostname = u.hostname;
      locState.port = u.port; locState.pathname = u.pathname; locState.search = u.search; locState.hash = u.hash;
    }
    if (push) hist.length += 1;
    hist.state = state;
  };
  protoMethod(HistoryProto, 'pushState', function pushState(data, unused, url) { stateObjectAdded('pushState', arguments, true); });
  protoMethod(HistoryProto, 'replaceState', function replaceState(data, unused, url) { stateObjectAdded('replaceState', arguments, false); });
  protoMethod(HistoryProto, 'back', function back() {});
  protoMethod(HistoryProto, 'forward', function forward() {});
  protoMethod(HistoryProto, 'go', function go(delta) {});
  win.history = Object.create(HistoryProto);

  // The tag is an own property: the global's prototype chain is shared with
  // ordinary objects.
  try {
    Object.defineProperty(win, Symbol.toStringTag, { value: 'Window', configurable: true });
  } catch (e) {}

  // Browser console: twenty-odd methods, each with its own name and
  // `[native code]`, the object tags as `[object console]`. Messages are kept:
  // pages report errors there ("[Cloudflare Turnstile] Unhandled error: ...").
  const CONSOLE = ['assert', 'clear', 'context', 'count', 'countReset', 'createTask', 'debug',
    'dir', 'dirxml', 'error', 'group', 'groupCollapsed', 'groupEnd', 'info', 'log', 'profile',
    'profileEnd', 'table', 'time', 'timeEnd', 'timeLog', 'timeStamp', 'trace', 'warn'];
  const SPOKEN = { log: 1, info: 1, warn: 1, error: 1, debug: 1, trace: 1, assert: 1, dir: 1 };
  const said = [];
  globalThis.__pt_drainConsole = () => said.splice(0);
  // Display for the log without running page code: the browser console calls
  // no toString/toJSON/getters (except formatting below), and pages measure it.
  const show = (v) => {
    try {
      if (typeof v === 'string') return v;
      if (v instanceof Error) return String(v.stack || v.message || v);
      if (typeof v === 'function') return 'function ' + (v.name || '');
      if (typeof v === 'symbol') return v.toString();
      if (typeof v === 'object' && v !== null) {
        const tag = Object.prototype.toString.call(v);
        if (Array.isArray(v)) return 'Array(' + v.length + ')';
        if (tag !== '[object Object]') return tag;
        const parts = [];
        for (const k of __s_slice(Object.keys(v), 0, 12)) {
          const d = Object.getOwnPropertyDescriptor(v, k);
          if (!d || !('value' in d)) { parts.push(k + ': (...)'); continue; }
          const x = d.value;
          parts.push(k + ': ' + (typeof x === 'string' ? __s_slice(JSON.stringify(x), 0, 60) : typeof x === 'object' && x !== null ? Object.prototype.toString.call(x) : typeof x === 'function' ? 'ƒ' : String(x)));
        }
        return '{' + parts.join(', ') + '}';
      }
      return String(v);
    } catch (e) { return '?'; }
  };
  // V8 formatting (builtins-console.cc): for log/debug/info/warn/error/trace/
  // group/groupCollapsed (and assert from the second arg when the condition is
  // false), a first string with %d/%i/%f/%s converts the next arg via
  // parseInt/parseFloat/String, i.e. ToString with hint "string"; %c/%o/%O
  // consume an arg unconverted, %% and unknown consume nothing; Symbol under
  // %d gives NaN without throwing. Exceptions from toString propagate.
  // Checked against Chrome.
  const FORMATTED = { log: 1, debug: 1, info: 1, warn: 1, error: 1, trace: 1, group: 1, groupCollapsed: 1, assert: 1 };
  const LABELED = { count: 1, countReset: 1, time: 1, timeEnd: 1, timeLog: 1, timeStamp: 1, profile: 1, profileEnd: 1, context: 1 };
  // Methods whose arguments all go into the message (described by the inspector).
  const REPORTED = { log: 1, debug: 1, info: 1, warn: 1, error: 1, trace: 1, dir: 1, dirxml: 1, table: 1, group: 1, groupCollapsed: 1, assert: 1 };
  const format = (args, idx) => {
    if (args.length < idx + 2 || typeof args[idx] !== 'string') return;
    const s = args[idx]; let off = 0, ai = idx + 1;
    while (ai < args.length) {
      const p = __s_indexOf(s, '%', off);
      if (p < 0 || p === s.length - 1) break;
      const c = s[p + 1], cur = args[ai];
      if (c === 'd' || c === 'i') args[ai] = typeof cur === 'symbol' ? NaN : parseInt(cur, 10);
      else if (c === 'f') args[ai] = typeof cur === 'symbol' ? NaN : parseFloat(cur);
      else if (c === 's') args[ai] = String(cur);
      else if (c === 'c' || c === 'o' || c === 'O') { /* consumed as is */ }
      else if (c === '%') { off = p + 2; continue; }
      else { off = p + 1; continue; }
      ai++; off = p + 2;
    }
  };
  const con = {};
  for (const name of CONSOLE) {
    con[name] = { [name]: function () {
      const args = Array.prototype.slice.call(arguments);
      if (FORMATTED[name]) {
        if (name === 'assert') { if (args[0]) return undefined; format(args, 1); }
        else format(args, 0);
      } else if (LABELED[name] && args.length) {
        // Counter/timer label: ToString of the first arg (Symbol throws); via a
        // template string so no `String` frame appears on the stack.
        if (typeof args[0] === 'symbol') throw __pt_mkErr(TypeError, 'Cannot convert a Symbol value to a string');
        args[0] = `${args[0]}`;
      } else if (name === 'createTask') {
        if (typeof args[0] !== 'string' || !args[0]) throw new Error('First argument must be a non-empty string.');
        const task = {}; Object.defineProperty(task, 'run', { value: ({ run(f) { return f(); } }).run, writable: true, enumerable: true, configurable: true });
        return task;
      }
      // Like V8's inspector (v8-console-message.cc): message text is ToString of
      // the first arg (object, function; arrays element-wise), and any error arg
      // is described via its own toString. Exceptions are swallowed. Pages
      // measure exactly these calls and their stacks.
      const texts = [];
      if (REPORTED[name]) {
        const base = name === 'assert' ? 1 : 0;
        // V8ValueStringBuilder: plain object -> Object.prototype.toString (no
        // page code); Date, function, native error, RegExp -> ToString (their
        // toString is called); arrays element-wise joined by commas, null and
        // undefined inside are skipped.
        const tagOf = (v) => { try { return Object.prototype.toString.call(v); } catch (e) { return '[object Object]'; } };
        // By internal tag, not instanceof: objects from another window (the
        // widget logs to its srcdoc frame's console) would not match otherwise.
        const viaToString = (v) => { if (typeof v === 'function') return true; const t = tagOf(v); return t === '[object Date]' || t === '[object RegExp]' || t === '[object Error]'; };
        const str = (v, depth, inArray) => {
          try {
            if (v === null || v === undefined) return inArray ? '' : String(v);
            if (typeof v === 'symbol') return v.toString();
            if (typeof v !== 'object' && typeof v !== 'function') return String(v);
            { const t = tagOf(v); if (t === '[object String]' || t === '[object Number]' || t === '[object Boolean]' || t === '[object BigInt]') { try { return String(v.valueOf()); } catch (e) { return ''; } } }
            if (Array.isArray(v)) { if (depth > 3) return ''; const parts = []; for (let i = 0; i < v.length && i < 100; i++) parts.push(str(v[i], depth + 1, true)); return parts.join(','); }
            if (viaToString(v)) return `${v}`;
            return tagOf(v);
          } catch (e) { return ''; }
        };
        if (args.length > base) texts[base] = str(args[base], 0, false);
        // Every error arg is described via its toString, except the first,
        // which already went through ToString above.
        for (let i = base + 1; i < args.length; i++) {
          const v = args[i];
          if (v !== null && typeof v === 'object' && tagOf(v) === '[object Error]') { try { texts[i] = String(v.toString()); } catch (e) {} }
        }
      }
      if (!SPOKEN[name] || said.length > 256) return undefined;
      const parts = [];
      for (let i = 0; i < args.length && i < 8; i++) parts.push(typeof texts[i] === 'string' ? texts[i] : show(args[i]));
      said.push([name, __s_slice(parts.join(' '), 0, 600)]);
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
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_toUpperCase = __sm(String.prototype.toUpperCase, 'toUpperCase'),
    __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_toLowerCase = __sm(String.prototype.toLowerCase, 'toLowerCase'),
    __s_split = __sm(String.prototype.split, 'split');
  const TZ = __TZ__, LOCALE = __LANG0__;
  const norm = (l) => Array.isArray(l) ? (l[0] || LOCALE) : (l || LOCALE);
  const list = (l) => Array.isArray(l) ? __s_slice(l) : (l == null ? [] : [l]);

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

  // `Intl.Locale` needs `maximize()` (pages use it to find the region) and
  // `getTextInfo()` (writing direction); a missing method crashes whole bundles
  // (CapSolver's does). Likely subtags for living languages and the RTL list
  // are enough, no full CLDR.
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
    if (!(this instanceof Locale)) throw __pt_mkErr(TypeError, "Constructor Intl.Locale requires 'new'");
    const parts = __s_split(String(norm(tag) || 'en-US'), '-');
    const opts = options || {};
    const script = parts.find((p) => p.length === 4 && /^[A-Za-z]+$/.test(p));
    const region = __s_slice(parts, 1).find((p) => /^([A-Za-z]{2}|\d{3})$/.test(p));
    const set = (k, v) => Object.defineProperty(this, k, { value: v, enumerable: true, configurable: true });
    set('language', opts.language || __s_toLowerCase(parts[0]));
    set('script', opts.script || (script ? __s_toUpperCase(script[0]) + __s_toLowerCase(__s_slice(script, 1)) : undefined));
    set('region', opts.region || (region ? __s_toUpperCase(region) : undefined));
    for (const k of ['calendar', 'caseFirst', 'collation', 'hourCycle', 'numeric', 'numberingSystem']) {
      set(k, opts[k]);
    }
    set('baseName', [this.language, this.script, this.region].filter(Boolean).join('-'));
  }
  Locale.prototype = {
    toString() { return this.baseName; },
    maximize() {
      const [script, region] = LIKELY[this.language] || ['Latn', __s_toUpperCase(this.language || 'en')];
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
        .replace("__RTC_CHROME__", &json_table(RTC_CHROME))
        .replace("__GL_ARITY__", &json_table(GL_ARITY))
        .replace("__WEBGL_EXT_SHAPES__", &json_table(WEBGL_EXT_SHAPES))
        .replace("__WEBGL_VENDOR__", &quoted(&profile.webgl_vendor))
        .replace("__WEBGL_RENDERER__", &quoted(&profile.webgl_renderer))
        .replace("__FP_SEED__", &identity_seed(profile).to_string())
}

/// The canvas/audio seed for a profile: FNV-1a over the fields that make up the
/// machine's identity. Deterministic across runs and processes on purpose — a
/// device's canvas hash does not change between visits, and one that does is a
/// tell. Distinct profiles (`--rotate-fingerprint`) still get distinct seeds.
fn identity_seed(profile: &StealthProfile) -> u32 {
    let mut h: u32 = 2166136261;
    let mut eat = |s: &str| {
        for b in s.as_bytes() {
            h ^= u32::from(*b);
            h = h.wrapping_mul(16777619);
        }
        h ^= 0xff;
        h = h.wrapping_mul(16777619);
    };
    eat(&profile.user_agent);
    eat(&profile.platform);
    eat(&profile.webgl_vendor);
    eat(&profile.webgl_renderer);
    eat(&profile.timezone);
    eat(&profile.screen_width.to_string());
    eat(&profile.screen_height.to_string());
    eat(&profile.hardware_concurrency.to_string());
    eat(&profile.device_memory_gb.to_string());
    h & 0x7fff_ffff
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
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_slice = __sm(String.prototype.slice, 'slice');
  const FAST = __FAST_TIMERS__;
  let seq = 1;
  let virt = 0; // fast mode only: the clock that jumps to each due time
  const q = new Map(); // id -> {fn, delay, interval, due, cancelled, id, depth}
  // High-resolution queue clock: `Date.now()` is whole milliseconds, so a 4 ms
  // timer fired anywhere between 4 and 5 and the frame grid snapped to integers;
  // the browser uses a monotonic clock for both.
  // One scale for the queue's lifetime: `performance` appears after us, and
  // switching from absolute to page-relative ms would push existing timers
  // far into the future.
  const T0 = Date.now();
  const hi = () => {
    const p = globalThis.performance;
    return p && typeof p.now === 'function' ? p.now() : Date.now() - T0;
  };
  const clock = () => (FAST ? virt : hi());

  // Chrome clamps a timer nested deeper than five levels to 4 ms. Without the
  // clamp a `setTimeout(f, 0)` chain spins the driver at CPU speed — which is
  // both a tell and a way to starve every other context on the worker.
  let depth = 0;

  // Engine tasks (`__pt_addTask`) use separate negative ids, so the page's first
  // `setTimeout` returns 1 as in the browser.
  let iseq = -1;
  const add = (fn, delay, interval, args, internal) => {
    // A string handler is compiled as global code when the timer fires.
    // Trusted Types passes TrustedScript through here too.
    if (typeof fn === 'string' || (fn !== null && typeof fn === 'object' &&
        globalThis.trustedTypes && globalThis.trustedTypes.isScript &&
        (() => { try { return trustedTypes.isScript(fn); } catch (e) { return false; } })())) {
      const code = String(fn);
      // Empty string: the browser returns 0 and schedules nothing.
      if (code === '') return 0;
      fn = () => { try { (0, eval)(code); } catch (e) { if (globalThis.__pt_reportError) __pt_reportError(e, 'timer string'); else throw e; } };
      args = [];
    }
    if (typeof fn !== 'function') return 0;
    let d = Number(delay);
    if (!(d > 0)) d = 0; // negative, NaN and undefined all mean "as soon as possible"
    if (depth > 5 && d < 4) d = 4;
    const id = internal ? iseq-- : seq++;
    q.set(id, { fn: () => fn.apply(globalThis, args), orig: fn, delay: d, interval,
                due: clock() + d, cancelled: false, id, depth: depth + 1 });
    return id;
  };
  globalThis.setTimeout = (fn, delay, ...args) => add(fn, delay, false, args);
  globalThis.setInterval = (fn, delay, ...args) => add(fn, delay, true, args);
  // Chrome's length for both is 1 (only the handler is required).
  try { Object.defineProperty(globalThis.setTimeout, 'length', { value: 1, configurable: true }); } catch (e) {}
  try { Object.defineProperty(globalThis.setInterval, 'length', { value: 1, configurable: true }); } catch (e) {}
  globalThis.clearTimeout = (id) => { const t = q.get(id); if (t) t.cancelled = true; q.delete(id); };
  // Separate function: in the browser clearTimeout !== clearInterval.
  globalThis.clearInterval = (id) => { const t = q.get(id); if (t) t.cancelled = true; q.delete(id); };
  // Non-timer task (`scheduler.postTask` with high priority): runs before
  // already queued zero-delay timers, as in the browser.
  Object.defineProperty(globalThis, '__pt_addTask', { value: (fn, delay, front) => {
    const id = add(fn, delay, false, [], true);
    if (front) { const t = q.get(id); if (t) t.due = clock() - 1; }
    return id;
  }, configurable: true, enumerable: false });
  globalThis.queueMicrotask = (fn) => { Promise.resolve().then(fn); };
  // Animation frames have their own counter: the page's first
  // `requestAnimationFrame` returns 1 even after timers were created.
  let rafSeq = 0;
  const rafIds = new Map();
  // A frame is a node on the vsync grid, not a 16 ms timer: browser ticks are
  // exactly 16.7 ms apart however busy it is, which is the first thing frame
  // rate checks measure. The grid starts at page start, so the first frame
  // comes after a random fraction of a period.
  const FRAME_MS = 1000 / 60;
  const frameOrigin = clock();
  let frameSlot = null;
  globalThis.requestAnimationFrame = (fn) => {
    if (typeof fn !== 'function') {
      throw __pt_mkErr(TypeError, "Failed to execute 'requestAnimationFrame' on 'Window': " +
        "parameter 1 is not of type 'Function'.");
    }
    const rid = ++rafSeq;
    const now = clock();
    let at = frameOrigin + Math.ceil((now - frameOrigin) / FRAME_MS) * FRAME_MS;
    if (at - now < 0.5) at += FRAME_MS;
    if (!frameSlot || frameSlot.at !== at) {
      const slot = { at, list: [] };
      frameSlot = slot;
      const tid = add(() => {
        if (frameSlot === slot) frameSlot = null;
        // All callbacks of one frame get the same timestamp (the frame time),
        // rounded to 0.1 ms like the browser (16.6 and 16.7 alternating; an
        // even 16.667 betrays a counter).
        const stamp = Math.round(slot.at * 10) / 10;
        for (const [id, cb] of slot.list.splice(0)) {
          rafIds.delete(id);
          try { cb(stamp); } catch (e) {
            try { if (globalThis.__pt_reportError) __pt_reportError(e, 'requestAnimationFrame'); } catch (x) {}
          }
        }
      }, Math.max(0, at - now), false, []);
      // A long animation frame is attributed to FrameRequestCallback.
      try { const t = q.get(tid); if (t) { t.invoker = 'FrameRequestCallback'; t.orig = fn; } } catch (e) {}
    }
    frameSlot.list.push([rid, fn]);
    rafIds.set(rid, frameSlot);
    return rid;
  };
  globalThis.cancelAnimationFrame = (rid) => {
    const slot = rafIds.get(rid);
    if (!slot) return;
    rafIds.delete(rid);
    const i = slot.list.findIndex((x) => x[0] === rid);
    if (i >= 0) slot.list.splice(i, 1);
  };
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
  // Realms (empty and srcdoc frame windows) share this isolate but have no
  // driver of their own: their queues are pumped from here. Detached frames
  // drop out of the list.
  const children = [];
  Object.defineProperty(globalThis, '__pt_addChildRealm', { value: (w) => { if (w && __s_indexOf(children, w) < 0) children.push(w); }, configurable: true, enumerable: false });
  // Diagnostics: every realm this window created, including detached ones.
  const everyChild = [];
  Object.defineProperty(globalThis, '__pt_childRealms', { value: () => __s_slice(everyChild), configurable: true, enumerable: false });
  const addEvery = globalThis.__pt_addChildRealm;
  Object.defineProperty(globalThis, '__pt_addChildRealm', { value: (w) => { if (w && __s_indexOf(everyChild, w) < 0) everyChild.push(w); addEvery(w); }, configurable: true, enumerable: false });
  const liveChildren = () => {
    for (let i = children.length - 1; i >= 0; i--) {
      let ok = false;
      try { const fe = children[i].frameElement; ok = !fe || fe.isConnected !== false; } catch (e) { ok = false; }
      if (!ok) children.splice(i, 1);
    }
    return children;
  };
  const childDue = () => {
    let best = -1;
    for (const w of liveChildren()) {
      let d = -1; try { d = typeof w.__pt_nextTimerDelay === 'function' ? w.__pt_nextTimerDelay() : -1; } catch (e) {}
      if (d >= 0 && (best < 0 || d < best)) best = d;
    }
    return best;
  };
  const runChild = () => {
    for (const w of liveChildren()) {
      let d = -1; try { d = typeof w.__pt_nextTimerDelay === 'function' ? w.__pt_nextTimerDelay() : -1; } catch (e) {}
      if (d === 0) { try { if (w.__pt_runNextTimer()) return 1; } catch (e) {} }
    }
    return 0;
  };
  globalThis.__pt_runNextTimer = () => {
    const best = earliest();
    if (!best) return children.length ? runChild() : 0;
    const now = clock();
    if (best.due > now) {
      if (!FAST) return children.length ? runChild() : 0;
      virt = best.due; // fast mode: skip the wait rather than serve it
    }
    // An interval that fell behind (a long callback, a busy worker) schedules
    // its next tick from now, so it never fires a burst to catch up.
    if (best.interval) best.due = Math.max(clock(), best.due) + best.delay;
    else q.delete(best.id);
    const outer = depth;
    depth = best.depth;
    const t0 = hi();
    try { best.fn(); } catch (e) {
      // As with event handlers, the browser reports it.
      if (typeof globalThis.__pt_reportError === 'function') __pt_reportError(e, 'timer');
    }
    finally {
      depth = outer;
      const dt = hi() - t0;
      if (dt > 50 && typeof globalThis.__pt_noteLoaf === 'function') {
        try { __pt_noteLoaf(t0, dt, best.invoker || (best.interval ? 'TimerHandler:setInterval' : 'TimerHandler:setTimeout'), best.invokerType || 'user-callback', best.orig); } catch (e) {}
      }
    }
    return 1;
  };

  // Milliseconds until the earliest pending timer: 0 = due now, -1 = nothing
  // pending. This is what lets the driver sleep for exactly as long as the page
  // asked for instead of polling.
  globalThis.__pt_nextTimerDelay = () => {
    const best = earliest();
    const own = best ? Math.max(0, best.due - clock()) : -1;
    if (!children.length) return own;
    const c = childDue();
    return own < 0 ? c : c < 0 ? own : Math.min(own, c);
  };
  globalThis.__pt_pendingTimers = () => { let n = q.size; for (const w of liveChildren()) { try { n += w.__pt_pendingTimers() | 0; } catch (e) {} } return n; };
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
    let cap = std::env::var("NOKK_TRACE_CAP")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(40_000);
    TRACER_TEMPLATE.replace("__HEAD_CAP__", &cap.to_string())
}

const TRACER_TEMPLATE: &str = r##"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_lastIndexOf = __sm(String.prototype.lastIndexOf, 'lastIndexOf'),
    __s_slice = __sm(String.prototype.slice, 'slice');
  // Head ring cap; NOKK_TRACE_CAP raises it for long stalls.
  const HEAD_CAP = __HEAD_CAP__;
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
      return s.length > 90 ? __s_slice(s, 0, 90) + '…' : s;
    } catch (e) { return '<threw>'; }
  };
  // Counters say what the page asked, not where it stopped: hence the tail,
  // the last accesses in order with time since start.
  const tail = [], head = [];
  const t0 = Date.now();
  // `isNaN` in a decoder loop yields hundreds of thousands of entries and
  // drowns the trace.
  const NOISY = /^isNaN\(/;
  const note = (name, v) => {
    if (NOISY.test(name)) return v;
    const e = log.get(name) || { n: 0, last: '' };
    e.n++; e.last = show(v);
    log.set(name, e);
    if (head.length < HEAD_CAP) head.push([Date.now() - t0, name, e.last]);
    if (tail.length >= 400) tail.shift();
    tail.push([Date.now() - t0, name, e.last]);
    return v;
  };
  globalThis.__pt_probeLog = () => __ptJSON.stringify([...log]
    .sort((a, b) => b[1].n - a[1].n)
    .map(([k, v]) => [k, v.n, v.last]));
  globalThis.__pt_probeTail = (n) => __ptJSON.stringify(__s_slice(tail, -(n || 60)));
  // Marker in the trace, to find where a foreign program's segment begins and ends.
  globalThis.__pt_probeMark = (text) => {
    note('== ' + text, '');
    // Snapshot of the tail at the marker: the head ring has overflowed by now,
    // and what matters is what was read just before the event.
    try { globalThis.__pt_atMark = __ptJSON.stringify(__s_slice(tail, -400)); } catch (e) {}
  };
  globalThis.__pt_probeHead = (n) => __ptJSON.stringify(__s_slice(head, 0, n || 40000));
  globalThis.__pt_probeT0 = () => t0;

  const native = globalThis.__pt_native || ((f) => f);
  const rename = (f, name) => {
    try { Object.defineProperty(f, 'name', { value: name, configurable: true }); } catch (e) {}
    return native(f);
  };

  // Constructors cannot be wrapped: a wrapper loses statics and the prototype,
  // and wrapping `Object` breaks everything. Only methods and getters are
  // touched. A capitalized name marks a constructor: `Proxy` and `Symbol` have
  // no prototype in the usual sense and a page won't survive wrapping them.
  const isConstructor = (v) => typeof v === 'function'
    && (/^[A-Z]/.test(v.name || '') || !!v.prototype);

  const trace = (obj, prefix) => {
    if (!obj) return;
    for (const key of Object.getOwnPropertyNames(obj)) {
      if (key === 'constructor' || __s_lastIndexOf(key, '__pt', 0) === 0) continue;
      if (key === 'eval' || key === 'Function' || key === 'Object' || key === 'Reflect') continue;
      let d;
      try { d = Object.getOwnPropertyDescriptor(obj, key); } catch (e) { continue; }
      if (!d || !d.configurable) continue;
      if (d.get) {
        const get = d.get;
        try {
          Object.defineProperty(obj, key, Object.assign({}, d, {
            get: rename(function () {
              // A throw from a property is the most valuable thing to record:
              // their VM catches it internally and only an abort is visible.
              try { return note(prefix + key, get.call(this)); }
              catch (e) { note('THROW ' + prefix + key, String((e && e.message) || e)); throw e; }
            }, 'get ' + key),
          }));
        } catch (e) {}
      } else if (typeof d.value === 'function' && !isConstructor(d.value)) {
        const fn = d.value;
        try {
          Object.defineProperty(obj, key, Object.assign({}, d, {
            value: rename(function (...args) {
              let out;
              try { out = fn.apply(this, args); }
              catch (e) {
                note('THROW ' + prefix + key + '(' + __s_slice(args.map(show).join(','), 0, 30) + ')',
                     String((e && e.message) || e));
                throw e;
              }
              return note(prefix + key + '(' + __s_slice(args.map(show).join(','), 0, 40) + ')', out);
            }, key),
          }));
        } catch (e) {}
      }
    }
  };

  // Enumeration is the fingerprinter's main tool: it walks `Object.keys` up the
  // prototype chain. Record what was enumerated and how many names came back.
  const nameOf = (o) => {
    try {
      if (o === globalThis) return 'window';
      if (o === null || o === undefined) return String(o);
      const tag = __s_slice(Object.prototype.toString.call(o), 8, -1);
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
          note('walk:' + key + '(' + nameOf(target) + ')', Array.isArray(out) ? out.length + ' names' : out);
          return out;
        }, key),
        writable: true, configurable: true,
      });
    } catch (e) {}
  }

  // Code the page compiles on the fly and the workers it hides collection in.
  const origFunction = globalThis.Function;
  for (const name of ['Worker', 'SharedWorker', 'ServiceWorker']) {
    const C = globalThis[name];
    if (typeof C !== 'function') continue;
    try {
      globalThis[name] = new Proxy(C, {
        construct(t, args) { note('new ' + name + '(' + show(args[0]) + ')', 'created'); return Reflect.construct(t, args); },
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
  // XHR: what went out, what came back and in what state.
  try {
    const X = globalThis.XMLHttpRequest;
    if (typeof X === 'function') {
      const open_ = X.prototype.open, send_ = X.prototype.send;
      X.prototype.open = rename(function (m, u) {
        note('xhr.open(' + String(m) + ' ' + __s_slice(String(u), -48) + ')', 'opened');
        try {
          this.addEventListener('readystatechange', () => {
            if (this.readyState !== 4) return;
            let n = -1;
            try { n = String(this.responseText || '').length; } catch (e) {}
            note('xhr.done(' + __s_slice(String(u), -48) + ')', this.status + ', ' + n + ' bytes');
          });
          this.addEventListener('timeout', () => note('xhr.timeout(' + __s_slice(String(u), -48) + ')', 'timed out'));
          this.addEventListener('error', () => note('xhr.error(' + __s_slice(String(u), -48) + ')', 'error'));
        } catch (e) {}
        return open_.apply(this, arguments);
      }, 'open');
      X.prototype.send = rename(function (body) {
        note('xhr.send', (body && body.length) || 0);
        return send_.apply(this, arguments);
      }, 'send');
      native(X.prototype.open); native(X.prototype.send);
    }
  } catch (e) {}
  try {
    globalThis.Function = new Proxy(origFunction, {
      construct(t, args) {
        note('new Function(' + __s_slice(String(args[args.length - 1] || ''), 0, 50) + ')', 'compiled');
        return Reflect.construct(t, args);
      },
      apply(t, self, args) {
        note('Function(' + __s_slice(String(args[args.length - 1] || ''), 0, 50) + ')', 'compiled');
        return Reflect.apply(t, self, args);
      },
    });
  } catch (e) {}

  // Data properties of roots: the getter wrapper misses them, collectors read them.
  const traceData = (obj, prefix) => {
    if (!obj) return;
    for (const key of Object.getOwnPropertyNames(obj)) {
      if (__s_lastIndexOf(key, '__pt', 0) === 0) continue;
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

  // Every fingerprint root and commonly judged surface: drawing, audio, fonts,
  // time, device.
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
    // Less obvious surfaces that fingerprints are collected from too.
    ['FontFaceSet', 'fonts.'], ['NavigatorUAData', 'uaData.'], ['MediaDevices', 'mediaDevices.'],
    ['Permissions', 'permissions.'], ['StorageManager', 'storageMgr.'],
    ['MediaCapabilities', 'mediaCaps.'], ['Keyboard', 'keyboard.'],
    ['GPU', 'gpu.'], ['GPUAdapter', 'gpuAdapter.'], ['PerformanceObserver', 'perfObs.'],
    ['TextEncoder', 'textEnc.'], ['TextDecoder', 'textDec.'], ['URL', 'url.'],
    ['SubtleCrypto', 'subtle.'], ['NetworkInformation', 'connection.'],
  ]) {
    trace(proto(name), tag);
  }
  // Objects whose interface is not exposed on window: trace the objects themselves.
  try {
    const pairs = [
      [globalThis.WebAssembly, 'wasm.'],
      [globalThis.document && document.fonts, 'fonts.own.'],
      [globalThis.navigator && navigator.userAgentData, 'uaData.own.'],
      [globalThis.navigator && navigator.mediaDevices, 'mediaDevices.own.'],
      [globalThis.navigator && navigator.permissions, 'permissions.own.'],
      [globalThis.navigator && navigator.connection, 'connection.own.'],
      [globalThis.navigator && navigator.gpu, 'gpu.own.'],
      [globalThis.crypto && crypto.subtle, 'subtle.own.'],
    ];
    for (const [obj, tag] of pairs) if (obj) trace(obj, tag);
  } catch (e) {}
  for (const [name, tag] of [['navigator', 'n.'], ['screen', 's.'], ['performance', 'perf.']]) {
    if (globalThis[name]) { trace(globalThis[name], tag + 'own.'); traceData(globalThis[name], tag); }
  }
  traceData(globalThis, 'win.');
})();"##;

/// Turn a freshly created context into a worker's global scope. A worker is not
/// a window with things missing — it is a different global object, and code that
/// collects a fingerprint inside one knows exactly what belongs there. Running it
/// in the page's realm, however carefully shimmed, gets the realm wrong; this
/// runs in a context of its own, and only reshapes what that context exposes.
/// Worker scope names captured from Chrome 148 (see `worker_scope_script`).
const WORKER_OWN: &str = r#"["AbortController", "AbortSignal", "AggregateError", "Array", "ArrayBuffer", "AsyncDisposableStack", "Atomics", "AudioData", "AudioDecoder", "AudioEncoder", "BackgroundFetchManager", "BackgroundFetchRecord", "BackgroundFetchRegistration", "BigInt", "BigInt64Array", "BigUint64Array", "Blob", "Boolean", "BroadcastChannel", "ByteLengthQueuingStrategy", "CSSSkewX", "CSSSkewY", "Cache", "CacheStorage", "CanvasGradient", "CanvasPattern", "CloseEvent", "CompressionStream", "CountQueuingStrategy", "CreateMonitor", "CropTarget", "Crypto", "CryptoKey", "CustomEvent", "DOMException", "DOMMatrix", "DOMMatrixReadOnly", "DOMPoint", "DOMPointReadOnly", "DOMQuad", "DOMRect", "DOMRectReadOnly", "DOMStringList", "DataView", "Date", "DecompressionStream", "DedicatedWorkerGlobalScope", "DisposableStack", "EncodedAudioChunk", "EncodedVideoChunk", "Error", "ErrorEvent", "EvalError", "Event", "EventSource", "EventTarget", "File", "FileList", "FileReader", "FileReaderSync", "FileSystemDirectoryHandle", "FileSystemFileHandle", "FileSystemHandle", "FileSystemObserver", "FileSystemSyncAccessHandle", "FileSystemWritableFileStream", "FinalizationRegistry", "Float16Array", "Float32Array", "Float64Array", "FontFace", "FontFaceSet", "FormData", "Function", "GPU", "GPUAdapter", "GPUAdapterInfo", "GPUBindGroup", "GPUBindGroupLayout", "GPUBuffer", "GPUBufferUsage", "GPUCanvasContext", "GPUColorWrite", "GPUCommandBuffer", "GPUCommandEncoder", "GPUCompilationInfo", "GPUCompilationMessage", "GPUComputePassEncoder", "GPUComputePipeline", "GPUDevice", "GPUDeviceLostInfo", "GPUError", "GPUExternalTexture", "GPUInternalError", "GPUMapMode", "GPUOutOfMemoryError", "GPUPipelineError", "GPUPipelineLayout", "GPUQuerySet", "GPUQueue", "GPURenderBundle", "GPURenderBundleEncoder", "GPURenderPassEncoder", "GPURenderPipeline", "GPUSampler", "GPUShaderModule", "GPUShaderStage", "GPUSupportedFeatures", "GPUSupportedLimits", "GPUTexture", "GPUTextureUsage", "GPUTextureView", "GPUUncapturedErrorEvent", "GPUValidationError", "HID", "HIDConnectionEvent", "HIDDevice", "HIDInputReportEvent", "Headers", "IDBCursor", "IDBCursorWithValue", "IDBDatabase", "IDBFactory", "IDBIndex", "IDBKeyRange", "IDBObjectStore", "IDBOpenDBRequest", "IDBRecord", "IDBRequest", "IDBTransaction", "IDBVersionChangeEvent", "IdleDetector", "ImageBitmap", "ImageBitmapRenderingContext", "ImageData", "ImageDecoder", "ImageTrack", "ImageTrackList", "Infinity", "Int16Array", "Int32Array", "Int8Array", "Intl", "Iterator", "JSON", "Lock", "LockManager", "Map", "Math", "MediaCapabilities", "MediaSource", "MediaSourceHandle", "MessageChannel", "MessageEvent", "MessagePort", "NaN", "NavigationPreloadManager", "NavigatorUAData", "NetworkInformation", "Notification", "Number", "Object", "Observable", "OffscreenCanvas", "OffscreenCanvasRenderingContext2D", "Origin", "Path2D", "Performance", "PerformanceEntry", "PerformanceMark", "PerformanceMeasure", "PerformanceObserver", "PerformanceObserverEntryList", "PerformanceResourceTiming", "PerformanceServerTiming", "PeriodicSyncManager", "PermissionStatus", "Permissions", "PressureObserver", "PressureRecord", "ProgressEvent", "Promise", "PromiseRejectionEvent", "Proxy", "PushManager", "PushSubscription", "PushSubscriptionOptions", "QuotaExceededError", "RTCDataChannel", "RTCEncodedAudioFrame", "RTCEncodedVideoFrame", "RTCRtpScriptTransformer", "RTCTransformEvent", "RangeError", "ReadableByteStreamController", "ReadableStream", "ReadableStreamBYOBReader", "ReadableStreamBYOBRequest", "ReadableStreamDefaultController", "ReadableStreamDefaultReader", "ReferenceError", "Reflect", "RegExp", "ReportBody", "ReportingObserver", "Request", "Response", "RestrictionTarget", "Scheduler", "SecurityPolicyViolationEvent", "Serial", "SerialPort", "ServiceWorkerRegistration", "Set", "SourceBuffer", "SourceBufferList", "StorageBucket", "StorageBucketManager", "StorageManager", "String", "Subscriber", "SubtleCrypto", "SuppressedError", "Symbol", "SyncManager", "SyntaxError", "TaskController", "TaskPriorityChangeEvent", "TaskSignal", "Temporal", "TextDecoder", "TextDecoderStream", "TextEncoder", "TextEncoderStream", "TextMetrics", "TransformStream", "TransformStreamDefaultController", "TrustedHTML", "TrustedScript", "TrustedScriptURL", "TrustedTypePolicy", "TrustedTypePolicyFactory", "TypeError", "URIError", "URL", "URLPattern", "URLSearchParams", "USB", "USBAlternateInterface", "USBConfiguration", "USBConnectionEvent", "USBDevice", "USBEndpoint", "USBInTransferResult", "USBInterface", "USBIsochronousInTransferPacket", "USBIsochronousInTransferResult", "USBIsochronousOutTransferPacket", "USBIsochronousOutTransferResult", "USBOutTransferResult", "Uint16Array", "Uint32Array", "Uint8Array", "Uint8ClampedArray", "UserActivation", "VideoColorSpace", "VideoDecoder", "VideoEncoder", "VideoFrame", "WGSLLanguageFeatures", "WeakMap", "WeakRef", "WeakSet", "WebAssembly", "WebGL2RenderingContext", "WebGLActiveInfo", "WebGLBuffer", "WebGLContextEvent", "WebGLFramebuffer", "WebGLObject", "WebGLProgram", "WebGLQuery", "WebGLRenderbuffer", "WebGLRenderingContext", "WebGLSampler", "WebGLShader", "WebGLShaderPrecisionFormat", "WebGLSync", "WebGLTexture", "WebGLTransformFeedback", "WebGLUniformLocation", "WebGLVertexArrayObject", "WebSocket", "WebSocketError", "WebSocketStream", "WebTransport", "WebTransportBidirectionalStream", "WebTransportDatagramDuplexStream", "WebTransportError", "Worker", "WorkerGlobalScope", "WorkerLocation", "WorkerNavigator", "WritableStream", "WritableStreamDefaultController", "WritableStreamDefaultWriter", "XMLHttpRequest", "XMLHttpRequestEventTarget", "XMLHttpRequestUpload", "cancelAnimationFrame", "close", "console", "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent", "escape", "eval", "globalThis", "isFinite", "isNaN", "name", "onmessage", "onmessageerror", "onrtctransform", "parseFloat", "parseInt", "postMessage", "requestAnimationFrame", "undefined", "unescape", "webkitRequestFileSystem", "webkitRequestFileSystemSync", "webkitResolveLocalFileSystemSyncURL", "webkitResolveLocalFileSystemURL"]"#;
const WORKER_ENUMERABLE: &str = r#"["cancelAnimationFrame", "close", "name", "onmessage", "onmessageerror", "onrtctransform", "postMessage", "requestAnimationFrame", "webkitRequestFileSystem", "webkitRequestFileSystemSync", "webkitResolveLocalFileSystemSyncURL", "webkitResolveLocalFileSystemURL"]"#;
const WORKER_NAVIGATOR: &str = r#"["appCodeName", "appName", "appVersion", "connection", "deviceMemory", "gpu", "hardwareConcurrency", "hid", "language", "languages", "locks", "mediaCapabilities", "onLine", "permissions", "platform", "product", "serial", "storage", "storageBuckets", "usb", "userAgent", "userAgentData"]"#;

/// Worker scope names captured from Chrome 148 (see `worker_scope_script`).
const WORKER_SCOPE: &str = r#"["atob", "btoa", "caches", "clearInterval", "clearTimeout", "createImageBitmap", "crossOriginIsolated", "crypto", "fetch", "fonts", "importScripts", "indexedDB", "isSecureContext", "location", "navigator", "onerror", "onlanguagechange", "onrejectionhandled", "onunhandledrejection", "origin", "performance", "queueMicrotask", "reportError", "scheduler", "self", "setInterval", "setTimeout", "structuredClone", "trustedTypes"]"#;
const WORKER_SCOPE_ENUMERABLE: &str = r#"["atob", "btoa", "caches", "clearInterval", "clearTimeout", "createImageBitmap", "crossOriginIsolated", "crypto", "fetch", "fonts", "importScripts", "indexedDB", "isSecureContext", "location", "navigator", "onerror", "onlanguagechange", "onrejectionhandled", "onunhandledrejection", "origin", "performance", "queueMicrotask", "reportError", "scheduler", "self", "setInterval", "setTimeout", "structuredClone", "trustedTypes"]"#;

/// Prototype shape as in Chrome 151: own members of every interface, in order
/// (crates/stealth/src/proto_shape.json, captured from Chrome); graph walks
/// see missing members and order.
/// Missing members are copied from the inherited place or stubbed (accessor
/// with a slot, no-op method of Chrome's length, constant with its value).
/// Extra members are removed.
pub fn proto_shape_script() -> String {
    // `NOKK_PROTO_SHAPE_SKIP=<regex>`: interfaces to leave alone (for bisection).
    let skip = std::env::var("NOKK_PROTO_SHAPE_SKIP")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| format!("new RegExp({})", quoted(&s)))
        .unwrap_or_else(|| "null".to_string());
    PROTO_SHAPE_TEMPLATE
        .replace("__SHAPE_SKIP__", &skip)
        .replace("__SHAPE__", &json_table(PROTO_SHAPE))
        .replace("__BRAND_TRACE__", if std::env::var_os("NOKK_TRACE_BRAND").is_some() { "true" } else { "false" })
}

const PROTO_SHAPE: &str = include_str!("proto_shape.json");

const PROTO_SHAPE_TEMPLATE: &str = r#"(() => {
  'use strict';
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_trim = __sm(String.prototype.trim, 'trim'),
    __s_replace = __sm(String.prototype.replace, 'replace'),
    __s_split = __sm(String.prototype.split, 'split');
  const SKIP = __SHAPE_SKIP__;
  // Released at the end: stubs outlive this layer and keep its scope.
  let T = {};
  { const T0 = __SHAPE__; for (const k of Object.keys(T0)) if (!SKIP || !SKIP.test(k)) T[k] = T0[k]; }
  const TRACE = __BRAND_TRACE__;
  const desc = (o, k) => { try { return Object.getOwnPropertyDescriptor(o, k); } catch (e) { return undefined; } };
  const def = (o, k, d) => { try { Object.defineProperty(o, k, d); return true; } catch (e) { return false; } };
  const del = (o, k) => { try { return delete o[k]; } catch (e) { return false; } };
  const stubs = globalThis.__pt_stubMembers || null;
  const mark = (f) => { if (stubs) try { stubs.add(f); } catch (e) {} return f; };
  const named = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return f; };
  const writers = globalThis.__pt_writers;
  // Name and length come from birth, not by editing `name`/`length`: editing
  // turns a function into dictionary mode with its own property store
  // (~290 bytes), and there are thousands of stubs per context. A literal
  // getter is named `get x` by itself, a literal method has no `prototype`,
  // as in the browser.
  // One store for every stub accessor (object -> {name: value}): a WeakMap
  // per member was thousands per context.
  const slots = stubs ? stubs.slots : new WeakMap();
  const stubAccessor = (P, name, kind) => {
    const pair = Object.getOwnPropertyDescriptor({
      get [name]() { const s = slots.get(this); return s && name in s ? s[name] : undefined; },
      set [name](v) { let s = slots.get(this); if (!s) { s = Object.create(null); try { slots.set(this, s); } catch (e) { return; } } s[name] = v; },
    }, name);
    const get = mark(pair.get);
    const write = pair.set;
    let set = __s_indexOf(kind, 's') >= 0 ? mark(write) : undefined;
    // Read-only from outside, but the engine writes via `__pt_write`.
    if (!set && writers) { let w = writers.get(P); if (!w) { w = Object.create(null); writers.set(P, w); } w[name] = write; }
    // Under tracing a read-only write is logged with its call site and goes
    // through: this finds every place the engine bypasses `__pt_write`.
    if (!set && TRACE) set = function (v) {
      try { console.error('[brand] write to read-only ' + name + ' on ' + Object.prototype.toString.call(this) + ' | ' + __s_slice(__s_split(String(new Error().stack || ''), '\n'), 2, 6).map((x) => __s_replace(__s_trim(x), /https?:\/\/[^ )]*\//, '')).join(' < ')); } catch (e) {}
      write.call(this, v);
    };
    return { get, set };
  };
  const STUB_ARITY = [
    (n) => ({ [n]() { return undefined; } })[n],
    (n) => ({ [n](a) { return undefined; } })[n],
    (n) => ({ [n](a, b) { return undefined; } })[n],
    (n) => ({ [n](a, b, c) { return undefined; } })[n],
    (n) => ({ [n](a, b, c, d) { return undefined; } })[n],
    (n) => ({ [n](a, b, c, d, e) { return undefined; } })[n],
    (n) => ({ [n](a, b, c, d, e, f) { return undefined; } })[n],
  ];
  const stubMethod = (name, len) => {
    const l = len | 0;
    if (l < STUB_ARITY.length) return mark(STUB_ARITY[l](name));
    const f = mark(STUB_ARITY[0](name));
    try { Object.defineProperty(f, 'length', { value: l, configurable: true }); } catch (e) {}
    return f;
  };
  const protoOf = (name) => { try { const C = globalThis[name]; return C && typeof C === 'function' ? C.prototype : null; } catch (e) { return null; } };
  const inherited = (P, k) => {
    let p = Object.getPrototypeOf(P);
    for (let i = 0; i < 12 && p && p !== Object.prototype; i++) { const d = desc(p, k); if (d) return d; p = Object.getPrototypeOf(p); }
    return undefined;
  };
  // Where Chrome keeps a member: interface -> member name -> present.
  const has = {};
  for (const name of Object.keys(T)) { const set = {}; for (const r of T[name].m) set[r[0]] = 1; has[name] = set; }
  const chromeOwnerUp = (name, k) => {
    let n = T[name] && T[name].p;
    for (let i = 0; i < 12 && n && T[n]; i++) { if (has[n][k]) return n; n = T[n].p; }
    return null;
  };
  // First pass: members that sit lower in the chain than in Chrome are lifted
  // to their place, otherwise removing extras would leave a hole.
  for (const name of Object.keys(T)) {
    const P = protoOf(name); if (!P || typeof P !== 'object') continue;
    for (const k of Object.getOwnPropertyNames(P)) {
      if (has[name][k] || __s_slice(k, 0, 4) === '__pt') continue;
      const up = chromeOwnerUp(name, k);
      if (!up) continue;
      const A = protoOf(up);
      if (A && !desc(A, k)) { const d = desc(P, k); if (d && d.configurable) def(A, k, d); }
    }
  }
  // Second pass: membership and order.
  for (const name of Object.keys(T)) {
    const P = protoOf(name); if (!P || typeof P !== 'object') continue;
    const rows = T[name].m;
    const built = [];
    for (const r of rows) {
      const k = r[0], kind = r[1];
      let d = desc(P, k);
      if (!d) {
        const inh = inherited(P, k);
        if (inh) d = Object.assign({}, inh);
        else if (kind[0] === 'a') d = stubAccessor(P, k, kind);
        else if (kind[1] === 'f') d = { value: stubMethod(k, r[2]), writable: true };
        else d = { value: r[2], writable: __s_indexOf(kind, 'w') >= 0 };
      }
      d.enumerable = __s_indexOf(kind, 'e') >= 0;
      d.configurable = __s_indexOf(kind, 'c') >= 0;
      if (!('get' in d) && !('set' in d) && kind[0] === 'v') d.writable = __s_indexOf(kind, 'w') >= 0;
      built.push([k, d]);
    }
    // Remove everything configurable and re-add in order. Extras (about forty
    // members the engine itself uses: `Element.getElementById`, own
    // `addEventListener` on Worker and WebSocket...) stay, at the tail.
    const extra = [];
    for (const k of Object.getOwnPropertyNames(P)) {
      if (__s_slice(k, 0, 4) === '__pt') continue;
      const d = desc(P, k);
      if (!d || !d.configurable) continue;
      if (!has[name][k]) extra.push([k, d]);
      del(P, k);
    }
    for (const [k, d] of built) { if (!desc(P, k)) def(P, k, d); }
    for (const [k, d] of extra) { if (!desc(P, k)) def(P, k, d); }
  }
  // Twins: the offscreen context has the same members as the canvas context,
  // and they must be real from the start: the challenge grabs methods off the
  // prototype early and calls them on a context later; stubs returned
  // undefined and the canvas blocks dropped out of the report.
  for (const [to, from] of [['OffscreenCanvasRenderingContext2D', 'CanvasRenderingContext2D']]) {
    const P = protoOf(to), S = protoOf(from);
    if (!P || !S) continue;
    for (const k of Object.getOwnPropertyNames(P)) {
      if (k === 'constructor') continue;
      const d = desc(P, k), sd = desc(S, k);
      if (!d || !sd || !d.configurable) continue;
      const isStub = stubs && ((d.value && stubs.has(d.value)) || (d.get && stubs.has(d.get)));
      if (isStub) def(P, k, Object.assign({}, sd, { enumerable: d.enumerable, configurable: d.configurable }));
    }
  }
  T = null;
  for (const k of Object.keys(has)) delete has[k];
})();"#;

pub fn naturalize_script() -> String {
    // `NOKK_NATURALIZE_SKIP=<regex>`: interfaces to leave alone (for bisecting
    // breakage after naturalization).
    let skip = std::env::var("NOKK_NATURALIZE_SKIP")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| format!("new RegExp({})", quoted(&s)))
        .unwrap_or_else(|| "null".to_string());
    NATURALIZE_TEMPLATE
        .replace("__SKIP__", &skip)
        .replace("__BRAND_EXCEPTIONS__", &json_table(BRAND_EXCEPTIONS))
        .replace("__CTOR_TABLE__", &json_table(CTOR_TABLE))
        .replace("__EVENT_DEFAULTS__", &json_table(EVENT_DEFAULTS))
        .replace("__METHOD_LENGTHS__", &json_table(METHOD_LENGTHS))
        .replace("__BRAND_TRACE__", if std::env::var_os("NOKK_TRACE_BRAND").is_some() { "true" } else { "false" })
}

/// Members Chrome 151 lets be called with a foreign `this` without "Illegal
/// invocation" (captured from Chrome, 404 entries: promises, iterators,
/// `toJSON`...). All others check the brand.
const BRAND_EXCEPTIONS: &str = include_str!("brand_exceptions.json");
/// Chrome 151 interface constructors: length, outcome of `new X()` without
/// args (`illegal`, `args:N`, `ok`) and of a call without `new` (`illegal`,
/// `nonew`). Captured from Chrome.
const CTOR_TABLE: &str = include_str!("ctor_table.json");
/// Chrome 151 default event field values (`new X('t')` without a dict).
const EVENT_DEFAULTS: &str = include_str!("event_defaults.json");
/// Method lengths on Chrome 151 interface prototypes (`Iface.method` ->
/// number of required args).
const METHOD_LENGTHS: &str = include_str!("method_lengths.json");

const NATURALIZE_TEMPLATE: &str = r#"(() => {
  'use strict';
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_trim = __sm(String.prototype.trim, 'trim'),
    __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_replace = __sm(String.prototype.replace, 'replace'),
    __s_split = __sm(String.prototype.split, 'split');
  const N = globalThis.__pt_native;
  if (typeof N !== 'function') return;
  const SKIP = __SKIP__;
  // Brand checks. An interface member called with a foreign `this` throws
  // `TypeError: Illegal invocation` in the browser (7850 of 8254 members), and
  // every one throws on reading `.caller`. Without this any JS wrapper, and so
  // our whole DOM, is detectable. An object is ours if its prototype chain has
  // the interface prototype or a constructor of that name (other realms too).
  let EXC = new Set(__BRAND_EXCEPTIONS__);
  const TRACE = __BRAND_TRACE__;
  const trace = (what) => {
    try {
      const st = __s_slice(__s_split(String(new Error().stack || ''), '\n'), 2, 7).map((x) => __s_replace(__s_trim(x), /https?:\/\/[^ )]*\//, '')).join(' < ');
      console.error('[brand] ' + what + ' | ' + st);
    } catch (e) {}
  };
  const illegal = (label, t) => {
    if (TRACE) {
      let who = ''; try { who = t === null ? 'null' : typeof t !== 'object' && typeof t !== 'function' ? typeof t : (Object.prototype.toString.call(t) + ' ' + __s_slice(Object.getOwnPropertyNames(t), 0, 5).join(',')); } catch (e) {}
      trace(label + ' this=' + who);
    }
    return __pt_mkErr(TypeError, 'Illegal invocation');
  };
  // The interface prototype itself is not an instance: it has its own
  // `constructor`, and graph walks call every getter on it expecting "Illegal
  // invocation". So the chain is checked from the object's prototype.
  const chainHas = (t, name) => {
    let p;
    try { p = Object.getPrototypeOf(t); } catch (e) { return false; }
    for (let i = 0; i < 12 && p; i++) {
      try {
        const c = Object.getOwnPropertyDescriptor(p, 'constructor');
        if (c && typeof c.value === 'function' && c.value.name === name) return true;
        p = Object.getPrototypeOf(p);
      } catch (e) { return false; }
    }
    return false;
  };
  // A bare call of a window member (`addEventListener('load', ...)`,
  // `postMessage(...)`) arrives with strict `this === undefined`; for global
  // object members the browser treats that as the window.
  const ownerOk = (C, P, t) => {
    if (t === undefined || t === null) return P.isPrototypeOf(globalThis);
    if (typeof t !== 'object' && typeof t !== 'function') return false;
    if (P.isPrototypeOf(t)) return true;
    if (t === globalThis) return true;
    return chainHas(t, C.name);
  };
  const asThis = (P, t) => ((t === undefined || t === null) && P.isPrototypeOf(globalThis) ? globalThis : t);
  const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  const desc = (o, k) => { try { return Object.getOwnPropertyDescriptor(o, k); } catch (e) { return undefined; } };
  const def = (o, k, d) => { try { Object.defineProperty(o, k, d); return true; } catch (e) { return false; } };
  const keyName = (k) => (typeof k === 'symbol' ? '[' + (k.description || '') + ']' : String(k));
  // Only fix `name`/`length` when wrong: editing moves the function to
  // dictionary mode (~290 bytes each), and there are thousands here.
  const setNL = (f, name, len) => {
    if (len !== undefined && f.length !== len) def(f, 'length', { value: len, configurable: true });
    if (name !== undefined && f.name !== name) def(f, 'name', { value: name, configurable: true });
    return f;
  };
  // A constructor (or alias like webkitURL) legitimately has a prototype; a
  // method does not. Told apart by the prototype's contents and the name.
  const ctorLike = (f, key) => {
    if (typeof key === 'string' && /^[A-Z]/.test(key)) return true;
    const p = f.prototype;
    if (!p) return false;
    try {
      const names = Object.getOwnPropertyNames(p);
      return names.length > 1 || (names.length === 1 && names[0] !== 'constructor');
    } catch (e) { return true; }
  };
  // Rebuilt method: strict (reading `.caller` throws), no `.prototype`, brand
  // check where due. `guard` is the interface constructor, or null when the
  // owner is not an interface prototype.
  let LENGTHS = __METHOD_LENGTHS__;
  const fewArgs = (what, need, got) => (TRACE && trace('args ' + what + ' need ' + need + ' got ' + got), __pt_mkErr(TypeError, 'Failed to execute \'' + __s_slice(what, __s_indexOf(what, '.') + 1) + '\' on \'' + __s_slice(what, 0, __s_indexOf(what, '.')) + '\': ' + need + ' argument' + (need === 1 ? '' : 's') + ' required, but only ' + got + ' present.'));
  const asMethod = (fn, key, guard) => {
    const name = keyName(key);
    const P = guard && guard.prototype;
    // Not captured: a label string per member added up; errors rebuild it.
    const lk = guard ? guard.name + '.' + name : name;
    // Chrome's number of required args; too few throws, as there.
    const need = guard && Object.prototype.hasOwnProperty.call(LENGTHS, lk) ? LENGTHS[lk] : fn.length;
    // Born with Chrome's `length`: one literal per arity, since writing
    // `length` afterwards moves the function to dictionary mode (~290 bytes,
    // thousands of methods per context). Rare longer ones are fixed after.
    let holder;
    switch (need) {
      case 0: holder = guard ? { [name]() { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); return fn.apply(asThis(P, this), arguments); } } : { [name]() { return fn.apply(this, arguments); } }; break;
      case 1: holder = guard ? { [name]($0) { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); return fn.apply(asThis(P, this), arguments); } } : { [name]($0) { return fn.apply(this, arguments); } }; break;
      case 2: holder = guard ? { [name]($0, $1) { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); return fn.apply(asThis(P, this), arguments); } } : { [name]($0, $1) { return fn.apply(this, arguments); } }; break;
      case 3: holder = guard ? { [name]($0, $1, $2) { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); return fn.apply(asThis(P, this), arguments); } } : { [name]($0, $1, $2) { return fn.apply(this, arguments); } }; break;
      case 4: holder = guard ? { [name]($0, $1, $2, $3) { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); return fn.apply(asThis(P, this), arguments); } } : { [name]($0, $1, $2, $3) { return fn.apply(this, arguments); } }; break;
      case 5: holder = guard ? { [name]($0, $1, $2, $3, $4) { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); return fn.apply(asThis(P, this), arguments); } } : { [name]($0, $1, $2, $3, $4) { return fn.apply(this, arguments); } }; break;
      case 6: holder = guard ? { [name]($0, $1, $2, $3, $4, $5) { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); return fn.apply(asThis(P, this), arguments); } } : { [name]($0, $1, $2, $3, $4, $5) { return fn.apply(this, arguments); } }; break;
      default: holder = guard ? { [name]() { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); return fn.apply(asThis(P, this), arguments); } } : { [name]() { return fn.apply(this, arguments); } };
    }
    const m = holder[name];
    return setNL(m, typeof key === 'symbol' ? name : key, need);
  };
  // Promise getters (`closed`, `ready`, `finished`...) on a foreign `this` do
  // not throw in the browser; they return a promise rejected with the TypeError.
  const PROMISE_GETTERS = new Set(['WritableStreamDefaultWriter.closed', 'WritableStreamDefaultWriter.ready', 'ViewTransition.finished', 'ViewTransition.ready', 'ViewTransition.updateCallbackDone', 'ReadableStreamDefaultReader.closed', 'ReadableStreamBYOBReader.closed', 'NavigationTransition.committed', 'NavigationTransition.finished', 'BeforeInstallPromptEvent.userChoice', 'Animation.finished', 'Animation.ready', 'ImageDecoder.completed', 'ImageTrackList.ready', 'MediaKeySession.closed', 'WebTransport.ready', 'WebTransport.closed', 'PresentationReceiver.connectionList', 'BackgroundFetchRecord.responseReady', 'WebSocketStream.opened', 'WebSocketStream.closed']);
  // V8 aliases carry the original's name (`trimLeft.name === 'trimStart'`,
  // `Set.prototype.keys.name === 'values'`); must not be renamed.
  const ALIAS_NAME = (owner, key, f) => (key === 'trimLeft' && f.name === 'trimStart') || (key === 'trimRight' && f.name === 'trimEnd')
    || (key === 'toGMTString' && f.name === 'toUTCString') || (key === 'keys' && f.name === 'values' && owner === Set.prototype);
  const asAccessor = (fn, key, kind, guard) => {
    const P = guard && guard.prototype;
    const rejects = !!guard && PROMISE_GETTERS.has(guard.name + '.' + keyName(key));
    // Method syntax: like a native getter, the trampoline has no `.prototype`.
    // A literal with a computed key gets name `get x`/`set x` and length 0/1
    // from birth.
    const k = typeof key === 'symbol' ? key : String(key);
    const g = kind === 'get '
      ? (guard ? Object.getOwnPropertyDescriptor({ get [k]() { if (!ownerOk(guard, P, this)) { const err = illegal(guard.name + '.' + keyName(key) + '#get', this); if (rejects) return Promise.reject(err); throw err; } return fn.call(asThis(P, this)); } }, k).get
               : Object.getOwnPropertyDescriptor({ get [k]() { return fn.call(this); } }, k).get)
      : (guard ? Object.getOwnPropertyDescriptor({ set [k](v) { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + keyName(key) + '#set', this); return fn.call(asThis(P, this), v); } }, k).set
               : Object.getOwnPropertyDescriptor({ set [k](v) { return fn.call(this, v); } }, k).set);
    return setNL(g, kind + keyName(key), kind === 'get ' ? 0 : 1);
  };
  // Strict (and native) functions throw on reading `.caller`.
  const isStrict = (f) => { try { void f.caller; return false; } catch (e) { return true; } };
  const STUBS = globalThis.__pt_stubMembers || null;
  const SLOTS = STUBS ? STUBS.slots : null;
  // A stub member gets one function, brand check and value store together,
  // instead of a guard wrapped around the stub: two closures per member were
  // most of a context's size. Each literal here makes only stubs.
  const stubAccessor = (key, kind, guard) => {
    const P = guard.prototype;
    const rejects = PROMISE_GETTERS.has(guard.name + '.' + keyName(key));
    const k = typeof key === 'symbol' ? key : String(key);
    const g = kind === 'get '
      ? Object.getOwnPropertyDescriptor({ get [k]() { if (!ownerOk(guard, P, this)) { const err = illegal(guard.name + '.' + keyName(key) + '#get', this); if (rejects) return Promise.reject(err); throw err; } const s = SLOTS.get(asThis(P, this)); return s && k in s ? s[k] : undefined; } }, k).get
      : Object.getOwnPropertyDescriptor({ set [k](v) { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + keyName(key) + '#set', this); const t = asThis(P, this); let s = SLOTS.get(t); if (!s) { s = Object.create(null); try { SLOTS.set(t, s); } catch (e) { return; } } s[k] = v; } }, k).set;
    STUBS.add(g);
    return setNL(g, kind + keyName(key), kind === 'get ' ? 0 : 1);
  };
  const stubMethod = (key, guard, need) => {
    const name = keyName(key);
    const P = guard.prototype;
    let holder;
    switch (need) {
      case 0: holder = { [name]() { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); } }; break;
      case 1: holder = { [name]($0) { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); } }; break;
      case 2: holder = { [name]($0, $1) { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); } }; break;
      case 3: holder = { [name]($0, $1, $2) { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); } }; break;
      default: holder = { [name]() { if (!ownerOk(guard, P, this)) throw illegal(guard.name + '.' + name, this); if (arguments.length < need) throw fewArgs(guard.name + '.' + name, need, arguments.length); } };
    }
    const m = holder[name];
    STUBS.add(m);
    return setNL(m, typeof key === 'symbol' ? name : key, need);
  };
  const fix = (owner, key, guard) => {
    const d = desc(owner, key);
    if (!d) return;
    const label = (guard ? guard.name : '') + '.' + keyName(key);
    const wantGuard = guard && !EXC.has(label);
    if (typeof d.value === 'function') {
      let f = d.value;
      if (key !== 'constructor' && !ctorLike(f, key)) {
        const needs = hasOwn(f, 'prototype') || !isStrict(f) || wantGuard
          || (guard && Object.prototype.hasOwnProperty.call(LENGTHS, label) && LENGTHS[label] !== f.length);
        if (needs && d.configurable) {
          // A surface stub stays a stub: layers that install real members over
          // stubs (audio) recognize them.
          f = wantGuard && STUBS && STUBS.has(f)
            ? stubMethod(key, guard, Object.prototype.hasOwnProperty.call(LENGTHS, label) ? LENGTHS[label] : f.length)
            : asMethod(f, key, wantGuard ? guard : null);
          def(owner, key, Object.assign({}, d, { value: f }));
        } else if (typeof key === 'string' && f.name !== key && !ALIAS_NAME(owner, key, f)) {
          def(f, 'name', { value: key, configurable: true });
        }
      }
      N(f);
    }
    if (d.get || d.set) {
      let get = d.get, set = d.set, changed = false;
      for (const kind of ['get ', 'set ']) {
        const f = kind === 'get ' ? get : set;
        if (typeof f !== 'function') continue;
        const wantG = guard && (!EXC.has(label + '#' + __s_trim(kind)) || (kind === 'get ' && PROMISE_GETTERS.has(label)));
        if ((wantG || !isStrict(f)) && d.configurable) {
          // A stub keeps the stub store; the engine's writes to a read-only
          // stub go through `__pt_writers`, to the same store.
          const w = wantG && STUBS && STUBS.has(f) ? stubAccessor(key, kind, guard) : asAccessor(f, key, kind, wantG ? guard : null);
          if (kind === 'get ') get = w; else set = w;
          changed = true;
          N(w);
        } else {
          const want = kind + keyName(key);
          if (f.name !== want) def(f, 'name', { value: want, configurable: true });
          N(f);
        }
      }
      if (changed) def(owner, key, { get, set, enumerable: d.enumerable, configurable: d.configurable });
    }
  };
  const BUILTIN = new Set(['Object', 'Function', 'Array', 'String', 'Number', 'Boolean', 'Symbol', 'Error',
    'RegExp', 'Date', 'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'ArrayBuffer', 'SharedArrayBuffer',
    'DataView', 'Proxy', 'BigInt', 'Iterator', 'FinalizationRegistry', 'WeakRef', 'AsyncDisposableStack',
    'DisposableStack', 'Temporal', 'AggregateError', 'EvalError', 'RangeError', 'ReferenceError',
    'SyntaxError', 'TypeError', 'URIError', 'SuppressedError', 'Int8Array', 'Uint8Array',
    'Uint8ClampedArray', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array', 'Float16Array',
    'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'Intl', 'Reflect', 'JSON',
    'Math', 'Atomics', 'WebAssembly', 'globalThis']);
  // Interface constructors behave like the browser's: a call without `new`
  // is refused, `new` on an abstract one throws "Illegal constructor", others
  // check the arg count. Outside sits a facade with the real class's
  // prototype and statics; the engine keeps the class itself.
  let CT = __CTOR_TABLE__;
  // Captured up front: the constructor facade must not call anything the page
  // can wrap.
  const RC = Reflect.construct, GPO = Object.getPrototypeOf, GOPD = Object.getOwnPropertyDescriptor;
  // Stub events (ErrorEvent, ProgressEvent, WheelEvent...: 79 of 93) were built
  // without event state, so the first `e.type` threw. Build through the
  // nearest real ancestor (Event, UIEvent, MouseEvent...) and put dict fields
  // into the interface's properties.
  const REAL_EVENT = new Map();
  const isRealEvent = (K) => {
    if (REAL_EVENT.has(K)) return REAL_EVENT.get(K);
    let ok = false;
    try { const o = RC(K, ['x'], K); ok = !!(o && o.__ptE); } catch (e) { ok = false; }
    REAL_EVENT.set(K, ok);
    return ok;
  };
  // Required event dict members: Chrome's constructor refuses without them
  // (captured from all window events).
  const EV_REQUIRED = {"WindowControlsOverlayGeometryChangeEvent":["titlebarAreaRect","WindowControlsOverlayGeometryChangeEventInit"],"TaskPriorityChangeEvent":["previousPriority","TaskPriorityChangeEventInit"],"RTCTrackEvent":["receiver","RTCTrackEventInit"],"RTCPeerConnectionIceErrorEvent":["errorCode","RTCPeerConnectionIceErrorEventInit"],"RTCErrorEvent":["error","RTCErrorEventInit"],"RTCDataChannelEvent":["channel","RTCDataChannelEventInit"],"PromiseRejectionEvent":["promise","PromiseRejectionEventInit"],"PictureInPictureEvent":["pictureInPictureWindow","PictureInPictureEventInit"],"OfflineAudioCompletionEvent":["renderedBuffer","OfflineAudioCompletionEventInit"],"NavigationCurrentEntryChangeEvent":["from","NavigationCurrentEntryChangeEventInit"],"NavigateEvent":["destination","NavigateEventInit"],"MediaStreamTrackEvent":["track","MediaStreamTrackEventInit"],"FormDataEvent":["formData","FormDataEventInit"],"BlobEvent":["data","BlobEventInit"],"AudioProcessingEvent":["inputBuffer","AudioProcessingEventInit"],"GPUUncapturedErrorEvent":["error","GPUUncapturedErrorEventInit"],"MediaKeyMessageEvent":["message","MediaKeyMessageEventInit"],"SensorErrorEvent":["error","SensorErrorEventInit"],"HIDConnectionEvent":["device","HIDConnectionEventInit"],"PresentationConnectionAvailableEvent":["connection","PresentationConnectionAvailableEventInit"],"PresentationConnectionCloseEvent":["reason","PresentationConnectionCloseEventInit"],"USBConnectionEvent":["device","USBConnectionEventInit"],"XRInputSourceEvent":["frame","XRInputSourceEventInit"],"XRInputSourcesChangeEvent":["added","XRInputSourcesChangeEventInit"],"XRReferenceSpaceEvent":["referenceSpace","XRReferenceSpaceEventInit"],"XRSessionEvent":["session","XRSessionEventInit"],"XRLayerEvent":["layer","XRLayerEventInit"],"XRVisibilityMaskChangeEvent":["eye","XRVisibilityMaskChangeEventInit"],"DocumentPictureInPictureEvent":["window","DocumentPictureInPictureEventInit"],"SpeechSynthesisErrorEvent":["utterance","SpeechSynthesisEventInit"],"SpeechSynthesisEvent":["utterance","SpeechSynthesisEventInit"]};
  // Events whose dicts do not inherit EventInit (bubbles/cancelable are not
  // read) and whose type is fixed by the interface.
  const EV_DEFAULTS = __EVENT_DEFAULTS__;
  const EV_FORCE = { IDBVersionChangeEvent: { bubbles: false, cancelable: false }, VirtualKeyboardGeometryChangeEvent: { bubbles: false, cancelable: false }, SecurityPolicyViolationEvent: { cancelable: false }, RTCDTMFToneChangeEvent: { type: 'tonechange' } };
  const eventFromStub = (C, args, nt, name) => {
    const req = EV_REQUIRED[name];
    if (req) {
      const i0 = args.length > 1 ? args[1] : undefined;
      if (!i0 || typeof i0 !== 'object' || i0[req[0]] === undefined) {
        throw __pt_mkErr(TypeError, "Failed to construct '" + name + "': Failed to read the '" + req[0] + "' property from '" + req[1] + "': Required member is undefined.");
      }
    }
    let base = null, stopAt = null;
    for (let p = GPO(C.prototype); p; p = GPO(p)) {
      const cd = GOPD(p, 'constructor');
      const K = cd && cd.value;
      if (typeof K === 'function' && K !== C && isRealEvent(K)) { base = K; stopAt = p; break; }
    }
    if (!base) return null;
    const force = EV_FORCE[name] || null;
    const type = force && force.type ? force.type : (args.length > 0 ? String(args[0]) : '');
    let init = args.length > 1 && args[1] && typeof args[1] === 'object' ? args[1] : undefined;
    let baseInit = init;
    if (force && init) { baseInit = Object.assign({}, init); for (const k of ['bubbles', 'cancelable']) if (k in force) baseInit[k] = force[k]; }
    const e = RC(base, baseInit === undefined ? [type] : [type, baseInit], nt);
    const W = globalThis.__pt_writers;
    const writeMember = (k, v) => {
      for (let p = C.prototype; p && p !== stopAt; p = GPO(p)) {
        const pd = GOPD(p, k);
        if (!pd) continue;
        const w = (W && W.get(p) && W.get(p)[k]) || pd.set;
        if (typeof w === 'function') { try { Reflect.apply(w, e, [v]); } catch (x) {} }
        return;
      }
    };
    // Missing from the dict: Chrome's default ('' / 0 / false / null).
    const DEF = EV_DEFAULTS[name];
    if (DEF) for (const k of Object.keys(DEF)) {
      if (init && init[k] !== undefined) continue;
      writeMember(k, DEF[k] === '__arr' ? [] : DEF[k]);
    }
    if (init) {
      for (const k in init) {
        if (k === 'bubbles' || k === 'cancelable' || k === 'composed') continue;
        for (let p = C.prototype; p && p !== stopAt; p = GPO(p)) {
          const pd = GOPD(p, k);
          if (!pd) continue;
          const w = (W && W.get(p) && W.get(p)[k]) || pd.set;
          if (typeof w === 'function') { try { Reflect.apply(w, e, [init[k]]); } catch (x) {} }
          break;
        }
      }
    }
    return e;
  };
  const EVENT_P = globalThis.Event && globalThis.Event.prototype;
  const facade = (name, C, d) => {
    const row = CT[name];
    // A namespace without a prototype (NodeFilter) is not a constructor and
    // needs no facade.
    if (!row || row.n === 'notctor' || !C.prototype) return;
    const F = { [name]: function () {
      if (TRACE && (new.target === undefined || (new.target === F && row.n !== 'ok'))) trace('ctor ' + name + ' new=' + (new.target !== undefined) + ' args=' + arguments.length + ' rule=' + row.n + '/' + row.c);
      if (new.target === undefined) {
        throw __pt_mkErr(TypeError, row.c === 'illegal' ? 'Illegal constructor'
          : 'Failed to construct \'' + name + '\': Please use the \'new\' operator, this DOM object constructor cannot be called as a function.');
      }
      // A subclass (`class X extends HTMLElement` via `super()`) is always
      // built: refusal and arg counting apply only to the interface itself.
      const own = new.target === F;
      if (own && row.n === 'illegal') throw __pt_mkErr(TypeError, 'Failed to construct \'' + name + '\': Illegal constructor');
      const m = own ? /^args:(\d+)$/.exec(row.n) : null;
      if (m && arguments.length < +m[1]) {
        throw __pt_mkErr(TypeError, 'Failed to construct \'' + name + '\': ' + m[1] + ' argument' + (m[1] === '1' ? '' : 's') + ' required, but only ' + arguments.length + ' present.');
      }
      const nt = new.target === F ? C : new.target;
      const made = RC(C, arguments, nt);
      if (EVENT_P && made && typeof made === 'object' && !made.__ptE && EVENT_P.isPrototypeOf(made)) {
        const e = eventFromStub(C, arguments, nt, name);
        if (e) return e;
      }
      return made;
    } }[name];
    def(F, 'name', { value: name, configurable: true });
    def(F, 'length', { value: row.l, configurable: true });
    def(F, 'prototype', { value: C.prototype, writable: false, enumerable: false, configurable: false });
    for (const k of keysOf(C)) {
      if (k === 'length' || k === 'name' || k === 'prototype' || k === 'arguments' || k === 'caller') continue;
      const sd = desc(C, k);
      if (sd) def(F, k, sd);
    }
    const cd = desc(C.prototype, 'constructor');
    if (cd && cd.configurable) def(C.prototype, 'constructor', Object.assign({}, cd, { value: F }));
    N(F);
    def(globalThis, name, Object.assign({}, d, { value: F }));
  };
  const keysOf = (o) => { try { return Object.getOwnPropertyNames(o).concat(Object.getOwnPropertySymbols(o)); } catch (e) { return []; } };
  let doneProto = new WeakSet();
  const walkProto = (proto, guard) => {
    if (!proto || typeof proto !== 'object' || doneProto.has(proto)) return;
    doneProto.add(proto);
    for (const k of keysOf(proto)) fix(proto, k, guard);
  };
  for (const name of Object.getOwnPropertyNames(globalThis)) {
    if (__s_slice(name, 0, 4) === '__pt') continue;
    if (SKIP && SKIP.test(name)) continue;
    const d = desc(globalThis, name);
    if (!d) continue;
    let C;
    try { C = d.value; } catch (e) { continue; }
    if (typeof C !== 'function') { if (d.get || d.set) fix(globalThis, name); continue; }
    fix(globalThis, name, null);
    for (const k of keysOf(C)) if (k !== 'length' && k !== 'name' && k !== 'prototype' && k !== 'arguments' && k !== 'caller') fix(C, k, null);
    // Brand checks apply to platform interface members; language builtins
    // (Array, Promise...) are V8-native and left alone.
    const platform = /^[A-Z]/.test(name) && !BUILTIN.has(name) && C.prototype !== Object.prototype;
    walkProto(C.prototype, platform ? C : null);
    if (platform && d.configurable) facade(name, C, d);
  }
  // Singletons: their methods sit on their own prototypes, which the walk
  // over constructors does not always reach.
  for (const name of ['navigator', 'document', 'performance', 'screen', 'history', 'location', 'localStorage', 'sessionStorage', 'crypto', 'speechSynthesis', 'visualViewport', 'scheduler']) {
    let o; try { o = globalThis[name]; } catch (e) { continue; }
    if (!o || typeof o !== 'object') continue;
    let p = Object.getPrototypeOf(o);
    for (let i = 0; i < 4 && p && p !== Object.prototype; i++) {
      const c = desc(p, 'constructor');
      walkProto(p, c && typeof c.value === 'function' && c.value.prototype === p ? c.value : null);
      p = Object.getPrototypeOf(p);
    }
  }
  // Load-time tables: the wrappers outlive this layer and keep its scope.
  CT = LENGTHS = EXC = doneProto = null;
})();"#;

pub fn late_interfaces_script() -> String {
    r##"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_toLowerCase = __sm(String.prototype.toLowerCase, 'toLowerCase'),
    __s_trim = __sm(String.prototype.trim, 'trim');
  const native = (f) => (globalThis.__pt_native ? __pt_native(f) : f);
  const named = (name, f) => {
    try { Object.defineProperty(f, 'name', { value: name, configurable: true }); } catch (e) {}
    return native(f);
  };
  const meth = (o, n, f) => {
    try {
      Object.defineProperty(o, n, { value: named(n, f), writable: true, enumerable: true, configurable: true });
    } catch (e) {}
  };
  const defg = (o, n, get, set) => {
    try {
      Object.defineProperty(o, n, {
        get: named('get ' + n, get),
        set: set ? named('set ' + n, set) : undefined,
        enumerable: true, configurable: true,
      });
    } catch (e) {}
  };
  const DESCRIPTORS = [['style', 'normal'], ['weight', 'normal'], ['stretch', 'normal'],
    ['unicodeRange', 'U+0-10FFFF'], ['variant', 'normal'], ['featureSettings', 'normal'],
    ['variationSettings', 'normal'], ['display', 'auto'], ['ascentOverride', 'normal'],
    ['descentOverride', 'normal'], ['lineGapOverride', 'normal'], ['sizeAdjust', 'normal']];
  const state = new WeakMap();
  const netError = () => __pt_mkErr(globalThis.DOMException || Error, 
    'A network error occurred.', 'NetworkError');
  const FontFace = function FontFace(family, source, descriptors) {
    if (!new.target) {
      throw __pt_mkErr(TypeError, "Failed to construct 'FontFace': Please use the 'new' operator, " +
        'this DOM object constructor cannot be called as a function.');
    }
    if (arguments.length < 2) {
      throw __pt_mkErr(TypeError, "Failed to construct 'FontFace': 2 arguments required, but only " +
        arguments.length + ' present.');
    }
    const own = { family: String(family), source: String(source), status: 'unloaded', promise: null };
    for (const [k, v] of DESCRIPTORS) {
      own[k] = descriptors && descriptors[k] !== undefined ? String(descriptors[k]) : v;
    }
    state.set(this, own);
  };
  const P = FontFace.prototype;
  const at = (o) => state.get(o) || {};
  for (const [k] of DESCRIPTORS.concat([['family']])) {
    defg(P, k, function () { return at(this)[k]; },
      function (v) { const o = state.get(this); if (o) o[k] = String(v); });
  }
  defg(P, 'status', function () { return at(this).status; });
  const start = (face) => {
    const o = state.get(face);
    if (!o) return Promise.reject(__pt_mkErr(TypeError, 'Illegal invocation'));
    if (o.promise) return o.promise;
    // `local(Name)` is the only source resolved without the network; anything
    // else fails with a network error, like the browser with an unreachable
    // URL. fontconfig substitutes do not count: the browser matches the font
    // files' own names, and `Arial` is not found on a machine without it.
    const m = /local\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))\s*\)/i.exec(o.source || '');
    const name = m ? __s_trim(String(m[1] || m[2] || m[3] || '')) : null;
    const have = !!(name && typeof globalThis.__pt_localFont === 'function' && __pt_localFont(name));
    o.status = 'loading';
    o.promise = have
      ? Promise.resolve().then(() => { o.status = 'loaded'; return face; })
      : Promise.resolve().then(() => { o.status = 'error'; throw netError(); });
    o.promise.catch(() => {});
    return o.promise;
  };
  meth(P, 'load', function load() { return start(this); });
  defg(P, 'loaded', function () { return start(this); });
  try { Object.defineProperty(P, Symbol.toStringTag, { value: 'FontFace', configurable: true }); } catch (e) {}
  try { Object.defineProperty(FontFace, 'length', { value: 2, configurable: true }); } catch (e) {}
  // The browser lists prototype names with `constructor` among them,
  // alphabetically: the table already put it first, leave as is.
  try {
    Object.defineProperty(globalThis, 'FontFace', {
      value: named('FontFace', FontFace), writable: true, enumerable: false, configurable: true,
    });
  } catch (e) {}

  // `DOMParser` and `XMLSerializer`: the name table puts empty classes there
  // and calls throw. The DOM layer does the work; this only declares them on
  // top of the table.
  const late = globalThis.__pt_lateDom;
  if (late) {
    const DOMParser = function DOMParser() {};
    meth(DOMParser.prototype, 'parseFromString', function parseFromString(markup, type) {
      if (arguments.length < 2) {
        throw __pt_mkErr(TypeError, "Failed to execute 'parseFromString' on 'DOMParser': " +
          '2 arguments required, but only ' + arguments.length + ' present.');
      }
      const kind = __s_toLowerCase(String(type));
      if (!/^(text\/html|text\/xml|application\/xml|application\/xhtml\+xml|image\/svg\+xml)$/.test(kind)) {
        throw __pt_mkErr(TypeError, "Failed to execute 'parseFromString' on 'DOMParser': " +
          "The provided value '" + type + "' is not a valid enum value of type SupportedType.");
      }
      return late.parseDocument(markup, kind);
    });
    try { Object.defineProperty(DOMParser.prototype, Symbol.toStringTag, { value: 'DOMParser', configurable: true }); } catch (e) {}
    const XMLSerializer = function XMLSerializer() {};
    meth(XMLSerializer.prototype, 'serializeToString', function serializeToString(node) {
      if (!arguments.length) {
        throw __pt_mkErr(TypeError, "Failed to execute 'serializeToString' on 'XMLSerializer': " +
          '1 argument required, but only 0 present.');
      }
      return late.serializeXml(node);
    });
    try { Object.defineProperty(XMLSerializer.prototype, Symbol.toStringTag, { value: 'XMLSerializer', configurable: true }); } catch (e) {}
    for (const [name, C] of [['DOMParser', DOMParser], ['XMLSerializer', XMLSerializer]]) {
      try {
        Object.defineProperty(globalThis, name,
          { value: named(name, C), writable: true, enumerable: false, configurable: true });
      } catch (e) {}
    }
  }

  // Five names we lacked on window entirely, and the challenge's graph walk
  // reads the whole window. Shapes captured from Chrome 151: member order,
  // descriptor kinds and parent per interface.
  {
    const eventProp = (P, k) => {
      let store = null;
      try {
        Object.defineProperty(P, k, {
          get: named('get ' + k, function () { return store; }),
          set: named('set ' + k, function (v) { store = v; }),
          enumerable: true, configurable: true,
        });
      } catch (e) {}
    };
    const getterProp = (P, k, v) => {
      try {
        Object.defineProperty(P, k, {
          get: named('get ' + k, function () { return typeof v === 'function' ? v.call(this) : v; }),
          enumerable: true, configurable: true,
        });
      } catch (e) {}
    };
    const finish = (P, C) => {
      // The browser's `constructor` comes last: it is added after members.
      try { delete P.constructor; } catch (e) {}
      try {
        Object.defineProperty(P, 'constructor', { value: C, writable: true, configurable: true });
      } catch (e) {}
    };
    const makeIface = (ifaceName, parentProto) => {
      const C = named(ifaceName, (function () {
        'use strict';
        return function () { throw __pt_mkErr(TypeError, 'Illegal constructor'); };
      })());
      const P = Object.create(parentProto || Object.prototype);
      try { Object.defineProperty(P, Symbol.toStringTag, { value: ifaceName, configurable: true }); } catch (e) {}
      try { Object.defineProperty(C, 'prototype', { value: P, writable: false, configurable: false }); } catch (e) {}
      try { Object.defineProperty(C, 'length', { value: 0, configurable: true }); } catch (e) {}
      return [C, P];
    };
    const publish = (ifaceName, C) => {
      try {
        Object.defineProperty(globalThis, ifaceName, {
          value: C, writable: true, enumerable: false, configurable: true,
        });
      } catch (e) {}
    };

    // The browser exposes `FontFaceSet` on window and `document.fonts` is an
    // instance; we lacked the name. Also matches member order and descriptors.
    try {
      const fonts = globalThis.document && document.fonts;
      const P = fonts ? Object.getPrototypeOf(fonts) : null;
      if (P && typeof globalThis.FontFaceSet !== 'function') {
        const C = P.constructor && P.constructor.name === 'FontFaceSet'
          ? P.constructor
          : named('FontFaceSet', (function () { 'use strict'; return function () { throw __pt_mkErr(TypeError, 'Illegal constructor'); }; })());
        try { Object.defineProperty(C, 'prototype', { value: P, writable: false, configurable: false }); } catch (e) {}
        try { Object.defineProperty(C, 'length', { value: 0, configurable: true }); } catch (e) {}
        // Browser order: handlers, getters, methods, `constructor`.
        const prev = {};
        for (const k of Object.getOwnPropertyNames(P)) {
          prev[k] = Object.getOwnPropertyDescriptor(P, k);
          if (k !== 'constructor') { try { delete P[k]; } catch (e) {} }
        }
        for (const k of ['onloading', 'onloadingdone', 'onloadingerror']) eventProp(P, k);
        for (const k of ['ready', 'status', 'size']) {
          const d = prev[k];
          if (d && d.get) {
            try { Object.defineProperty(P, k, { get: d.get, enumerable: true, configurable: true }); } catch (e) {}
          } else {
            getterProp(P, k, k === 'ready' ? function () { return Promise.resolve(this); }
                       : k === 'status' ? 'loaded' : 0);
          }
        }
        for (const k of ['check', 'load', 'add', 'clear', 'delete', 'entries', 'forEach', 'has', 'keys', 'values']) {
          const d = prev[k];
          if (d && typeof d.value === 'function') {
            try { Object.defineProperty(P, k, { value: d.value, writable: true, enumerable: true, configurable: true }); }
            catch (e) {}
          } else {
            meth(P, k, function () { return undefined; });
          }
        }
        finish(P, C);
        publish('FontFaceSet', C);
      }
    } catch (e) {}

    // The other four names stay bare interfaces: the page reads them in a
    // walk but never gets instances.
    const table = [
      ['CSSPseudoElement', null, [['type', 'g'], ['element', 'g'], ['parent', 'g'], ['pseudo', 'm']]],
      ['HTMLUserMediaElement', 'HTMLElement', [['error', 'g'], ['onstream', 'e'], ['oncancel', 'e'],
        ['onerror', 'e'], ['stream', 'g'], ['setConstraints', 'm']]],
      ['InteractionContentfulPaint', 'PerformanceEntry', [['largestContentfulPaint', 'g'],
        ['interactionId', 'g'], ['toJSON', 'm'], ['paintTime', 'g'], ['presentationTime', 'g']]],
      ['PerformanceSoftNavigation', 'PerformanceEntry', [['navigationType', 'g'], ['interactionId', 'g'],
        ['getLargestInteractionContentfulPaint', 'm'], ['paintTime', 'g'], ['presentationTime', 'g']]],
    ];
    for (const [ifaceName, parentName, members] of table) {
      if (typeof globalThis[ifaceName] === 'function') continue;
      let parentProto = Object.prototype;
      try {
        const B = parentName ? globalThis[parentName] : null;
        if (B && B.prototype) parentProto = B.prototype;
      } catch (e) {}
      const [C, P] = makeIface(ifaceName, parentProto);
      for (const [k, kind] of members) {
        if (kind === 'e') eventProp(P, k);
        else if (kind === 'g') getterProp(P, k, null);
        else meth(P, k, function () { return undefined; });
      }
      finish(P, C);
      publish(ifaceName, C);
    }
  }

})();"##
        .to_string()
}

/// Window own-property order captured from Chrome 151: everything after
/// `console`, i.e. after V8's own builtins, which V8 adds in the same order.
/// The challenge's graph walk enumerates the window, and enumeration returns
/// names in creation order, so order is as telling as membership.
const WINDOW_ORDER: &str = r#"["Option","Image","Audio","webkitURL","webkitRTCPeerConnection","webkitMediaStream","WebKitMutationObserver","WebKitCSSMatrix","XPathResult","XPathExpression","XPathEvaluator","XMLSerializer","XMLHttpRequestUpload","XMLHttpRequestEventTarget","XMLHttpRequest","XMLDocument","WritableStreamDefaultWriter","WritableStreamDefaultController","WritableStream","Worker","WindowControlsOverlayGeometryChangeEvent","WindowControlsOverlay","Window","WheelEvent","WebSocket","WebGLVertexArrayObject","WebGLUniformLocation","WebGLTransformFeedback","WebGLTexture","WebGLSync","WebGLShaderPrecisionFormat","WebGLShader","WebGLSampler","WebGLRenderingContext","WebGLRenderbuffer","WebGLQuery","WebGLProgram","WebGLObject","WebGLFramebuffer","WebGLContextEvent","WebGLBuffer","WebGLActiveInfo","WebGL2RenderingContext","WaveShaperNode","VisualViewport","VisibilityStateEntry","VirtualKeyboardGeometryChangeEvent","ViewTransitionTypeSet","ViewTransition","ViewTimeline","VideoPlaybackQuality","VideoFrame","VideoColorSpace","ValidityState","VTTCue","UserActivation","URLSearchParams","URLPattern","URL","UIEvent","TrustedTypePolicyFactory","TrustedTypePolicy","TrustedScriptURL","TrustedScript","TrustedHTML","TreeWalker","TransitionEvent","TransformStreamDefaultController","TransformStream","TrackEvent","TouchList","TouchEvent","Touch","ToggleEvent","TimeRanges","TextUpdateEvent","TextTrackList","TextTrackCueList","TextTrackCue","TextTrack","TextMetrics","TextFormatUpdateEvent","TextFormat","TextEvent","TextEncoderStream","TextEncoder","TextDecoderStream","TextDecoder","Text","TaskSignal","TaskPriorityChangeEvent","TaskController","TaskAttributionTiming","SyncManager","Subscriber","SubmitEvent","StyleSheetList","StyleSheet","StylePropertyMapReadOnly","StylePropertyMap","StorageEvent","Storage","StereoPannerNode","StaticRange","SourceBufferList","SourceBuffer","ShadowRoot","Selection","SecurityPolicyViolationEvent","ScrollTimeline","ScriptProcessorNode","ScreenOrientation","Screen","Scheduling","Scheduler","SVGViewElement","SVGUseElement","SVGUnitTypes","SVGTransformList","SVGTransform","SVGTitleElement","SVGTextPositioningElement","SVGTextPathElement","SVGTextElement","SVGTextContentElement","SVGTSpanElement","SVGSymbolElement","SVGSwitchElement","SVGStyleElement","SVGStringList","SVGStopElement","SVGSetElement","SVGScriptElement","SVGSVGElement","SVGRectElement","SVGRect","SVGRadialGradientElement","SVGPreserveAspectRatio","SVGPolylineElement","SVGPolygonElement","SVGPointList","SVGPoint","SVGPatternElement","SVGPathElement","SVGNumberList","SVGNumber","SVGMetadataElement","SVGMatrix","SVGMaskElement","SVGMarkerElement","SVGMPathElement","SVGLinearGradientElement","SVGLineElement","SVGLengthList","SVGLength","SVGImageElement","SVGGraphicsElement","SVGGradientElement","SVGGeometryElement","SVGGElement","SVGForeignObjectElement","SVGFilterElement","SVGFETurbulenceElement","SVGFETileElement","SVGFESpotLightElement","SVGFESpecularLightingElement","SVGFEPointLightElement","SVGFEOffsetElement","SVGFEMorphologyElement","SVGFEMergeNodeElement","SVGFEMergeElement","SVGFEImageElement","SVGFEGaussianBlurElement","SVGFEFuncRElement","SVGFEFuncGElement","SVGFEFuncBElement","SVGFEFuncAElement","SVGFEFloodElement","SVGFEDropShadowElement","SVGFEDistantLightElement","SVGFEDisplacementMapElement","SVGFEDiffuseLightingElement","SVGFEConvolveMatrixElement","SVGFECompositeElement","SVGFEComponentTransferElement","SVGFEColorMatrixElement","SVGFEBlendElement","SVGEllipseElement","SVGElement","SVGDescElement","SVGDefsElement","SVGComponentTransferFunctionElement","SVGClipPathElement","SVGCircleElement","SVGAnimationElement","SVGAnimatedTransformList","SVGAnimatedString","SVGAnimatedRect","SVGAnimatedPreserveAspectRatio","SVGAnimatedNumberList","SVGAnimatedNumber","SVGAnimatedLengthList","SVGAnimatedLength","SVGAnimatedInteger","SVGAnimatedEnumeration","SVGAnimatedBoolean","SVGAnimatedAngle","SVGAnimateTransformElement","SVGAnimateMotionElement","SVGAnimateElement","SVGAngle","SVGAElement","Response","ResizeObserverSize","ResizeObserverEntry","ResizeObserver","Request","ReportingObserver","ReportBody","ReadableStreamDefaultReader","ReadableStreamDefaultController","ReadableStreamBYOBRequest","ReadableStreamBYOBReader","ReadableStream","ReadableByteStreamController","Range","RadioNodeList","RTCTrackEvent","RTCStatsReport","RTCSessionDescription","RTCSctpTransport","RTCRtpTransceiver","RTCRtpSender","RTCRtpReceiver","RTCPeerConnectionIceEvent","RTCPeerConnectionIceErrorEvent","RTCPeerConnection","RTCIceTransport","RTCIceCandidate","RTCErrorEvent","RTCError","RTCEncodedVideoFrame","RTCEncodedAudioFrame","RTCDtlsTransport","RTCDataChannelEvent","RTCDTMFToneChangeEvent","RTCDTMFSender","RTCCertificate","PromiseRejectionEvent","ProgressEvent","ProcessingInstruction","PopStateEvent","PointerEvent","PluginArray","Plugin","PictureInPictureWindow","PictureInPictureEvent","Permissions","PermissionStatus","PeriodicWave","PerformanceTiming","PerformanceServerTiming","PerformanceScriptTiming","PerformanceResourceTiming","PerformancePaintTiming","PerformanceObserverEntryList","PerformanceObserver","PerformanceNavigationTiming","PerformanceNavigation","PerformanceMeasure","PerformanceMark","PerformanceLongTaskTiming","PerformanceLongAnimationFrameTiming","PerformanceEventTiming","PerformanceEntry","PerformanceElementTiming","Performance","Path2D","PannerNode","PageTransitionEvent","OverconstrainedError","OscillatorNode","OffscreenCanvasRenderingContext2D","OffscreenCanvas","OfflineAudioContext","OfflineAudioCompletionEvent","Observable","NodeList","NodeIterator","NodeFilter","Node","NetworkInformation","NavigatorUAData","Navigator","NavigationTransition","NavigationPrecommitController","NavigationHistoryEntry","NavigationDestination","NavigationCurrentEntryChangeEvent","NavigationActivation","Navigation","NavigateEvent","NamedNodeMap","MutationRecord","MutationObserver","MouseEvent","MimeTypeArray","MimeType","MessagePort","MessageEvent","MessageChannel","MediaStreamTrackVideoStats","MediaStreamTrackProcessor","MediaStreamTrackGenerator","MediaStreamTrackEvent","MediaStreamTrackAudioStats","MediaStreamTrack","MediaStreamEvent","MediaStreamAudioSourceNode","MediaStreamAudioDestinationNode","MediaStream","MediaSourceHandle","MediaSource","MediaRecorder","MediaQueryListEvent","MediaQueryList","MediaList","MediaError","MediaEncryptedEvent","MediaElementAudioSourceNode","MediaCapabilities","MathMLElement","Location","LayoutShiftAttribution","LayoutShift","LargestContentfulPaint","KeyframeEffect","KeyboardEvent","IntersectionObserverEntry","IntersectionObserver","InterestEvent","InputEvent","InputDeviceInfo","InputDeviceCapabilities","Ink","ImageData","ImageBitmapRenderingContext","ImageBitmap","IdleDeadline","IIRFilterNode","IDBVersionChangeEvent","IDBTransaction","IDBRequest","IDBRecord","IDBOpenDBRequest","IDBObjectStore","IDBKeyRange","IDBIndex","IDBFactory","IDBDatabase","IDBCursorWithValue","IDBCursor","History","HighlightRegistry","Highlight","Headers","HashChangeEvent","HTMLVideoElement","HTMLUnknownElement","HTMLUListElement","HTMLTrackElement","HTMLTitleElement","HTMLTimeElement","HTMLTextAreaElement","HTMLTemplateElement","HTMLTableSectionElement","HTMLTableRowElement","HTMLTableElement","HTMLTableColElement","HTMLTableCellElement","HTMLTableCaptionElement","HTMLStyleElement","HTMLSpanElement","HTMLSourceElement","HTMLSlotElement","HTMLSelectedContentElement","HTMLSelectElement","HTMLScriptElement","HTMLQuoteElement","HTMLProgressElement","HTMLPreElement","HTMLPictureElement","HTMLParamElement","HTMLParagraphElement","HTMLOutputElement","HTMLOptionsCollection","HTMLOptionElement","HTMLOptGroupElement","HTMLObjectElement","HTMLOListElement","HTMLModElement","HTMLMeterElement","HTMLMetaElement","HTMLMenuElement","HTMLMediaElement","HTMLMarqueeElement","HTMLMapElement","HTMLLinkElement","HTMLLegendElement","HTMLLabelElement","HTMLLIElement","HTMLInputElement","HTMLImageElement","HTMLIFrameElement","HTMLHtmlElement","HTMLHeadingElement","HTMLHeadElement","HTMLHRElement","HTMLFrameSetElement","HTMLFrameElement","HTMLFormElement","HTMLFormControlsCollection","HTMLFontElement","HTMLFieldSetElement","HTMLEmbedElement","HTMLElement","HTMLDocument","HTMLDivElement","HTMLDirectoryElement","HTMLDialogElement","HTMLDetailsElement","HTMLDataListElement","HTMLDataElement","HTMLDListElement","HTMLCollection","HTMLCanvasElement","HTMLButtonElement","HTMLBodyElement","HTMLBaseElement","HTMLBRElement","HTMLAudioElement","HTMLAreaElement","HTMLAnchorElement","HTMLAllCollection","GeolocationPositionError","GeolocationPosition","GeolocationCoordinates","Geolocation","GamepadHapticActuator","GamepadEvent","GamepadButton","Gamepad","GainNode","FormDataEvent","FormData","FontFaceSetLoadEvent","FontFaceSet","FontFace","FocusEvent","FileReader","FileList","File","FeaturePolicy","External","EventTarget","EventSource","EventCounts","Event","ErrorEvent","EncodedVideoChunk","EncodedAudioChunk","ElementInternals","Element","EditContext","DynamicsCompressorNode","DragEvent","DocumentType","DocumentTimeline","DocumentFragment","Document","DelegatedInkTrailPresenter","DelayNode","DecompressionStream","DataTransferItemList","DataTransferItem","DataTransfer","DOMTokenList","DOMStringMap","DOMStringList","DOMRectReadOnly","DOMRectList","DOMRect","DOMQuad","DOMPointReadOnly","DOMPoint","DOMParser","DOMMatrixReadOnly","DOMMatrix","DOMImplementation","DOMException","DOMError","CustomStateSet","CustomEvent","CustomElementRegistry","Crypto","CountQueuingStrategy","ConvolverNode","ContentVisibilityAutoStateChangeEvent","ConstantSourceNode","CompressionStream","CompositionEvent","Comment","CommandEvent","CloseWatcher","CloseEvent","ClipboardEvent","CharacterData","CharacterBoundsUpdateEvent","ChannelSplitterNode","ChannelMergerNode","CaretPosition","CanvasRenderingContext2D","CanvasPattern","CanvasGradient","CanvasCaptureMediaStreamTrack","CSSViewTransitionRule","CSSVariableReferenceValue","CSSUnparsedValue","CSSUnitValue","CSSTranslate","CSSTransition","CSSTransformValue","CSSTransformComponent","CSSSupportsRule","CSSStyleValue","CSSStyleSheet","CSSStyleRule","CSSStyleDeclaration","CSSStartingStyleRule","CSSSkewY","CSSSkewX","CSSSkew","CSSScopeRule","CSSScale","CSSRuleList","CSSRule","CSSRotate","CSSPropertyRule","CSSPositionValue","CSSPositionTryRule","CSSPositionTryDescriptors","CSSPerspective","CSSPageRule","CSSNumericValue","CSSNumericArray","CSSNestedDeclarations","CSSNamespaceRule","CSSMediaRule","CSSMatrixComponent","CSSMathValue","CSSMathSum","CSSMathProduct","CSSMathNegate","CSSMathMin","CSSMathMax","CSSMathInvert","CSSMathClamp","CSSMarginRule","CSSLayerStatementRule","CSSLayerBlockRule","CSSKeywordValue","CSSKeyframesRule","CSSKeyframeRule","CSSImportRule","CSSImageValue","CSSGroupingRule","CSSFontPaletteValuesRule","CSSFontFaceRule","CSSCounterStyleRule","CSSContainerRule","CSSConditionRule","CSSAnimation","CSS","CSPViolationReportBody","CDATASection","ByteLengthQueuingStrategy","BrowserCaptureMediaStreamTrack","BroadcastChannel","BlobEvent","Blob","BiquadFilterNode","BeforeUnloadEvent","BeforeInstallPromptEvent","BaseAudioContext","BarProp","AudioWorkletNode","AudioSinkInfo","AudioScheduledSourceNode","AudioProcessingEvent","AudioParamMap","AudioParam","AudioNode","AudioListener","AudioDestinationNode","AudioData","AudioContext","AudioBufferSourceNode","AudioBuffer","Attr","AnimationTimeline","AnimationPlaybackEvent","AnimationEvent","AnimationEffect","Animation","AnalyserNode","AbstractRange","AbortSignal","AbortController","window","self","document","name","location","customElements","history","navigation","locationbar","menubar","personalbar","scrollbars","statusbar","toolbar","status","closed","frames","length","top","opener","parent","frameElement","navigator","origin","external","screen","innerWidth","innerHeight","scrollX","pageXOffset","scrollY","pageYOffset","visualViewport","screenX","screenY","outerWidth","outerHeight","devicePixelRatio","event","clientInformation","offscreenBuffering","screenLeft","screenTop","styleMedia","onsearch","onappinstalled","onbeforeinstallprompt","onabort","onbeforeinput","onbeforematch","onbeforetoggle","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncuechange","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpause","onplay","onplaying","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onsecuritypolicyviolation","onseeked","onseeking","onselect","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","onauxclick","ongotpointercapture","onlostpointercapture","onpointerdown","onpointermove","onpointerup","onpointercancel","onpointerover","onpointerout","onpointerenter","onpointerleave","onselectstart","onselectionchange","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","ontransitionrun","ontransitionstart","ontransitionend","ontransitioncancel","onbeforexrselect","onafterprint","onbeforeprint","onbeforeunload","onhashchange","onlanguagechange","onmessage","onmessageerror","onoffline","ononline","onpagehide","onpageshow","onpopstate","onrejectionhandled","onstorage","onunhandledrejection","onunload","isSecureContext","crossOriginIsolated","scheduler","performance","trustedTypes","crypto","indexedDB","localStorage","sessionStorage","alert","atob","blur","btoa","cancelAnimationFrame","cancelIdleCallback","captureEvents","clearInterval","clearTimeout","close","confirm","createImageBitmap","fetch","find","focus","getComputedStyle","getSelection","matchMedia","moveBy","moveTo","open","postMessage","print","prompt","queueMicrotask","releaseEvents","reportError","requestAnimationFrame","requestIdleCallback","resizeBy","resizeTo","scroll","scrollBy","scrollTo","setInterval","setTimeout","stop","structuredClone","webkitCancelAnimationFrame","webkitRequestAnimationFrame","Temporal","SuppressedError","DisposableStack","AsyncDisposableStack","Float16Array","chrome","WebAssembly","crashReport","cookieStore","ondevicemotion","ondeviceorientation","ondeviceorientationabsolute","onpointerrawupdate","caches","documentPictureInPicture","sharedStorage","AbsoluteOrientationSensor","Accelerometer","AudioDecoder","AudioEncoder","AudioWorklet","BatteryManager","Cache","CacheStorage","Clipboard","ClipboardChangeEvent","ClipboardItem","CookieChangeEvent","CookieStore","CookieStoreManager","CreateMonitor","Credential","CredentialsContainer","CryptoKey","DeviceMotionEvent","DeviceMotionEventAcceleration","DeviceMotionEventRotationRate","DeviceOrientationEvent","FederatedCredential","GPU","GPUAdapter","GPUAdapterInfo","GPUBindGroup","GPUBindGroupLayout","GPUBuffer","GPUBufferUsage","GPUCanvasContext","GPUColorWrite","GPUCommandBuffer","GPUCommandEncoder","GPUCompilationInfo","GPUCompilationMessage","GPUComputePassEncoder","GPUComputePipeline","GPUDevice","GPUDeviceLostInfo","GPUError","GPUExternalTexture","GPUInternalError","GPUMapMode","GPUOutOfMemoryError","GPUPipelineError","GPUPipelineLayout","GPUQuerySet","GPUQueue","GPURenderBundle","GPURenderBundleEncoder","GPURenderPassEncoder","GPURenderPipeline","GPUSampler","GPUShaderModule","GPUShaderStage","GPUSupportedFeatures","GPUSupportedLimits","GPUTexture","GPUTextureUsage","GPUTextureView","GPUUncapturedErrorEvent","GPUValidationError","GravitySensor","Gyroscope","IdleDetector","ImageCapture","ImageDecoder","ImageTrack","ImageTrackList","Keyboard","KeyboardLayoutMap","LinearAccelerationSensor","MIDIAccess","MIDIConnectionEvent","MIDIInput","MIDIInputMap","MIDIMessageEvent","MIDIOutput","MIDIOutputMap","MIDIPort","MediaDeviceInfo","MediaDevices","MediaKeyMessageEvent","MediaKeySession","MediaKeyStatusMap","MediaKeySystemAccess","MediaKeys","NavigationPreloadManager","NavigatorManagedData","OrientationSensor","PasswordCredential","ProtectedAudience","RelativeOrientationSensor","ScreenDetailed","ScreenDetails","Sensor","SensorErrorEvent","ServiceWorkerRegistration","StorageManager","SubtleCrypto","VideoDecoder","VideoEncoder","VirtualKeyboard","WGSLLanguageFeatures","WebTransport","WebTransportBidirectionalStream","WebTransportDatagramDuplexStream","WebTransportError","Worklet","XRDOMOverlayState","XRLayer","XRWebGLBinding","AudioPlaybackStats","AuthenticatorAssertionResponse","AuthenticatorAttestationResponse","AuthenticatorResponse","PublicKeyCredential","CaptureController","CrashReportContext","DevicePosture","DigitalCredential","DocumentPictureInPicture","FetchLaterResult","FileSystemDirectoryHandle","FileSystemFileHandle","FileSystemHandle","FileSystemWritableFileStream","FileSystemObserver","FontData","FragmentDirective","HID","HIDConnectionEvent","HIDDevice","HIDInputReportEvent","IdentityCredential","IdentityCredentialError","IdentityProvider","NavigatorLogin","LanguageDetector","LanguageModel","Lock","LockManager","ServiceWorker","ServiceWorkerContainer","NotRestoredReasonDetails","NotRestoredReasons","OTPCredential","PaymentAddress","PaymentRequest","PaymentRequestUpdateEvent","PaymentResponse","PaymentManager","PaymentMethodChangeEvent","Presentation","PresentationAvailability","PresentationConnection","PresentationConnectionAvailableEvent","PresentationConnectionCloseEvent","PresentationConnectionList","PresentationReceiver","PresentationRequest","PressureObserver","PressureRecord","Serial","SerialPort","SpeechRecognitionPhrase","StorageBucket","StorageBucketManager","Summarizer","Translator","USB","USBAlternateInterface","USBConfiguration","USBConnectionEvent","USBDevice","USBEndpoint","USBInTransferResult","USBInterface","USBIsochronousInTransferPacket","USBIsochronousInTransferResult","USBIsochronousOutTransferPacket","USBIsochronousOutTransferResult","USBOutTransferResult","WakeLock","WakeLockSentinel","XRAnchor","XRAnchorSet","XRBoundedReferenceSpace","XRCPUDepthInformation","XRCamera","XRDepthInformation","XRFrame","XRHand","XRHitTestResult","XRHitTestSource","XRInputSource","XRInputSourceArray","XRInputSourceEvent","XRInputSourcesChangeEvent","XRJointPose","XRJointSpace","XRLightEstimate","XRLightProbe","XRPose","XRRay","XRReferenceSpace","XRReferenceSpaceEvent","XRRenderState","XRRigidTransform","XRSession","XRSessionEvent","XRSpace","XRSystem","XRTransientInputHitTestResult","XRTransientInputHitTestSource","XRView","XRViewerPose","XRViewport","XRWebGLDepthInformation","XRWebGLLayer","XRCompositionLayer","XRProjectionLayer","XRCubeLayer","XRCylinderLayer","XREquirectLayer","XRLayerEvent","XRQuadLayer","XRSubImage","XRWebGLSubImage","XRPlane","XRPlaneSet","XRVisibilityMaskChangeEvent","fetchLater","getScreenDetails","queryLocalFonts","showDirectoryPicker","showOpenFilePicker","showSaveFilePicker","originAgentCluster","viewport","onpageswap","onpagereveal","credentialless","fence","launchQueue","speechSynthesis","onscrollsnapchange","onscrollsnapchanging","ongamepadconnected","ongamepaddisconnected","AnimationTrigger","BackgroundFetchManager","BackgroundFetchRecord","BackgroundFetchRegistration","CSSFontFeatureValuesRule","CSSFunctionDeclarations","CSSFunctionDescriptors","CSSFunctionRule","CSSPseudoElement","ChapterInformation","CropTarget","DocumentPictureInPictureEvent","Fence","FencedFrameConfig","HTMLFencedFrameElement","HTMLGeolocationElement","HTMLUserMediaElement","IntegrityViolationReportBody","InteractionContentfulPaint","PerformanceSoftNavigation","LaunchParams","LaunchQueue","MediaMetadata","MediaSession","Notification","Origin","PageRevealEvent","PageSwapEvent","PerformanceTimingConfidence","PeriodicSyncManager","Profiler","PushManager","PushSubscription","PushSubscriptionOptions","QuotaExceededError","RTCDataChannel","RTCRtpScriptTransform","RemotePlayback","RestrictionTarget","Sanitizer","SharedStorage","SharedStorageWorklet","SharedStorageAppendMethod","SharedStorageClearMethod","SharedStorageDeleteMethod","SharedStorageModifierMethod","SharedStorageSetMethod","SharedWorker","SnapEvent","SpeechGrammar","SpeechGrammarList","SpeechRecognition","SpeechRecognitionErrorEvent","SpeechRecognitionEvent","SpeechSynthesis","SpeechSynthesisErrorEvent","SpeechSynthesisEvent","SpeechSynthesisUtterance","SpeechSynthesisVoice","TimelineTrigger","TimelineTriggerRange","TimelineTriggerRangeList","Viewport","WebSocketError","WebSocketStream","XSLTProcessor","webkitSpeechGrammar","webkitSpeechGrammarList","webkitSpeechRecognition","webkitSpeechRecognitionError","webkitSpeechRecognitionEvent","webkitRequestFileSystem","webkitResolveLocalFileSystemURL"]"#;

/// Reorders window names into the browser's order: a redefined own property
/// moves to the end, so one pass over the list fixes the whole tail. Runs
/// last, after all layers.
/// Late shape fixes on top of all layers: WebAssembly name order (Chrome
/// defines compileStreaming/instantiateStreaming before JSPI), webkit-prefixed
/// aliases being the same objects as the originals, RTCPeerConnection arity,
/// Notification static order.
/// Chrome 151 constructor statics (order, flags, lengths), captured from Chrome.
const CTOR_STATICS: &str = include_str!("ctor_statics.json");
/// Chrome 151 prototype member shapes (name, length, strictness, accessors), captured from Chrome.
const PROTO_MEMBERS: &str = include_str!("proto_members.json");

pub fn shape_fixes_script() -> String {
    SHAPE_FIXES.replace("__CTOR_STATICS__", &json_table(CTOR_STATICS)).replace("__PROTO_MEMBERS__", &json_table(PROTO_MEMBERS))
}

const SHAPE_FIXES: &str = r#"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_charCodeAt = __sm(String.prototype.charCodeAt, 'charCodeAt'),
    __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_includes = __sm(String.prototype.includes, 'includes'),
    __s_split = __sm(String.prototype.split, 'split'),
    __s_replace = __sm(String.prototype.replace, 'replace'),
    __s_toLowerCase = __sm(String.prototype.toLowerCase, 'toLowerCase');
  const redo = (o, k) => { try { const d = Object.getOwnPropertyDescriptor(o, k); if (d && d.configurable) { delete o[k]; Object.defineProperty(o, k, d); } } catch (e) {} };
  try { for (const k of ['Suspending', 'promising', 'SuspendError']) redo(globalThis.WebAssembly, k); } catch (e) {}
  for (const [alias, orig] of [['webkitURL', 'URL'], ['webkitMediaStream', 'MediaStream'], ['WebKitMutationObserver', 'MutationObserver'],
                               ['WebKitCSSMatrix', 'DOMMatrix'], ['webkitRTCPeerConnection', 'RTCPeerConnection']]) {
    try {
      const d = Object.getOwnPropertyDescriptor(globalThis, alias); const o = globalThis[orig];
      if (d && d.configurable && typeof o === 'function' && d.value !== o) Object.defineProperty(globalThis, alias, { value: o, writable: true, enumerable: false, configurable: true });
    } catch (e) {}
  }
  try { if (globalThis.RTCPeerConnection) Object.defineProperty(RTCPeerConnection, 'length', { value: 0, configurable: true }); } catch (e) {}
  // Graph shape per diff against Chrome 151.
  try {
    const nat = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    // Method without `.prototype`, masked: wrapper with method syntax.
    const methodize = (o, k) => {
      try {
        const d = Object.getOwnPropertyDescriptor(o, k);
        if (!d || typeof d.value !== 'function' || !d.configurable) return;
        const f = d.value;
        const isAsync = Object.prototype.toString.call(f) === '[object AsyncFunction]';
        if (!Object.prototype.hasOwnProperty.call(f, 'prototype') && !isAsync && globalThis.__pt_native && /\[native code\]/.test(Function.prototype.toString.call(f))) return;
        const m = ({ [k](...a) { return f.apply(this, a); } })[k];
        try { Object.defineProperty(m, 'length', { value: f.length, configurable: true }); } catch (e) {}
        Object.defineProperty(o, k, { value: nat(m, k), writable: d.writable, enumerable: d.enumerable, configurable: true });
      } catch (e) {}
    };
    // Iterable lists share methods with Array.prototype, as in the browser.
    for (const n of ['NodeList', 'DOMTokenList', 'CSSUnparsedValue', 'CSSTransformValue', 'CSSNumericArray', 'XRInputSourceArray', 'TimelineTriggerRangeList']) {
      const P = globalThis[n] && globalThis[n].prototype; if (!P) continue;
      for (const k of ['entries', 'keys', 'values', 'forEach']) { try { Object.defineProperty(P, k, { value: Array.prototype[k], writable: true, enumerable: true, configurable: true }); } catch (e) {} }
      try { Object.defineProperty(P, Symbol.iterator, { value: Array.prototype.values, writable: true, enumerable: false, configurable: true }); } catch (e) {}
    }
    // console: dummy prototype, `memory`, methods without `.prototype`.
    if (globalThis.console && typeof console === 'object') {
      try { if (Object.getPrototypeOf(console) === Object.prototype) Object.setPrototypeOf(console, Object.create(Object.prototype)); } catch (e) {}
      try {
        if (!('memory' in console)) {
          const mem = globalThis.performance && performance.memory;
          const MI = mem ? Object.getPrototypeOf(mem) : Object.prototype;
          const m = Object.create(MI);
          Object.defineProperty(console, 'memory', { get: nat(function () { return m; }, 'get memory'), set: nat(function () {}, 'set memory'), enumerable: true, configurable: true });
        }
      } catch (e) {}
      for (const k of Object.getOwnPropertyNames(console)) methodize(console, k);
    }
    // CSS: unit factories, highlights, paintWorklet, registerProperty.
    if (globalThis.CSS && typeof CSS === 'object') {
      const UNITS = ['Hz', 'Q', 'cap', 'ch', 'cm', 'cqb', 'cqh', 'cqi', 'cqmax', 'cqmin', 'cqw', 'deg', 'dpcm', 'dpi', 'dppx', 'dvb', 'dvh', 'dvi', 'dvmax', 'dvmin', 'dvw', 'em', 'ex', 'fr', 'grad', 'ic', 'in', 'kHz', 'lh', 'lvb', 'lvh', 'lvi', 'lvmax', 'lvmin', 'lvw', 'mm', 'ms', 'number', 'pc', 'percent', 'pt', 'px', 'rad', 'rcap', 'rch', 'rem', 'rex', 'ric', 'rlh', 's', 'svb', 'svh', 'svi', 'svmax', 'svmin', 'svw', 'turn', 'vb', 'vh', 'vi', 'vmax', 'vmin', 'vw', 'x'];
      let U = globalThis.CSSUnitValue;
      let ok = false; try { const t = new U(1, 'px'); ok = t && t.unit === 'px' && t.value === 1; } catch (e) {}
      if (!ok) {
        const NV = globalThis.CSSNumericValue;
        const STATE = new WeakMap();
        const CU = function CSSUnitValue(value, unit) {
          if (!new.target) throw __pt_mkErr(TypeError, "Failed to construct 'CSSUnitValue': Please use the 'new' operator, this DOM object constructor cannot be called as a function.");
          if (arguments.length < 2) throw __pt_mkErr(TypeError, "Failed to construct 'CSSUnitValue': 2 arguments required, but only " + arguments.length + ' present.');
          const v = Number(value); const u = String(unit);
          if (!isFinite(v)) throw __pt_mkErr(TypeError, "Failed to construct 'CSSUnitValue': The provided double value is non-finite.");
          if (!__s_includes(UNITS, u)) throw __pt_mkErr(TypeError, "Failed to construct 'CSSUnitValue': Invalid unit: " + u);
          STATE.set(this, { value: v, unit: u });
        };
        const oldP = U && U.prototype;
        CU.prototype = oldP && typeof oldP === 'object' ? oldP : Object.create(NV ? NV.prototype : Object.prototype);
        try { Object.defineProperty(CU.prototype, 'constructor', { value: CU, writable: true, configurable: true }); } catch (e) {}
        const st = (o) => { const x = STATE.get(o); if (!x) throw __pt_mkErr(TypeError, 'Illegal invocation'); return x; };
        Object.defineProperty(CU.prototype, 'value', { get: nat(function () { return st(this).value; }, 'get value'), set: nat(function (v) { st(this).value = Number(v); }, 'set value'), enumerable: true, configurable: true });
        Object.defineProperty(CU.prototype, 'unit', { get: nat(function () { return st(this).unit; }, 'get unit'), enumerable: true, configurable: true });
        const suffix = (u) => (u === 'number' ? '' : u === 'percent' ? '%' : u);
        Object.defineProperty(CU.prototype, 'toString', { value: nat(({ toString() { const x = st(this); return String(x.value) + suffix(x.unit); } }).toString, 'toString'), writable: true, enumerable: true, configurable: true });
        try { Object.defineProperty(CU.prototype, Symbol.toStringTag, { value: 'CSSUnitValue', configurable: true }); } catch (e) {}
        try { Object.defineProperty(CU, 'length', { value: 2, configurable: true }); } catch (e) {}
        Object.defineProperty(globalThis, 'CSSUnitValue', { value: nat(CU, 'CSSUnitValue'), writable: true, enumerable: false, configurable: true });
        U = CU;
      }
      for (const u of UNITS) {
        if (typeof CSS[u] === 'function') continue;
        const f = ({ [u](value) { if (arguments.length < 1) throw __pt_mkErr(TypeError, "Failed to execute '" + u + "' on 'CSS': 1 argument required, but only 0 present."); return new U(value, u); } })[u];
        Object.defineProperty(CSS, u, { value: nat(f, u), writable: true, enumerable: true, configurable: true });
      }
      if (!('highlights' in CSS)) { const HR = globalThis.HighlightRegistry; const h = HR && HR.prototype ? Object.create(HR.prototype) : new Map(); Object.defineProperty(CSS, 'highlights', { get: nat(function () { return h; }, 'get highlights'), enumerable: true, configurable: true }); }
      if (!('paintWorklet' in CSS)) { const W = globalThis.Worklet; const w = W && W.prototype ? Object.create(W.prototype) : {}; Object.defineProperty(CSS, 'paintWorklet', { get: nat(function () { return w; }, 'get paintWorklet'), enumerable: true, configurable: true }); }
      if (typeof CSS.registerProperty !== 'function') { Object.defineProperty(CSS, 'registerProperty', { value: nat(({ registerProperty(d) { if (arguments.length < 1) throw __pt_mkErr(TypeError, "Failed to execute 'registerProperty' on 'CSS': 1 argument required, but only 0 present."); } }).registerProperty, 'registerProperty'), writable: true, enumerable: true, configurable: true }); }
      for (const k of ['escape', 'supports']) methodize(CSS, k);
    }
    // Frozen static lists.
    const FROZEN_ENC = Object.freeze(['aes128gcm', 'aesgcm']);
    const FROZEN_SRC = Object.freeze(['cpu']);
    try { if (globalThis.PushManager) Object.defineProperty(PushManager, 'supportedContentEncodings', { get: nat(function () { return FROZEN_ENC; }, 'get supportedContentEncodings'), set: undefined, enumerable: true, configurable: true }); } catch (e) {}
    try { if (globalThis.PressureObserver) Object.defineProperty(PressureObserver, 'knownSources', { get: nat(function () { return FROZEN_SRC; }, 'get knownSources'), set: undefined, enumerable: true, configurable: true }); } catch (e) {}
    try { const t = globalThis.PerformanceObserver && PerformanceObserver.supportedEntryTypes; if (Array.isArray(t) && !Object.isFrozen(t)) Object.freeze(t); } catch (e) {}
    // styleMedia: StyleMedia interface with `type` and `matchMedium`.
    try {
      if (globalThis.styleMedia && typeof styleMedia === 'object' && Object.getPrototypeOf(styleMedia) === Object.prototype) {
        // Constructor hidden (Chrome has no global StyleMedia), own prototype.
        const SM = nat(function StyleMedia() { throw __pt_mkErr(TypeError, 'Illegal constructor'); }, 'StyleMedia');
        const P = SM.prototype;
        Object.defineProperty(P, 'type', { get: nat(function () { if (this !== styleMedia) throw __pt_mkErr(TypeError, 'Illegal invocation'); return 'screen'; }, 'get type'), enumerable: true, configurable: true });
        Object.defineProperty(P, 'matchMedium', { value: nat(({ matchMedium(q) { if (this !== styleMedia) throw __pt_mkErr(TypeError, 'Illegal invocation'); try { return !!matchMedia(String(q)).matches; } catch (e) { return false; } } }).matchMedium, 'matchMedium'), writable: true, enumerable: true, configurable: true });
        try { Object.defineProperty(P, Symbol.toStringTag, { value: 'StyleMedia', configurable: true }); } catch (e) {}
        try { delete P.constructor; } catch (e) {}
        for (const k of Object.getOwnPropertyNames(styleMedia)) { try { delete styleMedia[k]; } catch (e) {} }
        Object.setPrototypeOf(styleMedia, P);
      }
    } catch (e) {}
    // Option.prototype is HTMLOptionElement's prototype, like Image/Audio.
    try {
      if (globalThis.Option && globalThis.HTMLOptionElement && Option.prototype !== HTMLOptionElement.prototype) {
        const d = Object.getOwnPropertyDescriptor(globalThis, 'Option');
        const O = function Option(text, value, defaultSelected, selected) {
          if (!new.target) throw __pt_mkErr(TypeError, "Failed to construct 'Option': Please use the 'new' operator, this DOM object constructor cannot be called as a function.");
          const o = document.createElement('option');
          if (text !== undefined) o.text = String(text);
          if (value !== undefined) o.value = String(value);
          if (defaultSelected) o.setAttribute('selected', '');
          if (selected) o.selected = true;
          return o;
        };
        O.prototype = HTMLOptionElement.prototype;
        try { Object.defineProperty(O, 'length', { value: 0, configurable: true }); } catch (e) {}
        Object.defineProperty(globalThis, 'Option', { value: nat(O, 'Option'), writable: true, enumerable: d ? d.enumerable : false, configurable: true });
      }
    } catch (e) {}
    // Window chain: Window.prototype -> WindowProperties -> EventTarget.prototype.
    try {
      const WPp = Object.getPrototypeOf(Window.prototype);
      if (WPp && Object.prototype.toString.call(WPp) !== '[object WindowProperties]') {
        // An empty layer above EventTarget.prototype already exists: that is it.
        if (WPp !== EventTarget.prototype && Object.getOwnPropertyNames(WPp).length === 0 && Object.getPrototypeOf(WPp) === EventTarget.prototype) {
          Object.defineProperty(WPp, Symbol.toStringTag, { value: 'WindowProperties', configurable: true });
        } else {
          const WP = Object.create(WPp);
          Object.defineProperty(WP, Symbol.toStringTag, { value: 'WindowProperties', configurable: true });
          Object.setPrototypeOf(Window.prototype, WP);
        }
      }
    } catch (e) {}
    // webkit* aliases are the same functions.
    for (const [alias, orig] of [['webkitSpeechRecognition', 'SpeechRecognition'], ['webkitSpeechGrammar', 'SpeechGrammar'], ['webkitSpeechGrammarList', 'SpeechGrammarList'], ['webkitSpeechRecognitionError', 'SpeechRecognitionErrorEvent'], ['webkitSpeechRecognitionEvent', 'SpeechRecognitionEvent']]) {
      try { const d = Object.getOwnPropertyDescriptor(globalThis, alias); const o = globalThis[orig]; if (d && d.configurable && typeof o === 'function' && d.value !== o) Object.defineProperty(globalThis, alias, { value: o, writable: true, enumerable: false, configurable: true }); } catch (e) {}
    }
    // Extra own members: remove on Text/Comment lives on CharacterData.
    for (const n of ['Text', 'Comment']) { try { const P = globalThis[n] && globalThis[n].prototype; if (P && Object.prototype.hasOwnProperty.call(P, 'remove') && globalThis.CharacterData && 'remove' in CharacterData.prototype) delete P.remove; } catch (e) {} }
    // Async methods are plain functions returning a promise.
    for (const n of ['RTCPeerConnection']) { const P = globalThis[n] && globalThis[n].prototype; if (!P) continue; for (const k of Object.getOwnPropertyNames(P)) { try { const d = Object.getOwnPropertyDescriptor(P, k); if (d && typeof d.value === 'function' && Object.prototype.toString.call(d.value) === '[object AsyncFunction]') methodize(P, k); } catch (e) {} } }
    // Methods without `.prototype`, masked.
    for (const [o, keys] of [[globalThis.WebAssembly, ['compileStreaming', 'instantiateStreaming']], [globalThis.location, ['valueOf']], [globalThis, ['postMessage']], [globalThis.External && External.prototype, ['AddSearchProvider', 'IsSearchProviderInstalled']], [globalThis.Scheduler && Scheduler.prototype, ['postTask', 'yield']], [globalThis.Navigation && Navigation.prototype, ['entries']], [globalThis.chrome && chrome.app, ['getDetails', 'getIsInstalled', 'installState', 'runningState']], [globalThis.DOMImplementation && DOMImplementation.prototype, ['createDocument', 'createDocumentType', 'createHTMLDocument', 'hasFeature']]]) {
      if (!o) continue; for (const k of keys) methodize(o, k);
    }
    globalThis.__pt_methodize = methodize;
    // No duplicated inherited members: EventTarget methods and stream
    // close/abort live on ancestors, `resume` only on AudioContext.
    // Own listener implementations (WebSocket, Worker...) move off the
    // prototypes into a table and EventTarget.prototype forwards to them, so
    // prototypes have no own methods the browser lacks.
    try {
      const ETP = globalThis.EventTarget && EventTarget.prototype;
      const EVT = new WeakMap();
      if (ETP) {
        for (const n of ['Worker', 'WebSocket', 'MessagePort', 'FileReader', 'BroadcastChannel', 'BaseAudioContext', 'AbortSignal']) {
          const P = globalThis[n] && globalThis[n].prototype; if (!P) continue;
          const impl = {}; let any = false;
          for (const k of ['addEventListener', 'removeEventListener', 'dispatchEvent']) {
            const d = Object.getOwnPropertyDescriptor(P, k);
            if (d && typeof d.value === 'function' && d.configurable && d.value !== ETP[k]) { impl[k] = d.value; delete P[k]; any = true; }
          }
          if (any) EVT.set(P, impl);
        }
        const find = (t) => { let p = t; for (let i = 0; i < 12 && p; i++) { const e = EVT.get(p); if (e) return e; p = Object.getPrototypeOf(p); } return null; };
        for (const k of ['addEventListener', 'removeEventListener', 'dispatchEvent']) {
          const d = Object.getOwnPropertyDescriptor(ETP, k);
          if (!d || typeof d.value !== 'function') continue;
          const base = d.value;
          const w = ({ [k](...a) {
            const t = this;
            if (t !== null && (typeof t === 'object' || typeof t === 'function')) { const e = find(Object.getPrototypeOf(t)); if (e && e[k]) return e[k].apply(t, a); }
            return base.apply(this, a);
          } })[k];
          try { Object.defineProperty(w, 'length', { value: base.length, configurable: true }); } catch (e) {}
          Object.defineProperty(ETP, k, { value: nat(w, k), writable: d.writable, enumerable: d.enumerable, configurable: d.configurable });
        }
      }
    } catch (e) {}
    try { const P = globalThis.FileSystemWritableFileStream && FileSystemWritableFileStream.prototype; if (P && globalThis.WritableStream) for (const k of ['close', 'abort']) if (Object.prototype.hasOwnProperty.call(P, k) && k in WritableStream.prototype) delete P[k]; } catch (e) {}
    try { const B = globalThis.BaseAudioContext && BaseAudioContext.prototype, A = globalThis.AudioContext && AudioContext.prototype; if (B && A && Object.prototype.hasOwnProperty.call(B, 'resume') && Object.prototype.hasOwnProperty.call(A, 'resume')) delete B.resume; } catch (e) {}
    // toString of CSS units lives on CSSNumericValue.prototype, as in the browser.
    try { const SV = globalThis.CSSStyleValue && CSSStyleValue.prototype, U = globalThis.CSSUnitValue && CSSUnitValue.prototype; if (SV && U && Object.prototype.hasOwnProperty.call(U, 'toString')) { const d = Object.getOwnPropertyDescriptor(U, 'toString'); Object.defineProperty(SV, 'toString', d); delete U.toString; } } catch (e) {}
    // chrome.loadTimes/csi: anonymous functions with `.prototype`, but native-looking.
    try { if (globalThis.chrome && globalThis.__pt_native) for (const k of ['loadTimes', 'csi']) if (typeof chrome[k] === 'function') __pt_native(chrome[k]); } catch (e) {}
  } catch (e) {}
  // Navigation API: Chrome's `navigation.currentEntry` and
  // `navigation.activation` are objects with URL and entry keys; pages read
  // their fields.
  try {
    const N = globalThis.Navigation, nav = globalThis.navigation;
    const natn = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    if (N && N.prototype && nav && typeof nav === 'object') {
      const uuid = () => { const h = '0123456789abcdef'; let out = ''; for (let i = 0; i < 36; i++) { if (i === 8 || i === 13 || i === 18 || i === 23) out += '-'; else if (i === 14) out += '4'; else if (i === 19) out += h[8 + Math.floor(Math.random() * 4)]; else out += h[Math.floor(Math.random() * 16)]; } return out; };
      const mkEntry = () => {
        const EP = globalThis.NavigationHistoryEntry && NavigationHistoryEntry.prototype;
        const e = Object.create(EP || Object.prototype);
        const key = uuid(), id = uuid();
        const vals = { url: String(globalThis.location && location.href || ''), key, id, index: 0, sameDocument: true };
        if (EP) {
          for (const k of Object.keys(vals)) {
            try { Object.defineProperty(EP, k, { get: natn(function () { const st = ENTRY_STATE.get(this); if (!st) throw __pt_mkErr(TypeError, 'Illegal invocation'); return st[k]; }, 'get ' + k), enumerable: true, configurable: true }); } catch (x) {}
          }
          try { Object.defineProperty(EP, 'getState', { value: natn(function getState() { if (!ENTRY_STATE.has(this)) throw __pt_mkErr(TypeError, 'Illegal invocation'); return undefined; }, 'getState'), writable: true, enumerable: true, configurable: true }); } catch (x) {}
        }
        ENTRY_STATE.set(e, vals);
        return e;
      };
      const ENTRY_STATE = new WeakMap();
      let current = null;
      const cur = () => (current || (current = mkEntry()));
      let activation = null;
      const act = () => {
        if (activation) return activation;
        const AP = globalThis.NavigationActivation && NavigationActivation.prototype;
        activation = Object.create(AP || Object.prototype);
        const vals = { entry: cur(), from: null, navigationType: 'push' };
        if (AP) for (const k of Object.keys(vals)) {
          try { Object.defineProperty(AP, k, { get: natn(function () { if (this !== activation) throw __pt_mkErr(TypeError, 'Illegal invocation'); return vals[k]; }, 'get ' + k), enumerable: true, configurable: true }); } catch (x) {}
        }
        return activation;
      };
      const P = N.prototype;
      const acc = (k, get) => { try { Object.defineProperty(P, k, { get: natn(function () { if (this !== nav) throw __pt_mkErr(TypeError, 'Illegal invocation'); return get.call(this); }, 'get ' + k), enumerable: true, configurable: true }); } catch (e) {} };
      acc('currentEntry', function () { return cur(); });
      acc('activation', function () { return act(); });
      acc('transition', function () { return null; });
      acc('canGoBack', function () { return false; });
      acc('canGoForward', function () { return false; });
      try { Object.defineProperty(P, 'entries', { value: natn(({ entries() { if (this !== nav) throw __pt_mkErr(TypeError, 'Illegal invocation'); return [cur()]; } }).entries, 'entries'), writable: true, enumerable: true, configurable: true }); } catch (e) {}
    }
  } catch (e) {}
  try { for (const k of ['permission', 'maxActions', 'requestPermission']) redo(globalThis.Notification, k); } catch (e) {}
  // `tabIndex` reflects to the `tabindex` attribute, as in the browser (the
  // challenge marks its hidden frame with `el.tabIndex = -1`).
  try {
    const HP = globalThis.HTMLElement && HTMLElement.prototype;
    const natn = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    if (HP) {
      const FOCUSABLE = new Set(['a', 'area', 'button', 'input', 'select', 'textarea', 'iframe', 'summary', 'details', 'frame', 'audio', 'video']);
      Object.defineProperty(HP, 'tabIndex', {
        get: natn(function () {
          const v = this.getAttribute && this.getAttribute('tabindex');
          if (v != null && /^\s*[-+]?\d+/.test(v)) return parseInt(v, 10) | 0;
          const t = __s_toLowerCase(String(this.localName || ''));
          return FOCUSABLE.has(t) || (this.hasAttribute && this.hasAttribute('contenteditable')) ? 0 : -1;
        }, 'get tabIndex'),
        set: natn(function (v) { if (this.setAttribute) this.setAttribute('tabindex', String(Number(v) | 0)); }, 'set tabIndex'),
        enumerable: true, configurable: true,
      });
    }
  } catch (e) {}
  // `window.postMessage` to self: the message arrives as a task with its own
  // source and origin.
  try {
    const natp = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    const pm = function postMessage(message, targetOrigin) {
      if (arguments.length < 1) throw __pt_mkErr(TypeError, "Failed to execute 'postMessage' on 'Window': 1 argument required, but only 0 present.");
      let origin = '*';
      if (targetOrigin && typeof targetOrigin === 'object') { if (targetOrigin.targetOrigin !== undefined) origin = String(targetOrigin.targetOrigin); }
      else if (targetOrigin !== undefined) origin = String(targetOrigin);
      const mine = (globalThis.location && location.origin) || 'null';
      if (origin !== '*' && origin !== '/') {
        let ok = false;
        try { ok = new URL(origin).origin === mine; } catch (e) {
          throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'postMessage' on 'Window': Invalid target origin '" + origin + "' in a call to 'postMessage'.", 'SyntaxError');
        }
        if (!ok) return;
      }
      const data = typeof structuredClone === 'function' ? structuredClone(message) : message;
      setTimeout(() => {
        let ev;
        try { ev = new MessageEvent('message', { data, origin: mine, lastEventId: '', source: globalThis, ports: [] }); } catch (e) { return; }
        try { if (globalThis.__pt_trustEvent) __pt_trustEvent(ev); } catch (e) {}
        try { globalThis.dispatchEvent(ev); } catch (e) {}
      }, 0);
    };
    const d = Object.getOwnPropertyDescriptor(globalThis, 'postMessage');
    if (!d || d.configurable) Object.defineProperty(globalThis, 'postMessage', { value: natp(pm, 'postMessage'), writable: true, enumerable: true, configurable: true });
  } catch (e) {}
  // Scheduler: `postTask` resolves with the task's result, `yield` with
  // nothing. Installed over the name table's stubs.
  try {
    let SP = globalThis.scheduler && Object.getPrototypeOf(globalThis.scheduler);
    // For a bare object the prototype is Object.prototype: can't go there.
    if (SP === Object.prototype) SP = globalThis.scheduler;
    const nat = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    if (SP) {
      Object.defineProperty(SP, 'postTask', { value: nat(function postTask(cb, opts) {
        const delay = opts && Number(opts.delay) > 0 ? Number(opts.delay) : 0;
        const prio = String((opts && opts.priority) || (opts && opts.signal && opts.signal.priority) || 'user-visible');
        // user-blocking/user-visible run before timers, background like a plain one.
        return new Promise((res, rej) => {
          const run = () => { try { res(cb()); } catch (e) { rej(e); } };
          if (prio === 'background') setTimeout(run, delay + 18);
          else if (typeof globalThis.__pt_addTask === 'function') __pt_addTask(run, delay, true);
          else setTimeout(run, delay);
        });
      }, 'postTask'), writable: true, enumerable: true, configurable: true });
      Object.defineProperty(SP, 'yield', { value: nat(function () { return new Promise((r) => setTimeout(r, 0)); }, 'yield'), writable: true, enumerable: true, configurable: true });
    }
  } catch (e) {}
  // Constructor and namespace statics as in Chrome 151: order, descriptor
  // flags, function lengths and names, no `.prototype`.
  try { if (typeof globalThis.__pt_installRtcCaps === 'function') __pt_installRtcCaps(); } catch (e) {}
  // ONLY is a set of roots: after a V8 snapshot restore only what V8 added
  // itself is processed (see __pt_lateShape below).
  const ctorStatics = (ONLY) => { try {
    const TAB = __CTOR_STATICS__;
    const NS = new Set(['console', 'CSS', 'WebAssembly']);
    const nat2 = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    const shapeFn = (f, fname, len, ctor) => {
      if (typeof f !== 'function') f = ctor ? function () {} : ({ [fname](...a) {} })[fname];
      const bad = !ctor && (Object.prototype.hasOwnProperty.call(f, 'prototype') || Object.prototype.toString.call(f) !== '[object Function]');
      if (bad) { const orig = f; f = ({ [fname](...a) { return orig.apply(this, a); } })[fname]; }
      try { Object.defineProperty(f, 'length', { value: len, configurable: true }); } catch (e) {}
      try { Object.defineProperty(f, 'name', { value: fname, configurable: true }); } catch (e) {}
      return nat2(f, fname);
    };
    for (const name of Object.keys(TAB)) {
      if (ONLY && !ONLY.has(name)) continue;
      let I; try { I = globalThis[name]; } catch (e) { continue; }
      if (I === null || I === undefined) continue;
      if (typeof I !== 'function' && !(typeof I === 'object' && NS.has(name))) continue;
      const rows = TAB[name];
      const saved = new Map();
      try {
        for (const [k] of rows) { const d = Object.getOwnPropertyDescriptor(I, k); if (d) { saved.set(k, d); if (d.configurable) delete I[k]; } }
        for (const [k, spec] of rows) {
          const d = saved.get(k);
          if (d && !d.configurable) continue;
          const sm0 = /^([ecw-]*):(.*)$/.exec(spec); if (!sm0) continue;
          const flags = sm0[1], kind = sm0[2];
          const enumerable = __s_includes(flags, 'e'), configurable = __s_includes(flags, 'c'), writable = __s_includes(flags, 'w');
          if (kind[0] === 'f') {
            const m = /^f..(.)\/(.*)\/(\d+)$/.exec(kind);
            const fname = m ? m[2] : k, len = m ? +m[3] : 0, ctor = !!m && m[1] === 'P';
            Object.defineProperty(I, k, { value: shapeFn(d && d.value, fname, len, ctor), writable, enumerable, configurable });
          } else if (kind[0] === 'a') {
            const gm = /g...\/([^/]*)\/(\d+)/.exec(kind), sm = /s...\/([^/]*)\/(\d+)/.exec(kind);
            const desc = { enumerable, configurable };
            // A value that was a data property now comes from a getter (frozen lists, highlights...).
            if (gm) { const val = d && 'value' in d ? d.value : undefined; const g = d && d.get ? d.get : function () { return val; }; desc.get = shapeFn(g, gm[1], +gm[2]); }
            if (sm) { const st = d && d.set ? d.set : function (v) {}; desc.set = shapeFn(st, sm[1], +sm[2]); }
            Object.defineProperty(I, k, desc);
          } else {
            let v; if (d) { if ('value' in d) v = d.value; else if (d.get) { try { v = d.get.call(I); } catch (e) { v = undefined; } } }
            Object.defineProperty(I, k, { value: v, writable, enumerable, configurable });
          }
        }
      } catch (e) {
        for (const [k, d] of saved) { try { if (!Object.getOwnPropertyDescriptor(I, k)) Object.defineProperty(I, k, d); } catch (x) {} }
      }
    }
  } catch (e) {} };
  ctorStatics(null);
  // Prototype members per Chrome's table: name, length, strictness, no
  // `.prototype` on methods and accessors, native toString; an extra setter
  // is removed. Missing members are not added (see the Performance* note).
  const protoMembers = (ONLY) => { try {
    const PS = __PROTO_MEMBERS__;
    const nat = (f) => (globalThis.__pt_native ? __pt_native(f) : f);
    const isStrictF = (f) => { try { void f.caller; return false; } catch (e) { return true; } };
    const isNativeF = globalThis.__pt_isNative ? __pt_isNative : ((f) => { try { return /\[native code\]/.test(Function.prototype.toString.call(f)); } catch (e) { return false; } });
    const resolve = (path) => { let o = globalThis; for (const part of __s_split(path, '.')) { if (o === null || o === undefined) return null; o = part === '__proto__' ? Object.getPrototypeOf(o) : o[part]; } return o; };
    const fixFn = (f, key, sig, kindName) => {
      // sig = "Nsp/name/len": native, strict, no prototype.
      const m = /^(.)(.)(.)\/(.*)\/(\d+)$/.exec(sig); if (!m) return f;
      const wantStrict = m[2] === 's', wantNoProto = m[3] === 'p', name = m[4], len = +m[5];
      let g = f;
      if ((wantNoProto && Object.prototype.hasOwnProperty.call(g, 'prototype')) || (wantStrict && !isStrictF(g))) {
        const orig = g;
        const nk = __s_replace(String(name), /^[gs]et /, '');
        g = kindName === 'get' ? Object.getOwnPropertyDescriptor({ get [nk]() { return orig.call(this); } }, nk).get
          : kindName === 'set' ? Object.getOwnPropertyDescriptor({ set [nk](v) { return orig.call(this, v); } }, nk).set
          : ({ [key](...a) { return orig.apply(this, a); } })[key];
      }
      try { if (g.length !== len) Object.defineProperty(g, 'length', { value: len, configurable: true }); } catch (e) {}
      try { if (g.name !== name) Object.defineProperty(g, 'name', { value: name, configurable: true }); } catch (e) {}
      if (!isNativeF(g)) g = nat(g);
      return g;
    };
    for (const path of Object.keys(PS)) {
      if (ONLY && !ONLY.has(__s_split(path, '.')[0])) continue;
      let O; try { O = resolve(path); } catch (e) { continue; }
      if (O === null || (typeof O !== 'object' && typeof O !== 'function')) continue;
      for (const [key, spec] of PS[path]) {
        try {
          const d = Object.getOwnPropertyDescriptor(O, key);
          if (!d || !d.configurable) continue;
          const sm = /^([ecw-]*):(.*)$/.exec(spec); if (!sm) continue;
          const flags = sm[1], kind = sm[2];
          const enumerable = __s_includes(flags, 'e'), writable = __s_includes(flags, 'w');
          if (kind[0] === 'f') {
            if (typeof d.value !== 'function') continue;
            const f0 = d.value;
            // Fast path: length, name, nativeness and no prototype already match.
            if (d.enumerable === enumerable && d.writable === writable && kind[3] === 'p' && !Object.prototype.hasOwnProperty.call(f0, 'prototype') && isNativeF(f0)) {
              const m0 = /^f...\/(.*)\/(\d+)$/.exec(kind);
              if (m0 && f0.name === m0[1] && f0.length === +m0[2] && isStrictF(f0)) continue;
            }
            const f = fixFn(d.value, key, __s_slice(kind, 1), 'fn');
            if (f !== d.value || d.enumerable !== enumerable || d.writable !== writable) Object.defineProperty(O, key, { value: f, writable, enumerable, configurable: true });
          } else if (kind[0] === 'a') {
            if (!d.get && !d.set) continue;
            const gm = /g([^/]{3}\/[^/]*\/\d+)/.exec(kind), smm = /s([^/]{3}\/[^/]*\/\d+)/.exec(kind);
            const nd = { enumerable, configurable: true };
            let changed = d.enumerable !== enumerable;
            if (d.get) { if (gm) { nd.get = fixFn(d.get, key, gm[1], 'get'); changed = changed || nd.get !== d.get; } else { changed = true; } }
            if (d.set) { if (smm) { nd.set = fixFn(d.set, key, smm[1], 'set'); changed = changed || nd.set !== d.set; } else { changed = true; } }
            if (!nd.get && !nd.set) continue;
            if (changed) Object.defineProperty(O, key, nd);
          }
        } catch (e) {}
      }
    }
  } catch (e) {} };
  protoMembers(null);
  // What V8 adds on snapshot restore (WebAssembly, DisposableStack...) was not
  // seen by the loader at build time: rerun exactly the passes that concern
  // those names, in the same order.
  if (globalThis.__pt_lateNames) {
    const late = __pt_lateNames;
    Object.defineProperty(globalThis, '__pt_lateShape', { writable: true, configurable: true, value: () => {
      try { for (const k of ['Suspending', 'promising', 'SuspendError']) redo(globalThis.WebAssembly, k); } catch (e) {}
      try { if (globalThis.WebAssembly && globalThis.__pt_methodize) for (const k of ['compileStreaming', 'instantiateStreaming']) __pt_methodize(WebAssembly, k); } catch (e) {}
      ctorStatics(late);
      protoMembers(late);
    } });
  }
  // Symbol-keyed prototype members as in Chrome 151:
  // lists iterate with Array.prototype.values, maplike with its own entries,
  // setlike with its own values; the type tag comes first; five node
  // interfaces have Symbol.unscopables with a null prototype.
  try {
    const ARR = ['TouchList', 'TextTrackList', 'TextTrackCueList', 'StyleSheetList', 'SourceBufferList', 'SVGTransformList', 'SVGStringList', 'SVGPointList', 'SVGNumberList', 'SVGLengthList', 'RadioNodeList', 'Plugin', 'NamedNodeMap', 'MediaList', 'HTMLSelectElement', 'HTMLOptionsCollection', 'HTMLFormElement', 'HTMLFormControlsCollection', 'HTMLAllCollection', 'FileList', 'DataTransferItemList', 'DOMStringList', 'DOMRectList', 'CSSStyleDeclaration', 'CSSRuleList', 'CSSKeyframesRule', 'ImageTrackList', 'SpeechGrammarList', 'HTMLCollection', 'PluginArray', 'MimeTypeArray', 'NodeList', 'DOMTokenList', 'CSSNumericArray', 'CSSTransformValue', 'CSSUnparsedValue'];
    const MAPL = ['StylePropertyMapReadOnly', 'RTCStatsReport', 'HighlightRegistry', 'EventCounts', 'AudioParamMap', 'MIDIInputMap', 'MIDIOutputMap', 'MediaKeyStatusMap', 'XRHand', 'Headers', 'FormData', 'URLSearchParams'];
    const SETL = ['ViewTransitionTypeSet', 'Highlight', 'CustomStateSet', 'XRAnchorSet', 'XRPlaneSet', 'FontFaceSet'];
    const UNSC = { Element: ['after', 'append', 'before', 'prepend', 'remove', 'replaceChildren', 'replaceWith', 'slot'], DocumentType: ['after', 'before', 'remove', 'replaceWith'], DocumentFragment: ['append', 'prepend', 'replaceChildren'], Document: ['append', 'fullscreen', 'prepend', 'replaceChildren'], CharacterData: ['after', 'before', 'remove', 'replaceWith'] };
    const nat2 = (f) => (globalThis.__pt_native ? __pt_native(f) : f);
    const retag = (P, name) => {
      // The type tag is a non-enumerable data property, moved first among symbols.
      const d = Object.getOwnPropertyDescriptor(P, Symbol.toStringTag);
      if (d && !d.configurable) return;
      const it = Object.getOwnPropertyDescriptor(P, Symbol.iterator);
      if (d) delete P[Symbol.toStringTag];
      if (it && it.configurable) delete P[Symbol.iterator];
      Object.defineProperty(P, Symbol.toStringTag, { value: name, writable: false, enumerable: false, configurable: true });
      if (it && it.configurable) Object.defineProperty(P, Symbol.iterator, it);
    };
    const setIter = (P, fn) => {
      const d = Object.getOwnPropertyDescriptor(P, Symbol.iterator);
      if (d && !d.configurable) return;
      if (typeof fn !== 'function') return;
      Object.defineProperty(P, Symbol.iterator, { value: fn, writable: true, enumerable: false, configurable: true });
    };
    const protoOf = (n) => { try { const C = globalThis[n]; return typeof C === 'function' && C.prototype ? C.prototype : null; } catch (e) { return null; } };
    for (const n of ARR) { const P = protoOf(n); if (!P) continue; retag(P, n); setIter(P, Array.prototype.values); }
    for (const n of MAPL) {
      const P = protoOf(n); if (!P) continue; retag(P, n);
      if (typeof P.entries !== 'function') Object.defineProperty(P, 'entries', { value: nat2(({ entries() { return new Map().entries(); } }).entries), writable: true, enumerable: true, configurable: true });
      setIter(P, P.entries);
    }
    for (const n of SETL) {
      const P = protoOf(n); if (!P) continue; retag(P, n);
      if (typeof P.values !== 'function') Object.defineProperty(P, 'values', { value: nat2(({ values() { return new Set().values(); } }).values), writable: true, enumerable: true, configurable: true });
      setIter(P, P.values);
    }
    for (const n of Object.keys(UNSC)) {
      const P = protoOf(n); if (!P || Object.prototype.hasOwnProperty.call(P, Symbol.unscopables)) continue;
      const o = Object.create(null); for (const k of UNSC[n]) o[k] = true;
      Object.defineProperty(P, Symbol.unscopables, { value: o, writable: false, enumerable: false, configurable: true });
    }
  } catch (e) {}
  // Members Chrome keeps higher in the chain (Node, CharacterData) that we
  // duplicated on Text/Comment/Element; Worker without onmessageerror.
  try {
    const hasOwnP = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
    const CD = globalThis.CharacterData && CharacterData.prototype, NP = globalThis.Node && Node.prototype;
    for (const C of [globalThis.Text, globalThis.Comment]) {
      if (!C || !C.prototype) continue;
      for (const k of ['data', 'length', 'nodeName', 'nodeValue', 'textContent']) {
        if ((CD && hasOwnP(CD, k)) || (NP && hasOwnP(NP, k))) delete C.prototype[k];
      }
    }
    if (globalThis.Element && NP) for (const k of ['nodeName', 'parentElement']) if (hasOwnP(NP, k)) delete Element.prototype[k];
    if (globalThis.Worker && Worker.prototype) delete Worker.prototype.onmessageerror;
    // HTMLOptionsCollection: length and selectedIndex are accessors with setters, via <select>.
    if (globalThis.HTMLOptionsCollection && typeof __pt_selSetLength === 'function') {
      const OC = HTMLOptionsCollection.prototype;
      const nat2 = (f) => (globalThis.__pt_native ? __pt_native(f) : f);
      const own = (c) => (c && c.__ptSelect) || null;
      Object.defineProperty(OC, 'length', { get: nat2(({ get length() { return this.__ptLen | 0; } }).__lookupGetter__('length')),
        set: nat2(({ set length(v) { const s = own(this); if (s) __pt_selSetLength(s, v); } }).__lookupSetter__('length')), enumerable: true, configurable: true });
      Object.defineProperty(OC, 'selectedIndex', { get: nat2(({ get selectedIndex() { const s = own(this); return s ? s.selectedIndex : -1; } }).__lookupGetter__('selectedIndex')),
        set: nat2(({ set selectedIndex(v) { const s = own(this); if (s) __pt_selSetIndex(s, v); } }).__lookupSetter__('selectedIndex')), enumerable: true, configurable: true });
    }
    // SVGElement.className is a read-only SVGAnimatedString.
    if (globalThis.SVGElement) { const d = Object.getOwnPropertyDescriptor(SVGElement.prototype, 'className'); if (d && d.set) Object.defineProperty(SVGElement.prototype, 'className', { get: d.get, set: undefined, enumerable: true, configurable: true }); }
    // styleMedia: the type tag lives on the prototype, not the object.
    try { const smd = Object.getOwnPropertyDescriptor(styleMedia, Symbol.toStringTag); if (smd && smd.configurable) { delete styleMedia[Symbol.toStringTag]; const SP = Object.getPrototypeOf(styleMedia); if (SP && !Object.prototype.hasOwnProperty.call(SP, Symbol.toStringTag)) Object.defineProperty(SP, Symbol.toStringTag, { value: 'StyleMedia', configurable: true }); } } catch (e) {}
    // location[Symbol.toPrimitive] is a non-configurable undefined, as in the browser.
    try { if (!Object.getOwnPropertyDescriptor(location, Symbol.toPrimitive)) Object.defineProperty(location, Symbol.toPrimitive, { value: undefined, writable: false, enumerable: false, configurable: false }); } catch (e) {}
    if (globalThis.MediaDevices) {
      const MP = MediaDevices.prototype, d = Object.getOwnPropertyDescriptor(MP, 'ondevicechange');
      if (d && d.get && !d.set) {
        const H = new WeakMap(), og = d.get;
        const nat2 = (f) => (globalThis.__pt_native ? __pt_native(f) : f);
        Object.defineProperty(MP, 'ondevicechange', { get: nat2(({ get ondevicechange() { return H.has(this) ? H.get(this) : og.call(this); } }).__lookupGetter__('ondevicechange')),
          set: nat2(({ set ondevicechange(v) { H.set(this, typeof v === 'function' || (v && typeof v === 'object') ? v : null); } }).__lookupSetter__('ondevicechange')), enumerable: true, configurable: true });
      }
    }
  } catch (e) {}
  try {
    for (const n of ['Option', 'CSSUnitValue']) {
      const C = globalThis[n]; if (typeof C !== 'function') continue;
      const d = Object.getOwnPropertyDescriptor(C, 'prototype');
      if (d && d.writable) Object.defineProperty(C, 'prototype', { value: d.value, writable: false, enumerable: false, configurable: false });
    }
    const L = globalThis.location;
    if (L) {
      const vd = Object.getOwnPropertyDescriptor(L, 'valueOf');
      if (vd && typeof vd.value === 'function' && Object.prototype.hasOwnProperty.call(vd.value, 'prototype')) {
        const orig = vd.value; const f = ({ valueOf() { return orig.call(this); } }).valueOf;
        Object.defineProperty(L, 'valueOf', { value: __pt_native ? __pt_native(f) : f, writable: false, enumerable: false, configurable: false });
      }
      const ad = Object.getOwnPropertyDescriptor(L, 'ancestorOrigins');
      if (ad && ad.get && ad.get.name !== 'get ancestorOrigins') {
        const og = ad.get; const g = ({ get ancestorOrigins() { return og.call(this); } });
        const gd = Object.getOwnPropertyDescriptor(g, 'ancestorOrigins').get;
        Object.defineProperty(L, 'ancestorOrigins', { get: __pt_native ? __pt_native(gd) : gd, enumerable: true, configurable: false });
      }
    }
  } catch (e) {}
  // Chrome 151 built-in AI (LanguageModel, Summarizer, Translator,
  // LanguageDetector): availability() resolves to a string. In a top-level
  // window models are "downloadable" (language detector "available"), and
  // create() without a user gesture rejects with NotAllowedError; in a
  // cross-site frame without policy permission: "unavailable" and "Access
  // denied...". Report section CMJGg7 reads this. Checked against Chrome 151
  // (page and frame).
  try {
    const nat = (f) => (globalThis.__pt_native ? __pt_native(f) : f);
    // The cross-site frame flag is set after the loader: read at call time.
    const isCross = () => !!globalThis.__pt_crossSite;
    const dom = (msg, name) => (typeof DOMException === 'function' ? __pt_mkErr(DOMException, msg, name) : new Error(msg));
    const GESTURE = 'Requires a user gesture when availability is "downloading" or "downloadable".';
    const POLICY = 'Access denied because the Permission Policy is not enabled.';
    const spec = { LanguageModel: 'downloadable', Summarizer: 'downloadable', Translator: 'downloadable', LanguageDetector: 'available' };
    for (const n of Object.keys(spec)) {
      const C = globalThis[n]; if (typeof C !== 'function') continue;
      const needsArg = n === 'Translator';
      const stateNow = () => (isCross() ? 'unavailable' : spec[n]);
      const few = (m) => __pt_mkErr(TypeError, "Failed to execute '" + m + "' on '" + n + "': 1 argument required, but only 0 present.");
      const lenA = typeof C.availability === 'function' ? C.availability.length : (needsArg ? 1 : 0);
      const lenC = typeof C.create === 'function' ? C.create.length : (needsArg ? 1 : 0);
      const av = ({ availability(o) { if (needsArg && arguments.length < 1) return Promise.reject(few('availability')); return Promise.resolve(stateNow()); } }).availability;
      const cr = ({ create(o) {
        if (needsArg && arguments.length < 1) return Promise.reject(few('create'));
        if (isCross()) return Promise.reject(dom(POLICY, 'NotAllowedError'));
        if (stateNow() === 'available') return Promise.resolve(Object.create(C.prototype));
        return Promise.reject(dom(GESTURE, 'NotAllowedError'));
      } }).create;
      for (const [k, f, len] of [['availability', av, lenA], ['create', cr, lenC]]) {
        try { Object.defineProperty(f, 'length', { value: len, configurable: true }); } catch (e) {}
        const d = Object.getOwnPropertyDescriptor(C, k);
        Object.defineProperty(C, k, { value: nat(f), writable: d ? d.writable : true, enumerable: d ? d.enumerable : true, configurable: true });
      }
    }
  } catch (e) {}
  // Late methods without `.prototype`: postMessage, scheduler, navigation.
  try { const mz = globalThis.__pt_methodize; if (typeof mz === 'function') { for (const [o, keys] of [[globalThis, ['postMessage']], [globalThis.Scheduler && Scheduler.prototype, ['postTask', 'yield']], [globalThis.Navigation && Navigation.prototype, ['entries']]]) { if (!o) continue; for (const k of keys) mz(o, k); } } delete globalThis.__pt_methodize; } catch (e) {}
  // An interface object inherits its parent's (WebIDL): in Chrome
  // Object.getPrototypeOf(HTMLDivElement) === HTMLElement, Worker -> EventTarget.
  // The parent is the nearest prototype in the chain with its own
  // `constructor` exposed on window under its name. Except language builtins
  // (they have their own) and the Image/Audio/Option factories and
  // DOMException, which Chrome derives straight from Function.
  try {
    const SKIP = new Set(['Image', 'Audio', 'Option', 'DOMException', 'Object', 'Function', 'Array', 'Error',
      'AggregateError', 'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError', 'SuppressedError',
      'Int8Array', 'Uint8Array', 'Uint8ClampedArray', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array',
      'Float16Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'Promise', 'Map', 'Set',
      'WeakMap', 'WeakSet', 'WeakRef', 'FinalizationRegistry', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView',
      'Boolean', 'Number', 'String', 'Symbol', 'BigInt', 'Date', 'RegExp', 'Proxy', 'Iterator',
      'DisposableStack', 'AsyncDisposableStack']);
    const GOPN = globalThis.__pt_rawGOPN || Object.getOwnPropertyNames;
    const names = GOPN(globalThis);
    const has = new Set(names);
    for (const k of names) {
      if (SKIP.has(k) || __s_charCodeAt(k, 0) < 65 || __s_charCodeAt(k, 0) > 90) continue;
      let C; try { C = globalThis[k]; } catch (e) { continue; }
      if (typeof C !== 'function' || !C.prototype || typeof C.prototype !== 'object') continue;
      if (Object.getPrototypeOf(C) !== Function.prototype) continue;
      let parent = null;
      for (let P = Object.getPrototypeOf(C.prototype), i = 0; P && P !== Object.prototype && i < 20; P = Object.getPrototypeOf(P), i++) {
        const d = Object.getOwnPropertyDescriptor(P, 'constructor');
        const f = d && d.value;
        if (typeof f === 'function' && f !== C && has.has(f.name) && globalThis[f.name] === f) { parent = f; break; }
      }
      if (parent) { try { Object.setPrototypeOf(C, parent); } catch (e) {} }
    }
  } catch (e) {}
  // InputDeviceCapabilities: firesTouchEvents comes from the constructor dict
  // (default false); for mouse input Chrome gives an object with false.
  try {
    const C = globalThis.InputDeviceCapabilities;
    if (typeof C === 'function' && C.prototype) {
      const V = new WeakMap();
      const d = Object.getOwnPropertyDescriptor(C.prototype, 'firesTouchEvents');
      const g = ({ get firesTouchEvents() { return V.has(this) ? V.get(this) : false; } });
      const get = Object.getOwnPropertyDescriptor(g, 'firesTouchEvents').get;
      if (globalThis.__pt_native) __pt_native(get);
      Object.defineProperty(C.prototype, 'firesTouchEvents', { get, set: undefined, enumerable: d ? d.enumerable : true, configurable: true });
      Object.defineProperty(globalThis, '__pt_idcSet', { value: (o, v) => V.set(o, !!v), writable: true, configurable: true });
    }
  } catch (e) {}
})();"#;

pub fn window_order_script() -> String {
    WINDOW_ORDER_TEMPLATE.replace("__WINDOW_ORDER__", &json_table(WINDOW_ORDER))
}

const WINDOW_ORDER_TEMPLATE: &str = r#"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_charCodeAt = __sm(String.prototype.charCodeAt, 'charCodeAt');
  // Engine-internal names (`__pt...`, `__...`) must not enumerate on interface
  // prototypes or on window: Chrome's `for...in` over a node does not show them.
  // Found with for...in itself, which the introspection filter leaves alone.
  try {
    const GOPN = globalThis.__pt_rawGOPN || Object.getOwnPropertyNames, GOPD = globalThis.__pt_rawGOPD || Object.getOwnPropertyDescriptor;
    const hideOn = (o) => {
      if (!o || (typeof o !== 'object' && typeof o !== 'function')) return;
      let ks = [];
      try { ks = GOPN(o).filter((k) => __s_charCodeAt(k, 0) === 95 && __s_charCodeAt(k, 1) === 95); } catch (e) { return; }
      for (const k of ks) {
        try { const d = GOPD(o, k); if (d && d.enumerable && d.configurable) { d.enumerable = false; Object.defineProperty(o, k, d); } } catch (e) {}
      }
    };
    hideOn(globalThis);
    const seen = new Set();
    for (const n of Object.getOwnPropertyNames(globalThis)) {
      let C; try { C = globalThis[n]; } catch (e) { continue; }
      if (typeof C !== 'function') continue;
      for (let P = C.prototype, i = 0; P && i < 12 && !seen.has(P); P = Object.getPrototypeOf(P), i++) { seen.add(P); hideOn(P); }
    }
    try { if (globalThis.document) for (let P = document, i = 0; P && i < 12; P = Object.getPrototypeOf(P), i++) hideOn(P); } catch (e) {}
  } catch (e) {}
  const ORDER = __WINDOW_ORDER__;
  for (const name of ORDER) {
    let d;
    try { d = Object.getOwnPropertyDescriptor(globalThis, name); } catch (e) { continue; }
    if (!d || !d.configurable) continue;
    try {
      delete globalThis[name];
      Object.defineProperty(globalThis, name, d);
    } catch (e) {}
  }
})();"#;

pub fn late_originals_script() -> String {
    r#"(() => {
  try {
    const keep = {};
    const C = globalThis.HTMLCanvasElement && HTMLCanvasElement.prototype;
    if (C) { keep.getContext = C.getContext; keep.toDataURL = C.toDataURL; }
    const D = globalThis.Document && Document.prototype;
    if (D) {
      keep.createElement = D.createElement;
      keep.createTextNode = D.createTextNode;
      keep.createComment = D.createComment;
      keep.createDocumentFragment = D.createDocumentFragment;
      keep.createElementNS = D.createElementNS;
    }
    const N = globalThis.Node && Node.prototype;
    if (N) { keep.appendChild = N.appendChild; keep.insertBefore = N.insertBefore; }
    const E = globalThis.Element && Element.prototype;
    if (E) keep.setAttribute = E.setAttribute;
    // 2D context: our `createImageBitmap` draws through it, and anyone wrapping
    // drawing would see these two calls.
    const X = globalThis.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype;
    if (X) { keep.drawImage = X.drawImage; keep.putImageData = X.putImageData; }
    // All GL methods: our WebGPU sits on WebGL and calls dozens of them, and
    // the page can wrap any. Captured once, here.
    for (const N of ['WebGLRenderingContext', 'WebGL2RenderingContext']) {
      const C = globalThis[N];
      if (!C || !C.prototype) continue;
      const table = Object.create(null);
      for (const k of Object.getOwnPropertyNames(C.prototype)) {
        const d = Object.getOwnPropertyDescriptor(C.prototype, k);
        if (d && typeof d.value === 'function') table[k] = d.value;
      }
      keep[N] = table;
    }
    Object.defineProperty(globalThis, '__pt_orig',
      { value: keep, enumerable: false, configurable: true, writable: true });
    // Old name, for layers captured before the rename.
    Object.defineProperty(globalThis, '__pt_canvasOrig',
      { value: keep, enumerable: false, configurable: true, writable: true });
  } catch (e) {}
})();"#
        .to_string()
}

pub fn worker_scope_script(name: &str, url: &str) -> String {
    format!(
        r##"{helper}
(() => {{
  const NAME = {name};
  const URL_ = {url};
  // Shape captured from a real Chrome 148 worker, level by level: the scope
  // has 334 own names (12 enumerable), WorkerGlobalScope 30,
  // DedicatedWorkerGlobalScope TEMPORARY and PERSISTENT. A window context
  // exposes over a thousand names at the first level, and enumerating `self`
  // is the first thing a fingerprinter does inside a worker.
  // Interface object shape: a strict function has exactly `length, name,
  // prototype` (no `arguments`/`caller`) and, unlike a class, throws
  // "Illegal constructor" when called without `new` too.
  const __ptIllegal = (function () {{
    'use strict';
    return function () {{ return function () {{ throw __pt_mkErr(TypeError, 'Illegal constructor'); }}; }};
  }})();
  const __ptName = (f, n) => {{
    try {{ Object.defineProperty(f, 'name', {{ value: n, configurable: true }}); }} catch (e) {{}}
    return f;
  }};
  const OWN = new Set(__WORKER_OWN__);
  const OWN_ENUM = new Set(__WORKER_ENUM__);
  const SCOPE = __WORKER_SCOPE__;
  const SCOPE_ENUM = new Set(__WORKER_SCOPE_ENUM__);
  const NAV_KEYS = __WORKER_NAV__;

  // 1. WorkerGlobalScope level: what the browser keeps on the prototype moves
  //    there along with its implementation.
  const EventTargetProto = (globalThis.EventTarget && EventTarget.prototype) || Object.prototype;
  // The global is born from a V8 template and its prototype cannot change
  // (as in Chrome): the window links (Window.prototype, WindowProperties)
  // become worker links, cleared of window members.
  const __T = globalThis.__pt_protos;
  const __reuse = !!(__T && __T.w && Object.getPrototypeOf(globalThis) === __T.w && Object.getPrototypeOf(__T.wp) === EventTargetProto);
  const __clear = (o) => {{ for (const k of Reflect.ownKeys(o)) {{ try {{ delete o[k]; }} catch (e) {{}} }} return o; }};
  const wgsProto = __reuse ? __clear(__T.wp) : Object.create(EventTargetProto);
  for (const k of SCOPE) {{
    let d;
    try {{ d = Object.getOwnPropertyDescriptor(globalThis, k); }} catch (e) {{ continue; }}
    if (d) {{
      try {{ Object.defineProperty(wgsProto, k, Object.assign({{}}, d, {{ enumerable: SCOPE_ENUM.has(k) }})); }} catch (e) {{}}
      try {{ delete globalThis[k]; }} catch (e) {{}}
    }}
  }}

  // 2. Remove everything workers lack, DOM interfaces included.
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

  // 3. WorkerNavigator: same device, trimmed interface.
  // The window navigator already moved to the prototype in step 1: read values from there.
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
  const WorkerNavigator = __ptIllegal('WorkerNavigator');
  WorkerNavigator.prototype = navProto;
  Object.defineProperty(navProto, 'constructor', {{ value: WorkerNavigator, writable: true, configurable: true }});
  globalThis.WorkerNavigator = WorkerNavigator;
  const workerNavigator = Object.create(navProto);
  Object.defineProperty(wgsProto, 'navigator', {{ get: () => workerNavigator, enumerable: true, configurable: true }});

  // 4. WorkerLocation is the script's own URL. A blob worker has an opaque
  //    scheme: `href` is the whole `blob:<inner URL>`, `pathname` is the
  //    rest, no host or port, and `origin` is the creating page's. Parsing it
  //    as plain `http:` would yield `blob://http://...`.
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
  const WorkerLocation = __ptIllegal('WorkerLocation');
  WorkerLocation.prototype = locProto;
  Object.defineProperty(locProto, 'constructor', {{ value: WorkerLocation, writable: true, configurable: true }});
  globalThis.WorkerLocation = WorkerLocation;
  const workerLocation = Object.create(locProto);
  Object.defineProperty(wgsProto, 'location', {{ get: () => workerLocation, enumerable: true, configurable: true }});

  // 5. The chain: globalThis -> DedicatedWorkerGlobalScope -> WorkerGlobalScope
  //    -> EventTarget -> Object, as in the browser.
  const WorkerGlobalScope = __ptIllegal('WorkerGlobalScope');
  WorkerGlobalScope.prototype = wgsProto;
  Object.defineProperty(wgsProto, 'constructor', {{ value: WorkerGlobalScope, writable: true, configurable: true }});
  try {{ Object.defineProperty(wgsProto, Symbol.toStringTag, {{ value: 'WorkerGlobalScope', configurable: true }}); }} catch (e) {{}}
  Object.defineProperty(wgsProto, 'self', {{ get: () => globalThis, enumerable: true, configurable: true }});

  const dwgsProto = __reuse ? __clear(__T.w) : Object.create(wgsProto);
  const DedicatedWorkerGlobalScope = __ptIllegal('DedicatedWorkerGlobalScope');
  DedicatedWorkerGlobalScope.prototype = dwgsProto;
  Object.defineProperty(dwgsProto, 'constructor', {{ value: DedicatedWorkerGlobalScope, writable: true, configurable: true }});
  // Interface constants as in Chrome: read-only, non-configurable.
  try {{ Object.defineProperty(dwgsProto, 'TEMPORARY', {{ value: 0, writable: false, enumerable: true, configurable: false }}); }} catch (e) {{}}
  try {{ Object.defineProperty(dwgsProto, 'PERSISTENT', {{ value: 1, writable: false, enumerable: true, configurable: false }}); }} catch (e) {{}}
  try {{ Object.defineProperty(dwgsProto, Symbol.toStringTag, {{ value: 'DedicatedWorkerGlobalScope', configurable: true }}); }} catch (e) {{}}
  globalThis.WorkerGlobalScope = WorkerGlobalScope;
  globalThis.DedicatedWorkerGlobalScope = DedicatedWorkerGlobalScope;
  // Interface objects inherit their parents, as on window (WebIDL).
  try {{ if (typeof EventTarget === 'function') Object.setPrototypeOf(WorkerGlobalScope, EventTarget); }} catch (e) {{}}
  try {{ Object.setPrototypeOf(DedicatedWorkerGlobalScope, WorkerGlobalScope); }} catch (e) {{}}
  try {{ Object.setPrototypeOf(globalThis, dwgsProto); }} catch (e) {{}}
  // The window's own tag: here the name belongs to the scope prototype.
  try {{ delete globalThis[Symbol.toStringTag]; }} catch (e) {{}}

  // 6. Missing entirely: stubs of the same kind as in the browser (worker
  //    sync APIs and RTC transforms).
  for (const [k, kind] of [['FileReaderSync', 'N'], ['FileSystemSyncAccessHandle', 'N'],
    ['RTCRtpScriptTransformer', 'N'], ['RTCTransformEvent', 'N'],
    ['webkitRequestFileSystemSync', 'N'], ['webkitResolveLocalFileSystemSyncURL', 'N'],
    ['onrtctransform', 'x']]) {{
    if (k in globalThis) continue;
    const value = kind === 'N' ? (() => {{
      const f = __ptIllegal(k);
      return globalThis.__pt_native ? __pt_native(f) : f;
    }})() : null;
    try {{
      Object.defineProperty(globalThis, k, {{
        value, writable: true, configurable: true, enumerable: OWN_ENUM.has(k),
      }});
    }} catch (e) {{}}
  }}
  // RTCTransformEvent is an event: both object and prototype inherit Event.
  try {{
    const E = globalThis.RTCTransformEvent;
    if (typeof E === 'function' && typeof Event === 'function' && E.prototype) {{
      Object.setPrototypeOf(E, Event);
      Object.setPrototypeOf(E.prototype, Event.prototype);
      Object.defineProperty(E.prototype, Symbol.toStringTag, {{ value: 'RTCTransformEvent', configurable: true }});
    }}
  }} catch (e) {{}}
  for (const k of ['importScripts']) {{
    if (k in wgsProto) continue;
    const f = function importScripts() {{}};
    try {{ Object.defineProperty(wgsProto, k, {{ value: globalThis.__pt_native ? __pt_native(f) : f, writable: true, configurable: true, enumerable: true }}); }} catch (e) {{}}
  }}
  if (!('fonts' in wgsProto)) {{
    const fonts = {{ ready: Promise.resolve(), check: () => true, load: () => Promise.resolve([]), size: 0 }};
    try {{ Object.defineProperty(wgsProto, 'fonts', {{ get: () => fonts, enumerable: true, configurable: true }}); }} catch (e) {{}}
  }}
  // Worker scope interfaces are never enumerable.
  for (const k of ['WorkerGlobalScope', 'DedicatedWorkerGlobalScope', 'WorkerNavigator', 'WorkerLocation']) {{
    try {{
      const d = Object.getOwnPropertyDescriptor(globalThis, k);
      if (d) Object.defineProperty(globalThis, k, Object.assign({{}}, d, {{ enumerable: false }}));
    }} catch (e) {{}}
  }}

  // 7. The outbound port. Both sides are native scope methods with the same
  //    `toString` as the rest; a `postMessage` showing its source betrays us.
  globalThis.name = NAME;
  const native = (f) => (globalThis.__pt_native ? __pt_native(f) : f);
  const outbox = [];
  globalThis.__pt_drainWorkerOut = () => outbox.splice(0);
  globalThis.postMessage = native(function postMessage(data) {{
    // Cloned, not serialized: the other side expects the same types.
    try {{ outbox.push(__pt_cloneEncode(data)); }} catch (e) {{ outbox.push('null'); }}
  }});
  globalThis.close = native(function close() {{ globalThis.__ptClosed = true; }});
  globalThis.__pt_workerDeliver = (json) => {{
    let data = null;
    try {{ data = __pt_cloneDecode(json); }} catch (e) {{}}
    // A dedicated worker's message has empty `origin` and null `source`: it
    // came through a port, not from a window.
    let ev;
    try {{ ev = new MessageEvent('message', {{ data, origin: '', lastEventId: '', source: null, ports: [] }}); }} catch (e) {{
      ev = {{ type: 'message', data, origin: '', lastEventId: '', source: null, ports: [] }};
    }}
    try {{ __pt_write(ev, 'target', globalThis); __pt_write(ev, 'currentTarget', globalThis); }} catch (e) {{}}
    // Delivered by the engine, i.e. the browser: the event is trusted.
    // Cloudflare's collector runs the posted job only if
    // `e.isTrusted && '' === e.origin && null === e.source`.
    try {{ if (globalThis.__pt_trustEvent) __pt_trustEvent(ev); else ev.isTrusted = true; }} catch (e) {{}}
    // One delivery: `dispatchEvent` calls both listeners and `onmessage`;
    // calling both would run the handler twice.
    if (typeof globalThis.dispatchEvent === 'function') {{
      try {{ globalThis.dispatchEvent(ev); return; }} catch (e) {{}}
    }}
    try {{ if (typeof globalThis.onmessage === 'function') globalThis.onmessage(ev); }} catch (e) {{}}
  }};

  // Worker OPFS differs from the window's: only here is there a sync handle
  // (`FileSystemSyncAccessHandle`), which the challenge probe uses. Same
  // block as the page's but built anew, since the window lacks the sync name.
__OPFS__
  try {{
    const st = globalThis.navigator && globalThis.navigator.storage;
    if (st && typeof __ptOPFS === 'function') {{
      const proto = Object.getPrototypeOf(st) || st;
      const g = function getDirectory() {{ return __ptOPFS(); }};
      Object.defineProperty(proto, 'getDirectory', {{
        value: globalThis.__pt_native ? __pt_native(g) : g,
        writable: true, enumerable: true, configurable: true,
      }});
    }}
  }} catch (e) {{}}
  // Worker font set is a real interface: `self.fonts` is a `FontFaceSet` and
  // the name lives on the scope. Members and descriptors from Chrome 151.
  try {{
    const fonts = globalThis.fonts;
    if (fonts && typeof globalThis.FontFaceSet !== 'function') {{
      const FontFaceSet = __ptIllegal('FontFaceSet');
      const P = Object.create(EventTargetProto);
      const nat = (f, n) => (globalThis.__pt_native ? __pt_native(__ptName(f, n)) : __ptName(f, n));
      for (const [k, v] of [['onloading', null], ['onloadingdone', null], ['onloadingerror', null]]) {{
        let store = v;
        Object.defineProperty(P, k, {{
          get: nat(function () {{ return store; }}, 'get ' + k),
          set: nat(function (x) {{ store = x; }}, 'set ' + k),
          enumerable: true, configurable: true,
        }});
      }}
      Object.defineProperty(P, 'ready', {{
        get: nat(function () {{ return Promise.resolve(this); }}, 'get ready'),
        enumerable: true, configurable: true,
      }});
      Object.defineProperty(P, 'status', {{
        get: nat(function () {{ return 'loaded'; }}, 'get status'),
        enumerable: true, configurable: true,
      }});
      Object.defineProperty(P, 'size', {{
        get: nat(function () {{ return 0; }}, 'get size'),
        enumerable: true, configurable: true,
      }});
      const members = {{
        check: function check() {{ return true; }},
        load: function load() {{ return Promise.resolve([]); }},
        add: function add() {{ return this; }},
        clear: function clear() {{}},
        delete: function () {{ return false; }},
        entries: function entries() {{ return [][Symbol.iterator](); }},
        forEach: function forEach() {{}},
        has: function has() {{ return false; }},
        keys: function keys() {{ return [][Symbol.iterator](); }},
        values: function values() {{ return [][Symbol.iterator](); }},
      }};
      for (const k of Object.keys(members)) {{
        Object.defineProperty(P, k, {{
          value: nat(members[k], k), writable: true, enumerable: true, configurable: true,
        }});
      }}
      Object.defineProperty(P, 'constructor', {{
        value: FontFaceSet, writable: true, configurable: true,
      }});
      try {{ Object.defineProperty(P, Symbol.toStringTag, {{ value: 'FontFaceSet', configurable: true }}); }} catch (e) {{}}
      Object.defineProperty(FontFaceSet, 'prototype', {{ value: P, writable: false, configurable: false }});
      try {{ Object.setPrototypeOf(fonts, P); }} catch (e) {{}}
      Object.defineProperty(globalThis, 'FontFaceSet', {{
        value: globalThis.__pt_native ? __pt_native(FontFaceSet) : FontFaceSet,
        writable: true, enumerable: false, configurable: true,
      }});
    }}
  }} catch (e) {{}}

  // Workers have no `event`: it is window legacy, delivered by a late layer
  // after the own-name cleanup.
  try {{ delete globalThis.event; }} catch (e) {{}}

}})();"##,
        helper = PT_WRITE_HELPER,
        name = quoted(name),
        url = quoted(url),
    )
    .replace("__WORKER_OWN__", &json_table(WORKER_OWN))
    .replace("__WORKER_ENUM__", WORKER_ENUMERABLE)
    .replace("__WORKER_SCOPE_ENUM__", WORKER_SCOPE_ENUMERABLE)
    .replace("__WORKER_SCOPE__", WORKER_SCOPE)
    .replace("__WORKER_NAV__", WORKER_NAVIGATOR)
    .replace("__OPFS__", OPFS_TEMPLATE)
}

/// Names enumerable on `window` in Chrome 148: all 237, captured from a live
/// browser (`Object.keys(window)`). Everything else on window is
/// non-enumerable (interfaces are `{enumerable: false}`). Fingerprinters
/// walk the graph by enumerable keys up the prototype chain, so the difference
/// shows immediately.
const WINDOW_ENUMERABLE: &str = r#"["alert", "atob", "blur", "btoa", "caches", "cancelAnimationFrame", "cancelIdleCallback", "captureEvents", "chrome", "clearInterval", "clearTimeout", "clientInformation", "close", "closed", "confirm", "cookieStore", "crashReport", "createImageBitmap", "credentialless", "crossOriginIsolated", "crypto", "customElements", "devicePixelRatio", "document", "documentPictureInPicture", "event", "external", "fence", "fetch", "fetchLater", "find", "focus", "frameElement", "frames", "getComputedStyle", "getScreenDetails", "getSelection", "history", "indexedDB", "innerHeight", "innerWidth", "isSecureContext", "launchQueue", "length", "localStorage", "location", "locationbar", "matchMedia", "menubar", "moveBy", "moveTo", "name", "navigation", "navigator", "onabort", "onafterprint", "onanimationcancel", "onanimationend", "onanimationiteration", "onanimationstart", "onappinstalled", "onauxclick", "onbeforeinput", "onbeforeinstallprompt", "onbeforematch", "onbeforeprint", "onbeforetoggle", "onbeforeunload", "onbeforexrselect", "onblur", "oncancel", "oncanplay", "oncanplaythrough", "onchange", "onclick", "onclose", "oncommand", "oncontentvisibilityautostatechange", "oncontextlost", "oncontextmenu", "oncontextrestored", "oncuechange", "ondblclick", "ondevicemotion", "ondeviceorientation", "ondeviceorientationabsolute", "ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop", "ondurationchange", "onemptied", "onended", "onerror", "onfocus", "onformdata", "ongamepadconnected", "ongamepaddisconnected", "ongotpointercapture", "onhashchange", "oninput", "oninvalid", "onkeydown", "onkeypress", "onkeyup", "onlanguagechange", "onload", "onloadeddata", "onloadedmetadata", "onloadstart", "onlostpointercapture", "onmessage", "onmessageerror", "onmousedown", "onmouseenter", "onmouseleave", "onmousemove", "onmouseout", "onmouseover", "onmouseup", "onmousewheel", "onoffline", "ononline", "onpagehide", "onpagereveal", "onpageshow", "onpageswap", "onpause", "onplay", "onplaying", "onpointercancel", "onpointerdown", "onpointerenter", "onpointerleave", "onpointermove", "onpointerout", "onpointerover", "onpointerrawupdate", "onpointerup", "onpopstate", "onprogress", "onratechange", "onrejectionhandled", "onreset", "onresize", "onscroll", "onscrollend", "onscrollsnapchange", "onscrollsnapchanging", "onsearch", "onsecuritypolicyviolation", "onseeked", "onseeking", "onselect", "onselectionchange", "onselectstart", "onslotchange", "onstalled", "onstorage", "onsubmit", "onsuspend", "ontimeupdate", "ontoggle", "ontransitioncancel", "ontransitionend", "ontransitionrun", "ontransitionstart", "onunhandledrejection", "onunload", "onvolumechange", "onwaiting", "onwebkitanimationend", "onwebkitanimationiteration", "onwebkitanimationstart", "onwebkittransitionend", "onwheel", "open", "opener", "origin", "originAgentCluster", "outerHeight", "outerWidth", "pageXOffset", "pageYOffset", "parent", "performance", "personalbar", "postMessage", "print", "prompt", "queryLocalFonts", "queueMicrotask", "releaseEvents", "reportError", "requestAnimationFrame", "requestIdleCallback", "resizeBy", "resizeTo", "scheduler", "screen", "screenLeft", "screenTop", "screenX", "screenY", "scroll", "scrollBy", "scrollTo", "scrollX", "scrollY", "scrollbars", "self", "sessionStorage", "setInterval", "setTimeout", "sharedStorage", "showDirectoryPicker", "showOpenFilePicker", "showSaveFilePicker", "speechSynthesis", "status", "statusbar", "stop", "structuredClone", "styleMedia", "toolbar", "top", "trustedTypes", "viewport", "visualViewport", "webkitCancelAnimationFrame", "webkitRequestAnimationFrame", "webkitRequestFileSystem", "webkitResolveLocalFileSystemURL", "window"]"#;

/// Descriptor kind of every prototype member, captured from Chrome 151 over
/// all ~950 interfaces: an interface property is an accessor (`agec`
/// read-only, `agsec` read-write), a method an enumerable value (`vfwec`), a
/// constant like `Node.ELEMENT_NODE` non-writable and non-configurable
/// (`vne`). The challenge's graph walk reads descriptors exactly this way.
const IFACE_KINDS: &str = r#"{"Image":{"agsec":["alt","crossOrigin","height","loading","name","referrerPolicy","width"],"agec":["naturalHeight","naturalWidth"]},"webkitRTCPeerConnection":{"agec":["canTrickleIceCandidates","connectionState","currentLocalDescription","currentRemoteDescription","iceConnectionState","iceGatheringState","localDescription","pendingLocalDescription","pendingRemoteDescription","remoteDescription","sctp","signalingState"],"vfwec":["addIceCandidate","close","createAnswer","createDataChannel","createOffer","getConfiguration","getReceivers","getSenders","getStats","getTransceivers","restartIce","setConfiguration","setLocalDescription","setRemoteDescription"]},"WebSocket":{"vfwec":["close","send"]},"WebGLRenderingContext":{"agec":["canvas","drawingBufferFormat","drawingBufferHeight","drawingBufferWidth"]},"WebGL2RenderingContext":{"agec":["canvas","drawingBufferFormat","drawingBufferHeight","drawingBufferWidth"]},"VisualViewport":{"agsec":["onresize","onscroll","onscrollend"]},"URLSearchParams":{"agec":["size"],"vfwec":["append","delete","entries","forEach","get","getAll","has","keys","set","sort","toString","values"]},"URL":{"agec":["origin","searchParams"],"agsec":["hash","host","hostname","href","password","pathname","port","protocol","search","username"],"vfwec":["toJSON","toString"]},"UIEvent":{"agec":["detail","view","which"]},"TextMetrics":{"agec":["actualBoundingBoxAscent","actualBoundingBoxDescent","actualBoundingBoxLeft","actualBoundingBoxRight","alphabeticBaseline","fontBoundingBoxAscent","fontBoundingBoxDescent","hangingBaseline","ideographicBaseline","width"]},"TextEncoder":{"agec":["encoding"],"vfwec":["encode","encodeInto"]},"TextDecoder":{"agec":["encoding","fatal","ignoreBOM"],"vfwec":["decode"]},"ShadowRoot":{"agsec":["fullscreenElement","onslotchange"],"agec":["activeElement","clonable","customElementRegistry","delegatesFocus","pictureInPictureElement","pointerLockElement","serializable","slotAssignment"]},"Selection":{"agec":["anchorNode","anchorOffset","baseNode","baseOffset","direction","extentNode","extentOffset","focusNode","focusOffset","isCollapsed","rangeCount","type"],"vfwec":["addRange","collapse","collapseToEnd","collapseToStart","containsNode","deleteFromDocument","empty","extend","getComposedRanges","getRangeAt","modify","removeAllRanges","removeRange","selectAllChildren","setBaseAndExtent","setPosition","toString"]},"Screen":{"agsec":["onchange"]},"SVGTransformList":{"agec":["length","numberOfItems"]},"SVGStringList":{"agec":["length","numberOfItems"]},"SVGSVGElement":{"agsec":["currentScale","zoomAndPan"],"agec":["currentTranslate","preserveAspectRatio"],"vne":["SVG_ZOOMANDPAN_DISABLE","SVG_ZOOMANDPAN_MAGNIFY","SVG_ZOOMANDPAN_UNKNOWN"]},"SVGRect":{"agsec":["height","width","x","y"]},"SVGPointList":{"agec":["length","numberOfItems"]},"SVGPoint":{"agsec":["x","y"]},"SVGMatrix":{"agsec":["a","b","c","d","e","f"]},"SVGLength":{"agec":["unitType"],"agsec":["value","valueAsString","valueInSpecifiedUnits"],"vne":["SVG_LENGTHTYPE_CM","SVG_LENGTHTYPE_EMS","SVG_LENGTHTYPE_EXS","SVG_LENGTHTYPE_IN","SVG_LENGTHTYPE_MM","SVG_LENGTHTYPE_NUMBER","SVG_LENGTHTYPE_PC","SVG_LENGTHTYPE_PERCENTAGE","SVG_LENGTHTYPE_PT","SVG_LENGTHTYPE_PX","SVG_LENGTHTYPE_UNKNOWN"]},"SVGGraphicsElement":{"agec":["farthestViewportElement","nearestViewportElement","requiredExtensions","systemLanguage","transform"]},"SVGElement":{"agec":["attributeStyleMap","dataset","ownerSVGElement","viewportElement"],"agsec":["autofocus","nonce","onabort","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onauxclick","onbeforeinput","onbeforematch","onbeforetoggle","onbeforexrselect","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncopy","oncuechange","oncut","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","ongotpointercapture","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onlostpointercapture","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpaste","onpause","onplay","onplaying","onpointercancel","onpointerdown","onpointerenter","onpointerleave","onpointermove","onpointerout","onpointerover","onpointerrawupdate","onpointerup","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onscrollsnapchange","onscrollsnapchanging","onsecuritypolicyviolation","onseeked","onseeking","onselect","onselectionchange","onselectstart","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","ontransitioncancel","ontransitionend","ontransitionrun","ontransitionstart","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","style","tabIndex"],"vfwec":["blur","focus"]},"SVGAnimatedTransformList":{"agec":["animVal","baseVal"]},"SVGAnimatedString":{"agsec":["baseVal"],"agec":["animVal"]},"SVGAnimatedRect":{"agec":["animVal","baseVal"]},"SVGAnimatedLength":{"agec":["animVal","baseVal"]},"RTCPeerConnection":{"agec":["canTrickleIceCandidates","connectionState","currentLocalDescription","currentRemoteDescription","iceConnectionState","iceGatheringState","localDescription","pendingLocalDescription","pendingRemoteDescription","remoteDescription","sctp","signalingState"],"vfwec":["addIceCandidate","close","createAnswer","createDataChannel","createOffer","getConfiguration","getReceivers","getSenders","getStats","getTransceivers","restartIce","setConfiguration","setLocalDescription","setRemoteDescription"]},"PointerEvent":{"agec":["altitudeAngle","azimuthAngle","height","isPrimary","pointerId","pointerType","pressure","tangentialPressure","tiltX","tiltY","twist","width"]},"PerformanceTiming":{"vfwec":["toJSON"]},"PerformanceObserverEntryList":{"vfwec":["getEntries","getEntriesByName","getEntriesByType"]},"PerformanceObserver":{"vfwec":["disconnect","observe","takeRecords"]},"PerformanceNavigation":{"vne":["TYPE_BACK_FORWARD","TYPE_NAVIGATE","TYPE_RELOAD","TYPE_RESERVED"],"vfwec":["toJSON"]},"PerformanceEntry":{"vfwec":["toJSON"]},"Performance":{"agsec":["onresourcetimingbufferfull"],"vfwec":["clearMarks","clearMeasures","clearResourceTimings","getEntries","getEntriesByName","getEntriesByType","mark","measure","now","setResourceTimingBufferSize","toJSON"],"agec":["eventCounts","interactionCount"]},"OffscreenCanvas":{"agsec":["height","width"],"vfwec":["convertToBlob","getContext","transferToImageBitmap"]},"OfflineAudioContext":{"agsec":["oncomplete"],"agec":["length"],"vfwec":["resume","startRendering","suspend"]},"NodeList":{"agec":["length"]},"Node":{"agec":["childNodes","nodeType","ownerDocument","parentNode"],"vne":["ATTRIBUTE_NODE","CDATA_SECTION_NODE","COMMENT_NODE","DOCUMENT_FRAGMENT_NODE","DOCUMENT_NODE","DOCUMENT_POSITION_CONTAINED_BY","DOCUMENT_POSITION_CONTAINS","DOCUMENT_POSITION_DISCONNECTED","DOCUMENT_POSITION_FOLLOWING","DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC","DOCUMENT_POSITION_PRECEDING","DOCUMENT_TYPE_NODE","ELEMENT_NODE","ENTITY_NODE","ENTITY_REFERENCE_NODE","NOTATION_NODE","PROCESSING_INSTRUCTION_NODE","TEXT_NODE"]},"NetworkInformation":{"agsec":["onchange"]},"Navigator":{"agec":["clipboard","connection","credentials","deprecatedRunAdAuctionEnforcesKAnonymity","devicePosture","geolocation","gpu","hid","ink","keyboard","locks","login","managed","mediaCapabilities","mediaDevices","mediaSession","presentation","protectedAudience","scheduling","serial","serviceWorker","storage","storageBuckets","usb","userActivation","virtualKeyboard","wakeLock","webkitPersistentStorage","webkitTemporaryStorage","windowControlsOverlay","xr"]},"NamedNodeMap":{"agec":["length"]},"MouseEvent":{"agec":["altKey","button","buttons","clientX","clientY","ctrlKey","layerX","layerY","metaKey","movementX","movementY","offsetX","offsetY","pageX","pageY","relatedTarget","screenX","screenY","shiftKey","x","y"]},"MessageEvent":{"agec":["data","lastEventId","origin","ports","source"]},"MediaQueryList":{"agec":["matches","media"]},"KeyboardEvent":{"agec":["altKey","charCode","code","ctrlKey","key","keyCode","location","metaKey","repeat","shiftKey"]},"IntersectionObserver":{"agec":["delay","root","rootMargin","scrollMargin","thresholds","trackVisibility"],"vfwec":["disconnect","observe","takeRecords","unobserve"]},"InputEvent":{"agec":["data","inputType","isComposing"]},"History":{"agsec":["scrollRestoration"]},"HTMLVideoElement":{"agsec":["height","width"]},"HTMLUListElement":{"agsec":["type"]},"HTMLTitleElement":{"agsec":["text"]},"HTMLTextAreaElement":{"agsec":["defaultValue","disabled","maxLength","minLength","name","placeholder","readOnly","selectionEnd","selectionStart","value"],"agec":["type","willValidate"],"vfwec":["select","setRangeText","setSelectionRange"]},"HTMLTableElement":{"agsec":["width"]},"HTMLStyleElement":{"agsec":["disabled","type"]},"HTMLSelectElement":{"agsec":["disabled","name","value"],"agec":["type","willValidate"]},"HTMLScriptElement":{"agsec":["async","crossOrigin","defer","htmlFor","integrity","noModule","referrerPolicy","src","text","type"]},"HTMLOptionElement":{"agsec":["disabled","text","value"]},"HTMLMetaElement":{"agsec":["content","httpEquiv","name"]},"HTMLLinkElement":{"agsec":["crossOrigin","disabled","href","hreflang","integrity","referrerPolicy","rel","relList","target","type"]},"HTMLLabelElement":{"agsec":["htmlFor"]},"HTMLLIElement":{"agsec":["type","value"]},"HTMLInputElement":{"agsec":["alt","checked","defaultValue","disabled","height","maxLength","minLength","name","placeholder","readOnly","selectionEnd","selectionStart","src","type","value","width"],"agec":["willValidate"],"vfwec":["select","setRangeText","setSelectionRange"]},"HTMLImageElement":{"agsec":["alt","crossOrigin","height","loading","name","referrerPolicy","width"],"agec":["naturalHeight","naturalWidth"]},"HTMLIFrameElement":{"agsec":["allow","height","loading","name","referrerPolicy","sandbox","src","srcdoc","width"],"agec":["contentDocument","contentWindow"]},"HTMLFormElement":{"agsec":["action","name","rel","relList","target"]},"HTMLElement":{"agsec":["accessKey","autocapitalize","autofocus","contentEditable","dir","draggable","editContext","enterKeyHint","inert","inputMode","lang","onabort","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onauxclick","onbeforeinput","onbeforematch","onbeforetoggle","onbeforexrselect","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncopy","oncuechange","oncut","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","ongotpointercapture","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onlostpointercapture","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpaste","onpause","onplay","onplaying","onpointercancel","onpointerdown","onpointerenter","onpointerleave","onpointermove","onpointerout","onpointerover","onpointerrawupdate","onpointerup","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onscrollsnapchange","onscrollsnapchanging","onsecuritypolicyviolation","onseeked","onseeking","onselect","onselectionchange","onselectstart","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","ontransitioncancel","ontransitionend","ontransitionrun","ontransitionstart","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","outerText","popover","spellcheck","style","tabIndex","title","translate","virtualKeyboardPolicy","writingSuggestions"],"agec":["attributeStyleMap"]},"HTMLCanvasElement":{"agsec":["height","width"]},"HTMLButtonElement":{"agsec":["disabled","name","type","value"],"agec":["willValidate"]},"HTMLBodyElement":{"agsec":["text"]},"HTMLAnchorElement":{"agsec":["hash","host","hostname","href","hreflang","name","password","pathname","port","protocol","referrerPolicy","rel","relList","search","target","text","type","username"],"agec":["origin"]},"FormData":{"vfwec":["append","delete","entries","forEach","get","getAll","has","keys","set","values"]},"FocusEvent":{"agec":["relatedTarget"]},"FileReader":{"vfwec":["abort","readAsArrayBuffer","readAsBinaryString","readAsDataURL","readAsText"]},"Event":{"agec":["bubbles","cancelable","composed","currentTarget","defaultPrevented","eventPhase","target","timeStamp","type"]},"Element":{"agec":["activeViewTransition","assignedSlot","currentCSSZoom","customElementRegistry","namespaceURI","prefix"],"agsec":["ariaActiveDescendantElement","ariaAtomic","ariaAutoComplete","ariaBrailleLabel","ariaBrailleRoleDescription","ariaBusy","ariaChecked","ariaColCount","ariaColIndex","ariaColIndexText","ariaColSpan","ariaControlsElements","ariaCurrent","ariaDescribedByElements","ariaDescription","ariaDetailsElements","ariaDisabled","ariaErrorMessageElements","ariaExpanded","ariaFlowToElements","ariaHasPopup","ariaHidden","ariaInvalid","ariaKeyShortcuts","ariaLabel","ariaLabelledByElements","ariaLevel","ariaLive","ariaModal","ariaMultiLine","ariaMultiSelectable","ariaOrientation","ariaPlaceholder","ariaPosInSet","ariaPressed","ariaReadOnly","ariaRelevant","ariaRequired","ariaRoleDescription","ariaRowCount","ariaRowIndex","ariaRowIndexText","ariaRowSpan","ariaSelected","ariaSetSize","ariaSort","ariaValueMax","ariaValueMin","ariaValueNow","ariaValueText","classList","elementTiming","onbeforecopy","onbeforecut","onbeforepaste","onfullscreenchange","onfullscreenerror","onsearch","onwebkitfullscreenchange","onwebkitfullscreenerror","outerHTML","part","role","scrollLeft","scrollTop","slot"]},"Document":{"agec":["activeElement","activeViewTransition","all","applets","childElementCount","children","currentScript","customElementRegistry","defaultView","documentElement","featurePolicy","firstElementChild","fonts","fragmentDirective","implementation","lastElementChild","pictureInPictureElement","pictureInPictureEnabled","pointerLockElement","prerendering","readyState","referrer","rootElement","scrollingElement","timeline","wasDiscarded","webkitCurrentFullScreenElement","webkitFullscreenElement","webkitFullscreenEnabled","webkitHidden","webkitIsFullScreen","xmlEncoding"],"agsec":["body","fullscreen","fullscreenElement","fullscreenEnabled","onabort","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onauxclick","onbeforecopy","onbeforecut","onbeforeinput","onbeforematch","onbeforepaste","onbeforetoggle","onbeforexrselect","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncopy","oncuechange","oncut","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","onfreeze","onfullscreenchange","onfullscreenerror","ongotpointercapture","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onlostpointercapture","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpaste","onpause","onplay","onplaying","onpointercancel","onpointerdown","onpointerenter","onpointerleave","onpointerlockchange","onpointerlockerror","onpointermove","onpointerout","onpointerover","onpointerrawupdate","onpointerup","onprerenderingchange","onprogress","onratechange","onreadystatechange","onreset","onresize","onresume","onscroll","onscrollend","onscrollsnapchange","onscrollsnapchanging","onsearch","onsecuritypolicyviolation","onseeked","onseeking","onselect","onselectionchange","onselectstart","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","ontransitioncancel","ontransitionend","ontransitionrun","ontransitionstart","onvisibilitychange","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkitfullscreenchange","onwebkitfullscreenerror","onwebkittransitionend","onwheel","xmlStandalone","xmlVersion"]},"DOMTokenList":{"agec":["length"],"agsec":["value"]},"DOMRectReadOnly":{"agec":["bottom","height","left","right","top","width","x","y"],"vfwec":["toJSON"]},"DOMRect":{"agsec":["height","width","x","y"]},"CustomEvent":{"agec":["detail"]},"CustomElementRegistry":{"vfwec":["define","get","getName","upgrade","whenDefined"]},"Crypto":{"vfwec":["getRandomValues","randomUUID"]},"CanvasRenderingContext2D":{"agec":["canvas"]},"CanvasPattern":{"vfwec":["setTransform"]},"CanvasGradient":{"vfwec":["addColorStop"]},"CSSStyleDeclaration":{"agsec":["cssFloat","cssText"],"agec":["length","parentRule"]},"Blob":{"agec":["size","type"],"vfwec":["arrayBuffer","bytes","slice","text"]},"BaseAudioContext":{"agec":["audioWorklet","currentTime","destination","listener","sampleRate","state"],"agsec":["onstatechange"],"vfwec":["createAnalyser","createBiquadFilter","createBuffer","createBufferSource","createConvolver","createDelay","createDynamicsCompressor","createGain","createOscillator","createPanner","createPeriodicWave","createScriptProcessor","createStereoPanner","createWaveShaper","decodeAudioData"]},"AudioContext":{"agec":["baseLatency","outputLatency","playbackStats","sinkId"],"agsec":["onerror","onsinkchange"],"vfwec":["close","resume","suspend"]},"AnalyserNode":{"agec":["frequencyBinCount"]},"GPUDevice":{"agsec":["label"]},"SubtleCrypto":{"vfwec":["decrypt","deriveBits","deriveKey","digest","encrypt","exportKey","generateKey","importKey","sign","verify"]},"SharedWorker":{"agec":["port"],"agsec":["onerror"]},"SpeechSynthesis":{"agsec":["onvoiceschanged"]}}"#;

/// Fixes descriptors to the captured kinds: adds nothing, only reshapes what
/// exists. Runs last, after stubs, lifts and moves, or the fixes get
/// overwritten.
const IFACE_KINDS_TEMPLATE: &str = r#"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_charAt = __sm(String.prototype.charAt, 'charAt'),
    __s_charCodeAt = __sm(String.prototype.charCodeAt, 'charCodeAt');
  const K = __IFACE_KINDS__;
  const nat = globalThis.__pt_native || ((f) => f);
  const named = (f, n) => {
    try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {}
    return f;
  };
  // Stub accessor get/set: the value lives on the object itself, as in the
  // browser, not shared across the prototype. One store for all of them (a
  // WeakMap per property was thousands per context), and accessors born with
  // their names (writing `name` later moves a function to dictionary mode).
  const slots = new WeakMap();
  const pair = (name, dflt) => {
    const d = Object.getOwnPropertyDescriptor({
      get [name]() { const s = slots.get(this); return s && name in s ? s[name] : dflt; },
      set [name](v) {
        let s = slots.get(this);
        if (!s) { s = Object.create(null); try { slots.set(this, s); } catch (e) { return; } }
        s[name] = v;
      },
    }, name);
    return [nat(d.get), nat(d.set)];
  };
  // The engine still needs removed setters: the browser writes these fields
  // internally, the page cannot. The store was created earlier (constructors
  // use it too); here it is only filled.
  const writers = globalThis.__pt_writers;
  for (const iface of Object.keys(K)) {
    let P;
    try { const C = globalThis[iface]; P = C && C.prototype; } catch (e) { continue; }
    if (!P || typeof P !== 'object') continue;
    const groups = K[iface];
    for (const kind of Object.keys(groups)) {
      const wantE = __s_indexOf(kind, 'e') >= 0, wantC = __s_indexOf(kind, 'c') >= 0;
      for (const name of groups[kind]) {
        let d;
        try { d = Object.getOwnPropertyDescriptor(P, name); } catch (e) { continue; }
        if (!d || !d.configurable) continue;
        try {
          if (__s_charCodeAt(kind, 0) === 97) {
            const wantSet = __s_charAt(kind, 2) === 's';
            let get = d.get, set = d.set;
            if (!get || (wantSet && !set)) {
              const made = pair(name, d.get ? undefined : d.value);
              if (!get) { get = made[0]; set = made[1]; }
              else if (wantSet && !set) set = made[1];
            }
            if (!wantSet && set && writers) {
              let w = writers.get(P);
              if (!w) { w = Object.create(null); writers.set(P, w); }
              w[name] = set;
            }
            Object.defineProperty(P, name, {
              get, set: wantSet ? set : undefined, enumerable: wantE, configurable: wantC,
            });
          } else {
            let value = d.value;
            if (d.get) { try { value = d.get.call(P); } catch (e) { value = undefined; } }
            // Configurable for now: the prototype shape layer sets final flags
            // and Chrome's member order, and could not move a non-configurable
            // constant (Node's constants used to come first).
            Object.defineProperty(P, name, {
              value, writable: __s_indexOf(kind, 'w') >= 0, enumerable: wantE, configurable: true,
            });
          }
        } catch (e) {}
      }
    }
  }
})();"#;

pub fn web_surface_script() -> String {
    // Sub-layer markers for NOKK_TRACE_BOOT (and the debug NOKK_SNAP_CUT).
    let m = |n: &str| if std::env::var_os("NOKK_TRACE_BOOT").is_some() { format!("\n;(globalThis.__pt_bootT = globalThis.__pt_bootT || []).push(['{n}', Date.now()]);\n") } else { "\n".to_string() };
    format!(
        "{WEB_SURFACE_TEMPLATE}{}{}{}{}{}{}",
        m("surf_fill"),
        WEB_BODIES_TEMPLATE
            .replace("__CLONE__", CLONE_TEMPLATE)
            .replace("__OPFS__", OPFS_TEMPLATE)
            .replace("__CHROME_FULL__", CHROME_FULL),
        m("surf_bodies"),
        WINDOW_SHAPE_TEMPLATE.replace("__WINDOW_ENUMERABLE__", &json_table(WINDOW_ENUMERABLE)),
        m("surf_window"),
        IFACE_STATICS_TEMPLATE
            .replace("__IFACE_STATICS__", &json_table(IFACE_STATICS))
            .replace("__IFACE_PROTO_MOVES__", &json_table(IFACE_PROTO_MOVES))
            .replace("__IFACE_CHAIN__", &json_table(IFACE_CHAIN))
            .replace("__IFACE_LIFT__", &json_table(IFACE_LIFT)),
    ) + &m("surf_statics") + &IFACE_KINDS_TEMPLATE.replace("__IFACE_KINDS__", &json_table(IFACE_KINDS))
}

/// Makes window own-property enumerability match the browser. Runs last:
/// everything the engine puts on `window` is in place and page scripts have
/// not run yet, so their own globals stay enumerable as they should.
const WINDOW_SHAPE_TEMPLATE: &str = r#"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_lastIndexOf = __sm(String.prototype.lastIndexOf, 'lastIndexOf'),
    __s_indexOf = __sm(String.prototype.indexOf, 'indexOf');
  // Window chain captured from Chrome 148:
  //   window -> Window.prototype (TEMPORARY, PERSISTENT) -> WindowProperties ->
  //   EventTarget.prototype (addEventListener, dispatchEvent, removeEventListener,
  //   when) -> Object.prototype, and `window.constructor === Window`.
  const native = globalThis.__pt_native || ((f) => f);
  const ET = globalThis.EventTarget;
  const etProto = (ET && ET.prototype) || Object.prototype;
  for (const name of ['addEventListener', 'removeEventListener', 'dispatchEvent', 'when']) {
    let own;
    try { own = Object.getOwnPropertyDescriptor(globalThis, name); } catch (e) { continue; }
    if (!own) continue;
    // Whatever EventTarget lacks moves there; the rest just leaves the window
    // and the inherited version takes over.
    if (!Object.getOwnPropertyDescriptor(etProto, name)) {
      try { Object.defineProperty(etProto, name, Object.assign({}, own, { enumerable: true })); } catch (e) {}
    }
    try { delete globalThis[name]; } catch (e) {}
  }

  // The global is born from the Window template: its chain is already set and
  // immutable, as in Chrome; reuse its links instead of building our own.
  const T = (globalThis.__pt_protos !== undefined ? globalThis.__pt_protos : (() => { let t = null; try { if (typeof __pt_protoTemplates === 'function') t = __pt_protoTemplates() || null; } catch (e) {} try { Object.defineProperty(globalThis, '__pt_protos', { value: t, configurable: true }); } catch (e) {} return t; })());
  const fromTemplate = !!(T && T.w && Object.getPrototypeOf(globalThis) === T.w && Object.getPrototypeOf(T.wp) === etProto);
  const windowProperties = fromTemplate ? T.wp : Object.create(etProto);
  if (fromTemplate) { try { delete windowProperties.constructor; } catch (e) {} }
  const Window = globalThis.Window && typeof globalThis.Window === 'function'
    ? globalThis.Window
    : native(__ptIllegal('Window'));
  const winProto = fromTemplate ? T.w : Object.create(windowProperties);
  for (const [name, fallback] of [['TEMPORARY', 0], ['PERSISTENT', 1]]) {
    let own;
    try { own = Object.getOwnPropertyDescriptor(globalThis, name); } catch (e) {}
    try {
      Object.defineProperty(winProto, name, {
        value: own ? own.value : fallback, enumerable: true, writable: false, configurable: false,
      });
    } catch (e) {}
    try { delete globalThis[name]; } catch (e) {}
  }
  try { Object.defineProperty(winProto, 'constructor', { value: Window, writable: true, configurable: true }); } catch (e) {}
  try { Object.defineProperty(winProto, Symbol.toStringTag, { value: 'Window', configurable: true }); } catch (e) {}
  try { Object.defineProperty(Window, 'prototype', { value: winProto, writable: false, configurable: false }); } catch (e) { Window.prototype = winProto; }
  globalThis.Window = Window;
  if (Object.setPrototypeOf(globalThis, winProto) === globalThis) {
    // The window's name is now on the prototype, as in the browser; drop the own tag.
    try { delete globalThis[Symbol.toStringTag]; } catch (e) {}
  }

  // Screen inherits EventTarget, but the browser keeps the methods on
  // EventTarget.prototype, not Screen.prototype (exactly 12 names there).
  if (globalThis.Screen && Screen.prototype) {
    try { Object.setPrototypeOf(Screen.prototype, etProto); } catch (e) {}
    for (const name of ['addEventListener', 'removeEventListener', 'dispatchEvent', 'when']) {
      try { delete Screen.prototype[name]; } catch (e) {}
    }
  }

  // Location is the only interface whose members the browser keeps as own
  // (non-configurable) properties of the object, leaving only `constructor`
  // on the prototype.
  try {
    const loc = globalThis.location;
    const lproto = loc && Object.getPrototypeOf(loc);
    if (loc && lproto && lproto !== Object.prototype) {
      // ancestorOrigins is a real DOMStringList: zero length for a top-level
      // page, but with its prototype, `item` and `contains`. Prepared before
      // the move, since moved members are non-configurable.
      let ancestors = null;
      try {
        const DSL = typeof globalThis.DOMStringList === 'function' ? globalThis.DOMStringList : null;
        if (DSL) {
          const P = DSL.prototype;
          const nat = globalThis.__pt_native || ((f) => f);
          if (!Object.prototype.hasOwnProperty.call(P, 'length')) {
            Object.defineProperty(P, 'length', {
              get: nat(function length() { return 0; }), enumerable: true, configurable: true,
            });
            for (const [m, f] of [['contains', function contains() { return false; }],
                                  ['item', function item() { return null; }]]) {
              Object.defineProperty(P, m, { value: nat(f), writable: true, enumerable: true, configurable: true });
            }
            // The browser's `constructor` comes last, i.e. added after members;
            // enumerating the prototype shows it.
            const ctor = Object.getOwnPropertyDescriptor(P, 'constructor');
            if (ctor && ctor.configurable) { delete P.constructor; Object.defineProperty(P, 'constructor', ctor); }
            try { Object.defineProperty(P, Symbol.toStringTag, { value: 'DOMStringList', configurable: true }); }
            catch (e2) {}
          }
          ancestors = Object.create(P);
        }
      } catch (e) {}
      // Chrome's own-member order (`valueOf` first).
      const LOC_ORDER = ['valueOf', 'ancestorOrigins', 'href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash', 'assign', 'reload', 'replace', 'toString'];
      const lnames = LOC_ORDER.filter((n) => Object.prototype.hasOwnProperty.call(lproto, n))
        .concat(Object.getOwnPropertyNames(lproto).filter((n) => __s_indexOf(LOC_ORDER, n) < 0));
      for (const name of lnames) {
        if (name === 'constructor') continue;
        let d = Object.getOwnPropertyDescriptor(lproto, name);
        if (!d) continue;
        if (name === 'ancestorOrigins' && ancestors) {
          d = { get: (globalThis.__pt_native || ((f) => f))(
                  ({ get ancestorOrigins() { return ancestors; } }).__lookupGetter__('ancestorOrigins')), enumerable: true, configurable: true };
        }
        try {
          // The browser's `valueOf` is non-enumerable, the other fifteen are enumerable.
          const own = Object.assign({}, d, {
            enumerable: name !== 'valueOf', configurable: false,
          });
          // The browser keeps Location members non-writable and
          // non-configurable; a descriptor read shows it.
          if ('writable' in own) own.writable = false;
          // `origin` is read-only: in the browser assignment silently does nothing.
          if (name === 'origin') delete own.set;
          Object.defineProperty(loc, name, own);
          delete lproto[name];
        } catch (e) {}
      }

    }
  } catch (e) {}

  // The document has two levels: members on Document.prototype, and between
  // it and the document an empty HTMLDocument.prototype with only
  // `constructor`. `location` is an own property of the document.
  try {
    const dproto = Object.getPrototypeOf(globalThis.document);
    const HTMLDocument = typeof globalThis.HTMLDocument === 'function'
      ? globalThis.HTMLDocument
      : __ptIllegal('HTMLDocument');
    if (dproto && !Object.getOwnPropertyDescriptor(dproto, 'constructor')) {
      // nothing: never seen a document prototype without a constructor
    }
    if (Object.getPrototypeOf(dproto) !== null && dproto.constructor !== HTMLDocument) {
      const htmlDocProto = Object.create(dproto);
      Object.defineProperty(htmlDocProto, 'constructor', { value: HTMLDocument, writable: true, configurable: true });
      try { Object.defineProperty(htmlDocProto, Symbol.toStringTag, { value: 'HTMLDocument', configurable: true }); } catch (e) {}
      try { Object.defineProperty(HTMLDocument, 'prototype', { value: htmlDocProto, writable: false, configurable: false }); }
      catch (e) { HTMLDocument.prototype = htmlDocProto; }
      globalThis.HTMLDocument = globalThis.__pt_native ? __pt_native(HTMLDocument) : HTMLDocument;
      Object.setPrototypeOf(globalThis.document, htmlDocProto);
    }
    // HTML4 legacy the browser still keeps: six document attributes; and what
    // belongs to Node is not duplicated on Document.
    for (const name of ['baseURI', 'nodeName', 'textContent', 'when']) {
      try { delete dproto[name]; } catch (e) {}
    }
    for (const [name, initial] of [['alinkColor', ''], ['bgColor', ''], ['fgColor', ''],
                                   ['linkColor', ''], ['vlinkColor', ''], ['dir', '']]) {
      if (Object.getOwnPropertyDescriptor(dproto, name)) continue;
      let value = initial;
      try {
        Object.defineProperty(dproto, name, {
          get: function () { return value; },
          set: function (v) { value = String(v); },
          enumerable: true, configurable: true,
        });
      } catch (e) {}
    }
    const locDesc = Object.getOwnPropertyDescriptor(dproto, 'location');
    if (locDesc) {
      Object.defineProperty(globalThis.document, 'location',
        Object.assign({}, locDesc, { enumerable: true, configurable: false }));
      delete dproto.location;
    }
  } catch (e) {}

  // `window.status`: nineties legacy, but Chrome has it as a writable empty string.
  if (!('status' in globalThis)) {
    try {
      Object.defineProperty(globalThis, 'status', {
        value: '', writable: true, enumerable: true, configurable: true,
      });
    } catch (e) {}
  }

  const ENUM = new Set(__WINDOW_ENUMERABLE__);
  for (const name of Object.getOwnPropertyNames(globalThis)) {
    if (__s_lastIndexOf(name, '__pt', 0) === 0 || __s_lastIndexOf(name, '__out', 0) === 0) continue;
    let d;
    try { d = Object.getOwnPropertyDescriptor(globalThis, name); } catch (e) { continue; }
    if (!d || !d.configurable) continue;
    const want = ENUM.has(name);
    if (!!d.enumerable === want) continue;
    try { Object.defineProperty(globalThis, name, Object.assign({}, d, { enumerable: want })); } catch (e) {}
  }
})();"#;

/// Bodies for interfaces the graph table only names.
///
/// A `{}` stub answers "does this name exist" but not "what can it do", which
/// shows on the first call: the Turnstile widget builds its worker URL via
/// `trustedTypes.createPolicy`, and fingerprint collection runs inside that
/// worker.
///
/// Values are captured from a local Chrome 148, including
/// the WebGPU adapter limits and features and the keyboard layout.
///
/// Runs after [`WEB_SURFACE_TEMPLATE`], which creates names like
/// `navigator.gpu`; a stub can only be rebranded once it exists.
const CLONE_TEMPLATE: &str = r##"  // ── Structured clone ─────────────────────────────────────────────
  // Messages between window, frame and worker go by structured clone:
  // `Uint8Array` arrives as bytes, `Map` as a map, a date as a date. JSON would
  // turn bytes into `{0:1,1:2}` and dates into strings.
  (() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_charCodeAt = __sm(String.prototype.charCodeAt, 'charCodeAt');
    const TA = ['Int8Array', 'Uint8Array', 'Uint8ClampedArray', 'Int16Array', 'Uint16Array',
                'Int32Array', 'Uint32Array', 'Float32Array', 'Float64Array',
                'BigInt64Array', 'BigUint64Array', 'DataView'];
    const b64 = (bytes) => {
      let s = '';
      for (let i = 0; i < bytes.length; i += 0x8000) {
        s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      return globalThis.btoa ? btoa(s) : s;
    };
    const unb64 = (text) => {
      const s = globalThis.atob ? atob(text) : text;
      const out = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) out[i] = __s_charCodeAt(s, i) & 255;
      return out;
    };
    const bytesOf = (v) => (v instanceof ArrayBuffer
      ? new Uint8Array(v)
      : new Uint8Array(v.buffer, v.byteOffset, v.byteLength));

    const encodeValue = (v, seen) => {
      if (v === undefined) return { $: 'u' };
      if (v === null) return null;
      const t = typeof v;
      if (t === 'string' || t === 'boolean') return v;
      if (t === 'number') return Number.isFinite(v) ? v : { $: 'nf', v: String(v) };
      if (t === 'bigint') return { $: 'big', v: String(v) };
      if (t === 'function' || t === 'symbol') {
        const e = __pt_mkErr(globalThis.DOMException || Error, 
          'Failed to execute \'postMessage\': ' + String(v) + ' could not be cloned.', 'DataCloneError');
        e.name = 'DataCloneError';
        throw e;
      }
      const known = seen.get(v);
      if (known !== undefined) return { $: 'ref', i: known };
      const id = seen.size;
      seen.set(v, id);
      const tag = Object.prototype.toString.call(v);
      // A transferred canvas survives the worker boundary: its surface id
      // goes along so the worker draws on the same surface.
      if (tag === '[object OffscreenCanvas]' && v.__ptO) {
        let surf = 0;
        try { surf = (v.__ptO.c && v.__ptO.c.__ptSurf && v.__ptO.c.__ptSurf.id()) || 0; } catch (e) {}
        return { $: 'offscreen', w: v.__ptO.w | 0, h: v.__ptO.h | 0, s: surf };
      }
      // A bitmap also survives the boundary and stays drawable on the other
      // side; otherwise a worker-drawn snapshot reached the main thread
      // without pixels and `drawImage` rejected it.
      if (tag === '[object ImageBitmap]' || v.__ptImageBitmap) {
        const st = v.__ptImageBitmap;
        const w = (st ? st.w : v.width) | 0, h = (st ? st.h : v.height) | 0;
        // The pixels themselves cross, not the surface id: surfaces live on
        // their own thread and a foreign id means nothing there. A worker that
        // draws a canvas and returns a bitmap is exactly how canvas
        // fingerprints are collected.
        let bits = '';
        try {
          const pm = st && st.surf && st.surf.pixels ? st.surf.pixels() : null;
          if (pm && pm.data) bits = b64(pm.data.subarray ? pm.data.subarray(0, w * h * 4) : pm.data);
        } catch (e) { bits = ''; }
        return { $: 'bitmap', w, h, b: bits };
      }
      if (tag === '[object Date]') return { $: 'date', t: v.getTime() };
      if (tag === '[object RegExp]') return { $: 're', s: v.source, f: v.flags };
      if (tag === '[object Error]' || v instanceof Error) {
        return { $: 'err', n: String(v.name || 'Error'), m: String(v.message || ''), k: String(v.stack || '') };
      }
      if (tag === '[object ArrayBuffer]') return { $: 'ab', b: b64(new Uint8Array(v)) };
      const kind = __s_slice(tag, 8, -1);
      if (__s_indexOf(TA, kind) >= 0) {
        return { $: 'ta', k: kind, b: b64(bytesOf(v)), o: 0, n: kind === 'DataView' ? v.byteLength : v.length };
      }
      if (tag === '[object Map]') {
        const e = [];
        v.forEach((val, key) => e.push([encodeValue(key, seen), encodeValue(val, seen)]));
        return { $: 'map', e };
      }
      if (tag === '[object Set]') {
        const e = [];
        v.forEach((val) => e.push(encodeValue(val, seen)));
        return { $: 'set', e };
      }
      if (tag === '[object Blob]' || tag === '[object File]') {
        // The browser clones a Blob whole, with contents and type.
        let data = '';
        try { data = globalThis.__pt_blobParts ? (__pt_blobParts(v) || []).join('') : ''; } catch (e) {}
        return { $: 'blob', d: data, t: String(v.type || ''), n: v.name === undefined ? null : String(v.name) };
      }
      if (Array.isArray(v)) return { $: 'arr', v: v.map((x) => encodeValue(x, seen)) };
      const p = {};
      for (const k of Object.keys(v)) {
        let val;
        try { val = v[k]; } catch (e) { continue; }
        p[k] = encodeValue(val, seen);
      }
      return { $: 'obj', p };
    };

    const reviveValue = (v, made) => {
      if (v === null || typeof v !== 'object') return v;
      if (Array.isArray(v)) return v.map((x) => reviveValue(x, made));
      const kind = v.$;
      if (kind === undefined) {                     // foreign format: as is
        const out = {};
        for (const k of Object.keys(v)) out[k] = reviveValue(v[k], made);
        return out;
      }
      if (kind === 'u') return undefined;
      if (kind === 'nf') return Number(v.v);
      if (kind === 'big') return globalThis.BigInt ? BigInt(v.v) : Number(v.v);
      if (kind === 'ref') return made[v.i];
      // A canvas passed to a worker: build an `OffscreenCanvas` of the same
      // size. The surface id goes along so drawing lands on the same surface
      // when the worker runs on the same thread.
      if (kind === 'offscreen') {
        let off = null;
        try {
          off = new globalThis.OffscreenCanvas(v.w || 0, v.h || 0);
          if (v.s && off.__ptO && off.__ptO.c) {
            try { Object.defineProperty(off.__ptO.c, '__ptSurfId', { value: v.s, configurable: true }); } catch (e) {}
          }
        } catch (e) {}
        made.push(off);
        return off;
      }
      if (kind === 'bitmap') {
        const w = v.w | 0, h = v.h | 0;
        let surf = null;
        try {
          if (v.b && globalThis.OffscreenCanvas) {
            const off = new globalThis.OffscreenCanvas(w, h);
            const g = globalThis.__pt_privateCtx
              ? globalThis.__pt_privateCtx(off.__ptO && off.__ptO.c, '2d')
              : off.getContext('2d');
            const bytes = unb64(v.b);
            if (g && globalThis.__pt_makeImageData) {
              g.putImageData(globalThis.__pt_makeImageData(
                new Uint8ClampedArray(bytes.buffer, bytes.byteOffset, Math.min(bytes.length, w * h * 4)),
                w, h), 0, 0);
            }
            surf = off.__ptO && off.__ptO.c && off.__ptO.c.__ptSurf;
          }
        } catch (e) { surf = null; }
        const bm = globalThis.__pt_makeBitmap
          ? globalThis.__pt_makeBitmap(surf, w, h)
          : { width: w, height: h, close() {} };
        made.push(bm);
        return bm;
      }
      if (kind === 'date') { const d = new Date(v.t); made.push(d); return d; }
      if (kind === 're') { const r = new RegExp(v.s, v.f); made.push(r); return r; }
      if (kind === 'err') {
        const C = globalThis[v.n] && /Error$/.test(v.n) ? globalThis[v.n] : Error;
        const e = new C(v.m);
        try { e.stack = v.k; } catch (x) {}
        made.push(e);
        return e;
      }
      if (kind === 'ab') { const b = unb64(v.b); made.push(b.buffer); return b.buffer; }
      if (kind === 'ta') {
        const bytes = unb64(v.b);
        const C = globalThis[v.k] || Uint8Array;
        const out = v.k === 'DataView' ? new DataView(bytes.buffer) : new C(bytes.buffer);
        made.push(out);
        return out;
      }
      if (kind === 'map') {
        const m = new Map(); made.push(m);
        for (const [k, val] of v.e) m.set(reviveValue(k, made), reviveValue(val, made));
        return m;
      }
      if (kind === 'set') {
        const s = new Set(); made.push(s);
        for (const val of v.e) s.add(reviveValue(val, made));
        return s;
      }
      if (kind === 'blob') {
        const b = new Blob([v.d], { type: v.t });
        if (v.n !== null) { try { Object.defineProperty(b, 'name', { value: v.n, configurable: true }); } catch (x) {} }
        made.push(b);
        return b;
      }
      if (kind === 'arr') {
        const out = []; made.push(out);
        for (const x of v.v) out.push(reviveValue(x, made));
        return out;
      }
      if (kind === 'obj') {
        const out = {}; made.push(out);
        for (const k of Object.keys(v.p)) out[k] = reviveValue(v.p[k], made);
        return out;
      }
      return v;
    };

    Object.defineProperty(globalThis, '__pt_cloneEncode', { value: (v) => __ptJSON.stringify(encodeValue(v, new Map())), writable: true, configurable: true });
    Object.defineProperty(globalThis, '__pt_cloneRevive', { value: (v) => reviveValue(v, []), writable: true, configurable: true });
    Object.defineProperty(globalThis, '__pt_cloneDecode', {
      value: (text) => {
        let parsed = null;
        try { parsed = __ptJSON.parse(text); } catch (e) { return null; }
        return reviveValue(parsed, []);
      },
      writable: true, configurable: true,
    });
  })();
"##;

const OPFS_TEMPLATE: &str = r##"  // ── Origin Private File System ───────────────────────────────────────────
  // In the browser, origin file system calls cross a process boundary:
  // `getDirectory()`, `getFileHandle()` and `createSyncAccessHandle()` resolve
  // on a later task, not the same tick. A chain of three taking zero ms is
  // impossible, and the challenge times that chain.
  const soon = (v) => new Promise((res) => { setTimeout(() => res(v), 0); });

  // The challenge asks a worker for an OPFS file, takes a sync handle, writes
  // a byte and times `flush()`; Chrome never denies `getDirectory()` in a
  // secure context. Storage is in realm memory: the probe writes one byte.
  const __ptOPFS = (() => {
    const bytesOf = (chunk) => {
      if (chunk == null) return new Uint8Array(0);
      if (typeof chunk === 'string') return new TextEncoder().encode(chunk);
      if (chunk instanceof Uint8Array) return chunk;
      if (chunk.buffer instanceof ArrayBuffer) return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
      if (chunk instanceof ArrayBuffer) return new Uint8Array(chunk);
      return new TextEncoder().encode(String(chunk));
    };
    const putAt = (file, data, at) => {
      const start = Math.max(0, at | 0), end = start + data.length;
      if (end > file.data.length) {
        const grown = new Uint8Array(end);
        grown.set(file.data);
        __pt_write(file, 'data', grown);
      }
      file.data.set(data, start);
      return data.length;
    };
    const iface = (name, base) => {
      const C = globalThis[name];
      if (!C || !C.prototype) return null;
      if (base && Object.getPrototypeOf(C.prototype) !== base.prototype) {
        try { Object.setPrototypeOf(C.prototype, base.prototype); } catch (e) {}
      }
      try {
        if (!Object.getOwnPropertyDescriptor(C.prototype, Symbol.toStringTag)) {
          Object.defineProperty(C.prototype, Symbol.toStringTag, { value: name, configurable: true });
        }
      } catch (e) {}
      return C;
    };
    const put = (C, name, fn) => {
      if (!C) return;
      try { Object.defineProperty(fn, 'name', { value: name, configurable: true }); } catch (e) {}
      try {
        Object.defineProperty(C.prototype, name, {
          value: globalThis.__pt_native ? __pt_native(fn) : fn,
          writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
    };
    const accessor = (C, name, get) => {
      if (!C) return;
      try {
        Object.defineProperty(C.prototype, name, {
          get: globalThis.__pt_native ? __pt_native(get) : get,
          enumerable: true, configurable: true,
        });
      } catch (e) {}
    };

    const STATE = new WeakMap();          // handle -> its node
    const Handle = iface('FileSystemHandle');
    const Dir = iface('FileSystemDirectoryHandle', Handle);
    const FileH = iface('FileSystemFileHandle', Handle);
    const Writable = iface('FileSystemWritableFileStream');
    const Sync = iface('FileSystemSyncAccessHandle');
    if (!Handle || !Dir || !FileH) return null;

    const makeHandle = (C, node) => { const h = Object.create(C.prototype); STATE.set(h, node); return h; };
    const node = (h) => STATE.get(h);

    accessor(Handle, 'kind', function kind() { const n = node(this); return n ? n.kind : undefined; });
    accessor(Handle, 'name', function name() { const n = node(this); return n ? n.name : undefined; });
    put(Handle, 'isSameEntry', function isSameEntry(other) { return Promise.resolve(node(this) === node(other)); });
    put(Handle, 'queryPermission', function queryPermission() { return Promise.resolve('granted'); });
    put(Handle, 'requestPermission', function requestPermission() { return Promise.resolve('granted'); });
    put(Handle, 'remove', function remove() {
      const n = node(this);
      if (n && n.parent) n.parent.children.delete(n.name);
      return Promise.resolve(undefined);
    });

    const notFound = (name) => {
      const e = __pt_mkErr(globalThis.DOMException || Error, 
        'A requested file or directory could not be found at the time an operation was processed.', 'NotFoundError');
      e.name = 'NotFoundError';
      return e;
    };

    put(Dir, 'getFileHandle', function getFileHandle(name, opts) {
      const n = node(this);
      const key = String(name);
      let child = n.children.get(key);
      if (!child) {
        if (!(opts && opts.create)) return Promise.reject(notFound(key));
        child = { kind: 'file', name: key, data: new Uint8Array(0), parent: n };
        n.children.set(key, child);
      }
      return soon(makeHandle(FileH, child));
    });
    put(Dir, 'getDirectoryHandle', function getDirectoryHandle(name, opts) {
      const n = node(this);
      const key = String(name);
      let child = n.children.get(key);
      if (!child) {
        if (!(opts && opts.create)) return Promise.reject(notFound(key));
        child = { kind: 'directory', name: key, children: new Map(), parent: n };
        n.children.set(key, child);
      }
      return soon(makeHandle(Dir, child));
    });
    put(Dir, 'removeEntry', function removeEntry(name) {
      const n = node(this);
      return n.children.delete(String(name)) ? Promise.resolve(undefined) : Promise.reject(notFound(String(name)));
    });
    put(Dir, 'resolve', function resolve(child) {
      const path = [];
      let cur = node(child);
      const root = node(this);
      while (cur && cur !== root) { path.unshift(cur.name); cur = cur.parent; }
      return Promise.resolve(cur === root ? path : null);
    });
    const entriesOf = (dir, pick) => {
      const items = [...node(dir).children.values()].map(pick);
      let i = 0;
      const it = { next: () => Promise.resolve(i < items.length ? { value: items[i++], done: false } : { value: undefined, done: true }) };
      it[Symbol.asyncIterator] = function () { return this; };
      return it;
    };
    put(Dir, 'keys', function keys() { return entriesOf(this, (c) => c.name); });
    put(Dir, 'values', function values() {
      return entriesOf(this, (c) => makeHandle(c.kind === 'file' ? FileH : Dir, c));
    });
    put(Dir, 'entries', function entries() {
      return entriesOf(this, (c) => [c.name, makeHandle(c.kind === 'file' ? FileH : Dir, c)]);
    });
    if (Dir) {
      try { Object.defineProperty(Dir.prototype, Symbol.asyncIterator, { value: Dir.prototype.entries, writable: true, configurable: true }); } catch (e) {}
    }

    put(FileH, 'getFile', function getFile() {
      const n = node(this);
      const blob = new Blob([n.data]);
      try {
        Object.defineProperty(blob, 'name', { value: n.name, configurable: true });
        Object.defineProperty(blob, 'lastModified', { value: Date.now(), configurable: true });
      } catch (e) {}
      return Promise.resolve(blob);
    });
    put(FileH, 'move', function move(dest, name) {
      const n = node(this);
      if (n.parent) n.parent.children.delete(n.name);
      const target = typeof dest === 'string' ? n.parent : node(dest);
      n.name = String(typeof dest === 'string' ? dest : (name === undefined ? n.name : name));
      n.parent = target;
      if (target) target.children.set(n.name, n);
      return Promise.resolve(undefined);
    });
    put(FileH, 'createWritable', function createWritable(opts) {
      const n = node(this);
      if (!(opts && opts.keepExistingData)) __pt_write(n, 'data', new Uint8Array(0));
      const stream = Object.create(Writable ? Writable.prototype : Object.prototype);
      STATE.set(stream, { file: n, at: 0 });
      return Promise.resolve(stream);
    });

    if (Writable) {
      accessor(Writable, 'mode', function mode() { return 'siloed'; });
      put(Writable, 'write', function write(chunk) {
        const st = node(this);
        if (chunk && typeof chunk === 'object' && chunk.type) {
          if (chunk.type === 'seek') { st.at = chunk.position | 0; return Promise.resolve(undefined); }
          if (chunk.type === 'truncate') { __pt_write(st.file, 'data', st.file.data.slice(0, chunk.size | 0)); return Promise.resolve(undefined); }
          chunk = chunk.data;
        }
        st.at += putAt(st.file, bytesOf(chunk), st.at);
        return Promise.resolve(undefined);
      });
      put(Writable, 'seek', function seek(pos) { node(this).at = pos | 0; return Promise.resolve(undefined); });
      put(Writable, 'truncate', function truncate(size) {
        const st = node(this);
        __pt_write(st.file, 'data', st.file.data.slice(0, size | 0));
        return Promise.resolve(undefined);
      });
      put(Writable, 'close', function close() { return Promise.resolve(undefined); });
      put(Writable, 'abort', function abort() { return Promise.resolve(undefined); });
    }

    // Only workers have a sync handle; Chrome's window lacks the name.
    if (Sync) {
      put(FileH, 'createSyncAccessHandle', function createSyncAccessHandle() {
        const h = Object.create(Sync.prototype);
        const f = node(this);
        // A real file backs the handle: contents stay in memory, but `flush()`
        // writes to disk and waits, which is what the browser's ~4 ms pays for.
        let fd = 0;
        try {
          if (typeof __pt_fsOpen === 'function') fd = __pt_fsOpen(String(f.name || 'opfs')) | 0;
        } catch (e) {}
        STATE.set(h, { file: f, closed: false, fd });
        return soon(h);
      });
      put(Sync, 'write', function write(buf, opts) {
        const st = node(this);
        return putAt(st.file, bytesOf(buf), opts && opts.at !== undefined ? opts.at : 0);
      });
      put(Sync, 'read', function read(buf, opts) {
        const st = node(this), at = Math.max(0, (opts && opts.at) | 0);
        const out = bytesOf(buf);
        const n = Math.max(0, Math.min(out.length, st.file.data.length - at));
        out.set(st.file.data.subarray(at, at + n));
        return n;
      });
      put(Sync, 'getSize', function getSize() { return node(this).file.data.length; });
      put(Sync, 'truncate', function truncate(size) { const st = node(this); __pt_write(st.file, 'data', st.file.data.slice(0, size | 0)); });
      put(Sync, 'flush', function flush() {
        const st = node(this);
        if (!st.fd) return;
        try { __pt_fsFlush(st.fd, st.file.data); } catch (e) {}
      });
      put(Sync, 'close', function close() {
        const st = node(this);
        st.closed = true;
        if (st.fd) { try { __pt_fsClose(st.fd); } catch (e) {} st.fd = 0; }
      });
    }

    const root = { kind: 'directory', name: '', children: new Map(), parent: null };
    return () => soon(makeHandle(Dir, root));
  })();
"##;

const WEB_BODIES_TEMPLATE: &str = r##"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_lastIndexOf = __sm(String.prototype.lastIndexOf, 'lastIndexOf'),
    __s_replace = __sm(String.prototype.replace, 'replace'),
    __s_split = __sm(String.prototype.split, 'split'),
    __s_trim = __sm(String.prototype.trim, 'trim'),
    __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_toLowerCase = __sm(String.prototype.toLowerCase, 'toLowerCase'),
    __s_includes = __sm(String.prototype.includes, 'includes');
__CLONE__
__OPFS__
  const native = globalThis.__pt_native || ((f) => f);
  const defv = (o, k, v) => {
    try { Object.defineProperty(o, k, { value: v, writable: true, enumerable: true, configurable: true }); } catch (e) {}
  };
  const defg = (o, k, g) => {
    try { Object.defineProperty(g, 'name', { value: 'get ' + k, configurable: true }); } catch (e) {}
    try { Object.defineProperty(o, k, { get: native(g), enumerable: true, configurable: true }); } catch (e) {}
  };
  // A method, not a function: browser methods have no `prototype` (see `asMethod`).
  const fn = (name, f) => {
    let m = f;
    const methodish = /^[a-z_$]/.test(String(name))
      && Object.getOwnPropertyNames((f && f.prototype) || {}).length <= 1;
    if (typeof f === 'function' && methodish && Object.getOwnPropertyDescriptor(f, 'prototype')) {
      m = __pt_method(name, f);
    }
    try { Object.defineProperty(m, 'name', { value: name, configurable: true }); } catch (e) {}
    return native(m);
  };
  const meth = (proto, name, f) => defv(proto, name, fn(name, f));

  // An interface as the page sees it: the constructor throws "Illegal
  // constructor", the prototype has toStringTag and a back reference, and the
  // name is non-enumerable on window. `hidden`: no name on window (Chrome's
  // `FontFaceSet` is like that), since an extra global name shows in a walk.
  const iface = (name, base, hidden) => {
    const C = __ptIllegal(name);
    if (base) { try { Object.setPrototypeOf(C.prototype, base); } catch (e) {} }
    try { Object.defineProperty(C.prototype, 'constructor', { value: C, writable: true, configurable: true }); } catch (e) {}
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: name, configurable: true }); } catch (e) {}
    native(C);
    if (!hidden) {
      try { Object.defineProperty(globalThis, name, { value: C, writable: true, enumerable: false, configurable: true }); } catch (e) {}
    }
    return C;
  };

  // Moves a working object onto a real interface. Values move to the
  // prototype: in Chrome neither `navigator.storage` nor `screen.orientation`
  // has own properties, and fingerprinters walk the graph that way.
  const rebrand = (obj, name, base, hidden) => {
    if (!obj || typeof obj !== 'object') return obj;
    const C = iface(name, base, hidden);
    for (const k of Object.getOwnPropertyNames(obj)) {
      let d;
      try { d = Object.getOwnPropertyDescriptor(obj, k); } catch (e) { continue; }
      if (!d || !d.configurable) continue;
      // What the parent already has (addEventListener on EventTarget) is not
      // copied, only removed from the object and inherited.
      if (base && (k in base)) { try { delete obj[k]; } catch (e) {} continue; }
      try {
        if (typeof d.value === 'function') defv(C.prototype, k, native(d.value));
        else if ('value' in d) { const v = d.value; defg(C.prototype, k, function () { return v; }); }
        else Object.defineProperty(C.prototype, k, d);
        delete obj[k];
      } catch (e) {}
    }
    try { Object.setPrototypeOf(obj, C.prototype); } catch (e) {}
    return C;
  };

  const ET = globalThis.EventTarget && EventTarget.prototype;

  // ── Trusted Types ────────────────────────────────────────────────────────
  // The value lives in a WeakMap: a real TrustedScriptURL has no own
  // properties, only toString/toJSON on the prototype.
  const VAL = new WeakMap();
  const TrustedHTML = iface('TrustedHTML');
  const TrustedScript = iface('TrustedScript');
  const TrustedScriptURL = iface('TrustedScriptURL');
  const wrapped = (C, s) => {
    let o = null;
    if (C === TrustedScript && typeof globalThis.__pt_codeLike === 'function') {
      try { o = __pt_codeLike(String(s)); Object.setPrototypeOf(o, C.prototype); } catch (e) { o = null; }
    }
    if (!o) o = Object.create(C.prototype);
    VAL.set(o, String(s)); return o;
  };
  for (const C of [TrustedHTML, TrustedScript, TrustedScriptURL]) {
    meth(C.prototype, 'toString', function () { return VAL.get(this); });
    meth(C.prototype, 'toJSON', function () { return VAL.get(this); });
  }

  // String execution gates for TrustedScript are not wrappers around eval and
  // timers (a wrapper has its own `prototype`, visible to the challenge's
  // native function check, and a wrapped eval stops being direct):
  // TrustedScript carries its text in a hidden field (`__pt_codeLike`), eval
  // and new Function read it via the code generation callback, and timers
  // accept it in their queue.
  const installTrustedSinks = () => {};

  const isTrustedScript = (v) => { try { return v instanceof TrustedScript; } catch (e) { return false; } };
  const POL = new WeakMap();
  const TrustedTypePolicy = iface('TrustedTypePolicy');
  defg(TrustedTypePolicy.prototype, 'name', function () { const p = POL.get(this); return p ? p.name : ''; });
  const creator = (member, C) => function (input) {
    const p = POL.get(this);
    const rule = p && p.rules && p.rules[member];
    if (typeof rule !== 'function') {
      throw __pt_mkErr(TypeError, "Failed to execute '" + member + "' on 'TrustedTypePolicy': Policy " +
                          (p ? p.name : '') + "'s TrustedTypePolicyOptions did not specify a '" + member + "' member.");
    }
    // The rule is called without `this`, like any IDL callback.
    return wrapped(C, rule.apply(undefined, arguments));
  };
  meth(TrustedTypePolicy.prototype, 'createHTML', creator('createHTML', TrustedHTML));
  meth(TrustedTypePolicy.prototype, 'createScript', creator('createScript', TrustedScript));
  meth(TrustedTypePolicy.prototype, 'createScriptURL', creator('createScriptURL', TrustedScriptURL));

  const TrustedTypePolicyFactory = iface('TrustedTypePolicyFactory');
  const TTF = TrustedTypePolicyFactory.prototype;
  const emptyHTML = wrapped(TrustedHTML, '');
  const emptyScript = wrapped(TrustedScript, '');
  let defaultPolicy = null;
  const createdNames = new Set();
  meth(TTF, 'createPolicy', function (name, rules) {
    const n = String(name);
    // `trusted-types a b default` directive: an unlisted name is refused, as
    // is a duplicate without 'allow-duplicates'; without the directive any
    // name goes, but a second 'default' is still refused.
    let names = null;
    try { names = typeof globalThis.__pt_ttNames === 'function' ? __pt_ttNames() : null; } catch (e) {}
    if (names) {
      const low = names.map((x) => __s_toLowerCase(x));
      if (!__s_includes(low, __s_toLowerCase(n)) && !__s_includes(low, '*')) throw __pt_mkErr(TypeError, "Failed to execute 'createPolicy' on 'TrustedTypePolicyFactory': Policy \"" + n + "\" disallowed.");
      if (createdNames.has(n) && !__s_includes(low, "'allow-duplicates'")) throw __pt_mkErr(TypeError, "Failed to execute 'createPolicy' on 'TrustedTypePolicyFactory': Policy with name \"" + n + "\" already exists.");
    } else if (n === 'default' && defaultPolicy) {
      throw __pt_mkErr(TypeError, "Failed to execute 'createPolicy' on 'TrustedTypePolicyFactory': Policy with name \"default\" already exists.");
    }
    createdNames.add(n);
    const p = Object.create(TrustedTypePolicy.prototype);
    POL.set(p, { name: n, rules: rules || {} });
    if (n === 'default') defaultPolicy = p;
    // Code gates open only now: without a policy no TrustedScript can exist,
    // and `eval` stays the real intrinsic with direct-call scoping. Pages that
    // don't use Trusted Types lose nothing.
    installTrustedSinks();
    return p;
  });
  defg(TTF, 'emptyHTML', function () { return emptyHTML; });
  defg(TTF, 'emptyScript', function () { return emptyScript; });
  defg(TTF, 'defaultPolicy', function () { return defaultPolicy; });
  // Sinks (dom_runtime) need the default policy and its rules.
  try { Object.defineProperty(globalThis, '__pt_ttDefault', { value: () => (defaultPolicy ? POL.get(defaultPolicy) : null), writable: true, enumerable: false, configurable: true }); } catch (e) {}
  // Where Chrome demands a trusted value — measured, not guessed.
  const ATTR = {
    'script:src': 'TrustedScriptURL', 'script:text': 'TrustedScript',
    'iframe:srcdoc': 'TrustedHTML', 'embed:src': 'TrustedScriptURL',
    'object:data': 'TrustedScriptURL', 'object:codebase': 'TrustedScriptURL',
  };
  const PROP = { 'script:src': 'TrustedScriptURL', 'script:text': 'TrustedScript',
                 'script:innerText': 'TrustedScript', 'script:textContent': 'TrustedScript',
                 'iframe:srcdoc': 'TrustedHTML', '*:innerHTML': 'TrustedHTML', '*:outerHTML': 'TrustedHTML' };
  meth(TTF, 'getAttributeType', function (tag, attr) {
    return ATTR[__s_toLowerCase(String(tag)) + ':' + __s_toLowerCase(String(attr))] || null;
  });
  meth(TTF, 'getPropertyType', function (tag, prop) {
    const t = __s_toLowerCase(String(tag)), p = String(prop);
    return PROP[t + ':' + p] || PROP['*:' + p] || null;
  });
  meth(TTF, 'getTypeMapping', function () { return {}; });
  meth(TTF, 'isHTML', function (v) { return v instanceof TrustedHTML; });
  meth(TTF, 'isScript', function (v) { return v instanceof TrustedScript; });
  meth(TTF, 'isScriptURL', function (v) { return v instanceof TrustedScriptURL; });
  try {
    Object.defineProperty(globalThis, 'trustedTypes', {
      value: Object.create(TTF), writable: true, enumerable: true, configurable: true,
    });
  } catch (e) {}

  // Trusted Types and eval: the browser executes `eval(trustedScript)`, a
  // bare engine does not; per spec PerformEval returns a non-string argument
  // untouched, silently. The Turnstile widget declares its XOR helper this
  // way: policy -> TrustedScript -> eval -> a global function.
  //
  // Known cost of a wrapper: `eval` stops being the intrinsic, so a direct
  // eval inside a function no longer sees its locals (it becomes indirect).
  // Our own page scripts run via `(0, eval)` anyway, and TrustedScript
  // behaviour matters more than this rare case.
  // ── navigator.* ──────────────────────────────────────────────────────────
  const nav = globalThis.navigator;
  if (nav) {
    const Storage_ = rebrand(nav.storage, 'StorageManager');
    if (Storage_) {
      if (typeof nav.storage.estimate !== 'function') {
        meth(Storage_.prototype, 'estimate', function () {
          return Promise.resolve({ quota: 10737418240, usage: 0, usageDetails: {} });
        });
      }
      meth(Storage_.prototype, 'persisted', function () { return Promise.resolve(false); });
      meth(Storage_.prototype, 'persist', function () { return Promise.resolve(false); });
      // Chrome always has OPFS in a secure context: a refusal is itself a
      // tell. Implementation shared with workers, see `OPFS_TEMPLATE`.
      if (typeof __ptOPFS === 'function') {
        meth(Storage_.prototype, 'getDirectory', function getDirectory() { return __ptOPFS(); });
      }
    }

    rebrand(nav.permissions, 'Permissions');
    rebrand(nav.connection, 'NetworkInformation', ET);
    rebrand(nav.ink, 'Ink');
    rebrand(nav.locks, 'LockManager');
    rebrand(nav.devicePosture, 'DevicePosture', ET);
    // Members live on the prototype: in Chrome these objects have no own properties.
    rebrand(nav.mediaDevices, 'MediaDevices', ET);
    rebrand(nav.userActivation, 'UserActivation');
    // Devices an empty profile lacks: the browser answers with empty lists and
    // rejections, not missing methods. Verified against Chrome 151.
    const USB_ = rebrand(nav.usb, 'USB', ET);
    if (USB_) {
      meth(USB_.prototype, 'getDevices', function getDevices() { return Promise.resolve([]); });
      meth(USB_.prototype, 'requestDevice', function requestDevice() { return Promise.reject(__pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'requestDevice' on 'USB': Must be handling a user gesture to show a permission request.", 'SecurityError')); });
    }
    const HID_ = rebrand(nav.hid, 'HID', ET);
    if (HID_) {
      meth(HID_.prototype, 'getDevices', function getDevices() { return Promise.resolve([]); });
      meth(HID_.prototype, 'requestDevice', function requestDevice() { return Promise.reject(__pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'requestDevice' on 'HID': Must be handling a user gesture to show a permission request.", 'SecurityError')); });
    }
    const Serial_ = rebrand(nav.serial, 'Serial', ET);
    if (Serial_) {
      meth(Serial_.prototype, 'getPorts', function getPorts() { return Promise.resolve([]); });
      meth(Serial_.prototype, 'requestPort', function requestPort() { return Promise.reject(__pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'requestPort' on 'Serial': Must be handling a user gesture to show a permission request.", 'SecurityError')); });
    }
    const XR_ = rebrand(nav.xr, 'XRSystem', ET);
    if (XR_) {
      meth(XR_.prototype, 'isSessionSupported', function isSessionSupported() { return Promise.resolve(false); });
      meth(XR_.prototype, 'requestSession', function requestSession() { return Promise.reject(__pt_mkErr(globalThis.DOMException || Error, 'The specified session configuration is not supported.', 'NotSupportedError')); });
    }
    const WL_ = rebrand(nav.wakeLock, 'WakeLock');
    if (WL_) {
      meth(WL_.prototype, 'request', function request(type) {
        const S = globalThis.WakeLockSentinel;
        const s = S && S.prototype ? Object.create(S.prototype) : {};
        __pt_write(s, 'type', type === undefined ? 'screen' : String(type));
        __pt_write(s, 'released', false);
        __pt_write(s, 'onrelease', null);
        return Promise.resolve(s);
      });
    }
    const Login_ = rebrand(nav.login, 'NavigatorLogin');
    if (Login_) meth(Login_.prototype, 'setStatus', function setStatus() { return Promise.resolve(undefined); });
    const Pres_ = rebrand(nav.presentation, 'Presentation');
    if (Pres_) {
      { const DR = new WeakMap();
        Object.defineProperty(Pres_.prototype, 'defaultRequest', { get: ({ get defaultRequest() { return DR.has(this) ? DR.get(this) : null; } }).__lookupGetter__('defaultRequest'),
          set: ({ set defaultRequest(v) { DR.set(this, v === undefined ? null : v); } }).__lookupSetter__('defaultRequest'), enumerable: true, configurable: true }); }
      defg(Pres_.prototype, 'receiver', function () { return null; });
    }
    if (nav.devicePosture) {
      try { const DP = Object.getPrototypeOf(nav.devicePosture); if (DP && DP !== Object.prototype) defg(DP, 'type', function () { return 'continuous'; }); } catch (e) {}
    }
    if (nav.ink && typeof nav.ink.requestPresenter !== 'function') {
      try { const IP = Object.getPrototypeOf(nav.ink); if (IP && IP !== Object.prototype) meth(IP, 'requestPresenter', function requestPresenter() {
        const D = globalThis.DelegatedInkTrailPresenter;
        const p = D && D.prototype ? Object.create(D.prototype) : {};
        __pt_write(p, 'presentationArea', null);
        return Promise.resolve(p);
      }); } catch (e) {}
    }
    try {
    // Sandboxed cross-site frame: Chrome refuses per permissions policy and
    // says why in words.
    const crossSite = () => !!globalThis.__pt_crossSite;
    // Override any kind of stub: remove first, then define.
    const setm = (o, k, f) => { try { const d = Object.getOwnPropertyDescriptor(o, k); if (d && d.configurable) delete o[k]; } catch (e) {} return meth(o, k, f); };
    const dx = (msg, name) => __pt_mkErr(globalThis.DOMException || Error, msg, name);
    const rejectDx = (msg, name) => Promise.reject(dx(msg, name));
    const policy = (feature, what, iface) => rejectDx("Failed to execute '" + what + "' on '" + iface + "': Access to the feature \"" + feature + "\" is disallowed by permissions policy.", 'SecurityError');
    setm(Object.getPrototypeOf(nav), 'getInstalledRelatedApps', function getInstalledRelatedApps() {
      if (crossSite()) return rejectDx("Failed to execute 'getInstalledRelatedApps' on 'Navigator': getInstalledRelatedApps() is only supported in top-level browsing contexts.", 'InvalidStateError');
      return Promise.resolve([]);
    });
    if (USB_) setm(USB_.prototype, 'getDevices', function getDevices() { return crossSite() ? policy('usb', 'getDevices', 'USB') : Promise.resolve([]); });
    if (HID_) setm(HID_.prototype, 'getDevices', function getDevices() { return crossSite() ? policy('hid', 'getDevices', 'HID') : Promise.resolve([]); });
    if (Serial_) setm(Serial_.prototype, 'getPorts', function getPorts() { return crossSite() ? policy('serial', 'getPorts', 'Serial') : Promise.resolve([]); });
    if (WL_) setm(WL_.prototype, 'request', function request(type) {
      if (crossSite()) return rejectDx("Failed to execute 'request' on 'WakeLock': Access to Screen Wake Lock features is disallowed by permissions policy", 'NotAllowedError');
      const S = globalThis.WakeLockSentinel;
      const s = S && S.prototype ? Object.create(S.prototype) : {};
      __pt_write(s, 'type', type === undefined ? 'screen' : String(type));
      __pt_write(s, 'released', false);
      __pt_write(s, 'onrelease', null);
      return Promise.resolve(s);
    });
    if (XR_) setm(XR_.prototype, 'requestSession', function requestSession(mode) {
      if (String(mode) === 'inline') {
        const XS = globalThis.XRSession;
        const ses = XS && XS.prototype ? Object.create(XS.prototype) : {};
        __pt_write(ses, 'visibilityState', 'visible'); __pt_write(ses, 'frameRate', undefined); __pt_write(ses, 'interactionMode', 'screen-space');
        return Promise.resolve(ses);
      }
      return rejectDx('The specified session configuration is not supported.', 'NotSupportedError');
    });
    const Clip_ = rebrand(nav.clipboard, 'Clipboard', ET);
    if (Clip_) {
      setm(Clip_.prototype, 'read', function read() { return rejectDx("Failed to execute 'read' on 'Clipboard': Read permission denied.", 'NotAllowedError'); });
      setm(Clip_.prototype, 'readText', function readText() { return rejectDx("Failed to execute 'readText' on 'Clipboard': Read permission denied.", 'NotAllowedError'); });
      setm(Clip_.prototype, 'write', function write() { return crossSite() ? rejectDx("Failed to execute 'write' on 'Clipboard': Write permission denied.", 'NotAllowedError') : Promise.resolve(undefined); });
      setm(Clip_.prototype, 'writeText', function writeText() { return crossSite() ? rejectDx("Failed to execute 'writeText' on 'Clipboard': Write permission denied.", 'NotAllowedError') : Promise.resolve(undefined); });
    }
    const Cred_ = rebrand(nav.credentials, 'CredentialsContainer');
    if (Cred_) {
      setm(Cred_.prototype, 'get', function get(opts) {
        const o = opts || {};
        if (o.publicKey) return crossSite()
          ? rejectDx("The 'publickey-credentials-get' feature is not enabled in this document.", 'NotAllowedError')
          : rejectDx('The operation either timed out or was not allowed. See: https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client.', 'NotAllowedError');
        if (o.digital) return crossSite()
          ? rejectDx("The 'digital-credentials-get' feature is not enabled in this document.", 'NotAllowedError')
          : rejectDx("Failed to execute 'get' on 'CredentialsContainer': Digital credentials API requires user activation.", 'NotAllowedError');
        if (o.identity) return crossSite()
          ? rejectDx("The 'identity-credentials-get' feature is not enabled in this document.", 'NotAllowedError')
          : rejectDx('Error retrieving a token.', 'NetworkError');
        if (crossSite()) return rejectDx("The following credential operations can only occur in a document which is same-origin with all of its ancestors: storage/retrieval of 'PasswordCredential' and 'FederatedCredential', storage of 'PublicKeyCredential'.", 'NotAllowedError');
        return Promise.resolve(null);
      });
      setm(Cred_.prototype, 'create', function create(opts) {
        const o = opts || {};
        if (o.password) {
          const PC = globalThis.PasswordCredential;
          const c = PC && PC.prototype ? Object.create(PC.prototype) : {};
          const pw = o.password;
          __pt_write(c, 'id', String(pw.id === undefined ? '' : pw.id)); __pt_write(c, 'type', 'password'); __pt_write(c, 'name', String(pw.name || '')); __pt_write(c, 'iconURL', String(pw.iconURL || '')); __pt_write(c, 'password', String(pw.password === undefined ? '' : pw.password));
          return Promise.resolve(c);
        }
        if (o.publicKey) return rejectDx(crossSite() ? "The 'publickey-credentials-create' feature is not enabled in this document." : 'The operation either timed out or was not allowed. See: https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client.', 'NotAllowedError');
        return Promise.resolve(null);
      });
      setm(Cred_.prototype, 'store', function store() { return Promise.resolve(undefined); });
      setm(Cred_.prototype, 'preventSilentAccess', function preventSilentAccess() { return Promise.resolve(undefined); });
    }
    const Geo_ = rebrand(nav.geolocation, 'Geolocation');
    if (Geo_) {
      const posErr = (code, message) => { const E = globalThis.GeolocationPositionError; const e = E && E.prototype ? Object.create(E.prototype) : {}; __pt_write(e, 'code', code); __pt_write(e, 'message', message); return e; };
      const deny = (err) => (crossSite() ? posErr(1, 'Geolocation has been disabled in this document by permissions policy.') : posErr(1, 'User denied Geolocation'));
      setm(Geo_.prototype, 'getCurrentPosition', function getCurrentPosition(ok, err) { if (typeof err === 'function') setTimeout(() => { try { err(deny()); } catch (e) {} }, 0); });
      setm(Geo_.prototype, 'watchPosition', function watchPosition(ok, err) { if (typeof err === 'function') setTimeout(() => { try { err(deny()); } catch (e) {} }, 0); return 1; });
      setm(Geo_.prototype, 'clearWatch', function clearWatch() {});
    }
    setm(Object.getPrototypeOf(nav), 'requestMIDIAccess', function requestMIDIAccess() {
      return crossSite() ? rejectDx("Failed to execute 'requestMIDIAccess' on 'Navigator': Midi has been disabled in this document by permissions policy.", 'SecurityError')
        : rejectDx("Failed to execute 'requestMIDIAccess' on 'Navigator': Midi permission request denied.", 'SecurityError');
    });
    const protoOf = (o, name, base) => { if (!o) return null; let P = Object.getPrototypeOf(o); if (P === Object.prototype) { const C = rebrand(o, name, base); P = C && C.prototype; } return P && P !== Object.prototype ? P : null; };
    const KB = protoOf(nav.keyboard, 'Keyboard');
    if (KB) { try { setm(KB, 'lock', function lock() { return crossSite() ? rejectDx("Failed to execute 'lock' on 'Keyboard': lock() must be called from a primary top-level browsing context.", 'InvalidStateError') : Promise.resolve(undefined); }); } catch (e) {}
    }
    const SWP = protoOf(nav.serviceWorker, 'ServiceWorkerContainer', ET);
    if (SWP) { try { try { delete SWP.ready; } catch (e) {} defg(SWP, 'ready', function () { return new Promise(() => {}); }); } catch (e) {} }
    try { setm(globalThis, 'getScreenDetails', function getScreenDetails() { return rejectDx('Permission denied.', 'NotAllowedError'); }); } catch (e) {}
    try { setm(globalThis, 'queryLocalFonts', function queryLocalFonts() { return crossSite() ? policy('local-fonts', 'queryLocalFonts', 'Window') : Promise.resolve([]); }); } catch (e) {}
    for (const pk of ['showOpenFilePicker', 'showSaveFilePicker', 'showDirectoryPicker']) {
      try { setm(globalThis, pk, function () { return crossSite() ? rejectDx("Failed to execute '" + pk + "' on 'Window': Cross origin sub frames aren't allowed to show a file picker.", 'SecurityError') : rejectDx("Failed to execute '" + pk + "' on 'Window': Must be handling a user gesture to show a file picker.", 'SecurityError'); }); try { Object.defineProperty(globalThis[pk], 'name', { value: pk, configurable: true }); } catch (e) {} } catch (e) {}
    }
    try {
      const DP = globalThis.Document && Document.prototype;
      if (DP) {
        setm(DP, 'exitPictureInPicture', function exitPictureInPicture() { return rejectDx("Failed to execute 'exitPictureInPicture' on 'Document': There is no Picture-in-Picture element in this document.", 'InvalidStateError'); });
        setm(DP, 'requestStorageAccess', function requestStorageAccess() { return crossSite() ? rejectDx('requestStorageAccess not allowed', 'NotAllowedError') : Promise.resolve(undefined); });
        setm(DP, 'requestStorageAccessFor', function requestStorageAccessFor() { return crossSite() ? rejectDx('requestStorageAccessFor not allowed', 'NotAllowedError') : Promise.resolve(undefined); });
      }
      const EP = globalThis.Element && Element.prototype;
      if (EP) {
        setm(EP, 'requestFullscreen', function requestFullscreen() { return Promise.reject(__pt_mkErr(TypeError, 'Permissions check failed')); });
        setm(EP, 'requestPointerLock', function requestPointerLock() { if (crossSite()) return rejectDx("Failed to execute 'requestPointerLock' on 'Element': Blocked pointer lock on an element because the element's frame is sandboxed and the 'allow-pointer-lock' permission is not set.", 'SecurityError'); return Promise.resolve(undefined); });
      }
    } catch (e) {}
    // Constructors Chrome refuses in a cross-site frame before doing anything.
    const guardCtor = (name, msg, kind) => {
      try {
        const C = globalThis[name]; if (typeof C !== 'function') return;
        const G = function () { if (crossSite()) throw dx(msg, kind); return Reflect.construct(C, arguments, new.target || G); };
        G.prototype = C.prototype; Object.defineProperty(G, 'name', { value: name, configurable: true }); Object.defineProperty(G, 'length', { value: C.length, configurable: true });
        for (const k of Object.getOwnPropertyNames(C)) { if (__s_indexOf(['length', 'name', 'prototype'], k) >= 0) continue; try { Object.defineProperty(G, k, Object.getOwnPropertyDescriptor(C, k)); } catch (e) {} }
        try { Object.defineProperty(C.prototype, 'constructor', { value: G, writable: true, configurable: true }); } catch (e) {}
        Object.defineProperty(globalThis, name, { value: native(G), writable: true, enumerable: false, configurable: true });
      } catch (e) {}
    };
    guardCtor('PaymentRequest', "Failed to construct 'PaymentRequest': Must be in a top-level browsing context or an iframe needs to specify allow=\"payment\" explicitly", 'SecurityError');
    guardCtor('PresentationRequest', "Failed to construct 'PresentationRequest': The document is sandboxed and lacks the 'allow-presentation' flag.", 'SecurityError');
    for (const sn of ['Accelerometer', 'Gyroscope', 'Magnetometer', 'LinearAccelerationSensor', 'GravitySensor', 'AbsoluteOrientationSensor', 'RelativeOrientationSensor']) guardCtor(sn, "Failed to construct '" + sn + "': Access to sensor features is disallowed by permissions policy", 'SecurityError');
    try {
      const ID = globalThis.IdleDetector;
      if (typeof ID === 'function') {
        Object.defineProperty(ID, 'requestPermission', { value: native(function requestPermission() { return rejectDx("Failed to execute 'requestPermission' on 'IdleDetector': Must be handling a user gesture to show a permission request.", 'NotAllowedError'); }), writable: true, enumerable: true, configurable: true });
        setm(ID.prototype, 'start', function start() { return crossSite() ? policy('idle-detection', 'start', 'IdleDetector') : rejectDx("Failed to execute 'start' on 'IdleDetector': Idle detection permission not granted", 'NotAllowedError'); });
      }
    } catch (e) {}
    try {
      const SO = globalThis.screen && globalThis.screen.orientation && protoOf(globalThis.screen.orientation, 'ScreenOrientation', ET);
      if (SO) setm(SO, 'lock', function lock() { return crossSite() ? rejectDx("Failed to execute 'lock' on 'ScreenOrientation': The window is sandboxed and lacks the 'allow-orientation-lock' flag.", 'SecurityError') : rejectDx('screen.orientation.lock() is not available on this device.', 'NotSupportedError'); });
    } catch (e) {}
    if (globalThis.cookieStore) { try { const CS = protoOf(globalThis.cookieStore, 'CookieStore', ET); if (CS) { setm(CS, 'getAll', function getAll() { return Promise.resolve([]); }); setm(CS, 'get', function get() { return Promise.resolve(null); }); setm(CS, 'set', function set() { return Promise.resolve(undefined); }); setm(CS, 'delete', function () { return Promise.resolve(undefined); }); } } catch (e) {} }
    } catch (e) { try { console.error('[policy block] ' + (e && e.stack)); } catch (x) {} }
    // Scheduler: `postTask` resolves with the task's result, `yield` with nothing.
    if (globalThis.scheduler) {
      try {
        let SP = Object.getPrototypeOf(globalThis.scheduler);
        if (SP === Object.prototype) SP = globalThis.scheduler;
        meth(SP, 'postTask', function postTask(cb, opts) {
          const delay = opts && Number(opts.delay) > 0 ? Number(opts.delay) : 0;
          return new Promise((res, rej) => { setTimeout(() => { try { res(cb()); } catch (e) { rej(e); } }, delay); });
        });
        meth(SP, 'yield', function () { return new Promise((r) => setTimeout(r, 0)); });
        try { Object.defineProperty(SP.yield, 'name', { value: 'yield', configurable: true }); } catch (e) {}
      } catch (e) {}
    }

    const MC = rebrand(nav.mediaCapabilities, 'MediaCapabilities');
    if (MC) {
      // Chrome answers this for any supported profile; checked live.
      meth(MC.prototype, 'decodingInfo', function () {
        return Promise.resolve({ supported: true, smooth: true, powerEfficient: true, keySystemAccess: null });
      });
      meth(MC.prototype, 'encodingInfo', function () {
        return Promise.resolve({ supported: true, smooth: true, powerEfficient: true });
      });
    }

    const KB = rebrand(nav.keyboard, 'Keyboard');
    if (KB) {
      const LAYOUT = [["KeyK","k"],["KeyG","g"],["Digit2","2"],["Digit0","0"],["KeyV","v"],["KeyA","a"],["Backquote","`"],["KeyL","l"],["IntlBackslash","<"],["Quote","'"],["KeyW","w"],["Digit8","8"],["KeyM","m"],["KeyH","h"],["Period","."],["Digit7","7"],["Digit1","1"],["KeyP","p"],["KeyD","d"],["KeyF","f"],["KeyO","o"],["KeyQ","q"],["KeyC","c"],["KeyN","n"],["BracketLeft","["],["KeyZ","z"],["KeyY","y"],["Digit3","3"],["Digit6","6"],["Digit5","5"],["KeyX","x"],["Slash","/"],["Backslash","\\"],["Comma",","],["Minus","-"],["Digit4","4"],["KeyB","b"],["KeyT","t"],["Digit9","9"],["KeyS","s"],["KeyI","i"],["KeyU","u"],["Equal","="],["KeyJ","j"],["Semicolon",";"],["KeyR","r"],["BracketRight","]"],["KeyE","e"]];
      const KLM = iface('KeyboardLayoutMap');
      const MAP = new WeakMap();
      defg(KLM.prototype, 'size', function () { return MAP.get(this).size; });
      meth(KLM.prototype, 'get', function (k) { return MAP.get(this).get(String(k)); });
      meth(KLM.prototype, 'has', function (k) { return MAP.get(this).has(String(k)); });
      meth(KLM.prototype, 'keys', function () { return MAP.get(this).keys(); });
      meth(KLM.prototype, 'values', function () { return MAP.get(this).values(); });
      meth(KLM.prototype, 'entries', function () { return MAP.get(this).entries(); });
      meth(KLM.prototype, 'forEach', function (f, t) { return MAP.get(this).forEach(f, t); });
      try {
        Object.defineProperty(KLM.prototype, Symbol.iterator, {
          value: fn('[Symbol.iterator]', function () { return MAP.get(this).entries(); }),
          writable: true, configurable: true,
        });
      } catch (e) {}
      meth(KB.prototype, 'getLayoutMap', function () {
        const m = Object.create(KLM.prototype);
        MAP.set(m, new Map(LAYOUT));
        return Promise.resolve(m);
      });
      meth(KB.prototype, 'lock', function () { return Promise.resolve(); });
      meth(KB.prototype, 'unlock', function () {});
    }

    const UA = nav.userAgentData;
    if (UA) {
      // Values already exist (set by the fingerprint layer): take them before rebranding.
      const brands = UA.brands, mobile = UA.mobile, platform = UA.platform;
      const HIGH = {"architecture":"x86","bitness":"64","formFactors":["Desktop"],"fullVersionList":[{"brand":"Not=A?Brand","version":"99.0.0.0"},{"brand":"Google Chrome","version":"__CHROME_FULL__"},{"brand":"Chromium","version":"__CHROME_FULL__"}],"model":"","platformVersion":"","uaFullVersion":"__CHROME_FULL__","wow64":false};
      const UAD = rebrand(UA, 'NavigatorUAData');
      meth(UAD.prototype, 'toJSON', function () { return { brands: brands, mobile: mobile, platform: platform }; });
      meth(UAD.prototype, 'getHighEntropyValues', function (hints) {
        // The browser's key order is alphabetical, visible via `JSON.stringify`.
        const all = { brands: brands, mobile: mobile, platform: platform };
        for (const h of (hints || [])) if (Object.prototype.hasOwnProperty.call(HIGH, h)) all[h] = HIGH[h];
        const out = {};
        for (const k of Object.keys(all).sort()) out[k] = all[k];
        return Promise.resolve(out);
      });
    }

    // ── WebGPU ─────────────────────────────────────────────────────────────
    const GPU_ = rebrand(nav.gpu, 'GPU');
    if (GPU_) {
      const LIMITS = {"maxTextureDimension1D": 16384, "maxTextureDimension2D": 16384, "maxTextureDimension3D": 2048, "maxTextureArrayLayers": 2048, "maxBindGroups": 4, "maxBindGroupsPlusVertexBuffers": 24, "maxBindingsPerBindGroup": 1000, "maxDynamicUniformBuffersPerPipelineLayout": 8, "maxDynamicStorageBuffersPerPipelineLayout": 4, "maxSampledTexturesPerShaderStage": 16, "maxSamplersPerShaderStage": 16, "maxStorageBuffersPerShaderStage": 16, "maxStorageTexturesPerShaderStage": 4, "maxUniformBuffersPerShaderStage": 12, "maxUniformBufferBindingSize": 65536, "maxStorageBufferBindingSize": 1073741824, "minUniformBufferOffsetAlignment": 256, "minStorageBufferOffsetAlignment": 256, "maxVertexBuffers": 8, "maxBufferSize": 1073741824, "maxVertexAttributes": 16, "maxVertexBufferArrayStride": 2048, "maxInterStageShaderVariables": 16, "maxColorAttachments": 8, "maxColorAttachmentBytesPerSample": 128, "maxComputeWorkgroupStorageSize": 65536, "maxComputeInvocationsPerWorkgroup": 1024, "maxComputeWorkgroupSizeX": 1024, "maxComputeWorkgroupSizeY": 1024, "maxComputeWorkgroupSizeZ": 64, "maxComputeWorkgroupsPerDimension": 65535, "maxImmediateSize": 64, "maxStorageBuffersInFragmentStage": 16, "maxStorageTexturesInFragmentStage": 4, "maxStorageBuffersInVertexStage": 16, "maxStorageTexturesInVertexStage": 4};
      // A device without requiredLimits/requiredFeatures gets default limits
      // and only core-features-and-limits, not the adapter's.
      const DEV_LIMITS = {"maxTextureDimension1D": 8192, "maxTextureDimension2D": 8192, "maxTextureDimension3D": 2048, "maxTextureArrayLayers": 256, "maxBindGroups": 4, "maxBindGroupsPlusVertexBuffers": 24, "maxBindingsPerBindGroup": 1000, "maxDynamicUniformBuffersPerPipelineLayout": 8, "maxDynamicStorageBuffersPerPipelineLayout": 4, "maxSampledTexturesPerShaderStage": 16, "maxSamplersPerShaderStage": 16, "maxStorageBuffersPerShaderStage": 8, "maxStorageTexturesPerShaderStage": 4, "maxUniformBuffersPerShaderStage": 12, "maxUniformBufferBindingSize": 65536, "maxStorageBufferBindingSize": 134217728, "minUniformBufferOffsetAlignment": 256, "minStorageBufferOffsetAlignment": 256, "maxVertexBuffers": 8, "maxBufferSize": 268435456, "maxVertexAttributes": 16, "maxVertexBufferArrayStride": 2048, "maxInterStageShaderVariables": 16, "maxColorAttachments": 8, "maxColorAttachmentBytesPerSample": 32, "maxComputeWorkgroupStorageSize": 16384, "maxComputeInvocationsPerWorkgroup": 256, "maxComputeWorkgroupSizeX": 256, "maxComputeWorkgroupSizeY": 256, "maxComputeWorkgroupSizeZ": 64, "maxComputeWorkgroupsPerDimension": 65535, "maxImmediateSize": 64, "maxStorageBuffersInFragmentStage": 8, "maxStorageTexturesInFragmentStage": 4, "maxStorageBuffersInVertexStage": 8, "maxStorageTexturesInVertexStage": 4};
      const FEATURES = ["depth32float-stencil8", "rg11b10ufloat-renderable", "bgra8unorm-storage", "texture-formats-tier1", "texture-compression-bc", "dual-source-blending", "core-features-and-limits", "float32-filterable", "indirect-first-instance", "texture-compression-astc-sliced-3d", "float32-blendable", "texture-compression-astc", "texture-compression-etc2", "depth-clip-control", "texture-compression-bc-sliced-3d", "texture-formats-tier2", "clip-distances", "shader-f16", "timestamp-query", "primitive-index", "texture-component-swizzle", "subgroups"];
      const INFO = {"vendor":"intel","architecture":"gen-12lp","device":"","description":"","subgroupMinSize":8,"subgroupMaxSize":32,"isFallbackAdapter":false};
      const WGSL = ["packed_4x8_integer_dot_product", "subgroup_uniformity", "immediate_address_space", "subgroup_id", "linear_indexing", "readonly_and_readwrite_storage_textures", "unrestricted_pointer_parameters", "texture_and_sampler_let", "pointer_composite_access", "uniform_buffer_standard_layout"];

      // setlike interface: Chrome returns these this way, not as an array.
      const setlike = (name) => {
        const C = iface(name);
        const S = new WeakMap();
        defg(C.prototype, 'size', function () { return S.get(this).size; });
        meth(C.prototype, 'has', function (k) { return S.get(this).has(String(k)); });
        meth(C.prototype, 'keys', function () { return S.get(this).keys(); });
        meth(C.prototype, 'values', function () { return S.get(this).values(); });
        meth(C.prototype, 'entries', function () { return S.get(this).entries(); });
        meth(C.prototype, 'forEach', function (f, t) { return S.get(this).forEach(f, t); });
        try {
          Object.defineProperty(C.prototype, Symbol.iterator, {
            value: fn('[Symbol.iterator]', function () { return S.get(this).values(); }),
            writable: true, configurable: true,
          });
        } catch (e) {}
        return (items) => { const o = Object.create(C.prototype); S.set(o, new Set(items)); return o; };
      };
      const mkFeatures = setlike('GPUSupportedFeatures');
      const mkWgsl = setlike('WGSLLanguageFeatures');

      const GPUSupportedLimits = iface('GPUSupportedLimits');
      const LIMVALS = new WeakMap();
      for (const k of Object.keys(LIMITS)) {
        const v = LIMITS[k];
        defg(GPUSupportedLimits.prototype, k, function () { const m = LIMVALS.get(this); return m ? m[k] : v; });
      }
      const mkLimits = (vals) => { const o = Object.create(GPUSupportedLimits.prototype); LIMVALS.set(o, vals); return o; };
      const GPUAdapterInfo = iface('GPUAdapterInfo');
      for (const k of Object.keys(INFO)) {
        const v = INFO[k];
        defg(GPUAdapterInfo.prototype, k, function () { return v; });
      }
      const GPUQueue = iface('GPUQueue');
      const GPUDevice = iface('GPUDevice', ET);
      const GPUAdapter = iface('GPUAdapter');

      const limits = mkLimits(LIMITS);
      const devLimits = mkLimits(DEV_LIMITS);
      const info = Object.create(GPUAdapterInfo.prototype);
      const features = mkFeatures(FEATURES);
      const devFeatures = mkFeatures(['core-features-and-limits']);
      defg(GPUAdapter.prototype, 'features', function () { return features; });
      defg(GPUAdapter.prototype, 'limits', function () { return limits; });
      defg(GPUAdapter.prototype, 'info', function () { return info; });
      defg(GPUDevice.prototype, 'features', function () { return devFeatures; });
      defg(GPUDevice.prototype, 'limits', function () { return devLimits; });
      defg(GPUDevice.prototype, 'adapterInfo', function () { return info; });
      defg(GPUDevice.prototype, 'label', function () { return ''; });
      // A live device never resolves its `lost`.
      const lost = new Promise(() => {});
      defg(GPUDevice.prototype, 'lost', function () { return lost; });
      defg(GPUDevice.prototype, 'queue', function () { return Object.create(GPUQueue.prototype); });
      meth(GPUDevice.prototype, 'destroy', function () {});
      meth(GPUAdapter.prototype, 'requestDevice', function () {
        return Promise.resolve(Object.create(GPUDevice.prototype));
      });
      const adapter = Object.create(GPUAdapter.prototype);
      meth(GPU_.prototype, 'requestAdapter', function (opts) {
        // No software fallback adapter on this machine, same as Chrome.
        if (opts && opts.forceFallbackAdapter) return Promise.resolve(null);
        return Promise.resolve(adapter);
      });
      meth(GPU_.prototype, 'getPreferredCanvasFormat', function () { return 'rgba8unorm'; });
      const wgsl = mkWgsl(WGSL);
      defg(GPU_.prototype, 'wgslLanguageFeatures', function () { return wgsl; });
    }
  }

  if (globalThis.screen) {
    // Already rebranded earlier (frame rules block): a second rebrand lost
    // angle and type, whose getters stayed on the old prototype.
    const so = screen.orientation, sp = so && Object.getPrototypeOf(so);
    const SO = (sp && sp !== Object.prototype && typeof sp.constructor === 'function' && sp.constructor.name === 'ScreenOrientation')
      ? sp.constructor : rebrand(so, 'ScreenOrientation', ET);
    // `onchange` is an event handler: null, read-write.
    if (SO && !Object.getOwnPropertyDescriptor(SO.prototype, 'onchange')) {
      const cell = new WeakMap();
      Object.defineProperty(SO.prototype, 'onchange', {
        get: fn('get onchange', function () { return cell.has(this) ? cell.get(this) : null; }),
        set: fn('set onchange', function (v) { cell.set(this, typeof v === 'function' ? v : null); }),
        enumerable: true, configurable: true,
      });
    }
  }

  // Everything on window before the first page script is the browser's and
  // `toString` must say [native code]. Interfaces declared before the masking
  // mechanism itself (XHR and its layers, Storage) would otherwise read as
  // page functions.
  for (const name of Object.getOwnPropertyNames(globalThis)) {
    if (__s_lastIndexOf(name, '__pt', 0) === 0) continue;
    let v;
    try { v = globalThis[name]; } catch (e) { continue; }
    if (typeof v === 'function') native(v);
  }

  // Second interface shape pass: Storage, SpeechSynthesis and audio are
  // declared after the DOM layer and missing the first time.
  try { if (globalThis.__pt_fillShapes) __pt_fillShapes(); } catch (e) {}
  // `for...in` over a style yields nine prototype names in declaration order,
  // and Chrome's order differs. The shape filler groups members by kind
  // (length first, then methods), so rebuild in browser order here.
  try {
    const P = globalThis.CSSStyleDeclaration && globalThis.CSSStyleDeclaration.prototype;
    if (P) {
      const order = ['cssText', 'length', 'parentRule', 'cssFloat', 'getPropertyPriority',
        'getPropertyValue', 'item', 'removeProperty', 'setProperty'];
      const saved = [];
      for (const k of order) {
        const d = Object.getOwnPropertyDescriptor(P, k);
        if (d && d.configurable) saved.push([k, d]);
      }
      for (const [k] of saved) delete P[k];
      for (const [k, d] of saved) Object.defineProperty(P, k, d);
    }
  } catch (e) {}

  // `document.fonts` is a FontFaceSet. `fonts.check('12px "Some Font"')` is a
  // common font fingerprinting method. The browser returns true for any
  // family (a fallback always exists) and throws SyntaxError on a string that
  // does not parse as a font.
  if (globalThis.document) {
    // Chrome does not expose the FontFaceSet name on window: the interface exists, the global does not.
    const FFS = rebrand(document.fonts, 'FontFaceSet', ET, true);
    if (FFS) {
      const P = FFS.prototype;
      // A real set: the page adds `FontFace`s, reads `size`, iterates and
      // awaits `load`.
      const faces = new Set();
      let pending = 0;
      defg(P, 'size', function () { return faces.size; });
      defg(P, 'status', function () { return pending > 0 ? 'loading' : 'loaded'; });
      const ready = Promise.resolve(document.fonts);
      defg(P, 'ready', function () { return ready; });
      for (const on of ['onloading', 'onloadingdone', 'onloadingerror']) {
        try { Object.defineProperty(P, on, { value: null, writable: true, enumerable: true, configurable: true }); } catch (e) {}
      }
      // Shorthand parse: without a size and family it is not a font.
      const parses = (font) => /(^|\s)(\d+(\.\d+)?(px|pt|em|rem|%)|x?x-(small|large)|small|medium|large|larger|smaller)(\s|\/)/.test(' ' + String(font) + ' ');
      meth(P, 'check', function (font) {
        if (!parses(font)) {
          throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'check' on 'FontFaceSet': Could not resolve '" + font + "' as a font.", 'SyntaxError');
        }
        return true;
      });
      // Family from a shorthand: `12px "Name", serif` gives "Name".
      const familyOf = (font) => {
        const t = String(font);
        const m = /(?:\d+(?:\.\d+)?(?:px|pt|em|rem|%)|x?x-(?:small|large)|small|medium|large|larger|smaller)\s+(.+)$/.exec(t);
        if (!m) return '';
        const first = __s_trim(__s_split(m[1], ',')[0]);
        return __s_replace(first, /^["']|["']$/g, '');
      };
      meth(P, 'load', function (font) {
        if (!parses(font)) {
          return Promise.reject(__pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'load' on 'FontFaceSet': Could not resolve '" + font + "' as a font.", 'SyntaxError'));
        }
        const want = familyOf(font);
        const mine = [...faces].filter((f) => {
          try { return String(f.family) === want; } catch (e) { return false; }
        });
        pending++;
        const done = () => { pending = Math.max(0, pending - 1); };
        return Promise.all(mine.map((f) => {
          try { return f.load().then(() => f, () => null); } catch (e) { return Promise.resolve(null); }
        })).then((list) => {
          setTimeout(done, 0);
          return list.filter(Boolean);
        }, (e) => { setTimeout(done, 0); throw e; });
      });
      meth(P, 'add', function (face) { if (face) faces.add(face); return this; });
      meth(P, 'delete', function (face) { return faces.delete(face); });
      meth(P, 'clear', function () { faces.clear(); });
      meth(P, 'has', function (face) { return faces.has(face); });
      meth(P, 'forEach', function (f, t) { faces.forEach(f, t); });
      meth(P, 'keys', function () { return faces.keys(); });
      meth(P, 'values', function () { return faces.values(); });
      meth(P, 'entries', function () { return faces.entries(); });
      try {
        Object.defineProperty(P, Symbol.iterator, {
          value: fn('[Symbol.iterator]', function () { return faces.values(); }),
          writable: true, configurable: true,
        });
      } catch (e) {}
    }
  }

  // `navigator.locks` is a LockManager: `request` takes the lock and calls back.
  if (globalThis.navigator && navigator.locks) {
    const LM = rebrand(navigator.locks, 'LockManager');
    if (LM) {
      meth(LM.prototype, 'request', function (name, optionsOrCb, maybeCb) {
        const cb = typeof optionsOrCb === 'function' ? optionsOrCb : maybeCb;
        const lock = { name: String(name), mode: 'exclusive' };
        try { return Promise.resolve(typeof cb === 'function' ? cb(lock) : undefined); }
        catch (e) { return Promise.reject(e); }
      });
      meth(LM.prototype, 'query', function () {
        return Promise.resolve({ held: [], pending: [] });
      });
    }
  }

  // `caches` must be a real interface answering with promises (the
  // collector's worker calls `caches.keys()`), even without real storage.
  const CS = rebrand(globalThis.caches, 'CacheStorage');
  if (CS) {
    const CacheIface = iface('Cache');
    const emptyCache = () => {
      const c = Object.create(CacheIface.prototype);
      return c;
    };
    for (const m of ['add', 'addAll', 'put', 'delete']) meth(CacheIface.prototype, m, function () { return Promise.resolve(m === 'delete' ? false : undefined); });
    meth(CacheIface.prototype, 'match', function () { return Promise.resolve(undefined); });
    meth(CacheIface.prototype, 'matchAll', function () { return Promise.resolve([]); });
    meth(CacheIface.prototype, 'keys', function () { return Promise.resolve([]); });
    meth(CS.prototype, 'open', function () { return Promise.resolve(emptyCache()); });
    meth(CS.prototype, 'has', function () { return Promise.resolve(false); });
    meth(CS.prototype, 'delete', function () { return Promise.resolve(false); });
    meth(CS.prototype, 'keys', function () { return Promise.resolve([]); });
    meth(CS.prototype, 'match', function () { return Promise.resolve(undefined); });
  }

  // Name-table placeholders are empty objects tagging as `[object Object]`
  // where the browser names itself: `visualViewport`, six `BarProp`s,
  // `customElements`, `indexedDB`, `cookieStore`... 31 of them, found by
  // comparison with Chrome 148. Fingerprinters call
  // `Object.prototype.toString` across the whole window.
  //
  // The table already created their constructors, so moving each object onto
  // the right prototype is enough; it also fixes `instanceof` and `constructor`.
  const BRANDED = {
    locationbar: 'BarProp', menubar: 'BarProp', personalbar: 'BarProp',
    scrollbars: 'BarProp', statusbar: 'BarProp', toolbar: 'BarProp',
    visualViewport: 'VisualViewport', navigation: 'Navigation', external: 'External',
    scheduler: 'Scheduler', customElements: 'CustomElementRegistry',
    indexedDB: 'IDBFactory', cookieStore: 'CookieStore', sharedStorage: 'SharedStorage',
    crashReport: 'CrashReportContext', documentPictureInPicture: 'DocumentPictureInPicture',
    viewport: 'Viewport', launchQueue: 'LaunchQueue',
  };
  // One interface per name: Chrome's six window bars share one prototype,
  // as `Object.getPrototypeOf(locationbar) === Object.getPrototypeOf(toolbar)`
  // shows.
  const made = new Map();
  for (const [prop, name] of Object.entries(BRANDED)) {
    try {
      const v = globalThis[prop];
      if (!v || typeof v !== 'object') continue;
      // Name-table dummies move onto the real interface. An object with its
      // own prototype keeps its methods there, so it is tagged in place;
      // otherwise `customElements` would lose `define` and `get`.
      const proto = Object.getPrototypeOf(v);
      if (proto && proto !== Object.prototype) {
        try { Object.defineProperty(proto, Symbol.toStringTag, { value: name, configurable: true }); } catch (e) {}
        const C = proto.constructor;
        if (typeof C === 'function') {
          try { Object.defineProperty(C, 'name', { value: name, configurable: true }); } catch (e) {}
        }
        continue;
      }
      const done = made.get(name);
      // Declare the interface openly: the name table put an untagged empty
      // function there, and `instanceof`/`constructor` must match the
      // prototype the object is about to move to.
      if (done) Object.setPrototypeOf(v, done.prototype);
      else made.set(name, rebrand(v, name, name === 'VisualViewport' ? ET : undefined));
    } catch (e) {}
  }
  // Prototype name order is read too: Chrome has members first and
  // `constructor` last, while a fresh interface has it first.
  const constructorLast = (proto) => {
    try {
      const d = Object.getOwnPropertyDescriptor(proto, 'constructor');
      if (!d) return;
      delete proto.constructor;
      Object.defineProperty(proto, 'constructor', d);
    } catch (e) {}
  };
  // A window bar reports whether it is visible; in a normal window all are.
  try {
    const BP = made.get('BarProp').prototype;
    defg(BP, 'visible', function () { return true; });
    constructorLast(BP);
  } catch (e) {}
  // Visual viewport: same as `innerWidth`/`innerHeight`, no offset or scale.
  // Window measurements read it first.
  try {
    const VV = made.get('VisualViewport').prototype;
    defg(VV, 'offsetLeft', function () { return 0; });
    defg(VV, 'offsetTop', function () { return 0; });
    defg(VV, 'pageLeft', function () { return globalThis.scrollX || 0; });
    defg(VV, 'pageTop', function () { return globalThis.scrollY || 0; });
    defg(VV, 'width', function () { return globalThis.innerWidth; });
    defg(VV, 'height', function () { return globalThis.innerHeight; });
    defg(VV, 'scale', function () { return 1; });
    for (const on of ['onresize', 'onscroll', 'onscrollend']) {
      Object.defineProperty(VV, on, { value: null, writable: true, enumerable: true, configurable: true });
    }
    constructorLast(VV);
  } catch (e) {}
  // Namespaces differ: no constructor, the object itself carries the name.
  // `StyleMedia` is the same kind: Chrome does not expose its constructor,
  // yet the object tags as `[object StyleMedia]`.
  const TAGGED = {
    Intl: 'Intl', CSS: 'CSS', Temporal: 'Temporal', styleMedia: 'StyleMedia',
    GPUBufferUsage: 'GPUBufferUsage', GPUColorWrite: 'GPUColorWrite', GPUMapMode: 'GPUMapMode',
    GPUShaderStage: 'GPUShaderStage', GPUTextureUsage: 'GPUTextureUsage',
  };
  for (const [prop, tag] of Object.entries(TAGGED)) {
    try {
      const v = globalThis[prop];
      if (v && typeof v === 'object') {
        Object.defineProperty(v, Symbol.toStringTag, { value: tag, configurable: true });
      }
    } catch (e) {}
  }
  // `clientInformation` is the navigator itself, not a copy: an equality
  // check shows it.
  try {
    if (globalThis.navigator) {
      Object.defineProperty(globalThis, 'clientInformation', {
        get: native(function clientInformation() { return navigator; }),
        enumerable: true, configurable: true,
      });
    }
  } catch (e) {}
  const brandInPlace = (v, name, base) => {
    if (!v || typeof v !== 'object') return;
    const proto = Object.getPrototypeOf(v);
    if (proto && proto !== Object.prototype) {
      try { Object.defineProperty(proto, Symbol.toStringTag, { value: name, configurable: true }); } catch (e) {}
      return;
    }
    rebrand(v, name, base);
  };
  try { brandInPlace(document && document.timeline, 'DocumentTimeline'); } catch (e) {}
  // `document.timeline.currentTime` is the frame clock: a number with three
  // decimals (Chrome: 1514.782), frozen for the task as in Chrome (all reads
  // within one task are equal).
  try {
    const TL = document && document.timeline;
    const TP = TL && Object.getPrototypeOf(TL);
    if (TP && (typeof TL.currentTime !== 'number')) {
      let frozen = null;
      const g = ({ get currentTime() {
        if (frozen === null) {
          frozen = Math.round(performance.now() * 1000) / 1000;
          try { if (typeof globalThis.__pt_addTask === 'function') __pt_addTask(() => { frozen = null; }, 0, true); else setTimeout(() => { frozen = null; }, 0); } catch (e) {}
        }
        return frozen;
      } }).__lookupGetter__('currentTime');
      Object.defineProperty(TP, 'currentTime', { get: native(g), enumerable: true, configurable: true });
    }
  } catch (e) {}
  try { brandInPlace(globalThis.navigator && navigator.serviceWorker, 'ServiceWorkerContainer', ET); } catch (e) {}
  // WebRTC channels are created while the page runs and need a ready tagged
  // prototype, not a table dummy.
  try { iface('RTCDataChannel', ET); } catch (e) {}

  // Objects the page builds itself must tag themselves too:
  // `Object.prototype.toString.call(new Blob([]))` is in every check suite
  // (31 of 36 checked objects answered `[object Object]`, compared with
  // Chrome 148). The tag lives on the prototype, so fix in bulk: give the
  // interface name to any prototype lacking one.
  //
  // Language builtins are left alone: they either have tags (Map, Promise)
  // or are identified otherwise (arrays, functions), and an extra tag would
  // be a difference the other way.
  {
    const LANGUAGE = new Set([
      'Object', 'Function', 'Array', 'Number', 'String', 'Boolean', 'Symbol', 'BigInt',
      'Date', 'RegExp', 'Error', 'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError',
      'TypeError', 'URIError', 'AggregateError', 'SuppressedError', 'Proxy', 'Reflect',
      'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Int8Array', 'Uint8Array',
      'Uint8ClampedArray', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array',
      'Float16Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array',
      'Map', 'Set', 'WeakMap', 'WeakSet', 'WeakRef', 'FinalizationRegistry', 'Promise',
      'Iterator', 'DisposableStack', 'AsyncDisposableStack',
      // These three are factories, not interfaces: `new Audio()` returns an
      // HTMLAudioElement, and a factory-named tag would be wrong.
      'Image', 'Audio', 'Option',
    ]);
    for (const name of Object.getOwnPropertyNames(globalThis)) {
      if (LANGUAGE.has(name) || __s_lastIndexOf(name, '__pt', 0) === 0) continue;
      let C;
      try { C = globalThis[name]; } catch (e) { continue; }
      if (typeof C !== 'function' || !C.prototype || typeof C.prototype !== 'object') continue;
      try {
        if (Object.getOwnPropertyDescriptor(C.prototype, Symbol.toStringTag)) continue;
        Object.defineProperty(C.prototype, Symbol.toStringTag, { value: name, configurable: true });
      } catch (e) {}
    }
  }

  // `speechSynthesis` has no voices (headless Chrome neither), but must be
  // an interface: collectors walk its prototype.
  const SS = rebrand(globalThis.speechSynthesis, 'SpeechSynthesis', ET);
  if (SS) {
    defg(SS.prototype, 'paused', function () { return false; });
    defg(SS.prototype, 'pending', function () { return false; });
    defg(SS.prototype, 'speaking', function () { return false; });
    try { Object.defineProperty(SS.prototype, 'onvoiceschanged', { value: null, writable: true, enumerable: true, configurable: true }); } catch (e) {}
    meth(SS.prototype, 'getVoices', function () { return []; });
    for (const m of ['speak', 'cancel', 'pause', 'resume']) meth(SS.prototype, m, function () {});
  }
})();"##;

/// Eight interfaces whose members we kept on the object while the browser keeps
/// them on the prototype — `url.protocol`, `pc.iceGatheringState`,
/// `mql.matches`. The challenge counts the names on each prototype, and ours
/// came up 12 short on `URL`, 31 on `RTCPeerConnection`. Measured from Chrome
/// 148: `a` are properties, `m` are methods with their arity.
const IFACE_LIFT: &str = r#"{"URL":{"a":["hash","host","hostname","origin","password","pathname","port","protocol","search","searchParams","username"],"m":{"toJSON":0}},"RTCPeerConnection":{"a":["canTrickleIceCandidates","connectionState","currentLocalDescription","currentRemoteDescription","iceConnectionState","iceGatheringState","localDescription","onaddstream","onconnectionstatechange","ondatachannel","onicecandidate","onicecandidateerror","oniceconnectionstatechange","onicegatheringstatechange","onnegotiationneeded","onremovestream","onsignalingstatechange","ontrack","pendingLocalDescription","pendingRemoteDescription","remoteDescription","sctp","signalingState"],"m":{"addStream":1,"addTrack":1,"addTransceiver":1,"createDTMFSender":1,"getLocalStreams":0,"getRemoteStreams":0,"removeStream":1,"removeTrack":1}},"AnalyserNode":{"a":["fftSize","frequencyBinCount","maxDecibels","minDecibels","smoothingTimeConstant"],"m":{"getByteFrequencyData":1,"getByteTimeDomainData":1,"getFloatFrequencyData":1,"getFloatTimeDomainData":1}},"MediaDevices":{"a":["ondevicechange"],"m":{"enumerateDevices":0,"getDisplayMedia":0,"getSupportedConstraints":0,"getUserMedia":0,"setCaptureHandleConfig":0}},"MediaQueryList":{"a":["matches","media","onchange"],"m":{"addListener":1,"removeListener":1}},"TextDecoder":{"a":["encoding","fatal","ignoreBOM"]},"TextEncoder":{"a":["encoding"],"m":{"encodeInto":2}},"SubtleCrypto":{"m":{"unwrapKey":7,"wrapKey":4}},"Date":{"m":{"toTemporalInstant":0}}}"#;

/// Who inherits from whom, measured from Chrome 148. Our interfaces were mostly
/// flat — `AbortSignal` did not descend from `EventTarget`, `Text` did not
/// descend from `CharacterData` — and a graph walk reads the chain, not just the
/// names on each level.
const IFACE_CHAIN: &str = r#"{"AggregateError":"Error","EvalError":"Error","RangeError":"Error","ReferenceError":"Error","SyntaxError":"Error","TypeError":"Error","URIError":"Error","Uint8Array":"TypedArray","Int8Array":"TypedArray","Uint16Array":"TypedArray","Int16Array":"TypedArray","Uint32Array":"TypedArray","Int32Array":"TypedArray","BigUint64Array":"TypedArray","BigInt64Array":"TypedArray","Uint8ClampedArray":"TypedArray","Float32Array":"TypedArray","Float64Array":"TypedArray","Option":"HTMLElement","Image":"HTMLElement","Audio":"HTMLMediaElement","WebKitCSSMatrix":"DOMMatrixReadOnly","XMLHttpRequestUpload":"XMLHttpRequestEventTarget","XMLHttpRequestEventTarget":"EventTarget","XMLHttpRequest":"XMLHttpRequestEventTarget","XMLDocument":"Document","Worker":"EventTarget","Window":"EventTarget","WheelEvent":"MouseEvent","WebSocket":"EventTarget","WebGLVertexArrayObject":"WebGLObject","WebGLTransformFeedback":"WebGLObject","WebGLTexture":"WebGLObject","WebGLSync":"WebGLObject","WebGLShader":"WebGLObject","WebGLSampler":"WebGLObject","WebGLRenderbuffer":"WebGLObject","WebGLQuery":"WebGLObject","WebGLProgram":"WebGLObject","WebGLFramebuffer":"WebGLObject","WebGLContextEvent":"Event","WebGLBuffer":"WebGLObject","WaveShaperNode":"AudioNode","VisualViewport":"EventTarget","VisibilityStateEntry":"PerformanceEntry","VirtualKeyboardGeometryChangeEvent":"Event","ViewTimeline":"ScrollTimeline","VTTCue":"TextTrackCue","UIEvent":"Event","TransitionEvent":"Event","TrackEvent":"Event","TouchEvent":"UIEvent","ToggleEvent":"Event","TextUpdateEvent":"Event","TextTrackList":"EventTarget","TextTrackCue":"EventTarget","TextTrack":"EventTarget","TextFormatUpdateEvent":"Event","TextEvent":"UIEvent","Text":"CharacterData","TaskSignal":"AbortSignal","TaskPriorityChangeEvent":"Event","TaskController":"AbortController","TaskAttributionTiming":"PerformanceEntry","SubmitEvent":"Event","StylePropertyMap":"StylePropertyMapReadOnly","StorageEvent":"Event","StereoPannerNode":"AudioNode","StaticRange":"AbstractRange","SourceBufferList":"EventTarget","SourceBuffer":"EventTarget","ShadowRoot":"DocumentFragment","SecurityPolicyViolationEvent":"Event","ScrollTimeline":"AnimationTimeline","ScriptProcessorNode":"AudioNode","ScreenOrientation":"EventTarget","Screen":"EventTarget","SVGViewElement":"SVGElement","SVGUseElement":"SVGGraphicsElement","SVGTitleElement":"SVGElement","SVGTextPositioningElement":"SVGTextContentElement","SVGTextPathElement":"SVGTextContentElement","SVGTextElement":"SVGTextPositioningElement","SVGTextContentElement":"SVGGraphicsElement","SVGTSpanElement":"SVGTextPositioningElement","SVGSymbolElement":"SVGGraphicsElement","SVGSwitchElement":"SVGGraphicsElement","SVGStyleElement":"SVGElement","SVGStopElement":"SVGElement","SVGSetElement":"SVGAnimationElement","SVGScriptElement":"SVGElement","SVGSVGElement":"SVGGraphicsElement","SVGRectElement":"SVGGeometryElement","SVGRadialGradientElement":"SVGGradientElement","SVGPolylineElement":"SVGGeometryElement","SVGPolygonElement":"SVGGeometryElement","SVGPatternElement":"SVGElement","SVGPathElement":"SVGGeometryElement","SVGMetadataElement":"SVGElement","SVGMaskElement":"SVGElement","SVGMarkerElement":"SVGElement","SVGMPathElement":"SVGElement","SVGLinearGradientElement":"SVGGradientElement","SVGLineElement":"SVGGeometryElement","SVGImageElement":"SVGGraphicsElement","SVGGraphicsElement":"SVGElement","SVGGradientElement":"SVGElement","SVGGeometryElement":"SVGGraphicsElement","SVGGElement":"SVGGraphicsElement","SVGForeignObjectElement":"SVGGraphicsElement","SVGFilterElement":"SVGElement","SVGFETurbulenceElement":"SVGElement","SVGFETileElement":"SVGElement","SVGFESpotLightElement":"SVGElement","SVGFESpecularLightingElement":"SVGElement","SVGFEPointLightElement":"SVGElement","SVGFEOffsetElement":"SVGElement","SVGFEMorphologyElement":"SVGElement","SVGFEMergeNodeElement":"SVGElement","SVGFEMergeElement":"SVGElement","SVGFEImageElement":"SVGElement","SVGFEGaussianBlurElement":"SVGElement","SVGFEFuncRElement":"SVGComponentTransferFunctionElement","SVGFEFuncGElement":"SVGComponentTransferFunctionElement","SVGFEFuncBElement":"SVGComponentTransferFunctionElement","SVGFEFuncAElement":"SVGComponentTransferFunctionElement","SVGFEFloodElement":"SVGElement","SVGFEDropShadowElement":"SVGElement","SVGFEDistantLightElement":"SVGElement","SVGFEDisplacementMapElement":"SVGElement","SVGFEDiffuseLightingElement":"SVGElement","SVGFEConvolveMatrixElement":"SVGElement","SVGFECompositeElement":"SVGElement","SVGFEComponentTransferElement":"SVGElement","SVGFEColorMatrixElement":"SVGElement","SVGFEBlendElement":"SVGElement","SVGEllipseElement":"SVGGeometryElement","SVGElement":"Element","SVGDescElement":"SVGElement","SVGDefsElement":"SVGGraphicsElement","SVGComponentTransferFunctionElement":"SVGElement","SVGClipPathElement":"SVGElement","SVGCircleElement":"SVGGeometryElement","SVGAnimationElement":"SVGElement","SVGAnimateTransformElement":"SVGAnimationElement","SVGAnimateMotionElement":"SVGAnimationElement","SVGAnimateElement":"SVGAnimationElement","SVGAElement":"SVGGraphicsElement","Range":"AbstractRange","RadioNodeList":"NodeList","RTCTrackEvent":"Event","RTCSctpTransport":"EventTarget","RTCPeerConnectionIceEvent":"Event","RTCPeerConnectionIceErrorEvent":"Event","RTCPeerConnection":"EventTarget","RTCIceTransport":"EventTarget","RTCErrorEvent":"Event","RTCError":"DOMException","RTCDtlsTransport":"EventTarget","RTCDataChannelEvent":"Event","RTCDTMFToneChangeEvent":"Event","RTCDTMFSender":"EventTarget","PromiseRejectionEvent":"Event","ProgressEvent":"Event","ProcessingInstruction":"CharacterData","PopStateEvent":"Event","PointerEvent":"MouseEvent","PictureInPictureWindow":"EventTarget","PictureInPictureEvent":"Event","PermissionStatus":"EventTarget","PerformanceScriptTiming":"PerformanceEntry","PerformanceResourceTiming":"PerformanceEntry","PerformancePaintTiming":"PerformanceEntry","PerformanceNavigationTiming":"PerformanceResourceTiming","PerformanceMeasure":"PerformanceEntry","PerformanceMark":"PerformanceEntry","PerformanceLongTaskTiming":"PerformanceEntry","PerformanceLongAnimationFrameTiming":"PerformanceEntry","PerformanceEventTiming":"PerformanceEntry","PerformanceElementTiming":"PerformanceEntry","Performance":"EventTarget","PannerNode":"AudioNode","PageTransitionEvent":"Event","OverconstrainedError":"DOMException","OscillatorNode":"AudioScheduledSourceNode","OffscreenCanvas":"EventTarget","OfflineAudioContext":"BaseAudioContext","OfflineAudioCompletionEvent":"Event","Node":"EventTarget","NetworkInformation":"EventTarget","NavigationHistoryEntry":"EventTarget","NavigationCurrentEntryChangeEvent":"Event","Navigation":"EventTarget","NavigateEvent":"Event","MouseEvent":"UIEvent","MessagePort":"EventTarget","MessageEvent":"Event","MediaStreamTrackGenerator":"MediaStreamTrack","MediaStreamTrackEvent":"Event","MediaStreamTrack":"EventTarget","MediaStreamEvent":"Event","MediaStreamAudioSourceNode":"AudioNode","MediaStreamAudioDestinationNode":"AudioNode","MediaStream":"EventTarget","MediaSource":"EventTarget","MediaRecorder":"EventTarget","MediaQueryListEvent":"Event","MediaQueryList":"EventTarget","MediaEncryptedEvent":"Event","MediaElementAudioSourceNode":"AudioNode","MathMLElement":"Element","LayoutShift":"PerformanceEntry","LargestContentfulPaint":"PerformanceEntry","KeyframeEffect":"AnimationEffect","KeyboardEvent":"UIEvent","InputEvent":"UIEvent","InputDeviceInfo":"MediaDeviceInfo","IIRFilterNode":"AudioNode","IDBVersionChangeEvent":"Event","IDBTransaction":"EventTarget","IDBRequest":"EventTarget","IDBOpenDBRequest":"IDBRequest","IDBDatabase":"EventTarget","IDBCursorWithValue":"IDBCursor","HashChangeEvent":"Event","HTMLVideoElement":"HTMLMediaElement","HTMLUnknownElement":"HTMLElement","HTMLUListElement":"HTMLElement","HTMLTrackElement":"HTMLElement","HTMLTitleElement":"HTMLElement","HTMLTimeElement":"HTMLElement","HTMLTextAreaElement":"HTMLElement","HTMLTemplateElement":"HTMLElement","HTMLTableSectionElement":"HTMLElement","HTMLTableRowElement":"HTMLElement","HTMLTableElement":"HTMLElement","HTMLTableColElement":"HTMLElement","HTMLTableCellElement":"HTMLElement","HTMLTableCaptionElement":"HTMLElement","HTMLStyleElement":"HTMLElement","HTMLSpanElement":"HTMLElement","HTMLSourceElement":"HTMLElement","HTMLSlotElement":"HTMLElement","HTMLSelectedContentElement":"HTMLElement","HTMLSelectElement":"HTMLElement","HTMLScriptElement":"HTMLElement","HTMLQuoteElement":"HTMLElement","HTMLProgressElement":"HTMLElement","HTMLPreElement":"HTMLElement","HTMLPictureElement":"HTMLElement","HTMLParamElement":"HTMLElement","HTMLParagraphElement":"HTMLElement","HTMLOutputElement":"HTMLElement","HTMLOptionsCollection":"HTMLCollection","HTMLOptionElement":"HTMLElement","HTMLOptGroupElement":"HTMLElement","HTMLObjectElement":"HTMLElement","HTMLOListElement":"HTMLElement","HTMLModElement":"HTMLElement","HTMLMeterElement":"HTMLElement","HTMLMetaElement":"HTMLElement","HTMLMenuElement":"HTMLElement","HTMLMediaElement":"HTMLElement","HTMLMarqueeElement":"HTMLElement","HTMLMapElement":"HTMLElement","HTMLLinkElement":"HTMLElement","HTMLLegendElement":"HTMLElement","HTMLLabelElement":"HTMLElement","HTMLLIElement":"HTMLElement","HTMLInputElement":"HTMLElement","HTMLImageElement":"HTMLElement","HTMLIFrameElement":"HTMLElement","HTMLHtmlElement":"HTMLElement","HTMLHeadingElement":"HTMLElement","HTMLHeadElement":"HTMLElement","HTMLHRElement":"HTMLElement","HTMLFrameSetElement":"HTMLElement","HTMLFrameElement":"HTMLElement","HTMLFormElement":"HTMLElement","HTMLFormControlsCollection":"HTMLCollection","HTMLFontElement":"HTMLElement","HTMLFieldSetElement":"HTMLElement","HTMLEmbedElement":"HTMLElement","HTMLElement":"Element","HTMLDocument":"Document","HTMLDivElement":"HTMLElement","HTMLDirectoryElement":"HTMLElement","HTMLDialogElement":"HTMLElement","HTMLDetailsElement":"HTMLElement","HTMLDataListElement":"HTMLElement","HTMLDataElement":"HTMLElement","HTMLDListElement":"HTMLElement","HTMLCanvasElement":"HTMLElement","HTMLButtonElement":"HTMLElement","HTMLBodyElement":"HTMLElement","HTMLBaseElement":"HTMLElement","HTMLBRElement":"HTMLElement","HTMLAudioElement":"HTMLMediaElement","HTMLAreaElement":"HTMLElement","HTMLAnchorElement":"HTMLElement","GamepadEvent":"Event","GainNode":"AudioNode","FormDataEvent":"Event","FontFaceSetLoadEvent":"Event","FocusEvent":"UIEvent","FileReader":"EventTarget","File":"Blob","EventSource":"EventTarget","ErrorEvent":"Event","Element":"Node","EditContext":"EventTarget","DynamicsCompressorNode":"AudioNode","DragEvent":"MouseEvent","DocumentType":"Node","DocumentTimeline":"AnimationTimeline","DocumentFragment":"Node","Document":"Node","DelayNode":"AudioNode","DOMRect":"DOMRectReadOnly","DOMPoint":"DOMPointReadOnly","DOMMatrix":"DOMMatrixReadOnly","DOMException":"Error","CustomEvent":"Event","ConvolverNode":"AudioNode","ContentVisibilityAutoStateChangeEvent":"Event","ConstantSourceNode":"AudioScheduledSourceNode","CompositionEvent":"UIEvent","Comment":"CharacterData","CommandEvent":"Event","CloseWatcher":"EventTarget","CloseEvent":"Event","ClipboardEvent":"Event","CharacterData":"Node","CharacterBoundsUpdateEvent":"Event","ChannelSplitterNode":"AudioNode","ChannelMergerNode":"AudioNode","CanvasCaptureMediaStreamTrack":"MediaStreamTrack","CSSViewTransitionRule":"CSSRule","CSSUnparsedValue":"CSSStyleValue","CSSUnitValue":"CSSNumericValue","CSSTranslate":"CSSTransformComponent","CSSTransition":"Animation","CSSTransformValue":"CSSStyleValue","CSSSupportsRule":"CSSConditionRule","CSSStyleSheet":"StyleSheet","CSSStyleRule":"CSSRule","CSSStartingStyleRule":"CSSGroupingRule","CSSSkewY":"CSSTransformComponent","CSSSkewX":"CSSTransformComponent","CSSSkew":"CSSTransformComponent","CSSScopeRule":"CSSGroupingRule","CSSScale":"CSSTransformComponent","CSSRotate":"CSSTransformComponent","CSSPropertyRule":"CSSRule","CSSPositionValue":"CSSStyleValue","CSSPositionTryRule":"CSSRule","CSSPositionTryDescriptors":"CSSStyleDeclaration","CSSPerspective":"CSSTransformComponent","CSSPageRule":"CSSGroupingRule","CSSNumericValue":"CSSStyleValue","CSSNestedDeclarations":"CSSRule","CSSNamespaceRule":"CSSRule","CSSMediaRule":"CSSConditionRule","CSSMatrixComponent":"CSSTransformComponent","CSSMathValue":"CSSNumericValue","CSSMathSum":"CSSMathValue","CSSMathProduct":"CSSMathValue","CSSMathNegate":"CSSMathValue","CSSMathMin":"CSSMathValue","CSSMathMax":"CSSMathValue","CSSMathInvert":"CSSMathValue","CSSMathClamp":"CSSMathValue","CSSMarginRule":"CSSRule","CSSLayerStatementRule":"CSSRule","CSSLayerBlockRule":"CSSGroupingRule","CSSKeywordValue":"CSSStyleValue","CSSKeyframesRule":"CSSRule","CSSKeyframeRule":"CSSRule","CSSImportRule":"CSSRule","CSSImageValue":"CSSStyleValue","CSSGroupingRule":"CSSRule","CSSFontPaletteValuesRule":"CSSRule","CSSFontFaceRule":"CSSRule","CSSCounterStyleRule":"CSSRule","CSSContainerRule":"CSSConditionRule","CSSConditionRule":"CSSGroupingRule","CSSAnimation":"Animation","CSPViolationReportBody":"ReportBody","CDATASection":"Text","BrowserCaptureMediaStreamTrack":"MediaStreamTrack","BroadcastChannel":"EventTarget","BlobEvent":"Event","BiquadFilterNode":"AudioNode","BeforeUnloadEvent":"Event","BeforeInstallPromptEvent":"Event","BaseAudioContext":"EventTarget","AudioWorkletNode":"AudioNode","AudioScheduledSourceNode":"AudioNode","AudioProcessingEvent":"Event","AudioNode":"EventTarget","AudioDestinationNode":"AudioNode","AudioContext":"BaseAudioContext","AudioBufferSourceNode":"AudioScheduledSourceNode","Attr":"Node","AnimationPlaybackEvent":"Event","AnimationEvent":"Event","Animation":"EventTarget","AnalyserNode":"AudioNode","AbortSignal":"EventTarget","SuppressedError":"Error","Float16Array":"TypedArray","AbsoluteOrientationSensor":"OrientationSensor","Accelerometer":"Sensor","AudioDecoder":"EventTarget","AudioEncoder":"EventTarget","AudioWorklet":"Worklet","BatteryManager":"EventTarget","Clipboard":"EventTarget","CookieChangeEvent":"Event","CookieStore":"EventTarget","CreateMonitor":"EventTarget","DeviceMotionEvent":"Event","DeviceOrientationEvent":"Event","FederatedCredential":"Credential","GPUDevice":"EventTarget","GPUInternalError":"GPUError","GPUOutOfMemoryError":"GPUError","GPUPipelineError":"DOMException","GPUUncapturedErrorEvent":"Event","GPUValidationError":"GPUError","GravitySensor":"Accelerometer","Gyroscope":"Sensor","IdleDetector":"EventTarget","LinearAccelerationSensor":"Accelerometer","MIDIAccess":"EventTarget","MIDIConnectionEvent":"Event","MIDIInput":"MIDIPort","MIDIMessageEvent":"Event","MIDIOutput":"MIDIPort","MIDIPort":"EventTarget","MediaDevices":"EventTarget","MediaKeyMessageEvent":"Event","MediaKeySession":"EventTarget","NavigatorManagedData":"EventTarget","OrientationSensor":"Sensor","PasswordCredential":"Credential","RelativeOrientationSensor":"OrientationSensor","ScreenDetailed":"Screen","ScreenDetails":"EventTarget","Sensor":"EventTarget","SensorErrorEvent":"Event","ServiceWorkerRegistration":"EventTarget","VideoDecoder":"EventTarget","VideoEncoder":"EventTarget","VirtualKeyboard":"EventTarget","WebTransportError":"DOMException","XRLayer":"EventTarget","AuthenticatorAssertionResponse":"AuthenticatorResponse","AuthenticatorAttestationResponse":"AuthenticatorResponse","PublicKeyCredential":"Credential","CaptureController":"EventTarget","ClipboardChangeEvent":"Event","DevicePosture":"EventTarget","DigitalCredential":"Credential","DocumentPictureInPicture":"EventTarget","FileSystemDirectoryHandle":"FileSystemHandle","FileSystemFileHandle":"FileSystemHandle","FileSystemWritableFileStream":"WritableStream","HID":"EventTarget","HIDConnectionEvent":"Event","HIDDevice":"EventTarget","HIDInputReportEvent":"Event","IdentityCredential":"Credential","IdentityCredentialError":"DOMException","LanguageModel":"EventTarget","ServiceWorker":"EventTarget","ServiceWorkerContainer":"EventTarget","OTPCredential":"Credential","PaymentRequest":"EventTarget","PaymentRequestUpdateEvent":"Event","PaymentResponse":"EventTarget","PaymentMethodChangeEvent":"PaymentRequestUpdateEvent","PresentationAvailability":"EventTarget","PresentationConnection":"EventTarget","PresentationConnectionAvailableEvent":"Event","PresentationConnectionCloseEvent":"Event","PresentationConnectionList":"EventTarget","PresentationRequest":"EventTarget","Serial":"EventTarget","SerialPort":"EventTarget","USB":"EventTarget","USBConnectionEvent":"Event","WakeLockSentinel":"EventTarget","XRBoundedReferenceSpace":"XRReferenceSpace","XRCPUDepthInformation":"XRDepthInformation","XRInputSourceEvent":"Event","XRInputSourcesChangeEvent":"Event","XRJointPose":"XRPose","XRJointSpace":"XRSpace","XRLightProbe":"EventTarget","XRReferenceSpace":"XRSpace","XRReferenceSpaceEvent":"Event","XRSession":"EventTarget","XRSessionEvent":"Event","XRSpace":"EventTarget","XRSystem":"EventTarget","XRViewerPose":"XRPose","XRWebGLDepthInformation":"XRDepthInformation","XRWebGLLayer":"XRLayer","XRCompositionLayer":"XRLayer","XRProjectionLayer":"XRCompositionLayer","XRCubeLayer":"XRCompositionLayer","XRCylinderLayer":"XRCompositionLayer","XREquirectLayer":"XRCompositionLayer","XRLayerEvent":"Event","XRQuadLayer":"XRCompositionLayer","XRWebGLSubImage":"XRSubImage","XRVisibilityMaskChangeEvent":"Event","BackgroundFetchRegistration":"EventTarget","CSSFontFeatureValuesRule":"CSSRule","CSSFunctionDeclarations":"CSSRule","CSSFunctionDescriptors":"CSSStyleDeclaration","CSSFunctionRule":"CSSGroupingRule","DocumentPictureInPictureEvent":"Event","HTMLFencedFrameElement":"HTMLElement","HTMLGeolocationElement":"HTMLElement","IntegrityViolationReportBody":"ReportBody","InterestEvent":"Event","Notification":"EventTarget","PageRevealEvent":"Event","PageSwapEvent":"Event","Profiler":"EventTarget","QuotaExceededError":"DOMException","RTCDataChannel":"EventTarget","RemotePlayback":"EventTarget","SharedStorageAppendMethod":"SharedStorageModifierMethod","SharedStorageClearMethod":"SharedStorageModifierMethod","SharedStorageDeleteMethod":"SharedStorageModifierMethod","SharedStorageSetMethod":"SharedStorageModifierMethod","SharedWorker":"EventTarget","SnapEvent":"Event","SpeechRecognition":"EventTarget","SpeechRecognitionErrorEvent":"Event","SpeechRecognitionEvent":"Event","SpeechSynthesis":"EventTarget","SpeechSynthesisErrorEvent":"SpeechSynthesisEvent","SpeechSynthesisEvent":"Event","SpeechSynthesisUtterance":"EventTarget","TimelineTrigger":"AnimationTrigger","WebSocketError":"DOMException","WindowControlsOverlay":"EventTarget","WindowControlsOverlayGeometryChangeEvent":"Event"}"#;

/// Members we declare where the browser does not. Each maps to the interfaces
/// Chrome 148 says own it, and the installer walks our own chain to find which
/// of them is the ancestor; an empty list means the browser declares it nowhere.
///
/// Deliberately small. The obvious candidates — `addEventListener` and its pair,
/// which Chrome declares once on `EventTarget` and we declare on every event
/// target — cannot be moved: ours are not copies of a shared implementation but
/// each class's own machinery, and a socket, a port or a signal without its own
/// copy stops delivering events. The challenge stopped dead after its first
/// question to the worker.
const IFACE_PROTO_MOVES: &str = r#"{"Blob":{"toString":[]},"FormData":{"toString":[]},"KeyboardEvent":{"which":["UIEvent"]},"ShadowRoot":{"append":["DocumentFragment"],"prepend":["DocumentFragment"],"children":["DocumentFragment"],"childElementCount":["DocumentFragment"],"firstElementChild":["DocumentFragment"],"lastElementChild":["DocumentFragment"],"querySelector":["DocumentFragment"],"querySelectorAll":["DocumentFragment"],"getElementById":["DocumentFragment"],"replaceChildren":["DocumentFragment"],"moveBefore":["DocumentFragment"],"nodeName":["Node"],"nodeValue":["Node"],"textContent":["Node"],"getElementsByClassName":[],"getElementsByTagName":[]}}"#;


/// The interface objects' static members, installed last of all: constants like
/// `Event.AT_TARGET` and `DOMException.ABORT_ERR` sit on the interface itself,
/// and a graph walk reads them on its first step. Runs after every layer has
/// declared its interfaces — half of them do not exist earlier.
const IFACE_STATICS_TEMPLATE: &str = r#"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_charAt = __sm(String.prototype.charAt, 'charAt'),
    __s_trim = __sm(String.prototype.trim, 'trim'),
    __s_toLowerCase = __sm(String.prototype.toLowerCase, 'toLowerCase'),
    __s_split = __sm(String.prototype.split, 'split'),
    __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_charCodeAt = __sm(String.prototype.charCodeAt, 'charCodeAt'),
    __s_replace = __sm(String.prototype.replace, 'replace'),
    __s_startsWith = __sm(String.prototype.startsWith, 'startsWith');
  const native = globalThis.__pt_native || ((f) => f);
  // Strict function: interface members have no own `arguments`/`caller`.
  // Method/getter: strict and without `.prototype`, like native ones.
  // Born with name and length: editing them turns a function into dictionary
  // mode (~260 bytes each).
  const strictMethod = (function () {
    'use strict';
    return (n, len) => {
      const f = len === 0 ? ({ [n]() {} })[n] : len === 1 ? ({ [n](a) {} })[n] : len === 2 ? ({ [n](a, b) {} })[n] : ({ [n](a, b, c) {} })[n];
      if (len > 3) Object.defineProperty(f, 'length', { value: len, configurable: true });
      return f;
    };
  })();
  const strictGetter = (function () {
    'use strict';
    return (n) => Object.getOwnPropertyDescriptor({ get [n]() {} }, n).get;
  })();
  // Chain first: until `Text` inherits `CharacterData`, placing members by
  // level is pointless. Only set where our chain is broken, and only if no
  // cycle results.
  const CHAIN = __IFACE_CHAIN__;
  const protoOf = (n) => {
    // %TypedArray% has no name on window: reachable only via any concrete
    // typed array.
    if (n === 'TypedArray') {
      try { return Object.getPrototypeOf(Int8Array.prototype); } catch (e) { return null; }
    }
    try { const C = globalThis[n]; return (typeof C === 'function' && C.prototype) || null; }
    catch (e) { return null; }
  };
  // Table order is arbitrary but links depend on each other: `Text` cannot
  // go under `CharacterData` until that is linked into `Node`, or a level is
  // lost. Repeat while the chain keeps growing.
  for (let pass = 0; pass < 6; pass++) {
  let changed = false;
  for (const child of Object.keys(CHAIN)) {
    const P = protoOf(child), Q = protoOf(CHAIN[child]);
    if (!P || !Q || P === Q) continue;
    const now = Object.getPrototypeOf(P);
    if (now !== Object.prototype) {
      // Already linked somewhere. A missing link (`Text` inherits
      // `CharacterData`, which inherits `Node`) can be inserted only if the
      // current parent stays in the chain below the new one.
      if (now === Q) continue;
      let keeps = false;
      for (let q = Q; q; q = Object.getPrototypeOf(q)) { if (q === now) { keeps = true; break; } }
      if (!keeps) continue;
    }
    let cycle = false;
    for (let q = Q; q; q = Object.getPrototypeOf(q)) { if (q === P) { cycle = true; break; } }
    if (cycle) continue;
    try { Object.setPrototypeOf(P, Q); changed = true; } catch (e) {}
  }
  if (!changed) break;
  }

  // WebAssembly streaming entry points come from the browser, not the engine:
  // they take a `Response` and read its bytes. V8 lacks them, and they were
  // the only two names missing from the namespace vs Chrome. Implemented
  // honestly via the same response our `fetch` returns.
  // A separate function: a snapshot context gets WebAssembly from V8 after
  // the loader, and then __pt_afterRestore calls it.
  const wasmStreaming = () => { try {
    const W = globalThis.WebAssembly;
    if (W && typeof W.compile === 'function' && typeof W.compileStreaming !== 'function') {
      // As in the browser: only a `Response` with MIME `application/wasm` and
      // an ok status is accepted, otherwise TypeError in its words.
      const bytesOf = (src, what) => Promise.resolve(src).then((r) => {
        const head = "Failed to execute '" + what + "' on 'WebAssembly': ";
        if (globalThis.__pt_encTrace) { try { (globalThis.__pt_parentConsole || console).error('[wasm] ' + what + 'Streaming src=' + Object.prototype.toString.call(r) + ' ct=' + (r && r.headers && typeof r.headers.get === 'function' ? r.headers.get('content-type') : '?') + ' status=' + (r && r.status) + ' used=' + (r && r.bodyUsed) + ' ab=' + typeof (r && r.arrayBuffer)); } catch (e) {} }
        // The response may come from another realm (a sandbox Response):
        // recognize it by shape, not instanceof.
        const looksResponse = r && typeof r === 'object' && typeof r.arrayBuffer === 'function' && r.headers && typeof r.headers.get === 'function';
        if (!looksResponse) {
          throw __pt_mkErr(TypeError, head + "An argument must be provided, which must be a Response or Promise<Response> object");
        }
        const mime = __s_toLowerCase(__s_trim(__s_split(String((r.headers && r.headers.get('content-type')) || ''), ';')[0]));
        if (mime !== 'application/wasm') throw __pt_mkErr(TypeError, head + "Incorrect response MIME type. Expected 'application/wasm'.");
        if (!r.ok) throw __pt_mkErr(TypeError, head + 'HTTP status code is not ok');
        if (r.bodyUsed) throw __pt_mkErr(TypeError, head + 'Response already read');
        return r.arrayBuffer();
      });
      const traceRej = (what) => (e) => { if (globalThis.__pt_encTrace) { try { (globalThis.__pt_parentConsole || console).error('[wasm] ' + what + ' rejected: ' + __s_slice(String(e && e.message), 0, 120)); } catch (x) {} } throw e; };
      const cs = function compileStreaming(source) { return bytesOf(source, 'compile').then((b) => W.compile(b)).catch(traceRej('compileStreaming')); };
      const is = function instantiateStreaming(source, imports) {
        return bytesOf(source, 'instantiate').then((b) => W.instantiate(b, imports)).catch(traceRej('instantiateStreaming'));
      };
      // Trace (`NOKK_TRACE_ENC=1`): what WebAssembly is called with.
      if (globalThis.__pt_encTrace) {
        for (const k of ['instantiate', 'compile', 'validate']) {
          const F = W[k];
          if (typeof F !== 'function') continue;
          const wrapped = function (a, b) {
            const desc = a && typeof a === 'object' ? Object.prototype.toString.call(a) + (a.byteLength !== undefined ? '#' + a.byteLength : '') : typeof a;
            let r;
            try { r = F.call(this, a, b); } catch (e) { try { (globalThis.__pt_parentConsole || console).error('[wasm] ' + k + '(' + desc + ') threw ' + __s_slice(String(e && e.message), 0, 100)); } catch (x) {} throw e; }
            if (r && typeof r.then === 'function') r.then((v) => { try { (globalThis.__pt_parentConsole || console).error('[wasm] ' + k + '(' + desc + ') ok ' + Object.prototype.toString.call(v)); } catch (x) {} }, (e) => { try { (globalThis.__pt_parentConsole || console).error('[wasm] ' + k + '(' + desc + ') rejected ' + __s_slice(String(e && e.message), 0, 120)); } catch (x) {} });
            else { try { (globalThis.__pt_parentConsole || console).error('[wasm] ' + k + '(' + desc + ') = ' + String(r)); } catch (x) {} }
            return r;
          };
          try { Object.defineProperty(wrapped, 'name', { value: k, configurable: true }); Object.defineProperty(wrapped, 'length', { value: F.length, configurable: true }); } catch (e) {}
          Object.defineProperty(W, k, { value: native(wrapped), writable: true, enumerable: false, configurable: true });
        }
      }
      Object.defineProperty(W, 'compileStreaming', {
        value: native(cs), writable: true, enumerable: false, configurable: true });
      Object.defineProperty(W, 'instantiateStreaming', {
        value: native(is), writable: true, enumerable: false, configurable: true });
    }
  } catch (e) {} };
  wasmStreaming();
  if (globalThis.__pt_lateNames) Object.defineProperty(globalThis, '__pt_wasmStreaming', { value: wasmStreaming, writable: true, configurable: true });

  const STATICS = __IFACE_STATICS__;
  for (const iface of Object.keys(STATICS)) {
    const I = globalThis[iface];
    if (typeof I !== 'function' && !(typeof I === 'object' && I !== null && __s_startsWith(iface, 'GPU'))) continue;
    const spec = STATICS[iface];
    const hidden = new Set(spec.h || []);
    const has = (k) => Object.prototype.hasOwnProperty.call(I, k);
    for (const k of Object.keys(spec.c || {})) {
      if (has(k)) continue;
      // Browser descriptor shape: a constant is enumerable but non-writable
      // and non-configurable.
      try {
        Object.defineProperty(I, k, {
          value: spec.c[k], writable: false, enumerable: !hidden.has(k), configurable: false,
        });
      } catch (e) {}
    }
    for (const k of Object.keys(spec.f || {})) {
      if (has(k)) continue;
      try {
        // A method has no prototype: it is not a constructor.
        const f = strictMethod(k, spec.f[k] | 0);
        Object.defineProperty(I, k, {
          value: native(f), writable: true, enumerable: !hidden.has(k), configurable: true,
        });
      } catch (e) {}
    }
    for (const k of spec.g || []) {
      if (has(k)) continue;
      try {
        Object.defineProperty(I, k, { get: native(strictGetter(k)), enumerable: true, configurable: true });
      } catch (e) {}
    }
  }

  // The table for the level below (prototypes) is captured but not applied.
  // Declaring all 5007 members we lack vs Chrome is not possible: a name on a
  // prototype promises behaviour, and pages call what they find. With the
  // `Performance*` family this broke the challenge widget: our timing
  // entries live on those prototypes and stubs shadowed real values. "An
  // interface the engine implements" cannot be reliably told apart from "a
  // name from the graph table" (the former may have an empty, lazily filled
  // prototype). A deliberate trade of name fidelity for behaviour.
  try { if (globalThis.__pt_sinkAudioMethods) __pt_sinkAudioMethods(); } catch (e) {}
  // Transferring a canvas to a worker. It returned `undefined`, and a
  // collector that draws on a worker aborted entirely (the 44x49 snapshot and
  // the 32x32 WebGL read went missing from the report). Installed here, not
  // in the DOM layer: the interface shape table overwrites it with a stub.
  try {
    const CP = globalThis.HTMLCanvasElement && globalThis.HTMLCanvasElement.prototype;
    if (CP && globalThis.__pt_makeTransferred) {
      const fn = function transferControlToOffscreen() {
        if (this.__ptTransferred) {
          const e = __pt_mkErr(globalThis.DOMException || Error, 
            "Failed to execute 'transferControlToOffscreen' on 'HTMLCanvasElement': Cannot transfer control from a canvas for more than one time.",
            'InvalidStateError');
          e.name = 'InvalidStateError';
          throw e;
        }
        try { Object.defineProperty(this, '__ptTransferred', { value: true, configurable: true }); } catch (e) {}
        return __pt_makeTransferred(this);
      };
      Object.defineProperty(CP, 'transferControlToOffscreen', {
        value: globalThis.__pt_native ? __pt_native(fn) : fn,
        writable: true, enumerable: true, configurable: true,
      });
    }
  } catch (e) {}
  // `new ImageData(...)`: the constructor was a shape-table stub producing an
  // object without pixels, so `d.data.length` threw.
  try {
    const P0 = globalThis.ImageData && globalThis.ImageData.prototype;
    if (P0 && !globalThis.__pt_imageDataReal) {
      const err = (why) => {
        const e = __pt_mkErr(globalThis.DOMException || Error, 
          "Failed to construct 'ImageData': " + why, 'InvalidStateError');
        e.name = 'InvalidStateError';
        return e;
      };
      const ctor = function ImageData(a, b, c) {
        const settings = [].slice.call(arguments).filter(
          (x) => x && typeof x === 'object' && !ArrayBuffer.isView(x)).pop() || null;
        if (!(this instanceof ctor)) {
          throw __pt_mkErr(TypeError, "Failed to construct 'ImageData': " +
            'Please use the \'new\' operator, this DOM object constructor cannot be called as a function.');
        }
        if (arguments.length < 2) {
          throw __pt_mkErr(TypeError, "Failed to construct 'ImageData': " +
            '2 arguments required, but only ' + arguments.length + ' present.');
        }
        let data = null, w = 0, h = 0;
        if (typeof a === 'number') {
          w = a | 0; h = b | 0;
          if (w <= 0) throw err('The source width is zero or not a number.');
          if (h <= 0) throw err('The source height is zero or not a number.');
          data = new Uint8ClampedArray(4 * w * h);
        } else {
          const f16 = globalThis.Float16Array && a instanceof globalThis.Float16Array;
          if (!(a instanceof Uint8ClampedArray) && !f16) {
            throw __pt_mkErr(TypeError, "Failed to construct 'ImageData': " +
              "The provided value is not of type '(Uint8ClampedArray or Float16Array)'.");
          }
          // Half precision is only allowed with an explicit pixel format, and
          // the browser reports that with a separate error.
          if (f16 && !(settings && settings.pixelFormat === 'rgba-float16')) {
            throw err('Float16Array must use rgba-float16 pixel format.');
          }
          data = a; w = b | 0;
          if (data.length % 4) throw err('The input data length is not a multiple of 4.');
          if (w <= 0) throw err('The source width is zero or not a number.');
          const rows = data.length / 4 / w;
          if (arguments.length >= 3 && typeof c === 'number') {
            h = c | 0;
            if (h <= 0) throw err('The source height is zero or not a number.');
            if (data.length !== 4 * w * h) {
              throw err('The input data length is not equal to (4 * width * height).');
            }
          } else {
            if (rows !== Math.floor(rows)) {
              throw err('The input data length is not a multiple of (4 * width).');
            }
            h = rows;
          }
        }
        const o = globalThis.__pt_makeImageData(data, w, h,
          settings && settings.colorSpace, settings && settings.pixelFormat);
        Object.setPrototypeOf(o, Object.getPrototypeOf(this) || P0);
        return o;
      };
      Object.defineProperty(ctor, 'prototype', { value: P0, writable: false, enumerable: false });
      try { Object.defineProperty(ctor, 'length', { value: 2, configurable: true }); } catch (e) {}
      try { Object.defineProperty(P0, 'constructor', { value: ctor, writable: true, configurable: true }); } catch (e) {}
      globalThis.ImageData = globalThis.__pt_native ? __pt_native(ctor) : ctor;
      Object.defineProperty(globalThis, '__pt_imageDataReal', { value: true, writable: true, configurable: true });
    }
  } catch (e) {}

  // `DOMMatrix`: pages read transforms via `getTransform`, `WebKitCSSMatrix`
  // or by parsing a `transform` string.
  try {
    const RO = globalThis.DOMMatrixReadOnly, MM = globalThis.DOMMatrix;
    if (MM && MM.prototype && !globalThis.__pt_matrixReal) {
      Object.defineProperty(globalThis, '__pt_matrixReal', { value: true, writable: true, configurable: true });
      const ST = new WeakMap();
      const ident = () => [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1];
      const stateOf = (o) => { let v = ST.get(o); if (!v) { v = { m: ident(), d2: true }; ST.set(o, v); } return v; };
      // Column-major order, as in the spec: m11..m44.
      const IDX = { m11: 0, m12: 1, m13: 2, m14: 3, m21: 4, m22: 5, m23: 6, m24: 7,
        m31: 8, m32: 9, m33: 10, m34: 11, m41: 12, m42: 13, m43: 14, m44: 15 };
      const ALIAS = { a: 'm11', b: 'm12', c: 'm21', d: 'm22', e: 'm41', f: 'm42' };
      const fromInit = (o, init) => {
        const st = stateOf(o);
        if (init === undefined || init === null) return o;
        if (typeof init === 'string') {
          // A string like `matrix(a, b, c, d, e, f)` or `matrix3d(...)`.
          const m = /^\s*matrix(3d)?\(([^)]*)\)\s*$/.exec(init);
          if (!m) { if (__s_trim(String(init))) throw __pt_mkErr(globalThis.DOMException || Error, 
            "Failed to construct 'DOMMatrix': Failed to parse '" + init + "'.", 'SyntaxError'); return o; }
          const n = __s_split(m[2], ',').map((x) => parseFloat(x) || 0);
          if (m[1]) { st.m = __s_slice(n, 0, 16); st.d2 = false; }
          else { st.m = ident(); st.m[0] = n[0]; st.m[1] = n[1]; st.m[4] = n[2];
            st.m[5] = n[3]; st.m[12] = n[4]; st.m[13] = n[5]; st.d2 = true; }
          return o;
        }
        const arr = Array.from(init);
        if (arr.length === 6) {
          st.m = ident(); st.m[0] = +arr[0] || 0; st.m[1] = +arr[1] || 0; st.m[4] = +arr[2] || 0;
          st.m[5] = +arr[3] || 0; st.m[12] = +arr[4] || 0; st.m[13] = +arr[5] || 0; st.d2 = true;
        } else if (arr.length === 16) {
          st.m = arr.map((x) => +x || 0); st.d2 = false;
        } else {
          const e = __pt_mkErr(TypeError, "Failed to construct 'DOMMatrix': " +
            'Failed to construct matrix: The sequence must contain 6 elements for a 2D matrix or 16 elements for a 3D matrix.');
          throw e;
        }
        return o;
      };
      const mulm = (A, B) => {            // A * B, both column-major
        const r = new Array(16).fill(0);
        for (let c = 0; c < 4; c++) for (let rr = 0; rr < 4; rr++) {
          let v = 0;
          for (let k = 0; k < 4; k++) v += A[k * 4 + rr] * B[c * 4 + k];
          r[c * 4 + rr] = v;
        }
        return r;
      };
      const make = (Cls, m, d2) => { const o = Object.create(Cls.prototype); ST.set(o, { m: __s_slice(m), d2 }); return o; };
      const shape = (Cls, writable) => {
        const P = Cls && Cls.prototype;
        if (!P || Object.prototype.hasOwnProperty.call(P, '__ptMatrixShaped')) return;
        try { Object.defineProperty(P, '__ptMatrixShaped', { value: true }); } catch (e) {}
        // DOMMatrix's own members are only setter accessors, *Self methods and
        // setMatrixValue; the rest is inherited from DOMMatrixReadOnly.
        const roOnly = new Set(['is2D', 'isIdentity', 'multiply', 'translate', 'scale', 'scale3d', 'scaleNonUniform', 'rotate', 'rotateFromVector', 'rotateAxisAngle', 'skewX', 'skewY', 'inverse', 'flipX', 'flipY', 'transformPoint', 'toFloat32Array', 'toFloat64Array', 'toJSON', 'toString']);
        const put = (name, get, set) => {
          if (writable && roOnly.has(name)) return;
          try { Object.defineProperty(P, name, { get, set, enumerable: true, configurable: true }); } catch (e) {}
        };
        for (const k of Object.keys(IDX)) {
          const i = IDX[k];
          put(k, function () { return stateOf(this).m[i]; },
            writable ? function (v) { const st = stateOf(this); st.m[i] = +v || 0;
              if (i !== 0 && i !== 1 && i !== 4 && i !== 5 && i !== 12 && i !== 13) st.d2 = false; } : undefined);
        }
        for (const k of Object.keys(ALIAS)) {
          const i = IDX[ALIAS[k]];
          put(k, function () { return stateOf(this).m[i]; },
            writable ? function (v) { stateOf(this).m[i] = +v || 0; } : undefined);
        }
        put('is2D', function () { return stateOf(this).d2; }, undefined);
        put('isIdentity', function () {
          const m = stateOf(this).m, I = ident();
          for (let i = 0; i < 16; i++) if (m[i] !== I[i]) return false;
          return true;
        }, undefined);
        const method = (name, fn) => {
          if (writable && roOnly.has(name)) return;
          try { Object.defineProperty(P, name, { value: fn, writable: true, enumerable: true, configurable: true }); } catch (e) {}
        };
        method('multiply', function (other) {
          const st = stateOf(this), o = other ? stateOf(other) : { m: ident(), d2: true };
          return make(globalThis.DOMMatrix, mulm(st.m, o.m), st.d2 && o.d2);
        });
        method('translate', function (tx, ty, tz) {
          const t = ident(); t[12] = +tx || 0; t[13] = +ty || 0; t[14] = +tz || 0;
          const st = stateOf(this);
          return make(globalThis.DOMMatrix, mulm(st.m, t), st.d2 && !tz);
        });
        method('scale', function (sx, sy, sz) {
          const t = ident(); const x = sx === undefined ? 1 : +sx || 0;
          t[0] = x; t[5] = sy === undefined ? x : +sy || 0; t[10] = sz === undefined ? 1 : +sz || 0;
          const st = stateOf(this);
          return make(globalThis.DOMMatrix, mulm(st.m, t), st.d2 && (sz === undefined || sz === 1));
        });
        method('rotate', function (deg) {
          const r = (+deg || 0) * Math.PI / 180, cs = Math.cos(r), sn = Math.sin(r);
          const t = ident(); t[0] = cs; t[1] = sn; t[4] = -sn; t[5] = cs;
          const st = stateOf(this);
          return make(globalThis.DOMMatrix, mulm(st.m, t), st.d2);
        });
        method('flipX', function () { const t = ident(); t[0] = -1;
          return make(globalThis.DOMMatrix, mulm(stateOf(this).m, t), stateOf(this).d2); });
        method('flipY', function () { const t = ident(); t[5] = -1;
          return make(globalThis.DOMMatrix, mulm(stateOf(this).m, t), stateOf(this).d2); });
        method('inverse', function () {
          const m = stateOf(this).m;
          const det = m[0] * m[5] - m[1] * m[4];
          if (!det) return make(globalThis.DOMMatrix, new Array(16).fill(NaN), false);
          const r = ident();
          r[0] = m[5] / det; r[1] = -m[1] / det; r[4] = -m[4] / det; r[5] = m[0] / det;
          r[12] = (m[4] * m[13] - m[5] * m[12]) / det;
          r[13] = (m[1] * m[12] - m[0] * m[13]) / det;
          return make(globalThis.DOMMatrix, r, true);
        });
        method('transformPoint', function (pt) {
          const m = stateOf(this).m;
          const x = (pt && +pt.x) || 0, y = (pt && +pt.y) || 0, z = (pt && +pt.z) || 0;
          const w = pt && pt.w !== undefined ? +pt.w : 1;
          const X = m[0] * x + m[4] * y + m[8] * z + m[12] * w;
          const Y = m[1] * x + m[5] * y + m[9] * z + m[13] * w;
          const Z = m[2] * x + m[6] * y + m[10] * z + m[14] * w;
          const W = m[3] * x + m[7] * y + m[11] * z + m[15] * w;
          const P2 = globalThis.DOMPoint || globalThis.DOMPointReadOnly;
          return P2 ? new P2(X, Y, Z, W) : { x: X, y: Y, z: Z, w: W };
        });
        method('toFloat32Array', function () { return new Float32Array(stateOf(this).m); });
        method('toFloat64Array', function () { return new Float64Array(stateOf(this).m); });
        method('toJSON', function () {
          const st = stateOf(this), o = {};
          for (const k of Object.keys(IDX)) o[k] = st.m[IDX[k]];
          for (const k of Object.keys(ALIAS)) o[k] = st.m[IDX[ALIAS[k]]];
          o.is2D = st.d2; o.isIdentity = this.isIdentity;
          return o;
        });
        method('toString', function () {
          const st = stateOf(this), m = st.m;
          if (st.d2) return 'matrix(' + [m[0], m[1], m[4], m[5], m[12], m[13]].join(', ') + ')';
          return 'matrix3d(' + m.join(', ') + ')';
        });
        try {
          if (!Object.getOwnPropertyDescriptor(P, Symbol.toStringTag)) {
            Object.defineProperty(P, Symbol.toStringTag, { value: Cls.name, configurable: true });
          }
        } catch (e) {}
      };
      shape(RO, false);
      shape(MM, true);
      // Constructors: both parse the argument the same way.
      for (const Cls of [RO, MM]) {
        if (!Cls) continue;
        const orig = Cls;
        const ctor = function (init) {
          if (!(this instanceof ctor)) {
            throw __pt_mkErr(TypeError, "Failed to construct '" + orig.name + "': " +
              'Please use the \'new\' operator, this DOM object constructor cannot be called as a function.');
          }
          const o = Object.create(new.target && new.target.prototype ? new.target.prototype : orig.prototype);
          stateOf(o);
          return fromInit(o, init);
        };
        Object.defineProperty(ctor, 'prototype', { value: orig.prototype, writable: false, enumerable: false });
        try { Object.defineProperty(ctor, 'name', { value: orig.name, configurable: true }); } catch (e) {}
        try { Object.defineProperty(orig.prototype, 'constructor', { value: ctor, writable: true, configurable: true }); } catch (e) {}
        for (const st of ['fromMatrix', 'fromFloat32Array', 'fromFloat64Array']) {
          try {
            Object.defineProperty(ctor, st, {
              value: function (v) {
                const o = Object.create(orig.prototype);
                stateOf(o);
                if (st === 'fromMatrix' && v && typeof v === 'object' && !ArrayBuffer.isView(v) && !Array.isArray(v)) {
                  const src = ST.get(v);
                  if (src) { ST.set(o, { m: __s_slice(src.m), d2: src.d2 }); return o; }
                  const arr = [];
                  for (const k of Object.keys(IDX)) arr[IDX[k]] = v[k] === undefined ? ident()[IDX[k]] : +v[k] || 0;
                  ST.set(o, { m: arr, d2: v.is2D !== false });
                  return o;
                }
                return fromInit(o, v);
              },
              writable: true, enumerable: false, configurable: true,
            });
          } catch (e) {}
        }
        globalThis[orig.name] = globalThis.__pt_native ? __pt_native(ctor) : ctor;
      }
      if (globalThis.WebKitCSSMatrix) globalThis.WebKitCSSMatrix = globalThis.DOMMatrix;
    }
  } catch (e) {}

  // WebGPU: the collector branch renders a triangle into a texture and reads
  // it back (a 4096-byte report block).
  //
  // Rendered by our GL: WGSL is translated to GLSL ES and goes through the
  // normal pipeline. The translation is narrow, covering exactly what such
  // probes use: entry points with `@builtin`/`@location`, vector types,
  // literal arrays and arithmetic. Anything unknown is not translated and the
  // pipeline honestly fails instead of guessing.
  try {
    const G = globalThis;
    const iface = (n) => (G[n] && G[n].prototype) || null;
    const put = (P, name, fn) => {
      if (!P) return;
      try {
        Object.defineProperty(P, name, {
          value: G.__pt_native ? G.__pt_native(fn) : fn,
          writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
    };
    const getter = (P, name, fn) => {
      if (!P) return;
      try { Object.defineProperty(P, name, { get: fn, enumerable: true, configurable: true }); } catch (e) {}
    };
    const mk = (n) => (iface(n) ? Object.create(iface(n)) : {});
    const ST = new WeakMap();
    const st = (o) => ST.get(o) || {};
    // WebGPU trace (NOKK_TRACE_GPU=1): shaders, descriptors, buffers and calls
    // the program sends, invisible to the page.
    const glog = (what, v) => {
      try { if (!G.__pt_gpuTrace) return; (G.__pt_parentConsole || console).error('[gpu] ' + what + ' ' + (typeof v === 'string' ? v : JSON.stringify(v, (k, x) => (x && typeof x === 'object' && !Array.isArray(x) && ST.has(x)) ? '<' + (x.constructor && x.constructor.name) + '>' : (ArrayBuffer.isView(x) ? Array.from(x.subarray ? x.subarray(0, 64) : x).join(',') : x)))); } catch (e) {}
    };

    // ---- WGSL -> GLSL ES 3.00 ------------------------------------------
    const wgslNum = (t) => __s_replace(t, /(^|[^\w.])\.(\d)/g, '$10.$2');
    const wgslTypes = (t) => __s_replace(__s_replace(__s_replace(__s_replace(__s_replace(__s_replace(__s_replace(__s_replace(__s_replace(t, /\bvec2f\b/g, 'vec2'), /\bvec3f\b/g, 'vec3'), /\bvec4f\b/g, 'vec4'), /\bvec2<f32>/g, 'vec2'), /\bvec3<f32>/g, 'vec3'), /\bvec4<f32>/g, 'vec4'), /\bf32\b/g, 'float'), /\bi32\b/g, 'int'), /\bu32\b/g, 'uint');
    // Integers inside vector constructors must become floats.
    const floatLits = (t) => __s_replace(t, /vec([234])\(([^()]*)\)/g, (m, n, args) =>
      'vec' + n + '(' + __s_split(args, ',').map((a) => {
        const s = __s_trim(a);
        return /^-?\d+$/.test(s) ? s + '.0' : a;
      }).join(',') + ')');
    const entry = (code, kind) => {
      // Parameter lists contain nested parens (`@builtin(vertex_index) i:u32`),
      // so the list is found by counting parens, not with a regex.
      const head = new RegExp('@' + kind + '\\s+fn\\s+(\\w+)\\s*\\(', 'm');
      const h = head.exec(code);
      if (!h) return null;
      let d = 1, k = h.index + h[0].length;
      for (; k < code.length && d; k++) {
        if (code[k] === '(') d++;
        else if (code[k] === ')') d--;
      }
      const params = __s_slice(code, h.index + h[0].length, k - 1);
      const rest = /^\s*->\s*([^{]*)\{/.exec(__s_slice(code, k));
      if (!rest) return null;
      const m = { 1: h[1], 2: params, 3: rest[1], index: h.index,
        0: __s_slice(code, h.index, k + rest[0].length) };
      // Body runs to the matching closing brace.
      let depth = 1, i = m.index + m[0].length;
      for (; i < code.length && depth; i++) {
        if (code[i] === '{') depth++;
        else if (code[i] === '}') depth--;
      }
      return { name: m[1], params: m[2], ret: __s_trim(m[3]), body: __s_slice(code, m.index + m[0].length, i - 1) };
    };
    const translate = (code) => {
      const v = entry(code, 'vertex'), f = entry(code, 'fragment');
      if (!v || !f) return null;
      const prep = (b) => __s_replace(__s_replace(__s_replace(floatLits(wgslTypes(wgslNum(b))), /\bvar\s+(\w+)\s*=\s*array<([^,]+),\s*(\d+)>\s*\(/g, '$2 $1[$3] = $2[$3]('), /\blet\s+/g, 'float '), /\bvar\s+/g, 'float ');
      let vs = prep(v.body), fs = prep(f.body);
      // The vertex index parameter becomes a GL builtin variable.
      const vi = /@builtin\(vertex_index\)\s*(\w+)/.exec(v.params);
      if (vi) vs = __s_replace(vs, new RegExp('\\b' + vi[1] + '\\b', 'g'), 'gl_VertexID');
      const ii = /@builtin\(instance_index\)\s*(\w+)/.exec(v.params);
      if (ii) vs = __s_replace(vs, new RegExp('\\b' + ii[1] + '\\b', 'g'), 'gl_InstanceID');
      if (!/@builtin\(position\)/.test(v.ret)) return null;
      vs = __s_replace(vs, /return\s+([^;]+);/g, 'gl_Position = $1;');
      if (!/@location\(0\)/.test(f.ret)) return null;
      fs = __s_replace(fs, /return\s+([^;]+);/g, '__pt_out = $1;');
      // Untranslated code keeps WGSL markers: a sign of failure.
      if (/[@]|array<|->/.test(vs + fs)) return null;
      return {
        vs: '#version 300 es\nvoid main() {\n' + vs + '\n}\n',
        fs: '#version 300 es\nprecision highp float;\nout vec4 __pt_out;\nvoid main() {\n' + fs + '\n}\n',
      };
    };

    // ---- drawing through our GL ----------------------------------------
    // The GL canvas is internal: our WebGPU sits on WebGL, and going through
    // `OffscreenCanvas.getContext` would show the page an extra context the
    // browser does not have.
    // A context shielded from the page: methods come from a snapshot taken
    // before page code, not from a prototype the page may have wrapped. Used
    // only by our WebGPU.
    const shield = (gl) => {
      const keep = globalThis.__pt_orig;
      if (!gl || !keep) return gl;
      const table = (globalThis.WebGL2RenderingContext && gl instanceof WebGL2RenderingContext
        ? keep.WebGL2RenderingContext : keep.WebGLRenderingContext) || null;
      if (!table) return gl;
      const bound = new Map();
      return __pt_proxy(gl, {
        get(t, k) {
          const own = table[k];
          if (typeof own === 'function') {
            let f = bound.get(k);
            if (!f) { f = own.bind(t); bound.set(k, f); }
            return f;
          }
          const v = t[k];
          return typeof v === 'function' ? v.bind(t) : v;
        },
      });
    };
    const glFor = (w, h) => {
      if (globalThis.__pt_privateCanvas && globalThis.__pt_privateCtx) {
        const c = globalThis.__pt_privateCanvas(w, h);
        return shield(globalThis.__pt_privateCtx(c, 'webgl2')
          || globalThis.__pt_privateCtx(c, 'webgl'));
      }
      const c = new G.OffscreenCanvas(w, h);
      return shield(c.getContext('webgl2') || c.getContext('webgl'));
    };
    const runPass = (tex, pass) => {
      const gl = tex.gl;
      if (!gl) return;
      gl.viewport(0, 0, tex.w, tex.h);
      // GPUColor is a dict (r, g, b, a) or a sequence [r, g, b, a]; with an
      // array the alpha used to default to 1, giving opaque black instead of
      // Chrome's transparent background.
      const c0 = pass.clear || { r: 0, g: 0, b: 0, a: 0 };
      const cv = Array.isArray(c0) || (c0 && typeof c0 === 'object' && typeof c0[Symbol.iterator] === 'function')
        ? (() => { const a = Array.from(c0); return { r: a[0], g: a[1], b: a[2], a: a[3] }; })() : c0;
      if (pass.loadOp === 'clear') {
        gl.clearColor(+cv.r || 0, +cv.g || 0, +cv.b || 0, cv.a === undefined ? 1 : +cv.a);
        gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
      }
      for (const d of pass.draws) {
        const p = d.pipeline && d.pipeline.program;
        if (!p) continue;
        gl.useProgram(p);
        gl.drawArrays(gl.TRIANGLES, d.first | 0, d.count | 0);
      }
    };

    const GPUDeviceP = iface('GPUDevice');
    const GPUQueueP = iface('GPUQueue');
    if (GPUDeviceP && GPUQueueP) {
      put(GPUDeviceP, 'createShaderModule', function createShaderModule(desc) {
        glog('shader', String((desc && desc.code) || ''));
        const o = mk('GPUShaderModule');
        ST.set(o, { code: String((desc && desc.code) || '') });
        return o;
      });
      put(GPUDeviceP, 'createTexture', function createTexture(desc) {
        const size = (desc && desc.size) || [1, 1];
        const w = (Array.isArray(size) ? size[0] : size.width) | 0;
        const h = (Array.isArray(size) ? (size[1] === undefined ? 1 : size[1]) : size.height) | 0;
        const o = mk('GPUTexture');
        ST.set(o, { w: Math.max(1, w), h: Math.max(1, h), gl: glFor(Math.max(1, w), Math.max(1, h)),
          format: (desc && desc.format) || 'rgba8unorm', usage: (desc && desc.usage) >>> 0 });
        return o;
      });
      put(GPUDeviceP, 'createBuffer', function createBuffer(desc) {
        const o = mk('GPUBuffer');
        const n = Math.max(0, (desc && desc.size) | 0);
        ST.set(o, { size: n, bytes: new Uint8Array(n), mapped: null });
        return o;
      });
      put(GPUDeviceP, 'createRenderPipeline', function createRenderPipeline(desc) {
        glog('pipeline', desc);
        const o = mk('GPURenderPipeline');
        const mod = desc && desc.vertex && desc.vertex.module;
        const src = mod ? st(mod).code : '';
        ST.set(o, { src });
        return o;
      });
      put(GPUDeviceP, 'createCommandEncoder', function createCommandEncoder() {
        const o = mk('GPUCommandEncoder');
        ST.set(o, { cmds: [] });
        return o;
      });
      put(GPUDeviceP, 'createBindGroup', function createBindGroup() { return mk('GPUBindGroup'); });
      put(GPUDeviceP, 'createPipelineLayout', function createPipelineLayout() { return mk('GPUPipelineLayout'); });
      put(GPUDeviceP, 'createSampler', function createSampler() { return mk('GPUSampler'); });
      put(GPUDeviceP, 'createComputePipeline', function createComputePipeline() { return mk('GPUComputePipeline'); });
      put(GPUDeviceP, 'pushErrorScope', function pushErrorScope() {});
      put(GPUDeviceP, 'popErrorScope', function popErrorScope() { return Promise.resolve(null); });

      const TexP = iface('GPUTexture');
      put(TexP, 'createView', function createView() {
        const o = mk('GPUTextureView');
        ST.set(o, { tex: this });
        return o;
      });
      put(TexP, 'destroy', function destroy() {});
      for (const [k, f] of [['width', (s) => s.w], ['height', (s) => s.h], ['depthOrArrayLayers', () => 1],
        ['mipLevelCount', () => 1], ['sampleCount', () => 1], ['dimension', () => '2d'],
        ['format', (s) => s.format || 'rgba8unorm'], ['usage', (s) => s.usage || 0]]) {
        getter(TexP, k, function () { return f(st(this)); });
      }

      const EncP = iface('GPUCommandEncoder');
      put(EncP, 'beginRenderPass', function beginRenderPass(desc) {
        const at = (desc && desc.colorAttachments && desc.colorAttachments[0]) || {};
        glog('beginRenderPass', { loadOp: at.loadOp, storeOp: at.storeOp, clear: at.clearValue, tex: at.view && st(st(at.view).tex) && { w: st(st(at.view).tex).w, h: st(st(at.view).tex).h, format: st(st(at.view).tex).format } });
        const view = at.view;
        const tex = view ? st(view).tex : null;
        const pass = { tex, loadOp: at.loadOp, clear: at.clearValue, draws: [] };
        st(this).cmds.push({ kind: 'pass', pass });
        const o = mk('GPURenderPassEncoder');
        ST.set(o, { pass });
        return o;
      });
      put(EncP, 'copyTextureToBuffer', function copyTextureToBuffer(src, dst, size) {
        st(this).cmds.push({ kind: 'copy', tex: src && src.texture, buf: dst && dst.buffer,
          bytesPerRow: (dst && dst.bytesPerRow) | 0, size });
      });
      put(EncP, 'copyBufferToBuffer', function copyBufferToBuffer() {});
      put(EncP, 'finish', function finish() {
        const o = mk('GPUCommandBuffer');
        ST.set(o, { cmds: __s_slice(st(this).cmds) });
        return o;
      });

      const PassP = iface('GPURenderPassEncoder');
      put(PassP, 'setPipeline', function setPipeline(p) { st(this).pending = p; });
      put(PassP, 'setBindGroup', function setBindGroup() {});
      put(PassP, 'setVertexBuffer', function setVertexBuffer(slot, buf, off, size) { glog('setVertexBuffer', { slot, size: st(buf).size, off, bytes: st(buf).bytes && new Float32Array(st(buf).bytes.buffer, 0, Math.min(16, st(buf).size >> 2)) }); });
      put(PassP, 'draw', function draw(count, instances, first) {
        glog('draw', { count, instances, first });
        st(this).pass.draws.push({ pipeline: st(this).pending, count: count | 0, first: first | 0 });
      });
      put(PassP, 'drawIndexed', function drawIndexed() {});
      put(PassP, 'end', function end() {});

      put(GPUQueueP, 'submit', function submit(list) {
        for (const cb of (list || [])) {
          for (const c of (st(cb).cmds || [])) {
            if (c.kind === 'pass') {
              const tex = c.pass.tex ? st(c.pass.tex) : null;
              if (!tex || !tex.gl) continue;
              // Pipelines are built here: the program lives in the same
              // context that is drawn into.
              for (const d of c.pass.draws) {
                const ps = d.pipeline ? st(d.pipeline) : null;
                if (!ps || ps.program !== undefined) continue;
                const t = translate(ps.src || '');
                ps.program = null;
                if (!t) continue;
                const gl = tex.gl;
                const vs = gl.createShader(gl.VERTEX_SHADER);
                gl.shaderSource(vs, t.vs); gl.compileShader(vs);
                const fs = gl.createShader(gl.FRAGMENT_SHADER);
                gl.shaderSource(fs, t.fs); gl.compileShader(fs);
                if (!gl.getShaderParameter(vs, gl.COMPILE_STATUS) ||
                    !gl.getShaderParameter(fs, gl.COMPILE_STATUS)) continue;
                const pr = gl.createProgram();
                gl.attachShader(pr, vs); gl.attachShader(pr, fs); gl.linkProgram(pr);
                if (!gl.getProgramParameter(pr, gl.LINK_STATUS)) continue;
                ps.program = pr;
              }
              for (const d of c.pass.draws) d.pipeline = d.pipeline ? st(d.pipeline) : null;
              runPass(tex, c.pass);
            } else if (c.kind === 'copy') {
              const tex = c.tex ? st(c.tex) : null;
              const buf = c.buf ? st(c.buf) : null;
              if (!tex || !buf || !tex.gl) continue;
              const gl = tex.gl;
              const px = new Uint8Array(tex.w * tex.h * 4);
              gl.readPixels(0, 0, tex.w, tex.h, gl.RGBA, gl.UNSIGNED_BYTE, px);
              // Buffer rows are aligned (`bytesPerRow` exceeds the width) and
              // top-down: GL's origin is at the bottom, WebGPU's at the top.
              const stride = c.bytesPerRow || tex.w * 4;
              for (let y = 0; y < tex.h; y++) {
                const from = (tex.h - 1 - y) * tex.w * 4, to = y * stride;
                if (to + tex.w * 4 > buf.bytes.length) break;
                buf.bytes.set(px.subarray(from, from + tex.w * 4), to);
              }
            }
          }
        }
      });
      put(GPUQueueP, 'writeBuffer', function writeBuffer(buf, off, data, dataOff, size) {
        glog('writeBuffer', { size: st(buf).size, off, data: ArrayBuffer.isView(data) ? data : new Uint8Array(data) });
        try { const bytes = st(buf).bytes; if (bytes) { const src = ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data); bytes.set(src.subarray(dataOff | 0, size === undefined ? src.length : (dataOff | 0) + size), off | 0); } } catch (e) {}
      });
      put(GPUQueueP, 'writeTexture', function writeTexture() {});
      // Chrome's GPU work does not finish at once: the promise resolves a
      // frame or two later (3-14 ms in a probe), not in the same microtask.
      const RAF = G.requestAnimationFrame, RA = Reflect.apply;
      const afterFrame = () => new Promise((res) => {
        try { RA(RAF, G, [() => res()]); } catch (e) { res(); }
      });
      put(GPUQueueP, 'onSubmittedWorkDone', function onSubmittedWorkDone() { return afterFrame(); });

      const BufP = iface('GPUBuffer');
      put(BufP, 'mapAsync', function mapAsync() { return afterFrame(); });
      put(BufP, 'getMappedRange', function getMappedRange(offset, size) {
        glog('getMappedRange', { offset, size, nz: st(this).bytes && __s_slice(Array.from(st(this).bytes).map((b, i) => (b && (i & 3) !== 3) ? i + ':' + b : '').filter(Boolean), 0, 160).join(' ') });
        const s = st(this);
        const o = offset | 0;
        const n = size === undefined ? s.size - o : size | 0;
        const out = new ArrayBuffer(Math.max(0, n));
        new Uint8Array(out).set(s.bytes.subarray(o, o + n));
        s.mapped = out;
        return out;
      });
      put(BufP, 'unmap', function unmap() { st(this).mapped = null; });
      put(BufP, 'destroy', function destroy() {});
      getter(BufP, 'size', function () { return st(this).size || 0; });
      getter(BufP, 'usage', function () { return 0; });
      getter(BufP, 'mapState', function () { return st(this).mapped ? 'mapped' : 'unmapped'; });
    }

    // Canvas configuration: the page reads it back.
    const CtxP = iface('GPUCanvasContext');
    if (CtxP) {
      const CONF = new WeakMap();
      put(CtxP, 'configure', function configure(desc) { CONF.set(this, desc || null); });
      put(CtxP, 'unconfigure', function unconfigure() { CONF.delete(this); });
      put(CtxP, 'getConfiguration', function getConfiguration() {
        const d = CONF.get(this);
        if (!d) return null;
        return {
          device: d.device, format: d.format,
          usage: d.usage === undefined ? 0x10 : d.usage,
          viewFormats: d.viewFormats ? Array.from(d.viewFormats) : [],
          colorSpace: d.colorSpace || 'srgb',
          toneMapping: d.toneMapping || { mode: 'standard' },
          alphaMode: d.alphaMode || 'opaque',
        };
      });
    }
  } catch (e) {}

  // `createImageBitmap`: the bitmap carries the source's pixels, knows its
  // size, can be closed, and accepts cropping and resizing. Fingerprinters
  // work with images exactly this way.
  try {
    const D = globalThis.document;
    // The canvas layer's helper is not visible here, and the method name must
    // look native: `__pt_native` does the same.
    const mask = (f, name) => {
      try { if (f.name !== name) Object.defineProperty(f, 'name', { value: name, configurable: true }); } catch (e) {}
      return globalThis.__pt_native ? globalThis.__pt_native(f) : f;
    };
    // Our own canvas, not via `document.createElement`, which a page may have
    // wrapped; the browser's `createImageBitmap` creates no elements.
    const newCanvas = (w, h) => {
      if (globalThis.__pt_privateCanvas) return globalThis.__pt_privateCanvas(w, h);
      if (!D || !D.createElement) return null;
      const el = D.createElement('canvas');
      __pt_write(el, 'width', w); __pt_write(el, 'height', h);
      return el;
    };
    const ctx2d = (c) => (globalThis.__pt_privateCtx
      ? globalThis.__pt_privateCtx(c, '2d')
      : (c && c.getContext('2d')));
    // Drawing goes through the pre-page snapshot: the engine fills its
    // intermediate canvas silently, as the browser does.
    const draw = (g, args) => {
      const O = globalThis.__pt_orig;
      return (O && O.drawImage ? O.drawImage : g.drawImage).apply(g, args);
    };
    const put = (g, args) => {
      const O = globalThis.__pt_orig;
      return (O && O.putImageData ? O.putImageData : g.putImageData).apply(g, args);
    };
    // The bitmap prototype is shaped once: in the browser width and height are
    // read from the prototype, not the object, and `close` zeroes them.
    const shape = () => {
      const B = globalThis.ImageBitmap;
      const P = B && B.prototype;
      if (!P || P.__ptShaped) return P;
      try { Object.defineProperty(P, '__ptShaped', { value: true }); } catch (e) {}
      const dim = (k) => ({
        get: mask(function () {
          const st = this && this.__ptImageBitmap;
          return st ? (st.closed ? 0 : st[k] | 0) : undefined;
        }, 'get ' + k),
        enumerable: true, configurable: true,
      });
      try { Object.defineProperty(P, 'width', dim('w')); } catch (e) {}
      try { Object.defineProperty(P, 'height', dim('h')); } catch (e) {}
      try {
        Object.defineProperty(P, 'close', {
          value: mask(function close() {
            const st = this && this.__ptImageBitmap;
            if (st) st.closed = true;
          }, 'close'),
          writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
      try {
        if (!Object.getOwnPropertyDescriptor(P, Symbol.toStringTag)) {
          Object.defineProperty(P, Symbol.toStringTag, { value: 'ImageBitmap', configurable: true });
        }
      } catch (e) {}
      return P;
    };
    const makeBitmap = (surf, w, h) => {
      const P = shape();
      const b = Object.create(P || Object.prototype);
      Object.defineProperty(b, '__ptImageBitmap', { value: { surf, w: w | 0, h: h | 0, closed: false } });
      return b;
    };
    Object.defineProperty(globalThis, '__pt_makeBitmap', { value: makeBitmap, writable: true, configurable: true });

    // Bitmap from a `Blob`: size is read from the image header, and it is
    // drawn via a data URL, the same path as `<img>`.
    const fromBlob = (b) => {
      let bin = '';
      try { bin = b.__ptText ? b.__ptText() : ''; } catch (e) { bin = ''; }
      if (!bin) return null;
      let w = 0, h = 0;
      const at = (i) => __s_charCodeAt(bin, i) & 0xff;
      if (__s_charCodeAt(bin, 0) === 0x89 && __s_slice(bin, 1, 4) === 'PNG') {
        w = (at(16) << 24) | (at(17) << 16) | (at(18) << 8) | at(19);
        h = (at(20) << 24) | (at(21) << 16) | (at(22) << 8) | at(23);
      } else if (at(0) === 0xff && at(1) === 0xd8) {
        for (let i = 2; i + 9 < bin.length;) {
          if (at(i) !== 0xff) { i++; continue; }
          const m = at(i + 1), len = (at(i + 2) << 8) | at(i + 3);
          if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) {
            h = (at(i + 5) << 8) | at(i + 6); w = (at(i + 7) << 8) | at(i + 8); break;
          }
          i += 2 + len;
        }
      }
      if (w <= 0 || h <= 0) return null;
      let url = '';
      try { url = 'data:' + (b.type || 'image/png') + ';base64,' + btoa(bin); } catch (e) { return null; }
      return { src: url, width: w, height: h, naturalWidth: w, naturalHeight: h };
    };

    const intrinsic = (src) => {
      if (!src || typeof src !== 'object') return null;
      const st = src.__ptImageBitmap;
      if (st) return [st.closed ? 0 : st.w, st.closed ? 0 : st.h];
      if (src.__ptO) return [src.__ptO.w | 0, src.__ptO.h | 0];
      if (src.naturalWidth) return [src.naturalWidth | 0, src.naturalHeight | 0];
      if (src.videoWidth) return [src.videoWidth | 0, src.videoHeight | 0];
      if (src.codedWidth) return [src.codedWidth | 0, src.codedHeight | 0];
      if (typeof src.width === 'number') return [src.width | 0, src.height | 0];
      return null;
    };
    const accepted = (src) => !!(src && typeof src === 'object' && (
      src.localName === 'img' || src.localName === 'canvas' || src.localName === 'video' ||
      src.__ptImageBitmap || src.__ptO || src.__ptSurf || src.__ptC2d ||
      (src.data && typeof src.width === 'number' && typeof src.height === 'number') ||
      (globalThis.Blob && src instanceof globalThis.Blob) ||
      typeof src.src === 'string'));

    const fn = function createImageBitmap(image) {
      const n = arguments.length;
      if (n < 1) {
        return Promise.reject(__pt_mkErr(TypeError, 
          "Failed to execute 'createImageBitmap' on 'Window': " +
          '1 argument required, but only 0 present.'));
      }
      if (!accepted(image)) {
        return Promise.reject(__pt_mkErr(TypeError, 
          "Failed to execute 'createImageBitmap' on 'Window': " +
          "The provided value is not of type '(Blob or CSSImageValue or HTMLCanvasElement or " +
          "HTMLImageElement or HTMLVideoElement or ImageBitmap or ImageData or OffscreenCanvas " +
          "or SVGImageElement or VideoFrame)'."));
      }
      let sx = 0, sy = 0, sw = 0, sh = 0, opts = null, cropped = false;
      if (n >= 5 && typeof arguments[1] === 'number') {
        sx = arguments[1] | 0; sy = arguments[2] | 0;
        sw = arguments[3] | 0; sh = arguments[4] | 0;
        opts = arguments[5] || null;
        cropped = true;
        if (sw === 0 || sh === 0) {
          const e = __pt_mkErr(globalThis.DOMException || Error, 
            "Failed to execute 'createImageBitmap' on 'Window': The crop rect width is 0.",
            'RangeError');
          e.name = 'RangeError';
          return Promise.reject(e);
        }
      } else {
        opts = (n >= 2 ? arguments[1] : null) || null;
      }
      if (globalThis.Blob && image instanceof globalThis.Blob) {
        const shim = fromBlob(image);
        if (!shim) {
          const e = __pt_mkErr(globalThis.DOMException || Error, 
            "Failed to execute 'createImageBitmap' on 'Window': " +
            'The source image could not be decoded.', 'InvalidStateError');
          e.name = 'InvalidStateError';
          return Promise.reject(e);
        }
        image = shim;
      }
      const size = intrinsic(image);
      if (!size || size[0] <= 0 || size[1] <= 0) {
        const e = __pt_mkErr(globalThis.DOMException || Error, 
          "Failed to execute 'createImageBitmap' on 'Window': The source image " +
          'width is 0.', 'InvalidStateError');
        e.name = 'InvalidStateError';
        return Promise.reject(e);
      }
      if (!cropped) { sw = size[0]; sh = size[1]; }
      let ow = sw, oh = sh;
      const rw = opts && opts.resizeWidth | 0, rh = opts && opts.resizeHeight | 0;
      if (rw > 0 && rh > 0) { ow = rw; oh = rh; }
      else if (rw > 0) { ow = rw; oh = Math.max(1, Math.round(sh * rw / sw)); }
      else if (rh > 0) { oh = rh; ow = Math.max(1, Math.round(sw * rh / sh)); }

      const out = newCanvas(ow, oh);
      const g = out && ctx2d(out);
      if (g) {
        try {
          if (image.data && typeof image.width === 'number' && !image.localName) {
            // `ImageData` cannot be drawn directly: it goes onto an
            // intermediate canvas, which is then copied with crop and scale.
            const tmp = newCanvas(size[0], size[1]);
            const tg = tmp && ctx2d(tmp);
            if (tg) { put(tg, [image, 0, 0]); draw(g, [tmp, sx, sy, sw, sh, 0, 0, ow, oh]); }
          } else {
            draw(g, [image, sx, sy, sw, sh, 0, 0, ow, oh]);
          }
        } catch (e) {}
      }
      const surf = out && out.__ptSurf;
      return Promise.resolve(makeBitmap(surf, ow, oh));
    };
    Object.defineProperty(globalThis, 'createImageBitmap', {
      value: globalThis.__pt_native ? __pt_native(fn) : fn,
      writable: true, enumerable: true, configurable: true,
    });
  } catch (e) {}
  // Statics are placed by table after the DOM layer defined them, and the
  // stub overwrote the real codec check; restore it here. This is **not**
  // `canPlayType`: the streaming source has its own list, captured from
  // Chrome 151 over 597 strings. It is both wider (`video/mp2t` is
  // supported though `canPlayType` says nothing) and narrower (`mp3`,
  // `mp4a.69` and `video/x-matroska` are not supported at all).
  try {
    if (globalThis.MediaSource) {
      const MSE = {
        'video/mp4': ['avc1.', 'avc3.', 'hev1.', 'hvc1.', 'av01.', 'vp09.', 'mp4a.40.2',
                      'mp4a.40.5', 'opus', 'flac'],
        'video/webm': ['vp8', 'vp9', 'vp09.', 'av01.', 'opus', 'vorbis'],
        'video/mp2t': ['avc1.', 'avc3.', 'mp4a.40.', 'mp4a.69', 'mp4a.6b', 'mp3'],
        'audio/mp4': ['mp4a.40.2', 'mp4a.40.5', 'opus', 'flac'],
        'audio/webm': ['opus', 'vorbis'],
        'audio/mpeg': [],
        'audio/aac': [],
      };
      // Only these three are accepted without a codec list; other containers
      // need more than a name.
      const BARE = new Set(['audio/mpeg', 'audio/aac', 'video/mp2t']);
      const fn = function isTypeSupported(type) {
        const t = __s_trim(String(type == null ? '' : type));
        const semi = __s_indexOf(t, ';');
        const mime = __s_toLowerCase(__s_trim(semi < 0 ? t : __s_slice(t, 0, semi)));
        const rest = semi < 0 ? '' : __s_slice(t, semi + 1);
        const m = /codecs\s*=\s*"?([^"]*)"?/i.exec(rest);
        const codecs = m ? __s_split(m[1], ',').map((c) => __s_toLowerCase(__s_trim(c))).filter(Boolean) : [];
        const allowed = MSE[mime];
        if (!allowed) return false;
        if (!codecs.length) return BARE.has(mime);
        return codecs.every((c) => allowed.some(
          (a) => (__s_charAt(a, a.length - 1) === '.' ? __s_indexOf(c, a) === 0 : c === a)));
      };
      Object.defineProperty(globalThis.MediaSource, 'isTypeSupported', {
        value: globalThis.__pt_native ? __pt_native(fn) : fn,
        writable: true, enumerable: false, configurable: true,
      });
    }
  } catch (e) {}

  // Members the browser declares on the prototype but we kept on the object.
  // The property becomes an accessor over hidden instance state: our own
  // constructor's `this.protocol = 'https:'` goes through the setter, so
  // behaviour is unchanged while the instance's `Object.keys` becomes empty,
  // as in the browser. A method we lack entirely is declared empty.
  // Layers that shape their prototypes later (audio nodes, on first node
  // creation) check whether a name is taken and would yield to ours, so mark
  // what is declared here as free for them.
  const stubs = globalThis.__pt_stubMembers;
  const liftSlots = stubs.slots;
  const named = (f) => { try { stubs.add(f); } catch (e) {} return native(f); };

  const LIFT = __IFACE_LIFT__;
  for (const iface of Object.keys(LIFT)) {
    const C = globalThis[iface];
    let P;
    try { P = C && C.prototype; } catch (e) { continue; }
    if (!P) continue;
    const spec = LIFT[iface];
    for (const k of spec.a || []) {
      if (Object.prototype.hasOwnProperty.call(P, k)) continue;
      try {
        const pair = Object.getOwnPropertyDescriptor({
          get [k]() { const st = liftSlots.get(this); return st && k in st ? st[k] : undefined; },
          set [k](v) {
            let st = liftSlots.get(this);
            if (!st) { st = Object.create(null); try { liftSlots.set(this, st); } catch (e2) { return; } }
            st[k] = v;
          },
        }, k);
        Object.defineProperty(P, k, { get: named(pair.get), set: named(pair.set), enumerable: true, configurable: true });
      } catch (e) {}
    }
    for (const k of Object.keys(spec.m || {})) {
      if (Object.prototype.hasOwnProperty.call(P, k)) continue;
      try {
        const n = spec.m[k];
        const f = n === 0 ? ({ [k]() {} })[k] : n === 1 ? ({ [k](a) {} })[k] : n === 2 ? ({ [k](a, b) {} })[k] : ({ [k](a, b, c) {} })[k];
        if (n > 3) Object.defineProperty(f, 'length', { value: n, configurable: true });
        Object.defineProperty(P, k, {
          value: named(f), writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
    }
  }

  // In a fresh profile `Notification.permission` is "default": the user has
  // neither granted nor denied.
  try {
    const N = globalThis.Notification;
    if (typeof N === 'function') {
      // In a cross-site frame (and its sandboxes) Chrome answers "denied"
      // without asking; the engine sets the flag at frame creation. Chrome's
      // `maxActions` on Linux is 2. Static order as in Chrome.
      const get = function () { return globalThis.__pt_crossSite ? 'denied' : 'default'; };
      const getMax = function () { return 2; };
      const ask = function () { return Promise.resolve(get()); };
      try { Object.defineProperty(get, 'name', { value: 'get permission', configurable: true }); } catch (e) {}
      try { Object.defineProperty(getMax, 'name', { value: 'get maxActions', configurable: true }); } catch (e) {}
      try { Object.defineProperty(ask, 'name', { value: 'requestPermission', configurable: true }); } catch (e) {}
      for (const k of ['permission', 'maxActions', 'requestPermission']) { try { delete N[k]; } catch (e) {} }
      Object.defineProperty(N, 'permission', { get: native(get), enumerable: true, configurable: true });
      Object.defineProperty(N, 'maxActions', { get: native(getMax), enumerable: true, configurable: true });
      Object.defineProperty(N, 'requestPermission', { value: native(ask), writable: true, enumerable: true, configurable: true });
    }
  } catch (e) {}


  const MOVES = __IFACE_PROTO_MOVES__;
  for (const iface of Object.keys(MOVES)) {
    const I = globalThis[iface];
    let P;
    try { P = I && I.prototype; } catch (e) { continue; }
    if (!P) continue;
    for (const name of Object.keys(MOVES[iface])) {
      let d;
      try { d = Object.getOwnPropertyDescriptor(P, name); } catch (e) { continue; }
      if (!d || !d.configurable) continue;
      const owners = MOVES[iface][name];
      let target = null, answered = false;
      for (let q = Object.getPrototypeOf(P); q; q = Object.getPrototypeOf(q)) {
        if (Object.prototype.hasOwnProperty.call(q, name)) { answered = true; break; }
        if (q === Object.prototype) break;
        let who = '';
        try { who = (q.constructor && q.constructor.name) || ''; } catch (e) {}
        if (__s_indexOf(owners, who) >= 0) { target = q; break; }
      }
      // The parent already provides this name, so our copy is redundant. With
      // neither a parent nor an answer, the name exists nowhere in the browser
      // (`Blob.prototype.toString`): remove it, but only if it carries nothing.
      if (!target && !answered && owners.length) continue;
      try { delete P[name]; } catch (e) { continue; }
      if (target) { try { Object.defineProperty(target, name, d); } catch (e) {} }
    }
  }
})();"#;

const WEB_SURFACE_TEMPLATE: &str = r##"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_charCodeAt = __sm(String.prototype.charCodeAt, 'charCodeAt');
  const T = {"window":{"#0":["TEMPORARY","pageXOffset","pageYOffset","scrollX","scrollY"],"#1":["PERSISTENT"],"#10":["screenLeft","screenTop","screenX","screenY"],"o":["GPUBufferUsage","GPUColorWrite","GPUMapMode","GPUShaderStage","GPUTextureUsage","Temporal","caches","clientInformation","cookieStore","crashReport","customElements","documentPictureInPicture","external","launchQueue","locationbar","menubar","navigation","personalbar","scheduler","scrollbars","sharedStorage","speechSynthesis","statusbar","styleMedia","toolbar","trustedTypes","viewport","visualViewport"],"F":["credentialless","crossOriginIsolated"],"x":["fence","frameElement","onabort","onafterprint","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onappinstalled","onauxclick","onbeforeinput","onbeforeinstallprompt","onbeforematch","onbeforeprint","onbeforetoggle","onbeforeunload","onbeforexrselect","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncuechange","ondblclick","ondevicemotion","ondeviceorientation","ondeviceorientationabsolute","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","ongamepadconnected","ongamepaddisconnected","ongotpointercapture","onhashchange","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onlanguagechange","onload","onloadeddata","onloadedmetadata","onloadstart","onlostpointercapture","onmessage","onmessageerror","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onoffline","ononline","onpagehide","onpagereveal","onpageshow","onpageswap","onpause","onplay","onplaying","onpointercancel","onpointerdown","onpointerenter","onpointerleave","onpointermove","onpointerout","onpointerover","onpointerrawupdate","onpointerup","onpopstate","onprogress","onratechange","onrejectionhandled","onreset","onresize","onscroll","onscrollend","onscrollsnapchange","onscrollsnapchanging","onsearch","onsecuritypolicyviolation","onseeked","onseeking","onselect","onselectionchange","onselectstart","onslotchange","onstalled","onstorage","onsubmit","onsuspend","ontimeupdate","ontoggle","ontransitioncancel","ontransitionend","ontransitionrun","ontransitionstart","onunhandledrejection","onunload","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","opener"],"u":["event"],"T":["isSecureContext","offscreenBuffering","originAgentCluster"],"N":["AbsoluteOrientationSensor","AbstractRange","Accelerometer","AnalyserNode","Animation","AnimationEffect","AnimationEvent","AnimationPlaybackEvent","AnimationTimeline","AnimationTrigger","AsyncDisposableStack","Attr","Audio","AudioBuffer","AudioBufferSourceNode","AudioData","AudioDecoder","AudioDestinationNode","AudioEncoder","AudioListener","AudioNode","AudioParam","AudioParamMap","AudioPlaybackStats","AudioProcessingEvent","AudioScheduledSourceNode","AudioSinkInfo","AudioWorklet","AudioWorkletNode","AuthenticatorAssertionResponse","AuthenticatorAttestationResponse","AuthenticatorResponse","BackgroundFetchManager","BackgroundFetchRecord","BackgroundFetchRegistration","BarProp","BaseAudioContext","BatteryManager","BeforeInstallPromptEvent","BeforeUnloadEvent","BiquadFilterNode","BlobEvent","BrowserCaptureMediaStreamTrack","ByteLengthQueuingStrategy","CDATASection","CSPViolationReportBody","CSSAnimation","CSSConditionRule","CSSContainerRule","CSSCounterStyleRule","CSSFontFaceRule","CSSFontFeatureValuesRule","CSSFontPaletteValuesRule","CSSFunctionDeclarations","CSSFunctionDescriptors","CSSFunctionRule","CSSGroupingRule","CSSImageValue","CSSImportRule","CSSKeyframeRule","CSSKeyframesRule","CSSKeywordValue","CSSLayerBlockRule","CSSLayerStatementRule","CSSMarginRule","CSSMathClamp","CSSMathInvert","CSSMathMax","CSSMathMin","CSSMathNegate","CSSMathProduct","CSSMathSum","CSSMathValue","CSSMatrixComponent","CSSMediaRule","CSSNamespaceRule","CSSNestedDeclarations","CSSNumericArray","CSSNumericValue","CSSPageRule","CSSPerspective","CSSPositionTryDescriptors","CSSPositionTryRule","CSSPositionValue","CSSPropertyRule","CSSRotate","CSSRule","CSSRuleList","CSSScale","CSSScopeRule","CSSSkew","CSSSkewX","CSSSkewY","CSSStartingStyleRule","CSSStyleDeclaration","CSSStyleRule","CSSStyleSheet","CSSStyleValue","CSSSupportsRule","CSSTransformComponent","CSSTransformValue","CSSTransition","CSSTranslate","CSSUnitValue","CSSUnparsedValue","CSSVariableReferenceValue","CSSViewTransitionRule","Cache","CacheStorage","CanvasCaptureMediaStreamTrack","CanvasGradient","CanvasPattern","CaptureController","CaretPosition","ChannelMergerNode","ChannelSplitterNode","ChapterInformation","CharacterBoundsUpdateEvent","CharacterData","Clipboard","ClipboardChangeEvent","ClipboardEvent","ClipboardItem","CloseEvent","CloseWatcher","CommandEvent","CompositionEvent","CompressionStream","ConstantSourceNode","ContentVisibilityAutoStateChangeEvent","ConvolverNode","CookieChangeEvent","CookieStore","CookieStoreManager","CountQueuingStrategy","CrashReportContext","CreateMonitor","Credential","CredentialsContainer","CropTarget","CustomElementRegistry","CustomStateSet","DOMError","DOMImplementation","DOMMatrix","DOMMatrixReadOnly","DOMParser","DOMPoint","DOMPointReadOnly","DOMQuad","DOMRect","DOMRectList","DOMRectReadOnly","DOMStringList","DOMStringMap","DOMTokenList","DataTransfer","DataTransferItem","DataTransferItemList","DecompressionStream","DelayNode","DelegatedInkTrailPresenter","DeviceMotionEvent","DeviceMotionEventAcceleration","DeviceMotionEventRotationRate","DeviceOrientationEvent","DevicePosture","DigitalCredential","DisposableStack","DocumentPictureInPicture","DocumentPictureInPictureEvent","DocumentTimeline","DocumentType","DragEvent","DynamicsCompressorNode","EditContext","ElementInternals","EncodedAudioChunk","EncodedVideoChunk","ErrorEvent","EventCounts","EventSource","External","FeaturePolicy","FederatedCredential","Fence","FencedFrameConfig","FetchLaterResult","FileList","FileSystemDirectoryHandle","FileSystemFileHandle","FileSystemHandle","FileSystemObserver","FileSystemWritableFileStream","Float16Array","FontData","FontFace","FontFaceSetLoadEvent","FormDataEvent","FragmentDirective","GPU","GPUAdapter","GPUAdapterInfo","GPUBindGroup","GPUBindGroupLayout","GPUBuffer","GPUCanvasContext","GPUCommandBuffer","GPUCommandEncoder","GPUCompilationInfo","GPUCompilationMessage","GPUComputePassEncoder","GPUComputePipeline","GPUDevice","GPUDeviceLostInfo","GPUError","GPUExternalTexture","GPUInternalError","GPUOutOfMemoryError","GPUPipelineError","GPUPipelineLayout","GPUQuerySet","GPUQueue","GPURenderBundle","GPURenderBundleEncoder","GPURenderPassEncoder","GPURenderPipeline","GPUSampler","GPUShaderModule","GPUSupportedFeatures","GPUSupportedLimits","GPUTexture","GPUTextureView","GPUUncapturedErrorEvent","GPUValidationError","GainNode","Gamepad","GamepadButton","GamepadEvent","GamepadHapticActuator","Geolocation","GeolocationCoordinates","GeolocationPosition","GeolocationPositionError","GravitySensor","Gyroscope","HID","HIDConnectionEvent","HIDDevice","HIDInputReportEvent","HTMLAllCollection","HTMLBaseElement","HTMLCollection","HTMLDListElement","HTMLDataElement","HTMLDirectoryElement","HTMLDocument","HTMLFencedFrameElement","HTMLFontElement","HTMLFormControlsCollection","HTMLFrameElement","HTMLFrameSetElement","HTMLGeolocationElement","HTMLMarqueeElement","HTMLMenuElement","HTMLOptionsCollection","HTMLParamElement","HTMLSelectedContentElement","HTMLTableCaptionElement","HTMLTableColElement","HTMLTrackElement","HashChangeEvent","Highlight","HighlightRegistry","IDBCursor","IDBCursorWithValue","IDBDatabase","IDBFactory","IDBIndex","IDBKeyRange","IDBObjectStore","IDBOpenDBRequest","IDBRecord","IDBRequest","IDBTransaction","IDBVersionChangeEvent","IIRFilterNode","IdentityCredential","IdentityCredentialError","IdentityProvider","IdleDeadline","IdleDetector","ImageBitmap","ImageBitmapRenderingContext","ImageCapture","ImageData","ImageDecoder","ImageTrack","ImageTrackList","Ink","InputDeviceCapabilities","InputDeviceInfo","IntegrityViolationReportBody","InterestEvent","IntersectionObserverEntry","Keyboard","KeyboardLayoutMap","KeyframeEffect","LanguageDetector","LanguageModel","LargestContentfulPaint","LaunchParams","LaunchQueue","LayoutShift","LayoutShiftAttribution","LinearAccelerationSensor","Lock","LockManager","MIDIAccess","MIDIConnectionEvent","MIDIInput","MIDIInputMap","MIDIMessageEvent","MIDIOutput","MIDIOutputMap","MIDIPort","MathMLElement","MediaCapabilities","MediaDeviceInfo","MediaDevices","MediaElementAudioSourceNode","MediaEncryptedEvent","MediaError","MediaKeyMessageEvent","MediaKeySession","MediaKeyStatusMap","MediaKeySystemAccess","MediaKeys","MediaList","MediaMetadata","MediaQueryList","MediaQueryListEvent","MediaRecorder","MediaSession","MediaSource","MediaSourceHandle","MediaStream","MediaStreamAudioDestinationNode","MediaStreamAudioSourceNode","MediaStreamEvent","MediaStreamTrack","MediaStreamTrackAudioStats","MediaStreamTrackEvent","MediaStreamTrackGenerator","MediaStreamTrackProcessor","MediaStreamTrackVideoStats","MutationRecord","NamedNodeMap","NavigateEvent","Navigation","NavigationActivation","NavigationCurrentEntryChangeEvent","NavigationDestination","NavigationHistoryEntry","NavigationPrecommitController","NavigationPreloadManager","NavigationTransition","NavigatorLogin","NavigatorManagedData","NavigatorUAData","NetworkInformation","NodeList","NotRestoredReasonDetails","NotRestoredReasons","Notification","OTPCredential","Observable","OfflineAudioCompletionEvent","OffscreenCanvasRenderingContext2D","Option","OrientationSensor","Origin","OscillatorNode","OverconstrainedError","PageRevealEvent","PageSwapEvent","PageTransitionEvent","PannerNode","PasswordCredential","Path2D","PaymentAddress","PaymentManager","PaymentMethodChangeEvent","PaymentRequest","PaymentRequestUpdateEvent","PaymentResponse","PerformanceElementTiming","PerformanceEntry","PerformanceEventTiming","PerformanceLongAnimationFrameTiming","PerformanceLongTaskTiming","PerformanceMark","PerformanceMeasure","PerformanceNavigationTiming","PerformanceObserverEntryList","PerformancePaintTiming","PerformanceResourceTiming","PerformanceScriptTiming","PerformanceServerTiming","PerformanceTimingConfidence","PeriodicSyncManager","PeriodicWave","PermissionStatus","Permissions","PictureInPictureEvent","PictureInPictureWindow","PopStateEvent","Presentation","PresentationAvailability","PresentationConnection","PresentationConnectionAvailableEvent","PresentationConnectionCloseEvent","PresentationConnectionList","PresentationReceiver","PresentationRequest","PressureObserver","PressureRecord","ProcessingInstruction","Profiler","ProgressEvent","PromiseRejectionEvent","ProtectedAudience","PublicKeyCredential","PushManager","PushSubscription","PushSubscriptionOptions","QuotaExceededError","RTCCertificate","RTCDTMFSender","RTCDTMFToneChangeEvent","RTCDataChannel","RTCDataChannelEvent","RTCDtlsTransport","RTCEncodedAudioFrame","RTCEncodedVideoFrame","RTCError","RTCErrorEvent","RTCIceCandidate","RTCIceTransport","RTCPeerConnectionIceErrorEvent","RTCPeerConnectionIceEvent","RTCRtpReceiver","RTCRtpScriptTransform","RTCRtpSender","RTCRtpTransceiver","RTCSctpTransport","RTCSessionDescription","RTCStatsReport","RTCTrackEvent","RadioNodeList","Range","ReadableByteStreamController","ReadableStreamBYOBReader","ReadableStreamBYOBRequest","ReadableStreamDefaultController","ReadableStreamDefaultReader","RelativeOrientationSensor","RemotePlayback","ReportBody","ReportingObserver","ResizeObserverEntry","ResizeObserverSize","RestrictionTarget","SVGAElement","SVGAngle","SVGAnimateElement","SVGAnimateMotionElement","SVGAnimateTransformElement","SVGAnimatedAngle","SVGAnimatedBoolean","SVGAnimatedEnumeration","SVGAnimatedInteger","SVGAnimatedLength","SVGAnimatedLengthList","SVGAnimatedNumber","SVGAnimatedNumberList","SVGAnimatedPreserveAspectRatio","SVGAnimatedRect","SVGAnimatedString","SVGAnimatedTransformList","SVGAnimationElement","SVGCircleElement","SVGClipPathElement","SVGComponentTransferFunctionElement","SVGDefsElement","SVGDescElement","SVGElement","SVGEllipseElement","SVGFEBlendElement","SVGFEColorMatrixElement","SVGFEComponentTransferElement","SVGFECompositeElement","SVGFEConvolveMatrixElement","SVGFEDiffuseLightingElement","SVGFEDisplacementMapElement","SVGFEDistantLightElement","SVGFEDropShadowElement","SVGFEFloodElement","SVGFEFuncAElement","SVGFEFuncBElement","SVGFEFuncGElement","SVGFEFuncRElement","SVGFEGaussianBlurElement","SVGFEImageElement","SVGFEMergeElement","SVGFEMergeNodeElement","SVGFEMorphologyElement","SVGFEOffsetElement","SVGFEPointLightElement","SVGFESpecularLightingElement","SVGFESpotLightElement","SVGFETileElement","SVGFETurbulenceElement","SVGFilterElement","SVGForeignObjectElement","SVGGElement","SVGGeometryElement","SVGGradientElement","SVGGraphicsElement","SVGImageElement","SVGLength","SVGLengthList","SVGLineElement","SVGLinearGradientElement","SVGMPathElement","SVGMarkerElement","SVGMaskElement","SVGMatrix","SVGMetadataElement","SVGNumber","SVGNumberList","SVGPathElement","SVGPatternElement","SVGPoint","SVGPointList","SVGPolygonElement","SVGPolylineElement","SVGPreserveAspectRatio","SVGRadialGradientElement","SVGRect","SVGRectElement","SVGSVGElement","SVGScriptElement","SVGSetElement","SVGStopElement","SVGStringList","SVGStyleElement","SVGSwitchElement","SVGSymbolElement","SVGTSpanElement","SVGTextContentElement","SVGTextElement","SVGTextPathElement","SVGTextPositioningElement","SVGTitleElement","SVGTransform","SVGTransformList","SVGUnitTypes","SVGUseElement","SVGViewElement","Sanitizer","Scheduler","Scheduling","ScreenDetailed","ScreenDetails","ScreenOrientation","ScriptProcessorNode","ScrollTimeline","SecurityPolicyViolationEvent","Selection","Sensor","SensorErrorEvent","Serial","SerialPort","ServiceWorker","ServiceWorkerContainer","ServiceWorkerRegistration","SharedStorage","SharedStorageAppendMethod","SharedStorageClearMethod","SharedStorageDeleteMethod","SharedStorageModifierMethod","SharedStorageSetMethod","SharedStorageWorklet","SnapEvent","SourceBuffer","SourceBufferList","SpeechGrammar","SpeechGrammarList","SpeechRecognition","SpeechRecognitionErrorEvent","SpeechRecognitionEvent","SpeechRecognitionPhrase","SpeechSynthesis","SpeechSynthesisErrorEvent","SpeechSynthesisEvent","SpeechSynthesisUtterance","SpeechSynthesisVoice","StaticRange","StereoPannerNode","Storage","StorageBucket","StorageBucketManager","StorageEvent","StorageManager","StylePropertyMap","StylePropertyMapReadOnly","StyleSheet","StyleSheetList","SubmitEvent","Subscriber","Summarizer","SuppressedError","SyncManager","TaskAttributionTiming","TaskController","TaskPriorityChangeEvent","TaskSignal","TextDecoderStream","TextEncoderStream","TextEvent","TextFormat","TextFormatUpdateEvent","TextMetrics","TextTrack","TextTrackCue","TextTrackCueList","TextTrackList","TextUpdateEvent","TimeRanges","TimelineTrigger","TimelineTriggerRange","TimelineTriggerRangeList","ToggleEvent","Touch","TouchEvent","TouchList","TrackEvent","TransformStreamDefaultController","TransitionEvent","Translator","TrustedHTML","TrustedScript","TrustedScriptURL","TrustedTypePolicy","TrustedTypePolicyFactory","URLPattern","USB","USBAlternateInterface","USBConfiguration","USBConnectionEvent","USBDevice","USBEndpoint","USBInTransferResult","USBInterface","USBIsochronousInTransferPacket","USBIsochronousInTransferResult","USBIsochronousOutTransferPacket","USBIsochronousOutTransferResult","USBOutTransferResult","UserActivation","VTTCue","ValidityState","VideoColorSpace","VideoDecoder","VideoEncoder","VideoFrame","VideoPlaybackQuality","ViewTimeline","ViewTransition","ViewTransitionTypeSet","Viewport","VirtualKeyboard","VirtualKeyboardGeometryChangeEvent","VisibilityStateEntry","VisualViewport","WGSLLanguageFeatures","WakeLock","WakeLockSentinel","WaveShaperNode","WebGLContextEvent","WebGLObject","WebGLQuery","WebGLSampler","WebGLShaderPrecisionFormat","WebGLSync","WebGLTransformFeedback","WebKitCSSMatrix","WebKitMutationObserver","WebSocketError","WebSocketStream","WebTransport","WebTransportBidirectionalStream","WebTransportDatagramDuplexStream","WebTransportError","WheelEvent","Window","WindowControlsOverlay","WindowControlsOverlayGeometryChangeEvent","Worklet","WritableStreamDefaultController","WritableStreamDefaultWriter","XMLDocument","XMLHttpRequestEventTarget","XMLHttpRequestUpload","XMLSerializer","XPathEvaluator","XPathExpression","XPathResult","XRAnchor","XRAnchorSet","XRBoundedReferenceSpace","XRCPUDepthInformation","XRCamera","XRCompositionLayer","XRCubeLayer","XRCylinderLayer","XRDOMOverlayState","XRDepthInformation","XREquirectLayer","XRFrame","XRHand","XRHitTestResult","XRHitTestSource","XRInputSource","XRInputSourceArray","XRInputSourceEvent","XRInputSourcesChangeEvent","XRJointPose","XRJointSpace","XRLayer","XRLayerEvent","XRLightEstimate","XRLightProbe","XRPlane","XRPlaneSet","XRPose","XRProjectionLayer","XRQuadLayer","XRRay","XRReferenceSpace","XRReferenceSpaceEvent","XRRenderState","XRRigidTransform","XRSession","XRSessionEvent","XRSpace","XRSubImage","XRSystem","XRTransientInputHitTestResult","XRTransientInputHitTestSource","XRView","XRViewerPose","XRViewport","XRVisibilityMaskChangeEvent","XRWebGLBinding","XRWebGLDepthInformation","XRWebGLLayer","XRWebGLSubImage","XSLTProcessor","alert","blur","captureEvents","close","confirm","createImageBitmap","fetchLater","find","focus","getScreenDetails","getSelection","moveBy","moveTo","open","postMessage","print","prompt","queryLocalFonts","releaseEvents","resizeBy","resizeTo","scroll","scrollBy","scrollTo","showDirectoryPicker","showOpenFilePicker","showSaveFilePicker","stop","webkitCancelAnimationFrame","webkitMediaStream","webkitRequestAnimationFrame","webkitRequestFileSystem","webkitResolveLocalFileSystemURL","webkitSpeechGrammar","webkitSpeechGrammarList","webkitSpeechRecognition","webkitSpeechRecognitionError","webkitSpeechRecognitionEvent","webkitURL","when"]},"document":{"#1":["DOCUMENT_POSITION_DISCONNECTED","childElementCount"],"#2":["DOCUMENT_POSITION_PRECEDING"],"#4":["DOCUMENT_POSITION_FOLLOWING"],"#5":["ENTITY_REFERENCE_NODE"],"#6":["ENTITY_NODE"],"#8":["DOCUMENT_POSITION_CONTAINS"],"#12":["NOTATION_NODE"],"#16":["DOCUMENT_POSITION_CONTAINED_BY"],"#32":["DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC"],"o":["applets","children","customElementRegistry","doctype","featurePolicy","firstElementChild","fonts","fragmentDirective","implementation","lastElementChild","scrollingElement","timeline"],"F":["fullscreen","prerendering","wasDiscarded","webkitHidden","webkitIsFullScreen","xmlStandalone"],"x":["activeViewTransition","fullscreenElement","nodeValue","onabort","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onauxclick","onbeforecopy","onbeforecut","onbeforeinput","onbeforematch","onbeforepaste","onbeforetoggle","onbeforexrselect","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncopy","oncuechange","oncut","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","onfreeze","onfullscreenchange","onfullscreenerror","ongotpointercapture","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onlostpointercapture","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpaste","onpause","onplay","onplaying","onpointercancel","onpointerdown","onpointerenter","onpointerleave","onpointerlockchange","onpointerlockerror","onpointermove","onpointerout","onpointerover","onpointerrawupdate","onpointerup","onprerenderingchange","onprogress","onratechange","onreadystatechange","onreset","onresize","onresume","onscroll","onscrollend","onscrollsnapchange","onscrollsnapchanging","onsearch","onsecuritypolicyviolation","onseeked","onseeking","onselect","onselectionchange","onselectstart","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","ontransitioncancel","ontransitionend","ontransitionrun","ontransitionstart","onvisibilitychange","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkitfullscreenchange","onwebkitfullscreenerror","onwebkittransitionend","onwheel","parentElement","pictureInPictureElement","pointerLockElement","rootElement","webkitCurrentFullScreenElement","webkitFullscreenElement","xmlEncoding","xmlVersion"],"u":["all"],"T":["fullscreenEnabled","pictureInPictureEnabled","webkitFullscreenEnabled"],"N":["adoptNode","append","ariaNotify","browsingTopics","captureEvents","caretPositionFromPoint","caretRangeFromPoint","clear","compareDocumentPosition","createAttribute","createAttributeNS","createCDATASection","createExpression","createNSResolver","createProcessingInstruction","createRange","evaluate","execCommand","exitFullscreen","exitPictureInPicture","exitPointerLock","getAnimations","getElementsByName","getElementsByTagNameNS","getSelection","hasFocus","hasPrivateToken","hasRedemptionRecord","hasStorageAccess","hasUnpartitionedCookieAccess","importNode","isDefaultNamespace","isEqualNode","isSameNode","lookupNamespaceURI","lookupPrefix","moveBefore","normalize","prepend","queryCommandEnabled","queryCommandIndeterm","queryCommandState","queryCommandSupported","queryCommandValue","releaseEvents","replaceChildren","requestStorageAccess","requestStorageAccessFor","startViewTransition","webkitCancelFullScreen","webkitExitFullscreen","when"]},"navigator":{"o":["clipboard","credentials","devicePosture","geolocation","gpu","hid","ink","keyboard","locks","login","managed","mediaCapabilities","mediaSession","presentation","protectedAudience","scheduling","serial","storageBuckets","usb","virtualKeyboard","wakeLock","webkitPersistentStorage","webkitTemporaryStorage","windowControlsOverlay","xr"],"F":["deprecatedRunAdAuctionEnforcesKAnonymity"],"N":["adAuctionComponents","canLoadAdAuctionFencedFrame","clearOriginJoinedAdInterestGroups","createAuctionNonce","deprecatedReplaceInURN","deprecatedURNToURL","getGamepads","getInstalledRelatedApps","getInterestGroupAdAuctionData","getUserMedia","javaEnabled","joinAdInterestGroup","leaveAdInterestGroup","registerProtocolHandler","requestMIDIAccess","requestMediaKeySystemAccess","runAdAuction","unregisterProtocolHandler","updateAdInterestGroups","webkitGetUserMedia"]},"location":{"o":["ancestorOrigins"],"N":["valueOf"]},"screen":{"x":["onchange"],"N":["addEventListener","dispatchEvent","removeEventListener","when"]}};
  const native = globalThis.__pt_native || ((f) => f);
  // A stub must be a strict function: a sloppy one has own `arguments` and
  // `caller`, which browser interfaces lack (two extra properties on each of
  // ~1000 graph names). The stub still does nothing.
  // Born with its name: editing `name` turns a function into dictionary mode.
  const strictFn = (function () {
    'use strict';
    return (n) => ({ [n]: function () {} })[n];
  })();
  const stub = (name, cat) => {
    if (cat === 'N' || cat === 'f') {
      // A method (lowercase name) has no `.prototype`, like a native; an interface has one.
      const f = /^[a-z]/.test(name) ? ({ [name]() {} })[name] : strictFn(name);
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
    if (__s_charCodeAt(cat, 0) === 35) return Number(__s_slice(cat, 1));  // '#12' → 12
    return undefined;
  };
  // Pages see SharedArrayBuffer only under cross-origin isolation, and we
  // report crossOriginIsolated=false. V8 always exposes it, so remove it: "no
  // isolation but SAB present" is impossible in a real Chrome.
  try { delete globalThis.SharedArrayBuffer; } catch (e) {}

  for (const root of Object.keys(T)) {
    const obj = root === 'window' ? globalThis : globalThis[root];
    if (!obj) continue;
    // Interface properties live on the prototype: a real `document` or
    // `navigator` has no own properties, and our tests guard that.
    const proto = root === 'window' ? obj : (Object.getPrototypeOf(obj) || obj);
    const target = proto;
    // "Already present" means on the interface itself, not inherited from
    // Object.prototype (where `location.valueOf` hides; otherwise Location
    // never got its own enumerable valueOf).
    const has = (name) => {
      for (let p = target; p && p !== Object.prototype; p = Object.getPrototypeOf(p)) {
        if (Object.prototype.hasOwnProperty.call(p, name)) return true;
      }
      return false;
    };
    for (const cat of Object.keys(T[root])) {
      for (const name of T[root][cat]) {
        if (has(name)) continue;                    // implemented: leave alone
        // When building the snapshot V8 hides some builtins (Float16Array,
        // DisposableStack, WebAssembly...) and adds them on restore: a stub
        // here would shadow the real thing.
        if (root === 'window' && globalThis.__pt_lateNames && __pt_lateNames.has(name)) continue;
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
/// Error stack processing. In the browser there are no JS frames between an
/// event handler and its caller (the dispatcher is browser code). Ours is JS,
/// so `new Error()` in a handler showed `fire`, `__ptDispatch` and a position
/// in an unnamed script. V8 hands the parsed frames here
/// (`SetPrepareStackTraceCallback`); our frames are filtered out and the
/// string is built exactly as V8 would, including calling the page's own
/// `Error.prepareStackTrace` with the same list minus our frames.
const STACK_TEMPLATE: &str = r##"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_replace = __sm(String.prototype.replace, 'replace'),
    __s_slice = __sm(String.prototype.slice, 'slice');
  const ours = (f) => {
    try {
      // URL rather than resource name: an inline script has no name, and
      // `//# sourceURL` gives it a URL, as in the browser.
      const from = typeof f.getScriptNameOrSourceURL === 'function'
        ? (f.getScriptNameOrSourceURL() || f.getFileName())
        : f.getFileName();
      if (from) return false;                 // script with a URL: the page's
      if (f.isEval()) return false;           // eval/Function: also the page's
      return f.getLineNumber() != null;       // unnamed but positioned: ours
    } catch (e) { return false; }
  };
  // A proxy that cannot be made its own prototype: the browser's
  // `Object.setPrototypeOf(x, x)` throws "Cyclic __proto__ value" for any
  // object, but for a trapless proxy the cycle check stops at the proxy and
  // the target got its own wrapper as prototype. A global graph walk does
  // exactly this to everything, after which `Function.prototype.toString`
  // looped through an endless prototype chain.
  // Captured up front: the trap must not call anything the page may wrap.
  const __pxGPO = Reflect.getPrototypeOf, __pxSPO = Reflect.setPrototypeOf, __pxProxy = Proxy;
  Object.defineProperty(globalThis, '__pt_proxy', {
    value: (target, handler) => {
      const px = new __pxProxy(target, handler);
      handler.setPrototypeOf = (t, proto) => {
        for (let q = proto, i = 0; q !== null && q !== undefined && i < 100000; i++) {
          if (q === t || q === px) throw __pt_mkErr(TypeError, 'Cyclic __proto__ value');
          q = __pxGPO(q);
        }
        return __pxSPO(t, proto);
      };
      return px;
    },
    writable: true, enumerable: false, configurable: true,
  });
  globalThis.__pt_formatStack = (err, sites) => {
    let keep = sites;
    // Raw stack, for debugging our own breakage: shows where in the engine a
    // foreign program stopped. Never shown to pages; separate env var only.
    if (!__STACK_RAW__) {
      try {
        // A V8 builtin (`String`, `Array.join`) called by our frame is part of
        // a native function's internals: the browser converts arguments in C++
        // and leaves no frame. Such a frame is hidden along with ours; builtins
        // called by the page itself stay.
        const mine = Array.prototype.map.call(sites, (f) => ours(f));
        const builtin = (f) => { try { return f.getLineNumber() == null && !f.getFileName() && !f.isEval(); } catch (e) { return false; } };
        // The browser's console is builtin: its frame shows as
        // `console.log (<anonymous>)`, with argument conversion from formatting
        // (parseInt/parseFloat/String) as its own frame above it. Our console
        // method is a plain prologue function: its frame is replaced with such a
        // frame rather than hidden, and builtins inside it stay visible.
        const CONS = new Set(['assert', 'clear', 'context', 'count', 'countReset', 'createTask', 'debug', 'dir', 'dirxml', 'error', 'group', 'groupCollapsed', 'groupEnd', 'info', 'log', 'profile', 'profileEnd', 'table', 'time', 'timeEnd', 'timeLog', 'timeStamp', 'trace', 'warn']);
        const consoleName = (f, i) => { try { const n = f.getFunctionName(); const t = f.getTypeName(); return mine[i] && CONS.has(n) && (t === 'console' || t === 'Object' || t == null) ? n : null; } catch (e) { return null; } };
        const fake = (name) => {
          const label = 'console.' + name + ' (<anonymous>)';
          const u = () => undefined, n = () => null, no = () => false;
          return { toString: () => label, getFunctionName: () => 'console.' + name, getMethodName: () => name, getTypeName: n, getFileName: u, getScriptNameOrSourceURL: u, getLineNumber: n, getColumnNumber: n, getEnclosingLineNumber: n, getEnclosingColumnNumber: n, getPosition: () => 0, getPromiseIndex: n, getEvalOrigin: u, getThis: u, getFunction: u, getScriptHash: () => '', isNative: no, isEval: no, isConstructor: no, isToplevel: no, isAsync: no, isPromiseAll: no };
        };
        // Outside in: a chain of builtins above our frame is hidden entirely,
        // except the one inside a console frame.
        const hidden = new Array(sites.length), swap = new Array(sites.length);
        let inside = false;
        for (let i = sites.length - 1; i >= 0; i--) {
          const cn = consoleName(sites[i], i);
          if (cn) {
            // Nested wrappers of one method are one frame.
            if (swap[i + 1] && swap[i + 1].getMethodName() === cn) { hidden[i] = true; continue; }
            hidden[i] = false; swap[i] = fake(cn); inside = true; continue;
          }
          hidden[i] = mine[i] || (builtin(sites[i]) && !inside && !!hidden[i + 1]);
        }
        keep = [];
        for (let i = 0; i < sites.length; i++) if (!hidden[i]) keep.push(swap[i] || sites[i]);
        // Captured with headroom (`__pt_mkErr`): emit no more than the page's limit.
        try { const lim = Error.stackTraceLimit; if (typeof lim === 'number' && keep.length > lim) keep = __s_slice(keep, 0, Math.max(0, Math.floor(lim))); } catch (e) {}
      } catch (e) {}
    }
    try {
      const mine = Error.prepareStackTrace;
      if (typeof mine === 'function') return mine(err, keep);
    } catch (e) {}
    let head = 'Error';
    try {
      const n = err == null ? undefined : err.name;
      const m = err == null ? undefined : err.message;
      const name = n === undefined ? 'Error' : String(n);
      let msg = m === undefined || m === null || m === '' ? '' : String(m);
      // The browser's binding `TypeError` stack header lacks the
      // "Failed to execute 'x' on 'Y': " prefix; it stays only in `message`.
      if (name === 'TypeError') msg = __s_replace(msg, /^Failed to (?:execute '[^']*' on '[^']*'|construct '[^']*'): /, '');
      head = !name ? msg : (!msg ? name : name + ': ' + msg);
    } catch (e) {}
    let out = head;
    for (let i = 0; i < keep.length; i++) {
      try { out += '\n    at ' + String(keep[i]); } catch (e) {}
    }
    return out;
  };
})();"##;

const PERFORMANCE_TEMPLATE: &str = r#"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_toLowerCase = __sm(String.prototype.toLowerCase, 'toLowerCase'),
    __s_trim = __sm(String.prototype.trim, 'trim'),
    __s_split = __sm(String.prototype.split, 'split');
  // The browser's time origin is not an integer either: it comes from the
  // same clock as `now()` and carries fractions of a millisecond.
  const originNow = () => {
    const ms = Date.now();
    const hr0 = typeof globalThis.__pt_hrtime === 'function' ? globalThis.__pt_hrtime() : 0;
    const frac = Math.floor((hr0 - Math.floor(hr0)) * 10) / 10;
    return Math.floor((ms + frac) * 16777216) / 16777216;
  };
  let ORIGIN = originNow();

  // DOMHighResTimeStamp: 0.1 ms granularity (Chrome coarsens it against timing
  // attacks) and never decreasing. Derived from the same clock as `Date.now()`,
  // so `timeOrigin + now()` tracks it exactly.
  // Real monotonic clock, coarsened to the browser's 0.1 ms step. `Date.now()`
  // won't do: it moves in whole ms, so time stood still within a task. The
  // Cloudflare challenge measures exactly this: five thousand samples and the
  // minimum positive difference.
  const hr = globalThis.__pt_hrtime;
  let HR_BASE = typeof hr === 'function' ? hr() : 0;
  let last = 0;
  const nowMs = () => {
    const raw = typeof hr === 'function' ? hr() - HR_BASE : Math.max(0, Date.now() - ORIGIN);
    // Same quantum as Chrome and the same float arithmetic: dividing by 10
    // gives 98.59999996423721, not 98.6, which shows in measurements.
    const coarse = Math.floor(raw * 10) / 10;
    // And the browser's grid: Chrome keeps timestamps at 2^-24 ms precision,
    // so its tenths are inexact (2294.1 is 2294.099999964237, while .5 and .0
    // are exact). The min-difference test shows 0.09999996423721313 in the
    // browser vs an even 0.09999999999999432 without this.
    const v = Math.floor(coarse * 16777216) / 16777216;
    if (v > last) last = v;
    return last;
  };

  // Plausible, correctly ordered navigation milestones anchored at the origin.
  // `performance.timing` fields are integer epoch milliseconds, as in the browser.
  const T = (d) => Math.round(ORIGIN + d);
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
  // Live readings, not constants: a page that allocates an array and rereads
  // `usedJSHeapSize` sees a larger number in the browser. The engine computes
  // the limit from physical memory with the same V8 function as Chrome. A
  // missing `performance.memory` while claiming Chrome is a tell too, so
  // fallback values remain for builds without the native hook.
  const MEMORY_FALLBACK = { jsHeapSizeLimit: 4395630592, totalJSHeapSize: 12800000, usedJSHeapSize: 10600000 };
  const heapStats = typeof __pt_heapStats === 'function' ? __pt_heapStats : null;
  // As in Chrome (verified in the widget frame; section LYTA4 reads this eight
  // times): every performance.memory access is a new object with sampled
  // values; values refresh at most every 50 ms; and it is the memory of this
  // context, not the whole isolate (which hosts other windows too: the widget
  // frame reported 266 MB vs Chrome's 33). Counted from context birth: Chrome's
  // fresh page level plus heap growth since.
  const MEM_FRESH_USED = 733790, MEM_FRESH_TOTAL = 1317838;
  let MEM_BASE = null, MEM_SNAP = null, MEM_AT = -1e12;
  const memReset = () => { MEM_BASE = heapStats ? heapStats() : null; MEM_SNAP = null; MEM_AT = -1e12; };
  memReset();
  const memSnap = () => {
    const now = Date.now();
    if (MEM_SNAP && now - MEM_AT < 50) return MEM_SNAP;
    let snap;
    if (heapStats && MEM_BASE) {
      const raw = heapStats();
      const used = MEM_FRESH_USED + Math.max(0, raw[0] - MEM_BASE[0]);
      const total = Math.max(used + 4096, MEM_FRESH_TOTAL + Math.max(0, raw[1] - MEM_BASE[1]));
      snap = [used, total, raw[2]];
    } else snap = [MEMORY_FALLBACK.usedJSHeapSize, MEMORY_FALLBACK.totalJSHeapSize, MEMORY_FALLBACK.jsHeapSizeLimit];
    MEM_SNAP = snap; MEM_AT = now;
    return snap;
  };
  const MEM_OF = new WeakMap();
  const memOf = (o) => MEM_OF.get(o) || memSnap();
  const MEMORY = {
    get totalJSHeapSize() { return memOf(this)[1]; },
    get usedJSHeapSize() { return memOf(this)[0]; },
    get jsHeapSizeLimit() { return memOf(this)[2]; },
  };

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

  // Every page request leaves a Resource Timing entry, dozens after load. An
  // empty list marks a browser that loaded nothing, which anti-bots check via
  // getEntriesByType('resource'). The engine adds entries as requests finish.
  const entries = [];
  // `toJSON` field order follows how the entry was built (verified against
  // Chrome), not the prototype accessor order: in the browser they differ.
  const ENTRY_ORDER = new WeakMap();
  // Entries whose toJSON is exactly the ENTRY_ORDER fields (long-animation-frame
  // and its script: Chrome leaves out paintTime/presentationTime/window).
  const ENTRY_STRICT = new WeakSet();
  // navigation.confidence is a PerformanceTimingConfidence, as in Chrome 151.
  const __ptConfidence = () => {
    const C = globalThis.PerformanceTimingConfidence;
    const o = Object.create(C && C.prototype ? C.prototype : Object.prototype);
    __pt_write(o, 'randomizedTriggerRate', 0.4994798);
    __pt_write(o, 'value', 'low');
    try {
      if (C && C.prototype && !C.prototype.__ptJson) {
        Object.defineProperty(C.prototype, '__ptJson', { value: true });
        const f = ({ toJSON() { return { randomizedTriggerRate: this.randomizedTriggerRate, value: this.value }; } }).toJSON;
        Object.defineProperty(C.prototype, 'toJSON', { value: globalThis.__pt_native ? __pt_native(f) : f, writable: true, enumerable: true, configurable: true });
      }
    } catch (e) {}
    return o;
  };
  const putEntry = (o, bag) => { for (const k of Object.keys(bag)) __pt_write(o, k, bag[k]); };
  class PerformanceEntry {
    // Fields are prototype accessors, not own properties; `toJSON` walks the
    // chain from PerformanceEntry to the concrete kind, in declaration order
    // on each prototype, as Chrome builds it.
    toJSON() {
      const chain = [];
      for (let p = Object.getPrototypeOf(this); p && p !== Object.prototype; p = Object.getPrototypeOf(p)) chain.unshift(p);
      const o = {};
      const first = ENTRY_ORDER.get(this);
      if (first) for (const k of first) { try { o[k] = this[k]; } catch (e) {} }
      if (ENTRY_STRICT.has(this)) {
        if (Array.isArray(o.scripts)) o.scripts = o.scripts.map((x) => (x && typeof x.toJSON === 'function' ? x.toJSON() : x));
        return o;
      }
      for (const p of chain) {
        for (const k of Object.getOwnPropertyNames(p)) {
          // Chrome's JSON for marks and measures omits `detail`.
          if (k === 'constructor' || k === 'toJSON' || k === 'detail' || __s_slice(k, 0, 4) === '__pt') continue;
          const d = Object.getOwnPropertyDescriptor(p, k);
          if (!d || !d.get || k in o) continue;
          try { o[k] = this[k]; } catch (e) {}
        }
      }
      for (const k of Object.keys(this)) if (!(k in o) && k !== 'detail') o[k] = this[k];
      return o;
    }
  }
  tag(PerformanceEntry.prototype, 'PerformanceEntry');
  class PerformanceResourceTiming extends PerformanceEntry {}
  tag(PerformanceResourceTiming.prototype, 'PerformanceResourceTiming');
  class PerformanceNavigationTiming extends PerformanceEntry {}
  tag(PerformanceNavigationTiming.prototype, 'PerformanceNavigationTiming');
  class PerformancePaintTiming extends PerformanceEntry {}
  tag(PerformancePaintTiming.prototype, 'PerformancePaintTiming');
  globalThis.PerformanceEntry = PerformanceEntry;
  globalThis.PerformanceResourceTiming = PerformanceResourceTiming;
  globalThis.PerformanceNavigationTiming = PerformanceNavigationTiming;
  globalThis.PerformancePaintTiming = PerformancePaintTiming;

  // Navigation id: the browser uses one for all entries of a document.
  const NAV_ID = 1000 + Math.floor(Math.random() * 9000);
  // "Minimized" MIME as Resource Timing writes it: any JavaScript is
  // `text/javascript`, JSON `application/json`, SVG and XML their own, other
  // supported types the essence without parameters, unknown ones empty.
  const __ptMinimizeMime = (raw) => {
    const t = __s_toLowerCase(__s_trim(__s_split(String(raw || ''), ';')[0]));
    if (!t) return '';
    if (/^(application|text)\/(x-)?(java|ecma)script$|^text\/(jscript|livescript|x-javascript1\.\d)$|^text\/javascript1\.\d$/.test(t)) return 'text/javascript';
    if (t === 'application/json' || t === 'text/json' || /\+json$/.test(t)) return 'application/json';
    if (t === 'image/svg+xml') return 'image/svg+xml';
    if (t === 'text/xml' || t === 'application/xml' || /\+xml$/.test(t)) return 'application/xml';
    return t;
  };
  // Document marks (domInteractive, DOMContentLoaded, load) are set when the
  // event happens; zeros until then, as in the browser.
  const NAV_MARKS = {};
  let NAV_ENTRY = null;
  const __ptSyncTimingMarks = () => {
    const at = (v) => (v ? Math.round(ORIGIN + v) : 0);
    const m = NAV_MARKS;
    Object.assign(TIMING, {
      domInteractive: at(m.interactive), domContentLoadedEventStart: at(m.dclStart),
      domContentLoadedEventEnd: at(m.dclEnd), domComplete: at(m.complete),
      loadEventStart: at(m.loadStart), loadEventEnd: at(m.loadEnd),
    });
  };
  Object.defineProperty(globalThis, '__pt_markNav', {
    value: (name) => {
      if (NAV_MARKS[name]) return;
      NAV_MARKS[name] = nowMs();
      const e = NAV_ENTRY;
      if (e) {
        const field = { interactive: 'domInteractive', dclStart: 'domContentLoadedEventStart',
          dclEnd: 'domContentLoadedEventEnd', complete: 'domComplete',
          loadStart: 'loadEventStart', loadEnd: 'loadEventEnd' }[name];
        if (field) __pt_write(e, field, NAV_MARKS[name]);
        if (name === 'loadEnd') __pt_write(e, 'duration', NAV_MARKS[name]);
      }
      __ptSyncTimingMarks();
    },
    enumerable: false, configurable: true,
  });
  globalThis.__pt_noteResources = (json, pageEpoch) => {
    let list;
    const fresh = [];
    try { list = __ptJSON.parse(json); } catch (e) { return 0; }
    // Shift from the page clock to this window's clock (a frame's timeOrigin is later).
    const shift = pageEpoch ? pageEpoch - ORIGIN : 0;
    for (const r of list) {
      const Ctor = r.entryType === 'navigation' ? PerformanceNavigationTiming : PerformanceResourceTiming;
      const e = new Ctor();
      const start = r.entryType === 'navigation' ? (Number(r.start) || 0) : Math.max(0, (Number(r.start) || 0) + shift);
      const end = start + (Number(r.duration) || 0);
      // Fields in the browser's order (`toJSON` follows own names): Turnstile's
      // api.js forwards its entry to the widget whole, and it goes into the
      // first POST body.
      // Redirects: the entry starts at the first request, fetchStart at the
      // end of the last redirect.
      const hop = r.redirect != null && Number(r.redirect) > 0 ? Math.min(Number(r.redirect), Number(r.duration) || 0) : 0;
      const isNav = r.entryType === 'navigation';
      const net = Math.max(0, (Number(r.duration) || 0) - hop);
      // For navigation fetchStart is not at zero, and connect, request and
      // first byte are separate steps: Chrome's widget frame shows
      // 56 -> 58...147 -> 147 -> 204 -> 242.
      const fs = start + hop + (isNav ? Math.min(net * 0.02, 5) : 0);
      const span = Math.max(0, end - fs);
      const cEnd = isNav && span > 120 ? fs + span * 0.45 : fs;
      const rq = isNav ? cEnd + (span > 120 ? 0.3 : 0) : fs;
      const rs = isNav ? fs + span * 0.78 : fs + net * 0.8;
      const put = (o, bag) => {
        const keys = Object.keys(bag);
        for (const k of keys) __pt_write(o, k, bag[k]);
        const had = ENTRY_ORDER.get(o);
        ENTRY_ORDER.set(o, had ? had.concat(keys.filter((k) => __s_indexOf(had, k) < 0)) : keys);
      };
      // Cross-origin resource without `Timing-Allow-Origin` for our origin: the
      // browser hides sizes, status, protocol and intermediate marks (TAO).
      const taoPass = (() => {
        try {
          if (isNav) return true;
          const u = new URL(String(r.name || ''), (globalThis.location && location.href) || undefined);
          const mine = (globalThis.location && location.origin) || 'null';
          if (u.origin === mine) return true;
          const h = __s_trim(String(r.tao == null ? '' : r.tao));
          if (!h) return false;
          return __s_split(h, ',').map((x) => __s_trim(x)).some((x) => x === '*' || __s_toLowerCase(x) === __s_toLowerCase(mine));
        } catch (e) { return true; }
      })();
      put(e, {
        name: String(r.name || ''), entryType: r.entryType || 'resource',
        startTime: start, duration: Number(r.duration) || 0,
        navigationId: NAV_ID,
        initiatorType: r.initiatorType || 'other', deliveryType: '',
        nextHopProtocol: r.protocol || 'h2', renderBlockingStatus: 'non-blocking',
        contentType: __ptMinimizeMime(r.contentType), contentEncoding: String(r.encoding || ''),
        workerStart: 0, workerRouterEvaluationStart: 0, workerCacheLookupStart: 0,
        workerMatchedSourceType: '', workerFinalSourceType: '',
        redirectStart: hop ? start : 0, redirectEnd: hop ? fs : 0,
        fetchStart: fs, domainLookupStart: fs, domainLookupEnd: fs,
        connectStart: cEnd > fs ? fs + 1.5 : fs, secureConnectionStart: cEnd > fs ? fs + 1.5 : fs, connectEnd: cEnd,
        requestStart: rq, responseStart: rs,
        firstInterimResponseStart: 0, finalResponseHeadersStart: rs, responseEnd: end,
        transferSize: Number(r.size) || 0,
        encodedBodySize: Math.max(0, (Number(r.size) || 0) - 300),
        decodedBodySize: Number(r.decoded) || Math.max(0, (Number(r.size) || 0) - 300),
        responseStatus: Number(r.status) || 200,
        serverTiming: [],
      });
      if (!taoPass) {
        put(e, {
          nextHopProtocol: '', redirectStart: 0, redirectEnd: 0, domainLookupStart: 0, domainLookupEnd: 0,
          connectStart: 0, secureConnectionStart: 0, connectEnd: 0, requestStart: 0, responseStart: 0,
          firstInterimResponseStart: 0, finalResponseHeadersStart: 0,
          transferSize: 0, encodedBodySize: 0, decodedBodySize: 0, responseStatus: 0,
        });
      }
      if (r.entryType === 'navigation') {
        // Document marks are zero until the event happens, as in the browser;
        // __pt_markNav sets them. Navigation duration runs to the end of `load`.
        const m = NAV_MARKS;
        put(e, {
          unloadEventStart: 0, unloadEventEnd: 0, domInteractive: m.interactive || 0,
          domContentLoadedEventStart: m.dclStart || 0, domContentLoadedEventEnd: m.dclEnd || 0,
          domComplete: m.complete || 0, loadEventStart: m.loadStart || 0, loadEventEnd: m.loadEnd || 0,
          type: 'navigate', redirectCount: 0, activationStart: 0, criticalCHRestart: 0,
          notRestoredReasons: null, confidence: __ptConfidence(),
        });
      }
      if (r.entryType === 'navigation') {
        __pt_write(e, 'duration', NAV_MARKS.loadEnd || 0);
        NAV_ENTRY = e;
        // `performance.timing`: the same marks in epoch milliseconds.
        const at = (v) => (v ? Math.round(ORIGIN + v) : 0);
        Object.assign(TIMING, {
          fetchStart: at(e.fetchStart), domainLookupStart: at(e.domainLookupStart),
          domainLookupEnd: at(e.domainLookupEnd), connectStart: at(e.connectStart),
          secureConnectionStart: at(e.secureConnectionStart), connectEnd: at(e.connectEnd),
          requestStart: at(e.requestStart), responseStart: at(e.responseStart),
          responseEnd: at(e.responseEnd), domLoading: at(e.responseStart),
        });
        __ptSyncTimingMarks();
      }
      entries.push(e);
      fresh.push(e);
      // Visibility entry right after navigation: Chrome always has one.
      if (isNav && !globalThis.__ptVisEntry) {
        try {
          Object.defineProperty(globalThis, '__ptVisEntry', { value: true, configurable: true });
          const v = Object.create((globalThis.VisibilityStateEntry || PerformanceEntry).prototype);
          put(v, { name: 'visible', entryType: 'visibility-state', startTime: 0, duration: 0, navigationId: NAV_ID });
          entries.push(v);
          fresh.push(v);
        } catch (e2) {}
      }
      // Paint: the browser has two entries next to navigation (first paint
      // and first contentful paint), and pages read them.
      // A frame without a box (0x0 for Turnstile's api.js before the first
      // response, or 1x1) is not painted: Chrome has no paint entries there.
      const painted = (globalThis.innerWidth | 0) > 1 && (globalThis.innerHeight | 0) > 1;
      if (r.entryType === 'navigation' && painted && !entries.some((x) => x.entryType === 'paint')) {
        const at = Math.round((start + (Number(r.duration) || 0) * 0.92) * 10) / 10;
        for (const name of ['first-paint', 'first-contentful-paint']) {
          const p = new PerformancePaintTiming();
          // Chrome: startTime = presentationTime (frame shown), paintTime
          // earlier, when the frame was drawn.
          const painted_at = Math.round(at * 0.3 * 10) / 10;
          put(p, { name, entryType: 'paint', startTime: at, duration: 0, navigationId: NAV_ID, paintTime: painted_at, presentationTime: at });
          entries.push(p);
          fresh.push(p);
        }
      }
    }
    __ptNotify(fresh);
    return entries.length;
  };

  // PerformanceObserver: pages subscribe and wait for callbacks. An empty
  // `supportedEntryTypes` is a tell (the browser lists a dozen), and an
  // observer that never fires hangs code relying on it.
  const observers = [];
  class PerformanceObserverEntryList {
    constructor(list) { Object.defineProperty(this, '__ptList', { value: list, enumerable: false }); }
    getEntries() { return __s_slice(this.__ptList); }
    getEntriesByType(t) { return this.__ptList.filter((e) => e.entryType === String(t)); }
    getEntriesByName(n, t) { return this.__ptList.filter((e) => e.name === String(n) && (!t || e.entryType === String(t))); }
  }
  tag(PerformanceObserverEntryList.prototype, 'PerformanceObserverEntryList');
  class PerformanceObserver {
    constructor(cb) {
      if (typeof cb !== 'function') throw __pt_mkErr(TypeError, "Failed to construct 'PerformanceObserver': parameter 1 is not of type 'Function'.");
      for (const [k, v] of [['__ptCb', cb], ['__ptTypes', []], ['__ptQueue', []], ['__ptOn', false]]) {
        Object.defineProperty(this, k, { value: v, writable: true, enumerable: false });
      }
    }
    observe(opts) {
      opts = opts || {};
      const types = opts.entryTypes ? Array.from(opts.entryTypes).map(String)
                  : opts.type ? [String(opts.type)] : [];
      for (const t of types) if (__s_indexOf(this.__ptTypes, t) < 0) this.__ptTypes.push(t);
      if (!this.__ptOn) { this.__ptOn = true; observers.push(this); }
      // `buffered`: what happened before subscribing.
      if (opts.buffered) {
        const past = entries.filter((e) => __s_indexOf(this.__ptTypes, e.entryType) >= 0);
        if (past.length) { this.__ptQueue.push(...past); __ptFlush(this); }
      }
    }
    disconnect() {
      this.__ptOn = false; __pt_write(this.__ptQueue, 'length', 0);
      const i = __s_indexOf(observers, this); if (i >= 0) observers.splice(i, 1);
    }
    takeRecords() { return this.__ptQueue.splice(0); }
  }
  tag(PerformanceObserver.prototype, 'PerformanceObserver');
  // Order and contents as in Chrome 148.
  PerformanceObserver.supportedEntryTypes = Object.freeze(['element', 'event', 'first-input',
    'interaction-contentful-paint', 'largest-contentful-paint', 'layout-shift',
    'long-animation-frame', 'longtask', 'mark', 'measure', 'navigation', 'paint',
    'resource', 'soft-navigation', 'visibility-state']);
  globalThis.PerformanceObserver = PerformanceObserver;
  globalThis.PerformanceObserverEntryList = PerformanceObserverEntryList;

  // The callback arrives as a task, not during recording, as in the browser.
  const __ptFlush = (obs) => {
    Promise.resolve().then(() => {
      const batch = obs.__ptQueue.splice(0);
      if (!batch.length || !obs.__ptOn) return;
      try { obs.__ptCb(new PerformanceObserverEntryList(batch), obs); } catch (e) {}
    });
  };
  const __ptNotify = (fresh) => {
    for (const obs of __s_slice(observers)) {
      const mine = fresh.filter((e) => __s_indexOf(obs.__ptTypes, e.entryType) >= 0);
      if (mine.length) { obs.__ptQueue.push(...mine); __ptFlush(obs); }
    }
  };
  // long-animation-frame: Chrome 151 puts these in the main timeline
  // (getEntries) for frames whose work exceeded 50 ms. Without rendering
  // (renderStart 0) it is one long task: a timer, animation frame, document
  // script or message handler. The entry names the culprit script with a
  // source location. The Turnstile report lists the whole timeline.
  let loafCount = 0;
  Object.defineProperty(globalThis, '__pt_noteLoaf', { value: (start, dur, invoker, invokerType, fn, url) => {
    try {
      if (!(dur > 50) || loafCount >= 200) return;
      loafCount++;
      const L = globalThis.PerformanceLongAnimationFrameTiming, ST = globalThis.PerformanceScriptTiming;
      const e = Object.create(L && L.prototype ? L.prototype : PerformanceEntry.prototype);
      const s = Object.create(ST && ST.prototype ? ST.prototype : PerformanceEntry.prototype);
      let src = String(url || ''), fname = '', pos = -1;
      if (typeof fn === 'function') {
        try {
          const loc = typeof __pt_fnLocation === 'function' ? __pt_fnLocation(fn) : null;
          if (loc) {
            if (!src) src = String(loc[0] || '');
            pos = loc[2];
            // Inline script: Chrome counts the position from the start of that
            // <script>'s text; our lines count from the document markup start.
            const m = globalThis.document && document.__ptMarkup;
            if (typeof m === 'string' && String(loc[0]) === String(document.URL)) {
              const lineOf = (idx) => { let n = 0; for (let k = __s_indexOf(m, '\n'); k >= 0 && k < idx; k = __s_indexOf(m, '\n', k + 1)) n++; return n; };
              let best = null;
              for (const el of Array.from(document.scripts || [])) {
                const t = el.textContent; if (!t || el.getAttribute('src')) continue;
                const idx = __s_indexOf(m, t); if (idx < 0) continue;
                const ln = lineOf(idx);
                if (ln <= loc[1] && (!best || ln >= best.ln)) best = { idx, ln };
              }
              if (best) {
                let abs;
                if (loc[1] === best.ln) abs = best.idx + loc[2];
                else { let off = 0, line = 0; while (line < loc[1]) { const nl = __s_indexOf(m, '\n', off); if (nl < 0) break; off = nl + 1; line++; } abs = off + loc[2]; }
                pos = abs - best.idx;
              }
            }
          }
        } catch (x) {}
        try { const n = fn.name; fname = typeof n === 'string' && !/^bound /.test(n) ? n : ''; } catch (x) {}
      }
      const d3 = Math.round(dur * 1000) / 1000;
      const sStart = Math.round((start + 0.1) * 10) / 10;
      ENTRY_ORDER.set(s, ['name', 'entryType', 'startTime', 'duration', 'navigationId', 'invoker', 'invokerType', 'windowAttribution', 'executionStart', 'forcedStyleAndLayoutDuration', 'pauseDuration', 'sourceURL', 'sourceFunctionName', 'sourceCharPosition']);
      ENTRY_STRICT.add(s);
      putEntry(s, { name: 'script', entryType: 'script', startTime: sStart, duration: Math.max(0, Math.round((dur - 0.1) * 10) / 10),
        navigationId: NAV_ID, invoker: String(invoker || ''), invokerType: String(invokerType || 'user-callback'), windowAttribution: 'self',
        executionStart: sStart, forcedStyleAndLayoutDuration: 0, pauseDuration: 0, sourceURL: src, sourceFunctionName: fname,
        sourceCharPosition: pos, window: globalThis });
      ENTRY_ORDER.set(e, ['name', 'entryType', 'startTime', 'duration', 'navigationId', 'renderStart', 'styleAndLayoutStart', 'firstUIEventTimestamp', 'blockingDuration', 'scripts']);
      ENTRY_STRICT.add(e);
      putEntry(e, { name: 'long-animation-frame', entryType: 'long-animation-frame', startTime: Math.round(start * 10) / 10, duration: d3,
        navigationId: NAV_ID, renderStart: 0, styleAndLayoutStart: 0, firstUIEventTimestamp: 0,
        blockingDuration: Math.round((dur - 50) * 10) / 10, scripts: Object.freeze([s]), paintTime: 0, presentationTime: 0 });
      entries.push(e);
      __ptNotify([e]);
    } catch (x) {}
  }, configurable: true, enumerable: false });

  const __ptByStart = (list) => list.map((e, i) => [e, i]).sort((a, b) => ((Number(a[0].startTime) || 0) - (Number(b[0].startTime) || 0)) || (a[1] - b[1])).map((x) => x[0]);
  class Performance {
    now() { return nowMs(); }
    // By start time, as in Chrome (resource entries arrive after they
    // started; the sort is stable).
    getEntries() { return __ptByStart(__s_slice(entries)); }
    getEntriesByType(type) { return __ptByStart(entries.filter((e) => e.entryType === String(type))); }
    getEntriesByName(name, type) {
      return __ptByStart(entries.filter((e) => e.name === String(name) && (!type || e.entryType === String(type))));
    }
    mark(name, opts) {
      const e = Object.create((globalThis.PerformanceMark || PerformanceEntry).prototype);
      ENTRY_ORDER.set(e, ['name', 'entryType', 'startTime', 'duration', 'navigationId']);
      putEntry(e, { name: String(name), entryType: 'mark',
        startTime: (opts && typeof opts.startTime === 'number') ? opts.startTime : nowMs(),
        duration: 0, navigationId: NAV_ID, detail: (opts && opts.detail) !== undefined ? opts.detail : null });
      entries.push(e); __ptNotify([e]); return e;
    }
    measure(name, startOrOpts, end) {
      const e = Object.create((globalThis.PerformanceMeasure || PerformanceEntry).prototype);
      const from = typeof startOrOpts === 'string'
        ? (entries.filter((x) => x.name === startOrOpts).pop() || { startTime: 0 }).startTime
        : (startOrOpts && typeof startOrOpts.start === 'number') ? startOrOpts.start : 0;
      const to = typeof end === 'string'
        ? (entries.filter((x) => x.name === end).pop() || { startTime: nowMs() }).startTime
        : nowMs();
      ENTRY_ORDER.set(e, ['name', 'entryType', 'startTime', 'duration', 'navigationId']);
      putEntry(e, { name: String(name), entryType: 'measure', startTime: from,
                         duration: Math.max(0, to - from), navigationId: NAV_ID, detail: null });
      entries.push(e); __ptNotify([e]); return e;
    }
    clearMarks() {}
    clearMeasures() {}
    clearResourceTimings() { __pt_write(entries, 'length', 0); }
    setResourceTimingBufferSize() {}
    // Listeners come from `EventTarget`, which `Performance` inherits; a
    // dummy here gave three extra prototype names vs the browser.
    toJSON() {
      return { timeOrigin: ORIGIN, timing: timing.toJSON(), navigation: navigation.toJSON() };
    }
  }
  const PERF_BAG = { timeOrigin: ORIGIN, timing, navigation, memory };
  // performance.memory: a new MemoryInfo per access with values sampled at
  // that moment (cached for 50 ms).
  Object.defineProperty(PERF_BAG, 'memory', {
    get() { const m = new MemoryInfo(); MEM_OF.set(m, memSnap()); return m; },
    enumerable: true, configurable: true,
  });
  onProto(Performance.prototype, PERF_BAG);
  // The spare realm is built ahead and handed out when the page inserts an
  // empty frame: its clock must start at hand-out, like a new window.
  {
    const offsets = {};
    for (const k of Object.keys(TIMING)) offsets[k] = TIMING[k] ? TIMING[k] - ORIGIN : 0;
    // The document clock starts at its navigation start. A frame context is
    // built after the document is downloaded; without the shift the frame's
    // navigation started from a ready response and came out three times
    // shorter than Chrome's, and the Turnstile widget puts it in the first POST.
    Object.defineProperty(globalThis, '__pt_shiftOrigin', {
      value: (ms) => {
        const d = Math.max(0, Number(ms) || 0);
        ORIGIN -= d;
        HR_BASE -= d;
        for (const k of Object.keys(offsets)) TIMING[k] = offsets[k] || k === 'navigationStart' ? Math.round(ORIGIN + offsets[k]) : 0;
        PERF_BAG.timeOrigin = ORIGIN;
      },
      enumerable: false, configurable: true,
    });
    Object.defineProperty(globalThis, '__pt_resetClock', {
      value: () => {
        memReset();
        ORIGIN = originNow();
        HR_BASE = typeof hr === 'function' ? hr() : 0;
        last = 0;
        for (const k of Object.keys(offsets)) TIMING[k] = offsets[k] || k === 'navigationStart' ? Math.round(ORIGIN + offsets[k]) : 0;
        PERF_BAG.timeOrigin = ORIGIN;
      },
      enumerable: false, configurable: true,
    });
  }
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
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_padStart = __sm(String.prototype.padStart, 'padStart'),
    __s_toLowerCase = __sm(String.prototype.toLowerCase, 'toLowerCase'),
    __s_toUpperCase = __sm(String.prototype.toUpperCase, 'toUpperCase');
  const N = globalThis;
  const u8 = (d) => {
    if (d instanceof Uint8Array) return d;
    if (ArrayBuffer.isView(d)) return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
    if (d instanceof ArrayBuffer) return new Uint8Array(d);
    return new Uint8Array(0);
  };
  // WebCrypto hands back ArrayBuffers, not views.
  const buf = (a) => __s_slice(a.buffer, a.byteOffset, a.byteOffset + a.byteLength);
  const fail = (name, msg) => { const e = new Error(msg || name); e.name = name; return Promise.reject(e); };
  const nameOf = (a) => __s_toUpperCase(String(typeof a === 'string' ? a : (a && a.name) || ''));
  const hashOf = (a) => { const h = a && a.hash; return __s_toUpperCase(String(typeof h === 'string' ? h : (h && h.name) || 'SHA-256')); };
  const norm = (a) => {
    const o = { name: nameOf(a) };
    if (a && typeof a === 'object') {
      if (a.hash) o.hash = { name: hashOf(a) };
      if (a.length != null) __pt_write(o, 'length', a.length);
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
    KEYS.set(k, { raw, algorithm, extractable: !!extractable, usages: __s_slice(usages || []), type: 'secret' });
    return k;
  };
  const raw = (k) => { const r = KEYS.get(k); return r ? r.raw : null; };

  class SubtleCrypto {
    digest(alg, data) {
      const out = __pt_digest(nameOf(alg), u8(data));
      return out ? Promise.resolve(buf(out)) : fail('NotSupportedError', 'Unrecognized digest algorithm');
    }
    importKey(format, keyData, algorithm, extractable, usages) {
      if (__s_toLowerCase(String(format)) !== 'raw') return fail('NotSupportedError', 'Only raw import is supported');
      return Promise.resolve(mkKey(__s_slice(u8(keyData)), norm(algorithm), extractable, usages));
    }
    exportKey(format, key) {
      const r = KEYS.get(key);
      if (!r) return fail('InvalidAccessError', 'Not a CryptoKey');
      if (__s_toLowerCase(String(format)) !== 'raw') return fail('NotSupportedError', 'Only raw export is supported');
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
    encrypt(alg, key, data) { return this.__ptOp(true, alg, key, data); }
    decrypt(alg, key, data) { return this.__ptOp(false, alg, key, data); }
    __ptOp(enc, alg, key, data) {
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
      const h = Array.from(b).map((x) => __s_padStart(x.toString(16), 2, '0')).join('');
      return __s_slice(h, 0, 8) + '-' + __s_slice(h, 8, 12) + '-' + __s_slice(h, 12, 16) + '-' + __s_slice(h, 16, 20) + '-' + __s_slice(h, 20);
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
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_replace = __sm(String.prototype.replace, 'replace'),
    __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_toLowerCase = __sm(String.prototype.toLowerCase, 'toLowerCase'),
    __s_lastIndexOf = __sm(String.prototype.lastIndexOf, 'lastIndexOf'),
    __s_toUpperCase = __sm(String.prototype.toUpperCase, 'toUpperCase'),
    __s_charCodeAt = __sm(String.prototype.charCodeAt, 'charCodeAt'),
    __s_codePointAt = __sm(String.prototype.codePointAt, 'codePointAt'),
    __s_padStart = __sm(String.prototype.padStart, 'padStart'),
    __s_trim = __sm(String.prototype.trim, 'trim'),
    __s_split = __sm(String.prototype.split, 'split');
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
    if (__s_slice(s, 0, 5) === 'blob:') {
      const b = globalThis.__pt_blobs && globalThis.__pt_blobs.get(s);
      if (!b) return null;
      const body = typeof b.__ptText === 'function' ? b.__ptText() : String(b);
      return { body, type: b.type || '' };
    }
    if (__s_slice(s, 0, 5) === 'data:') {
      const comma = __s_indexOf(s, ',');
      if (comma < 0) return null;
      const meta = __s_slice(s, 5, comma), payload = __s_slice(s, comma + 1);
      try {
        return { body: /;base64/i.test(meta) ? globalThis.atob(payload) : decodeURIComponent(payload),
                 type: __s_split(meta, ';')[0] || 'text/plain' };
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
    // Implementation trace (`NOKK_TRACE_ENC=1`): the challenge's fetch requests.
    if (globalThis.__pt_encTrace) { try { (globalThis.__pt_parentConsole || console).error('[fetch] ' + Math.round(performance.now()) + 'ms #' + id + ' ' + (opts.method || 'GET') + ' ' + __s_slice(String(url), 0, 120) + ' opts=' + JSON.stringify({ mode: opts.mode, credentials: opts.credentials, cache: opts.cache, redirect: opts.redirect, headers: headerObj(opts.headers), signal: !!opts.signal, keepalive: opts.keepalive })); } catch (e) {} }
    // The browser turns `cache` into headers: no-cache -> max-age=0,
    // no-store/reload -> no-cache + Pragma. The challenge server sees them.
    const hdrs = headerObj(opts.headers);
    const cacheMode = String(opts.cache || 'default');
    if (cacheMode === 'no-cache' && !('cache-control' in hdrs)) hdrs['cache-control'] = 'max-age=0';
    else if ((cacheMode === 'no-store' || cacheMode === 'reload') && !('cache-control' in hdrs)) { hdrs['cache-control'] = 'no-cache'; hdrs['pragma'] = 'no-cache'; }
    // Bytes travel as base64: `String(new Uint8Array(…))` is "1,2,3", which sent every
    // binary body (reCAPTCHA's protobuf, a beacon's ArrayBuffer) as digits and commas.
    let body = null, bodyB64 = false;
    const b = opts.body;
    if (b != null) {
      let bytes = null;
      if (b instanceof ArrayBuffer) bytes = new Uint8Array(b);
      else if (ArrayBuffer.isView(b)) bytes = new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
      if (bytes) {
        let bin = '';
        for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
        body = globalThis.btoa(bin); bodyB64 = true;
      } else if (typeof b !== 'string' && globalThis.__pt_blobParts && globalThis.__pt_blobParts(b)) {
        body = b.__ptText();
      } else {
        body = String(b);
      }
    }
    const req = {
      id, url: String(url),
      method: __s_toUpperCase(opts.method || 'GET'),
      headers: hdrs,
      // A blob worker's requests carry no referrer.
      noReferrer: !!globalThis.__ptNoReferrer,
      body, bodyB64,
      // A frame granted access to its cookies marks its requests: the browser
      // adds a separate header to them.
      storageAccess: !!globalThis.__ptStorageAccess,
    };
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject, url: req.url });
      queue.push(req);
    });
  };

  // Page subresources (images, styles, preloads) take the same road as
  // `fetch` but bypass the page's `fetch`: the browser makes these requests
  // itself, and code that replaced `window.fetch` does not see them.
  // The document's memory of what it has already fetched. A page routinely asks
  // for one address twice — a `<link rel=preload as=image>` and then the `<img>`
  // that uses it — and a browser answers the second from memory, so one address
  // is one request. Without this the challenge's beacon went out twice, which is
  // one time more than it is ever meant to be sent.
  const subresources = new Map();
  globalThis.__pt_subresource = (url, kind) => {
    url = String(url);
    const seen = subresources.get(url);
    if (seen) return seen;
    const id = fid++;
    queue.push({ id, url, method: 'GET', headers: { 'x-pt-kind': kind || 'img' }, body: null });
    const p = new Promise((resolve, reject) => { pending.set(id, { resolve, reject, url }); });
    subresources.set(url, p);
    // A failure is not worth remembering: a browser retries a broken image.
    p.catch(() => { subresources.delete(url); });
    return p;
  };

  // What an image turned out to be, by address. Rust reads the two numbers out
  // of the image header — the body reaches us as lossy text, where they are
  // gone — and states them just before settling the request, so an element that
  // has loaded can answer `naturalWidth` the moment its `load` fires.
  const imageSizes = new Map();
  const imageCors = new Set();
  globalThis.__pt_imageMeta = (url, w, h, cors) => {
    imageSizes.set(String(url), [w | 0, h | 0]);
    if (cors) imageCors.add(String(url));
  };
  globalThis.__pt_imageSizeOf = (url) => imageSizes.get(String(url)) || null;
  // Whether the server lets others read this image: decides whether it
  // taints a canvas it is drawn on.
  globalThis.__pt_imageCorsOk = (url) => imageCors.has(String(url));

  // Rust hooks -------------------------------------------------------------
  globalThis.__pt_drainFetchQueue = () => { const q = queue.splice(0); return __ptJSON.stringify(q); };
  globalThis.__pt_pendingFetches = () => pending.size;

  // `bytes64`: the body's own bytes when they are not UTF-8 text (an mp3, an image, a
  // protobuf). `body` is then lossy text, as `text()` would decode it.
  globalThis.__pt_fetchResolve = (id, status, statusText, headers, body, finalUrl, bytes64) => {
    const p = pending.get(id); if (!p) return; pending.delete(id);
    if (globalThis.__pt_encTrace) { try { (globalThis.__pt_parentConsole || console).error('[fetch] ' + Math.round(performance.now()) + 'ms #' + id + ' resp ' + status + ' len=' + (body == null ? 0 : (body.byteLength || body.length || 0)) + ' ' + __s_slice(String(p.url), -60) + ' hdrs=' + __s_slice(JSON.stringify(headers), 0, 300) + ((body && (body.byteLength || body.length || 0) < 500) ? ' body=' + __s_slice(JSON.stringify(typeof body === 'string' ? body : new TextDecoder().decode(body)), 0, 400) : '')); } catch (e) {} }
    const lower = {}; for (const k in headers) lower[__s_toLowerCase(k)] = headers[k];
    const resp = {
      ok: status >= 200 && status < 300, status, statusText: statusText || '',
      url: finalUrl || p.url, redirected: false, type: 'basic', bodyUsed: false, _body: body,
      _bytes: bytes64 ? Uint8Array.from(globalThis.atob(bytes64), (c) => __s_charCodeAt(c, 0)) : null,
      // A real Headers: pages iterate `[...r.headers]` and `for...of`.
      headers: (typeof globalThis.Headers === 'function' ? (() => { try { return new Headers(lower); } catch (e) { return null; } })() : null) || {
        get: (k) => (__s_toLowerCase(k) in lower ? lower[__s_toLowerCase(k)] : null),
        has: (k) => __s_toLowerCase(k) in lower,
        forEach: (f) => { for (const k in lower) f(lower[k], k); },
        entries: () => Object.entries(lower),
        keys: () => Object.keys(lower),
      },
      text() { this.bodyUsed = true; return Promise.resolve(this._body); },
      json() { this.bodyUsed = true; return Promise.resolve(__ptJSON.parse(this._body)); },
      arrayBuffer() { this.bodyUsed = true; return Promise.resolve(this._bytes ? __s_slice(this._bytes).buffer : new TextEncoder().encode(this._body).buffer); },
      clone() { return Object.assign({}, this); },
    };
    p.resolve(resp);
  };
  globalThis.__pt_fetchReject = (id, msg) => {
    const p = pending.get(id); if (!p) return; pending.delete(id);
    if (globalThis.__pt_encTrace) { try { (globalThis.__pt_parentConsole || console).error('[fetch] ' + Math.round(performance.now()) + 'ms #' + id + ' FAIL ' + __s_slice(String(msg), 0, 80) + ' ' + __s_slice(String(p.url), -60)); } catch (e) {} }
    // Chrome says exactly `Failed to fetch` and nothing else, whatever went
    // wrong underneath. Ours used to append the transport's own words — and a
    // page that stringifies the error sends them onward: Cloudflare's worker
    // reports the message it caught verbatim, so "error sending request for
    // uri" would have travelled to them as our signature. The detail stays
    // here, for a debugger to read.
    globalThis.__pt_lastFetchError = msg;
    p.reject(__pt_mkErr(TypeError, 'Failed to fetch'));
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
    // No receiver means the window: `addEventListener('x', f)` unprefixed gives
    // `this === undefined` (class methods are strict), and the browser uses
    // the global object then. Verified on Chrome 148: a bare call, strict mode
    // and even `.call(undefined)` work.
    const __ptSelf = (t) => (t === undefined || t === null ? globalThis : t);
    globalThis.EventTarget = class EventTarget {
      constructor() { Object.defineProperty(this, '__ptLis', { value: Object.create(null), enumerable: false, writable: true }); }
      addEventListener(type, fn, opts) {
        const t = __ptSelf(this);
        if (!fn) return;
        if (!t.__ptLis) Object.defineProperty(t, '__ptLis', { value: Object.create(null), enumerable: false, writable: true });
        const l = (t.__ptLis[type] = t.__ptLis[type] || []);
        if (!l.some(e => e.fn === fn)) l.push({ fn, once: !!(opts && opts.once) });
      }
      removeEventListener(type, fn) {
        const t = __ptSelf(this);
        const l = t.__ptLis && t.__ptLis[type];
        if (l) t.__ptLis[type] = l.filter(e => e.fn !== fn);
      }
      dispatchEvent(ev) {
        const t = __ptSelf(this);
        const type = ev && ev.type;
        const l = (t.__ptLis && t.__ptLis[type]) || [];
        // `window.event` is the event being handled right now: inside a handler
        // it holds the event, outside nothing. Workers have no `event` at all,
        // and restoring must not create it: assigning `undefined` creates an
        // own property.
        const wasOwn = Object.prototype.hasOwnProperty.call(globalThis, 'event');
        const outer = wasOwn ? globalThis.event : undefined;
        if (typeof importScripts === 'undefined') { try { globalThis.event = ev; } catch (x) {} }
        try {
          for (const e of __s_slice(l)) {
            if (e.once) t.removeEventListener(type, e.fn);
            try { typeof e.fn === 'function' ? e.fn.call(t, ev) : (e.fn.handleEvent && e.fn.handleEvent(ev)); } catch (x) {}
          }
          const on = t['on' + type];
          if (typeof on === 'function') { try { on.call(t, ev); } catch (x) {} }
        } finally {
          try { if (wasOwn) globalThis.event = outer; else delete globalThis.event; } catch (x) {}
        }
        return !ev || !ev.defaultPrevented;
      }
    };
    // Chrome's EventTarget prototype is immutable (window chain): take it from
    // the V8 template (`__pt_protoTemplates`), move class members there, and
    // expose a strict function that builds instances with the same class.
    const T = (globalThis.__pt_protos !== undefined ? globalThis.__pt_protos : (() => { let t = null; try { if (typeof __pt_protoTemplates === 'function') t = __pt_protoTemplates() || null; } catch (e) {} try { Object.defineProperty(globalThis, '__pt_protos', { value: t, configurable: true }); } catch (e) {} return t; })());
    if (T && T.et) {
      const C = globalThis.EventTarget, P = T.et, old = C.prototype;
      for (const k of Reflect.ownKeys(old)) {
        if (k === 'constructor') continue;
        try { Object.defineProperty(P, k, Object.getOwnPropertyDescriptor(old, k)); } catch (e) {}
      }
      const F = (function () {
        'use strict';
        return function EventTarget() {
          if (new.target === undefined) throw __pt_mkErr(TypeError, "Failed to construct 'EventTarget': Please use the 'new' operator, this DOM object constructor cannot be called as a function.");
          return Reflect.construct(C, [], new.target);
        };
      })();
      Object.defineProperty(F, 'prototype', { value: P, writable: false, enumerable: false, configurable: false });
      Object.defineProperty(P, 'constructor', { value: F, writable: true, enumerable: false, configurable: true });
      globalThis.EventTarget = globalThis.__pt_native ? __pt_native(F) : F;
    }
  }

  // XHR shaped like the browser's: state in a hidden bag, everything else on
  // the prototype. A real XHR has no own properties, and Cloudflare's code
  // calls `XMLHttpRequest.prototype.open.call(x, ...)` as its standard way
  // around interception.
  {
    const xmask = (f, n) => {
      if (n) { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} }
      return globalThis.__pt_native ? __pt_native(f) : f;
    };
    const XHRET = __ptIllegal('XMLHttpRequestEventTarget');
    Object.setPrototypeOf(XHRET.prototype, globalThis.EventTarget.prototype);
    Object.defineProperty(XHRET.prototype, 'constructor', { value: XHRET, writable: true, configurable: true });
    Object.defineProperty(XHRET.prototype, Symbol.toStringTag, { value: 'XMLHttpRequestEventTarget', configurable: true });
    globalThis.XMLHttpRequestEventTarget = xmask(XHRET, 'XMLHttpRequestEventTarget');

    const XHRUpload = __ptIllegal('XMLHttpRequestUpload');
    Object.setPrototypeOf(XHRUpload.prototype, XHRET.prototype);
    Object.defineProperty(XHRUpload.prototype, 'constructor', { value: XHRUpload, writable: true, configurable: true });
    Object.defineProperty(XHRUpload.prototype, Symbol.toStringTag, { value: 'XMLHttpRequestUpload', configurable: true });
    globalThis.XMLHttpRequestUpload = xmask(XHRUpload, 'XMLHttpRequestUpload');

    const EVENTS = ['abort', 'error', 'load', 'loadend', 'loadstart', 'progress', 'timeout'];
    // `on...` handlers live on XMLHttpRequestEventTarget, for both the request and its upload.
    for (const name of EVENTS) {
      const key = 'on' + name;
      Object.defineProperty(XHRET.prototype, key, {
        get: xmask(function () { const b = this.__ptX; return b ? (b[key] || null) : null; }, 'get ' + key),
        set: xmask(function (v) { const b = this.__ptX; if (b) b[key] = typeof v === 'function' ? v : null; }, 'set ' + key),
        enumerable: true, configurable: true,
      });
    }

    // The listener bag is created by the EventTarget constructor; we do not
    // call it (the prototype is built by hand), so create it ourselves.
    const seedTarget = (o) => {
      try { Object.defineProperty(o, '__ptLis', { value: Object.create(null), enumerable: false, writable: true }); } catch (e) {}
      return o;
    };
    const XHR = (function () {
    'use strict';
    return function XMLHttpRequest() {
      if (!new.target) throw __pt_mkErr(TypeError, "Failed to construct 'XMLHttpRequest': Please use the 'new' operator.");
      seedTarget(this);
      const up = seedTarget(Object.create(XHRUpload.prototype));
      Object.defineProperty(up, '__ptX', { value: {}, enumerable: false });
      Object.defineProperty(this, '__ptX', {
        value: {
          readyState: 0, status: 0, statusText: '', responseText: '', response: '',
          responseType: '', responseURL: '', responseXML: null, withCredentials: false,
          timeout: 0, headers: {}, respHeaders: {}, aborted: false, upload: up,
          method: 'GET', url: '', onreadystatechange: null,
        },
        enumerable: false,
      });
    };
    })();
    Object.setPrototypeOf(XHR.prototype, XHRET.prototype);
    Object.defineProperty(XHR.prototype, 'constructor', { value: XHR, writable: true, configurable: true });
    Object.defineProperty(XHR.prototype, Symbol.toStringTag, { value: 'XMLHttpRequest', configurable: true });
    const P = XHR.prototype;
    const def = (name, get, set) => {
      const d = { enumerable: true, configurable: true, get: xmask(get, 'get ' + name) };
      if (set) d.set = xmask(set, 'set ' + name);
      Object.defineProperty(P, name, d);
    };
    const meth = (name, f) => {
      Object.defineProperty(P, name, { value: xmask(f, name), writable: true, enumerable: true, configurable: true });
    };
    for (const [name, value] of [['UNSENT', 0], ['OPENED', 1], ['HEADERS_RECEIVED', 2], ['LOADING', 3], ['DONE', 4]]) {
      Object.defineProperty(P, name, { value, enumerable: true, configurable: false, writable: false });
      Object.defineProperty(XHR, name, { value, enumerable: true, configurable: false, writable: false });
    }
    for (const name of ['readyState', 'status', 'statusText', 'responseText', 'response',
                        'responseURL', 'responseXML', 'upload']) {
      def(name, function () { return this.__ptX[name]; });
    }
    for (const name of ['responseType', 'withCredentials', 'timeout']) {
      def(name, function () { return this.__ptX[name]; }, function (v) { this.__ptX[name] = v; });
    }
    def('onreadystatechange',
        function () { return this.__ptX.onreadystatechange; },
        function (v) { this.__ptX.onreadystatechange = typeof v === 'function' ? v : null; });

    const fire = (self, type, extra) => {
      const ev = Object.assign({
        type, target: self, currentTarget: self, isTrusted: true,
        lengthComputable: false, loaded: 0, total: 0, bubbles: false, cancelable: false,
      }, extra || {});
      self.dispatchEvent(ev);
    };
    // Order matters: `readystatechange` reaches both the handler property and
    // the listeners.
    const setState = (self, n) => { __pt_write(self.__ptX, 'readyState', n); fire(self, 'readystatechange'); };

    meth('open', function (method, url) {
      const b = this.__ptX;
      b.method = __s_toUpperCase(String(method)); b.url = String(url);
      setState(this, 1);
    });
    meth('setRequestHeader', function (k, v) { this.__ptX.headers[k] = String(v); });
    meth('overrideMimeType', function () {});
    meth('setAttributionReporting', function () {});
    meth('setPrivateToken', function () {});
    // Every line ends with CRLF, including the last: code splitting on '\r\n'
    // gets an empty trailing element in the browser.
    meth('getAllResponseHeaders', function () {
      return Object.entries(this.__ptX.respHeaders).map(([k, v]) => k + ': ' + v + '\r\n').join('');
    });
    meth('getResponseHeader', function (k) {
      const v = this.__ptX.respHeaders[__s_toLowerCase(String(k))];
      return v === undefined ? null : v;
    });
    meth('abort', function () {
      const b = this.__ptX;
      b.aborted = true; __pt_write(b, 'readyState', 4); b.status = 0;
      fire(this, 'abort'); fire(this, 'loadend');
    });
    meth('send', function (body) {
      const self = this, b = this.__ptX;
      fire(this, 'loadstart');
      // Mark the request as XHR: the browser's resource list calls it
      // `xmlhttprequest`, not `fetch`, visible from outside.
      // The browser sets the content type itself when the page did not: a
      // string goes as `text/plain;charset=UTF-8`, a form with its own type.
      const headers = Object.assign({}, b.headers, { 'x-pt-kind': 'xhr' });
      if (body != null && !Object.keys(headers).some((k) => __s_toLowerCase(k) === 'content-type')) {
        if (typeof body === 'string') headers['Content-Type'] = 'text/plain;charset=UTF-8';
        else if (globalThis.URLSearchParams && body instanceof URLSearchParams) {
          headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
        } else if (globalThis.Blob && body instanceof globalThis.Blob && body.type) {
          headers['Content-Type'] = body.type;
        } else if (globalThis.Document && body instanceof globalThis.Document) {
          headers['Content-Type'] = 'text/html;charset=UTF-8';
        }
      }
      // Implementation trace (`NOKK_TRACE_ENC=1`): the challenge's XHRs (URL,
      // body and response sizes); invisible to the page.
      const encTrace = !!globalThis.__pt_encTrace;
      const bodyLen = body == null ? 0 : (typeof body === 'string' ? body.length : (body.byteLength || body.size || 0));
      if (encTrace) { try { (globalThis.__pt_parentConsole || console).error('[xhr] ' + Math.round(performance.now()) + 'ms ' + b.method + ' ' + __s_slice(String(b.url), 0, 110) + ' body=' + bodyLen); } catch (e) {} }
      fetch(b.url, { method: b.method, headers, body })
        .then(async (r) => {
          if (b.aborted) return;
          b.status = r.status; b.statusText = r.statusText; b.responseURL = r.url || b.url;
          r.headers.forEach((v, k) => { b.respHeaders[k] = v; });
          setState(self, 2); setState(self, 3);
          if (b.responseType === 'arraybuffer') { b.response = await r.arrayBuffer(); b.responseText = ''; }
          else b.responseText = await r.text();
          if (encTrace) { try { (globalThis.__pt_parentConsole || console).error('[xhr] ' + Math.round(performance.now()) + 'ms resp ' + r.status + ' ' + __s_slice(String(b.url), -40) + ' body=' + bodyLen + ' resp=' + b.responseText.length); } catch (e) {} }
          if (b.responseType !== 'arraybuffer') {
            try { b.response = b.responseType === 'json' ? __ptJSON.parse(b.responseText || 'null') : b.responseText; }
            catch (e) { b.response = null; }
          }
          const got = b.responseType === 'arraybuffer' ? b.response.byteLength : b.responseText.length;
          setState(self, 4);
          fire(self, 'progress', { lengthComputable: true, loaded: got, total: got });
          fire(self, 'load'); fire(self, 'loadend');
        })
        .catch(() => {
          if (b.aborted) return;
          b.status = 0; setState(self, 4);
          fire(self, 'error'); fire(self, 'loadend');
        });
    });
    globalThis.XMLHttpRequest = xmask(XHR, 'XMLHttpRequest');
  }

  // Minimal Headers/TextEncoder if missing.
  if (!globalThis.TextEncoder) {
    // UTF-8 encoder: anything hashing encoded text depends on it (the old
    // version emitted the low byte of each code unit).
    globalThis.TextEncoder = class TextEncoder {
      get encoding() { return 'utf-8'; }
      encode(input) {
        const s = input === undefined ? '' : String(input);
        // Implementation trace (`NOKK_TRACE_ENC=1`): challenge report chunks in
        // plain text, without hooks visible to the page: length, count of
        // non-zero chars and the same sum as measured in Chrome.
        if (globalThis.__pt_encTrace && s.length > 4) {
          try {
            let nz = 0, sum = 0;
            for (let i = 0; i < s.length; i++) { const c = __s_charCodeAt(s, i); if (c) { nz++; sum = (sum * 31 + c) >>> 0; } }
            let host = '?'; try { host = __s_slice(String(globalThis.location && globalThis.location.host), 0, 18); } catch (e) {}
            (globalThis.__pt_parentConsole || console).error('[enc] ' + Math.round(performance.now()) + 'ms ' + host + ' len=' + s.length + ' nz=' + nz + ' sum=' + sum + ' ' + (s.length < 200 ? JSON.stringify(__s_slice(s, 0, 80)) : JSON.stringify(__s_slice(s, 0, 40))));
            // Length ranges `lo-hi,lo-hi` in the flag value dump the whole chunk.
            const dump = __s_split(String(globalThis.__pt_encTrace), ',').some((r) => { const m = /^(\d+)-(\d+)$/.exec(__s_trim(r)); return m && s.length >= +m[1] && s.length <= +m[2]; });
            // The console truncates lines past 600 chars: dump in 500-char JSON slices.
            if (dump) { const j = __s_replace(JSON.stringify(s), /[^\x21-\x7e]/g, (c) => '\\u' + __s_padStart(__s_charCodeAt(c, 0).toString(16), 4, '0')), k = Math.ceil(j.length / 500); for (let i = 0; i < k; i++) (globalThis.__pt_parentConsole || console).error('[encdump] len=' + s.length + ' part=' + i + '/' + k + ' ' + __s_slice(j, i * 500, (i + 1) * 500)); }
          } catch (e) {}
        }
        const out = [];
        for (let i = 0; i < s.length; i++) {
          let cp = __s_charCodeAt(s, i);
          // A surrogate pair is one character; the browser replaces a lone surrogate.
          if (cp >= 0xd800 && cp <= 0xdbff) {
            const next = __s_charCodeAt(s, i + 1);
            if (next >= 0xdc00 && next <= 0xdfff) { cp = 0x10000 + ((cp - 0xd800) << 10) + (next - 0xdc00); i++; }
            else cp = 0xfffd;
          } else if (cp >= 0xdc00 && cp <= 0xdfff) cp = 0xfffd;
          if (cp < 0x80) out.push(cp);
          else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
          else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
          else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
        }
        return new Uint8Array(out);
      }
      encodeInto(input, target) {
        if (!(target instanceof Uint8Array)) {
          throw __pt_mkErr(TypeError, "Failed to execute 'encodeInto' on 'TextEncoder': parameter 2 is not of type 'Uint8Array'.");
        }
        const s = input === undefined ? '' : String(input);
        const bytes = this.encode(s);
        // Only whole characters are written: the browser never leaves half in the buffer.
        let written = 0, read = 0, i = 0;
        while (i < s.length) {
          const cp = __s_codePointAt(s, i);
          const size = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
          if (written + size > target.length) break;
          for (let k = 0; k < size; k++) target[written + k] = bytes[written + k];
          written += size;
          const step = cp > 0xffff ? 2 : 1;
          read += step; i += step;
        }
        return { read, written };
      }
    };
  }

  // --- base64 and the other globals every browser has ---------------------
  // `atob` missing is not a nicety: Cloudflare's challenge script decodes base64
  // on its first line and dies with a ReferenceError, and any page doing the same
  // breaks just as silently. These are cheap and their absence is both a
  // functional break and something a probe can list in one line.
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  if (!globalThis.atob) {
    const NATIVE_ATOB = globalThis.__pt_atob;
    globalThis.atob = function atob(input) {
      if (typeof NATIVE_ATOB === 'function') {
        const out = NATIVE_ATOB(String(input));
        if (out === null) {
          throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'atob' on 'Window': The string to be decoded is not correctly encoded.", 'InvalidCharacterError');
        }
        return out;
      }
      const s = __s_replace(String(input), /[ \t\n\f\r]/g, '');
      const body = __s_replace(s, /=+$/, '');
      if (body.length % 4 === 1 || /[^A-Za-z0-9+/]/.test(body)) {
        throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'atob' on 'Window': The string to be decoded is not correctly encoded.", 'InvalidCharacterError');
      }
      let out = '', bits = 0, acc = 0;
      for (const ch of body) {
        acc = (acc << 6) | __s_indexOf(B64, ch);
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
        const c0 = __s_charCodeAt(s, i), c1 = __s_charCodeAt(s, i + 1), c2 = __s_charCodeAt(s, i + 2);
        if (c0 > 255 || c1 > 255 || c2 > 255) {
          throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'btoa' on 'Window': The string to be encoded contains characters outside of the Latin1 range.", 'InvalidCharacterError');
        }
        const n = (c0 << 16) | ((c1 || 0) << 8) | (c2 || 0);
        out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63]
          + (isNaN(c1) ? '=' : B64[(n >> 6) & 63])
          + (isNaN(c2) ? '=' : B64[n & 63]);
      }
      return out;
    };
  }
  // Structured clone per HTML (StructuredSerializeInternal), verified against
  // Chrome 151 on 30 kinds of values:
  // Boolean/Number/String/BigInt wrappers, errors (name from the seven native
  // ones, otherwise Error; own message, cause and stack), holes and
  // non-index array properties, getters read into data, prototype not
  // carried; Symbol, functions, WeakMap/Promise and platform objects throw
  // DataCloneError with Chrome's text. Blob, File, ImageData and
  // DOMException are cloned.
  if (!globalThis.structuredClone) {
    const ERR_NAMES = new Set(['Error', 'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError']);
    const JS_UNCLONEABLE = new Set(['WeakMap', 'WeakSet', 'WeakRef', 'FinalizationRegistry', 'Promise', 'Generator', 'AsyncGenerator', 'Module']);
    const tagOf = (x) => { try { return __s_slice(Object.prototype.toString.call(x), 8, -1); } catch (e) { return 'Object'; } };
    const cloneErr = (what) => {
      const m = "Failed to execute 'structuredClone' on 'Window': " + what + ' could not be cloned.';
      return typeof DOMException === 'function' ? __pt_mkErr(DOMException, m, 'DataCloneError') : new Error(m);
    };
    const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
    globalThis.structuredClone = function structuredClone(v) {
      if (arguments.length < 1) throw __pt_mkErr(TypeError, "Failed to execute 'structuredClone' on 'Window': 1 argument required, but only 0 present.");
      const opts = arguments[1];
      const seen = new Map();
      // Transfer detaches: in the browser the source buffer has zero length afterwards.
      const moved = [];
      try {
        const list = opts && opts.transfer ? Array.from(opts.transfer) : [];
        for (const t of list) {
          if (t instanceof ArrayBuffer && typeof t.transfer === 'function') moved.push(t);
        }
      } catch (e) {}
      const walk = (x) => {
        if (typeof x === 'symbol') throw cloneErr(x.toString());
        if (typeof x === 'function') { let src = ''; try { src = Function.prototype.toString.call(x); } catch (e) {} throw cloneErr(src); }
        if (x === null || typeof x !== 'object') return x;
        if (seen.has(x)) return seen.get(x);
        const tag = tagOf(x);
        const keep = (c) => { seen.set(x, c); return c; };
        switch (tag) {
          case 'Boolean': return keep(Object(Boolean.prototype.valueOf.call(x)));
          case 'Number': return keep(Object(Number.prototype.valueOf.call(x)));
          case 'String': return keep(Object(String.prototype.valueOf.call(x)));
          case 'BigInt': return keep(Object(BigInt.prototype.valueOf.call(x)));
          case 'Date': return keep(new Date(Date.prototype.getTime.call(x)));
          case 'RegExp': return keep(new RegExp(x.source, x.flags));
          case 'ArrayBuffer': return keep(__s_slice(x, 0));
          case 'Map': { const m = keep(new Map()); for (const [k, val] of Map.prototype.entries.call(x)) m.set(walk(k), walk(val)); return m; }
          case 'Set': { const st = keep(new Set()); for (const val of Set.prototype.values.call(x)) st.add(walk(val)); return st; }
          case 'Error': {
            let name = 'Error'; try { const n = x.name; if (ERR_NAMES.has(n)) name = n; } catch (e) {}
            const C = globalThis[name] || Error;
            // A real error (internal [[ErrorData]] slot), not Object.create.
            const e = keep(new C());
            const d = Object.getOwnPropertyDescriptor(x, 'message');
            if (d && 'value' in d) Object.defineProperty(e, 'message', { value: String(d.value), writable: true, enumerable: false, configurable: true });
            if (own(x, 'cause')) { let c; try { c = x.cause; } catch (er) {} Object.defineProperty(e, 'cause', { value: walk(c), writable: true, enumerable: false, configurable: true }); }
            let st; try { st = x.stack; } catch (er) {}
            if (typeof st === 'string') Object.defineProperty(e, 'stack', { value: st, writable: true, enumerable: false, configurable: true });
            return e;
          }
        }
        if (ArrayBuffer.isView(x)) return keep(new x.constructor(x));
        if (Array.isArray(x)) {
          const a = keep(new Array(x.length));
          for (const k of Object.keys(x)) a[k] = walk(x[k]);
          return a;
        }
        if (tag === 'Blob' && typeof x.slice === 'function') return keep(x.slice(0, x.size, x.type));
        if (tag === 'File' && typeof File === 'function') return keep(new File([x], x.name, { type: x.type, lastModified: x.lastModified }));
        if (tag === 'ImageData' && typeof ImageData === 'function') return keep(new ImageData(new Uint8ClampedArray(x.data), x.width, x.height));
        if (tag === 'DOMException' && typeof DOMException === 'function') return keep(__pt_mkErr(DOMException, x.message, x.name));
        if (JS_UNCLONEABLE.has(tag)) throw cloneErr('#<' + tag + '>');
        if (tag !== 'Object' && tag !== 'Arguments') throw cloneErr(tag + ' object');
        const o = keep({});
        for (const k of Object.keys(x)) o[k] = walk(x[k]);
        return o;
      };
      const out = walk(v);
      // Detach after copying: the browser does the same, in the same order.
      for (const b of moved) { try { b.transfer(0); } catch (e) {} }
      return out;
    };
  }
  if (!globalThis.reportError) globalThis.reportError = function reportError(e) { try { console.error(e); } catch (x) {} };
  if (!globalThis.AbortController) {
    // We keep the class; outside sits a facade where `new AbortSignal()` is refused.
    const __AbortSignal = globalThis.AbortSignal = globalThis.AbortSignal || class AbortSignal {
      constructor() { __pt_write(this, 'aborted', false); __pt_write(this, 'reason', undefined); this.onabort = null; this._ls = []; }
      addEventListener(t, fn) { if (t === 'abort' && typeof fn === 'function') this._ls.push(fn); }
      removeEventListener(t, fn) { const i = __s_indexOf(this._ls, fn); if (i >= 0) this._ls.splice(i, 1); }
      dispatchEvent() { return true; }
      throwIfAborted() { if (this.aborted) throw this.reason; }
      static abort(reason) { const s = new __AbortSignal(); __pt_write(s, 'aborted', true); __pt_write(s, 'reason', reason); return s; }
    };
    globalThis.AbortController = class AbortController {
      constructor() { __pt_write(this, 'signal', new __AbortSignal()); }
      abort(reason) {
        const s = this.signal;
        if (s.aborted) return;
        __pt_write(s, 'aborted', true);
        __pt_write(s, 'reason', reason === undefined ? new Error('signal is aborted without reason') : reason);
        const ev = { type: 'abort', target: s, currentTarget: s };
        try { if (typeof s.onabort === 'function') s.onabort(ev); } catch (e) {}
        for (const fn of __s_slice(s._ls)) { try { fn(ev); } catch (e) {} }
      }
    };
  }

  // --- DOMException, MessageChannel, and the fetch classes ----------------
  // All present in every browser and all absent here, which breaks pages in the
  // quietest possible way: a widget that opens a `MessageChannel` to talk to its
  // embedder, or constructs a `Request`, simply stops — no error, no output.
  if (!globalThis.DOMException) {
    // An exception has a single own property, `stack`; `message` and `name`
    // are read from the prototype, as in the browser.
    const __dx = new WeakMap();
    const __ErrC = Error;
    globalThis.DOMException = class DOMException extends Error {
      constructor(message, name) {
        // The stack is captured here in `super()` with headroom for our frames
        // (see `__pt_mkErr`), otherwise the page's limit falls short.
        let lim; try { lim = __ErrC.stackTraceLimit; } catch (e) {}
        const bump = typeof lim === 'number' && lim >= 0 && lim < Infinity;
        if (bump) { try { __ErrC.stackTraceLimit = lim + 16; } catch (e) {} }
        try { super(); } finally { if (bump) { try { __ErrC.stackTraceLimit = lim; } catch (e) {} } }
        __dx.set(this, { message: message === undefined ? '' : String(message), name: name === undefined ? 'Error' : String(name) });
        // Chrome's `new DOMException(...)` from page script has no `stack`: the
        // own property appears only on binding-thrown ones.
        try { if (!(typeof globalThis.__pt_errDepth === 'function' && globalThis.__pt_errDepth() > 0)) delete this.stack; } catch (e) {}
      }
      get message() { const st = __dx.get(this); return st ? st.message : ''; }
      get name() { const st = __dx.get(this); return st ? st.name : 'Error'; }
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
    const __MessagePort = globalThis.MessagePort = class MessagePort {
      constructor() {
        Object.defineProperty(this, '__pt', {
          // `remote`: the other end lives in another frame; the engine carries the message.
          value: { peer: null, remote: null, started: false, queue: [], onmessage: null, listeners: [] },
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
        const l = this.__pt.listeners, i = __s_indexOf(l, fn);
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
        if (this.__pt.remote && typeof globalThis.__pt_portOut === 'function') {
          globalThis.__pt_portOut(this.__pt.remote, data);
          return;
        }
        const peer = this.__pt.peer;
        if (!peer) return;
        const ev = { type: 'message', data, origin: '', lastEventId: '', source: null, ports: [], isTrusted: true, target: peer, currentTarget: peer };
        // A port message is a task, not a microtask: in the browser it comes
        // after already queued zero-delay timers.
        setTimeout(() => {
          const st = peer.__pt;
          if (!st.started) { st.queue.push(ev); return; }
          peer.__ptDeliver(ev);
        }, 0);
      }
      __ptDeliver(ev) {
        const st = this.__pt;
        try { if (typeof st.onmessage === 'function') st.onmessage.call(this, ev); } catch (e) {}
        for (const fn of __s_slice(st.listeners)) { try { fn.call(this, ev); } catch (e) {} }
      }
    };
    globalThis.MessageChannel = class MessageChannel {
      constructor() {
        // The class, not the window name: outside sits a facade where
        // `new MessagePort()` is "Illegal constructor", as in the browser.
        const a = new __MessagePort(), b = new __MessagePort();
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
        const key = __s_toLowerCase(String(k)), cur = this.__h.get(key);
        this.__h.set(key, cur === undefined ? String(v) : cur + ', ' + String(v));
      }
      set(k, v) { this.__h.set(__s_toLowerCase(String(k)), String(v)); }
      get(k) { const v = this.__h.get(__s_toLowerCase(String(k))); return v === undefined ? null : v; }
      has(k) { return this.__h.has(__s_toLowerCase(String(k))); }
      delete(k) { this.__h.delete(__s_toLowerCase(String(k))); }
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
        __pt_write(this, 'url', String(input && input.url !== undefined ? input.url : input));
        __pt_write(this, 'method', __s_toUpperCase(String(init.method || (input && input.method) || 'GET')));
        __pt_write(this, 'headers', new globalThis.Headers(init.headers || (input && input.headers)));
        __pt_write(this, 'credentials', init.credentials || 'same-origin');
        __pt_write(this, 'mode', init.mode || 'cors');
        __pt_write(this, 'cache', init.cache || 'default');
        __pt_write(this, 'redirect', init.redirect || 'follow');
        __pt_write(this, 'referrer', init.referrer === undefined ? 'about:client' : String(init.referrer));
        __pt_write(this, 'signal', init.signal || null);
        Object.defineProperty(this, '__body', { value: init.body === undefined ? null : init.body, enumerable: false });
        __pt_write(this, 'bodyUsed', false);
        // The body sets its own type unless given: a string is
        // `text/plain;charset=UTF-8`, a form `multipart/form-data`, a blob its
        // own. The browser does this.
        try {
          const b = this.__body;
          if (b != null && !this.headers.has('content-type')) {
            if (typeof b === 'string') this.headers.set('content-type', 'text/plain;charset=UTF-8');
            else if (globalThis.URLSearchParams && b instanceof URLSearchParams) {
              this.headers.set('content-type', 'application/x-www-form-urlencoded;charset=UTF-8');
            } else if (globalThis.FormData && b instanceof FormData) {
              this.headers.set('content-type', 'multipart/form-data; boundary=----WebKitFormBoundary');
            } else if (b && typeof b === 'object' && typeof b.type === 'string' && b.type) {
              this.headers.set('content-type', b.type);
            }
          }
        } catch (e) {}
      }
      clone() { return new globalThis.Request(this); }
      text() { __pt_write(this, 'bodyUsed', true); return Promise.resolve(this.__body == null ? '' : String(this.__body)); }
      json() { return this.text().then(JSON.parse); }
      arrayBuffer() { return this.text().then(t => new TextEncoder().encode(t).buffer); }
    };
  }
  if (!globalThis.Response) {
    globalThis.Response = class Response {
      constructor(body, init) {
        init = init || {};
        __pt_write(this, 'status', init.status === undefined ? 200 : (init.status | 0));
        __pt_write(this, 'statusText', init.statusText === undefined ? '' : String(init.statusText));
        __pt_write(this, 'headers', new globalThis.Headers(init.headers));
        __pt_write(this, 'ok', this.status >= 200 && this.status < 300);
        __pt_write(this, 'redirected', false);
        __pt_write(this, 'type', 'default');
        __pt_write(this, 'url', '');
        __pt_write(this, 'bodyUsed', false);
        // A body given as bytes is stored as bytes: the browser's
        // `new Response(u8)` returns the same bytes from `arrayBuffer()`
        // (stringifying it to "0,97,115..." broke WebAssembly.instantiateStreaming).
        let raw = body == null ? '' : body;
        try {
          if (raw instanceof ArrayBuffer) raw = new Uint8Array(__s_slice(raw, 0));
          else if (ArrayBuffer.isView(raw)) raw = new Uint8Array(__s_slice(raw.buffer, raw.byteOffset, raw.byteOffset + raw.byteLength));
          else if (typeof raw !== 'string' && !(globalThis.Blob && raw instanceof Blob) && !(globalThis.FormData && raw instanceof FormData) && !(globalThis.URLSearchParams && raw instanceof URLSearchParams) && !(globalThis.ReadableStream && raw instanceof ReadableStream)) raw = String(raw);
        } catch (e) { raw = String(raw); }
        Object.defineProperty(this, '__body', { value: raw, enumerable: false });
      }
      static error() { const r = new globalThis.Response(null, { status: 0 }); __pt_write(r, 'type', 'error'); return r; }
      static json(data, init) { return new globalThis.Response(__ptJSON.stringify(data), init); }
      clone() { return new globalThis.Response(this.__body, { status: this.status, statusText: this.statusText, headers: this.headers }); }
      __ptBytes() {
        __pt_write(this, 'bodyUsed', true);
        const b = this.__body;
        if (b instanceof Uint8Array) return Promise.resolve(b);
        if (globalThis.Blob && b instanceof Blob && typeof b.arrayBuffer === 'function') return b.arrayBuffer().then((ab) => new Uint8Array(ab));
        if (globalThis.URLSearchParams && b instanceof URLSearchParams) return Promise.resolve(new TextEncoder().encode(b.toString()));
        return Promise.resolve(new TextEncoder().encode(String(b)));
      }
      text() { return this.__ptBytes().then((u) => new TextDecoder().decode(u)); }
      json() { return this.text().then(JSON.parse); }
      arrayBuffer() { return this.__ptBytes().then((u) => __s_slice(u.buffer, u.byteOffset, u.byteOffset + u.byteLength)); }
      bytes() { return this.__ptBytes().then((u) => __s_slice(u)); }
      blob() { return this.__ptBytes().then((u) => new Blob([u], { type: String(this.headers.get('content-type') || '') })); }
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
        if (st.locked) throw __pt_mkErr(TypeError, 'ReadableStream is locked');
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
        if (!pair || !pair.writable || !pair.readable) throw __pt_mkErr(TypeError, 'pipeThrough needs a { writable, readable }');
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
        if (st.locked) throw __pt_mkErr(TypeError, 'WritableStream is locked');
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
        __pt_write(this, 'name', String(name));
        this.onmessage = null; this.onmessageerror = null;
        Object.defineProperty(this, '__pt', { value: { closed: false, listeners: [] }, enumerable: false });
        if (!__bcRooms.has(this.name)) __bcRooms.set(this.name, new Set());
        __bcRooms.get(this.name).add(this);
      }
      postMessage(data) {
        if (this.__pt.closed) throw __pt_mkErr(globalThis.DOMException || Error, 'channel is closed', 'InvalidStateError');
        const peers = __bcRooms.get(this.name);
        if (!peers) return;
        for (const p of peers) {
          if (p === this || p.__pt.closed) continue;   // never echoes to the sender
          // The browser's broadcast goes through another thread and arrives a
          // few milliseconds after timers.
          setTimeout(() => {
            const ev = { type: 'message', data, origin: (globalThis.location && location.origin) || '', lastEventId: '', source: null, ports: [], isTrusted: true, target: p, currentTarget: p };
            try { if (typeof p.onmessage === 'function') p.onmessage(ev); } catch (e) {}
            for (const fn of __s_slice(p.__pt.listeners)) { try { fn.call(p, ev); } catch (e) {} }
          }, 5);
        }
      }
      addEventListener(t, fn) { if (t === 'message' && typeof fn === 'function') this.__pt.listeners.push(fn); }
      removeEventListener(t, fn) { const l = this.__pt.listeners, i = __s_indexOf(l, fn); if (i >= 0) l.splice(i, 1); }
      dispatchEvent() { return true; }
      close() { this.__pt.closed = true; const r = __bcRooms.get(this.name); if (r) r.delete(this); }
    };
  }

  if (!globalThis.CSS) {
    globalThis.CSS = {
      escape: (s) => __s_replace(String(s), /[^a-zA-Z0-9_\u00a0-\uffff-]/g, (c) => '\\' + c),
      // Answering `true` to everything would be its own giveaway; a real engine
      // rejects nonsense. This accepts a well-formed declaration and no more.
      supports: (a, b) => {
        // Property names are checked against the engine's list: the browser
        // answers `false` for made-up ones, and "anything with a colon" is a
        // tell. Custom properties (`--x`) are always accepted.
        const known = (n) => (__s_lastIndexOf(String(n), '--', 0) === 0
          || (globalThis.__pt_cssKnown ? __pt_cssKnown(n) : /^[-a-zA-Z]+$/.test(n)));
        if (b !== undefined) return /^[-a-zA-Z]+$/.test(String(a)) && String(b).length > 0 && known(a);
        const m = /^\s*(--[-a-zA-Z0-9_]+|[-a-zA-Z]+)\s*:\s*([^;]+?)\s*$/.exec(String(a));
        return !!m && known(m[1]);
      },
    };
  }

  // Minimal but genuinely working IndexedDB: pages use it to store and to probe
  // for storage at all, and `undefined` is the loudest possible answer.
  if (!globalThis.indexedDB) {
    const __idbData = new Map();   // dbName -> { version, stores: Map<name, Map> }
    // Databases belong to the origin, not the document: on navigation the
    // engine takes them from the old document and gives them to the next one
    // of the same origin. Values go through JSON.
    (globalThis.__pt_carryParts || (globalThis.__pt_carryParts = {})).idb = {
      out: () => [...__idbData].map(([name, e]) => [name, e.version,
        [...e.stores].map(([sn, m]) => [sn, [...m].filter(([, v]) => {
          try { __ptJSON.stringify(v); return true; } catch (x) { return false; }
        })])]),
      in: (dbs) => {
        if (!Array.isArray(dbs)) return;
        for (const [name, version, stores] of dbs) {
          __idbData.set(String(name), { version: version | 0,
            stores: new Map((stores || []).map(([sn, rows]) => [String(sn), new Map(rows || [])])) });
        }
      },
    };
    const req = (run) => {
      const r = { readyState: 'pending', result: undefined, error: null,
        onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null,
        addEventListener(t, fn) { this['on' + t] = fn; }, removeEventListener() {}, dispatchEvent() { return true; } };
      queueMicrotask(() => {
        try {
          run(r);
          __pt_write(r, 'readyState', 'done');
          const ev = { type: 'success', target: r, currentTarget: r };
          if (typeof r.onsuccess === 'function') r.onsuccess(ev);
        } catch (e) {
          r.error = e; __pt_write(r, 'readyState', 'done');
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
          __pt_write(r, 'readyState', 'done');
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
    for (const fn of __s_slice(st.listeners.get(type) || [])) {
      try { fn.call(sock, evt); } catch (e) {}
    }
  };

  globalThis.__pt_drainWsQueue = () => wsOps.splice(0);
  globalThis.__pt_wsOpen = (id, protocol) => {
    const sock = wsLive.get(id); if (!sock) return;
    const st = wsState.get(sock);
    __pt_write(st, 'readyState', 1); st.protocol = String(protocol || '');
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
      if (arguments.length < 1) throw __pt_mkErr(TypeError, "Failed to construct 'WebSocket': 1 argument required, but only 0 present.");
      // ws:/wss: only. http(s) is upgraded as the URL parser does; anything else
      // is a SyntaxError, exactly as in a browser.
      const base = globalThis.location ? String(location.href) : 'https://localhost/';
      let abs;
      try { abs = new globalThis.URL(String(url), base).href; } catch (e) { abs = String(url); }
      const scheme = __s_toLowerCase(String((/^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(abs) || [])[1] || ''));
      if (scheme === 'http') abs = 'ws' + __s_slice(abs, 4);
      else if (scheme === 'https') abs = 'wss' + __s_slice(abs, 5);
      else if (scheme !== 'ws' && scheme !== 'wss') {
        throw new SyntaxError("Failed to construct 'WebSocket': The URL's scheme must be either 'ws' or 'wss'. '" + scheme + ":' is not allowed.");
      }
      const list = protocols == null ? [] : (Array.isArray(protocols) ? protocols.map(String) : [String(protocols)]);
      const id = wsid++;
      wsState.set(this, {
        id, url: abs, protocol: '', extensions: '', binaryType: 'blob',
        bufferedAmount: 0, readyState: 0, listeners: new Map(),
        origin: __s_replace(__s_replace(abs, /^ws/, 'http'), /^([a-z]+:\/\/[^/]*).*$/, '$1'),
        onopen: null, onmessage: null, onclose: null, onerror: null,
      });
      wsLive.set(id, this);
      wsOps.push({ op: 'open', id, url: abs, protocols: list });
    }
    send(data) {
      const st = wsState.get(this);
      if (st.readyState === 0) {
        const msg = "Failed to execute 'send' on 'WebSocket': Still in CONNECTING state.";
        throw (typeof DOMException === 'function' ? __pt_mkErr(DOMException, msg, 'InvalidStateError')
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
      __pt_write(st, 'readyState', 2);
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
      const i = __s_indexOf(l, fn); if (i >= 0) l.splice(i, 1);
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
/// Static members of the interface objects, measured from Chrome 148: the
/// constants and statics that live on the interface itself rather than on its
/// prototype. A graph walk reads them on its first step.
const IFACE_STATICS: &str = r#"{"AbortSignal":{"f":{"any":1,"timeout":1}},"AudioDecoder":{"f":{"isConfigSupported":1}},"AudioEncoder":{"f":{"isConfigSupported":1}},"CSSNumericValue":{"f":{"parse":1}},"CSSRule":{"c":{"STYLE_RULE":1,"CHARSET_RULE":2,"IMPORT_RULE":3,"MEDIA_RULE":4,"FONT_FACE_RULE":5,"PAGE_RULE":6,"MARGIN_RULE":9,"NAMESPACE_RULE":10,"KEYFRAMES_RULE":7,"KEYFRAME_RULE":8,"COUNTER_STYLE_RULE":11,"FONT_FEATURE_VALUES_RULE":14,"SUPPORTS_RULE":12}},"CSSStyleValue":{"f":{"parse":2,"parseAll":2}},"ClipboardItem":{"f":{"supports":1}},"Credential":{"f":{"isConditionalMediationAvailable":0}},"CropTarget":{"f":{"fromElement":1}},"DOMException":{"c":{"INDEX_SIZE_ERR":1,"DOMSTRING_SIZE_ERR":2,"HIERARCHY_REQUEST_ERR":3,"WRONG_DOCUMENT_ERR":4,"INVALID_CHARACTER_ERR":5,"NO_DATA_ALLOWED_ERR":6,"NO_MODIFICATION_ALLOWED_ERR":7,"NOT_FOUND_ERR":8,"NOT_SUPPORTED_ERR":9,"INUSE_ATTRIBUTE_ERR":10,"INVALID_STATE_ERR":11,"SYNTAX_ERR":12,"INVALID_MODIFICATION_ERR":13,"NAMESPACE_ERR":14,"INVALID_ACCESS_ERR":15,"VALIDATION_ERR":16,"TYPE_MISMATCH_ERR":17,"SECURITY_ERR":18,"NETWORK_ERR":19,"ABORT_ERR":20,"URL_MISMATCH_ERR":21,"QUOTA_EXCEEDED_ERR":22,"TIMEOUT_ERR":23,"INVALID_NODE_TYPE_ERR":24,"DATA_CLONE_ERR":25}},"DOMMatrix":{"f":{"fromFloat32Array":1,"fromFloat64Array":1,"fromMatrix":0}},"DOMMatrixReadOnly":{"f":{"fromFloat32Array":1,"fromFloat64Array":1,"fromMatrix":0}},"DOMPoint":{"f":{"fromPoint":0}},"DOMPointReadOnly":{"f":{"fromPoint":0}},"DOMQuad":{"f":{"fromQuad":0,"fromRect":0}},"DOMRect":{"f":{"fromRect":0}},"DOMRectReadOnly":{"f":{"fromRect":0}},"DigitalCredential":{"f":{"userAgentAllowsProtocol":1}},"Document":{"f":{"parseHTML":1,"parseHTMLUnsafe":1}},"Event":{"c":{"NONE":0,"CAPTURING_PHASE":1,"AT_TARGET":2,"BUBBLING_PHASE":3}},"EventSource":{"c":{"CONNECTING":0,"OPEN":1,"CLOSED":2}},"FileReader":{"c":{"EMPTY":0,"LOADING":1,"DONE":2}},"Float16Array":{"c":{"BYTES_PER_ELEMENT":2},"h":["BYTES_PER_ELEMENT"]},"GeolocationPositionError":{"c":{"PERMISSION_DENIED":1,"POSITION_UNAVAILABLE":2,"TIMEOUT":3}},"HTMLFencedFrameElement":{"f":{"canLoadOpaqueURL":0}},"HTMLMediaElement":{"c":{"NETWORK_EMPTY":0,"NETWORK_IDLE":1,"NETWORK_LOADING":2,"NETWORK_NO_SOURCE":3,"HAVE_NOTHING":0,"HAVE_METADATA":1,"HAVE_CURRENT_DATA":2,"HAVE_FUTURE_DATA":3,"HAVE_ENOUGH_DATA":4}},"HTMLScriptElement":{"f":{"supports":1}},"HTMLTrackElement":{"c":{"NONE":0,"LOADING":1,"LOADED":2,"ERROR":3}},"IDBKeyRange":{"f":{"bound":2,"lowerBound":1,"only":1,"upperBound":1}},"IdentityCredential":{"f":{"disconnect":1}},"IdentityProvider":{"f":{"close":0,"getUserInfo":1,"resolve":1}},"IdleDetector":{"f":{"requestPermission":0}},"ImageDecoder":{"f":{"isTypeSupported":1}},"Iterator":{"f":{"concat":0},"h":["concat"]},"KeyboardEvent":{"c":{"DOM_KEY_LOCATION_STANDARD":0,"DOM_KEY_LOCATION_LEFT":1,"DOM_KEY_LOCATION_RIGHT":2,"DOM_KEY_LOCATION_NUMPAD":3}},"LanguageDetector":{"f":{"availability":0,"create":0}},"LanguageModel":{"f":{"availability":0,"create":0}},"MediaError":{"c":{"MEDIA_ERR_ABORTED":1,"MEDIA_ERR_NETWORK":2,"MEDIA_ERR_DECODE":3,"MEDIA_ERR_SRC_NOT_SUPPORTED":4}},"MediaRecorder":{"f":{"isTypeSupported":1}},"MediaSource":{"f":{"isTypeSupported":1},"g":["canConstructInDedicatedWorker"]},"Notification":{"f":{"requestPermission":0},"g":["maxActions","permission"]},"Observable":{"f":{"from":1}},"Origin":{"f":{"from":1}},"PaymentRequest":{"f":{"getSecurePaymentConfirmationCapabilities":0,"securePaymentConfirmationAvailability":0}},"PerformanceNavigation":{"c":{"TYPE_NAVIGATE":0,"TYPE_RELOAD":1,"TYPE_BACK_FORWARD":2,"TYPE_RESERVED":255}},"PerformanceObserver":{"g":["supportedEntryTypes"]},"PressureObserver":{"g":["knownSources"]},"PublicKeyCredential":{"f":{"getClientCapabilities":0,"isConditionalMediationAvailable":0,"isUserVerifyingPlatformAuthenticatorAvailable":0,"parseCreationOptionsFromJSON":1,"parseRequestOptionsFromJSON":1,"signalAllAcceptedCredentials":1,"signalCurrentUserDetails":1,"signalUnknownCredential":1}},"PushManager":{"g":["supportedContentEncodings"]},"RTCPeerConnection":{"f":{"generateCertificate":1}},"RTCRtpReceiver":{"f":{"getCapabilities":1}},"RTCRtpSender":{"f":{"getCapabilities":1}},"Range":{"c":{"START_TO_START":0,"START_TO_END":1,"END_TO_END":2,"END_TO_START":3}},"Response":{"f":{"redirect":1}},"RestrictionTarget":{"f":{"fromElement":1}},"SVGAngle":{"c":{"SVG_ANGLETYPE_UNKNOWN":0,"SVG_ANGLETYPE_UNSPECIFIED":1,"SVG_ANGLETYPE_DEG":2,"SVG_ANGLETYPE_RAD":3,"SVG_ANGLETYPE_GRAD":4}},"SVGComponentTransferFunctionElement":{"c":{"SVG_FECOMPONENTTRANSFER_TYPE_UNKNOWN":0,"SVG_FECOMPONENTTRANSFER_TYPE_IDENTITY":1,"SVG_FECOMPONENTTRANSFER_TYPE_TABLE":2,"SVG_FECOMPONENTTRANSFER_TYPE_DISCRETE":3,"SVG_FECOMPONENTTRANSFER_TYPE_LINEAR":4,"SVG_FECOMPONENTTRANSFER_TYPE_GAMMA":5}},"SVGFEBlendElement":{"c":{"SVG_FEBLEND_MODE_UNKNOWN":0,"SVG_FEBLEND_MODE_NORMAL":1,"SVG_FEBLEND_MODE_MULTIPLY":2,"SVG_FEBLEND_MODE_SCREEN":3,"SVG_FEBLEND_MODE_DARKEN":4,"SVG_FEBLEND_MODE_LIGHTEN":5,"SVG_FEBLEND_MODE_OVERLAY":6,"SVG_FEBLEND_MODE_COLOR_DODGE":7,"SVG_FEBLEND_MODE_COLOR_BURN":8,"SVG_FEBLEND_MODE_HARD_LIGHT":9,"SVG_FEBLEND_MODE_SOFT_LIGHT":10,"SVG_FEBLEND_MODE_DIFFERENCE":11,"SVG_FEBLEND_MODE_EXCLUSION":12,"SVG_FEBLEND_MODE_HUE":13,"SVG_FEBLEND_MODE_SATURATION":14,"SVG_FEBLEND_MODE_COLOR":15,"SVG_FEBLEND_MODE_LUMINOSITY":16}},"SVGFEColorMatrixElement":{"c":{"SVG_FECOLORMATRIX_TYPE_UNKNOWN":0,"SVG_FECOLORMATRIX_TYPE_MATRIX":1,"SVG_FECOLORMATRIX_TYPE_SATURATE":2,"SVG_FECOLORMATRIX_TYPE_HUEROTATE":3,"SVG_FECOLORMATRIX_TYPE_LUMINANCETOALPHA":4}},"SVGFECompositeElement":{"c":{"SVG_FECOMPOSITE_OPERATOR_UNKNOWN":0,"SVG_FECOMPOSITE_OPERATOR_OVER":1,"SVG_FECOMPOSITE_OPERATOR_IN":2,"SVG_FECOMPOSITE_OPERATOR_OUT":3,"SVG_FECOMPOSITE_OPERATOR_ATOP":4,"SVG_FECOMPOSITE_OPERATOR_XOR":5,"SVG_FECOMPOSITE_OPERATOR_ARITHMETIC":6}},"SVGFEConvolveMatrixElement":{"c":{"SVG_EDGEMODE_UNKNOWN":0,"SVG_EDGEMODE_DUPLICATE":1,"SVG_EDGEMODE_WRAP":2,"SVG_EDGEMODE_NONE":3}},"SVGFEDisplacementMapElement":{"c":{"SVG_CHANNEL_UNKNOWN":0,"SVG_CHANNEL_R":1,"SVG_CHANNEL_G":2,"SVG_CHANNEL_B":3,"SVG_CHANNEL_A":4}},"SVGFEMorphologyElement":{"c":{"SVG_MORPHOLOGY_OPERATOR_UNKNOWN":0,"SVG_MORPHOLOGY_OPERATOR_ERODE":1,"SVG_MORPHOLOGY_OPERATOR_DILATE":2}},"SVGFETurbulenceElement":{"c":{"SVG_TURBULENCE_TYPE_UNKNOWN":0,"SVG_TURBULENCE_TYPE_FRACTALNOISE":1,"SVG_TURBULENCE_TYPE_TURBULENCE":2,"SVG_STITCHTYPE_UNKNOWN":0,"SVG_STITCHTYPE_STITCH":1,"SVG_STITCHTYPE_NOSTITCH":2}},"SVGGradientElement":{"c":{"SVG_SPREADMETHOD_UNKNOWN":0,"SVG_SPREADMETHOD_PAD":1,"SVG_SPREADMETHOD_REFLECT":2,"SVG_SPREADMETHOD_REPEAT":3}},"SVGLength":{"c":{"SVG_LENGTHTYPE_UNKNOWN":0,"SVG_LENGTHTYPE_NUMBER":1,"SVG_LENGTHTYPE_PERCENTAGE":2,"SVG_LENGTHTYPE_EMS":3,"SVG_LENGTHTYPE_EXS":4,"SVG_LENGTHTYPE_PX":5,"SVG_LENGTHTYPE_CM":6,"SVG_LENGTHTYPE_MM":7,"SVG_LENGTHTYPE_IN":8,"SVG_LENGTHTYPE_PT":9,"SVG_LENGTHTYPE_PC":10}},"SVGMarkerElement":{"c":{"SVG_MARKERUNITS_UNKNOWN":0,"SVG_MARKERUNITS_USERSPACEONUSE":1,"SVG_MARKERUNITS_STROKEWIDTH":2,"SVG_MARKER_ORIENT_UNKNOWN":0,"SVG_MARKER_ORIENT_AUTO":1,"SVG_MARKER_ORIENT_ANGLE":2}},"SVGPreserveAspectRatio":{"c":{"SVG_PRESERVEASPECTRATIO_UNKNOWN":0,"SVG_PRESERVEASPECTRATIO_NONE":1,"SVG_PRESERVEASPECTRATIO_XMINYMIN":2,"SVG_PRESERVEASPECTRATIO_XMIDYMIN":3,"SVG_PRESERVEASPECTRATIO_XMAXYMIN":4,"SVG_PRESERVEASPECTRATIO_XMINYMID":5,"SVG_PRESERVEASPECTRATIO_XMIDYMID":6,"SVG_PRESERVEASPECTRATIO_XMAXYMID":7,"SVG_PRESERVEASPECTRATIO_XMINYMAX":8,"SVG_PRESERVEASPECTRATIO_XMIDYMAX":9,"SVG_PRESERVEASPECTRATIO_XMAXYMAX":10,"SVG_MEETORSLICE_UNKNOWN":0,"SVG_MEETORSLICE_MEET":1,"SVG_MEETORSLICE_SLICE":2}},"SVGSVGElement":{"c":{"SVG_ZOOMANDPAN_UNKNOWN":0,"SVG_ZOOMANDPAN_DISABLE":1,"SVG_ZOOMANDPAN_MAGNIFY":2}},"SVGTextContentElement":{"c":{"LENGTHADJUST_UNKNOWN":0,"LENGTHADJUST_SPACING":1,"LENGTHADJUST_SPACINGANDGLYPHS":2}},"SVGTextPathElement":{"c":{"TEXTPATH_METHODTYPE_UNKNOWN":0,"TEXTPATH_METHODTYPE_ALIGN":1,"TEXTPATH_METHODTYPE_STRETCH":2,"TEXTPATH_SPACINGTYPE_UNKNOWN":0,"TEXTPATH_SPACINGTYPE_AUTO":1,"TEXTPATH_SPACINGTYPE_EXACT":2}},"SVGTransform":{"c":{"SVG_TRANSFORM_UNKNOWN":0,"SVG_TRANSFORM_MATRIX":1,"SVG_TRANSFORM_TRANSLATE":2,"SVG_TRANSFORM_SCALE":3,"SVG_TRANSFORM_ROTATE":4,"SVG_TRANSFORM_SKEWX":5,"SVG_TRANSFORM_SKEWY":6}},"SVGUnitTypes":{"c":{"SVG_UNIT_TYPE_UNKNOWN":0,"SVG_UNIT_TYPE_USERSPACEONUSE":1,"SVG_UNIT_TYPE_OBJECTBOUNDINGBOX":2}},"SVGViewElement":{"c":{"SVG_ZOOMANDPAN_UNKNOWN":0,"SVG_ZOOMANDPAN_DISABLE":1,"SVG_ZOOMANDPAN_MAGNIFY":2}},"SpeechRecognition":{"f":{"available":1,"install":1}},"Summarizer":{"f":{"availability":0,"create":0}},"TaskSignal":{"f":{"any":1}},"Translator":{"f":{"availability":1,"create":1}},"URL":{"f":{"canParse":1,"parse":1}},"Uint8Array":{"f":{"fromBase64":1,"fromHex":1},"h":["fromBase64","fromHex"]},"VideoDecoder":{"f":{"isConfigSupported":1}},"VideoEncoder":{"f":{"isConfigSupported":1}},"WebGL2RenderingContext":{"c":{"DEPTH_BUFFER_BIT":256,"STENCIL_BUFFER_BIT":1024,"COLOR_BUFFER_BIT":16384,"POINTS":0,"LINES":1,"LINE_LOOP":2,"LINE_STRIP":3,"TRIANGLES":4,"TRIANGLE_STRIP":5,"TRIANGLE_FAN":6,"ZERO":0,"ONE":1,"SRC_COLOR":768,"ONE_MINUS_SRC_COLOR":769,"SRC_ALPHA":770,"ONE_MINUS_SRC_ALPHA":771,"DST_ALPHA":772,"ONE_MINUS_DST_ALPHA":773,"DST_COLOR":774,"ONE_MINUS_DST_COLOR":775,"SRC_ALPHA_SATURATE":776,"FUNC_ADD":32774,"BLEND_EQUATION":32777,"BLEND_EQUATION_RGB":32777,"BLEND_EQUATION_ALPHA":34877,"FUNC_SUBTRACT":32778,"FUNC_REVERSE_SUBTRACT":32779,"BLEND_DST_RGB":32968,"BLEND_SRC_RGB":32969,"BLEND_DST_ALPHA":32970,"BLEND_SRC_ALPHA":32971,"CONSTANT_COLOR":32769,"ONE_MINUS_CONSTANT_COLOR":32770,"CONSTANT_ALPHA":32771,"ONE_MINUS_CONSTANT_ALPHA":32772,"BLEND_COLOR":32773,"ARRAY_BUFFER":34962,"ELEMENT_ARRAY_BUFFER":34963,"ARRAY_BUFFER_BINDING":34964,"ELEMENT_ARRAY_BUFFER_BINDING":34965,"STREAM_DRAW":35040,"STATIC_DRAW":35044,"DYNAMIC_DRAW":35048,"BUFFER_SIZE":34660,"BUFFER_USAGE":34661,"CURRENT_VERTEX_ATTRIB":34342,"FRONT":1028,"BACK":1029,"FRONT_AND_BACK":1032,"TEXTURE_2D":3553,"CULL_FACE":2884,"BLEND":3042,"DITHER":3024,"STENCIL_TEST":2960,"DEPTH_TEST":2929,"SCISSOR_TEST":3089,"POLYGON_OFFSET_FILL":32823,"SAMPLE_ALPHA_TO_COVERAGE":32926,"SAMPLE_COVERAGE":32928,"NO_ERROR":0,"INVALID_ENUM":1280,"INVALID_VALUE":1281,"INVALID_OPERATION":1282,"OUT_OF_MEMORY":1285,"CW":2304,"CCW":2305,"LINE_WIDTH":2849,"ALIASED_POINT_SIZE_RANGE":33901,"ALIASED_LINE_WIDTH_RANGE":33902,"CULL_FACE_MODE":2885,"FRONT_FACE":2886,"DEPTH_RANGE":2928,"DEPTH_WRITEMASK":2930,"DEPTH_CLEAR_VALUE":2931,"DEPTH_FUNC":2932,"STENCIL_CLEAR_VALUE":2961,"STENCIL_FUNC":2962,"STENCIL_FAIL":2964,"STENCIL_PASS_DEPTH_FAIL":2965,"STENCIL_PASS_DEPTH_PASS":2966,"STENCIL_REF":2967,"STENCIL_VALUE_MASK":2963,"STENCIL_WRITEMASK":2968,"STENCIL_BACK_FUNC":34816,"STENCIL_BACK_FAIL":34817,"STENCIL_BACK_PASS_DEPTH_FAIL":34818,"STENCIL_BACK_PASS_DEPTH_PASS":34819,"STENCIL_BACK_REF":36003,"STENCIL_BACK_VALUE_MASK":36004,"STENCIL_BACK_WRITEMASK":36005,"VIEWPORT":2978,"SCISSOR_BOX":3088,"COLOR_CLEAR_VALUE":3106,"COLOR_WRITEMASK":3107,"UNPACK_ALIGNMENT":3317,"PACK_ALIGNMENT":3333,"MAX_TEXTURE_SIZE":3379,"MAX_VIEWPORT_DIMS":3386,"SUBPIXEL_BITS":3408,"RED_BITS":3410,"GREEN_BITS":3411,"BLUE_BITS":3412,"ALPHA_BITS":3413,"DEPTH_BITS":3414,"STENCIL_BITS":3415,"POLYGON_OFFSET_UNITS":10752,"POLYGON_OFFSET_FACTOR":32824,"TEXTURE_BINDING_2D":32873,"SAMPLE_BUFFERS":32936,"SAMPLES":32937,"SAMPLE_COVERAGE_VALUE":32938,"SAMPLE_COVERAGE_INVERT":32939,"COMPRESSED_TEXTURE_FORMATS":34467,"DONT_CARE":4352,"FASTEST":4353,"NICEST":4354,"GENERATE_MIPMAP_HINT":33170,"BYTE":5120,"UNSIGNED_BYTE":5121,"SHORT":5122,"UNSIGNED_SHORT":5123,"INT":5124,"UNSIGNED_INT":5125,"FLOAT":5126,"DEPTH_COMPONENT":6402,"ALPHA":6406,"RGB":6407,"RGBA":6408,"LUMINANCE":6409,"LUMINANCE_ALPHA":6410,"UNSIGNED_SHORT_4_4_4_4":32819,"UNSIGNED_SHORT_5_5_5_1":32820,"UNSIGNED_SHORT_5_6_5":33635,"FRAGMENT_SHADER":35632,"VERTEX_SHADER":35633,"MAX_VERTEX_ATTRIBS":34921,"MAX_VERTEX_UNIFORM_VECTORS":36347,"MAX_VARYING_VECTORS":36348,"MAX_COMBINED_TEXTURE_IMAGE_UNITS":35661,"MAX_VERTEX_TEXTURE_IMAGE_UNITS":35660,"MAX_TEXTURE_IMAGE_UNITS":34930,"MAX_FRAGMENT_UNIFORM_VECTORS":36349,"SHADER_TYPE":35663,"DELETE_STATUS":35712,"LINK_STATUS":35714,"VALIDATE_STATUS":35715,"ATTACHED_SHADERS":35717,"ACTIVE_UNIFORMS":35718,"ACTIVE_ATTRIBUTES":35721,"SHADING_LANGUAGE_VERSION":35724,"CURRENT_PROGRAM":35725,"NEVER":512,"LESS":513,"EQUAL":514,"LEQUAL":515,"GREATER":516,"NOTEQUAL":517,"GEQUAL":518,"ALWAYS":519,"KEEP":7680,"REPLACE":7681,"INCR":7682,"DECR":7683,"INVERT":5386,"INCR_WRAP":34055,"DECR_WRAP":34056,"VENDOR":7936,"RENDERER":7937,"VERSION":7938,"NEAREST":9728,"LINEAR":9729,"NEAREST_MIPMAP_NEAREST":9984,"LINEAR_MIPMAP_NEAREST":9985,"NEAREST_MIPMAP_LINEAR":9986,"LINEAR_MIPMAP_LINEAR":9987,"TEXTURE_MAG_FILTER":10240,"TEXTURE_MIN_FILTER":10241,"TEXTURE_WRAP_S":10242,"TEXTURE_WRAP_T":10243,"TEXTURE":5890,"TEXTURE_CUBE_MAP":34067,"TEXTURE_BINDING_CUBE_MAP":34068,"TEXTURE_CUBE_MAP_POSITIVE_X":34069,"TEXTURE_CUBE_MAP_NEGATIVE_X":34070,"TEXTURE_CUBE_MAP_POSITIVE_Y":34071,"TEXTURE_CUBE_MAP_NEGATIVE_Y":34072,"TEXTURE_CUBE_MAP_POSITIVE_Z":34073,"TEXTURE_CUBE_MAP_NEGATIVE_Z":34074,"MAX_CUBE_MAP_TEXTURE_SIZE":34076,"TEXTURE0":33984,"TEXTURE1":33985,"TEXTURE2":33986,"TEXTURE3":33987,"TEXTURE4":33988,"TEXTURE5":33989,"TEXTURE6":33990,"TEXTURE7":33991,"TEXTURE8":33992,"TEXTURE9":33993,"TEXTURE10":33994,"TEXTURE11":33995,"TEXTURE12":33996,"TEXTURE13":33997,"TEXTURE14":33998,"TEXTURE15":33999,"TEXTURE16":34000,"TEXTURE17":34001,"TEXTURE18":34002,"TEXTURE19":34003,"TEXTURE20":34004,"TEXTURE21":34005,"TEXTURE22":34006,"TEXTURE23":34007,"TEXTURE24":34008,"TEXTURE25":34009,"TEXTURE26":34010,"TEXTURE27":34011,"TEXTURE28":34012,"TEXTURE29":34013,"TEXTURE30":34014,"TEXTURE31":34015,"ACTIVE_TEXTURE":34016,"REPEAT":10497,"CLAMP_TO_EDGE":33071,"MIRRORED_REPEAT":33648,"FLOAT_VEC2":35664,"FLOAT_VEC3":35665,"FLOAT_VEC4":35666,"INT_VEC2":35667,"INT_VEC3":35668,"INT_VEC4":35669,"BOOL":35670,"BOOL_VEC2":35671,"BOOL_VEC3":35672,"BOOL_VEC4":35673,"FLOAT_MAT2":35674,"FLOAT_MAT3":35675,"FLOAT_MAT4":35676,"SAMPLER_2D":35678,"SAMPLER_CUBE":35680,"VERTEX_ATTRIB_ARRAY_ENABLED":34338,"VERTEX_ATTRIB_ARRAY_SIZE":34339,"VERTEX_ATTRIB_ARRAY_STRIDE":34340,"VERTEX_ATTRIB_ARRAY_TYPE":34341,"VERTEX_ATTRIB_ARRAY_NORMALIZED":34922,"VERTEX_ATTRIB_ARRAY_POINTER":34373,"VERTEX_ATTRIB_ARRAY_BUFFER_BINDING":34975,"IMPLEMENTATION_COLOR_READ_TYPE":35738,"IMPLEMENTATION_COLOR_READ_FORMAT":35739,"COMPILE_STATUS":35713,"LOW_FLOAT":36336,"MEDIUM_FLOAT":36337,"HIGH_FLOAT":36338,"LOW_INT":36339,"MEDIUM_INT":36340,"HIGH_INT":36341,"FRAMEBUFFER":36160,"RENDERBUFFER":36161,"RGBA4":32854,"RGB5_A1":32855,"RGB565":36194,"DEPTH_COMPONENT16":33189,"STENCIL_INDEX8":36168,"DEPTH_STENCIL":34041,"RENDERBUFFER_WIDTH":36162,"RENDERBUFFER_HEIGHT":36163,"RENDERBUFFER_INTERNAL_FORMAT":36164,"RENDERBUFFER_RED_SIZE":36176,"RENDERBUFFER_GREEN_SIZE":36177,"RENDERBUFFER_BLUE_SIZE":36178,"RENDERBUFFER_ALPHA_SIZE":36179,"RENDERBUFFER_DEPTH_SIZE":36180,"RENDERBUFFER_STENCIL_SIZE":36181,"FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE":36048,"FRAMEBUFFER_ATTACHMENT_OBJECT_NAME":36049,"FRAMEBUFFER_ATTACHMENT_TEXTURE_LEVEL":36050,"FRAMEBUFFER_ATTACHMENT_TEXTURE_CUBE_MAP_FACE":36051,"COLOR_ATTACHMENT0":36064,"DEPTH_ATTACHMENT":36096,"STENCIL_ATTACHMENT":36128,"DEPTH_STENCIL_ATTACHMENT":33306,"NONE":0,"FRAMEBUFFER_COMPLETE":36053,"FRAMEBUFFER_INCOMPLETE_ATTACHMENT":36054,"FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT":36055,"FRAMEBUFFER_INCOMPLETE_DIMENSIONS":36057,"FRAMEBUFFER_UNSUPPORTED":36061,"FRAMEBUFFER_BINDING":36006,"RENDERBUFFER_BINDING":36007,"MAX_RENDERBUFFER_SIZE":34024,"INVALID_FRAMEBUFFER_OPERATION":1286,"UNPACK_FLIP_Y_WEBGL":37440,"UNPACK_PREMULTIPLY_ALPHA_WEBGL":37441,"CONTEXT_LOST_WEBGL":37442,"UNPACK_COLORSPACE_CONVERSION_WEBGL":37443,"BROWSER_DEFAULT_WEBGL":37444,"READ_BUFFER":3074,"UNPACK_ROW_LENGTH":3314,"UNPACK_SKIP_ROWS":3315,"UNPACK_SKIP_PIXELS":3316,"PACK_ROW_LENGTH":3330,"PACK_SKIP_ROWS":3331,"PACK_SKIP_PIXELS":3332,"COLOR":6144,"DEPTH":6145,"STENCIL":6146,"RED":6403,"RGB8":32849,"RGBA8":32856,"RGB10_A2":32857,"TEXTURE_BINDING_3D":32874,"UNPACK_SKIP_IMAGES":32877,"UNPACK_IMAGE_HEIGHT":32878,"TEXTURE_3D":32879,"TEXTURE_WRAP_R":32882,"MAX_3D_TEXTURE_SIZE":32883,"UNSIGNED_INT_2_10_10_10_REV":33640,"MAX_ELEMENTS_VERTICES":33000,"MAX_ELEMENTS_INDICES":33001,"TEXTURE_MIN_LOD":33082,"TEXTURE_MAX_LOD":33083,"TEXTURE_BASE_LEVEL":33084,"TEXTURE_MAX_LEVEL":33085,"MIN":32775,"MAX":32776,"DEPTH_COMPONENT24":33190,"MAX_TEXTURE_LOD_BIAS":34045,"TEXTURE_COMPARE_MODE":34892,"TEXTURE_COMPARE_FUNC":34893,"CURRENT_QUERY":34917,"QUERY_RESULT":34918,"QUERY_RESULT_AVAILABLE":34919,"STREAM_READ":35041,"STREAM_COPY":35042,"STATIC_READ":35045,"STATIC_COPY":35046,"DYNAMIC_READ":35049,"DYNAMIC_COPY":35050,"MAX_DRAW_BUFFERS":34852,"DRAW_BUFFER0":34853,"DRAW_BUFFER1":34854,"DRAW_BUFFER2":34855,"DRAW_BUFFER3":34856,"DRAW_BUFFER4":34857,"DRAW_BUFFER5":34858,"DRAW_BUFFER6":34859,"DRAW_BUFFER7":34860,"DRAW_BUFFER8":34861,"DRAW_BUFFER9":34862,"DRAW_BUFFER10":34863,"DRAW_BUFFER11":34864,"DRAW_BUFFER12":34865,"DRAW_BUFFER13":34866,"DRAW_BUFFER14":34867,"DRAW_BUFFER15":34868,"MAX_FRAGMENT_UNIFORM_COMPONENTS":35657,"MAX_VERTEX_UNIFORM_COMPONENTS":35658,"SAMPLER_3D":35679,"SAMPLER_2D_SHADOW":35682,"FRAGMENT_SHADER_DERIVATIVE_HINT":35723,"PIXEL_PACK_BUFFER":35051,"PIXEL_UNPACK_BUFFER":35052,"PIXEL_PACK_BUFFER_BINDING":35053,"PIXEL_UNPACK_BUFFER_BINDING":35055,"FLOAT_MAT2x3":35685,"FLOAT_MAT2x4":35686,"FLOAT_MAT3x2":35687,"FLOAT_MAT3x4":35688,"FLOAT_MAT4x2":35689,"FLOAT_MAT4x3":35690,"SRGB":35904,"SRGB8":35905,"SRGB8_ALPHA8":35907,"COMPARE_REF_TO_TEXTURE":34894,"RGBA32F":34836,"RGB32F":34837,"RGBA16F":34842,"RGB16F":34843,"VERTEX_ATTRIB_ARRAY_INTEGER":35069,"MAX_ARRAY_TEXTURE_LAYERS":35071,"MIN_PROGRAM_TEXEL_OFFSET":35076,"MAX_PROGRAM_TEXEL_OFFSET":35077,"MAX_VARYING_COMPONENTS":35659,"TEXTURE_2D_ARRAY":35866,"TEXTURE_BINDING_2D_ARRAY":35869,"R11F_G11F_B10F":35898,"UNSIGNED_INT_10F_11F_11F_REV":35899,"RGB9_E5":35901,"UNSIGNED_INT_5_9_9_9_REV":35902,"TRANSFORM_FEEDBACK_BUFFER_MODE":35967,"MAX_TRANSFORM_FEEDBACK_SEPARATE_COMPONENTS":35968,"TRANSFORM_FEEDBACK_VARYINGS":35971,"TRANSFORM_FEEDBACK_BUFFER_START":35972,"TRANSFORM_FEEDBACK_BUFFER_SIZE":35973,"TRANSFORM_FEEDBACK_PRIMITIVES_WRITTEN":35976,"RASTERIZER_DISCARD":35977,"MAX_TRANSFORM_FEEDBACK_INTERLEAVED_COMPONENTS":35978,"MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS":35979,"INTERLEAVED_ATTRIBS":35980,"SEPARATE_ATTRIBS":35981,"TRANSFORM_FEEDBACK_BUFFER":35982,"TRANSFORM_FEEDBACK_BUFFER_BINDING":35983,"RGBA32UI":36208,"RGB32UI":36209,"RGBA16UI":36214,"RGB16UI":36215,"RGBA8UI":36220,"RGB8UI":36221,"RGBA32I":36226,"RGB32I":36227,"RGBA16I":36232,"RGB16I":36233,"RGBA8I":36238,"RGB8I":36239,"RED_INTEGER":36244,"RGB_INTEGER":36248,"RGBA_INTEGER":36249,"SAMPLER_2D_ARRAY":36289,"SAMPLER_2D_ARRAY_SHADOW":36292,"SAMPLER_CUBE_SHADOW":36293,"UNSIGNED_INT_VEC2":36294,"UNSIGNED_INT_VEC3":36295,"UNSIGNED_INT_VEC4":36296,"INT_SAMPLER_2D":36298,"INT_SAMPLER_3D":36299,"INT_SAMPLER_CUBE":36300,"INT_SAMPLER_2D_ARRAY":36303,"UNSIGNED_INT_SAMPLER_2D":36306,"UNSIGNED_INT_SAMPLER_3D":36307,"UNSIGNED_INT_SAMPLER_CUBE":36308,"UNSIGNED_INT_SAMPLER_2D_ARRAY":36311,"DEPTH_COMPONENT32F":36012,"DEPTH32F_STENCIL8":36013,"FLOAT_32_UNSIGNED_INT_24_8_REV":36269,"FRAMEBUFFER_ATTACHMENT_COLOR_ENCODING":33296,"FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE":33297,"FRAMEBUFFER_ATTACHMENT_RED_SIZE":33298,"FRAMEBUFFER_ATTACHMENT_GREEN_SIZE":33299,"FRAMEBUFFER_ATTACHMENT_BLUE_SIZE":33300,"FRAMEBUFFER_ATTACHMENT_ALPHA_SIZE":33301,"FRAMEBUFFER_ATTACHMENT_DEPTH_SIZE":33302,"FRAMEBUFFER_ATTACHMENT_STENCIL_SIZE":33303,"FRAMEBUFFER_DEFAULT":33304,"UNSIGNED_INT_24_8":34042,"DEPTH24_STENCIL8":35056,"UNSIGNED_NORMALIZED":35863,"DRAW_FRAMEBUFFER_BINDING":36006,"READ_FRAMEBUFFER":36008,"DRAW_FRAMEBUFFER":36009,"READ_FRAMEBUFFER_BINDING":36010,"RENDERBUFFER_SAMPLES":36011,"FRAMEBUFFER_ATTACHMENT_TEXTURE_LAYER":36052,"MAX_COLOR_ATTACHMENTS":36063,"COLOR_ATTACHMENT1":36065,"COLOR_ATTACHMENT2":36066,"COLOR_ATTACHMENT3":36067,"COLOR_ATTACHMENT4":36068,"COLOR_ATTACHMENT5":36069,"COLOR_ATTACHMENT6":36070,"COLOR_ATTACHMENT7":36071,"COLOR_ATTACHMENT8":36072,"COLOR_ATTACHMENT9":36073,"COLOR_ATTACHMENT10":36074,"COLOR_ATTACHMENT11":36075,"COLOR_ATTACHMENT12":36076,"COLOR_ATTACHMENT13":36077,"COLOR_ATTACHMENT14":36078,"COLOR_ATTACHMENT15":36079,"FRAMEBUFFER_INCOMPLETE_MULTISAMPLE":36182,"MAX_SAMPLES":36183,"HALF_FLOAT":5131,"RG":33319,"RG_INTEGER":33320,"R8":33321,"RG8":33323,"R16F":33325,"R32F":33326,"RG16F":33327,"RG32F":33328,"R8I":33329,"R8UI":33330,"R16I":33331,"R16UI":33332,"R32I":33333,"R32UI":33334,"RG8I":33335,"RG8UI":33336,"RG16I":33337,"RG16UI":33338,"RG32I":33339,"RG32UI":33340,"VERTEX_ARRAY_BINDING":34229,"R8_SNORM":36756,"RG8_SNORM":36757,"RGB8_SNORM":36758,"RGBA8_SNORM":36759,"SIGNED_NORMALIZED":36764,"COPY_READ_BUFFER":36662,"COPY_WRITE_BUFFER":36663,"COPY_READ_BUFFER_BINDING":36662,"COPY_WRITE_BUFFER_BINDING":36663,"UNIFORM_BUFFER":35345,"UNIFORM_BUFFER_BINDING":35368,"UNIFORM_BUFFER_START":35369,"UNIFORM_BUFFER_SIZE":35370,"MAX_VERTEX_UNIFORM_BLOCKS":35371,"MAX_FRAGMENT_UNIFORM_BLOCKS":35373,"MAX_COMBINED_UNIFORM_BLOCKS":35374,"MAX_UNIFORM_BUFFER_BINDINGS":35375,"MAX_UNIFORM_BLOCK_SIZE":35376,"MAX_COMBINED_VERTEX_UNIFORM_COMPONENTS":35377,"MAX_COMBINED_FRAGMENT_UNIFORM_COMPONENTS":35379,"UNIFORM_BUFFER_OFFSET_ALIGNMENT":35380,"ACTIVE_UNIFORM_BLOCKS":35382,"UNIFORM_TYPE":35383,"UNIFORM_SIZE":35384,"UNIFORM_BLOCK_INDEX":35386,"UNIFORM_OFFSET":35387,"UNIFORM_ARRAY_STRIDE":35388,"UNIFORM_MATRIX_STRIDE":35389,"UNIFORM_IS_ROW_MAJOR":35390,"UNIFORM_BLOCK_BINDING":35391,"UNIFORM_BLOCK_DATA_SIZE":35392,"UNIFORM_BLOCK_ACTIVE_UNIFORMS":35394,"UNIFORM_BLOCK_ACTIVE_UNIFORM_INDICES":35395,"UNIFORM_BLOCK_REFERENCED_BY_VERTEX_SHADER":35396,"UNIFORM_BLOCK_REFERENCED_BY_FRAGMENT_SHADER":35398,"INVALID_INDEX":4294967295,"MAX_VERTEX_OUTPUT_COMPONENTS":37154,"MAX_FRAGMENT_INPUT_COMPONENTS":37157,"MAX_SERVER_WAIT_TIMEOUT":37137,"OBJECT_TYPE":37138,"SYNC_CONDITION":37139,"SYNC_STATUS":37140,"SYNC_FLAGS":37141,"SYNC_FENCE":37142,"SYNC_GPU_COMMANDS_COMPLETE":37143,"UNSIGNALED":37144,"SIGNALED":37145,"ALREADY_SIGNALED":37146,"TIMEOUT_EXPIRED":37147,"CONDITION_SATISFIED":37148,"WAIT_FAILED":37149,"SYNC_FLUSH_COMMANDS_BIT":1,"VERTEX_ATTRIB_ARRAY_DIVISOR":35070,"ANY_SAMPLES_PASSED":35887,"ANY_SAMPLES_PASSED_CONSERVATIVE":36202,"SAMPLER_BINDING":35097,"RGB10_A2UI":36975,"INT_2_10_10_10_REV":36255,"TRANSFORM_FEEDBACK":36386,"TRANSFORM_FEEDBACK_PAUSED":36387,"TRANSFORM_FEEDBACK_ACTIVE":36388,"TRANSFORM_FEEDBACK_BINDING":36389,"TEXTURE_IMMUTABLE_FORMAT":37167,"MAX_ELEMENT_INDEX":36203,"TEXTURE_IMMUTABLE_LEVELS":33503,"TIMEOUT_IGNORED":-1,"MAX_CLIENT_WAIT_TIMEOUT_WEBGL":37447}},"WebGLRenderingContext":{"c":{"DEPTH_BUFFER_BIT":256,"STENCIL_BUFFER_BIT":1024,"COLOR_BUFFER_BIT":16384,"POINTS":0,"LINES":1,"LINE_LOOP":2,"LINE_STRIP":3,"TRIANGLES":4,"TRIANGLE_STRIP":5,"TRIANGLE_FAN":6,"ZERO":0,"ONE":1,"SRC_COLOR":768,"ONE_MINUS_SRC_COLOR":769,"SRC_ALPHA":770,"ONE_MINUS_SRC_ALPHA":771,"DST_ALPHA":772,"ONE_MINUS_DST_ALPHA":773,"DST_COLOR":774,"ONE_MINUS_DST_COLOR":775,"SRC_ALPHA_SATURATE":776,"FUNC_ADD":32774,"BLEND_EQUATION":32777,"BLEND_EQUATION_RGB":32777,"BLEND_EQUATION_ALPHA":34877,"FUNC_SUBTRACT":32778,"FUNC_REVERSE_SUBTRACT":32779,"BLEND_DST_RGB":32968,"BLEND_SRC_RGB":32969,"BLEND_DST_ALPHA":32970,"BLEND_SRC_ALPHA":32971,"CONSTANT_COLOR":32769,"ONE_MINUS_CONSTANT_COLOR":32770,"CONSTANT_ALPHA":32771,"ONE_MINUS_CONSTANT_ALPHA":32772,"BLEND_COLOR":32773,"ARRAY_BUFFER":34962,"ELEMENT_ARRAY_BUFFER":34963,"ARRAY_BUFFER_BINDING":34964,"ELEMENT_ARRAY_BUFFER_BINDING":34965,"STREAM_DRAW":35040,"STATIC_DRAW":35044,"DYNAMIC_DRAW":35048,"BUFFER_SIZE":34660,"BUFFER_USAGE":34661,"CURRENT_VERTEX_ATTRIB":34342,"FRONT":1028,"BACK":1029,"FRONT_AND_BACK":1032,"TEXTURE_2D":3553,"CULL_FACE":2884,"BLEND":3042,"DITHER":3024,"STENCIL_TEST":2960,"DEPTH_TEST":2929,"SCISSOR_TEST":3089,"POLYGON_OFFSET_FILL":32823,"SAMPLE_ALPHA_TO_COVERAGE":32926,"SAMPLE_COVERAGE":32928,"NO_ERROR":0,"INVALID_ENUM":1280,"INVALID_VALUE":1281,"INVALID_OPERATION":1282,"OUT_OF_MEMORY":1285,"CW":2304,"CCW":2305,"LINE_WIDTH":2849,"ALIASED_POINT_SIZE_RANGE":33901,"ALIASED_LINE_WIDTH_RANGE":33902,"CULL_FACE_MODE":2885,"FRONT_FACE":2886,"DEPTH_RANGE":2928,"DEPTH_WRITEMASK":2930,"DEPTH_CLEAR_VALUE":2931,"DEPTH_FUNC":2932,"STENCIL_CLEAR_VALUE":2961,"STENCIL_FUNC":2962,"STENCIL_FAIL":2964,"STENCIL_PASS_DEPTH_FAIL":2965,"STENCIL_PASS_DEPTH_PASS":2966,"STENCIL_REF":2967,"STENCIL_VALUE_MASK":2963,"STENCIL_WRITEMASK":2968,"STENCIL_BACK_FUNC":34816,"STENCIL_BACK_FAIL":34817,"STENCIL_BACK_PASS_DEPTH_FAIL":34818,"STENCIL_BACK_PASS_DEPTH_PASS":34819,"STENCIL_BACK_REF":36003,"STENCIL_BACK_VALUE_MASK":36004,"STENCIL_BACK_WRITEMASK":36005,"VIEWPORT":2978,"SCISSOR_BOX":3088,"COLOR_CLEAR_VALUE":3106,"COLOR_WRITEMASK":3107,"UNPACK_ALIGNMENT":3317,"PACK_ALIGNMENT":3333,"MAX_TEXTURE_SIZE":3379,"MAX_VIEWPORT_DIMS":3386,"SUBPIXEL_BITS":3408,"RED_BITS":3410,"GREEN_BITS":3411,"BLUE_BITS":3412,"ALPHA_BITS":3413,"DEPTH_BITS":3414,"STENCIL_BITS":3415,"POLYGON_OFFSET_UNITS":10752,"POLYGON_OFFSET_FACTOR":32824,"TEXTURE_BINDING_2D":32873,"SAMPLE_BUFFERS":32936,"SAMPLES":32937,"SAMPLE_COVERAGE_VALUE":32938,"SAMPLE_COVERAGE_INVERT":32939,"COMPRESSED_TEXTURE_FORMATS":34467,"DONT_CARE":4352,"FASTEST":4353,"NICEST":4354,"GENERATE_MIPMAP_HINT":33170,"BYTE":5120,"UNSIGNED_BYTE":5121,"SHORT":5122,"UNSIGNED_SHORT":5123,"INT":5124,"UNSIGNED_INT":5125,"FLOAT":5126,"DEPTH_COMPONENT":6402,"ALPHA":6406,"RGB":6407,"RGBA":6408,"LUMINANCE":6409,"LUMINANCE_ALPHA":6410,"UNSIGNED_SHORT_4_4_4_4":32819,"UNSIGNED_SHORT_5_5_5_1":32820,"UNSIGNED_SHORT_5_6_5":33635,"FRAGMENT_SHADER":35632,"VERTEX_SHADER":35633,"MAX_VERTEX_ATTRIBS":34921,"MAX_VERTEX_UNIFORM_VECTORS":36347,"MAX_VARYING_VECTORS":36348,"MAX_COMBINED_TEXTURE_IMAGE_UNITS":35661,"MAX_VERTEX_TEXTURE_IMAGE_UNITS":35660,"MAX_TEXTURE_IMAGE_UNITS":34930,"MAX_FRAGMENT_UNIFORM_VECTORS":36349,"SHADER_TYPE":35663,"DELETE_STATUS":35712,"LINK_STATUS":35714,"VALIDATE_STATUS":35715,"ATTACHED_SHADERS":35717,"ACTIVE_UNIFORMS":35718,"ACTIVE_ATTRIBUTES":35721,"SHADING_LANGUAGE_VERSION":35724,"CURRENT_PROGRAM":35725,"NEVER":512,"LESS":513,"EQUAL":514,"LEQUAL":515,"GREATER":516,"NOTEQUAL":517,"GEQUAL":518,"ALWAYS":519,"KEEP":7680,"REPLACE":7681,"INCR":7682,"DECR":7683,"INVERT":5386,"INCR_WRAP":34055,"DECR_WRAP":34056,"VENDOR":7936,"RENDERER":7937,"VERSION":7938,"NEAREST":9728,"LINEAR":9729,"NEAREST_MIPMAP_NEAREST":9984,"LINEAR_MIPMAP_NEAREST":9985,"NEAREST_MIPMAP_LINEAR":9986,"LINEAR_MIPMAP_LINEAR":9987,"TEXTURE_MAG_FILTER":10240,"TEXTURE_MIN_FILTER":10241,"TEXTURE_WRAP_S":10242,"TEXTURE_WRAP_T":10243,"TEXTURE":5890,"TEXTURE_CUBE_MAP":34067,"TEXTURE_BINDING_CUBE_MAP":34068,"TEXTURE_CUBE_MAP_POSITIVE_X":34069,"TEXTURE_CUBE_MAP_NEGATIVE_X":34070,"TEXTURE_CUBE_MAP_POSITIVE_Y":34071,"TEXTURE_CUBE_MAP_NEGATIVE_Y":34072,"TEXTURE_CUBE_MAP_POSITIVE_Z":34073,"TEXTURE_CUBE_MAP_NEGATIVE_Z":34074,"MAX_CUBE_MAP_TEXTURE_SIZE":34076,"TEXTURE0":33984,"TEXTURE1":33985,"TEXTURE2":33986,"TEXTURE3":33987,"TEXTURE4":33988,"TEXTURE5":33989,"TEXTURE6":33990,"TEXTURE7":33991,"TEXTURE8":33992,"TEXTURE9":33993,"TEXTURE10":33994,"TEXTURE11":33995,"TEXTURE12":33996,"TEXTURE13":33997,"TEXTURE14":33998,"TEXTURE15":33999,"TEXTURE16":34000,"TEXTURE17":34001,"TEXTURE18":34002,"TEXTURE19":34003,"TEXTURE20":34004,"TEXTURE21":34005,"TEXTURE22":34006,"TEXTURE23":34007,"TEXTURE24":34008,"TEXTURE25":34009,"TEXTURE26":34010,"TEXTURE27":34011,"TEXTURE28":34012,"TEXTURE29":34013,"TEXTURE30":34014,"TEXTURE31":34015,"ACTIVE_TEXTURE":34016,"REPEAT":10497,"CLAMP_TO_EDGE":33071,"MIRRORED_REPEAT":33648,"FLOAT_VEC2":35664,"FLOAT_VEC3":35665,"FLOAT_VEC4":35666,"INT_VEC2":35667,"INT_VEC3":35668,"INT_VEC4":35669,"BOOL":35670,"BOOL_VEC2":35671,"BOOL_VEC3":35672,"BOOL_VEC4":35673,"FLOAT_MAT2":35674,"FLOAT_MAT3":35675,"FLOAT_MAT4":35676,"SAMPLER_2D":35678,"SAMPLER_CUBE":35680,"VERTEX_ATTRIB_ARRAY_ENABLED":34338,"VERTEX_ATTRIB_ARRAY_SIZE":34339,"VERTEX_ATTRIB_ARRAY_STRIDE":34340,"VERTEX_ATTRIB_ARRAY_TYPE":34341,"VERTEX_ATTRIB_ARRAY_NORMALIZED":34922,"VERTEX_ATTRIB_ARRAY_POINTER":34373,"VERTEX_ATTRIB_ARRAY_BUFFER_BINDING":34975,"IMPLEMENTATION_COLOR_READ_TYPE":35738,"IMPLEMENTATION_COLOR_READ_FORMAT":35739,"COMPILE_STATUS":35713,"LOW_FLOAT":36336,"MEDIUM_FLOAT":36337,"HIGH_FLOAT":36338,"LOW_INT":36339,"MEDIUM_INT":36340,"HIGH_INT":36341,"FRAMEBUFFER":36160,"RENDERBUFFER":36161,"RGBA4":32854,"RGB5_A1":32855,"RGB565":36194,"DEPTH_COMPONENT16":33189,"STENCIL_INDEX8":36168,"DEPTH_STENCIL":34041,"RENDERBUFFER_WIDTH":36162,"RENDERBUFFER_HEIGHT":36163,"RENDERBUFFER_INTERNAL_FORMAT":36164,"RENDERBUFFER_RED_SIZE":36176,"RENDERBUFFER_GREEN_SIZE":36177,"RENDERBUFFER_BLUE_SIZE":36178,"RENDERBUFFER_ALPHA_SIZE":36179,"RENDERBUFFER_DEPTH_SIZE":36180,"RENDERBUFFER_STENCIL_SIZE":36181,"FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE":36048,"FRAMEBUFFER_ATTACHMENT_OBJECT_NAME":36049,"FRAMEBUFFER_ATTACHMENT_TEXTURE_LEVEL":36050,"FRAMEBUFFER_ATTACHMENT_TEXTURE_CUBE_MAP_FACE":36051,"COLOR_ATTACHMENT0":36064,"DEPTH_ATTACHMENT":36096,"STENCIL_ATTACHMENT":36128,"DEPTH_STENCIL_ATTACHMENT":33306,"NONE":0,"FRAMEBUFFER_COMPLETE":36053,"FRAMEBUFFER_INCOMPLETE_ATTACHMENT":36054,"FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT":36055,"FRAMEBUFFER_INCOMPLETE_DIMENSIONS":36057,"FRAMEBUFFER_UNSUPPORTED":36061,"FRAMEBUFFER_BINDING":36006,"RENDERBUFFER_BINDING":36007,"MAX_RENDERBUFFER_SIZE":34024,"INVALID_FRAMEBUFFER_OPERATION":1286,"UNPACK_FLIP_Y_WEBGL":37440,"UNPACK_PREMULTIPLY_ALPHA_WEBGL":37441,"CONTEXT_LOST_WEBGL":37442,"UNPACK_COLORSPACE_CONVERSION_WEBGL":37443,"BROWSER_DEFAULT_WEBGL":37444,"RGB8":32849,"RGBA8":32856}},"WebKitCSSMatrix":{"f":{"fromFloat32Array":1,"fromFloat64Array":1,"fromMatrix":0}},"WheelEvent":{"c":{"DOM_DELTA_PIXEL":0,"DOM_DELTA_LINE":1,"DOM_DELTA_PAGE":2}},"Window":{"c":{"TEMPORARY":0,"PERSISTENT":1}},"XPathResult":{"c":{"ANY_TYPE":0,"NUMBER_TYPE":1,"STRING_TYPE":2,"BOOLEAN_TYPE":3,"UNORDERED_NODE_ITERATOR_TYPE":4,"ORDERED_NODE_ITERATOR_TYPE":5,"UNORDERED_NODE_SNAPSHOT_TYPE":6,"ORDERED_NODE_SNAPSHOT_TYPE":7,"ANY_UNORDERED_NODE_TYPE":8,"FIRST_ORDERED_NODE_TYPE":9}},"XRWebGLLayer":{"f":{"getNativeFramebufferScaleFactor":1}},"GPUBufferUsage":{"c":{"MAP_READ":1,"MAP_WRITE":2,"COPY_SRC":4,"COPY_DST":8,"INDEX":16,"VERTEX":32,"UNIFORM":64,"STORAGE":128,"INDIRECT":256,"QUERY_RESOLVE":512}},"GPUColorWrite":{"c":{"RED":1,"GREEN":2,"BLUE":4,"ALPHA":8,"ALL":15}},"GPUMapMode":{"c":{"READ":1,"WRITE":2}},"GPUShaderStage":{"c":{"VERTEX":1,"FRAGMENT":2,"COMPUTE":4}},"GPUTextureUsage":{"c":{"COPY_SRC":1,"COPY_DST":2,"TEXTURE_BINDING":4,"STORAGE_BINDING":8,"RENDER_ATTACHMENT":16,"TRANSIENT_ATTACHMENT":32}}}"#;

/// How many arguments each WebGL call insists on, measured from Chrome 148.
/// A call made with fewer is a refusal there, with the method named in the
/// message; ours answered `undefined` and carried on.
/// Chrome 151 WebGL extension prototypes: constants, methods, flags.
const WEBGL_EXT_SHAPES: &str = include_str!("webgl_ext_shapes.json");
const GL_ARITY: &str = r#"{"activeTexture":1,"attachShader":2,"bindAttribLocation":3,"bindRenderbuffer":2,"blendColor":4,"blendEquation":1,"blendEquationSeparate":2,"blendFunc":2,"blendFuncSeparate":4,"bufferData":3,"bufferSubData":3,"checkFramebufferStatus":1,"compileShader":1,"compressedTexImage2D":7,"compressedTexSubImage2D":8,"copyTexImage2D":8,"copyTexSubImage2D":8,"createShader":1,"cullFace":1,"deleteBuffer":1,"deleteFramebuffer":1,"deleteProgram":1,"deleteRenderbuffer":1,"deleteShader":1,"deleteTexture":1,"depthFunc":1,"depthMask":1,"depthRange":2,"detachShader":2,"disable":1,"enable":1,"framebufferRenderbuffer":4,"framebufferTexture2D":5,"frontFace":1,"generateMipmap":1,"getActiveAttrib":2,"getActiveUniform":2,"getAttachedShaders":1,"getAttribLocation":2,"getBufferParameter":2,"getExtension":1,"getFramebufferAttachmentParameter":3,"getParameter":1,"getProgramInfoLog":1,"getProgramParameter":2,"getRenderbufferParameter":2,"getShaderInfoLog":1,"getShaderParameter":2,"getShaderPrecisionFormat":2,"getShaderSource":1,"getTexParameter":2,"getUniform":2,"getUniformLocation":2,"getVertexAttrib":2,"getVertexAttribOffset":2,"hint":2,"isBuffer":1,"isEnabled":1,"isFramebuffer":1,"isProgram":1,"isRenderbuffer":1,"isShader":1,"isTexture":1,"lineWidth":1,"linkProgram":1,"pixelStorei":2,"polygonOffset":2,"readPixels":7,"renderbufferStorage":4,"sampleCoverage":2,"shaderSource":2,"stencilFunc":3,"stencilFuncSeparate":4,"stencilMask":1,"stencilMaskSeparate":2,"stencilOp":3,"stencilOpSeparate":4,"texImage2D":6,"texParameterf":3,"texParameteri":3,"texSubImage2D":7,"useProgram":1,"validateProgram":1,"bindBuffer":2,"bindFramebuffer":2,"bindTexture":2,"clear":1,"clearColor":4,"clearDepth":1,"clearStencil":1,"colorMask":4,"disableVertexAttribArray":1,"drawArrays":3,"drawElements":4,"enableVertexAttribArray":1,"scissor":4,"uniform1f":2,"uniform1fv":2,"uniform1i":2,"uniform1iv":2,"uniform2f":3,"uniform2fv":2,"uniform2i":3,"uniform2iv":2,"uniform3f":4,"uniform3fv":2,"uniform3i":4,"uniform3iv":2,"uniform4f":5,"uniform4fv":2,"uniform4i":5,"uniform4iv":2,"uniformMatrix2fv":3,"uniformMatrix3fv":3,"uniformMatrix4fv":3,"vertexAttrib1f":2,"vertexAttrib1fv":2,"vertexAttrib2f":3,"vertexAttrib2fv":2,"vertexAttrib3f":4,"vertexAttrib3fv":2,"vertexAttrib4f":5,"vertexAttrib4fv":2,"vertexAttribPointer":6,"viewport":4,"drawingBufferStorage":3,"beginQuery":2,"beginTransformFeedback":1,"bindBufferBase":3,"bindBufferRange":5,"bindSampler":2,"bindTransformFeedback":2,"bindVertexArray":1,"blitFramebuffer":10,"clientWaitSync":3,"compressedTexImage3D":8,"compressedTexSubImage3D":10,"copyBufferSubData":5,"copyTexSubImage3D":9,"deleteQuery":1,"deleteSampler":1,"deleteSync":1,"deleteTransformFeedback":1,"deleteVertexArray":1,"drawArraysInstanced":4,"drawElementsInstanced":5,"drawRangeElements":6,"endQuery":1,"fenceSync":2,"framebufferTextureLayer":5,"getActiveUniformBlockName":2,"getActiveUniformBlockParameter":3,"getActiveUniforms":3,"getBufferSubData":3,"getFragDataLocation":2,"getIndexedParameter":2,"getInternalformatParameter":3,"getQuery":2,"getQueryParameter":2,"getSamplerParameter":2,"getSyncParameter":2,"getTransformFeedbackVarying":2,"getUniformBlockIndex":2,"getUniformIndices":2,"invalidateFramebuffer":2,"invalidateSubFramebuffer":6,"isQuery":1,"isSampler":1,"isSync":1,"isTransformFeedback":1,"isVertexArray":1,"readBuffer":1,"renderbufferStorageMultisample":5,"samplerParameterf":3,"samplerParameteri":3,"texImage3D":10,"texStorage2D":5,"texStorage3D":6,"texSubImage3D":11,"transformFeedbackVaryings":3,"uniform1ui":2,"uniform2ui":3,"uniform3ui":4,"uniform4ui":5,"uniformBlockBinding":3,"vertexAttribDivisor":2,"vertexAttribI4i":5,"vertexAttribI4ui":5,"vertexAttribIPointer":5,"waitSync":3,"clearBufferfi":4,"clearBufferfv":3,"clearBufferiv":3,"clearBufferuiv":3,"drawBuffers":1,"uniform1uiv":2,"uniform2uiv":2,"uniform3uiv":2,"uniform4uiv":2,"uniformMatrix2x3fv":3,"uniformMatrix2x4fv":3,"uniformMatrix3x2fv":3,"uniformMatrix3x4fv":3,"uniformMatrix4x2fv":3,"uniformMatrix4x3fv":3,"vertexAttribI4iv":2,"vertexAttribI4uiv":2}"#;

/// Captured from Chrome 151: WebRTC offer sections and getCapabilities.
const RTC_CHROME: &str = include_str!("rtc_chrome.json");

// The windows-1250 byte table below carries literal C1 control bytes on
// purpose: it replicates exactly what Chrome's TextDecoder hands a page, and
// clippy::invisible_characters would otherwise refuse the very data this
// template exists to reproduce.
#[allow(clippy::invisible_characters)]
const FINGERPRINT_TEMPLATE: &str = r#"(() => {
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_lastIndexOf = __sm(String.prototype.lastIndexOf, 'lastIndexOf'),
    __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_startsWith = __sm(String.prototype.startsWith, 'startsWith'),
    __s_replace = __sm(String.prototype.replace, 'replace'),
    __s_toLowerCase = __sm(String.prototype.toLowerCase, 'toLowerCase'),
    __s_search = __sm(String.prototype.search, 'search'),
    __s_trim = __sm(String.prototype.trim, 'trim'),
    __s_endsWith = __sm(String.prototype.endsWith, 'endsWith'),
    __s_split = __sm(String.prototype.split, 'split'),
    __s_toUpperCase = __sm(String.prototype.toUpperCase, 'toUpperCase'),
    __s_padStart = __sm(String.prototype.padStart, 'padStart'),
    __s_codePointAt = __sm(String.prototype.codePointAt, 'codePointAt'),
    __s_charCodeAt = __sm(String.prototype.charCodeAt, 'charCodeAt');
  // Interface object shape: a strict function has exactly `length, name,
  // prototype` (no `arguments`/`caller`, which browser interfaces lack) and,
  // unlike a class, throws "Illegal constructor" when called without `new` too.
  const __ptIllegal = (function () {
    'use strict';
    return function () { return function () { throw __pt_mkErr(TypeError, 'Illegal constructor'); }; };
  })();
  const __ptName = (f, n) => {
    try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {}
    return f;
  };
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
  // The bootstrap's own functions read as native in every context of the
  // isolate (an iframe's toString showed our source); the set keeps the rest.
  const __ptBoot = typeof globalThis.__pt_isBoot === 'function' ? globalThis.__pt_isBoot : null;
  const __ptIsNat = (f) => __ptNative.has(f) || (__ptBoot !== null && __ptBoot(f));
  const __ptMark = (f) => { if (__ptBoot === null || !__ptBoot(f)) __ptNative.add(f); return f; };
  // Everything the trap uses is captured up front: a page that wrapped
  // Reflect.apply or put a `name` getter on a function would otherwise see
  // toString calling its code (Chrome's calls nothing).
  const __ptRApply = Reflect.apply, __ptGOPD = Object.getOwnPropertyDescriptor;
  // For canvas/GL logs: join and hash without calling anything the page can
  // wrap (Array.prototype.join, String.prototype.charCodeAt).
  const __ptRA = Reflect.apply, __ptCCA = String.prototype.charCodeAt, __ptCCA1 = [0], __ptImul = Math.imul;
  const __ptJ = function () {
    let out = '';
    for (let i = 0; i < arguments.length; i++) {
      const v = arguments[i];
      if (i) out += ',';
      if (v === null || v === undefined) continue;
      out += (typeof v === 'object' || typeof v === 'function' || typeof v === 'symbol') ? '[o]' : '' + v;
    }
    return out;
  };
  const __ptFnName = (f) => {
    try {
      const d = __ptGOPD(f, 'name');
      return d && typeof d.value === 'string' ? d.value : '';
    } catch (e) { return ''; }
  };
  const __ptToStr = __pt_proxy(Function.prototype.toString, {
    apply(target, thisArg, args) {
      if (__ptIsNat(thisArg)) {
        return 'function ' + __ptFnName(thisArg) + '() { [native code] }';
      }
      return __ptRApply(target, thisArg, args);
    },
  });
  try {
    Object.defineProperty(Function.prototype, 'toString', {
      value: __ptToStr,
      configurable: true,
      writable: true,
    });
  } catch (e) {}
  __ptMark(__ptToStr);

  // Register a function as native, optionally renaming it. No longer sets an own
  // `toString` (the global patch above handles every call route).
  // Exported under a __pt name (hidden by the introspection filter): the
  // WEB_SURFACE_TEMPLATE surface marks its functions native through it.
  globalThis.__pt_native = (fn) => { if (typeof fn === 'function') __ptMark(fn); return fn; };
  // Check without going through the toString proxy, for late shape layers.
  globalThis.__pt_isNative = (fn) => __ptIsNat(fn);

  // A browser method is not a constructor: no `prototype`, and `new` throws.
  // A plain function has both and its `prototype` cannot be deleted, so the
  // function must be recreated as a method. `'prototype' in el.getAttribute`
  // costs nothing and exposes us at once.
  const asMethod = (fn, name) => {
    if (typeof fn !== 'function') return fn;
    if (!Object.getOwnPropertyDescriptor(fn, 'prototype')) return fn;   // already a method
    const key = name || fn.name || 'anonymous';
    // Interfaces are not turned into methods: a class has a capitalized name
    // and members on its prototype.
    const looksLikeMethod = /^[a-z_$]/.test(key)
      && Object.getOwnPropertyNames(fn.prototype || {}).length <= 1;
    if (!looksLikeMethod) return fn;
    return __pt_method(key, fn);
  };

  const mask = (fn, name) => {
    const m = asMethod(fn, name);
    // Only when it differs: writing `name` moves a function to dictionary
    // mode (~260 bytes), and there are thousands.
    try {
      if (name && m.name !== name) Object.defineProperty(m, 'name', { value: name, configurable: true });
    } catch (e) {}
    if (typeof m === 'function') __ptMark(m);
    return m;
  };

  // Mark every own function/accessor on a prototype as native — real DOM and
  // Web-API methods all report `[native code]`, so ours must too.
  const maskProto = (proto) => {
    if (!proto) return proto;
    for (const k of Object.getOwnPropertyNames(proto)) {
      try {
        const d = Object.getOwnPropertyDescriptor(proto, k);
        if (!d) continue;
        // A function on a prototype is a method: recreate it as one if it still
        // has `prototype`, then mark it native.
        if (typeof d.value === 'function' && k !== 'constructor' && d.configurable
            && /^[a-z_$]/.test(k)
            && Object.getOwnPropertyNames(d.value.prototype || {}).length <= 1
            && Object.getOwnPropertyDescriptor(d.value, 'prototype')) {
          const m = asMethod(d.value, k);
          Object.defineProperty(proto, k, Object.assign({}, d, { value: m }));
          __ptMark(m);
          continue;
        }
        if (typeof d.value === 'function') __ptMark(d.value);
        if (typeof d.get === 'function') __ptMark(d.get);
        if (typeof d.set === 'function') __ptMark(d.set);
      } catch (e) {}
    }
    return proto;
  };

  const noop = () => {};
  // Own values for names the browser declares read-only: assigning throws,
  // defining does not.
  const own = (o, k, v) => {
    try { Object.defineProperty(o, k, { value: v, writable: true, enumerable: true, configurable: true }); }
    catch (e) {}
  };


  // The seed canvas and audio derive their device-specific character from.
  // It is a hash of *this profile* — the same identity therefore draws the same
  // pixels and plays the same waveform in every run, the way one machine does,
  // and two identities differ. It used to be `Math.random()` per session, which
  // is the opposite of a device: a fingerprint that changes on every visit is
  // itself the signal anti-bot scoring hunts for.
  const SEED = __FP_SEED__;
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
    if (!globalThis[n]) globalThis[n] = mask(__ptIllegal(n), n);
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
  // All CSS named colors, captured from Chrome: pages name colors far more
  // often than they use hex codes.
  const CSS_NAMES = Object.create(null);
  for (const pair of __s_split('aliceblue:f0f8ff,antiquewhite:faebd7,aqua:00ffff,aquamarine:7fffd4,azure:f0ffff,beige:f5f5dc,bisque:ffe4c4,black:000000,blanchedalmond:ffebcd,blue:0000ff,blueviolet:8a2be2,brown:a52a2a,burlywood:deb887,cadetblue:5f9ea0,chartreuse:7fff00,chocolate:d2691e,coral:ff7f50,cornflowerblue:6495ed,cornsilk:fff8dc,crimson:dc143c,cyan:00ffff,darkblue:00008b,darkcyan:008b8b,darkgoldenrod:b8860b,darkgray:a9a9a9,darkgreen:006400,darkgrey:a9a9a9,darkkhaki:bdb76b,darkmagenta:8b008b,darkolivegreen:556b2f,darkorange:ff8c00,darkorchid:9932cc,darkred:8b0000,darksalmon:e9967a,darkseagreen:8fbc8f,darkslateblue:483d8b,darkslategray:2f4f4f,darkslategrey:2f4f4f,darkturquoise:00ced1,darkviolet:9400d3,deeppink:ff1493,deepskyblue:00bfff,dimgray:696969,dimgrey:696969,dodgerblue:1e90ff,firebrick:b22222,floralwhite:fffaf0,forestgreen:228b22,fuchsia:ff00ff,gainsboro:dcdcdc,ghostwhite:f8f8ff,gold:ffd700,goldenrod:daa520,gray:808080,green:008000,greenyellow:adff2f,grey:808080,honeydew:f0fff0,hotpink:ff69b4,indianred:cd5c5c,indigo:4b0082,ivory:fffff0,khaki:f0e68c,lavender:e6e6fa,lavenderblush:fff0f5,lawngreen:7cfc00,lemonchiffon:fffacd,lightblue:add8e6,lightcoral:f08080,lightcyan:e0ffff,lightgoldenrodyellow:fafad2,lightgray:d3d3d3,lightgreen:90ee90,lightgrey:d3d3d3,lightpink:ffb6c1,lightsalmon:ffa07a,lightseagreen:20b2aa,lightskyblue:87cefa,lightslategray:778899,lightslategrey:778899,lightsteelblue:b0c4de,lightyellow:ffffe0,lime:00ff00,limegreen:32cd32,linen:faf0e6,magenta:ff00ff,maroon:800000,mediumaquamarine:66cdaa,mediumblue:0000cd,mediumorchid:ba55d3,mediumpurple:9370db,mediumseagreen:3cb371,mediumslateblue:7b68ee,mediumspringgreen:00fa9a,mediumturquoise:48d1cc,mediumvioletred:c71585,midnightblue:191970,mintcream:f5fffa,mistyrose:ffe4e1,moccasin:ffe4b5,navajowhite:ffdead,navy:000080,oldlace:fdf5e6,olive:808000,olivedrab:6b8e23,orange:ffa500,orangered:ff4500,orchid:da70d6,palegoldenrod:eee8aa,palegreen:98fb98,paleturquoise:afeeee,palevioletred:db7093,papayawhip:ffefd5,peachpuff:ffdab9,peru:cd853f,pink:ffc0cb,plum:dda0dd,powderblue:b0e0e6,purple:800080,rebeccapurple:663399,red:ff0000,rosybrown:bc8f8f,royalblue:4169e1,saddlebrown:8b4513,salmon:fa8072,sandybrown:f4a460,seagreen:2e8b57,seashell:fff5ee,sienna:a0522d,silver:c0c0c0,skyblue:87ceeb,slateblue:6a5acd,slategray:708090,slategrey:708090,snow:fffafa,springgreen:00ff7f,steelblue:4682b4,tan:d2b48c,teal:008080,thistle:d8bfd8,tomato:ff6347,turquoise:40e0d0,violet:ee82ee,wheat:f5deb3,white:ffffff,whitesmoke:f5f5f5,yellow:ffff00,yellowgreen:9acd32', ',')) {
    const i = __s_indexOf(pair, ':');
    CSS_NAMES[__s_slice(pair, 0, i)] = __s_slice(pair, i + 1);
  }
  const hue2rgb = (h, s2, l) => {
    h = ((h % 360) + 360) % 360;
    const a = s2 * Math.min(l, 1 - l);
    const f = (n) => { const k = (n + h / 30) % 12; return l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1)); };
    return [f(0), f(8), f(4)];
  };
  // Lab via XYZ D50, Oklab via XYZ D65; standard matrices.
  const lab2srgb = (L, a, b) => {
    const fy = (L + 16) / 116, fx = fy + a / 500, fz = fy - b / 200;
    const e = 216 / 24389, k = 24389 / 27;
    const f3 = (t) => (t * t * t > e ? t * t * t : (116 * t - 16) / k);
    const X = f3(fx) * 0.3457 / 0.3585, Y = (L > k * e ? Math.pow(fy, 3) : L / k), Z = f3(fz) * (1 - 0.3457 - 0.3585) / 0.3585;
    // D50 -> D65 (Bradford) and XYZ -> linear sRGB folded into one matrix.
    const M = [3.1341359569958707, -1.6173863321612538, -0.4906619460083532,
      -0.978795502912089, 1.916142228104716, 0.03344668406522899,
      0.07195537988411677, -0.2289768264158322, 1.405386058324125];
    const r = M[0] * X + M[1] * Y + M[2] * Z, g2 = M[3] * X + M[4] * Y + M[5] * Z, b2 = M[6] * X + M[7] * Y + M[8] * Z;
    return [LIN_TO_SRGB(r), LIN_TO_SRGB(g2), LIN_TO_SRGB(b2)];
  };
  const oklab2srgb = (L, a, b) => {
    const l = Math.pow(L + 0.3963377774 * a + 0.2158037573 * b, 3);
    const m = Math.pow(L - 0.1055613458 * a - 0.0638541728 * b, 3);
    const s2 = Math.pow(L - 0.0894841775 * a - 1.2914855480 * b, 3);
    return [
      LIN_TO_SRGB(4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s2),
      LIN_TO_SRGB(-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s2),
      LIN_TO_SRGB(-0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s2),
    ];
  };
  // Parses one numeric argument: percentages, fractions, angles and the keyword `none`.
  const num = (t, scale, isHue) => {
    t = __s_trim(String(t));
    if (t === 'none') return 0;
    if (/%$/.test(t)) return (parseFloat(t) || 0) / 100 * (scale === undefined ? 1 : scale);
    let v = parseFloat(t) || 0;
    if (isHue) {
      if (/grad$/.test(t)) v *= 0.9;
      else if (/rad$/.test(t)) v *= 180 / Math.PI;
      else if (/turn$/.test(t)) v *= 360;
    }
    return v;
  };
  const splitArgs = (t) => {
    const slash = __s_indexOf(t, '/');
    const head = __s_trim(slash < 0 ? t : __s_slice(t, 0, slash));
    const alpha = slash < 0 ? null : __s_trim(__s_slice(t, slash + 1));
    return [__s_split(head, /[\s,]+/).filter(Boolean), alpha];
  };
  // Color to four bytes. Anything the browser parses we parse; unparsable
  // input is a refusal, not black: the browser then leaves `fillStyle` unchanged.
  const parseColorRaw = (c) => {
    // A gradient or pattern is not a color; stringifying the object would call
    // its toString (visible to the page).
    if (c !== null && (typeof c === 'object' || typeof c === 'function')) return null;
    let t = __s_toLowerCase(__s_trim(String(c == null ? '' : c)));
    if (!t) return null;
    if (t === 'transparent') return [0, 0, 0, 0];
    if (t === 'currentcolor') return [0, 0, 0, 255];
    if (CSS_NAMES[t]) t = '#' + CSS_NAMES[t];
    let m = /^#([0-9a-f]{3,8})$/.exec(t);
    if (m) {
      const h = m[1];
      const dup = (x) => parseInt(x + x, 16);
      if (h.length === 3) return [dup(h[0]), dup(h[1]), dup(h[2]), 255];
      if (h.length === 4) return [dup(h[0]), dup(h[1]), dup(h[2]), dup(h[3])];
      if (h.length === 6) return [parseInt(__s_slice(h, 0, 2), 16), parseInt(__s_slice(h, 2, 4), 16), parseInt(__s_slice(h, 4, 6), 16), 255];
      if (h.length === 8) return [parseInt(__s_slice(h, 0, 2), 16), parseInt(__s_slice(h, 2, 4), 16),
        parseInt(__s_slice(h, 4, 6), 16), parseInt(__s_slice(h, 6, 8), 16)];
      return null;
    }
    m = /^([a-z-]+)\(([^]*)\)$/.exec(t);
    if (!m) return null;
    const fn = m[1];
    const b255 = (v) => Math.max(0, Math.min(255, Math.round(v)));
    const unit = (v) => Math.max(0, Math.min(255, Math.round(v * 255)));
    if (fn === 'color-mix') {
      // Mixing in sRGB: the only form seen on pages.
      const body = __s_replace(m[2], /^in\s+[a-z0-9-]+\s*,?/, '');
      const parts = __s_split(body, ',').map((x) => __s_trim(x)).filter(Boolean);
      if (parts.length !== 2) return null;
      const one = (x) => {
        const pm = /\s([0-9.]+)%$/.exec(x);
        return { col: parseColorRaw(pm ? __s_slice(x, 0, pm.index) : x), w: pm ? parseFloat(pm[1]) / 100 : null };
      };
      const A = one(parts[0]), B = one(parts[1]);
      if (!A.col || !B.col) return null;
      let wa = A.w, wb = B.w;
      if (wa == null && wb == null) { wa = wb = 0.5; }
      else if (wa == null) { wa = 1 - wb; } else if (wb == null) { wb = 1 - wa; }
      const sum = wa + wb || 1;
      wa /= sum; wb /= sum;
      const out = [b255(A.col[0] * wa + B.col[0] * wb), b255(A.col[1] * wa + B.col[1] * wb),
        b255(A.col[2] * wa + B.col[2] * wb), b255(A.col[3] * wa + B.col[3] * wb)];
      // The browser serializes the mix computed, as sRGB fractions, taking the
      // fraction before byte rounding (otherwise a half would be "0.502").
      const mix = (i) => (A.col[i] * wa + B.col[i] * wb) / 255;
      const f = (i) => String(Math.round(mix(i) * 10000) / 10000);
      out.css = 'color(srgb ' + f(0) + ' ' + f(1) + ' ' + f(2) +
        (out[3] >= 255 ? '' : ' / ' + Math.round(out[3] / 255 * 1000) / 1000) + ')';
      return out;
    }
    const [args, alphaTxt] = splitArgs(m[2]);
    const alpha = alphaTxt !== null ? num(alphaTxt, 1) : (args.length > 3 ? num(args[3], 1) : 1);
    const A255 = Math.max(0, Math.min(255, Math.round(alpha * 255)));
    if (fn === 'rgb' || fn === 'rgba') {
      const ch = (x) => (/%$/.test(x) ? unit(parseFloat(x) / 100) : b255(parseFloat(x) || 0));
      return [ch(args[0] || '0'), ch(args[1] || '0'), ch(args[2] || '0'), A255];
    }
    if (fn === 'hsl' || fn === 'hsla') {
      const rgb = hue2rgb(num(args[0], undefined, true), num(args[1], 1), num(args[2], 1));
      return [unit(rgb[0]), unit(rgb[1]), unit(rgb[2]), A255];
    }
    if (fn === 'hwb') {
      const h = num(args[0], undefined, true);
      let w = num(args[1], 1), bl = num(args[2], 1);
      if (w + bl >= 1) { const g2 = w / (w + bl); return [unit(g2), unit(g2), unit(g2), A255]; }
      const rgb = hue2rgb(h, 1, 0.5).map((v) => v * (1 - w - bl) + w);
      return [unit(rgb[0]), unit(rgb[1]), unit(rgb[2]), A255];
    }
    if (fn === 'lab' || fn === 'lch' || fn === 'oklab' || fn === 'oklch') {
      const ok = fn[0] === 'o';
      const Lmax = ok ? 1 : 100;
      const L = /%$/.test(args[0] || '') ? parseFloat(args[0]) / 100 * Lmax : (parseFloat(args[0]) || 0);
      let a, b;
      if (fn === 'lch' || fn === 'oklch') {
        const C = /%$/.test(args[1] || '') ? parseFloat(args[1]) / 100 * (ok ? 0.4 : 150) : (parseFloat(args[1]) || 0);
        const H = num(args[2], undefined, true) * Math.PI / 180;
        a = C * Math.cos(H); b = C * Math.sin(H);
      } else {
        const S2 = ok ? 0.4 : 125;
        a = /%$/.test(args[1] || '') ? parseFloat(args[1]) / 100 * S2 : (parseFloat(args[1]) || 0);
        b = /%$/.test(args[2] || '') ? parseFloat(args[2]) / 100 * S2 : (parseFloat(args[2]) || 0);
      }
      const rgb = ok ? oklab2srgb(L, a, b) : lab2srgb(L, a, b);
      const out = [unit(rgb[0]), unit(rgb[1]), unit(rgb[2]), A255];
      // The browser does not convert modern notations to hex: it keeps their
      // own space, with normalized numbers.
      const nn = (x) => String(/%$/.test(String(x)) ? parseFloat(x) : (parseFloat(x) || 0));
      out.css = fn + '(' + [nn(args[0]), nn(args[1]), nn(args[2])].join(' ') +
        (alpha >= 1 ? '' : ' / ' + alpha) + ')';
      return out;
    }
    if (fn === 'color') {
      const space = args[0];
      const q = [num(args[1], 1), num(args[2], 1), num(args[3], 1)];
      const rgb = space === 'display-p3' ? convertSpace(q, 'display-p3', 'srgb') : q;
      const al = alphaTxt !== null ? num(alphaTxt, 1) : (args.length > 4 ? num(args[4], 1) : 1);
      const out = [unit(rgb[0]), unit(rgb[1]), unit(rgb[2]), Math.max(0, Math.min(255, Math.round(al * 255)))];
      const nn = (x) => String(parseFloat(x) || 0);
      out.css = 'color(' + space + ' ' + [nn(args[1]), nn(args[2]), nn(args[3])].join(' ') +
        (al >= 1 ? '' : ' / ' + al) + ')';
      return out;
    }
    return null;
  };
  const parseColor = (c) => parseColorRaw(c) || [0, 0, 0, 255];
  // Color as `getComputedStyle` prints it: the browser turns any sRGB
  // notation into `rgb(r, g, b)` (or `rgba(...)` with alpha) and leaves its own
  // spaces (`lab`, `oklch`, `color()`) as is. Alpha comes from the notation,
  // not the rounded byte: `0.9` stays `0.9`, not `0.902`.
  try {
    Object.defineProperty(globalThis, '__pt_cssColour', {
      value: (v) => {
        const t = __s_trim(String(v == null ? '' : v));
        const low = __s_toLowerCase(t);
        if (!low) return null;
        if (/^(color|lab|lch|oklab|oklch|color-mix|var|calc|attr|light-dark)\(/.test(low)) return null;
        if (low === 'transparent') return 'rgba(0, 0, 0, 0)';
        if (low === 'currentcolor') return null;
        const c = parseColorRaw(low);
        if (!c) return null;
        let a = c[3] / 255;
        const m = /^(?:rgba?|hsla?|hwb)\(([^]*)\)$/.exec(low);
        if (m) {
          const body = m[1];
          const slash = __s_lastIndexOf(body, '/');
          let txt = null;
          if (slash >= 0) txt = __s_trim(__s_slice(body, slash + 1));
          else { const parts = __s_split(body, ','); if (parts.length === 4) txt = __s_trim(parts[3]); }
          if (txt != null && txt !== '') {
            const val = /%$/.test(txt) ? parseFloat(txt) / 100 : parseFloat(txt);
            if (!Number.isNaN(val)) a = val;
          }
        }
        a = Math.max(0, Math.min(1, a));
        return a >= 1
          ? 'rgb(' + c[0] + ', ' + c[1] + ', ' + c[2] + ')'
          : 'rgba(' + c[0] + ', ' + c[1] + ', ' + c[2] + ', ' + (Math.round(a * 1000) / 1000) + ')';
      },
      enumerable: false, configurable: true, writable: true,
    });
  } catch (e) {}
  // Color serialization: the browser gives `#rrggbb`, or `rgba(r, g, b, a)`
  // when translucent.
  const serializeColor = (rgba) => {
    if (!rgba) return '#000000';
    if (rgba.css) return rgba.css;
    if (rgba[3] >= 255) {
      const h = (v) => __s_padStart((v | 0).toString(16), 2, '0');
      return '#' + h(rgba[0]) + h(rgba[1]) + h(rgba[2]);
    }
    // Alpha is written as the shortest fraction mapping back to the same byte:
    // the browser calls 128/255 "0.5", not "0.502".
    const n = rgba[3] | 0;
    let a = String(n / 255);
    for (let places = 1; places <= 3; places++) {
      const d = Math.round(n / 255 * Math.pow(10, places)) / Math.pow(10, places);
      if (Math.round(d * 255) === n) { a = String(d); break; }
    }
    return 'rgba(' + (rgba[0] | 0) + ', ' + (rgba[1] | 0) + ', ' + (rgba[2] | 0) + ', ' + a + ')';
  };

  // Canvas color spaces. Pages fill with `color(display-p3 ...)` and read it
  // back in every combination of space and precision; the browser's
  // conversion identifies it.
  const SRGB_TO_LIN = (v) => (v <= 0.04045 ? v / 12.92 : Math.sign(v) * Math.pow((Math.abs(v) + 0.055) / 1.055, 2.4));
  const LIN_TO_SRGB = (v) => (Math.abs(v) <= 0.0031308 ? v * 12.92
    : Math.sign(v) * (1.055 * Math.pow(Math.abs(v), 1 / 2.4) - 0.055));
  // Linear space matrices, both via XYZ D65, pre-folded.
  const P3_TO_SRGB = [1.2249401762805587, -0.2249401762805586, 0,
    -0.04205697751790907, 1.0420569775179091, 0,
    -0.019636239203287, -0.07863715131854902, 1.0982734115802371];
  const SRGB_TO_P3 = [0.8224621, 0.1775380, 0, 0.0331941, 0.9668058, 0,
    0.0170827, 0.0723974, 0.9105199];
  const applyM = (m, r, g, b) => [
    m[0] * r + m[1] * g + m[2] * b,
    m[3] * r + m[4] * g + m[5] * b,
    m[6] * r + m[7] * g + m[8] * b,
  ];
  // Conversion between spaces goes through linear light, not codes.
  const convertSpace = (rgb, from, to) => {
    if (from === to) return __s_slice(rgb);
    const lin = rgb.map(SRGB_TO_LIN);
    const out = applyM(from === 'display-p3' ? P3_TO_SRGB : SRGB_TO_P3, lin[0], lin[1], lin[2]);
    return out.map(LIN_TO_SRGB);
  };
  // `color(<space> r g b / a)` and all the usual notations as numbers from 0
  // to 1 in the named space.
  const parseColorFloat = (c) => {
    const t = __s_toLowerCase(__s_trim(String(c == null ? '#000000' : c)));
    const m = /^color\(\s*([a-z0-9-]+)\s+([^)\/]+?)(?:\s*\/\s*([^)]+))?\s*\)$/.exec(t);
    if (m) {
      const parts = __s_split(__s_trim(m[2]), /\s+/).map((x) => (x === 'none' ? 0 : parseFloat(x) || 0));
      const a = m[3] === undefined ? 1 : (/%$/.test(__s_trim(m[3]))
        ? parseFloat(m[3]) / 100 : parseFloat(m[3]));
      const space = m[1] === 'display-p3' ? 'display-p3' : 'srgb';
      return { rgb: [parts[0] || 0, parts[1] || 0, parts[2] || 0],
        a: Number.isFinite(a) ? a : 1, space };
    }
    const b = parseColor(c);
    return { rgb: [b[0] / 255, b[1] / 255, b[2] / 255], a: b[3] / 255, space: 'srgb' };
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
        s = '' + s;
        for (let i = 0; i < s.length; i++) { __ptCCA1[0] = i; ops ^= __ptRA(__ptCCA, s, __ptCCA1); ops = __ptImul(ops, 16777619) >>> 0; }
      },
      // A real image on the canvas. The bytes stay in Rust, only the URL comes
      // here; if nothing was decoded for it, the caller stamps its own.
      image(url, dx, dy, dw, dh) {
        sync();
        if (typeof __pt_canvasDrawImage !== 'function') return false;
        try { return !!__pt_canvasDrawImage(id, String(url), dx, dy, dw, dh); }
        catch (e) { return false; }
      },
      solid(x, y, w, h, rgba) {
        sync();
        if ((rgba[3] | 0) === 0) __pt_canvasClearRect(id, x, y, w, h);
        else __pt_canvasFillRect(id, x, y, w, h, rgba[0], rgba[1], rgba[2], rgba[3],
          new Float32Array(arguments[5] || []), arguments[6] | 0);
      },
      // Real glyphs. `y` is the alphabetic baseline, matching canvas semantics.
      text(t, x, y, size, rgba, fam, b, i, sh) { sync(); __pt_canvasFillText(id, String(t), x, y, size, rgba[0], rgba[1], rgba[2], rgba[3], fam || '', !!b, !!i, new Float32Array(sh || [])); },
      textOps(t, x, y, M, size, fam, b, i, stroke, lw, rgba, grad, sh, mode, align, baseline, cap, join, miter) { sync(); return __pt_canvasTextOps(id, String(t), x, y, new Float32Array(M), size, fam || '', !!b, !!i, !!stroke, lw, rgba[0], rgba[1], rgba[2], rgba[3], new Float32Array(grad || []), new Float32Array(sh || []), mode | 0, align | 0, baseline | 0, cap | 0, join | 0, +miter || 10); },
      width(t, size, fam, b, i) { return __pt_canvasMeasureText(String(t), size, fam || '', !!b, !!i); },
      // Real vector paths: JS tessellates curves/arcs to a move/line/close verb
      // stream, tiny-skia fills or strokes it.
      fillPath(verbs, evenOdd, rgba, sh, mode) { sync(); __pt_canvasFillPath(id, new Float32Array(verbs), evenOdd ? 1 : 0, rgba[0], rgba[1], rgba[2], rgba[3], new Float32Array(sh || []), mode | 0); },
      // Fill from path ops in page coordinates and the canvas matrix: the
      // engine computes arcs, conics and antialiasing, like Chrome's Skia.
      fillOps(ops, m, evenOdd, rgba, sh, mode) { sync(); __pt_canvasFillOps(id, new Float32Array(ops), new Float32Array(m), evenOdd ? 1 : 0, rgba[0], rgba[1], rgba[2], rgba[3], new Float32Array(sh || []), mode | 0); },
      fillOpsGradient(ops, m, evenOdd, grad, sh, mode) { sync(); __pt_canvasFillOpsGradient(id, new Float32Array(ops), new Float32Array(m), evenOdd ? 1 : 0, new Float32Array(grad), new Float32Array(sh || []), mode | 0); },
      // Stroke from ops: true if drawn (hairline), false if thicker than a pixel.
      strokeOps(ops, m, lw, rgba, grad, sh, mode, cap, join, miter) { sync(); return !!__pt_canvasStrokeOps(id, new Float32Array(ops), new Float32Array(m), +lw || 0, rgba[0], rgba[1], rgba[2], rgba[3], new Float32Array(grad || []), new Float32Array(sh || []), mode | 0, cap | 0, join | 0, +miter || 10); },
      fillPathGradient(verbs, evenOdd, grad, sh, mode) { sync(); __pt_canvasFillPathGradient(id, new Float32Array(verbs), evenOdd ? 1 : 0, new Float32Array(grad), new Float32Array(sh || []), mode | 0); },
      strokePath(verbs, lw, rgba, sh, mode) { sync(); __pt_canvasStrokePath(id, new Float32Array(verbs), lw, rgba[0], rgba[1], rgba[2], rgba[3], new Float32Array(sh || []), mode | 0); },
      // Images we still can't rasterize: a deterministic semi-transparent fill
      // keyed by the op-log, so the drawing still influences the pixels stably.
      stamp(x, y, w, h) {
        sync();
        let v = (ops ^ SEED) >>> 0;
        v = Math.imul(v ^ (v >>> 15), 2246822519) >>> 0; v = (v ^ (v >>> 13)) >>> 0;
        __pt_canvasFillRect(id, x, y, w, h, v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, 48);
      },
      put(data, x, y, w, h) { sync(); __pt_canvasPutImageData(id, x, y, w, h, data); },
      id() { sync(); return id; },
      // Canvas onto canvas: the engine copies pixels with scaling and alpha
      // blending, as the browser does.
      blit(srcId, sx, sy, sw, sh, dx, dy, dw, dh) {
        sync();
        if (typeof __pt_canvasBlit !== 'function' || !srcId) return false;
        try { return !!__pt_canvasBlit(id, srcId, sx, sy, sw, sh, dx, dy, dw, dh); }
        catch (e) { return false; }
      },
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
        s = '' + s;
        for (let i = 0; i < s.length; i++) { __ptCCA1[0] = i; ops ^= __ptRA(__ptCCA, s, __ptCCA1); ops = __ptImul(ops, 16777619) >>> 0; }
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

  // Context shape captured from Chrome 148: 45 methods and 28 accessors, all
  // on the prototype; the context itself has no own properties.
  // Fingerprinters walk the prototype.
  //
  // The implementation stays the same object behind a WeakMap; the page gets
  // a dummy on the real prototype whose members call the implementation.
  const CTX2D_METHODS = ['clip','createConicGradient','createImageData','createLinearGradient','createPattern','createRadialGradient','drawFocusIfNeeded','drawImage','fill','fillText','getContextAttributes','getImageData','getLineDash','getTransform','isContextLost','isPointInPath','isPointInStroke','measureText','reset','roundRect','setLineDash','strokeText','arc','arcTo','beginPath','bezierCurveTo','clearRect','closePath','ellipse','fillRect','lineTo','moveTo','putImageData','quadraticCurveTo','rect','resetTransform','restore','rotate','save','scale','setTransform','stroke','strokeRect','transform','translate'];
  const CTX2D_ATTRS = ['canvas','lang','font','textAlign','textBaseline','direction','fontKerning','fontStretch','fontVariantCaps','letterSpacing','textRendering','wordSpacing','globalCompositeOperation','filter','imageSmoothingQuality','strokeStyle','fillStyle','shadowColor','lineCap','lineJoin','globalAlpha','imageSmoothingEnabled','shadowOffsetX','shadowOffsetY','shadowBlur','lineWidth','miterLimit','lineDashOffset'];
  const CTX_IMPL = new WeakMap();
  // A context member called on something else: the browser throws
  // `TypeError: Illegal invocation`. Our prototype trampoline used to find
  // itself (its accessor is an own property of the prototype) and recurse
  // until the stack ran out; a global graph walk calls every getter on every
  // prototype and caught RangeError instead of TypeError.
  // The trampolines themselves (masked) identify the prototype, also via its
  // copy: a realm gets OffscreenCanvasRenderingContext2D by moving the same members.
  const CTX_STUBS = new WeakSet();
  const ctxOf = (self, P, name) => {
    const t = CTX_IMPL.get(self);
    if (t) return t;
    if (self === P || self === null || (typeof self !== 'object' && typeof self !== 'function')) {
      throw __pt_mkErr(TypeError, 'Illegal invocation');
    }
    const own = Object.getOwnPropertyDescriptor(self, name);
    // A prototype (own `constructor`, member is the trampoline itself) is not a context.
    if (!own || Object.prototype.hasOwnProperty.call(self, 'constructor') ||
        (own.get && CTX_STUBS.has(own.get)) || (own.set && CTX_STUBS.has(own.set)) ||
        (own.value && CTX_STUBS.has(own.value))) {
      throw __pt_mkErr(TypeError, 'Illegal invocation');
    }
    return self;
  };
  // In the browser `save()`/`restore()` roll back the whole drawing state,
  // not just the matrix.
  const SAVED = ['fillStyle', 'strokeStyle', 'globalAlpha', 'globalCompositeOperation',
    'lineWidth', 'lineCap', 'lineJoin', 'miterLimit', 'lineDashOffset', 'font',
    'textAlign', 'textBaseline', 'direction', 'letterSpacing', 'wordSpacing',
    'fontKerning', 'fontStretch', 'fontVariantCaps', 'textRendering',
    'shadowBlur', 'shadowColor', 'shadowOffsetX', 'shadowOffsetY', 'filter',
    'imageSmoothingEnabled', 'imageSmoothingQuality'];
  // The engine needs the context's internal side (to read pixels); the page does not.
  globalThis.__pt_ctxImpl = (pub) => CTX_IMPL.get(pub) || pub;
  // Allowed values of enumerated context properties: the browser silently
  // rejects invalid ones and keeps the previous value.
  const CTX2D_ENUMS = {
    globalCompositeOperation: ['source-over','source-in','source-out','source-atop','destination-over',
      'destination-in','destination-out','destination-atop','lighter','copy','xor','multiply','screen',
      'overlay','darken','lighten','color-dodge','color-burn','hard-light','soft-light','difference',
      'exclusion','hue','saturation','color','luminosity','plus-darker','plus-lighter'],
    textAlign: ['start','end','left','right','center'],
    textBaseline: ['top','hanging','middle','alphabetic','ideographic','bottom'],
    direction: ['ltr','rtl','inherit'],
    imageSmoothingQuality: ['low','medium','high'],
    fontKerning: ['auto','normal','none'],
    textRendering: ['auto','optimizeSpeed','optimizeLegibility','geometricPrecision'],
    lineCap: ['butt','round','square'],
    lineJoin: ['round','bevel','miter'],
  };

  // Canvas trace (NOKK_TRACE_CANVAS=1): every context call and assignment,
  // tagged with the canvas, from inside the trampoline, invisible to the page.
  const CTX_IDS = new WeakMap();
  let ctxSeq = 0;
  const ctrace = (t, what) => {
    try {
      if (!globalThis.__pt_canvasTrace) return;
      let id = CTX_IDS.get(t);
      if (!id) { id = ++ctxSeq; CTX_IDS.set(t, id); }
      const c = t.canvas; const size = c ? (c.width | 0) + 'x' + (c.height | 0) : '?';
      (globalThis.__pt_parentConsole || console).error('[canvas ' + id + ' ' + size + '] ' + what);
    } catch (e) {}
  };
  const cshow = (v) => {
    if (typeof v === 'number') return String(v);
    if (typeof v === 'string') return JSON.stringify(v.length > 60 ? __s_slice(v, 0, 60) + '…' : v);
    if (v == null || typeof v !== 'object') return String(v);
    try { return '<' + (__s_slice(Object.prototype.toString.call(v), 8, -1)) + (v.width ? ' ' + v.width + 'x' + v.height : '') + '>'; } catch (e) { return '<obj>'; }
  };
  // WebIDL binding as in Chrome: each argument is converted exactly once, in
  // order, before calling the implementation; conversion errors carry the
  // "Failed to execute 'x' on 'Y': " prefix; NaN throws where the browser
  // throws; overloads are checked. The challenge's native function check
  // (section oebe1) calls canvas methods exactly this way.
  const IDL = (() => {
    const symMsg = (e) => e && (e.message === 'Cannot convert a Symbol value to a number' || e.message === 'Cannot convert a BigInt value to a number' || e.message === 'Cannot convert a Symbol value to a string');
    const num = (x, pre) => { try { return +x; } catch (e) { if (e instanceof TypeError && symMsg(e)) throw __pt_mkErr(TypeError, pre + e.message); throw e; } };
    const str = (x, pre) => { if (typeof x === 'symbol') throw __pt_mkErr(TypeError, pre + 'Cannot convert a Symbol value to a string'); try { return String(x); } catch (e) { if (e instanceof TypeError && symMsg(e)) throw __pt_mkErr(TypeError, pre + e.message); throw e; } };
    const dbl = (x, pre) => { const v = num(x, pre); if (!Number.isFinite(v)) throw __pt_mkErr(TypeError, pre + 'The provided double value is non-finite.'); return v; };
    const lng = (x, pre) => {
      const v = num(x, pre);
      if (Number.isNaN(v)) throw __pt_mkErr(TypeError, pre + "Value is not of type 'long'.");
      if (!Number.isFinite(v)) throw __pt_mkErr(TypeError, pre + "Value is infinite and not of type 'long'.");
      const t = Math.trunc(v);
      if (t < -2147483648 || t > 2147483647) throw __pt_mkErr(TypeError, pre + "Value is outside the 'long' value range.");
      return t === 0 ? 0 : t;
    };
    const rule = (x, pre) => { const v = str(x, pre); if (v !== 'nonzero' && v !== 'evenodd') throw __pt_mkErr(TypeError, pre + "The provided value '" + v + "' is not a valid enum value of type CanvasFillRule."); return v; };
    const T = { u: num, d: dbl, L: lng, s: str, b: (x) => !!x, r: rule, a: (x) => x };
    // Copy without Array.prototype.slice, which the page may wrap.
    const copy = (a) => { const o = []; for (let i = 0; i < a.length; i++) o[i] = a[i]; return o; };
    // Signature: type letters; `?` marks optional (undefined left alone).
    const run = (sig, args, pre) => {
      const out = copy(args);
      for (let i = 0, k = 0; k < sig.length; k++) {
        const ch = sig[k];
        if (ch === '?') continue;
        const opt = sig[k + 1] === '?';
        if (i >= args.length) break;
        if (!(opt && args[i] === undefined)) out[i] = T[ch](args[i], pre);
        i++;
      }
      return out;
    };
    const isA = (v, names) => {
      for (let i = 0; i < names.length; i++) { const C = globalThis[names[i]]; try { if (typeof C === 'function' && v instanceof C) return true; } catch (e) {} }
      return false;
    };
    const oneOf = (v, list) => { for (let i = 0; i < list.length; i++) if (list[i] === v) return true; return false; };
    const IMG = ['HTMLCanvasElement', 'HTMLImageElement', 'HTMLVideoElement', 'ImageBitmap', 'OffscreenCanvas', 'SVGImageElement', 'VideoFrame', 'CSSImageValue'];
    const imgCheck = (v, pre) => { if (!isA(v, IMG)) throw __pt_mkErr(TypeError, pre + "The provided value is not of type '(CSSImageValue or HTMLCanvasElement or HTMLImageElement or HTMLVideoElement or ImageBitmap or OffscreenCanvas or SVGImageElement or VideoFrame)'."); };
    const isPath = (v) => isA(v, ['Path2D']);
    const isImageData = (v) => isA(v, ['ImageData']);
    const idx = (msg) => __pt_mkErr(DOMException, msg, 'IndexSizeError');
    // fill/clip: with two or more args there is one overload, (Path2D, rule).
    const fillLike = (a, pre) => {
      if (a.length >= 2) {
        if (!isPath(a[0])) throw __pt_mkErr(TypeError, pre + "parameter 1 is not of type 'Path2D'.");
        return run('ar?', a, pre);
      }
      return a.length && isPath(a[0]) ? a : run('r?', a, pre);
    };
    const S = {
      moveTo: 'uu', lineTo: 'uu', quadraticCurveTo: 'uuuu', bezierCurveTo: 'uuuuuu', rect: 'uuuu',
      fillRect: 'uuuu', strokeRect: 'uuuu', clearRect: 'uuuu', scale: 'uu', translate: 'uu', rotate: 'u',
      transform: 'uuuuuu', fillText: 'suuu?', strokeText: 'suuu?', measureText: 's',
      createLinearGradient: 'dddd', createConicGradient: 'ddd',
    };
    const F = {
      arcTo: (a, pre) => { const o = run('uuuuu', a, pre); if (o[4] < 0) throw idx(pre + 'The radius provided (' + o[4] + ') is negative.'); return o; },
      arc: (a, pre) => { const o = run('uuuuub?', a, pre); if (o[2] < 0) throw idx(pre + 'The radius provided (' + o[2] + ') is negative.'); return o; },
      ellipse: (a, pre) => {
        const o = run('uuuuuuub?', a, pre);
        if (o[2] < 0) throw idx(pre + 'The major-axis radius provided (' + o[2] + ') is negative.');
        if (o[3] < 0) throw idx(pre + 'The minor-axis radius provided (' + o[3] + ') is negative.');
        return o;
      },
      createRadialGradient: (a, pre) => {
        const o = run('dddddd', a, pre);
        if (o[2] < 0) throw idx(pre + 'The r0 provided is less than 0.');
        if (o[5] < 0) throw idx(pre + 'The r1 provided is less than 0.');
        return o;
      },
      fill: (a, pre) => fillLike(a, pre),
      clip: (a, pre) => fillLike(a, pre),
      stroke: (a, pre) => { if (a.length && !isPath(a[0])) throw __pt_mkErr(TypeError, pre + "parameter 1 is not of type 'Path2D'."); return a; },
      isPointInPath: (a, pre) => {
        if (a.length >= 4 && !isPath(a[0])) throw __pt_mkErr(TypeError, pre + "parameter 1 is not of type 'Path2D'.");
        return isPath(a[0]) && a.length >= 3 ? run('auur?', a, pre) : run('uur?', a, pre);
      },
      isPointInStroke: (a, pre) => (isPath(a[0]) ? run('auu', a, pre) : run('uu', a, pre)),
      setTransform: (a, pre) => {
        if (a.length >= 6) return run('uuuuuu', a, pre);
        const m = a[0];
        if (m !== undefined && m !== null && typeof m !== 'object' && typeof m !== 'function') throw __pt_mkErr(TypeError, pre + "The provided value is not of type 'DOMMatrixInit'.");
        if (a.length > 1) throw __pt_mkErr(TypeError, pre + "The provided value is not of type 'DOMMatrixInit'.");
        return a;
      },
      getImageData: (a, pre) => { const o = run('LLLL', a, pre); return o; },
      createImageData: (a, pre) => {
        if (a.length === 1) { if (!isImageData(a[0])) throw __pt_mkErr(TypeError, pre + "parameter 1 is not of type 'ImageData'."); return a; }
        return run('LL', a, pre);
      },
      putImageData: (a, pre) => {
        if (!isImageData(a[0])) throw __pt_mkErr(TypeError, pre + "parameter 1 is not of type 'ImageData'.");
        if (a.length > 3 && a.length < 7) throw __pt_mkErr(TypeError, pre + 'Overload resolution failed.');
        return run(a.length >= 7 ? 'aLLLLLL' : 'aLL', a, pre);
      },
      drawImage: (a, pre) => {
        const n = a.length;
        if (n === 4 || (n > 5 && n < 9)) throw __pt_mkErr(TypeError, pre + 'Overload resolution failed.');
        imgCheck(a[0], pre);
        return run(n >= 9 ? 'auuuuuuuu' : n >= 5 ? 'auuuu' : 'auu', a, pre);
      },
      createPattern: (a, pre) => {
        imgCheck(a[0], pre);
        const o = copy(a);
        o[1] = a[1] === null ? '' : str(a[1], pre);
        if (!oneOf(o[1], ['', 'repeat', 'no-repeat', 'repeat-x', 'repeat-y'])) {
          throw __pt_mkErr(DOMException, pre + "The provided type ('" + o[1] + "') is not one of 'repeat', 'no-repeat', 'repeat-x', or 'repeat-y'.", 'SyntaxError');
        }
        return o;
      },
      setLineDash: (a, pre) => {
        const v = a[0];
        if (v === null || (typeof v !== 'object' && typeof v !== 'function') || typeof v[Symbol.iterator] !== 'function') throw __pt_mkErr(TypeError, pre + 'The provided value cannot be converted to a sequence.');
        const list = []; for (const x of v) list[list.length] = num(x, pre);
        const o = copy(a); o[0] = list; return o;
      },
      roundRect: (a, pre) => {
        const o = run('uuuu', a, pre);
        if (a.length > 4 && a[4] !== undefined) {
          const r = a[4];
          const one = (x) => {
            if (x !== null && typeof x === 'object') return x;
            const v = num(x, pre);
            if (v < 0) throw __pt_mkErr(RangeError, pre + 'Radius value ' + v + ' is negative.');
            return v;
          };
          if (r !== null && typeof r === 'object' && typeof r[Symbol.iterator] === 'function') {
            const list = []; for (const x of r) list[list.length] = one(x);
            if (list.length < 1 || list.length > 4) throw __pt_mkErr(RangeError, pre + list.length + ' radii provided. Between one and four radii are necessary.');
            o[4] = list;
          } else o[4] = one(r);
        }
        return o;
      },
    };
    return (name, iface, args) => {
      const pre = "Failed to execute '" + name + "' on '" + iface + "': ";
      if (F[name]) return F[name](args, pre);
      if (S[name]) return run(S[name], args, pre);
      return args;
    };
  })();
  const publishContext = (impl, C, methods, attrs) => {
    if (!C || !C.prototype) return impl;
    const P = C.prototype;
    if (!P.__ptPublished) {
      try { Object.defineProperty(P, '__ptPublished', { value: true }); } catch (e) {}
      for (const name of methods) {
        // A method, not a function: browser methods have no `prototype` and
        // cannot be called with `new`. Also only the implementation's own
        // method: otherwise a name it lacks would find this same trampoline on
        // the prototype and call itself.
        const IFACE = C.name;
        const f = ({
          [name](...args) {
            const t = ctxOf(this, P, name);
            args = IDL(name, IFACE, args);
            const m = Object.prototype.hasOwnProperty.call(t, name) ? t[name] : null;
            if (globalThis.__pt_canvasTrace) ctrace(t, name + '(' + args.map(cshow).join(', ') + ')');
            return typeof m === 'function' ? m.apply(t, args) : undefined;
          },
        })[name];
        try { Object.defineProperty(f, 'length', { value: 0, configurable: true }); } catch (e) {}
        const mf = mask(f, name);
        try { CTX_STUBS.add(mf); } catch (e) {}
        try { Object.defineProperty(P, name, { value: mf, writable: true, enumerable: true, configurable: true }); } catch (e) {}
      }
      for (const name of attrs) {
        const acc = {
          get [name]() {
            const t = ctxOf(this, P, name);
            const v = Object.prototype.hasOwnProperty.call(t, name) ? t[name] : undefined;
            return name === 'canvas' && v && v.__ptOwner ? v.__ptOwner : v;
          },
          set [name](v) {
            const t = ctxOf(this, P, name);
            if (globalThis.__pt_canvasTrace) ctrace(t, name + ' = ' + cshow(v));
            // The browser silently rejects an invalid enum value and keeps the
            // previous one.
            const allowed = CTX2D_ENUMS[name];
            if (allowed && __s_indexOf(allowed, String(v)) < 0) return;
            // Colors are stored parsed and reserialized, not as the page's
            // string: the browser returns `#rrggbb`, translucent as `rgba(...)`,
            // and keeps the old value for unrecognized input.
            if ((name === 'fillStyle' || name === 'strokeStyle' || name === 'shadowColor') &&
                (v === null || typeof v !== 'object')) {
              const rgba = parseColorRaw(v);
              if (!rgba) return;
              t[name] = serializeColor(rgba);
              return;
            }
            t[name] = v;
          },
        };
        const d0 = Object.getOwnPropertyDescriptor(acc, name);
        const get = d0.get, set = d0.set;
        const mg = mask(get, 'get ' + name), ms = mask(set, 'set ' + name);
        try { CTX_STUBS.add(mg); CTX_STUBS.add(ms); } catch (e) {}
        try {
          Object.defineProperty(P, name, { get: mg, set: ms, enumerable: true, configurable: true });
        } catch (e) {}
      }
    }
    if (!impl) return null;                    // only declare the interface
    const pub = Object.create(P);
    CTX_IMPL.set(pub, impl);
    return pub;
  };

  // Pixels are returned as an ImageData, not a literal: pages call
  // `Object.prototype.toString` on it. `data` is an own property, the rest
  // comes from the prototype.
  const IMAGE_DATA = new WeakMap();
  // The `ImageData` constructor is installed later (the shape table has not
  // created its class when this layer runs), so the builder is visible here.
  const makeImageData = (data, w, h, space, format) => {
    const C = globalThis.ImageData;
    if (typeof C !== 'function' || !C.prototype) return { data, width: w, height: h, colorSpace: 'srgb' };
    const P = C.prototype;
    if (!P.__ptShaped) {
      try { Object.defineProperty(P, '__ptShaped', { value: true }); } catch (e) {}
      const acc = (name, pick) => {
        try {
          Object.defineProperty(P, name, {
            get: mask(({ [name]() { const st = IMAGE_DATA.get(this); return st ? pick(st) : undefined; } })[name], 'get ' + name),
            enumerable: true, configurable: true,
          });
        } catch (e) {}
      };
      acc('width', (st) => st.w);
      acc('height', (st) => st.h);
      acc('colorSpace', (st) => st.cs || 'srgb');
      acc('pixelFormat', (st) => st.pf || 'rgba-unorm8');
      try {
        if (!Object.getOwnPropertyDescriptor(P, Symbol.toStringTag)) {
          Object.defineProperty(P, Symbol.toStringTag, { value: 'ImageData', configurable: true });
        }
      } catch (e) {}
    }
    const o = Object.create(P);
    IMAGE_DATA.set(o, { w, h, cs: space === 'display-p3' ? 'display-p3' : 'srgb',
      pf: format === 'rgba-float16' ? 'rgba-float16' : 'rgba-unorm8' });
    // `data` is the only own property, as in the browser.
    try { Object.defineProperty(o, 'data', { value: data, enumerable: true }); } catch (e) {}
    return o;
  };
  globalThis.__pt_makeImageData = makeImageData;

  // A canvas that has been shown something from another origin stops being
  // readable: the browser refuses `getImageData` and `toDataURL` on it. We
  // handed the pixels over regardless — a one-line probe (draw a foreign image,
  // ask for the data, expect a throw) that we failed in the loudest direction,
  // by answering where a browser refuses.
  const securityError = (method, iface, why) => {
    const e = __pt_mkErr(globalThis.DOMException || Error, 
      "Failed to execute '" + method + "' on '" + iface + "': " + why, 'SecurityError');
    return e;
  };
  // Does drawing this taint the canvas? Same-origin content and anything the
  // server opened up with CORS does not; a foreign image without that
  // permission does. Another canvas passes on whatever state it carries.
  const taints = (src) => {
    if (!src) return false;
    try {
      const g = __pt_ctxImpl(src.__ptC2d || src.__ptGl1 || src.__ptGl2);
      if (g && typeof g.__ptTainted === 'function') return g.__ptTainted();
      const raw = String(src.currentSrc || src.src || '');
      if (!raw || __s_slice(raw, 0, 5) === 'data:' || __s_slice(raw, 0, 5) === 'blob:') return false;
      const u = new URL(raw, location.href);
      if (u.origin === location.origin) return false;
      const ok = globalThis.__pt_imageCorsOk && __pt_imageCorsOk(u.href);
      return !(src.crossOrigin && ok);
    } catch (e) { return false; }
  };

  // A wrong call is an answer too, and the browser's is precise: the challenge
  // calls `getImageData()` with no arguments and expects Chrome's TypeError
  // with its exact text.
  const needArgs = (got, want, method, iface) => {
    if (got >= want) return;
    throw __pt_mkErr(TypeError, "Failed to execute '" + method + "' on '" + iface + "': " +
      want + " argument" + (want === 1 ? '' : 's') + " required, but only " + got + " present.");
  };
  const sizeError = (method, why) => {
    const msg = "Failed to execute '" + method + "' on 'CanvasRenderingContext2D': " + why;
    return __pt_mkErr(globalThis.DOMException || Error, msg, 'IndexSizeError');
  };

  const make2DContext = (canvas, attrs) => {
    // The browser remembers the settings a context was requested with and
    // returns them, along with the pixel color space; a probe compares
    // requested vs received.
    const A = attrs && typeof attrs === 'object' ? attrs : {};
    const CS = A.colorSpace === 'display-p3' ? 'display-p3' : 'srgb';
    const CT = A.colorType === 'float16' ? 'float16' : 'unorm8';
    const WRF = !!A.willReadFrequently;
    const ALPHA = A.alpha === undefined ? true : !!A.alpha;
    const DESYNC = !!A.desynchronized;
    const S = makeSurface(canvas);
    // Marker for `drawImage` to find a canvas's pixels. Hidden like all of
    // ours, so the page cannot enumerate it.
    try { Object.defineProperty(canvas, '__ptSurf', { value: S, configurable: true }); } catch (e) {}
    // A uniform fill is remembered as the exact color: 8 bits per channel hold
    // neither values above one nor third-decimal differences, which
    // cross-space conversion produces. Any other drawing clears this, and
    // pixels are read from the surface as usual.
    let uniform = null;
    // Resizing a canvas resets the context: the browser restores the matrix,
    // colors, shadow, compositing, font and path to defaults and clears the
    // bitmap. Without it later drawing used the stale matrix.
    let lastW = canvas.width | 0, lastH = canvas.height | 0;
    const DEFAULTS = {
      fillStyle: '#000000', strokeStyle: '#000000', font: '10px sans-serif',
      globalAlpha: 1, globalCompositeOperation: 'source-over', filter: 'none',
      lineWidth: 1, lineCap: 'butt', lineJoin: 'miter', miterLimit: 10, lineDashOffset: 0,
      shadowBlur: 0, shadowColor: 'rgba(0, 0, 0, 0)', shadowOffsetX: 0, shadowOffsetY: 0,
      textAlign: 'start', textBaseline: 'alphabetic', direction: 'ltr', lang: 'inherit',
      letterSpacing: '0px', wordSpacing: '0px', fontKerning: 'auto', fontStretch: 'normal',
      fontVariantCaps: 'normal', textRendering: 'auto',
      imageSmoothingEnabled: true, imageSmoothingQuality: 'low',
    };
    const checkResize = () => {
      const w = canvas.width | 0, h = canvas.height | 0;
      if (w === lastW && h === lastH) return;
      lastW = w; lastH = h;
      M = [1, 0, 0, 1, 0, 0];
      __pt_write(mStack, 'length', 0);
      verbs = []; ops = []; sub = false; cx = 0; cy = 0;
      bx0 = by0 = bx1 = by1 = 0;
      uniform = null;
      tainted = false;
      for (const k of Object.keys(DEFAULTS)) impl[k] = DEFAULTS[k];
    };
    // A shadow is drawn when its color is non-transparent and there is blur or
    // offset, as in the browser. Descriptor: [blur, offsetX, offsetY, r, g, b,
    // a], in the same order as the engine's table.
    const GCO = ['source-over','source-in','source-out','source-atop','destination-over',
      'destination-in','destination-out','destination-atop','lighter','copy','xor','multiply',
      'screen','overlay','darken','lighten','color-dodge','color-burn','hard-light','soft-light',
      'difference','exclusion','hue','saturation','color','luminosity'];
    const modeOf = (ctx) => Math.max(0, __s_indexOf(GCO, String(ctx.globalCompositeOperation)));
    const shadowOf = function (ctx) {
      const col = parseColorRaw(ctx.shadowColor);
      if (!col || !col[3]) return null;
      // The matrix affects neither blur nor offset: shadows live in canvas
      // space, not page space (scaling them made blur at scale 0.384 three
      // times narrower than the browser's).
      const blur = Math.max(0, +ctx.shadowBlur || 0);
      const dx = (+ctx.shadowOffsetX || 0), dy = (+ctx.shadowOffsetY || 0);
      if (blur <= 0 && dx === 0 && dy === 0) return null;
      return [blur, dx, dy, col[0], col[1], col[2], col[3]];
    };
    const note = (m) => { checkResize(); uniform = null; S.note(m); };
    // The canvas calls this on resize: the reset must happen immediately, not
    // at the next draw, since the page reads state without drawing.
    try { Object.defineProperty(canvas, '__ptCtxResize', { value: checkResize, configurable: true }); } catch (e) {}
    const solid = S.solid, stamp = S.stamp;
    let bx0 = 0, by0 = 0, bx1 = 0, by1 = 0;     // current path bounding box
    let tainted = false;                        // shown something from elsewhere

    const pathPoint = (ux, uy) => {
      const x = tX(+ux || 0, +uy || 0), y = tY(+ux || 0, +uy || 0);
      if (bx1 <= bx0 && by1 <= by0) { bx0 = x; by0 = y; bx1 = x; by1 = y; }
      bx0 = Math.min(bx0, x); by0 = Math.min(by0, y); bx1 = Math.max(bx1, x); by1 = Math.max(by1, y);
    };
    const paintPath = () => { stamp(bx0 - 1, by0 - 1, (bx1 - bx0) + 2, (by1 - by0) + 2); };

    // Path verb stream (0,x,y=move · 1,x,y=line · 4=close) for the native
    // rasterizer: curves and arcs are tessellated to line segments here so the
    // Rust side stays a trivial, robust decoder. Built only when the surface is
    // native; the JS fallback keeps using the bounding-box stamp above.
    // Canvas matrix. Pages that scale the canvas and draw at large coordinates
    // (as every fingerprinter does) need `translate`/`scale`/`rotate` to
    // really move things. Path points are stored already transformed, as in
    // the browser: the matrix applies when a point is added, not when the
    // path is drawn.
    let M = [1, 0, 0, 1, 0, 0];
    const mStack = [];
    const tX = (x, y) => M[0] * x + M[2] * y + M[4];
    const tY = (x, y) => M[1] * x + M[3] * y + M[5];
    const tScale = () => Math.sqrt(Math.abs(M[0] * M[3] - M[1] * M[2])) || 1;
    const plain = () => M[0] === 1 && M[1] === 0 && M[2] === 0 && M[3] === 1 && M[4] === 0 && M[5] === 0;
    const mulM = (a, b, c, d, e, f) => {
      M = [
        M[0] * a + M[2] * b, M[1] * a + M[3] * b,
        M[0] * c + M[2] * d, M[1] * c + M[3] * d,
        M[0] * e + M[2] * f + M[4], M[1] * e + M[3] * f + M[5],
      ];
    };

    let verbs = [], cx = 0, cy = 0, sub = false;
    // Path ops as the canvas received them (page coordinates, before the
    // matrix): the engine builds the path from them per Blink's rules.
    let ops = [];
    // The current point is kept in page coordinates while transformed points
    // go to the list; otherwise curves would mix coordinate systems.
    const moveV = (x, y) => { x = +x || 0; y = +y || 0; verbs.push(0, tX(x, y), tY(x, y)); cx = x; cy = y; sub = true; };
    const lineV = (x, y) => { x = +x || 0; y = +y || 0; if (!sub) return moveV(x, y); verbs.push(1, tX(x, y), tY(x, y)); cx = x; cy = y; };
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
    // Families from `ctx.font`: everything after the size. The engine measures
    // and draws with real font files, so the whole list must be passed: the
    // browser walks it to the first one installed.
    // Style: bold and italic are separate font files with their own widths
    // (`bold 20px Times New Roman` measured as regular was 4% off).
    const fontBold = (f) => /(^|\s)(bold|bolder|[5-9]00)(\s|$)/i.test(String(f));
    const fontItalic = (f) => /(^|\s)(italic|oblique)(\s|$)/i.test(String(f));
    const fontFamily = (f) => {
      const t = String(f);
      const m = /(?:\d+(?:\.\d+)?)(?:px|pt|em|%)\s*(?:\/\s*\S+\s*)?(.*)$/.exec(t);
      return __s_trim(m ? m[1] : t);
    };
    // Stroke cap and join codes as in Skia: butt/round/square, miter/round/bevel.
    const capCode = (c) => c === 'round' ? 1 : c === 'square' ? 2 : 0;
    const joinCode = (j) => j === 'round' ? 1 : j === 'bevel' ? 2 : 0;
    const drawText = function (t, x, y, rgba, stroke, style) {
      const size = fontSize(this.font);
      // Text as in Chrome: Blink layout, Skia/Fontations glyphs, glyph-based
      // shadow. Strokes still use the old path (false).
      if (S.native && S.textOps) {
        const a = this.textAlign, b = this.textBaseline;
        const ai = a === 'center' ? 1 : (a === 'right' || a === 'end') ? 2 : 0;
        const bi = (b === 'top' || b === 'hanging') ? 1 : b === 'middle' ? 2 : (b === 'bottom' || b === 'ideographic') ? 3 : 0;
        const g = gradOf(style);
        if (S.textOps(t, +x || 0, +y || 0, M, size, fontFamily(this.font), fontBold(this.font), fontItalic(this.font),
            !!stroke, Math.max(0, +this.lineWidth || 1), g ? [0, 0, 0, 255] : rgba, g ? encodeGrad(g) : [], shadowOf(this), modeOf(this), ai, bi,
            capCode(this.lineCap), joinCode(this.lineJoin), +this.miterLimit || 10)) return;
      }
      const w = this.measureText(t).width;
      let ox = +x || 0, oy = +y || 0;
      const a = this.textAlign;                 // shift origin for align/baseline
      if (a === 'center') ox -= w / 2; else if (a === 'right' || a === 'end') ox -= w;
      const b = this.textBaseline;
      if (b === 'top' || b === 'hanging') oy += size * 0.8;
      else if (b === 'middle') oy += size * 0.3;
      else if (b === 'bottom' || b === 'ideographic') oy -= size * 0.2;
      // Text lives in transformed coordinates too, and the font size scales.
      // Skew and rotation are approximated with uniform scale: the engine
      // lays glyphs horizontally.
      if (S.native) {
        S.text(t, tX(ox, oy), tY(ox, oy), size * tScale(), rgba,
          fontFamily(this.font), fontBold(this.font), fontItalic(this.font), shadowOf(this));
      } else stamp(tX(ox, oy), tY(ox, oy) - size, w, size * 1.3);
    };

    // Gradient fillStyle/strokeStyle: real objects carrying coords + stops, flattened
    // to the [type,x0,y0,x1,y1,r0,r1,n,(pos,r,g,b,a)…] descriptor the native decoder
    // reads. A gradient object is detected by its `__ptGrad` marker.
    // Gradient state lives behind a WeakMap, not an own property: the
    // browser's `CanvasGradient` has zero own properties.
    const GRAD = new WeakMap();
    const makeGradient = (type, coords) => {
      const state = { type, coords, stops: [] };
      const add = (pos, color) => {
        // Chrome's checks in its order: number, range, then color.
        const head = "Failed to execute 'addColorStop' on 'CanvasGradient': ";
        const at = Number(pos);
        if (!Number.isFinite(at)) throw __pt_mkErr(TypeError, head + 'The provided double value is non-finite.');
        const cs = String(color);
        if (at < 0 || at > 1) throw __pt_mkErr(DOMException, head + 'The provided value (' + at + ') is outside the range (0.0, 1.0).', 'IndexSizeError');
        if (!parseColorRaw(cs)) throw __pt_mkErr(DOMException, head + "The value provided ('" + cs + "') could not be parsed as a color.", 'SyntaxError');
        note('stop|' + __ptJ(pos, color));
        if (globalThis.__pt_canvasTrace) ctrace(impl, 'gradient.addColorStop(' + cshow(pos) + ', ' + cshow(color) + ')');
        state.stops.push([+pos || 0, parseColor(color)]);
      };
      const g = globalThis.__pt_makeGradient ? __pt_makeGradient({ add }) : { addColorStop(pos, color) { add(pos, color); } };
      GRAD.set(g, state);
      return g;
    };
    const gradOf = (v) => (v && GRAD.get(v)) || null;
    const encodeGrad = (g) => {
      // Points and radii stay in user space: the engine puts the canvas
      // matrix into the shader pipeline itself (MatrixRec: ptsToUnit * CTM^-1),
      // like Skia; they must not be converted to canvas space up front.
      const c = g.coords;
      const co = [+c[0] || 0, +c[1] || 0, +c[2] || 0, +c[3] || 0, +c[4] || 0, +c[5] || 0];
      const a = [g.type, co[0], co[1], co[2], co[3], co[4], co[5], g.stops.length];
      for (let k = 0; k < g.stops.length; k++) { const s = g.stops[k]; a.push(s[0], s[1][0], s[1][1], s[1][2], s[1][3]); }
      return a;
    };
    // Rect corners go through the matrix too: rotated, it is no longer a
    // rectangle and the browser draws a rhombus.
    const rectVerbs = (x, y, w, h) => {
      const X = +x || 0, Y = +y || 0, W2 = +w || 0, H2 = +h || 0;
      const p = (px, py) => [tX(px, py), tY(px, py)];
      const a = p(X, Y), b = p(X + W2, Y), c = p(X + W2, Y + H2), d = p(X, Y + H2);
      return [0, a[0], a[1], 1, b[0], b[1], 1, c[0], c[1], 1, d[0], d[1], 4];
    };

    // A canvas without a document is offscreen and its context is a separate
    // interface: workers have no `CanvasRenderingContext2D` at all, only
    // OffscreenCanvasRenderingContext2D, as in the browser.
    const C2D = (canvas && canvas.ownerDocument && globalThis.CanvasRenderingContext2D)
      || globalThis.OffscreenCanvasRenderingContext2D
      || globalThis.CanvasRenderingContext2D;
    // An interface stub may have arrived without its name: set it, or the
    // context tags as [object Object].
    try {
      if (C2D && !Object.getOwnPropertyDescriptor(C2D.prototype, Symbol.toStringTag)) {
        Object.defineProperty(C2D.prototype, Symbol.toStringTag, { value: C2D.name, configurable: true });
      }
    } catch (e) {}
    // The implementation is a plain object, not an interface instance: the
    // page never sees it, and `Object.assign` into it would otherwise hit the
    // prototype accessors (which forward here) and loop.
    const impl = maskProto(Object.assign({}, {
      canvas,
      fillStyle: '#000000', strokeStyle: '#000000', font: '10px sans-serif',
      globalAlpha: 1.0, lineWidth: 1.0, textBaseline: 'alphabetic', textAlign: 'start',
      shadowColor: 'rgba(0, 0, 0, 0)', shadowBlur: 0, globalCompositeOperation: 'source-over',
      // The browser's canvas filter is the string `none`, not `undefined`
      // (the challenge frame reads it).
      filter: 'none',
      // Other context defaults, captured from Chrome 151.
      imageSmoothingEnabled: true, imageSmoothingQuality: 'low',
      letterSpacing: '0px', wordSpacing: '0px',
      fontKerning: 'auto', fontStretch: 'normal', fontVariantCaps: 'normal',
      textRendering: 'auto', direction: 'ltr', lang: 'inherit',
      miterLimit: 10, lineDashOffset: 0, lineCap: 'butt', lineJoin: 'miter',
      shadowOffsetX: 0, shadowOffsetY: 0,

      fillRect(x, y, w, h) {
        note('fillRect|' + __ptJ(x, y, w, h, this.fillStyle));
        const fs = this.fillStyle;
        const sh = shadowOf(this);
        const md = modeOf(this);
        // ValidateRectForCanvas + AdjustRectForCanvas (in double), then
        // drawRect: the SkScan::AntiFillRect route, not a path (op code 8).
        let X = +x, Y = +y, W2 = +w, H2 = +h;
        if (!(isFinite(X) && isFinite(Y) && isFinite(W2) && isFinite(H2))) return;
        if (W2 < 0) { W2 = -W2; X -= W2; }
        if (H2 < 0) { H2 = -H2; Y -= H2; }
        if (S.native && gradOf(fs)) S.fillOpsGradient([8, X, Y, W2, H2], M, false, encodeGrad(gradOf(fs)), sh, md);
        else if (S.native) S.fillOps([8, X, Y, W2, H2], M, false, parseColor(fs), sh, md);
        else solid(x, y, w, h, parseColor(fs));
        if (!gradOf(fs) && plain() && (+x || 0) <= 0 && (+y || 0) <= 0 &&
            (+w || 0) >= (canvas.width | 0) && (+h || 0) >= (canvas.height | 0)) {
          const c = parseColorFloat(fs);
          uniform = { rgb: convertSpace(c.rgb, c.space, CS), a: c.a };
        }
      },
      clearRect(x, y, w, h) {
        note('clearRect|' + __ptJ(x, y, w, h));
        solid(x, y, w, h, [0, 0, 0, 0]);
        if (plain() && (+x || 0) <= 0 && (+y || 0) <= 0 &&
            (+w || 0) >= (canvas.width | 0) && (+h || 0) >= (canvas.height | 0)) {
          uniform = { rgb: [0, 0, 0], a: 0 };
        }
      },
      strokeRect(x, y, w, h) {
        note('strokeRect|' + __ptJ(x, y, w, h, this.strokeStyle, this.lineWidth));
        const X = +x || 0, Y = +y || 0, W2 = +w || 0, H2 = +h || 0;
        if (S.native) {
          S.strokePath(rectVerbs(X, Y, W2, H2),
            Math.max(0, +this.lineWidth || 1) * tScale(), parseColor(this.strokeStyle),
            shadowOf(this), modeOf(this));
          return;
        }
        const lw = Math.max(1, this.lineWidth | 0);
        stamp(X, Y, W2, lw); stamp(X, Y + H2 - lw, W2, lw);
        stamp(X, Y, lw, H2); stamp(X + W2 - lw, Y, lw, H2);
      },
      fillText(t, x, y) { note('fillText|' + __ptJ(t, x, y, this.font, this.fillStyle, this.textAlign, this.textBaseline)); drawText.call(this, t, +x || 0, +y || 0, parseColor(this.fillStyle), false, this.fillStyle); },
      strokeText(t, x, y) { note('strokeText|' + __ptJ(t, x, y, this.font, this.strokeStyle)); drawText.call(this, t, +x || 0, +y || 0, parseColor(this.strokeStyle), true, this.strokeStyle); },

      beginPath() { note('beginPath'); bx0 = by0 = bx1 = by1 = 0; verbs = []; ops = []; sub = false; },
      closePath() { note('closePath'); closeV(); ops.push(4); },
      moveTo(x, y) { note('moveTo|' + __ptJ(x, y)); pathPoint(x, y); moveV(x, y); ops.push(0, +x, +y); },
      lineTo(x, y) { note('lineTo|' + __ptJ(x, y)); pathPoint(x, y); lineV(x, y); ops.push(1, +x, +y); },
      rect(x, y, w, h) {
        note('rect|' + __ptJ(x, y, w, h));
        const X = +x || 0, Y = +y || 0, W2 = +w || 0, H2 = +h || 0;
        pathPoint(X, Y); pathPoint(X + W2, Y + H2);
        moveV(X, Y); lineV(X + W2, Y); lineV(X + W2, Y + H2); lineV(X, Y + H2); closeV();
        ops.push(7, +x, +y, +w, +h);
      },
      arc(x, y, r, a0, a1, ccw) {
        note('arc|' + __ptJ(x, y, r, a0, a1, ccw));
        pathPoint((+x || 0) - (+r || 0), (+y || 0) - (+r || 0)); pathPoint((+x || 0) + (+r || 0), (+y || 0) + (+r || 0));
        arcV(x, y, r, +a0 || 0, a1 === undefined ? 2 * Math.PI : +a1, !!ccw);
        ops.push(5, +x, +y, +r, +a0, +a1, ccw ? 1 : 0);
      },
      arcTo(x1, y1, x2, y2) { note('arcTo|' + __ptJ(x1, y1, x2, y2)); pathPoint(x1, y1); pathPoint(x2, y2); lineV(x1, y1); lineV(x2, y2); ops.push(1, +x1, +y1, 1, +x2, +y2); },
      ellipse(x, y, rx, ry, rot, a0, a1, ccw) {
        needArgs(arguments.length, 7, 'ellipse', 'CanvasRenderingContext2D');
        note('ellipse|' + __ptJ(x, y, rx, ry));
        pathPoint((+x || 0) - (+rx || 0), (+y || 0) - (+ry || 0)); pathPoint((+x || 0) + (+rx || 0), (+y || 0) + (+ry || 0));
        // Approximate as a circle of radius rx then squash y — good enough, deterministic.
        const X = +x || 0, Y = +y || 0, RX = +rx || 0, RY = +ry || 0;
        const s0 = +a0 || 0, s1 = a1 === undefined ? 2 * Math.PI : +a1;
        let sweep = s1 - s0; if (!ccw && sweep < 0) sweep += 2 * Math.PI; if (ccw && sweep > 0) sweep -= 2 * Math.PI;
        const steps = Math.max(2, Math.ceil(Math.abs(sweep) / (Math.PI / 16)));
        for (let k = 0; k <= steps; k++) { const a = s0 + sweep * (k / steps);
          const px = X + RX * Math.cos(a), py = Y + RY * Math.sin(a);
          if (k === 0 && !sub) moveV(px, py); else lineV(px, py); }
        ops.push(6, +x, +y, +rx, +ry, +rot, +a0, +a1, ccw ? 1 : 0);
      },
      bezierCurveTo(a, b, c, d, e, f) { note('bezierCurveTo|' + __ptJ(a, b, c, d, e, f)); pathPoint(a, b); pathPoint(e, f); cubicV(+a || 0, +b || 0, +c || 0, +d || 0, +e || 0, +f || 0); ops.push(3, +a, +b, +c, +d, +e, +f); },
      quadraticCurveTo(a, b, c, d) { note('quadraticCurveTo|' + __ptJ(a, b, c, d)); pathPoint(a, b); pathPoint(c, d); quadV(+a || 0, +b || 0, +c || 0, +d || 0); ops.push(2, +a, +b, +c, +d); },
      fill(rule) {
        note('fill|' + __ptJ(this.fillStyle));
        if (!S.native) return paintPath();
        const fs = this.fillStyle;
        const sh = shadowOf(this);
        if (gradOf(fs)) S.fillOpsGradient(ops, M, String(rule) === 'evenodd', encodeGrad(gradOf(fs)), sh, modeOf(this));
        else S.fillOps(ops, M, String(rule) === 'evenodd', parseColor(fs), sh, modeOf(this));
      },
      stroke() {
        note('stroke|' + __ptJ(this.strokeStyle, this.lineWidth));
        if (S.native) {
          const ss = this.strokeStyle, g = gradOf(ss);
          if (!S.strokeOps(ops, M, Math.max(0, +this.lineWidth || 1), g ? [0, 0, 0, 255] : parseColor(ss), g ? encodeGrad(g) : [], shadowOf(this), modeOf(this), capCode(this.lineCap), joinCode(this.lineJoin), +this.miterLimit || 10)) {
            S.strokePath(verbs, Math.max(0, +this.lineWidth || 1) * tScale(),
              parseColor(ss), shadowOf(this), modeOf(this));
          }
        } else paintPath();
      },
      clip() { note('clip'); },

      save() {
        note('save');
        const t = CTX_IMPL.get(this) || this;
        const style = {};
        for (const k of SAVED) style[k] = t[k];
        mStack.push({ m: __s_slice(M), style });
      },
      restore() {
        note('restore');
        const top = mStack.pop();
        if (!top) return;
        M = top.m;
        const t = CTX_IMPL.get(this) || this;
        for (const k of SAVED) t[k] = top.style[k];
      },
      translate(x, y) { note('translate|' + __ptJ(x, y)); mulM(1, 0, 0, 1, +x || 0, +y || 0); },
      scale(x, y) { note('scale|' + __ptJ(x, y)); mulM(+x || 0, 0, 0, +y || 0, 0, 0); },
      rotate(a) {
        note('rotate|' + a);
        const r = +a || 0, c = Math.cos(r), n = Math.sin(r);
        mulM(c, n, -n, c, 0, 0);
      },
      setTransform(a, b, c, d, e, f) {
        note('setTransform|' + __ptRA(__ptJ, null, arguments));
        if (a && typeof a === 'object') {
          M = [+a.a || 0, +a.b || 0, +a.c || 0, +a.d || 0, +a.e || 0, +a.f || 0];
          return;
        }
        M = arguments.length ? [+a || 0, +b || 0, +c || 0, +d || 0, +e || 0, +f || 0] : [1, 0, 0, 1, 0, 0];
      },
      transform(a, b, c, d, e, f) {
        note('transform|' + __ptRA(__ptJ, null, arguments));
        mulM(+a || 0, +b || 0, +c || 0, +d || 0, +e || 0, +f || 0);
      },
      resetTransform() { note('resetTransform'); M = [1, 0, 0, 1, 0, 0]; },
      getTransform() {
        const D = globalThis.DOMMatrix;
        return D ? new D([M[0], M[1], M[2], M[3], M[4], M[5]])
          : { a: M[0], b: M[1], c: M[2], d: M[3], e: M[4], f: M[5] };
      },
      setLineDash(d) { note('setLineDash|' + (d && typeof d === 'object' ? __ptRA(__ptJ, null, d) : __ptJ(d))); }, getLineDash() { return []; },

      drawImage(img, a1, a2, a3, a4, a5, a6, a7, a8) {
        needArgs(arguments.length, 3, 'drawImage', 'CanvasRenderingContext2D');
        // Three forms: (img,dx,dy), (img,dx,dy,dw,dh) and a source crop
        // (img,sx,sy,sw,sh,dx,dy,dw,dh).
        const crop = arguments.length >= 9;
        const sx = crop ? +a1 || 0 : 0, sy = crop ? +a2 || 0 : 0;
        const sw = crop ? +a3 || 0 : 0, sh = crop ? +a4 || 0 : 0;
        const x = crop ? +a5 || 0 : +a1 || 0, y = crop ? +a6 || 0 : +a2 || 0;
        const w = crop ? +a7 || 0 : +a3 || 0, h = crop ? +a8 || 0 : +a4 || 0;
        // Only what the browser can draw is accepted; anything else is
        // refused with its long verbatim message.
        const drawable = img && (img.localName === 'img' || img.localName === 'canvas' ||
          img.localName === 'video' || img.__ptC2d || img.__ptGl1 || img.__ptGl2 ||
          typeof img.src === 'string' || img.__ptImageBitmap || img.__ptO || img.__ptSurf);
        if (!drawable) {
          throw __pt_mkErr(TypeError, "Failed to execute 'drawImage' on 'CanvasRenderingContext2D': " +
            "The provided value is not of type '(CSSImageValue or HTMLCanvasElement or " +
            "HTMLImageElement or HTMLVideoElement or ImageBitmap or OffscreenCanvas or " +
            "SVGImageElement or VideoFrame)'.");
        }
        note('drawImage|' + __ptJ(sx, sy, sw, sh, x, y, w, h, img && (img.src || img.localName)));
        if (taints(img)) tainted = true;
        // Real pixels first: a page that draws an image and reads the canvas
        // back must see the image (the challenge reads its beacon this way).
        // The stamp is a fallback when there is nothing to decode (foreign
        // format, `blob:`, another canvas).
        // Another canvas is drawn with its own pixels: `OffscreenCanvas` holds
        // a real element inside, `ImageBitmap` its own surface.
        const from = img && (img.__ptSurf
          || (img.__ptO && img.__ptO.c && img.__ptO.c.__ptSurf)
          || (img.__ptImageBitmap && img.__ptImageBitmap.surf));
        if (from && S.blit && S.blit(from.id(), sx, sy, sw, sh, x, y, w, h)) return;
        const src = img && (img.currentSrc || img.src);
        if (src && S.image && S.image(src, x, y, w, h)) return;
        stamp(x, y, w || (img && img.width) || 32, h || (img && img.height) || 32);
      },
      putImageData(data, x, y) {
        needArgs(arguments.length, 3, 'putImageData', 'CanvasRenderingContext2D');
        note('putImageData|' + __ptJ(x, y, data && data.width, data && data.height));
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
        // Metrics are measured by the engine from the real font file: font
        // enumeration by measuring text is the most common fingerprinting
        // method, so per-family metrics must differ as in the browser.
        const m = S.native
          ? S.width(t, size, fontFamily(this.font), fontBold(this.font), fontItalic(this.font))
          : null;
        // A `TextMetrics`, not a literal: the page reads the object's name.
        // The constructor computes the baselines.
        const mk = globalThis.__pt_makeMetrics || ((v) => v);
        if (!m) {
          const w = String(t).length * 6.7;
          return mk({ width: w, left: 0, right: w, ascent: size * 0.7, descent: size * 0.2,
                      fontAscent: size * 0.9, fontDescent: size * 0.2 });
        }
        return mk({ width: m[0], left: m[1], right: m[2], ascent: m[3], descent: m[4],
                    fontAscent: m[5], fontDescent: m[6] });
      },
      getImageData(x, y, w, h) {
        needArgs(arguments.length, 4, 'getImageData', 'CanvasRenderingContext2D');
        // The fifth arg is an ImageDataSettings dict; Chrome's binding checks it
        // before anything else: type, then enums alphabetically.
        if (arguments.length > 4) {
          const st = arguments[4];
          const head = "Failed to execute 'getImageData' on 'CanvasRenderingContext2D': ";
          if (st !== undefined && st !== null && typeof st !== 'object' && typeof st !== 'function') {
            throw __pt_mkErr(TypeError, head + "The provided value is not of type 'ImageDataSettings'.");
          }
          if (st) {
            for (const [k, T, ok] of [['colorSpace', 'PredefinedColorSpace', ['srgb', 'display-p3']],
                                      ['pixelFormat', 'ImageDataPixelFormat', ['rgba-unorm8', 'rgba-float16']]]) {
              const v = st[k];
              if (v === undefined) continue;
              const sv = String(v);
              if (__s_indexOf(ok, sv) < 0) throw __pt_mkErr(TypeError, head + "Failed to read the '" + k + "' property from 'ImageDataSettings': The provided value '" + sv + "' is not a valid enum value of type " + T + '.');
            }
          }
        }
        if (tainted) throw securityError('getImageData', 'CanvasRenderingContext2D',
          'The canvas has been tainted by cross-origin data.');
        w = w | 0; h = h | 0;
        // Negative width means a rectangle in the other direction, as in Chrome.
        if (w < 0) { x = (x | 0) + w; w = -w; }
        if (h < 0) { y = (y | 0) + h; h = -h; }
        if (w === 0) throw sizeError('getImageData', 'The source width is 0.');
        if (h === 0) throw sizeError('getImageData', 'The source height is 0.');
        const o = arguments.length > 4 ? arguments[4] : null;
        const want = (o && o.colorSpace === 'display-p3') ? 'display-p3'
          : ((o && o.colorSpace === 'srgb') ? 'srgb' : CS);
        const half = o && o.pixelFormat === 'rgba-float16' && globalThis.Float16Array;
        if (uniform) {
          // The canvas is a uniform color: the exact value is known, and
          // conversion to the requested space uses it rather than bytes.
          const v = convertSpace(uniform.rgb, CS, want);
          const n = Math.max(0, w * h * 4);
          if (half) {
            const f = new globalThis.Float16Array(n);
            for (let i = 0; i < n; i += 4) { f[i] = v[0]; f[i + 1] = v[1]; f[i + 2] = v[2]; f[i + 3] = uniform.a; }
            return makeImageData(f, w, h, want, 'rgba-float16');
          }
          const u = new Uint8ClampedArray(n);
          // The browser's rounding depends on the space (measured, not
          // derived): on an sRGB canvas 0.5 reads as 128, on display-p3 as 127,
          // while 0.25 gives 64 in both. So in p3 half rounds down, in sRGB up.
          const down = want === 'display-p3';
          const b8 = (t) => {
            const x = Math.max(0, Math.min(1, t)) * 255;
            return down ? Math.floor(x + 0.5 - 1e-9) : Math.round(x);
          };
          const al = b8(uniform.a);
          // The canvas stores translucent colors premultiplied, so they come
          // back changed: 136 at alpha 128 reads as 135. The fast path must
          // reproduce this too.
          const trip = (t) => {
            const c = b8(t);
            if (al >= 255 || al === 0) return al === 0 ? 0 : c;
            const pm = Math.floor((c * al + 127) / 255);
            return Math.min(255, Math.floor((pm * 255 + al / 2) / al));
          };
          for (let i = 0; i < n; i += 4) {
            u[i] = trip(v[0]); u[i + 1] = trip(v[1]); u[i + 2] = trip(v[2]); u[i + 3] = al;
          }
          return makeImageData(u, w, h, want, o && o.pixelFormat);
        }
        const out = S.read(x, y, w, h, new Uint8ClampedArray(Math.max(0, w * h * 4)));
        // Half precision: the browser returns the same pixels as fractions,
        // not bytes. A `colorType: float16` canvas expects exactly this read.
        if (want !== CS) {
          for (let i = 0; i < out.length; i += 4) {
            const v = convertSpace([out[i] / 255, out[i + 1] / 255, out[i + 2] / 255], CS, want);
            out[i] = Math.round(Math.max(0, Math.min(1, v[0])) * 255);
            out[i + 1] = Math.round(Math.max(0, Math.min(1, v[1])) * 255);
            out[i + 2] = Math.round(Math.max(0, Math.min(1, v[2])) * 255);
          }
        }
        if (half) {
          const f = new globalThis.Float16Array(out.length);
          for (let i = 0; i < out.length; i++) f[i] = out[i] / 255;
          return makeImageData(f, w, h, want, 'rgba-float16');
        }
        return makeImageData(out, w, h, want, o && o.pixelFormat);
      },
      createImageData(w, h) {
        needArgs(arguments.length, 1, 'createImageData', 'CanvasRenderingContext2D');
        // ImageData overload: an empty image of the same size and space.
        if (arguments.length === 1 && w !== null && typeof w === 'object') {
          const W = w.width | 0, H = w.height | 0;
          return makeImageData(new Uint8ClampedArray(Math.max(0, W * H * 4)), W, H, w.colorSpace || CS, w.pixelFormat);
        }
        // The browser drops the size sign: (-2, 3) is a 2x3 image.
        if (typeof w === 'number' && w < 0) w = -w;
        if (typeof h === 'number' && h < 0) h = -h;
        if ((w | 0) === 0) throw sizeError('createImageData', 'The source width is zero or not a number.');
        if (arguments.length > 1 && (h | 0) === 0) {
          throw sizeError('createImageData', 'The source height is zero or not a number.');
        }
        const o = arguments.length > 2 ? arguments[2] : null;
        const n = Math.max(0, (w | 0) * (h | 0) * 4);
        if (o && o.pixelFormat === 'rgba-float16' && globalThis.Float16Array) {
          return makeImageData(new globalThis.Float16Array(n), w | 0, h | 0,
            o.colorSpace || CS, 'rgba-float16');
        }
        return makeImageData(new Uint8ClampedArray(n), w | 0, h | 0,
          (o && o.colorSpace) || CS, o && o.pixelFormat);
      },
      createLinearGradient(x0, y0, x1, y1) { note('linearGradient|' + __ptJ(x0, y0, x1, y1)); return makeGradient(0, [+x0 || 0, +y0 || 0, +x1 || 0, +y1 || 0, 0, 0]); },
      createRadialGradient(x0, y0, r0, x1, y1, r1) { note('radialGradient|' + __ptJ(x0, y0, r0, x1, y1, r1)); return makeGradient(1, [+x0 || 0, +y0 || 0, +x1 || 0, +y1 || 0, +r0 || 0, +r1 || 0]); },
      createPattern(img, rep) {
        note('pattern|' + rep);
        return globalThis.__pt_makePattern ? __pt_makePattern({ img, repetition: rep }) : {};
      },
      // Conic gradient: the browser returns an object.
      createConicGradient(angle, x, y) {
        note('conicGradient|' + __ptJ(angle, x, y));
        return makeGradient(2, [+x || 0, +y || 0, 0, 0, +angle || 0, 0]);
      },
      getContextAttributes() {
        return { alpha: ALPHA, colorSpace: CS, colorType: CT, desynchronized: DESYNC,
          toneMapping: { mode: 'standard' }, willReadFrequently: WRF };
      },
      // Hidden (filtered) accessor the canvas element uses to encode itself.
      __ptPixels() { return S.pixels(); },
      __ptTainted() { return tainted; },
    }));
    return publishContext(impl, C2D, CTX2D_METHODS, CTX2D_ATTRS);
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
  // WebGL context shape captured from Chrome 148: constants, methods and
  // accessors all on the prototype, no own properties on the context.
  // Fingerprinters read WebGL most closely, and they walk the prototype.
  const GL1_CONSTS = 'DEPTH_BUFFER_BIT=256,STENCIL_BUFFER_BIT=1024,COLOR_BUFFER_BIT=16384,POINTS=0,LINES=1,LINE_LOOP=2,LINE_STRIP=3,TRIANGLES=4,TRIANGLE_STRIP=5,TRIANGLE_FAN=6,ZERO=0,ONE=1,SRC_COLOR=768,ONE_MINUS_SRC_COLOR=769,SRC_ALPHA=770,ONE_MINUS_SRC_ALPHA=771,DST_ALPHA=772,ONE_MINUS_DST_ALPHA=773,DST_COLOR=774,ONE_MINUS_DST_COLOR=775,SRC_ALPHA_SATURATE=776,FUNC_ADD=32774,BLEND_EQUATION=32777,BLEND_EQUATION_RGB=32777,BLEND_EQUATION_ALPHA=34877,FUNC_SUBTRACT=32778,FUNC_REVERSE_SUBTRACT=32779,BLEND_DST_RGB=32968,BLEND_SRC_RGB=32969,BLEND_DST_ALPHA=32970,BLEND_SRC_ALPHA=32971,CONSTANT_COLOR=32769,ONE_MINUS_CONSTANT_COLOR=32770,CONSTANT_ALPHA=32771,ONE_MINUS_CONSTANT_ALPHA=32772,BLEND_COLOR=32773,ARRAY_BUFFER=34962,ELEMENT_ARRAY_BUFFER=34963,ARRAY_BUFFER_BINDING=34964,ELEMENT_ARRAY_BUFFER_BINDING=34965,STREAM_DRAW=35040,STATIC_DRAW=35044,DYNAMIC_DRAW=35048,BUFFER_SIZE=34660,BUFFER_USAGE=34661,CURRENT_VERTEX_ATTRIB=34342,FRONT=1028,BACK=1029,FRONT_AND_BACK=1032,TEXTURE_2D=3553,CULL_FACE=2884,BLEND=3042,DITHER=3024,STENCIL_TEST=2960,DEPTH_TEST=2929,SCISSOR_TEST=3089,POLYGON_OFFSET_FILL=32823,SAMPLE_ALPHA_TO_COVERAGE=32926,SAMPLE_COVERAGE=32928,NO_ERROR=0,INVALID_ENUM=1280,INVALID_VALUE=1281,INVALID_OPERATION=1282,OUT_OF_MEMORY=1285,CW=2304,CCW=2305,LINE_WIDTH=2849,ALIASED_POINT_SIZE_RANGE=33901,ALIASED_LINE_WIDTH_RANGE=33902,CULL_FACE_MODE=2885,FRONT_FACE=2886,DEPTH_RANGE=2928,DEPTH_WRITEMASK=2930,DEPTH_CLEAR_VALUE=2931,DEPTH_FUNC=2932,STENCIL_CLEAR_VALUE=2961,STENCIL_FUNC=2962,STENCIL_FAIL=2964,STENCIL_PASS_DEPTH_FAIL=2965,STENCIL_PASS_DEPTH_PASS=2966,STENCIL_REF=2967,STENCIL_VALUE_MASK=2963,STENCIL_WRITEMASK=2968,STENCIL_BACK_FUNC=34816,STENCIL_BACK_FAIL=34817,STENCIL_BACK_PASS_DEPTH_FAIL=34818,STENCIL_BACK_PASS_DEPTH_PASS=34819,STENCIL_BACK_REF=36003,STENCIL_BACK_VALUE_MASK=36004,STENCIL_BACK_WRITEMASK=36005,VIEWPORT=2978,SCISSOR_BOX=3088,COLOR_CLEAR_VALUE=3106,COLOR_WRITEMASK=3107,UNPACK_ALIGNMENT=3317,PACK_ALIGNMENT=3333,MAX_TEXTURE_SIZE=3379,MAX_VIEWPORT_DIMS=3386,SUBPIXEL_BITS=3408,RED_BITS=3410,GREEN_BITS=3411,BLUE_BITS=3412,ALPHA_BITS=3413,DEPTH_BITS=3414,STENCIL_BITS=3415,POLYGON_OFFSET_UNITS=10752,POLYGON_OFFSET_FACTOR=32824,TEXTURE_BINDING_2D=32873,SAMPLE_BUFFERS=32936,SAMPLES=32937,SAMPLE_COVERAGE_VALUE=32938,SAMPLE_COVERAGE_INVERT=32939,COMPRESSED_TEXTURE_FORMATS=34467,DONT_CARE=4352,FASTEST=4353,NICEST=4354,GENERATE_MIPMAP_HINT=33170,BYTE=5120,UNSIGNED_BYTE=5121,SHORT=5122,UNSIGNED_SHORT=5123,INT=5124,UNSIGNED_INT=5125,FLOAT=5126,DEPTH_COMPONENT=6402,ALPHA=6406,RGB=6407,RGBA=6408,LUMINANCE=6409,LUMINANCE_ALPHA=6410,UNSIGNED_SHORT_4_4_4_4=32819,UNSIGNED_SHORT_5_5_5_1=32820,UNSIGNED_SHORT_5_6_5=33635,FRAGMENT_SHADER=35632,VERTEX_SHADER=35633,MAX_VERTEX_ATTRIBS=34921,MAX_VERTEX_UNIFORM_VECTORS=36347,MAX_VARYING_VECTORS=36348,MAX_COMBINED_TEXTURE_IMAGE_UNITS=35661,MAX_VERTEX_TEXTURE_IMAGE_UNITS=35660,MAX_TEXTURE_IMAGE_UNITS=34930,MAX_FRAGMENT_UNIFORM_VECTORS=36349,SHADER_TYPE=35663,DELETE_STATUS=35712,LINK_STATUS=35714,VALIDATE_STATUS=35715,ATTACHED_SHADERS=35717,ACTIVE_UNIFORMS=35718,ACTIVE_ATTRIBUTES=35721,SHADING_LANGUAGE_VERSION=35724,CURRENT_PROGRAM=35725,NEVER=512,LESS=513,EQUAL=514,LEQUAL=515,GREATER=516,NOTEQUAL=517,GEQUAL=518,ALWAYS=519,KEEP=7680,REPLACE=7681,INCR=7682,DECR=7683,INVERT=5386,INCR_WRAP=34055,DECR_WRAP=34056,VENDOR=7936,RENDERER=7937,VERSION=7938,NEAREST=9728,LINEAR=9729,NEAREST_MIPMAP_NEAREST=9984,LINEAR_MIPMAP_NEAREST=9985,NEAREST_MIPMAP_LINEAR=9986,LINEAR_MIPMAP_LINEAR=9987,TEXTURE_MAG_FILTER=10240,TEXTURE_MIN_FILTER=10241,TEXTURE_WRAP_S=10242,TEXTURE_WRAP_T=10243,TEXTURE=5890,TEXTURE_CUBE_MAP=34067,TEXTURE_BINDING_CUBE_MAP=34068,TEXTURE_CUBE_MAP_POSITIVE_X=34069,TEXTURE_CUBE_MAP_NEGATIVE_X=34070,TEXTURE_CUBE_MAP_POSITIVE_Y=34071,TEXTURE_CUBE_MAP_NEGATIVE_Y=34072,TEXTURE_CUBE_MAP_POSITIVE_Z=34073,TEXTURE_CUBE_MAP_NEGATIVE_Z=34074,MAX_CUBE_MAP_TEXTURE_SIZE=34076,TEXTURE0=33984,TEXTURE1=33985,TEXTURE2=33986,TEXTURE3=33987,TEXTURE4=33988,TEXTURE5=33989,TEXTURE6=33990,TEXTURE7=33991,TEXTURE8=33992,TEXTURE9=33993,TEXTURE10=33994,TEXTURE11=33995,TEXTURE12=33996,TEXTURE13=33997,TEXTURE14=33998,TEXTURE15=33999,TEXTURE16=34000,TEXTURE17=34001,TEXTURE18=34002,TEXTURE19=34003,TEXTURE20=34004,TEXTURE21=34005,TEXTURE22=34006,TEXTURE23=34007,TEXTURE24=34008,TEXTURE25=34009,TEXTURE26=34010,TEXTURE27=34011,TEXTURE28=34012,TEXTURE29=34013,TEXTURE30=34014,TEXTURE31=34015,ACTIVE_TEXTURE=34016,REPEAT=10497,CLAMP_TO_EDGE=33071,MIRRORED_REPEAT=33648,FLOAT_VEC2=35664,FLOAT_VEC3=35665,FLOAT_VEC4=35666,INT_VEC2=35667,INT_VEC3=35668,INT_VEC4=35669,BOOL=35670,BOOL_VEC2=35671,BOOL_VEC3=35672,BOOL_VEC4=35673,FLOAT_MAT2=35674,FLOAT_MAT3=35675,FLOAT_MAT4=35676,SAMPLER_2D=35678,SAMPLER_CUBE=35680,VERTEX_ATTRIB_ARRAY_ENABLED=34338,VERTEX_ATTRIB_ARRAY_SIZE=34339,VERTEX_ATTRIB_ARRAY_STRIDE=34340,VERTEX_ATTRIB_ARRAY_TYPE=34341,VERTEX_ATTRIB_ARRAY_NORMALIZED=34922,VERTEX_ATTRIB_ARRAY_POINTER=34373,VERTEX_ATTRIB_ARRAY_BUFFER_BINDING=34975,IMPLEMENTATION_COLOR_READ_TYPE=35738,IMPLEMENTATION_COLOR_READ_FORMAT=35739,COMPILE_STATUS=35713,LOW_FLOAT=36336,MEDIUM_FLOAT=36337,HIGH_FLOAT=36338,LOW_INT=36339,MEDIUM_INT=36340,HIGH_INT=36341,FRAMEBUFFER=36160,RENDERBUFFER=36161,RGBA4=32854,RGB5_A1=32855,RGB565=36194,DEPTH_COMPONENT16=33189,STENCIL_INDEX8=36168,DEPTH_STENCIL=34041,RENDERBUFFER_WIDTH=36162,RENDERBUFFER_HEIGHT=36163,RENDERBUFFER_INTERNAL_FORMAT=36164,RENDERBUFFER_RED_SIZE=36176,RENDERBUFFER_GREEN_SIZE=36177,RENDERBUFFER_BLUE_SIZE=36178,RENDERBUFFER_ALPHA_SIZE=36179,RENDERBUFFER_DEPTH_SIZE=36180,RENDERBUFFER_STENCIL_SIZE=36181,FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE=36048,FRAMEBUFFER_ATTACHMENT_OBJECT_NAME=36049,FRAMEBUFFER_ATTACHMENT_TEXTURE_LEVEL=36050,FRAMEBUFFER_ATTACHMENT_TEXTURE_CUBE_MAP_FACE=36051,COLOR_ATTACHMENT0=36064,DEPTH_ATTACHMENT=36096,STENCIL_ATTACHMENT=36128,DEPTH_STENCIL_ATTACHMENT=33306,NONE=0,FRAMEBUFFER_COMPLETE=36053,FRAMEBUFFER_INCOMPLETE_ATTACHMENT=36054,FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT=36055,FRAMEBUFFER_INCOMPLETE_DIMENSIONS=36057,FRAMEBUFFER_UNSUPPORTED=36061,FRAMEBUFFER_BINDING=36006,RENDERBUFFER_BINDING=36007,MAX_RENDERBUFFER_SIZE=34024,INVALID_FRAMEBUFFER_OPERATION=1286,UNPACK_FLIP_Y_WEBGL=37440,UNPACK_PREMULTIPLY_ALPHA_WEBGL=37441,CONTEXT_LOST_WEBGL=37442,UNPACK_COLORSPACE_CONVERSION_WEBGL=37443,BROWSER_DEFAULT_WEBGL=37444,RGB8=32849,RGBA8=32856';
  const GL1_METHODS = 'activeTexture,attachShader,bindAttribLocation,bindRenderbuffer,blendColor,blendEquation,blendEquationSeparate,blendFunc,blendFuncSeparate,bufferData,bufferSubData,checkFramebufferStatus,compileShader,compressedTexImage2D,compressedTexSubImage2D,copyTexImage2D,copyTexSubImage2D,createBuffer,createFramebuffer,createProgram,createRenderbuffer,createShader,createTexture,cullFace,deleteBuffer,deleteFramebuffer,deleteProgram,deleteRenderbuffer,deleteShader,deleteTexture,depthFunc,depthMask,depthRange,detachShader,disable,enable,finish,flush,framebufferRenderbuffer,framebufferTexture2D,frontFace,generateMipmap,getActiveAttrib,getActiveUniform,getAttachedShaders,getAttribLocation,getBufferParameter,getContextAttributes,getError,getExtension,getFramebufferAttachmentParameter,getParameter,getProgramInfoLog,getProgramParameter,getRenderbufferParameter,getShaderInfoLog,getShaderParameter,getShaderPrecisionFormat,getShaderSource,getSupportedExtensions,getTexParameter,getUniform,getUniformLocation,getVertexAttrib,getVertexAttribOffset,hint,isBuffer,isContextLost,isEnabled,isFramebuffer,isProgram,isRenderbuffer,isShader,isTexture,lineWidth,linkProgram,pixelStorei,polygonOffset,readPixels,renderbufferStorage,sampleCoverage,shaderSource,stencilFunc,stencilFuncSeparate,stencilMask,stencilMaskSeparate,stencilOp,stencilOpSeparate,texImage2D,texParameterf,texParameteri,texSubImage2D,useProgram,validateProgram,bindBuffer,bindFramebuffer,bindTexture,clear,clearColor,clearDepth,clearStencil,colorMask,disableVertexAttribArray,drawArrays,drawElements,enableVertexAttribArray,scissor,uniform1f,uniform1fv,uniform1i,uniform1iv,uniform2f,uniform2fv,uniform2i,uniform2iv,uniform3f,uniform3fv,uniform3i,uniform3iv,uniform4f,uniform4fv,uniform4i,uniform4iv,uniformMatrix2fv,uniformMatrix3fv,uniformMatrix4fv,vertexAttrib1f,vertexAttrib1fv,vertexAttrib2f,vertexAttrib2fv,vertexAttrib3f,vertexAttrib3fv,vertexAttrib4f,vertexAttrib4fv,vertexAttribPointer,viewport,drawingBufferStorage,makeXRCompatible';
  const GL2_CONSTS = 'DEPTH_BUFFER_BIT=256,STENCIL_BUFFER_BIT=1024,COLOR_BUFFER_BIT=16384,POINTS=0,LINES=1,LINE_LOOP=2,LINE_STRIP=3,TRIANGLES=4,TRIANGLE_STRIP=5,TRIANGLE_FAN=6,ZERO=0,ONE=1,SRC_COLOR=768,ONE_MINUS_SRC_COLOR=769,SRC_ALPHA=770,ONE_MINUS_SRC_ALPHA=771,DST_ALPHA=772,ONE_MINUS_DST_ALPHA=773,DST_COLOR=774,ONE_MINUS_DST_COLOR=775,SRC_ALPHA_SATURATE=776,FUNC_ADD=32774,BLEND_EQUATION=32777,BLEND_EQUATION_RGB=32777,BLEND_EQUATION_ALPHA=34877,FUNC_SUBTRACT=32778,FUNC_REVERSE_SUBTRACT=32779,BLEND_DST_RGB=32968,BLEND_SRC_RGB=32969,BLEND_DST_ALPHA=32970,BLEND_SRC_ALPHA=32971,CONSTANT_COLOR=32769,ONE_MINUS_CONSTANT_COLOR=32770,CONSTANT_ALPHA=32771,ONE_MINUS_CONSTANT_ALPHA=32772,BLEND_COLOR=32773,ARRAY_BUFFER=34962,ELEMENT_ARRAY_BUFFER=34963,ARRAY_BUFFER_BINDING=34964,ELEMENT_ARRAY_BUFFER_BINDING=34965,STREAM_DRAW=35040,STATIC_DRAW=35044,DYNAMIC_DRAW=35048,BUFFER_SIZE=34660,BUFFER_USAGE=34661,CURRENT_VERTEX_ATTRIB=34342,FRONT=1028,BACK=1029,FRONT_AND_BACK=1032,TEXTURE_2D=3553,CULL_FACE=2884,BLEND=3042,DITHER=3024,STENCIL_TEST=2960,DEPTH_TEST=2929,SCISSOR_TEST=3089,POLYGON_OFFSET_FILL=32823,SAMPLE_ALPHA_TO_COVERAGE=32926,SAMPLE_COVERAGE=32928,NO_ERROR=0,INVALID_ENUM=1280,INVALID_VALUE=1281,INVALID_OPERATION=1282,OUT_OF_MEMORY=1285,CW=2304,CCW=2305,LINE_WIDTH=2849,ALIASED_POINT_SIZE_RANGE=33901,ALIASED_LINE_WIDTH_RANGE=33902,CULL_FACE_MODE=2885,FRONT_FACE=2886,DEPTH_RANGE=2928,DEPTH_WRITEMASK=2930,DEPTH_CLEAR_VALUE=2931,DEPTH_FUNC=2932,STENCIL_CLEAR_VALUE=2961,STENCIL_FUNC=2962,STENCIL_FAIL=2964,STENCIL_PASS_DEPTH_FAIL=2965,STENCIL_PASS_DEPTH_PASS=2966,STENCIL_REF=2967,STENCIL_VALUE_MASK=2963,STENCIL_WRITEMASK=2968,STENCIL_BACK_FUNC=34816,STENCIL_BACK_FAIL=34817,STENCIL_BACK_PASS_DEPTH_FAIL=34818,STENCIL_BACK_PASS_DEPTH_PASS=34819,STENCIL_BACK_REF=36003,STENCIL_BACK_VALUE_MASK=36004,STENCIL_BACK_WRITEMASK=36005,VIEWPORT=2978,SCISSOR_BOX=3088,COLOR_CLEAR_VALUE=3106,COLOR_WRITEMASK=3107,UNPACK_ALIGNMENT=3317,PACK_ALIGNMENT=3333,MAX_TEXTURE_SIZE=3379,MAX_VIEWPORT_DIMS=3386,SUBPIXEL_BITS=3408,RED_BITS=3410,GREEN_BITS=3411,BLUE_BITS=3412,ALPHA_BITS=3413,DEPTH_BITS=3414,STENCIL_BITS=3415,POLYGON_OFFSET_UNITS=10752,POLYGON_OFFSET_FACTOR=32824,TEXTURE_BINDING_2D=32873,SAMPLE_BUFFERS=32936,SAMPLES=32937,SAMPLE_COVERAGE_VALUE=32938,SAMPLE_COVERAGE_INVERT=32939,COMPRESSED_TEXTURE_FORMATS=34467,DONT_CARE=4352,FASTEST=4353,NICEST=4354,GENERATE_MIPMAP_HINT=33170,BYTE=5120,UNSIGNED_BYTE=5121,SHORT=5122,UNSIGNED_SHORT=5123,INT=5124,UNSIGNED_INT=5125,FLOAT=5126,DEPTH_COMPONENT=6402,ALPHA=6406,RGB=6407,RGBA=6408,LUMINANCE=6409,LUMINANCE_ALPHA=6410,UNSIGNED_SHORT_4_4_4_4=32819,UNSIGNED_SHORT_5_5_5_1=32820,UNSIGNED_SHORT_5_6_5=33635,FRAGMENT_SHADER=35632,VERTEX_SHADER=35633,MAX_VERTEX_ATTRIBS=34921,MAX_VERTEX_UNIFORM_VECTORS=36347,MAX_VARYING_VECTORS=36348,MAX_COMBINED_TEXTURE_IMAGE_UNITS=35661,MAX_VERTEX_TEXTURE_IMAGE_UNITS=35660,MAX_TEXTURE_IMAGE_UNITS=34930,MAX_FRAGMENT_UNIFORM_VECTORS=36349,SHADER_TYPE=35663,DELETE_STATUS=35712,LINK_STATUS=35714,VALIDATE_STATUS=35715,ATTACHED_SHADERS=35717,ACTIVE_UNIFORMS=35718,ACTIVE_ATTRIBUTES=35721,SHADING_LANGUAGE_VERSION=35724,CURRENT_PROGRAM=35725,NEVER=512,LESS=513,EQUAL=514,LEQUAL=515,GREATER=516,NOTEQUAL=517,GEQUAL=518,ALWAYS=519,KEEP=7680,REPLACE=7681,INCR=7682,DECR=7683,INVERT=5386,INCR_WRAP=34055,DECR_WRAP=34056,VENDOR=7936,RENDERER=7937,VERSION=7938,NEAREST=9728,LINEAR=9729,NEAREST_MIPMAP_NEAREST=9984,LINEAR_MIPMAP_NEAREST=9985,NEAREST_MIPMAP_LINEAR=9986,LINEAR_MIPMAP_LINEAR=9987,TEXTURE_MAG_FILTER=10240,TEXTURE_MIN_FILTER=10241,TEXTURE_WRAP_S=10242,TEXTURE_WRAP_T=10243,TEXTURE=5890,TEXTURE_CUBE_MAP=34067,TEXTURE_BINDING_CUBE_MAP=34068,TEXTURE_CUBE_MAP_POSITIVE_X=34069,TEXTURE_CUBE_MAP_NEGATIVE_X=34070,TEXTURE_CUBE_MAP_POSITIVE_Y=34071,TEXTURE_CUBE_MAP_NEGATIVE_Y=34072,TEXTURE_CUBE_MAP_POSITIVE_Z=34073,TEXTURE_CUBE_MAP_NEGATIVE_Z=34074,MAX_CUBE_MAP_TEXTURE_SIZE=34076,TEXTURE0=33984,TEXTURE1=33985,TEXTURE2=33986,TEXTURE3=33987,TEXTURE4=33988,TEXTURE5=33989,TEXTURE6=33990,TEXTURE7=33991,TEXTURE8=33992,TEXTURE9=33993,TEXTURE10=33994,TEXTURE11=33995,TEXTURE12=33996,TEXTURE13=33997,TEXTURE14=33998,TEXTURE15=33999,TEXTURE16=34000,TEXTURE17=34001,TEXTURE18=34002,TEXTURE19=34003,TEXTURE20=34004,TEXTURE21=34005,TEXTURE22=34006,TEXTURE23=34007,TEXTURE24=34008,TEXTURE25=34009,TEXTURE26=34010,TEXTURE27=34011,TEXTURE28=34012,TEXTURE29=34013,TEXTURE30=34014,TEXTURE31=34015,ACTIVE_TEXTURE=34016,REPEAT=10497,CLAMP_TO_EDGE=33071,MIRRORED_REPEAT=33648,FLOAT_VEC2=35664,FLOAT_VEC3=35665,FLOAT_VEC4=35666,INT_VEC2=35667,INT_VEC3=35668,INT_VEC4=35669,BOOL=35670,BOOL_VEC2=35671,BOOL_VEC3=35672,BOOL_VEC4=35673,FLOAT_MAT2=35674,FLOAT_MAT3=35675,FLOAT_MAT4=35676,SAMPLER_2D=35678,SAMPLER_CUBE=35680,VERTEX_ATTRIB_ARRAY_ENABLED=34338,VERTEX_ATTRIB_ARRAY_SIZE=34339,VERTEX_ATTRIB_ARRAY_STRIDE=34340,VERTEX_ATTRIB_ARRAY_TYPE=34341,VERTEX_ATTRIB_ARRAY_NORMALIZED=34922,VERTEX_ATTRIB_ARRAY_POINTER=34373,VERTEX_ATTRIB_ARRAY_BUFFER_BINDING=34975,IMPLEMENTATION_COLOR_READ_TYPE=35738,IMPLEMENTATION_COLOR_READ_FORMAT=35739,COMPILE_STATUS=35713,LOW_FLOAT=36336,MEDIUM_FLOAT=36337,HIGH_FLOAT=36338,LOW_INT=36339,MEDIUM_INT=36340,HIGH_INT=36341,FRAMEBUFFER=36160,RENDERBUFFER=36161,RGBA4=32854,RGB5_A1=32855,RGB565=36194,DEPTH_COMPONENT16=33189,STENCIL_INDEX8=36168,DEPTH_STENCIL=34041,RENDERBUFFER_WIDTH=36162,RENDERBUFFER_HEIGHT=36163,RENDERBUFFER_INTERNAL_FORMAT=36164,RENDERBUFFER_RED_SIZE=36176,RENDERBUFFER_GREEN_SIZE=36177,RENDERBUFFER_BLUE_SIZE=36178,RENDERBUFFER_ALPHA_SIZE=36179,RENDERBUFFER_DEPTH_SIZE=36180,RENDERBUFFER_STENCIL_SIZE=36181,FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE=36048,FRAMEBUFFER_ATTACHMENT_OBJECT_NAME=36049,FRAMEBUFFER_ATTACHMENT_TEXTURE_LEVEL=36050,FRAMEBUFFER_ATTACHMENT_TEXTURE_CUBE_MAP_FACE=36051,COLOR_ATTACHMENT0=36064,DEPTH_ATTACHMENT=36096,STENCIL_ATTACHMENT=36128,DEPTH_STENCIL_ATTACHMENT=33306,NONE=0,FRAMEBUFFER_COMPLETE=36053,FRAMEBUFFER_INCOMPLETE_ATTACHMENT=36054,FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT=36055,FRAMEBUFFER_INCOMPLETE_DIMENSIONS=36057,FRAMEBUFFER_UNSUPPORTED=36061,FRAMEBUFFER_BINDING=36006,RENDERBUFFER_BINDING=36007,MAX_RENDERBUFFER_SIZE=34024,INVALID_FRAMEBUFFER_OPERATION=1286,UNPACK_FLIP_Y_WEBGL=37440,UNPACK_PREMULTIPLY_ALPHA_WEBGL=37441,CONTEXT_LOST_WEBGL=37442,UNPACK_COLORSPACE_CONVERSION_WEBGL=37443,BROWSER_DEFAULT_WEBGL=37444,READ_BUFFER=3074,UNPACK_ROW_LENGTH=3314,UNPACK_SKIP_ROWS=3315,UNPACK_SKIP_PIXELS=3316,PACK_ROW_LENGTH=3330,PACK_SKIP_ROWS=3331,PACK_SKIP_PIXELS=3332,COLOR=6144,DEPTH=6145,STENCIL=6146,RED=6403,RGB8=32849,RGBA8=32856,RGB10_A2=32857,TEXTURE_BINDING_3D=32874,UNPACK_SKIP_IMAGES=32877,UNPACK_IMAGE_HEIGHT=32878,TEXTURE_3D=32879,TEXTURE_WRAP_R=32882,MAX_3D_TEXTURE_SIZE=32883,UNSIGNED_INT_2_10_10_10_REV=33640,MAX_ELEMENTS_VERTICES=33000,MAX_ELEMENTS_INDICES=33001,TEXTURE_MIN_LOD=33082,TEXTURE_MAX_LOD=33083,TEXTURE_BASE_LEVEL=33084,TEXTURE_MAX_LEVEL=33085,MIN=32775,MAX=32776,DEPTH_COMPONENT24=33190,MAX_TEXTURE_LOD_BIAS=34045,TEXTURE_COMPARE_MODE=34892,TEXTURE_COMPARE_FUNC=34893,CURRENT_QUERY=34917,QUERY_RESULT=34918,QUERY_RESULT_AVAILABLE=34919,STREAM_READ=35041,STREAM_COPY=35042,STATIC_READ=35045,STATIC_COPY=35046,DYNAMIC_READ=35049,DYNAMIC_COPY=35050,MAX_DRAW_BUFFERS=34852,DRAW_BUFFER0=34853,DRAW_BUFFER1=34854,DRAW_BUFFER2=34855,DRAW_BUFFER3=34856,DRAW_BUFFER4=34857,DRAW_BUFFER5=34858,DRAW_BUFFER6=34859,DRAW_BUFFER7=34860,DRAW_BUFFER8=34861,DRAW_BUFFER9=34862,DRAW_BUFFER10=34863,DRAW_BUFFER11=34864,DRAW_BUFFER12=34865,DRAW_BUFFER13=34866,DRAW_BUFFER14=34867,DRAW_BUFFER15=34868,MAX_FRAGMENT_UNIFORM_COMPONENTS=35657,MAX_VERTEX_UNIFORM_COMPONENTS=35658,SAMPLER_3D=35679,SAMPLER_2D_SHADOW=35682,FRAGMENT_SHADER_DERIVATIVE_HINT=35723,PIXEL_PACK_BUFFER=35051,PIXEL_UNPACK_BUFFER=35052,PIXEL_PACK_BUFFER_BINDING=35053,PIXEL_UNPACK_BUFFER_BINDING=35055,FLOAT_MAT2x3=35685,FLOAT_MAT2x4=35686,FLOAT_MAT3x2=35687,FLOAT_MAT3x4=35688,FLOAT_MAT4x2=35689,FLOAT_MAT4x3=35690,SRGB=35904,SRGB8=35905,SRGB8_ALPHA8=35907,COMPARE_REF_TO_TEXTURE=34894,RGBA32F=34836,RGB32F=34837,RGBA16F=34842,RGB16F=34843,VERTEX_ATTRIB_ARRAY_INTEGER=35069,MAX_ARRAY_TEXTURE_LAYERS=35071,MIN_PROGRAM_TEXEL_OFFSET=35076,MAX_PROGRAM_TEXEL_OFFSET=35077,MAX_VARYING_COMPONENTS=35659,TEXTURE_2D_ARRAY=35866,TEXTURE_BINDING_2D_ARRAY=35869,R11F_G11F_B10F=35898,UNSIGNED_INT_10F_11F_11F_REV=35899,RGB9_E5=35901,UNSIGNED_INT_5_9_9_9_REV=35902,TRANSFORM_FEEDBACK_BUFFER_MODE=35967,MAX_TRANSFORM_FEEDBACK_SEPARATE_COMPONENTS=35968,TRANSFORM_FEEDBACK_VARYINGS=35971,TRANSFORM_FEEDBACK_BUFFER_START=35972,TRANSFORM_FEEDBACK_BUFFER_SIZE=35973,TRANSFORM_FEEDBACK_PRIMITIVES_WRITTEN=35976,RASTERIZER_DISCARD=35977,MAX_TRANSFORM_FEEDBACK_INTERLEAVED_COMPONENTS=35978,MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS=35979,INTERLEAVED_ATTRIBS=35980,SEPARATE_ATTRIBS=35981,TRANSFORM_FEEDBACK_BUFFER=35982,TRANSFORM_FEEDBACK_BUFFER_BINDING=35983,RGBA32UI=36208,RGB32UI=36209,RGBA16UI=36214,RGB16UI=36215,RGBA8UI=36220,RGB8UI=36221,RGBA32I=36226,RGB32I=36227,RGBA16I=36232,RGB16I=36233,RGBA8I=36238,RGB8I=36239,RED_INTEGER=36244,RGB_INTEGER=36248,RGBA_INTEGER=36249,SAMPLER_2D_ARRAY=36289,SAMPLER_2D_ARRAY_SHADOW=36292,SAMPLER_CUBE_SHADOW=36293,UNSIGNED_INT_VEC2=36294,UNSIGNED_INT_VEC3=36295,UNSIGNED_INT_VEC4=36296,INT_SAMPLER_2D=36298,INT_SAMPLER_3D=36299,INT_SAMPLER_CUBE=36300,INT_SAMPLER_2D_ARRAY=36303,UNSIGNED_INT_SAMPLER_2D=36306,UNSIGNED_INT_SAMPLER_3D=36307,UNSIGNED_INT_SAMPLER_CUBE=36308,UNSIGNED_INT_SAMPLER_2D_ARRAY=36311,DEPTH_COMPONENT32F=36012,DEPTH32F_STENCIL8=36013,FLOAT_32_UNSIGNED_INT_24_8_REV=36269,FRAMEBUFFER_ATTACHMENT_COLOR_ENCODING=33296,FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE=33297,FRAMEBUFFER_ATTACHMENT_RED_SIZE=33298,FRAMEBUFFER_ATTACHMENT_GREEN_SIZE=33299,FRAMEBUFFER_ATTACHMENT_BLUE_SIZE=33300,FRAMEBUFFER_ATTACHMENT_ALPHA_SIZE=33301,FRAMEBUFFER_ATTACHMENT_DEPTH_SIZE=33302,FRAMEBUFFER_ATTACHMENT_STENCIL_SIZE=33303,FRAMEBUFFER_DEFAULT=33304,UNSIGNED_INT_24_8=34042,DEPTH24_STENCIL8=35056,UNSIGNED_NORMALIZED=35863,DRAW_FRAMEBUFFER_BINDING=36006,READ_FRAMEBUFFER=36008,DRAW_FRAMEBUFFER=36009,READ_FRAMEBUFFER_BINDING=36010,RENDERBUFFER_SAMPLES=36011,FRAMEBUFFER_ATTACHMENT_TEXTURE_LAYER=36052,MAX_COLOR_ATTACHMENTS=36063,COLOR_ATTACHMENT1=36065,COLOR_ATTACHMENT2=36066,COLOR_ATTACHMENT3=36067,COLOR_ATTACHMENT4=36068,COLOR_ATTACHMENT5=36069,COLOR_ATTACHMENT6=36070,COLOR_ATTACHMENT7=36071,COLOR_ATTACHMENT8=36072,COLOR_ATTACHMENT9=36073,COLOR_ATTACHMENT10=36074,COLOR_ATTACHMENT11=36075,COLOR_ATTACHMENT12=36076,COLOR_ATTACHMENT13=36077,COLOR_ATTACHMENT14=36078,COLOR_ATTACHMENT15=36079,FRAMEBUFFER_INCOMPLETE_MULTISAMPLE=36182,MAX_SAMPLES=36183,HALF_FLOAT=5131,RG=33319,RG_INTEGER=33320,R8=33321,RG8=33323,R16F=33325,R32F=33326,RG16F=33327,RG32F=33328,R8I=33329,R8UI=33330,R16I=33331,R16UI=33332,R32I=33333,R32UI=33334,RG8I=33335,RG8UI=33336,RG16I=33337,RG16UI=33338,RG32I=33339,RG32UI=33340,VERTEX_ARRAY_BINDING=34229,R8_SNORM=36756,RG8_SNORM=36757,RGB8_SNORM=36758,RGBA8_SNORM=36759,SIGNED_NORMALIZED=36764,COPY_READ_BUFFER=36662,COPY_WRITE_BUFFER=36663,COPY_READ_BUFFER_BINDING=36662,COPY_WRITE_BUFFER_BINDING=36663,UNIFORM_BUFFER=35345,UNIFORM_BUFFER_BINDING=35368,UNIFORM_BUFFER_START=35369,UNIFORM_BUFFER_SIZE=35370,MAX_VERTEX_UNIFORM_BLOCKS=35371,MAX_FRAGMENT_UNIFORM_BLOCKS=35373,MAX_COMBINED_UNIFORM_BLOCKS=35374,MAX_UNIFORM_BUFFER_BINDINGS=35375,MAX_UNIFORM_BLOCK_SIZE=35376,MAX_COMBINED_VERTEX_UNIFORM_COMPONENTS=35377,MAX_COMBINED_FRAGMENT_UNIFORM_COMPONENTS=35379,UNIFORM_BUFFER_OFFSET_ALIGNMENT=35380,ACTIVE_UNIFORM_BLOCKS=35382,UNIFORM_TYPE=35383,UNIFORM_SIZE=35384,UNIFORM_BLOCK_INDEX=35386,UNIFORM_OFFSET=35387,UNIFORM_ARRAY_STRIDE=35388,UNIFORM_MATRIX_STRIDE=35389,UNIFORM_IS_ROW_MAJOR=35390,UNIFORM_BLOCK_BINDING=35391,UNIFORM_BLOCK_DATA_SIZE=35392,UNIFORM_BLOCK_ACTIVE_UNIFORMS=35394,UNIFORM_BLOCK_ACTIVE_UNIFORM_INDICES=35395,UNIFORM_BLOCK_REFERENCED_BY_VERTEX_SHADER=35396,UNIFORM_BLOCK_REFERENCED_BY_FRAGMENT_SHADER=35398,INVALID_INDEX=4294967295,MAX_VERTEX_OUTPUT_COMPONENTS=37154,MAX_FRAGMENT_INPUT_COMPONENTS=37157,MAX_SERVER_WAIT_TIMEOUT=37137,OBJECT_TYPE=37138,SYNC_CONDITION=37139,SYNC_STATUS=37140,SYNC_FLAGS=37141,SYNC_FENCE=37142,SYNC_GPU_COMMANDS_COMPLETE=37143,UNSIGNALED=37144,SIGNALED=37145,ALREADY_SIGNALED=37146,TIMEOUT_EXPIRED=37147,CONDITION_SATISFIED=37148,WAIT_FAILED=37149,SYNC_FLUSH_COMMANDS_BIT=1,VERTEX_ATTRIB_ARRAY_DIVISOR=35070,ANY_SAMPLES_PASSED=35887,ANY_SAMPLES_PASSED_CONSERVATIVE=36202,SAMPLER_BINDING=35097,RGB10_A2UI=36975,INT_2_10_10_10_REV=36255,TRANSFORM_FEEDBACK=36386,TRANSFORM_FEEDBACK_PAUSED=36387,TRANSFORM_FEEDBACK_ACTIVE=36388,TRANSFORM_FEEDBACK_BINDING=36389,TEXTURE_IMMUTABLE_FORMAT=37167,MAX_ELEMENT_INDEX=36203,TEXTURE_IMMUTABLE_LEVELS=33503,TIMEOUT_IGNORED=-1,MAX_CLIENT_WAIT_TIMEOUT_WEBGL=37447';
  const GL2_METHODS = 'activeTexture,attachShader,beginQuery,beginTransformFeedback,bindAttribLocation,bindBufferBase,bindBufferRange,bindRenderbuffer,bindSampler,bindTransformFeedback,bindVertexArray,blendColor,blendEquation,blendEquationSeparate,blendFunc,blendFuncSeparate,blitFramebuffer,bufferData,bufferSubData,checkFramebufferStatus,clientWaitSync,compileShader,compressedTexImage2D,compressedTexImage3D,compressedTexSubImage2D,compressedTexSubImage3D,copyBufferSubData,copyTexImage2D,copyTexSubImage2D,copyTexSubImage3D,createBuffer,createFramebuffer,createProgram,createQuery,createRenderbuffer,createSampler,createShader,createTexture,createTransformFeedback,createVertexArray,cullFace,deleteBuffer,deleteFramebuffer,deleteProgram,deleteQuery,deleteRenderbuffer,deleteSampler,deleteShader,deleteSync,deleteTexture,deleteTransformFeedback,deleteVertexArray,depthFunc,depthMask,depthRange,detachShader,disable,drawArraysInstanced,drawElementsInstanced,drawRangeElements,enable,endQuery,endTransformFeedback,fenceSync,finish,flush,framebufferRenderbuffer,framebufferTexture2D,framebufferTextureLayer,frontFace,generateMipmap,getActiveAttrib,getActiveUniform,getActiveUniformBlockName,getActiveUniformBlockParameter,getActiveUniforms,getAttachedShaders,getAttribLocation,getBufferParameter,getBufferSubData,getContextAttributes,getError,getExtension,getFragDataLocation,getFramebufferAttachmentParameter,getIndexedParameter,getInternalformatParameter,getParameter,getProgramInfoLog,getProgramParameter,getQuery,getQueryParameter,getRenderbufferParameter,getSamplerParameter,getShaderInfoLog,getShaderParameter,getShaderPrecisionFormat,getShaderSource,getSupportedExtensions,getSyncParameter,getTexParameter,getTransformFeedbackVarying,getUniform,getUniformBlockIndex,getUniformIndices,getUniformLocation,getVertexAttrib,getVertexAttribOffset,hint,invalidateFramebuffer,invalidateSubFramebuffer,isBuffer,isContextLost,isEnabled,isFramebuffer,isProgram,isQuery,isRenderbuffer,isSampler,isShader,isSync,isTexture,isTransformFeedback,isVertexArray,lineWidth,linkProgram,pauseTransformFeedback,pixelStorei,polygonOffset,readBuffer,readPixels,renderbufferStorage,renderbufferStorageMultisample,resumeTransformFeedback,sampleCoverage,samplerParameterf,samplerParameteri,shaderSource,stencilFunc,stencilFuncSeparate,stencilMask,stencilMaskSeparate,stencilOp,stencilOpSeparate,texImage2D,texImage3D,texParameterf,texParameteri,texStorage2D,texStorage3D,texSubImage2D,texSubImage3D,transformFeedbackVaryings,uniform1ui,uniform2ui,uniform3ui,uniform4ui,uniformBlockBinding,useProgram,validateProgram,vertexAttribDivisor,vertexAttribI4i,vertexAttribI4ui,vertexAttribIPointer,waitSync,bindBuffer,bindFramebuffer,bindTexture,clear,clearBufferfi,clearBufferfv,clearBufferiv,clearBufferuiv,clearColor,clearDepth,clearStencil,colorMask,disableVertexAttribArray,drawArrays,drawBuffers,drawElements,enableVertexAttribArray,scissor,uniform1f,uniform1fv,uniform1i,uniform1iv,uniform1uiv,uniform2f,uniform2fv,uniform2i,uniform2iv,uniform2uiv,uniform3f,uniform3fv,uniform3i,uniform3iv,uniform3uiv,uniform4f,uniform4fv,uniform4i,uniform4iv,uniform4uiv,uniformMatrix2fv,uniformMatrix2x3fv,uniformMatrix2x4fv,uniformMatrix3fv,uniformMatrix3x2fv,uniformMatrix3x4fv,uniformMatrix4fv,uniformMatrix4x2fv,uniformMatrix4x3fv,vertexAttrib1f,vertexAttrib1fv,vertexAttrib2f,vertexAttrib2fv,vertexAttrib3f,vertexAttrib3fv,vertexAttrib4f,vertexAttrib4fv,vertexAttribI4iv,vertexAttribI4uiv,vertexAttribPointer,viewport,drawingBufferStorage,makeXRCompatible';
  const GL_ATTRS = __s_split('canvas,drawingBufferWidth,drawingBufferHeight,drawingBufferColorSpace,unpackColorSpace,drawingBufferFormat', ',');
  // WebGL limits and formats captured from Chrome 148 on this machine (a real
  // GPU never reports zeros there). Our own strings (vendor, renderer,
  // versions) stay ours; the table only fills what was missing.
  const GL1_PARAMS = {2849:1,2884:false,2885:1029,2886:2305,2928:[0,1],2929:false,2930:true,2931:1,2932:513,2960:false,2961:0,2962:519,2963:4294967295,2964:7680,2965:7680,2966:7680,2967:0,2968:4294967295,2978:[0,0,300,150],3024:true,3042:false,3088:[0,0,300,150],3089:false,3106:[0,0,0,0],3107:[true,true,true,true],3317:4,3333:4,3379:16384,3386:[16384,16384],3408:4,3410:8,3411:8,3412:8,3413:8,3414:24,3415:0,7936:"WebKit",7937:"WebKit WebGL",7938:"WebGL 1.0 (OpenGL ES 2.0 Chromium)",10752:0,32773:[0,0,0,0],32777:32774,32823:false,32824:0,32926:false,32928:false,32936:1,32937:4,32938:1,32939:false,32968:0,32969:1,32970:0,32971:1,33170:4352,33901:[1,255],33902:[1,7.375],34016:33984,34024:16384,34076:16384,34467:[],34816:519,34817:7680,34818:7680,34819:7680,34877:32774,34921:16,34930:32,35660:32,35661:64,35724:"WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",35738:5121,35739:6408,36003:0,36004:4294967295,36005:4294967295,36347:1024,36348:32,36349:1024,37440:false,37441:false,37443:37444};
  const GL2_PARAMS = {2849:1,2884:false,2885:1029,2886:2305,2928:[0,1],2929:false,2930:true,2931:1,2932:513,2960:false,2961:0,2962:519,2963:4294967295,2964:7680,2965:7680,2966:7680,2967:0,2968:4294967295,2978:[0,0,300,150],3024:true,3042:false,3074:1029,3088:[0,0,300,150],3089:false,3106:[0,0,0,0],3107:[true,true,true,true],3314:0,3315:0,3316:0,3317:4,3330:0,3331:0,3332:0,3333:4,3379:16384,3386:[16384,16384],3408:4,3410:8,3411:8,3412:8,3413:8,3414:24,3415:0,7936:"WebKit",7937:"WebKit WebGL",7938:"WebGL 2.0 (OpenGL ES 3.0 Chromium)",10752:0,32773:[0,0,0,0],32777:32774,32823:false,32824:0,32877:0,32878:0,32883:2048,32926:false,32928:false,32936:1,32937:4,32938:1,32939:false,32968:0,32969:1,32970:0,32971:1,33000:3000,33001:3000,33170:4352,33901:[1,255],33902:[1,7.375],34016:33984,34024:16384,34045:15,34076:16384,34467:[],34816:519,34817:7680,34818:7680,34819:7680,34852:8,34853:1029,34854:1029,34855:1029,34856:1029,34857:1029,34858:1029,34859:1029,34860:1029,34877:32774,34921:16,34930:32,35071:2048,35076:-8,35077:7,35371:15,35373:15,35374:45,35375:72,35376:65536,35377:262144,35379:262144,35380:32,35657:4096,35658:4096,35659:128,35660:32,35661:64,35723:4352,35724:"WebGL GLSL ES 3.00 (OpenGL ES GLSL ES 3.0 Chromium)",35738:5121,35739:6408,35968:4,35977:false,35978:64,35979:4,36003:0,36004:4294967295,36005:4294967295,36063:8,36183:16,36203:4294967294,36347:1024,36348:32,36349:1024,36387:false,36388:false,37137:9223372034707292000,37154:128,37157:128,37440:false,37441:false,37443:37444,37447:0};
  // Shader type precision: range and significant bits.
  const GL_PRECISION = {"35633:36336":[127,127,23],"35633:36337":[127,127,23],"35633:36338":[127,127,23],"35633:36339":[31,30,0],"35633:36340":[31,30,0],"35633:36341":[31,30,0],"35632:36336":[127,127,23],"35632:36337":[127,127,23],"35632:36338":[127,127,23],"35632:36339":[31,30,0],"35632:36340":[31,30,0],"35632:36341":[31,30,0]};
  // Supported sample counts per internal renderbuffer format.
  const GL_FORMAT_SAMPLES = {32849:[16,8,4,2],32854:[16,8,4,2],32855:[16,8,4,2],32856:[16,8,4,2],32857:[16,8,4,2],33189:[16,8,4,2],33190:[16,8,4,2],33321:[16,8,4,2],33323:[16,8,4,2],33329:[],33330:[],33331:[],33332:[],33333:[],33334:[],33335:[],33336:[],33337:[],33338:[],33339:[],33340:[],35056:[16,8,4,2],35907:[16,8,4,2],36012:[16,8,4,2],36013:[16,8,4,2],36168:[16,8,4,2],36194:[16,8,4,2],36208:[],36214:[],36220:[],36226:[],36232:[],36238:[],36975:[]};
  const GL1_EXTS = ["ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_clip_control", "EXT_color_buffer_half_float", "EXT_depth_clamp", "EXT_disjoint_timer_query", "EXT_float_blend", "EXT_frag_depth", "EXT_polygon_offset_clamp", "EXT_texture_compression_bptc", "EXT_texture_compression_rgtc", "EXT_texture_filter_anisotropic", "EXT_sRGB", "KHR_parallel_shader_compile", "OES_element_index_uint", "OES_fbo_render_mipmap", "OES_standard_derivatives", "OES_texture_float", "OES_texture_float_linear", "OES_texture_half_float", "OES_texture_half_float_linear", "OES_vertex_array_object", "WEBGL_blend_func_extended", "WEBGL_color_buffer_float", "WEBGL_compressed_texture_astc", "WEBGL_compressed_texture_etc", "WEBGL_compressed_texture_etc1", "WEBGL_compressed_texture_s3tc", "WEBGL_compressed_texture_s3tc_srgb", "WEBGL_debug_renderer_info", "WEBGL_debug_shaders", "WEBGL_depth_texture", "WEBGL_draw_buffers", "WEBGL_lose_context", "WEBGL_multi_draw"];
  const GL2_EXTS = ["EXT_clip_control", "EXT_color_buffer_float", "EXT_color_buffer_half_float", "EXT_depth_clamp", "EXT_disjoint_timer_query_webgl2", "EXT_float_blend", "EXT_polygon_offset_clamp", "EXT_texture_compression_bptc", "EXT_texture_compression_rgtc", "EXT_texture_filter_anisotropic", "EXT_texture_norm16", "KHR_parallel_shader_compile", "NV_shader_noperspective_interpolation", "OES_draw_buffers_indexed", "OES_sample_variables", "OES_shader_multisample_interpolation", "OES_texture_float_linear", "WEBGL_blend_func_extended", "WEBGL_compressed_texture_astc", "WEBGL_compressed_texture_etc", "WEBGL_compressed_texture_etc1", "WEBGL_compressed_texture_s3tc", "WEBGL_compressed_texture_s3tc_srgb", "WEBGL_debug_renderer_info", "WEBGL_debug_shaders", "WEBGL_lose_context", "WEBGL_multi_draw", "WEBGL_stencil_texturing"];

  // WebGL extensions as Chrome 148 returns them: each has its own interface
  // and members, and `Object.prototype.toString` names it
  // (`[object EXTTextureFilterAnisotropic]`).
  const GL1_EXT_SHAPE = {"ANGLE_instanced_arrays":["ANGLEInstancedArrays","VERTEX_ATTRIB_ARRAY_DIVISOR_ANGLE,drawArraysInstancedANGLE,drawElementsInstancedANGLE,vertexAttribDivisorANGLE"],"EXT_blend_minmax":["EXTBlendMinMax","MIN_EXT,MAX_EXT"],"EXT_clip_control":["EXTClipControl","LOWER_LEFT_EXT,UPPER_LEFT_EXT,NEGATIVE_ONE_TO_ONE_EXT,ZERO_TO_ONE_EXT,CLIP_ORIGIN_EXT,CLIP_DEPTH_MODE_EXT,clipControlEXT"],"EXT_color_buffer_half_float":["EXTColorBufferHalfFloat","RGBA16F_EXT,RGB16F_EXT,FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE_EXT,UNSIGNED_NORMALIZED_EXT"],"EXT_depth_clamp":["EXTDepthClamp","DEPTH_CLAMP_EXT"],"EXT_disjoint_timer_query":["EXTDisjointTimerQuery","QUERY_COUNTER_BITS_EXT,CURRENT_QUERY_EXT,QUERY_RESULT_EXT,QUERY_RESULT_AVAILABLE_EXT,TIME_ELAPSED_EXT,TIMESTAMP_EXT,GPU_DISJOINT_EXT,beginQueryEXT,createQueryEXT,deleteQueryEXT,endQueryEXT,getQueryEXT,getQueryObjectEXT,isQueryEXT,queryCounterEXT"],"EXT_float_blend":["EXTFloatBlend",""],"EXT_frag_depth":["EXTFragDepth",""],"EXT_polygon_offset_clamp":["EXTPolygonOffsetClamp","POLYGON_OFFSET_CLAMP_EXT,polygonOffsetClampEXT"],"EXT_texture_compression_bptc":["EXTTextureCompressionBPTC","COMPRESSED_RGBA_BPTC_UNORM_EXT,COMPRESSED_SRGB_ALPHA_BPTC_UNORM_EXT,COMPRESSED_RGB_BPTC_SIGNED_FLOAT_EXT,COMPRESSED_RGB_BPTC_UNSIGNED_FLOAT_EXT"],"EXT_texture_compression_rgtc":["EXTTextureCompressionRGTC","COMPRESSED_RED_RGTC1_EXT,COMPRESSED_SIGNED_RED_RGTC1_EXT,COMPRESSED_RED_GREEN_RGTC2_EXT,COMPRESSED_SIGNED_RED_GREEN_RGTC2_EXT"],"EXT_texture_filter_anisotropic":["EXTTextureFilterAnisotropic","TEXTURE_MAX_ANISOTROPY_EXT,MAX_TEXTURE_MAX_ANISOTROPY_EXT"],"EXT_sRGB":["EXTsRGB","SRGB_EXT,SRGB_ALPHA_EXT,SRGB8_ALPHA8_EXT,FRAMEBUFFER_ATTACHMENT_COLOR_ENCODING_EXT"],"KHR_parallel_shader_compile":["KHRParallelShaderCompile","COMPLETION_STATUS_KHR"],"OES_element_index_uint":["OESElementIndexUint",""],"OES_fbo_render_mipmap":["OESFboRenderMipmap",""],"OES_standard_derivatives":["OESStandardDerivatives","FRAGMENT_SHADER_DERIVATIVE_HINT_OES"],"OES_texture_float":["OESTextureFloat",""],"OES_texture_float_linear":["OESTextureFloatLinear",""],"OES_texture_half_float":["OESTextureHalfFloat","HALF_FLOAT_OES"],"OES_texture_half_float_linear":["OESTextureHalfFloatLinear",""],"OES_vertex_array_object":["OESVertexArrayObject","VERTEX_ARRAY_BINDING_OES,bindVertexArrayOES,createVertexArrayOES,deleteVertexArrayOES,isVertexArrayOES"],"WEBGL_blend_func_extended":["WebGLBlendFuncExtended","SRC1_COLOR_WEBGL,SRC1_ALPHA_WEBGL,ONE_MINUS_SRC1_COLOR_WEBGL,ONE_MINUS_SRC1_ALPHA_WEBGL,MAX_DUAL_SOURCE_DRAW_BUFFERS_WEBGL"],"WEBGL_color_buffer_float":["WebGLColorBufferFloat","RGBA32F_EXT,FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE_EXT,UNSIGNED_NORMALIZED_EXT"],"WEBGL_compressed_texture_astc":["WebGLCompressedTextureASTC","COMPRESSED_RGBA_ASTC_4x4_KHR,COMPRESSED_RGBA_ASTC_5x4_KHR,COMPRESSED_RGBA_ASTC_5x5_KHR,COMPRESSED_RGBA_ASTC_6x5_KHR,COMPRESSED_RGBA_ASTC_6x6_KHR,COMPRESSED_RGBA_ASTC_8x5_KHR,COMPRESSED_RGBA_ASTC_8x6_KHR,COMPRESSED_RGBA_ASTC_8x8_KHR,COMPRESSED_RGBA_ASTC_10x5_KHR,COMPRESSED_RGBA_ASTC_10x6_KHR,COMPRESSED_RGBA_ASTC_10x8_KHR,COMPRESSED_RGBA_ASTC_10x10_KHR,COMPRESSED_RGBA_ASTC_12x10_KHR,COMPRESSED_RGBA_ASTC_12x12_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_4x4_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_5x4_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_5x5_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_6x5_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_6x6_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_8x5_KHR"],"WEBGL_compressed_texture_etc":["WebGLCompressedTextureETC","COMPRESSED_R11_EAC,COMPRESSED_SIGNED_R11_EAC,COMPRESSED_RG11_EAC,COMPRESSED_SIGNED_RG11_EAC,COMPRESSED_RGB8_ETC2,COMPRESSED_SRGB8_ETC2,COMPRESSED_RGB8_PUNCHTHROUGH_ALPHA1_ETC2,COMPRESSED_SRGB8_PUNCHTHROUGH_ALPHA1_ETC2,COMPRESSED_RGBA8_ETC2_EAC,COMPRESSED_SRGB8_ALPHA8_ETC2_EAC"],"WEBGL_compressed_texture_etc1":["WebGLCompressedTextureETC1","COMPRESSED_RGB_ETC1_WEBGL"],"WEBGL_compressed_texture_s3tc":["WebGLCompressedTextureS3TC","COMPRESSED_RGB_S3TC_DXT1_EXT,COMPRESSED_RGBA_S3TC_DXT1_EXT,COMPRESSED_RGBA_S3TC_DXT3_EXT,COMPRESSED_RGBA_S3TC_DXT5_EXT"],"WEBGL_compressed_texture_s3tc_srgb":["WebGLCompressedTextureS3TCsRGB","COMPRESSED_SRGB_S3TC_DXT1_EXT,COMPRESSED_SRGB_ALPHA_S3TC_DXT1_EXT,COMPRESSED_SRGB_ALPHA_S3TC_DXT3_EXT,COMPRESSED_SRGB_ALPHA_S3TC_DXT5_EXT"],"WEBGL_debug_renderer_info":["WebGLDebugRendererInfo","UNMASKED_VENDOR_WEBGL,UNMASKED_RENDERER_WEBGL"],"WEBGL_debug_shaders":["WebGLDebugShaders","getTranslatedShaderSource"],"WEBGL_depth_texture":["WebGLDepthTexture","UNSIGNED_INT_24_8_WEBGL"],"WEBGL_draw_buffers":["WebGLDrawBuffers","COLOR_ATTACHMENT0_WEBGL,COLOR_ATTACHMENT1_WEBGL,COLOR_ATTACHMENT2_WEBGL,COLOR_ATTACHMENT3_WEBGL,COLOR_ATTACHMENT4_WEBGL,COLOR_ATTACHMENT5_WEBGL,COLOR_ATTACHMENT6_WEBGL,COLOR_ATTACHMENT7_WEBGL,COLOR_ATTACHMENT8_WEBGL,COLOR_ATTACHMENT9_WEBGL,COLOR_ATTACHMENT10_WEBGL,COLOR_ATTACHMENT11_WEBGL,COLOR_ATTACHMENT12_WEBGL,COLOR_ATTACHMENT13_WEBGL,COLOR_ATTACHMENT14_WEBGL,COLOR_ATTACHMENT15_WEBGL,DRAW_BUFFER0_WEBGL,DRAW_BUFFER1_WEBGL,DRAW_BUFFER2_WEBGL,DRAW_BUFFER3_WEBGL"],"WEBGL_lose_context":["WebGLLoseContext","loseContext,restoreContext"],"WEBGL_multi_draw":["WebGLMultiDraw","multiDrawArraysInstancedWEBGL,multiDrawArraysWEBGL,multiDrawElementsInstancedWEBGL,multiDrawElementsWEBGL"]};
  const GL2_EXT_SHAPE = {"EXT_clip_control":["EXTClipControl","LOWER_LEFT_EXT,UPPER_LEFT_EXT,NEGATIVE_ONE_TO_ONE_EXT,ZERO_TO_ONE_EXT,CLIP_ORIGIN_EXT,CLIP_DEPTH_MODE_EXT,clipControlEXT"],"EXT_color_buffer_float":["EXTColorBufferFloat",""],"EXT_color_buffer_half_float":["EXTColorBufferHalfFloat","RGBA16F_EXT,RGB16F_EXT,FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE_EXT,UNSIGNED_NORMALIZED_EXT"],"EXT_depth_clamp":["EXTDepthClamp","DEPTH_CLAMP_EXT"],"EXT_disjoint_timer_query_webgl2":["EXTDisjointTimerQueryWebGL2","QUERY_COUNTER_BITS_EXT,TIME_ELAPSED_EXT,TIMESTAMP_EXT,GPU_DISJOINT_EXT,queryCounterEXT"],"EXT_float_blend":["EXTFloatBlend",""],"EXT_polygon_offset_clamp":["EXTPolygonOffsetClamp","POLYGON_OFFSET_CLAMP_EXT,polygonOffsetClampEXT"],"EXT_texture_compression_bptc":["EXTTextureCompressionBPTC","COMPRESSED_RGBA_BPTC_UNORM_EXT,COMPRESSED_SRGB_ALPHA_BPTC_UNORM_EXT,COMPRESSED_RGB_BPTC_SIGNED_FLOAT_EXT,COMPRESSED_RGB_BPTC_UNSIGNED_FLOAT_EXT"],"EXT_texture_compression_rgtc":["EXTTextureCompressionRGTC","COMPRESSED_RED_RGTC1_EXT,COMPRESSED_SIGNED_RED_RGTC1_EXT,COMPRESSED_RED_GREEN_RGTC2_EXT,COMPRESSED_SIGNED_RED_GREEN_RGTC2_EXT"],"EXT_texture_filter_anisotropic":["EXTTextureFilterAnisotropic","TEXTURE_MAX_ANISOTROPY_EXT,MAX_TEXTURE_MAX_ANISOTROPY_EXT"],"EXT_texture_norm16":["EXTTextureNorm16","R16_EXT,RG16_EXT,RGB16_EXT,RGBA16_EXT,R16_SNORM_EXT,RG16_SNORM_EXT,RGB16_SNORM_EXT,RGBA16_SNORM_EXT"],"KHR_parallel_shader_compile":["KHRParallelShaderCompile","COMPLETION_STATUS_KHR"],"NV_shader_noperspective_interpolation":["NVShaderNoperspectiveInterpolation",""],"OES_draw_buffers_indexed":["OESDrawBuffersIndexed","blendEquationSeparateiOES,blendEquationiOES,blendFuncSeparateiOES,blendFunciOES,colorMaskiOES,disableiOES,enableiOES"],"OES_sample_variables":["OESSampleVariables",""],"OES_shader_multisample_interpolation":["OESShaderMultisampleInterpolation","MIN_FRAGMENT_INTERPOLATION_OFFSET_OES,MAX_FRAGMENT_INTERPOLATION_OFFSET_OES,FRAGMENT_INTERPOLATION_OFFSET_BITS_OES"],"OES_texture_float_linear":["OESTextureFloatLinear",""],"WEBGL_blend_func_extended":["WebGLBlendFuncExtended","SRC1_COLOR_WEBGL,SRC1_ALPHA_WEBGL,ONE_MINUS_SRC1_COLOR_WEBGL,ONE_MINUS_SRC1_ALPHA_WEBGL,MAX_DUAL_SOURCE_DRAW_BUFFERS_WEBGL"],"WEBGL_compressed_texture_astc":["WebGLCompressedTextureASTC","COMPRESSED_RGBA_ASTC_4x4_KHR,COMPRESSED_RGBA_ASTC_5x4_KHR,COMPRESSED_RGBA_ASTC_5x5_KHR,COMPRESSED_RGBA_ASTC_6x5_KHR,COMPRESSED_RGBA_ASTC_6x6_KHR,COMPRESSED_RGBA_ASTC_8x5_KHR,COMPRESSED_RGBA_ASTC_8x6_KHR,COMPRESSED_RGBA_ASTC_8x8_KHR,COMPRESSED_RGBA_ASTC_10x5_KHR,COMPRESSED_RGBA_ASTC_10x6_KHR,COMPRESSED_RGBA_ASTC_10x8_KHR,COMPRESSED_RGBA_ASTC_10x10_KHR,COMPRESSED_RGBA_ASTC_12x10_KHR,COMPRESSED_RGBA_ASTC_12x12_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_4x4_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_5x4_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_5x5_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_6x5_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_6x6_KHR,COMPRESSED_SRGB8_ALPHA8_ASTC_8x5_KHR"],"WEBGL_compressed_texture_etc":["WebGLCompressedTextureETC","COMPRESSED_R11_EAC,COMPRESSED_SIGNED_R11_EAC,COMPRESSED_RG11_EAC,COMPRESSED_SIGNED_RG11_EAC,COMPRESSED_RGB8_ETC2,COMPRESSED_SRGB8_ETC2,COMPRESSED_RGB8_PUNCHTHROUGH_ALPHA1_ETC2,COMPRESSED_SRGB8_PUNCHTHROUGH_ALPHA1_ETC2,COMPRESSED_RGBA8_ETC2_EAC,COMPRESSED_SRGB8_ALPHA8_ETC2_EAC"],"WEBGL_compressed_texture_etc1":["WebGLCompressedTextureETC1","COMPRESSED_RGB_ETC1_WEBGL"],"WEBGL_compressed_texture_s3tc":["WebGLCompressedTextureS3TC","COMPRESSED_RGB_S3TC_DXT1_EXT,COMPRESSED_RGBA_S3TC_DXT1_EXT,COMPRESSED_RGBA_S3TC_DXT3_EXT,COMPRESSED_RGBA_S3TC_DXT5_EXT"],"WEBGL_compressed_texture_s3tc_srgb":["WebGLCompressedTextureS3TCsRGB","COMPRESSED_SRGB_S3TC_DXT1_EXT,COMPRESSED_SRGB_ALPHA_S3TC_DXT1_EXT,COMPRESSED_SRGB_ALPHA_S3TC_DXT3_EXT,COMPRESSED_SRGB_ALPHA_S3TC_DXT5_EXT"],"WEBGL_debug_renderer_info":["WebGLDebugRendererInfo","UNMASKED_VENDOR_WEBGL,UNMASKED_RENDERER_WEBGL"],"WEBGL_debug_shaders":["WebGLDebugShaders","getTranslatedShaderSource"],"WEBGL_lose_context":["WebGLLoseContext","loseContext,restoreContext"],"WEBGL_multi_draw":["WebGLMultiDraw","multiDrawArraysInstancedWEBGL,multiDrawArraysWEBGL,multiDrawElementsInstancedWEBGL,multiDrawElementsWEBGL"],"WEBGL_stencil_texturing":["WebGLStencilTexturing","DEPTH_STENCIL_TEXTURE_MODE_WEBGL,STENCIL_INDEX_WEBGL"]};
  const GL1_SUPPORTED = ["ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_clip_control", "EXT_color_buffer_half_float", "EXT_depth_clamp", "EXT_disjoint_timer_query", "EXT_float_blend", "EXT_frag_depth", "EXT_polygon_offset_clamp", "EXT_texture_compression_bptc", "EXT_texture_compression_rgtc", "EXT_texture_filter_anisotropic", "EXT_sRGB", "KHR_parallel_shader_compile", "OES_element_index_uint", "OES_fbo_render_mipmap", "OES_standard_derivatives", "OES_texture_float", "OES_texture_float_linear", "OES_texture_half_float", "OES_texture_half_float_linear", "OES_vertex_array_object", "WEBGL_blend_func_extended", "WEBGL_color_buffer_float", "WEBGL_compressed_texture_astc", "WEBGL_compressed_texture_etc", "WEBGL_compressed_texture_etc1", "WEBGL_compressed_texture_s3tc", "WEBGL_compressed_texture_s3tc_srgb", "WEBGL_debug_renderer_info", "WEBGL_debug_shaders", "WEBGL_depth_texture", "WEBGL_draw_buffers", "WEBGL_lose_context", "WEBGL_multi_draw"];
  const GL2_SUPPORTED = ["EXT_clip_control", "EXT_color_buffer_float", "EXT_color_buffer_half_float", "EXT_depth_clamp", "EXT_disjoint_timer_query_webgl2", "EXT_float_blend", "EXT_polygon_offset_clamp", "EXT_texture_compression_bptc", "EXT_texture_compression_rgtc", "EXT_texture_filter_anisotropic", "EXT_texture_norm16", "KHR_parallel_shader_compile", "NV_shader_noperspective_interpolation", "OES_draw_buffers_indexed", "OES_sample_variables", "OES_shader_multisample_interpolation", "OES_texture_float_linear", "WEBGL_blend_func_extended", "WEBGL_compressed_texture_astc", "WEBGL_compressed_texture_etc", "WEBGL_compressed_texture_etc1", "WEBGL_compressed_texture_s3tc", "WEBGL_compressed_texture_s3tc_srgb", "WEBGL_debug_renderer_info", "WEBGL_debug_shaders", "WEBGL_lose_context", "WEBGL_multi_draw", "WEBGL_stencil_texturing"];

  // Extension constants whose values matter; for the rest presence is enough.
  // Ranges and points are floats, the compressed format list unsigned.
  const GL_F32 = [2928, 3106, 32824, 33901, 33902, 2849, 32777];
  const GL_U32 = [34467];
  // Parameters that exist only with an extension: the browser returns `null`
  // until the page requests the extension via `getExtension`. A real Chrome
  // never names the GPU to someone who did not ask for
  // `WEBGL_debug_renderer_info`.
  const EXT_PARAMS = {
    34047: [16, 'EXT_texture_filter_anisotropic'],
    // In WebGL2 the derivative hint is a regular parameter; only version 1
    // needs the extension.
    35723: [4352, 'OES_standard_derivatives', 1],
    36795: [false, 'EXT_disjoint_timer_query'],
    37445: [null, 'WEBGL_debug_renderer_info'],
    37446: [null, 'WEBGL_debug_renderer_info'],
  };

  const EXT_VALUES = {
    UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246,
    MAX_TEXTURE_MAX_ANISOTROPY_EXT: 0x84FF, TEXTURE_MAX_ANISOTROPY_EXT: 0x84FE,
    VERTEX_ATTRIB_ARRAY_DIVISOR_ANGLE: 0x88FE, MIN_EXT: 0x8007, MAX_EXT: 0x8008,
    UNSIGNED_NORMALIZED_EXT: 0x8C17, RGBA16F_EXT: 0x881A, RGB16F_EXT: 0x881B,
    FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE_EXT: 0x8211,
    COMPLETION_STATUS_KHR: 0x91B1, MAX_DRAW_BUFFERS_WEBGL: 0x8824,
  };

  const GL_ARITY = __GL_ARITY__;
  // Lost WebGL context (WEBGL_lose_context.loseContext): in Chrome
  // webglcontextlost fires immediately, isContextLost is true, getError
  // returns CONTEXT_LOST_WEBGL (0x9242) once, queries return null, and
  // everything else does nothing.
  const GL_LOST = new WeakMap();
  const glLostAnswer = (name, lost) => {
    if (name === 'isContextLost') return true;
    if (name === 'getError') { if (lost.pending) { lost.pending = false; return 0x9242; } return 0; }
    if (name === 'checkFramebufferStatus') return 0x8CDD;
    if (/^is[A-Z]/.test(name)) return false;
    if (/^(get|create|fenceSync|clientWaitSync)/.test(name)) return name === 'clientWaitSync' ? 0x911D : null;
    return undefined;
  };
  const glEventTarget = (impl) => { const c = impl && impl.canvas; return (c && c.__ptOwner) || c || null; };
  const glFire = (impl, type) => {
    const target = glEventTarget(impl);
    if (!target || typeof target.dispatchEvent !== 'function') return true;
    let ev;
    try { ev = new WebGLContextEvent(type, { cancelable: type === 'webglcontextlost', statusMessage: '' }); }
    catch (e) { ev = new Event(type, { cancelable: type === 'webglcontextlost' }); }
    if (globalThis.__pt_trustEvent) globalThis.__pt_trustEvent(ev);
    return target.dispatchEvent(ev);
  };
  const glLose = (impl) => {
    if (!impl || GL_LOST.has(impl)) return;
    const lost = { pending: true, restorable: false };
    GL_LOST.set(impl, lost);
    // A cancelled event allows restoreContext (per spec).
    lost.restorable = !glFire(impl, 'webglcontextlost');
  };
  const glRestore = (impl) => {
    const lost = impl && GL_LOST.get(impl);
    if (!lost) return;
    setTimeout(() => { if (GL_LOST.get(impl) !== lost) return; GL_LOST.delete(impl); glFire(impl, 'webglcontextrestored'); }, 0);
  };
  const publishGL = (impl, C, constsStr, methodsStr) => {
    if (!C || !C.prototype) return impl;
    const P = C.prototype;
    if (!P.__ptPublished) {
      try { Object.defineProperty(P, '__ptPublished', { value: true }); } catch (e) {}
      // Constants are data, not functions, and in Chrome cannot be rewritten
      // or deleted: the descriptor is captured from there.
      for (const pair of __s_split(constsStr, ',')) {
        const eq = __s_indexOf(pair, '=');
        if (eq < 0) continue;
        try {
          Object.defineProperty(P, __s_slice(pair, 0, eq), {
            value: +__s_slice(pair, eq + 1), writable: false, enumerable: true, configurable: false,
          });
        } catch (e) {}
      }
      const glCall = (self, args, name, need, P) => {
        if (need && args.length < need) {
          throw __pt_mkErr(TypeError, "Failed to execute '" + name + "' on '" +
            (self instanceof globalThis.WebGL2RenderingContext ? 'WebGL2RenderingContext' : 'WebGLRenderingContext') +
            "': " + need + ' argument' + (need === 1 ? '' : 's') +
            ' required, but only ' + args.length + ' present.');
        }
        const t = ctxOf(self, P, name);
        const lost = GL_LOST.get(t);
        if (lost) return glLostAnswer(name, lost);
        const m = Object.prototype.hasOwnProperty.call(t, name) ? t[name] : null;
        return typeof m === 'function' ? m.apply(t, args) : undefined;
      };
      for (const name of __s_split(methodsStr, ',')) {
        // As many args as the browser requires: fewer is a refusal naming the
        // method, not a silent `undefined`.
        const need = GL_ARITY[name] | 0;
        // Born with Chrome's `length` (editing it costs a dictionary each).
        let f;
        switch (need) {
          case 0: f = ({ [name]() { return glCall(this, arguments, name, need, P); } })[name]; break;
          case 1: f = ({ [name](a) { return glCall(this, arguments, name, need, P); } })[name]; break;
          case 2: f = ({ [name](a, b) { return glCall(this, arguments, name, need, P); } })[name]; break;
          case 3: f = ({ [name](a, b, c) { return glCall(this, arguments, name, need, P); } })[name]; break;
          case 4: f = ({ [name](a, b, c, d) { return glCall(this, arguments, name, need, P); } })[name]; break;
          case 5: f = ({ [name](a, b, c, d, e) { return glCall(this, arguments, name, need, P); } })[name]; break;
          case 6: f = ({ [name](a, b, c, d, e, g) { return glCall(this, arguments, name, need, P); } })[name]; break;
          default:
            f = ({ [name]() { return glCall(this, arguments, name, need, P); } })[name];
            try { Object.defineProperty(f, 'length', { value: need, configurable: true }); } catch (e) {}
        }
        const mf = mask(f, name);
        try { CTX_STUBS.add(mf); } catch (e) {}
        try { Object.defineProperty(P, name, { value: mf, writable: true, enumerable: true, configurable: true }); } catch (e) {}
      }
      for (const name of GL_ATTRS) {
        const acc = {
          get [name]() {
            const t = ctxOf(this, P, name);
            const v = Object.prototype.hasOwnProperty.call(t, name) ? t[name] : undefined;
            return name === 'canvas' && v && v.__ptOwner ? v.__ptOwner : v;
          },
          set [name](v) { const t = ctxOf(this, P, name); t[name] = v; },
        };
        const d0 = Object.getOwnPropertyDescriptor(acc, name);
        const get = d0.get, set = d0.set;
        const mg = mask(get, 'get ' + name), ms = mask(set, 'set ' + name);
        try { CTX_STUBS.add(mg); CTX_STUBS.add(ms); } catch (e) {}
        try { Object.defineProperty(P, name, { get: mg, set: ms, enumerable: true, configurable: true }); } catch (e) {}
      }
    }
    if (!impl) return null;                    // only declare the interface
    const pub = Object.create(P);
    CTX_IMPL.set(pub, impl);
    return pub;
  };

  // Interfaces are declared up front, not at the first `getContext`: in the
  // browser members are on the prototype from the start, and a collector
  // enumerating `CanvasRenderingContext2D.prototype` before any canvas must
  // see them (so must our own tracer).
  try {
    publishContext(null, globalThis.CanvasRenderingContext2D, CTX2D_METHODS, CTX2D_ATTRS);
    publishContext(null, globalThis.OffscreenCanvasRenderingContext2D, CTX2D_METHODS, CTX2D_ATTRS);
    publishGL(null, globalThis.WebGLRenderingContext, GL1_CONSTS, GL1_METHODS);
    publishGL(null, globalThis.WebGL2RenderingContext, GL2_CONSTS, GL2_METHODS);
  } catch (e) {}

  // WebGL extension prototypes per the shape captured from Chrome
  // (webgl_ext_shapes.json): names, constant values, method lengths, flags.
  const EXT_TABLE = __WEBGL_EXT_SHAPES__;
  const EXT_CACHE = new WeakMap(), EXT_OWNER = new WeakMap(), EXT_PROTOS = new Map();
  const EXT_METHODS = {
    getSupportedProfiles() { return ['ldr']; },
    isVertexArrayOES(v) { return typeof this.isVertexArray === 'function' ? !!this.isVertexArray(v) : !!(v && typeof v === 'object'); },
    createVertexArrayOES() { return typeof this.createVertexArray === 'function' ? this.createVertexArray() : null; },
    bindVertexArrayOES(v) { if (typeof this.bindVertexArray === 'function') this.bindVertexArray(v); },
    deleteVertexArrayOES(v) { if (typeof this.deleteVertexArray === 'function') this.deleteVertexArray(v); },
    drawArraysInstancedANGLE(m, f, c, n) { if (typeof this.drawArraysInstanced === 'function') this.drawArraysInstanced(m, f, c, n); },
    drawElementsInstancedANGLE(m, c, t, o, n) { if (typeof this.drawElementsInstanced === 'function') this.drawElementsInstanced(m, c, t, o, n); },
    vertexAttribDivisorANGLE(i, d) { if (typeof this.vertexAttribDivisor === 'function') this.vertexAttribDivisor(i, d); },
    drawBuffersWEBGL(b) { if (typeof this.drawBuffers === 'function') this.drawBuffers(b); },
    loseContext() { glLose(this); },
    restoreContext() { glRestore(this); },
  };
  const extProto = (ver, name, shape) => {
    const key = (ver === 2 ? 'webgl2:' : 'webgl:') + name;
    if (EXT_PROTOS.has(key)) return EXT_PROTOS.get(key);
    const P = {};
    const row = EXT_TABLE[key];
    const members = row ? row.members : __s_split(shape[1] || '', ',').filter(Boolean).map((k) => {
      const v = EXT_VALUES[k];
      return typeof v === 'number' ? [k, 'n' + v, 'e--'] : [k, 'f0', 'ewc'];
    }).concat([['Symbol(Symbol.toStringTag)', 's' + shape[0], '--c']]);
    for (const [k, kind, fl] of members) {
      const e = fl[0] === 'e', w = fl[1] === 'w', c = fl[2] === 'c';
      try {
        if (k === 'Symbol(Symbol.toStringTag)') { Object.defineProperty(P, Symbol.toStringTag, { value: __s_slice(kind, 1), writable: w, enumerable: e, configurable: c }); continue; }
        if (kind[0] === 'n') { Object.defineProperty(P, k, { value: +__s_slice(kind, 1), writable: w, enumerable: e, configurable: c }); continue; }
        if (kind[0] === 'f') {
          const impl = EXT_METHODS[k];
          const f = ({ [k](...a) {
            const owner = EXT_OWNER.get(this);
            if (!owner) throw __pt_mkErr(TypeError, 'Illegal invocation');
            return impl ? Reflect.apply(impl, owner, a) : undefined;
          } })[k];
          try { Object.defineProperty(f, 'length', { value: +__s_slice(kind, 1) || 0, configurable: true }); } catch (x) {}
          Object.defineProperty(P, k, { value: mask(f, k), writable: w, enumerable: e, configurable: c });
        }
      } catch (x) {}
    }
    EXT_PROTOS.set(key, P);
    return P;
  };
  const makeGL = (canvas, ver, want) => {
    // getUniform returns what was stored, with floats already float32 as in
    // the browser.
    const US = new Map();
    const P = {
      0x1F00: 'WebKit',                                   // VENDOR
      0x1F01: 'WebKit WebGL',                             // RENDERER
      0x1F02: ver === 2 ? 'WebGL 2.0 (OpenGL ES 3.0 Chromium)' : 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',
      0x8B8C: ver === 2 ? 'WebGL GLSL ES 3.00 (OpenGL ES GLSL ES 3.0 Chromium)' : 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)',
      0x9245: WEBGL_VENDOR,                               // UNMASKED_VENDOR_WEBGL
      0x9246: WEBGL_RENDERER,                             // UNMASKED_RENDERER_WEBGL
    };
    // Numeric limits come from the measured table (`GL1_PARAMS`/`GL2_PARAMS`);
    // only our identity stays here: vendor, renderer and versions.
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
    // Limits are not invented: captured from Chrome on this machine into
    // `GL1_PARAMS`/`GL2_PARAMS`.
    const glProto = (ver === 2 ? globalThis.WebGL2RenderingContext : globalThis.WebGLRenderingContext).prototype;
    // Here too the implementation lives apart from the interface (see publishGL).
    // Extensions the page has requested: some values are visible only after that.
    const asked = new Set();
    // The drawing buffer follows the canvas size: a page sets a 1x1 canvas,
    // gets a context, grows it to 16x16 and reads. The viewport is left
    // alone, as the spec requires: the page sets it.
    let vp = [0, 0, canvas.width || 300, canvas.height || 150];
    let bw = canvas.width || 300, bh = canvas.height || 150;
    const syncSize = () => {
      const w = canvas.width || 300, h = canvas.height || 150;
      if (w === bw && h === bh) return;
      bw = w; bh = h;
      if (typeof __pt_glResize === 'function' && canvas.__ptGlId) {
        try { __pt_glResize(canvas.__ptGlId, w, h); } catch (e) {}
      }
    };
    const gl = Object.assign({}, C, {
      canvas,
      drawingBufferColorSpace: 'srgb', unpackColorSpace: 'srgb',
      getParameter(p){
        if (p === 0x0BA2) { syncSize(); return new Int32Array(vp); }   // VIEWPORT
        if (Object.prototype.hasOwnProperty.call(EXT_PARAMS, p)) {
          const [v, need, onlyVer] = EXT_PARAMS[p];
          if ((!onlyVer || onlyVer === ver) && !asked.has(need)) return null;
          return v !== null ? v : (Object.prototype.hasOwnProperty.call(P, p) ? P[p] : null);
        }
        if (Object.prototype.hasOwnProperty.call(P, p)) return P[p];
        const T = ver === 2 ? GL2_PARAMS : GL1_PARAMS;
        if (Object.prototype.hasOwnProperty.call(T, p)) {
          const v = T[p];
          // Each parameter has its own array type, and it is observable: ranges
          // are Float32Array, compressed formats Uint32Array, sizes Int32Array,
          // the color mask a plain boolean array.
          if (!Array.isArray(v)) return v;
          if (typeof v[0] === 'boolean') return __s_slice(v);
          if (__s_indexOf(GL_F32, p) >= 0) return new Float32Array(v);
          if (__s_indexOf(GL_U32, p) >= 0) return new Uint32Array(v);
          return new Int32Array(v);
        }
        // An unknown enum gives `null`, not zero, as in the browser.
        return null;
      },
      getShaderPrecisionFormat(st, pt){
        const v = GL_PRECISION[st + ':' + pt] || [127, 127, 23];
        const C = globalThis.WebGLShaderPrecisionFormat;
        const o = C && C.prototype ? Object.create(C.prototype) : {};
        Object.defineProperties(o, {
          rangeMin: { value: v[0], enumerable: true },
          rangeMax: { value: v[1], enumerable: true },
          precision: { value: v[2], enumerable: true },
        });
        return o;
      },
      getInternalformatParameter(target, format, pname){
        const v = GL_FORMAT_SAMPLES[format];
        return new Int32Array(v || []);
      },
      getExtension(name){
        const shape = (ver === 2 ? GL2_EXT_SHAPE : GL1_EXT_SHAPE)[name];
        if (!shape) return null;
        asked.add(name);
        // As in Chrome: one extension object per context, with no own
        // properties; constants, methods and tag live on a hidden interface
        // prototype (without its own constructor).
        let cache = EXT_CACHE.get(this);
        if (!cache) { cache = new Map(); EXT_CACHE.set(this, cache); }
        if (cache.has(name)) return cache.get(name);
        const o = Object.create(extProto(ver, name, shape));
        EXT_OWNER.set(o, this);
        cache.set(name, o);
        return o;
      },
      getSupportedExtensions(){ return __s_slice(ver === 2 ? GL2_SUPPORTED : GL1_SUPPORTED); },
      getAttribLocation(){ return 0; },
      getContextAttributes(){
        // Requested values are reflected as in the browser:
        // `powerPreference: 'low-power'` comes back as is, not as "default".
        const w = (want && typeof want === 'object') ? want : {};
        const b = (k, d) => (k in w ? !!w[k] : d);
        const pp = String(w.powerPreference || 'default');
        // In a cross-site frame Chrome reports "default" as "low-power" (not in workers).
        const dflt = globalThis.__pt_crossSite && typeof document !== 'undefined' ? 'low-power' : 'default';
        return { alpha: b('alpha', true), antialias: b('antialias', true), depth: b('depth', true), desynchronized: b('desynchronized', false),
          failIfMajorPerformanceCaveat: b('failIfMajorPerformanceCaveat', false),
          powerPreference: (pp === 'high-performance' || pp === 'low-power') ? pp : dflt,
          premultipliedAlpha: b('premultipliedAlpha', true), preserveDrawingBuffer: b('preserveDrawingBuffer', false),
          stencil: b('stencil', false), xrCompatible: b('xrCompatible', false) };
      },

      getContextAttributes_: null,
    });
    // Buffer sizes are live: `Object.assign` would call the getter and store
    // a number, so they are defined separately after the object is built.
    for (const [name, get] of [['drawingBufferWidth', () => { syncSize(); return bw; }],
                               ['drawingBufferHeight', () => { syncSize(); return bh; }]]) {
      Object.defineProperty(gl, name, { get, enumerable: true, configurable: true });
    }
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
      try { Object.defineProperty(canvas, '__ptGlId', { value: gid, configurable: true }); } catch (e) {}
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
        const g = __pt_ctxImpl(s.__ptC2d || s.__ptGl1 || s.__ptGl2);
        if (g && g.__ptPixels) { const p = g.__ptPixels(); return { w: p.w, h: p.h, data: p.data }; }
        const w = (s.naturalWidth || s.width || s.videoWidth || 0) | 0;
        const h = (s.naturalHeight || s.height || s.videoHeight || 0) | 0;
        return { w, h, data: EMPTY };
      };
      // As many args as the browser requires; wrapped after assembly, right
      // under `Object.assign` below.
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
        uniform1f(l, x) { const a = new Float32Array([x]); US.set(L(l), a); __pt_glUniformF(gid, L(l), a); },
        uniform2f(l, a, b) { const v = new Float32Array([a, b]); US.set(L(l), v); __pt_glUniformF(gid, L(l), v); },
        uniform3f(l, a, b, c2) { const v = new Float32Array([a, b, c2]); US.set(L(l), v); __pt_glUniformF(gid, L(l), v); },
        uniform4f(l, a, b, c2, d) { const v = new Float32Array([a, b, c2, d]); US.set(L(l), v); __pt_glUniformF(gid, L(l), v); },
        uniform1i(l, x) { US.set(L(l), new Int32Array([x | 0])); __pt_glUniform1i(gid, L(l), x | 0); },
        uniformMatrix4fv(l, transpose, v) { const a = new Float32Array(v); US.set(L(l), a); __pt_glUniformMatrix4(gid, L(l), transpose ? 1 : 0, a); },
        getUniform(p, l) { const v = US.get(L(l)); if (!v) return null; return v.length === 1 ? v[0] : __s_slice(v); },
        clearColor(r, g, b, a) { const q = (v) => Math.max(0, Math.min(255, Math.round((+v || 0) * 255))); clearRGBA = [q(r), q(g), q(b), q(a)]; P[0x0C22] = new Float32Array([+r || 0, +g || 0, +b || 0, +a || 0]); },
        // State read back via getParameter is already float32, as in the
        // browser: 11.2 comes back as 11.199999809265137.
        lineWidth(w) { P[0x0B21] = Math.fround(+w || 0); },
        polygonOffset(f, u) { P[0x8038] = Math.fround(+f || 0); P[0x2A00] = Math.fround(+u || 0); },
        depthRange(n, f) { P[0x0B70] = new Float32Array([Math.max(0, Math.min(1, +n || 0)), Math.max(0, Math.min(1, +f || 0))]); },
        sampleCoverage(v, invert) { P[0x80AA] = Math.fround(Math.max(0, Math.min(1, +v || 0))); P[0x80AB] = !!invert; },
        blendColor(r, g, b, a) { P[0x8005] = new Float32Array([+r || 0, +g || 0, +b || 0, +a || 0]); },
        clearDepth(d) { P[0x0B73] = Math.fround(Math.max(0, Math.min(1, +d || 0))); },
        clear(mask) { syncSize(); __pt_glClear(gid, clearRGBA[0], clearRGBA[1], clearRGBA[2], clearRGBA[3], mask | 0); },
        viewport(x, y, w, h) { syncSize(); vp = [x | 0, y | 0, w | 0, h | 0]; __pt_glViewport(gid, x | 0, y | 0, w | 0, h | 0); },
        enable(cap) { __pt_glEnable(gid, cap >>> 0, 1); },
        disable(cap) { __pt_glEnable(gid, cap >>> 0, 0); },
        blendFunc(s, d) { __pt_glBlendFunc(gid, s >>> 0, d >>> 0); },
        depthFunc(f) { __pt_glDepthFunc(gid, f >>> 0); },
        drawArrays(mode, first, count) { syncSize(); __pt_glDrawArrays(gid, mode >>> 0, first | 0, count | 0); },
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
        readPixels(x, y, w, h, format, type, dst) { syncSize();
          if (!dst) return dst;
          // Straight from the bound framebuffer (which may be an offscreen target
          // of its own size), bottom-up — exactly the order WebGL specifies.
          const px = __pt_glReadPixels(gid, x | 0, y | 0, w | 0, h | 0, 0);
          const n = Math.min(dst.length === undefined ? px.length : dst.length, px.length);
          for (let i = 0; i < n; i++) dst[i] = px[i];
          // Returns nothing: pixels go into the given array, and the call
          // returns undefined in the browser.
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
      // (OES_vertex_array_object methods now go through the shared extension
      // prototype and call the context's createVertexArray/bindVertexArray.)
    } else {
      // Fallback synthesis (no `webgl` feature): back the readback with the shared
      // surface — clears are exact, draws stamp a pattern keyed by the op log.
      const S = makeSurface(canvas);
      let clearRGBA = [0, 0, 0, 0];
      Object.assign(gl, {
        clearColor(r, g, b, a) {
          S.note('clearColor|' + __ptJ(r, g, b, a));
          const q = (v) => Math.max(0, Math.min(255, Math.round((+v || 0) * 255)));
          clearRGBA = [q(r), q(g), q(b), q(a)];
        },
        clear(mask) {
          S.note('clear|' + mask);
          if ((mask | 0) & C.COLOR_BUFFER_BIT) { const p = S.pixels(); S.solid(0, 0, p.w, p.h, clearRGBA); }
        },
        viewport(x, y, w, h) { vp = [x | 0, y | 0, w | 0, h | 0]; S.note('viewport|' + __ptJ(x, y, w, h)); },
        shaderSource(sh, src) { S.note('shaderSource|' + __ptJ(src)); },
        bufferData(target, data) { S.note('bufferData|' + __ptJ(target, data && (data.length || data.byteLength))); },
        uniform1f(l, v) { S.note('uniform1f|' + v); },
        uniform2f(l, a, b) { S.note('uniform2f|' + [a, b]); },
        uniform3f(l, a, b, c2) { S.note('uniform3f|' + [a, b, c2]); },
        uniform4f(l, a, b, c2, d) { S.note('uniform4f|' + [a, b, c2, d]); },
        drawArrays(mode, first, count) {
          S.note('drawArrays|' + __ptJ(mode, first, count));
          const p = S.pixels(); S.stamp(0, 0, p.w, p.h);
        },
        drawElements(mode, count, type, offset) {
          S.note('drawElements|' + __ptJ(mode, count, type, offset));
          const p = S.pixels(); S.stamp(0, 0, p.w, p.h);
        },
        readPixels(x, y, w, h, format, type, dst) {
          S.note('readPixels|' + __ptJ(x, y, w, h, format, type));
          w = w | 0; h = h | 0;
          if (dst && dst.length >= w * h * 4) S.read(x, y, w, h, dst);
          // Pixels go into the given array; the call itself returns undefined.
        },
        __ptPixels() { return S.pixels(); },
      });
    }

    // Whatever is left unimplemented, `createX` still has to hand back an opaque
    // object of the right type: a page that null-checks `createTexture()` (or
    // runs `instanceof`) would otherwise see straight through the context.
    for (const [m, n] of [['createShader','WebGLShader'],['createProgram','WebGLProgram'],
      ['createBuffer','WebGLBuffer'],['createTexture','WebGLTexture'],['createFramebuffer','WebGLFramebuffer'],
      ['createRenderbuffer','WebGLRenderbuffer'],['createVertexArray','WebGLVertexArrayObject'],
      ...(ver === 2 ? [['createQuery','WebGLQuery'],['createSampler','WebGLSampler'],['createTransformFeedback','WebGLTransformFeedback'],['fenceSync','WebGLSync']] : [])]) {
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
    // Read-back state as in Chrome 151:
    // current vertex attribute value (float32), texture and sampler params
    // with GL defaults (LOD in float32; unknown or non-WebGL1 -> null),
    // WebGL1 blendColor clamped to [0, 1].
    {
      const after = (name, fn) => { const f = gl[name]; gl[name] = function () { const r = typeof f === 'function' ? f.apply(this, arguments) : undefined; try { fn.apply(this, arguments); } catch (e) {} return r; }; };
      const VA = new Map();
      const vaOf = (i) => { i = i >>> 0; let v = VA.get(i); if (!v) { v = new Float32Array([0, 0, 0, 1]); VA.set(i, v); } return v; };
      for (let n = 1; n <= 4; n++) {
        after('vertexAttrib' + n + 'f', function (i, ...xs) { const v = vaOf(i); v.set([0, 0, 0, 1]); for (let k = 0; k < n; k++) v[k] = +xs[k] || 0; });
        after('vertexAttrib' + n + 'fv', function (i, arr) { const v = vaOf(i); v.set([0, 0, 0, 1]); for (let k = 0; k < n; k++) v[k] = +(arr && arr[k]) || 0; });
      }
      const ENABLED = new Set();
      after('enableVertexAttribArray', (i) => ENABLED.add(i >>> 0));
      after('disableVertexAttribArray', (i) => ENABLED.delete(i >>> 0));
      gl.getVertexAttrib = function (i, pn) {
        i = i >>> 0;
        switch (pn >>> 0) {
          case 0x8626: return new Float32Array(vaOf(i));
          case 0x8622: return ENABLED.has(i);
          case 0x8623: return 4;
          case 0x8624: return 0;
          case 0x8625: return 0x1406;
          case 0x886A: return false;
          case 0x889F: return null;
          case 0x88FE: return ver === 2 ? 0 : null;
          case 0x88FD: return ver === 2 ? false : null;
        }
        return null;
      };
      const TEX_INT = { 0x2800: 0x2601, 0x2801: 0x2702, 0x2802: 0x2901, 0x2803: 0x2901 };
      const TEX2_INT = { 0x8072: 0x2901, 0x813C: 0, 0x813D: 1000, 0x884C: 0, 0x884D: 0x0203, 0x912F: false, 0x82DF: 0 };
      const TEX2_F = { 0x813A: -1000, 0x813B: 1000 };
      const BOUND = {}; const TP = new WeakMap();
      after('bindTexture', (t, tex) => { BOUND[t >>> 0] = tex || null; });
      const texStore = (t, pn, v, isF) => { const tex = BOUND[t >>> 0]; if (!tex || typeof tex !== 'object') return; let m = TP.get(tex); if (!m) TP.set(tex, (m = new Map())); m.set(pn >>> 0, isF ? Math.fround(+v || 0) : (v | 0)); };
      after('texParameterf', (t, pn, v) => texStore(t, pn, v, true));
      after('texParameteri', (t, pn, v) => texStore(t, pn, v, false));
      const known = (pn) => pn in TEX_INT || (ver === 2 && (pn in TEX2_INT || pn in TEX2_F));
      gl.getTexParameter = function (t, pn) {
        pn = pn >>> 0;
        const tex = BOUND[t >>> 0];
        if (!tex || !known(pn)) return null;
        const m = TP.get(tex);
        if (m && m.has(pn)) { const v = m.get(pn); return pn in TEX2_F ? Math.fround(v) : v; }
        if (pn in TEX_INT) return TEX_INT[pn];
        if (pn in TEX2_INT) return TEX2_INT[pn];
        return TEX2_F[pn];
      };
      if (ver === 2) {
        const SP = new WeakMap();
        const SMP_INT = { 0x2800: 0x2601, 0x2801: 0x2702, 0x2802: 0x2901, 0x2803: 0x2901, 0x8072: 0x2901, 0x884C: 0, 0x884D: 0x0203 };
        const SMP_F = { 0x813A: -1000, 0x813B: 1000 };
        const put = (smp, pn, v, isF) => { if (!smp || typeof smp !== 'object') return; let m = SP.get(smp); if (!m) SP.set(smp, (m = new Map())); m.set(pn >>> 0, isF ? Math.fround(+v || 0) : (v | 0)); };
        after('samplerParameterf', (smp, pn, v) => put(smp, pn, v, true));
        after('samplerParameteri', (smp, pn, v) => put(smp, pn, v, false));
        gl.getSamplerParameter = function (smp, pn) {
          pn = pn >>> 0;
          if (!(pn in SMP_INT || pn in SMP_F)) return null;
          const m = SP.get(smp);
          if (m && m.has(pn)) return m.get(pn);
          return pn in SMP_INT ? SMP_INT[pn] : SMP_F[pn];
        };
      }
      if (ver !== 2) {
        after('blendColor', function () { const v = gl.getParameter(0x8005); if (v && v.length === 4) { for (let k = 0; k < 4; k++) v[k] = Math.min(1, Math.max(0, v[k])); } });
      }
    }
    const impl = maskProto(gl);
    const Ctor = ver === 2 ? globalThis.WebGL2RenderingContext : globalThis.WebGLRenderingContext;
    return publishGL(impl, Ctor, ver === 2 ? GL2_CONSTS : GL1_CONSTS, ver === 2 ? GL2_METHODS : GL1_METHODS);
  };

  // --- patch canvas element methods -------------------------------------
  // Canvas methods live on HTMLCanvasElement, not HTMLElement:
  // `Object.getOwnPropertyDescriptor(HTMLCanvasElement.prototype, 'getContext')`
  // is read directly, and an extra level shows as much as a missing one.
  const proto = (globalThis.HTMLCanvasElement && globalThis.HTMLCanvasElement.prototype)
    || (globalThis.HTMLElement && globalThis.HTMLElement.prototype);
  if (proto) {
    proto.getContext = mask(function getContext(type, ctxAttrs) {
      if (this.localName !== 'canvas') return null;
      // A canvas keeps the first context type it was given; a real browser
      // returns null for a conflicting request rather than a second context.
      const t = type === 'experimental-webgl' ? 'webgl' : String(type);
      if (this.__ptCtxType && this.__ptCtxType !== t) return null;
      // WebGPU: Chrome's canvas returns a context, not null, with `canvas`,
      // `configure`, `getCurrentTexture` etc. Null alongside a present
      // `navigator.gpu` would itself be a tell.
      if (t === 'webgpu') {
        if (this.__ptGpuCtx) return this.__ptGpuCtx;
        const C = globalThis.GPUCanvasContext;
        if (!C || !C.prototype) return null;
        const P = C.prototype;
        if (!P.__ptShaped) {
          try { Object.defineProperty(P, '__ptShaped', { value: true }); } catch (e) {}
          const owner = new WeakMap();
          globalThis.__pt_gpuCtxOwner = owner;
          const put = (name, value) => {
            try { Object.defineProperty(P, name, { value: mask(value, name), writable: true, enumerable: true, configurable: true }); } catch (e) {}
          };
          try {
            Object.defineProperty(P, 'canvas', {
              get: mask(function canvas() { return owner.get(this); }, 'get canvas'),
              enumerable: true, configurable: true,
            });
          } catch (e) {}
          // Real `configure`/`getConfiguration` are already on the prototype;
          // the stub is only added if they are missing.
          if (typeof P.configure !== 'function') put('configure', function configure() {});
          if (typeof P.unconfigure !== 'function') put('unconfigure', function unconfigure() {});
          if (typeof P.getConfiguration !== 'function') {
            put('getConfiguration', function getConfiguration() { return null; });
          }
          put('getCurrentTexture', function getCurrentTexture() {
            const T = globalThis.GPUTexture;
            return T && T.prototype ? Object.create(T.prototype) : {};
          });
          try {
            if (!Object.getOwnPropertyDescriptor(P, Symbol.toStringTag)) {
              Object.defineProperty(P, Symbol.toStringTag, { value: 'GPUCanvasContext', configurable: true });
            }
          } catch (e) {}
        }
        const ctx = Object.create(P);
        globalThis.__pt_gpuCtxOwner.set(ctx, this);
        try { Object.defineProperty(this, '__ptGpuCtx', { value: ctx, configurable: true, enumerable: false }); } catch (e) {}
        return ctx;
      }
      // `bitmaprenderer`: together with `transferToImageBitmap` it shows a
      // bitmap, and collectors use it.
      if (t === 'bitmaprenderer') {
        if (this.__ptBmpCtx) return this.__ptBmpCtx;
        const C = globalThis.ImageBitmapRenderingContext;
        const P = C && C.prototype;
        if (!P) return null;
        if (!P.__ptShaped) {
          try { Object.defineProperty(P, '__ptShaped', { value: true }); } catch (e) {}
          const owner = new WeakMap();
          globalThis.__pt_bmpCtxOwner = owner;
          try {
            Object.defineProperty(P, 'canvas', {
              get: mask(function canvas() { return owner.get(this); }, 'get canvas'),
              enumerable: true, configurable: true,
            });
          } catch (e) {}
          try {
            Object.defineProperty(P, 'transferFromImageBitmap', {
              value: mask(function transferFromImageBitmap(bm) {
                // The bitmap lands on the canvas; the page reads it back later.
                const el = globalThis.__pt_bmpCtxOwner.get(this);
                if (!el || !bm) return;
                try {
                  const src = bm.__ptImageBitmap && bm.__ptImageBitmap.surf;
                  const dst = el.__ptSurf;
                  if (src && dst && dst.blit) dst.blit(src.id(), 0, 0, 0, 0, 0, 0, 0, 0);
                } catch (e) {}
              }, 'transferFromImageBitmap'),
              writable: true, enumerable: true, configurable: true,
            });
          } catch (e) {}
          try {
            if (!Object.getOwnPropertyDescriptor(P, Symbol.toStringTag)) {
              Object.defineProperty(P, Symbol.toStringTag, { value: 'ImageBitmapRenderingContext', configurable: true });
            }
          } catch (e) {}
        }
        const ctx = Object.create(P);
        globalThis.__pt_bmpCtxOwner.set(ctx, this);
        try { Object.defineProperty(this, '__ptBmpCtx', { value: ctx, configurable: true, enumerable: false }); } catch (e) {}
        this.__ptCtxType = t;
        return ctx;
      }
      if (t !== '2d' && t !== 'webgl' && t !== 'webgl2') return null;
      this.__ptCtxType = t;
      if (t === '2d') {
        if (!this.__ptC2d) { this.__ptC2d = make2DContext(this, ctxAttrs); ctrace(CTX_IMPL.get(this.__ptC2d) || this.__ptC2d, 'getContext("2d", ' + JSON.stringify(ctxAttrs === undefined ? null : ctxAttrs) + ')'); }
        return this.__ptC2d;
      }
      if (t === 'webgl') return this.__ptGl1 || (this.__ptGl1 = makeGL(this, 1, ctxAttrs));
      return this.__ptGl2 || (this.__ptGl2 = makeGL(this, 2, ctxAttrs));
    }, 'getContext');
    proto.toDataURL = mask(function toDataURL() {
      if (this.localName !== 'canvas') return 'data:,';
      const g = __pt_ctxImpl(this.__ptC2d || this.__ptGl1 || this.__ptGl2 || this.getContext('2d'));
      if (g && typeof g.__ptTainted === 'function' && g.__ptTainted()) {
        throw securityError('toDataURL', 'HTMLCanvasElement', 'Tainted canvases may not be exported.');
      }
      const p = g && g.__ptPixels ? g.__ptPixels() : null;
      if (!p || !p.w || !p.h) return 'data:,';
      return __pt_pngDataUrl(p.w, p.h, p.data) || 'data:,';
    }, 'toDataURL');
    // Data URL to a real `Blob`: body decoded, type taken from the URL. Shared
    // by the element's `toBlob` and the offscreen `convertToBlob`.
    if (!globalThis.__pt_blobFromDataUrl) {
      globalThis.__pt_blobFromDataUrl = (url) => {
        let type = 'image/png', body = '';
        try {
          const head = __s_slice(String(url), 5, __s_indexOf(String(url), ','));
          if (head) type = __s_replace(head, ';base64', '') || type;
          const b64 = __s_slice(String(url), __s_indexOf(String(url), ',') + 1);
          body = /;base64/.test(head) ? atob(b64) : decodeURIComponent(b64);
        } catch (e) { body = ''; }
        return new Blob([body], { type });
      };
    }
    proto.toBlob = mask(function toBlob(cb, type, quality) {
      if (arguments.length < 1) {
        throw __pt_mkErr(TypeError, "Failed to execute 'toBlob' on 'HTMLCanvasElement': " +
          '1 argument required, but only 0 present.');
      }
      if (typeof cb !== 'function') return;
      // A real `Blob` with a real PNG inside, for anything that reads the
      // bitmap as bytes (`arrayBuffer`, `FileReader`, upload). The callback is
      // not immediate: the browser encodes in a task.
      const url = this.toDataURL(type, quality);
      Promise.resolve().then(() => { cb(globalThis.__pt_blobFromDataUrl(url)); });
    }, 'toBlob');
  }

  // --- Image (new Image(); img.src = ... fires onload) ------------------
  if (globalThis.document) {
    // The `Image` constructor lives in the DOM layer: it creates a real
    // element, and the request goes to any URL, including relative ones.
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
  const audioParam = (v, lo, hi) => ({
    value: v, defaultValue: v,
    minValue: lo == null ? -3.4028235e38 : lo,
    maxValue: hi == null ? 3.4028235e38 : hi,
    automationRate: 'a-rate',
    setValueAtTime(x) { this.value = +x; return this; },
    linearRampToValueAtTime(x) { this.value = +x; return this; },
    exponentialRampToValueAtTime(x) { this.value = +x; return this; },
    setTargetAtTime() { return this; }, setValueCurveAtTime() { return this; },
    cancelScheduledValues() { return this; }, cancelAndHoldAtTime() { return this; },
  });
  // An audio node is an interface: in the browser shared members live on
  // `AudioNode`, kind-specific ones on the kind's prototype (`AnalyserNode`,
  // `GainNode`...), and the object has no own properties. Audio is
  // fingerprinted as closely as canvas.
  const NODE_IFACE = {
    analyser: 'AnalyserNode', gain: 'GainNode', oscillator: 'OscillatorNode',
    compressor: 'DynamicsCompressorNode', biquad: 'BiquadFilterNode',
    scriptprocessor: 'ScriptProcessorNode', buffersource: 'AudioBufferSourceNode',
    convolver: 'ConvolverNode', stereopanner: 'StereoPannerNode', delay: 'DelayNode',
    waveshaper: 'WaveShaperNode', panner: 'PannerNode', destination: 'AudioDestinationNode',
  };
  const NODE_STATE = new WeakMap();
  const shapeNodeProto = (name, base, members) => {
    const C = globalThis[name];
    if (!C || !C.prototype) return null;
    const P = C.prototype;
    if (base && globalThis[base] && globalThis[base].prototype
        && Object.getPrototypeOf(P) !== globalThis[base].prototype) {
      try { Object.setPrototypeOf(P, globalThis[base].prototype); } catch (e) {}
    }
    for (const key of members) {
      const cur = Object.getOwnPropertyDescriptor(P, key);
      const stubbed = cur && globalThis.__pt_stubMembers
        && ((cur.get && __pt_stubMembers.has(cur.get)) || (cur.value && __pt_stubMembers.has(cur.value)));
      if (cur && !stubbed) continue;
      const acc = {
        get [key]() { const st = NODE_STATE.get(this); return st ? st[key] : undefined; },
        set [key](v) { const st = NODE_STATE.get(this); if (st) st[key] = v; },
      };
      const d = Object.getOwnPropertyDescriptor(acc, key);
      try {
        Object.defineProperty(P, key, { get: mask(d.get, 'get ' + key), set: mask(d.set, 'set ' + key), enumerable: true, configurable: true });
      } catch (e) {}
    }
    try {
      if (!Object.getOwnPropertyDescriptor(P, Symbol.toStringTag)) {
        Object.defineProperty(P, Symbol.toStringTag, { value: name, configurable: true });
      }
    } catch (e) {}
    return P;
  };

  const makeNode = (ctx, kind, extra) => {
    const state = Object.assign({
      __ptOut: [],
      context: ctx, numberOfInputs: 1, numberOfOutputs: 1, channelCount: 2,
      channelCountMode: 'max', channelInterpretation: 'speakers', __ptKind: kind,
      connect(dst) {
        ctx.__ptEdges.push(kind + '>' + (dst && dst.__ptKind || 'destination'));
        // Edges are stored by reference, not kind name: otherwise a graph of
        // two gain nodes is indistinguishable from one.
        try {
          const to = (globalThis.__pt_audioState && __pt_audioState.get(dst)) || dst;
          if (to && typeof to === 'object') state.__ptOut.push(to);
        } catch (e) {}
        return dst && dst.connect ? dst : undefined;
      },
      disconnect() { __pt_write(state.__ptOut, 'length', 0); },
      start() {}, stop() {},
      addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; },
    }, extra || {});
    const iface = NODE_IFACE[kind];
    // Shared members on `AudioNode`, own ones on the kind's prototype: Chrome's
    // `AnalyserNode` has exactly nine names plus `constructor`, while
    // `connect` and `channelCount` sit a level higher.
    shapeNodeProto('AudioNode', 'EventTarget',
      ['context', 'numberOfInputs', 'numberOfOutputs', 'channelCount', 'channelCountMode',
       'channelInterpretation', 'connect', 'disconnect']);
    const SHARED = new Set(['context', 'numberOfInputs', 'numberOfOutputs', 'channelCount',
      'channelCountMode', 'channelInterpretation', 'connect', 'disconnect',
      'addEventListener', 'removeEventListener', 'dispatchEvent',
      // `start`/`stop`/`onended` belong only to sources, on their own level
      // in the browser: AudioScheduledSourceNode.
      'start', 'stop']);
    const scheduled = kind === 'oscillator' || kind === 'buffersource';
    if (scheduled) {
      const S = shapeNodeProto('AudioScheduledSourceNode', 'AudioNode', ['start', 'stop', 'onended']);
      if (S && globalThis[NODE_IFACE[kind]]) {
        try { Object.setPrototypeOf(globalThis[NODE_IFACE[kind]].prototype, S); } catch (e) {}
      } else {
        // Name not in the table: put it on the kind itself, just not on the object.
        shapeNodeProto(NODE_IFACE[kind], 'AudioNode', ['start', 'stop', 'onended']);
      }
    }
    const ownMembers = Object.keys(state).filter(
      (k) => __s_lastIndexOf(k, '__pt', 0) !== 0 && !SHARED.has(k));
    // Sources have their own base: OscillatorNode inherits
    // AudioScheduledSourceNode, not AudioNode directly, or `start` is lost.
    const P = iface ? shapeNodeProto(iface, scheduled ? 'AudioScheduledSourceNode' : 'AudioNode', ownMembers) : null;
    if (!P) { ctx.__ptNodes.push(state); return state; }
    const node = Object.create(P);
    NODE_STATE.set(node, state);
    try {
      if (!globalThis.__pt_audioState) {
        Object.defineProperty(globalThis, '__pt_audioState',
          { value: NODE_STATE, enumerable: false, configurable: true, writable: true });
      }
    } catch (e) {}
    Object.defineProperty(node, '__ptKind', { value: kind, enumerable: false, configurable: true });
    ctx.__ptNodes.push(state);
    return node;
  };
  // FNV-1a over every node parameter + the edge list: the graph's identity.
  const graphHash = (ctx) => {
    let h = 2166136261 >>> 0;
    const note = (s) => { s = String(s); for (let i = 0; i < s.length; i++) { h ^= __s_charCodeAt(s, i); h = Math.imul(h, 16777619) >>> 0; } };
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
  // The browser's oscillator does not sum the Fourier series per sample: it
  // builds 4096-point tables, one per third of an octave with truncated
  // harmonics, and reads two neighbours with linear interpolation, blending
  // them. The difference from the exact series is small but real (258.047 vs
  // Chrome's 258.098 on the canonical test). Port of WebKit/Blink
  // PeriodicWave/OscillatorNode with their sizes: 3 bands per octave, 400
  // cents per band.
  const OSC_BANDS = 3, OSC_CENTS = 1200 / OSC_BANDS;
  const oscTableSize = (rate) => (rate <= 24000 ? 2048 : rate <= 88200 ? 4096 : 8192);
  const OSC_CACHE = new Map();

  // Series coefficients as in the browser: all shapes odd, no cosines.
  const oscPartial = (type, n) => {
    const pi = Math.PI, piFactor = 2 / (n * pi);
    if (type === 'square') return (n & 1) ? 2 * piFactor : 0;
    if (type === 'sawtooth') return piFactor * ((n & 1) ? 1 : -1);
    if (type === 'triangle') return (n & 1) ? 8 * Math.sin(n * pi / 2) / (pi * pi * n * n) : 0;
    return n === 1 ? 1 : 0;
  };

  const oscTables = (type, rate) => {
    const key = type + '@' + rate;
    const hit = OSC_CACHE.get(key);
    if (hit) return hit;
    const size = oscTableSize(rate);
    const maxPartials = size / 2;
    const ranges = Math.round(0.5 + OSC_BANDS * Math.log2(size));
    // Harmonics are accumulated by rotation instead of a sine per sample: the
    // fullest table is 2000 harmonics over 4000 points, and eight million
    // sines would take seconds. Rotation gives the same to double precision
    // in tens of milliseconds.
    const build = (partials) => {
      const t = new Float64Array(size);
      const step = 2 * Math.PI / size;
      for (let n = 1; n <= partials; n++) {
        const b = oscPartial(type, n);
        if (!b) continue;
        const c = Math.cos(step * n), sn = Math.sin(step * n);
        let x = 1, y = 0;
        for (let i = 0; i < size; i++) {
          t[i] += b * y;
          const nx = x * c - y * sn;
          y = x * sn + y * c;
          x = nx;
        }
      }
      return t;
    };
    // The browser takes the normalization scale from the fullest table, with
    // all harmonics, so they cannot be truncated here: the triangle series
    // converges as 1/n^2, and at 500 harmonics the scale is already off by
    // 0.06%, exactly our former fingerprint error.
    // The fullest table is only needed by our own computation, for the
    // normalization factor; the engine normalizes itself.
    let scale = 1;
    if (typeof __pt_waveTable !== 'function') {
      const full = build(maxPartials);
      let peak = 0;
      for (let i = 0; i < size; i++) peak = Math.max(peak, Math.abs(full[i]));
      scale = peak ? 1 / peak : 1;
    }
    const tables = new Array(ranges);
    const partialsFor = (r) => Math.floor(Math.pow(2, -r * OSC_CENTS / 1200) * maxPartials);
    // The engine builds the table with the same inverse transform as the
    // browser, in the same single precision: an audio fingerprint is the
    // table's content to the last bit. The rotation-based path remains as a
    // fallback for the light build.
    const native = typeof __pt_waveTable === 'function';
    const made = { size, ranges, scale, lowest: (rate / 2) / maxPartials,
                   get(r) {
                     if (!tables[r]) {
                       if (native) {
                         const t = __pt_waveTable(type, rate, r);
                         if (t && t.length === size) { tables[r] = t; return t; }
                       }
                       const src = build(partialsFor(r));
                       const t = new Float32Array(size);
                       for (let i = 0; i < size; i++) t[i] = src[i] * scale;
                       tables[r] = t;
                     }
                     return tables[r];
                   } };
    OSC_CACHE.set(key, made);
    return made;
  };

  // One oscillator sample: choose a table pair by pitch and interpolate twice,
  // within a table and between tables.
  const oscWaveAt = (type, phase, freq, rate) => {
    const T = oscTables(type, rate);
    const f = Math.abs(freq);
    const ratio = f > 0 ? f / T.lowest : 0.5;
    let pitch = 1 + Math.log2(ratio) * 1200 / OSC_CENTS;
    pitch = Math.min(Math.max(pitch, 0), T.ranges - 1);
    const r1 = Math.floor(pitch);
    const r2 = r1 < T.ranges - 1 ? r1 + 1 : r1;
    const between = pitch - r1;
    const higher = T.get(r1), lower = T.get(r2);
    const virt = (phase - Math.floor(phase)) * T.size;
    const i0 = Math.floor(virt) % T.size;
    const i1 = (i0 + 1) % T.size;
    const frac = Math.fround(Math.fround(virt) - Math.fround(Math.floor(virt)));
    // Exactly as the browser: `a + f*(b-a)` in single precision, not
    // `(1-f)*a + f*b`; on Chrome's table the former matches all 64 samples
    // bit for bit, the latter is off by one ulp in every fourth.
    const f32 = Math.fround;
    const lerp = (a, b, t) => f32(a + f32(t * f32(b - a)));
    const sHigher = lerp(higher[i0], higher[i1], frac);
    const sLower = lerp(lower[i0], lower[i1], frac);
    return lerp(sHigher, sLower, between);
  };

  // Compressor. A real node is a tracking detector with a knee, pre-delay and,
  // crucially, makeup gain (without it the canonical fingerprint sum was 11.9
  // vs Chrome's 124.0).
  //
  // Port of Google's WebKit/Blink algorithm (DynamicsCompressorKernel) with
  // its defaults: 6 ms pre-delay, release zones 0.09/0.16/0.42/0.98, 0 dB
  // post gain, wet mix 1.
  // The browser uses single precision: `powf(10, 0.05f*db)` and
  // `20*log10f(x)`. Their rounding decides where the knee coefficient binary
  // search lands, which is determined only to 3e-4 and shifts the whole
  // output. The browser's factor is a `float` constant: `0.05f` is
  // 0.0500000007450580596923828125, which rounds differently than double 0.05.
  const dbToLin = (db) => Math.fround(Math.pow(10, Math.fround(Math.fround(0.05) * db)));
  const linToDb = (x) => (x ? Math.fround(20 * Math.fround(Math.log10(x))) : -1000);

  function compressorKernel(input, rate, opts) {
    const dbThreshold = opts.threshold, dbKnee = opts.knee, ratio = opts.ratio;
    const f1 = Math.fround;
    const linearThreshold = f1(dbToLin(dbThreshold));
    const slope = f1(1 / ratio);

    // The knee coefficient search runs in single precision: fifteen bisections
    // determine it only to 3e-4, exactly where double precision diverges
    // from the browser; the difference is a constant factor of 1.5e-4 on the
    // whole output.
    const kneeCurve = (x, k) => x < linearThreshold
      ? x
      : f1(linearThreshold + f1(f1(1 - f1(Math.exp(f1(-k * f1(x - linearThreshold))))) / k));
    const slopeAt = (x, k) => {
      if (x < linearThreshold) return 1;
      const x2 = f1(x * 1.001);
      const xDb = f1(linToDb(x)), x2Db = f1(linToDb(x2));
      const yDb = f1(linToDb(kneeCurve(x, k))), y2Db = f1(linToDb(kneeCurve(x2, k)));
      return f1(f1(y2Db - yDb) / f1(x2Db - xDb));
    };
    // The knee coefficient is found by bisection on the slope, fifteen steps,
    // as in the source. Search bounds are single precision too: in the
    // browser they are `float`, and 0.1 is inexact there.
    let minK = f1(0.1), maxK = f1(10000), k = f1(5);
    {
      const x = f1(dbToLin(f1(dbThreshold + dbKnee)));
      for (let i = 0; i < 15; i++) {
        if (slopeAt(x, k) < slope) maxK = k; else minK = k;
        k = f1(Math.sqrt(f1(minK * maxK)));
      }
    }
    const kneeThresholdDb = f1(dbThreshold + dbKnee);
    const kneeThreshold = f1(dbToLin(kneeThresholdDb));
    const ykneeThresholdDb = f1(linToDb(kneeCurve(kneeThreshold, k)));
    const saturate = (x) => x < kneeThreshold
      ? kneeCurve(x, k)
      : f1(dbToLin(f1(ykneeThresholdDb + f1(slope * f1(f1(linToDb(x)) - kneeThresholdDb)))));

    // Makeup gain: without it a compressor at -50 dB threshold crushes the
    // signal by two orders of magnitude; the browser restores it with power
    // 0.6. The exponent is a `float` constant: `0.6f` is
    // 0.60000002384185791015625, giving a different result than an even 0.6.
    // The factor applies to the whole output, so an error shows in every sample.
    const masterLinearGain = f1(Math.pow(f1(1 / f1(saturate(1))), f1(0.6)));

    // All constants and operations in single precision and in the browser's
    // order: there they are `constexpr float` computed from release zone
    // fractions, not doubles rounded at the end. The difference lands in the
    // seventh digit of every sample, exactly where pages look.
    const PI_OVER_TWO = f1(Math.PI / 2);
    const z1 = f1(0.09), z2 = f1(0.16), z3 = f1(0.42), z4 = f1(0.98);
    const mul = (c, z) => f1(f1(c) * z);
    const kABase = f1(f1(f1(mul(0.9999999999999998, z1) + mul(1.8432219684323923e-16, z2))
                       - mul(1.9373394351676423e-16, z3)) + mul(8.824516011816245e-18, z4));
    const kBBase = f1(f1(f1(mul(-1.5788320352845888, z1) + mul(2.3305837032074286, z2))
                       - mul(0.9141194204840429, z3)) + mul(0.1623677525612032, z4));
    const kCBase = f1(f1(f1(mul(0.5334142869106424, z1) - mul(1.272736789213631, z2))
                       + mul(0.9258856042207512, z3)) - mul(0.18656310191776226, z4));
    const kDBase = f1(f1(f1(mul(0.08783463138207234, z1) - mul(0.1694162967925622, z2))
                       + mul(0.08588057951595272, z3)) - mul(0.00429891410546283, z4));
    const kEBase = f1(f1(f1(mul(-0.042416883008123074, z1) + mul(0.1115693827987602, z2))
                       - mul(0.09764676325265872, z3)) + mul(0.028494263462021576, z4));
    const attackFrames = f1(f1(Math.max(f1(0.001), f1(opts.attack))) * f1(rate));
    const releaseFrames = f1(f1(rate) * f1(opts.release));
    const satReleaseFrames = f1(f1(0.0025) * f1(rate));
    const kA = f1(releaseFrames * kABase), kB = f1(releaseFrames * kBBase);
    const kC = f1(releaseFrames * kCBase), kD = f1(releaseFrames * kDBase);
    const kE = f1(releaseFrames * kEBase);

    const MASK = 1023;
    const delay = new Float32Array(1024);
    let readIndex = 0;
    let writeIndex = Math.min(Math.floor(0.006 * rate), 1023);
    let detectorAverage = 0, compressorGain = 1, maxAttackCompressionDiffDb = -1;
    let meteringGain = 0;
    const meteringReleaseK = Math.fround(1 - Math.exp(-1 / (rate * 0.325)));

    const out = new Float32Array(input.length);
    const nDivisionFrames = 32;
    const nDivisions = Math.floor(input.length / nDivisionFrames);
    let frame = 0;
    for (let d = 0; d < nDivisions; d++) {
      if (!Number.isFinite(detectorAverage)) detectorAverage = 1;
      const desiredGain = detectorAverage;
      // Arcsine in single precision divided by a single-precision pi/2: the
      // browser uses `asinf` and a `float` divisor.
      const scaledDesiredGain = f1(f1(Math.asin(desiredGain)) / PI_OVER_TWO);

      let envelopeRate;
      const isReleasing = scaledDesiredGain > compressorGain;
      let compressionDiffDb = scaledDesiredGain === 0
        ? (isReleasing ? -1 : 1)
        : f1(linToDb(f1(compressorGain / scaledDesiredGain)));
      if (isReleasing) {
        maxAttackCompressionDiffDb = -1;
        if (!Number.isFinite(compressionDiffDb)) compressionDiffDb = -1;
        let x = Math.min(0, Math.max(-12, compressionDiffDb));
        x = f1(f1(0.25) * f1(x + 12));
        const x2 = f1(x * x), x3 = f1(x2 * x), x4 = f1(x2 * x2);
        const rf = f1(f1(f1(f1(kA + f1(kB * x)) + f1(kC * x2)) + f1(kD * x3)) + f1(kE * x4));
        envelopeRate = f1(dbToLin(f1(5 / rf)));
      } else {
        if (!Number.isFinite(compressionDiffDb)) compressionDiffDb = 1;
        if (maxAttackCompressionDiffDb === -1 || maxAttackCompressionDiffDb < compressionDiffDb) {
          maxAttackCompressionDiffDb = compressionDiffDb;
        }
        const effAttenDiffDb = f1(Math.max(f1(0.5), maxAttackCompressionDiffDb));
        const x = f1(f1(0.25) / effAttenDiffDb);
        envelopeRate = f1(1 - f1(Math.pow(x, f1(1 / attackFrames))));
      }

      // The browser computes all of this in single precision, and over forty
      // thousand samples the accumulator drifts 5e-5 from double. Round every
      // step as it does.
      const f = Math.fround;
      for (let n = 0; n < nDivisionFrames; n++) {
        const undelayed = input[frame];
        delay[writeIndex] = undelayed;
        const absInput = f(Math.abs(undelayed));
        const shaped = f(saturate(absInput));
        const attenuation = absInput <= 0.0001 ? 1 : f(shaped / absInput);
        const attenuationDb = f(Math.max(2, f(-linToDb(attenuation))));
        const satReleaseRate = f(f(dbToLin(f(attenuationDb / satReleaseFrames))) - 1);
        const rate2 = attenuation > detectorAverage ? satReleaseRate : 1;
        detectorAverage = f(Math.min(1, f(detectorAverage + f(f(attenuation - detectorAverage) * rate2))));
        if (!Number.isFinite(detectorAverage)) detectorAverage = 1;

        if (envelopeRate < 1) {
          compressorGain = f(compressorGain + f(f(scaledDesiredGain - compressorGain) * envelopeRate));
        } else {
          compressorGain = f(Math.min(1, f(compressorGain * envelopeRate)));
        }

        // The sine argument is a single-precision product: the browser keeps
        // pi/2 as a separate `float` constant, not a rounded double.
        const postWarp = f(Math.sin(f(PI_OVER_TWO * compressorGain)));
        // Gains are multiplied first, then the sample: the order shows in the
        // last digit of every number.
        const totalGain = f(masterLinearGain * postWarp);
        out[frame] = f(delay[readIndex] * totalGain);
        // Reduction meter: the browser keeps a smoothed minimum in dB, not the
        // last value; it drops instantly and releases with a 0.325 s constant.
        // Pages read it as `compressor.reduction`.
        const dbRealGain = f(20 * Math.log10(postWarp));
        if (dbRealGain < meteringGain) meteringGain = dbRealGain;
        else meteringGain = f(meteringGain + f(f(dbRealGain - meteringGain) * meteringReleaseK));

        frame++;
        readIndex = (readIndex + 1) & MASK;
        writeIndex = (writeIndex + 1) & MASK;
      }
    }
    // The reduction the page reads on the node: the browser keeps the last
    // value in dB there, negative when the compressor acted.
    compressorKernel.lastReduction = meteringGain;
    return out;
  }

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
      // Chrome's live context rate is the sound card's, 48 kHz, not 44.1.
      // Output latency is the buffer size divided by it. Without user
      // activation the browser keeps the context suspended.
      __pt_write(this, 'sampleRate', 48000); __pt_write(this, 'currentTime', 0); __pt_write(this, 'state', 'suspended');
      this.__ptNodes = []; this.__ptEdges = [];
      // The destination has no output and an explicit channel count rather
      // than "whatever arrives": captured from Chrome 151.
      __pt_write(this, 'destination', makeNode(this, 'destination',
        { maxChannelCount: 2, numberOfOutputs: 0, channelCountMode: 'explicit' }));
      __pt_write(this, 'listener', { positionX: audioParam(0), positionY: audioParam(0), positionZ: audioParam(0), setPosition() {}, setOrientation() {} });
      __pt_write(this, 'audioWorklet', { addModule() { return Promise.resolve(); } });
      this.onstatechange = null;
    }
    createOscillator() {
      // Frequencies above Nyquist cannot be reproduced, and the browser
      // declares that limit on the parameter itself.
      const nyq = this.sampleRate / 2;
      return makeNode(this, 'oscillator', {
        type: 'sine', frequency: audioParam(440, -nyq, nyq), detune: audioParam(0),
        onended: null, setPeriodicWave() {},
      });
    }
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
    createBuffer(ch, len, rate) {
      if (arguments.length < 3) {
        throw __pt_mkErr(TypeError, "Failed to execute 'createBuffer' on 'BaseAudioContext': 3 arguments required, but only " +
          arguments.length + ' present.');
      }
      if (!(ch >= 1)) {
        throw __pt_mkErr(globalThis.DOMException || Error, 
          "Failed to execute 'createBuffer' on 'BaseAudioContext': The number of channels provided (" +
          (ch | 0) + ') is outside the range [1, 32].', 'NotSupportedError');
      }
      if (!(len >= 1)) {
        throw __pt_mkErr(globalThis.DOMException || Error, 
          "Failed to execute 'createBuffer' on 'BaseAudioContext': The number of frames provided (" +
          (len | 0) + ') is less than or equal to the minimum bound (0).', 'NotSupportedError');
      } return bufferOf(new Float32Array(len), ch, len, rate || this.sampleRate); }
    createPeriodicWave() { return {}; }
    decodeAudioData(_d, cb) { const b = this.createBuffer(2, this.sampleRate, this.sampleRate); if (typeof cb === 'function') cb(b); return Promise.resolve(b); }
    resume() { __pt_write(this, 'state', 'running'); return Promise.resolve(); }
    suspend() { __pt_write(this, 'state', 'suspended'); return Promise.resolve(); }
    close() { __pt_write(this, 'state', 'closed'); return Promise.resolve(); }
    addEventListener() {} removeEventListener() {} dispatchEvent() { return true; }
    // The graph is rendered by walking from the destination, not replaced by a
    // fixed synthesis: buffer sources must produce their own numbers and
    // `compressor.reduction` the browser's -20 dB.
    __ptRender(chans, want) {
      const rate = this.sampleRate;
      // The browser renders whole 128-frame quanta but returns as many frames
      // as requested: the tail of an unfinished quantum is still computed.
      const len = Math.ceil(want / 128) * 128;
      const zero = () => new Float32Array(len);
      const pv = (p, dflt) => (p && typeof p.value === 'number' ? p.value : dflt);
      const stateOf = (n) => (globalThis.__pt_audioState && __pt_audioState.get(n)) || n;
      const dest = stateOf(this.destination);
      // Who feeds into what.
      const inputsOf = new Map();
      for (const n of this.__ptNodes) {
        for (const to of (n.__ptOut || [])) {
          if (!inputsOf.has(to)) inputsOf.set(to, []);
          inputsOf.get(to).push(n);
        }
      }
      const cache = new Map();
      const sumInputs = (node, depth) => {
        const ins = inputsOf.get(node) || [];
        if (!ins.length) return zero();
        const out = zero();
        for (const src of ins) {
          const d = pull(src, depth + 1);
          for (let i = 0; i < len; i++) out[i] = Math.fround(out[i] + d[i]);
        }
        return out;
      };
      // Oscillator: computed the way the browser does on this machine, not
      // sample by sample in double precision: the table index advances in
      // groups of four in single precision and is recomputed from double once
      // per 128-frame quantum ("so the accumulated error stays bounded").
      // Without this the seventh digit diverges by sample 1000, and pages sum
      // all 44 thousand.
      const f32 = Math.fround;
      // Wraps the index into the table with the same operations as
      // `WrapVirtualIndexVector`: division, truncation toward zero, and a
      // correction by one if truncated the wrong way.
      const wrap32 = (x, size, invSize) => {
        const r = f32(x * invSize);
        let fl = Math.trunc(r) | 0;
        if (r < f32(fl)) fl -= 1;
        return f32(x - f32(f32(fl) * size));
      };
      const oscillate = (node) => {
        const type = node.type || 'sine';
        const freq = pv(node.frequency, 440) * Math.pow(2, pv(node.detune, 0) / 1200);
        const T = oscTables(type, rate);
        const tsize = T.size;
        const mask = tsize - 1;
        const invSize32 = f32(1 / tsize);
        const incr = f32(f32(freq) * f32(tsize / rate));
        const out = zero();
        // Table pair and blend factor are fixed for the run: constant frequency.
        // The pitch band is computed in single precision as in the browser,
        // where frequency, log and the blend factor are all `float`; in double
        // the factor differed by one ulp and every sample where the tables
        // differ diverged.
        const af = f32(Math.abs(freq));
        const ratio = af > 0 ? f32(af / f32(T.lowest)) : 0.5;
        let pitch = f32(1 + f32(f32(f32(Math.log2(ratio)) * 1200) / OSC_CENTS));
        pitch = Math.min(Math.max(pitch, 0), T.ranges - 1);
        const r1 = Math.trunc(pitch);
        const r2 = r1 < T.ranges - 1 ? r1 + 1 : r1;
        const between = f32(pitch - r1);
        const higher = T.get(r1), lower = T.get(r2);
        let vri = 0;                      // double precision, between quanta
        // The browser computes the first quantum differently: while the
        // frequency has a timeline event (left by assigning `value`), it takes
        // the per-sample path with a double index; afterwards groups of four in
        // single precision. Visible directly: in the first quantum samples match
        // double to the bit, from the second only the grouped computation does.
        const invSize = f32(1 / tsize);
        const wrap32 = (x) => {
          const r = f32(x * invSize);
          let fl = Math.trunc(r) | 0;
          if (r < f32(fl)) fl -= 1;
          return f32(x - f32(f32(fl) * tsize));
        };
        const pick = (v) => {
          const i0 = Math.trunc(v) & mask;
          const i1 = (i0 + 1) & mask;
          const frac = f32(f32(v) - i0);
          const sh = f32(higher[i0] + f32(frac * f32(higher[i1] - higher[i0])));
          const sl = f32(lower[i0] + f32(frac * f32(lower[i1] - lower[i0])));
          return f32(sh + f32(between * f32(sl - sh)));
        };
        let quantum = 0;
        for (let start = 0; start < len; start += 128, quantum++) {
          const n = Math.min(128, len - start);
          if (quantum === 0) {
            let v = vri;
            for (let k = 0; k < n; k++) {
              out[start + k] = pick(v);
              v += incr;
              v -= Math.floor(v / tsize) * tsize;
            }
          } else {
            // Four indices advance together, four increments per step, and
            // all four are wrapped after each step.
            let v0 = wrap32(f32(vri));
            let v1 = wrap32(f32(vri + incr));
            let v2 = wrap32(f32(vri + f32(2 * incr)));
            let v3 = wrap32(f32(vri + f32(3 * incr)));
            const step = f32(4 * incr);
            let k = 0;
            const loops = Math.floor(n / 4);
            for (let loop = 0; loop < loops; loop++, k += 4) {
              out[start + k] = pick(v0);
              out[start + k + 1] = pick(v1);
              out[start + k + 2] = pick(v2);
              out[start + k + 3] = pick(v3);
              v0 = wrap32(f32(v0 + step));
              v1 = wrap32(f32(v1 + step));
              v2 = wrap32(f32(v2 + step));
              v3 = wrap32(f32(v3 + step));
            }
            // Quantum tail: one by one, in double precision.
            let tail = vri + f32(k * incr);
            tail -= Math.floor(tail / tsize) * tsize;
            for (; k < n; k++) {
              out[start + k] = pick(tail);
              tail += incr;
              tail -= Math.floor(tail / tsize) * tsize;
            }
          }
          // Between quanta the index is recomputed from the quantum start.
          vri += f32(n * incr);
          vri -= Math.floor(vri / tsize) * tsize;
        }
        return out;
      };
      const fromBuffer = (node) => {
        const out = zero();
        const buf = node.buffer;
        let src = null;
        try { src = buf && buf.getChannelData ? buf.getChannelData(0) : null; } catch (e) {}
        if (!src) return out;
        const loop = !!node.loop;
        for (let i = 0; i < len; i++) {
          out[i] = i < src.length ? src[i] : (loop && src.length ? src[i % src.length] : 0);
        }
        return out;
      };
      // Biquad filter: same coefficients as `biquad.cc`.
      const biquad = (node, input) => {
        const out = zero();
        const nyq = rate / 2;
        const f = Math.min(1, Math.max(0, pv(node.frequency, 350)
          * Math.pow(2, pv(node.detune, 0) / 1200) / nyq));
        const q = pv(node.Q, 1), gainDb = pv(node.gain, 0);
        const w0 = Math.PI * f;
        let b0 = 1, b1 = 0, b2 = 0, a0 = 1, a1 = 0, a2 = 0;
        const alphaQ = Math.sin(w0) / (2 * Math.max(1e-9, q));
        const type = node.type || 'lowpass';
        if (type === 'lowpass' || type === 'highpass') {
          const g = Math.pow(10, 0.05 * (q));
          const alpha = Math.sin(w0) / (2 * g);
          const cosw = Math.cos(w0);
          if (type === 'lowpass') { b0 = (1 - cosw) / 2; b1 = 1 - cosw; b2 = b0; }
          else { b0 = (1 + cosw) / 2; b1 = -(1 + cosw); b2 = b0; }
          a0 = 1 + alpha; a1 = -2 * cosw; a2 = 1 - alpha;
        } else if (type === 'bandpass') {
          const cosw = Math.cos(w0);
          b0 = alphaQ; b1 = 0; b2 = -alphaQ; a0 = 1 + alphaQ; a1 = -2 * cosw; a2 = 1 - alphaQ;
        } else if (type === 'notch' || type === 'allpass') {
          const cosw = Math.cos(w0);
          if (type === 'notch') { b0 = 1; b1 = -2 * cosw; b2 = 1; }
          else { b0 = 1 - alphaQ; b1 = -2 * cosw; b2 = 1 + alphaQ; }
          a0 = 1 + alphaQ; a1 = -2 * cosw; a2 = 1 - alphaQ;
        } else if (type === 'peaking' || type === 'lowshelf' || type === 'highshelf') {
          const A = Math.pow(10, gainDb / 40);
          const cosw = Math.cos(w0), sinw = Math.sin(w0);
          if (type === 'peaking') {
            b0 = 1 + alphaQ * A; b1 = -2 * cosw; b2 = 1 - alphaQ * A;
            a0 = 1 + alphaQ / A; a1 = -2 * cosw; a2 = 1 - alphaQ / A;
          } else {
            const s = 1, alpha = sinw / 2 * Math.sqrt((A + 1 / A) * (1 / s - 1) + 2);
            const twoSqrtAAlpha = 2 * Math.sqrt(A) * alpha;
            if (type === 'lowshelf') {
              b0 = A * ((A + 1) - (A - 1) * cosw + twoSqrtAAlpha);
              b1 = 2 * A * ((A - 1) - (A + 1) * cosw);
              b2 = A * ((A + 1) - (A - 1) * cosw - twoSqrtAAlpha);
              a0 = (A + 1) + (A - 1) * cosw + twoSqrtAAlpha;
              a1 = -2 * ((A - 1) + (A + 1) * cosw);
              a2 = (A + 1) + (A - 1) * cosw - twoSqrtAAlpha;
            } else {
              b0 = A * ((A + 1) + (A - 1) * cosw + twoSqrtAAlpha);
              b1 = -2 * A * ((A - 1) + (A + 1) * cosw);
              b2 = A * ((A + 1) + (A - 1) * cosw - twoSqrtAAlpha);
              a0 = (A + 1) - (A - 1) * cosw + twoSqrtAAlpha;
              a1 = 2 * ((A - 1) - (A + 1) * cosw);
              a2 = (A + 1) - (A - 1) * cosw - twoSqrtAAlpha;
            }
          }
        }
        const n0 = b0 / a0, n1 = b1 / a0, n2 = b2 / a0, d1 = a1 / a0, d2 = a2 / a0;
        let x1 = 0, x2 = 0, y1 = 0, y2 = 0;
        for (let i = 0; i < len; i++) {
          const x = input[i];
          const y = n0 * x + n1 * x1 + n2 * x2 - d1 * y1 - d2 * y2;
          x2 = x1; x1 = x; y2 = y1; y1 = y;
          out[i] = Math.fround(y);
        }
        return out;
      };
      const shape = (node, input) => {
        const kind = node.__ptKind;
        if (kind === 'gain') {
          const g = pv(node.gain, 1);
          const out = zero();
          for (let i = 0; i < len; i++) out[i] = Math.fround(input[i] * g);
          return out;
        }
        if (kind === 'delay') {
          const shift = Math.max(0, Math.round(pv(node.delayTime, 0) * rate));
          const out = zero();
          for (let i = shift; i < len; i++) out[i] = input[i - shift];
          return out;
        }
        if (kind === 'waveshaper') {
          const curve = node.curve;
          if (!curve || !curve.length) return input;
          const out = zero();
          const n = curve.length;
          for (let i = 0; i < len; i++) {
            const x = Math.min(1, Math.max(-1, input[i]));
            const t = (x + 1) * 0.5 * (n - 1);
            const k = Math.min(n - 2, Math.floor(t));
            const frac = t - k;
            out[i] = Math.fround(curve[k] * (1 - frac) + curve[k + 1] * frac);
          }
          return out;
        }
        if (kind === 'biquad') return biquad(node, input);
        if (kind === 'compressor') {
          const opts = {
            threshold: pv(node.threshold, -24), knee: pv(node.knee, 30),
            ratio: pv(node.ratio, 12), attack: pv(node.attack, 0.003),
            release: pv(node.release, 0.25),
          };
          // The engine computes it: the browser takes powers and logs from the
          // system library, and JS math rounds differently, diverging from the
          // knee coefficient on. The JS version remains for the light build.
          if (typeof __pt_compress === 'function') {
            const got = __pt_compress(input, rate, opts.threshold, opts.knee,
                                      opts.ratio, opts.attack, opts.release);
            if (got && got.length === input.length + 1) {
              // The page reads `reduction` directly: the last number is it.
              try { node.reduction = got[input.length]; } catch (e) {}
              return got.subarray(0, input.length);
            }
          }
          const res = compressorKernel(input, rate, opts);
          try { node.reduction = compressorKernel.lastReduction; } catch (e) {}
          return res;
        }
        if (kind === 'stereopanner' || kind === 'panner') {
          const out = zero();
          const pan = Math.min(1, Math.max(-1, pv(node.pan, 0)));
          const g = Math.cos((pan + 1) * Math.PI / 4);
          for (let i = 0; i < len; i++) out[i] = Math.fround(input[i] * g);
          return out;
        }
        // Everything else passes through: analyser, convolver, processor.
        return input;
      };
      const pull = (node, depth) => {
        if (!node || depth > 32) return zero();
        if (cache.has(node)) return cache.get(node);
        cache.set(node, zero());
        let out;
        const kind = node.__ptKind;
        if (kind === 'oscillator') out = oscillate(node);
        else if (kind === 'buffersource') out = fromBuffer(node);
        else if (kind === 'constant') {
          out = zero();
          const v = pv(node.offset, 1);
          for (let i = 0; i < len; i++) out[i] = v;
        } else out = shape(node, sumInputs(node, depth));
        cache.set(node, out);
        return out;
      };
      const data = sumInputs(dest, 0);
      // Output exactly as many frames as requested.
      return bufferOf(data.length === want ? data : data.subarray(0, want), chans, want, rate);
    }
  }
  const audioTag = (Ctor, name) => { try { Object.defineProperty(Ctor.prototype, Symbol.toStringTag, { value: name, configurable: true }); } catch (e) {} return Ctor; };
  // The base must be declared on window itself, otherwise the name
  // `BaseAudioContext` goes to a graph table stub and the chain holds a
  // different object of that name:
  // `Object.getPrototypeOf(AudioContext.prototype) !== BaseAudioContext.prototype`.
  globalThis.BaseAudioContext = audioTag(mask(BaseAudioContext, 'BaseAudioContext'), 'BaseAudioContext');
  globalThis.AudioContext = audioTag(mask(class AudioContext extends BaseAudioContext {
    constructor() {
      super();
      // Live output latencies: Chrome's is a 512-sample buffer at the card's
      // rate; the output latency is unknown on this machine and reported as
      // zero. Their absence is a tell: offline contexts lack them, live ones
      // have them.
      __pt_write(this, 'baseLatency', 512 / this.sampleRate);
      __pt_write(this, 'outputLatency', 0);
    }
  }, 'AudioContext'), 'AudioContext');
  // The browser declares `close`/`resume`/`suspend` on the concrete contexts,
  // not the shared base; graph walks read the level.
  globalThis.__pt_sinkAudioMethods = () => {
    const B = globalThis.BaseAudioContext && globalThis.BaseAudioContext.prototype;
    if (!B) return;
    for (const k of ['close', 'resume', 'suspend']) {
      const d = Object.getOwnPropertyDescriptor(B, k);
      if (!d) continue;
      for (const n of ['AudioContext', 'OfflineAudioContext']) {
        const C = globalThis[n];
        if (!C || !C.prototype || Object.prototype.hasOwnProperty.call(C.prototype, k)) continue;
        if (n === 'OfflineAudioContext' && k === 'close') continue;   // offline contexts lack it
        try { Object.defineProperty(C.prototype, k, d); } catch (e) {}
      }
      try { delete B[k]; } catch (e) {}
    }
  };
  globalThis.OfflineAudioContext = audioTag(mask(class OfflineAudioContext extends BaseAudioContext {
    constructor(ch, len, rate) {
      super();
      if (ch && typeof ch === 'object') { this.__ptChans = ch.numberOfChannels || 1; __pt_write(this, 'length', ch.length || 44100); if (ch.sampleRate) __pt_write(this, 'sampleRate', ch.sampleRate); }
      else { this.__ptChans = ch || 1; __pt_write(this, 'length', len || 44100); if (rate) __pt_write(this, 'sampleRate', rate); }
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
    const Ctor = __ptIllegal(name);
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
  // Table captured from Chrome 151: some names it answers outright, some it
  // asks the user about, unknown names throw (and `push` specially).
  // Names Chrome 151 accepts: how it names them in the result, what it
  // answers at top level and in a cross-site frame (verified on chess.com).
  // Other names are an error with Chrome's own text.
  const PERMS = {
    'geolocation': ['geolocation', 'prompt', 'denied'], 'notifications': ['notifications', 'prompt', 'denied'],
    'midi': ['midi', 'prompt', 'denied'], 'camera': ['video_capture', 'prompt', 'denied'],
    'microphone': ['audio_capture', 'prompt', 'denied'], 'background-fetch': ['background_fetch', 'granted', 'granted'],
    'background-sync': ['background_sync', 'granted', 'granted'], 'persistent-storage': ['durable_storage', 'prompt', 'prompt'],
    'accelerometer': ['sensors', 'granted', 'granted'], 'gyroscope': ['sensors', 'granted', 'granted'],
    'magnetometer': ['sensors', 'granted', 'granted'], 'screen-wake-lock': ['screen_wake_lock', 'granted', 'denied'],
    'display-capture': ['display_capture', 'prompt', 'denied'], 'clipboard-read': ['clipboard_read', 'prompt', 'denied'],
    'clipboard-write': ['clipboard_write', 'granted', 'denied'], 'payment-handler': ['payment_handler', 'granted', 'granted'],
    'idle-detection': ['idle_detection', 'prompt', 'denied'], 'periodic-background-sync': ['periodic_background_sync', 'denied', 'denied'],
    'storage-access': ['storage-access', 'granted', 'prompt'], 'window-management': ['window-management', 'prompt', 'denied'],
    'local-fonts': ['local_fonts', 'prompt', 'denied'], 'captured-surface-control': ['captured-surface-control', 'prompt', 'denied'],
    'keyboard-lock': ['keyboard-lock', 'granted', 'granted'], 'pointer-lock': ['pointer-lock', 'granted', 'granted'],
  };
  const PERM_ERRORS = {
    'push': ['NotSupportedError', "Push Permission without userVisibleOnly:true isn't supported yet."],
    'ambient-light-sensor': ['TypeError', 'GenericSensorExtraClasses flag is not enabled.'],
    'nfc': ['TypeError', 'Web NFC is not enabled.'],
    'system-wake-lock': ['TypeError', 'System Wake Lock is not enabled.'],
    'top-level-storage-access': ['TypeError', 'The requested origin is invalid.'],
    'speaker-selection': ['TypeError', 'The Speaker Selection API is not enabled.'],
    'web-app-installation': ['TypeError', 'The Web App Install API is not enabled.'],
    'fullscreen': ['TypeError', 'Fullscreen Permission only supports allowWithoutGesture:true.'],
  };
  const permissions = { query: mask(function query(desc){
    const name = desc && desc.name;
    const head = "Failed to execute 'query' on 'Permissions': ";
    const known = PERM_ERRORS[name];
    if (known) {
      const [kind, text] = known;
      return Promise.reject(kind === 'TypeError' ? __pt_mkErr(TypeError, head + text)
        : __pt_mkErr(globalThis.DOMException || Error, head + text, kind));
    }
    const row = PERMS[name];
    if (!row) {
      return Promise.reject(__pt_mkErr(TypeError, head + "Failed to read the 'name' property from " +
        "'PermissionDescriptor': The provided value '" + name +
        "' is not a valid enum value of type PermissionName."));
    }
    const state = globalThis.__pt_crossSite ? row[2] : row[1];
    // The result is a real PermissionStatus, not a bare object: pages check
    // `Object.prototype.toString` and the constructor.
    const PS = globalThis.PermissionStatus;
    const status = PS && PS.prototype ? Object.create(PS.prototype) : { addEventListener(){}, removeEventListener(){} };
    __pt_write(status, 'name', row[0]);
    __pt_write(status, 'state', state);
    __pt_write(status, 'onchange', null);
    return Promise.resolve(status);
  }, 'query') };
  try { Object.defineProperty(navProto, 'permissions', { get: () => permissions, enumerable: true, configurable: true }); } catch (e) {}

  // --- window.chrome (its absence/shape is a classic headless tell) -----
  if (!globalThis.chrome) {
    const ts = () => performance.now() / 1000;
    // Chrome's `loadTimes`/`csi` are anonymous, `runtime` is absent without
    // extensions, member order is loadTimes, csi, app; `app` has `installState`.
    const anon = (f) => { try { Object.defineProperty(f, 'name', { value: '', configurable: true }); } catch (e) {} return f; };
    globalThis.chrome = {
      loadTimes: anon(function () { return { requestTime: ts(), startLoadTime: ts(), commitLoadTime: ts(), finishDocumentLoadTime: ts(), finishLoadTime: ts(), firstPaintTime: ts(), firstPaintAfterLoadTime: 0, navigationType: 'Other', wasFetchedViaSpdy: true, wasNpnNegotiated: true, npnNegotiatedProtocol: 'h2', wasAlternateProtocolAvailable: false, connectionInfo: 'h2' }; }),
      csi: anon(function () { return { startE: Date.now(), onloadT: Date.now(), pageT: performance.now(), tran: 15 }; }),
      app: {
        isInstalled: false,
        getDetails: function getDetails() { return null; },
        getIsInstalled: function getIsInstalled() { return false; },
        installState: function installState() { return 'not_installed'; },
        runningState: function runningState() { return 'cannot_run'; },
        InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
        RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
      },
    };
  }

  // --- extra navigator surface -----------------------------------------
  const navExtra = (name, value) => { try { Object.defineProperty(navProto, name, { value, enumerable: true, configurable: true, writable: true }); } catch (e) {} };
  // The browser's device list is not empty even without permission: three
  // entries with empty labels and `deviceId` (audio in, video in, audio out).
  // An empty list means a machine without a sound card.
  const mediaDevice = (kind) => {
    const d = { deviceId: '', kind, label: '', groupId: '' };
    d.toJSON = function toJSON() { return { deviceId: '', kind, label: '', groupId: '' }; };
    try {
      const P = globalThis.MediaDeviceInfo && MediaDeviceInfo.prototype;
      if (P) Object.setPrototypeOf(d, P);
    } catch (e) {}
    return d;
  };
  navExtra('mediaDevices', {
    enumerateDevices: () => Promise.resolve([
      mediaDevice('audioinput'), mediaDevice('videoinput'), mediaDevice('audiooutput')]),
    getUserMedia: () => Promise.reject(new Error('Permission denied')),
    getDisplayMedia: () => Promise.reject(new Error('Permission denied')),
    getSupportedConstraints: () => ({ aspectRatio: true, autoGainControl: true, brightness: true, channelCount: true, colorTemperature: true, contrast: true, deviceId: true, displaySurface: true, echoCancellation: true, exposureCompensation: true, exposureMode: true, exposureTime: true, facingMode: true, focusDistance: true, focusMode: true, frameRate: true, groupId: true, height: true, iso: true, latency: true, noiseSuppression: true, pan: true, pointsOfInterest: true, resizeMode: true, restrictOwnAudio: true, sampleRate: true, sampleSize: true, saturation: true, sharpness: true, suppressLocalAudioPlayback: true, tilt: true, torch: true, voiceIsolation: true, whiteBalanceMode: true, width: true, zoom: true }),
    ondevicechange: null, addEventListener: noop, removeEventListener: noop,
  });
  // Desktop Chrome's NetworkInformation omits `type` (it's mobile-only) — its
  // presence is a tell, so we leave it off.
  // Network info is derived from our own request timings, rounded like the
  // browser: `rtt` to 25 ms, `downlink` to 25 kbit/s and capped at 10 Mbit/s.
  const netFromTiming = () => {
    try {
      const nav = performance.getEntriesByType('navigation')[0];
      if (!nav) return null;
      // The navigation plus everything it pulled in: the browser averages over
      // many requests.
      const all = [nav].concat(performance.getEntriesByType('resource'));
      const rtts = all.map((e) => Math.max(0, (e.responseStart || 0) - (e.requestStart || 0)))
        .filter((x) => x > 0).sort((a, b) => a - b);
      // The browser's estimate is transport-level (TCP/QUIC), not HTTP: our
      // fastest response is closest to it, not the median.
      const mid = rtts.length ? rtts[0] : 50;
      // Between 50 and 300: the home network range. Chrome reports a fast
      // network as exactly 50: anything under 100 maps there.
      const rtt = mid < 100 ? 50 : Math.min(300, Math.round(mid / 25) * 25);
      let bytes = 0, secs = 0;
      for (const e of all) {
        bytes += Number(e.transferSize) || 0;
        secs += Math.max(0, (e.responseEnd - e.requestStart)) / 1000;
      }
      const mbit = secs > 0.01 ? (bytes * 8) / 1e6 / secs : 1.55;
      const downlink = Math.min(10, Math.max(1.5, Math.round(mbit / 0.025) * 0.025));
      return { rtt, downlink: Math.round(downlink * 1000) / 1000 };
    } catch (e) { return null; }
  };
  navExtra('connection', {
    effectiveType: '4g', saveData: false, onchange: null,
    get rtt() { const n = netFromTiming(); return n ? n.rtt : 50; },
    get downlink() { const n = netFromTiming(); return n ? n.downlink : 1.55; },
  });
  // A desktop is always "charged and plugged in": level exactly 1, charging
  // time 0, discharging time Infinity. A fraction like 0.71 means a laptop.
  const batteryLevel = 1;
  navExtra('getBattery', mask(function getBattery() { return Promise.resolve({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: Math.round(batteryLevel * 100) / 100, onchargingchange: null, onchargingtimechange: null, ondischargingtimechange: null, onlevelchange: null, addEventListener: noop, removeEventListener: noop }); }, 'getBattery'));
  navExtra('storage', { estimate: () => Promise.resolve({ quota: 10737418240, usage: 0, usageDetails: {} }), persist: () => Promise.resolve(false), persisted: () => Promise.resolve(false) });
  // Before the first gesture the browser answers false to both; a click
  // raises the flag itself.
  navExtra('userActivation', {
    get hasBeenActive() { return !!globalThis.__pt_userActivated; },
    get isActive() { return !!globalThis.__pt_userActive; },
  });
  // `navigator.mediaSession`: the browser has six members on the prototype,
  // and `playbackState` is read.
  {
    const proto = (globalThis.MediaSession && MediaSession.prototype) || {};
    const state = { metadata: null, playbackState: 'none' };
    try {
      Object.defineProperty(proto, 'metadata', {
        get: mask(function () { return state.metadata; }, 'get metadata'),
        set: mask(function (v) { state.metadata = v === undefined ? null : v; }, 'set metadata'),
        enumerable: true, configurable: true,
      });
      Object.defineProperty(proto, 'playbackState', {
        get: mask(function () { return state.playbackState; }, 'get playbackState'),
        set: mask(function (v) { state.playbackState = String(v); }, 'set playbackState'),
        enumerable: true, configurable: true,
      });
      for (const m of ['setActionHandler', 'setCameraActive', 'setMicrophoneActive', 'setPositionState']) {
        Object.defineProperty(proto, m, {
          value: mask(function () {}, m), writable: true, enumerable: true, configurable: true,
        });
      }
      if (!Object.getOwnPropertyDescriptor(proto, Symbol.toStringTag)) {
        Object.defineProperty(proto, Symbol.toStringTag, { value: 'MediaSession', configurable: true });
      }
      navExtra('mediaSession', Object.create(proto));
    } catch (e) {}
  }
  // Scheduling: desktop Chrome has `isInputPending`, and it gets asked.
  navExtra('scheduling', {
    isInputPending: mask(function isInputPending() { return false; }, 'isInputPending'),
  });
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
  // WebRTC is not decorative: anti-bots open a data channel, create an offer
  // and listen for `icecandidate`. Real Chrome answers with an offer with
  // ufrag, password and DTLS fingerprint, then one or two host candidates
  // with an mDNS name (it hides the real address since 2019) and a final
  // null. A silent dummy is a browser without network.
  const hex = (n) => {
    const out = [];
    const bytes = new Uint8Array(n);
    (globalThis.crypto && crypto.getRandomValues) ? crypto.getRandomValues(bytes) : bytes.fill(7);
    for (const b of bytes) out.push(__s_padStart(b.toString(16), 2, '0'));
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
    return [...bytes].map((b) => __s_toUpperCase(__s_padStart(b.toString(16), 2, '0'))).join(':');
  };

  // WebRTC as in Chrome 151 (report section cHOXt5): the offer is built from
  // sections captured from Chrome (audio, video, application; BUNDLE);
  // gathering yields one section per address family: an mDNS host on the
  // real socket port and srflx from the STUN reply (native __pt_rtcStart /
  // __pt_rtcPoll). localDescription is completed as in Chrome: candidates
  // after `a=rtcp`, `m=` port and `c=` address from the srflx IPv4.
  const RTC_CHROME = __RTC_CHROME__;
  const rtcUuid = () => {
    const h = (n) => Array.from({ length: n }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('');
    return h(8) + '-' + h(4) + '-4' + h(3) + '-' + '89ab'[Math.floor(Math.random() * 4)] + h(3) + '-' + h(12);
  };
  const rtcFoundation = () => String(Math.floor(1e9 + Math.random() * 3.2e9));
  // Event, candidate and description fields live on prototypes, as in Chrome:
  // own properties would show in getOwnPropertyNames.
  const RTC_EV = new WeakMap();
  const rtcProtoOnce = () => {
    if (rtcProtoOnce.done) return; rtcProtoOnce.done = true;
    const nat2 = (f) => (globalThis.__pt_native ? __pt_native(f) : f);
    try {
      const EP = globalThis.RTCPeerConnectionIceEvent && RTCPeerConnectionIceEvent.prototype;
      if (EP) for (const k of ['candidate', 'url']) {
        const d = Object.getOwnPropertyDescriptor(EP, k);
        Object.defineProperty(EP, k, { get: nat2(({ get [k]() { const v = RTC_EV.get(this); if (v && k in v) return v[k]; return d && d.get ? d.get.call(this) : null; } }).__lookupGetter__(k)), enumerable: true, configurable: true });
      }
      for (const [n, keys] of [['RTCSessionDescription', ['type', 'sdp']], ['RTCIceCandidate', ['candidate', 'sdpMid', 'sdpMLineIndex', 'usernameFragment']]]) {
        const P = globalThis[n] && globalThis[n].prototype; if (!P) continue;
        const f = ({ toJSON() { const o = {}; for (const k of keys) o[k] = this[k]; return o; } }).toJSON;
        Object.defineProperty(P, 'toJSON', { value: nat2(f), writable: true, enumerable: true, configurable: true });
      }
    } catch (e) {}
  };
  const rtcEvent = (type, extra) => {
    rtcProtoOnce();
    let ev;
    try { ev = new Event(type); } catch (e) { ev = { type }; }
    const C = extra && 'candidate' in extra ? globalThis.RTCPeerConnectionIceEvent : null;
    try { if (C && C.prototype) Object.setPrototypeOf(ev, C.prototype); } catch (e) {}
    if (C) RTC_EV.set(ev, Object.assign({ url: null }, extra));
    else for (const k of Object.keys(extra || {})) { try { Object.defineProperty(ev, k, { value: extra[k], enumerable: false, configurable: true }); } catch (e) {} }
    try { if (typeof globalThis.__ptTrust === 'function') globalThis.__ptTrust(ev); } catch (e) {}
    return ev;
  };
  const rtcCandidate = (line, mid, idx, ufrag, f) => {
    const C = globalThis.RTCIceCandidate;
    const o = Object.create(C && C.prototype ? C.prototype : Object.prototype);
    // In object fields Chrome brackets IPv6 (not in the candidate string).
    const br = (a) => (typeof a === 'string' && __s_indexOf(a, ':') >= 0 ? '[' + a + ']' : a);
    const bag = { candidate: line, sdpMid: String(mid), sdpMLineIndex: idx, foundation: f.foundation, component: 'rtp', priority: f.priority,
      address: br(f.address), protocol: 'udp', port: f.port, type: f.type, tcpType: null, relatedAddress: f.raddr === undefined ? null : br(f.raddr),
      relatedPort: f.rport === undefined ? null : f.rport, usernameFragment: ufrag };
    for (const k of Object.keys(bag)) __pt_write(o, k, bag[k]);
    rtcProtoOnce();
    return o;
  };
  const rtcDesc = (type, sdp) => {
    const C = globalThis.RTCSessionDescription;
    const o = Object.create(C && C.prototype ? C.prototype : Object.prototype);
    __pt_write(o, 'type', type); __pt_write(o, 'sdp', sdp);
    rtcProtoOnce();
    return o;
  };
  const rtcTransceiver = (kind) => {
    const mk = (n) => { const C = globalThis[n]; return Object.create(C && C.prototype ? C.prototype : Object.prototype); };
    const t = mk('RTCRtpTransceiver'), rcv = mk('RTCRtpReceiver'), snd = mk('RTCRtpSender'), tr = mk('MediaStreamTrack');
    __pt_write(tr, 'kind', kind); __pt_write(tr, 'id', rtcUuid()); __pt_write(tr, 'label', 'remote ' + kind); __pt_write(tr, 'enabled', true);
    __pt_write(tr, 'muted', true); __pt_write(tr, 'readyState', 'live');
    __pt_write(rcv, 'track', tr); __pt_write(rcv, 'transport', null);
    __pt_write(snd, 'track', null); __pt_write(snd, 'transport', null);
    __pt_write(t, 'mid', null); __pt_write(t, 'direction', 'recvonly'); __pt_write(t, 'currentDirection', null);
    __pt_write(t, 'receiver', rcv); __pt_write(t, 'sender', snd); __pt_write(t, 'stopped', false);
    return t;
  };

  globalThis.RTCPeerConnection = globalThis.RTCPeerConnection || mask(class RTCPeerConnection extends EventTarget {
    constructor(config) {
      super();
      const sid = String(Math.floor(1 + Math.random() * 9)) + Array.from({ length: 18 }, () => Math.floor(Math.random() * 10)).join('');
      Object.defineProperty(this, '__pt', {
        value: {
          ufrag: b64ish(4), pwd: b64ish(24), print: dtlsPrint(), sid,
          mdns4: rtcUuid() + '.local', mdns6: rtcUuid() + '.local',
          fh4: rtcFoundation(), fh6: rtcFoundation(), fs4: rtcFoundation(), fs6: rtcFoundation(),
          tx: [], data: false, kinds: [], cands: [], srflx4: [], gathered: false, closed: false, config: config || {}, neg: false,
        },
        enumerable: false,
      });
      for (const [k, v] of [['localDescription', null], ['remoteDescription', null], ['currentLocalDescription', null], ['pendingLocalDescription', null],
        ['currentRemoteDescription', null], ['pendingRemoteDescription', null], ['iceGatheringState', 'new'], ['iceConnectionState', 'new'],
        ['connectionState', 'new'], ['signalingState', 'stable'], ['canTrickleIceCandidates', null], ['sctp', null]]) __pt_write(this, k, v);
      for (const k of ['onicecandidate', 'onicegatheringstatechange', 'oniceconnectionstatechange', 'onconnectionstatechange', 'ondatachannel',
        'onnegotiationneeded', 'onsignalingstatechange', 'onicecandidateerror', 'ontrack']) this[k] = null;
    }
    __ptFire(type, extra) {
      const ev = rtcEvent(type, extra);
      try { this.dispatchEvent(ev); } catch (e) {
        const on = this['on' + type];
        if (typeof on === 'function') { try { on.call(this, ev); } catch (e2) {} }
      }
    }
    __ptNeg() {
      const st = this.__pt;
      if (st.neg || st.closed) return;
      st.neg = true;
      setTimeout(() => { st.neg = false; if (!st.closed) this.__ptFire('negotiationneeded'); }, 0);
    }
    __ptKinds() {
      const st = this.__pt;
      const k = st.tx.map((t) => t.receiver.track.kind);
      if (st.data) k.push('application');
      return k.length ? k : ['application'];
    }
    __ptSection(kind, mid, withCands) {
      const st = this.__pt;
      let sec = RTC_CHROME.sections[kind] || RTC_CHROME.sections.application;
      sec = __s_replace(__s_split(__s_split(__s_split(sec, '{UFRAG}').join(st.ufrag), '{PWD}').join(st.pwd), '{FP}').join(st.print), /a=mid:\d+/, 'a=mid:' + mid);
      if (!withCands) return sec;
      const mine = st.cands.filter((c) => c.idx === mid);
      if (!mine.length) return sec;
      const lines = mine.map((c) => 'a=' + c.sdpLine + '\r\n').join('');
      const s4 = st.srflx4[mid];
      if (s4) sec = __s_replace(__s_replace(sec, /^m=(\S+) 9 /, 'm=$1 ' + s4.port + ' '), 'c=IN IP4 0.0.0.0', 'c=IN IP4 ' + s4.ip);
      const anchor = __s_indexOf(sec, 'a=rtcp:9 IN IP4 0.0.0.0\r\n');
      if (anchor >= 0) { const at = anchor + 'a=rtcp:9 IN IP4 0.0.0.0\r\n'.length; return __s_slice(sec, 0, at) + lines + __s_slice(sec, at); }
      const c = __s_indexOf(sec, '\r\n', __s_indexOf(sec, 'c=IN IP4')) + 2;
      return __s_slice(sec, 0, c) + lines + __s_slice(sec, c);
    }
    __ptSdp(withCands) {
      const st = this.__pt;
      const kinds = st.kinds.length ? st.kinds : this.__ptKinds();
      const head = __s_replace(__s_split(RTC_CHROME.head, '{SID}').join(st.sid), /a=group:BUNDLE[^\r]*/, 'a=group:BUNDLE ' + kinds.map((_, i) => i).join(' '));
      return head + kinds.map((k, i) => this.__ptSection(k, i, withCands)).join('');
    }
    createDataChannel(label, opts) {
      const st = this.__pt;
      if (st.closed) throw (typeof DOMException === 'function' ? __pt_mkErr(DOMException, "Failed to execute 'createDataChannel' on 'RTCPeerConnection': The RTCPeerConnection's signalingState is 'closed'.", 'InvalidStateError') : new Error('closed'));
      const first = !st.data;
      st.data = true;
      const C = globalThis.RTCDataChannel;
      const channel = Object.create(C && C.prototype ? C.prototype : EventTarget.prototype);
      const bag = { label: String(label == null ? '' : label), ordered: !(opts && opts.ordered === false), maxPacketLifeTime: (opts && opts.maxPacketLifeTime != null) ? opts.maxPacketLifeTime : null,
        maxRetransmits: (opts && opts.maxRetransmits != null) ? opts.maxRetransmits : null, protocol: (opts && opts.protocol) || '', negotiated: !!(opts && opts.negotiated),
        id: (opts && opts.negotiated && opts.id != null) ? opts.id : null, readyState: 'connecting', bufferedAmount: 0, bufferedAmountLowThreshold: 0, binaryType: 'arraybuffer' };
      for (const k of Object.keys(bag)) __pt_write(channel, k, bag[k]);
      if (first) this.__ptNeg();
      return channel;
    }
    addTransceiver(kind) {
      const k = typeof kind === 'string' ? kind : (kind && kind.kind) || 'audio';
      const t = rtcTransceiver(k);
      this.__pt.tx.push(t);
      this.__ptNeg();
      return t;
    }
    async createOffer(opts) {
      const st = this.__pt;
      if (st.closed) throw (typeof DOMException === 'function' ? __pt_mkErr(DOMException, "Failed to execute 'createOffer' on 'RTCPeerConnection': The RTCPeerConnection's signalingState is 'closed'.", 'InvalidStateError') : new Error('closed'));
      if (opts && typeof opts === 'object') {
        for (const [key, kind] of [['offerToReceiveAudio', 'audio'], ['offerToReceiveVideo', 'video']]) {
          if (opts[key] && !st.tx.some((t) => t.receiver.track.kind === kind)) st.tx.push(rtcTransceiver(kind));
        }
      }
      // Section order: audio, video, data (as Chrome lays them out with legacy
      // offer options).
      st.tx.sort((a, b) => (a.receiver.track.kind === 'audio' ? 0 : 1) - (b.receiver.track.kind === 'audio' ? 0 : 1));
      if (!st.kinds.length) st.kinds = this.__ptKinds();
      // Chrome builds the offer on its own thread (~25 ms) and returns an
      // RTCSessionDescriptionInit dict, not an RTCSessionDescription.
      const sdp = this.__ptSdp(false);
      await new Promise((r) => setTimeout(r, 20 + Math.random() * 8));
      return { sdp, type: 'offer' };
    }
    async createAnswer() {
      const sdp = __s_replace(this.__ptSdp(false), /a=setup:actpass/g, 'a=setup:active');
      await new Promise((r) => setTimeout(r, 5));
      return { sdp, type: 'answer' };
    }
    async setLocalDescription(desc) {
      const st = this.__pt;
      if (!st.kinds.length) st.kinds = this.__ptKinds();
      const type = (desc && desc.type) || 'offer';
      const value = rtcDesc(type, (desc && desc.sdp) || this.__ptSdp(false));
      __pt_write(this, 'localDescription', value);
      __pt_write(this, 'pendingLocalDescription', type === 'offer' ? value : null);
      __pt_write(this, 'currentLocalDescription', type === 'offer' ? null : value);
      st.tx.forEach((t, i) => __pt_write(t, 'mid', String(i)));
      const was = this.signalingState;
      __pt_write(this, 'signalingState', type === 'offer' ? 'have-local-offer' : 'stable');
      if (was !== this.signalingState) this.__ptFire('signalingstatechange');
      setTimeout(() => this.__ptGather(), 0);
    }
    async setRemoteDescription(desc) {
      __pt_write(this, 'remoteDescription', desc ? rtcDesc(desc.type, desc.sdp) : null);
      __pt_write(this, 'signalingState', 'stable');
    }
    __ptRefreshLocal() {
      const st = this.__pt, ld = this.localDescription;
      if (!ld || ld.type !== 'offer') return;
      const v = rtcDesc(ld.type, this.__ptSdp(true));
      __pt_write(this, 'localDescription', v);
      __pt_write(this, 'pendingLocalDescription', v);
    }
    __ptAddCand(idx, f) {
      const st = this.__pt;
      const base = 'candidate:' + f.foundation + ' 1 udp ' + f.priority + ' ' + f.address + ' ' + f.port + ' typ ' + f.type
        + (f.type === 'srflx' ? ' raddr ' + f.raddr + ' rport 0' : '') + ' generation 0';
      const line = base + ' ufrag ' + st.ufrag + ' network-cost 999';
      st.cands.push({ idx, sdpLine: base + ' network-cost 999' });
      if (f.type === 'srflx' && f.fam === 4) st.srflx4[idx] = { ip: f.address, port: f.port };
      this.__ptRefreshLocal();
      this.__ptFire('icecandidate', { candidate: rtcCandidate(line, idx, idx, st.ufrag, f) });
    }
    __ptGather() {
      const st = this.__pt;
      if (st.gathered || st.closed) return;
      st.gathered = true;
      __pt_write(this, 'iceGatheringState', 'gathering');
      this.__ptFire('icegatheringstatechange');
      const n = st.kinds.length;
      const servers = [];
      try {
        for (const s of (st.config.iceServers || [])) {
          for (const u of [].concat(s && s.urls || s && s.url || [])) {
            const m = /^stuns?:([^:?]+|\[[^\]]+\])(?::(\d+))?/.exec(String(u));
            if (m) servers.push(__s_replace(m[1], /^\[|\]$/g, '') + ':' + (m[2] || '3478'));
          }
        }
      } catch (e) {}
      let job = null;
      try { if (typeof __pt_rtcStart === 'function') job = JSON.parse(__pt_rtcStart(n, JSON.stringify(servers))); } catch (e) {}
      const rnd = () => 32768 + Math.floor(Math.random() * 28000);
      const ports4 = (job && job.v4) || Array.from({ length: n }, rnd);
      const ports6 = (job && job.v6) || [];
      const self = this;
      setTimeout(() => {
        if (st.closed) return;
        for (let i = 0; i < n; i++) {
          if (ports4[i]) self.__ptAddCand(i, { fam: 4, type: 'host', foundation: st.fh4, priority: 2113937151, address: st.mdns4, port: ports4[i] });
          if (ports6[i]) self.__ptAddCand(i, { fam: 6, type: 'host', foundation: st.fh6, priority: 2113939711, address: st.mdns6, port: ports6[i] });
        }
        const finish = () => setTimeout(() => {
          if (st.closed) return;
          __pt_write(self, 'iceGatheringState', 'complete');
          self.__ptFire('icegatheringstatechange');
          self.__ptFire('icecandidate', { candidate: null });
        }, 60);
        if (!job) { finish(); return; }
        const poll = () => {
          if (st.closed) return;
          let r = { r: [], done: true };
          try { r = JSON.parse(__pt_rtcPoll(job.id)); } catch (e) {}
          for (const [fam, i, ip, port] of r.r) {
            self.__ptAddCand(i, fam === 4
              ? { fam: 4, type: 'srflx', foundation: st.fs4, priority: 1677729535, address: ip, port, raddr: '0.0.0.0' }
              : { fam: 6, type: 'srflx', foundation: st.fs6, priority: 1677732095, address: ip, port, raddr: '::' });
          }
          if (r.done) finish(); else setTimeout(poll, 4);
        };
        setTimeout(poll, 4);
      }, 2);
    }
    addIceCandidate() { return Promise.resolve(); }
    getStats() { return Promise.resolve(new Map()); }
    getSenders() { return this.__pt.tx.map((t) => t.sender); }
    getReceivers() { return this.__pt.tx.map((t) => t.receiver); }
    getTransceivers() { return __s_slice(this.__pt.tx); }
    getConfiguration() { return this.__pt.config; }
    setConfiguration(c) { this.__pt.config = c || {}; }
    restartIce() {}
    close() {
      const st = this.__pt;
      if (st.closed) return;
      st.closed = true;
      __pt_write(this, 'signalingState', 'closed');
      __pt_write(this, 'iceConnectionState', 'closed');
      __pt_write(this, 'connectionState', 'closed');
    }
  }, 'RTCPeerConnection');

  // Codecs and header extensions: Chrome 151's list (getCapabilities).
  // RTCRtp* interfaces appear after this layer, so a late pass installs them
  // (SHAPE_FIXES calls __pt_installRtcCaps).
  Object.defineProperty(globalThis, '__pt_installRtcCaps', { configurable: true, value: () => {
  for (const n of ['RTCRtpReceiver', 'RTCRtpSender']) {
    const C = globalThis[n];
    if (typeof C !== 'function') continue;
    const f = ({ getCapabilities(kind) {
      if (arguments.length < 1) throw __pt_mkErr(TypeError, "Failed to execute 'getCapabilities' on '" + n + "': 1 argument required, but only 0 present.");
      const v = RTC_CHROME.caps[n + '.' + String(kind)];
      return v ? JSON.parse(JSON.stringify(v)) : null;
    } }).getCapabilities;
    try { Object.defineProperty(C, 'getCapabilities', { value: mask(f, 'getCapabilities'), writable: true, enumerable: true, configurable: true }); } catch (e) {}
  }
  } });

  globalThis.webkitRTCPeerConnection = globalThis.RTCPeerConnection;

  // --- extra Web APIs so real sites' scripts run (and their trackers fire) --
  // A bare V8 has none of these; their absence makes analytics/framework code
  // throw before it does anything (incl. its network beacons).
  // `localStorage` is a Storage interface, not a literal: pages read
  // `Object.prototype.toString.call(localStorage)` like everything else.
  const StorageData = new WeakMap();
  const Storage = __ptIllegal('Storage');
  {
    const P = Storage.prototype, data = (o) => StorageData.get(o) || new Map();
    const put = (name, f) => {
      try { Object.defineProperty(f, 'name', { value: name, configurable: true }); } catch (e) {}
      Object.defineProperty(P, name, { value: mask(f, name), writable: true, enumerable: true, configurable: true });
    };
    // As many args as the browser requires: a call without them is refused
    // with the exact text.
    const need = (got, want, method) => {
      if (got >= want) return;
      throw __pt_mkErr(TypeError, "Failed to execute '" + method + "' on 'Storage': " + want +
        ' argument' + (want === 1 ? '' : 's') + ' required, but only ' + got + ' present.');
    };
    put('getItem', function (k) {
      need(arguments.length, 1, 'getItem');
      const m = data(this); return m.has(String(k)) ? m.get(String(k)) : null;
    });
    put('setItem', function (k, v) {
      need(arguments.length, 2, 'setItem');
      data(this).set(String(k), String(v));
    });
    put('removeItem', function (k) {
      need(arguments.length, 1, 'removeItem');
      data(this).delete(String(k));
    });
    put('clear', function () { data(this).clear(); });
    put('key', function (i) { const ks = [...data(this).keys()]; return i < ks.length ? ks[i] : null; });
    Object.defineProperty(P, 'length', {
      get: mask(function length() { return data(this).size; }, 'get length'),
      enumerable: true, configurable: true,
    });
    Object.defineProperty(P, Symbol.toStringTag, { value: 'Storage', configurable: true });
    globalThis.Storage = mask(Storage, 'Storage');
  }
  const makeStorage = () => {
    const m = new Map();
    // The storage itself has no own properties except page keys; everything
    // else is on the prototype, as in the browser.
    const api = Object.create(Storage.prototype);
    StorageData.set(api, m);
    // A symbol is an ordinary object property, not a storage key: in Chrome
    // `localStorage[sym] = 1; delete localStorage[sym]` leaves data untouched
    // and no trace.
    const sym = (p) => typeof p === 'symbol';
    const proxy = __pt_proxy(api, {
      get: (t, p) => (p in t || sym(p) ? t[p] : (m.has(p) ? m.get(p) : undefined)),
      set: (t, p, v, r) => { if (sym(p)) return Reflect.set(t, p, v); if (p in t) return true; m.set(String(p), String(v)); return true; },
      has: (t, p) => p in t || (!sym(p) && m.has(p)),
      deleteProperty: (t, p) => { if (sym(p)) return Reflect.deleteProperty(t, p); m.delete(String(p)); return true; },
      // Storage keys are own properties: in the browser `Object.keys(localStorage)`
      // lists what is stored.
      ownKeys: (t) => [...new Set([...m.keys(), ...Reflect.ownKeys(t)])],
      getOwnPropertyDescriptor: (t, p) => (!sym(p) && m.has(p)
        ? { value: m.get(String(p)), writable: true, enumerable: true, configurable: true }
        : Reflect.getOwnPropertyDescriptor(t, p)),
    });
    // Methods are called with `this` being the Proxy the page holds, not its
    // target; without this `data(this)` found nothing and returned a fresh
    // empty map each time.
    StorageData.set(proxy, m);
    return proxy;
  };
  if (!globalThis.localStorage) globalThis.localStorage = makeStorage();
  if (!globalThis.sessionStorage) globalThis.sessionStorage = makeStorage();
  {
    // Storage belongs to the origin (localStorage) and to the tab plus origin
    // (sessionStorage), while each document has its own context: the engine
    // takes them on navigation and hands them to the next same-origin document.
    const local = StorageData.get(globalThis.localStorage), session = StorageData.get(globalThis.sessionStorage);
    const fill = (m, o) => { if (m && o && typeof o === 'object') for (const k of Object.keys(o)) m.set(k, String(o[k])); };
    (globalThis.__pt_carryParts || (globalThis.__pt_carryParts = {})).storage = {
      out: () => ({ local: local ? Object.fromEntries(local) : {}, session: session ? Object.fromEntries(session) : {} }),
      in: (v) => { if (v) { fill(local, v.local); fill(session, v.session); } },
    };
    const parts = globalThis.__pt_carryParts;
    // What the leaving document passes on: a JSON string for the engine.
    globalThis.__pt_carryOut = () => {
      const out = {};
      for (const k of Object.keys(parts)) { try { out[k] = parts[k].out(); } catch (e) {} }
      return __ptJSON.stringify(out);
    };
    // Before the new document's first script: what the engine kept for its origin.
    globalThis.__pt_carryIn = (json) => {
      let v; try { v = __ptJSON.parse(json); } catch (e) { return; }
      for (const k of Object.keys(parts)) { try { if (k in v) parts[k].in(v[k]); } catch (e) {} }
    };
  }

  // Not `||`: the name table already put an empty function here, and the
  // browser delivers the first observation immediately; code waits for it.
  globalThis.IntersectionObserver = class IntersectionObserver {
    constructor(cb, opts) {
      this._cb = cb;
      // The observer exposes thresholds and margins, and they are read: a list
      // of numbers and four space-separated sides.
      const t = opts && opts.threshold;
      const list = t === undefined ? [0] : (Array.isArray(t) ? __s_slice(t) : [Number(t) || 0]);
      const margin = __s_split(__s_trim(String((opts && opts.rootMargin) || '0px')), /\s+/);
      const four = margin.length === 1 ? [margin[0], margin[0], margin[0], margin[0]]
        : margin.length === 2 ? [margin[0], margin[1], margin[0], margin[1]]
        : margin.length === 3 ? [margin[0], margin[1], margin[2], margin[1]]
        : __s_slice(margin, 0, 4);
      Object.defineProperty(this, '__ptOpts', {
        value: { thresholds: Object.freeze(list), rootMargin: four.join(' '),
                 root: (opts && opts.root) || null, delay: (opts && opts.delay) | 0,
                 scrollMargin: '0px 0px 0px 0px', trackVisibility: !!(opts && opts.trackVisibility) },
        enumerable: false,
      });
    }
    get thresholds() { return this.__ptOpts.thresholds; }
    get rootMargin() { return this.__ptOpts.rootMargin; }
    get root() { return this.__ptOpts.root; }
    get delay() { return this.__ptOpts.delay; }
    get scrollMargin() { return this.__ptOpts.scrollMargin; }
    get trackVisibility() { return this.__ptOpts.trackVisibility; }
    observe(el) { const cb = this._cb, self = this; setTimeout(() => { try { cb([{ target: el, isIntersecting: true, intersectionRatio: 1, boundingClientRect: {}, intersectionRect: {}, rootBounds: null, time: 0 }], self); } catch (e) {} }, 0); }
    unobserve() {} disconnect() {} takeRecords() { return []; }
  };
  try {
    const P = globalThis.IntersectionObserver.prototype;
    Object.defineProperty(P, Symbol.toStringTag, { value: 'IntersectionObserver', configurable: true });
    mask(globalThis.IntersectionObserver, 'IntersectionObserver');
    for (const m of ['observe', 'unobserve', 'disconnect', 'takeRecords']) {
      if (typeof P[m] === 'function') mask(P[m], m);
    }
  } catch (e) {}
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
    // A normal tab is `display-mode: browser`; other modes are apps.
    else if (/display-mode\s*:\s*browser/i.test(query)) matches = true;
    else if (/display-mode\s*:\s*(standalone|fullscreen|minimal-ui|window-controls-overlay|picture-in-picture)/i.test(query)) matches = false;
    else if (/scripting\s*:\s*enabled/i.test(query)) matches = true;
    else if (/update\s*:\s*fast/i.test(query)) matches = true;
    else if (/color-gamut\s*:\s*srgb/i.test(query)) matches = true;
    else if (/forced-colors\s*:\s*none/i.test(query)) matches = true;
    else if (/inverted-colors\s*:\s*none/i.test(query)) matches = true;
    else {
      const maxW = num(/max-width\s*:\s*(\d+(?:\.\d+)?)px/i), minW = num(/min-width\s*:\s*(\d+(?:\.\d+)?)px/i);
      const maxH = num(/max-height\s*:\s*(\d+(?:\.\d+)?)px/i), minH = num(/min-height\s*:\s*(\d+(?:\.\d+)?)px/i);
      if (maxW !== null || minW !== null || maxH !== null || minH !== null) {
        matches = (maxW === null || w <= maxW) && (minW === null || w >= minW)
               && (maxH === null || h <= maxH) && (minH === null || h >= minH);
      }
    }
    const listeners = [];
    // An interface object, not a literal: pages read
    // `Object.prototype.toString.call(matchMedia(...))`.
    const MQL = globalThis.MediaQueryList;
    const proto = MQL && MQL.prototype ? MQL.prototype : Object.prototype;
    // The browser's `matches` and `media` are read-only: set them via internal
    // write, otherwise `Object.assign` fails on our own interface.
    const mql = Object.create(proto);
    __pt_write(mql, 'matches', matches);
    __pt_write(mql, 'media', query);
    return Object.assign(mql, {
      onchange: null,
      addListener: (f) => { if (f) listeners.push(f); },
      removeListener: (f) => { const i = __s_indexOf(listeners, f); if (i >= 0) listeners.splice(i, 1); },
      addEventListener: (t, f) => { if (t === 'change' && f) listeners.push(f); },
      removeEventListener: (t, f) => { const i = __s_indexOf(listeners, f); if (i >= 0) listeners.splice(i, 1); },
      dispatchEvent: () => false,
    });
  };
  globalThis.getComputedStyle = globalThis.getComputedStyle || (() => ({ getPropertyValue: () => '', getPropertyPriority: () => '', length: 0, cssText: '', item: () => '', display: '', visibility: 'visible' }));
  // The browser's idle period comes after the next frame, not after a millisecond.
  globalThis.requestIdleCallback = globalThis.requestIdleCallback || ((cb) => setTimeout(() => cb({ didTimeout: false, timeRemaining: () => 50 }), 18));
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
    // A frame removed from the document is hidden, as in the browser.
    Object.defineProperty(dproto, 'visibilityState', { get: () => (globalThis.__ptDetached ? 'hidden' : 'visible'), configurable: true });
    Object.defineProperty(dproto, 'hidden', { get: () => !!globalThis.__ptDetached, configurable: true });
  } catch (e) {}

  if (!globalThis.TextDecoder) {
  // The challenge builds strings from bytes with TextDecoder, and every
  // upper-half byte must decode exactly as in the browser or the hash
  // differs. `latin1` in the browser is windows-1252 (0x80 is the euro sign).
  // Upper halves of single-byte encodings follow the Encoding Standard
  // indexes (encoding.spec.whatwg.org/index-*.txt), including windows-1252,
  // where the challenge puts canvas bytes. Python codec tables are wrong here:
  // they leave 0x81/0x8D/0x8F/0x90/0x9D undefined (U+FFFD), while the
  // standard maps them to the C1 controls U+0081...
    const HIGH = JSON.parse("{\"windows-1250\": \"€‚„…†‡‰Š‹ŚŤŽŹ‘’“”•–—™š›śťžź ˇ˘Ł¤Ą¦§¨©Ş«¬­®Ż°±˛ł´µ¶·¸ąş»Ľ˝ľżŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖ×ŘŮÚŰÜÝŢßŕáâăäĺćçčéęëěíîďđńňóôőö÷řůúűüýţ˙\", \"windows-1251\": \"\u0402\u0403‚\u0453„…†‡€‰\u0409‹\u040a\u040c\u040b\u040f\u0452‘’“”•–—™\u0459›\u045a\u045c\u045b\u045f \u040e\u045e\u0408¤\u0490¦§\u0401©\u0404«¬­®\u0407°±\u0406\u0456\u0491µ¶·\u0451№\u0454»\u0458\u0405\u0455\u0457\u0410\u0411\u0412\u0413\u0414\u0415\u0416\u0417\u0418\u0419\u041a\u041b\u041c\u041d\u041e\u041f\u0420\u0421\u0422\u0423\u0424\u0425\u0426\u0427\u0428\u0429\u042a\u042b\u042c\u042d\u042e\u042f\u0430\u0431\u0432\u0433\u0434\u0435\u0436\u0437\u0438\u0439\u043a\u043b\u043c\u043d\u043e\u043f\u0440\u0441\u0442\u0443\u0444\u0445\u0446\u0447\u0448\u0449\u044a\u044b\u044c\u044d\u044e\u044f\", \"windows-1252\": \"€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ\", \"windows-1253\": \"€‚ƒ„…†‡‰‹‘’“”•–—™› ΅Ά£¤¥¦§¨©�«¬­®―°±²³΄µ¶·ΈΉΊ»Ό½ΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡ�ΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ�\", \"windows-1254\": \"€‚ƒ„…†‡ˆ‰Š‹Œ‘’“”•–—˜™š›œŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏĞÑÒÓÔÕÖ×ØÙÚÛÜİŞßàáâãäåæçèéêëìíîïğñòóôõö÷øùúûüışÿ\", \"windows-1255\": \"€‚ƒ„…†‡ˆ‰‹‘’“”•–—˜™› ¡¢£₪¥¦§¨©×«¬­®¯°±²³´µ¶·¸¹÷»¼½¾¿ְֱֲֳִֵֶַָֹֺֻּֽ־ֿ׀ׁׂ׃װױײ׳״�������אבגדהוזחטיךכלםמןנסעףפץצקרשת��‎‏�\", \"windows-1256\": \"€پ‚ƒ„…†‡ˆ‰ٹ‹Œچژڈگ‘’“”•–—ک™ڑ›œ‌‍ں ،¢£¤¥¦§¨©ھ«¬­®¯°±²³´µ¶·¸¹؛»¼½¾؟ہءآأؤإئابةتثجحخدذرزسشصض×طظعغـفقكàلâمنهوçèéêëىيîïًٌٍَôُِ÷ّùْûü‎‏ے\", \"windows-1257\": \"€‚„…†‡‰‹¨ˇ¸‘’“”•–—™›¯˛ �¢£¤�¦§Ø©Ŗ«¬­®Æ°±²³´µ¶·ø¹ŗ»¼½¾æĄĮĀĆÄÅĘĒČÉŹĖĢĶĪĻŠŃŅÓŌÕÖ×ŲŁŚŪÜŻŽßąįāćäåęēčéźėģķīļšńņóōõö÷ųłśūüżž˙\", \"windows-1258\": \"€‚ƒ„…†‡ˆ‰‹Œ‘’“”•–—˜™›œŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂĂÄÅÆÇÈÉÊË̀ÍÎÏĐÑ̉ÓÔƠÖ×ØÙÚÛÜỮßàáâăäåæçèéêë́íîïđṇ̃óôơö÷øùúûüư₫ÿ\", \"iso-8859-2\": \" Ą˘Ł¤ĽŚ§¨ŠŞŤŹ­ŽŻ°ą˛ł´ľśˇ¸šşťź˝žżŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖ×ŘŮÚŰÜÝŢßŕáâăäĺćçčéęëěíîďđńňóôőö÷řůúűüýţ˙\", \"iso-8859-3\": \" Ħ˘£¤�Ĥ§¨İŞĞĴ­�Ż°ħ²³´µĥ·¸ışğĵ½�żÀÁÂ�ÄĊĈÇÈÉÊËÌÍÎÏ�ÑÒÓÔĠÖ×ĜÙÚÛÜŬŜßàáâ�äċĉçèéêëìíîï�ñòóôġö÷ĝùúûüŭŝ˙\", \"iso-8859-4\": \" ĄĸŖ¤ĨĻ§¨ŠĒĢŦ­Ž¯°ą˛ŗ´ĩļˇ¸šēģŧŊžŋĀÁÂÃÄÅÆĮČÉĘËĖÍÎĪĐŅŌĶÔÕÖ×ØŲÚÛÜŨŪßāáâãäåæįčéęëėíîīđņōķôõö÷øųúûüũū˙\", \"iso-8859-5\": \" \u0401\u0402\u0403\u0404\u0405\u0406\u0407\u0408\u0409\u040a\u040b\u040c­\u040e\u040f\u0410\u0411\u0412\u0413\u0414\u0415\u0416\u0417\u0418\u0419\u041a\u041b\u041c\u041d\u041e\u041f\u0420\u0421\u0422\u0423\u0424\u0425\u0426\u0427\u0428\u0429\u042a\u042b\u042c\u042d\u042e\u042f\u0430\u0431\u0432\u0433\u0434\u0435\u0436\u0437\u0438\u0439\u043a\u043b\u043c\u043d\u043e\u043f\u0440\u0441\u0442\u0443\u0444\u0445\u0446\u0447\u0448\u0449\u044a\u044b\u044c\u044d\u044e\u044f№\u0451\u0452\u0453\u0454\u0455\u0456\u0457\u0458\u0459\u045a\u045b\u045c§\u045e\u045f\", \"iso-8859-6\": \" ���¤�������،­�������������؛���؟�ءآأؤإئابةتثجحخدذرزسشصضطظعغ�����ـفقكلمنهوىيًٌٍَُِّْ�������������\", \"iso-8859-7\": \" ‘’£€₯¦§¨©ͺ«¬­�―°±²³΄΅Ά·ΈΉΊ»Ό½ΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡ�ΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ�\", \"iso-8859-8\": \" �¢£¤¥¦§¨©×«¬­®¯°±²³´µ¶·¸¹÷»¼½¾��������������������������������‗אבגדהוזחטיךכלםמןנסעףפץצקרשת��‎‏�\", \"iso-8859-10\": \" ĄĒĢĪĨĶ§ĻĐŠŦŽ­ŪŊ°ąēģīĩķ·ļđšŧž―ūŋĀÁÂÃÄÅÆĮČÉĘËĖÍÎÏÐŅŌÓÔÕÖŨØŲÚÛÜÝÞßāáâãäåæįčéęëėíîïðņōóôõöũøųúûüýþĸ\", \"iso-8859-13\": \" ”¢£¤„¦§Ø©Ŗ«¬­®Æ°±²³“µ¶·ø¹ŗ»¼½¾æĄĮĀĆÄÅĘĒČÉŹĖĢĶĪĻŠŃŅÓŌÕÖ×ŲŁŚŪÜŻŽßąįāćäåęēčéźėģķīļšńņóōõö÷ųłśūüżž’\", \"iso-8859-14\": \" Ḃḃ£ĊċḊ§Ẁ©ẂḋỲ­®ŸḞḟĠġṀṁ¶ṖẁṗẃṠỳẄẅṡÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏŴÑÒÓÔÕÖṪØÙÚÛÜÝŶßàáâãäåæçèéêëìíîïŵñòóôõöṫøùúûüýŷÿ\", \"iso-8859-15\": \" ¡¢£€¥Š§š©ª«¬­®¯°±²³Žµ¶·ž¹º»ŒœŸ¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ\", \"iso-8859-16\": \" ĄąŁ€„Š§š©Ș«Ź­źŻ°±ČłŽ”¶·žčș»ŒœŸżÀÁÂĂÄĆÆÇÈÉÊËÌÍÎÏĐŃÒÓÔŐÖŚŰÙÚÛÜĘȚßàáâăäćæçèéêëìíîïđńòóôőöśűùúûüęțÿ\", \"koi8-r\": \"─│┌┐└┘├┤┬┴┼▀▄█▌▐░▒▓⌠■∙√≈≤≥ ⌡°²·÷═║╒\u0451╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡\u0401╢╣╤╥╦╧╨╩╪╫╬©\u044e\u0430\u0431\u0446\u0434\u0435\u0444\u0433\u0445\u0438\u0439\u043a\u043b\u043c\u043d\u043e\u043f\u044f\u0440\u0441\u0442\u0443\u0436\u0432\u044c\u044b\u0437\u0448\u044d\u0449\u0447\u044a\u042e\u0410\u0411\u0426\u0414\u0415\u0424\u0413\u0425\u0418\u0419\u041a\u041b\u041c\u041d\u041e\u041f\u042f\u0420\u0421\u0422\u0423\u0416\u0412\u042c\u042b\u0417\u0428\u042d\u0429\u0427\u042a\", \"koi8-u\": \"─│┌┐└┘├┤┬┴┼▀▄█▌▐░▒▓⌠■∙√≈≤≥ ⌡°²·÷═║╒\u0451\u0454╔\u0456\u0457╗╘╙╚╛\u0491\u045e╞╟╠╡\u0401\u0404╣\u0406\u0407╦╧╨╩╪\u0490\u040e©\u044e\u0430\u0431\u0446\u0434\u0435\u0444\u0433\u0445\u0438\u0439\u043a\u043b\u043c\u043d\u043e\u043f\u044f\u0440\u0441\u0442\u0443\u0436\u0432\u044c\u044b\u0437\u0448\u044d\u0449\u0447\u044a\u042e\u0410\u0411\u0426\u0414\u0415\u0424\u0413\u0425\u0418\u0419\u041a\u041b\u041c\u041d\u041e\u041f\u042f\u0420\u0421\u0422\u0423\u0416\u0412\u042c\u042b\u0417\u0428\u042d\u0429\u0427\u042a\", \"macintosh\": \"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄€‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ\", \"ibm866\": \"\u0410\u0411\u0412\u0413\u0414\u0415\u0416\u0417\u0418\u0419\u041a\u041b\u041c\u041d\u041e\u041f\u0420\u0421\u0422\u0423\u0424\u0425\u0426\u0427\u0428\u0429\u042a\u042b\u042c\u042d\u042e\u042f\u0430\u0431\u0432\u0433\u0434\u0435\u0436\u0437\u0438\u0439\u043a\u043b\u043c\u043d\u043e\u043f░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀\u0440\u0441\u0442\u0443\u0444\u0445\u0446\u0447\u0448\u0449\u044a\u044b\u044c\u044d\u044e\u044f\u0401\u0451\u0404\u0454\u0407\u0457\u040e\u045e°∙·√№¤■ \"}");
    const LABELS = {
      'utf-8': 'utf-8', 'utf8': 'utf-8', 'unicode-1-1-utf-8': 'utf-8', 'unicode11utf8': 'utf-8',
      'x-unicode20utf8': 'utf-8', 'unicode20utf8': 'utf-8',
      'latin1': 'windows-1252', 'iso-8859-1': 'windows-1252', 'windows-1252': 'windows-1252',
      'ascii': 'windows-1252', 'us-ascii': 'windows-1252', 'cp1252': 'windows-1252',
      'iso8859-1': 'windows-1252', 'iso_8859-1': 'windows-1252', 'l1': 'windows-1252',
      'cp819': 'windows-1252', 'ibm819': 'windows-1252', 'csisolatin1': 'windows-1252',
      'utf-16le': 'utf-16le', 'utf-16': 'utf-16le', 'ucs-2': 'utf-16le', 'unicode': 'utf-16le',
      'unicodefeff': 'utf-16le', 'utf-16be': 'utf-16be', 'unicodefffe': 'utf-16be',
      'windows-1250': 'windows-1250', 'cp1250': 'windows-1250', 'x-cp1250': 'windows-1250',
      'windows-1251': 'windows-1251', 'cp1251': 'windows-1251', 'x-cp1251': 'windows-1251',
      'windows-1253': 'windows-1253', 'cp1253': 'windows-1253', 'x-cp1253': 'windows-1253',
      'windows-1254': 'windows-1254', 'cp1254': 'windows-1254', 'x-cp1254': 'windows-1254',
      'iso-8859-9': 'windows-1254', 'iso8859-9': 'windows-1254', 'latin5': 'windows-1254',
      'windows-1255': 'windows-1255', 'cp1255': 'windows-1255', 'x-cp1255': 'windows-1255',
      'windows-1256': 'windows-1256', 'cp1256': 'windows-1256', 'x-cp1256': 'windows-1256',
      'windows-1257': 'windows-1257', 'cp1257': 'windows-1257', 'x-cp1257': 'windows-1257',
      'windows-1258': 'windows-1258', 'cp1258': 'windows-1258', 'x-cp1258': 'windows-1258',
      'iso-8859-2': 'iso-8859-2', 'iso8859-2': 'iso-8859-2', 'latin2': 'iso-8859-2', 'l2': 'iso-8859-2',
      'iso-8859-3': 'iso-8859-3', 'iso8859-3': 'iso-8859-3', 'latin3': 'iso-8859-3',
      'iso-8859-4': 'iso-8859-4', 'iso8859-4': 'iso-8859-4', 'latin4': 'iso-8859-4',
      'iso-8859-5': 'iso-8859-5', 'iso8859-5': 'iso-8859-5', 'cyrillic': 'iso-8859-5',
      'iso-8859-6': 'iso-8859-6', 'iso8859-6': 'iso-8859-6', 'arabic': 'iso-8859-6',
      'iso-8859-7': 'iso-8859-7', 'iso8859-7': 'iso-8859-7', 'greek': 'iso-8859-7',
      'iso-8859-8': 'iso-8859-8', 'iso8859-8': 'iso-8859-8', 'hebrew': 'iso-8859-8',
      'iso-8859-8-i': 'iso-8859-8', 'iso-8859-10': 'iso-8859-10', 'iso-8859-13': 'iso-8859-13',
      'iso-8859-14': 'iso-8859-14', 'iso-8859-15': 'iso-8859-15', 'iso8859-15': 'iso-8859-15',
      'latin9': 'iso-8859-15', 'iso-8859-16': 'iso-8859-16',
      'koi8-r': 'koi8-r', 'koi8_r': 'koi8-r', 'koi': 'koi8-r', 'koi8': 'koi8-r',
      'koi8-u': 'koi8-u', 'koi8-ru': 'koi8-u',
      'macintosh': 'macintosh', 'mac': 'macintosh', 'x-mac-roman': 'macintosh',
      'ibm866': 'ibm866', '866': 'ibm866', 'cp866': 'ibm866', 'csibm866': 'ibm866',
      // The browser knows multi-byte encodings too; the label is accepted and
      // decoded as single-byte: pages using them do not show up in
      // fingerprinting, while a refused label shows immediately.
      'gbk': 'gbk', 'gb18030': 'gb18030', 'gb2312': 'gbk', 'big5': 'big5',
      'euc-jp': 'euc-jp', 'shift_jis': 'shift_jis', 'sjis': 'shift_jis',
      'euc-kr': 'euc-kr', 'iso-2022-jp': 'iso-2022-jp', 'replacement': 'replacement',
      'x-user-defined': 'x-user-defined',
    };
    globalThis.TextDecoder = class TextDecoder {
      constructor(label, opts) {
        const want = __s_toLowerCase(__s_trim(String(label === undefined ? 'utf-8' : label)));
        const enc = LABELS[want];
        if (!enc) throw __pt_mkErr(RangeError, "Failed to construct 'TextDecoder': The encoding label provided ('" + label + "') is invalid.");
        Object.defineProperty(this, '__ptEnc', { value: enc, enumerable: false });
        Object.defineProperty(this, '__ptFatal', { value: !!(opts && opts.fatal), enumerable: false });
        Object.defineProperty(this, '__ptBOM', { value: !!(opts && opts.ignoreBOM), enumerable: false });
      }
      get encoding() { return this.__ptEnc; }
      get fatal() { return this.__ptFatal; }
      get ignoreBOM() { return this.__ptBOM; }
      decode(buf) {
        if (globalThis.__pt_decodeSpy) { try { __pt_decodeSpy(buf); } catch (e) {} }
        if (buf === undefined || buf === null) return '';
        const a = buf instanceof Uint8Array ? buf
          : ArrayBuffer.isView(buf) ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
          : new Uint8Array(buf);
        const enc = this.__ptEnc;
        let s = '';
        const high = HIGH[enc];
        if (high) {
          for (let i = 0; i < a.length; i++) {
            const b = a[i];
            s += b < 0x80 ? String.fromCharCode(b) : high[b - 0x80];
          }
          return s;
        }
        if (enc === 'utf-16be') {
          for (let i = 0; i + 1 < a.length; i += 2) s += String.fromCharCode((a[i] << 8) | a[i + 1]);
          return s;
        }
        if (enc === 'utf-16le') {
          for (let i = 0; i + 1 < a.length; i += 2) s += String.fromCharCode(a[i] | (a[i + 1] << 8));
          return s;
        }
        // utf-8, with U+FFFD replacement exactly where the browser puts it.
        let i = 0;
        if (!this.__ptBOM && a.length >= 3 && a[0] === 0xef && a[1] === 0xbb && a[2] === 0xbf) i = 3;
        const bad = () => { if (this.__ptFatal) throw __pt_mkErr(TypeError, 'Failed to execute \'decode\' on \'TextDecoder\': The encoded data was not valid.'); return '\ufffd'; };
        while (i < a.length) {
          const b = a[i];
          if (b < 0x80) { s += String.fromCharCode(b); i += 1; continue; }
          let need, cp, low, high;
          if (b >= 0xc2 && b <= 0xdf) { need = 1; cp = b & 0x1f; low = 0x80; high = 0xbf; }
          else if (b >= 0xe0 && b <= 0xef) {
            need = 2; cp = b & 0x0f;
            low = b === 0xe0 ? 0xa0 : 0x80; high = b === 0xed ? 0x9f : 0xbf;
          } else if (b >= 0xf0 && b <= 0xf4) {
            need = 3; cp = b & 0x07;
            low = b === 0xf0 ? 0x90 : 0x80; high = b === 0xf4 ? 0x8f : 0xbf;
          } else { s += bad(); i += 1; continue; }
          let ok = true;
          for (let k = 1; k <= need; k++) {
            const c = a[i + k];
            const lo = k === 1 ? low : 0x80, hi = k === 1 ? high : 0xbf;
            if (c === undefined || c < lo || c > hi) { ok = false; i += k; break; }
            cp = (cp << 6) | (c & 0x3f);
          }
          if (!ok) { s += bad(); continue; }
          i += need + 1;
          if (cp > 0xffff) {
            cp -= 0x10000;
            s += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
          } else s += String.fromCharCode(cp);
        }
        return s;
      }
    };
  }
  if (!globalThis.Blob) {
    // Blob parts are not only strings: the browser accepts buffers and views
    // and concatenates bytes. `String(new Uint8Array([104,105]))` is "104,105",
    // not "hi", so a worker built from bytes would get a list of numbers.
    const blobPart = (x) => {
      try {
        if (x instanceof ArrayBuffer || ArrayBuffer.isView(x)) return new TextDecoder().decode(x);
      } catch (e) {}
      return String(x);
    };
    // Parts, type and size are not own properties: a real Blob has none
    // (`Object.getOwnPropertyNames(blob)` is empty), everything is read from
    // the prototype. The key is a symbol, which that enumeration does not show.
    const BLOB = Symbol('blob');
    globalThis.Blob = class Blob {
      constructor(parts, opts) {
        const p = (parts || []).map(blobPart);
        Object.defineProperty(this, BLOB, {
          value: { parts: p, type: (opts && opts.type) || '', size: p.reduce((n, x) => n + x.length, 0) },
        });
      }
      get size() { return this[BLOB].size; }
      get type() { return this[BLOB].type; }
      text() { return Promise.resolve(this[BLOB].parts.join('')); }
      arrayBuffer() { return Promise.resolve(new TextEncoder().encode(this[BLOB].parts.join('')).buffer); }
      bytes() { return Promise.resolve(new TextEncoder().encode(this[BLOB].parts.join(''))); }
      slice() { return new Blob([]); }
      __ptText() { return this[BLOB].parts.join(''); }
    };
    globalThis.__pt_blobParts = (b) => (b && b[BLOB] ? b[BLOB].parts : null);
  }
  // Here rather than with the other web globals: `File` extends `Blob`, which is
  // defined just above, and a class body is evaluated where it is written.
  if (!globalThis.File) {
    globalThis.File = class File extends Blob {
      constructor(parts, name, opts) {
        super(parts, opts);
        __pt_write(this, 'name', String(name));
        __pt_write(this, 'lastModified', (opts && opts.lastModified) || 0);
        __pt_write(this, 'webkitRelativePath', '');
      }
    };
  }
  if (!globalThis.FileReader) {
    globalThis.FileReader = class FileReader {
      constructor() {
        __pt_write(this, 'readyState', 0); __pt_write(this, 'result', null); __pt_write(this, 'error', null);
        this.onload = null; this.onloadend = null; this.onerror = null; this.onprogress = null;
        Object.defineProperty(this, '__ls', { value: {}, enumerable: false });
      }
      addEventListener(t, fn) { (this.__ls[t] = this.__ls[t] || []).push(fn); }
      removeEventListener(t, fn) { const l = this.__ls[t]; if (!l) return; const i = __s_indexOf(l, fn); if (i >= 0) l.splice(i, 1); }
      dispatchEvent() { return true; }
      abort() { __pt_write(this, 'readyState', 2); }
      __ptFire(type) {
        const ev = { type, target: this, currentTarget: this, isTrusted: true };
        try { if (typeof this['on' + type] === 'function') this['on' + type](ev); } catch (e) {}
        for (const fn of __s_slice(this.__ls[type] || [])) { try { fn.call(this, ev); } catch (e) {} }
      }
      __ptRead(blob, make) {
        __pt_write(this, 'readyState', 1);
        Promise.resolve(blob && blob.text ? blob.text() : String(blob)).then((t) => {
          __pt_write(this, 'result', make(t)); __pt_write(this, 'readyState', 2);
          this.__ptFire('load'); this.__ptFire('loadend');
        }, (e) => { __pt_write(this, 'error', e); __pt_write(this, 'readyState', 2); this.__ptFire('error'); this.__ptFire('loadend'); });
      }
      readAsText(b) { this.__ptRead(b, (t) => t); }
      readAsDataURL(b) { this.__ptRead(b, (t) => 'data:' + ((b && b.type) || 'application/octet-stream') + ';base64,' + btoa(t)); }
      readAsArrayBuffer(b) { this.__ptRead(b, (t) => new TextEncoder().encode(t).buffer); }
      readAsBinaryString(b) { this.__ptRead(b, (t) => t); }
    };
  }
  if (!globalThis.FormData) {
    globalThis.FormData = class FormData { constructor() { this.__ptD = []; } append(k, v) { this.__ptD.push([String(k), v]); } set(k, v) { this.delete(k); this.append(k, v); } get(k) { const e = this.__ptD.find((x) => x[0] === k); return e ? e[1] : null; } getAll(k) { return this.__ptD.filter((x) => x[0] === k).map((x) => x[1]); } has(k) { return this.__ptD.some((x) => x[0] === k); } delete(k) { this.__ptD = this.__ptD.filter((x) => x[0] !== k); } forEach(f) { for (const [k, v] of this.__ptD) f(v, k, this); } keys() { return this.__ptD.map((x) => x[0])[Symbol.iterator](); } values() { return this.__ptD.map((x) => x[1])[Symbol.iterator](); } entries() { return this.__ptD.map((x) => [x[0], x[1]])[Symbol.iterator](); } [Symbol.iterator]() { return this.entries(); } toString() { return this.__ptD.map(([k, v]) => k + '=' + v).join('&'); } };
  }

  // Params owned by a URL (`url.searchParams`) rewrite its query when edited;
  // a hidden link, not a property on the object.
  const PARAMS_OWNER = new WeakMap();
  const syncOwner = (p) => { const st = PARAMS_OWNER.get(p); if (!st) return; const q = p.toString(); st.query = q ? '?' + q : ''; };
  if (!globalThis.URLSearchParams) {
    globalThis.URLSearchParams = class URLSearchParams {
      constructor(init) { this.__ptD = [];
        if (typeof init === 'string') { __s_split(__s_replace(init, /^[?]/, ''), '&').forEach((p) => { if (!p) return; const i = __s_indexOf(p, '='); const k = decodeURIComponent(i < 0 ? p : __s_slice(p, 0, i)); const v = i < 0 ? '' : decodeURIComponent(__s_replace(__s_slice(p, i + 1), /[+]/g, ' ')); this.__ptD.push([k, v]); }); }
        else if (init && typeof init === 'object') { for (const k in init) this.__ptD.push([k, String(init[k])]); } }
      get(k) { const e = this.__ptD.find((x) => x[0] === k); return e ? e[1] : null; }
      getAll(k) { return this.__ptD.filter((x) => x[0] === k).map((x) => x[1]); }
      has(k) { return this.__ptD.some((x) => x[0] === k); }
      set(k, v) { const e = this.__ptD.find((x) => x[0] === k); if (e) e[1] = String(v); else this.__ptD.push([k, String(v)]); syncOwner(this); }
      append(k, v) { this.__ptD.push([k, String(v)]); syncOwner(this); }
      delete(k) { this.__ptD = this.__ptD.filter((x) => x[0] !== k); syncOwner(this); }
      forEach(f) { for (const [k, v] of this.__ptD) f(v, k, this); }
      keys() { return this.__ptD.map((x) => x[0])[Symbol.iterator](); }
      values() { return this.__ptD.map((x) => x[1])[Symbol.iterator](); }
      entries() { return this.__ptD.map((x) => [x[0], x[1]])[Symbol.iterator](); }
      // The browser provides iteration and count on the object itself:
      // `[...params]` and `params.size` are common on any page.
      [Symbol.iterator]() { return this.entries(); }
      get size() { return this.__ptD.length; }
      sort() { this.__ptD.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)); syncOwner(this); }
      toString() { return this.__ptD.map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&'); }
    };
  }
  if (!globalThis.URL || !globalThis.URL.prototype || !('searchParams' in (globalThis.URL.prototype || {}))) {
    const parse = (s) => { const m = /^([a-zA-Z][a-zA-Z0-9+.-]*:)?([/][/]([^/?#]*))?([^?#]*)([?][^#]*)?([#].*)?$/.exec(String(s)) || []; return { protocol: m[1] || '', authority: m[3] || '', path: m[4] || '', search: m[5] || '', hash: m[6] || '' }; };
    let blobSeq = 1;
    // UUID of the browser's form (version 4, variant 8..b), but derived from
    // the profile seed: the same profile yields the same sequence.
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
      return __s_slice(s, 0, 8) + '-' + __s_slice(s, 8, 12) + '-' + __s_slice(s, 12, 16) + '-' + __s_slice(s, 16, 20) + '-' + __s_slice(s, 20);
    };
    // URL parsing per the URL standard rules: lowercase scheme and host, drop
    // the default port, collapse `..` in paths, percent-encode spaces,
    // punycode, and `mailto:` stays without `//`. URLs are read from
    // everywhere (`<a>`, `location`, `URL` itself).
    const SPECIAL = { 'http:': '80', 'https:': '443', 'ws:': '80', 'wss:': '443', 'ftp:': '21', 'file:': '' };
    // Punycode: the browser writes non-ASCII hostnames as `xn--...`.
    const punyEncode = (label) => {
      if (!/[^\x00-\x7f]/.test(label)) return label;
      const base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;
      const cps = Array.from(label).map((c) => __s_codePointAt(c, 0));
      const basic = cps.filter((c) => c < 128);
      let out = basic.map((c) => String.fromCharCode(c)).join('');
      let h = basic.length;
      const delim = h > 0 ? '-' : '';
      let n = initialN, delta = 0, bias = initialBias;
      const adapt = (d, num, first) => {
        d = first ? Math.floor(d / damp) : d >> 1;
        d += Math.floor(d / num);
        let k = 0;
        while (d > ((base - tmin) * tmax) >> 1) { d = Math.floor(d / (base - tmin)); k += base; }
        return k + Math.floor(((base - tmin + 1) * d) / (d + skew));
      };
      while (h < cps.length) {
        let m = Infinity;
        for (const c of cps) if (c >= n && c < m) m = c;
        delta += (m - n) * (h + 1);
        n = m;
        for (const c of cps) {
          if (c < n) delta++;
          if (c !== n) continue;
          let q = delta;
          for (let k = base; ; k += base) {
            const t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
            if (q < t) break;
            out += String.fromCharCode(t + ((q - t) % (base - t)) < 26
              ? t + ((q - t) % (base - t)) + 97
              : t + ((q - t) % (base - t)) + 22);
            q = Math.floor((q - t) / (base - t));
          }
          out += String.fromCharCode(q < 26 ? q + 97 : q + 22);
          bias = adapt(delta, h + 1, h === basic.length);
          delta = 0;
          h++;
        }
        delta++; n++;
      }
      return 'xn--' + (delim ? out : out);
    };
    const encHost = (h) => __s_split(h, '.').map(punyEncode).join('.');
    // The browser percent-encodes spaces and non-ASCII in paths; already
    // encoded sequences are left alone.
    const encPath = (p) => __s_replace(p, /[^\x21-\x7e]|[\\"<>^`{|}]/g, (c) =>
      Array.from(new TextEncoder().encode(c)).map((b) => '%' + __s_padStart(__s_toUpperCase(b.toString(16)), 2, '0')).join(''));
    // Query and fragment are percent-encoded too: space, quote, angle
    // brackets, non-ASCII; the fragment also backtick.
    const pct = (c) => Array.from(new TextEncoder().encode(c)).map((b) => '%' + __s_padStart(__s_toUpperCase(b.toString(16)), 2, '0')).join('');
    const encQuery = (q, special) => __s_replace(q, special ? /[^\x21-\x7e]|[#"<>']/g : /[^\x21-\x7e]|[#"<>]/g, pct);
    const encFrag = (f) => __s_replace(f, /[^\x21-\x7e]|["<>`]/g, pct);
    const normPath = (p) => {
      const abs = __s_startsWith(p, '/');
      const out = [];
      for (const seg of __s_split(p, '/')) {
        if (seg === '.' || (seg === '' && out.length && abs)) continue;
        if (seg === '..') { out.pop(); continue; }
        out.push(seg);
      }
      let r = out.join('/');
      if (abs && !__s_startsWith(r, '/')) r = '/' + r;
      if (/\/(\.|\.\.)$/.test(p) && !__s_endsWith(r, '/')) r += '/';
      return r || (abs ? '/' : '');
    };
    const URL_STATE = new WeakMap();
    // URL params: editing them (`append`, `set`, `delete`, `sort`) changes the
    // URL's own query string, as URL and URLSearchParams are linked in the browser.
    const linkParams = (st) => {
      const p = new globalThis.URLSearchParams(st.query);
      PARAMS_OWNER.set(p, st);
      return p;
    };
    const parseInto = (st, raw, base) => {
      let s = __s_trim(String(raw));
      const m = /^([a-zA-Z][a-zA-Z0-9+.\-]*):/.exec(s);
      let scheme = m ? __s_toLowerCase(m[1]) + ':' : '';
      if (scheme) s = __s_slice(s, m[0].length);
      if (!scheme) {
        if (!base) return false;
        const b = URL_STATE.get(base) || base;
        scheme = b.scheme;
        if (!__s_startsWith(s, '//')) {
          // Relative URL: scheme, credentials and host are taken from the base
          // as is. Rebuilding them into a string lost the port, so navigating
          // to `/dest` from a base with a port went nowhere.
          st.scheme = scheme;
          st.username = b.username; st.password = b.password;
          st.host = b.host; __pt_write(st, 'port', b.port);
          st.opaque = false;
          let rest = s;
          const hi = __s_indexOf(rest, '#'); st.fragment = hi >= 0 ? encFrag(__s_slice(rest, hi)) : '';
          if (hi >= 0) rest = __s_slice(rest, 0, hi);
          const qi = __s_indexOf(rest, '?'); st.query = qi >= 0 ? encQuery(__s_slice(rest, qi), true) : '';
          if (qi >= 0) rest = __s_slice(rest, 0, qi);
          let path;
          if (!rest) path = b.path;
          else if (__s_startsWith(rest, '/')) path = rest;
          else path = __s_replace(b.path, /[^/]*$/, '') + rest;
          if (!rest && !st.query) st.query = st.fragment ? b.query : b.query;
          st.path = encPath(normPath(path || '/'));
          return true;
        }
      }
      st.scheme = scheme;
      const special = Object.prototype.hasOwnProperty.call(SPECIAL, scheme);
      st.opaque = !special && !__s_startsWith(s, '//');
      if (st.opaque) {
        // `mailto:`, `data:`, `about:`, `blob:`: the whole path, no host.
        const hi = __s_indexOf(s, '#'); const frag = hi >= 0 ? __s_slice(s, hi) : '';
        if (hi >= 0) s = __s_slice(s, 0, hi);
        const qi = __s_indexOf(s, '?'); const q = qi >= 0 ? __s_slice(s, qi) : '';
        if (qi >= 0) s = __s_slice(s, 0, qi);
        st.host = ''; __pt_write(st, 'port', ''); st.username = ''; st.password = '';
        st.path = s; st.query = q; st.fragment = frag;
        return true;
      }
      // A special scheme tolerates any number of slashes after the colon
      // (`http:/a`, `http:///a`): all are `http://a/`.
      if (special && scheme !== 'file:') s = __s_replace(s, /^[\/\\]*/, '');
      else if (__s_startsWith(s, '//')) s = __s_slice(s, 2);
      const cut = __s_search(s, /[/?#\\]/);
      let auth = cut < 0 ? s : __s_slice(s, 0, cut);
      let rest = cut < 0 ? '' : __s_slice(s, cut);
      const at = __s_lastIndexOf(auth, '@');
      if (at >= 0) {
        const ui = __s_slice(auth, 0, at); auth = __s_slice(auth, at + 1);
        const ci = __s_indexOf(ui, ':');
        st.username = ci < 0 ? ui : __s_slice(ui, 0, ci);
        st.password = ci < 0 ? '' : __s_slice(ui, ci + 1);
      } else { st.username = st.username || ''; st.password = st.password || ''; }
      // IPv6 is bracketed, and colons inside are not the port.
      let hostPart = auth, portPart = '';
      if (__s_startsWith(auth, '[')) {
        const close = __s_indexOf(auth, ']');
        if (close < 0) return false;
        hostPart = __s_slice(auth, 0, close + 1);
        const after = __s_slice(auth, close + 1);
        if (__s_startsWith(after, ':')) portPart = __s_slice(after, 1);
      } else {
        const ci = __s_lastIndexOf(auth, ':');
        if (ci >= 0) { hostPart = __s_slice(auth, 0, ci); portPart = __s_slice(auth, ci + 1); }
      }
      // A special scheme without a host (`http://`), forbidden host code points
      // or a non-numeric port: not a URL for the browser.
      if (special && scheme !== 'file:' && !hostPart) return false;
      if (special && /[\x00-\x1f#/<>?@\\^|]/.test(__s_replace(hostPart, /^\[.*\]$/, ''))) return false;
      if (portPart && (!/^\d+$/.test(portPart) || +portPart > 65535)) return false;
      st.host = __s_startsWith(hostPart, '[') ? __s_toLowerCase(hostPart) : __s_replace(encHost(__s_toLowerCase(hostPart)), / /g, '%20');
      __pt_write(st, 'port', portPart === SPECIAL[scheme] ? '' : portPart);
      const hi = __s_indexOf(rest, '#'); st.fragment = hi >= 0 ? encFrag(__s_slice(rest, hi)) : '';
      if (hi >= 0) rest = __s_slice(rest, 0, hi);
      const qi = __s_indexOf(rest, '?'); st.query = qi >= 0 ? encQuery(__s_slice(rest, qi), special) : '';
      if (qi >= 0) rest = __s_slice(rest, 0, qi);
      st.path = encPath(normPath(__s_replace(rest, /\\/g, '/') || '/'));
      return true;
    };
    class URL {
      constructor(url, base) {
        if (arguments.length < 1) {
          throw __pt_mkErr(TypeError, "Failed to construct 'URL': 1 argument required, but only 0 present.");
        }
        const st = { scheme: '', username: '', password: '', host: '', port: '', path: '', query: '', fragment: '', opaque: false };
        let baseState = null;
        if (base !== undefined) {
          const bs = { scheme: '', username: '', password: '', host: '', port: '', path: '', query: '', fragment: '', opaque: false };
          if (!parseInto(bs, base, null)) {
            throw __pt_mkErr(TypeError, "Failed to construct 'URL': Invalid base URL");
          }
          baseState = bs;
        }
        if (!parseInto(st, url, baseState)) {
          throw __pt_mkErr(TypeError, "Failed to construct 'URL': Invalid URL");
        }
        URL_STATE.set(this, st);
        st.params = linkParams(st);
      }
      get protocol() { return URL_STATE.get(this).scheme; }
      set protocol(v) { const st = URL_STATE.get(this); const t = __s_replace(String(v), /:*$/, '') + ':'; if (/^[a-z][a-z0-9+.\-]*:$/i.test(t)) st.scheme = __s_toLowerCase(t); }
      get username() { return URL_STATE.get(this).username; }
      set username(v) { URL_STATE.get(this).username = String(v); }
      get password() { return URL_STATE.get(this).password; }
      set password(v) { URL_STATE.get(this).password = String(v); }
      get hostname() { return URL_STATE.get(this).host; }
      set hostname(v) { const st = URL_STATE.get(this); if (!st.opaque) st.host = encHost(__s_toLowerCase(String(v))); }
      get port() { return URL_STATE.get(this).port; }
      set port(v) { const st = URL_STATE.get(this); const t = __s_replace(String(v), /[^0-9]/g, ''); __pt_write(st, 'port', t === SPECIAL[st.scheme] ? '' : t); }
      get host() { const st = URL_STATE.get(this); return st.host + (st.port ? ':' + st.port : ''); }
      set host(v) {
        const st = URL_STATE.get(this); const t = String(v);
        const ci = __s_startsWith(t, '[') ? __s_indexOf(t, ']') + 1 : __s_lastIndexOf(t, ':');
        if (ci > 0 && t[ci] === ':') { this.hostname = __s_slice(t, 0, ci); __pt_write(this, 'port', __s_slice(t, ci + 1)); }
        else this.hostname = t;
      }
      get pathname() { return URL_STATE.get(this).path; }
      set pathname(v) { const st = URL_STATE.get(this); if (!st.opaque) st.path = encPath(normPath(String(v) || '/')); }
      // `search` is the query as written (`?x` stays `?x`), not a
      // URLSearchParams rebuild, which appended `=` to every key. Edits via
      // `searchParams` write back into the URL.
      get search() { const st = URL_STATE.get(this); return st.query === '?' ? '' : st.query; }
      set search(v) { const st = URL_STATE.get(this); const t = encQuery(String(v), Object.prototype.hasOwnProperty.call(SPECIAL, st.scheme)); st.query = t && t[0] !== '?' ? '?' + t : t; st.params = linkParams(st); }
      get searchParams() { return URL_STATE.get(this).params; }
      get hash() { const st = URL_STATE.get(this); return st.fragment; }
      set hash(v) { const st = URL_STATE.get(this); const t = encFrag(String(v)); st.fragment = t ? (t[0] === '#' ? t : '#' + t) : ''; }
      get origin() {
        const st = URL_STATE.get(this);
        if (st.scheme === 'blob:') {
          try { return new URL(st.path).origin; } catch (e) { return 'null'; }
        }
        // A file URL has an origin, but without a host: `file://`.
        if (st.scheme === 'file:') return 'file://';
        if (st.opaque || !Object.prototype.hasOwnProperty.call(SPECIAL, st.scheme)) return 'null';
        return st.scheme + '//' + this.host;
      }
      get href() {
        const st = URL_STATE.get(this);
        if (st.opaque) return st.scheme + st.path + this.search + st.fragment;
        const cred = st.username ? st.username + (st.password ? ':' + st.password : '') + '@' : '';
        return st.scheme + '//' + cred + this.host + st.path + this.search + st.fragment;
      }
      set href(v) {
        const st = URL_STATE.get(this);
        const fresh = { scheme: '', username: '', password: '', host: '', port: '', path: '', query: '', fragment: '', opaque: false };
        if (!parseInto(fresh, v, null)) throw __pt_mkErr(TypeError, "Failed to set the 'href' property on 'URL': Invalid URL");
        Object.assign(st, fresh);
        st.params = linkParams(st);
      }
      toString() { return this.href; }
      toJSON() { return this.href; }
      static canParse(url, base) {
        try { new URL(url, base); return true; } catch (e) { return false; }
      }
      static parse(url, base) {
        try { return new URL(url, base); } catch (e) { return null; }
      }
      // The URL has to lead back to the object: a page that stores a Blob and
      // fetches its URL (or runs it as a Worker) expects its own bytes back, and
      // handing out a URL that resolves to nothing breaks that silently.
      static createObjectURL(obj) {
        // The URL shape is part of the fingerprint: the browser uses
        // `blob:<origin>/<uuid>`, not a short counter. A worker sees it as its
        // `location.href`, and pages send it to the collector.
        const u = 'blob:' + (globalThis.location ? location.origin : 'null') + '/' + uuid4(blobSeq++);
        (globalThis.__pt_blobs || (globalThis.__pt_blobs = new Map())).set(u, obj);
        return u;
      }
      static revokeObjectURL(u) { if (globalThis.__pt_blobs) globalThis.__pt_blobs.delete(String(u)); }
    }
    globalThis.URL = URL;
  }

  // Interfaces we define as classes must read as native: in the browser they
  // are `[native code]`, which fingerprinters bucket as `N`, user functions as `f`.
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
    // Found by the challenge's own collector: these four read as user
    // functions (bucket `f` where the browser gives `N`).
    'PerformanceEntry', 'PerformanceResourceTiming', 'PerformanceNavigationTiming',
    'CustomElementRegistry']) {
    const c = globalThis[n];
    if (typeof c === 'function') { __ptMark(c); maskProto(c.prototype); }
  }
  for (const n of ['dispatchEvent', 'reportError', 'cancelIdleCallback', 'requestIdleCallback',
    'addEventListener', 'removeEventListener', 'queueMicrotask', 'structuredClone']) {
    if (typeof globalThis[n] === 'function') __ptMark(globalThis[n]);
  }
  // The element interface ladder is built in the DOM runtime before the
  // native registry exists here, so collect all of them by name.
  for (const n of Object.getOwnPropertyNames(globalThis)) {
    if (!/^(HTML|SVG)[A-Za-z]*Element$/.test(n)) continue;
    const c = globalThis[n];
    if (typeof c === 'function') { __ptMark(c); maskProto(c.prototype); }
  }

  // `console.log.toString()` is read like everything else.
  try {
    for (const k of Object.getOwnPropertyNames(globalThis.console || {})) {
      const f = console[k];
      if (typeof f === 'function') __ptMark(f);
    }
  } catch (e) {}

  // `NodeFilter` is an interface object (a function holding constants), not a
  // dict: in the browser it lands in the same `N` bucket.
  try {
    const F = globalThis.NodeFilter;
    if (F && typeof F !== 'function') {
      // In Chrome `NodeFilter` is the only interface without `prototype`: it
      // only holds traversal constants. A function's `prototype` cannot be
      // deleted, so use method shorthand, which has none, with the same name
      // and throw.
      const ctor = ({ NodeFilter() { throw __pt_mkErr(TypeError, 'Illegal constructor'); } }).NodeFilter;
      for (const k of Object.keys(F)) {
        Object.defineProperty(ctor, k, { value: F[k], enumerable: true, configurable: true });
      }
      __ptMark(ctor);
      globalThis.NodeFilter = ctor;
    }
  } catch (e) {}

  // `origin` on window, `valueOf` on location.
  if (!('origin' in globalThis)) {
    // For `about:blank` the window origin is inherited from the creator
    // (location.origin stays "null", as in the browser); the parent leaves a hint.
    try { Object.defineProperty(globalThis, 'origin', { get: () => ((globalThis.location && location.href === 'about:blank' && globalThis.__pt_inheritedOrigin) || (globalThis.location && location.origin) || 'null'), enumerable: true, configurable: true }); } catch (e) {}
  }
  try {
    const lp = globalThis.location && Object.getPrototypeOf(globalThis.location);
    if (lp && !('valueOf' in lp)) {
      Object.defineProperty(lp, 'valueOf', { value: __ptMark(function valueOf() { return this; }) ? function valueOf() { return this; } : undefined, enumerable: true, configurable: true });
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
  // `__out*` are names of the engine's one-shot probe (`--eval` puts its
  // answer there); the whole family must be hidden, or `__outDone` shows on window.
  const __ptHidden = (k) => typeof k === 'string' && (__s_lastIndexOf(k, '__pt', 0) === 0 || __s_lastIndexOf(k, '__out', 0) === 0);
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
  // Object.hasOwn too: it saw internal node fields.
  const origHasOwn = Object.hasOwn;
  if (typeof origHasOwn === 'function') {
    Object.defineProperty(Object, 'hasOwn', {
      value: mask(function hasOwn(o, k) { return __ptHidden(k) ? (origHasOwn(o, k), false) : origHasOwn(o, k); }, 'hasOwn'),
      configurable: true, writable: true,
    });
  }
  // Raw versions for the loader's last pass (which hides enumerability of
  // internal prototype methods); themselves under a hidden name.
  Object.defineProperty(globalThis, '__pt_rawGOPN', { value: origGOPN, configurable: true });
  Object.defineProperty(globalThis, '__pt_rawGOPD', { value: origGOPD, configurable: true });
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
            assert!(s.device_memory_gb.is_power_of_two() && s.device_memory_gb <= 64);
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
            win.contains(r#"version: "151""#),
            "client-hints brand version not 151"
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
        assert!(!p.user_agent.contains("Chrome/151"));
        // The bootstrap's userAgentData brand version follows the field.
        let js = bootstrap_script(&p);
        assert!(js.contains(r#"version: "131""#));
        assert!(!js.contains(r#"version: "151""#));
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
    fn the_fingerprint_seed_belongs_to_the_identity_not_the_run() {
        let a = StealthProfile::default();
        // The same machine draws the same pixels every time it is asked.
        assert_eq!(identity_seed(&a), identity_seed(&StealthProfile::default()));
        let script = fingerprint_script(&a);
        assert!(!script.contains("__FP_SEED__"), "seed left unsubstituted");
        assert!(
            script.contains(&format!("const SEED = {};", identity_seed(&a))),
            "the seed is not the profile's"
        );
        // A different machine draws differently.
        let b = StealthProfile {
            webgl_renderer: "ANGLE (NVIDIA, GeForce RTX 3060, OpenGL 4.6)".into(),
            ..StealthProfile::default()
        };
        assert_ne!(identity_seed(&a), identity_seed(&b));
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

#[cfg(test)]
mod dump_scripts {
    /// Dumps layer scripts to disk when `NOKK_DUMP_DIR` is set, so their syntax
    /// can be checked with `node --check` like `dom_runtime.js`: inside Rust
    /// strings a typo otherwise surfaces only as a `SyntaxError` with no location.
    #[test]
    fn dump_scripts() {
        let dir = std::env::var("NOKK_DUMP_DIR").unwrap_or_default();
        if dir.is_empty() {
            return;
        }
        let prof = super::StealthProfile::default();
        for (name, body) in [
            ("write_helper", super::write_helper_script()),
            ("web_surface", super::web_surface_script()),
            ("injection", super::injection_script(&prof)),
            ("bootstrap", super::bootstrap_script(&prof)),
            ("fingerprint", super::fingerprint_script(&prof)),
            ("late_interfaces", super::late_interfaces_script()),
            ("late_originals", super::late_originals_script()),
            ("worker_scope", super::worker_scope_script("w", "https://example.com/w.js")),
        ] {
            std::fs::write(format!("{dir}/dump_{name}.js"), body).unwrap();
        }
    }
}
