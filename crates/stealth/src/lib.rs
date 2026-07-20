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
}

impl Default for StealthProfile {
    /// A recent stable Chrome on desktop Linux. Bump alongside the network
    /// profile when Chrome's stable channel moves.
    fn default() -> Self {
        Self {
            // Keep the Chrome major version in step with the TLS emulation
            // (`nokk_net::FingerprintClient::EMULATION` = Chrome 137), or
            // the JS UA and the ClientHello disagree — an instant tell.
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
                .into(),
            platform: "Linux x86_64".into(),
            languages: vec!["en-US".into(), "en".into()],
            hardware_concurrency: 8,
            device_memory_gb: 8,
            vendor: "Google Inc.".into(),
            webgl_vendor: "Google Inc. (Intel)".into(),
            webgl_renderer: "ANGLE (Intel, Mesa Intel(R) UHD Graphics, OpenGL 4.6)".into(),
            timezone: "America/New_York".into(),
            timezone_offset_minutes: 300, // EST (UTC-5); DST rule yields EDT (240)
            timezone_dst: "us".into(),
            timezone_name_std: "Eastern Standard Time".into(),
            timezone_name_dst: "Eastern Daylight Time".into(),
        }
    }
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
        .replace("__WEBGL_RENDERER__", &quoted(&profile.webgl_renderer));

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

    format!("{env}\n{intl}\n{TIMERS_TEMPLATE}\n{PERFORMANCE_TEMPLATE}\n{FETCH_TEMPLATE}")
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
      { brand: "Chromium", version: "137" }, { brand: "Google Chrome", version: "137" }, { brand: "Not.A/Brand", version: "24" }
    ], mobile: false, platform: "Linux" },
  });
  win.navigator = Object.create(NavigatorProto);

  win.window = win; win.self = win; win.top = win; win.parent = win; win.frames = win;
  win.length = 0; win.name = ""; win.closed = false;

  // --- screen -----------------------------------------------------------
  const ScreenProto = defClass("Screen");
  staticProps(ScreenProto, {
    width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, availTop: 0, availLeft: 0,
    colorDepth: 24, pixelDepth: 24, isExtended: false,
    orientation: { type: "landscape-primary", angle: 0 },
  });
  win.screen = Object.create(ScreenProto);
  win.innerWidth = 1920; win.innerHeight = 969;
  win.outerWidth = 1920; win.outerHeight = 1080;
  win.devicePixelRatio = 1;

  // --- location (getters read a backing store the Rust driver updates) --
  const LocationProto = defClass("Location");
  const locState = { href: "about:blank", protocol: "about:", host: "", hostname: "", port: "", pathname: "blank", search: "", hash: "", origin: "null" };
  for (const k of Object.keys(locState)) accessor(LocationProto, k, () => locState[k], (v) => { locState[k] = String(v); });
  protoMethod(LocationProto, "assign", function assign(){});
  protoMethod(LocationProto, "replace", function replace(){});
  protoMethod(LocationProto, "reload", function reload(){});
  protoMethod(LocationProto, "toString", function toString(){ return locState.href; });
  win.location = Object.create(LocationProto);
  // Rust calls this on navigation to populate `location` from the real URL —
  // a static `about:blank` is an instant tell (and breaks relative logic).
  globalThis.__pt_setLocation = (o) => { for (const k in o) if (k in locState) locState[k] = o[k]; };

  // --- history ----------------------------------------------------------
  const HistoryProto = defClass("History");
  staticProps(HistoryProto, { length: 1, scrollRestoration: "auto", state: null });
  for (const m of ["back", "forward", "go", "pushState", "replaceState"]) protoMethod(HistoryProto, m, function(){});
  win.history = Object.create(HistoryProto);

  const noop = () => {};
  win.console = {
    log: noop, warn: noop, error: noop, info: noop, debug: noop,
    trace: noop, dir: noop, table: noop, group: noop, groupEnd: noop, assert: noop
  };
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

  globalThis.Intl = {
    DateTimeFormat, NumberFormat, Collator,
    RelativeTimeFormat: passthru({ format: (v, u) => v + ' ' + u, formatToParts: (v, u) => [{ type: 'literal', value: v + ' ' + u }] }),
    PluralRules: passthru({ select: () => 'other' }),
    ListFormat: passthru({ format: (a) => list(a).join(', '), formatToParts: (a) => list(a).map(v => ({ type: 'element', value: v })) }),
    DisplayNames: passthru({ of: (c) => String(c) }),
    Segmenter: passthru({ segment: (s) => [{ segment: String(s), index: 0, input: String(s) }] }),
    Locale: function (tag) { this.baseName = norm(tag); this.language = String(norm(tag)).split('-')[0]; this.toString = () => this.baseName; },
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
/// `requestAnimationFrame` plus `performance.now()`, backed by a virtual-time
/// queue. `__pt_runNextTimer` (called from Rust) runs the earliest pending timer
/// and advances the virtual clock to it, collapsing real delays so a page that
/// does `setTimeout(fn, 4000)` completes instantly rather than blocking a worker.
/// `setInterval` reschedules itself, so the Rust driver caps total callbacks.
const TIMERS_TEMPLATE: &str = r#"(() => {
  let seq = 1;
  let clock = 0;
  const q = new Map(); // id -> {fn, delay, interval, due, cancelled, id}

  const add = (fn, delay, interval, args) => {
    if (typeof fn !== 'function') return 0;
    const id = seq++;
    q.set(id, { fn: () => fn.apply(globalThis, args), delay: +delay || 0,
                interval, due: clock + (+delay || 0), cancelled: false, id });
    return id;
  };
  globalThis.setTimeout = (fn, delay, ...args) => add(fn, delay, false, args);
  globalThis.setInterval = (fn, delay, ...args) => add(fn, delay, true, args);
  globalThis.clearTimeout = (id) => { const t = q.get(id); if (t) t.cancelled = true; q.delete(id); };
  globalThis.clearInterval = globalThis.clearTimeout;
  globalThis.queueMicrotask = (fn) => { Promise.resolve().then(fn); };
  globalThis.requestAnimationFrame = (fn) =>
    add(() => fn(globalThis.performance ? globalThis.performance.now() : clock), 16, false, []);
  globalThis.cancelAnimationFrame = globalThis.clearTimeout;
  globalThis.setImmediate = (fn, ...args) => add(fn, 0, false, args);
  globalThis.clearImmediate = globalThis.clearTimeout;

  // `performance` is defined by PERFORMANCE_TEMPLATE (wall-clock coherent); a
  // frame callback receives the same high-res timestamp a real browser passes.

  // Run the single earliest pending timer, advancing the virtual clock to its
  // due time. Returns 1 if a timer ran, 0 if the queue is empty. Microtasks
  // scheduled by the callback drain automatically when this returns to Rust.
  globalThis.__pt_runNextTimer = () => {
    let best = null;
    for (const t of q.values()) {
      if (t.cancelled) continue;
      if (!best || t.due < best.due || (t.due === best.due && t.id < best.id)) best = t;
    }
    if (!best) return 0;
    clock = Math.max(clock, best.due);
    if (best.interval) best.due = clock + best.delay; else q.delete(best.id);
    try { best.fn(); } catch (e) { /* timer callback threw */ }
    return 1;
  };
  globalThis.__pt_pendingTimers = () => q.size;
})();"#;

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

  class Performance {
    now() { return nowMs(); }
    getEntries() { return []; }
    getEntriesByType() { return []; }
    getEntriesByName() { return []; }
    mark() { return undefined; }
    measure() { return undefined; }
    clearMarks() {}
    clearMeasures() {}
    clearResourceTimings() {}
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

  globalThis.fetch = (url, opts) => {
    opts = opts || {};
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
  globalThis.XMLHttpRequest = class XMLHttpRequest {
    constructor() {
      this.readyState = 0; this.status = 0; this.statusText = '';
      this.responseText = ''; this.response = ''; this.responseType = '';
      this._headers = {}; this._respHeaders = {};
      this.onreadystatechange = null; this.onload = null; this.onerror = null; this.onloadend = null;
    }
    open(method, url) { this.method = String(method).toUpperCase(); this.url = String(url); this._set(1); }
    setRequestHeader(k, v) { this._headers[k] = String(v); }
    getAllResponseHeaders() { return Object.entries(this._respHeaders).map(([k, v]) => k + ': ' + v).join('\r\n'); }
    getResponseHeader(k) { return this._respHeaders[k.toLowerCase()] ?? null; }
    abort() {}
    send(body) {
      fetch(this.url, { method: this.method, headers: this._headers, body })
        .then(async (r) => {
          this.status = r.status; this.statusText = r.statusText;
          r.headers.forEach((v, k) => { this._respHeaders[k] = v; });
          this.responseText = await r.text();
          this.response = this.responseType === 'json' ? JSON.parse(this.responseText || 'null') : this.responseText;
          this._set(4); if (this.onload) this.onload(); if (this.onloadend) this.onloadend();
        })
        .catch((e) => { this.status = 0; this._set(4); if (this.onerror) this.onerror(e); if (this.onloadend) this.onloadend(); });
    }
    _set(s) { this.readyState = s; if (this.onreadystatechange) this.onreadystatechange(); }
  };

  // Minimal Headers/TextEncoder if missing.
  if (!globalThis.TextEncoder) {
    globalThis.TextEncoder = class { encode(s) { s = String(s); const a = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i) & 0xff; return a; } };
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

  // --- Canvas 2D --------------------------------------------------------
  // A fixed, plausible PNG payload: consistent hash => looks like one device.
  const CANVAS_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAASwAAAAyCAYAAAAZ' +
    'UZThAAAGdElEQVR4nO3dz2sTQRTA8W+Spk1TQtOa1B9FRUEQ8SB48OBB8OBB8OBB8OBB8OBB8ODBg' +
    'wcPgncvXrx48eLFgwcPggcRBEEEQdQqiLZq09TUJk2TZpMdD5Nkk2yyu9nZ3dnk+8Fjs7Mzs+/N7' +
    'OzM7MJEBEREREREREREREREREREREREREREREREREREREREREREREREREREREZE/AZUqlQGVAZUBlQ' +
    'GVAZUBlQGVAZUBlQGVAZUBlQGVAZUBlQPUb+AXcBu4Dj4EnwFPgGfAceAG8BF4Br4E3wFvgHfAe+A';
  const make2DContext = (canvas) => maskProto(Object.assign(Object.create(globalThis.CanvasRenderingContext2D.prototype), {
    canvas,
    fillStyle: '#000000', strokeStyle: '#000000', font: '10px sans-serif',
    globalAlpha: 1.0, lineWidth: 1.0, textBaseline: 'alphabetic', textAlign: 'start',
    shadowColor: 'rgba(0, 0, 0, 0)', shadowBlur: 0, globalCompositeOperation: 'source-over',
    fillRect(){}, clearRect(){}, strokeRect(){}, fillText(){}, strokeText(){},
    beginPath(){}, closePath(){}, moveTo(){}, lineTo(){}, arc(){}, arcTo(){}, rect(){},
    bezierCurveTo(){}, quadraticCurveTo(){}, ellipse(){}, fill(){}, stroke(){}, clip(){},
    save(){}, restore(){}, translate(){}, scale(){}, rotate(){}, setTransform(){}, transform(){}, resetTransform(){},
    drawImage(){}, putImageData(){}, setLineDash(){}, getLineDash(){ return []; },
    isPointInPath(){ return false; },
    measureText(t){ const w = String(t).length * 6.7; return { width: w, actualBoundingBoxLeft: 0, actualBoundingBoxRight: w, actualBoundingBoxAscent: 8, actualBoundingBoxDescent: 2, fontBoundingBoxAscent: 9, fontBoundingBoxDescent: 2 }; },
    getImageData(x, y, w, h){ w = w|0; h = h|0; const d = new Uint8ClampedArray(Math.max(0, w * h * 4)); for (let i = 0; i < d.length; i++) d[i] = seededByte(i); return { data: d, width: w, height: h, colorSpace: 'srgb' }; },
    createImageData(w, h){ return { data: new Uint8ClampedArray(Math.max(0, (w|0) * (h|0) * 4)), width: w|0, height: h|0 }; },
    createLinearGradient(){ return { addColorStop(){} }; },
    createRadialGradient(){ return { addColorStop(){} }; },
    createPattern(){ return {}; },
    getContextAttributes(){ return { alpha: true, colorSpace: 'srgb', desynchronized: false, willReadFrequently: false }; },
  }));

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
    // No-op the GL calls a fingerprinter drives before reading parameters.
    for (const m of ['viewport','clearColor','clear','enable','disable','createShader','shaderSource',
      'compileShader','getShaderParameter','createProgram','attachShader','linkProgram','getProgramParameter',
      'useProgram','createBuffer','bindBuffer','bufferData','getAttribLocation','vertexAttribPointer',
      'enableVertexAttribArray','getUniformLocation','uniform2f','uniform1f','drawArrays','deleteShader',
      'deleteProgram','deleteBuffer','activeTexture','bindTexture','createTexture','texParameteri','texImage2D',
      'framebufferTexture2D','bindFramebuffer','createFramebuffer','readPixels','pixelStorei','depthFunc','flush','finish']) {
      if (!gl[m]) gl[m] = function(){};
    }
    return maskProto(gl);
  };

  // --- patch canvas element methods -------------------------------------
  const proto = globalThis.HTMLElement && globalThis.HTMLElement.prototype;
  if (proto) {
    proto.getContext = mask(function getContext(type){
      if (this.localName !== 'canvas') return null;
      if (type === '2d') return this.__c2d || (this.__c2d = make2DContext(this));
      if (type === 'webgl' || type === 'experimental-webgl') return this.__gl1 || (this.__gl1 = makeGL(this, 1));
      if (type === 'webgl2') return this.__gl2 || (this.__gl2 = makeGL(this, 2));
      return null;
    }, 'getContext');
    // Vary the tail per session so the canvas hash isn't a single fixed value.
    const CANVAS_OUT = CANVAS_PNG.slice(0, -8) + ('0000000' + SEED.toString(36)).slice(-8);
    proto.toDataURL = mask(function toDataURL(){ return this.localName === 'canvas' ? CANVAS_OUT : 'data:,'; }, 'toDataURL');
    proto.toBlob = mask(function toBlob(cb){ if (typeof cb === 'function') cb({ size: 8192, type: 'image/png' }); }, 'toBlob');
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
  const audioNode = () => ({ connect(){ return audioNode(); }, disconnect(){}, start(){}, stop(){},
    gain: { value: 1, setValueAtTime(){} }, frequency: { value: 440, setValueAtTime(){} },
    threshold: { value: -24, setValueAtTime(){} }, knee:{value:30,setValueAtTime(){}}, ratio:{value:12,setValueAtTime(){}},
    attack:{value:0.003,setValueAtTime(){}}, release:{value:0.25,setValueAtTime(){}},
    Q:{value:1,setValueAtTime(){}}, type: 'sine', buffer: null });
  class BaseAudioContext {
    constructor(){ this.sampleRate = 44100; this.currentTime = 0; this.state = 'running';
      this.destination = audioNode(); this.listener = {}; }
    createOscillator(){ return audioNode(); } createGain(){ return audioNode(); }
    createAnalyser(){ return Object.assign(audioNode(), { frequencyBinCount: 1024, fftSize: 2048, getFloatFrequencyData(){}, getByteFrequencyData(){} }); }
    createDynamicsCompressor(){ return audioNode(); } createBiquadFilter(){ return audioNode(); }
    createScriptProcessor(){ return audioNode(); } createBuffer(ch, len, rate){ return { numberOfChannels: ch, length: len, sampleRate: rate, getChannelData(){ return new Float32Array(len); } }; }
    createBufferSource(){ return audioNode(); } createConvolver(){ return audioNode(); }
    createStereoPanner(){ return audioNode(); } decodeAudioData(){ return Promise.resolve(this.createBuffer(2, 44100, 44100)); }
    resume(){ this.state = 'running'; return Promise.resolve(); } suspend(){ return Promise.resolve(); } close(){ this.state = 'closed'; return Promise.resolve(); }
  }
  globalThis.AudioContext = mask(class AudioContext extends BaseAudioContext {}, 'AudioContext');
  globalThis.webkitAudioContext = globalThis.AudioContext;
  globalThis.OfflineAudioContext = mask(class OfflineAudioContext extends BaseAudioContext {
    constructor(ch, len, rate){ super(); this.length = len || 44100; if (rate) this.sampleRate = rate;
      this._chans = ch || 1; }
    startRendering(){ const len = this.length, self = this;
      // Deterministic rendered buffer => stable audio fingerprint.
      return Promise.resolve({ numberOfChannels: self._chans, length: len, sampleRate: self.sampleRate,
        getChannelData(){ const a = new Float32Array(len); const amp = 0.1 + (SEED % 4096) / 4.194304e9; for (let i = 0; i < len; i++) a[i] = Math.sin(i / 100) * amp; return a; } });
    }
  }, 'OfflineAudioContext');

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
  globalThis.RTCPeerConnection = globalThis.RTCPeerConnection || mask(class RTCPeerConnection {
    constructor() { this.localDescription = null; this.remoteDescription = null; this.iceGatheringState = 'complete'; this.iceConnectionState = 'new'; this.connectionState = 'new'; this.onicecandidate = null; }
    createDataChannel() { return { close: noop, send: noop, addEventListener: noop }; }
    createOffer() { return Promise.resolve({ type: 'offer', sdp: '' }); }
    createAnswer() { return Promise.resolve({ type: 'answer', sdp: '' }); }
    setLocalDescription() { return Promise.resolve(); }
    setRemoteDescription() { return Promise.resolve(); }
    addIceCandidate() { return Promise.resolve(); }
    getStats() { return Promise.resolve(new Map()); }
    addEventListener() {} removeEventListener() {} close() {}
  }, 'RTCPeerConnection');
  globalThis.webkitRTCPeerConnection = globalThis.RTCPeerConnection;

  // --- synthetic events look trusted (like a real user gesture) ---------
  if (globalThis.Event && !Object.getOwnPropertyDescriptor(globalThis.Event.prototype, 'isTrusted')) {
    try { Object.defineProperty(globalThis.Event.prototype, 'isTrusted', { get: () => true, configurable: true }); } catch (e) {}
  }

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

  if (!globalThis.crypto || !globalThis.crypto.getRandomValues) {
    let s = (SEED >>> 0) || 123456789;
    const rnd = () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>> 0; };
    globalThis.crypto = globalThis.crypto || {};
    globalThis.crypto.getRandomValues = (arr) => { for (let i = 0; i < arr.length; i++) arr[i] = rnd(); return arr; };
    globalThis.crypto.randomUUID = () => {
      const b = []; for (let i = 0; i < 16; i++) b.push((rnd() & 0xff));
      b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
      const h = b.map((x) => x.toString(16).padStart(2, '0')).join('');
      return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
    };
  }

  globalThis.IntersectionObserver = globalThis.IntersectionObserver || class IntersectionObserver {
    constructor(cb) { this._cb = cb; }
    observe(el) { const cb = this._cb, self = this; setTimeout(() => { try { cb([{ target: el, isIntersecting: true, intersectionRatio: 1, boundingClientRect: {}, intersectionRect: {}, rootBounds: null, time: 0 }], self); } catch (e) {} }, 0); }
    unobserve() {} disconnect() {} takeRecords() { return []; }
  };
  globalThis.MutationObserver = globalThis.MutationObserver || class MutationObserver { constructor(cb) { this._cb = cb; } observe() {} disconnect() {} takeRecords() { return []; } };
  globalThis.ResizeObserver = globalThis.ResizeObserver || class ResizeObserver { constructor(cb) { this._cb = cb; } observe() {} unobserve() {} disconnect() {} };
  globalThis.PerformanceObserver = globalThis.PerformanceObserver || class PerformanceObserver { constructor() {} observe() {} disconnect() {} takeRecords() { return []; } };
  globalThis.PerformanceObserver.supportedEntryTypes = [];

  globalThis.matchMedia = globalThis.matchMedia || ((q) => ({ matches: false, media: String(q), onchange: null, addListener: noop, removeListener: noop, addEventListener: noop, removeEventListener: noop, dispatchEvent: () => false }));
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
    globalThis.Blob = class Blob { constructor(parts, opts) { this._p = (parts || []).map(String); this.type = (opts && opts.type) || ''; this.size = this._p.reduce((n, x) => n + x.length, 0); } text() { return Promise.resolve(this._p.join('')); } arrayBuffer() { return Promise.resolve(new TextEncoder().encode(this._p.join('')).buffer); } slice() { return new Blob([]); } toString() { return this._p.join(''); } };
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
      static createObjectURL() { return 'blob:' + (globalThis.location ? location.origin : 'null') + '/' + (SEED.toString(36)); }
      static revokeObjectURL() {}
    };
  }

  // --- mask key patched globals so their toString reads native ----------
  for (const [obj, key] of [[globalThis, 'fetch'], [globalThis, 'setTimeout'], [globalThis, 'setInterval'],
    [globalThis, 'clearTimeout'], [globalThis, 'clearInterval'], [globalThis, 'queueMicrotask'],
    [globalThis, 'requestAnimationFrame'], [globalThis, 'cancelAnimationFrame'], [globalThis, 'requestIdleCallback'],
    [globalThis, 'XMLHttpRequest'], [globalThis, 'AudioContext'], [globalThis, 'Image'],
    [globalThis, 'getComputedStyle'], [globalThis, 'matchMedia'], [globalThis, 'TextEncoder'],
    [globalThis, 'TextDecoder'], [globalThis, 'Blob'], [globalThis, 'FormData'], [globalThis, 'URL']]) {
    if (obj[key]) mask(obj[key], key);
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
    globalThis.FocusEvent, globalThis.Text, globalThis.Comment,
    globalThis.Performance, globalThis.PerformanceTiming, globalThis.PerformanceNavigation]) {
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
