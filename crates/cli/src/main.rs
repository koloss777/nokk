//! `nokk` — CLI entry point.
//!
//! Wires up configuration, logging and the engine, then dispatches on the flags:
//! one-shot `--fetch`/`--eval`/`--load` modes, or (the default) a CDP WebSocket
//! server on `--port` that Puppeteer can attach to.

use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use nokk::{BrowserContext, Engine, EngineConfig, PoolConfig};
use nokk_net::ClientConfig;

/// Headless browser-emulation engine with a Chrome-compatible fingerprint.
#[derive(Debug, Parser)]
#[command(name = "nokk", version, about)]
struct Cli {
    /// CDP WebSocket port. With no one-shot flag, nokk runs as a CDP server on
    /// this port for Puppeteer to connect to.
    #[arg(long, env = "NOKK_PORT", default_value_t = 9222)]
    port: u16,

    /// CDP server: solve a challenge transparently on every navigation that
    /// lands on one, within this many seconds (default 30 when the value is
    /// omitted), before `Page.navigate` reports the load. A page still showing
    /// a gate afterwards is announced with a `Nokk.challenge` event; a client
    /// can also ask on demand with `Nokk.solveChallenge` / `Nokk.challengeState`,
    /// or per browser context with `createBrowserContext({ autoSolve: true })`.
    #[arg(long, env = "NOKK_AUTO_SOLVE", value_name = "SECONDS", num_args = 0..=1, default_missing_value = "30")]
    auto_solve: Option<u64>,

    /// Address the CDP server binds to. Defaults to loopback; set `0.0.0.0` to
    /// accept connections from other hosts (e.g. inside a Docker container).
    #[arg(long, env = "NOKK_HOST", default_value = "127.0.0.1")]
    host: std::net::IpAddr,

    /// Require this token from every CDP client: `ws://…/devtools/browser/nokk?token=…`
    /// or `Authorization: Bearer …`. Whoever reaches the port can browse from this
    /// machine and read its sessions, so set one when the server is reachable from
    /// other hosts. Use URL-safe characters.
    #[arg(long, env = "NOKK_TOKEN", value_name = "TOKEN")]
    token: Option<String>,

    /// Maximum number of isolate worker threads. The pool starts with one and
    /// grows only when every live worker already carries a context; a worker
    /// whose last context closed drains again. Defaults to available parallelism
    /// for the CDP server, and to 1 for a one-shot `--load`/`--eval`: one page
    /// needs no pool, and every extra isolate costs ~150 MB at the peak of a
    /// challenge.
    #[arg(long, env = "NOKK_WORKERS")]
    workers: Option<usize>,

    /// Maximum number of simultaneously live contexts (memory backpressure).
    #[arg(long, env = "NOKK_MAX_CONTEXTS")]
    max_contexts: Option<usize>,

    /// Cap each worker isolate's JS heap, in MB (shared across that worker's
    /// contexts). Total JS heap is bounded by roughly `workers * this`. A page
    /// that exceeds it fails with an out-of-memory error instead of the process
    /// growing unbounded. Unset = V8 default.
    #[arg(long, env = "NOKK_MAX_HEAP_MB")]
    max_heap_mb: Option<usize>,

    /// Log filter, e.g. `info`, `nokk_pool=debug`.
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log: String,

    /// One-shot: fetch this URL through the Chrome-fingerprinted HTTP client
    /// (JA3/JA4 + HTTP/2), print the response, and exit.
    #[arg(long, value_name = "URL")]
    fetch: Option<String>,

    /// One-shot: evaluate this JavaScript, print the result, and exit. Runs in a
    /// fresh stealth context, or — combined with `--load` — against the loaded
    /// page's DOM. E.g. `--eval navigator.webdriver`, or
    /// `--load <url> --eval 'document.title'`.
    #[arg(long, value_name = "JS")]
    eval: Option<String>,

    /// One-shot: navigate to this URL (fetch, build the DOM, run page scripts,
    /// fire DOMContentLoaded/load), print a summary, and exit. Enables real
    /// networking. Pair with `--eval` to probe the resulting DOM.
    #[arg(long, value_name = "URL")]
    load: Option<String>,

    /// Wait for a challenge widget to finish, pressing whatever it puts up —
    /// a checkbox, a switch — the way a person would. The engine can reach the
    /// control (widgets keep it in a closed shadow root inside a cross-origin
    /// frame, where page script cannot); a driver only says how long to wait, in
    /// seconds. Stops early once a `cf_clearance` is in the jar.
    #[arg(long, value_name = "SECONDS", num_args = 0..=1, default_missing_value = "60")]
    solve_challenge: Option<u64>,

    /// For `--load` with `--solve-challenge`: stop the moment Cloudflare hands
    /// out a fresh `cf_clearance`, without loading the site behind it. For a
    /// caller that only wants the cookie (it lands in `--session-store`): on a
    /// heavy site the page behind the gate is most of the time a solve takes.
    #[arg(long, requires = "solve_challenge", env = "NOKK_UNTIL_CLEARANCE")]
    until_clearance: bool,

    /// Route all requests through a proxy, e.g.
    /// `http://user:pass@host:port` or `socks5://host:port`. Essential for
    /// IP rotation against WAFs like Cloudflare (a burned IP gets an instant 403).
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// Directory for persistent, named sessions. When set, a Puppeteer browser
    /// context named via `createBrowserContext` persists its cookie jar (login
    /// state, `cf_clearance`, …) to `<dir>/<name>.json`, so you can warm a session
    /// once and resume it in a later run. Unset = sessions are in-memory only.
    #[arg(long, env = "NOKK_SESSION_STORE", value_name = "DIR")]
    session_store: Option<std::path::PathBuf>,

    /// For `--load`: bind the navigation to a named session (its cookie jar is
    /// reused). Pair with `--import-cookies` to preload a harvested clearance.
    #[arg(long, value_name = "NAME")]
    session: Option<String>,

    /// For `--load`: import cookies from a JSON file into the `--session` jar
    /// before navigating — e.g. a `cf_clearance.json` harvested by nokk-cf
    /// (`{ "cookies": { name: value, … }, "domain": "…", "url": "…" }`). Replay
    /// only works if this engine's Chrome emulation + exit IP match the harvester.
    #[arg(long, value_name = "FILE")]
    import_cookies: Option<std::path::PathBuf>,

    /// Load ad/analytics/tracker scripts instead of dropping them. Tracker
    /// blocking is on by default (trims the passive-fingerprinting surface and
    /// speeds loads); pass this to disable it.
    #[arg(long, env = "NOKK_ALLOW_TRACKERS")]
    allow_trackers: bool,

    /// Do not load images (`<img>`, CSS backgrounds, image preloads), as Chrome
    /// does with images switched off: less traffic and faster pages when the
    /// pictures do not matter. A Cloudflare challenge's own images still load.
    #[arg(long, env = "NOKK_NO_IMAGES")]
    no_images: bool,

    /// Give each browser context its own coherent fingerprint (OS, UA, screen,
    /// WebGL, and a matching TLS emulation), selected deterministically from the
    /// context's identity. Off by default; useful when driving many isolated
    /// contexts that should each look like a different machine.
    #[arg(long, env = "NOKK_ROTATE_FINGERPRINT")]
    rotate_fingerprint: bool,

    /// Derive each context's timezone and locale from its proxy's exit IP, so the
    /// reported `Intl` timezone and `navigator.languages` match where the traffic
    /// comes from. Costs one geolocation request per distinct proxy (cached),
    /// made through that proxy. Best-effort; no effect without a proxy.
    #[arg(long, env = "NOKK_GEOIP_TIMEZONE")]
    geoip_timezone: bool,

    /// Chrome major version to emulate (TLS fingerprint + JS UA together), e.g.
    /// `148`. Defaults to current stable; set it to match the browser a reused
    /// `cf_clearance` was minted under. Bounded by what wreq-util ships — an
    /// unavailable version falls back to the default.
    #[arg(long, env = "NOKK_CHROME_VERSION", value_name = "MAJOR")]
    chrome_version: Option<u32>,

    /// For `--load`: retry up to N extra times if the response is a Cloudflare
    /// "Just a moment…" challenge (the pass is probabilistic).
    #[arg(long, default_value_t = 0)]
    retries: u32,

    /// For `--load`: exit with code 3 if the page still shows a Cloudflare
    /// challenge at the end. Turns "is my `cf_clearance` still good?" into a
    /// question a script can ask — a dead or mismatched clearance otherwise
    /// looks like an ordinary load of a "Just a moment…" page.
    #[arg(long)]
    fail_on_challenge: bool,

    /// For `--load`: after loading, print every network request the page made
    /// (document + scripts + fetch/XHR) as `[type] METHOD url → status (N bytes)`.
    #[arg(long)]
    dump_requests: bool,

    /// For `--load`: print the response *body* of the first captured request
    /// whose URL contains this substring (e.g. an `/api/...` JSON call).
    #[arg(long, value_name = "URL_SUBSTR")]
    dump_request: Option<String>,

    /// For `--load`: fill a form field, `SELECTOR=VALUE`. Repeatable, applied
    /// in order before `--click`. Sets the value and fires the input/change
    /// events a real keystroke sequence produces.
    #[arg(long, value_name = "SELECTOR=VALUE", requires = "load")]
    fill: Vec<String>,

    /// For `--load`: click an element by selector, with real (trusted) pointer
    /// events. Repeatable, applied in order after `--fill`.
    #[arg(long, value_name = "SELECTOR", requires = "load")]
    click: Vec<String>,

    /// For `--load`: after the steps above, wait for a captured response whose
    /// URL contains this substring, print its body to stdout, and exit. The
    /// event loop is pumped while waiting so the page's own callbacks run.
    #[arg(long, value_name = "URL_SUBSTR", requires = "load")]
    wait_response: Option<String>,

    /// Seconds to wait for `--wait-response` (default 45).
    #[arg(long, default_value_t = 45)]
    response_timeout: u64,
}

/// Parse a `scheme://[user:pass@]host:port` proxy URL into a `ProxyConfig`.
fn parse_proxy(s: &str) -> Option<nokk_net::ProxyConfig> {
    let u = url::Url::parse(s).ok()?;
    let scheme = match u.scheme() {
        "http" | "https" => nokk_net::ProxyScheme::Http,
        "socks5" | "socks5h" => nokk_net::ProxyScheme::Socks5,
        _ => return None,
    };
    // `url` drops a port equal to the scheme's default, so `http://host:80` reads as
    // portless. A port written out counts; a missing one is still an error.
    let port = u.port().or_else(|| {
        let default = u.port_or_known_default()?;
        let authority = s.split_once("://")?.1.split(['/', '?', '#']).next()?;
        authority.ends_with(&format!(":{default}")).then_some(default)
    })?;
    // Userinfo comes percent-encoded (`p%40ss`); the proxy wants the real bytes.
    let decode = |v: &str| percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned();
    Some(nokk_net::ProxyConfig {
        scheme,
        host: u.host_str()?.to_string(),
        port,
        username: (!u.username().is_empty()).then(|| decode(u.username())),
        password: u.password().map(decode),
    })
}

/// Import cookies from a harvested-clearance JSON file into a named session.
///
/// Expects the shape nokk-cf writes: `{ "cookies": { name: value, … }, "domain":
/// "…", "url": "…" }`. Each cookie is stored as if the origin had set it for the
/// domain, so the session's next request replays them.
fn import_cookies_file(engine: &Engine, session: &str, path: &std::path::Path) -> Result<()> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&data)?;
    let domain = v
        .get("domain")
        .and_then(|d| d.as_str())
        .ok_or_else(|| anyhow::anyhow!("cookie file missing \"domain\""))?;
    let origin = v
        .get("url")
        .and_then(|u| u.as_str())
        .ok_or_else(|| anyhow::anyhow!("cookie file missing \"url\""))?;
    let cookies = v
        .get("cookies")
        .and_then(|c| c.as_object())
        .ok_or_else(|| anyhow::anyhow!("cookie file missing \"cookies\" object"))?;
    let mut n = 0;
    for (name, value) in cookies {
        let Some(value) = value.as_str() else {
            continue;
        };
        let set_cookie = format!("{name}={value}; Domain={domain}; Path=/; Secure");
        engine
            .import_session_cookie(session, &set_cookie, origin)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        n += 1;
    }
    eprintln!("imported {n} cookies into session '{session}' for {domain}");
    Ok(())
}

/// Render an eval result for the terminal: unwrap a JSON string to its raw text
/// (so newlines/quotes render naturally); print other values as-is.
fn render(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Fill one `--fill SELECTOR=VALUE` step: set the field's value and fire the
/// events a real keystroke sequence produces. Fails when nothing matches, so a
/// renamed form stops the run instead of submitting an empty field. The value
/// itself is never logged.
async fn fill_input(ctx: &BrowserContext, spec: &str) -> Result<()> {
    let (selector, value) = spec
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("--fill needs SELECTOR=VALUE, got {spec:?}"))?;
    let js = format!(
        "((sel, val) => {{ const el = document.querySelector(sel); \
           if (!el) return 'missing'; el.focus(); el.value = val; \
           el.dispatchEvent(new Event('input', {{ bubbles: true }})); \
           el.dispatchEvent(new Event('change', {{ bubbles: true }})); \
           return 'ok'; }})({}, {})",
        serde_json::to_string(selector).unwrap_or_default(),
        serde_json::to_string(value).unwrap_or_default()
    );
    match ctx.evaluate(&js).await {
        Ok(serde_json::Value::String(s)) if s == "ok" => Ok(()),
        _ => anyhow::bail!("--fill: no element matches {selector:?}"),
    }
}

/// Click one `--click SELECTOR` step with trusted pointer events: scroll the
/// element into view, hit its centre. Fails when nothing matches. The page is
/// not touched otherwise — a click that lands on an overlay lands there, as a
/// person's would.
async fn click_selector(ctx: &BrowserContext, selector: &str) -> Result<()> {
    let js = format!(
        "(sel => {{ const el = document.querySelector(sel); if (!el) return 'missing'; \
           el.scrollIntoView({{ block: 'center' }}); \
           const r = el.getBoundingClientRect(); \
           return JSON.stringify({{ x: r.left + r.width / 2, y: r.top + r.height / 2 }}); \
         }})({})",
        serde_json::to_string(selector).unwrap_or_default()
    );
    let out = ctx.evaluate(&js).await?;
    let coords: serde_json::Value = match &out {
        serde_json::Value::String(s) => serde_json::from_str(s).unwrap_or_default(),
        v => v.clone(),
    };
    let (x, y) = match (
        coords.get("x").and_then(|v| v.as_f64()),
        coords.get("y").and_then(|v| v.as_f64()),
    ) {
        (Some(x), Some(y)) => (x, y),
        _ => anyhow::bail!("--click: no element matches {selector:?}"),
    };
    for kind in ["mouseMoved", "mousePressed", "mouseReleased"] {
        ctx.dispatch_mouse(kind, x, y, "left", 1).await?;
    }
    ctx.run_event_loop().await.ok();
    Ok(())
}

/// Wait for the page's own request whose URL contains `needle`, then print its
/// body. The engine records every request with its body, so no in-page hook is
/// needed; the event loop is pumped while waiting so the page's callbacks run.
async fn wait_response(
    ctx: &BrowserContext,
    needle: &str,
    timeout_secs: u64,
    after: usize,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        ctx.run_event_loop().await.ok();
        // Only what the steps caused: a page that asked the same endpoint while
        // loading would otherwise hand back that earlier, unrelated answer.
        if let Some(r) = ctx
            .requests()
            .into_iter()
            .skip(after)
            .find(|r| r.url.contains(needle) && r.status != 0)
        {
            println!("{}", String::from_utf8_lossy(&r.body));
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("no response matching {needle:?} within {timeout_secs}s");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Evaluate `js`, then drive the event loop so any `fetch`/timers it starts
/// complete, and print the result. If the expression is (or resolves to) a
/// Promise, the *resolved* value is printed; otherwise the value itself.
async fn eval_and_print(ctx: &BrowserContext, js: &str) -> Result<()> {
    // Route both sync values and Promise resolutions through `__out`.
    let wrapped = format!(
        "(() => {{ const put = (k, v) => Object.defineProperty(globalThis, k, {{ value: v, writable: true, enumerable: false, configurable: true }}); \
           put('__outDone', false); const v = ({js}); \
           if (v && typeof v.then === 'function') {{ \
             v.then(x => {{ put('__out', x); put('__outDone', true); }}, \
                    e => {{ put('__out', 'ERR: ' + e); put('__outDone', true); }}); \
           }} else {{ put('__out', v); put('__outDone', true); }} \
           return undefined; }})()"
    );
    if let Err(e) = ctx.evaluate(&wrapped).await {
        eprintln!("eval error: {e}");
        std::process::exit(1);
    }
    // One loop turn only drains microtasks, not timers or workers, and most
    // probes wait on those. Spin until the promise settles.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        ctx.run_event_loop().await.ok();
        // `evaluate` returns the result as a string, not a bool.
        let done = ctx.evaluate("globalThis.__outDone === true").await;
        let ready = matches!(&done, Ok(serde_json::Value::Bool(true)))
            || matches!(&done, Ok(serde_json::Value::String(s)) if s == "true");
        if ready || Instant::now() > deadline {
            break;
        }
        // 1 ms, not 10: at 10 ms animation frames land on the wrong grid and
        // `requestAnimationFrame` ticks at 12/24 ms instead of 16.7.
        tokio::time::sleep(Duration::from_micros(500)).await;
    }
    let out = ctx
        .evaluate(
            "globalThis.__out === undefined ? 'undefined' \
             : (typeof globalThis.__out === 'object' ? JSON.stringify(globalThis.__out) : String(globalThis.__out))",
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", render(&out));
    Ok(())
}

impl Cli {
    fn engine_config(&self) -> EngineConfig {
        let mut pool = PoolConfig::default();
        if let Some(w) = self.workers {
            pool.workers = w.max(1);
        } else if self.load.is_some() || self.eval.is_some() {
            // One page, one isolate: a Cloudflare interstitial solve peaks at
            // ~0.6 GB on one thread against ~1.05 GB on eight, in the same time
            // and with the same verdict on every target we test.
            pool.workers = 1;
        }
        if let Some(m) = self.max_contexts {
            pool.max_live_contexts = m.max(1);
        }
        if let Some(mb) = self.max_heap_mb {
            pool.max_heap_mb = Some(mb.max(16)); // a tiny cap would fail instantly
        }
        let mut client = ClientConfig::default();
        // Validated in `real_main`: a proxy that does not parse never gets here.
        client.proxy = self.proxy.as_deref().and_then(parse_proxy);
        EngineConfig {
            pool,
            client,
            // The CLI always drives real traffic (one-shot fetch/load/eval or the
            // CDP server); only the library test harness stays offline.
            use_real_network: true,
            session_store: self.session_store.clone(),
            block_trackers: !self.allow_trackers,
            no_images: self.no_images,
            rotate_fingerprint: self.rotate_fingerprint,
            geoip_timezone: self.geoip_timezone,
            chrome_major: self
                .chrome_version
                .unwrap_or(nokk_net::DEFAULT_CHROME_MAJOR),
            ..Default::default()
        }
    }
}

/// Two malloc arenas for the whole process. glibc gives every thread that
/// contends for the heap an arena of its own (up to 8 per core, 64 MB each), and
/// V8's helper threads, the isolate threads and tokio's all qualify; memory
/// freed in one arena is not reused by the others. On a Cloudflare solve this
/// takes 30-50 MB off the peak (runs vary by +-40 MB), with no change in time. `MALLOC_ARENA_MAX` in the
/// environment still wins, as glibc reads it first.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn limit_malloc_arenas() {
    extern "C" {
        fn mallopt(param: i32, value: i32) -> i32;
    }
    const M_ARENA_MAX: i32 = -8;
    if std::env::var_os("MALLOC_ARENA_MAX").is_none() {
        // SAFETY: mallopt only adjusts allocator tunables; called before any
        // other thread exists.
        unsafe {
            mallopt(M_ARENA_MAX, 2);
        }
    }
}
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn limit_malloc_arenas() {}

fn main() -> Result<()> {
    limit_malloc_arenas();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(real_main())
}

async fn real_main() -> Result<()> {
    let cli = Cli::parse();
    // Going direct when the proxy was meant would expose the real address.
    if let Some(spec) = &cli.proxy {
        if parse_proxy(spec).is_none() {
            anyhow::bail!("--proxy '{spec}' is not scheme://[user:pass@]host:port (http, https, socks5, socks5h)");
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&cli.log))
        .with_target(true)
        .init();

    let started = Instant::now();
    let engine = Engine::new(cli.engine_config())?;
    tracing::info!(
        elapsed_ms = started.elapsed().as_millis(),
        workers = engine.worker_count(),
        "engine ready"
    );

    // One-shot fetch mode: prove the network path end-to-end.
    if let Some(url) = &cli.fetch {
        let t = Instant::now();
        let resp = engine.fetch(url).await?;
        let body = String::from_utf8_lossy(&resp.body);
        tracing::info!(
            status = resp.status,
            bytes = resp.body.len(),
            elapsed_ms = t.elapsed().as_millis(),
            "fetch complete"
        );
        println!("HTTP {} — {}", resp.status, url);
        println!("{body}");
        return Ok(());
    }

    // One-shot load mode: navigate to a URL, then optionally probe the DOM.
    if let Some(url) = &cli.load {
        let t = Instant::now();
        let session = cli.session.clone();
        let proxy = cli.proxy.as_deref().and_then(parse_proxy);
        // Preload a harvested clearance (cf_clearance.json) into the session so the
        // navigation carries it — cookie replay for a Cloudflare-gated site.
        if let Some(path) = &cli.import_cookies {
            let name = session
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--import-cookies requires --session"))?;
            import_cookies_file(&engine, name, path)?;
        }
        // Retry on a Cloudflare challenge (the pass is probabilistic). Without a
        // session each try is a fresh context so a poisoned session doesn't carry
        // over; a named session deliberately reuses its (imported) jar.
        let mut ctx = None;
        for attempt in 0..=cli.retries {
            let c = match &session {
                Some(name) => {
                    engine
                        .new_context_with_session(name.clone(), proxy.clone())
                        .await?
                }
                None => engine.new_context().await?,
            };
            if cli.until_clearance {
                c.set_stop_at_clearance(true);
            }
            // Narrow tool: only the `Error` constructor, to see what the foreign
            // program tripped on. Wider hooks (`JSON.stringify`, `Array.join`,
            // `String.fromCharCode`) change the challenge's course. This one is only
            // visible via `toString`, which is masked.
            if std::env::var("NOKK_TRACE_THROWS").is_ok() {
                let probe = r#"(() => {
                  // Also log who calls the decoder and with what (an empty buffer where
                  // Chrome has data), and who reads pixels (an empty result means a
                  // zero-size canvas).
                  try {
                    const C = globalThis.CanvasRenderingContext2D;
                    if (C && C.prototype && C.prototype.getImageData) {
                      const G = C.prototype.getImageData;
                      C.prototype.getImageData = function (x, y, w, h) {
                        try {
                          const c = this.canvas || {};
                          console.error('[pixels] request ' + w + 'x' + h + ' from canvas ' +
                                        c.width + 'x' + c.height + ' (' + (c.id || c.className || '') + ')');
                        } catch (e) {}
                        return G.apply(this, arguments);
                      };
                    }
                  } catch (e) {}
                  globalThis.__pt_decodeSpy = (buf) => {
                    try {
                      if (Object.prototype.toString.call(buf) !== '[object ArrayBuffer]') return;
                      // The challenge lowers `stackTraceLimit` and replaces `prepareStackTrace`
                      // to hide its frames; read the stack around that.
                      const lim = Error.stackTraceLimit;
                      const prep = Error.prepareStackTrace;
                      try { Error.stackTraceLimit = 30; Error.prepareStackTrace = undefined; } catch (e) {}
                      const snap = String(new Error().stack || '');
                      try { Error.stackTraceLimit = lim; Error.prepareStackTrace = prep; } catch (e) {}
                      const st = snap.split('\n').slice(2, 8)
                        .map((l) => l.trim()).join(' | ');
                      console.error('[decode] ArrayBuffer ' + buf.byteLength + ' bytes @ ' + st.slice(0, 330));
                    } catch (e) {}
                  };
                  const E = globalThis.Error;
                  const seen = [];
                  globalThis.__pt_throwTail = (n) => seen.slice(-(n || 12)).join('\n');
                  const Wrapped = function Error(...a) {
                    const e = new E(...a);
                    try {
                      const where = String(e.stack || '').split('\n').slice(1, 3)
                        .map((l) => l.trim()).join(' | ');
                      seen.push(String(a[0] === undefined ? '' : a[0]).slice(0, 160) + ' @ ' + where.slice(0, 200));
                      if (seen.length > 400) seen.shift();
                    } catch (e2) {}
                    return e;
                  };
                  Wrapped.prototype = E.prototype;
                  for (const k of Object.getOwnPropertyNames(E)) {
                    if (k === 'prototype' || k === 'name' || k === 'length') continue;
                    try { Wrapped[k] = E[k]; } catch (e2) {}
                  }
                  try { Object.defineProperty(E.prototype, 'constructor', { value: Wrapped, writable: true, configurable: true }); } catch (e2) {}
                  globalThis.Error = globalThis.__pt_native ? __pt_native(Wrapped) : Wrapped;
                })();"#;
                c.add_frame_init_script(probe.to_string());
                c.add_init_script(probe.to_string());
            }
            // Where the error beacon is sent from. The challenge posts to `/eb/` when
            // something fails; Chrome never does there. The body is encrypted but the
            // call site is readable from the stack. Deliberately narrow: one hook on
            // send, since any extra patching changes what is measured.
            if std::env::var("NOKK_TRACE_BEACON").is_ok() {
                let probe = r#"(() => {
                  globalThis.__ptEncMin = __ENCMIN__;
                  globalThis.__ptLight = __LIGHT__;
                  try {
                    const S = XMLHttpRequest.prototype.send;
                    const O = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function (m, u) {
                      this.__ptU = String(u);
                      // Serialization window: the body is built between open and send; only then
                      // does the string feed show body fields rather than the engine's own style
                      // parsing.
                      try {
                        if (/\/cdn-cgi\/challenge-platform\//.test(this.__ptU) && !globalThis.__ptCollected) {
                          globalThis.__ptSerializing = 1;
                        }
                      } catch (e) {}
                      return O.apply(this, arguments);
                    };
                    XMLHttpRequest.prototype.send = function (b) {
                      try {
                        // Report is going out, so collection is done: dump the counters.
                        if (/\/fo\//.test(this.__ptU || '') && b && b.length > 50000) {
                          try { globalThis.__ptDumpCounts && __ptDumpCounts(); } catch (e) {}
                          try {
                            const T = globalThis.__ptTime || {};
                            const rows = Object.keys(T).map((k) => [k, T[k]]).sort((x, y) => y[1] - x[1]).slice(0, 14);
                            for (const [k, v] of rows) {
                              console.error('[time] ' + Math.round(v) + 'ms - ' + k);
                            }
                          } catch (e) {}
                        }
                        // Size oracle: which program came back for the first POST and what the
                        // report got. Decrypted length, not compressed; compare with Chrome's
                        // run on the same address.
                        // Mark in the probe feed: everything read before it went into the first
                        // POST body.
                        if (/\/cdn-cgi\/challenge-platform\//.test(this.__ptU || '') && b && b.length > 1000
                            && !globalThis.__ptMarked) {
                          globalThis.__ptMarked = 1;
                          try { globalThis.__pt_probeMark && __pt_probeMark('first POST ' + b.length); } catch (e) {}
                        }
                        if (/\/cdn-cgi\/challenge-platform\//.test(this.__ptU || '') && b && b.length > 1000
                            && b.length < 20000 && !globalThis.__ptFirstBody) {
                          globalThis.__ptFirstBody = 1;
                          globalThis.__ptCollected = 1;
                          globalThis.__ptSerializing = 0;
                          try {
                            const strs = globalThis.__ptStrings || [];
                            const s1 = JSON.stringify(strs);
                            console.error('[strings] total=' + strs.length);
                            for (let q = 0; q < s1.length; q += 250) {
                              console.error('[strings ' + strs.length + ':' + (q / 250) + '] ' + s1.slice(q, q + 250));
                            }
                          } catch (e) {}
                          const s0 = String(b);
                          for (let q = 0; q < s0.length; q += 250) {
                            console.error('[FIRST ' + s0.length + ':' + (q / 250) + '] ' + s0.slice(q, q + 250));
                          }
                        }
                        if (/\/cdn-cgi\/challenge-platform\//.test(this.__ptU || '')) {
                          const url = this.__ptU, t0 = Math.round(performance.now());
                          const sent = (b && b.length) || 0;
                          this.addEventListener('loadend', () => {
                            let got = 0;
                            try { got = (this.responseText || '').length; } catch (e) {}
                            console.error('[xhr] ' + t0 + 'ms body=' + sent + ' → ' + this.status +
                                          ' resp=' + got + ' in ' + (Math.round(performance.now()) - t0) +
                                          'ms ' + url.slice(-46));
                          });
                        }
                        if (/\/eb\//.test(this.__ptU || '')) {
                          const at = String(new Error().stack || '(no stack)');
                          for (const line of at.split('\n').slice(0, 14)) {
                            console.error('[beacon] ' + line.trim().slice(0, 220));
                          }
                          console.error('[beacon] size=' + ((b && b.length) || 0));
                        }
                      } catch (e) {}
                      return S.apply(this, arguments);
                    };
                    // Counts calls our usual probe does not see: Chrome's collector calls
                    // these, and we need to know whether our run reaches them.
                    const N = Object.create(null);
                    const L = Object.create(null);
                    const bump = (k) => { N[k] = (N[k] || 0) + 1; };
                    const grew = (k, v) => {
                      try {
                        const n = v == null ? 0 : (typeof v === 'string' ? v.length
                          : (typeof v === 'number' || typeof v === 'boolean' ? String(v).length
                          : (v.length !== undefined && typeof v.length === 'number' ? v.length : 0)));
                        L[k] = (L[k] || 0) + n;
                      } catch (e) {}
                    };
                    const count = (obj, label, names) => {
                      // `NOKK_TRACE_BEACON=light`: request feed only, no member patching. The
                      // counters slow collection by seconds; real timing needs the light run.
                      if (globalThis.__ptLight || !obj) return;
                      for (const n of names) {
                        const f = obj[n];
                        if (typeof f !== 'function') continue;
                        try {
                          Object.defineProperty(obj, n, {
                            value: function (...a) {
                              bump(label + '.' + n);
                              const t0 = performance.now();
                              const r = f.apply(this, a);
                              // Time per call: the challenge times itself, so a slow answer is as
                              // visible to it as a wrong one.
                              try {
                                const key = label + '.' + n;
                                const T = (globalThis.__ptTime = globalThis.__ptTime || {});
                                T[key] = (T[key] || 0) + (performance.now() - t0);
                              } catch (e) {}
                              grew(label + '.' + n, r);
                              return r;
                            },
                            writable: true, enumerable: false, configurable: true,
                          });
                        } catch (e) {}
                      }
                    };
                    // The report passes through `TextEncoder.encode` before compression and
                    // encryption, so its pieces are plaintext here. Retried hook: the encoder
                    // appears after the probe.
                    {
                      let en = 0;
                      const arm = () => {
                        const TE = globalThis.TextEncoder && globalThis.TextEncoder.prototype;
                        const enc = TE && TE.encode;
                        if (!enc || enc.__ptWrapped) return !!enc;
                        const wrapped = function (x) {
                          const s = String(x == null ? '' : x);
                          if (s.length > (globalThis.__ptEncMin || 30) && (globalThis.__encN = (globalThis.__encN || 0) + 1) < 70) {
                            let at = '';
                            try {
                              at = String(new Error().stack || '').split('\n').slice(2, 5)
                                .map((x) => x.trim().replace(/^at /, '').slice(0, 46)).join(' < ');
                            } catch (e) {}
                            console.error('[enc ' + (en++) + '] ' + Math.round(performance.now()) + 'ms ' + (() => { try { return location.host.slice(0, 18) + ' '; } catch (e) { return '? '; } })() + s.length + ' | nonzero=' + (() => { let n = 0, sum = 0; for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c) { n++; sum = (sum * 31 + c) >>> 0; } } return n + ' sum=' + sum; })() + (s.length < 2000 || s.length > 14000 ? ' text: ' + s.slice(0, 400).replace(/[^\x20-\x7e]/g, '.') : ' codes: ') + Array.from(s.slice(0, 24)).map((c) => c.charCodeAt(0)).join(',') + ' | ' + Array.from(s.slice(Math.floor(s.length / 2), Math.floor(s.length / 2) + 12)).map((c) => c.charCodeAt(0)).join(','));
if (s.length >= __DUMPLO__ && s.length <= __DUMPHI__ && !(globalThis.__ptD = globalThis.__ptD || {})[s.length]) {
  globalThis.__ptD[s.length] = 1;
  for (let q = 0; q < s.length; q += 60) console.error('[chunk ' + s.length + ':' + (q / 60) + '] ' + Array.from(s.slice(q, q + 60)).map((c) => c.charCodeAt(0)).join(','));
  console.error('[tail ' + s.length + '] parts=' + s.split('|').length + ' last=' + JSON.stringify(s.split('|').slice(-3).map((x) => x.slice(-40))));
}
                          }
                          return enc.call(this, x);
                        };
                        wrapped.__ptWrapped = true;
                        try {
                          Object.defineProperty(TE, 'encode', { value: wrapped, writable: true, configurable: true });
                          return true;
                        } catch (e) { return false; }
                      };
                      if (!arm()) {
                        let tries = 0;
                        const t = setInterval(() => { if (arm() || ++tries > 40) clearInterval(t); }, 25);
                      }
                    }
                    // Whose style is enumerated. The challenge dumps a node's whole computed
                    // style, and ours came out 300 chars longer than Chrome's: wrong node or
                    // wrong environment. Light hook: node traits only, first twenty calls.
                    try {
                      const G = globalThis.getComputedStyle;
                      if (G && !G.__ptSaid) {
                        const V = function getComputedStyle(el, ps) {
                          const r = G.apply(this, arguments);
                          try {
                            if ((globalThis.__ptCsN = (globalThis.__ptCsN || 0) + 1) <= 20) {
                              const who = (n) => !n ? '-' : (n.nodeName || '?') +
                                (n.id ? '#' + n.id : '') +
                                (n.className && n.className.baseVal === undefined && typeof n.className === 'string' && n.className ? '.' + n.className.slice(0, 24) : '');
                              let chain = '', p = el;
                              for (let i = 0; i < 4 && p; i++) { chain += (i ? ' < ' : '') + who(p); p = p.parentNode; }
                              console.error('[cs] ' + who(el) + ' chain ' + chain +
                                ' connected=' + (el && el.isConnected) +
                                ' pseudo=' + String(ps) +
                                ' doc=' + (el && el.ownerDocument === document) +
                                ' color=' + (r && r.color) + ' fontSize=' + (r && r.fontSize) +' children=' + (el && el.children ? Array.prototype.map.call(el.children, (k) => k.nodeName + (k.getAttribute && k.getAttribute('style') ? '[' + k.getAttribute('style').slice(0, 40) + ']' : '')).join(',').slice(0, 160) : '?') + ' text=' + JSON.stringify(String((el && el.textContent) || '').slice(0, 40)) + ' from=' + (() => { try { return String(new Error().stack || '').split('\n').slice(2, 4).map((x) => x.trim().replace(/^at /, '').slice(0, 60)).join(' < '); } catch (e) { return '?'; } })());
                            }
                          } catch (e) {}
                          return r;
                        };
                        V.__ptSaid = 1;
                        globalThis.getComputedStyle = globalThis.__pt_native ? __pt_native(V) : V;
                      }
                    } catch (e) {}
                    // How SVG text is measured: for emoji this reveals which sequences the
                    // browser merges into one glyph.
                    try {
                      const P = globalThis.SVGTextContentElement && SVGTextContentElement.prototype;
                      for (const name of ['getComputedTextLength', 'getSubStringLength', 'getNumberOfChars',
                                          'getExtentOfChar', 'getStartPositionOfChar', 'getEndPositionOfChar']) {
                        const f = P && P[name];
                        if (!f || f.__ptSaid) continue;
                        const V = function (...a) {
                          const r = f.apply(this, a);
                          try {
                            if ((globalThis.__ptSvgN = (globalThis.__ptSvgN || 0) + 1) <= 40) {
                              const show = (v) => (v && typeof v === 'object'
                                ? '{' + ['x', 'y', 'width', 'height'].map((k) => k + '=' + (v[k] === undefined ? '?' : v[k])).join(',') + '}'
                                : String(v));
                              console.error('[svg] ' + name + '(' + a.join(',') + ') font=' + (() => { try { const cs = getComputedStyle(this); return cs.fontSize + '/' + cs.fontFamily.slice(0, 20); } catch (e) { return '?'; } })() + ' text=' +
                                JSON.stringify(String(this.textContent || '').slice(0, 70)) + ' -> ' + show(r));
                            }
                          } catch (e) {}
                          return r;
                        };
                        V.__ptSaid = 1;
                        try { Object.defineProperty(V, 'name', { value: name }); } catch (e) {}
                        Object.defineProperty(P, name, { value: V, writable: true, configurable: true });
                      }
                      const G = globalThis.SVGGraphicsElement && SVGGraphicsElement.prototype;
                      const bb = G && G.getBBox;
                      if (bb && !bb.__ptSaid) {
                        const V = function getBBox(...a) {
                          const r = bb.apply(this, a);
                          try {
                            if ((globalThis.__ptBBoxN = (globalThis.__ptBBoxN || 0) + 1) <= 40) {
                              console.error('[svg] getBBox font=' + (() => { try { const cs = getComputedStyle(this); return cs.fontSize + '/' + cs.fontFamily.slice(0, 20); } catch (e) { return '?'; } })() + ' text=' +
                                JSON.stringify(String(this.textContent || '').slice(0, 70)) +
                                ' -> {' + [r.x, r.y, r.width, r.height].join(',') + '}');
                            }
                          } catch (e) {}
                          return r;
                        };
                        V.__ptSaid = 1;
                        Object.defineProperty(G, 'getBBox', { value: V, writable: true, configurable: true });
                      }
                    } catch (e) {}
                    // What the page passes to JSON and base64: the initial payload is built
                    // this way and its content is only visible here.
                    try {
                      const J = JSON.stringify;
                      if (!J.__ptSaid) {
                        const V = function stringify(...a) {
                          const r = J.apply(this, a);
                          try {
                            if (typeof r === 'string' && r.length > 300
                                && (globalThis.__ptJsonN = (globalThis.__ptJsonN || 0) + 1) <= 6) {
                              for (let q = 0; q < Math.min(r.length, 4000); q += 250) {
                                console.error('[json ' + r.length + ':' + (q / 250) + '] ' + r.slice(q, q + 250));
                              }
                            }
                          } catch (e) {}
                          return r;
                        };
                        V.__ptSaid = 1;
                        JSON.stringify = globalThis.__pt_native ? __pt_native(V) : V;
                      }
                      const B = globalThis.btoa;
                      if (B && !B.__ptSaid) {
                        const V = function btoa(x) {
                          const s0 = String(x);
                          try {
                            if (s0.length > 300 && (globalThis.__ptBtoaN = (globalThis.__ptBtoaN || 0) + 1) <= 4) {
                              for (let q = 0; q < Math.min(s0.length, 4000); q += 250) {
                                console.error('[btoa ' + s0.length + ':' + (q / 250) + '] ' + s0.slice(q, q + 250));
                              }
                            }
                          } catch (e) {}
                          return B.call(this, x);
                        };
                        V.__ptSaid = 1;
                        globalThis.btoa = globalThis.__pt_native ? __pt_native(V) : V;
                      }
                    } catch (e) {}
                    count(globalThis.OfflineAudioContext && OfflineAudioContext.prototype, 'audio',
                          ['startRendering', 'createOscillator', 'createDynamicsCompressor']);
                    count(globalThis.HTMLMediaElement && HTMLMediaElement.prototype, 'media', ['canPlayType']);
                    // Which codecs are queried and what we answered: Chrome answers the same
                    // list differently, and the whole list is needed to compare offline.
                    try {
                      const M = globalThis.HTMLMediaElement && HTMLMediaElement.prototype;
                      const C = M && M.canPlayType;
                      if (C && !C.__ptSaid) {
                        const V = function canPlayType(t) {
                          const r = C.apply(this, arguments);
                          try { console.error('[codec] ' + String(t) + ' -> ' + String(r)); } catch (e) {}
                          return r;
                        };
                        V.__ptSaid = 1;
                        Object.defineProperty(M, 'canPlayType',
                          { value: globalThis.__pt_native ? __pt_native(V) : V,
                            writable: true, enumerable: false, configurable: true });
                      }
                    } catch (e) {}
                    count(globalThis.HTMLCanvasElement && HTMLCanvasElement.prototype, 'canvas',
                          ['transferControlToOffscreen', 'toDataURL', 'toBlob', 'captureStream', 'getContext']);
                    count(globalThis.OffscreenCanvas && OffscreenCanvas.prototype, 'off',
                          ['convertToBlob', 'transferToImageBitmap']);
                    try {
                        for (const N of ['WebGLRenderingContext', 'WebGL2RenderingContext']) {
                          const W = globalThis[N] && globalThis[N].prototype;
                          if (!W || !W.readPixels || W.__ptRp) continue;
                          try { Object.defineProperty(W, '__ptRp', { value: 1 }); } catch (e) {}
                          const rp = W.readPixels;
                          W.readPixels = function (x, y, w, h, f, t, p) {
                            console.error('[rp] ' + N + ' ' + w + 'x' + h);
                            return rp.apply(this, arguments);
                          };
                        }
                        const HC = globalThis.HTMLCanvasElement && globalThis.HTMLCanvasElement.prototype;
                        if (HC && HC.getContext && !HC.__ptGc) {
                          try { Object.defineProperty(HC, '__ptGc', { value: 1 }); } catch (e) {}
                          const hg = HC.getContext;
                          HC.getContext = function (ty, a) {
                            const r = hg.apply(this, arguments);
                            console.error('[ectx] ' + ty + ' ' + this.width + 'x' + this.height +
                                ' -> ' + (r ? 'ok' : String(r)));
                            return r;
                          };
                        }
                        for (const N of ['CanvasRenderingContext2D', 'OffscreenCanvasRenderingContext2D']) {
                          const C = globalThis[N] && globalThis[N].prototype;
                          if (!C || !C.getImageData || C.__ptGid) continue;
                          try { Object.defineProperty(C, '__ptGid', { value: 1 }); } catch (e) {}
                          const gi = C.getImageData;
                          C.getImageData = function (x, y, w, h) {
                            const r = gi.apply(this, arguments);
                            let show = '';
                            if (w * h <= 4) {
                              try {
                                show = ' -> ' + Object.prototype.toString.call(r.data) + '[' + [].slice.call(r.data).join(',') + '] ' +
                                  r.colorSpace + '/' + r.pixelFormat + ' options=' + JSON.stringify(arguments[4] || null) +
                                  ' canvas=' + JSON.stringify(this.getContextAttributes ? this.getContextAttributes() : null);
                              } catch (e) { show = ' -> ' + e.name; }
                            }
                            console.error('[gid] ' + w + 'x' + h + ' on ' + (this.canvas ? this.canvas.width + 'x' + this.canvas.height : '?') + show);
                            return r;
                            
                          };
                        }
                        // The challenge catches its own exceptions and reports them to `/eb/`.
                        // A trap at error construction is the lightest possible hook. The beacon
                        // is encrypted, but the challenge first serializes the error itself with
                        // `JSON.stringify(err, Object.getOwnPropertyNames(err))`, so it is
                        // plaintext here. Fires only on errors; nothing else is touched.
                        if (!globalThis.__ptJsonHook) {
                          globalThis.__ptJsonHook = 1;
                          const S = JSON.stringify;
                          JSON.stringify = function (v, ...rest) {
                            try {
                              if (v instanceof Error) {
                                console.error('[caught] ' + Math.round(performance.now()) + 'ms ' +
                                  String(v.name) + ': ' + String(v.message).slice(0, 200) + ' | fields: ' +
                                  Object.getOwnPropertyNames(v).join(',') + ' | ' +
                                  String(v.stack || '').split(String.fromCharCode(10)).slice(0, 5)
                                    .map((l) => l.trim()).join(' <- ').slice(0, 300));
                              }
                            } catch (x) {}
                            return S.call(this, v, ...rest);
                          };
                        }
                        if (!globalThis.__ptErrHook) {
                          globalThis.__ptErrHook = 1;
                          let shown = 0;
                          const E0 = globalThis.Error;
                          for (const N of ['Error', 'TypeError', 'RangeError', 'ReferenceError', 'SyntaxError']) {
                            const C = globalThis[N];
                            if (typeof C !== 'function') continue;
                            const W = function (...a) {
                              const e = new C(...a);
                              // The challenge lowers `stackTraceLimit` and installs its own
                              // `prepareStackTrace`; lift both while reading, otherwise script names
                              // become `<anonymous>` and the code path reads wrong.
                              const lim = E0.stackTraceLimit, prep = E0.prepareStackTrace;
                              try { E0.stackTraceLimit = 30; E0.prepareStackTrace = undefined; } catch (x) {}
                              const snap = String(e.stack || '');
                              try { E0.stackTraceLimit = lim; E0.prepareStackTrace = prep; } catch (x) {}
                              if (shown++ < 120) {
                                try {
                                  // Six frames, not three: the challenge's own errors have no message, so
                                  // only the constructing code and collection step identify them.
                                  console.error('[thrown] ' + Math.round(performance.now()) + 'ms ' + N + ': ' + String(a[0]).slice(0, 90) +
                                    ' | ' + snap.split(String.fromCharCode(10)).slice(1, 8)
                                      .map((l) => l.trim().replace(/^at /, '')).join(' <- ').slice(0, 460));
                                } catch (x) {}
                              }
                              return e;
                            };
                            W.prototype = C.prototype;
                            try { Object.defineProperty(W, 'name', { value: N }); } catch (x) {}
                            try { globalThis[N] = W; } catch (x) {}
                          }
                        }
                        // Event-loop lag in this frame: if the host page hogs the thread, the
                        // challenge just waits and its own clock shows seconds where Chrome shows
                        // fractions.
                        if (!globalThis.__ptLagProbe) {
                          globalThis.__ptLagProbe = 1;
                          let last = performance.now(), worst = 0, ticks = 0;
                          const tick = () => {
                            const now = performance.now();
                            const lag = now - last - 4;
                            if (lag > worst) worst = lag;
                            if (lag > 400) {
                              console.error('[stall] from ' + Math.round(last) + 'ms to ' + Math.round(now) +
                                            'ms, idle ' + Math.round(lag) + 'ms');
                            }
                            last = now;
                            if (++ticks % 100 === 0) {
                              console.error('[lag] ' + Math.round(now) + 'ms ticks=' + ticks +
                                            ' worst delay=' + Math.round(worst) + 'ms');
                              worst = 0;
                            }
                            setTimeout(tick, 4);
                          };
                          setTimeout(tick, 4);
                        }
                        const gpu = globalThis.navigator && globalThis.navigator.gpu;
                        if (gpu && !gpu.__ptG) {
                          try { Object.defineProperty(gpu, '__ptG', { value: 1 }); } catch (e) {}
                          for (const k of ['requestAdapter', 'getPreferredCanvasFormat']) {
                            const f = gpu[k];
                            if (typeof f !== 'function') continue;
                            gpu[k] = function () {
                              let r;
                              try { r = f.apply(this, arguments); } catch (e) { console.error('[gpu] ' + k + ' threw ' + e.name); throw e; }
                              if (r && typeof r.then === 'function') {
                                return r.then((v) => { console.error('[gpu] ' + k + ' -> ' + (v ? 'object' : String(v))); return v; },
                                              (e) => { console.error('[gpu] ' + k + ' rejected ' + e); throw e; });
                              }
                              console.error('[gpu] ' + k + ' -> ' + String(r));
                              return r;
                            };
                          }
                        }
                        const OP = globalThis.OffscreenCanvas && globalThis.OffscreenCanvas.prototype;
                        const og = OP && OP.getContext;
                        if (og) {
                          let seq = 0;
                          Object.defineProperty(OP, 'getContext', { value: function (ty, a) {
                            let r, err = '';
                            try { r = og.call(this, ty, a); } catch (e) { err = e.name; }
                            const id = ++seq;
                            console.error('[octx] #' + id + ' ' + ty + ' ' + this.width + 'x' + this.height +
                                ' options=' + (a ? JSON.stringify(a) : '-') + ' -> ' + (err || (r ? 'ok' : String(r))));
                            // For the 49x44 canvas, trace the first ops: shows how the third differs
                            // from the first two.
                            if (r && ty === '2d' && this.width * this.height === 2156) {
                              let n = 0;
                              const seen = Object.create(null);
                              for (const k of Object.getOwnPropertyNames(Object.getPrototypeOf(r))) {
                                let d;
                                try { d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(r), k); } catch (e) { continue; }
                                if (!d || typeof d.value !== 'function') continue;
                                const f = d.value;
                                try {
                                  r[k] = function (...args) {
                                    if (n < 26 && !seen[k]) { seen[k] = 1; console.error('[cop] #' + id + ' ' + (n++) + ' ' + k); }
                                    return f.apply(this, args);
                                  };
                                } catch (e) {}
                              }
                            }
                            if (err) throw new TypeError(err);
                            return r;
                          }, writable: true, configurable: true });
                        }
                    } catch (e) {}
                    count(globalThis.Worker && Worker.prototype, 'worker', ['postMessage', 'terminate']);
                    count(globalThis.Navigator && Navigator.prototype, 'nav', ['getGamepads']);
                    count(globalThis, 'win', ['atob', 'btoa', 'matchMedia', 'getComputedStyle',
                                              'setTimeout', 'requestAnimationFrame', 'queueMicrotask']);
                    // Other possibly slow calls: measurement, layout, images.
                    count(globalThis.Document && Document.prototype, 'd',
                          ['createElement', 'createElementNS', 'querySelector', 'querySelectorAll', 'getElementById']);
                    count(globalThis.Element && Element.prototype, 'el',
                          ['getBoundingClientRect', 'getClientRects', 'querySelector', 'querySelectorAll',
                           'setAttribute', 'getAttribute', 'attachShadow', 'closest', 'matches']);
                    count(globalThis.Node && Node.prototype, 'node', ['appendChild', 'insertBefore', 'removeChild', 'cloneNode']);
                    count(globalThis.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype, 'ctx2d',
                          ['measureText', 'fillText', 'strokeText', 'getImageData', 'putImageData', 'drawImage',
                           'fill', 'stroke', 'createRadialGradient', 'createLinearGradient']);
                    count(globalThis.SVGTextContentElement && SVGTextContentElement.prototype, 'svgText',
                          ['getComputedTextLength', 'getNumberOfChars', 'getSubStringLength']);
                    count(globalThis.SVGGraphicsElement && SVGGraphicsElement.prototype, 'svg', ['getBBox']);
                    count(globalThis.FontFaceSet && FontFaceSet.prototype, 'fonts', ['check', 'load']);
                    count(globalThis.RTCPeerConnection && RTCPeerConnection.prototype, 'rtc', ['getStats']);
                    // Dump when the report is sent, not on a timer: the widget frame may be
                    // gone by then, taking the counters with it.
                    globalThis.__ptDumpCounts = () => {
                      for (const k of Object.keys(N).sort((a, b) => (L[b] || 0) - (L[a] || 0))) {
                        console.error('[count] ' + N[k] + ' calls, ' + (L[k] || 0) + ' chars - ' + k);
                      }
                    };
                    setTimeout(() => { try { __ptDumpCounts(); } catch (e) {} }, 24000);
                    // Also what the challenge itself treats as an error: it does not always
                    // call `console.error` before the beacon, but its rejected promise reaches
                    // the global handler.
                    addEventListener('unhandledrejection', (e) => {
                      try { console.error('[beacon] rejected: ' + String((e.reason && e.reason.stack) || e.reason).slice(0, 300)); } catch (x) {}
                    });
                    addEventListener('error', (e) => {
                      try { console.error('[beacon] error: ' + String(e.message || '') + ' @ ' + String(e.filename || '').slice(-40) + ':' + e.lineno); } catch (x) {}
                    });
                  } catch (e) {}
                })();"#;
                // Report pieces below this length are not logged: small ones flood the
                // output, though sometimes the short one differs (Chrome's font list is
                // 71 chars).
                let probe = probe.replace(
                    "__LIGHT__",
                    if std::env::var("NOKK_TRACE_BEACON").as_deref() == Ok("light") { "1" } else { "0" },
                );
                let probe = probe.replace(
                    "__ENCMIN__",
                    &std::env::var("NOKK_ENC_MIN").unwrap_or_else(|_| "30".into()),
                );
                // Which piece to dump whole: `NOKK_DUMP_ENC=30000-32000`. Defaults to the
                // audio block. Use the same range for the Chrome run it is compared with.
                let window = std::env::var("NOKK_DUMP_ENC").unwrap_or_else(|_| "15000-16000".into());
                let (lo, hi) = window.split_once('-').unwrap_or(("15000", "16000"));
                let probe = probe.replace("__DUMPLO__", lo.trim()).replace("__DUMPHI__", hi.trim());
                c.add_frame_init_script(spread_to_realms(&probe, "beacon"));
                c.add_worker_init_script(probe.clone());
                c.add_init_script(probe);
            }
            // Source of the foreign program. It is built with `new Function`, the only
            // place it is plaintext: the network copy is encrypted and its stack gives
            // offsets that are useless without the source. One hook, on the
            // constructor, enabled with `NOKK_DUMP_VM`.
            if std::env::var("NOKK_DUMP_VM").is_ok() {
                let probe = r#"(() => {
                  try {
                    const F = globalThis.Function;
                    const keep = (a) => {
                      try {
                        const t = String(a.length ? a[a.length - 1] : '');
                        if (t.length > (globalThis.__ptVmMin || 20000) &&
                            (!globalThis.__pt_vmSrc || t.length > globalThis.__pt_vmSrc.length)) {
                          globalThis.__pt_vmSrc = t;
                          console.error('[vmsrc] ' + Math.round(performance.now()) + 'ms ' + t.length + ' chars');
                        }
                      } catch (e) {}
                    };
                    const mask = (f) => (globalThis.__pt_native ? __pt_native(f) : f);
                    const wrap = (host) => {
                      // The challenge serializes caught errors before encrypting the `/eb/`
                      // beacon, using a clean `JSON` from the sandbox realm, so it is plaintext
                      // here. Log to the frame console: the realm has none that is read.
                      try {
                        const J = host.JSON;
                        if (J && typeof J.stringify === 'function' && !J.stringify.__ptSeen) {
                          const S = J.stringify;
                          const V = function stringify(v) {
                            try {
                              if (v && typeof v === 'object' && typeof v.stack === 'string') {
                                console.error('[caught] ' + Math.round(performance.now()) + 'ms ' +
                                  String(v.name) + ': ' + String(v.message).slice(0, 200) +
                                  ' | fields: ' + Object.getOwnPropertyNames(v).join(',') + ' | ' +
                                  String(v.stack).split(String.fromCharCode(10)).slice(0, 6)
                                    .map((l) => l.trim()).join(' <- ').slice(0, 320));
                              }
                            } catch (e) {}
                            return S.apply(this, arguments);
                          };
                          V.__ptSeen = 1;
                          J.stringify = mask(V);
                        }
                      } catch (e) {}
                      // Who calls node replacement. The challenge takes clean references from
                      // the sandbox realm, so the hook goes there too. `appendChild` and
                      // `insertBefore` stay untouched: they are hot and wrapping them changes
                      // collection.
                      try {
                        // Ring of recent node lookups: when replacement gets an empty value, we
                        // need to know what produced it.
                        if (!globalThis.__ptRing) globalThis.__ptRing = [];
                        const ring = globalThis.__ptRing;
                        const note = (what, got) => {
                          try {
                            ring.push(Math.round(performance.now()) + 'ms ' + what + ' -> ' +
                              (got === undefined ? 'undefined' : got === null ? 'null'
                                : (typeof got === 'object' ? String(got.nodeName || Object.prototype.toString.call(got)) : typeof got)));
                            if (ring.length > 16) ring.shift();
                          } catch (e) {}
                        };
                        const watch = (obj, label, names) => {
                          if (!obj) return;
                          for (const n of names) {
                            try {
                              const F = obj[n];
                              if (typeof F !== 'function' || F.__ptSeen) continue;
                              const V = function (...a) {
                                const r = F.apply(this, a);
                                note(label + '.' + n + '(' + a.map((x) => typeof x === 'string' ? x.slice(0, 24) : typeof x).join(',') + ')', r);
                                return r;
                              };
                              V.__ptSeen = 1;
                              Object.defineProperty(obj, n,
                                { value: mask(V), writable: true, enumerable: false, configurable: true });
                            } catch (e) {}
                          }
                        };
                        const D = host.Document && host.Document.prototype;
                        watch(D, 'doc', ['createElement', 'createElementNS', 'createTextNode', 'createComment',
                                         'createDocumentFragment', 'importNode', 'adoptNode', 'getElementById',
                                         'querySelector', 'createRange', 'getElementsByTagName', 'write']);
                        watch(host.Node && host.Node.prototype, 'node', ['cloneNode']);
                        watch(host.Element && host.Element.prototype, 'el', ['attachShadow', 'closest', 'querySelector']);
                        watch(host.DOMParser && host.DOMParser.prototype, 'parser', ['parseFromString']);
                        const P = host.Node && host.Node.prototype;
                        if (P && typeof P.replaceChild === 'function' && !P.replaceChild.__ptSeen) {
                          const F = P.replaceChild;
                          const V = function replaceChild(...a) {
                            try {
                              console.error('[replace] ' + Math.round(performance.now()) + 'ms on ' +
                                (this && this.nodeName) + ' args=' + a.length + ' [' +
                                a.map((x) => x === undefined ? 'undefined' : x === null ? 'null'
                                  : (typeof x === 'object' ? String(x.nodeName) : typeof x + ':' + String(x).slice(0, 20))).join(', ') + ']');
                              if (a[0] === undefined || a[0] === null) {
                                for (const line of (globalThis.__ptRing || [])) console.error('[before replace] ' + line);
                              }
                            } catch (e) {}
                            return F.apply(this, a);
                          };
                          V.__ptSeen = 1;
                          Object.defineProperty(P, 'replaceChild',
                            { value: mask(V), writable: true, enumerable: false, configurable: true });
                        }
                      } catch (e) {}
                      const G = host.Function;
                      if (typeof G !== 'function' || G.__ptSeen) return;
                      const W = function Function(...a) { keep(a); return new G(...a); };
                      W.__ptSeen = 1;
                      W.prototype = G.prototype;
                      try {
                        Object.defineProperty(G.prototype, 'constructor',
                          { value: W, writable: true, configurable: true });
                      } catch (e) {}
                      try { host.Function = mask(W); } catch (e) {}
                      // `Function`'s siblings compile code the same way (async function and
                      // generator constructors). Take them from the realm itself, not from us,
                      // or we would patch ours and miss theirs.
                      let kin = [];
                      try {
                        kin = new G('return [Object.getPrototypeOf(async function(){}).constructor,' +
                                    ' Object.getPrototypeOf(function*(){}).constructor]')();
                      } catch (e) {}
                      for (const C of kin) {
                        try {
                          if (typeof C !== 'function' || C.__ptSeen) continue;
                          const V = function (...a) { keep(a); return new C(...a); };
                          V.__ptSeen = 1;
                          V.prototype = C.prototype;
                          Object.defineProperty(C.prototype, 'constructor',
                            { value: mask(V), writable: true, configurable: true });
                        } catch (e) {}
                      }
                    };
                    globalThis.__ptVmMin = __VMMIN__;
                    wrap(globalThis);
                    console.error('[vmsrc] hook installed, threshold ' + globalThis.__ptVmMin);
                    // The foreign program takes `Function` from a clean realm (an empty
                    // same-origin frame, via `contentWindow`) where our patches are not yet
                    // installed; install them as the realm is handed out.
                    const R = globalThis.__pt_makeRealm;
                    if (typeof R === 'function') {
                      globalThis.__pt_makeRealm = mask(function __pt_makeRealm() {
                        const g = R.apply(this, arguments);
                        try { if (g) wrap(g); } catch (e) {}
                        return g;
                      });
                    }
                  } catch (e) {}
                })();"#;
                // Threshold to keep page noise out of the log; lower it to find what
                // compiles code at all.
                let probe = probe.replace(
                    "__VMMIN__",
                    &std::env::var("NOKK_VM_MIN").unwrap_or_else(|_| "20000".into()),
                );
                c.add_frame_init_script(probe.clone());
                c.add_worker_init_script(probe.clone());
                c.add_init_script(probe);
            }
            // 2D canvas trace: context calls and assignments, from inside the
            // implementation.
            if std::env::var("NOKK_TRACE_CANVAS").is_ok() {
                let flag = "Object.defineProperty(globalThis, '__pt_canvasTrace', { value: 1, configurable: true });";
                c.add_frame_init_script(spread_to_realms(flag, "canvas"));
                c.add_worker_init_script(flag.to_string());
                c.add_init_script(flag.to_string());
            }
            // WebGPU trace: flag for the implementation (frame, its realms, workers).
            if std::env::var("NOKK_TRACE_GPU").is_ok() {
                let flag = "Object.defineProperty(globalThis, '__pt_gpuTrace', { value: 1, configurable: true });";
                c.add_frame_init_script(spread_to_realms(flag, "gpu"));
                c.add_worker_init_script(flag.to_string());
                c.add_init_script(flag.to_string());
            }
            // Custom script injected into every frame at creation
            // (`NOKK_FRAME_INIT=<file>`), for Chrome comparisons where CDP injects the
            // same. The script stores its result in a global that `NOKK_EVAL_FRAMES`
            // reads.
            if let Ok(path) = std::env::var("NOKK_FRAME_INIT") {
                match std::fs::read_to_string(&path) {
                    Ok(js) => {
                        // Also into empty-frame realms: the challenge keeps its sandbox there and
                        // half of its calls are invisible without the probe.
                        c.add_frame_init_script(spread_to_realms(&js, "frame_init"));
                        c.add_init_script(spread_to_realms(&js, "frame_init"));
                    }
                    Err(e) => eprintln!("# NOKK_FRAME_INIT: {path}: {e}"),
                }
            }
            if std::env::var("NOKK_TRACE_FIELDS").is_ok() {
                let probe = r#"(() => {
                  const nat = (f, src) => {
                    try {
                      Object.defineProperty(f, 'name', { value: src.name, configurable: true });
                      Object.defineProperty(f, 'length', { value: src.length, configurable: true });
                    } catch (e) {}
                    return globalThis.__pt_native ? __pt_native(f) : f;
                  };
                  const cf = () => {
                    if (globalThis.__ptInRealm) return true;
                    // And the interstitial page itself (orchestrator on the site's domain): it
                    // posts its own reports to /cdn-cgi/challenge-platform/.
                    if (globalThis._cf_chl_opt) return true;
                    try { return /challenges\.cloudflare/.test(location.host); } catch (e) { return false; }
                  };
                  try {
                    const P = XMLHttpRequest.prototype, XO = P.open, XS = P.send;
                    P.open = nat(function open(m, u) {
                      try {
                        if (cf() && /challenge-platform/.test(String(u))) {
                          if (!globalThis.__ptCollected) globalThis.__ptSerializing = 1;
                          // Second window is the report: same serializer, same per-char reads, body
                          // over 50K.
                          else globalThis.__ptSerializing2 = 1;
                        }
                      } catch (e) {}
                      return XO.apply(this, arguments);
                    }, XO);
                    P.send = nat(function send(b) {
                      try {
                        if (globalThis.__ptSerializing && b && b.length > 1000 && b.length < 20000 && !globalThis.__ptCollected) {
                          globalThis.__ptCollected = 1;
                          globalThis.__ptSerializing = 0;
                          const strs = globalThis.__ptStrings || [];
                          const s1 = JSON.stringify(strs);
                          console.error('[fields] total=' + strs.length + ' body=' + b.length);
                          globalThis.__ptStrings = [];
                          try {
                            const readLog = globalThis.__ptReads || [];
                            const s2 = JSON.stringify(readLog.slice(-200));
                            for (let q = 0; q < s2.length; q += 250) console.error('[reads ' + q / 250 + '] ' + s2.slice(q, q + 250));
                          } catch (e) {}
                          for (let q = 0; q < s1.length; q += 250) {
                            console.error('[fields ' + strs.length + ':' + (q / 250) + '] ' + s1.slice(q, q + 250));
                          }
                        }
                        if (globalThis.__ptSerializing2 && b && b.length > 1000 && b.length <= 50000) {
                          // Small report after the first (the interstitial orchestrator's final one).
                          const k = (globalThis.__ptSmallK = (globalThis.__ptSmallK || 0) + 1);
                          globalThis.__ptSerializing2 = 0;
                          const strs = globalThis.__ptStrings2 || [];
                          globalThis.__ptStrings2 = [];
                          const s1 = JSON.stringify(strs);
                          console.error('[fields#' + k + '] total=' + strs.length + ' body=' + b.length + ' slices=' + Math.ceil(s1.length / 250));
                          for (let q = 0; q * 250 < s1.length; q++) console.error('[fields#' + k + ' ' + q + '] ' + s1.slice(q * 250, (q + 1) * 250));
                        }
                        if (globalThis.__ptSerializing2 && b && b.length > 50000) {
                          // There may be several reports (the second after a click); each gets its
                          // own batch and the strings are reset.
                          const k = (globalThis.__ptReportK = (globalThis.__ptReportK || 0) + 1);
                          globalThis.__ptReportCollected = 1;
                          globalThis.__ptSerializing2 = 0;
                          const strs = globalThis.__ptStrings2 || [];
                          globalThis.__ptStrings2 = [];
                          const s1 = JSON.stringify(strs);
                          console.error('[report#' + k + '] total=' + strs.length + ' body=' + b.length + ' chars=' + s1.length + ' slices=' + Math.ceil(s1.length / 250));
                          // The console holds 256 lines between drains, so slices go out in batches
                          // on a timer.
                          const chunks = Math.ceil(s1.length / 250);
                          let q = 0;
                          const flush = () => {
                            for (let k = 0; k < 100 && q < chunks; k++, q++) console.error('[report ' + chunks + ':' + q + '] ' + s1.slice(q * 250, (q + 1) * 250));
                            if (q < chunks) setTimeout(flush, 40);
                          };
                          flush();
                        }
                      } catch (e) {}
                      return XS.apply(this, arguments);
                    }, XS);
                  } catch (e) {}
                  // Clock read log (NOKK_TRACE_READS): what the frame read from clocks
                  // before building the body.
                  if (__READS__ && cf) {
                    const noteRead = (what, v) => {
                      try {
                        if (!cf()) return;
                        const readLog = globalThis.__ptReads || (globalThis.__ptReads = []);
                        let site = '';
                        try { site = String(new Error().stack).split('\n').slice(3, 5).map((x) => x.trim().replace(/^at /, '').replace(/\(?https?:\/\/[^)]*?(:\d+:\d+)\)?/, '$1')).join(' < '); } catch (e) {}
                        readLog.push([what, typeof v === 'number' ? Math.round(v * 10) / 10 : String(v).slice(0, 30), site]);
                        if (readLog.length > 400) readLog.splice(0, 100);
                      } catch (e) {}
                    };
                    try {
                      // Slow insertions and geometry reads: what exactly is expensive.
                      const slow = (label, f) => nat(function () {
                        const t0 = performance.now();
                        const r = f.apply(this, arguments);
                        const dt = performance.now() - t0;
                        if (dt > 3 && cf()) {
                          const a = arguments[0];
                          noteRead('slow ' + label, Math.round(dt) + ' ' + ((a && a.nodeName) || (this && this.nodeName) || ''));
                        }
                        return r;
                      }, f);
                      const NP = Node.prototype;
                      for (const k of ['appendChild', 'insertBefore', 'removeChild', 'replaceChild']) NP[k] = slow(k, NP[k]);
                      if (globalThis.SVGGraphicsElement) SVGGraphicsElement.prototype.getBBox = slow('getBBox', SVGGraphicsElement.prototype.getBBox);
                      Element.prototype.getBoundingClientRect = slow('rect', Element.prototype.getBoundingClientRect);
                      globalThis.getComputedStyle = slow('gcs', globalThis.getComputedStyle);
                    } catch (e) {}
                    try {
                      const PN = Performance.prototype.now;
                      Performance.prototype.now = nat(function now() { const v = PN.call(this); noteRead('now', v); return v; }, PN);
                      const DN = Date.now;
                      Date.now = nat(function now() { const v = DN(); noteRead('Date.now', v % 100000); return v; }, DN);
                      for (const [proto, label] of [[globalThis.PerformanceTiming && PerformanceTiming.prototype, 'timing'],
                                                    [globalThis.PerformanceNavigationTiming && PerformanceNavigationTiming.prototype, 'nav'],
                                                    [globalThis.PerformanceResourceTiming && PerformanceResourceTiming.prototype, 'res'],
                                                    [globalThis.Performance && Performance.prototype, 'perf']]) {
                        if (!proto) continue;
                        for (const k of Object.getOwnPropertyNames(proto)) {
                          const d = Object.getOwnPropertyDescriptor(proto, k);
                          if (!d || !d.get || k === 'constructor') continue;
                          const g = d.get;
                          Object.defineProperty(proto, k, { get: nat(function () { const v = g.call(this); if (typeof v === 'number') noteRead(label + '.' + k, label === 'timing' ? v % 100000 : v); return v; }, g), set: d.set, enumerable: d.enumerable, configurable: true });
                        }
                      }
                    } catch (e) {}
                  }
                  try {
                    const CCA = String.prototype.charCodeAt;
                    String.prototype.charCodeAt = nat(function charCodeAt(i) {
                      if (i === 0 && globalThis.__ptSerializing && this.length < 120) {
                        const strs = globalThis.__ptStrings || (globalThis.__ptStrings = []);
                        if (strs.length < 600) strs.push(String(this));
                      } else if (i === 0 && globalThis.__ptSerializing2) {
                        const strs = globalThis.__ptStrings2 || (globalThis.__ptStrings2 = []);
                        if (strs.length < 60000) strs.push(this.length < 2000 ? String(this) : '\u0001' + this.length);
                      }
                      return CCA.call(this, i);
                    }, CCA);
                  } catch (e) {}
                })();"#;
                let probe = probe.replace(
                    "__READS__",
                    if std::env::var("NOKK_TRACE_READS").is_ok() { "true" } else { "false" },
                );
                c.add_frame_init_script(spread_to_realms(&probe, "fields"));
                // Also on the page itself: the interstitial posts its own reports to
                // /challenge-platform/.
                c.add_init_script(spread_to_realms(&probe, "fields"));
            }
            if std::env::var("NOKK_TRACE_HOOKS").is_ok() {
                let hook = r#"(() => {
                  try { console.error('[hook] installed'); } catch (e) {}
                  globalThis.__pt_streamHooks = __STREAM__;
                  // Experiment: in Chrome an unreachable host never answers and the request
                  // hangs. Here the connection fails at once, so the challenge gets a
                  // rejection where Chrome gets nothing.
                  if (__HANG__) {
                    try {
                      const F = globalThis.fetch;
                      globalThis.fetch = function (r, o) {
                        const u = String((r && r.url) || r || '');
                        if (/brunhild\./.test(u)) {
                          try { console.error('[hang] ' + u.slice(0, 90)); } catch (e) {}
                          return new Promise(() => {});
                        }
                        return F.apply(this, arguments);
                      };
                    } catch (e) {}
                  }
                  // The collected fingerprint goes through JSON.stringify before compression
                  // and encryption: the only point where we can see what we reported.
                  try {
                    const S_ = XMLHttpRequest.prototype.send, O_ = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function (m, u) { this.__ptU = String(u); return O_.apply(this, arguments); };
                    XMLHttpRequest.prototype.send = function (b) {
                      try {
                        const size = b == null ? 0
                          : (typeof b === 'string' ? b.length
                          : (b.byteLength !== undefined ? b.byteLength
                          : (b.size !== undefined ? b.size : (b.length || 0))));
                        console.error('[send] ' + Math.round(performance.now()) + 'ms bytes=' + size + ' kind=' + Object.prototype.toString.call(b) +
                                      ' url=' + String(this.__ptU || '').slice(-40));
                      } catch (e) {}
                      // The `/eb/` beacon is the only place the challenge says what went wrong.
                      // Its body bypasses JSON.stringify and btoa, so capture it here.
                      try {
                        if (/\/eb\//.test(String(this.__ptU || ''))) {
                          const t = typeof b === 'string' ? b : Object.prototype.toString.call(b);
                          for (let i = 0; i < Math.min(t.length, 1600); i += 200) {
                            console.error('[eb ' + i + '] ' + t.slice(i, i + 200));
                          }
                        }
                      } catch (e) {}
                      return S_.apply(this, arguments);
                    };
                  } catch (e) {}
                  try {
                    // Their serialization skips JSON, but the string is assembled somewhere:
                    // from an array, by concatenation or from char codes.
                    let seen = 0, dumped = 0;
                    // Chrome builds the first POST body with an array join; we have no such
                    // join, so it is built differently. Three more hooks: char codes, typed
                    // array join and base64. Only strings of the right size are printed.
                    // Hooks are made to look native: a patched function shows different
                    // source and length, the challenge reads both, and under crude patching
                    // it does not start.
                    const asNative = (f, src) => {
                      try {
                        Object.defineProperty(f, 'name', { value: src.name, configurable: true });
                        Object.defineProperty(f, 'length', { value: src.length, configurable: true });
                      } catch (e) {}
                      return globalThis.__pt_native ? __pt_native(f) : f;
                    };
                    try {
                      const FCC = String.fromCharCode;
                      String.fromCharCode = asNative(function (...a) {
                        const out = FCC.apply(this, a);
                        try {
                          if (out.length > 1000 && out.length < 9000
                              && (globalThis.__ptFccN = (globalThis.__ptFccN || 0) + 1) < 12) {
                            console.error('[codes ' + out.length + '] args=' + a.length +
                                  ' ' + out.slice(0, 120));
                          }
                        } catch (e) {}
                        return out;
                      }, FCC);
                    } catch (e) {}
                    try {
                      const TA = Object.getPrototypeOf(Int8Array.prototype);
                      const TJ = TA.join;
                      TA.join = asNative(function (sep) {
                        const out = TJ.apply(this, arguments);
                        try {
                          if (typeof out === 'string' && out.length > 1000
                              && (globalThis.__ptTaN = (globalThis.__ptTaN || 0) + 1) < 12) {
                            console.error('[join numbers ' + out.length + '] n=' + this.length +
                                  ' ' + out.slice(0, 100));
                          }
                        } catch (e) {}
                        return out;
                      }, TJ);
                    } catch (e) {}
                    try {
                      const B = globalThis.btoa;
                      if (typeof B === 'function') {
                        globalThis.btoa = asNative(function (x) {
                          const src = String(x == null ? '' : x);
                          try {
                            if (src.length > 1000 && src.length < 9000
                                && (globalThis.__ptBtoaN = (globalThis.__ptBtoaN || 0) + 1) < 12) {
                              console.error('[base64 ' + src.length + '] ' + src.slice(0, 120));
                            }
                          } catch (e) {}
                          return B.call(this, x);
                        }, B);
                      }
                    } catch (e) {}
                    // What api.js sees when it looks up its Resource Timing entry.
                    try {
                      const P = globalThis.Performance && Performance.prototype;
                      const G = P && P.getEntriesByType;
                      if (G) P.getEntriesByType = asNative(function (t) {
                        const r = G.apply(this, arguments);
                        try {
                          if (String(t) === 'resource' && !__ptForeign()
                              && (globalThis.__ptResQueries = (globalThis.__ptResQueries || 0) + 1) < 6) {
                            const cs = document.currentScript;
                            const cf = r.filter((e) => /challenges\.cloudflare/.test(e.name));
                            console.error('[resources] total=' + r.length + ' cf=' + cf.length
                                  + ' current=' + (cs ? String(cs.src || '(inline)').slice(-60) : 'none')
                                  + ' names=' + cf.map((e) => String(e.name).slice(-50) + (e instanceof PerformanceResourceTiming ? '' : '(not PRT)')).join(','));
                          }
                        } catch (e) {}
                        return r;
                      }, G);
                    } catch (e) {}

                    // Where the widget wrapper sits when api.js measures it (the `wp` field of
                    // the message): ancestor chain and stylesheet count.
                    try {
                      const E = globalThis.Element && Element.prototype;
                      const R = E && E.getBoundingClientRect;
                      if (R) E.getBoundingClientRect = asNative(function () {
                        const r = R.apply(this, arguments);
                        try {
                          if (!__ptForeign() && this.closest && this.closest('#turnstile-login-form')
                              && (globalThis.__ptPlaceN = (globalThis.__ptPlaceN || 0) + 1) < 4) {
                            const anc = [];
                            for (let e = this; e && e.nodeType === 1 && anc.length < 9; e = e.parentElement) {
                              const q = R.call(e);
                              anc.push(e.tagName.toLowerCase() + '.' + String(e.className || '').split(' ')[0]
                                + ' ' + q.left + ',' + q.top + ' ' + q.width + 'x' + q.height);
                            }
                            console.error('[place] sheets=' + document.styleSheets.length + ' readyState=' + document.readyState
                              + ' t=' + Math.round(performance.now()) + ' | ' + anc.join(' < '));
                            console.error('[place] stack ' + String(new Error().stack).split('\n').slice(2, 9).map((x) => x.trim().replace(/https?:\/\/[^ ]*\//, '')).join(' / '));
                            console.error('[place] scripts ' + [...document.getElementsByTagName('script')].map((x) =>
                              x.src ? x.src.replace(/^https:\/\/[^/]+/, '').slice(0, 60)
                                    : 'inline:' + x.textContent.trim().slice(0, 30).replace(/\s+/g, ' ')).join(' | '));
                            console.error('[place] ' + [...document.styleSheets].map((t) => {
                              let n = '?'; try { n = t.cssRules.length; } catch (e) { n = 'x'; }
                              return String(t.href || (t.ownerNode && t.ownerNode.tagName) || '').slice(-40) + '=' + n;
                            }).join(' '));
                          }
                        } catch (e) {}
                        return r;
                      }, R);
                    } catch (e) {}

                    // Messages posted to the frame: part of the first POST body comes from the
                    // page (api.js), and Chrome has fields there that we lack.
                    try {
                      const AL2 = EventTarget.prototype.addEventListener;
                      EventTarget.prototype.addEventListener = asNative(function (type, fn, opts) {
                        if (__ptForeign() && String(type) === 'message' && typeof fn === 'function') {
                          const listener = function (ev) {
                            try {
                              if ((globalThis.__ptMessages = (globalThis.__ptMessages || 0) + 1) < 25) {
                                const d = ev && ev.data;
                                const t = typeof d === 'string' ? d : (() => {
                                  try { return JSON.stringify(d); } catch (e) { return String(d); }
                                })();
                                // Long messages are printed in pieces: they hold what the first POST body
                                // is missing.
                                const s1 = String(t);
                                if (s1.length <= 220) {
                                  console.error('[postmsg] ' + String(ev && ev.origin).slice(0, 30) + ' ' + s1);
                                } else {
                                  for (let q = 0; q < Math.min(s1.length, 8000); q += 220) {
                                    console.error('[postmsg ' + s1.length + ':' + (q / 220) + '] ' + s1.slice(q, q + 220));
                                  }
                                }
                              }
                            } catch (e) {}
                            return fn.apply(this, arguments);
                          };
                          return AL2.call(this, type, listener, opts);
                        }
                        return AL2.apply(this, arguments);
                      }, AL2);
                    } catch (e) {}

                    // Where the challenge gets pristine builtins: it builds a sandbox frame
                    // and reads its `contentWindow`. If that window is missing or wrong, the
                    // code takes another branch and the body is built in a different realm
                    // than in Chrome.
                    try {
                      const D = Document.prototype.createElement;
                      Document.prototype.createElement = asNative(function (tag) {
                        const el = D.apply(this, arguments);
                        try {
                          if (__ptForeign() && /^iframe$/i.test(String(tag))
                              && (globalThis.__ptFrames = (globalThis.__ptFrames || 0) + 1) < 12) {
                            console.error('[sandbox] frame created #' + globalThis.__ptFrames);
                          }
                        } catch (e) {}
                        return el;
                      }, D);
                      const IF = globalThis.HTMLIFrameElement;
                      const d = IF && Object.getOwnPropertyDescriptor(IF.prototype, 'contentWindow');
                      if (d && d.get) {
                        Object.defineProperty(IF.prototype, 'contentWindow', {
                          get: asNative(function () {
                            const w = d.get.call(this);
                            try {
                              if (__ptForeign()
                                  && (globalThis.__ptWindows = (globalThis.__ptWindows || 0) + 1) < 12) {
                                console.error('[sandbox] contentWindow -> ' + (w ? 'window' : String(w))
                                      + ' src=' + String(this.getAttribute('src') || '-').slice(0, 30)
                                      + ' sandbox=' + String(this.getAttribute('sandbox') || '-').slice(0, 30)
                                      + ' connected=' + !!this.isConnected);
                              }
                            } catch (e) {}
                            return w;
                          }, d.get),
                          set: d.set, enumerable: d.enumerable, configurable: d.configurable,
                        });
                      }
                    } catch (e) {}

                    // Which events the challenge listens to and which reach it. It keeps a
                    // list and sends a summary; in Chrome the list is empty at the first send,
                    // so a non-empty one means the engine dispatches something itself.
                    try {
                      const ET = EventTarget.prototype;
                      const AL = ET.addEventListener;
                      const DE = ET.dispatchEvent;
                      const whoOf = (o) => {
                        try {
                          return o === globalThis ? 'window'
                            : (o && o.nodeType === 9) ? 'document'
                            : (o && o.localName) || (o && o.constructor && o.constructor.name) || '?';
                        } catch (e) { return '?'; }
                      };
                      const INPUT0 = /^(pointer|mouse|touch|key|wheel|scroll|focus|blur|visibilitychange|selectionchange|devicemotion|deviceorientation)/;
                      ET.addEventListener = asNative(function (type, fn, opts) {
                        if ((__ptForeign() || INPUT0.test(String(type)))
                            && (globalThis.__ptSubscriptions = (globalThis.__ptSubscriptions || 0) + 1) < 80) {
                          console.error('[listens] ' + (__ptForeign() ? 'frame ' : 'page ')
                                + whoOf(this) + ' ' + String(type));
                        }
                        return AL.apply(this, arguments);
                      }, AL);
                      // The page (api.js) collects the input summary and forwards it to the
                      // frame, so watch input on the page too, but only input, or the feed
                      // drowns.
                      const INPUT_RE = /^(pointer|mouse|touch|key|wheel|scroll|focus|blur|visibilitychange|selectionchange|devicemotion|deviceorientation)/;
                      ET.dispatchEvent = asNative(function (ev) {
                        const typ = String((ev && ev.type) || '');
                        const inFrame = __ptForeign();
                        if ((inFrame || INPUT_RE.test(typ))
                            && (globalThis.__ptEvents = (globalThis.__ptEvents || 0) + 1) < 120) {
                          console.error('[event] ' + (inFrame ? 'frame ' : 'page ') + whoOf(this) + ' ' + typ
                                + ' trusted=' + !!(ev && ev.isTrusted));
                        }
                        return DE.apply(this, arguments);
                      }, DE);
                    } catch (e) {}

                    // Where the challenge calls `isFinite` before the first send: Chrome makes
                    // no such calls, we made ~30, so the code takes another branch; the stack
                    // shows which.
                    try {
                      const IF = globalThis.isFinite;
                      let cnt = 0;
                      globalThis.isFinite = asNative(function (x) {
                        if (__ptForeign() && cnt < 40) {
                          cnt++;
                          let stk = '';
                          try {
                            stk = String(new Error().stack || '').split('\n').slice(1, 3)
                              .map((l) => l.trim().replace(/^at /, '').replace(/https?:[^)]*normal\?lang=auto/, ''))
                              .join(' | ');
                          } catch (e) {}
                          console.error('[isFinite ' + cnt + '] ' + x + ' <- ' + stk.slice(0, 260));
                        }
                        return IF.call(this, x);
                      }, IF);
                    } catch (e) {}

                    // Plaintext of the first POST. It goes through neither `TextEncoder` nor
                    // `JSON.stringify`; the compressor reads it char by char. This hook sits
                    // on the hottest path, so the check is short: index 0 and long strings
                    // only. Only needed in the challenge frame: the page itself reads
                    // thousands of strings per char.
                    const __ptForeign = () => {
                      if (globalThis.__ptInRealm) return true;
                      try { return /challenges\.cloudflare/.test(location.host); } catch (e) { return false; }
                    };
                    try {
                      const CCA = String.prototype.charCodeAt;
                      const seenSrc = Object.create(null);
                      String.prototype.charCodeAt = asNative(function (i) {
                        if (i === 0 && this.length > 0 && this.length < 40000 && __ptForeign()) {
                          const n = this.length;
                          // Short strings are field names and values of the body: the serializer
                          // reads them per char like numbers. Order matters more than content, so
                          // keep a sequence.
                          if (n < 120) {
                            if (!globalThis.__ptSerializing) return CCA.call(this, i);
                            const strs = globalThis.__ptStrings || (globalThis.__ptStrings = []);
                            if (strs.length < 400) strs.push(String(this));
                          } else if (!seenSrc[n] && Object.keys(seenSrc).length < 30) {
                            seenSrc[n] = 1;
                            const s0 = String(this);
                            console.error('[source ' + n + '] ' + Math.round(performance.now()) + 'ms');
                            for (let q = 0; q < s0.length; q += 250) {
                              console.error('[source ' + n + ':' + (q / 250) + '] ' + s0.slice(q, q + 250));
                            }
                          }
                        }
                        return CCA.call(this, i);
                      }, CCA);
                    } catch (e) {}
                    const J = Array.prototype.join;
                    Array.prototype.join = asNative(function (sep) {
                      const out = J.apply(this, arguments);
                      if (typeof out === 'string' && out.length > 1500 && seen++ < 3) {
                        try { console.error('[join ' + out.length + '] ' + out.slice(0, 700)); } catch (e) {}
                      }
                      // Join census. The report leaves as an array join, but by then it is
                      // encrypted (same length as the send). The plaintext is joined earlier by
                      // another join, findable only by the sequence of joins. The strings stay
                      // in the frame for NOKK_EVAL_FRAMES.
                      if (__REPORT__ && typeof out === 'string' && out.length > __JMIN__) {
                        try {
                          if (!globalThis.__ptJoins) globalThis.__ptJoins = [];
                          if (!globalThis.__ptJoinN) globalThis.__ptJoinN = 0;
                          const n = globalThis.__ptJoinN++;
                          // Retaining strings is costly (some are megabytes) and changes what we
                          // measure: Chrome under such a hook starts re-running the challenge. Keep
                          // only report-sized ones.
                          if (out.length < 200000) {
                            __ptJoins.push([n, out]);
                            if (__ptJoins.length > 12) __ptJoins.shift();
                          } else if (out.length > 500000) {
                            // The challenge program. It is served in two sizes, short to suspicious
                            // clients and long to trusted ones. Fetched via NOKK_EVAL_FRAMES.
                            globalThis.__ptProg = out;
                          }
                          let host = '?';
                          try { host = location.host.slice(0, 12); } catch (e) {}
                          // Join sequence ([j n host length separator]): what was joined in what
                          // order, to put beside a Chrome run and find the join we lack.
                          if (n < 40) {
                            try {
                              console.error('[j ' + n + ' ' + host + ' ' + out.length + ' ' +
                                    JSON.stringify(String(sep === undefined ? ',' : sep)).slice(0, 12) + ']');
                            } catch (e) {}
                          }
                          // The first POST body is built by the same kind of join; ours is ~50 chars
                          // shorter than Chrome's. Piece lengths in order show which piece is short.
                          if (out.length > 3000 && out.length < 6000 && String(sep) === ''
                              && this.length > 1 && !globalThis.__ptFirstParts) {
                            globalThis.__ptFirstParts = 1;
                            try {
                              const lens = Array.prototype.map.call(this, (x) => String(x == null ? '' : x).length);
                              console.error('[first parts] total=' + out.length + ' n=' + lens.length +
                                    ' lengths=' + lens.join(','));
                            } catch (e) {}
                          }
                          // What the report is joined from: piece lengths in order.
                          if (out.length > 50000 && String(sep) === '' && this.length !== out.length && !globalThis.__ptPartsDone) {
            globalThis.__ptPartsDone = 1;
            try {
              const lens = Array.prototype.map.call(this, (x) => String(x == null ? '' : x).length);
              const big = lens.map((v, i) => [v, i]).sort((a, b) => b[0] - a[0]).slice(0, 25);
              console.error('[parts] n=' + lens.length + ' total=' + out.length +
                    ' largest: ' + big.map(([v, i]) => i + ':' + v).join(' '));
              const buckets = [0, 0, 0, 0, 0];
              for (const v of lens) buckets[v < 10 ? 0 : v < 100 ? 1 : v < 1000 ? 2 : v < 10000 ? 3 : 4]++;
              console.error('[parts] by size: <10=' + buckets[0] + ' <100=' + buckets[1] +
                    ' <1k=' + buckets[2] + ' <10k=' + buckets[3] + ' >=10k=' + buckets[4]);
            } catch (e) {}
          }
                          // Style enumeration in full: it must be compared with Chrome line by line,
                          // and the frame is gone by the end of the run.
                          if (String(sep) === '|' && out.length > 5000 &&
                              (globalThis.__ptCssN = (globalThis.__ptCssN || 0) + 1) <= 2) {
                            for (let i = 0; i < out.length; i += 4000) {
                              console.error('[C' + globalThis.__ptCssN + ' @' + i + '] ' + out.slice(i, i + 4000));
                            }
                            console.error('[C' + globalThis.__ptCssN + ' end ' + out.length + ']');
                          }
                          console.error('[j ' + n + ' ' + host + ' ' + out.length + ' ' +
                                        JSON.stringify(String(sep)) + '] ' +
                                        out.slice(0, 90).replace(/\n/g, ' '));
                        } catch (e) {}
                      }
                      return out;
                    }, J);
                    const FCC = String.fromCharCode;
                    let fccBuf = 0;
                    String.fromCharCode = function () { fccBuf += arguments.length; return FCC.apply(this, arguments); };
                    globalThis.__pt_fccCount = () => fccBuf;
                  } catch (e) {}
                  try {
                    let n = 0, biggest = '';
                    const S = JSON.stringify;
                    JSON.stringify = function (v) {
                      const out = S.apply(this, arguments);
                      if (typeof out === 'string' && out.length > biggest.length) biggest = out;
                      if (typeof out === 'string' && out.length > 300 && n++ < 6) {
                        try { console.error('[payload ' + out.length + '] ' + out.slice(0, 900)); } catch (e) {}
                        // The error report is the only place their code names what broke. Print
                        // our list of read misses next to it: the missing member is almost always
                        // there, last.
                        if (out.indexOf('\"stack\"') >= 0 || out.indexOf('is not a function') >= 0) {
                          try {
                            const tail = (globalThis.__pt_missTail && __pt_missTail(24)) || '(none)';
                            for (let i = 0; i < tail.length; i += 200) {
                              console.error('[misses@err ' + i + '] ' + tail.slice(i, i + 200));
                            }
                          } catch (e2) {}
                        }
                      }
                      return out;
                    };
                    globalThis.__pt_biggestPayload = () => biggest.slice(0, 4000);
                    // Their own serializer: the bundle has its own string builder and the
                    // fingerprint may bypass JSON. Catch that too.
                    const A = globalThis.btoa;
                    if (typeof A === 'function') {
                      globalThis.btoa = function (x) {
                        if (typeof x === 'string' && x.length > 300) {
                          try { console.error('[b64 ' + x.length + '] ' + x.slice(0, 600)); } catch (e) {}
                        }
                        return A.apply(this, arguments);
                      };
                    }
                  } catch (e) {}
                  // Their frame postMessage reads `contentWindow` before checking the target
                  // origin and silently does nothing if the origin is empty. The read shows
                  // whether a tick reached the send at all.
                  try {
                    const d = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
                    if (d && d.get) {
                      let n = 0;
                      Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
                        configurable: true,
                        get() {
                          if (n++ < 40) {
                            try {
                              const at = String(new Error().stack || '').split('\n').slice(2, 4)
                                .map(x => x.trim().replace(/^at /, '')).join(' | ').slice(0, 150);
                              console.error('[cw] read #' + n + ' on #' + (this.id || '?') + ' @ ' + at);
                            } catch (e) {}
                          }
                          const win = d.get.call(this);
                          // The call itself: their `Cr` drops the message silently on an empty
                          // target origin, so log whether postMessage was reached and with what.
                          try {
                            if (win && !win.__ptLogged) {
                              const P = win.postMessage;
                              win.postMessage = function (data, origin) {
                                try {
                                  const ev = data && data.event;
                                  console.error('[pm] → frame event=' + ev + ' origin=' + JSON.stringify(origin));
                                } catch (e) {}
                                return P.apply(this, arguments);
                              };
                              win.__ptLogged = true;
                            }
                          } catch (e) {}
                          return win;
                        },
                      });
                    }
                  } catch (e) {}
                  // Everything the VM compiles at runtime: stacks inside such code give
                  // offsets, and the source is not available otherwise.
                  try {
                    globalThis.__ptBuilt = [];
                    const F0 = globalThis.Function;
                    const FN = function Function() {
                      const src = Array.prototype.join.call(arguments, ',');
                      try { if (src.length > 200) __ptBuilt.push(src); } catch (e) {}
                      return F0.apply(this, arguments);
                    };
                    FN.prototype = F0.prototype;
                    globalThis.Function = FN;
                    const E0 = globalThis.eval;
                    globalThis.eval = function (src) {
                      try { if (typeof src === 'string' && src.length > 200) __ptBuilt.push(src); } catch (e) {}
                      return E0.apply(this, arguments);
                    };
                  } catch (e) {}
                  // What a stalled frame waits for: every two seconds print whatever could
                  // wake it (pending requests, next timer, promises pending over 5 s with
                  // their creation site). The widget stalls silently; this is the only way
                  // to ask what it waits for.
                  try {
                    const inflight = new Map();
                    let reqId = 0;
                    const F = globalThis.fetch;
                    if (typeof F === 'function') {
                      globalThis.fetch = function (r, o) {
                        const id = ++reqId;
                        const u = String((r && r.url) || r || '').slice(-60);
                        inflight.set(id, { kind: 'fetch', url: u, at: Date.now() });
                        const done = () => inflight.delete(id);
                        let p;
                        try { p = F.apply(this, arguments); } catch (e) { done(); throw e; }
                        return p && p.then ? p.then((v) => { done(); return v; }, (e) => { done(); throw e; }) : p;
                      };
                    }
                    const XS = XMLHttpRequest.prototype.send, XO = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function (m, u) { this.__ptURL = String(u); return XO.apply(this, arguments); };
                    XMLHttpRequest.prototype.send = function () {
                      const id = ++reqId;
                      inflight.set(id, { kind: 'xhr', url: String(this.__ptURL || '').slice(-60), at: Date.now() });
                      this.addEventListener('loadend', () => inflight.delete(id));
                      return XS.apply(this, arguments);
                    };
                    // Promises: count only those not created by our own glue.
                    const pending = new Map();
                    let pid = 0;
                    const P0 = globalThis.Promise;
                    const Wrapped = function Promise(executor) {
                      const id = ++pid;
                      let at = '';
                      try { at = String(new Error().stack || '').split('\n').slice(2, 9).map((x) => x.trim()).join(' | ').slice(0, 400); } catch (e) {}
                      let did = '';
                      const p = new P0(function (res, rej) {
                        // What the executor asked the host while running: the promise hangs
                        // waiting for exactly that.
                        let before = 0;
                        try { before = (globalThis.__pt_probeTail ? JSON.parse(__pt_probeTail(400)).length : 0); } catch (e) {}
                        try {
                          return executor(function (v) { pending.delete(id); return res(v); },
                                          function (e) { pending.delete(id); return rej(e); });
                        } finally {
                          try {
                            const tail = globalThis.__pt_probeTail ? JSON.parse(__pt_probeTail(400)) : [];
                            did = tail.slice(Math.max(0, before)).map((r) => r[1] + '→' + String(r[2]).slice(0, 24)).join(' ; ').slice(0, 400);
                          } catch (e) {}
                        }
                      });
                      // The executor's own source: the creation site points into generated
                      // code we do not have, but the function body is always readable.
                      let body = '';
                      try {
                        body = String(executor).replace(/\s+/g, ' ').slice(0, 300)
                             + ' | name=' + (executor && executor.name) + ' arity=' + (executor && executor.length);
                      } catch (e) {}
                      pending.set(id, { at, born: Date.now(), body, did });
                      return p;
                    };
                    Wrapped.prototype = P0.prototype;
                    Object.setPrototypeOf(Wrapped, P0);
                    for (const k of ['resolve', 'reject', 'all', 'allSettled', 'race', 'any', 'try', 'withResolvers']) {
                      if (typeof P0[k] === 'function') Wrapped[k] = P0[k].bind(P0);
                    }
                    globalThis.Promise = Wrapped;
                    // Which tasks wake the frame at all: animation frames, microtasks, message
                    // channel port, plain timer. If the program waits on one that never
                    // comes, that is the stall.
                    let raf = 0, micro = 0, port = 0, idleCb = 0;
                    try { (function tick() { raf++; requestAnimationFrame(tick); })(); } catch (e) {}
                    // Not in a loop: a microtask chain feeds itself and starves everything
                    // else, so count a few at a time and schedule the next batch on a timer.
                    let chan = null;
                    try {
                      chan = new MessageChannel();
                      chan.port1.onmessage = () => { port++; };
                      chan.port1.start && chan.port1.start();
                    } catch (e) {}
                    globalThis.setInterval(function () {
                      try { queueMicrotask(() => { micro++; }); } catch (e) {}
                      try { if (chan) chan.port2.postMessage(1); } catch (e) {}
                      try { requestIdleCallback(() => { idleCb++; }); } catch (e) {}
                    }, 500);
                    globalThis.setTimeout(function idle() {
                      try {
                        const now = Date.now();
                        const reqs = [...inflight.values()].map((r) => r.kind + ':' + r.url + ' (' + (now - r.at) + 'ms)');
                        const old = [...pending.values()].filter((p) => now - p.born > 5000);
                        console.error('[idle] requests in flight=' + reqs.length +
                                      ' next timer in=' + (globalThis.__pt_nextTimerDelay ? __pt_nextTimerDelay() : '?') +
                                      ' timers=' + (globalThis.__pt_pendingTimers ? __pt_pendingTimers() : '?') +
                                      ' promises pending>5s=' + old.length +
                                      ' | frames=' + raf + ' microtasks=' + micro + ' port=' + port + ' idle=' + idleCb +
                                      (reqs.length ? ' :: ' + reqs.join(' ; ') : ''));
                        for (const p of old.slice(-3)) {
                          console.error('[idle] promise for ' + Math.round((now - p.born) / 1000) + 's @ ' + p.at);
                          console.error('[idle] its body: ' + p.body);
                          console.error('[idle] executor asked: ' + (p.did || '(nothing)'));
                          // Find the creation site by the function name from the stack: generated
                          // code has no URL, but it has text.
                          try {
                            const m = /at ([\w$.]+) \(<anonymous>:\d+:(\d+)\)/.exec(p.at);
                            const fname = m ? m[1].split('.').pop() : '';
                            if (fname) {
                              for (const src of (globalThis.__ptBuilt || [])) {
                                const k = src.indexOf(fname + ':function');
                                const k2 = k >= 0 ? k : src.indexOf(fname + '=function');
                                if (k2 >= 0) {
                                  console.error('[idle] ' + fname + ' found in bundle ' + src.length + ' bytes: ' +
                                                src.slice(k2, k2 + 320).replace(/\s+/g, ' '));
                                  break;
                                }
                              }
                            }
                          } catch (e) {}
                        }
                      } catch (e) { try { console.error('[idle] threw ' + e); } catch (x) {} }
                      globalThis.setTimeout(idle, 2000);
                    }, 2000);
                  } catch (e) {}
                  // What the watchcat sees each tick: its checks walk the widget's shadow
                  // root and wrapper, and any of them can silently skip the step. Re-run
                  // them ourselves every two seconds.
                  try {
                    const shadows = [];
                    const AS = Element.prototype.attachShadow;
                    Element.prototype.attachShadow = function (init) {
                      const sh = AS.apply(this, arguments);
                      try {
                        shadows.push([this, sh]);
                        console.error('[shadow] host=' + this.localName + '#' + (this.id || '') +
                                      ' mode=' + (init && init.mode));
                      } catch (e) {}
                      return sh;
                    };
                    globalThis.setTimeout(function report() {
                      try {
                        for (const [host, sh] of shadows) {
                          const kids = [];
                          try { for (const k of sh.children) kids.push(k.localName + '#' + (k.id || '')); } catch (e) {}
                          console.error('[watchcat] host=' + host.localName + '#' + (host.id || '') +
                                        ' connected=' + host.isConnected +
                                        ' isShadowRoot=' + (sh instanceof ShadowRoot) +
                                        ' kids=' + kids.join(',') +
                                        ' qsWidget=' + kids.map(k => k.split('#')[1])
                                            .filter(Boolean)
                                            .map(id => id + ':' + !!sh.querySelector('#' + id)).join(' '));
                          // The watchcat step itself: it posts a message with a target origin to
                          // the found element. If that throws, their loop swallows it.
                          for (const k of sh.children) {
                            if (k.localName !== 'iframe') continue;
                            let win = 'n/a', posted = 'n/a';
                            try { win = String(!!k.contentWindow); } catch (e) { win = 'threw ' + e; }
                            try {
                              const origin = new URL(k.src || 'https://challenges.cloudflare.com').origin;
                              k.contentWindow.postMessage({ event: 'probe' }, origin);
                              posted = 'ok';
                            } catch (e) { posted = 'threw ' + String(e).slice(0, 90); }
                            console.error('[watchcat] send to ' + k.id + ': contentWindow=' + win + ' post=' + posted);
                          }
                        }
                      } catch (e) { try { console.error('[watchcat] threw ' + e); } catch (x) {} }
                      globalThis.setTimeout(report, 2000);
                    }, 2000);
                  } catch (e) {}
                  // Repeating timers: the Turnstile watchcat is a 900 ms setInterval in the
                  // page context; this shows whether it is armed but not ticking.
                  try {
                    const SI = globalThis.setInterval;
                    let ivId = 0;
                    globalThis.setInterval = function (fn, ms) {
                      const id = ++ivId;
                      let fired = 0;
                      try { console.error('[interval] set #' + id + ' every ' + ms + 'ms'); } catch (e) {}
                      const wrapped = typeof fn !== 'function' ? fn : function () {
                        fired++;
                        if (fired <= 3 || fired % 10 === 0) {
                          try { console.error('[interval] #' + id + ' tick ' + fired + ' (' + ms + 'ms)'); } catch (e) {}
                        }
                        return fn.apply(this, arguments);
                      };
                      return SI.call(this, wrapped, ms);
                    };
                  } catch (e) {}
                  // The challenge catches errors itself and ships them encrypted in its
                  // beacon, but constructs them here with the plain constructor. One hook
                  // gives what would otherwise need decrypting the beacon.
                  try {
                    for (const nm of ['Error', 'TypeError', 'RangeError', 'ReferenceError', 'SyntaxError']) {
                      const E = globalThis[nm];
                      if (typeof E !== 'function') continue;
                      const Wrapped = function (...a) {
                        const e = new E(...a);
                        try {
                          const at = String(e.stack || '').split('\n').slice(1, 3).join(' | ').slice(0, 220);
                          console.error('[throw] ' + nm + ': ' + String(a[0]).slice(0, 160) + ' @ ' + at);
                        } catch (x) {}
                        return e;
                      };
                      Wrapped.prototype = E.prototype;
                      Object.setPrototypeOf(Wrapped, E);
                      Object.defineProperty(Wrapped, 'name', { value: nm, configurable: true });
                      globalThis[nm] = Wrapped;
                    }
                  } catch (e) {}
                  // Their own breadcrumbs: the code calls UpvLO0(<label>) and
                  // eVARP2(<label>) at each step. Labels are unique, so the call sequence
                  // traces their state machine and can be compared with Chrome.
                  for (const name of ['UpvLO0', 'eVARP2']) {
                    try {
                      let held;
                      Object.defineProperty(globalThis, name, {
                        configurable: true,
                        get() { return held; },
                        set(v) {
                          held = typeof v !== 'function' ? v : function (tag) {
                            // The label is encrypted per issue, but the call site is not: the bundle
                            // line is the same here and in Chrome, so traces compare by it.
                            let at = '';
                            try {
                              const f = String(new Error().stack || '').split('\n').slice(2);
                              at = (f.find(s => s.indexOf('cloudflare.com') >= 0) || f[0] || '')
                                     .replace(/^\s*at\s*/, '').replace(/^.*\/(?=[^/]*:)/, '');
                            } catch (e) {}
                            try { console.error('[crumb] ' + name + ' ' + String(tag).slice(0, 24) + ' @ ' + at); } catch (e) {}
                            return v.apply(this, arguments);
                          };
                        },
                      });
                    } catch (e) {}
                  }

                  // What the VM touched before a throw: stacks inside their interpreter
                  // show only the opcode dispatcher, but the last host-table reads tell.
                  // Their interpreter fails on `fn.call(obj, ...)` with fn read from a host
                  // object, and a missing property is only visible at the bottom of the
                  // prototype chain: put a Proxy there and log what was asked.
                  // Globals snapshot before the first script: anything beyond it was
                  // declared by the challenge; diffing with Chrome shows which stage did not
                  // run here.
                  let baseGlobals = [];
                  try { baseGlobals = Object.getOwnPropertyNames(globalThis); } catch (e) {}
                  // Step counter for their VM. Bundle names change every issue, so match
                  // behaviour, not names: after the program is built, take every function
                  // that was not on the window before and count calls. The opcode dispatcher
                  // stands out by frequency, which is what compares with Chrome.
                  try {
                    globalThis.__ptSteps = new Map();
                    globalThis.__ptLastArgs = new Map();
                    globalThis.__ptCountVM = () => {
                      let wrapped = 0;
                      for (const name of Object.getOwnPropertyNames(globalThis)) {
                        if (name.lastIndexOf('__pt', 0) === 0) continue;
                        if (baseGlobals.indexOf(name) >= 0) continue;
                        let v;
                        try { v = globalThis[name]; } catch (e) { continue; }
                        if (typeof v !== 'function' || v.__ptCounted) continue;
                        const counter = { n: 0 };
                        __ptSteps.set(name, counter);
                        const wrap = function (...args) {
                          counter.n++;
                          if (counter.n % 5000 === 0 || counter.n < 3) {
                            try { __ptLastArgs.set(name, args.map((a) => String(a).slice(0, 18)).join(',').slice(0, 60)); } catch (e) {}
                          }
                          return v.apply(this, args);
                        };
                        wrap.__ptCounted = true;
                        try { Object.defineProperty(globalThis, name, { value: wrap, writable: true, configurable: true }); wrapped++; } catch (e) {}
                      }
                      return wrapped;
                    };
                    // Start counting once the program is built; print totals every two
                    // seconds.
                    globalThis.setTimeout(function counter() {
                      try {
                        const added = __ptCountVM();
                        const top = [...__ptSteps.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 4);
                        if (top.length && top[0][1].n > 0) {
                          console.error('[vmsteps] ' + top.map(([k, c]) => k + '=' + c.n).join(' ') +
                                        (added ? ' (+' + added + ' new)' : ''));
                        }
                      } catch (e) { try { console.error('[vmsteps] threw ' + e); } catch (x) {} }
                      globalThis.setTimeout(counter, 2000);
                    }, 1500);
                  } catch (e) {}

                  const addedGlobals = () => {
                    try {
                      const b = new Set(baseGlobals);
                      return Object.getOwnPropertyNames(globalThis)
                        .filter((n) => !b.has(n) && n.lastIndexOf('__pt', 0) !== 0)
                        .map((n) => { let t = '?'; try { t = typeof globalThis[n]; } catch (e) {} return n + ':' + t; })
                        .join(' ');
                    } catch (e) { return '(failed)'; }
                  };
                  const misses = [];
                  globalThis.__pt_missTail = (n) => misses.slice(-(n || 24)).join(' ');
                  try {
                    const toStr = Object.prototype.toString;
                    const describe = (r) => {
                      if (r === globalThis) return 'window';
                      if (r === document) return 'document';
                      const t = toStr.call(r).slice(8, -1);
                      let extra = '';
                      try {
                        if (r && ('nodeType' in r) && r.nodeType === 1) extra = '<' + String(r.localName) + (r.id ? '#' + r.id : '') + '>';
                      } catch (e) {}
                      return t + extra;
                    };
                    // Object.prototype is immutable, so the trap goes one level up, between
                    // the root interface and it.
                    const sink = () => new Proxy(Object.prototype, {
                      get(t, p, r) {
                        if (typeof p === 'string' && !(p in t) && p.lastIndexOf('__pt', 0) !== 0) {
                          let who = '?';
                          try { who = describe(r); } catch (e) {}
                          misses.push(who + '.' + p);
                          if (misses.length > 60) misses.shift();
                          // Indices and `toJSON` are serialization noise (tens of thousands of
                          // lines per run): kept in the ring, not streamed.
                          if (globalThis.__pt_streamHooks && !/^(-?\d+|toJSON)$/.test(p)) {
                            try { console.error('[m] ' + who + '.' + p); } catch (e) {}
                          }
                        }
                        return Reflect.get(t, p, r);
                      },
                    });
                    let hooked = 0;
    for (const name of ['EventTarget', 'Navigator', 'Screen', 'Location', 'History',
                                        'Performance', 'Crypto', 'Storage', 'CSSStyleDeclaration',
                                        'DOMTokenList', 'NodeList', 'HTMLCollection', 'NamedNodeMap',
                                        'PerformanceEntry', 'MessagePort', 'Event', 'URL',
                                        'Function', 'Array', 'String', 'Number', 'Boolean', 'Symbol',
                                        'Error', 'Date', 'RegExp', 'Map', 'Set', 'WeakMap', 'WeakSet',
                                        'Promise', 'ArrayBuffer', 'DataView', 'Uint8Array', 'Blob',
                                        'Worker', 'MessageEvent', 'XMLHttpRequest', 'Response', 'Headers']) {
                      const C = globalThis[name], proto = C && C.prototype;
                      if (proto && Object.getPrototypeOf(proto) === Object.prototype) {
                        Object.setPrototypeOf(proto, sink());
                        hooked++;
                      }
                    }
                    void document.__pt_sinkSelfTest;
                    console.error('[vm] miss-sink on ' + hooked + ' roots, self-test ' + (misses.length > 0));
                    misses.length = 0;
                  } catch (e) { console.error('[vm] miss-sink failed: ' + e); }
                  const recent = [];
                  const stream = !!globalThis.__pt_streamHooks;
                  const remember = (s) => {
                    recent.push(s);
                    if (recent.length > 24) recent.shift();
                    if (stream) { try { console.error('[t] ' + String(s).slice(0, 150)); } catch (e) {} }
                  };
                  // Messages with the collection worker: who sent what to whom.
                  try {
                    const WP = Worker.prototype.postMessage;
                    const peek = (v) => {
                      try {
                        if (typeof v === 'string') return 'str' + v.length + ':' + v.slice(0, 90);
                        if (v && typeof v === 'object') {
                          return 'obj{' + Object.keys(v).map((k) => {
                            const x = v[k];
                            return k + '=' + (typeof x === 'string' ? 's' + x.length + ':' + x.slice(0, 40)
                                              : x && typeof x === 'object' ? Object.prototype.toString.call(x)
                                              : String(x).slice(0, 20));
                          }).join(' ').slice(0, 200) + '}';
                        }
                        return String(v).slice(0, 60);
                      } catch (e) { return '?'; }
                    };
                    Worker.prototype.postMessage = function (data) {
                      remember('worker.postMessage ' + peek(data));
                      return WP.apply(this, arguments);
                    };
                    const WA = Worker.prototype.addEventListener;
                    const wrapHandler = (h) => (typeof h !== 'function' ? h : function (e) {
                      remember('worker→frame ' + (e && e.type) + ' ' + peek(e && e.data));
                      return h.apply(this, arguments);
                    });
                    Worker.prototype.addEventListener = function (t, h) {
                      remember('worker.on ' + t);
                      return WA.call(this, t, wrapHandler(h), arguments[2]);
                    };
                    // Worker replies also arrive via the handler property.
                    const OM = new WeakMap();
                    Object.defineProperty(Worker.prototype, 'onmessage', {
                      configurable: true, enumerable: true,
                      get() { return OM.get(this) || null; },
                      set(h) { OM.set(this, h); this.addEventListener('message', h); },
                    });
                  } catch (e) {}
                  globalThis.__pt_recent = () => recent.join(' → ');
                  // Their second collection stage runs on a timer and is silent if it
                  // throws inside: Chrome prints such errors, we do not.
                  try {
                    addEventListener('error', (e) => {
                      try { console.error('[err] ' + (e && e.message) + ' @ ' + (e && e.filename) + ':' + (e && e.lineno)); } catch (x) {}
                    });
                    addEventListener('unhandledrejection', (e) => {
                      try {
                        const r = e && e.reason;
                        console.error('[reject] ' + String((r && r.stack) || r).split('\n').join(' | ').slice(0, 300));
                      } catch (x) {}
                    });
                  } catch (e) {}
                  try {
                    const D = EventTarget.prototype.dispatchEvent;
                    const show = (v) => {
                      if (v === null || v === undefined) return String(v);
                      if (typeof v === 'string') return 'str(' + v.length + '):' + v.slice(0, 60);
                      if (typeof v !== 'object') return typeof v + ':' + String(v).slice(0, 30);
                      try {
                        return 'obj{' + Object.keys(v).map((k) => {
                          const x = v[k];
                          return k + '=' + (typeof x === 'string' ? 's' + x.length + ':' + x.slice(0, 24)
                                            : x && typeof x === 'object' ? 'o{' + Object.keys(x).slice(0, 4).join(',') + '}'
                                            : String(x).slice(0, 18));
                        }).join(' ') + '}';
                      } catch (x) { return 'obj?'; }
                    };
                    EventTarget.prototype.dispatchEvent = function (e) {
                      remember('dispatch:' + (e && e.type) +
                               (e && e.type === 'message' ? '[' + show(e.data) + ']' : ''));
                      return D.apply(this, arguments);
                    };
                  } catch (e) {}
                  const wrap = (obj, label) => {
                    for (const k of Object.keys(obj)) {
                      const v = obj[k];
                      if (typeof v !== 'function') continue;
                      obj[k] = function () {
                        // Once: their timestamp vs our clock. The challenge declares `fail` if
                        // they differ by more than 12 hours.
                        if (!globalThis.__pt_clockLogged) {
                          globalThis.__pt_clockLogged = true;
                          try {
                            const o = globalThis._cf_chl_opt || {};
                            const theirs = Object.keys(o)
                              .filter((n) => /^\d{10}$/.test(String(o[n])))
                              .map((n) => n + '=' + o[n]);
                            const now = Math.floor(Date.now() / 1000);
                            console.error('[clock] ours=' + now + ' theirs=[' + theirs.join(' ') +
                                          '] skew=' + theirs.map((t) => now - Number(t.split('=')[1])).join(','));
                          } catch (e) {}
                        }
                        remember(label + '.' + k);
                        try { console.error('[hook] ' + label + '.' + k); } catch (e) {}
                        try {
                          return v.apply(this, arguments);
                        } catch (err) {
                          // Their code catches such throws itself, and these are what cut the chain
                          // halfway.
                          try { console.error('[hookerr] ' + label + '.' + k + ': ' + ((err && err.stack) || err)); } catch (e) {}
                          throw err;
                        }
                      };
                    }
                    return obj;
                  };
                  // Their interpreter: the server program arrives as bytecode and runs via
                  // window.runProgram. Log how long it ran and how it ended.
                  try {
                    let rp;
                    Object.defineProperty(globalThis, 'runProgram', {
                      configurable: true,
                      get() { return rp; },
                      set(v) {
                        rp = typeof v !== 'function' ? v : function (src) {
                          const t0 = Date.now();
                          let fn;
                          try { fn = v.apply(this, arguments); }
                          catch (e) { console.error('[vm] build threw after ' + (Date.now() - t0) + 'ms: ' + e); throw e; }
                          console.error('[vm] built in ' + (Date.now() - t0) + 'ms from ' +
                                        ((src && src.length) || 0) + ' bytes → ' + typeof fn);
                          // Keep the program text: stacks inside it give offsets that are useless
                          // without the source. Keep the largest one: the main program arrives
                          // first, followed by small pieces that would overwrite it.
                          try {
                            const t = String(src || '');
                            if (!globalThis.__pt_vmSrc || t.length > globalThis.__pt_vmSrc.length) {
                              globalThis.__pt_vmSrc = t;
                            }
                          } catch (e) {}
                          if (typeof fn !== 'function') return fn;
                          return function () {
                            const t1 = Date.now();
                            try { globalThis.__pt_probeMark && __pt_probeMark('program start ' + ((src && src.length) || 0)); } catch (e) {}
                            try {
                              const out = fn.apply(this, arguments);
                              try { globalThis.__pt_probeMark && __pt_probeMark('program end'); } catch (e) {}
                              console.error('[vm] ran ' + (Date.now() - t1) + 'ms → ' + typeof out);
                              return out;
                            } catch (e) {
                              try { globalThis.__pt_probeMark && __pt_probeMark('program threw'); } catch (e2) {}
                              console.error('[vm] threw after ' + (Date.now() - t1) + 'ms: ' +
                                            String((e && e.stack) || e).split('\n').join(' | '));
                              try {
                                const line = recent.join(' → ');
                                for (let i = 0; i < line.length; i += 200) {
                                  console.error('[vm] before ' + i + ': ' + line.slice(i, i + 200));
                                }
                              } catch (e2) {}
                              try {
                                const ss = document.scripts;
                                let sizes = [];
                                for (let i = 0; i < ss.length; i++) {
                                  sizes.push((ss[i].src ? 'src:' + String(ss[i].src).slice(-24) : 'inline') +
                                             '=' + String(ss[i].text || '').length);
                                }
                                console.error('[vm] scripts: ' + sizes.join(' ') +
                                              ' | doc ' + document.documentElement.outerHTML.length);
                              } catch (e2) {}
                              try {
                                const g = addedGlobals();
                                for (let i = 0; i < g.length; i += 220) {
                                  console.error('[vm] globals ' + i + ': ' + g.slice(i, i + 220));
                                }
                              } catch (e2) {}
                              try {
                                const tail = misses.slice(-24);
                                for (let i = 0; i < tail.length; i += 6) {
                                  console.error('[vm] missed reads ' + i + ': ' + tail.slice(i, i + 6).join(' '));
                                }
                              } catch (e2) {}
                              throw e;
                            }
                          };
                        };
                      },
                    });
                  } catch (e) {}
                  for (const name of ['RItcy2', 'HuCI0']) {
                    let store;
                    try {
                      Object.defineProperty(globalThis, name, {
                        configurable: true,
                        get() { return store; },
                        set(v) { store = (v && typeof v === 'object') ? wrap(v, name) : v; },
                      });
                    } catch (e) {}
                  }
                })();"#;
                // Streaming event log: enabled by NOKK_TRACE_STREAM=1, otherwise the ring
                // is printed only on a throw.
                let stream = std::env::var("NOKK_TRACE_STREAM").is_ok();
                let hook = hook.replace("__STREAM__", if stream { "true" } else { "false" });
                let hook = hook.replace(
                    "__JMIN__",
                    &std::env::var("NOKK_JOIN_MIN").unwrap_or_else(|_| "2000".into()),
                );
                let hook = hook.replace(
                    "__REPORT__",
                    if std::env::var("NOKK_DUMP_REPORT").is_ok() { "true" } else { "false" },
                );
                let hook = hook.replace(
                    "__HANG__",
                    if std::env::var("NOKK_HANG_UNREACHABLE").is_ok() { "true" } else { "false" },
                );
                c.add_frame_init_script(spread_to_realms(&hook, "hooks"));
                c.add_worker_init_script(hook.clone());
                c.add_init_script(hook);
            }
            c.navigate(url).await?;
            let title = c.evaluate("document.title").await.unwrap_or_default();
            let challenged =
                matches!(&title, serde_json::Value::String(s) if s.contains("Just a moment"));
            ctx = Some(c);
            if !challenged || attempt == cli.retries {
                if challenged && cli.retries > 0 {
                    eprintln!("(still challenged after {} attempt(s))", attempt + 1);
                }
                break;
            }
            tracing::info!(attempt = attempt + 1, "Cloudflare challenge, retrying");
        }
        let ctx = ctx.expect("retry loop runs at least once");
        tracing::info!(elapsed_ms = t.elapsed().as_millis(), "page loaded");

        if let Some(seconds) = cli.solve_challenge {
            let outcome = ctx.solve_challenge(Duration::from_secs(seconds)).await;
            tracing::debug!(status = outcome.status.as_str(), presses = outcome.presses, elapsed_ms = outcome.elapsed_ms, "solve finished");
        }

        // With the probe tracer on, say what the page asked us — in the page and
        // in every frame, since a widget interrogates from inside its own.
        if std::env::var("NOKK_TRACE_PROBES").is_ok() {
            let dump = |where_: String, v: serde_json::Value| {
                if let Some(text) = v.as_str() {
                    if let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(text) {
                        eprintln!("# probes {where_}: {} distinct", rows.len());
                        for row in rows.iter().take(3000) {
                            eprintln!(
                                "#   {:>5}x {} -> {}",
                                row[1].as_u64().unwrap_or(0),
                                row[0].as_str().unwrap_or(""),
                                row[2].as_str().unwrap_or("")
                            );
                        }
                    }
                }
            };
            if let Ok(v) = ctx.evaluate("__pt_probeLog()").await {
                dump("page".into(), v);
            }
            // Workers are where a challenge does its collecting, and a worker's
            // context is reachable from nothing on the page — so ask each live one
            // directly. A collector usually posts its result and hangs up long
            // before this runs; the engine leaves what it was asked with the
            // document that started it, so read that too.
            for (url, v) in ctx
                .evaluate_in_workers("typeof __pt_probeLog === 'function' ? __pt_probeLog() : ''")
                .await
            {
                dump(format!("worker {url}"), v);
            }
            // Same for the page itself: the interstitial draws its UI in a closed
            // shadow root just like the widget.
            if let Ok(serde_json::Value::String(t)) = ctx
                .evaluate("(() => { const ids = [];                    for (const el of document.querySelectorAll('*')) if (el.id) ids.push(el.localName + '#' + el.id);                    const root = (globalThis._cf_chl_opt || {}).wTgF5;                    return JSON.stringify({ids: ids.slice(0, 20),                      renderRoot: root ? (root.nodeName || 'shadow') : null,                      rootKids: root && root.childNodes ? root.childNodes.length : -1}); })()")
                .await
            {
                eprintln!("# page ids: {t}");
            }
            if let Ok(serde_json::Value::String(t)) = ctx.evaluate("(() => { const seen = []; const walk = (root) => {                            for (const el of root.querySelectorAll('*')) {                              const tag = el.localName;                              if (tag === 'input' || tag === 'button' || el.getAttribute('role'))                                seen.push(tag + (el.type ? '[' + el.type + ']' : '') +                                          (el.getAttribute('role') ? '{' + el.getAttribute('role') + '}' : ''));                              const sr = el.shadowRoot || el.__ptShadow; if (sr) walk(sr); } };                          const root = document.body && (document.body.shadowRoot || document.body.__ptShadow);                          try { walk(document); if (root) walk(root); } catch (e) {}                          return JSON.stringify({controls: seen.slice(0, 12),                            events: (globalThis._cf_chl_opt && _cf_chl_opt.FELcX1) ? _cf_chl_opt.FELcX1.length : -1, bodyShadow: !!root,                            shadowKids: root ? root.childNodes.length : -1,                            shadowText: root ? String(root.textContent || '').trim().slice(0, 60) : '',                            bodyKids: document.body ? document.body.childNodes.length : -1,                            view: [innerWidth, innerHeight],                            html: (document.documentElement ? document.documentElement.outerHTML : '').length}); })()").await {
                eprintln!("# page widget: {t}");
            }
            // What the widget finally rendered: the interactive control the engine
            // expects; its absence is only visible this way.
            for f in ctx.frame_list() {
                if let Ok(serde_json::Value::String(t)) = ctx
                    .evaluate_in_frame(
                        f.id,
                        "(() => { const seen = []; const walk = (root) => {                            for (const el of root.querySelectorAll('*')) {                              const tag = el.localName;                              if (tag === 'input' || tag === 'button' || el.getAttribute('role'))                                seen.push(tag + (el.type ? '[' + el.type + ']' : '') +                                          (el.getAttribute('role') ? '{' + el.getAttribute('role') + '}' : ''));                              const sr = el.shadowRoot || el.__ptShadow; if (sr) walk(sr); } };                          const root = document.body && (document.body.shadowRoot || document.body.__ptShadow);                          try { walk(document); if (root) walk(root); } catch (e) {}                          return JSON.stringify({controls: seen.slice(0, 12),                            events: (globalThis._cf_chl_opt && _cf_chl_opt.FELcX1) ? _cf_chl_opt.FELcX1.length : -1, bodyShadow: !!root,                            shadowKids: root ? root.childNodes.length : -1,                            shadowText: root ? String(root.textContent || '').trim().slice(0, 60) : '',                            bodyKids: document.body ? document.body.childNodes.length : -1,                            view: [innerWidth, innerHeight],                            html: (document.documentElement ? document.documentElement.outerHTML : '').length}); })()",
                    )
                    .await
                {
                    eprintln!("# widget frame {}: {t}", f.id);
                }
            }
            // This run's challenge keys: without them the server response cannot be
            // decrypted later (the key derives from the widget's ray).
            for f in ctx.frame_list() {
                if let Ok(serde_json::Value::String(t)) = ctx
                    .evaluate_in_frame(
                        f.id,
                        "JSON.stringify({ray: (globalThis._cf_chl_opt||{}).wxfI5 || null,                          sitekey: (globalThis._cf_chl_opt||{}).ZSOv1 || null})",
                    )
                    .await
                {
                    if t.contains("\"ray\":\"") {
                        eprintln!("# chl frame {}: {t}", f.id);
                    }
                }
            }
            let tail = match std::env::var("NOKK_TRACE_HEAD") {
                Ok(_) => "typeof __pt_probeHead === 'function' ? __pt_probeHead(400000) : ''",
                Err(_) => "typeof __pt_probeTail === 'function' ? __pt_probeTail(40) : ''",
            };
            let mut where_: Vec<Option<u32>> = vec![None];
            where_.extend(ctx.frame_list().iter().map(|f| Some(f.id)));
            for slot in where_ {
                let out = match slot {
                    None => ctx.evaluate(tail).await,
                    Some(id) => ctx.evaluate_in_frame(id, tail).await,
                };
                if let Ok(serde_json::Value::String(text)) = out {
                    if let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                        if !rows.is_empty() {
                            let label = slot
                                .map(|i| format!("frame {i}"))
                                .unwrap_or_else(|| "page".to_string());
                            eprintln!("# tail {label}:");
                            for row in rows {
                                eprintln!("#   {:>6}ms {} -> {}", row[0].as_i64().unwrap_or(0),
                                          row[1].as_str().unwrap_or(""), row[2].as_str().unwrap_or(""));
                            }
                        }
                    }
                }
            }
            // Feed snapshot at the mark: what was read last before sending.
            for slot in ctx.frame_list().iter().map(|f| Some(f.id)).chain(std::iter::once(None)) {
                let expr = "globalThis.__pt_atMark || ''";
                let out = match slot {
                    None => ctx.evaluate(expr).await,
                    Some(id) => ctx.evaluate_in_frame(id, expr).await,
                };
                if let Ok(serde_json::Value::String(text)) = out {
                    if let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                        if !rows.is_empty() {
                            let label = slot
                                .map(|i| format!("frame {i}"))
                                .unwrap_or_else(|| "page".to_string());
                            eprintln!("# mark {label}: {} rows", rows.len());
                            for row in rows {
                                eprintln!(
                                    "#M {:>6}ms {} -> {}",
                                    row[0].as_i64().unwrap_or(0),
                                    row[1].as_str().unwrap_or(""),
                                    row[2].as_str().unwrap_or("")
                                );
                            }
                        }
                    }
                }
            }
            let trace = "JSON.stringify(globalThis.__pt_workerTrace || [])";
            let mut traces = vec![ctx.evaluate(trace).await];
            for f in ctx.frame_list() {
                traces.push(ctx.evaluate_in_frame(f.id, trace).await);
            }
            for v in traces.into_iter().flatten() {
                let rows: Vec<(String, String)> = v
                    .as_str()
                    .and_then(|t| serde_json::from_str(t).ok())
                    .unwrap_or_default();
                for (url, log) in rows {
                    dump(format!("worker {url} (ended)"), serde_json::Value::String(log));
                }
            }
            for f in ctx.frame_list() {
                if let Ok(v) = ctx
                    .evaluate_in_frame(
                        f.id,
                        "typeof __pt_probeLog === 'function' ? __pt_probeLog() : ''",
                    )
                    .await
                {
                    dump(format!("frame {} {}", f.id, f.url), v);
                }
            }
        }

        // Each tool below has its own env var; the probe tracer itself perturbs
        // what is measured, so they must not depend on it.
        // Challenge program source on demand: too big (600+ KB) for the log, but
        // needed whole to read stack offsets.
        if let Ok(path) = std::env::var("NOKK_DUMP_VM") {
            let mut where_: Vec<Option<u32>> = vec![None];
            where_.extend(ctx.frame_list().iter().map(|f| Some(f.id)));
            // Two large strings, not one: the source given to `Function` and the one
            // joined from the `/fo/` response. They differ (different starts); compare
            // both with Chrome.
            for (js, tag) in [
                ("typeof __pt_vmSrc === 'string' ? __pt_vmSrc : ''", "js"),
                // The largest inline script of the document: in the widget frame it holds
                // the interpreter and the collector, which foreign error stacks point
                // into.
                (
                    "(() => { let big = ''; for (const e of document.scripts) \
                       if (!e.src && e.textContent && e.textContent.length > big.length) \
                         big = e.textContent; \
                     return big; })()",
                    "doc",
                ),
                ("typeof __ptProg === 'string' ? __ptProg : ''", "join"),
                // Smaller joins (report, style enumeration) go one per file: line-by-line
                // comparison with Chrome needs them whole.
                ("(globalThis.__ptJoins||[]).map(j => j[0] + '\\u0000' + j[1]).join('\\u0001')", "joins"),
            ] {
            for slot in where_.clone() {
                let out = match slot {
                    None => ctx.evaluate(js).await,
                    Some(id) => ctx.evaluate_in_frame(id, js).await,
                };
                if let Ok(serde_json::Value::String(src)) = out {
                    if src.len() > 1000 {
                        let name = match slot {
                            None => format!("{path}.page.{tag}"),
                            Some(id) => format!("{path}.frame{id}.{tag}"),
                        };
                        if tag == "joins" {
                            for part in src.split('\u{1}') {
                                let Some((n, body)) = part.split_once('\u{0}') else {
                                    continue;
                                };
                                let name = format!("{name}.{n}");
                                if std::fs::write(&name, body).is_ok() {
                                    eprintln!("# join saved: {name} ({} bytes)", body.len());
                                }
                            }
                        } else if std::fs::write(&name, &src).is_ok() {
                            eprintln!("# program saved: {name} ({} bytes)", src.len());
                        }
                    }
                }
            }
            }
        }
        // Ask the same thing of the page and each of its frames. The challenge
        // frame is cross-origin and unreachable from the page, but the engine can
        // enter it directly.
        if let Ok(js) = std::env::var("NOKK_EVAL_FRAMES") {
            let mut where_: Vec<Option<u32>> = vec![None];
            where_.extend(ctx.frame_list().iter().map(|f| Some(f.id)));
            for slot in where_ {
                let out = match slot {
                    None => ctx.evaluate(&js).await,
                    Some(id) => ctx.evaluate_in_frame(id, &js).await,
                };
                let label = slot
                    .map(|i| format!("frame {i}"))
                    .unwrap_or_else(|| "page".to_string());
                match out {
                    Ok(v) => eprintln!("# {label}: {}", render(&v)),
                    Err(e) => eprintln!("# {label}: error: {e}"),
                }
            }
        }
        // Errors the foreign program built in its own frame: unreadable from the
        // cross-origin page, but the engine can enter the frame.
        if std::env::var("NOKK_TRACE_THROWS").is_ok() {
            let js = "typeof __pt_throwTail === 'function' ? __pt_throwTail(20) : ''";
            let mut where_: Vec<Option<u32>> = vec![None];
            where_.extend(ctx.frame_list().iter().map(|f| Some(f.id)));
            for slot in where_ {
                let out = match slot {
                    None => ctx.evaluate(js).await,
                    Some(id) => ctx.evaluate_in_frame(id, js).await,
                };
                if let Ok(serde_json::Value::String(text)) = out {
                    if text.is_empty() {
                        continue;
                    }
                    let label = slot
                        .map(|i| format!("frame {i}"))
                        .unwrap_or_else(|| "page".to_string());
                    eprintln!("# throws {label}:");
                    for line in text.lines() {
                        eprintln!("#   {line}");
                    }
                }
            }
        }

        // Drive a form: fills, then trusted clicks, in order. Runs before
        // `--eval` so a probe sees the page the steps left behind.
        let before_steps = ctx.requests().len();
        for spec in &cli.fill {
            fill_input(&ctx, spec).await?;
        }
        for selector in &cli.click {
            click_selector(&ctx, selector).await?;
        }

        // Run `--eval` first — it may trigger further requests (fetch/beacon/img)
        // that should then appear in the interception log.
        if let Some(js) = &cli.eval {
            eval_and_print(&ctx, js).await?;
        }

        // Wait for the page's own answer (e.g. a bill query's XHR), print its
        // body, and exit.
        if let Some(needle) = &cli.wait_response {
            wait_response(&ctx, needle, cli.response_timeout, before_steps).await?;
            return Ok(());
        }

        // Print the response body of a specific captured request (e.g. an API).
        if let Some(needle) = &cli.dump_request {
            match ctx.requests().into_iter().find(|r| r.url.contains(needle)) {
                Some(r) => {
                    eprintln!(
                        "# {} {} → {} ({} bytes)",
                        r.method,
                        r.url,
                        r.status,
                        r.body.len()
                    );
                    // The outgoing half of the exchange: the challenge error beacon answers
                    // empty, and everything it reports about us is in the request body.
                    if !r.request_body.is_empty() {
                        eprintln!("# sent ({} bytes):", r.request_body.len());
                        println!("{}", String::from_utf8_lossy(&r.request_body));
                        eprintln!("# received ({} bytes):", r.body.len());
                    }
                    println!("{}", String::from_utf8_lossy(&r.body));
                }
                None => eprintln!("no captured request matching '{needle}'"),
            }
            return Ok(());
        }
        // List every request the page made (the built-in interception log).
        if cli.dump_requests {
            let reqs = ctx.requests();
            println!("{} requests for {url}", reqs.len());
            for r in &reqs {
                // Request body size is only visible here.
                let sent = if r.request_body.is_empty() {
                    String::new()
                } else {
                    format!(" [sent {} bytes]", r.request_body.len())
                };
                println!(
                    "[{:<8}] {:<4} {} → {} ({} bytes){sent}",
                    r.resource_type,
                    r.method,
                    r.url,
                    r.status,
                    r.body.len()
                );
            }
            return Ok(());
        }

        // A challenge still in place at exit means the clearance is dead; say so
        // instead of returning the Just a moment page as if it loaded normally.
        let final_title = ctx.evaluate("document.title").await.unwrap_or_default();
        let at_gate =
            matches!(&final_title, serde_json::Value::String(s) if s.contains("Just a moment"));
        // `--until-clearance` stops on the gate's page on purpose, lock in hand.
        let still_challenged = at_gate && !ctx.stopped_at_clearance();
        if at_gate && !still_challenged {
            eprintln!("clearance obtained; the site behind the gate was not loaded (--until-clearance)");
        }
        if still_challenged {
            if cli.import_cookies.is_some() {
                eprintln!(
                    "still challenged: the imported clearance was rejected (expired, or taken \
                     with another Chrome version or from another address)"
                );
            } else {
                eprintln!("still challenged: no clearance cookie (see --import-cookies)");
            }
        }

        if cli.eval.is_none() {
            // Default summary: title + a count of elements in the built DOM.
            let title = final_title.clone();
            let count = ctx
                .evaluate("document.querySelectorAll('*').length")
                .await
                .unwrap_or_default();
            println!("loaded {url}");
            println!("title: {title}");
            println!("elements: {count}");
        }
        if still_challenged && cli.fail_on_challenge {
            std::process::exit(3);
        }
        return Ok(());
    }

    // One-shot eval mode: run JS in a stealth-patched context and print it
    // (driving the event loop so fetch/timers can complete).
    if let Some(js) = &cli.eval {
        let ctx = engine.new_context().await?;
        eval_and_print(&ctx, js).await?;
        return Ok(());
    }

    // Default: run the CDP server so Puppeteer/Playwright can drive the engine.
    let addr = std::net::SocketAddr::new(cli.host, cli.port);
    // Advertise a connectable host: 0.0.0.0 isn't dialable, so point clients at
    // loopback (the common `-p` / local case).
    let advertise = if cli.host.is_unspecified() {
        std::net::IpAddr::from([127, 0, 0, 1])
    } else {
        cli.host
    };
    let token = cli.token.clone().filter(|t| !t.is_empty());
    let query = token.as_ref().map(|t| format!("?token={t}")).unwrap_or_default();
    println!(
        "CDP server on ws://{advertise}:{}/devtools/browser/nokk{query}",
        cli.port
    );
    println!("  Puppeteer: puppeteer.connect({{ browserWSEndpoint: 'ws://{advertise}:{}/devtools/browser/nokk{query}' }})", cli.port);
    if token.is_none() && !cli.host.is_loopback() {
        eprintln!(
            "warning: the CDP server listens on {} without a token; anyone who reaches the port \
             can browse from this machine and read its sessions. Set --token or NOKK_TOKEN.",
            cli.host
        );
    }
    nokk_cdp::serve(engine, nokk_cdp::ServerConfig { addr, auto_solve: cli.auto_solve.map(Duration::from_secs), token }).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nokk_net::ProxyScheme;

    #[test]
    fn parse_proxy_http_with_credentials() {
        let p = parse_proxy("http://user:pass@10.0.0.1:8080").expect("should parse");
        assert_eq!(p.scheme, ProxyScheme::Http);
        assert_eq!(p.host, "10.0.0.1");
        assert_eq!(p.port, 8080);
        assert_eq!(p.username.as_deref(), Some("user"));
        assert_eq!(p.password.as_deref(), Some("pass"));
    }

    #[test]
    fn parse_proxy_socks5_without_credentials() {
        let p = parse_proxy("socks5://127.0.0.1:1080").expect("should parse");
        assert_eq!(p.scheme, ProxyScheme::Socks5);
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 1080);
        assert!(p.username.is_none());
        assert!(p.password.is_none());
    }

    #[test]
    fn parse_proxy_socks5h_maps_to_socks5() {
        let p = parse_proxy("socks5h://host.example:1081").expect("should parse");
        assert_eq!(p.scheme, ProxyScheme::Socks5);
    }

    #[test]
    fn parse_proxy_rejects_unsupported_scheme() {
        assert!(parse_proxy("ftp://host:21").is_none());
        assert!(parse_proxy("not a url").is_none());
    }

    #[test]
    fn parse_proxy_requires_explicit_port() {
        // No default-port inference — the proxy port must be given.
        assert!(parse_proxy("http://host.example").is_none());
        // Written out, the scheme's default port counts (`url` hides it).
        assert_eq!(parse_proxy("http://u:p@proxy.example.net:80").expect(":80").port, 80);
        assert_eq!(parse_proxy("https://h.example:443/").expect(":443").port, 443);
        assert!(parse_proxy("http://h.example:8080").is_some());
    }

    #[test]
    fn parse_proxy_decodes_credentials() {
        let p = parse_proxy("http://us%40er:p%3Ass%40@10.0.0.1:3128").expect("should parse");
        assert_eq!(p.username.as_deref(), Some("us@er"));
        assert_eq!(p.password.as_deref(), Some("p:ss@"));
    }

    #[test]
    fn render_unwraps_json_string_to_raw_text() {
        let v = serde_json::Value::String("line1\nline2".to_string());
        assert_eq!(render(&v), "line1\nline2");
    }

    #[test]
    fn render_leaves_non_strings_as_json() {
        let v = serde_json::json!({ "a": 1 });
        assert_eq!(render(&v), "{\"a\":1}");
    }
}

/// Installs the trace probe into every fresh realm too. The Turnstile widget
/// serializes and sends through an empty frame via `contentWindow`, and
/// frame probes do not reach it since the realm is built from the
/// bootstrap. The realm shares the serialization-window flags with its
/// parent. Tracing only.
fn spread_to_realms(probe: &str, key: &str) -> String {
    let body = serde_json::to_string(probe).unwrap_or_default();
    format!(
        r#"{probe}
;(() => {{
  const RM = globalThis.__pt_makeRealm;
  if (typeof RM !== 'function' || globalThis['__ptSpread_{key}']) return;
  globalThis['__ptSpread_{key}'] = 1;
  const parentG = globalThis;
  globalThis.__pt_makeRealm = function __pt_makeRealm() {{
    const g = RM.apply(this, arguments);
    try {{
      if (g && typeof g.eval === 'function' && !g['__ptSpread_{key}']) {{
        for (const k of ['__ptSerializing', '__ptCollected', '__ptStrings', '__ptFirstBody', '__ptMarked']) {{
          if (Object.getOwnPropertyDescriptor(g, k)) continue;
          Object.defineProperty(g, k, {{ get() {{ return parentG[k]; }}, set(v) {{ parentG[k] = v; }}, configurable: true }});
        }}
        g.__ptInRealm = 1;
        // The realm console writes to a sink the engine does not read; give the
        // probe the parent's console lexically, without touching the realm window.
        Object.defineProperty(g, '__ptParentConsole', {{ value: parentG.console, configurable: true }});
        g.eval('(function (console) {{' + {body} + '\n}})(globalThis.__ptParentConsole)');
      }}
    }} catch (e) {{ try {{ console.error('[realm] probe install failed: ' + e); }} catch (x) {{}} }}
    return g;
  }};
}})();"#
    )
}
