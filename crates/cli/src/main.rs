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

    /// Address the CDP server binds to. Defaults to loopback; set `0.0.0.0` to
    /// accept connections from other hosts (e.g. inside a Docker container).
    #[arg(long, env = "NOKK_HOST", default_value = "127.0.0.1")]
    host: std::net::IpAddr,

    /// Number of isolate worker threads. Defaults to available parallelism.
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

    /// For `--load`: after loading, print every network request the page made
    /// (document + scripts + fetch/XHR) as `[type] METHOD url → status (N bytes)`.
    #[arg(long)]
    dump_requests: bool,

    /// For `--load`: print the response *body* of the first captured request
    /// whose URL contains this substring (e.g. an `/api/...` JSON call).
    #[arg(long, value_name = "URL_SUBSTR")]
    dump_request: Option<String>,
}

/// Parse a `scheme://[user:pass@]host:port` proxy URL into a `ProxyConfig`.
fn parse_proxy(s: &str) -> Option<nokk_net::ProxyConfig> {
    let u = url::Url::parse(s).ok()?;
    let scheme = match u.scheme() {
        "http" | "https" => nokk_net::ProxyScheme::Http,
        "socks5" | "socks5h" => nokk_net::ProxyScheme::Socks5,
        _ => return None,
    };
    Some(nokk_net::ProxyConfig {
        scheme,
        host: u.host_str()?.to_string(),
        port: u.port()?,
        username: (!u.username().is_empty()).then(|| u.username().to_string()),
        password: u.password().map(|p| p.to_string()),
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

/// Evaluate `js`, then drive the event loop so any `fetch`/timers it starts
/// complete, and print the result. If the expression is (or resolves to) a
/// Promise, the *resolved* value is printed; otherwise the value itself.
async fn eval_and_print(ctx: &BrowserContext, js: &str) -> Result<()> {
    // Route both sync values and Promise resolutions through `__out`.
    let wrapped = format!(
        "(() => {{ const v = ({js}); \
           if (v && typeof v.then === 'function') {{ \
             v.then(x => {{ globalThis.__out = x; }}, e => {{ globalThis.__out = 'ERR: ' + e; }}); \
           }} else {{ globalThis.__out = v; }} \
           return undefined; }})()"
    );
    if let Err(e) = ctx.evaluate(&wrapped).await {
        eprintln!("eval error: {e}");
        std::process::exit(1);
    }
    ctx.run_event_loop().await.ok();
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
        }
        if let Some(m) = self.max_contexts {
            pool.max_live_contexts = m.max(1);
        }
        if let Some(mb) = self.max_heap_mb {
            pool.max_heap_mb = Some(mb.max(16)); // a tiny cap would fail instantly
        }
        let mut client = ClientConfig::default();
        if let Some(spec) = &self.proxy {
            match parse_proxy(spec) {
                Some(p) => client.proxy = Some(p),
                None => eprintln!("warning: could not parse --proxy '{spec}', ignoring"),
            }
        }
        EngineConfig {
            pool,
            client,
            // The CLI always drives real traffic (one-shot fetch/load/eval or the
            // CDP server); only the library test harness stays offline.
            use_real_network: true,
            session_store: self.session_store.clone(),
            block_trackers: !self.allow_trackers,
            rotate_fingerprint: self.rotate_fingerprint,
            geoip_timezone: self.geoip_timezone,
            chrome_major: self
                .chrome_version
                .unwrap_or(nokk_net::DEFAULT_CHROME_MAJOR),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

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
            let deadline = Instant::now() + Duration::from_secs(seconds);
            /// A widget asks once or twice; more than this is a loop, not a user.
            const MAX_PRESSES: usize = 3;
            let mut pressed = 0usize;
            let mut seen_controls = std::collections::HashSet::new();
            loop {
                ctx.run_event_loop().await.ok();
                let cleared = ctx.cookies(&[]).iter().any(|c| c.name == "cf_clearance");
                if cleared {
                    tracing::info!(
                        elapsed_ms = t.elapsed().as_millis(),
                        presses = pressed,
                        "challenge cleared"
                    );
                    break;
                }
                if Instant::now() >= deadline {
                    tracing::warn!(presses = pressed, "challenge did not clear in time");
                    break;
                }
                // Press only what is offered; a widget still verifying offers
                // nothing, and pressing nothing is the correct thing to do.
                // One press per control that appears. A widget that ignores it is
                // not asking to be pressed again — a person would not keep
                // clicking either, and a flurry of clicks is its own signature.
                if pressed < MAX_PRESSES {
                    if let Ok(Some(what)) = ctx.press_widget_control().await {
                        if seen_controls.insert(what.clone()) {
                            pressed += 1;
                            tracing::info!(control = %what, "pressed the challenge widget");
                            tokio::time::sleep(Duration::from_millis(1_500)).await;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
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
            // Что виджет в итоге нарисовал: интерактивный контрол — то, чего
            // движок ждёт от него, и его отсутствие видно только так.
            for f in ctx.frame_list() {
                if let Ok(serde_json::Value::String(t)) = ctx
                    .evaluate_in_frame(
                        f.id,
                        "(() => { const seen = []; const walk = (root) => {                            for (const el of root.querySelectorAll('*')) {                              const tag = el.localName;                              if (tag === 'input' || tag === 'button' || el.getAttribute('role'))                                seen.push(tag + (el.type ? '[' + el.type + ']' : '') +                                          (el.getAttribute('role') ? '{' + el.getAttribute('role') + '}' : ''));                              if (el.shadowRoot) walk(el.shadowRoot); } };                          try { walk(document); } catch (e) {}                          return JSON.stringify({controls: seen.slice(0, 12), \
                           body: !!document.body, \
                           bodyKids: document.body ? document.body.childNodes.length : -1, \
                           iframes: document.getElementsByTagName('iframe').length, \
                           shadows: Array.prototype.filter.call(document.querySelectorAll('*'), (e) => e.shadowRoot).length, \
                           htmlLen: (document.documentElement ? document.documentElement.outerHTML : '').length, \
                           view: [innerWidth, innerHeight, document.documentElement.clientWidth, document.documentElement.clientHeight], \
                           vis: [document.visibilityState, document.hidden, document.readyState], \
                           box: (() => { const b = document.body.getBoundingClientRect(); return [b.width, b.height]; })(), \
                           text: (document.body ? document.body.textContent : '').trim().slice(0, 60)}); })()",
                    )
                    .await
                {
                    eprintln!("# widget frame {}: {t}", f.id);
                }
            }
            // Ключи челленджа этого прогона: без них ответ сервера не расшифровать
            // задним числом (ключ выводится из ray самого виджета).
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
            // Хвост: чем страница и каждый фрейм занимались последними, по порядку.
            let tail = match std::env::var("NOKK_TRACE_HEAD") {
                Ok(_) => "typeof __pt_probeHead === 'function' ? __pt_probeHead(6000) : ''",
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

        // Run `--eval` first — it may trigger further requests (fetch/beacon/img)
        // that should then appear in the interception log.
        if let Some(js) = &cli.eval {
            eval_and_print(&ctx, js).await?;
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
                println!(
                    "[{:<8}] {:<4} {} → {} ({} bytes)",
                    r.resource_type,
                    r.method,
                    r.url,
                    r.status,
                    r.body.len()
                );
            }
            return Ok(());
        }

        if cli.eval.is_none() {
            // Default summary: title + a count of elements in the built DOM.
            let title = ctx.evaluate("document.title").await.unwrap_or_default();
            let count = ctx
                .evaluate("document.querySelectorAll('*').length")
                .await
                .unwrap_or_default();
            println!("loaded {url}");
            println!("title: {title}");
            println!("elements: {count}");
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
    println!(
        "CDP server on ws://{advertise}:{}/devtools/browser/nokk",
        cli.port
    );
    println!("  Puppeteer: puppeteer.connect({{ browserWSEndpoint: 'ws://{advertise}:{}/devtools/browser/nokk' }})", cli.port);
    nokk_cdp::serve(engine, nokk_cdp::ServerConfig { addr }).await?;
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
