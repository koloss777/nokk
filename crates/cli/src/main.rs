//! `nokk` — CLI entry point.
//!
//! Wires up configuration, logging and the engine, then dispatches on the flags:
//! one-shot `--fetch`/`--eval`/`--load` modes, or (the default) a CDP WebSocket
//! server on `--port` that Puppeteer can attach to.

use std::time::Instant;

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
        // Retry on a Cloudflare challenge (the pass is probabilistic). Each try
        // is a fresh context so a poisoned session doesn't carry over.
        let mut ctx = None;
        for attempt in 0..=cli.retries {
            let c = engine.new_context().await?;
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
