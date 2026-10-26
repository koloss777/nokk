//! A V8 isolate, owned by exactly one worker thread.
//!
//! Phase 1: this wraps a real `v8::OwnedIsolate`. Each isolate multiplexes
//! several contexts ("tabs"), stored as persistent [`v8::Global`] handles.
//! Because V8 handles are thread-affine and `!Send`, an isolate and its contexts
//! are only ever touched from the worker thread that created them — which is
//! exactly the [`crate::IsolatePool`] contract.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use crate::WorkerId;

/// Every module this isolate has compiled, and what it imports. A module graph
/// is instantiated through a *synchronous* callback, so the whole graph has to
/// be compiled and its specifiers resolved before instantiation begins — the
/// fetching happens outside, in the engine, and lands here. Kept in an isolate
/// slot because the resolve callback is a bare fn with no state of its own.
#[derive(Default)]
struct ModuleRegistry {
    /// "{context index}:{absolute url}" → the compiled module.
    modules: HashMap<String, v8::Global<v8::Module>>,
    /// V8's identity hash for a module → the same key, so a referrer can be
    /// named when it asks for one of its imports.
    by_hash: HashMap<i32, String>,
    /// (referrer key, specifier as written) → key of what it resolves to.
    edges: HashMap<(String, String), String>,
}

/// Pending `import()` calls. V8 has no module loader of its own: it calls a
/// hook and waits on a promise the embedder must settle. Without the hook every
/// dynamic import rejects, which breaks any code-split site.
#[derive(Default)]
#[allow(clippy::type_complexity)]
struct DynamicImports {
    next_id: u32,
    /// id -> promise to settle once the module is ready.
    pending: HashMap<u32, v8::Global<v8::PromiseResolver>>,
    /// What was asked and by whom: (id, context index, referrer URL, specifier).
    queue: Vec<(u32, usize, String, String)>,
}

/// Whether the engine has ICU data. With it native `Intl` answers like Chrome
/// (currencies, plurals, time zones, segmentation); without it a stub stands in
/// and answers differently.
static ICU_READY: AtomicBool = AtomicBool::new(false);

/// Whether ICU data is loaded (see [`ICU_READY`]).
pub fn icu_ready() -> bool {
    ICU_READY.load(Ordering::Relaxed)
}

/// Chrome 151's own `icudtl.dat` (ICU 78, the version this V8 links), so `Intl`
/// answers as Chrome does. Embedded: the release archives and packages carry only
/// the binary, and without data every published build ran the `Intl` stub.
/// ICU reads its data in place and expects it aligned; `include_bytes!` is byte-aligned.
#[repr(C, align(16))]
struct Aligned<T: ?Sized>(T);
static EMBEDDED_ICU: &Aligned<[u8]> = &Aligned(*include_bytes!("../icu/icudtl.dat"));

/// Where to look for `icudtl.dat` before the embedded copy: the configured path,
/// then next to the binary. The data format is tied to the ICU version V8 was
/// built with, so a foreign file may not fit; then the next candidate is tried.
fn icu_candidates() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = std::env::var("NOKK_ICU_DATA") {
        out.push(std::path::PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join("icudtl.dat"));
        }
    }
    out
}

static V8_INIT: Once = Once::new();
/// Serialises `v8::Isolate::new`. Concurrent isolate construction from multiple
/// threads segfaults with the prebuilt V8; construction is a one-time,
/// startup-only cost per worker, so a global lock here is free in practice.
static CREATE_LOCK: Mutex<()> = Mutex::new(());

/// V8 snapshot with the bootstrap already run: a context restores in
/// milliseconds instead of the ~300 ms bootstrap. One per process, for the
/// default bootstrap; others (rotated profiles, geolocation) take the regular path.
pub struct Snapshot {
    bootstrap: String,
    data: &'static [u8],
}
static SNAPSHOT: std::sync::OnceLock<Snapshot> = std::sync::OnceLock::new();

pub(crate) fn snapshot_matches(bootstrap: &str) -> bool {
    snapshot_for(bootstrap)
}

fn snapshot_for(bootstrap: &str) -> bool {
    if std::env::var_os("NOKK_SNAP_CUT").is_some() {
        return SNAPSHOT.get().is_some();
    }
    SNAPSHOT.get().is_some_and(|s| s.bootstrap.len() == bootstrap.len() && s.bootstrap == bootstrap)
}

const NORMALIZE_FOR_SNAPSHOT: &str = r#"(() => {
  const N = globalThis.__pt_rawGOPN || Object.getOwnPropertyNames;
  const seen = new Set();
  const norm = (o) => {
    if (!o || (typeof o !== 'object' && typeof o !== 'function') || seen.has(o)) return;
    seen.add(o);
    try {
      if (!Object.isExtensible(o)) return;
      const a = Symbol('a'), b = Symbol('b');
      Object.defineProperty(o, a, { value: 1, configurable: true, writable: true });
      Object.defineProperty(o, b, { value: 1, configurable: true, writable: true });
      delete o[a]; delete o[b];
    } catch (e) {}
  };
  for (const k of N(globalThis)) {
    let v; try { const d = Object.getOwnPropertyDescriptor(globalThis, k); v = d && d.value; } catch (e) { continue; }
    if (typeof v === 'function') { norm(v); for (let p = v.prototype, i = 0; p && i < 16; p = Object.getPrototypeOf(p), i++) norm(p); }
    else if (v && typeof v === 'object') { norm(v); for (let p = Object.getPrototypeOf(v), i = 0; p && i < 16; p = Object.getPrototypeOf(p), i++) norm(p); }
  }
})();"#;

/// After restoring from the snapshot: the clock starts now, not at build time.
/// Also reshapes what V8 delivered on restore the way the bootstrap would have
/// (`__pt_afterRestore`, installed only when building the snapshot).
pub(crate) const AFTER_SNAPSHOT: &str = "globalThis.__pt_resetClock && __pt_resetClock();\n\
    if (globalThis.__pt_afterRestore) { try { __pt_afterRestore(); } catch (e) {} delete globalThis.__pt_afterRestore; delete globalThis.__pt_wasmStreaming; delete globalThis.__pt_lateShape; }";

/// Build the snapshot for `bootstrap`. Call before creating the pool (isolates
/// get the snapshot at birth). `NOKK_NO_SNAPSHOT=1` disables it.
pub fn build_snapshot(bootstrap: &str) -> Result<usize, String> {
    if std::env::var_os("NOKK_NO_SNAPSHOT").is_some() {
        return Err("disabled".into());
    }
    if SNAPSHOT.get().is_some() {
        return Ok(0);
    }
    init_platform();
    let t0 = std::time::Instant::now();
    // Install all natives in an empty isolate first so the external-reference
    // list is complete before the snapshot. Also record the regular context's
    // global names: V8 omits some when building a snapshot (flag-gated features,
    // WebAssembly, SharedArrayBuffer) and adds them on restore, on top of the
    // bootstrap's work.
    const GLOBAL_NAMES: &str = "JSON.stringify(Object.getOwnPropertyNames(globalThis))";
    let plain_names: Vec<String> = {
        let _guard = CREATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut iso = v8::Isolate::new(v8::CreateParams::default());
        let names = {
            v8::scope!(scope, &mut iso);
            let context = crate::natives::new_page_context(scope);
            let scope = &mut v8::ContextScope::new(scope, context);
            let names = run_script(scope, GLOBAL_NAMES).unwrap_or_default();
            crate::natives::install(scope);
            names
        };
        drop(iso);
        serde_json::from_str(&names).unwrap_or_default()
    };
    let refs = crate::natives::external_refs();
    // Debug: NOKK_SNAP_CUT=<layer> snapshots the bootstrap up to the end of that
    // layer (needs NOKK_TRACE_BOOT so the source carries layer markers).
    let cut: String;
    let bootstrap = match std::env::var("NOKK_SNAP_CUT") {
        Ok(layer) => {
            let key = format!("push(['{layer}'");
            match bootstrap.find(&key) {
                Some(i) => {
                    let end = bootstrap[i..].find('\n').map(|j| i + j).unwrap_or(bootstrap.len());
                    cut = bootstrap[..end].to_string();
                    &cut
                }
                None => bootstrap,
            }
        }
        Err(_) => bootstrap,
    };
    // The snapshot depends only on the bootstrap, V8 flags and the binary, and
    // takes 700+ ms to build, so it is cached on disk for per-site processes.
    let cache = snapshot_cache_path(bootstrap);
    if let Some(path) = &cache {
        if let Ok(bytes) = std::fs::read(path) {
            if bytes.len() > 1024 {
                let data: &'static [u8] = Box::leak(bytes.into_boxed_slice());
                let size = data.len();
                let _ = SNAPSHOT.set(Snapshot { bootstrap: bootstrap.to_string(), data });
                tracing::info!(bytes = size, ms = t0.elapsed().as_millis() as u64, path = %path.display(), "v8 snapshot loaded from cache");
                return Ok(size);
            }
        }
    }
    let blob = {
        let _guard = CREATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut iso = v8::Isolate::snapshot_creator(Some(refs), None);
        // A bootstrap error must not crash the process: the snapshot creator must
        // finish create_blob, or rusty_v8 panics on drop.
        let built: Result<(), String> = (|| {
            v8::scope!(scope, &mut iso);
            let default = v8::Context::new(scope, v8::ContextOptions::default());
            scope.set_default_context(default);
            let context = crate::natives::new_page_context(scope);
            {
                let cs = &mut v8::ContextScope::new(scope, context);
                let here: Vec<String> = serde_json::from_str(&run_script(cs, GLOBAL_NAMES)?).unwrap_or_default();
                let late: Vec<&String> = plain_names.iter().filter(|n| !here.contains(n)).collect();
                tracing::debug!(?late, "names V8 adds after restore");
                let late = serde_json::to_string(&late).unwrap_or_else(|_| "[]".into());
                run_script(cs, &format!("Object.defineProperty(globalThis, '__pt_lateNames', {{ value: new Set({late}), configurable: true }});"))?;
                crate::natives::install(cs);
                run_script(cs, bootstrap)?;
                cs.perform_microtask_checkpoint();
                run_script(cs, "delete globalThis.__pt_lateNames;")?;
                // Switch interface objects to dictionary mode before the snapshot: V8's
                // deserializer tripped on shared descriptor arrays ("Check failed:
                // LinearSearch...") after our member reordering. Adding two properties and
                // deleting the first converts without a trace.
                let _ = run_script(cs, NORMALIZE_FOR_SNAPSHOT);
            }
            scope.add_context(context);
            Ok(())
        })();
        crate::natives::drop_proto_templates(&mut iso);
        let blob = iso.create_blob(v8::FunctionCodeHandling::Clear);
        built?;
        blob.ok_or_else(|| "snapshot blob failed".to_string())?
    };
    let data: &'static [u8] = Box::leak(blob.to_vec().into_boxed_slice());
    let size = data.len();
    let _ = SNAPSHOT.set(Snapshot { bootstrap: bootstrap.to_string(), data });
    tracing::info!(bytes = size, ms = t0.elapsed().as_millis() as u64, "v8 snapshot built");
    if let Some(path) = cache {
        // Atomic: a process starting at the same moment reads either the whole file
        // or none.
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        if path.parent().map(std::fs::create_dir_all).is_some()
            && std::fs::write(&tmp, data).is_ok()
        {
            let _ = std::fs::rename(&tmp, &path);
            prune_snapshot_cache(&path, 3);
        }
    }
    Ok(size)
}

/// The snapshot key changes with every engine build; without cleanup the
/// directory grew by 10 MB per update. Keep the `keep` newest, including the one
/// just written.
fn prune_snapshot_cache(current: &std::path::Path, keep: usize) {
    let Some(dir) = current.parent() else { return };
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<(std::time::SystemTime, std::path::PathBuf)> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("snapshot-") && (n.ends_with(".bin") || n.contains(".tmp")))
        })
        .filter_map(|p| std::fs::metadata(&p).and_then(|m| m.modified()).ok().map(|t| (t, p)))
        .collect();
    files.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, p) in files.into_iter().skip(keep) {
        if p != current {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Snapshot path for this bootstrap: `$NOKK_CACHE_DIR`, else
/// `$XDG_CACHE_HOME/nokk`, else `~/.cache/nokk` (`%LOCALAPPDATA%\nokk` on Windows).
/// The name hashes the bootstrap,
/// V8 flags and the binary (size and mtime, so a rebuilt engine never reads a
/// stale snapshot). `NOKK_NO_SNAPSHOT_CACHE=1` disables the disk cache.
fn snapshot_cache_path(bootstrap: &str) -> Option<std::path::PathBuf> {
    use sha2::{Digest, Sha256};
    if std::env::var_os("NOKK_NO_SNAPSHOT_CACHE").is_some() {
        return None;
    }
    let dir = std::env::var_os("NOKK_CACHE_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CACHE_HOME").map(|d| std::path::PathBuf::from(d).join("nokk")))
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache").join("nokk")))
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(|d| std::path::PathBuf::from(d).join("nokk")))?;
    let exe = std::env::current_exe().ok()?;
    let meta = std::fs::metadata(&exe).ok()?;
    let mtime = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_nanos();
    let mut h = Sha256::new();
    h.update(bootstrap.as_bytes());
    h.update(std::env::var("NOKK_V8_FLAGS").unwrap_or_default().as_bytes());
    h.update(format!("{}|{}|{}", exe.display(), meta.len(), mtime).as_bytes());
    let hex: String = h.finalize().iter().take(12).map(|b| format!("{b:02x}")).collect();
    Some(dir.join(format!("snapshot-{hex}.bin")))
}

/// Context from the snapshot (if the bootstrap matches), with natives and bootstrap already applied.
fn context_from_snapshot<'s>(scope: &mut v8::PinScope<'s, '_, ()>, bootstrap: &str) -> Option<v8::Local<'s, v8::Context>> {
    if !snapshot_for(bootstrap) {
        return None;
    }
    v8::Context::from_snapshot(scope, 0, v8::ContextOptions::default())
}

/// Initialise the V8 platform exactly once per process. This MUST run on the
/// main thread before any worker thread is spawned — triggering the platform
/// init from a worker (racing other workers) segfaults. [`crate::IsolatePool::new`]
/// calls it on the calling thread before spawning workers; the per-worker call
/// in [`Isolate::new`] is then a no-op.
pub(crate) fn init_platform() {
    V8_INIT.call_once(|| {
        // `--no-maglev` used to be set here: V8 13.7's mid-tier compiler miscompiled
        // the global-graph enumeration loop of fingerprint collectors, silently
        // dropping a property after ~1000 iterations. V8 14.9 is fine (see
        // `a_warmed_enumeration_still_sees_every_property`), so no flags by default.
        // `NOKK_V8_FLAGS` replaces the whole set.
        let flags = std::env::var("NOKK_V8_FLAGS").unwrap_or_default();
        if !flags.is_empty() {
            v8::V8::set_flags_from_string(&flags);
        }
        // No zone from the host (no `TZ`, no /etc/localtime, as in a distroless
        // image): ICU would report `Etc/Unknown`, which no browser does. Keep the
        // zone the default profile always had. Main thread, before any worker.
        // An empty `TZ` gives `Etc/Unknown` too; it means "the host's", so drop it.
        #[cfg(unix)]
        {
            if std::env::var_os("TZ").is_some_and(|v| v.is_empty()) {
                std::env::remove_var("TZ");
            }
            if std::env::var_os("TZ").is_none() && !std::path::Path::new("/etc/localtime").exists() {
                std::env::set_var("TZ", "America/New_York");
            }
        }
        // ICU data: without it the pinned V8 build has no `Intl` and no locale
        // date/number formats, and the stub answers differently from Chrome. An
        // external file wins, so the data can follow a V8 upgrade without a rebuild.
        for path in icu_candidates() {
            let Ok(bytes) = std::fs::read(&path) else { continue };
            let leaked: &'static [u8] = Box::leak(bytes.into_boxed_slice());
            match v8::icu::set_common_data_78(leaked) {
                Ok(()) => {
                    ICU_READY.store(true, Ordering::Relaxed);
                    tracing::info!(path = %path.display(), "ICU data loaded");
                    break;
                }
                Err(code) => tracing::warn!(path = %path.display(), code, "ICU data refused"),
            }
        }
        if !ICU_READY.load(Ordering::Relaxed) {
            match v8::icu::set_common_data_78(&EMBEDDED_ICU.0) {
                Ok(()) => {
                    ICU_READY.store(true, Ordering::Relaxed);
                    tracing::debug!("ICU data loaded from the binary");
                }
                Err(code) => tracing::warn!(code, "embedded ICU data refused"),
            }
        }
        let platform = v8::new_default_platform(0, false).make_shared();
        // Pin one ref for the whole process so the platform is never freed while
        // isolates still reference it (a use-after-free otherwise).
        std::mem::forget(platform.clone());
        // Keep a handle for pumping: the platform has its own task queue, and
        // without pumping V8's async work never completes (most visibly,
        // `WebAssembly.compile` promises never resolve and collectors time out).
        PLATFORM.set(platform.clone()).ok();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Process-wide V8 platform, kept to pump its task queue between event-loop turns.
static PLATFORM: std::sync::OnceLock<v8::SharedRef<v8::Platform>> = std::sync::OnceLock::new();

/// Pump the platform task queue for this isolate: one batch of tasks and a
/// microtask checkpoint. Returns `true` if anything ran.
fn pump_platform(isolate: &mut v8::Isolate) -> bool {
    let Some(platform) = PLATFORM.get() else {
        return false;
    };
    let mut ran = false;
    // Bound the batch: the queue can refill itself and would freeze the worker.
    for _ in 0..64 {
        if !v8::Platform::pump_message_loop(platform, isolate, false) {
            break;
        }
        ran = true;
    }
    isolate.perform_microtask_checkpoint();
    ran
}

/// The browser's answer to a machine running out of memory: Chrome forwards
/// the OS's memory pressure to every renderer, and V8 collects and gives
/// pages back. With several isolates each growing its heap at leisure (V8
/// sizes it from physical memory), a busy server was killed by the OOM
/// killer instead. Checked after jobs, at most once a second per thread.
#[derive(Default)]
pub(crate) struct MemoryPressure {
    checked: Option<std::time::Instant>,
    collected: Option<std::time::Instant>,
}

impl MemoryPressure {
    /// Below this share of physical memory available, collect.
    const LOW: f64 = 0.20;

    pub(crate) fn after_job(&mut self, isolate: &mut Isolate) {
        let now = std::time::Instant::now();
        if self.checked.is_some_and(|t| now.duration_since(t) < std::time::Duration::from_secs(1)) {
            return;
        }
        self.checked = Some(now);
        if self.collected.is_some_and(|t| now.duration_since(t) < std::time::Duration::from_secs(2)) {
            return;
        }
        let Some(share) = available_share() else { return };
        if share < Self::LOW {
            isolate.isolate.memory_pressure_notification(v8::MemoryPressureLevel::Critical);
            self.collected = Some(std::time::Instant::now());
            tracing::debug!(target: "nokk::heap", share, "memory pressure: collected");
        }
    }
}

/// `MemAvailable / MemTotal`, where the OS reports it.
fn available_share() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/meminfo").ok()?;
        let field = |name: &str| -> Option<f64> {
            s.lines().find_map(|l| l.strip_prefix(name)).and_then(|r| r.split_whitespace().next()).and_then(|v| v.parse::<f64>().ok())
        };
        let (avail, total) = (field("MemAvailable:")?, field("MemTotal:")?);
        (total > 0.0).then(|| avail / total)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// One JS isolate plus its contexts.
///
/// Field order is load-bearing: `contexts` is declared before `isolate` so the
/// persistent [`v8::Global`] handles are dropped *before* the `OwnedIsolate`
/// they belong to. Dropping a `Global` after its isolate is gone segfaults.
pub struct Isolate {
    id: WorkerId,
    /// Persistent handles to each context on this isolate, indexed by the value
    /// returned from [`Isolate::create_context`]. A disposed context leaves a
    /// `None` tombstone so later indices never shift — a [`crate::WorkerId`]-pinned
    /// [`BrowserContext`] keeps its index for its whole life.
    contexts: Vec<Option<v8::Global<v8::Context>>>,
    isolate: v8::OwnedIsolate,
    /// Backing store for the near-heap-limit callback, when a heap cap is set.
    /// Declared last so it is dropped *after* `isolate` — V8 holds a raw pointer
    /// into this box for the callback, so it must outlive the isolate.
    heap_state: Option<Box<HeapLimitState>>,
}

/// Shared state for the near-heap-limit callback. A raw pointer to this (kept
/// alive in [`Isolate::heap_state`]) is handed to V8.
struct HeapLimitState {
    /// Cross-thread handle used to force-terminate the running script from inside
    /// the callback (the callback runs on the isolate's own thread during GC).
    handle: v8::IsolateHandle,
    /// Set by the callback when the cap is reached, read+cleared after each run.
    hit: AtomicBool,
    /// The configured cap in bytes, used to restore the limit after a hit so it
    /// doesn't ratchet upward from the headroom the callback grants.
    limit_bytes: usize,
}

/// Called by V8 when the isolate's heap is about to exceed its limit. Rather than
/// let V8 hard-abort the process (its default on OOM), we flag the event and
/// terminate the running script — it unwinds and surfaces as a catchable error,
/// while the isolate and its other contexts survive. We return a slightly higher
/// limit so V8 has room to unwind before it would abort; the caller restores the
/// real cap afterwards (see [`Isolate::took_oom`]).
extern "C" fn near_heap_limit_callback(
    data: *mut c_void,
    current_heap_limit: usize,
    _initial_heap_limit: usize,
) -> usize {
    // SAFETY: `data` is the pointer to the `HeapLimitState` box owned by the
    // isolate for at least as long as this callback is registered.
    let state = unsafe { &*(data as *const HeapLimitState) };
    state.hit.store(true, Ordering::SeqCst);
    state.handle.terminate_execution();
    current_heap_limit + 32 * 1024 * 1024
}

impl Isolate {
    /// Native stack for each worker thread. V8 derives its own stack-limit (the
    /// one that yields a catchable `RangeError`) from the stack base at first
    /// entry, reserving ~1MB. A large native stack guarantees that limit is
    /// reached — and the exception thrown — long before the real stack end, so
    /// deep page recursion never overflows for real and aborts the process.
    pub(crate) const STACK_SIZE: usize = 64 * 1024 * 1024;
    /// Default wall-clock limit for a single [`Isolate::eval`]. A runaway script
    /// (infinite loop) is force-terminated after this so it cannot wedge a worker
    /// forever. Overridable via `NOKK_EVAL_TIMEOUT_MS`.
    const EVAL_TIMEOUT: Duration = Duration::from_secs(10);

    fn eval_timeout() -> Duration {
        std::env::var("NOKK_EVAL_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Self::EVAL_TIMEOUT)
    }

    /// Physical memory size. Chrome derives the heap limit from it (not from free
    /// memory), and `navigator.deviceMemory` too.
    pub fn physical_memory_bytes() -> u64 {
        #[cfg(target_os = "linux")]
        if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    if let Some(kb) = rest.split_whitespace().next().and_then(|n| n.parse::<u64>().ok())
                    {
                        return kb * 1024;
                    }
                }
            }
        }
        // Unknown: report a typical machine.
        8 * 1024 * 1024 * 1024
    }

    /// Create an isolate. `max_heap_mb` caps this isolate's JS heap (shared across
    /// all its contexts); `None` leaves V8's default (effectively unbounded).
    pub(crate) fn new(id: WorkerId, max_heap_mb: Option<usize>) -> Self {
        init_platform();
        let mut params = v8::CreateParams::default();
        if let Some(snap) = SNAPSHOT.get() {
            params = params
                .snapshot_blob(v8::StartupData::from(snap.data))
                .external_references(crate::natives::external_refs());
        }
        if let Some(mb) = max_heap_mb {
            // initial = 0 lets V8 pick its default starting heap; max is the cap.
            params = params.heap_limits(0, mb * 1024 * 1024);
        } else {
            // Without an explicit limit V8 derives it from free memory, which on a busy
            // machine is three times below Chrome's. Chrome uses physical memory (same V8
            // function), and pages see it via `performance.memory`: on 16 GB Chrome
            // reports 4 395 630 592 where we reported 1 568 669 696.
            params = params.heap_limits_from_system_memory(Self::physical_memory_bytes(), 0);
        }
        let mut isolate = {
            // Never construct two isolates concurrently (see CREATE_LOCK).
            let _guard = CREATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            v8::Isolate::new(params)
        };
        // Modules live for the isolate's whole life: their registry, and the hook
        // that gives each one its `import.meta.url`.
        isolate.set_slot(ModuleRegistry::default());
        isolate.set_slot(DynamicImports::default());
        isolate.set_host_initialize_import_meta_object_callback(import_meta);
        isolate.set_host_import_module_dynamically_callback(import_dynamically);
        // `error.stack` formatting. With this hook V8 no longer calls
        // `Error.prepareStackTrace` itself; `__pt_formatStack` does, without engine frames.
        isolate.set_prepare_stack_trace_callback(prepare_stack_trace);
        // CSP: where `__pt_setCodegen(false)` disallowed codegen from strings,
        // `eval`/`Function` get their source replaced with a throw of Chrome's
        // EvalError. The ban is per context, so substitute the source rather than
        // refuse; otherwise V8 throws its own "Code generation from strings disallowed".
        isolate.set_modify_code_generation_from_strings_callback(modify_codegen);

        // Install the graceful-OOM callback once, if a cap is in effect.
        let heap_state = max_heap_mb.map(|mb| {
            let state = Box::new(HeapLimitState {
                handle: isolate.thread_safe_handle(),
                hit: AtomicBool::new(false),
                limit_bytes: mb * 1024 * 1024,
            });
            let data = &*state as *const HeapLimitState as *mut c_void;
            isolate.add_near_heap_limit_callback(near_heap_limit_callback, data);
            state
        });
        Self {
            id,
            contexts: Vec::new(),
            isolate,
            heap_state,
        }
    }

    /// If the heap cap was hit during the last run, clear the flag, restore the
    /// real cap (undoing the headroom the callback granted so it doesn't ratchet
    /// up), and report `true`. Callers turn this into a clean "out of memory"
    /// error instead of the opaque termination V8 surfaces.
    fn took_oom(&mut self) -> bool {
        let (hit, limit) = match self.heap_state.as_ref() {
            Some(s) => (s.hit.swap(false, Ordering::SeqCst), s.limit_bytes),
            None => return false,
        };
        if !hit {
            return false;
        }
        let data = &**self.heap_state.as_ref().unwrap() as *const HeapLimitState as *mut c_void;
        self.isolate
            .remove_near_heap_limit_callback(near_heap_limit_callback, limit);
        self.isolate
            .add_near_heap_limit_callback(near_heap_limit_callback, data);
        true
    }

    /// The worker thread that owns this isolate.
    pub fn worker_id(&self) -> WorkerId {
        self.id
    }

    /// Number of live (non-disposed) contexts on this isolate.
    pub fn context_count(&self) -> usize {
        self.contexts.iter().filter(|c| c.is_some()).count()
    }

    /// Top up the spare realms to `n`, building at most `step` at a time, so an
    /// idle-time refill does not hold the thread long.
    pub fn top_up_realms(&mut self, n: usize, step: usize) {
        // Refill only after pages asked for realms recently, as many as they
        // asked for plus one; once demand (and any prewarm) has gone quiet, the
        // spares are memory nobody uses, so let them go.
        let ttl = crate::natives::REALM_DEMAND_TTL;
        let demand = self
            .isolate
            .get_slot::<crate::natives::RealmDemand>()
            .filter(|d| d.last.elapsed() <= ttl)
            .map(|d| d.recent);
        let Some(recent) = demand else {
            let prewarm_fresh = self
                .isolate
                .get_slot::<crate::natives::RealmPrewarm>()
                .is_some_and(|p| p.0.elapsed() <= ttl);
            if !prewarm_fresh {
                if let Some(s) = self.isolate.get_slot_mut::<crate::natives::SpareRealms>() {
                    s.0.clear();
                }
            }
            return;
        };
        let n = n.min(recent + 1);
        let Some(have) = self
            .isolate
            .get_slot::<crate::natives::SpareRealms>()
            .map(|s| s.0.len())
        else {
            return;
        };
        let Some(boot) = self
            .isolate
            .get_slot::<crate::natives::RealmBootstrap>()
            .map(|b| b.0.clone())
        else {
            return;
        };
        if have < n {
            self.prewarm_realms(&boot, (have + step).min(n));
        }
    }

    /// Fill the spare realms up to `n` (see [`crate::natives::SpareRealms`]).
    /// Called at context creation, before the page measures anything.
    pub fn prewarm_realms(&mut self, bootstrap: &str, n: usize) {
        // Built ahead of a request that may not come: they expire if none does
        // (see `top_up_realms`).
        self.isolate.set_slot(crate::natives::RealmPrewarm(std::time::Instant::now()));
        if self.isolate.get_slot::<crate::natives::RealmBootstrap>().is_none() {
            self.isolate
                .set_slot(crate::natives::RealmBootstrap(bootstrap.to_string()));
        }
        let boot = bootstrap.to_string();
        loop {
            let have = self
                .isolate
                .get_slot::<crate::natives::SpareRealms>()
                .map(|s| s.0.len())
                .unwrap_or(0);
            if have >= n {
                break;
            }
            let t0 = std::time::Instant::now();
            let ready = {
                v8::scope!(scope, &mut self.isolate);
                if let Some(context) = context_from_snapshot(scope, &boot) {
                    let global = v8::Global::new(scope, context);
                    let scope = &mut v8::ContextScope::new(scope, context);
                    let _ = run_script(scope, AFTER_SNAPSHOT);
                    global
                } else {
                    let context = crate::natives::new_page_context(scope);
                    let global = v8::Global::new(scope, context);
                    let scope = &mut v8::ContextScope::new(scope, context);
                    crate::natives::install(scope);
                    if run_script(scope, &boot).is_err() {
                        return;
                    }
                    global
                }
            };
            tracing::debug!(target: "nokk::build", kind = "spare realm", ms = t0.elapsed().as_millis() as u64, thread = ?std::thread::current().name(), "context built");
            if self.isolate.get_slot::<crate::natives::SpareRealms>().is_none() {
                self.isolate.set_slot(crate::natives::SpareRealms::default());
            }
            if let Some(s) = self.isolate.get_slot_mut::<crate::natives::SpareRealms>() {
                s.0.push(ready);
            }
        }
    }

    /// Spare ready contexts (bootstrap run, no index assigned) for workers: a
    /// page creates a worker and posts to it right away, while the bootstrap takes
    /// ~300 ms. Built while the thread is idle.
    pub fn prewarm_contexts(&mut self, bootstrap: &str, n: usize) {
        loop {
            let have = self
                .isolate
                .get_slot::<crate::natives::SpareContexts>()
                .map(|s| s.0.len())
                .unwrap_or(0);
            if have >= n {
                break;
            }
            let t0 = std::time::Instant::now();
            let ready = {
                v8::scope!(scope, &mut self.isolate);
                if let Some(context) = context_from_snapshot(scope, bootstrap) {
                    let global = v8::Global::new(scope, context);
                    let scope = &mut v8::ContextScope::new(scope, context);
                    let _ = run_script(scope, AFTER_SNAPSHOT);
                    global
                } else {
                    let context = crate::natives::new_page_context(scope);
                    let global = v8::Global::new(scope, context);
                    let scope = &mut v8::ContextScope::new(scope, context);
                    crate::natives::install(scope);
                    if run_script(scope, bootstrap).is_err() {
                        return;
                    }
                    global
                }
            };
            tracing::debug!(target: "nokk::build", kind = "spare context", ms = t0.elapsed().as_millis() as u64, thread = ?std::thread::current().name(), "context built");
            if self.isolate.get_slot::<crate::natives::SpareContexts>().is_none() {
                self.isolate.set_slot(crate::natives::SpareContexts::default());
            }
            if let Some(s) = self.isolate.get_slot_mut::<crate::natives::SpareContexts>() {
                s.0.push(ready);
            }
        }
    }

    /// Like [`Self::create_context`], but from the spare pool when available;
    /// the context clock starts at hand-out.
    pub fn create_context_or_spare(&mut self, bootstrap: &str) -> Result<usize, String> {
        let spare = self
            .isolate
            .get_slot_mut::<crate::natives::SpareContexts>()
            .and_then(|s| s.0.pop());
        tracing::debug!(target: "nokk::realm", from_spare = spare.is_some(), "a page asked for a worker context");
        let Some(global) = spare else {
            return self.create_context(bootstrap);
        };
        if self.isolate.get_slot::<crate::natives::RealmBootstrap>().is_none() {
            self.isolate
                .set_slot(crate::natives::RealmBootstrap(bootstrap.to_string()));
        }
        let index = self.contexts.len();
        {
            v8::scope!(scope, &mut self.isolate);
            let context = v8::Local::new(scope, &global);
            let scope = &mut v8::ContextScope::new(scope, context);
            let _ = run_script(
                scope,
                &format!(
                    "Object.defineProperty(globalThis, '__pt_ctxIndex', \
                     {{ value: {index}, writable: true, configurable: true }}); \
                     globalThis.__pt_resetClock && __pt_resetClock();"
                ),
            );
        }
        self.contexts.push(Some(global));
        Ok(index)
    }

    /// Create a fresh context, run `bootstrap` in it (the stealth environment:
    /// `navigator`/`window`/`screen`...), and return its index. If the bootstrap
    /// script throws, the context is discarded and the error is returned.
    pub fn create_context(&mut self, bootstrap: &str) -> Result<usize, String> {
        let t_build = std::time::Instant::now();
        let r = self.create_context_inner(bootstrap);
        tracing::debug!(target: "nokk::build", kind = "context", ms = t_build.elapsed().as_millis() as u64, thread = ?std::thread::current().name(), "context built");
        r
    }

    fn create_context_inner(&mut self, bootstrap: &str) -> Result<usize, String> {
        let index = self.contexts.len();
        // Keep the bootstrap on the isolate so a *realm* can be built from it
        // later without the page ever seeing the source. A same-origin `<iframe>`
        // with no `src` is a real window in a browser, and anti-bot code reaches
        // into one for pristine natives (`contentWindow.eval`); building that
        // realm has to happen synchronously, inside the property access, which is
        // why it is a native binding rather than a round trip through the driver.
        if self.isolate.get_slot::<crate::natives::RealmBootstrap>().is_none() {
            self.isolate
                .set_slot(crate::natives::RealmBootstrap(bootstrap.to_string()));
        }
        let global = {
            v8::scope!(scope, &mut self.isolate);
            let snapped = context_from_snapshot(scope, bootstrap);
            let from_snapshot = snapped.is_some();
            let context = snapped.unwrap_or_else(|| crate::natives::new_page_context(scope));
            let global = v8::Global::new(scope, context);
            let scope = &mut v8::ContextScope::new(scope, context);
            if from_snapshot {
                let _ = run_script(scope, AFTER_SNAPSHOT);
            } else {
                // Native bindings must exist before the bootstrap runs — the JS
                // WebCrypto layer is built on top of them.
                crate::natives::install(scope);
                // NOKK_AUDIT_NATIVES=1: which natives the bootstrap itself calls.
                let audit = std::env::var_os("NOKK_AUDIT_NATIVES").is_some();
                if audit {
                    let _ = run_script(scope, "(() => { const c = {}; Object.defineProperty(globalThis, '__pt_auditCounts', { value: c, configurable: true }); for (const k of Object.getOwnPropertyNames(globalThis)) { if (!k.startsWith('__pt_')) continue; const f = globalThis[k]; if (typeof f !== 'function') continue; globalThis[k] = function () { c[k] = (c[k] || 0) + 1; return f.apply(this, arguments); }; } })();");
                }
                run_script(scope, bootstrap)?;
                if audit {
                    if let Ok(v) = run_script(scope, "JSON.stringify(globalThis.__pt_auditCounts)") {
                        eprintln!("[audit natives] {v}");
                    }
                }
            }
            // The dynamic-import hook sees only the scope, so the context stores its
            // index under a `__pt` name, which enumeration hides. Defined non-enumerable:
            // a plain assignment showed up in the page's `for...in` over window.
            let _ = run_script(
                scope,
                &format!(
                    "Object.defineProperty(globalThis, '__pt_ctxIndex', \
                     {{ value: {index}, writable: true, configurable: true }});"
                ),
            );
            global
        };
        self.contexts.push(Some(global));
        // Memory debugging: NOKK_HEAP_SNAPSHOT_AT=<n> writes the isolate heap to
        // `nokk-heap-<n>.heapsnapshot` when it reaches n contexts.
        if let Ok(at) = std::env::var("NOKK_HEAP_SNAPSHOT_AT") {
            if at.parse::<usize>().ok() == Some(self.contexts.len()) {
                let mut out = Vec::new();
                self.isolate.take_heap_snapshot(|chunk| { out.extend_from_slice(chunk); true });
                let _ = std::fs::write(format!("nokk-heap-{at}.heapsnapshot"), out);
            }
        }
        self.log_heap("create");
        Ok(self.contexts.len() - 1)
    }

    /// Fetch a live context handle by index, or an error if the index is unknown
    /// or the context has been disposed.
    fn context(&self, index: usize) -> Result<v8::Global<v8::Context>, String> {
        self.contexts
            .get(index)
            .and_then(|c| c.clone())
            .ok_or_else(|| format!("no context with index {index}"))
    }

    /// Evaluate `source` in context `index` and return the result stringified.
    /// A thrown exception (or a force-termination after [`Self::EVAL_TIMEOUT`]) is
    /// returned as `Err` with its message; the isolate stays reusable afterward.
    /// Tie a context to its profile's storage (IndexedDB). Done by the
    /// engine right after building it, before any page script: the binding
    /// lives in the context, not in a global a page could rewrite, and goes
    /// away with it.
    pub fn bind_storage(&mut self, index: usize, partition: u64) {
        let Ok(global) = self.context(index) else { return };
        v8::scope_with_context!(scope, &mut self.isolate, &global);
        crate::idb::bind_context(scope, partition);
    }

    pub fn eval(&mut self, index: usize, source: &str) -> Result<String, String> {
        self.eval_named(index, source, None)
    }

    /// Join a same-origin frame to its page, as one browser would: the two
    /// contexts share a security token, so each may touch the other's objects,
    /// and each gets the other's window — the frame its `parent` and its
    /// `<iframe>` as `frameElement`, the page the frame's `contentWindow`.
    /// Both must live in this isolate.
    pub fn link_frame(&mut self, page: usize, frame: usize, frame_id: u32) -> Result<(), String> {
        let pg = self.context(page)?;
        let fr = self.context(frame)?;
        let (page_win, owner) = {
            v8::scope_with_context!(scope, &mut self.isolate, &pg);
            let token = scope.get_current_context().get_security_token(scope);
            v8::Local::new(scope, &fr).set_security_token(token);
            let win: v8::Local<v8::Value> = scope.get_current_context().global(scope).into();
            let id: v8::Local<v8::Value> = v8::Integer::new_from_unsigned(scope, frame_id).into();
            let el = call_global(scope, "__pt_frameOwnerEl", &[id]).ok_or("no <iframe> for the frame")?;
            (v8::Global::new(scope, win), v8::Global::new(scope, el))
        };
        let frame_win = {
            v8::scope_with_context!(scope, &mut self.isolate, &fr);
            let win = v8::Local::new(scope, &page_win);
            let el = v8::Local::new(scope, &owner);
            call_global(scope, "__pt_linkParent", &[win, el]).ok_or("frame refused the link")?;
            let mine: v8::Local<v8::Value> = scope.get_current_context().global(scope).into();
            v8::Global::new(scope, mine)
        };
        v8::scope_with_context!(scope, &mut self.isolate, &pg);
        let id: v8::Local<v8::Value> = v8::Integer::new_from_unsigned(scope, frame_id).into();
        let fw = v8::Local::new(scope, &frame_win);
        call_global(scope, "__pt_linkChild", &[id, fw]).ok_or("page refused the link")?;
        Ok(())
    }

    /// Same, but the script is named by its URL, as Chrome does. The name goes
    /// into `ScriptOrigin` rather than `//# sourceURL`: the former is visible to a
    /// nested `eval`'s parent frame, the latter is not.
    pub fn eval_named(
        &mut self,
        index: usize,
        source: &str,
        name: Option<&str>,
    ) -> Result<String, String> {
        let global = self.context(index)?;
        let watchdog = TerminateWatchdog::arm(&mut self.isolate);

        let result = {
            v8::scope_with_context!(scope, &mut self.isolate, &global);
            run_script_named(scope, source, name)
        };

        // Disarm and clear any pending termination so the next eval on this
        // isolate starts clean.
        if watchdog.disarm() && std::env::var_os("NOKK_TRACE_WATCHDOG").is_some() {
            let head: String = source.chars().take(300).collect();
            tracing::warn!(name = ?name, source = %head, "watchdog stopped an evaluation");
        }
        self.isolate.cancel_terminate_execution();
        // A termination caused by the heap cap reads as a generic error; surface
        // it as a clear out-of-memory message instead.
        if self.took_oom() {
            return Err("JavaScript heap out of memory (isolate cap reached)".to_string());
        }
        result
    }

    /// Compile `source` as an ES module and report what it imports, without
    /// instantiating it. The engine fetches those, hands them back the same way,
    /// and repeats until the graph is closed — only then can it be instantiated,
    /// because V8 resolves imports synchronously and the network is not.
    pub fn module_requests(
        &mut self,
        index: usize,
        url: &str,
        source: &str,
    ) -> Result<Vec<String>, String> {
        let global = self.context(index)?;
        let key = format!("{index}:{url}");
        v8::scope_with_context!(scope, &mut self.isolate, &global);
        v8::tc_scope!(scope, scope);

        let module = match compile_module(scope, url, source) {
            Some(m) => m,
            None => return Err(exception_message(scope)),
        };
        let requests = module.get_module_requests();
        let mut out = Vec::new();
        for i in 0..requests.length() {
            let Some(req) = requests.get(scope, i) else { continue };
            let Ok(req) = v8::Local::<v8::ModuleRequest>::try_from(req) else { continue };
            out.push(req.get_specifier().to_rust_string_lossy(scope));
        }
        let hash = module.get_identity_hash().get();
        let handle = v8::Global::new(scope, module);
        let registry = scope
            .get_slot_mut::<ModuleRegistry>()
            .expect("module registry installed with the isolate");
        registry.by_hash.insert(hash, key.clone());
        registry.modules.insert(key, handle);
        Ok(out)
    }

    /// Has this context already compiled the module at `url`?
    ///
    /// A browser keeps one module map per realm: an address is fetched once,
    /// however many chunks import it. Ours refetched the shared dependencies of
    /// every dynamic import, so a code-split page loaded twice the modules a
    /// browser does.
    pub fn has_module(&self, index: usize, url: &str) -> bool {
        self.isolate
            .get_slot::<ModuleRegistry>()
            .map(|r| r.modules.contains_key(&format!("{index}:{url}")))
            .unwrap_or(false)
    }

    /// Record where one module's import specifier leads, so the synchronous
    /// resolve callback can answer without touching the network.
    pub fn link_module(&mut self, index: usize, url: &str, specifier: &str, target: &str) {
        if let Some(reg) = self.isolate.get_slot_mut::<ModuleRegistry>() {
            reg.edges.insert(
                (format!("{index}:{url}"), specifier.to_string()),
                format!("{index}:{target}"),
            );
        }
    }

    /// What `import()` calls are waiting to be loaded, taken off the queue.
    /// Same, but only for the listed contexts; the rest stay queued. One thread
    /// hosts contexts of different pages, and a frame moved to another thread must
    /// not take their `import()`s.
    pub fn drain_dynamic_imports_for(&mut self, indices: &[usize]) -> Vec<(u32, usize, String, String)> {
        let Some(d) = self.isolate.get_slot_mut::<DynamicImports>() else {
            return Vec::new();
        };
        let (mine, rest): (Vec<_>, Vec<_>) =
            std::mem::take(&mut d.queue).into_iter().partition(|e| indices.contains(&e.1));
        d.queue = rest;
        mine
    }

    pub fn drain_dynamic_imports(&mut self) -> Vec<(u32, usize, String, String)> {
        self.isolate
            .get_slot_mut::<DynamicImports>()
            .map(|d| std::mem::take(&mut d.queue))
            .unwrap_or_default()
    }

    /// Settle a waiting `import()` with the namespace of the module now compiled
    /// and evaluated under `url`, or with an error if it could not be loaded.
    pub fn settle_dynamic_import(
        &mut self,
        id: u32,
        index: usize,
        outcome: Result<&str, String>,
    ) -> Result<(), String> {
        let global = self.context(index)?;
        v8::scope_with_context!(scope, &mut self.isolate, &global);

        let Some(handle) = scope
            .get_slot_mut::<DynamicImports>()
            .and_then(|d| d.pending.remove(&id))
        else {
            return Err(format!("no import waiting under {id}"));
        };
        let resolver = v8::Local::new(scope, &handle);
        match outcome {
            Ok(url) => {
                let key = format!("{index}:{url}");
                let module = scope
                    .get_slot::<ModuleRegistry>()
                    .and_then(|r| r.modules.get(&key).cloned());
                match module {
                    Some(m) => {
                        let m = v8::Local::new(scope, &m);
                        let namespace = m.get_module_namespace();
                        resolver.resolve(scope, namespace);
                    }
                    None => {
                        let msg = v8::String::new(scope, &format!("module {url} was never compiled"))
                            .ok_or("string")?;
                        let err = v8::Exception::type_error(scope, msg);
                        resolver.reject(scope, err);
                    }
                }
            }
            Err(why) => {
                let msg = v8::String::new(scope, &why).ok_or("string")?;
                let err = v8::Exception::type_error(scope, msg);
                resolver.reject(scope, err);
            }
        }
        Ok(())
    }

    /// Instantiate and evaluate an already-compiled module graph. Top-level
    /// `await` makes evaluation a promise; a rejection is reported like a throw.
    pub fn eval_module(&mut self, index: usize, url: &str) -> Result<(), String> {
        let global = self.context(index)?;
        let key = format!("{index}:{url}");
        let watchdog = TerminateWatchdog::arm(&mut self.isolate);

        let result = (|| {
            v8::scope_with_context!(scope, &mut self.isolate, &global);
            v8::tc_scope!(scope, scope);

            let handle = scope
                .get_slot::<ModuleRegistry>()
                .and_then(|r| r.modules.get(&key).cloned())
                .ok_or_else(|| format!("module {url} was never compiled"))?;
            let module = v8::Local::new(scope, &handle);
            if module.instantiate_module(scope, resolve_module).is_none() {
                return Err(exception_message(scope));
            }
            let Some(value) = module.evaluate(scope) else {
                return Err(exception_message(scope));
            };
            // Top-level await: a still-pending promise is left running, but a
            // rejection is an error the page would have reported.
            if let Ok(promise) = v8::Local::<v8::Promise>::try_from(value) {
                if promise.state() == v8::PromiseState::Rejected {
                    let reason = promise.result(scope);
                    return Err(reason
                        .to_string(scope)
                        .map(|s| s.to_rust_string_lossy(scope))
                        .unwrap_or_else(|| "module rejected".to_string()));
                }
            }
            Ok(())
        })();

        watchdog.disarm();
        self.isolate.cancel_terminate_execution();
        result
    }

    /// Drive the event loop for context `index`: repeatedly run the earliest
    /// pending timer (via the JS `__pt_runNextTimer` driver) and let V8 drain the
    /// microtask queue between turns, until no timers remain, `max_callbacks` is
    /// hit, or `budget` elapses. Returns the number of timer callbacks run.
    ///
    /// Timers use virtual time, so this does not sleep for `setTimeout` delays;
    /// the wall-clock `budget` only bounds pathological `setInterval` loops (the
    /// callback cap is the primary guard). Runs on the worker thread, so it holds
    /// the isolate for its duration.
    pub fn run_event_loop(
        &mut self,
        index: usize,
        max_callbacks: u32,
        budget: std::time::Duration,
    ) -> Result<u32, String> {
        let global = self.context(index)?;
        let deadline = std::time::Instant::now() + budget;

        // A single timer callback can itself loop forever (`setTimeout(() => {
        // while(true){} })`), and the between-turns deadline check below never
        // gets a chance to fire in that case. Arm the same terminate-watchdog as
        // `eval` so one runaway callback can't wedge the worker permanently.
        let watchdog = TerminateWatchdog::arm(&mut self.isolate);
        // Platform queue first: it finishes work V8 started itself (async
        // WebAssembly compilation etc.). Its promises resolve only here, and page
        // timers wait on them.
        let pumped = pump_platform(&mut self.isolate);
        let mut result = self.pump_timers(&global, max_callbacks, deadline);
        // Again after timers: a callback may have started new background work.
        if pump_platform(&mut self.isolate) || pumped {
            if let Ok(n) = result.as_mut() {
                *n += 1;
            }
        }
        let stopped = watchdog.disarm();
        self.isolate.cancel_terminate_execution();
        if self.took_oom() {
            return Err("JavaScript heap out of memory (isolate cap reached)".to_string());
        }
        // A callback that ran past the limit is stopped, not the page: Chrome
        // lets a slow script finish, and failing the turn failed the whole load.
        if stopped && result.is_err() {
            tracing::warn!(limit_ms = Self::eval_timeout().as_millis() as u64, "a page timer ran too long and was stopped");
            return Ok(1);
        }
        result
    }

    /// Same, but the context keeps its own time: when nothing is due and the next
    /// timer is closer than `near`, the thread waits for it here and continues
    /// instead of returning to the caller.
    ///
    /// This matches a browser worker, which has its own thread: a chain of short
    /// timers (where Cloudflare's fingerprint collector runs) proceeds back to back,
    /// not one step per turn of a shared loop. Waiting is safe only because a
    /// worker context's isolate serves nobody else; for a page it would stall
    /// everything.
    pub fn run_worker_loop(
        &mut self,
        index: usize,
        max_callbacks: u32,
        budget: std::time::Duration,
        near: std::time::Duration,
    ) -> Result<u32, String> {
        let deadline = std::time::Instant::now() + budget;
        let mut total = 0u32;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() || total >= max_callbacks {
                return Ok(total);
            }
            total += self.run_event_loop(index, max_callbacks - total, left)?;
            let next = self.next_timer_delay(index);
            let Some(wait) = next.filter(|d| *d <= near.min(left)) else {
                return Ok(total);
            };
            std::thread::sleep(wait);
        }
    }

    /// Time until the context's next timer; `None` if nothing is pending.
    fn next_timer_delay(&mut self, index: usize) -> Option<std::time::Duration> {
        let ms = self
            .eval(
                index,
                "typeof __pt_nextTimerDelay === 'function' ? __pt_nextTimerDelay() : -1",
            )
            .ok()?
            .trim()
            .parse::<f64>()
            .ok()?;
        (ms >= 0.0).then(|| std::time::Duration::from_millis(ms.max(0.0) as u64))
    }

    /// Inner timer pump for [`Self::run_event_loop`], factored out so the
    /// watchdog can wrap it. Runs the earliest pending timer repeatedly until the
    /// queue drains, `max_callbacks` is hit, or `deadline` passes.
    fn pump_timers(
        &mut self,
        global: &v8::Global<v8::Context>,
        max_callbacks: u32,
        deadline: std::time::Instant,
    ) -> Result<u32, String> {
        v8::scope_with_context!(scope, &mut self.isolate, global);
        v8::tc_scope!(scope, scope);

        // Compile the driver once; each run executes one timer, and the default
        // (Auto) microtask policy drains promise continuations when it returns.
        let code = v8::String::new(scope, "__pt_runNextTimer()")
            .ok_or_else(|| "driver source too large".to_string())?;
        let script =
            v8::Script::compile(scope, code, None).ok_or_else(|| exception_message(scope))?;

        let mut count = 0u32;
        while count < max_callbacks && std::time::Instant::now() < deadline {
            let Some(v) = script.run(scope) else {
                return Err(exception_message(scope));
            };
            if !v.boolean_value(scope) {
                break; // queue empty (driver returned 0)
            }
            count += 1;
        }
        Ok(count)
    }

    /// Tear down context `index`, dropping its persistent handle so V8 can
    /// reclaim the memory on the next GC. Leaves a `None` tombstone so the
    /// indices of other contexts are preserved (the slot is emptied, not
    /// removed) — otherwise every later context's pinned index would shift.
    /// Memory debugging (`RUST_LOG=nokk::heap=debug`): isolate heap and its live context count.
    fn log_heap(&mut self, what: &'static str) {
        if tracing::enabled!(target: "nokk::heap", tracing::Level::DEBUG) {
            let st = self.isolate.get_heap_statistics();
            let live = self.contexts.iter().filter(|c| c.is_some()).count();
            tracing::debug!(target: "nokk::heap", what, live,
                used_mb = st.used_heap_size() / 1_048_576, total_mb = st.total_heap_size() / 1_048_576,
                thread = ?std::thread::current().name(), "heap");
        }
    }

    pub fn dispose_context(&mut self, index: usize) {
        self.log_heap("dispose");
        if let Some(slot) = self.contexts.get_mut(index) {
            if slot.take().is_some() && gc_hint_due() {
                // A context is megabytes of heap that only GC frees; the hint speeds that
                // up at CPU cost. Enabled by `NOKK_GC_HINT_MS` (see `gc_hint_due`).
                self.isolate
                    .memory_pressure_notification(v8::MemoryPressureLevel::Moderate);
            }
        }
    }

    /// Dispose the isolate and all its contexts under the global V8 lock.
    /// Concurrent isolate disposal (many workers ending at once when the pool
    /// drops) segfaults just like concurrent construction, so teardown is
    /// serialised the same way. Workers must call this instead of letting the
    /// isolate drop implicitly.
    pub(crate) fn shutdown(self) {
        let guard = CREATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        drop(self); // contexts (Globals) then OwnedIsolate, all under the lock
        drop(guard);
    }
}

/// A one-shot watchdog that force-terminates a running script if it outlives the
/// eval timeout (infinite loop, pathological input). `terminate_execution` is the
/// only cross-thread-safe V8 op, so this runs on a scratch thread holding a
/// `thread_safe_handle`.
///
/// If the watchdog thread cannot be spawned (e.g. `EAGAIN` under heavy load), we
/// log and run *without* the timeout guard rather than panicking the worker — a
/// dropped guard is far better than unwinding the isolate loop and orphaning
/// every context pinned to it.
struct TerminateWatchdog {
    done_tx: Option<mpsc::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
    fired: Arc<AtomicBool>,
}

impl TerminateWatchdog {
    fn arm(isolate: &mut v8::OwnedIsolate) -> Self {
        let tsh = isolate.thread_safe_handle();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let fired = Arc::new(AtomicBool::new(false));
        let flag = fired.clone();
        let handle = std::thread::Builder::new()
            .name("eval-watchdog".into())
            .spawn(move || {
                // Only a timeout is actionable; a clean finish (Ok/Disconnected)
                // means the script returned in time.
                if let Err(RecvTimeoutError::Timeout) =
                    done_rx.recv_timeout(Isolate::eval_timeout())
                {
                    flag.store(true, Ordering::SeqCst);
                    tsh.terminate_execution();
                }
            });
        match handle {
            Ok(handle) => Self {
                done_tx: Some(done_tx),
                handle: Some(handle),
                fired,
            },
            Err(e) => {
                tracing::warn!(error = %e, "could not spawn eval watchdog; running without timeout guard");
                Self {
                    done_tx: None,
                    handle: None,
                    fired,
                }
            }
        }
    }

    /// Wake the watchdog and join it, so no pending termination can leak into the
    /// next script run on this isolate.
    /// Returns whether the watchdog stopped the script.
    fn disarm(mut self) -> bool {
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.fired.load(Ordering::SeqCst)
    }
}

/// Compile `source` as a module, tagged with its URL so stacks and
/// `import.meta.url` name the right file.
fn compile_module<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    url: &str,
    source: &str,
) -> Option<v8::Local<'s, v8::Module>> {
    let code = v8::String::new(scope, source)?;
    let name = v8::String::new(scope, url)?;
    let origin = v8::ScriptOrigin::new(
        scope,
        name.into(),
        0,
        0,
        false,
        0,
        None,
        false,
        false,
        true, // is_module
        None,
    );
    let mut src = v8::script_compiler::Source::new(code, Some(&origin));
    v8::script_compiler::compile_module(scope, &mut src)
}

fn trusted_script_text<'s>(scope: &mut v8::PinScope<'s, '_>, source: v8::Local<'s, v8::Value>) -> Option<v8::Local<'s, v8::String>> {
    if source.is_string() || !source.is_object() {
        return None;
    }
    let obj = source.to_object(scope)?;
    let name = v8::String::new(scope, crate::natives::TRUSTED_SCRIPT_KEY)?;
    let key = v8::Private::for_api(scope, Some(name));
    let v = obj.get_private(scope, key)?;
    if v.is_string() { v.to_string(scope) } else { None }
}

/// What to compile instead of an `eval`/`Function` string in a CSP context
/// without 'unsafe-eval': an expression throwing EvalError with the text from
/// `globalThis.__pt_cspEval`. Without that text, the source as is.
fn modify_codegen<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    source: v8::Local<'s, v8::Value>,
    is_code_like: bool,
) -> v8::ModifyCodeGenerationFromStringsResult<'s> {
    let context = scope.get_current_context();
    let global = context.global(scope);
    // Trusted Types before CSP: with `require-trusted-types-for 'script'` the
    // string goes through the default policy (`__pt_ttEval`); without one, eval
    // throws Chrome's EvalError. A TrustedScript is already trusted.
    let mut tt_source: Option<v8::Local<'s, v8::String>> = None;
    let tt_on = v8::String::new(scope, "__pt_ttOn")
        .and_then(|k| global.get(scope, k.into()))
        .map(|v| v.is_true())
        .unwrap_or(false);
    if tt_on && source.is_string() {
        let f = v8::String::new(scope, "__pt_ttEval")
            .and_then(|k| global.get(scope, k.into()))
            .and_then(|v| v8::Local::<v8::Function>::try_from(v).ok());
        if let Some(f) = f {
            let r = f.call(scope, global.into(), &[source]);
            match r.filter(|v| v.is_string()).and_then(|v| v.to_string(scope)) {
                Some(code) => tt_source = Some(code),
                None => {
                    // `new Function(...)`: V8 parses the substitute as a function body, so the
                    // throw goes inside it (fires on call); direct eval throws immediately.
                    let src = source.to_rust_string_lossy(scope);
                    let throw = "throw new EvalError(\"Evaluating a string as JavaScript violates this document's Trusted Type assignment requirements.\");";
                    let js = if src.starts_with("(function anonymous(") || src.starts_with("(async function anonymous(") || src.starts_with("(function* anonymous(") || src.starts_with("(async function* anonymous(") {
                        let head = src.find("\n) {\n").map(|i| &src[..i + 5]).unwrap_or("(function anonymous(\n) {\n");
                        format!("{head}{throw}\n}})")
                    } else {
                        format!("(function () {{ {throw} }})()")
                    };
                    let modified = v8::String::new(scope, &js);
                    return v8::ModifyCodeGenerationFromStringsResult { codegen_allowed: true, modified_source: modified };
                }
            }
        }
    }
    let msg = v8::String::new(scope, "__pt_cspEval")
        .and_then(|k| global.get(scope, k.into()))
        .filter(|v| v.is_string())
        .map(|v| v.to_rust_string_lossy(scope))
        .filter(|m| !m.is_empty());
    let Some(msg) = msg else {
        // A TrustedScript runs its own text (hidden field, see
        // natives::TRUSTED_SCRIPT_KEY); eval returns other objects unchanged.
        let _ = is_code_like;
        let modified = tt_source.or_else(|| trusted_script_text(scope, source));
        return v8::ModifyCodeGenerationFromStringsResult { codegen_allowed: true, modified_source: modified };
    };
    let mut quoted = String::with_capacity(msg.len() + 2);
    quoted.push('"');
    for ch in msg.chars() {
        match ch {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\u{2028}' => quoted.push_str("\\u2028"),
            '\u{2029}' => quoted.push_str("\\u2029"),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    // Under Trusted Types the EvalError text is always TT's: Blink sets the
    // codegen message once per document and TT overrides it.
    let quoted = if tt_on { "\"Evaluating a string as JavaScript violates this document's Trusted Type assignment requirements.\"".to_string() } else { quoted };
    let js = format!("(function () {{ try {{ if (typeof __pt_cspEvalViolation === 'function') __pt_cspEvalViolation(); }} catch (e) {{}} throw new EvalError({quoted}); }})()");
    let modified = v8::String::new(scope, &js);
    v8::ModifyCodeGenerationFromStringsResult { codegen_allowed: true, modified_source: modified }
}

/// The error stack as the page sees it. V8 calls this on the first read of
/// `stack` with parsed frames; `__pt_formatStack` from the shared prologue drops
/// the engine's own frames (unnamed scripts: event dispatch, XHR, timers) and
/// calls the page's `Error.prepareStackTrace` if set. Otherwise `new Error()` in
/// a handler exposed engine internals.
fn prepare_stack_trace<'s, 'a>(
    scope: &mut v8::PinScope<'s, 'a>,
    error: v8::Local<'s, v8::Value>,
    sites: v8::Local<'s, v8::Array>,
) -> v8::Local<'s, v8::Value> {
    let context = scope.get_current_context();
    let global = context.global(scope);
    let formatter = v8::String::new(scope, "__pt_formatStack")
        .and_then(|k| global.get(scope, k.into()))
        .and_then(|v| v8::Local::<v8::Function>::try_from(v).ok());
    if let Some(f) = formatter {
        let undef: v8::Local<v8::Value> = v8::undefined(scope).into();
        if let Some(v) = f.call(scope, undef, &[error, sites.into()]) {
            return v;
        }
        // The formatter threw: let the throw reach the reader, as V8 would.
        return v8::undefined(scope).into();
    }
    // No prologue (bare context): default format, frame by frame.
    let mut out = String::from("Error");
    for i in 0..sites.length() {
        if let Some(site) = sites.get_index(scope, i) {
            if let Some(s) = site.to_string(scope) {
                out.push_str("\n    at ");
                out.push_str(&s.to_rust_string_lossy(scope));
            }
        }
    }
    match v8::String::new(scope, &out) {
        Some(s) => s.into(),
        None => v8::undefined(scope).into(),
    }
}

/// V8 asks the embedder to load an `import()`, and waits on the promise we
/// hand back. Everything here is bookkeeping: make the promise, remember the
/// resolver by id, and queue what was asked for the driver to fetch.
fn import_dynamically<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _host_defined_options: v8::Local<'s, v8::Data>,
    resource_name: v8::Local<'s, v8::Value>,
    specifier: v8::Local<'s, v8::String>,
    _import_attributes: v8::Local<'s, v8::FixedArray>,
) -> Option<v8::Local<'s, v8::Promise>> {
    let resolver = v8::PromiseResolver::new(scope)?;
    let promise = resolver.get_promise(scope);
    let referrer = resource_name.to_rust_string_lossy(scope);
    let what = specifier.to_rust_string_lossy(scope);

    // Which context asked. The number is on the global under a `__pt` name.
    let context = scope.get_current_context();
    let index = {
        let global = context.global(scope);
        v8::String::new(scope, "__pt_ctxIndex")
            .and_then(|k| global.get(scope, k.into()))
            .and_then(|v| v.uint32_value(scope))
            .unwrap_or(0) as usize
    };

    let handle = v8::Global::new(scope, resolver);
    let dynamic = scope.get_slot_mut::<DynamicImports>()?;
    dynamic.next_id += 1;
    let id = dynamic.next_id;
    dynamic.pending.insert(id, handle);
    dynamic.queue.push((id, index, referrer, what));
    Some(promise)
}

/// `import.meta.url` — the module's own address, which bundles use to build
/// paths to their sibling chunks and assets.
unsafe extern "C" fn import_meta(
    context: v8::Local<v8::Context>,
    module: v8::Local<v8::Module>,
    meta: v8::Local<v8::Object>,
) {
    v8::callback_scope!(unsafe scope, context);
    let hash = module.get_identity_hash().get();
    let Some(key) = scope.get_slot::<ModuleRegistry>().and_then(|r| r.by_hash.get(&hash).cloned())
    else {
        return;
    };
    // The key is "{context index}:{url}"; the page only ever sees the URL.
    let url = key.split_once(':').map(|(_, u)| u).unwrap_or(&key).to_string();
    let (Some(name), Some(value)) = (v8::String::new(scope, "url"), v8::String::new(scope, &url))
    else {
        return;
    };
    meta.set(scope, name.into(), value.into());
}

/// Answer one import. Everything it needs was put in the registry before
/// instantiation started; an unknown specifier is a missing fetch, not a
/// resolution the callback can do itself.
fn resolve_module<'a>(
    context: v8::Local<'a, v8::Context>,
    specifier: v8::Local<'a, v8::String>,
    _attributes: v8::Local<'a, v8::FixedArray>,
    referrer: v8::Local<'a, v8::Module>,
) -> Option<v8::Local<'a, v8::Module>> {
    v8::callback_scope!(unsafe scope, context);
    let spec = specifier.to_rust_string_lossy(scope);
    let hash = referrer.get_identity_hash().get();
    let handle = {
        let reg = scope.get_slot::<ModuleRegistry>()?;
        let from = reg.by_hash.get(&hash)?.clone();
        let target = reg.edges.get(&(from, spec))?.clone();
        reg.modules.get(&target)?.clone()
    };
    Some(v8::Local::new(scope, &handle))
}

/// Call a function on the current context's global; `None` when it is
/// missing or threw.
fn call_global<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    args: &[v8::Local<'s, v8::Value>],
) -> Option<v8::Local<'s, v8::Value>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, name)?;
    let f = v8::Local::<v8::Function>::try_from(global.get(scope, key.into())?).ok()?;
    v8::tc_scope!(tc, scope);
    let undef: v8::Local<v8::Value> = v8::undefined(tc).into();
    f.call(tc, undef, args)
}

/// Compile and run `source` in the current context, returning its result as a
/// string, or the exception message on failure.
fn run_script(scope: &mut v8::PinScope, source: &str) -> Result<String, String> {
    run_script_named(scope, source, None)
}

/// Same, but the script is named by its URL. The name shows not only in the
/// script's own frames (`//# sourceURL` would do for that) but also where V8
/// names the *parent*: for `new Function` and `eval` Chrome writes
/// `eval at <anonymous> (https://...:2:12)`, while an unnamed script gives
/// `unknown source`. Pages read stacks, so the difference shows.
fn run_script_named(
    scope: &mut v8::PinScope,
    source: &str,
    name: Option<&str>,
) -> Result<String, String> {
    v8::tc_scope!(scope, scope);

    let Some(code) = v8::String::new(scope, source) else {
        return Err("script source too large for V8".to_string());
    };
    let origin = match name {
        Some(url) => {
            let Some(n) = v8::String::new(scope, url) else {
                return Err("script name too large for V8".to_string());
            };
            Some(v8::ScriptOrigin::new(
                scope,
                n.into(),
                0,
                0,
                false,
                0,
                None,
                false,
                false,
                false, // is_module
                None,
            ))
        }
        None => None,
    };
    let Some(script) = v8::Script::compile(scope, code, origin.as_ref()) else {
        return Err(exception_message(scope));
    };
    let Some(value) = script.run(scope) else {
        return Err(exception_message(scope));
    };
    let Some(s) = value.to_string(scope) else {
        return Err("result could not be converted to string".to_string());
    };
    Ok(s.to_rust_string_lossy(scope))
}

/// Extract a human-readable message from a caught JS exception.
fn exception_message(
    tc: &mut v8::PinnedRef<'_, v8::TryCatch<'_, '_, v8::HandleScope<'_>>>,
) -> String {
    match tc.exception() {
        Some(ex) => {
            let msg = ex
                .to_string(tc)
                .map(|s| s.to_rust_string_lossy(tc))
                .unwrap_or_else(|| "uncatchable JS exception".to_string());
            // Include the stack when present: a bootstrap error without one is a needle
            // in a 100k-line haystack.
            let stack = ex
                .to_object(tc)
                .and_then(|o| {
                    let key = v8::String::new(tc, "stack")?;
                    let v = o.get(tc, key.into())?;
                    if v.is_string() { Some(v.to_rust_string_lossy(tc)) } else { None }
                })
                .unwrap_or_default();
            if stack.len() > msg.len() { stack } else { msg }
        }
        None => "unknown JS error".to_string(),
    }
}

/// Whether a disposed context should nudge the collector now. Off unless
/// `NOKK_GC_HINT_MS=<ms>` asks for it (0 = on every disposal): each nudge starts
/// a concurrent marking of the whole heap on V8's helper threads, and a solve
/// disposes dozens of contexts. Measured on two Cloudflare interstitials, four
/// runs each: hinting on every disposal 9.3 s CPU / 430 MB peak, at most every
/// 3 s 8.3 s / 510 MB, never 6.9 s / 575 MB. A server bound by cores, not RAM,
/// wants the last; a tight-memory box can trade CPU back for memory.
fn gc_hint_due() -> bool {
    use std::cell::Cell;
    thread_local! { static LAST: Cell<Option<std::time::Instant>> = const { Cell::new(None) }; }
    let Some(every) = std::env::var("NOKK_GC_HINT_MS").ok().and_then(|v| v.parse::<u64>().ok()) else {
        return false;
    };
    LAST.with(|last| {
        let now = std::time::Instant::now();
        let due = last.get().map_or(true, |t| now.duration_since(t).as_millis() as u64 >= every);
        if due {
            last.set(Some(now));
        }
        due
    })
}

