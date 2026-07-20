//! A V8 isolate, owned by exactly one worker thread.
//!
//! Phase 1: this wraps a real `v8::OwnedIsolate`. Each isolate multiplexes
//! several contexts ("tabs"), stored as persistent [`v8::Global`] handles.
//! Because V8 handles are thread-affine and `!Send`, an isolate and its contexts
//! are only ever touched from the worker thread that created them — which is
//! exactly the [`crate::IsolatePool`] contract.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Mutex, Once};
use std::time::Duration;

use crate::WorkerId;

static V8_INIT: Once = Once::new();
/// Serialises `v8::Isolate::new`. Concurrent isolate construction from multiple
/// threads segfaults with the prebuilt V8; construction is a one-time,
/// startup-only cost per worker, so a global lock here is free in practice.
static CREATE_LOCK: Mutex<()> = Mutex::new(());

/// Initialise the V8 platform exactly once per process. This MUST run on the
/// main thread before any worker thread is spawned — triggering the platform
/// init from a worker (racing other workers) segfaults. [`crate::IsolatePool::new`]
/// calls it on the calling thread before spawning workers; the per-worker call
/// in [`Isolate::new`] is then a no-op.
pub(crate) fn init_platform() {
    V8_INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        // Pin one ref for the whole process so the platform is never freed while
        // isolates still reference it (a use-after-free otherwise).
        std::mem::forget(platform.clone());
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
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

    /// Create an isolate. `max_heap_mb` caps this isolate's JS heap (shared across
    /// all its contexts); `None` leaves V8's default (effectively unbounded).
    pub(crate) fn new(id: WorkerId, max_heap_mb: Option<usize>) -> Self {
        init_platform();
        let mut params = v8::CreateParams::default();
        if let Some(mb) = max_heap_mb {
            // initial = 0 lets V8 pick its default starting heap; max is the cap.
            params = params.heap_limits(0, mb * 1024 * 1024);
        }
        let mut isolate = {
            // Never construct two isolates concurrently (see CREATE_LOCK).
            let _guard = CREATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            v8::Isolate::new(params)
        };
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

    /// Create a fresh context, run `bootstrap` in it (the stealth environment:
    /// `navigator`/`window`/`screen`…), and return its index. If the bootstrap
    /// script throws, the context is discarded and the error is returned.
    pub fn create_context(&mut self, bootstrap: &str) -> Result<usize, String> {
        let global = {
            let scope = &mut v8::HandleScope::new(&mut self.isolate);
            let context = v8::Context::new(scope, v8::ContextOptions::default());
            let global = v8::Global::new(scope, context);
            let scope = &mut v8::ContextScope::new(scope, context);
            // Native bindings must exist before the bootstrap runs — the JS
            // WebCrypto layer is built on top of them.
            crate::natives::install(scope);
            run_script(scope, bootstrap)?;
            global
        };
        self.contexts.push(Some(global));
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
    pub fn eval(&mut self, index: usize, source: &str) -> Result<String, String> {
        let global = self.context(index)?;
        let watchdog = TerminateWatchdog::arm(&mut self.isolate);

        let result = {
            let scope = &mut v8::HandleScope::new(&mut self.isolate);
            let context = v8::Local::new(scope, &global);
            let scope = &mut v8::ContextScope::new(scope, context);
            run_script(scope, source)
        };

        // Disarm and clear any pending termination so the next eval on this
        // isolate starts clean.
        watchdog.disarm();
        self.isolate.cancel_terminate_execution();
        // A termination caused by the heap cap reads as a generic error; surface
        // it as a clear out-of-memory message instead.
        if self.took_oom() {
            return Err("JavaScript heap out of memory (isolate cap reached)".to_string());
        }
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
        let result = self.pump_timers(&global, max_callbacks, deadline);
        watchdog.disarm();
        self.isolate.cancel_terminate_execution();
        if self.took_oom() {
            return Err("JavaScript heap out of memory (isolate cap reached)".to_string());
        }
        result
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
        let scope = &mut v8::HandleScope::new(&mut self.isolate);
        let context = v8::Local::new(scope, global);
        let scope = &mut v8::ContextScope::new(scope, context);
        let scope = &mut v8::TryCatch::new(scope);

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
    pub fn dispose_context(&mut self, index: usize) {
        if let Some(slot) = self.contexts.get_mut(index) {
            *slot = None;
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
}

impl TerminateWatchdog {
    fn arm(isolate: &mut v8::OwnedIsolate) -> Self {
        let tsh = isolate.thread_safe_handle();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let handle = std::thread::Builder::new()
            .name("eval-watchdog".into())
            .spawn(move || {
                // Only a timeout is actionable; a clean finish (Ok/Disconnected)
                // means the script returned in time.
                if let Err(RecvTimeoutError::Timeout) =
                    done_rx.recv_timeout(Isolate::eval_timeout())
                {
                    tsh.terminate_execution();
                }
            });
        match handle {
            Ok(handle) => Self {
                done_tx: Some(done_tx),
                handle: Some(handle),
            },
            Err(e) => {
                tracing::warn!(error = %e, "could not spawn eval watchdog; running without timeout guard");
                Self {
                    done_tx: None,
                    handle: None,
                }
            }
        }
    }

    /// Wake the watchdog and join it, so no pending termination can leak into the
    /// next script run on this isolate.
    fn disarm(mut self) {
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Compile and run `source` in the current context, returning its result as a
/// string, or the exception message on failure.
fn run_script(scope: &mut v8::HandleScope, source: &str) -> Result<String, String> {
    let scope = &mut v8::TryCatch::new(scope);

    let Some(code) = v8::String::new(scope, source) else {
        return Err("script source too large for V8".to_string());
    };
    let Some(script) = v8::Script::compile(scope, code, None) else {
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
fn exception_message(tc: &mut v8::TryCatch<v8::HandleScope>) -> String {
    match tc.exception() {
        Some(ex) => ex
            .to_string(tc)
            .map(|s| s.to_rust_string_lossy(tc))
            .unwrap_or_else(|| "uncatchable JS exception".to_string()),
        None => "unknown JS error".to_string(),
    }
}
