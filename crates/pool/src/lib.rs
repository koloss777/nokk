//! Isolate worker pool.
//!
//! A V8 isolate is single-threaded, so concurrency comes from a pool of OS
//! threads — one [`Isolate`] per thread — each multiplexing several contexts
//! ("tabs"). This crate owns that thread model and the backpressure primitives;
//! it is deliberately independent of the rest of the engine so it can be tested
//! in isolation and so Phase 1 can swap the placeholder [`Isolate`] for a real
//! `rusty_v8` isolate without touching the scheduling logic.
//!
//! Key invariants:
//! - A context is *pinned* to the worker that created it. Jobs for a context
//!   MUST be dispatched to that same worker ([`WorkerId`]); an isolate and its
//!   contexts never move between threads.
//! - The number of simultaneously live contexts is capped by a semaphore
//!   ([`IsolatePool::acquire_context`]), because 1000 × ~30–50 MB would exhaust
//!   memory. Callers hold the returned permit for the context's lifetime.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

mod isolate;
mod natives;

pub use isolate::Isolate;

/// Errors surfaced by the pool.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("worker {0} is gone")]
    WorkerGone(usize),
    #[error("pool is shutting down")]
    ShuttingDown,
    #[error("the worker dropped the job before returning a result")]
    Canceled,
}

/// Configuration for the isolate pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Number of isolate worker threads. Defaults to available parallelism.
    pub workers: usize,
    /// Maximum number of simultaneously live contexts across the whole pool.
    pub max_live_contexts: usize,
    /// Per-isolate JS heap cap in MB (shared across that worker's contexts).
    /// `None` leaves V8's default. Total JS heap is bounded by roughly
    /// `workers * max_heap_mb`; exceeding the cap fails the offending run with an
    /// out-of-memory error instead of aborting the process.
    pub max_heap_mb: Option<usize>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            workers,
            // A conservative default; the scheduler (Phase 7) tunes this against
            // the per-context memory budget.
            max_live_contexts: workers * 16,
            max_heap_mb: None,
        }
    }
}

/// Identifies a single isolate worker thread. Jobs for a pinned context must be
/// dispatched to the worker that owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerId(pub usize);

/// A unit of work that runs *on* an isolate worker thread with mutable access to
/// that thread's [`Isolate`]. This is the only way to touch V8 state, which is
/// not `Send`.
type Job = Box<dyn FnOnce(&mut Isolate) + Send + 'static>;

struct Worker {
    id: WorkerId,
    tx: mpsc::UnboundedSender<Job>,
    /// Number of contexts currently assigned to this worker; used for
    /// least-loaded placement.
    load: Arc<AtomicUsize>,
    join: Option<JoinHandle<()>>,
}

/// A pool of isolate worker threads plus the live-context semaphore.
pub struct IsolatePool {
    workers: Vec<Worker>,
    live_contexts: Arc<Semaphore>,
    max_live_contexts: usize,
}

impl IsolatePool {
    /// Spawn the worker threads described by `config`.
    pub fn new(config: PoolConfig) -> Self {
        // Initialise the V8 platform here, on the calling (main) thread, before
        // any worker is spawned — doing it from a racing worker segfaults.
        isolate::init_platform();

        let mut workers = Vec::with_capacity(config.workers);
        let max_heap_mb = config.max_heap_mb;
        for i in 0..config.workers {
            let id = WorkerId(i);
            let (tx, mut rx) = mpsc::unbounded_channel::<Job>();
            let load = Arc::new(AtomicUsize::new(0));
            let join = std::thread::Builder::new()
                .name(format!("isolate-{i}"))
                // A generous native stack: V8 sizes its own stack limit (the one
                // that yields a catchable RangeError) from the stack base at
                // isolate creation. If the OS stack is smaller than V8 assumes,
                // deep recursion in page JS overflows for real and aborts the
                // process (SIGSEGV/SIGTRAP) instead of throwing. See
                // `Isolate::STACK_SIZE`.
                .stack_size(Isolate::STACK_SIZE)
                .spawn(move || {
                    // Each thread owns exactly one isolate for its whole life.
                    let mut isolate = Isolate::new(id, max_heap_mb);
                    tracing::debug!(worker = i, "isolate worker started");
                    // Blocking receive: isolate threads are OS threads, not tokio
                    // tasks, since V8 work is CPU-bound and thread-affine.
                    while let Some(job) = rx.blocking_recv() {
                        job(&mut isolate);
                    }
                    // Dispose under the global V8 lock rather than letting the
                    // isolate drop implicitly (concurrent disposal segfaults).
                    isolate.shutdown();
                    tracing::debug!(worker = i, "isolate worker stopped");
                })
                .expect("failed to spawn isolate worker thread");
            workers.push(Worker {
                id,
                tx,
                load,
                join: Some(join),
            });
        }

        Self {
            workers,
            live_contexts: Arc::new(Semaphore::new(config.max_live_contexts)),
            max_live_contexts: config.max_live_contexts,
        }
    }

    /// Number of worker threads.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Maximum simultaneously live contexts.
    pub fn max_live_contexts(&self) -> usize {
        self.max_live_contexts
    }

    /// Pick the least-loaded worker for a *new* context. The returned id must be
    /// remembered and reused for every subsequent job touching that context.
    pub fn pick_worker(&self) -> WorkerId {
        self.workers
            .iter()
            .min_by_key(|w| w.load.load(Ordering::Relaxed))
            .map(|w| w.id)
            .unwrap_or(WorkerId(0))
    }

    /// Acquire a permit representing one live context. Awaits (backpressure) when
    /// the pool is already at `max_live_contexts`. Hold the permit for the
    /// context's lifetime; dropping it frees a slot for a queued navigation.
    pub async fn acquire_context(&self) -> Result<OwnedSemaphorePermit, PoolError> {
        self.live_contexts
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| PoolError::ShuttingDown)
    }

    /// Number of context slots currently available.
    pub fn available_context_slots(&self) -> usize {
        self.live_contexts.available_permits()
    }

    /// Record that a context was placed on `worker`. Returned guard decrements
    /// the worker's load counter on drop.
    pub fn register_context(&self, worker: WorkerId) -> ContextLoadGuard {
        let load = self.workers[worker.0].load.clone();
        load.fetch_add(1, Ordering::Relaxed);
        ContextLoadGuard { load }
    }

    /// Dispatch a closure onto `worker`'s isolate thread and await its result.
    pub async fn dispatch<F, R>(&self, worker: WorkerId, f: F) -> Result<R, PoolError>
    where
        F: FnOnce(&mut Isolate) -> R + Send + 'static,
        R: Send + 'static,
    {
        let w = self
            .workers
            .get(worker.0)
            .ok_or(PoolError::WorkerGone(worker.0))?;
        let (tx, rx) = oneshot::channel();
        let job: Job = Box::new(move |iso| {
            // Ignore send errors: the awaiting side may have been dropped.
            let _ = tx.send(f(iso));
        });
        w.tx.send(job)
            .map_err(|_| PoolError::WorkerGone(worker.0))?;
        rx.await.map_err(|_| PoolError::Canceled)
    }

    /// Fire-and-forget a closure onto `worker`'s isolate thread — no result is
    /// awaited. For teardown work (e.g. disposing a context) that must run on the
    /// owning thread but has no caller to return to (called from `Drop`). A gone
    /// worker is ignored.
    pub fn dispatch_detached<F>(&self, worker: WorkerId, f: F)
    where
        F: FnOnce(&mut Isolate) + Send + 'static,
    {
        if let Some(w) = self.workers.get(worker.0) {
            let _ = w.tx.send(Box::new(f));
        }
    }

    /// Stop accepting work and join all worker threads. Equivalent to dropping
    /// the pool, but blocks until every isolate has finished draining.
    pub fn shutdown(self) {
        drop(self);
    }
}

impl Drop for IsolatePool {
    fn drop(&mut self) {
        // Dropping each worker's sender closes its channel, so the blocking
        // receive in the worker loop returns `None` and the thread exits. We
        // must drop *all* senders before joining, or the first join would block
        // waiting on a thread whose channel is still open.
        let workers = std::mem::take(&mut self.workers);
        let mut joins = Vec::with_capacity(workers.len());
        for mut w in workers {
            joins.extend(w.join.take());
            drop(w.tx); // close this worker's channel
        }
        for j in joins {
            let _ = j.join();
        }
    }
}

/// Decrements a worker's load counter when dropped.
pub struct ContextLoadGuard {
    load: Arc<AtomicUsize>,
}

impl Drop for ContextLoadGuard {
    fn drop(&mut self) {
        self.load.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::{Mutex, MutexGuard};

    // Serialise pool lifetimes across tests in this binary: overlapping isolate
    // pool create/teardown across threads segfaults the prebuilt V8 (see
    // `isolate.rs`). Each test holds this for its whole body so pools never
    // coexist. Production creates one long-lived pool, so this does not apply
    // there.
    // Async-aware mutex so the guard can be held across `.await` without tripping
    // `await_holding_lock`; each test still serialises for its whole body.
    static SERIAL: Mutex<()> = Mutex::const_new(());

    async fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().await
    }

    fn test_pool() -> IsolatePool {
        IsolatePool::new(PoolConfig {
            workers: 4,
            max_live_contexts: 8,
            max_heap_mb: None,
        })
    }

    #[tokio::test]
    async fn dispatch_runs_on_worker_and_returns_value() {
        let _serial = serial().await;
        let pool = test_pool();
        let worker = pool.pick_worker();
        let out = pool
            .dispatch(worker, |iso| iso.worker_id().0 + 100)
            .await
            .unwrap();
        assert_eq!(out, worker.0 + 100);
    }

    #[tokio::test]
    async fn least_loaded_placement_spreads_contexts() {
        let _serial = serial().await;
        let pool = test_pool();
        // Register one context per pick; each pick should choose a fresh worker
        // until all four are loaded once.
        let mut guards = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..4 {
            let w = pool.pick_worker();
            seen.insert(w.0);
            guards.push(pool.register_context(w));
        }
        assert_eq!(seen.len(), 4, "should spread across all workers");
    }

    #[tokio::test]
    async fn semaphore_caps_live_contexts() {
        let _serial = serial().await;
        let pool = IsolatePool::new(PoolConfig {
            workers: 2,
            max_live_contexts: 2,
            max_heap_mb: None,
        });
        let _a = pool.acquire_context().await.unwrap();
        let _b = pool.acquire_context().await.unwrap();
        assert_eq!(pool.available_context_slots(), 0);
        // A third acquire must not resolve while the pool is full.
        let pending = pool.acquire_context();
        tokio::pin!(pending);
        tokio::select! {
            _ = &mut pending => panic!("acquired past the cap"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }
        drop(_a);
        // Now a slot is free and the pending acquire resolves.
        let _freed = pending.await.unwrap();
    }

    #[tokio::test]
    async fn disposing_a_context_keeps_later_indices_stable() {
        let _serial = serial().await;
        let pool = test_pool();
        let worker = pool.pick_worker();
        // Create three contexts on one isolate, each tagging a global so we can
        // tell them apart.
        let (a, b, c) = pool
            .dispatch(worker, |iso| {
                let a = iso.create_context("globalThis.tag = 'A'").unwrap();
                let b = iso.create_context("globalThis.tag = 'B'").unwrap();
                let c = iso.create_context("globalThis.tag = 'C'").unwrap();
                (a, b, c)
            })
            .await
            .unwrap();
        assert_eq!((a, b, c), (0, 1, 2));

        // Dispose the *first* context. B and C must keep their indices — a naive
        // Vec::remove would shift them and corrupt the pinned-index contract.
        let (b_tag, c_tag, a_err, count) = pool
            .dispatch(worker, move |iso| {
                iso.dispose_context(a);
                let b_tag = iso.eval(b, "globalThis.tag");
                let c_tag = iso.eval(c, "globalThis.tag");
                let a_err = iso.eval(a, "1");
                (b_tag, c_tag, a_err, iso.context_count())
            })
            .await
            .unwrap();
        assert_eq!(b_tag.as_deref(), Ok("B"));
        assert_eq!(c_tag.as_deref(), Ok("C"));
        assert!(a_err.is_err(), "disposed index must not resolve");
        assert_eq!(count, 2, "two live contexts remain");
    }

    #[tokio::test]
    async fn runaway_timer_callback_is_terminated_not_hung() {
        let _serial = serial().await;
        // A short eval timeout so the watchdog fires quickly in the test.
        std::env::set_var("NOKK_EVAL_TIMEOUT_MS", "300");
        let pool = test_pool();
        let worker = pool.pick_worker();
        let idx = pool
            .dispatch(worker, |iso| {
                // Minimal timer machinery: a queue with one callback that loops
                // forever, driven by `__pt_runNextTimer` like the real runtime.
                iso.create_context(
                    "var __q = [() => { while (true) {} }]; \
                     globalThis.__pt_runNextTimer = () => { \
                       const f = __q.shift(); if (!f) return false; f(); return true; };",
                )
                .unwrap()
            })
            .await
            .unwrap();

        // Without the watchdog this dispatch would never return. Bound the wait so
        // a regression fails the test instead of hanging the suite.
        let run = pool.dispatch(worker, move |iso| {
            iso.run_event_loop(idx, 100, std::time::Duration::from_secs(5))
        });
        let out = tokio::time::timeout(std::time::Duration::from_secs(3), run)
            .await
            .expect("worker hung: run_event_loop was not terminated")
            .unwrap();
        assert!(out.is_err(), "runaway callback should surface as an error");
        std::env::remove_var("NOKK_EVAL_TIMEOUT_MS");
    }
}
