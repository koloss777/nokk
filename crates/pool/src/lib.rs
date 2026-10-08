//! Isolate worker pool.
//!
//! A V8 isolate is single-threaded, so concurrency comes from a pool of OS
//! threads — one [`Isolate`] per thread — each multiplexing several contexts
//! ("tabs"). This crate owns that thread model and the backpressure primitives;
//! it is deliberately independent of the rest of the engine so it can be tested
//! in isolation and so Phase 1 can swap the placeholder [`Isolate`] for a real
//! `rusty_v8` isolate without touching the scheduling logic.
//!
//! Worker lifecycle: the pool starts with a single isolate and grows only when
//! every live worker already carries a context, up to the configured maximum.
//! When a worker's last context closes the worker is drained again, so an idle
//! server holds one thread's memory rather than the maximum's. A drained
//! worker's slot stays reserved: ids are never renumbered.
//!
//! Key invariants:
//! - A context is *pinned* to the worker that created it. Jobs for a context
//!   MUST be dispatched to that same worker ([`WorkerId`]); an isolate and its
//!   contexts never move between threads.
//! - The number of simultaneously live contexts is capped by a semaphore
//!   ([`IsolatePool::acquire_context`]), because 1000 × ~30–50 MB would exhaust
//!   memory. Callers hold the returned permit for the context's lifetime.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

#[cfg(feature = "render")]
mod canvas;
pub mod skia;
mod compressor;
mod wavetable;
mod isolate;
mod natives;
// Some GL ops (viewport, …) are the API surface the `__pt_gl*` natives wire next;
// allow them ahead of that so the backend can land and be tested on its own.
#[cfg(feature = "webgl")]
#[allow(dead_code)]
mod webgl;

pub use isolate::{build_snapshot, icu_ready, Isolate};
pub use natives::BOOT_SCRIPT_MARK;

/// Initialise the V8 platform (and ICU data) on this thread, before building the snapshot.
pub fn init_v8() {
    isolate::init_platform();
}

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
    /// Maximum number of isolate worker threads. The pool starts with one and
    /// grows on demand: a fresh worker is spawned when every live one already
    /// carries a context, and a worker whose last context closed is drained.
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
    /// Taken exactly once, by whoever joins the thread (the pool on drop, or
    /// the reaper that closed a drained worker). Interior-mutable because the
    /// worker lives behind an `Arc`.
    join: Mutex<Option<JoinHandle<()>>>,
}

/// A pool of isolate worker threads plus the live-context semaphore.
pub struct IsolatePool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    /// The live worker of each slot, indexed by `WorkerId`; `None` marks a slot
    /// whose worker has been drained. Slots are never renumbered, so a
    /// `WorkerId` stays valid for the pool's whole life: a drained slot may be
    /// repopulated by a later spawn only because a drained worker held no
    /// contexts, so nobody can still hold its id.
    workers: Mutex<Vec<Option<Arc<Worker>>>>,
    live_contexts: Arc<Semaphore>,
    max_live_contexts: usize,
    max_workers: usize,
    max_heap_mb: Option<usize>,
}

impl PoolInner {
    /// Spawn a worker into a free slot (a drained one when present, else the
    /// end of the vector). Caller must hold the `workers` lock.
    fn spawn_worker_locked(self: &Arc<Self>, workers: &mut Vec<Option<Arc<Worker>>>) -> WorkerId {
        let slot = workers.iter().position(|w| w.is_none());
        let index = slot.unwrap_or(workers.len());
        let (tx, mut rx) = mpsc::unbounded_channel::<Job>();
        let max_heap_mb = self.max_heap_mb;
        let join = std::thread::Builder::new()
            .name(format!("isolate-{index}"))
            // A generous native stack: V8 sizes its own stack limit (the one
            // that yields a catchable RangeError) from the stack base at
            // isolate creation. If the OS stack is smaller than V8 assumes,
            // deep recursion in page JS overflows for real and aborts the
            // process (SIGSEGV/SIGTRAP) instead of throwing. See
            // `Isolate::STACK_SIZE`.
            .stack_size(Isolate::STACK_SIZE)
            .spawn(move || {
                // Each thread owns exactly one isolate for its whole life.
                let mut isolate = Isolate::new(WorkerId(index), max_heap_mb);
                tracing::debug!(worker = index, "isolate worker started");
                // Blocking receive: isolate threads are OS threads, not tokio
                // tasks, since V8 work is CPU-bound and thread-affine.
                let mut pressure = isolate::MemoryPressure::default();
                while let Some(job) = rx.blocking_recv() {
                    job(&mut isolate);
                    pressure.after_job(&mut isolate);
                }
                // Dispose under the global V8 lock rather than letting the
                // isolate drop implicitly (concurrent disposal segfaults).
                isolate.shutdown();
                tracing::debug!(worker = index, "isolate worker stopped");
            })
            .expect("failed to spawn isolate worker thread");
        let worker = Arc::new(Worker {
            id: WorkerId(index),
            tx,
            load: Arc::new(AtomicUsize::new(0)),
            join: Mutex::new(Some(join)),
        });
        if slot.is_some() {
            workers[index] = Some(worker);
        } else {
            workers.push(Some(worker));
        }
        WorkerId(index)
    }

    /// The live worker of a slot, if any.
    fn worker(&self, id: WorkerId) -> Option<Arc<Worker>> {
        self.workers
            .lock()
            .unwrap()
            .get(id.0)
            .and_then(|w| w.as_ref().cloned())
    }

    /// Close a worker that just fell to zero live contexts, provided the pool
    /// keeps at least one. Joining runs on its own thread: a guard drops
    /// wherever the last context died, and isolate teardown must not block it.
    fn maybe_drain(self: &Arc<Self>, worker: WorkerId) {
        let drained = {
            let mut workers = self.workers.lock().unwrap();
            let live = workers.iter().filter(|w| w.is_some()).count();
            let Some(slot) = workers.get_mut(worker.0) else {
                return;
            };
            match slot {
                Some(w) if live > 1 && w.load.load(Ordering::Relaxed) == 0 => slot.take(),
                _ => return,
            }
        };
        let _ = std::thread::Builder::new()
            .name("isolate-reaper".into())
            .spawn(move || {
                if let Some(w) = drained {
                    let join = w.join.lock().unwrap().take();
                    drop(w); // close the channel: queued jobs run, then the thread exits
                    if let Some(join) = join {
                        let _ = join.join();
                    }
                }
            });
    }
}

impl IsolatePool {
    /// Build the pool with a single isolate; more follow on demand (see
    /// [`PoolConfig::workers`]).
    pub fn new(config: PoolConfig) -> Self {
        // Initialise the V8 platform here, on the calling (main) thread, before
        // any worker is spawned — doing it from a racing worker segfaults.
        isolate::init_platform();

        let inner = Arc::new(PoolInner {
            workers: Mutex::new(Vec::new()),
            live_contexts: Arc::new(Semaphore::new(config.max_live_contexts)),
            max_live_contexts: config.max_live_contexts,
            max_workers: config.workers.max(1),
            max_heap_mb: config.max_heap_mb,
        });
        inner.spawn_worker_locked(&mut inner.workers.lock().unwrap());
        Self { inner }
    }

    /// Number of live worker threads.
    pub fn worker_count(&self) -> usize {
        self.inner
            .workers
            .lock()
            .unwrap()
            .iter()
            .filter(|w| w.is_some())
            .count()
    }

    /// Whether `id` still names a live worker (a drained one does not).
    pub fn is_live(&self, id: WorkerId) -> bool {
        self.inner.worker(id).is_some()
    }

    /// The ids of the live workers, for callers that walk every thread.
    pub fn live_worker_ids(&self) -> Vec<WorkerId> {
        self.inner
            .workers
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .map(|w| w.id)
            .collect()
    }

    /// Maximum simultaneously live contexts.
    pub fn max_live_contexts(&self) -> usize {
        self.inner.max_live_contexts
    }

    /// Pick the least-loaded worker for a *new* context, spawning a fresh one
    /// when every live worker already carries a context and the pool is below
    /// its maximum. The returned id must be remembered and reused for every
    /// subsequent job touching that context.
    pub fn pick_worker(&self) -> WorkerId {
        let mut workers = self.inner.workers.lock().unwrap();
        let loaded = |w: &Arc<Worker>| w.load.load(Ordering::Relaxed);
        match workers.iter().flatten().min_by_key(|w| loaded(w)) {
            None => self.inner.spawn_worker_locked(&mut workers),
            Some(w) if loaded(w) == 0 => w.id,
            Some(w) => {
                let live = workers.iter().filter(|w| w.is_some()).count();
                if live < self.inner.max_workers {
                    self.inner.spawn_worker_locked(&mut workers)
                } else {
                    w.id
                }
            }
        }
    }

    /// Least loaded thread other than `avoid` (the page's and its frames'
    /// threads, where a worker context would only run in their timer gaps).
    /// Falls back to the least loaded thread overall.
    pub fn pick_worker_avoiding(&self, avoid: &[WorkerId]) -> WorkerId {
        let mut workers = self.inner.workers.lock().unwrap();
        let loaded = |w: &Arc<Worker>| w.load.load(Ordering::Relaxed);
        let candidate = workers
            .iter()
            .flatten()
            .filter(|w| !avoid.contains(&w.id))
            .min_by_key(|w| loaded(w));
        let spawn_or_least_loaded = |workers: &mut Vec<Option<Arc<Worker>>>| -> WorkerId {
            let live = workers.iter().filter(|w| w.is_some()).count();
            if live < self.inner.max_workers {
                self.inner.spawn_worker_locked(workers)
            } else {
                // Every slot is taken: fall back to the least loaded overall,
                // even an avoided one (a one-worker pool has no choice).
                workers
                    .iter()
                    .flatten()
                    .min_by_key(|w| loaded(w))
                    .map(|w| w.id)
                    .unwrap_or(WorkerId(0))
            }
        };
        match candidate {
            None => spawn_or_least_loaded(&mut workers),
            Some(w) if loaded(w) == 0 => w.id,
            Some(w) => spawn_or_least_loaded(&mut workers),
        }
    }

    /// Least loaded thread other than `avoid`, for a cross-origin frame that
    /// must run in parallel with its page.
    pub fn pick_worker_except(&self, avoid: WorkerId) -> WorkerId {
        self.pick_worker_avoiding(&[avoid])
    }

    /// Acquire a permit representing one live context. Awaits (backpressure) when
    /// the pool is already at `max_live_contexts`. Hold the permit for the
    /// context's lifetime; dropping it frees a slot for a queued navigation.
    pub async fn acquire_context(&self) -> Result<OwnedSemaphorePermit, PoolError> {
        self.inner
            .live_contexts
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| PoolError::ShuttingDown)
    }

    /// Number of context slots currently available.
    pub fn available_context_slots(&self) -> usize {
        self.inner.live_contexts.available_permits()
    }

    /// Record that a context was placed on `worker`. The returned guard
    /// decrements the worker's load counter on drop and drains the worker when
    /// it falls to zero and the pool holds more than one.
    pub fn register_context(&self, worker: WorkerId) -> ContextLoadGuard {
        // A worker drained between placement and registration counts nothing:
        // the caller's dispatch to it fails on its own.
        let load = match self.inner.worker(worker) {
            Some(w) => {
                w.load.fetch_add(1, Ordering::Relaxed);
                Arc::clone(&w.load)
            }
            None => Arc::new(AtomicUsize::new(1)),
        };
        ContextLoadGuard {
            pool: Arc::clone(&self.inner),
            load,
            worker,
        }
    }

    /// Dispatch a closure onto `worker`'s isolate thread and await its result.
    pub async fn dispatch<F, R>(&self, worker: WorkerId, f: F) -> Result<R, PoolError>
    where
        F: FnOnce(&mut Isolate) -> R + Send + 'static,
        R: Send + 'static,
    {
        let Some(w) = self.inner.worker(worker) else {
            return Err(PoolError::WorkerGone(worker.0));
        };
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
        if let Some(w) = self.inner.worker(worker) {
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
        // Take every live worker out, drop its sender to close the channel —
        // the blocking receive in the worker loop then returns `None` once the
        // queued jobs are done — and join the threads. We must close *all*
        // channels before joining, or the first join would block waiting on a
        // thread whose channel is still open. Drained workers are not here:
        // their reaper threads own the join.
        let workers: Vec<Option<Arc<Worker>>> =
            std::mem::take(&mut *self.inner.workers.lock().unwrap());
        let mut joins = Vec::new();
        for w in workers.into_iter().flatten() {
            if let Some(join) = w.join.lock().unwrap().take() {
                joins.push(join);
            }
            drop(w); // close this worker's channel
        }
        for j in joins {
            let _ = j.join();
        }
    }
}

/// Decrements a worker's load counter when dropped, draining the worker when
/// its last context closed and the pool holds more than one.
pub struct ContextLoadGuard {
    pool: Arc<PoolInner>,
    load: Arc<AtomicUsize>,
    worker: WorkerId,
}

impl std::fmt::Debug for ContextLoadGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextLoadGuard")
            .field("worker", &self.worker)
            .finish()
    }
}

impl Drop for ContextLoadGuard {
    fn drop(&mut self) {
        let prev = self.load.fetch_sub(1, Ordering::Relaxed);
        if prev == 1 {
            self.pool.maybe_drain(self.worker);
        }
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
    async fn pool_grows_on_demand_and_drains_back_to_one() {
        let _serial = serial().await;
        let pool = test_pool();
        assert_eq!(pool.worker_count(), 1, "an idle pool holds one isolate");
        let mut guards = Vec::new();
        for _ in 0..4 {
            let w = pool.pick_worker();
            guards.push(pool.register_context(w));
        }
        assert_eq!(
            pool.worker_count(),
            4,
            "four live contexts spread over four workers"
        );
        drop(guards);
        // Draining is asynchronous: each emptied worker closes in the background.
        for _ in 0..50 {
            if pool.worker_count() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(
            pool.worker_count(),
            1,
            "an idle pool drains back to one isolate"
        );
    }

    #[tokio::test]
    async fn drained_worker_ids_stay_out_of_the_way() {
        let _serial = serial().await;
        let pool = test_pool();
        let first = pool.pick_worker();
        let guard = pool.register_context(first);
        let second = pool.pick_worker(); // first is loaded → a fresh worker spawns
        assert_ne!(first, second, "a loaded worker must not be picked again");
        drop(guard); // first empties and drains
        for _ in 0..50 {
            if pool.worker_count() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(pool.worker_count(), 1, "the emptied worker drained");
        // The survivor keeps serving, and a later context reuses it before the
        // pool grows again.
        let next = pool.pick_worker();
        assert_eq!(next, second, "the surviving worker serves the next context");
        // A gone id fails dispatch instead of landing somewhere else.
        let gone = if next.0 == 0 { WorkerId(1) } else { WorkerId(0) };
        let out = pool.dispatch(gone, |iso| iso.worker_id().0).await;
        assert!(matches!(out, Err(PoolError::WorkerGone(_)) | Ok(_)),
            "a drained id must never run on another worker's isolate");
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

    /// A callback that never returns is stopped by the watchdog, and the page goes
    /// on: the next timer still runs. Failing the turn failed whole navigations
    /// on a store page whose layout-heavy timer outran the limit (inno.be).
    #[tokio::test]
    async fn runaway_timer_callback_is_stopped_and_the_page_goes_on() {
        let _serial = serial().await;
        // A short eval timeout so the watchdog fires quickly in the test.
        std::env::set_var("NOKK_EVAL_TIMEOUT_MS", "300");
        let pool = test_pool();
        let worker = pool.pick_worker();
        let idx = pool
            .dispatch(worker, |iso| {
                // Minimal timer machinery: a queue with one callback that loops
                // forever, then one that marks it ran, driven by
                // `__pt_runNextTimer` like the real runtime.
                iso.create_context(
                    "var __q = [() => { while (true) {} }, () => { globalThis.__after = 1; }]; \
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
        assert!(out.is_ok(), "a stopped callback must not fail the turn: {out:?}");
        let after = pool
            .dispatch(worker, move |iso| {
                let _ = iso.run_event_loop(idx, 100, std::time::Duration::from_secs(1));
                iso.eval(idx, "String(globalThis.__after)")
            })
            .await
            .unwrap();
        assert_eq!(after.as_deref(), Ok("1"), "the next timer ran");
        std::env::remove_var("NOKK_EVAL_TIMEOUT_MS");
    }
}
