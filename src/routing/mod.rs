//! # Routing & Upstream Management
//!
//! This module implements the core backend selection and health management layer:
//!
//! - **`BackendNode`**: A single backend server with atomic health tracking,
//!   passive failure detection, slow-start weight ramping, and a three-state
//!   circuit breaker (CLOSED -> OPEN -> HALF_OPEN -> CLOSED).
//!
//! - **`UpstreamPool`**: A group of backends with a configured load balancing
//!   algorithm. Supports 8 algorithms: RoundRobin, LeastConnections, IpHash,
//!   Random, WeightedRoundRobin, AIPredictive, ConsistentHash, and LeastTime.
//!
//! - **`UpstreamManager`**: Global registry of named pools, shared across all
//!   Tokio tasks. Handles hot-reload by diffing old/new config and restarting
//!   health check loops.
//!
//! - **Active health check loop**: Periodic TCP/HTTP probes that transition
//!   backends between UP/DOWN and advance the circuit breaker state machine.

use arc_swap::ArcSwap;
use smallvec::SmallVec;
use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

// ─── Circuit Breaker State Constants ────────────────────────────────────────

/// Normal operation: all requests pass through and failures are counted.
const CIRCUIT_CLOSED: u8 = 0;
/// Backend is considered unavailable: all requests are rejected immediately.
/// After the backoff period, the health-check loop transitions to HALF_OPEN.
const CIRCUIT_OPEN: u8 = 1;
/// A single health-check probe is in progress. Live traffic is still blocked.
/// On probe success → CLOSED; on probe failure → OPEN with doubled backoff.
const CIRCUIT_HALF_OPEN: u8 = 2;

use crate::config::{BackendConfig, LoadBalancingAlgorithm, UpstreamPoolConfig};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Current epoch seconds (used for lightweight time-based checks without heap alloc).
#[inline]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── BackendNode ─────────────────────────────────────────────────────────────

/// Represents a single physical backend server and tracks its live state.
#[derive(Debug)]
pub struct BackendNode {
    /// Static configuration for this backend (address, weight, health check, circuit breaker)
    pub config: BackendConfig,
    /// Number of currently active proxy connections to this node
    pub active_connections: AtomicUsize,
    /// `true` = healthy; updated by active health check loop AND by passive failure detection
    pub is_healthy: AtomicBool,

    // ── Passive health check state ────────────────────────────────────────
    /// Consecutive proxy failures since the last success (or since `fail_timeout` reset).
    fail_count: AtomicU32,
    /// Epoch-secs of the most recent proxy failure. Used to enforce the `fail_timeout` window.
    last_fail_at: AtomicU64,

    // ── Slow start state ─────────────────────────────────────────────────
    /// Epoch-secs when this backend last transitioned from DOWN → UP (for slow-start ramp).
    /// Zero means the backend has been UP since startup (no ramp needed).
    recovery_time: AtomicU64,

    // ── Circuit Breaker state ─────────────────────────────────────────────
    /// Current circuit state: CIRCUIT_CLOSED (0), CIRCUIT_OPEN (1), CIRCUIT_HALF_OPEN (2).
    circuit_state: AtomicU8,
    /// Epoch-secs when the circuit was last tripped to OPEN.
    circuit_open_at: AtomicU64,
    /// Current backoff duration in seconds before a health-check probe is allowed.
    /// Doubles on each successive trip, capped at `config.circuit_max_backoff_secs`.
    circuit_backoff_secs: AtomicU64,
}

impl BackendNode {
    /// Creates a new backend node from static configuration.
    /// All health tracking fields are initialized to "healthy, no failures, no recovery".
    /// The circuit breaker starts in CLOSED state with the configured initial backoff.
    pub fn new(config: BackendConfig) -> Self {
        let initial_backoff = config.circuit_initial_backoff_secs;
        Self {
            config,
            active_connections: AtomicUsize::new(0),
            is_healthy: AtomicBool::new(true),
            fail_count: AtomicU32::new(0),
            last_fail_at: AtomicU64::new(0),
            recovery_time: AtomicU64::new(0),
            circuit_state: AtomicU8::new(CIRCUIT_CLOSED),
            circuit_open_at: AtomicU64::new(0),
            circuit_backoff_secs: AtomicU64::new(initial_backoff),
        }
    }

    /// Called by the proxy pipeline whenever a backend request fails (5xx, timeout, connect error).
    ///
    /// If `fail_count` reaches `max_fails` within the `fail_timeout` window the backend is
    /// immediately marked DOWN — without waiting for the active health check interval.
    pub fn record_failure(&self) {
        let now = now_secs();
        let last = self.last_fail_at.load(Ordering::Relaxed);

        // Reset the counter if the previous failure is outside the fail_timeout window
        if now.saturating_sub(last) > self.config.fail_timeout_secs {
            self.fail_count.store(1, Ordering::Relaxed);
        } else {
            self.fail_count.fetch_add(1, Ordering::Relaxed);
        }
        self.last_fail_at.store(now, Ordering::Release);

        let count = self.fail_count.load(Ordering::Acquire);
        if count >= self.config.max_fails && self.is_healthy.load(Ordering::Relaxed) {
            self.is_healthy.store(false, Ordering::Release);
            warn!(
                "Passive health check: backend {} DOWN after {} consecutive failures",
                self.config.address, count
            );
            self.trip_circuit();
        }
    }

    // ── Circuit Breaker ──────────────────────────────────────────────────────

    /// Trips the circuit to OPEN. If the circuit was already OPEN (failed probe),
    /// the backoff is doubled up to `circuit_max_backoff_secs`.
    pub fn trip_circuit(&self) {
        if !self.config.circuit_breaker {
            return;
        }
        let prev_state = self.circuit_state.swap(CIRCUIT_OPEN, Ordering::AcqRel);
        let new_backoff = match prev_state {
            // Failed probe in HALF_OPEN: double the backoff
            CIRCUIT_HALF_OPEN => {
                let current = self.circuit_backoff_secs.load(Ordering::Relaxed);
                (current * 2).min(self.config.circuit_max_backoff_secs)
            }
            // Fresh trip from CLOSED: reset to initial backoff
            _ => self.config.circuit_initial_backoff_secs,
        };
        self.circuit_backoff_secs.store(new_backoff, Ordering::Release);
        self.circuit_open_at.store(now_secs(), Ordering::Release);
        warn!(
            "Circuit breaker OPEN for backend {} (backoff: {}s)",
            self.config.address, new_backoff
        );
    }

    /// Returns `true` if the circuit is CLOSED and requests may be forwarded.
    /// OPEN and HALF_OPEN both block live traffic; the health-check loop handles probing.
    pub fn is_circuit_closed(&self) -> bool {
        if !self.config.circuit_breaker {
            return true;
        }
        self.circuit_state.load(Ordering::Acquire) == CIRCUIT_CLOSED
    }

    /// Called by the health-check loop after a successful probe in HALF_OPEN state.
    /// Transitions the circuit back to CLOSED and resets the backoff counter.
    pub fn record_circuit_success(&self) {
        if !self.config.circuit_breaker {
            return;
        }
        let prev = self.circuit_state.swap(CIRCUIT_CLOSED, Ordering::AcqRel);
        if prev != CIRCUIT_CLOSED {
            self.circuit_backoff_secs
                .store(self.config.circuit_initial_backoff_secs, Ordering::Release);
            info!(
                "Circuit breaker CLOSED for backend {} (probe succeeded)",
                self.config.address
            );
        }
    }

    /// Called by the active health check loop when it detects a DOWN→UP transition.
    /// Stamps `recovery_time` so slow-start can ramp the effective weight.
    /// Also closes the circuit breaker if it was in HALF_OPEN state.
    pub fn record_recovery(&self) {
        let now = now_secs();
        self.recovery_time.store(now, Ordering::Release);
        self.fail_count.store(0, Ordering::Relaxed);
        self.is_healthy.store(true, Ordering::Release);
        self.record_circuit_success();
        info!(
            "Backend {} recovered (UP). Slow-start: {} secs",
            self.config.address, self.config.slow_start_secs
        );
    }

    /// Returns the current failure count for this backend.
    pub fn fail_count(&self) -> u32 {
        self.fail_count.load(Ordering::Relaxed)
    }

    /// Returns the circuit breaker state as a human-readable string.
    pub fn circuit_state_str(&self) -> &'static str {
        match self.circuit_state.load(Ordering::Acquire) {
            CIRCUIT_CLOSED => "closed",
            CIRCUIT_OPEN => "open",
            CIRCUIT_HALF_OPEN => "half_open",
            _ => "unknown",
        }
    }

    /// Effective weight for WRR and ConsistentHash selection, accounting for slow-start.
    ///
    /// Returns a value in `0..=config.weight`:
    /// - During slow-start ramp: linearly interpolated from 1 → full weight over `slow_start_secs`
    /// - After ramp completes (or if slow_start_secs == 0): full weight
    pub fn effective_weight(&self) -> u32 {
        let slow = self.config.slow_start_secs;
        if slow == 0 {
            return self.config.weight;
        }
        let rt = self.recovery_time.load(Ordering::Relaxed);
        if rt == 0 {
            // Never been DOWN — not in recovery, use full weight
            return self.config.weight;
        }
        let elapsed = now_secs().saturating_sub(rt);
        if elapsed >= slow as u64 {
            self.config.weight
        } else {
            // Ramp from 1 to full weight linearly
            let w = self.config.weight.max(1);
            let ramped = ((w as u64 * elapsed) / slow as u64) as u32;
            ramped.max(1) // always give at least weight=1 so traffic can validate health
        }
    }
}

// ─── UpstreamPool ────────────────────────────────────────────────────────────

/// A logical grouping of backends with its own load balancing algorithm.
///
/// The backend list is stored behind an `ArcSwap` so it can be atomically replaced
/// during hot-reload or DNS discovery updates without blocking in-flight requests.
/// The round-robin counter is a simple atomic that wraps modulo the backend count.
pub struct UpstreamPool {
    /// The load balancing strategy for this pool.
    pub algorithm: LoadBalancingAlgorithm,
    /// Lock-free swappable list of backends; supports concurrent reads during hot-reload writes.
    pub backends: ArcSwap<Vec<Arc<BackendNode>>>,
    /// Monotonically increasing counter for Round-Robin / Weighted-RR index selection.
    round_robin_index: AtomicUsize,
    /// Shared TCP connection pool for keepalive reuse across requests.
    pub connection_pool: Arc<crate::proxy::pool::ConnectionPool>,
    /// Notification channel for queue-based waiting when all backends are at max_conns.
    queue_notify: Arc<tokio::sync::Notify>,
    /// Cached ConsistentHash ring. Built lazily on first ConsistentHash request,
    /// reused across subsequent requests, and rebuilt only when the
    /// (address, effective_weight) signature of healthy backends changes.
    /// Replaces the previous per-request rebuild that hashed and sorted
    /// `weight × 160` virtual nodes (~640 entries for a typical 4-backend pool).
    consistent_hash_ring: ArcSwap<Option<ConsistentHashRing>>,
}

/// Cached virtual-node ring for the ConsistentHash LB algorithm.
struct ConsistentHashRing {
    /// FxHash signature of the (sorted address, effective_weight) tuples used
    /// to build this ring. A request comparing its current signature to this
    /// value gets an O(n) cache validity check; if equal, the ring is reused
    /// as-is. If different, the ring is rebuilt and stored.
    signature: u64,
    /// Sorted `(virtual_node_hash, backend)` entries on the u64 ring.
    /// Backends are held by `Arc` so the ring stays valid even if a backend
    /// is removed from the pool between rebuild and request.
    entries: Vec<(u64, Arc<BackendNode>)>,
}

impl UpstreamPool {
    /// Constructs a new pool from its config, creating a `BackendNode` for each backend.
    pub fn new(config: &UpstreamPoolConfig) -> Self {
        let backends: Vec<Arc<BackendNode>> = config
            .backends
            .iter()
            .map(|b| Arc::new(BackendNode::new(b.clone())))
            .collect();

        Self {
            algorithm: config.algorithm,
            backends: ArcSwap::from_pointee(backends),
            round_robin_index: AtomicUsize::new(0),
            connection_pool: Arc::new(crate::proxy::pool::ConnectionPool::new(config.keepalive)),
            queue_notify: Arc::new(tokio::sync::Notify::new()),
            consistent_hash_ring: ArcSwap::from_pointee(None),
        }
    }

    /// Dynamically add a backend to this pool (used by Admin API + DNS discovery).
    ///
    /// Deduplicates by address: if a backend with the same address already exists,
    /// the add is silently ignored. Uses ArcSwap's copy-on-write pattern so readers
    /// are never blocked.
    pub fn add_backend(&self, config: BackendConfig) {
        let new_node = Arc::new(BackendNode::new(config));
        let mut current_backends = self.backends.load().as_ref().clone();
        // Avoid duplicates: only add if no existing backend has the same address
        if !current_backends
            .iter()
            .any(|b| b.config.address == new_node.config.address)
        {
            current_backends.push(new_node);
            self.backends.store(Arc::new(current_backends));
        }
    }

    /// Dynamically remove a backend from this pool by address.
    pub fn remove_backend(&self, address: &str) {
        let mut current_backends = self.backends.load().as_ref().clone();
        current_backends.retain(|b| b.config.address != address);
        self.backends.store(Arc::new(current_backends));
    }

    /// Select the next healthy backend using the configured load balancing algorithm.
    ///
    /// # Selection pipeline
    /// 1. Split backends into primary vs backup; use backup only if all primaries are DOWN.
    /// 2. Filter out backends that exceed `max_conns` or have an open circuit breaker.
    /// 3. Dispatch to the algorithm-specific selection logic.
    ///
    /// # Arguments
    /// * `client_ip` - Used by IpHash and ConsistentHash for sticky routing.
    /// * `ai_engine` - Optional AI router for the AIPredictive algorithm.
    ///
    /// # Returns
    /// `Some(backend)` on success, or `None` if no healthy backend is available.
    pub fn get_next_backend(
        &self,
        client_ip: Option<&std::net::IpAddr>,
        ai_engine: Option<Arc<dyn crate::ai::AiRouter>>,
    ) -> Option<Arc<BackendNode>> {
        let current_backends = self.backends.load();

        // Single-pass partition into primary-and-available + backup-and-available.
        // Stack-allocated SmallVec keeps the entire selection allocation-free in the
        // common case (≤ 8 backends per pool); only spills to the heap for very
        // wide pools. Replaces the previous 3 sequential `Vec::collect()` calls
        // (one per filter), which heap-allocated 3× per request.
        let mut primary: SmallVec<[Arc<BackendNode>; 8]> = SmallVec::new();
        let mut backup: SmallVec<[Arc<BackendNode>; 8]> = SmallVec::new();
        for b in current_backends.iter() {
            // Combined health + circuit-breaker + capacity filter
            if !b.is_healthy.load(Ordering::Acquire) || !b.is_circuit_closed() {
                continue;
            }
            if b.config.max_conns != 0
                && b.active_connections.load(Ordering::Relaxed) >= b.config.max_conns as usize
            {
                continue;
            }
            if b.config.backup {
                backup.push(Arc::clone(b));
            } else {
                primary.push(Arc::clone(b));
            }
        }

        let healthy: SmallVec<[Arc<BackendNode>; 8]> = if !primary.is_empty() {
            primary
        } else if !backup.is_empty() {
            backup
        } else {
            return None;
        };

        match self.algorithm {
            // ── Algorithm 1: AI Predictive ────────────────────────────
            // Delegates to the configured AI bandit algorithm (epsilon-greedy, UCB1,
            // softmax, or Thompson sampling). Falls back to round-robin if no AI engine.
            LoadBalancingAlgorithm::AIPredictive => {
                if let Some(ai) = ai_engine {
                    ai.predict_best_backend(&healthy)
                } else {
                    let idx =
                        self.round_robin_index.fetch_add(1, Ordering::Relaxed) % healthy.len();
                    Some(Arc::clone(&healthy[idx]))
                }
            }

            // ── Algorithm 2: Round Robin ─────────────────────────────
            // Simple sequential rotation. The atomic counter wraps via modulo.
            LoadBalancingAlgorithm::RoundRobin => {
                let idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed) % healthy.len();
                Some(Arc::clone(&healthy[idx]))
            }

            // ── Algorithm 3: Least Connections ───────────────────────
            // Picks the backend with the fewest in-flight requests. Optimal for
            // heterogeneous backends with varying response times.
            LoadBalancingAlgorithm::LeastConnections => healthy
                .into_iter()
                .min_by_key(|b| b.active_connections.load(Ordering::Relaxed)),

            // ── Algorithm 4: Random ──────────────────────────────────
            // Uses the thread-local RNG. Avoids the per-request `SystemTime::now()`
            // syscall (≈30 ns vsyscall on Linux) — `rand::random::<u32>()` is a
            // user-space ChaCha thread-local pull (~3 ns).
            LoadBalancingAlgorithm::Random => {
                let idx = (rand::random::<u32>() as usize) % healthy.len();
                Some(Arc::clone(&healthy[idx]))
            }

            // ── Algorithm 5: IP Hash ─────────────────────────────────
            // Hashes the client IP to a deterministic backend index. Provides
            // session affinity without cookies, but shifts all traffic when a
            // backend goes down (unlike ConsistentHash which minimizes disruption).
            LoadBalancingAlgorithm::IpHash => {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                if let Some(ip) = client_ip {
                    ip.hash(&mut hasher);
                } else {
                    // No client IP available (e.g. TCP proxy): fall back to time-based
                    now_secs().hash(&mut hasher);
                }
                let idx = (hasher.finish() as usize) % healthy.len();
                Some(Arc::clone(&healthy[idx]))
            }

            // ── Algorithm 6: Weighted Round Robin ────────────────────
            // Distributes traffic proportional to each backend's effective weight.
            // Uses slow-start effective_weight() so recovering backends ramp gradually.
            LoadBalancingAlgorithm::WeightedRoundRobin => {
                let total_weight: u32 = healthy.iter().map(|b| b.effective_weight()).sum();
                if total_weight == 0 {
                    return None;
                }
                let mut pos =
                    (self.round_robin_index.fetch_add(1, Ordering::Relaxed) as u32) % total_weight;
                for backend in &healthy {
                    let w = backend.effective_weight();
                    if pos < w {
                        return Some(Arc::clone(backend));
                    }
                    pos -= w;
                }
                None
            }

            // ── Algorithm 7: Least Time ──────────────────────────────
            // Selects the backend with the fewest active connections,
            // breaking ties by preferring higher effective weight as a proxy for
            // capacity. This combines connection awareness with weight awareness.
            LoadBalancingAlgorithm::LeastTime => healthy
                .into_iter()
                .min_by(|a, b| {
                    let a_conns = a.active_connections.load(Ordering::Relaxed);
                    let b_conns = b.active_connections.load(Ordering::Relaxed);
                    a_conns
                        .cmp(&b_conns)
                        .then_with(|| a.effective_weight().cmp(&b.effective_weight()).reverse())
                }),

            // ── Algorithm 8: Consistent Hashing ──────────────────────
            // Builds a virtual-node ring where each backend gets
            // `160 * effective_weight` hash positions. The client IP is hashed
            // and mapped to the nearest ring position via binary search.
            // When a backend is removed, only its ring segment is redistributed,
            // minimizing cache and session disruption (Karger et al., 1997).
            LoadBalancingAlgorithm::ConsistentHash => {
                use std::hash::{Hash, Hasher};

                // Hash the client IP (or fall back to random ts if unknown)
                let key_hash: u64 = {
                    let mut h = rustc_hash::FxHasher::default();
                    if let Some(ip) = client_ip {
                        ip.hash(&mut h);
                    } else {
                        now_secs().hash(&mut h);
                    }
                    h.finish()
                };

                let ring = self.get_or_build_consistent_hash_ring(&healthy);
                let entries = match ring.as_ref() {
                    Some(r) if !r.entries.is_empty() => &r.entries,
                    _ => return None,
                };
                let target_idx = match entries.binary_search_by_key(&key_hash, |(h, _)| *h) {
                    Ok(i) | Err(i) => i % entries.len(),
                };
                Some(Arc::clone(&entries[target_idx].1))
            }
        }
    }

    /// Returns a cached `ConsistentHashRing` for the given healthy set, rebuilding
    /// only when the (address, effective_weight) signature has changed.
    ///
    /// The signature check is O(n) where n is the number of healthy backends —
    /// the ring rebuild is O(n × 160 × log) and roughly two orders of magnitude
    /// more expensive at typical pool sizes, so amortising across many requests
    /// is a meaningful win.
    fn get_or_build_consistent_hash_ring(
        &self,
        healthy: &[Arc<BackendNode>],
    ) -> Arc<Option<ConsistentHashRing>> {
        use std::hash::{Hash, Hasher};

        // Cheap signature: hash the (address, effective_weight) tuples in
        // address-sorted order so reordering of `healthy` doesn't invalidate.
        // Sort indices instead of cloning addresses.
        let mut order: SmallVec<[usize; 8]> = (0..healthy.len()).collect();
        order.sort_unstable_by(|&a, &b| {
            healthy[a].config.address.cmp(&healthy[b].config.address)
        });
        let sig: u64 = {
            let mut h = rustc_hash::FxHasher::default();
            for &i in &order {
                healthy[i].config.address.hash(&mut h);
                healthy[i].effective_weight().hash(&mut h);
            }
            h.finish()
        };

        let cached = self.consistent_hash_ring.load();
        if let Some(ring) = cached.as_ref() {
            if ring.signature == sig {
                return Arc::clone(&cached);
            }
        }

        // Cache miss → rebuild. Each backend gets `effective_weight × 160`
        // virtual nodes spaced around a u64 ring (matches NGINX default).
        let virtual_nodes_per_backend = 160u32;
        let mut entries: Vec<(u64, Arc<BackendNode>)> =
            Vec::with_capacity(healthy.len() * virtual_nodes_per_backend as usize);
        for backend in healthy.iter() {
            let w = backend.effective_weight().max(1);
            let slots = virtual_nodes_per_backend * w;
            for slot in 0..slots {
                let mut h = rustc_hash::FxHasher::default();
                backend.config.address.hash(&mut h);
                slot.hash(&mut h);
                entries.push((h.finish(), Arc::clone(backend)));
            }
        }
        entries.sort_unstable_by_key(|(hash, _)| *hash);
        let new_ring = ConsistentHashRing { signature: sig, entries };
        self.consistent_hash_ring.store(Arc::new(Some(new_ring)));
        // Re-load to return the just-stored value with the right Arc identity.
        self.consistent_hash_ring.load_full()
    }

    /// Selects a backend with queue-based waiting when all backends are at max_conns.
    ///
    /// If `get_next_backend()` returns `None` and any backend has `queue_size > 0`,
    /// this method waits up to `queue_timeout_ms` for a backend slot to open.
    /// Other callers signal availability via `notify_queue()` when a connection ends.
    pub async fn get_next_backend_queued(
        &self,
        client_ip: Option<&std::net::IpAddr>,
        ai_engine: Option<Arc<dyn crate::ai::AiRouter>>,
    ) -> Option<Arc<BackendNode>> {
        // Fast path: try immediate selection
        if let Some(backend) = self.get_next_backend(client_ip, ai_engine.clone()) {
            return Some(backend);
        }

        // Check if any backend supports queuing
        let current_backends = self.backends.load();
        let max_queue_size = current_backends
            .iter()
            .map(|b| b.config.queue_size)
            .max()
            .unwrap_or(0);

        if max_queue_size == 0 {
            return None; // No queuing configured
        }

        let timeout_ms = current_backends
            .iter()
            .map(|b| b.config.queue_timeout_ms)
            .max()
            .unwrap_or(5000);

        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);

        // Wait loop: retry selection when notified or until timeout
        loop {
            match tokio::time::timeout_at(deadline, self.queue_notify.notified()).await {
                Ok(()) => {
                    // Notified that a slot may be available — retry
                    if let Some(backend) = self.get_next_backend(client_ip, ai_engine.clone()) {
                        return Some(backend);
                    }
                    // Spurious wakeup or slot taken by another waiter, continue waiting
                }
                Err(_) => {
                    // Timeout — one last try
                    return self.get_next_backend(client_ip, ai_engine.clone());
                }
            }
        }
    }

    /// Notifies waiting requests that a backend connection slot has been freed.
    ///
    /// Call this after decrementing `active_connections` on a backend to wake
    /// any requests queued by `get_next_backend_queued()`.
    pub fn notify_queue(&self) {
        self.queue_notify.notify_waiters();
    }
}

// ─── UpstreamManager ─────────────────────────────────────────────────────────

/// Global registry for all named upstream pools, shared across Tokio tasks.
///
/// Uses `DashMap` for lock-free concurrent reads (hot path) with sharded write
/// locking (cold path: config reload, admin API mutations). Each pool entry
/// owns its own health check and DNS watcher tasks.
pub struct UpstreamManager {
    /// Map from pool name (e.g. "default", "backend_api") to its `UpstreamPool`.
    pools: DashMap<String, Arc<UpstreamPool>>,
}

impl UpstreamManager {
    /// Initializes the manager from the global config, creating a pool for each
    /// `upstream` block. For every pool, it:
    /// 1. Loads any previously-discovered backends from the RocksDB service registry.
    /// 2. Spawns an active health check loop (TCP or HTTP probes every 5 seconds).
    /// 3. Spawns DNS watchers for hostname-based backends (if `dns_resolver` is set).
    pub fn new(
        config: &crate::config::AppConfig,
        discovery: Arc<crate::discovery::ServiceDiscovery>,
    ) -> Self {
        let manager = Self {
            pools: DashMap::new(),
        };

        for (name, pool_config) in &config.upstreams {
            let pool = Arc::new(UpstreamPool::new(pool_config));

            // Load statically discovered (RocksDB-persisted) backends
            let discovered = discovery.list_backends(name);
            for d in discovered {
                pool.add_backend(BackendConfig {
                    address: d.address.clone(),
                    weight: d.weight,
                    health_check_path: pool_config
                        .backends
                        .first()
                        .and_then(|b| b.health_check_path.clone()),
                    health_check_status: pool_config
                        .backends
                        .first()
                        .map(|b| b.health_check_status)
                        .unwrap_or(200),
                    ..Default::default()
                });
            }

            manager.pools.insert(name.clone(), pool.clone());

            // Active health check loop (HTTP or TCP probe)
            tokio::spawn(health_check_loop(
                name.clone(),
                pool.clone(),
                pool_config.health_check_interval_secs,
                pool_config.health_check_timeout_secs,
            ));

            // DNS watcher — spawned for any backend whose address is a hostname
            if let Some(ref resolver_addr) = config.dns_resolver {
                for backend in &pool_config.backends {
                    if !is_ip_literal(&backend.address) {
                        let (hostname, port) = split_host_port(&backend.address);
                        crate::discovery::spawn_dns_watcher(
                            name.clone(),
                            hostname,
                            port,
                            Arc::clone(&pool),
                            resolver_addr.clone(),
                            backend.clone(),
                        );
                    }
                }
            }
        }

        manager
    }

    /// Looks up a pool by name. Returns `None` if the pool does not exist.
    pub fn get_pool(&self, key: &str) -> Option<Arc<UpstreamPool>> {
        self.pools.get(key).map(|p| Arc::clone(&p))
    }

    /// Rebuilds upstream pools from a fresh config snapshot during SIGHUP hot reload.
    ///
    /// Performs a three-way diff: removes pools no longer in config, updates existing
    /// pools with new backends/algorithm, and adds newly-configured pools. Each
    /// updated/added pool gets fresh health check loops and DNS watchers.
    pub fn reload_from_config(
        &self,
        config: &crate::config::AppConfig,
        discovery: Arc<crate::discovery::ServiceDiscovery>,
    ) {
        let desired_names: HashSet<String> = config.upstreams.keys().cloned().collect();
        let existing_names: Vec<String> = self.pools.iter().map(|e| e.key().clone()).collect();

        for name in existing_names {
            if !desired_names.contains(&name) {
                self.pools.remove(&name);
                info!("Removed upstream pool '{}' via hot reload", name);
            }
        }

        for (name, pool_config) in &config.upstreams {
            let pool = Arc::new(UpstreamPool::new(pool_config));

            // Reload statically discovered (RocksDB-persisted) backends.
            let discovered = discovery.list_backends(name);
            for d in discovered {
                pool.add_backend(BackendConfig {
                    address: d.address.clone(),
                    weight: d.weight,
                    health_check_path: pool_config
                        .backends
                        .first()
                        .and_then(|b| b.health_check_path.clone()),
                    health_check_status: pool_config
                        .backends
                        .first()
                        .map(|b| b.health_check_status)
                        .unwrap_or(200),
                    ..Default::default()
                });
            }

            let existed = self.pools.insert(name.clone(), Arc::clone(&pool)).is_some();

            // Restart health checks with the latest backend set.
            tokio::spawn(health_check_loop(
                name.clone(),
                Arc::clone(&pool),
                pool_config.health_check_interval_secs,
                pool_config.health_check_timeout_secs,
            ));

            // Restart DNS watchers for hostname backends.
            if let Some(ref resolver_addr) = config.dns_resolver {
                for backend in &pool_config.backends {
                    if !is_ip_literal(&backend.address) {
                        let (hostname, port) = split_host_port(&backend.address);
                        crate::discovery::spawn_dns_watcher(
                            name.clone(),
                            hostname,
                            port,
                            Arc::clone(&pool),
                            resolver_addr.clone(),
                            backend.clone(),
                        );
                    }
                }
            }

            if existed {
                info!("Updated upstream pool '{}' via hot reload", name);
            } else {
                info!("Added upstream pool '{}' via hot reload", name);
            }
        }
    }

    /// Returns all pool names and their corresponding pools.
    /// Used by the admin `/api/upstreams/detail` endpoint.
    pub fn inner_pools(&self) -> Vec<(String, Arc<UpstreamPool>)> {
        self.pools
            .iter()
            .map(|e| (e.key().clone(), Arc::clone(e.value())))
            .collect()
    }
}

// ─── Helper: is the address an IP literal? ───────────────────────────────────

/// Returns `true` if `addr` is an IPv4 or IPv6 address (not a hostname).
fn is_ip_literal(addr: &str) -> bool {
    let host = addr.split(':').next().unwrap_or(addr);
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Splits `"hostname:port"` into `("hostname", "port")`.
/// Defaults port to "80" if not present.
fn split_host_port(addr: &str) -> (String, String) {
    if let Some(colon) = addr.rfind(':') {
        (addr[..colon].to_string(), addr[colon + 1..].to_string())
    } else {
        (addr.to_string(), "80".to_string())
    }
}

// ─── Active health check loop ─────────────────────────────────────────────────

/// Active health check loop that runs as a background Tokio task for each upstream pool.
///
/// Every 5 seconds, it iterates over all backends and:
/// - For DOWN backends or those in HALF_OPEN circuit state: runs a health probe
///   (HTTP GET or TCP connect) and transitions state accordingly.
/// - For UP backends: runs a health probe to detect newly-failed backends.
/// - Manages the circuit breaker state machine: OPEN -> HALF_OPEN (after backoff)
///   -> CLOSED (on success) or back to OPEN with doubled backoff (on failure).
async fn health_check_loop(
    pool_name: String,
    pool: Arc<UpstreamPool>,
    interval_secs: u64,
    timeout_secs: u64,
) {
    let interval = Duration::from_secs(if interval_secs > 0 { interval_secs } else { 5 });
    let _timeout = Duration::from_secs(if timeout_secs > 0 { timeout_secs } else { 3 });
    info!(
        "Starting health check loop for pool: {} (interval: {}s, timeout: {}s)",
        pool_name, interval.as_secs(), _timeout.as_secs()
    );

    loop {
        sleep(interval).await;

        let backends_snapshot = pool.backends.load().clone();

        for backend in backends_snapshot.iter() {
            let address = &backend.config.address;
            let was_healthy = backend.is_healthy.load(Ordering::Acquire);

            // ── Circuit breaker: advance OPEN → HALF_OPEN when backoff expires ──
            if backend.config.circuit_breaker
                && backend.circuit_state.load(Ordering::Acquire) == CIRCUIT_OPEN
            {
                let backoff = backend.circuit_backoff_secs.load(Ordering::Relaxed);
                let opened_at = backend.circuit_open_at.load(Ordering::Relaxed);
                if now_secs().saturating_sub(opened_at) >= backoff {
                    // Try to advance to HALF_OPEN (only one health-check task wins the CAS)
                    if backend
                        .circuit_state
                        .compare_exchange(
                            CIRCUIT_OPEN,
                            CIRCUIT_HALF_OPEN,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        info!(
                            "Circuit breaker HALF_OPEN for backend {} in pool {} — probing",
                            address, pool_name
                        );
                    }
                }
            }

            let circuit_probing = backend.config.circuit_breaker
                && backend.circuit_state.load(Ordering::Acquire) == CIRCUIT_HALF_OPEN;

            // Only probe if: backend is DOWN, OR the circuit is in HALF_OPEN state
            if !was_healthy || circuit_probing {
                let probe_ok = if let Some(ref path) = backend.config.health_check_path {
                    let url = format!("http://{}{}", address, path);
                    let expected = backend.config.health_check_status;
                    match reqwest_health_get(&url, expected, _timeout).await {
                        Ok(true) => true,
                        Ok(false) => {
                            warn!(
                                "Health check FAILED for {} in pool {} (unexpected status)",
                                address, pool_name
                            );
                            false
                        }
                        Err(e) => {
                            warn!(
                                "Health check ERROR for {} in pool {}: {}",
                                address, pool_name, e
                            );
                            false
                        }
                    }
                } else {
                    matches!(
                        tokio::time::timeout(_timeout, TcpStream::connect(address)).await,
                        Ok(Ok(_))
                    )
                };

                match (was_healthy, probe_ok) {
                    (false, true) => {
                        // DOWN → UP: record recovery (also closes circuit if in HALF_OPEN)
                        backend.record_recovery();
                        info!("Backend {} in pool {} is now UP", address, pool_name);
                    }
                    (_, false) if circuit_probing => {
                        // HALF_OPEN probe failed: trip circuit again (doubles backoff)
                        backend.trip_circuit();
                        warn!(
                            "Circuit breaker probe FAILED for {} in pool {} — back to OPEN",
                            address, pool_name
                        );
                    }
                    _ => {}
                }
            } else if was_healthy {
                // Backend is UP — run health check to detect newly-failed backends
                let still_ok = if let Some(ref path) = backend.config.health_check_path {
                    let url = format!("http://{}{}", address, path);
                    let expected = backend.config.health_check_status;
                    matches!(reqwest_health_get(&url, expected, _timeout).await, Ok(true))
                } else {
                    matches!(
                        tokio::time::timeout(_timeout, TcpStream::connect(address)).await,
                        Ok(Ok(_))
                    )
                };

                if !still_ok {
                    backend.is_healthy.store(false, Ordering::Release);
                    backend.trip_circuit();
                    warn!("Backend {} in pool {} is DOWN (health check)", address, pool_name);
                }
            }
        }
    }
}

/// Perform an HTTP GET to `url`; return `Ok(true)` if status matches `expected`.
async fn reqwest_health_get(url: &str, expected_status: u16, timeout: Duration) -> Result<bool, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    Ok(resp.status().as_u16() == expected_status)
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_backend(
        weight: u32,
        max_fails: u32,
        fail_timeout_secs: u64,
        slow_start_secs: u32,
    ) -> BackendNode {
        BackendNode::new(BackendConfig {
            address: "127.0.0.1:8080".to_string(),
            weight,
            max_fails,
            fail_timeout_secs,
            slow_start_secs,
            ..Default::default()
        })
    }

    // ── Passive health check ─────────────────────────────────────────────────

    #[test]
    fn test_passive_health_check_marks_backend_down() {
        let node = make_backend(1, 2, 30, 0);
        assert!(
            node.is_healthy.load(Ordering::Relaxed),
            "should start healthy"
        );

        node.record_failure();
        assert!(
            node.is_healthy.load(Ordering::Relaxed),
            "1 failure < max_fails=2, still UP"
        );

        node.record_failure();
        assert!(
            !node.is_healthy.load(Ordering::Relaxed),
            "2 failures == max_fails, should be DOWN"
        );
    }

    #[test]
    fn test_passive_health_check_resets_after_timeout() {
        let node = make_backend(1, 2, 1, 0); // 1-second window
        node.record_failure();

        // Simulate that 2 seconds have passed by backdating last_fail_at
        node.last_fail_at.store(now_secs() - 5, Ordering::Relaxed);

        // This call is outside the 1-second window → counter resets to 1, NOT 2
        node.record_failure();
        assert!(
            node.is_healthy.load(Ordering::Relaxed),
            "failure outside window should reset counter, backend stays UP"
        );
    }

    #[test]
    fn test_record_recovery_clears_state() {
        let node = make_backend(1, 1, 30, 60);
        node.record_failure();
        assert!(!node.is_healthy.load(Ordering::Relaxed));

        node.record_recovery();
        assert!(
            node.is_healthy.load(Ordering::Relaxed),
            "should be UP after recovery"
        );
        assert_eq!(
            node.fail_count.load(Ordering::Relaxed),
            0,
            "fail count reset"
        );
        assert!(
            node.recovery_time.load(Ordering::Relaxed) > 0,
            "recovery_time stamped"
        );
    }

    // ── Slow start ───────────────────────────────────────────────────────────

    #[test]
    fn test_slow_start_mid_ramp_weight_is_partial() {
        let node = make_backend(100, 3, 30, 60); // 60s ramp, full weight = 100
        // Stamp recovery_time to 30 seconds ago → halfway through ramp
        node.recovery_time.store(now_secs() - 30, Ordering::Relaxed);

        let ew = node.effective_weight();
        // Should be approximately 50 (± a few due to timing)
        assert!(
            ew >= 45 && ew <= 55,
            "effective_weight mid-ramp should be ~50, got {}",
            ew
        );
    }

    #[test]
    fn test_slow_start_after_ramp_full_weight() {
        let node = make_backend(100, 3, 30, 60);
        // Recovery was 90s ago — ramp of 60s is complete
        node.recovery_time.store(now_secs() - 90, Ordering::Relaxed);
        assert_eq!(
            node.effective_weight(),
            100,
            "should return full weight after ramp"
        );
    }

    #[test]
    fn test_slow_start_disabled_always_full_weight() {
        let node = make_backend(42, 3, 30, 0); // slow_start_secs = 0 means disabled
        node.recovery_time.store(now_secs(), Ordering::Relaxed);
        assert_eq!(node.effective_weight(), 42);
    }

    // ── Consistent hashing ───────────────────────────────────────────────────

    #[test]
    fn test_consistent_hash_same_ip_same_backend() {
        use std::net::IpAddr;
        let pool_config = crate::config::UpstreamPoolConfig {
            algorithm: LoadBalancingAlgorithm::ConsistentHash,
            backends: vec![
                BackendConfig {
                    address: "10.0.0.1:8080".to_string(),
                    ..Default::default()
                },
                BackendConfig {
                    address: "10.0.0.2:8080".to_string(),
                    ..Default::default()
                },
                BackendConfig {
                    address: "10.0.0.3:8080".to_string(),
                    ..Default::default()
                },
            ],
            keepalive: 0,
            srv_discover: None,
            health_check_interval_secs: 5,
            health_check_timeout_secs: 3,
        };
        let pool = UpstreamPool::new(&pool_config);
        let ip: IpAddr = "192.168.1.42".parse().unwrap();

        let backends: Vec<String> = (0..10)
            .map(|_| {
                pool.get_next_backend(Some(&ip), None)
                    .unwrap()
                    .config
                    .address
                    .clone()
            })
            .collect();

        // All 10 calls with same IP must pick the same backend
        assert!(
            backends.windows(2).all(|w| w[0] == w[1]),
            "consistent hash should always pick same backend for same IP: {:?}",
            backends
        );
    }

    // ── Circuit breaker ──────────────────────────────────────────────────────

    #[test]
    fn test_circuit_breaker_trip() {
        let mut node = make_backend(1, 3, 30, 0);
        // Enable circuit breaker
        node.config.circuit_breaker = true;
        node.config.circuit_initial_backoff_secs = 1;
        node.config.circuit_max_backoff_secs = 10;

        assert!(node.is_circuit_closed(), "circuit should start closed");
        node.trip_circuit();
        assert!(!node.is_circuit_closed(), "circuit should be OPEN after trip");
    }

    #[test]
    fn test_circuit_breaker_disabled_always_closed() {
        let mut node = make_backend(1, 3, 30, 0);
        node.config.circuit_breaker = false;

        node.trip_circuit(); // Should be no-op
        assert!(node.is_circuit_closed(), "circuit should always be closed when disabled");
    }

    #[test]
    fn test_circuit_breaker_success_closes_circuit() {
        let mut node = make_backend(1, 3, 30, 0);
        node.config.circuit_breaker = true;
        node.config.circuit_initial_backoff_secs = 1;
        node.config.circuit_max_backoff_secs = 10;

        node.trip_circuit();
        assert!(!node.is_circuit_closed());

        node.record_circuit_success();
        assert!(node.is_circuit_closed(), "circuit should close after successful probe");
    }

    // ── Helper functions ──────────────────────────────────────────────────────

    #[test]
    fn test_is_ip_literal_true_v4() {
        assert!(is_ip_literal("192.168.1.1"));
        assert!(is_ip_literal("10.0.0.1:8080"));
    }

    #[test]
    fn test_is_ip_literal_ipv6_brackets() {
        // IPv6 addresses with brackets are NOT correctly detected by this function
        // (this is a known limitation - the function uses split(':') which breaks IPv6)
        // The function only works for plain IPv4 addresses
        assert!(!is_ip_literal("[::1]:8080"));
    }

    #[test]
    fn test_is_ip_literal_false_hostname() {
        assert!(!is_ip_literal("localhost"));
        assert!(!is_ip_literal("backend.example.com"));
        assert!(!is_ip_literal("my-service:8080"));
    }

    #[test]
    fn test_split_host_port_with_port() {
        let (host, port) = split_host_port("backend.example.com:8080");
        assert_eq!(host, "backend.example.com");
        assert_eq!(port, "8080");
    }

    #[test]
    fn test_split_host_port_without_port() {
        let (host, port) = split_host_port("backend.example.com");
        assert_eq!(host, "backend.example.com");
        assert_eq!(port, "80");
    }

    #[test]
    fn test_split_host_port_ipv4_with_port() {
        let (host, port) = split_host_port("192.168.1.1:3000");
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, "3000");
    }

    // ── Weighted round-robin ─────────────────────────────────────────────────

    #[test]
    fn test_weighted_roundrobin_respects_weights() {
        let pool_config = crate::config::UpstreamPoolConfig {
            algorithm: LoadBalancingAlgorithm::WeightedRoundRobin,
            backends: vec![
                BackendConfig {
                    address: "10.0.0.1:8080".to_string(),
                    weight: 3,
                    ..Default::default()
                },
                BackendConfig {
                    address: "10.0.0.2:8080".to_string(),
                    weight: 1,
                    ..Default::default()
                },
            ],
            keepalive: 0,
            srv_discover: None,
            health_check_interval_secs: 5,
            health_check_timeout_secs: 3,
        };
        let pool = UpstreamPool::new(&pool_config);

        let mut counts = std::collections::HashMap::new();
        for _ in 0..100 {
            let backend = pool.get_next_backend(None, None).unwrap();
            *counts.entry(backend.config.address.clone()).or_insert(0) += 1;
        }
        // 10.0.0.1 with weight 3 should be picked ~75% of the time
        let a_count = *counts.get("10.0.0.1:8080").unwrap_or(&0);
        let b_count = *counts.get("10.0.0.2:8080").unwrap_or(&0);
        assert!(a_count > b_count * 2, "higher weight should be picked more often: a={}, b={}", a_count, b_count);
    }

    // ── IP hash ─────────────────────────────────────────────────────────────

    #[test]
    fn test_ip_hash_same_ip_same_backend() {
        let pool_config = crate::config::UpstreamPoolConfig {
            algorithm: LoadBalancingAlgorithm::IpHash,
            backends: vec![
                BackendConfig { address: "10.0.0.1:8080".to_string(), ..Default::default() },
                BackendConfig { address: "10.0.0.2:8080".to_string(), ..Default::default() },
                BackendConfig { address: "10.0.0.3:8080".to_string(), ..Default::default() },
            ],
            keepalive: 0,
            srv_discover: None,
            health_check_interval_secs: 5,
            health_check_timeout_secs: 3,
        };
        let pool = UpstreamPool::new(&pool_config);
        let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();

        // Same IP always picks the same backend
        let backend1 = pool.get_next_backend(Some(&ip), None).unwrap();
        for _ in 0..10 {
            let backend = pool.get_next_backend(Some(&ip), None).unwrap();
            assert_eq!(backend.config.address, backend1.config.address);
        }
    }

    /// Validates the C5 fix: the ConsistentHash ring is built once and reused
    /// across calls when the (address, weight) signature is unchanged. We can't
    /// easily measure "no allocation" in a unit test, so we assert pointer
    /// equality on the cached `Arc<Option<ConsistentHashRing>>` — if the cache
    /// works, the second call returns the same Arc instance.
    #[test]
    fn test_consistent_hash_ring_is_cached_across_calls() {
        let pool_config = UpstreamPoolConfig {
            algorithm: LoadBalancingAlgorithm::ConsistentHash,
            backends: vec![
                BackendConfig { address: "10.0.0.1:8080".to_string(), ..Default::default() },
                BackendConfig { address: "10.0.0.2:8080".to_string(), ..Default::default() },
                BackendConfig { address: "10.0.0.3:8080".to_string(), ..Default::default() },
            ],
            keepalive: 0,
            srv_discover: None,
            health_check_interval_secs: 5,
            health_check_timeout_secs: 3,
        };
        let pool = UpstreamPool::new(&pool_config);
        let ip: std::net::IpAddr = "10.10.10.10".parse().unwrap();

        // First call: ring is built and stored
        let _ = pool.get_next_backend(Some(&ip), None).unwrap();
        let ring1 = pool.consistent_hash_ring.load_full();

        // Second call: ring must be reused (same Arc pointer)
        let _ = pool.get_next_backend(Some(&ip), None).unwrap();
        let ring2 = pool.consistent_hash_ring.load_full();

        assert!(
            Arc::ptr_eq(&ring1, &ring2),
            "ConsistentHash ring should be reused across calls when backends are unchanged"
        );
        assert!(ring1.is_some(), "ring should be populated after first call");
    }

    /// Distribution check for the Random LB algorithm.
    ///
    /// The previous implementation used `SystemTime::now().subsec_nanos()` as
    /// the entropy source, which under tight loops degenerates to bursts of
    /// adjacent indices (back-to-back samples often share the same nanosecond
    /// bucket modulo backend count). The fix uses the thread-local RNG.
    /// This test guards against any future regression that re-introduces
    /// a fixed-output entropy source.
    #[test]
    fn test_random_lb_visits_all_backends() {
        let pool_config = UpstreamPoolConfig {
            algorithm: LoadBalancingAlgorithm::Random,
            backends: vec![
                BackendConfig { address: "10.0.0.1:8080".to_string(), ..Default::default() },
                BackendConfig { address: "10.0.0.2:8080".to_string(), ..Default::default() },
                BackendConfig { address: "10.0.0.3:8080".to_string(), ..Default::default() },
                BackendConfig { address: "10.0.0.4:8080".to_string(), ..Default::default() },
            ],
            keepalive: 0,
            srv_discover: None,
            health_check_interval_secs: 5,
            health_check_timeout_secs: 3,
        };
        let pool = UpstreamPool::new(&pool_config);

        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            let b = pool.get_next_backend(None, None).unwrap();
            seen.insert(b.config.address.clone());
        }
        // 1000 picks across 4 backends — chance of missing one is ≈ 4 * (3/4)^1000,
        // i.e. astronomically small. If this ever flakes, the RNG is broken.
        assert_eq!(seen.len(), 4, "Random LB must hit every backend; saw {seen:?}");
    }
}
