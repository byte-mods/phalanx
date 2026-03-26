use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

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
}

impl BackendNode {
    pub fn new(config: BackendConfig) -> Self {
        Self {
            config,
            active_connections: AtomicUsize::new(0),
            is_healthy: AtomicBool::new(true),
            fail_count: AtomicU32::new(0),
            last_fail_at: AtomicU64::new(0),
            recovery_time: AtomicU64::new(0),
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
        }
    }

    /// Called by the active health check loop when it detects a DOWN→UP transition.
    /// Stamps `recovery_time` so slow-start can ramp the effective weight.
    pub fn record_recovery(&self) {
        let now = now_secs();
        self.recovery_time.store(now, Ordering::Release);
        self.fail_count.store(0, Ordering::Relaxed);
        self.is_healthy.store(true, Ordering::Release);
        info!(
            "Backend {} recovered (UP). Slow-start: {} secs",
            self.config.address, self.config.slow_start_secs
        );
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
pub struct UpstreamPool {
    pub algorithm: LoadBalancingAlgorithm,
    pub backends: ArcSwap<Vec<Arc<BackendNode>>>,
    /// Counter for Round-Robin / Weighted-RR selection
    round_robin_index: AtomicUsize,
    /// Keepalive connection pool
    pub connection_pool: Arc<crate::proxy::pool::ConnectionPool>,
}

impl UpstreamPool {
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
        }
    }

    /// Dynamically add a backend to this pool (used by Admin API + DNS discovery).
    pub fn add_backend(&self, config: BackendConfig) {
        let new_node = Arc::new(BackendNode::new(config));
        let mut current_backends = self.backends.load().as_ref().clone();
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

    /// Select the next healthy backend using the configured algorithm.
    /// Respects backup servers: they are only used when all primary backends are DOWN.
    /// Also enforces max_conns limits.
    pub fn get_next_backend(
        &self,
        client_ip: Option<&std::net::IpAddr>,
        ai_engine: Option<Arc<dyn crate::ai::AiRouter>>,
    ) -> Option<Arc<BackendNode>> {
        let current_backends = self.backends.load();

        // Split into primary and backup backends
        let healthy_primary: Vec<Arc<BackendNode>> = current_backends
            .iter()
            .filter(|b| b.is_healthy.load(Ordering::Acquire) && !b.config.backup)
            .cloned()
            .collect();

        let healthy = if healthy_primary.is_empty() {
            // Fallback to backup backends
            let backup: Vec<Arc<BackendNode>> = current_backends
                .iter()
                .filter(|b| b.is_healthy.load(Ordering::Acquire) && b.config.backup)
                .cloned()
                .collect();
            if backup.is_empty() {
                return None;
            }
            backup
        } else {
            healthy_primary
        };

        // Filter by max_conns (skip backends at capacity)
        let available: Vec<Arc<BackendNode>> = healthy
            .into_iter()
            .filter(|b| {
                b.config.max_conns == 0
                    || b.active_connections.load(Ordering::Relaxed) < b.config.max_conns as usize
            })
            .collect();

        if available.is_empty() {
            return None;
        }
        let healthy = available;

        match self.algorithm {
            // ── AI Predictive ──────────────────────────────────────────
            LoadBalancingAlgorithm::AIPredictive => {
                if let Some(ai) = ai_engine {
                    ai.predict_best_backend(&healthy)
                } else {
                    let idx =
                        self.round_robin_index.fetch_add(1, Ordering::Relaxed) % healthy.len();
                    Some(Arc::clone(&healthy[idx]))
                }
            }

            // ── Round Robin ───────────────────────────────────────────
            LoadBalancingAlgorithm::RoundRobin => {
                let idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed) % healthy.len();
                Some(Arc::clone(&healthy[idx]))
            }

            // ── Least Connections ─────────────────────────────────────
            LoadBalancingAlgorithm::LeastConnections => healthy
                .into_iter()
                .min_by_key(|b| b.active_connections.load(Ordering::Relaxed)),

            // ── Random ────────────────────────────────────────────────
            LoadBalancingAlgorithm::Random => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos();
                let idx = (ts as usize) % healthy.len();
                Some(Arc::clone(&healthy[idx]))
            }

            // ── IP Hash ───────────────────────────────────────────────
            LoadBalancingAlgorithm::IpHash => {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                if let Some(ip) = client_ip {
                    ip.hash(&mut hasher);
                } else {
                    now_secs().hash(&mut hasher);
                }
                let idx = (hasher.finish() as usize) % healthy.len();
                Some(Arc::clone(&healthy[idx]))
            }

            // ── Weighted Round Robin (with slow-start effective weight) ──
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

            // ── Least Time ──────────────────────────────────────────
            // Selects the backend with the fewest active connections,
            // breaking ties by preferring lower weight (proxy for lower latency).
            LoadBalancingAlgorithm::LeastTime => healthy
                .into_iter()
                .min_by(|a, b| {
                    let a_conns = a.active_connections.load(Ordering::Relaxed);
                    let b_conns = b.active_connections.load(Ordering::Relaxed);
                    a_conns
                        .cmp(&b_conns)
                        .then_with(|| a.effective_weight().cmp(&b.effective_weight()).reverse())
                }),

            // ── Consistent Hashing ────────────────────────────────────
            // Uses a virtual node ring so the same client IP always lands
            // on the same backend (unless it becomes unhealthy).
            LoadBalancingAlgorithm::ConsistentHash => {
                use std::hash::{Hash, Hasher};

                // Hash the client IP (or fall back to random ts if unknown)
                let key_hash: u64 = {
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    if let Some(ip) = client_ip {
                        ip.hash(&mut h);
                    } else {
                        now_secs().hash(&mut h);
                    }
                    h.finish()
                };

                // Build a sorted virtual-node ring from backend addresses.
                // Each backend gets `weight` virtual nodes spaced around a u64 ring.
                let virtual_nodes_per_backend = 40u32;
                let mut ring: Vec<(u64, usize)> = Vec::new();
                for (idx, backend) in healthy.iter().enumerate() {
                    let w = backend.effective_weight().max(1);
                    let slots = virtual_nodes_per_backend * w;
                    for slot in 0..slots {
                        let mut h = std::collections::hash_map::DefaultHasher::new();
                        format!("{}#{}", backend.config.address, slot).hash(&mut h);
                        ring.push((h.finish(), idx));
                    }
                }
                ring.sort_unstable_by_key(|(hash, _)| *hash);

                if ring.is_empty() {
                    return None;
                }

                // Binary search for the first ring position >= key_hash (wrap-around)
                let target_idx = match ring.binary_search_by_key(&key_hash, |(h, _)| *h) {
                    Ok(i) | Err(i) => i % ring.len(),
                };
                Some(Arc::clone(&healthy[ring[target_idx].1]))
            }
        }
    }
}

// ─── UpstreamManager ─────────────────────────────────────────────────────────

/// Global registry for all Upstream Pools, shared across Tokio tasks.
pub struct UpstreamManager {
    pools: DashMap<String, Arc<UpstreamPool>>,
}

impl UpstreamManager {
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
            tokio::spawn(health_check_loop(name.clone(), pool.clone()));

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

    pub fn get_pool(&self, key: &str) -> Option<Arc<UpstreamPool>> {
        self.pools.get(key).map(|p| Arc::clone(&p))
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

async fn health_check_loop(pool_name: String, pool: Arc<UpstreamPool>) {
    let interval = Duration::from_secs(5);
    info!("Starting health check loop for pool: {}", pool_name);

    loop {
        sleep(interval).await;

        let backends_snapshot = pool.backends.load().clone();

        for backend in backends_snapshot.iter() {
            let address = &backend.config.address;
            let was_healthy = backend.is_healthy.load(Ordering::Acquire);

            let now_healthy = if let Some(ref path) = backend.config.health_check_path {
                let url = format!("http://{}{}", address, path);
                let expected = backend.config.health_check_status;
                match reqwest_health_get(&url, expected).await {
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
                matches!(TcpStream::connect(address).await, Ok(_))
            };

            match (was_healthy, now_healthy) {
                (false, true) => {
                    // DOWN → UP transition: stamp recovery_time for slow-start
                    backend.record_recovery();
                    info!("Backend {} in pool {} is now UP", address, pool_name);
                }
                (true, false) => {
                    backend.is_healthy.store(false, Ordering::Release);
                    warn!("Backend {} in pool {} is DOWN", address, pool_name);
                }
                _ => {} // no change
            }
        }
    }
}

/// Perform an HTTP GET to `url`; return `Ok(true)` if status matches `expected`.
async fn reqwest_health_get(url: &str, expected_status: u16) -> Result<bool, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
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
}
