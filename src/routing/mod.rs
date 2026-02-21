use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

use crate::config::{BackendConfig, LoadBalancingAlgorithm, UpstreamPoolConfig};

/// Represents a single physical backend server and tracks its live state.
#[derive(Debug)]
pub struct BackendNode {
    /// Static configuration for this backend (address, weight, etc.)
    pub config: BackendConfig,
    /// Tracks the number of currently active TCP proxy connections to this node
    pub active_connections: AtomicUsize,
    /// Boolean flag updated by the background health check task (true = UP)
    pub is_healthy: std::sync::atomic::AtomicBool,
}

impl BackendNode {
    pub fn new(config: BackendConfig) -> Self {
        Self {
            config,
            active_connections: AtomicUsize::new(0),
            is_healthy: std::sync::atomic::AtomicBool::new(true),
        }
    }
}

/// A logical grouping of backends (e.g., all authentication servers)
/// with its own dedicated load balancing algorithm.
pub struct UpstreamPool {
    /// The algorithm to use for picking the next backend (e.g., RoundRobin)
    pub algorithm: LoadBalancingAlgorithm,
    /// The list of physical backend nodes in this pool
    pub backends: Vec<Arc<BackendNode>>,
    /// Counter used strictly for Round-Robin selection logic
    round_robin_index: AtomicUsize,
}

impl UpstreamPool {
    pub fn new(config: &UpstreamPoolConfig) -> Self {
        let backends = config
            .backends
            .iter()
            .map(|b| Arc::new(BackendNode::new(b.clone())))
            .collect();

        Self {
            algorithm: config.algorithm,
            backends,
            round_robin_index: AtomicUsize::new(0),
        }
    }

    /// Selects the next healthy backend node using the configured algorithm.
    /// Returns `None` if all nodes are marked as unhealthy.
    pub fn get_next_backend(
        &self,
        client_ip: Option<&std::net::IpAddr>,
        ai_engine: Option<Arc<dyn crate::ai::AiRouter>>,
    ) -> Option<Arc<BackendNode>> {
        // Find only backends that the health checker confirmed are alive
        let healthy_backends: Vec<_> = self
            .backends
            .iter()
            .filter(|b| b.is_healthy.load(Ordering::Acquire))
            .map(|b| Arc::clone(b))
            .collect();

        if healthy_backends.is_empty() {
            return None;
        }

        // Apply Load Balancing Algorithm
        match self.algorithm {
            LoadBalancingAlgorithm::AIPredictive => {
                if let Some(ai) = ai_engine {
                    ai.predict_best_backend(&healthy_backends)
                } else {
                    // Fallback if AI engine isn't provided (e.g. raw TCP proxy)
                    let index = self.round_robin_index.fetch_add(1, Ordering::Relaxed)
                        % healthy_backends.len();
                    Some(Arc::clone(&healthy_backends[index]))
                }
            }
            LoadBalancingAlgorithm::RoundRobin => {
                let index =
                    self.round_robin_index.fetch_add(1, Ordering::Relaxed) % healthy_backends.len();
                Some(Arc::clone(&healthy_backends[index]))
            }
            LoadBalancingAlgorithm::LeastConnections => healthy_backends
                .into_iter()
                .min_by_key(|b| b.active_connections.load(Ordering::Relaxed)),
            LoadBalancingAlgorithm::Random => {
                // simple pseudo random via timestamp for speed instead of importing rand here
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos();
                let index = (ts as usize) % healthy_backends.len();
                Some(Arc::clone(&healthy_backends[index]))
            }
            LoadBalancingAlgorithm::IpHash => {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                if let Some(ip) = client_ip {
                    ip.hash(&mut hasher);
                } else {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .subsec_nanos();
                    ts.hash(&mut hasher);
                }
                let index = (hasher.finish() as usize) % healthy_backends.len();
                Some(Arc::clone(&healthy_backends[index]))
            }
            LoadBalancingAlgorithm::WeightedRoundRobin => {
                let total_weight: u32 = healthy_backends.iter().map(|b| b.config.weight).sum();
                if total_weight == 0 {
                    return None;
                }

                let mut current_pos =
                    (self.round_robin_index.fetch_add(1, Ordering::Relaxed) as u32) % total_weight;

                for backend in healthy_backends {
                    if current_pos < backend.config.weight {
                        return Some(backend);
                    }
                    current_pos -= backend.config.weight;
                }
                None
            }
        }
    }
}

/// Global registry for all Upstream Pools, securely shared across thousands of Tokio worker tasks.
pub struct UpstreamManager {
    /// A high-performance lock-free concurrent hash map storing pool configurations.
    /// The Key is the Host name (e.g., "api.example.com") or the route definition.
    pools: DashMap<String, Arc<UpstreamPool>>,
}

impl UpstreamManager {
    /// Initializes the manager with the supplied configurations and automatically
    /// spawns asynchronous background health checkers for each pool.
    pub fn new(config: &crate::config::AppConfig) -> Self {
        let manager = Self {
            pools: DashMap::new(),
        };

        for (name, pool_config) in &config.upstreams {
            let pool = Arc::new(UpstreamPool::new(pool_config));
            manager.pools.insert(name.clone(), pool.clone());

            // Start an asynchronous health check task specific to this pool
            tokio::spawn(health_check_loop(name.clone(), pool));
        }

        manager
    }

    /// Finds an Upstream Pool by its config key (Host/Route mapping).
    pub fn get_pool(&self, key: &str) -> Option<Arc<UpstreamPool>> {
        self.pools.get(key).map(|p| Arc::clone(&p))
    }
}

/// A background asynchronous task that runs indefinitely, pinging the backends.
/// Every 5 seconds, it attempts a raw TCP connection to determine if the node is UP or DOWN.
async fn health_check_loop(pool_name: String, pool: Arc<UpstreamPool>) {
    let interval = Duration::from_secs(5);
    info!("Starting health check loop for pool: {}", pool_name);

    loop {
        sleep(interval).await;
        for backend in &pool.backends {
            let address = &backend.config.address;
            match TcpStream::connect(address).await {
                Ok(_) => {
                    let was_down = !backend.is_healthy.swap(true, Ordering::Release);
                    if was_down {
                        info!("Backend {} in pool {} is now UP", address, pool_name);
                    }
                }
                Err(e) => {
                    let was_up = backend.is_healthy.swap(false, Ordering::Release);
                    if was_up {
                        warn!("Backend {} in pool {} is DOWN: {}", address, pool_name, e);
                    }
                }
            }
        }
    }
}
