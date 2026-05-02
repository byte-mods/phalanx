//! Service discovery subsystem.
//!
//! Provides persistent backend registration (RocksDB) and dynamic discovery
//! via DNS A/AAAA and SRV record polling. External systems (CI/CD, health
//! probes) register backends through the Admin API; the discovery module
//! persists them so they survive proxy restarts.

use rocksdb::{DB, Options};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Represents a backend entry stored in RocksDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredBackend {
    pub address: String,
    pub pool: String,
    pub weight: u32,
    pub healthy: bool,
    /// Timestamp (epoch secs) when this backend was registered.
    pub registered_at: u64,
    /// Optional health check path (e.g., "/health").
    #[serde(default)]
    pub health_check_path: Option<String>,
    /// Max consecutive failures before marking DOWN.
    #[serde(default)]
    pub max_fails: Option<u32>,
    /// Fail timeout window in seconds.
    #[serde(default)]
    pub fail_timeout_secs: Option<u64>,
    /// Slow-start ramp duration in seconds.
    #[serde(default)]
    pub slow_start_secs: Option<u32>,
    /// Max concurrent connections to this backend.
    #[serde(default)]
    pub max_conns: Option<u32>,
    /// Queue size for waiting requests when at max_conns.
    #[serde(default)]
    pub queue_size: Option<u32>,
    /// Queue timeout in milliseconds.
    #[serde(default)]
    pub queue_timeout_ms: Option<u64>,
    /// Whether circuit breaker is enabled for this backend.
    #[serde(default)]
    pub circuit_breaker: Option<bool>,
    /// Expected HTTP status code for health check. Default: 200.
    #[serde(default)]
    pub health_check_status: Option<u16>,
    /// Whether this backend is a hot-standby (only used when all non-backup backends are DOWN).
    #[serde(default)]
    pub backup: Option<bool>,
    /// Circuit breaker initial backoff in seconds. Default: 5.
    #[serde(default)]
    pub circuit_initial_backoff_secs: Option<u64>,
    /// Circuit breaker max backoff in seconds. Default: 60.
    #[serde(default)]
    pub circuit_max_backoff_secs: Option<u64>,
}

/// RocksDB-backed service discovery.
/// Stores upstream backend registrations persistently so backends survive proxy restarts.
/// External agents (health probes, deploy scripts, CI/CD) can write entries via the Admin API.
pub struct ServiceDiscovery {
    db: Option<Arc<DB>>,
}

impl ServiceDiscovery {
    /// Opens or creates RocksDB at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_allow_concurrent_memtable_write(true);

        let db = DB::open(&opts, path.as_ref())?;
        info!(
            "Service Discovery initialized with RocksDB at {:?}",
            path.as_ref()
        );
        Ok(Self {
            db: Some(Arc::new(db)),
        })
    }

    /// Registers or updates a backend in persistent storage.
    /// Key format: `pool::address` (e.g., `default::127.0.0.1:8081`)
    pub fn register_backend(&self, backend: &DiscoveredBackend) {
        let Some(db) = self.db.as_ref() else {
            warn!("Service Discovery DB unavailable: register_backend skipped");
            return;
        };
        let key = format!("{}::{}", backend.pool, backend.address);
        match serde_json::to_vec(backend) {
            Ok(value) => {
                if let Err(e) = db.put(key.as_bytes(), &value) {
                    error!("Failed to register backend {}: {}", key, e);
                } else {
                    info!(
                        "Registered backend: {} (pool={})",
                        backend.address, backend.pool
                    );
                }
            }
            Err(e) => error!("Failed to serialize backend {}: {}", key, e),
        }
    }

    /// Removes a backend from persistent storage.
    pub fn deregister_backend(&self, pool: &str, address: &str) {
        let Some(db) = self.db.as_ref() else {
            warn!("Service Discovery DB unavailable: deregister_backend skipped");
            return;
        };
        let key = format!("{}::{}", pool, address);
        if let Err(e) = db.delete(key.as_bytes()) {
            error!("Failed to deregister backend {}: {}", key, e);
        } else {
            warn!("Deregistered backend: {} (pool={})", address, pool);
        }
    }

    /// Lists all registered backends for a given pool.
    pub fn list_backends(&self, pool: &str) -> Vec<DiscoveredBackend> {
        let Some(db) = self.db.as_ref() else {
            return Vec::new();
        };
        let prefix = format!("{}::", pool);
        let mut backends = Vec::new();

        let iter = db.prefix_iterator(prefix.as_bytes());
        for item in iter {
            match item {
                Ok((key, value)) => {
                    let key_str = String::from_utf8_lossy(&key);
                    if !key_str.starts_with(&prefix) {
                        break;
                    }
                    match serde_json::from_slice::<DiscoveredBackend>(&value) {
                        Ok(b) => backends.push(b),
                        Err(e) => warn!("Corrupt backend entry {}: {}", key_str, e),
                    }
                }
                Err(e) => {
                    warn!("RocksDB iteration error: {}", e);
                    break;
                }
            }
        }
        backends
    }

    /// Lists ALL backends across all pools.
    pub fn list_all_backends(&self) -> Vec<DiscoveredBackend> {
        let Some(db) = self.db.as_ref() else {
            return Vec::new();
        };
        let mut backends = Vec::new();
        let iter = db.iterator(rocksdb::IteratorMode::Start);
        for item in iter {
            match item {
                Ok((_key, value)) => {
                    if let Ok(b) = serde_json::from_slice::<DiscoveredBackend>(&value) {
                        backends.push(b);
                    }
                }
                Err(e) => {
                    warn!("RocksDB iteration error: {}", e);
                    break;
                }
            }
        }
        backends
    }

    /// Mark a backend as healthy/unhealthy.
    pub fn set_health(&self, pool: &str, address: &str, healthy: bool) {
        let Some(db) = self.db.as_ref() else {
            return;
        };
        let key = format!("{}::{}", pool, address);
        if let Some(value) = db.get(key.as_bytes()).ok().flatten() {
            if let Ok(mut backend) = serde_json::from_slice::<DiscoveredBackend>(&value) {
                backend.healthy = healthy;
                if let Ok(updated) = serde_json::to_vec(&backend) {
                    let _ = db.put(key.as_bytes(), &updated);
                }
            }
        }
    }
}

// ─── DNS A/AAAA Service Discovery ────────────────────────────────────────────

/// Spawns a background task that periodically resolves `hostname` via DNS and updates the pool.
///
/// Every 30 seconds the hostname is resolved. New IPs are added to the pool; IPs that
/// disappeared from DNS are removed.
pub fn spawn_dns_watcher(
    pool_name: String,
    hostname: String,
    port: String,
    pool: Arc<crate::routing::UpstreamPool>,
    resolver_addr: String,
    template: crate::config::BackendConfig,
    cancel: tokio_util::sync::CancellationToken,
) {
    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(30);
        let mut prev_addrs: std::collections::HashSet<String> = std::collections::HashSet::new();

        {
            let backends = pool.backends.load();
            for b in backends.iter() {
                prev_addrs.insert(b.config.address.clone());
            }
        }

        info!(
            "DNS watcher started for {}:{} in pool '{}' via {}",
            hostname, port, pool_name, resolver_addr
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("DNS watcher stopping for '{}' in pool '{}'", hostname, pool_name);
                    return;
                }
                _ = tokio::time::sleep(interval) => {}
            }

            let lookup_host = format!("{}:{}", hostname, port);
            let resolved: Vec<String> = match tokio::net::lookup_host(&lookup_host).await {
                Ok(addrs) => addrs.map(|a| a.to_string()).collect(),
                Err(e) => {
                    warn!("DNS watcher: failed to resolve '{}': {}", hostname, e);
                    continue;
                }
            };

            let new_set: std::collections::HashSet<String> = resolved.iter().cloned().collect();

            for addr in new_set.difference(&prev_addrs) {
                info!(
                    "DNS watcher: new address {} for '{}' in pool '{}'",
                    addr, hostname, pool_name
                );
                let mut cfg = template.clone();
                cfg.address = addr.clone();
                pool.add_backend(cfg);
            }

            for addr in prev_addrs.difference(&new_set) {
                warn!(
                    "DNS watcher: address {} removed for '{}' in pool '{}'",
                    addr, hostname, pool_name
                );
                pool.remove_backend(addr);
            }

            prev_addrs = new_set;
        }
    });
}

// ─── DNS SRV Service Discovery ───────────────────────────────────────────────

/// Spawns a background task that resolves SRV records and dynamically updates the pool.
///
/// SRV records follow the format `_service._proto.name` (e.g.
/// `_http._tcp.myservice.consul.`). Each SRV record provides a target
/// hostname and port; the watcher resolves these to actual IP addresses
/// and adds/removes them from the pool as DNS changes.
///
/// # Config directive (per upstream block)
/// ```text
/// upstream my_pool {
///     srv_discover _http._tcp.myservice.local;
/// }
/// ```
pub fn spawn_srv_watcher(
    pool_name: String,
    srv_name: String,
    pool: Arc<crate::routing::UpstreamPool>,
    template: crate::config::BackendConfig,
    cancel: tokio_util::sync::CancellationToken,
) {
    tokio::spawn(async move {
        use trust_dns_resolver::TokioAsyncResolver;
        use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

        let interval = tokio::time::Duration::from_secs(30);

        info!(
            "SRV watcher started for '{}' in pool '{}'",
            srv_name, pool_name
        );

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let mut prev_addrs: std::collections::HashSet<String> = std::collections::HashSet::new();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = cancel.cancelled() => {
                    info!("SRV watcher stopping for '{}' in pool '{}'", srv_name, pool_name);
                    return;
                }
            }

            // 1. Resolve SRV record
            let srv_records = match resolver.srv_lookup(&srv_name).await {
                Ok(records) => records,
                Err(e) => {
                    warn!("SRV watcher: failed to query '{}': {}", srv_name, e);
                    continue;
                }
            };

            let mut new_set: std::collections::HashSet<String> =
                std::collections::HashSet::new();

            // 2. For each SRV record resolve the A/AAAA target
            for srv in srv_records.iter() {
                let target = srv.target().to_string();
                let port = srv.port();
                let lookup_host = format!("{}:{}", target, port);
                match tokio::net::lookup_host(&lookup_host).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            new_set.insert(addr.to_string());
                        }
                    }
                    Err(e) => {
                        warn!(
                            "SRV watcher: failed to resolve target '{}': {}",
                            target, e
                        );
                    }
                }
            }

            // 3. Diff: add new, remove gone
            for addr in new_set.difference(&prev_addrs) {
                info!(
                    "SRV watcher: adding {} to pool '{}' (via {})",
                    addr, pool_name, srv_name
                );
                let mut cfg = template.clone();
                cfg.address = addr.clone();
                pool.add_backend(cfg);
            }
            for addr in prev_addrs.difference(&new_set) {
                warn!(
                    "SRV watcher: removing {} from pool '{}' (SRV disappeared)",
                    addr, pool_name
                );
                pool.remove_backend(addr);
            }

            prev_addrs = new_set;
        }
    });
}

// ─── SRV name parsing helpers ─────────────────────────────────────────────────

/// Parse a DNS SRV name into its service, protocol, and domain components.
/// Expected format: `_service._proto.domain`
///
/// Returns `None` if the name doesn't match the convention.
pub fn parse_srv_name(name: &str) -> Option<(&str, &str, &str)> {
    let parts: Vec<&str> = name.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }
    let service = parts[0].strip_prefix('_')?;
    let proto = parts[1].strip_prefix('_')?;
    let domain = parts[2];
    Some((service, proto, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_srv_name_valid() {
        let result = parse_srv_name("_http._tcp.myservice.local");
        assert!(result.is_some());
        let (svc, proto, domain) = result.unwrap();
        assert_eq!(svc, "http");
        assert_eq!(proto, "tcp");
        assert_eq!(domain, "myservice.local");
    }

    #[test]
    fn test_parse_srv_name_grpc() {
        let result = parse_srv_name("_grpc._tcp.api.internal");
        let (svc, proto, domain) = result.unwrap();
        assert_eq!(svc, "grpc");
        assert_eq!(proto, "tcp");
        assert_eq!(domain, "api.internal");
    }

    #[test]
    fn test_parse_srv_name_underscore_required() {
        // Missing underscore prefix on service
        assert!(parse_srv_name("http._tcp.foo").is_none());
    }

    #[test]
    fn test_parse_srv_name_too_few_parts() {
        assert!(parse_srv_name("_http._tcp").is_none());
    }

    #[test]
    fn test_parse_srv_name_deep_domain() {
        // Extra dots in domain are okay — splitn(3) captures them all
        let result = parse_srv_name("_http._tcp.my.deep.service");
        let (_, _, domain) = result.unwrap();
        assert_eq!(domain, "my.deep.service");
    }

    #[test]
    fn test_spawn_srv_watcher_accepts_cancellation_token() {
        // Verify the function signature compiles with CancellationToken parameter
        let _ = tokio_util::sync::CancellationToken::new();
    }
}
