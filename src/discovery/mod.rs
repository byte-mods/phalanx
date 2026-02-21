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
}

/// RocksDB-backed service discovery.
/// Stores upstream backend registrations persistently so backends survive proxy restarts.
/// External agents (health probes, deploy scripts, CI/CD) can write entries via the Admin API.
pub struct ServiceDiscovery {
    db: Arc<DB>,
}

impl ServiceDiscovery {
    /// Opens or creates RocksDB at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        // Optimize for point lookups (backend addresses are short keys)
        opts.set_allow_concurrent_memtable_write(true);

        let db =
            DB::open(&opts, path.as_ref()).expect("Failed to open RocksDB for Service Discovery");
        info!(
            "Service Discovery initialized with RocksDB at {:?}",
            path.as_ref()
        );
        Self { db: Arc::new(db) }
    }

    /// Registers or updates a backend in persistent storage.
    /// Key format: `pool::address` (e.g., `default::127.0.0.1:8081`)
    pub fn register_backend(&self, backend: &DiscoveredBackend) {
        let key = format!("{}::{}", backend.pool, backend.address);
        match serde_json::to_vec(backend) {
            Ok(value) => {
                if let Err(e) = self.db.put(key.as_bytes(), &value) {
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
        let key = format!("{}::{}", pool, address);
        if let Err(e) = self.db.delete(key.as_bytes()) {
            error!("Failed to deregister backend {}: {}", key, e);
        } else {
            warn!("Deregistered backend: {} (pool={})", address, pool);
        }
    }

    /// Lists all registered backends for a given pool.
    pub fn list_backends(&self, pool: &str) -> Vec<DiscoveredBackend> {
        let prefix = format!("{}::", pool);
        let mut backends = Vec::new();

        let iter = self.db.prefix_iterator(prefix.as_bytes());
        for item in iter {
            match item {
                Ok((key, value)) => {
                    let key_str = String::from_utf8_lossy(&key);
                    if !key_str.starts_with(&prefix) {
                        break; // Past our prefix
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
        let mut backends = Vec::new();
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);
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
        let key = format!("{}::{}", pool, address);
        if let Some(value) = self.db.get(key.as_bytes()).ok().flatten() {
            if let Ok(mut backend) = serde_json::from_slice::<DiscoveredBackend>(&value) {
                backend.healthy = healthy;
                if let Ok(updated) = serde_json::to_vec(&backend) {
                    let _ = self.db.put(key.as_bytes(), &updated);
                }
            }
        }
    }
}
