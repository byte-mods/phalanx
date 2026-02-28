pub mod compression;
pub mod ratelimit;

use moka::future::Cache;
use std::time::{Duration, Instant};
use tracing::debug;

/// A high-performance in-memory response cache using Moka (a concurrent LFU cache).
/// Stores HTTP response bodies keyed by `method:host:path:query`.
/// Cacheable responses (GET 200) are stored for `time_to_live` seconds.
pub struct ResponseCache {
    store: Cache<String, CachedResponse>,
}

/// A cached HTTP response with status and body.
#[derive(Clone, Debug)]
pub struct CachedResponse {
    pub status: u16,
    pub body: bytes::Bytes,
    pub content_type: String,
    pub expires_at: Instant,
}

impl ResponseCache {
    pub fn new(max_capacity: u64, ttl_secs: u64) -> Self {
        Self {
            store: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(Duration::from_secs(ttl_secs))
                .build(),
        }
    }

    /// Generates a cache key from request components.
    pub fn cache_key(method: &str, host: &str, path: &str, query: Option<&str>) -> String {
        match query {
            Some(q) => format!("{}:{}:{}?{}", method, host, path, q),
            None => format!("{}:{}:{}", method, host, path),
        }
    }

    /// Attempts to retrieve a cached response.
    pub async fn get(&self, key: &str) -> Option<CachedResponse> {
        let hit = self.store.get(key).await;
        if let Some(entry) = hit {
            if Instant::now() >= entry.expires_at {
                self.store.invalidate(key).await;
                return None;
            }
            debug!("Cache HIT: {}", key);
            return Some(entry);
        }
        None
    }

    /// Stores a response in the cache.
    pub async fn insert_with_ttl(&self, key: String, mut response: CachedResponse, ttl_secs: u64) {
        response.expires_at = Instant::now() + Duration::from_secs(ttl_secs.max(1));
        debug!("Cache STORE: {} ({} bytes)", key, response.body.len());
        self.store.insert(key, response).await;
    }

    /// Returns the current number of entries in the cache.
    pub fn entry_count(&self) -> u64 {
        self.store.entry_count()
    }
}
