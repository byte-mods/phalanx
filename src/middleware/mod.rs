/// Middleware layer providing caching, compression, rate limiting, and connection control.
///
/// Sub-modules:
/// - [`cache`] - Advanced two-tier (L1 memory + L2 disk) cache with Vary, stale-while-revalidate, and thundering herd protection
/// - [`compression`] - Gzip response compression
/// - [`brotli`] - Brotli response compression
/// - [`ratelimit`] - Per-IP and global token bucket rate limiting with optional Redis cluster sync
/// - [`connlimit`] - Zone-based connection and request rate limiting with flexible key extraction
///
/// This module also provides a simpler [`ResponseCache`] (L1-only, Moka-backed)
/// for lightweight caching needs.
pub mod brotli;
pub mod cache;
pub mod compression;
pub mod connlimit;
pub mod ratelimit;

pub use cache::{AdvancedCache, CacheEntry, build_cache_key};

use moka::future::Cache;
use std::time::{Duration, Instant};
use tracing::debug;

/// A high-performance in-memory response cache using Moka (a concurrent LFU cache).
/// Stores HTTP response bodies keyed by `method:host:path:query`.
/// Cacheable responses (GET 200) are stored for `time_to_live` seconds.
pub struct ResponseCache {
    store: Cache<String, CachedResponse>,
}

/// A cached HTTP response with status, body, content type, and expiration.
///
/// Stored inside [`ResponseCache`] and returned on cache hits. The
/// `expires_at` field provides a secondary TTL check beyond Moka's
/// built-in eviction.
#[derive(Clone, Debug)]
pub struct CachedResponse {
    /// HTTP status code of the cached response.
    pub status: u16,
    /// Response body bytes.
    pub body: bytes::Bytes,
    /// Value of the Content-Type header.
    pub content_type: String,
    /// Absolute time after which this entry should be treated as stale.
    pub expires_at: Instant,
}

impl ResponseCache {
    /// Creates a new response cache with the given maximum entry count and default TTL.
    ///
    /// # Arguments
    /// * `max_capacity` - Maximum number of entries before LFU eviction kicks in.
    /// * `ttl_secs` - Default time-to-live for entries in seconds.
    pub fn new(max_capacity: u64, ttl_secs: u64) -> Self {
        Self {
            store: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(Duration::from_secs(ttl_secs))
                .support_invalidation_closures()
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

    /// Removes a single entry by exact key. Returns true if the key was present.
    pub async fn purge(&self, key: &str) -> bool {
        let was_present = self.store.get(key).await.is_some();
        self.store.invalidate(key).await;
        was_present
    }

    /// Removes all entries whose key starts with `prefix`. Returns count removed.
    pub async fn purge_prefix(&self, prefix: &str) -> u64 {
        // Moka doesn't expose iteration, so we track an approximate count via a
        // before/after entry_count delta (best-effort, fine for admin use).
        let before = self.store.entry_count();
        let prefix_owned = prefix.to_string();
        if let Err(e) = self
            .store
            .invalidate_entries_if(move |k, _v| k.starts_with(&prefix_owned))
        {
            tracing::warn!("Failed to purge cache entries by prefix '{}': {}", prefix, e);
            return 0;
        }
        self.store.run_pending_tasks().await;
        let after = self.store.entry_count();
        before.saturating_sub(after)
    }

    /// Removes all entries from the cache.
    pub async fn purge_all(&self) {
        self.store.invalidate_all();
        self.store.run_pending_tasks().await;
    }

    /// Returns the current number of entries in the cache.
    pub fn entry_count(&self) -> u64 {
        self.store.entry_count()
    }
}
