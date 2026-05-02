//! # Keyval Store
//!
//! An in-memory key-value store backed by `DashMap` with per-entry TTL.
//! Equivalent to NGINX Plus `keyval_zone` / `keyval` directives.
//!
//! ## Usage
//! - WAF ban list: store banned IPs as keys with a TTL.
//! - Route conditional logic: look up custom flags (e.g. feature flags, A/B groups).
//! - Admin API: read/write/delete arbitrary key-value pairs via HTTP.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ─── Entry ───────────────────────────────────────────────────────────────────

/// A single entry in the keyval store, with an optional expiry.
#[derive(Debug, Clone)]
struct Entry {
    value: String,
    /// Absolute expiry instant. `None` means the entry never expires.
    expires_at: Option<Instant>,
}

impl Entry {
    /// Returns `true` if this entry has a set expiry time and it has passed.
    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Instant::now() > exp)
            .unwrap_or(false)
    }
}

// ─── KeyvalStore ─────────────────────────────────────────────────────────────

/// Thread-safe in-memory key-value store with optional per-entry TTL.
///
/// Entries are lazily evicted — expired entries are skipped on reads and
/// explicitly removed on writes.
#[derive(Clone)]
pub struct KeyvalStore {
    inner: Arc<DashMap<String, Entry>>,
    /// Default TTL for entries when none is specified. `None` = no expiry.
    default_ttl: Option<Duration>,
    /// Optional Redis client to sync the KeyvalStore state across the cluster.
    redis_client: Option<redis::Client>,
}

impl KeyvalStore {
    /// Create a new store. `default_ttl_secs = 0` disables TTL by default.
    ///
    /// Call `spawn_background_tasks()` after construction to start the periodic
    /// eviction sweep and Redis pubsub listener (requires a Tokio runtime).
    pub fn new(default_ttl_secs: u64, redis_client: Option<redis::Client>) -> Arc<Self> {
        let default_ttl = if default_ttl_secs > 0 {
            Some(Duration::from_secs(default_ttl_secs))
        } else {
            None
        };
        Arc::new(Self {
            inner: Arc::new(DashMap::new()),
            default_ttl,
            redis_client: redis_client.clone(),
        })
    }

    /// Spawn background tasks: periodic eviction sweep (60s) and Redis pubsub
    /// listener for cross-node sync. Requires a running Tokio runtime.
    pub fn spawn_background_tasks(self: &Arc<Self>) {
        self.spawn_eviction_sweep(Duration::from_secs(60));
        self.spawn_redis_listener();
    }

    /// Spawn the periodic eviction sweep with the given interval.
    ///
    /// Each tick calls `evict_expired()`, which acquires per-shard locks
    /// via `DashMap::retain`. The lock is held only for the duration of
    /// the retain and never across an await point.
    fn spawn_eviction_sweep(self: &Arc<Self>, interval_dur: Duration) {
        let sweep_store = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_dur);
            loop {
                interval.tick().await;
                sweep_store.evict_expired();
            }
        });
    }

    /// Spawn the Redis pubsub listener for cross-node keyval sync.
    ///
    /// Wraps the pubsub subscription in a reconnection loop with capped
    /// exponential backoff so transient Redis failures (restart, network
    /// blip) don't permanently desync the store from the cluster.
    fn spawn_redis_listener(self: &Arc<Self>) {
        if let Some(client) = &self.redis_client {
            let store_clone = Arc::clone(self);
            let client = client.clone();
            tokio::spawn(async move {
                const BASE_MS: u64 = 100;
                const MAX_MS: u64 = 30_000;
                let mut backoff_ms: u64 = 0;
                loop {
                    match client.get_async_pubsub().await {
                        Ok(mut pubsub) => {
                            if pubsub.subscribe("phalanx:keyval:sync").await.is_ok() {
                                // Connection established — reset backoff.
                                backoff_ms = 0;
                                let mut stream = pubsub.on_message();
                                use futures_util::StreamExt;
                                while let Some(msg) = stream.next().await {
                                    if let Ok(payload) = msg.get_payload::<String>() {
                                        if let Some((cmd, rest)) = payload.split_once(':') {
                                            match cmd {
                                                "SET" => {
                                                    if let Some((key, val_ttl)) = rest.split_once(':') {
                                                        if let Some((ttl_str, value)) = val_ttl.split_once(':') {
                                                            let ttl = if ttl_str.is_empty() { None } else { ttl_str.parse().ok() };
                                                            store_clone.set_local(key.to_string(), value.to_string(), ttl);
                                                        }
                                                    }
                                                }
                                                "DEL" => {
                                                    store_clone.delete_local(rest);
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                            }
                            // Stream ended — connection dropped.
                        }
                        Err(_) => {
                            // Could not connect.
                        }
                    }
                    backoff_ms = next_backoff(backoff_ms, BASE_MS, MAX_MS);
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                }
            });
        }
    }

    /// Get a value by key. Returns `None` if absent or expired.
    pub fn get(&self, key: &str) -> Option<String> {
        let entry = self.inner.get(key)?;
        if entry.is_expired() {
            drop(entry);
            // `remove_if` checks expiry atomically within the shard lock,
            // preventing a TOCTOU race where another thread inserts a fresh
            // entry between our expiry check and a blind `remove()`.
            self.inner.remove_if(key, |_, v| v.is_expired());
            return None;
        }
        Some(entry.value.clone())
    }

    /// Insert or update a key with an optional explicit TTL (in seconds).
    /// If `ttl_secs` is `None`, the store's `default_ttl` is used.
    pub fn set(&self, key: String, value: String, ttl_secs: Option<u64>) {
        self.set_local(key.clone(), value.clone(), ttl_secs);
        
        if let Some(client) = &self.redis_client {
            let client_clone = client.clone();
            let ttl_str = ttl_secs.map(|t| t.to_string()).unwrap_or_default();
            let payload = format!("SET:{}:{}:{}", key, ttl_str, value);
            tokio::spawn(async move {
                if let Ok(mut con) = client_clone.get_multiplexed_async_connection().await {
                    use redis::AsyncCommands;
                    let _: redis::RedisResult<()> = con.publish("phalanx:keyval:sync", payload).await;
                }
            });
        }
    }

    /// Local setter that doesn't trigger a broadcast loop.
    pub fn set_local(&self, key: String, value: String, ttl_secs: Option<u64>) {
        let expires_at = ttl_secs
            .map(Duration::from_secs)
            .or(self.default_ttl)
            .map(|d| Instant::now() + d);
        self.inner.insert(key, Entry { value, expires_at });
    }

    /// Delete a key. Returns `true` if the key existed.
    pub fn delete(&self, key: &str) -> bool {
        let existed = self.delete_local(key);
        
        if existed {
            if let Some(client) = &self.redis_client {
                let client_clone = client.clone();
                let payload = format!("DEL:{}", key);
                tokio::spawn(async move {
                    if let Ok(mut con) = client_clone.get_multiplexed_async_connection().await {
                        use redis::AsyncCommands;
                        let _: redis::RedisResult<()> = con.publish("phalanx:keyval:sync", payload).await;
                    }
                });
            }
        }
        
        existed
    }

    /// Local delete that doesn't trigger a broadcast loop.
    pub fn delete_local(&self, key: &str) -> bool {
        self.inner.remove(key).is_some()
    }

    /// List all non-expired entries as `(key, value)` pairs.
    pub fn list(&self) -> Vec<(String, String)> {
        let now = Instant::now();
        self.inner
            .iter()
            .filter(|e| e.value().expires_at.map(|exp| exp > now).unwrap_or(true))
            .map(|e| (e.key().clone(), e.value().value.clone()))
            .collect()
    }

    /// Returns `true` if the key exists and is not expired.
    /// Useful for WAF ban-list checks.
    pub fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }
}

// ─── Backoff helper ──────────────────────────────────────────────────────────

/// Compute the next reconnect backoff: double, capped at `max`.
/// Resets to `base` on a successful (zero) connection.
fn next_backoff(current_ms: u64, base_ms: u64, max_ms: u64) -> u64 {
    if current_ms == 0 {
        base_ms
    } else {
        (current_ms * 2).min(max_ms)
    }
}

impl KeyvalStore {
    /// Remove all expired entries. Call periodically to prevent unbounded growth.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.inner
            .retain(|_, v| v.expires_at.map(|exp| exp > now).unwrap_or(true));
    }
}

// ─── Serialisable API types ───────────────────────────────────────────────────

/// Request body for `POST /api/keyval/{key}`.
#[derive(Debug, Deserialize, Serialize)]
pub struct KeyvalSetRequest {
    pub value: String,
    /// Optional TTL in seconds. Omit to use the store's default TTL.
    pub ttl_secs: Option<u64>,
}

/// Response for `GET /api/keyval/{key}`.
#[derive(Debug, Serialize)]
pub struct KeyvalGetResponse {
    pub key: String,
    pub value: String,
}

/// Entry in the list response for `GET /api/keyval`.
#[derive(Debug, Serialize)]
pub struct KeyvalListEntry {
    pub key: String,
    pub value: String,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_set_and_get() {
        let store = KeyvalStore::new(0, None);
        store.set("foo".into(), "bar".into(), None);
        assert_eq!(store.get("foo"), Some("bar".to_string()));
    }

    #[tokio::test]
    async fn test_get_missing_key_returns_none() {
        let store = KeyvalStore::new(0, None);
        assert_eq!(store.get("missing"), None);
    }

    #[tokio::test]
    async fn test_delete_existing_key() {
        let store = KeyvalStore::new(0, None);
        store.set("k".into(), "v".into(), None);
        assert!(store.delete("k"));
        assert_eq!(store.get("k"), None);
    }

    #[tokio::test]
    async fn test_delete_missing_key_returns_false() {
        let store = KeyvalStore::new(0, None);
        assert!(!store.delete("nope"));
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        let store = KeyvalStore::new(0, None);
        // Set with a 0-second TTL — immediately expired
        store.set("exp".into(), "val".into(), Some(0));
        // Sleep to ensure TTL is past
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(store.get("exp"), None);
    }

    #[tokio::test]
    async fn test_no_expiry_entry_persists() {
        let store = KeyvalStore::new(0, None);
        store.set("perm".into(), "value".into(), None);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(store.get("perm"), Some("value".to_string()));
    }

    #[tokio::test]
    async fn test_contains() {
        let store = KeyvalStore::new(0, None);
        store.set("ip".into(), "banned".into(), None);
        assert!(store.contains("ip"));
        assert!(!store.contains("other"));
    }

    #[tokio::test]
    async fn test_list_returns_all_live_entries() {
        let store = KeyvalStore::new(0, None);
        store.set("a".into(), "1".into(), None);
        store.set("b".into(), "2".into(), None);
        let list = store.list();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn test_list_excludes_expired() {
        let store = KeyvalStore::new(0, None);
        store.set("live".into(), "yes".into(), None);
        store.set("dead".into(), "no".into(), Some(0));
        std::thread::sleep(Duration::from_millis(5));
        let list = store.list();
        assert!(list.iter().all(|(k, _)| k == "live"));
    }

    #[tokio::test]
    async fn test_evict_expired() {
        let store = KeyvalStore::new(0, None);
        store.set("gone".into(), "val".into(), Some(0));
        std::thread::sleep(Duration::from_millis(5));
        store.evict_expired();
        assert_eq!(store.inner.len(), 0);
    }

    #[tokio::test]
    async fn test_overwrite_key() {
        let store = KeyvalStore::new(0, None);
        store.set("x".into(), "first".into(), None);
        store.set("x".into(), "second".into(), None);
        assert_eq!(store.get("x"), Some("second".to_string()));
    }

    /// `remove_if` must not delete a fresh entry inserted by another thread
    /// between our expiry read and the conditional remove.
    #[tokio::test]
    async fn test_get_expired_remove_if_does_not_delete_fresh_entry() {
        let store = KeyvalStore::new(0, None);

        // Set an expired entry, then immediately overwrite with a fresh one.
        store.set_local("key".into(), "expired".into(), Some(0));
        std::thread::sleep(Duration::from_millis(10));
        store.set_local("key".into(), "fresh".into(), Some(3600));

        // get() must return the fresh value and leave it intact.
        assert_eq!(store.get("key"), Some("fresh".to_string()));
        assert_eq!(store.get("key"), Some("fresh".to_string()));
    }

    #[test]
    fn test_next_backoff() {
        // Reset to base on clean connection.
        assert_eq!(next_backoff(0, 100, 30_000), 100);
        // Double on failure.
        assert_eq!(next_backoff(100, 100, 30_000), 200);
        assert_eq!(next_backoff(200, 100, 30_000), 400);
        // Cap at max.
        assert_eq!(next_backoff(16_000, 100, 30_000), 30_000);
        assert_eq!(next_backoff(30_000, 100, 30_000), 30_000);
    }

    /// The background eviction sweep must purge expired entries without
    /// any explicit reads or manual calls to evict_expired().
    #[tokio::test]
    async fn test_background_eviction_sweep() {
        let store = KeyvalStore::new(0, None);

        // Insert an entry that expires within the sweep window.
        store.set_local("ephemeral".into(), "val".into(), Some(0));
        std::thread::sleep(Duration::from_millis(5));

        // Start a fast sweep (50ms) and wait for it to fire.
        store.spawn_eviction_sweep(Duration::from_millis(50));
        tokio::time::sleep(Duration::from_millis(120)).await;

        assert_eq!(store.get("ephemeral"), None);
        assert_eq!(store.inner.len(), 0);
    }

    /// Concurrent get() on an expired key must not wipe a fresh entry
    /// inserted by a racing writer.
    #[tokio::test]
    async fn test_get_toc_tou_race() {
        let store = KeyvalStore::new(0, None);

        store.set_local("shared".into(), "expiring".into(), Some(0));
        std::thread::sleep(Duration::from_millis(10));

        let store_a = store.clone();
        let store_b = store.clone();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b1 = barrier.clone();
        let b2 = barrier.clone();

        let t_a = std::thread::spawn(move || {
            b1.wait();
            store_a.get("shared")
        });

        let t_b = std::thread::spawn(move || {
            b2.wait();
            store_b.set_local("shared".into(), "fresh".into(), Some(3600));
        });

        t_a.join().unwrap();
        t_b.join().unwrap();

        // The fresh entry must survive the race.
        assert_eq!(store.get("shared"), Some("fresh".to_string()));
    }
}
