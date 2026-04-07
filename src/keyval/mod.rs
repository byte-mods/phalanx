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
    pub fn new(default_ttl_secs: u64, redis_client: Option<redis::Client>) -> Arc<Self> {
        let default_ttl = if default_ttl_secs > 0 {
            Some(Duration::from_secs(default_ttl_secs))
        } else {
            None
        };
        let store = Arc::new(Self {
            inner: Arc::new(DashMap::new()),
            default_ttl,
            redis_client: redis_client.clone(),
        });

        if let Some(client) = redis_client {
            let store_clone = Arc::clone(&store);
            tokio::spawn(async move {
                if let Ok(mut pubsub) = client.get_async_pubsub().await {
                    if pubsub.subscribe("phalanx:keyval:sync").await.is_ok() {
                        let mut stream = pubsub.on_message();
                        use futures_util::StreamExt;
                        while let Some(msg) = stream.next().await {
                            if let Ok(payload) = msg.get_payload::<String>() {
                                // Simple text protocol: `SET:key:ttl_secs:value` or `DEL:key`
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
                }
            });
        }

        store
    }

    /// Get a value by key. Returns `None` if absent or expired.
    pub fn get(&self, key: &str) -> Option<String> {
        let entry = self.inner.get(key)?;
        if entry.is_expired() {
            drop(entry);
            self.inner.remove(key);
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
}
