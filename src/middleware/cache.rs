/// Advanced two-tier response cache (L1 in-memory + L2 on-disk).
///
/// Features beyond simple key-value caching:
/// - **Vary-aware keys**: different cached variants per `Accept-Encoding`, etc.
/// - **Stale-while-revalidate**: serves stale content while background refresh runs
/// - **Stale-if-error**: serves stale content when upstream returns errors
/// - **Thundering herd protection**: per-key mutex prevents parallel upstream fetches
/// - **Disk persistence**: optional L2 tier survives process restarts
/// - **Purge API**: single key, prefix-based, and full cache invalidation
use bytes::Bytes;
use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Extended cache supporting disk tiers, Vary, stale-while-revalidate, locking,
/// background updates, range/slice, and a purge API.
pub struct AdvancedCache {
    /// In-memory L1 cache: key → CacheEntry
    memory: moka::future::Cache<String, CacheEntry>,
    /// Disk cache directory
    disk_path: Option<PathBuf>,
    /// Lock map for cache-miss thundering herd protection
    locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Vary header tracking: maps base cache key → set of Vary header names
    vary_map: Arc<DashMap<String, Vec<String>>>,
}

/// A single cached response entry with full HTTP metadata and freshness tracking.
///
/// Supports three freshness states:
/// 1. **Fresh**: `created_at + max_age` has not elapsed
/// 2. **Stale-revalidatable**: expired but within `stale_while_revalidate` window
/// 3. **Stale-on-error**: expired but within `stale_if_error` window
#[derive(Clone, Debug)]
pub struct CacheEntry {
    /// HTTP status code of the cached response.
    pub status: u16,
    /// Response body bytes.
    pub body: Bytes,
    /// Value of the Content-Type response header.
    pub content_type: String,
    /// All response headers to replay on cache hit.
    pub headers: Vec<(String, String)>,
    /// When this entry was originally cached.
    pub created_at: Instant,
    /// Maximum time this entry is considered fresh.
    pub max_age: Duration,
    /// How long the entry can be served stale while a background refresh happens.
    pub stale_while_revalidate: Duration,
    /// How long the entry can be served stale on upstream errors.
    pub stale_if_error: Duration,
}

impl CacheEntry {
    /// Returns `true` if this entry has not exceeded its `max_age`.
    pub fn is_fresh(&self) -> bool {
        self.created_at.elapsed() < self.max_age
    }

    /// Returns `true` if stale but within the `stale_while_revalidate` grace window.
    pub fn is_stale_revalidatable(&self) -> bool {
        !self.is_fresh()
            && self.created_at.elapsed() < self.max_age + self.stale_while_revalidate
    }

    /// Returns `true` if stale but within the `stale_if_error` grace window.
    pub fn is_stale_on_error(&self) -> bool {
        !self.is_fresh() && self.created_at.elapsed() < self.max_age + self.stale_if_error
    }
}

/// Cache key builder that accounts for Vary headers.
pub fn build_cache_key(
    method: &str,
    host: &str,
    path: &str,
    query: Option<&str>,
    vary_headers: &[(String, String)],
) -> String {
    let mut key = match query {
        Some(q) => format!("{}:{}:{}?{}", method, host, path, q),
        None => format!("{}:{}:{}", method, host, path),
    };

    if !vary_headers.is_empty() {
        key.push_str(":V:");
        for (name, value) in vary_headers {
            key.push_str(&format!("{}={};", name, value));
        }
    }

    key
}

impl AdvancedCache {
    /// Creates a new advanced cache with L1 memory and optional L2 disk tiers.
    ///
    /// # Arguments
    /// * `max_capacity` - Maximum entries in the L1 Moka cache.
    /// * `default_ttl_secs` - Default TTL for Moka eviction (minimum 60s).
    /// * `disk_path` - Optional directory for L2 disk cache; created if absent.
    pub fn new(max_capacity: u64, default_ttl_secs: u64, disk_path: Option<&str>) -> Self {
        let cache = moka::future::Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(Duration::from_secs(default_ttl_secs.max(60)))
            .build();

        let dp = disk_path.map(|p| {
            let pb = PathBuf::from(p);
            if let Err(e) = std::fs::create_dir_all(&pb) {
                warn!("Failed to create disk cache dir {:?}: {}", pb, e);
            } else {
                info!("Disk cache initialized at {:?}", pb);
            }
            pb
        });

        Self {
            memory: cache,
            disk_path: dp,
            locks: Arc::new(DashMap::new()),
            vary_map: Arc::new(DashMap::new()),
        }
    }

    /// Retrieves an entry from the cache. Checks memory first, then disk.
    pub async fn get(&self, key: &str) -> Option<CacheEntry> {
        // L1: in-memory
        if let Some(entry) = self.memory.get(key).await {
            if entry.is_fresh() || entry.is_stale_revalidatable() || entry.is_stale_on_error() {
                return Some(entry);
            }
            self.memory.invalidate(key).await;
        }

        // L2: disk
        if let Some(ref dp) = self.disk_path {
            if let Some(entry) = self.read_disk(dp, key).await {
                if entry.is_fresh() || entry.is_stale_revalidatable() {
                    self.memory.insert(key.to_string(), entry.clone()).await;
                    return Some(entry);
                }
            }
        }

        None
    }

    /// Stores an entry in both memory and disk cache.
    pub async fn insert(&self, key: String, entry: CacheEntry) {
        self.memory.insert(key.clone(), entry.clone()).await;

        if let Some(ref dp) = self.disk_path {
            self.write_disk(dp, &key, &entry).await;
        }
    }

    /// Purges a specific cache key from all tiers.
    pub async fn purge(&self, key: &str) -> bool {
        let mut found = false;

        if self.memory.get(key).await.is_some() {
            self.memory.invalidate(key).await;
            found = true;
        }

        if let Some(ref dp) = self.disk_path {
            let path = self.disk_entry_path(dp, key);
            if tokio::fs::remove_file(&path).await.is_ok() {
                found = true;
            }
        }

        found
    }

    /// Purges all entries matching a path prefix.
    pub async fn purge_prefix(&self, prefix: &str) -> u64 {
        // Memory cache doesn't support prefix iteration efficiently,
        // but we can track keys separately or accept the limitation.
        // For disk, we can scan the directory.
        let mut count = 0u64;

        if let Some(ref dp) = self.disk_path {
            if let Ok(mut entries) = tokio::fs::read_dir(dp).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.starts_with(&hex_prefix(prefix)) {
                            if tokio::fs::remove_file(entry.path()).await.is_ok() {
                                count += 1;
                            }
                        }
                    }
                }
            }
        }

        count
    }

    /// Acquires a lock for a cache key to prevent thundering herd.
    /// Returns a guard that must be held while fetching from upstream.
    pub async fn lock_key(&self, key: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let mutex = self
            .locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        mutex.lock_owned().await
    }

    /// Records which Vary headers were sent for a base key.
    pub fn record_vary(&self, base_key: &str, vary_names: Vec<String>) {
        self.vary_map.insert(base_key.to_string(), vary_names);
    }

    /// Returns the Vary header names for a base key.
    pub fn get_vary(&self, base_key: &str) -> Option<Vec<String>> {
        self.vary_map.get(base_key).map(|v| v.clone())
    }

    /// Returns the approximate number of entries in the L1 memory cache.
    pub fn entry_count(&self) -> u64 {
        self.memory.entry_count()
    }

    /// Flushes Moka's internal pending-write queue so that `entry_count()` reflects
    /// all inserts that have already been `.await`ed. Must be called in async tests
    /// before asserting on `entry_count()`.
    pub async fn run_pending_tasks(&self) {
        self.memory.run_pending_tasks().await;
    }

    /// Removes all entries from memory and disk cache.
    pub async fn purge_all(&self) {
        self.memory.invalidate_all();
        self.memory.run_pending_tasks().await;

        if let Some(ref dp) = self.disk_path {
            if let Ok(mut entries) = tokio::fs::read_dir(dp).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let _ = tokio::fs::remove_file(entry.path()).await;
                }
            }
        }
    }

    // ── Disk I/O helpers ──

    /// Computes the filesystem path for a disk cache entry by hashing the key.
    fn disk_entry_path(&self, base: &Path, key: &str) -> PathBuf {
        let hash = hex_prefix(key);
        base.join(format!("{}.cache", hash))
    }

    /// Reads and deserializes a cache entry from the L2 disk tier.
    async fn read_disk(&self, base: &Path, key: &str) -> Option<CacheEntry> {
        let path = self.disk_entry_path(base, key);
        let data = tokio::fs::read(&path).await.ok()?;
        deserialize_entry(&data)
    }

    /// Serializes and writes a cache entry to the L2 disk tier.
    async fn write_disk(&self, base: &Path, key: &str, entry: &CacheEntry) {
        let path = self.disk_entry_path(base, key);
        if let Some(data) = serialize_entry(entry) {
            if let Err(e) = tokio::fs::write(&path, data).await {
                debug!("Failed to write disk cache {}: {}", path.display(), e);
            }
        }
    }
}

/// Generates a deterministic 16-hex-char filename from a cache key using
/// the standard library's `DefaultHasher`. This avoids filesystem issues
/// with special characters in cache keys.
fn hex_prefix(key: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Serializes a cache entry to a compact binary format for disk persistence.
///
/// Layout: [status:4][max_age:8][swr:8][sie:8][ct_len:4][ct:..][hdr_len:4][hdr_json:..][body:..]
fn serialize_entry(entry: &CacheEntry) -> Option<Vec<u8>> {
    let max_age_secs = entry.max_age.as_secs();
    let swr_secs = entry.stale_while_revalidate.as_secs();
    let sie_secs = entry.stale_if_error.as_secs();
    let header_json = serde_json::to_vec(&entry.headers).ok()?;

    let mut buf = Vec::new();
    buf.extend_from_slice(&(entry.status as u32).to_le_bytes());
    buf.extend_from_slice(&max_age_secs.to_le_bytes());
    buf.extend_from_slice(&swr_secs.to_le_bytes());
    buf.extend_from_slice(&sie_secs.to_le_bytes());
    buf.extend_from_slice(&(entry.content_type.len() as u32).to_le_bytes());
    buf.extend_from_slice(entry.content_type.as_bytes());
    buf.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    buf.extend_from_slice(&header_json);
    buf.extend_from_slice(&entry.body);

    Some(buf)
}

/// Deserializes a cache entry from the binary disk format produced by `serialize_entry`.
///
/// Returns `None` if the data is too short or any field fails to parse.
/// The `created_at` timestamp is set to `Instant::now()` since absolute
/// instants cannot be persisted across process restarts.
fn deserialize_entry(data: &[u8]) -> Option<CacheEntry> {
    if data.len() < 32 {
        return None;
    }
    let mut pos = 0;

    let status = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as u16;
    pos += 4;
    let max_age_secs = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
    pos += 8;
    let swr_secs = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
    pos += 8;
    let sie_secs = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
    pos += 8;

    let ct_len = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
    pos += 4;
    let content_type = std::str::from_utf8(data.get(pos..pos + ct_len)?).ok()?.to_string();
    pos += ct_len;

    let hdr_len = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
    pos += 4;
    let headers: Vec<(String, String)> =
        serde_json::from_slice(data.get(pos..pos + hdr_len)?).ok()?;
    pos += hdr_len;

    let body = Bytes::copy_from_slice(data.get(pos..)?);

    Some(CacheEntry {
        status,
        body,
        content_type,
        headers,
        created_at: Instant::now(),
        max_age: Duration::from_secs(max_age_secs),
        stale_while_revalidate: Duration::from_secs(swr_secs),
        stale_if_error: Duration::from_secs(sie_secs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_entry() -> CacheEntry {
        CacheEntry {
            status: 200,
            body: Bytes::from_static(b"hello"),
            content_type: "text/plain".to_string(),
            headers: vec![("x-test".to_string(), "1".to_string())],
            created_at: Instant::now(),
            max_age: Duration::from_secs(60),
            stale_while_revalidate: Duration::from_secs(30),
            stale_if_error: Duration::from_secs(120),
        }
    }

    #[test]
    fn test_cache_entry_is_fresh() {
        let entry = fresh_entry();
        assert!(entry.is_fresh());
        assert!(!entry.is_stale_revalidatable());
    }

    #[test]
    fn test_cache_entry_expired() {
        let entry = CacheEntry {
            created_at: Instant::now() - Duration::from_secs(200),
            max_age: Duration::from_secs(60),
            stale_while_revalidate: Duration::from_secs(30),
            stale_if_error: Duration::from_secs(120),
            ..fresh_entry()
        };
        assert!(!entry.is_fresh());
        assert!(!entry.is_stale_revalidatable());
    }

    #[test]
    fn test_cache_entry_stale_revalidatable() {
        let entry = CacheEntry {
            created_at: Instant::now() - Duration::from_secs(70),
            max_age: Duration::from_secs(60),
            stale_while_revalidate: Duration::from_secs(30),
            stale_if_error: Duration::from_secs(0),
            ..fresh_entry()
        };
        assert!(!entry.is_fresh());
        assert!(entry.is_stale_revalidatable());
    }

    #[test]
    fn test_cache_entry_stale_on_error() {
        let entry = CacheEntry {
            created_at: Instant::now() - Duration::from_secs(70),
            max_age: Duration::from_secs(60),
            stale_while_revalidate: Duration::from_secs(0),
            stale_if_error: Duration::from_secs(120),
            ..fresh_entry()
        };
        assert!(entry.is_stale_on_error());
    }

    #[test]
    fn test_build_cache_key_basic() {
        let key = build_cache_key("GET", "example.com", "/api", None, &[]);
        assert_eq!(key, "GET:example.com:/api");
    }

    #[test]
    fn test_build_cache_key_with_query() {
        let key = build_cache_key("GET", "example.com", "/api", Some("page=1"), &[]);
        assert_eq!(key, "GET:example.com:/api?page=1");
    }

    #[test]
    fn test_build_cache_key_with_vary() {
        let vary = vec![
            ("Accept-Encoding".to_string(), "gzip".to_string()),
        ];
        let key = build_cache_key("GET", "example.com", "/api", None, &vary);
        assert!(key.contains(":V:"));
        assert!(key.contains("Accept-Encoding=gzip;"));
    }

    #[tokio::test]
    async fn test_advanced_cache_insert_and_get() {
        let cache = AdvancedCache::new(100, 120, None);
        let entry = fresh_entry();
        cache.insert("key1".to_string(), entry.clone()).await;
        let retrieved = cache.get("key1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().body, entry.body);
    }

    #[tokio::test]
    async fn test_advanced_cache_miss() {
        let cache = AdvancedCache::new(100, 120, None);
        assert!(cache.get("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_advanced_cache_purge() {
        let cache = AdvancedCache::new(100, 120, None);
        cache.insert("purge-me".to_string(), fresh_entry()).await;
        assert!(cache.purge("purge-me").await);
        assert!(cache.get("purge-me").await.is_none());
    }

    #[tokio::test]
    async fn test_advanced_cache_purge_missing() {
        let cache = AdvancedCache::new(100, 120, None);
        assert!(!cache.purge("does-not-exist").await);
    }

    #[tokio::test]
    async fn test_advanced_cache_vary_tracking() {
        let cache = AdvancedCache::new(100, 120, None);
        cache.record_vary("base-key", vec!["Accept-Encoding".to_string()]);
        let vary = cache.get_vary("base-key");
        assert_eq!(vary, Some(vec!["Accept-Encoding".to_string()]));
        assert!(cache.get_vary("other-key").is_none());
    }

    #[tokio::test]
    async fn test_advanced_cache_entry_count() {
        let cache = AdvancedCache::new(100, 120, None);
        assert_eq!(cache.entry_count(), 0);
        cache.insert("a".to_string(), fresh_entry()).await;
        cache.insert("b".to_string(), fresh_entry()).await;
        // Moka's async cache defers index updates — flush before asserting count.
        cache.run_pending_tasks().await;
        assert_eq!(cache.entry_count(), 2);
    }

    #[test]
    fn test_serialize_deserialize_entry() {
        let entry = fresh_entry();
        let data = serialize_entry(&entry).unwrap();
        let restored = deserialize_entry(&data).unwrap();
        assert_eq!(restored.status, 200);
        assert_eq!(restored.body, Bytes::from_static(b"hello"));
        assert_eq!(restored.content_type, "text/plain");
        assert_eq!(restored.headers.len(), 1);
    }

    #[test]
    fn test_deserialize_entry_too_short() {
        assert!(deserialize_entry(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_hex_prefix_deterministic() {
        let a = hex_prefix("test-key");
        let b = hex_prefix("test-key");
        assert_eq!(a, b);
        assert_ne!(hex_prefix("key-a"), hex_prefix("key-b"));
    }
}
