/// Per-IP and global token bucket rate limiter with optional Redis cluster sync.
///
/// Provides two tiers of protection:
/// 1. **Global DDoS ceiling** -- a single bucket that limits total throughput
///    across all clients, preventing saturation attacks.
/// 2. **Per-IP token bucket** -- individual buckets per source IP to prevent
///    any single client from monopolizing capacity.
///
/// When Redis is configured, both tiers use a Lua-based sliding window script
/// for consistent enforcement across cluster nodes. When Redis is unavailable,
/// falls back to local in-memory `governor` rate limiters.
use arc_swap::ArcSwap;
use governor::{
    clock::DefaultClock,
    state::{direct::NotKeyed, keyed::DefaultKeyedStateStore, InMemoryState},
    Quota, RateLimiter,
};
use std::sync::Arc;
use std::{net::IpAddr, num::NonZeroU32};
use tracing::{error, info, warn};

/// Inner state holding the actual governor limiters.
///
/// Wrapped in `ArcSwap` so that SIGHUP reload can atomically swap in new
/// limiters with updated rate/burst values without disrupting in-flight requests.
struct RateLimiterInner {
    ip_limiter: RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>,
    global_limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    global_enabled: bool,
    global_rate: Option<u32>,
    per_ip_burst: u32,
}

/// The main rate limiter used by the Phalanx proxy.
///
/// Combines local (governor-based) and distributed (Redis-based) rate limiting
/// with automatic fallback from distributed to local when Redis is unreachable.
pub struct PhalanxRateLimiter {
    /// Atomically swappable inner state for hot-reload support.
    inner: ArcSwap<RateLimiterInner>,
    /// Optional Redis client for distributed rate limiting.
    pub redis_client: Option<redis::Client>,
    /// Lazily-initialized multiplexed Redis connection, cached to avoid
    /// creating a new connection on every rate-limit check.
    redis_conn: tokio::sync::Mutex<Option<redis::aio::MultiplexedConnection>>,
    /// Per-IP cumulative request counter for the admin dashboard's top-N queries.
    pub request_counts: Arc<dashmap::DashMap<String, u64>>,
}

/// Builds a `RateLimiterInner` from the given rate parameters.
fn build_inner(per_ip_rate: u32, per_ip_burst: u32, global_rate: Option<u32>) -> RateLimiterInner {
    let safe_per_ip_rate = if per_ip_rate == 0 {
        warn!("rate_limit_per_ip of 0 is invalid; clamping to 1");
        1
    } else {
        per_ip_rate
    };
    let safe_per_ip_burst = if per_ip_burst == 0 {
        warn!("rate_limit_burst of 0 is invalid; clamping to 1");
        1
    } else {
        per_ip_burst
    };
    let normalized_global_rate = match global_rate {
        Some(0) => {
            warn!("global_rate_limit of 0 disables global limiter");
            None
        }
        Some(v) => Some(v),
        None => None,
    };

    let ip_quota = Quota::per_second(NonZeroU32::new(safe_per_ip_rate).unwrap_or(NonZeroU32::MIN))
        .allow_burst(NonZeroU32::new(safe_per_ip_burst).unwrap_or(NonZeroU32::MIN));

    let global_limiter = if let Some(gr) = normalized_global_rate {
        RateLimiter::direct(Quota::per_second(NonZeroU32::new(gr).unwrap_or(NonZeroU32::MIN)))
    } else {
        RateLimiter::direct(Quota::per_second(NonZeroU32::MIN))
    };

    RateLimiterInner {
        ip_limiter: RateLimiter::keyed(ip_quota),
        global_limiter,
        global_enabled: normalized_global_rate.is_some(),
        global_rate: normalized_global_rate,
        per_ip_burst: safe_per_ip_burst,
    }
}

impl PhalanxRateLimiter {
    /// Creates a new rate limiter with the specified per-IP and global limits.
    ///
    /// # Arguments
    /// * `per_ip_rate` - Sustained requests/second per IP (clamped to 1 if 0).
    /// * `per_ip_burst` - Maximum burst allowance per IP (clamped to 1 if 0).
    /// * `global_rate` - Optional global requests/second cap (`None` or `Some(0)` disables).
    /// * `redis_url` - Optional Redis URL for distributed rate limiting.
    pub fn new(per_ip_rate: u32, per_ip_burst: u32, global_rate: Option<u32>, redis_url: Option<&str>) -> Self {
        let inner = build_inner(per_ip_rate, per_ip_burst, global_rate);

        let redis_client = redis_url.and_then(|url| {
            redis::Client::open(url).map_err(|e| {
                error!("Failed to connect to Redis for Rate Limiter: {}", e);
                e
            }).ok()
        });

        Self {
            inner: ArcSwap::from_pointee(inner),
            redis_client,
            redis_conn: tokio::sync::Mutex::new(None),
            request_counts: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Atomically replaces the rate limiters with new instances using updated parameters.
    ///
    /// Called on SIGHUP reload when rate limit config values change. Existing
    /// in-flight requests that already loaded the old inner will finish against
    /// the old limiters; new requests see the new limits immediately.
    pub fn reload(&self, per_ip_rate: Option<u32>, per_ip_burst: Option<u32>, global_rate: Option<u32>) {
        let new_inner = build_inner(
            per_ip_rate.unwrap_or(50),
            per_ip_burst.unwrap_or(100),
            global_rate,
        );
        info!(
            "Rate limiter reloaded: per_ip={}/s burst={} global={:?}",
            per_ip_rate.unwrap_or(50),
            per_ip_burst.unwrap_or(100),
            global_rate
        );
        self.inner.store(Arc::new(new_inner));
    }

    /// Returns the currently configured global rate limit.
    pub fn global_rate(&self) -> Option<u32> {
        self.inner.load().global_rate
    }

    /// Returns whether the global rate limiter is active.
    pub fn global_enabled(&self) -> bool {
        self.inner.load().global_enabled
    }

    /// Returns the currently configured per-IP burst allowance.
    pub fn per_ip_burst(&self) -> u32 {
        self.inner.load().per_ip_burst
    }

    /// Records a request from an IP (increments counter for dashboard top-N).
    pub fn record_request(&self, ip: &str) {
        self.request_counts
            .entry(ip.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    /// Returns the top N IPs by cumulative request count, sorted descending.
    ///
    /// Uses a capped min-heap to keep memory bounded at O(N) rather than O(total IPs).
    /// Each entry is pushed onto a `BinaryHeap<Reverse<(count, key)>>`; once the heap
    /// exceeds `n`, the smallest element is popped. After iteration, the heap contains
    /// exactly the top N entries which are drained into a descending Vec.
    pub fn top_ips(&self, n: usize) -> Vec<(String, u64)> {
        use std::collections::BinaryHeap;
        use std::cmp::Reverse;

        if n == 0 {
            return Vec::new();
        }

        let mut heap: BinaryHeap<Reverse<(u64, String)>> = BinaryHeap::with_capacity(n);

        for entry in self.request_counts.iter() {
            let item = Reverse((*entry.value(), entry.key().clone()));
            heap.push(item);
            if heap.len() > n {
                heap.pop();
            }
        }

        heap
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse((count, key))| (key, count))
            .collect()
    }

    /// Spawns a background sweeper that periodically resets the `request_counts`
    /// DashMap to prevent unbounded memory growth under high-cardinality traffic.
    pub fn spawn_sweeper(&self) {
        let counts = Arc::clone(&self.request_counts);
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        handle.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                counts.clear();
            }
        });
    }

    /// Lua script for a sliding window or strict token bucket rate limit
    /// KEYS[1]: "ratelimit:global" or "ratelimit:ip"
    /// ARGV[1]: Burst Size, ARGV[2]: Current Time Ms, ARGV[3]: Expiry Ms
    const REDIS_LUA_RATELIMIT: &'static str = r#"
        local key = KEYS[1]
        local burst = tonumber(ARGV[1])
        local now = tonumber(ARGV[2])
        local expiry = tonumber(ARGV[3])
        local clear_before = now - expiry
        redis.call('ZREMRANGEBYSCORE', key, 0, clear_before)
        local count = redis.call('ZCARD', key)
        if count < burst then
            redis.call('ZADD', key, now, now)
            redis.call('PEXPIRE', key, expiry)
            return 1
        else
            return 0
        end
    "#;

    /// Checks if the IP is allowed to make a request. Returns true if allowed, false if rate limited.
    pub async fn check_ip(&self, ip: IpAddr) -> bool {
        // 1. Redis Cluster Sync: global + per-IP checks (when Redis is available)
        if let Some(ref client) = self.redis_client {
            // Lazy-init: cache the multiplexed connection to avoid creating a new
            // TCP connection on every rate-limit check.
            let mut guard = self.redis_conn.lock().await;
            if guard.is_none() {
                if let Ok(con) = client.get_multiplexed_async_connection().await {
                    *guard = Some(con);
                }
            }
            if let Some(ref mut con) = *guard {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let script = redis::Script::new(Self::REDIS_LUA_RATELIMIT);

                // 1a. Global DDoS ceiling check via Redis
                if let Some(gr) = self.global_rate() {
                    let result: redis::RedisResult<i32> = script
                        .key("phalanx:ratelimit:global")
                        .arg(gr)
                        .arg(now)
                        .arg(1000u64)
                        .invoke_async(&mut *con)
                        .await;
                    if let Ok(0) = result {
                        warn!("Global DDoS Rate Limit Exceeded (Redis)! {:?}", ip);
                        return false;
                    }
                }

                // 1b. Per-IP check via Redis — keeps buckets consistent across cluster nodes
                let ip_key = format!("phalanx:ratelimit:ip:{}", ip);
                // Re-fetch the per-ip quota from the local governor's burst setting.
                // We use the governor quota's burst as the Redis window burst too.
                let ip_burst = self.per_ip_burst();
                let result: redis::RedisResult<i32> = script
                    .key(ip_key)
                    .arg(ip_burst)
                    .arg(now)
                    .arg(1000u64)
                    .invoke_async(&mut *con)
                    .await;
                if let Ok(0) = result {
                    warn!("Per-IP Rate Limit Exceeded (Redis) for {}! Dropping connection.", ip);
                    return false;
                }

                // Redis checks passed — skip local fallbacks to avoid double-counting
                return true;
            }
            // Redis unreachable — fall through to local checks below
        }

        // 2. Global DDoS Panic Mode — local fallback when Redis is not configured/reachable
        let inner = self.inner.load();
        if inner.global_enabled {
            if inner.global_limiter.check().is_err() {
                warn!("Global DDoS Rate Limit Exceeded (Local)! Dropping connection from {}", ip);
                return false;
            }
        }

        // 3. Per-IP Token Bucket — local fallback
        if inner.ip_limiter.check_key(&ip).is_err() {
            warn!("Per-IP Rate Limit Exceeded for {}! Dropping connection.", ip);
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_rate_limiter_allows_initial_requests() {
        let limiter = PhalanxRateLimiter::new(100, 10, None, None);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(limiter.check_ip(ip).await);
    }

    #[test]
    fn test_rate_limiter_global_disabled() {
        let limiter = PhalanxRateLimiter::new(100, 10, None, None);
        assert!(!limiter.global_enabled());
    }

    #[test]
    fn test_rate_limiter_global_enabled() {
        let limiter = PhalanxRateLimiter::new(100, 10, Some(1000), None);
        assert!(limiter.global_enabled());
    }

    #[tokio::test]
    async fn test_rate_limiter_per_ip_eventually_blocks() {
        let limiter = PhalanxRateLimiter::new(1, 1, None, None);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        limiter.check_ip(ip).await;
        let mut blocked = false;
        for _ in 0..100 {
            if !limiter.check_ip(ip).await {
                blocked = true;
                break;
            }
        }
        assert!(blocked, "per-IP rate limit should eventually block");
    }

    #[tokio::test]
    async fn test_rate_limiter_different_ips_independent() {
        let limiter = PhalanxRateLimiter::new(1, 1, None, None);
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        limiter.check_ip(ip1).await;
        assert!(limiter.check_ip(ip2).await, "different IPs should not share buckets");
    }

    #[test]
    fn test_rate_limiter_per_ip_burst_config() {
        let limiter = PhalanxRateLimiter::new(50, 200, None, None);
        assert_eq!(limiter.per_ip_burst(), 200);
    }

    #[test]
    fn test_rate_limiter_global_rate_config() {
        let limiter = PhalanxRateLimiter::new(50, 100, Some(5000), None);
        assert_eq!(limiter.global_rate(), Some(5000));
    }

    #[test]
    fn test_rate_limiter_zero_values_are_sanitized() {
        let limiter = PhalanxRateLimiter::new(0, 0, Some(0), None);
        assert_eq!(limiter.per_ip_burst(), 1);
        assert_eq!(limiter.global_rate(), None);
        assert!(!limiter.global_enabled());
    }

    #[tokio::test]
    async fn test_rate_limiter_zero_values_do_not_panic_or_block_all() {
        let limiter = PhalanxRateLimiter::new(0, 0, Some(0), None);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        assert!(limiter.check_ip(ip).await);
    }

    #[tokio::test]
    async fn test_rate_limiter_ipv6_independent() {
        let limiter = PhalanxRateLimiter::new(1, 1, None, None);
        let ip_v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_v6 = IpAddr::V6("::1".parse().unwrap());
        limiter.check_ip(ip_v4).await;
        assert!(limiter.check_ip(ip_v6).await, "IPv4 and IPv6 should have independent buckets");
    }

    #[tokio::test]
    async fn test_rate_limiter_redis_url_optional() {
        // Should not panic with invalid Redis URL
        let limiter = PhalanxRateLimiter::new(100, 10, None, Some("redis://invalid:9999"));
        assert!(limiter.redis_client.is_some()); // Client is created even if connection fails
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // Should fall back to local checks
        assert!(limiter.check_ip(ip).await);
    }

    #[test]
    fn test_record_and_top_ips() {
        let limiter = PhalanxRateLimiter::new(1000, 2000, None, None);
        limiter.record_request("10.0.0.1");
        limiter.record_request("10.0.0.1");
        limiter.record_request("10.0.0.2");
        let top = limiter.top_ips(10);
        assert_eq!(top[0].0, "10.0.0.1");
        assert_eq!(top[0].1, 2);
        assert_eq!(top[1].0, "10.0.0.2");
        assert_eq!(top[1].1, 1);
    }

    #[test]
    fn test_top_ips_limited() {
        let limiter = PhalanxRateLimiter::new(1000, 2000, None, None);
        for i in 0..20u64 {
            for _ in 0..=i {
                limiter.record_request(&format!("10.0.0.{}", i));
            }
        }
        let top = limiter.top_ips(5);
        assert_eq!(top.len(), 5);
        for w in top.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn test_top_ips_empty() {
        let limiter = PhalanxRateLimiter::new(100, 200, None, None);
        assert!(limiter.top_ips(10).is_empty());
    }

    #[test]
    fn test_top_ips_heap_allocates_bounded() {
        let limiter = PhalanxRateLimiter::new(1000, 2000, None, None);
        // 100 unique IPs, each with distinct counts
        for i in 0..100u64 {
            for _ in 0..=i {
                limiter.record_request(&format!("10.0.0.{}", i));
            }
        }
        let top = limiter.top_ips(3);
        assert_eq!(top.len(), 3);
        // Highest-count IPs: 10.0.0.99 (100 hits), 10.0.0.98 (99), 10.0.0.97 (98)
        assert_eq!(top[0].0, "10.0.0.99");
        assert_eq!(top[0].1, 100);
        assert_eq!(top[1].0, "10.0.0.98");
        assert_eq!(top[2].0, "10.0.0.97");
        // Verify descending order
        for w in top.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn test_top_ips_n_zero() {
        let limiter = PhalanxRateLimiter::new(1000, 2000, None, None);
        limiter.record_request("10.0.0.1");
        assert!(limiter.top_ips(0).is_empty());
    }

    #[test]
    fn test_top_ips_n_greater_than_entries() {
        let limiter = PhalanxRateLimiter::new(1000, 2000, None, None);
        limiter.record_request("a");
        limiter.record_request("b");
        limiter.record_request("b");
        let top = limiter.top_ips(10);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "b");
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_reload_updates_limits() {
        let limiter = PhalanxRateLimiter::new(50, 100, Some(5000), None);
        assert_eq!(limiter.per_ip_burst(), 100);
        assert_eq!(limiter.global_rate(), Some(5000));

        limiter.reload(Some(200), Some(500), Some(10000));
        assert_eq!(limiter.per_ip_burst(), 500);
        assert_eq!(limiter.global_rate(), Some(10000));
        assert!(limiter.global_enabled());
    }

    #[test]
    fn test_reload_disables_global() {
        let limiter = PhalanxRateLimiter::new(50, 100, Some(5000), None);
        assert!(limiter.global_enabled());

        limiter.reload(Some(50), Some(100), None);
        assert!(!limiter.global_enabled());
    }
}
