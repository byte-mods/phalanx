use governor::{
    clock::DefaultClock,
    state::{direct::NotKeyed, keyed::DefaultKeyedStateStore, InMemoryState},
    Quota, RateLimiter,
};
use std::net::IpAddr;
use std::num::NonZeroU32;
use tracing::{warn, error};
use redis::AsyncCommands;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct PhalanxRateLimiter {
    pub ip_limiter: RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>,
    pub global_limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    pub global_enabled: bool,
    pub global_rate: Option<u32>,
    /// Burst allowance stored so Redis per-IP check can use the same limit.
    pub per_ip_burst: u32,
    pub redis_client: Option<redis::Client>,
    /// Per-IP cumulative request counter for dashboard top-N queries.
    pub request_counts: Arc<dashmap::DashMap<String, u64>>,
}

impl PhalanxRateLimiter {
    pub fn new(per_ip_rate: u32, per_ip_burst: u32, global_rate: Option<u32>, redis_url: Option<&str>) -> Self {
        let ip_quota = Quota::per_second(NonZeroU32::new(per_ip_rate).unwrap())
            .allow_burst(NonZeroU32::new(per_ip_burst).unwrap());

        let global_limiter = if let Some(gr) = global_rate {
            RateLimiter::direct(Quota::per_second(NonZeroU32::new(gr).unwrap()))
        } else {
            RateLimiter::direct(Quota::per_second(NonZeroU32::new(1).unwrap()))
        };
        
        let redis_client = redis_url.and_then(|url| {
            redis::Client::open(url).map_err(|e| {
                error!("Failed to connect to Redis for Rate Limiter: {}", e);
                e
            }).ok()
        });

        Self {
            ip_limiter: RateLimiter::keyed(ip_quota),
            global_limiter,
            global_enabled: global_rate.is_some(),
            global_rate,
            per_ip_burst,
            redis_client,
            request_counts: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Records a request from an IP (increments counter for dashboard top-N).
    pub fn record_request(&self, ip: &str) {
        self.request_counts
            .entry(ip.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    /// Returns the top N IPs by cumulative request count, sorted descending.
    pub fn top_ips(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self.request_counts
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
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
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let script = redis::Script::new(Self::REDIS_LUA_RATELIMIT);

                // 1a. Global DDoS ceiling check via Redis
                if let Some(gr) = self.global_rate {
                    let result: redis::RedisResult<i32> = script
                        .key("phalanx:ratelimit:global")
                        .arg(gr)
                        .arg(now)
                        .arg(1000u64)
                        .invoke_async(&mut con)
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
                let ip_burst = self.per_ip_burst;
                let result: redis::RedisResult<i32> = script
                    .key(ip_key)
                    .arg(ip_burst)
                    .arg(now)
                    .arg(1000u64)
                    .invoke_async(&mut con)
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
        if self.global_enabled {
            if self.global_limiter.check().is_err() {
                warn!("Global DDoS Rate Limit Exceeded (Local)! Dropping connection from {}", ip);
                return false;
            }
        }

        // 3. Per-IP Token Bucket — local fallback
        if self.ip_limiter.check_key(&ip).is_err() {
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
        assert!(!limiter.global_enabled);
    }

    #[test]
    fn test_rate_limiter_global_enabled() {
        let limiter = PhalanxRateLimiter::new(100, 10, Some(1000), None);
        assert!(limiter.global_enabled);
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
        assert_eq!(limiter.per_ip_burst, 200);
    }

    #[test]
    fn test_rate_limiter_global_rate_config() {
        let limiter = PhalanxRateLimiter::new(50, 100, Some(5000), None);
        assert_eq!(limiter.global_rate, Some(5000));
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
}
