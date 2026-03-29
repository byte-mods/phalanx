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
    pub redis_client: Option<redis::Client>,
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
            redis_client,
        }
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
        // 1. Redis Cluster Sync Check (if enabled)
        if let Some(ref client) = self.redis_client {
            // Get async connection
            if let Ok(mut con) = client.get_async_connection().await {
                if let Some(gr) = self.global_rate {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                    let script = redis::Script::new(Self::REDIS_LUA_RATELIMIT);
                    
                    let result: redis::RedisResult<i32> = script.key("phalanx:ratelimit:global")
                        .arg(gr)
                        .arg(now)
                        .arg(1000) // 1 second window
                        .invoke_async(&mut con)
                        .await;
                        
                    if let Ok(allowed) = result {
                        if allowed == 0 {
                            warn!("Global DDoS Rate Limit Exceeded (Redis)! {:?}", ip);
                            return false;
                        }
                    }
                }
            }
        }

        // 2. Global DDoS Panic Mode check first (Local Fallback)
        if self.global_enabled && self.redis_client.is_none() {
            if self.global_limiter.check().is_err() {
                warn!("Global DDoS Rate Limit Exceeded (Local)! Dropping connection from {}", ip);
                return false;
            }
        }

        // 3. Per-IP Token Bucket check
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
}
