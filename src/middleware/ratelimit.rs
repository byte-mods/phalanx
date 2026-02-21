use governor::{
    clock::DefaultClock,
    state::{direct::NotKeyed, keyed::DefaultKeyedStateStore, InMemoryState},
    Quota, RateLimiter,
};
use std::net::IpAddr;
use std::num::NonZeroU32;
use tracing::warn;

pub struct PhalanxRateLimiter {
    pub ip_limiter: RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>,
    pub global_limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    pub global_enabled: bool,
}

impl PhalanxRateLimiter {
    pub fn new(per_ip_rate: u32, per_ip_burst: u32, global_rate: Option<u32>) -> Self {
        let ip_quota = Quota::per_second(NonZeroU32::new(per_ip_rate).unwrap())
            .allow_burst(NonZeroU32::new(per_ip_burst).unwrap());

        let global_limiter = if let Some(gr) = global_rate {
            RateLimiter::direct(Quota::per_second(NonZeroU32::new(gr).unwrap()))
        } else {
            RateLimiter::direct(Quota::per_second(NonZeroU32::new(1).unwrap()))
        };

        Self {
            ip_limiter: RateLimiter::keyed(ip_quota),
            global_limiter,
            global_enabled: global_rate.is_some(),
        }
    }

    /// Checks if the IP is allowed to make a request. Returns true if allowed, false if rate limited.
    pub fn check_ip(&self, ip: IpAddr) -> bool {
        // Global DDoS Panic Mode check first
        if self.global_enabled {
            if self.global_limiter.check().is_err() {
                warn!("Global DDoS Rate Limit Exceeded! Dropping connection from {}", ip);
                return false;
            }
        }

        // Per-IP Token Bucket check
        if self.ip_limiter.check_key(&ip).is_err() {
            warn!("Per-IP Rate Limit Exceeded for {}! Dropping connection.", ip);
            return false;
        }

        true
    }
}
