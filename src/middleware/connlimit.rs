/// Zone-based connection and request rate limiting.
///
/// Provides NGINX-style `limit_conn_zone` and `limit_req_zone` functionality
/// with flexible key extraction from client IP, headers, cookies, JWT claims,
/// query parameters, or composite combinations. Each zone independently tracks
/// both request rate (token bucket) and concurrent connection count.
///
/// Use [`ConnectionGuard`] for RAII-style connection slot management that
/// automatically releases on drop.
use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::sync::Arc;
use governor::{
    clock::DefaultClock,
    state::keyed::DefaultKeyedStateStore,
    Quota, RateLimiter,
};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::{info, warn};

/// Zone-based rate and connection limiter.
///
/// Unlike the simple per-IP limiter, this supports keying by arbitrary strings
/// (header values, JWT claims, cookie values, API keys, URI patterns, etc.)
/// and enforces both request rate and concurrent connection limits per key.
pub struct ZoneLimiter {
    /// Human-readable zone name for logging.
    name: String,
    /// Per-key token bucket rate limiter (governor-based, hot-swappable via ArcSwap).
    rate_limiter: ArcSwap<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>,
    /// Concurrent connection counter per key (atomic for lock-free updates).
    connections: DashMap<String, AtomicU32>,
    /// Max concurrent connections per key (0 = unlimited, no enforcement).
    max_connections: AtomicU32,
}

impl ZoneLimiter {
    /// Creates a new zone limiter with the specified rate and connection limits.
    ///
    /// # Arguments
    /// * `name` - Human-readable zone name (used in log messages).
    /// * `rate_per_sec` - Sustained request rate limit per key (minimum 1).
    /// * `burst` - Maximum burst allowance per key (minimum 1).
    /// * `max_connections` - Max concurrent connections per key (0 = unlimited).
    pub fn new(name: &str, rate_per_sec: u32, burst: u32, max_connections: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(rate_per_sec.max(1)).unwrap())
            .allow_burst(NonZeroU32::new(burst.max(1)).unwrap());

        Self {
            name: name.to_string(),
            rate_limiter: ArcSwap::from_pointee(RateLimiter::keyed(quota)),
            connections: DashMap::new(),
            max_connections: AtomicU32::new(max_connections),
        }
    }

    /// Atomically replaces the zone rate limiter with new rate/burst/connection limits.
    ///
    /// Called on SIGHUP reload. Existing connection counters are preserved.
    pub fn reload(&self, rate_per_sec: u32, burst: u32, max_connections: u32) {
        let quota = Quota::per_second(NonZeroU32::new(rate_per_sec.max(1)).unwrap())
            .allow_burst(NonZeroU32::new(burst.max(1)).unwrap());
        self.rate_limiter.store(Arc::new(RateLimiter::keyed(quota)));
        self.max_connections.store(max_connections, Ordering::Relaxed);
        info!(
            "Zone '{}' reloaded: rate={}/s burst={} max_conns={}",
            self.name, rate_per_sec, burst, max_connections
        );
    }

    /// Checks if the request is allowed for the given key.
    /// Returns `true` if allowed.
    pub fn check_rate(&self, key: &str) -> bool {
        let limiter = self.rate_limiter.load();
        if limiter.check_key(&key.to_string()).is_err() {
            warn!(
                "Zone '{}' rate limit exceeded for key '{}'",
                self.name, key
            );
            return false;
        }
        true
    }

    /// Attempts to acquire a connection slot for the given key.
    /// Returns `true` if the connection is allowed.
    pub fn acquire_connection(&self, key: &str) -> bool {
        let max_conns = self.max_connections.load(Ordering::Relaxed);
        if max_conns == 0 {
            return true;
        }

        let counter = self
            .connections
            .entry(key.to_string())
            .or_insert_with(|| AtomicU32::new(0));
        let current = counter.fetch_add(1, Ordering::Relaxed);

        if current >= max_conns {
            counter.fetch_sub(1, Ordering::Relaxed);
            warn!(
                "Zone '{}' connection limit ({}) exceeded for key '{}'",
                self.name, max_conns, key
            );
            return false;
        }
        true
    }

    /// Releases a connection slot for the given key.
    pub fn release_connection(&self, key: &str) {
        if let Some(counter) = self.connections.get(key) {
            let prev = counter.fetch_sub(1, Ordering::Relaxed);
            if prev <= 1 {
                drop(counter);
                self.connections.remove(key);
            }
        }
    }

    /// Returns the human-readable name of this zone.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Key extraction strategy for zone-based limiting.
///
/// Determines how to derive the rate-limit key from the incoming request.
/// For example, `ClientIp` uses the source IP, `Header("X-Api-Key")` uses
/// the value of that header, and `Composite` concatenates multiple sources
/// with `:` separators for fine-grained limiting (e.g., per-user-per-endpoint).
#[derive(Debug, Clone)]
pub enum ZoneKeySource {
    /// Key by client IP address (most common for per-client limiting).
    ClientIp,
    /// Key by value of a specific request header (e.g., `X-Api-Key`).
    Header(String),
    /// Key by value of a specific cookie (e.g., `session_id`).
    Cookie(String),
    /// Key by a JWT claim name extracted from the `Authorization: Bearer` header.
    JwtClaim(String),
    /// Key by the request URI path (for per-endpoint limiting).
    Uri,
    /// Key by a specific query parameter value.
    QueryParam(String),
    /// Composite: combine multiple sources into a single key joined by `:`.
    Composite(Vec<ZoneKeySource>),
}

impl ZoneKeySource {
    /// Extracts the key from the request context.
    pub fn extract(
        &self,
        client_ip: &str,
        headers: &hyper::HeaderMap,
        path: &str,
        query: Option<&str>,
    ) -> String {
        match self {
            ZoneKeySource::ClientIp => client_ip.to_string(),
            ZoneKeySource::Header(name) => headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or("_")
                .to_string(),
            ZoneKeySource::Cookie(name) => extract_cookie_value(headers, name)
                .unwrap_or_else(|| "_".to_string()),
            ZoneKeySource::JwtClaim(claim) => {
                extract_jwt_claim(headers, claim).unwrap_or_else(|| "_".to_string())
            }
            ZoneKeySource::Uri => path.to_string(),
            ZoneKeySource::QueryParam(param) => {
                query
                    .and_then(|q| {
                        q.split('&')
                            .find(|p| p.starts_with(&format!("{}=", param)))
                            .and_then(|p| p.split('=').nth(1))
                            .map(String::from)
                    })
                    .unwrap_or_else(|| "_".to_string())
            }
            ZoneKeySource::Composite(sources) => {
                let parts: Vec<String> = sources
                    .iter()
                    .map(|s| s.extract(client_ip, headers, path, query))
                    .collect();
                parts.join(":")
            }
        }
    }
}

/// Extracts a named cookie value from the `Cookie` request header.
fn extract_cookie_value(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            for part in cookies.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix(name) {
                    let val = val.trim_start_matches('=');
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
            None
        })
}

/// Extracts a named claim from a JWT Bearer token without full cryptographic validation.
///
/// Splits the token on `.`, base64url-decodes the payload, and reads the
/// specified claim as a string. Returns `None` if the header is absent,
/// the token is malformed, or the claim is missing.
fn extract_jwt_claim(headers: &hyper::HeaderMap, claim: &str) -> Option<String> {
    let auth = headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let token = auth.strip_prefix("Bearer ")?.trim();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims
        .get(claim)
        .and_then(|v| v.as_str())
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_limiter_rate_allowed() {
        let limiter = ZoneLimiter::new("test", 100, 10, 0);
        assert!(limiter.check_rate("client-1"));
    }

    #[test]
    fn test_zone_limiter_rate_exceeded() {
        let limiter = ZoneLimiter::new("test", 1, 1, 0);
        assert!(limiter.check_rate("client-1"));
        let mut blocked = false;
        for _ in 0..100 {
            if !limiter.check_rate("client-1") {
                blocked = true;
                break;
            }
        }
        assert!(blocked, "rate limiter should eventually block");
    }

    #[test]
    fn test_zone_limiter_connection_limit() {
        let limiter = ZoneLimiter::new("test", 100, 10, 2);
        assert!(limiter.acquire_connection("key1"));
        assert!(limiter.acquire_connection("key1"));
        assert!(!limiter.acquire_connection("key1"), "3rd connection should be denied");
    }

    #[test]
    fn test_zone_limiter_connection_release() {
        let limiter = ZoneLimiter::new("test", 100, 10, 1);
        assert!(limiter.acquire_connection("k"));
        assert!(!limiter.acquire_connection("k"));
        limiter.release_connection("k");
        assert!(limiter.acquire_connection("k"), "after release, should allow again");
    }

    #[test]
    fn test_zone_limiter_unlimited_connections() {
        let limiter = ZoneLimiter::new("test", 100, 10, 0);
        for _ in 0..1000 {
            assert!(limiter.acquire_connection("key"));
        }
    }

    #[test]
    fn test_zone_limiter_name() {
        let limiter = ZoneLimiter::new("my-zone", 10, 5, 0);
        assert_eq!(limiter.name(), "my-zone");
    }

    #[test]
    fn test_zone_key_source_client_ip() {
        let src = ZoneKeySource::ClientIp;
        let headers = hyper::HeaderMap::new();
        assert_eq!(src.extract("1.2.3.4", &headers, "/", None), "1.2.3.4");
    }

    #[test]
    fn test_zone_key_source_header() {
        let src = ZoneKeySource::Header("X-Api-Key".to_string());
        let mut headers = hyper::HeaderMap::new();
        headers.insert("X-Api-Key", "abc123".parse().unwrap());
        assert_eq!(src.extract("ip", &headers, "/", None), "abc123");
    }

    #[test]
    fn test_zone_key_source_header_missing() {
        let src = ZoneKeySource::Header("X-Missing".to_string());
        let headers = hyper::HeaderMap::new();
        assert_eq!(src.extract("ip", &headers, "/", None), "_");
    }

    #[test]
    fn test_zone_key_source_cookie() {
        let src = ZoneKeySource::Cookie("session_id".to_string());
        let mut headers = hyper::HeaderMap::new();
        headers.insert(hyper::header::COOKIE, "session_id=xyz789; other=val".parse().unwrap());
        assert_eq!(src.extract("ip", &headers, "/", None), "xyz789");
    }

    #[test]
    fn test_zone_key_source_uri() {
        let src = ZoneKeySource::Uri;
        let headers = hyper::HeaderMap::new();
        assert_eq!(src.extract("ip", &headers, "/api/v1", None), "/api/v1");
    }

    #[test]
    fn test_zone_key_source_query_param() {
        let src = ZoneKeySource::QueryParam("user_id".to_string());
        let headers = hyper::HeaderMap::new();
        assert_eq!(src.extract("ip", &headers, "/", Some("user_id=42&page=1")), "42");
    }

    #[test]
    fn test_zone_key_source_query_param_missing() {
        let src = ZoneKeySource::QueryParam("missing".to_string());
        let headers = hyper::HeaderMap::new();
        assert_eq!(src.extract("ip", &headers, "/", Some("other=1")), "_");
    }

    #[test]
    fn test_zone_key_source_composite() {
        let src = ZoneKeySource::Composite(vec![
            ZoneKeySource::ClientIp,
            ZoneKeySource::Uri,
        ]);
        let headers = hyper::HeaderMap::new();
        assert_eq!(src.extract("1.2.3.4", &headers, "/api", None), "1.2.3.4:/api");
    }

    #[test]
    fn test_extract_jwt_claim_valid() {
        use base64::Engine;
        let payload = serde_json::json!({"sub": "user-42", "role": "admin"});
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let fake_token = format!("header.{}.signature", payload_b64);
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::AUTHORIZATION,
            format!("Bearer {}", fake_token).parse().unwrap(),
        );
        assert_eq!(extract_jwt_claim(&headers, "sub"), Some("user-42".to_string()));
        assert_eq!(extract_jwt_claim(&headers, "role"), Some("admin".to_string()));
    }

    #[test]
    fn test_extract_jwt_claim_missing_header() {
        let headers = hyper::HeaderMap::new();
        assert_eq!(extract_jwt_claim(&headers, "sub"), None);
    }

    #[test]
    fn test_zone_limiter_reload_updates_connection_limit() {
        let limiter = ZoneLimiter::new("test", 100, 10, 2);
        assert!(limiter.acquire_connection("k"));
        assert!(limiter.acquire_connection("k"));
        assert!(!limiter.acquire_connection("k"), "should be limited at 2");

        // Reload with higher connection limit
        limiter.reload(100, 10, 5);
        // Existing counters are preserved (2 active), but limit is now 5
        assert!(limiter.acquire_connection("k"), "should allow 3rd after reload to 5");
    }
}

/// RAII guard that automatically releases a connection slot when dropped.
///
/// Ensures `release_connection` is called even on early returns or panics,
/// preventing connection slot leaks under all code paths.
pub struct ConnectionGuard {
    /// The zone limiter that owns the connection slot.
    zone: Arc<ZoneLimiter>,
    /// The key whose connection slot this guard holds.
    key: String,
}

impl ConnectionGuard {
    /// Creates a new guard that will release the connection slot for `key`
    /// in `zone` when dropped.
    pub fn new(zone: Arc<ZoneLimiter>, key: String) -> Self {
        Self { zone, key }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.zone.release_connection(&self.key);
    }
}
