use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::keyed::DefaultKeyedStateStore,
    Quota, RateLimiter,
};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::warn;

/// Zone-based rate and connection limiter.
///
/// Unlike the simple per-IP limiter, this supports keying by arbitrary strings
/// (header values, JWT claims, cookie values, API keys, URI patterns, etc.)
/// and enforces both request rate and concurrent connection limits per key.
pub struct ZoneLimiter {
    name: String,
    rate_limiter: RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>,
    /// Concurrent connection tracking per key
    connections: DashMap<String, AtomicU32>,
    /// Max concurrent connections per key (0 = unlimited)
    max_connections: u32,
}

impl ZoneLimiter {
    pub fn new(name: &str, rate_per_sec: u32, burst: u32, max_connections: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(rate_per_sec.max(1)).unwrap())
            .allow_burst(NonZeroU32::new(burst.max(1)).unwrap());

        Self {
            name: name.to_string(),
            rate_limiter: RateLimiter::keyed(quota),
            connections: DashMap::new(),
            max_connections,
        }
    }

    /// Checks if the request is allowed for the given key.
    /// Returns `true` if allowed.
    pub fn check_rate(&self, key: &str) -> bool {
        if self.rate_limiter.check_key(&key.to_string()).is_err() {
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
        if self.max_connections == 0 {
            return true;
        }

        let counter = self
            .connections
            .entry(key.to_string())
            .or_insert_with(|| AtomicU32::new(0));
        let current = counter.fetch_add(1, Ordering::Relaxed);

        if current >= self.max_connections {
            counter.fetch_sub(1, Ordering::Relaxed);
            warn!(
                "Zone '{}' connection limit ({}) exceeded for key '{}'",
                self.name, self.max_connections, key
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

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Key extraction strategy for zone-based limiting.
#[derive(Debug, Clone)]
pub enum ZoneKeySource {
    /// Key by client IP address
    ClientIp,
    /// Key by value of a specific request header
    Header(String),
    /// Key by value of a specific cookie
    Cookie(String),
    /// Key by a JWT claim name
    JwtClaim(String),
    /// Key by the request URI path
    Uri,
    /// Key by a query parameter
    QueryParam(String),
    /// Composite: combine multiple sources
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
}
