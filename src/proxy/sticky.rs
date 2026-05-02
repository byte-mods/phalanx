//! Sticky session (session affinity) management.
//!
//! Ensures that requests belonging to the same user session are consistently
//! routed to the same backend server. This is critical for stateful applications
//! that store session data in-process (e.g. shopping carts, WebSocket state).
//!
//! Three persistence modes are supported (matching NGINX Plus behavior):
//!
//! 1. **Cookie** -- the proxy sets a `Set-Cookie` header with a base64-encoded
//!    backend address. Subsequent requests carrying this cookie are routed directly.
//! 2. **Learn** -- the proxy observes a response header (e.g. `X-Session-Id`) and
//!    remembers which backend served which session key. Entries expire after a timeout.
//! 3. **Route** -- the proxy extracts a routing key from a request cookie (e.g.
//!    `jsessionid`) and maps it to a specific backend.

use dashmap::DashMap;
use hmac::{Hmac, Mac as _};
use rand::RngExt;
use sha2::Sha256;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Sticky session persistence modes matching NGINX Plus behavior.
#[derive(Debug, Clone)]
pub enum StickyMode {
    /// Server sets a cookie on the first response; subsequent requests with that
    /// cookie are routed to the same backend.
    Cookie {
        name: String,
        path: String,
        http_only: bool,
        secure: bool,
        /// Max-Age in seconds. 0 = session cookie.
        max_age: u64,
    },
    /// The proxy learns the mapping from a response header/cookie and remembers
    /// which backend served a given session identifier.
    Learn {
        /// Response header or cookie name to extract the session key from.
        lookup_header: String,
        /// Duration after which a learned mapping expires.
        timeout: Duration,
    },
    /// Route based on a value embedded in the request (e.g. a `route` cookie or
    /// the first portion of a `jsessionid`).
    Route {
        cookie_name: String,
    },
}

/// A single learned session → backend mapping.
struct LearnedEntry {
    backend_addr: String,
    created: Instant,
}

/// HMAC type alias for cookie signing (HMAC-SHA256).
type HmacSha256 = Hmac<Sha256>;

/// Thread-safe session affinity manager shared across all proxy tasks.
pub struct StickySessionManager {
    mode: StickyMode,
    /// Maps session-id → backend address for Cookie and Learn modes.
    table: Arc<DashMap<String, LearnedEntry>>,
    /// 256-bit key for HMAC-SHA256 cookie signing. Generated randomly
    /// at startup if not provided. Rotating this key invalidates all
    /// existing sticky cookies.
    hmac_key: [u8; 32],
}

impl StickySessionManager {
    /// Creates a new manager with the given persistence mode and an empty session table.
    /// A random HMAC key is generated for cookie signing.
    pub fn new(mode: StickyMode) -> Self {
        let hmac_key = rand::rng().random();
        Self {
            mode,
            table: Arc::new(DashMap::new()),
            hmac_key,
        }
    }

    /// Creates a new manager with a specific HMAC key (e.g., restored from config
    /// or shared across cluster nodes for consistent cookie validation).
    pub fn new_with_key(mode: StickyMode, hmac_key: [u8; 32]) -> Self {
        Self {
            mode,
            table: Arc::new(DashMap::new()),
            hmac_key,
        }
    }

    /// Returns a reference to the configured sticky mode.
    pub fn mode(&self) -> &StickyMode {
        &self.mode
    }

    /// Looks up a backend for the given session key.
    /// Returns `None` if no mapping exists or the entry expired.
    pub fn lookup(&self, session_key: &str) -> Option<String> {
        if let Some(entry) = self.table.get(session_key) {
            if let StickyMode::Learn { timeout, .. } = &self.mode {
                if entry.created.elapsed() > *timeout {
                    drop(entry);
                    self.table.remove(session_key);
                    return None;
                }
            }
            Some(entry.backend_addr.clone())
        } else {
            None
        }
    }

    /// Records a session → backend mapping.
    pub fn learn(&self, session_key: String, backend_addr: String) {
        self.table.insert(
            session_key,
            LearnedEntry {
                backend_addr,
                created: Instant::now(),
            },
        );
    }

    /// Generates a `Set-Cookie` header value for Cookie-mode sticky sessions.
    /// The cookie value is `<base64(addr)>.<base64(hmac)>` so tampering is
    /// detectable on extraction.
    pub fn set_cookie_header(&self, backend_addr: &str) -> Option<String> {
        match &self.mode {
            StickyMode::Cookie {
                name,
                path,
                http_only,
                secure,
                max_age,
            } => {
                let encoded = base64_encode_addr(backend_addr);
                let signature = sign_cookie_value(&encoded, &self.hmac_key);
                let value = format!("{}.{}", encoded, signature);
                let mut cookie = format!("{}={}; Path={}", name, value, path);
                if *max_age > 0 {
                    cookie.push_str(&format!("; Max-Age={}", max_age));
                }
                if *http_only {
                    cookie.push_str("; HttpOnly");
                }
                if *secure {
                    cookie.push_str("; Secure");
                }
                Some(cookie)
            }
            _ => None,
        }
    }

    /// Extracts a session key from the request cookies.
    /// For Cookie mode, the HMAC signature is verified and only the payload
    /// (base64-encoded backend address) is returned. For Route mode, the
    /// raw cookie value is returned as-is.
    pub fn extract_from_cookie(&self, cookie_header: &str) -> Option<String> {
        let cookie_name = match &self.mode {
            StickyMode::Cookie { name, .. } => name.as_str(),
            StickyMode::Route { cookie_name } => cookie_name.as_str(),
            _ => return None,
        };
        for part in cookie_header.split(';') {
            let part = part.trim();
            // Exact match: strip_prefix alone matches "sid" in "sid_other=val".
            // Verify the next character after the name is '='.
            if let Some(rest) = part.strip_prefix(cookie_name) {
                if let Some(val) = rest.strip_prefix('=') {
                    if !val.is_empty() {
                        // Cookie mode: verify HMAC signature before returning
                        if matches!(&self.mode, StickyMode::Cookie { .. }) {
                            return verify_and_extract_cookie_payload(val, &self.hmac_key);
                        }
                        return Some(val.to_string());
                    }
                }
            }
        }
        None
    }

    /// Extracts a session key from a response header for Learn mode.
    pub fn extract_from_response_header(&self, headers: &hyper::HeaderMap) -> Option<String> {
        if let StickyMode::Learn { lookup_header, .. } = &self.mode {
            headers
                .get(lookup_header.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        } else {
            None
        }
    }

    /// Spawns a background sweeper that periodically evicts expired session entries
    /// to prevent unbounded memory growth.
    pub fn spawn_sweeper(&self) {
        let table = Arc::clone(&self.table);
        let timeout = match &self.mode {
            StickyMode::Learn { timeout, .. } => *timeout,
            StickyMode::Cookie { max_age, .. } if *max_age > 0 => Duration::from_secs(*max_age),
            _ => return, // Cookie with max_age=0 or Route mode: no expiry sweep needed
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        handle.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                table.retain(|_key, entry| entry.created.elapsed() < timeout);
            }
        });
    }
}

/// Encodes a backend address (e.g. `"10.0.0.1:8080"`) as a URL-safe base64
/// string for embedding in cookies.
fn base64_encode_addr(addr: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(addr.as_bytes())
}

/// Decodes a URL-safe base64 cookie value back into a backend address string.
/// Returns `None` if the base64 is invalid or the decoded bytes are not valid UTF-8.
pub fn base64_decode_addr(encoded: &str) -> Option<String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// HMAC-SHA256 sign a cookie payload, returning the base64-encoded signature.
fn sign_cookie_value(payload: &str, key: &[u8; 32]) -> String {
    use base64::Engine;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key is always 32 bytes");
    mac.update(payload.as_bytes());
    let signature = mac.finalize().into_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature[..])
}

/// Verify an HMAC-signed cookie value of the form `<payload>.<signature>`.
/// Returns the payload on success, `None` if the format is invalid or the
/// signature does not match.
fn verify_and_extract_cookie_payload(value: &str, key: &[u8; 32]) -> Option<String> {
    use base64::Engine;
    let (payload, sig_b64) = value.rsplit_once('.')?;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .ok()?;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key is always 32 bytes");
    mac.update(payload.as_bytes());
    mac.verify_slice(&sig).ok()?;
    Some(payload.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie_manager() -> StickySessionManager {
        StickySessionManager::new(StickyMode::Cookie {
            name: "SERVERID".to_string(),
            path: "/".to_string(),
            http_only: true,
            secure: false,
            max_age: 3600,
        })
    }

    fn learn_manager() -> StickySessionManager {
        StickySessionManager::new(StickyMode::Learn {
            lookup_header: "X-Session-Id".to_string(),
            timeout: Duration::from_secs(60),
        })
    }

    fn route_manager() -> StickySessionManager {
        StickySessionManager::new(StickyMode::Route {
            cookie_name: "ROUTEID".to_string(),
        })
    }

    #[test]
    fn test_cookie_mode_learn_and_lookup() {
        let mgr = cookie_manager();
        mgr.learn("session-abc".to_string(), "10.0.0.1:8080".to_string());
        assert_eq!(mgr.lookup("session-abc"), Some("10.0.0.1:8080".to_string()));
        assert_eq!(mgr.lookup("nonexistent"), None);
    }

    #[test]
    fn test_cookie_mode_set_cookie_header() {
        let mgr = cookie_manager();
        let header = mgr.set_cookie_header("10.0.0.1:8080").unwrap();
        assert!(header.contains("SERVERID="));
        assert!(header.contains("Path=/"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Max-Age=3600"));
        assert!(!header.contains("Secure"));
    }

    #[test]
    fn test_cookie_mode_secure_flag() {
        let mgr = StickySessionManager::new(StickyMode::Cookie {
            name: "SRV".to_string(),
            path: "/api".to_string(),
            http_only: false,
            secure: true,
            max_age: 0,
        });
        let header = mgr.set_cookie_header("backend:80").unwrap();
        assert!(header.contains("Secure"));
        assert!(!header.contains("HttpOnly"));
        assert!(!header.contains("Max-Age"));
    }

    #[test]
    fn test_learn_mode_no_cookie_header() {
        let mgr = learn_manager();
        assert!(mgr.set_cookie_header("addr").is_none());
    }

    #[test]
    fn test_learn_mode_response_header_extraction() {
        let mgr = learn_manager();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("X-Session-Id", "sess-999".parse().unwrap());
        let key = mgr.extract_from_response_header(&headers);
        assert_eq!(key, Some("sess-999".to_string()));
    }

    #[test]
    fn test_learn_mode_missing_header() {
        let mgr = learn_manager();
        let headers = hyper::HeaderMap::new();
        assert_eq!(mgr.extract_from_response_header(&headers), None);
    }

    #[test]
    fn test_route_mode_extract_cookie() {
        let mgr = route_manager();
        let extracted = mgr.extract_from_cookie("other=val; ROUTEID=backend1; foo=bar");
        assert_eq!(extracted, Some("backend1".to_string()));
    }

    #[test]
    fn test_route_mode_missing_cookie() {
        let mgr = route_manager();
        assert_eq!(mgr.extract_from_cookie("other=val; foo=bar"), None);
    }

    /// M19 regression: prefix match must not confuse "sid" with "sid_other".
    #[test]
    fn test_cookie_exact_name_match() {
        let mgr = route_manager();
        // ROUTEID_other should NOT match ROUTEID
        assert_eq!(
            mgr.extract_from_cookie("ROUTEID_other=wrong; ROUTEID=correct"),
            Some("correct".to_string())
        );
        // Only the suffixed cookie should not match
        assert_eq!(
            mgr.extract_from_cookie("ROUTEID_other=val"),
            None
        );
    }

    #[test]
    fn test_base64_roundtrip() {
        let addr = "192.168.1.100:8080";
        let encoded = base64_encode_addr(addr);
        let decoded = base64_decode_addr(&encoded);
        assert_eq!(decoded, Some(addr.to_string()));
    }

    #[test]
    fn test_base64_decode_invalid() {
        assert!(base64_decode_addr("!!!invalid!!!").is_none());
    }

    #[test]
    fn test_learn_mode_timeout() {
        let mgr = StickySessionManager::new(StickyMode::Learn {
            lookup_header: "X-Sess".to_string(),
            timeout: Duration::from_secs(0),
        });
        mgr.learn("key".to_string(), "backend".to_string());
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(mgr.lookup("key"), None);
    }

    // ── HMAC signing tests ─────────────────────────────────────────────────

    #[test]
    fn test_cookie_hmac_sign_and_extract_roundtrip() {
        let mgr = cookie_manager();
        let header = mgr.set_cookie_header("10.0.0.1:8080").unwrap();
        // Extract the signed value from the Set-Cookie header
        let signed_value = header
            .split('=')
            .nth(1)
            .and_then(|s| s.split(';').next())
            .unwrap();
        // Reconstruct a Cookie header and extract
        let extracted = mgr.extract_from_cookie(&format!("SERVERID={}", signed_value));
        assert!(extracted.is_some());
        let decoded = base64_decode_addr(&extracted.unwrap());
        assert_eq!(decoded, Some("10.0.0.1:8080".to_string()));
    }

    #[test]
    fn test_cookie_hmac_tampered_payload_rejected() {
        let mgr = cookie_manager();
        let header = mgr.set_cookie_header("10.0.0.1:8080").unwrap();
        let signed_value = header
            .split('=')
            .nth(1)
            .and_then(|s| s.split(';').next())
            .unwrap();
        // Flip a character in the payload portion
        let mut chars: Vec<char> = signed_value.chars().collect();
        if let Some(pos) = chars.iter().position(|&c| c == '.') {
            if pos > 0 {
                chars[pos - 1] = if chars[pos - 1] == 'A' { 'B' } else { 'A' };
            }
        }
        let tampered: String = chars.into_iter().collect();
        assert!(mgr.extract_from_cookie(&format!("SERVERID={}", tampered)).is_none());
    }

    #[test]
    fn test_cookie_hmac_unsigned_rejected() {
        let mgr = cookie_manager();
        // A bare base64 value without signature is rejected
        assert!(mgr.extract_from_cookie("SERVERID=dGVzdA").is_none());
    }

    #[test]
    fn test_cookie_hmac_wrong_key_rejected() {
        let mgr_a = cookie_manager();
        let mgr_b = StickySessionManager::new(StickyMode::Cookie {
            name: "SERVERID".to_string(),
            path: "/".to_string(),
            http_only: true,
            secure: false,
            max_age: 3600,
        });
        let header = mgr_a.set_cookie_header("10.0.0.1:8080").unwrap();
        let signed_value = header
            .split('=')
            .nth(1)
            .and_then(|s| s.split(';').next())
            .unwrap();
        assert!(mgr_b.extract_from_cookie(&format!("SERVERID={}", signed_value)).is_none());
    }

    #[test]
    fn test_cookie_hmac_new_with_key_deterministic() {
        let key = [42u8; 32];
        let mgr1 = StickySessionManager::new_with_key(
            StickyMode::Cookie {
                name: "S".to_string(),
                path: "/".to_string(),
                http_only: false,
                secure: false,
                max_age: 0,
            },
            key,
        );
        let mgr2 = StickySessionManager::new_with_key(
            StickyMode::Cookie {
                name: "S".to_string(),
                path: "/".to_string(),
                http_only: false,
                secure: false,
                max_age: 0,
            },
            key,
        );
        // Same key → mgr2 can verify mgr1's cookies (cluster compatibility)
        let header = mgr1.set_cookie_header("10.0.0.1:8080").unwrap();
        let signed_value = header
            .split('=')
            .nth(1)
            .and_then(|s| s.split(';').next())
            .unwrap();
        let extracted = mgr2.extract_from_cookie(&format!("S={}", signed_value));
        assert!(extracted.is_some());
    }

    #[test]
    fn test_route_mode_unsigned_still_works() {
        // Route mode cookies are set by the backend — no HMAC expected
        let mgr = route_manager();
        let extracted = mgr.extract_from_cookie("other=val; ROUTEID=backend1; foo=bar");
        assert_eq!(extracted, Some("backend1".to_string()));
    }
}
