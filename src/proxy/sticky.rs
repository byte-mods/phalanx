use dashmap::DashMap;
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

/// Thread-safe session affinity manager shared across all proxy tasks.
pub struct StickySessionManager {
    mode: StickyMode,
    /// Maps session-id → backend address for Cookie and Learn modes.
    table: Arc<DashMap<String, LearnedEntry>>,
}

impl StickySessionManager {
    pub fn new(mode: StickyMode) -> Self {
        Self {
            mode,
            table: Arc::new(DashMap::new()),
        }
    }

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
                let mut cookie = format!("{}={}; Path={}", name, encoded, path);
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
    pub fn extract_from_cookie(&self, cookie_header: &str) -> Option<String> {
        let cookie_name = match &self.mode {
            StickyMode::Cookie { name, .. } => name.as_str(),
            StickyMode::Route { cookie_name } => cookie_name.as_str(),
            _ => return None,
        };
        for part in cookie_header.split(';') {
            let part = part.trim();
            if let Some(val) = part.strip_prefix(cookie_name) {
                let val = val.trim_start_matches('=');
                if !val.is_empty() {
                    return Some(val.to_string());
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
}

fn base64_encode_addr(addr: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(addr.as_bytes())
}

pub fn base64_decode_addr(encoded: &str) -> Option<String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
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
}
