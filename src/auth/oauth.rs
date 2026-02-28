use super::AuthResult;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use dashmap::DashMap;
use hyper::{HeaderMap, StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};

/// The duration to cache a valid (active) introspection result.
const CACHE_TTL: Duration = Duration::from_secs(60);

/// OAuth 2.0 Token Introspection response (RFC 7662).
#[derive(Debug, Deserialize)]
struct IntrospectResponse {
    active: bool,
    sub: Option<String>,
    scope: Option<String>,
    #[allow(dead_code)]
    exp: Option<u64>,
}

/// Shared, async-safe OAuth token introspection cache.
/// Key: raw Bearer token string. Value: cached introspection result.
pub type OAuthCache = Arc<DashMap<String, (bool, Option<String>, Instant)>>;

/// Create a new empty OAuth cache.
pub fn new_cache() -> OAuthCache {
    Arc::new(DashMap::new())
}

/// Check OAuth 2.0 Bearer token via RFC 7662 token introspection.
///
/// Calls the configured `introspect_url` with the token as a POST body.
/// Results are cached for `CACHE_TTL` seconds to avoid hammering the auth server.
///
/// On success, returns `Allowed` and the `sub` claim if present.
/// On failure or inactive token, returns `Denied(401)`.
pub async fn check(
    headers: &HeaderMap,
    introspect_url: &str,
    client_id: &str,
    client_secret: &str,
    cache: &OAuthCache,
) -> (AuthResult, Option<String>) {
    // Extract Bearer token
    let token = match extract_bearer_token(headers) {
        Some(t) => t.to_string(),
        None => {
            return (
                AuthResult::Denied(
                    StatusCode::UNAUTHORIZED,
                    "Missing or malformed Bearer token",
                ),
                None,
            );
        }
    };

    // Check cache first
    if let Some(entry) = cache.get(&token) {
        let (active, sub, cached_at) = entry.value().clone();
        if cached_at.elapsed() < CACHE_TTL {
            debug!("OAuth cache hit for token (active={})", active);
            return if active {
                (AuthResult::Allowed, sub)
            } else {
                (
                    AuthResult::Denied(StatusCode::UNAUTHORIZED, "OAuth token is inactive"),
                    None,
                )
            };
        }
        // Expired cache entry — remove it
        drop(entry);
        cache.remove(&token);
    }

    // Call introspection endpoint
    match introspect_token(&token, introspect_url, client_id, client_secret).await {
        Ok(resp) => {
            let sub = resp.sub.clone();
            // Cache the result
            cache.insert(token.clone(), (resp.active, sub.clone(), Instant::now()));
            if resp.active {
                debug!("OAuth token active, scope={:?}", resp.scope);
                (AuthResult::Allowed, sub)
            } else {
                warn!("OAuth token introspection returned inactive");
                (
                    AuthResult::Denied(
                        StatusCode::UNAUTHORIZED,
                        "OAuth token is inactive or revoked",
                    ),
                    None,
                )
            }
        }
        Err(e) => {
            error!("OAuth introspection request failed: {}", e);
            (
                AuthResult::Denied(StatusCode::UNAUTHORIZED, "OAuth token validation failed"),
                None,
            )
        }
    }
}

/// Make the HTTP POST introspection request to the auth server.
async fn introspect_token(
    token: &str,
    introspect_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<IntrospectResponse, String> {
    let client = reqwest_client()?;

    // Build HTTP Basic auth header for the client credentials
    let credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let auth_header = format!("Basic {credentials}");

    // Build form body
    let body = format!("token={}", urlencoded(token));

    let response = client
        .post(introspect_url)
        .header("Authorization", auth_header)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("HTTP request to introspect_url failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "Introspection endpoint returned HTTP {}",
            response.status()
        ));
    }

    response
        .json::<IntrospectResponse>()
        .await
        .map_err(|e| format!("Failed to parse introspection response: {e}"))
}

/// Build a minimal `reqwest` HTTP client.
fn reqwest_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))
}

/// URL-encode a token string (percent-encode special characters).
fn urlencoded(input: &str) -> String {
    input
        .chars()
        .flat_map(|c| {
            if c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                vec![c]
            } else {
                // Percent-encode the byte(s)
                c.encode_utf8(&mut [0u8; 4])
                    .bytes()
                    .flat_map(|b| format!("%{:02X}", b).chars().collect::<Vec<_>>())
                    .collect()
            }
        })
        .collect()
}

/// Extract the raw token from `Authorization: Bearer <token>`.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(hyper::header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::trim)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            hyper::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    #[test]
    fn test_cache_hit_active_allowed() {
        let cache = new_cache();
        cache.insert(
            "valid-token".to_string(),
            (true, Some("user-1".to_string()), Instant::now()),
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (result, sub) = rt.block_on(check(
            &bearer_headers("valid-token"),
            "https://does-not-matter.example.com/introspect",
            "client",
            "secret",
            &cache,
        ));
        assert!(matches!(result, AuthResult::Allowed));
        assert_eq!(sub.as_deref(), Some("user-1"));
    }

    #[test]
    fn test_cache_hit_inactive_denied() {
        let cache = new_cache();
        cache.insert("inactive-token".to_string(), (false, None, Instant::now()));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (result, _) = rt.block_on(check(
            &bearer_headers("inactive-token"),
            "https://does-not-matter.example.com/introspect",
            "client",
            "secret",
            &cache,
        ));
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_missing_bearer_denied() {
        let cache = new_cache();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (result, _) = rt.block_on(check(
            &HeaderMap::new(),
            "https://does-not-matter.example.com/introspect",
            "client",
            "secret",
            &cache,
        ));
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_expired_cache_entry_evicted() {
        let cache = new_cache();
        // Insert an expired entry (cached 2 minutes ago)
        let old = Instant::now()
            .checked_sub(Duration::from_secs(120))
            .unwrap_or(Instant::now());
        cache.insert("old-token".to_string(), (true, None, old));

        // The cache should detect expiry and attempt a live introspection.
        // Since the URL is unreachable, it should return Denied with an error.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (result, _) = rt.block_on(check(
            &bearer_headers("old-token"),
            "http://127.0.0.1:0/introspect", // no server
            "client",
            "secret",
            &cache,
        ));
        // Expects Denied because the live introspection fails
        assert!(matches!(result, AuthResult::Denied(..)));
        // Cache entry should have been removed
        assert!(!cache.contains_key("old-token"));
    }

    #[test]
    fn test_urlencoded_plain() {
        assert_eq!(urlencoded("hello"), "hello");
    }

    #[test]
    fn test_urlencoded_special_chars() {
        let encoded = urlencoded("a b+c");
        assert!(encoded.contains("%20") || encoded.contains('+'));
        assert!(!encoded.contains(' '));
    }
}
