/// OAuth 2.0 Token Introspection (RFC 7662) authentication.
///
/// Validates Bearer tokens by calling a remote introspection endpoint with
/// the proxy's own client credentials. Results are cached in a thread-safe
/// [`DashMap`] to avoid hammering the authorization server on every request.
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
///
/// The `active` field is the only mandatory field -- if `false`, the token
/// is expired, revoked, or otherwise invalid.
#[derive(Debug, Deserialize)]
struct IntrospectResponse {
    /// Whether the token is currently active and valid.
    active: bool,
    /// Subject identifier for the token owner.
    sub: Option<String>,
    /// Space-delimited list of OAuth scopes granted to the token.
    scope: Option<String>,
    /// Token expiration time (Unix timestamp); used to cap cache TTL.
    exp: Option<u64>,
}

/// Shared, async-safe OAuth token introspection cache.
/// Key: raw Bearer token string. Value: (active, subject, cached_at, token_exp).
pub type OAuthCache = Arc<DashMap<String, (bool, Option<String>, Instant, Option<u64>)>>;

/// Create a new empty OAuth cache.
pub fn new_cache() -> OAuthCache {
    Arc::new(DashMap::new())
}

/// Spawns a background task that periodically removes expired entries from the cache.
pub fn spawn_cache_reaper(cache: OAuthCache) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cache.retain(|_, (_, _, cached_at, exp)| {
                // Remove if past fixed TTL
                if cached_at.elapsed() >= CACHE_TTL {
                    return false;
                }
                // Remove if token has expired (exp is in the past)
                if let Some(exp_ts) = exp {
                    let now_ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now_ts >= *exp_ts {
                        return false;
                    }
                }
                true
            });
        }
    });
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
        let (active, sub, cached_at, exp) = entry.value().clone();
        // Effective TTL: min(CACHE_TTL, time until token exp)
        let effective_ttl = match exp {
            Some(exp_ts) => {
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now_ts >= exp_ts {
                    Duration::from_secs(0) // already expired
                } else {
                    CACHE_TTL.min(Duration::from_secs(exp_ts - now_ts))
                }
            }
            None => CACHE_TTL,
        };
        if cached_at.elapsed() < effective_ttl {
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
            // Cache the result (include exp for TTL capping)
            cache.insert(token.clone(), (resp.active, sub.clone(), Instant::now(), resp.exp));
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
    let client = reqwest_client();

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

/// Build a minimal `reqwest` HTTP client, cached globally for reuse.
fn reqwest_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// URL-encode a token string (percent-encode special characters).
///
/// Implements RFC 3986 unreserved character pass-through: alphanumeric and
/// `-`, `_`, `.`, `~` are left as-is; everything else is percent-encoded
/// byte-by-byte (supporting multi-byte UTF-8 characters).
fn urlencoded(input: &str) -> String {
    input
        .chars()
        .flat_map(|c| {
            if c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                // Unreserved characters pass through unchanged
                vec![c]
            } else {
                // Percent-encode each byte of the UTF-8 representation
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
            (true, Some("user-1".to_string()), Instant::now(), None),
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
        cache.insert("inactive-token".to_string(), (false, None, Instant::now(), None));
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
        cache.insert("old-token".to_string(), (true, None, old, None));

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
    fn test_cache_entry_with_exp_in_past_is_evicted() {
        let cache = new_cache();
        // Token expired 10 seconds ago
        let past_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 10;
        cache.insert(
            "expired-token".to_string(),
            (true, Some("user-1".to_string()), Instant::now(), Some(past_exp)),
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (result, _) = rt.block_on(check(
            &bearer_headers("expired-token"),
            "http://127.0.0.1:0/introspect",
            "client",
            "secret",
            &cache,
        ));
        // Effective TTL is 0 due to past exp, so cache miss → introspection fails → Denied
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_cache_reaper_removes_expired_entries() {
        let cache = new_cache();
        let old = Instant::now()
            .checked_sub(Duration::from_secs(120))
            .unwrap_or(Instant::now());
        cache.insert("stale".to_string(), (true, None, old, None));
        cache.insert("fresh".to_string(), (true, None, Instant::now(), None));

        // Manually run the reaper logic
        cache.retain(|_, (_, _, cached_at, exp)| {
            if cached_at.elapsed() >= CACHE_TTL {
                return false;
            }
            if let Some(exp_ts) = exp {
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now_ts >= *exp_ts {
                    return false;
                }
            }
            true
        });

        assert!(!cache.contains_key("stale"));
        assert!(cache.contains_key("fresh"));
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
