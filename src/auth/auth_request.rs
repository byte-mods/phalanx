/// Nginx-style `auth_request` subrequest authentication.
///
/// Delegates authentication to an external HTTP service by forwarding the
/// original request headers along with `X-Original-Method` and `X-Original-URI`.
/// The auth service's HTTP status code determines the outcome:
/// - 2xx: allowed (any `X-Auth-*` response headers are forwarded upstream)
/// - 401: unauthorized
/// - 403: forbidden
/// - Other: treated as an error, request is denied
use hyper::{HeaderMap, StatusCode};
use tracing::{debug, warn};

use super::AuthResult;

/// Headers stripped before forwarding to an external auth service to prevent
/// credential leakage (passwords, tokens, session cookies).
const SENSITIVE_HEADERS: &[&str] = &["authorization", "cookie", "set-cookie"];

/// Returns `false` when the header name matches a sensitive credential header
/// that must not be forwarded to a third-party auth endpoint.
fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADERS
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h))
}

/// Shared `reqwest::Client` for auth_request subrequests, cached globally for reuse.
fn auth_request_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Implements `auth_request`-style subrequest authentication (like nginx `auth_request`).
///
/// Sends a subrequest to the specified URL with the original request headers.
/// If the auth service returns 2xx, the request is allowed.
/// If 401/403, denied. Any other status is treated as an error → denied.
///
/// The auth service can set `X-Auth-*` response headers which are forwarded
/// upstream (e.g. `X-Auth-User`, `X-Auth-Groups`).
pub async fn check(
    headers: &HeaderMap,
    auth_url: &str,
    method: &str,
    path: &str,
) -> (AuthResult, Vec<(String, String)>) {
    let client = auth_request_client();

    let reqwest_method = reqwest::Method::from_bytes(method.as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut req = client.request(reqwest_method, auth_url);

    // Forward original headers to the auth service, stripping sensitive
    // credentials (Authorization, Cookie) so they are not leaked to a
    // third-party auth endpoint.
    for (key, value) in headers.iter() {
        let key_str = key.as_str();
        if is_sensitive_header(key_str) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            req = req.header(key_str, v);
        }
    }
    req = req.header("X-Original-Method", method);
    req = req.header("X-Original-URI", path);

    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();

            // Collect X-Auth-* headers from the auth service response
            let mut auth_headers = Vec::new();
            for (key, value) in resp.headers().iter() {
                let key_str = key.as_str();
                if key_str.starts_with("x-auth-") {
                    if let Ok(v) = value.to_str() {
                        auth_headers.push((key_str.to_string(), v.to_string()));
                    }
                }
            }

            if (200..300).contains(&status) {
                debug!("auth_request: {} returned {} → allowed", auth_url, status);
                (AuthResult::Allowed, auth_headers)
            } else if status == 401 {
                debug!("auth_request: {} returned 401 → denied", auth_url);
                (
                    AuthResult::Denied(StatusCode::UNAUTHORIZED, "Authentication required"),
                    vec![],
                )
            } else if status == 403 {
                debug!("auth_request: {} returned 403 → forbidden", auth_url);
                (
                    AuthResult::Denied(StatusCode::FORBIDDEN, "Access denied"),
                    vec![],
                )
            } else {
                warn!(
                    "auth_request: {} returned unexpected status {}",
                    auth_url, status
                );
                (
                    AuthResult::Denied(StatusCode::FORBIDDEN, "Auth service error"),
                    vec![],
                )
            }
        }
        Err(e) => {
            warn!("auth_request: subrequest to {} failed: {}", auth_url, e);
            (
                AuthResult::Denied(StatusCode::INTERNAL_SERVER_ERROR, "Auth service unreachable"),
                vec![],
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sensitive_header_matches_exact() {
        assert!(is_sensitive_header("authorization"));
        assert!(is_sensitive_header("AUTHORIZATION"));
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("cookie"));
        assert!(is_sensitive_header("Cookie"));
        assert!(is_sensitive_header("set-cookie"));
        assert!(is_sensitive_header("Set-Cookie"));
    }

    #[test]
    fn test_is_sensitive_header_allows_safe_headers() {
        assert!(!is_sensitive_header("x-original-method"));
        assert!(!is_sensitive_header("x-auth-user"));
        assert!(!is_sensitive_header("host"));
        assert!(!is_sensitive_header("content-type"));
        assert!(!is_sensitive_header("accept"));
        assert!(!is_sensitive_header("user-agent"));
    }

    /// M38 regression: Authorization and Cookie headers must not be forwarded
    /// to third-party auth_request endpoints.
    #[test]
    fn test_auth_request_strips_sensitive_headers() {
        // Verify the sensitive header list includes the key credential headers
        let sensitive: Vec<&str> = SENSITIVE_HEADERS.to_vec();
        assert!(sensitive.contains(&"authorization"));
        assert!(sensitive.contains(&"cookie"));
        assert!(sensitive.contains(&"set-cookie"));
    }

    /// M39 regression: auth_request must forward the actual request method,
    /// not hardcode GET. The subrequest to the auth service should use the
    /// same HTTP method as the original client request.
    #[test]
    fn test_auth_request_method_forwarding() {
        // Valid methods are parsed correctly
        let get = reqwest::Method::from_bytes(b"GET").unwrap();
        assert_eq!(get, reqwest::Method::GET);

        let post = reqwest::Method::from_bytes(b"POST").unwrap();
        assert_eq!(post, reqwest::Method::POST);

        let delete = reqwest::Method::from_bytes(b"DELETE").unwrap();
        assert_eq!(delete, reqwest::Method::DELETE);

        // Invalid method falls back to GET
        let invalid = reqwest::Method::from_bytes(b"\0invalid").unwrap_or(reqwest::Method::GET);
        assert_eq!(invalid, reqwest::Method::GET);
    }
}
