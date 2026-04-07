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
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("auth_request: failed to create HTTP client: {}", e);
            return (
                AuthResult::Denied(StatusCode::INTERNAL_SERVER_ERROR, "Auth service unavailable"),
                vec![],
            );
        }
    };

    let mut req = client.get(auth_url);

    // Forward original headers to the auth service
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            req = req.header(key.as_str(), v);
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
