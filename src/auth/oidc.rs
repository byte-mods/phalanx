use dashmap::DashMap;
use hyper::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};

use super::AuthResult;

/// Configuration for an OpenID Connect Relying Party flow.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

/// Cached OIDC provider metadata (from `.well-known/openid-configuration`).
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
}

/// Token response from the OIDC provider.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    id_token: Option<String>,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
}

/// Session stored after successful OIDC login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcSession {
    pub sub: String,
    pub email: Option<String>,
    pub access_token: String,
    pub created_at: u64,
    pub expires_in: u64,
}

/// Thread-safe session store keyed by session cookie value.
pub type OidcSessionStore = Arc<DashMap<String, OidcSession>>;

pub fn new_session_store() -> OidcSessionStore {
    Arc::new(DashMap::new())
}

/// Fetches the OIDC discovery document from the issuer.
pub async fn discover(issuer_url: &str) -> Result<OidcDiscovery, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("OIDC discovery failed: {}", e))?;
    resp.json::<OidcDiscovery>()
        .await
        .map_err(|e| format!("OIDC discovery parse error: {}", e))
}

/// Generates the authorization redirect URL for the OIDC authorization code flow.
pub fn authorization_url(config: &OidcConfig, discovery: &OidcDiscovery, state: &str) -> String {
    let scopes = if config.scopes.is_empty() {
        "openid profile email".to_string()
    } else {
        config.scopes.join(" ")
    };

    format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        discovery.authorization_endpoint,
        urlencoded(&config.client_id),
        urlencoded(&config.redirect_uri),
        urlencoded(&scopes),
        urlencoded(state),
    )
}

/// Exchanges an authorization code for tokens.
pub async fn exchange_code(
    config: &OidcConfig,
    discovery: &OidcDiscovery,
    code: &str,
) -> Result<OidcSession, String> {
    let client = reqwest::Client::new();

    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &config.redirect_uri),
        ("client_id", &config.client_id),
        ("client_secret", &config.client_secret),
    ];

    let resp = client
        .post(&discovery.token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Token exchange failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Token endpoint returned {}", resp.status()));
    }

    let token_resp: TokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("Token parse error: {}", e))?;

    // Decode ID token claims (without full validation for simplicity)
    let sub = if let Some(ref id_token) = token_resp.id_token {
        extract_sub_from_id_token(id_token).unwrap_or_else(|| "unknown".to_string())
    } else {
        "unknown".to_string()
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(OidcSession {
        sub,
        email: None,
        access_token: token_resp.access_token,
        created_at: now,
        expires_in: token_resp.expires_in.unwrap_or(3600),
    })
}

/// Checks the request for an existing OIDC session cookie.
pub fn check_session(
    headers: &HeaderMap,
    cookie_name: &str,
    sessions: &OidcSessionStore,
) -> (AuthResult, Option<OidcSession>) {
    let cookie_val = extract_cookie(headers, cookie_name);

    match cookie_val {
        Some(session_id) => {
            if let Some(session) = sessions.get(&session_id) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if now > session.created_at + session.expires_in {
                    debug!("OIDC session expired for {}", session.sub);
                    drop(session);
                    sessions.remove(&session_id);
                    (
                        AuthResult::Denied(StatusCode::UNAUTHORIZED, "Session expired"),
                        None,
                    )
                } else {
                    (AuthResult::Allowed, Some(session.clone()))
                }
            } else {
                (
                    AuthResult::Denied(StatusCode::UNAUTHORIZED, "Invalid session"),
                    None,
                )
            }
        }
        None => (
            AuthResult::Denied(StatusCode::UNAUTHORIZED, "No session cookie"),
            None,
        ),
    }
}

/// Generates a random session ID for use as a cookie value.
pub fn generate_session_id() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
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

fn extract_sub_from_id_token(id_token: &str) -> Option<String> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims.get("sub").and_then(|v| v.as_str()).map(String::from)
}

fn urlencoded(input: &str) -> String {
    input
        .replace('%', "%25")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace(':', "%3A")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OidcConfig {
        OidcConfig {
            issuer_url: "https://idp.example.com".to_string(),
            client_id: "my-app".to_string(),
            client_secret: "secret123".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
        }
    }

    fn test_discovery() -> OidcDiscovery {
        OidcDiscovery {
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: Some("https://idp.example.com/userinfo".to_string()),
            jwks_uri: "https://idp.example.com/.well-known/jwks.json".to_string(),
        }
    }

    #[test]
    fn test_authorization_url_contains_params() {
        let url = authorization_url(&test_config(), &test_discovery(), "state123");
        assert!(url.starts_with("https://idp.example.com/authorize?"));
        assert!(url.contains("client_id=my-app"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("scope=openid%20profile"));
    }

    #[test]
    fn test_authorization_url_default_scopes() {
        let mut config = test_config();
        config.scopes = vec![];
        let url = authorization_url(&config, &test_discovery(), "s");
        assert!(url.contains("scope=openid%20profile%20email"));
    }

    #[test]
    fn test_new_session_store_empty() {
        let store = new_session_store();
        assert!(store.is_empty());
    }

    #[test]
    fn test_check_session_no_cookie() {
        let store = new_session_store();
        let headers = hyper::HeaderMap::new();
        let (result, session) = check_session(&headers, "oidc_session", &store);
        assert!(matches!(result, AuthResult::Denied(..)));
        assert!(session.is_none());
    }

    #[test]
    fn test_check_session_invalid_session_id() {
        let store = new_session_store();
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::COOKIE,
            "oidc_session=invalid-id".parse().unwrap(),
        );
        let (result, _) = check_session(&headers, "oidc_session", &store);
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_check_session_valid() {
        let store = new_session_store();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        store.insert(
            "valid-session".to_string(),
            OidcSession {
                sub: "user-1".to_string(),
                email: Some("user@example.com".to_string()),
                access_token: "at-123".to_string(),
                created_at: now,
                expires_in: 3600,
            },
        );
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::COOKIE,
            "oidc_session=valid-session".parse().unwrap(),
        );
        let (result, session) = check_session(&headers, "oidc_session", &store);
        assert!(matches!(result, AuthResult::Allowed));
        let session = session.unwrap();
        assert_eq!(session.sub, "user-1");
        assert_eq!(session.email, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_check_session_expired() {
        let store = new_session_store();
        store.insert(
            "expired".to_string(),
            OidcSession {
                sub: "user-2".to_string(),
                email: None,
                access_token: "at".to_string(),
                created_at: 1000,
                expires_in: 1,
            },
        );
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::COOKIE,
            "oidc_session=expired".parse().unwrap(),
        );
        let (result, _) = check_session(&headers, "oidc_session", &store);
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_extract_sub_from_id_token() {
        use base64::Engine;
        let claims = serde_json::json!({"sub": "user-42", "name": "Test"});
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let token = format!("header.{}.signature", payload_b64);
        assert_eq!(
            extract_sub_from_id_token(&token),
            Some("user-42".to_string())
        );
    }

    #[test]
    fn test_extract_sub_from_id_token_malformed() {
        assert_eq!(extract_sub_from_id_token("no-dots"), None);
    }

    #[test]
    fn test_urlencoded() {
        assert_eq!(urlencoded("hello world"), "hello%20world");
        assert_eq!(urlencoded("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencoded("http://x"), "http%3A%2F%2Fx");
    }

    #[test]
    fn test_generate_session_id_length() {
        let id = generate_session_id();
        assert_eq!(id.len(), 64, "32 bytes hex-encoded = 64 chars");
    }

    #[test]
    fn test_generate_session_id_unique() {
        let a = generate_session_id();
        let b = generate_session_id();
        assert_ne!(a, b);
    }

    #[test]
    fn test_extract_cookie_present() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::COOKIE,
            "sid=abc; other=xyz".parse().unwrap(),
        );
        assert_eq!(extract_cookie(&headers, "sid"), Some("abc".to_string()));
    }

    #[test]
    fn test_extract_cookie_absent() {
        let headers = hyper::HeaderMap::new();
        assert_eq!(extract_cookie(&headers, "sid"), None);
    }
}
