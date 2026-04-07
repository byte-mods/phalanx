/// OpenID Connect (OIDC) Relying Party implementation.
///
/// Implements the Authorization Code Flow: redirects unauthenticated users to
/// the identity provider, exchanges authorization codes for tokens, and manages
/// server-side sessions via secure cookies. Sessions are stored in a concurrent
/// [`DashMap`] keyed by a random 256-bit hex session ID.
use dashmap::DashMap;
use hyper::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::debug;

use super::AuthResult;

/// Configuration for an OpenID Connect Relying Party flow.
///
/// Typically populated from the Phalanx YAML config and used to drive
/// the authorization code exchange with the identity provider.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Base URL of the OIDC issuer (e.g., `https://accounts.google.com`).
    pub issuer_url: String,
    /// OAuth client ID registered with the provider.
    pub client_id: String,
    /// OAuth client secret for confidential client authentication.
    pub client_secret: String,
    /// The callback URL the provider redirects to after login.
    pub redirect_uri: String,
    /// Requested scopes (defaults to `openid profile email` if empty).
    pub scopes: Vec<String>,
}

/// Cached OIDC provider metadata (from `.well-known/openid-configuration`).
///
/// Contains the essential endpoints the RP needs to complete the auth code flow.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    /// URL where the RP redirects the user to authenticate.
    pub authorization_endpoint: String,
    /// URL where the RP exchanges an auth code for tokens.
    pub token_endpoint: String,
    /// Optional URL to fetch additional user profile claims.
    pub userinfo_endpoint: Option<String>,
    /// URL of the provider's JWKS endpoint for ID token signature verification.
    pub jwks_uri: String,
}

/// Token response from the OIDC provider's token endpoint.
///
/// Contains the access token, optional ID token (for OIDC), and refresh token.
/// The `id_token` is decoded to extract the `sub` claim for session creation.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TokenResponse {
    /// Bearer access token for API calls.
    access_token: String,
    /// OIDC ID token (JWT) containing identity claims.
    id_token: Option<String>,
    /// Token type, typically "Bearer".
    token_type: String,
    /// Token lifetime in seconds.
    expires_in: Option<u64>,
    /// Refresh token for obtaining new access tokens without re-authentication.
    refresh_token: Option<String>,
}

/// Session stored after successful OIDC login.
///
/// Persisted server-side in the [`OidcSessionStore`] and referenced by a
/// random session cookie. The session tracks the user's identity, access
/// token, and expiration so the proxy can enforce session timeouts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcSession {
    /// Subject identifier from the ID token (unique user ID).
    pub sub: String,
    /// User email, if available from the ID token or userinfo endpoint.
    pub email: Option<String>,
    /// The OIDC issuer that created this session, for multi-IdP validation.
    #[serde(default)]
    pub issuer: Option<String>,
    /// The OAuth access token, useful for proxying authenticated API calls.
    pub access_token: String,
    /// Refresh token for obtaining new access tokens without re-authentication.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Unix timestamp (seconds) when the session was created.
    pub created_at: u64,
    /// Session lifetime in seconds from creation time.
    pub expires_in: u64,
}

/// Thread-safe session store keyed by session cookie value.
pub type OidcSessionStore = Arc<DashMap<String, OidcSession>>;

/// Creates a new empty OIDC session store backed by a concurrent hash map.
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

/// Thread-safe store for PKCE code verifiers, keyed by OAuth state parameter.
pub type PkceVerifierStore = Arc<DashMap<String, String>>;

/// Creates a new empty PKCE verifier store.
pub fn new_pkce_verifier_store() -> PkceVerifierStore {
    Arc::new(DashMap::new())
}

/// Generates a cryptographically random PKCE code_verifier (43-128 chars, RFC 7636).
pub fn generate_code_verifier() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Computes the S256 code_challenge from a code_verifier (SHA-256 + base64url).
pub fn compute_code_challenge(verifier: &str) -> String {
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(verifier.as_bytes());
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Generates the authorization redirect URL for the OIDC authorization code flow.
///
/// If `pkce_store` is provided, generates a PKCE code_verifier, stores it keyed
/// by `state`, and appends `code_challenge` + `code_challenge_method=S256` to the URL.
pub fn authorization_url(config: &OidcConfig, discovery: &OidcDiscovery, state: &str) -> String {
    authorization_url_with_pkce(config, discovery, state, None)
}

/// Generates the authorization URL with optional PKCE support.
pub fn authorization_url_with_pkce(
    config: &OidcConfig,
    discovery: &OidcDiscovery,
    state: &str,
    pkce_store: Option<&PkceVerifierStore>,
) -> String {
    let scopes = if config.scopes.is_empty() {
        "openid profile email".to_string()
    } else {
        config.scopes.join(" ")
    };

    let mut url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        discovery.authorization_endpoint,
        urlencoded(&config.client_id),
        urlencoded(&config.redirect_uri),
        urlencoded(&scopes),
        urlencoded(state),
    );

    if let Some(store) = pkce_store {
        let verifier = generate_code_verifier();
        let challenge = compute_code_challenge(&verifier);
        store.insert(state.to_string(), verifier);
        url.push_str(&format!(
            "&code_challenge={}&code_challenge_method=S256",
            urlencoded(&challenge),
        ));
    }

    url
}

/// Exchanges an authorization code for tokens.
///
/// If `code_verifier` is provided, it is included in the token request for PKCE validation.
pub async fn exchange_code(
    config: &OidcConfig,
    discovery: &OidcDiscovery,
    code: &str,
) -> Result<OidcSession, String> {
    exchange_code_with_pkce(config, discovery, code, None).await
}

/// Exchanges an authorization code for tokens with optional PKCE verifier.
pub async fn exchange_code_with_pkce(
    config: &OidcConfig,
    discovery: &OidcDiscovery,
    code: &str,
    code_verifier: Option<&str>,
) -> Result<OidcSession, String> {
    let client = reqwest::Client::new();

    let mut params: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &config.redirect_uri),
        ("client_id", &config.client_id),
        ("client_secret", &config.client_secret),
    ];
    if let Some(verifier) = code_verifier {
        params.push(("code_verifier", verifier));
    }

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
        issuer: Some(config.issuer_url.clone()),
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token,
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

/// Refreshes an expired session using the refresh_token grant type.
///
/// POSTs `grant_type=refresh_token` to the token endpoint and returns a new
/// session if successful.
pub async fn refresh_session(
    config: &OidcConfig,
    discovery: &OidcDiscovery,
    refresh_token: &str,
) -> Result<OidcSession, String> {
    let client = reqwest::Client::new();

    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", &config.client_id),
        ("client_secret", &config.client_secret),
    ];

    let resp = client
        .post(&discovery.token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Refresh token exchange failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Token endpoint returned {}", resp.status()));
    }

    let token_resp: TokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("Token parse error: {}", e))?;

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
        issuer: Some(config.issuer_url.clone()),
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token,
        created_at: now,
        expires_in: token_resp.expires_in.unwrap_or(3600),
    })
}

/// Async variant of `check_session` that attempts token refresh on expiry.
///
/// When a session is expired but has a refresh_token, this function will
/// attempt to refresh it before returning 401. On success the session store
/// is updated with the new session.
pub async fn check_session_async(
    headers: &HeaderMap,
    cookie_name: &str,
    sessions: &OidcSessionStore,
    config: Option<&OidcConfig>,
    discovery: Option<&OidcDiscovery>,
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
                    // Session expired — try refresh if possible
                    let refresh_token = session.refresh_token.clone();
                    drop(session);

                    if let (Some(rt), Some(cfg), Some(disc)) = (refresh_token, config, discovery) {
                        match refresh_session(cfg, disc, &rt).await {
                            Ok(new_session) => {
                                debug!("OIDC session refreshed for {}", new_session.sub);
                                let result_session = new_session.clone();
                                sessions.insert(session_id, new_session);
                                return (AuthResult::Allowed, Some(result_session));
                            }
                            Err(e) => {
                                debug!("OIDC refresh failed: {}", e);
                                sessions.remove(&session_id);
                            }
                        }
                    } else {
                        sessions.remove(&session_id);
                    }

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

/// Validates that a session was issued by the expected OIDC issuer.
/// If the session has no issuer metadata while one is required, validation fails closed.
pub fn session_matches_issuer(session: &OidcSession, expected_issuer: &str) -> bool {
    match session.issuer.as_deref() {
        Some(iss) => iss.trim_end_matches('/') == expected_issuer.trim_end_matches('/'),
        None => false,
    }
}

/// Generates a random session ID for use as a cookie value.
pub fn generate_session_id() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Extracts a named cookie value from the `Cookie` request header.
///
/// Parses the semicolon-delimited cookie string and returns the first
/// matching value, or `None` if the cookie is absent or empty.
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

/// Extracts the `sub` claim from a JWT ID token without full cryptographic validation.
///
/// Splits the token on `.`, base64url-decodes the payload (part 2), and reads
/// the `sub` field. This is safe because the token has already been received
/// over a trusted TLS channel from the token endpoint.
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

/// Minimal percent-encoding for URL query parameter values.
///
/// Encodes characters that are unsafe in query strings (space, ampersand,
/// equals, plus, slash, colon, percent) while leaving alphanumeric characters
/// and other safe characters untouched.
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
                issuer: Some("https://idp.example.com".to_string()),
                access_token: "at-123".to_string(),
                refresh_token: None,
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
                issuer: Some("https://idp.example.com".to_string()),
                access_token: "at".to_string(),
                refresh_token: None,
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

    #[test]
    fn test_session_matches_issuer_exact() {
        let s = OidcSession {
            sub: "u".to_string(),
            email: None,
            issuer: Some("https://idp.example.com".to_string()),
            access_token: "a".to_string(),
            refresh_token: None,
            created_at: 1,
            expires_in: 1,
        };
        assert!(session_matches_issuer(&s, "https://idp.example.com"));
    }

    #[test]
    fn test_session_matches_issuer_rejects_missing_issuer() {
        let s = OidcSession {
            sub: "u".to_string(),
            email: None,
            issuer: None,
            access_token: "a".to_string(),
            refresh_token: None,
            created_at: 1,
            expires_in: 1,
        };
        assert!(!session_matches_issuer(&s, "https://idp.example.com"));
    }

    #[test]
    fn test_session_refresh_token_stored() {
        // Verify OidcSession can hold a refresh_token
        let session = OidcSession {
            sub: "user-1".to_string(),
            email: None,
            issuer: Some("https://idp.example.com".to_string()),
            access_token: "at-123".to_string(),
            refresh_token: Some("rt-xyz".to_string()),
            created_at: 1000,
            expires_in: 3600,
        };
        assert_eq!(session.refresh_token, Some("rt-xyz".to_string()));
    }

    #[test]
    fn test_session_without_refresh_token() {
        let session = OidcSession {
            sub: "user-1".to_string(),
            email: None,
            issuer: None,
            access_token: "at".to_string(),
            refresh_token: None,
            created_at: 1000,
            expires_in: 3600,
        };
        assert!(session.refresh_token.is_none());
    }

    #[test]
    fn test_session_serialization_with_refresh_token() {
        let session = OidcSession {
            sub: "u".to_string(),
            email: None,
            issuer: None,
            access_token: "a".to_string(),
            refresh_token: Some("rt-1".to_string()),
            created_at: 1,
            expires_in: 1,
        };
        let json = serde_json::to_string(&session).unwrap();
        let decoded: OidcSession = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.refresh_token, Some("rt-1".to_string()));
    }

    #[test]
    fn test_session_deserialization_without_refresh_token() {
        // Sessions without refresh_token (legacy) should deserialize with None
        let json = r#"{"sub":"u","email":null,"issuer":null,"access_token":"a","created_at":1,"expires_in":1}"#;
        let session: OidcSession = serde_json::from_str(json).unwrap();
        assert!(session.refresh_token.is_none());
    }

    #[tokio::test]
    async fn test_check_session_async_expired_no_refresh() {
        let store = new_session_store();
        store.insert(
            "expired".to_string(),
            OidcSession {
                sub: "user".to_string(),
                email: None,
                issuer: None,
                access_token: "at".to_string(),
                refresh_token: None,
                created_at: 1000,
                expires_in: 1,
            },
        );
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::COOKIE,
            "sess=expired".parse().unwrap(),
        );
        let (result, _) = check_session_async(&headers, "sess", &store, None, None).await;
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    // ── PKCE Tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_generate_code_verifier_length() {
        let verifier = generate_code_verifier();
        // 32 bytes base64url encoded = 43 chars (no padding)
        assert_eq!(verifier.len(), 43);
    }

    #[test]
    fn test_generate_code_verifier_unique() {
        let a = generate_code_verifier();
        let b = generate_code_verifier();
        assert_ne!(a, b);
    }

    #[test]
    fn test_compute_code_challenge_s256() {
        // RFC 7636 Appendix B test vector:
        // verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        // expected challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = compute_code_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn test_authorization_url_with_pkce_includes_challenge() {
        let store = new_pkce_verifier_store();
        let url = authorization_url_with_pkce(
            &test_config(),
            &test_discovery(),
            "state-xyz",
            Some(&store),
        );
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        // Verifier should be stored
        assert!(store.contains_key("state-xyz"));
    }

    #[test]
    fn test_authorization_url_without_pkce_no_challenge() {
        let url = authorization_url(&test_config(), &test_discovery(), "state-abc");
        assert!(!url.contains("code_challenge"));
    }

    #[test]
    fn test_pkce_verifier_store_operations() {
        let store = new_pkce_verifier_store();
        assert!(store.is_empty());
        store.insert("state-1".to_string(), "verifier-1".to_string());
        assert_eq!(store.len(), 1);
        let v = store.remove("state-1").map(|(_, v)| v);
        assert_eq!(v, Some("verifier-1".to_string()));
        assert!(store.is_empty());
    }
}
