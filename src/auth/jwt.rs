/// JWT Bearer token authentication.
///
/// Validates `Authorization: Bearer <token>` headers using the `jsonwebtoken` crate.
/// Supports HMAC (HS256/384/512), RSA (RS256/384/512), and ECDSA (ES256/384)
/// algorithms. On success, decoded claims are returned so the proxy can inject
/// `X-Auth-*` headers into upstream requests.
use super::AuthResult;
use hyper::{HeaderMap, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standard JWT claims extracted on successful token validation.
///
/// Only commonly used claims are deserialized; additional custom claims
/// are silently ignored by serde. The `aud` field uses a generic JSON value
/// because the JWT spec allows it to be either a string or an array of strings.
#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    /// Subject identifier (unique user ID in the IdP).
    pub sub: Option<String>,
    /// User email address, if present in the token.
    pub email: Option<String>,
    /// Expiration time as a Unix timestamp (seconds since epoch).
    pub exp: Option<u64>,
    /// Issuer of the token (e.g., `https://auth.example.com`).
    pub iss: Option<String>,
    /// Audience claim -- can be a single string or array of strings per RFC 7519.
    pub aud: Option<serde_json::Value>,
}

/// Check JWT Bearer token authentication.
///
/// Validates the `Authorization: Bearer <token>` header against the configured
/// secret key and algorithm. Checks expiry automatically.
///
/// On success, returns `Allowed` plus decoded claims for header forwarding.
/// On failure, returns `Denied(401)`.
pub fn check(headers: &HeaderMap, secret: &str, algorithm: &str) -> (AuthResult, Option<Claims>) {
    let token = match extract_bearer_token(headers) {
        Some(t) => t,
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

    let algo = match parse_algorithm(algorithm) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("JWT algorithm configuration error: {}", e);
            return (
                AuthResult::Denied(StatusCode::UNAUTHORIZED, "JWT configuration error"),
                None,
            );
        }
    };
    let key = match decoding_key_from_secret(secret, algo) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("JWT key material misconfigured for algorithm {:?}: {}", algo, e);
            return (
                AuthResult::Denied(StatusCode::UNAUTHORIZED, "JWT configuration error"),
                None,
            );
        }
    };
    let mut validation = Validation::new(algo);
    // Disable audience validation by default (configurable in future)
    validation.validate_aud = false;

    match decode::<Claims>(token, &key, &validation) {
        Ok(data) => (AuthResult::Allowed, Some(data.claims)),
        Err(e) => {
            use jsonwebtoken::errors::ErrorKind;
            let msg = match e.kind() {
                ErrorKind::ExpiredSignature => "JWT token has expired",
                ErrorKind::InvalidSignature => "JWT signature verification failed",
                ErrorKind::InvalidToken => "JWT token is malformed",
                _ => "JWT authentication failed",
            };
            (AuthResult::Denied(StatusCode::UNAUTHORIZED, msg), None)
        }
    }
}

/// Extract the raw token string from `Authorization: Bearer <token>`.
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(hyper::header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::trim)
}

/// Build a `DecodingKey` appropriate for the configured algorithm.
///
/// HMAC algorithms use `from_secret`; RSA uses `from_rsa_pem`;
/// ECDSA uses `from_ec_pem`. If the PEM is malformed for an asymmetric
/// algorithm, the function returns `Err` so the caller can deny all tokens
/// (instead of silently falling back to HMAC which would always fail).
fn decoding_key_from_secret(
    secret: &str,
    algo: Algorithm,
) -> Result<DecodingKey, jsonwebtoken::errors::Error> {
    match algo {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(DecodingKey::from_secret(secret.as_bytes()))
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            DecodingKey::from_rsa_pem(secret.as_bytes())
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            DecodingKey::from_ec_pem(secret.as_bytes())
        }
        Algorithm::EdDSA => {
            DecodingKey::from_ed_pem(secret.as_bytes())
        }
        _ => Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm,
        )),
    }
}

/// Parse an algorithm name string into a `jsonwebtoken::Algorithm`.
///
/// Returns `Err` for unrecognised algorithm strings instead of silently
/// falling back — a typo like `RS265` must be surfaced, not treated as HMAC.
fn parse_algorithm(algorithm: &str) -> Result<Algorithm, String> {
    match algorithm.to_uppercase().as_str() {
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        _ => Err(format!("Unknown or unsupported JWT algorithm: '{}'", algorithm)),
    }
}

/// Build the set of `X-Auth-*` headers to inject into the upstream request
/// from a successfully validated JWT's claims.
pub fn claims_to_headers(claims: &Claims) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(ref sub) = claims.sub {
        map.insert("X-Auth-Sub".to_string(), sub.clone());
    }
    if let Some(ref email) = claims.email {
        map.insert("X-Auth-Email".to_string(), email.clone());
    }
    map
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    fn make_token(secret: &str, claims: &Claims, algo: Algorithm) -> String {
        encode(
            &Header::new(algo),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn make_claims(exp_offset_secs: i64) -> Claims {
        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + exp_offset_secs) as u64;
        Claims {
            sub: Some("user-123".to_string()),
            email: Some("user@example.com".to_string()),
            exp: Some(exp),
            iss: None,
            aud: None,
        }
    }

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            hyper::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    #[test]
    fn test_valid_hs256_token_allowed() {
        let secret = "super-secret";
        let claims = make_claims(3600);
        let token = make_token(secret, &claims, Algorithm::HS256);
        let (result, decoded) = check(&bearer_headers(&token), secret, "HS256");
        assert!(matches!(result, AuthResult::Allowed));
        let decoded = decoded.unwrap();
        assert_eq!(decoded.sub.as_deref(), Some("user-123"));
        assert_eq!(decoded.email.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn test_wrong_secret_denied() {
        let claims = make_claims(3600);
        let token = make_token("correct-secret", &claims, Algorithm::HS256);
        let (result, _) = check(&bearer_headers(&token), "wrong-secret", "HS256");
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_expired_token_denied() {
        let secret = "secret";
        let claims = make_claims(-100); // expired 100s ago
        let token = make_token(secret, &claims, Algorithm::HS256);
        let (result, _) = check(&bearer_headers(&token), secret, "HS256");
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_missing_bearer_header_denied() {
        let (result, _) = check(&HeaderMap::new(), "secret", "HS256");
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_malformed_token_denied() {
        let headers = bearer_headers("not.a.valid.jwt");
        let (result, _) = check(&headers, "secret", "HS256");
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_claims_to_headers_populated() {
        let claims = Claims {
            sub: Some("abc123".to_string()),
            email: Some("test@test.com".to_string()),
            exp: None,
            iss: None,
            aud: None,
        };
        let map = claims_to_headers(&claims);
        assert_eq!(map.get("X-Auth-Sub").map(String::as_str), Some("abc123"));
        assert_eq!(
            map.get("X-Auth-Email").map(String::as_str),
            Some("test@test.com")
        );
    }

    #[test]
    fn test_extract_bearer_token() {
        let headers = bearer_headers("my.token.here");
        assert_eq!(extract_bearer_token(&headers), Some("my.token.here"));
    }

    #[test]
    fn test_unknown_algorithm_returns_error() {
        assert!(parse_algorithm("BOGUS").is_err());
        assert!(parse_algorithm("RS265").is_err());
    }

    #[test]
    fn test_hs512_algorithm_parsed() {
        assert!(matches!(parse_algorithm("HS512"), Ok(Algorithm::HS512)));
    }

    #[test]
    fn test_all_valid_algorithms_parsed() {
        for alg in &["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384"] {
            assert!(parse_algorithm(alg).is_ok(), "algorithm {} should parse", alg);
        }
    }
}
