use dashmap::DashMap;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(300);
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// A single JSON Web Key from a JWKS endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    #[serde(rename = "use")]
    pub use_: Option<String>,
    pub alg: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    pub crv: Option<String>,
}

/// The full JWKS response from the provider.
#[derive(Debug, Clone, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// Cached JWKS entry with expiry tracking.
struct CachedJwks {
    keys: JwksResponse,
    fetched_at: Instant,
}

/// Thread-safe JWKS manager that fetches and caches keys from remote endpoints.
/// Automatically refreshes keys on a configurable interval.
pub struct JwksManager {
    /// Maps JWKS URI → cached key set
    cache: DashMap<String, CachedJwks>,
}

impl JwksManager {
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

    /// Fetches keys from the JWKS endpoint, using cache if available and fresh.
    pub async fn get_keys(&self, jwks_uri: &str) -> Result<JwksResponse, String> {
        // Check cache
        if let Some(cached) = self.cache.get(jwks_uri) {
            if cached.fetched_at.elapsed() < JWKS_REFRESH_INTERVAL {
                debug!("JWKS cache hit for {}", jwks_uri);
                return Ok(cached.keys.clone());
            }
        }

        // Fetch fresh keys
        debug!("Fetching JWKS from {}", jwks_uri);
        let client = reqwest::Client::builder()
            .timeout(JWKS_FETCH_TIMEOUT)
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let resp = client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch error: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("JWKS endpoint returned {}", resp.status()));
        }

        let jwks: JwksResponse = resp
            .json()
            .await
            .map_err(|e| format!("JWKS parse error: {}", e))?;

        info!(
            "Loaded {} keys from JWKS endpoint {}",
            jwks.keys.len(),
            jwks_uri
        );

        self.cache.insert(
            jwks_uri.to_string(),
            CachedJwks {
                keys: jwks.clone(),
                fetched_at: Instant::now(),
            },
        );

        Ok(jwks)
    }

    /// Finds a key by `kid` (Key ID) from the cached JWKS.
    pub async fn find_key(&self, jwks_uri: &str, kid: &str) -> Option<Jwk> {
        let keys = self.get_keys(jwks_uri).await.ok()?;
        keys.keys
            .into_iter()
            .find(|k| k.kid.as_deref() == Some(kid))
    }

    /// Builds a `jsonwebtoken::DecodingKey` from a JWK.
    pub fn decoding_key_from_jwk(jwk: &Jwk) -> Result<(DecodingKey, Algorithm), String> {
        match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk.n.as_ref().ok_or("Missing 'n' in RSA JWK")?;
                let e = jwk.e.as_ref().ok_or("Missing 'e' in RSA JWK")?;
                let key = DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| format!("RSA key build error: {}", e))?;

                let algo = match jwk.alg.as_deref() {
                    Some("RS384") => Algorithm::RS384,
                    Some("RS512") => Algorithm::RS512,
                    _ => Algorithm::RS256,
                };
                Ok((key, algo))
            }
            "EC" => {
                let x = jwk.x.as_ref().ok_or("Missing 'x' in EC JWK")?;
                let y = jwk.y.as_ref().ok_or("Missing 'y' in EC JWK")?;

                let algo = match jwk.crv.as_deref() {
                    Some("P-384") => Algorithm::ES384,
                    _ => Algorithm::ES256,
                };

                let key = DecodingKey::from_ec_components(x, y)
                    .map_err(|e| format!("EC key build error: {}", e))?;
                Ok((key, algo))
            }
            other => Err(format!("Unsupported key type: {}", other)),
        }
    }

    /// Spawns a background task that periodically refreshes the JWKS cache.
    pub fn spawn_refresh_loop(self: Arc<Self>, jwks_uri: String) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(JWKS_REFRESH_INTERVAL).await;
                match self.get_keys(&jwks_uri).await {
                    Ok(keys) => {
                        debug!("JWKS auto-refresh: {} keys loaded from {}", keys.keys.len(), jwks_uri);
                    }
                    Err(e) => {
                        warn!("JWKS auto-refresh failed for {}: {}", jwks_uri, e);
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwks_manager_new() {
        let mgr = JwksManager::new();
        assert!(mgr.cache.is_empty());
    }

    #[test]
    fn test_decoding_key_from_rsa_jwk() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: Some("rsa-key-1".to_string()),
            use_: Some("sig".to_string()),
            alg: Some("RS256".to_string()),
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        };
        let result = JwksManager::decoding_key_from_jwk(&jwk);
        assert!(result.is_ok());
        let (_, algo) = result.unwrap();
        assert_eq!(algo, Algorithm::RS256);
    }

    #[test]
    fn test_decoding_key_from_rsa_rs384() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: None,
            use_: None,
            alg: Some("RS384".to_string()),
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        };
        let (_, algo) = JwksManager::decoding_key_from_jwk(&jwk).unwrap();
        assert_eq!(algo, Algorithm::RS384);
    }

    #[test]
    fn test_decoding_key_rsa_missing_n() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: None,
            use_: None,
            alg: None,
            n: None,
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        };
        assert!(JwksManager::decoding_key_from_jwk(&jwk).is_err());
    }

    #[test]
    fn test_decoding_key_unsupported_type() {
        let jwk = Jwk {
            kty: "oct".to_string(),
            kid: None,
            use_: None,
            alg: None,
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
        };
        let result = JwksManager::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.contains("Unsupported key type")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn test_ec_jwk_missing_x() {
        let jwk = Jwk {
            kty: "EC".to_string(),
            kid: None,
            use_: None,
            alg: None,
            n: None,
            e: None,
            x: None,
            y: Some("y-val".to_string()),
            crv: Some("P-256".to_string()),
        };
        assert!(JwksManager::decoding_key_from_jwk(&jwk).is_err());
    }
}
