use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// OCSP stapling manager.
///
/// Fetches and caches OCSP responses for the server certificate,
/// then staples them to the TLS handshake via rustls's `ResolvesServerCert`.
///
/// This avoids clients needing to make separate OCSP requests,
/// improving TLS handshake latency and privacy.
pub struct OcspStapler {
    /// The cached DER-encoded OCSP response
    cached_response: Arc<RwLock<Option<CachedOcspResponse>>>,
    /// OCSP responder URL (extracted from the certificate's AIA extension)
    responder_url: Option<String>,
    /// The DER-encoded server certificate (for building OCSP requests)
    cert_der: Vec<u8>,
    /// The DER-encoded issuer certificate
    issuer_der: Option<Vec<u8>>,
}

struct CachedOcspResponse {
    der: Vec<u8>,
    fetched_at: Instant,
    next_update: Option<Instant>,
}

impl OcspStapler {
    pub fn new(
        cert_der: Vec<u8>,
        issuer_der: Option<Vec<u8>>,
        responder_url: Option<String>,
    ) -> Self {
        Self {
            cached_response: Arc::new(RwLock::new(None)),
            responder_url,
            cert_der,
            issuer_der,
        }
    }

    /// Returns the cached OCSP response if available and fresh.
    pub async fn get_staple(&self) -> Option<Vec<u8>> {
        let cached = self.cached_response.read().await;
        cached.as_ref().and_then(|c| {
            let age = c.fetched_at.elapsed();
            let max_age = c
                .next_update
                .map(|nu| {
                    if nu > Instant::now() {
                        nu.duration_since(c.fetched_at)
                    } else {
                        Duration::from_secs(0)
                    }
                })
                .unwrap_or(Duration::from_secs(3600));

            if age < max_age {
                Some(c.der.clone())
            } else {
                None
            }
        })
    }

    /// Fetches a fresh OCSP response from the responder.
    pub async fn refresh(&self) -> Result<(), String> {
        let url = match &self.responder_url {
            Some(u) => u.clone(),
            None => return Err("No OCSP responder URL configured".to_string()),
        };

        debug!("Fetching OCSP response from {}", url);

        // Build a minimal OCSP request
        // In production, use the `x509-ocsp` crate for proper ASN.1 encoding.
        // Here we do a simple HTTP GET with the cert hash embedded in the URL path.
        let cert_hash = simple_hash(&self.cert_der);
        let ocsp_url = format!("{}/{}", url.trim_end_matches('/'), hex::encode(&cert_hash));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let resp = client
            .get(&ocsp_url)
            .header("Accept", "application/ocsp-response")
            .send()
            .await
            .map_err(|e| format!("OCSP fetch error: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("OCSP responder returned {}", resp.status()));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("OCSP response read error: {}", e))?;

        let mut cached = self.cached_response.write().await;
        *cached = Some(CachedOcspResponse {
            der: body.to_vec(),
            fetched_at: Instant::now(),
            next_update: Some(Instant::now() + Duration::from_secs(3600)),
        });

        info!("OCSP response cached ({} bytes)", body.len());
        Ok(())
    }

    /// Spawns a background loop that refreshes the OCSP staple periodically.
    pub fn spawn_refresh_loop(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            loop {
                match self.refresh().await {
                    Ok(_) => debug!("OCSP staple refreshed successfully"),
                    Err(e) => warn!("OCSP staple refresh failed: {}", e),
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
}

fn simple_hash(data: &[u8]) -> [u8; 20] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut hasher);
    let h = hasher.finish();
    let mut out = [0u8; 20];
    out[..8].copy_from_slice(&h.to_le_bytes());
    out[8..16].copy_from_slice(&h.to_be_bytes());
    let h2 = h.wrapping_mul(0x9E3779B97F4A7C15);
    out[16..20].copy_from_slice(&(h2 as u32).to_le_bytes());
    out
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_hash_deterministic() {
        let data = b"test certificate data";
        let h1 = simple_hash(data);
        let h2 = simple_hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_simple_hash_different_inputs() {
        let h1 = simple_hash(b"cert-a");
        let h2 = simple_hash(b"cert-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex::encode(&[0x0a, 0xff, 0x00]), "0aff00");
        assert_eq!(hex::encode(&[]), "");
    }

    #[test]
    fn test_ocsp_stapler_creation() {
        let stapler = OcspStapler::new(
            vec![1, 2, 3],
            Some(vec![4, 5, 6]),
            Some("http://ocsp.example.com".to_string()),
        );
        assert_eq!(stapler.cert_der, vec![1, 2, 3]);
        assert_eq!(stapler.issuer_der, Some(vec![4, 5, 6]));
        assert_eq!(stapler.responder_url, Some("http://ocsp.example.com".to_string()));
    }

    #[test]
    fn test_ocsp_stapler_no_responder() {
        let stapler = OcspStapler::new(vec![1], None, None);
        assert!(stapler.responder_url.is_none());
    }

    #[tokio::test]
    async fn test_get_staple_empty_cache() {
        let stapler = OcspStapler::new(vec![], None, None);
        assert!(stapler.get_staple().await.is_none());
    }

    #[tokio::test]
    async fn test_refresh_no_responder_url() {
        let stapler = OcspStapler::new(vec![], None, None);
        let result = stapler.refresh().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No OCSP responder URL"));
    }
}
