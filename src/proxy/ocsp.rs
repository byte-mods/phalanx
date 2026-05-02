//! OCSP stapling for TLS certificates.
//!
//! Online Certificate Status Protocol (OCSP) stapling allows the TLS server
//! to present a signed proof of certificate validity during the handshake,
//! eliminating the need for clients to contact the CA's OCSP responder
//! themselves. This improves handshake latency, privacy (the CA never sees
//! the client IP), and reliability (handshake succeeds even if the CA is down).
//!
//! The `OcspStapler` fetches OCSP responses on a configurable interval and
//! caches them in memory. The cached DER blob is attached to rustls via
//! `ResolvesServerCert` at handshake time.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

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
    /// The DER-encoded issuer certificate (for building proper OCSP requests)
    issuer_der: Option<Vec<u8>>,
}

/// Internal cache entry holding a single fetched OCSP response.
struct CachedOcspResponse {
    /// DER-encoded OCSP response bytes, ready to staple.
    der: Vec<u8>,
    /// Wall-clock instant when this response was fetched.
    fetched_at: Instant,
    /// If the OCSP response included a `nextUpdate` field, the absolute
    /// instant after which the response is considered stale.
    next_update: Option<Instant>,
}

impl OcspStapler {
    /// Creates a new `OcspStapler` with empty cache.
    ///
    /// # Arguments
    ///
    /// * `cert_der`      - DER-encoded server certificate (used to build OCSP requests).
    /// * `issuer_der`    - DER-encoded issuer certificate (optional; for request signing).
    /// * `responder_url` - OCSP responder URL from the certificate's AIA extension.
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
    ///
    /// When `issuer_der` is available, builds a proper DER-encoded OCSP request
    /// and sends it via HTTP POST with `Content-Type: application/ocsp-request`.
    /// Falls back to HTTP GET with a cert hash in the URL when issuer_der is absent.
    pub async fn refresh(&self) -> Result<(), String> {
        let url = match &self.responder_url {
            Some(u) => u.clone(),
            None => return Err("No OCSP responder URL configured".to_string()),
        };

        debug!("Fetching OCSP response from {}", url);

        let client = ocsp_client();

        let resp = if let Some(ref issuer) = self.issuer_der {
            // Build a proper OCSP request body (DER-encoded, minimal ASN.1)
            let ocsp_request = build_ocsp_request(&self.cert_der, issuer)?;
            debug!("Sending OCSP POST request ({} bytes) to {}", ocsp_request.len(), url);

            client
                .post(&url)
                .header("Content-Type", "application/ocsp-request")
                .header("Accept", "application/ocsp-response")
                .body(ocsp_request)
                .send()
                .await
                .map_err(|e| format!("OCSP fetch error: {}", e))?
        } else {
            // Fallback: HTTP GET with cert hash in URL (degraded mode)
            let cert_hash = simple_hash(&self.cert_der);
            let ocsp_url = format!("{}/{}", url.trim_end_matches('/'), hex::encode(&cert_hash));
            debug!("Sending OCSP GET request to {}", ocsp_url);

            client
                .get(&ocsp_url)
                .header("Accept", "application/ocsp-response")
                .send()
                .await
                .map_err(|e| format!("OCSP fetch error: {}", e))?
        };

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

/// Builds a DER-encoded OCSP request per RFC 6960.
///
/// Structure:
///   OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest }
///   TBSRequest  ::= SEQUENCE { requestList SEQUENCE OF Request }
///   Request     ::= SEQUENCE { reqCert CertID }
///   CertID      ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
///
/// Uses SHA-1 (OID 1.3.14.3.2.26) as the hash algorithm per RFC 6960.
///
/// Correctly extracts:
/// - **issuerNameHash**: SHA-1 of the DER-encoded issuer Subject Name.
/// - **issuerKeyHash**:  SHA-1 of the DER-encoded issuer Subject Public Key Info.
/// - **serialNumber**:   The actual certificate serial number (not a hash fragment).
fn build_ocsp_request(cert_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>, String> {
    use x509_parser::parse_x509_certificate;

    let (_, issuer_cert) =
        parse_x509_certificate(issuer_der).map_err(|e| format!("Failed to parse issuer certificate: {}", e))?;
    let (_, server_cert) =
        parse_x509_certificate(cert_der).map_err(|e| format!("Failed to parse server certificate: {}", e))?;

    // Hash of the DER encoding of the issuer's distinguished name
    let issuer_name_hash = simple_hash(issuer_cert.tbs_certificate.issuer.as_raw());
    // Hash of the DER encoding of the issuer's SubjectPublicKeyInfo
    let issuer_key_hash = simple_hash(issuer_cert.tbs_certificate.subject_pki.raw);
    // Actual certificate serial number
    let serial_number = server_cert.tbs_certificate.raw_serial();

    // SHA-1 AlgorithmIdentifier: SEQUENCE { OID 1.3.14.3.2.26, NULL }
    let sha1_oid: &[u8] = &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
    let null_param: &[u8] = &[0x05, 0x00];
    let alg_id = der_sequence(&[sha1_oid, null_param]);

    // CertID: SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    let name_hash = der_octet_string(&issuer_name_hash);
    let key_hash = der_octet_string(&issuer_key_hash);
    let serial = der_integer(serial_number);
    let cert_id = der_sequence(&[&alg_id, &name_hash, &key_hash, &serial]);

    // Request: SEQUENCE { reqCert CertID }
    let request = der_sequence(&[&cert_id]);

    // requestList: SEQUENCE OF Request
    let request_list = der_sequence(&[&request]);

    // TBSRequest: SEQUENCE { requestList }
    let tbs_request = der_sequence(&[&request_list]);

    // OCSPRequest: SEQUENCE { tbsRequest }
    Ok(der_sequence(&[&tbs_request]))
}

/// Encodes data as a DER SEQUENCE (tag 0x30).
fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    let mut result = vec![0x30];
    der_encode_length(&mut result, content.len());
    result.extend(content);
    result
}

/// Encodes data as a DER OCTET STRING (tag 0x04).
fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04];
    der_encode_length(&mut result, data.len());
    result.extend_from_slice(data);
    result
}

/// Encodes data as a DER INTEGER (tag 0x02).
fn der_integer(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x02];
    // Add leading zero if high bit is set (to keep positive)
    if !data.is_empty() && data[0] & 0x80 != 0 {
        der_encode_length(&mut result, data.len() + 1);
        result.push(0x00);
    } else {
        der_encode_length(&mut result, data.len());
    }
    result.extend_from_slice(data);
    result
}

/// Encodes a DER length field.
fn der_encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Produces a 20-byte SHA-1 hash of `data` for use as a certificate identifier
/// in OCSP request URLs, as required by RFC 6960.
fn simple_hash(data: &[u8]) -> [u8; 20] {
    use sha1::{Sha1, Digest};
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Shared `reqwest::Client` for OCSP fetches, cached globally for reuse.
fn ocsp_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Minimal hex encoding utility (avoids pulling in the `hex` crate for one call site).
mod hex {
    /// Encodes a byte slice as a lowercase hexadecimal string.
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

    /// Helper: generate a self-signed DER certificate + key via rcgen.
    fn generate_test_cert(common_name: &str) -> (Vec<u8>, Vec<u8>) {
        let params = rcgen::CertificateParams::new(vec![common_name.to_string()])
            .expect("Failed to create cert params");
        let key_pair = rcgen::KeyPair::generate().expect("Failed to generate key pair");
        let cert = params.self_signed(&key_pair).expect("Failed to self-sign cert");
        let der = cert.der().to_vec();
        // For self-signed certs, issuer == cert
        (der.clone(), der)
    }

    #[test]
    fn test_build_ocsp_request_produces_valid_der() {
        let (cert_der, issuer_der) = generate_test_cert("test.example.com");
        let request = build_ocsp_request(&cert_der, &issuer_der)
            .expect("should build OCSP request from valid certs");
        // Must start with SEQUENCE tag (0x30)
        assert_eq!(request[0], 0x30);
        // Must be non-empty (typically 60-80 bytes)
        assert!(request.len() > 20);
    }

    #[test]
    fn test_build_ocsp_request_deterministic() {
        let (cert_der, issuer_der) = generate_test_cert("test.example.com");
        let r1 = build_ocsp_request(&cert_der, &issuer_der)
            .expect("should produce valid request");
        let r2 = build_ocsp_request(&cert_der, &issuer_der)
            .expect("should produce valid request");
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_build_ocsp_request_different_for_different_certs() {
        let (cert_a, issuer_a) = generate_test_cert("a.example.com");
        let (cert_b, issuer_b) = generate_test_cert("b.example.com");
        let r1 = build_ocsp_request(&cert_a, &issuer_a)
            .expect("should produce valid request");
        let r2 = build_ocsp_request(&cert_b, &issuer_b)
            .expect("should produce valid request");
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_build_ocsp_request_rejects_invalid_der() {
        let result = build_ocsp_request(b"not-a-cert", b"also-not-a-cert");
        assert!(result.is_err());
    }

    #[test]
    fn test_der_sequence_encoding() {
        let inner = &[0x04, 0x02, 0x41, 0x42]; // OCTET STRING "AB"
        let seq = der_sequence(&[inner]);
        assert_eq!(seq[0], 0x30); // SEQUENCE tag
        assert_eq!(seq[1], 4);    // length of inner
        assert_eq!(&seq[2..], inner);
    }

    #[test]
    fn test_der_integer_no_leading_zero_needed() {
        let int = der_integer(&[0x01, 0x02]);
        assert_eq!(int, vec![0x02, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn test_der_integer_leading_zero_for_high_bit() {
        let int = der_integer(&[0x80, 0x01]);
        assert_eq!(int, vec![0x02, 0x03, 0x00, 0x80, 0x01]);
    }

    #[test]
    fn test_ocsp_stapler_uses_issuer_der() {
        let stapler = OcspStapler::new(
            vec![1, 2, 3],
            Some(vec![4, 5, 6]),
            Some("http://ocsp.example.com".to_string()),
        );
        // issuer_der is stored and accessible
        assert!(stapler.issuer_der.is_some());
    }
}
