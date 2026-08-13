//! TLS certificate management for the proxy server.
//!
//! Provides:
//! - Static certificate loading from PEM files on disk.
//! - Automatic TLS via Let's Encrypt (ACME) when `auto_ssl_domain` is configured.
//! - Mutual TLS (mTLS) when a CA certificate is provided for client verification.
//! - Hot-reload of certificates on SIGHUP without downtime.
//!
//! The produced `TlsAcceptor` is shared across all proxy tasks via `ArcSwap`
//! so that certificate rotation is lock-free and instantaneous.

use crate::config::AppConfig;
use futures_util::StreamExt;
use rustls::{
    ServerConfig,
    pki_types::CertificateDer,
    server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier},
    sign::CertifiedKey,
};
use rustls_acme::AcmeConfig;
use rustls_acme::caches::DirCache;
use rustls_pemfile::{certs, private_key};
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

/// Installs the process-wide rustls `CryptoProvider` exactly once.
///
/// rustls 0.23 refuses to pick a provider on its own when more than one backend
/// could be linked in, and any `ServerConfig::builder()` / `ClientConfig::builder()`
/// call **panics** until one has been installed. The HTTP/1 and HTTP/2 TLS paths
/// build their providers explicitly and so were unaffected, but the QUIC listener
/// used the process default and panicked on every start — restart-looping forever
/// so HTTP/3 never bound a socket.
///
/// Call this once, before any listener is spawned. Idempotent and safe to call
/// from tests.
pub fn install_default_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // `install_default` errors only if a provider is already installed, which
        // is precisely the state we want — so the result is intentionally ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Loads a certificate chain and private key from disk into a `CertifiedKey`.
fn load_certified_key(
    cert_path: &str,
    key_path: &str,
    provider: &rustls::crypto::CryptoProvider,
) -> Option<Arc<CertifiedKey>> {
    let cert_file = File::open(cert_path).ok()?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer<'static>> =
        certs(&mut cert_reader).filter_map(|c| c.ok()).collect();
    if cert_chain.is_empty() {
        warn!("No valid certificates found in {}", cert_path);
        return None;
    }

    let key_file = File::open(key_path).ok()?;
    let mut key_reader = BufReader::new(key_file);
    let key = private_key(&mut key_reader).ok()??;

    let certified_key = CertifiedKey::from_der(cert_chain, key, provider)
        .map_err(|e| {
            warn!(
                "Failed to build certified key from {} / {}: {}",
                cert_path, key_path, e
            );
            e
        })
        .ok()?;
    Some(Arc::new(certified_key))
}

/// A `ResolvesServerCert` that always returns the same fallback certificate.
#[derive(Debug)]
struct SingleCertResolver {
    cert: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SingleCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.cert))
    }
}

/// Cached dynamic certificate entry keyed by `added_at` timestamp so that
/// admin API updates (delete + re-add) naturally invalidate the cache.
struct CachedCert {
    added_at: u64,
    cert: Arc<CertifiedKey>,
}

/// SNI-aware certificate resolver that consults the admin API's `dynamic_certs`
/// table before falling back to the statically configured certificate.
pub struct PhalanxCertResolver {
    fallback: Arc<CertifiedKey>,
    dynamic_certs: Arc<dashmap::DashMap<String, crate::admin::api::SslCertEntry>>,
    cache: dashmap::DashMap<String, CachedCert>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl fmt::Debug for PhalanxCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhalanxCertResolver")
            .field("dynamic_certs_count", &self.dynamic_certs.len())
            .field("cache_count", &self.cache.len())
            .finish()
    }
}

impl PhalanxCertResolver {
    pub fn new(
        fallback: Arc<CertifiedKey>,
        dynamic_certs: Arc<dashmap::DashMap<String, crate::admin::api::SslCertEntry>>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Self {
        Self {
            fallback,
            dynamic_certs,
            cache: dashmap::DashMap::new(),
            provider,
        }
    }
}

impl ResolvesServerCert for PhalanxCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = match client_hello.server_name() {
            Some(name) => name,
            None => return Some(Arc::clone(&self.fallback)),
        };

        if let Some(entry) = self.dynamic_certs.get(server_name) {
            // Check cache first (invalidated when added_at changes)
            if let Some(cached) = self.cache.get(server_name) {
                if cached.added_at == entry.added_at {
                    return Some(Arc::clone(&cached.cert));
                }
            }

            // Cache miss or stale — load from disk
            if let Some(cert) =
                load_certified_key(&entry.cert_path, &entry.key_path, &self.provider)
            {
                self.cache.insert(
                    server_name.to_string(),
                    CachedCert {
                        added_at: entry.added_at,
                        cert: Arc::clone(&cert),
                    },
                );
                return Some(cert);
            }
        }

        Some(Arc::clone(&self.fallback))
    }
}

/// Resolves the minimum TLS protocol version from a config string.
/// Accepts "1.2", "1.3", "TLSv1.2", "TLSv1.3" (case-insensitive).
fn resolve_min_tls_version(s: &str) -> Option<&'static rustls::SupportedProtocolVersion> {
    let normalized = s.to_lowercase().replace("tlsv", "");
    match normalized.as_str() {
        "1.3" => Some(&rustls::version::TLS13),
        "1.2" | "" => Some(&rustls::version::TLS12),
        _ => {
            warn!("Unknown TLS version '{}', defaulting to TLS 1.2", s);
            Some(&rustls::version::TLS12)
        }
    }
}

/// Filters the default rustls cipher suites based on user-specified names.
/// Returns the intersection (in user order) of `requested` and `available`.
/// If no matches are found, returns all available suites with a warning.
fn filter_cipher_suites(requested: &[String]) -> Vec<rustls::SupportedCipherSuite> {
    let available = rustls::crypto::ring::default_provider().cipher_suites;
    if requested.is_empty() {
        return available.to_vec();
    }
    let mut result = Vec::new();
    for name in requested {
        let name_upper = name.to_uppercase().replace('-', "_");
        if let Some(suite) = available.iter().find(|s| {
            let sn = format!("{:?}", s.suite()).to_uppercase().replace('-', "_");
            sn.contains(&name_upper) || name_upper.contains(&sn)
        }) {
            result.push(*suite);
        } else {
            warn!(
                "TLS cipher suite '{}' not available in rustls, skipping",
                name
            );
        }
    }
    if result.is_empty() {
        warn!("No valid cipher suites matched from config — using rustls defaults");
        return available.to_vec();
    }
    info!("Using {} configured TLS cipher suites", result.len());
    result
}

/// Builds a rustls `ServerConfig` from cert and key file paths.
///
/// If `ca_cert_path` is provided, enables mTLS client certificate verification
/// using `WebPkiClientVerifier`. Otherwise, no client authentication is required.
///
/// # Returns
///
/// `Some(Arc<ServerConfig>)` on success, or `None` if any file cannot be read
/// or parsed. Errors are logged at the `error` level.
pub(crate) fn build_server_config(
    cert_path: &str,
    key_path: &str,
    ca_cert_path: Option<&str>,
) -> Option<Arc<ServerConfig>> {
    build_server_config_with_tls_opts(cert_path, key_path, ca_cert_path, None, &[], None)
}

/// Builds a rustls `ServerConfig` with optional TLS version/cipher constraints.
pub(crate) fn build_server_config_with_tls_opts(
    cert_path: &str,
    key_path: &str,
    ca_cert_path: Option<&str>,
    tls_min_version: Option<&str>,
    tls_ciphers: &[String],
    dynamic_certs: Option<Arc<dashmap::DashMap<String, crate::admin::api::SslCertEntry>>>,
) -> Option<Arc<ServerConfig>> {
    let cert_file = match File::open(cert_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open cert file {}: {}", cert_path, e);
            return None;
        }
    };
    let mut cert_reader = BufReader::new(cert_file);
    let server_certs: Vec<CertificateDer> = certs(&mut cert_reader)
        .filter_map(|c| match c {
            Ok(cert) => Some(cert),
            Err(e) => {
                warn!("Skipping malformed certificate in {}: {}", cert_path, e);
                None
            }
        })
        .collect();

    if server_certs.is_empty() {
        error!("No valid certificates found in {}", cert_path);
        return None;
    }

    let key_file = match File::open(key_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open key file {}: {}", key_path, e);
            return None;
        }
    };
    let mut key_reader = BufReader::new(key_file);
    let key = match private_key(&mut key_reader) {
        Ok(Some(k)) => k,
        _ => {
            error!("Failed to parse private key from {}", key_path);
            return None;
        }
    };

    // Build a crypto provider with filtered cipher suites if configured
    let suites = filter_cipher_suites(tls_ciphers);
    let versions: Vec<&'static rustls::SupportedProtocolVersion> =
        if let Some(min_ver) = tls_min_version {
            let min = resolve_min_tls_version(min_ver);
            match min {
                Some(v) if std::ptr::eq(v, &rustls::version::TLS13) => {
                    vec![&rustls::version::TLS13]
                }
                _ => vec![&rustls::version::TLS12, &rustls::version::TLS13],
            }
        } else {
            vec![&rustls::version::TLS12, &rustls::version::TLS13]
        };

    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: suites,
        ..rustls::crypto::ring::default_provider()
    };

    let provider_arc = Arc::new(provider.clone());
    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)
        .map_err(|e| {
            error!(
                "Failed to build TLS config with custom protocol versions: {}",
                e
            );
            e
        })
        .ok()?;
    let fallback_cert = CertifiedKey::from_der(server_certs, key, &provider_arc)
        .map_err(|e| {
            error!("Failed to build fallback CertifiedKey: {}", e);
            e
        })
        .ok()?;
    let fallback_cert = Arc::new(fallback_cert);

    let resolver: Arc<dyn ResolvesServerCert> = if let Some(dyn_certs) = dynamic_certs {
        info!(
            "Enabling SNI-based dynamic certificate resolution with {} pre-registered certs",
            dyn_certs.len()
        );
        Arc::new(PhalanxCertResolver::new(
            fallback_cert,
            dyn_certs,
            provider_arc,
        ))
    } else {
        Arc::new(SingleCertResolver {
            cert: fallback_cert,
        })
    };

    let mut server_config = if let Some(ca_path) = ca_cert_path {
        // ── mTLS branch ──────────────────────────────────────────────────────
        info!("Enabling mTLS — loading CA from {}", ca_path);
        let ca_file = match File::open(ca_path) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open CA cert file {}: {}", ca_path, e);
                return None;
            }
        };
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs: Vec<CertificateDer> = certs(&mut ca_reader)
            .filter_map(|c| match c {
                Ok(cert) => Some(cert),
                Err(e) => {
                    warn!("Skipping malformed CA certificate in {}: {}", ca_path, e);
                    None
                }
            })
            .collect();

        let mut root_store = rustls::RootCertStore::empty();
        for ca_cert in ca_certs {
            if let Err(e) = root_store.add(ca_cert) {
                warn!(
                    "Skipping CA certificate that failed to add to root store: {}",
                    e
                );
            }
        }
        if root_store.is_empty() {
            error!("No valid CA certificates could be loaded from {}", ca_path);
            return None;
        }
        let root_store = Arc::new(root_store);
        let client_verifier = match WebPkiClientVerifier::builder(root_store).build() {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to build client verifier: {}", e);
                return None;
            }
        };
        builder
            .with_client_cert_verifier(client_verifier)
            .with_cert_resolver(resolver)
    } else {
        // ── Standard TLS (no client auth) ─────────────────────────────────
        builder.with_no_client_auth().with_cert_resolver(resolver)
    };

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Some(Arc::new(server_config))
}

/// Loads TLS configuration and returns a `TlsAcceptor`.
///
/// Called once at startup. The loading strategy has two tiers:
///
/// 1. **Auto-SSL (Let's Encrypt)** -- if `auto_ssl_domain` is set in config,
///    an ACME client is started in a background task that handles HTTP-01
///    challenges and certificate renewal automatically.
/// 2. **Static certificates** -- reads `tls_cert_path` and `tls_key_path` from
///    disk. Enables mTLS if `tls_ca_cert_path` is also configured.
///
/// Returns `None` if no TLS configuration is present (plaintext-only mode).
pub fn load_tls_acceptor(
    config: &AppConfig,
    dynamic_certs: Option<Arc<dashmap::DashMap<String, crate::admin::api::SslCertEntry>>>,
) -> Option<TlsAcceptor> {
    // 1. Auto-SSL via Let's Encrypt takes precedence if configured
    if let Some(domain) = &config.auto_ssl_domain {
        info!("Enabling Let's Encrypt Auto-SSL for domain: {}", domain);

        let mail = config
            .auto_ssl_email
            .as_deref()
            .unwrap_or("admin@example.com");
        let cache_dir = config
            .auto_ssl_cache_dir
            .clone()
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| {
                std::env::temp_dir()
                    .join("phalanx_acme_cache")
                    .to_string_lossy()
                    .into_owned()
            });

        // Pre-flight: ensure the ACME cache directory exists. The background
        // renewal task handles runtime I/O errors with backoff; this catches
        // the "directory unusable" condition at startup so operators see it.
        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            warn!("Cannot create ACME cache directory {}: {}", cache_dir, e);
        } else {
            // The ACME cache stores private keys; restrict it to owner-only.
            // If we cannot enforce this, abort rather than risk world-readable keys.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) =
                    std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700))
                {
                    error!(
                        "Cannot set permissions on ACME cache directory {}: {} — aborting ACME",
                        cache_dir, e
                    );
                    return None;
                }
            }
        }

        // Chain the builder to avoid type change reassignment errors
        let mut state = AcmeConfig::new(vec![domain.clone()])
            .contact(vec![format!("mailto:{}", mail)])
            .cache(DirCache::new(cache_dir))
            .state();

        let acceptor = state.default_rustls_config();

        // Spawn the ACME background worker task to answer challenges and handle renewal.
        // Retries with exponential backoff on consecutive errors, capped at 5 minutes.
        tokio::spawn(async move {
            let mut consecutive_errors: u32 = 0;
            while let Some(event) = state.next().await {
                match event {
                    Ok(e) => {
                        consecutive_errors = 0;
                        info!("Let's Encrypt ACME event: {:?}", e);
                    }
                    Err(err) => {
                        consecutive_errors += 1;
                        let backoff_secs = (1u64 << consecutive_errors.min(8)).min(300);
                        error!(
                            "Let's Encrypt ACME error (attempt {}, retry in {}s): {:?}",
                            consecutive_errors, backoff_secs, err
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                    }
                }
            }
            warn!("ACME event stream ended — certificate renewal will no longer occur");
        });

        return Some(TlsAcceptor::from(acceptor));
    }

    // 2. Static Certificate Files
    let cert_path = config.tls_cert_path.as_ref()?;
    let key_path = config.tls_key_path.as_ref()?;
    let ca_path = config.tls_ca_cert_path.as_deref();

    info!(
        "Loading static TLS certificates from {} and {}{}",
        cert_path,
        key_path,
        if ca_path.is_some() {
            " (mTLS enabled)"
        } else {
            ""
        }
    );

    let server_config = build_server_config_with_tls_opts(
        cert_path,
        key_path,
        ca_path,
        config.tls_min_version.as_deref(),
        &config.tls_ciphers,
        dynamic_certs,
    )?;
    Some(TlsAcceptor::from(server_config))
}

/// Reloads TLS certificates from disk and returns a new `TlsAcceptor`.
///
/// Called on SIGHUP to hot-reload certificates without restarting the server.
/// If the reload fails (e.g. the new cert file is malformed), the caller
/// should keep the previous acceptor in place -- this function does not
/// modify any global state itself.
///
/// # Returns
///
/// `Some(TlsAcceptor)` on success, `None` on failure (a warning is logged).
pub async fn reload_tls_acceptor(
    config: &AppConfig,
    dynamic_certs: Option<Arc<dashmap::DashMap<String, crate::admin::api::SslCertEntry>>>,
) -> Option<TlsAcceptor> {
    let cert_path = config.tls_cert_path.as_ref()?.to_owned();
    let key_path = config.tls_key_path.as_ref()?.to_owned();
    let ca_path = config.tls_ca_cert_path.clone();
    let tls_min_version = config.tls_min_version.clone();
    let tls_ciphers = config.tls_ciphers.clone();

    info!(
        "Hot-reloading TLS certificates from {} and {}",
        cert_path, key_path
    );

    let result = tokio::task::spawn_blocking(move || {
        build_server_config_with_tls_opts(
            &cert_path,
            &key_path,
            ca_path.as_deref(),
            tls_min_version.as_deref(),
            &tls_ciphers,
            dynamic_certs,
        )
    })
    .await;

    match result {
        Ok(Some(server_config)) => {
            info!("TLS certificates reloaded successfully.");
            Some(TlsAcceptor::from(server_config))
        }
        Ok(None) => {
            warn!("TLS certificate reload failed — keeping existing certificates.");
            None
        }
        Err(join_err) => {
            warn!(
                "TLS reload task panicked: {} — keeping existing certificates.",
                join_err
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_min_tls_version_1_3() {
        let v = resolve_min_tls_version("1.3").unwrap();
        assert!(std::ptr::eq(v, &rustls::version::TLS13));
    }

    #[test]
    fn test_resolve_min_tls_version_1_2() {
        let v = resolve_min_tls_version("1.2").unwrap();
        assert!(std::ptr::eq(v, &rustls::version::TLS12));
    }

    #[test]
    fn test_resolve_min_tls_version_tlsv_prefix() {
        let v = resolve_min_tls_version("TLSv1.3").unwrap();
        assert!(std::ptr::eq(v, &rustls::version::TLS13));
    }

    #[test]
    fn test_resolve_min_tls_version_unknown_defaults_to_1_2() {
        let v = resolve_min_tls_version("1.0").unwrap();
        assert!(std::ptr::eq(v, &rustls::version::TLS12));
    }

    #[test]
    fn test_filter_cipher_suites_empty_returns_defaults() {
        let suites = filter_cipher_suites(&[]);
        assert!(!suites.is_empty());
    }

    #[test]
    fn test_filter_cipher_suites_nonexistent_returns_defaults() {
        let suites = filter_cipher_suites(&["NONEXISTENT_CIPHER".to_string()]);
        // Should fall back to defaults when no match
        assert!(!suites.is_empty());
    }

    #[test]
    fn test_build_server_config_missing_cert() {
        let result = build_server_config("/nonexistent/cert.pem", "/nonexistent/key.pem", None);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_server_config_with_tls_opts_missing_cert() {
        let result = build_server_config_with_tls_opts(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            None,
            Some("1.3"),
            &["TLS_AES_256_GCM_SHA384".to_string()],
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_load_tls_acceptor_no_config() {
        let config = AppConfig::default();
        let result = load_tls_acceptor(&config, None);
        assert!(result.is_none());
    }

    // ── L1: malformed cert detection ────────────────────────────────────────

    #[test]
    fn test_malformed_cert_in_chain_is_skipped_keeps_valid() {
        // A PEM chain with one valid cert + one entry whose base64 is
        // garbage between valid delimiters. The valid cert should still
        // load successfully.
        let tmp = std::env::temp_dir().join("phalanx_tls_l1a");
        std::fs::create_dir_all(&tmp).unwrap();

        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let malformed_pem = format!(
            "{}\n-----BEGIN CERTIFICATE-----\n!!!NOT_BASE64!!!\n-----END CERTIFICATE-----\n",
            cert.pem()
        );

        let cert_path = tmp.join("chain.pem");
        let key_path = tmp.join("key.pem");
        std::fs::write(&cert_path, &malformed_pem).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        let result = build_server_config_with_tls_opts(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            None,
            None,
            &[],
            None,
        );
        assert!(
            result.is_some(),
            "valid cert should load despite malformed sibling"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_all_certs_malformed_returns_none() {
        // PEM file where every certificate entry has garbage base64.
        // No valid CertificateDer survives → with_single_cert fails → None.
        let tmp = std::env::temp_dir().join("phalanx_tls_l1b");
        std::fs::create_dir_all(&tmp).unwrap();

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let bad_pem = "-----BEGIN CERTIFICATE-----\n!!!GARBAGE!!!\n-----END CERTIFICATE-----\n";

        let cert_path = tmp.join("bad.pem");
        let key_path = tmp.join("key.pem");
        std::fs::write(&cert_path, bad_pem).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        let result = build_server_config_with_tls_opts(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            None,
            None,
            &[],
            None,
        );
        assert!(result.is_none(), "no valid certs → config build must fail");

        std::fs::remove_dir_all(&tmp).ok();
    }

    // ── L2: mTLS CA resilience ──────────────────────────────────────────────

    /// Generates a self-signed CA certificate suitable for RootCertStore.
    fn gen_ca_cert(common_name: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
        let mut params = rcgen::CertificateParams::new(vec![common_name.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert, key)
    }

    /// Generates a self-signed end-entity certificate (no CA:TRUE).
    fn gen_ee_cert(common_name: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
        let params = rcgen::CertificateParams::new(vec![common_name.to_string()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert, key)
    }

    #[test]
    fn test_mtls_valid_ca_cert_succeeds() {
        // A proper CA cert (basicConstraints CA:TRUE, self-signed) is
        // accepted by root_store → mTLS config builds successfully.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = std::env::temp_dir().join("phalanx_tls_l2b");
        std::fs::create_dir_all(&tmp).unwrap();

        let (server_cert, server_key) = gen_ee_cert("server.example.com");
        let (ca_cert, _ca_key) = gen_ca_cert("My Test CA");

        let cert_path = tmp.join("server.pem");
        let key_path = tmp.join("key.pem");
        let ca_path = tmp.join("ca.pem");
        std::fs::write(&cert_path, server_cert.pem()).unwrap();
        std::fs::write(&key_path, server_key.serialize_pem()).unwrap();
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();

        let result = build_server_config_with_tls_opts(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            Some(ca_path.to_str().unwrap()),
            None,
            &[],
            None,
        );
        assert!(
            result.is_some(),
            "valid CA cert must produce a working mTLS config"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_mtls_mixed_ca_bundle_skips_bad_keeps_good() {
        // CA bundle: one non-CA cert (rejected) + one CA cert (accepted).
        // The non-CA cert is skipped with a warning; the CA cert is kept;
        // mTLS config builds successfully.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = std::env::temp_dir().join("phalanx_tls_l2c");
        std::fs::create_dir_all(&tmp).unwrap();

        let (server_cert, server_key) = gen_ee_cert("server.example.com");
        let (ca_cert, _ca_key) = gen_ca_cert("My Test CA");
        let (bad_ee, _bad_key) = gen_ee_cert("not-a-ca.example.com");

        let bundle = format!("{}\n{}", bad_ee.pem(), ca_cert.pem());

        let cert_path = tmp.join("server.pem");
        let key_path = tmp.join("key.pem");
        let ca_path = tmp.join("ca.pem");
        std::fs::write(&cert_path, server_cert.pem()).unwrap();
        std::fs::write(&key_path, server_key.serialize_pem()).unwrap();
        std::fs::write(&ca_path, bundle).unwrap();

        let result = build_server_config_with_tls_opts(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            Some(ca_path.to_str().unwrap()),
            None,
            &[],
            None,
        );
        assert!(
            result.is_some(),
            "mixed CA bundle: bad cert skipped, good cert kept → succeeds"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    // ── L3: ACME cache directory pre-flight ─────────────────────────────────

    #[tokio::test]
    async fn test_acme_cache_dir_created_on_startup() {
        let tmp = std::env::temp_dir().join("phalanx_tls_l3");
        let _ = std::fs::remove_dir_all(&tmp);

        let cache_dir = tmp.join("acme_cache");

        let mut config = AppConfig::default();
        config.auto_ssl_domain = Some("test.example.com".to_string());
        config.auto_ssl_cache_dir = Some(cache_dir.to_str().unwrap().to_string());

        let _ = load_tls_acceptor(&config, None);

        assert!(
            cache_dir.exists(),
            "ACME cache directory must be created by pre-flight check"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_acme_cache_dir_permissions_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join("phalanx_tls_l3b");
        let _ = std::fs::remove_dir_all(&tmp);

        let cache_dir = tmp.join("acme_cache");

        let mut config = AppConfig::default();
        config.auto_ssl_domain = Some("test.example.com".to_string());
        config.auto_ssl_cache_dir = Some(cache_dir.to_str().unwrap().to_string());

        let acceptor = load_tls_acceptor(&config, None);
        assert!(
            acceptor.is_some(),
            "ACME acceptor must load when cache dir is secure"
        );

        assert!(cache_dir.exists(), "ACME cache directory must exist");
        let metadata = std::fs::metadata(&cache_dir).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "ACME cache directory must be restricted to owner only (mode 700)"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    // ── L4: Dynamic certificate SNI resolution ────────────────────────────

    #[derive(Debug)]
    struct SkipServerVerification;

    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    fn build_test_client_config() -> Arc<rustls::ClientConfig> {
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        config.enable_sni = true;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// Helper: performs a TLS handshake against a localhost listener using
    /// the given SNI server name, returns the certificate chain presented
    /// by the server.
    async fn handshake_and_get_server_cert(
        server_config: Arc<ServerConfig>,
        server_name: &str,
    ) -> Option<Vec<CertificateDer<'static>>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.ok()?;
        let addr = listener.local_addr().ok()?;
        let acceptor = TlsAcceptor::from(server_config);

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.ok()?;
            let tls = acceptor.accept(tcp).await.ok()?;
            Some(tls)
        });

        let client_config = build_test_client_config();
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
        let server_name_rustls =
            rustls::pki_types::ServerName::try_from(server_name.to_string()).ok()?;
        let client_tls = connector.connect(server_name_rustls, tcp).await.ok()?;

        let certs = client_tls
            .get_ref()
            .1
            .peer_certificates()
            .map(|c| c.to_vec());

        // Drain server task so it doesn't leak
        let _ = server_task.await;
        certs
    }

    /// Computes a SHA-256 fingerprint of a certificate for comparison.
    fn cert_fingerprint(cert_der: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        format!("{:x}", hasher.finalize())
    }

    #[tokio::test]
    async fn test_dynamic_cert_resolver_sni_match() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = std::env::temp_dir().join(format!("phalanx_tls_l4a_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        // Generate fallback cert
        let fallback_params =
            rcgen::CertificateParams::new(vec!["fallback.test".to_string()]).unwrap();
        let fallback_key = rcgen::KeyPair::generate().unwrap();
        let fallback_cert = fallback_params.self_signed(&fallback_key).unwrap();

        // Generate dynamic cert
        let dynamic_params =
            rcgen::CertificateParams::new(vec!["dynamic.test".to_string()]).unwrap();
        let dynamic_key = rcgen::KeyPair::generate().unwrap();
        let dynamic_cert = dynamic_params.self_signed(&dynamic_key).unwrap();

        let fallback_cert_path = tmp.join("fallback.pem");
        let fallback_key_path = tmp.join("fallback.key");
        let dynamic_cert_path = tmp.join("dynamic.pem");
        let dynamic_key_path = tmp.join("dynamic.key");

        std::fs::write(&fallback_cert_path, fallback_cert.pem()).unwrap();
        std::fs::write(&fallback_key_path, fallback_key.serialize_pem()).unwrap();
        std::fs::write(&dynamic_cert_path, dynamic_cert.pem()).unwrap();
        std::fs::write(&dynamic_key_path, dynamic_key.serialize_pem()).unwrap();

        let dynamic_certs: Arc<dashmap::DashMap<String, crate::admin::api::SslCertEntry>> =
            Arc::new(dashmap::DashMap::new());
        dynamic_certs.insert(
            "dynamic.test".to_string(),
            crate::admin::api::SslCertEntry {
                server_name: "dynamic.test".to_string(),
                cert_path: dynamic_cert_path.to_str().unwrap().to_string(),
                key_path: dynamic_key_path.to_str().unwrap().to_string(),
                added_at: 0,
            },
        );

        let server_config = build_server_config_with_tls_opts(
            fallback_cert_path.to_str().unwrap(),
            fallback_key_path.to_str().unwrap(),
            None,
            None,
            &[],
            Some(dynamic_certs),
        )
        .expect("server config must build");

        let peer_certs = handshake_and_get_server_cert(server_config, "dynamic.test")
            .await
            .expect("handshake must succeed");
        assert!(!peer_certs.is_empty(), "server must present a certificate");

        let fp = cert_fingerprint(&peer_certs[0]);
        let expected_fp = cert_fingerprint(dynamic_cert.der());
        assert_eq!(fp, expected_fp, "SNI match must return dynamic cert");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_dynamic_cert_resolver_sni_fallback() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = std::env::temp_dir().join(format!("phalanx_tls_l4b_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let fallback_params =
            rcgen::CertificateParams::new(vec!["fallback.test".to_string()]).unwrap();
        let fallback_key = rcgen::KeyPair::generate().unwrap();
        let fallback_cert = fallback_params.self_signed(&fallback_key).unwrap();

        let dynamic_params =
            rcgen::CertificateParams::new(vec!["dynamic.test".to_string()]).unwrap();
        let dynamic_key = rcgen::KeyPair::generate().unwrap();
        let dynamic_cert = dynamic_params.self_signed(&dynamic_key).unwrap();

        let fallback_cert_path = tmp.join("fallback.pem");
        let fallback_key_path = tmp.join("fallback.key");
        let dynamic_cert_path = tmp.join("dynamic.pem");
        let dynamic_key_path = tmp.join("dynamic.key");

        std::fs::write(&fallback_cert_path, fallback_cert.pem()).unwrap();
        std::fs::write(&fallback_key_path, fallback_key.serialize_pem()).unwrap();
        std::fs::write(&dynamic_cert_path, dynamic_cert.pem()).unwrap();
        std::fs::write(&dynamic_key_path, dynamic_key.serialize_pem()).unwrap();

        let dynamic_certs: Arc<dashmap::DashMap<String, crate::admin::api::SslCertEntry>> =
            Arc::new(dashmap::DashMap::new());
        dynamic_certs.insert(
            "dynamic.test".to_string(),
            crate::admin::api::SslCertEntry {
                server_name: "dynamic.test".to_string(),
                cert_path: dynamic_cert_path.to_str().unwrap().to_string(),
                key_path: dynamic_key_path.to_str().unwrap().to_string(),
                added_at: 0,
            },
        );

        let server_config = build_server_config_with_tls_opts(
            fallback_cert_path.to_str().unwrap(),
            fallback_key_path.to_str().unwrap(),
            None,
            None,
            &[],
            Some(dynamic_certs),
        )
        .expect("server config must build");

        let peer_certs = handshake_and_get_server_cert(server_config, "unknown.test")
            .await
            .expect("handshake must succeed");
        assert!(!peer_certs.is_empty(), "server must present a certificate");

        let fp = cert_fingerprint(&peer_certs[0]);
        let expected_fp = cert_fingerprint(fallback_cert.der());
        assert_eq!(fp, expected_fp, "SNI miss must return fallback cert");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_dynamic_cert_resolver_no_sni() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = std::env::temp_dir().join(format!("phalanx_tls_l4c_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let fallback_params =
            rcgen::CertificateParams::new(vec!["fallback.test".to_string()]).unwrap();
        let fallback_key = rcgen::KeyPair::generate().unwrap();
        let fallback_cert = fallback_params.self_signed(&fallback_key).unwrap();

        let fallback_cert_path = tmp.join("fallback.pem");
        let fallback_key_path = tmp.join("fallback.key");
        std::fs::write(&fallback_cert_path, fallback_cert.pem()).unwrap();
        std::fs::write(&fallback_key_path, fallback_key.serialize_pem()).unwrap();

        let server_config = build_server_config_with_tls_opts(
            fallback_cert_path.to_str().unwrap(),
            fallback_key_path.to_str().unwrap(),
            None,
            None,
            &[],
            Some(Arc::new(dashmap::DashMap::new())),
        )
        .expect("server config must build");

        // Connect with an IP address — rustls disables SNI for IPs by default
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(server_config);

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.ok()?;
            let tls = acceptor.accept(tcp).await.ok()?;
            Some(tls)
        });

        let mut client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        client_config.enable_sni = false;
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::IpAddress(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)).into(),
        );
        let client_tls = connector.connect(server_name, tcp).await.unwrap();

        let peer_certs = client_tls
            .get_ref()
            .1
            .peer_certificates()
            .expect("server must present a certificate")
            .to_vec();
        assert!(!peer_certs.is_empty());

        let fp = cert_fingerprint(&peer_certs[0]);
        let expected_fp = cert_fingerprint(fallback_cert.der());
        assert_eq!(fp, expected_fp, "no SNI must return fallback cert");

        let _ = server_task.await;
        std::fs::remove_dir_all(&tmp).ok();
    }
}
