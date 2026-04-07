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
use rustls::{ServerConfig, pki_types::CertificateDer, server::WebPkiClientVerifier};
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use futures_util::StreamExt;

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
fn filter_cipher_suites(
    requested: &[String],
) -> Vec<rustls::SupportedCipherSuite> {
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
            warn!("TLS cipher suite '{}' not available in rustls, skipping", name);
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
    build_server_config_with_tls_opts(cert_path, key_path, ca_cert_path, None, &[])
}

/// Builds a rustls `ServerConfig` with optional TLS version/cipher constraints.
pub(crate) fn build_server_config_with_tls_opts(
    cert_path: &str,
    key_path: &str,
    ca_cert_path: Option<&str>,
    tls_min_version: Option<&str>,
    tls_ciphers: &[String],
) -> Option<Arc<ServerConfig>> {
    let cert_file = match File::open(cert_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open cert file {}: {}", cert_path, e);
            return None;
        }
    };
    let mut cert_reader = BufReader::new(cert_file);
    let server_certs: Vec<CertificateDer> =
        certs(&mut cert_reader).filter_map(|c| c.ok()).collect();

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
    let versions: Vec<&'static rustls::SupportedProtocolVersion> = if let Some(min_ver) = tls_min_version {
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

    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)
        .map_err(|e| {
            error!("Failed to build TLS config with custom protocol versions: {}", e);
            e
        })
        .ok()?;

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
        let ca_certs: Vec<CertificateDer> = certs(&mut ca_reader).filter_map(|c| c.ok()).collect();

        let mut root_store = rustls::RootCertStore::empty();
        for ca_cert in ca_certs {
            if let Err(e) = root_store.add(ca_cert) {
                error!("Failed to add CA certificate to root store: {}", e);
                return None;
            }
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
            .with_single_cert(server_certs, key)
            .map_err(|e| {
                error!("Failed to build mTLS ServerConfig: {}", e);
                e
            })
            .ok()?
    } else {
        // ── Standard TLS (no client auth) ─────────────────────────────────
        builder
            .with_no_client_auth()
            .with_single_cert(server_certs, key)
            .map_err(|e| {
                error!("Failed to build TLS ServerConfig: {}", e);
                e
            })
            .ok()?
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
pub fn load_tls_acceptor(config: &AppConfig) -> Option<TlsAcceptor> {
    // 1. Auto-SSL via Let's Encrypt takes precedence if configured
    if let Some(domain) = &config.auto_ssl_domain {
        info!("Enabling Let's Encrypt Auto-SSL for domain: {}", domain);
        
        let mail = config.auto_ssl_email.as_deref().unwrap_or("admin@example.com");
        let cache_dir = config.auto_ssl_cache_dir.clone().unwrap_or_else(|| {
            std::env::temp_dir().join("phalanx_acme_cache").to_string_lossy().into_owned()
        });

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
pub fn reload_tls_acceptor(config: &AppConfig) -> Option<TlsAcceptor> {
    let cert_path = config.tls_cert_path.as_ref()?;
    let key_path = config.tls_key_path.as_ref()?;
    let ca_path = config.tls_ca_cert_path.as_deref();

    info!(
        "Hot-reloading TLS certificates from {} and {}",
        cert_path, key_path
    );

    match build_server_config_with_tls_opts(
        cert_path,
        key_path,
        ca_path,
        config.tls_min_version.as_deref(),
        &config.tls_ciphers,
    ) {
        Some(server_config) => {
            info!("TLS certificates reloaded successfully.");
            Some(TlsAcceptor::from(server_config))
        }
        None => {
            warn!("TLS certificate reload failed — keeping existing certificates.");
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
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_load_tls_acceptor_no_config() {
        let config = AppConfig::default();
        let result = load_tls_acceptor(&config);
        assert!(result.is_none());
    }
}
