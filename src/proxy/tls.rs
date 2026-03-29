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

/// Builds a rustls `ServerConfig` from cert and key file paths.
/// If `ca_cert_path` is provided, enables mTLS client certificate verification.
fn build_server_config(
    cert_path: &str,
    key_path: &str,
    ca_cert_path: Option<&str>,
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
        ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certs, key)
            .map_err(|e| {
                error!("Failed to build mTLS ServerConfig: {}", e);
                e
            })
            .ok()?
    } else {
        // ── Standard TLS (no client auth) ─────────────────────────────────
        ServerConfig::builder()
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

/// Loads TLS configuration and returns a TlsAcceptor.
/// Called once at startup. Enables mTLS if `tls_ca_cert_path` is configured.
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
        
        // Spawn the ACME background worker task to answer challenges
        tokio::spawn(async move {
            while let Some(event) = state.next().await {
                match event {
                    Ok(e) => info!("Let's Encrypt ACME event: {:?}", e),
                    Err(err) => error!("Let's Encrypt ACME error: {:?}", err),
                }
            }
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

    let server_config = build_server_config(cert_path, key_path, ca_path)?;
    Some(TlsAcceptor::from(server_config))
}

/// Reloads TLS certificates from disk and returns a new TlsAcceptor.
/// Called on SIGHUP to hot-reload certificates without restarting.
pub fn reload_tls_acceptor(config: &AppConfig) -> Option<TlsAcceptor> {
    let cert_path = config.tls_cert_path.as_ref()?;
    let key_path = config.tls_key_path.as_ref()?;
    let ca_path = config.tls_ca_cert_path.as_deref();

    info!(
        "Hot-reloading TLS certificates from {} and {}",
        cert_path, key_path
    );

    match build_server_config(cert_path, key_path, ca_path) {
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
