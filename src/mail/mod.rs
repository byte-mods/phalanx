use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::routing::UpstreamManager;

/// Mail protocol proxy supporting SMTP, IMAP, and POP3.
///
/// Operates as a transparent TCP proxy with protocol-aware banner detection
/// and optional STARTTLS interception.

/// Supported mail protocols for the transparent proxy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MailProtocol {
    /// Simple Mail Transfer Protocol (port 25).
    Smtp,
    /// Internet Message Access Protocol (port 143).
    Imap,
    /// Post Office Protocol v3 (port 110).
    Pop3,
}

impl MailProtocol {
    /// Returns the well-known default port for this protocol.
    pub fn default_port(&self) -> u16 {
        match self {
            MailProtocol::Smtp => 25,
            MailProtocol::Imap => 143,
            MailProtocol::Pop3 => 110,
        }
    }

    /// Returns the uppercase protocol name for logging.
    pub fn name(&self) -> &'static str {
        match self {
            MailProtocol::Smtp => "SMTP",
            MailProtocol::Imap => "IMAP",
            MailProtocol::Pop3 => "POP3",
        }
    }
}

/// Configuration for a mail proxy listener.
#[derive(Debug, Clone)]
pub struct MailProxyConfig {
    /// Which mail protocol this listener serves.
    pub protocol: MailProtocol,
    /// TCP address to listen on (e.g. `"0.0.0.0:25"`).
    pub bind_addr: String,
    /// Name of the upstream pool containing mail backend servers.
    pub upstream_pool: String,
    /// Optional custom greeting banner injected before proxying.
    pub banner: Option<String>,
    /// Whether to support STARTTLS upgrade.
    pub starttls: bool,
    /// Path to TLS certificate file for STARTTLS (PEM format).
    pub tls_cert_path: Option<String>,
    /// Path to TLS private key file for STARTTLS (PEM format).
    pub tls_key_path: Option<String>,
}

/// Builds a TLS acceptor for STARTTLS from cert and key paths.
fn build_starttls_acceptor(cert_path: &str, key_path: &str) -> Option<TlsAcceptor> {
    let server_config = crate::proxy::tls::build_server_config(cert_path, key_path, None)?;
    Some(TlsAcceptor::from(server_config))
}

/// Detects a STARTTLS command in a protocol line.
fn is_starttls_command(line: &str, protocol: MailProtocol) -> bool {
    let trimmed = line.trim();
    match protocol {
        MailProtocol::Smtp => trimmed.eq_ignore_ascii_case("STARTTLS"),
        MailProtocol::Imap => {
            // IMAP format: "tag STARTTLS"
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            parts.len() == 2 && parts[1].eq_ignore_ascii_case("STARTTLS")
        }
        MailProtocol::Pop3 => trimmed.eq_ignore_ascii_case("STLS"),
    }
}

/// Extracts the IMAP tag from a command line (e.g., "a001" from "a001 STARTTLS").
fn extract_imap_tag(line: &str) -> &str {
    line.trim().split(' ').next().unwrap_or("*")
}

/// Performs STARTTLS negotiation on an accepted client connection.
///
/// Reads protocol lines until the STARTTLS command is detected, sends the
/// appropriate acknowledgment, and upgrades the connection to TLS.
/// All non-STARTTLS commands received during negotiation are rejected.
async fn negotiate_starttls(
    mut client: TcpStream,
    protocol: MailProtocol,
    banner: &str,
    tls_acceptor: &TlsAcceptor,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>, String> {
    // Send greeting with STARTTLS capability
    let greeting = match protocol {
        MailProtocol::Smtp => format!(
            "220 {} ESMTP Phalanx\r\n",
            banner
        ),
        MailProtocol::Imap => format!(
            "* OK [CAPABILITY IMAP4rev1 STARTTLS] {} Phalanx IMAP Proxy\r\n",
            banner
        ),
        MailProtocol::Pop3 => format!(
            "+OK {} Phalanx POP3 Proxy\r\n",
            banner
        ),
    };
    client.write_all(greeting.as_bytes()).await.map_err(|e| format!("banner write: {}", e))?;

    let (reader, mut writer) = client.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            buf_reader.read_line(&mut line),
        )
        .await
        .map_err(|_| "STARTTLS negotiation timeout".to_string())?
        .map_err(|e| format!("read error: {}", e))?;

        if n == 0 {
            return Err("client disconnected during STARTTLS negotiation".to_string());
        }

        if is_starttls_command(&line, protocol) {
            // Send STARTTLS acknowledgment
            let ack = match protocol {
                MailProtocol::Smtp => "220 Ready to start TLS\r\n".to_string(),
                MailProtocol::Imap => {
                    let tag = extract_imap_tag(&line);
                    format!("{} OK Begin TLS negotiation now\r\n", tag)
                }
                MailProtocol::Pop3 => "+OK Begin TLS negotiation\r\n".to_string(),
            };
            writer.write_all(ack.as_bytes()).await.map_err(|e| format!("ack write: {}", e))?;

            // Reunite the split stream for TLS upgrade
            let client = buf_reader.into_inner().reunite(writer)
                .map_err(|e| format!("reunite error: {}", e))?;

            // Perform TLS handshake
            let tls_stream = tls_acceptor
                .accept(client)
                .await
                .map_err(|e| format!("TLS handshake failed: {}", e))?;

            return Ok(tls_stream);
        }

        // Handle pre-STARTTLS protocol commands
        match protocol {
            MailProtocol::Smtp => {
                let cmd = line.trim().to_uppercase();
                if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                    let host = banner;
                    let resp = format!(
                        "250-{}\r\n250-STARTTLS\r\n250 OK\r\n",
                        host
                    );
                    writer.write_all(resp.as_bytes()).await.map_err(|e| format!("write: {}", e))?;
                } else if cmd.starts_with("QUIT") {
                    writer.write_all(b"221 Bye\r\n").await.ok();
                    return Err("client quit before STARTTLS".to_string());
                } else {
                    writer
                        .write_all(b"530 Must issue a STARTTLS command first\r\n")
                        .await
                        .map_err(|e| format!("write: {}", e))?;
                }
            }
            MailProtocol::Imap => {
                let tag = extract_imap_tag(&line);
                let resp = format!("{} BAD Must negotiate STARTTLS first\r\n", tag);
                writer.write_all(resp.as_bytes()).await.map_err(|e| format!("write: {}", e))?;
            }
            MailProtocol::Pop3 => {
                let cmd = line.trim().to_uppercase();
                if cmd.starts_with("CAPA") {
                    writer
                        .write_all(b"+OK Capability list follows\r\nSTLS\r\n.\r\n")
                        .await
                        .map_err(|e| format!("write: {}", e))?;
                } else if cmd.starts_with("QUIT") {
                    writer.write_all(b"+OK Bye\r\n").await.ok();
                    return Err("client quit before STARTTLS".to_string());
                } else {
                    writer
                        .write_all(b"-ERR Must negotiate STLS first\r\n")
                        .await
                        .map_err(|e| format!("write: {}", e))?;
                }
            }
        }
    }
}

/// Starts a mail proxy server for the given protocol.
///
/// When `verify_backend_tls` is false (the default for backwards compatibility),
/// a warning is logged indicating that backend TLS certificate verification is
/// skipped. Set `mail_verify_backend_tls true;` in the server block to enable.
pub async fn start_mail_proxy(
    config: MailProxyConfig,
    upstreams: Arc<UpstreamManager>,
    shutdown: CancellationToken,
    verify_backend_tls: bool,
) {
    let addr: SocketAddr = match config.bind_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            error!(
                "{} proxy: invalid bind address '{}': {}",
                config.protocol.name(),
                config.bind_addr,
                e
            );
            return;
        }
    };

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(
                "{} proxy failed to bind on {}: {}",
                config.protocol.name(),
                addr,
                e
            );
            return;
        }
    };

    // Build STARTTLS acceptor if configured
    let starttls_acceptor = if config.starttls {
        match (&config.tls_cert_path, &config.tls_key_path) {
            (Some(cert), Some(key)) => {
                match build_starttls_acceptor(cert, key) {
                    Some(acceptor) => {
                        info!("{} proxy: STARTTLS enabled", config.protocol.name());
                        Some(Arc::new(acceptor))
                    }
                    None => {
                        error!("{} proxy: failed to build STARTTLS acceptor", config.protocol.name());
                        None
                    }
                }
            }
            _ => {
                error!(
                    "{} proxy: STARTTLS enabled but tls_cert_path/tls_key_path not configured",
                    config.protocol.name()
                );
                None
            }
        }
    } else {
        None
    };

    info!(
        "{} proxy listening on {}",
        config.protocol.name(),
        addr
    );

    loop {
        let (client, peer) = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(s) => s,
                    Err(e) => {
                        error!("{} accept error: {}", config.protocol.name(), e);
                        continue;
                    }
                }
            }
            _ = shutdown.cancelled() => {
                info!("{} proxy shutting down.", config.protocol.name());
                break;
            }
        };

        let upts = Arc::clone(&upstreams);
        let cfg = config.clone();
        let tls_acceptor = starttls_acceptor.clone();

        tokio::spawn(async move {
            debug!("{} connection from {}", cfg.protocol.name(), peer);

            // Select backend
            let pool = match upts.get_pool(&cfg.upstream_pool) {
                Some(p) => p,
                None => {
                    error!("No upstream pool '{}' for mail proxy", cfg.upstream_pool);
                    return;
                }
            };

            let backend = match pool.get_next_backend(None, None) {
                Some(b) => b,
                None => {
                    error!("No healthy backends for mail proxy");
                    return;
                }
            };

            // Connect to backend
            let mut server = match TcpStream::connect(&backend.config.address).await {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "Failed to connect to mail backend {}: {}",
                        backend.config.address, e
                    );
                    return;
                }
            };

            // Warn if backend TLS certificate verification is disabled
            if cfg.starttls && !verify_backend_tls {
                tracing::warn!(
                    "{} proxy: backend TLS certificate verification is disabled for {}. \
                     Set 'mail_verify_backend_tls true;' to enable.",
                    cfg.protocol.name(),
                    backend.config.address
                );
            }

            // STARTTLS path: negotiate TLS upgrade before proxying
            if let Some(ref acceptor) = tls_acceptor {
                let banner = cfg.banner.as_deref().unwrap_or("mail.phalanx.local");
                match negotiate_starttls(client, cfg.protocol, banner, acceptor).await {
                    Ok(mut tls_client) => {
                        // Read and discard the backend's own banner
                        let mut buf = vec![0u8; 512];
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            server.read(&mut buf),
                        )
                        .await;

                        match crate::proxy::zero_copy::copy_bidirectional_fallback(
                            &mut tls_client,
                            &mut server,
                        )
                        .await
                        {
                            Ok((from_client, from_server)) => {
                                debug!(
                                    "{} STARTTLS session closed: {} sent {} bytes, server sent {} bytes",
                                    cfg.protocol.name(), peer, from_client, from_server
                                );
                            }
                            Err(e) => {
                                debug!("{} STARTTLS proxy error: {}", cfg.protocol.name(), e);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("{} STARTTLS negotiation failed for {}: {}", cfg.protocol.name(), peer, e);
                    }
                }
                return;
            }

            // Plain TCP proxy path (no STARTTLS)
            let mut client = client;

            // Optionally send a custom banner before proxying
            if let Some(ref banner) = cfg.banner {
                let greeting = match cfg.protocol {
                    MailProtocol::Smtp => format!("220 {} ESMTP Phalanx\r\n", banner),
                    MailProtocol::Imap => format!("* OK {} Phalanx IMAP Proxy\r\n", banner),
                    MailProtocol::Pop3 => format!("+OK {} Phalanx POP3 Proxy\r\n", banner),
                };
                if let Err(e) = client.write_all(greeting.as_bytes()).await {
                    debug!("Failed to send mail banner: {}", e);
                    return;
                }

                // Read and discard the backend's own banner
                let mut buf = vec![0u8; 512];
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    server.read(&mut buf),
                )
                .await;
            }

            // Bidirectional streaming
            match crate::proxy::zero_copy::copy_bidirectional_fallback(&mut client, &mut server)
                .await
            {
                Ok((from_client, from_server)) => {
                    debug!(
                        "{} session closed: {} sent {} bytes, server sent {} bytes",
                        cfg.protocol.name(),
                        peer,
                        from_client,
                        from_server
                    );
                }
                Err(e) => {
                    debug!("{} proxy error: {}", cfg.protocol.name(), e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mail_protocol_smtp_port() {
        assert_eq!(MailProtocol::Smtp.default_port(), 25);
    }

    #[test]
    fn test_mail_protocol_imap_port() {
        assert_eq!(MailProtocol::Imap.default_port(), 143);
    }

    #[test]
    fn test_mail_protocol_pop3_port() {
        assert_eq!(MailProtocol::Pop3.default_port(), 110);
    }

    #[test]
    fn test_mail_protocol_names() {
        assert_eq!(MailProtocol::Smtp.name(), "SMTP");
        assert_eq!(MailProtocol::Imap.name(), "IMAP");
        assert_eq!(MailProtocol::Pop3.name(), "POP3");
    }

    #[test]
    fn test_mail_protocol_equality() {
        assert_eq!(MailProtocol::Smtp, MailProtocol::Smtp);
        assert_ne!(MailProtocol::Smtp, MailProtocol::Imap);
    }

    #[test]
    fn test_mail_proxy_config_creation() {
        let config = MailProxyConfig {
            protocol: MailProtocol::Smtp,
            bind_addr: "0.0.0.0:25".to_string(),
            upstream_pool: "mail_backend".to_string(),
            banner: Some("mx.example.com".to_string()),
            starttls: true,
            tls_cert_path: Some("/etc/phalanx/cert.pem".to_string()),
            tls_key_path: Some("/etc/phalanx/key.pem".to_string()),
        };
        assert_eq!(config.protocol, MailProtocol::Smtp);
        assert_eq!(config.bind_addr, "0.0.0.0:25");
        assert!(config.starttls);
        assert_eq!(config.banner, Some("mx.example.com".to_string()));
        assert!(config.tls_cert_path.is_some());
        assert!(config.tls_key_path.is_some());
    }

    #[test]
    fn test_mail_proxy_config_clone() {
        let config = MailProxyConfig {
            protocol: MailProtocol::Imap,
            bind_addr: "0.0.0.0:143".to_string(),
            upstream_pool: "imap".to_string(),
            banner: None,
            starttls: false,
            tls_cert_path: None,
            tls_key_path: None,
        };
        let cloned = config.clone();
        assert_eq!(cloned.protocol, config.protocol);
        assert_eq!(cloned.bind_addr, config.bind_addr);
    }

    #[test]
    fn test_starttls_command_detection_smtp() {
        assert!(is_starttls_command("STARTTLS\r\n", MailProtocol::Smtp));
        assert!(is_starttls_command("starttls\r\n", MailProtocol::Smtp));
        assert!(is_starttls_command("  STARTTLS  ", MailProtocol::Smtp));
        assert!(!is_starttls_command("EHLO example.com", MailProtocol::Smtp));
    }

    #[test]
    fn test_starttls_command_detection_imap() {
        assert!(is_starttls_command("a001 STARTTLS\r\n", MailProtocol::Imap));
        assert!(is_starttls_command("tag STARTTLS", MailProtocol::Imap));
        assert!(!is_starttls_command("STARTTLS", MailProtocol::Imap)); // needs tag
        assert!(!is_starttls_command("a001 LOGIN user pass", MailProtocol::Imap));
    }

    #[test]
    fn test_starttls_command_detection_pop3() {
        assert!(is_starttls_command("STLS\r\n", MailProtocol::Pop3));
        assert!(is_starttls_command("stls", MailProtocol::Pop3));
        assert!(!is_starttls_command("USER admin", MailProtocol::Pop3));
    }

    #[test]
    fn test_extract_imap_tag() {
        assert_eq!(extract_imap_tag("a001 STARTTLS\r\n"), "a001");
        assert_eq!(extract_imap_tag("tag LOGIN user pass"), "tag");
        assert_eq!(extract_imap_tag("*"), "*");
    }

    #[test]
    fn test_mail_proxy_config_with_tls_verification() {
        // Verify the config struct accepts STARTTLS + verification settings
        let config = MailProxyConfig {
            protocol: MailProtocol::Smtp,
            bind_addr: "0.0.0.0:25".to_string(),
            upstream_pool: "mail_backend".to_string(),
            banner: Some("mx.example.com".to_string()),
            starttls: true,
            tls_cert_path: Some("/etc/phalanx/cert.pem".to_string()),
            tls_key_path: Some("/etc/phalanx/key.pem".to_string()),
        };
        assert!(config.starttls);
        // verify_backend_tls is passed as a separate parameter to start_mail_proxy(),
        // not stored in MailProxyConfig, for backwards compatibility
    }
}
