use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::routing::UpstreamManager;

/// Mail protocol proxy supporting SMTP, IMAP, and POP3.
///
/// Operates as a transparent TCP proxy with protocol-aware banner detection
/// and optional STARTTLS interception.

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MailProtocol {
    Smtp,
    Imap,
    Pop3,
}

impl MailProtocol {
    pub fn default_port(&self) -> u16 {
        match self {
            MailProtocol::Smtp => 25,
            MailProtocol::Imap => 143,
            MailProtocol::Pop3 => 110,
        }
    }

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
    pub protocol: MailProtocol,
    pub bind_addr: String,
    pub upstream_pool: String,
    pub banner: Option<String>,
    pub starttls: bool,
}

/// Starts a mail proxy server for the given protocol.
pub async fn start_mail_proxy(
    config: MailProxyConfig,
    upstreams: Arc<UpstreamManager>,
    shutdown: CancellationToken,
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

    info!(
        "{} proxy listening on {}",
        config.protocol.name(),
        addr
    );

    loop {
        let (mut client, peer) = tokio::select! {
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

use tokio::io::AsyncReadExt;

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
        };
        assert_eq!(config.protocol, MailProtocol::Smtp);
        assert_eq!(config.bind_addr, "0.0.0.0:25");
        assert!(config.starttls);
        assert_eq!(config.banner, Some("mx.example.com".to_string()));
    }

    #[test]
    fn test_mail_proxy_config_clone() {
        let config = MailProxyConfig {
            protocol: MailProtocol::Imap,
            bind_addr: "0.0.0.0:143".to_string(),
            upstream_pool: "imap".to_string(),
            banner: None,
            starttls: false,
        };
        let cloned = config.clone();
        assert_eq!(cloned.protocol, config.protocol);
        assert_eq!(cloned.bind_addr, config.bind_addr);
    }
}
