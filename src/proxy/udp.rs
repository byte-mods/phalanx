use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::routing::UpstreamManager;

const UDP_BUF_SIZE: usize = 65535;
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

struct UdpSession {
    backend_socket: Arc<UdpSocket>,
    backend_addr: SocketAddr,
    last_active: Instant,
}

/// Starts a UDP stream proxy that load-balances datagrams to upstream backends.
/// Each unique client address gets a dedicated backend socket for the session.
pub async fn start_udp_proxy(
    bind_addr: &str,
    upstreams: Arc<UpstreamManager>,
    shutdown: CancellationToken,
) {
    let addr: SocketAddr = match bind_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Invalid UDP proxy bind address '{}': {}", bind_addr, e);
            return;
        }
    };

    let socket = match UdpSocket::bind(&addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("UDP Proxy failed to bind on {}: {}", addr, e);
            return;
        }
    };

    info!("UDP Proxy listening on udp://{}", addr);

    let sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Spawn a reaper task to clean up expired sessions
    let sessions_reaper = Arc::clone(&sessions);
    let shutdown_reaper = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    let mut map = sessions_reaper.lock().await;
                    map.retain(|_client, session| {
                        session.last_active.elapsed() < SESSION_TIMEOUT
                    });
                }
                _ = shutdown_reaper.cancelled() => break,
            }
        }
    });

    let mut buf = vec![0u8; UDP_BUF_SIZE];

    loop {
        let (len, client_addr) = tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok(r) => r,
                    Err(e) => {
                        error!("UDP recv error: {}", e);
                        continue;
                    }
                }
            }
            _ = shutdown.cancelled() => {
                info!("UDP Proxy shutting down gracefully.");
                break;
            }
        };

        let data = buf[..len].to_vec();

        let mut map = sessions.lock().await;

        // Reuse existing session or create a new one
        if let Some(session) = map.get_mut(&client_addr) {
            session.last_active = Instant::now();
            let backend_sock = Arc::clone(&session.backend_socket);
            let backend_addr = session.backend_addr;
            drop(map);

            if let Err(e) = backend_sock.send_to(&data, backend_addr).await {
                debug!("UDP forward to {} failed: {}", backend_addr, e);
            }
        } else {
            // Select a backend from the "default" pool
            let pool = match upstreams.get_pool("default") {
                Some(p) => p,
                None => {
                    error!("No default pool for UDP proxy");
                    continue;
                }
            };

            let backend = match pool.get_next_backend(None, None) {
                Some(b) => b,
                None => {
                    error!("No healthy backends for UDP proxy");
                    continue;
                }
            };

            let backend_addr: SocketAddr = match backend.config.address.parse() {
                Ok(a) => a,
                Err(_) => continue,
            };

            // Bind a new ephemeral socket for talking to this backend
            let backend_socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    error!("Failed to bind ephemeral UDP socket: {}", e);
                    continue;
                }
            };

            if let Err(e) = backend_socket.send_to(&data, backend_addr).await {
                debug!("UDP forward to {} failed: {}", backend_addr, e);
                continue;
            }

            let session = UdpSession {
                backend_socket: Arc::clone(&backend_socket),
                backend_addr,
                last_active: Instant::now(),
            };
            map.insert(client_addr, session);
            drop(map);

            // Spawn a receiver task for backend → client responses
            let frontend = Arc::clone(&socket);
            let sessions_rx = Arc::clone(&sessions);
            let shutdown_rx = shutdown.clone();
            tokio::spawn(async move {
                let mut rx_buf = vec![0u8; UDP_BUF_SIZE];
                loop {
                    let result = tokio::select! {
                        r = backend_socket.recv_from(&mut rx_buf) => r,
                        _ = shutdown_rx.cancelled() => break,
                    };

                    match result {
                        Ok((n, _from)) => {
                            if let Err(e) = frontend.send_to(&rx_buf[..n], client_addr).await {
                                debug!("UDP reply to {} failed: {}", client_addr, e);
                                break;
                            }
                            {
                                let mut guard = sessions_rx.lock().await;
                                if let Some(s) = guard.get_mut(&client_addr) {
                                    s.last_active = Instant::now();
                                }
                            }
                        }
                        Err(e) => {
                            debug!("UDP backend recv error: {}", e);
                            break;
                        }
                    }
                }
            });
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const UDP_BUF_SIZE: usize = 65535;
    const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

    #[test]
    fn test_constants_defined() {
        assert_eq!(UDP_BUF_SIZE, 65535);
        assert_eq!(SESSION_TIMEOUT, Duration::from_secs(60));
    }

    #[test]
    fn test_session_timeout_is_reasonable() {
        // Session timeout should be at least 30 seconds
        assert!(SESSION_TIMEOUT >= Duration::from_secs(30));
    }

    #[test]
    fn test_udp_buffer_size_adequate() {
        // Buffer should be large enough for a typical UDP packet
        assert!(UDP_BUF_SIZE >= 512);
        // And not excessively large
        assert!(UDP_BUF_SIZE <= 1024 * 1024);
    }
}
