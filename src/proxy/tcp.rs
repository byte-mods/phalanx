use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::routing::UpstreamManager;
use std::sync::atomic::Ordering;

/// Starts a dedicated raw TCP proxy server.
/// This runs on a separate port from the main multiplexer and blindly forwards
/// bytes in both directions between the client and a backend server from the "default" pool.
pub async fn start_tcp_proxy(
    bind_addr: &str,
    upstreams: Arc<UpstreamManager>,
    shutdown: CancellationToken,
) {
    let addr: SocketAddr = bind_addr.parse().expect("Invalid TCP proxy bind address");
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(
                "TCP Proxy failed to bind on {}: {} (port may be in use)",
                addr, e
            );
            return;
        }
    };
    info!("TCP Proxy listening on tcp://{}", addr);

    loop {
        // Accept incoming TCP client connections, or break on shutdown signal
        let (mut client_stream, peer) = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Accept error: {}", e);
                        continue;
                    }
                }
            }
            _ = shutdown.cancelled() => {
                info!("TCP Proxy shutting down gracefully.");
                break;
            }
        };

        debug!("Accepted TCP connection from {}", peer);
        let upts = Arc::clone(&upstreams);

        // Spawn a green thread for each connection
        tokio::spawn(async move {
            // Because it's a raw TCP proxy, we don't have SNI or Host header (unless we parse TLS/HTTP),
            // so we route everything to the 'default' pool for this dedicated port.
            let pool = match upts.get_pool("default") {
                Some(p) => p,
                None => {
                    error!("No default upstream pool configured for TCP proxy");
                    return;
                }
            };

            // Select a healthy backend using the pool's load balancing algorithm
            let backend = match pool.get_next_backend(None, None) {
                Some(b) => b,
                None => {
                    error!("No healthy backends available for TCP proxy");
                    return;
                }
            };

            // Increment active connection count (used by LeastConnections algorithm)
            backend.active_connections.fetch_add(1, Ordering::Relaxed);

            // Connect to the chosen backend server
            match TcpStream::connect(&backend.config.address).await {
                Ok(mut server_stream) => {
                    // Start streaming bytes bidirectionally: Client <-> Proxy <-> Backend
                    match copy_bidirectional(&mut client_stream, &mut server_stream).await {
                        Ok((from_client, from_server)) => {
                            debug!(
                                "TCP Proxy completed: client sent {} bytes, server sent {} bytes",
                                from_client, from_server
                            );
                        }
                        Err(e) => {
                            debug!("TCP Proxy error streaming data: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "TCP Proxy failed to connect to backend {}: {}",
                        backend.config.address, e
                    );
                }
            }
            // Decrement active connection count when the session closes
            backend.active_connections.fetch_sub(1, Ordering::Relaxed);
        });
    }
}
