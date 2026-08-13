//! Raw TCP (Layer 4) proxy server.
//!
//! Unlike the main multiplexer which speaks HTTP, this module opens a dedicated
//! TCP listen port and blindly forwards bytes between clients and upstream
//! backends. It is useful for protocols like databases, MQTT, or custom
//! binary protocols where Phalanx acts as a transparent load-balancing relay.
//!
//! On Linux, the data path uses kernel `splice(2)` for true zero-copy I/O.
//! On other platforms it falls back to `tokio::io::copy_bidirectional`.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::routing::UpstreamManager;
use std::sync::atomic::Ordering;

/// Starts a dedicated raw TCP proxy server.
///
/// This runs on a separate port from the main multiplexer and blindly forwards
/// bytes in both directions between the client and a backend server from
/// `pool_name`.
///
/// # Arguments
///
/// * `bind_addr` - Socket address to listen on (e.g. `"0.0.0.0:9000"`).
/// * `upstreams` - Shared upstream pool manager used to select a healthy backend.
/// * `pool_name` - Upstream pool to forward to (`tcp_upstream_pool`, default `"default"`).
/// * `trusted`   - Peers allowed to declare a client address via PROXY protocol.
/// * `shutdown`  - Cancellation token that triggers graceful shutdown.
pub async fn start_tcp_proxy(
    bind_addr: &str,
    upstreams: Arc<UpstreamManager>,
    pool_name: String,
    trusted: crate::proxy::realip::TrustedProxies,
    shutdown: CancellationToken,
) {
    let addr: SocketAddr = match bind_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Invalid TCP proxy bind address '{}': {}", bind_addr, e);
            return;
        }
    };
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
        let pool_name = pool_name.clone();
        // A PROXY protocol header is only believed from a peer that is allowed to
        // speak for others; otherwise the header is stripped but the socket
        // address stands. See the matching note in the mux accept path.
        let pp_trusted = trusted.is_trusted(&peer.ip());

        // Spawn a green thread for each connection
        tokio::spawn(async move {
            // ── PROXY Protocol detection ──
            // Peek at the first bytes to detect a PROXY protocol header (v2 first,
            // then v1 as fallback). If present, extract the real client address and
            // strip the header before forwarding.
            let mut pp_buf = [0u8; 232]; // max PP2 header size (16 + 216 TLV); PP1 fits within
            let real_peer = match client_stream.peek(&mut pp_buf).await {
                Ok(n) if n >= 16 => {
                    match crate::proxy::proxy_proto_v2::parse_v2_header(&pp_buf[..n]) {
                        Ok((hdr, consumed)) => {
                            // Consume the PP2 header bytes from the stream
                            let mut discard = vec![0u8; consumed];
                            let _ = tokio::io::AsyncReadExt::read_exact(
                                &mut client_stream,
                                &mut discard,
                            )
                            .await;
                            let addr = hdr.src_addr.unwrap_or(peer);
                            if pp_trusted {
                                debug!("TCP proxy: PP2 real client IP: {}", addr);
                                addr
                            } else {
                                warn!(
                                    "TCP proxy: PP2 header from untrusted peer {} claimed {} — ignoring",
                                    peer.ip(),
                                    addr.ip()
                                );
                                peer
                            }
                        }
                        Err(crate::proxy::proxy_proto_v2::ParseError::NotProxyProtocol) => {
                            // PP2 magic didn't match — try PROXY protocol v1
                            match crate::proxy::realip::parse_proxy_protocol_v1(&pp_buf[..n]) {
                                Some((addr, consumed)) => {
                                    let mut discard = vec![0u8; consumed];
                                    let _ = tokio::io::AsyncReadExt::read_exact(
                                        &mut client_stream,
                                        &mut discard,
                                    )
                                    .await;
                                    debug!("TCP proxy: PP1 real client IP: {}", addr);
                                    addr
                                }
                                None => peer,
                            }
                        }
                        Err(_) => peer,
                    }
                }
                _ => peer,
            };
            debug!("TCP proxy: effective client: {}", real_peer);

            // Because it's a raw TCP proxy, we don't have SNI or Host header (unless we parse
            // TLS/HTTP), so the whole listener forwards to one configured pool.
            let pool = match upts.get_pool(&pool_name) {
                Some(p) => p,
                None => {
                    error!(
                        "TCP proxy: upstream pool '{}' not configured (set `tcp_upstream_pool`)",
                        pool_name
                    );
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
                    #[cfg(target_os = "linux")]
                    let res = crate::proxy::zero_copy::linux::splice_bidirectional(
                        &mut client_stream,
                        &mut server_stream,
                    )
                    .await;
                    #[cfg(not(target_os = "linux"))]
                    let res = crate::proxy::zero_copy::copy_bidirectional_fallback(
                        &mut client_stream,
                        &mut server_stream,
                    )
                    .await;

                    match res {
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
