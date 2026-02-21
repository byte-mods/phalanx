use hyper::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

/// Checks if an HTTP request is a WebSocket upgrade by examining typed headers.
pub fn is_websocket_upgrade<T>(req: &Request<T>) -> bool {
    let has_upgrade = req
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    let has_connection = req
        .headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);

    has_upgrade && has_connection
}

/// Handles a WebSocket upgrade by establishing a bidirectional byte tunnel
/// between the client and the backend. This is a raw TCP tunnel after the
/// HTTP 101 Switching Protocols handshake.
///
/// The flow:
/// 1. Client sends `GET /ws HTTP/1.1` with `Upgrade: websocket`
/// 2. Phalanx opens a TCP connection to the backend
/// 3. Phalanx forwards the original upgrade request to the backend
/// 4. Backend responds with `101 Switching Protocols`
/// 5. Phalanx relays the 101 response to the client
/// 6. Both directions are tunneled with `tokio::io::copy_bidirectional`
pub async fn handle_websocket_upgrade(
    mut client_stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    raw_request: &[u8],
    backend_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("WebSocket upgrade → tunneling to {}", backend_addr);

    // Connect to the backend
    let mut backend_stream = TcpStream::connect(backend_addr).await?;

    // Forward the raw HTTP upgrade request to the backend
    backend_stream.write_all(raw_request).await?;

    // Read the backend's 101 response and relay it to the client
    let mut response_buf = vec![0u8; 4096];
    let n = backend_stream.read(&mut response_buf).await?;
    if n == 0 {
        return Err("Backend closed connection during WebSocket handshake".into());
    }
    client_stream.write_all(&response_buf[..n]).await?;

    // Verify it's a 101 response
    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    if !response_str.contains("101") {
        error!(
            "Backend did not return 101 Switching Protocols: {}",
            response_str
        );
        return Err("Backend rejected WebSocket upgrade".into());
    }

    debug!("WebSocket handshake complete, starting bidirectional tunnel");

    // Bidirectional tunnel: relay all data between client and backend
    let (client_read, client_write) = tokio::io::split(&mut client_stream);
    let (backend_read, backend_write) = tokio::io::split(&mut backend_stream);

    let mut client_reader = tokio::io::BufReader::new(client_read);
    let mut backend_writer = tokio::io::BufWriter::new(backend_write);
    let mut backend_reader = tokio::io::BufReader::new(backend_read);
    let mut client_writer = tokio::io::BufWriter::new(client_write);

    let client_to_backend = tokio::io::copy(&mut client_reader, &mut backend_writer);
    let backend_to_client = tokio::io::copy(&mut backend_reader, &mut client_writer);

    // Run both directions concurrently; if either ends, close both
    tokio::select! {
        result = client_to_backend => {
            if let Err(e) = result {
                debug!("WebSocket client→backend stream ended: {}", e);
            }
        }
        result = backend_to_client => {
            if let Err(e) = result {
                debug!("WebSocket backend→client stream ended: {}", e);
            }
        }
    }

    info!("WebSocket connection closed for backend {}", backend_addr);
    Ok(())
}
