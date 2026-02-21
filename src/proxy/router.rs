use bytes::BytesMut;
use std::io::Error as IoError;
use tokio::io::AsyncReadExt;

/// Defines the successfully sniffed protocol from the first few bytes of a connection.
#[derive(Debug, PartialEq)]
pub enum Protocol {
    /// Standard HTTP/1.x traffic
    Http1,
    /// HTTP/2 or gRPC traffic (identified by the HTTP/2 connection preface)
    Http2,
    /// TLS encrypted traffic (useful for ALPN or SNI routing later)
    Tls,
    /// Could not identify as HTTP or TLS; assumed to be raw TCP.
    UnknownTcp,
}

/// Peeks into the stream without consuming bytes permanently for the downstream handler.
/// It reads the first few bytes (up to 8) to sniff the protocol signature,
/// and stores those bytes in `buf`, which is later replayed by `PeekableStream`.
pub async fn sniff_protocol<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    buf: &mut BytesMut,
) -> Result<Protocol, IoError> {
    // Read up to 8 bytes to make a guess about the protocol
    let mut temp_buf = [0u8; 8];
    let n = stream.read(&mut temp_buf).await?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Connection closed early",
        ));
    }

    // Push the read bytes into the returned buffer so they aren't lost
    // to the actual request handler (like hyper or the TCP copy loop).
    buf.extend_from_slice(&temp_buf[..n]);

    let sig = &temp_buf[..n];

    // Check for HTTP/2 Connection Preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    if sig.starts_with(b"PRI * HT") {
        return Ok(Protocol::Http2);
    }

    // Check for TLS Client Hello (Content Type 22 (0x16), Version 0x03 0x01/02/03)
    if sig.len() >= 3 && sig[0] == 0x16 && sig[1] == 0x03 {
        return Ok(Protocol::Tls);
    }

    // Check for obvious HTTP/1.1 methods (GET, POST, PUT, HEAD, DELETE, OPTIONS, PATCH)
    let is_http1 = sig.starts_with(b"GET ") ||
                   sig.starts_with(b"POST ") ||
                   sig.starts_with(b"PUT ") ||
                   sig.starts_with(b"HEAD ") ||
                   sig.starts_with(b"DELETE ") ||
                   sig.starts_with(b"OPTION") || // OPTIONS
                   sig.starts_with(b"PATCH ");

    if is_http1 {
        return Ok(Protocol::Http1);
    }

    // If none of the signatures match, default to treating the connection as Raw TCP
    Ok(Protocol::UnknownTcp)
}
