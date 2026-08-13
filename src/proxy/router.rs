//! Protocol detection (sniffing) for the multiplexer proxy.
//!
//! When a new TCP connection arrives on the main proxy port, Phalanx does not
//! know in advance whether the client will speak HTTP/1, HTTP/2, TLS, or raw
//! TCP. This module reads the first few bytes from the socket to classify the
//! protocol, then stashes those bytes so they can be replayed to the actual
//! protocol handler (see `PeekableStream` in `mod.rs`).

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
/// It classifies the connection from the first few bytes and guarantees those
/// bytes end up in `buf`, which is later replayed by `PeekableStream`.
///
/// `buf` may already hold bytes the caller pulled off the socket (the accept
/// path reads ahead to test for a PROXY-protocol v2 header). When it does, we
/// classify from those bytes instead of issuing a second read — the client has
/// already sent its request head and is waiting for a response, so reading
/// again would block until the client gives up.
pub async fn sniff_protocol<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    buf: &mut BytesMut,
) -> Result<Protocol, IoError> {
    // Only touch the socket when the caller has not already buffered bytes for us.
    if buf.is_empty() {
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
    }

    // Classify on at most the first 8 bytes — the longest signature we match
    // is the 8-byte HTTP/2 preface prefix.
    let sig = &buf[..buf.len().min(8)];

    // Check for HTTP/2 Connection Preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    if sig.starts_with(b"PRI * HT") {
        return Ok(Protocol::Http2);
    }

    // Check for TLS Client Hello (Content Type 22 (0x16), Version 0x03 0x01/02/03)
    if sig.len() >= 3 && sig[0] == 0x16 && sig[1] == 0x03 {
        return Ok(Protocol::Tls);
    }

    // Check for HTTP/1.1 request methods. This covers every method defined in
    // RFC 9110 §9.3 — TRACE and CONNECT included, so they are answered as HTTP
    // (with whatever status the pipeline decides) instead of being mistaken for
    // an opaque byte stream and handed to the raw-TCP path.
    let is_http1 = sig.starts_with(b"GET ") ||
                   sig.starts_with(b"POST ") ||
                   sig.starts_with(b"PUT ") ||
                   sig.starts_with(b"HEAD ") ||
                   sig.starts_with(b"DELETE ") ||
                   sig.starts_with(b"OPTION") || // OPTIONS
                   sig.starts_with(b"PATCH ") ||
                   sig.starts_with(b"TRACE ") ||
                   sig.starts_with(b"CONNECT");

    if is_http1 {
        return Ok(Protocol::Http1);
    }

    // Extension methods (RFC 9110 §9.1 — the method set is open) are not in the
    // list above: WebDAV's PROPFIND/MKCOL, a cache PURGE, and anything bespoke.
    // Those used to fall through to the raw-TCP path and be dropped without a
    // response at all, which is both wrong and undiagnosable from the client.
    //
    // When the caller has already buffered the request head — the normal case,
    // since the PROXY-protocol pre-read pulls in far more than 8 bytes — look
    // for the HTTP version token on the first line. That is decisive: no raw
    // TCP protocol carries " HTTP/1." in its opening line, so this cannot
    // steal traffic from the mux's raw-TCP passthrough.
    let first_line_end = buf
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(buf.len());
    let first_line = &buf[..first_line_end.min(MAX_REQUEST_LINE_SNIFF)];
    if first_line
        .windows(HTTP_VERSION_TOKEN.len())
        .any(|w| w == HTTP_VERSION_TOKEN)
    {
        return Ok(Protocol::Http1);
    }

    // If none of the signatures match, default to treating the connection as Raw TCP
    Ok(Protocol::UnknownTcp)
}

/// The HTTP/1 version token that terminates a request line. Matching on this
/// identifies HTTP regardless of which method was used.
const HTTP_VERSION_TOKEN: &[u8] = b" HTTP/1.";

/// How far into the first line to look for the version token. RFC 9112 sets no
/// limit on the request line, but a bounded scan keeps this O(1) on the hot path
/// and still covers any realistic request target.
const MAX_REQUEST_LINE_SNIFF: usize = 8192;
