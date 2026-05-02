//! WebTransport-over-HTTP/3 session driver — RFC 9220 / draft-ietf-webtrans-http3.
//!
//! Phalanx accepts WT sessions only when the operator opts in via the
//! `webtransport on;` directive in `phalanx.conf`. The H3 listener
//! advertises `SETTINGS_ENABLE_WEBTRANSPORT = 1`, `H3_DATAGRAM = 1`, and
//! `ENABLE_CONNECT_PROTOCOL = 1` during the handshake (see
//! `start_http3_proxy` in `proxy/http3.rs`). On receipt of an Extended
//! CONNECT request whose `:protocol` is `webtransport`, the H3 listener
//! hands the entire `h3::server::Connection` to `serve_session` here —
//! `WebTransportSession::accept` consumes it, so once we run, the QUIC
//! connection is owned by this module for the rest of its life.
//!
//! ## v1 forwarding semantics: terminate-with-echo
//!
//! plan.md (W1.4) called out three possible forwarding modes:
//!   a. Terminate (publish/subscribe via Phalanx admin API)
//!   b. Tunnel    (proxy WT to an upstream that also speaks WT)
//!   c. Both, per-route via `wt_mode terminate|tunnel;`
//!
//! v1 ships *terminate-with-echo*: every incoming bidi stream, uni
//! stream, and datagram is echoed back to the client. Reasons:
//!   - The published `h3-webtransport = 0.1.2` crate ships **server-only**
//!     APIs (no client). Tunnel mode therefore requires implementing the
//!     WT client over h3 primitives — a multi-day project of its own.
//!   - The pubsub/admin-API design for option (a) is also non-trivial
//!     and would block this PR on a separate API surface design.
//!   - Echo exercises the full wire path (settings negotiation, Extended
//!     CONNECT acceptance, bidi+uni stream lifecycle, datagrams) end-to-end
//!     against any real WT client. That is what makes the feature actually
//!     testable and observable in production today.
//!
//! Tunnel and pubsub are deliberately deferred — when a WT client crate
//! lands (or we write our own), `bidi_echo_loop` / `uni_echo_loop` /
//! `datagram_echo_loop` become the swap point. The session driver shape
//! does not change.

use bytes::Bytes;
use h3::ext::Protocol;
use h3::server::{Connection, RequestStream};
use h3_quinn::BidiStream;
use h3_webtransport::server::{AcceptedBi, WebTransportSession};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

/// Returns true if the request is a WebTransport Extended CONNECT
/// (RFC 9220). h3 0.0.8 surfaces the `:protocol` pseudo-header via the
/// request extensions, so the modern check is on the extension; legacy
/// browsers sometimes also send the older `sec-webtransport-http3-draft*`
/// headers — we accept both.
pub fn is_webtransport_request(req: &hyper::Request<()>) -> bool {
    if req.method() != hyper::Method::CONNECT {
        return false;
    }
    if req.extensions().get::<Protocol>() == Some(&Protocol::WEB_TRANSPORT) {
        return true;
    }
    req.headers().contains_key("sec-webtransport-http3-draft02")
        || req.headers().contains_key("sec-webtransport-http3-draft")
}

/// Drive a single WebTransport session in echo mode.
///
/// Consumes the H3 connection. Returns when the session ends (either the
/// client closed it cleanly, or any of the three echo loops hit an
/// unrecoverable error).
pub async fn serve_session(
    req: hyper::Request<()>,
    stream: RequestStream<BidiStream<Bytes>, Bytes>,
    conn: Connection<h3_quinn::Connection, Bytes>,
    remote_addr: SocketAddr,
    metrics: Arc<crate::admin::ProxyMetrics>,
) {
    let session = match WebTransportSession::accept(req, stream, conn).await {
        Ok(s) => {
            info!("WebTransport session accepted from {}", remote_addr);
            metrics.wt_sessions_total.with_label_values(&["accepted"]).inc();
            metrics.wt_active_sessions.inc();
            s
        }
        Err(e) => {
            warn!(
                "WebTransport accept failed from {}: {}",
                remote_addr, e
            );
            metrics.wt_sessions_total.with_label_values(&["error"]).inc();
            return;
        }
    };

    let session = Arc::new(session);
    let metrics_clone = Arc::clone(&metrics);

    // Three concurrent echo loops sharing the session via Arc.
    tokio::select! {
        _ = bidi_echo_loop(session.clone(), remote_addr, Arc::clone(&metrics)) => {},
        _ = uni_echo_loop(session.clone(), remote_addr, Arc::clone(&metrics)) => {},
        _ = datagram_echo_loop(session.clone(), remote_addr, metrics_clone) => {},
    }

    metrics.wt_active_sessions.dec();
    debug!("WebTransport session ended (remote={})", remote_addr);
}

/// Type alias to keep generics readable. h3_quinn-specific so we don't
/// drag generic bounds through the file.
type WtSession = WebTransportSession<h3_quinn::Connection, Bytes>;

/// Echo every incoming bidirectional stream back to the client. Each
/// accepted stream is handled in its own task so a slow reader on one
/// stream doesn't stall accepting the next.
async fn bidi_echo_loop(
    session: Arc<WtSession>,
    remote_addr: SocketAddr,
    metrics: Arc<crate::admin::ProxyMetrics>,
) {
    loop {
        match session.accept_bi().await {
            Ok(Some(AcceptedBi::BidiStream(_session_id, mut bidi))) => {
                let m = metrics.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let outcome = loop {
                        match bidi.read(&mut buf).await {
                            Ok(0) => break "echoed", // peer half-closed
                            Ok(n) => {
                                if let Err(e) = bidi.write_all(&buf[..n]).await {
                                    debug!("WT bidi echo write: {}", e);
                                    break "error";
                                }
                            }
                            Err(e) => {
                                debug!("WT bidi echo read: {}", e);
                                break "error";
                            }
                        }
                    };
                    m.wt_streams_total
                        .with_label_values(&["bidi", outcome])
                        .inc();
                    // Best-effort flush + finish; ignore errors because
                    // the peer may already have closed the stream.
                    let _ = bidi.shutdown().await;
                });
            }
            Ok(Some(AcceptedBi::Request(_req, mut req_stream))) => {
                // RFC 9220 lets clients open nested HTTP/3 requests inside
                // a WT session. Phalanx echo doesn't speak any of those
                // — return 501 and move on. The WT session itself stays
                // up.
                let resp = hyper::Response::builder()
                    .status(hyper::StatusCode::NOT_IMPLEMENTED)
                    .body(())
                    .unwrap_or_else(|_| hyper::Response::new(()));
                let _ = req_stream.send_response(resp).await;
                let _ = req_stream.finish().await;
            }
            Ok(None) => {
                debug!("WT session: bidi accept returned None (remote={})", remote_addr);
                return;
            }
            Err(e) => {
                debug!("WT bidi accept error (remote={}): {}", remote_addr, e);
                return;
            }
        }
    }
}

/// Echo every incoming unidirectional stream by reading it to EOF, then
/// opening a fresh server-initiated uni stream and writing the same
/// bytes back. (Uni streams are one-way by definition, so the echo path
/// has to use a new stream in the opposite direction.)
async fn uni_echo_loop(
    session: Arc<WtSession>,
    remote_addr: SocketAddr,
    metrics: Arc<crate::admin::ProxyMetrics>,
) {
    loop {
        match session.accept_uni().await {
            Ok(Some((session_id, mut recv))) => {
                let session_for_task = session.clone();
                let m = metrics.clone();
                tokio::spawn(async move {
                    // Drain the incoming uni stream first. WT uni
                    // streams typically carry small messages, so an
                    // 8 KiB scratch buffer + a Vec is fine for v1.
                    let mut payload: Vec<u8> = Vec::with_capacity(4096);
                    let mut buf = [0u8; 8192];
                    let outcome = loop {
                        match recv.read(&mut buf).await {
                            Ok(0) => break "drained",
                            Ok(n) => payload.extend_from_slice(&buf[..n]),
                            Err(e) => {
                                debug!("WT uni read: {}", e);
                                m.wt_streams_total
                                    .with_label_values(&["uni", "error"])
                                    .inc();
                                return;
                            }
                        }
                    };
                    // Open a fresh server-initiated uni stream back to
                    // the client and write the captured payload.
                    let mut send = match session_for_task.open_uni(session_id).await {
                        Ok(s) => s,
                        Err(e) => {
                            debug!("WT uni open_uni: {}", e);
                            m.wt_streams_total
                                .with_label_values(&["uni", "error"])
                                .inc();
                            return;
                        }
                    };
                    if let Err(e) = send.write_all(&payload).await {
                        debug!("WT uni echo write: {}", e);
                        m.wt_streams_total
                            .with_label_values(&["uni", "error"])
                            .inc();
                        return;
                    }
                    let _ = send.shutdown().await;
                    m.wt_streams_total
                        .with_label_values(&["uni", outcome])
                        .inc();
                });
            }
            Ok(None) => {
                debug!("WT session: uni accept returned None (remote={})", remote_addr);
                return;
            }
            Err(e) => {
                debug!("WT uni accept error (remote={}): {}", remote_addr, e);
                return;
            }
        }
    }
}

/// Echo HTTP/3 datagrams. Each datagram read becomes one datagram sent.
/// `send_datagram` is non-blocking on quinn (the OS buffers; if it
/// can't, the datagram is dropped — that's the contract for unreliable
/// transport).
async fn datagram_echo_loop(
    session: Arc<WtSession>,
    remote_addr: SocketAddr,
    metrics: Arc<crate::admin::ProxyMetrics>,
) {
    let mut reader = session.datagram_reader();
    let mut sender = session.datagram_sender();

    loop {
        match reader.read_datagram().await {
            Ok(dgram) => {
                let payload = dgram.into_payload();
                if let Err(e) = sender.send_datagram(payload) {
                    debug!("WT datagram send: {}", e);
                    metrics
                        .wt_datagrams_total
                        .with_label_values(&["error"])
                        .inc();
                    return;
                }
                metrics
                    .wt_datagrams_total
                    .with_label_values(&["echoed"])
                    .inc();
            }
            Err(e) => {
                debug!(
                    "WT datagram read error (remote={}): {}",
                    remote_addr, e
                );
                metrics
                    .wt_datagrams_total
                    .with_label_values(&["error"])
                    .inc();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: an extension-tagged WT request matches.
    #[test]
    fn detects_protocol_extension() {
        let mut req = hyper::Request::builder()
            .method(hyper::Method::CONNECT)
            .uri("/")
            .body(())
            .unwrap();
        req.extensions_mut().insert(Protocol::WEB_TRANSPORT);
        assert!(is_webtransport_request(&req));
    }

    /// Sanity: legacy `sec-webtransport-http3-draft02` header still
    /// counts as a WT request (older Chromium ships this).
    #[test]
    fn detects_legacy_header() {
        let req = hyper::Request::builder()
            .method(hyper::Method::CONNECT)
            .uri("/")
            .header("sec-webtransport-http3-draft02", "1")
            .body(())
            .unwrap();
        assert!(is_webtransport_request(&req));
    }

    /// Negative: a regular GET is not a WT request.
    #[test]
    fn rejects_non_connect() {
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri("/")
            .body(())
            .unwrap();
        assert!(!is_webtransport_request(&req));
    }

    /// Negative: CONNECT *without* the WT protocol extension or legacy
    /// header is some other Extended CONNECT (e.g. `connect-udp`) and
    /// must not be misrouted into the WT session driver.
    #[test]
    fn rejects_other_extended_connect() {
        let mut req = hyper::Request::builder()
            .method(hyper::Method::CONNECT)
            .uri("/")
            .body(())
            .unwrap();
        req.extensions_mut().insert(Protocol::CONNECT_UDP);
        assert!(!is_webtransport_request(&req));
    }
}
