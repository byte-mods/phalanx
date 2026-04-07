//! Core proxy subsystem -- the heart of Phalanx.
//!
//! This module contains the primary multiplexer (`start_proxy`) that accepts
//! TCP connections, sniffs the application-layer protocol, and dispatches to
//! the appropriate handler:
//!
//! | Protocol    | Handler                                  |
//! |-------------|------------------------------------------|
//! | HTTP/1.x    | `handle_http_request` (via hyper HTTP/1) |
//! | HTTP/2/gRPC | `handle_http2_request` (via hyper HTTP/2)|
//! | TLS         | TLS termination then HTTP/1 or HTTP/2    |
//! | Raw TCP     | Discarded on the MUX port (use `tcp.rs`) |
//!
//! Each request handler runs through a multi-step pipeline:
//! 1. Real IP resolution (X-Forwarded-For / PROXY Protocol)
//! 2. Zone-based concurrent connection limiting
//! 3. CAPTCHA / bot detection
//! 4. WAF inspection (URL, headers, body)
//! 5. GeoIP country blocking
//! 6. Scripting hooks (PreRoute, PreUpstream, Log)
//! 7. URL rewrite engine (break/last/redirect/permanent)
//! 8. Authentication (Basic, JWT, JWKS, OAuth, OIDC, auth_request)
//! 9. Route matching (longest-prefix)
//! 10. Static file serving / FastCGI / uWSGI dispatch
//! 11. Backend selection (round-robin, least-conn, IP hash, AI-weighted)
//! 12. Sticky session affinity
//! 13. Request header injection + OpenTelemetry trace context
//! 14. HTTP proxying with keepalive connection pooling
//! 15. WebSocket upgrade tunneling
//! 16. Response caching
//! 17. Traffic mirroring
//! 18. Compression (Brotli > gzip)
//! 19. gRPC-Web response translation
//! 20. Access logging + Prometheus metrics + AI score updates
//!
//! Submodules handle specific concerns (TLS, HTTP/3, TCP/UDP, FastCGI, etc.).

use bytes::{Buf, Bytes, BytesMut};
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rand::RngExt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::middleware::compression;
use arc_swap::ArcSwap;

pub mod executor;
pub mod fastcgi;
pub mod grpc_web;
pub mod http3;
pub mod mirror;
pub mod ocsp;
pub mod pool;
pub mod proxy_proto_v2;
pub mod realip;
pub mod rewrite;
pub mod router;
pub mod sticky;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod uwsgi;
pub mod webrtc;
pub mod zero_copy;

use fastcgi::serve_fastcgi;
use rewrite::{RewriteResult, apply_rewrites, compile_rules};
use uwsgi::serve_uwsgi;

use crate::admin::ProxyMetrics;
use crate::ai::AiRouter;
use crate::config::AppConfig;
use crate::middleware::{AdvancedCache, CacheEntry, build_cache_key};
use crate::routing::UpstreamManager;
use crate::telemetry::access_log::{AccessLogEntry, AccessLogger};
use router::Protocol;

/// A wrapper around a standard Tokio `TcpStream` that can seamlessly replay
/// a sequence of bytes (the `buffer`) before yielding new bytes from the underlying stream.
/// This is used by the protocol sniffer which has to consume the first few bytes
/// to identify the protocol, but then must hand the connection off to a protocol handler
/// (like hyper for HTTP) which expects to see those bytes again.
pub struct PeekableStream {
    /// The underlying TCP connection to the client.
    stream: TcpStream,
    /// Bytes that were read during protocol sniffing and must be replayed first.
    buffer: BytesMut,
}

// ── AsyncRead / AsyncWrite implementations for PeekableStream ───────────────

impl AsyncRead for PeekableStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // First replay whatever bytes we sniffed
        if !self.buffer.is_empty() {
            let len = std::cmp::min(self.buffer.len(), buf.remaining());
            buf.put_slice(&self.buffer[..len]);
            self.buffer.advance(len);
            Poll::Ready(Ok(()))
        } else {
            // Once the prefix buffer is drained, read directly from the OS socket
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
}

impl AsyncWrite for PeekableStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Helper function to create standard HTTP BoxBody responses for errors (like 502/404)
///
/// ### Example Input / Output
///
/// **Input**:
/// `hyper::StatusCode::BAD_GATEWAY`
///
/// **Output**:
/// `Response<BoxBody<Bytes, hyper::Error>>` with a status of 502 Bad Gateway and an empty body.
fn empty_response(status: hyper::StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .body(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Constructs an HTTP 429 Too Many Requests response with a configurable Retry-After header.
///
/// # Arguments
/// * `retry_after` - Seconds the client should wait before retrying.
fn rate_limit_response_with_retry(retry_after: u64) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Bytes::from_static(b"429 Too Many Requests\n");
    Response::builder()
        .status(hyper::StatusCode::TOO_MANY_REQUESTS)
        .header("Retry-After", retry_after.to_string())
        .header("Content-Type", "text/plain")
        .body(
            http_body_util::Full::new(body)
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Backward-compatible wrapper: 429 with Retry-After: 60.
fn rate_limit_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    rate_limit_response_with_retry(60)
}

/// Constructs a structured error response. Returns JSON when the client accepts it,
/// otherwise text/plain. Includes a request-scoped trace ID for correlation.
fn error_response(
    status: hyper::StatusCode,
    message: &str,
    request_id: &str,
    accept_json: bool,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let reason = status.canonical_reason().unwrap_or("Error");
    if accept_json {
        let json = serde_json::json!({
            "status": status.as_u16(),
            "error": reason,
            "message": message,
            "request_id": request_id,
        });
        let body = Bytes::from(serde_json::to_string(&json).unwrap_or_default());
        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(
                http_body_util::Full::new(body)
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    } else {
        let body = Bytes::from(format!("{} {}: {}\n", status.as_u16(), reason, message));
        Response::builder()
            .status(status)
            .header("Content-Type", "text/plain")
            .body(
                http_body_util::Full::new(body)
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

/// Returns true if the Accept header indicates the client wants JSON responses.
fn client_accepts_json(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json") || v.contains("*/*"))
        .unwrap_or(false)
}

/// Constructs an HTML response with the given status code and body string.
/// Used for CAPTCHA challenge pages and similar browser-facing responses.
fn html_response(
    status: hyper::StatusCode,
    html: String,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(
            Full::new(Bytes::from(html))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Decodes a single URL-encoded form component (percent-decoding + `+` to space).
fn decode_form_component(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &input[i + 1..i + 3];
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Parses an `application/x-www-form-urlencoded` body into a key-value map.
fn parse_urlencoded_form(bytes: &[u8]) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let raw = String::from_utf8_lossy(bytes);
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        out.insert(decode_form_component(k), decode_form_component(v));
    }
    out
}

/// Reconstructs the original URL (path + query string) for post-CAPTCHA redirect.
fn build_return_to(path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) if !q.is_empty() => format!("{}?{}", path, q),
        _ => path.to_string(),
    }
}

/// Handles the `/__phalanx/captcha/verify` POST endpoint.
///
/// Validates the CAPTCHA token submitted by the browser, consumes the
/// challenge nonce on success, and redirects the user back to the
/// original page. On failure, re-serves the challenge HTML.
async fn handle_captcha_verify_request(
    req: Request<hyper::body::Incoming>,
    client_ip: &str,
    captcha_manager: Arc<Option<crate::waf::bot::CaptchaManager>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let manager = match captcha_manager.as_ref() {
        Some(m) => m,
        None => return Ok(empty_response(hyper::StatusCode::NOT_FOUND)),
    };

    if req.method() != hyper::Method::POST {
        return Ok(empty_response(hyper::StatusCode::METHOD_NOT_ALLOWED));
    }

    let body_bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(empty_response(hyper::StatusCode::BAD_REQUEST)),
    };

    let form_values = parse_urlencoded_form(&body_bytes);
    let token = match manager.extract_token_from_form(&form_values) {
        Some(t) => t,
        None => return Ok(empty_response(hyper::StatusCode::BAD_REQUEST)),
    };
    let nonce = match manager.extract_nonce_from_form(&form_values) {
        Some(n) => n,
        None => return Ok(empty_response(hyper::StatusCode::BAD_REQUEST)),
    };
    let return_to = match manager.return_to_for_valid_nonce(client_ip, &nonce) {
        Some(p) => p,
        None => return Ok(empty_response(hyper::StatusCode::BAD_REQUEST)),
    };

    if token.is_empty() {
        return Ok(empty_response(hyper::StatusCode::BAD_REQUEST));
    }

    if manager.verify_token(&token, client_ip).await {
        manager.consume_challenge(client_ip);
        return Ok(Response::builder()
            .status(hyper::StatusCode::SEE_OTHER)
            .header(hyper::header::LOCATION, return_to)
            .body(
                http_body_util::Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap());
    }

    Ok(html_response(
        hyper::StatusCode::FORBIDDEN,
        manager.challenge_html(),
    ))
}

// ── Main Proxy Entrypoint ────────────────────────────────────────────────────

/// Starts the primary universal multiplexer (Mux) proxy on the configured port.
///
/// This is the main entry point for all client traffic. It accepts raw TCP
/// connections, sniffs the first bytes to determine the application protocol
/// (HTTP/1, HTTP/2/gRPC, TLS, or raw TCP), then hands off to the appropriate
/// handler.
///
/// # Parameters
///
/// * `bind_addr`      - Socket address to listen on (e.g. `"0.0.0.0:8080"`).
/// * `app_config`     - Hot-swappable application configuration (routes, TLS paths, etc.).
/// * `upstreams`      - Shared upstream pool manager with health-checked backends.
/// * `tls_acceptor`   - Hot-swappable TLS acceptor (reloaded on SIGHUP).
/// * `_waf`           - Web Application Firewall engine for request inspection.
/// * `rate_limiter`   - IP-based and global rate limiter.
/// * `_ai_engine`     - AI/ML-powered load balancing score tracker.
/// * `cache`          - Response cache (L1 in-memory, L2 disk).
/// * `hook_engine`    - Rhai scripting hook engine (PreRoute, PreUpstream, Log).
/// * `metrics`        - Prometheus metrics collector.
/// * `access_logger`  - Structured access log writer.
/// * `geo_db`         - Optional GeoIP database for country-based routing/blocking.
/// * `geo_policy`     - Country allow/deny policy.
/// * `sticky`         - Optional sticky session manager.
/// * `zone_limiter`   - Per-zone concurrent connection limiter.
/// * `captcha_manager`- Optional CAPTCHA challenge manager.
/// * `wasm_plugins`   - WebAssembly plugin manager for custom request/response transforms.
/// * `gslb_router`    - Optional GSLB router for geo-based pool selection.
/// * `k8s_controller` - Optional Kubernetes Ingress controller.
/// * `bandwidth`      - Per-protocol bandwidth tracker.
/// * `shutdown`       - Cancellation token for graceful shutdown.
/// * `oidc_sessions`  - OIDC session store for OpenID Connect authentication.
pub async fn start_proxy(
    bind_addr: &str,
    app_config: Arc<ArcSwap<AppConfig>>,
    upstreams: Arc<UpstreamManager>,
    tls_acceptor: Arc<ArcSwap<Option<tokio_rustls::TlsAcceptor>>>,
    waf: Arc<crate::waf::WafEngine>,
    rate_limiter: Arc<crate::middleware::ratelimit::PhalanxRateLimiter>,
    ai_engine: Arc<dyn AiRouter>,
    cache: Arc<AdvancedCache>,
    hook_engine: Arc<crate::scripting::HookEngine>,
    metrics: Arc<ProxyMetrics>,
    access_logger: Arc<AccessLogger>,
    geo_db: Arc<Option<crate::geo::GeoIpDatabase>>,
    geo_policy: Arc<crate::geo::GeoPolicy>,
    sticky: Arc<Option<crate::proxy::sticky::StickySessionManager>>,
    zone_limiter: Arc<crate::middleware::connlimit::ZoneLimiter>,
    captcha_manager: Arc<Option<crate::waf::bot::CaptchaManager>>,
    wasm_plugins: Arc<crate::wasm::WasmPluginManager>,
    gslb_router: Arc<Option<crate::gslb::GslbRouter>>,
    k8s_controller: Arc<Option<crate::k8s::IngressController>>,
    bandwidth: Arc<crate::telemetry::bandwidth::BandwidthTracker>,
    shutdown: CancellationToken,
    oidc_sessions: crate::auth::oidc::OidcSessionStore,
) {
    let addr: SocketAddr = match bind_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Invalid proxy bind address '{}': {}", bind_addr, e);
            return;
        }
    };
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind proxy listener on {}: {}", addr, e);
            return;
        }
    };
    info!("Mux Proxy listening on {}", addr);

    loop {
        // Accept new connections, or break on shutdown signal
        let (mut stream, peer) = tokio::select! {
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
                info!("Mux Proxy shutting down gracefully — no new connections accepted.");
                break;
            }
        };

        // Clone Arcs to move into the background task
        let upstreams_clone = Arc::clone(&upstreams);
        let config_clone = Arc::clone(&app_config);
        let tls_acceptor_clone = Arc::clone(&tls_acceptor);
        let waf_spawn_clone = Arc::clone(&waf);
        let ai_spawn_clone = Arc::clone(&ai_engine);
        let rl_clone = Arc::clone(&rate_limiter);
        let cache_clone = Arc::clone(&cache);
        let hook_clone = Arc::clone(&hook_engine);
        let metrics_clone = Arc::clone(&metrics);
        let logger_clone = Arc::clone(&access_logger);
        let geo_db_clone = Arc::clone(&geo_db);
        let geo_policy_clone = Arc::clone(&geo_policy);
        let sticky_clone = Arc::clone(&sticky);
        let zone_clone = Arc::clone(&zone_limiter);
        let captcha_clone = Arc::clone(&captcha_manager);
        let wasm_clone = Arc::clone(&wasm_plugins);
        let gslb_clone = Arc::clone(&gslb_router);
        let k8s_clone = Arc::clone(&k8s_controller);
        let bw_clone = Arc::clone(&bandwidth);
        let oidc_clone = Arc::clone(&oidc_sessions);

        // Spawn a new green thread per connection (Tokio task)
        tokio::spawn(async move {
            // ── PROXY Protocol v2 detection ──────────────────────────────────
            // Read up to 232 bytes (max PP2 fixed header + IPv6 address block)
            // without consuming bytes needed by the protocol sniffer below.
            let mut pp2_peek = [0u8; 232];
            let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut pp2_peek).await {
                Ok(0) | Err(_) => return, // connection closed immediately
                Ok(n) => n,
            };

            // Try to parse as PROXY Protocol v2. On success, override `peer` with
            // the real source address. On failure/mismatch, put all bytes back.
            let (real_peer, remaining_bytes) =
                match proxy_proto_v2::parse_v2_header(&pp2_peek[..n]) {
                    Ok((hdr, consumed)) => {
                        let real_peer = hdr.src_addr.unwrap_or(peer);
                        (real_peer, &pp2_peek[consumed..n])
                    }
                    Err(proxy_proto_v2::ParseError::NotProxyProtocol) => {
                        // Not a PP2 connection — treat all peeked bytes as normal traffic
                        (peer, &pp2_peek[..n])
                    }
                    Err(_) => return, // Malformed PP2 header — drop the connection
                };
            let peer = real_peer;

            let mut prefix_buf = BytesMut::with_capacity(64);
            prefix_buf.extend_from_slice(remaining_bytes);

            // Wait to receive the first few bytes to guess the protocol
            let proto = match router::sniff_protocol(&mut stream, &mut prefix_buf).await {
                Ok(p) => p,
                Err(e) => {
                    debug!("Sniffing completely failed / closed: {}", e);
                    return;
                }
            };

            debug!("Sniffed Protocol: {:?} from {}", proto, peer);

            // Rate Limit Check — for HTTP protocols, return 429; for others, silently drop
            if !rl_clone.check_ip(peer.ip()).await {
                metrics_clone
                    .rate_limit_rejections
                    .with_label_values(&["ip_or_global"])
                    .inc();
                match proto {
                    Protocol::Http1 | Protocol::Http2 => {
                        // Send a proper HTTP 429 response before closing
                        let peekable = PeekableStream {
                            stream,
                            buffer: prefix_buf,
                        };
                        let io = TokioIo::new(peekable);
                        let retry_after = config_clone.load().rate_limit_retry_after.unwrap_or(60);
                        let svc = service_fn(move |_req| async move {
                            Ok::<_, hyper::Error>(rate_limit_response_with_retry(retry_after))
                        });
                        let _ = http1::Builder::new().serve_connection(io, svc).await;
                        return;
                    }
                    _ => {
                        // TLS/UnknownTcp — silently drop
                        return;
                    }
                }
            }

            // Wrap the OS socket in our PeekableStream to replay the sniffed bytes
            let peekable_stream = PeekableStream {
                stream,
                buffer: prefix_buf,
            };
            let tls_acceptor_current = tls_acceptor_clone.load_full();

            // Route execution based on protocol
            match proto {
                Protocol::Http1 => {
                    let io = TokioIo::new(peekable_stream);
                    let oidc_h1 = Arc::clone(&oidc_clone);
                    let svc = service_fn(move |req| {
                        let upts = Arc::clone(&upstreams_clone);
                        let cfg = Arc::clone(&config_clone);
                        let waf_svc = Arc::clone(&waf_spawn_clone);
                        let ai_svc = Arc::clone(&ai_spawn_clone);
                        let cache_svc = Arc::clone(&cache_clone);
                        let hook_svc = Arc::clone(&hook_clone);
                        let metrics_svc = Arc::clone(&metrics_clone);
                        let logger_svc = Arc::clone(&logger_clone);
                        let geo_db_svc = Arc::clone(&geo_db_clone);
                        let geo_policy_svc = Arc::clone(&geo_policy_clone);
                        let sticky_svc = Arc::clone(&sticky_clone);
                        let zone_svc = Arc::clone(&zone_clone);
                        let captcha_svc = Arc::clone(&captcha_clone);
                        let wasm_svc = Arc::clone(&wasm_clone);
                        let gslb_svc = Arc::clone(&gslb_clone);
                        let k8s_svc = Arc::clone(&k8s_clone);
                        let bw_svc = Arc::clone(&bw_clone);
                        let oidc_svc = Arc::clone(&oidc_h1);
                        async move {
                            handle_http_request(
                                req,
                                peer,
                                upts,
                                cfg,
                                waf_svc,
                                ai_svc,
                                cache_svc,
                                hook_svc,
                                metrics_svc,
                                logger_svc,
                                geo_db_svc,
                                geo_policy_svc,
                                sticky_svc,
                                zone_svc,
                                captcha_svc,
                                wasm_svc,
                                gslb_svc,
                                k8s_svc,
                                bw_svc,
                                oidc_svc,
                            )
                            .await
                        }
                    });

                    // Start the Hyper HTTP/1 server logic
                    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                        debug!("Error serving HTTP/1 connection: {:?}", e);
                    }
                }
                Protocol::Http2 => {
                    let io = TokioIo::new(peekable_stream);
                    let oidc_h2 = Arc::clone(&oidc_clone);
                    let svc = service_fn(move |req| {
                        let upts = Arc::clone(&upstreams_clone);
                        let cfg = Arc::clone(&config_clone);
                        let waf_svc = Arc::clone(&waf_spawn_clone);
                        let ai_svc = Arc::clone(&ai_spawn_clone);
                        let cache_svc = Arc::clone(&cache_clone);
                        let hook_svc = Arc::clone(&hook_clone);
                        let metrics_svc = Arc::clone(&metrics_clone);
                        let logger_svc = Arc::clone(&logger_clone);
                        let geo_db_svc = Arc::clone(&geo_db_clone);
                        let geo_policy_svc = Arc::clone(&geo_policy_clone);
                        let sticky_svc = Arc::clone(&sticky_clone);
                        let zone_svc = Arc::clone(&zone_clone);
                        let captcha_svc = Arc::clone(&captcha_clone);
                        let wasm_svc = Arc::clone(&wasm_clone);
                        let gslb_svc = Arc::clone(&gslb_clone);
                        let k8s_svc = Arc::clone(&k8s_clone);
                        let bw_svc = Arc::clone(&bw_clone);
                        let oidc_svc = Arc::clone(&oidc_h2);
                        async move {
                            handle_http2_request(
                                req,
                                peer,
                                upts,
                                cfg,
                                waf_svc,
                                ai_svc,
                                cache_svc,
                                hook_svc,
                                metrics_svc,
                                logger_svc,
                                geo_db_svc,
                                geo_policy_svc,
                                sticky_svc,
                                zone_svc,
                                captcha_svc,
                                wasm_svc,
                                gslb_svc,
                                k8s_svc,
                                bw_svc,
                                oidc_svc,
                            )
                            .await
                        }
                    });

                    // Start the Hyper HTTP/2 server logic
                    if let Err(e) =
                        hyper::server::conn::http2::Builder::new(executor::TokioExecutor)
                            .serve_connection(io, svc)
                            .await
                    {
                        debug!("Error serving HTTP/2 connection: {:?}", e);
                    }
                }
                Protocol::Tls => {
                    if let Some(acceptor) = tls_acceptor_current.as_ref().clone() {
                        match acceptor.accept(peekable_stream).await {
                            Ok(tls_stream) => {
                                let (io, alpn) = {
                                    let (_, session) = tls_stream.get_ref();
                                    let alpn = session.alpn_protocol().map(|p| p.to_vec());
                                    (TokioIo::new(tls_stream), alpn)
                                };

                                let is_h2 = alpn.as_deref() == Some(b"h2");

                                if is_h2 {
                                    let oidc_tls_h2 = Arc::clone(&oidc_clone);
                                    let svc = service_fn(move |req| {
                                        let upts = Arc::clone(&upstreams_clone);
                                        let cfg = Arc::clone(&config_clone);
                                        let waf_svc = Arc::clone(&waf_spawn_clone);
                                        let ai_svc = Arc::clone(&ai_spawn_clone);
                                        let cache_svc = Arc::clone(&cache_clone);
                                        let hook_svc = Arc::clone(&hook_clone);
                                        let metrics_svc = Arc::clone(&metrics_clone);
                                        let logger_svc = Arc::clone(&logger_clone);
                                        let geo_db_svc = Arc::clone(&geo_db_clone);
                                        let geo_policy_svc = Arc::clone(&geo_policy_clone);
                                        let sticky_svc = Arc::clone(&sticky_clone);
                                        let zone_svc = Arc::clone(&zone_clone);
                                        let captcha_svc = Arc::clone(&captcha_clone);
                                        let wasm_svc = Arc::clone(&wasm_clone);
                                        let gslb_svc = Arc::clone(&gslb_clone);
                                        let k8s_svc = Arc::clone(&k8s_clone);
                                        let bw_svc = Arc::clone(&bw_clone);
                                        let oidc_svc = Arc::clone(&oidc_tls_h2);
                                        async move {
                                            handle_http2_request(
                                                req,
                                                peer,
                                                upts,
                                                cfg,
                                                waf_svc,
                                                ai_svc,
                                                cache_svc,
                                                hook_svc,
                                                metrics_svc,
                                                logger_svc,
                                                geo_db_svc,
                                                geo_policy_svc,
                                                sticky_svc,
                                                zone_svc,
                                                captcha_svc,
                                                wasm_svc,
                                                gslb_svc,
                                                k8s_svc,
                                                bw_svc,
                                                oidc_svc,
                                            )
                                            .await
                                        }
                                    });
                                    if let Err(e) = hyper::server::conn::http2::Builder::new(
                                        executor::TokioExecutor,
                                    )
                                    .serve_connection(io, svc)
                                    .await
                                    {
                                        debug!("Error serving TLS HTTP/2 connection: {:?}", e);
                                    }
                                } else {
                                    let oidc_tls_h1 = Arc::clone(&oidc_clone);
                                    let svc = service_fn(move |req| {
                                        let upts = Arc::clone(&upstreams_clone);
                                        let cfg = Arc::clone(&config_clone);
                                        let waf_svc = Arc::clone(&waf_spawn_clone);
                                        let ai_svc = Arc::clone(&ai_spawn_clone);
                                        let cache_svc = Arc::clone(&cache_clone);
                                        let hook_svc = Arc::clone(&hook_clone);
                                        let metrics_svc = Arc::clone(&metrics_clone);
                                        let logger_svc = Arc::clone(&logger_clone);
                                        let geo_db_svc = Arc::clone(&geo_db_clone);
                                        let geo_policy_svc = Arc::clone(&geo_policy_clone);
                                        let sticky_svc = Arc::clone(&sticky_clone);
                                        let zone_svc = Arc::clone(&zone_clone);
                                        let captcha_svc = Arc::clone(&captcha_clone);
                                        let wasm_svc = Arc::clone(&wasm_clone);
                                        let gslb_svc = Arc::clone(&gslb_clone);
                                        let k8s_svc = Arc::clone(&k8s_clone);
                                        let bw_svc = Arc::clone(&bw_clone);
                                        let oidc_svc = Arc::clone(&oidc_tls_h1);
                                        async move {
                                            handle_http_request(
                                                req,
                                                peer,
                                                upts,
                                                cfg,
                                                waf_svc,
                                                ai_svc,
                                                cache_svc,
                                                hook_svc,
                                                metrics_svc,
                                                logger_svc,
                                                geo_db_svc,
                                                geo_policy_svc,
                                                sticky_svc,
                                                zone_svc,
                                                captcha_svc,
                                                wasm_svc,
                                                gslb_svc,
                                                k8s_svc,
                                                bw_svc,
                                                oidc_svc,
                                            )
                                            .await
                                        }
                                    });
                                    if let Err(e) =
                                        http1::Builder::new().serve_connection(io, svc).await
                                    {
                                        debug!("Error serving TLS HTTP/1 connection: {:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("TLS handshake failed: {}", e);
                            }
                        }
                    } else {
                        error!("TLS connection received but no certificates configured. Dropping.");
                    }
                }
                Protocol::UnknownTcp => {
                    // If it isn't HTTP or TLS, ignore it on the HTTP proxy port
                    debug!("Raw TCP connection on MUX port discarded.");
                }
            }
        });
    }
}

/// Checks if an HTTP request is a WebSocket upgrade by examining typed headers.
///
/// ### Example Input / Output
///
/// **Input 1 (WebSocket Request)**:
/// ```text
/// GET /chat HTTP/1.1
/// Host: example.com
/// Upgrade: websocket
/// Connection: Upgrade
/// ```
/// **Output 1**: `true`
///
/// **Input 2 (Standard HTTP Request)**:
/// ```text
/// GET /index.html HTTP/1.1
/// Host: example.com
/// ```
/// **Output 2**: `false`
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

/// The main worker function for HTTP/1.x traffic.
/// This parses route configurations, modifies headers, selects backends,
/// and streams data bidirectionally between the client and downstream Server.
///
/// ### Example Input / Output
///
/// **Input**:
/// - `req`: Incoming HTTP Request (e.g., `GET /api/v1/users HTTP/1.1`)
/// - `_peer`: Client socket address (e.g., `192.168.1.50:54321`)
/// - `upstreams`: Global `UpstreamManager` containing backend pools.
/// - `app_config`: Current routing and server configuration.
/// - Middleware components: WAF, Cache, AI Engine, Metrics, Logger.
///
/// **Output**:
/// - `Ok(Response)`: A valid `hyper::Response` ready to be streamed to the client (e.g., `200 OK` with data or `502 Bad Gateway`).
/// - `Err(hyper::Error)`: Low-level HTTP or TCP connection errors.
async fn handle_http_request(
    mut req: Request<hyper::body::Incoming>,
    _peer: SocketAddr,
    upstreams: Arc<UpstreamManager>,
    app_config: Arc<ArcSwap<AppConfig>>,
    waf: Arc<crate::waf::WafEngine>,
    ai_engine: Arc<dyn crate::ai::AiRouter>,
    cache: Arc<AdvancedCache>,
    hook_engine: Arc<crate::scripting::HookEngine>,
    metrics: Arc<ProxyMetrics>,
    access_logger: Arc<AccessLogger>,
    geo_db: Arc<Option<crate::geo::GeoIpDatabase>>,
    geo_policy: Arc<crate::geo::GeoPolicy>,
    sticky: Arc<Option<crate::proxy::sticky::StickySessionManager>>,
    zone_limiter: Arc<crate::middleware::connlimit::ZoneLimiter>,
    captcha_manager: Arc<Option<crate::waf::bot::CaptchaManager>>,
    wasm_plugins: Arc<crate::wasm::WasmPluginManager>,
    gslb_router: Arc<Option<crate::gslb::GslbRouter>>,
    k8s_controller: Arc<Option<crate::k8s::IngressController>>,
    bandwidth: Arc<crate::telemetry::bandwidth::BandwidthTracker>,
    oidc_sessions: crate::auth::oidc::OidcSessionStore,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let app_config = app_config.load_full();

    // Path is mutable so rewrite rules can modify it before route dispatch
    let mut path = req.uri().path().to_string();

    debug!("Handling HTTP request: {}", path);
    let start_time = std::time::Instant::now();
    let method_str = req.method().to_string();
    let req_accepts_json = client_accepts_json(req.headers());
    // Generate a request-scoped trace ID for correlation across logs/errors
    let (req_trace_id, _req_span_id) = generate_trace_context_ids();

    // ── Step 0: Resolve Real Client IP ────────────────────────────────────────
    // Respects X-Forwarded-For from trusted proxies, falls back to socket peer
    let trusted_proxies = realip::TrustedProxies::from_cidrs(&app_config.trusted_proxies);
    let real_ip = realip::resolve_client_ip(&_peer, req.headers(), &trusted_proxies);
    let ip_str = real_ip.to_string();

    // ── CAPTCHA Verification Endpoint (short-circuit) ───────────────────────
    if path == "/__phalanx/captcha/verify" {
        return handle_captcha_verify_request(req, &ip_str, captcha_manager).await;
    }

    // ── Step 1: Zone-Based Connection Limiting ────────────────────────────────
    // RAII guard: releases the slot automatically on any exit path
    let _zone_guard = {
        if !zone_limiter.acquire_connection(&ip_str) {
            return Ok(error_response(
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "Server at capacity",
                &req_trace_id,
                req_accepts_json,
            ));
        }
        crate::middleware::connlimit::ConnectionGuard::new(Arc::clone(&zone_limiter), ip_str.clone())
    };

    // ── Step 2: gRPC-Web Detection ────────────────────────────────────────────
    // Must happen before into_parts() consumes the request
    let is_grpc_web_req = grpc_web::is_grpc_web(&req);
    let is_grpc_web_text = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/grpc-web-text"))
        .unwrap_or(false);

    // ── Step 2b: Wasm OnRequestHeaders ─────────────────────────────────────────
    // Execute Wasm plugins before scripting hooks; short-circuit on direct_response
    if wasm_plugins.plugin_count() > 0 {
        let wasm_req_ctx = crate::wasm::WasmRequestContext {
            method: method_str.clone(),
            path: path.clone(),
            query: req.uri().query().map(str::to_string),
            headers: req
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            body: None,
            client_ip: ip_str.clone(),
            protocol: "http/1.1".to_string(),
        };
        let result = wasm_plugins.execute_request_headers(&wasm_req_ctx);
        if let Some(direct) = result.direct_response {
            let sc = hyper::StatusCode::from_u16(direct.status_code)
                .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
            return Ok(Response::builder()
                .status(sc)
                .body(Full::new(Bytes::from(direct.body)).map_err(|never| match never {}).boxed())
                .unwrap());
        }
        if let Some(hdrs) = result.headers {
            for (k, v) in hdrs {
                if let (Ok(hk), Ok(hv)) = (
                    hyper::header::HeaderName::from_bytes(k.as_bytes()),
                    hyper::header::HeaderValue::from_str(&v),
                ) {
                    req.headers_mut().insert(hk, hv);
                }
            }
        }
    }

    // ── Step 3: PreRoute Scripting Hooks ──────────────────────────────────────
    // May rewrite path, inject headers, or short-circuit with a canned response
    if hook_engine.has_hooks(crate::scripting::HookPhase::PreRoute) {
        let hook_ctx = crate::scripting::HookContext {
            client_ip: ip_str.clone(),
            method: method_str.clone(),
            path: path.clone(),
            query: req.uri().query().map(str::to_string),
            headers: req
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            status: None,
            response_headers: Default::default(),
        };
        for result in hook_engine.execute(crate::scripting::HookPhase::PreRoute, &hook_ctx) {
            match result {
                crate::scripting::HookResult::Respond { status, body, .. } => {
                    let sc = hyper::StatusCode::from_u16(status)
                        .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
                    return Ok(Response::builder()
                        .status(sc)
                        .body(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed())
                        .unwrap());
                }
                crate::scripting::HookResult::RewritePath(new_path) => {
                    path = new_path;
                }
                crate::scripting::HookResult::SetHeaders(hdrs) => {
                    for (k, v) in hdrs {
                        if let (Ok(hk), Ok(hv)) = (
                            hyper::header::HeaderName::from_bytes(k.as_bytes()),
                            hyper::header::HeaderValue::from_str(&v),
                        ) {
                            req.headers_mut().insert(hk, hv);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // ── Step 4: WAF + Bot Detection + CAPTCHA ─────────────────────────────────
    let query = req.uri().query();
    let user_agent = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    // Capture Accept-Encoding before WAF check (needed later for compression)
    let accept_encoding = req
        .headers()
        .get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok());
    let client_accepts_gzip = compression::accepts_gzip(accept_encoding);
    let client_accepts_brotli = crate::middleware::brotli::accepts_brotli(accept_encoding);

    let waf_enabled = app_config.waf_enabled.unwrap_or(false);
    if let Some(manager) = captcha_manager.as_ref() {
        match manager.evaluate(&ip_str, user_agent.unwrap_or("")) {
            crate::waf::bot::CaptchaAction::Allow => {}
            crate::waf::bot::CaptchaAction::Block => {
                metrics
                    .waf_blocks_total
                    .with_label_values(&["captcha_bot_block"])
                    .inc();
                return Ok(empty_response(hyper::StatusCode::FORBIDDEN));
            }
            crate::waf::bot::CaptchaAction::Challenge => {
                let return_to = build_return_to(&path, query);
                return Ok(html_response(
                    hyper::StatusCode::FORBIDDEN,
                    manager.challenge_html_for(&ip_str, &return_to),
                ));
            }
        }
    }
    if waf_enabled {
        if let crate::waf::WafAction::Block(reason) = waf.inspect(&ip_str, &path, query, user_agent)
        {
            warn!("WAF blocked request from {}: {}", ip_str, reason);
            metrics.waf_blocks_total.with_label_values(&[&reason]).inc();
            return Ok(empty_response(hyper::StatusCode::FORBIDDEN));
        }
    }

    // ── Step 5: GeoIP Country Check ───────────────────────────────────────────
    // Enforces allow/deny country policy and injects X-Geo-* headers
    if let Some(ref db) = *geo_db {
        if let Some(geo_result) = db.lookup(&real_ip) {
            if !geo_policy.is_allowed(&geo_result.country_code) {
                warn!("GeoIP blocked request from {} (country: {})", ip_str, geo_result.country_code);
                return Ok(empty_response(hyper::StatusCode::FORBIDDEN));
            }
            crate::geo::inject_geo_headers(req.headers_mut(), &geo_result);
        }
    }

    // ── Step 6: gRPC-Web CORS Preflight ───────────────────────────────────────
    if *req.method() == hyper::Method::OPTIONS && is_grpc_web_req {
        return Ok(grpc_web::cors_preflight_response());
    }

    // ── Step 7: WebSocket Upgrade Detection ───────────────────────────────────
    let is_websocket = is_websocket_upgrade(&req);
    // If it's a WebSocket upgrade, we must extract the `OnUpgrade` future from the hyper request
    // before the request body is consumed and sent to the backend.
    let client_upgrade = if is_websocket {
        debug!("WebSocket upgrade detected from {}", ip_str);
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    // ── Rewrite Engine ────────────────────────────────────────────────────────
    // Apply rewrite rules for the matched route BEFORE final dispatch.
    // Supports: break (stop, forward with new URI), last (restart routing),
    //           redirect (302), permanent (301).
    'rewrite: loop {
        let mut best_match: Option<(&String, &crate::config::RouteConfig)> = None;
        let mut best_len = 0usize;
        for (r_path, r_config) in &app_config.routes {
            if path.starts_with(r_path.as_str()) && r_path.len() > best_len {
                best_match = Some((r_path, r_config));
                best_len = r_path.len();
            }
        }
        // Only run rewrite rules when a matching route has any
        if let Some((_r_path, r_config)) = best_match {
            if !r_config.rewrite_rules.is_empty() {
                let rules = match compile_rules(&r_config.rewrite_rules) {
                    Ok(rules) => rules,
                    Err(e) => {
                        error!("Invalid rewrite rule configuration: {}", e);
                        return Ok(empty_response(hyper::StatusCode::INTERNAL_SERVER_ERROR));
                    }
                };
                match apply_rewrites(&rules, &path) {
                    RewriteResult::Redirect { status, location } => {
                        debug!("Rewrite redirect {} -> {} ({})", path, location, status);
                        let mut resp = Response::new(
                            http_body_util::Empty::new()
                                .map_err(|_| unreachable!())
                                .boxed(),
                        );
                        *resp.status_mut() = status;
                        resp.headers_mut().insert(
                            hyper::header::LOCATION,
                            location.parse().unwrap_or_else(|_| "/".parse().unwrap()),
                        );
                        return Ok(resp);
                    }
                    RewriteResult::Rewritten {
                        new_uri,
                        restart_routing: true,
                    } => {
                        debug!("Rewrite (last): {} -> {}", path, new_uri);
                        path = new_uri;
                        continue 'rewrite; // restart route matching loop
                    }
                    RewriteResult::Rewritten {
                        new_uri,
                        restart_routing: false,
                    } => {
                        debug!("Rewrite (break): {} -> {}", path, new_uri);
                        path = new_uri;
                        break 'rewrite; // continue with new URI in same route
                    }
                    RewriteResult::NoMatch => {}
                }
            }
        }
        break 'rewrite;
    }

    // 1. Prefix path routing matching Nginx-like config
    // We sort routes by length descending at config load, or we find the longest matching prefix.
    // K8s Ingress routes are checked as additional pool-name overrides when no config route matches.
    let k8s_pool_override: Option<String> = if let Some(ref ctrl) = *k8s_controller {
        let host_header = req
            .headers()
            .get(hyper::header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        let k8s_routes = ctrl.get_routes_for_host(host_header);
        let mut best: Option<&crate::k8s::PhalanxRoute> = None;
        let mut best_len = 0usize;
        for kr in &k8s_routes {
            if path.starts_with(&kr.path) && kr.path.len() > best_len {
                best = Some(kr);
                best_len = kr.path.len();
            }
        }
        best.map(|kr| kr.upstream_pool.clone())
    } else {
        None
    };

    let route = {
        let mut best_match = None;
        let mut best_len = 0;
        for (r_path, r_config) in &app_config.routes {
            if path.starts_with(r_path.as_str()) && r_path.len() > best_len {
                best_match = Some((r_path, r_config));
                best_len = r_path.len();
            }
        }
        // Fallback to exactly "/" if no longest prefix found
        best_match.or_else(|| app_config.routes.get_key_value("/"))
    };

    // ── CORS Middleware ─────────────────────────────────────────────────────
    // After route matching, before auth: handle CORS preflight and response headers.
    if let Some((_r_path, r_config)) = route {
        if r_config.cors_enabled {
            let origin = req
                .headers()
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);

            let is_origin_allowed = if let Some(ref orig) = origin {
                r_config.cors_allowed_origins.is_empty()
                    || r_config.cors_allowed_origins.iter().any(|o| o == orig)
            } else {
                false
            };

            // Handle OPTIONS preflight request
            if req.method() == hyper::Method::OPTIONS && is_origin_allowed {
                let allowed_origin = if r_config.cors_allowed_origins.is_empty() {
                    "*".to_string()
                } else {
                    origin.clone().unwrap_or_default()
                };
                let methods_str = r_config.cors_allowed_methods.join(", ");
                let headers_str = r_config.cors_allowed_headers.join(", ");
                let max_age_str = r_config.cors_max_age_secs.to_string();

                let mut resp = Response::new(
                    http_body_util::Empty::new()
                        .map_err(|never| match never {})
                        .boxed(),
                );
                *resp.status_mut() = hyper::StatusCode::NO_CONTENT;
                resp.headers_mut().insert(
                    "access-control-allow-origin",
                    allowed_origin.parse().unwrap(),
                );
                resp.headers_mut().insert(
                    "access-control-allow-methods",
                    methods_str.parse().unwrap(),
                );
                resp.headers_mut().insert(
                    "access-control-allow-headers",
                    headers_str.parse().unwrap(),
                );
                resp.headers_mut().insert(
                    "access-control-max-age",
                    max_age_str.parse().unwrap(),
                );
                if r_config.cors_allow_credentials {
                    resp.headers_mut().insert(
                        "access-control-allow-credentials",
                        "true".parse().unwrap(),
                    );
                }
                return Ok(resp);
            }
        }
    }

    // ── Authentication Middleware ────────────────────────────────────────────
    // Runs after WAF+Rewrite, before backend dispatch.
    // Priority: Basic Auth → JWT → OAuth. If none configured, request passes through.
    if let Some((_r_path, r_config)) = route {
        use crate::auth::AuthResult;

        // 1. Basic Auth
        if let Some(ref realm) = r_config.auth_basic_realm {
            match crate::auth::basic::check(req.headers(), realm, &r_config.auth_basic_users) {
                AuthResult::Allowed => {}
                AuthResult::Denied(status, msg) => {
                    debug!("Basic auth denied from {}: {}", ip_str, msg);
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    resp.headers_mut().insert(
                        hyper::header::WWW_AUTHENTICATE,
                        crate::auth::basic::www_authenticate_header(realm)
                            .parse()
                            .unwrap(),
                    );
                    return Ok(resp);
                }
            }
        }
        // 2. JWT Auth
        else if let Some(ref secret) = r_config.auth_jwt_secret {
            let algorithm = r_config.auth_jwt_algorithm.as_deref().unwrap_or("HS256");
            let (result, claims) = crate::auth::jwt::check(req.headers(), secret, algorithm);
            match result {
                AuthResult::Allowed => {
                    // Inject claim headers upstream
                    if let Some(ref c) = claims {
                        for (k, v) in crate::auth::jwt::claims_to_headers(c) {
                            if let (Ok(name), Ok(val)) = (
                                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                                v.parse::<hyper::header::HeaderValue>(),
                            ) {
                                req.headers_mut().insert(name, val);
                            }
                        }
                    }
                }
                AuthResult::Denied(status, msg) => {
                    debug!("JWT auth denied from {}: {}", ip_str, msg);
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    resp.headers_mut()
                        .insert(hyper::header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
                    return Ok(resp);
                }
            }
        }
        // 3. OAuth 2.0 Introspection
        else if let Some(ref introspect_url) = r_config.auth_oauth_introspect_url {
            let client_id = r_config.auth_oauth_client_id.as_deref().unwrap_or("");
            let client_secret = r_config.auth_oauth_client_secret.as_deref().unwrap_or("");
            // Use a per-config-reload cache (simple global DashMap shared across requests)
            use std::sync::OnceLock;
            static OAUTH_CACHE: OnceLock<crate::auth::oauth::OAuthCache> = OnceLock::new();
            let cache = OAUTH_CACHE.get_or_init(crate::auth::oauth::new_cache);
            let (result, sub) = crate::auth::oauth::check(
                req.headers(),
                introspect_url,
                client_id,
                client_secret,
                cache,
            )
            .await;
            match result {
                AuthResult::Allowed => {
                    if let Some(sub_val) = sub {
                        if let Ok(val) = sub_val.parse::<hyper::header::HeaderValue>() {
                            req.headers_mut()
                                .insert(hyper::header::HeaderName::from_static("x-auth-sub"), val);
                        }
                    }
                }
                AuthResult::Denied(status, msg) => {
                    debug!("OAuth auth denied from {}: {}", ip_str, msg);
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    resp.headers_mut()
                        .insert(hyper::header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
                    return Ok(resp);
                }
            }
        }
        // 4. JWKS-based JWT Auth (dynamic public key lookup)
        else if let Some(ref jwks_uri) = r_config.auth_jwks_uri {
            use std::sync::OnceLock;
            static JWKS_MGR: OnceLock<Arc<crate::auth::jwks::JwksManager>> = OnceLock::new();
            let mgr = JWKS_MGR.get_or_init(|| Arc::new(crate::auth::jwks::JwksManager::new()));
            if let Some(token) = crate::auth::jwt::extract_bearer_token(req.headers()) {
                let parts: Vec<&str> = token.split('.').collect();
                let kid = if parts.len() >= 1 {
                    use base64::Engine;
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(parts[0])
                        .ok()
                        .and_then(|h| serde_json::from_slice::<serde_json::Value>(&h).ok())
                        .and_then(|v| v.get("kid").and_then(|k| k.as_str()).map(String::from))
                } else {
                    None
                };
                let auth_result = if let Some(kid_str) = kid {
                    match mgr.find_key(jwks_uri, &kid_str).await {
                        Some(jwk) => match crate::auth::jwks::JwksManager::decoding_key_from_jwk(&jwk) {
                            Ok((decoding_key, algo)) => {
                                use jsonwebtoken::{Validation, decode};
                                use crate::auth::jwt::Claims;
                                let mut validation = Validation::new(algo);
                                validation.validate_aud = false;
                                match decode::<Claims>(token, &decoding_key, &validation) {
                                    Ok(data) => {
                                        for (k, v) in crate::auth::jwt::claims_to_headers(&data.claims) {
                                            if let (Ok(name), Ok(val)) = (
                                                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                                                v.parse::<hyper::header::HeaderValue>(),
                                            ) {
                                                req.headers_mut().insert(name, val);
                                            }
                                        }
                                        AuthResult::Allowed
                                    }
                                    Err(_) => AuthResult::Denied(hyper::StatusCode::UNAUTHORIZED, "JWKS JWT validation failed"),
                                }
                            }
                            Err(_) => AuthResult::Denied(hyper::StatusCode::UNAUTHORIZED, "JWKS key build error"),
                        },
                        None => AuthResult::Denied(hyper::StatusCode::UNAUTHORIZED, "JWKS key not found"),
                    }
                } else {
                    AuthResult::Denied(hyper::StatusCode::UNAUTHORIZED, "Missing kid in JWT header")
                };
                if let AuthResult::Denied(status, msg) = auth_result {
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    resp.headers_mut()
                        .insert(hyper::header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
                    return Ok(resp);
                }
            } else {
                let mut resp = Response::new(
                    http_body_util::Full::new(Bytes::from("Missing Bearer token"))
                        .map_err(|_| unreachable!())
                        .boxed(),
                );
                *resp.status_mut() = hyper::StatusCode::UNAUTHORIZED;
                resp.headers_mut()
                    .insert(hyper::header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
                return Ok(resp);
            }
        }
        // 5. OIDC session check
        else if let Some(ref cookie_name) = r_config.auth_oidc_cookie_name {
            let (result, session) = crate::auth::oidc::check_session(req.headers(), cookie_name, &oidc_sessions);
            match result {
                AuthResult::Allowed => {
                    if let Some(s) = session {
                        if let Some(ref issuer) = r_config.auth_oidc_issuer {
                            if !crate::auth::oidc::session_matches_issuer(&s, issuer) {
                                let mut resp = Response::new(
                                    http_body_util::Full::new(Bytes::from(
                                        "OIDC issuer mismatch",
                                    ))
                                    .map_err(|_| unreachable!())
                                    .boxed(),
                                );
                                *resp.status_mut() = hyper::StatusCode::UNAUTHORIZED;
                                return Ok(resp);
                            }
                        }
                        if let Ok(val) = s.sub.parse::<hyper::header::HeaderValue>() {
                            req.headers_mut().insert(
                                hyper::header::HeaderName::from_static("x-auth-sub"), val);
                        }
                        if let Some(email) = s.email {
                            if let Ok(val) = email.parse::<hyper::header::HeaderValue>() {
                                req.headers_mut().insert(
                                    hyper::header::HeaderName::from_static("x-auth-email"), val);
                            }
                        }
                    }
                }
                AuthResult::Denied(status, msg) => {
                    if r_config.auth_oidc_issuer.is_some() {
                        let mut resp = Response::new(
                            http_body_util::Full::new(Bytes::from("Authentication required"))
                                .map_err(|_| unreachable!())
                                .boxed(),
                        );
                        *resp.status_mut() = status;
                        return Ok(resp);
                    }
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    return Ok(resp);
                }
            }
        }
        // 6. auth_request subrequest (nginx-style external auth)
        else if let Some(ref auth_url) = r_config.auth_request_url {
            let (result, auth_headers) =
                crate::auth::auth_request::check(req.headers(), auth_url, &method_str, &path).await;
            match result {
                AuthResult::Allowed => {
                    for (k, v) in auth_headers {
                        if let (Ok(name), Ok(val)) = (
                            hyper::header::HeaderName::from_bytes(k.as_bytes()),
                            v.parse::<hyper::header::HeaderValue>(),
                        ) {
                            req.headers_mut().insert(name, val);
                        }
                    }
                }
                AuthResult::Denied(status, msg) => {
                    debug!("auth_request denied from {}: {}", ip_str, msg);
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    return Ok(resp);
                }
            }
        }
        // 7. Global auth_request fallback (not per-route)
        else if let Some(ref auth_url) = app_config.auth_request_url {
            let (result, auth_headers) =
                crate::auth::auth_request::check(req.headers(), auth_url, &method_str, &path).await;
            match result {
                AuthResult::Allowed => {
                    for (k, v) in auth_headers {
                        if let (Ok(name), Ok(val)) = (
                            hyper::header::HeaderName::from_bytes(k.as_bytes()),
                            v.parse::<hyper::header::HeaderValue>(),
                        ) {
                            req.headers_mut().insert(name, val);
                        }
                    }
                }
                AuthResult::Denied(status, msg) => {
                    debug!("auth_request denied from {}: {}", ip_str, msg);
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    return Ok(resp);
                }
            }
        }
    }

    // ── Body Size Limit Check ────────────────────────────────────────────────
    // Enforce client_max_body_size before buffering/forwarding the request body.
    let max_body = {
        let route_limit = route.map(|(_, r)| r.client_max_body_size).unwrap_or(0);
        if route_limit > 0 { route_limit } else { app_config.client_max_body_size }
    };
    if max_body > 0 {
        if let Some(cl) = req.headers().get(hyper::header::CONTENT_LENGTH) {
            if let Ok(len) = cl.to_str().unwrap_or("0").parse::<usize>() {
                if len > max_body {
                    warn!("Request body too large from {}: {} > {} bytes", ip_str, len, max_body);
                    return Ok(empty_response(hyper::StatusCode::PAYLOAD_TOO_LARGE));
                }
            }
        }
    }

    // Route-level/body-dependent features should buffer only when needed.
    let route_has_mirror = route
        .and_then(|(_, r)| r.mirror_pool.as_ref())
        .is_some()
        || app_config.mirror_pool.is_some();
    let should_buffer_request_body = waf_enabled
        || is_grpc_web_req
        || route_has_mirror
        || app_config.ml_fraud_model_path.is_some();

    let (parts, body) = req.into_parts();
    let mirror_req_headers = parts.headers.clone();
    let mirror_req_uri = parts.uri.to_string();
    let mirror_req_method = parts.method.to_string();
    let ml_method = parts.method.as_str().to_string();
    let ml_path = parts.uri.path().to_string();
    let ml_query = parts.uri.query().map(|s| s.to_string());
    let ml_header_count = parts.headers.len();
    let ml_user_agent_len = parts
        .headers
        .get(hyper::header::USER_AGENT)
        .map(|v| v.len())
        .unwrap_or(0);

    let mut mirror_req_body = Bytes::new();
    let mut ml_body_len = 0usize;
    let mut ml_body_snippet = String::new();

    let mut req = if should_buffer_request_body {
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!("Failed to read request body: {}", e);
                return Ok(empty_response(hyper::StatusCode::BAD_REQUEST));
            }
        };
        if waf_enabled && !body_bytes.is_empty() {
            let body_text = String::from_utf8_lossy(&body_bytes);
            if let crate::waf::WafAction::Block(reason) = waf.inspect_body(&ip_str, &body_text) {
                warn!("WAF blocked request body from {}: {}", ip_str, reason);
                metrics.waf_blocks_total.with_label_values(&[&reason]).inc();
                return Ok(empty_response(hyper::StatusCode::FORBIDDEN));
            }
        }
        ml_body_len = body_bytes.len();
        ml_body_snippet = String::from_utf8_lossy(&body_bytes).chars().take(200).collect();
        mirror_req_body = body_bytes.clone();

        if is_grpc_web_req {
            let req_full = grpc_web::translate_request(Request::from_parts(parts, Full::new(body_bytes)));
            let (parts, body) = req_full.into_parts();
            Request::from_parts(parts, body.map_err(|never| match never {}).boxed())
        } else {
            Request::from_parts(
                parts,
                Full::new(body_bytes)
                    .map_err(|never| match never {})
                    .boxed(),
            )
        }
    } else {
        Request::from_parts(parts, body.map_err(|e| e).boxed())
    };

    // Dispatch request metadata to Machine Learning Fraud Engine (Async/OOB).
    // For streaming pass-through requests we intentionally avoid full buffering,
    // so body metrics are left as zero/empty.
    let ml_event = crate::waf::ml_fraud::MlEvent {
        ip: ip_str.clone(),
        method: ml_method,
        path: ml_path,
        query: ml_query,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        header_count: ml_header_count,
        user_agent_len: ml_user_agent_len,
        body_len: ml_body_len,
        body_snippet: ml_body_snippet,
    };
    waf.ml_engine.queue_inspection(ml_event);

    // Inject forwarding headers only on the outbound upstream request.
    realip::inject_forwarding_headers(req.headers_mut(), &real_ip, false);

    // Extract Host Header to fallback if no specific path match is found
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("default");
    let host_name = host.split(':').next().unwrap_or("default");

    // Select Upstream Pool Name (if upstream exists, else fallback to host_name)
    let pool_name = match route {
        Some((r_path, r)) => {
            if let Some(ref root_path) = r.root {
                // If a root directory is configured, serve static files directly!
                let res = serve_static_file(
                    r_path,
                    &path,
                    root_path.clone(),
                    &req,
                    Arc::clone(&access_logger),
                    &method_str,
                    &ip_str,
                )
                .await;
                return res;
            }

            if let Some(ref fastcgi_pass) = r.fastcgi_pass {
                let res = serve_fastcgi(
                    r_path,
                    &path,
                    fastcgi_pass.clone(),
                    req,
                    Arc::clone(&access_logger),
                    &method_str,
                    &ip_str,
                )
                .await;
                return res;
            }

            if let Some(ref uwsgi_pass) = r.uwsgi_pass {
                let res = serve_uwsgi(
                    r_path,
                    &path,
                    uwsgi_pass.clone(),
                    req,
                    Arc::clone(&access_logger),
                    &method_str,
                    &ip_str,
                )
                .await;
                return res;
            }

            r.upstream.clone().unwrap_or_else(|| host_name.to_string())
        }
        None => host_name.to_string(),
    };

    // K8s Ingress route override: if a K8s-generated route matches, prefer its pool
    let pool_name = k8s_pool_override.unwrap_or(pool_name);

    // GSLB override: if a GSLB router is configured, use the client's geo country to
    // select a geographically appropriate upstream pool instead.
    let pool_name = if let Some(ref router) = *gslb_router {
        let country_code = req
            .headers()
            .get("x-geo-country-code")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !country_code.is_empty() {
            router.route(country_code).unwrap_or(pool_name)
        } else {
            pool_name
        }
    } else {
        pool_name
    };

    // ── Resolve gzip + brotli + cache + mirror flags from matched route config ──
    let (route_gzip, route_gzip_min, route_cache, route_cache_ttl, route_brotli, route_mirror) = match route {
        Some((_, r)) => (
            r.gzip,
            r.gzip_min_length,
            r.proxy_cache,
            r.proxy_cache_valid_secs,
            r.brotli,
            r.mirror_pool.clone(),
        ),
        None => (false, 1024, false, 60, false, None),
    };
    let accepts_gzip = client_accepts_gzip && route_gzip;
    // Brotli is preferred over gzip when both client and route/global config agree
    let accepts_brotli = client_accepts_brotli && (route_brotli || app_config.brotli_enabled);
    // Mirror pool: route-level overrides global
    let mirror_pool = route_mirror.or_else(|| app_config.mirror_pool.clone());

    // ── Response Cache: lookup for GET requests ──
    let is_get = req.method() == hyper::Method::GET;
    let cache_key = if route_cache && is_get && !is_websocket {
        let ck = build_cache_key("GET", host_name, &path, req.uri().query(), &[]);
        // Check cache
        if let Some(cached) = cache.get(&ck).await {
            debug!("Cache HIT for {}", ck);
            metrics.cache_hits_total.with_label_values(&["hit"]).inc();
            let body = Full::new(cached.body)
                .map_err(|never| match never {})
                .boxed();
            let mut resp = Response::builder()
                .status(cached.status)
                .body(body)
                .unwrap();
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_str(&cached.content_type).unwrap_or_else(|_| {
                    hyper::header::HeaderValue::from_static("application/octet-stream")
                }),
            );
            resp.headers_mut().insert(
                hyper::header::HeaderName::from_static("x-phalanx-cache"),
                hyper::header::HeaderValue::from_static("HIT"),
            );
            return Ok(resp);
        }
        Some(ck)
    } else {
        // Cache miss — record the miss metric even when caching is disabled/skipped
        if route_cache && is_get && !is_websocket {
            metrics.cache_hits_total.with_label_values(&["miss"]).inc();
        }
        None
    };

    // PreUpstream hook: may add headers to the request or short-circuit before backend dispatch
    if hook_engine.has_hooks(crate::scripting::HookPhase::PreUpstream) {
        let hook_ctx = crate::scripting::HookContext {
            client_ip: ip_str.clone(),
            method: method_str.clone(),
            path: path.clone(),
            query: req.uri().query().map(str::to_string),
            headers: req
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            status: None,
            response_headers: Default::default(),
        };
        for result in hook_engine.execute(crate::scripting::HookPhase::PreUpstream, &hook_ctx) {
            match result {
                crate::scripting::HookResult::Respond { status, body, .. } => {
                    let sc = hyper::StatusCode::from_u16(status)
                        .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
                    return Ok(Response::builder()
                        .status(sc)
                        .body(
                            Full::new(Bytes::from(body))
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .unwrap());
                }
                crate::scripting::HookResult::SetHeaders(hdrs) => {
                    for (k, v) in hdrs {
                        if let (Ok(hk), Ok(hv)) = (
                            hyper::header::HeaderName::from_bytes(k.as_bytes()),
                            hyper::header::HeaderValue::from_str(&v),
                        ) {
                            req.headers_mut().insert(hk, hv);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // 2. Fetch healthy backend from pool manager, respecting sticky session preference
    let pool = upstreams
        .get_pool(pool_name.as_str())
        .or_else(|| upstreams.get_pool("default"));

    let backend = {
        let p = match &pool {
            Some(p) => p,
            None => return Ok(empty_response(hyper::StatusCode::NOT_FOUND)),
        };
        // Sticky session: look up preferred backend from request cookie
        let sticky_preferred = if let Some(ref mgr) = *sticky {
            let cookie_hdr = req
                .headers()
                .get(hyper::header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            mgr.extract_from_cookie(cookie_hdr)
                .and_then(|key| match mgr.mode() {
                    crate::proxy::sticky::StickyMode::Cookie { .. } => {
                        crate::proxy::sticky::base64_decode_addr(&key)
                    }
                    _ => mgr.lookup(&key),
                })
                .and_then(|addr| {
                    p.backends
                        .load()
                        .iter()
                        .find(|b| {
                            b.config.address == addr
                                && b.is_healthy.load(Ordering::Acquire)
                        })
                        .cloned()
                })
        } else {
            None
        };
        match sticky_preferred
            .or_else(|| p.get_next_backend(Some(&_peer.ip()), Some(Arc::clone(&ai_engine))))
        {
            Some(b) => b,
            None => return Ok(error_response(
                hyper::StatusCode::BAD_GATEWAY,
                "No healthy backends available",
                &req_trace_id,
                req_accepts_json,
            )),
        }
    };

    // 3. Request Header Injection Phase (from config)
    if let Some((_, r)) = route {
        for (k, v) in &r.add_headers {
            if let (Ok(hk), Ok(hv)) = (
                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                hyper::header::HeaderValue::from_str(v),
            ) {
                req.headers_mut().insert(hk, hv);
            }
        }
    }
    let (trace_id, span_id) = generate_trace_context_ids();
    crate::telemetry::otel::inject_trace_context(req.headers_mut(), &trace_id, &span_id, true);

    // ── Resolve timeout + retry settings: route -> global -> hardcoded defaults ──
    let connect_timeout = std::time::Duration::from_secs({
        let rt = route.map(|(_, r)| r.proxy_connect_timeout_secs).unwrap_or(0);
        if rt > 0 { rt } else if app_config.proxy_connect_timeout_secs > 0 { app_config.proxy_connect_timeout_secs } else { 10 }
    });
    let read_timeout = std::time::Duration::from_secs({
        let rt = route.map(|(_, r)| r.proxy_read_timeout_secs).unwrap_or(0);
        if rt > 0 { rt } else if app_config.proxy_read_timeout_secs > 0 { app_config.proxy_read_timeout_secs } else { 60 }
    });
    let max_retries = {
        let rt = route.map(|(_, r)| r.proxy_next_upstream_tries).unwrap_or(0);
        if rt > 0 { rt } else { app_config.proxy_next_upstream_tries }
    };
    let retry_timeout_secs = {
        let rt = route.map(|(_, r)| r.proxy_next_upstream_timeout_secs).unwrap_or(0);
        if rt > 0 { rt } else { app_config.proxy_next_upstream_timeout_secs }
    };
    let is_idempotent_method = matches!(
        req.method(),
        &hyper::Method::GET | &hyper::Method::HEAD | &hyper::Method::OPTIONS
            | &hyper::Method::PUT | &hyper::Method::DELETE
    );
    let can_retry_connect = is_idempotent_method && max_retries > 0;
    let retry_deadline = if retry_timeout_secs > 0 {
        Some(std::time::Instant::now() + std::time::Duration::from_secs(retry_timeout_secs))
    } else {
        None
    };

    // 4. Forward the request to physical backend IP (with connect + read timeouts)
    let mut current_backend = backend;
    let mut retries_left = if can_retry_connect { max_retries } else { 0u32 };
    current_backend.active_connections.fetch_add(1, Ordering::Relaxed);
    metrics.active_connections.inc();
    let Some(pool_ref) = pool.as_ref() else {
        error!("Upstream pool unexpectedly missing after backend selection");
        current_backend.active_connections.fetch_sub(1, Ordering::Relaxed);
        metrics.active_connections.dec();
        return Ok(error_response(
            hyper::StatusCode::BAD_GATEWAY,
            "Upstream pool configuration error",
            &req_trace_id,
            req_accepts_json,
        ));
    };
    let pool_ref = Arc::clone(pool_ref);

    // Establish TCP connection to backend with connect timeout + retry loop
    let stream = loop {
        let connect_result = tokio::time::timeout(
            connect_timeout,
            pool_ref.connection_pool.acquire(&current_backend.config.address),
        ).await;
        match connect_result {
            Ok(Ok(s)) => break s,
            Ok(Err(e)) => {
                error!("Failed to connect to backend {}: {}", current_backend.config.address, e);
                let phase = "connect".to_string();
                metrics.backend_errors_total
                    .with_label_values(&[&current_backend.config.address, &pool_name, &phase])
                    .inc();
                current_backend.record_failure();
            }
            Err(_elapsed) => {
                warn!("Connect timeout to backend {} after {:?}", current_backend.config.address, connect_timeout);
                let phase = "timeout".to_string();
                metrics.backend_errors_total
                    .with_label_values(&[&current_backend.config.address, &pool_name, &phase])
                    .inc();
                current_backend.record_failure();
            }
        }
        // Retry with next backend if allowed
        if retries_left > 0 {
            retries_left -= 1;
            current_backend.active_connections.fetch_sub(1, Ordering::Relaxed);
            metrics.active_connections.dec();
            if let Some(dl) = retry_deadline {
                if std::time::Instant::now() >= dl {
                    return Ok(error_response(hyper::StatusCode::GATEWAY_TIMEOUT, "Upstream retry timeout exceeded", &req_trace_id, req_accepts_json));
                }
            }
            if let Some(p) = pool.as_ref() {
                if let Some(next) = p.get_next_backend(Some(&_peer.ip()), Some(Arc::clone(&ai_engine))) {
                    warn!("Retrying connect to next upstream {} (retries left: {})", next.config.address, retries_left);
                    current_backend = next;
                    current_backend.active_connections.fetch_add(1, Ordering::Relaxed);
                    metrics.active_connections.inc();
                    continue;
                }
            }
            return Ok(error_response(hyper::StatusCode::GATEWAY_TIMEOUT, "All upstream connect attempts failed", &req_trace_id, req_accepts_json));
        }
        current_backend.active_connections.fetch_sub(1, Ordering::Relaxed);
        metrics.active_connections.dec();
        return Ok(error_response(hyper::StatusCode::GATEWAY_TIMEOUT, "Backend connect failed", &req_trace_id, req_accepts_json));
    };

    let io = TokioIo::new(stream);

    // Check if route requests HTTP/2 backend forwarding (e.g. for gRPC backends)
    let use_h2_backend = route
        .and_then(|(_, r)| r.proxy_http_version.as_deref())
        .map(|v| v == "2")
        .unwrap_or(false);

    // HTTP/2 backend path: complete early-return block.
    // HTTP/2 does not support 101 WebSocket upgrades, so we skip that handling entirely.
    if use_h2_backend {
        let (mut sender, conn) =
            match hyper::client::conn::http2::handshake(executor::TokioExecutor, io).await {
                Ok(handshake) => handshake,
                Err(e) => {
                    error!("HTTP/2 handshake failed with backend {}: {}", current_backend.config.address, e);
                    let phase = "connect".to_string();
                    metrics.backend_errors_total
                        .with_label_values(&[&current_backend.config.address, &pool_name, &phase])
                        .inc();
                    current_backend.active_connections.fetch_sub(1, Ordering::Relaxed);
                    return Ok(error_response(hyper::StatusCode::SERVICE_UNAVAILABLE, "Backend HTTP/2 handshake failed", &req_trace_id, req_accepts_json));
                }
            };
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("Backend HTTP/2 connection error: {:?}", e);
            }
        });
        let res = match tokio::time::timeout(read_timeout, sender.send_request(req)).await {
            Ok(r) => r,
            Err(_) => {
                warn!("Read timeout from backend {} after {:?}", current_backend.config.address, read_timeout);
                current_backend.record_failure();
                current_backend.active_connections.fetch_sub(1, Ordering::Relaxed);
                metrics.active_connections.dec();
                return Ok(error_response(hyper::StatusCode::GATEWAY_TIMEOUT, "Backend read timeout", &req_trace_id, req_accepts_json));
            }
        };
        current_backend.active_connections.fetch_sub(1, Ordering::Relaxed);
        metrics.active_connections.dec();
        let backend_addr = current_backend.config.address.clone();
        match res {
            Ok(response) => {
                let response = response.map(|b| b.map_err(|e: hyper::Error| e).boxed());
                return Ok(response);
            }
            Err(e) => {
                error!("HTTP/2 request to backend {} failed: {}", backend_addr, e);
                current_backend.record_failure();
                return Ok(error_response(hyper::StatusCode::BAD_GATEWAY, "Backend request failed", &req_trace_id, req_accepts_json));
            }
        }
    }

    // HTTP/1 backend path: conn stays in scope for WebSocket upgrade handling.
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(handshake) => handshake,
        Err(e) => {
            error!(
                "Handshake failed with backend {}: {}",
                current_backend.config.address, e
            );
            let phase = "connect".to_string();
            metrics
                .backend_errors_total
                .with_label_values(&[&current_backend.config.address, &pool_name, &phase])
                .inc();
            current_backend.active_connections.fetch_sub(1, Ordering::Relaxed);
            return Ok(error_response(
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "Backend handshake failed",
                &req_trace_id,
                req_accepts_json,
            ));
        }
    };

    // Send the proxy request with read timeout
    let res = match tokio::time::timeout(read_timeout, sender.send_request(req)).await {
        Ok(r) => r,
        Err(_) => {
            warn!("Read timeout from backend {} after {:?}", current_backend.config.address, read_timeout);
            current_backend.record_failure();
            current_backend.active_connections.fetch_sub(1, Ordering::Relaxed);
            metrics.active_connections.dec();
            return Ok(error_response(hyper::StatusCode::GATEWAY_TIMEOUT, "Backend read timeout", &req_trace_id, req_accepts_json));
        }
    };
    current_backend.active_connections.fetch_sub(1, Ordering::Relaxed);
    metrics.active_connections.dec();

    let backend_addr = current_backend.config.address.clone();

    match res {
        Ok(mut response) => {
            // Check if this is a 101 Switching Protocols response to our WebSocket upgrade
            let is_101 = response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS;
            if is_websocket && is_101 {
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        debug!("WebSocket backend connection error: {:?}", e);
                    }
                });
                if let Some(client_fut) = client_upgrade {
                    // Extract the backend's upgrade future from the response
                    let backend_upgrade = hyper::upgrade::on(&mut response);

                    // Spawn a background task to handle the actual byte tunneling
                    let backend_addr_clone = backend_addr.clone();
                    tokio::spawn(async move {
                        match tokio::try_join!(client_fut, backend_upgrade) {
                            Ok((client_upgraded, backend_upgraded)) => {
                                info!("WebSocket tunnel established to {}", backend_addr_clone);

                                // Turn hyper::upgrade::Upgraded back into Tokio IO streams
                                let mut client_io = TokioIo::new(client_upgraded);
                                let mut backend_io = TokioIo::new(backend_upgraded);

                                // Relay bytes bidirectionally with optional idle timeout
                                let ws_timeout = app_config.websocket_idle_timeout_secs;
                                let tunnel_result = if ws_timeout > 0 {
                                    tokio::time::timeout(
                                        std::time::Duration::from_secs(ws_timeout),
                                        crate::proxy::zero_copy::copy_bidirectional_fallback(
                                            &mut client_io,
                                            &mut backend_io,
                                        ),
                                    )
                                    .await
                                    .unwrap_or_else(|_| {
                                        debug!(
                                            "WebSocket tunnel idle timeout ({}s) to {}",
                                            ws_timeout, backend_addr_clone
                                        );
                                        Ok((0, 0))
                                    })
                                } else {
                                    crate::proxy::zero_copy::copy_bidirectional_fallback(
                                        &mut client_io,
                                        &mut backend_io,
                                    )
                                    .await
                                };
                                match tunnel_result {
                                    Ok((from_client, from_backend)) => {
                                        debug!(
                                            "WebSocket tunnel closed normally to {}, client sent {} bytes, backend sent {} bytes",
                                            backend_addr_clone, from_client, from_backend
                                        );
                                    }
                                    Err(e) => {
                                        debug!(
                                            "WebSocket tunnel error to {}: {}",
                                            backend_addr_clone, e
                                        );
                                    }
                                }
                            }
                            Err(e) => error!("WebSocket upgrade handshake failed: {}", e),
                        }
                    });
                }
                let response = response.map(|body| body.map_err(|e| e).boxed());
                return Ok(response);
            }

            // Train AI Router
            let latency = start_time.elapsed().as_millis() as u64;
            let is_error = response.status().is_server_error();
            ai_engine.update_score(&backend_addr, latency, is_error);

            // Record Prometheus metrics
            let status_code = response.status().as_u16();
            let status_str = status_code.to_string();
            metrics
                .http_requests_total
                .with_label_values(&[method_str.as_str(), status_str.as_str(), &pool_name])
                .inc();
            metrics
                .http_request_duration
                .with_label_values(&[method_str.as_str(), &pool_name])
                .observe(start_time.elapsed().as_secs_f64());

            // Per-backend metrics
            metrics
                .backend_request_duration
                .with_label_values(&[&backend_addr, &pool_name])
                .observe(start_time.elapsed().as_secs_f64());
            if response.status().is_server_error() {
                metrics
                    .backend_errors_total
                    .with_label_values(&[&backend_addr, &pool_name, &"5xx".to_string()])
                    .inc();
            }

            // HSTS header injection
            if let Some(max_age) = app_config.hsts_max_age {
                if let Ok(hv) = hyper::header::HeaderValue::from_str(
                    &format!("max-age={}", max_age),
                ) {
                    response.headers_mut().insert(
                        hyper::header::STRICT_TRANSPORT_SECURITY,
                        hv,
                    );
                }
            }

            // 5. Response Header Injection Phase (from config)
            if let Some((_, r)) = route {
                for (k, v) in &r.add_headers {
                    if let (Ok(hk), Ok(hv)) = (
                        hyper::header::HeaderName::from_bytes(k.as_bytes()),
                        hyper::header::HeaderValue::from_str(v),
                    ) {
                        response.headers_mut().insert(hk, hv);
                    }
                }

                // 5b. CORS response headers for normal (non-preflight) requests
                if r.cors_enabled {
                    // We don't have access to request headers here since `req` was consumed.
                    // Use wildcard for simple case, or first origin from allowed list.
                    let cors_origin = if r.cors_allowed_origins.is_empty() {
                        "*".to_string()
                    } else if let Some(first) = r.cors_allowed_origins.first() {
                        first.clone()
                    } else {
                        "*".to_string()
                    };
                    if let Ok(hv) = cors_origin.parse::<hyper::header::HeaderValue>() {
                        response
                            .headers_mut()
                            .insert("access-control-allow-origin", hv);
                    }
                    if r.cors_allow_credentials {
                        response.headers_mut().insert(
                            "access-control-allow-credentials",
                            "true".parse().unwrap(),
                        );
                    }
                }
            }

            // 6. Fast-Path / Zero-Copy Routing
            // If caching is bypassed AND compression is bypassed, simply pipe the raw Stream
            // back to the client natively via hyper. No buffering = 0 RAM cost for massive files!
            let content_type = response
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let should_compress = accepts_gzip && compression::is_compressible(Some(&content_type));
            let should_cache = cache_key.is_some() && status_code == 200;
            // Collect full body so we can optionally cache/compress and safely return
            // the backend socket to the keepalive pool after request completion.
            let body_bytes = match http_body_util::BodyExt::collect(response.body_mut()).await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return Ok(empty_response(hyper::StatusCode::BAD_GATEWAY));
                }
            };

            let body_len = body_bytes.len();
            let min_size = route_gzip_min.max(crate::middleware::compression::MIN_COMPRESS_SIZE);
            let should_compress = should_compress && body_len >= min_size;
            let should_brotli = accepts_brotli
                && compression::is_compressible(Some(&content_type))
                && body_len >= crate::middleware::brotli::MIN_BROTLI_SIZE;

            // ── Cache Store: cache GET 200 responses ──
            if should_cache {
                if let Some(ref ck) = cache_key {
                    cache
                        .insert(
                            ck.clone(),
                            CacheEntry {
                                status: status_code,
                                body: body_bytes.clone(),
                                content_type: content_type.clone(),
                                headers: vec![],
                                created_at: std::time::Instant::now(),
                                max_age: std::time::Duration::from_secs(route_cache_ttl),
                                stale_while_revalidate: std::time::Duration::ZERO,
                                stale_if_error: std::time::Duration::ZERO,
                            },
                        )
                        .await;
                }
            }

            // ── Traffic Mirroring: fire-and-forget copy to shadow pool ──
            if let Some(ref mp_name) = mirror_pool {
                mirror::mirror_request(
                    &mirror_req_method,
                    &mirror_req_uri,
                    mirror_req_headers,
                    mirror_req_body,
                    mp_name.clone(),
                    Arc::clone(&upstreams),
                );
            }

            // ── Compression: prefer Brotli > Gzip ──
            let (final_body, content_encoding) = if should_brotli {
                match crate::middleware::brotli::brotli_compress(&body_bytes, 6) {
                    Some(compressed) => (compressed, "br"),
                    None => (body_bytes, ""),
                }
            } else if should_compress {
                match compression::gzip_compress(&body_bytes) {
                    Some(compressed) => (compressed, "gzip"),
                    None => (body_bytes, ""),
                }
            } else {
                (body_bytes, "")
            };
            let is_compressed = !content_encoding.is_empty();

            // Build final response
            let mut final_resp = Response::builder()
                .status(status_code)
                .body(
                    Full::new(final_body)
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap();

            // Copy original headers
            for (key, value) in response.headers().iter() {
                final_resp.headers_mut().insert(key.clone(), value.clone());
            }

            if is_compressed {
                final_resp.headers_mut().insert(
                    hyper::header::CONTENT_ENCODING,
                    hyper::header::HeaderValue::from_static(content_encoding),
                );
                final_resp.headers_mut().insert(
                    hyper::header::HeaderName::from_static("vary"),
                    hyper::header::HeaderValue::from_static("Accept-Encoding"),
                );
                final_resp
                    .headers_mut()
                    .remove(hyper::header::CONTENT_LENGTH);
            }

            // gRPC-Web: rewrite response content-type back to grpc-web and add CORS headers
            if is_grpc_web_req {
                final_resp = grpc_web::translate_response(final_resp, is_grpc_web_text).await;
            }

            // Sticky session: set cookie (Cookie mode) or learn from response header (Learn mode)
            if let Some(ref mgr) = *sticky {
                match mgr.mode() {
                    crate::proxy::sticky::StickyMode::Cookie { .. } => {
                        if let Some(cookie_val) = mgr.set_cookie_header(&backend_addr) {
                            if let Ok(hv) = hyper::header::HeaderValue::from_str(&cookie_val) {
                                final_resp.headers_mut().insert(hyper::header::SET_COOKIE, hv);
                            }
                        }
                    }
                    crate::proxy::sticky::StickyMode::Learn { .. } => {
                        if let Some(session_key) =
                            mgr.extract_from_response_header(final_resp.headers())
                        {
                            mgr.learn(session_key, backend_addr.clone());
                        }
                    }
                    _ => {}
                }
            }

            // Return backend socket to keepalive pool when possible.
            match conn.without_shutdown().await {
                Ok(parts) => {
                    if parts.read_buf.is_empty() {
                        pool_ref
                            .connection_pool
                            .release(backend_addr.clone(), parts.io.into_inner())
                            .await;
                    }
                }
                Err(e) => {
                    debug!(
                        "Connection not reusable for backend {}: {}",
                        backend_addr, e
                    );
                }
            }

            // Bandwidth tracking: record bytes in/out for this protocol
            let bw_proto = if is_websocket { "ws" } else { "http1" };
            let bw_stats = bandwidth.protocol(bw_proto);
            bw_stats.inc_requests();
            bw_stats.add_out(body_len as u64);

            // Per-pool bandwidth tracking
            let pool_bw = bandwidth.pool(&pool_name);
            pool_bw.inc_requests();
            pool_bw.add_out(body_len as u64);

            // Wasm OnResponseHeaders: execute plugins on response
            if wasm_plugins.plugin_count() > 0 {
                let wasm_resp_ctx = crate::wasm::WasmResponseContext {
                    status_code,
                    headers: final_resp
                        .headers()
                        .iter()
                        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                        .collect(),
                    body: None,
                };
                let result = wasm_plugins.execute_response_headers(&wasm_resp_ctx);
                if let Some(hdrs) = result.headers {
                    for (k, v) in hdrs {
                        if let (Ok(hk), Ok(hv)) = (
                            hyper::header::HeaderName::from_bytes(k.as_bytes()),
                            hyper::header::HeaderValue::from_str(&v),
                        ) {
                            final_resp.headers_mut().insert(hk, hv);
                        }
                    }
                }
            }

            // Structured Access Log
            access_logger.log(AccessLogEntry {
                timestamp: chrono_timestamp(),
                client_ip: ip_str.clone(),
                method: method_str.clone(),
                path: path.clone(),
                status: status_code,
                latency_ms: latency,
                backend: backend_addr,
                pool: pool_name.clone(),
                bytes_sent: body_len as u64,
                referer: String::new(),
                user_agent: String::new(),
                trace_id: req_trace_id.clone(),
            });

            // Log hook: post-response auditing (fire-and-forget, non-blocking)
            if hook_engine.has_hooks(crate::scripting::HookPhase::Log) {
                let log_ctx = crate::scripting::HookContext {
                    client_ip: ip_str,
                    method: method_str,
                    path,
                    query: None,
                    headers: Default::default(),
                    status: Some(status_code),
                    response_headers: Default::default(),
                };
                hook_engine.execute(crate::scripting::HookPhase::Log, &log_ctx);
            }

            Ok(final_resp)
        }
        Err(e) => {
            error!("Failed to proxy request to backend {}: {}", backend_addr, e);
            // Passive health check: record this failure against the backend
            current_backend.record_failure();
            metrics.backend_errors_total
                .with_label_values(&[&backend_addr, &pool_name, &"connect".to_string()])
                .inc();

            // Log the error in access log
            access_logger.log(AccessLogEntry {
                timestamp: chrono_timestamp(),
                client_ip: ip_str,
                method: method_str,
                path,
                status: 502,
                latency_ms: start_time.elapsed().as_millis() as u64,
                backend: backend_addr,
                pool: pool_name,
                bytes_sent: 0,
                referer: String::new(),
                user_agent: String::new(),
                trace_id: req_trace_id.clone(),
            });

            Ok(error_response(
                hyper::StatusCode::BAD_GATEWAY,
                "Failed to proxy request to backend",
                &req_trace_id,
                req_accepts_json,
            ))
        }
    }
}

// ── HTTP/2 Handler ──────────────────────────────────────────────────────────

/// The main worker function for HTTP/2.x and gRPC traffic.
///
/// Has full feature parity with `handle_http_request` (HTTP/1): rewrites,
/// authentication (Basic/JWT/JWKS/OAuth/OIDC/auth_request), WAF, gzip
/// compression, response caching, and access logging.
///
/// Key differences from the HTTP/1 handler:
/// - Uses `hyper::client::conn::http2::handshake` for backend connections.
/// - Detects native gRPC (`application/grpc`) and records `grpc-status` metrics.
/// - Does not support WebSocket upgrades (HTTP/2 uses different mechanisms).
/// - Does not support traffic mirroring or Brotli compression (planned).
/// - The backend HTTP/2 connection is spawned as a background task since HTTP/2
///   multiplexes streams over a single TCP connection.
async fn handle_http2_request(
    mut req: Request<hyper::body::Incoming>,
    _peer: SocketAddr,
    upstreams: Arc<UpstreamManager>,
    app_config: Arc<ArcSwap<AppConfig>>,
    waf: Arc<crate::waf::WafEngine>,
    ai_engine: Arc<dyn crate::ai::AiRouter>,
    cache: Arc<AdvancedCache>,
    hook_engine: Arc<crate::scripting::HookEngine>,
    metrics: Arc<ProxyMetrics>,
    access_logger: Arc<AccessLogger>,
    geo_db: Arc<Option<crate::geo::GeoIpDatabase>>,
    geo_policy: Arc<crate::geo::GeoPolicy>,
    sticky: Arc<Option<crate::proxy::sticky::StickySessionManager>>,
    zone_limiter: Arc<crate::middleware::connlimit::ZoneLimiter>,
    captcha_manager: Arc<Option<crate::waf::bot::CaptchaManager>>,
    wasm_plugins: Arc<crate::wasm::WasmPluginManager>,
    gslb_router: Arc<Option<crate::gslb::GslbRouter>>,
    k8s_controller: Arc<Option<crate::k8s::IngressController>>,
    bandwidth: Arc<crate::telemetry::bandwidth::BandwidthTracker>,
    oidc_sessions: crate::auth::oidc::OidcSessionStore,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let app_config = app_config.load_full();

    let mut path = req.uri().path().to_string();

    let is_grpc = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/grpc"))
        .unwrap_or(false);

    if is_grpc {
        debug!("gRPC request detected: {}", path);
    } else {
        debug!("Handling HTTP/2 request: {}", path);
    }

    let start_time = std::time::Instant::now();
    let method_str = req.method().to_string();
    let req_accepts_json = client_accepts_json(req.headers());
    let (req_trace_id, _req_span_id) = generate_trace_context_ids();

    // ── Step 0: Real IP resolution (parity with HTTP/1) ──
    let trusted_proxies = realip::TrustedProxies::from_cidrs(&app_config.trusted_proxies);
    let real_ip = realip::resolve_client_ip(&_peer, req.headers(), &trusted_proxies);
    let ip_str = real_ip.to_string();

    if path == "/__phalanx/captcha/verify" {
        return handle_captcha_verify_request(req, &ip_str, captcha_manager).await;
    }

    // ── Step 1: Zone-Based Connection Limiting ──
    let _zone_guard = {
        if !zone_limiter.acquire_connection(&ip_str) {
            return Ok(empty_response(hyper::StatusCode::SERVICE_UNAVAILABLE));
        }
        crate::middleware::connlimit::ConnectionGuard::new(Arc::clone(&zone_limiter), ip_str.clone())
    };

    let query_str = req.uri().query().map(str::to_string);
    let user_agent_str = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let accept_encoding_str = req
        .headers()
        .get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let client_accepts_gzip = compression::accepts_gzip(accept_encoding_str.as_deref());
    let client_accepts_brotli = crate::middleware::brotli::accepts_brotli(accept_encoding_str.as_deref());

    // ── Step 2: Wasm OnRequestHeaders ──
    if wasm_plugins.plugin_count() > 0 {
        let wasm_req_ctx = crate::wasm::WasmRequestContext {
            method: method_str.clone(),
            path: path.clone(),
            query: query_str.clone(),
            headers: req
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            body: None,
            client_ip: ip_str.clone(),
            protocol: if is_grpc { "grpc".to_string() } else { "h2".to_string() },
        };
        let result = wasm_plugins.execute_request_headers(&wasm_req_ctx);
        if let Some(direct) = result.direct_response {
            let sc = hyper::StatusCode::from_u16(direct.status_code)
                .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
            return Ok(Response::builder()
                .status(sc)
                .body(Full::new(Bytes::from(direct.body)).map_err(|never| match never {}).boxed())
                .unwrap());
        }
        if let Some(hdrs) = result.headers {
            for (k, v) in hdrs {
                if let (Ok(hk), Ok(hv)) = (
                    hyper::header::HeaderName::from_bytes(k.as_bytes()),
                    hyper::header::HeaderValue::from_str(&v),
                ) {
                    req.headers_mut().insert(hk, hv);
                }
            }
        }
    }

    // ── Step 3: PreRoute Hooks ──
    if hook_engine.has_hooks(crate::scripting::HookPhase::PreRoute) {
        let hook_ctx = crate::scripting::HookContext {
            client_ip: ip_str.clone(),
            method: method_str.clone(),
            path: path.clone(),
            query: req.uri().query().map(str::to_string),
            headers: req
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            status: None,
            response_headers: Default::default(),
        };
        for result in hook_engine.execute(crate::scripting::HookPhase::PreRoute, &hook_ctx) {
            match result {
                crate::scripting::HookResult::Respond { status, body, .. } => {
                    let sc = hyper::StatusCode::from_u16(status)
                        .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
                    return Ok(Response::builder()
                        .status(sc)
                        .body(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed())
                        .unwrap());
                }
                crate::scripting::HookResult::RewritePath(new_path) => {
                    path = new_path;
                }
                crate::scripting::HookResult::SetHeaders(hdrs) => {
                    for (k, v) in hdrs {
                        if let (Ok(hk), Ok(hv)) = (
                            hyper::header::HeaderName::from_bytes(k.as_bytes()),
                            hyper::header::HeaderValue::from_str(&v),
                        ) {
                            req.headers_mut().insert(hk, hv);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // ── Step 4: WAF + CAPTCHA ──
    let waf_enabled = app_config.waf_enabled.unwrap_or(false);
    if let Some(manager) = captcha_manager.as_ref() {
        match manager.evaluate(&ip_str, user_agent_str.as_deref().unwrap_or("")) {
            crate::waf::bot::CaptchaAction::Allow => {}
            crate::waf::bot::CaptchaAction::Block => {
                metrics
                    .waf_blocks_total
                    .with_label_values(&["captcha_bot_block"])
                    .inc();
                return Ok(empty_response(hyper::StatusCode::FORBIDDEN));
            }
            crate::waf::bot::CaptchaAction::Challenge => {
                let return_to = build_return_to(&path, query_str.as_deref());
                return Ok(html_response(
                    hyper::StatusCode::FORBIDDEN,
                    manager.challenge_html_for(&ip_str, &return_to),
                ));
            }
        }
    }
    if waf_enabled {
        if let crate::waf::WafAction::Block(reason) = waf.inspect(&ip_str, &path, query_str.as_deref(), user_agent_str.as_deref())
        {
            warn!("WAF blocked HTTP/2 request from {}: {}", ip_str, reason);
            metrics.waf_blocks_total.with_label_values(&[&reason]).inc();
            return Ok(empty_response(hyper::StatusCode::FORBIDDEN));
        }
    }

    // ── Step 5: GeoIP Country Check ──
    if let Some(ref db) = *geo_db {
        if let Some(geo_result) = db.lookup(&real_ip) {
            if !geo_policy.is_allowed(&geo_result.country_code) {
                warn!("GeoIP blocked HTTP/2 request from {} (country: {})", ip_str, geo_result.country_code);
                return Ok(empty_response(hyper::StatusCode::FORBIDDEN));
            }
            crate::geo::inject_geo_headers(req.headers_mut(), &geo_result);
        }
    }

    // ── Rewrite Engine (parity with HTTP/1) ──
    'rewrite: loop {
        let mut best_match: Option<(&String, &crate::config::RouteConfig)> = None;
        let mut best_len = 0usize;
        for (r_path, r_config) in &app_config.routes {
            if path.starts_with(r_path.as_str()) && r_path.len() > best_len {
                best_match = Some((r_path, r_config));
                best_len = r_path.len();
            }
        }
        if let Some((_r_path, r_config)) = best_match {
            if !r_config.rewrite_rules.is_empty() {
                let rules = match compile_rules(&r_config.rewrite_rules) {
                    Ok(rules) => rules,
                    Err(e) => {
                        error!("Invalid rewrite rule configuration: {}", e);
                        return Ok(empty_response(hyper::StatusCode::INTERNAL_SERVER_ERROR));
                    }
                };
                match apply_rewrites(&rules, &path) {
                    RewriteResult::Redirect { status, location } => {
                        let mut resp = Response::new(
                            http_body_util::Empty::new()
                                .map_err(|_| unreachable!())
                                .boxed(),
                        );
                        *resp.status_mut() = status;
                        resp.headers_mut().insert(
                            hyper::header::LOCATION,
                            location.parse().unwrap_or_else(|_| "/".parse().unwrap()),
                        );
                        return Ok(resp);
                    }
                    RewriteResult::Rewritten {
                        new_uri,
                        restart_routing: true,
                    } => {
                        path = new_uri;
                        continue 'rewrite;
                    }
                    RewriteResult::Rewritten {
                        new_uri,
                        restart_routing: false,
                    } => {
                        path = new_uri;
                        break 'rewrite;
                    }
                    RewriteResult::NoMatch => {}
                }
            }
        }
        break 'rewrite;
    }

    // 1. Prefix path routing (with K8s Ingress route fallback)
    let k8s_pool_override: Option<String> = if let Some(ref ctrl) = *k8s_controller {
        let host_header = req
            .headers()
            .get(hyper::header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        let k8s_routes = ctrl.get_routes_for_host(host_header);
        let mut best: Option<&crate::k8s::PhalanxRoute> = None;
        let mut best_len = 0usize;
        for kr in &k8s_routes {
            if path.starts_with(&kr.path) && kr.path.len() > best_len {
                best = Some(kr);
                best_len = kr.path.len();
            }
        }
        best.map(|kr| kr.upstream_pool.clone())
    } else {
        None
    };

    let route = {
        let mut best_match = None;
        let mut best_len = 0;
        for (r_path, r_config) in &app_config.routes {
            if path.starts_with(r_path) && r_path.len() > best_len {
                best_match = Some((r_path, r_config));
                best_len = r_path.len();
            }
        }
        best_match.or_else(|| app_config.routes.get_key_value("/"))
    };

    // ── CORS Middleware (parity with HTTP/1) ──
    if let Some((_r_path, r_config)) = route {
        if r_config.cors_enabled {
            let origin = req
                .headers()
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);

            let is_origin_allowed = if let Some(ref orig) = origin {
                r_config.cors_allowed_origins.is_empty()
                    || r_config.cors_allowed_origins.iter().any(|o| o == orig)
            } else {
                false
            };

            if req.method() == hyper::Method::OPTIONS && is_origin_allowed {
                let allowed_origin = if r_config.cors_allowed_origins.is_empty() {
                    "*".to_string()
                } else {
                    origin.clone().unwrap_or_default()
                };
                let methods_str = r_config.cors_allowed_methods.join(", ");
                let headers_str = r_config.cors_allowed_headers.join(", ");
                let max_age_str = r_config.cors_max_age_secs.to_string();

                let mut resp = Response::new(
                    http_body_util::Empty::new()
                        .map_err(|never| match never {})
                        .boxed(),
                );
                *resp.status_mut() = hyper::StatusCode::NO_CONTENT;
                resp.headers_mut().insert(
                    "access-control-allow-origin",
                    allowed_origin.parse().unwrap(),
                );
                resp.headers_mut().insert(
                    "access-control-allow-methods",
                    methods_str.parse().unwrap(),
                );
                resp.headers_mut().insert(
                    "access-control-allow-headers",
                    headers_str.parse().unwrap(),
                );
                resp.headers_mut().insert(
                    "access-control-max-age",
                    max_age_str.parse().unwrap(),
                );
                if r_config.cors_allow_credentials {
                    resp.headers_mut().insert(
                        "access-control-allow-credentials",
                        "true".parse().unwrap(),
                    );
                }
                return Ok(resp);
            }
        }
    }

    // ── Authentication Middleware (parity with HTTP/1) ──
    if let Some((_r_path, r_config)) = route {
        use crate::auth::AuthResult;

        if let Some(ref realm) = r_config.auth_basic_realm {
            match crate::auth::basic::check(req.headers(), realm, &r_config.auth_basic_users) {
                AuthResult::Allowed => {}
                AuthResult::Denied(status, msg) => {
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    resp.headers_mut().insert(
                        hyper::header::WWW_AUTHENTICATE,
                        crate::auth::basic::www_authenticate_header(realm)
                            .parse()
                            .unwrap(),
                    );
                    return Ok(resp);
                }
            }
        } else if let Some(ref secret) = r_config.auth_jwt_secret {
            let algorithm = r_config.auth_jwt_algorithm.as_deref().unwrap_or("HS256");
            let (result, claims) = crate::auth::jwt::check(req.headers(), secret, algorithm);
            match result {
                AuthResult::Allowed => {
                    if let Some(ref c) = claims {
                        for (k, v) in crate::auth::jwt::claims_to_headers(c) {
                            if let (Ok(name), Ok(val)) = (
                                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                                v.parse::<hyper::header::HeaderValue>(),
                            ) {
                                req.headers_mut().insert(name, val);
                            }
                        }
                    }
                }
                AuthResult::Denied(status, msg) => {
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    resp.headers_mut()
                        .insert(hyper::header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
                    return Ok(resp);
                }
            }
        } else if let Some(ref introspect_url) = r_config.auth_oauth_introspect_url {
            let client_id = r_config.auth_oauth_client_id.as_deref().unwrap_or("");
            let client_secret = r_config.auth_oauth_client_secret.as_deref().unwrap_or("");
            use std::sync::OnceLock;
            static OAUTH_CACHE_H2: OnceLock<crate::auth::oauth::OAuthCache> = OnceLock::new();
            let oauth_cache = OAUTH_CACHE_H2.get_or_init(crate::auth::oauth::new_cache);
            let (result, sub) = crate::auth::oauth::check(
                req.headers(),
                introspect_url,
                client_id,
                client_secret,
                oauth_cache,
            )
            .await;
            match result {
                AuthResult::Allowed => {
                    if let Some(sub_val) = sub {
                        if let Ok(val) = sub_val.parse::<hyper::header::HeaderValue>() {
                            req.headers_mut()
                                .insert(hyper::header::HeaderName::from_static("x-auth-sub"), val);
                        }
                    }
                }
                AuthResult::Denied(status, msg) => {
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    resp.headers_mut()
                        .insert(hyper::header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
                    return Ok(resp);
                }
            }
        }
        // 4. JWKS-based JWT Auth (dynamic public key lookup)
        else if let Some(ref jwks_uri) = r_config.auth_jwks_uri {
            use std::sync::OnceLock;
            static JWKS_MGR_H2: OnceLock<Arc<crate::auth::jwks::JwksManager>> = OnceLock::new();
            let mgr = JWKS_MGR_H2.get_or_init(|| Arc::new(crate::auth::jwks::JwksManager::new()));
            if let Some(token) = crate::auth::jwt::extract_bearer_token(req.headers()) {
                let parts: Vec<&str> = token.split('.').collect();
                let kid = if parts.len() >= 1 {
                    use base64::Engine;
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(parts[0])
                        .ok()
                        .and_then(|h| serde_json::from_slice::<serde_json::Value>(&h).ok())
                        .and_then(|v| v.get("kid").and_then(|k| k.as_str()).map(String::from))
                } else {
                    None
                };
                let auth_result = if let Some(kid_str) = kid {
                    match mgr.find_key(jwks_uri, &kid_str).await {
                        Some(jwk) => match crate::auth::jwks::JwksManager::decoding_key_from_jwk(&jwk) {
                            Ok((decoding_key, algo)) => {
                                use jsonwebtoken::{Validation, decode};
                                use crate::auth::jwt::Claims;
                                let mut validation = Validation::new(algo);
                                validation.validate_aud = false;
                                match decode::<Claims>(token, &decoding_key, &validation) {
                                    Ok(data) => {
                                        for (k, v) in crate::auth::jwt::claims_to_headers(&data.claims) {
                                            if let (Ok(name), Ok(val)) = (
                                                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                                                v.parse::<hyper::header::HeaderValue>(),
                                            ) {
                                                req.headers_mut().insert(name, val);
                                            }
                                        }
                                        AuthResult::Allowed
                                    }
                                    Err(_) => AuthResult::Denied(hyper::StatusCode::UNAUTHORIZED, "JWKS JWT validation failed"),
                                }
                            }
                            Err(_) => AuthResult::Denied(hyper::StatusCode::UNAUTHORIZED, "JWKS key build error"),
                        },
                        None => AuthResult::Denied(hyper::StatusCode::UNAUTHORIZED, "JWKS key not found"),
                    }
                } else {
                    AuthResult::Denied(hyper::StatusCode::UNAUTHORIZED, "Missing kid in JWT header")
                };
                if let AuthResult::Denied(status, msg) = auth_result {
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    resp.headers_mut()
                        .insert(hyper::header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
                    return Ok(resp);
                }
            } else {
                let mut resp = Response::new(
                    http_body_util::Full::new(Bytes::from("Missing Bearer token"))
                        .map_err(|_| unreachable!())
                        .boxed(),
                );
                *resp.status_mut() = hyper::StatusCode::UNAUTHORIZED;
                resp.headers_mut()
                    .insert(hyper::header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
                return Ok(resp);
            }
        }
        // 5. OIDC session check
        else if let Some(ref cookie_name) = r_config.auth_oidc_cookie_name {
            let (result, session) = crate::auth::oidc::check_session(req.headers(), cookie_name, &oidc_sessions);
            match result {
                AuthResult::Allowed => {
                    if let Some(s) = session {
                        if let Some(ref issuer) = r_config.auth_oidc_issuer {
                            if !crate::auth::oidc::session_matches_issuer(&s, issuer) {
                                let mut resp = Response::new(
                                    http_body_util::Full::new(Bytes::from(
                                        "OIDC issuer mismatch",
                                    ))
                                    .map_err(|_| unreachable!())
                                    .boxed(),
                                );
                                *resp.status_mut() = hyper::StatusCode::UNAUTHORIZED;
                                return Ok(resp);
                            }
                        }
                        if let Ok(val) = s.sub.parse::<hyper::header::HeaderValue>() {
                            req.headers_mut().insert(
                                hyper::header::HeaderName::from_static("x-auth-sub"), val);
                        }
                        if let Some(email) = s.email {
                            if let Ok(val) = email.parse::<hyper::header::HeaderValue>() {
                                req.headers_mut().insert(
                                    hyper::header::HeaderName::from_static("x-auth-email"), val);
                            }
                        }
                    }
                }
                AuthResult::Denied(status, msg) => {
                    if r_config.auth_oidc_issuer.is_some() {
                        let mut resp = Response::new(
                            http_body_util::Full::new(Bytes::from("Authentication required"))
                                .map_err(|_| unreachable!())
                                .boxed(),
                        );
                        *resp.status_mut() = status;
                        return Ok(resp);
                    }
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    return Ok(resp);
                }
            }
        }
        // 6. auth_request subrequest (nginx-style external auth)
        else if let Some(ref auth_url) = r_config.auth_request_url {
            let (result, auth_headers) =
                crate::auth::auth_request::check(req.headers(), auth_url, &method_str, &path).await;
            match result {
                AuthResult::Allowed => {
                    for (k, v) in auth_headers {
                        if let (Ok(name), Ok(val)) = (
                            hyper::header::HeaderName::from_bytes(k.as_bytes()),
                            v.parse::<hyper::header::HeaderValue>(),
                        ) {
                            req.headers_mut().insert(name, val);
                        }
                    }
                }
                AuthResult::Denied(status, msg) => {
                    debug!("auth_request denied from {}: {}", ip_str, msg);
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    return Ok(resp);
                }
            }
        }
        // 7. Global auth_request fallback
        else if let Some(ref auth_url) = app_config.auth_request_url {
            let (result, auth_headers) =
                crate::auth::auth_request::check(req.headers(), auth_url, &method_str, &path).await;
            match result {
                AuthResult::Allowed => {
                    for (k, v) in auth_headers {
                        if let (Ok(name), Ok(val)) = (
                            hyper::header::HeaderName::from_bytes(k.as_bytes()),
                            v.parse::<hyper::header::HeaderValue>(),
                        ) {
                            req.headers_mut().insert(name, val);
                        }
                    }
                }
                AuthResult::Denied(status, msg) => {
                    debug!("auth_request denied from {}: {}", ip_str, msg);
                    let mut resp = Response::new(
                        http_body_util::Full::new(Bytes::from(msg))
                            .map_err(|_| unreachable!())
                            .boxed(),
                    );
                    *resp.status_mut() = status;
                    return Ok(resp);
                }
            }
        }
    }

    // ── Body Size Limit Check (HTTP/2) ────────────────────────────────────────
    let h2_max_body = {
        let route_limit = route.map(|(_, r)| r.client_max_body_size).unwrap_or(0);
        if route_limit > 0 { route_limit } else { app_config.client_max_body_size }
    };
    if h2_max_body > 0 {
        if let Some(cl) = req.headers().get(hyper::header::CONTENT_LENGTH) {
            if let Ok(len) = cl.to_str().unwrap_or("0").parse::<usize>() {
                if len > h2_max_body {
                    warn!("HTTP/2 request body too large from {}: {} > {} bytes", ip_str, len, h2_max_body);
                    return Ok(empty_response(hyper::StatusCode::PAYLOAD_TOO_LARGE));
                }
            }
        }
    }

    let route_has_mirror = route
        .and_then(|(_, r)| r.mirror_pool.as_ref())
        .is_some()
        || app_config.mirror_pool.is_some();
    let should_buffer_request_body = waf_enabled
        || route_has_mirror
        || app_config.ml_fraud_model_path.is_some();
    let (parts, body) = req.into_parts();
    let mirror_req_headers = parts.headers.clone();
    let mirror_req_uri = parts.uri.to_string();
    let mirror_req_method = parts.method.to_string();
    let mut mirror_req_body = Bytes::new();
    let mut req = if should_buffer_request_body {
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!("Failed to read HTTP/2 request body: {}", e);
                return Ok(empty_response(hyper::StatusCode::BAD_REQUEST));
            }
        };
        if !body_bytes.is_empty() {
            let body_text = String::from_utf8_lossy(&body_bytes);
            if let crate::waf::WafAction::Block(reason) = waf.inspect_body(&ip_str, &body_text) {
                warn!(
                    "WAF blocked HTTP/2 request body from {}: {}",
                    ip_str, reason
                );
                metrics.waf_blocks_total.with_label_values(&[&reason]).inc();
                return Ok(empty_response(hyper::StatusCode::FORBIDDEN));
            }
        }
        mirror_req_body = body_bytes.clone();
        Request::from_parts(
            parts,
            Full::new(body_bytes)
                .map_err(|never| match never {})
                .boxed(),
        )
    } else {
        Request::from_parts(parts, body.map_err(|e| e).boxed())
    };

    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("default")
        .to_string();
    let host_name = host.split(':').next().unwrap_or("default").to_string();

    // ── Resolve gzip + brotli + cache + mirror flags from matched route config ──
    let (route_gzip, route_gzip_min, route_cache, route_cache_ttl, route_brotli, route_mirror) = match route {
        Some((_, r)) => (
            r.gzip,
            r.gzip_min_length,
            r.proxy_cache,
            r.proxy_cache_valid_secs,
            r.brotli,
            r.mirror_pool.clone(),
        ),
        None => (false, 1024, false, 60, false, None),
    };
    let accepts_gzip = client_accepts_gzip && route_gzip;
    let accepts_brotli = client_accepts_brotli && (route_brotli || app_config.brotli_enabled);
    // Mirror pool: route-level overrides global
    let mirror_pool = route_mirror.or_else(|| app_config.mirror_pool.clone());

    let pool_name = match route {
        Some((r_path, r)) => {
            if let Some(ref root_path) = r.root {
                let res = serve_static_file(
                    r_path,
                    &path,
                    root_path.clone(),
                    &req,
                    Arc::clone(&access_logger),
                    &method_str,
                    &ip_str,
                )
                .await;
                return res;
            }

            if let Some(ref fastcgi_pass) = r.fastcgi_pass {
                let res = serve_fastcgi(
                    r_path,
                    &path,
                    fastcgi_pass.clone(),
                    req,
                    Arc::clone(&access_logger),
                    &method_str,
                    &ip_str,
                )
                .await;
                return res;
            }

            if let Some(ref uwsgi_pass) = r.uwsgi_pass {
                let res = serve_uwsgi(
                    r_path,
                    &path,
                    uwsgi_pass.clone(),
                    req,
                    Arc::clone(&access_logger),
                    &method_str,
                    &ip_str,
                )
                .await;
                return res;
            }

            r.upstream.clone().unwrap_or_else(|| host_name.to_string())
        }
        None => host_name.to_string(),
    };

    // K8s Ingress route override
    let pool_name = k8s_pool_override.unwrap_or(pool_name);

    // GSLB override: geographic pool selection
    let pool_name = if let Some(ref router) = *gslb_router {
        let country_code = req
            .headers()
            .get("x-geo-country-code")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !country_code.is_empty() {
            router.route(country_code).unwrap_or(pool_name)
        } else {
            pool_name
        }
    } else {
        pool_name
    };

    // ── PreUpstream Hooks ──
    if hook_engine.has_hooks(crate::scripting::HookPhase::PreUpstream) {
        let hook_ctx = crate::scripting::HookContext {
            client_ip: ip_str.clone(),
            method: method_str.clone(),
            path: path.clone(),
            query: req.uri().query().map(str::to_string),
            headers: req
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            status: None,
            response_headers: Default::default(),
        };
        for result in hook_engine.execute(crate::scripting::HookPhase::PreUpstream, &hook_ctx) {
            match result {
                crate::scripting::HookResult::Respond { status, body, .. } => {
                    let sc = hyper::StatusCode::from_u16(status)
                        .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
                    return Ok(Response::builder()
                        .status(sc)
                        .body(
                            Full::new(Bytes::from(body))
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .unwrap());
                }
                crate::scripting::HookResult::SetHeaders(hdrs) => {
                    for (k, v) in hdrs {
                        if let (Ok(hk), Ok(hv)) = (
                            hyper::header::HeaderName::from_bytes(k.as_bytes()),
                            hyper::header::HeaderValue::from_str(&v),
                        ) {
                            req.headers_mut().insert(hk, hv);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // ── Response Cache: lookup for GET requests ──
    let is_get = method_str == "GET";
    let cache_key = if route_cache && is_get {
        let ck = build_cache_key("GET", &host_name, &path, req.uri().query(), &[]);
        if let Some(cached) = cache.get(&ck).await {
            debug!("H2 Cache HIT for {}", ck);
            metrics.cache_hits_total.with_label_values(&["hit"]).inc();
            let body = Full::new(cached.body)
                .map_err(|never| match never {})
                .boxed();
            let mut resp = Response::builder()
                .status(cached.status)
                .body(body)
                .unwrap();
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_str(&cached.content_type).unwrap_or_else(|_| {
                    hyper::header::HeaderValue::from_static("application/octet-stream")
                }),
            );
            resp.headers_mut().insert(
                hyper::header::HeaderName::from_static("x-phalanx-cache"),
                hyper::header::HeaderValue::from_static("HIT"),
            );
            return Ok(resp);
        }
        Some(ck)
    } else {
        None
    };

    // 2. Fetch healthy backend from pool manager, respecting sticky session preference
    let pool = upstreams
        .get_pool(pool_name.as_str())
        .or_else(|| upstreams.get_pool("default"));

    let backend = {
        let p = match &pool {
            Some(p) => p,
            None => return Ok(empty_response(hyper::StatusCode::NOT_FOUND)),
        };
        // Sticky session: look up preferred backend from request cookie
        let sticky_preferred = if let Some(ref mgr) = *sticky {
            let cookie_hdr = req
                .headers()
                .get(hyper::header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            mgr.extract_from_cookie(cookie_hdr)
                .and_then(|key| match mgr.mode() {
                    crate::proxy::sticky::StickyMode::Cookie { .. } => {
                        crate::proxy::sticky::base64_decode_addr(&key)
                    }
                    _ => mgr.lookup(&key),
                })
                .and_then(|addr| {
                    p.backends
                        .load()
                        .iter()
                        .find(|b| {
                            b.config.address == addr
                                && b.is_healthy.load(Ordering::Acquire)
                        })
                        .cloned()
                })
        } else {
            None
        };
        match sticky_preferred
            .or_else(|| p.get_next_backend(Some(&_peer.ip()), Some(Arc::clone(&ai_engine))))
        {
            Some(b) => b,
            None => return Ok(error_response(
                hyper::StatusCode::BAD_GATEWAY,
                "No healthy backends available",
                &req_trace_id,
                req_accepts_json,
            )),
        }
    };

    // 3. Request Header Injection Phase (from config) + forwarding headers
    realip::inject_forwarding_headers(req.headers_mut(), &real_ip, false);
    if let Some((_, r)) = route {
        for (k, v) in &r.add_headers {
            if let (Ok(hk), Ok(hv)) = (
                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                hyper::header::HeaderValue::from_str(v),
            ) {
                req.headers_mut().insert(hk, hv);
            }
        }
    }
    let (trace_id, span_id) = generate_trace_context_ids();
    crate::telemetry::otel::inject_trace_context(req.headers_mut(), &trace_id, &span_id, true);

    // ── Resolve timeout settings: route -> global -> hardcoded defaults ──
    let h2_connect_timeout = std::time::Duration::from_secs({
        let rt = route.map(|(_, r)| r.proxy_connect_timeout_secs).unwrap_or(0);
        if rt > 0 { rt } else if app_config.proxy_connect_timeout_secs > 0 { app_config.proxy_connect_timeout_secs } else { 10 }
    });
    let h2_read_timeout = std::time::Duration::from_secs({
        let rt = route.map(|(_, r)| r.proxy_read_timeout_secs).unwrap_or(0);
        if rt > 0 { rt } else if app_config.proxy_read_timeout_secs > 0 { app_config.proxy_read_timeout_secs } else { 60 }
    });

    // 4. Forward the request to physical backend IP (with connect + read timeouts)
    backend.active_connections.fetch_add(1, Ordering::Relaxed);
    metrics.active_connections.inc();
    let Some(pool_ref) = pool.as_ref() else {
        error!("Upstream pool unexpectedly missing after backend selection");
        backend.active_connections.fetch_sub(1, Ordering::Relaxed);
        metrics.active_connections.dec();
        return Ok(error_response(hyper::StatusCode::BAD_GATEWAY, "Upstream pool configuration error", &req_trace_id, req_accepts_json));
    };
    let pool_ref = Arc::clone(pool_ref);

    let stream = match tokio::time::timeout(h2_connect_timeout, pool_ref.connection_pool.acquire(&backend.config.address)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            error!("Failed to connect to backend {}: {}", backend.config.address, e);
            metrics.backend_errors_total.with_label_values(&[&backend.config.address, &pool_name, &"connect".to_string()]).inc();
            backend.active_connections.fetch_sub(1, Ordering::Relaxed);
            return Ok(error_response(hyper::StatusCode::SERVICE_UNAVAILABLE, "Failed to connect to backend", &req_trace_id, req_accepts_json));
        }
        Err(_) => {
            warn!("Connect timeout to backend {} after {:?}", backend.config.address, h2_connect_timeout);
            metrics.backend_errors_total.with_label_values(&[&backend.config.address, &pool_name, &"timeout".to_string()]).inc();
            backend.active_connections.fetch_sub(1, Ordering::Relaxed);
            backend.record_failure();
            return Ok(error_response(hyper::StatusCode::GATEWAY_TIMEOUT, "Backend connect timeout", &req_trace_id, req_accepts_json));
        }
    };

    let io = TokioIo::new(stream);

    let (mut sender, conn) =
        match hyper::client::conn::http2::handshake(executor::TokioExecutor, io).await {
            Ok(handshake) => handshake,
            Err(e) => {
                error!("HTTP/2 Handshake failed with backend {}: {}", backend.config.address, e);
                metrics.backend_errors_total.with_label_values(&[&backend.config.address, &pool_name, &"handshake".to_string()]).inc();
                backend.active_connections.fetch_sub(1, Ordering::Relaxed);
                return Ok(error_response(hyper::StatusCode::SERVICE_UNAVAILABLE, "HTTP/2 handshake failed with backend", &req_trace_id, req_accepts_json));
            }
        };

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("Backend HTTP/2 connection error: {:?}", e);
        }
    });

    let res = match tokio::time::timeout(h2_read_timeout, sender.send_request(req)).await {
        Ok(r) => r,
        Err(_) => {
            warn!("Read timeout from backend {} after {:?}", backend.config.address, h2_read_timeout);
            backend.record_failure();
            backend.active_connections.fetch_sub(1, Ordering::Relaxed);
            return Ok(error_response(hyper::StatusCode::GATEWAY_TIMEOUT, "Backend read timeout", &req_trace_id, req_accepts_json));
        }
    };
    backend.active_connections.fetch_sub(1, Ordering::Relaxed);

    let backend_addr = backend.config.address.clone();

    match res {
        Ok(mut response) => {
            let latency = start_time.elapsed().as_millis() as u64;
            let is_error = response.status().is_server_error();
            ai_engine.update_score(&backend_addr, latency, is_error);

            let status_code = response.status().as_u16();

            if is_grpc {
                let grpc_status = response
                    .headers()
                    .get("grpc-status")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("0");
                debug!(
                    "gRPC response: status={}, grpc-status={}",
                    status_code, grpc_status
                );
                metrics
                    .http_requests_total
                    .with_label_values(&["GRPC", grpc_status, &pool_name])
                    .inc();
            } else {
                let status_str = status_code.to_string();
                metrics
                    .http_requests_total
                    .with_label_values(&[method_str.as_str(), status_str.as_str(), &pool_name])
                    .inc();
            }
            metrics
                .http_request_duration
                .with_label_values(&[method_str.as_str(), &pool_name])
                .observe(start_time.elapsed().as_secs_f64());

            // Per-backend metrics
            metrics
                .backend_request_duration
                .with_label_values(&[&backend_addr, &pool_name])
                .observe(start_time.elapsed().as_secs_f64());
            if response.status().is_server_error() {
                metrics
                    .backend_errors_total
                    .with_label_values(&[&backend_addr, &pool_name, &"5xx".to_string()])
                    .inc();
            }

            // HSTS header injection
            if let Some(max_age) = app_config.hsts_max_age {
                if let Ok(hv) = hyper::header::HeaderValue::from_str(
                    &format!("max-age={}", max_age),
                ) {
                    response.headers_mut().insert(
                        hyper::header::STRICT_TRANSPORT_SECURITY,
                        hv,
                    );
                }
            }

            // 5. Response Header Injection Phase
            if let Some((_, r)) = route {
                for (k, v) in &r.add_headers {
                    if let (Ok(hk), Ok(hv)) = (
                        hyper::header::HeaderName::from_bytes(k.as_bytes()),
                        hyper::header::HeaderValue::from_str(v),
                    ) {
                        response.headers_mut().insert(hk, hv);
                    }
                }

                // 5b. CORS response headers (parity with HTTP/1)
                if r.cors_enabled {
                    let cors_origin = if r.cors_allowed_origins.is_empty() {
                        "*".to_string()
                    } else if let Some(first) = r.cors_allowed_origins.first() {
                        first.clone()
                    } else {
                        "*".to_string()
                    };
                    if let Ok(hv) = cors_origin.parse::<hyper::header::HeaderValue>() {
                        response
                            .headers_mut()
                            .insert("access-control-allow-origin", hv);
                    }
                    if r.cors_allow_credentials {
                        response.headers_mut().insert(
                            "access-control-allow-credentials",
                            "true".parse().unwrap(),
                        );
                    }
                }
            }

            // 6. Collect body for cache + compression
            let content_type = response
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let should_compress = accepts_gzip && compression::is_compressible(Some(&content_type));
            let should_cache = cache_key.is_some() && status_code == 200;

            let body_bytes = match http_body_util::BodyExt::collect(response.body_mut()).await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return Ok(empty_response(hyper::StatusCode::BAD_GATEWAY));
                }
            };

            let body_len = body_bytes.len();
            let should_compress = should_compress
                && body_len >= route_gzip_min.max(crate::middleware::compression::MIN_COMPRESS_SIZE);

            // ── Cache Store ──
            if should_cache {
                if let Some(ref ck) = cache_key {
                    cache
                        .insert(
                            ck.clone(),
                            CacheEntry {
                                status: status_code,
                                body: body_bytes.clone(),
                                content_type: content_type.clone(),
                                headers: vec![],
                                created_at: std::time::Instant::now(),
                                max_age: std::time::Duration::from_secs(route_cache_ttl),
                                stale_while_revalidate: std::time::Duration::ZERO,
                                stale_if_error: std::time::Duration::ZERO,
                            },
                        )
                        .await;
                }
            }

            // ── Traffic Mirroring: fire-and-forget copy to shadow pool (parity with HTTP/1) ──
            if let Some(ref mp_name) = mirror_pool {
                mirror::mirror_request(
                    &mirror_req_method,
                    &mirror_req_uri,
                    mirror_req_headers,
                    mirror_req_body,
                    mp_name.clone(),
                    Arc::clone(&upstreams),
                );
            }

            // ── Compression: prefer Brotli > Gzip (parity with HTTP/1) ──
            let should_brotli = accepts_brotli
                && compression::is_compressible(Some(&content_type))
                && body_len >= crate::middleware::brotli::MIN_BROTLI_SIZE;

            let (final_body, content_encoding) = if should_brotli {
                match crate::middleware::brotli::brotli_compress(&body_bytes, 6) {
                    Some(compressed) => (compressed, "br"),
                    None => (body_bytes, ""),
                }
            } else if should_compress {
                match compression::gzip_compress(&body_bytes) {
                    Some(compressed) => (compressed, "gzip"),
                    None => (body_bytes, ""),
                }
            } else {
                (body_bytes, "")
            };
            let is_compressed = !content_encoding.is_empty();

            let mut final_resp = Response::builder()
                .status(status_code)
                .body(
                    Full::new(final_body)
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap();

            for (key, value) in response.headers().iter() {
                final_resp.headers_mut().insert(key.clone(), value.clone());
            }

            if is_compressed {
                final_resp.headers_mut().insert(
                    hyper::header::CONTENT_ENCODING,
                    hyper::header::HeaderValue::from_static(content_encoding),
                );
                final_resp.headers_mut().insert(
                    hyper::header::HeaderName::from_static("vary"),
                    hyper::header::HeaderValue::from_static("Accept-Encoding"),
                );
                final_resp
                    .headers_mut()
                    .remove(hyper::header::CONTENT_LENGTH);
            }

            // Sticky session cookie (parity with HTTP/1)
            if let Some(ref mgr) = *sticky {
                match mgr.mode() {
                    crate::proxy::sticky::StickyMode::Cookie { .. } => {
                        if let Some(cookie_val) = mgr.set_cookie_header(&backend_addr) {
                            if let Ok(hv) = hyper::header::HeaderValue::from_str(&cookie_val) {
                                final_resp.headers_mut().insert(hyper::header::SET_COOKIE, hv);
                            }
                        }
                    }
                    crate::proxy::sticky::StickyMode::Learn { .. } => {
                        if let Some(session_key) =
                            mgr.extract_from_response_header(final_resp.headers())
                        {
                            mgr.learn(session_key, backend_addr.clone());
                        }
                    }
                    _ => {}
                }
            }

            // Bandwidth tracking
            let bw_proto = if is_grpc { "grpc" } else { "http2" };
            let bw_stats = bandwidth.protocol(bw_proto);
            bw_stats.inc_requests();
            bw_stats.add_out(body_len as u64);

            // Per-pool bandwidth tracking
            let pool_bw = bandwidth.pool(&pool_name);
            pool_bw.inc_requests();
            pool_bw.add_out(body_len as u64);

            // Wasm OnResponseHeaders
            if wasm_plugins.plugin_count() > 0 {
                let wasm_resp_ctx = crate::wasm::WasmResponseContext {
                    status_code,
                    headers: final_resp
                        .headers()
                        .iter()
                        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                        .collect(),
                    body: None,
                };
                let result = wasm_plugins.execute_response_headers(&wasm_resp_ctx);
                if let Some(hdrs) = result.headers {
                    for (k, v) in hdrs {
                        if let (Ok(hk), Ok(hv)) = (
                            hyper::header::HeaderName::from_bytes(k.as_bytes()),
                            hyper::header::HeaderValue::from_str(&v),
                        ) {
                            final_resp.headers_mut().insert(hk, hv);
                        }
                    }
                }
            }

            access_logger.log(AccessLogEntry {
                timestamp: chrono_timestamp(),
                client_ip: ip_str.clone(),
                method: if is_grpc {
                    format!("gRPC:{}", method_str)
                } else {
                    method_str.clone()
                },
                path: path.clone(),
                status: status_code,
                latency_ms: latency,
                backend: backend_addr,
                pool: pool_name.clone(),
                bytes_sent: body_len as u64,
                referer: String::new(),
                user_agent: String::new(),
                trace_id: req_trace_id.clone(),
            });

            // Log hook (parity with HTTP/1)
            if hook_engine.has_hooks(crate::scripting::HookPhase::Log) {
                let log_ctx = crate::scripting::HookContext {
                    client_ip: ip_str,
                    method: method_str,
                    path,
                    query: None,
                    headers: Default::default(),
                    status: Some(status_code),
                    response_headers: Default::default(),
                };
                hook_engine.execute(crate::scripting::HookPhase::Log, &log_ctx);
            }

            Ok(final_resp)
        }
        Err(e) => {
            error!("Failed to proxy request to backend {}: {}", backend_addr, e);
            backend.record_failure();
            metrics.backend_errors_total
                .with_label_values(&[&backend_addr, &pool_name, &"proxy".to_string()])
                .inc();

            access_logger.log(AccessLogEntry {
                timestamp: chrono_timestamp(),
                client_ip: ip_str,
                method: method_str,
                path,
                status: 502,
                latency_ms: start_time.elapsed().as_millis() as u64,
                backend: backend_addr,
                pool: pool_name,
                bytes_sent: 0,
                referer: String::new(),
                user_agent: String::new(),
                trace_id: req_trace_id.clone(),
            });

            Ok(error_response(
                hyper::StatusCode::BAD_GATEWAY,
                "Failed to proxy request to backend",
                &req_trace_id,
                req_accepts_json,
            ))
        }
    }
}

// ── OpenTelemetry Trace Context Helpers ──────────────────────────────────────

/// Generates random W3C Trace Context IDs for distributed tracing.
///
/// Returns `(trace_id, span_id)` where:
/// - `trace_id` is a 32-character hex string (128-bit random).
/// - `span_id` is a 16-character hex string (64-bit random).
///
/// These are injected into the `traceparent` header on upstream requests.
fn generate_trace_context_ids() -> (String, String) {
    let mut trace = [0u8; 16];
    let mut span = [0u8; 8];
    let mut rng = rand::rng();
    rng.fill(&mut trace);
    rng.fill(&mut span);
    let trace_id = trace.iter().map(|b| format!("{:02x}", b)).collect();
    let span_id = span.iter().map(|b| format!("{:02x}", b)).collect();
    (trace_id, span_id)
}

/// Generates an ISO-8601-ish timestamp string for access log entries.
///
/// Format: `{unix_seconds}.{milliseconds}Z` (e.g. `"1712505600.042Z"`).
/// Uses `SystemTime` rather than chrono to avoid the dependency.
pub fn chrono_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}Z", now.as_secs(), now.subsec_millis())
}

/// Safely resolves a requested path against a base directory, preventing
/// directory traversal attacks (e.g. `../../etc/passwd`).
///
/// # Algorithm
/// 1. Strip the leading `/` and query string from `requested`.
/// 2. Join with `base` to form the candidate path.
/// 3. Canonicalize (resolves symlinks and `..` segments).
/// 4. Verify the canonical path still starts with the canonical `base`.
///
/// Returns `None` if the file does not exist or the path escapes the base.
fn sanitize_path(base: &std::path::Path, requested: &str) -> Option<std::path::PathBuf> {
    // Remove leading slash and query params
    let req_path = requested
        .trim_start_matches('/')
        .split('?')
        .next()
        .unwrap_or("");
    let full_path = base.join(req_path);

    // Canonicalize to resolve symlinks and ../
    match full_path.canonicalize() {
        Ok(canon) => {
            // Ensure the canonicalized path starts with the base directory
            if canon.starts_with(base.canonicalize().unwrap_or_else(|_| base.to_path_buf())) {
                Some(canon)
            } else {
                None // Traversal attempt!
            }
        }
        Err(_) => None, // File does not exist or unreadable
    }
}

// ── Static File Server ──────────────────────────────────────────────────────

/// Serves a static file from disk, streaming it directly to the client.
///
/// Supports `GET` and `HEAD` methods only. If the path resolves to a
/// directory, it automatically tries to serve `index.html` within it.
///
/// # Arguments
///
/// * `route_path`    - The matched route prefix (stripped from `req_path`).
/// * `req_path`      - The full request URI path.
/// * `root_dir`      - Filesystem root directory for this route.
/// * `_req`          - The HTTP request (unused beyond method check).
/// * `access_logger` - Logger for structured access log entries.
/// * `method_str`    - HTTP method (`"GET"` or `"HEAD"`).
/// * `ip_str`        - Client IP address string for logging.
///
/// # Returns
///
/// 200 with streamed file body, 404 if not found, 403 for directory traversal
/// attempts, or 405 for non-GET/HEAD methods.
async fn serve_static_file<T>(
    route_path: &str,
    req_path: &str,
    root_dir: String,
    _req: &Request<T>,
    access_logger: Arc<AccessLogger>,
    method_str: &str,
    ip_str: &str,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let start_time = std::time::Instant::now();
    let base_path = std::path::Path::new(&root_dir);

    // Only allow GET or HEAD requests for static files
    if method_str != "GET" && method_str != "HEAD" {
        return Ok(empty_response(hyper::StatusCode::METHOD_NOT_ALLOWED));
    }

    // Strip the route prefix from the requested path
    // E.g. route: /static, req: /static/css/style.css -> /css/style.css
    // Or if route is /, req: /index.html -> /index.html
    let mut relative_path = req_path;
    if relative_path.starts_with(route_path) {
        relative_path = &relative_path[route_path.len()..];
    }
    if relative_path.is_empty() {
        relative_path = "/";
    }

    // Attempt to safely resolve the file path mapping
    // E.g. root: /var/www/html, rel: /css/style.css -> /var/www/html/css/style.css
    let safe_path = match sanitize_path(base_path, relative_path) {
        Some(p) => {
            if p.is_dir() {
                // Try serving index.html if it's a directory
                match sanitize_path(base_path, &format!("{}/index.html", relative_path)) {
                    Some(idx) => idx,
                    None => return Ok(empty_response(hyper::StatusCode::FORBIDDEN)),
                }
            } else {
                p
            }
        }
        None => {
            access_logger.log(AccessLogEntry {
                timestamp: chrono_timestamp(),
                client_ip: ip_str.to_string(),
                method: method_str.to_string(),
                path: req_path.to_string(),
                status: 404,
                latency_ms: start_time.elapsed().as_millis() as u64,
                backend: "static_files".to_string(),
                pool: format!("root:{}", root_dir),
                bytes_sent: 0,
                referer: String::new(),
                user_agent: String::new(),
                trace_id: String::new(),
            });
            return Ok(empty_response(hyper::StatusCode::NOT_FOUND));
        }
    };

    let file = match tokio::fs::File::open(&safe_path).await {
        Ok(f) => f,
        Err(_) => return Ok(empty_response(hyper::StatusCode::NOT_FOUND)),
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(_) => return Ok(empty_response(hyper::StatusCode::INTERNAL_SERVER_ERROR)),
    };

    let file_size = metadata.len();

    // Guess Mime type
    let mime_type = mime_guess::from_path(&safe_path)
        .first_or_octet_stream()
        .to_string();

    let latency = start_time.elapsed().as_millis() as u64;

    access_logger.log(AccessLogEntry {
        timestamp: chrono_timestamp(),
        client_ip: ip_str.to_string(),
        method: method_str.to_string(),
        path: req_path.to_string(),
        status: 200,
        latency_ms: latency,
        backend: "static_files".to_string(),
        pool: format!("root:{}", root_dir),
        bytes_sent: file_size,
        referer: String::new(),
        user_agent: String::new(),
        trace_id: String::new(),
    });

    if method_str == "HEAD" {
        let mut resp = empty_response(hyper::StatusCode::OK);
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_str(&mime_type).unwrap(),
        );
        resp.headers_mut().insert(
            hyper::header::CONTENT_LENGTH,
            hyper::header::HeaderValue::from_str(&file_size.to_string()).unwrap(),
        );
        return Ok(resp);
    }

    // Fast-path: Convert Tokio File -> ReaderStream -> StreamBody -> BoxBody
    // This allows Zero-Copy OS byte streaming straight down the socket.
    let reader_stream = tokio_util::io::ReaderStream::new(file);
    let stream = async_stream::stream! {
        let mut reader_stream = reader_stream;
        while let Some(item) = reader_stream.next().await {
            match item {
                Ok(chunk) => yield Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(chunk)),
                Err(e) => {
                    error!("Static file stream read error: {}", e);
                    break;
                }
            }
        }
    };
    let boxed_body = BodyExt::boxed(
        http_body_util::StreamBody::new(stream).map_err(|never| match never {}),
    );

    let mut response = Response::builder()
        .status(hyper::StatusCode::OK)
        .body(boxed_body)
        .unwrap();

    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_str(&mime_type).unwrap(),
    );
    response.headers_mut().insert(
        hyper::header::CONTENT_LENGTH,
        hyper::header::HeaderValue::from_str(&file_size.to_string()).unwrap(),
    );

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrono_timestamp_format() {
        let ts = chrono_timestamp();
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('.'));
        let parts: Vec<&str> = ts.trim_end_matches('Z').split('.').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].parse::<u64>().is_ok());
        assert_eq!(parts[1].len(), 3);
    }

    #[test]
    fn test_is_websocket_upgrade_true() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/ws")
            .header(hyper::header::UPGRADE, "websocket")
            .header(hyper::header::CONNECTION, "Upgrade")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn test_is_websocket_upgrade_false_no_headers() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/api")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn test_is_websocket_upgrade_false_wrong_upgrade() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header(hyper::header::UPGRADE, "h2c")
            .header(hyper::header::CONNECTION, "Upgrade")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn test_is_websocket_upgrade_case_insensitive() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/ws")
            .header(hyper::header::UPGRADE, "WebSocket")
            .header(hyper::header::CONNECTION, "upgrade")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn test_is_websocket_connection_with_multiple_values() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/ws")
            .header(hyper::header::UPGRADE, "websocket")
            .header(hyper::header::CONNECTION, "keep-alive, Upgrade")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn test_empty_response_status() {
        let resp = empty_response(hyper::StatusCode::NOT_FOUND);
        assert_eq!(resp.status(), hyper::StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_empty_response_ok() {
        let resp = empty_response(hyper::StatusCode::OK);
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }

    #[test]
    fn test_rate_limit_response_status() {
        let resp = rate_limit_response();
        assert_eq!(resp.status(), hyper::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_rate_limit_response_with_custom_retry() {
        let resp = rate_limit_response_with_retry(120);
        assert_eq!(resp.status(), hyper::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get("Retry-After").unwrap().to_str().unwrap(),
            "120"
        );
    }

    #[test]
    fn test_error_response_json() {
        let resp = error_response(
            hyper::StatusCode::BAD_GATEWAY,
            "Backend unavailable",
            "trace-123",
            true,
        );
        assert_eq!(resp.status(), hyper::StatusCode::BAD_GATEWAY);
        assert_eq!(
            resp.headers()
                .get(hyper::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_error_response_text() {
        let resp = error_response(
            hyper::StatusCode::SERVICE_UNAVAILABLE,
            "Service down",
            "trace-456",
            false,
        );
        assert_eq!(resp.status(), hyper::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get(hyper::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/plain"
        );
    }

    #[test]
    fn test_client_accepts_json_true() {
        let req = Request::builder()
            .header(hyper::header::ACCEPT, "application/json")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(client_accepts_json(req.headers()));
    }

    #[test]
    fn test_client_accepts_json_false() {
        let req = Request::builder()
            .header(hyper::header::ACCEPT, "text/html")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(!client_accepts_json(req.headers()));
    }

    #[test]
    fn test_generate_trace_context_ids_format() {
        let (trace_id, span_id) = generate_trace_context_ids();
        assert_eq!(trace_id.len(), 32, "trace_id should be 32 hex chars");
        assert_eq!(span_id.len(), 16, "span_id should be 16 hex chars");
        assert!(trace_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(span_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_trace_ids_unique() {
        let (t1, _) = generate_trace_context_ids();
        let (t2, _) = generate_trace_context_ids();
        assert_ne!(t1, t2);
    }
}
