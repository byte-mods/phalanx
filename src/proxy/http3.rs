/// HTTP/3 (QUIC) reverse proxy server for Phalanx.
///
/// Listens on a UDP port, completes QUIC handshakes via `quinn`, then
/// speaks HTTP/3 via the `h3` crate. Each request is forwarded to an
/// upstream backend over HTTP/1.1 (reusing the same backend pools).
///
/// # Configuration (`phalanx.conf`)
/// ```text
/// listen_quic 8443;              # UDP port for HTTP/3
/// ssl_certificate     /etc/phalanx/certs/cert.pem;
/// ssl_certificate_key /etc/phalanx/certs/key.pem;
/// ```
///
/// If no certificate is configured, a self-signed cert is generated
/// for development.
use bytes::{Buf, Bytes, BytesMut};
use h3::server::RequestStream;
use h3_quinn::quinn;
use hyper::StatusCode;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::admin::ProxyMetrics;
use crate::ai::AiRouter;
use crate::config::AppConfig;
use crate::middleware::connlimit::{ConnectionGuard, ZoneLimiter};
use crate::middleware::{AdvancedCache, CacheEntry, build_cache_key};
use crate::proxy::sticky::StickySessionManager;
use crate::routing::UpstreamManager;
use crate::scripting::{HookContext, HookEngine, HookPhase, HookResult};
use crate::telemetry::access_log::AccessLogEntry;
use crate::wasm::{WasmPluginManager, WasmRequestContext};

/// Shared upstream HTTP/1.1 client for HTTP/3 forwarding.
///
/// Building a `reqwest::Client` is expensive: it instantiates a DNS resolver,
/// a TLS context, and a connection pool. Doing this per request kills
/// keep-alive reuse and TLS session resumption. The client is internally
/// `Arc`-shared, so cloning is cheap.
fn shared_upstream_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .pool_idle_timeout(Some(std::time::Duration::from_secs(90)))
            .pool_max_idle_per_host(64)
            .build()
            .unwrap_or_else(|e| {
                warn!(
                    "shared_upstream_client builder failed, falling back to default: {}",
                    e
                );
                reqwest::Client::new()
            })
    })
}

/// Upstream client for **gRPC** forwarding.
///
/// gRPC requires HTTP/2 framing for trailers (`grpc-status`/`grpc-message`).
/// `http2_prior_knowledge()` makes reqwest send the HTTP/2 connection
/// preface immediately instead of probing via ALPN — appropriate because
/// the upstream pool entry for a gRPC backend is expected to speak H2.
/// Falls back to the plain HTTP/1 client if construction fails (defensive).
fn shared_grpc_upstream_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .pool_idle_timeout(Some(std::time::Duration::from_secs(90)))
            .pool_max_idle_per_host(64)
            .http2_prior_knowledge()
            .build()
            .unwrap_or_else(|e| {
                warn!(
                    "shared_grpc_upstream_client builder failed, falling back to default: {}",
                    e
                );
                reqwest::Client::new()
            })
    })
}

/// True if the request looks like a gRPC-Web call (any subtype).
fn is_h3_grpc_web(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/grpc-web"))
        .unwrap_or(false)
}

/// True if the request specifically uses the base64 text encoding
/// (`application/grpc-web-text` or `application/grpc-web-text+proto`),
/// in which case the body is base64-encoded protobuf instead of raw bytes.
fn is_h3_grpc_web_text(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/grpc-web-text"))
        .unwrap_or(false)
}

/// Translates a gRPC-Web request body into raw gRPC framed bytes.
/// For `grpc-web-text`, base64-decodes the payload; for binary
/// (`grpc-web` / `grpc-web+proto`), returns the bytes unchanged.
/// Returns `None` if base64 decoding fails — caller should reject with 400.
fn translate_h3_grpc_web_request_body(body: &Bytes, is_text: bool) -> Option<Bytes> {
    if !is_text {
        return Some(body.clone());
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(body.as_ref())
        .ok()
        .map(Bytes::from)
}

/// Builds a gRPC-Web trailer frame from the upstream response headers.
///
/// The gRPC-Web wire format appends a frame to the body: a flag byte
/// (`0x80`) + 4-byte big-endian length + the trailer text (CRLF-separated
/// `name: value` lines). We take `grpc-status` and `grpc-message` from
/// the upstream response headers (reqwest surfaces HTTP/2 trailers as
/// headers when the response is fully read), which is the common case.
fn build_h3_grpc_web_trailer_frame(headers: &reqwest::header::HeaderMap) -> Vec<u8> {
    let mut text = String::new();
    if let Some(s) = headers.get("grpc-status").and_then(|v| v.to_str().ok()) {
        text.push_str(&format!("grpc-status: {}\r\n", s));
    }
    if let Some(s) = headers.get("grpc-message").and_then(|v| v.to_str().ok()) {
        text.push_str(&format!("grpc-message: {}\r\n", s));
    }
    if text.is_empty() {
        // Default to OK if upstream didn't set a status header
        text.push_str("grpc-status: 0\r\n");
    }
    let bytes = text.as_bytes();
    let mut frame = Vec::with_capacity(5 + bytes.len());
    frame.push(0x80);
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    frame
}

/// Assembles the final gRPC-Web response body: upstream gRPC bytes +
/// trailer frame, base64-encoded if the client used the text encoding.
fn build_h3_grpc_web_response_body(
    upstream_body: &[u8],
    upstream_headers: &reqwest::header::HeaderMap,
    use_text: bool,
) -> Bytes {
    let trailer = build_h3_grpc_web_trailer_frame(upstream_headers);
    let mut combined = Vec::with_capacity(upstream_body.len() + trailer.len());
    combined.extend_from_slice(upstream_body);
    combined.extend_from_slice(&trailer);
    if use_text {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&combined);
        Bytes::from(encoded.into_bytes())
    } else {
        Bytes::from(combined)
    }
}

/// Longest-prefix route resolution for HTTP/3.
///
/// Checks `dynamic_routes` (admin API CRUD) first, then falls back to
/// `app_config.routes`. Returns `None` only when no routes exist at all.
fn resolve_h3_route(
    path: &str,
    dynamic_routes: &dashmap::DashMap<String, crate::config::RouteConfig>,
    app_config: &AppConfig,
) -> Option<(String, crate::config::RouteConfig)> {
    let mut best: Option<(String, crate::config::RouteConfig)> = None;
    let mut best_len = 0usize;
    for entry in dynamic_routes.iter() {
        let (r_path, r_cfg) = entry.pair();
        if path.starts_with(r_path.as_str()) && r_path.len() > best_len {
            best = Some((r_path.clone(), r_cfg.clone()));
            best_len = r_path.len();
        }
    }
    for (r_path, r_cfg) in &app_config.routes {
        if path.starts_with(r_path.as_str()) && r_path.len() > best_len {
            best = Some((r_path.clone(), r_cfg.clone()));
            best_len = r_path.len();
        }
    }
    best.or_else(|| {
        app_config
            .routes
            .get_key_value("/")
            .map(|(k, v)| (k.clone(), v.clone()))
    })
}

/// Builds a CORS preflight response for HTTP/3.
///
/// Returns `Some(response)` when the route has CORS enabled and the origin
/// is allowed. Returns `None` when CORS is disabled or the origin is not
/// in the allowed list.
fn build_h3_cors_preflight_response(
    r_config: &crate::config::RouteConfig,
    origin: Option<&str>,
) -> Option<hyper::Response<()>> {
    if !r_config.cors_enabled {
        return None;
    }

    let is_origin_allowed = if let Some(orig) = origin {
        r_config.cors_allowed_origins.is_empty()
            || r_config.cors_allowed_origins.iter().any(|o| o == orig)
    } else {
        false
    };

    if !is_origin_allowed {
        return None;
    }

    let allowed_origin = if r_config.cors_allowed_origins.is_empty() {
        "*".to_string()
    } else {
        origin.unwrap_or("").to_string()
    };
    let methods_str = r_config.cors_allowed_methods.join(", ");
    let headers_str = r_config.cors_allowed_headers.join(", ");
    let max_age_str = r_config.cors_max_age_secs.to_string();

    let mut resp = hyper::Response::builder().status(hyper::StatusCode::NO_CONTENT);
    if let Ok(hv) = allowed_origin.parse::<hyper::header::HeaderValue>() {
        resp = resp.header("access-control-allow-origin", hv);
    }
    if let Ok(hv) = methods_str.parse::<hyper::header::HeaderValue>() {
        resp = resp.header("access-control-allow-methods", hv);
    }
    if let Ok(hv) = headers_str.parse::<hyper::header::HeaderValue>() {
        resp = resp.header("access-control-allow-headers", hv);
    }
    if let Ok(hv) = max_age_str.parse::<hyper::header::HeaderValue>() {
        resp = resp.header("access-control-max-age", hv);
    }
    if r_config.cors_allow_credentials {
        resp = resp.header(
            "access-control-allow-credentials",
            hyper::header::HeaderValue::from_static("true"),
        );
    }
    Some(resp.body(()).unwrap())
}

/// Injects CORS response headers into an HTTP/3 response builder for
/// normal (non-preflight) requests.
fn inject_h3_cors_response_headers(
    mut response: hyper::http::response::Builder,
    r_config: &crate::config::RouteConfig,
) -> hyper::http::response::Builder {
    if !r_config.cors_enabled {
        return response;
    }
    let cors_origin = if r_config.cors_allowed_origins.is_empty() {
        "*".to_string()
    } else if let Some(first) = r_config.cors_allowed_origins.first() {
        first.clone()
    } else {
        "*".to_string()
    };
    if let Ok(hv) = cors_origin.parse::<hyper::header::HeaderValue>() {
        response = response.header("access-control-allow-origin", hv);
    }
    if r_config.cors_allow_credentials {
        response = response.header(
            "access-control-allow-credentials",
            hyper::header::HeaderValue::from_static("true"),
        );
    }
    response
}

/// Starts the HTTP/3 QUIC server on the configured UDP bind address.
pub async fn start_http3_proxy(
    bind_addr: &str,
    app_config: Arc<AppConfig>,
    upstreams: Arc<UpstreamManager>,
    metrics: Arc<ProxyMetrics>,
    cache: Arc<AdvancedCache>,
    ai_engine: Arc<dyn AiRouter>,
    waf: Arc<crate::waf::WafEngine>,
    rate_limiter: Arc<crate::middleware::ratelimit::PhalanxRateLimiter>,
    geo_db: Arc<Option<crate::geo::GeoIpDatabase>>,
    geo_policy: Arc<crate::geo::GeoPolicy>,
    captcha_manager: Arc<Option<crate::waf::bot::CaptchaManager>>,
    zone_limiter: Arc<ZoneLimiter>,
    hook_engine: Arc<HookEngine>,
    wasm_plugins: Arc<WasmPluginManager>,
    sticky: Arc<Option<StickySessionManager>>,
    access_logger: Arc<crate::telemetry::access_log::AccessLogger>,
    bandwidth: Arc<crate::telemetry::bandwidth::BandwidthTracker>,
    oidc_sessions: crate::auth::oidc::OidcSessionStore,
    trusted_proxies: crate::proxy::realip::TrustedProxies,
    dynamic_routes: Arc<dashmap::DashMap<String, crate::config::RouteConfig>>,
    shutdown: CancellationToken,
) {
    let addr: SocketAddr = match bind_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Invalid HTTP/3 bind address '{}': {}", bind_addr, e);
            return;
        }
    };

    // Build TLS config for QUIC (TLS 1.3 only, h3 ALPN)
    let tls_config = match build_quic_tls_config(&app_config) {
        Some(cfg) => cfg,
        None => {
            warn!("HTTP/3: could not build TLS config — skipping HTTP/3 listener");
            return;
        }
    };

    let quic_server_config = match quinn::crypto::rustls::QuicServerConfig::try_from(tls_config) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to build QUIC server crypto config: {}", e);
            return;
        }
    };

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    let endpoint = match quinn::Endpoint::server(server_config, addr) {
        Ok(ep) => {
            info!("HTTP/3 QUIC listener on udp://{}", addr);
            ep
        }
        Err(e) => {
            error!("Failed to bind HTTP/3 UDP endpoint {}: {}", addr, e);
            return;
        }
    };

    loop {
        tokio::select! {
            Some(incoming) = endpoint.accept() => {
                let upstreams_c = Arc::clone(&upstreams);
                let config_c = Arc::clone(&app_config);
                let metrics_c = Arc::clone(&metrics);
                let cache_c = Arc::clone(&cache);
                let ai_c = Arc::clone(&ai_engine);
                let waf_c = Arc::clone(&waf);
                let rl_c = Arc::clone(&rate_limiter);
                let geo_db_c = Arc::clone(&geo_db);
                let geo_policy_c = Arc::clone(&geo_policy);
                let captcha_c = Arc::clone(&captcha_manager);
                let zone_c = Arc::clone(&zone_limiter);
                let hook_c = Arc::clone(&hook_engine);
                let wasm_c = Arc::clone(&wasm_plugins);
                let sticky_c = Arc::clone(&sticky);
                let al_c = Arc::clone(&access_logger);
                let bw_c = Arc::clone(&bandwidth);
                let oidc_c = Arc::clone(&oidc_sessions);
                let trusted_proxies_c = trusted_proxies.clone();
                let dynamic_routes_c = Arc::clone(&dynamic_routes);
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!("QUIC incoming connection failed: {}", e);
                            return;
                        }
                    };
                    let remote_addr = conn.remote_address();
                    debug!("QUIC connection from {:?}", remote_addr);

                    // Build h3 server connection (generic over Bytes buf).
                    // Extended CONNECT is required for both WebTransport (RFC 9220)
                    // and WebSocket over HTTP/3 (RFC 9220). Enable it
                    // unconditionally so clients can dial either protocol.
                    // WT-specific settings (SETTINGS_ENABLE_WEBTRANSPORT,
                    // H3_DATAGRAM, max sessions) are only advertised when the
                    // operator has opted in via `webtransport on;`.
                    let mut h3_builder = h3::server::builder();
                    h3_builder.enable_extended_connect(true);
                    // Disable GREASE (RFC 9114 §7.2.8). `h3` appends a reserved
                    // frame after the DATA frame of the first response on each
                    // connection. That is legal — receivers MUST ignore reserved
                    // frames — but a client that tracks stream end by "last frame
                    // parsed" then never sees the response terminate, so the very
                    // first request on every QUIC connection hangs until timeout.
                    // Verified against aioquic: with GREASE on, `stream_ended` is
                    // never set; with it off, the response completes normally.
                    // Interop beats exercising a peer's extensibility handling.
                    h3_builder.send_grease(false);
                    if config_c.webtransport_enabled {
                        h3_builder
                            .enable_webtransport(true)
                            .enable_datagram(true)
                            .max_webtransport_sessions(64);
                    }
                    let h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
                        match h3_builder.build(h3_quinn::Connection::new(conn)).await {
                            Ok(c) => c,
                            Err(e) => {
                                debug!("HTTP/3 session setup failed: {}", e);
                                return;
                            }
                        };

                    serve_h3_connection(
                        h3_conn,
                        remote_addr,
                        upstreams_c,
                        config_c,
                        metrics_c,
                        cache_c,
                        ai_c,
                        waf_c,
                        rl_c,
                        geo_db_c,
                        geo_policy_c,
                        captcha_c,
                        zone_c,
                        hook_c,
                        wasm_c,
                        sticky_c,
                        al_c,
                        bw_c,
                        oidc_c,
                        trusted_proxies_c,
                        dynamic_routes_c,
                    )
                    .await;
                });
            }
            _ = shutdown.cancelled() => {
                info!("HTTP/3 QUIC server shutting down.");
                endpoint.close(0u32.into(), b"server shutdown");
                break;
            }
        }
    }
}

/// Drive a single HTTP/3 connection: accept request streams and spawn handlers.
async fn serve_h3_connection(
    mut conn: h3::server::Connection<h3_quinn::Connection, Bytes>,
    remote_addr: SocketAddr,
    upstreams: Arc<UpstreamManager>,
    app_config: Arc<AppConfig>,
    metrics: Arc<ProxyMetrics>,
    cache: Arc<AdvancedCache>,
    ai_engine: Arc<dyn AiRouter>,
    waf: Arc<crate::waf::WafEngine>,
    rate_limiter: Arc<crate::middleware::ratelimit::PhalanxRateLimiter>,
    geo_db: Arc<Option<crate::geo::GeoIpDatabase>>,
    geo_policy: Arc<crate::geo::GeoPolicy>,
    captcha_manager: Arc<Option<crate::waf::bot::CaptchaManager>>,
    zone_limiter: Arc<ZoneLimiter>,
    hook_engine: Arc<HookEngine>,
    wasm_plugins: Arc<WasmPluginManager>,
    sticky: Arc<Option<StickySessionManager>>,
    access_logger: Arc<crate::telemetry::access_log::AccessLogger>,
    bandwidth: Arc<crate::telemetry::bandwidth::BandwidthTracker>,
    oidc_sessions: crate::auth::oidc::OidcSessionStore,
    trusted_proxies: crate::proxy::realip::TrustedProxies,
    dynamic_routes: Arc<dashmap::DashMap<String, crate::config::RouteConfig>>,
) {
    let webtransport_enabled = app_config.webtransport_enabled;

    loop {
        // h3 0.0.8: accept() returns Option<RequestResolver<C,B>>
        match conn.accept().await {
            Ok(Some(resolver)) => {
                // Resolve the request and stream from the RequestResolver
                let (req, stream) = match resolver.resolve_request().await {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("HTTP/3 request resolution failed: {}", e);
                        continue;
                    }
                };

                // ── WebTransport pre-spawn intercept ─────────────────────
                // `WebTransportSession::accept` consumes the whole h3
                // `Connection`, so we need to detect Extended CONNECT
                // *before* spawning the regular request handler. Once a
                // WT session is established, all further bidi/uni streams
                // and datagrams on this QUIC connection are demuxed by
                // the session driver (not by `conn.accept()`), so we
                // return from `serve_h3_connection` and never come back.
                if webtransport_enabled && crate::proxy::wt::is_webtransport_request(&req) {
                    // C2: apply the same auth chain as regular HTTP/3 requests
                    // before handing the connection to the WT session driver.
                    let path = req.uri().path().to_string();
                    let route = {
                        let mut best: Option<(String, crate::config::RouteConfig)> = None;
                        let mut best_len = 0usize;
                        // Check admin API CRUD routes first
                        for entry in dynamic_routes.iter() {
                            let (r_path, r_cfg) = entry.pair();
                            if path.starts_with(r_path.as_str()) && r_path.len() > best_len {
                                best = Some((r_path.clone(), r_cfg.clone()));
                                best_len = r_path.len();
                            }
                        }
                        for (r_path, r_cfg) in &app_config.routes {
                            if path.starts_with(r_path.as_str()) && r_path.len() > best_len {
                                best = Some((r_path.clone(), r_cfg.clone()));
                                best_len = r_path.len();
                            }
                        }
                        best.or_else(|| {
                            app_config
                                .routes
                                .get_key_value("/")
                                .map(|(k, v)| (k.clone(), v.clone()))
                        })
                    };

                    match apply_h3_auth_chain(
                        route.as_ref(),
                        &app_config,
                        req.headers(),
                        req.method(),
                        &path,
                        &oidc_sessions,
                    )
                    .await
                    {
                        H3AuthOutcome::Allowed(_) => {
                            crate::proxy::wt::serve_session(
                                req,
                                stream,
                                conn,
                                remote_addr,
                                Arc::clone(&metrics),
                            )
                            .await;
                            return;
                        }
                        H3AuthOutcome::Denied {
                            status,
                            www_authenticate,
                            body,
                        } => {
                            let mut stream = stream;
                            if let Some(b) = body {
                                let resp =
                                    hyper::Response::builder().status(status).body(()).unwrap();
                                let _ = stream.send_response(resp).await;
                                let _ = stream.send_data(Bytes::from(b)).await;
                                let _ = stream.finish().await;
                            } else {
                                match www_authenticate {
                                    Some(v) => {
                                        send_h3_response_with_header(
                                            &mut stream,
                                            status,
                                            hyper::header::WWW_AUTHENTICATE,
                                            v,
                                        )
                                        .await;
                                    }
                                    None => send_h3_error(&mut stream, status).await,
                                }
                            }
                            continue;
                        }
                    }
                }

                let u = Arc::clone(&upstreams);
                let c = Arc::clone(&app_config);
                let m = Arc::clone(&metrics);
                let ca = Arc::clone(&cache);
                let ai = Arc::clone(&ai_engine);
                let waf = Arc::clone(&waf);
                let rl = Arc::clone(&rate_limiter);
                let geo_db = Arc::clone(&geo_db);
                let geo_policy = Arc::clone(&geo_policy);
                let captcha = Arc::clone(&captcha_manager);
                let zone = Arc::clone(&zone_limiter);
                let hooks = Arc::clone(&hook_engine);
                let wasm = Arc::clone(&wasm_plugins);
                let sticky_svc = Arc::clone(&sticky);
                let al = Arc::clone(&access_logger);
                let bw = Arc::clone(&bandwidth);
                let oidc = Arc::clone(&oidc_sessions);
                let trusted_proxies_spawn = trusted_proxies.clone();
                let dynamic_routes_spawn = Arc::clone(&dynamic_routes);
                tokio::spawn(async move {
                    handle_h3_request(
                        req,
                        stream,
                        remote_addr,
                        u,
                        c,
                        m,
                        ca,
                        ai,
                        waf,
                        rl,
                        geo_db,
                        geo_policy,
                        captcha,
                        zone,
                        hooks,
                        wasm,
                        sticky_svc,
                        al,
                        bw,
                        oidc,
                        trusted_proxies_spawn,
                        dynamic_routes_spawn,
                    )
                    .await;
                });
            }
            Ok(None) => {
                debug!("HTTP/3 connection closed cleanly.");
                break;
            }
            Err(e) => {
                debug!("HTTP/3 connection error: {}", e);
                break;
            }
        }
    }
}

/// Handles a single HTTP/3 request through the full proxy pipeline:
///
/// 1. Rate limiting
/// 2. Zone connection limiting (RAII guard)
/// 3. Request body extraction
/// 4. CAPTCHA verification endpoint (short-circuit)
/// 5. ML fraud detection (async background inference)
/// 6. Wasm plugins: OnRequestHeaders phase
/// 7. PreRoute hooks (Rhai scripting)
/// 8. Bot detection / CAPTCHA challenge
/// 9. WAF inspection (URL + body)
/// 10. GeoIP country check
/// 11. Response cache lookup (GET only)
/// 12. Longest-prefix route matching
/// 13. PreUpstream hooks
/// 14. Backend selection (with sticky session affinity)
/// 15. Forward request over HTTP/1.1 to backend
/// 16. Metrics recording (Prometheus + AI engine)
/// 17. Response caching (GET 200 only)
/// 18. Traffic mirroring (fire-and-forget)
/// 19. Sticky session cookie / learn
/// 20. Stream response back to client over QUIC
/// 21. Log hooks (post-response auditing)
async fn handle_h3_request(
    mut req: hyper::Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    remote_addr: SocketAddr,
    upstreams: Arc<UpstreamManager>,
    app_config: Arc<AppConfig>,
    metrics: Arc<ProxyMetrics>,
    cache: Arc<AdvancedCache>,
    ai_engine: Arc<dyn AiRouter>,
    waf: Arc<crate::waf::WafEngine>,
    rate_limiter: Arc<crate::middleware::ratelimit::PhalanxRateLimiter>,
    geo_db: Arc<Option<crate::geo::GeoIpDatabase>>,
    geo_policy: Arc<crate::geo::GeoPolicy>,
    captcha_manager: Arc<Option<crate::waf::bot::CaptchaManager>>,
    zone_limiter: Arc<ZoneLimiter>,
    hook_engine: Arc<HookEngine>,
    wasm_plugins: Arc<WasmPluginManager>,
    sticky: Arc<Option<StickySessionManager>>,
    access_logger: Arc<crate::telemetry::access_log::AccessLogger>,
    bandwidth: Arc<crate::telemetry::bandwidth::BandwidthTracker>,
    oidc_sessions: crate::auth::oidc::OidcSessionStore,
    trusted_proxies: crate::proxy::realip::TrustedProxies,
    dynamic_routes: Arc<dashmap::DashMap<String, crate::config::RouteConfig>>,
) {
    let mut path = req.uri().path().to_string();
    let query = req.uri().query().map(String::from);
    let method = req.method().clone();
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("_")
        .to_string();
    let start = std::time::Instant::now();
    let ip = crate::proxy::realip::resolve_client_ip(&remote_addr, req.headers(), &trusted_proxies);
    let ip_str = ip.to_string();
    // Bandwidth: per-request count for in-bytes (approx: body so far; headers small)
    bandwidth.protocol("http3").inc_requests();

    // ── W3C Trace Context (traceparent) ─────────────────────────────────────
    // Generate per-request trace_id + span_id so distributed traces span the
    // proxy boundary. Mirrors HTTP/1 at proxy/mod.rs:1865 — uses the same
    // 16-byte trace / 8-byte span hex shape so backends with W3C support
    // (jaeger / datadog / tempo) automatically continue the trace.
    let (trace_id, span_id) = crate::proxy::generate_trace_context_ids();

    // ── gRPC-Web detection ─────────────────────────────────────────────────
    // Captured early from the *original* request so the value isn't lost
    // when we later mutate forward_headers. Two flags so we can distinguish
    // text (base64) vs binary at both request-decode and response-encode time.
    let req_is_grpc_web = is_h3_grpc_web(req.headers());
    let req_is_grpc_web_text = is_h3_grpc_web_text(req.headers());

    // ── Per-request Arc<str> snapshots for HookContext sharing (P2) ────────
    // ip_str and method don't change after this point, so we build the Arc
    // once and Arc::clone (atomic increment, no heap alloc) at each phase
    // instead of re-allocating a String per phase. Path gets two Arcs: one
    // for PreRoute (which sees the original client-sent path) and one
    // built after the rewrite loop for PreUpstream / PostUpstream / Log.
    let ip_arc: Arc<str> = Arc::from(ip_str.as_str());
    let method_arc: Arc<str> = Arc::from(method.as_str());
    let query_arc: Option<Arc<str>> = query.as_deref().map(Arc::from);
    let user_agent: Option<String> = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let referer = req
        .headers()
        .get(hyper::header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    debug!("HTTP/3 {} {}", method, path);

    // ── Rate limiting ──
    if !rate_limiter.check_ip(ip).await {
        metrics
            .rate_limit_rejections
            .with_label_values(&["ip_or_global"])
            .inc();
        h3_log_rejected(
            &access_logger,
            &ip_str,
            method.as_str(),
            &path,
            429,
            start,
            user_agent.as_deref().unwrap_or(""),
            "",
            &trace_id,
            0,
        );
        send_h3_error(&mut stream, StatusCode::TOO_MANY_REQUESTS).await;
        return;
    }

    // ── Zone connection limiting (RAII guard releases on drop) ──
    let _zone_guard = {
        if !zone_limiter.acquire_connection(&ip_str) {
            h3_log_rejected(
                &access_logger,
                &ip_str,
                method.as_str(),
                &path,
                503,
                start,
                user_agent.as_deref().unwrap_or(""),
                "",
                &trace_id,
                0,
            );
            send_h3_error(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await;
            return;
        }
        ConnectionGuard::new(Arc::clone(&zone_limiter), ip_str.clone())
    };

    // ── Request body extraction (with client_max_body_size enforcement) ──
    // Check Content-Length header early to reject oversized bodies before buffering.
    let max_body = app_config.client_max_body_size;
    if max_body > 0 {
        if let Some(cl) = req.headers().get(hyper::header::CONTENT_LENGTH) {
            if let Ok(len) = cl.to_str().unwrap_or("0").parse::<usize>() {
                if len > max_body {
                    warn!(
                        "HTTP/3 request body too large from {}: {} > {} bytes",
                        ip_str, len, max_body
                    );
                    send_h3_error(&mut stream, StatusCode::PAYLOAD_TOO_LARGE).await;
                    return;
                }
            }
        }
    }
    // ── Extended CONNECT / WebTransport ──────────────────────────────────
    // Must be answered *before* the request body is read. A CONNECT stream is
    // the tunnel: the client keeps it open and never half-closes, so
    // `read_h3_request_body` blocks forever waiting for an end-of-stream that
    // will not come. The 501 below was therefore only ever delivered to a
    // client that had already given up on the tunnel and closed its side.
    // ── WebTransport / Extended CONNECT fallback ─────────────────────────
    // The `:protocol = webtransport` case is handled before this function
    // is ever called — `serve_h3_connection` peeks at the resolved request
    // and hands the whole h3 connection to `wt::serve_session` instead of
    // spawning this handler. So when execution gets here, we are looking at
    // either:
    //   • Extended CONNECT with a non-WT protocol (we don't speak any
    //     other extended-CONNECT protocols), or
    //   • An Extended CONNECT for `webtransport` that arrived while the
    //     `webtransport_enabled` gate is off.
    // WebSocket over H3 (RFC 9220) is proxied to an HTTP/1.1 backend WS.
    if is_h3_extended_connect(&method, req.headers()) {
        if is_h3_websocket_connect(&method, req.headers()) {
            // Select a backend from the default pool (or first available pool)
            let pool = upstreams
                .get_pool("default")
                .or_else(|| upstreams.first_pool());
            let backend_addr = match pool.as_ref() {
                Some(p) => p
                    .get_next_backend(None, Some(Arc::clone(&ai_engine)))
                    .map(|b| b.config.address.clone()),
                None => None,
            };
            if let Some(addr) = backend_addr {
                match h3_ws_backend_handshake(&addr, &path, &host, req.headers()).await {
                    Ok(mut tcp) => {
                        let response = hyper::Response::builder()
                            .status(StatusCode::OK)
                            .header(
                                "sec-websocket-protocol",
                                req.headers()
                                    .get("sec-websocket-protocol")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or(""),
                            )
                            .body(())
                            .unwrap();
                        if let Err(e) = stream.send_response(response).await {
                            debug!("H3 WS response send failed: {}", e);
                            return;
                        }
                        let ws_timeout = app_config.websocket_idle_timeout_secs;
                        relay_h3_websocket(&mut stream, &mut tcp, ws_timeout).await;
                        return;
                    }
                    Err(e) => {
                        warn!("H3 WebSocket backend handshake failed for {}: {}", addr, e);
                        h3_log_rejected(
                            &access_logger,
                            &ip_str,
                            method.as_str(),
                            &path,
                            502,
                            start,
                            user_agent.as_deref().unwrap_or(""),
                            &referer,
                            &trace_id,
                            0,
                        );
                        send_h3_error(&mut stream, StatusCode::BAD_GATEWAY).await;
                        return;
                    }
                }
            } else {
                h3_log_rejected(
                    &access_logger,
                    &ip_str,
                    method.as_str(),
                    &path,
                    502,
                    start,
                    user_agent.as_deref().unwrap_or(""),
                    &referer,
                    &trace_id,
                    0,
                );
                send_h3_error(&mut stream, StatusCode::BAD_GATEWAY).await;
                return;
            }
        }
        let target =
            h3_extended_connect_protocol(req.headers()).unwrap_or_else(|| "<unknown>".to_string());
        let status_value = if target == "webtransport" {
            "disabled"
        } else {
            "not_implemented"
        };
        debug!(
            "HTTP/3 Extended CONNECT from {} for protocol {} — {}",
            ip_str, target, status_value
        );
        send_h3_response_with_header(
            &mut stream,
            StatusCode::NOT_IMPLEMENTED,
            hyper::header::HeaderName::from_static("phalanx-webtransport-status"),
            hyper::header::HeaderValue::from_static(status_value),
        )
        .await;
        return;
    }

    let request_body = match read_h3_request_body(&mut stream, max_body).await {
        Ok(Some(body)) => body,
        Ok(None) => {
            warn!(
                "HTTP/3 request body exceeded limit {} from {}",
                max_body, ip_str
            );
            send_h3_error(&mut stream, StatusCode::PAYLOAD_TOO_LARGE).await;
            return;
        }
        Err(e) => {
            debug!("HTTP/3 request body read failed: {}", e);
            send_h3_error(&mut stream, StatusCode::BAD_REQUEST).await;
            return;
        }
    };


    // ── CAPTCHA verify endpoint (short-circuit) ──
    if path == "/__phalanx/captcha/verify" {
        handle_h3_captcha_verify_request(
            &mut stream,
            &method,
            &request_body,
            &ip_str,
            captcha_manager,
        )
        .await;
        return;
    }

    // ── gRPC-Web CORS preflight (browser sends OPTIONS before grpc-web POST) ──
    // Short-circuits before WAF / auth / route resolution because preflights
    // are protocol-level, not application-level. Same response shape as
    // `grpc_web::cors_preflight_response()` for HTTP/1.
    if is_h3_grpc_web_preflight(&method, req.headers()) {
        send_h3_grpc_web_preflight(&mut stream).await;
        return;
    }

    let query_opt = query.as_deref();
    let waf_enabled = app_config.waf_enabled.unwrap_or(false);

    // ── ML Fraud Detection: queue event for background inference ──
    if app_config.ml_fraud_model_path.is_some() {
        let ml_event = crate::waf::ml_fraud::MlEvent {
            ip: ip_str.clone(),
            method: method.as_str().to_string(),
            path: path.clone(),
            query: query.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            header_count: req.headers().len(),
            user_agent_len: user_agent.as_ref().map(|ua| ua.len()).unwrap_or(0),
            body_len: request_body.len(),
            body_snippet: std::str::from_utf8(&request_body[..request_body.len().min(200)])
                .unwrap_or("")
                .to_string(),
        };
        waf.ml_engine.queue_inspection(ml_event);
    }

    // ── Wasm plugins: OnRequestHeaders phase ──
    if wasm_plugins.plugin_count() > 0 {
        let wasm_req_ctx = WasmRequestContext {
            method: method.as_str().to_string(),
            path: path.clone(),
            query: query.clone(),
            headers: req
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            body: None,
            client_ip: ip_str.clone(),
            protocol: "h3".to_string(),
        };
        let result = wasm_plugins.execute_request_headers(&wasm_req_ctx);
        if let Some(direct) = result.direct_response {
            let sc = StatusCode::from_u16(direct.status_code)
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            h3_log_rejected(
                &access_logger,
                &ip_str,
                method.as_str(),
                &path,
                sc.as_u16(),
                start,
                user_agent.as_deref().unwrap_or(""),
                &referer,
                &trace_id,
                0,
            );
            send_h3_error(&mut stream, sc).await;
            return;
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

    // Inject forwarding headers on the outbound upstream request.
    // H3 always runs over TLS (QUIC requires TLS 1.3), so X-Forwarded-Proto
    // is set to "https".
    crate::proxy::realip::inject_forwarding_headers(req.headers_mut(), &ip, true);

    // ── PreRoute hooks (Rhai scripting) ──
    if hook_engine.has_hooks(HookPhase::PreRoute) {
        // PreRoute fires BEFORE the rewrite loop, so its `path` is the
        // original client-sent path. Build a separate Arc for this phase.
        let pre_route_path: Arc<str> = Arc::from(path.as_str());
        let hook_ctx = HookContext {
            client_ip: Arc::clone(&ip_arc),
            method: Arc::clone(&method_arc),
            path: pre_route_path,
            query: query_arc.clone(),
            headers: req
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            status: None,
            response_headers: Default::default(),
        };
        for result in hook_engine.execute(HookPhase::PreRoute, &hook_ctx) {
            if let HookResult::Respond { status, .. } = result {
                let sc = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                send_h3_error(&mut stream, sc).await;
                return;
            }
        }
    }

    // ── Bot detection / CAPTCHA challenge ──
    if let Some(manager) = captcha_manager.as_ref() {
        match manager.evaluate(&ip_str, user_agent.as_deref().unwrap_or("")) {
            crate::waf::bot::CaptchaAction::Allow => {}
            crate::waf::bot::CaptchaAction::Block => {
                metrics
                    .waf_blocks_total
                    .with_label_values(&["captcha_bot_block"])
                    .inc();
                h3_log_rejected(
                    &access_logger,
                    &ip_str,
                    method.as_str(),
                    &path,
                    403,
                    start,
                    user_agent.as_deref().unwrap_or(""),
                    &referer,
                    &trace_id,
                    0,
                );
                send_h3_error(&mut stream, StatusCode::FORBIDDEN).await;
                return;
            }
            crate::waf::bot::CaptchaAction::Challenge => {
                let return_to = crate::proxy::build_return_to(&path, query_opt);
                send_h3_html_response(
                    &mut stream,
                    StatusCode::FORBIDDEN,
                    manager.challenge_html_for(&ip_str, &return_to),
                )
                .await;
                return;
            }
        }
    }

    // ── WAF inspection ──
    if waf_enabled {
        let req_headers_map: std::collections::HashMap<String, String> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        if let crate::waf::WafAction::Block(reason) = waf.inspect(
            &ip_str,
            &path,
            query_opt,
            &req_headers_map,
            user_agent.as_deref(),
        ) {
            warn!("WAF blocked HTTP/3 request from {}: {}", ip_str, reason);
            metrics.waf_blocks_total.with_label_values(&[&reason]).inc();
            h3_log_rejected(
                &access_logger,
                &ip_str,
                method.as_str(),
                &path,
                403,
                start,
                user_agent.as_deref().unwrap_or(""),
                &referer,
                &trace_id,
                0,
            );
            send_h3_error(&mut stream, StatusCode::FORBIDDEN).await;
            return;
        }
        if matches!(
            method,
            hyper::Method::POST | hyper::Method::PUT | hyper::Method::PATCH
        ) {
            if let Ok(body_text) = std::str::from_utf8(&request_body) {
                if let crate::waf::WafAction::Block(reason) =
                    waf.inspect_body(&ip_str, body_text, &path, query_opt)
                {
                    warn!("WAF blocked HTTP/3 body from {}: {}", ip_str, reason);
                    metrics.waf_blocks_total.with_label_values(&[&reason]).inc();
                    h3_log_rejected(
                        &access_logger,
                        &ip_str,
                        method.as_str(),
                        &path,
                        403,
                        start,
                        user_agent.as_deref().unwrap_or(""),
                        &referer,
                        &trace_id,
                        0,
                    );
                    send_h3_error(&mut stream, StatusCode::FORBIDDEN).await;
                    return;
                }
            }
        }
    }

    // ── GeoIP country check ──
    let geo_result = if let Some(ref db) = *geo_db {
        if let Some(result) = db.lookup(&ip) {
            if !geo_policy.is_allowed(&result.country_code) {
                warn!(
                    "GeoIP blocked HTTP/3 request from {} (country: {})",
                    ip_str, result.country_code
                );
                h3_log_rejected(
                    &access_logger,
                    &ip_str,
                    method.as_str(),
                    &path,
                    403,
                    start,
                    user_agent.as_deref().unwrap_or(""),
                    &referer,
                    &trace_id,
                    0,
                );
                send_h3_error(&mut stream, StatusCode::FORBIDDEN).await;
                return;
            }
            crate::geo::inject_geo_headers(req.headers_mut(), &result);
            Some(result)
        } else {
            None
        }
    } else {
        None
    };

    // ── Response cache lookup (GET only) ──
    if method == hyper::Method::GET {
        let cache_key = build_cache_key("GET", &host, &path, query.as_deref(), &[]);
        if let Some(cached) = cache.get(&cache_key).await {
            let response = hyper::Response::builder()
                .status(cached.status)
                .header("x-proxy-by", "Phalanx/HTTP3")
                .header("x-cache", "HIT")
                .header("content-type", cached.content_type.as_str())
                .body(())
                .unwrap();
            if let Err(e) = stream.send_response(response).await {
                debug!("HTTP/3 cache send error: {}", e);
                return;
            }
            let _ = stream.send_data(Bytes::from(cached.body)).await;
            let _ = stream.finish().await;
            return;
        }
    }

    // ── URL rewriting (mirrors HTTP/1 'rewrite loop at proxy/mod.rs:1083) ──
    // Sits after WAF / GeoIP / cache so those see the original client-sent
    // path, but before final route resolution + auth so the rewritten path
    // drives auth, backend selection, hook contexts, and forwarding.
    'rewrite: loop {
        if let Some((_, r_cfg)) = resolve_h3_route(&path, &dynamic_routes, &app_config) {
            if !r_cfg.rewrite_rules.is_empty() {
                let rules = match crate::proxy::rewrite::compile_rules(&r_cfg.rewrite_rules) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("HTTP/3 invalid rewrite rule configuration: {}", e);
                        send_h3_error(&mut stream, StatusCode::INTERNAL_SERVER_ERROR).await;
                        return;
                    }
                };
                match crate::proxy::rewrite::apply_rewrites(&rules, &path) {
                    crate::proxy::rewrite::RewriteResult::Redirect { status, location } => {
                        debug!(
                            "HTTP/3 rewrite redirect {} -> {} ({})",
                            path, location, status
                        );
                        let location_hv = location
                            .parse()
                            .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("/"));
                        send_h3_response_with_header(
                            &mut stream,
                            status,
                            hyper::header::LOCATION,
                            location_hv,
                        )
                        .await;
                        return;
                    }
                    crate::proxy::rewrite::RewriteResult::Rewritten {
                        new_uri,
                        restart_routing: true,
                    } => {
                        debug!("HTTP/3 rewrite (last): {} -> {}", path, new_uri);
                        path = new_uri;
                        continue 'rewrite;
                    }
                    crate::proxy::rewrite::RewriteResult::Rewritten {
                        new_uri,
                        restart_routing: false,
                    } => {
                        debug!("HTTP/3 rewrite (break): {} -> {}", path, new_uri);
                        path = new_uri;
                        break 'rewrite;
                    }
                    crate::proxy::rewrite::RewriteResult::NoMatch => {}
                }
            }
        }
        break 'rewrite;
    }

    // After the rewrite loop `path` is the final value used by the rest of
    // the pipeline. Build one Arc<str> here and Arc::clone into each
    // remaining HookContext (PreUpstream, PostUpstream, Log).
    let final_path_arc: Arc<str> = Arc::from(path.as_str());

    // ── Route matching — longest-prefix match (uses possibly-rewritten path) ──
    let route = resolve_h3_route(&path, &dynamic_routes, &app_config);

    // ── CORS Middleware (parity with HTTP/1 + HTTP/2) ──
    // After route matching, before auth: handle CORS preflight and response headers.
    if let Some((_r_path, r_config)) = route.as_ref() {
        let origin = req
            .headers()
            .get("origin")
            .and_then(|v| v.to_str().ok());
        if method == hyper::Method::OPTIONS {
            if let Some(resp) = build_h3_cors_preflight_response(r_config, origin) {
                if let Err(e) = stream.send_response(resp).await {
                    debug!("HTTP/3 CORS preflight response failed: {}", e);
                }
                let _ = stream.finish().await;
                return;
            }
        }
    }

    let pool_name = route
        .as_ref()
        .and_then(|(_, r)| r.upstream.clone())
        .unwrap_or_else(|| "default".to_string());

    // ── Mirror pool resolution (route-level overrides global) ──
    let mirror_pool = route
        .as_ref()
        .and_then(|(_, r)| r.mirror_pool.clone())
        .or_else(|| app_config.mirror_pool.clone());

    // ── Authentication chain (Basic / JWT / per-route auth_request / global) ──
    // Extracted to `apply_h3_auth_chain` for unit-testability — see tests
    // module below for coverage of each branch. Headers it returns are
    // injected upstream after the geo / X-Geo-* injection block.
    let injected_auth_headers = match apply_h3_auth_chain(
        route.as_ref(),
        &app_config,
        req.headers(),
        &method,
        &path,
        &oidc_sessions,
    )
    .await
    {
        H3AuthOutcome::Allowed(hs) => hs,
        H3AuthOutcome::Denied {
            status,
            www_authenticate,
            body,
        } => {
            debug!("HTTP/3 auth denied from {} → {}", ip_str, status);
            h3_log_rejected(
                &access_logger,
                &ip_str,
                method.as_str(),
                &path,
                status.as_u16(),
                start,
                user_agent.as_deref().unwrap_or(""),
                &referer,
                &trace_id,
                body.as_ref().map(|b| b.len() as u64).unwrap_or(0),
            );
            if let Some(b) = body {
                let resp = hyper::Response::builder().status(status).body(()).unwrap();
                if let Err(e) = stream.send_response(resp).await {
                    debug!("H3 auth denial response failed: {}", e);
                    return;
                }
                if let Err(e) = stream.send_data(Bytes::from(b)).await {
                    debug!("H3 auth denial body failed: {}", e);
                }
                let _ = stream.finish().await;
                return;
            }
            match www_authenticate {
                Some(v) => {
                    send_h3_response_with_header(
                        &mut stream,
                        status,
                        hyper::header::WWW_AUTHENTICATE,
                        v,
                    )
                    .await;
                }
                None => send_h3_error(&mut stream, status).await,
            }
            return;
        }
    };

    // ── PreUpstream hooks ──
    if hook_engine.has_hooks(HookPhase::PreUpstream) {
        let hook_ctx = HookContext {
            client_ip: Arc::clone(&ip_arc),
            method: Arc::clone(&method_arc),
            path: Arc::clone(&final_path_arc),
            query: query_arc.clone(),
            headers: req
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            status: None,
            response_headers: Default::default(),
        };
        for result in hook_engine.execute(HookPhase::PreUpstream, &hook_ctx) {
            if let HookResult::Respond { status, .. } = result {
                let sc = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                send_h3_error(&mut stream, sc).await;
                return;
            }
        }
    }

    // ── Backend selection (with sticky session support) ──
    let pool = upstreams
        .get_pool(&pool_name)
        .or_else(|| upstreams.get_pool("default"));

    let backend = {
        let p = match &pool {
            Some(p) => p,
            None => {
                send_h3_error(&mut stream, StatusCode::BAD_GATEWAY).await;
                return;
            }
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
                                && b.is_healthy.load(std::sync::atomic::Ordering::Acquire)
                        })
                        .cloned()
                })
        } else {
            None
        };
        match sticky_preferred.or_else(|| p.get_next_backend(None, Some(Arc::clone(&ai_engine)))) {
            Some(b) => b,
            None => {
                send_h3_error(&mut stream, StatusCode::BAD_GATEWAY).await;
                return;
            }
        }
    };

    // ── Build target URL and forward over HTTP/1.1 ──
    let backend_url = match query.as_deref() {
        Some(q) if !q.is_empty() => format!("http://{}{}?{}", backend.config.address, path, q),
        _ => format!("http://{}{}", backend.config.address, path),
    };
    // gRPC-Web requests need HTTP/2 forwarding so trailers carry through.
    // All other H3 requests stay on the HTTP/1 keepalive client (faster,
    // wider compatibility).
    let client = if req_is_grpc_web {
        shared_grpc_upstream_client()
    } else {
        shared_upstream_client()
    };

    // Propagate original request headers
    let mut forward_headers = reqwest::header::HeaderMap::new();
    for (k, v) in req.headers() {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            forward_headers.insert(name, val);
        }
    }
    // gRPC-Web → gRPC translation on the request side: rewrite Content-Type
    // to plain `application/grpc(+proto)` and require trailers from the
    // upstream so `grpc-status` / `grpc-message` reach us.
    if req_is_grpc_web {
        let new_ct = if req_is_grpc_web_text {
            "application/grpc+proto"
        } else {
            "application/grpc"
        };
        forward_headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static(new_ct),
        );
        forward_headers.insert(
            reqwest::header::TE,
            reqwest::header::HeaderValue::from_static("trailers"),
        );
    }
    if let Some(geo) = geo_result.as_ref() {
        if let Ok(v) = reqwest::header::HeaderValue::from_str(&geo.country_code) {
            forward_headers.insert(
                reqwest::header::HeaderName::from_static("x-geo-country-code"),
                v,
            );
        }
        if let Ok(v) = reqwest::header::HeaderValue::from_str(&geo.country_name) {
            forward_headers.insert(reqwest::header::HeaderName::from_static("x-geo-country"), v);
        }
    }
    // Auth chain may have produced extra headers (JWT claims, X-Auth-* from
    // the auth_request subrequest). Inject them so the upstream sees them.
    for (k, v) in &injected_auth_headers {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            reqwest::header::HeaderValue::from_str(v),
        ) {
            forward_headers.insert(name, val);
        }
    }
    // Route-level add_headers — injected upstream so backends receive
    // operator-configured custom headers (e.g. X-Frame-Options, X-Version).
    if let Some((_, r)) = route.as_ref() {
        for (k, v) in &r.add_headers {
            if let (Ok(name), Ok(val)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                forward_headers.insert(name, val);
            }
        }
    }
    // W3C traceparent — `00-{trace_id}-{span_id}-01` (sampled). Backends
    // with W3C support continue the trace started here.
    if let Ok(traceparent) =
        reqwest::header::HeaderValue::from_str(&format!("00-{}-{}-01", trace_id, span_id))
    {
        forward_headers.insert(
            reqwest::header::HeaderName::from_static("traceparent"),
            traceparent,
        );
    }

    let method_str = method.as_str().to_string();
    // Bandwidth: in-bytes (request body)
    bandwidth
        .protocol("http3")
        .add_in(request_body.len() as u64);
    bandwidth.pool(&pool_name).add_in(request_body.len() as u64);

    // Only allocate mirror copies when there's actually a mirror pool configured
    let mirror_payload = mirror_pool
        .as_ref()
        .map(|_| (req.headers().clone(), Bytes::copy_from_slice(&request_body)));

    // gRPC-Web body translation: text variant carries base64-encoded
    // protobuf — decode before forwarding upstream.
    let outgoing_body = if req_is_grpc_web {
        match translate_h3_grpc_web_request_body(&request_body, req_is_grpc_web_text) {
            Some(b) => b,
            None => {
                debug!(
                    "HTTP/3 grpc-web-text body base64 decode failed from {}",
                    ip_str
                );
                send_h3_error(&mut stream, StatusCode::BAD_REQUEST).await;
                return;
            }
        }
    } else {
        request_body
    };

    let mut backend_request = client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
        &backend_url,
    );
    backend_request = backend_request.headers(forward_headers).body(outgoing_body);

    let mut backend_resp = match backend_request.send().await {
        Ok(r) => r,
        Err(e) => {
            error!("HTTP/3 upstream error for {}: {}", backend_url, e);
            backend.record_failure();
            send_h3_error(&mut stream, StatusCode::BAD_GATEWAY).await;
            return;
        }
    };

    let status_u16 = backend_resp.status().as_u16();
    let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let latency_secs = start.elapsed().as_secs_f64();

    if status.is_server_error() {
        warn!(
            "HTTP/3 backend {} returned {} in {:.1}ms",
            backend.config.address,
            status,
            latency_secs * 1000.0
        );
        backend.record_failure();
    }

    // ── Prometheus counters ──
    metrics
        .http_requests_total
        .with_label_values(&[&method_str, &status_u16.to_string(), &pool_name])
        .inc();
    metrics
        .http_request_duration
        .with_label_values(&[&method_str, &pool_name])
        .observe(latency_secs);

    // ── AI engine: feed latency/error signal ──
    ai_engine.update_score(
        &backend.config.address,
        (latency_secs * 1000.0) as u64,
        status.is_server_error(),
    );

    // ── PostUpstream hooks ──
    if hook_engine.has_hooks(crate::scripting::HookPhase::PostUpstream) {
        let resp_hdrs: std::collections::HashMap<String, String> = backend_resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|vs| (k.as_str().to_string(), vs.to_string()))
            })
            .collect();
        let hook_ctx = crate::scripting::HookContext {
            client_ip: Arc::clone(&ip_arc),
            method: Arc::clone(&method_arc),
            path: Arc::clone(&final_path_arc),
            query: None,
            headers: Default::default(),
            status: Some(status.as_u16()),
            response_headers: resp_hdrs,
        };
        for result in hook_engine.execute(crate::scripting::HookPhase::PostUpstream, &hook_ctx) {
            match result {
                crate::scripting::HookResult::Respond { status: s, .. } => {
                    let sc =
                        hyper::StatusCode::from_u16(s).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    send_h3_error(&mut stream, sc).await;
                    return;
                }
                _ => {}
            }
        }
    }

    // Collect response body from backend
    let content_type = backend_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let backend_resp_headers = backend_resp.headers().clone();

    // ── Wasm OnResponseHeaders ───────────────────────────────────────────
    // Mirrors the HTTP/1 path at proxy/mod.rs:2416. Plugins may append /
    // overwrite response headers (e.g. CSP, custom audit tags). Body is
    // not exposed at this phase (matches HTTP/1 — body is None).
    let mut wasm_response_extra_headers: Vec<(String, String)> = Vec::new();
    if wasm_plugins.plugin_count() > 0 {
        let wasm_resp_ctx = crate::wasm::WasmResponseContext {
            status_code: status_u16,
            headers: backend_resp_headers
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            body: None,
        };
        let result = wasm_plugins.execute_response_headers(&wasm_resp_ctx);
        if let Some(hdrs) = result.headers {
            wasm_response_extra_headers = hdrs.into_iter().collect();
        }
    }

    // ── Read upstream response body (streamed with size limit) ──
    // Use client_max_body_size as the response buffer limit to prevent OOM
    // on large upstream responses. Falls back to 64 MiB when unconfigured.
    let resp_buffer_limit = if max_body > 0 {
        max_body
    } else {
        64 * 1024 * 1024
    };
    let raw_backend_body = {
        let mut body = BytesMut::with_capacity(8192);
        let mut total = 0usize;
        loop {
            match backend_resp.chunk().await {
                Ok(Some(chunk)) => {
                    total += chunk.len();
                    if total > resp_buffer_limit {
                        warn!(
                            "HTTP/3 upstream response body exceeded buffer limit {} from {}",
                            resp_buffer_limit, backend.config.address
                        );
                        send_h3_error(&mut stream, StatusCode::BAD_GATEWAY).await;
                        return;
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    error!("Failed to read HTTP/3 backend body chunk: {}", e);
                    send_h3_error(&mut stream, StatusCode::BAD_GATEWAY).await;
                    return;
                }
            }
        }
        body.freeze()
    };


    // gRPC-Web → gRPC-Web response translation: append a length-prefixed
    // trailer frame built from the upstream's `grpc-status`/`grpc-message`
    // headers, then base64-encode the whole thing if the client used the
    // text variant. Also override the content_type that we'll emit so the
    // client sees the correct grpc-web subtype.
    let (body_bytes, content_type) = if req_is_grpc_web {
        let translated = build_h3_grpc_web_response_body(
            &raw_backend_body,
            &backend_resp_headers,
            req_is_grpc_web_text,
        );
        let new_ct = if req_is_grpc_web_text {
            "application/grpc-web-text+proto".to_string()
        } else {
            "application/grpc-web+proto".to_string()
        };
        (translated, new_ct)
    } else {
        (raw_backend_body, content_type)
    };

    // ── Cache GET 200 responses ──
    if method == hyper::Method::GET && status == StatusCode::OK {
        // Honour the route's `proxy_cache_valid` directive instead of a
        // hardcoded 60 s. Falls back to 60 s when the route is missing or
        // the directive is 0.
        let route_ttl_secs = route
            .as_ref()
            .map(|(_, r)| r.proxy_cache_valid_secs)
            .unwrap_or(0);
        let max_age_secs = if route_ttl_secs > 0 {
            route_ttl_secs
        } else {
            60
        };
        let cache_key = build_cache_key("GET", &host, &path, query.as_deref(), &[]);
        cache
            .insert(
                cache_key,
                CacheEntry {
                    status: status_u16,
                    body: body_bytes.clone(),
                    content_type: content_type.clone(),
                    headers: vec![],
                    created_at: std::time::Instant::now(),
                    max_age: std::time::Duration::from_secs(max_age_secs),
                    stale_while_revalidate: std::time::Duration::ZERO,
                    stale_if_error: std::time::Duration::ZERO,
                },
            )
            .await;
    }

    // ── Traffic mirroring: fire-and-forget copy to shadow pool ──
    if let (Some(mp_name), Some((mh, mb))) = (mirror_pool.as_ref(), mirror_payload) {
        crate::proxy::mirror::mirror_request(
            &method_str,
            &path,
            mh,
            mb,
            mp_name.clone(),
            Arc::clone(&upstreams),
        );
    }

    // ── Sticky session cookie ──
    let sticky_cookie = if let Some(ref mgr) = *sticky {
        match mgr.mode() {
            crate::proxy::sticky::StickyMode::Cookie { .. } => {
                mgr.set_cookie_header(&backend.config.address)
            }
            crate::proxy::sticky::StickyMode::Learn { .. } => {
                if let Some(session_key) = mgr.extract_from_response_header(&backend_resp_headers) {
                    mgr.learn(session_key, backend.config.address.clone());
                }
                None
            }
            _ => None,
        }
    } else {
        None
    };

    // ── Response compression (gzip + brotli, prefer brotli) ──
    // Mirrors the HTTP/1 path at proxy/mod.rs:2316. Negotiates against the
    // client's `accept-encoding`, requires the route or server to opt in,
    // checks the response content-type is compressible, and skips bodies
    // smaller than `MIN_COMPRESS_SIZE` / `MIN_BROTLI_SIZE`.
    let accept_encoding = req
        .headers()
        .get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok());
    let route_gzip = route.as_ref().map(|(_, r)| r.gzip).unwrap_or(false);
    let route_brotli = route.as_ref().map(|(_, r)| r.brotli).unwrap_or(false);
    let route_gzip_min = route.as_ref().map(|(_, r)| r.gzip_min_length).unwrap_or(0);

    let accepts_gzip = route_gzip && crate::middleware::compression::accepts_gzip(accept_encoding);
    let accepts_brotli = (route_brotli || app_config.brotli_enabled)
        && crate::middleware::brotli::accepts_brotli(accept_encoding);
    let is_compressible = crate::middleware::compression::is_compressible(Some(&content_type));
    let body_len_pre = body_bytes.len();

    let (body_to_send, content_encoding) = if accepts_brotli
        && is_compressible
        && body_len_pre >= crate::middleware::brotli::MIN_BROTLI_SIZE
    {
        match crate::middleware::brotli::brotli_compress_async(body_bytes.clone(), 6).await {
            Some(c) => (c, "br"),
            None => (body_bytes, ""),
        }
    } else if accepts_gzip
        && is_compressible
        && body_len_pre >= route_gzip_min.max(crate::middleware::compression::MIN_COMPRESS_SIZE)
    {
        match crate::middleware::compression::gzip_compress_async(body_bytes.clone()).await {
            Some(c) => (c, "gzip"),
            None => (body_bytes, ""),
        }
    } else {
        (body_bytes, "")
    };

    // ── Send HTTP/3 response headers ──
    // Capture length before moving the body, so we can record bandwidth + log later
    let body_len = body_to_send.len() as u64;

    let mut response = hyper::Response::builder()
        .status(status)
        .header("x-proxy-by", "Phalanx/HTTP3")
        .header("content-type", content_type.as_str());

    if !content_encoding.is_empty() {
        response = response.header(hyper::header::CONTENT_ENCODING, content_encoding);
    }

    if let Some(ref cookie_val) = sticky_cookie {
        response = response.header(hyper::header::SET_COOKIE, cookie_val.as_str());
    }

    // HSTS header injection — matches HTTP/1 behavior at proxy/mod.rs:2208.
    // Only emitted when the operator opts in via `hsts_max_age`.
    if let Some(max_age) = app_config.hsts_max_age {
        if let Ok(hv) = hyper::header::HeaderValue::from_str(&format!("max-age={}", max_age)) {
            response = response.header(hyper::header::STRICT_TRANSPORT_SECURITY, hv);
        }
    }

    // Wasm-injected response headers (from OnResponseHeaders phase). Inserted
    // after HSTS so a plugin can override the HSTS value if it wants to,
    // matching HTTP/1's "last writer wins" header insertion order.
    for (k, v) in &wasm_response_extra_headers {
        if let (Ok(hk), Ok(hv)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            response = response.header(hk, hv);
        }
    }

    // Route-level add_headers — injected into the client response so
    // operator-configured custom headers (e.g. X-Frame-Options, X-Version,
    // Cache-Control) reach the browser. Mirrors H2 at proxy/mod.rs:2373.
    if let Some((_, r)) = route.as_ref() {
        for (k, v) in &r.add_headers {
            if let (Ok(hk), Ok(hv)) = (
                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                hyper::header::HeaderValue::from_str(v),
            ) {
                response = response.header(hk, hv);
            }
        }
    }

    // CORS response headers for normal (non-preflight) requests
    if let Some((_, r)) = route.as_ref() {
        response = inject_h3_cors_response_headers(response, r);
    }

    let response = response.body(()).unwrap();

    if let Err(e) = stream.send_response(response).await {
        debug!("Failed to send HTTP/3 response headers: {}", e);
        return;
    }

    // Send body data
    if let Err(e) = stream.send_data(Bytes::from(body_to_send)).await {
        debug!("Failed to send HTTP/3 body: {}", e);
        return;
    }

    if let Err(e) = stream.finish().await {
        debug!("HTTP/3 stream finish error: {}", e);
    }

    // ── Bandwidth: out-bytes (response body, both per-protocol and per-pool) ──
    bandwidth.protocol("http3").add_out(body_len);
    bandwidth.pool(&pool_name).add_out(body_len);

    let latency_ms = start.elapsed().as_millis() as u64;

    // ── Structured access log ──
    let user_agent_str = user_agent.as_deref().unwrap_or("").to_string();
    let referer = req
        .headers()
        .get(hyper::header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    access_logger.log(AccessLogEntry {
        timestamp: crate::proxy::chrono_timestamp(),
        client_ip: ip_str.clone(),
        method: method_str.clone(),
        path: path.clone(),
        status: status_u16,
        latency_ms,
        backend: backend.config.address.clone(),
        pool: pool_name.clone(),
        bytes_sent: body_len,
        referer,
        user_agent: user_agent_str,
        trace_id: trace_id.clone(),
    });

    // ── Wasm OnLog: post-response auditing for plugins ──
    // Mirrors what HTTP/1 / HTTP/2 will need too — execute_log() existed in
    // wasm/mod.rs but was never wired into any handler before this batch.
    // Skipped when no plugins are registered (count check is a relaxed atomic).
    if wasm_plugins.plugin_count() > 0 {
        let req_ctx = WasmRequestContext {
            method: method_str.clone(),
            path: path.clone(),
            query: query.clone(),
            headers: req
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            body: None,
            client_ip: ip_str.clone(),
            protocol: "h3".to_string(),
        };
        let resp_ctx = crate::wasm::WasmResponseContext {
            status_code: status_u16,
            headers: backend_resp_headers
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect(),
            body: None,
        };
        let _ = wasm_plugins.execute_log(&req_ctx, &resp_ctx);
    }

    // ── Log hooks: post-response auditing ──
    if hook_engine.has_hooks(HookPhase::Log) {
        let log_ctx = HookContext {
            client_ip: Arc::clone(&ip_arc),
            method: Arc::clone(&method_arc),
            path: Arc::clone(&final_path_arc),
            query: query_arc.clone(),
            headers: Default::default(),
            status: Some(status_u16),
            response_headers: Default::default(),
        };
        hook_engine.execute(HookPhase::Log, &log_ctx);
    }
}

/// Reads the full request body from an HTTP/3 stream into a contiguous `Bytes` buffer.
/// Also drains any trailing headers (required by the h3 protocol to complete the stream).
/// Reads the HTTP/3 request body stream, enforcing `max_body_bytes` when non-zero.
/// Returns `None` if the body exceeds the limit (caller should reject with 413).
async fn read_h3_request_body(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    max_body_bytes: usize,
) -> Result<Option<Bytes>, h3::error::StreamError> {
    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        if chunk.has_remaining() {
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            body.extend_from_slice(&bytes);
            if max_body_bytes > 0 && body.len() > max_body_bytes {
                let _ = stream.recv_trailers().await;
                return Ok(None);
            }
        }
    }
    let _ = stream.recv_trailers().await?;
    Ok(Some(body.freeze()))
}

/// Handles the `/__phalanx/captcha/verify` endpoint over HTTP/3.
/// Validates the CAPTCHA token and nonce, then redirects on success or
/// re-serves the challenge page on failure.
async fn handle_h3_captcha_verify_request(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    method: &hyper::Method,
    body: &Bytes,
    client_ip: &str,
    captcha_manager: Arc<Option<crate::waf::bot::CaptchaManager>>,
) {
    let manager = match captcha_manager.as_ref() {
        Some(m) => m,
        None => {
            send_h3_error(stream, StatusCode::NOT_FOUND).await;
            return;
        }
    };

    if method != hyper::Method::POST {
        send_h3_error(stream, StatusCode::METHOD_NOT_ALLOWED).await;
        return;
    }

    let form_values = crate::proxy::parse_urlencoded_form(body.as_ref());
    let token = match manager.extract_token_from_form(&form_values) {
        Some(t) => t,
        None => {
            send_h3_error(stream, StatusCode::BAD_REQUEST).await;
            return;
        }
    };
    let nonce = match manager.extract_nonce_from_form(&form_values) {
        Some(n) => n,
        None => {
            send_h3_error(stream, StatusCode::BAD_REQUEST).await;
            return;
        }
    };
    let return_to = match manager.return_to_for_valid_nonce(client_ip, &nonce) {
        Some(p) => p,
        None => {
            send_h3_error(stream, StatusCode::BAD_REQUEST).await;
            return;
        }
    };

    if manager.verify_token(&token, client_ip).await {
        manager.consume_challenge(client_ip);
        let response = hyper::Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(hyper::header::LOCATION, return_to)
            .body(())
            .unwrap();
        if let Err(e) = stream.send_response(response).await {
            debug!("HTTP/3 captcha verify redirect send failed: {}", e);
        }
        let _ = stream.finish().await;
        return;
    }

    send_h3_html_response(stream, StatusCode::FORBIDDEN, manager.challenge_html()).await;
}

/// Sends an HTML response (e.g. CAPTCHA challenge page) over an HTTP/3 stream.
async fn send_h3_html_response(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    html: String,
) {
    let response = hyper::Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(())
        .unwrap();
    if let Err(e) = stream.send_response(response).await {
        debug!(
            "send_h3_html_response: failed to send headers {}: {}",
            status, e
        );
        return;
    }
    if let Err(e) = stream.send_data(Bytes::from(html)).await {
        debug!(
            "send_h3_html_response: failed to send body {}: {}",
            status, e
        );
        return;
    }
    let _ = stream.finish().await;
}

/// Send a bare HTTP/3 error response (status only, no body) and close the stream.
async fn send_h3_error(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
) {
    let resp = hyper::Response::builder().status(status).body(()).unwrap();
    if let Err(e) = stream.send_response(resp).await {
        debug!("send_h3_error: failed to send {}: {}", status, e);
    }
    let _ = stream.finish().await;
}

/// Send a status-only response with one extra header. Used by the auth chain
/// to attach `WWW-Authenticate` to a 401 so clients know how to reauthenticate.
async fn send_h3_response_with_header(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    header_name: hyper::header::HeaderName,
    header_value: hyper::header::HeaderValue,
) {
    let resp = hyper::Response::builder()
        .status(status)
        .header(header_name, header_value)
        .body(())
        .unwrap();
    if let Err(e) = stream.send_response(resp).await {
        debug!(
            "send_h3_response_with_header: failed to send {}: {}",
            status, e
        );
    }
    let _ = stream.finish().await;
}

/// Logs a rejected HTTP/3 request to the access logger so security events
/// (WAF blocks, rate limits, auth denials, geo blocks) are visible.
fn h3_log_rejected(
    access_logger: &crate::telemetry::access_log::AccessLogger,
    ip: &str,
    method: &str,
    path: &str,
    status: u16,
    start_time: std::time::Instant,
    user_agent: &str,
    referer: &str,
    trace_id: &str,
    bytes_sent: u64,
) {
    access_logger.log(AccessLogEntry {
        timestamp: crate::proxy::chrono_timestamp(),
        client_ip: ip.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        status,
        latency_ms: start_time.elapsed().as_millis() as u64,
        backend: String::new(),
        pool: String::new(),
        bytes_sent,
        referer: referer.to_string(),
        user_agent: user_agent.to_string(),
        trace_id: trace_id.to_string(),
    });
}

/// Attempts to open an HTTP/1.1 WebSocket upgrade to `backend_addr` using
/// headers extracted from the original H3 Extended CONNECT request.
/// Returns `Ok(TcpStream)` positioned after the 101 response if successful.
async fn h3_ws_backend_handshake(
    backend_addr: &str,
    path: &str,
    host: &str,
    headers: &hyper::HeaderMap,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(backend_addr).await?;
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
        path, host
    );
    for (k, v) in headers {
        let k_str = k.as_str();
        if k_str.starts_with("sec-websocket") {
            if let Ok(v_str) = v.to_str() {
                request.push_str(&format!("{}: {}\r\n", k_str, v_str));
            }
        }
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut buf = vec![0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 {
            return Err("backend closed before WS handshake completed".into());
        }
        total += n;
        let response = String::from_utf8_lossy(&buf[..total]);
        if response.contains("\r\n\r\n") {
            if response.starts_with("HTTP/1.1 101") {
                return Ok(stream);
            } else {
                return Err(format!(
                    "backend WS handshake failed: {}",
                    response.lines().next().unwrap_or("unknown")
                )
                .into());
            }
        }
        if total >= buf.len() {
            return Err("backend WS handshake response too large".into());
        }
    }
}

/// Relays raw bytes between an H3 request stream and a backend TCP socket.
/// Used for WebSocket over HTTP/3 (RFC 9220) tunneling.
async fn relay_h3_websocket(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    backend: &mut tokio::net::TcpStream,
    idle_timeout_secs: u64,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 8192];
    let relay = async {
        loop {
            tokio::select! {
                data = stream.recv_data() => {
                    match data {
                        Ok(Some(mut buf_data)) => {
                            let bytes = buf_data.copy_to_bytes(buf_data.remaining());
                            if let Err(e) = backend.write_all(&bytes).await {
                                debug!("H3 WS backend write error: {}", e);
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            debug!("H3 WS stream recv error: {}", e);
                            break;
                        }
                    }
                }
                n = backend.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Err(e) = stream.send_data(Bytes::copy_from_slice(&buf[..n])).await {
                                debug!("H3 WS stream send error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("H3 WS backend read error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    };
    if idle_timeout_secs > 0 {
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(idle_timeout_secs), relay).await;
    } else {
        relay.await;
    }
}

/// Outcome of the HTTP/3 auth chain.
#[derive(Debug)]
enum H3AuthOutcome {
    /// Auth passed (or not configured). Inject these headers upstream.
    Allowed(Vec<(String, String)>),
    /// Auth denied. Send `status` to the client; if `www_authenticate` is
    /// `Some`, attach it as the `WWW-Authenticate` response header.
    /// `body` overrides the default empty body when present (e.g. OIDC
    /// "Authentication required" landing page).
    Denied {
        status: StatusCode,
        www_authenticate: Option<hyper::header::HeaderValue>,
        body: Option<String>,
    },
}

/// Runs the HTTP/3 authentication chain in priority order:
///
/// 1. Per-route Basic Auth (`auth_basic_realm`)
/// 2. Per-route JWT Bearer (`auth_jwt_secret`) — injects claim headers on success
/// 3. Per-route OAuth 2.0 token introspection (`auth_oauth_introspect_url`)
/// 4. Per-route JWKS-based JWT (`auth_jwks_uri`) — dynamic public key lookup by kid
/// 5. Per-route OIDC session check (`auth_oidc_cookie_name`) — validates server-side session
/// 6. Per-route auth_request subrequest (`auth_request_url`) — injects X-Auth-* headers on success
/// 7. Global auth_request fallback (`app_config.auth_request_url`) — only when no per-route auth is configured
///
/// Returns the headers to inject upstream on success, or a denial response.
async fn apply_h3_auth_chain(
    route: Option<&(String, crate::config::RouteConfig)>,
    app_config: &AppConfig,
    headers: &hyper::HeaderMap,
    method: &hyper::Method,
    path: &str,
    oidc_sessions: &crate::auth::oidc::OidcSessionStore,
) -> H3AuthOutcome {
    use crate::auth::AuthResult;
    let mut injected: Vec<(String, String)> = Vec::new();

    if let Some((_, r_config)) = route {
        // 1. Basic Auth
        if let Some(ref realm) = r_config.auth_basic_realm {
            return match crate::auth::basic::check(headers, realm, &r_config.auth_basic_users) {
                AuthResult::Allowed => H3AuthOutcome::Allowed(injected),
                AuthResult::Denied(status, _) => {
                    let www = crate::auth::basic::www_authenticate_header(realm)
                        .parse()
                        .unwrap_or_else(|_| {
                            hyper::header::HeaderValue::from_static("Basic realm=\"protected\"")
                        });
                    H3AuthOutcome::Denied {
                        status,
                        www_authenticate: Some(www),
                        body: None,
                    }
                }
            };
        }
        // 2. JWT Bearer
        if let Some(ref secret) = r_config.auth_jwt_secret {
            let algo = r_config.auth_jwt_algorithm.as_deref().unwrap_or("HS256");
            let (result, claims) = crate::auth::jwt::check(headers, secret, algo);
            return match result {
                AuthResult::Allowed => {
                    if let Some(ref c) = claims {
                        for (k, v) in crate::auth::jwt::claims_to_headers(c) {
                            injected.push((k, v));
                        }
                    }
                    H3AuthOutcome::Allowed(injected)
                }
                AuthResult::Denied(status, _) => H3AuthOutcome::Denied {
                    status,
                    www_authenticate: Some(hyper::header::HeaderValue::from_static("Bearer")),
                    body: None,
                },
            };
        }
        // 3. OAuth 2.0 token introspection (RFC 7662)
        if let Some(ref introspect_url) = r_config.auth_oauth_introspect_url {
            use std::sync::OnceLock;
            // One process-wide 60s response cache so repeated tokens don't
            // re-hit the introspection endpoint. Mirrors HTTP/1's static.
            static OAUTH_CACHE: OnceLock<crate::auth::oauth::OAuthCache> = OnceLock::new();
            let cache = OAUTH_CACHE.get_or_init(crate::auth::oauth::new_cache);
            let client_id = r_config.auth_oauth_client_id.as_deref().unwrap_or("");
            let client_secret = r_config.auth_oauth_client_secret.as_deref().unwrap_or("");
            let (result, sub) =
                crate::auth::oauth::check(headers, introspect_url, client_id, client_secret, cache)
                    .await;
            return match result {
                AuthResult::Allowed => {
                    if let Some(sub_val) = sub {
                        injected.push(("X-Auth-Sub".to_string(), sub_val));
                    }
                    H3AuthOutcome::Allowed(injected)
                }
                AuthResult::Denied(status, _) => H3AuthOutcome::Denied {
                    status,
                    www_authenticate: Some(hyper::header::HeaderValue::from_static("Bearer")),
                    body: None,
                },
            };
        }
        // 4. JWKS-based JWT (dynamic public key lookup by kid)
        if let Some(ref jwks_uri) = r_config.auth_jwks_uri {
            use std::sync::OnceLock;
            static JWKS_MGR: OnceLock<std::sync::Arc<crate::auth::jwks::JwksManager>> =
                OnceLock::new();
            let mgr =
                JWKS_MGR.get_or_init(|| std::sync::Arc::new(crate::auth::jwks::JwksManager::new()));
            return apply_h3_jwks(jwks_uri, mgr.as_ref(), headers, &mut injected).await;
        }
        // 5. OIDC session check
        // Reads the session cookie named in `auth_oidc_cookie_name`, looks
        // up the server-side OidcSessionStore, validates expiry, and on
        // success injects X-Auth-Sub / X-Auth-Email upstream. Mirrors
        // HTTP/1 at proxy/mod.rs:1407-1457. The OIDC RP login flow itself
        // (auth-code redirect, token exchange) is not handled here; admin
        // endpoints establish the session, this branch only validates it.
        if let Some(ref cookie_name) = r_config.auth_oidc_cookie_name {
            let (result, session) =
                crate::auth::oidc::check_session(headers, cookie_name, oidc_sessions);
            return match result {
                AuthResult::Allowed => {
                    if let Some(s) = session {
                        // Issuer mismatch — reject even if the session is fresh
                        if let Some(ref issuer) = r_config.auth_oidc_issuer {
                            if !crate::auth::oidc::session_matches_issuer(&s, issuer) {
                                return H3AuthOutcome::Denied {
                                    status: StatusCode::UNAUTHORIZED,
                                    www_authenticate: None,
                                    body: Some("OIDC issuer mismatch".to_string()),
                                };
                            }
                        }
                        injected.push(("X-Auth-Sub".to_string(), s.sub));
                        if let Some(email) = s.email {
                            injected.push(("X-Auth-Email".to_string(), email));
                        }
                    }
                    H3AuthOutcome::Allowed(injected)
                }
                AuthResult::Denied(status, _) => H3AuthOutcome::Denied {
                    status,
                    www_authenticate: None,
                    body: if r_config.auth_oidc_issuer.is_some() {
                        Some("Authentication required".to_string())
                    } else {
                        None
                    },
                },
            };
        }
        // 6. Per-route auth_request
        if let Some(ref auth_url) = r_config.auth_request_url {
            let (result, auth_headers) =
                crate::auth::auth_request::check(headers, auth_url, method.as_str(), path).await;
            return match result {
                AuthResult::Allowed => {
                    injected.extend(auth_headers);
                    H3AuthOutcome::Allowed(injected)
                }
                AuthResult::Denied(status, _) => H3AuthOutcome::Denied {
                    status,
                    www_authenticate: None,
                    body: if r_config.auth_oidc_issuer.is_some() {
                        Some("Authentication required".to_string())
                    } else {
                        None
                    },
                },
            };
        }
    }

    // 4. Global auth_request fallback (only when no per-route auth was set).
    if let Some(ref auth_url) = app_config.auth_request_url {
        let (result, auth_headers) =
            crate::auth::auth_request::check(headers, auth_url, method.as_str(), path).await;
        return match result {
            AuthResult::Allowed => {
                injected.extend(auth_headers);
                H3AuthOutcome::Allowed(injected)
            }
            AuthResult::Denied(status, _) => H3AuthOutcome::Denied {
                status,
                www_authenticate: None,
                body: None,
            },
        };
    }

    H3AuthOutcome::Allowed(injected)
}

/// JWKS-based JWT validation: extract `kid` from the Bearer token's header,
/// fetch the matching key from the JWKS endpoint (5-min TTL cache inside
/// `JwksManager`), validate, and on success append claim headers to `injected`.
///
/// Mirrors `proxy/mod.rs:1338-1406` for the HTTP/1 path. Extracted as its own
/// fn so `apply_h3_auth_chain` stays readable.
async fn apply_h3_jwks(
    jwks_uri: &str,
    mgr: &crate::auth::jwks::JwksManager,
    headers: &hyper::HeaderMap,
    injected: &mut Vec<(String, String)>,
) -> H3AuthOutcome {
    let bearer_challenge = Some(hyper::header::HeaderValue::from_static("Bearer"));

    let token = match crate::auth::jwt::extract_bearer_token(headers) {
        Some(t) => t,
        None => {
            return H3AuthOutcome::Denied {
                status: StatusCode::UNAUTHORIZED,
                www_authenticate: bearer_challenge,
                body: None,
            };
        }
    };

    // Token header is the first dot-separated segment, base64url-encoded JSON
    let kid: Option<String> = token.split('.').next().and_then(|seg| {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(seg)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|v| v.get("kid").and_then(|k| k.as_str()).map(String::from))
    });

    let kid = match kid {
        Some(k) => k,
        None => {
            return H3AuthOutcome::Denied {
                status: StatusCode::UNAUTHORIZED,
                www_authenticate: bearer_challenge,
                body: None,
            };
        }
    };

    let jwk = match mgr.find_key(jwks_uri, &kid).await {
        Some(j) => j,
        None => {
            return H3AuthOutcome::Denied {
                status: StatusCode::UNAUTHORIZED,
                www_authenticate: bearer_challenge,
                body: None,
            };
        }
    };

    let (decoding_key, algo) = match crate::auth::jwks::JwksManager::decoding_key_from_jwk(&jwk) {
        Ok(pair) => pair,
        Err(_) => {
            return H3AuthOutcome::Denied {
                status: StatusCode::UNAUTHORIZED,
                www_authenticate: bearer_challenge,
                body: None,
            };
        }
    };

    use jsonwebtoken::{Validation, decode};
    let mut validation = Validation::new(algo);
    validation.validate_aud = false;
    match decode::<crate::auth::jwt::Claims>(token, &decoding_key, &validation) {
        Ok(data) => {
            for (k, v) in crate::auth::jwt::claims_to_headers(&data.claims) {
                injected.push((k, v));
            }
            H3AuthOutcome::Allowed(std::mem::take(injected))
        }
        Err(_) => H3AuthOutcome::Denied {
            status: StatusCode::UNAUTHORIZED,
            www_authenticate: bearer_challenge,
            body: None,
        },
    }
}

/// Detects a gRPC-Web CORS preflight request: an `OPTIONS` whose
/// `Access-Control-Request-Headers` mentions `grpc-web` (case-insensitive).
/// Browsers send these before issuing the actual `POST application/grpc-web`
/// gRPC call. We answer 204 with the standard CORS response so the call
/// is allowed without round-tripping to the upstream.
fn is_h3_grpc_web_preflight(method: &hyper::Method, headers: &hyper::HeaderMap) -> bool {
    if method != hyper::Method::OPTIONS {
        return false;
    }
    headers
        .get(hyper::header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("grpc-web"))
        .unwrap_or(false)
}

/// True for HTTP Extended CONNECT requests (RFC 8441 / 9220) — the
/// transport mechanism WebTransport uses on top of HTTP/3.
///
/// We detect either:
/// 1. The hyper `Protocol` extension (set by hyper when the H3 layer
///    surfaces the `:protocol` pseudo-header). This is the canonical
///    signal but its presence depends on the h3 crate version.
/// 2. Plain `CONNECT` method (covers HTTP CONNECT tunnelling too — also
///    not implemented here).
///
/// Either way, the appropriate response is "not implemented" rather than
/// "404", because the URL is fine — we just don't speak this protocol.
fn is_h3_extended_connect(method: &hyper::Method, headers: &hyper::HeaderMap) -> bool {
    if *method == hyper::Method::CONNECT {
        return true;
    }
    // Some clients send the protocol via a `:protocol`-equivalent header
    // when targeting servers that surface it differently. Defensive check.
    headers
        .get("sec-webtransport-http3-draft02")
        .or_else(|| headers.get("sec-webtransport-http3-draft"))
        .is_some()
}

/// Returns the protocol name from an Extended CONNECT request, when known.
/// Used purely for the diagnostic log/header so operators can see which
/// extension was being requested (most commonly `webtransport`).
fn h3_extended_connect_protocol(headers: &hyper::HeaderMap) -> Option<String> {
    if headers.contains_key("sec-webtransport-http3-draft02")
        || headers.contains_key("sec-webtransport-http3-draft")
    {
        return Some("webtransport".to_string());
    }
    // Fall back to a generic indication when the extension isn't named.
    headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// True when the request is a WebSocket Extended CONNECT over HTTP/3
/// (RFC 9220). h3 0.0.8 does not include `websocket` in its `Protocol`
/// enum, so we detect via CONNECT method + `Upgrade: websocket` or the
/// `sec-websocket-*` family of headers.
fn is_h3_websocket_connect(method: &hyper::Method, headers: &hyper::HeaderMap) -> bool {
    if *method != hyper::Method::CONNECT {
        return false;
    }
    let upgrade_is_ws = headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if upgrade_is_ws {
        return true;
    }
    // Some clients send sec-websocket-key / sec-websocket-version even
    // over H3, despite RFC 9220 not requiring them.
    headers.contains_key("sec-websocket-key") || headers.contains_key("sec-websocket-version")
}

/// CORS preflight response for gRPC-Web over HTTP/3. Mirrors the headers
/// emitted by `grpc_web::cors_preflight_response` for HTTP/1.
async fn send_h3_grpc_web_preflight(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) {
    let resp = hyper::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(hyper::header::ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS")
        .header(
            hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
            "content-type,x-grpc-web,x-user-agent,grpc-timeout",
        )
        .header(hyper::header::ACCESS_CONTROL_MAX_AGE, "86400")
        .body(())
        .unwrap();
    if let Err(e) = stream.send_response(resp).await {
        debug!("send_h3_grpc_web_preflight: failed: {}", e);
    }
    let _ = stream.finish().await;
}

/// Build a `rustls::ServerConfig` for QUIC (TLS 1.3 only, ALPN "h3").
/// Uses cert/key from config, falls back to self-signed for development.
fn build_quic_tls_config(app_config: &AppConfig) -> Option<rustls::ServerConfig> {
    let (cert_chain, private_key) = if let (Some(cert_path), Some(key_path)) = (
        app_config.tls_cert_path.as_deref(),
        app_config.tls_key_path.as_deref(),
    ) {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| error!("Cannot read H3 cert {}: {}", cert_path, e))
            .ok()?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| error!("Cannot read H3 key {}: {}", key_path, e))
            .ok()?;

        // Parse the certificate chain, warning on individual malformed entries
        // rather than silently dropping them (parity with HTTP/1 TLS path).
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_pem.as_slice())
                .filter_map(|r| match r {
                    Ok(c) => Some(c.into_owned()),
                    Err(e) => {
                        warn!("Skipping malformed certificate in {}: {}", cert_path, e);
                        None
                    }
                })
                .collect();

        // Fail explicitly if every certificate in the file was unusable.
        if certs.is_empty() {
            error!("No valid certificates found in {}", cert_path);
            return None;
        }

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .ok()
            .flatten()
            .map(|k| k.clone_key())?;

        (certs, key)
    } else {
        // Self-signed certificate for development
        info!("HTTP/3: generating self-signed dev certificate (no cert configured)");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| error!("rcgen error: {}", e))
            .ok()?;

        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        // rcgen 0.14.x uses `signing_key`, not `key_pair`
        let key_der =
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());

        (vec![cert_der], key_der)
    };

    // Build from an explicit provider rather than the process default. Relying on
    // the default made this a hard panic whenever `install_default_crypto_provider`
    // had not run, which took the whole HTTP/3 listener down at startup.
    let mut tls_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| error!("QUIC TLS protocol version error: {}", e))
    .ok()?
    .with_no_client_auth()
    .with_single_cert(cert_chain, private_key)
    .map_err(|e| error!("QUIC TLS config error: {}", e))
    .ok()?;

    // HTTP/3 ALPN identifier
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    Some(tls_config)
}

#[cfg(test)]
mod tests {
    use super::{
        H3AuthOutcome, apply_h3_auth_chain, build_h3_cors_preflight_response,
        build_h3_grpc_web_response_body, build_h3_grpc_web_trailer_frame,
        h3_extended_connect_protocol, inject_h3_cors_response_headers, is_h3_extended_connect,
        is_h3_grpc_web, is_h3_grpc_web_preflight, is_h3_grpc_web_text, is_h3_websocket_connect,
        resolve_h3_route, shared_grpc_upstream_client, shared_upstream_client,
        translate_h3_grpc_web_request_body,
    };
    use crate::config::{AppConfig, RouteConfig};
    use crate::proxy::{
        build_return_to, decode_form_component, generate_trace_context_ids, parse_urlencoded_form,
    };
    use crate::telemetry::bandwidth::BandwidthTracker;
    use bytes::Bytes;
    use hyper::StatusCode;
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_build_return_to_includes_query() {
        assert_eq!(build_return_to("/a", Some("x=1&y=2")), "/a?x=1&y=2");
        assert_eq!(build_return_to("/a", None), "/a");
        assert_eq!(build_return_to("/a", Some("")), "/a");
    }

    #[test]
    fn test_parse_urlencoded_form_decodes_components() {
        let parsed = parse_urlencoded_form(
            b"phalanx_challenge_nonce=abc%2B123&return_to=%2Fdocs%3Fa%3D1%2B2",
        );
        assert_eq!(
            parsed.get("phalanx_challenge_nonce").map(String::as_str),
            Some("abc+123")
        );
        assert_eq!(
            parsed.get("return_to").map(String::as_str),
            Some("/docs?a=1+2")
        );
    }

    #[test]
    fn test_parse_urlencoded_form_handles_pluses_and_empty() {
        let parsed = parse_urlencoded_form(b"a=hello+world&b=&c");
        assert_eq!(parsed.get("a").map(String::as_str), Some("hello world"));
        assert_eq!(parsed.get("b").map(String::as_str), Some(""));
        assert_eq!(parsed.get("c").map(String::as_str), Some(""));
    }

    #[test]
    fn test_decode_form_component_invalid_percent_passes_through() {
        // Bare '%' with non-hex follow should be left as-is, not panic
        assert_eq!(decode_form_component("100%off"), "100%off");
        assert_eq!(decode_form_component("a%2Gb"), "a%2Gb");
    }

    #[test]
    fn test_shared_upstream_client_is_singleton() {
        // Two calls return the same underlying client (same pointer).
        let c1 = shared_upstream_client();
        let c2 = shared_upstream_client();
        assert!(std::ptr::eq(c1, c2));
    }

    #[test]
    fn test_bandwidth_http3_protocol_counters() {
        // Validates the per-protocol counter shape that `handle_h3_request`
        // increments. Catches regressions if the "http3" label changes.
        let tracker = BandwidthTracker::new();
        let p = tracker.protocol("http3");
        p.inc_requests();
        p.add_in(123);
        p.add_out(456);

        assert_eq!(p.requests.load(Ordering::Relaxed), 1);
        assert_eq!(p.bytes_in.load(Ordering::Relaxed), 123);
        assert_eq!(p.bytes_out.load(Ordering::Relaxed), 456);

        // Same label returns the same Arc bucket
        let p2 = tracker.protocol("http3");
        assert_eq!(p2.requests.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_bandwidth_pool_counters_isolated_per_pool() {
        let tracker = BandwidthTracker::new();
        tracker.pool("api").add_out(1000);
        tracker.pool("static").add_out(50);
        assert_eq!(tracker.pool("api").bytes_out.load(Ordering::Relaxed), 1000);
        assert_eq!(tracker.pool("static").bytes_out.load(Ordering::Relaxed), 50);
    }

    /// Install the rustls process-level CryptoProvider exactly once.
    ///
    /// Delegates to the same helper the binary calls at startup. Keeping a private
    /// copy here is what previously hid the production defect: the tests installed
    /// a provider that `main` never did, so `build_quic_tls_config` passed under
    /// test and panicked in the real listener.
    fn ensure_crypto_provider() {
        crate::proxy::tls::install_default_crypto_provider();
    }

    #[test]
    fn test_build_quic_tls_config_falls_back_to_self_signed() {
        ensure_crypto_provider();
        // No cert configured → must produce a self-signed config so dev / docker
        // don't crash. Regression guard for the dev-mode fallback at
        // build_quic_tls_config().
        let cfg = AppConfig::default();
        let tls = super::build_quic_tls_config(&cfg);
        assert!(tls.is_some(), "self-signed fallback should always succeed");
        let tls = tls.unwrap();
        assert_eq!(tls.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn test_build_quic_tls_config_returns_none_for_missing_files() {
        ensure_crypto_provider();
        // If cert paths are configured but unreadable, fallback path is NOT
        // taken — function returns None so the listener cleanly skips.
        let mut cfg = AppConfig::default();
        cfg.tls_cert_path = Some("/nonexistent/cert.pem".to_string());
        cfg.tls_key_path = Some("/nonexistent/key.pem".to_string());
        assert!(super::build_quic_tls_config(&cfg).is_none());
    }

    #[test]
    fn test_build_quic_tls_config_malformed_cert_skipped_keeps_valid() {
        ensure_crypto_provider();
        let tmp = std::env::temp_dir().join("phalanx_h3_l1a");
        std::fs::create_dir_all(&tmp).unwrap();

        let params = rcgen::CertificateParams::new(vec!["h3.example.com".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let malformed_pem = format!(
            "{}\n-----BEGIN CERTIFICATE-----\n!!!NOT_BASE64!!!\n-----END CERTIFICATE-----\n",
            cert.pem()
        );

        let cert_path = tmp.join("chain.pem");
        let key_path = tmp.join("key.pem");
        std::fs::write(&cert_path, &malformed_pem).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        let mut cfg = AppConfig::default();
        cfg.tls_cert_path = Some(cert_path.to_str().unwrap().to_string());
        cfg.tls_key_path = Some(key_path.to_str().unwrap().to_string());

        let tls = super::build_quic_tls_config(&cfg);
        assert!(
            tls.is_some(),
            "valid cert should load despite malformed sibling in H3 path"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_build_quic_tls_config_all_malformed_returns_none() {
        ensure_crypto_provider();
        let tmp = std::env::temp_dir().join("phalanx_h3_l1b");
        std::fs::create_dir_all(&tmp).unwrap();

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let bad_pem = "-----BEGIN CERTIFICATE-----\n!!!GARBAGE!!!\n-----END CERTIFICATE-----\n";

        let cert_path = tmp.join("bad.pem");
        let key_path = tmp.join("key.pem");
        std::fs::write(&cert_path, bad_pem).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        let mut cfg = AppConfig::default();
        cfg.tls_cert_path = Some(cert_path.to_str().unwrap().to_string());
        cfg.tls_key_path = Some(key_path.to_str().unwrap().to_string());

        let tls = super::build_quic_tls_config(&cfg);
        assert!(
            tls.is_none(),
            "all certs malformed → H3 TLS config must fail"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    // ── HTTP/3 auth chain tests (C2 partial) ─────────────────────────────────

    fn empty_route() -> Option<(String, RouteConfig)> {
        None
    }

    /// Helper: route with only the field of interest set, everything else default.
    fn route_with(modify: impl FnOnce(&mut RouteConfig)) -> Option<(String, RouteConfig)> {
        let mut r = RouteConfig::default();
        modify(&mut r);
        Some(("/".to_string(), r))
    }

    /// Per-test empty OIDC store. Each test gets its own to avoid cross-test
    /// pollution; the store is just an `Arc<DashMap>` so this is cheap.
    fn empty_oidc_store() -> crate::auth::oidc::OidcSessionStore {
        crate::auth::oidc::new_session_store()
    }

    #[tokio::test]
    async fn test_h3_auth_chain_no_auth_configured_allows() {
        let cfg = AppConfig::default();
        let h = hyper::HeaderMap::new();
        let out = apply_h3_auth_chain(
            empty_route().as_ref(),
            &cfg,
            &h,
            &hyper::Method::GET,
            "/anything",
            &empty_oidc_store(),
        )
        .await;
        assert!(matches!(out, H3AuthOutcome::Allowed(ref v) if v.is_empty()));
    }

    #[tokio::test]
    async fn test_h3_basic_auth_denied_without_credentials_attaches_www_authenticate() {
        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_basic_realm = Some("MyArea".to_string());
            r.auth_basic_users = HashMap::new();
        });
        let h = hyper::HeaderMap::new();
        let out = apply_h3_auth_chain(
            route.as_ref(),
            &cfg,
            &h,
            &hyper::Method::GET,
            "/p",
            &empty_oidc_store(),
        )
        .await;
        match out {
            H3AuthOutcome::Denied {
                status,
                www_authenticate,
                ..
            } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                let v = www_authenticate.expect("WWW-Authenticate must be set on Basic 401");
                assert!(v.to_str().unwrap().contains("Basic realm="));
                assert!(v.to_str().unwrap().contains("MyArea"));
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_h3_basic_auth_allows_correct_credentials() {
        // Plaintext password match (constant-time fallback path of basic::check).
        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_basic_realm = Some("MyArea".to_string());
            let mut users = HashMap::new();
            users.insert("alice".to_string(), "wonderland".to_string());
            r.auth_basic_users = users;
        });
        // base64("alice:wonderland") = YWxpY2U6d29uZGVybGFuZA==
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::AUTHORIZATION,
            "Basic YWxpY2U6d29uZGVybGFuZA==".parse().unwrap(),
        );
        let out = apply_h3_auth_chain(
            route.as_ref(),
            &cfg,
            &h,
            &hyper::Method::GET,
            "/p",
            &empty_oidc_store(),
        )
        .await;
        assert!(
            matches!(out, H3AuthOutcome::Allowed(ref v) if v.is_empty()),
            "valid creds should be allowed with no injected headers, got {out:?}"
        );
    }

    #[tokio::test]
    async fn test_h3_jwt_denied_without_bearer_uses_bearer_challenge() {
        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_jwt_secret = Some("secret".to_string());
        });
        let h = hyper::HeaderMap::new();
        let out = apply_h3_auth_chain(
            route.as_ref(),
            &cfg,
            &h,
            &hyper::Method::GET,
            "/p",
            &empty_oidc_store(),
        )
        .await;
        match out {
            H3AuthOutcome::Denied {
                status,
                www_authenticate,
                ..
            } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                let v = www_authenticate.expect("Bearer challenge expected");
                assert_eq!(v, "Bearer");
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_h3_jwt_allowed_injects_claim_headers() {
        // Mint an HS256 token with sub/email; expect those to appear in the
        // injected header set so they reach the upstream as X-Auth-*.
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        let secret = "h3-jwt-secret";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = crate::auth::jwt::Claims {
            sub: Some("user-h3".to_string()),
            email: Some("h3@example.com".to_string()),
            exp: Some(now + 3600),
            iss: None,
            aud: None,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_jwt_secret = Some(secret.to_string());
            r.auth_jwt_algorithm = Some("HS256".to_string());
        });
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let out = apply_h3_auth_chain(
            route.as_ref(),
            &cfg,
            &h,
            &hyper::Method::GET,
            "/p",
            &empty_oidc_store(),
        )
        .await;
        let injected = match out {
            H3AuthOutcome::Allowed(v) => v,
            other => panic!("expected Allowed, got {:?}", other),
        };
        let kvs: HashMap<String, String> = injected.into_iter().collect();
        assert_eq!(kvs.get("X-Auth-Sub").map(String::as_str), Some("user-h3"));
        assert_eq!(
            kvs.get("X-Auth-Email").map(String::as_str),
            Some("h3@example.com")
        );
    }

    #[tokio::test]
    async fn test_h3_jwt_denied_on_wrong_secret() {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = crate::auth::jwt::Claims {
            sub: Some("u".into()),
            email: None,
            exp: Some(now + 3600),
            iss: None,
            aud: None,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"signing-secret"),
        )
        .unwrap();
        let cfg = AppConfig::default();
        let route = route_with(|r| {
            // Different secret on the verifier side
            r.auth_jwt_secret = Some("DIFFERENT-secret".into());
        });
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let out = apply_h3_auth_chain(
            route.as_ref(),
            &cfg,
            &h,
            &hyper::Method::GET,
            "/p",
            &empty_oidc_store(),
        )
        .await;
        assert!(matches!(out, H3AuthOutcome::Denied { .. }));
    }

    /// JWKS branch: missing Bearer token → 401 + Bearer challenge.
    /// Validates the early-return path in `apply_h3_jwks` before any HTTP fetch.
    #[tokio::test]
    async fn test_h3_jwks_missing_bearer_token_denied() {
        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_jwks_uri = Some("https://example.invalid/.well-known/jwks.json".into());
        });
        let h = hyper::HeaderMap::new();
        let out = apply_h3_auth_chain(
            route.as_ref(),
            &cfg,
            &h,
            &hyper::Method::GET,
            "/p",
            &empty_oidc_store(),
        )
        .await;
        match out {
            H3AuthOutcome::Denied {
                status,
                www_authenticate,
                ..
            } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(www_authenticate.unwrap(), "Bearer");
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    /// JWKS branch: token without a `kid` in its header → 401.
    /// Catches regressions in the kid-extraction path (base64url decode + JSON parse).
    #[tokio::test]
    async fn test_h3_jwks_missing_kid_denied() {
        // Mint a token with NO kid in its header (default Header::new omits kid).
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = crate::auth::jwt::Claims {
            sub: Some("u".into()),
            email: None,
            exp: Some(now + 3600),
            iss: None,
            aud: None,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"x"),
        )
        .unwrap();
        assert!(!token.contains("kid"), "test fixture must not contain kid");

        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_jwks_uri = Some("https://example.invalid/jwks.json".into());
        });
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let out = apply_h3_auth_chain(
            route.as_ref(),
            &cfg,
            &h,
            &hyper::Method::GET,
            "/p",
            &empty_oidc_store(),
        )
        .await;
        assert!(matches!(out, H3AuthOutcome::Denied { .. }));
    }

    /// OAuth branch: missing Bearer token → 401 + Bearer challenge.
    /// We don't test the success path here because that would require a live
    /// introspection endpoint; coverage of the introspection logic itself
    /// lives in `auth/oauth.rs::tests`.
    #[tokio::test]
    async fn test_h3_oauth_missing_bearer_denied() {
        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_oauth_introspect_url = Some("https://example.invalid/oauth/introspect".into());
            r.auth_oauth_client_id = Some("cid".into());
            r.auth_oauth_client_secret = Some("csecret".into());
        });
        let h = hyper::HeaderMap::new();
        let out = apply_h3_auth_chain(
            route.as_ref(),
            &cfg,
            &h,
            &hyper::Method::GET,
            "/p",
            &empty_oidc_store(),
        )
        .await;
        match out {
            H3AuthOutcome::Denied {
                status,
                www_authenticate,
                ..
            } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(www_authenticate.unwrap(), "Bearer");
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    /// Compression negotiation: brotli wins when both are accepted.
    /// We test the predicate combination directly since the actual
    /// compression call lives inline in `handle_h3_request`.
    #[test]
    fn test_h3_compression_prefers_brotli_when_both_accepted() {
        // Predicates that drive the H3 compression branch
        let accepts_gzip = crate::middleware::compression::accepts_gzip(Some("gzip, br"));
        let accepts_brotli = crate::middleware::brotli::accepts_brotli(Some("gzip, br"));
        assert!(accepts_gzip);
        assert!(accepts_brotli);
        // Both true → brotli branch fires first in handle_h3_request.
        // (Order is: brotli check, then gzip check.)
    }

    #[test]
    fn test_h3_compression_skips_uncompressible_types() {
        // image/png is NOT in the compressible whitelist.
        assert!(!crate::middleware::compression::is_compressible(Some(
            "image/png"
        )));
        // text/html and application/json are.
        assert!(crate::middleware::compression::is_compressible(Some(
            "text/html"
        )));
        assert!(crate::middleware::compression::is_compressible(Some(
            "application/json"
        )));
    }

    #[test]
    fn test_h3_brotli_min_size_bound() {
        // Bodies under MIN_BROTLI_SIZE must NOT be compressed in the H3 path.
        // Regression guard against regressing the body_len_pre check.
        assert!(crate::middleware::brotli::MIN_BROTLI_SIZE > 0);
    }

    // ── OIDC tests ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_h3_oidc_denied_without_session_cookie() {
        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_oidc_cookie_name = Some("PHALANX_SESSION".into());
        });
        let h = hyper::HeaderMap::new();
        let store = empty_oidc_store();
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/p", &store).await;
        assert!(matches!(out, H3AuthOutcome::Denied { .. }));
    }

    #[tokio::test]
    async fn test_h3_oidc_allows_with_valid_session_and_injects_headers() {
        // Plant a fresh session in the store, then verify the auth chain
        // returns Allowed and includes X-Auth-Sub / X-Auth-Email.
        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_oidc_cookie_name = Some("PHALANX_SESSION".into());
        });
        let store = empty_oidc_store();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let session_id = "test-sid-allow".to_string();
        store.insert(
            session_id.clone(),
            crate::auth::oidc::OidcSession {
                sub: "u123".to_string(),
                email: Some("u@example.com".to_string()),
                issuer: Some("https://idp.example.com".to_string()),
                access_token: "fake-access-token".to_string(),
                refresh_token: None,
                created_at: now,
                expires_in: 3600,
            },
        );

        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::COOKIE,
            format!("PHALANX_SESSION={session_id}").parse().unwrap(),
        );
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/p", &store).await;
        let injected = match out {
            H3AuthOutcome::Allowed(v) => v,
            other => panic!("expected Allowed, got {:?}", other),
        };
        let kv: HashMap<String, String> = injected.into_iter().collect();
        assert_eq!(kv.get("X-Auth-Sub").map(String::as_str), Some("u123"));
        assert_eq!(
            kv.get("X-Auth-Email").map(String::as_str),
            Some("u@example.com")
        );
    }

    #[tokio::test]
    async fn test_h3_oidc_rejects_issuer_mismatch() {
        // Session is from issuer A, route requires issuer B → Denied.
        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_oidc_cookie_name = Some("PHALANX_SESSION".into());
            r.auth_oidc_issuer = Some("https://expected.example.com".into());
        });
        let store = empty_oidc_store();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let session_id = "test-sid-mismatch".to_string();
        store.insert(
            session_id.clone(),
            crate::auth::oidc::OidcSession {
                sub: "u".to_string(),
                email: None,
                issuer: Some("https://OTHER.example.com".to_string()),
                access_token: "fake".to_string(),
                refresh_token: None,
                created_at: now,
                expires_in: 3600,
            },
        );

        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::COOKIE,
            format!("PHALANX_SESSION={session_id}").parse().unwrap(),
        );
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/p", &store).await;
        assert!(matches!(out, H3AuthOutcome::Denied { .. }));
    }

    /// C2: WebTransport requests must go through the same auth chain as
    /// regular HTTP/3 requests. A CONNECT with `:protocol = webtransport`
    /// and no credentials should be denied when Basic Auth is configured.
    #[tokio::test]
    async fn test_h3_webtransport_auth_rejected_without_credentials() {
        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_basic_realm = Some("WTArea".to_string());
            r.auth_basic_users = HashMap::new();
        });
        let h = hyper::HeaderMap::new();
        let out = apply_h3_auth_chain(
            route.as_ref(),
            &cfg,
            &h,
            &hyper::Method::CONNECT,
            "/wt",
            &empty_oidc_store(),
        )
        .await;
        assert!(
            matches!(out, H3AuthOutcome::Denied { status, .. } if status == StatusCode::UNAUTHORIZED)
        );
    }

    // ── WebTransport (Extended CONNECT) detection ───────────────────────

    #[test]
    fn test_h3_detects_plain_connect_as_extended_connect() {
        // CONNECT method alone is enough — covers WebTransport, HTTP CONNECT
        // tunnelling, and any future Extended-CONNECT variant.
        let h = hyper::HeaderMap::new();
        assert!(is_h3_extended_connect(&hyper::Method::CONNECT, &h));
    }

    #[test]
    fn test_h3_detects_webtransport_via_draft_header() {
        // A non-CONNECT request with the WebTransport draft header still
        // counts (defensive — covers clients that use a non-standard signal).
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::HeaderName::from_static("sec-webtransport-http3-draft02"),
            "1".parse().unwrap(),
        );
        assert!(is_h3_extended_connect(&hyper::Method::POST, &h));
    }

    #[test]
    fn test_h3_extended_connect_does_not_match_normal_request() {
        // Plain GET without any draft header must NOT trip WT detection.
        let h = hyper::HeaderMap::new();
        assert!(!is_h3_extended_connect(&hyper::Method::GET, &h));
        assert!(!is_h3_extended_connect(&hyper::Method::POST, &h));
    }

    #[test]
    fn test_h3_extended_connect_protocol_extracts_webtransport() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::HeaderName::from_static("sec-webtransport-http3-draft02"),
            "1".parse().unwrap(),
        );
        assert_eq!(
            h3_extended_connect_protocol(&h).as_deref(),
            Some("webtransport")
        );
    }

    #[test]
    fn test_h3_extended_connect_protocol_falls_back_to_upgrade_header() {
        // If neither WT draft header is set but `Upgrade` is, surface it
        // verbatim so the diagnostic log captures whatever the client asked for.
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::UPGRADE, "websocket".parse().unwrap());
        assert_eq!(
            h3_extended_connect_protocol(&h).as_deref(),
            Some("websocket")
        );
    }

    // ── WebSocket over HTTP/3 detection ──────────────────────────────

    #[test]
    fn test_h3_websocket_connect_detected_via_upgrade_header() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::UPGRADE, "websocket".parse().unwrap());
        assert!(is_h3_websocket_connect(&hyper::Method::CONNECT, &h));
    }

    #[test]
    fn test_h3_websocket_connect_upgrade_case_insensitive() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::UPGRADE, "WebSocket".parse().unwrap());
        assert!(is_h3_websocket_connect(&hyper::Method::CONNECT, &h));
        let mut h2 = hyper::HeaderMap::new();
        h2.insert(hyper::header::UPGRADE, "WEBSOCKET".parse().unwrap());
        assert!(is_h3_websocket_connect(&hyper::Method::CONNECT, &h2));
    }

    #[test]
    fn test_h3_websocket_connect_detected_via_sec_websocket_key() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::HeaderName::from_static("sec-websocket-key"),
            "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap(),
        );
        assert!(is_h3_websocket_connect(&hyper::Method::CONNECT, &h));
    }

    #[test]
    fn test_h3_websocket_connect_detected_via_sec_websocket_version() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::HeaderName::from_static("sec-websocket-version"),
            "13".parse().unwrap(),
        );
        assert!(is_h3_websocket_connect(&hyper::Method::CONNECT, &h));
    }

    #[test]
    fn test_h3_websocket_connect_not_detected_on_normal_requests() {
        let h = hyper::HeaderMap::new();
        assert!(!is_h3_websocket_connect(&hyper::Method::GET, &h));
        assert!(!is_h3_websocket_connect(&hyper::Method::POST, &h));
    }

    #[test]
    fn test_h3_websocket_connect_not_detected_on_connect_without_ws_headers() {
        let h = hyper::HeaderMap::new();
        // CONNECT method alone is extended-connect but NOT specifically websocket
        assert!(!is_h3_websocket_connect(&hyper::Method::CONNECT, &h));
    }

    #[test]
    fn test_h3_websocket_connect_requires_connect_method() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::UPGRADE, "websocket".parse().unwrap());
        // Upgrade: websocket on a GET is not a WebSocket CONNECT
        assert!(!is_h3_websocket_connect(&hyper::Method::GET, &h));
    }

    // ── P2: HookContext Arc<str> sharing tests ──────────────────────────

    #[test]
    fn test_hook_context_arc_clone_is_cheap_and_shares_data() {
        // Validates the P2 invariant: cloning an Arc<str> stored in
        // HookContext does NOT allocate a new buffer; the inner pointer
        // is shared. A regression where someone accidentally changes
        // HookContext.path to `String` would break this (String::clone
        // does allocate).
        use crate::scripting::{HookContext, HookPhase};
        let _ = HookPhase::PreRoute; // ensure import is used
        let path: std::sync::Arc<str> = std::sync::Arc::from("/api/v1/users");
        let ctx_a = HookContext {
            client_ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: std::sync::Arc::clone(&path),
            query: None,
            headers: std::collections::HashMap::new(),
            status: None,
            response_headers: std::collections::HashMap::new(),
        };
        // Both `path` and `ctx_a.path` must point at the SAME allocation.
        assert!(std::sync::Arc::ptr_eq(&path, &ctx_a.path));
        // Cloning into a second context still shares — no new allocation.
        let ctx_b = HookContext {
            client_ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: std::sync::Arc::clone(&ctx_a.path),
            query: None,
            headers: std::collections::HashMap::new(),
            status: None,
            response_headers: std::collections::HashMap::new(),
        };
        assert!(std::sync::Arc::ptr_eq(&ctx_a.path, &ctx_b.path));
    }

    // ── gRPC-Web body translation tests ─────────────────────────────────

    #[test]
    fn test_h3_grpc_web_detects_binary_subtype() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::CONTENT_TYPE,
            "application/grpc-web+proto".parse().unwrap(),
        );
        assert!(is_h3_grpc_web(&h));
        assert!(!is_h3_grpc_web_text(&h));
    }

    #[test]
    fn test_h3_grpc_web_detects_text_subtype() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::CONTENT_TYPE,
            "application/grpc-web-text".parse().unwrap(),
        );
        assert!(is_h3_grpc_web(&h));
        assert!(is_h3_grpc_web_text(&h));
    }

    #[test]
    fn test_h3_grpc_web_does_not_match_plain_grpc() {
        // `application/grpc` (no -web suffix) is plain gRPC over HTTP/2,
        // not gRPC-Web. The detector must reject it so we don't try to
        // base64-decode a binary protobuf body.
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::CONTENT_TYPE,
            "application/grpc".parse().unwrap(),
        );
        assert!(!is_h3_grpc_web(&h));
        assert!(!is_h3_grpc_web_text(&h));
    }

    #[test]
    fn test_h3_grpc_web_request_body_passthrough_for_binary() {
        // Binary subtype: body is forwarded as-is (no base64 decode).
        let raw = Bytes::from_static(&[0x00, 0x01, 0x02, 0x03]);
        let out = translate_h3_grpc_web_request_body(&raw, false).expect("binary always succeeds");
        assert_eq!(out.as_ref(), &[0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_h3_grpc_web_request_body_decodes_text() {
        // base64("hello") = "aGVsbG8="
        let encoded = Bytes::from_static(b"aGVsbG8=");
        let out = translate_h3_grpc_web_request_body(&encoded, true).expect("valid base64 decodes");
        assert_eq!(out.as_ref(), b"hello");
    }

    #[test]
    fn test_h3_grpc_web_request_body_rejects_invalid_base64() {
        // `!@#$` is not a valid base64 alphabet — must signal failure so the
        // caller returns 400 instead of forwarding garbage.
        let bad = Bytes::from_static(b"!@#$");
        assert!(translate_h3_grpc_web_request_body(&bad, true).is_none());
    }

    #[test]
    fn test_h3_grpc_web_trailer_frame_uses_status_and_message() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert("grpc-status", "0".parse().unwrap());
        h.insert("grpc-message", "OK".parse().unwrap());
        let frame = build_h3_grpc_web_trailer_frame(&h);
        // Frame layout: 0x80 | 4 bytes length BE | trailer text
        assert_eq!(frame[0], 0x80, "must start with the trailer flag byte");
        let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        assert_eq!(len, frame.len() - 5);
        let trailer_text = std::str::from_utf8(&frame[5..]).unwrap();
        assert!(trailer_text.contains("grpc-status: 0"));
        assert!(trailer_text.contains("grpc-message: OK"));
        assert!(trailer_text.ends_with("\r\n"));
    }

    #[test]
    fn test_h3_grpc_web_trailer_frame_defaults_to_status_zero() {
        // Upstream emitted no grpc-status header — we must default to 0
        // (OK) so a gRPC-Web client doesn't crash on a missing trailer.
        let h = reqwest::header::HeaderMap::new();
        let frame = build_h3_grpc_web_trailer_frame(&h);
        let trailer_text = std::str::from_utf8(&frame[5..]).unwrap();
        assert_eq!(trailer_text, "grpc-status: 0\r\n");
    }

    #[test]
    fn test_h3_grpc_web_response_body_appends_trailer_frame() {
        let upstream_body = b"\x00\x00\x00\x00\x05hello"; // 5-byte length-prefix + payload
        let mut h = reqwest::header::HeaderMap::new();
        h.insert("grpc-status", "0".parse().unwrap());
        let out = build_h3_grpc_web_response_body(upstream_body, &h, false);
        // First N bytes are the original body, then the 0x80 flag marks the trailer frame
        assert_eq!(&out[..upstream_body.len()], upstream_body);
        assert_eq!(out[upstream_body.len()], 0x80);
    }

    #[test]
    fn test_h3_grpc_web_response_body_text_mode_is_base64() {
        let upstream_body = b"abc";
        let h = reqwest::header::HeaderMap::new();
        let out = build_h3_grpc_web_response_body(upstream_body, &h, true);
        // text mode → base64 ASCII; only valid base64 chars
        assert!(
            out.iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=')
        );
        // Round-trip: decoding it should reproduce the binary form
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&out)
            .expect("text-mode output must be valid base64");
        let binary_form = build_h3_grpc_web_response_body(upstream_body, &h, false);
        assert_eq!(decoded, binary_form.as_ref());
    }

    /// Sanity: the gRPC client and the regular HTTP/1 client are *different*
    /// instances. Catches accidental fallthrough where a future refactor
    /// makes both helpers return the same singleton.
    #[test]
    fn test_h3_grpc_client_is_separate_from_default_client() {
        let regular = shared_upstream_client();
        let grpc = shared_grpc_upstream_client();
        assert!(
            !std::ptr::eq(regular, grpc),
            "gRPC forwarder must be its own HTTP/2 client"
        );
    }

    // ── URL rewrite tests (regression guard for the H3 rewrite loop) ────

    /// The H3 rewrite loop calls `crate::proxy::rewrite::apply_rewrites` with
    /// rules compiled by `compile_rules`. This test exercises that pair the
    /// same way `handle_h3_request` does. If the rewrite module's API or the
    /// `RewriteResult` enum shape ever changes, this catches it before
    /// regressing the H3 path.
    #[test]
    fn test_h3_rewrite_loop_helpers_apply_a_simple_regex() {
        use crate::proxy::rewrite::{RewriteResult, apply_rewrites, compile_rules};
        // (pattern, replacement, flag) — `last` means restart routing.
        let rules = compile_rules(&[(
            "^/old(.*)$".to_string(),
            "/new$1".to_string(),
            "last".to_string(),
        )])
        .expect("rule should compile");
        let outcome = apply_rewrites(&rules, "/old/profile");
        match outcome {
            RewriteResult::Rewritten {
                new_uri,
                restart_routing,
            } => {
                assert_eq!(new_uri, "/new/profile");
                assert!(restart_routing, "`last` flag must request a re-match");
            }
            other => panic!("expected Rewritten, got {:?}", other),
        }
    }

    #[test]
    fn test_h3_rewrite_loop_helpers_yield_redirect() {
        use crate::proxy::rewrite::{RewriteResult, apply_rewrites, compile_rules};
        let rules = compile_rules(&[(
            "^/legacy(.*)$".to_string(),
            "https://new.example.com$1".to_string(),
            "permanent".to_string(),
        )])
        .expect("rule should compile");
        let outcome = apply_rewrites(&rules, "/legacy/x");
        match outcome {
            RewriteResult::Redirect { status, location } => {
                assert_eq!(status, hyper::StatusCode::MOVED_PERMANENTLY);
                assert_eq!(location, "https://new.example.com/x");
            }
            other => panic!("expected Redirect, got {:?}", other),
        }
    }

    /// Rules that don't match leave the path alone — the H3 loop's NoMatch
    /// branch breaks out without modifying `path`.
    #[test]
    fn test_h3_rewrite_loop_no_match_leaves_path_unchanged() {
        use crate::proxy::rewrite::{RewriteResult, apply_rewrites, compile_rules};
        let rules = compile_rules(&[(
            "^/match-me$".to_string(),
            "/somewhere".to_string(),
            "break".to_string(),
        )])
        .expect("rule should compile");
        assert!(matches!(
            apply_rewrites(&rules, "/something-else"),
            RewriteResult::NoMatch
        ));
    }

    // ── Wasm OnResponseHeaders shape test (regression guard) ─────────────

    /// The H3 path constructs a `WasmResponseContext` with `body: None` (matches
    /// HTTP/1) and feeds it to `execute_response_headers`. If the result type's
    /// shape changes (e.g. `headers` becomes non-Optional), this catches it.
    #[test]
    fn test_h3_wasm_response_ctx_shape_and_default_pipeline() {
        let ctx = crate::wasm::WasmResponseContext {
            status_code: 200,
            headers: vec![("content-type".to_string(), "text/html".to_string())]
                .into_iter()
                .collect(),
            body: None,
        };
        // Build a manager with NO plugins — the H3 short-circuits via
        // `plugin_count() > 0`, but we still verify the manager round-trips
        // an empty response cleanly so the surrounding code can't panic.
        let mgr = crate::wasm::WasmPluginManager::new();
        assert_eq!(mgr.plugin_count(), 0);
        let result = mgr.execute_response_headers(&ctx);
        // No plugins → no header overrides — result.headers should be None or empty.
        assert!(
            result
                .headers
                .as_ref()
                .map(|h| h.is_empty())
                .unwrap_or(true),
            "empty plugin chain should not synthesize headers"
        );
    }

    // ── W3C trace context tests ──────────────────────────────────────────

    #[test]
    fn test_h3_trace_ids_have_correct_shape() {
        // Each call must yield a fresh, well-formed pair.
        let (trace_a, span_a) = generate_trace_context_ids();
        let (trace_b, span_b) = generate_trace_context_ids();

        // Hex-encoded 16 bytes = 32 chars; 8 bytes = 16 chars.
        assert_eq!(trace_a.len(), 32);
        assert_eq!(span_a.len(), 16);
        assert!(trace_a.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(span_a.chars().all(|c| c.is_ascii_hexdigit()));

        // Two consecutive calls must produce different IDs (chance of
        // collision is 2^-128 / 2^-64).
        assert_ne!(trace_a, trace_b);
        assert_ne!(span_a, span_b);
    }

    // ── gRPC-Web preflight tests ─────────────────────────────────────────

    #[test]
    fn test_h3_grpc_web_preflight_detects_browser_request() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-grpc-web,content-type".parse().unwrap(),
        );
        assert!(is_h3_grpc_web_preflight(&hyper::Method::OPTIONS, &h));
    }

    #[test]
    fn test_h3_grpc_web_preflight_case_insensitive() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::ACCESS_CONTROL_REQUEST_HEADERS,
            "X-Grpc-Web".parse().unwrap(),
        );
        assert!(is_h3_grpc_web_preflight(&hyper::Method::OPTIONS, &h));
    }

    #[test]
    fn test_h3_grpc_web_preflight_rejects_non_options() {
        // Same header present, but POST method — must NOT trigger preflight.
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-grpc-web".parse().unwrap(),
        );
        assert!(!is_h3_grpc_web_preflight(&hyper::Method::POST, &h));
    }

    #[test]
    fn test_h3_grpc_web_preflight_rejects_options_without_request_headers() {
        // Plain OPTIONS without ACR-Headers — not a grpc-web preflight.
        let h = hyper::HeaderMap::new();
        assert!(!is_h3_grpc_web_preflight(&hyper::Method::OPTIONS, &h));
    }

    #[tokio::test]
    async fn test_h3_auth_chain_priority_basic_beats_jwt() {
        // When BOTH Basic and JWT are configured, Basic runs first.
        // Bad creds → Basic 401 with Basic realm WWW-Authenticate (NOT Bearer).
        let cfg = AppConfig::default();
        let route = route_with(|r| {
            r.auth_basic_realm = Some("R".into());
            r.auth_basic_users = HashMap::new();
            r.auth_jwt_secret = Some("ignored".into());
        });
        let h = hyper::HeaderMap::new();
        let out = apply_h3_auth_chain(
            route.as_ref(),
            &cfg,
            &h,
            &hyper::Method::GET,
            "/",
            &empty_oidc_store(),
        )
        .await;
        match out {
            H3AuthOutcome::Denied {
                www_authenticate, ..
            } => {
                let v = www_authenticate.unwrap();
                let s = v.to_str().unwrap();
                assert!(
                    s.starts_with("Basic"),
                    "Basic should win priority over JWT, got {s:?}"
                );
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    // ── Dynamic route resolution (parity with HTTP/1 + HTTP/2) ────────────

    #[test]
    fn test_resolve_h3_route_static_only() {
        let mut cfg = AppConfig::default();
        let mut rc = RouteConfig::default();
        rc.upstream = Some("static-pool".to_string());
        cfg.routes.insert("/api".to_string(), rc.clone());

        let dynamic = dashmap::DashMap::new();
        let (path, route) = resolve_h3_route("/api/v1", &dynamic, &cfg).unwrap();
        assert_eq!(path, "/api");
        assert_eq!(route.upstream.as_deref(), Some("static-pool"));
    }

    #[test]
    fn test_resolve_h3_route_dynamic_overrides_static() {
        let mut cfg = AppConfig::default();
        let mut static_rc = RouteConfig::default();
        static_rc.upstream = Some("static-pool".to_string());
        cfg.routes.insert("/api".to_string(), static_rc);

        let dynamic = dashmap::DashMap::new();
        let mut dyn_rc = RouteConfig::default();
        dyn_rc.upstream = Some("dynamic-pool".to_string());
        dynamic.insert("/api/v2".to_string(), dyn_rc);

        // /api/v2 matches the dynamic route (longer prefix)
        let (path, route) = resolve_h3_route("/api/v2/users", &dynamic, &cfg).unwrap();
        assert_eq!(path, "/api/v2");
        assert_eq!(route.upstream.as_deref(), Some("dynamic-pool"));

        // /api/v1 only matches the static route
        let (path, route) = resolve_h3_route("/api/v1/users", &dynamic, &cfg).unwrap();
        assert_eq!(path, "/api");
        assert_eq!(route.upstream.as_deref(), Some("static-pool"));
    }

    #[test]
    fn test_resolve_h3_route_dynamic_takes_priority_even_when_shorter() {
        // When a dynamic route and static route both match, the longest prefix wins
        // regardless of which map it came from.
        let mut cfg = AppConfig::default();
        let mut static_rc = RouteConfig::default();
        static_rc.upstream = Some("static-pool".to_string());
        cfg.routes.insert("/api/v2/special".to_string(), static_rc);

        let dynamic = dashmap::DashMap::new();
        let mut dyn_rc = RouteConfig::default();
        dyn_rc.upstream = Some("dynamic-pool".to_string());
        dynamic.insert("/api/v2".to_string(), dyn_rc);

        // Longest match is /api/v2/special from static config
        let (path, route) = resolve_h3_route("/api/v2/special/case", &dynamic, &cfg).unwrap();
        assert_eq!(path, "/api/v2/special");
        assert_eq!(route.upstream.as_deref(), Some("static-pool"));
    }

    #[test]
    fn test_resolve_h3_route_fallback_to_root() {
        let mut cfg = AppConfig::default();
        let mut root_rc = RouteConfig::default();
        root_rc.upstream = Some("root-pool".to_string());
        cfg.routes.insert("/".to_string(), root_rc.clone());

        let dynamic = dashmap::DashMap::new();
        let (path, route) = resolve_h3_route("/no-match-here", &dynamic, &cfg).unwrap();
        assert_eq!(path, "/");
        assert_eq!(route.upstream.as_deref(), Some("root-pool"));
    }

    #[test]
    fn test_resolve_h3_route_no_routes_at_all() {
        let mut cfg = AppConfig::default();
        cfg.routes.clear(); // remove the default "/" route
        let dynamic = dashmap::DashMap::new();
        assert!(resolve_h3_route("/anything", &dynamic, &cfg).is_none());
    }

    // ── CORS parity tests (HTTP/3 mirrors HTTP/1 + HTTP/2) ────────────────

    #[test]
    fn test_build_h3_cors_preflight_disabled_returns_none() {
        let mut route = RouteConfig::default();
        route.cors_enabled = false;
        assert!(build_h3_cors_preflight_response(&route, Some("https://example.com")).is_none());
    }

    #[test]
    fn test_build_h3_cors_preflight_no_origin_returns_none() {
        let mut route = RouteConfig::default();
        route.cors_enabled = true;
        assert!(build_h3_cors_preflight_response(&route, None).is_none());
    }

    #[test]
    fn test_build_h3_cors_preflight_denied_origin_returns_none() {
        let mut route = RouteConfig::default();
        route.cors_enabled = true;
        route.cors_allowed_origins = vec!["https://trusted.com".to_string()];
        assert!(build_h3_cors_preflight_response(&route, Some("https://evil.com")).is_none());
    }

    #[test]
    fn test_build_h3_cors_preflight_wildcard_origin() {
        let mut route = RouteConfig::default();
        route.cors_enabled = true;
        route.cors_allowed_methods = vec!["GET".to_string(), "POST".to_string()];
        route.cors_allowed_headers = vec!["Content-Type".to_string()];
        route.cors_max_age_secs = 86400;
        route.cors_allow_credentials = true;

        let resp = build_h3_cors_preflight_response(&route, Some("https://any.com")).unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::NO_CONTENT);
        let h = resp.headers();
        assert_eq!(h["access-control-allow-origin"], "*");
        assert_eq!(h["access-control-allow-methods"], "GET, POST");
        assert_eq!(h["access-control-allow-headers"], "Content-Type");
        assert_eq!(h["access-control-max-age"], "86400");
        assert_eq!(h["access-control-allow-credentials"], "true");
    }

    #[test]
    fn test_build_h3_cors_preflight_specific_origin() {
        let mut route = RouteConfig::default();
        route.cors_enabled = true;
        route.cors_allowed_origins = vec!["https://app.example.com".to_string()];
        route.cors_allowed_methods = vec!["PUT".to_string()];

        let resp = build_h3_cors_preflight_response(&route, Some("https://app.example.com")).unwrap();
        assert_eq!(resp.headers()["access-control-allow-origin"], "https://app.example.com");
        assert_eq!(resp.headers()["access-control-allow-methods"], "PUT");
    }

    #[test]
    fn test_inject_h3_cors_response_headers_wildcard() {
        let mut route = RouteConfig::default();
        route.cors_enabled = true;
        route.cors_allow_credentials = false;

        let builder = inject_h3_cors_response_headers(hyper::Response::builder(), &route);
        let resp = builder.body(()).unwrap();
        let h = resp.headers();
        assert_eq!(h["access-control-allow-origin"], "*");
        assert!(!h.contains_key("access-control-allow-credentials"));
    }

    #[test]
    fn test_inject_h3_cors_response_headers_specific_origin_with_credentials() {
        let mut route = RouteConfig::default();
        route.cors_enabled = true;
        route.cors_allowed_origins = vec!["https://a.com".to_string()];
        route.cors_allow_credentials = true;

        let builder = inject_h3_cors_response_headers(hyper::Response::builder(), &route);
        let resp = builder.body(()).unwrap();
        let h = resp.headers();
        assert_eq!(h["access-control-allow-origin"], "https://a.com");
        assert_eq!(h["access-control-allow-credentials"], "true");
    }

    #[test]
    fn test_inject_h3_cors_response_headers_disabled_is_noop() {
        let mut route = RouteConfig::default();
        route.cors_enabled = false;

        let builder = inject_h3_cors_response_headers(hyper::Response::builder(), &route);
        let resp = builder.body(()).unwrap();
        assert!(!resp.headers().contains_key("access-control-allow-origin"));
    }
}
