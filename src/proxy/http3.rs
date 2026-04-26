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
            .unwrap_or_default()
    })
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

                    // Build h3 server connection (generic over Bytes buf)
                    let h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
                        match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
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
) {
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
    req: hyper::Request<()>,
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
) {
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(String::from);
    let method = req.method().clone();
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("_");
    let start = std::time::Instant::now();
    let ip = remote_addr.ip();
    let ip_str = ip.to_string();
    // Bandwidth: per-request count for in-bytes (approx: body so far; headers small)
    bandwidth.protocol("http3").inc_requests();

    debug!("HTTP/3 {} {}", method, path);

    // ── Rate limiting ──
    if !rate_limiter.check_ip(ip).await {
        metrics
            .rate_limit_rejections
            .with_label_values(&["ip_or_global"])
            .inc();
        send_h3_error(&mut stream, StatusCode::TOO_MANY_REQUESTS).await;
        return;
    }

    // ── Zone connection limiting (RAII guard releases on drop) ──
    let _zone_guard = {
        if !zone_limiter.acquire_connection(&ip_str) {
            send_h3_error(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await;
            return;
        }
        ConnectionGuard::new(Arc::clone(&zone_limiter), ip_str.clone())
    };

    // ── Request body extraction ──
    let request_body = match read_h3_request_body(&mut stream).await {
        Ok(body) => body,
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

    let query_opt = query.as_deref();
    let user_agent = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
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
            user_agent_len: user_agent.map(|ua| ua.len()).unwrap_or(0),
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
            send_h3_error(&mut stream, sc).await;
            return;
        }
    }

    // ── PreRoute hooks (Rhai scripting) ──
    if hook_engine.has_hooks(HookPhase::PreRoute) {
        let hook_ctx = HookContext {
            client_ip: ip_str.clone(),
            method: method.as_str().to_string(),
            path: path.clone(),
            query: query.clone(),
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
                let sc = StatusCode::from_u16(status)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                send_h3_error(&mut stream, sc).await;
                return;
            }
        }
    }

    // ── Bot detection / CAPTCHA challenge ──
    if let Some(manager) = captcha_manager.as_ref() {
        match manager.evaluate(&ip_str, user_agent.unwrap_or("")) {
            crate::waf::bot::CaptchaAction::Allow => {}
            crate::waf::bot::CaptchaAction::Block => {
                metrics
                    .waf_blocks_total
                    .with_label_values(&["captcha_bot_block"])
                    .inc();
                send_h3_error(&mut stream, StatusCode::FORBIDDEN).await;
                return;
            }
            crate::waf::bot::CaptchaAction::Challenge => {
                let return_to = build_return_to(&path, query_opt);
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
        if let crate::waf::WafAction::Block(reason) = waf.inspect(&ip_str, &path, query_opt, user_agent) {
            warn!("WAF blocked HTTP/3 request from {}: {}", ip_str, reason);
            metrics.waf_blocks_total.with_label_values(&[&reason]).inc();
            send_h3_error(&mut stream, StatusCode::FORBIDDEN).await;
            return;
        }
        if matches!(method, hyper::Method::POST | hyper::Method::PUT | hyper::Method::PATCH) {
            if let Ok(body_text) = std::str::from_utf8(&request_body) {
                if let crate::waf::WafAction::Block(reason) = waf.inspect_body(&ip_str, body_text) {
                    warn!("WAF blocked HTTP/3 body from {}: {}", ip_str, reason);
                    metrics.waf_blocks_total.with_label_values(&[&reason]).inc();
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
                    ip_str,
                    result.country_code
                );
                send_h3_error(&mut stream, StatusCode::FORBIDDEN).await;
                return;
            }
            Some(result)
        } else {
            None
        }
    } else {
        None
    };

    // ── Response cache lookup (GET only) ──
    if method == hyper::Method::GET {
        let cache_key = build_cache_key("GET", host, &path, query.as_deref(), &[]);
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

    // ── Route matching — longest-prefix match ──
    let route = {
        let mut best: Option<(String, crate::config::RouteConfig)> = None;
        let mut best_len = 0usize;
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

    let pool_name = route
        .as_ref()
        .and_then(|(_, r)| r.upstream.clone())
        .unwrap_or_else(|| "default".to_string());

    // ── Mirror pool resolution (route-level overrides global) ──
    let mirror_pool = route
        .as_ref()
        .and_then(|(_, r)| r.mirror_pool.clone())
        .or_else(|| app_config.mirror_pool.clone());

    // ── PreUpstream hooks ──
    if hook_engine.has_hooks(HookPhase::PreUpstream) {
        let hook_ctx = HookContext {
            client_ip: ip_str.clone(),
            method: method.as_str().to_string(),
            path: path.clone(),
            query: query.clone(),
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
                let sc = StatusCode::from_u16(status)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
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
        match sticky_preferred
            .or_else(|| p.get_next_backend(None, Some(Arc::clone(&ai_engine))))
        {
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
    let client = shared_upstream_client();

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

    let method_str = method.as_str().to_string();
    // Bandwidth: in-bytes (request body)
    bandwidth.protocol("http3").add_in(request_body.len() as u64);
    bandwidth.pool(&pool_name).add_in(request_body.len() as u64);

    // Only allocate mirror copies when there's actually a mirror pool configured
    let mirror_payload = mirror_pool.as_ref().map(|_| {
        (
            req.headers().clone(),
            Bytes::copy_from_slice(&request_body),
        )
    });

    let mut backend_request = client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
        &backend_url,
    );
    backend_request = backend_request
        .headers(forward_headers)
        .body(request_body);

    let backend_resp = match backend_request.send().await {
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
            .filter_map(|(k, v)| v.to_str().ok().map(|vs| (k.as_str().to_string(), vs.to_string())))
            .collect();
        let hook_ctx = crate::scripting::HookContext {
            client_ip: ip_str.clone(),
            method: method_str.clone(),
            path: path.clone(),
            query: None,
            headers: Default::default(),
            status: Some(status.as_u16()),
            response_headers: resp_hdrs,
        };
        for result in hook_engine.execute(crate::scripting::HookPhase::PostUpstream, &hook_ctx) {
            match result {
                crate::scripting::HookResult::Respond { status: s, .. } => {
                    let sc = hyper::StatusCode::from_u16(s).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
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
    let body_bytes = match backend_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to read HTTP/3 backend body: {}", e);
            send_h3_error(&mut stream, StatusCode::BAD_GATEWAY).await;
            return;
        }
    };

    // ── Cache GET 200 responses ──
    if method == hyper::Method::GET && status == StatusCode::OK {
        let cache_key = build_cache_key("GET", host, &path, query.as_deref(), &[]);
        cache
            .insert(
                cache_key,
                CacheEntry {
                    status: status_u16,
                    body: Bytes::copy_from_slice(&body_bytes),
                    content_type: content_type.clone(),
                    headers: vec![],
                    created_at: std::time::Instant::now(),
                    max_age: std::time::Duration::from_secs(60),
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

    // ── Send HTTP/3 response headers ──
    // Capture length before moving the body, so we can record bandwidth + log later
    let body_len = body_bytes.len() as u64;

    let mut response = hyper::Response::builder()
        .status(status)
        .header("x-proxy-by", "Phalanx/HTTP3")
        .header("content-type", content_type.as_str());

    if let Some(ref cookie_val) = sticky_cookie {
        response = response.header(hyper::header::SET_COOKIE, cookie_val.as_str());
    }

    let response = response.body(()).unwrap();

    if let Err(e) = stream.send_response(response).await {
        debug!("Failed to send HTTP/3 response headers: {}", e);
        return;
    }

    // Send body data
    if let Err(e) = stream.send_data(Bytes::from(body_bytes)).await {
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
    let user_agent_str = user_agent.unwrap_or("").to_string();
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
        trace_id: String::new(),
    });

    // ── Log hooks: post-response auditing ──
    if hook_engine.has_hooks(HookPhase::Log) {
        let log_ctx = HookContext {
            client_ip: ip_str,
            method: method_str,
            path,
            query,
            headers: Default::default(),
            status: Some(status_u16),
            response_headers: Default::default(),
        };
        hook_engine.execute(HookPhase::Log, &log_ctx);
    }
}

/// Reads the full request body from an HTTP/3 stream into a contiguous `Bytes` buffer.
/// Also drains any trailing headers (required by the h3 protocol to complete the stream).
async fn read_h3_request_body(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<Bytes, h3::error::StreamError> {
    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        if chunk.has_remaining() {
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            body.extend_from_slice(&bytes);
        }
    }
    let _ = stream.recv_trailers().await?;
    Ok(body.freeze())
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

    let form_values = parse_urlencoded_form(body.as_ref());
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
        debug!("send_h3_html_response: failed to send headers {}: {}", status, e);
        return;
    }
    if let Err(e) = stream.send_data(Bytes::from(html)).await {
        debug!("send_h3_html_response: failed to send body {}: {}", status, e);
        return;
    }
    let _ = stream.finish().await;
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

/// Parses a `application/x-www-form-urlencoded` body into a key-value map.
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

/// Reconstructs the original URL (path + query) for post-CAPTCHA redirect.
fn build_return_to(path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) if !q.is_empty() => format!("{}?{}", path, q),
        _ => path.to_string(),
    }
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

        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_pem.as_slice())
                .filter_map(|r| r.ok())
                .map(|c| c.into_owned())
                .collect();

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

    let mut tls_config = rustls::ServerConfig::builder()
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
    use super::{build_return_to, decode_form_component, parse_urlencoded_form, shared_upstream_client};
    use crate::config::AppConfig;
    use crate::telemetry::bandwidth::BandwidthTracker;
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
        assert_eq!(parsed.get("return_to").map(String::as_str), Some("/docs?a=1+2"));
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
    /// Required because `build_quic_tls_config` uses the default provider,
    /// which is installed lazily and panics if no provider has been chosen.
    fn ensure_crypto_provider() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
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
}
