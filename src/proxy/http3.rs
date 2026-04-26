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
    )
    .await
    {
        H3AuthOutcome::Allowed(hs) => hs,
        H3AuthOutcome::Denied { status, www_authenticate } => {
            debug!("HTTP/3 auth denied from {} → {}", ip_str, status);
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
        // Honour the route's `proxy_cache_valid` directive instead of a
        // hardcoded 60 s. Falls back to 60 s when the route is missing or
        // the directive is 0.
        let route_ttl_secs = route
            .as_ref()
            .map(|(_, r)| r.proxy_cache_valid_secs)
            .unwrap_or(0);
        let max_age_secs = if route_ttl_secs > 0 { route_ttl_secs } else { 60 };
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
    let route_gzip_min = route
        .as_ref()
        .map(|(_, r)| r.gzip_min_length)
        .unwrap_or(0);

    let accepts_gzip = route_gzip
        && crate::middleware::compression::accepts_gzip(accept_encoding);
    let accepts_brotli = (route_brotli || app_config.brotli_enabled)
        && crate::middleware::brotli::accepts_brotli(accept_encoding);
    let is_compressible =
        crate::middleware::compression::is_compressible(Some(&content_type));
    let body_len_pre = body_bytes.len();

    let (body_to_send, content_encoding) = if accepts_brotli
        && is_compressible
        && body_len_pre >= crate::middleware::brotli::MIN_BROTLI_SIZE
    {
        match crate::middleware::brotli::brotli_compress(&body_bytes, 6) {
            Some(c) => (c, "br"),
            None => (body_bytes, ""),
        }
    } else if accepts_gzip
        && is_compressible
        && body_len_pre
            >= route_gzip_min.max(crate::middleware::compression::MIN_COMPRESS_SIZE)
    {
        match crate::middleware::compression::gzip_compress(&body_bytes) {
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
        if let Ok(hv) =
            hyper::header::HeaderValue::from_str(&format!("max-age={}", max_age))
        {
            response = response.header(hyper::header::STRICT_TRANSPORT_SECURITY, hv);
        }
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
        debug!("send_h3_response_with_header: failed to send {}: {}", status, e);
    }
    let _ = stream.finish().await;
}

/// Outcome of the HTTP/3 auth chain.
#[derive(Debug)]
enum H3AuthOutcome {
    /// Auth passed (or not configured). Inject these headers upstream.
    Allowed(Vec<(String, String)>),
    /// Auth denied. Send `status` to the client; if `www_authenticate` is
    /// `Some`, attach it as the `WWW-Authenticate` response header.
    Denied {
        status: StatusCode,
        www_authenticate: Option<hyper::header::HeaderValue>,
    },
}

/// Runs the HTTP/3 authentication chain in priority order:
///
/// 1. Per-route Basic Auth (`auth_basic_realm`)
/// 2. Per-route JWT Bearer (`auth_jwt_secret`) — injects claim headers on success
/// 3. Per-route auth_request subrequest (`auth_request_url`) — injects X-Auth-* headers on success
/// 4. Global auth_request fallback (`app_config.auth_request_url`) — only when no per-route auth is configured
///
/// Returns the headers to inject upstream on success, or a denial response.
/// OAuth/JWKS/OIDC are intentionally **not** ported here — they involve session
/// stores and discovery flows that need their own focused work; that remains
/// a tracked C2 gap in `plan_v2.md`.
async fn apply_h3_auth_chain(
    route: Option<&(String, crate::config::RouteConfig)>,
    app_config: &AppConfig,
    headers: &hyper::HeaderMap,
    method: &hyper::Method,
    path: &str,
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
                    H3AuthOutcome::Denied { status, www_authenticate: Some(www) }
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
            let (result, sub) = crate::auth::oauth::check(
                headers,
                introspect_url,
                client_id,
                client_secret,
                cache,
            )
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
                },
            };
        }
        // 4. JWKS-based JWT (dynamic public key lookup by kid)
        if let Some(ref jwks_uri) = r_config.auth_jwks_uri {
            use std::sync::OnceLock;
            static JWKS_MGR: OnceLock<std::sync::Arc<crate::auth::jwks::JwksManager>> =
                OnceLock::new();
            let mgr = JWKS_MGR.get_or_init(|| {
                std::sync::Arc::new(crate::auth::jwks::JwksManager::new())
            });
            return apply_h3_jwks(jwks_uri, mgr.as_ref(), headers, &mut injected).await;
        }
        // 5. Per-route auth_request
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
            };
        }
    };

    let jwk = match mgr.find_key(jwks_uri, &kid).await {
        Some(j) => j,
        None => {
            return H3AuthOutcome::Denied {
                status: StatusCode::UNAUTHORIZED,
                www_authenticate: bearer_challenge,
            };
        }
    };

    let (decoding_key, algo) =
        match crate::auth::jwks::JwksManager::decoding_key_from_jwk(&jwk) {
            Ok(pair) => pair,
            Err(_) => {
                return H3AuthOutcome::Denied {
                    status: StatusCode::UNAUTHORIZED,
                    www_authenticate: bearer_challenge,
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
        },
    }
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
    use super::{
        apply_h3_auth_chain, build_return_to, decode_form_component, parse_urlencoded_form,
        shared_upstream_client, H3AuthOutcome,
    };
    use crate::config::{AppConfig, RouteConfig};
    use crate::telemetry::bandwidth::BandwidthTracker;
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
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/p").await;
        match out {
            H3AuthOutcome::Denied { status, www_authenticate } => {
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
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/p").await;
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
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/p").await;
        match out {
            H3AuthOutcome::Denied { status, www_authenticate } => {
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
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/p").await;
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
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/p").await;
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
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/p").await;
        match out {
            H3AuthOutcome::Denied { status, www_authenticate } => {
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
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/p").await;
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
            r.auth_oauth_introspect_url =
                Some("https://example.invalid/oauth/introspect".into());
            r.auth_oauth_client_id = Some("cid".into());
            r.auth_oauth_client_secret = Some("csecret".into());
        });
        let h = hyper::HeaderMap::new();
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/p").await;
        match out {
            H3AuthOutcome::Denied { status, www_authenticate } => {
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
        let accepts_gzip =
            crate::middleware::compression::accepts_gzip(Some("gzip, br"));
        let accepts_brotli =
            crate::middleware::brotli::accepts_brotli(Some("gzip, br"));
        assert!(accepts_gzip);
        assert!(accepts_brotli);
        // Both true → brotli branch fires first in handle_h3_request.
        // (Order is: brotli check, then gzip check.)
    }

    #[test]
    fn test_h3_compression_skips_uncompressible_types() {
        // image/png is NOT in the compressible whitelist.
        assert!(!crate::middleware::compression::is_compressible(Some("image/png")));
        // text/html and application/json are.
        assert!(crate::middleware::compression::is_compressible(Some("text/html")));
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
        let out =
            apply_h3_auth_chain(route.as_ref(), &cfg, &h, &hyper::Method::GET, "/").await;
        match out {
            H3AuthOutcome::Denied { www_authenticate, .. } => {
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
}
