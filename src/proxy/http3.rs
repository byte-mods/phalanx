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
use bytes::Bytes;
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
use crate::middleware::ResponseCache;
use crate::routing::UpstreamManager;

/// Starts the HTTP/3 QUIC server on the configured UDP bind address.
pub async fn start_http3_proxy(
    bind_addr: &str,
    app_config: Arc<AppConfig>,
    upstreams: Arc<UpstreamManager>,
    metrics: Arc<ProxyMetrics>,
    _cache: Arc<ResponseCache>,
    _ai_engine: Arc<dyn AiRouter>,
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

                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!("QUIC incoming connection failed: {}", e);
                            return;
                        }
                    };
                    debug!("QUIC connection from {:?}", conn.remote_address());

                    // Build h3 server connection (generic over Bytes buf)
                    let h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
                        match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
                            Ok(c) => c,
                            Err(e) => {
                                debug!("HTTP/3 session setup failed: {}", e);
                                return;
                            }
                        };

                    serve_h3_connection(h3_conn, upstreams_c, config_c, metrics_c).await;
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
    upstreams: Arc<UpstreamManager>,
    app_config: Arc<AppConfig>,
    metrics: Arc<ProxyMetrics>,
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
                tokio::spawn(async move {
                    handle_h3_request(req, stream, u, c, m).await;
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

/// Handle one HTTP/3 request: proxy through HTTP/1.1 to an upstream backend.
async fn handle_h3_request(
    req: hyper::Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    upstreams: Arc<UpstreamManager>,
    app_config: Arc<AppConfig>,
    metrics: Arc<ProxyMetrics>,
) {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let start = std::time::Instant::now();

    debug!("HTTP/3 {} {}", method, path);

    // Route matching — longest-prefix match
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

    // Resolve backend from pool
    let pool = upstreams
        .get_pool(&pool_name)
        .or_else(|| upstreams.get_pool("default"));

    let backend = match pool.as_ref().and_then(|p| p.get_next_backend(None, None)) {
        Some(b) => b,
        None => {
            send_h3_error(&mut stream, StatusCode::BAD_GATEWAY).await;
            return;
        }
    };

    // Build target URL and forward over HTTP/1.1
    let backend_url = format!("http://{}{}", backend.config.address, path);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

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

    let method_str = method.as_str().to_string();
    let backend_resp = match client
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
            &backend_url,
        )
        .headers(forward_headers)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("HTTP/3 upstream error for {}: {}", backend_url, e);
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
    }

    // Prometheus counters
    metrics
        .http_requests_total
        .with_label_values(&[&method_str, &status_u16.to_string(), &pool_name])
        .inc();
    metrics
        .http_request_duration
        .with_label_values(&[&method_str, &pool_name])
        .observe(latency_secs);

    // Collect response body from backend
    let body_bytes = match backend_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to read HTTP/3 backend body: {}", e);
            send_h3_error(&mut stream, StatusCode::BAD_GATEWAY).await;
            return;
        }
    };

    // Send HTTP/3 response headers
    let response = hyper::Response::builder()
        .status(status)
        .header("x-proxy-by", "Phalanx/HTTP3")
        .body(())
        .unwrap();

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
