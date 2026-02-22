use bytes::{Buf, Bytes, BytesMut};
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::middleware::CachedResponse;
use crate::middleware::compression;

pub mod executor;
pub mod fastcgi;
pub mod pool;
pub mod rewrite;
pub mod router;
pub mod tcp;
pub mod tls;
pub mod uwsgi;

use fastcgi::serve_fastcgi;
use rewrite::{RewriteResult, apply_rewrites, compile_rules};
use uwsgi::serve_uwsgi;

use crate::admin::ProxyMetrics;
use crate::ai::AiRouter;
use crate::config::AppConfig;
use crate::middleware::ResponseCache;
use crate::routing::UpstreamManager;
use crate::telemetry::access_log::{AccessLogEntry, AccessLogger};
use router::Protocol;

/// A wrapper around a standard Tokio `TcpStream` that can seamlessly replay
/// a sequence of bytes (the `buffer`) before yielding new bytes from the underlying stream.
/// This is used by the protocol sniffer which has to consume the first few bytes
/// to identify the protocol, but then must hand the connection off to a protocol handler
/// (like hyper for HTTP) which expects to see those bytes again.
pub struct PeekableStream {
    stream: TcpStream,
    buffer: BytesMut,
}

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

/// Constructs an HTTP 429 Too Many Requests response with a Retry-After header.
fn rate_limit_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Bytes::from_static(b"429 Too Many Requests\n");
    Response::builder()
        .status(hyper::StatusCode::TOO_MANY_REQUESTS)
        .header("Retry-After", "1")
        .header("Content-Type", "text/plain")
        .body(
            http_body_util::Full::new(body)
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Starts the primary universal multiplexer (Mux) proxy on the configured port.
/// This listener accepts raw TCP connections, sniffs the application layer protocol
/// (HTTP/1, HTTP/2/gRPC, TLS), and spawns appropriate async tasks to handle the requests.
pub async fn start_proxy(
    bind_addr: &str,
    app_config: Arc<AppConfig>,
    upstreams: Arc<UpstreamManager>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    _waf: Arc<crate::waf::WafEngine>,
    rate_limiter: Arc<crate::middleware::ratelimit::PhalanxRateLimiter>,
    _ai_engine: Arc<dyn AiRouter>,
    cache: Arc<ResponseCache>,
    metrics: Arc<ProxyMetrics>,
    access_logger: Arc<AccessLogger>,
    shutdown: CancellationToken,
) {
    let addr: SocketAddr = bind_addr.parse().expect("Invalid proxy bind address");
    let listener = TcpListener::bind(&addr).await.unwrap();
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
        let tls_acceptor_clone = tls_acceptor.clone();
        let waf_spawn_clone = Arc::clone(&_waf);
        let ai_spawn_clone = Arc::clone(&_ai_engine);
        let rl_clone = Arc::clone(&rate_limiter);
        let cache_clone = Arc::clone(&cache);
        let metrics_clone = Arc::clone(&metrics);
        let logger_clone = Arc::clone(&access_logger);

        // Spawn a new green thread per connection (Tokio task)
        tokio::spawn(async move {
            let mut prefix_buf = BytesMut::with_capacity(64);
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
            if !rl_clone.check_ip(peer.ip()) {
                match proto {
                    Protocol::Http1 | Protocol::Http2 => {
                        // Send a proper HTTP 429 response before closing
                        let peekable = PeekableStream {
                            stream,
                            buffer: prefix_buf,
                        };
                        let io = TokioIo::new(peekable);
                        let svc = service_fn(move |_req| async move {
                            Ok::<_, hyper::Error>(rate_limit_response())
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

            // Route execution based on protocol
            match proto {
                Protocol::Http1 => {
                    let io = TokioIo::new(peekable_stream);
                    let svc = service_fn(move |req| {
                        let upts = Arc::clone(&upstreams_clone);
                        let cfg = Arc::clone(&config_clone);
                        let waf_svc = Arc::clone(&waf_spawn_clone);
                        let ai_svc = Arc::clone(&ai_spawn_clone);
                        let cache_svc = Arc::clone(&cache_clone);
                        let metrics_svc = Arc::clone(&metrics_clone);
                        let logger_svc = Arc::clone(&logger_clone);
                        async move {
                            handle_http_request(
                                req,
                                peer,
                                upts,
                                cfg,
                                waf_svc,
                                ai_svc,
                                cache_svc,
                                metrics_svc,
                                logger_svc,
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
                    let svc = service_fn(move |req| {
                        let upts = Arc::clone(&upstreams_clone);
                        let cfg = Arc::clone(&config_clone);
                        let waf_svc = Arc::clone(&waf_spawn_clone);
                        let ai_svc = Arc::clone(&ai_spawn_clone);
                        let cache_svc = Arc::clone(&cache_clone);
                        let metrics_svc = Arc::clone(&metrics_clone);
                        let logger_svc = Arc::clone(&logger_clone);
                        async move {
                            handle_http2_request(
                                req,
                                peer,
                                upts,
                                cfg,
                                waf_svc,
                                ai_svc,
                                cache_svc,
                                metrics_svc,
                                logger_svc,
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
                    if let Some(acceptor) = tls_acceptor_clone {
                        match acceptor.accept(peekable_stream).await {
                            Ok(tls_stream) => {
                                let (io, alpn) = {
                                    let (_, session) = tls_stream.get_ref();
                                    let alpn = session.alpn_protocol().map(|p| p.to_vec());
                                    (TokioIo::new(tls_stream), alpn)
                                };

                                let is_h2 = alpn.as_deref() == Some(b"h2");

                                if is_h2 {
                                    let svc = service_fn(move |req| {
                                        let upts = Arc::clone(&upstreams_clone);
                                        let cfg = Arc::clone(&config_clone);
                                        let waf_svc = Arc::clone(&waf_spawn_clone);
                                        let ai_svc = Arc::clone(&ai_spawn_clone);
                                        let cache_svc = Arc::clone(&cache_clone);
                                        let metrics_svc = Arc::clone(&metrics_clone);
                                        let logger_svc = Arc::clone(&logger_clone);
                                        async move {
                                            handle_http2_request(
                                                req,
                                                peer,
                                                upts,
                                                cfg,
                                                waf_svc,
                                                ai_svc,
                                                cache_svc,
                                                metrics_svc,
                                                logger_svc,
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
                                    let svc = service_fn(move |req| {
                                        let upts = Arc::clone(&upstreams_clone);
                                        let cfg = Arc::clone(&config_clone);
                                        let waf_svc = Arc::clone(&waf_spawn_clone);
                                        let ai_svc = Arc::clone(&ai_spawn_clone);
                                        let cache_svc = Arc::clone(&cache_clone);
                                        let metrics_svc = Arc::clone(&metrics_clone);
                                        let logger_svc = Arc::clone(&logger_clone);
                                        async move {
                                            handle_http_request(
                                                req,
                                                peer,
                                                upts,
                                                cfg,
                                                waf_svc,
                                                ai_svc,
                                                cache_svc,
                                                metrics_svc,
                                                logger_svc,
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
async fn handle_http_request(
    mut req: Request<hyper::body::Incoming>,
    _peer: SocketAddr,
    upstreams: Arc<UpstreamManager>,
    app_config: Arc<AppConfig>,
    waf: Arc<crate::waf::WafEngine>,
    ai_engine: Arc<dyn crate::ai::AiRouter>,
    cache: Arc<ResponseCache>,
    metrics: Arc<ProxyMetrics>,
    access_logger: Arc<AccessLogger>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Path is mutable so rewrite rules can modify it before route dispatch
    let mut path = req.uri().path().to_string();

    debug!("Handling HTTP request: {}", path);
    let start_time = std::time::Instant::now();
    let method_str = req.method().to_string();

    // 0. WAF Inspection
    let ip_str = _peer.ip().to_string();
    let query = req.uri().query();
    let user_agent = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    // Capture Accept-Encoding before WAF check (needed later for compression)
    // Will be AND-ed with route.gzip config flag below.
    let client_accepts_gzip = compression::accepts_gzip(
        req.headers()
            .get(hyper::header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok()),
    );

    if let crate::waf::WafAction::Block(reason) = waf.inspect(&ip_str, &path, query, user_agent) {
        warn!("WAF blocked request from {}: {}", ip_str, reason);
        metrics.waf_blocks_total.with_label_values(&[&reason]).inc();
        return Ok(empty_response(hyper::StatusCode::FORBIDDEN));
    }

    // Check for WebSocket upgrade request
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
                let rules = compile_rules(&r_config.rewrite_rules);
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
    }

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
                return res.map(|r| {
                    r.map(|b| {
                        b.map_err(|_e| {
                            // Can't cast io::Error to hyper::Error natively
                            panic!(
                                "hyper::Error conversion bypassed on static stream read failure"
                            );
                        })
                        .boxed()
                    })
                });
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
                return res.map(|r| {
                    r.map(|b| {
                        b.map_err(|_e| {
                            // Convert fastcgi error
                            panic!("hyper::Error conversion bypassed on proxy stream failure");
                        })
                        .boxed()
                    })
                });
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
                return res.map(|r| {
                    r.map(|b| {
                        b.map_err(|_e| {
                            // Convert uwsgi error
                            panic!("hyper::Error conversion bypassed on proxy stream failure");
                        })
                        .boxed()
                    })
                });
            }

            r.upstream.clone().unwrap_or_else(|| host_name.to_string())
        }
        None => host_name.to_string(),
    };

    // ── Resolve gzip + cache flags from matched route config ──
    let (route_gzip, route_gzip_min, route_cache, route_cache_ttl) = match route {
        Some((_, r)) => (
            r.gzip,
            r.gzip_min_length,
            r.proxy_cache,
            r.proxy_cache_valid_secs,
        ),
        None => (false, 1024, false, 60),
    };
    let accepts_gzip = client_accepts_gzip && route_gzip;

    // ── Response Cache: lookup for GET requests ──
    let is_get = req.method() == hyper::Method::GET;
    let cache_key = if route_cache && is_get && !is_websocket {
        let ck = ResponseCache::cache_key("GET", host_name, &path, req.uri().query());
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
        None
    };

    let _ = (route_gzip_min, route_cache_ttl); // used below in slow-path

    // 2. Fetch healthy backend from pool manager
    let pool = upstreams
        .get_pool(pool_name.as_str())
        .or_else(|| upstreams.get_pool("default"));

    let backend = match &pool {
        Some(p) => match p.get_next_backend(Some(&_peer.ip()), Some(Arc::clone(&ai_engine))) {
            Some(b) => b,
            None => return Ok(empty_response(hyper::StatusCode::BAD_GATEWAY)),
        },
        None => return Ok(empty_response(hyper::StatusCode::NOT_FOUND)),
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

    // 4. Forward the request to physical backend IP
    backend.active_connections.fetch_add(1, Ordering::Relaxed);
    metrics.active_connections.inc();

    // Establish TCP connection to backend (using keepalive pool if enabled)
    let stream = match pool
        .as_ref()
        .unwrap()
        .connection_pool
        .acquire(&backend.config.address)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            error!(
                "Failed to connect to backend {}: {}",
                backend.config.address, e
            );
            backend.active_connections.fetch_sub(1, Ordering::Relaxed);
            return Ok(empty_response(hyper::StatusCode::SERVICE_UNAVAILABLE));
        }
    };

    let io = TokioIo::new(stream);

    // Perform hyper client handshake over the TCP connection
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(handshake) => handshake,
        Err(e) => {
            error!(
                "Handshake failed with backend {}: {}",
                backend.config.address, e
            );
            backend.active_connections.fetch_sub(1, Ordering::Relaxed);
            return Ok(empty_response(hyper::StatusCode::SERVICE_UNAVAILABLE));
        }
    };

    // Spawn the hyper connection driver task to manage IO asynchronously
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("Backend connection error: {:?}", e);
        }
    });

    // Send the proxy request
    let res = sender.send_request(req).await;
    // Client has responded locally, decrement active proxy connection count
    backend.active_connections.fetch_sub(1, Ordering::Relaxed);
    metrics.active_connections.dec();

    let backend_addr = backend.config.address.clone();

    match res {
        Ok(mut response) => {
            // Check if this is a 101 Switching Protocols response to our WebSocket upgrade
            let is_101 = response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS;
            if is_websocket && is_101 {
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

                                // Relay bytes bidirectionally
                                match tokio::io::copy_bidirectional(&mut client_io, &mut backend_io)
                                    .await
                                {
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

            if !should_compress && !should_cache {
                // Zero-Copy Fast Path: Map hyper::body::Incoming -> BoxBody
                let boxed_fast_path = response.map(|b| b.map_err(|e| e).boxed());

                access_logger.log(AccessLogEntry {
                    timestamp: chrono_timestamp(),
                    client_ip: ip_str,
                    method: method_str,
                    path,
                    status: status_code,
                    latency_ms: latency,
                    backend: backend_addr,
                    pool: pool_name.clone(),
                    bytes_sent: Default::default(), // Size is dynamic, streaming.
                    referer: String::new(),
                    user_agent: String::new(),
                });

                return Ok(boxed_fast_path);
            }

            // 7. Slow-Path (Memory Buffering) for Caching and Compression
            // Collect the full response body into memory
            let body_bytes = match http_body_util::BodyExt::collect(response.body_mut()).await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    let boxed = response.map(|b| b.map_err(|e| e).boxed());
                    return Ok(boxed);
                }
            };

            let body_len = body_bytes.len();

            // ── Cache Store: cache GET 200 responses ──
            if should_cache {
                if let Some(ref ck) = cache_key {
                    cache
                        .insert(
                            ck.clone(),
                            CachedResponse {
                                status: status_code,
                                body: body_bytes.clone(),
                                content_type: content_type.clone(),
                            },
                        )
                        .await;
                }
            }

            // ── Compression: gzip ──
            let (final_body, is_compressed) = if should_compress {
                match compression::gzip_compress(&body_bytes) {
                    Some(compressed) => (compressed, true),
                    None => (body_bytes, false),
                }
            } else {
                (body_bytes, false)
            };

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
                    hyper::header::HeaderValue::from_static("gzip"),
                );
                final_resp.headers_mut().insert(
                    hyper::header::HeaderName::from_static("vary"),
                    hyper::header::HeaderValue::from_static("Accept-Encoding"),
                );
                final_resp
                    .headers_mut()
                    .remove(hyper::header::CONTENT_LENGTH);
            }

            // Structured Access Log
            access_logger.log(AccessLogEntry {
                timestamp: chrono_timestamp(),
                client_ip: ip_str,
                method: method_str,
                path,
                status: status_code,
                latency_ms: latency,
                backend: backend_addr,
                pool: pool_name.clone(),
                bytes_sent: body_len as u64,
                referer: String::new(),
                user_agent: String::new(),
            });

            Ok(final_resp)
        }
        Err(e) => {
            error!("Failed to proxy request to backend {}: {}", backend_addr, e);

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
            });

            Ok(empty_response(hyper::StatusCode::BAD_GATEWAY))
        }
    }
}

/// The main worker function for HTTP/2.x and gRPC traffic.
async fn handle_http2_request(
    mut req: Request<hyper::body::Incoming>,
    _peer: SocketAddr,
    upstreams: Arc<UpstreamManager>,
    app_config: Arc<AppConfig>,
    waf: Arc<crate::waf::WafEngine>,
    ai_engine: Arc<dyn crate::ai::AiRouter>,
    cache: Arc<ResponseCache>,
    metrics: Arc<ProxyMetrics>,
    access_logger: Arc<AccessLogger>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let path = req.uri().path().to_string();

    // Detect gRPC traffic via content-type header
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
    let _ = &cache; // use cache (reserved for future H2 cache integration)

    // 0. WAF Inspection
    let ip_str = _peer.ip().to_string();
    let query = req.uri().query();
    let user_agent = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    if let crate::waf::WafAction::Block(reason) = waf.inspect(&ip_str, &path, query, user_agent) {
        warn!("WAF blocked HTTP/2 request from {}: {}", ip_str, reason);
        return Ok(empty_response(hyper::StatusCode::FORBIDDEN));
    }

    // 1. Prefix path routing matching Nginx-like config
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

    // Extract Host Header to fallback if no specific path match is found
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("default");
    let host_name = host.split(':').next().unwrap_or("default");

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
                return res.map(|r| {
                    r.map(|b| {
                        b.map_err(|_e| {
                            panic!(
                                "hyper::Error conversion bypassed on static stream read failure"
                            );
                        })
                        .boxed()
                    })
                });
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
                return res.map(|r| {
                    r.map(|b| {
                        b.map_err(|_e| {
                            // Convert fastcgi error
                            panic!("hyper::Error conversion bypassed on proxy stream failure");
                        })
                        .boxed()
                    })
                });
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
                return res.map(|r| {
                    r.map(|b| {
                        b.map_err(|_e| {
                            // Convert uwsgi error
                            panic!("hyper::Error conversion bypassed on proxy stream failure");
                        })
                        .boxed()
                    })
                });
            }

            r.upstream.clone().unwrap_or_else(|| host_name.to_string())
        }
        None => host_name.to_string(),
    };

    // 2. Fetch healthy backend from pool manager
    let pool = upstreams
        .get_pool(pool_name.as_str())
        .or_else(|| upstreams.get_pool("default"));

    let backend = match pool {
        Some(p) => match p.get_next_backend(Some(&_peer.ip()), Some(Arc::clone(&ai_engine))) {
            Some(b) => b,
            None => return Ok(empty_response(hyper::StatusCode::BAD_GATEWAY)),
        },
        None => return Ok(empty_response(hyper::StatusCode::NOT_FOUND)),
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

    // 4. Forward the request to physical backend IP
    backend.active_connections.fetch_add(1, Ordering::Relaxed);

    // Establish TCP connection to backend
    let stream = match TcpStream::connect(&backend.config.address).await {
        Ok(s) => s,
        Err(e) => {
            error!(
                "Failed to connect to backend {}: {}",
                backend.config.address, e
            );
            backend.active_connections.fetch_sub(1, Ordering::Relaxed);
            return Ok(empty_response(hyper::StatusCode::SERVICE_UNAVAILABLE));
        }
    };

    let io = TokioIo::new(stream);

    // Perform hyper client handshake over the TCP connection using http2
    let (mut sender, conn) =
        match hyper::client::conn::http2::handshake(executor::TokioExecutor, io).await {
            Ok(handshake) => handshake,
            Err(e) => {
                error!(
                    "HTTP/2 Handshake failed with backend {}: {}",
                    backend.config.address, e
                );
                backend.active_connections.fetch_sub(1, Ordering::Relaxed);
                return Ok(empty_response(hyper::StatusCode::SERVICE_UNAVAILABLE));
            }
        };

    // Spawn the hyper connection driver task to manage IO asynchronously
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("Backend HTTP/2 connection error: {:?}", e);
        }
    });

    // Send the proxy request
    let res = sender.send_request(req).await;
    // Client has responded locally, decrement active proxy connection count
    backend.active_connections.fetch_sub(1, Ordering::Relaxed);

    let backend_addr = backend.config.address.clone();

    match res {
        Ok(mut response) => {
            // Train AI Router
            let latency = start_time.elapsed().as_millis() as u64;
            let is_error = response.status().is_server_error();
            ai_engine.update_score(&backend_addr, latency, is_error);

            let status_code = response.status().as_u16();

            // gRPC-specific metrics
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

            // Structured Access Log
            access_logger.log(AccessLogEntry {
                timestamp: chrono_timestamp(),
                client_ip: ip_str,
                method: if is_grpc {
                    format!("gRPC:{}", method_str)
                } else {
                    method_str
                },
                path,
                status: status_code,
                latency_ms: latency,
                backend: backend_addr,
                pool: pool_name.clone(),
                bytes_sent: 0,
                referer: String::new(),
                user_agent: String::new(),
            });

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
            }

            // Box the response body to match the uniform boxbody return type
            let response = response.map(|body| {
                body.map_err(|e| {
                    // hyper::Error
                    e
                })
                .boxed()
            });
            Ok(response)
        }
        Err(e) => {
            error!("Failed to proxy request to backend {}: {}", backend_addr, e);

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
            });

            Ok(empty_response(hyper::StatusCode::BAD_GATEWAY))
        }
    }
}

/// Helper for access logs (shared across proxy handlers)
pub fn chrono_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}Z", now.as_secs(), now.subsec_millis())
}

/// Helper to safely resolve a path against a base directory to prevent Directory Traversal
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

/// Helper for empty std::io::Error responses
fn empty_io_response(status: hyper::StatusCode) -> Response<BoxBody<Bytes, std::io::Error>> {
    Response::builder()
        .status(status)
        .body(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Asynchronously streams a file from disk directly to the TCP socket using Tokio.
async fn serve_static_file<T>(
    route_path: &str,
    req_path: &str,
    root_dir: String,
    _req: &Request<T>,
    access_logger: Arc<AccessLogger>,
    method_str: &str,
    ip_str: &str,
) -> Result<Response<BoxBody<Bytes, std::io::Error>>, hyper::Error> {
    let start_time = std::time::Instant::now();
    let base_path = std::path::Path::new(&root_dir);

    // Only allow GET or HEAD requests for static files
    if method_str != "GET" && method_str != "HEAD" {
        return Ok(empty_io_response(hyper::StatusCode::METHOD_NOT_ALLOWED));
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
                    None => return Ok(empty_io_response(hyper::StatusCode::FORBIDDEN)),
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
            });
            return Ok(empty_io_response(hyper::StatusCode::NOT_FOUND));
        }
    };

    let file = match tokio::fs::File::open(&safe_path).await {
        Ok(f) => f,
        Err(_) => return Ok(empty_io_response(hyper::StatusCode::NOT_FOUND)),
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(_) => return Ok(empty_io_response(hyper::StatusCode::INTERNAL_SERVER_ERROR)),
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
    });

    if method_str == "HEAD" {
        let mut resp = empty_io_response(hyper::StatusCode::OK);
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
    // Since hyper::Error doesn't implement From<std::io::Error> generically and its `new` constructor is private,
    // we convert the IO Stream frames directly, mapping the stream error into an empty synthetic error variant
    // or dropping the connection when ReaderStream fails.
    // To match hyper's strict internal types, we unfortunately must create a dummy `empty_response()` mapping.
    // In practice, since this is streaming, an error mid-stream will just terminate the connection.
    let stream_body = http_body_util::StreamBody::new(
        reader_stream.map(|result| result.map(hyper::body::Frame::data)),
    );

    // Map the internal StreamBody std::io::Error into a synthetic hyper::Error using generic into/mapping
    // Actually, `hyper::Error` CANNOT be constructed. So we just use `anyhow` or a string locally if needed,
    // OR we change the function return type to `std::io::Error` and map it at the HTTP connection boundary.
    let boxed_body = BodyExt::boxed(stream_body);

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
