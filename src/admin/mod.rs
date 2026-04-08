//! Admin API server and Prometheus metrics registry.
//!
//! Exposes endpoints for health checks, Prometheus metrics, backend discovery
//! management, keyval operations, cache purge, upstream details, config reload,
//! and a built-in HTML dashboard.

/// Resource alert engine for bandwidth, memory, and file-descriptor monitoring.
pub mod alerts;
/// Extended admin API: RBAC, dynamic routes, SSL certificate management, ML endpoints.
pub mod api;
/// Dashboard-specific API: WAF bans, attack logs, rate-limit top-N, cluster status.
pub mod dashboard_api;

use crate::discovery::{DiscoveredBackend, ServiceDiscovery};
use crate::keyval::{KeyvalGetResponse, KeyvalListEntry, KeyvalSetRequest, KeyvalStore};
use crate::routing::UpstreamManager;
use actix_web::{App, HttpResponse, HttpServer, Responder, delete, get, post, web};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tracing::info;

/// Shared application state injected into every admin API handler via Actix-Web `web::Data`.
///
/// Holds `Arc` references to the major subsystems so handlers can query
/// metrics, manage backends, manipulate the keyval store, and trigger WAF actions.
#[derive(Clone)]
pub struct AdminState {
    pub metrics: Arc<ProxyMetrics>,
    pub discovery: Arc<ServiceDiscovery>,
    pub manager: Arc<UpstreamManager>,
    /// Shared keyval store — injected from main at startup.
    pub keyval: Arc<KeyvalStore>,
    /// Shared WAF Engine for ML models
    pub waf: Arc<crate::waf::WafEngine>,
    /// Shared response cache for purge operations (L1 memory + optional L2 disk)
    pub cache: Arc<crate::middleware::cache::AdvancedCache>,
    /// Rate limiter (for top-IP dashboard panel and request counting)
    pub rate_limiter: Arc<crate::middleware::ratelimit::PhalanxRateLimiter>,
    /// Per-protocol bandwidth counters
    pub bandwidth: Arc<crate::telemetry::bandwidth::BandwidthTracker>,
    /// Resource alert engine
    pub alert_engine: Arc<alerts::AlertEngine>,
}

/// Global metrics registry shared across the proxy and admin server.
#[derive(Clone)]
pub struct ProxyMetrics {
    pub registry: Registry,
    /// Total HTTP requests processed, labeled by method, status_code, and pool.
    pub http_requests_total: IntCounterVec,
    /// HTTP request duration in seconds, labeled by method and pool.
    pub http_request_duration: HistogramVec,
    /// Number of currently active backend connections.
    pub active_connections: IntGauge,
    /// Total WAF blocks, labeled by rule category.
    pub waf_blocks_total: IntCounterVec,
    /// Total rate limit rejections.
    pub rate_limit_rejections: IntCounterVec,
    /// Response cache hit/miss counters.
    pub cache_hits_total: IntCounterVec,
    /// Per-backend request duration in seconds, labeled by backend address and pool.
    pub backend_request_duration: HistogramVec,
    /// Per-backend error counter, labeled by backend address, pool, and error type.
    pub backend_errors_total: IntCounterVec,
    /// Counter for ML fraud model load failures (fallback to rule-based mode).
    pub ml_model_load_failures: IntCounter,
}

impl ProxyMetrics {
    /// Creates a new metrics registry and registers all Phalanx-specific
    /// counters, histograms, and gauges. Called once at startup.
    pub fn new() -> Self {
        let registry = Registry::new();

        let http_requests_total = IntCounterVec::new(
            Opts::new(
                "phalanx_http_requests_total",
                "Total HTTP requests processed",
            ),
            &["method", "status", "pool"],
        )
        .unwrap();

        let http_request_duration = HistogramVec::new(
            HistogramOpts::new(
                "phalanx_http_request_duration_seconds",
                "HTTP request latency in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method", "pool"],
        )
        .unwrap();

        let active_connections = IntGauge::new(
            "phalanx_active_connections",
            "Number of currently active backend connections",
        )
        .unwrap();

        let waf_blocks_total = IntCounterVec::new(
            Opts::new("phalanx_waf_blocks_total", "Total WAF blocked requests"),
            &["category"],
        )
        .unwrap();

        let rate_limit_rejections = IntCounterVec::new(
            Opts::new(
                "phalanx_rate_limit_rejections_total",
                "Total rate limit rejections",
            ),
            &["type"],
        )
        .unwrap();

        let cache_hits_total = IntCounterVec::new(
            Opts::new("phalanx_cache_total", "Response cache hits and misses"),
            &["result"],
        )
        .unwrap();

        let backend_request_duration = HistogramVec::new(
            HistogramOpts::new(
                "phalanx_backend_request_duration_seconds",
                "Per-backend request latency in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["backend", "pool"],
        )
        .unwrap();

        let backend_errors_total = IntCounterVec::new(
            Opts::new(
                "phalanx_backend_errors_total",
                "Per-backend error counter",
            ),
            &["backend", "pool", "error_type"],
        )
        .unwrap();

        let ml_model_load_failures = IntCounter::new(
            "phalanx_ml_model_load_failures_total",
            "Number of times the ML fraud ONNX model failed to load (rule-based fallback active)",
        )
        .unwrap();

        // Register all metrics
        registry
            .register(Box::new(http_requests_total.clone()))
            .unwrap();
        registry
            .register(Box::new(http_request_duration.clone()))
            .unwrap();
        registry
            .register(Box::new(active_connections.clone()))
            .unwrap();
        registry
            .register(Box::new(waf_blocks_total.clone()))
            .unwrap();
        registry
            .register(Box::new(rate_limit_rejections.clone()))
            .unwrap();
        registry
            .register(Box::new(cache_hits_total.clone()))
            .unwrap();
        registry
            .register(Box::new(backend_request_duration.clone()))
            .unwrap();
        registry
            .register(Box::new(backend_errors_total.clone()))
            .unwrap();
        registry
            .register(Box::new(ml_model_load_failures.clone()))
            .unwrap();

        Self {
            registry,
            http_requests_total,
            http_request_duration,
            active_connections,
            waf_blocks_total,
            rate_limit_rejections,
            cache_hits_total,
            backend_request_duration,
            backend_errors_total,
            ml_model_load_failures,
        }
    }

    /// Encodes all registered metrics into Prometheus text exposition format.
    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap_or_default()
    }
}

/// GET /health -- simple liveness probe returning 200 OK.
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

/// GET /metrics -- Prometheus text exposition format for all registered metrics.
#[get("/metrics")]
async fn metrics_endpoint(state: web::Data<AdminState>) -> impl Responder {
    let body = state.metrics.encode();
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(body)
}

/// GET /api/stats -- JSON summary of key metrics for the dashboard UI.
/// Builds a custom JSON structure by iterating the Prometheus registry so
/// the frontend can render counters without parsing the text format.
#[get("/api/stats")]
async fn api_stats(state: web::Data<AdminState>) -> impl Responder {
    // Instead of using generic Prometheus encoding which is hard to parse in JS,
    // we create a custom JSON structure wrapping the registry output.
    // However, the cleanest way to expose Prometheus metrics to a simple UI
    // is to just use a custom struct. For simplicity here, we'll manually
    // extract the gauge/counter values.

    let active = state.metrics.active_connections.get();

    // Summing counters across all labels involves iterating the registry
    // But since the UI JS fetches this, we can give it raw counts or parsed.
    // The easiest robust way is just exposing the prometheus `gather()` in a simplified shape.
    let families = state.metrics.registry.gather();

    // We'll return a raw JSON map that the JS can parse
    // using serde_json. We don't have to perfectly serialize prometheus,
    // just give enough data to the UI.
    let mut stats = serde_json::json!({
        "active_connections": active,
        "http_requests_total": [],
        "cache_hits_total": [],
        "waf_blocks_total": [],
        "rate_limit_rejections": [],
    });

    for family in families {
        let name = family.name().to_string();
        let mut metrics_array = vec![];

        for m in family.get_metric() {
            let mut labels = serde_json::Map::new();
            for lp in m.get_label() {
                labels.insert(
                    lp.name().to_string(),
                    serde_json::Value::String(lp.value().to_string()),
                );
            }

            let val = if let Some(counter) = m.get_counter().as_ref() {
                counter.value()
            } else if let Some(gauge) = m.get_gauge().as_ref() {
                gauge.value()
            } else {
                0.0
            };

            metrics_array.push(serde_json::json!({
                "labels": labels,
                "value": val
            }));
        }

        if name == "phalanx_http_requests_total" {
            stats["http_requests_total"] = serde_json::json!(metrics_array);
        } else if name == "phalanx_cache_total" {
            stats["cache_hits_total"] = serde_json::json!(metrics_array);
        } else if name == "phalanx_waf_blocks_total" {
            stats["waf_blocks_total"] = serde_json::json!(metrics_array);
        } else if name == "phalanx_rate_limit_rejections_total" {
            stats["rate_limit_rejections"] = serde_json::json!(metrics_array);
        }
    }

    HttpResponse::Ok().json(stats)
}

/// GET /dashboard -- serves the embedded HTML dashboard (compiled into the binary).
#[get("/dashboard")]
async fn dashboard_ui() -> impl Responder {
    let html = include_str!("dashboard.html");
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// POST /api/discovery/backends -- registers a new backend in persistent
/// storage (RocksDB) and adds it to the in-memory routing pool.
#[post("/api/discovery/backends")]
async fn add_backend(
    state: web::Data<AdminState>,
    backend: web::Json<DiscoveredBackend>,
) -> impl Responder {
    let backend = backend.into_inner();

    // Persist to DB
    state.discovery.register_backend(&backend);

    // Add to active memory
    if let Some(pool) = state.manager.get_pool(&backend.pool) {
        pool.add_backend(crate::config::BackendConfig {
            address: backend.address.clone(),
            weight: backend.weight,
            ..Default::default()
        });
        HttpResponse::Ok().json(serde_json::json!({"status": "added"}))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "pool not found"}))
    }
}

/// DELETE /api/discovery/backends/{pool}/{address} -- deregisters a backend
/// from persistent storage and removes it from the in-memory routing pool.
#[delete("/api/discovery/backends/{pool}/{address}")]
async fn remove_backend(
    state: web::Data<AdminState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (pool_name, address) = path.into_inner();

    // Remove from DB
    state.discovery.deregister_backend(&pool_name, &address);

    // Remove from active memory
    if let Some(pool) = state.manager.get_pool(&pool_name) {
        pool.remove_backend(&address);
        HttpResponse::Ok().json(serde_json::json!({"status": "removed"}))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "pool not found"}))
    }
}

/// Starts the Actix-Web admin/metrics server.
///
/// Registers all admin and dashboard endpoints and runs until the
/// `shutdown` cancellation token is triggered, at which point it
/// performs a graceful stop.
///
/// # Arguments
/// * `bind_addr` - TCP address to listen on (e.g. `"127.0.0.1:9090"`).
/// * `state` - Shared admin state containing metrics, discovery, WAF, etc.
/// * `shutdown` - Token signalled by the main supervisor on graceful shutdown.
pub async fn start_admin_server(
    bind_addr: String,
    state: AdminState,
    shutdown: tokio_util::sync::CancellationToken,
) {
    info!("Admin API listening on http://{}", bind_addr);

    let rate_limiter = Arc::clone(&state.rate_limiter);
    let admin_state = web::Data::new(state);

    // Dashboard state shares the same inner data via Arc clones
    let dash_state: web::Data<dashboard_api::DashboardState> = {
        let s = admin_state.as_ref();
        web::Data::new(dashboard_api::DashboardState {
            base: AdminState {
                metrics: Arc::clone(&s.metrics),
                discovery: Arc::clone(&s.discovery),
                manager: Arc::clone(&s.manager),
                keyval: Arc::clone(&s.keyval),
                waf: Arc::clone(&s.waf),
                cache: Arc::clone(&s.cache),
                rate_limiter: Arc::clone(&s.rate_limiter),
                bandwidth: Arc::clone(&s.bandwidth),
                alert_engine: Arc::clone(&s.alert_engine),
            },
            rate_limiter,
            bandwidth: Arc::clone(&s.bandwidth),
            alert_engine: Arc::clone(&s.alert_engine),
        })
    };

    let server = HttpServer::new(move || {
        App::new()
            .app_data(admin_state.clone())
            .app_data(dash_state.clone())
            .service(health)
            .service(metrics_endpoint)
            .service(api_stats)
            .service(dashboard_ui)
            .service(add_backend)
            .service(remove_backend)
            .service(keyval_get)
            .service(keyval_set)
            .service(keyval_delete)
            .service(keyval_list)
            .service(upstreams_detail)
            .service(upstreams_health)
            .service(config_validate)
            .service(config_reload)
            .service(api::ml_upload)
            .service(api::ml_logs)
            .service(api::ml_mode)
            .service(cache_purge)
            // Dashboard API endpoints
            .service(dashboard_api::list_bans)
            .service(dashboard_api::manual_ban)
            .service(dashboard_api::unban_ip)
            .service(dashboard_api::list_attacks)
            .service(dashboard_api::list_strikes)
            .service(dashboard_api::top_rate_ips)
            .service(dashboard_api::cluster_nodes)
            .service(dashboard_api::cache_stats)
            .service(dashboard_api::bandwidth_stats)
            .service(dashboard_api::bandwidth_pool_stats)
            .service(dashboard_api::list_alerts)
            .service(dashboard_api::trigger_alert_check)
    });
    let server = match server.bind(&bind_addr) {
        Ok(s) => s.run(),
        Err(e) => {
            tracing::error!("Invalid admin bind address '{}': {}", bind_addr, e);
            return;
        }
    };
    let handle = server.handle();

    tokio::select! {
        res = server => {
            if let Err(e) = res {
                tracing::error!("Admin server error: {}", e);
            }
        }
        _ = shutdown.cancelled() => {
            handle.stop(true).await;
            tracing::info!("Admin server shutdown signal received.");
        }
    }
}

// ─── Cache Purge Endpoint ─────────────────────────────────────────────────────

/// Request body for the cache purge endpoint.
#[derive(serde::Deserialize)]
struct PurgeBody {
    /// If set, purge this exact cache key.
    key: Option<String>,
    /// If set, purge all keys matching this prefix.
    prefix: Option<String>,
}

/// POST /api/cache/purge -- invalidates cached responses by key, prefix,
/// or all entries if neither is specified.
#[post("/api/cache/purge")]
async fn cache_purge(
    state: web::Data<AdminState>,
    body: web::Json<PurgeBody>,
) -> impl Responder {
    let purged = if let Some(ref key) = body.key {
        let removed = state.cache.purge(key).await;
        serde_json::json!({ "status": "ok", "key": key, "removed": removed })
    } else if let Some(ref prefix) = body.prefix {
        let count = state.cache.purge_prefix(prefix).await;
        serde_json::json!({ "status": "ok", "prefix": prefix, "removed_approx": count })
    } else {
        state.cache.purge_all().await;
        serde_json::json!({ "status": "ok", "action": "purge_all" })
    };
    HttpResponse::Ok().json(purged)
}

// ─── Keyval Endpoints ─────────────────────────────────────────────────────────

/// GET /api/keyval/{key} -- retrieves a single key-value entry.
#[get("/api/keyval/{key}")]
async fn keyval_get(
    state: web::Data<AdminState>,
    path: web::Path<String>,
) -> impl Responder {
    let key = path.into_inner();
    match state.keyval.get(&key) {
        Some(value) => HttpResponse::Ok().json(KeyvalGetResponse { key, value }),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "key not found" })),
    }
}

/// POST /api/keyval/{key} -- sets a key-value entry with optional TTL.
#[post("/api/keyval/{key}")]
async fn keyval_set(
    state: web::Data<AdminState>,
    path: web::Path<String>,
    body: web::Json<KeyvalSetRequest>,
) -> impl Responder {
    let key = path.into_inner();
    let req = body.into_inner();
    state.keyval.set(key.clone(), req.value, req.ttl_secs);
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok", "key": key }))
}

/// DELETE /api/keyval/{key} -- removes a key-value entry.
#[delete("/api/keyval/{key}")]
async fn keyval_delete(
    state: web::Data<AdminState>,
    path: web::Path<String>,
) -> impl Responder {
    let key = path.into_inner();
    let deleted = state.keyval.delete(&key);
    if deleted {
        HttpResponse::Ok().json(serde_json::json!({ "status": "deleted", "key": key }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "key not found" }))
    }
}

/// GET /api/keyval -- lists all non-expired key-value entries.
#[get("/api/keyval")]
async fn keyval_list(state: web::Data<AdminState>) -> impl Responder {
    let entries: Vec<KeyvalListEntry> = state
        .keyval
        .list()
        .into_iter()
        .map(|(k, v)| KeyvalListEntry { key: k, value: v })
        .collect();
    HttpResponse::Ok().json(entries)
}

// ─── Upstream Detail Endpoint ────────────────────────────────────────────────

/// GET /api/upstreams/detail -- returns per-pool backend details including
/// health status, active connections, and weight for the dashboard.
#[get("/api/upstreams/detail")]
async fn upstreams_detail(state: web::Data<AdminState>) -> impl Responder {
    let mut pools = serde_json::Map::new();
    // Iterate all pools via the discovery DB (all registered backends)
    let all_backends = state.discovery.list_all_backends();

    // Group by pool name from discovery
    let mut pool_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for b in &all_backends {
        pool_names.insert(b.pool.clone());
    }

    // Also add pools from the routing manager
    for pool_entry in state.manager.inner_pools() {
        let pool_name = pool_entry.0;
        let pool = pool_entry.1;
        let backends_snap = pool.backends.load();
        let backends_json: Vec<serde_json::Value> = backends_snap
            .iter()
            .map(|b| {
                serde_json::json!({
                    "address": b.config.address,
                    "healthy": b.is_healthy.load(Ordering::Relaxed),
                    "active_conns": b.active_connections.load(Ordering::Relaxed),
                    "weight": b.config.weight,
                })
            })
            .collect();
        pools.insert(pool_name, serde_json::json!({ "backends": backends_json }));
    }

    HttpResponse::Ok().json(pools)
}

// ─── Upstream Health Endpoint ─────────────────────────────────────────────────

/// GET /api/upstreams/health -- returns per-backend health info for all pools.
#[get("/api/upstreams/health")]
async fn upstreams_health(state: web::Data<AdminState>) -> impl Responder {
    let mut entries = Vec::new();
    for (pool_name, pool) in state.manager.inner_pools() {
        let backends_snap = pool.backends.load();
        for backend in backends_snap.iter() {
            let circuit_state_val = backend.circuit_state_str();
            entries.push(serde_json::json!({
                "pool": pool_name,
                "backend": backend.config.address,
                "healthy": backend.is_healthy.load(Ordering::Relaxed),
                "active_connections": backend.active_connections.load(Ordering::Relaxed),
                "fail_count": backend.fail_count(),
                "circuit_state": circuit_state_val,
                "effective_weight": backend.effective_weight(),
            }));
        }
    }
    HttpResponse::Ok().json(entries)
}

// ─── Config Validate Endpoint ────────────────────────────────────────────────

/// POST /api/config/validate -- validates config content without applying it.
#[post("/api/config/validate")]
async fn config_validate(body: web::Bytes) -> impl Responder {
    let content = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "valid": false,
                "errors": [format!("Invalid UTF-8: {}", e)],
            }));
        }
    };

    match crate::config::parser::parse_phalanx_config(&content) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "valid": true,
            "errors": [],
        })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "valid": false,
            "errors": [e],
        })),
    }
}

// ─── Config Reload ────────────────────────────────────────────────────────────

/// POST /api/reload -- triggers a configuration reload by sending SIGHUP
/// to the current process (Unix only).
#[post("/api/reload")]
async fn config_reload() -> impl Responder {
    // Signal a config reload via SIGHUP (Unix only)
    #[cfg(unix)]
    {
        use std::os::raw::c_int;
        unsafe extern "C" {
            fn getpid() -> u32;
            fn kill(pid: u32, sig: c_int) -> c_int;
        }
        let sighup: c_int = 1; // SIGHUP = 1
        unsafe { kill(getpid(), sighup); }
        return HttpResponse::Ok().json(serde_json::json!({
            "status": "reload signaled (live-routed components and listeners will refresh)"
        }));
    }
    #[cfg(not(unix))]
    HttpResponse::Ok().json(serde_json::json!({ "status": "reload not supported on this platform" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_metrics_creation() {
        let metrics = ProxyMetrics::new();
        assert_eq!(metrics.active_connections.get(), 0);
    }

    #[test]
    fn test_proxy_metrics_encode_not_empty() {
        let metrics = ProxyMetrics::new();
        let encoded = metrics.encode();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_proxy_metrics_counter_increment() {
        let metrics = ProxyMetrics::new();
        metrics
            .http_requests_total
            .with_label_values(&["GET", "200", "default"])
            .inc();
        let encoded = metrics.encode();
        assert!(encoded.contains("phalanx_http_requests_total"));
    }

    #[test]
    fn test_proxy_metrics_gauge() {
        let metrics = ProxyMetrics::new();
        metrics.active_connections.inc();
        metrics.active_connections.inc();
        assert_eq!(metrics.active_connections.get(), 2);
        metrics.active_connections.dec();
        assert_eq!(metrics.active_connections.get(), 1);
    }

    #[test]
    fn test_proxy_metrics_histogram() {
        let metrics = ProxyMetrics::new();
        metrics
            .http_request_duration
            .with_label_values(&["GET", "default"])
            .observe(0.05);
        let encoded = metrics.encode();
        assert!(encoded.contains("phalanx_http_request_duration_seconds"));
    }

    #[test]
    fn test_proxy_metrics_waf_blocks() {
        let metrics = ProxyMetrics::new();
        metrics
            .waf_blocks_total
            .with_label_values(&["sqli"])
            .inc_by(3);
        let encoded = metrics.encode();
        assert!(encoded.contains("phalanx_waf_blocks_total"));
    }

    #[test]
    fn test_proxy_metrics_cache_hits() {
        let metrics = ProxyMetrics::new();
        metrics
            .cache_hits_total
            .with_label_values(&["hit"])
            .inc();
        metrics
            .cache_hits_total
            .with_label_values(&["miss"])
            .inc_by(5);
        let encoded = metrics.encode();
        assert!(encoded.contains("phalanx_cache_total"));
    }
}
