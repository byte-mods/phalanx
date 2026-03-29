pub mod api;

use crate::discovery::{DiscoveredBackend, ServiceDiscovery};
use crate::keyval::{KeyvalGetResponse, KeyvalListEntry, KeyvalSetRequest, KeyvalStore};
use crate::routing::UpstreamManager;
use actix_web::{App, HttpResponse, HttpServer, Responder, delete, get, post, web};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tracing::info;

pub struct AdminState {
    pub metrics: Arc<ProxyMetrics>,
    pub discovery: Arc<ServiceDiscovery>,
    pub manager: Arc<UpstreamManager>,
    /// Shared keyval store — injected from main at startup.
    pub keyval: Arc<KeyvalStore>,
    /// Shared WAF Engine for ML models
    pub waf: Arc<crate::waf::WafEngine>,
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
}

impl ProxyMetrics {
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

        Self {
            registry,
            http_requests_total,
            http_request_duration,
            active_connections,
            waf_blocks_total,
            rate_limit_rejections,
            cache_hits_total,
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

#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[get("/metrics")]
async fn metrics_endpoint(state: web::Data<AdminState>) -> impl Responder {
    let body = state.metrics.encode();
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(body)
}

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

#[get("/dashboard")]
async fn dashboard_ui() -> impl Responder {
    let html = include_str!("dashboard.html");
    HttpResponse::Ok().content_type("text/html").body(html)
}

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

pub async fn start_admin_server(bind_addr: String, state: AdminState) {
    info!("Admin API listening on http://{}", bind_addr);

    let admin_state = web::Data::new(state);

    let server = HttpServer::new(move || {
        App::new()
            .app_data(admin_state.clone())
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
            .service(config_reload)
            .service(api::ml_upload)
            .service(api::ml_logs)
            .service(api::ml_mode)
    })
    .bind(&bind_addr)
    .expect("Invalid admin bind address")
    .run();

    if let Err(e) = server.await {
        tracing::error!("Admin server error: {}", e);
    }
}

// ─── Keyval Endpoints ─────────────────────────────────────────────────────────

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

// ─── Config Reload ────────────────────────────────────────────────────────────

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
        return HttpResponse::Ok().json(serde_json::json!({ "status": "reload signaled" }));
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
