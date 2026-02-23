use crate::discovery::{DiscoveredBackend, ServiceDiscovery};
use crate::routing::UpstreamManager;
use actix_web::{App, HttpResponse, HttpServer, Responder, delete, get, post, web};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};
use std::sync::Arc;
use tracing::info;

pub struct AdminState {
    pub metrics: Arc<ProxyMetrics>,
    pub discovery: Arc<ServiceDiscovery>,
    pub manager: Arc<UpstreamManager>,
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
            health_check_path: None,
            health_check_status: 200,
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
    })
    .bind(&bind_addr)
    .expect("Invalid admin bind address")
    .run();

    if let Err(e) = server.await {
        tracing::error!("Admin server error: {}", e);
    }
}
