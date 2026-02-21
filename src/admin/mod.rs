use actix_web::{App, HttpResponse, HttpServer, Responder, get, web};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};
use std::sync::Arc;
use tracing::info;

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
async fn metrics_endpoint(metrics_data: web::Data<Arc<ProxyMetrics>>) -> impl Responder {
    let body = metrics_data.encode();
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(body)
}

pub async fn start_admin_server(bind_addr: String, metrics: Arc<ProxyMetrics>) {
    info!("Admin API listening on http://{}", bind_addr);

    let metrics_data = web::Data::new(metrics);

    let server = HttpServer::new(move || {
        App::new()
            .app_data(metrics_data.clone())
            .service(health)
            .service(metrics_endpoint)
    })
    .bind(&bind_addr)
    .expect("Invalid admin bind address")
    .run();

    if let Err(e) = server.await {
        tracing::error!("Admin server error: {}", e);
    }
}
