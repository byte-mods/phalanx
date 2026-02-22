// Core module declarations are now in lib.rs
use ai_load_balancer::*;

use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// The main entry point for the Phalanx AI Load Balancer.
/// We use a standard synchronous `main` function here instead of `#[tokio::main]`
/// because we need to parse the configuration file *before* building the async runtime
/// to determine how many worker threads the runtime should use.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Telemetry (Logging, Metrics, Tracing)
    telemetry::init_telemetry();

    // 2. Load Configuration (Synchronous)
    // This reads the path provided or defaults to `phalanx.conf` and parses Nginx-like blocks into the `AppConfig` struct.
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "phalanx.conf".to_string());
    let cfg = Arc::new(ArcSwap::from_pointee(config::load_config(&config_path)));

    // Snapshot the current config for components that need a static Arc<AppConfig>
    let cfg_snapshot = cfg.load_full();

    tracing::info!(
        "Starting AI Load Balancer with {} worker threads... (Config: {})",
        cfg_snapshot.workers,
        config_path
    );

    // 3. Build Tokio Runtime
    // We dynamically allocate the number of OS threads based on `worker_threads` config.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg_snapshot.workers)
        .enable_all()
        .build()?;

    // 4. Start the Async Application Block
    rt.block_on(async {
        // --- Graceful Shutdown ---
        // A CancellationToken propagates shutdown signals to all spawned tasks.
        let shutdown_token = CancellationToken::new();

        // Spawn the shutdown signal handler (Ctrl+C / SIGTERM)
        let shutdown_token_signal = shutdown_token.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("Shutdown signal received — initiating graceful shutdown...");
            shutdown_token_signal.cancel();
        });

        // --- Hot Reload (SIGHUP) ---
        reload::spawn_reload_handler(Arc::clone(&cfg), config_path.clone());

        // State & Routing: Manages backend health and load balancing algorithms.
        let upstreams = Arc::new(routing::UpstreamManager::new(&cfg_snapshot));

        // Service Discovery: RocksDB-backed persistent backend registry.
        let _discovery = Arc::new(discovery::ServiceDiscovery::new("data/discovery.db"));

        // Prometheus Metrics: Real counters, histograms, and gauges.
        let metrics = Arc::new(admin::ProxyMetrics::new());

        // Response Cache: Moka-based in-memory LFU cache for GET responses.
        let cache = Arc::new(middleware::ResponseCache::new(10_000, 60));

        // Access Logger: Writes formatted access log entries to disk.
        let access_log_path = cfg_snapshot
            .access_log_path
            .as_deref()
            .unwrap_or("logs/access.log");
        let access_log_format = telemetry::access_log::LogFormat::from_str(
            cfg_snapshot.access_log_format.as_deref().unwrap_or("json"),
        );
        let access_logger = Arc::new(telemetry::access_log::AccessLogger::new(
            access_log_path,
            access_log_format,
        ));

        // Initialize Rate Limiter with config bounds (e.g. 50 req/sec, burst 100)
        let rate_limiter = Arc::new(middleware::ratelimit::PhalanxRateLimiter::new(
            cfg_snapshot.rate_limit_per_ip_sec.unwrap_or(50),
            cfg_snapshot.rate_limit_burst.unwrap_or(100),
            cfg_snapshot.global_rate_limit_sec,
        ));

        // Initialize WAF Reputation and Engine
        let waf_reputation = Arc::new(waf::reputation::IpReputationManager::new(
            cfg_snapshot.waf_auto_ban_threshold.unwrap_or(15),
            cfg_snapshot.waf_auto_ban_duration.unwrap_or(3600),
        ));
        let waf_engine = Arc::new(waf::WafEngine::new(
            cfg_snapshot.waf_enabled.unwrap_or(false),
            waf_reputation,
        ));

        // AI Inference Engine: Config-driven algorithm selection
        let ai_algorithm = ai::AiAlgorithm::from_str(
            cfg_snapshot
                .ai_algorithm
                .as_deref()
                .unwrap_or("epsilon_greedy"),
        );
        let ai_engine = ai::build_ai_router(
            ai_algorithm,
            cfg_snapshot.ai_epsilon.unwrap_or(0.10),
            cfg_snapshot.ai_temperature.unwrap_or(1.0),
            cfg_snapshot.ai_ucb_constant.unwrap_or(2.0),
            cfg_snapshot.ai_thompson_threshold_ms.unwrap_or(100.0),
        );

        // Setup TLS if configured
        let tls_acceptor = proxy::tls::load_tls_acceptor(&cfg_snapshot);

        // Start the Admin Server API continuously in the background
        let cfg_admin = Arc::clone(&cfg_snapshot);
        let metrics_admin = Arc::clone(&metrics);
        tokio::spawn(async move {
            admin::start_admin_server(cfg_admin.admin_bind.clone(), metrics_admin).await;
        });

        // Start the Raw TCP Proxy on a separate port (e.g., 5000)
        let cfg_tcp = Arc::clone(&cfg_snapshot);
        let upstreams_tcp = Arc::clone(&upstreams);
        let shutdown_tcp = shutdown_token.clone();
        tokio::spawn(async move {
            proxy::tcp::start_tcp_proxy(&cfg_tcp.tcp_bind, upstreams_tcp, shutdown_tcp).await;
        });

        // Start the Main Protocol Multiplexer Proxy (Sniffs HTTP/gRPC/TCP on the primary port)
        let cfg_proxy = Arc::clone(&cfg_snapshot);
        proxy::start_proxy(
            &cfg_proxy.proxy_bind,
            cfg_snapshot.clone(),
            upstreams.clone(),
            tls_acceptor.clone(),
            waf_engine.clone(),
            rate_limiter.clone(),
            ai_engine.clone(),
            cache.clone(),
            metrics.clone(),
            access_logger.clone(),
            shutdown_token.clone(),
        )
        .await;
    });

    Ok(())
}

/// Waits for Ctrl+C or SIGTERM to initiate graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => { tracing::info!("Received Ctrl+C"); }
            _ = sigterm.recv() => { tracing::info!("Received SIGTERM"); }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("Failed to listen for Ctrl+C");
    }
}
