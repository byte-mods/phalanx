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

        if let Some(endpoint) = cfg_snapshot.otel_endpoint.as_deref() {
            let service = cfg_snapshot
                .otel_service_name
                .as_deref()
                .unwrap_or("phalanx");
            // Keep the provider alive for the process lifetime.
            // Dropping it on exit triggers a final span flush to the collector.
            let _otel_provider = telemetry::otel::init_otel_layer(endpoint, service);
        }

        // Setup TLS (shared, hot-reloadable)
        let tls_acceptor = Arc::new(ArcSwap::from_pointee(proxy::tls::load_tls_acceptor(
            &cfg_snapshot,
        )));

        // --- Hot Reload (SIGHUP) ---
        reload::spawn_reload_handler(
            Arc::clone(&cfg),
            Arc::clone(&tls_acceptor),
            config_path.clone(),
        );

        // Service Discovery: RocksDB-backed persistent backend registry.
        let discovery = Arc::new(discovery::ServiceDiscovery::new("data/discovery.db"));

        // State & Routing: Manages backend health and load balancing algorithms.
        let upstreams = Arc::new(routing::UpstreamManager::new(
            &cfg_snapshot,
            discovery.clone(),
        ));

        // Prometheus Metrics: Real counters, histograms, and gauges.
        let metrics = Arc::new(admin::ProxyMetrics::new());

        // Keyval Store: In-memory DashMap-backed store with TTL (NGINX Plus keyval_zone equivalent).
        let keyval = keyval::KeyvalStore::new(
            0,
            cfg_snapshot.redis_url.as_deref().and_then(|url| redis::Client::open(url).ok()),
        );

        // Response Cache: L1 in-memory (Moka LFU) + optional L2 disk cache.
        let cache = Arc::new(middleware::cache::AdvancedCache::new(
            10_000,
            60,
            cfg_snapshot.cache_disk_path.as_deref(),
        ));

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
            cfg_snapshot.redis_url.as_deref(),
        ));

        // Initialize WAF Reputation and Engine
        let waf_reputation = waf::reputation::IpReputationManager::new(
            cfg_snapshot.waf_auto_ban_threshold.unwrap_or(15),
            cfg_snapshot.waf_auto_ban_duration.unwrap_or(3600),
            cfg_snapshot.redis_url.as_deref().and_then(|url| redis::Client::open(url).ok()),
        );
        let waf_base = waf::WafEngine::new(true, waf_reputation).with_keyval(keyval.clone());
        // Load declarative WAF policy if configured
        let waf_base = if let Some(ref policy_path) = cfg_snapshot.waf_policy_path {
            let mut policy_engine = waf::policy::PolicyEngine::new();
            match policy_engine.load_from_file(policy_path) {
                Ok(()) => {
                    tracing::info!("WAF policy loaded from {}", policy_path);
                    waf_base.with_policy_engine(policy_engine)
                }
                Err(e) => {
                    tracing::warn!("WAF policy load failed from {}: {}", policy_path, e);
                    waf_base
                }
            }
        } else {
            waf_base
        };
        let waf_engine = Arc::new(waf_base);

        // Service Discovery: DNS SRV records
        for (pool_name, pool_config) in &cfg_snapshot.upstreams {
            if let Some(srv_name) = &pool_config.srv_discover {
                if let Some(pool) = upstreams.get_pool(pool_name) {
                    let template = pool_config.backends.first().cloned().unwrap_or_default();
                    discovery::spawn_srv_watcher(pool_name.clone(), srv_name.to_string(), pool, template);
                }
            }
        }

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

        // Per-protocol bandwidth tracker and resource alert engine
        let bandwidth_tracker = telemetry::bandwidth::BandwidthTracker::new();
        let alert_engine = admin::alerts::AlertEngine::new(Arc::clone(&bandwidth_tracker));
        // Start background alert polling every 30 seconds
        Arc::clone(&alert_engine).spawn_background_check(30);

        let cfg_admin = Arc::clone(&cfg_snapshot);
        let metrics_admin = Arc::clone(&metrics);
        let discovery_admin = Arc::clone(&discovery);
        let manager_admin = Arc::clone(&upstreams);
        let keyval_admin = Arc::clone(&keyval);
        let waf_admin = Arc::clone(&waf_engine);
        let cache_admin = Arc::clone(&cache);
        let rate_limiter_admin = Arc::clone(&rate_limiter);
        let bandwidth_admin = Arc::clone(&bandwidth_tracker);
        let alert_admin = Arc::clone(&alert_engine);
        tokio::spawn(async move {
            let admin_state = admin::AdminState {
                metrics: metrics_admin,
                discovery: discovery_admin,
                manager: manager_admin,
                keyval: keyval_admin,
                waf: waf_admin,
                cache: cache_admin,
                rate_limiter: rate_limiter_admin,
                bandwidth: bandwidth_admin,
                alert_engine: alert_admin,
            };
            admin::start_admin_server(cfg_admin.admin_bind.clone(), admin_state).await;
        });

        // Start the Raw TCP Proxy on a separate port (e.g., 5000)
        let cfg_tcp = Arc::clone(&cfg_snapshot);
        let upstreams_tcp = Arc::clone(&upstreams);
        let shutdown_tcp = shutdown_token.clone();
        tokio::spawn(async move {
            proxy::tcp::start_tcp_proxy(&cfg_tcp.tcp_bind, upstreams_tcp, shutdown_tcp).await;
        });

        // Start the UDP Stream Proxy (opt-in: requires `udp_bind` in phalanx.conf)
        if let Some(ref udp_addr) = cfg_snapshot.udp_bind {
            let udp_addr = udp_addr.clone();
            let upstreams_udp = Arc::clone(&upstreams);
            let shutdown_udp = shutdown_token.clone();
            tokio::spawn(async move {
                proxy::udp::start_udp_proxy(&udp_addr, upstreams_udp, shutdown_udp).await;
            });
        }

        // Mail Proxy (opt-in: requires smtp_bind / imap_bind / pop3_bind in phalanx.conf)
        let mail_pool = cfg_snapshot
            .mail_upstream_pool
            .clone()
            .unwrap_or_else(|| "default".to_string());
        for (proto, bind_opt) in [
            (mail::MailProtocol::Smtp, cfg_snapshot.smtp_bind.clone()),
            (mail::MailProtocol::Imap, cfg_snapshot.imap_bind.clone()),
            (mail::MailProtocol::Pop3, cfg_snapshot.pop3_bind.clone()),
        ] {
            if let Some(bind_addr) = bind_opt {
                let mail_cfg = mail::MailProxyConfig {
                    protocol: proto,
                    bind_addr,
                    upstream_pool: mail_pool.clone(),
                    banner: None,
                    starttls: false,
                };
                let upstreams_mail = Arc::clone(&upstreams);
                let shutdown_mail = shutdown_token.clone();
                tokio::spawn(async move {
                    mail::start_mail_proxy(mail_cfg, upstreams_mail, shutdown_mail).await;
                });
            }
        }

        // Start the HTTP/3 QUIC Server (opt-in: requires `listen_quic` in phalanx.conf)
        if let Some(ref quic_bind) = cfg_snapshot.quic_bind {
            let quic_bind = quic_bind.clone();
            let cfg_h3 = Arc::clone(&cfg_snapshot);
            let upstreams_h3 = Arc::clone(&upstreams);
            let metrics_h3 = Arc::clone(&metrics);
            let cache_h3 = Arc::clone(&cache);
            let ai_h3 = Arc::clone(&ai_engine);
            let shutdown_h3 = shutdown_token.clone();
            tokio::spawn(async move {
                proxy::http3::start_http3_proxy(
                    &quic_bind,
                    cfg_h3,
                    upstreams_h3,
                    metrics_h3,
                    cache_h3,
                    ai_h3,
                    shutdown_h3,
                )
                .await;
            });
        }

        // GeoIP Database (opt-in: requires `geoip_db_path` in phalanx.conf)
        let geo_db = if let Some(ref db_path) = cfg_snapshot.geoip_db_path {
            let mut db = geo::GeoIpDatabase::new();
            match db.load_csv(db_path) {
                Ok(()) => {
                    tracing::info!("GeoIP database loaded from {}", db_path);
                    Some(db)
                }
                Err(e) => {
                    tracing::warn!("GeoIP database failed to load from {}: {}", db_path, e);
                    None
                }
            }
        } else {
            None
        };
        let geo_db: Arc<Option<geo::GeoIpDatabase>> = Arc::new(geo_db);
        let geo_policy = Arc::new(geo::GeoPolicy {
            allow_countries: cfg_snapshot.geo_allow_countries.clone(),
            deny_countries: cfg_snapshot.geo_deny_countries.clone(),
        });

        // Hook engine (pre-populated from rhai_script if configured)
        let hook_engine = Arc::new(scripting::HookEngine::new());

        // Sticky session manager: Cookie mode by default (opt-in per session)
        let sticky = Arc::new(Some(proxy::sticky::StickySessionManager::new(
            proxy::sticky::StickyMode::Cookie {
                name: "PHALANXID".to_string(),
                path: "/".to_string(),
                http_only: true,
                secure: cfg_snapshot.tls_cert_path.is_some(),
                max_age: 3600,
            },
        )));

        // Zone-based concurrent request limiter (tracks per-IP active requests)
        let zone_limiter = Arc::new(middleware::connlimit::ZoneLimiter::new(
            "per_ip",
            1_000_000, // use PhalanxRateLimiter for actual rate; zone tracks concurrency
            1_000_000,
            0, // 0 = unlimited concurrent connections by default
        ));

        // OIDC session store (shared across all connections)
        let oidc_sessions = auth::oidc::new_session_store();

        // ClusterState: shared KV across Phalanx nodes via Redis or etcd.
        // Enables distributed rate limiting, sticky sessions, and leader election.
        let node_id = cfg_snapshot
            .node_id
            .clone()
            .unwrap_or_else(|| {
                std::env::var("HOSTNAME")
                    .unwrap_or_else(|_| "phalanx-node-1".to_string())
            });
        let _cluster_state = std::sync::Arc::new({
            use cluster::{ClusterBackend, ClusterState};
            let backend = if let Some(ref gossip_addr) = cfg_snapshot.gossip_bind {
                let seed_peers: Vec<String> = cfg_snapshot
                    .gossip_seed_peers
                    .as_deref()
                    .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
                    .unwrap_or_default();
                ClusterBackend::Gossip {
                    bind_addr: gossip_addr.clone(),
                    seed_peers,
                }
            } else if let Some(endpoints_str) = cfg_snapshot.etcd_endpoints.as_deref() {
                let endpoints: Vec<String> = endpoints_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
                ClusterBackend::Etcd { endpoints }
            } else if let Some(redis_url) = cfg_snapshot.redis_url.as_deref() {
                ClusterBackend::Redis { url: redis_url.to_string() }
            } else {
                ClusterBackend::Standalone
            };
            ClusterState::new(backend, node_id)
        });

        // OCSP Stapling: fetch certificate revocation status and staple to TLS handshake.
        // Started only when TLS is configured; improves handshake latency and privacy.
        if cfg_snapshot.tls_cert_path.is_some() {
            let cert_der = cfg_snapshot
                .tls_cert_path
                .as_deref()
                .and_then(|p| std::fs::read(p).ok())
                .unwrap_or_default();
            let ocsp_stapler = std::sync::Arc::new(proxy::ocsp::OcspStapler::new(
                cert_der,
                None,
                cfg_snapshot.ocsp_responder_url.clone(),
            ));
            ocsp_stapler.spawn_refresh_loop(std::time::Duration::from_secs(3600));
            tracing::info!("OCSP stapling started");
        }

        // ML Fraud Detection: load ONNX model and start background inference worker.
        // Mode: "shadow" = log only (default), "active" = auto-ban flagged IPs.
        if let Some(ref model_path) = cfg_snapshot.ml_fraud_model_path {
            let ml_engine = std::sync::Arc::new(waf::ml_fraud::MlFraudEngine::new());
            let mode_str = cfg_snapshot.ml_fraud_mode.as_deref().unwrap_or("shadow");
            if mode_str == "active" {
                ml_engine.mode.store(std::sync::Arc::new(waf::ml_fraud::MlFraudMode::Active));
            }
            let ml_reputation = std::sync::Arc::clone(&waf_engine.as_ref().reputation);
            ml_engine.load_model(model_path, ml_reputation).await;
            tracing::info!("ML Fraud Engine started in {} mode from {}", mode_str, model_path);
        }

        let cfg_proxy = Arc::clone(&cfg_snapshot);
        proxy::start_proxy(
            &cfg_proxy.proxy_bind,
            cfg.clone(),
            upstreams.clone(),
            tls_acceptor.clone(),
            waf_engine.clone(),
            rate_limiter.clone(),
            ai_engine.clone(),
            cache.clone(),
            hook_engine.clone(),
            metrics.clone(),
            access_logger.clone(),
            geo_db.clone(),
            geo_policy.clone(),
            sticky.clone(),
            zone_limiter.clone(),
            shutdown_token.clone(),
            oidc_sessions,
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
