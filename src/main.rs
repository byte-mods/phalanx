//! Binary entrypoint for the Phalanx AI Load Balancer.
//!
//! Orchestrates startup, wires all subsystems, spawns supervised
//! listener tasks, and handles graceful shutdown.

// Core module declarations are now in lib.rs
use ai_load_balancer::*;

use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::info;

/// The main entry point for the Phalanx AI Load Balancer.
/// We use a standard synchronous `main` function here instead of `#[tokio::main]`
/// because we need to parse the configuration file *before* building the async runtime
/// to determine how many worker threads the runtime should use.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load Configuration (Synchronous)
    // This reads the path provided or defaults to `phalanx.conf` and parses Nginx-like blocks into the `AppConfig` struct.
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "phalanx.conf".to_string());
    let config_policy = config::ConfigParsePolicy::from_env();
    let initial_cfg = config::try_load_config(&config_path, config_policy).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    let cfg = Arc::new(ArcSwap::from_pointee(initial_cfg));

    // Snapshot the current config for components that need a static Arc<AppConfig>
    let cfg_snapshot = cfg.load_full();

    // 2. Initialize Telemetry (Logging, Metrics, Tracing)
    let _otel_provider = telemetry::init_telemetry(
        cfg_snapshot.otel_endpoint.as_deref(),
        cfg_snapshot.otel_service_name.as_deref(),
    );

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

        // Setup TLS (shared, hot-reloadable)
        let tls_acceptor = Arc::new(ArcSwap::from_pointee(proxy::tls::load_tls_acceptor(
            &cfg_snapshot,
        )));

        // Service Discovery: RocksDB-backed persistent backend registry.
        let discovery = Arc::new(discovery::ServiceDiscovery::new("data/discovery.db"));

        // State & Routing: Manages backend health and load balancing algorithms.
        let upstreams = Arc::new(routing::UpstreamManager::new(
            &cfg_snapshot,
            discovery.clone(),
        ));
        let (config_updates_tx, config_updates_rx) = watch::channel(Arc::clone(&cfg_snapshot));

        // Hot reload handler is spawned below after all subsystems are initialized.

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
        let captcha_manager = Arc::new(
            match (
                cfg_snapshot.captcha_site_key.clone(),
                cfg_snapshot.captcha_secret_key.clone(),
            ) {
                (Some(site_key), Some(secret_key)) => {
                    let provider = waf::bot::CaptchaProvider::from_str(
                        cfg_snapshot
                            .captcha_provider
                            .as_deref()
                            .unwrap_or("hcaptcha"),
                    );
                    let threshold = cfg_snapshot.captcha_challenge_threshold.unwrap_or(5.0);
                    Some(waf::bot::CaptchaManager::new(
                        site_key,
                        secret_key,
                        provider,
                        threshold,
                    ))
                }
                _ => None,
            },
        );

        // Service Discovery: DNS SRV records
        for (pool_name, pool_config) in &cfg_snapshot.upstreams {
            if let Some(srv_name) = &pool_config.srv_discover {
                if let Some(pool) = upstreams.get_pool(pool_name) {
                    let template = pool_config.backends.first().cloned().unwrap_or_default();
                    discovery::spawn_srv_watcher(pool_name.clone(), srv_name.to_string(), pool, template, shutdown_token.clone());
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

        let admin_state = admin::AdminState {
            metrics: Arc::clone(&metrics),
            discovery: Arc::clone(&discovery),
            manager: Arc::clone(&upstreams),
            keyval: Arc::clone(&keyval),
            waf: Arc::clone(&waf_engine),
            cache: Arc::clone(&cache),
            rate_limiter: Arc::clone(&rate_limiter),
            bandwidth: Arc::clone(&bandwidth_tracker),
            alert_engine: Arc::clone(&alert_engine),
        };

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

        // GSLB Router: geographic traffic steering across data centers
        let gslb_router: Arc<Option<gslb::GslbRouter>> = Arc::new(
            cfg_snapshot.gslb_policy.as_deref().map(|policy_str| {
                let policy = gslb::GslbPolicy::from_str(policy_str);
                let max_latency = cfg_snapshot.gslb_max_latency_ms.unwrap_or(500.0);
                let router = gslb::GslbRouter::new(policy, max_latency, 3);
                tracing::info!("GSLB router initialized with {:?} policy", policy);
                router
            }),
        );

        // K8s Ingress Controller: watches K8s resources and generates routes
        let k8s_controller: Arc<Option<k8s::IngressController>> = Arc::new(
            if cfg_snapshot.k8s_ingress_enabled {
                let ingress_class = cfg_snapshot
                    .k8s_ingress_class
                    .as_deref()
                    .unwrap_or("phalanx");
                let controller = k8s::IngressController::new(ingress_class, "cluster.local");
                tracing::info!(
                    "Kubernetes Ingress controller enabled (class: {})",
                    ingress_class
                );
                Some(controller)
            } else {
                None
            },
        );

        // Hook engine (pre-populated from rhai_script if configured)
        let hook_engine = {
            let engine = scripting::HookEngine::new();
            if let Some(ref script_path) = cfg_snapshot.rhai_script {
                match scripting::rhai_engine::RhaiHookHandler::from_file(script_path) {
                    Ok(handler) => {
                        engine.register(scripting::Hook {
                            name: format!("rhai:{}", script_path),
                            phase: scripting::HookPhase::PreRoute,
                            priority: 0,
                            handler: Box::new(handler),
                        });
                        tracing::info!("Rhai script loaded from {}", script_path);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load Rhai script {}: {}", script_path, e);
                    }
                }
            }
            Arc::new(engine)
        };

        // Wasm Plugin Manager: native Rust plugins loaded from config file
        let wasm_plugins = Arc::new(wasm::WasmPluginManager::new());
        if let Some(ref wasm_config_path) = cfg_snapshot.wasm_plugin_config_path {
            match wasm::WasmPluginManager::load_config_from_file(wasm_config_path) {
                Ok(configs) => {
                    for plugin_cfg in configs {
                        if !plugin_cfg.enabled {
                            continue;
                        }
                        // Create native plugin instances based on name convention
                        let plugin: Arc<dyn wasm::WasmPlugin> = match plugin_cfg.name.as_str() {
                            name if name.starts_with("header-injection") => {
                                let headers: Vec<(String, String)> = serde_json::from_str(&plugin_cfg.config)
                                    .unwrap_or_default();
                                Arc::new(wasm::HeaderInjectionPlugin::new(name, headers))
                            }
                            name if name.starts_with("path-blocker") => {
                                let patterns: Vec<String> = serde_json::from_str(&plugin_cfg.config)
                                    .unwrap_or_default();
                                Arc::new(wasm::PathBlockerPlugin::new(name, patterns))
                            }
                            name if name.starts_with("header-rate-limit") => {
                                #[derive(serde::Deserialize)]
                                struct RlCfg { header: String, max: u64 }
                                let rl: RlCfg = serde_json::from_str(&plugin_cfg.config)
                                    .unwrap_or(RlCfg { header: "x-api-key".into(), max: 100 });
                                Arc::new(wasm::HeaderRateLimitPlugin::new(name, &rl.header, rl.max))
                            }
                            _ => {
                                tracing::warn!("Unknown Wasm plugin type: {}", plugin_cfg.name);
                                continue;
                            }
                        };
                        wasm_plugins.register(plugin, plugin_cfg);
                    }
                    tracing::info!(
                        "Wasm plugins loaded from {} ({} active)",
                        wasm_config_path,
                        wasm_plugins.plugin_count()
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to load Wasm plugin config from {}: {}", wasm_config_path, e);
                }
            }
        }

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
            cfg_snapshot.zone_rate_per_sec,
            cfg_snapshot.zone_burst,
            cfg_snapshot.zone_max_connections,
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
        let cluster_state = std::sync::Arc::new({
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

        // Spawn cluster heartbeat (30s interval, 90s TTL = 3× interval)
        Arc::clone(&cluster_state).spawn_heartbeat(30);

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

        // ML Fraud Detection: load ONNX model into the WAF engine's ml_engine
        // and start background inference worker.
        // Mode: "shadow" = log only (default), "active" = auto-ban flagged IPs.
        if let Some(ref model_path) = cfg_snapshot.ml_fraud_model_path {
            let mode_str = cfg_snapshot.ml_fraud_mode.as_deref().unwrap_or("shadow");
            if mode_str == "active" {
                waf_engine.ml_engine.mode.store(std::sync::Arc::new(waf::ml_fraud::MlFraudMode::Active));
            }
            let ml_reputation = std::sync::Arc::clone(&waf_engine.reputation);
            waf_engine.ml_engine.load_model(
                model_path,
                ml_reputation,
                Some(metrics.ml_model_load_failures.clone()),
            ).await;
            tracing::info!("ML Fraud Engine started in {} mode from {}", mode_str, model_path);
        }

        // --- Hot Reload (SIGHUP) ---
        // Spawned after all subsystems are initialized so the reload handler
        // can propagate config changes to every reloadable component.
        reload::spawn_reload_handler(
            Arc::clone(&cfg),
            Arc::clone(&tls_acceptor),
            Arc::clone(&upstreams),
            Arc::clone(&discovery),
            config_path.clone(),
            config_policy,
            config_updates_tx,
            Arc::clone(&rate_limiter),
            Arc::clone(&waf_engine),
            Arc::clone(&geo_db),
            Arc::clone(&hook_engine),
            Arc::clone(&zone_limiter),
            Arc::clone(&gslb_router),
        );

        let mut supervisor_handles: Vec<JoinHandle<()>> = Vec::new();

        supervisor_handles.push(tokio::spawn(supervise_proxy_listener(
            config_updates_rx.clone(),
            Arc::clone(&cfg),
            Arc::clone(&upstreams),
            Arc::clone(&tls_acceptor),
            Arc::clone(&waf_engine),
            Arc::clone(&rate_limiter),
            Arc::clone(&ai_engine),
            Arc::clone(&cache),
            Arc::clone(&hook_engine),
            Arc::clone(&metrics),
            Arc::clone(&access_logger),
            Arc::clone(&geo_db),
            Arc::clone(&geo_policy),
            Arc::clone(&sticky),
            Arc::clone(&zone_limiter),
            Arc::clone(&captcha_manager),
            Arc::clone(&wasm_plugins),
            Arc::clone(&gslb_router),
            Arc::clone(&k8s_controller),
            Arc::clone(&bandwidth_tracker),
            shutdown_token.clone(),
            Arc::clone(&oidc_sessions),
        )));
        supervisor_handles.push(tokio::spawn(supervise_admin_listener(
            config_updates_rx.clone(),
            admin_state,
            shutdown_token.clone(),
        )));
        supervisor_handles.push(tokio::spawn(supervise_tcp_listener(
            config_updates_rx.clone(),
            Arc::clone(&upstreams),
            shutdown_token.clone(),
        )));
        supervisor_handles.push(tokio::spawn(supervise_udp_listener(
            config_updates_rx.clone(),
            Arc::clone(&upstreams),
            shutdown_token.clone(),
        )));
        supervisor_handles.push(tokio::spawn(supervise_mail_listener(
            config_updates_rx.clone(),
            mail::MailProtocol::Smtp,
            Arc::clone(&upstreams),
            shutdown_token.clone(),
        )));
        supervisor_handles.push(tokio::spawn(supervise_mail_listener(
            config_updates_rx.clone(),
            mail::MailProtocol::Imap,
            Arc::clone(&upstreams),
            shutdown_token.clone(),
        )));
        supervisor_handles.push(tokio::spawn(supervise_mail_listener(
            config_updates_rx.clone(),
            mail::MailProtocol::Pop3,
            Arc::clone(&upstreams),
            shutdown_token.clone(),
        )));
        supervisor_handles.push(tokio::spawn(supervise_http3_listener(
            config_updates_rx,
            Arc::clone(&upstreams),
            Arc::clone(&metrics),
            Arc::clone(&cache),
            Arc::clone(&ai_engine),
            Arc::clone(&waf_engine),
            Arc::clone(&rate_limiter),
            Arc::clone(&geo_db),
            Arc::clone(&geo_policy),
            Arc::clone(&captcha_manager),
            Arc::clone(&zone_limiter),
            Arc::clone(&hook_engine),
            Arc::clone(&wasm_plugins),
            Arc::clone(&sticky),
            Arc::clone(&access_logger),
            Arc::clone(&bandwidth_tracker),
            shutdown_token.clone(),
        )));

        shutdown_token.cancelled().await;
        let shutdown_timeout = cfg.load_full().shutdown_timeout_secs;
        tracing::info!("Waiting up to {}s for in-flight requests to drain...", shutdown_timeout);
        let drain_result = tokio::time::timeout(
            std::time::Duration::from_secs(shutdown_timeout),
            async {
                for handle in supervisor_handles {
                    let _ = handle.await;
                }
            },
        ).await;
        if drain_result.is_err() {
            tracing::warn!(
                "Graceful shutdown timeout ({}s) exceeded — force-stopping remaining tasks",
                shutdown_timeout
            );
        } else {
            tracing::info!("All listeners drained cleanly");
        }
    });

    Ok(())
}

/// Tracks a spawned listener task together with its cancellation token,
/// allowing the supervisor to stop or await the task.
struct RunningListener {
    /// Token that, when cancelled, signals the listener to shut down.
    shutdown: CancellationToken,
    /// The join handle for the spawned async task.
    handle: JoinHandle<()>,
}

impl RunningListener {
    /// Waits for the listener task to complete without cancelling it.
    async fn join(self) -> Result<(), tokio::task::JoinError> {
        self.handle.await
    }

    /// Signals the listener to stop and waits for it to finish.
    async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.handle.await;
    }
}

/// Computes exponential backoff delay for listener restarts.
/// Caps at 2^5 = 32 seconds to avoid unbounded waits.
fn listener_restart_backoff(attempt: u32) -> std::time::Duration {
    // Shift by attempt (capped at 5), giving 1s, 2s, 4s, 8s, 16s, 32s
    let capped = attempt.min(5);
    std::time::Duration::from_secs(1u64 << capped)
}

/// Supervises the main HTTP/HTTPS proxy listener.
///
/// Monitors the spawned listener for unexpected exits and restarts it with
/// exponential backoff. Also watches the config `watch` channel for bind-address
/// changes and hot-swaps the listener when the address changes.
async fn supervise_proxy_listener(
    mut config_rx: watch::Receiver<Arc<config::AppConfig>>,
    app_config: Arc<ArcSwap<config::AppConfig>>,
    upstreams: Arc<routing::UpstreamManager>,
    tls_acceptor: Arc<ArcSwap<Option<tokio_rustls::TlsAcceptor>>>,
    waf: Arc<waf::WafEngine>,
    rate_limiter: Arc<middleware::ratelimit::PhalanxRateLimiter>,
    ai_engine: Arc<dyn ai::AiRouter>,
    cache: Arc<middleware::cache::AdvancedCache>,
    hook_engine: Arc<scripting::HookEngine>,
    metrics: Arc<admin::ProxyMetrics>,
    access_logger: Arc<telemetry::access_log::AccessLogger>,
    geo_db: Arc<Option<geo::GeoIpDatabase>>,
    geo_policy: Arc<geo::GeoPolicy>,
    sticky: Arc<Option<proxy::sticky::StickySessionManager>>,
    zone_limiter: Arc<middleware::connlimit::ZoneLimiter>,
    captcha_manager: Arc<Option<waf::bot::CaptchaManager>>,
    wasm_plugins: Arc<wasm::WasmPluginManager>,
    gslb_router: Arc<Option<gslb::GslbRouter>>,
    k8s_controller: Arc<Option<k8s::IngressController>>,
    bandwidth: Arc<telemetry::bandwidth::BandwidthTracker>,
    shutdown: CancellationToken,
    oidc_sessions: auth::oidc::OidcSessionStore,
) {
    let start = |bind_addr: String| {
        let listener_shutdown = shutdown.child_token();
        let task_shutdown = listener_shutdown.clone();
        let app_config = Arc::clone(&app_config);
        let upstreams = Arc::clone(&upstreams);
        let tls_acceptor = Arc::clone(&tls_acceptor);
        let waf = Arc::clone(&waf);
        let rate_limiter = Arc::clone(&rate_limiter);
        let ai_engine = Arc::clone(&ai_engine);
        let cache = Arc::clone(&cache);
        let hook_engine = Arc::clone(&hook_engine);
        let metrics = Arc::clone(&metrics);
        let access_logger = Arc::clone(&access_logger);
        let geo_db = Arc::clone(&geo_db);
        let geo_policy = Arc::clone(&geo_policy);
        let sticky = Arc::clone(&sticky);
        let zone_limiter = Arc::clone(&zone_limiter);
        let captcha_manager = Arc::clone(&captcha_manager);
        let wasm_plugins = Arc::clone(&wasm_plugins);
        let gslb_router = Arc::clone(&gslb_router);
        let k8s_controller = Arc::clone(&k8s_controller);
        let bandwidth = Arc::clone(&bandwidth);
        let oidc_sessions = Arc::clone(&oidc_sessions);
        let handle = tokio::spawn(async move {
            proxy::start_proxy(
                &bind_addr,
                app_config,
                upstreams,
                tls_acceptor,
                waf,
                rate_limiter,
                ai_engine,
                cache,
                hook_engine,
                metrics,
                access_logger,
                geo_db,
                geo_policy,
                sticky,
                zone_limiter,
                captcha_manager,
                wasm_plugins,
                gslb_router,
                k8s_controller,
                bandwidth,
                task_shutdown,
                oidc_sessions,
            )
            .await;
        });
        RunningListener {
            shutdown: listener_shutdown,
            handle,
        }
    };

    let mut current_bind = config_rx.borrow().proxy_bind.clone();
    let mut running = Some(start(current_bind.clone()));
    let mut restart_attempt: u32 = 0;
    let mut health_tick = time::interval(std::time::Duration::from_secs(1));
    health_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = health_tick.tick() => {
                let finished = running
                    .as_ref()
                    .is_some_and(|task| task.handle.is_finished());
                if finished {
                    if let Some(task) = running.take() {
                        if let Err(e) = task.join().await {
                            tracing::warn!("Proxy listener task join error: {}", e);
                        }
                    }
                    if shutdown.is_cancelled() {
                        break;
                    }
                    let backoff = listener_restart_backoff(restart_attempt);
                    tracing::warn!(
                        "Proxy listener task exited unexpectedly. Restarting in {:?}.",
                        backoff
                    );
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = time::sleep(backoff) => {}
                    }
                    running = Some(start(current_bind.clone()));
                    restart_attempt = restart_attempt.saturating_add(1);
                }
            }
            changed = config_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let next_bind = config_rx.borrow().proxy_bind.clone();
                if next_bind != current_bind {
                    info!(
                        "Proxy listener bind changed: {} -> {}. Restarting listener.",
                        current_bind,
                        next_bind
                    );
                    if let Some(task) = running.take() {
                        task.stop().await;
                    }
                    current_bind = next_bind.clone();
                    running = Some(start(next_bind));
                    restart_attempt = 0;
                }
            }
        }
    }

    if let Some(task) = running.take() {
        task.stop().await;
    }
}

/// Supervises the admin/metrics API listener (Actix-Web).
///
/// Restarts with backoff on unexpected exit; hot-swaps when
/// `admin_bind` changes in the config.
async fn supervise_admin_listener(
    mut config_rx: watch::Receiver<Arc<config::AppConfig>>,
    state: admin::AdminState,
    shutdown: CancellationToken,
) {
    let start = |bind_addr: String| {
        let listener_shutdown = shutdown.child_token();
        let task_shutdown = listener_shutdown.clone();
        let state = state.clone();
        let handle = tokio::spawn(async move {
            admin::start_admin_server(bind_addr, state, task_shutdown).await;
        });
        RunningListener {
            shutdown: listener_shutdown,
            handle,
        }
    };

    let mut current_bind = config_rx.borrow().admin_bind.clone();
    let mut running = Some(start(current_bind.clone()));
    let mut restart_attempt: u32 = 0;
    let mut health_tick = time::interval(std::time::Duration::from_secs(1));
    health_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = health_tick.tick() => {
                let finished = running
                    .as_ref()
                    .is_some_and(|task| task.handle.is_finished());
                if finished {
                    if let Some(task) = running.take() {
                        if let Err(e) = task.join().await {
                            tracing::warn!("Admin listener task join error: {}", e);
                        }
                    }
                    if shutdown.is_cancelled() {
                        break;
                    }
                    let backoff = listener_restart_backoff(restart_attempt);
                    tracing::warn!(
                        "Admin listener task exited unexpectedly. Restarting in {:?}.",
                        backoff
                    );
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = time::sleep(backoff) => {}
                    }
                    running = Some(start(current_bind.clone()));
                    restart_attempt = restart_attempt.saturating_add(1);
                }
            }
            changed = config_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let next_bind = config_rx.borrow().admin_bind.clone();
                if next_bind != current_bind {
                    info!(
                        "Admin listener bind changed: {} -> {}. Restarting listener.",
                        current_bind,
                        next_bind
                    );
                    if let Some(task) = running.take() {
                        task.stop().await;
                    }
                    current_bind = next_bind.clone();
                    running = Some(start(next_bind));
                    restart_attempt = 0;
                }
            }
        }
    }

    if let Some(task) = running.take() {
        task.stop().await;
    }
}

/// Supervises the Layer-4 TCP proxy listener.
///
/// Restarts with backoff on unexpected exit; hot-swaps when
/// `tcp_bind` changes in the config.
async fn supervise_tcp_listener(
    mut config_rx: watch::Receiver<Arc<config::AppConfig>>,
    upstreams: Arc<routing::UpstreamManager>,
    shutdown: CancellationToken,
) {
    let start = |bind_addr: String| {
        let listener_shutdown = shutdown.child_token();
        let task_shutdown = listener_shutdown.clone();
        let upstreams = Arc::clone(&upstreams);
        let handle = tokio::spawn(async move {
            proxy::tcp::start_tcp_proxy(&bind_addr, upstreams, task_shutdown).await;
        });
        RunningListener {
            shutdown: listener_shutdown,
            handle,
        }
    };

    let mut current_bind = config_rx.borrow().tcp_bind.clone();
    let mut running = Some(start(current_bind.clone()));
    let mut restart_attempt: u32 = 0;
    let mut health_tick = time::interval(std::time::Duration::from_secs(1));
    health_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = health_tick.tick() => {
                let finished = running
                    .as_ref()
                    .is_some_and(|task| task.handle.is_finished());
                if finished {
                    if let Some(task) = running.take() {
                        if let Err(e) = task.join().await {
                            tracing::warn!("TCP listener task join error: {}", e);
                        }
                    }
                    if shutdown.is_cancelled() {
                        break;
                    }
                    let backoff = listener_restart_backoff(restart_attempt);
                    tracing::warn!(
                        "TCP listener task exited unexpectedly. Restarting in {:?}.",
                        backoff
                    );
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = time::sleep(backoff) => {}
                    }
                    running = Some(start(current_bind.clone()));
                    restart_attempt = restart_attempt.saturating_add(1);
                }
            }
            changed = config_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let next_bind = config_rx.borrow().tcp_bind.clone();
                if next_bind != current_bind {
                    info!(
                        "TCP listener bind changed: {} -> {}. Restarting listener.",
                        current_bind,
                        next_bind
                    );
                    if let Some(task) = running.take() {
                        task.stop().await;
                    }
                    current_bind = next_bind.clone();
                    running = Some(start(next_bind));
                    restart_attempt = 0;
                }
            }
        }
    }

    if let Some(task) = running.take() {
        task.stop().await;
    }
}

/// Supervises the UDP proxy listener (optional; only active when `udp_bind` is configured).
///
/// Restarts with backoff on unexpected exit; hot-swaps when
/// `udp_bind` changes in the config.
async fn supervise_udp_listener(
    mut config_rx: watch::Receiver<Arc<config::AppConfig>>,
    upstreams: Arc<routing::UpstreamManager>,
    shutdown: CancellationToken,
) {
    let start = |bind_addr: String, session_timeout_secs: u64| {
        let listener_shutdown = shutdown.child_token();
        let task_shutdown = listener_shutdown.clone();
        let upstreams = Arc::clone(&upstreams);
        let timeout = std::time::Duration::from_secs(session_timeout_secs);
        let handle = tokio::spawn(async move {
            proxy::udp::start_udp_proxy(&bind_addr, upstreams, timeout, task_shutdown).await;
        });
        RunningListener {
            shutdown: listener_shutdown,
            handle,
        }
    };

    let (mut current_bind, current_timeout) = {
        let cfg = config_rx.borrow();
        (cfg.udp_bind.clone(), cfg.udp_session_timeout_secs)
    };
    let mut running = current_bind.clone().map(|addr| start(addr, current_timeout));
    let mut restart_attempt: u32 = 0;
    let mut health_tick = time::interval(std::time::Duration::from_secs(1));
    health_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = health_tick.tick() => {
                let finished = running
                    .as_ref()
                    .is_some_and(|task| task.handle.is_finished());
                if finished {
                    if let Some(task) = running.take() {
                        if let Err(e) = task.join().await {
                            tracing::warn!("UDP listener task join error: {}", e);
                        }
                    }
                    if shutdown.is_cancelled() {
                        break;
                    }
                    if current_bind.is_some() {
                        let backoff = listener_restart_backoff(restart_attempt);
                        tracing::warn!(
                            "UDP listener task exited unexpectedly. Restarting in {:?}.",
                            backoff
                        );
                        tokio::select! {
                            _ = shutdown.cancelled() => break,
                            _ = time::sleep(backoff) => {}
                        }
                        let timeout = config_rx.borrow().udp_session_timeout_secs;
                        running = current_bind.clone().map(|addr| start(addr, timeout));
                        restart_attempt = restart_attempt.saturating_add(1);
                    }
                }
            }
            changed = config_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let (next_bind, timeout) = {
                    let cfg = config_rx.borrow();
                    (cfg.udp_bind.clone(), cfg.udp_session_timeout_secs)
                };
                if next_bind != current_bind {
                    info!(
                        "UDP listener bind changed: {:?} -> {:?}. Restarting listener.",
                        current_bind,
                        next_bind
                    );
                    if let Some(task) = running.take() {
                        task.stop().await;
                    }
                    current_bind = next_bind.clone();
                    running = next_bind.map(|addr| start(addr, timeout));
                    restart_attempt = 0;
                }
            }
        }
    }

    if let Some(task) = running.take() {
        task.stop().await;
    }
}

/// Supervises a mail protocol (SMTP/IMAP/POP3) proxy listener.
///
/// One instance is spawned per protocol. Restarts with backoff on
/// unexpected exit; hot-swaps when the protocol's bind address or
/// upstream pool changes in the config.
async fn supervise_mail_listener(
    mut config_rx: watch::Receiver<Arc<config::AppConfig>>,
    protocol: mail::MailProtocol,
    upstreams: Arc<routing::UpstreamManager>,
    shutdown: CancellationToken,
) {
    let config_for = |cfg: &config::AppConfig| -> Option<mail::MailProxyConfig> {
        let bind_addr = match protocol {
            mail::MailProtocol::Smtp => cfg.smtp_bind.clone(),
            mail::MailProtocol::Imap => cfg.imap_bind.clone(),
            mail::MailProtocol::Pop3 => cfg.pop3_bind.clone(),
        }?;
        let upstream_pool = cfg
            .mail_upstream_pool
            .clone()
            .unwrap_or_else(|| "default".to_string());
        Some(mail::MailProxyConfig {
            protocol,
            bind_addr,
            upstream_pool,
            banner: None,
            starttls: false,
            tls_cert_path: cfg.tls_cert_path.clone(),
            tls_key_path: cfg.tls_key_path.clone(),
        })
    };
    let start = |mail_cfg: mail::MailProxyConfig, verify_backend_tls: bool| {
        let listener_shutdown = shutdown.child_token();
        let task_shutdown = listener_shutdown.clone();
        let upstreams = Arc::clone(&upstreams);
        let handle = tokio::spawn(async move {
            mail::start_mail_proxy(mail_cfg, upstreams, task_shutdown, verify_backend_tls).await;
        });
        RunningListener {
            shutdown: listener_shutdown,
            handle,
        }
    };

    let (mut current_cfg, mut verify_tls) = {
        let init_cfg = config_rx.borrow();
        (config_for(init_cfg.as_ref()), init_cfg.mail_verify_backend_tls)
    };
    let mut running = current_cfg.clone().map(|c| start(c, verify_tls));
    let mut restart_attempt: u32 = 0;
    let mut health_tick = time::interval(std::time::Duration::from_secs(1));
    health_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = health_tick.tick() => {
                let finished = running
                    .as_ref()
                    .is_some_and(|task| task.handle.is_finished());
                if finished {
                    if let Some(task) = running.take() {
                        if let Err(e) = task.join().await {
                            tracing::warn!("{} listener task join error: {}", protocol.name(), e);
                        }
                    }
                    if shutdown.is_cancelled() {
                        break;
                    }
                    if current_cfg.is_some() {
                        let backoff = listener_restart_backoff(restart_attempt);
                        tracing::warn!(
                            "{} listener task exited unexpectedly. Restarting in {:?}.",
                            protocol.name(),
                            backoff
                        );
                        tokio::select! {
                            _ = shutdown.cancelled() => break,
                            _ = time::sleep(backoff) => {}
                        }
                        verify_tls = config_rx.borrow().mail_verify_backend_tls;
                        running = current_cfg.clone().map(|c| start(c, verify_tls));
                        restart_attempt = restart_attempt.saturating_add(1);
                    }
                }
            }
            changed = config_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let (next_cfg, new_verify_tls) = {
                    let new_cfg_full = config_rx.borrow();
                    (config_for(new_cfg_full.as_ref()), new_cfg_full.mail_verify_backend_tls)
                };
                verify_tls = new_verify_tls;
                if next_cfg.as_ref().map(|c| (&c.bind_addr, &c.upstream_pool))
                    != current_cfg.as_ref().map(|c| (&c.bind_addr, &c.upstream_pool))
                {
                    info!(
                        "{} listener changed: {:?} -> {:?}. Restarting listener.",
                        protocol.name(),
                        current_cfg.as_ref().map(|c| (c.bind_addr.as_str(), c.upstream_pool.as_str())),
                        next_cfg.as_ref().map(|c| (c.bind_addr.as_str(), c.upstream_pool.as_str()))
                    );
                    if let Some(task) = running.take() {
                        task.stop().await;
                    }
                    current_cfg = next_cfg.clone();
                    running = next_cfg.map(|c| start(c, verify_tls));
                    restart_attempt = 0;
                }
            }
        }
    }

    if let Some(task) = running.take() {
        task.stop().await;
    }
}

/// Supervises the HTTP/3 (QUIC) proxy listener (optional; only active when `quic_bind` is set).
///
/// Restarts with backoff on unexpected exit; hot-swaps when
/// `quic_bind` changes in the config.
async fn supervise_http3_listener(
    mut config_rx: watch::Receiver<Arc<config::AppConfig>>,
    upstreams: Arc<routing::UpstreamManager>,
    metrics: Arc<admin::ProxyMetrics>,
    cache: Arc<middleware::cache::AdvancedCache>,
    ai_engine: Arc<dyn ai::AiRouter>,
    waf: Arc<waf::WafEngine>,
    rate_limiter: Arc<middleware::ratelimit::PhalanxRateLimiter>,
    geo_db: Arc<Option<geo::GeoIpDatabase>>,
    geo_policy: Arc<geo::GeoPolicy>,
    captcha_manager: Arc<Option<waf::bot::CaptchaManager>>,
    zone_limiter: Arc<middleware::connlimit::ZoneLimiter>,
    hook_engine: Arc<scripting::HookEngine>,
    wasm_plugins: Arc<wasm::WasmPluginManager>,
    sticky: Arc<Option<proxy::sticky::StickySessionManager>>,
    access_logger: Arc<telemetry::access_log::AccessLogger>,
    bandwidth: Arc<telemetry::bandwidth::BandwidthTracker>,
    shutdown: CancellationToken,
) {
    let start = |bind_addr: String, cfg_snapshot: Arc<config::AppConfig>| {
        let listener_shutdown = shutdown.child_token();
        let task_shutdown = listener_shutdown.clone();
        let upstreams = Arc::clone(&upstreams);
        let metrics = Arc::clone(&metrics);
        let cache = Arc::clone(&cache);
        let ai_engine = Arc::clone(&ai_engine);
        let waf = Arc::clone(&waf);
        let rate_limiter = Arc::clone(&rate_limiter);
        let geo_db = Arc::clone(&geo_db);
        let geo_policy = Arc::clone(&geo_policy);
        let captcha_manager = Arc::clone(&captcha_manager);
        let zone_limiter = Arc::clone(&zone_limiter);
        let hook_engine = Arc::clone(&hook_engine);
        let wasm_plugins = Arc::clone(&wasm_plugins);
        let sticky = Arc::clone(&sticky);
        let access_logger = Arc::clone(&access_logger);
        let bandwidth = Arc::clone(&bandwidth);
        let handle = tokio::spawn(async move {
            proxy::http3::start_http3_proxy(
                &bind_addr,
                cfg_snapshot,
                upstreams,
                metrics,
                cache,
                ai_engine,
                waf,
                rate_limiter,
                geo_db,
                geo_policy,
                captcha_manager,
                zone_limiter,
                hook_engine,
                wasm_plugins,
                sticky,
                access_logger,
                bandwidth,
                task_shutdown,
            )
            .await;
        });
        RunningListener {
            shutdown: listener_shutdown,
            handle,
        }
    };

    let mut current_bind = config_rx.borrow().quic_bind.clone();
    let mut running = current_bind
        .clone()
        .map(|bind| start(bind, config_rx.borrow().clone()));
    let mut restart_attempt: u32 = 0;
    let mut health_tick = time::interval(std::time::Duration::from_secs(1));
    health_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = health_tick.tick() => {
                let finished = running
                    .as_ref()
                    .is_some_and(|task| task.handle.is_finished());
                if finished {
                    if let Some(task) = running.take() {
                        if let Err(e) = task.join().await {
                            tracing::warn!("HTTP/3 listener task join error: {}", e);
                        }
                    }
                    if shutdown.is_cancelled() {
                        break;
                    }
                    if current_bind.is_some() {
                        let backoff = listener_restart_backoff(restart_attempt);
                        tracing::warn!(
                            "HTTP/3 listener task exited unexpectedly. Restarting in {:?}.",
                            backoff
                        );
                        tokio::select! {
                            _ = shutdown.cancelled() => break,
                            _ = time::sleep(backoff) => {}
                        }
                        let cfg_snapshot = config_rx.borrow().clone();
                        running = current_bind.clone().map(|bind| start(bind, cfg_snapshot));
                        restart_attempt = restart_attempt.saturating_add(1);
                    }
                }
            }
            changed = config_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let next_cfg = config_rx.borrow().clone();
                let next_bind = next_cfg.quic_bind.clone();
                let should_restart = next_bind.is_some() && next_bind == current_bind;

                if next_bind != current_bind || should_restart {
                    info!(
                        "HTTP/3 listener changed: {:?} -> {:?}. Restarting listener.",
                        current_bind,
                        next_bind
                    );
                    if let Some(task) = running.take() {
                        task.stop().await;
                    }
                    current_bind = next_bind.clone();
                    running = next_bind.map(|bind| start(bind, Arc::clone(&next_cfg)));
                    restart_attempt = 0;
                }
            }
        }
    }

    if let Some(task) = running.take() {
        task.stop().await;
    }
}

/// Waits for Ctrl+C or SIGTERM to initiate graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => { tracing::info!("Received Ctrl+C"); }
                    _ = sigterm.recv() => { tracing::info!("Received SIGTERM"); }
                }
            }
            Err(e) => {
                tracing::error!("Failed to register SIGTERM handler: {}", e);
                if ctrl_c.await.is_ok() {
                    tracing::info!("Received Ctrl+C");
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(e) = ctrl_c.await {
            tracing::error!("Failed to listen for Ctrl+C: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::listener_restart_backoff;

    #[test]
    fn test_listener_restart_backoff_exponential_until_cap() {
        assert_eq!(listener_restart_backoff(0).as_secs(), 1);
        assert_eq!(listener_restart_backoff(1).as_secs(), 2);
        assert_eq!(listener_restart_backoff(2).as_secs(), 4);
        assert_eq!(listener_restart_backoff(5).as_secs(), 32);
        assert_eq!(listener_restart_backoff(10).as_secs(), 32);
    }
}
