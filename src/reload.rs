//! SIGHUP-driven hot-reload handler.
//!
//! Allows Phalanx to pick up configuration changes at runtime without
//! restarting the process. Sends the new config through an `ArcSwap` for
//! lock-free reads and a `watch` channel for listener supervisors.
//!
//! ## Reloadable subsystems
//!
//! | Subsystem        | What changes                                      |
//! |------------------|---------------------------------------------------|
//! | Config + TLS     | All config values, TLS certificates                |
//! | Upstreams        | Backend pools, health check targets                |
//! | Rate limiter     | per-IP rate, burst, global rate                    |
//! | WAF              | OWASP rules recompiled, policy file re-read        |
//! | GeoIP            | CSV database re-read, lookup cache cleared         |
//! | Hook engine      | Rhai script file re-read and re-registered         |
//! | Zone limiter     | Rate/burst/max-connection limits                   |
//! | GSLB             | Data center list, routing policy                   |
//!
//! ## Not reloadable (require restart)
//!
//! AI routing algorithm, CAPTCHA provider, Wasm plugins, K8s ingress class,
//! ML fraud model, worker thread count.

use arc_swap::ArcSwap;
use parking_lot::RwLock;
use serde::Serialize;
use std::sync::Arc;
use tracing::info;

/// Snapshot of the most recent SIGHUP reload attempt.
#[derive(Debug, Clone, Serialize)]
pub struct ReloadStatus {
    /// Epoch seconds when the reload was attempted.
    pub last_attempt: u64,
    /// True if all subsystems reloaded without error and config was swapped.
    pub success: bool,
    /// Human-readable errors from subsystems that failed during reload.
    pub errors: Vec<String>,
}

/// Spawns a background task that listens for SIGHUP (Unix) signals.
/// On SIGHUP, it re-reads `phalanx.conf`, parses it into a new `AppConfig`,
/// and atomically swaps the shared configuration pointer via `ArcSwap`.
///
/// This enables zero-downtime configuration changes such as:
/// - Adding/removing upstream backends
/// - Changing rate limit thresholds
/// - Toggling WAF rules
/// - Switching AI routing algorithms
/// - Updating GeoIP database
/// - Reloading Rhai scripts
/// - Adjusting zone limiter parameters
/// - Reconfiguring GSLB data centers and policy
pub fn spawn_reload_handler(
    config: Arc<ArcSwap<crate::config::AppConfig>>,
    tls_acceptor: Arc<ArcSwap<Option<tokio_rustls::TlsAcceptor>>>,
    upstreams: Arc<crate::routing::UpstreamManager>,
    discovery: Arc<crate::discovery::ServiceDiscovery>,
    conf_path: String,
    config_policy: crate::config::ConfigParsePolicy,
    config_updates: tokio::sync::watch::Sender<Arc<crate::config::AppConfig>>,
    rate_limiter: Arc<crate::middleware::ratelimit::PhalanxRateLimiter>,
    waf_engine: Arc<crate::waf::WafEngine>,
    geo_db: Arc<Option<crate::geo::GeoIpDatabase>>,
    hook_engine: Arc<crate::scripting::HookEngine>,
    zone_limiter: Arc<crate::middleware::connlimit::ZoneLimiter>,
    gslb_router: Arc<Option<crate::gslb::GslbRouter>>,
    cancel: tokio_util::sync::CancellationToken,
    reload_status: Arc<RwLock<Option<ReloadStatus>>>,
    dynamic_certs: Arc<dashmap::DashMap<String, crate::admin::api::SslCertEntry>>,
) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sighup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to register SIGHUP handler: {}", e);
                    return;
                }
            };

            loop {
                sighup.recv().await;
                info!("SIGHUP received — reloading configuration...");

                let attempt_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut errors: Vec<String> = Vec::new();

                let new_config = match crate::config::try_load_config(&conf_path, config_policy) {
                    Ok(cfg) => Arc::new(cfg),
                    Err(e) => {
                        errors.push(format!("Config parse error: {}", e));
                        *reload_status.write() = Some(ReloadStatus {
                            last_attempt: attempt_time,
                            success: false,
                            errors,
                        });
                        continue;
                    }
                };
                info!(
                    "Config reloaded: {} workers, {} upstream pools, {} routes",
                    new_config.workers,
                    new_config.upstreams.len(),
                    new_config.routes.len(),
                );

                // ── Core: TLS + Upstreams ──
                let new_tls = crate::proxy::tls::reload_tls_acceptor(
                    new_config.as_ref(),
                    Some(Arc::clone(&dynamic_certs)),
                )
                .await;
                // Only swap the TLS acceptor if the new one loaded successfully.
                // reload_tls_acceptor returns None when certs are malformed or missing —
                // keeping the previous acceptor in place avoids dropping all TLS traffic.
                if new_tls.is_some() {
                    tls_acceptor.store(Arc::new(new_tls));
                }
                upstreams.reload_from_config(
                    new_config.as_ref(),
                    Arc::clone(&discovery),
                    cancel.clone(),
                );

                // ── Rate limiter ──
                rate_limiter.reload(
                    new_config.rate_limit_per_ip_sec,
                    new_config.rate_limit_burst,
                    new_config.global_rate_limit_sec,
                );

                // ── WAF rules + policy ──
                waf_engine.reload_rules();
                if let Some(ref policy_path) = new_config.waf_policy_path {
                    if let Err(e) = waf_engine.reload_policy(policy_path) {
                        errors.push(format!("WAF policy reload failed: {}", e));
                    }
                }

                // ── GeoIP database ──
                if let Some(ref db) = *geo_db {
                    if let Some(ref db_path) = new_config.geoip_db_path {
                        if let Err(e) = db.reload(db_path) {
                            errors.push(format!("GeoIP reload failed: {}", e));
                        }
                    }
                }

                // ── Rhai hook engine ──
                if let Some(ref script_path) = new_config.rhai_script {
                    if let Err(e) = hook_engine.reload_rhai_script(script_path) {
                        errors.push(format!("Rhai script reload failed: {}", e));
                    }
                }

                // ── Zone limiter ──
                zone_limiter.reload(
                    new_config.zone_rate_per_sec,
                    new_config.zone_burst,
                    new_config.zone_max_connections,
                );

                // ── GSLB router ──
                if let Some(ref router) = *gslb_router {
                    if let Some(ref policy_str) = new_config.gslb_policy {
                        let new_policy = crate::gslb::GslbPolicy::from_str(policy_str);
                        router.set_policy(new_policy);
                        info!("GSLB policy reloaded: {:?}", new_policy);
                    }
                }

                // ── Swap config pointer last (after all subsystems are updated) ──
                if !errors.is_empty() {
                    tracing::error!(
                        "Reload aborted — {} subsystem error(s). Config NOT swapped.",
                        errors.len()
                    );
                    *reload_status.write() = Some(ReloadStatus {
                        last_attempt: attempt_time,
                        success: false,
                        errors,
                    });
                    continue;
                }

                config.store(Arc::clone(&new_config));
                if let Err(e) = config_updates.send(Arc::clone(&new_config)) {
                    tracing::warn!("Config update channel closed (no listeners): {}", e);
                }
                *reload_status.write() = Some(ReloadStatus {
                    last_attempt: attempt_time,
                    success: true,
                    errors: Vec::new(),
                });
                info!("Configuration swap complete — all reloadable subsystems updated.");
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix platforms, SIGHUP is not available.
            // The hot-reload feature is disabled.
            tracing::warn!("Hot reload (SIGHUP) is only supported on Unix platforms.");
            let _config = config; // suppress unused warning
            let _tls_acceptor = tls_acceptor; // suppress unused warning
            let _config_updates = config_updates; // suppress unused warning
            let _rate_limiter = rate_limiter;
            let _waf_engine = waf_engine;
            let _geo_db = geo_db;
            let _hook_engine = hook_engine;
            let _zone_limiter = zone_limiter;
            let _gslb_router = gslb_router;
            std::future::pending::<()>().await;
        }
    });
}
