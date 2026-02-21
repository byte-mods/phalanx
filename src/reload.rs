use arc_swap::ArcSwap;
use std::sync::Arc;
use tracing::info;

/// Spawns a background task that listens for SIGHUP (Unix) signals.
/// On SIGHUP, it re-reads `phalanx.conf`, parses it into a new `AppConfig`,
/// and atomically swaps the shared configuration pointer via `ArcSwap`.
///
/// This enables zero-downtime configuration changes such as:
/// - Adding/removing upstream backends
/// - Changing rate limit thresholds
/// - Toggling WAF rules
/// - Switching AI routing algorithms
pub fn spawn_reload_handler(config: Arc<ArcSwap<crate::config::AppConfig>>, conf_path: String) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sighup =
                signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");

            loop {
                sighup.recv().await;
                info!("SIGHUP received — reloading configuration...");

                let new_config = crate::config::load_config(&conf_path);
                info!(
                    "Config reloaded: {} workers, {} upstream pools, {} routes",
                    new_config.workers,
                    new_config.upstreams.len(),
                    new_config.routes.len(),
                );

                config.store(Arc::new(new_config));
                info!("Configuration swap complete (zero-downtime reload).");
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix platforms, SIGHUP is not available.
            // The hot-reload feature is disabled.
            tracing::warn!("Hot reload (SIGHUP) is only supported on Unix platforms.");
            let _config = config; // suppress unused warning
            std::future::pending::<()>().await;
        }
    });
}
