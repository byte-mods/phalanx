pub mod access_log;
pub mod otel;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_telemetry() {
    // Initialize tracing with env-filter and formatted stdout output.
    // The OpenTelemetry OTLP layer is installed separately via `install_otel_layer()`
    // after the config file is parsed (since we need the endpoint URL from config).
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ai_load_balancer=debug,info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Telemetry initialized.");
}
