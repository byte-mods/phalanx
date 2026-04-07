//! Telemetry subsystem: structured logging, distributed tracing, and bandwidth monitoring.
//!
//! Initialises the `tracing` subscriber stack. When an OpenTelemetry OTLP
//! endpoint is configured, spans are exported to a collector (Jaeger, Tempo,
//! Datadog, etc.) for end-to-end distributed tracing.

/// Structured access log writer supporting JSON, combined, and common formats.
pub mod access_log;
/// Per-protocol bandwidth tracking with atomic counters and threshold alerts.
pub mod bandwidth;
/// OpenTelemetry OTLP exporter and W3C Trace Context propagation.
pub mod otel;

use opentelemetry::trace::TracerProvider;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Bootstraps the global `tracing` subscriber with an env-based filter and an
/// optional OpenTelemetry OTLP export layer.
///
/// # Arguments
/// * `otel_endpoint` - OTLP gRPC endpoint (e.g. `http://localhost:4317`). `None` disables tracing export.
/// * `otel_service_name` - Service name reported to the collector. Defaults to `"phalanx"`.
///
/// # Returns
/// The `SdkTracerProvider` if OTLP was initialised. The caller must keep the
/// provider alive for the process lifetime; dropping it flushes pending spans.
pub fn init_telemetry(
    otel_endpoint: Option<&str>,
    otel_service_name: Option<&str>,
) -> Option<opentelemetry_sdk::trace::SdkTracerProvider> {
    // Honour RUST_LOG if set, otherwise default to debug for this crate and info globally
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "ai_load_balancer=debug,info".into());

    let otel_provider = otel_endpoint.and_then(|endpoint| {
        let service = otel_service_name.unwrap_or("phalanx");
        otel::init_otel_layer(endpoint, service)
    });

    // Wire the fmt layer (stdout) and optional OTel layer into the subscriber
    if let Some(provider) = otel_provider.clone() {
        let tracer = provider.tracer("phalanx");
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    tracing::info!("Telemetry initialized.");
    otel_provider
}
