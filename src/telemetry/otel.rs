use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::info;

/// Initializes OpenTelemetry tracing with an OTLP gRPC exporter.
///
/// When an `otel_endpoint` is configured (e.g., `http://localhost:4317`),
/// this sets up trace context propagation (W3C `traceparent` header) and
/// exports spans to a collector like Jaeger, Tempo, or Datadog.
///
/// # Usage in phalanx.conf
///
/// ```text
/// otel_endpoint http://localhost:4317;
/// otel_service_name phalanx-lb;
/// ```
///
/// # Returns
/// `Some(SdkTracerProvider)` on success. Caller must keep the provider alive for the
/// process lifetime — dropping it flushes and shuts down the exporter.
pub fn init_otel_layer(endpoint: &str, service_name: &str) -> Option<SdkTracerProvider> {
    info!(
        "OpenTelemetry OTLP exporter initializing: endpoint={}, service={}",
        endpoint, service_name
    );

    // Build the OTLP span exporter (gRPC / tonic)
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build OTLP exporter: {}", e);
        })
        .ok()?;

    // Build the SDK tracer provider with batch export and service resource
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service_name.to_string())
                .build(),
        )
        .build();

    // Install this tracer as the global OTel provider.
    // After this call, any `opentelemetry::global::tracer()` calls return spans
    // that are exported to the configured collector.
    opentelemetry::global::set_tracer_provider(provider.clone());

    info!(
        "OpenTelemetry: traces exporting to {} as service '{}'",
        endpoint, service_name
    );

    Some(provider)
}

/// Injects W3C Trace Context (`traceparent`) header into outgoing proxy requests.
///
/// Format: `00-{trace_id}-{span_id}-{flags}`
///
/// This enables distributed tracing across the load balancer boundary —
/// backend services that support W3C Trace Context will automatically
/// continue the trace created by Phalanx.
pub fn inject_trace_context(
    headers: &mut hyper::header::HeaderMap,
    trace_id: &str,
    span_id: &str,
    sampled: bool,
) {
    let flags = if sampled { "01" } else { "00" };
    let traceparent = format!("00-{}-{}-{}", trace_id, span_id, flags);
    if let Ok(value) = hyper::header::HeaderValue::from_str(&traceparent) {
        headers.insert(hyper::header::HeaderName::from_static("traceparent"), value);
    }
}
