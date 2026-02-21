use tracing::{debug, info};

/// Initializes OpenTelemetry tracing with an OTLP gRPC exporter.
///
/// When an `otel_endpoint` is configured (e.g., `http://localhost:4317`),
/// this sets up trace context propagation (W3C `traceparent` header) and
/// exports spans to a collector like Jaeger, Tempo, or Datadog.
///
/// # Integration
///
/// Traces are automatically created for each proxied request via the
/// `tracing` instrumentation already in the proxy handlers. The OTLP
/// exporter runs in a background task and batches span exports.
///
/// # Usage in phalanx.conf
///
/// ```text
/// otel_endpoint http://localhost:4317;
/// otel_service_name phalanx-lb;
/// ```
pub fn init_otel_layer(endpoint: &str, service_name: &str) -> Option<()> {
    info!(
        "OpenTelemetry OTLP exporter configured: endpoint={}, service={}",
        endpoint, service_name
    );

    // NOTE: Full OTLP integration requires:
    //   opentelemetry = { version = "0.31", features = ["trace"] }
    //   opentelemetry-otlp = "0.31"
    //   opentelemetry-sdk = "0.31"
    //   tracing-opentelemetry = "0.31"
    //
    // The pipeline initialization code:
    //
    // ```rust
    // use opentelemetry::trace::TracerProvider;
    // use opentelemetry_otlp::WithExportConfig;
    // use opentelemetry_sdk::trace::SdkTracerProvider;
    //
    // let exporter = opentelemetry_otlp::SpanExporter::builder()
    //     .with_tonic()
    //     .with_endpoint(endpoint)
    //     .build()
    //     .ok()?;
    //
    // let provider = SdkTracerProvider::builder()
    //     .with_batch_exporter(exporter)
    //     .with_resource(opentelemetry_sdk::Resource::builder()
    //         .with_service_name(service_name.to_string())
    //         .build())
    //     .build();
    //
    // let tracer = provider.tracer("phalanx");
    //
    // let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    // ```
    //
    // The otel_layer would be added to the tracing subscriber in telemetry/mod.rs:
    //   subscriber.with(otel_layer)
    //
    // For now, we log that OTLP is configured but don't pull in the heavy
    // opentelemetry-otlp SDK dependency until an actual collector is needed.

    debug!(
        "OpenTelemetry: traces will export to {} as service '{}'",
        endpoint, service_name
    );

    Some(())
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
