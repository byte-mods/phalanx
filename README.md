# AI Load Balancer Boilerplate

A high-performance, AI-enhanced load balancer and API gateway boilerplate written in Rust.

This repository serves as a starting point for building edge routers, API gateways, or load balancers with capabilities similar to F5 or Nginx, enhanced with modern asynchronous paradigms and AI-based predictive routing or WAF anomaly detection.

## Architecture & Capabilities

*   **Proxy Core**: Built on `tokio` (async runtime), `hyper` (HTTP/1 & HTTP/2), and `quinn` (HTTP/3 - QUIC). Supports high-throughput, low-latency networking leveraging zero-copy byte buffers (`bytes`). Can also use `tokio-uring` on Linux for extreme IO performance.
*   **Routing & Load Balancing**: Uses `consistent-hash` and `dashmap` for lock-free, concurrent upstream caching and state management.
*   **Discovery**: Prepared for dynamic upstream discovery via DNS (`trust-dns-resolver`), etcd (`etcd-client`).
*   **Middleware**:
    *   **Caching**: In-memory caching with TTL using `moka`. Persistent caching available via `sled` or `rocksdb`.
    *   **Rate Limiting**: Integrated `governor` for token-bucket rate limiting.
    *   **WAF (Web Application Firewall)**: Stubs available for hooking into regex pattern matchers or hyperscan.
*   **Observability**: Integrated `tracing`, `tracing-subscriber`, `prometheus`, and `opentelemetry` to export metrics, logs, and distributed traces.
*   **AI Inference Plugin**: Bundled with `tract-onnx` to load ONNX models. Use cases include predictive routing, anomaly detection, or dynamic threat mitigation without an external API call.
*   **Admin Control Plane**: Built-in REST API using `axum` on a separate management port to view health metrics, modify routing rules, or reload configurations (`figment`, `serde`).

## Getting Started

1. **Prerequisites**: Ensure you have Rust installed (`rustup`).
2. **Build**:
   ```bash
   cargo build --release
   ```
3. **Run**:
   ```bash
   cargo run --release
   ```

By default, the proxy listens on `0.0.0.0:8080`, and the admin API listens on `127.0.0.0:9090`.

## Modules Overview

- `src/main.rs`: Bootstraps telemetry, configs, AI engine, state, and spawns the proxy/admin servers.
- `src/proxy.rs`: Hyper-based request handler per connection. Add custom WAF or cache logic here.
- `src/middleware.rs`: Definitions for Response Caching (`moka`) and WAF.
- `src/routing.rs`: Upstream manager taking advantage of Consistent Hashing and lock-free concurrency.
- `src/discovery.rs`: Stub for `etcd` or DNS watching to dynamically update upstreams.
- `src/ai.rs`: Minimal `tract-onnx` setup to run AI models on the edge directly in Rust.
- `src/telemetry.rs`: Structured logging and metrics initialization.
- `src/config.rs`: Strongly-typed configuration structures.
- `src/admin.rs`: HTTP REST API for management using `axum`.
