# Phalanx

## Tech Stack
- **Core:** Rust 2024, Tokio async runtime, Hyper HTTP/1+2, Quinn + h3 (HTTP/3 / QUIC)
- **TLS:** rustls, rustls-acme (Let's Encrypt)
- **Concurrency:** arc-swap, dashmap, parking_lot, atomics (lock-free hot path)
- **Cache:** Moka L1 (in-memory LFU) + optional disk L2; FxHash for cache keys
- **Rate Limiting:** governor (token bucket) + Redis (cluster sliding-window)
- **WAF:** regex (OWASP signatures), ML fraud via tract-onnx, declarative policy engine
- **Auth:** Basic / JWT (jsonwebtoken) / OAuth introspection / JWKS / OIDC / auth_request
- **Scripting:** Rhai (sandboxed), Proxy-Wasm via wasmtime
- **Cluster:** etcd-client, redis, SWIM gossip
- **Admin:** Actix-web (REST API + dashboard)
- **Observability:** Prometheus, OpenTelemetry OTLP, structured access logs (with W3C trace context)
- **Build:** `cargo build` · **Test:** `cargo test` (955+ tests) · **Run:** `cargo run -- phalanx.conf`
