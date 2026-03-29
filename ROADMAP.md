# Phalanx Load Balancer: Development Roadmap

This document outlines the proposed next-generation features for the Phalanx load balancer to achieve parity with the world's most advanced edge proxies (like Envoy, Caddy, Cloudflare, and Traefik).

---

## Phase 1: Edge Essentials & Resiliency

### 1. Active Health Checking & Circuit Breaking
**Goal:** Prevent cascading failures by actively monitoring upstream health rather than relying solely on passive (request-based) failures.
*   **Implementation:** 
    *   Add a background `tokio` task in `src/routing/` that periodically sends `GET /health` or TCP pings to all active backends.
    *   Implement an **Exponential Backoff Circuit Breaker** algorithm. If a backend fails `X%` of requests within `Y` seconds, trip the circuit to `OPEN`, immediately returning `503 Service Unavailable` for that specific node to allow it to recover, while redirecting traffic to healthy nodes.
*   **Dependencies:** Standard HTTP client logic within the existing proxy core.

### 2. Dynamic HTTP Compression (Brotli & Zstd)
**Goal:** Drastically reduce bandwidth costs and improve client load times.
*   **Implementation:** 
    *   Create a dedicated compression middleware layer operating post-cache.
    *   Inspect incoming `Accept-Encoding: br, zstd, gzip` headers.
    *   Buffer and compress the upstream HTTP response bodies using `async-compression`.
*   **Dependencies:** `async-compression` crate (supporting `tokio`).

---

## Phase 2: Distributed Scale & Automation

### 3. Fully Automatic TLS (Auto-SSL via Let's Encrypt)
**Goal:** Zero-friction HTTPS for downstream clients. Users only need to configure the domain name, and Phalanx handles the rest.
*   **Implementation:**
    *   Integrate ACME protocol (Let's Encrypt) directly into the `tls_acceptor`.
    *   Upon receiving a TLS ClientHello (SNI) for a configured domain, intercept the challenge (HTTP-01 or ALPN-01) and automatically provision the certificate.
    *   Store certificates persistently in the existing `RocksDB` instance to prevent rate-limiting across restarts.
*   **Dependencies:** `rustls-acme` or `acme2`.

### 4. Distributed State Clustering (Redis/Gossip)
**Goal:** Share state across a fleet of horizontally scaled Phalanx nodes.
*   **Implementation:**
    *   Enhance `src/middleware/ratelimit.rs` and `src/waf/reputation.rs` to support a Redis backend.
    *   When an IP hits a rate limit or gets banned by the Machine Learning engine on **Node A**, sync that penalty to **Node B** and **Node C** within milliseconds.
    *   This also applies to the Keyval store, making the TTL data global instead of local.
*   **Dependencies:** `redis` or `fred` crate for async Redis Pub/Sub, or `aquatic` for Gossip.

---

## Phase 3: Ultimate Enterprise Architecture

### 5. Proxy-Wasm Extensibility
**Goal:** Replace or augment the `Rhai` script engine with the industry-standard WebAssembly (Wasm) Application Binary Interface (ABI), enabling near-native plugin speeds.
*   **Implementation:**
    *   Integrate a WebAssembly Engine like `wasmtime`.
    *   Implement the `proxy-wasm` ABI specifications for routing, header manipulation, and body inspection.
    *   This allows platform engineers to write custom plugins in Go, Rust, or C++ and hot-load them seamlessly.
*   **Dependencies:** `wasmtime`, `proxy-wasm`.

### 6. Kubernetes Ingress / Gateway API Controller
**Goal:** Make deployment zero-touch in containerized environments.
*   **Implementation:**
    *   Build a standalone loop relying on the `kube` crate to watch Kubernetes API events.
    *   When a user applies a generic `Ingress` or new `Gateway` resource, Phalanx automatically translates the manifest into its internal `RouteConfig` and `UpstreamPoolConfig`, auto-updating without requiring a config reload or sidecar restarting.
*   **Dependencies:** `kube`.

### 7. Global Anycast / Global Server Load Balancing (GSLB)
**Goal:** Expand load balancing scope from local networks to global data centers.
*   **Implementation:**
    *   Build out `src/geo/mod.rs` to intersect with health-checks. Route clients not just to a healthy upstream, but logically direct them to the geographic datacenter with the lowest latency payload.
    *   Implement fallback peering tunnels directly into Phalanx to bridge disconnected data centers internally.
