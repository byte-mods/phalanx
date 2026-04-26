# Phalanx

```
Copyright 2024 Phalanx Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

**Phalanx** is a high-performance, enterprise-grade reverse proxy and API gateway written in Rust. It is inspired by NGINX's configuration syntax but built from scratch with modern capabilities: AI-driven traffic routing, a built-in WAF with ONNX-based fraud detection, automatic TLS, WebRTC SFU with per-room bandwidth counters, HTTP/3, distributed cluster state, per-protocol bandwidth monitoring, configurable resource alerts, and deep observability.

---

## Table of Contents

1. [What Is Built](#what-is-built)
2. [What Is Left (Roadmap)](#what-is-left-roadmap)
3. [Prerequisites](#prerequisites)
4. [Building & Running](#building--running)
5. [Configuration Primer](#configuration-primer)
6. [Feature Tutorials](#feature-tutorials)
   - [1. Load Balancing Algorithms](#1-load-balancing-algorithms)
   - [2. AI-Predictive Routing](#2-ai-predictive-routing)
   - [3. TLS / mTLS](#3-tls--mtls)
   - [4. Automatic TLS via Let's Encrypt (Auto-SSL)](#4-automatic-tls-via-lets-encrypt-auto-ssl)
   - [5. HTTP/3 (QUIC)](#5-http3-quic)
   - [6. Rate Limiting & DDoS Protection](#6-rate-limiting--ddos-protection)
   - [7. Web Application Firewall (WAF)](#7-web-application-firewall-waf)
   - [8. ML-Based Fraud Detection (ONNX)](#8-ml-based-fraud-detection-onnx)
   - [9. Authentication & Authorization](#9-authentication--authorization)
   - [10. Response Caching](#10-response-caching)
   - [11. Compression (Gzip & Brotli)](#11-compression-gzip--brotli)
   - [12. URL Rewriting](#12-url-rewriting)
   - [13. Static File Serving](#13-static-file-serving)
   - [14. FastCGI & uWSGI Proxying](#14-fastcgi--uwsgi-proxying)
   - [15. WebSocket Proxying](#15-websocket-proxying)
   - [16. gRPC & gRPC-Web Gateway](#16-grpc--grpc-web-gateway)
   - [17. TCP & UDP Proxying](#17-tcp--udp-proxying)
   - [18. Mail Proxy (SMTP / IMAP / POP3)](#18-mail-proxy-smtp--imap--pop3)
   - [19. WebRTC SFU](#19-webrtc-sfu)
   - [20. Traffic Mirroring & Splitting](#20-traffic-mirroring--splitting)
   - [21. Session Affinity (Sticky Sessions)](#21-session-affinity-sticky-sessions)
   - [22. GeoIP Routing](#22-geoip-routing)
   - [23. Real Client IP Extraction](#23-real-client-ip-extraction)
   - [24. Connection Limiting (Zone-Based)](#24-connection-limiting-zone-based)
   - [25. OCSP Stapling](#25-ocsp-stapling)
   - [26. Scripting & Hooks (Rhai)](#26-scripting--hooks-rhai)
   - [27. Key-Value Store](#27-key-value-store)
   - [28. Service Discovery](#28-service-discovery)
   - [29. Cluster State Sharing](#29-cluster-state-sharing)
   - [30. Observability (Prometheus, OTLP, Access Logs)](#30-observability-prometheus-otlp-access-logs)
   - [31. Admin API & Dashboard](#31-admin-api--dashboard)
   - [32. Hot Config Reload](#32-hot-config-reload)
   - [33. Active-Active Load Balancer Cluster (High Availability)](#33-active-active-load-balancer-cluster-high-availability)
   - [34. WebRTC SFU Advanced & WebRTC-to-HLS Live Streaming](#34-webrtc-sfu-advanced--webrtc-to-hls-live-streaming)
   - [35. Per-Protocol Bandwidth Monitoring](#35-per-protocol-bandwidth-monitoring)
   - [36. Resource Alert System](#36-resource-alert-system)
   - [37. Circuit Breaker with Exponential Backoff](#37-circuit-breaker-with-exponential-backoff)
   - [38. Slow-Start Ramp for Recovering Backends](#38-slow-start-ramp-for-recovering-backends)
   - [39. Active Health Checks](#39-active-health-checks)
   - [40. Zero-Copy File Proxying (Linux sendfile / splice)](#40-zero-copy-file-proxying-linux-sendfile--splice)
   - [41. Keyval / WAF Dynamic Ban Integration](#41-keyval--waf-dynamic-ban-integration)
   - [42. CAPTCHA Bot Challenge](#42-captcha-bot-challenge)
   - [43. Gossip-Based Cluster State](#43-gossip-based-cluster-state)
   - [44. Proxy-Wasm Plugin Extensibility](#44-proxy-wasm-plugin-extensibility)
   - [45. Kubernetes Ingress Controller](#45-kubernetes-ingress-controller)
   - [46. Global Anycast / GSLB](#46-global-anycast--gslb)
7. [Testing Guide](#testing-guide)
   - [Rust Tests](#rust-tests)
   - [Start Test Backends](#start-test-backends)
   - [Python Smoke Test](#python-smoke-test)
   - [Python API Test Suite](#python-api-test-suite)
   - [Load Testing](#load-testing)
   - [Browser Test Pages](#browser-test-pages)
   - [Bandwidth Monitor](#bandwidth-monitor)
   - [Master Orchestrator](#master-orchestrator)
8. [Full Configuration Reference](#full-configuration-reference)
9. [Admin API Reference](#admin-api-reference)
10. [License](#license)

---

## What Is Built

Every item below is fully implemented, compiles, and is covered by tests. **748 tests total (524 unit + 224 integration) — all passing.**

> **2026-03-30 update:** All Phase 1, Phase 2, and Phase 3 features are now complete. New additions: CAPTCHA bot challenge integration (hCaptcha/Turnstile/reCAPTCHA), SWIM-style gossip protocol for peer-to-peer cluster state, Proxy-Wasm plugin extensibility framework, Kubernetes Ingress & Gateway API controller, and Global Anycast / GSLB with geographic, latency-based, and weighted routing policies.

| Category | Features |
|---|---|
| **Protocols** | HTTP/1.1, HTTP/2, HTTP/3 (QUIC) with AI routing + caching, WebSocket, gRPC, gRPC-Web, FastCGI, uWSGI, TCP, UDP, SMTP/IMAP/POP3, WebRTC SFU |
| **Load Balancing** | Round Robin, Least Connections, IP Hash, Random, Weighted, Consistent Hash, Least Time, AI Predictive (4 algorithms) |
| **TLS** | Static certificates, mTLS, ALPN, Auto-SSL via Let's Encrypt, OCSP stapling (background refresh loop wired), hot reload |
| **WAF** | Signature rules (OWASP), IP reputation, tiered bot classification (good/bad/unknown + rate anomaly scoring), CAPTCHA challenges (hCaptcha/Turnstile/reCAPTCHA), ONNX ML fraud detection, declarative policy engine (NGINX App Protect-style) |
| **Auth** | Basic (bcrypt + plaintext), JWT (HS/RS/ES), OAuth 2.0 introspection, auth_request subrequest, OIDC RP, JWKS |
| **Caching** | L1 in-memory (Moka), L2 disk tier, stale-while-revalidate, Vary support |
| **Compression** | Gzip, Brotli (both fully wired; Brotli preferred over Gzip when client sends `Accept-Encoding: br`) |
| **Rate Limiting** | Per-IP token bucket, global DDoS panic mode, zone-based connection limits, top-N IP leaderboard |
| **Routing** | Prefix routing, URL rewrite engine, static files, real client IP extraction (XFF / X-Real-IP / PROXY protocol v1/v2) |
| **Traffic Shaping** | Traffic mirroring/tee (fully wired), consistent-hash splitting, sticky sessions |
| **Resilience** | Circuit breaker (3-state, exponential backoff), slow-start ramp (linear weight recovery), active + passive health checks, backend request queue |
| **Performance** | Zero-copy TCP proxy via Linux `splice(2)`; fallback `copy_bidirectional` on non-Linux; L2 disk cache with stale-while-revalidate |
| **Dynamic Security** | Keyval-backed runtime IP bans (TTL-based); WAF auto-ban feeds back into keyval; external systems can update ban list without restart |
| **Observability** | Prometheus metrics, OpenTelemetry OTLP traces with W3C `traceparent` injection, structured access logs, admin dashboard |
| **Bandwidth Monitoring** | Per-protocol atomic counters (bytes_in, bytes_out, requests, active_connections) for HTTP1/2/3, WebSocket, gRPC, TCP, UDP, WebRTC; sorted utilization snapshots; configurable per-protocol thresholds |
| **Resource Alerts** | Warning/Critical threshold engine for bandwidth and connections per protocol; process memory + open FD monitoring (Linux); rolling 500-entry alert log; optional webhook delivery; background polling every 30 s |
| **WebRTC SFU** | VP8/H.264/Opus codecs, room management, trickle ICE, per-room bytes/packets forwarded, publisher vs subscriber counts, live bandwidth dashboard tab |
| **Cluster** | Redis pub/sub (bans/keyval sync) + full Redis KV put/get/delete with TTL, etcd KV (fully functional), SWIM gossip protocol (peer-to-peer, no external deps), shared sticky sessions, WAF ban synchronization |
| **GeoIP** | CSV-based country lookup; allow/deny by country code; injects `X-Geo-Country-Code` header (fully wired) |
| **Discovery** | DNS SRV records, RocksDB registry, etcd watch |
| **Scripting** | Rhai embedded script engine, compile-time hook plugins — PreRoute/PreUpstream/Log phases fully wired into proxy pipeline |
| **Extensibility** | Proxy-Wasm plugin framework (trait-based ABI), built-in plugins (header injection, rate limit, path blocker), priority-ordered plugin chain |
| **Kubernetes** | Ingress v1 controller, Gateway API HTTPRoute reconciliation, annotation-driven config (CORS, rewrite, WAF, rate-limit), TLS secret mapping |
| **GSLB** | Geographic routing, latency-based routing, weighted round-robin, geo+latency failover; 7-region proximity model; health-check integration |
| **Admin** | REST API, RBAC (Admin/Operator/ReadOnly), dynamic routes & SSL certs, ML model upload, bandwidth stats, resource alerts, WebRTC room stats |

All Phase 1, Phase 2, and Phase 3 features are now complete.

---

## What Is Left (Roadmap)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

The following items remain before Phalanx reaches full enterprise parity:

### Phase 1 — Wiring & Integration

The following modules are **fully implemented** but not yet integrated into the request pipeline. Each section includes instructions on how to wire them.

| Item | Status | How to Wire |
|---|---|---|
| **GeoIP** | ✅ **Wired** | `GeoIpDatabase` loaded in `main.rs`; `lookup()` called in `handle_http_request`; injects `X-Geo-Country-Code` header; blocked clients receive 403 |
| **RealIP Extraction** | ✅ **Wired** | `realip::resolve_client_ip()` called at start of `handle_http_request`; `inject_forwarding_headers()` injects `X-Forwarded-For` / `X-Real-IP` to upstreams |
| **Brotli Compression** | ✅ **Wired** | `brotli_compress()` called after response body is buffered; preferred over gzip when client sends `Accept-Encoding: br`; 1 KB minimum size |
| **Traffic Mirroring** | ✅ **Wired** | `mirror::mirror_request()` called as fire-and-forget after upstream response; triggered by `mirror <pool_name>` in route or `mirror_pool` globally |
| **UDP Proxy** | ✅ **Wired** | `proxy::udp::start_udp_proxy()` spawned in `main.rs` when `udp_bind` / `listen_udp` is set |
| **HookEngine / Rhai Scripting** | ✅ **Wired** | `PreRoute`, `PreUpstream`, and `Log` phases called in `handle_http_request`; supports `Respond` (short-circuit), `RewritePath`, `SetHeaders` results |
| **Mail Proxy (SMTP/IMAP/POP3)** | ✅ **Wired** | Spawned from `main.rs` when `smtp_bind`, `imap_bind`, or `pop3_bind` is set; upstream pool set via `mail_upstream_pool` (defaults to `default`) |
| **WAF Policy Engine** | ✅ **Wired** | `PolicyEngine` added as field on `WafEngine`; `evaluate()` called in `inspect()` after rule/reputation checks; load policy with `waf_policy_path` config key |
| **ML Fraud Model Auto-load** | ✅ **Wired** | Set `ml_fraud_model_path /path/to/model.onnx;` and optionally `ml_fraud_mode active;` in server block; engine starts at boot |
| **Cache Purge API** | ✅ **Wired** | `POST /api/cache/purge` on admin server; passes `{"key":"…"}`, `{"prefix":"…"}`, or `{}` (purge all); backed by `ResponseCache` reference in `AdminState` |
| **Redis Cluster State** | ✅ **Complete** | Full Redis `SET`/`GET`/`DEL` with TTL wired in `src/cluster/mod.rs`; pub/sub uses `get_async_pubsub()`, KV uses `get_multiplexed_async_connection()` |
| **OCSP Stapling** | ✅ **Wired** | `OcspStapler` instantiated in `main.rs` when `tls_cert_path` is set; background refresh loop runs every hour; optional override via `ocsp_responder_url` |
| **ZoneLimiter (Connection Limiting)** | ✅ **Wired** | `ZoneLimiter` instantiated in `main.rs`; `acquire_connection()` called at request start with RAII `ConnectionGuard` for auto-release |
| **Sticky Sessions** | ✅ **Wired** | `StickySessionManager` (Cookie mode `PHALANXID`) instantiated in `main.rs`; cookie lookup on request, `Set-Cookie` header set on response; Learn mode records session→backend from response header |
| **gRPC-Web** | ✅ **Wired** | `is_grpc_web()` detects browser requests; `translate_request()` rewrites content-type + adds `TE: trailers`; `translate_response()` rewrites back + adds CORS headers; OPTIONS preflight returns 204 |
| **Cluster State Sharing** | ✅ **Wired** | `ClusterState` instantiated in `main.rs`; backend selected from `etcd_endpoints` > `redis_url` > Standalone; `node_id` defaults to `$HOSTNAME` |
| **AdvancedCache (disk tier)** | ✅ **Wired** | `AdvancedCache` initialized in `main.rs` with `cache_disk_path` config; L1 Moka + L2 disk with stale-while-revalidate |
| **OIDC Auth** | ✅ **Wired** | `OidcSessionStore` passed to `handle_http_request`; session cookie validation runs for routes with `auth_oidc_issuer` + `auth_oidc_cookie_name` |
| **JWKS Manager** | ✅ **Wired** | `JwksManager` used in JWT validation path for routes with `auth_jwks_uri`; RS256/ES256 public keys fetched and cached from JWKS endpoint |
| **HTTP/3 AI/Cache** | ✅ **Wired** | AI engine passed to `get_next_backend(None, Some(ai_engine))`; `update_score()` called with latency after each request; GET 200 responses stored in cache; cache hit returns early with `X-Cache: HIT` |
| **HTTP/3 Access Log + Bandwidth** | ✅ **Wired** | `AccessLogger.log()` called after response with full `AccessLogEntry` (timestamp, client IP, method, path, status, latency, backend, pool, bytes sent, referer, UA); `BandwidthTracker.protocol("http3")` and `.pool(name)` increment requests, in-bytes, and out-bytes |
| **HTTP/3 Shared Upstream Client** | ✅ **Wired** | Forwarder uses one process-wide `OnceLock<reqwest::Client>` instead of building per request; DNS resolver, TLS context, and HTTP/1 keepalive pool are constructed once. Mirror request body is only cloned when a `mirror_pool` is configured |

### Phase 2 — Distributed Scale

| Item | Status | Notes |
|---|---|---|
| **Gossip-Based State** | ✅ **Complete** | SWIM-style gossip protocol in `src/cluster/gossip.rs`; UDP-based peer-to-peer state sync; LWW merge; membership management |
| **Bot Detection (CAPTCHA)** | ✅ **Complete** | `CaptchaManager` in `src/waf/bot.rs`; supports hCaptcha, Cloudflare Turnstile, reCAPTCHA v2; rate-based challenge trigger; async token verification |

### Phase 3 — Ultimate Enterprise

| Item | Status | Notes |
|---|---|---|
| **Proxy-Wasm Extensibility** | ✅ **Complete** | `WasmPluginManager` in `src/wasm/mod.rs`; trait-based plugin ABI; 5 lifecycle phases; priority chain; built-in header injection, rate limit, path blocker plugins |
| **Kubernetes Ingress Controller** | ✅ **Complete** | `IngressController` in `src/k8s/mod.rs`; Ingress v1 + Gateway API HTTPRoute reconciliation; annotation-driven config; TLS secret mapping |
| **Global Anycast / GSLB** | ✅ **Complete** | `GslbRouter` in `src/gslb/mod.rs`; Geographic, Latency, Weighted RR, and Geo+Latency failover policies; 60+ country mappings; health-check integration |

> **Note:** Active Health Checking, Circuit Breaker, and Distributed Rate Limiting via Redis Lua ZSET are **fully implemented** in `src/routing/mod.rs` and `src/middleware/ratelimit.rs` respectively.

---

## Prerequisites

- **Rust** 1.85+ (edition 2024): `curl https://sh.rustup.rs -sSf | sh`
- **RocksDB system libs**: `brew install rocksdb` (macOS) or `apt install librocksdb-dev` (Debian/Ubuntu)
- **Protobuf compiler** (for OTLP/tonic): `brew install protobuf` or `apt install protobuf-compiler`
- Optional: **Redis** for distributed state, **etcd** for service discovery

---

## Building & Running

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

```bash
# Clone
git clone https://github.com/your-org/phalanx.git
cd phalanx

# Release build (recommended for production)
cargo build --release

# Debug build
cargo build

# Run tests (908 total: 682 unit + 226 integration — all passing)
cargo test

# Run with default config
./target/release/ai_load_balancer
```

The binary reads `phalanx.conf` from the current directory by default.

---

## Configuration Primer

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

Phalanx uses an NGINX-inspired configuration file (`phalanx.conf`). The structure is:

```nginx
# Global directives
worker_threads 4;
admin_listen   127.0.0.1:9090;

http {
    # Define backend pools
    upstream <pool_name> {
        server <ip>:<port> [weight=N] [backup] [max_conns=N];
        algorithm <algorithm>;
        health_check /health;
        keepalive 32;
    }

    server {
        listen <port>;

        # TLS, rate limiting, WAF, AI routing, observability directives here

        route /path {
            upstream <pool_name>;
            # Per-route directives: auth, cache, compression, rewrite, headers
        }
    }
}
```

A minimal working configuration is included in [`phalanx.conf`](./phalanx.conf).

---

## Feature Tutorials

---

### 1. Load Balancing Algorithms

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Distributes incoming requests across a pool of upstream backends.

**Algorithms available:**

| Directive value | Algorithm |
|---|---|
| `roundrobin` | Sequential rotation (default) |
| `least_connections` | Backend with fewest active requests |
| `ip_hash` | Client IP hash — same client → same backend |
| `random` | Uniformly random healthy backend |
| `weighted_roundrobin` | Proportional by `weight=N` |
| `consistent_hash` | Ketama-style ring — minimizes reshuffling on topology changes |
| `least_time` | Fewest connections with weight tiebreak |
| `ai` | AI-predictive (see tutorial #2) |

**How to configure:**

```nginx
upstream web_pool {
    server 10.0.0.1:8080 weight=3;
    server 10.0.0.2:8080 weight=1;
    server 10.0.0.3:8080 backup;        # used only when all primary nodes are down
    algorithm weighted_roundrobin;

    health_check        /healthz;        # endpoint to poll
    health_check_status 200;             # expected HTTP status
    max_fails           3;               # failures before marking down
    fail_timeout        30s;             # how long to keep backend marked down
    slow_start          10s;             # ramp-up window for recovering nodes
    keepalive           32;              # max idle keep-alive connections
}

http {
    server {
        listen 8080;
        route / {
            upstream web_pool;
        }
    }
}
```

**Testing:**
```bash
# Watch which backend responds
for i in $(seq 1 6); do curl -s http://localhost:8080/; done
```

---

### 2. AI-Predictive Routing

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Uses multi-armed bandit algorithms to learn which backend performs best and route more traffic to it, while still exploring occasionally.

**Four sub-algorithms:**

| Value | Algorithm | Behavior |
|---|---|---|
| `epsilon_greedy` | Epsilon-Greedy | Exploit best backend 90% of the time, explore randomly 10% |
| `ucb1` | Upper Confidence Bound | Adds an exploration bonus to less-tried backends |
| `softmax` | Boltzmann / Softmax | Probabilistic selection proportional to latency performance, tuned by temperature |
| `thompson_sampling` | Thompson Sampling | Bayesian Beta(α,β) model per backend; low-latency nodes get higher probability mass |

**How to configure:**

```nginx
upstream api_pool {
    server 10.0.0.1:8080;
    server 10.0.0.2:8080;
    algorithm ai;
}

server {
    listen 8080;

    # --- AI Routing Parameters ---
    ai_algorithm             epsilon_greedy;
    ai_epsilon               0.10;          # 10% exploration rate (epsilon_greedy)
    ai_temperature           1.0;           # higher = more uniform (softmax)
    ai_ucb_constant          1.414;         # exploration bonus multiplier (ucb1)
    ai_thompson_threshold_ms 200.0;         # latency threshold for success/failure (thompson_sampling)

    route /api {
        upstream api_pool;
    }
}
```

**How it adapts:** Each backend maintains a running latency average. After each request the AI engine updates its model. Slow or failing backends are deprioritized within seconds.

---

### 3. TLS / mTLS

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Terminates HTTPS connections using rustls. Optionally enforces mutual TLS (client certificates).

**How to configure — one-way TLS:**

```nginx
server {
    listen 443;
    ssl_certificate     /etc/phalanx/certs/server.pem;
    ssl_certificate_key /etc/phalanx/certs/server.key;

    route / {
        upstream backend_pool;
    }
}
```

**How to configure — mutual TLS (client cert required):**

```nginx
server {
    listen 443;
    ssl_certificate     /etc/phalanx/certs/server.pem;
    ssl_certificate_key /etc/phalanx/certs/server.key;
    tls_ca_cert_path    /etc/phalanx/certs/ca.pem;   # CA that signed client certs

    route /internal {
        upstream internal_pool;
    }
}
```

**Generating a self-signed certificate for testing:**
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.pem \
    -days 365 -nodes -subj '/CN=localhost'
```

**ALPN:** Phalanx automatically advertises `h2` and `http/1.1` in the ALPN extension, enabling HTTP/2 upgrade for browsers and clients that support it.

---

### 4. Automatic TLS via Let's Encrypt (Auto-SSL)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Automatically provisions and renews a TLS certificate from Let's Encrypt using the ACME protocol. No manual certificate management required.

**Requirements:**
- Port 443 must be publicly reachable from the internet
- The domain must resolve to this server's IP

**How to configure:**

```nginx
server {
    listen 443;
    auto_ssl_domain    example.com;
    auto_ssl_email     admin@example.com;
    auto_ssl_cache_dir /var/cache/phalanx/acme;   # persists certs across restarts

    route / {
        upstream backend_pool;
    }
}
```

**How it works internally:** On startup, `rustls-acme` launches a background ACME worker. The first TLS ClientHello for the domain triggers an ALPN-01 challenge. The certificate is stored in `auto_ssl_cache_dir` and reused on restart to avoid Let's Encrypt rate limits.

---

### 5. HTTP/3 (QUIC)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Serves HTTP/3 over QUIC (UDP) on a separate port using `quinn` and `h3`.

**How to configure:**

```nginx
server {
    listen     443;                      # TCP for HTTP/1+2
    listen_quic 0.0.0.0:8443;           # UDP for HTTP/3

    ssl_certificate     /etc/phalanx/certs/server.pem;
    ssl_certificate_key /etc/phalanx/certs/server.key;

    route / {
        upstream backend_pool;
    }
}
```

**Testing:**
```bash
# Using curl with HTTP/3 support (requires curl built with quiche/ngtcp2)
curl --http3 https://example.com:8443/
```

**Notes:** HTTP/3 runs entirely in parallel with the TCP listeners. Both protocols share the same upstream pool configuration.

**Pipeline parity with HTTP/1:** The H3 path runs through rate limiting, zone connection limits, CAPTCHA, WAF (URL + body), GeoIP, response cache, route matching, sticky sessions, AI-driven backend selection, traffic mirroring, PreRoute / PreUpstream / PostUpstream / Log hooks, Wasm `OnRequestHeaders`, plus per-protocol and per-pool bandwidth tracking and structured access logs. Auth (Basic/JWT/OAuth/JWKS/OIDC), URL rewriting, gzip/brotli compression, and W3C trace context propagation are HTTP/1+2 only today and tracked as parity gaps.

**Performance:** The HTTP/3 forwarder reuses a single process-wide `reqwest::Client` (DNS resolver, TLS context, and HTTP/1 connection pool are built once), and only allocates the request mirror copy when a `mirror_pool` is configured.

---

### 6. Rate Limiting & DDoS Protection

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Enforces per-IP request rate limits and a global rate ceiling using token-bucket algorithms.

**How to configure:**

```nginx
server {
    listen 8080;

    # Per-IP: max 50 requests/sec with a burst allowance of 100
    rate_limit_per_ip  50;
    rate_limit_burst   100;

    # Global DDoS panic mode: if total RPS exceeds 5000, all new clients are rejected
    global_rate_limit  5000;

    # Optional: sync bans across cluster nodes via Redis
    redis_url redis://127.0.0.1:6379;
}
```

**Behavior:**
- Clients exceeding the per-IP limit receive `429 Too Many Requests`
- When `global_rate_limit` is exceeded, all new connections receive `503 Service Unavailable`
- With `redis_url` configured, global counters are maintained in Redis ZSET so all cluster nodes enforce the same ceiling

**Testing:**
```bash
# Flood test (requires hey)
hey -n 10000 -c 200 http://localhost:8080/
```

---

### 7. Web Application Firewall (WAF)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Inspects every request for attack patterns (SQLi, XSS, SSRF, XXE, path traversal, etc.), detects bots, and auto-bans repeat offenders.

**Components:**
1. **Signature Rules** — regex patterns against URL, query string, headers, body
2. **Bot Detection** — User-Agent analysis for known malicious crawlers and empty UA
3. **IP Reputation** — strike-based system; exceeding threshold → automatic temporary ban
4. **Policy Engine** — NGINX App Protect-style declarative WAF policies loaded from JSON (see `src/waf/policy.rs`)

**How to configure:**

```nginx
server {
    listen 8080;

    waf_enabled             true;
    waf_auto_ban_threshold  15;     # strikes before IP is banned
    waf_auto_ban_duration   3600;   # ban duration in seconds (1 hour)
    waf_policy_path         /etc/phalanx/waf-policy.json;   # optional declarative policy
}
```

**Declarative Policy (JSON — NGINX App Protect-style):**

```json
{
    "name": "strict-api-policy",
    "enforcement_mode": "Blocking",
    "blocking_status": 403,
    "exclusions": ["^/health$", "^/metrics$"],
    "signature_sets": [],
    "custom_rules": [
        {
            "id": 1001,
            "description": "Block curl user-agent",
            "pattern": "^curl/",
            "target": "Headers",
            "action": "Block"
        },
        {
            "id": 1002,
            "description": "Block admin path scan",
            "pattern": "^/admin",
            "target": "Url",
            "action": "Block"
        }
    ]
}
```

`RuleTarget` options: `Url`, `QueryString`, `Headers`, `Body`, `All`. `RuleAction` options: `Block`, `Log`, `Allow`. The first policy loaded becomes the default. Exclusion patterns are regexes matched against the request path.

**How the strike system works:**
- Each WAF rule match adds 1–10 strike points to the client IP
- When strikes ≥ `waf_auto_ban_threshold`, the IP is added to the ban list
- After `waf_auto_ban_duration` seconds, the ban expires automatically
- With Redis configured, bans are broadcast to all cluster nodes within milliseconds

**Covered OWASP rules include:**
- SQL injection patterns (`' OR 1=1`, `UNION SELECT`, etc.)
- XSS vectors (`<script>`, `javascript:`, event handlers)
- Path traversal (`../`, `..%2F`)
- SSRF indicators (internal IP ranges in URLs)
- XXE payloads (`<!ENTITY`, `SYSTEM "file://`)
- Prototype pollution (`__proto__`, `constructor.prototype`)

> **Note:** `src/waf/bot.rs` implements a tiered `BotDetector` with `BotClass` enum (`GoodBot`, `BadBot`, `Unknown`, `Human`), rate-anomaly scoring, and a CAPTCHA challenge stub. Known-bad scanner signatures (sqlmap, nikto, masscan, etc.) are blocked immediately; known-good crawlers (Googlebot, Bingbot) are classified separately. The CAPTCHA integration point exists but requires wiring to an external provider (hCaptcha, Cloudflare Turnstile).

---

### 8. ML-Based Fraud Detection (ONNX)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Runs a user-supplied ONNX model against each request to predict whether it is fraudulent. Operates in **shadow** (log-only) or **active** (auto-ban) mode.

**Feature vector extracted per request:**

| Feature | Description |
|---|---|
| Path length | Number of characters in the URL path |
| HTTP method | Encoded as integer (GET=0, POST=1, etc.) |
| Query string length | Characters in query parameters |
| Header count | Number of HTTP headers |
| User-Agent length | Characters in UA string |
| Body length | Bytes in request body |

**Admin API:**

```bash
# 1. Upload your ONNX model (binary file)
curl -X POST http://localhost:9090/api/ml/upload \
    -H "Authorization: Bearer <admin-token>" \
    --data-binary @fraud_model.onnx

# 2. Switch to active mode (default: shadow)
curl -X PUT http://localhost:9090/api/ml/mode \
    -H "Authorization: Bearer <admin-token>" \
    -H "Content-Type: application/json" \
    -d '{"mode": "active"}'

# 3. View inference logs (last 100 predictions)
curl http://localhost:9090/api/ml/logs \
    -H "Authorization: Bearer <admin-token>"
```

**Modes:**

| Mode | Effect |
|---|---|
| `shadow` | Model runs on every request; predictions are logged but not enforced |
| `active` | Requests classified as fraudulent result in the client IP being auto-banned |

**Model requirements:** ONNX format, single float32 input tensor of shape `[1, 6]`, single float32 output (score 0.0–1.0 where >0.5 = fraud).

> **Implementation note:** `MlFraudEngine::new()` creates an uninitialized engine. The ONNX model must be loaded via the Admin API (`POST /api/ml/upload`) and is not automatically loaded from disk at startup. If no model is loaded, the ML engine silently passes all requests.

---

### 9. Authentication & Authorization

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Enforces authentication on specific routes using one of several methods.

#### 9a. HTTP Basic Auth

```nginx
route /admin {
    upstream admin_pool;
    auth_basic            "Admin Area";
    auth_basic_user       "alice" "$2b$10$...bcrypt_hash...";
    auth_basic_user       "bob"   "plaintext_password";
}
```

#### 9b. JWT Bearer Token

```nginx
route /api {
    upstream api_pool;
    auth_jwt_secret    "your-256-bit-secret";
    auth_jwt_algorithm HS256;             # or RS256, ES256, HS384, RS384, etc.
}
```

For RS256/ES256, set `auth_jwt_secret` to the PEM-encoded public key.

#### 9c. OAuth 2.0 Token Introspection (RFC 7662)

```nginx
route /api {
    upstream api_pool;
    auth_oauth_introspect_url  http://auth-server/oauth/introspect;
    auth_oauth_client_id       my-client;
    auth_oauth_client_secret   my-secret;
}
```

#### 9d. External Auth Request (auth_request)

```nginx
server {
    auth_request http://auth-service.internal/check;   # called for every request

    route /protected {
        upstream protected_pool;
    }
}
```

The auth service receives the original request method, URI, and all headers. A `2xx` response allows the request through; any other status rejects it with `401 Unauthorized`.

#### 9e. OIDC (OpenID Connect)

```nginx
route /app {
    upstream app_pool;
    # Full OIDC authorization code flow
    # Session state is stored in the built-in TTL key-value store
}
```

#### 9f. JWKS (JSON Web Key Set)

JWKS endpoints are automatically fetched and cached when JWT verification with `kid` (Key ID) lookup is needed. The JWKS Manager runs a background refresh loop and supports RSA and EC keys.

---

### 10. Response Caching

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Caches upstream responses to serve subsequent identical requests without hitting the backend.

**Two-tier architecture:**
- **L1 (in-memory):** Moka LFU cache, up to 10,000 entries, sub-microsecond lookup
- **L2 (disk):** RocksDB or sled — survives process restart

**How to configure:**

```nginx
server {
    cache_disk_path /var/cache/phalanx;    # enables L2 disk tier

    route /api/data {
        upstream data_pool;
        proxy_cache       on;
        proxy_cache_valid 60;              # TTL in seconds
    }
}
```

**Cache invalidation:**
```bash
# Purge a specific path
curl -X POST http://localhost:9090/api/cache/purge \
    -H "Authorization: Bearer <admin-token>" \
    -H "Content-Type: application/json" \
    -d '{"key": "/api/data/users"}'

# Purge all entries with a prefix
curl -X POST http://localhost:9090/api/cache/purge \
    -H "Authorization: Bearer <admin-token>" \
    -H "Content-Type: application/json" \
    -d '{"prefix": "/api/data/"}'
```

Purge responses: `{"status":"ok","key":"...","removed":true}` (key), `{"status":"ok","prefix":"...","removed_approx":N}` (prefix), or `{"status":"ok","action":"purge_all"}` (no body). The purge endpoint is fully wired and backed by the live `ResponseCache`.

**Advanced features:**
- `Vary` header support — different cache entries per Accept-Language, etc.
- `stale-while-revalidate` — serves stale content while refreshing in background
- `stale-if-error` — serves stale content when upstream is down
- Thundering herd protection — only one background revalidation per key

---

### 11. Compression (Gzip & Brotli)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Compresses response bodies to reduce bandwidth. Automatically negotiated via `Accept-Encoding`.

**How to configure:**

```nginx
route / {
    upstream web_pool;

    # Gzip
    gzip            on;
    gzip_min_length 1024;    # only compress responses larger than 1KB

    # Brotli (better compression ratio than gzip, supported by all modern browsers)
    brotli on;
}

# Server-wide brotli
server {
    listen 8080;
    brotli on;   # applies to all routes unless overridden
}
```

**How it works:** Phalanx checks `Accept-Encoding` in the request. If `br` is present, Brotli is preferred over gzip. If only `gzip` is present, gzip is used. The response is only returned compressed if the compressed size is smaller than the original.

**Priority:** Brotli > Gzip. Brotli is skipped for responses under 1 KB (`MIN_BROTLI_SIZE`). Compression is skipped for non-compressible content types (images, video, already-compressed formats).

---

### 12. URL Rewriting

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Rewrites request URLs before forwarding to upstream, or returns redirects to clients.

**Syntax:** `rewrite <regex> <replacement> [flag]`

| Flag | Effect |
|---|---|
| `last` | Rewrites path and re-evaluates routing rules |
| `break` | Rewrites path and continues with current route (no re-evaluation) |
| `redirect` | Returns `302 Found` to client |
| `permanent` | Returns `301 Moved Permanently` to client |

**Examples:**

```nginx
route / {
    upstream api_pool;

    # Rewrite /v1/users → /api/users and re-match routes
    rewrite ^/v1/(.+)$ /api/$1 last;

    # Redirect old docs URL permanently
    rewrite ^/docs/(.+)$ https://docs.example.com/$1 permanent;

    # Normalize trailing slash without redirect
    rewrite ^/home/$ /home break;
}
```

---

### 13. Static File Serving

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Serves files directly from the filesystem without forwarding to an upstream.

**How to configure:**

```nginx
route /static {
    root /var/www/html/static;
    add_header Cache-Control "public, max-age=31536000";
}
```

File paths are constructed as `<root><uri_path>`. A request for `/static/app.js` serves `/var/www/html/static/app.js`.

**Custom response headers** can be added to any route using `add_header`:

```nginx
route /api {
    upstream api_pool;
    add_header X-Proxy-By  "Phalanx";
    add_header X-Frame-Options "DENY";
}
```

---

### 14. FastCGI & uWSGI Proxying

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Forwards requests to PHP-FPM (FastCGI) or Python/Ruby applications (uWSGI) using their native protocols.

**FastCGI (PHP-FPM):**

```nginx
route /php {
    fastcgi_pass 127.0.0.1:9000;
}
```

Start PHP-FPM first:
```bash
php-fpm -F -d listen=127.0.0.1:9000
```

**uWSGI (Python/Django):**

```nginx
route /app {
    uwsgi_pass 127.0.0.1:3030;
}
```

Start uWSGI:
```bash
uwsgi --socket 127.0.0.1:3030 --wsgi-file app.py --master --processes 4
```

---

### 15. WebSocket Proxying

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Transparently proxies WebSocket connections by detecting the `Upgrade: websocket` header and switching to bidirectional byte streaming.

**How to configure:**

```nginx
route /ws {
    upstream ws_pool;
}
```

No special directive is needed — Phalanx automatically detects the `Connection: Upgrade` + `Upgrade: websocket` headers and handles the protocol upgrade.

**Testing:**
```bash
# Using websocat
websocat ws://localhost:8080/ws
```

---

### 16. gRPC & gRPC-Web Gateway

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:**
- **gRPC:** Proxies gRPC requests (detected via `content-type: application/grpc`) to upstream gRPC servers over HTTP/2
- **gRPC-Web:** Translates gRPC-Web (browser-friendly) requests into native gRPC for upstreams, and translates responses back

**How to configure:**

```nginx
upstream grpc_pool {
    server 10.0.0.1:50051;
    algorithm roundrobin;
}

server {
    listen 8080;
    ssl_certificate     /etc/phalanx/certs/server.pem;
    ssl_certificate_key /etc/phalanx/certs/server.key;

    route /proto.UserService {
        upstream grpc_pool;
    }
}
```

**gRPC-Web** is handled automatically when the client sends `content-type: application/grpc-web` or `application/grpc-web+proto`. Phalanx rewrites the content-type to `application/grpc`, adds `TE: trailers`, forwards to the backend, and translates the response back. CORS preflight (OPTIONS) requests are handled with the proper `Access-Control-*` response headers.

---

### 17. TCP & UDP Proxying

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Proxies raw TCP and UDP streams (Layer 4) without HTTP parsing.

**TCP Proxying:**

```nginx
# In global config (outside http block)
tcp_listen 5555;    # binds on TCP port 5555 and proxies to upstream default pool
```

**UDP Proxying:**

```nginx
server {
    listen_udp 0.0.0.0:5353;    # DNS proxy example
}
```

UDP sessions maintain per-client-address affinity. Each client gets its own ephemeral backend socket. Idle sessions are reaped after a configurable timeout.

---

### 18. Mail Proxy (SMTP / IMAP / POP3)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Proxies SMTP, IMAP, and POP3 connections with optional custom banner injection and STARTTLS support.

**How to configure (`phalanx.conf`):**

```nginx
# Mail upstream pool
upstream mail_pool {
    server 10.0.0.10:25;
    server 10.0.0.11:25;
}

server {
    listen 8080;

    smtp_bind          0.0.0.0:25;    # SMTP proxy (port 25)
    imap_bind          0.0.0.0:143;   # IMAP proxy (port 143)
    pop3_bind          0.0.0.0:110;   # POP3 proxy (port 110)
    mail_upstream_pool mail_pool;     # defaults to "default" if omitted
}
```

**Runtime behavior:**
- A TCP listener is started for each configured protocol (`smtp_bind`, `imap_bind`, `pop3_bind`)
- On connection, Phalanx selects a backend from the `mail_upstream_pool` using the configured load balancing algorithm
- All bytes are relayed bidirectionally
- Multiple protocols can be active simultaneously on different ports

---

### 19. WebRTC SFU

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Acts as a Selective Forwarding Unit for real-time media, enabling multi-party WebRTC video/audio conferences.

**Supported codecs:** VP8, H.264, Opus

**How it works:**
1. Clients connect to the signaling endpoint
2. Phalanx creates or joins a room
3. Each peer's tracks (video/audio) are forwarded to all other peers in the room
4. Trickle ICE candidate exchange is handled by the SFU

**Testing:**
Open `src/admin/webrtc_test.html` in two browser tabs and connect both to the same room name.

---

### 20. Traffic Mirroring & Splitting

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:**
- **Mirroring:** Sends a fire-and-forget copy of every request to a shadow upstream (does not affect the client-visible response)
- **Splitting:** Routes a deterministic percentage of traffic to a second upstream using consistent hashing

**Mirroring:**

```nginx
# Per-route mirror
route /api {
    upstream primary_pool;
    mirror shadow_pool;      # shadow copy sent here; response discarded
}

# Server-wide mirror (applies to all routes)
server {
    mirror shadow_pool;
}
```

The mirror is a fire-and-forget operation — it does not delay the primary response or affect the client. The shadow upstream receives the same method, URI, headers, and body as the primary.

**Traffic splitting:** The `split_traffic()` function uses consistent hash to send X% of requests to pool A and (100-X)% to pool B. The distribution is deterministic — the same request hash always maps to the same pool.

---

### 21. Session Affinity (Sticky Sessions)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Ensures requests from the same client always reach the same backend.

**Three modes:**

| Mode | Mechanism |
|---|---|
| `Cookie` | Phalanx sets a `Set-Cookie` header encoding the backend address (base64); subsequent requests read this cookie for affinity |
| `Learn` | Phalanx learns the session→backend mapping from a response header set by the application |
| `Route` | Routes based on an existing session cookie value already in the request |

**Wiring status:** Fully wired. Cookie mode is active by default with cookie name `PHALANXID`. On each request, Phalanx checks for the session cookie and, if found, routes to the encoded backend (if still healthy). On the response, `Set-Cookie: PHALANXID=<encoded-addr>; Path=/; Max-Age=3600; HttpOnly` is added. For Learn mode, the response header named in `lookup_header` is read and the mapping stored.

Session mappings are stored in a thread-safe `DashMap`. With Redis configured, they are shared across cluster nodes.

---

### 22. GeoIP Routing

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Allows or denies requests based on the client's country, determined by IP geolocation.

**Database format:** CSV file with rows: `CIDR,country_code,country_name`

Example `geoip.csv`:
```
1.0.0.0/8,US,United States
2.0.0.0/8,CN,China
```

**How to configure:**

```nginx
server {
    listen 8080;

    geoip_db    /etc/phalanx/geoip.csv;
    geo_allow   US,CA,GB,AU;              # only allow these countries
    geo_deny    CN,RU,KP;                 # explicitly deny these countries

    route / {
        upstream backend_pool;
    }
}
```

Blocked clients receive `403 Forbidden`.

**Headers injected for allowed clients:**
- `X-Geo-Country-Code: US`
- `X-Geo-Country: United States`

GeoIP is evaluated after the WAF check and before routing. If no database is configured, all requests pass through.

---

### 23. Real Client IP Extraction

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Correctly determines the real client IP when Phalanx sits behind a load balancer or CDN, and injects standard forwarding headers.

**Resolution priority:**
1. `X-Real-IP` header (from trusted proxy)
2. `X-Forwarded-For` — rightmost IP not in the trusted proxy CIDR list
3. HAProxy PROXY protocol v1 source address
4. TCP socket peer address (fallback)

**How to configure:**

```nginx
server {
    listen 8080;
    trusted_proxy 10.0.0.0/8;
    trusted_proxy 172.16.0.0/12;
    trusted_proxy 192.168.0.0/16;

    route / {
        upstream backend_pool;
    }
}
```

Note: `trusted_proxy` is specified once per CIDR (one directive per line).

**Headers injected by Phalanx to upstreams:**
- `X-Forwarded-For: <real-client-ip>, <proxy-ip>` (appended if already present)
- `X-Real-IP: <real-client-ip>`
- `X-Forwarded-Proto: https` (or `http`)

---

### 24. Connection Limiting (Zone-Based)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Limits concurrent connections per client IP, per header value, per cookie value, per JWT claim, or any composable combination.

**Key sources:**

| Source type | Description |
|---|---|
| `ClientIp` | Limit by client IP address |
| `Header(name)` | Limit by a specific header value |
| `Cookie(name)` | Limit by a specific cookie value |
| `JwtClaim(claim)` | Limit by a JWT claim (e.g., `sub` for user ID) |
| `Uri` | Limit by full request URI |
| `QueryParam(name)` | Limit by a query parameter value |
| `Composite(sources)` | Combine multiple sources into one key |

**How it works (wired as of main.rs):**

`ZoneLimiter` is instantiated at startup and passed into `handle_http_request`. On every request, `acquire_connection(&ip_str)` is called immediately after real IP resolution. A RAII `ConnectionGuard` is created that automatically calls `release_connection` when it drops — even on error paths or early returns. If the slot is not available (when `max_connections > 0`), the request is rejected with `503 Service Unavailable`.

```rust
// Current default in main.rs (unlimited concurrent connections — ZoneLimiter wired for infrastructure)
let zone_limiter = Arc::new(middleware::connlimit::ZoneLimiter::new(
    "per_ip",
    1_000_000,  // rate (use PhalanxRateLimiter for actual rate limiting)
    1_000_000,  // burst
    0,          // max_connections: 0 = unlimited
));
```

To enable a hard connection cap, change the last argument:

```rust
// Limit to 20 concurrent connections per IP
let zone_limiter = Arc::new(middleware::connlimit::ZoneLimiter::new("per_ip", 100, 100, 20));
```

---

### 25. OCSP Stapling

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Caches the OCSP response from the certificate authority and includes it in the TLS handshake, eliminating the need for clients to separately query the OCSP responder. This improves TLS handshake speed and client privacy.

**How it works:** `OcspStapler` reads the OCSP responder URL from the certificate's AIA (Authority Information Access) extension, fetches and caches the DER-encoded response, and runs a background `spawn_refresh_loop()` task to keep it fresh. No configuration directive is required — OCSP stapling is automatically enabled when a TLS certificate is loaded.

---

### 26. Scripting & Hooks (Rhai)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Allows custom logic at four phases of request processing using an embedded Rhai script or compiled Rust hook plugins.

**Hook phases:**

| Phase | When it runs |
|---|---|
| `PreRoute` | Before route matching — can rewrite the path |
| `PreUpstream` | After routing, before forwarding — can modify headers or block |
| `PostUpstream` | After upstream responds — can modify response headers |
| `Log` | After response is sent — for auditing/metrics |

**Built-in hooks:**
- `HeaderInjectionHook` — unconditionally adds headers
- `ConditionalRewriteHook` — rewrites path based on a condition
- `IpAccessHook` — blocks specific IP addresses

**Rhai script example** (`script.rhai`):

```rhai
// Called in PreRoute phase
if uri.starts_with("/legacy") {
    uri = uri.replace("/legacy", "/v2");
}

// Block requests from a specific IP
if client_ip == "1.2.3.4" {
    respond(403, "Forbidden");
}
```

**How to configure:**

```nginx
server {
    rhai_script /etc/phalanx/hooks.rhai;

    route / {
        upstream backend_pool;
    }
}
```

**Wiring status:** The `HookEngine` is fully wired into the request pipeline. Three phases are active:

| Phase | Where it runs | Supported results |
|---|---|---|
| `PreRoute` | Before WAF / route matching | `Respond` (short-circuit 4xx/5xx), `RewritePath`, `SetHeaders` |
| `PreUpstream` | After auth, before backend dispatch | `Respond`, `RewritePath`, `SetHeaders` |
| `Log` | After access logger write | `Continue` (audit only) |

Register hooks programmatically at startup:
```rust
use ai_load_balancer::scripting::{Hook, HookEngine, HookPhase, HeaderInjectionHook};
use std::collections::HashMap;

let mut engine = HookEngine::new();
let mut headers = HashMap::new();
headers.insert("X-Proxy-Version".to_string(), "1.0".to_string());
engine.register(Hook {
    name: "version-header".to_string(),
    phase: HookPhase::PreUpstream,
    priority: 0,
    handler: Box::new(HeaderInjectionHook::new(headers)),
});
```

---

### 27. Key-Value Store

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** A shared in-memory key-value store with TTL, equivalent to NGINX Plus `keyval_zone`. Useful for dynamic allow/deny lists, feature flags, or rate limit overrides.

**How to configure:**

```nginx
server {
    keyval_ttl_secs 3600;    # default TTL for entries (1 hour)
}
```

**Admin API:**

```bash
# Set a key (with optional TTL override)
curl -X POST http://localhost:9090/api/keyval/my-key \
    -H "Authorization: Bearer <admin-token>" \
    -H "Content-Type: application/json" \
    -d '{"value": "my-value", "ttl_secs": 300}'

# Get a key
curl http://localhost:9090/api/keyval/my-key \
    -H "Authorization: Bearer <admin-token>"

# List all keys
curl http://localhost:9090/api/keyval \
    -H "Authorization: Bearer <admin-token>"

# Delete a key
curl -X DELETE http://localhost:9090/api/keyval/my-key \
    -H "Authorization: Bearer <admin-token>"
```

With Redis configured, keyval entries are automatically synchronized across all cluster nodes via pub/sub.

---

### 28. Service Discovery

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Dynamically discovers and registers backends without restarting or reloading configuration.

**Three mechanisms:**

#### DNS SRV Records

```nginx
upstream my_service {
    srv_discover _http._tcp.my-service.internal;  # polls every 30 seconds
}
```

#### RocksDB Persistent Registry

```bash
# Register a new backend dynamically
curl -X POST http://localhost:9090/api/discovery/backends \
    -H "Authorization: Bearer <admin-token>" \
    -H "Content-Type: application/json" \
    -d '{"pool": "web_pool", "address": "10.0.0.5:8080"}'

# Remove a backend
curl -X DELETE http://localhost:9090/api/discovery/backends/web_pool/10.0.0.5:8080 \
    -H "Authorization: Bearer <admin-token>"

# List current backends
curl http://localhost:9090/api/upstreams/detail \
    -H "Authorization: Bearer <admin-token>"
```

Registered backends survive Phalanx restarts (stored in RocksDB).

#### etcd Watch

Configure etcd in `ClusterConfig` and backends registered in the etcd key space are automatically picked up via a watch loop — no polling delay.

---

### 29. Cluster State Sharing

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Synchronizes state (WAF bans, sticky sessions, keyval entries) across a fleet of Phalanx nodes.

**Backends:**

| Backend | Use case |
|---|---|
| Redis | Pub/sub for real-time ban/keyval sync; ZSET for distributed rate limits |
| etcd | KV with TTL leases; watch-based updates; best for Kubernetes environments |
| Standalone | Single-node mode, no external dependency |

**How to configure Redis cluster sync:**

```nginx
server {
    redis_url redis://127.0.0.1:6379;
    node_id   phalanx-node-1;
}
```

With Redis configured:
- WAF IP bans are broadcast to all nodes within milliseconds
- Sticky session mappings are shared (cross-node affinity)
- Keyval store entries are replicated

**etcd setup (config file):**
```nginx
server {
    etcd_endpoints http://etcd1:2379,http://etcd2:2379;
    node_id        phalanx-node-1;
}
```

When both `etcd_endpoints` and `redis_url` are set, etcd takes precedence for cluster KV. Redis is still used for pub/sub (ban and keyval sync).

---

### 30. Observability (Prometheus, OTLP, Access Logs)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Exposes metrics, distributed traces, and structured access logs.

#### Prometheus Metrics

```bash
curl http://localhost:9090/metrics
```

**Available metrics:**

| Metric | Type | Labels |
|---|---|---|
| `phalanx_http_requests_total` | Counter | method, status, pool |
| `phalanx_http_request_duration_seconds` | Histogram | — |
| `phalanx_active_connections` | Gauge | — |
| `phalanx_waf_blocks_total` | Counter | category |
| `phalanx_rate_limit_rejections_total` | Counter | type |
| `phalanx_cache_total` | Counter | result (hit/miss) |

**Example Prometheus scrape config:**
```yaml
scrape_configs:
  - job_name: phalanx
    static_configs:
      - targets: ['localhost:9090']
```

#### OpenTelemetry Distributed Tracing

```nginx
server {
    otel_endpoint     http://jaeger:4317;    # OTLP gRPC endpoint
    otel_service_name phalanx-prod;
}
```

Traces are exported in OTLP format and work with Jaeger, Tempo, Honeycomb, Datadog, etc.

#### Structured Access Logs

```nginx
server {
    access_log        /var/log/phalanx/access.log;
    access_log_format json;    # json | combined | common
}
```

**JSON log example:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "method": "GET",
  "uri": "/api/users",
  "status": 200,
  "duration_ms": 12,
  "client_ip": "203.0.113.5",
  "upstream": "api_pool"
}
```

---

### 31. Admin API & Dashboard

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Provides a REST API and web dashboard for managing Phalanx at runtime without restarts.

**Admin server bind:**

```nginx
admin_listen 127.0.0.1:9090;
```

#### RBAC Authentication

All admin endpoints require a Bearer token. Three roles exist:

| Role | Permissions |
|---|---|
| `Admin` | Full access including destructive operations and ML model upload |
| `Operator` | Can manage routes, upstreams, and cache; cannot manage SSL certs or ML |
| `ReadOnly` | GET-only access to stats and listings |

```bash
curl http://localhost:9090/api/stats \
    -H "Authorization: Bearer <your-token>"
```

#### Dynamic Route Management

```bash
# Add a new route
curl -X POST http://localhost:9090/api/routes \
    -H "Authorization: Bearer <admin-token>" \
    -H "Content-Type: application/json" \
    -d '{"path": "/new-service", "upstream": "new_pool"}'

# List all routes
curl http://localhost:9090/api/routes \
    -H "Authorization: Bearer <admin-token>"

# Delete a route
curl -X DELETE "http://localhost:9090/api/routes/%2Fnew-service" \
    -H "Authorization: Bearer <admin-token>"
```

#### Dynamic SSL Certificate Management

```bash
# Add a certificate
curl -X POST http://localhost:9090/api/ssl \
    -H "Authorization: Bearer <admin-token>" \
    -H "Content-Type: application/json" \
    -d '{
        "server_name": "api.example.com",
        "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
        "key_pem": "-----BEGIN PRIVATE KEY-----\n..."
    }'

# List certificates
curl http://localhost:9090/api/ssl \
    -H "Authorization: Bearer <admin-token>"

# Remove a certificate
curl -X DELETE http://localhost:9090/api/ssl/api.example.com \
    -H "Authorization: Bearer <admin-token>"
```

#### Web Dashboard

Open `http://localhost:9090/dashboard` in a browser to see:
- Live request throughput and latency histograms
- Backend health status for all upstream pools
- WAF block counts by category
- Cache hit rate
- Active connection count

---

### 32. Hot Config Reload

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Reloads the configuration file and rotates TLS certificates without restarting the process or dropping connections.

**How to trigger:**

```bash
# Send SIGHUP to the Phalanx process
kill -HUP $(pgrep ai_load_balancer)

# Or via the admin API
curl -X POST http://localhost:9090/api/reload \
    -H "Authorization: Bearer <admin-token>"
```

**What gets reloaded:**
- All `server`, `upstream`, and `route` blocks from `phalanx.conf`
- TLS certificates and keys (new connections get the new cert immediately)
- Rate limit and WAF settings

**What is NOT affected:**
- In-flight requests (completed normally with old config)
- Active TCP/UDP sessions
- Existing sticky session mappings in memory

The reload is atomic — Phalanx uses `ArcSwap` to swap the config pointer. Threads serving old requests hold a reference to the old config until their requests complete, then naturally transition to the new config.

---

### 33. Active-Active Load Balancer Cluster (High Availability)

**What it does:** Runs multiple Phalanx nodes simultaneously behind a shared VIP. All nodes accept traffic at the same time. If one node goes down, the others continue serving without any failover delay.

#### Architecture

```
Internet
    │
    ▼
[VIP 203.0.113.1]  ← keepalived / AWS NLB / GCP TCP LB
    │
    ├─── Node A: phalanx (10.0.0.1:8080)
    ├─── Node B: phalanx (10.0.0.2:8080)
    └─── Node C: phalanx (10.0.0.3:8080)
    │
    ├── Shared Redis (10.0.1.1:6379)    — bans, keyval, rate-limit counters
    └── Shared etcd  (10.0.1.2:2379)   — leader election, cluster KV
```

Each Phalanx node is completely stateless with respect to traffic (no master/slave distinction). Shared state (bans, sticky sessions, keyval) is synchronized via Redis pub/sub and the `ClusterState` KV store.

#### Step 1 — Configure Each Node

Create identical `phalanx.conf` on every node, varying only `node_id`:

**Node A (`10.0.0.1`):**
```nginx
worker_threads 8;
admin_listen   127.0.0.1:9090;
node_id        phalanx-a;

http {
    upstream backend_pool {
        server 10.0.2.1:8080 weight=1;
        server 10.0.2.2:8080 weight=1;
        server 10.0.2.3:8080 weight=1;
        algorithm least_connections;
        health_check /health;
        keepalive 64;
    }

    server {
        listen 8080;

        # Shared state — all nodes point to the same Redis/etcd
        redis_url      redis://10.0.1.1:6379;
        etcd_endpoints http://10.0.1.2:2379;

        # Distribute session cookies so any node can pick them up
        route / {
            upstream backend_pool;
        }
    }
}
```

**Node B** and **Node C** use the exact same config with `node_id phalanx-b;` / `node_id phalanx-c;`.

#### Step 2 — keepalived VIP (Linux)

Install keepalived on every Phalanx node. The node with the highest `priority` holds the VIP; if it goes down, the next node takes over within 1–2 seconds.

`/etc/keepalived/keepalived.conf` on **Node A** (priority 100):

```conf
vrrp_script chk_phalanx {
    script "curl -sf http://127.0.0.1:8080/ -o /dev/null"
    interval 2
    fall    2
    rise    2
}

vrrp_instance VI_PHALANX {
    state  MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1

    virtual_ipaddress {
        203.0.113.1/24
    }

    track_script {
        chk_phalanx
    }
}
```

On **Node B** use `state BACKUP` and `priority 90`. On **Node C** use `state BACKUP` and `priority 80`.

When Node A's Phalanx process stops responding, keepalived removes the VIP from Node A and assigns it to Node B within the `advert_int` window. Node B already has all shared state from Redis, so it immediately handles new connections.

#### Step 3 — Cloud Load Balancer (AWS / GCP / Azure)

If you run on cloud infrastructure, skip keepalived and use a managed TCP load balancer:

**AWS Network Load Balancer:**
```bash
# Create target group with TCP health checks on port 8080
aws elbv2 create-target-group \
    --name phalanx-tg \
    --protocol TCP \
    --port 8080 \
    --health-check-protocol TCP \
    --health-check-port 8080 \
    --target-type ip

# Register all three Phalanx node IPs
aws elbv2 register-targets \
    --target-group-arn <tg-arn> \
    --targets Id=10.0.0.1 Id=10.0.0.2 Id=10.0.0.3

# Create NLB listener forwarding to the target group
aws elbv2 create-listener \
    --load-balancer-arn <nlb-arn> \
    --protocol TCP --port 80 \
    --default-actions Type=forward,TargetGroupArn=<tg-arn>
```

The NLB health-checks each node every 10 seconds. A failing node is drained from the rotation without affecting in-flight requests on healthy nodes.

#### Step 4 — Verify Shared State

Start all three nodes and confirm state is shared:

```bash
# On Node A — add a keyval entry
curl -X POST http://10.0.0.1:9090/api/keyval/test_key \
    -H "Authorization: Bearer admin" \
    -d '{"value":"hello","ttl_secs":300}'

# On Node B — confirm the entry is visible (synced via Redis)
curl http://10.0.0.2:9090/api/keyval/test_key \
    -H "Authorization: Bearer admin"
# → {"value":"hello","node_id":"phalanx-a","updated_at":...}
```

#### Failover Behavior

| Scenario | Recovery time | Data loss |
|---|---|---|
| Node process crash | < 2 s (keepalived) or < 10 s (cloud LB) | None — state in Redis |
| Node network partition | < advert_int (keepalived) | None |
| Redis failure | Graceful degradation: bans/keyval in-memory only until Redis recovers | Possible ban/keyval divergence |
| All nodes down simultaneously | Full outage | N/A |

#### Distributed Rate Limiting Across Nodes

With Redis configured, `PhalanxRateLimiter` uses Redis Lua ZSET atomics to enforce the rate limit cluster-wide. A client that hits 40 req/s on Node A and 40 req/s on Node B will be correctly throttled at the configured 50 req/s global limit — not 100 req/s.

```nginx
server {
    redis_url          redis://10.0.1.1:6379;
    rate_limit_per_ip  50;    # global 50 req/s per IP (enforced across all nodes via Redis)
    rate_limit_burst   100;
}
```

#### WAF Ban Synchronization

When Node A bans an IP (e.g., after a SQL injection attempt), it immediately publishes the ban to the Redis `phalanx:bans` channel. Nodes B and C receive the pub/sub message within milliseconds and add the IP to their local ban list. The banned IP is blocked on all nodes without waiting for a health-check cycle.

---

### 34. WebRTC SFU Advanced & WebRTC-to-HLS Live Streaming

#### Current SFU Capabilities

Phalanx's SFU (`src/proxy/webrtc.rs`) provides:

| Feature | Status |
|---|---|
| Multi-party rooms | Fully implemented |
| VP8, H.264, Opus codecs | Supported |
| Trickle ICE | Supported |
| Simulcast (multiple quality layers) | Planned |
| SVC (scalable video coding) | Planned |
| End-to-end encryption (insertable streams) | Planned |
| Recording to disk | Planned |
| WHIP/WHEP ingest/egress protocol | Planned |

#### Planned WebRTC Improvements

1. **Simulcast & Adaptive Bitrate** — Let each publisher send 3 quality layers (low/mid/high). The SFU selects the right layer per subscriber based on available bandwidth, eliminating the need for transcoding.

2. **WHIP Ingest** (WebRTC-HTTP Ingest Protocol) — Standard-compliant `/whip` endpoint so encoders like OBS, Gstreamer, and FFmpeg can push a live stream to Phalanx over WebRTC using a single HTTP POST instead of a custom signaling flow.

3. **WHEP Egress** — Matching `/whep` endpoint so viewers can subscribe using any WHEP-compliant player.

4. **Data Channels** — Binary/text data channels for chat, reactions, and signaling side-channels.

5. **Per-Room Recording** — Store each room's media tracks to disk as `.webm` files using `webrtc::track::TrackLocalStaticSample`.

#### WebRTC to HLS Live Streaming Pipeline

WebRTC delivers ultra-low latency (< 500 ms) but HLS is required for wide compatibility (smart TVs, set-top boxes, CDN distribution). The WebRTC→HLS pipeline bridges both worlds.

**Architecture:**

```
WebRTC Publisher (OBS / browser)
        │
        │  WHIP POST /ingest/live/room-1
        ▼
Phalanx SFU (WebRTC ingestion)
        │
        │  Raw RTP packets (VP8/H.264 + Opus)
        ▼
Transcoder Worker (GStreamer / FFmpeg pipe)
        │
        │  Segmented .ts files (2 s segments)
        ▼
HLS Segment Store (local disk / S3)
        │
        │  Served via Phalanx static file route
        ▼
HLS Players (hls.js, Safari, VLC, smart TV)
```

**How to implement the transcoding bridge (GStreamer example):**

```bash
# Start GStreamer pipeline reading from Phalanx's RTP forwarder port
# and writing HLS segments to /var/www/hls/
gst-launch-1.0 \
  udpsrc port=5004 caps="application/x-rtp,media=video,encoding-name=H264" \
  ! rtph264depay ! h264parse ! avdec_h264 \
  ! x264enc bitrate=2000 tune=zerolatency \
  ! mpegtsmux \
  ! hlssink \
      location="/var/www/hls/segment_%05d.ts" \
      playlist-location="/var/www/hls/stream.m3u8" \
      target-duration=2 \
      max-files=10
```

**Serve HLS from Phalanx:**

```nginx
http {
    server {
        listen 8080;

        # Serve HLS segments with correct MIME types and CORS for players
        route /hls {
            root /var/www/hls;
            add_header Access-Control-Allow-Origin *;
            add_header Cache-Control no-cache;
        }
    }
}
```

**Client HLS playback (hls.js):**

```html
<video id="video" controls></video>
<script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
<script>
  const video = document.getElementById('video');
  if (Hls.isSupported()) {
    const hls = new Hls({ lowLatencyMode: true, liveSyncDurationCount: 3 });
    hls.loadSource('http://your-server:8080/hls/stream.m3u8');
    hls.attachMedia(video);
  } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
    video.src = 'http://your-server:8080/hls/stream.m3u8'; // Safari native HLS
  }
</script>
```

**End-to-end latency targets:**

| Pipeline | Typical Latency |
|---|---|
| WebRTC viewer (SFU only) | 100–500 ms |
| WebRTC → HLS (LL-HLS, 2 s segments) | 2–5 s |
| WebRTC → HLS (standard, 6 s segments) | 10–20 s |
| WebRTC → DASH (CMAF chunks) | 2–4 s |

**Low-Latency HLS (LL-HLS)** can be achieved by writing partial segments and exposing the `EXT-X-PART` extension. Supported by hls.js v1+ and iOS 14+.

#### Admin Dashboard — Implemented Tabs

The admin dashboard (`GET /dashboard`) has seven fully implemented tabs:

| Tab | Contents |
|---|---|
| **Overview** | Global stats (6 counters), live req/s bar chart (30-poll ring buffer), top-IP leaderboard with inline ban buttons |
| **Upstreams** | Backend health heatmap (color-coded per pool), full backend table with health/conns/weight |
| **WAF & Security** | Live attack feed (method/path/reason/IP), active ban list with unban, strike leaderboard, manual ban input |
| **ML Fraud** | Fraud score histogram (10-bucket distribution), inference log, shadow/active mode toggle |
| **Bandwidth & Alerts** | Per-protocol bytes in/out/total/requests/connections table with utilization bars; traffic distribution chart; active connections chart; resource alert table (timestamp, level, metric, message, value vs threshold); WebRTC room bandwidth table |
| **Keyval** | Key-value store CRUD, list all entries |
| **Cluster** | Node health table, cache entry count and hit-rate |

---

### 35. Per-Protocol Bandwidth Monitoring

**What it does:** Tracks cumulative `bytes_in`, `bytes_out`, `requests`, and `active_connections` for every protocol Phalanx handles, exposed as a REST endpoint and visualised in the dashboard.

**Supported protocols:** `http1`, `http2`, `http3`, `websocket`, `grpc`, `tcp`, `udp`, `webrtc`

**API endpoint:**

```bash
curl http://127.0.0.1:9099/api/bandwidth
```

```json
{
  "protocols": [
    {
      "protocol": "http1",
      "bytes_in": 1048576,
      "bytes_out": 5242880,
      "requests": 12345,
      "active_connections": 42
    },
    {
      "protocol": "webrtc",
      "bytes_in": 0,
      "bytes_out": 0,
      "requests": 0,
      "active_connections": 0
    }
  ]
}
```

The response is sorted by total bytes descending so the busiest protocol appears first.

**Wiring in `main.rs`:**

```rust
let bandwidth_tracker = telemetry::bandwidth::BandwidthTracker::new();
// Inject into AdminState → served at /api/bandwidth
```

**Recording traffic (example — HTTP1 path):**

```rust
let p = bandwidth_tracker.protocol("http1");
p.add_in(request_bytes);
p.add_out(response_bytes);
p.inc_requests();
p.conn_open();   // connection accepted
// ... handle request ...
p.conn_close();  // connection done
```

**Configuring per-protocol thresholds:**

```rust
use crate::telemetry::bandwidth::ProtocolThreshold;

bandwidth_tracker.set_threshold("webrtc", ProtocolThreshold {
    bandwidth_bps_warn: 100 * 1024 * 1024,      // 100 MiB cumulative → warning
    bandwidth_bps_critical: 500 * 1024 * 1024,  // 500 MiB → critical
    connections_warn: 500,
    connections_critical: 2_000,
});
```

---

### 36. Resource Alert System

**What it does:** Monitors bandwidth and connection thresholds per protocol (plus process memory and open file descriptors on Linux) and maintains a rolling log of triggered alerts. Alerts are exposed via REST and displayed in the dashboard. An optional webhook fires for every new alert.

**API endpoints:**

```bash
# List most recent 50 alerts (newest first)
curl http://127.0.0.1:9099/api/alerts?n=50

# Trigger an immediate check cycle
curl -X POST http://127.0.0.1:9099/api/alerts/check
```

**Alert response shape:**

```json
{
  "alerts": [
    {
      "timestamp": 1711900000,
      "level": "warning",
      "category": "bandwidth",
      "protocol": "http1",
      "metric": "bandwidth",
      "message": "http1 cumulative traffic 128.0 MiB exceeds warning threshold",
      "value": 134217728,
      "threshold": 104857600
    }
  ],
  "total": 1
}
```

**Alert levels:** `info` · `warning` · `critical`

**Alert categories:** `bandwidth` (per-protocol) · `system` (process memory, open FDs — Linux only)

**Background polling** starts automatically at boot (every 30 s):

```rust
// in main.rs — already wired
Arc::clone(&alert_engine).spawn_background_check(30);
```

**Webhook delivery** (configure in `main.rs`):

```rust
let alert_engine = AlertEngine::new(bandwidth_tracker)
    .with_webhook("https://hooks.slack.com/services/…".to_string());
```

The webhook sends a JSON `POST` with the full `AlertRecord` payload to the configured URL on every new alert.

---

### 37. Circuit Breaker with Exponential Backoff

The circuit breaker is a per-backend state machine with three states: `CLOSED` (normal), `OPEN` (all traffic rejected), and `HALF_OPEN` (one probe allowed). Configure per backend in `phalanx.conf`:

```nginx
upstream api {
    server 10.0.0.1:8080 circuit_breaker=on circuit_initial_backoff=5 circuit_max_backoff=60;
    server 10.0.0.2:8080 circuit_breaker=on;
}
```

**State transitions:**

| Event | Transition |
|-------|-----------|
| `max_fails` consecutive failures within `fail_timeout_secs` | `CLOSED → OPEN` |
| Failed probe in `HALF_OPEN` | `HALF_OPEN → OPEN` (backoff doubles, capped at `circuit_max_backoff_secs`) |
| Successful probe in `HALF_OPEN` | `HALF_OPEN → CLOSED` (backoff resets) |
| Active health check detects backend UP | any → `CLOSED` |

**Backoff schedule** (default: initial=5s, max=60s): `5 → 10 → 20 → 40 → 60 → 60 → …`

Implementation: `src/routing/mod.rs` — `trip_circuit()`, `record_circuit_success()`, `is_circuit_closed()`.

---

### 38. Slow-Start Ramp for Recovering Backends

After a backend comes back online (detected by active health check), Phalanx linearly increases its effective weight from 1 → full weight over `slow_start_secs`. This prevents overwhelming a freshly-restarted backend with full traffic immediately.

```nginx
upstream api {
    server 10.0.0.1:8080 weight=10 slow_start=30s;
}
```

During the ramp:
```
effective_weight = max(1, floor(weight * elapsed_secs / slow_start_secs))
```

After `slow_start_secs` seconds, the backend receives its full configured weight. Implementation: `src/routing/mod.rs` — `effective_weight()`.

---

### 39. Active Health Checks

Active health checks run in a background loop probing each backend independently of incoming traffic.

```nginx
upstream api {
    server 10.0.0.1:8080 health_check_path=/health health_check_status=200 max_fails=3 fail_timeout=30;
}
```

- **TCP connect check** (default): establishes a TCP connection; success = backend is UP
- **HTTP GET check** (`health_check_path`): sends GET to the path; checks response status against `health_check_status`
- **Passive check**: counts 5xx/timeout responses; trips circuit after `max_fails` within `fail_timeout_secs`

When a backend recovers (DOWN → UP), `record_recovery()` stamps the timestamp for slow-start and closes the circuit breaker. Implementation: `src/routing/mod.rs`.

---

### 40. Zero-Copy File Proxying (Linux sendfile / splice)

On Linux, raw TCP proxy connections use `splice(2)` via two pipes for true zero-copy bidirectional streaming. No data is copied into userspace.

```
Client → [pipe] → splice → [pipe] → Backend
```

On macOS/non-Linux, a fallback `copy_bidirectional_fallback()` using Tokio's `AsyncRead`/`AsyncWrite` is used automatically.

The zero-copy path is activated in:
- `src/proxy/tcp.rs` — raw TCP proxy sessions
- `src/proxy/zero_copy.rs` — `splice_bidirectional()` (Linux) and `copy_bidirectional_fallback()` (all platforms)

No configuration needed — platform detection is automatic at compile time via `#[cfg(target_os = "linux")]`.

---

### 41. Keyval ↔ WAF Dynamic Ban Integration

The WAF's ban list is backed by the Keyval store, enabling runtime IP bans without config reload:

```bash
# Ban an IP for 1 hour
curl -X POST http://127.0.0.1:9099/api/keyval \
  -H "Content-Type: application/json" \
  -d '{"key": "ban:10.0.0.42", "value": "1", "ttl_secs": 3600}'

# The WAF checks this key on every request:
# src/waf/mod.rs — WafEngine.with_keyval(keyval) sets up the integration
```

When `ban:<ip>` exists in keyval, the WAF blocks the IP with a `403 Forbidden`. The entry auto-expires after `ttl_secs`. The WAF also auto-populates bans via `IpReputationManager` after `waf_auto_ban_threshold` strikes, writing them back to keyval with a TTL of `waf_auto_ban_duration` seconds.

This means external systems (CI/CD, SIEM, threat intel feeds) can dynamically update the blocklist without restarting Phalanx.

---

### 42. CAPTCHA Bot Challenge

Phalanx can serve CAPTCHA challenges to suspicious bots before allowing access. The system classifies User-Agents into four tiers (Human, GoodBot, BadBot, Unknown) and challenges Unknown bots whose request rate exceeds a configurable threshold.

**Supported providers:** hCaptcha, Cloudflare Turnstile, Google reCAPTCHA v2.

```nginx
server {
    # Enable CAPTCHA bot challenge
    captcha_site_key          10000000-ffff-ffff-ffff-000000000001;
    captcha_secret_key        0x0000000000000000000000000000000000000000;
    captcha_provider          hcaptcha;          # hcaptcha | turnstile | recaptcha
    captcha_challenge_threshold 5.0;             # req/s above which Unknown bots get challenged
}
```

**How it works:**

| Bot Classification | Action |
|---|---|
| `Human` (Chrome, Firefox, Safari) | Allow |
| `GoodBot` (Googlebot, Bingbot, Pingdom) | Allow |
| `BadBot` (sqlmap, nikto, masscan) | Block immediately |
| `Unknown` (curl, python-requests) below threshold | Allow |
| `Unknown` above threshold | Serve CAPTCHA challenge page |

**Challenge flow:**

1. Client sends request with Unknown bot User-Agent at high rate
2. Phalanx serves an HTML challenge page at `/__phalanx/captcha/verify`
3. Client solves the CAPTCHA widget
4. Phalanx verifies the token with the provider's API (server-side)
5. On success, the IP is marked as verified and subsequent requests pass through
6. Verified IPs can be revoked or cleared via the `CaptchaManager` API

**Implementation:** `src/waf/bot.rs` — `CaptchaManager`, `CaptchaProvider`, `CaptchaAction`, `classify_user_agent()`.

---

### 43. Gossip-Based Cluster State

For environments where Redis or etcd is not available, Phalanx supports a SWIM-style gossip protocol for peer-to-peer cluster state synchronization over UDP. Nodes exchange state digests every gossip round and reconcile differences using last-write-wins (LWW) semantics.

```nginx
server {
    # Enable gossip-based cluster state (takes priority over etcd/redis)
    gossip_bind         0.0.0.0:7946;
    gossip_seed_peers   10.0.0.2:7946,10.0.0.3:7946;
    gossip_interval_ms  1000;                  # gossip round interval (default: 1000ms)
    node_id             phalanx-node-1;
}
```

**Protocol details:**

| Message | Purpose |
|---|---|
| `Ping` | Periodic state exchange with random peers (entries + member list) |
| `Ack` | Response to Ping with local state |
| `Join` | Announce a new node to the cluster |
| `Leave` | Graceful departure notification |
| `PingReq` | Indirect ping for failure detection |

**Membership lifecycle:** `Alive → Suspect → Dead` (configurable suspicion timeout).

**State sharing:** KV entries are replicated across all nodes with TTL support. Each entry carries a timestamp for LWW conflict resolution. Expired entries are evicted during gossip rounds.

**Configuration priority:** `gossip_bind` > `etcd_endpoints` > `redis_url` > Standalone.

**Implementation:** `src/cluster/gossip.rs` — `GossipState`, `GossipConfig`, `GossipMessage`.

---

### 44. Proxy-Wasm Plugin Extensibility

Phalanx supports a Proxy-Wasm-inspired plugin framework for extending request/response processing. Plugins implement the `WasmPlugin` trait and are registered with the `WasmPluginManager`, which orchestrates execution across five lifecycle phases.

```nginx
server {
    # Load plugin configurations from a JSON file
    wasm_plugin_config /etc/phalanx/plugins.json;
}
```

**Plugin configuration file (`plugins.json`):**

```json
[
  {
    "name": "header-injector",
    "wasm_path": "/etc/phalanx/plugins/headers.wasm",
    "config": "{\"X-Env\": \"production\"}",
    "phases": ["OnRequestHeaders"],
    "priority": 10,
    "enabled": true
  },
  {
    "name": "api-rate-limiter",
    "wasm_path": "/etc/phalanx/plugins/ratelimit.wasm",
    "config": "{\"header\": \"X-API-Key\", \"max\": 1000}",
    "phases": ["OnRequestHeaders"],
    "priority": 20,
    "enabled": true
  }
]
```

**Lifecycle phases:**

| Phase | When |
|---|---|
| `OnRequestHeaders` | After request headers are received |
| `OnRequestBody` | After request body is buffered |
| `OnResponseHeaders` | After upstream response headers |
| `OnResponseBody` | After upstream response body |
| `OnLog` | After the request is fully processed |
| `OnTick` | Periodic background callback |

**Plugin chain behavior:**

- Plugins execute in priority order (lower number = higher priority)
- A plugin returning `WasmDirectResponse` short-circuits the chain (e.g., 403 Forbidden)
- Headers and metadata from multiple plugins are merged
- Disabled plugins and phase-mismatched plugins are skipped

**Built-in plugins:**

| Plugin | Description |
|---|---|
| `HeaderInjectionPlugin` | Adds custom headers to every request |
| `HeaderRateLimitPlugin` | Rate-limits by header value (e.g., API key) |
| `PathBlockerPlugin` | Blocks requests matching path patterns |

**Implementation:** `src/wasm/mod.rs` — `WasmPluginManager`, `WasmPlugin` trait, `WasmPhase`.

---

### 45. Kubernetes Ingress Controller

Phalanx can act as a Kubernetes Ingress Controller, watching Ingress v1 and Gateway API HTTPRoute resources and translating them into internal route configurations.

```nginx
server {
    k8s_ingress_enabled true;
    k8s_ingress_class   phalanx;    # only reconcile Ingress resources with this class
}
```

**Supported resource types:**

| Resource | API Group | Status |
|---|---|---|
| Ingress v1 | `networking.k8s.io/v1` | Full support |
| HTTPRoute | `gateway.networking.k8s.io/v1` | Full support |

**Ingress annotations:**

| Annotation | Description | Example |
|---|---|---|
| `phalanx.io/load-balancing` | Load balancing algorithm | `least_connections` |
| `phalanx.io/waf-enabled` | Enable WAF for this Ingress | `true` |
| `phalanx.io/rate-limit` | Per-IP rate limit | `100` |
| `phalanx.io/ssl-redirect` | Force HTTPS redirect | `true` |
| `phalanx.io/rewrite-target` | URL rewrite target | `/v2` |
| `phalanx.io/cors-enabled` | Add CORS headers | `true` |
| `phalanx.io/cache-enabled` | Enable response caching | `true` |
| `phalanx.io/auth-type` | Authentication type | `jwt` |

**Example Ingress resource:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
  annotations:
    kubernetes.io/ingress.class: phalanx
    phalanx.io/cors-enabled: "true"
    phalanx.io/rewrite-target: /v2
spec:
  tls:
    - hosts: [app.example.com]
      secretName: app-tls
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: api-svc
                port:
                  number: 8080
```

**Gateway API example:**

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: canary-route
spec:
  hostnames: [api.example.com]
  rules:
    - matches:
        - path:
            type: Prefix
            value: /v1
      backendRefs:
        - name: api-stable
          port: 8080
          weight: 90
        - name: api-canary
          port: 8080
          weight: 10
```

**Features:** Host-based routing, path-based routing, TLS termination with Secret references, weighted backends (canary deployments), Gateway API filters (header modification, URL rewrite, redirects).

**Implementation:** `src/k8s/mod.rs` — `IngressController`, `reconcile_ingress()`, `reconcile_gateway_route()`.

---

### 46. Global Anycast / GSLB

Phalanx includes a Global Server Load Balancer (GSLB) that routes clients to the nearest healthy data center based on geographic proximity, measured latency, or weighted distribution.

```nginx
server {
    gslb_policy         geographic;     # geographic | latency | weighted | geo_latency
    gslb_max_latency_ms 500;            # max acceptable latency before DC is unhealthy
}
```

**Routing policies:**

| Policy | Description |
|---|---|
| `geographic` | Route to the DC whose `primary_countries` list matches the client's GeoIP country; fall back by region proximity |
| `latency` | Route to the DC with the lowest measured health-check latency |
| `weighted` | Weighted round-robin across all healthy DCs |
| `geo_latency` | Try geographic first; if no match, fall back to lowest latency |

**Geographic regions and proximity:**

The GSLB uses a 7-region model with proximity-based fallback ordering:

| Region | Countries (examples) | Proximity fallback |
|---|---|---|
| North America | US, CA, MX | SA → EU → AS → OC → ME → AF |
| South America | BR, AR, CL, CO | NA → EU → AF → AS → OC → ME |
| Europe | GB, DE, FR, IT, ES | ME → AF → NA → AS → SA → OC |
| Africa | ZA, NG, KE, EG | EU → ME → SA → AS → NA → OC |
| Middle East | AE, SA, IL, TR | EU → AF → AS → NA → SA → OC |
| Asia | CN, JP, KR, IN, SG | OC → ME → EU → NA → SA → AF |
| Oceania | AU, NZ, FJ | AS → NA → SA → EU → ME → AF |

**Data center configuration (programmatic):**

```rust
use ai_load_balancer::gslb::{GslbRouter, GslbPolicy, DataCenter, GeoRegion};

let router = GslbRouter::new(GslbPolicy::GeographicWithLatencyFailover, 500.0, 3);

router.add_data_center(DataCenter {
    id: "us-east-1".to_string(),
    name: "US East (Virginia)".to_string(),
    region: GeoRegion::NorthAmerica,
    primary_countries: vec!["US".into(), "CA".into()],
    upstream_pool: "us-east-pool".to_string(),
    weight: 100,
    enabled: true,
});

router.add_data_center(DataCenter {
    id: "eu-west-1".to_string(),
    name: "EU West (Ireland)".to_string(),
    region: GeoRegion::Europe,
    primary_countries: vec!["GB".into(), "DE".into(), "FR".into()],
    upstream_pool: "eu-west-pool".to_string(),
    weight: 100,
    enabled: true,
});

// Route a client from Germany
let pool = router.route("DE"); // → Some("eu-west-pool")

// Update health from periodic checks
router.update_health("us-east-1", true, 45.0);  // healthy, 45ms latency
router.update_health("eu-west-1", false, 600.0); // unhealthy, high latency

// German client now falls back to US East
let pool = router.route("DE"); // → Some("us-east-pool")
```

**Health integration:** The GSLB router tracks consecutive failures per DC. After `max_failures` consecutive failures or if latency exceeds `gslb_max_latency_ms`, the DC is marked unhealthy and traffic is rerouted.

**Implementation:** `src/gslb/mod.rs` — `GslbRouter`, `DataCenter`, `GeoRegion`, `GslbPolicy`, `country_to_region()`.

---

## Testing Guide

All test scripts live in `scripts/`. No external test framework is required for Rust tests; Python tests need `requests` and optionally `pytest` and `locust`.

---

### Rust Tests

```bash
# All 908 tests (682 unit + 226 integration)
cargo test

# Only unit tests
cargo test --lib

# Only integration tests
cargo test --test proxy_test

# Run a specific test
cargo test bandwidth::tests::test_bandwidth_warning_alert
```

---

### Start Test Backends

Before running integration tests against a live proxy, spin up two lightweight Python HTTP backends that match the default `phalanx.conf` upstream pool:

```bash
./scripts/start_test_backends.sh

# Backends started:
#   http://127.0.0.1:18081   (primary backend — echoes request info as JSON)
#   http://127.0.0.1:18082   (secondary backend)
#   ws://127.0.0.1:18083     (WebSocket echo)

# Stop all:
./scripts/start_test_backends.sh --stop
```

Special paths on each backend:

| Path | Behaviour |
|---|---|
| `/health` | Returns `{"status":"ok","backend":"backend-N"}` |
| `/slow` | Adds 500 ms artificial delay |
| `/error` | Always returns HTTP 500 |
| `/notfound` | Always returns HTTP 404 |
| `/*` | Echoes method, path, headers, body as JSON |

---

### Python Smoke Test

**Requirements:** none — uses only the Python 3 standard library.

A fast, dependency-free end-to-end gate suitable for post-deploy verification or CI smoke checks. Hits the proxy, the admin API, and verifies a per-request bandwidth counter actually moves.

```bash
# Defaults: proxy on :18080, admin on :9099
python3 scripts/smoke_test.py

# Custom endpoints + tighter latency budget (ms) for the proxied GET / response
PROXY=http://127.0.0.1:18080 ADMIN=http://127.0.0.1:9099 \
  LATENCY_BUDGET_MS=50 python3 scripts/smoke_test.py
```

**Checks performed:** proxy reachability, `x-proxy-by` identity header, single-request latency under budget, admin `/health`, admin `/metrics` is Prometheus-formatted, admin `/api/stats` returns JSON, bandwidth counters increment after generating traffic, unknown paths return a 4xx (not a crash).

Exit code is `0` on success, non-zero on the first failed check; one `[PASS]` / `[FAIL]` line is printed per check for easy `grep`-ing in CI.

---

### Python API Test Suite

**Requirements:** `pip install requests pytest`

```bash
# Run all tests against a live Phalanx instance
ADMIN=http://127.0.0.1:9099 PROXY=http://127.0.0.1:18080 \
  pytest scripts/test_api.py -v

# Run only one class
pytest scripts/test_api.py::TestBandwidth -v
pytest scripts/test_api.py::TestAlerts -v
pytest scripts/test_api.py::TestWaf -v
```

**Test coverage (80+ test cases across 15 classes):**

| Class | What is tested |
|---|---|
| `TestHealthMetrics` | `/health`, `/metrics`, `/api/stats`, dashboard HTML |
| `TestDiscovery` | Add/remove backend, upstreams detail field validation |
| `TestKeyval` | Set/get/delete/list/overwrite/TTL roundtrip |
| `TestWaf` | Ban/unban/list, multi-IP, strikes, attacks |
| `TestRateLimit` | Top-N IPs, n capped at 100, field presence |
| `TestCache` | Stats, purge-all/key/prefix |
| `TestBandwidth` | All 8 protocols present, field types, sorted order |
| `TestAlerts` | Shape, check trigger, field validation, level enum, newest-first ordering |
| `TestCluster` | Nodes shape, at-least-one-healthy assertion |
| `TestMl` | Log shape, mode update |
| `TestWebRtc` | Rooms endpoint, shape, bandwidth fields |
| `TestProxySmoke` | WAF SQLi/XSS → 403, rate-limit burst → 429 |
| `TestE2EBanFlow` | Full ban → verify → unban → verify cycle |
| `TestConcurrent` | 100 concurrent health / stats / bandwidth requests |

---

### Load Testing

#### Standalone (no extra dependencies)

```bash
# 50 virtual users for 30 seconds
python scripts/load_test.py --users=50 --duration=30

# 200 users for 2 minutes
python scripts/load_test.py --users=200 --duration=120
```

The standalone runner uses a weighted scenario mix:
- 40% proxy root GET
- 20% `/api` GET
- 10% static files
- 10% admin stats / bandwidth
- 5% WAF attack attempts (expect 403 — counted as a pass)
- 5% keyval writes
- Other admin reads

At the end it prints a full latency report (min/p50/p90/p99/max/stdev) and validates that all WAF attack requests returned 403.

#### Locust (recommended for high concurrency)

```bash
pip install locust

# Interactive UI at http://localhost:8089
locust -f scripts/load_test.py --host=http://127.0.0.1:18080

# Headless — 500 users, 20/s spawn rate, 60 s
locust -f scripts/load_test.py \
  --host=http://127.0.0.1:18080 \
  --users=500 --spawn-rate=20 --run-time=60s --headless \
  --csv=target/test-reports/locust
```

**Locust user classes:**

| Class | Behaviour |
|---|---|
| `ProxyUser` | GET /  /api  /static/*  POST /api/data |
| `WafAttackUser` | SQLi / XSS / path traversal — expects 403 |
| `AdminApiUser` | Dashboard polling: stats, bandwidth, alerts, bans |
| `KeyvalChurnUser` | Rapid keyval set/get/delete |
| `WafBanChurnUser` | Concurrent ban/unban cycles on a shared IP pool |

---

### Browser Test Pages

Open these HTML files directly in your browser (no server needed — they call the admin API via `fetch`):

#### `scripts/test_dashboard.html` — Full Feature Tester

- **20 automated tests** with pass/fail badges covering every admin endpoint
- Interactive panels for WAF (ban/unban + live attack simulation), keyval CRUD, cache purge, bandwidth chart, alert trigger, burst test, discovery add/remove
- Attack simulation buttons send SQLi / XSS / path traversal / CMDi payloads to the proxy and verify the WAF returns 403

```bash
open scripts/test_dashboard.html
# or: python3 -m http.server 8888 && open http://localhost:8888/scripts/test_dashboard.html
```

#### `scripts/test_webrtc.html` — WebRTC Test Suite

- **10 automated tests:** rooms endpoint, `getUserMedia`, `RTCPeerConnection`, publish SDP offer/answer, subscribe SDP offer/answer, ICE candidate, room listing, bandwidth counter increase
- Live video publisher + subscriber preview panels
- Real-time RTC stats: outbound/inbound bitrate (with bar gauges), packet loss, RTT, jitter
- Per-room bandwidth table showing `bytes_forwarded` and `packets_forwarded`
- Manual ICE candidate submission tool

```bash
open scripts/test_webrtc.html
```

---

### Bandwidth Monitor

Live terminal monitor that polls `/api/bandwidth` and renders per-protocol utilization bars alongside OS-level RX/TX rates:

```bash
# Default: Python live table, polls every 3 s
./scripts/monitor_bandwidth.sh

# Poll every 1 s on a specific interface
./scripts/monitor_bandwidth.sh --interval=1 --iface=en0

# Launch nload (must be installed: brew install nload)
./scripts/monitor_bandwidth.sh --nload

# Launch iftop filtered to proxy ports (must be installed)
./scripts/monitor_bandwidth.sh --iftop

# Launch nethogs (per-process, must be installed)
./scripts/monitor_bandwidth.sh --nethogs
```

The Python live table shows:

```
⚡ Phalanx Live Bandwidth Monitor  [14:22:05]  interval=3s  iface=lo
──────────────────────────────────────────────────────────────────────
OS Network (lo):
  RX:     12.4 Mbps  total: 1.2 GB
  TX:      9.8 Mbps  total: 0.9 GB

Protocol     Bytes In       Bytes Out          Total    Requests   Conns  Utilization
──────────────────────────────────────────────────────────────────────────────────────
  http1        512.0 MB        1.2 GB          1.7 GB       45231      12  ████████░░ 82.3%
  websocket     64.0 MB       64.0 MB        128.0 MB        3421       4  ██░░░░░░░░ 12.1%
  grpc           2.0 MB        8.0 MB         10.0 MB         891       2  ░░░░░░░░░░  1.0%
  ...

Resource Alerts: 1 total
  [WARNING ] http1       bandwidth      http1 cumulative traffic 1.7 GiB exceeds warning threshold
```

---

### Master Orchestrator

Runs the complete test suite in order and generates an HTML report:

```bash
# Full suite: cargo test → port checks → pytest → WAF curl → burst → load test
./scripts/run_tests.sh

# Skip the 30-second load test
./scripts/run_tests.sh --quick

# Load test only
./scripts/run_tests.sh --load-only

# Network monitoring reference
./scripts/run_tests.sh --monitor
```

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `ADMIN` | `http://127.0.0.1:9099` | Admin API base URL |
| `PROXY` | `http://127.0.0.1:18080` | Proxy base URL |
| `LOAD_USERS` | `50` | Concurrent users for load test |
| `LOAD_DURATION` | `30` | Load test duration in seconds |

HTML report is written to `target/test-reports/report_<timestamp>.html`.

---

## Full Configuration Reference

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

```nginx
# ============================================================
# Global
# ============================================================
worker_threads     4;
tcp_listen         5555;
admin_listen       127.0.0.1:9090;

http {
    # ============================================================
    # Upstream Pool
    # ============================================================
    upstream <name> {
        server <ip:port> [weight=N] [backup] [max_conns=N] [queue_size=N];
        algorithm  roundrobin | least_connections | ip_hash | random
                   | weighted_roundrobin | consistent_hash | least_time | ai;
        health_check        /health;
        health_check_status 200;
        max_fails           3;
        fail_timeout        30s;
        slow_start          10s;
        keepalive           32;
    }

    # ============================================================
    # Server Block
    # ============================================================
    server {
        listen         8080;

        # --- TLS ---
        ssl_certificate     /path/to/cert.pem;
        ssl_certificate_key /path/to/key.pem;
        tls_ca_cert_path    /path/to/ca.pem;

        # --- Auto-SSL (Let's Encrypt) ---
        auto_ssl_domain    example.com;
        auto_ssl_email     admin@example.com;
        auto_ssl_cache_dir /var/cache/phalanx/acme;

        # --- HTTP/3 (QUIC/UDP) ---
        listen_quic 0.0.0.0:8443;

        # --- UDP Stream Proxy ---
        listen_udp  0.0.0.0:5353;

        # --- Rate Limiting ---
        rate_limit_per_ip  50;
        rate_limit_burst   100;
        global_rate_limit  5000;

        # --- WAF ---
        waf_enabled             true;
        waf_auto_ban_threshold  15;
        waf_auto_ban_duration   3600;

        # --- AI Routing ---
        ai_algorithm             epsilon_greedy | ucb1 | softmax | thompson_sampling;
        ai_epsilon               0.10;
        ai_temperature           1.0;
        ai_ucb_constant          1.414;
        ai_thompson_threshold_ms 200.0;

        # --- Observability ---
        otel_endpoint     http://127.0.0.1:4317;
        otel_service_name phalanx;
        access_log        /var/log/phalanx/access.log;
        access_log_format json | combined | common;

        # --- Cluster / Distributed State ---
        redis_url        redis://127.0.0.1:6379;
        etcd_endpoints   http://127.0.0.1:2379;   # comma-separated; takes priority over redis_url
        node_id          phalanx-node-1;           # default: $HOSTNAME env var

        # --- ML Fraud Detection ---
        ml_fraud_model_path /etc/phalanx/fraud.onnx;
        ml_fraud_mode       shadow;                # shadow (log-only) | active (auto-ban)

        # --- CAPTCHA Bot Challenge ---
        captcha_site_key          10000000-ffff-ffff-ffff-000000000001;
        captcha_secret_key        0x0000000000000000000000000000000000000000;
        captcha_provider          hcaptcha;      # hcaptcha | turnstile | recaptcha
        captcha_challenge_threshold 5.0;         # req/s threshold for Unknown bots

        # --- Gossip Cluster State ---
        gossip_bind         0.0.0.0:7946;
        gossip_seed_peers   10.0.0.2:7946,10.0.0.3:7946;
        gossip_interval_ms  1000;

        # --- Proxy-Wasm Plugins ---
        wasm_plugin_config  /etc/phalanx/plugins.json;

        # --- Kubernetes Ingress Controller ---
        k8s_ingress_enabled true;
        k8s_ingress_class   phalanx;

        # --- Global Server Load Balancing ---
        gslb_policy         geographic;          # geographic | latency | weighted | geo_latency
        gslb_max_latency_ms 500;

        # --- OCSP Stapling ---
        ocsp_responder_url  http://ocsp.example.com/;

        # --- GeoIP ---
        geoip_db    /etc/phalanx/geoip.csv;
        geo_allow   US,CA,GB;
        geo_deny    CN,RU;

        # --- Trusted Proxies (one per line) ---
        trusted_proxy 10.0.0.0/8;
        trusted_proxy 172.16.0.0/12;
        trusted_proxy 192.168.0.0/16;

        # --- Caching ---
        cache_disk_path /var/cache/phalanx;

        # --- Compression ---
        brotli on;

        # --- PROXY Protocol v2 ---
        proxy_proto_v2 on;    # parse PP2 header from upstream load balancer

        # --- Scripting ---
        rhai_script /etc/phalanx/hooks.rhai;

        # --- Key-Value Store ---
        keyval_ttl_secs 3600;

        # --- Auth Request (server-wide) ---
        auth_request http://auth-service.internal/check;

        # ============================================================
        # Route Block
        # ============================================================
        route /path {
            upstream      <pool_name>;
            root          /var/www/html;

            fastcgi_pass  127.0.0.1:9000;
            uwsgi_pass    127.0.0.1:3030;

            add_header    <name> "<value>";

            rewrite       <regex> <replacement> [last|break|redirect|permanent];

            # --- Auth ---
            auth_basic            "realm";
            auth_basic_user       "user" "password_or_bcrypt";
            auth_jwt_secret       "secret";
            auth_jwt_algorithm    HS256;
            auth_oauth_introspect_url  http://oauth/introspect;
            auth_oauth_client_id       client-id;
            auth_oauth_client_secret   client-secret;
            auth_request          http://auth/check;

            # --- Caching ---
            proxy_cache       on;
            proxy_cache_valid 60;

            # --- Compression ---
            gzip            on;
            gzip_min_length 1024;
            brotli          on;

            # --- Traffic Shaping ---
            mirror <pool_name>;   # fire-and-forget shadow copy to this pool
        }
    }
}
```

**Global directives outside `http {}` block:**

```nginx
# ============================================================
# Global
# ============================================================
worker_threads 4;          # Tokio worker threads (default: 4)
tcp_listen     5555;       # Layer-4 TCP proxy port (default: 5000)
admin_listen   127.0.0.1:9090;  # Admin REST API bind address
```

---

## Admin API Reference

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

All endpoints require `Authorization: Bearer <token>` unless marked public.

#### Health & Metrics

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/health` | Public | Returns `OK` |
| `GET` | `/metrics` | Public | Prometheus exposition format |
| `GET` | `/dashboard` | Public | HTML admin dashboard (7 tabs) |
| `GET` | `/api/stats` | ReadOnly | JSON metrics snapshot (counters, gauge) |

#### Upstreams & Discovery

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/upstreams/detail` | ReadOnly | All upstream pool backends with health/conns/weight |
| `POST` | `/api/discovery/backends` | Operator | Register a backend `{"address":"…","pool":"…","weight":1}` |
| `DELETE` | `/api/discovery/backends/:pool/:addr` | Operator | Remove a backend |

#### Keyval Store

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/keyval` | ReadOnly | List all keyval entries |
| `GET` | `/api/keyval/:key` | ReadOnly | Get a single keyval entry |
| `POST` | `/api/keyval/:key` | Operator | Set `{"value":"…","ttl_secs":N}` |
| `DELETE` | `/api/keyval/:key` | Operator | Delete a keyval entry |

#### WAF & Security

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/waf/bans` | ReadOnly | List all banned IPs with strike count and expiry |
| `POST` | `/api/waf/ban/:ip` | Operator | Manually ban an IP immediately |
| `DELETE` | `/api/waf/ban/:ip` | Operator | Unban an IP (clear all strikes) |
| `GET` | `/api/waf/attacks` | ReadOnly | Last 50 WAF block events (newest first) |
| `GET` | `/api/waf/strikes` | ReadOnly | All tracked IPs with strike counts |

#### Rate Limiting

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/rates/top?n=10` | ReadOnly | Top N IPs by cumulative request count |

#### Cache

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/cache/stats` | ReadOnly | Cache entry count snapshot |
| `POST` | `/api/cache/purge` | Operator | Purge by `{"key":"…"}`, `{"prefix":"…"}`, or `{}` (all) |

#### Bandwidth Monitoring

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/bandwidth` | ReadOnly | Per-protocol snapshot sorted by total bytes desc |

Response:
```json
{
  "protocols": [
    { "protocol": "http1", "bytes_in": 0, "bytes_out": 0, "requests": 0, "active_connections": 0 }
  ]
}
```

#### Resource Alerts

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/alerts?n=50` | ReadOnly | Most recent N alerts (newest first, max 500) |
| `POST` | `/api/alerts/check` | Operator | Trigger an immediate threshold check cycle |

Response fields: `timestamp`, `level` (`info`/`warning`/`critical`), `category`, `protocol`, `metric`, `message`, `value`, `threshold`.

#### Cluster

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/cluster/nodes` | ReadOnly | Registered cluster nodes and their health |

#### ML Fraud Detection

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/api/ml/upload` | Admin | Upload ONNX fraud detection model |
| `GET` | `/api/ml/logs` | ReadOnly | View ML inference logs |
| `PUT` | `/api/ml/mode` | Admin | Switch ML mode (`shadow` / `active`) |

#### Dynamic Config

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/api/reload` | Admin | Trigger hot config reload (sends SIGHUP) |
| `POST` | `/api/routes` | Admin | Add a dynamic route |
| `GET` | `/api/routes` | ReadOnly | List dynamic routes |
| `DELETE` | `/api/routes/:path` | Admin | Delete a dynamic route |
| `POST` | `/api/ssl` | Admin | Add a TLS certificate |
| `GET` | `/api/ssl` | ReadOnly | List TLS certificates |
| `DELETE` | `/api/ssl/:server_name` | Admin | Remove a TLS certificate |

#### WebRTC Rooms

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/webrtc/rooms` | ReadOnly | Active rooms with track count, bytes/packets forwarded, publishers, subscribers |
| `POST` | `/api/webrtc/publish` | Public | Submit SDP offer to publish into a room — returns SDP answer |
| `POST` | `/api/webrtc/subscribe` | Public | Submit SDP offer to subscribe to a room — returns SDP answer |
| `POST` | `/api/webrtc/ice/:peer_id` | Public | Add trickle ICE candidate (`?room=<id>`) |

---

## License

```
Copyright 2024 Phalanx Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

### Third-Party Licenses

Phalanx depends on open-source crates. Major dependencies and their licenses:

| Crate | License |
|---|---|
| `tokio` | MIT |
| `hyper` | MIT |
| `rustls` | Apache-2.0 / ISC / MIT |
| `quinn` + `h3` | MIT / Apache-2.0 |
| `actix-web` | MIT / Apache-2.0 |
| `moka` | MIT / Apache-2.0 |
| `rocksdb` | Apache-2.0 |
| `prometheus` | Apache-2.0 |
| `opentelemetry` | Apache-2.0 |
| `tract-onnx` | MIT / Apache-2.0 |
| `rhai` | MIT / Apache-2.0 |
| `webrtc` | MIT |
| `redis` | BSD-3-Clause |
| `etcd-client` | Apache-2.0 |
| `governor` | MIT |
| `jsonwebtoken` | MIT |
| `regex` | MIT / Apache-2.0 |

A full dependency audit can be run with:
```bash
cargo deny check licenses
```
