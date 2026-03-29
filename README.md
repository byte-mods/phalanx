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

**Phalanx** is a high-performance, enterprise-grade reverse proxy and API gateway written in Rust. It is inspired by NGINX's configuration syntax but built from scratch with modern capabilities: AI-driven traffic routing, a built-in WAF with ONNX-based fraud detection, automatic TLS, WebRTC SFU, HTTP/3, distributed cluster state, and deep observability.

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
7. [Full Configuration Reference](#full-configuration-reference)
8. [Admin API Reference](#admin-api-reference)
9. [License](#license)

---

## What Is Built

Every item below is fully implemented and compiles:

| Category | Features |
|---|---|
| **Protocols** | HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, gRPC-Web, FastCGI, uWSGI, TCP, UDP, SMTP/IMAP/POP3, WebRTC SFU |
| **Load Balancing** | Round Robin, Least Connections, IP Hash, Random, Weighted, Consistent Hash, Least Time, AI Predictive (4 algorithms) |
| **TLS** | Static certificates, mTLS, ALPN, Auto-SSL via Let's Encrypt, OCSP stapling, hot reload |
| **WAF** | Signature rules (OWASP), IP reputation, bot detection, ONNX ML fraud detection |
| **Auth** | Basic, JWT (HS/RS/ES), OAuth 2.0 introspection, auth_request subrequest, OIDC RP, JWKS |
| **Caching** | L1 in-memory (Moka), L2 disk tier, stale-while-revalidate, Vary support, purge API |
| **Compression** | Gzip, Brotli |
| **Rate Limiting** | Per-IP token bucket, global DDoS panic mode, zone-based connection limits |
| **Routing** | Prefix routing, URL rewrite engine, static files |
| **Traffic Shaping** | Traffic mirroring/tee, consistent-hash splitting, sticky sessions |
| **Observability** | Prometheus metrics, OpenTelemetry OTLP traces, structured access logs, admin dashboard |
| **Cluster** | Redis pub/sub, etcd KV, shared sticky sessions, WAF ban synchronization |
| **Discovery** | DNS SRV records, RocksDB registry, etcd watch |
| **Scripting** | Rhai embedded script engine, compile-time hook plugins |
| **Admin** | REST API, RBAC (Admin/Operator/ReadOnly), dynamic routes & SSL certs, ML model upload |

---

## What Is Left (Roadmap)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

Three phases remain before Phalanx reaches full enterprise parity:

### Phase 1 — Edge Essentials

| Item | Status | Notes |
|---|---|---|
| **Active Health Checking** | Not yet implemented | Background tokio task sending GET /health or TCP ping to all backends on a configurable interval |
| **Circuit Breaker** | Not yet implemented | Exponential-backoff circuit breaker: trip to OPEN after X% failures in Y seconds, auto-recover |

### Phase 2 — Distributed Scale

| Item | Status | Notes |
|---|---|---|
| **Distributed Rate Limit via Redis** | Partial | Redis Lua ZSET script for global DDoS check exists; per-IP Redis sync is not wired |
| **Gossip-Based State** | Not yet implemented | Alternative to etcd/Redis for peer-to-peer cluster sync |

### Phase 3 — Ultimate Enterprise

| Item | Status | Notes |
|---|---|---|
| **Proxy-Wasm Extensibility** | Not yet implemented | Replace/augment Rhai with wasmtime + proxy-wasm ABI for Go/Rust/C++ plugins |
| **Kubernetes Ingress Controller** | Not yet implemented | `kube` crate watch loop translating Ingress/Gateway resources into RouteConfig |
| **Global Anycast / GSLB** | Not yet implemented | Geographic data-center routing based on GeoIP + health-check latency |

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

# Run tests
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

**How to configure:**

```nginx
server {
    listen 8080;

    waf_enabled             true;
    waf_auto_ban_threshold  15;     # strikes before IP is banned
    waf_auto_ban_duration   3600;   # ban duration in seconds (1 hour)
}
```

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

**How it works:** Phalanx checks `Accept-Encoding` in the request. If `br` is present, Brotli is preferred. If only `gzip`, gzip is used. The response is only returned compressed if the compressed size is smaller than the original.

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
# In AppConfig
udp_bind 0.0.0.0:5353;    # DNS proxy example
```

UDP sessions maintain per-client-address affinity. Each client gets its own ephemeral backend socket. Idle sessions are reaped after a configurable timeout.

---

### 18. Mail Proxy (SMTP / IMAP / POP3)

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Proxies SMTP, IMAP, and POP3 connections with optional custom banner injection and STARTTLS support.

**How to configure (in code — `MailProxyConfig`):**

```rust
MailProxyConfig {
    protocol: MailProtocol::Smtp,
    bind_addr: "0.0.0.0:2525".to_string(),
    upstream_pool: "mail_pool".to_string(),
    banner: Some("220 mail.example.com ESMTP Phalanx".to_string()),
    starttls: true,
}
```

**Runtime behavior:**
- A TCP listener is started for each configured mail protocol
- On connection, Phalanx selects a backend from the upstream pool
- If a custom `banner` is set, it is sent to the client instead of the backend's banner
- All subsequent bytes are relayed bidirectionally

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
route /api {
    upstream primary_pool;
    mirror shadow_pool;      # shadow copy sent here; response discarded
}
```

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
| `Cookie` | Phalanx sets a session cookie encoding the backend address; subsequent requests read this cookie |
| `Learn` | Phalanx learns the session→backend mapping from a response header set by the application |
| `Route` | Routes based on an existing session cookie value already in the request |

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

---

### 23. Real Client IP Extraction

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

**What it does:** Correctly determines the real client IP when Phalanx sits behind a load balancer or CDN, and injects standard forwarding headers.

**Resolution priority:**
1. `X-Real-IP` header
2. `X-Forwarded-For` — rightmost IP not in the trusted proxy CIDR list
3. HAProxy PROXY protocol v1 source address
4. TCP socket peer address (fallback)

**How to configure:**

```nginx
server {
    listen 8080;
    trusted_proxies 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16;

    route / {
        upstream backend_pool;
    }
}
```

**Headers injected by Phalanx to upstreams:**
- `X-Forwarded-For: <real-client-ip>, <proxy-ip>`
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

**How to use (in code — `ZoneLimiter`):**
```rust
let limiter = ZoneLimiter::new(100);  // max 100 concurrent connections per key
limiter.acquire_connection(&zone_key)?;
// ... handle request ...
limiter.release_connection(&zone_key);
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
}
```

With Redis configured:
- WAF IP bans are broadcast to all nodes within milliseconds
- Sticky session mappings are shared (cross-node affinity)
- Keyval store entries are replicated

**etcd setup (in code):**
```rust
ClusterConfig {
    backend: ClusterBackend::Etcd,
    etcd_endpoints: vec!["http://etcd:2379".into()],
    node_id: "node-1".into(),
}
```

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

        # --- HTTP/3 ---
        listen_quic 0.0.0.0:8443;

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
        redis_url redis://127.0.0.1:6379;

        # --- GeoIP ---
        geoip_db    /etc/phalanx/geoip.csv;
        geo_allow   US,CA,GB;
        geo_deny    CN,RU;

        # --- Trusted Proxies ---
        trusted_proxies 10.0.0.0/8 172.16.0.0/12;

        # --- Caching ---
        cache_disk_path /var/cache/phalanx;

        # --- Compression ---
        brotli on;

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
            mirror <pool_name>;
        }
    }
}
```

---

## Admin API Reference

```
Copyright 2024 Phalanx Contributors
Licensed under the Apache License, Version 2.0
```

All endpoints require `Authorization: Bearer <token>` unless marked public.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/health` | Public | Returns `{"status":"ok"}` |
| `GET` | `/metrics` | Public | Prometheus exposition format |
| `GET` | `/dashboard` | Public | HTML admin dashboard |
| `GET` | `/api/stats` | ReadOnly | JSON metrics snapshot |
| `GET` | `/api/upstreams/detail` | ReadOnly | All upstream pool backends |
| `GET` | `/api/keyval` | ReadOnly | List all keyval entries |
| `GET` | `/api/keyval/:key` | ReadOnly | Get a single keyval entry |
| `POST` | `/api/keyval/:key` | Operator | Set a keyval entry (body: `{"value":"...","ttl_secs":N}`) |
| `DELETE` | `/api/keyval/:key` | Operator | Delete a keyval entry |
| `POST` | `/api/discovery/backends` | Operator | Register a backend |
| `DELETE` | `/api/discovery/backends/:pool/:addr` | Operator | Remove a backend |
| `POST` | `/api/cache/purge` | Operator | Purge cache by key or prefix |
| `POST` | `/api/reload` | Admin | Trigger hot config reload |
| `POST` | `/api/routes` | Admin | Add a dynamic route |
| `GET` | `/api/routes` | ReadOnly | List dynamic routes |
| `DELETE` | `/api/routes/:path` | Admin | Delete a dynamic route |
| `POST` | `/api/ssl` | Admin | Add a TLS certificate |
| `GET` | `/api/ssl` | ReadOnly | List TLS certificates |
| `DELETE` | `/api/ssl/:server_name` | Admin | Remove a TLS certificate |
| `POST` | `/api/ml/upload` | Admin | Upload ONNX fraud detection model |
| `GET` | `/api/ml/logs` | ReadOnly | View ML inference logs |
| `PUT` | `/api/ml/mode` | Admin | Switch ML mode (`shadow`/`active`) |

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
