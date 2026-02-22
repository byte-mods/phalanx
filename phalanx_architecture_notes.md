# Phalanx AI Load Balancer — Complete Architecture & Implementation Notes

> This document maps every feature in Phalanx to the **exact source file** that implements it.
> Read this to understand the entire system end-to-end.

---

## Table of Contents
1. [Startup & Configuration](#1-startup--configuration)
2. [Protocol Sniffing & Connection Mux](#2-protocol-sniffing--connection-mux)
3. [TLS/SSL Termination](#3-tlsssl-termination)
4. [HTTP Request Handling Pipeline](#4-http-request-handling-pipeline)
5. [Load Balancing Algorithms](#5-load-balancing-algorithms)
6. [AI Predictive Routing](#6-ai-predictive-routing)
7. [Active Health Checks](#7-active-health-checks)
8. [Rate Limiting & DDoS Mitigation](#8-rate-limiting--ddos-mitigation)
9. [Web Application Firewall (WAF)](#9-web-application-firewall-waf)
10. [Admin API & Telemetry](#10-admin-api--telemetry)
11. [Raw TCP Proxy](#11-raw-tcp-proxy)
12. [Configuration Reference (`phalanx.conf`)](#12-configuration-reference-phalanxconf)

---

## 1. Startup & Configuration

### `src/main.rs`
The entry point. It does **not** use `#[tokio::main]` because it needs to read the config file
synchronously *before* building the Tokio runtime — the config determines how many worker threads
the runtime should have.

**Boot sequence:**
1. `telemetry::init_telemetry()` → sets up `tracing` (structured logging).
2. `config::load_config()` → reads `phalanx.conf` from disk.
3. Builds a multi-threaded Tokio runtime with `cfg.workers` OS threads.
4. Inside the async block:
   - Creates `UpstreamManager` (backend pools + health checkers).
   - Creates `PhalanxRateLimiter` (token bucket from `governor` crate).
   - Creates `IpReputationManager` + `WafEngine` (WAF security layer).
   - Creates `EpsilonGreedyRouter` (AI routing engine).
   - Calls `proxy::tls::load_tls_acceptor()` to load TLS certificates (if configured).
   - Spawns the **Admin API** on a separate port.
   - Spawns the **Raw TCP Proxy** on its own port.
   - Starts the **Main Protocol Mux Proxy** on the primary HTTP port.

### `src/config/mod.rs`
Defines the `AppConfig` struct — the single source of truth for every configurable parameter:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `proxy_bind` | `String` | `0.0.0.0:8080` | Primary HTTP/HTTPS listener port |
| `tcp_bind` | `String` | `0.0.0.0:5000` | Dedicated raw TCP proxy port |
| `admin_bind` | `String` | `127.0.0.1:9090` | Admin API / health endpoint |
| `workers` | `usize` | `4` | Tokio green thread count |
| `tls_cert_path` | `Option<String>` | `None` | Path to PEM certificate |
| `tls_key_path` | `Option<String>` | `None` | Path to PEM private key |
| `rate_limit_per_ip_sec` | `Option<u32>` | `50` | Per-IP token refill rate (req/sec) |
| `rate_limit_burst` | `Option<u32>` | `100` | Per-IP instant burst capacity |
| `global_rate_limit_sec` | `Option<u32>` | `None` | Global DDoS panic-mode limit |
| `waf_enabled` | `Option<bool>` | `true` | Master WAF on/off switch |
| `waf_auto_ban_threshold` | `Option<u32>` | `15` | Strikes before auto-ban |
| `waf_auto_ban_duration` | `Option<u64>` | `3600` | Auto-ban duration in seconds |
| `ai_epsilon` | `Option<f64>` | `0.10` | Exploration rate for AI router |

### `src/config/parser.rs`
A **hand-written, recursive-descent parser** for Nginx-like syntax. It tokenizes the raw config
string and then builds an AST of `NginxConfig → HttpBlock → ServerBlock → RouteBlock`.

**Key design**: The `ServerBlock` contains a `directives: HashMap<String, String>` that captures
any generic `key value;` pairs (e.g., `waf_enabled true;`, `ai_epsilon 0.10;`). This means new
configuration parameters can be added to `phalanx.conf` without modifying the parser.

---

## 2. Protocol Sniffing & Connection Mux

### `src/proxy/router.rs`
The **Protocol Sniffer**. When a TCP connection arrives on the primary port, Phalanx reads the first
8 bytes without consuming them:

| Byte Pattern | Detected Protocol |
|---|---|
| `GET `, `POST `, `PUT `, `HEAD `, `DELETE `, `OPTIONS`, `PATCH ` | **HTTP/1.1** |
| `PRI * HT` (HTTP/2 preface) | **HTTP/2 / gRPC** |
| `0x16 0x03` (TLS ClientHello) | **TLS (HTTPS)** |
| Anything else | **Raw TCP** (dropped on HTTP port) |

### `src/proxy/mod.rs` — `PeekableStream`
Because the sniffer "consumes" bytes from the socket, those bytes are saved in a `BytesMut` buffer.
A `PeekableStream` struct wraps the original `TcpStream` and **replays** the saved bytes first,
then transparently yields new bytes. This means `hyper` (the HTTP library) sees the complete
request from the beginning as if nothing was consumed.

### `src/proxy/mod.rs` — `start_proxy()`
The main event loop. For each accepted connection:
1. Sniff the protocol.
2. Apply the global **Rate Limiter** check (drop connection if exceeded).
3. Wrap the socket in `PeekableStream`.
4. Route to the correct handler based on protocol:
   - `Protocol::Http1` → `handle_http_request()` via Hyper `http1::Builder`
   - `Protocol::Http2` → `handle_http2_request()` via Hyper `http2::Builder`
   - `Protocol::Tls` → TLS handshake, then ALPN negotiation to pick HTTP/1 or HTTP/2
   - `Protocol::UnknownTcp` → Connection dropped (wrong port)

---

## 3. TLS/SSL Termination

### `src/proxy/tls.rs` — `load_tls_acceptor()`
Loads certificates from the paths specified in `phalanx.conf`:
- Reads PEM certificate chain via `rustls_pemfile::certs()`
- Reads PEM private key via `rustls_pemfile::private_key()`
- Builds a `rustls::ServerConfig` with **no client auth** and ALPN support for both `h2` and `http/1.1`
- Wraps it in a `tokio_rustls::TlsAcceptor`

**ALPN Negotiation**: After the TLS handshake, Phalanx inspects `session.alpn_protocol()`:
- If `h2` → routes to `handle_http2_request()`
- Otherwise → routes to `handle_http_request()` (HTTP/1.1)

**To enable TLS in `phalanx.conf`:**
```
ssl_certificate     /etc/phalanx/certs/cert.pem;
ssl_certificate_key /etc/phalanx/certs/key.pem;
```

---

## 4. HTTP Request Handling Pipeline

### `src/proxy/mod.rs` — `handle_http_request()` / `handle_http2_request()`

Both handlers follow the exact same pipeline (HTTP/1.1 and HTTP/2 share the logic):

```
Client → [Rate Limiter] → [WAF Engine] → [Route Matching] → [Header Injection] → [Backend Selection] → [Proxy to Backend] → [AI Score Update] → Response
```

**Step-by-step:**
1. **WAF Inspection**: Extract client IP, URI path, query string, and User-Agent. Call `waf.inspect()`. If blocked → immediate `403 Forbidden`.
2. **Route Matching**: Match the request URI path against `phalanx.conf` route definitions (longest prefix match). Fall back to `/` if no specific match.
3. **Header Injection**: Inject `add_header` values from the matched route into the outgoing request.
4. **Backend Selection**: Look up the upstream pool, call `pool.get_next_backend()` with the chosen load balancing algorithm.
5. **Proxying**: Acquire an idle TCP connection from the keepalive pool (or open a new one), forward the full HTTP request via Hyper's client connector, and stream the response back.
6. **AI Feedback**: After the response is received, measure turnaround latency and whether it was a 5xx error. Call `ai_engine.update_score()` to train the model.

### 4.5 Static File Serving (Zero-Copy)
If a route block contains the `root` directive instead of `upstream` (e.g., `route /static { root /var/www/html; }`), Phalanx intercepts the request before proxying.
- It dynamically strips the route prefix from the request to sanitize the destination relative file path mapping natively into disk arrays avoiding Directory Traversal vulnerabilities. 
- It efficiently acts as a high-performance web server by leveraging `tokio::fs::File`, `tokio_util::io::ReaderStream` and `http_body_util::StreamBody` allowing continuous asynchronous chunking of native byte structures back to callers with virtually **zero memory allocations** equivalent to highly optimized servers like Nginx.

### 4.6 FastCGI & uWSGI Direct Proxying
Like Nginx, Phalanx can directly execute Python or PHP backends bypassing intermediate HTTP servers using `fastcgi_pass` and `uwsgi_pass` directives.
- **FastCGI** (`src/proxy/fastcgi.rs`): Uses the `fastcgi-client` crate to multiplex FastCGI params and data over a persistent TCP stream.
- **uWSGI** (`src/proxy/uwsgi.rs`): Implements native dictionary-based binary serialization of the WSGI environment variables into the specific uWSGI TCP packet format.
- Both endpoints stream response body chunks synchronously back to the client using chunked encoding, without buffering the entire payload in memory.

---

## 5. Load Balancing Algorithms

### `src/routing/mod.rs` — `UpstreamPool::get_next_backend()`

Six algorithms are implemented:

| Algorithm | Config Key | Logic |
|-----------|-----------|-------|
| **Round Robin** | `roundrobin` | Sequential rotation through healthy backends |
| **Weighted Round Robin** | `weightedroundrobin` | Backends receive traffic proportional to their `weight` |
| **Least Connections** | `leastconnections` | Routes to the backend with fewest active TCP sessions |
| **IP Hash** | `iphash` | Hashes the client IP so the same user always reaches the same backend (session affinity) |
| **Random** | `random` | Pseudo-random selection via nanosecond timestamp |
| **AI Predictive** | `aipredictive` | Delegates to the `EpsilonGreedyRouter` (see below) |

---

## 6. AI Predictive Routing

### `src/ai/mod.rs`

All AI algorithms implement the `AiRouter` trait, making them swappable at startup via `phalanx.conf`.
The `build_ai_router()` factory function constructs the right implementation based on config.

### Algorithm 1: Epsilon-Greedy (Default)
Classic multi-armed bandit. Exploits the best-known backend (1-ε)% of the time and explores
randomly ε% of the time. Simple, battle-tested, used at Netflix and AWS.

- **Training**: EWMA with α=0.2 blends new latency with historical scores.
- **Penalty**: 5xx errors add +10,000ms artificial latency penalty.
- **Config**: `ai_algorithm epsilon_greedy;` + `ai_epsilon 0.10;`

### Algorithm 2: UCB1 (Upper Confidence Bound)
Mathematically principled bandit from Auer et al. (2002) with **provably optimal regret bounds**.
Used at Google for experiment traffic allocation.

- **Core idea**: Selects the backend with the lowest `avg_score - C * sqrt(ln(N) / n_i)`. Under-explored
  backends get a bonus that shrinks as they receive more traffic.
- **Config**: `ai_algorithm ucb1;` + `ai_ucb_constant 2.0;`

### Algorithm 3: Softmax / Boltzmann
Creates a probability distribution over backends proportional to their quality. Unlike ε-Greedy
which explores uniformly, Softmax gives higher probability to near-optimal backends.
Used at LinkedIn and Twitter for canary deployments.

- **High τ (temperature)**: All backends equally likely (pure exploration)
- **Low τ**: Deterministically picks the best (pure exploitation)
- **Config**: `ai_algorithm softmax;` + `ai_temperature 1.0;`

### Algorithm 4: Thompson Sampling (Bayesian)
The **gold standard** for online exploration-exploitation. Each backend has a Beta(α, β) prior;
on each request, we sample from each distribution and pick the best.
Used at Microsoft (Bing Ads), Spotify, and Adobe.

- **Training**: Low-latency responses increase α (successes), high-latency/errors increase β (failures).
- **Decay**: 0.999 multiplicative decay prevents old data from dominating.
- **Config**: `ai_algorithm thompson_sampling;` + `ai_thompson_threshold_ms 100.0;`

---

## 7. Active Health Checks

### `src/routing/mod.rs` — `health_check_loop()`

A background Tokio task spawned per upstream pool. Every **5 seconds**, it:
1. Attempts a raw TCP `connect()` to each backend address.
2. If successful → marks `is_healthy = true`.
3. If connection refused/timeout → marks `is_healthy = false`.
4. Logs state transitions (UP → DOWN, DOWN → UP).

All load balancing algorithms automatically filter out unhealthy backends before making a selection.

---

## 8. Rate Limiting & DDoS Mitigation

### `src/middleware/ratelimit.rs` — `PhalanxRateLimiter`

Uses the `governor` crate for a high-performance token bucket.

**Two layers of protection:**
1. **Per-IP Limiter** (keyed by `IpAddr`): Each IP gets `rate_limit_burst` tokens instantly, refilling at `rate_limit_per_ip` tokens/second.
2. **Global DDoS Limiter** (optional): If `global_rate_limit` is set, it caps total requests across ALL clients to protect during attack scenarios.

**Enforcement point**: Inside `start_proxy()`, BEFORE protocol handling. If the rate limit is exceeded, the raw TCP connection is silently dropped — no HTTP response is generated, saving maximum CPU.

**Configuration in `phalanx.conf`:**
```
rate_limit_per_ip  50;
rate_limit_burst   100;
# global_rate_limit  10000;
```

---

## 9. Web Application Firewall (WAF)

The WAF is a modular, layered defense system living in `src/waf/`.

### `src/waf/mod.rs` — `WafEngine`
The orchestrator. Takes `enabled` flag and an `IpReputationManager`. Exposes `inspect()` which
runs three checks in order of cost (cheapest first):

```
Request → [1. IP Reputation] → [2. Bot Protection] → [3. OWASP Payload Rules] → Allow/Block
```

### `src/waf/reputation.rs` — `IpReputationManager`
A thread-safe `DashMap<String, u32>` that tracks **strike counts** per IP address.

| Action | Strike Penalty |
|--------|---------------|
| Generic payload violation (SQLi, XSS, etc.) | +3 strikes |
| Empty User-Agent | +1 strike |
| Known malicious bot User-Agent | +5 strikes |

When an IP's total strikes exceed `waf_auto_ban_threshold` (default: 15), every subsequent request
is immediately rejected with `403 Forbidden` — even benign ones.

### `src/waf/rules.rs` — `WafRules`
Pre-compiled `RegexSet` engines for each attack category. All regexes are compiled **once at startup**
and reused for every request (zero allocation on the hot path).

**OWASP Top 10 Coverage:**

| Category | Examples Blocked |
|----------|-----------------|
| **SQL Injection** | `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `--`, `%27` |
| **Cross-Site Scripting** | `<script>`, `onerror=`, `javascript:`, `document.cookie` |
| **Path Traversal / LFI / RFI** | `../`, `%2e%2e%2f`, `/etc/passwd`, `win.ini`, `http://evil.com?cmd=` |
| **OS Command Injection** | `; cat`, `| wget`, `` `bash` ``, `& curl` |
| **NoSQL Injection** | `$ne`, `$gt`, `$lt`, `$in`, `$nin` |

**Bot Protection** (`is_malicious_bot()`): Blocks scanners like `sqlmap`, `nikto`, `nmap`, `masscan`,
`dirbuster`, `acunetix`, `nuclei`, `python-requests`, `go-http-client`, and `java/`.

**Configuration in `phalanx.conf`:**
```
waf_enabled             true;    # Master switch (default: true)
waf_auto_ban_threshold  15;      # Strikes before auto-ban (default: 15)
waf_auto_ban_duration   3600;    # Ban duration in seconds (default: 3600)
```

---

## 10. Admin API & Telemetry

### `src/admin/mod.rs`
An **Actix-Web** server running on a separate port (default: `127.0.0.1:9090`).

| Endpoint | Response |
|----------|----------|
| `GET /health` | `200 OK` — used for external health probes (e.g., Kubernetes) |
| `GET /metrics` | Prometheus metrics stub (placeholder for future OpenTelemetry export) |

### `src/telemetry/mod.rs`
Initializes `tracing_subscriber` with:
- An `EnvFilter` (controllable via `RUST_LOG` environment variable).
- A formatted stdout layer for human-readable log output.

---

## 11. Raw TCP Proxy

### `src/proxy/tcp.rs` — `start_tcp_proxy()`
A **dedicated** TCP reverse proxy on a separate port (default: `0.0.0.0:5000`).

- Routes ALL connections to the `"default"` upstream pool.
- Uses `tokio::io::copy_bidirectional()` for zero-copy byte streaming.
- Tracks `active_connections` per backend for the `LeastConnections` algorithm.
- No WAF or HTTP inspection — it's a raw L4 proxy.

---

## 12. Configuration Reference (`phalanx.conf`)

```nginx
worker_threads 8;

http {
    server {
        listen 8080;

        # --- TLS / SSL ---
        # ssl_certificate     /etc/phalanx/certs/cert.pem;
        # ssl_certificate_key /etc/phalanx/certs/key.pem;

        # --- Rate Limiting ---
        rate_limit_per_ip  50;       # Requests per second per IP
        rate_limit_burst   100;      # Burst capacity per IP
        # global_rate_limit  10000;  # Global DDoS limit (all IPs combined)

        # --- WAF ---
        waf_enabled             true;
        waf_auto_ban_threshold  15;
        waf_auto_ban_duration   3600;

        # --- AI Routing ---
        # Options: epsilon_greedy | ucb1 | softmax | thompson_sampling
        ai_algorithm  epsilon_greedy;
        ai_epsilon    0.10;              # Epsilon-Greedy: exploration rate
        # ai_temperature  1.0;           # Softmax: temperature
        # ai_ucb_constant  2.0;          # UCB1: exploration constant
        # ai_thompson_threshold_ms  100; # Thompson: success threshold (ms)

        # --- Routes ---
        route /api {
            upstream default;
            add_header X-Proxy-By "Phalanx";
            add_header X-Powered-By "Rust";
        }

        route / {
            upstream default;
            add_header Cache-Control "no-cache";
        }
    }
}
```

---

## Module Map (Quick Reference)

| Module | File |  Purpose |
|--------|------|----------|
| **Entry Point** | `src/main.rs` | Boot sequence, runtime init |
| **Config** | `src/config/mod.rs` | `AppConfig` struct, `load_config()` |
| **Config Parser** | `src/config/parser.rs` | Nginx-syntax tokenizer & AST builder |
| **Protocol Sniffer** | `src/proxy/router.rs` | First-byte protocol detection |
| **HTTP Proxy** | `src/proxy/mod.rs` | HTTP/1.1 + HTTP/2 handlers, WAF integration |
| **TLS** | `src/proxy/tls.rs` | Certificate loading, ALPN negotiation |
| **TCP Proxy** | `src/proxy/tcp.rs` | Raw L4 bidirectional proxy |
| **Routing** | `src/routing/mod.rs` | `UpstreamPool`, `BackendNode`, health checks |
| **AI Router** | `src/ai/mod.rs` | Epsilon-Greedy RL engine |
| **Rate Limiter** | `src/middleware/ratelimit.rs` | Token bucket (governor crate) |
| **WAF Engine** | `src/waf/mod.rs` | Orchestrator: IP rep → Bot → OWASP rules |
| **WAF Rules** | `src/waf/rules.rs` | Compiled RegexSet for attack signatures |
| **IP Reputation** | `src/waf/reputation.rs` | DashMap strike counter & auto-ban |
| **Admin API** | `src/admin/mod.rs` | Actix-Web health/metrics endpoints |
| **Telemetry** | `src/telemetry/mod.rs` | Tracing subscriber init |
| **Discovery** | `src/discovery/mod.rs` | Service discovery stub (DNS/etcd) |
