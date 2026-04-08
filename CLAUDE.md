# Phalanx

Enterprise-grade reverse proxy and API gateway written in Rust (~29,500 lines across 70+ source files). NGINX-inspired config syntax, built from scratch with AI-driven routing, WAF with ML fraud detection, HTTP/3, WebRTC SFU, GSLB, Kubernetes ingress, and distributed clustering.

## Quick Reference

- **Build**: `cargo build`
- **Run**: `cargo run -- phalanx.conf` (defaults to `phalanx.conf` if omitted)
- **Test**: `cargo test` (771 total tests, all passing)
- **Config policy**: Set `PHALANX_CONFIG_POLICY=strict` env var for fail-closed config parsing (default: lenient)
- **Edition**: Rust 2024 (experimental)
- **Package name**: `ai_load_balancer` (in Cargo.toml)

## Architecture Overview

### Design Principles

1. **Single-binary deployment** — all features compile into one binary, optional via config
2. **Zero-downtime reload** — SIGHUP atomically swaps config, TLS certs, upstream pools via `ArcSwap`
3. **Protocol multiplexing** — single TCP port sniffs HTTP/1, HTTP/2, and TLS via first 8 bytes; HTTP/3 on separate UDP port
4. **Pluggable everything** — auth, routing, WAF, compression, scripting are all modular and opt-in
5. **Lock-free hot path** — `ArcSwap` for config, `DashMap` for concurrent maps, atomics for per-backend counters; no Mutex on the request path

### Startup Flow (src/main.rs, 1213 lines)

`main()` is synchronous — parses config before building the Tokio runtime so `worker_threads` can be configured.

1. **Config parse** — `config::try_load_config()` reads NGINX-style `phalanx.conf`
2. **Telemetry init** — `telemetry::init_telemetry()` sets up tracing + optional OTLP exporter
3. **Tokio runtime** — `Builder::new_multi_thread().worker_threads(N)` from config
4. **Async init block** — creates all subsystems in dependency order:
   - TLS acceptor → Service discovery → Upstream manager → SIGHUP reload handler
   - Prometheus metrics → Keyval store → Response cache → Access logger
   - Rate limiter → WAF engine (reputation + policy + keyval) → CAPTCHA manager
   - DNS SRV watchers → AI routing engine → Bandwidth tracker → Alert engine
   - GeoIP database → GSLB router → K8s Ingress controller
   - Rhai hook engine → Wasm plugin manager → Sticky sessions → Zone limiter
   - OIDC session store → Cluster state (gossip/etcd/Redis) → OCSP stapling → ML fraud engine
5. **Supervisor spawn** — 8 supervised listeners with auto-restart + exponential backoff:
   - `supervise_proxy_listener` — HTTP/1+2 mux (main proxy)
   - `supervise_admin_listener` — Actix-web admin API
   - `supervise_tcp_listener` — raw TCP proxy
   - `supervise_udp_listener` — UDP proxy
   - `supervise_mail_listener` ×3 — SMTP, IMAP, POP3
   - `supervise_http3_listener` — HTTP/3 QUIC
6. **Graceful shutdown** — `CancellationToken` propagates Ctrl+C / SIGTERM to all tasks

Each supervisor watches a `watch::Receiver<Arc<AppConfig>>` channel. On config change, if the bind address changed, it stops the old listener and starts a new one. If a listener crashes, it restarts with `listener_restart_backoff()` (1s, 2s, 4s, ... capped at 32s).

### Architecture Diagram

```
                        ┌────────────────────────────────────────────────────┐
                        │               phalanx.conf                        │
                        │         (NGINX-style block syntax)                │
                        └───────────────────┬────────────────────────────────┘
                                            │ parse (tokenize → recursive descent)
                                            ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                     AppConfig (Arc<ArcSwap<AppConfig>>)                          │
│                 lock-free atomic swap on SIGHUP reload                           │
└──────┬────────────────────────┬──────────────────────┬────────────────────────────┘
       │                        │                      │
       ▼                        ▼                      ▼
┌──────────────┐   ┌────────────────────┐   ┌────────────────────────────┐
│ 8 Supervised │   │ UpstreamManager    │   │  22 Arc<T> Subsystems      │
│ Listeners    │   │ (pool→BackendNode  │   │  WAF, cache, AI, auth,     │
│ (auto-restart│   │  + health checks   │   │  geo, GSLB, K8s, Wasm,    │
│  + backoff)  │   │  + circuit breaker)│   │  scripting, cluster, ...   │
└──────────────┘   └────────────────────┘   └────────────────────────────┘

Task Hierarchy:
main() [sync]
├── tokio runtime (N worker threads from config)
│   ├── shutdown_signal() — Ctrl+C / SIGTERM
│   ├── reload_handler() — SIGHUP → config swap
│   ├── cluster heartbeat, alert engine, OCSP refresh
│   ├── supervise_proxy_listener()    → proxy::start_proxy() → per-request tasks
│   ├── supervise_admin_listener()    → actix-web admin API
│   ├── supervise_tcp_listener()      → TCP L4 proxy
│   ├── supervise_udp_listener()      → UDP L4 proxy
│   ├── supervise_mail_listener() ×3  → SMTP/IMAP/POP3
│   └── supervise_http3_listener()    → QUIC HTTP/3
```

### Concurrency Model

- **Per-connection task** — each TCP accept spawns a Tokio task with cloned Arcs (22 parameters)
- **State sharing** — `Arc<ArcSwap<AppConfig>>` for config; `Arc<T>` for everything else
- **Backend health** — `AtomicBool` (is_healthy), `AtomicU32` (fail_count), `AtomicU64` (timestamps), `AtomicU8` (circuit state)
- **No global Mutex** — `DashMap` for keyval, sticky sessions, OIDC sessions, rate counters

#### Concurrency Primitives Reference

| Primitive | Usage | Hot Path? |
|-----------|-------|-----------|
| `Arc<ArcSwap<T>>` | Config, TLS acceptor — lock-free atomic swap | ✅ |
| `DashMap` | Keyval, sticky sessions, rate counters, OIDC sessions, AI state | ✅ |
| `AtomicBool/U32/U64/U8` | Backend health, fail counts, circuit state, connection counts | ✅ |
| `tokio::sync::Notify` | Connection queue wakeup when backend slot opens | ✅ |
| `watch::channel` | Config broadcast to supervisors | ❌ (control) |
| `CancellationToken` | Hierarchical shutdown propagation | ❌ (lifecycle) |
| `parking_lot::RwLock` | Gossip state (infrequent writes) | ❌ (background) |
| `tokio::sync::Mutex` | Cache thundering-herd protection (per-key) | ⚠️ (miss path) |

#### The 22 Supervisor Parameters

Every `supervise_proxy_listener` call clones these 22 `Arc`s into the proxy task:

1. `app_config: Arc<ArcSwap<AppConfig>>` 2. `upstreams: Arc<UpstreamManager>` 3. `tls_acceptor: Arc<ArcSwap<Option<TlsAcceptor>>>` 4. `waf: Arc<WafEngine>` 5. `rate_limiter: Arc<PhalanxRateLimiter>` 6. `ai_engine: Arc<dyn AiRouter>` 7. `cache: Arc<AdvancedCache>` 8. `hook_engine: Arc<HookEngine>` 9. `metrics: Arc<ProxyMetrics>` 10. `access_logger: Arc<AccessLogger>` 11. `geo_db: Arc<Option<GeoIpDatabase>>` 12. `geo_policy: Arc<GeoPolicy>` 13. `sticky: Arc<Option<StickySessionManager>>` 14. `zone_limiter: Arc<ZoneLimiter>` 15. `captcha_manager: Arc<Option<CaptchaManager>>` 16. `wasm_plugins: Arc<WasmPluginManager>` 17. `gslb_router: Arc<Option<GslbRouter>>` 18. `k8s_controller: Arc<Option<IngressController>>` 19. `bandwidth: Arc<BandwidthTracker>` 20. `oidc_sessions: OidcSessionStore` 21. `shutdown: CancellationToken` 22. `config_rx: watch::Receiver<Arc<AppConfig>>`

#### SIGHUP Reload Scope

What gets reloaded on SIGHUP (via `spawn_reload_handler()`):
- ✅ AppConfig (ArcSwap swap)
- ✅ TLS certificates (reload from disk)
- ✅ Upstream pools (3-way diff: add/update/remove)
- ✅ Bind addresses (supervisor restarts listener)
- ✅ Rate limiter (per-IP rate, burst, global rate from new config)
- ✅ WAF rules + policy (RegexSet recompiled, policy file re-read)
- ✅ GeoIP database (CSV re-read, lookup cache cleared)
- ✅ Hook engine / Rhai scripts (script file re-read and re-registered)
- ✅ Zone limiter (rate/burst/max-connections from config)
- ✅ GSLB router (data center list preserved, health state kept)
- ❌ AI router algorithm/params
- ❌ CAPTCHA provider config
- ❌ Wasm plugins
- ❌ K8s ingress class
- ❌ ML fraud model
- ❌ Worker thread count

---

## File-by-File Reference

### Core: `src/lib.rs` (69 lines)

Crate root. Declares all 19 public modules with doc comments. No logic.

### Core: `src/main.rs` (1213 lines)

| Function | Lines | Purpose |
|----------|-------|---------|
| `main()` | 16-501 | Synchronous entry: config parse, telemetry, runtime build, async init block, supervisor spawn |
| `supervise_proxy_listener()` | 527-611 | Manages HTTP/1+2 mux lifecycle. Accepts 22 Arc params, creates `start` closure that calls `proxy::start_proxy()`. Watches config for bind-address changes. |
| `supervise_admin_listener()` | 613-691 | Manages admin API lifecycle. Restarts on crash or bind change. |
| `supervise_tcp_listener()` | 693-771 | Manages raw TCP proxy. Optional (skips if `tcp_bind` not set). |
| `supervise_udp_listener()` | 773-853 | Manages UDP proxy. Optional (skips if `udp_bind` not set). |
| `supervise_mail_listener()` | 855-958 | Generic mail proxy supervisor. Parameterized by `MailProtocol` enum (SMTP/IMAP/POP3). |
| `supervise_http3_listener()` | 960-1076 | Manages HTTP/3 QUIC listener. Optional (skips if `quic_bind` not set). |
| `shutdown_signal()` | 1078-1106 | Waits for Ctrl+C or SIGTERM (Unix-only SIGTERM handler). |
| `listener_restart_backoff()` | 478-481 | Exponential backoff: `1 << min(attempt, 5)` seconds, capped at 32s. |
| `RunningListener` | 462-476 | Struct wrapping a `JoinHandle` + `CancellationToken` for clean stop/join. |

### Core: `src/reload.rs` (78 lines)

| Function | Purpose |
|----------|---------|
| `spawn_reload_handler()` | Spawns Unix SIGHUP listener. On signal: re-parses config, swaps `ArcSwap`, reloads TLS acceptor, rebuilds upstream pools, broadcasts via `watch::Sender`. |

---

### `src/proxy/` — Core Proxy Engine (19 files, ~7500 lines)

#### `mod.rs` (3078 lines) — Main multiplexer and request handlers

| Item | Lines | Purpose |
|------|-------|---------|
| `PeekableStream` | 61-101 | Wraps `TcpStream` to replay bytes consumed by protocol sniffing. Implements `AsyncRead` (serves buffered bytes first, then underlying stream) and `AsyncWrite` (passthrough). |
| `empty_response()` | 113-122 | Returns an empty HTTP response with given status code. Used for 502/503/404 error pages. |
| `rate_limit_response()` | 134-147 | Returns 429 Too Many Requests with `Retry-After: 60` header. |
| `html_response()` | 149-162 | Returns HTML body with `text/html; charset=utf-8` content type. Used for CAPTCHA challenge pages. |
| `decode_form_component()` | 165-196 | URL-decodes a string: `%XX` → byte, `+` → space. Used by CAPTCHA form handler. |
| `parse_urlencoded_form()` | 198-211 | Splits `key=value&key2=value2` form body into HashMap. |
| `build_return_to()` | 213-219 | Constructs return URL from path + optional query string for CAPTCHA redirect. |
| `handle_captcha_verify_request()` | 221-268 | POST handler for `/__phalanx/captcha/verify`. Extracts token + nonce from form, validates via CaptchaManager, redirects on success. |
| `start_proxy()` | 269-639 | **Main multiplexer.** Binds TCP listener, accepts connections, per-connection: reads PROXY Protocol v2 header (optional), sniffs protocol (8 bytes), rate-limits, dispatches to HTTP/1, HTTP/2, or TLS handler. 22 Arc parameters threaded through. |
| `is_websocket_upgrade()` | 669-688 | Checks `Upgrade: websocket` + `Connection: upgrade` headers. |
| `handle_http_request()` | 703-1895 | **HTTP/1 handler.** 29-step pipeline (see Architecture section). 1192 lines. |
| `handle_http2_request()` | 1899-2719 | **HTTP/2 handler.** Similar pipeline minus WebSocket, gRPC-Web translation, mirror. |
| `generate_trace_context_ids()` | 2721-2730 | Generates random 16-byte trace ID + 8-byte span ID for W3C Trace Context. |
| `chrono_timestamp()` | 2733-2739 | Returns ISO 8601 timestamp string for access logs. |
| `sanitize_path()` | 2742-2763 | Prevents directory traversal: resolves `..` via `canonicalize()`, verifies result is under root. |
| `serve_static_file()` | 2766-2906 | Serves files from disk with `Content-Type` guessing, `Content-Length`, `Last-Modified`, and streaming via `ReaderStream`. |

#### `router.rs` (66 lines) — Protocol sniffer

| Item | Purpose |
|------|---------|
| `Protocol` enum | `Http1`, `Http2`, `Tls`, `UnknownTcp` |
| `sniff_protocol()` | Reads first 8 bytes: HTTP/2 preface (`PRI * HT`), TLS handshake (`0x16 0x03`), HTTP methods (GET/POST/...), else UnknownTcp. Returns protocol + consumed bytes for replay. |

#### `executor.rs` (15 lines)

`TokioExecutor` — bridges Hyper's `Executor` trait to `tokio::spawn()`.

#### `pool.rs` (95 lines) — Connection keepalive

| Item | Purpose |
|------|---------|
| `ConnectionPool` | Per-backend idle connection queue. `acquire()` pops from queue or opens new TCP connection. `release()` pushes back if below `max_idle`. |

#### `tls.rs` (174 lines) — TLS management

| Function | Purpose |
|----------|---------|
| `build_server_config()` | Constructs `rustls::ServerConfig` from cert + key files, optional client CA for mTLS, ALPN [h2, http/1.1]. `pub(crate)` — also used by mail STARTTLS. |
| `load_tls_acceptor()` | Startup: tries ACME (Let's Encrypt) first, falls back to static certs, returns `Option<TlsAcceptor>`. ACME background worker retries with exponential backoff (1s→5min cap) on errors and warns if event stream ends. |
| `reload_tls_acceptor()` | SIGHUP: reloads certs from disk, keeps existing acceptor on failure. |

#### `http3.rs` (794 lines) — HTTP/3 QUIC server

| Function | Purpose |
|----------|---------|
| `start_http3_proxy()` | Binds UDP socket, creates QUIC endpoint via Quinn, accepts H3 connections. Per-connection: processes requests through WAF/geo/cache/captcha pipeline (subset of HTTP/1 pipeline). |
| `serve_h3_connection()` | Handles one HTTP/3 connection: reads request frames, forwards to upstream via HTTP/1.1, sends response back over H3. |
| `handle_h3_request()` | 13-step request processing: real IP, captcha, WAF, geo, rewrite, route match, auth (Basic/JWT), cache, backend selection, forwarding, compression, caching, access log. **Parity gap**: missing zone limits, gRPC-Web, WebSocket, Wasm hooks, scripting hooks, sticky sessions, traffic mirroring, ML fraud, connection pooling, Prometheus metrics vs HTTP/1's 29 steps. |

#### `rewrite.rs` (385 lines) — URL rewriting engine

| Item | Purpose |
|------|---------|
| `RewriteRule` | Compiled regex pattern + replacement + flag (Break/Last/Redirect/Permanent). |
| `compile_rules()` | Validates and compiles `(pattern, replacement, flag)` tuples from config. |
| `apply_rewrites()` | Sequential rule evaluation. Returns `NoMatch`, `Rewritten{new_uri, restart_routing}`, or `Redirect{status, location}`. |
| `nginx_to_regex_replacement()` | Converts NGINX `$1` capture syntax to regex `${1}`. |

#### `sticky.rs` (277 lines) — Session affinity

| Item | Purpose |
|------|---------|
| `StickyMode` | `Cookie{name, path, ...}`, `Learn{timeout_secs}`, `Route` |
| `StickySessionManager` | DashMap-backed session → backend mapping. `lookup()` returns cached backend (respects Learn timeout). `learn()` records new mapping. `set_cookie_header()` generates Set-Cookie. |

#### `realip.rs` (246 lines) — Real client IP

| Item | Purpose |
|------|---------|
| `TrustedProxies` | List of CIDR ranges. `is_trusted(ip)` checks membership. |
| `resolve_client_ip()` | Priority: X-Real-IP → rightmost untrusted in X-Forwarded-For → socket address. Only inspects headers if direct connection is from trusted proxy. |
| `inject_forwarding_headers()` | Adds/appends X-Forwarded-For, X-Forwarded-Proto, X-Real-IP. |

#### `proxy_proto_v2.rs` (356 lines) — HAProxy PROXY Protocol v2

| Function | Purpose |
|----------|---------|
| `parse_v2_header()` | Parses binary PP2 header (magic signature `\r\n\r\n\x00\r\nQUIT\n`). Extracts real client IP/port for load balancers sitting in front of Phalanx. Returns parsed struct + bytes consumed. |

#### `grpc_web.rs` (232 lines) — gRPC-Web gateway

| Function | Purpose |
|----------|---------|
| `is_grpc_web()` | Detects `application/grpc-web*` content type. |
| `translate_request()` | Rewrites content-type to `application/grpc`, adds `TE: trailers`. |
| `translate_response()` | Converts gRPC response back to gRPC-Web format, handles base64 text variant. |
| `cors_preflight_response()` | Returns 204 with CORS headers for OPTIONS requests. |

#### `fastcgi.rs` (207 lines), `uwsgi.rs` (228 lines)

Protocol translators for PHP-FPM (FastCGI) and Python WSGI (uWSGI). Both: connect TCP to backend, encode HTTP request into protocol-specific format (CGI params), parse CGI response headers + body.

#### `tcp.rs` (122 lines), `udp.rs` (208 lines)

Layer 4 proxies. TCP uses zero-copy splice on Linux. UDP maintains per-client sessions with 60s timeout + reaper task.

#### `mirror.rs` (142 lines) — Traffic shadowing

| Function | Purpose |
|----------|---------|
| `mirror_request()` | Fire-and-forget: clones request to shadow pool via `reqwest` (5s timeout). Response discarded. |
| `split_traffic()` | Deterministic weighted split via consistent hashing. Returns pool index for canary/A-B testing. |

#### `webrtc.rs` (575 lines) — WebRTC SFU

`SfuState` manages rooms (`DashMap<String, SfuRoom>`). Each room has publishers and subscribers. Media tracks forwarded via RTP relay. HTTP signaling endpoints for publish/subscribe.

#### `ocsp.rs` (205 lines), `zero_copy.rs` (125 lines)

OCSP: periodic fetch of certificate revocation status, cached with validity period. Zero-copy: Linux `splice()` syscalls for TCP proxy, fallback `tokio::io::copy_bidirectional`.

---

### `src/config/` — Configuration (2 files, ~2180 lines)

#### `mod.rs` (1052 lines) — Config structs

| Struct | Purpose | Key Fields |
|--------|---------|------------|
| `ConfigParsePolicy` | Strict (fail on error) vs Lenient (fall back to defaults) | Controlled by `PHALANX_CONFIG_POLICY` env var |
| `LoadBalancingAlgorithm` | 8 variants: RoundRobin, LeastConnections, IpHash, Random, WeightedRoundRobin, AIPredictive, ConsistentHash, LeastTime | |
| `BackendConfig` | Single backend server | address, weight, health_check_path/status, max_fails, fail_timeout_secs, slow_start_secs, backup, max_conns, queue_size, queue_timeout_ms, circuit_breaker + backoff settings |
| `UpstreamPoolConfig` | Pool of backends | algorithm, backends[], keepalive, srv_discover |
| `RouteConfig` | Path → handler mapping | upstream, root, fastcgi_pass, uwsgi_pass, add_headers, rewrite_rules, auth_* (Basic/JWT/OAuth/JWKS/OIDC/auth_request), gzip, brotli, proxy_cache, mirror_pool |
| `AppConfig` | Top-level config | proxy_bind, tcp_bind, admin_bind, workers, upstreams{}, routes{}, TLS paths, rate limits, WAF settings, AI params, QUIC bind, geo/GSLB/K8s/gossip/CAPTCHA/Wasm/ML fraud settings |
| `try_load_config()` | Parses config file, overlays onto `AppConfig::default()`. In Lenient mode, returns defaults on failure. |

#### `parser.rs` (1128 lines) — NGINX-style parser

Two-phase: `tokenize()` (lexical) → recursive descent parser. AST structs: `PhalanxConfig` → `HttpBlock` → `ServerBlock` → `RouteBlock` / `UpstreamBlock`. Handles quoted strings, comments (`#`), semicolons, brace nesting.

| Function | Purpose |
|----------|---------|
| `tokenize()` | Splits input into tokens respecting quotes and `#` comments |
| `parse_phalanx_config()` | Top-level: worker_threads, tcp_listen, admin_listen, http block |
| `parse_http_block()` | Parses upstream and server sub-blocks |
| `parse_server_block()` | Parses listen, rate limits, WAF, AI, route, and global directives |
| `parse_route_block()` | Parses per-route: upstream, root, auth, cache, compression, rewrite rules |
| `parse_upstream_block()` | Parses server entries with weight/health/circuit-breaker options |

---

### `src/routing/mod.rs` (1091 lines) — Upstream Management

| Item | Purpose |
|------|---------|
| `BackendNode` | Single backend with atomic health state. Fields: `config`, `active_connections` (AtomicUsize), `is_healthy` (AtomicBool), `fail_count`/`last_fail_at`, `recovery_time` (slow-start), `circuit_state`/`circuit_open_at`/`circuit_backoff_secs`. |
| `BackendNode::record_failure()` | Passive health: increments fail_count within fail_timeout window. Marks DOWN + trips circuit if count >= max_fails. |
| `BackendNode::trip_circuit()` | CLOSED→OPEN: sets initial backoff. HALF_OPEN→OPEN: doubles backoff (capped at max). |
| `BackendNode::record_circuit_success()` | HALF_OPEN→CLOSED: resets backoff. |
| `BackendNode::effective_weight()` | During slow-start: linearly ramps weight from 1 → full over `slow_start_secs`. |
| `UpstreamPool` | Collection of BackendNodes. `get_next_backend()` dispatches to algorithm. Filters unhealthy + circuit-open + max_conns-exceeded backends. Tries primary backends first, then backups. `get_next_backend_queued()` waits up to `queue_timeout_ms` when all backends are at `max_conns` and `queue_size > 0`. `notify_queue()` wakes waiters when a slot frees. |
| **LB algorithms** (inline in `get_next_backend`): | |
| — RoundRobin | Atomic counter mod healthy_count |
| — LeastConnections | Min `active_connections.load()` |
| — IpHash | FNV hash of client IP → consistent backend |
| — Random | `rand::rng().random_range(0..n)` |
| — WeightedRoundRobin | Cumulative weight scan with atomic counter |
| — AIPredictive | Delegates to `AiRouter::predict_best_backend()` |
| — ConsistentHash | 150 virtual nodes per backend on hash ring, binary search |
| — LeastTime | Composite: `active_connections * 1000 + recent_latency_ms` |
| `UpstreamManager` | HashMap of pool_name → UpstreamPool. `reload_from_config()` does 3-way diff: add new pools, update existing, remove deleted. |
| `health_check_loop()` | Spawned per pool. Every 5s: TCP connect (or HTTP GET if health_check_path set). On failure: marks DOWN, trips circuit. On recovery: marks UP, records recovery_time for slow-start. |

#### Circuit Breaker State Machine

```
CLOSED ──[fail_count >= max_fails]──> OPEN
  ↑                                     │
  │                                     │ (backoff timer expires)
  │                                     ▼
  └────[probe succeeds]──── HALF_OPEN ──[probe fails]──> OPEN (backoff doubles)
```

- **CLOSED**: Normal. Passive health counts failures within `fail_timeout_secs` window.
- **OPEN**: All requests rejected. After `circuit_backoff_secs` → HALF_OPEN.
- **HALF_OPEN**: Single health probe allowed. Success → CLOSED (reset backoff). Failure → OPEN (backoff doubles, capped at `circuit_max_backoff_secs`).
- **Slow-start**: On CLOSED recovery, `effective_weight()` linearly ramps from 1 → full over `slow_start_secs`.
- **Defaults**: `max_fails=3`, `fail_timeout_secs=30`, `circuit_initial_backoff_secs=5`, `circuit_max_backoff_secs=60`.

---

### `src/ai/mod.rs` (633 lines) — AI Routing Algorithms

| Item | Purpose |
|------|---------|
| `AiRouter` trait | `update_score(backend, latency_ms, is_error)` + `predict_best_backend(backends)`. Thread-safe (Send+Sync). |
| `EpsilonGreedy` | Explore-exploit: ε% random, (1-ε)% best EMA score. Score = `α * (1/latency) + (1-α) * old_score`, penalized 50% on error. |
| `Ucb1Router` | UCB1 formula: `mean_reward + c * sqrt(ln(N) / n_i)`. Favors under-explored backends. Incremental mean update. |
| `SoftmaxRouter` | Boltzmann: `P(i) = exp(score_i / T) / Σ exp(score_j / T)`. Temperature T controls exploration (high=uniform, low=greedy). Roulette wheel selection. |
| `ThompsonSamplingRouter` | Beta(α,β) per backend. Success (latency < threshold): α += 1. Failure: β += 1. Periodic decay (α,β *= 0.95) prevents stale beliefs. Samples from posterior, picks highest. |
| `build_ai_router()` | Factory: creates algorithm from config string + params. |

---

### `src/auth/` — Authentication (7 files, ~1600 lines)

All methods return `AuthResult::Allowed | Denied(StatusCode, &str)`.

| File | Key Functions | Design |
|------|---------------|--------|
| `basic.rs` | `check(headers, realm, users)` | Bcrypt hash detection (`$2b$`/`$2y$`/`$2a$`), falls back to constant-time plaintext compare |
| `jwt.rs` | `check(headers, secret, algorithm)` → (AuthResult, Option\<Claims\>) | Extracts Bearer token, validates with `jsonwebtoken` crate, `claims_to_headers()` injects X-Auth-Sub/Email/Iss |
| `jwks.rs` | `JwksManager::get_keys(uri)`, `find_key(uri, kid)` | 5-min TTL cache, supports RSA (RS256-512) + EC (ES256/384), `decoding_key_from_jwk()` converts JWK → DecodingKey |
| `oauth.rs` | `check(headers, introspect_url, client_id, secret, cache)` | RFC 7662 POST with HTTP Basic. 60s DashMap cache. Returns (AuthResult, Option\<subject\>). |
| `oidc.rs` | `discover()`, `authorization_url()`, `exchange_code()`, `check_session()` | Full OIDC RP flow: .well-known discovery, auth redirect, code→token exchange, DashMap session store |
| `auth_request.rs` | `check(headers, auth_url, method, path)` | Nginx-style: GET to auth service with original headers + X-Original-Method/URI. Forwards X-Auth-* response headers. |

---

### `src/waf/` — Web Application Firewall (6 files, ~2600 lines)

#### Inspection pipeline (`WafEngine::inspect()`):
1. **Keyval ban** — if IP exists in keyval store → Block
2. **IP reputation** — if strikes >= threshold → Block (auto-ban with TTL)
3. **Bot detection** — user-agent classification (18 bad + 13 good signatures)
4. **Regex rules** — OWASP patterns for SQLi, XSS, LFI, command injection (RegexSet, compiled once)
5. **Policy engine** — declarative signature sets + custom rules (Blocking vs Transparent mode)
6. **ML fraud** — async ONNX inference queued via MPSC channel (not part of sync pipeline; strike weight: 10)

| File | Key Types | Design |
|------|-----------|--------|
| `rules.rs` | `WafRules` with `RegexSet` per category | Compiled once at startup. `inspect_payload()` checks path+query+UA against all sets. |
| `bot.rs` | `BotClass`, `BotRateTracker`, `CaptchaManager`, `CaptchaProvider` | 18 bad bot signatures, 13 good bot signatures. Rate anomaly detection. CAPTCHA challenge with one-time nonces (10-min TTL). Supports hCaptcha, Turnstile, reCAPTCHA v2. |
| `policy.rs` | `WafPolicy`, `PolicyEngine`, `SignatureSet`, `CustomRule` | JSON-loaded policies. Enforcement modes: Blocking vs Transparent (log-only). Severity levels, exclusion patterns, default OWASP policy with 7 signature sets. |
| `reputation.rs` | `IpReputationManager` | Per-IP strike counter with auto-ban threshold + TTL expiry. Redis pub/sub broadcast for cluster sync. Strike weights: 3 (payload), 5 (bot), 10 (ML fraud). |
| `ml_fraud.rs` | `MlFraudEngine`, `MlEvent` | Async ONNX inference via `tract-onnx`. 6-float feature vector [path_len, method_enum, query_len, header_count, ua_len, body_len]. Score > 0.5 = fraud. Shadow mode (log) vs Active mode (auto-ban). |

---

### `src/middleware/` — Request/Response Processing (6 files, ~1920 lines)

| File | Key Types | Design |
|------|-----------|--------|
| `cache.rs` | `AdvancedCache`, `CacheEntry` | L1: Moka LFU (in-memory). L2: optional disk (hex-hashed filenames). Vary header tracking. Per-key mutex for thundering herd protection. `build_cache_key()` = `METHOD:HOST:PATH?QUERY:V:VARY_HEADERS`. **Freshness**: Fresh (within max_age) → Stale-While-Revalidate (serve stale + background refresh) → Stale-If-Error (serve stale on 5xx). **Purge**: single key, prefix scan, or full. |
| `ratelimit.rs` | `PhalanxRateLimiter` | Dual-layer: local (`governor` token bucket) + cluster (Redis Lua sliding-window ZSET on `phalanx:ratelimit:*`). Per-IP + global DDoS ceiling. Fallback: Redis unavailable → local-only. `top_ips()` for dashboard top-N. |
| `compression.rs` | `accepts_gzip()`, `gzip_compress()` | MIN_COMPRESS_SIZE = 1KB. Only compresses text/*, application/json, application/javascript, image/svg+xml. Skips if compressed >= original. |
| `brotli.rs` | `accepts_brotli()`, `brotli_compress()` | Quality clamped 0-11, lgwin=22 (32KB window). MIN_BROTLI_SIZE = 1KB. |
| `connlimit.rs` | `ZoneLimiter`, `ZoneKeySource`, `ConnectionGuard` | Zone-based rate + concurrent connection limiting. Key sources: `ClientIp`, `Header(name)`, `Cookie(name)`, `JwtClaim(field)`, `Uri`, `QueryParam(name)`, `Composite(Vec<...>)`. RAII `ConnectionGuard` auto-releases slot on drop. Governor-backed rate check + atomic connection counter. |

---

### `src/cluster/` — Distributed State (2 files, ~1220 lines)

| File | Key Types | Design |
|------|-----------|--------|
| `mod.rs` | `ClusterState`, `ClusterBackend` | Abstraction: `put()/get()/delete()` dispatches to etcd v3, Redis, gossip, or no-op standalone. Gossip backend auto-creates `GossipState` and spawns gossip loop. `spawn_heartbeat()` with TTL = 3× interval. |
| `gossip.rs` | `GossipState`, `GossipMessage`, `NodeState` | SWIM protocol via UDP. Messages: Ping, Ack, PingReq (indirect probe via ephemeral socket), Join, Leave. LWW (last-write-wins) state merge. Incarnation-based membership conflict resolution. Alive→Suspect→Dead state machine. Default: 1s rounds, fanout=3, 5s suspicion timeout. |

---

### `src/admin/` — Admin API (4 files, ~2120 lines)

| File | Key Functions | Design |
|------|---------------|--------|
| `mod.rs` | `start_admin_server()`, `AdminState`, `ProxyMetrics` | Actix-web server. Endpoints: `/health`, `/metrics` (Prometheus), `/api/stats`, `/api/discovery/backends` (CRUD), `/api/keyval/*`, `/api/config/reload`. ProxyMetrics: counters for http_requests_total, waf_blocks_total, cache_hits_total, rate_limit_hits_total + histogram for request_duration. |
| `api.rs` | Extended RBAC API | `ApiRole`: Admin > Operator > ReadOnly. Bearer token auth. Endpoints: dynamic route CRUD, SSL cert management, upstream listing, ML fraud model upload/mode switch/logs. |
| `alerts.rs` | `AlertEngine` | Background check every 30s. Monitors bandwidth thresholds + system resources (memory/FD on Linux). Rolling alert log (max 500). Webhook delivery for external notification. |
| `dashboard_api.rs` | Dashboard data endpoints | WAF ban list, attack logs (last N), strike counts, rate limit top-N IPs, cluster node status, cache stats, bandwidth per-protocol, resource alerts. |

---

### `src/gslb/mod.rs` (565 lines) — Global Server Load Balancing

| Item | Purpose |
|------|---------|
| `DataCenter` | id, name, region (7 GeoRegions), primary_countries, upstream_pool, weight, enabled |
| `GslbPolicy` | Geographic, LatencyBased, WeightedRoundRobin, GeographicWithLatencyFailover |
| `GslbRouter` | `route(country_code)` → upstream pool name. Geographic: exact country match → region proximity fallback. Latency: lowest measured latency. Weighted: atomic counter mod total_weight. Geo+Latency: tries geo first, falls back to latency. |
| `country_to_region()` | Maps ~60 country codes to 7 regions (NA/SA/EU/AF/ME/AS/OC). |

Wired into proxy pipeline: after normal pool selection, if GSLB is configured and X-Geo-Country-Code header is present, overrides the upstream pool.

---

### `src/k8s/mod.rs` (786 lines) — Kubernetes Ingress Controller

| Item | Purpose |
|------|---------|
| `IngressResource` | Simplified K8s Ingress v1: name, namespace, annotations, rules[], tls[] |
| `GatewayHttpRoute` | Gateway API v1: hostnames, rules with matches/backends/filters |
| `IngressController` | `reconcile_ingress()`: converts Ingress rules → `PhalanxRoute` entries. `reconcile_gateway_route()`: converts HTTPRoute → PhalanxRoute. Resolves service names to `service.namespace.svc.cluster.local:port`. Supports annotations for WAF, rate limit, CORS, rewrite-target. |
| `PhalanxRoute` | Generated route: path, path_type, host, upstream_pool, backends, tls_secret, add_headers, rewrite_rules |

---

### Other Modules

| File | Lines | Key Items | Purpose |
|------|-------|-----------|---------|
| `src/discovery/mod.rs` | 389 | `ServiceDiscovery`, `DiscoveredBackend` | RocksDB persistent backend registry. `spawn_dns_watcher()` resolves hostnames every 30s. `spawn_srv_watcher()` discovers SRV records. |
| `src/geo/mod.rs` | 224 | `GeoIpDatabase`, `GeoPolicy` | CSV-based CIDR→country lookup with DashMap cache. Allow/deny country lists (deny overrides). `inject_geo_headers()` adds X-Geo-Country-Code. |
| `src/keyval/mod.rs` | 305 | `KeyvalStore` | DashMap with lazy TTL expiry. Optional Redis pub/sub sync (`phalanx:keyval:sync` channel). Used for WAF ban lists, feature flags, A/B groups. |
| `src/mail/mod.rs` | 500+ | `MailProxyConfig`, `start_mail_proxy()`, `negotiate_starttls()` | Transparent TCP proxy for SMTP/IMAP/POP3. Optional custom banner. STARTTLS support: protocol-aware negotiation (SMTP `STARTTLS`, IMAP `tag STARTTLS`, POP3 `STLS`), TLS upgrade via tokio-rustls, then bidirectional proxying. |
| `src/scripting/mod.rs` | 455 | `HookEngine`, `HookPhase`, `HookResult` | 4 phases: PreRoute, PreUpstream, PostUpstream, Log. Priority-ordered execution. Short-circuits on `Respond`. Built-in hooks: HeaderInjection, ConditionalRewrite, IpAccess. |
| `src/scripting/rhai_engine.rs` | 299 | `RhaiHookHandler` | Loads `.rhai` script file. Exposes: uri, method, client_ip, headers, status. Returns: `()` → Continue, `"rewrite:/path"` → RewritePath, `"respond:403:msg"` → Respond, `false` → block. Safety: 1M ops, 64KB strings, 1K arrays, 100 maps. |
| `src/telemetry/mod.rs` | 37 | `init_telemetry()` | Sets up tracing subscriber + optional OpenTelemetry layer. |
| `src/telemetry/otel.rs` | 78 | `init_otel_layer()` | OTLP gRPC exporter for Jaeger/Tempo/Datadog. W3C Trace Context `traceparent` header injection. |
| `src/telemetry/access_log.rs` | 198 | `AccessLogger`, `LogFormat` | Async file writer via mpsc channel. Formats: JSON (structured), combined (NGINX-style), common (Apache-style). |
| `src/telemetry/bandwidth.rs` | 401 | `BandwidthTracker`, `ProtocolStats` | Per-protocol atomic counters for 8 protocols (HTTP1/2/3, WS, gRPC, TCP, UDP, WebRTC). `check_thresholds()` generates bandwidth alerts at warning/critical levels. |
| `src/wasm/mod.rs` | 918 | `WasmPlugin` trait, `WasmPluginManager` | Proxy-Wasm ABI v0.2.1 host. Phases: OnRequestHeaders/Body, OnResponseHeaders/Body, OnLog, OnTick. Built-in native plugins: HeaderInjection, PathBlocker, HeaderRateLimit. `WasmPluginConfig` loaded from JSON. Priority-sorted execution with short-circuit on direct_response. |

---

## HTTP/1 Request Pipeline

Full 29-step processing order in `handle_http_request()`:

1. **Real IP resolution** — `realip::resolve_client_ip()` from X-Forwarded-For/X-Real-IP/PROXY Protocol
2. **CAPTCHA verify** — short-circuit for `/__phalanx/captcha/verify` POST
3. **Zone connection limit** — `ZoneLimiter::acquire_connection()` with RAII `ConnectionGuard`
4. **gRPC-Web detection** — `grpc_web::is_grpc_web()` content-type check
5. **PreRoute hooks** — `HookEngine::execute(PreRoute)` — Rhai scripts can rewrite/inject/short-circuit
6. **CAPTCHA evaluation** — `CaptchaManager::evaluate()` → Allow/Block/Challenge HTML page
7. **WAF inspection** — `WafEngine::inspect()` 5-stage pipeline
8. **GeoIP check** — country allow/deny + `inject_geo_headers()`
9. **gRPC-Web CORS** — 204 for OPTIONS preflight
10. **WebSocket detection** — `is_websocket_upgrade()`, extract `hyper::upgrade::on()`
11. **URL rewriting** — `apply_rewrites()` with break/last/redirect/permanent loop
12. **Route matching** — longest-prefix match over `app_config.routes`
13. **Authentication** — chain: Basic → JWT → OAuth → JWKS → OIDC → auth_request (route) → auth_request (global)
14. **Body buffering** — conditional: only when WAF, gRPC-Web, mirror, or ML fraud needs full body
15. **GSLB override** — `GslbRouter::route(country_code)` overrides pool selection
16. **Cache lookup** — `AdvancedCache::get()` for GET requests; cache hit returns immediately
17. **PreUpstream hooks** — `HookEngine::execute(PreUpstream)` for final header injection
18. **Backend selection** — sticky session lookup → AI router or LB algorithm via `UpstreamPool::get_next_backend()`
19. **Request forwarding** — keepalive pool, header injection, OpenTelemetry trace context
20. **WebSocket upgrade** — 101 → bidirectional `copy_bidirectional_fallback()` tunnel
21. **AI training** — `AiRouter::update_score()` with latency + error flag
22. **Prometheus metrics** — http_requests_total (method/status/pool), request_duration histogram
23. **Response compression** — Brotli (quality 6) preferred over gzip, min-size thresholds
24. **Cache store** — `AdvancedCache::insert()` for GET 200 responses
25. **Traffic mirroring** — `mirror::mirror_request()` fire-and-forget to shadow pool
26. **Sticky session cookie** — `StickySessionManager::set_cookie_header()` with base64 backend addr
27. **Connection keepalive** — `ConnectionPool::release()` returns socket to pool
28. **Access log** — `AccessLogger` structured entry with all request/response metadata
29. **Log hooks** — `HookEngine::execute(Log)` for post-response auditing

---

## Configuration

NGINX-style block syntax. See `phalanx.conf` for working example.

```
worker_threads N;
tcp_listen ADDR;
admin_listen ADDR;

http {
    upstream NAME {
        server ADDR weight=N;
        algorithm roundrobin|weighted_roundrobin|least_connections|ip_hash|random|ai_predictive|consistent_hash|least_time;
        keepalive N;
        srv_discover _service._proto.domain;
    }
    server {
        listen PORT;
        rate_limit_per_ip N;  rate_limit_burst N;  global_rate_limit N;
        waf_enabled true;  waf_auto_ban_threshold N;  waf_auto_ban_duration N;
        ai_algorithm epsilon_greedy|ucb1|softmax|thompson_sampling;
        gslb_policy geographic|latency|weighted|geo_latency;
        route /path {
            upstream POOL;
            root DIR;                         # static files
            fastcgi_pass ADDR;                # PHP-FPM
            uwsgi_pass ADDR;                  # Python WSGI
            add_header KEY "VALUE";
            rewrite REGEX REPLACEMENT FLAG;   # break|last|redirect|permanent
            auth_basic_realm "NAME";  auth_basic_user USER PASS;
            auth_jwt_secret SECRET;  auth_jwt_algorithm HS256;
            auth_request URL;
            proxy_cache true;  proxy_cache_valid N;
            gzip true;  brotli true;
            mirror_pool NAME;
        }
    }
}
```

## Testing

**771 total tests**: unit tests (colocated `#[cfg(test)]`) + integration tests (`tests/proxy_test.rs`, ~3000 lines).

```bash
cargo test                    # All 771 tests
cargo test waf                # Filter by module
cargo test --lib              # Unit tests only
cargo test -- --nocapture     # Show tracing output
```

Test infrastructure: `scripts/run_tests.sh` (Rust + Python + load), `scripts/test_api.py` (pytest admin API), `scripts/load_test.py` (Locust), `scripts/start_test_backends.sh` (mock backends on :18081-18083).

## Key Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| hyper | 1.8 | HTTP/1 + HTTP/2 server |
| quinn + h3 | 0.11 / 0.0.8 | HTTP/3 (QUIC) |
| tokio + tokio-rustls | 1.49 / 0.26 | Async runtime + TLS |
| rustls-acme | 0.15 | Let's Encrypt ACME |
| actix-web | 4.13 | Admin API |
| moka | 0.12 | In-memory LFU cache |
| governor | 0.10 | Token bucket rate limiting |
| rocksdb | 0.24 | Persistent service discovery |
| tract-onnx | 0.22 | ML fraud inference |
| rhai | 1.x | Embedded scripting |
| webrtc | 0.17 | WebRTC SFU |
| prometheus | 0.14 | Metrics |
| opentelemetry | 0.31 | OTLP tracing |
| dashmap | 6.1 | Concurrent hash maps |
| arc-swap | 1.8 | Lock-free config swap |
| etcd-client | 0.18 | etcd v3 cluster |
| redis | 0.27 | Redis cluster + rate limiting |
| trust-dns-resolver | 0.23 | DNS/SRV discovery |

## Common Tasks

**Add a new subsystem to the proxy pipeline**: Define struct → create in main.rs init block → add `Arc::clone` to supervisor closure → add param to `start_proxy()` → add to per-connection clone block → add to `handle_http_request()` + `handle_http2_request()` signatures → use in pipeline. (5 layers of threading.)

**Add a new route handler**: Define field in `RouteConfig` (config/mod.rs) → parse directive in `parser.rs` → handle in `proxy/mod.rs` handler functions.

**Add a new LB algorithm**: Add variant to `LoadBalancingAlgorithm` → implement in `routing/mod.rs` `get_next_backend()` match arm.

**Add a new auth method**: Create `src/auth/new.rs` → return `AuthResult` → add `else if` in auth chain (proxy/mod.rs, after OIDC, before auth_request) in both HTTP/1 and HTTP/2 handlers.

**Add a WAF rule category**: Add `RegexSet` in `waf/rules.rs`, or add signature set in `waf/policy.rs`.

**Add an admin endpoint**: Add handler in `admin/api.rs` or `dashboard_api.rs` → register route in `admin/mod.rs` `start_admin_server()`.

**Add a Wasm plugin type**: Implement `WasmPlugin` trait in `wasm/mod.rs` → add name-matching branch in main.rs plugin loader.
