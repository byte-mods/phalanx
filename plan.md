# Phalanx — Comprehensive Gap Analysis & Completion Plan

Last updated: 2026-04-08

## Status Legend
- `[ ]` Not started
- `[-]` In progress
- `[x]` Completed
- `[!]` Blocked / needs follow-up

---

## Phase 0: In-Progress / Carried Forward

These items were identified in previous audits and are either in-progress or unresolved.

| # | Status | Item | Source |
|---|--------|------|--------|
| 0.1 | [-] | Rate limiter zero-value hardening — `unwrap()` panic on 0 values | plan.md P1-4 |

---

## Phase 1: HTTP/3 Feature Parity (CRITICAL)

`handle_h3_request()` implements a 13-step subset of the 29-step HTTP/1 pipeline. These features are missing from HTTP/3 and represent a security/functionality gap for QUIC clients.

| # | Severity | Missing Feature | HTTP/1 Step | Impact |
|---|----------|----------------|-------------|--------|
| 1.1 | CRITICAL | Zone connection limiting | Step 3 | No per-zone concurrency control on H3 |
| 1.2 | HIGH | Wasm OnRequestHeaders/OnResponseHeaders hooks | Step 5 (Wasm) | Plugins don't execute on H3 requests |
| 1.3 | HIGH | PreRoute / PreUpstream / Log scripting hooks | Steps 5, 17, 29 | Rhai scripts bypassed on H3 |
| 1.4 | HIGH | Sticky session lookup + cookie | Steps 18, 26 | Session affinity broken for H3 clients |
| 1.5 | HIGH | ML fraud detection (async queue) | Step 17 (body) | No fraud scoring on H3 traffic |
| 1.6 | MEDIUM | Traffic mirroring | Step 25 | Shadow traffic not sent for H3 |
| 1.7 | MEDIUM | Prometheus metrics (http_requests_total, duration) | Step 22 | H3 traffic invisible in dashboards |
| 1.8 | MEDIUM | Connection keepalive pool | Steps 19, 27 | New TCP connection per H3→backend request |
| 1.9 | LOW | gRPC-Web detection + translation | Steps 4, 9, 25 | gRPC-Web over H3 unsupported |
| 1.10 | LOW | WebSocket upgrade | Steps 10, 20 | WebSocket over H3 unsupported (rare) |

**Approach**: Extract shared pipeline logic into a `RequestPipeline` struct/trait that all three handlers (HTTP/1, HTTP/2, HTTP/3) can reuse.

---

## Phase 2: SIGHUP Reload Propagation (HIGH)

`spawn_reload_handler()` swaps config + TLS + upstreams, but many subsystems are initialized once at startup and never updated on reload.

| # | Subsystem | File | What's Stale After Reload |
|---|-----------|------|---------------------------|
| 2.1 | Rate limiter | `middleware/ratelimit.rs` | per_ip_rate, burst, global_rate unchanged |
| 2.2 | WAF policy engine | `waf/policy.rs` | Policy file not re-read; new rules not loaded |
| 2.3 | WAF rules | `waf/rules.rs` | RegexSet compiled once, not refreshed |
| 2.4 | AI router | `ai/mod.rs` | Algorithm + hyperparams (ε, τ, C) frozen |
| 2.5 | GeoIP database | `geo/mod.rs` | CSV not re-read; country list stale |
| 2.6 | Hook engine | `scripting/mod.rs` | Rhai scripts not reloaded |
| 2.7 | CAPTCHA manager | `waf/bot.rs` | Provider config (site key, secret) frozen |
| 2.8 | Zone limiter | `middleware/connlimit.rs` | Zone definitions not updated |
| 2.9 | Wasm plugins | `wasm/mod.rs` | Plugin list not refreshed |
| 2.10 | GSLB router | `gslb/mod.rs` | DC definitions not updated |
| 2.11 | K8s ingress class | `k8s/mod.rs` | Ingress class filter not updated |

**Approach**: For each subsystem, either:
- (a) Wrap in `ArcSwap` and add a reload path in `spawn_reload_handler()`, or
- (b) Read from `AppConfig` on each request (only if cheap — e.g., rate limit values).

---

## Phase 3: Missing Production Features (HIGH)

Features that a production enterprise proxy should have but Phalanx currently lacks.

| # | Feature | Description | Files Affected |
|---|---------|-------------|----------------|
| 3.1 | **Request timeout per-route** | No per-route or per-upstream timeout. Backend hangs → client hangs forever. Need configurable `proxy_read_timeout` and `proxy_connect_timeout`. | `config/mod.rs`, `config/parser.rs`, `proxy/mod.rs` |
| 3.2 | **Retry policy** | No automatic retry on 502/503/connect failure. NGINX has `proxy_next_upstream`. Need retry count + retry conditions + idempotency guard. | `proxy/mod.rs`, `config/mod.rs` |
| 3.3 | **Request/response body size limits** | No `client_max_body_size` equivalent. Unbounded body reads can OOM the process. | `proxy/mod.rs`, `config/mod.rs`, `config/parser.rs` |
| 3.4 | **Graceful connection draining** | On shutdown/reload, in-flight requests are cancelled immediately. Need drain period (e.g., 30s) where new connections are refused but existing ones complete. | `main.rs`, `proxy/mod.rs` |
| 3.5 | **Access log rotation** | `AccessLogger` appends to a single file forever. No rotation by size/time. Need logrotate-compatible reopen-on-SIGUSR1 or built-in rotation. | `telemetry/access_log.rs` |
| 3.6 | **CORS middleware** | Only gRPC-Web has CORS headers. No general-purpose CORS config (allowed origins, methods, headers, credentials). | `proxy/mod.rs`, `config/mod.rs`, `config/parser.rs` |
| 3.7 | **Connection pool idle timeout** | `ConnectionPool` has no TTL on idle connections. Stale connections discovered on use (connect error), causing latency spikes. | `proxy/pool.rs` |
| 3.8 | **HTTP/2 backend forwarding** | Backend requests always use HTTP/1.1. gRPC backends that require HTTP/2 won't work. Need `proxy_http_version 2` config. | `proxy/mod.rs`, `config/mod.rs` |
| 3.9 | **Health check customization** | Interval (5s) and timeout (3s) are hardcoded. Need per-upstream `health_check_interval` and `health_check_timeout` config. | `routing/mod.rs`, `config/mod.rs`, `config/parser.rs` |
| 3.10 | **Admin API token persistence** | RBAC tokens stored in DashMap, lost on restart. Need file-based or config-based token store. | `admin/api.rs` |

---

## Phase 4: Protocol & Correctness Gaps (MEDIUM)

| # | Feature | Description | Files Affected |
|---|---------|-------------|----------------|
| 4.1 | **HTTP/2 handler feature parity** | `handle_http2_request()` is missing: traffic mirroring, gRPC-Web translation, WebSocket tunneling (RFC 8441). These work in HTTP/1 only. | `proxy/mod.rs` |
| 4.2 | **GSLB active latency probing** | `GslbRouter` stores latency values but has no active measurement loop. Latency-based routing uses stale or zero values. Need periodic HTTP probe per DC. | `gslb/mod.rs` |
| 4.3 | **K8s Gateway API watcher** | `IngressController` has `reconcile_gateway_route()` but only `spawn_watcher()` for Ingress v1 is documented. No watcher for HTTPRoute resources. | `k8s/mod.rs` |
| 4.4 | **WebSocket ping/pong keepalive** | After 101 upgrade, the bidirectional tunnel does raw byte copy. No WebSocket-level ping/pong for connection health. Long-idle WebSockets may be dropped by intermediaries. | `proxy/mod.rs` |
| 4.5 | **Mail proxy backend TLS verification** | `negotiate_starttls()` upgrades the client→Phalanx side but doesn't verify the backend's TLS certificate. MITM between Phalanx and mail backend is possible. | `mail/mod.rs` |
| 4.6 | **UDP session timeout configurability** | UDP proxy uses hardcoded 60s session timeout + reaper. Should be configurable per-upstream. | `proxy/udp.rs`, `config/mod.rs` |
| 4.7 | **Consistent hash vnode count** | Uses `40 * weight` virtual nodes per backend. NGINX uses `160 * weight`. Lower count = more uneven distribution, especially with few backends. | `routing/mod.rs` |
| 4.8 | **OAuth cache reaper** | Cache entries leak if tokens are never re-checked. Need periodic sweep. (From IMPLEMENTATION_PLAN.md Issue 4 — marked DONE but verify implementation.) | `auth/oauth.rs` |

---

## Phase 5: Observability & Operations Gaps (MEDIUM)

| # | Feature | Description | Files Affected |
|---|---------|-------------|----------------|
| 5.1 | **Per-upstream metrics** | No per-backend latency histograms or error rate counters in Prometheus. Only aggregate `http_requests_total` by pool. | `admin/mod.rs`, `proxy/mod.rs` |
| 5.2 | **Upstream health status endpoint** | No admin API endpoint exposing per-backend health, circuit state, active connections, fail count. Dashboard API has partial coverage. | `admin/dashboard_api.rs` |
| 5.3 | **Config validation endpoint** | No dry-run config validation API (like `nginx -t`). Admin can only reload and hope. | `admin/api.rs`, `config/mod.rs` |
| 5.4 | **Structured error responses** | Error pages (502, 503, 429, 403) return minimal bodies. No JSON error format for API consumers. No custom error page config. | `proxy/mod.rs` |
| 5.5 | **Request tracing correlation** | W3C traceparent injected but not logged in access log. Can't correlate access log entry to distributed trace. | `telemetry/access_log.rs`, `proxy/mod.rs` |
| 5.6 | **Bandwidth per-pool tracking** | `BandwidthTracker` tracks by protocol but not by upstream pool. Can't answer "which pool is consuming the most bandwidth?" | `telemetry/bandwidth.rs` |

---

## Phase 6: Wasm & Extensibility Gaps (LOW)

| # | Feature | Description | Files Affected |
|---|---------|-------------|----------------|
| 6.1 | **Actual .wasm file loading** | `WasmPluginManager` only runs native Rust plugins. `wasm_path` field exists but wasmtime integration is incomplete. (IMPLEMENTATION_PLAN.md Issue 10 — marked DONE, verify.) | `wasm/mod.rs` |
| 6.2 | **Wasm host ABI completeness** | Even if .wasm loads, the proxy-wasm ABI host functions (proxy_log, proxy_get/set_header, proxy_get_property, proxy_send_local_response) may not be fully implemented. | `wasm/mod.rs` |
| 6.3 | **Plugin hot-reload** | Wasm and Rhai plugins loaded once at startup. No mechanism to add/remove/update plugins at runtime without restart. | `wasm/mod.rs`, `scripting/mod.rs` |
| 6.4 | **Rhai script variables** | Rhai scripts can read request data but cannot write to shared state (e.g., keyval store) or access response body. | `scripting/rhai_engine.rs` |

---

## Phase 7: Security Hardening (LOW)

| # | Feature | Description | Files Affected |
|---|---------|-------------|----------------|
| 7.1 | **TLS cipher suite configuration** | No config for cipher suite selection, min TLS version, or HSTS. Uses rustls defaults. | `proxy/tls.rs`, `config/mod.rs` |
| 7.2 | **Rate limit response customization** | 429 response always says `Retry-After: 60`. Should use actual bucket refill time. | `proxy/mod.rs` |
| 7.3 | **WAF rule hot-reload** | RegexSet compiled once at startup. New rules require full restart. | `waf/rules.rs` |
| 7.4 | **Trusted proxy CIDR from config** | `TrustedProxies` CIDR list may not be configurable via phalanx.conf (verify). | `proxy/realip.rs`, `config/mod.rs` |
| 7.5 | **OIDC PKCE support** | OIDC flow uses basic authorization code grant. No PKCE (S256) support for public clients. | `auth/oidc.rs` |

---

## Implementation Priority Matrix

```
                        HIGH IMPACT
                            │
   Phase 3.1-3.4            │         Phase 1.1-1.5
   (Timeouts, retries,      │         (H3 parity)
    body limits, drain)      │
                            │
  LOW EFFORT ───────────────┼─────────────── HIGH EFFORT
                            │
   Phase 2.1-2.3            │         Phase 4.1-4.3
   (Reload propagation)     │         (H2 parity, GSLB probe,
                            │          K8s Gateway watcher)
                            │
                        LOW IMPACT
```

**Recommended execution order:**

1. **Phase 3.1–3.4** (request timeouts, retry, body limits, drain) — production safety
2. **Phase 1.1–1.5** (H3 critical parity) — security gap for QUIC traffic
3. **Phase 2.1–2.3** (reload: rate limiter, WAF, GeoIP) — operational necessity
4. **Phase 3.5–3.10** (log rotation, CORS, pool TTL, H2 backends, health config)
5. **Phase 4.1–4.8** (H2 parity, GSLB probing, K8s Gateway, consistency)
6. **Phase 5** (observability improvements)
7. **Phase 6–7** (extensibility, security hardening)

---

## Verification Checklist (per item)

- [ ] `cargo build` passes
- [ ] `cargo test` passes (all 771+ tests)
- [ ] New tests added for the fix
- [ ] No new `#[allow(dead_code)]` introduced
- [ ] No new `unwrap()` on fallible operations in non-test code
- [ ] No Mutex added to hot path
- [ ] Config changes parsed in `parser.rs` if applicable
- [ ] Both HTTP/1 and HTTP/2 handlers updated if pipeline change
- [ ] CLAUDE.md updated if architecture changes
