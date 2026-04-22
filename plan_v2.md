# Phalanx Gap Fix Plan v2

Last updated: 2026-04-22

## Status Legend
- ⬜ Not started
- 🔧 In progress
- ✅ Done
- 🧪 Testing

---

## Audit Summary

**Source:** Full codebase analysis + graphify knowledge graph (1939 nodes, 40 communities)
**Tests:** 226 tests passing
**Lines:** ~31,500 lines across 70+ files

---

## 🔴 CRITICAL — Must Fix for Production

### C1: Dangerous `.unwrap()` Calls in Hot Path
**Problem:** 24+ `.unwrap()` calls in `src/proxy/mod.rs` on config-derived headers.
Crashes on malformed config, invalid CORS headers, bad auth settings.

**Locations:**
- Line 158, 176, 209, 220, 247: `.parse().unwrap()` on header values
- Lines 1291, 1330, 1390, 1401: `.insert(header, value.parse().unwrap())` for CORS
- Lines 1736, 1785, 2164, 2247, 2338, 2617, 2654: various `.unwrap()` in request path

**Fix:** Use `.unwrap_or_default()` or validate at config parse time.
**Status:** ✅ Done — 20 unwrap() calls replaced with .expect() and static HeaderValue

### C2: HTTP/3 Parity Gap — 13 steps vs 29
**Problem:** `handle_h3_request()` in `src/proxy/http3.rs` missing critical functionality.
Auth chain, compression, metrics, mirroring, WebSocket, gRPC-Web NOT implemented.

**Missing from HTTP/3 pipeline:**
| Step | HTTP/1 | HTTP/3 | File:Line |
|------|--------|--------|-----------|
| gRPC-Web CORS preflight | ✅ | ❌ | - |
| WebSocket detection/upgrade | ✅ | ❌ | - |
| Auth chain (Basic/JWT/OAuth/JWKS/OIDC/auth_request) | ✅ | ❌ | http3.rs:264 |
| Response compression (gzip/brotli) | ✅ | ❌ | - |
| Traffic mirroring | ✅ | ❌ | - |
| Prometheus metrics | ✅ | ❌ | http3.rs:264 |
| PostUpstream hooks | ✅ | ❌ | - |
| Log hooks | ✅ | ❌ | - |
| GeoIP headers injection | ✅ | ❌ | - |
| Connection pooling | ✅ | ❌ | - |

**Fix:** Port full 29-step pipeline to HTTP/3 handler.
**Status:** ⬜ Not started

### C3: Connection Pool Leak — `release()` Never Called
**Problem:** `acquire()` IS used (mod.rs:1921) but `release()` never called.
Hyper takes ownership of TcpStream. Connections never returned to pool.

**Affected:** `src/proxy/pool.rs`, `src/proxy/mod.rs:1921`
**Fix:** After `copy_bidirectional`, call `pool.release()` or implement stream wrapping.
**Status:** ⬜ Not started
**Note:** Architecture limitation — needs refactor to wrap stream in guard that releases on drop.

---

## 🟡 HIGH — Performance Blockers for Bare Metal

### P1: Vec Allocation on Every Request — `get_next_backend()`
**Problem:** 3 `Vec::clone().collect()` calls per backend selection.
Heap allocations on hot path (~10µs overhead per request).

**File:** `src/routing/mod.rs:326-360`
```rust
// CURRENT (slow):
let healthy_primary: Vec<Arc<BackendNode>> = current_backends.iter().filter(...).cloned().collect();
let backup: Vec<...> = current_backends.iter().filter(...).cloned().collect();
let available: Vec<...> = healthy.into_iter().filter(...).collect();

// FIX: Iterate in-place, avoid cloning
```

**Fix:** Use stack-allocated array or smallvec, filter in single pass.
**Status:** ⬜ Not started

### P2: String Cloning on Hot Path
**Problem:** 227+ `.to_string()` / `.to_owned()` calls per request in proxy handler.
GC pressure, latency spikes.

**Key offenders:**
- Line 882: `path.to_string()` — path is already &str
- Line 895: `ip_str = real_ip.to_string()` — IP already available
- Lines 936, 974, 1768: `.filter_map(...to_string())` on headers

**Fix:** Use `Cow<'_, str>` or `&str` references where possible.
**Status:** ⬜ Not started

### P3: Mutex Contention in Cache and Pool
**Problem:** `tokio::sync::Mutex` in `src/middleware/cache.rs:25` and `src/proxy/pool.rs:18`.
Per-key locks cause contention under high throughput.

**Files:**
- `src/middleware/cache.rs:25` — per-key thundering herd mutex
- `src/proxy/pool.rs:18` — connection pool mutex per backend

**Fix:** Replace with atomic spin-wait or DashMap's internal locking.
**Status:** ⬜ Not started

### P4: Random Algorithm Uses SystemTime Syscall
**Problem:** `SystemTime::now()` in `src/routing/mod.rs:394-398` for Random LB.
System call every request = latency jitter.

**Fix:**
```rust
// CURRENT (slow):
let ts = std::time::SystemTime::now().duration_since(UNIX_EPOCH)...
// FIX:
use rand::rngs::SmallRng;  // per-thread, no syscall
```

**Status:** ⬜ Not started

### P5: OIDC Session Cleanup O(n) Scan
**Problem:** `src/auth/oidc.rs` — cleanup iterates all sessions to find expired.
No TTL index.

**Fix:** Use `IndexMap` with expiration ordering, or timer wheel.
**Status:** ⬜ Not started

### P6: HookEngine.has_hooks() Lock + Scan
**Problem:** Every request calls `hook_engine.has_hooks(PreRoute)` which does:
RwLock read + HashMap lookup per phase.

**File:** `src/scripting/mod.rs:123`
**Fix:** Cache phase count in atomic or use bitflags.
**Status:** ⬜ Not started

---

## 🟠 MEDIUM — Correctness & Robustness

### R1: HTTP/3 WAF Body Inspection Missing
**Problem:** `handle_h3_request()` comment says "WAF inspection (URL + body)" but body
is not passed to WAF.

**File:** `src/proxy/http3.rs:444`
**Status:** ⬜ Not started

### R2: GeoIP Header Not Injected in HTTP/3
**Problem:** `inject_geo_headers()` never called in HTTP/3 handler.
GSLB routing won't work correctly for HTTP/3.

**File:** `src/proxy/http3.rs`
**Status:** ⬜ Not started

### R3: Prometheus Metrics Never Updated for HTTP/3
**Problem:** `metrics.rate_limit_rejections.inc()` exists but `http_requests_total`
and `request_duration` histogram never updated.

**File:** `src/proxy/http3.rs`
**Status:** ⬜ Not started

### R4: auth Module Never Called in HTTP/3
**Problem:** Auth chain (Basic/JWT/OAuth/JWKS/OIDC) completely missing from HTTP/3.
Security gap — HTTP/3 requests bypass authentication.

**File:** `src/proxy/http3.rs:264-450`
**Status:** ⬜ Not started

### R5: WasmPlugins Not Fully Wired
**Problem:** Wasm plugins receive incomplete context in HTTP/3. Body not passed.
Phase handling may not match HTTP/1 behavior.

**File:** `src/proxy/http3.rs` (wasm section)
**Status:** ⬜ Not started

---

## Additional Critical Findings (from deep audit)

### C4: HTTP/3 Creates Fresh reqwest::Client Per Request
**Problem:** `src/proxy/http3.rs:612-615` creates a new HTTP client per request.
Connection pooling completely broken for HTTP/3 — no keepalive reuse.

**Status:** ⬜ Not started

### C5: ConsistentHash Rebuilds Ring on Every Call
**Problem:** `src/routing/mod.rs:473-486` rebuilds virtual node ring per request.
For 4 backends with weight 10 = 6400 virtual nodes sorted per request.

**Status:** ⬜ Not started

### C6: Static File `.unwrap()` on MIME Header Parsing
**Problem:** `src/proxy/mod.rs:4044,4048,4079,4083` can panic on invalid MIME types.
Serving arbitrary paths with invalid content-type chars causes crash.

**Status:** ⬜ Not started

### C7: 503 Responses Panic on Missing Retry-After Header
**Problem:** `src/proxy/mod.rs:4185` assumes Retry-After header exists.
Backend 503 without header = panic.

**Status:** ⬜ Not started

### P7: `hex_prefix()` Uses Slow DefaultHasher (SipHash)
**Problem:** `src/middleware/cache.rs:280` uses `DefaultHasher` (SipHash).
Not optimal for in-memory cache with 100K+ ops/sec.

**Status:** ⬜ Not started

### P8: HTTP/3 Missing Bandwidth Tracking
**Problem:** No `bandwidth.inc_requests()` or `bandwidth.add_out()` calls in H3.
Metrics will underreport HTTP/3 traffic.

**Status:** ⬜ Not started

### P9: HTTP/3 Missing Structured Access Logging
**Problem:** No `access_logger.log()` call in H3.
Access logs missing for all HTTP/3 requests.

**Status:** ⬜ Not started

### R6: HTTP/3 Missing HSTS Header Injection
**Problem:** No HSTS injection in H3 handler.
HTTP security header not applied to HTTP/3 responses.

**Status:** ⬜ Not started

### R7: HTTP/3 Hardcodes Cache TTL to 60s
**Problem:** `src/proxy/http3.rs:750` uses hardcoded 60s TTL.
Ignores route-level `proxy_cache_valid` configuration.

**Status:** ⬜ Not started

### R8: HTTP/3 Missing gRPC-Web Support
**Problem:** No `is_grpc_web()` detection or `translate_response()` in H3.
gRPC-Web requests to HTTP/3 not handled correctly.

**Status:** ⬜ Not started

---

## Execution Order

```
1. C1 (unwrap fixes) — Quick win, prevents production crashes
2. C4 (HTTP/3 reqwest client) — Quick win, enables connection reuse
3. C2 (HTTP/3 parity) — Full pipeline port
4. C3 (connection pool leak) — Architecture fix
5. P1-P9 (performance) — Iterate for bare metal throughput
6. R1-R8 (correctness) — Polish remaining gaps
```

**For each task:**
1. Implement fix
2. Add/update unit tests
3. Run `cargo test` — all must pass
4. Update status in this file
5. Update CLAUDE.md if architecture changes

---

## Previous Status (v1 — All DONE)

P0-P2 from previous plan (Tasks 1-11) — ✅ COMPLETED
- Task 1: Zone limiter reload fix
- Task 2: PostUpstream hook invocation
- Task 3: CLAUDE.md reload table fix
- Task 4: WAF signature enforcement
- Task 5: split_traffic wiring
- Task 6: HTTP/1 backend connection pooling (acquire wired)
- Task 7: PROXY Protocol v2 in TCP proxy
- Task 8: Dangerous unwrap() replacement (partial — C1 continues this)
- Task 9: Stale HTTP/2 comments fix
- Task 10: GSLB country mapping complete
- Task 11: WAF ML fraud fallback alerting
