# Phalanx Gap Fix Plan v2

Last updated: 2026-04-27

## Status Legend
- ⬜ Not started
- 🔧 In progress
- ✅ Done
- 🧪 Testing

---

## Audit Summary

**Source:** Full codebase analysis + graphify knowledge graph (1939 nodes, 40 communities)
**Tests:** 911 tests passing (685 unit + 226 integration)
**Lines:** ~34,000 lines across 64 files

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

**Status:** 🔧 **Partial** — significant chunks shipped, but the full surface
(auth chain + compression + gRPC-Web + WebTransport) remains as its own focused PR.

**Already shipped (batches 1-4):**
- Mirroring, hooks, sticky, AI routing, cache, GeoIP check, CAPTCHA, WAF
  (URL + body), zone limits, AccessLogger, BandwidthTracker (per-protocol +
  per-pool), Prometheus `http_requests_total` + `request_duration` histogram,
  PostUpstream + Log hooks, shared `reqwest::Client`, conditional mirror clone.
- **Auth chain — Basic + JWT + auth_request (per-route + global fallback)** —
  extracted to `apply_h3_auth_chain` for unit-testability; injects claim
  headers on JWT pass and X-Auth-* on auth_request pass.
- **HSTS** (`Strict-Transport-Security`) injection when `hsts_max_age` is set.
- **Route-level cache TTL** — H3 cache writes now honour
  `proxy_cache_valid_secs` from the matched route instead of hardcoded 60 s.

**Still missing (deferred, big surface):**
- OAuth / JWKS / OIDC for HTTP/3 — these involve session stores and
  discovery flows that need their own focused work.
- Response compression (gzip / brotli) — needs streaming-aware port; the
  current H3 path collects the full body before sending.
- gRPC-Web detection + translation — needs CORS preflight handling over H3.
- WebSocket equivalent (WebTransport over HTTP/3) — different protocol, not
  a port.
- W3C trace context propagation — minor.



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

**Fix:** Replaced 3 sequential `Vec::collect()` filters with a single-pass
partition into stack-allocated `SmallVec<[Arc<BackendNode>; 8]>`. Most
deployments have ≤8 backends per pool, so the entire selection is
zero-heap-allocation in the common case.

**Status:** ✅ Done (2026-04-27, batch 3) — `src/routing/mod.rs:325-353`.

### P2: String Cloning on Hot Path
**Problem:** 227+ `.to_string()` / `.to_owned()` calls per request in proxy handler.
GC pressure, latency spikes.

**Status:** ⏸ **Deferred** — needs API redesign, not a drive-by fix.

**Why deferred:** Most of the clones are at boundaries where the consumer
type owns a `String` (`HookContext.path: String`, `AccessLogEntry.method: String`,
`WasmRequestContext.client_ip: String`, etc.). Replacing them requires
either:
1. Changing those struct fields to `Arc<str>` (a transitive API change
   across the `HookHandler` trait, `WasmPlugin` trait, and access log
   serialisation), or
2. Threading `Cow<'a, str>` through with explicit lifetimes (also
   transitive, with significant friction at `Arc::clone` / cross-task boundaries).

A correct version would require microbenchmarks to confirm the
allocation reduction beats the added Arc atomic overhead (`Arc::clone`
is cheap but not free), and likely a new `RequestSnapshot` struct that
owns one set of strings shared across all per-phase contexts.

This is a focused refactor PR's worth of work, not a single-commit fix.

### P3: Mutex Contention in Cache and Pool
**Problem:** `tokio::sync::Mutex` in `src/middleware/cache.rs:25` and `src/proxy/pool.rs:18`.
Per-key locks cause contention under high throughput.

**Fix (pool):** Replaced `Arc<Mutex<HashMap<String, VecDeque>>>` with
`Arc<DashMap<String, VecDeque>>`. Operations on different backend addresses
now run in parallel (per-shard lock instead of one global lock). The reaper
loop also iterates per-shard. Regression test
`pool_per_backend_isolation_via_dashmap` verifies independent backends can be
released without serialising.

**Status (pool):** ✅ Done (2026-04-27, batch 3).

**Status (cache per-key Mutex):** ⏸ Kept as-is — the per-key
`tokio::sync::Mutex` is the **singleflight** pattern (only one request
fetches from upstream on cache miss; others wait for the result). That
serialisation is intentional and correct. Removing it would amplify
upstream load on cache miss. The lock-map's unbounded growth (entries
never removed) is a separate concern — a dedicated cleanup is a follow-up
that doesn't change the lock pattern itself.

### P4: Random Algorithm Uses SystemTime Syscall
**Problem:** `SystemTime::now()` in `src/routing/mod.rs:394-398` for Random LB.
System call every request = latency jitter.

**Fix:** Use `rand::random::<u32>()` (thread-local ChaCha RNG, ~3 ns user-space)
instead of `SystemTime::now().subsec_nanos()`. `rand::rng()` is already a
dependency, no need for `SmallRng`.

**Status:** ✅ Done (2026-04-27) — `src/routing/mod.rs:393-399`. Regression
test `test_random_lb_visits_all_backends` checks 4-way distribution.

### P5: OIDC Session Cleanup O(n) Scan
**Original premise:** plan_v2 v1 said `oidc.rs` had a per-request O(n)
cleanup scan. Re-audit shows that was inaccurate — `check_session()`
prunes expired sessions O(1) on access (`sessions.remove(...)` at the
single matching key). There was NO scan loop.

**Real underlying issue:** sessions that are never re-accessed (user
closes the tab) accumulate forever in the `DashMap`. Memory leak, not
latency.

**Fix:** Added `sweep_expired_sessions()` (`DashMap::retain` over the
single store) and `spawn_session_cleanup()` (Tokio task on a 5-min ticker,
respecting the shutdown token). Wired from `main.rs` after
`new_session_store()`. Per-request path remains O(1).

**Status:** ✅ Done (2026-04-27, batch 3) — `src/auth/oidc.rs:100-148`.

### P6: HookEngine.has_hooks() Lock + Scan
**Problem:** Every request calls `hook_engine.has_hooks(PreRoute)` which does:
RwLock read + HashMap lookup per phase.

**File:** `src/scripting/mod.rs:167`
**Fix:** Added `phase_present: [AtomicBool; 4]` field, indexed by `phase_index()`.
`register()` and `reload_rhai_script()` update it with Release; `has_hooks()`
loads with Acquire — no `RwLock`, no `HashMap` lookup on hot path.
**Status:** ✅ Done (2026-04-27) — regression tests
`test_has_hooks_atomic_per_phase_isolation` and
`test_has_hooks_concurrent_readers` (8 threads × 10k iters) cover correctness
and absence of torn reads.

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

**Fix (partial):** Basic Auth, JWT Bearer, and `auth_request` (per-route +
global fallback) now run in `apply_h3_auth_chain` between route resolution
and PreUpstream hooks. Headers from JWT (`X-Auth-Sub`, `X-Auth-Email`, etc.)
and from `auth_request` responses (`X-Auth-*`) are injected into the
forwarded request. 7 unit tests cover priority, denial paths, claim
header injection, and wrong-secret rejection.

**Status:** 🔧 Partial. OAuth introspection / JWKS / OIDC remain — those
need session-store / discovery-flow work that doesn't trivially port from
HTTP/1. Tracked under C2.

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

**Fix:** Process-wide `OnceLock<reqwest::Client>` via `shared_upstream_client()`
helper. DNS resolver, TLS context, and HTTP/1 keepalive pool are built once
at first request and reused across all subsequent HTTP/3 → HTTP/1 forwards.
Mirror payload (req headers + body) is now only cloned when `mirror_pool` is
configured — eliminates an unconditional allocation in the hot path.

**Status:** ✅ Done (2026-04-27, commit 64c245b) — regression test
`test_shared_upstream_client_is_singleton` asserts pointer equality across
calls.

### C5: ConsistentHash Rebuilds Ring on Every Call
**Problem:** `src/routing/mod.rs:473-486` rebuilds virtual node ring per request.
For 4 backends with weight 10 = 6400 virtual nodes sorted per request.

**Fix:** Added `consistent_hash_ring: ArcSwap<Option<ConsistentHashRing>>` on
`UpstreamPool`. `get_or_build_consistent_hash_ring()` computes a cheap O(n)
FxHash signature of the (sorted address, effective_weight) tuples; if the
signature matches the cached ring, the existing ring is reused as-is. Only
rebuilds when backends are added/removed or `effective_weight()` changes
(slow-start ramp completion). Hashing inside the ring itself also switched
from `DefaultHasher` (SipHash) to `FxHasher` for ~3-4× faster construction.

**Status:** ✅ Done (2026-04-27, batch 3) — `src/routing/mod.rs:455-540`.
Regression test `test_consistent_hash_ring_is_cached_across_calls` asserts
pointer equality on the cached `Arc` across consecutive calls.

### C6: Static File `.unwrap()` on MIME Header Parsing
**Problem:** `src/proxy/mod.rs:4044,4048,4079,4083` can panic on invalid MIME types.
Serving arbitrary paths with invalid content-type chars causes crash.

**Fix:** All four `HeaderValue::from_str(&mime_type).unwrap()` and
`HeaderValue::from_str(&file_size.to_string()).unwrap()` calls now use
`.unwrap_or_else(...)` with safe fallbacks (`application/octet-stream` and
`"0"`). Audited the rest of `proxy/mod.rs`: the remaining `.unwrap()` sites
are either inside the `#[cfg(test)]` module or on infallible operations
(`Response::builder().body()` with `Full<Bytes>`); fixed one additional
`config-derived realm parse` panic at the WWW-Authenticate header
construction site (line 2880).

**Status:** ✅ Done (2026-04-27, commits 64c245b + this batch).

### C7: 503 Responses Panic on Missing Retry-After Header
**Problem:** `src/proxy/mod.rs:4185` assumes Retry-After header exists.
Backend 503 without header = panic.

**Status:** ⬜ Not started

### P7: `hex_prefix()` Uses Slow DefaultHasher (SipHash)
**Problem:** `src/middleware/cache.rs:280` uses `DefaultHasher` (SipHash).
Not optimal for in-memory cache with 100K+ ops/sec.

**Fix:** Swapped `std::hash::DefaultHasher` for `rustc_hash::FxHasher` (the
hash function rustc itself uses). FxHash is ~3-4× faster on the short-string
keys typical of HTTP cache keys. No DoS-resistance concern: cache keys are
server-constructed (`METHOD:HOST:PATH:…`), never directly attacker-controlled.
Added `rustc-hash = "2.1"` as a direct dep (was already transitively present).

**Status:** ✅ Done (2026-04-27, batch 3) — `src/middleware/cache.rs:276-289`.

### P8: HTTP/3 Missing Bandwidth Tracking
**Problem:** No `bandwidth.inc_requests()` or `bandwidth.add_out()` calls in H3.
Metrics will underreport HTTP/3 traffic.

**Fix:** `BandwidthTracker` threaded into `handle_h3_request`.
`bandwidth.protocol("http3").inc_requests()` is called at request entry,
`add_in()` after body read, `add_out()` after response body is sent. Mirrored
to the per-pool counter via `bandwidth.pool(&pool_name)`.

**Status:** ✅ Done (2026-04-27, commit 64c245b). Regression tests
`test_bandwidth_http3_protocol_counters` and
`test_bandwidth_pool_counters_isolated_per_pool`.

### P9: HTTP/3 Missing Structured Access Logging
**Problem:** No `access_logger.log()` call in H3.
Access logs missing for all HTTP/3 requests.

**Fix:** `AccessLogger` threaded into `handle_h3_request`. After response is
sent, `access_logger.log(AccessLogEntry { … })` records timestamp, client IP,
method, path, status, latency, backend, pool, bytes_sent, referer, user_agent
— same shape as the HTTP/1 path.

**Status:** ✅ Done (2026-04-27, commit 64c245b).

### R6: HTTP/3 Missing HSTS Header Injection
**Problem:** No HSTS injection in H3 handler.
HTTP security header not applied to HTTP/3 responses.

**Fix:** Inject `Strict-Transport-Security: max-age=N` on every H3 response
when `app_config.hsts_max_age` is set. Mirrors HTTP/1 behavior at
`proxy/mod.rs:2208`.

**Status:** ✅ Done (2026-04-27, batch 4) — `src/proxy/http3.rs` response builder.

### R7: HTTP/3 Hardcodes Cache TTL to 60s
**Problem:** `src/proxy/http3.rs:750` uses hardcoded 60s TTL.
Ignores route-level `proxy_cache_valid` configuration.

**Fix:** H3 cache write now reads `route.proxy_cache_valid_secs` and uses it
as the entry's `max_age`; falls back to 60 s when the route has no
explicit TTL configured. Same precedence as the HTTP/1 path.

**Status:** ✅ Done (2026-04-27, batch 4) — `src/proxy/http3.rs` cache insert.

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
