# Phalanx — What's Next

Last updated: 2026-04-27 (after batch 9 / commit `899de22`)

## Status Legend
- ⬜ Not started
- 🔧 In progress
- 🧪 Testing
- ✅ Done

## Context
- 955 tests passing (729 unit + 226 integration).
- HTTP/3 now matches HTTP/1 for every shipped feature except WebTransport.
- Historical work is recorded in `plan_v2.md` (v2 audit, 9 batches done).
- This file lists only **what still needs doing**, in priority order.

---

## 🔴 CRITICAL — Production correctness

### C3: Connection pool `release()` never called
**Problem:** `proxy/pool.rs::release` exists and `acquire()` is wired, but
Hyper takes ownership of the `TcpStream` after handing it to the request
state machine, so connections are never returned to the pool. Sustained
high-QPS workloads pay the TCP handshake cost on every request.

**Approach:**
1. Wrap the acquired stream in a small RAII guard
   (`PooledStream { inner: TcpStream, addr: String, pool: Arc<ConnectionPool> }`)
   that calls `pool.release(addr, inner)` in its `Drop` impl.
2. Hyper's `hyper_util::client::legacy::connect::Connection` trait can
   wrap arbitrary streams — implement it for `PooledStream` so Hyper
   accepts it without further changes.
3. Add a benchmark first to **prove** the impact before refactoring; if
   the keep-alive path is rarely hit in real workloads the priority drops.

**Verify:** new integration test that drives N requests against a single
backend and asserts `pool.idle_counts()` is non-zero after the run; full
suite green.

**Files:** `src/proxy/pool.rs`, `src/proxy/mod.rs` (per-backend dispatch).

**Status:** ⬜

---

## 🟡 MEDIUM — Feature completeness

### W1: WebTransport session protocol
**Problem:** Detection ships (501 + `phalanx-webtransport-status: not_implemented`).
The actual session protocol — Extended CONNECT negotiation, bidirectional
streams, unidirectional streams, HTTP/3 datagrams,
`SETTINGS_ENABLE_WEBTRANSPORT` — is not implemented.

**Approach:**
1. Add `h3-webtransport = "0.1"` (experimental crate). Pin and audit.
2. Settings: send `SETTINGS_ENABLE_WEBTRANSPORT = 1`, `H3_DATAGRAM = 1`,
   `ENABLE_CONNECT_PROTOCOL = 1` from the H3 server.
3. Detect Extended CONNECT with `:protocol = webtransport` (replace the
   current 501 short-circuit), accept the session, return 200 on the
   request stream.
4. Forwarding semantics — **the open design question.** Options:
   a. Terminate WT in Phalanx (publish/subscribe model with backend
      pushing data via Phalanx admin API)
   b. Tunnel WT to a backend that also speaks WT (transparent proxy
      model)
   c. Both, configured per route
5. Stream lifecycle: forward client streams to upstream, plumb datagrams,
   handle close-codes correctly.

**Why deferred so far:** ~1-2 days of focused work plus a design
decision on (4). Not single-session sized.

**Files:** `src/proxy/http3.rs` (new module `wt.rs` likely), `Cargo.toml`.

**Status:** ⬜

### W2: Wasm `OnLog` / `OnTick` phases for HTTP/3
**Problem:** HTTP/3 wires `OnRequestHeaders` and `OnResponseHeaders` but
not `OnLog` (post-response auditing) or `OnTick` (background timer).
HTTP/1 wires all four.

**Approach:** Mirror HTTP/1's `OnLog` invocation site (already runs after
the response is sent). For `OnTick`, the existing tick task in
`WasmPluginManager` already runs globally — just verify H3 plugins are
included in the iteration.

**Files:** `src/proxy/http3.rs` (after access log call), `src/wasm/mod.rs`
(verify tick scope).

**Status:** ⬜

---

## 🟢 LOW — Hygiene / observability

### H1: Dead-code warnings cleanup
**Problem:** Build emits these on every `cargo build`:
- `src/proxy/mod.rs:180` — `rate_limit_response` never used
- `src/proxy/udp.rs:27` — `DEFAULT_SESSION_TIMEOUT` never used
- `src/proxy/pool.rs:180-181` — two `let mut` that don't need `mut`
- `tests/proxy_test.rs` — 8 `unused_mut` on test bindings

**Approach:** Delete the dead helpers (or wire them if intentional) and
strip the unnecessary `mut`. Single commit.

**Files:** as listed above.

**Status:** ⬜

### H2: Criterion bench harness
**Problem:** Several recent perf wins (P1, P3-pool, P4, P6, C5, P7, P2)
shipped without before/after numbers. "Bare-metal performance" claims
need bench backing.

**Approach:**
1. Add `[dev-dependencies] criterion = "0.5"` and a `[[bench]]` entry.
2. Microbenches in `benches/`:
   - `routing_get_next_backend` (P1, C5)
   - `cache_hex_prefix` (P7)
   - `hookengine_has_hooks` (P6)
   - `pool_acquire_release` (P3)
   - `random_lb_pick` (P4)
   - `hookcontext_construct` (P2 — measure clones-per-request)
3. Document baseline numbers in `bench_baseline.md` so future work has
   a reference.

**Files:** new `benches/` directory, `Cargo.toml`.

**Status:** ⬜

### H3: HTTP/3 paths in `scripts/smoke_test.py`
**Problem:** The smoke test only exercises HTTP/1 endpoints. After 9
batches of H3 work it should validate the H3 listener too.

**Approach:** Add an optional `H3_PROXY=https://…:8443` env var; when set,
run a subset of the checks against H3 using `httpx[http2,http3]` (only
runtime dep) — proxy reachability, `x-proxy-by` header, simple GET.

**Files:** `scripts/smoke_test.py`.

**Status:** ⬜

### H4: CI workflow
**Problem:** No `.github/workflows/` directory. Every commit currently
relies on local `cargo test`.

**Approach:** Add `.github/workflows/ci.yml` running `cargo build` +
`cargo test` (lib + integration) on each push to `main` and PR to `main`.
Cache the cargo registry + target dir.

**Files:** new `.github/workflows/ci.yml`.

**Status:** ⬜

### H5: Refresh `graphify-out/`
**Problem:** The graph hasn't been re-built since batch 6
(commit `ee5ba41`). 3 batches of code changes since. Per the new
`CLAUDE.md`, every change should trigger `/graphify . --update`.

**Approach:** Run `/graphify . --update`. One-off chore.

**Files:** `graphify-out/` (gitignored, local only).

**Status:** ⬜

---

## ❌ Out of scope (intentionally not tracked here)

- New LB algorithms beyond the current 8.
- HTTP/3 server push (deprecated by the spec).
- Multipath QUIC (different feature, not a parity gap).
- Migrating away from `reqwest` for upstream forwarding (large refactor;
  no concrete need right now).

---

## Suggested execution order

1. **H5** (refresh graph) — required by CLAUDE.md before any other task.
2. **H1** (dead-code cleanup) — quick, removes noise.
3. **H2** (Criterion bench) — establishes baseline before C3 refactor.
4. **C3** (pool release) — guided by the new bench numbers.
5. **W2** (Wasm OnLog/OnTick H3) — small parity gap, cheap to close.
6. **H3** (H3 in smoke test) — validates the long arc of H3 work.
7. **H4** (CI workflow) — protects future work.
8. **W1** (WebTransport) — biggest item, take last with the most context.
