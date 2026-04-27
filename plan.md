# Phalanx — What's Next

Last updated: 2026-04-27 (W1 complete; v1.0.0 cut)

## What this batch closed
- ✅ H1 (dead-code) — `rate_limit_response` and `DEFAULT_SESSION_TIMEOUT`
  gated `#[cfg(test)]`; 8 unused `mut` removed. Zero warnings.
- ✅ H2 (Criterion bench) — `benches/hot_paths.rs` covers P1, P4, C5,
  P6, P2, P7. `cargo bench --bench hot_paths`.
- ✅ H3 (smoke H3) — optional `H3_PROXY` env; httpx client, UDP fallback.
- ✅ H4 (CI) — `.github/workflows/ci.yml` build + tests on push/PR.
- ✅ W2 (Wasm OnLog) — wired into HTTP/1, HTTP/2, AND HTTP/3 (the audit
  found OnLog had `execute_log` but no caller anywhere).
- ✅ C3 (pool release) — `PooledStream` RAII wrapper with Drop-based
  release; `take_stream()` for the explicit-discard path.
- ✅ W1 (WebTransport session protocol) — `enable_webtransport`,
  `enable_extended_connect`, `enable_datagram` advertised when the
  `webtransport on;` directive is set. Extended CONNECT for
  `:protocol = webtransport` is intercepted before request dispatch and
  handed to `proxy::wt::serve_session`. Echo-mode termination ships as
  v1: bidi streams, uni streams, and H3 datagrams are echoed back via
  three concurrent loops. Tunnel mode (plan's option b) is deliberately
  deferred — `h3-webtransport = 0.1.2` ships server-side APIs only.
- ✅ H5 (graph refresh) — `/graphify . --update` ran;
  2049 → 2142 nodes, 41 communities, `graph.html` regenerated.

**Test count:** 964 passing (735 unit + 226 integration + 1 doc + 2 WT
smoke). Zero production behaviour regressed.

## What's still open
Nothing tracked in this plan. The next chunk of work is whatever ships
on top of v1.0.0 — see `plan_v2.md` for historical context and any new
items the team adds.

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
**Problem (was):** `proxy/pool.rs::release` existed and `acquire()` was
wired, but Hyper took ownership of the `TcpStream` after handing it to
the request state machine, so connections were never returned to the
pool on error / cancellation paths.

**Fix shipped:** New `PooledStream` wrapper around `Option<TcpStream>`
implements `AsyncRead` + `AsyncWrite` (delegates to inner) so it's a
drop-in replacement when Hyper's `TokioIo` wraps it. `Drop::drop` calls
`pool.release_sync(addr, stream.take().unwrap())`. `take_stream()`
short-circuits the auto-release for the explicit-discard path
(non-empty `parts.read_buf` in the post-response handler).
`acquire_pooled()` returns `PooledStream`; both H1 and H2 backend-
connect call sites were switched to use it. Two regression tests with
real loopback listeners assert `idle_counts()` reflects the Drop-based
re-pool and the `take_stream()` short-circuit.

**Status:** ✅ Done (this batch).

---

## 🟡 MEDIUM — Feature completeness

### W1: WebTransport session protocol — ✅ Done (v1.0.0)
**What shipped:** WebTransport-over-HTTP/3 with echo-mode termination.
The H3 listener advertises `SETTINGS_ENABLE_WEBTRANSPORT = 1`,
`H3_DATAGRAM = 1`, and `ENABLE_CONNECT_PROTOCOL = 1` during the QUIC
handshake when `webtransport on;` is set. Extended CONNECT for
`:protocol = webtransport` is intercepted before the regular request
dispatch (the Hyper-style spawn path) and handed to
`proxy::wt::serve_session`, which calls `WebTransportSession::accept`
and runs three concurrent echo loops (bidi / uni / datagrams).

**Forwarding-semantics decision (W1.4):** echo-mode termination, not
tunnel. Reason: `h3-webtransport = 0.1.2` ships server-side APIs only —
no client. Tunnel mode (option b in this plan) requires implementing
the WT client over h3 primitives, a multi-day project of its own.
Pubsub termination (option a) requires designing an admin-API surface
for backends to fan-out from. Echo exercises the full wire path
(settings → Extended CONNECT → bidi/uni/datagram) end-to-end against
any real WT client today, and is the swap point when a Rust WT client
crate lands.

**Files touched:**
- `src/proxy/wt.rs` (new) — `serve_session`, `is_webtransport_request`,
  three echo loops, four unit tests.
- `src/proxy/mod.rs` — `pub mod wt;`.
- `src/proxy/http3.rs` — h3 server builder uses WT settings when
  `webtransport_enabled`; pre-spawn intercept for Extended CONNECT;
  501 fallback updated (`disabled` vs `not_implemented` per the
  protocol the client requested).
- `Cargo.toml` — `h3-quinn` gains `features = ["datagram"]`.
- `tests/wt_smoke.rs` (new) — settings-handshake smoke + gate-off path.

**Test coverage:** unit tests on the WT-request detector + SETTINGS
handshake completes against an h3 client + gate-off Extended CONNECT
does not return 200. End-to-end echo of bidi/uni/datagrams is covered
manually against real WT clients (Chrome DevTools, etc.) — h3 0.0.8's
client builder doesn't expose `enable_webtransport`, so a Rust test
client can't satisfy the server precondition; this is a known
ecosystem gap documented in `tests/wt_smoke.rs`.

**Follow-ups (not in this plan):**
- Tunnel mode when an h3 client crate lands.
- Pubsub termination if a use case materializes.
- Per-route `wt_mode` directive when there's more than one mode.

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

**Status:** ✅ Done (this batch).

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

**Status:** ✅ Done (this batch).

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

**Status:** ✅ Done (this batch).

### H3: HTTP/3 paths in `scripts/smoke_test.py`
**Problem:** The smoke test only exercises HTTP/1 endpoints. After 9
batches of H3 work it should validate the H3 listener too.

**Approach:** Add an optional `H3_PROXY=https://…:8443` env var; when set,
run a subset of the checks against H3 using `httpx[http2,http3]` (only
runtime dep) — proxy reachability, `x-proxy-by` header, simple GET.

**Files:** `scripts/smoke_test.py`.

**Status:** ✅ Done (this batch).

### H4: CI workflow
**Problem:** No `.github/workflows/` directory. Every commit currently
relies on local `cargo test`.

**Approach:** Add `.github/workflows/ci.yml` running `cargo build` +
`cargo test` (lib + integration) on each push to `main` and PR to `main`.
Cache the cargo registry + target dir.

**Files:** new `.github/workflows/ci.yml`.

**Status:** ✅ Done (this batch).

### H5: Refresh `graphify-out/`
**Problem (was):** The graph hadn't been re-built since batch 6
(commit `ee5ba41`). Several batches of code changes since. Per
`CLAUDE.md`, every change should trigger `/graphify . --update`.

**Fix shipped:** `/graphify . --update` ran across the 11 changed code
files + 4 changed docs from this batch. AST extracted 568 nodes /
1461 edges; semantic extraction (one general-purpose subagent) added
67 nodes / 98 edges over README/plan/plan_v2/CLAUDE — covering all
the H1–H5 / W1 / W2 / C3 items as proper graph nodes with
`rationale_for` / `semantically_similar_to` / `cites` edges to their
v2-counterpart items and to the dated batch-update notes in README.

**Result:** graph went from 2049 → **2142 nodes / 4670 edges /
41 communities**. New top god nodes: `url()`, `parse_phalanx_config()`,
`plan_v2.md`, `make_state()`, `handle_h3_request()`. `graph.html`
regenerated. `manifest.json` snapshot taken so the next `--update`
sees the right deltas.

**Files:** `graphify-out/` (gitignored, local only).

**Status:** ✅ Done (this batch).

---

## ❌ Out of scope (intentionally not tracked here)

- New LB algorithms beyond the current 8.
- HTTP/3 server push (deprecated by the spec).
- Multipath QUIC (different feature, not a parity gap).
- Migrating away from `reqwest` for upstream forwarding (large refactor;
  no concrete need right now).

---

## Execution order (closed)

All items shipped in the order below — leaving as-is for posterity.

1. **H5** ✅ refresh graph
2. **H1** ✅ dead-code cleanup
3. **H2** ✅ Criterion bench
4. **C3** ✅ pool release
5. **W2** ✅ Wasm OnLog/OnTick H3
6. **H3** ✅ H3 in smoke test
7. **H4** ✅ CI workflow
8. **W1** ✅ WebTransport (echo-mode v1)
