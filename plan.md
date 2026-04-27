# Phalanx — What's Next

Last updated: 2026-04-27 (after plan.md execution batch / commit pending)

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
- 🔧 W1 (WebTransport scaffold) — config gate `webtransport_enabled`
  shipped; H3 detection now reports `enabled_pending_implementation`
  vs `not_implemented` based on the flag. Session protocol (W1.1–W1.6)
  remains as the **only** open item from this plan.
- ✅ H5 (graph refresh) — `/graphify . --update` ran;
  2049 → 2142 nodes, 41 communities, `graph.html` regenerated.

**Test count:** 957 passing (731 unit + 226 integration). Zero
production behaviour broke during the refactors; both new pool tests
plus all earlier batches still green.

## What's still open
The only remaining item from this plan is the WebTransport
**session-protocol** implementation (W1.1–W1.6 below). The scaffold
(config gate, detection, structured response header) is in. Each of
W1.1–W1.6 is genuinely a separate-PR-sized piece of work, with W1.4
gated on a real forwarding-semantics design decision.

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

### W1: WebTransport session protocol
**Problem:** Detection ships (501 + `phalanx-webtransport-status` header).
The actual session protocol — Extended CONNECT negotiation, bidirectional
streams, unidirectional streams, HTTP/3 datagrams,
`SETTINGS_ENABLE_WEBTRANSPORT` — is not implemented.

**Status:** 🔧 In progress (scaffold landed; session protocol pending).

**Scaffold landed in this batch:**
- New config flag `webtransport_enabled` (default `false`) parsed from
  the `webtransport on;` directive in `phalanx.conf`. When `false`, the
  H3 listener responds 501 with
  `phalanx-webtransport-status: not_implemented` (unchanged behaviour).
  When `true`, the same 501 is returned but the header reads
  `enabled_pending_implementation` so operators can verify the gate
  and the future implementation path.
- Forward-looking gate: when the session protocol lands, it'll consume
  this flag instead of introducing a new one.

**Remaining work — concrete sub-tasks:**
- W1.1 Add `h3-webtransport = "0.1.x"` (experimental crate). Audit
  version compatibility against the pinned `h3 = "0.0.8"` and `quinn`.
  Pin both ends.
- W1.2 Send `SETTINGS_ENABLE_WEBTRANSPORT = 1`, `H3_DATAGRAM = 1`,
  `ENABLE_CONNECT_PROTOCOL = 1` from the H3 server during the QUIC
  handshake.
- W1.3 Replace the current 501 short-circuit when `webtransport_enabled`:
  detect Extended CONNECT with `:protocol = webtransport`, accept the
  session, return 200 on the request stream, hand control to a per-
  session task.
- W1.4 **Forwarding-semantics design decision** (still open):
    a. Terminate WT in Phalanx (publish/subscribe model — backend pushes
       to Phalanx admin API which fans out)
    b. Tunnel WT to a backend that also speaks WT (transparent proxy —
       Phalanx opens a WT session to the upstream and pipes streams)
    c. Both, configured per route via `wt_mode terminate|tunnel;`
- W1.5 Stream lifecycle: forward client bidi/uni streams to upstream,
  plumb datagrams, propagate close-codes correctly.
- W1.6 Tests against a real WT client (e.g. quiche-client or a Chromium
  smoke test).

**Why each remaining sub-task is its own commit:** W1.1 + W1.2 +
session-accept (W1.3) without a forwarding model produces an "accepted
but data-less" session — worse than the current honest 501. Need to
ship at least one forwarding mode (W1.4 + W1.5) in the same PR as the
acceptance code.

**Files:** `src/proxy/http3.rs` (new module `wt.rs` likely), `Cargo.toml`,
`src/config/mod.rs` (already gated), `src/config/parser.rs`.

**Estimated effort:** 1–2 focused days of work + the W1.4 design decision.

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

## Suggested execution order

1. **H5** (refresh graph) — required by CLAUDE.md before any other task.
2. **H1** (dead-code cleanup) — quick, removes noise.
3. **H2** (Criterion bench) — establishes baseline before C3 refactor.
4. **C3** (pool release) — guided by the new bench numbers.
5. **W2** (Wasm OnLog/OnTick H3) — small parity gap, cheap to close.
6. **H3** (H3 in smoke test) — validates the long arc of H3 work.
7. **H4** (CI workflow) — protects future work.
8. **W1** (WebTransport) — biggest item, take last with the most context.
