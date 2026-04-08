# Phalanx Gap Fix Plan

Last updated: 2026-04-08

## Status Legend
- ⬜ Not started
- 🔧 In progress
- ✅ Done
- 🧪 Testing

---

## P0 — Critical: Dead Code / Broken Wiring

### Task 1: Fix Zone Limiter Reload (hardcoded → config)
- **Problem**: `reload.rs:124` passes `(1_000_000, 1_000_000, 0)` instead of config values. No `zone_*` fields in AppConfig/parser.
- **Fix**: Add zone config fields → parser directives → reload reads config → main.rs uses config at init.
- **Verify**: `cargo test`, new unit tests for parse + reload path.
- **Status**: ✅

### Task 2: Invoke PostUpstream Hook Phase
- **Problem**: `HookPhase::PostUpstream` defined but never called in any proxy handler.
- **Fix**: Add `hook_engine.execute(PostUpstream, ...)` after backend response in HTTP/1, HTTP/2, HTTP/3 handlers.
- **Verify**: `cargo test`, new test that PostUpstream hook fires.
- **Status**: ✅

### Task 3: Fix CLAUDE.md Reload Table
- **Problem**: CLAUDE.md says rate limiter/WAF/GeoIP/hooks NOT reloadable. `reload.rs` proves they ARE.
- **Fix**: Correct the SIGHUP Reload Scope table.
- **Verify**: Manual cross-reference against `reload.rs`.
- **Status**: ✅

---

## P1 — High: Feature Gaps

### Task 4: WAF Policy Engine — Enforce Signature Sets
- **Problem**: `policy.rs evaluate()` ignores `signature_sets`; only checks custom rules.
- **Fix**: In `evaluate()`, iterate signature sets and match against request path/UA/body.
- **Verify**: Unit test: OWASP signature set blocks SQLi/XSS patterns.
- **Status**: ✅

### Task 5: Wire `split_traffic()` Into Proxy Pipeline
- **Problem**: `mirror::split_traffic()` implemented + tested but never called in proxy handlers.
- **Fix**: Add config field for split weights, call `split_traffic()` in routing to select pool.
- **Verify**: Test that weighted traffic split routes to correct pools.
- **Status**: ✅

### Task 6: HTTP/1 Backend Connection Pooling
- **Problem**: Initially thought unused in HTTP/1. Actually `acquire()` IS used (line 1921).
  `release()` never called — hyper takes ownership of TcpStream. Arch limitation.
- **Status**: ✅ (acquire wired; release needs hyper pooling refactor — out of scope)

### Task 7: PROXY Protocol v2 in TCP Proxy
- **Problem**: PP2 parsed in HTTP mux (mod.rs:487) but not in `tcp.rs`.
- **Fix**: Add PP2 header detection at TCP proxy accept, extract real peer IP.
- **Verify**: Unit test PP2 parsing in TCP path.
- **Status**: ✅

---

## P2 — Medium: Correctness & Robustness

### Task 8: Replace Dangerous `.unwrap()` on Config-Derived Headers
- **Problem**: CORS headers in proxy/mod.rs use `.parse().unwrap()` on user config. Crash on bad input.
- **Fix**: Validate at config parse time, or use `unwrap_or_default()` at use site.
- **Verify**: Test with malformed CORS config, verify no panic.
- **Status**: ✅

### Task 9: Fix Stale HTTP/2 Handler Comments
- **Problem**: Comments say HTTP/2 lacks Brotli + mirroring. Both are implemented.
- **Fix**: Remove/correct misleading comments.
- **Verify**: Visual.
- **Status**: ✅

### Task 10: GSLB Country Mapping — Complete Coverage
- **Problem**: Only ~50 of ~195 countries mapped. Unknown defaults to NorthAmerica.
- **Fix**: Add remaining ISO 3166-1 alpha-2 country→region mappings.
- **Verify**: Test all major countries resolve correctly.
- **Status**: ✅

### Task 11: WAF ML Fraud — Fallback Alerting
- **Problem**: When ONNX model fails to load, silent fallback to rule-based. No alert/metric.
- **Fix**: Add tracing::warn on model load failure, increment a metric counter.
- **Verify**: Test that missing model produces warning log.
- **Status**: ✅

---

## Execution Rules
1. Complete one task fully (implement + test + cargo test passes) before moving to next.
2. After each task, update this file's status.
3. If cargo test regresses, fix before proceeding.
