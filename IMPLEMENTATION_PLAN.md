# Phalanx Issue Remediation Plan

Last updated: 2026-04-04

## Status Legend
- `[ ]` Not started
- `[-]` In progress
- `[x]` Completed
- `[!]` Blocked / needs follow-up

## Phase 1: Stability and correctness
- [x] P1-1: HTTP/3 request body forwarding (`src/proxy/http3.rs`)
  - Goal: Read inbound HTTP/3 request body frames and forward bytes upstream.
  - Validation: compile + tests; body-bearing methods (POST/PUT/PATCH) no longer drop body.
- [x] P1-2: Listener supervisor resilience (`src/main.rs`)
  - Goal: Auto-restart listener tasks when they exit unexpectedly (bind failure/crash), not only on config change.
  - Validation: compile + tests; restart loop with bounded backoff.
- [x] P1-3: Strict config policy for missing file (`src/config/mod.rs`)
  - Goal: In `strict` mode, missing config file returns `Err` instead of defaults.
  - Validation: unit test for strict missing-file path.
- [-] P1-4: Rate limiter zero-value hardening (`src/middleware/ratelimit.rs`)
  - Goal: Remove `unwrap()` panic path when config provides 0 values.
  - Validation: unit tests with zero values and successful construction.

## Phase 2: Parity follow-ups
- [ ] P2-1: HTTP/3 middleware/security parity baseline (WAF/rate limit/geo/auth/captcha hooks)
- [ ] P2-2: Reload propagation to startup-initialized components (rate limiter/WAF policy/AI/geo/hook/captcha)
- [ ] P2-3: Unwired admin APIs / mail `starttls` follow-up

## Execution Log
- 2026-04-04: Plan created. Started P1-1.
- 2026-04-04: Completed P1-1 (HTTP/3 now reads and forwards request body; query string preserved on upstream URL).
- 2026-04-04: Started P1-2 (listener supervisor unexpected-exit restarts).
- 2026-04-04: Completed P1-2 (all listener supervisors now restart on unexpected exits with bounded backoff).
- 2026-04-04: Started P1-3 (strict-mode missing-config behavior).
- 2026-04-04: Completed P1-3 (strict mode now errors on unreadable/missing config files; added unit test).
- 2026-04-04: Started P1-4 (rate limiter zero-value hardening).
