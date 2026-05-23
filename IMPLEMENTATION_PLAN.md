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
- [x] P1-4: Rate limiter zero-value hardening (`src/middleware/ratelimit.rs`)
  - Goal: Remove `unwrap()` panic path when config provides 0 values.
  - Validation: unit tests with zero values and successful construction.
  - Note: `build_inner()` already clamps per-IP rate/burst to 1 and disables global limiter on 0; `NonZeroU32` construction uses `unwrap_or(NonZeroU32::MIN)`. Existing tests (`test_rate_limiter_zero_values_are_sanitized`, `test_rate_limiter_zero_values_do_not_panic_or_block_all`) verify this.

## Phase 2: Parity follow-ups
- [x] P2-1: HTTP/3 middleware/security parity baseline (WAF/rate limit/geo/auth/captcha hooks)
  - Status: Fully wired. `handle_h3_request` runs WAF, rate limiting, GeoIP, auth (Basic/JWT/OAuth/JWKS/OIDC/auth_request), CAPTCHA/bot detection, zone connection limits, and all hook phases.
- [x] P2-2: Reload propagation to startup-initialized components (rate limiter/WAF policy/AI/geo/hook/captcha)
  - Status: Reload handler (`src/reload.rs`) propagates to rate limiter, WAF rules/policy, GeoIP DB, hook engine, zone limiter, and GSLB router. AI algorithm, CAPTCHA provider, Wasm plugins, K8s ingress, and ML model are documented as requiring restart.
- [x] P2-3: Unwired admin APIs / mail `starttls` follow-up
  - Status: **Admin APIs wired** — `POST/GET/DELETE /api/routes`, `POST/GET/DELETE /api/ssl`, and `GET /api/upstreams` are now registered in `start_admin_server()` with RBAC via `ExtendedAdminState`. Integration tests added for CRUD, RBAC enforcement, and auth rejection.
  - Status: **Mail backend STARTTLS implemented** — `negotiate_backend_starttls()` reads the backend banner, sends the protocol-specific command (`STARTTLS`/`STLS`), validates the acknowledgment, and upgrades to TLS via `build_backend_tls_connector()`. New config directive `mail_backend_starttls on;` enables it per protocol. Existing `verify_backend_tls` (immediate TLS wrap) is preserved for SMTPS/IMAPS/POP3S ports. Unit tests cover acknowledgment parsing for all three protocols and config parsing.

## Execution Log
- 2026-04-04: Plan created. Started P1-1.
- 2026-04-04: Completed P1-1 (HTTP/3 now reads and forwards request body; query string preserved on upstream URL).
- 2026-04-04: Started P1-2 (listener supervisor unexpected-exit restarts).
- 2026-04-04: Completed P1-2 (all listener supervisors now restart on unexpected exits with bounded backoff).
- 2026-04-04: Started P1-3 (strict-mode missing-config behavior).
- 2026-04-04: Completed P1-3 (strict mode now errors on unreadable/missing config files; added unit test).
- 2026-04-04: Started P1-4 (rate limiter zero-value hardening).
- 2026-05-23: Completed P1-4 (verified existing hardening and updated plan).
- 2026-05-23: Fixed compilation errors in `src/proxy/zero_copy.rs` caused by nix 0.31 API changes (`zerocopy` feature, `AsFd` trait, `Errno` type).
- 2026-05-23: Wired missing admin API endpoints (`/api/routes`, `/api/ssl`, `/api/upstreams`) with RBAC. Added 7 integration tests covering CRUD, permission enforcement, and unauthorized access.
