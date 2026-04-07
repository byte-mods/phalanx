//! # Phalanx AI Load Balancer
//!
//! A high-performance reverse proxy and API gateway written in Rust,
//! featuring AI-driven routing, a WAF with ML fraud detection, GSLB,
//! Kubernetes ingress control, Wasm/Rhai scripting, and multi-protocol
//! support (HTTP/1.1, HTTP/2, HTTP/3/QUIC, gRPC-Web, WebSocket, TCP,
//! UDP, SMTP, IMAP, POP3).
//!
//! ## Architecture
//!
//! The crate is organised into feature modules that are wired together
//! in `main.rs`. Shared state is passed via `Arc` and hot-reloaded
//! through `ArcSwap` on SIGHUP.
//!
//! ## Key modules
//!
//! | Module       | Purpose |
//! |-------------|---------|
//! | `proxy`     | Core request handling, TLS, and protocol proxies |
//! | `routing`   | Upstream pool management and load-balancing algorithms |
//! | `ai`        | AI/ML-based routing (epsilon-greedy, Thompson sampling, UCB) |
//! | `waf`       | Web Application Firewall with rule engine and reputation tracking |
//! | `admin`     | Admin API, dashboard, Prometheus metrics |
//! | `config`    | Nginx-style config file parser |
//! | `discovery` | RocksDB-backed service discovery with DNS/SRV watchers |
//! | `gslb`      | Global Server Load Balancing across data centers |
//! | `k8s`       | Kubernetes Ingress and Gateway API controller |
//! | `wasm`      | Proxy-Wasm plugin framework for extensibility |
//! | `telemetry` | Logging, OpenTelemetry tracing, and bandwidth monitoring |

/// Admin API server, Prometheus metrics, dashboard endpoints, and alert engine.
pub mod admin;
/// AI-driven routing algorithms (epsilon-greedy, Thompson sampling, UCB, softmax).
pub mod ai;
/// Authentication: JWT/JWKS validation and OpenID Connect (OIDC) support.
pub mod auth;
/// Distributed cluster state (Redis, etcd, gossip protocol, or standalone).
pub mod cluster;
/// Nginx-style configuration file parser and `AppConfig` definition.
pub mod config;
/// RocksDB-backed service discovery with DNS A/AAAA and SRV record watchers.
pub mod discovery;
/// GeoIP database, country-based access policies, and header enrichment.
pub mod geo;
/// Global Server Load Balancing for geographic traffic steering across data centers.
pub mod gslb;
/// Kubernetes Ingress v1 and Gateway API controller with route reconciliation.
pub mod k8s;
/// In-memory key-value store with per-entry TTL and optional Redis cluster sync.
pub mod keyval;
/// Mail protocol proxy for SMTP, IMAP, and POP3 with banner injection.
pub mod mail;
/// HTTP middleware: response caching, rate limiting, and connection limits.
pub mod middleware;
/// Core reverse proxy: HTTP handler, TLS, TCP/UDP, gRPC-Web, HTTP/3, and more.
pub mod proxy;
/// SIGHUP-driven hot-reload handler for zero-downtime config changes.
pub mod reload;
/// Route matching, upstream pool management, and load-balancing strategies.
pub mod routing;
/// Rhai scripting engine and hook-based request interception.
pub mod scripting;
/// Telemetry: structured access logs, OpenTelemetry tracing, bandwidth monitoring.
pub mod telemetry;
/// Web Application Firewall: rule engine, bot detection, CAPTCHA, ML fraud, and IP reputation.
pub mod waf;
/// Proxy-Wasm plugin framework for extensible request/response processing.
pub mod wasm;
