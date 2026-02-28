pub mod parser;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Defines the algorithm used to select a backend from an upstream pool.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default)]
pub enum LoadBalancingAlgorithm {
    /// Iterates through backends sequentially.
    #[default]
    RoundRobin,
    /// Selects the backend with the fewest active connections.
    LeastConnections,
    /// Hashes the client IP to consistently route to the same backend.
    IpHash,
    /// Randomly selects a healthy backend.
    Random,
    /// Uses backend weights to proportionately distribute traffic.
    WeightedRoundRobin,
    /// Uses reinforcement learning to dynamically route traffic based on latency and errors.
    AIPredictive,
}

/// Represents a single backend server within an upstream pool.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BackendConfig {
    pub address: String,
    pub weight: u32,
    /// Optional HTTP path to GET for health checks (e.g. "/health"). If None, TCP connect is used.
    pub health_check_path: Option<String>,
    /// Expected HTTP status code for a passing health check. Default: 200.
    pub health_check_status: u16,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            weight: 1,
            health_check_path: None,
            health_check_status: 200,
        }
    }
}

/// A pool of backend servers associated with a specific load balancing algorithm.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpstreamPoolConfig {
    pub algorithm: LoadBalancingAlgorithm,
    pub backends: Vec<BackendConfig>,
    /// Maximum number of idle keepalive connections per backend. 0 = disabled.
    pub keepalive: u32,
}

/// Configuration for a specific route (e.g., `/api` or `/static`).
/// Maps a request path to either an upstream pool or a static file root directory.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RouteConfig {
    pub upstream: Option<String>,
    pub root: Option<String>,
    pub fastcgi_pass: Option<String>,
    pub uwsgi_pass: Option<String>,
    pub add_headers: HashMap<String, String>,
    /// Ordered list of `(pattern, replacement, flag)` rewrite rules for this route.
    /// Applied before dispatching to a backend.
    pub rewrite_rules: Vec<(String, String, String)>,

    // ── Basic Auth ───────────────────────────────────────────────────────────
    /// The realm string shown to the client in the WWW-Authenticate challenge.
    /// Set to enable Basic Auth on this route.
    pub auth_basic_realm: Option<String>,
    /// Map of `username` → `password` (plaintext or bcrypt hash).
    pub auth_basic_users: HashMap<String, String>,

    // ── JWT Auth ─────────────────────────────────────────────────────────────
    /// HMAC secret or RSA public key for verifying JWT Bearer tokens.
    pub auth_jwt_secret: Option<String>,
    /// Algorithm for JWT verification. Default: `HS256`.
    /// Supported: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384.
    pub auth_jwt_algorithm: Option<String>,

    // ── OAuth 2.0 Introspection ──────────────────────────────────────────────
    /// RFC 7662 token introspection endpoint URL.
    pub auth_oauth_introspect_url: Option<String>,
    /// OAuth client ID used for introspection endpoint authentication.
    pub auth_oauth_client_id: Option<String>,
    /// OAuth client secret used for introspection endpoint authentication.
    pub auth_oauth_client_secret: Option<String>,

    // ── Gzip Compression ────────────────────────────────────────────────────
    /// Enable gzip compression for responses on this route. Default: false.
    pub gzip: bool,
    /// Minimum response body size in bytes to trigger compression. Default: 1024.
    pub gzip_min_length: usize,

    // ── Response Cache ───────────────────────────────────────────────────────
    /// Enable response caching for GET 200 responses on this route.
    pub proxy_cache: bool,
    /// Default TTL in seconds when backend sends no Cache-Control max-age. Default: 60.
    pub proxy_cache_valid_secs: u64,
}

/// The global application configuration state.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    pub proxy_bind: String,
    pub tcp_bind: String,
    pub admin_bind: String,
    pub workers: usize,
    /// Maps generic pool names (e.g., "default", "backend_api") to their configuration.
    pub upstreams: HashMap<String, UpstreamPoolConfig>,
    /// Maps request paths or hostnames to specific routing configurations and header injections.
    pub routes: HashMap<String, RouteConfig>,
    /// Path to the TLS certificate file (e.g., cert.pem)
    pub tls_cert_path: Option<String>,
    /// Path to the TLS private key file (e.g., key.pem)
    pub tls_key_path: Option<String>,
    /// How many requests per second to allow per unique IP
    pub rate_limit_per_ip_sec: Option<u32>,
    /// How many total burst requests an IP can instantly send before being bucket throttled
    pub rate_limit_burst: Option<u32>,
    #[serde(default)]
    pub waf_enabled: Option<bool>,
    #[serde(default)]
    pub waf_auto_ban_threshold: Option<u32>,
    #[serde(default)]
    pub waf_auto_ban_duration: Option<u64>,
    /// Epsilon value for the AI Predictive Router (0.0-1.0, e.g., 0.10 = 10% exploration)
    #[serde(default)]
    pub ai_epsilon: Option<f64>,
    /// AI algorithm selection: epsilon_greedy, ucb1, softmax, thompson_sampling
    #[serde(default)]
    pub ai_algorithm: Option<String>,
    /// Temperature for Softmax/Boltzmann AI router (higher = more exploration)
    #[serde(default)]
    pub ai_temperature: Option<f64>,
    /// Exploration constant for UCB1 AI router
    #[serde(default)]
    pub ai_ucb_constant: Option<f64>,
    /// Latency threshold (ms) for Thompson Sampling success/failure classification
    #[serde(default)]
    pub ai_thompson_threshold_ms: Option<f64>,
    /// The global DDoS panic mode rate limit limit per second across the entire proxy
    pub global_rate_limit_sec: Option<u32>,
    /// Path to write structured access logs. If None, access logging is disabled.
    pub access_log_path: Option<String>,
    /// Format of access log entries: "json" (default), "combined", or "common".
    pub access_log_format: Option<String>,
    /// Path to a CA certificate PEM file for verifying client TLS certificates (mTLS).
    /// When set, all TLS connections must present a valid client certificate.
    pub tls_ca_cert_path: Option<String>,
    /// Optional OTLP endpoint (e.g. http://127.0.0.1:4317) for trace export.
    pub otel_endpoint: Option<String>,
    /// Service name to emit in OpenTelemetry resources.
    pub otel_service_name: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "default".to_string(),
            UpstreamPoolConfig {
                algorithm: LoadBalancingAlgorithm::RoundRobin,
                keepalive: 0,
                backends: vec![
                    BackendConfig {
                        address: "127.0.0.1:8081".to_string(),
                        ..Default::default()
                    },
                    BackendConfig {
                        address: "127.0.0.1:8082".to_string(),
                        ..Default::default()
                    },
                ],
            },
        );

        let mut routes = HashMap::new();
        routes.insert(
            "/".to_string(),
            RouteConfig {
                upstream: Some("default".to_string()),
                ..Default::default()
            },
        );

        Self {
            proxy_bind: "0.0.0.0:8080".to_string(),
            tcp_bind: "0.0.0.0:5000".to_string(),
            admin_bind: "127.0.0.1:9090".to_string(), // fixed 127.0.0.0 to 127.0.0.1
            workers: 4,
            upstreams,
            routes,
            tls_cert_path: None,
            tls_key_path: None,
            rate_limit_per_ip_sec: None,
            rate_limit_burst: None,
            global_rate_limit_sec: None,
            waf_enabled: Some(false),
            waf_auto_ban_threshold: None,
            waf_auto_ban_duration: None,
            ai_epsilon: None,
            ai_algorithm: Some("none".to_string()),
            ai_temperature: None,
            ai_ucb_constant: None,
            ai_thompson_threshold_ms: None,
            access_log_path: None,
            access_log_format: None,
            tls_ca_cert_path: None,
            otel_endpoint: None,
            otel_service_name: None,
        }
    }
}

/// Synchronously loads and parses the given config path from the disk.
/// Panics immediately with a descriptive error if the config file is malformed
/// (e.g., missing semicolons, unbalanced braces, or unknown directives).
pub fn load_config(conf_path: &str) -> AppConfig {
    if let Ok(content) = std::fs::read_to_string(conf_path) {
        // Use our strict phalanx-syntax parser — panics on malformed config
        let phalanx_cfg = parser::parse_phalanx_config(&content)
            .unwrap_or_else(|e| panic!("Configuration error in '{conf_path}': {e}"));
        let mut app_cfg = AppConfig::default();

        if let Some(w) = phalanx_cfg.worker_threads {
            app_cfg.workers = w;
        }

        if let Some(t) = phalanx_cfg.tcp_listen {
            if t.contains(':') {
                app_cfg.tcp_bind = t;
            } else {
                app_cfg.tcp_bind = format!("0.0.0.0:{}", t);
            }
        }

        if let Some(a) = phalanx_cfg.admin_listen {
            if a.contains(':') {
                app_cfg.admin_bind = a;
            } else {
                app_cfg.admin_bind = format!("127.0.0.1:{}", a);
            }
        }

        if let Some(http) = phalanx_cfg.http {
            for server in http.servers {
                if let Some(listen) = server.listen {
                    app_cfg.proxy_bind = format!("0.0.0.0:{}", listen);
                }

                if server.ssl_certificate.is_some() {
                    app_cfg.tls_cert_path = server.ssl_certificate;
                }
                if server.ssl_certificate_key.is_some() {
                    app_cfg.tls_key_path = server.ssl_certificate_key;
                }
                if let Some(v) = server.directives.get("tls_ca_cert_path") {
                    app_cfg.tls_ca_cert_path = Some(v.clone());
                } else if let Some(v) = server.directives.get("ssl_client_certificate") {
                    app_cfg.tls_ca_cert_path = Some(v.clone());
                }
                if let Some(v) = server.directives.get("otel_endpoint") {
                    app_cfg.otel_endpoint = Some(v.clone());
                }
                if let Some(v) = server.directives.get("otel_service_name") {
                    app_cfg.otel_service_name = Some(v.clone());
                }

                // Parse rate limiting directives
                if let Some(v) = route_or_directive_u32(&server.directives, "rate_limit_per_ip") {
                    app_cfg.rate_limit_per_ip_sec = Some(v);
                }
                if let Some(v) = route_or_directive_u32(&server.directives, "rate_limit_burst") {
                    app_cfg.rate_limit_burst = Some(v);
                }
                if let Some(v) = route_or_directive_u32(&server.directives, "global_rate_limit") {
                    app_cfg.global_rate_limit_sec = Some(v);
                }

                // Parse WAF directives
                if let Some(v) = server.directives.get("waf_enabled") {
                    app_cfg.waf_enabled = Some(v == "true");
                }
                if let Some(v) =
                    route_or_directive_u32(&server.directives, "waf_auto_ban_threshold")
                {
                    app_cfg.waf_auto_ban_threshold = Some(v);
                }
                if let Some(v) = server.directives.get("waf_auto_ban_duration") {
                    if let Ok(val) = v.parse::<u64>() {
                        app_cfg.waf_auto_ban_duration = Some(val);
                    }
                }

                // Parse AI routing directives
                if let Some(v) = server.directives.get("ai_algorithm") {
                    app_cfg.ai_algorithm = Some(v.clone());
                }
                if let Some(v) = server.directives.get("ai_epsilon") {
                    if let Ok(val) = v.parse::<f64>() {
                        app_cfg.ai_epsilon = Some(val);
                    }
                }
                if let Some(v) = server.directives.get("ai_temperature") {
                    if let Ok(val) = v.parse::<f64>() {
                        app_cfg.ai_temperature = Some(val);
                    }
                }
                if let Some(v) = server.directives.get("ai_ucb_constant") {
                    if let Ok(val) = v.parse::<f64>() {
                        app_cfg.ai_ucb_constant = Some(val);
                    }
                }
                if let Some(v) = server.directives.get("ai_thompson_threshold_ms") {
                    if let Ok(val) = v.parse::<f64>() {
                        app_cfg.ai_thompson_threshold_ms = Some(val);
                    }
                }

                // Map phalanx-style route blocks into our RouteConfig hashmap
                for (path, route) in server.routes {
                    app_cfg.routes.insert(
                        path,
                        RouteConfig {
                            upstream: route.upstream,
                            root: route.root,
                            fastcgi_pass: route.fastcgi_pass,
                            uwsgi_pass: route.uwsgi_pass,
                            add_headers: route.add_headers,
                            rewrite_rules: route.rewrite_rules,
                            auth_basic_realm: route.auth_basic_realm,
                            auth_basic_users: route.auth_basic_users,
                            auth_jwt_secret: route.auth_jwt_secret,
                            auth_jwt_algorithm: route.auth_jwt_algorithm,
                            auth_oauth_introspect_url: route.auth_oauth_introspect_url,
                            auth_oauth_client_id: route.auth_oauth_client_id,
                            auth_oauth_client_secret: route.auth_oauth_client_secret,
                            gzip: route.gzip,
                            gzip_min_length: route.gzip_min_length,
                            proxy_cache: route.proxy_cache,
                            proxy_cache_valid_secs: route.proxy_cache_valid_secs,
                        },
                    );
                }
            }

            // Map parsed upstream blocks into AppConfig.upstreams
            for upstream in http.upstreams {
                let algorithm = match upstream.algorithm.as_deref() {
                    Some("roundrobin") | Some("round_robin") => LoadBalancingAlgorithm::RoundRobin,
                    Some("leastconnections") | Some("least_connections") => {
                        LoadBalancingAlgorithm::LeastConnections
                    }
                    Some("iphash") | Some("ip_hash") => LoadBalancingAlgorithm::IpHash,
                    Some("random") => LoadBalancingAlgorithm::Random,
                    Some("weighted") | Some("weighted_roundrobin") => {
                        LoadBalancingAlgorithm::WeightedRoundRobin
                    }
                    Some("ai") | Some("ai_predictive") => LoadBalancingAlgorithm::AIPredictive,
                    _ => LoadBalancingAlgorithm::RoundRobin,
                };
                let backends = upstream
                    .servers
                    .into_iter()
                    .map(|(addr, weight)| BackendConfig {
                        address: addr,
                        weight,
                        health_check_path: upstream.health_check_path.clone(),
                        health_check_status: upstream.health_check_status,
                    })
                    .collect();
                app_cfg.upstreams.insert(
                    upstream.name,
                    UpstreamPoolConfig {
                        algorithm,
                        backends,
                        keepalive: upstream.keepalive,
                    },
                );
            }
        }
        tracing::info!("Loaded config from {}", conf_path);
        app_cfg
    } else {
        tracing::warn!("Could not find {}, using default config", conf_path);
        AppConfig::default()
    }
}

/// Helper to extract a u32 directive from the server block's directives map.
fn route_or_directive_u32(directives: &HashMap<String, String>, key: &str) -> Option<u32> {
    directives.get(key).and_then(|v| v.parse::<u32>().ok())
}
