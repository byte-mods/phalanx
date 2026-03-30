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
    /// Uses consistent hashing on client IP, keeping a client routed to the same backend.
    ConsistentHash,
    /// Selects the backend with the lowest combined active connections and recent latency.
    LeastTime,
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
    /// How many consecutive proxy failures before marking this backend DOWN. Default: 3.
    pub max_fails: u32,
    /// Time window (secs) in which max_fails must occur to trip the circuit. Default: 30.
    pub fail_timeout_secs: u64,
    /// Slow-start ramp-up duration in seconds after a backend recovers. 0 = disabled.
    pub slow_start_secs: u32,
    /// If true, this backend is only used when all non-backup backends are DOWN.
    pub backup: bool,
    /// Maximum concurrent connections allowed to this backend. 0 = unlimited.
    pub max_conns: u32,
    /// Queue size when max_conns is reached. Requests wait up to `queue_timeout_ms`. 0 = no queue.
    pub queue_size: u32,

    // ── Circuit Breaker ──────────────────────────────────────────────────────
    /// Enable the exponential-backoff circuit breaker for this backend. Default: false.
    pub circuit_breaker: bool,
    /// Initial backoff duration (secs) when circuit trips to OPEN. Doubles on each re-trip.
    /// Default: 5.
    pub circuit_initial_backoff_secs: u64,
    /// Maximum backoff duration (secs) the circuit will wait before probing. Default: 60.
    pub circuit_max_backoff_secs: u64,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            weight: 1,
            health_check_path: None,
            health_check_status: 200,
            max_fails: 3,
            fail_timeout_secs: 30,
            slow_start_secs: 0,
            backup: false,
            max_conns: 0,
            queue_size: 0,
            circuit_breaker: false,
            circuit_initial_backoff_secs: 5,
            circuit_max_backoff_secs: 60,
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
    /// Optional DNS SRV name to watch for dynamic backend discovery.
    /// Format: `_service._proto.domain` e.g. `_http._tcp.myservice.local`
    /// When set, backends from SRV records are added/removed every 30s.
    #[serde(default)]
    pub srv_discover: Option<String>,
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
    /// Enable Brotli compression for this route (in addition to gzip).
    pub brotli: bool,
    /// auth_request subrequest URL for this route.
    pub auth_request_url: Option<String>,
    /// Mirror pool name for traffic tee on this route.
    pub mirror_pool: Option<String>,

    // ── JWKS-based JWT Auth ──────────────────────────────────────────────────
    /// JWKS endpoint URI for dynamic public key fetching (RS256/ES256).
    /// When set, replaces static `auth_jwt_secret` with remote JWKS key lookup.
    #[serde(default)]
    pub auth_jwks_uri: Option<String>,

    // ── OIDC Session Auth ────────────────────────────────────────────────────
    /// OIDC issuer URL (e.g. https://accounts.google.com). When set with
    /// `auth_oidc_cookie_name`, enables OIDC session validation on this route.
    #[serde(default)]
    pub auth_oidc_issuer: Option<String>,
    /// Cookie name that holds the OIDC session ID. Default: "phalanx_oidc".
    #[serde(default)]
    pub auth_oidc_cookie_name: Option<String>,
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
    /// UDP bind address for the HTTP/3 QUIC server (e.g. "0.0.0.0:8443").
    /// When None (default), HTTP/3 is disabled.
    pub quic_bind: Option<String>,
    /// DNS resolver address (e.g. "8.8.8.8:53") for resolving hostnames in upstream blocks.
    /// When set, hostname-based backends are watched for DNS changes every 30 seconds.
    pub dns_resolver: Option<String>,
    /// UDP bind address for the UDP stream proxy (e.g. "0.0.0.0:5353").
    pub udp_bind: Option<String>,
    /// Trusted proxy CIDR list for X-Forwarded-For / PROXY protocol real IP extraction.
    pub trusted_proxies: Vec<String>,
    /// Path to a GeoIP CSV database file.
    pub geoip_db_path: Option<String>,
    /// GeoIP allow-list of country codes (empty = allow all).
    pub geo_allow_countries: Vec<String>,
    /// GeoIP deny-list of country codes.
    pub geo_deny_countries: Vec<String>,
    /// Path to the disk cache directory for the advanced cache tier.
    pub cache_disk_path: Option<String>,
    /// Enable Brotli compression (in addition to gzip). Default: false.
    pub brotli_enabled: bool,
    /// auth_request subrequest URL (per-route override is also possible).
    pub auth_request_url: Option<String>,
    /// Mirror/shadow upstream pool name for traffic tee.
    pub mirror_pool: Option<String>,
    /// Enable PROXY Protocol v2 parsing on incoming connections.
    /// When true, the PP2 header is stripped and the real client IP extracted.
    #[serde(default)]
    pub proxy_proto_v2: bool,
    /// Path to a Rhai script file to run as a pre-upstream request hook.
    /// The script receives `uri`, `method`, `client_ip`, `headers`, `status`.
    #[serde(default)]
    pub rhai_script: Option<String>,
    /// Default TTL in seconds for keyval store entries. 0 = no expiry.
    #[serde(default)]
    pub keyval_ttl_secs: u64,
    /// Auto-SSL domain to request Let's Encrypt certificates for.
    pub auto_ssl_domain: Option<String>,
    /// Contact email for Let's Encrypt registration.
    pub auto_ssl_email: Option<String>,
    /// Cache directory for Let's Encrypt certificates.
    pub auto_ssl_cache_dir: Option<String>,
    /// Redis connection URL for cluster state sharing.
    pub redis_url: Option<String>,
    /// SMTP proxy bind address (e.g. "0.0.0.0:25"). Enables mail proxy for SMTP when set.
    #[serde(default)]
    pub smtp_bind: Option<String>,
    /// IMAP proxy bind address (e.g. "0.0.0.0:143"). Enables mail proxy for IMAP when set.
    #[serde(default)]
    pub imap_bind: Option<String>,
    /// POP3 proxy bind address (e.g. "0.0.0.0:110"). Enables mail proxy for POP3 when set.
    #[serde(default)]
    pub pop3_bind: Option<String>,
    /// Upstream pool name for mail proxies. Defaults to "default".
    #[serde(default)]
    pub mail_upstream_pool: Option<String>,
    /// WAF policy file path (JSON format, NGINX App Protect-style). Optional.
    #[serde(default)]
    pub waf_policy_path: Option<String>,

    // ── OCSP Stapling ────────────────────────────────────────────────────────
    /// Override OCSP responder URL (normally extracted from the cert AIA extension).
    #[serde(default)]
    pub ocsp_responder_url: Option<String>,

    // ── Cluster State ────────────────────────────────────────────────────────
    /// etcd v3 endpoint list (comma-separated). When set, enables etcd-backed cluster state.
    /// Example: "http://etcd1:2379,http://etcd2:2379"
    #[serde(default)]
    pub etcd_endpoints: Option<String>,
    /// Node identifier for this Phalanx instance in a cluster. Defaults to hostname.
    #[serde(default)]
    pub node_id: Option<String>,

    // ── Gossip Protocol ─────────────────────────────────────────────────────
    /// UDP bind address for gossip protocol (e.g., "0.0.0.0:7946").
    /// When set, enables gossip-based cluster state sync.
    #[serde(default)]
    pub gossip_bind: Option<String>,
    /// Comma-separated list of seed peer addresses for gossip protocol.
    #[serde(default)]
    pub gossip_seed_peers: Option<String>,
    /// Gossip round interval in milliseconds. Default: 1000.
    #[serde(default)]
    pub gossip_interval_ms: Option<u64>,

    // ── ML Fraud Detection ───────────────────────────────────────────────────
    /// Path to an ONNX model file for ML-based fraud detection.
    /// When set, the ML fraud engine is started at launch.
    #[serde(default)]
    pub ml_fraud_model_path: Option<String>,
    /// ML fraud detection mode: "shadow" (log only) or "active" (auto-ban). Default: shadow.
    #[serde(default)]
    pub ml_fraud_mode: Option<String>,

    // ── CAPTCHA Bot Challenge ───────────────────────────────────────────────
    /// CAPTCHA site key (provider-specific). When set, enables bot CAPTCHA challenges.
    #[serde(default)]
    pub captcha_site_key: Option<String>,
    /// CAPTCHA secret key for server-side verification.
    #[serde(default)]
    pub captcha_secret_key: Option<String>,
    /// CAPTCHA provider: "hcaptcha" (default), "turnstile", "recaptcha".
    #[serde(default)]
    pub captcha_provider: Option<String>,
    /// Rate threshold (req/s) above which unknown bots get CAPTCHA challenge. Default: 5.0.
    #[serde(default)]
    pub captcha_challenge_threshold: Option<f64>,

    // ── Proxy-Wasm Plugins ──────────────────────────────────────────────────
    /// Path to a JSON file containing Wasm plugin configurations.
    #[serde(default)]
    pub wasm_plugin_config_path: Option<String>,

    // ── Kubernetes Ingress Controller ───────────────────────────────────────
    /// Enable Kubernetes ingress controller mode.
    #[serde(default)]
    pub k8s_ingress_enabled: bool,
    /// Ingress class name to watch. Default: "phalanx".
    #[serde(default)]
    pub k8s_ingress_class: Option<String>,

    // ── Global Server Load Balancing ────────────────────────────────────────
    /// GSLB routing policy: "geographic", "latency", "weighted", "geo_latency".
    #[serde(default)]
    pub gslb_policy: Option<String>,
    /// Maximum latency (ms) before a DC is considered unhealthy. Default: 500.
    #[serde(default)]
    pub gslb_max_latency_ms: Option<f64>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "default".to_string(),
            UpstreamPoolConfig {
                algorithm: LoadBalancingAlgorithm::RoundRobin,
                keepalive: 0,
                srv_discover: None,
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
            quic_bind: None,
            dns_resolver: None,
            udp_bind: None,
            trusted_proxies: Vec::new(),
            geoip_db_path: None,
            geo_allow_countries: Vec::new(),
            geo_deny_countries: Vec::new(),
            cache_disk_path: None,
            brotli_enabled: false,
            auth_request_url: None,
            mirror_pool: None,
            proxy_proto_v2: false,
            rhai_script: None,
            keyval_ttl_secs: 0,
            auto_ssl_domain: None,
            auto_ssl_email: None,
            auto_ssl_cache_dir: None,
            redis_url: None,
            smtp_bind: None,
            imap_bind: None,
            pop3_bind: None,
            mail_upstream_pool: None,
            waf_policy_path: None,
            ocsp_responder_url: None,
            etcd_endpoints: None,
            node_id: None,
            gossip_bind: None,
            gossip_seed_peers: None,
            gossip_interval_ms: None,
            ml_fraud_model_path: None,
            ml_fraud_mode: None,
            captcha_site_key: None,
            captcha_secret_key: None,
            captcha_provider: None,
            captcha_challenge_threshold: None,
            wasm_plugin_config_path: None,
            k8s_ingress_enabled: false,
            k8s_ingress_class: None,
            gslb_policy: None,
            gslb_max_latency_ms: None,
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
                if let Some(v) = server.directives.get("listen_quic") {
                    app_cfg.quic_bind = Some(if v.contains(':') {
                        v.clone()
                    } else {
                        format!("0.0.0.0:{}", v)
                    });
                }
                if let Some(v) = server.directives.get("listen_udp") {
                    app_cfg.udp_bind = Some(if v.contains(':') {
                        v.clone()
                    } else {
                        format!("0.0.0.0:{}", v)
                    });
                }
                if let Some(v) = server.directives.get("trusted_proxy") {
                    app_cfg.trusted_proxies.push(v.clone());
                }
                if let Some(v) = server.directives.get("geoip_db") {
                    app_cfg.geoip_db_path = Some(v.clone());
                }
                if let Some(v) = server.directives.get("geo_allow") {
                    app_cfg
                        .geo_allow_countries
                        .extend(v.split(',').map(|s| s.trim().to_string()));
                }
                if let Some(v) = server.directives.get("geo_deny") {
                    app_cfg
                        .geo_deny_countries
                        .extend(v.split(',').map(|s| s.trim().to_string()));
                }
                if let Some(v) = server.directives.get("cache_disk_path") {
                    app_cfg.cache_disk_path = Some(v.clone());
                }
                if let Some(v) = server.directives.get("brotli") {
                    app_cfg.brotli_enabled = v == "on" || v == "true";
                }
                if let Some(v) = server.directives.get("auth_request") {
                    app_cfg.auth_request_url = Some(v.clone());
                }
                if let Some(v) = server.directives.get("mirror") {
                    app_cfg.mirror_pool = Some(v.clone());
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

                // Parse newer fields
                if let Some(v) = server.directives.get("proxy_proto_v2") {
                    app_cfg.proxy_proto_v2 = v == "on" || v == "true";
                }
                if let Some(v) = server.directives.get("rhai_script") {
                    app_cfg.rhai_script = Some(v.clone());
                }
                if let Some(v) = route_or_directive_u32(&server.directives, "keyval_ttl_secs") {
                    app_cfg.keyval_ttl_secs = v as u64;
                }
                if let Some(v) = server.directives.get("auto_ssl_domain") {
                    app_cfg.auto_ssl_domain = Some(v.clone());
                }
                if let Some(v) = server.directives.get("auto_ssl_email") {
                    app_cfg.auto_ssl_email = Some(v.clone());
                }
                if let Some(v) = server.directives.get("auto_ssl_cache_dir") {
                    app_cfg.auto_ssl_cache_dir = Some(v.clone());
                }
                if let Some(v) = server.directives.get("redis_url") {
                    app_cfg.redis_url = Some(v.clone());
                }
                if let Some(v) = server.directives.get("ocsp_responder_url") {
                    app_cfg.ocsp_responder_url = Some(v.clone());
                }
                if let Some(v) = server.directives.get("etcd_endpoints") {
                    app_cfg.etcd_endpoints = Some(v.clone());
                }
                if let Some(v) = server.directives.get("node_id") {
                    app_cfg.node_id = Some(v.clone());
                }
                if let Some(v) = server.directives.get("gossip_bind") {
                    app_cfg.gossip_bind = Some(v.clone());
                }
                if let Some(v) = server.directives.get("gossip_seed_peers") {
                    app_cfg.gossip_seed_peers = Some(v.clone());
                }
                if let Some(v) = server.directives.get("gossip_interval_ms") {
                    if let Ok(val) = v.parse::<u64>() {
                        app_cfg.gossip_interval_ms = Some(val);
                    }
                }
                if let Some(v) = server.directives.get("ml_fraud_model_path") {
                    app_cfg.ml_fraud_model_path = Some(v.clone());
                }
                if let Some(v) = server.directives.get("ml_fraud_mode") {
                    app_cfg.ml_fraud_mode = Some(v.clone());
                }
                if let Some(v) = server.directives.get("smtp_bind") {
                    app_cfg.smtp_bind = Some(v.clone());
                }
                if let Some(v) = server.directives.get("imap_bind") {
                    app_cfg.imap_bind = Some(v.clone());
                }
                if let Some(v) = server.directives.get("pop3_bind") {
                    app_cfg.pop3_bind = Some(v.clone());
                }
                if let Some(v) = server.directives.get("mail_upstream_pool") {
                    app_cfg.mail_upstream_pool = Some(v.clone());
                }
                if let Some(v) = server.directives.get("waf_policy_path") {
                    app_cfg.waf_policy_path = Some(v.clone());
                }
                if let Some(v) = server.directives.get("captcha_site_key") {
                    app_cfg.captcha_site_key = Some(v.clone());
                }
                if let Some(v) = server.directives.get("captcha_secret_key") {
                    app_cfg.captcha_secret_key = Some(v.clone());
                }
                if let Some(v) = server.directives.get("captcha_provider") {
                    app_cfg.captcha_provider = Some(v.clone());
                }
                if let Some(v) = server.directives.get("captcha_challenge_threshold") {
                    if let Ok(val) = v.parse::<f64>() {
                        app_cfg.captcha_challenge_threshold = Some(val);
                    }
                }
                if let Some(v) = server.directives.get("wasm_plugin_config") {
                    app_cfg.wasm_plugin_config_path = Some(v.clone());
                }
                if let Some(v) = server.directives.get("k8s_ingress_enabled") {
                    app_cfg.k8s_ingress_enabled = v == "true" || v == "on";
                }
                if let Some(v) = server.directives.get("k8s_ingress_class") {
                    app_cfg.k8s_ingress_class = Some(v.clone());
                }
                if let Some(v) = server.directives.get("gslb_policy") {
                    app_cfg.gslb_policy = Some(v.clone());
                }
                if let Some(v) = server.directives.get("gslb_max_latency_ms") {
                    if let Ok(val) = v.parse::<f64>() {
                        app_cfg.gslb_max_latency_ms = Some(val);
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
                            brotli: route.brotli,
                            auth_request_url: route.auth_request_url,
                            mirror_pool: route.mirror_pool,
                            auth_jwks_uri: route.auth_jwks_uri,
                            auth_oidc_issuer: route.auth_oidc_issuer,
                            auth_oidc_cookie_name: route.auth_oidc_cookie_name,
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
                    Some("consistent_hash") | Some("consistenthash") => {
                        LoadBalancingAlgorithm::ConsistentHash
                    }
                    Some("least_time") | Some("leasttime") => {
                        LoadBalancingAlgorithm::LeastTime
                    }
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
                        max_fails: upstream.max_fails,
                        fail_timeout_secs: upstream.fail_timeout_secs,
                        slow_start_secs: upstream.slow_start_secs,
                        backup: false,
                        max_conns: 0,
                        queue_size: 0,
                        ..Default::default()
                    })
                    .collect();
                app_cfg.upstreams.insert(
                    upstream.name.clone(),
                    UpstreamPoolConfig {
                        algorithm,
                        backends,
                        keepalive: upstream.keepalive,
                        srv_discover: upstream.srv_discover.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_proxy_bind() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.proxy_bind, "0.0.0.0:8080");
    }

    #[test]
    fn test_default_config_tcp_bind() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.tcp_bind, "0.0.0.0:5000");
    }

    #[test]
    fn test_default_config_admin_bind() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.admin_bind, "127.0.0.1:9090");
    }

    #[test]
    fn test_default_config_workers() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.workers, 4);
    }

    #[test]
    fn test_default_config_has_default_upstream() {
        let cfg = AppConfig::default();
        assert!(cfg.upstreams.contains_key("default"));
        let pool = &cfg.upstreams["default"];
        assert_eq!(pool.backends.len(), 2);
        assert!(matches!(pool.algorithm, LoadBalancingAlgorithm::RoundRobin));
    }

    #[test]
    fn test_default_config_has_root_route() {
        let cfg = AppConfig::default();
        assert!(cfg.routes.contains_key("/"));
        assert_eq!(cfg.routes["/"].upstream, Some("default".to_string()));
    }

    #[test]
    fn test_default_config_tls_disabled() {
        let cfg = AppConfig::default();
        assert!(cfg.tls_cert_path.is_none());
        assert!(cfg.tls_key_path.is_none());
    }

    #[test]
    fn test_default_config_optional_fields() {
        let cfg = AppConfig::default();
        assert!(cfg.rate_limit_per_ip_sec.is_none());
        assert!(cfg.rate_limit_burst.is_none());
        assert!(cfg.global_rate_limit_sec.is_none());
        assert_eq!(cfg.waf_enabled, Some(false));
        assert!(cfg.otel_endpoint.is_none());
        assert!(cfg.quic_bind.is_none());
        assert!(cfg.udp_bind.is_none());
        assert!(cfg.trusted_proxies.is_empty());
        assert!(!cfg.brotli_enabled);
        assert!(cfg.auth_request_url.is_none());
        assert!(cfg.mirror_pool.is_none());
    }

    #[test]
    fn test_backend_config_default() {
        let bc = BackendConfig::default();
        assert_eq!(bc.weight, 1);
        assert_eq!(bc.max_fails, 3);
        assert_eq!(bc.fail_timeout_secs, 30);
        assert_eq!(bc.slow_start_secs, 0);
        assert!(!bc.backup);
        assert_eq!(bc.max_conns, 0);
        assert_eq!(bc.queue_size, 0);
        assert_eq!(bc.health_check_status, 200);
    }

    #[test]
    fn test_route_config_default() {
        let rc = RouteConfig::default();
        assert!(rc.upstream.is_none());
        assert!(rc.root.is_none());
        assert!(!rc.gzip);
        assert!(!rc.proxy_cache);
        assert!(!rc.brotli);
    }

    #[test]
    fn test_load_config_missing_file() {
        let cfg = load_config("/nonexistent/path/to/config.conf");
        assert_eq!(cfg.proxy_bind, "0.0.0.0:8080");
    }

    #[test]
    fn test_route_or_directive_u32_valid() {
        let mut map = HashMap::new();
        map.insert("count".to_string(), "42".to_string());
        assert_eq!(route_or_directive_u32(&map, "count"), Some(42));
    }

    #[test]
    fn test_route_or_directive_u32_invalid() {
        let mut map = HashMap::new();
        map.insert("bad".to_string(), "not-a-number".to_string());
        assert_eq!(route_or_directive_u32(&map, "bad"), None);
    }

    #[test]
    fn test_route_or_directive_u32_missing() {
        let map = HashMap::new();
        assert_eq!(route_or_directive_u32(&map, "missing"), None);
    }

    #[test]
    fn test_load_balancing_algorithm_default() {
        let algo: LoadBalancingAlgorithm = Default::default();
        assert!(matches!(algo, LoadBalancingAlgorithm::RoundRobin));
    }
}
