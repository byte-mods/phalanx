//! # NGINX-Style Configuration Parser
//!
//! A strict recursive-descent parser for Phalanx's NGINX-inspired configuration
//! syntax. The parser operates in two phases:
//!
//! 1. **Lexical analysis** (`tokenize`): Splits the raw config text into tokens,
//!    handling whitespace, quoted strings, `#` comments, and structural chars
//!    (`{`, `}`, `;`).
//!
//! 2. **Recursive descent parsing** (`parse_phalanx_config` and helpers): Walks
//!    the token stream to build a typed AST (`PhalanxConfig` → `HttpBlock` →
//!    `ServerBlock` → `RouteBlock` / `UpstreamBlock`).
//!
//! Every directive must end with `;`, every block must be balanced with `{ }`,
//! and unknown tokens produce immediate, descriptive errors.

use std::collections::HashMap;

/// The root abstract syntax tree (AST) for the parsed Phalanx configuration.
///
/// Mirrors the top-level structure of a `phalanx.conf` file:
/// global directives (`worker_threads`, `tcp_listen`, `admin_listen`) plus
/// an optional `http { ... }` block containing servers and upstreams.
#[derive(Debug, Default)]
pub struct PhalanxConfig {
    /// Number of worker threads for the Tokio runtime
    pub worker_threads: Option<usize>,
    /// TCP listen port for the raw TCP multiplexer proxy
    pub tcp_listen: Option<String>,
    /// Admin listen address for the dashboard and metrics
    pub admin_listen: Option<String>,
    /// The global `http` block containing server configurations
    pub http: Option<HttpBlock>,
}

/// Represents the `http { ... }` block.
///
/// Contains one or more `server` blocks (virtual hosts) and zero or more
/// `upstream` blocks (backend pools). This is the top-level HTTP configuration
/// container analogous to nginx's `http` context.
#[derive(Debug, Default)]
pub struct HttpBlock {
    /// A list of virtual server configurations within the HTTP block
    pub servers: Vec<ServerBlock>,
    /// Named upstream pools: `upstream pool_name { ... }`
    pub upstreams: Vec<UpstreamBlock>,
}

/// Represents an `upstream pool_name { ... }` block.
/// Contains a list of backend servers and a load balancing algorithm.
#[derive(Debug, Default)]
pub struct UpstreamBlock {
    /// The name of this upstream pool (e.g., "default", "backend_api")
    pub name: String,
    /// List of (address, weight) pairs
    pub servers: Vec<(String, u32)>,
    /// Load balancing algorithm (e.g., "roundrobin", "leastconnections")
    pub algorithm: Option<String>,
    /// HTTP path for health checks (e.g., "/health"). None = TCP connect only.
    pub health_check_path: Option<String>,
    /// Expected HTTP status code for a healthy response. Default: 200.
    pub health_check_status: u16,
    /// Max idle keepalive connections per backend. 0 = disabled.
    pub keepalive: u32,
    /// Consecutive proxy failures before marking a backend DOWN. Default: 3.
    pub max_fails: u32,
    /// Window in seconds for max_fails to trip the circuit. Default: 30.
    pub fail_timeout_secs: u64,
    /// Slow-start ramp-up seconds after recovery. 0 = disabled.
    pub slow_start_secs: u32,
    /// DNS SRV record name for discovery
    pub srv_discover: Option<String>,
    /// Health check interval in seconds. Default: 5.
    pub health_check_interval_secs: u64,
    /// Health check timeout in seconds. Default: 3.
    pub health_check_timeout_secs: u64,
}

/// Represents a `server { ... }` block inside the HTTP block.
///
/// A server block defines a virtual host with its own listen port, TLS settings,
/// route handlers, and generic key-value directives. Multiple server blocks can
/// coexist in a single `http` block for multi-tenant setups.
#[derive(Debug, Default)]
pub struct ServerBlock {
    /// The port to listen on (e.g., "8080")
    pub listen: Option<String>,
    /// Path to TLS certificate
    pub ssl_certificate: Option<String>,
    /// Path to TLS private key
    pub ssl_certificate_key: Option<String>,
    /// A mapping of URL paths to specific route handler configurations
    pub routes: HashMap<String, RouteBlock>,
    /// Generic key-value directives (e.g., rate_limit_per_ip, waf_enabled, ai_epsilon)
    pub directives: HashMap<String, String>,
    /// ICE server URLs for WebRTC NAT traversal (STUN/TURN).
    /// Each entry is a URL like `stun:host:port` or `turn:host:port?transport=udp`.
    pub ice_servers: Vec<String>,
}

/// Represents a `route /path { ... }` block inside a server.
///
/// Each route block binds a URL prefix to a specific handler (upstream proxy,
/// static file root, FastCGI, or uWSGI) and carries per-route settings for
/// authentication, compression, caching, rewrites, and header injection.
#[derive(Debug, Default)]
pub struct RouteBlock {
    /// The URL prefix to match against (e.g., "/api")
    pub path: String,
    /// The name of the upstream pool to forward this traffic to (e.g., "backend_api")
    pub upstream: Option<String>,
    /// The physical file directory root if serving static files (e.g., "/var/www/html")
    pub root: Option<String>,
    /// The TCP address of a FastCGI backend pool (e.g., PHP-FPM at "127.0.0.1:9000")
    pub fastcgi_pass: Option<String>,
    /// The TCP address of a uWSGI backend pool (e.g., Python app at "127.0.0.1:3030")
    pub uwsgi_pass: Option<String>,
    /// Headers to manually inject into requests/responses matched by this route
    pub add_headers: HashMap<String, String>,
    /// Ordered list of (pattern, replacement, flag) rewrite rules for this route.
    /// Syntax: `rewrite PATTERN REPLACEMENT FLAG;`
    pub rewrite_rules: Vec<(String, String, String)>,
    // ── Auth fields ───────────────────────────────────────────────────────────
    /// HTTP Basic Auth realm string shown in the WWW-Authenticate challenge header.
    pub auth_basic_realm: Option<String>,
    /// Map of username -> password (plaintext or bcrypt) for Basic Auth.
    pub auth_basic_users: HashMap<String, String>,
    /// HMAC secret or RSA public key for JWT Bearer token verification.
    pub auth_jwt_secret: Option<String>,
    /// JWT signing algorithm (e.g. "HS256", "RS256").
    pub auth_jwt_algorithm: Option<String>,
    /// RFC 7662 token introspection endpoint URL for OAuth 2.0.
    pub auth_oauth_introspect_url: Option<String>,
    /// OAuth client ID for introspection authentication.
    pub auth_oauth_client_id: Option<String>,
    /// OAuth client secret for introspection authentication.
    pub auth_oauth_client_secret: Option<String>,
    // ── Gzip + Cache ────────────────────────────────────────────────────────────
    /// Enable gzip compression for this route.
    pub gzip: bool,
    /// Minimum response body size (bytes) to trigger gzip compression.
    pub gzip_min_length: usize,
    /// Enable response caching for GET 200 responses.
    pub proxy_cache: bool,
    /// Default cache TTL in seconds when the backend sends no Cache-Control.
    pub proxy_cache_valid_secs: u64,
    // ── Brotli ────────────────────────────────────────────────────────────────
    /// Enable Brotli compression for this route.
    pub brotli: bool,
    // ── auth_request ──────────────────────────────────────────────────────────
    /// External auth subrequest URL. A 200 response allows the request through.
    pub auth_request_url: Option<String>,
    // ── Mirror ────────────────────────────────────────────────────────────────
    /// Upstream pool name for traffic mirroring (shadow copy of live traffic).
    pub mirror_pool: Option<String>,
    // ── JWKS-based JWT Auth ───────────────────────────────────────────────────
    /// JWKS endpoint URI for dynamic public key fetching (RS256/ES256).
    pub auth_jwks_uri: Option<String>,
    // ── OIDC Session Auth ─────────────────────────────────────────────────────
    /// OIDC issuer URL for session-based authentication.
    pub auth_oidc_issuer: Option<String>,
    /// Cookie name holding the OIDC session ID.
    pub auth_oidc_cookie_name: Option<String>,

    // ── Proxy Timeouts ──────────────────────────────────────────────────────
    /// TCP connect timeout in seconds for this route. 0 = use global default.
    pub proxy_connect_timeout_secs: u64,
    /// Response read timeout in seconds for this route. 0 = use global default.
    pub proxy_read_timeout_secs: u64,

    // ── Retry Policy ────────────────────────────────────────────────────────
    /// Max upstream retry attempts for this route. 0 = disabled.
    pub proxy_next_upstream_tries: u32,
    /// Overall retry timeout in seconds for this route. 0 = no limit.
    pub proxy_next_upstream_timeout_secs: u64,

    // ── Request Body Size Limit ─────────────────────────────────────────────
    /// Maximum request body size in bytes. 0 = use global default.
    pub client_max_body_size: usize,

    // ── CORS ────────────────────────────────────────────────────────────────
    /// Enable CORS for this route.
    pub cors_enabled: bool,
    /// Allowed origins (empty = allow all).
    pub cors_allowed_origins: Vec<String>,
    /// Allowed HTTP methods.
    pub cors_allowed_methods: Vec<String>,
    /// Allowed request headers.
    pub cors_allowed_headers: Vec<String>,
    /// Max age in seconds for preflight cache.
    pub cors_max_age_secs: u64,
    /// Whether to include credentials header.
    pub cors_allow_credentials: bool,

    // ── HTTP/2 Backend Forwarding ────────────────────────────────────────────
    /// Proxy HTTP version for backend connections ("2" = HTTP/2).
    pub proxy_http_version: Option<String>,

    // ── Traffic Splitting ──────────────────────────────────────────────────
    /// Upstream pool names for A/B/canary traffic splitting.
    pub split_pools: Vec<String>,
    /// Relative weights for each pool (e.g. [90, 10] for 90/10).
    pub split_weights: Vec<u32>,
}

/// Entry point: parses a raw NGINX-style configuration string into a `PhalanxConfig` AST.
///
/// The parser is strict by design -- it rejects:
/// - Missing semicolons after directives
/// - Unclosed `{` blocks
/// - Unknown or unexpected tokens at any nesting level
///
/// # Arguments
/// * `input` - The full text content of a `phalanx.conf` file.
///
/// # Returns
/// `Ok(PhalanxConfig)` on success, or `Err(String)` with a human-readable
/// error message describing the exact problem and token position.
pub fn parse_phalanx_config(input: &str) -> Result<PhalanxConfig, String> {
    let mut config = PhalanxConfig::default();

    // Phase 1: Lexical analysis -- split the raw text into a flat token stream.
    let tokens = tokenize(input);
    let mut i = 0;

    // Phase 2: Recursive descent parsing -- walk the token stream and build the AST.
    while i < tokens.len() {
        let token = &tokens[i];

        // Parse: `worker_threads 8;`
        if token == "worker_threads" {
            expect_directive_value_semicolon(&tokens, i, "worker_threads")?;
            if let Ok(threads) = tokens[i + 1].parse::<usize>() {
                config.worker_threads = Some(threads);
            } else {
                return Err(format!(
                    "Invalid value '{}' for directive 'worker_threads': expected a positive integer",
                    tokens[i + 1]
                ));
            }
            i += 3;
            continue;
        }

        // Parse: `tcp_listen 5000;`
        if token == "tcp_listen" {
            expect_directive_value_semicolon(&tokens, i, "tcp_listen")?;
            config.tcp_listen = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `admin_listen 127.0.0.1:9090;`
        if token == "admin_listen" {
            expect_directive_value_semicolon(&tokens, i, "admin_listen")?;
            config.admin_listen = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `http { ... }`
        if token == "http" {
            expect_open_brace(&tokens, i, "http")?;
            i += 2;
            let (http_block, new_i) = parse_http_block(&tokens, i)?;
            config.http = Some(http_block);
            i = new_i;
            continue;
        }

        return Err(format!(
            "Unknown top-level directive '{}' at token position {}",
            token, i
        ));
    }

    Ok(config)
}

/// Parses the contents inside an `http { ... }` block.
///
/// Expects to be called after the opening `{` has been consumed. Returns the
/// completed `HttpBlock` and the token index immediately after the closing `}`.
/// Valid children are `server { ... }` and `upstream name { ... }` blocks.
fn parse_http_block(tokens: &[String], mut i: usize) -> Result<(HttpBlock, usize), String> {
    let mut block = HttpBlock::default();
    while i < tokens.len() {
        let token = &tokens[i];
        if token == "}" {
            return Ok((block, i + 1));
        }

        // Parse: `server { ... }`
        if token == "server" {
            expect_open_brace(tokens, i, "server")?;
            i += 2;
            let (server_block, new_i) = parse_server_block(tokens, i)?;
            block.servers.push(server_block);
            i = new_i;
            continue;
        }

        // Parse: `upstream pool_name { ... }`
        if token == "upstream" {
            if i + 2 >= tokens.len() {
                return Err(format!(
                    "'upstream' block at token {} is missing a name and/or opening brace '{{'",
                    i
                ));
            }
            let name = tokens[i + 1].clone();
            if tokens[i + 2] != "{" {
                return Err(format!(
                    "Expected '{{' after 'upstream {name}', found '{}'",
                    tokens[i + 2]
                ));
            }
            i += 3;
            let (upstream_block, new_i) = parse_upstream_block(tokens, i, name)?;
            block.upstreams.push(upstream_block);
            i = new_i;
            continue;
        }

        return Err(format!(
            "Unknown directive '{}' inside 'http' block at token position {}",
            token, i
        ));
    }
    Err("Unclosed 'http' block: missing closing '}'".to_string())
}

/// Parses the contents inside a `server { ... }` block.
///
/// Recognizes specific directives (`listen`, `ssl_certificate`, `ssl_certificate_key`),
/// `route /path { ... }` sub-blocks, and generic `key value;` directives that are
/// stored in the `directives` map for later interpretation by `try_load_config`.
fn parse_server_block(tokens: &[String], mut i: usize) -> Result<(ServerBlock, usize), String> {
    let mut block = ServerBlock::default();
    while i < tokens.len() {
        let token = &tokens[i];
        if token == "}" {
            return Ok((block, i + 1));
        }

        // Parse: `listen 8080;`
        if token == "listen" {
            expect_directive_value_semicolon(tokens, i, "listen")?;
            block.listen = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `ssl_certificate /path/to/cert.pem;`
        if token == "ssl_certificate" {
            expect_directive_value_semicolon(tokens, i, "ssl_certificate")?;
            block.ssl_certificate = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `ssl_certificate_key /path/to/key.pem;`
        if token == "ssl_certificate_key" {
            expect_directive_value_semicolon(tokens, i, "ssl_certificate_key")?;
            block.ssl_certificate_key = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `route /path { ... }`
        if token == "route" {
            if i + 2 >= tokens.len() {
                return Err(format!(
                    "'route' directive at token {} is missing a path and/or opening brace '{{'",
                    i
                ));
            }
            let path = tokens[i + 1].clone();
            if tokens[i + 2] != "{" {
                return Err(format!(
                    "Expected '{{' after 'route {path}', found '{}'",
                    tokens[i + 2]
                ));
            }
            i += 3;
            let (route_block, new_i) = parse_route_block(tokens, i, path.clone())?;
            block.routes.insert(path, route_block);
            i = new_i;
            continue;
        }

        // Parse: `api_token TOKEN ROLE;` (3 tokens: keyword, token, role)
        if token == "api_token" {
            if i + 3 >= tokens.len() {
                return Err(format!(
                    "'api_token' at token {} requires 'TOKEN ROLE;' but found insufficient tokens",
                    i
                ));
            }
            if tokens[i + 3] != ";" {
                return Err(format!(
                    "'api_token {} {}' at token position {} is missing a semicolon ';'",
                    tokens[i + 1],
                    tokens[i + 2],
                    i
                ));
            }
            // Store as "api_token:TOKEN" → "ROLE" in directives map
            block.directives.insert(
                format!("api_token:{}", tokens[i + 1]),
                tokens[i + 2].clone(),
            );
            i += 4;
            continue;
        }

        // Parse: `ice_server stun:host:port;` or `ice_server turn:host:port?transport=udp;`
        // Accumulates — each directive appends one ICE server URL.
        if token == "ice_server" {
            expect_directive_value_semicolon(tokens, i, "ice_server")?;
            block.ice_servers.push(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Generic directive: `key value;`
        // Must match exactly: TOKEN VALUE ;
        if i + 2 < tokens.len() && tokens[i + 2] == ";" {
            block
                .directives
                .insert(tokens[i].clone(), tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // If we see `key value` without a semicolon next
        if i + 1 < tokens.len() && tokens[i + 1] != "{" && tokens[i + 1] != "}" {
            return Err(format!(
                "Directive '{}' at token position {} is missing a semicolon ';'",
                token, i
            ));
        }

        return Err(format!(
            "Unknown or unexpected token '{}' inside 'server' block at position {}",
            token, i
        ));
    }
    Err("Unclosed 'server' block: missing closing '}'".to_string())
}

/// Parses the contents inside a `route /path { ... }` block.
///
/// Recognizes handler directives (`upstream`, `root`, `fastcgi_pass`, `uwsgi_pass`),
/// header injection (`add_header`), URL rewrites (`rewrite`), auth directives
/// (`auth_basic`, `auth_jwt_secret`, `auth_oauth_*`), and compression/cache toggles.
fn parse_route_block(
    tokens: &[String],
    mut i: usize,
    path: String,
) -> Result<(RouteBlock, usize), String> {
    let mut block = RouteBlock {
        path,
        ..Default::default()
    };
    while i < tokens.len() {
        let token = &tokens[i];
        if token == "}" {
            return Ok((block, i + 1));
        }

        // Parse: `upstream default;`
        if token == "upstream" {
            expect_directive_value_semicolon(tokens, i, "upstream")?;
            block.upstream = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `root /var/www/html;`
        if token == "root" {
            expect_directive_value_semicolon(tokens, i, "root")?;
            block.root = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `fastcgi_pass 127.0.0.1:9000;`
        if token == "fastcgi_pass" {
            expect_directive_value_semicolon(tokens, i, "fastcgi_pass")?;
            block.fastcgi_pass = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `uwsgi_pass 127.0.0.1:3030;`
        if token == "uwsgi_pass" {
            expect_directive_value_semicolon(tokens, i, "uwsgi_pass")?;
            block.uwsgi_pass = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `add_header X-Proxy Phalanx;`
        if token == "add_header" {
            if i + 3 >= tokens.len() {
                return Err(format!(
                    "'add_header' at token {} requires 'name value;' but found insufficient tokens",
                    i
                ));
            }
            if tokens[i + 3] != ";" {
                return Err(format!(
                    "'add_header {} {}' at token position {} is missing a semicolon ';'",
                    tokens[i + 1],
                    tokens[i + 2],
                    i
                ));
            }
            block
                .add_headers
                .insert(tokens[i + 1].clone(), tokens[i + 2].clone());
            i += 4;
            continue;
        }

        // Parse: `rewrite PATTERN REPLACEMENT [FLAG];`
        // Supports: last, break, redirect, permanent
        // e.g. rewrite ^/old/(.+)$ /new/$1 last;
        if token == "rewrite" {
            // Format: rewrite PATTERN REPLACEMENT FLAG ;
            if i + 4 >= tokens.len() {
                return Err(format!(
                    "'rewrite' at token {} requires 'PATTERN REPLACEMENT FLAG;' but found insufficient tokens",
                    i
                ));
            }
            if tokens[i + 4] != ";" {
                return Err(format!(
                    "'rewrite {} {} {}' at token {} is missing a semicolon ';'",
                    tokens[i + 1],
                    tokens[i + 2],
                    tokens[i + 3],
                    i
                ));
            }
            block.rewrite_rules.push((
                tokens[i + 1].clone(), // regex pattern
                tokens[i + 2].clone(), // replacement
                tokens[i + 3].clone(), // flag: last | break | redirect | permanent
            ));
            i += 5;
            continue;
        }

        // ── Auth directives ────────────────────────────────────────────────────

        // Parse: `auth_basic "Realm";`
        if token == "auth_basic" {
            expect_directive_value_semicolon(tokens, i, "auth_basic")?;
            block.auth_basic_realm = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `auth_basic_user username:password;`
        if token == "auth_basic_user" {
            expect_directive_value_semicolon(tokens, i, "auth_basic_user")?;
            let user_pass = &tokens[i + 1];
            if let Some((u, p)) = user_pass.split_once(':') {
                block.auth_basic_users.insert(u.to_string(), p.to_string());
            } else {
                return Err(format!(
                    "'auth_basic_user' value '{}' must be in 'username:password' format",
                    user_pass
                ));
            }
            i += 3;
            continue;
        }

        // Parse: `auth_jwt_secret "mysecret";`
        if token == "auth_jwt_secret" {
            expect_directive_value_semicolon(tokens, i, "auth_jwt_secret")?;
            block.auth_jwt_secret = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `auth_jwt_algorithm HS256;`
        if token == "auth_jwt_algorithm" {
            expect_directive_value_semicolon(tokens, i, "auth_jwt_algorithm")?;
            block.auth_jwt_algorithm = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `auth_oauth_introspect_url "https://...";`
        if token == "auth_oauth_introspect_url" {
            expect_directive_value_semicolon(tokens, i, "auth_oauth_introspect_url")?;
            block.auth_oauth_introspect_url = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `auth_oauth_client_id "phalanx";`
        if token == "auth_oauth_client_id" {
            expect_directive_value_semicolon(tokens, i, "auth_oauth_client_id")?;
            block.auth_oauth_client_id = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `auth_oauth_client_secret "secret";`
        if token == "auth_oauth_client_secret" {
            expect_directive_value_semicolon(tokens, i, "auth_oauth_client_secret")?;
            block.auth_oauth_client_secret = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // ── Gzip + Cache directives ────────────────────────────────────────────

        // Parse: `gzip on;` or `gzip off;`
        if token == "gzip" {
            expect_directive_value_semicolon(tokens, i, "gzip")?;
            block.gzip = tokens[i + 1].to_lowercase() == "on";
            i += 3;
            continue;
        }

        // Parse: `gzip_min_length 1024;`
        if token == "gzip_min_length" {
            expect_directive_value_semicolon(tokens, i, "gzip_min_length")?;
            block.gzip_min_length = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for gzip_min_length", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `proxy_cache on;`
        if token == "proxy_cache" {
            expect_directive_value_semicolon(tokens, i, "proxy_cache")?;
            block.proxy_cache = tokens[i + 1].to_lowercase() == "on";
            i += 3;
            continue;
        }

        // Parse: `proxy_cache_valid 60;`
        if token == "proxy_cache_valid" {
            expect_directive_value_semicolon(tokens, i, "proxy_cache_valid")?;
            block.proxy_cache_valid_secs = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for proxy_cache_valid", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `brotli on;` or `brotli off;`
        if token == "brotli" {
            expect_directive_value_semicolon(tokens, i, "brotli")?;
            block.brotli = tokens[i + 1].to_lowercase() == "on";
            i += 3;
            continue;
        }

        // Parse: `auth_request http://auth-service:8080/verify;`
        if token == "auth_request" {
            expect_directive_value_semicolon(tokens, i, "auth_request")?;
            block.auth_request_url = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `mirror shadow_pool;`
        if token == "mirror" {
            expect_directive_value_semicolon(tokens, i, "mirror")?;
            block.mirror_pool = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `proxy_connect_timeout 10;`
        if token == "proxy_connect_timeout" {
            expect_directive_value_semicolon(tokens, i, "proxy_connect_timeout")?;
            block.proxy_connect_timeout_secs = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for proxy_connect_timeout", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `proxy_read_timeout 60;`
        if token == "proxy_read_timeout" {
            expect_directive_value_semicolon(tokens, i, "proxy_read_timeout")?;
            block.proxy_read_timeout_secs = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for proxy_read_timeout", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `proxy_next_upstream_tries 3;`
        if token == "proxy_next_upstream_tries" {
            expect_directive_value_semicolon(tokens, i, "proxy_next_upstream_tries")?;
            block.proxy_next_upstream_tries = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for proxy_next_upstream_tries", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `proxy_next_upstream_timeout 30;`
        if token == "proxy_next_upstream_timeout" {
            expect_directive_value_semicolon(tokens, i, "proxy_next_upstream_timeout")?;
            block.proxy_next_upstream_timeout_secs = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for proxy_next_upstream_timeout", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `client_max_body_size 10M;`
        if token == "client_max_body_size" {
            expect_directive_value_semicolon(tokens, i, "client_max_body_size")?;
            block.client_max_body_size = match crate::config::parse_size_value(&tokens[i + 1]) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            i += 3;
            continue;
        }

        // ── CORS directives ───────────────────────────────────────────────────

        // Parse: `cors_enabled on;`
        if token == "cors_enabled" {
            expect_directive_value_semicolon(tokens, i, "cors_enabled")?;
            block.cors_enabled = tokens[i + 1].to_lowercase() == "on" || tokens[i + 1] == "true";
            i += 3;
            continue;
        }

        // Parse: `cors_allowed_origins "https://example.com" "https://other.com";`
        if token == "cors_allowed_origins" {
            i += 1;
            while i < tokens.len() && tokens[i] != ";" {
                block.cors_allowed_origins.push(tokens[i].clone());
                i += 1;
            }
            if i < tokens.len() {
                i += 1; // skip ;
            }
            continue;
        }

        // Parse: `cors_allowed_methods "GET" "POST";`
        if token == "cors_allowed_methods" {
            block.cors_allowed_methods.clear();
            i += 1;
            while i < tokens.len() && tokens[i] != ";" {
                block.cors_allowed_methods.push(tokens[i].clone());
                i += 1;
            }
            if i < tokens.len() {
                i += 1; // skip ;
            }
            continue;
        }

        // Parse: `cors_allowed_headers "Content-Type" "Authorization";`
        if token == "cors_allowed_headers" {
            block.cors_allowed_headers.clear();
            i += 1;
            while i < tokens.len() && tokens[i] != ";" {
                block.cors_allowed_headers.push(tokens[i].clone());
                i += 1;
            }
            if i < tokens.len() {
                i += 1; // skip ;
            }
            continue;
        }

        // Parse: `cors_max_age 86400;`
        if token == "cors_max_age" {
            expect_directive_value_semicolon(tokens, i, "cors_max_age")?;
            block.cors_max_age_secs = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for cors_max_age", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `cors_allow_credentials on;`
        if token == "cors_allow_credentials" {
            expect_directive_value_semicolon(tokens, i, "cors_allow_credentials")?;
            block.cors_allow_credentials = tokens[i + 1].to_lowercase() == "on" || tokens[i + 1] == "true";
            i += 3;
            continue;
        }

        // Parse: `proxy_http_version 2;`
        if token == "proxy_http_version" {
            expect_directive_value_semicolon(tokens, i, "proxy_http_version")?;
            block.proxy_http_version = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `split_pools pool_v1:90 pool_v2:10;`
        // Format: pool_name:weight pairs separated by spaces, ending with semicolon.
        if token == "split_traffic" {
            i += 1;
            while i < tokens.len() && tokens[i] != ";" {
                let part = &tokens[i];
                if let Some((pool, weight_str)) = part.split_once(':') {
                    if let Ok(w) = weight_str.parse::<u32>() {
                        block.split_pools.push(pool.to_string());
                        block.split_weights.push(w);
                    }
                }
                i += 1;
            }
            if i < tokens.len() && tokens[i] == ";" {
                i += 1;
            }
            continue;
        }

        // If we see `key value` without a semicolon next
        if i + 1 < tokens.len() && tokens[i + 1] != "{" && tokens[i + 1] != "}" {
            if i + 2 >= tokens.len() || tokens[i + 2] != ";" {
                return Err(format!(
                    "Directive '{}' inside route block at token position {} is missing a semicolon ';'",
                    token, i
                ));
            }
        }

        return Err(format!(
            "Unknown directive '{}' inside route block at token position {}",
            token, i
        ));
    }
    Err(format!(
        "Unclosed route '{}' block: missing closing '}}'",
        block.path
    ))
}

/// Parses the contents inside an `upstream pool_name { ... }` block.
///
/// Recognizes the following directives:
/// - `server addr [weight=N];` -- backend with optional weight
/// - `algorithm roundrobin;` -- load balancing strategy
/// - `keepalive N;` -- idle connection pool size
/// - `health_check_path /path;` -- HTTP probe endpoint
/// - `health_check_status N;` -- expected probe status code
/// - `max_fails N;` -- failure threshold before marking DOWN
/// - `fail_timeout N;` -- time window for failure counting
/// - `slow_start N;` -- ramp-up seconds after recovery
/// - `srv_discover name;` -- DNS SRV-based discovery
fn parse_upstream_block(
    tokens: &[String],
    mut i: usize,
    name: String,
) -> Result<(UpstreamBlock, usize), String> {
    let mut block = UpstreamBlock {
        name: name.clone(),
        servers: Vec::new(),
        algorithm: None,
        health_check_path: None,
        health_check_status: 200,
        keepalive: 0,
        max_fails: 3,
        fail_timeout_secs: 30,
        slow_start_secs: 0,
        srv_discover: None,
        health_check_interval_secs: 5,
        health_check_timeout_secs: 3,
    };
    while i < tokens.len() {
        let token = &tokens[i];
        if token == "}" {
            return Ok((block, i + 1));
        }

        // Parse: `max_fails 3;`
        if token == "max_fails" {
            expect_directive_value_semicolon(tokens, i, "max_fails")?;
            block.max_fails = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for max_fails", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `srv_discover _http._tcp.local;`
        if token == "srv_discover" {
            expect_directive_value_semicolon(tokens, i, "srv_discover")?;
            block.srv_discover = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `fail_timeout 30;`
        if token == "fail_timeout" {
            expect_directive_value_semicolon(tokens, i, "fail_timeout")?;
            block.fail_timeout_secs = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for fail_timeout", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `slow_start 30;`
        if token == "slow_start" {
            expect_directive_value_semicolon(tokens, i, "slow_start")?;
            block.slow_start_secs = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for slow_start", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `server 127.0.0.1:8081 weight=3;` or `server 127.0.0.1:8081;`
        if token == "server" {
            if i + 1 >= tokens.len() {
                return Err(format!(
                    "'server' directive inside upstream '{}' at token {} is missing an address",
                    name, i
                ));
            }
            let addr = tokens[i + 1].clone();
            i += 2;
            let mut weight = 1u32;
            // Consume optional weight and other options before the required semicolon
            while i < tokens.len() && tokens[i] != ";" {
                if tokens[i] == "}" {
                    return Err(format!(
                        "'server {}' inside upstream '{}' is missing a semicolon ';'",
                        addr, name
                    ));
                }
                if let Some(w) = tokens[i].strip_prefix("weight=") {
                    weight = w.parse().map_err(|_| {
                        format!(
                            "Invalid weight value '{}' for server '{}' in upstream '{}'",
                            w, addr, name
                        )
                    })?;
                }
                i += 1;
            }
            // Consume the semicolon
            if i >= tokens.len() {
                return Err(format!(
                    "'server {}' inside upstream '{}' is missing a semicolon ';'",
                    addr, name
                ));
            }
            i += 1; // skip `;`
            block.servers.push((addr, weight));
            continue;
        }

        // Parse: `algorithm roundrobin;`
        if token == "algorithm" {
            expect_directive_value_semicolon(tokens, i, "algorithm")?;
            block.algorithm = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `keepalive 32;`
        if token == "keepalive" {
            expect_directive_value_semicolon(tokens, i, "keepalive")?;
            block.keepalive = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for keepalive", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `health_check_path /health;`
        if token == "health_check_path" {
            expect_directive_value_semicolon(tokens, i, "health_check_path")?;
            block.health_check_path = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `health_check_status 200;`
        if token == "health_check_status" {
            expect_directive_value_semicolon(tokens, i, "health_check_status")?;
            block.health_check_status = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for health_check_status", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `health_check_interval 10;`
        if token == "health_check_interval" {
            expect_directive_value_semicolon(tokens, i, "health_check_interval")?;
            block.health_check_interval_secs = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for health_check_interval", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Parse: `health_check_timeout 5;`
        if token == "health_check_timeout" {
            expect_directive_value_semicolon(tokens, i, "health_check_timeout")?;
            block.health_check_timeout_secs = match tokens[i + 1].parse() {
                Ok(v) => v,
                Err(_) => return Err(format!("Invalid value '{}' for health_check_timeout", tokens[i + 1])),
            };
            i += 3;
            continue;
        }

        // Generic directive inside upstream block is an error
        return Err(format!(
            "Unknown directive '{}' inside upstream '{}' block at token position {}",
            token, name, i
        ));
    }
    Err(format!(
        "Unclosed 'upstream {}' block: missing closing '}}'",
        name
    ))
}

/// Validation helper: asserts that `tokens[i]` follows the `KEY VALUE ;` pattern.
///
/// Checks that `tokens[i+1]` exists (the value) and `tokens[i+2]` is a semicolon.
/// Returns a descriptive error if the directive is incomplete or missing its `;`.
fn expect_directive_value_semicolon(
    tokens: &[String],
    i: usize,
    directive: &str,
) -> Result<(), String> {
    if i + 2 >= tokens.len() {
        return Err(format!(
            "Directive '{directive}' at token position {i} is incomplete: expected 'VALUE ;'"
        ));
    }
    if tokens[i + 2] != ";" {
        return Err(format!(
            "Directive '{directive} {}' at token position {i} is missing a semicolon ';' (found '{}')",
            tokens[i + 1],
            tokens[i + 2]
        ));
    }
    Ok(())
}

/// Validation helper: asserts that `tokens[i+1]` is an opening brace `{`.
///
/// Used before entering a block parser to catch missing braces early with
/// a clear error message referencing the block name.
fn expect_open_brace(tokens: &[String], i: usize, block_name: &str) -> Result<(), String> {
    if i + 1 >= tokens.len() {
        return Err(format!(
            "'{block_name}' block at token position {i} is missing an opening brace '{{'"
        ));
    }
    if tokens[i + 1] != "{" {
        return Err(format!(
            "Expected '{{' after '{block_name}' at token position {i}, found '{}'",
            tokens[i + 1]
        ));
    }
    Ok(())
}

/// Lexical scanner that breaks a raw configuration string into a flat token vector.
///
/// Token types produced:
/// - **Structural**: `{`, `}`, `;` (always emitted as standalone single-char tokens)
/// - **Quoted strings**: Characters between matching `"` or `'` pairs (quotes stripped)
/// - **Words**: Contiguous non-whitespace, non-structural characters (directives, values, paths)
/// - **Comments**: Lines starting with `#` are discarded entirely
///
/// The scanner is single-pass and operates character-by-character. Quoted strings
/// preserve embedded whitespace (e.g. `"My Realm"` becomes a single token `My Realm`).
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current_token = String::new();
    let mut in_quotes = false;
    let mut in_comment = false;

    for c in input.chars() {
        // Inside a comment: consume everything until end-of-line
        if in_comment {
            if c == '\n' {
                in_comment = false;
            }
            continue;
        }

        // Start of a comment: flush any in-progress token and skip to EOL
        if c == '#' && !in_quotes {
            in_comment = true;
            if !current_token.is_empty() {
                tokens.push(current_token.clone());
                current_token.clear();
            }
            continue;
        }

        // Toggle quote state to capture strings with embedded spaces (e.g. realm names)
        if c == '"' || c == '\'' {
            in_quotes = !in_quotes;
            continue;
        }

        if in_quotes {
            current_token.push(c);
            continue;
        }

        // Whitespace acts as a token delimiter
        if c.is_whitespace() {
            if !current_token.is_empty() {
                tokens.push(current_token.clone());
                current_token.clear();
            }
            continue;
        }

        // Structural characters are their own immediate tokens
        if c == '{' || c == '}' || c == ';' {
            if !current_token.is_empty() {
                tokens.push(current_token.clone());
                current_token.clear();
            }
            tokens.push(c.to_string());
            continue;
        }

        // Build up normal text tokens (e.g., words, numbers, paths)
        current_token.push(c);
    }

    if !current_token.is_empty() {
        tokens.push(current_token);
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Happy path ──────────────────────────────────────────────────────────

    #[test]
    fn test_valid_config_parses_successfully() {
        let cfg = r#"
            worker_threads 2;
            http {
                upstream default {
                    server 127.0.0.1:8081;
                    algorithm roundrobin;
                }
                server {
                    listen 18080;
                    route / {
                        upstream default;
                        add_header X-Proxy Phalanx;
                    }
                    route /fcgi {
                        fastcgi_pass 127.0.0.1:9000;
                    }
                    route /uwsgi {
                        uwsgi_pass 127.0.0.1:3030;
                    }
                    route /static {
                        root /var/www/html;
                    }
                }
            }
        "#;
        let result = parse_phalanx_config(cfg);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        let parsed = result.unwrap();
        assert_eq!(parsed.worker_threads, Some(2));
        let http = parsed.http.unwrap();
        assert_eq!(http.upstreams.len(), 1);
        assert_eq!(http.servers.len(), 1);
        let server = &http.servers[0];
        assert_eq!(server.routes.len(), 4);
        assert!(server.routes.contains_key("/fcgi"));
        assert!(server.routes.contains_key("/uwsgi"));
        assert!(server.routes.contains_key("/static"));
        assert_eq!(
            server.routes["/fcgi"].fastcgi_pass,
            Some("127.0.0.1:9000".to_string())
        );
        assert_eq!(
            server.routes["/uwsgi"].uwsgi_pass,
            Some("127.0.0.1:3030".to_string())
        );
    }

    // ── Missing semicolon errors ────────────────────────────────────────────

    #[test]
    fn test_missing_semicolon_on_top_level_directive() {
        let cfg = "worker_threads 4\nhttp { }";
        let result = parse_phalanx_config(cfg);
        assert!(result.is_err(), "Expected Err for missing semicolon");
        let err = result.unwrap_err();
        assert!(
            err.contains("worker_threads"),
            "Error should mention the directive: {err}"
        );
        assert!(
            err.contains("semicolon") || err.contains(';'),
            "Error should mention semicolon: {err}"
        );
    }

    #[test]
    fn test_missing_semicolon_on_listen_directive() {
        let cfg = "http { server { listen 8080 } }";
        let result = parse_phalanx_config(cfg);
        assert!(
            result.is_err(),
            "Expected Err for missing semicolon on listen"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("listen"),
            "Error should mention 'listen': {err}"
        );
    }

    #[test]
    fn test_missing_semicolon_on_route_directive() {
        let cfg = r#"http { server { listen 8080; route / { upstream default } } }"#;
        let result = parse_phalanx_config(cfg);
        assert!(
            result.is_err(),
            "Expected Err for missing semicolon inside route"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("upstream") || err.contains("semicolon"),
            "Error should mention the directive or semicolon: {err}"
        );
    }

    #[test]
    fn test_missing_semicolon_on_add_header() {
        let cfg = r#"http { server { listen 8080; route / { add_header X-Foo Bar } } }"#;
        let result = parse_phalanx_config(cfg);
        assert!(
            result.is_err(),
            "Expected Err for missing semicolon on add_header"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("add_header") || err.contains("semicolon"),
            "Error should mention add_header or semicolon: {err}"
        );
    }

    // ── Unclosed brace errors ───────────────────────────────────────────────

    #[test]
    fn test_unclosed_http_block() {
        let cfg = "http {";
        let result = parse_phalanx_config(cfg);
        assert!(result.is_err(), "Expected Err for unclosed http block");
        let err = result.unwrap_err();
        assert!(
            err.contains("http") || err.contains("'}'"),
            "Error should mention http block or closing brace: {err}"
        );
    }

    #[test]
    fn test_unclosed_server_block() {
        let cfg = "http { server { listen 8080;";
        let result = parse_phalanx_config(cfg);
        assert!(result.is_err(), "Expected Err for unclosed server block");
        let err = result.unwrap_err();
        assert!(
            err.contains("server") || err.contains("'}'"),
            "Error should mention server block: {err}"
        );
    }

    #[test]
    fn test_unclosed_route_block() {
        let cfg = "http { server { listen 8080; route / { upstream default;";
        let result = parse_phalanx_config(cfg);
        assert!(result.is_err(), "Expected Err for unclosed route block");
        let err = result.unwrap_err();
        assert!(
            err.contains("route") || err.contains("'}'"),
            "Error should mention route block: {err}"
        );
    }

    #[test]
    fn test_unclosed_upstream_block() {
        let cfg = "http { upstream backend { server 127.0.0.1:8080;";
        let result = parse_phalanx_config(cfg);
        assert!(result.is_err(), "Expected Err for unclosed upstream block");
        let err = result.unwrap_err();
        assert!(
            err.contains("upstream") || err.contains("backend"),
            "Error should mention upstream block: {err}"
        );
    }

    // ── Missing opening brace errors ────────────────────────────────────────

    #[test]
    fn test_missing_opening_brace_on_http() {
        let cfg = "http server { }";
        let result = parse_phalanx_config(cfg);
        assert!(result.is_err(), "Expected Err for missing {{ after http");
        let err = result.unwrap_err();
        assert!(
            err.contains("http"),
            "Error should mention http block: {err}"
        );
    }

    #[test]
    fn test_missing_opening_brace_on_route() {
        let cfg = "http { server { listen 8080; route / upstream default; } }";
        let result = parse_phalanx_config(cfg);
        assert!(result.is_err(), "Expected Err for missing {{ after route");
        let err = result.unwrap_err();
        assert!(
            err.contains("route") || err.contains("{{") || err.contains('{'),
            "Error should mention route block or brace: {err}"
        );
    }

    // ── Unknown directive errors ─────────────────────────────────────────────

    #[test]
    fn test_unknown_top_level_directive() {
        let cfg = "notareal directive;";
        let result = parse_phalanx_config(cfg);
        assert!(
            result.is_err(),
            "Expected Err for unknown top-level directive"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("notareal") || err.contains("Unknown"),
            "Error should mention the unknown token: {err}"
        );
    }

    #[test]
    fn test_unknown_directive_inside_route() {
        let cfg = r#"http { server { listen 8080; route / { unknownkey value; } } }"#;
        let result = parse_phalanx_config(cfg);
        assert!(result.is_err(), "Expected Err for unknown route directive");
        let err = result.unwrap_err();
        assert!(
            err.contains("unknownkey") || err.contains("Unknown"),
            "Error should mention the unknown directive: {err}"
        );
    }

    #[test]
    fn test_unknown_directive_inside_upstream() {
        let cfg = r#"http { upstream pool { server 127.0.0.1:8080; badkey val; } server { listen 8080; } }"#;
        let result = parse_phalanx_config(cfg);
        assert!(
            result.is_err(),
            "Expected Err for unknown upstream directive"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("badkey") || err.contains("Unknown"),
            "Error should mention the unknown directive: {err}"
        );
    }

    // ── CORS directives ─────────────────────────────────────────────────────

    #[test]
    fn test_cors_directives_in_route_block() {
        let cfg = r#"
            http {
                server {
                    listen 8080;
                    route /api {
                        upstream default;
                        cors_enabled on;
                        cors_allowed_origins "https://example.com" "https://other.com";
                        cors_allowed_methods "GET" "POST";
                        cors_allowed_headers "Content-Type" "Authorization" "X-Custom";
                        cors_max_age 3600;
                        cors_allow_credentials on;
                    }
                }
            }
        "#;
        let result = parse_phalanx_config(cfg);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        let parsed = result.unwrap();
        let http = parsed.http.unwrap();
        let server = &http.servers[0];
        let route = &server.routes["/api"];
        assert!(route.cors_enabled);
        assert_eq!(route.cors_allowed_origins.len(), 2);
        assert_eq!(route.cors_allowed_origins[0], "https://example.com");
        assert_eq!(route.cors_allowed_methods.len(), 2);
        assert_eq!(route.cors_allowed_headers.len(), 3);
        assert_eq!(route.cors_max_age_secs, 3600);
        assert!(route.cors_allow_credentials);
    }

    #[test]
    fn test_cors_disabled_by_default() {
        let cfg = r#"
            http {
                server {
                    listen 8080;
                    route / {
                        upstream default;
                    }
                }
            }
        "#;
        let result = parse_phalanx_config(cfg).unwrap();
        let http = result.http.unwrap();
        let route = &http.servers[0].routes["/"];
        assert!(!route.cors_enabled);
        assert!(route.cors_allowed_origins.is_empty());
    }

    // ── proxy_http_version ──────────────────────────────────────────────────

    #[test]
    fn test_proxy_http_version_in_route_block() {
        let cfg = r#"
            http {
                server {
                    listen 8080;
                    route /grpc {
                        upstream default;
                        proxy_http_version 2;
                    }
                }
            }
        "#;
        let result = parse_phalanx_config(cfg).unwrap();
        let http = result.http.unwrap();
        let route = &http.servers[0].routes["/grpc"];
        assert_eq!(route.proxy_http_version, Some("2".to_string()));
    }

    // ── Traffic Splitting ──────────────────────────────────────────────────

    #[test]
    fn test_split_traffic_in_route_block() {
        let cfg = r#"
            http {
                server {
                    listen 8080;
                    route /api {
                        upstream default;
                        split_traffic pool_v1:90 pool_v2:10;
                    }
                }
            }
        "#;
        let result = parse_phalanx_config(cfg).unwrap();
        let http = result.http.unwrap();
        let route = &http.servers[0].routes["/api"];
        assert_eq!(route.split_pools, vec!["pool_v1", "pool_v2"]);
        assert_eq!(route.split_weights, vec![90, 10]);
    }

    #[test]
    fn test_split_traffic_empty_by_default() {
        let cfg = r#"
            http {
                server {
                    listen 8080;
                    route / {
                        upstream default;
                    }
                }
            }
        "#;
        let result = parse_phalanx_config(cfg).unwrap();
        let http = result.http.unwrap();
        let route = &http.servers[0].routes["/"];
        assert!(route.split_pools.is_empty());
        assert!(route.split_weights.is_empty());
    }

    // ── Health check interval/timeout ────────────────────────────────────────

    #[test]
    fn test_health_check_interval_timeout_in_upstream() {
        let cfg = r#"
            http {
                upstream backend {
                    server 127.0.0.1:8081;
                    health_check_interval 10;
                    health_check_timeout 5;
                }
                server {
                    listen 8080;
                }
            }
        "#;
        let result = parse_phalanx_config(cfg).unwrap();
        let http = result.http.unwrap();
        let upstream = &http.upstreams[0];
        assert_eq!(upstream.health_check_interval_secs, 10);
        assert_eq!(upstream.health_check_timeout_secs, 5);
    }

    #[test]
    fn test_health_check_interval_timeout_defaults() {
        let cfg = r#"
            http {
                upstream backend {
                    server 127.0.0.1:8081;
                }
                server {
                    listen 8080;
                }
            }
        "#;
        let result = parse_phalanx_config(cfg).unwrap();
        let http = result.http.unwrap();
        let upstream = &http.upstreams[0];
        assert_eq!(upstream.health_check_interval_secs, 5);
        assert_eq!(upstream.health_check_timeout_secs, 3);
    }

    // ── api_token ────────────────────────────────────────────────────────────

    #[test]
    fn test_api_token_in_server_block() {
        let cfg = r#"
            http {
                server {
                    listen 8080;
                    api_token mysecrettoken admin;
                    api_token readtoken readonly;
                }
            }
        "#;
        let result = parse_phalanx_config(cfg).unwrap();
        let http = result.http.unwrap();
        let server = &http.servers[0];
        assert_eq!(
            server.directives.get("api_token:mysecrettoken"),
            Some(&"admin".to_string())
        );
        assert_eq!(
            server.directives.get("api_token:readtoken"),
            Some(&"readonly".to_string())
        );
    }

    #[test]
    fn test_route_timeout_directives_parsed() {
        let cfg = r#"
            http {
                upstream default { server 127.0.0.1:8081; }
                server {
                    listen 8080;
                    route /api {
                        upstream default;
                        proxy_connect_timeout 5;
                        proxy_read_timeout 30;
                        proxy_next_upstream_tries 3;
                        proxy_next_upstream_timeout 10;
                        client_max_body_size 10M;
                    }
                }
            }
        "#;
        let result = parse_phalanx_config(cfg);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        let parsed = result.unwrap();
        let http = parsed.http.unwrap();
        let route = &http.servers[0].routes["/api"];
        assert_eq!(route.proxy_connect_timeout_secs, 5);
        assert_eq!(route.proxy_read_timeout_secs, 30);
        assert_eq!(route.proxy_next_upstream_tries, 3);
        assert_eq!(route.proxy_next_upstream_timeout_secs, 10);
        assert_eq!(route.client_max_body_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_route_timeout_defaults_when_not_set() {
        let cfg = r#"
            http {
                upstream default { server 127.0.0.1:8081; }
                server {
                    listen 8080;
                    route / {
                        upstream default;
                    }
                }
            }
        "#;
        let result = parse_phalanx_config(cfg);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        let route = &parsed.http.unwrap().servers[0].routes["/"];
        assert_eq!(route.proxy_connect_timeout_secs, 0);
        assert_eq!(route.proxy_read_timeout_secs, 0);
        assert_eq!(route.proxy_next_upstream_tries, 0);
        assert_eq!(route.client_max_body_size, 0);
    }

    #[test]
    fn test_client_max_body_size_suffixes_in_route() {
        let cfg = r#"
            http {
                upstream default { server 127.0.0.1:8081; }
                server {
                    listen 8080;
                    route /upload {
                        upstream default;
                        client_max_body_size 1G;
                    }
                }
            }
        "#;
        let result = parse_phalanx_config(cfg);
        assert!(result.is_ok());
        let route = &result.unwrap().http.unwrap().servers[0].routes["/upload"];
        assert_eq!(route.client_max_body_size, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_ice_server_single_directive() {
        let cfg = r#"
            http {
                upstream default { server 127.0.0.1:8081; }
                server {
                    listen 8080;
                    ice_server stun:stun.l.google.com:19302;
                }
            }
        "#;
        let result = parse_phalanx_config(cfg);
        assert!(result.is_ok());
        let servers = &result.unwrap().http.unwrap().servers;
        assert_eq!(servers[0].ice_servers, vec!["stun:stun.l.google.com:19302"]);
    }

    #[test]
    fn test_ice_server_multiple_directives_accumulate() {
        let cfg = r#"
            http {
                upstream default { server 127.0.0.1:8081; }
                server {
                    listen 8080;
                    ice_server stun:stun.l.google.com:19302;
                    ice_server turn:turn.example.com:3478?transport=udp;
                    ice_server turns:turns.example.com:5349?transport=tcp;
                }
            }
        "#;
        let result = parse_phalanx_config(cfg);
        assert!(result.is_ok());
        let servers = &result.unwrap().http.unwrap().servers;
        assert_eq!(servers[0].ice_servers.len(), 3);
        assert_eq!(servers[0].ice_servers[0], "stun:stun.l.google.com:19302");
        assert_eq!(servers[0].ice_servers[1], "turn:turn.example.com:3478?transport=udp");
        assert_eq!(servers[0].ice_servers[2], "turns:turns.example.com:5349?transport=tcp");
    }

    #[test]
    fn test_ice_server_missing_semicolon() {
        let cfg = r#"
            http {
                upstream default { server 127.0.0.1:8081; }
                server {
                    listen 8080;
                    ice_server stun:stun.l.google.com:19302
                }
            }
        "#;
        let result = parse_phalanx_config(cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_ice_server_missing_value() {
        let cfg = r#"
            http {
                upstream default { server 127.0.0.1:8081; }
                server {
                    listen 8080;
                    ice_server;
                }
            }
        "#;
        let result = parse_phalanx_config(cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_ice_server_multiple_server_blocks_accumulate_independently() {
        let cfg = r#"
            http {
                upstream default { server 127.0.0.1:8081; }
                server {
                    listen 8080;
                    ice_server stun:stun-a.example.com:3478;
                }
                server {
                    listen 8443;
                    ice_server turn:turn-b.example.com:3478;
                    ice_server stun:stun-b.example.com:3478;
                }
            }
        "#;
        let result = parse_phalanx_config(cfg);
        assert!(result.is_ok());
        let servers = &result.unwrap().http.unwrap().servers;
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].ice_servers, vec!["stun:stun-a.example.com:3478"]);
        assert_eq!(servers[1].ice_servers.len(), 2);
    }
}
