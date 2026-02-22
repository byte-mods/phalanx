use std::collections::HashMap;

/// The root abstract syntax tree (AST) for the parsed Nginx configuration.
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
}

/// Represents a `server { ... }` block inside the HTTP block.
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
}

/// Represents a `route /path { ... }` block inside a server.
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
    pub auth_basic_realm: Option<String>,
    pub auth_basic_users: HashMap<String, String>,
    pub auth_jwt_secret: Option<String>,
    pub auth_jwt_algorithm: Option<String>,
    pub auth_oauth_introspect_url: Option<String>,
    pub auth_oauth_client_id: Option<String>,
    pub auth_oauth_client_secret: Option<String>,
    // ── Gzip + Cache ────────────────────────────────────────────────────────────
    pub gzip: bool,
    pub gzip_min_length: usize,
    pub proxy_cache: bool,
    pub proxy_cache_valid_secs: u64,
}

/// A strict parser for a subset of Nginx configuration syntax.
/// Returns a descriptive error string if the configuration is malformed.
///
/// Rules enforced:
/// - Every directive must end with a semicolon `;`
/// - Every block opened with `{` must be closed with `}`
/// - Unknown or unexpected tokens cause an immediate parse failure
pub fn parse_phalanx_config(input: &str) -> Result<PhalanxConfig, String> {
    let mut config = PhalanxConfig::default();

    // First pass: Lexical analysis (tokenize the string)
    let tokens = tokenize(input);
    let mut i = 0;

    // Second pass: Recursive descent parsing
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
            block.gzip_min_length = tokens[i + 1].parse().unwrap_or(1024);
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
            block.proxy_cache_valid_secs = tokens[i + 1].parse().unwrap_or(60);
            i += 3;
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
/// Supports:
///   `server 127.0.0.1:8081;`
///   `server 127.0.0.1:8082 weight=3;`
///   `algorithm roundrobin;`
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
    };
    while i < tokens.len() {
        let token = &tokens[i];
        if token == "}" {
            return Ok((block, i + 1));
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
            block.keepalive = tokens[i + 1].parse().unwrap_or(0);
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
            block.health_check_status = tokens[i + 1].parse().unwrap_or(200);
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

/// Asserts that `tokens[i]` is a directive keyword with the pattern: `KEY VALUE ;`
/// i.e., tokens[i+1] is a value and tokens[i+2] is a semicolon.
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

/// Asserts that `tokens[i+1]` is an opening brace `{`.
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

/// Basic lexical scanner that breaks a raw configuration string into semantic tokens.
/// Accounts for whitespace separation and specific control characters (`{`, `}`, `;`).
/// Also handles string literals wrapped in quotes (single or double).
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current_token = String::new();
    let mut in_quotes = false;
    let mut in_comment = false;

    for c in input.chars() {
        if in_comment {
            if c == '\n' {
                in_comment = false;
            }
            continue;
        }

        if c == '#' && !in_quotes {
            in_comment = true;
            if !current_token.is_empty() {
                tokens.push(current_token.clone());
                current_token.clear();
            }
            continue;
        }

        // Toggle quote state to capture strings with embedded spaces
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
}
