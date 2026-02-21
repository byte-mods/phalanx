use std::collections::HashMap;

/// The root abstract syntax tree (AST) for the parsed Nginx configuration.
#[derive(Debug, Default)]
pub struct PhalanxConfig {
    /// Number of worker threads for the Tokio runtime
    pub worker_threads: Option<usize>,
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
    /// Headers to manually inject into requests/responses matched by this route
    pub add_headers: HashMap<String, String>,
}

/// A highly simplified parser for a subset of Nginx configuration syntax.
/// It converts a raw string of configuration text into the `NginxConfig` AST.
pub fn parse_phalanx_config(input: &str) -> PhalanxConfig {
    let mut config = PhalanxConfig::default();

    // First pass: Lexical analysis (tokenize the string)
    let tokens = tokenize(input);
    let mut i = 0;

    // Second pass: Recursive descent parsing
    while i < tokens.len() {
        let token = &tokens[i];

        // Parse: `worker_threads 8;`
        if token == "worker_threads" && i + 2 < tokens.len() && tokens[i + 2] == ";" {
            if let Ok(threads) = tokens[i + 1].parse::<usize>() {
                config.worker_threads = Some(threads);
            }
            i += 3;
            continue;
        }

        // Parse: `http { ... }`
        if token == "http" && i + 1 < tokens.len() && tokens[i + 1] == "{" {
            i += 2;
            let (http_block, new_i) = parse_http_block(&tokens, i);
            config.http = Some(http_block);
            i = new_i;
            continue;
        }

        i += 1;
    }

    config
}

/// Parses the contents inside an `http { ... }` block.
fn parse_http_block(tokens: &[String], mut i: usize) -> (HttpBlock, usize) {
    let mut block = HttpBlock::default();
    while i < tokens.len() {
        let token = &tokens[i];
        if token == "}" {
            return (block, i + 1);
        }

        // Parse: `server { ... }`
        if token == "server" && i + 1 < tokens.len() && tokens[i + 1] == "{" {
            i += 2;
            let (server_block, new_i) = parse_server_block(tokens, i);
            block.servers.push(server_block);
            i = new_i;
            continue;
        }

        // Parse: `upstream pool_name { ... }`
        if token == "upstream" && i + 2 < tokens.len() && tokens[i + 2] == "{" {
            let name = tokens[i + 1].clone();
            i += 3;
            let (upstream_block, new_i) = parse_upstream_block(tokens, i, name);
            block.upstreams.push(upstream_block);
            i = new_i;
            continue;
        }
        i += 1;
    }
    (block, i)
}

/// Parses the contents inside a `server { ... }` block.
fn parse_server_block(tokens: &[String], mut i: usize) -> (ServerBlock, usize) {
    let mut block = ServerBlock::default();
    while i < tokens.len() {
        let token = &tokens[i];
        if token == "}" {
            return (block, i + 1);
        }

        // Parse: `listen 8080;`
        if token == "listen" && i + 2 < tokens.len() && tokens[i + 2] == ";" {
            block.listen = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `ssl_certificate /path/to/cert.pem;`
        if token == "ssl_certificate" && i + 2 < tokens.len() && tokens[i + 2] == ";" {
            block.ssl_certificate = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `ssl_certificate_key /path/to/key.pem;`
        if token == "ssl_certificate_key" && i + 2 < tokens.len() && tokens[i + 2] == ";" {
            block.ssl_certificate_key = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `route /path { ... }`
        if token == "route" && i + 2 < tokens.len() && tokens[i + 2] == "{" {
            let path = tokens[i + 1].clone();
            i += 3;
            let (route_block, new_i) = parse_route_block(tokens, i, path.clone());
            block.routes.insert(path, route_block);
            i = new_i;
            continue;
        }

        // Generic directive: `key value;`
        if i + 2 < tokens.len() && tokens[i + 2] == ";" {
            block
                .directives
                .insert(tokens[i].clone(), tokens[i + 1].clone());
            i += 3;
            continue;
        }
        i += 1;
    }
    (block, i)
}

/// Parses the contents inside a `route /path { ... }` block.
fn parse_route_block(tokens: &[String], mut i: usize, path: String) -> (RouteBlock, usize) {
    let mut block = RouteBlock {
        path,
        upstream: None,
        add_headers: HashMap::new(),
    };
    while i < tokens.len() {
        let token = &tokens[i];
        if token == "}" {
            return (block, i + 1);
        }

        // Parse: `upstream default;`
        if token == "upstream" && i + 2 < tokens.len() && tokens[i + 2] == ";" {
            block.upstream = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        // Parse: `add_header X-Proxy Phalanx;`
        if token == "add_header" && i + 3 < tokens.len() && tokens[i + 3] == ";" {
            block
                .add_headers
                .insert(tokens[i + 1].clone(), tokens[i + 2].clone());
            i += 4;
            continue;
        }
        i += 1;
    }
    (block, i)
}

/// Basic lexical scanner that breaks a raw configuration string into semantic tokens.
/// Accounts for whitespace separation and specific control characters (`{`, `}`, `;`).
/// Also handles string literals wrapped in quotes (single or double).
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current_token = String::new();
    let mut in_quotes = false;

    for c in input.chars() {
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

/// Parses the contents inside an `upstream pool_name { ... }` block.
/// Supports:
///   `server 127.0.0.1:8081;`
///   `server 127.0.0.1:8082 weight=3;`
///   `algorithm roundrobin;`
fn parse_upstream_block(tokens: &[String], mut i: usize, name: String) -> (UpstreamBlock, usize) {
    let mut block = UpstreamBlock {
        name,
        servers: Vec::new(),
        algorithm: None,
    };
    while i < tokens.len() {
        let token = &tokens[i];
        if token == "}" {
            return (block, i + 1);
        }

        // Parse: `server 127.0.0.1:8081 weight=3;` or `server 127.0.0.1:8081;`
        if token == "server" && i + 1 < tokens.len() {
            let addr = tokens[i + 1].clone();
            i += 2;
            let mut weight = 1u32;
            // Check for optional weight=N before semicolon
            while i < tokens.len() && tokens[i] != ";" {
                if let Some(w) = tokens[i].strip_prefix("weight=") {
                    weight = w.parse().unwrap_or(1);
                }
                i += 1;
            }
            if i < tokens.len() && tokens[i] == ";" {
                i += 1; // skip semicolon
            }
            block.servers.push((addr, weight));
            continue;
        }

        // Parse: `algorithm roundrobin;`
        if token == "algorithm" && i + 2 < tokens.len() && tokens[i + 2] == ";" {
            block.algorithm = Some(tokens[i + 1].clone());
            i += 3;
            continue;
        }

        i += 1;
    }
    (block, i)
}
