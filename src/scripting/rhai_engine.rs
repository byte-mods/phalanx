//! # Rhai Embedded Scripting Engine
//!
//! Integrates the [Rhai](https://rhai.rs/) scripting language as a `HookHandler`
//! in Phalanx's `HookEngine`. This allows per-route `.rhai` scripts to inspect
//! and modify requests and responses at any hook phase, without recompiling.
//!
//! ## Exposed Rhai API
//! Scripts receive a Rhai `Map` (object map) with the following keys:
//!
//! | Key                | Type     | Description                            |
//! |--------------------|----------|----------------------------------------|
//! | `uri`              | String   | Request path + optional query string   |
//! | `method`           | String   | HTTP method (GET, POST, …)             |
//! | `client_ip`        | String   | Client IP address                      |
//! | `headers`          | Map      | Request headers (key → value)          |
//! | `status`           | i64      | Response status code (0 if pre-upstream)|
//!
//! ## Script Return Values
//! A script must return one of:
//! - `()` / `()` — HookResult::Continue
//! - `"rewrite:/new/path"` — HookResult::RewritePath
//! - `"respond:403:Forbidden"` — HookResult::Respond (status:body)
//!
//! Any other return value is treated as Continue.

use rhai::{Engine, Map, Scope};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{error, warn};

use crate::scripting::{HookContext, HookHandler, HookResult};

// ─── RhaiEngine ──────────────────────────────────────────────────────────────

/// Wrapper around a `rhai::Engine` instance configured with Phalanx's safety limits.
///
/// The engine is sandboxed with resource limits to prevent script abuse:
/// - Max 1M operations per execution (prevents infinite loops)
/// - Max 64KB string length (prevents memory bombs)
/// - Max 1000 array elements and 100 map entries
///
/// Scripts can call `set_header(name, value)` to inject request headers and
/// `set_var(key, value)` to set metadata variables. These are collected after
/// execution and returned as part of the `RhaiResult`.
pub struct RhaiEngine {
    /// The underlying Rhai scripting engine with configured safety limits.
    engine: Engine,
    /// Headers set by script via `set_header(name, value)`.
    pending_headers: Arc<Mutex<HashMap<String, String>>>,
    /// Variables set by script via `set_var(key, value)`.
    pending_vars: Arc<Mutex<HashMap<String, String>>>,
}

/// Result of a Rhai script evaluation including side-effects.
pub struct RhaiResult {
    /// The return value of the script.
    pub value: Option<rhai::Dynamic>,
    /// Headers set via `set_header()` during execution.
    pub headers: HashMap<String, String>,
    /// Variables set via `set_var()` during execution.
    pub vars: HashMap<String, String>,
}

impl RhaiEngine {
    /// Creates a new Rhai engine with security limits applied.
    pub fn new() -> Self {
        let mut engine = Engine::new();

        // Safety: restrict potential abuse in embedded scripts
        engine.set_max_operations(1_000_000);
        engine.set_max_string_size(65_536);
        engine.set_max_array_size(1_000);
        engine.set_max_map_size(100);

        let pending_headers: Arc<Mutex<HashMap<String, String>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_vars: Arc<Mutex<HashMap<String, String>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Register set_header(name, value) function
        let hdrs = Arc::clone(&pending_headers);
        engine.register_fn("set_header", move |name: String, value: String| {
            if let Ok(mut map) = hdrs.lock() {
                map.insert(name, value);
            }
        });

        // Register set_var(key, value) function
        let vars = Arc::clone(&pending_vars);
        engine.register_fn("set_var", move |key: String, value: String| {
            if let Ok(mut map) = vars.lock() {
                map.insert(key, value);
            }
        });

        Self {
            engine,
            pending_headers,
            pending_vars,
        }
    }

    /// Compile and evaluate a script with request context values injected into scope.
    ///
    /// Populates the Rhai scope with `uri`, `method`, `client_ip`, `status`, and
    /// `headers` variables, then evaluates the script. Returns the script result
    /// along with any headers/vars set via `set_header()`/`set_var()`.
    fn eval_script(&self, script: &str, ctx: &HookContext) -> RhaiResult {
        // Clear pending state from any previous execution
        if let Ok(mut h) = self.pending_headers.lock() {
            h.clear();
        }
        if let Ok(mut v) = self.pending_vars.lock() {
            v.clear();
        }

        let mut scope = Scope::new();

        // Populate the scope with request context variables
        scope.push("uri", ctx.path.clone());
        scope.push("method", ctx.method.clone());
        scope.push("client_ip", ctx.client_ip.clone());
        scope.push("status", ctx.status.map(|s| s as i64).unwrap_or(0i64));

        // Convert headers HashMap<String, String> → rhai::Map
        let mut headers_map = Map::new();
        for (k, v) in &ctx.headers {
            headers_map.insert(k.clone().into(), v.clone().into());
        }
        scope.push("headers", headers_map);

        let value = match self.engine.eval_with_scope::<rhai::Dynamic>(&mut scope, script) {
            Ok(result) => Some(result),
            Err(e) => {
                warn!("Rhai script execution error: {}", e);
                None
            }
        };

        // Collect side-effects
        let headers = self
            .pending_headers
            .lock()
            .map(|h| h.clone())
            .unwrap_or_default();
        let vars = self
            .pending_vars
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default();

        RhaiResult {
            value,
            headers,
            vars,
        }
    }
}

impl Default for RhaiEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── RhaiHookHandler ─────────────────────────────────────────────────────────

/// A `HookHandler` that executes a `.rhai` script file at a configured hook phase.
///
/// The script is loaded once at registration time and re-evaluated on every
/// request. Each invocation gets a fresh Rhai scope populated with request context.
pub struct RhaiHookHandler {
    /// Dedicated Rhai engine instance for this handler.
    engine: RhaiEngine,
    /// Script source code (loaded once from file or inline string at registration).
    script: String,
}

impl RhaiHookHandler {
    /// Create a new handler by loading and compiling a script file.
    /// Returns an error string if the file cannot be read.
    pub fn from_file<P: Into<PathBuf>>(path: P) -> Result<Self, String> {
        let path = path.into();
        let script = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to load Rhai script {:?}: {}", path, e))?;
        Ok(Self {
            engine: RhaiEngine::new(),
            script,
        })
    }

    /// Create a handler from an inline script string (useful for tests).
    pub fn from_str(script: impl Into<String>) -> Self {
        Self {
            engine: RhaiEngine::new(),
            script: script.into(),
        }
    }
}

impl HookHandler for RhaiHookHandler {
    /// Executes the Rhai script and interprets its return value as a `HookResult`.
    ///
    /// Return value interpretation (checked in order):
    /// 1. `()` (unit) -> Continue (or SetHeaders if `set_header()` was called)
    /// 2. `String` -> Parsed as a directive ("rewrite:/path" or "respond:403:body")
    /// 3. `bool` -> false = 403 Forbidden, true = Continue
    /// 4. Any other type -> Continue (treated as no-op)
    ///
    /// If the script called `set_header(name, value)`, those headers are returned
    /// via `HookResult::SetHeaders` (merged with any directive result).
    fn execute(&self, ctx: &HookContext) -> HookResult {
        let rhai_result = self.engine.eval_script(&self.script, ctx);

        let result = match rhai_result.value {
            Some(r) => r,
            // Script error (syntax, runtime, resource limit) -> fail open
            None => {
                // Even on error, return any headers that were set before the failure
                if !rhai_result.headers.is_empty() {
                    return HookResult::SetHeaders(rhai_result.headers);
                }
                return HookResult::Continue;
            }
        };

        // Check for set_header side-effects — if present and no other directive,
        // return SetHeaders
        let has_set_headers = !rhai_result.headers.is_empty();

        // Unit / void return -> Continue or SetHeaders
        if result.is_unit() {
            if has_set_headers {
                return HookResult::SetHeaders(rhai_result.headers);
            }
            return HookResult::Continue;
        }

        // String return -> parse as a directive command
        if let Some(s) = result.clone().try_cast::<String>() {
            let directive = parse_rhai_directive(&s);
            // If headers were set and the directive is Continue, upgrade to SetHeaders
            if has_set_headers && matches!(directive, HookResult::Continue) {
                return HookResult::SetHeaders(rhai_result.headers);
            }
            return directive;
        }

        // Bool return -> false = block (403), true = allow
        if let Some(b) = result.try_cast::<bool>() {
            if !b {
                return HookResult::Respond {
                    status: 403,
                    body: "Forbidden by script".to_string(),
                    headers: HashMap::new(),
                };
            }
            if has_set_headers {
                return HookResult::SetHeaders(rhai_result.headers);
            }
            return HookResult::Continue;
        }

        if has_set_headers {
            return HookResult::SetHeaders(rhai_result.headers);
        }
        HookResult::Continue
    }
}

/// Parses a string directive returned by a Rhai script into a `HookResult`.
///
/// This is the bridge between Rhai's untyped string return values and Phalanx's
/// typed hook result system. The format is intentionally simple so scripts can
/// control behavior with plain string concatenation.
///
/// # Supported formats
/// - `"rewrite:/new/path"` -> `RewritePath("/new/path")`
/// - `"respond:403:Forbidden"` -> `Respond { status: 403, body: "Forbidden" }`
/// - Anything else -> `Continue`
fn parse_rhai_directive(s: &str) -> HookResult {
    if let Some(path) = s.strip_prefix("rewrite:") {
        return HookResult::RewritePath(path.to_string());
    }
    if let Some(rest) = s.strip_prefix("respond:") {
        if let Some((code, body)) = rest.split_once(':') {
            if let Ok(status) = code.parse::<u16>() {
                return HookResult::Respond {
                    status,
                    body: body.to_string(),
                    headers: HashMap::new(),
                };
            }
        }
        error!("Rhai: malformed respond directive '{}'", s);
    }
    HookResult::Continue
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scripting::HookContext;
    use std::collections::HashMap;

    fn ctx() -> HookContext {
        HookContext {
            client_ip: "10.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            query: None,
            headers: HashMap::new(),
            status: None,
            response_headers: HashMap::new(),
        }
    }

    #[test]
    fn test_unit_return_continues() {
        let handler = RhaiHookHandler::from_str("()");
        assert!(matches!(handler.execute(&ctx()), HookResult::Continue));
    }

    #[test]
    fn test_rewrite_directive() {
        let handler = RhaiHookHandler::from_str(r#""rewrite:/new/path""#);
        match handler.execute(&ctx()) {
            HookResult::RewritePath(p) => assert_eq!(p, "/new/path"),
            other => panic!("expected RewritePath, got {:?}", other),
        }
    }

    #[test]
    fn test_respond_directive() {
        let handler = RhaiHookHandler::from_str(r#""respond:403:Denied by policy""#);
        match handler.execute(&ctx()) {
            HookResult::Respond { status, body, .. } => {
                assert_eq!(status, 403);
                assert_eq!(body, "Denied by policy");
            }
            other => panic!("expected Respond, got {:?}", other),
        }
    }

    #[test]
    fn test_bool_false_blocks() {
        let handler = RhaiHookHandler::from_str("false");
        assert!(matches!(
            handler.execute(&ctx()),
            HookResult::Respond { status: 403, .. }
        ));
    }

    #[test]
    fn test_bool_true_continues() {
        let handler = RhaiHookHandler::from_str("true");
        assert!(matches!(handler.execute(&ctx()), HookResult::Continue));
    }

    #[test]
    fn test_ip_access_via_script() {
        // Script blocks a specific IP
        let script = r#"
            if client_ip == "10.0.0.1" {
                "respond:403:IP Blocked"
            } else {
                ()
            }
        "#;
        let handler = RhaiHookHandler::from_str(script);
        match handler.execute(&ctx()) {
            HookResult::Respond { status: 403, .. } => {}
            other => panic!("expected Respond 403, got {:?}", other),
        }
    }

    #[test]
    fn test_conditional_rewrite_via_script() {
        let script = r#"
            if uri.starts_with("/old") {
                "rewrite:/new"
            } else {
                ()
            }
        "#;
        let mut c = ctx();
        c.path = "/old/api".to_string();
        let handler = RhaiHookHandler::from_str(script);
        match handler.execute(&c) {
            HookResult::RewritePath(p) => assert_eq!(p, "/new"),
            other => panic!("expected RewritePath, got {:?}", other),
        }
    }

    #[test]
    fn test_script_can_read_headers() {
        // Use 'in' keyword for rhai Map membership check
        let script = r#"
            if "x-internal" in headers {
                "respond:200:OK internal"
            } else {
                ()
            }
        "#;
        let mut c = ctx();
        c.headers
            .insert("x-internal".to_string(), "true".to_string());
        let handler = RhaiHookHandler::from_str(script);
        match handler.execute(&c) {
            HookResult::Respond { status: 200, .. } => {}
            other => panic!("expected Respond 200, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_script_continues() {
        let handler = RhaiHookHandler::from_str("this is not valid rhai code !!!");
        // Should not panic — returns Continue
        assert!(matches!(handler.execute(&ctx()), HookResult::Continue));
    }

    #[test]
    fn test_set_header_returns_set_headers() {
        let script = r#"
            set_header("X-Custom", "injected-value");
        "#;
        let handler = RhaiHookHandler::from_str(script);
        match handler.execute(&ctx()) {
            HookResult::SetHeaders(hdrs) => {
                assert_eq!(hdrs.get("X-Custom").unwrap(), "injected-value");
            }
            other => panic!("expected SetHeaders, got {:?}", other),
        }
    }

    #[test]
    fn test_set_var_collected() {
        // set_var doesn't directly affect HookResult, but set_header does.
        // Verify both work together.
        let script = r#"
            set_var("request_id", "abc-123");
            set_header("X-Request-Id", "abc-123");
        "#;
        let handler = RhaiHookHandler::from_str(script);
        match handler.execute(&ctx()) {
            HookResult::SetHeaders(hdrs) => {
                assert_eq!(hdrs.get("X-Request-Id").unwrap(), "abc-123");
            }
            other => panic!("expected SetHeaders, got {:?}", other),
        }
    }

    #[test]
    fn test_set_header_with_rewrite_returns_rewrite() {
        // When the script explicitly returns a rewrite directive, headers from
        // set_header() are not merged — the directive takes precedence.
        let script = r#"
            set_header("X-Extra", "val");
            "rewrite:/new-path"
        "#;
        let handler = RhaiHookHandler::from_str(script);
        match handler.execute(&ctx()) {
            HookResult::RewritePath(p) => assert_eq!(p, "/new-path"),
            other => panic!("expected RewritePath, got {:?}", other),
        }
    }

    #[test]
    fn test_multiple_set_headers() {
        let script = r#"
            set_header("X-One", "1");
            set_header("X-Two", "2");
            set_header("X-Three", "3");
        "#;
        let handler = RhaiHookHandler::from_str(script);
        match handler.execute(&ctx()) {
            HookResult::SetHeaders(hdrs) => {
                assert_eq!(hdrs.len(), 3);
                assert_eq!(hdrs.get("X-One").unwrap(), "1");
                assert_eq!(hdrs.get("X-Two").unwrap(), "2");
                assert_eq!(hdrs.get("X-Three").unwrap(), "3");
            }
            other => panic!("expected SetHeaders, got {:?}", other),
        }
    }
}
