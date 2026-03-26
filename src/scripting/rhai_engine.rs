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
use std::path::PathBuf;
use tracing::{error, warn};

use crate::scripting::{HookContext, HookHandler, HookResult};

// ─── RhaiEngine ──────────────────────────────────────────────────────────────

/// Wrapper around a `rhai::Engine` instance configured with Phalanx's API.
pub struct RhaiEngine {
    engine: Engine,
}

impl RhaiEngine {
    pub fn new() -> Self {
        let mut engine = Engine::new();

        // Safety: restrict potential abuse in embedded scripts
        engine.set_max_operations(1_000_000);
        engine.set_max_string_size(65_536);
        engine.set_max_array_size(1_000);
        engine.set_max_map_size(100);

        Self { engine }
    }

    /// Compile and evaluate a script with context values in scope.
    /// Returns the raw Rhai `Dynamic` result, or `None` on error.
    fn eval_script(&self, script: &str, ctx: &HookContext) -> Option<rhai::Dynamic> {
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

        match self.engine.eval_with_scope::<rhai::Dynamic>(&mut scope, script) {
            Ok(result) => Some(result),
            Err(e) => {
                warn!("Rhai script execution error: {}", e);
                None
            }
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
pub struct RhaiHookHandler {
    engine: RhaiEngine,
    /// Compiled script content (loaded once at registration time).
    script: String,
    /// Original path — used for error messages.
    path: PathBuf,
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
            path,
        })
    }

    /// Create a handler from an inline script string (useful for tests).
    pub fn from_str(script: impl Into<String>) -> Self {
        Self {
            engine: RhaiEngine::new(),
            script: script.into(),
            path: PathBuf::from("<inline>"),
        }
    }
}

impl HookHandler for RhaiHookHandler {
    fn execute(&self, ctx: &HookContext) -> HookResult {
        let result = match self.engine.eval_script(&self.script, ctx) {
            Some(r) => r,
            None => return HookResult::Continue,
        };

        // Unit / void return → Continue
        if result.is_unit() {
            return HookResult::Continue;
        }

        // String return → parse directive
        if let Some(s) = result.clone().try_cast::<String>() {
            return parse_rhai_directive(&s);
        }

        // Bool return → false = block (403), true = allow
        if let Some(b) = result.try_cast::<bool>() {
            if !b {
                return HookResult::Respond {
                    status: 403,
                    body: "Forbidden by script".to_string(),
                    headers: std::collections::HashMap::new(),
                };
            }
            return HookResult::Continue;
        }

        HookResult::Continue
    }
}

/// Parse a string directive returned by a Rhai script.
///
/// Supported formats:
/// - `"rewrite:/new/path"` → `RewritePath`
/// - `"respond:403:Body text"` → `Respond { status, body }`
/// - Anything else → `Continue`
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
                    headers: std::collections::HashMap::new(),
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
}
