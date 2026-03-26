use bytes::Bytes;
use hyper::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, warn};

pub mod rhai_engine;


/// A plugin/hook system for extensible request/response processing.
///
/// Provides lifecycle hooks that custom scripts or compiled plugins can
/// register for. This is Phalanx's equivalent to nginx's njs / Lua / OpenResty.
///
/// Supports:
/// - Pre-compiled Rust plugin functions loaded at startup
/// - Simple JSON-based scriptable rules evaluated at runtime
/// - Future: WASM plugin support

/// The phase of the request lifecycle where a hook executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HookPhase {
    /// Before route matching — can modify the request path/headers
    PreRoute,
    /// After route matching, before backend dispatch
    PreUpstream,
    /// After receiving the response from the backend, before sending to client
    PostUpstream,
    /// During logging, after the response is sent
    Log,
}

/// The context available to a hook during execution.
#[derive(Debug, Clone)]
pub struct HookContext {
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: HashMap<String, String>,
    pub status: Option<u16>,
    pub response_headers: HashMap<String, String>,
}

/// The result of executing a hook.
#[derive(Debug, Clone)]
pub enum HookResult {
    /// Continue processing normally
    Continue,
    /// Modify the request path
    RewritePath(String),
    /// Add/modify request headers
    SetHeaders(HashMap<String, String>),
    /// Short-circuit with a custom response
    Respond {
        status: u16,
        body: String,
        headers: HashMap<String, String>,
    },
    /// Add/modify response headers (PostUpstream phase only)
    SetResponseHeaders(HashMap<String, String>),
}

/// A hook definition: a named piece of logic attached to a lifecycle phase.
pub struct Hook {
    pub name: String,
    pub phase: HookPhase,
    pub priority: i32,
    pub handler: Box<dyn HookHandler>,
}

/// Trait for implementing hook handlers.
pub trait HookHandler: Send + Sync {
    fn execute(&self, ctx: &HookContext) -> HookResult;
}

/// The hook engine manages all registered hooks and dispatches them in order.
pub struct HookEngine {
    hooks: HashMap<HookPhase, Vec<Hook>>,
}

impl HookEngine {
    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
        }
    }

    /// Registers a hook for a specific phase.
    pub fn register(&mut self, hook: Hook) {
        let phase = hook.phase;
        let hooks = self.hooks.entry(phase).or_insert_with(Vec::new);
        hooks.push(hook);
        hooks.sort_by_key(|h| h.priority);
    }

    /// Executes all hooks for a given phase, collecting results.
    pub fn execute(&self, phase: HookPhase, ctx: &HookContext) -> Vec<HookResult> {
        let hooks = match self.hooks.get(&phase) {
            Some(h) => h,
            None => return vec![],
        };

        let mut results = Vec::new();
        for hook in hooks {
            let result = hook.handler.execute(ctx);
            debug!("Hook '{}' ({:?}) → {:?}", hook.name, phase, result);
            match &result {
                HookResult::Respond { .. } => {
                    results.push(result);
                    return results; // short-circuit
                }
                _ => results.push(result),
            }
        }
        results
    }

    /// Returns whether any hooks are registered for the given phase.
    pub fn has_hooks(&self, phase: HookPhase) -> bool {
        self.hooks.get(&phase).map(|h| !h.is_empty()).unwrap_or(false)
    }
}

// ── Built-in hook implementations ──

/// A simple header-injection hook configured via JSON rules.
pub struct HeaderInjectionHook {
    headers: HashMap<String, String>,
}

impl HeaderInjectionHook {
    pub fn new(headers: HashMap<String, String>) -> Self {
        Self { headers }
    }
}

impl HookHandler for HeaderInjectionHook {
    fn execute(&self, _ctx: &HookContext) -> HookResult {
        HookResult::SetHeaders(self.headers.clone())
    }
}

/// A conditional rewrite hook that rewrites paths matching a condition.
pub struct ConditionalRewriteHook {
    condition_header: String,
    condition_value: String,
    new_path: String,
}

impl ConditionalRewriteHook {
    pub fn new(header: String, value: String, path: String) -> Self {
        Self {
            condition_header: header,
            condition_value: value,
            new_path: path,
        }
    }
}

impl HookHandler for ConditionalRewriteHook {
    fn execute(&self, ctx: &HookContext) -> HookResult {
        if ctx
            .headers
            .get(&self.condition_header)
            .map(|v| v == &self.condition_value)
            .unwrap_or(false)
        {
            HookResult::RewritePath(self.new_path.clone())
        } else {
            HookResult::Continue
        }
    }
}

/// An IP-based access control hook.
pub struct IpAccessHook {
    allowed_ips: Vec<String>,
    denied_ips: Vec<String>,
}

impl IpAccessHook {
    pub fn new(allowed: Vec<String>, denied: Vec<String>) -> Self {
        Self {
            allowed_ips: allowed,
            denied_ips: denied,
        }
    }
}

impl HookHandler for IpAccessHook {
    fn execute(&self, ctx: &HookContext) -> HookResult {
        if self.denied_ips.contains(&ctx.client_ip) {
            return HookResult::Respond {
                status: 403,
                body: "Forbidden".to_string(),
                headers: HashMap::new(),
            };
        }
        if !self.allowed_ips.is_empty() && !self.allowed_ips.contains(&ctx.client_ip) {
            return HookResult::Respond {
                status: 403,
                body: "Forbidden".to_string(),
                headers: HashMap::new(),
            };
        }
        HookResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook_ctx() -> HookContext {
        HookContext {
            client_ip: "1.2.3.4".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            headers: HashMap::new(),
            status: None,
            response_headers: HashMap::new(),
        }
    }

    #[test]
    fn test_hook_engine_empty() {
        let engine = HookEngine::new();
        let ctx = hook_ctx();
        assert!(engine.execute(HookPhase::PreRoute, &ctx).is_empty());
    }

    #[test]
    fn test_hook_engine_register_and_execute() {
        let mut headers = HashMap::new();
        headers.insert("X-Test".to_string(), "alpha".to_string());

        let mut engine = HookEngine::new();
        engine.register(Hook {
            name: "inject".to_string(),
            phase: HookPhase::PreRoute,
            priority: 0,
            handler: Box::new(HeaderInjectionHook::new(headers.clone())),
        });

        let results = engine.execute(HookPhase::PreRoute, &hook_ctx());
        assert_eq!(results.len(), 1);
        match &results[0] {
            HookResult::SetHeaders(h) => assert_eq!(h, &headers),
            other => panic!("expected SetHeaders, got {:?}", other),
        }
    }

    #[test]
    fn test_hook_priority_ordering() {
        let mut first = HashMap::new();
        first.insert("X-Order".to_string(), "first".to_string());
        let mut second = HashMap::new();
        second.insert("X-Order".to_string(), "second".to_string());

        let mut engine = HookEngine::new();
        engine.register(Hook {
            name: "later".to_string(),
            phase: HookPhase::PreRoute,
            priority: 10,
            handler: Box::new(HeaderInjectionHook::new(second.clone())),
        });
        engine.register(Hook {
            name: "earlier".to_string(),
            phase: HookPhase::PreRoute,
            priority: 0,
            handler: Box::new(HeaderInjectionHook::new(first.clone())),
        });

        let results = engine.execute(HookPhase::PreRoute, &hook_ctx());
        assert_eq!(results.len(), 2);
        match (&results[0], &results[1]) {
            (HookResult::SetHeaders(a), HookResult::SetHeaders(b)) => {
                assert_eq!(a.get("X-Order").map(String::as_str), Some("first"));
                assert_eq!(b.get("X-Order").map(String::as_str), Some("second"));
            }
            _ => panic!("expected two SetHeaders results"),
        }
    }

    #[test]
    fn test_conditional_rewrite_hook_match() {
        let mut ctx = hook_ctx();
        ctx.headers.insert("X-Flag".to_string(), "yes".to_string());

        let hook = ConditionalRewriteHook::new("X-Flag".to_string(), "yes".to_string(), "/rewritten".to_string());
        match hook.execute(&ctx) {
            HookResult::RewritePath(p) => assert_eq!(p, "/rewritten"),
            other => panic!("expected RewritePath, got {:?}", other),
        }
    }

    #[test]
    fn test_conditional_rewrite_hook_no_match() {
        let mut ctx = hook_ctx();
        ctx.headers.insert("X-Flag".to_string(), "no".to_string());

        let hook = ConditionalRewriteHook::new("X-Flag".to_string(), "yes".to_string(), "/rewritten".to_string());
        match hook.execute(&ctx) {
            HookResult::Continue => {}
            other => panic!("expected Continue, got {:?}", other),
        }
    }

    #[test]
    fn test_ip_access_hook_denied() {
        let hook = IpAccessHook::new(vec![], vec!["1.2.3.4".to_string()]);
        match hook.execute(&hook_ctx()) {
            HookResult::Respond { status, body, .. } => {
                assert_eq!(status, 403);
                assert_eq!(body, "Forbidden");
            }
            other => panic!("expected Respond, got {:?}", other),
        }
    }

    #[test]
    fn test_ip_access_hook_allowed() {
        let hook = IpAccessHook::new(vec!["1.2.3.4".to_string()], vec![]);
        match hook.execute(&hook_ctx()) {
            HookResult::Continue => {}
            other => panic!("expected Continue, got {:?}", other),
        }
    }

    #[test]
    fn test_ip_access_hook_empty_lists() {
        let hook = IpAccessHook::new(vec![], vec![]);
        match hook.execute(&hook_ctx()) {
            HookResult::Continue => {}
            other => panic!("expected Continue, got {:?}", other),
        }
    }

    #[test]
    fn test_respond_short_circuits() {
        let mut inject = HashMap::new();
        inject.insert("X-Never".to_string(), "seen".to_string());

        let mut engine = HookEngine::new();
        engine.register(Hook {
            name: "deny".to_string(),
            phase: HookPhase::PreRoute,
            priority: 0,
            handler: Box::new(IpAccessHook::new(vec![], vec!["1.2.3.4".to_string()])),
        });
        engine.register(Hook {
            name: "inject".to_string(),
            phase: HookPhase::PreRoute,
            priority: 1,
            handler: Box::new(HeaderInjectionHook::new(inject)),
        });

        let results = engine.execute(HookPhase::PreRoute, &hook_ctx());
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], HookResult::Respond { .. }));
    }

    #[test]
    fn test_has_hooks() {
        let mut engine = HookEngine::new();
        assert!(!engine.has_hooks(HookPhase::PreRoute));

        let mut h = HashMap::new();
        h.insert("a".to_string(), "b".to_string());
        engine.register(Hook {
            name: "h".to_string(),
            phase: HookPhase::PreRoute,
            priority: 0,
            handler: Box::new(HeaderInjectionHook::new(h)),
        });

        assert!(engine.has_hooks(HookPhase::PreRoute));
        assert!(!engine.has_hooks(HookPhase::PreUpstream));
    }
}
