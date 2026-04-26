use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info};

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

/// The request/response context available to a hook during execution.
///
/// This struct is populated by the proxy pipeline and passed to every hook
/// handler. Pre-upstream hooks see request data; post-upstream hooks also
/// see the response status and headers.
///
/// Performance: the high-frequency request fields (`client_ip`, `method`,
/// `path`, `query`) are `Arc<str>` so the proxy can build them **once** per
/// request and `Arc::clone` (atomic increment, no heap allocation) into
/// each per-phase context. Previously these were owned `String`s, which
/// meant every phase that fired re-allocated all four. The `headers` and
/// `response_headers` maps stay `HashMap<String, String>` because they're
/// per-phase data (request headers vs response headers) and there's no
/// cross-phase sharing to amortize.
#[derive(Debug, Clone)]
pub struct HookContext {
    /// Client's IP address (after real-IP extraction).
    pub client_ip: Arc<str>,
    /// HTTP method (e.g. "GET", "POST").
    pub method: Arc<str>,
    /// Request URI path (e.g. "/api/users").
    pub path: Arc<str>,
    /// Optional query string (without the leading `?`).
    pub query: Option<Arc<str>>,
    /// Request headers as a flat key-value map.
    pub headers: HashMap<String, String>,
    /// Response status code (only populated in PostUpstream and Log phases).
    pub status: Option<u16>,
    /// Response headers from the backend (only populated in PostUpstream and Log phases).
    pub response_headers: HashMap<String, String>,
}

/// The result of executing a hook, determining how the proxy pipeline proceeds.
///
/// Hooks can pass through, modify the request, inject headers, or short-circuit
/// the entire pipeline with a custom response. The proxy processes results
/// sequentially; a `Respond` variant stops further hook execution.
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
///
/// Hooks within the same phase are executed in ascending `priority` order.
/// Lower priority values execute first.
pub struct Hook {
    /// Human-readable name for logging and debugging (e.g. "rate-limit-check").
    pub name: String,
    /// The lifecycle phase when this hook fires.
    pub phase: HookPhase,
    /// Execution order within the phase. Lower values run first.
    pub priority: i32,
    /// The actual logic to execute. Must be `Send + Sync` for concurrent use.
    pub handler: Box<dyn HookHandler>,
}

/// Trait for implementing hook handlers.
///
/// Implementors receive the current request/response context and return a
/// `HookResult` that controls pipeline behavior. Implementations must be
/// `Send + Sync` because hooks run concurrently across Tokio tasks.
pub trait HookHandler: Send + Sync {
    /// Execute the hook logic against the given context.
    ///
    /// # Returns
    /// A `HookResult` indicating whether to continue, rewrite, inject headers,
    /// or short-circuit the request with a custom response.
    fn execute(&self, ctx: &HookContext) -> HookResult;
}

/// The hook engine manages all registered hooks and dispatches them in order.
///
/// Hooks are organized by phase, and within each phase sorted by priority.
/// The engine is typically initialized once at startup and shared immutably
/// across all request-handling tasks.
pub struct HookEngine {
    /// Map from lifecycle phase to sorted list of hooks for that phase.
    /// Wrapped in RwLock for interior mutability to support SIGHUP reload
    /// (re-registering Rhai hooks without rebuilding the entire engine).
    hooks: RwLock<HashMap<HookPhase, Vec<Hook>>>,
    /// Lock-free per-phase presence bitmap. Indexed by `phase_index()`.
    /// Read on every request via `has_hooks()` to skip building a HookContext
    /// when nothing is registered — turns 4 RwLock reads + HashMap lookups
    /// per request into 4 relaxed atomic loads.
    phase_present: [AtomicBool; 4],
}

/// Maps a `HookPhase` variant to its slot in `phase_present`.
#[inline]
fn phase_index(phase: HookPhase) -> usize {
    match phase {
        HookPhase::PreRoute => 0,
        HookPhase::PreUpstream => 1,
        HookPhase::PostUpstream => 2,
        HookPhase::Log => 3,
    }
}

impl HookEngine {
    /// Creates a new empty hook engine with no registered hooks.
    pub fn new() -> Self {
        Self {
            hooks: RwLock::new(HashMap::new()),
            phase_present: [
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
            ],
        }
    }

    /// Registers a hook for a specific phase and re-sorts by priority.
    ///
    /// The hook list is sorted after each insertion so that execution order
    /// is always deterministic based on the `priority` field.
    pub fn register(&self, hook: Hook) {
        let phase = hook.phase;
        let mut hooks = self.hooks.write();
        let phase_hooks = hooks.entry(phase).or_insert_with(Vec::new);
        phase_hooks.push(hook);
        phase_hooks.sort_by_key(|h| h.priority);
        // Mark this phase as populated. Release pairs with the Acquire load
        // in has_hooks() so a request-thread that observes `true` is
        // guaranteed to see the pushed Hook in the map under the read lock.
        self.phase_present[phase_index(phase)].store(true, Ordering::Release);
    }

    /// Executes all hooks for a given phase in priority order, collecting results.
    ///
    /// If any hook returns `HookResult::Respond`, execution stops immediately
    /// (short-circuit) and only results up to and including that response are returned.
    /// This enables early denial (e.g. IP block) without running subsequent hooks.
    pub fn execute(&self, phase: HookPhase, ctx: &HookContext) -> Vec<HookResult> {
        let hooks = self.hooks.read();
        let phase_hooks = match hooks.get(&phase) {
            Some(h) => h,
            None => return vec![],
        };

        let mut results = Vec::new();
        for hook in phase_hooks {
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
    ///
    /// Hot path: this is called on every request, once per phase. It reads
    /// a single relaxed-but-acquire atomic — no `RwLock`, no `HashMap` lookup
    /// — so the common case (no hooks configured) costs ~1 ns instead of
    /// taking a parking_lot read lock four times per request.
    pub fn has_hooks(&self, phase: HookPhase) -> bool {
        self.phase_present[phase_index(phase)].load(Ordering::Acquire)
    }

    /// Removes all Rhai hooks (identified by name prefix "rhai:") and re-registers
    /// from the given script file. Called on SIGHUP reload when `rhai_script` changes.
    ///
    /// On error, logs a warning and preserves existing hooks.
    pub fn reload_rhai_script(&self, script_path: &str) {
        match rhai_engine::RhaiHookHandler::from_file(script_path) {
            Ok(handler) => {
                // Remove existing Rhai hooks, then recompute the per-phase
                // presence bits — `retain` may have emptied a phase entirely.
                {
                    let mut hooks = self.hooks.write();
                    for phase_hooks in hooks.values_mut() {
                        phase_hooks.retain(|h| !h.name.starts_with("rhai:"));
                    }
                    for (phase, phase_hooks) in hooks.iter() {
                        self.phase_present[phase_index(*phase)]
                            .store(!phase_hooks.is_empty(), Ordering::Release);
                    }
                }
                // Register the new Rhai handler for all 4 phases. `register()`
                // re-sets the corresponding presence bit.
                let handler = std::sync::Arc::new(handler);
                for phase in [HookPhase::PreRoute, HookPhase::PreUpstream, HookPhase::PostUpstream, HookPhase::Log] {
                    self.register(Hook {
                        name: format!("rhai:{}", script_path),
                        phase,
                        priority: 50,
                        handler: Box::new(RhaiHookProxy(std::sync::Arc::clone(&handler))),
                    });
                }
                info!("Rhai script reloaded from {}", script_path);
            }
            Err(e) => {
                tracing::warn!("Rhai script reload failed (keeping existing): {}", e);
            }
        }
    }
}

/// Proxy that delegates to a shared RhaiHookHandler via Arc.
struct RhaiHookProxy(std::sync::Arc<rhai_engine::RhaiHookHandler>);

impl HookHandler for RhaiHookProxy {
    fn execute(&self, ctx: &HookContext) -> HookResult {
        self.0.execute(ctx)
    }
}

// ── Built-in hook implementations ──

/// A simple header-injection hook configured via JSON rules.
///
/// Unconditionally adds/overwrites the configured headers on every request
/// that passes through this hook's phase. Useful for adding security headers
/// (e.g. `X-Frame-Options`, `Strict-Transport-Security`).
pub struct HeaderInjectionHook {
    /// Headers to inject (key -> value).
    headers: HashMap<String, String>,
}

impl HeaderInjectionHook {
    /// Creates a new header injection hook with the given header map.
    pub fn new(headers: HashMap<String, String>) -> Self {
        Self { headers }
    }
}

impl HookHandler for HeaderInjectionHook {
    fn execute(&self, _ctx: &HookContext) -> HookResult {
        HookResult::SetHeaders(self.headers.clone())
    }
}

/// A conditional rewrite hook that rewrites the request path when a specific
/// header matches a specific value.
///
/// Example: Rewrite to `/v2/api` when `X-API-Version: 2` is present.
pub struct ConditionalRewriteHook {
    /// The header name to check (e.g. "X-API-Version").
    condition_header: String,
    /// The expected header value that triggers the rewrite.
    condition_value: String,
    /// The new path to rewrite to when the condition matches.
    new_path: String,
}

impl ConditionalRewriteHook {
    /// Creates a new conditional rewrite hook.
    ///
    /// # Arguments
    /// * `header` - Header name to match against.
    /// * `value` - Expected header value to trigger rewrite.
    /// * `path` - New request path when condition is met.
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
///
/// Implements a deny-first, then allow-list policy:
/// 1. If the client IP is in `denied_ips`, return 403 immediately.
/// 2. If `allowed_ips` is non-empty and the client IP is NOT in it, return 403.
/// 3. Otherwise, allow the request to continue.
///
/// When both lists are empty, all IPs are allowed.
pub struct IpAccessHook {
    /// Allowlist of client IPs. Empty = allow all (unless denied).
    allowed_ips: Vec<String>,
    /// Denylist of client IPs. Checked before the allowlist.
    denied_ips: Vec<String>,
}

impl IpAccessHook {
    /// Creates a new IP access hook with the given allow/deny lists.
    pub fn new(allowed: Vec<String>, denied: Vec<String>) -> Self {
        Self {
            allowed_ips: allowed,
            denied_ips: denied,
        }
    }
}

impl HookHandler for IpAccessHook {
    fn execute(&self, ctx: &HookContext) -> HookResult {
        // `ctx.client_ip` is `Arc<str>`; `denied_ips`/`allowed_ips` are
        // `Vec<String>`. Compare via `&str` deref so we don't have to
        // convert types just to call `Vec::contains`.
        let ip: &str = &ctx.client_ip;
        // Step 1: Check denylist first (deny takes precedence over allow)
        if self.denied_ips.iter().any(|s| s == ip) {
            return HookResult::Respond {
                status: 403,
                body: "Forbidden".to_string(),
                headers: HashMap::new(),
            };
        }
        // Step 2: If an allowlist exists, the client must be on it
        if !self.allowed_ips.is_empty() && !self.allowed_ips.iter().any(|s| s == ip) {
            return HookResult::Respond {
                status: 403,
                body: "Forbidden".to_string(),
                headers: HashMap::new(),
            };
        }
        // Step 3: Not denied, and either on allowlist or no allowlist defined
        HookResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook_ctx() -> HookContext {
        HookContext {
            client_ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/".into(),
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

        let engine = HookEngine::new();
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

        let engine = HookEngine::new();
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

        let engine = HookEngine::new();
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
        let engine = HookEngine::new();
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

    /// Validates the atomic phase-present bitmap that backs `has_hooks()`:
    /// - registration on one phase must not flip another phase's bit
    /// - all four phases must be independently addressable
    /// Regression guard for the P6 perf fix (avoids the per-request RwLock).
    #[test]
    fn test_has_hooks_atomic_per_phase_isolation() {
        let engine = HookEngine::new();
        for p in [
            HookPhase::PreRoute,
            HookPhase::PreUpstream,
            HookPhase::PostUpstream,
            HookPhase::Log,
        ] {
            assert!(!engine.has_hooks(p), "fresh engine should report no hooks");
        }

        let mut h = HashMap::new();
        h.insert("k".into(), "v".into());
        engine.register(Hook {
            name: "post".into(),
            phase: HookPhase::PostUpstream,
            priority: 0,
            handler: Box::new(HeaderInjectionHook::new(h)),
        });

        assert!(engine.has_hooks(HookPhase::PostUpstream));
        // The other three slots must remain false — the bit-array indexing
        // must not collide.
        assert!(!engine.has_hooks(HookPhase::PreRoute));
        assert!(!engine.has_hooks(HookPhase::PreUpstream));
        assert!(!engine.has_hooks(HookPhase::Log));
    }

    /// Hot-path correctness: many concurrent readers must all observe the
    /// post-register state without deadlock or torn reads. This is what the
    /// per-request `has_hooks()` calls look like at runtime.
    #[test]
    fn test_has_hooks_concurrent_readers() {
        use std::sync::Arc;
        use std::thread;

        let engine = Arc::new(HookEngine::new());
        let mut h = HashMap::new();
        h.insert("k".into(), "v".into());
        engine.register(Hook {
            name: "log".into(),
            phase: HookPhase::Log,
            priority: 0,
            handler: Box::new(HeaderInjectionHook::new(h)),
        });

        let mut handles = Vec::new();
        for _ in 0..8 {
            let e = Arc::clone(&engine);
            handles.push(thread::spawn(move || {
                for _ in 0..10_000 {
                    assert!(e.has_hooks(HookPhase::Log));
                    assert!(!e.has_hooks(HookPhase::PreRoute));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
