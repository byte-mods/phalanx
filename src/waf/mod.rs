/// Web Application Firewall (WAF) engine.
///
/// Orchestrates multiple protection layers in a prioritized pipeline:
/// 1. **Keyval ban list** -- dynamic bans from the admin API or external feeds
/// 2. **IP reputation** -- automatic bans based on accumulated strike points
/// 3. **Bot detection** -- User-Agent classification and malicious scanner blocking
/// 4. **OWASP rule inspection** -- regex-based SQLi, XSS, LFI, command injection detection
/// 5. **Declarative policy engine** -- custom NGINX App Protect-style rules (SSRF, XXE, etc.)
/// 6. **ML fraud detection** -- asynchronous ONNX model inference for anomaly scoring
///
/// Sub-modules:
/// - [`rules`] - Compiled OWASP Top 10 regex patterns
/// - [`bot`] - Tiered bot classification and CAPTCHA challenge management
/// - [`policy`] - Declarative WAF policies with custom rules and exclusions
/// - [`reputation`] - IP strike tracking with auto-ban and expiry
/// - [`ml_fraud`] - Background ONNX-based fraud scoring engine
use arc_swap::ArcSwap;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::keyval::KeyvalStore;

pub mod bot;
pub mod ml_fraud;
pub mod policy;
pub mod reputation;
pub mod rules;

use self::ml_fraud::MlFraudEngine;
use self::policy::PolicyEngine;
use self::reputation::IpReputationManager;
use self::rules::WafRules;

/// The outcome of a WAF inspection on a request.
#[derive(Debug, PartialEq)]
pub enum WafAction {
    /// The request passed all WAF checks and may proceed to the backend.
    Allow,
    /// The request was blocked; the `String` contains a human-readable reason
    /// (e.g., "SQL Injection (SQLi)") suitable for logging and error responses.
    Block(String),
}

/// A single WAF attack event recorded for the dashboard live feed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackEvent {
    pub timestamp: u64,
    pub ip: String,
    pub path: String,
    pub reason: String,
    pub method: String,
}

/// Core WAF engine that coordinates all protection layers.
///
/// Cloneable (all inner state is behind `Arc`) so it can be shared across
/// async request handlers. The `inspect()` method runs the full pipeline
/// synchronously; the ML engine runs asynchronously in a background task.
#[derive(Clone)]
pub struct WafEngine {
    /// Compiled OWASP regex rule sets for payload inspection (hot-swappable via ArcSwap).
    rules: Arc<ArcSwap<WafRules>>,
    /// IP reputation manager for strike tracking and auto-bans.
    pub reputation: Arc<IpReputationManager>,
    /// Master switch -- when `false`, all inspection is bypassed.
    pub enabled: bool,
    /// Optional keyval store: if `keyval.get(ip)` returns any value, the IP is banned.
    keyval: Option<Arc<KeyvalStore>>,
    /// Asynchronous Machine Learning Fraud Detection Engine (ONNX-based).
    pub ml_engine: Arc<MlFraudEngine>,
    /// Declarative WAF policy engine (hot-swappable via ArcSwap).
    pub policy_engine: Arc<ArcSwap<PolicyEngine>>,
    /// Rolling log of the last 200 attack events for the admin dashboard live feed.
    pub attack_log: Arc<RwLock<VecDeque<AttackEvent>>>,
}

/// Decodes percent-encoded URL sequences (%XX → character).
/// This ensures WAF regex patterns can match payloads like `%20` (space),
/// `%3C` (<), `%27` ('), etc. Also converts `+` to space (form encoding).
fn url_decode(input: &str) -> String {
    let mut result = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            result.push(b' ');
        } else {
            result.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

impl WafEngine {
    /// Creates a new WAF engine with default OWASP rules and an empty policy engine.
    ///
    /// The ML fraud engine starts uninitialized; call `ml_engine.load_model()` to activate it.
    pub fn new(enabled: bool, reputation: Arc<IpReputationManager>) -> Self {
        Self {
            rules: Arc::new(ArcSwap::from_pointee(WafRules::new())),
            reputation,
            enabled,
            keyval: None,
            ml_engine: Arc::new(MlFraudEngine::new()),
            policy_engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new())),
            attack_log: Arc::new(RwLock::new(VecDeque::with_capacity(200))),
        }
    }

    /// Records an attack event in the rolling log (max 200 entries).
    pub async fn record_attack(&self, ip: &str, path: &str, method: &str, reason: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let event = AttackEvent {
            timestamp: now,
            ip: ip.to_string(),
            path: path.to_string(),
            reason: reason.to_string(),
            method: method.to_string(),
        };
        let mut log = self.attack_log.write().await;
        if log.len() >= 200 {
            log.pop_front();
        }
        log.push_back(event);
    }

    /// Returns the last N attack events (newest first).
    pub async fn recent_attacks(&self, n: usize) -> Vec<AttackEvent> {
        let log = self.attack_log.read().await;
        log.iter().rev().take(n).cloned().collect()
    }

    /// Attach a shared [`KeyvalStore`] for dynamic IP ban list lookups.
    /// Any key matching the client IP (with any value) is treated as a ban.
    pub fn with_keyval(mut self, keyval: Arc<KeyvalStore>) -> Self {
        self.keyval = Some(keyval);
        self
    }

    /// Replace the default (empty) policy engine with a pre-configured one.
    pub fn with_policy_engine(mut self, engine: PolicyEngine) -> Self {
        self.policy_engine = Arc::new(ArcSwap::from_pointee(engine));
        self
    }

    /// Atomically replaces the OWASP regex rule sets with freshly compiled ones.
    ///
    /// Called on SIGHUP reload. Since WafRules compilation is moderately expensive,
    /// this runs synchronously in the reload handler (not on the hot path).
    pub fn reload_rules(&self) {
        let new_rules = WafRules::new();
        self.rules.store(Arc::new(new_rules));
        info!("WAF rules recompiled and swapped");
    }

    /// Reloads the declarative WAF policy from a JSON file on disk.
    ///
    /// On error, logs a warning and keeps the existing policy active.
    pub fn reload_policy(&self, path: &str) {
        let mut engine = PolicyEngine::new();
        match engine.load_from_file(path) {
            Ok(()) => {
                self.policy_engine.store(Arc::new(engine));
                info!("WAF policy reloaded from {}", path);
            }
            Err(e) => {
                warn!("WAF policy reload failed (keeping existing): {}", e);
            }
        }
    }

    /// Updates the WAF enabled state (for SIGHUP reload).
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Inspects the full request context (path, query, headers, and IP).
    /// Returns WafAction::Allow or WafAction::Block(Reason).
    pub fn inspect(
        &self,
        ip: &str,
        path: &str,
        query: Option<&str>,
        user_agent: Option<&str>,
    ) -> WafAction {
        if !self.enabled {
            return WafAction::Allow;
        }

        // 0. Keyval dynamic ban list (highest priority — overrides all other checks)
        if let Some(kv) = &self.keyval {
            if kv.contains(ip) {
                warn!("WAF Blocked: IP {} found in keyval ban list", ip);
                return WafAction::Block("Keyval Ban List".to_string());
            }
        }

        // 1. IP Reputation Check (Fastest drop)
        if self.reputation.is_banned(ip) {
            warn!("WAF Blocked: IP {} is currently banned.", ip);
            return WafAction::Block("IP Banned".to_string());
        }

        // Load rules snapshot once for this inspection (lock-free via ArcSwap)
        let rules = self.rules.load();

        // 2. Bot Protection (User-Agent)
        if let Some(ua) = user_agent {
            if rules.is_malicious_bot(ua) {
                warn!("WAF Blocked: Malicious Bot User-Agent from {}: {}", ip, ua);
                self.reputation.add_strike(ip, 5);
                return WafAction::Block("Malicious Bot Detected".to_string());
            }
        } else {
            debug!("WAF Blocked: Empty User-Agent from {}", ip);
            self.reputation.add_strike(ip, 1);
            return WafAction::Block("Empty User-Agent".to_string());
        }

        // 3. Path & Query Inspection (OWASP Top 10)
        // URL-decode first so %20, %3C, %27 etc. are matched by regex
        let full_url = match query {
            Some(q) => format!("{}?{}", path, q),
            None => path.to_string(),
        };
        let decoded_url = url_decode(&full_url);

        if let Some(violation) = rules.inspect_payload(&decoded_url) {
            warn!(
                "WAF Blocked: Malicious payload from {} in URL {}: {}",
                ip, decoded_url, violation
            );
            self.reputation.add_strike(ip, 3);
            return WafAction::Block(format!("WAF Rule: {}", violation));
        }

        // 4. Declarative Policy Engine (NGINX App Protect-style custom rules)
        let policy = self.policy_engine.load();
        let policy_violations = policy.evaluate(None, path, query, &[], None);
        for v in &policy_violations {
            if matches!(v.action, policy::RuleAction::Block) {
                warn!(
                    "WAF Policy Blocked: rule {} '{}' matched for {}",
                    v.rule_id, v.description, ip
                );
                self.reputation.add_strike(ip, 2);
                return WafAction::Block(format!("Policy Rule {}: {}", v.rule_id, v.category));
            }
        }

        WafAction::Allow
    }

    /// Inspects the request body (POST/PUT/PATCH payloads) for malicious content.
    pub fn inspect_body(&self, ip: &str, body: &str) -> WafAction {
        if !self.enabled {
            return WafAction::Allow;
        }

        let rules = self.rules.load();

        // URL-decode the body in case form-encoded data contains payloads
        let decoded = url_decode(body);

        if let Some(violation) = rules.inspect_payload(&decoded) {
            warn!(
                "WAF Blocked: Malicious payload from {} in request body: {}",
                ip, violation
            );
            self.reputation.add_strike(ip, 3);
            return WafAction::Block(format!("WAF Body Rule: {}", violation));
        }

        WafAction::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waf_reload_rules_does_not_panic() {
        let reputation = IpReputationManager::new(100, 60, None);
        let waf = WafEngine::new(true, reputation);
        // Reload should atomically swap rules without errors
        waf.reload_rules();
        // Verify inspection still works after reload
        let result = waf.inspect("1.2.3.4", "/safe", None, Some("Mozilla/5.0"));
        assert_eq!(result, WafAction::Allow);
    }

    #[test]
    fn test_waf_reload_policy_missing_file() {
        let reputation = IpReputationManager::new(100, 60, None);
        let waf = WafEngine::new(true, reputation);
        // Reload with missing file should log warning, not panic
        waf.reload_policy("/nonexistent/policy.json");
        // Engine should still work
        let result = waf.inspect("1.2.3.4", "/safe", None, Some("Mozilla/5.0"));
        assert_eq!(result, WafAction::Allow);
    }
}
