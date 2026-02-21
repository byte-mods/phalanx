use std::sync::Arc;
use tracing::{debug, warn};

pub mod bot;
pub mod reputation;
pub mod rules;

use self::reputation::IpReputationManager;
use self::rules::WafRules;

#[derive(Debug, PartialEq)]
pub enum WafAction {
    Allow,
    Block(String), // Reason for blocking
}

#[derive(Clone)]
pub struct WafEngine {
    rules: Arc<WafRules>,
    reputation: Arc<IpReputationManager>,
    pub enabled: bool,
}

impl WafEngine {
    pub fn new(enabled: bool, reputation: Arc<IpReputationManager>) -> Self {
        Self {
            rules: Arc::new(WafRules::new()),
            reputation,
            enabled,
        }
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

        // 1. IP Reputation Check (Fastest drop)
        if self.reputation.is_banned(ip) {
            warn!("WAF Blocked: IP {} is currently banned.", ip);
            return WafAction::Block("IP Banned".to_string());
        }

        // 2. Bot Protection (User-Agent)
        if let Some(ua) = user_agent {
            if self.rules.is_malicious_bot(ua) {
                warn!("WAF Blocked: Malicious Bot User-Agent from {}: {}", ip, ua);
                self.reputation.add_strike(ip, 5); // Heavy penalty for obvious bots
                return WafAction::Block("Malicious Bot Detected".to_string());
            }
        } else {
            // Block empty User-Agents as they are often automated scripts
            debug!("WAF Blocked: Empty User-Agent from {}", ip);
            self.reputation.add_strike(ip, 1);
            return WafAction::Block("Empty User-Agent".to_string());
        }

        // 3. Path & Query Inspection (OWASP Top 10)
        let full_url = match query {
            Some(q) => format!("{}?{}", path, q),
            None => path.to_string(),
        };

        if let Some(violation) = self.rules.inspect_payload(&full_url) {
            warn!(
                "WAF Blocked: Malicious payload from {} in URL {}: {}",
                ip, full_url, violation
            );
            self.reputation.add_strike(ip, 3); // Medium penalty for payload violation
            return WafAction::Block(format!("WAF Rule: {}", violation));
        }

        WafAction::Allow
    }

    /// Inspects the request body (POST/PUT/PATCH payloads) for malicious content.
    /// This catches SQL injection, XSS, and command injection in form data and JSON bodies.
    pub fn inspect_body(&self, ip: &str, body: &str) -> WafAction {
        if !self.enabled {
            return WafAction::Allow;
        }

        if let Some(violation) = self.rules.inspect_payload(body) {
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
