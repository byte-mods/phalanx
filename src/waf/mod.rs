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

        if let Some(violation) = self.rules.inspect_payload(&decoded_url) {
            warn!(
                "WAF Blocked: Malicious payload from {} in URL {}: {}",
                ip, decoded_url, violation
            );
            self.reputation.add_strike(ip, 3);
            return WafAction::Block(format!("WAF Rule: {}", violation));
        }

        WafAction::Allow
    }

    /// Inspects the request body (POST/PUT/PATCH payloads) for malicious content.
    pub fn inspect_body(&self, ip: &str, body: &str) -> WafAction {
        if !self.enabled {
            return WafAction::Allow;
        }

        // URL-decode the body in case form-encoded data contains payloads
        let decoded = url_decode(body);

        if let Some(violation) = self.rules.inspect_payload(&decoded) {
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
