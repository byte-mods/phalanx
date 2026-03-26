use regex::RegexSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{error, info, warn};

/// A WAF policy is a named collection of signature rules + configuration.
/// Modeled after F5 NGINX App Protect declarative policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafPolicy {
    pub name: String,
    pub enforcement_mode: EnforcementMode,
    pub signature_sets: Vec<SignatureSet>,
    pub custom_rules: Vec<CustomRule>,
    /// Response status code sent on block (default: 403)
    pub blocking_status: u16,
    /// URLs/paths excluded from WAF inspection
    pub exclusions: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum EnforcementMode {
    Blocking,
    Transparent,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        Self::Blocking
    }
}

/// Pre-defined signature categories aligned with OWASP Top 10.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSet {
    pub name: String,
    pub enabled: bool,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// User-defined rules with custom regex patterns and actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: u32,
    pub description: String,
    pub pattern: String,
    pub target: RuleTarget,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleTarget {
    Url,
    QueryString,
    Headers,
    Body,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Block,
    Log,
    Allow,
}

/// The compiled policy engine that evaluates requests against loaded policies.
pub struct PolicyEngine {
    policies: HashMap<String, CompiledPolicy>,
    default_policy: Option<String>,
}

struct CompiledPolicy {
    config: WafPolicy,
    custom_patterns: Vec<(u32, regex::Regex, RuleTarget, RuleAction)>,
    exclusion_set: Option<RegexSet>,
}

#[derive(Debug)]
pub struct PolicyViolation {
    pub rule_id: u32,
    pub category: String,
    pub description: String,
    pub severity: Severity,
    pub action: RuleAction,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            default_policy: None,
        }
    }

    /// Loads a policy from a JSON file on disk.
    pub fn load_from_file(&mut self, path: &str) -> Result<(), String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
        let policy: WafPolicy =
            serde_json::from_str(&content).map_err(|e| format!("Invalid policy JSON: {}", e))?;
        self.add_policy(policy)
    }

    /// Adds a policy to the engine.
    pub fn add_policy(&mut self, policy: WafPolicy) -> Result<(), String> {
        let name = policy.name.clone();

        let mut custom_patterns = Vec::new();
        for rule in &policy.custom_rules {
            let re = regex::Regex::new(&rule.pattern)
                .map_err(|e| format!("Invalid regex in rule {}: {}", rule.id, e))?;
            custom_patterns.push((rule.id, re, rule.target.clone(), rule.action.clone()));
        }

        let exclusion_set = if !policy.exclusions.is_empty() {
            Some(
                RegexSet::new(&policy.exclusions)
                    .map_err(|e| format!("Invalid exclusion pattern: {}", e))?,
            )
        } else {
            None
        };

        if self.default_policy.is_none() {
            self.default_policy = Some(name.clone());
        }

        info!("Loaded WAF policy '{}' with {} custom rules", name, custom_patterns.len());

        self.policies.insert(
            name,
            CompiledPolicy {
                config: policy,
                custom_patterns,
                exclusion_set,
            },
        );

        Ok(())
    }

    /// Evaluates a request against the named policy (or default).
    pub fn evaluate(
        &self,
        policy_name: Option<&str>,
        path: &str,
        query: Option<&str>,
        headers: &[(String, String)],
        body: Option<&str>,
    ) -> Vec<PolicyViolation> {
        let policy_key = policy_name
            .map(String::from)
            .or_else(|| self.default_policy.clone());

        let compiled = match policy_key.and_then(|k| self.policies.get(&k)) {
            Some(p) => p,
            None => return vec![],
        };

        // Check exclusions
        if let Some(ref exc) = compiled.exclusion_set {
            if exc.is_match(path) {
                return vec![];
            }
        }

        let mut violations = Vec::new();

        for (id, pattern, target, action) in &compiled.custom_patterns {
            let matched = match target {
                RuleTarget::Url => pattern.is_match(path),
                RuleTarget::QueryString => query.map(|q| pattern.is_match(q)).unwrap_or(false),
                RuleTarget::Headers => headers.iter().any(|(_, v)| pattern.is_match(v)),
                RuleTarget::Body => body.map(|b| pattern.is_match(b)).unwrap_or(false),
                RuleTarget::All => {
                    pattern.is_match(path)
                        || query.map(|q| pattern.is_match(q)).unwrap_or(false)
                        || headers.iter().any(|(_, v)| pattern.is_match(v))
                        || body.map(|b| pattern.is_match(b)).unwrap_or(false)
                }
            };

            if matched {
                violations.push(PolicyViolation {
                    rule_id: *id,
                    category: "Custom Rule".to_string(),
                    description: format!("Pattern matched rule {}", id),
                    severity: Severity::High,
                    action: action.clone(),
                });
            }
        }

        violations
    }

    /// Returns whether any violation should result in blocking.
    pub fn should_block(&self, violations: &[PolicyViolation], policy_name: Option<&str>) -> bool {
        let policy_key = policy_name
            .map(String::from)
            .or_else(|| self.default_policy.clone());

        let compiled = match policy_key.and_then(|k| self.policies.get(&k)) {
            Some(p) => p,
            None => return false,
        };

        if compiled.config.enforcement_mode == EnforcementMode::Transparent {
            return false;
        }

        violations
            .iter()
            .any(|v| matches!(v.action, RuleAction::Block))
    }

    pub fn blocking_status(&self, policy_name: Option<&str>) -> u16 {
        let policy_key = policy_name
            .map(String::from)
            .or_else(|| self.default_policy.clone());

        policy_key
            .and_then(|k| self.policies.get(&k))
            .map(|p| p.config.blocking_status)
            .unwrap_or(403)
    }
}

/// Returns a default policy with comprehensive OWASP coverage.
pub fn default_owasp_policy() -> WafPolicy {
    WafPolicy {
        name: "default-owasp".to_string(),
        enforcement_mode: EnforcementMode::Blocking,
        blocking_status: 403,
        signature_sets: vec![
            SignatureSet {
                name: "SQL Injection".to_string(),
                enabled: true,
                severity: Severity::Critical,
            },
            SignatureSet {
                name: "Cross-Site Scripting".to_string(),
                enabled: true,
                severity: Severity::Critical,
            },
            SignatureSet {
                name: "Path Traversal".to_string(),
                enabled: true,
                severity: Severity::High,
            },
            SignatureSet {
                name: "Command Injection".to_string(),
                enabled: true,
                severity: Severity::Critical,
            },
            SignatureSet {
                name: "Server-Side Request Forgery".to_string(),
                enabled: true,
                severity: Severity::High,
            },
            SignatureSet {
                name: "XML External Entity".to_string(),
                enabled: true,
                severity: Severity::High,
            },
            SignatureSet {
                name: "HTTP Protocol Violation".to_string(),
                enabled: true,
                severity: Severity::Medium,
            },
        ],
        custom_rules: vec![
            CustomRule {
                id: 1001,
                description: "SSRF: Internal IP access attempt".to_string(),
                pattern: r"(?i)(127\.0\.0\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|0\.0\.0\.0)".to_string(),
                target: RuleTarget::All,
                action: RuleAction::Block,
            },
            CustomRule {
                id: 1002,
                description: "XXE: XML Entity Injection".to_string(),
                pattern: r#"(?i)(<!ENTITY|<!DOCTYPE.*\[.*<!ENTITY|SYSTEM\s+["']file:)"#.to_string(),
                target: RuleTarget::Body,
                action: RuleAction::Block,
            },
            CustomRule {
                id: 1003,
                description: "Prototype pollution attempt".to_string(),
                pattern: r"(?i)(__proto__|constructor\s*\[|Object\.assign)".to_string(),
                target: RuleTarget::All,
                action: RuleAction::Block,
            },
        ],
        exclusions: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_owasp_policy_has_rules() {
        let p = default_owasp_policy();
        assert!(!p.signature_sets.is_empty(), "expected signature_sets");
        assert!(!p.custom_rules.is_empty(), "expected custom_rules");
    }

    #[test]
    fn test_policy_engine_add_policy() {
        let mut engine = PolicyEngine::new();
        let policy = default_owasp_policy();
        let name = policy.name.clone();
        engine.add_policy(policy).expect("add_policy");
        let v = engine.evaluate(
            Some(&name),
            "/trigger-ssrf",
            Some("127.0.0.1"),
            &[],
            None,
        );
        assert!(
            !v.is_empty(),
            "policy should be stored and used for evaluation"
        );
    }

    #[test]
    fn test_evaluate_ssrf_blocked() {
        let mut engine = PolicyEngine::new();
        engine
            .add_policy(default_owasp_policy())
            .expect("add_policy");
        let v = engine.evaluate(None, "/x", None, &[], Some("connect to 127.0.0.1"));
        assert!(
            v.iter().any(|x| x.rule_id == 1001),
            "expected SSRF rule 1001 violation, got {:?}",
            v
        );
    }

    #[test]
    fn test_evaluate_xxe_blocked() {
        let mut engine = PolicyEngine::new();
        engine
            .add_policy(default_owasp_policy())
            .expect("add_policy");
        let body = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r/>"#;
        let v = engine.evaluate(None, "/xml", None, &[], Some(body));
        assert!(
            v.iter().any(|x| x.rule_id == 1002),
            "expected XXE rule 1002 violation, got {:?}",
            v
        );
    }

    #[test]
    fn test_evaluate_clean_request() {
        let mut engine = PolicyEngine::new();
        engine
            .add_policy(default_owasp_policy())
            .expect("add_policy");
        let v = engine.evaluate(
            None,
            "/api/v1/resource",
            Some("page=1&sort=name"),
            &[("X-Request-Id".to_string(), "abc-123".to_string())],
            Some(r#"{"ok":true}"#),
        );
        assert!(v.is_empty(), "expected no violations, got {:?}", v);
    }

    #[test]
    fn test_evaluate_exclusion() {
        let mut p = default_owasp_policy();
        p.exclusions = vec![r"^/health$".to_string()];
        let mut engine = PolicyEngine::new();
        engine.add_policy(p).expect("add_policy");
        let v = engine.evaluate(
            None,
            "/health",
            Some("127.0.0.1"),
            &[],
            None,
        );
        assert!(
            v.is_empty(),
            "excluded path should skip inspection, got {:?}",
            v
        );
    }

    #[test]
    fn test_enforcement_transparent() {
        let mut p = default_owasp_policy();
        p.enforcement_mode = EnforcementMode::Transparent;
        let mut engine = PolicyEngine::new();
        engine.add_policy(p).expect("add_policy");
        let v = engine.evaluate(None, "/x", None, &[], Some("127.0.0.1"));
        assert!(!v.is_empty(), "transparent mode still records violations");
        assert!(
            !engine.should_block(&v, None),
            "transparent mode must not block"
        );
    }

    #[test]
    fn test_enforcement_blocking() {
        let mut engine = PolicyEngine::new();
        engine
            .add_policy(default_owasp_policy())
            .expect("add_policy");
        let v = engine.evaluate(None, "/x", None, &[], Some("127.0.0.1"));
        assert!(
            engine.should_block(&v, None),
            "blocking mode should block on Block action"
        );
    }

    #[test]
    fn test_custom_rule_url_target() {
        let policy = WafPolicy {
            name: "url-only".to_string(),
            enforcement_mode: EnforcementMode::Blocking,
            signature_sets: vec![],
            custom_rules: vec![CustomRule {
                id: 9001,
                description: "url marker".to_string(),
                pattern: r"BADURL".to_string(),
                target: RuleTarget::Url,
                action: RuleAction::Block,
            }],
            blocking_status: 403,
            exclusions: vec![],
        };
        let mut engine = PolicyEngine::new();
        engine.add_policy(policy).expect("add_policy");
        let url_hit = engine.evaluate(
            Some("url-only"),
            "/prefix/BADURL/suffix",
            None,
            &[],
            Some("BADURL in body should not match Url target"),
        );
        assert_eq!(url_hit.len(), 1);
        assert_eq!(url_hit[0].rule_id, 9001);

        let body_only = engine.evaluate(
            Some("url-only"),
            "/clean/path",
            None,
            &[],
            Some("BADURL"),
        );
        assert!(
            body_only.is_empty(),
            "Url target must not match body, got {:?}",
            body_only
        );
    }

    #[test]
    fn test_custom_rule_body_target() {
        let policy = WafPolicy {
            name: "body-only".to_string(),
            enforcement_mode: EnforcementMode::Blocking,
            signature_sets: vec![],
            custom_rules: vec![CustomRule {
                id: 9002,
                description: "body marker".to_string(),
                pattern: r"BADBODY".to_string(),
                target: RuleTarget::Body,
                action: RuleAction::Block,
            }],
            blocking_status: 403,
            exclusions: vec![],
        };
        let mut engine = PolicyEngine::new();
        engine.add_policy(policy).expect("add_policy");
        let body_hit = engine.evaluate(
            Some("body-only"),
            "/BADBODY/in/path",
            None,
            &[],
            Some("payload BADBODY here"),
        );
        assert_eq!(body_hit.len(), 1);
        assert_eq!(body_hit[0].rule_id, 9002);

        let url_only = engine.evaluate(Some("body-only"), "/clean", None, &[], None);
        assert!(
            url_only.is_empty(),
            "Body target must not match when body absent, got {:?}",
            url_only
        );
    }

    #[test]
    fn test_blocking_status_default() {
        assert_eq!(default_owasp_policy().blocking_status, 403);
        let engine = PolicyEngine::new();
        assert_eq!(engine.blocking_status(None), 403);
    }
}
