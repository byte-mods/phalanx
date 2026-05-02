/// Declarative WAF policy engine modeled after F5 NGINX App Protect.
///
/// Supports named policies with custom signature rules, enforcement modes
/// (blocking vs. transparent/monitor-only), path exclusions, and configurable
/// blocking status codes. Policies can be loaded from JSON files or built
/// programmatically.
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// A WAF policy is a named collection of signature rules + configuration.
/// Modeled after F5 NGINX App Protect declarative policies.
///
/// Policies are serializable to/from JSON for file-based configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafPolicy {
    /// Unique name identifying this policy (used as a lookup key in the engine).
    pub name: String,
    /// Whether violations result in blocking or are only logged (transparent).
    pub enforcement_mode: EnforcementMode,
    /// Pre-defined signature categories (SQLi, XSS, etc.) with enable/disable toggles.
    pub signature_sets: Vec<SignatureSet>,
    /// User-defined rules with custom regex patterns and actions.
    pub custom_rules: Vec<CustomRule>,
    /// HTTP status code returned when a request is blocked (default: 403).
    pub blocking_status: u16,
    /// Regex patterns for URL paths excluded from WAF inspection (e.g., health checks).
    pub exclusions: Vec<String>,
}

/// Controls whether the WAF actively blocks or passively monitors violations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum EnforcementMode {
    /// Violations trigger immediate request blocking with the configured status code.
    Blocking,
    /// Violations are recorded and logged but requests are allowed through.
    /// Useful for testing new rules before enforcing them.
    Transparent,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        Self::Blocking
    }
}

/// Pre-defined signature categories aligned with OWASP Top 10.
///
/// Each set can be individually enabled/disabled and has a severity rating
/// that affects how violations are prioritized in logs and alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSet {
    /// Human-readable name (e.g., "SQL Injection", "Cross-Site Scripting").
    pub name: String,
    /// Whether this signature set is active.
    pub enabled: bool,
    /// Severity level for violations from this set.
    pub severity: Severity,
}

/// Severity classification for WAF rule violations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    /// Informational or minor concern.
    Low,
    /// Moderate security risk.
    Medium,
    /// Significant security risk requiring attention.
    High,
    /// Active exploitation attempt or critical vulnerability.
    Critical,
}

/// User-defined rules with custom regex patterns and actions.
///
/// Rules are compiled into regex at load time by the [`PolicyEngine`].
/// Each rule targets a specific part of the request and specifies what
/// action to take on match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    /// Unique numeric rule identifier (used in violation reports and logs).
    pub id: u32,
    /// Human-readable description of what this rule detects.
    pub description: String,
    /// Regex pattern to match against the specified target.
    pub pattern: String,
    /// Which part of the request to inspect.
    pub target: RuleTarget,
    /// What to do when the pattern matches.
    pub action: RuleAction,
}

/// Specifies which part of the HTTP request a custom rule should inspect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleTarget {
    /// Match against the URL path only.
    Url,
    /// Match against the query string only.
    QueryString,
    /// Match against header values.
    Headers,
    /// Match against the request body only.
    Body,
    /// Match against all request components (URL, query, headers, and body).
    All,
}

/// Action to take when a custom WAF rule matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    /// Block the request and return the configured blocking status code.
    Block,
    /// Log the violation but allow the request through.
    Log,
    /// Explicitly allow the request (overrides other rules).
    Allow,
}

/// The compiled policy engine that evaluates requests against loaded policies.
///
/// Policies are stored by name. The first policy added becomes the default
/// unless overridden. Evaluation compiles custom rule regexes once at load
/// time so per-request matching is fast.
pub struct PolicyEngine {
    /// Named policies indexed by policy name.
    policies: HashMap<String, CompiledPolicy>,
    /// Name of the default policy (used when no explicit name is specified).
    default_policy: Option<String>,
}

/// Internal representation of a loaded policy with pre-compiled regex patterns.
struct CompiledPolicy {
    /// Original policy configuration (for metadata lookups).
    config: WafPolicy,
    /// Pre-compiled custom rules: (rule_id, regex, target, action).
    custom_patterns: Vec<(u32, regex::Regex, RuleTarget, RuleAction)>,
    /// Pre-compiled exclusion patterns for fast path matching.
    exclusion_set: Option<RegexSet>,
    /// Pre-lowered signature set names to avoid per-request allocations in the
    /// category-matching hot loop. (original_name, lowered_name, severity, enabled)
    sig_set_names_lower: Vec<(String, String, Severity, bool)>,
}

/// A single policy violation detected during request evaluation.
#[derive(Debug)]
pub struct PolicyViolation {
    /// The rule ID that triggered this violation.
    pub rule_id: u32,
    /// Category label (e.g., "Custom Rule").
    pub category: String,
    /// Human-readable description of the match.
    pub description: String,
    /// Severity of the triggering rule.
    pub severity: Severity,
    /// Action specified by the rule.
    pub action: RuleAction,
}

impl PolicyEngine {
    /// Creates a new empty policy engine with no loaded policies.
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

        let sig_set_names_lower: Vec<_> = policy
            .signature_sets
            .iter()
            .map(|s| (s.name.clone(), s.name.to_lowercase(), s.severity, s.enabled))
            .collect();

        info!("Loaded WAF policy '{}' with {} custom rules", name, custom_patterns.len());

        self.policies.insert(
            name,
            CompiledPolicy {
                config: policy,
                custom_patterns,
                exclusion_set,
                sig_set_names_lower,
            },
        );

        Ok(())
    }

    /// Evaluates a request against the named policy (or default).
    ///
    /// Accepts `&HashMap` for headers to avoid a per-request Vec allocation
    /// on the WAF hot path — the caller's existing HashMap is borrowed directly.
    pub fn evaluate(
        &self,
        policy_name: Option<&str>,
        path: &str,
        query: Option<&str>,
        headers: &std::collections::HashMap<String, String>,
        body: Option<&str>,
    ) -> Vec<PolicyViolation> {
        self.evaluate_with_categories(policy_name, path, query, headers, body, &[])
    }

    /// Full evaluation including matched WAF rule categories.
    pub fn evaluate_with_categories(
        &self,
        policy_name: Option<&str>,
        path: &str,
        query: Option<&str>,
        headers: &std::collections::HashMap<String, String>,
        body: Option<&str>,
        matched_categories: &[&str],
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

        // Evaluate enabled signature sets against matched WAF rule categories.
        // Pre-lowered category names (hoisted from inner loop) and pre-computed
        // sig_set_names_lower (built at policy load time) avoid per-request heap
        // allocations for every category × signature-set pair.
        let cat_lower: Vec<String> = matched_categories
            .iter()
            .map(|c| c.to_lowercase())
            .collect();
        for cat in &cat_lower {
            for (orig_name, sig_name, severity, enabled) in &compiled.sig_set_names_lower {
                if !enabled {
                    continue;
                }
                if cat.contains(sig_name.as_str()) || sig_name.contains(cat.as_str()) {
                    violations.push(PolicyViolation {
                        rule_id: 0, // signature-set match, not a numbered rule
                        category: orig_name.clone(),
                        description: format!(
                            "Signature set '{}' matched category '{}'",
                            orig_name, cat
                        ),
                        severity: *severity,
                        action: RuleAction::Block,
                    });
                }
            }
        }

        for (id, pattern, target, action) in &compiled.custom_patterns {
            let matched = match target {
                RuleTarget::Url => pattern.is_match(path),
                RuleTarget::QueryString => query.map(|q| pattern.is_match(q)).unwrap_or(false),
                RuleTarget::Headers => headers.values().any(|v| pattern.is_match(v)),
                RuleTarget::Body => body.map(|b| pattern.is_match(b)).unwrap_or(false),
                RuleTarget::All => {
                    pattern.is_match(path)
                        || query.map(|q| pattern.is_match(q)).unwrap_or(false)
                        || headers.values().any(|v| pattern.is_match(v))
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

    /// Returns the HTTP status code to use when blocking for the specified policy.
    /// Defaults to 403 if no policy is found.
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
            &std::collections::HashMap::new(),
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
        let v = engine.evaluate(None, "/x", None, &std::collections::HashMap::new(), Some("connect to 127.0.0.1"));
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
        let v = engine.evaluate(None, "/xml", None, &std::collections::HashMap::new(), Some(body));
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
        let headers: std::collections::HashMap<String, String> = [
            ("X-Request-Id".to_string(), "abc-123".to_string()),
        ].into_iter().collect();
        let v = engine.evaluate(
            None,
            "/api/v1/resource",
            Some("page=1&sort=name"),
            &headers,
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
            &std::collections::HashMap::new(),
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
        let v = engine.evaluate(None, "/x", None, &std::collections::HashMap::new(), Some("127.0.0.1"));
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
        let v = engine.evaluate(None, "/x", None, &std::collections::HashMap::new(), Some("127.0.0.1"));
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
            &std::collections::HashMap::new(),
            Some("BADURL in body should not match Url target"),
        );
        assert_eq!(url_hit.len(), 1);
        assert_eq!(url_hit[0].rule_id, 9001);

        let body_only = engine.evaluate(
            Some("url-only"),
            "/clean/path",
            None,
            &std::collections::HashMap::new(),
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
            &std::collections::HashMap::new(),
            Some("payload BADBODY here"),
        );
        assert_eq!(body_hit.len(), 1);
        assert_eq!(body_hit[0].rule_id, 9002);

        let url_only = engine.evaluate(Some("body-only"), "/clean", None, &std::collections::HashMap::new(), None);
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

    #[test]
    fn test_signature_set_sqli_produces_violation() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(default_owasp_policy()).expect("add_policy");
        let v = engine.evaluate_with_categories(
            None,
            "/api/data",
            None,
            &std::collections::HashMap::new(),
            None,
            &["SQL Injection (SQLi)"],
        );
        assert!(
            v.iter().any(|x| x.category == "SQL Injection"),
            "expected SQL Injection signature set violation, got {:?}",
            v.iter().map(|x| &x.category).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_signature_set_xss_produces_violation() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(default_owasp_policy()).expect("add_policy");
        let v = engine.evaluate_with_categories(
            None,
            "/",
            None,
            &std::collections::HashMap::new(),
            None,
            &["Cross-Site Scripting (XSS)"],
        );
        assert!(
            v.iter().any(|x| x.category == "Cross-Site Scripting"),
            "expected XSS signature set violation, got {:?}",
            v.iter().map(|x| &x.category).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_disabled_signature_set_skipped() {
        let mut policy = default_owasp_policy();
        // Disable SQL Injection set
        for sig in &mut policy.signature_sets {
            if sig.name == "SQL Injection" {
                sig.enabled = false;
            }
        }
        let mut engine = PolicyEngine::new();
        engine.add_policy(policy).expect("add_policy");
        let v = engine.evaluate_with_categories(
            None,
            "/",
            None,
            &std::collections::HashMap::new(),
            None,
            &["SQL Injection (SQLi)"],
        );
        assert!(
            !v.iter().any(|x| x.category == "SQL Injection"),
            "disabled signature set should not produce violation"
        );
    }

    #[test]
    fn test_signature_set_unmatched_category_no_violation() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(default_owasp_policy()).expect("add_policy");
        let v = engine.evaluate_with_categories(
            None,
            "/",
            None,
            &std::collections::HashMap::new(),
            None,
            &["Unknown Attack Category"],
        );
        // Only custom_rules might match, not signature sets
        let sig_violations: Vec<_> = v.iter().filter(|x| x.rule_id == 0).collect();
        assert!(
            sig_violations.is_empty(),
            "unknown category should not match any signature set"
        );
    }

    #[test]
    fn test_evaluate_backward_compatible_without_categories() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(default_owasp_policy()).expect("add_policy");
        // Original evaluate() without categories still works
        let v = engine.evaluate(None, "/x", None, &std::collections::HashMap::new(), Some("127.0.0.1"));
        assert!(!v.is_empty(), "SSRF custom rule should still match");
    }
}
