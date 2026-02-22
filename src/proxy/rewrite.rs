use hyper::StatusCode;
use regex::Regex;

/// The action to take after evaluating a rewrite rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteFlag {
    /// Rewrite URI and stop processing further rules in this route, then forward.
    Break,
    /// Rewrite URI and restart route matching from the top with the new URI.
    Last,
    /// Return a 302 Found redirect to the rewritten URI.
    Redirect,
    /// Return a 301 Moved Permanently redirect to the rewritten URI.
    Permanent,
}

impl RewriteFlag {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "break" => Some(Self::Break),
            "last" => Some(Self::Last),
            "redirect" => Some(Self::Redirect),
            "permanent" => Some(Self::Permanent),
            _ => None,
        }
    }
}

/// A compiled rewrite rule ready for evaluation.
#[derive(Debug)]
pub struct RewriteRule {
    /// Compiled regex pattern to match against the URI.
    pub pattern: Regex,
    /// Replacement string (supports `$1`, `$2`, ... capture group references).
    pub replacement: String,
    /// How Phalanx should behave after this rule matches.
    pub flag: RewriteFlag,
}

impl RewriteRule {
    /// Compile a raw `(pattern, replacement, flag_str)` tuple into a `RewriteRule`.
    /// Returns `Err` with a descriptive message if the regex or flag is invalid.
    pub fn compile(pattern: &str, replacement: &str, flag_str: &str) -> Result<Self, String> {
        let regex = Regex::new(pattern)
            .map_err(|e| format!("Invalid regex pattern '{}' in rewrite rule: {}", pattern, e))?;
        let flag = RewriteFlag::from_str(flag_str).ok_or_else(|| {
            format!(
                "Unknown rewrite flag '{}'. Valid flags: last, break, redirect, permanent",
                flag_str
            )
        })?;
        Ok(Self {
            pattern: regex,
            replacement: replacement.to_string(),
            flag,
        })
    }

    /// Apply this rule to a URI. Returns `Some(new_uri)` on match, `None` otherwise.
    fn apply(&self, uri: &str) -> Option<String> {
        if !self.pattern.is_match(uri) {
            return None;
        }
        // Replace all capture groups: convert Nginx-style `$N` to regex `${N}` syntax
        let replacement = nginx_to_regex_replacement(&self.replacement);
        let new_uri = self
            .pattern
            .replacen(uri, 1, replacement.as_str())
            .to_string();
        Some(new_uri)
    }
}

/// Converts Nginx-style capture group references (`$1`, `$2`, ...) in a
/// replacement string to the `regex` crate's format (`${1}`, `${2}`, ...).
///
/// Also handles `$0` (whole match) and named groups `$name`.
fn nginx_to_regex_replacement(replacement: &str) -> String {
    // Replace bare $N with ${N} so the regex crate interprets them as capture group refs.
    // We process character by character to handle adjacent digits correctly.
    let mut out = String::with_capacity(replacement.len() + 8);
    let chars: Vec<char> = replacement.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() {
            // Is the next character a digit (positional group) or a letter (named group)?
            if chars[i + 1].is_ascii_digit() {
                // Consume all consecutive digits for the group number
                let start = i + 1;
                let mut end = start;
                while end < chars.len() && chars[end].is_ascii_digit() {
                    end += 1;
                }
                let group_num: String = chars[start..end].iter().collect();
                out.push_str(&format!("${{{}}}", group_num));
                i = end;
                continue;
            } else if chars[i + 1].is_alphabetic() || chars[i + 1] == '_' {
                // Named capture group reference
                let start = i + 1;
                let mut end = start;
                while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
                    end += 1;
                }
                let group_name: String = chars[start..end].iter().collect();
                out.push_str(&format!("${{{}}}", group_name));
                i = end;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// The result of attempting to apply a set of rewrite rules to a URI.
#[derive(Debug, PartialEq, Eq)]
pub enum RewriteResult {
    /// No rule matched — the original URI is unchanged.
    NoMatch,
    /// A `break` or `last` rule matched. Contains the new URI.
    Rewritten {
        new_uri: String,
        /// If true (`last` flag), route matching should restart from the top.
        restart_routing: bool,
    },
    /// A `redirect` or `permanent` rule matched.
    Redirect {
        status: StatusCode,
        location: String,
    },
}

/// Evaluate an ordered slice of compiled `RewriteRule`s against a request URI.
///
/// Rules are applied sequentially. The first matching rule's flag determines
/// whether processing continues or exits early.
pub fn apply_rewrites(rules: &[RewriteRule], uri: &str) -> RewriteResult {
    for rule in rules {
        if let Some(new_uri) = rule.apply(uri) {
            return match rule.flag {
                RewriteFlag::Break => RewriteResult::Rewritten {
                    new_uri,
                    restart_routing: false,
                },
                RewriteFlag::Last => RewriteResult::Rewritten {
                    new_uri,
                    restart_routing: true,
                },
                RewriteFlag::Redirect => RewriteResult::Redirect {
                    status: StatusCode::FOUND,
                    location: new_uri,
                },
                RewriteFlag::Permanent => RewriteResult::Redirect {
                    status: StatusCode::MOVED_PERMANENTLY,
                    location: new_uri,
                },
            };
        }
    }
    RewriteResult::NoMatch
}

/// Compile a slice of raw `(pattern, replacement, flag)` tuples into `RewriteRule`s.
/// Panics at startup with a descriptive message if any rule is invalid.
pub fn compile_rules(raw: &[(String, String, String)]) -> Vec<RewriteRule> {
    raw.iter()
        .map(|(pat, rep, flag)| {
            RewriteRule::compile(pat, rep, flag).unwrap_or_else(|e| {
                panic!("Configuration error in rewrite rule: {}", e);
            })
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pat: &str, rep: &str, flag: &str) -> RewriteRule {
        RewriteRule::compile(pat, rep, flag).unwrap()
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn test_break_rewrites_and_stops() {
        let rules = vec![
            rule(r"^/old/(.+)$", "/new/$1", "break"),
            rule(r"^/new/(.+)$", "/final/$1", "break"), // should NOT run
        ];
        let result = apply_rewrites(&rules, "/old/users/42");
        assert_eq!(
            result,
            RewriteResult::Rewritten {
                new_uri: "/new/users/42".to_string(),
                restart_routing: false,
            }
        );
    }

    #[test]
    fn test_last_rewrites_and_signals_restart() {
        let rules = vec![rule(r"^/legacy/(.+)$", "/api/$1", "last")];
        let result = apply_rewrites(&rules, "/legacy/orders/7");
        assert_eq!(
            result,
            RewriteResult::Rewritten {
                new_uri: "/api/orders/7".to_string(),
                restart_routing: true,
            }
        );
    }

    #[test]
    fn test_redirect_returns_302() {
        let rules = vec![rule(r"^/redirect-me$", "/new-home", "redirect")];
        let result = apply_rewrites(&rules, "/redirect-me");
        assert_eq!(
            result,
            RewriteResult::Redirect {
                status: StatusCode::FOUND,
                location: "/new-home".to_string(),
            }
        );
    }

    #[test]
    fn test_permanent_returns_301() {
        let rules = vec![rule(r"^/old-home$", "/new-home", "permanent")];
        let result = apply_rewrites(&rules, "/old-home");
        assert_eq!(
            result,
            RewriteResult::Redirect {
                status: StatusCode::MOVED_PERMANENTLY,
                location: "/new-home".to_string(),
            }
        );
    }

    #[test]
    fn test_no_match_returns_no_match() {
        let rules = vec![rule(r"^/missing$", "/somewhere", "last")];
        let result = apply_rewrites(&rules, "/other-path");
        assert_eq!(result, RewriteResult::NoMatch);
    }

    // ── Capture group expansion ────────────────────────────────────────────────

    #[test]
    fn test_single_capture_group() {
        let rules = vec![rule(r"^/users/(\d+)$", "/profile/$1", "break")];
        let result = apply_rewrites(&rules, "/users/99");
        assert_eq!(
            result,
            RewriteResult::Rewritten {
                new_uri: "/profile/99".to_string(),
                restart_routing: false,
            }
        );
    }

    #[test]
    fn test_multiple_capture_groups() {
        let rules = vec![rule(r"^/v1/(\w+)/(\d+)$", "/api/$1/resource/$2", "break")];
        let result = apply_rewrites(&rules, "/v1/orders/42");
        assert_eq!(
            result,
            RewriteResult::Rewritten {
                new_uri: "/api/orders/resource/42".to_string(),
                restart_routing: false,
            }
        );
    }

    #[test]
    fn test_capture_group_in_redirect() {
        let rules = vec![rule(
            r"^/old-shop/(.+)$",
            "https://shop.example.com/$1",
            "permanent",
        )];
        let result = apply_rewrites(&rules, "/old-shop/products/t-shirt");
        assert_eq!(
            result,
            RewriteResult::Redirect {
                status: StatusCode::MOVED_PERMANENTLY,
                location: "https://shop.example.com/products/t-shirt".to_string(),
            }
        );
    }

    // ── Multiple rules — first match wins ────────────────────────────────────

    #[test]
    fn test_first_matching_rule_wins() {
        let rules = vec![
            rule(r"^/api/v1/(.+)$", "/v1/$1", "break"),
            rule(r"^/api/(.+)$", "/generic/$1", "break"), // should not run
        ];
        // Both patterns match but the first wins
        let result = apply_rewrites(&rules, "/api/v1/ping");
        assert_eq!(
            result,
            RewriteResult::Rewritten {
                new_uri: "/v1/ping".to_string(),
                restart_routing: false,
            }
        );
    }

    #[test]
    fn test_second_rule_runs_when_first_does_not_match() {
        let rules = vec![
            rule(r"^/api/v2/(.+)$", "/v2/$1", "break"),
            rule(r"^/api/(.+)$", "/generic/$1", "break"),
        ];
        let result = apply_rewrites(&rules, "/api/health");
        assert_eq!(
            result,
            RewriteResult::Rewritten {
                new_uri: "/generic/health".to_string(),
                restart_routing: false,
            }
        );
    }

    // ── Nginx replacement conversion ───────────────────────────────────────────

    #[test]
    fn test_nginx_to_regex_replacement_single() {
        assert_eq!(nginx_to_regex_replacement("/prefix/$1"), "/prefix/${1}");
    }

    #[test]
    fn test_nginx_to_regex_replacement_multi_digit() {
        assert_eq!(nginx_to_regex_replacement("/$12/end"), "/${12}/end");
    }

    #[test]
    fn test_nginx_to_regex_replacement_multiple_groups() {
        assert_eq!(
            nginx_to_regex_replacement("/$1/middle/$2"),
            "/${1}/middle/${2}"
        );
    }

    #[test]
    fn test_nginx_to_regex_replacement_no_groups() {
        assert_eq!(nginx_to_regex_replacement("/static/path"), "/static/path");
    }

    // ── Error handling ─────────────────────────────────────────────────────────

    #[test]
    fn test_invalid_regex_returns_err() {
        let result = RewriteRule::compile("[invalid", "/out", "last");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Invalid regex"), "got: {err}");
    }

    #[test]
    fn test_invalid_flag_returns_err() {
        let result = RewriteRule::compile(r"^/path$", "/out", "bogus");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Unknown rewrite flag"), "got: {err}");
    }
}
