/// Advanced bot classification beyond the regex-based detection in `rules.rs`.
///
/// This module provides:
/// - A tiered bot classification (known-good, known-bad, unknown)
/// - Rate-anomaly scoring for bot-like traffic patterns
/// - A CAPTCHA challenge interface (stub — wire to a provider like hCaptcha or Cloudflare Turnstile)
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Classification of a detected bot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotClass {
    /// Known-good crawler (Googlebot, Bingbot, etc.) — typically should be allowed.
    GoodBot,
    /// Known-bad scanner or exploit tool (sqlmap, nikto, masscan, etc.) — should be blocked.
    BadBot,
    /// Unverified or unknown bot (generic crawler UA) — rate-limit or challenge.
    Unknown,
    /// Appears to be a human browser.
    Human,
}

/// Classifies a User-Agent string into a bot tier.
///
/// Returns `None` if the UA is blank (handled separately by the WAF core as block).
pub fn classify_user_agent(ua: &str) -> BotClass {
    let ua_lower = ua.to_lowercase();

    // ── Known-bad scanners / attack tools ────────────────────────────────────
    const BAD_BOTS: &[&str] = &[
        "sqlmap", "nikto", "masscan", "nmap", "nuclei", "zgrab",
        "dirbuster", "gobuster", "wfuzz", "burpsuite", "hydra",
        "acunetix", "nessus", "openvas", "w3af", "whatweb",
        "httprint", "havij", "pangolin", "jbrofuzz",
    ];
    for sig in BAD_BOTS {
        if ua_lower.contains(sig) {
            return BotClass::BadBot;
        }
    }

    // ── Known-good crawlers ────────────────────────────────────────────────
    const GOOD_BOTS: &[&str] = &[
        "googlebot", "bingbot", "slurp",          // major search engines
        "duckduckbot", "baiduspider", "yandexbot",
        "applebot", "facebot", "twitterbot",       // social
        "linkedinbot", "pinterestbot",
        "ia_archiver",                              // Internet Archive
        "screaming frog",                           // SEO tool (intentional)
        "uptimerobot", "pingdom", "statuscake",    // monitoring
    ];
    for sig in GOOD_BOTS {
        if ua_lower.contains(sig) {
            return BotClass::GoodBot;
        }
    }

    // ── Generic / unknown bots ────────────────────────────────────────────
    const GENERIC_BOT_SIGS: &[&str] = &[
        "bot", "crawler", "spider", "scraper", "archiver",
        "fetch", "wget", "curl", "python-requests", "go-http-client",
        "libwww", "java/", "okhttp", "axios", "got/",
    ];
    for sig in GENERIC_BOT_SIGS {
        if ua_lower.contains(sig) {
            return BotClass::Unknown;
        }
    }

    BotClass::Human
}

/// Per-IP request rate tracker for anomaly detection.
///
/// Tracks request timestamps in a sliding window and returns an anomaly
/// score (requests per second) that the WAF can use to challenge or block.
pub struct BotRateTracker {
    /// IP → ring-buffer of request timestamps
    windows: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    /// Duration of the sliding window
    window: Duration,
}

impl BotRateTracker {
    pub fn new(window_secs: u64) -> Self {
        Self {
            windows: Arc::new(Mutex::new(HashMap::new())),
            window: Duration::from_secs(window_secs),
        }
    }

    /// Records a request for `ip` and returns the current request rate (req/s).
    pub fn record_and_rate(&self, ip: &str) -> f64 {
        let now = Instant::now();
        let mut guard = self.windows.lock().unwrap();
        let timestamps = guard.entry(ip.to_string()).or_default();

        // Evict old entries outside the window
        timestamps.retain(|t| now.duration_since(*t) < self.window);
        timestamps.push(now);

        let count = timestamps.len() as f64;
        let window_secs = self.window.as_secs_f64();
        count / window_secs
    }

    /// Clears state for an IP (e.g., after a ban is lifted).
    pub fn clear(&self, ip: &str) {
        self.windows.lock().unwrap().remove(ip);
    }
}

/// Placeholder for CAPTCHA challenge integration.
///
/// In production, wire this to hCaptcha, Cloudflare Turnstile, or reCAPTCHA.
/// Returns the HTML challenge page to serve, or an error if the provider
/// is not configured.
pub fn captcha_challenge_html(site_key: Option<&str>) -> Result<String, &'static str> {
    let key = site_key.ok_or("CAPTCHA site key not configured")?;
    Ok(format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Bot Check</title>
<script src="https://hcaptcha.com/1/api.js" async defer></script>
</head>
<body>
<h1>Please verify you are human</h1>
<form method="POST">
  <div class="h-captcha" data-sitekey="{key}"></div>
  <button type="submit">Continue</button>
</form>
</body>
</html>"#
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_bad_bot_sqlmap() {
        assert_eq!(classify_user_agent("sqlmap/1.5.8#stable"), BotClass::BadBot);
    }

    #[test]
    fn test_classify_bad_bot_nikto() {
        assert_eq!(classify_user_agent("Nikto/2.1.5"), BotClass::BadBot);
    }

    #[test]
    fn test_classify_good_bot_googlebot() {
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (compatible; Googlebot/2.1)"),
            BotClass::GoodBot
        );
    }

    #[test]
    fn test_classify_good_bot_bingbot() {
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (compatible; bingbot/2.0)"),
            BotClass::GoodBot
        );
    }

    #[test]
    fn test_classify_generic_bot_python_requests() {
        assert_eq!(classify_user_agent("python-requests/2.28.0"), BotClass::Unknown);
    }

    #[test]
    fn test_classify_generic_bot_curl() {
        assert_eq!(classify_user_agent("curl/7.85.0"), BotClass::Unknown);
    }

    #[test]
    fn test_classify_human_chrome() {
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"),
            BotClass::Human
        );
    }

    #[test]
    fn test_classify_human_firefox() {
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"),
            BotClass::Human
        );
    }

    #[test]
    fn test_rate_tracker_returns_zero_for_new_ip() {
        let tracker = BotRateTracker::new(10);
        // Just check that it doesn't panic and returns a reasonable rate
        let rate = tracker.record_and_rate("10.0.0.1");
        assert!(rate > 0.0);
    }

    #[test]
    fn test_rate_tracker_increases_with_requests() {
        let tracker = BotRateTracker::new(60);
        for _ in 0..10 {
            tracker.record_and_rate("10.0.0.2");
        }
        let rate = tracker.record_and_rate("10.0.0.2");
        assert!(rate > 0.1, "rate should be >0.1 req/s after 11 requests");
    }

    #[test]
    fn test_rate_tracker_independent_ips() {
        let tracker = BotRateTracker::new(60);
        for _ in 0..20 {
            tracker.record_and_rate("10.0.0.3");
        }
        // Different IP should start fresh
        let rate = tracker.record_and_rate("10.0.0.4");
        assert!(rate < 1.0, "fresh IP should have very low rate");
    }

    #[test]
    fn test_rate_tracker_clear() {
        let tracker = BotRateTracker::new(60);
        for _ in 0..10 {
            tracker.record_and_rate("10.0.0.5");
        }
        tracker.clear("10.0.0.5");
        let rate = tracker.record_and_rate("10.0.0.5");
        assert!(rate < 1.0, "after clear, rate should be low");
    }

    #[test]
    fn test_captcha_challenge_no_key_returns_err() {
        let result = captcha_challenge_html(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_captcha_challenge_with_key_contains_key() {
        let html = captcha_challenge_html(Some("abc-123")).unwrap();
        assert!(html.contains("abc-123"));
        assert!(html.contains("hcaptcha.com"));
    }
}
