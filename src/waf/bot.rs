/// Advanced bot classification beyond the regex-based detection in `rules.rs`.
///
/// This module provides:
/// - A tiered bot classification (known-good, known-bad, unknown)
/// - Rate-anomaly scoring for bot-like traffic patterns
/// - A CAPTCHA challenge interface with provider-specific rendering and verification hooks
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use base64::Engine;
use rand::RngExt;

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
/// An empty or blank UA returns `Human` here; the WAF core handles
/// missing/empty UAs at the call site with a strike but no automatic block.
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
///
/// Uses `DashMap` for lock-free per-IP access on the hot path. A background
/// sweeper evicts stale IP entries to prevent unbounded memory growth.
pub struct BotRateTracker {
    /// IP → ring-buffer of request timestamps (lock-free sharded map)
    windows: Arc<DashMap<String, Vec<Instant>>>,
    /// Duration of the sliding window
    window: Duration,
}

impl BotRateTracker {
    /// Creates a new rate tracker with the given sliding window duration.
    ///
    /// Spawns a background sweeper that evicts IP entries with no recent
    /// timestamps, preventing unbounded memory growth from abandoned sessions.
    ///
    /// # Arguments
    /// * `window_secs` - Length of the sliding window in seconds. Requests
    ///   older than this are evicted before computing the rate.
    pub fn new(window_secs: u64) -> Self {
        Self {
            windows: Arc::new(DashMap::new()),
            window: Duration::from_secs(window_secs),
        }
    }

    /// Spawns a background sweeper that evicts IPs with no recent timestamps,
    /// preventing unbounded memory growth from abandoned sessions.
    ///
    /// No-ops silently when no Tokio runtime is active (e.g. in unit tests).
    pub fn spawn_sweeper(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let windows = Arc::clone(&self.windows);
        let window = self.window;
        handle.spawn(async move {
            let interval = std::time::Duration::from_secs(60);
            loop {
                tokio::time::sleep(interval).await;
                windows.retain(|_ip, timestamps| {
                    timestamps.retain(|t| t.elapsed() < window);
                    !timestamps.is_empty()
                });
            }
        });
    }

    /// Records a request for `ip` and returns the current request rate (req/s).
    pub fn record_and_rate(&self, ip: &str) -> f64 {
        let now = Instant::now();
        let mut timestamps = self.windows.entry(ip.to_string()).or_default();

        // Evict old entries outside the window
        timestamps.retain(|t| now.duration_since(*t) < self.window);
        timestamps.push(now);

        let count = timestamps.len() as f64;
        let window_secs = self.window.as_secs_f64();
        count / window_secs
    }

    /// Clears state for an IP (e.g., after a ban is lifted).
    pub fn clear(&self, ip: &str) {
        self.windows.remove(ip);
    }
}

/// Legacy helper for static hCaptcha challenge HTML.
/// Prefer `CaptchaManager::challenge_html` for provider-specific output.
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

/// Action to take after evaluating a request for CAPTCHA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptchaAction {
    /// Allow the request through
    Allow,
    /// Block the request (known bad bot)
    Block,
    /// Serve a CAPTCHA challenge page
    Challenge,
}

/// Supported CAPTCHA service providers.
///
/// Each provider has its own JavaScript widget, server-side verification URL,
/// HTML div class, and form field name. The [`CaptchaManager`] generates
/// provider-specific challenge pages automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaProvider {
    /// hCaptcha (privacy-focused alternative to reCAPTCHA).
    HCaptcha,
    /// Cloudflare Turnstile (invisible/managed challenge).
    Turnstile,
    /// Google reCAPTCHA v2 (checkbox challenge).
    RecaptchaV2,
}

impl CaptchaProvider {
    /// Parses a provider name string into its enum variant.
    /// Defaults to `HCaptcha` for unrecognized values.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "turnstile" | "cloudflare" => Self::Turnstile,
            "recaptcha" | "recaptcha_v2" => Self::RecaptchaV2,
            _ => Self::HCaptcha,
        }
    }

    /// Returns the JavaScript SDK URL for the CAPTCHA provider widget.
    pub fn script_url(&self) -> &'static str {
        match self {
            Self::HCaptcha => "https://hcaptcha.com/1/api.js",
            Self::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/api.js",
            Self::RecaptchaV2 => "https://www.google.com/recaptcha/api.js",
        }
    }

    /// Returns the server-side token verification API endpoint.
    pub fn verify_url(&self) -> &'static str {
        match self {
            Self::HCaptcha => "https://hcaptcha.com/siteverify",
            Self::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            Self::RecaptchaV2 => "https://www.google.com/recaptcha/api/siteverify",
        }
    }

    /// Returns the CSS class name for the CAPTCHA widget container div.
    pub fn div_class(&self) -> &'static str {
        match self {
            Self::HCaptcha => "h-captcha",
            Self::Turnstile => "cf-turnstile",
            Self::RecaptchaV2 => "g-recaptcha",
        }
    }

    /// Returns the HTML form field name that carries the solved CAPTCHA token.
    pub fn form_field(&self) -> &'static str {
        match self {
            Self::HCaptcha => "h-captcha-response",
            Self::Turnstile => "cf-turnstile-response",
            Self::RecaptchaV2 => "g-recaptcha-response",
        }
    }
}

/// Manages CAPTCHA challenge state: tracks which IPs have been challenged,
/// which have passed, and validates challenge tokens.
pub struct CaptchaManager {
    /// Site key for the CAPTCHA provider (hCaptcha/Turnstile)
    site_key: String,
    /// Secret key for server-side verification
    secret_key: String,
    /// Provider type
    provider: CaptchaProvider,
    /// IPs that have been challenged and passed verification
    verified_ips: Arc<Mutex<HashSet<String>>>,
    /// Rate threshold (req/s) above which Unknown bots get challenged
    challenge_threshold: f64,
    /// Bot rate tracker for anomaly scoring
    rate_tracker: BotRateTracker,
    /// Pending one-time CAPTCHA challenges keyed by client IP.
    pending_challenges: Arc<Mutex<HashMap<String, PendingChallenge>>>,
    /// Challenge nonce time-to-live.
    challenge_ttl: Duration,
}

/// Internal record of a CAPTCHA challenge issued to a specific client IP.
#[derive(Debug, Clone)]
struct PendingChallenge {
    /// Cryptographically random nonce to prevent replay attacks.
    nonce: String,
    /// URL path to redirect to after successful verification.
    return_to: String,
    /// When the challenge was issued, for TTL enforcement.
    issued_at: Instant,
}

impl CaptchaManager {
    /// Creates a new CAPTCHA manager with the given provider credentials.
    ///
    /// # Arguments
    /// * `site_key` - Public site key shown in the HTML widget.
    /// * `secret_key` - Server-side secret for token verification.
    /// * `provider` - Which CAPTCHA service to use.
    /// * `challenge_threshold` - Requests/second above which unknown bots are challenged.
    pub fn new(
        site_key: String,
        secret_key: String,
        provider: CaptchaProvider,
        challenge_threshold: f64,
    ) -> Self {
        let rate_tracker = BotRateTracker::new(60);
        rate_tracker.spawn_sweeper();
        Self {
            site_key,
            secret_key,
            provider,
            verified_ips: Arc::new(Mutex::new(HashSet::new())),
            challenge_threshold,
            rate_tracker,
            pending_challenges: Arc::new(Mutex::new(HashMap::new())),
            challenge_ttl: Duration::from_secs(600),
        }
    }

    /// Determines the action for an incoming request based on bot classification and rate.
    /// Returns the CAPTCHA action to take.
    pub fn evaluate(&self, ip: &str, user_agent: &str) -> CaptchaAction {
        let bot_class = classify_user_agent(user_agent);

        match bot_class {
            BotClass::Human => CaptchaAction::Allow,
            BotClass::GoodBot => CaptchaAction::Allow,
            BotClass::BadBot => CaptchaAction::Block,
            BotClass::Unknown => {
                // Check if already verified
                if self.verified_ips.lock().unwrap().contains(ip) {
                    return CaptchaAction::Allow;
                }
                // Check rate anomaly
                let rate = self.rate_tracker.record_and_rate(ip);
                if rate > self.challenge_threshold {
                    CaptchaAction::Challenge
                } else {
                    CaptchaAction::Allow
                }
            }
        }
    }

    /// Generates the challenge HTML page for the configured provider.
    pub fn challenge_html(&self) -> String {
        self.challenge_html_for("0.0.0.0", "/")
    }

    /// Generates challenge HTML with a one-time nonce bound to IP and return path.
    pub fn challenge_html_for(&self, ip: &str, return_to: &str) -> String {
        let mut nonce_bytes = [0u8; 24];
        rand::rng().fill(&mut nonce_bytes);
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
        let safe_return_to = sanitize_return_to(return_to);

        if let Ok(mut pending) = self.pending_challenges.lock() {
            pending.insert(
                ip.to_string(),
                PendingChallenge {
                    nonce: nonce.clone(),
                    return_to: safe_return_to.clone(),
                    issued_at: Instant::now(),
                },
            );
        }

        format!(
            r#"<!DOCTYPE html>
<html>
<head><title>Bot Verification</title>
<script src="{script_url}" async defer></script>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }}
.container {{ text-align: center; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
h1 {{ font-size: 1.5rem; color: #333; margin-bottom: 1.5rem; }}
button {{ margin-top: 1rem; padding: 0.75rem 2rem; background: #4A90D9; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }}
button:hover {{ background: #357ABD; }}
</style>
</head>
<body>
<div class="container">
<h1>Please verify you are human</h1>
<form method="POST" action="/__phalanx/captcha/verify">
  <input type="hidden" name="phalanx_challenge_nonce" value="{nonce}">
  <input type="hidden" name="return_to" value="{return_to}">
  <div class="{div_class}" data-sitekey="{site_key}"></div>
  <button type="submit">Continue</button>
</form>
</div>
</body>
</html>"#,
            script_url = self.provider.script_url(),
            div_class = self.provider.div_class(),
            site_key = self.site_key,
            nonce = nonce,
            return_to = html_escape_attr(&safe_return_to),
        )
    }

    /// Verifies a CAPTCHA token with the provider's API.
    /// Returns true if verification succeeded.
    pub async fn verify_token(&self, token: &str, ip: &str) -> bool {
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        let params = [
            ("secret", self.secret_key.as_str()),
            ("response", token),
            ("remoteip", ip),
        ];

        match client
            .post(self.provider.verify_url())
            .form(&params)
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    let success = json
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if success {
                        self.verified_ips.lock().unwrap().insert(ip.to_string());
                    }
                    success
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    /// Checks if an IP has already passed CAPTCHA verification.
    pub fn is_verified(&self, ip: &str) -> bool {
        self.verified_ips.lock().unwrap().contains(ip)
    }

    /// Removes verification for an IP (e.g., session expired).
    pub fn revoke(&self, ip: &str) {
        self.verified_ips.lock().unwrap().remove(ip);
    }

    /// Clears all verified IPs.
    pub fn clear_all(&self) {
        self.verified_ips.lock().unwrap().clear();
    }

    /// Returns a validated return path if the nonce matches the pending challenge for `ip`.
    pub fn return_to_for_valid_nonce(&self, ip: &str, nonce: &str) -> Option<String> {
        let mut pending = self.pending_challenges.lock().ok()?;
        if let Some(entry) = pending.get(ip) {
            if entry.issued_at.elapsed() > self.challenge_ttl {
                pending.remove(ip);
                return None;
            }
            if entry.nonce == nonce {
                return Some(entry.return_to.clone());
            }
        }
        None
    }

    /// Consumes an existing challenge nonce for `ip`.
    pub fn consume_challenge(&self, ip: &str) {
        if let Ok(mut pending) = self.pending_challenges.lock() {
            pending.remove(ip);
        }
    }

    /// Returns the public site key configured for this manager.
    pub fn site_key(&self) -> &str {
        &self.site_key
    }

    /// Returns the CAPTCHA provider type configured for this manager.
    pub fn provider(&self) -> CaptchaProvider {
        self.provider
    }

    /// Extracts a provider-appropriate CAPTCHA token from form fields.
    pub fn extract_token_from_form(
        &self,
        form_values: &std::collections::HashMap<String, String>,
    ) -> Option<String> {
        form_values
            .get(self.provider.form_field())
            .or_else(|| form_values.get("response"))
            .filter(|v| !v.is_empty())
            .cloned()
    }

    /// Extracts the `phalanx_challenge_nonce` hidden field from submitted form data.
    pub fn extract_nonce_from_form(
        &self,
        form_values: &std::collections::HashMap<String, String>,
    ) -> Option<String> {
        form_values
            .get("phalanx_challenge_nonce")
            .filter(|v| !v.is_empty())
            .cloned()
    }
}

/// Sanitizes the `return_to` URL to prevent open redirect attacks.
///
/// Only allows relative paths starting with a single `/`. Empty strings,
/// absolute URLs, and protocol-relative URLs (`//evil.com`) are replaced
/// with `/`.
fn sanitize_return_to(return_to: &str) -> String {
    if return_to.is_empty() {
        return "/".to_string();
    }
    if !return_to.starts_with('/') {
        return "/".to_string();
    }
    if return_to.starts_with("//") {
        return "/".to_string();
    }
    return_to.to_string()
}

/// Escapes special HTML characters in attribute values to prevent XSS in
/// the generated CAPTCHA challenge page.
fn html_escape_attr(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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

    // ── CAPTCHA Manager Tests ──────────────────────────────────────────────

    #[test]
    fn test_captcha_provider_from_str() {
        assert_eq!(CaptchaProvider::from_str("hcaptcha"), CaptchaProvider::HCaptcha);
        assert_eq!(CaptchaProvider::from_str("turnstile"), CaptchaProvider::Turnstile);
        assert_eq!(CaptchaProvider::from_str("cloudflare"), CaptchaProvider::Turnstile);
        assert_eq!(CaptchaProvider::from_str("recaptcha"), CaptchaProvider::RecaptchaV2);
        assert_eq!(CaptchaProvider::from_str("unknown"), CaptchaProvider::HCaptcha);
    }

    #[test]
    fn test_captcha_provider_urls() {
        assert!(CaptchaProvider::HCaptcha.script_url().contains("hcaptcha"));
        assert!(CaptchaProvider::Turnstile.script_url().contains("cloudflare"));
        assert!(CaptchaProvider::RecaptchaV2.script_url().contains("google"));
        assert!(CaptchaProvider::HCaptcha.verify_url().contains("hcaptcha"));
        assert!(CaptchaProvider::Turnstile.verify_url().contains("cloudflare"));
        assert!(CaptchaProvider::RecaptchaV2.verify_url().contains("google"));
    }

    #[test]
    fn test_captcha_provider_div_class() {
        assert_eq!(CaptchaProvider::HCaptcha.div_class(), "h-captcha");
        assert_eq!(CaptchaProvider::Turnstile.div_class(), "cf-turnstile");
        assert_eq!(CaptchaProvider::RecaptchaV2.div_class(), "g-recaptcha");
    }

    #[test]
    fn test_captcha_provider_form_field() {
        assert_eq!(CaptchaProvider::HCaptcha.form_field(), "h-captcha-response");
        assert_eq!(CaptchaProvider::Turnstile.form_field(), "cf-turnstile-response");
        assert_eq!(CaptchaProvider::RecaptchaV2.form_field(), "g-recaptcha-response");
    }

    #[test]
    fn test_captcha_manager_creation() {
        let mgr = CaptchaManager::new(
            "site-key-123".to_string(),
            "secret-key-456".to_string(),
            CaptchaProvider::HCaptcha,
            5.0,
        );
        assert_eq!(mgr.site_key(), "site-key-123");
        assert_eq!(mgr.provider(), CaptchaProvider::HCaptcha);
    }

    #[test]
    fn test_captcha_evaluate_human_allows() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::HCaptcha, 5.0);
        let action = mgr.evaluate("10.0.0.1", "Mozilla/5.0 Chrome/120.0");
        assert_eq!(action, CaptchaAction::Allow);
    }

    #[test]
    fn test_captcha_evaluate_good_bot_allows() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::HCaptcha, 5.0);
        let action = mgr.evaluate("10.0.0.1", "Googlebot/2.1");
        assert_eq!(action, CaptchaAction::Allow);
    }

    #[test]
    fn test_captcha_evaluate_bad_bot_blocks() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::HCaptcha, 5.0);
        let action = mgr.evaluate("10.0.0.1", "sqlmap/1.5");
        assert_eq!(action, CaptchaAction::Block);
    }

    #[test]
    fn test_captcha_evaluate_unknown_bot_low_rate_allows() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::HCaptcha, 100.0);
        let action = mgr.evaluate("10.0.0.1", "python-requests/2.28");
        assert_eq!(action, CaptchaAction::Allow);
    }

    #[test]
    fn test_captcha_evaluate_unknown_bot_high_rate_challenges() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::HCaptcha, 0.01);
        // First request records the rate, subsequent push rate over threshold
        for _ in 0..5 {
            mgr.evaluate("10.0.0.2", "python-requests/2.28");
        }
        let action = mgr.evaluate("10.0.0.2", "python-requests/2.28");
        assert_eq!(action, CaptchaAction::Challenge);
    }

    #[test]
    fn test_captcha_verified_ip_bypasses_challenge() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::HCaptcha, 0.01);
        // Manually mark as verified
        mgr.verified_ips.lock().unwrap().insert("10.0.0.3".to_string());
        // Even with high rate, verified IPs pass
        for _ in 0..10 {
            mgr.evaluate("10.0.0.3", "python-requests/2.28");
        }
        let action = mgr.evaluate("10.0.0.3", "python-requests/2.28");
        assert_eq!(action, CaptchaAction::Allow);
    }

    #[test]
    fn test_captcha_is_verified() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::HCaptcha, 5.0);
        assert!(!mgr.is_verified("10.0.0.1"));
        mgr.verified_ips.lock().unwrap().insert("10.0.0.1".to_string());
        assert!(mgr.is_verified("10.0.0.1"));
    }

    #[test]
    fn test_captcha_revoke() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::HCaptcha, 5.0);
        mgr.verified_ips.lock().unwrap().insert("10.0.0.1".to_string());
        assert!(mgr.is_verified("10.0.0.1"));
        mgr.revoke("10.0.0.1");
        assert!(!mgr.is_verified("10.0.0.1"));
    }

    #[test]
    fn test_captcha_clear_all() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::HCaptcha, 5.0);
        mgr.verified_ips.lock().unwrap().insert("10.0.0.1".to_string());
        mgr.verified_ips.lock().unwrap().insert("10.0.0.2".to_string());
        mgr.clear_all();
        assert!(!mgr.is_verified("10.0.0.1"));
        assert!(!mgr.is_verified("10.0.0.2"));
    }

    #[test]
    fn test_captcha_challenge_html_contains_provider_elements() {
        let mgr = CaptchaManager::new("my-site-key".into(), "s".into(), CaptchaProvider::HCaptcha, 5.0);
        let html = mgr.challenge_html();
        assert!(html.contains("my-site-key"));
        assert!(html.contains("hcaptcha.com"));
        assert!(html.contains("h-captcha"));
        assert!(html.contains("__phalanx/captcha/verify"));
    }

    #[test]
    fn test_captcha_challenge_html_turnstile() {
        let mgr = CaptchaManager::new("ts-key".into(), "s".into(), CaptchaProvider::Turnstile, 5.0);
        let html = mgr.challenge_html();
        assert!(html.contains("ts-key"));
        assert!(html.contains("cloudflare"));
        assert!(html.contains("cf-turnstile"));
    }

    #[test]
    fn test_captcha_challenge_html_recaptcha() {
        let mgr = CaptchaManager::new("rc-key".into(), "s".into(), CaptchaProvider::RecaptchaV2, 5.0);
        let html = mgr.challenge_html();
        assert!(html.contains("rc-key"));
        assert!(html.contains("google.com/recaptcha"));
        assert!(html.contains("g-recaptcha"));
    }

    #[test]
    fn test_captcha_action_equality() {
        assert_eq!(CaptchaAction::Allow, CaptchaAction::Allow);
        assert_eq!(CaptchaAction::Block, CaptchaAction::Block);
        assert_eq!(CaptchaAction::Challenge, CaptchaAction::Challenge);
        assert_ne!(CaptchaAction::Allow, CaptchaAction::Block);
        assert_ne!(CaptchaAction::Allow, CaptchaAction::Challenge);
    }

    #[test]
    fn test_extract_token_from_form_turnstile() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::Turnstile, 5.0);
        let mut form = std::collections::HashMap::new();
        form.insert("cf-turnstile-response".to_string(), "ts-token".to_string());
        assert_eq!(
            mgr.extract_token_from_form(&form),
            Some("ts-token".to_string())
        );
    }

    #[test]
    fn test_extract_token_from_form_recaptcha() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::RecaptchaV2, 5.0);
        let mut form = std::collections::HashMap::new();
        form.insert("g-recaptcha-response".to_string(), "rc-token".to_string());
        assert_eq!(
            mgr.extract_token_from_form(&form),
            Some("rc-token".to_string())
        );
    }

    #[test]
    fn test_extract_nonce_from_form() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::Turnstile, 5.0);
        let mut form = std::collections::HashMap::new();
        form.insert(
            "phalanx_challenge_nonce".to_string(),
            "nonce-123".to_string(),
        );
        assert_eq!(
            mgr.extract_nonce_from_form(&form),
            Some("nonce-123".to_string())
        );
    }

    #[test]
    fn test_challenge_html_for_embeds_nonce_and_return_to() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::Turnstile, 5.0);
        let html = mgr.challenge_html_for("10.1.1.1", "/docs?a=1");
        assert!(html.contains("phalanx_challenge_nonce"));
        assert!(html.contains("name=\"return_to\" value=\"/docs?a=1\""));
    }

    #[test]
    fn test_nonce_validation_and_consume() {
        let mgr = CaptchaManager::new("k".into(), "s".into(), CaptchaProvider::Turnstile, 5.0);
        let html = mgr.challenge_html_for("10.2.2.2", "/admin");
        let marker = "name=\"phalanx_challenge_nonce\" value=\"";
        let start = html.find(marker).expect("nonce marker");
        let rest = &html[start + marker.len()..];
        let end = rest.find('"').expect("nonce end");
        let nonce = &rest[..end];

        assert_eq!(
            mgr.return_to_for_valid_nonce("10.2.2.2", nonce),
            Some("/admin".to_string())
        );
        mgr.consume_challenge("10.2.2.2");
        assert_eq!(mgr.return_to_for_valid_nonce("10.2.2.2", nonce), None);
    }

    #[test]
    fn test_sanitize_return_to_rejects_external() {
        assert_eq!(sanitize_return_to("https://evil.com"), "/");
        assert_eq!(sanitize_return_to("//evil.com"), "/");
        assert_eq!(sanitize_return_to("/safe"), "/safe");
    }
}
