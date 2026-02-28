//! Integration tests for the Phalanx AI Load Balancer.
//!
//! These tests verify WAF URL-decoding, compression logic, cache behavior,
//! and protocol detection without starting the full proxy server.

#[cfg(test)]
mod waf_url_decode_tests {
    use ai_load_balancer::waf::WafEngine;
    use ai_load_balancer::waf::reputation::IpReputationManager;
    use std::sync::Arc;

    fn make_waf() -> WafEngine {
        let reputation = Arc::new(IpReputationManager::new(100, 60));
        WafEngine::new(true, reputation)
    }

    #[test]
    fn test_sqli_union_select_encoded() {
        let waf = make_waf();
        // UNION SELECT with %20 (URL-encoded space)
        let result = waf.inspect(
            "10.0.0.1",
            "/api",
            Some("q=UNION%20SELECT%20password%20FROM%20users"),
            Some("Mozilla/5.0"),
        );
        assert!(
            matches!(result, ai_load_balancer::waf::WafAction::Block(_)),
            "WAF should block URL-encoded UNION SELECT"
        );
    }

    #[test]
    fn test_sqli_drop_table_encoded() {
        let waf = make_waf();
        let result = waf.inspect(
            "10.0.0.2",
            "/api",
            Some("q=1;%20DROP%20TABLE%20users"),
            Some("Mozilla/5.0"),
        );
        assert!(
            matches!(result, ai_load_balancer::waf::WafAction::Block(_)),
            "WAF should block URL-encoded DROP TABLE"
        );
    }

    #[test]
    fn test_xss_script_tag_encoded() {
        let waf = make_waf();
        let result = waf.inspect(
            "10.0.0.3",
            "/api",
            Some("q=%3Cscript%3Ealert(1)%3C/script%3E"),
            Some("Mozilla/5.0"),
        );
        assert!(
            matches!(result, ai_load_balancer::waf::WafAction::Block(_)),
            "WAF should block URL-encoded <script> tags"
        );
    }

    #[test]
    fn test_path_traversal_encoded() {
        let waf = make_waf();
        let result = waf.inspect(
            "10.0.0.4",
            "/api",
            Some("file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
            Some("Mozilla/5.0"),
        );
        assert!(
            matches!(result, ai_load_balancer::waf::WafAction::Block(_)),
            "WAF should block URL-encoded path traversal"
        );
    }

    #[test]
    fn test_command_injection_encoded() {
        let waf = make_waf();
        let result = waf.inspect(
            "10.0.0.5",
            "/api",
            Some("ip=127.0.0.1;%20cat%20/etc/hosts"),
            Some("Mozilla/5.0"),
        );
        assert!(
            matches!(result, ai_load_balancer::waf::WafAction::Block(_)),
            "WAF should block URL-encoded command injection"
        );
    }

    #[test]
    fn test_benign_request_allowed() {
        let waf = make_waf();
        let result = waf.inspect(
            "10.0.0.6",
            "/api",
            Some("category=electronics&page=2"),
            Some("Mozilla/5.0 Chrome/120"),
        );
        assert!(
            matches!(result, ai_load_balancer::waf::WafAction::Allow),
            "WAF should allow benign request"
        );
    }

    #[test]
    fn test_bot_sqlmap_blocked() {
        let waf = make_waf();
        let result = waf.inspect("10.0.0.7", "/", None, Some("sqlmap/1.5.8"));
        assert!(
            matches!(result, ai_load_balancer::waf::WafAction::Block(_)),
            "WAF should block sqlmap bot"
        );
    }

    #[test]
    fn test_empty_user_agent_blocked() {
        let waf = make_waf();
        let result = waf.inspect("10.0.0.8", "/", None, None);
        assert!(
            matches!(result, ai_load_balancer::waf::WafAction::Block(_)),
            "WAF should block empty user agent"
        );
    }

    #[test]
    fn test_form_encoded_body_sqli() {
        let waf = make_waf();
        // Body with URL-encoded SQL injection
        let result = waf.inspect_body(
            "10.0.0.9",
            "username=admin%27%20OR%20%271%27=%271&password=test",
        );
        assert!(
            matches!(result, ai_load_balancer::waf::WafAction::Block(_)),
            "WAF should block URL-encoded SQLi in request body"
        );
    }

    #[test]
    fn test_ip_ban_and_expiry() {
        let reputation = Arc::new(IpReputationManager::new(10, 1)); // threshold=10, ban=1s
        let waf = WafEngine::new(true, Arc::clone(&reputation));

        // Add strikes to trigger ban
        reputation.add_strike("10.0.0.10", 15);

        // Should be banned now
        let result = waf.inspect("10.0.0.10", "/", None, Some("Mozilla/5.0"));
        assert!(
            matches!(result, ai_load_balancer::waf::WafAction::Block(_)),
            "IP should be banned after exceeding threshold"
        );

        // Wait for ban to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        let result = waf.inspect("10.0.0.10", "/", None, Some("Mozilla/5.0"));
        assert!(
            matches!(result, ai_load_balancer::waf::WafAction::Allow),
            "IP ban should have expired"
        );
    }
}

#[cfg(test)]
mod compression_tests {
    use ai_load_balancer::middleware::compression;

    #[test]
    fn test_accepts_gzip() {
        assert!(compression::accepts_gzip(Some("gzip, deflate, br")));
        assert!(compression::accepts_gzip(Some("gzip")));
        assert!(!compression::accepts_gzip(Some("deflate")));
        assert!(!compression::accepts_gzip(None));
    }

    #[test]
    fn test_is_compressible() {
        assert!(compression::is_compressible(Some("text/html")));
        assert!(compression::is_compressible(Some("text/plain")));
        assert!(compression::is_compressible(Some("application/json")));
        assert!(compression::is_compressible(Some("application/javascript")));
        assert!(!compression::is_compressible(Some("image/png")));
        assert!(!compression::is_compressible(Some(
            "application/octet-stream"
        )));
        assert!(!compression::is_compressible(None));
    }

    #[test]
    fn test_gzip_compress_small_body() {
        // Bodies < 1KB should not be compressed
        let small = b"Hello, world!";
        assert!(compression::gzip_compress(small).is_none());
    }

    #[test]
    fn test_gzip_compress_large_body() {
        // 2KB of repeated text — should compress well
        let large: Vec<u8> = "Hello, this is a test string for compression. "
            .repeat(50)
            .into_bytes();
        assert!(large.len() > 1024);

        let compressed = compression::gzip_compress(&large);
        assert!(compressed.is_some(), "Large body should be compressed");

        let compressed = compressed.unwrap();
        assert!(
            compressed.len() < large.len(),
            "Compressed should be smaller"
        );
    }
}

#[cfg(test)]
mod cache_tests {
    use ai_load_balancer::middleware::{CachedResponse, ResponseCache};
    use bytes::Bytes;

    #[tokio::test]
    async fn test_cache_miss_then_hit() {
        let cache = ResponseCache::new(100, 60);
        let key = ResponseCache::cache_key("GET", "example.com", "/api/data", None);

        // Miss
        let res: Option<CachedResponse> = cache.get(&key).await;
        assert!(res.is_none());

        // Insert
        cache
            .insert_with_ttl(
                key.clone(),
                CachedResponse {
                    status: 200,
                    body: Bytes::from("cached response body"),
                    content_type: "text/plain".to_string(),
                    expires_at: std::time::Instant::now(),
                },
                60,
            )
            .await;

        // Hit
        let cached: Option<CachedResponse> = cache.get(&key).await;
        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert_eq!(cached.status, 200);
        assert_eq!(cached.body, Bytes::from("cached response body"));
    }

    #[test]
    fn test_cache_key_generation() {
        let key = ResponseCache::cache_key("GET", "example.com", "/api", Some("id=42"));
        assert_eq!(key, "GET:example.com:/api?id=42");

        let key_no_query = ResponseCache::cache_key("GET", "example.com", "/api", None);
        assert_eq!(key_no_query, "GET:example.com:/api");
    }
}

#[cfg(test)]
mod config_tests {
    use ai_load_balancer::config::load_config;

    #[test]
    fn test_config_loads_without_panic() {
        // Should not panic even if phalanx.conf doesn't exist (uses defaults)
        let config = load_config("phalanx.conf");
        assert!(config.workers > 0);
    }
}

#[cfg(test)]
mod protocol_sniff_tests {
    use ai_load_balancer::proxy::router::{Protocol, sniff_protocol};
    use bytes::BytesMut;

    #[tokio::test]
    async fn test_sniff_http1_get() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut cursor = std::io::Cursor::new(&data[..]);
        let mut buf = BytesMut::new();
        let result: Protocol = sniff_protocol(&mut cursor, &mut buf).await.unwrap();
        assert_eq!(result, Protocol::Http1);
    }

    #[tokio::test]
    async fn test_sniff_http1_post() {
        let data = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let mut cursor = std::io::Cursor::new(&data[..]);
        let mut buf = BytesMut::new();
        let result: Protocol = sniff_protocol(&mut cursor, &mut buf).await.unwrap();
        assert_eq!(result, Protocol::Http1);
    }

    #[tokio::test]
    async fn test_sniff_http2() {
        let data = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let mut cursor = std::io::Cursor::new(&data[..]);
        let mut buf = BytesMut::new();
        let result: Protocol = sniff_protocol(&mut cursor, &mut buf).await.unwrap();
        assert_eq!(result, Protocol::Http2);
    }

    #[tokio::test]
    async fn test_sniff_tls() {
        // TLS Client Hello starts with 0x16 0x03 0x01
        let data = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01];
        let mut cursor = std::io::Cursor::new(&data[..]);
        let mut buf = BytesMut::new();
        let result: Protocol = sniff_protocol(&mut cursor, &mut buf).await.unwrap();
        assert_eq!(result, Protocol::Tls);
    }

    #[tokio::test]
    async fn test_sniff_unknown_tcp() {
        let data = b"\x00\x01\x02\x03\x04\x05\x06\x07";
        let mut cursor = std::io::Cursor::new(&data[..]);
        let mut buf = BytesMut::new();
        let result: Protocol = sniff_protocol(&mut cursor, &mut buf).await.unwrap();
        assert_eq!(result, Protocol::UnknownTcp);
    }
}
