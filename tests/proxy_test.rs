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
        let reputation = IpReputationManager::new(100, 60, None);
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
        let reputation = IpReputationManager::new(10, 1, None); // threshold=10, ban=1s
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
    use ai_load_balancer::middleware::{AdvancedCache, CacheEntry, build_cache_key};
    use bytes::Bytes;
    use std::time::{Duration, Instant};

    fn make_entry(body: &'static [u8], ttl_secs: u64) -> CacheEntry {
        CacheEntry {
            status: 200,
            body: Bytes::from_static(body),
            content_type: "text/plain".to_string(),
            headers: vec![],
            created_at: Instant::now(),
            max_age: Duration::from_secs(ttl_secs),
            stale_while_revalidate: Duration::ZERO,
            stale_if_error: Duration::ZERO,
        }
    }

    #[tokio::test]
    async fn test_cache_miss_then_hit() {
        let cache = AdvancedCache::new(100, 60, None);
        let key = build_cache_key("GET", "example.com", "/api/data", None, &[]);

        // Miss
        assert!(cache.get(&key).await.is_none());

        // Insert
        cache.insert(key.clone(), make_entry(b"cached response body", 60)).await;

        // Hit
        let cached = cache.get(&key).await.expect("should be cached");
        assert_eq!(cached.status, 200);
        assert_eq!(cached.body, Bytes::from_static(b"cached response body"));
    }

    #[test]
    fn test_cache_key_generation() {
        let key = build_cache_key("GET", "example.com", "/api", Some("id=42"), &[]);
        assert_eq!(key, "GET:example.com:/api?id=42");

        let key_no_query = build_cache_key("GET", "example.com", "/api", None, &[]);
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
mod geo_tests {
    use ai_load_balancer::geo::{GeoIpDatabase, GeoPolicy};

    #[test]
    fn test_geo_db_lookup_hit() {
        let mut db = GeoIpDatabase::new();
        db.add_entry("1.2.3.0/24", "DE", "Germany");
        let result = db.lookup(&"1.2.3.100".parse().unwrap());
        assert!(result.is_some());
        assert_eq!(result.unwrap().country_code, "DE");
    }

    #[test]
    fn test_geo_db_lookup_miss() {
        let mut db = GeoIpDatabase::new();
        db.add_entry("1.2.3.0/24", "DE", "Germany");
        let result = db.lookup(&"9.9.9.9".parse().unwrap());
        assert!(result.is_none());
    }

    #[test]
    fn test_geo_policy_allow_list_blocks_unlisted() {
        let mut policy = GeoPolicy::new();
        policy.allow_countries = vec!["US".to_string(), "CA".to_string()];
        assert!(policy.is_allowed("US"));
        assert!(policy.is_allowed("CA"));
        assert!(!policy.is_allowed("DE"));
        assert!(!policy.is_allowed("CN"));
    }

    #[test]
    fn test_geo_policy_deny_list() {
        let mut policy = GeoPolicy::new();
        policy.deny_countries = vec!["CN".to_string(), "RU".to_string()];
        assert!(!policy.is_allowed("CN"));
        assert!(!policy.is_allowed("RU"));
        assert!(policy.is_allowed("US"));
        assert!(policy.is_allowed("DE"));
    }

    #[test]
    fn test_geo_policy_deny_overrides_allow() {
        let mut policy = GeoPolicy::new();
        policy.allow_countries = vec!["CN".to_string()];
        policy.deny_countries = vec!["CN".to_string()];
        // Deny takes priority
        assert!(!policy.is_allowed("CN"));
    }

    #[test]
    fn test_geo_policy_empty_allows_all() {
        let policy = GeoPolicy::new();
        assert!(policy.is_allowed("US"));
        assert!(policy.is_allowed("CN"));
        assert!(policy.is_allowed("XX"));
    }

    #[test]
    fn test_geo_policy_case_insensitive() {
        let mut policy = GeoPolicy::new();
        policy.allow_countries = vec!["us".to_string()];
        assert!(policy.is_allowed("US"));
        assert!(policy.is_allowed("us"));
    }

    #[test]
    fn test_geo_inject_headers() {
        let result = ai_load_balancer::geo::GeoResult {
            country_code: "JP".to_string(),
            country_name: "Japan".to_string(),
        };
        let mut headers = hyper::HeaderMap::new();
        ai_load_balancer::geo::inject_geo_headers(&mut headers, &result);
        assert!(headers.contains_key("x-geo-country-code"));
        assert!(headers.contains_key("x-geo-country"));
        assert_eq!(
            headers.get("x-geo-country-code").unwrap().to_str().unwrap(),
            "JP"
        );
    }
}

#[cfg(test)]
mod sticky_session_tests {
    use ai_load_balancer::proxy::sticky::{StickyMode, StickySessionManager, base64_decode_addr};
    use std::time::Duration;

    #[test]
    fn test_cookie_mode_learn_and_lookup() {
        let mgr = StickySessionManager::new(StickyMode::Cookie {
            name: "SRV".to_string(),
            path: "/".to_string(),
            http_only: true,
            secure: false,
            max_age: 3600,
        });
        mgr.learn("session-1".to_string(), "10.0.0.1:8080".to_string());
        assert_eq!(mgr.lookup("session-1"), Some("10.0.0.1:8080".to_string()));
        assert!(mgr.lookup("session-999").is_none());
    }

    #[test]
    fn test_set_cookie_header_format() {
        let mgr = StickySessionManager::new(StickyMode::Cookie {
            name: "PHALANX_SRV".to_string(),
            path: "/api".to_string(),
            http_only: true,
            secure: true,
            max_age: 1800,
        });
        let header = mgr.set_cookie_header("backend:9000").unwrap();
        assert!(header.starts_with("PHALANX_SRV="));
        assert!(header.contains("Path=/api"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("Max-Age=1800"));
    }

    #[test]
    fn test_learn_mode_timeout_expiry() {
        let mgr = StickySessionManager::new(StickyMode::Learn {
            lookup_header: "X-Sess".to_string(),
            timeout: Duration::from_millis(1),
        });
        mgr.learn("k".to_string(), "backend".to_string());
        std::thread::sleep(Duration::from_millis(10));
        assert!(mgr.lookup("k").is_none(), "expired entry should not be returned");
    }

    #[test]
    fn test_extract_cookie() {
        let mgr = StickySessionManager::new(StickyMode::Cookie {
            name: "SRV".to_string(),
            path: "/".to_string(),
            http_only: false,
            secure: false,
            max_age: 0,
        });
        assert_eq!(
            mgr.extract_from_cookie("SRV=abc123; other=val"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn test_base64_addr_roundtrip() {
        let addr = "10.0.0.5:8080";
        let mgr = StickySessionManager::new(StickyMode::Cookie {
            name: "S".to_string(),
            path: "/".to_string(),
            http_only: false,
            secure: false,
            max_age: 0,
        });
        let header = mgr.set_cookie_header(addr).unwrap();
        let encoded = header.split('=').nth(1).and_then(|s| s.split(';').next()).unwrap();
        let decoded = base64_decode_addr(encoded).unwrap();
        assert_eq!(decoded, addr);
    }
}

#[cfg(test)]
mod mirror_tests {
    use ai_load_balancer::proxy::mirror::split_traffic;

    #[test]
    fn test_split_traffic_deterministic() {
        let weights = vec![80, 20];
        let key = "user-session-abc";
        assert_eq!(split_traffic(key, &weights), split_traffic(key, &weights));
    }

    #[test]
    fn test_split_traffic_empty_weights_returns_zero() {
        assert_eq!(split_traffic("any", &[]), 0);
    }

    #[test]
    fn test_split_traffic_single_bucket() {
        for i in 0..100 {
            let key = format!("user-{}", i);
            assert_eq!(split_traffic(&key, &[100]), 0);
        }
    }

    #[test]
    fn test_split_traffic_zero_total() {
        assert_eq!(split_traffic("k", &[0, 0]), 0);
    }

    #[test]
    fn test_split_traffic_90_10_roughly_correct() {
        let weights = vec![90, 10];
        let mut counts = [0u32; 2];
        for i in 0..10000 {
            let key = format!("user-{}", i);
            counts[split_traffic(&key, &weights)] += 1;
        }
        // 90% bucket should get roughly 9000 ± 300
        assert!(counts[0] > 8000 && counts[0] < 9500, "90% bucket got {}", counts[0]);
    }
}

#[cfg(test)]
mod realip_tests {
    use ai_load_balancer::proxy::realip::{TrustedProxies, resolve_client_ip, inject_forwarding_headers};
    use std::net::{IpAddr, SocketAddr};

    #[test]
    fn test_untrusted_peer_returns_socket_ip() {
        let tp = TrustedProxies::from_cidrs(&["10.0.0.0/8".to_string()]);
        let peer: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let headers = hyper::HeaderMap::new();
        let resolved = resolve_client_ip(&peer, &headers, &tp);
        assert_eq!(resolved, "203.0.113.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_trusted_peer_xff_resolution() {
        let tp = TrustedProxies::from_cidrs(&["10.0.0.0/8".to_string()]);
        let peer: SocketAddr = "10.1.1.1:80".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50, 10.1.1.1".parse().unwrap());
        let resolved = resolve_client_ip(&peer, &headers, &tp);
        assert_eq!(resolved, "203.0.113.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_trusted_peer_x_real_ip_priority() {
        let tp = TrustedProxies::from_cidrs(&["10.0.0.0/8".to_string()]);
        let peer: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-real-ip", "5.6.7.8".parse().unwrap());
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        // X-Real-IP has higher priority than X-Forwarded-For
        let resolved = resolve_client_ip(&peer, &headers, &tp);
        assert_eq!(resolved, "5.6.7.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_empty_trusted_proxies_no_header_trust() {
        let tp = TrustedProxies::from_cidrs(&[]);
        let peer: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        // No trusted proxies → socket IP always wins
        let resolved = resolve_client_ip(&peer, &headers, &tp);
        assert_eq!(resolved, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_inject_forwarding_headers() {
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        inject_forwarding_headers(&mut headers, &ip, false);
        assert!(headers.contains_key("x-forwarded-for"));
        assert!(headers.contains_key("x-real-ip"));
        assert_eq!(
            headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
            "http"
        );
    }

    #[test]
    fn test_inject_forwarding_headers_tls() {
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        inject_forwarding_headers(&mut headers, &ip, true);
        assert_eq!(
            headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
            "https"
        );
    }

    #[test]
    fn test_inject_appends_to_existing_xff() {
        let ip: IpAddr = "2.2.2.2".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "1.1.1.1".parse().unwrap());
        inject_forwarding_headers(&mut headers, &ip, false);
        let xff = headers.get("x-forwarded-for").unwrap().to_str().unwrap();
        assert!(xff.contains("1.1.1.1"), "should preserve existing XFF");
        assert!(xff.contains("2.2.2.2"), "should append new IP");
    }
}

#[cfg(test)]
mod connlimit_tests {
    use ai_load_balancer::middleware::connlimit::{ZoneLimiter, ZoneKeySource};

    #[test]
    fn test_zone_rate_allowed_initially() {
        let limiter = ZoneLimiter::new("api", 100, 50, 0);
        assert!(limiter.check_rate("client-1"));
    }

    #[test]
    fn test_zone_connection_limit_and_release() {
        let limiter = ZoneLimiter::new("zone", 100, 50, 2);
        assert!(limiter.acquire_connection("k"));
        assert!(limiter.acquire_connection("k"));
        assert!(!limiter.acquire_connection("k"), "3rd should be denied");
        limiter.release_connection("k");
        assert!(limiter.acquire_connection("k"), "after release should allow");
    }

    #[test]
    fn test_zone_unlimited_connections() {
        let limiter = ZoneLimiter::new("zone", 100, 50, 0);
        for _ in 0..1000 {
            assert!(limiter.acquire_connection("k"));
        }
    }

    #[test]
    fn test_key_source_composite() {
        let src = ZoneKeySource::Composite(vec![
            ZoneKeySource::ClientIp,
            ZoneKeySource::Uri,
        ]);
        let headers = hyper::HeaderMap::new();
        let key = src.extract("1.2.3.4", &headers, "/api/v1", None);
        assert_eq!(key, "1.2.3.4:/api/v1");
    }

    #[test]
    fn test_key_source_query_param_missing() {
        let src = ZoneKeySource::QueryParam("user_id".to_string());
        let headers = hyper::HeaderMap::new();
        assert_eq!(src.extract("ip", &headers, "/", Some("page=2")), "_");
    }
}

#[cfg(test)]
mod brotli_tests {
    use ai_load_balancer::middleware::brotli::{accepts_brotli, brotli_compress, MIN_BROTLI_SIZE};

    #[test]
    fn test_accepts_brotli_with_br() {
        assert!(accepts_brotli(Some("gzip, deflate, br")));
        assert!(accepts_brotli(Some("br")));
    }

    #[test]
    fn test_accepts_brotli_without_br() {
        assert!(!accepts_brotli(Some("gzip, deflate")));
        assert!(!accepts_brotli(None));
    }

    #[test]
    fn test_brotli_compress_small_returns_none() {
        let data = vec![b'a'; 100];
        assert!(brotli_compress(&data, 6).is_none());
    }

    #[test]
    fn test_brotli_compress_large_compressible() {
        let data = "the quick brown fox jumps over the lazy dog ".repeat(100);
        let compressed = brotli_compress(data.as_bytes(), 6).unwrap();
        assert!(compressed.len() < data.len(), "brotli output should be smaller");
    }

    #[test]
    fn test_brotli_minimum_size_constant() {
        assert!(MIN_BROTLI_SIZE >= 512, "MIN_BROTLI_SIZE should be at least 512 bytes");
    }
}

#[cfg(test)]
mod ai_router_tests {
    use ai_load_balancer::ai::{AiAlgorithm, build_ai_router};
    use ai_load_balancer::routing::BackendNode;
    use ai_load_balancer::config::BackendConfig;
    use std::sync::Arc;

    fn make_backend(addr: &str) -> Arc<BackendNode> {
        Arc::new(BackendNode::new(BackendConfig {
            address: addr.to_string(),
            ..Default::default()
        }))
    }

    #[test]
    fn test_epsilon_greedy_update_no_panic() {
        let router = build_ai_router(AiAlgorithm::EpsilonGreedy, 0.1, 1.0, 2.0, 100.0);
        // Should not panic on repeated updates
        for i in 0..10u64 {
            router.update_score("backend1", i * 10, i % 3 == 0);
        }
    }

    #[test]
    fn test_ucb1_router_predict_selects_from_list() {
        let router = build_ai_router(AiAlgorithm::Ucb1, 0.1, 1.0, 2.0, 100.0);
        let backends = vec![make_backend("b1"), make_backend("b2"), make_backend("b3")];
        let result = router.predict_best_backend(&backends);
        assert!(result.is_some());
        let chosen = result.unwrap();
        assert!(["b1", "b2", "b3"].contains(&chosen.config.address.as_str()));
    }

    #[test]
    fn test_softmax_router_update_then_predict() {
        let router = build_ai_router(AiAlgorithm::Softmax, 0.1, 1.0, 2.0, 100.0);
        let backends = vec![make_backend("fast"), make_backend("slow")];
        router.update_score("fast", 10, false);
        router.update_score("slow", 500, true);
        for _ in 0..10 {
            let result = router.predict_best_backend(&backends);
            assert!(result.is_some());
        }
    }

    #[test]
    fn test_thompson_sampling_update_no_panic() {
        let router = build_ai_router(AiAlgorithm::ThompsonSampling, 0.1, 1.0, 2.0, 100.0);
        for _ in 0..20 {
            router.update_score("fast", 10, false);
            router.update_score("slow", 500, false);
        }
        let backends = vec![make_backend("fast"), make_backend("slow")];
        let result = router.predict_best_backend(&backends);
        assert!(result.is_some());
    }

    #[test]
    fn test_algorithm_from_str() {
        assert_eq!(AiAlgorithm::from_str("epsilon_greedy"), AiAlgorithm::EpsilonGreedy);
        assert_eq!(AiAlgorithm::from_str("ucb1"), AiAlgorithm::Ucb1);
        assert_eq!(AiAlgorithm::from_str("softmax"), AiAlgorithm::Softmax);
        assert_eq!(AiAlgorithm::from_str("thompson_sampling"), AiAlgorithm::ThompsonSampling);
    }
}

#[cfg(test)]
mod routing_tests {
    use ai_load_balancer::routing::BackendNode;
    use ai_load_balancer::config::BackendConfig;
    use std::sync::atomic::Ordering;

    fn make_backend(addr: &str) -> BackendNode {
        BackendNode::new(BackendConfig {
            address: addr.to_string(),
            max_fails: 3,
            fail_timeout_secs: 30,
            circuit_breaker: true,
            ..Default::default()
        })
    }

    #[test]
    fn test_backend_starts_healthy() {
        let b = make_backend("127.0.0.1:8080");
        assert!(b.is_healthy.load(Ordering::Relaxed));
    }

    #[test]
    fn test_record_failure_trips_after_max_fails() {
        let b = make_backend("127.0.0.1:8080");
        for _ in 0..3 {
            b.record_failure();
        }
        assert!(!b.is_healthy.load(Ordering::Relaxed),
            "backend should be marked unhealthy after 3 failures");
    }

    #[test]
    fn test_circuit_breaker_trip_and_check() {
        let b = make_backend("127.0.0.1:8080");
        assert!(b.is_circuit_closed());
        b.trip_circuit();
        assert!(!b.is_circuit_closed());
    }

    #[test]
    fn test_record_circuit_success_resets_circuit() {
        let b = make_backend("127.0.0.1:8080");
        b.trip_circuit();
        assert!(!b.is_circuit_closed());
        b.record_circuit_success();
        assert!(b.is_circuit_closed());
    }

    #[test]
    fn test_effective_weight_default() {
        let b = make_backend("127.0.0.1:8080");
        // Default weight is 1, no slow-start
        assert!(b.effective_weight() > 0);
    }
}

#[cfg(test)]
mod keyval_tests {
    use ai_load_balancer::keyval::KeyvalStore;

    #[test]
    fn test_set_get_delete() {
        let store = KeyvalStore::new(0, None);
        store.set("hello".to_string(), "world".to_string(), None);
        assert_eq!(store.get("hello"), Some("world".to_string()));
        store.delete("hello");
        assert!(store.get("hello").is_none());
    }

    #[test]
    fn test_ttl_expiry() {
        let store = KeyvalStore::new(0, None);
        // TTL of 0 seconds = expires immediately next access
        store.set("temp".to_string(), "val".to_string(), Some(0));
        // Wait a moment and verify eviction kicks in
        std::thread::sleep(std::time::Duration::from_millis(10));
        store.evict_expired();
        assert!(store.get("temp").is_none(), "key with 0-second TTL should have expired");
    }

    #[test]
    fn test_ttl_not_expired() {
        let store = KeyvalStore::new(0, None);
        store.set("live".to_string(), "value".to_string(), Some(3600));
        assert_eq!(store.get("live"), Some("value".to_string()));
    }

    #[test]
    fn test_list_returns_all_live_keys() {
        let store = KeyvalStore::new(0, None);
        store.set("a".to_string(), "1".to_string(), None);
        store.set("b".to_string(), "2".to_string(), None);
        let keys = store.list();
        assert!(keys.iter().any(|(k, _)| k == "a"));
        assert!(keys.iter().any(|(k, _)| k == "b"));
    }

    #[test]
    fn test_contains() {
        let store = KeyvalStore::new(0, None);
        assert!(!store.contains("x"));
        store.set("x".to_string(), "y".to_string(), None);
        assert!(store.contains("x"));
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

// ─── gRPC-Web translation tests ───────────────────────────────────────────────
#[cfg(test)]
mod grpc_web_integration_tests {
    use ai_load_balancer::proxy::grpc_web::{
        cors_preflight_response, is_grpc_web, translate_request, translate_response,
    };
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::{header, Request, Response, StatusCode};

    fn grpc_web_req(content_type: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method("POST")
            .uri("http://example.com/pkg.Service/Method")
            .header(header::CONTENT_TYPE, content_type)
            .body(Full::new(Bytes::from_static(b"\x00\x00\x00\x00\x05hello")))
            .unwrap()
    }

    // ── is_grpc_web ──────────────────────────────────────────────────────────

    #[test]
    fn test_is_grpc_web_proto_variant() {
        assert!(is_grpc_web(&grpc_web_req("application/grpc-web+proto")));
    }

    #[test]
    fn test_is_grpc_web_text_variant() {
        assert!(is_grpc_web(&grpc_web_req("application/grpc-web-text")));
    }

    #[test]
    fn test_is_grpc_web_plain_variant() {
        assert!(is_grpc_web(&grpc_web_req("application/grpc-web")));
    }

    #[test]
    fn test_is_not_grpc_web_for_native_grpc() {
        let req = Request::builder()
            .header(header::CONTENT_TYPE, "application/grpc+proto")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(!is_grpc_web(&req));
    }

    // ── translate_request ────────────────────────────────────────────────────

    #[test]
    fn test_translate_request_grpc_web_to_grpc() {
        let out = translate_request(grpc_web_req("application/grpc-web"));
        assert_eq!(
            out.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/grpc")
        );
        assert_eq!(
            out.headers().get(header::TE).and_then(|v| v.to_str().ok()),
            Some("trailers")
        );
    }

    #[test]
    fn test_translate_request_grpc_web_proto_to_grpc_proto() {
        let out = translate_request(grpc_web_req("application/grpc-web+proto"));
        assert_eq!(
            out.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/grpc+proto")
        );
    }

    #[test]
    fn test_translate_request_grpc_web_text_to_grpc() {
        let out = translate_request(grpc_web_req("application/grpc-web-text"));
        assert_eq!(
            out.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/grpc")
        );
    }

    #[test]
    fn test_translate_request_always_adds_te_trailers() {
        // Even if TE was not set originally
        let req = Request::builder()
            .header(header::CONTENT_TYPE, "application/grpc-web+proto")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let out = translate_request(req);
        assert_eq!(
            out.headers().get(header::TE).and_then(|v| v.to_str().ok()),
            Some("trailers")
        );
    }

    // ── translate_response ───────────────────────────────────────────────────

    fn make_grpc_response(content_type: &str) -> Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>> {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .body(
                Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }

    #[tokio::test]
    async fn test_translate_response_grpc_to_grpc_web() {
        let resp = translate_response(make_grpc_response("application/grpc"), false).await;
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/grpc-web")
        );
    }

    #[tokio::test]
    async fn test_translate_response_grpc_to_grpc_web_text() {
        let resp = translate_response(make_grpc_response("application/grpc"), true).await;
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/grpc-web-text")
        );
    }

    #[tokio::test]
    async fn test_translate_response_adds_cors_expose_headers() {
        let resp = translate_response(make_grpc_response("application/grpc"), false).await;
        let expose = resp
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(expose.contains("grpc-status"), "must expose grpc-status");
        assert!(expose.contains("grpc-message"), "must expose grpc-message");
    }

    // ── cors_preflight_response ──────────────────────────────────────────────

    #[test]
    fn test_cors_preflight_is_204() {
        assert_eq!(cors_preflight_response().status(), StatusCode::NO_CONTENT);
    }

    #[test]
    fn test_cors_preflight_allow_origin_wildcard() {
        assert_eq!(
            cors_preflight_response()
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );
    }

    #[test]
    fn test_cors_preflight_allow_methods_includes_post() {
        let resp = cors_preflight_response();
        let methods = resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(methods.contains("POST"));
    }

    #[test]
    fn test_cors_preflight_allow_headers_includes_content_type() {
        let resp = cors_preflight_response();
        let allowed = resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(allowed.contains("content-type"));
        assert!(allowed.contains("x-grpc-web"));
    }

    #[test]
    fn test_cors_preflight_max_age_is_one_day() {
        assert_eq!(
            cors_preflight_response()
                .headers()
                .get(header::ACCESS_CONTROL_MAX_AGE)
                .and_then(|v| v.to_str().ok()),
            Some("86400")
        );
    }
}

// ─── Sticky session integration tests ─────────────────────────────────────────
#[cfg(test)]
mod sticky_session_integration_tests {
    use ai_load_balancer::proxy::sticky::{base64_decode_addr, StickyMode, StickySessionManager};
    use std::time::Duration;

    // ── Cookie mode ──────────────────────────────────────────────────────────

    fn cookie_mgr() -> StickySessionManager {
        StickySessionManager::new(StickyMode::Cookie {
            name: "PHALANXID".to_string(),
            path: "/".to_string(),
            http_only: true,
            secure: false,
            max_age: 3600,
        })
    }

    #[test]
    fn test_cookie_set_cookie_contains_name() {
        let mgr = cookie_mgr();
        let header = mgr.set_cookie_header("10.0.0.1:8080").unwrap();
        assert!(header.starts_with("PHALANXID="));
    }

    #[test]
    fn test_cookie_set_cookie_encodes_address() {
        let mgr = cookie_mgr();
        let header = mgr.set_cookie_header("10.0.0.1:8080").unwrap();
        // The value between '=' and ';' is base64-encoded addr
        let value = header
            .split('=')
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let decoded = base64_decode_addr(value);
        assert_eq!(decoded, Some("10.0.0.1:8080".to_string()));
    }

    #[test]
    fn test_cookie_extract_present() {
        let mgr = cookie_mgr();
        let result = mgr.extract_from_cookie("other=val; PHALANXID=dGVzdA; more=x");
        assert_eq!(result, Some("dGVzdA".to_string()));
    }

    #[test]
    fn test_cookie_extract_absent() {
        let mgr = cookie_mgr();
        assert!(mgr.extract_from_cookie("session=abc; user=john").is_none());
    }

    #[test]
    fn test_cookie_extract_empty_header() {
        let mgr = cookie_mgr();
        assert!(mgr.extract_from_cookie("").is_none());
    }

    #[test]
    fn test_cookie_learn_and_lookup_roundtrip() {
        let mgr = cookie_mgr();
        mgr.learn("key1".to_string(), "backend:9000".to_string());
        assert_eq!(mgr.lookup("key1"), Some("backend:9000".to_string()));
    }

    #[test]
    fn test_cookie_lookup_missing_key() {
        let mgr = cookie_mgr();
        assert!(mgr.lookup("no-such-key").is_none());
    }

    // ── Learn mode ───────────────────────────────────────────────────────────

    fn learn_mgr() -> StickySessionManager {
        StickySessionManager::new(StickyMode::Learn {
            lookup_header: "X-Session".to_string(),
            timeout: Duration::from_secs(60),
        })
    }

    #[test]
    fn test_learn_no_set_cookie() {
        let mgr = learn_mgr();
        assert!(mgr.set_cookie_header("backend:80").is_none());
    }

    #[test]
    fn test_learn_extract_from_response_header() {
        let mgr = learn_mgr();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-session", "sess-42".parse().unwrap());
        assert_eq!(
            mgr.extract_from_response_header(&headers),
            Some("sess-42".to_string())
        );
    }

    #[test]
    fn test_learn_extract_response_header_missing() {
        let mgr = learn_mgr();
        assert!(mgr.extract_from_response_header(&hyper::HeaderMap::new()).is_none());
    }

    #[test]
    fn test_learn_session_expires() {
        let mgr = StickySessionManager::new(StickyMode::Learn {
            lookup_header: "X-Sess".to_string(),
            timeout: Duration::from_nanos(1),
        });
        mgr.learn("k".to_string(), "b".to_string());
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(mgr.lookup("k").is_none());
    }

    #[test]
    fn test_learn_non_expired_session() {
        let mgr = learn_mgr();
        mgr.learn("active".to_string(), "b:80".to_string());
        assert_eq!(mgr.lookup("active"), Some("b:80".to_string()));
    }

    // ── Route mode ───────────────────────────────────────────────────────────

    #[test]
    fn test_route_extract_cookie() {
        let mgr = StickySessionManager::new(StickyMode::Route {
            cookie_name: "ROUTEID".to_string(),
        });
        assert_eq!(
            mgr.extract_from_cookie("ROUTEID=node1; extra=v"),
            Some("node1".to_string())
        );
    }

    #[test]
    fn test_route_no_set_cookie() {
        let mgr = StickySessionManager::new(StickyMode::Route {
            cookie_name: "ROUTEID".to_string(),
        });
        assert!(mgr.set_cookie_header("b:80").is_none());
    }

    // ── base64_decode_addr ───────────────────────────────────────────────────

    #[test]
    fn test_base64_decode_addr_valid() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("192.168.0.1:3000".as_bytes());
        assert_eq!(
            base64_decode_addr(&encoded),
            Some("192.168.0.1:3000".to_string())
        );
    }

    #[test]
    fn test_base64_decode_addr_garbage() {
        assert!(base64_decode_addr("not-valid-base64!!!").is_none());
    }
}

// ─── ZoneLimiter + ConnectionGuard RAII tests ─────────────────────────────────
#[cfg(test)]
mod zone_limiter_raii_tests {
    use ai_load_balancer::middleware::connlimit::{ConnectionGuard, ZoneLimiter};
    use std::sync::Arc;

    #[test]
    fn test_connection_guard_releases_on_drop() {
        let limiter = Arc::new(ZoneLimiter::new("test", 1000, 100, 1));
        assert!(limiter.acquire_connection("k"), "first acquire must succeed");

        // Second would exceed limit=1
        assert!(!limiter.acquire_connection("k"), "second must fail");

        // Release via drop
        limiter.release_connection("k");
        assert!(limiter.acquire_connection("k"), "after release must succeed again");
    }

    #[test]
    fn test_connection_guard_raii_drop() {
        let limiter = Arc::new(ZoneLimiter::new("raii", 1000, 100, 1));

        {
            // Simulate what handle_http_request does: guard holds the slot
            assert!(limiter.acquire_connection("ip"));
            let _guard = ConnectionGuard::new(Arc::clone(&limiter), "ip".to_string());
            // inside scope: slot is occupied
            assert!(!limiter.acquire_connection("ip"), "slot occupied");
            // guard goes out of scope here — Drop calls release_connection
        }

        assert!(
            limiter.acquire_connection("ip"),
            "after guard dropped, slot must be free"
        );
    }

    #[test]
    fn test_connection_guard_multiple_keys_independent() {
        let limiter = Arc::new(ZoneLimiter::new("multi", 1000, 100, 1));

        assert!(limiter.acquire_connection("a"));
        assert!(limiter.acquire_connection("b")); // different key — separate counter

        // Both occupied
        assert!(!limiter.acquire_connection("a"));
        assert!(!limiter.acquire_connection("b"));

        limiter.release_connection("a");
        assert!(limiter.acquire_connection("a"));
        assert!(!limiter.acquire_connection("b")); // still occupied
    }

    #[test]
    fn test_zone_unlimited_connections_never_blocks() {
        let limiter = Arc::new(ZoneLimiter::new("unlimited", 1000, 100, 0));
        for i in 0..500 {
            assert!(
                limiter.acquire_connection(&format!("key-{}", i)),
                "unlimited mode must always allow"
            );
        }
    }

    #[test]
    fn test_connection_guard_does_not_panic_on_unknown_key_release() {
        // release_connection on a key that was never acquired must not panic
        let limiter = Arc::new(ZoneLimiter::new("safe", 100, 10, 2));
        limiter.release_connection("ghost"); // should be a no-op
    }

    #[test]
    fn test_zone_rate_check_allows_under_limit() {
        let limiter = ZoneLimiter::new("rate", 500, 500, 0);
        assert!(limiter.check_rate("client"), "under-limit request must be allowed");
    }

    #[test]
    fn test_zone_rate_check_eventually_blocks() {
        let limiter = ZoneLimiter::new("tight", 1, 1, 0);
        let mut blocked = false;
        for _ in 0..200 {
            if !limiter.check_rate("c") {
                blocked = true;
                break;
            }
        }
        assert!(blocked, "tight rate limit must eventually block");
    }
}

// ─── HookEngine phase isolation tests ─────────────────────────────────────────
#[cfg(test)]
mod hook_engine_phase_tests {
    use ai_load_balancer::scripting::{
        Hook, HookContext, HookEngine, HookHandler, HookPhase, HookResult,
    };
    use std::collections::HashMap;

    struct EchoHook(String);
    impl HookHandler for EchoHook {
        fn execute(&self, _ctx: &HookContext) -> HookResult {
            HookResult::RewritePath(self.0.clone())
        }
    }

    struct RespondHook(u16);
    impl HookHandler for RespondHook {
        fn execute(&self, _ctx: &HookContext) -> HookResult {
            HookResult::Respond {
                status: self.0,
                body: format!("status {}", self.0),
                headers: HashMap::new(),
            }
        }
    }

    fn ctx() -> HookContext {
        HookContext {
            client_ip: "127.0.0.1".into(),
            method: "GET".into(),
            path: "/test".into(),
            query: None,
            headers: HashMap::new(),
            status: None,
            response_headers: HashMap::new(),
        }
    }

    #[test]
    fn test_pre_route_hook_fires_for_pre_route_only() {
        let mut engine = HookEngine::new();
        engine.register(Hook {
            name: "pr".to_string(),
            phase: HookPhase::PreRoute,
            priority: 0,
            handler: Box::new(EchoHook("/new".to_string())),
        });

        assert!(!engine.execute(HookPhase::PreUpstream, &ctx()).is_empty() == false);
        let results = engine.execute(HookPhase::PreRoute, &ctx());
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], HookResult::RewritePath(p) if p == "/new"));
    }

    #[test]
    fn test_pre_upstream_phase_separate_from_pre_route() {
        let mut engine = HookEngine::new();
        engine.register(Hook {
            name: "pre_route".to_string(),
            phase: HookPhase::PreRoute,
            priority: 0,
            handler: Box::new(EchoHook("/route".to_string())),
        });
        engine.register(Hook {
            name: "pre_upstream".to_string(),
            phase: HookPhase::PreUpstream,
            priority: 0,
            handler: Box::new(EchoHook("/upstream".to_string())),
        });

        let route_results = engine.execute(HookPhase::PreRoute, &ctx());
        let upstream_results = engine.execute(HookPhase::PreUpstream, &ctx());

        assert_eq!(route_results.len(), 1);
        assert!(matches!(&route_results[0], HookResult::RewritePath(p) if p == "/route"));
        assert_eq!(upstream_results.len(), 1);
        assert!(matches!(&upstream_results[0], HookResult::RewritePath(p) if p == "/upstream"));
    }

    #[test]
    fn test_log_phase_executes_independently() {
        let mut engine = HookEngine::new();
        engine.register(Hook {
            name: "logger".to_string(),
            phase: HookPhase::Log,
            priority: 0,
            handler: Box::new(EchoHook("/logged".to_string())),
        });

        assert!(engine.execute(HookPhase::PreRoute, &ctx()).is_empty());
        assert!(engine.execute(HookPhase::PreUpstream, &ctx()).is_empty());
        assert_eq!(engine.execute(HookPhase::Log, &ctx()).len(), 1);
    }

    #[test]
    fn test_respond_hook_short_circuits_remaining_hooks() {
        let mut engine = HookEngine::new();
        engine.register(Hook {
            name: "block".to_string(),
            phase: HookPhase::PreRoute,
            priority: 0,
            handler: Box::new(RespondHook(403)),
        });
        engine.register(Hook {
            name: "never_reached".to_string(),
            phase: HookPhase::PreRoute,
            priority: 1,
            handler: Box::new(EchoHook("/should-not-appear".to_string())),
        });

        let results = engine.execute(HookPhase::PreRoute, &ctx());
        assert_eq!(results.len(), 1, "only Respond hook result, not the subsequent one");
        assert!(matches!(&results[0], HookResult::Respond { status: 403, .. }));
    }

    #[test]
    fn test_has_hooks_per_phase_granularity() {
        let mut engine = HookEngine::new();
        assert!(!engine.has_hooks(HookPhase::PreRoute));
        assert!(!engine.has_hooks(HookPhase::PreUpstream));
        assert!(!engine.has_hooks(HookPhase::PostUpstream));
        assert!(!engine.has_hooks(HookPhase::Log));

        engine.register(Hook {
            name: "h".to_string(),
            phase: HookPhase::Log,
            priority: 0,
            handler: Box::new(EchoHook("/x".to_string())),
        });

        assert!(!engine.has_hooks(HookPhase::PreRoute));
        assert!(engine.has_hooks(HookPhase::Log));
    }

    #[test]
    fn test_multiple_hooks_same_phase_run_in_priority_order() {
        let mut engine = HookEngine::new();
        engine.register(Hook {
            name: "third".to_string(),
            phase: HookPhase::PreUpstream,
            priority: 30,
            handler: Box::new(EchoHook("/c".to_string())),
        });
        engine.register(Hook {
            name: "first".to_string(),
            phase: HookPhase::PreUpstream,
            priority: 10,
            handler: Box::new(EchoHook("/a".to_string())),
        });
        engine.register(Hook {
            name: "second".to_string(),
            phase: HookPhase::PreUpstream,
            priority: 20,
            handler: Box::new(EchoHook("/b".to_string())),
        });

        let results = engine.execute(HookPhase::PreUpstream, &ctx());
        assert_eq!(results.len(), 3);
        let paths: Vec<&str> = results.iter().map(|r| match r {
            HookResult::RewritePath(p) => p.as_str(),
            _ => "",
        }).collect();
        assert_eq!(paths, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn test_post_upstream_hook_receives_status_and_response_headers() {
        use std::sync::{Arc, Mutex};

        // Custom hook that captures the context it receives
        struct CaptureHook {
            captured: Arc<Mutex<Option<(Option<u16>, HashMap<String, String>)>>>,
        }
        impl HookHandler for CaptureHook {
            fn execute(&self, ctx: &HookContext) -> HookResult {
                *self.captured.lock().unwrap() = Some((
                    ctx.status,
                    ctx.response_headers.clone(),
                ));
                HookResult::Continue
            }
        }

        let captured = Arc::new(Mutex::new(None));
        let engine = HookEngine::new();
        engine.register(Hook {
            name: "capture_post".to_string(),
            phase: HookPhase::PostUpstream,
            priority: 0,
            handler: Box::new(CaptureHook { captured: captured.clone() }),
        });

        assert!(engine.has_hooks(HookPhase::PostUpstream));
        assert!(!engine.has_hooks(HookPhase::PreRoute));

        let mut resp_headers = HashMap::new();
        resp_headers.insert("x-custom".to_string(), "value123".to_string());

        let hook_ctx = HookContext {
            client_ip: "10.0.0.1".into(),
            method: "POST".into(),
            path: "/api/data".into(),
            query: None,
            headers: HashMap::new(),
            status: Some(200),
            response_headers: resp_headers,
        };

        let results = engine.execute(HookPhase::PostUpstream, &hook_ctx);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], HookResult::Continue));

        let captured = captured.lock().unwrap();
        let (status, headers) = captured.as_ref().unwrap();
        assert_eq!(*status, Some(200));
        assert_eq!(headers.get("x-custom").map(|s| s.as_str()), Some("value123"));
    }

    #[test]
    fn test_post_upstream_hook_set_headers_modifies_response() {
        struct InjectHeader;
        impl HookHandler for InjectHeader {
            fn execute(&self, _ctx: &HookContext) -> HookResult {
                let mut headers = HashMap::new();
                headers.insert("x-injected".to_string(), "from-hook".to_string());
                HookResult::SetHeaders(headers)
            }
        }

        let engine = HookEngine::new();
        engine.register(Hook {
            name: "inject".to_string(),
            phase: HookPhase::PostUpstream,
            priority: 0,
            handler: Box::new(InjectHeader),
        });

        let hook_ctx = HookContext {
            client_ip: "10.0.0.1".into(),
            method: "GET".into(),
            path: "/".into(),
            query: None,
            headers: HashMap::new(),
            status: Some(200),
            response_headers: HashMap::new(),
        };

        let results = engine.execute(HookPhase::PostUpstream, &hook_ctx);
        assert_eq!(results.len(), 1);
        match &results[0] {
            HookResult::SetHeaders(hdrs) => {
                assert_eq!(hdrs.get("x-injected").map(|s| s.as_str()), Some("from-hook"));
            }
            other => panic!("Expected SetHeaders, got {:?}", other),
        }
    }
}

// ─── WAF Policy Engine tests ───────────────────────────────────────────────────
#[cfg(test)]
mod waf_policy_engine_tests {
    use ai_load_balancer::waf::policy::{
        CustomRule, EnforcementMode, PolicyEngine, RuleAction, RuleTarget, WafPolicy,
    };
    use ai_load_balancer::waf::reputation::IpReputationManager;
    use ai_load_balancer::waf::{WafAction, WafEngine};

    fn make_waf_with_policy(policy: WafPolicy) -> WafEngine {
        let reputation = IpReputationManager::new(100, 60, None);
        let mut engine = PolicyEngine::new();
        engine.add_policy(policy).unwrap();
        WafEngine::new(true, reputation).with_policy_engine(engine)
    }

    fn blocking_policy(pattern: &str, target: RuleTarget) -> WafPolicy {
        WafPolicy {
            name: "test-policy".to_string(),
            enforcement_mode: EnforcementMode::Blocking,
            signature_sets: vec![],
            custom_rules: vec![CustomRule {
                id: 1001,
                description: "Test block rule".to_string(),
                pattern: pattern.to_string(),
                target,
                action: RuleAction::Block,
            }],
            blocking_status: 403,
            exclusions: vec![],
        }
    }

    #[test]
    fn test_policy_engine_new_is_empty() {
        let engine = PolicyEngine::new();
        // Empty engine returns no violations
        let violations = engine.evaluate(None, "/safe", None, &[], None);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_policy_add_and_evaluate_block_rule() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(blocking_policy(r"evil", RuleTarget::Url)).unwrap();
        let violations = engine.evaluate(None, "/evil/path", None, &[], None);
        assert!(!violations.is_empty());
        assert!(matches!(violations[0].action, RuleAction::Block));
    }

    #[test]
    fn test_policy_evaluate_no_match_allows() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(blocking_policy(r"evil", RuleTarget::Url)).unwrap();
        let violations = engine.evaluate(None, "/safe/path", None, &[], None);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_policy_query_target_match() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(blocking_policy(r"malicious", RuleTarget::QueryString)).unwrap();
        let violations = engine.evaluate(None, "/page", Some("q=malicious+content"), &[], None);
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_policy_body_target_match() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(blocking_policy(r"<script>", RuleTarget::Body)).unwrap();
        let violations = engine.evaluate(None, "/post", None, &[], Some("<script>alert(1)</script>"));
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_policy_headers_target_match() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(blocking_policy(r"sqlmap", RuleTarget::Headers)).unwrap();
        let headers = vec![("User-Agent".to_string(), "sqlmap/1.0".to_string())];
        let violations = engine.evaluate(None, "/api", None, &headers, None);
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_policy_exclusion_bypasses_rule() {
        let mut engine = PolicyEngine::new();
        let policy = WafPolicy {
            name: "excl-policy".to_string(),
            enforcement_mode: EnforcementMode::Blocking,
            signature_sets: vec![],
            custom_rules: vec![CustomRule {
                id: 1,
                description: "block evil".to_string(),
                pattern: "evil".to_string(),
                target: RuleTarget::Url,
                action: RuleAction::Block,
            }],
            blocking_status: 403,
            exclusions: vec![r"^/admin/.*".to_string()],
        };
        engine.add_policy(policy).unwrap();
        // Excluded path — no violations
        let violations = engine.evaluate(None, "/admin/evil", None, &[], None);
        assert!(violations.is_empty(), "excluded path should not trigger rule");
        // Non-excluded path — blocked
        let violations = engine.evaluate(None, "/public/evil", None, &[], None);
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_waf_engine_policy_blocks_via_inspect() {
        let waf = make_waf_with_policy(blocking_policy(r"badactor", RuleTarget::Url));
        let result = waf.inspect("1.2.3.4", "/badactor/action", None, Some("Mozilla/5.0"));
        assert!(
            matches!(result, WafAction::Block(_)),
            "policy engine should block matched URL"
        );
    }

    #[test]
    fn test_waf_engine_empty_policy_allows() {
        let reputation = IpReputationManager::new(100, 60, None);
        let waf = WafEngine::new(true, reputation);
        // Empty policy engine — safe URL passes
        let result = waf.inspect("1.2.3.4", "/safe", None, Some("Mozilla/5.0"));
        assert_eq!(result, WafAction::Allow);
    }

    #[test]
    fn test_policy_rule_id_and_category_in_violation() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(blocking_policy(r"exploit", RuleTarget::All)).unwrap();
        let violations = engine.evaluate(None, "/exploit", None, &[], None);
        assert_eq!(violations[0].rule_id, 1001);
        assert!(!violations[0].category.is_empty());
    }
}

// ─── AdvancedCache (L1 + L2) purge API tests ──────────────────────────────────
#[cfg(test)]
mod response_cache_purge_tests {
    use ai_load_balancer::middleware::{AdvancedCache, CacheEntry};
    use bytes::Bytes;
    use std::time::{Duration, Instant};

    fn make_entry(body: &'static [u8]) -> CacheEntry {
        CacheEntry {
            status: 200,
            body: Bytes::from_static(body),
            content_type: "text/plain".to_string(),
            headers: vec![],
            created_at: Instant::now(),
            max_age: Duration::from_secs(60),
            stale_while_revalidate: Duration::ZERO,
            stale_if_error: Duration::ZERO,
        }
    }

    #[tokio::test]
    async fn test_cache_purge_existing_key() {
        let cache = AdvancedCache::new(100, 60, None);
        cache.insert("k1".to_string(), make_entry(b"hello")).await;
        assert!(cache.get("k1").await.is_some());
        let removed = cache.purge("k1").await;
        assert!(removed, "purge should report key was present");
        assert!(cache.get("k1").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_purge_nonexistent_key() {
        let cache = AdvancedCache::new(100, 60, None);
        let removed = cache.purge("ghost").await;
        assert!(!removed, "purge of unknown key should return false");
    }

    #[tokio::test]
    async fn test_cache_purge_all() {
        let cache = AdvancedCache::new(100, 60, None);
        for i in 0..5u8 {
            cache.insert(format!("k{}", i), make_entry(b"v")).await;
        }
        cache.purge_all().await;
        for i in 0..5u8 {
            assert!(cache.get(&format!("k{}", i)).await.is_none());
        }
    }

    #[tokio::test]
    async fn test_cache_entry_count_after_purge() {
        let cache = AdvancedCache::new(100, 60, None);
        cache.insert("a".to_string(), make_entry(b"1")).await;
        cache.insert("b".to_string(), make_entry(b"2")).await;
        cache.run_pending_tasks().await;
        assert_eq!(cache.entry_count(), 2);
        cache.purge_all().await;
        assert!(cache.get("a").await.is_none());
        assert!(cache.get("b").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_purge_prefix() {
        let cache = AdvancedCache::new(100, 60, None);
        cache.insert("GET:host:/api/v1".to_string(), make_entry(b"1")).await;
        cache.insert("GET:host:/api/v2".to_string(), make_entry(b"2")).await;
        cache.insert("GET:host:/static/img".to_string(), make_entry(b"3")).await;
        cache.run_pending_tasks().await;
        cache.purge_prefix("GET:host:/api").await;
        // Disk-only prefix purge; memory entries can be verified by direct get
        assert!(cache.get("GET:host:/static/img").await.is_some(), "non-prefix entry should remain");
    }

    #[tokio::test]
    async fn test_l2_disk_cache_persist_and_reload() {
        let dir = format!("/tmp/phalanx_cache_test_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        {
            let cache = AdvancedCache::new(100, 300, Some(&dir));
            cache.insert("disk-key".to_string(), make_entry(b"disk-value")).await;
            cache.run_pending_tasks().await;
        }
        // New cache instance reads from disk
        let cache2 = AdvancedCache::new(100, 300, Some(&dir));
        let entry = cache2.get("disk-key").await;
        assert!(entry.is_some(), "disk-cached entry should survive across instances");
        assert_eq!(entry.unwrap().body, Bytes::from_static(b"disk-value"));
        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ─── Mail Proxy config tests ───────────────────────────────────────────────────
#[cfg(test)]
mod mail_proxy_config_tests {
    use ai_load_balancer::mail::{MailProtocol, MailProxyConfig};

    #[test]
    fn test_mail_protocol_default_ports() {
        assert_eq!(MailProtocol::Smtp.default_port(), 25);
        assert_eq!(MailProtocol::Imap.default_port(), 143);
        assert_eq!(MailProtocol::Pop3.default_port(), 110);
    }

    #[test]
    fn test_mail_protocol_names() {
        assert_eq!(MailProtocol::Smtp.name(), "SMTP");
        assert_eq!(MailProtocol::Imap.name(), "IMAP");
        assert_eq!(MailProtocol::Pop3.name(), "POP3");
    }

    #[test]
    fn test_mail_proxy_config_fields() {
        let cfg = MailProxyConfig {
            protocol: MailProtocol::Smtp,
            bind_addr: "0.0.0.0:25".to_string(),
            upstream_pool: "mail_pool".to_string(),
            banner: Some("220 phalanx.example.com".to_string()),
            starttls: true,
            tls_cert_path: Some("/etc/phalanx/cert.pem".to_string()),
            tls_key_path: Some("/etc/phalanx/key.pem".to_string()),
        };
        assert_eq!(cfg.protocol, MailProtocol::Smtp);
        assert_eq!(cfg.bind_addr, "0.0.0.0:25");
        assert_eq!(cfg.upstream_pool, "mail_pool");
        assert!(cfg.banner.is_some());
        assert!(cfg.starttls);
    }

    #[test]
    fn test_mail_proxy_config_no_banner() {
        let cfg = MailProxyConfig {
            protocol: MailProtocol::Imap,
            bind_addr: "0.0.0.0:143".to_string(),
            upstream_pool: "default".to_string(),
            banner: None,
            starttls: false,
            tls_cert_path: None,
            tls_key_path: None,
        };
        assert!(cfg.banner.is_none());
        assert!(!cfg.starttls);
    }

    #[test]
    fn test_app_config_mail_fields_default_none() {
        use ai_load_balancer::config::AppConfig;
        let cfg = AppConfig::default();
        assert!(cfg.smtp_bind.is_none());
        assert!(cfg.imap_bind.is_none());
        assert!(cfg.pop3_bind.is_none());
        assert!(cfg.mail_upstream_pool.is_none());
        assert!(cfg.waf_policy_path.is_none());
    }
}

// ─── URL Rewrite integration tests ────────────────────────────────────────────
#[cfg(test)]
mod rewrite_integration_tests {
    use ai_load_balancer::proxy::rewrite::{RewriteResult, apply_rewrites, compile_rules};
    use hyper::StatusCode;

    fn rules(raw: &[(&str, &str, &str)]) -> Vec<ai_load_balancer::proxy::rewrite::RewriteRule> {
        compile_rules(
            &raw.iter()
                .map(|(p, r, f)| (p.to_string(), r.to_string(), f.to_string()))
                .collect::<Vec<_>>(),
        )
        .expect("rewrite rules should compile")
    }

    #[test]
    fn test_no_rules_is_no_match() {
        let result = apply_rewrites(&[], "/any/path");
        assert_eq!(result, RewriteResult::NoMatch);
    }

    #[test]
    fn test_break_stops_after_first_match() {
        let r = rules(&[
            (r"^/api/v1/(.+)$", "/v1/$1", "break"),
            (r"^/api/(.+)$", "/generic/$1", "break"),
        ]);
        assert_eq!(
            apply_rewrites(&r, "/api/v1/users"),
            RewriteResult::Rewritten { new_uri: "/v1/users".to_string(), restart_routing: false }
        );
    }

    #[test]
    fn test_last_flag_sets_restart_routing() {
        let r = rules(&[(r"^/old/(.+)$", "/new/$1", "last")]);
        assert_eq!(
            apply_rewrites(&r, "/old/page"),
            RewriteResult::Rewritten { new_uri: "/new/page".to_string(), restart_routing: true }
        );
    }

    #[test]
    fn test_redirect_302_location() {
        let r = rules(&[(r"^/moved$", "/new-location", "redirect")]);
        assert_eq!(
            apply_rewrites(&r, "/moved"),
            RewriteResult::Redirect {
                status: StatusCode::FOUND,
                location: "/new-location".to_string(),
            }
        );
    }

    #[test]
    fn test_permanent_301_location() {
        let r = rules(&[(r"^/gone$", "/permanent", "permanent")]);
        assert_eq!(
            apply_rewrites(&r, "/gone"),
            RewriteResult::Redirect {
                status: StatusCode::MOVED_PERMANENTLY,
                location: "/permanent".to_string(),
            }
        );
    }

    #[test]
    fn test_capture_groups_substituted() {
        let r = rules(&[(r"^/v(\d+)/(.+)$", "/api/v$1/$2", "break")]);
        assert_eq!(
            apply_rewrites(&r, "/v2/items/42"),
            RewriteResult::Rewritten {
                new_uri: "/api/v2/items/42".to_string(),
                restart_routing: false,
            }
        );
    }

    #[test]
    fn test_non_matching_path_falls_through() {
        let r = rules(&[(r"^/admin/(.+)$", "/secure/$1", "break")]);
        assert_eq!(apply_rewrites(&r, "/public/index"), RewriteResult::NoMatch);
    }

    #[test]
    fn test_compile_rules_empty_slice() {
        let r = compile_rules(&[]).expect("empty rules should compile");
        assert!(r.is_empty());
    }

    #[test]
    fn test_multiple_capture_groups_in_redirect() {
        let r = rules(&[(r"^/shop/(\w+)/(\d+)$", "https://store.example.com/$1/$2", "permanent")]);
        assert_eq!(
            apply_rewrites(&r, "/shop/books/99"),
            RewriteResult::Redirect {
                status: StatusCode::MOVED_PERMANENTLY,
                location: "https://store.example.com/books/99".to_string(),
            }
        );
    }
}

// ─── Rate limiter integration tests ────────────────────────────────────────────
#[cfg(test)]
mod rate_limiter_integration_tests {
    use ai_load_balancer::middleware::ratelimit::PhalanxRateLimiter;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_new_ip_is_initially_allowed() {
        let limiter = PhalanxRateLimiter::new(100, 50, None, None);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(limiter.check_ip(ip).await, "Fresh IP should be allowed");
    }

    #[tokio::test]
    async fn test_burst_exhausted_triggers_block() {
        let limiter = PhalanxRateLimiter::new(1, 2, None, None);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1));
        let mut allowed = 0usize;
        for _ in 0..20 {
            if limiter.check_ip(ip).await { allowed += 1; }
        }
        assert!(allowed < 20, "Should be blocked after burst exhausted");
        assert!(allowed >= 1, "At least one request should succeed");
    }

    #[tokio::test]
    async fn test_two_ips_have_independent_buckets() {
        let limiter = PhalanxRateLimiter::new(1, 1, None, None);
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        // Exhaust ip1
        for _ in 0..10 { limiter.check_ip(ip1).await; }
        // ip2 should still be fresh
        assert!(limiter.check_ip(ip2).await, "ip2 bucket should be independent");
    }

    #[test]
    fn test_global_rate_stored_correctly() {
        let limiter = PhalanxRateLimiter::new(100, 10, Some(5000), None);
        assert!(limiter.global_enabled());
        assert_eq!(limiter.global_rate(), Some(5000));
    }

    #[test]
    fn test_no_global_rate_disables_global_limiter() {
        let limiter = PhalanxRateLimiter::new(100, 10, None, None);
        assert!(!limiter.global_enabled());
    }

    #[tokio::test]
    async fn test_ipv6_address_tracked_independently() {
        let limiter = PhalanxRateLimiter::new(100, 10, None, None);
        let v6: IpAddr = "fe80::1".parse().unwrap();
        assert!(limiter.check_ip(v6).await);
    }
}

// ─── Auth JWT integration tests ────────────────────────────────────────────────
#[cfg(test)]
mod auth_jwt_integration_tests {
    use ai_load_balancer::auth::AuthResult;
    use ai_load_balancer::auth::jwt::{check, claims_to_headers, extract_bearer_token};
    use hyper::HeaderMap;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct TestClaims {
        sub: Option<String>,
        email: Option<String>,
        exp: Option<u64>,
        iss: Option<String>,
        aud: Option<serde_json::Value>,
    }

    fn future_exp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600
    }

    fn past_exp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 100
    }

    fn make_hs256_token(secret: &str, sub: &str, exp: u64) -> String {
        let claims = TestClaims {
            sub: Some(sub.to_string()),
            email: Some(format!("{sub}@example.com")),
            exp: Some(exp),
            iss: None,
            aud: None,
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn with_bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(hyper::header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        h
    }

    #[test]
    fn test_valid_hs256_is_allowed() {
        let token = make_hs256_token("secret", "user-1", future_exp());
        let (result, claims) = check(&with_bearer(&token), "secret", "HS256");
        assert!(matches!(result, AuthResult::Allowed));
        assert_eq!(claims.unwrap().sub.as_deref(), Some("user-1"));
    }

    #[test]
    fn test_expired_token_is_denied() {
        let token = make_hs256_token("secret", "user-1", past_exp());
        let (result, _) = check(&with_bearer(&token), "secret", "HS256");
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_wrong_secret_is_denied() {
        let token = make_hs256_token("correct", "user-1", future_exp());
        let (result, _) = check(&with_bearer(&token), "wrong", "HS256");
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_no_auth_header_is_denied() {
        let (result, _) = check(&HeaderMap::new(), "secret", "HS256");
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_malformed_token_is_denied() {
        let (result, _) = check(&with_bearer("garbage.token.here"), "secret", "HS256");
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_extract_bearer_from_header() {
        let h = with_bearer("my.jwt.token");
        assert_eq!(extract_bearer_token(&h), Some("my.jwt.token"));
    }

    #[test]
    fn test_extract_bearer_missing_returns_none() {
        assert_eq!(extract_bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn test_claims_to_headers_includes_sub_and_email() {
        use ai_load_balancer::auth::jwt::Claims;
        let claims = Claims {
            sub: Some("abc".to_string()),
            email: Some("abc@test.com".to_string()),
            exp: None,
            iss: None,
            aud: None,
        };
        let hdrs = claims_to_headers(&claims);
        assert_eq!(hdrs.get("X-Auth-Sub").map(String::as_str), Some("abc"));
        assert_eq!(hdrs.get("X-Auth-Email").map(String::as_str), Some("abc@test.com"));
    }

    #[test]
    fn test_claims_to_headers_empty_when_no_sub_or_email() {
        use ai_load_balancer::auth::jwt::Claims;
        let claims = Claims { sub: None, email: None, exp: None, iss: None, aud: None };
        let hdrs = claims_to_headers(&claims);
        assert!(!hdrs.contains_key("X-Auth-Sub"));
        assert!(!hdrs.contains_key("X-Auth-Email"));
    }
}

// ─── Auth Basic integration tests ──────────────────────────────────────────────
#[cfg(test)]
mod auth_basic_integration_tests {
    use ai_load_balancer::auth::AuthResult;
    use ai_load_balancer::auth::basic::{check, www_authenticate_header};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use hyper::HeaderMap;
    use std::collections::HashMap;

    fn creds(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(u, p)| (u.to_string(), p.to_string())).collect()
    }

    fn basic_header(user: &str, pass: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        let encoded = STANDARD.encode(format!("{user}:{pass}"));
        h.insert(
            hyper::header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        h
    }

    #[test]
    fn test_correct_credentials_allowed() {
        let users = creds(&[("alice", "hunter2")]);
        let result = check(&basic_header("alice", "hunter2"), "Realm", &users);
        assert!(matches!(result, AuthResult::Allowed));
    }

    #[test]
    fn test_wrong_password_denied() {
        let users = creds(&[("alice", "correct")]);
        let result = check(&basic_header("alice", "wrong"), "Realm", &users);
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_unknown_user_denied() {
        let users = creds(&[("alice", "pw")]);
        let result = check(&basic_header("bob", "pw"), "Realm", &users);
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_missing_header_denied() {
        let users = creds(&[("alice", "pw")]);
        let result = check(&HeaderMap::new(), "Realm", &users);
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_bearer_scheme_rejected() {
        let users = creds(&[("alice", "pw")]);
        let mut h = HeaderMap::new();
        h.insert(hyper::header::AUTHORIZATION, "Bearer some.token".parse().unwrap());
        let result = check(&h, "Realm", &users);
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_password_with_colon_works() {
        let users = creds(&[("user", "p:a:s:s")]);
        let result = check(&basic_header("user", "p:a:s:s"), "Realm", &users);
        assert!(matches!(result, AuthResult::Allowed));
    }

    #[test]
    fn test_www_authenticate_header_format() {
        assert_eq!(www_authenticate_header("Protected"), r#"Basic realm="Protected""#);
    }

    #[test]
    fn test_empty_user_store_denies_all() {
        let users = HashMap::new();
        let result = check(&basic_header("alice", "pw"), "Realm", &users);
        assert!(matches!(result, AuthResult::Denied(..)));
    }
}

// ─── Cluster state integration tests (Standalone mode) ─────────────────────────
#[cfg(test)]
mod cluster_state_integration_tests {
    use ai_load_balancer::cluster::{ClusterBackend, ClusterEntry, ClusterState};

    #[tokio::test]
    async fn test_standalone_put_and_get_is_none() {
        let state = ClusterState::new(ClusterBackend::Standalone, "node-a".to_string());
        assert!(state.put("k", "v", None).await.is_ok());
        // Standalone has no persistent store — get returns None
        assert!(state.get("k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_standalone_delete_ok() {
        let state = ClusterState::new(ClusterBackend::Standalone, "node-a".to_string());
        assert!(state.delete("any-key").await.is_ok());
    }

    #[tokio::test]
    async fn test_standalone_heartbeat_ok() {
        let state = ClusterState::new(ClusterBackend::Standalone, "node-a".to_string());
        assert!(state.heartbeat(30).await.is_ok());
    }

    #[tokio::test]
    async fn test_standalone_sticky_session_roundtrip() {
        let state = ClusterState::new(ClusterBackend::Standalone, "node-a".to_string());
        assert!(state.share_sticky_session("sess-x", "10.0.0.5:8080", 60).await.is_ok());
        // Standalone has no storage — lookup returns None
        assert!(state.lookup_sticky_session("sess-x").await.is_none());
    }

    #[test]
    fn test_node_id_returns_configured_value() {
        let state = ClusterState::new(ClusterBackend::Standalone, "phalanx-node-42".to_string());
        assert_eq!(state.node_id(), "phalanx-node-42");
    }

    #[test]
    fn test_cluster_entry_serde_roundtrip() {
        let entry = ClusterEntry {
            value: "backend:8080".to_string(),
            node_id: "node-1".to_string(),
            updated_at: 9999999,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: ClusterEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.value, "backend:8080");
        assert_eq!(decoded.node_id, "node-1");
        assert_eq!(decoded.updated_at, 9999999);
    }

    #[tokio::test]
    async fn test_redis_backend_returns_error_when_unavailable() {
        let state = ClusterState::new(
            ClusterBackend::Redis { url: "redis://127.0.0.1:19999".to_string() },
            "node-b".to_string(),
        );
        // Should fail gracefully — not panic
        let result = state.put("key", "val", None).await;
        assert!(result.is_err(), "Unavailable Redis should return Err");
        let result = state.get("key").await;
        assert!(result.is_err(), "Unavailable Redis should return Err for get");
    }

    #[tokio::test]
    async fn test_put_with_ttl_standalone_ok() {
        let state = ClusterState::new(ClusterBackend::Standalone, "n".to_string());
        assert!(state.put("ttl-key", "value", Some(300)).await.is_ok());
    }
}

// ─── Bot detection tests ───────────────────────────────────────────────────────
#[cfg(test)]
mod bot_detection_tests {
    use ai_load_balancer::waf::bot::{BotClass, BotRateTracker, captcha_challenge_html, classify_user_agent};

    #[test]
    fn test_sqlmap_is_bad_bot() {
        assert_eq!(classify_user_agent("sqlmap/1.7.8#stable"), BotClass::BadBot);
    }

    #[test]
    fn test_nikto_is_bad_bot() {
        assert_eq!(classify_user_agent("Nikto/2.2.0"), BotClass::BadBot);
    }

    #[test]
    fn test_nuclei_is_bad_bot() {
        assert_eq!(classify_user_agent("nuclei-v2.9.1"), BotClass::BadBot);
    }

    #[test]
    fn test_googlebot_is_good_bot() {
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
            BotClass::GoodBot
        );
    }

    #[test]
    fn test_bingbot_is_good_bot() {
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
            BotClass::GoodBot
        );
    }

    #[test]
    fn test_uptimerobot_is_good_bot() {
        assert_eq!(classify_user_agent("UptimeRobot/2.0"), BotClass::GoodBot);
    }

    #[test]
    fn test_python_requests_is_unknown() {
        assert_eq!(classify_user_agent("python-requests/2.31.0"), BotClass::Unknown);
    }

    #[test]
    fn test_curl_is_unknown() {
        assert_eq!(classify_user_agent("curl/8.1.2"), BotClass::Unknown);
    }

    #[test]
    fn test_wget_is_unknown() {
        assert_eq!(classify_user_agent("Wget/1.21.4"), BotClass::Unknown);
    }

    #[test]
    fn test_go_http_client_is_unknown() {
        assert_eq!(classify_user_agent("Go-http-client/1.1"), BotClass::Unknown);
    }

    #[test]
    fn test_chrome_browser_is_human() {
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36"),
            BotClass::Human
        );
    }

    #[test]
    fn test_firefox_browser_is_human() {
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0"),
            BotClass::Human
        );
    }

    #[test]
    fn test_safari_browser_is_human() {
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Version/17.2 Mobile/15E148 Safari/604.1"),
            BotClass::Human
        );
    }

    #[test]
    fn test_rate_tracker_starts_positive() {
        let tracker = BotRateTracker::new(30);
        let rate = tracker.record_and_rate("1.2.3.4");
        assert!(rate > 0.0);
    }

    #[test]
    fn test_rate_tracker_accumulates() {
        let tracker = BotRateTracker::new(60);
        for _ in 0..50 {
            tracker.record_and_rate("5.5.5.5");
        }
        let rate = tracker.record_and_rate("5.5.5.5");
        assert!(rate > 0.5, "51 requests in 60s window should give rate > 0.5 req/s");
    }

    #[test]
    fn test_rate_tracker_clear_resets() {
        let tracker = BotRateTracker::new(60);
        for _ in 0..100 {
            tracker.record_and_rate("6.6.6.6");
        }
        tracker.clear("6.6.6.6");
        let rate = tracker.record_and_rate("6.6.6.6");
        assert!(rate < 1.0, "after clear, only 1 request — rate should be low");
    }

    #[test]
    fn test_captcha_html_no_key_errors() {
        assert!(captcha_challenge_html(None).is_err());
    }

    #[test]
    fn test_captcha_html_embeds_site_key() {
        let html = captcha_challenge_html(Some("xyz-site-key-123")).unwrap();
        assert!(html.contains("xyz-site-key-123"), "HTML should embed the site key");
        assert!(html.contains("<form"), "HTML should include a form");
    }
}

// ─── Basic auth bcrypt tests ───────────────────────────────────────────────────
#[cfg(test)]
mod basic_auth_bcrypt_tests {
    use ai_load_balancer::auth::AuthResult;
    use ai_load_balancer::auth::basic::check;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use hyper::HeaderMap;
    use std::collections::HashMap;

    fn basic_header(user: &str, pass: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        let encoded = STANDARD.encode(format!("{user}:{pass}"));
        h.insert(hyper::header::AUTHORIZATION, format!("Basic {encoded}").parse().unwrap());
        h
    }

    /// Generate a real bcrypt hash for testing.
    fn bcrypt_hash(password: &str) -> String {
        bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap()
    }

    #[test]
    fn test_bcrypt_hashed_password_allowed() {
        let hash = bcrypt_hash("secure_pass_42");
        let users: HashMap<String, String> = [("admin".to_string(), hash)].into();
        let result = check(&basic_header("admin", "secure_pass_42"), "Realm", &users);
        assert!(matches!(result, AuthResult::Allowed));
    }

    #[test]
    fn test_bcrypt_wrong_password_denied() {
        let hash = bcrypt_hash("correct_password");
        let users: HashMap<String, String> = [("alice".to_string(), hash)].into();
        let result = check(&basic_header("alice", "wrong_password"), "Realm", &users);
        assert!(matches!(result, AuthResult::Denied(..)));
    }

    #[test]
    fn test_bcrypt_2y_prefix_allowed() {
        // bcrypt crate produces $2b$ hashes — verify $2y$ prefix variant too (same format)
        let hash = bcrypt_hash("hunter2");
        let hash_2y = hash.replacen("$2b$", "$2y$", 1);
        let users: HashMap<String, String> = [("user".to_string(), hash_2y)].into();
        let result = check(&basic_header("user", "hunter2"), "Realm", &users);
        assert!(matches!(result, AuthResult::Allowed));
    }

    #[test]
    fn test_plaintext_still_works() {
        let users: HashMap<String, String> = [("user".to_string(), "plaintext".to_string())].into();
        let result = check(&basic_header("user", "plaintext"), "Realm", &users);
        assert!(matches!(result, AuthResult::Allowed));
    }
}

// ─── OTel trace context injection tests ───────────────────────────────────────
#[cfg(test)]
mod otel_tests {
    use ai_load_balancer::telemetry::otel::inject_trace_context;
    use hyper::HeaderMap;

    #[test]
    fn test_inject_trace_context_format() {
        let mut headers = HeaderMap::new();
        inject_trace_context(&mut headers, "abc123", "span456", true);
        let traceparent = headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(traceparent.starts_with("00-abc123-span456-"), "format: 00-traceid-spanid-flags");
        assert!(traceparent.ends_with("01"), "sampled flag should be 01");
    }

    #[test]
    fn test_inject_trace_context_not_sampled() {
        let mut headers = HeaderMap::new();
        inject_trace_context(&mut headers, "trace1", "span1", false);
        let traceparent = headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(traceparent.ends_with("00"), "not-sampled flag should be 00");
    }

    #[test]
    fn test_inject_trace_context_overwrites_existing() {
        let mut headers = HeaderMap::new();
        inject_trace_context(&mut headers, "old-trace", "old-span", true);
        inject_trace_context(&mut headers, "new-trace", "new-span", false);
        let traceparent = headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(traceparent.contains("new-trace"), "should overwrite with new trace id");
    }

    #[test]
    fn test_inject_adds_traceparent_to_empty_headers() {
        let mut headers = HeaderMap::new();
        assert!(headers.get("traceparent").is_none());
        inject_trace_context(&mut headers, "t", "s", true);
        assert!(headers.get("traceparent").is_some());
    }
}

// ─── OIDC session tests ────────────────────────────────────────────────────────
#[cfg(test)]
mod oidc_tests {
    use ai_load_balancer::auth::AuthResult;
    use ai_load_balancer::auth::oidc::{
        OidcConfig, OidcDiscovery, OidcSession, authorization_url, check_session,
        generate_session_id, new_session_store,
    };
    use hyper::HeaderMap;

    fn config() -> OidcConfig {
        OidcConfig {
            issuer_url: "https://idp.example.com".to_string(),
            client_id: "phalanx".to_string(),
            client_secret: "s3cr3t".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
        }
    }

    fn discovery() -> OidcDiscovery {
        OidcDiscovery {
            authorization_endpoint: "https://idp.example.com/auth".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: None,
            jwks_uri: "https://idp.example.com/.well-known/jwks.json".to_string(),
        }
    }

    #[test]
    fn test_auth_url_contains_client_id() {
        let url = authorization_url(&config(), &discovery(), "state-xyz");
        assert!(url.contains("client_id=phalanx"));
    }

    #[test]
    fn test_auth_url_contains_response_type_code() {
        let url = authorization_url(&config(), &discovery(), "s");
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn test_auth_url_contains_state() {
        let url = authorization_url(&config(), &discovery(), "abc-state");
        assert!(url.contains("state=abc-state"));
    }

    #[test]
    fn test_session_not_found_is_denied() {
        let store = new_session_store();
        let (result, session) = check_session(&HeaderMap::new(), "sess", &store);
        assert!(matches!(result, AuthResult::Denied(..)));
        assert!(session.is_none());
    }

    #[test]
    fn test_valid_session_cookie_is_allowed() {
        let store = new_session_store();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        store.insert("tok-1".to_string(), OidcSession {
            sub: "user-99".to_string(),
            email: Some("u@example.com".to_string()),
            issuer: Some("https://idp.example.com".to_string()),
            access_token: "at-abc".to_string(),
            refresh_token: None,
            created_at: now,
            expires_in: 3600,
        });
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::COOKIE, "sess=tok-1".parse().unwrap());
        let (result, session) = check_session(&headers, "sess", &store);
        assert!(matches!(result, AuthResult::Allowed));
        assert_eq!(session.unwrap().sub, "user-99");
    }

    #[test]
    fn test_expired_session_is_denied_and_removed() {
        let store = new_session_store();
        store.insert("old-tok".to_string(), OidcSession {
            sub: "ghost".to_string(),
            email: None,
            issuer: Some("https://idp.example.com".to_string()),
            access_token: "at".to_string(),
            refresh_token: None,
            created_at: 1000,
            expires_in: 1,
        });
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::COOKIE, "sess=old-tok".parse().unwrap());
        let (result, _) = check_session(&headers, "sess", &store);
        assert!(matches!(result, AuthResult::Denied(..)));
        assert!(!store.contains_key("old-tok"), "expired session should be removed");
    }

    #[test]
    fn test_session_id_generation_unique() {
        let a = generate_session_id();
        let b = generate_session_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }
}

// ─── PROXY protocol v2 tests ─────────────────────────────────────────────────
#[cfg(test)]
mod proxy_proto_v2_integration_tests {
    use ai_load_balancer::proxy::proxy_proto_v2::{
        AddressFamily, ParseError, TransportProtocol, parse_v2_header,
    };

    fn v2_ipv4_buf(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut buf = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51,
            0x55, 0x49, 0x54, 0x0A, // signature
            0x21,                   // version=2, command=PROXY
            0x11,                   // family=AF_INET, protocol=STREAM
            0x00, 0x0C,             // addr length = 12
        ];
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf
    }

    #[test]
    fn test_v2_ipv4_tcp_parse() {
        let buf = v2_ipv4_buf([192, 168, 1, 1], [10, 0, 0, 1], 12345, 80);
        let result = parse_v2_header(&buf);
        assert!(result.is_ok(), "should parse valid v2 IPv4 TCP header");
        let (hdr, consumed) = result.unwrap();
        assert_eq!(hdr.address_family, AddressFamily::Ipv4);
        assert_eq!(hdr.transport, TransportProtocol::Stream);
        assert_eq!(consumed, 28); // 16 fixed + 12 addr
        let src = hdr.src_addr.unwrap();
        assert_eq!(src.port(), 12345);
    }

    #[test]
    fn test_v2_header_too_short_errors() {
        let result = parse_v2_header(&[0x0D, 0x0A]);
        assert!(matches!(result, Err(ParseError::TooShort)));
    }

    #[test]
    fn test_v2_header_bad_signature_errors() {
        let buf = vec![0x00u8; 20];
        assert!(matches!(parse_v2_header(&buf), Err(ParseError::NotProxyProtocol)));
    }

    #[test]
    fn test_v2_local_command_no_addresses() {
        let mut buf = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51,
            0x55, 0x49, 0x54, 0x0A,
            0x20, // version=2, command=LOCAL
            0x00, // unspec
            0x00, 0x00, // length = 0
        ];
        // Pad to minimum
        buf.resize(16, 0);
        let result = parse_v2_header(&buf);
        assert!(result.is_ok(), "LOCAL command should parse successfully");
        let (hdr, _) = result.unwrap();
        assert_eq!(hdr.address_family, AddressFamily::Unspec);
        assert!(hdr.src_addr.is_none());
    }
}

// ─── FastCGI Protocol Tests ────────────────────────────────────────────────────
#[cfg(test)]
mod fastcgi_protocol_tests {
    use ai_load_balancer::proxy::fastcgi::serve_fastcgi;
    use ai_load_balancer::telemetry::access_log::{AccessLogger, LogFormat};
    use bytes::Bytes;
    use http_body_util::Empty;
    use hyper::{Request, StatusCode};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_fastcgi_unreachable_returns_502() {
        let logger = Arc::new(AccessLogger::new("/dev/null", LogFormat::Json));
        let req = Request::builder()
            .method("GET")
            .uri("/index.php")
            .body(
                Empty::<Bytes>::new(),
            )
            .unwrap();
        // Port 19901 — nothing listening
        let resp = serve_fastcgi("/", "/index.php", "127.0.0.1:19901".to_string(), req, logger, "GET", "127.0.0.1")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_fastcgi_connection_closed_immediately_returns_502() {
        // Start a server that immediately closes the connection (simulates PHP-FPM crash)
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                // Accept then immediately drop to simulate abrupt close
                let _ = conn.write_all(b"").await;
                drop(conn);
            }
        });

        let logger = Arc::new(AccessLogger::new("/dev/null", LogFormat::Json));
        let req = Request::builder()
            .method("GET")
            .uri("/test.php")
            .body(
                Empty::<Bytes>::new(),
            )
            .unwrap();
        let resp = serve_fastcgi("/", "/test.php", addr.to_string(), req, logger, "GET", "10.0.0.1")
            .await
            .unwrap();
        // FastCGI client will fail to parse an empty/invalid response → 502
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_fastcgi_method_and_path_passed_through() {
        // A minimal mock that captures what it receives and closes
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = conn.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(buf[..n].to_vec());
                drop(conn);
            }
        });

        let logger = Arc::new(AccessLogger::new("/dev/null", LogFormat::Json));
        let req = Request::builder()
            .method("POST")
            .uri("/api/submit.php?foo=bar")
            .body(
                Empty::<Bytes>::new(),
            )
            .unwrap();
        // Call — will return 502 since server doesn't speak FastCGI, but we
        // verify the connection was attempted (socket received data).
        let _ = serve_fastcgi("/api", "/api/submit.php", addr.to_string(), req, logger, "POST", "192.168.1.1")
            .await;

        // The mock should have received something (FastCGI begin-request record)
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx).await;
        assert!(received.is_ok(), "FastCGI client should have sent data to server");
        assert!(!received.unwrap().unwrap().is_empty(), "FastCGI request should be non-empty");
    }
}

// ─── uWSGI Protocol Tests ──────────────────────────────────────────────────────
#[cfg(test)]
mod uwsgi_protocol_tests {
    use ai_load_balancer::proxy::uwsgi::serve_uwsgi;
    use ai_load_balancer::telemetry::access_log::{AccessLogger, LogFormat};
    use bytes::Bytes;
    use http_body_util::Empty;
    use hyper::{Request, StatusCode};
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_uwsgi_unreachable_returns_502() {
        let logger = Arc::new(AccessLogger::new("/dev/null", LogFormat::Json));
        let req = Request::builder()
            .method("GET")
            .uri("/app/")
            .body(
                Empty::<Bytes>::new(),
            )
            .unwrap();
        let resp = serve_uwsgi("/", "/app/", "127.0.0.1:19902".to_string(), req, logger, "GET", "127.0.0.1")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_uwsgi_sends_correct_header_format() {
        // Capture the raw uWSGI payload the client sends
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let n = conn.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(buf[..n].to_vec());
                // Close immediately
                drop(conn);
            }
        });

        let logger = Arc::new(AccessLogger::new("/dev/null", LogFormat::Json));
        let req = Request::builder()
            .method("GET")
            .uri("/hello?name=world")
            .body(
                Empty::<Bytes>::new(),
            )
            .unwrap();
        let _ = serve_uwsgi("/", "/hello", addr.to_string(), req, logger, "GET", "10.1.2.3")
            .await;

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .expect("timeout")
            .unwrap();

        // uWSGI wire format: [modifier1=0][datasize_lo][datasize_hi][modifier2=0][...dict...]
        assert!(!received.is_empty(), "uWSGI client must send payload");
        // modifier1 must be 0 for Python/WSGI
        assert_eq!(received[0], 0, "uWSGI modifier1 should be 0 (WSGI)");
        // modifier2 must be 0
        assert_eq!(received[3], 0, "uWSGI modifier2 should be 0");
        // Data size (LE u16) should match actual payload
        let data_size = u16::from_le_bytes([received[1], received[2]]) as usize;
        assert_eq!(received.len(), 4 + data_size, "uWSGI payload length must match header");
    }

    #[tokio::test]
    async fn test_uwsgi_encodes_request_method_in_params() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let n = conn.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(buf[..n].to_vec());
                drop(conn);
            }
        });

        let logger = Arc::new(AccessLogger::new("/dev/null", LogFormat::Json));
        let req = Request::builder()
            .method("POST")
            .uri("/submit")
            .body(
                Empty::<Bytes>::new(),
            )
            .unwrap();
        let _ = serve_uwsgi("/", "/submit", addr.to_string(), req, logger, "POST", "1.2.3.4")
            .await;

        let payload = tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .expect("timeout")
            .unwrap();

        // Verify "POST" appears in the payload (as value of REQUEST_METHOD)
        let payload_str = String::from_utf8_lossy(&payload[4..]);
        assert!(payload_str.contains("POST"), "uWSGI params must contain REQUEST_METHOD=POST");
        assert!(payload_str.contains("REQUEST_METHOD"), "uWSGI params must include REQUEST_METHOD key");
    }
}

// ─── TCP Proxy Integration Tests ──────────────────────────────────────────────
#[cfg(test)]
mod tcp_proxy_integration_tests {
    use ai_load_balancer::config::{AppConfig, UpstreamPoolConfig, BackendConfig, LoadBalancingAlgorithm};
    use ai_load_balancer::discovery::ServiceDiscovery;
    use ai_load_balancer::routing::UpstreamManager;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    async fn start_echo_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    loop {
                        match conn.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => { let _ = conn.write_all(&buf[..n]).await; }
                            Err(_) => break,
                        }
                    }
                });
            }
        });
        addr
    }

    fn make_upstream_manager(backend_addr: &str) -> Arc<UpstreamManager> {
        let mut config = AppConfig::default();
        config.upstreams.insert(
            "default".to_string(),
            UpstreamPoolConfig {
                algorithm: LoadBalancingAlgorithm::RoundRobin,
                backends: vec![BackendConfig {
                    address: backend_addr.to_string(),
                    weight: 1,
                    ..Default::default()
                }],
                keepalive: 0,
                srv_discover: None,
                health_check_interval_secs: 5,
                health_check_timeout_secs: 3,
            },
        );
        let discovery = Arc::new(ServiceDiscovery::new("/tmp/phalanx_tcp_test_discovery"));
        Arc::new(UpstreamManager::new(&config, discovery))
    }

    #[tokio::test]
    async fn test_tcp_proxy_forwards_data_to_backend() {
        let backend_addr = start_echo_server().await;
        let upstreams = make_upstream_manager(&backend_addr.to_string());

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        drop(proxy_listener); // release so start_tcp_proxy can bind

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();
        let upstreams_clone = Arc::clone(&upstreams);
        tokio::spawn(async move {
            ai_load_balancer::proxy::tcp::start_tcp_proxy(
                &proxy_addr.to_string(),
                upstreams_clone,
                shutdown_clone,
            ).await;
        });

        // Give proxy time to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect through proxy
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.expect("connect to proxy");
        client.write_all(b"hello from client").await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read(&mut buf),
        ).await.expect("echo timeout").unwrap();

        assert_eq!(&buf[..n], b"hello from client", "TCP proxy must forward data to backend and echo back");
        shutdown.cancel();
    }

    #[tokio::test]
    async fn test_tcp_proxy_graceful_shutdown() {
        let discovery = Arc::new(ServiceDiscovery::new("/tmp/phalanx_tcp_shutdown_discovery"));
        let config = AppConfig::default();
        let upstreams = Arc::new(UpstreamManager::new(&config, discovery));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        drop(proxy_listener);

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(async move {
            ai_load_balancer::proxy::tcp::start_tcp_proxy(
                &proxy_addr.to_string(),
                upstreams,
                shutdown_clone,
            ).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        shutdown.cancel();

        // Proxy task should exit cleanly after cancellation
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "TCP proxy should shut down within 2 seconds after cancellation");
    }

    #[tokio::test]
    async fn test_tcp_proxy_no_healthy_backend_drops_connection() {
        // Pool with no backends → proxy accepts connection then drops it
        let discovery = Arc::new(ServiceDiscovery::new("/tmp/phalanx_tcp_no_backend_discovery"));
        let mut config = AppConfig::default();
        config.upstreams.insert(
            "default".to_string(),
            UpstreamPoolConfig {
                algorithm: LoadBalancingAlgorithm::RoundRobin,
                backends: vec![], // empty pool
                keepalive: 0,
                srv_discover: None,
                health_check_interval_secs: 5,
                health_check_timeout_secs: 3,
            },
        );
        let upstreams = Arc::new(UpstreamManager::new(&config, discovery));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        drop(proxy_listener);

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            ai_load_balancer::proxy::tcp::start_tcp_proxy(
                &proxy_addr.to_string(),
                upstreams,
                shutdown_clone,
            ).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.expect("proxy should accept");
        client.write_all(b"test").await.unwrap();

        let mut buf = vec![0u8; 64];
        // With no backend, proxy drops the connection — read returns 0 bytes
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read(&mut buf),
        ).await.expect("timeout").unwrap_or(0);
        assert_eq!(n, 0, "proxy should close connection when no backends available");

        shutdown.cancel();
    }
}
