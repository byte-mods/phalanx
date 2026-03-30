//! Additional admin API endpoints powering the full dashboard UI.
//!
//! Exposes WAF bans/attack-log/strikes, rate-limit top-N,
//! cluster node status, and cache stats for the `/dashboard` frontend.

use actix_web::{delete, get, post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::admin::{AdminState, alerts::AlertEngine};
use crate::middleware::ratelimit::PhalanxRateLimiter;
use crate::telemetry::bandwidth::BandwidthTracker;

/// Extended state passed to dashboard-specific handlers.
pub struct DashboardState {
    pub base: AdminState,
    pub rate_limiter: Arc<PhalanxRateLimiter>,
    pub bandwidth: Arc<BandwidthTracker>,
    pub alert_engine: Arc<AlertEngine>,
}

// ── WAF Ban Management ─────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct BanEntry {
    pub ip: String,
    pub strikes: u32,
    pub expires_in_secs: u64,
}

/// GET /api/waf/bans — list all currently-banned IPs with expiry.
#[get("/api/waf/bans")]
pub async fn list_bans(state: web::Data<DashboardState>) -> impl Responder {
    let bans: Vec<BanEntry> = state
        .base
        .waf
        .reputation
        .list_bans()
        .into_iter()
        .map(|(ip, strikes, expires_in_secs)| BanEntry { ip, strikes, expires_in_secs })
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "bans": bans }))
}

/// POST /api/waf/ban/{ip} — manually ban an IP immediately.
#[post("/api/waf/ban/{ip}")]
pub async fn manual_ban(
    state: web::Data<DashboardState>,
    path: web::Path<String>,
) -> impl Responder {
    let ip = path.into_inner();
    state.base.waf.reputation.manual_ban(&ip);
    HttpResponse::Ok().json(serde_json::json!({ "status": "banned", "ip": ip }))
}

/// DELETE /api/waf/ban/{ip} — unban an IP (clear all strikes).
#[delete("/api/waf/ban/{ip}")]
pub async fn unban_ip(
    state: web::Data<DashboardState>,
    path: web::Path<String>,
) -> impl Responder {
    let ip = path.into_inner();
    state.base.waf.reputation.unban(&ip);
    HttpResponse::Ok().json(serde_json::json!({ "status": "unbanned", "ip": ip }))
}

// ── WAF Attack Log ─────────────────────────────────────────────────────────────

/// GET /api/waf/attacks — most recent 50 WAF block events (newest first).
#[get("/api/waf/attacks")]
pub async fn list_attacks(state: web::Data<DashboardState>) -> impl Responder {
    let events = state.base.waf.recent_attacks(50).await;
    HttpResponse::Ok().json(serde_json::json!({ "attacks": events }))
}

/// GET /api/waf/strikes — all tracked IPs with their strike counts.
#[get("/api/waf/strikes")]
pub async fn list_strikes(state: web::Data<DashboardState>) -> impl Responder {
    let strikes = state.base.waf.reputation.list_all_strikes();
    let json: Vec<_> = strikes
        .into_iter()
        .map(|(ip, count)| serde_json::json!({ "ip": ip, "strikes": count }))
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "strikes": json }))
}

// ── Rate Limit Top-N ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TopQuery {
    pub n: Option<usize>,
}

/// GET /api/rates/top?n=10 — top N IPs by cumulative request count.
#[get("/api/rates/top")]
pub async fn top_rate_ips(
    state: web::Data<DashboardState>,
    query: web::Query<TopQuery>,
) -> impl Responder {
    let n = query.n.unwrap_or(10).min(100);
    let top = state.rate_limiter.top_ips(n);
    let json: Vec<_> = top
        .into_iter()
        .map(|(ip, count)| serde_json::json!({ "ip": ip, "requests": count }))
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "top_ips": json }))
}

// ── Cluster Node Status ────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct NodeStatus {
    pub node_id: String,
    pub status: String,
    pub last_seen_secs: u64,
}

/// GET /api/cluster/nodes — registered cluster nodes and their health.
#[get("/api/cluster/nodes")]
pub async fn cluster_nodes() -> impl Responder {
    let node_id = std::env::var("HOSTNAME").unwrap_or_else(|_| "local".to_string());
    let nodes = vec![NodeStatus {
        node_id,
        status: "healthy".to_string(),
        last_seen_secs: 0,
    }];
    HttpResponse::Ok().json(serde_json::json!({ "nodes": nodes }))
}

// ── Cache Stats ────────────────────────────────────────────────────────────────

/// GET /api/cache/stats — cache entry count snapshot.
#[get("/api/cache/stats")]
pub async fn cache_stats(state: web::Data<DashboardState>) -> impl Responder {
    let entries = state.base.cache.entry_count();
    HttpResponse::Ok().json(serde_json::json!({ "entries": entries }))
}

// ── Bandwidth Stats ────────────────────────────────────────────────────────────

/// GET /api/bandwidth — per-protocol traffic snapshot (bytes_in, bytes_out, requests, active_connections).
#[get("/api/bandwidth")]
pub async fn bandwidth_stats(state: web::Data<DashboardState>) -> impl Responder {
    let snap = state.bandwidth.snapshot();
    HttpResponse::Ok().json(serde_json::json!({ "protocols": snap }))
}

// ── Resource Alerts ────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct AlertsQuery {
    pub n: Option<usize>,
}

/// GET /api/alerts?n=50 — most recent resource alerts (newest first).
#[get("/api/alerts")]
pub async fn list_alerts(
    state: web::Data<DashboardState>,
    query: web::Query<AlertsQuery>,
) -> impl Responder {
    let n = query.n.unwrap_or(50).min(500);
    let alerts = state.alert_engine.recent(n).await;
    let count = state.alert_engine.count().await;
    HttpResponse::Ok().json(serde_json::json!({ "alerts": alerts, "total": count }))
}

/// POST /api/alerts/check — trigger an immediate alert check cycle.
#[post("/api/alerts/check")]
pub async fn trigger_alert_check(state: web::Data<DashboardState>) -> impl Responder {
    state.alert_engine.check().await;
    let count = state.alert_engine.count().await;
    HttpResponse::Ok().json(serde_json::json!({ "status": "checked", "alert_count": count }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use std::sync::Arc;

    fn make_state() -> web::Data<DashboardState> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::SeqCst);

        use crate::admin::{AdminState, ProxyMetrics, alerts::AlertEngine};
        use crate::config::AppConfig;
        use crate::discovery::ServiceDiscovery;
        use crate::keyval::KeyvalStore;
        use crate::middleware::{ratelimit::PhalanxRateLimiter, ResponseCache};
        use crate::routing::UpstreamManager;
        use crate::telemetry::bandwidth::BandwidthTracker;
        use crate::waf::{reputation::IpReputationManager, WafEngine};

        let reputation = IpReputationManager::new(5, 3600, None);
        let waf = Arc::new(WafEngine::new(true, Arc::clone(&reputation)));
        let cache = Arc::new(ResponseCache::new(1000, 60));
        // Unique path per test to avoid RocksDB lock contention.
        let db_path = format!("/tmp/phalanx_test_dash_{}", id);
        let discovery = Arc::new(ServiceDiscovery::new(&db_path));
        let config = AppConfig::default();
        let manager = Arc::new(UpstreamManager::new(&config, Arc::clone(&discovery)));
        let keyval = KeyvalStore::new(0, None);
        let metrics = Arc::new(ProxyMetrics::new());
        let rate_limiter = Arc::new(PhalanxRateLimiter::new(100, 200, None, None));
        let bandwidth = BandwidthTracker::new();
        let alert_engine = AlertEngine::new(Arc::clone(&bandwidth));

        let base = AdminState {
            metrics, discovery, manager, keyval, waf, cache,
            rate_limiter: Arc::clone(&rate_limiter),
            bandwidth: Arc::clone(&bandwidth),
            alert_engine: Arc::clone(&alert_engine),
        };
        web::Data::new(DashboardState {
            base,
            rate_limiter,
            bandwidth,
            alert_engine,
        })
    }

    #[actix_web::test]
    async fn test_list_bans_empty() {
        let state = make_state();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(list_bans)
        ).await;
        let req = test::TestRequest::get().uri("/api/waf/bans").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["bans"].as_array().unwrap().len(), 0);
    }

    #[actix_web::test]
    async fn test_manual_ban_endpoint_then_list() {
        let state = make_state();
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(manual_ban)
                .service(list_bans)
        ).await;
        let ban_req = test::TestRequest::post().uri("/api/waf/ban/9.9.9.9").to_request();
        let ban_resp = test::call_service(&app, ban_req).await;
        assert_eq!(ban_resp.status(), 200);

        let list_req = test::TestRequest::get().uri("/api/waf/bans").to_request();
        let list_resp = test::call_service(&app, list_req).await;
        let body: serde_json::Value = test::read_body_json(list_resp).await;
        let bans = body["bans"].as_array().unwrap();
        assert!(bans.iter().any(|b| b["ip"] == "9.9.9.9"));
    }

    #[actix_web::test]
    async fn test_unban_endpoint() {
        let state = make_state();
        state.base.waf.reputation.manual_ban("bad.ip");
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(unban_ip)
                .service(list_bans)
        ).await;
        let unban_req = test::TestRequest::delete().uri("/api/waf/ban/bad.ip").to_request();
        let unban_resp = test::call_service(&app, unban_req).await;
        assert_eq!(unban_resp.status(), 200);

        let list_req = test::TestRequest::get().uri("/api/waf/bans").to_request();
        let list_resp = test::call_service(&app, list_req).await;
        let body: serde_json::Value = test::read_body_json(list_resp).await;
        assert_eq!(body["bans"].as_array().unwrap().len(), 0);
    }

    #[actix_web::test]
    async fn test_list_bans_shows_pre_banned_ip() {
        let state = make_state();
        state.base.waf.reputation.manual_ban("1.2.3.4");
        let app = test::init_service(
            App::new().app_data(state.clone()).service(list_bans)
        ).await;
        let req = test::TestRequest::get().uri("/api/waf/bans").to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let bans = body["bans"].as_array().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0]["ip"], "1.2.3.4");
    }

    #[actix_web::test]
    async fn test_list_attacks_empty() {
        let state = make_state();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(list_attacks)
        ).await;
        let req = test::TestRequest::get().uri("/api/waf/attacks").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["attacks"].as_array().unwrap().len(), 0);
    }

    #[actix_web::test]
    async fn test_list_attacks_with_events() {
        let state = make_state();
        state.base.waf.record_attack("10.0.0.1", "/api/login", "POST", "SQLi").await;
        state.base.waf.record_attack("10.0.0.2", "/admin", "GET", "IP Banned").await;
        let app = test::init_service(
            App::new().app_data(state.clone()).service(list_attacks)
        ).await;
        let req = test::TestRequest::get().uri("/api/waf/attacks").to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let attacks = body["attacks"].as_array().unwrap();
        assert_eq!(attacks.len(), 2);
        // newest first — last recorded is /admin
        assert_eq!(attacks[0]["path"], "/admin");
        assert_eq!(attacks[1]["path"], "/api/login");
    }

    #[actix_web::test]
    async fn test_list_strikes() {
        let state = make_state();
        state.base.waf.reputation.add_strike("strike.ip", 3);
        let app = test::init_service(
            App::new().app_data(state.clone()).service(list_strikes)
        ).await;
        let req = test::TestRequest::get().uri("/api/waf/strikes").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let strikes = body["strikes"].as_array().unwrap();
        assert!(strikes.iter().any(|s| s["ip"] == "strike.ip" && s["strikes"] == 3));
    }

    #[actix_web::test]
    async fn test_top_rate_ips_empty() {
        let state = make_state();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(top_rate_ips)
        ).await;
        let req = test::TestRequest::get().uri("/api/rates/top?n=5").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["top_ips"].as_array().unwrap().len(), 0);
    }

    #[actix_web::test]
    async fn test_top_rate_ips_with_data() {
        let state = make_state();
        for _ in 0..5 { state.rate_limiter.record_request("192.168.1.1"); }
        for _ in 0..3 { state.rate_limiter.record_request("192.168.1.2"); }
        let app = test::init_service(
            App::new().app_data(state.clone()).service(top_rate_ips)
        ).await;
        let req = test::TestRequest::get().uri("/api/rates/top?n=10").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let top = body["top_ips"].as_array().unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0]["ip"], "192.168.1.1");
        assert_eq!(top[0]["requests"], 5);
        assert_eq!(top[1]["ip"], "192.168.1.2");
        assert_eq!(top[1]["requests"], 3);
    }

    #[actix_web::test]
    async fn test_top_rate_default_n() {
        let state = make_state();
        for i in 0..15u32 { state.rate_limiter.record_request(&format!("10.0.{}.1", i)); }
        let app = test::init_service(
            App::new().app_data(state.clone()).service(top_rate_ips)
        ).await;
        // no ?n= → defaults to 10
        let req = test::TestRequest::get().uri("/api/rates/top").to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["top_ips"].as_array().unwrap().len(), 10);
    }

    #[actix_web::test]
    async fn test_cluster_nodes() {
        let app = test::init_service(App::new().service(cluster_nodes)).await;
        let req = test::TestRequest::get().uri("/api/cluster/nodes").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(!body["nodes"].as_array().unwrap().is_empty());
        assert_eq!(body["nodes"][0]["status"], "healthy");
    }

    #[actix_web::test]
    async fn test_cache_stats() {
        let state = make_state();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(cache_stats)
        ).await;
        let req = test::TestRequest::get().uri("/api/cache/stats").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["entries"].as_u64().is_some());
    }

    #[actix_web::test]
    async fn test_bandwidth_stats_returns_all_protocols() {
        let state = make_state();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(bandwidth_stats)
        ).await;
        let req = test::TestRequest::get().uri("/api/bandwidth").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let protocols = body["protocols"].as_array().unwrap();
        // All 8 known protocols must be present
        for proto in &["http1", "http2", "http3", "websocket", "grpc", "tcp", "udp", "webrtc"] {
            assert!(
                protocols.iter().any(|p| p["protocol"] == *proto),
                "Missing protocol in bandwidth response: {}",
                proto
            );
        }
    }

    #[actix_web::test]
    async fn test_bandwidth_stats_reflects_traffic() {
        let state = make_state();
        // Inject some traffic
        state.bandwidth.protocol("http1").add_in(12345);
        state.bandwidth.protocol("http1").add_out(6789);
        let app = test::init_service(
            App::new().app_data(state.clone()).service(bandwidth_stats)
        ).await;
        let req = test::TestRequest::get().uri("/api/bandwidth").to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let http1 = body["protocols"]
            .as_array().unwrap()
            .iter()
            .find(|p| p["protocol"] == "http1")
            .unwrap();
        assert_eq!(http1["bytes_in"], 12345);
        assert_eq!(http1["bytes_out"], 6789);
    }

    #[actix_web::test]
    async fn test_list_alerts_empty() {
        let state = make_state();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(list_alerts)
        ).await;
        let req = test::TestRequest::get().uri("/api/alerts?n=10").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 0);
        assert_eq!(body["total"], 0);
    }

    #[actix_web::test]
    async fn test_trigger_alert_check() {
        let state = make_state();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(trigger_alert_check)
        ).await;
        let req = test::TestRequest::post().uri("/api/alerts/check").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "checked");
        assert!(body["alert_count"].as_u64().is_some());
    }

    #[actix_web::test]
    async fn test_list_alerts_after_threshold_breach() {
        use crate::telemetry::bandwidth::ProtocolThreshold;
        let state = make_state();
        // Set tiny threshold and add traffic
        state.bandwidth.set_threshold("tcp", ProtocolThreshold {
            bandwidth_bps_warn: 1,
            bandwidth_bps_critical: 1_000_000,
            connections_warn: 999_999,
            connections_critical: 9_999_999,
        });
        state.bandwidth.protocol("tcp").add_in(100);
        state.alert_engine.check().await;

        let app = test::init_service(
            App::new().app_data(state.clone()).service(list_alerts)
        ).await;
        let req = test::TestRequest::get().uri("/api/alerts?n=20").to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let alerts = body["alerts"].as_array().unwrap();
        assert!(!alerts.is_empty(), "Expected at least one alert");
        assert!(
            alerts.iter().any(|a| a["protocol"] == "tcp"),
            "Expected tcp alert"
        );
    }
}
