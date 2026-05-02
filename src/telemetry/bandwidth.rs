//! Per-protocol bandwidth tracking with atomic counters.
//!
//! `BandwidthTracker` maintains per-protocol statistics:
//! - `bytes_in`  — inbound bytes received from clients
//! - `bytes_out` — outbound bytes sent to clients
//! - `requests`  — total request count
//! - `active_connections` — gauge of live connections
//!
//! All counters use `AtomicU64` and are safe to share across threads via `Arc`.
//!
//! ## Supported protocols
//! HTTP1, HTTP2, HTTP3/QUIC, WebSocket, gRPC, TCP, UDP, WebRTC

use dashmap::DashMap;
use serde::Serialize;
use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicU64, Ordering},
};

/// Per-protocol traffic counters.
pub struct ProtocolStats {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub requests: AtomicU64,
    /// Signed gauge so dec() never underflows below 0.
    pub active_connections: AtomicI64,
    /// Bytes at the last threshold check (for rate calculation).
    pub last_check_bytes: AtomicU64,
    /// Unix millis at the last threshold check (for rate calculation).
    pub last_check_time: AtomicU64,
}

impl ProtocolStats {
    /// Creates a new zeroed-out stats bucket.
    fn new() -> Self {
        Self {
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            last_check_bytes: AtomicU64::new(0),
            last_check_time: AtomicU64::new(0),
        }
    }

    /// Records `n` inbound bytes received from the client.
    pub fn add_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    /// Records `n` outbound bytes sent to the client.
    pub fn add_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    /// Increments the total request counter by one.
    pub fn inc_requests(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the active connection gauge by one.
    pub fn conn_open(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the active connection gauge by one, saturating at zero.
    pub fn conn_close(&self) {
        // saturate at 0 — never report negative connections
        self.active_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(if v > 0 { v - 1 } else { 0 })
            })
            .ok();
    }
}

/// Snapshot of one protocol's counters (serialisable for the API).
#[derive(Serialize, Clone, Debug)]
pub struct ProtocolSnapshot {
    pub protocol: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub requests: u64,
    pub active_connections: i64,
}

/// Thresholds that trigger resource alerts for a protocol.
#[derive(Clone)]
pub struct ProtocolThreshold {
    /// Alert when `bytes_in + bytes_out` per-minute exceeds this.
    pub bandwidth_bps_warn: u64,
    pub bandwidth_bps_critical: u64,
    /// Alert when active connections exceed this count.
    pub connections_warn: i64,
    pub connections_critical: i64,
}

impl Default for ProtocolThreshold {
    fn default() -> Self {
        Self {
            bandwidth_bps_warn: 100 * 1024 * 1024,      // 100 MiB/s
            bandwidth_bps_critical: 500 * 1024 * 1024,  // 500 MiB/s
            connections_warn: 5_000,
            connections_critical: 20_000,
        }
    }
}

/// Central bandwidth tracker — one `ProtocolStats` per protocol label.
pub struct BandwidthTracker {
    stats: DashMap<String, Arc<ProtocolStats>>,
    thresholds: DashMap<String, ProtocolThreshold>,
    /// Per-upstream-pool traffic counters.
    pool_stats: DashMap<String, Arc<ProtocolStats>>,
}

impl BandwidthTracker {
    /// Creates a new tracker with pre-initialised buckets for all known protocols.
    pub fn new() -> Arc<Self> {
        let tracker = Arc::new(Self {
            stats: DashMap::new(),
            thresholds: DashMap::new(),
            pool_stats: DashMap::new(),
        });

        // Pre-create all known protocol buckets
        for proto in &[
            "http1", "http2", "http3", "websocket", "grpc",
            "tcp", "udp", "webrtc",
        ] {
            tracker.stats.insert(proto.to_string(), Arc::new(ProtocolStats::new()));
            tracker.thresholds.insert(proto.to_string(), ProtocolThreshold::default());
        }

        tracker
    }

    /// Get (or lazily create) the stats bucket for a protocol label.
    pub fn protocol(&self, proto: &str) -> Arc<ProtocolStats> {
        self.stats
            .entry(proto.to_string())
            .or_insert_with(|| Arc::new(ProtocolStats::new()))
            .clone()
    }

    /// Get (or lazily create) the stats bucket for an upstream pool name.
    pub fn pool(&self, pool_name: &str) -> Arc<ProtocolStats> {
        self.pool_stats
            .entry(pool_name.to_string())
            .or_insert_with(|| Arc::new(ProtocolStats::new()))
            .clone()
    }

    /// Snapshot of all per-pool traffic counters, sorted by total bytes descending.
    pub fn pool_snapshot(&self) -> Vec<ProtocolSnapshot> {
        let mut snap: Vec<ProtocolSnapshot> = self
            .pool_stats
            .iter()
            .map(|e| ProtocolSnapshot {
                protocol: e.key().clone(),
                bytes_in: e.value().bytes_in.load(Ordering::Relaxed),
                bytes_out: e.value().bytes_out.load(Ordering::Relaxed),
                requests: e.value().requests.load(Ordering::Relaxed),
                active_connections: e.value().active_connections.load(Ordering::Relaxed),
            })
            .collect();
        snap.sort_by(|a, b| {
            (b.bytes_in + b.bytes_out).cmp(&(a.bytes_in + a.bytes_out))
        });
        snap
    }

    /// Snapshot of all protocols, sorted by total bytes descending.
    pub fn snapshot(&self) -> Vec<ProtocolSnapshot> {
        let mut snap: Vec<ProtocolSnapshot> = self
            .stats
            .iter()
            .map(|e| ProtocolSnapshot {
                protocol: e.key().clone(),
                bytes_in: e.value().bytes_in.load(Ordering::Relaxed),
                bytes_out: e.value().bytes_out.load(Ordering::Relaxed),
                requests: e.value().requests.load(Ordering::Relaxed),
                active_connections: e.value().active_connections.load(Ordering::Relaxed),
            })
            .collect();
        snap.sort_by(|a, b| {
            (b.bytes_in + b.bytes_out).cmp(&(a.bytes_in + a.bytes_out))
        });
        snap
    }

    /// Check all protocols against thresholds and return triggered alerts.
    pub fn check_thresholds(&self) -> Vec<BandwidthAlert> {
        let mut alerts = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        for entry in self.stats.iter() {
            let proto = entry.key();
            let stat = entry.value();
            let threshold = self
                .thresholds
                .get(proto)
                .map(|t| t.clone())
                .unwrap_or_default();

            let current_bytes = stat.bytes_in.load(Ordering::Relaxed)
                + stat.bytes_out.load(Ordering::Relaxed);
            let active = stat.active_connections.load(Ordering::Relaxed);

            // Compute bytes-per-second rate since last check
            let last_bytes = stat.last_check_bytes.load(Ordering::Relaxed);
            let last_time = stat.last_check_time.load(Ordering::Relaxed);
            let bps = if last_time > 0 && now > last_time {
                let delta_bytes = current_bytes.saturating_sub(last_bytes);
                let delta_secs = (now - last_time) as f64 / 1000.0;
                (delta_bytes as f64 / delta_secs) as u64
            } else {
                0
            };

            // Update last-check snapshot
            stat.last_check_bytes.store(current_bytes, Ordering::Relaxed);
            stat.last_check_time.store(now, Ordering::Relaxed);

            if bps >= threshold.bandwidth_bps_critical {
                alerts.push(BandwidthAlert {
                    protocol: proto.clone(),
                    level: AlertLevel::Critical,
                    message: format!(
                        "{} traffic {:.1} MiB/s exceeds critical threshold",
                        proto,
                        bps as f64 / (1024.0 * 1024.0)
                    ),
                    metric: "bandwidth".to_string(),
                    value: bps as f64,
                    threshold: threshold.bandwidth_bps_critical as f64,
                });
            } else if bps >= threshold.bandwidth_bps_warn {
                alerts.push(BandwidthAlert {
                    protocol: proto.clone(),
                    level: AlertLevel::Warning,
                    message: format!(
                        "{} traffic {:.1} MiB/s exceeds warning threshold",
                        proto,
                        bps as f64 / (1024.0 * 1024.0)
                    ),
                    metric: "bandwidth".to_string(),
                    value: bps as f64,
                    threshold: threshold.bandwidth_bps_warn as f64,
                });
            }

            if active >= threshold.connections_critical {
                alerts.push(BandwidthAlert {
                    protocol: proto.clone(),
                    level: AlertLevel::Critical,
                    message: format!(
                        "{} has {} active connections (critical threshold: {})",
                        proto, active, threshold.connections_critical
                    ),
                    metric: "connections".to_string(),
                    value: active as f64,
                    threshold: threshold.connections_critical as f64,
                });
            } else if active >= threshold.connections_warn {
                alerts.push(BandwidthAlert {
                    protocol: proto.clone(),
                    level: AlertLevel::Warning,
                    message: format!(
                        "{} has {} active connections (warn threshold: {})",
                        proto, active, threshold.connections_warn
                    ),
                    metric: "connections".to_string(),
                    value: active as f64,
                    threshold: threshold.connections_warn as f64,
                });
            }
        }
        alerts
    }

    /// Overwrite thresholds for a specific protocol.
    pub fn set_threshold(&self, proto: &str, threshold: ProtocolThreshold) {
        self.thresholds.insert(proto.to_string(), threshold);
    }
}

/// Severity of a triggered alert.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

/// A single threshold violation event.
#[derive(Serialize, Clone, Debug)]
pub struct BandwidthAlert {
    pub protocol: String,
    pub level: AlertLevel,
    pub message: String,
    pub metric: String,
    pub value: f64,
    pub threshold: f64,
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_creates_all_known_protocols() {
        let tracker = BandwidthTracker::new();
        let snap = tracker.snapshot();
        let protos: Vec<&str> = snap.iter().map(|s| s.protocol.as_str()).collect();
        for p in &["http1", "http2", "http3", "websocket", "grpc", "tcp", "udp", "webrtc"] {
            assert!(protos.contains(p), "Missing protocol: {}", p);
        }
    }

    #[test]
    fn test_bytes_in_out_accumulate() {
        let tracker = BandwidthTracker::new();
        let p = tracker.protocol("http1");
        p.add_in(1024);
        p.add_in(512);
        p.add_out(2048);
        let snap = tracker.snapshot();
        let h1 = snap.iter().find(|s| s.protocol == "http1").unwrap();
        assert_eq!(h1.bytes_in, 1536);
        assert_eq!(h1.bytes_out, 2048);
    }

    #[test]
    fn test_request_counter() {
        let tracker = BandwidthTracker::new();
        let p = tracker.protocol("http2");
        for _ in 0..5 { p.inc_requests(); }
        let snap = tracker.snapshot();
        let h2 = snap.iter().find(|s| s.protocol == "http2").unwrap();
        assert_eq!(h2.requests, 5);
    }

    #[test]
    fn test_active_connections_gauge() {
        let tracker = BandwidthTracker::new();
        let p = tracker.protocol("websocket");
        p.conn_open();
        p.conn_open();
        p.conn_open();
        p.conn_close();
        let snap = tracker.snapshot();
        let ws = snap.iter().find(|s| s.protocol == "websocket").unwrap();
        assert_eq!(ws.active_connections, 2);
    }

    #[test]
    fn test_conn_close_does_not_go_negative() {
        let tracker = BandwidthTracker::new();
        let p = tracker.protocol("tcp");
        p.conn_close(); // no open — should stay 0
        let snap = tracker.snapshot();
        let tcp = snap.iter().find(|s| s.protocol == "tcp").unwrap();
        assert_eq!(tcp.active_connections, 0);
    }

    #[test]
    fn test_no_alerts_below_thresholds() {
        let tracker = BandwidthTracker::new();
        // First check establishes baseline — should not trigger
        let alerts = tracker.check_thresholds();
        assert!(alerts.is_empty(), "Unexpected alerts: {:?}", alerts);
    }

    #[test]
    fn test_bandwidth_warning_alert() {
        let tracker = BandwidthTracker::new();
        tracker.set_threshold("tcp", ProtocolThreshold {
            bandwidth_bps_warn: 100,
            bandwidth_bps_critical: 1_000_000,
            connections_warn: 999_999,
            connections_critical: 9_999_999,
        });
        let p = tracker.protocol("tcp");
        // Seed last-check state to 1 second ago with 0 bytes
        let one_sec_ago = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        p.last_check_bytes.store(0, Ordering::Relaxed);
        p.last_check_time.store(one_sec_ago, Ordering::Relaxed);
        p.add_in(200); // 200 B/s > 100 B/s warn threshold
        let alerts = tracker.check_thresholds();
        let tcp_alert = alerts.iter().find(|a| a.protocol == "tcp" && a.metric == "bandwidth");
        assert!(tcp_alert.is_some(), "Expected bandwidth warning alert");
        assert_eq!(tcp_alert.unwrap().level, AlertLevel::Warning);
    }

    #[test]
    fn test_bandwidth_critical_alert() {
        let tracker = BandwidthTracker::new();
        tracker.set_threshold("udp", ProtocolThreshold {
            bandwidth_bps_warn: 100,
            bandwidth_bps_critical: 500,
            connections_warn: 999_999,
            connections_critical: 9_999_999,
        });
        let p = tracker.protocol("udp");
        let one_sec_ago = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        p.last_check_bytes.store(0, Ordering::Relaxed);
        p.last_check_time.store(one_sec_ago, Ordering::Relaxed);
        p.add_out(600); // 600 B/s > 500 B/s critical threshold
        let alerts = tracker.check_thresholds();
        let a = alerts.iter().find(|a| a.protocol == "udp" && a.level == AlertLevel::Critical);
        assert!(a.is_some(), "Expected bandwidth critical alert");
    }

    #[test]
    fn test_bandwidth_threshold_rate_not_cumulative() {
        let tracker = BandwidthTracker::new();
        tracker.set_threshold("http1", ProtocolThreshold {
            bandwidth_bps_warn: 1_000_000, // 1 MiB/s
            bandwidth_bps_critical: 5_000_000,
            connections_warn: 999_999,
            connections_critical: 9_999_999,
        });
        let p = tracker.protocol("http1");
        // Simulate a huge cumulative total with a very old baseline
        let ten_min_ago = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(600))
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        p.last_check_bytes.store(0, Ordering::Relaxed);
        p.last_check_time.store(ten_min_ago, Ordering::Relaxed);
        p.add_in(10 * 1024 * 1024); // 10 MiB over 10 min = ~17 KiB/s
        let alerts = tracker.check_thresholds();
        // Should NOT alert because rate (17 KiB/s) is well below 1 MiB/s threshold
        let bw_alert = alerts.iter().find(|a| a.protocol == "http1" && a.metric == "bandwidth");
        assert!(
            bw_alert.is_none(),
            "Rate-based check should not alert on low rate: {:?}",
            bw_alert
        );
    }

    #[test]
    fn test_connection_warning_alert() {
        let tracker = BandwidthTracker::new();
        tracker.set_threshold("webrtc", ProtocolThreshold {
            bandwidth_bps_warn: u64::MAX,
            bandwidth_bps_critical: u64::MAX,
            connections_warn: 2,
            connections_critical: 100,
        });
        let p = tracker.protocol("webrtc");
        p.conn_open();
        p.conn_open();
        p.conn_open();
        let alerts = tracker.check_thresholds();
        let a = alerts.iter().find(|a| a.protocol == "webrtc" && a.metric == "connections");
        assert!(a.is_some());
        assert_eq!(a.unwrap().level, AlertLevel::Warning);
    }

    #[test]
    fn test_lazy_protocol_creation() {
        let tracker = BandwidthTracker::new();
        tracker.protocol("mqtt").add_in(100);
        let snap = tracker.snapshot();
        assert!(snap.iter().any(|s| s.protocol == "mqtt"));
    }

    #[test]
    fn test_snapshot_sorted_by_total_bytes_desc() {
        let tracker = BandwidthTracker::new();
        tracker.protocol("http1").add_in(1000);
        tracker.protocol("http2").add_in(5000);
        tracker.protocol("tcp").add_out(3000);
        let snap = tracker.snapshot();
        // http2 (5000) should come before tcp (3000) before http1 (1000)
        let positions: Vec<usize> = ["http2", "tcp", "http1"]
            .iter()
            .map(|name| snap.iter().position(|s| &s.protocol == name).unwrap())
            .collect();
        assert!(positions[0] < positions[1]);
        assert!(positions[1] < positions[2]);
    }

    // ── Per-pool bandwidth tests ───────────────────────────────────────────

    #[test]
    fn test_pool_stats_separate_from_protocol() {
        let tracker = BandwidthTracker::new();
        tracker.pool("backend_api").add_in(5000);
        tracker.protocol("http1").add_in(3000);
        let pool_snap = tracker.pool_snapshot();
        let proto_snap = tracker.snapshot();
        let pool_entry = pool_snap.iter().find(|s| s.protocol == "backend_api");
        assert!(pool_entry.is_some());
        assert_eq!(pool_entry.unwrap().bytes_in, 5000);
        // Protocol snapshot should not contain pool names
        assert!(proto_snap.iter().all(|s| s.protocol != "backend_api"));
    }

    #[test]
    fn test_pool_snapshot_sorted_by_total() {
        let tracker = BandwidthTracker::new();
        tracker.pool("pool_a").add_in(100);
        tracker.pool("pool_b").add_in(500);
        tracker.pool("pool_c").add_out(300);
        let snap = tracker.pool_snapshot();
        let positions: Vec<usize> = ["pool_b", "pool_c", "pool_a"]
            .iter()
            .map(|name| snap.iter().position(|s| &s.protocol == name).unwrap())
            .collect();
        assert!(positions[0] < positions[1]);
        assert!(positions[1] < positions[2]);
    }

    #[test]
    fn test_pool_requests_and_connections() {
        let tracker = BandwidthTracker::new();
        let p = tracker.pool("web");
        p.inc_requests();
        p.inc_requests();
        p.conn_open();
        p.conn_open();
        p.conn_close();
        let snap = tracker.pool_snapshot();
        let web = snap.iter().find(|s| s.protocol == "web").unwrap();
        assert_eq!(web.requests, 2);
        assert_eq!(web.active_connections, 1);
    }
}
