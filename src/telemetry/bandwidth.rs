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
}

impl ProtocolStats {
    fn new() -> Self {
        Self {
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
        }
    }

    pub fn add_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_requests(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn conn_open(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

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
}

impl BandwidthTracker {
    pub fn new() -> Arc<Self> {
        let tracker = Arc::new(Self {
            stats: DashMap::new(),
            thresholds: DashMap::new(),
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
        for entry in self.stats.iter() {
            let proto = entry.key();
            let stat = entry.value();
            let threshold = self
                .thresholds
                .get(proto)
                .map(|t| t.clone())
                .unwrap_or_default();

            let total_bytes = stat.bytes_in.load(Ordering::Relaxed)
                + stat.bytes_out.load(Ordering::Relaxed);
            let active = stat.active_connections.load(Ordering::Relaxed);

            if total_bytes >= threshold.bandwidth_bps_critical {
                alerts.push(BandwidthAlert {
                    protocol: proto.clone(),
                    level: AlertLevel::Critical,
                    message: format!(
                        "{} cumulative traffic {:.1} GiB exceeds critical threshold",
                        proto,
                        total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
                    ),
                    metric: "bandwidth".to_string(),
                    value: total_bytes as f64,
                    threshold: threshold.bandwidth_bps_critical as f64,
                });
            } else if total_bytes >= threshold.bandwidth_bps_warn {
                alerts.push(BandwidthAlert {
                    protocol: proto.clone(),
                    level: AlertLevel::Warning,
                    message: format!(
                        "{} cumulative traffic {:.1} MiB exceeds warning threshold",
                        proto,
                        total_bytes as f64 / (1024.0 * 1024.0)
                    ),
                    metric: "bandwidth".to_string(),
                    value: total_bytes as f64,
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
        // Small traffic — should not trigger
        tracker.protocol("http1").add_in(1024);
        let alerts = tracker.check_thresholds();
        assert!(alerts.is_empty(), "Unexpected alerts: {:?}", alerts);
    }

    #[test]
    fn test_bandwidth_warning_alert() {
        let tracker = BandwidthTracker::new();
        // Set a low warning threshold to trigger
        tracker.set_threshold("tcp", ProtocolThreshold {
            bandwidth_bps_warn: 100,
            bandwidth_bps_critical: 1_000_000,
            connections_warn: 999_999,
            connections_critical: 9_999_999,
        });
        tracker.protocol("tcp").add_in(200);
        let alerts = tracker.check_thresholds();
        let tcp_alert = alerts.iter().find(|a| a.protocol == "tcp" && a.metric == "bandwidth");
        assert!(tcp_alert.is_some());
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
        tracker.protocol("udp").add_out(600);
        let alerts = tracker.check_thresholds();
        let a = alerts.iter().find(|a| a.protocol == "udp" && a.level == AlertLevel::Critical);
        assert!(a.is_some());
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
}
