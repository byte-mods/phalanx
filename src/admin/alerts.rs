//! Resource alert engine.
//!
//! `AlertEngine` watches configurable thresholds for bandwidth, connections,
//! memory, and CPU, and maintains a rolling in-memory alert log.
//!
//! Consumers call `check()` on each polling cycle; triggered alerts are stored
//! in an `Arc<RwLock<VecDeque<AlertRecord>>>` (capped at `MAX_ALERTS`).
//!
//! Optional webhook (`webhook_url`) receives a JSON POST for every new alert.

use crate::telemetry::bandwidth::{AlertLevel, BandwidthAlert, BandwidthTracker};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

/// Maximum number of alerts retained in the rolling in-memory log.
/// Oldest alerts are evicted when this cap is reached.
const MAX_ALERTS: usize = 500;

// ─── Alert Record ─────────────────────────────────────────────────────────────

/// A single alert event stored in the rolling log.
///
/// Contains the threshold that was exceeded, the observed value, and
/// human-readable context (protocol, metric name, message).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AlertRecord {
    /// Unix epoch seconds when the alert was created.
    pub timestamp: u64,
    /// Severity: `"info"`, `"warning"`, or `"critical"`.
    pub level: String,
    /// Alert category: `"bandwidth"` or `"system"`.
    pub category: String,
    /// Protocol label (e.g. `"http1"`, `"tcp"`, `"system"`).
    pub protocol: String,
    /// Metric name that triggered the alert (e.g. `"bandwidth"`, `"connections"`, `"memory"`).
    pub metric: String,
    /// Human-readable description of the alert.
    pub message: String,
    /// Observed value at the time the alert fired.
    pub value: f64,
    /// Threshold value that was exceeded.
    pub threshold: f64,
}

impl AlertRecord {
    /// Converts a bandwidth threshold violation into a generic `AlertRecord`.
    fn from_bandwidth(alert: &BandwidthAlert) -> Self {
        Self {
            timestamp: now_unix(),
            level: match alert.level {
                AlertLevel::Info => "info",
                AlertLevel::Warning => "warning",
                AlertLevel::Critical => "critical",
            }
            .to_string(),
            category: "bandwidth".to_string(),
            protocol: alert.protocol.clone(),
            metric: alert.metric.clone(),
            message: alert.message.clone(),
            value: alert.value,
            threshold: alert.threshold,
        }
    }

    /// Creates a system-level alert (memory, file descriptors, etc.).
    fn system(level: &str, metric: &str, message: String, value: f64, threshold: f64) -> Self {
        Self {
            timestamp: now_unix(),
            level: level.to_string(),
            category: "system".to_string(),
            protocol: "system".to_string(),
            metric: metric.to_string(),
            message,
            value,
            threshold,
        }
    }
}

// ─── System Thresholds ────────────────────────────────────────────────────────

/// Process-level resource thresholds.
#[derive(Clone)]
pub struct SystemThresholds {
    /// RSS memory (bytes) above which a warning fires.
    pub memory_warn_bytes: u64,
    pub memory_critical_bytes: u64,
    /// Open file descriptors above which a warning fires.
    pub fd_warn: u64,
    pub fd_critical: u64,
}

impl Default for SystemThresholds {
    fn default() -> Self {
        Self {
            memory_warn_bytes: 512 * 1024 * 1024,       // 512 MiB
            memory_critical_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
            fd_warn: 10_000,
            fd_critical: 60_000,
        }
    }
}

// ─── Alert Engine ─────────────────────────────────────────────────────────────

/// Monitors bandwidth, memory, and file-descriptor thresholds and records
/// triggered alerts into a capped rolling log.
///
/// Alerts can also be delivered to an external webhook (best-effort HTTP POST).
pub struct AlertEngine {
    /// Bandwidth tracker supplying per-protocol traffic counters.
    bandwidth: Arc<BandwidthTracker>,
    /// Configurable system-level thresholds (memory, FD counts).
    system_thresholds: SystemThresholds,
    /// Rolling in-memory alert log, capped at `MAX_ALERTS` entries.
    log: Arc<RwLock<VecDeque<AlertRecord>>>,
    /// Optional webhook URL for external alert delivery.
    webhook_url: Option<String>,
}

impl AlertEngine {
    /// Creates a new `AlertEngine` with default system thresholds and no webhook.
    pub fn new(bandwidth: Arc<BandwidthTracker>) -> Arc<Self> {
        Arc::new(Self {
            bandwidth,
            system_thresholds: SystemThresholds::default(),
            log: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_ALERTS))),
            webhook_url: None,
        })
    }

    /// Returns a new `AlertEngine` clone with the specified webhook URL enabled.
    pub fn with_webhook(self: Arc<Self>, url: String) -> Arc<Self> {
        Arc::new(Self {
            bandwidth: Arc::clone(&self.bandwidth),
            system_thresholds: self.system_thresholds.clone(),
            log: Arc::clone(&self.log),
            webhook_url: Some(url),
        })
    }

    /// Run one check cycle: bandwidth thresholds + process memory + open FDs.
    /// New alerts are appended to the rolling log.
    pub async fn check(&self) {
        let mut new_alerts: Vec<AlertRecord> = Vec::new();

        // --- Bandwidth ---
        for ba in self.bandwidth.check_thresholds() {
            new_alerts.push(AlertRecord::from_bandwidth(&ba));
        }

        // --- Process memory (Linux: /proc/self/status) ---
        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("VmRSS:") {
                        if let Some(kb_str) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = kb_str.parse::<u64>() {
                                let bytes = kb * 1024;
                                if bytes >= self.system_thresholds.memory_critical_bytes {
                                    new_alerts.push(AlertRecord::system(
                                        "critical",
                                        "memory",
                                        format!(
                                            "Process RSS {:.1} GiB exceeds critical threshold",
                                            bytes as f64 / (1024.0 * 1024.0 * 1024.0)
                                        ),
                                        bytes as f64,
                                        self.system_thresholds.memory_critical_bytes as f64,
                                    ));
                                } else if bytes >= self.system_thresholds.memory_warn_bytes {
                                    new_alerts.push(AlertRecord::system(
                                        "warning",
                                        "memory",
                                        format!(
                                            "Process RSS {:.1} MiB exceeds warning threshold",
                                            bytes as f64 / (1024.0 * 1024.0)
                                        ),
                                        bytes as f64,
                                        self.system_thresholds.memory_warn_bytes as f64,
                                    ));
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }

        // --- Process memory (macOS: libc::getrusage) ---
        #[cfg(target_os = "macos")]
        {
            let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
            let ret = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
            if ret == 0 {
                // macOS reports ru_maxrss in bytes
                let bytes = usage.ru_maxrss as u64;
                if bytes >= self.system_thresholds.memory_critical_bytes {
                    new_alerts.push(AlertRecord::system(
                        "critical",
                        "memory",
                        format!(
                            "Process RSS {:.1} GiB exceeds critical threshold",
                            bytes as f64 / (1024.0 * 1024.0 * 1024.0)
                        ),
                        bytes as f64,
                        self.system_thresholds.memory_critical_bytes as f64,
                    ));
                } else if bytes >= self.system_thresholds.memory_warn_bytes {
                    new_alerts.push(AlertRecord::system(
                        "warning",
                        "memory",
                        format!(
                            "Process RSS {:.1} MiB exceeds warning threshold",
                            bytes as f64 / (1024.0 * 1024.0)
                        ),
                        bytes as f64,
                        self.system_thresholds.memory_warn_bytes as f64,
                    ));
                }
            }
        }

        // --- Open file descriptors (Linux: /proc/self/fd) ---
        #[cfg(target_os = "linux")]
        {
            if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
                let fd_count = entries.count() as u64;
                if fd_count >= self.system_thresholds.fd_critical {
                    new_alerts.push(AlertRecord::system(
                        "critical",
                        "file_descriptors",
                        format!(
                            "Open FD count {} exceeds critical threshold {}",
                            fd_count, self.system_thresholds.fd_critical
                        ),
                        fd_count as f64,
                        self.system_thresholds.fd_critical as f64,
                    ));
                } else if fd_count >= self.system_thresholds.fd_warn {
                    new_alerts.push(AlertRecord::system(
                        "warning",
                        "file_descriptors",
                        format!(
                            "Open FD count {} exceeds warning threshold {}",
                            fd_count, self.system_thresholds.fd_warn
                        ),
                        fd_count as f64,
                        self.system_thresholds.fd_warn as f64,
                    ));
                }
            }
        }

        // --- Open file descriptors (macOS: /dev/fd) ---
        #[cfg(target_os = "macos")]
        {
            if let Ok(entries) = std::fs::read_dir("/dev/fd") {
                let fd_count = entries.count() as u64;
                if fd_count >= self.system_thresholds.fd_critical {
                    new_alerts.push(AlertRecord::system(
                        "critical",
                        "file_descriptors",
                        format!(
                            "Open FD count {} exceeds critical threshold {}",
                            fd_count, self.system_thresholds.fd_critical
                        ),
                        fd_count as f64,
                        self.system_thresholds.fd_critical as f64,
                    ));
                } else if fd_count >= self.system_thresholds.fd_warn {
                    new_alerts.push(AlertRecord::system(
                        "warning",
                        "file_descriptors",
                        format!(
                            "Open FD count {} exceeds warning threshold {}",
                            fd_count, self.system_thresholds.fd_warn
                        ),
                        fd_count as f64,
                        self.system_thresholds.fd_warn as f64,
                    ));
                }
            }
        }

        if new_alerts.is_empty() {
            return;
        }

        // Append to rolling log
        {
            let mut log = self.log.write().await;
            for alert in &new_alerts {
                if log.len() >= MAX_ALERTS {
                    log.pop_front();
                }
                log.push_back(alert.clone());
            }
        }

        // Fire webhooks in background (non-blocking)
        if let Some(ref url) = self.webhook_url {
            for alert in new_alerts {
                let url = url.clone();
                tokio::spawn(async move {
                    send_webhook(&url, &alert).await;
                });
            }
        }
    }

    /// Returns the most recent `n` alerts (newest first).
    pub async fn recent(&self, n: usize) -> Vec<AlertRecord> {
        let log = self.log.read().await;
        log.iter().rev().take(n).cloned().collect()
    }

    /// Total alert count stored.
    pub async fn count(&self) -> usize {
        self.log.read().await.len()
    }

    /// Spawn a background task that calls `check()` every `interval_secs` seconds.
    pub fn spawn_background_check(self: Arc<Self>, interval_secs: u64) {
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                self.check().await;
            }
        });
    }
}

// ─── Webhook Delivery ─────────────────────────────────────────────────────────

/// Best-effort HTTP POST of a serialised alert to the configured webhook URL.
/// Failures are logged but not retried.
async fn send_webhook(url: &str, alert: &AlertRecord) {
    let payload = match serde_json::to_string(alert) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Alert webhook serialisation failed: {}", e);
            return;
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Alert webhook client build failed: {}", e);
            return;
        }
    };

    match client
        .post(url)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                tracing::debug!("Alert webhook delivered to {}", url);
            } else {
                tracing::warn!(
                    "Alert webhook to {} returned HTTP {}",
                    url,
                    resp.status()
                );
            }
        }
        Err(e) => {
            tracing::warn!("Alert webhook POST to {} failed: {}", url, e);
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Returns the current time as Unix epoch seconds.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::bandwidth::{BandwidthTracker, ProtocolThreshold};

    fn make_engine() -> Arc<AlertEngine> {
        let tracker = BandwidthTracker::new();
        AlertEngine::new(tracker)
    }

    fn make_engine_with_thresholds(
        bandwidth: Arc<BandwidthTracker>,
        thresholds: SystemThresholds,
    ) -> Arc<AlertEngine> {
        Arc::new(AlertEngine {
            bandwidth,
            system_thresholds: thresholds,
            log: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_ALERTS))),
            webhook_url: None,
        })
    }

    #[tokio::test]
    async fn test_no_alerts_when_below_thresholds() {
        let engine = make_engine();
        engine.check().await;
        assert_eq!(engine.count().await, 0);
    }

    #[tokio::test]
    async fn test_bandwidth_alert_fires() {
        let tracker = BandwidthTracker::new();
        tracker.set_threshold("tcp", ProtocolThreshold {
            bandwidth_bps_warn: 100,
            bandwidth_bps_critical: 1_000_000,
            connections_warn: 999_999,
            connections_critical: 9_999_999,
        });
        tracker.protocol("tcp").add_in(200);
        let engine = AlertEngine::new(tracker);
        engine.check().await;
        assert!(engine.count().await > 0);
        let recent = engine.recent(10).await;
        assert!(recent.iter().any(|a| a.protocol == "tcp" && a.metric == "bandwidth"));
    }

    #[tokio::test]
    async fn test_connection_alert_fires() {
        let tracker = BandwidthTracker::new();
        tracker.set_threshold("websocket", ProtocolThreshold {
            bandwidth_bps_warn: u64::MAX,
            bandwidth_bps_critical: u64::MAX,
            connections_warn: 1,
            connections_critical: 100,
        });
        tracker.protocol("websocket").conn_open();
        tracker.protocol("websocket").conn_open();
        let engine = AlertEngine::new(tracker);
        engine.check().await;
        let recent = engine.recent(10).await;
        assert!(recent.iter().any(|a| a.protocol == "websocket" && a.metric == "connections"));
    }

    #[tokio::test]
    async fn test_recent_returns_newest_first() {
        let tracker = BandwidthTracker::new();
        // Trigger alerts on two protocols with tiny thresholds
        for proto in &["http1", "http2"] {
            tracker.set_threshold(proto, ProtocolThreshold {
                bandwidth_bps_warn: 1,
                bandwidth_bps_critical: u64::MAX,
                connections_warn: 999_999,
                connections_critical: 9_999_999,
            });
            tracker.protocol(proto).add_in(10);
        }
        let engine = AlertEngine::new(tracker);
        engine.check().await;
        let recent = engine.recent(5).await;
        assert!(recent.len() >= 2);
        // Newest first: timestamps should be non-increasing
        for w in recent.windows(2) {
            assert!(w[0].timestamp >= w[1].timestamp);
        }
    }

    #[tokio::test]
    async fn test_rolling_log_caps_at_max() {
        let tracker = BandwidthTracker::new();
        // Set low threshold on many protocols to generate lots of alerts
        for i in 0..10 {
            let proto = format!("proto_{}", i);
            tracker.set_threshold(&proto, ProtocolThreshold {
                bandwidth_bps_warn: 1,
                bandwidth_bps_critical: u64::MAX,
                connections_warn: 999_999,
                connections_critical: 9_999_999,
            });
            tracker.protocol(&proto).add_in(5);
        }
        let engine = AlertEngine::new(Arc::clone(&tracker));
        // Run many cycles
        for _ in 0..60 {
            engine.check().await;
        }
        assert!(engine.count().await <= MAX_ALERTS);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_macos_system_monitoring_runs() {
        let tracker = BandwidthTracker::new();
        let engine = make_engine_with_thresholds(
            tracker,
            SystemThresholds {
                memory_warn_bytes: 1,       // 1 byte — will always trigger
                memory_critical_bytes: u64::MAX,
                fd_warn: 1,                 // 1 FD — will always trigger
                fd_critical: u64::MAX,
            },
        );
        engine.check().await;
        let recent = engine.recent(10).await;
        assert!(recent.iter().any(|a| a.category == "system" && a.metric == "memory"));
        assert!(recent.iter().any(|a| a.category == "system" && a.metric == "file_descriptors"));
    }

    #[tokio::test]
    async fn test_alert_record_fields() {
        let tracker = BandwidthTracker::new();
        tracker.set_threshold("grpc", ProtocolThreshold {
            bandwidth_bps_warn: 1,
            bandwidth_bps_critical: u64::MAX,
            connections_warn: 999_999,
            connections_critical: 9_999_999,
        });
        tracker.protocol("grpc").add_in(50);
        let engine = AlertEngine::new(tracker);
        engine.check().await;
        let recent = engine.recent(1).await;
        assert_eq!(recent.len(), 1);
        let r = &recent[0];
        assert_eq!(r.category, "bandwidth");
        assert_eq!(r.protocol, "grpc");
        assert!(r.timestamp > 0);
        assert!(r.value > 0.0);
    }
}
