/// IP reputation and automatic ban management.
///
/// Tracks per-IP "strike" points accumulated from WAF violations. When an IP
/// exceeds the configured threshold, it is automatically banned for a
/// configurable duration. Bans expire automatically (checked lazily on
/// next lookup). Optionally broadcasts strikes to other cluster nodes
/// via Redis Pub/Sub for consistent enforcement across a fleet.
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

/// Thread-safe IP reputation manager that tracks strikes and enforces bans.
///
/// Strikes are weighted by severity (e.g., SQLi = 3, missing User-Agent = 1).
/// Once strikes exceed `ban_threshold`, the IP is considered banned until
/// `ban_duration_secs` elapse since the last strike.
pub struct IpReputationManager {
    /// Tracks (strike_count, last_strike_time) for each IP Address
    strikes: DashMap<String, (u32, Instant)>,
    /// Threshold of strikes before an auto-ban is enacted
    ban_threshold: u32,
    /// How long a ban lasts (in seconds) before the IP is automatically unbanned
    ban_duration_secs: u64,
    /// Optional Redis client to broadcast strikes to cluster
    redis_client: Option<redis::Client>,
}

impl IpReputationManager {
    /// Creates a new reputation manager and optionally starts a Redis Pub/Sub subscriber.
    ///
    /// # Arguments
    /// * `ban_threshold` - Number of strike points before an IP is auto-banned.
    /// * `ban_duration_secs` - How long a ban lasts before automatic expiry.
    /// * `redis_client` - Optional Redis client for cluster-wide strike propagation.
    ///
    /// Returns an `Arc<Self>` because the manager is shared across request handlers
    /// and the optional background Pub/Sub task.
    pub fn new(ban_threshold: u32, ban_duration_secs: u64, redis_client: Option<redis::Client>) -> Arc<Self> {
        let mgr = Arc::new(Self {
            strikes: DashMap::new(),
            ban_threshold,
            ban_duration_secs,
            redis_client: redis_client.clone(),
        });

        // If Redis is enabled, spawn a pubsub subscriber task
        if let Some(client) = redis_client {
            let mgr_clone = Arc::clone(&mgr);
            tokio::spawn(async move {
                if let Ok(mut pubsub) = client.get_async_pubsub().await {
                    if pubsub.subscribe("phalanx:waf:strikes").await.is_ok() {
                        let mut stream = pubsub.on_message();
                        use futures_util::StreamExt;
                        while let Some(msg) = stream.next().await {
                            if let Ok(payload) = msg.get_payload::<String>() {
                                // Payload format: "ip:severity"
                                if let Some((ip, severity)) = payload.split_once(':') {
                                    if let Ok(sev) = severity.parse::<u32>() {
                                        mgr_clone.add_strike_local(ip, sev);
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        mgr
    }

    /// Increments the strike count for an IP locally without broadcasting.
    pub fn add_strike_local(&self, ip: &str, severity: u32) {
        let mut entry = self
            .strikes
            .entry(ip.to_string())
            .or_insert((0, Instant::now()));
        entry.0 = entry.0.saturating_add(severity);
        entry.1 = Instant::now();
    }

    /// Increments the strike count for an IP by the given severity amount.
    /// Also broadcasts to Redis cluster if enabled.
    pub fn add_strike(&self, ip: &str, severity: u32) {
        self.add_strike_local(ip, severity);
        
        // Broadcast to cluster
        if let Some(client) = &self.redis_client {
            let ip_str = ip.to_string();
            let client_clone = client.clone();
            tokio::spawn(async move {
                if let Ok(mut con) = client_clone.get_multiplexed_async_connection().await {
                    use redis::AsyncCommands;
                    let payload = format!("{}:{}", ip_str, severity);
                    let _: redis::RedisResult<()> = con.publish("phalanx:waf:strikes", payload).await;
                }
            });
        }
    }

    /// Checks if the IP has exceeded the ban threshold.
    /// If the ban has expired (older than `ban_duration_secs`), the strikes are
    /// automatically cleared and the IP is unbanned.
    pub fn is_banned(&self, ip: &str) -> bool {
        if let Some(entry) = self.strikes.get(ip) {
            let (count, last_time) = *entry;
            if count >= self.ban_threshold {
                // Check if the ban has expired
                if last_time.elapsed().as_secs() >= self.ban_duration_secs {
                    // Ban expired — clear strikes and allow
                    drop(entry);
                    self.strikes.remove(ip);
                    tracing::info!(
                        "IP {} ban expired after {}s, strikes cleared.",
                        ip,
                        self.ban_duration_secs
                    );
                    return false;
                }
                return true; // Still banned
            }
        }
        false
    }

    /// Returns the current strike count for an IP (0 if not tracked).
    pub fn get_strikes(&self, ip: &str) -> u32 {
        self.strikes.get(ip).map(|e| e.0).unwrap_or(0)
    }

    /// Returns all currently-banned IPs with their strike count and seconds remaining.
    pub fn list_bans(&self) -> Vec<(String, u32, u64)> {
        let _now = std::time::Instant::now();
        self.strikes
            .iter()
            .filter_map(|entry| {
                let (count, last_time) = *entry.value();
                if count >= self.ban_threshold {
                    let elapsed = last_time.elapsed().as_secs();
                    if elapsed < self.ban_duration_secs {
                        let remaining = self.ban_duration_secs - elapsed;
                        Some((entry.key().clone(), count, remaining))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Removes an IP from the ban list (clears all strikes).
    pub fn unban(&self, ip: &str) {
        self.strikes.remove(ip);
        tracing::info!("IP {} manually unbanned", ip);
    }

    /// Immediately bans an IP by setting its strikes to the threshold.
    pub fn manual_ban(&self, ip: &str) {
        self.strikes
            .entry(ip.to_string())
            .and_modify(|e| { e.0 = self.ban_threshold; e.1 = std::time::Instant::now(); })
            .or_insert((self.ban_threshold, std::time::Instant::now()));
        tracing::info!("IP {} manually banned", ip);
    }

    /// Returns strike count for all tracked IPs (not just banned ones), sorted by count descending.
    pub fn list_all_strikes(&self) -> Vec<(String, u32)> {
        let mut result: Vec<(String, u32)> = self.strikes
            .iter()
            .map(|e| (e.key().clone(), e.value().0))
            .collect();
        result.sort_by(|a, b| b.1.cmp(&a.1));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_initial_state_no_strikes() {
        let mgr = IpReputationManager::new(5, 60, None);
        assert_eq!(mgr.get_strikes("1.2.3.4"), 0);
        assert!(!mgr.is_banned("1.2.3.4"));
    }

    #[tokio::test]
    async fn test_add_strike_increments() {
        let mgr = IpReputationManager::new(10, 60, None);
        mgr.add_strike("1.2.3.4", 3);
        assert_eq!(mgr.get_strikes("1.2.3.4"), 3);
        mgr.add_strike("1.2.3.4", 2);
        assert_eq!(mgr.get_strikes("1.2.3.4"), 5);
    }

    #[tokio::test]
    async fn test_ban_threshold_reached() {
        let mgr = IpReputationManager::new(5, 3600, None);
        for _ in 0..5 {
            mgr.add_strike("evil", 1);
        }
        assert!(mgr.is_banned("evil"));
    }

    #[tokio::test]
    async fn test_below_ban_threshold() {
        let mgr = IpReputationManager::new(5, 3600, None);
        mgr.add_strike("normal", 4);
        assert!(!mgr.is_banned("normal"));
    }

    #[tokio::test]
    async fn test_ban_expiry() {
        let mgr = IpReputationManager::new(1, 0, None);
        mgr.add_strike("temp", 1);
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(!mgr.is_banned("temp"), "ban should have expired");
        assert_eq!(mgr.get_strikes("temp"), 0, "strikes should be cleared on expiry");
    }

    #[tokio::test]
    async fn test_different_ips_independent() {
        let mgr = IpReputationManager::new(3, 3600, None);
        mgr.add_strike("a", 5);
        mgr.add_strike("b", 1);
        assert!(mgr.is_banned("a"));
        assert!(!mgr.is_banned("b"));
    }

    #[tokio::test]
    async fn test_severity_multiplier() {
        let mgr = IpReputationManager::new(10, 3600, None);
        mgr.add_strike("high", 10);
        assert!(mgr.is_banned("high"));
    }

    #[tokio::test]
    async fn test_list_bans_empty() {
        let mgr = IpReputationManager::new(5, 3600, None);
        assert!(mgr.list_bans().is_empty());
    }

    #[tokio::test]
    async fn test_list_bans_returns_banned_ips() {
        let mgr = IpReputationManager::new(3, 3600, None);
        mgr.add_strike("1.2.3.4", 3);
        mgr.add_strike("5.6.7.8", 1);
        let bans = mgr.list_bans();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, "1.2.3.4");
        assert_eq!(bans[0].1, 3);
        assert!(bans[0].2 <= 3600);
    }

    #[tokio::test]
    async fn test_unban_removes_ip() {
        let mgr = IpReputationManager::new(3, 3600, None);
        mgr.add_strike("victim", 5);
        assert!(mgr.is_banned("victim"));
        mgr.unban("victim");
        assert!(!mgr.is_banned("victim"));
        assert_eq!(mgr.get_strikes("victim"), 0);
    }

    #[tokio::test]
    async fn test_manual_ban() {
        let mgr = IpReputationManager::new(5, 3600, None);
        assert!(!mgr.is_banned("target"));
        mgr.manual_ban("target");
        assert!(mgr.is_banned("target"));
    }

    #[tokio::test]
    async fn test_list_all_strikes_sorted() {
        let mgr = IpReputationManager::new(100, 3600, None);
        mgr.add_strike("a", 10);
        mgr.add_strike("b", 30);
        mgr.add_strike("c", 20);
        let strikes = mgr.list_all_strikes();
        assert_eq!(strikes[0].0, "b");
        assert_eq!(strikes[1].0, "c");
        assert_eq!(strikes[2].0, "a");
    }
}
