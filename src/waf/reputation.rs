use dashmap::DashMap;
use std::time::Instant;

#[derive(Clone)]
pub struct IpReputationManager {
    /// Tracks (strike_count, last_strike_time) for each IP Address
    strikes: DashMap<String, (u32, Instant)>,
    /// Threshold of strikes before an auto-ban is enacted
    ban_threshold: u32,
    /// How long a ban lasts (in seconds) before the IP is automatically unbanned
    ban_duration_secs: u64,
}

impl IpReputationManager {
    pub fn new(ban_threshold: u32, ban_duration_secs: u64) -> Self {
        Self {
            strikes: DashMap::new(),
            ban_threshold,
            ban_duration_secs,
        }
    }

    /// Increments the strike count for an IP by the given severity amount.
    /// Also updates the timestamp to track when the last strike occurred.
    pub fn add_strike(&self, ip: &str, severity: u32) {
        let mut entry = self
            .strikes
            .entry(ip.to_string())
            .or_insert((0, Instant::now()));
        entry.0 = entry.0.saturating_add(severity);
        entry.1 = Instant::now();
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state_no_strikes() {
        let mgr = IpReputationManager::new(5, 60);
        assert_eq!(mgr.get_strikes("1.2.3.4"), 0);
        assert!(!mgr.is_banned("1.2.3.4"));
    }

    #[test]
    fn test_add_strike_increments() {
        let mgr = IpReputationManager::new(10, 60);
        mgr.add_strike("1.2.3.4", 3);
        assert_eq!(mgr.get_strikes("1.2.3.4"), 3);
        mgr.add_strike("1.2.3.4", 2);
        assert_eq!(mgr.get_strikes("1.2.3.4"), 5);
    }

    #[test]
    fn test_ban_threshold_reached() {
        let mgr = IpReputationManager::new(5, 3600);
        for _ in 0..5 {
            mgr.add_strike("evil", 1);
        }
        assert!(mgr.is_banned("evil"));
    }

    #[test]
    fn test_below_ban_threshold() {
        let mgr = IpReputationManager::new(5, 3600);
        mgr.add_strike("normal", 4);
        assert!(!mgr.is_banned("normal"));
    }

    #[test]
    fn test_ban_expiry() {
        let mgr = IpReputationManager::new(1, 0);
        mgr.add_strike("temp", 1);
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(!mgr.is_banned("temp"), "ban should have expired");
        assert_eq!(mgr.get_strikes("temp"), 0, "strikes should be cleared on expiry");
    }

    #[test]
    fn test_different_ips_independent() {
        let mgr = IpReputationManager::new(3, 3600);
        mgr.add_strike("a", 5);
        mgr.add_strike("b", 1);
        assert!(mgr.is_banned("a"));
        assert!(!mgr.is_banned("b"));
    }

    #[test]
    fn test_severity_multiplier() {
        let mgr = IpReputationManager::new(10, 3600);
        mgr.add_strike("high", 10);
        assert!(mgr.is_banned("high"));
    }
}
