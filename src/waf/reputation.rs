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
