//! GeoIP database, country-based access policies, and request header enrichment.
//!
//! Loads CIDR-to-country mappings from a CSV file and provides O(n) lookup
//! with an in-memory cache for hot IPs. Policies can allow or deny traffic
//! by country code. Matched results are injected as `X-Geo-Country-Code` and
//! `X-Geo-Country` headers for upstream consumption.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

/// GeoIP-based access control and request enrichment.
///
/// Uses a simple CSV-based database of CIDR → country code mappings.
/// For production, integrate MaxMind GeoLite2 via the `maxminddb` crate.
pub struct GeoIpDatabase {
    /// IP range → country code lookup table (hot-swappable via ArcSwap for SIGHUP reload)
    entries: ArcSwap<Vec<GeoEntry>>,
    /// Cached lookups for hot IPs
    cache: DashMap<IpAddr, GeoResult>,
}

/// Internal representation of a CIDR range and its associated country.
#[derive(Clone)]
struct GeoEntry {
    /// Network address as a 128-bit integer (IPv4 uses the low 32 bits).
    network: u128,
    /// Bitmask derived from the CIDR prefix length.
    mask: u128,
    /// `true` for IPv4 entries, `false` for IPv6.
    is_v4: bool,
    /// ISO 3166-1 alpha-2 country code (upper-case).
    country_code: String,
    /// Human-readable country name.
    country_name: String,
}

#[derive(Debug, Clone)]
pub struct GeoResult {
    pub country_code: String,
    pub country_name: String,
}

/// GeoIP access policy: allow or deny by country code.
#[derive(Debug, Clone)]
pub struct GeoPolicy {
    /// If non-empty, only these country codes are allowed.
    pub allow_countries: Vec<String>,
    /// These country codes are always denied (takes precedence).
    pub deny_countries: Vec<String>,
}

impl GeoPolicy {
    pub fn new() -> Self {
        Self {
            allow_countries: Vec::new(),
            deny_countries: Vec::new(),
        }
    }

    /// Returns `true` if the country code is allowed by this policy.
    pub fn is_allowed(&self, country_code: &str) -> bool {
        let code = country_code.to_uppercase();

        if self.deny_countries.iter().any(|c| c.to_uppercase() == code) {
            return false;
        }

        if self.allow_countries.is_empty() {
            return true;
        }

        self.allow_countries.iter().any(|c| c.to_uppercase() == code)
    }
}

impl GeoIpDatabase {
    /// Creates an empty GeoIP database.
    pub fn new() -> Self {
        Self {
            entries: ArcSwap::from_pointee(Vec::new()),
            cache: DashMap::new(),
        }
    }

    /// Loads GeoIP data from a simple CSV file.
    /// Format: `cidr,country_code,country_name`
    /// Example: `1.0.0.0/24,AU,Australia`
    pub fn load_csv(&mut self, path: &str) -> Result<(), String> {
        let new_entries = Self::parse_csv_file(path)?;
        let count = new_entries.len();
        self.entries.store(Arc::new(new_entries));
        info!("Loaded {} GeoIP entries from {}", count, path);
        Ok(())
    }

    /// Reloads the GeoIP database from a CSV file, atomically swapping entries
    /// and clearing the lookup cache. On error, the existing database is preserved.
    pub fn reload(&self, path: &str) -> Result<(), String> {
        let new_entries = Self::parse_csv_file(path)?;
        let count = new_entries.len();
        self.entries.store(Arc::new(new_entries));
        self.cache.clear();
        info!("GeoIP database reloaded: {} entries from {}", count, path);
        Ok(())
    }

    /// Parses a CSV file into a Vec of GeoEntry (shared by load_csv and reload).
    fn parse_csv_file(path: &str) -> Result<Vec<GeoEntry>, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;

        let mut entries = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, ',').collect();
            if parts.len() < 3 {
                continue;
            }

            if let Some(entry) = parse_geo_entry(parts[0], parts[1], parts[2]) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /// Looks up the country for an IP address.
    pub fn lookup(&self, ip: &IpAddr) -> Option<GeoResult> {
        if let Some(cached) = self.cache.get(ip) {
            return Some(cached.clone());
        }

        let ip_bits = ip_to_u128(ip);
        let is_v4 = ip.is_ipv4();
        let entries = self.entries.load();

        for entry in entries.iter() {
            if entry.is_v4 != is_v4 {
                continue;
            }
            if (ip_bits & entry.mask) == entry.network {
                let result = GeoResult {
                    country_code: entry.country_code.clone(),
                    country_name: entry.country_name.clone(),
                };
                self.cache.insert(*ip, result.clone());
                return Some(result);
            }
        }

        None
    }

    /// Adds custom geo entries from config (for simple setups without an external DB).
    pub fn add_entry(&self, cidr: &str, country_code: &str, country_name: &str) {
        if let Some(entry) = parse_geo_entry(cidr, country_code, country_name) {
            let mut entries: Vec<GeoEntry> = (**self.entries.load()).clone();
            entries.push(entry);
            self.entries.store(Arc::new(entries));
        }
    }
}

/// Parses a CIDR string (e.g. `"1.0.0.0/24"`) into a `GeoEntry` with the
/// computed network address and bitmask. Returns `None` if the CIDR is invalid.
fn parse_geo_entry(cidr: &str, code: &str, name: &str) -> Option<GeoEntry> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    let ip: IpAddr = addr_str.trim().parse().ok()?;
    let prefix_len: u8 = prefix_str.trim().parse().ok()?;
    let is_v4 = ip.is_ipv4();

    let ip_bits = ip_to_u128(&ip);
    let max_bits = if is_v4 { 32u8 } else { 128u8 };
    if prefix_len > max_bits {
        return None;
    }

    let mask = if prefix_len == 0 {
        0u128
    } else if is_v4 {
        let m32 = u32::MAX << (32 - prefix_len);
        m32 as u128
    } else {
        u128::MAX << (128 - prefix_len)
    };

    Some(GeoEntry {
        network: ip_bits & mask,
        mask,
        is_v4,
        country_code: code.trim().to_uppercase(),
        country_name: name.trim().to_string(),
    })
}

/// Converts an `IpAddr` to a 128-bit integer for bitwise CIDR matching.
/// IPv4 addresses occupy the low 32 bits.
fn ip_to_u128(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from(*v4) as u128,
        IpAddr::V6(v6) => u128::from(*v6),
    }
}

/// Injects GeoIP headers into the request for upstream consumption.
pub fn inject_geo_headers(headers: &mut hyper::HeaderMap, geo: &GeoResult) {
    if let Ok(val) = geo.country_code.parse() {
        headers.insert(
            hyper::header::HeaderName::from_static("x-geo-country-code"),
            val,
        );
    }
    if let Ok(val) = geo.country_name.parse() {
        headers.insert(
            hyper::header::HeaderName::from_static("x-geo-country"),
            val,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_policy_deny() {
        let mut policy = GeoPolicy::new();
        policy.deny_countries = vec!["CN".to_string(), "RU".to_string()];
        assert!(!policy.is_allowed("CN"));
        assert!(!policy.is_allowed("RU"));
        assert!(policy.is_allowed("US"));
    }

    #[test]
    fn test_geo_policy_allow_list() {
        let mut policy = GeoPolicy::new();
        policy.allow_countries = vec!["US".to_string(), "GB".to_string()];
        assert!(policy.is_allowed("US"));
        assert!(policy.is_allowed("GB"));
        assert!(!policy.is_allowed("FR"));
    }

    #[test]
    fn test_geo_lookup() {
        let db = GeoIpDatabase::new();
        db.add_entry("1.0.0.0/24", "AU", "Australia");
        db.add_entry("8.8.8.0/24", "US", "United States");

        let result = db.lookup(&"1.0.0.1".parse().unwrap());
        assert!(result.is_some());
        assert_eq!(result.unwrap().country_code, "AU");

        let result = db.lookup(&"8.8.8.8".parse().unwrap());
        assert!(result.is_some());
        assert_eq!(result.unwrap().country_code, "US");
    }

    #[test]
    fn test_geo_reload_missing_file() {
        let db = GeoIpDatabase::new();
        db.add_entry("1.0.0.0/24", "AU", "Australia");

        // Reload with nonexistent file should return error
        let result = db.reload("/nonexistent/geo.csv");
        assert!(result.is_err());

        // Existing entries should still be intact
        let lookup = db.lookup(&"1.0.0.1".parse().unwrap());
        assert!(lookup.is_some());
        assert_eq!(lookup.unwrap().country_code, "AU");
    }

    #[test]
    fn test_geo_add_entry_clears_not_needed_for_new_entries() {
        let db = GeoIpDatabase::new();
        db.add_entry("1.0.0.0/24", "AU", "Australia");
        db.add_entry("8.8.8.0/24", "US", "United States");

        // Both should be lookupable
        assert!(db.lookup(&"1.0.0.1".parse().unwrap()).is_some());
        assert!(db.lookup(&"8.8.8.8".parse().unwrap()).is_some());
    }
}
