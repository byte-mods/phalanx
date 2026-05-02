//! GeoIP database, country-based access policies, and request header enrichment.
//!
//! Lookups use a binary radix trie for O(bit-length) performance — 32 steps
//! for IPv4, 128 steps for IPv6 — regardless of database size.  The trie
//! lives behind an `ArcSwap` so SIGHUP reloads are lock-free.  A `DashMap`
//! caches hot-IP results to avoid repeated trie walks.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

// ── Binary radix trie ──────────────────────────────────────────────────────

/// A node in the binary radix trie.  Children are indexed by bit value (0 or 1).
/// A node that carries `country_code` represents a CIDR prefix endpoint.
#[derive(Clone, Default)]
struct GeoTrieNode {
    children: [Option<Box<GeoTrieNode>>; 2],
    country_code: Option<String>,
    country_name: Option<String>,
}

/// Complete binary radix trie with separate IPv4 and IPv6 roots.
#[derive(Clone, Default)]
struct GeoTrie {
    v4_root: GeoTrieNode,
    v6_root: GeoTrieNode,
}

impl GeoTrie {
    /// Insert a CIDR range with its country metadata.
    fn insert(&mut self, network: u128, _mask: u128, prefix_len: u8, is_v4: bool, code: &str, name: &str) {
        let root = if is_v4 { &mut self.v4_root } else { &mut self.v6_root };
        let total_bits: u8 = if is_v4 { 32 } else { 128 };
        let mut node = root;

        for i in (0..total_bits).rev() {
            if i >= total_bits - prefix_len {
                let bit = ((network >> i) & 1) as usize;
                if node.children[bit].is_none() {
                    node.children[bit] = Some(Box::new(GeoTrieNode::default()));
                }
                node = node.children[bit].as_mut().unwrap();
            } else {
                break;
            }
        }

        node.country_code = Some(code.to_string());
        node.country_name = Some(name.to_string());
    }

    /// Longest-prefix-match lookup.  Walks the trie bit by bit, recording the
    /// last-seen country data at each node — that gives the most-specific match.
    fn lookup(&self, ip: &IpAddr) -> Option<(String, String)> {
        let is_v4 = ip.is_ipv4();
        let root = if is_v4 { &self.v4_root } else { &self.v6_root };
        let total_bits: u8 = if is_v4 { 32 } else { 128 };
        let ip_bits = ip_to_u128(ip);

        let mut node = root;
        let mut last_code: Option<&str> = node.country_code.as_deref();
        let mut last_name: Option<&str> = node.country_name.as_deref();

        for i in (0..total_bits).rev() {
            let bit = ((ip_bits >> i) & 1) as usize;
            match &node.children[bit] {
                Some(child) => {
                    node = child;
                    if let Some(ref code) = node.country_code {
                        last_code = Some(code.as_str());
                        last_name = Some(node.country_name.as_deref().unwrap_or(""));
                    }
                }
                None => break,
            }
        }

        last_code.map(|c| (c.to_string(), last_name.unwrap_or("").to_string()))
    }
}

// ── Public types ────────────────────────────────────────────────────────────

/// GeoIP-based access control and request enrichment.
pub struct GeoIpDatabase {
    trie: ArcSwap<GeoTrie>,
    cache: DashMap<IpAddr, GeoResult>,
}

#[derive(Debug, Clone)]
pub struct GeoResult {
    pub country_code: String,
    pub country_name: String,
}

/// GeoIP access policy: allow or deny by country code.
/// Comparisons are case-insensitive (ASCII).
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
    ///
    /// Uses `eq_ignore_ascii_case` so both pre-normalized uppercase codes
    /// (from GeoIpDatabase lookups) and raw config values match correctly
    /// without any per-call allocation.
    pub fn is_allowed(&self, country_code: &str) -> bool {
        if self
            .deny_countries
            .iter()
            .any(|c| c.eq_ignore_ascii_case(country_code))
        {
            return false;
        }

        if self.allow_countries.is_empty() {
            return true;
        }

        self.allow_countries
            .iter()
            .any(|c| c.eq_ignore_ascii_case(country_code))
    }
}

impl GeoIpDatabase {
    pub fn new() -> Self {
        Self {
            trie: ArcSwap::from_pointee(GeoTrie::default()),
            cache: DashMap::new(),
        }
    }

    /// Loads GeoIP data from a CSV file.  Format: `cidr,country_code,country_name`
    pub fn load_csv(&mut self, path: &str) -> Result<(), String> {
        let trie = build_trie_from_csv(path)?;
        let entries = count_trie_entries(&trie);
        self.trie.store(Arc::new(trie));
        info!("Loaded {} GeoIP entries from {}", entries, path);
        Ok(())
    }

    /// Reloads from a CSV file, atomically swapping the trie and clearing the
    /// lookup cache.  On error the existing trie is preserved.
    pub fn reload(&self, path: &str) -> Result<(), String> {
        let trie = build_trie_from_csv(path)?;
        let entries = count_trie_entries(&trie);
        self.trie.store(Arc::new(trie));
        self.cache.clear();
        info!(
            "GeoIP database reloaded: {} entries from {}",
            entries, path
        );
        Ok(())
    }

    /// Looks up the country for an IP address.  Checks the hot-IP cache first,
    /// then walks the binary radix trie for a longest-prefix match.
    pub fn lookup(&self, ip: &IpAddr) -> Option<GeoResult> {
        if let Some(cached) = self.cache.get(ip) {
            return Some(cached.clone());
        }

        let trie = self.trie.load();
        if let Some((code, name)) = trie.lookup(ip) {
            let result = GeoResult {
                country_code: code,
                country_name: name,
            };
            self.cache.insert(*ip, result.clone());
            return Some(result);
        }

        None
    }

    /// Adds a single CIDR entry for simple setups without an external DB.
    /// Clones the current trie and inserts — acceptable for the cold
    /// config-time path.  Use `load_csv` / `reload` for bulk changes.
    pub fn add_entry(&self, cidr: &str, country_code: &str, country_name: &str) {
        let (network, mask, prefix_len, is_v4, code, name) =
            match parse_cidr_parts(cidr, country_code, country_name) {
                Some(parts) => parts,
                None => return,
            };

        let current = self.trie.load();
        let mut new_trie = GeoTrie {
            v4_root: current.v4_root.clone(),
            v6_root: current.v6_root.clone(),
        };
        new_trie.insert(network, mask, prefix_len, is_v4, &code, &name);
        self.trie.store(Arc::new(new_trie));
        self.cache.clear();
    }
}

// ── CSV parsing ─────────────────────────────────────────────────────────────

/// Parses a CSV file and builds a `GeoTrie` from all entries.
fn build_trie_from_csv(path: &str) -> Result<GeoTrie, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;

    let mut trie = GeoTrie::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ',').collect();
        if parts.len() < 3 {
            continue;
        }

        if let Some((network, mask, prefix_len, is_v4, code, name)) =
            parse_cidr_parts(parts[0], parts[1], parts[2])
        {
            trie.insert(network, mask, prefix_len, is_v4, &code, &name);
        }
    }
    Ok(trie)
}

/// Parses a CIDR string and country info into trie-insertion-ready parts.
/// Returns `None` if the CIDR is invalid.
fn parse_cidr_parts(
    cidr: &str,
    code: &str,
    name: &str,
) -> Option<(u128, u128, u8, bool, String, String)> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    let ip: IpAddr = addr_str.trim().parse().ok()?;
    let prefix_len: u8 = prefix_str.trim().parse().ok()?;
    let is_v4 = ip.is_ipv4();

    let ip_bits = ip_to_u128(&ip);
    let max_bits: u8 = if is_v4 { 32 } else { 128 };
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

    Some((
        ip_bits & mask,
        mask,
        prefix_len,
        is_v4,
        code.trim().to_uppercase(),
        name.trim().to_string(),
    ))
}

/// Counts how many CIDR entries are stored in the trie (nodes with country data).
fn count_trie_entries(trie: &GeoTrie) -> usize {
    fn count_in_node(node: &GeoTrieNode) -> usize {
        let mut n = if node.country_code.is_some() { 1 } else { 0 };
        for child in &node.children {
            if let Some(c) = child {
                n += count_in_node(c);
            }
        }
        n
    }
    count_in_node(&trie.v4_root) + count_in_node(&trie.v6_root)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

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

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── GeoPolicy ────────────────────────────────────────────────────────

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
    fn test_geo_policy_case_insensitive() {
        let mut policy = GeoPolicy::new();
        policy.deny_countries = vec!["cn".to_string()];
        // eq_ignore_ascii_case handles any case
        assert!(!policy.is_allowed("CN"));
        assert!(!policy.is_allowed("cn"));
        assert!(policy.is_allowed("US"));
    }

    // ── Trie lookup ─────────────────────────────────────────────────────

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
    fn test_geo_trie_longest_prefix_match() {
        let db = GeoIpDatabase::new();
        // Broader prefix
        db.add_entry("10.0.0.0/8", "XX", "Broad");
        // More specific prefix — should win for 10.0.0.x
        db.add_entry("10.0.0.0/24", "YY", "Specific");

        let result = db.lookup(&"10.0.0.1".parse().unwrap());
        assert!(result.is_some());
        assert_eq!(result.unwrap().country_code, "YY");

        // 10.1.0.1 matches /8 but not /24
        let result = db.lookup(&"10.1.0.1".parse().unwrap());
        assert!(result.is_some());
        assert_eq!(result.unwrap().country_code, "XX");
    }

    #[test]
    fn test_geo_trie_ipv6() {
        let db = GeoIpDatabase::new();
        db.add_entry("2001:db8::/32", "DE", "Germany");
        db.add_entry("2001:db8:beef::/48", "FR", "France");

        let result = db.lookup(&"2001:db8:beef::1".parse().unwrap());
        assert!(result.is_some());
        assert_eq!(result.unwrap().country_code, "FR");

        let result = db.lookup(&"2001:db8:cafe::1".parse().unwrap());
        assert!(result.is_some());
        assert_eq!(result.unwrap().country_code, "DE");

        // IPv6 outside prefixes
        let result = db.lookup(&"::1".parse().unwrap());
        assert!(result.is_none());
    }

    #[test]
    fn test_geo_trie_mixed_v4_v6() {
        let db = GeoIpDatabase::new();
        db.add_entry("192.168.0.0/16", "US", "United States");
        db.add_entry("::ffff:192.168.0.0/112", "GB", "United Kingdom");

        // IPv4 entry matches IPv4 lookup
        let v4: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(db.lookup(&v4).unwrap().country_code, "US");

        // IPv6 entry matches IPv6 lookup
        let v6: IpAddr = "::ffff:192.168.0.1".parse().unwrap();
        assert_eq!(db.lookup(&v6).unwrap().country_code, "GB");
    }

    // ── Reload ───────────────────────────────────────────────────────────

    #[test]
    fn test_geo_reload_missing_file() {
        let db = GeoIpDatabase::new();
        db.add_entry("1.0.0.0/24", "AU", "Australia");

        let result = db.reload("/nonexistent/geo.csv");
        assert!(result.is_err());

        // Existing entries should still be intact
        let lookup = db.lookup(&"1.0.0.1".parse().unwrap());
        assert!(lookup.is_some());
        assert_eq!(lookup.unwrap().country_code, "AU");
    }

    #[test]
    fn test_geo_add_entry_no_clone_of_all_entries() {
        // add_entry should work incrementally without observable Vec clone.
        // The trie clone is internal and proportional to trie nodes, not entries.
        let db = GeoIpDatabase::new();
        db.add_entry("1.0.0.0/24", "AU", "Australia");
        db.add_entry("8.8.8.0/24", "US", "United States");
        db.add_entry("2.0.0.0/8", "FR", "France");

        assert!(db.lookup(&"1.0.0.1".parse().unwrap()).is_some());
        assert!(db.lookup(&"8.8.8.8".parse().unwrap()).is_some());
        assert_eq!(
            db.lookup(&"2.1.1.1".parse().unwrap()).unwrap().country_code,
            "FR"
        );
    }

    #[test]
    fn test_geo_trie_lookup_miss() {
        let db = GeoIpDatabase::new();
        db.add_entry("10.0.0.0/8", "US", "United States");
        assert!(db.lookup(&"192.168.1.1".parse().unwrap()).is_none());
    }

    #[test]
    fn test_geo_trie_exact_prefix_match() {
        let db = GeoIpDatabase::new();
        db.add_entry("10.0.0.0/32", "EX", "Exact");
        // The IP exactly matching the /32
        assert_eq!(
            db.lookup(&"10.0.0.0".parse().unwrap())
                .unwrap()
                .country_code,
            "EX"
        );
        // One off
        assert!(db.lookup(&"10.0.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn test_geo_trie_cache_consistency() {
        let db = GeoIpDatabase::new();
        db.add_entry("10.0.0.0/8", "US", "United States");

        // First lookup populates cache
        let r1 = db.lookup(&"10.1.1.1".parse().unwrap()).unwrap();
        assert_eq!(r1.country_code, "US");

        // Second lookup hits cache
        let r2 = db.lookup(&"10.1.1.1".parse().unwrap()).unwrap();
        assert_eq!(r2.country_code, "US");
    }

    #[test]
    fn test_geo_add_entry_cache_invalidation() {
        let db = GeoIpDatabase::new();
        db.add_entry("10.0.0.0/8", "XX", "Broad");

        // Populate cache
        let r1 = db.lookup(&"10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r1.country_code, "XX");

        // Add a more specific entry — cache must be cleared so longest-prefix wins
        db.add_entry("10.0.0.0/24", "YY", "Specific");

        let r2 = db.lookup(&"10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r2.country_code, "YY");
    }

    #[test]
    fn test_geo_policy_allow_list_case_insensitive() {
        let mut policy = GeoPolicy::new();
        policy.allow_countries = vec!["us".to_string(), "gb".to_string()];
        assert!(policy.is_allowed("US"));
        assert!(policy.is_allowed("us"));
        assert!(policy.is_allowed("GB"));
        assert!(!policy.is_allowed("FR"));
    }

    #[test]
    fn test_geo_trie_root_prefix() {
        // Prefix length 0 should match everything (catch-all)
        let db = GeoIpDatabase::new();
        db.add_entry("0.0.0.0/0", "XX", "Everywhere");
        assert_eq!(
            db.lookup(&"1.2.3.4".parse().unwrap()).unwrap().country_code,
            "XX"
        );
        assert_eq!(
            db.lookup(&"255.255.255.255".parse().unwrap()).unwrap().country_code,
            "XX"
        );
    }
}
