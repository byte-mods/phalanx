//! Global Server Load Balancing (GSLB) / Geographic Traffic Director.
//!
//! Routes clients to the nearest healthy data center based on:
//! - GeoIP-based proximity (country/region to data center mapping)
//! - Active health-check latency measurements
//! - Weighted failover with configurable policies
//!
//! Works alongside the existing GeoIP module to provide anycast-like routing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// A geographic data center (point of presence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataCenter {
    /// Unique identifier (e.g., "us-east-1", "eu-west-1")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Geographic region
    pub region: GeoRegion,
    /// Country codes this DC serves (primary affinity)
    pub primary_countries: Vec<String>,
    /// Upstream pool name in Phalanx config
    pub upstream_pool: String,
    /// Weight for load distribution (higher = more traffic). Default: 100.
    pub weight: u32,
    /// Whether this DC is currently enabled
    pub enabled: bool,
}

/// Geographic region for data center classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GeoRegion {
    NorthAmerica,
    SouthAmerica,
    Europe,
    Africa,
    MiddleEast,
    Asia,
    Oceania,
}

impl GeoRegion {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "na" | "north_america" | "northamerica" => Self::NorthAmerica,
            "sa" | "south_america" | "southamerica" => Self::SouthAmerica,
            "eu" | "europe" => Self::Europe,
            "af" | "africa" => Self::Africa,
            "me" | "middle_east" | "middleeast" => Self::MiddleEast,
            "as" | "asia" => Self::Asia,
            "oc" | "oceania" => Self::Oceania,
            _ => Self::NorthAmerica,
        }
    }

    /// Returns the default region ordering by proximity for fallback routing.
    pub fn proximity_order(&self) -> Vec<GeoRegion> {
        match self {
            Self::NorthAmerica => vec![Self::NorthAmerica, Self::SouthAmerica, Self::Europe, Self::Asia, Self::Oceania, Self::MiddleEast, Self::Africa],
            Self::SouthAmerica => vec![Self::SouthAmerica, Self::NorthAmerica, Self::Europe, Self::Africa, Self::Asia, Self::Oceania, Self::MiddleEast],
            Self::Europe => vec![Self::Europe, Self::MiddleEast, Self::Africa, Self::NorthAmerica, Self::Asia, Self::SouthAmerica, Self::Oceania],
            Self::Africa => vec![Self::Africa, Self::Europe, Self::MiddleEast, Self::SouthAmerica, Self::Asia, Self::NorthAmerica, Self::Oceania],
            Self::MiddleEast => vec![Self::MiddleEast, Self::Europe, Self::Africa, Self::Asia, Self::NorthAmerica, Self::SouthAmerica, Self::Oceania],
            Self::Asia => vec![Self::Asia, Self::Oceania, Self::MiddleEast, Self::Europe, Self::NorthAmerica, Self::SouthAmerica, Self::Africa],
            Self::Oceania => vec![Self::Oceania, Self::Asia, Self::NorthAmerica, Self::SouthAmerica, Self::Europe, Self::MiddleEast, Self::Africa],
        }
    }
}

/// Health status of a data center.
#[derive(Debug, Clone)]
pub struct DcHealthStatus {
    pub dc_id: String,
    pub healthy: bool,
    pub latency_ms: f64,
    pub last_check: Instant,
    pub consecutive_failures: u32,
}

/// Routing policy for GSLB decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GslbPolicy {
    /// Route to the geographically closest healthy DC
    Geographic,
    /// Route to the DC with lowest measured latency
    LatencyBased,
    /// Weighted round-robin across all healthy DCs
    WeightedRoundRobin,
    /// Geographic primary with latency-based failover
    GeographicWithLatencyFailover,
}

impl GslbPolicy {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "latency" | "latency_based" => Self::LatencyBased,
            "weighted" | "wrr" => Self::WeightedRoundRobin,
            "geo_latency" | "geographic_latency" => Self::GeographicWithLatencyFailover,
            _ => Self::Geographic,
        }
    }
}

/// Country-to-region mapping for GeoIP integration.
pub fn country_to_region(country_code: &str) -> GeoRegion {
    match country_code.to_uppercase().as_str() {
        "US" | "CA" | "MX" => GeoRegion::NorthAmerica,
        "BR" | "AR" | "CL" | "CO" | "PE" | "VE" | "EC" | "UY" | "PY" | "BO" => GeoRegion::SouthAmerica,
        "GB" | "DE" | "FR" | "IT" | "ES" | "NL" | "BE" | "CH" | "AT" | "SE" | "NO" | "DK" | "FI" | "PL" | "CZ" | "PT" | "IE" | "RO" | "HU" | "GR" | "UA" | "RU" => GeoRegion::Europe,
        "ZA" | "NG" | "KE" | "EG" | "GH" | "TZ" | "ET" | "MA" | "DZ" | "TN" => GeoRegion::Africa,
        "AE" | "SA" | "IL" | "TR" | "QA" | "KW" | "BH" | "OM" | "JO" | "LB" | "IQ" | "IR" => GeoRegion::MiddleEast,
        "CN" | "JP" | "KR" | "IN" | "SG" | "TH" | "VN" | "MY" | "ID" | "PH" | "TW" | "HK" | "PK" | "BD" => GeoRegion::Asia,
        "AU" | "NZ" | "FJ" | "PG" => GeoRegion::Oceania,
        _ => GeoRegion::NorthAmerica, // default fallback
    }
}

/// The Global Server Load Balancer.
pub struct GslbRouter {
    /// Configured data centers
    data_centers: Arc<RwLock<Vec<DataCenter>>>,
    /// Health status per DC
    health: Arc<RwLock<HashMap<String, DcHealthStatus>>>,
    /// Routing policy
    policy: GslbPolicy,
    /// Maximum latency (ms) before a DC is considered unhealthy
    max_latency_ms: f64,
    /// Max consecutive failures before marking DC down
    max_failures: u32,
    /// Round-robin counter for weighted distribution
    rr_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl GslbRouter {
    /// Creates a new GSLB router with the specified routing policy.
    ///
    /// # Arguments
    /// * `policy` - Routing strategy (geographic, latency, weighted, or hybrid).
    /// * `max_latency_ms` - DCs with latency above this value are marked unhealthy.
    /// * `max_failures` - Consecutive health-check failures before marking a DC down.
    pub fn new(policy: GslbPolicy, max_latency_ms: f64, max_failures: u32) -> Self {
        Self {
            data_centers: Arc::new(RwLock::new(Vec::new())),
            health: Arc::new(RwLock::new(HashMap::new())),
            policy,
            max_latency_ms,
            max_failures,
            rr_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Adds a data center to the GSLB configuration.
    pub fn add_data_center(&self, dc: DataCenter) {
        let dc_id = dc.id.clone();
        self.data_centers.write().push(dc);
        self.health.write().insert(
            dc_id.clone(),
            DcHealthStatus {
                dc_id,
                healthy: true,
                latency_ms: 0.0,
                last_check: Instant::now(),
                consecutive_failures: 0,
            },
        );
    }

    /// Removes a data center.
    pub fn remove_data_center(&self, dc_id: &str) -> bool {
        let mut dcs = self.data_centers.write();
        let before = dcs.len();
        dcs.retain(|dc| dc.id != dc_id);
        self.health.write().remove(dc_id);
        dcs.len() < before
    }

    /// Updates health status for a data center.
    pub fn update_health(&self, dc_id: &str, healthy: bool, latency_ms: f64) {
        let mut health = self.health.write();
        if let Some(status) = health.get_mut(dc_id) {
            status.healthy = healthy && latency_ms <= self.max_latency_ms;
            status.latency_ms = latency_ms;
            status.last_check = Instant::now();
            if healthy {
                status.consecutive_failures = 0;
            } else {
                status.consecutive_failures += 1;
                if status.consecutive_failures >= self.max_failures {
                    status.healthy = false;
                }
            }
        }
    }

    /// Routes a client to the best data center based on their country code.
    pub fn route(&self, country_code: &str) -> Option<String> {
        match self.policy {
            GslbPolicy::Geographic => self.route_geographic(country_code),
            GslbPolicy::LatencyBased => self.route_latency_based(),
            GslbPolicy::WeightedRoundRobin => self.route_weighted_rr(),
            GslbPolicy::GeographicWithLatencyFailover => {
                self.route_geo_with_latency_failover(country_code)
            }
        }
    }

    /// Geographic routing: find the DC that serves this country, fallback by region proximity.
    fn route_geographic(&self, country_code: &str) -> Option<String> {
        let dcs = self.data_centers.read();
        let health = self.health.read();

        // Try exact country match first
        for dc in dcs.iter() {
            if !dc.enabled {
                continue;
            }
            if dc.primary_countries.iter().any(|c| c.eq_ignore_ascii_case(country_code)) {
                if let Some(status) = health.get(&dc.id) {
                    if status.healthy {
                        return Some(dc.upstream_pool.clone());
                    }
                }
            }
        }

        // Fallback: find closest by region
        let client_region = country_to_region(country_code);
        let region_order = client_region.proximity_order();

        for region in &region_order {
            let mut candidates: Vec<&DataCenter> = dcs
                .iter()
                .filter(|dc| {
                    dc.enabled
                        && dc.region == *region
                        && health.get(&dc.id).map(|s| s.healthy).unwrap_or(false)
                })
                .collect();
            candidates.sort_by_key(|dc| std::cmp::Reverse(dc.weight));
            if let Some(dc) = candidates.first() {
                return Some(dc.upstream_pool.clone());
            }
        }

        None
    }

    /// Latency-based routing: pick the DC with lowest latency.
    fn route_latency_based(&self) -> Option<String> {
        let dcs = self.data_centers.read();
        let health = self.health.read();

        dcs.iter()
            .filter(|dc| {
                dc.enabled && health.get(&dc.id).map(|s| s.healthy).unwrap_or(false)
            })
            .min_by(|a, b| {
                let la = health.get(&a.id).map(|s| s.latency_ms).unwrap_or(f64::MAX);
                let lb = health.get(&b.id).map(|s| s.latency_ms).unwrap_or(f64::MAX);
                la.partial_cmp(&lb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|dc| dc.upstream_pool.clone())
    }

    /// Weighted round-robin across all healthy DCs.
    fn route_weighted_rr(&self) -> Option<String> {
        let dcs = self.data_centers.read();
        let health = self.health.read();

        let healthy_dcs: Vec<&DataCenter> = dcs
            .iter()
            .filter(|dc| {
                dc.enabled && health.get(&dc.id).map(|s| s.healthy).unwrap_or(false)
            })
            .collect();

        if healthy_dcs.is_empty() {
            return None;
        }

        let total_weight: u64 = healthy_dcs.iter().map(|dc| dc.weight as u64).sum();
        if total_weight == 0 {
            return None;
        }

        let counter = self
            .rr_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let target = counter % total_weight;

        let mut cumulative = 0u64;
        for dc in &healthy_dcs {
            cumulative += dc.weight as u64;
            if target < cumulative {
                return Some(dc.upstream_pool.clone());
            }
        }

        healthy_dcs.last().map(|dc| dc.upstream_pool.clone())
    }

    /// Geographic with latency failover: try geo first, fall back to lowest latency.
    fn route_geo_with_latency_failover(&self, country_code: &str) -> Option<String> {
        self.route_geographic(country_code)
            .or_else(|| self.route_latency_based())
    }

    /// Returns all data centers.
    pub fn data_centers(&self) -> Vec<DataCenter> {
        self.data_centers.read().clone()
    }

    /// Returns all health statuses.
    pub fn health_statuses(&self) -> Vec<DcHealthStatus> {
        self.health.read().values().cloned().collect()
    }

    /// Returns the number of healthy data centers.
    pub fn healthy_dc_count(&self) -> usize {
        self.health.read().values().filter(|s| s.healthy).count()
    }

    /// Returns the total number of data centers.
    pub fn dc_count(&self) -> usize {
        self.data_centers.read().len()
    }

    /// Returns the configured routing policy.
    pub fn policy(&self) -> GslbPolicy {
        self.policy
    }

    /// Replaces the routing policy (e.g., on SIGHUP config reload).
    pub fn set_policy(&mut self, policy: GslbPolicy) {
        self.policy = policy;
    }

    /// Replaces all data centers with the supplied list, re-initializing health
    /// entries for new DCs. Called on SIGHUP reload when GSLB config changes.
    pub fn reload_data_centers(&self, new_dcs: Vec<DataCenter>) {
        let mut dcs = self.data_centers.write();
        let mut health = self.health.write();

        // Preserve health status for DCs that still exist
        let mut new_health = HashMap::new();
        for dc in &new_dcs {
            if let Some(existing) = health.get(&dc.id) {
                new_health.insert(dc.id.clone(), existing.clone());
            } else {
                new_health.insert(
                    dc.id.clone(),
                    DcHealthStatus {
                        dc_id: dc.id.clone(),
                        healthy: true,
                        latency_ms: 0.0,
                        last_check: Instant::now(),
                        consecutive_failures: 0,
                    },
                );
            }
        }

        *dcs = new_dcs;
        *health = new_health;
        tracing::info!("GSLB reloaded: {} data centers", dcs.len());
    }

    /// Spawns a background task that periodically probes each data center's
    /// health endpoint, measuring RTT and updating health status.
    ///
    /// For each enabled DC, resolves the upstream pool's first backend and
    /// performs an HTTP GET to its `health_check_path` (or `/` if none).
    /// Results are fed into `update_health()`.
    ///
    /// Runs every 30 seconds. Each probe has a 5-second timeout.
    pub fn spawn_health_check_loop(
        self: &Arc<Self>,
        upstreams: Arc<crate::routing::UpstreamManager>,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        let router = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            // Don't pile up if a round takes longer than 30s
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = cancel.cancelled() => {
                        tracing::info!("GSLB health check loop stopping");
                        return;
                    }
                }

                let dcs = router.data_centers.read().clone();
                for dc in &dcs {
                    if !dc.enabled {
                        continue;
                    }

                    // Resolve the first backend in this DC's upstream pool
                    let health_url = match upstreams.get_pool(&dc.upstream_pool) {
                        Some(pool) => {
                            let backends = pool.backends.load();
                            backends.first().map(|b| {
                                let path = b.config.health_check_path.clone()
                                    .unwrap_or_else(|| "/".to_string());
                                (b.config.address.clone(), path)
                            })
                        }
                        None => None,
                    };

                    let (addr, health_path) = match health_url {
                        Some(v) => v,
                        None => {
                            router.update_health(&dc.id, false, 0.0);
                            continue;
                        }
                    };

                    let dc_id = dc.id.clone();
                    let router_probe = Arc::clone(&router);
                    tokio::spawn(async move {
                        let start = Instant::now();
                        let probe_result = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            async {
                                let url = format!("http://{}{}", addr, health_path);
                                let client = match reqwest::Client::builder()
                                    .timeout(std::time::Duration::from_secs(5))
                                    .build()
                                {
                                    Ok(c) => c,
                                    Err(_) => return Err("failed to build HTTP client".to_string()),
                                };
                                client.get(&url).send().await
                                    .map(|_| ())
                                    .map_err(|e| e.to_string())
                            },
                        )
                        .await;

                        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                        match probe_result {
                            Ok(Ok(())) => {
                                router_probe.update_health(&dc_id, true, latency_ms);
                            }
                            Ok(Err(e)) => {
                                tracing::debug!("GSLB health probe failed for {}: {}", dc_id, e);
                                router_probe.update_health(&dc_id, false, latency_ms);
                            }
                            Err(_) => {
                                tracing::debug!("GSLB health probe timed out for {}", dc_id);
                                router_probe.update_health(&dc_id, false, 5000.0);
                            }
                        }
                    });
                }
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dc(id: &str, region: GeoRegion, countries: Vec<&str>, weight: u32) -> DataCenter {
        DataCenter {
            id: id.to_string(),
            name: format!("DC {}", id),
            region,
            primary_countries: countries.into_iter().map(String::from).collect(),
            upstream_pool: format!("{}-pool", id),
            weight,
            enabled: true,
        }
    }

    fn make_router() -> GslbRouter {
        let router = GslbRouter::new(GslbPolicy::Geographic, 500.0, 3);
        router.add_data_center(make_dc("us-east", GeoRegion::NorthAmerica, vec!["US", "CA"], 100));
        router.add_data_center(make_dc("eu-west", GeoRegion::Europe, vec!["GB", "DE", "FR"], 100));
        router.add_data_center(make_dc("ap-south", GeoRegion::Asia, vec!["IN", "SG", "JP"], 100));
        router
    }

    #[test]
    fn test_gslb_router_creation() {
        let router = GslbRouter::new(GslbPolicy::Geographic, 500.0, 3);
        assert_eq!(router.dc_count(), 0);
        assert_eq!(router.policy(), GslbPolicy::Geographic);
    }

    #[test]
    fn test_add_data_center() {
        let router = make_router();
        assert_eq!(router.dc_count(), 3);
        assert_eq!(router.healthy_dc_count(), 3);
    }

    #[test]
    fn test_remove_data_center() {
        let router = make_router();
        assert!(router.remove_data_center("us-east"));
        assert_eq!(router.dc_count(), 2);
        assert!(!router.remove_data_center("nonexistent"));
    }

    #[test]
    fn test_geographic_routing_exact_country() {
        let router = make_router();
        assert_eq!(router.route("US"), Some("us-east-pool".to_string()));
        assert_eq!(router.route("GB"), Some("eu-west-pool".to_string()));
        assert_eq!(router.route("JP"), Some("ap-south-pool".to_string()));
    }

    #[test]
    fn test_geographic_routing_fallback_by_region() {
        let router = make_router();
        // Mexico isn't in any DC's primary_countries but is in NorthAmerica
        assert_eq!(router.route("MX"), Some("us-east-pool".to_string()));
        // Australia → closest is Asia
        assert_eq!(router.route("AU"), Some("ap-south-pool".to_string()));
    }

    #[test]
    fn test_geographic_routing_unhealthy_fallback() {
        let router = make_router();
        router.update_health("us-east", false, 1000.0);
        // US should fallback to next closest region
        let result = router.route("US");
        assert!(result.is_some());
        assert_ne!(result.unwrap(), "us-east-pool");
    }

    #[test]
    fn test_latency_based_routing() {
        let router = GslbRouter::new(GslbPolicy::LatencyBased, 500.0, 3);
        router.add_data_center(make_dc("dc-a", GeoRegion::NorthAmerica, vec!["US"], 100));
        router.add_data_center(make_dc("dc-b", GeoRegion::Europe, vec!["GB"], 100));
        router.update_health("dc-a", true, 150.0);
        router.update_health("dc-b", true, 50.0);
        assert_eq!(router.route("US"), Some("dc-b-pool".to_string())); // lower latency wins
    }

    #[test]
    fn test_weighted_rr_routing() {
        let router = GslbRouter::new(GslbPolicy::WeightedRoundRobin, 500.0, 3);
        router.add_data_center(make_dc("dc-a", GeoRegion::NorthAmerica, vec!["US"], 70));
        router.add_data_center(make_dc("dc-b", GeoRegion::Europe, vec!["GB"], 30));

        let mut counts: HashMap<String, u32> = HashMap::new();
        for _ in 0..100 {
            if let Some(pool) = router.route("US") {
                *counts.entry(pool).or_insert(0) += 1;
            }
        }
        assert!(counts.get("dc-a-pool").unwrap_or(&0) > counts.get("dc-b-pool").unwrap_or(&0));
    }

    #[test]
    fn test_geo_latency_failover() {
        let router = GslbRouter::new(GslbPolicy::GeographicWithLatencyFailover, 500.0, 3);
        router.add_data_center(make_dc("us", GeoRegion::NorthAmerica, vec!["US"], 100));
        router.add_data_center(make_dc("eu", GeoRegion::Europe, vec!["GB"], 100));
        router.update_health("us", true, 50.0);
        router.update_health("eu", true, 30.0);
        // Geographic match for US
        assert_eq!(router.route("US"), Some("us-pool".to_string()));
        // Mark US as unhealthy → falls back to latency-based (EU)
        router.update_health("us", false, 1000.0);
        assert_eq!(router.route("US"), Some("eu-pool".to_string()));
    }

    #[test]
    fn test_update_health_consecutive_failures() {
        let router = make_router();
        router.update_health("us-east", false, 100.0);
        router.update_health("us-east", false, 100.0);
        router.update_health("us-east", false, 100.0);
        let statuses = router.health_statuses();
        let us = statuses.iter().find(|s| s.dc_id == "us-east").unwrap();
        assert!(!us.healthy);
        assert_eq!(us.consecutive_failures, 3);
    }

    #[test]
    fn test_update_health_recovery() {
        let router = make_router();
        router.update_health("us-east", false, 100.0);
        router.update_health("us-east", false, 100.0);
        router.update_health("us-east", true, 50.0);
        let statuses = router.health_statuses();
        let us = statuses.iter().find(|s| s.dc_id == "us-east").unwrap();
        assert!(us.healthy);
        assert_eq!(us.consecutive_failures, 0);
    }

    #[test]
    fn test_no_healthy_dcs_returns_none() {
        let router = make_router();
        router.update_health("us-east", false, 1000.0);
        router.update_health("eu-west", false, 1000.0);
        router.update_health("ap-south", false, 1000.0);
        assert_eq!(router.route("US"), None);
    }

    #[test]
    fn test_disabled_dc_skipped() {
        let router = GslbRouter::new(GslbPolicy::Geographic, 500.0, 3);
        let mut dc = make_dc("us", GeoRegion::NorthAmerica, vec!["US"], 100);
        dc.enabled = false;
        router.add_data_center(dc);
        router.add_data_center(make_dc("eu", GeoRegion::Europe, vec!["GB"], 100));
        assert_ne!(router.route("US"), Some("us-pool".to_string()));
    }

    #[test]
    fn test_country_to_region_mapping() {
        assert_eq!(country_to_region("US"), GeoRegion::NorthAmerica);
        assert_eq!(country_to_region("BR"), GeoRegion::SouthAmerica);
        assert_eq!(country_to_region("GB"), GeoRegion::Europe);
        assert_eq!(country_to_region("ZA"), GeoRegion::Africa);
        assert_eq!(country_to_region("AE"), GeoRegion::MiddleEast);
        assert_eq!(country_to_region("JP"), GeoRegion::Asia);
        assert_eq!(country_to_region("AU"), GeoRegion::Oceania);
        assert_eq!(country_to_region("XX"), GeoRegion::NorthAmerica); // unknown
    }

    #[test]
    fn test_geo_region_from_str() {
        assert_eq!(GeoRegion::from_str("na"), GeoRegion::NorthAmerica);
        assert_eq!(GeoRegion::from_str("eu"), GeoRegion::Europe);
        assert_eq!(GeoRegion::from_str("asia"), GeoRegion::Asia);
        assert_eq!(GeoRegion::from_str("oceania"), GeoRegion::Oceania);
        assert_eq!(GeoRegion::from_str("unknown"), GeoRegion::NorthAmerica);
    }

    #[test]
    fn test_geo_region_proximity_order() {
        let order = GeoRegion::NorthAmerica.proximity_order();
        assert_eq!(order[0], GeoRegion::NorthAmerica);
        assert_eq!(order.len(), 7);
    }

    #[test]
    fn test_gslb_policy_from_str() {
        assert_eq!(GslbPolicy::from_str("geographic"), GslbPolicy::Geographic);
        assert_eq!(GslbPolicy::from_str("latency"), GslbPolicy::LatencyBased);
        assert_eq!(GslbPolicy::from_str("weighted"), GslbPolicy::WeightedRoundRobin);
        assert_eq!(GslbPolicy::from_str("geo_latency"), GslbPolicy::GeographicWithLatencyFailover);
    }

    #[test]
    fn test_data_center_serialization() {
        let dc = make_dc("test", GeoRegion::Europe, vec!["DE"], 50);
        let json = serde_json::to_string(&dc).unwrap();
        let decoded: DataCenter = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, "test");
        assert_eq!(decoded.weight, 50);
    }

    #[test]
    fn test_max_latency_threshold() {
        let router = GslbRouter::new(GslbPolicy::LatencyBased, 100.0, 3);
        router.add_data_center(make_dc("dc-a", GeoRegion::NorthAmerica, vec!["US"], 100));
        router.update_health("dc-a", true, 200.0); // exceeds max_latency_ms
        // DC should be marked unhealthy due to high latency
        assert_eq!(router.route("US"), None);
    }

    #[test]
    fn test_dc_health_status_clone() {
        let status = DcHealthStatus {
            dc_id: "test".to_string(),
            healthy: true,
            latency_ms: 42.0,
            last_check: Instant::now(),
            consecutive_failures: 0,
        };
        let cloned = status.clone();
        assert_eq!(cloned.dc_id, "test");
        assert_eq!(cloned.latency_ms, 42.0);
    }

    #[test]
    fn test_reload_data_centers_preserves_health() {
        let router = make_router();
        // Mark us-east as unhealthy
        router.update_health("us-east", false, 1000.0);

        // Reload with same DCs + a new one
        let new_dcs = vec![
            make_dc("us-east", GeoRegion::NorthAmerica, vec!["US", "CA"], 100),
            make_dc("eu-west", GeoRegion::Europe, vec!["GB", "DE", "FR"], 100),
            make_dc("new-dc", GeoRegion::Oceania, vec!["AU", "NZ"], 50),
        ];
        // ap-south is removed
        router.reload_data_centers(new_dcs);

        assert_eq!(router.dc_count(), 3);
        // us-east should still be unhealthy (preserved)
        let statuses = router.health_statuses();
        let us = statuses.iter().find(|s| s.dc_id == "us-east").unwrap();
        assert!(!us.healthy);
        // new-dc should be healthy (freshly initialized)
        let new = statuses.iter().find(|s| s.dc_id == "new-dc").unwrap();
        assert!(new.healthy);
        // ap-south should be gone
        assert!(statuses.iter().find(|s| s.dc_id == "ap-south").is_none());
    }

    #[test]
    fn test_gslb_router_is_arc_compatible() {
        // Verify GslbRouter can be wrapped in Arc (required by spawn_health_check_loop)
        let router = Arc::new(GslbRouter::new(GslbPolicy::Geographic, 500.0, 3));
        router.add_data_center(make_dc("us-east", GeoRegion::NorthAmerica, vec!["US"], 100));
        assert_eq!(router.dc_count(), 1);
        assert_eq!(router.healthy_dc_count(), 1);
    }
}
