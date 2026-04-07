//! Traffic mirroring and A/B traffic splitting.
//!
//! Mirroring copies an incoming request to a secondary ("shadow") upstream pool
//! so that new backends or services can be tested with live production traffic
//! without affecting the primary request path. The shadow response is discarded.
//!
//! Traffic splitting uses a consistent hash to deterministically route a
//! fraction of requests to different variants, enabling canary deployments and
//! A/B testing.

use bytes::Bytes;
use std::sync::Arc;
use tracing::{debug, error};

use crate::routing::UpstreamManager;

/// Fires a mirrored (tee'd) copy of the request to a shadow upstream pool.
///
/// The response is discarded -- this is purely for traffic shadowing / testing.
/// Runs in a background Tokio task so it never blocks the primary request path.
///
/// # Arguments
///
/// * `method`           - HTTP method string (e.g. `"GET"`, `"POST"`).
/// * `uri`              - Request URI path (e.g. `"/api/v1/users"`).
/// * `headers`          - Cloned header map from the original request.
/// * `body`             - Buffered request body bytes.
/// * `mirror_pool_name` - Name of the upstream pool to mirror traffic to.
/// * `upstreams`        - Shared upstream manager for backend selection.
///
/// # Side Effects
///
/// Spawns a Tokio task. If the mirror pool or backend is unavailable the
/// request is silently dropped (logged at debug level).
pub fn mirror_request(
    method: &str,
    uri: &str,
    headers: hyper::HeaderMap,
    body: Bytes,
    mirror_pool_name: String,
    upstreams: Arc<UpstreamManager>,
) {
    let method = method.to_string();
    let uri = uri.to_string();

    tokio::spawn(async move {
        let pool = match upstreams.get_pool(&mirror_pool_name) {
            Some(p) => p,
            None => {
                debug!("Mirror pool '{}' not found, skipping", mirror_pool_name);
                return;
            }
        };

        let backend = match pool.get_next_backend(None, None) {
            Some(b) => b,
            None => {
                debug!("No healthy backends in mirror pool '{}'", mirror_pool_name);
                return;
            }
        };

        let url = format!("http://{}{}", backend.config.address, uri);
        debug!("Mirroring {} {} to {}", method, uri, url);

        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create mirror HTTP client: {}", e);
                return;
            }
        };

        let req_method = match method.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "PATCH" => reqwest::Method::PATCH,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET,
        };

        let mut builder = client.request(req_method, &url);

        // Propagate all original request headers to the mirror backend
        for (key, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                builder = builder.header(key.as_str(), v);
            }
        }

        let result = builder.body(body.to_vec()).send().await;
        match result {
            Ok(resp) => {
                debug!("Mirror response from {}: {}", url, resp.status());
            }
            Err(e) => {
                debug!("Mirror request to {} failed: {}", url, e);
            }
        }
    });
}

/// Traffic splitting: determines which variant a request should go to based on
/// a consistent hash of a key (e.g. client IP, cookie, header value).
///
/// Returns the index of the chosen variant (0-based).
///
/// `weights` is a list of relative weights (e.g. `[90, 10]` for 90/10 split).
pub fn split_traffic(key: &str, weights: &[u32]) -> usize {
    if weights.is_empty() {
        return 0;
    }

    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    let hash = hasher.finish();

    let total: u32 = weights.iter().sum();
    if total == 0 {
        return 0;
    }

    // Map the hash into the [0, total) range to get a deterministic point
    let point = (hash % total as u64) as u32;
    // Walk through cumulative weight ranges to find which variant owns this point
    let mut cumulative = 0u32;
    for (i, w) in weights.iter().enumerate() {
        cumulative += w;
        if point < cumulative {
            return i;
        }
    }
    // Fallback: rounding edge case -- return the last variant
    weights.len() - 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_traffic_deterministic() {
        let w = vec![50, 50];
        let result1 = split_traffic("user-123", &w);
        let result2 = split_traffic("user-123", &w);
        assert_eq!(result1, result2, "same key must yield same variant");
    }

    #[test]
    fn test_split_traffic_distribution() {
        let w = vec![90, 10];
        let mut counts = [0u32; 2];
        for i in 0..1000 {
            let key = format!("user-{}", i);
            counts[split_traffic(&key, &w)] += 1;
        }
        assert!(counts[0] > 700, "90% variant should get most traffic");
    }

    #[test]
    fn test_split_traffic_single() {
        assert_eq!(split_traffic("any", &[100]), 0);
    }
}
