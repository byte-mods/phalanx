use bytes::Bytes;
use hyper::Request;
use http_body_util::Full;
use std::sync::Arc;
use tracing::{debug, error};

use crate::routing::UpstreamManager;

/// Fires a mirrored (tee'd) copy of the request to a shadow upstream pool.
/// The response is discarded — this is purely for traffic shadowing / testing.
/// Runs in a background task so it never blocks the primary request path.
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

    let point = (hash % total as u64) as u32;
    let mut cumulative = 0u32;
    for (i, w) in weights.iter().enumerate() {
        cumulative += w;
        if point < cumulative {
            return i;
        }
    }
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
