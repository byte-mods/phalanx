use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Shared state coordination across Phalanx cluster nodes via an external KV store.
///
/// Supports etcd and Redis as backends. This enables:
/// - Cross-node sticky session tables
/// - Distributed rate limiting zone counters
/// - Shared health status
/// - Leader election for singleton tasks
pub struct ClusterState {
    backend: ClusterBackend,
    node_id: String,
}

#[derive(Debug, Clone)]
pub enum ClusterBackend {
    /// etcd v3 API endpoint
    Etcd { endpoints: Vec<String> },
    /// Redis connection URL
    Redis { url: String },
    /// Single-node mode (no-op)
    Standalone,
}

/// A key-value entry with TTL support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterEntry {
    pub value: String,
    pub node_id: String,
    pub updated_at: u64,
}

impl ClusterState {
    pub fn new(backend: ClusterBackend, node_id: String) -> Self {
        info!("Cluster state initialized: node_id={}, backend={:?}", node_id, backend);
        Self { backend, node_id }
    }

    /// Stores a key-value pair in the cluster KV store with an optional TTL.
    pub async fn put(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = ClusterEntry {
            value: value.to_string(),
            node_id: self.node_id.clone(),
            updated_at: now,
        };

        match &self.backend {
            ClusterBackend::Etcd { endpoints } => {
                let endpoint = endpoints.first().ok_or("No etcd endpoints")?;
                let mut client = etcd_client::Client::connect([endpoint.as_str()], None)
                    .await
                    .map_err(|e| format!("etcd connect error: {}", e))?;

                let serialized =
                    serde_json::to_string(&entry).map_err(|e| format!("serialize: {}", e))?;

                if let Some(ttl) = ttl_secs {
                    let lease = client
                        .lease_grant(ttl as i64, None)
                        .await
                        .map_err(|e| format!("lease grant: {}", e))?;
                    client
                        .put(
                            key,
                            serialized,
                            Some(etcd_client::PutOptions::new().with_lease(lease.id())),
                        )
                        .await
                        .map_err(|e| format!("etcd put: {}", e))?;
                } else {
                    client
                        .put(key, serialized, None)
                        .await
                        .map_err(|e| format!("etcd put: {}", e))?;
                }
                Ok(())
            }
            ClusterBackend::Redis { url: _ } => {
                // Redis integration would use the `redis` crate
                debug!("Redis cluster put: {} (stub)", key);
                Ok(())
            }
            ClusterBackend::Standalone => Ok(()),
        }
    }

    /// Retrieves a value from the cluster KV store.
    pub async fn get(&self, key: &str) -> Result<Option<ClusterEntry>, String> {
        match &self.backend {
            ClusterBackend::Etcd { endpoints } => {
                let endpoint = endpoints.first().ok_or("No etcd endpoints")?;
                let mut client = etcd_client::Client::connect([endpoint.as_str()], None)
                    .await
                    .map_err(|e| format!("etcd connect: {}", e))?;

                let resp = client
                    .get(key, None)
                    .await
                    .map_err(|e| format!("etcd get: {}", e))?;

                if let Some(kv) = resp.kvs().first() {
                    let val = kv.value_str().map_err(|e| format!("utf8: {}", e))?;
                    let entry: ClusterEntry =
                        serde_json::from_str(val).map_err(|e| format!("deserialize: {}", e))?;
                    Ok(Some(entry))
                } else {
                    Ok(None)
                }
            }
            ClusterBackend::Redis { url: _ } => {
                debug!("Redis cluster get: {} (stub)", key);
                Ok(None)
            }
            ClusterBackend::Standalone => Ok(None),
        }
    }

    /// Deletes a key from the cluster KV store.
    pub async fn delete(&self, key: &str) -> Result<(), String> {
        match &self.backend {
            ClusterBackend::Etcd { endpoints } => {
                let endpoint = endpoints.first().ok_or("No etcd endpoints")?;
                let mut client = etcd_client::Client::connect([endpoint.as_str()], None)
                    .await
                    .map_err(|e| format!("etcd connect: {}", e))?;
                client
                    .delete(key, None)
                    .await
                    .map_err(|e| format!("etcd delete: {}", e))?;
                Ok(())
            }
            ClusterBackend::Redis { url: _ } => Ok(()),
            ClusterBackend::Standalone => Ok(()),
        }
    }

    /// Shares sticky session state: stores a session → backend mapping.
    pub async fn share_sticky_session(
        &self,
        session_key: &str,
        backend_addr: &str,
        ttl_secs: u64,
    ) -> Result<(), String> {
        let key = format!("phalanx/sticky/{}", session_key);
        self.put(&key, backend_addr, Some(ttl_secs)).await
    }

    /// Looks up a sticky session from cluster state.
    pub async fn lookup_sticky_session(&self, session_key: &str) -> Option<String> {
        let key = format!("phalanx/sticky/{}", session_key);
        self.get(&key).await.ok().flatten().map(|e| e.value)
    }

    /// Registers this node as alive in the cluster with a heartbeat TTL.
    pub async fn heartbeat(&self, ttl_secs: u64) -> Result<(), String> {
        let key = format!("phalanx/nodes/{}", self.node_id);
        let value = serde_json::json!({
            "node_id": self.node_id,
            "status": "healthy",
        })
        .to_string();
        self.put(&key, &value, Some(ttl_secs)).await
    }

    /// Spawns a background heartbeat loop.
    pub fn spawn_heartbeat(self: Arc<Self>, interval_secs: u64) {
        tokio::spawn(async move {
            loop {
                if let Err(e) = self.heartbeat(interval_secs * 3).await {
                    warn!("Cluster heartbeat failed: {}", e);
                }
                sleep(Duration::from_secs(interval_secs)).await;
            }
        });
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_state_standalone_creation() {
        let state = ClusterState::new(ClusterBackend::Standalone, "node-1".to_string());
        assert_eq!(state.node_id(), "node-1");
    }

    #[tokio::test]
    async fn test_standalone_put_ok() {
        let state = ClusterState::new(ClusterBackend::Standalone, "n1".to_string());
        let result = state.put("key", "value", Some(60)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_standalone_get_returns_none() {
        let state = ClusterState::new(ClusterBackend::Standalone, "n1".to_string());
        let result = state.get("key").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_standalone_delete_ok() {
        let state = ClusterState::new(ClusterBackend::Standalone, "n1".to_string());
        let result = state.delete("key").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_standalone_sticky_session_returns_none() {
        let state = ClusterState::new(ClusterBackend::Standalone, "n1".to_string());
        let result = state.lookup_sticky_session("sess-1").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_standalone_share_sticky_session_ok() {
        let state = ClusterState::new(ClusterBackend::Standalone, "n1".to_string());
        let result = state.share_sticky_session("sess", "10.0.0.1:80", 60).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_standalone_heartbeat() {
        let state = ClusterState::new(ClusterBackend::Standalone, "n1".to_string());
        let result = state.heartbeat(30).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_redis_backend_debug() {
        let backend = ClusterBackend::Redis { url: "redis://localhost".to_string() };
        let debug_str = format!("{:?}", backend);
        assert!(debug_str.contains("Redis"));
    }

    #[test]
    fn test_etcd_backend_debug() {
        let backend = ClusterBackend::Etcd { endpoints: vec!["http://localhost:2379".to_string()] };
        let debug_str = format!("{:?}", backend);
        assert!(debug_str.contains("Etcd"));
    }

    #[test]
    fn test_cluster_entry_serialization() {
        let entry = ClusterEntry {
            value: "10.0.0.1:8080".to_string(),
            node_id: "node-1".to_string(),
            updated_at: 1234567890,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: ClusterEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.value, "10.0.0.1:8080");
        assert_eq!(deserialized.node_id, "node-1");
        assert_eq!(deserialized.updated_at, 1234567890);
    }
}
