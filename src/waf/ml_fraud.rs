/// ONNX-based machine learning fraud detection engine.
///
/// Runs inference asynchronously in a dedicated background task to avoid
/// blocking request handling. Requests are queued via an MPSC channel;
/// the worker extracts a 6-feature vector from request metadata and runs
/// it through a pre-trained ONNX model (e.g., CatBoost binary classifier).
///
/// Two operational modes:
/// - **Shadow**: predictions are logged but no enforcement action is taken.
/// - **Active**: high-confidence fraud predictions trigger immediate IP bans
///   via the reputation manager.
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};
use tract_onnx::prelude::*;

use crate::waf::reputation::IpReputationManager;

/// Modes for the ML Fraud Engine
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MlFraudMode {
    /// Logs predictions but does not take blocking actions
    Shadow,
    /// Logs predictions and immediately issues bans for malicious IPs
    Active,
}

/// A serialized log entry for the admin dashboard UI.
///
/// Stored in a capped ring buffer (max 100 entries) for real-time display.
#[derive(Debug, Clone, Serialize)]
pub struct MlLogEntry {
    /// Unix timestamp when the prediction was made.
    pub timestamp: u64,
    /// Client IP address that was evaluated.
    pub ip: String,
    /// Request path that was inspected.
    pub path: String,
    /// Truncated request body for human review.
    pub payload_snippet: String,
    /// Model output score (0.0 = benign, 1.0 = fraudulent).
    pub fraud_score: f32,
    /// Whether the score exceeded the 0.5 threshold.
    pub flagged: bool,
    /// Action taken: "Pass", "ShadowFlag", "IpBanned", or "InferenceError".
    pub action_taken: String,
}

/// Request metadata captured asynchronously for ML inference.
///
/// Constructed in the request handler hot path and sent via MPSC channel
/// to the background inference worker. Fields are chosen to produce a
/// 6-dimensional feature vector: [path_len, method_enum, query_len,
/// header_count, ua_len, body_len].
#[derive(Debug, Clone)]
pub struct MlEvent {
    /// Client IP address.
    pub ip: String,
    /// HTTP method (GET, POST, PUT, DELETE, etc.).
    pub method: String,
    /// Request URL path.
    pub path: String,
    /// Optional query string.
    pub query: Option<String>,
    /// Unix timestamp when the request was received.
    pub timestamp: u64,
    /// Number of HTTP headers in the request.
    pub header_count: usize,
    /// Length of the User-Agent header string.
    pub user_agent_len: usize,
    /// Length of the request body in bytes.
    pub body_len: usize,
    /// First N bytes of the request body for logging/review.
    pub body_snippet: String,
}

/// The ML fraud detection background engine.
///
/// Manages the lifecycle of the ONNX inference worker: model loading,
/// event queuing, mode switching, and log retrieval. The engine is safe
/// to share across threads; all mutable state is behind locks or atomics.
pub struct MlFraudEngine {
    /// Channel sender for queuing events to the background worker.
    /// `None` until `load_model()` is called.
    tx: std::sync::RwLock<Option<mpsc::Sender<MlEvent>>>,
    /// Current operational mode (Shadow or Active), atomically swappable at runtime.
    pub mode: Arc<ArcSwap<MlFraudMode>>,
    /// Rolling log of the last 100 inference results for the admin dashboard.
    pub logs: Arc<RwLock<VecDeque<MlLogEntry>>>,
    /// Indicates whether the ONNX model loaded successfully.
    /// `false` means the engine is running in rule-based fallback mode.
    model_loaded: Arc<AtomicBool>,
}

impl MlFraudEngine {
    /// Creates a new uninitialized ML engine (no model loaded yet).
    pub fn new() -> Self {
        Self {
            tx: std::sync::RwLock::new(None),
            mode: Arc::new(ArcSwap::from_pointee(MlFraudMode::Shadow)),
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
            model_loaded: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns whether the ONNX model was successfully loaded.
    /// When `false`, the engine is operating in rule-based fallback mode.
    pub fn is_model_loaded(&self) -> bool {
        self.model_loaded.load(Ordering::Relaxed)
    }

    /// Triggers an asynchronous reload of the ONNX model and spawns the inference worker.
    pub async fn load_model(
        &self,
        model_path: &str,
        reputation: Arc<IpReputationManager>,
        ml_load_failure_metric: Option<prometheus::IntCounter>,
    ) {
        info!("ML Fraud Engine: Loading ONNX model from {}", model_path);

        let model_path_v = model_path.to_string();

        let (tx, mut rx) = mpsc::channel::<MlEvent>(10_000);
        if let Ok(mut guard) = self.tx.write() {
            *guard = Some(tx);
        }

        let mode_ref = Arc::clone(&self.mode);
        let logs_ref = Arc::clone(&self.logs);
        let model_loaded_ref = Arc::clone(&self.model_loaded);

        // Spawn the dedicated background worker
        tokio::spawn(async move {
            info!("ML Fraud Worker: Booting and compiling ONNX graph...");

            let model_path_v_log = model_path_v.clone();
            // Model compilation is blocking, so yield to blocking thread
            let model_result = tokio::task::spawn_blocking(move || {
                tract_onnx::onnx()
                    .model_for_path(&model_path_v)?
                    .into_optimized()?
                    .into_runnable()
            }).await.unwrap_or_else(|e| Err(anyhow::anyhow!("JoinError: {}", e)));

            let model = match model_result {
                Ok(m) => {
                    model_loaded_ref.store(true, Ordering::Relaxed);
                    info!("ML Fraud Worker: ONNX model successfully loaded and active.");
                    Some(m)
                }
                Err(e) => {
                    model_loaded_ref.store(false, Ordering::Relaxed);
                    error!("ML Fraud Worker: Failed to load ONNX model, using rule-based fallback. Error: {}", e);
                    warn!("ML Fraud Worker: ONNX model load failure — falling back to rule-based heuristic scoring. \
                           Model path: '{}'. Fraud detection accuracy will be degraded until a valid model is loaded.",
                           model_path_v_log);
                    if let Some(ref metric) = ml_load_failure_metric {
                        metric.inc();
                    }
                    None
                }
            };

            while let Some(event) = rx.recv().await {
                // Convert metadata into a standardized feature vector (6 floats)
                // Features: [PathLen, MethodEnum, QueryLen, HeaderCount, UALen, BodyLen]
                let method_val = match event.method.as_str() {
                    "GET" => 0.0,
                    "POST" => 1.0,
                    "PUT" => 2.0,
                    "DELETE" => 3.0,
                    _ => 4.0,
                };

                let features = vec![
                    event.path.len() as f32,
                    method_val,
                    event.query.as_ref().map(|q| q.len()).unwrap_or(0) as f32,
                    event.header_count as f32,
                    event.user_agent_len as f32,
                    event.body_len as f32,
                ];

                let event_clone = event.clone();
                let current_mode = **mode_ref.load();

                let log_entry = if let Some(ref model) = model {
                    let model_clone = model.clone();
                    // Perform Tract synchronous inference on a spawn_blocking thread
                    tokio::task::spawn_blocking(move || {
                        let mut is_fraud = false;
                        let mut score = 0.0;

                        let tensor = tract_ndarray::Array1::from_vec(features).into_tensor();
                        let reshaped = tensor.clone().into_shape(&[1, 6]).unwrap_or(tensor);

                        if let Ok(result) = model_clone.run(tvec!(reshaped.into())) {
                            if let Ok(view) = result[0].to_array_view::<f32>() {
                                if let Some(first_val) = view.iter().next() {
                                    score = *first_val;
                                    if score > 0.5 {
                                        is_fraud = true;
                                    }
                                }
                            }
                        }

                        MlLogEntry {
                            timestamp: event_clone.timestamp,
                            ip: event_clone.ip,
                            path: event_clone.path,
                            payload_snippet: event_clone.body_snippet,
                            fraud_score: score,
                            flagged: is_fraud,
                            action_taken: if is_fraud {
                                if current_mode == MlFraudMode::Active {
                                    "IpBanned".to_string()
                                } else {
                                    "ShadowFlag".to_string()
                                }
                            } else {
                                "Pass".to_string()
                            },
                        }
                    }).await.unwrap_or_else(|_| MlLogEntry {
                        timestamp: event.timestamp,
                        ip: event.ip.clone(),
                        path: event.path.clone(),
                        payload_snippet: event.body_snippet.clone(),
                        fraud_score: -1.0,
                        flagged: false,
                        action_taken: "InferenceError".to_string(),
                    })
                } else {
                    // Rule-based fallback scoring when ONNX model is unavailable
                    rule_based_score(&event, current_mode)
                };

                // If Active Mode and marked fraud, ban the IP instantly
                if log_entry.flagged && **mode_ref.load() == MlFraudMode::Active {
                    warn!("ML Fraud Engine (ACTIVE): Detected fraud from IP {}, applying strike penalty", log_entry.ip);
                    reputation.add_strike(&log_entry.ip, 10); // Instant ban threshold
                }

                // Update ring buffer UI logs
                let mut logs = logs_ref.write().await;
                if logs.len() == 100 {
                    logs.pop_front();
                }
                logs.push_back(log_entry);
            }
        });
    }

    /// Queues a request for background asynchronous fraud evaluation
    pub fn queue_inspection(&self, event: MlEvent) {
        if let Ok(guard) = self.tx.read() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.try_send(event); // drop if channel full to prevent OOM
            }
        }
    }
}

/// Rule-based fallback scorer used when the ONNX model is unavailable.
///
/// Applies simple heuristics to estimate a fraud score:
/// - Unusually long paths (>500 chars): 0.6
/// - Non-standard HTTP methods on static-looking paths: 0.4
/// - Very large bodies (>1MB): 0.5
/// - Missing user-agent: 0.3
/// Scores are capped at 1.0.
fn rule_based_score(event: &MlEvent, mode: MlFraudMode) -> MlLogEntry {
    let mut score: f32 = 0.0;

    if event.path.len() > 500 {
        score += 0.6;
    }
    if event.body_len > 1_000_000 {
        score += 0.5;
    }
    if event.user_agent_len == 0 {
        score += 0.3;
    }
    // Suspicious: non-GET methods on paths that look like static files
    if event.method != "GET"
        && (event.path.ends_with(".js")
            || event.path.ends_with(".css")
            || event.path.ends_with(".png")
            || event.path.ends_with(".jpg"))
    {
        score += 0.4;
    }

    score = score.min(1.0);
    let is_fraud = score > 0.5;

    MlLogEntry {
        timestamp: event.timestamp,
        ip: event.ip.clone(),
        path: event.path.clone(),
        payload_snippet: event.body_snippet.clone(),
        fraud_score: score,
        flagged: is_fraud,
        action_taken: if is_fraud {
            if mode == MlFraudMode::Active {
                "IpBanned".to_string()
            } else {
                "ShadowFlag".to_string()
            }
        } else {
            "Pass".to_string()
        },
    }
}

impl Default for MlFraudEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MlFraudEngine {
    /// Returns `true` if the engine is running in rule-based fallback mode
    /// (ONNX model not loaded or failed to load).
    pub fn is_fallback_mode(&self) -> bool {
        !self.model_loaded.load(Ordering::Relaxed)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_fraud_mode_defaults_to_shadow() {
        let engine = MlFraudEngine::new();
        assert_eq!(**engine.mode.load(), MlFraudMode::Shadow);
    }

    #[test]
    fn test_ml_event_creation() {
        let event = MlEvent {
            ip: "192.168.1.1".to_string(),
            method: "POST".to_string(),
            path: "/api/login".to_string(),
            query: Some("redirect=/home".to_string()),
            timestamp: 1234567890,
            header_count: 8,
            user_agent_len: 50,
            body_len: 128,
            body_snippet: "username=admin".to_string(),
        };
        assert_eq!(event.ip, "192.168.1.1");
        assert_eq!(event.method, "POST");
        assert_eq!(event.header_count, 8);
    }

    #[test]
    fn test_ml_log_entry_serialization() {
        let entry = MlLogEntry {
            timestamp: 1234567890,
            ip: "10.0.0.5".to_string(),
            path: "/api/submit".to_string(),
            payload_snippet: "data=...".to_string(),
            fraud_score: 0.87,
            flagged: true,
            action_taken: "ShadowFlag".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("0.87"));
        assert!(json.contains("ShadowFlag"));
    }

    #[test]
    fn test_queue_inspection_does_not_panic_when_no_model() {
        let engine = MlFraudEngine::new();
        let event = MlEvent {
            ip: "1.2.3.4".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            timestamp: 0,
            header_count: 0,
            user_agent_len: 0,
            body_len: 0,
            body_snippet: String::new(),
        };
        // Should not panic even though no model is loaded
        engine.queue_inspection(event);
    }

    #[test]
    fn test_mode_can_be_changed_to_active() {
        let engine = MlFraudEngine::new();
        assert_eq!(**engine.mode.load(), MlFraudMode::Shadow);

        // Swap to Active mode
        engine.mode.store(Arc::new(MlFraudMode::Active));
        assert_eq!(**engine.mode.load(), MlFraudMode::Active);
    }

    #[tokio::test]
    async fn test_logs_start_empty() {
        let engine = MlFraudEngine::new();
        // Accessing logs through the RwLock should work
        let logs = engine.logs.read().await;
        assert_eq!(logs.len(), 0);
    }

    #[test]
    fn test_rule_based_fallback_normal_request() {
        let event = MlEvent {
            ip: "1.2.3.4".to_string(),
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            query: None,
            timestamp: 0,
            header_count: 5,
            user_agent_len: 50,
            body_len: 0,
            body_snippet: String::new(),
        };
        let entry = rule_based_score(&event, MlFraudMode::Shadow);
        assert!(!entry.flagged, "normal request should not be flagged");
        assert_eq!(entry.action_taken, "Pass");
    }

    #[test]
    fn test_rule_based_fallback_suspicious_request() {
        let long_path = "/".repeat(600);
        let event = MlEvent {
            ip: "1.2.3.4".to_string(),
            method: "POST".to_string(),
            path: long_path,
            query: None,
            timestamp: 0,
            header_count: 0,
            user_agent_len: 0,   // missing UA
            body_len: 2_000_000, // very large body
            body_snippet: String::new(),
        };
        let entry = rule_based_score(&event, MlFraudMode::Shadow);
        assert!(entry.flagged, "suspicious request should be flagged");
        assert_eq!(entry.action_taken, "ShadowFlag");
    }

    #[test]
    fn test_rule_based_fallback_active_mode_bans() {
        let long_path = "/".repeat(600);
        let event = MlEvent {
            ip: "1.2.3.4".to_string(),
            method: "POST".to_string(),
            path: long_path,
            query: None,
            timestamp: 0,
            header_count: 0,
            user_agent_len: 0,
            body_len: 0,
            body_snippet: String::new(),
        };
        let entry = rule_based_score(&event, MlFraudMode::Active);
        assert!(entry.flagged);
        assert_eq!(entry.action_taken, "IpBanned");
    }

    #[test]
    fn test_rule_based_score_capped_at_one() {
        let event = MlEvent {
            ip: "1.2.3.4".to_string(),
            method: "PUT".to_string(),
            path: "/".repeat(600) + ".js", // long + static file method
            query: None,
            timestamp: 0,
            header_count: 0,
            user_agent_len: 0,
            body_len: 2_000_000,
            body_snippet: String::new(),
        };
        let entry = rule_based_score(&event, MlFraudMode::Shadow);
        assert!(entry.fraud_score <= 1.0);
    }

    #[test]
    fn test_ml_event_query_optional() {
        let event_no_query = MlEvent {
            ip: "1.1.1.1".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            timestamp: 0,
            header_count: 0,
            user_agent_len: 0,
            body_len: 0,
            body_snippet: String::new(),
        };
        assert!(event_no_query.query.is_none());

        let event_with_query = MlEvent {
            ip: "1.1.1.1".to_string(),
            method: "GET".to_string(),
            path: "/search".to_string(),
            query: Some("q=test".to_string()),
            timestamp: 0,
            header_count: 0,
            user_agent_len: 0,
            body_len: 0,
            body_snippet: String::new(),
        };
        assert_eq!(event_with_query.query, Some("q=test".to_string()));
    }

    #[test]
    fn test_model_loaded_flag_defaults_to_false() {
        let engine = MlFraudEngine::new();
        assert!(!engine.is_model_loaded(), "model should not be loaded on fresh engine");
        assert!(engine.is_fallback_mode(), "should be in fallback mode when no model loaded");
    }

    #[tokio::test]
    async fn test_load_model_with_invalid_path_sets_fallback() {
        let engine = MlFraudEngine::new();
        let reputation = IpReputationManager::new(10, 3600, None);
        // Load with a nonexistent model path — should trigger fallback
        engine.load_model("/nonexistent/model.onnx", reputation, None).await;
        // Give the spawned worker a moment to attempt model load
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(!engine.is_model_loaded(), "model should not be loaded for invalid path");
        assert!(engine.is_fallback_mode(), "should be in fallback mode after load failure");
    }

    #[tokio::test]
    async fn test_load_model_failure_increments_metric() {
        let engine = MlFraudEngine::new();
        let reputation = IpReputationManager::new(10, 3600, None);
        let counter = prometheus::IntCounter::new(
            "test_ml_load_failures",
            "test counter",
        ).unwrap();
        assert_eq!(counter.get(), 0);
        engine.load_model("/nonexistent/model.onnx", reputation, Some(counter.clone())).await;
        // Give the spawned worker time to attempt model load and increment counter
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(counter.get(), 1, "metric should be incremented on model load failure");
    }
}
