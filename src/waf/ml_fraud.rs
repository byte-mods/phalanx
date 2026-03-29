use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
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

/// A serialized log entry for the Dashboard UI
#[derive(Debug, Clone, Serialize)]
pub struct MlLogEntry {
    pub timestamp: u64,
    pub ip: String,
    pub path: String,
    pub payload_snippet: String,
    pub fraud_score: f32,
    pub flagged: bool,
    pub action_taken: String,
}

/// Request metadata captured asynchronously for ML inference
#[derive(Debug, Clone)]
pub struct MlEvent {
    pub ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub timestamp: u64,
    pub header_count: usize,
    pub user_agent_len: usize,
    pub body_len: usize,
    pub body_snippet: String,
}

/// The ML Inference background engine
pub struct MlFraudEngine {
    tx: std::sync::RwLock<Option<mpsc::Sender<MlEvent>>>,
    pub mode: Arc<ArcSwap<MlFraudMode>>,
    pub logs: Arc<RwLock<VecDeque<MlLogEntry>>>,
}

impl MlFraudEngine {
    /// Creates a new uninitialized ML engine (no model loaded yet).
    pub fn new() -> Self {
        Self {
            tx: std::sync::RwLock::new(None),
            mode: Arc::new(ArcSwap::from_pointee(MlFraudMode::Shadow)),
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
        }
    }

    /// Triggers an asynchronous reload of the ONNX model and spawns the inference worker.
    pub async fn load_model(&self, model_path: &str, reputation: Arc<IpReputationManager>) {
        info!("ML Fraud Engine: Loading ONNX model from {}", model_path);

        let model_path_v = model_path.to_string();
        
        let (tx, mut rx) = mpsc::channel::<MlEvent>(10_000);
        if let Ok(mut guard) = self.tx.write() {
            *guard = Some(tx);
        }
        
        let mode_ref = Arc::clone(&self.mode);
        let logs_ref = Arc::clone(&self.logs);

        // Spawn the dedicated background worker
        tokio::spawn(async move {
            info!("ML Fraud Worker: Booting and compiling ONNX graph...");
            
            // Model compilation is blocking, so yield to blocking thread
            let model_result = tokio::task::spawn_blocking(move || {
                tract_onnx::onnx()
                    .model_for_path(&model_path_v)?
                    .into_optimized()?
                    .into_runnable()
            }).await.unwrap_or_else(|e| Err(anyhow::anyhow!("JoinError: {}", e)));

            let model = match model_result {
                Ok(m) => m,
                Err(e) => {
                    error!("ML Fraud Worker: Failed to load ONNX model. Worker shutting down. Error: {}", e);
                    return;
                }
            };

            info!("ML Fraud Worker: ONNX model successfully loaded and active.");

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

                let model_clone = model.clone();
                let event_clone = event.clone();
                let current_mode = **mode_ref.load();
                
                // Perform Tract synchronous inference on a spawn_blocking thread
                // so we don't block the MPSC receiver loop or Tokio core for long inputs
                let log_entry = tokio::task::spawn_blocking(move || {
                    let mut is_fraud = false;
                    let mut score = 0.0;
                    
                    let tensor = tract_ndarray::Array1::from_vec(features).into_tensor();
                    // Reshape to (1, 6) if the model expects batching
                    let reshaped = tensor.clone().into_shape(&[1, 6]).unwrap_or(tensor);
                    
                    if let Ok(result) = model_clone.run(tvec!(reshaped.into())) {
                            if let Ok(view) = result[0].to_array_view::<f32>() {
                                if let Some(first_val) = view.iter().next() {
                                    score = *first_val;
                                    // Assuming a CatBoost binary classifier output: positive => fraud
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
                    path: event.path,
                    payload_snippet: event.body_snippet,
                    fraud_score: -1.0,
                    flagged: false,
                    action_taken: "InferenceError".to_string(),
                });

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

impl Default for MlFraudEngine {
    fn default() -> Self {
        Self::new()
    }
}
