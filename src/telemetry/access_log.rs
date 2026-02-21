use serde::Serialize;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{error, info};

/// A single structured access log entry, written as JSON per line.
#[derive(Debug, Serialize)]
pub struct AccessLogEntry {
    pub timestamp: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: u64,
    pub backend: String,
    pub pool: String,
    pub bytes_sent: u64,
}

/// Async access log writer that receives log entries via a channel
/// and writes them as newline-delimited JSON to the log file.
pub struct AccessLogger {
    sender: mpsc::UnboundedSender<AccessLogEntry>,
}

impl AccessLogger {
    /// Initializes the access logger with an async file writer.
    /// Creates the log directory if it doesn't exist.
    pub fn new(log_path: &str) -> Self {
        let (sender, mut receiver) = mpsc::unbounded_channel::<AccessLogEntry>();
        let path = log_path.to_string();

        tokio::spawn(async move {
            // Create logs directory if needed
            if let Some(parent) = std::path::Path::new(&path).parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }

            let file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await;

            match file {
                Ok(mut f) => {
                    info!("Access log writer started: {}", path);
                    while let Some(entry) = receiver.recv().await {
                        if let Ok(json) = serde_json::to_string(&entry) {
                            let line = format!("{}\n", json);
                            if let Err(e) = f.write_all(line.as_bytes()).await {
                                error!("Failed to write access log: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to open access log file {}: {}", path, e);
                    // Drain the channel to avoid blocking senders
                    while receiver.recv().await.is_some() {}
                }
            }
        });

        Self { sender }
    }

    /// Non-blocking log entry submission. Returns immediately.
    pub fn log(&self, entry: AccessLogEntry) {
        let _ = self.sender.send(entry);
    }
}
