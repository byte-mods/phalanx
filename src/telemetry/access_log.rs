use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{error, info};

/// The output format for access log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Newline-delimited JSON (structured, default).
    Json,
    /// Nginx "combined" log format:
    /// `$ip - [$time] "$method $path HTTP/1.1" $status $bytes "$referer" "$ua"`
    Combined,
    /// Apache "common" log format (no referer/ua):
    /// `$ip - - [$time] "$method $path HTTP/1.1" $status $bytes`
    Common,
}

impl LogFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "combined" => LogFormat::Combined,
            "common" => LogFormat::Common,
            _ => LogFormat::Json,
        }
    }
}

/// A single structured access log entry.
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
    /// HTTP Referer header value (empty string if absent).
    pub referer: String,
    /// HTTP User-Agent header value (empty string if absent).
    pub user_agent: String,
}

impl AccessLogEntry {
    /// Render as a Nginx "combined"-format line.
    fn as_combined(&self) -> String {
        format!(
            "{} - [{}] \"{} {} HTTP/1.1\" {} {} \"{}\" \"{}\"",
            self.client_ip,
            self.timestamp,
            self.method,
            self.path,
            self.status,
            self.bytes_sent,
            self.referer,
            self.user_agent,
        )
    }

    /// Render as an Apache "common"-format line.
    fn as_common(&self) -> String {
        format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} {}",
            self.client_ip, self.timestamp, self.method, self.path, self.status, self.bytes_sent,
        )
    }
}

/// Async access log writer that receives log entries via a channel
/// and appends them to a log file in the configured format.
pub struct AccessLogger {
    sender: mpsc::UnboundedSender<AccessLogEntry>,
}

impl AccessLogger {
    /// Initializes the access logger with an async file writer.
    /// Creates the log directory if it doesn't exist.
    pub fn new(log_path: &str, format: LogFormat) -> Self {
        let (sender, mut receiver) = mpsc::unbounded_channel::<AccessLogEntry>();
        let path = log_path.to_string();

        tokio::spawn(async move {
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
                    info!("Access log writer started: {} (format: {:?})", path, format);
                    while let Some(entry) = receiver.recv().await {
                        let line = match format {
                            LogFormat::Json => {
                                serde_json::to_string(&entry).unwrap_or_else(|_| String::new())
                            }
                            LogFormat::Combined => entry.as_combined(),
                            LogFormat::Common => entry.as_common(),
                        };
                        if !line.is_empty() {
                            let _ = f.write_all(format!("{}\n", line).as_bytes()).await;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to open access log file {}: {}", path, e);
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
