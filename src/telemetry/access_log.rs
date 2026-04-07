//! Structured access log writer.
//!
//! Receives log entries through an unbounded MPSC channel and writes them
//! asynchronously to a log file in JSON, Nginx "combined", or Apache
//! "common" format. The writer runs in a dedicated background task so
//! callers never block on disk I/O.

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{error, info};

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

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
    /// Parses a format name string (case-insensitive). Unrecognised values
    /// default to `Json`.
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
    /// W3C Trace Context trace ID for request correlation.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub trace_id: String,
}

impl AccessLogEntry {
    /// Render as a Nginx "combined"-format line (includes trace_id when present).
    fn as_combined(&self) -> String {
        if self.trace_id.is_empty() {
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
        } else {
            format!(
                "{} - [{}] \"{} {} HTTP/1.1\" {} {} \"{}\" \"{}\" trace_id={}",
                self.client_ip,
                self.timestamp,
                self.method,
                self.path,
                self.status,
                self.bytes_sent,
                self.referer,
                self.user_agent,
                self.trace_id,
            )
        }
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

                    #[cfg(unix)]
                    {
                        let mut sigusr1 = match signal(SignalKind::user_defined1()) {
                            Ok(s) => s,
                            Err(e) => {
                                error!("Failed to register SIGUSR1 handler for log rotation: {}", e);
                                // Fall back to non-rotation mode
                                while let Some(entry) = receiver.recv().await {
                                    let line = format_entry(&entry, format);
                                    if !line.is_empty() {
                                        let _ = f.write_all(format!("{}\n", line).as_bytes()).await;
                                    }
                                }
                                return;
                            }
                        };

                        loop {
                            tokio::select! {
                                entry = receiver.recv() => {
                                    match entry {
                                        Some(entry) => {
                                            let line = format_entry(&entry, format);
                                            if !line.is_empty() {
                                                let _ = f.write_all(format!("{}\n", line).as_bytes()).await;
                                            }
                                        }
                                        None => break, // channel closed
                                    }
                                }
                                _ = sigusr1.recv() => {
                                    info!("SIGUSR1 received — reopening access log: {}", path);
                                    let _ = f.flush().await;
                                    drop(f);
                                    match tokio::fs::OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open(&path)
                                        .await
                                    {
                                        Ok(new_f) => {
                                            f = new_f;
                                            info!("Access log reopened successfully: {}", path);
                                        }
                                        Err(e) => {
                                            error!("Failed to reopen access log {}: {}", path, e);
                                            // Re-create a dummy file so `f` is valid
                                            f = match tokio::fs::OpenOptions::new()
                                                .create(true)
                                                .append(true)
                                                .open(&path)
                                                .await
                                            {
                                                Ok(fallback) => fallback,
                                                Err(_) => return, // fatal: cannot reopen
                                            };
                                        }
                                    }
                                }
                            }
                        }
                    }

                    #[cfg(not(unix))]
                    {
                        while let Some(entry) = receiver.recv().await {
                            let line = format_entry(&entry, format);
                            if !line.is_empty() {
                                let _ = f.write_all(format!("{}\n", line).as_bytes()).await;
                            }
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

/// Formats a log entry according to the specified format.
fn format_entry(entry: &AccessLogEntry, format: LogFormat) -> String {
    match format {
        LogFormat::Json => serde_json::to_string(entry).unwrap_or_else(|_| String::new()),
        LogFormat::Combined => entry.as_combined(),
        LogFormat::Common => entry.as_common(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_format_from_str() {
        assert_eq!(LogFormat::from_str("json"), LogFormat::Json);
        assert_eq!(LogFormat::from_str("combined"), LogFormat::Combined);
        assert_eq!(LogFormat::from_str("common"), LogFormat::Common);
        assert_eq!(LogFormat::from_str("COMBINED"), LogFormat::Combined);
        assert_eq!(LogFormat::from_str("unknown"), LogFormat::Json);
        assert_eq!(LogFormat::from_str(""), LogFormat::Json);
    }

    fn sample_entry() -> AccessLogEntry {
        AccessLogEntry {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            client_ip: "192.168.1.1".to_string(),
            method: "GET".to_string(),
            path: "/api/v1/data".to_string(),
            status: 200,
            latency_ms: 42,
            backend: "10.0.0.1:8080".to_string(),
            pool: "default".to_string(),
            bytes_sent: 1024,
            referer: "https://example.com".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            trace_id: String::new(),
        }
    }

    #[test]
    fn test_as_combined_format() {
        let entry = sample_entry();
        let line = entry.as_combined();
        assert!(line.contains("192.168.1.1"));
        assert!(line.contains("GET /api/v1/data HTTP/1.1"));
        assert!(line.contains("200"));
        assert!(line.contains("1024"));
        assert!(line.contains("Mozilla/5.0"));
        assert!(line.contains("https://example.com"));
    }

    #[test]
    fn test_as_common_format() {
        let entry = sample_entry();
        let line = entry.as_common();
        assert!(line.contains("192.168.1.1"));
        assert!(line.contains("GET /api/v1/data HTTP/1.1"));
        assert!(line.contains("200"));
        assert!(line.contains("1024"));
        assert!(!line.contains("Mozilla"));
    }

    #[test]
    fn test_access_log_entry_json_serialization() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"client_ip\":\"192.168.1.1\""));
        assert!(json.contains("\"status\":200"));
        assert!(json.contains("\"latency_ms\":42"));
    }

    #[test]
    fn test_access_log_entry_fields() {
        let entry = sample_entry();
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.pool, "default");
        assert_eq!(entry.bytes_sent, 1024);
    }

    #[test]
    fn test_format_entry_json() {
        let entry = sample_entry();
        let line = format_entry(&entry, LogFormat::Json);
        assert!(line.contains("\"client_ip\":\"192.168.1.1\""));
        assert!(line.contains("\"status\":200"));
    }

    #[test]
    fn test_format_entry_combined() {
        let entry = sample_entry();
        let line = format_entry(&entry, LogFormat::Combined);
        assert!(line.contains("192.168.1.1"));
        assert!(line.contains("GET /api/v1/data HTTP/1.1"));
        assert!(line.contains("Mozilla/5.0"));
    }

    #[test]
    fn test_format_entry_common() {
        let entry = sample_entry();
        let line = format_entry(&entry, LogFormat::Common);
        assert!(line.contains("192.168.1.1"));
        assert!(!line.contains("Mozilla"));
    }

    #[test]
    fn test_trace_id_in_json() {
        let mut entry = sample_entry();
        entry.trace_id = "abc123def456".to_string();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"trace_id\":\"abc123def456\""));
    }

    #[test]
    fn test_trace_id_omitted_when_empty() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("trace_id"));
    }

    #[test]
    fn test_trace_id_in_combined_format() {
        let mut entry = sample_entry();
        entry.trace_id = "trace-xyz".to_string();
        let line = entry.as_combined();
        assert!(line.contains("trace_id=trace-xyz"));
    }

    #[tokio::test]
    async fn test_access_logger_writes_entry() {
        let dir = std::env::temp_dir().join(format!("phalanx_log_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let log_path = dir.join("access.log");
        let logger = AccessLogger::new(log_path.to_str().unwrap(), LogFormat::Json);
        logger.log(sample_entry());
        // Allow background writer to flush
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let contents = tokio::fs::read_to_string(&log_path).await.unwrap_or_default();
        assert!(contents.contains("192.168.1.1"), "log file should contain the entry");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
