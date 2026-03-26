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
}
