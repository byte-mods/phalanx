/// Upstream keepalive connection pool.
///
/// Maintains a per-backend queue of idle TCP connections that can be reused
/// across requests, avoiding the overhead of a new TCP handshake per request.
///
/// Behaviour:
/// - `acquire()` — pops from the idle queue; opens a new connection if empty.
/// - `release()` — pushes the connection back if the queue is not full.
/// - Max idle connections per backend: `max_idle` (from `keepalive N;` config).
/// - When `max_idle == 0`, the pool is disabled and every call opens a fresh connection.
/// - Idle connections are NOT proactively expired here; any dead connection will
///   surface as an I/O error on first use, at which point the caller should discard it.
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Thread-safe pool of idle TCP connections, keyed by backend address.
pub struct ConnectionPool {
    /// Maximum idle connections per backend address (0 = pooling disabled).
    max_idle: u32,
    /// Map from backend address string → idle connection queue.
    idle: Arc<Mutex<HashMap<String, VecDeque<TcpStream>>>>,
}

impl ConnectionPool {
    /// Create a new pool with the given maximum idle connections per backend.
    pub fn new(max_idle: u32) -> Self {
        Self {
            max_idle,
            idle: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Acquire a connection to `addr`.
    ///
    /// Returns an idle connection from the pool if one is available, otherwise
    /// opens a fresh TCP connection.
    pub async fn acquire(&self, addr: &str) -> std::io::Result<TcpStream> {
        if self.max_idle > 0 {
            let mut guard = self.idle.lock().await;
            if let Some(queue) = guard.get_mut(addr) {
                if let Some(conn) = queue.pop_front() {
                    return Ok(conn);
                }
            }
        }
        // No idle connection available — open a new one.
        TcpStream::connect(addr).await
    }

    /// Return a connection to the pool after use.
    ///
    /// The connection is only kept if pooling is enabled and the per-backend
    /// queue has not yet reached `max_idle`. Drops the connection otherwise.
    pub async fn release(&self, addr: String, conn: TcpStream) {
        if self.max_idle == 0 {
            return; // Pooling disabled — drop immediately.
        }
        let mut guard = self.idle.lock().await;
        let queue = guard.entry(addr).or_insert_with(VecDeque::new);
        if queue.len() < self.max_idle as usize {
            queue.push_back(conn);
        }
        // If queue is full, the connection is dropped here (RAII).
    }

    /// Returns a reference to the shared idle map (for metrics / admin API).
    pub async fn idle_counts(&self) -> HashMap<String, usize> {
        self.idle
            .lock()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_pool_has_zero_max_idle() {
        let pool = ConnectionPool::new(0);
        assert_eq!(pool.max_idle, 0);
    }

    #[test]
    fn pool_max_idle_stored_correctly() {
        let pool = ConnectionPool::new(32);
        assert_eq!(pool.max_idle, 32);
    }
}
