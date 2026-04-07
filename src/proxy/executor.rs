//! Hyper executor adapter for the Tokio runtime.
//!
//! Hyper's HTTP/2 server requires an `Executor` implementation to spawn
//! background tasks (e.g. for multiplexed stream handling). This module
//! provides a thin wrapper that delegates to `tokio::spawn`.

use std::future::Future;
use hyper::rt::Executor;

/// A zero-sized executor that bridges hyper's `Executor` trait to Tokio.
///
/// Used when constructing `hyper::server::conn::http2::Builder` so that
/// hyper can spawn internal connection-management futures on the Tokio
/// runtime without the caller needing to pass a runtime handle explicitly.
#[derive(Clone)]
pub struct TokioExecutor;

impl<F> Executor<F> for TokioExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    /// Spawns the future as an independent Tokio task.
    /// The task runs concurrently with all other work on the runtime.
    fn execute(&self, future: F) {
        tokio::spawn(future);
    }
}
