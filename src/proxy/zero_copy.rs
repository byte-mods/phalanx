//! Zero-copy bidirectional data transfer.
//!
//! Provides two implementations for relaying bytes between a client stream and
//! a backend stream:
//!
//! 1. **Fallback (all platforms)** -- `copy_bidirectional_fallback` uses Tokio's
//!    userspace `copy_bidirectional`, which copies data through a kernel-to-user
//!    bounce buffer.
//! 2. **Linux splice (zero-copy)** -- `linux::splice_bidirectional` uses the
//!    `splice(2)` syscall to move data between file descriptors via an in-kernel
//!    pipe, avoiding any user-space copy and halving the number of context
//!    switches per byte transferred.
//!
//! The TCP and WebSocket proxy modules choose the optimal implementation at
//! compile time with `#[cfg(target_os = "linux")]`.

use tokio::io::{AsyncRead, AsyncWrite};

/// Bi-directionally proxies data between two generic async streams using Tokio's
/// userspace `copy_bidirectional`.
///
/// Returns `(bytes_a_to_b, bytes_b_to_a)` on success.
///
/// This is the portable fallback used on macOS, Windows, and any non-Linux target.
pub async fn copy_bidirectional_fallback<A, B>(
    a: &mut A,
    b: &mut B,
) -> Result<(u64, u64), std::io::Error>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::io::copy_bidirectional(a, b).await
}

#[cfg(target_os = "linux")]
pub mod linux {
    //! Linux-specific zero-copy implementation using the `splice(2)` syscall.
    //!
    //! Data flows: socket_fd -> pipe -> socket_fd, entirely inside the kernel.
    //! This eliminates all user-space memory copies and is significantly faster
    //! for high-throughput TCP proxying (e.g. database traffic, video streaming).

    use nix::fcntl::{OFlag, SpliceFFlags, splice};
    use nix::unistd::pipe2;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::io::OwnedFd;
    use tokio::net::TcpStream;

    /// Convert a nix::Error to std::io::Error by extracting the real OS errno.
    /// The `e as i32` cast gives the enum discriminant, NOT the errno code.
    fn nix_to_io(e: nix::Error) -> std::io::Error {
        match e.as_errno() {
            Some(errno) => std::io::Error::from(errno),
            None => std::io::Error::new(std::io::ErrorKind::Other, e),
        }
    }

    /// Splice data in one direction: `src` socket -> kernel pipe -> `dst` socket.
    ///
    /// Runs in a loop until `src` reaches EOF (returns 0 from splice).
    /// Uses non-blocking splice with Tokio readiness notifications to avoid
    /// busy-waiting.
    ///
    /// # Returns
    /// Total bytes transferred from `src` to `dst`.
    async fn splice_unidirectional(
        src: &TcpStream,
        dst: &TcpStream,
        pipe_read: RawFd,
        pipe_write: RawFd,
    ) -> std::io::Result<u64> {
        let mut total_copied: u64 = 0;
        // Track how many bytes are currently sitting in the kernel pipe buffer,
        // waiting to be drained to the destination socket.
        let mut bytes_in_pipe: usize = 0;

        loop {
            // Phase 1: Fill the pipe from the source socket (splice src_fd -> pipe_write)
            if bytes_in_pipe == 0 {
                let res = src.try_io(tokio::io::Interest::READABLE, || {
                    splice(
                        src.as_raw_fd(),
                        None,
                        pipe_write,
                        None,
                        65536,
                        SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_NONBLOCK,
                    )
                    .map_err(nix_to_io)
                });

                match res {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        bytes_in_pipe += n;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Tokio cleared readiness, await next readable event
                        src.readable().await?;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }

            // Phase 2: Drain the pipe into the destination socket (splice pipe_read -> dst_fd)
            while bytes_in_pipe > 0 {
                let res = dst.try_io(tokio::io::Interest::WRITABLE, || {
                    splice(
                        pipe_read,
                        None,
                        dst.as_raw_fd(),
                        None,
                        65536,
                        SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_NONBLOCK,
                    )
                    .map_err(nix_to_io)
                });

                match res {
                    Ok(0) => {
                        // Destination closed
                        return Ok(total_copied);
                    }
                    Ok(n) => {
                        bytes_in_pipe -= n;
                        total_copied += n as u64;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        dst.writable().await?;
                        break; // exit inner while loop, continue outer loop
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(total_copied)
    }

    /// True zero-copy bidirectional proxy for `TcpStream`s using Linux `splice(2)`.
    ///
    /// Creates two kernel pipes (one per direction) and runs the two
    /// unidirectional splice loops concurrently via `tokio::try_join!`.
    ///
    /// # Returns
    /// `(bytes_client_to_server, bytes_server_to_client)` on success.
    ///
    /// The `OwnedFd` pipe handles are dropped (closed) automatically when
    /// this function returns, preventing file descriptor leaks.
    pub async fn splice_bidirectional(
        client: &mut TcpStream,
        server: &mut TcpStream,
    ) -> std::io::Result<(u64, u64)> {
        // Create two pipes with O_NONBLOCK
        let (c2s_read, c2s_write) =
            pipe2(OFlag::O_NONBLOCK).map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        let (s2c_read, s2c_write) =
            pipe2(OFlag::O_NONBLOCK).map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

        // We map RawFd directly since pipe2 returns OwnedFd in newer nix versions
        let c2s_r_fd = c2s_read.as_raw_fd();
        let c2s_w_fd = c2s_write.as_raw_fd();
        let s2c_r_fd = s2c_read.as_raw_fd();
        let s2c_w_fd = s2c_write.as_raw_fd();

        // Spawn two directional tasks
        // We need to move the &TcpStream references into async blocks.
        // Wait, tokio::try_join! takes futures that borrows local variables! Nothing is spawned.

        let client_to_server = splice_unidirectional(client, server, c2s_r_fd, c2s_w_fd);
        let server_to_client = splice_unidirectional(server, client, s2c_r_fd, s2c_w_fd);

        let (from_client, from_server) = tokio::try_join!(client_to_server, server_to_client)?;

        // The OwnedFd variables (c2s_read, etc) will drop here, securely closing the pipes
        Ok((from_client, from_server))
    }
}
