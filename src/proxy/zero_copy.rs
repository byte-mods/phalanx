use tokio::io::{AsyncRead, AsyncWrite};

/// Bi-directionally proxies data between two generic streams using Tokio's fallback.
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
    use nix::fcntl::{OFlag, SpliceFFlags, splice};
    use nix::unistd::pipe2;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::io::OwnedFd;
    use tokio::net::TcpStream;

    async fn splice_unidirectional(
        src: &TcpStream,
        dst: &TcpStream,
        pipe_read: RawFd,
        pipe_write: RawFd,
    ) -> std::io::Result<u64> {
        let mut total_copied: u64 = 0;
        let mut bytes_in_pipe: usize = 0;

        loop {
            // Fill pipe
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
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
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

            // Drain pipe
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
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
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

    /// True zero-copy bidirectional proxy for TcpStreams using Linux `splice`.
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
