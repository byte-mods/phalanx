//! End-to-end tests that run the real `phalanx` binary against a real backend
//! over real sockets.
//!
//! These exist because the rest of the suite is composed of unit tests that call
//! individual helpers directly. That left the actual request path —
//! accept → sniff → route → forward → respond — with no coverage at all, and two
//! separate defects that made the proxy answer *nothing* to an ordinary HTTP
//! request shipped with a fully green suite:
//!
//!   1. the PROXY-v2 pre-read consumed the request head, then `sniff_protocol`
//!      issued a second `read()` that blocked forever;
//!   2. the HTTP/1 backend `Connection` future was never polled, so not a single
//!      byte was written upstream.
//!
//! Anything asserted here must hold for a client that writes its request in one
//! `write()` and then waits — i.e. every real HTTP client.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Kills the proxy process when the test ends, including on panic.
struct ProxyGuard(Child);

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Reserves a port by binding and immediately releasing it.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// Minimal HTTP/1.1 backend. Echoes the request line and headers back as JSON so
/// tests can assert on exactly what the proxy forwarded.
fn start_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let peer = stream.try_clone().expect("clone stream");
                let mut reader = BufReader::new(peer);

                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
                    return;
                }

                let mut headers = Vec::new();
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        return;
                    }
                    let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = trimmed.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().unwrap_or(0);
                        }
                        headers.push(format!(
                            "\"{}\":\"{}\"",
                            name.trim().to_lowercase(),
                            value.trim().replace('"', "'")
                        ));
                    }
                }

                let mut body = vec![0u8; content_length];
                if content_length > 0 && reader.read_exact(&mut body).is_err() {
                    return;
                }

                // A body large enough to clear the 1 KB compression threshold.
                let filler = "abcdefghij".repeat(200);
                let payload = format!(
                    "{{\"request_line\":\"{}\",\"headers\":{{{}}},\"filler\":\"{}\"}}",
                    request_line.trim_end_matches(['\r', '\n']),
                    headers.join(","),
                    filler
                );

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            });
        }
    });

    port
}

/// Sends a raw request in a **single** write and returns the full response.
///
/// The single write matters: it is what every real client does, and it is the
/// exact shape that used to hang.
fn raw_request(port: u16, request: &str) -> String {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).expect("connect to proxy");
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().unwrap();

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 1_000_000 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn get(port: u16, path: &str, extra_headers: &str) -> String {
    raw_request(
        port,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra_headers}Connection: close\r\n\r\n"
        ),
    )
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or("").trim_end()
}

fn header_value<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let head = response.split("\r\n\r\n").next()?;
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim())
        } else {
            None
        }
    })
}

#[test]
fn end_to_end_request_path() {
    let backend = start_backend();
    let proxy_port = free_port();
    let admin_port = free_port();

    // Isolated working directory: the binary creates RocksDB/log directories
    // relative to its cwd.
    let workdir = std::env::temp_dir().join(format!("phalanx_e2e_{}", std::process::id()));
    std::fs::create_dir_all(&workdir).expect("create workdir");

    let config = format!(
        r#"
worker_threads 2;
tcp_listen {tcp};
admin_listen 127.0.0.1:{admin};

http {{
    upstream default {{
        server 127.0.0.1:{backend};
        algorithm roundrobin;
    }}

    server {{
        listen {proxy};

        rate_limit_per_ip 100000;
        rate_limit_burst  200000;

        route /gz {{
            upstream default;
            gzip on;
        }}

        route /secure {{
            upstream default;
            auth_basic "Restricted";
            auth_basic_user "alice:wonderland";
        }}

        route /old {{
            upstream default;
            rewrite ^/old/(.+)$ /new/$1 last;
        }}

        route / {{
            upstream default;
        }}
    }}
}}
"#,
        tcp = free_port(),
        admin = admin_port,
        backend = backend,
        proxy = proxy_port,
    );

    let config_path = workdir.join("e2e.conf");
    std::fs::write(&config_path, config).expect("write config");

    let child = Command::new(env!("CARGO_BIN_EXE_ai_load_balancer"))
        .arg(&config_path)
        .current_dir(&workdir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn phalanx binary");
    let _guard = ProxyGuard(child);

    // Wait for the listener to accept and actually answer. A proxy that accepts
    // but never responds must fail this loop rather than hang the test.
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut ready = false;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", proxy_port)).is_ok() {
            let resp = get(proxy_port, "/health", "");
            if resp.starts_with("HTTP/1.1 200") {
                ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        ready,
        "proxy never answered a plain GET — the request path is broken \
         (accepting a connection is not the same as serving it)"
    );

    // ── 1. A request written in one write() is answered ──────────────────────
    let resp = get(proxy_port, "/", "");
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "single-write GET must be answered, got: {}",
        status_line(&resp)
    );
    assert!(
        resp.contains("request_line"),
        "response body must come from the backend, got: {resp:.200}"
    );

    // ── 2. The upstream really received the request (bytes were written) ─────
    assert!(
        resp.contains(r#""request_line":"GET / HTTP/1.1""#),
        "backend must receive an origin-form request line, got: {resp:.400}"
    );

    // ── 3. Origin-form is preserved with a query string (RFC 9112 §3.2.1) ────
    let resp = get(proxy_port, "/thing?a=1&b=2", "");
    assert!(
        resp.contains(r#""request_line":"GET /thing?a=1&b=2 HTTP/1.1""#),
        "query string must survive and stay origin-form, got: {resp:.400}"
    );

    // ── 4. `rewrite … last` reaches the backend, not just route matching ─────
    let resp = get(proxy_port, "/old/page", "");
    assert!(
        resp.contains(r#""request_line":"GET /new/page HTTP/1.1""#),
        "rewritten path must be what the backend receives, got: {resp:.400}"
    );

    // ── 5. Basic auth challenges with Basic, not Bearer (RFC 7617 §2) ────────
    let resp = get(proxy_port, "/secure/x", "");
    assert!(
        resp.starts_with("HTTP/1.1 401"),
        "protected route must challenge, got: {}",
        status_line(&resp)
    );
    let challenge = header_value(&resp, "www-authenticate").unwrap_or("");
    assert!(
        challenge.starts_with("Basic realm="),
        "Basic-protected route must send a Basic challenge, got: {challenge:?}"
    );

    // Correct credentials pass (alice:wonderland).
    let resp = get(
        proxy_port,
        "/secure/x",
        "Authorization: Basic YWxpY2U6d29uZGVybGFuZA==\r\n",
    );
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "valid credentials must be accepted, got: {}",
        status_line(&resp)
    );

    // ── 6. Accept-Encoding qvalues are honoured (RFC 9110 §12.5.3) ───────────
    let resp = get(proxy_port, "/gz/big", "Accept-Encoding: gzip\r\n");
    assert_eq!(
        header_value(&resp, "content-encoding"),
        Some("gzip"),
        "gzip must be applied when the client accepts it"
    );

    let resp = get(proxy_port, "/gz/big", "Accept-Encoding: gzip;q=0\r\n");
    assert_eq!(
        header_value(&resp, "content-encoding"),
        None,
        "`gzip;q=0` explicitly refuses gzip and must not be compressed"
    );

    // ── 7. Keepalive pool is not poisoned across sequential requests ─────────
    for i in 0..5 {
        let resp = get(proxy_port, "/", "");
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "sequential request {i} must succeed, got: {}",
            status_line(&resp)
        );
    }

    let _ = std::fs::remove_dir_all(&workdir);
}
