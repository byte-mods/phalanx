//! uWSGI binary protocol gateway.
//!
//! Translates incoming HTTP requests into the uWSGI binary wire protocol and
//! forwards them to a uWSGI application server (typically Python/Django/Flask).
//!
//! The uWSGI protocol uses a compact binary header format:
//! - Byte 0:  `modifier1` (0 = WSGI/Python)
//! - Bytes 1-2: payload size (little-endian u16)
//! - Byte 3:  `modifier2`
//! - Followed by key-value pairs encoded as `[key_len_u16_le][key][val_len_u16_le][val]`
//!
//! After sending the header + request body, the server responds with standard
//! CGI-style headers followed by a `\r\n\r\n` separator and the response body.

use bytes::{Bytes, BytesMut};
use futures_util::stream::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const EXEC_TIMEOUT: Duration = Duration::from_secs(30);

use crate::proxy::chrono_timestamp;
use crate::telemetry::access_log::{AccessLogEntry, AccessLogger};

/// Constructs an empty HTTP response with the given status code.
/// Used for error responses when the uWSGI server is unreachable.
fn empty_response(status: hyper::StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .body(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Forwards an HTTP request to a uWSGI backend using the uWSGI binary protocol
/// and returns the translated HTTP response.
///
/// # Arguments
///
/// * `_route_path`   - The matched route prefix (unused, kept for signature parity).
/// * `req_path`      - The full request path (e.g. `/app/endpoint`).
/// * `uwsgi_pass`    - `host:port` of the uWSGI server (e.g. `"127.0.0.1:3031"`).
/// * `req`           - The incoming HTTP request (headers + streaming body).
/// * `access_logger` - Logger for structured access log entries.
/// * `method_str`    - HTTP method as a string (e.g. `"POST"`).
/// * `ip_str`        - Client IP address string for logging.
///
/// # Returns
///
/// An HTTP response with the uWSGI application's status, headers, and streamed
/// body. Returns 502 Bad Gateway if the uWSGI server is unreachable.
pub async fn serve_uwsgi<T>(
    _route_path: &str,
    req_path: &str,
    uwsgi_pass: String,
    req: Request<T>,
    access_logger: Arc<AccessLogger>,
    method_str: &str,
    ip_str: &str,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
where
    T: hyper::body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
    T::Error: std::fmt::Display + Send + Sync + 'static,
{
    let start_time = std::time::Instant::now();

    let stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&uwsgi_pass)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            error!("Failed to connect to uWSGI server {}: {}", uwsgi_pass, e);
            access_logger.log(AccessLogEntry {
                timestamp: chrono_timestamp(),
                client_ip: ip_str.to_string(),
                method: method_str.to_string(),
                path: req_path.to_string(),
                status: 502,
                latency_ms: start_time.elapsed().as_millis() as u64,
                backend: "uwsgi".to_string(),
                pool: uwsgi_pass,
                bytes_sent: 0,
                referer: String::new(),
                user_agent: String::new(),
                trace_id: String::new(),
            });
            return Ok(empty_response(StatusCode::BAD_GATEWAY));
        }
        Err(_elapsed) => {
            error!(
                "Timeout connecting to uWSGI server {} ({}s)",
                uwsgi_pass,
                CONNECT_TIMEOUT.as_secs()
            );
            access_logger.log(AccessLogEntry {
                timestamp: chrono_timestamp(),
                client_ip: ip_str.to_string(),
                method: method_str.to_string(),
                path: req_path.to_string(),
                status: 502,
                latency_ms: start_time.elapsed().as_millis() as u64,
                backend: "uwsgi".to_string(),
                pool: uwsgi_pass,
                bytes_sent: 0,
                referer: String::new(),
                user_agent: String::new(),
                trace_id: String::new(),
            });
            return Ok(empty_response(StatusCode::BAD_GATEWAY));
        }
    };

    let (mut rx, mut tx) = stream.into_split();
    let (parts, body) = req.into_parts();

    // Construct the uWSGI variable dictionary from HTTP request metadata.
    // Each key-value pair maps to a CGI environment variable.
    let mut params = std::collections::HashMap::new();
    params.insert("REQUEST_METHOD".to_string(), method_str.to_string());
    params.insert("REQUEST_URI".to_string(), req_path.to_string());
    params.insert("PATH_INFO".to_string(), req_path.to_string());
    params.insert(
        "QUERY_STRING".to_string(),
        parts.uri.query().unwrap_or("").to_string(),
    );
    params.insert("SERVER_PROTOCOL".to_string(), "HTTP/1.1".to_string());
    params.insert("REMOTE_ADDR".to_string(), ip_str.to_string());
    params.insert("SERVER_NAME".to_string(), "phalanx".to_string());
    params.insert("SERVER_PORT".to_string(), "80".to_string());

    for (name, value) in parts.headers.iter() {
        let key = format!("HTTP_{}", name.as_str().to_uppercase().replace("-", "_"));
        if let Ok(v) = value.to_str() {
            params.insert(key, v.to_string());
        }
    }

    // Encode the key-value dictionary in the uWSGI binary format:
    // Each pair: [key_len: u16 LE][key bytes][val_len: u16 LE][val bytes]
    let mut payload = Vec::new();
    for (k, v) in params {
        payload.extend_from_slice(&(k.len() as u16).to_le_bytes());
        payload.extend_from_slice(k.as_bytes());
        payload.extend_from_slice(&(v.len() as u16).to_le_bytes());
        payload.extend_from_slice(v.as_bytes());
    }

    // Build the 4-byte uWSGI packet header:
    //   [modifier1][payload_size_lo][payload_size_hi][modifier2]
    let mut header = vec![0; 4];
    header[0] = 0; // modifier1=0 (WSGI Python application)
    let data_size = payload.len() as u16;
    header[1] = (data_size & 0xff) as u8;       // low byte of payload size
    header[2] = ((data_size >> 8) & 0xff) as u8; // high byte of payload size
    header[3] = 0; // modifier2 (unused for standard WSGI)

    // Append the encoded dictionary right after the 4-byte header
    header.extend(payload);

    // Write the uWSGI header + body to the backend in a separate task so the
    // response can be read concurrently (full-duplex over the split TCP stream).
    tokio::spawn(async move {
        if let Err(e) = tx.write_all(&header).await {
            error!("Fail writing uWSGI header: {}", e);
            return;
        }
        let mut body_stream = body.into_data_stream();
        while let Some(chunk) = body_stream.next().await {
            if let Ok(bytes) = chunk {
                if let Err(e) = tx.write_all(&bytes).await {
                    error!("Fail writing uWSGI body chunk: {}", e);
                    break;
                }
            }
        }
    });

    // Read uWSGI response stream: buffer until we find the CGI header/body separator.
    let mut header_buf = Vec::new();
    let mut cgi_headers_done = false;
    let mut first_body_chunk = None;

    let header_read = tokio::time::timeout(EXEC_TIMEOUT, async {
        let mut buf = [0; 4096];
        loop {
            match rx.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = &buf[..n];
                    if !cgi_headers_done {
                        header_buf.extend_from_slice(chunk);
                        if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let body_start = header_buf.split_off(pos + 4);
                            if !body_start.is_empty() {
                                first_body_chunk = Some(Bytes::from(body_start));
                            }
                            cgi_headers_done = true;
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }).await;

    if header_read.is_err() {
        error!("uWSGI response header read timeout ({}s)", EXEC_TIMEOUT.as_secs());
        return Ok(empty_response(StatusCode::GATEWAY_TIMEOUT));
    }

    if !cgi_headers_done {
        error!(
            "Did not receive valid CGI headers from uWSGI, buffered so far: {}",
            String::from_utf8_lossy(&header_buf)
        );
        return Ok(empty_response(StatusCode::BAD_GATEWAY));
    }

    let header_str = String::from_utf8_lossy(&header_buf);
    let mut builder = Response::builder().status(StatusCode::OK);

    for line in header_str.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        // Sometimes backend returns "HTTP/1.1 200 OK"
        if line.to_uppercase().starts_with("HTTP/") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(c) = parts[1].parse::<u16>() {
                    builder = builder.status(c);
                }
            }
            continue;
        }

        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let value = v.trim();
            if key.eq_ignore_ascii_case("status") {
                if let Some(code) = value.split_whitespace().next() {
                    if let Ok(c) = code.parse::<u16>() {
                        builder = builder.status(c);
                    }
                }
            } else {
                builder = builder.header(key, value);
            }
        }
    }

    let uwsgi_stream = async_stream::stream! {
        if let Some(first) = first_body_chunk {
            yield Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(first));
        }

        let mut stream_buf = BytesMut::with_capacity(8192);
        loop {
            // Read next chunk directly into BytesMut to avoid copying payload over into body frame.
            let n = match rx.read_buf(&mut stream_buf).await {
                Ok(n) => n,
                Err(e) => {
                    error!("uWSGI stream chunk error: {}", e);
                    break;
                }
            };
            if n == 0 { break; }
            let bytes = stream_buf.split().freeze();
            yield Ok(hyper::body::Frame::data(bytes));
        }
    };

    let stream_body = BodyExt::boxed(BodyExt::map_err(
        StreamBody::new(uwsgi_stream),
        |never| match never {},
    ));
    let response = builder.body(stream_body).unwrap();

    let latency = start_time.elapsed().as_millis() as u64;
    access_logger.log(AccessLogEntry {
        timestamp: chrono_timestamp(),
        client_ip: ip_str.to_string(),
        method: method_str.to_string(),
        path: req_path.to_string(),
        status: response.status().as_u16(),
        latency_ms: latency,
        backend: "uwsgi".to_string(),
        pool: uwsgi_pass,
        bytes_sent: 0,
        referer: String::new(),
        user_agent: String::new(),
        trace_id: String::new(),
    });

    Ok(response)
}
