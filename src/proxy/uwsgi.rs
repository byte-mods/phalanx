use bytes::{Bytes, BytesMut};
use futures_util::stream::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::error;

use crate::proxy::chrono_timestamp;
use crate::telemetry::access_log::{AccessLogEntry, AccessLogger};

fn empty_io_response(status: hyper::StatusCode) -> Response<BoxBody<Bytes, std::io::Error>> {
    Response::builder()
        .status(status)
        .body(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

pub async fn serve_uwsgi<T>(
    _route_path: &str,
    req_path: &str,
    uwsgi_pass: String,
    req: Request<T>,
    access_logger: Arc<AccessLogger>,
    method_str: &str,
    ip_str: &str,
) -> Result<Response<BoxBody<Bytes, std::io::Error>>, hyper::Error>
where
    T: hyper::body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    let start_time = std::time::Instant::now();

    let stream = match TcpStream::connect(&uwsgi_pass).await {
        Ok(s) => s,
        Err(e) => {
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
            });
            return Ok(empty_io_response(StatusCode::BAD_GATEWAY));
        }
    };

    let (mut rx, mut tx) = stream.into_split();
    let (parts, mut body) = req.into_parts();

    // Construct uWSGI payload (Dictionary encoding)
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

    let mut payload = Vec::new();
    for (k, v) in params {
        payload.extend_from_slice(&(k.len() as u16).to_le_bytes());
        payload.extend_from_slice(k.as_bytes());
        payload.extend_from_slice(&(v.len() as u16).to_le_bytes());
        payload.extend_from_slice(v.as_bytes());
    }

    let mut header = vec![0; 4];
    header[0] = 0; // modifier1=0 (WSGI Python)
    let data_size = payload.len() as u16;
    header[1] = (data_size & 0xff) as u8;
    header[2] = ((data_size >> 8) & 0xff) as u8;
    header[3] = 0; // modifier2

    header.extend(payload);

    // Write request headers and body asynchronously to upstream
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

    // Read uWSGI response stream
    let mut header_buf = Vec::new();
    let mut cgi_headers_done = false;
    let mut first_body_chunk = None;

    let mut buf = [0; 4096];
    while let Ok(n) = rx.read(&mut buf).await {
        if n == 0 {
            break;
        }

        let chunk = &buf[..n];
        if !cgi_headers_done {
            header_buf.extend_from_slice(chunk);
            if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let mut body_start = header_buf.split_off(pos + 4);
                if !body_start.is_empty() {
                    first_body_chunk = Some(Bytes::from(body_start));
                }
                cgi_headers_done = true;
                break;
            }
        }
    }

    if !cgi_headers_done {
        error!(
            "Did not receive valid CGI headers from uWSGI, buffered so far: {}",
            String::from_utf8_lossy(&header_buf)
        );
        return Ok(empty_io_response(StatusCode::BAD_GATEWAY));
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
            yield Ok::<_, std::io::Error>(hyper::body::Frame::data(first));
        }

        let mut stream_buf = BytesMut::with_capacity(8192);
        loop {
            // Read next chunk directly into BytesMut to avoid copying payload over into body frame.
            let n = match rx.read_buf(&mut stream_buf).await {
                Ok(n) => n,
                Err(e) => {
                    error!("uWSGI stream chunk error: {}", e);
                    yield Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "disconnected"));
                    break;
                }
            };
            if n == 0 { break; }
            let bytes = stream_buf.split().freeze();
            yield Ok(hyper::body::Frame::data(bytes));
        }
    };

    let stream_body = BodyExt::boxed(StreamBody::new(uwsgi_stream));
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
    });

    Ok(response)
}
