use bytes::{BufMut, Bytes, BytesMut};
use fastcgi_client::response::Content;
use fastcgi_client::{Client, Params, Request as FcgiRequest};
use futures_util::stream::{StreamExt, TryStreamExt};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_util::io::StreamReader;
use tracing::{debug, error};

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

pub async fn serve_fastcgi<T>(
    _route_path: &str,
    req_path: &str,
    fastcgi_pass: String,
    req: Request<T>,
    access_logger: Arc<AccessLogger>,
    method_str: &str,
    ip_str: &str,
) -> Result<Response<BoxBody<Bytes, std::io::Error>>, hyper::Error>
where
    T: hyper::body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let start_time = std::time::Instant::now();

    let stream = match TcpStream::connect(&fastcgi_pass).await {
        Ok(s) => s,
        Err(e) => {
            error!(
                "Failed to connect to FastCGI server {}: {}",
                fastcgi_pass, e
            );
            access_logger.log(AccessLogEntry {
                timestamp: chrono_timestamp(),
                client_ip: ip_str.to_string(),
                method: method_str.to_string(),
                path: req_path.to_string(),
                status: 502,
                latency_ms: start_time.elapsed().as_millis() as u64,
                backend: "fastcgi".to_string(),
                pool: fastcgi_pass,
                bytes_sent: 0,
                referer: String::new(),
                user_agent: String::new(),
            });
            return Ok(empty_io_response(StatusCode::BAD_GATEWAY));
        }
    };

    let (parts, body) = req.into_parts();
    let query_string = parts.uri.query().unwrap_or("");

    // Setup FastCGI Params
    let mut params = Params::default()
        .request_method(method_str)
        .request_uri(req_path)
        .script_name(req_path)
        .query_string(query_string)
        .remote_addr(ip_str);

    // Standard CGI headers
    let mut cgiparams = std::collections::HashMap::new();
    for (name, value) in parts.headers.iter() {
        let key = format!("HTTP_{}", name.as_str().to_uppercase().replace("-", "_"));
        if let Ok(v) = value.to_str() {
            cgiparams.insert(key, v.to_string());
        }
    }
    for (k, v) in &cgiparams {
        params = params.custom(k, v);
    }

    let mapped_body = body
        .into_data_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.into()));
    let mut body_reader = StreamReader::new(mapped_body);

    let fcgi_req = FcgiRequest::new(params, &mut body_reader);
    let client = Client::new(stream);

    let mut fcgi_res_stream = match client.execute_once_stream(fcgi_req).await {
        Ok(s) => s,
        Err(e) => {
            error!("FastCGI stream execute error: {}", e);
            return Ok(empty_io_response(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };

    // Buffer output until we parse PHP-FPM / CGI headers (\r\n\r\n)
    let mut header_buf = Vec::new();
    let mut cgi_headers_done = false;
    let mut first_body_chunk = None;

    while let Some(content) = fcgi_res_stream.next().await {
        let Ok(content) = content else { break };
        match content {
            Content::Stdout(chunk) => {
                if !cgi_headers_done {
                    header_buf.extend_from_slice(&chunk);
                    // Check for end of headers
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
            Content::Stderr(err) => {
                error!("FastCGI Stderr: {:?}", std::str::from_utf8(&err));
            }
        }
    }

    if !cgi_headers_done {
        error!(
            "Did not receive valid CGI headers from FastCGI, buffered so far: {}",
            String::from_utf8_lossy(&header_buf)
        );
        return Ok(empty_io_response(StatusCode::BAD_GATEWAY));
    }

    let header_str = String::from_utf8_lossy(&header_buf);
    let mut builder = Response::builder().status(StatusCode::OK);

    // Parse CGI headers like `Status: 404 Not Found` or `Content-Type: text/html`
    for line in header_str.split("\r\n") {
        if line.is_empty() {
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

    let fcgi_stream = async_stream::stream! {
        if let Some(first) = first_body_chunk {
            yield Ok::<_, std::io::Error>(hyper::body::Frame::data(first));
        }

        while let Some(content) = fcgi_res_stream.next().await {
            match content {
                Ok(Content::Stdout(chunk)) => {
                    yield Ok(hyper::body::Frame::data(chunk));
                }
                Ok(Content::Stderr(err)) => {
                    error!("FastCGI Stderr: {:?}", std::str::from_utf8(&err));
                }
                Err(e) => {
                    error!("FastCGI stream chunk error: {}", e);
                    yield Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "fcgi disconnected"));
                }
            }
        }
    };

    let stream_body = BodyExt::boxed(StreamBody::new(fcgi_stream));
    let response = builder.body(stream_body).unwrap();

    let latency = start_time.elapsed().as_millis() as u64;
    access_logger.log(AccessLogEntry {
        timestamp: chrono_timestamp(),
        client_ip: ip_str.to_string(),
        method: method_str.to_string(),
        path: req_path.to_string(),
        status: response.status().as_u16(),
        latency_ms: latency,
        backend: "fastcgi".to_string(),
        pool: fastcgi_pass,
        bytes_sent: 0,
        referer: String::new(),
        user_agent: String::new(),
    });

    Ok(response)
}
