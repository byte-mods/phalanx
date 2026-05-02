//! gRPC-Web protocol translation layer.
//!
//! Browser-based gRPC clients cannot use native HTTP/2 gRPC because browsers
//! do not expose the HTTP/2 framing layer. Instead they use "gRPC-Web", which
//! encodes gRPC messages over HTTP/1.1 (or HTTP/2) with a different content
//! type (`application/grpc-web` or `application/grpc-web-text` for base64).
//!
//! This module translates:
//! - **Request**: `grpc-web` content type -> standard `grpc` content type, adds `TE: trailers`.
//! - **Response**: `grpc` content type -> `grpc-web` (or `grpc-web-text`), adds CORS headers.
//! - **Preflight**: Handles `OPTIONS` requests with proper CORS headers for browser compatibility.

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};

/// Detects whether the request is a gRPC-Web call by inspecting the `Content-Type` header.
///
/// Returns `true` if the content type starts with `application/grpc-web`,
/// `application/grpc-web+proto`, or `application/grpc-web-text`.
pub fn is_grpc_web<T>(req: &Request<T>) -> bool {
    req.headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            ct.starts_with("application/grpc-web")
                || ct.starts_with("application/grpc-web+proto")
                || ct.starts_with("application/grpc-web-text")
        })
        .unwrap_or(false)
}

/// Translates a gRPC-Web request into a standard gRPC (HTTP/2) request.
///
/// - Strips the `grpc-web` content type prefix → `application/grpc`
/// - If the original was `grpc-web-text` (base64), decodes the body
/// - Adds required HTTP/2 TE header
///
/// Callers pass the already-split `parts` and `body_bytes` to avoid
/// the `Full<Bytes>` extract/re-wrap dance.
pub fn translate_request(
    parts: hyper::http::request::Parts,
    body_bytes: Bytes,
) -> (hyper::http::request::Parts, Bytes) {
    let mut parts = parts;

    // Detect grpc-web-text before rewriting content-type
    let is_text = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/grpc-web-text"))
        .unwrap_or(false);

    // Rewrite content-type from grpc-web → grpc
    if let Some(ct) = parts.headers.get(hyper::header::CONTENT_TYPE) {
        if let Ok(ct_str) = ct.to_str() {
            let new_ct = ct_str
                .replace("application/grpc-web-text", "application/grpc")
                .replace("application/grpc-web+proto", "application/grpc+proto")
                .replace("application/grpc-web", "application/grpc");
            if let Ok(val) = new_ct.parse() {
                parts.headers.insert(hyper::header::CONTENT_TYPE, val);
            }
        }
    }

    // Ensure TE: trailers is set for gRPC
    parts
        .headers
        .insert(hyper::header::TE, "trailers".parse().unwrap());

    // Base64-decode the body for grpc-web-text requests
    let decoded_body = if is_text {
        match base64_decode(&body_bytes) {
            Ok(decoded) => Bytes::from(decoded),
            Err(_) => {
                tracing::warn!("gRPC-Web text mode: base64 decode failed, forwarding raw body");
                body_bytes
            }
        }
    } else {
        body_bytes
    };

    (parts, decoded_body)
}

/// Base64-decode a byte slice, returning the decoded bytes or an error.
fn base64_decode(input: &[u8]) -> Result<Vec<u8>, ()> {
    use base64::Engine;
    // Strip whitespace that browsers may include
    let trimmed: Vec<u8> = input.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&trimmed)
        .map_err(|_| ())
}

/// Translates a standard gRPC response back to gRPC-Web format.
///
/// - Rewrites content-type from `application/grpc` → `application/grpc-web`
/// - Appends trailers to the response body as a length-prefixed frame
///   (0x80 flag byte + 4-byte big-endian length + trailer text)
/// - Adds CORS headers for browser compatibility
pub async fn translate_response(
    response: Response<BoxBody<Bytes, hyper::Error>>,
    use_text_encoding: bool,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let (mut parts, body) = response.into_parts();

    // Rewrite content-type
    if let Some(ct) = parts.headers.get(hyper::header::CONTENT_TYPE) {
        if let Ok(ct_str) = ct.to_str() {
            let new_ct = if use_text_encoding {
                ct_str.replace("application/grpc", "application/grpc-web-text")
            } else {
                ct_str.replace("application/grpc", "application/grpc-web")
            };
            if let Ok(val) = new_ct.parse() {
                parts.headers.insert(hyper::header::CONTENT_TYPE, val);
            }
        }
    }

    // Collect the response body so we can append trailers
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    };

    // Build trailer frame from grpc-status and grpc-message headers
    let mut trailer_text = String::new();
    if let Some(status) = parts.headers.get("grpc-status") {
        if let Ok(s) = status.to_str() {
            trailer_text.push_str(&format!("grpc-status: {}\r\n", s));
        }
    }
    if let Some(msg) = parts.headers.get("grpc-message") {
        if let Ok(s) = msg.to_str() {
            trailer_text.push_str(&format!("grpc-message: {}\r\n", s));
        }
    }

    // Build final body: original body + trailer frame (0x80 | len | trailer_text)
    let mut final_body = body_bytes.to_vec();
    if !trailer_text.is_empty() {
        let trailer_bytes = trailer_text.as_bytes();
        // Trailer frame: flag byte (0x80) + 4-byte big-endian length + data
        final_body.push(0x80);
        final_body.extend_from_slice(&(trailer_bytes.len() as u32).to_be_bytes());
        final_body.extend_from_slice(trailer_bytes);
    }

    // If text encoding requested, base64-encode the entire body
    let response_body = if use_text_encoding {
        use base64::{Engine, engine::general_purpose::STANDARD};
        STANDARD.encode(&final_body).into_bytes()
    } else {
        final_body
    };

    // gRPC-Web CORS headers for browser clients
    parts.headers.insert(
        hyper::header::ACCESS_CONTROL_EXPOSE_HEADERS,
        "grpc-status,grpc-message,grpc-encoding,grpc-accept-encoding"
            .parse()
            .unwrap(),
    );

    Response::from_parts(
        parts,
        Full::new(Bytes::from(response_body))
            .map_err(|never| match never {})
            .boxed(),
    )
}

/// Adds standard CORS preflight headers for gRPC-Web OPTIONS requests.
pub fn cors_preflight_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(
            hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
            "POST, OPTIONS",
        )
        .header(
            hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
            "content-type,x-grpc-web,x-user-agent,grpc-timeout",
        )
        .header(hyper::header::ACCESS_CONTROL_MAX_AGE, "86400")
        .body(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{header, Request, Response, StatusCode};

    #[test]
    fn test_is_grpc_web_true() {
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/rpc")
            .header(header::CONTENT_TYPE, "application/grpc-web")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(is_grpc_web(&req));
    }

    #[test]
    fn test_is_grpc_web_proto() {
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/rpc")
            .header(header::CONTENT_TYPE, "application/grpc-web+proto")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(is_grpc_web(&req));
    }

    #[test]
    fn test_is_grpc_web_text() {
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/rpc")
            .header(header::CONTENT_TYPE, "application/grpc-web-text")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(is_grpc_web(&req));
    }

    #[test]
    fn test_is_grpc_web_false() {
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/api")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(!is_grpc_web(&req));
    }

    #[test]
    fn test_is_grpc_web_no_content_type() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(!is_grpc_web(&req));
    }

    #[test]
    fn test_translate_request_rewrites_content_type() {
        let parts = Request::builder()
            .method("POST")
            .uri("http://example.com/rpc")
            .header(header::CONTENT_TYPE, "application/grpc-web")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let (parts, _body) = translate_request(parts, Bytes::from_static(b"payload"));
        assert_eq!(
            parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/grpc")
        );
    }

    #[test]
    fn test_translate_request_sets_te_trailers() {
        let parts = Request::builder()
            .method("POST")
            .uri("http://example.com/rpc")
            .header(header::CONTENT_TYPE, "application/grpc-web+proto")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let (parts, _body) = translate_request(parts, Bytes::new());
        assert_eq!(
            parts.headers.get(header::TE).and_then(|v| v.to_str().ok()),
            Some("trailers")
        );
    }

    #[test]
    fn test_cors_preflight_response_status() {
        let resp = cors_preflight_response();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_translate_response_appends_trailers_to_body() {
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/grpc")
            .header("grpc-status", "0")
            .header("grpc-message", "OK")
            .body(
                Full::new(Bytes::from_static(b"\x00\x00\x00\x00\x05hello"))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap();

        let translated = translate_response(resp, false).await;
        let body = translated
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();

        // Body should contain original data + trailer frame (0x80 + len + trailer text)
        assert!(body.len() > 10);
        // Find the trailer frame: look for 0x80 byte
        let trailer_pos = body.iter().position(|&b| b == 0x80);
        assert!(trailer_pos.is_some(), "trailer frame must be present");
        let pos = trailer_pos.unwrap();
        // 4 bytes of length after the 0x80 flag
        let trailer_len = u32::from_be_bytes([body[pos + 1], body[pos + 2], body[pos + 3], body[pos + 4]]) as usize;
        let trailer_text = std::str::from_utf8(&body[pos + 5..pos + 5 + trailer_len]).unwrap();
        assert!(trailer_text.contains("grpc-status: 0"));
        assert!(trailer_text.contains("grpc-message: OK"));
    }

    #[tokio::test]
    async fn test_translate_response_text_encoding_base64() {
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/grpc")
            .header("grpc-status", "0")
            .body(
                Full::new(Bytes::from_static(b"\x00\x00\x00\x00\x02hi"))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap();

        let translated = translate_response(resp, true).await;
        let body = translated
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();

        // Text encoding should produce valid base64
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &body,
        );
        assert!(decoded.is_ok(), "body must be valid base64");
    }

    #[tokio::test]
    async fn test_translate_response_no_trailers() {
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/grpc")
            .body(
                Full::new(Bytes::from_static(b"data"))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap();

        let translated = translate_response(resp, false).await;
        let body = translated
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();

        // No grpc-status/grpc-message headers → no trailer frame appended
        assert_eq!(&body[..], b"data");
    }

    #[test]
    fn test_cors_preflight_response_headers() {
        let resp = cors_preflight_response();
        let h = resp.headers();
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .and_then(|v| v.to_str().ok()),
            Some("POST, OPTIONS")
        );
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                .and_then(|v| v.to_str().ok()),
            Some("content-type,x-grpc-web,x-user-agent,grpc-timeout")
        );
        assert_eq!(
            h.get(header::ACCESS_CONTROL_MAX_AGE)
                .and_then(|v| v.to_str().ok()),
            Some("86400")
        );
    }
}
