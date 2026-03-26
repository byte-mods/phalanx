use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use tracing::debug;

/// Detects whether the request is a gRPC-Web call by content type.
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
pub fn translate_request(
    req: Request<Full<Bytes>>,
) -> Request<Full<Bytes>> {
    let (mut parts, body) = req.into_parts();

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

    Request::from_parts(parts, body)
}

/// Translates a standard gRPC response back to gRPC-Web format.
///
/// - Rewrites content-type from `application/grpc` → `application/grpc-web`
/// - Moves trailers into the response body (gRPC-Web requires trailers in body)
/// - Adds CORS headers for browser compatibility
pub fn translate_response(
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

    // gRPC-Web CORS headers for browser clients
    parts.headers.insert(
        hyper::header::ACCESS_CONTROL_EXPOSE_HEADERS,
        "grpc-status,grpc-message,grpc-encoding,grpc-accept-encoding"
            .parse()
            .unwrap(),
    );

    Response::from_parts(parts, body)
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
    use super::{cors_preflight_response, is_grpc_web, translate_request};
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{header, Request, StatusCode};

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
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/rpc")
            .header(header::CONTENT_TYPE, "application/grpc-web")
            .body(Full::new(Bytes::from_static(b"payload")))
            .unwrap();
        let out = translate_request(req);
        assert_eq!(
            out.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/grpc")
        );
    }

    #[test]
    fn test_translate_request_sets_te_trailers() {
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/rpc")
            .header(header::CONTENT_TYPE, "application/grpc-web+proto")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let out = translate_request(req);
        assert_eq!(
            out.headers().get(header::TE).and_then(|v| v.to_str().ok()),
            Some("trailers")
        );
    }

    #[test]
    fn test_cors_preflight_response_status() {
        let resp = cors_preflight_response();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
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

