/// Gzip response compression middleware.
///
/// Compresses response bodies using the `flate2` crate when the client
/// advertises `Accept-Encoding: gzip` and the content type is text-based.
/// Bodies smaller than [`MIN_COMPRESS_SIZE`] (1 KB) are left uncompressed
/// because the compression overhead is not worth the savings at that scale.
use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use tracing::debug;

/// Returns the qvalue the client assigned to `coding` in an `Accept-Encoding`
/// header, per RFC 9110 §12.5.3.
///
/// The header is a comma-separated list of `codings [;q=qvalue]`. An entry
/// naming the coding exactly takes precedence over a `*` wildcard entry;
/// `None` means the client listed neither. A qvalue of `0` means "not
/// acceptable" — the coding MUST NOT be used.
///
/// Parsing tokens (rather than substring-matching the raw header) matters:
/// `contains("gzip")` also fires on `notgzipatall`, and `contains("br")` fires
/// on any value containing those two letters, e.g. `libra`.
pub fn encoding_qvalue(accept_encoding: &str, coding: &str) -> Option<f32> {
    let mut exact: Option<f32> = None;
    let mut wildcard: Option<f32> = None;

    for entry in accept_encoding.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.split(';');
        let token = parts.next().unwrap_or("").trim().to_ascii_lowercase();

        // Default qvalue is 1 when no q parameter is present.
        let mut q = 1.0f32;
        for param in parts {
            let param = param.trim();
            let (name, value) = match param.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            if name.trim().eq_ignore_ascii_case("q") {
                q = value.trim().parse::<f32>().unwrap_or(1.0);
            }
        }

        if token == coding {
            exact = Some(exact.map_or(q, |cur: f32| cur.max(q)));
        } else if token == "*" {
            wildcard = Some(wildcard.map_or(q, |cur: f32| cur.max(q)));
        }
    }

    exact.or(wildcard)
}

/// Returns `true` if the client is willing to receive `coding`.
///
/// A missing `Accept-Encoding` header is treated as "do not compress". RFC 9110
/// permits any coding in that case, but staying uncompressed is always a valid
/// response and avoids surprising clients that omit the header.
pub fn accepts_encoding(accept_encoding: Option<&str>, coding: &str) -> bool {
    match accept_encoding {
        Some(ae) => matches!(encoding_qvalue(ae, coding), Some(q) if q > 0.0),
        None => false,
    }
}

/// Checks if the client accepts gzip encoding.
pub fn accepts_gzip(accept_encoding: Option<&str>) -> bool {
    match accept_encoding {
        // `x-gzip` is a deprecated alias for `gzip` (RFC 9110 §8.4.1.3); only
        // consult it when the client did not name `gzip` explicitly.
        Some(ae) => {
            let q = encoding_qvalue(ae, "gzip").or_else(|| encoding_qvalue(ae, "x-gzip"));
            matches!(q, Some(q) if q > 0.0)
        }
        None => false,
    }
}

/// Checks if the content type is compressible (text/*, application/json, application/javascript, etc.)
pub fn is_compressible(content_type: Option<&str>) -> bool {
    match content_type {
        Some(ct) => {
            let ct_lower = ct.to_lowercase();
            ct_lower.starts_with("text/")
                || ct_lower.contains("application/json")
                || ct_lower.contains("application/javascript")
                || ct_lower.contains("application/xml")
                || ct_lower.contains("application/xhtml")
                || ct_lower.contains("image/svg+xml")
        }
        None => false,
    }
}

/// Minimum body size to compress (1 KB). Below this, compression overhead isn't worth it.
pub const MIN_COMPRESS_SIZE: usize = 1024;

/// Compresses bytes using gzip. Returns None if the body is too small or compression fails.
pub fn gzip_compress(body: &[u8]) -> Option<Bytes> {
    if body.len() < MIN_COMPRESS_SIZE {
        return None;
    }

    let mut encoder = GzEncoder::new(Vec::with_capacity(body.len() / 2), Compression::fast());
    if encoder.write_all(body).is_err() {
        return None;
    }
    match encoder.finish() {
        Ok(compressed) => {
            // Only use compressed version if it's actually smaller
            if compressed.len() < body.len() {
                debug!(
                    "Compressed response: {} → {} bytes ({:.0}% reduction)",
                    body.len(),
                    compressed.len(),
                    (1.0 - compressed.len() as f64 / body.len() as f64) * 100.0
                );
                Some(Bytes::from(compressed))
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Async wrapper that offloads gzip compression to `spawn_blocking`.
/// Prevents CPU-intensive compression from stalling Tokio worker threads.
pub async fn gzip_compress_async(body: Bytes) -> Option<Bytes> {
    if body.len() < MIN_COMPRESS_SIZE {
        return None;
    }
    tokio::task::spawn_blocking(move || gzip_compress(&body))
        .await
        .unwrap_or(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accepts_gzip_true() {
        assert!(accepts_gzip(Some("gzip, deflate, br")));
    }

    #[test]
    fn test_accepts_gzip_only() {
        assert!(accepts_gzip(Some("gzip")));
    }

    #[test]
    fn test_accepts_gzip_false() {
        assert!(!accepts_gzip(Some("deflate, br")));
    }

    #[test]
    fn test_accepts_gzip_none() {
        assert!(!accepts_gzip(None));
    }

    #[test]
    fn test_accepts_gzip_case_insensitive() {
        assert!(accepts_gzip(Some("GZIP")));
    }

    // ── RFC 9110 §12.5.3 qvalue / token handling ────────────────────────────

    #[test]
    fn test_qvalue_zero_refuses_coding() {
        // "A qvalue of 0 means 'not acceptable'."
        assert!(!accepts_gzip(Some("gzip;q=0")));
        assert!(!accepts_gzip(Some("gzip;q=0.0")));
        assert!(!accepts_gzip(Some("gzip; q=0")));
        assert!(!accepts_encoding(Some("br;q=0"), "br"));
    }

    #[test]
    fn test_qvalue_nonzero_accepts_coding() {
        assert!(accepts_gzip(Some("gzip;q=1")));
        assert!(accepts_gzip(Some("gzip;q=0.5")));
        assert!(accepts_gzip(Some("deflate;q=0.5, gzip;q=0.9")));
    }

    #[test]
    fn test_substring_tokens_do_not_match() {
        // Previously `contains("gzip")` / `contains("br")` false-positived here.
        assert!(!accepts_gzip(Some("notgzipatall")));
        assert!(!accepts_encoding(Some("libra"), "br"));
        assert!(!accepts_encoding(Some("brotli-not-real"), "br"));
    }

    #[test]
    fn test_wildcard_entry() {
        assert!(accepts_gzip(Some("*")));
        assert!(accepts_gzip(Some("deflate, *;q=0.5")));
        assert!(!accepts_gzip(Some("*;q=0")));
        // An exact entry overrides the wildcard, in both directions.
        assert!(!accepts_gzip(Some("*;q=1, gzip;q=0")));
        assert!(accepts_gzip(Some("*;q=0, gzip;q=1")));
    }

    #[test]
    fn test_x_gzip_alias() {
        assert!(accepts_gzip(Some("x-gzip")));
        assert!(!accepts_gzip(Some("x-gzip;q=0")));
    }

    #[test]
    fn test_encoding_qvalue_absent_coding() {
        assert_eq!(encoding_qvalue("deflate", "gzip"), None);
        assert_eq!(encoding_qvalue("gzip", "gzip"), Some(1.0));
    }

    #[test]
    fn test_is_compressible_text() {
        assert!(is_compressible(Some("text/html")));
        assert!(is_compressible(Some("text/css")));
        assert!(is_compressible(Some("text/plain; charset=utf-8")));
    }

    #[test]
    fn test_is_compressible_app_json() {
        assert!(is_compressible(Some("application/json")));
    }

    #[test]
    fn test_is_compressible_javascript() {
        assert!(is_compressible(Some("application/javascript")));
    }

    #[test]
    fn test_is_compressible_xml() {
        assert!(is_compressible(Some("application/xml")));
        assert!(is_compressible(Some("application/xhtml+xml")));
    }

    #[test]
    fn test_is_compressible_svg() {
        assert!(is_compressible(Some("image/svg+xml")));
    }

    #[test]
    fn test_is_compressible_false() {
        assert!(!is_compressible(Some("image/png")));
        assert!(!is_compressible(Some("application/octet-stream")));
        assert!(!is_compressible(None));
    }

    #[test]
    fn test_gzip_compress_too_small() {
        let small = vec![0u8; 100];
        assert!(gzip_compress(&small).is_none());
    }

    #[test]
    fn test_gzip_compress_large_compressible() {
        let data = "Hello World! ".repeat(500);
        let compressed = gzip_compress(data.as_bytes()).unwrap();
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_gzip_compress_at_boundary() {
        let data = vec![b'A'; MIN_COMPRESS_SIZE];
        let result = gzip_compress(&data);
        assert!(
            result.is_some(),
            "repeating data at boundary should compress"
        );
    }
}
