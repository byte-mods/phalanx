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

/// Checks if the client accepts gzip encoding.
pub fn accepts_gzip(accept_encoding: Option<&str>) -> bool {
    accept_encoding
        .map(|ae| ae.to_lowercase().contains("gzip"))
        .unwrap_or(false)
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
        assert!(result.is_some(), "repeating data at boundary should compress");
    }
}
