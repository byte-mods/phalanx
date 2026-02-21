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
const MIN_COMPRESS_SIZE: usize = 1024;

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
