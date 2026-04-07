/// Brotli response compression middleware.
///
/// Brotli typically achieves 15-25% better compression than gzip for text
/// content. This module provides detection of `Accept-Encoding: br` and
/// compression with configurable quality (0-11, clamped).
/// Bodies smaller than [`MIN_BROTLI_SIZE`] (1 KB) are skipped.
use bytes::Bytes;
use std::io::Write;
use tracing::debug;

/// Minimum body size to attempt Brotli compression (1 KB).
/// Below this threshold, compression overhead exceeds the savings.
pub const MIN_BROTLI_SIZE: usize = 1024;

/// Checks if the client accepts Brotli encoding.
pub fn accepts_brotli(accept_encoding: Option<&str>) -> bool {
    accept_encoding
        .map(|ae| ae.to_lowercase().contains("br"))
        .unwrap_or(false)
}

/// Compresses bytes using Brotli. Returns None if the body is too small or compression fails.
pub fn brotli_compress(body: &[u8], quality: u32) -> Option<Bytes> {
    if body.len() < MIN_BROTLI_SIZE {
        return None;
    }

    let quality = quality.min(11);
    let mut output = Vec::with_capacity(body.len() / 2);

    let params = brotli::enc::BrotliEncoderParams {
        quality: quality as i32,
        lgwin: 22,
        lgblock: 0,
        ..Default::default()
    };

    let mut writer = brotli::CompressorWriter::with_params(&mut output, 4096, &params);
    if writer.write_all(body).is_err() {
        return None;
    }
    drop(writer);

    if output.len() < body.len() {
        debug!(
            "Brotli compressed: {} → {} bytes ({:.0}% reduction)",
            body.len(),
            output.len(),
            (1.0 - output.len() as f64 / body.len() as f64) * 100.0
        );
        Some(Bytes::from(output))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accepts_brotli_true() {
        assert!(accepts_brotli(Some("gzip, deflate, br")));
    }

    #[test]
    fn test_accepts_brotli_only_br() {
        assert!(accepts_brotli(Some("br")));
    }

    #[test]
    fn test_accepts_brotli_false() {
        assert!(!accepts_brotli(Some("gzip, deflate")));
    }

    #[test]
    fn test_accepts_brotli_none() {
        assert!(!accepts_brotli(None));
    }

    #[test]
    fn test_accepts_brotli_case_insensitive() {
        assert!(accepts_brotli(Some("GZIP, BR")));
    }

    #[test]
    fn test_brotli_compress_too_small() {
        let small = vec![0u8; 100];
        assert!(brotli_compress(&small, 6).is_none());
    }

    #[test]
    fn test_brotli_compress_exactly_min_size() {
        let data = vec![b'A'; MIN_BROTLI_SIZE];
        let result = brotli_compress(&data, 6);
        assert!(result.is_some(), "repeating data should compress well");
    }

    #[test]
    fn test_brotli_compress_large_compressible() {
        let data = "Hello World! ".repeat(500);
        let compressed = brotli_compress(data.as_bytes(), 6).unwrap();
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_brotli_quality_clamped() {
        let data = vec![b'X'; 2048];
        let q0 = brotli_compress(&data, 0);
        let q99 = brotli_compress(&data, 99);
        assert!(q0.is_some());
        assert!(q99.is_some());
    }
}
