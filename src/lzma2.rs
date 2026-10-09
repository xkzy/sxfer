//! 100% Pure Rust LZMA2 Compressor & Decompressor.

use std::io::Cursor;

pub fn compress_lzma2(src: &[u8], _level: i32) -> Result<Vec<u8>, &'static str> {
    let mut input = Cursor::new(src);
    let mut output = Vec::with_capacity(src.len() / 2 + 128);
    lzma_rs::lzma_compress(&mut input, &mut output)
        .map_err(|_| "Pure Rust LZMA compression failed")?;
    Ok(output)
}

/// Writer that refuses to grow past `limit` bytes, so a malicious stream cannot
/// expand beyond the size the (already validated) header declared.
struct CappedWriter {
    buf: Vec<u8>,
    limit: usize,
}

impl std::io::Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > self.limit - self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed output exceeds declared size",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn decompress_lzma2(src: &[u8], expected_size: usize) -> Result<Vec<u8>, &'static str> {
    if expected_size == 0 {
        if src.is_empty() {
            return Ok(Vec::new());
        }
        // Try decompressing with 0 limit
        let mut input = Cursor::new(src);
        let mut output = CappedWriter {
            buf: Vec::new(),
            limit: 0,
        };
        lzma_rs::lzma_decompress(&mut input, &mut output)
            .map_err(|_| "Pure Rust LZMA decompression failed")?;
        return Ok(output.buf);
    }
    let mut input = Cursor::new(src);
    // Never pre-allocate more than 64 MiB on the strength of an untrusted size.
    let mut output = CappedWriter {
        buf: Vec::with_capacity(expected_size.min(64 << 20)),
        limit: expected_size,
    };
    lzma_rs::lzma_decompress(&mut input, &mut output)
        .map_err(|_| "Pure Rust LZMA decompression failed")?;
    if output.buf.len() != expected_size {
        return Err("decompressed size mismatch");
    }
    Ok(output.buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pure_rust_lzma2_roundtrip() {
        let original = b"The quick brown fox jumps over the lazy dog. Repeat text for pure Rust LZMA2 testing! ".repeat(100);
        let compressed = compress_lzma2(&original, 6).expect("Compression failed");
        assert!(
            compressed.len() < original.len(),
            "Compressed size must be smaller"
        );
        let decompressed =
            decompress_lzma2(&compressed, original.len()).expect("Decompression failed");
        assert_eq!(original, decompressed.as_slice());
    }

    #[test]
    fn test_decompress_empty() {
        assert_eq!(decompress_lzma2(&[], 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_decompress_truncated() {
        let original = b"Testing truncated LZMA decompression".repeat(10);
        let compressed = compress_lzma2(&original, 6).unwrap();
        let truncated = &compressed[..compressed.len() / 2];
        assert!(decompress_lzma2(truncated, original.len()).is_err());
    }

    #[test]
    fn test_decompress_corrupted() {
        let original = b"Testing corrupted LZMA decompression".repeat(10);
        let mut compressed = compress_lzma2(&original, 6).unwrap();
        if compressed.len() > 10 {
            compressed[5] ^= 0xFF;
            compressed[8] ^= 0xAA;
        }
        assert!(decompress_lzma2(&compressed, original.len()).is_err());
    }

    #[test]
    fn test_decompress_oversized_limit() {
        let original = vec![0u8; 10000];
        let compressed = compress_lzma2(&original, 6).unwrap();
        // Request decompressing into a limit smaller than actual
        assert!(decompress_lzma2(&compressed, 100).is_err());
    }
}
