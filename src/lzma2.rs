//! 100% Pure Rust LZMA2 Compressor & Decompressor.

use std::io::Cursor;

pub fn compress_lzma2(src: &[u8], _level: i32) -> Result<Vec<u8>, &'static str> {
    let mut input = Cursor::new(src);
    let mut output = Vec::with_capacity(src.len() / 2 + 128);
    lzma_rs::lzma_compress(&mut input, &mut output).map_err(|_| "Pure Rust LZMA compression failed")?;
    Ok(output)
}

pub fn decompress_lzma2(src: &[u8], expected_size: usize) -> Result<Vec<u8>, &'static str> {
    let mut input = Cursor::new(src);
    let mut output = Vec::with_capacity(expected_size);
    lzma_rs::lzma_decompress(&mut input, &mut output).map_err(|_| "Pure Rust LZMA decompression failed")?;
    Ok(output)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pure_rust_lzma2_roundtrip() {
        let original = b"The quick brown fox jumps over the lazy dog. Repeat text for pure Rust LZMA2 testing! ".repeat(100);
        let compressed = compress_lzma2(&original, 6).expect("Compression failed");
        assert!(compressed.len() < original.len(), "Compressed size must be smaller");
        let decompressed = decompress_lzma2(&compressed, original.len()).expect("Decompression failed");
        assert_eq!(original, decompressed.as_slice());
    }
}
