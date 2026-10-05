//! Baseband Line Modulation, LFSR Scrambler, and COBS Framing.

use crate::crc32::Crc32;
use crate::ldpc::{sc_ldpc_decode, sc_ldpc_encode};

/// Galois LFSR 16-bit PRBS scrambler/whitener (poly 0xB400).
pub fn lfsr_scramble(data: &mut [u8], seed: u16) {
    let mut lfsr = if seed != 0 { seed } else { 0xACE1 };
    for byte in data.iter_mut() {
        let mut mask = 0u8;
        for b in 0..8 {
            let lsb = lfsr & 1;
            lfsr >>= 1;
            if lsb != 0 {
                lfsr ^= 0xB400;
            }
            mask |= (lsb as u8) << b;
        }
        *byte ^= mask;
    }
}

/// COBS encode: encodes `src` into `dst` without any `0x00` bytes.
pub fn cobs_encode(src: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(src.len() + src.len() / 254 + 2);
    let mut code_idx = 0;
    dst.push(0x01); // placeholder for first code
    let mut code = 0x01u8;

    for &b in src {
        if b == 0 {
            dst[code_idx] = code;
            code_idx = dst.len();
            dst.push(0x01);
            code = 0x01;
        } else {
            dst.push(b);
            code += 1;
            if code == 0xFF {
                dst[code_idx] = code;
                code_idx = dst.len();
                dst.push(0x01);
                code = 0x01;
            }
        }
    }
    dst[code_idx] = code;
    dst
}

/// COBS decode: decodes COBS packet (without trailing 0x00) into original bytes.
pub fn cobs_decode(src: &[u8]) -> Option<Vec<u8>> {
    let mut dst = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        let code = src[i];
        if code == 0 {
            i += 1;
            continue;
        }
        i += 1;
        let count = (code - 1) as usize;
        let take = count.min(src.len().saturating_sub(i));
        dst.extend_from_slice(&src[i..i + take]);
        i += take;
        if code < 0xFF && i < src.len() && take == count {
            dst.push(0);
        }
    }
    Some(dst)
}

/// Wrap payload with Galois LFSR Scrambler, SC-LDPC bit-level FEC, CRC32, and COBS framing.
pub fn mod_frame_encode(payload: &[u8]) -> Vec<u8> {
    let mut scrambled_payload = payload.to_vec();
    lfsr_scramble(&mut scrambled_payload, 0x5A3C);

    let payload_crc = Crc32::calculate(payload);
    let ldpc_data = sc_ldpc_encode(&scrambled_payload);
    let ldpc_crc = Crc32::calculate(&ldpc_data);

    let mut tmp = Vec::with_capacity(ldpc_data.len() + 8);
    tmp.extend_from_slice(&ldpc_data);
    tmp.extend_from_slice(&payload_crc.to_be_bytes());
    tmp.extend_from_slice(&ldpc_crc.to_be_bytes());

    let mut encoded = cobs_encode(&tmp);
    encoded.push(0x00); // Frame delimiter
    encoded
}

#[derive(Debug, Clone)]
pub struct FrameDecodeResult {
    pub payload: Vec<u8>,
    pub bit_corrections: usize,
}

/// Decode frame, perform SC-LDPC bit-level error correction, unscramble payload, and verify integrity.
pub fn mod_frame_decode(frame: &[u8]) -> Option<FrameDecodeResult> {
    if frame.len() > 65536 + 1024 {
        return None;
    }

    let clean_frame = if frame.ends_with(&[0x00]) {
        &frame[..frame.len() - 1]
    } else {
        frame
    };
    if clean_frame.is_empty() {
        return None;
    }

    let tmp = cobs_decode(clean_frame)?;
    if tmp.len() < 8 {
        return None;
    }

    let pay_len = tmp.len() - 8;
    let expected_payload_crc = u32::from_be_bytes([tmp[pay_len], tmp[pay_len + 1], tmp[pay_len + 2], tmp[pay_len + 3]]);
    let _expected_ldpc_crc = u32::from_be_bytes([tmp[pay_len + 4], tmp[pay_len + 5], tmp[pay_len + 6], tmp[pay_len + 7]]);
    let _actual_ldpc_crc = Crc32::calculate(&tmp[..pay_len]);

    let (mut recovered, bit_corrections) = sc_ldpc_decode(&tmp[..pay_len])?;
    lfsr_scramble(&mut recovered, 0x5A3C);

    if Crc32::calculate(&recovered) == expected_payload_crc {
        return Some(FrameDecodeResult { payload: recovered, bit_corrections });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cobs_roundtrip() {
        let test_cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0x00, 0x00],
            vec![0x01, 0x02, 0x03, 0x00, 0x04, 0x05],
            (0..255).collect(),
            (0..1000).map(|x| (x % 256) as u8).collect(),
        ];

        for tc in test_cases {
            let enc = cobs_encode(&tc);
            assert!(!enc.contains(&0x00), "COBS output must not contain 0x00");
            let dec = cobs_decode(&enc).expect("COBS decode failed");
            assert_eq!(tc, dec);
        }
    }

    #[test]
    fn test_lfsr_scramble() {
        let original = vec![0x55; 128];
        let mut data = original.clone();
        lfsr_scramble(&mut data, 0xACE1);
        assert_ne!(original, data);
        lfsr_scramble(&mut data, 0xACE1);
        assert_eq!(original, data);
    }

    #[test]
    fn test_mod_frame_roundtrip() {
        let payload = b"Hello world from Rust SXFER modulation tests!";
        let frame = mod_frame_encode(payload);
        let res = mod_frame_decode(&frame).expect("Frame decode failed");
        assert_eq!(payload.as_slice(), res.payload.as_slice());
        assert_eq!(res.bit_corrections, 0);
    }

    #[test]
    fn test_mod_frame_ldpc_bit_flip_recovery() {
        let payload = b"Testing SC-LDPC bit-level recovery directly through COBS + Scramble pipeline!";
        let frame = mod_frame_encode(payload);

        // Frame ends with 0x00 delimiter. COBS-decode raw payload to simulate transmission bit flips
        let clean = &frame[..frame.len() - 1];
        let mut scrambled = cobs_decode(clean).unwrap();
        // Flip bit in the payload area
        scrambled[5] ^= 0x01;

        // Re-COBS encode and append 0x00 delimiter
        let mut corrupted_frame = cobs_encode(&scrambled);
        corrupted_frame.push(0x00);

        let res = mod_frame_decode(&corrupted_frame).expect("SC-LDPC must correct bit flips in frame");
        assert_eq!(payload.as_slice(), res.payload.as_slice());
    }
}
