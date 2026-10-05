//! Baseband Line Modulation, LFSR Scrambler, and COBS Framing.

use crate::crc32::Crc32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModMode {
    Raw = 0,
    Scramble = 1,
    Cobs = 2,
}

impl ModMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "raw" | "0" => Some(ModMode::Raw),
            "scramble" | "1" => Some(ModMode::Scramble),
            "cobs" | "2" => Some(ModMode::Cobs),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ModMode::Raw => "raw",
            ModMode::Scramble => "scramble",
            ModMode::Cobs => "cobs",
        }
    }
}

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
            return None; // 0x00 is illegal inside a COBS packet
        }
        i += 1;
        let count = (code - 1) as usize;
        if i + count > src.len() {
            return None;
        }
        dst.extend_from_slice(&src[i..i + count]);
        i += count;
        if code < 0xFF && i < src.len() {
            dst.push(0);
        }
    }
    Some(dst)
}

pub const MAGIC_RAW: [u8; 4] = [0xC3, 0xA5, 0x5A, 0x3C];

use crate::ldpc::{sc_ldpc_decode, sc_ldpc_encode};

/// Wrap payload with SC-LDPC bit-level FEC, CRC32, line modulation (LFSR/COBS), and framing.
pub fn mod_frame_encode(payload: &[u8], mode: ModMode) -> Vec<u8> {
    let payload_crc = Crc32::calculate(payload);
    let ldpc_data = sc_ldpc_encode(payload);
    let ldpc_crc = Crc32::calculate(&ldpc_data);
    let mut tmp = Vec::with_capacity(ldpc_data.len() + 8);
    tmp.extend_from_slice(&ldpc_data);
    tmp.extend_from_slice(&payload_crc.to_be_bytes());
    tmp.extend_from_slice(&ldpc_crc.to_be_bytes());

    if mode == ModMode::Scramble || mode == ModMode::Cobs {
        lfsr_scramble(&mut tmp, 0x5A3C);
    }

    match mode {
        ModMode::Cobs => {
            let mut encoded = cobs_encode(&tmp);
            encoded.push(0x00); // Frame delimiter
            encoded
        }
        ModMode::Scramble | ModMode::Raw => {
            let raw_len = tmp.len() as u16;
            let mut out = Vec::with_capacity(6 + tmp.len());
            out.extend_from_slice(&MAGIC_RAW);
            out.extend_from_slice(&raw_len.to_be_bytes());
            out.extend_from_slice(&tmp);
            out
        }
    }
}

/// Decode frame, attempting SC-LDPC bit-level error correction if bit flips occurred.
pub fn mod_frame_decode(frame: &[u8], mode: ModMode) -> Option<Vec<u8>> {
    if frame.len() > 65536 + 1024 {
        return None;
    }

    let mut tmp = match mode {
        ModMode::Cobs => {
            let clean_frame = if frame.ends_with(&[0x00]) {
                &frame[..frame.len() - 1]
            } else {
                frame
            };
            if clean_frame.is_empty() {
                return None;
            }
            cobs_decode(clean_frame)?
        }
        ModMode::Scramble | ModMode::Raw => {
            if frame.len() < 6 + 8 || !frame.starts_with(&MAGIC_RAW) {
                return None;
            }
            let raw_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
            if frame.len() < 6 + raw_len || raw_len < 8 {
                return None;
            }
            frame[6..6 + raw_len].to_vec()
        }
    };

    if tmp.len() < 8 {
        return None;
    }

    if mode == ModMode::Scramble || mode == ModMode::Cobs {
        lfsr_scramble(&mut tmp, 0x5A3C);
    }

    let pay_len = tmp.len() - 8;
    let expected_payload_crc = u32::from_be_bytes([tmp[pay_len], tmp[pay_len + 1], tmp[pay_len + 2], tmp[pay_len + 3]]);
    let expected_ldpc_crc = u32::from_be_bytes([tmp[pay_len + 4], tmp[pay_len + 5], tmp[pay_len + 6], tmp[pay_len + 7]]);
    let actual_ldpc_crc = Crc32::calculate(&tmp[..pay_len]);

    if expected_ldpc_crc == actual_ldpc_crc {
        // Direct clean frame
        return sc_ldpc_decode(&tmp[..pay_len]);
    }

    // CRC mismatch: Attempt bit-level error recovery using SC-LDPC
    if let Some(recovered) = sc_ldpc_decode(&tmp[..pay_len]) {
        if Crc32::calculate(&recovered) == expected_payload_crc {
            return Some(recovered);
        }
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
    fn test_mod_frame_modes() {
        let payload = b"Hello world from Rust SXFER modulation tests!";
        for mode in [ModMode::Cobs, ModMode::Scramble, ModMode::Raw] {
            let frame = mod_frame_encode(payload, mode);
            let decoded = mod_frame_decode(&frame, mode).expect("Frame decode failed");
            assert_eq!(payload.as_slice(), decoded.as_slice());
        }
    }

    #[test]
    fn test_mod_frame_ldpc_bit_flip_recovery() {
        let payload = b"Testing SC-LDPC bit-level recovery directly through the framing pipeline!";
        let mut frame = mod_frame_encode(payload, ModMode::Raw);

        // Inject bit flips into the raw payload body (after the 6-byte header)
        frame[10] ^= 0x01; // flip bit 0
        frame[25] ^= 0x04; // flip bit 2

        let decoded = mod_frame_decode(&frame, ModMode::Raw).expect("SC-LDPC must correct bit flips in frame");
        assert_eq!(payload.as_slice(), decoded.as_slice());
    }
}

