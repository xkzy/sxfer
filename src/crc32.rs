//! IEEE 802.3 CRC-32 Checksum Implementation.

pub struct Crc32 {
    state: u32,
}

impl Crc32 {
    pub fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut c = self.state;
        for &b in data {
            let mut byte = (c ^ (b as u32)) & 0xFF;
            for _ in 0..8 {
                if byte & 1 != 0 {
                    byte = 0xEDB8_8320 ^ (byte >> 1);
                } else {
                    byte >>= 1;
                }
            }
            c = byte ^ (c >> 8);
        }
        self.state = c;
    }

    pub fn finalize(self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }

    pub fn calculate(data: &[u8]) -> u32 {
        let mut crc = Self::new();
        crc.update(data);
        crc.finalize()
    }
}

pub fn crc32_file(path: &std::path::Path) -> std::io::Result<u32> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut crc = Crc32::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        crc.update(&buf[..n]);
    }
    Ok(crc.finalize())
}
