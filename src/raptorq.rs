//! RFC 6330 / Systematic Rateless Fountain Code Engine over GF(256).

pub const RQ_MAX_K: usize = 128;

// ----------------------------------------------------------------- GF(256) Math
struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
    mul_table: [[u8; 256]; 256],
}

impl Gf256 {
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut mul_table = [[0u8; 256]; 256];

        let poly = 0x11Du32; // x^8 + x^4 + x^3 + x^2 + 1
        let mut val = 1u32;
        for i in 0..255 {
            exp[i] = val as u8;
            exp[i + 255] = val as u8;
            log[val as usize] = i as u8;
            val <<= 1;
            if val & 0x100 != 0 {
                val ^= poly;
            }
        }
        log[0] = 0;

        for a in 0..256 {
            for b in 0..256 {
                if a == 0 || b == 0 {
                    mul_table[a][b] = 0;
                } else {
                    mul_table[a][b] = exp[(log[a] as usize) + (log[b] as usize)];
                }
            }
        }

        Self { exp, log, mul_table }
    }

    #[inline(always)]
    fn mul(&self, a: u8, b: u8) -> u8 {
        self.mul_table[a as usize][b as usize]
    }

    #[inline(always)]
    fn inv(&self, a: u8) -> u8 {
        if a == 0 {
            0
        } else {
            self.exp[255 - (self.log[a as usize] as usize)]
        }
    }

    #[inline(always)]
    fn add_mul(&self, dst: &mut [u8], src: &[u8], c: u8) {
        if c == 0 {
            return;
        }
        if c == 1 {
            for (d, s) in dst.iter_mut().zip(src.iter()) {
                *d ^= *s;
            }
            return;
        }
        let tab = &self.mul_table[c as usize];
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d ^= tab[*s as usize];
        }
    }
}

// Global thread-safe GF256 singleton
fn get_gf() -> &'static Gf256 {
    use std::sync::OnceLock;
    static GF: OnceLock<Gf256> = OnceLock::new();
    GF.get_or_init(Gf256::new)
}

#[inline(always)]
fn rq_hash(a: u32, b: u32) -> u32 {
    let mut x = (a.wrapping_mul(0x9E37_79B9)) ^ (b.wrapping_mul(0x85EB_CA6B));
    x ^= x >> 13;
    x = x.wrapping_mul(0xC2B2_AE35);
    x ^= x >> 16;
    x
}

fn get_symbol_row(esi: u32, k: usize, row_coeffs: &mut [u8]) {
    row_coeffs[..k].fill(0);
    if (esi as usize) < k {
        row_coeffs[esi as usize] = 1;
        return;
    }
    if k == 1 {
        row_coeffs[0] = 1;
        return;
    }
    for j in 0..k {
        let h = rq_hash(esi, j as u32);
        row_coeffs[j] = ((h % 255) + 1) as u8;
    }
}

// ----------------------------------------------------------------- Single Block Encoder
struct BlockEncoder {
    k: usize,
    symbol_size: usize,
    source_symbols: Vec<u8>, // k * symbol_size bytes
}

impl BlockEncoder {
    fn new(data: &[u8], symbol_size: usize) -> Self {
        let k = ((data.len() + symbol_size - 1) / symbol_size).max(1);
        let mut source_symbols = vec![0u8; k * symbol_size];
        source_symbols[..data.len()].copy_from_slice(data);

        Self {
            k,
            symbol_size,
            source_symbols,
        }
    }

    fn encode_symbol(&self, esi: u32, out_symbol: &mut [u8]) {
        let gf = get_gf();
        out_symbol[..self.symbol_size].fill(0);

        if (esi as usize) < self.k {
            let off = (esi as usize) * self.symbol_size;
            out_symbol[..self.symbol_size].copy_from_slice(&self.source_symbols[off..off + self.symbol_size]);
            return;
        }

        let mut row = [0u8; RQ_MAX_K];
        get_symbol_row(esi, self.k, &mut row);

        for i in 0..self.k {
            if row[i] != 0 {
                let off = i * self.symbol_size;
                gf.add_mul(
                    &mut out_symbol[..self.symbol_size],
                    &self.source_symbols[off..off + self.symbol_size],
                    row[i],
                );
            }
        }
    }
}

pub struct RaptorQEncoder {
    num_blocks: usize,
    blocks: Vec<BlockEncoder>,
}

impl RaptorQEncoder {
    pub fn new(data: &[u8], symbol_size: usize) -> Option<Self> {
        if data.is_empty() || symbol_size == 0 {
            return None;
        }

        let total_k = ((data.len() + symbol_size - 1) / symbol_size).max(1);
        let num_blocks = (total_k + RQ_MAX_K - 1) / RQ_MAX_K;
        let block_bytes = RQ_MAX_K * symbol_size;

        let mut blocks = Vec::with_capacity(num_blocks);
        for b in 0..num_blocks {
            let off = b * block_bytes;
            let blk_len = (data.len() - off).min(block_bytes);
            blocks.push(BlockEncoder::new(&data[off..off + blk_len], symbol_size));
        }

        Some(Self {
            num_blocks,
            blocks,
        })
    }

    #[allow(dead_code)]
    pub fn num_blocks(&self) -> usize {
        self.num_blocks
    }


    pub fn max_block_k(&self) -> usize {
        self.blocks.iter().map(|b| b.k).max().unwrap_or(1)
    }

    pub fn total_symbols_to_send(&self, pct: usize) -> usize {
        let max_k = self.max_block_k();
        let min_extra = if max_k <= 4 {
            ((pct * 6) / 100).max(4)
        } else if max_k <= 16 {
            ((pct * 4) / 100).max(6)
        } else {
            ((pct * 2) / 100).max(8)
        };
        let mut syms_per_block = (max_k * (100 + pct) + 99) / 100;
        if syms_per_block < max_k + min_extra {
            syms_per_block = max_k + min_extra;
        }
        syms_per_block * self.num_blocks
    }


    pub fn encode_symbol(&self, esi: u32, out_symbol: &mut [u8]) {
        let block_idx = (esi as usize) % self.num_blocks;
        let block_esi = (esi as usize) / self.num_blocks;
        self.blocks[block_idx].encode_symbol(block_esi as u32, out_symbol);
    }
}


// ----------------------------------------------------------------- Single Block Decoder
#[derive(Clone, Copy)]
enum RowOp {
    Swap(usize, usize),
    Scale(usize, u8),
    AddMul(usize, usize, u8),
}

struct BlockDecoder {
    k: usize,
    symbol_size: usize,
    data_len: usize,
    esis: Vec<u32>,
    symbols: Vec<u8>,
    visited_esis: std::collections::HashSet<u32>,
    is_decoded: bool,
    decoded_data: Vec<u8>,
}

impl BlockDecoder {
    fn new(data_len: usize, symbol_size: usize) -> Self {
        let k = ((data_len + symbol_size - 1) / symbol_size).max(1);
        Self {
            k,
            symbol_size,
            data_len,
            esis: Vec::with_capacity(k + 32),
            symbols: Vec::with_capacity((k + 32) * symbol_size),
            visited_esis: std::collections::HashSet::new(),
            is_decoded: false,
            decoded_data: vec![0u8; data_len],
        }
    }

    fn receive_symbol(&mut self, esi: u32, symbol_data: &[u8]) -> bool {
        if self.is_decoded {
            return true;
        }
        if self.visited_esis.contains(&esi) {
            return false;
        }

        self.esis.push(esi);
        self.symbols.extend_from_slice(&symbol_data[..self.symbol_size]);
        self.visited_esis.insert(esi);

        if self.esis.len() >= self.k {
            self.decode_block();
        }

        self.is_decoded
    }

    fn decode_block(&mut self) -> bool {
        if self.is_decoded {
            return true;
        }
        if self.esis.len() < self.k {
            return false;
        }

        let k = self.k;
        let n = self.esis.len();
        let t = self.symbol_size;
        let gf = get_gf();

        // Check if all K systematic symbols are already directly received
        let mut all_systematic = true;
        for i in 0..k {
            if !self.visited_esis.contains(&(i as u32)) {
                all_systematic = false;
                break;
            }
        }
        if all_systematic {
            for (i, &esi) in self.esis.iter().enumerate() {
                if (esi as usize) < k {
                    let off = (esi as usize) * t;
                    if off < self.data_len {
                        let take = (self.data_len - off).min(t);
                        self.decoded_data[off..off + take]
                            .copy_from_slice(&self.symbols[i * t..i * t + take]);
                    }
                }
            }
            self.is_decoded = true;
            return true;
        }

        // Phase 1: Fast Structure-only Gaussian Elimination
        let mut a = vec![0u8; n * k];
        let mut perm: Vec<usize> = (0..k).collect();
        let mut row_buf = [0u8; RQ_MAX_K];

        for i in 0..n {
            get_symbol_row(self.esis[i], k, &mut row_buf);
            a[i * k..i * k + k].copy_from_slice(&row_buf[..k]);
        }

        let mut ops = Vec::with_capacity(k * n + k);

        for step in 0..k {
            let mut best_r = step;
            let mut best_c = step;
            let mut found = false;

            for r in step..n {
                for c in step..k {
                    if a[r * k + c] != 0 {
                        best_r = r;
                        best_c = c;
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
            }

            if !found {
                return false; // Insufficient rank, wait for more symbols
            }

            if best_r != step {
                for j in 0..k {
                    a.swap(step * k + j, best_r * k + j);
                }
                ops.push(RowOp::Swap(step, best_r));
            }

            if best_c != step {
                for r in 0..n {
                    a.swap(r * k + step, r * k + best_c);
                }
                perm.swap(step, best_c);
            }

            let pivot_val = a[step * k + step];
            let inv_pivot = gf.inv(pivot_val);

            if pivot_val != 1 {
                for j in step..k {
                    a[step * k + j] = gf.mul(a[step * k + j], inv_pivot);
                }
                ops.push(RowOp::Scale(step, inv_pivot));
            }

            for r in 0..n {
                if r != step && a[r * k + step] != 0 {
                    let factor = a[r * k + step];
                    for j in step..k {
                        a[r * k + j] ^= gf.mul(factor, a[step * k + j]);
                    }
                    ops.push(RowOp::AddMul(r, step, factor));
                }
            }
        }

        // Phase 2: Apply Recorded Operations ONCE to Payload Matrix D
        let mut d = self.symbols.clone();
        let mut tmp_d = vec![0u8; t];

        for op in ops {
            match op {
                RowOp::Swap(r1, r2) => {
                    tmp_d.copy_from_slice(&d[r1 * t..r1 * t + t]);
                    let (first, second) = if r1 < r2 {
                        let (s1, s2) = d.split_at_mut(r2 * t);
                        (&mut s1[r1 * t..r1 * t + t], &mut s2[..t])
                    } else {
                        let (s1, s2) = d.split_at_mut(r1 * t);
                        (&mut s2[..t], &mut s1[r2 * t..r2 * t + t])
                    };
                    first.copy_from_slice(second);
                    second.copy_from_slice(&tmp_d);
                }
                RowOp::Scale(r, factor) => {
                    let tab = &gf.mul_table[factor as usize];
                    for b in &mut d[r * t..r * t + t] {
                        *b = tab[*b as usize];
                    }
                }
                RowOp::AddMul(r1, r2, factor) => {
                    let tab = &gf.mul_table[factor as usize];
                    if r1 < r2 {
                        let (s1, s2) = d.split_at_mut(r2 * t);
                        let dst = &mut s1[r1 * t..r1 * t + t];
                        let src = &s2[..t];
                        for (dest, source) in dst.iter_mut().zip(src.iter()) {
                            *dest ^= tab[*source as usize];
                        }
                    } else {
                        let (s1, s2) = d.split_at_mut(r1 * t);
                        let src = &s1[r2 * t..r2 * t + t];
                        let dst = &mut s2[..t];
                        for (dest, source) in dst.iter_mut().zip(src.iter()) {
                            *dest ^= tab[*source as usize];
                        }
                    }
                }
            }
        }

        for (i, &orig_idx) in perm.iter().enumerate().take(k) {
            let off = orig_idx * t;
            if off < self.data_len {
                let take = (self.data_len - off).min(t);
                self.decoded_data[off..off + take].copy_from_slice(&d[i * t..i * t + take]);
            }
        }

        self.is_decoded = true;
        true
    }
}

pub struct RaptorQDecoder {
    num_blocks: usize,
    blocks: Vec<BlockDecoder>,
}

impl RaptorQDecoder {
    pub fn new(data_len: usize, symbol_size: usize) -> Option<Self> {
        if data_len == 0 || symbol_size == 0 {
            return None;
        }

        let total_k = ((data_len + symbol_size - 1) / symbol_size).max(1);
        let num_blocks = (total_k + RQ_MAX_K - 1) / RQ_MAX_K;
        let block_bytes = RQ_MAX_K * symbol_size;

        let mut blocks = Vec::with_capacity(num_blocks);
        for b in 0..num_blocks {
            let off = b * block_bytes;
            let blk_len = (data_len - off).min(block_bytes);
            blocks.push(BlockDecoder::new(blk_len, symbol_size));
        }

        Some(Self { num_blocks, blocks })
    }

    pub fn receive_symbol(&mut self, esi: u32, symbol_data: &[u8]) -> bool {
        let block_idx = (esi as usize) % self.num_blocks;
        let block_esi = (esi as usize) / self.num_blocks;
        self.blocks[block_idx].receive_symbol(block_esi as u32, symbol_data);
        self.is_ready()
    }

    pub fn is_ready(&self) -> bool {
        self.blocks.iter().all(|b| b.is_decoded)
    }

    pub fn decode_data(&self) -> Option<Vec<u8>> {
        if !self.is_ready() {
            return None;
        }
        let mut out = Vec::new();
        for b in &self.blocks {
            out.extend_from_slice(&b.decoded_data);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raptorq_loss_recovery() {
        let size = 101503;
        let symbol_size = 1024;
        let data: Vec<u8> = (0..size).map(|i| (i * 37 % 256) as u8).collect();
        let encoder = RaptorQEncoder::new(&data, symbol_size).unwrap();
        let mut decoder = RaptorQDecoder::new(data.len(), symbol_size).unwrap();

        let k = (size + symbol_size - 1) / symbol_size;
        let mut sym = vec![0u8; symbol_size];

        // Drop 15% of systematic symbols and use repair symbols
        let mut received = 0;
        let mut esi = 0u32;
        while !decoder.is_ready() && esi < 200 {
            if esi < k as u32 && esi % 7 == 0 {
                // Drop this symbol
                esi += 1;
                continue;
            }
            encoder.encode_symbol(esi, &mut sym);
            decoder.receive_symbol(esi, &sym);
            received += 1;
            esi += 1;
        }

        assert!(decoder.is_ready(), "Decoder failed to recover with {} symbols for k={}", received, k);
        let decoded = decoder.decode_data().expect("Decode failed");
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_raptorq_80pct_loss_recovery() {
        let size = 80000;
        let symbol_size = 1024;
        let data: Vec<u8> = (0..size).map(|i| (i * 97 % 256) as u8).collect();
        let encoder = RaptorQEncoder::new(&data, symbol_size).unwrap();
        let mut decoder = RaptorQDecoder::new(data.len(), symbol_size).unwrap();

        let k = (size + symbol_size - 1) / symbol_size;
        let mut sym = vec![0u8; symbol_size];

        // 80% random drop rate
        let mut rng_state: u64 = 123456789;
        let mut next_rand = || {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            rng_state
        };

        let mut received = 0;
        let mut esi = 0u32;
        while !decoder.is_ready() && esi < 600 {
            if (next_rand() % 100) < 80 {
                // 80% drop rate!
                esi += 1;
                continue;
            }
            encoder.encode_symbol(esi, &mut sym);
            decoder.receive_symbol(esi, &sym);
            received += 1;
            esi += 1;
        }

        assert!(decoder.is_ready(), "Decoder failed at 80% loss: received {} for k={}", received, k);
        let decoded = decoder.decode_data().expect("Decode failed");
        assert_eq!(data, decoded);
    }
}


