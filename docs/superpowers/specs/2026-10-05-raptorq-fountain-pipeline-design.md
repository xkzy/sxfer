# Architecture Specification: RaptorQ Rateless Fountain Coding, Dynamic Chunk Sizing, Continuous Pipeline & Baseband Line Coding

**Date:** 2026-10-05  
**Topic:** sxfer Fountain Coding (RFC 6330 RaptorQ), Dynamic Chunk Sizing, 3-Stage Pipeline & Baseband Line Modulation

---

## 1. Executive Summary

`sxfer` is a high-reliability, unidirectional file transfer utility designed for TX-only serial links without a backchannel. This specification covers four key subsystems:
1. **Rateless Fountain Coding (RFC 6330 RaptorQ)**: Replaces fixed round repetitions and static FEC groups with an endless stream of independent encoded symbols. Receivers reconstruct the complete source block upon collecting any $(1 + \varepsilon)K$ symbols ($\varepsilon \approx 0.01 - 0.02$).
2. **Dynamic Chunk Sizing & Zero-Copy Staging**: Automatically adjusts chunk sizes based on link baud rate (1 KiB for low speeds, 4–16 KiB for high speeds $\ge 1\text{ Mbaud}$) to cut framing overhead to $< 0.1\%$ and minimize kernel `write()` context switches.
3. **Continuous 3-Stage Streaming Pipeline**: Asynchronously overlaps disk reading/compression, RaptorQ symbol generation, and serial port transmission using double/ring buffering to maintain 100% UART FIFO saturation with zero inter-file/inter-frame gaps.
4. **Baseband Line Coding & Scrambling (`-m cobs|scramble|raw`)**: Implements additive polynomial data whitening (LFSR transition scrambler) and Consistent Overhead Byte Stuffing (COBS) with `0x00` zero-delimiter framing for DC balancing and UART bit clock transition density over RS-485 links.

---

## 2. Architecture & Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             SENDER PIPELINE                                 │
│                                                                             │
│  ┌───────────────────────┐                                                  │
│  │ Stage 1: File Reader  │                                                  │
│  │  & Fast-LZMA2 Worker  │                                                  │
│  └──────────┬────────────┘                                                  │
│             │ (Ring Buffer Queue Q1: Compressed Source Blocks)               │
│             ▼                                                               │
│  ┌───────────────────────┐                                                  │
│  │ Stage 2: RaptorQ      │ (Systematic Pre-code + RFC 6330 Generator)      │
│  │ Fountain Generator    │                                                  │
│  └──────────┬────────────┘                                                  │
│             │ (Ring Buffer Queue Q2: Symbol Frames)                         │
│             ▼                                                               │
│  ┌───────────────────────┐                                                  │
│  │ Baseband Modulator    │ (LFSR Scrambler + COBS Line Coding)              │
│  └──────────┬────────────┘                                                  │
│             ▼                                                               │
│  ┌───────────────────────┐                                                  │
│  │ Stage 3: Serial TX    │                                                  │
│  │ Zero-Copy Worker      │ -> Continuous Serial TX Stream                   │
│  └───────────────────────┘                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Component Specifications

### 3.1. RFC 6330 RaptorQ Fountain Code Engine (`sxfer_raptorq.h` / `sxfer_raptorq.c`)
- **Field Arithmetic**: $GF(256)$ with irreducible polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (0x11D).
- **Source Block Partitioning**: Files/streams are partitioned into source blocks of $K$ source symbols ($K \le 8192$), each of symbol size $T$ bytes.
- **Systematic Pre-code**: Derives $L = K + S + H$ intermediate symbols $C$ by solving the constraint matrix $A \cdot C = [0; D]$ over $GF(256)$.
- **LT Generator**: RFC 6330 pseudo-random generator produces independent repair symbols for $X \ge K$.
- **Inactivation Decoder**: Peeling schedule combined with Gaussian elimination for inactivated symbols over $GF(256)$ to reconstruct all $K$ source symbols from any $K(1+\varepsilon)$ received symbols.

### 3.2. Baseband Modulation & Line Coding (`sxfer_mod.h` / `sxfer_mod.c`)
- **Additive Polynomial Whitener / Scrambler**:
  - Galois LFSR polynomial $P(x) = x^7 + x^4 + 1$ (or 15-bit ITU-T V.34 LFSR).
  - Synchronously XORed with frame payloads to break continuous runs of `0x00` or `0xFF` bytes, ensuring a uniform distribution of 0/1 bit transitions for UART bit clock phase locking on RS-485 differential transceivers.
- **Consistent Overhead Byte Stuffing (COBS)**:
  - Encodes packet payloads such that byte `0x00` never appears inside the encoded frame.
  - Byte `0x00` serves as an unambiguous frame delimiter, enabling instant $O(1)$ packet boundary recovery without false magic synchronization.
  - Guaranteed overhead: $\le 1 \text{ byte per } 254 \text{ bytes } (< 0.4\%)$.
- **Modulation Selection (`-m MODE`)**:
  - `cobs` (default): Scrambler + COBS framing with `0x00` delimiter.
  - `scramble`: Scrambled payload with 4-byte magic sync.
  - `raw`: Legacy framing (Magic + Length + Payload + CRC32).

### 3.3. Dynamic Chunk Sizing & Memory Alignment
- **Baud-Adaptive Chunk Sizing**:
  - $B < 500,000 \text{ baud} \implies T = 1024 \text{ bytes}$.
  - $500,000 \le B < 2,500,000 \text{ baud} \implies T = 4096 \text{ bytes}$.
  - $B \ge 2,500,000 \text{ baud} \implies T = 16384 \text{ bytes}$.
  - Manual override with `-c BYTES`.
- **Zero-Copy DMA & Cacheline Alignment**:
  - Symbol buffers are 64-byte aligned for vector operations.
  - Batched serial writes in 64 KiB buffers.

### 3.4. Continuous Asynchronous 3-Stage Pipeline
- **Thread 1 (Reader & Fast-LZMA2 Compressor)**: Reads files and streams compressed source blocks into Queue Q1.
- **Thread 2 (RaptorQ Fountain Encoder & Modulator)**: Generates fountain symbols, applies scrambler and COBS line coding, and enqueues frames into Queue Q2.
- **Thread 3 (Serial TX Worker)**: Continuously drains Queue Q2 into the serial device, keeping UART TX FIFO saturated at 100%.

---

## 4. Testing & Verification Plan
1. **Unit Tests**:
   - RaptorQ $GF(256)$ arithmetic, pre-code inversion, and inactivation decoder recovery across symbol loss percentages.
   - COBS encoding/decoding and LFSR scrambler roundtrip tests with all-zero, all-one, and random payloads.
2. **Integration Tests**:
   - 3-stage pipeline throughput test over virtual FIFO pipes and PTY pairs.
   - Framing corruption and bit noise recovery tests.
3. **End-to-End Compatibility**:
   - Verification of file trees, directory permissions, and symlinks with matching CRC-32 checksums.
